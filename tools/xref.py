#!/usr/bin/env python3
"""
xref.py — cross-reference and call graph builder for 68000 binaries / Mac ROMs
Usage: python3 xref.py <file> [--org 0x400000] [--output xref.txt]
       python3 xref.py <file> --sections --max-chunks 20 --output sections.json
       python3 xref.py <file> --callgraph [--mermaid]

Runs the same analysis as dasm68k.py (same flags -> same code/data split),
then offers three outputs:
  format_report()    human-readable xref: subroutines and callers, A-trap
                     calls, low-memory globals, hardware registers, vector
                     installs, data references, strings
  format_sections()  JSON chunk map consumed by annotator.py --split
  format_callgraph() call tree from the entry points (text or Mermaid)
Pass the same flags you gave dasm68k.py, or the section boundaries will
not line up with the listing.
"""

import sys
import json
import bisect
import argparse
from collections import defaultdict

try:
    from tools.dasm68k import build_disassembler, add_common_args
    from tools.m68k import ea_address
    from tools import macsyms, atarisyms
except ImportError:
    from dasm68k import build_disassembler, add_common_args
    from m68k import ea_address
    import macsyms
    import atarisyms

WRITERS = ("MOVE", "MOVEA", "CLR", "ADDQ", "SUBQ", "ADD", "SUB", "ADDI", "SUBI", "AND", "ANDI",
           "OR", "ORI", "EOR", "EORI", "NOT", "NEG", "NEGX", "BSET", "BCLR", "BCHG", "TAS", "ST",
           "SF", "MOVEM", "ASL", "ASR", "LSL", "LSR", "ROL", "ROR", "ROXL", "ROXR")


def mnemonic_base(m: str) -> str:
    return m.split(".")[0]


class CrossReferenceBuilder:
    """Call / jump / trap / data-reference maps from a Disassembler68k
    analysis. "from" maps are keyed by the referencing instruction, "to"
    maps by the target. Only placed instructions contribute."""

    def __init__(self, dasm):
        self.dasm = dasm
        self.mem = dasm.mem
        self.exec_addr = dasm.entry_addr
        self.calls_from = defaultdict(list)
        self.calls_to = defaultdict(list)
        self.jumps_from = defaultdict(list)
        self.jumps_to = defaultdict(list)
        self.data_refs = defaultdict(list)
        self.trap_calls = defaultdict(list)      # line-A word -> [pc]
        self.sys_calls = defaultdict(list)       # "GEMDOS Fopen" -> [pc] (Atari TRAP calls)
        self.lowmem = defaultdict(list)          # addr -> [(pc, 'r'|'w')]
        self.hw_accesses = defaultdict(list)     # addr -> [(pc, 'r'|'w')]
        self.ext_calls = defaultdict(list)       # outside-image call targets
        self.stores_to_code = defaultdict(list)
        self.subroutines: set[int] = set()
        self.strings = []

    def analyze(self):
        self.dasm.disassemble(show_hex=True, annotate=False)
        self._pass_find_refs()
        self._find_strings()

    def _pass_find_refs(self):
        d = self.dasm
        for pc, ins in sorted(d.instrs.items()):
            m = mnemonic_base(ins.mnemonic)
            if ins.trap:
                self.trap_calls[ins.words[0]].append(pc)
                continue
            if pc in d.tos_calls:
                sysname, name, _fn = d.tos_calls[pc]
                self.sys_calls[f"{sysname} {name}" if sysname not in ("AES", "VDI") else sysname].append(pc)
            t = ins.target if ins.flow == "call" else (d.a5_calls.get(pc) or
                                                        (d.reg_calls.get(pc) if ins.flow == "call_ind" else None))
            if t is not None:
                self.calls_from[pc].append(t)
                self.calls_to[t].append(pc)
                if self.mem.is_populated(t):
                    self.subroutines.add(t)
                else:
                    self.ext_calls[t].append(pc)
            elif ins.flow in ("jump", "branch") and ins.target is not None:
                self.jumps_from[pc].append(ins.target)
                self.jumps_to[ins.target].append(pc)
                if not self.mem.is_populated(ins.target) and ins.mnemonic == "JMP":
                    self.ext_calls[ins.target].append(pc)
            for i, op in enumerate(ins.ops):
                if op[0] not in ("absW", "absL", "d16PC", "idxPC"):
                    continue
                a = ea_address(op)
                if ins.target is not None and a == ins.target and m in ("JMP", "JSR"):
                    continue
                write = i == len(ins.ops) - 1 and len(ins.ops) >= 1 and m in WRITERS \
                    and not (m in ("MOVEM",) and op[0] != ins.ops[-1][0])
                if m == "MOVEM" and i == 0:
                    write = False
                rw = "w" if write else "r"
                if self.mem.is_populated(a):
                    self.data_refs[a].append(pc)
                    if write and a in d.owner and not d.rom_name:
                        self.stores_to_code[a].append(pc)
                elif a >= 0x400000 and (a in d.plat.hardware or d.plat.device(a)):
                    self.hw_accesses[a].append((pc, rw))
                elif a < d.plat.lowmem_limit and (d.plat.name != "generic" or d.vector_table):
                    self.lowmem[a].append((pc, rw))
            if m == "MOVE" and len(ins.ops) == 2 and ins.ops[0][0] == "imm" and ins.ops[0][2] == 4:
                v = ins.ops[0][1] & 0xFFFFFF
                if v >= 0x400000 and (v in d.plat.hardware or (d.mac and v == macsyms.VIA_BASE)):
                    self.hw_accesses[v].append((pc, "imm"))
        for a, refs in d.data_refs.items():
            for r in refs:
                if r not in self.data_refs[a]:
                    self.data_refs[a].append(r)
        for t in d.call_targets | set(d.named_entries):
            if self.mem.is_populated(t) and d.owner.get(t) == t:
                self.subroutines.add(t)

    def _find_strings(self):
        for pc, _hx, mn, op, cm in self.dasm.lines:
            if mn == "DC.B" and "'" in op and ("ASCII" in cm or "Pascal" in cm):
                self.strings.append((pc, op, "Pascal" in cm))

    # ---------------- naming ----------------

    def is_external_named(self, addr: int) -> bool:
        return not self.mem.is_populated(addr) and self.dasm.known_name(addr) is not None

    def name(self, addr: int) -> str:
        return self.dasm.addr_label(addr)

    def sub_name(self, addr: int) -> str:
        if addr in self.dasm.labels:
            return self.dasm.labels[addr]
        return self.dasm.known_name(addr) or f"SUB_{addr:06X}"

    def local_subs(self) -> list:
        if getattr(self, "_subs_cache", None) is None or len(self._subs_cache[0]) != len(self.subroutines):
            self._subs_cache = (set(self.subroutines),
                                sorted(s for s in self.subroutines if self.mem.is_populated(s)))
        return self._subs_cache[1]

    def sub_extent(self) -> dict:
        """subroutine -> end address (exclusive): up to the next subroutine."""
        subs = self.local_subs()
        if getattr(self, "_ext_cache", None) is not None and self._ext_cache[0] is subs:
            return self._ext_cache[1]
        ranges = self.mem.get_contiguous_ranges()
        out = {}
        for i, s in enumerate(subs):
            end = next(e for a, e in ranges if a <= s <= e) + 1
            if i + 1 < len(subs):
                end = min(end, subs[i + 1])
            out[s] = end
        self._ext_cache = (subs, out)
        return out

    def body_of(self, sub: int, ext: dict = None):
        """Instructions belonging to a subroutine (up to the next one)."""
        ext = ext or self.sub_extent()
        end = ext.get(sub, sub)
        if getattr(self, "_pcs", None) is None or len(self._pcs) != len(self.dasm.instrs):
            self._pcs = sorted(self.dasm.instrs)
        lo = bisect.bisect_left(self._pcs, sub)
        hi = bisect.bisect_left(self._pcs, end)
        return [self.dasm.instrs[pc] for pc in self._pcs[lo:hi]]

    # ---------------- report ----------------

    def format_report(self) -> str:
        d = self.dasm
        out = ["=" * 64, f"CROSS-REFERENCE REPORT (68000, {d.plat.title})", "=" * 64]
        if d.rom_name:
            out.append(f"ROM: {d.rom_name}")
        for s, e in self.mem.get_contiguous_ranges():
            out.append(f"Range: ${s:06X}-${e:06X} ({e - s + 1} bytes)")
        if self.exec_addr is not None:
            out.append(f"Entry: ${self.exec_addr:06X}")
        out.append(f"Instructions: {len(d.instrs)} (traced {len(d.traced)}, swept {len(d.swept)}, "
                   f"filled {len(d.instrs) - len(d.traced) - len(d.swept)}; fill mode {d.fill})")
        for note in d.auto_found:
            out.append(f"Auto-detected {note}")
        if d.sym.sources:
            out.append(f"Symbols: {', '.join(d.sym.sources)} ({len(d.sym)} entries)")
        out.append("")

        local = self.local_subs()
        out.append(f"--- Subroutines ({len(local)}) ---")
        for s in local:
            callers = self.calls_to.get(s, [])
            out.append(f"  {self.sub_name(s):24s} ${s:06X}  called from {len(callers)}: "
                       + ", ".join(f"${c:06X}" for c in sorted(callers)[:8])
                       + (" ..." if len(callers) > 8 else ""))
        out.append("")

        if self.sys_calls:
            out.append(f"--- System calls ({len(self.sys_calls)}) ---")
            for name in sorted(self.sys_calls, key=lambda n: -len(self.sys_calls[n])):
                refs = self.sys_calls[name]
                out.append(f"  {name:28s} x{len(refs):<4d} "
                           f"{atarisyms.CALL_DESC.get(name.split(' ')[-1], '') if ' ' in name else ''}")
                out.append("      from: " + ", ".join(f"${r:06X}" for r in sorted(refs)[:10])
                           + (" ..." if len(refs) > 10 else ""))
            out.append("")

        if self.trap_calls:
            out.append(f"--- Line-A words / traps called ({len(self.trap_calls)}) ---")
            for w in sorted(self.trap_calls, key=lambda w: -len(self.trap_calls[w])):
                t = d.plat.linea(w)
                refs = self.trap_calls[w]
                out.append(f"  ${w:04X} {t['display']:28s} x{len(refs):<4d} {t['manager']}")
                out.append("      from: " + ", ".join(f"${r:06X}" for r in sorted(refs)[:10])
                           + (" ..." if len(refs) > 10 else ""))
            out.append("")

        if self.ext_calls:
            out.append(f"--- Calls / jumps outside the image ({len(self.ext_calls)}) ---")
            for a in sorted(self.ext_calls):
                refs = self.ext_calls[a]
                out.append(f"  {self.name(a):20s} ${a:06X}  x{len(refs):<3d} from: "
                           + ", ".join(f"${r:06X}" for r in sorted(refs)[:8]))
            out.append("")

        if self.lowmem:
            out.append(f"--- Low-memory globals / vectors ({len(self.lowmem)}) ---")
            for a in sorted(self.lowmem):
                refs = self.lowmem[a]
                desc = d.describe(a)
                nr = sum(1 for _p, k in refs if k == "r")
                nw = len(refs) - nr
                out.append(f"  {self.name(a):16s} ${a:04X}  r{nr:<3d} w{nw:<3d} {desc[:50]}")
            out.append("")

        if self.hw_accesses:
            out.append(f"--- Hardware registers ({len(self.hw_accesses)}) ---")
            for a in sorted(self.hw_accesses):
                refs = self.hw_accesses[a]
                desc = d.plat.hw_desc(a) or ""
                out.append(f"  {self.name(a):16s} ${a:06X}  x{len(refs):<3d} {desc[:44]}  from: "
                           + ", ".join(f"${r:06X}" for r, _k in sorted(refs)[:6]))
            out.append("")

        if d.vector_installs:
            out.append("--- Vector / hook installs ---")
            for pc, vec, h in d.vector_installs:
                vn = d.plat.lowmem_name(vec) or f"${vec:04X}"
                out.append(f"  ${pc:06X}: {vn} (${vec:04X}) <- {self.sub_name(h)} ${h:06X}")
            out.append("")

        if d.dispatch_tables:
            out.append("--- Dispatch table candidates ---")
            for t in d.dispatch_tables:
                out.append(f"  ${t['addr']:06X}: {t['entries']} x {t['stride']}-byte entries, "
                           f"{t['hits']} hit routine starts" + (f" ({t['trap_map']})" if t["trap_map"] else ""))
            out.append("")

        if self.stores_to_code:
            out.append("--- Self-modifying code (stores into code) ---")
            for a in sorted(self.stores_to_code):
                out.append(f"  ${a:06X} written from " + ", ".join(f"${r:06X}" for r in self.stores_to_code[a]))
            out.append("")

        internal = {a: r for a, r in self.data_refs.items()
                    if self.mem.is_populated(a) and a not in d.owner}
        if internal:
            out.append(f"--- Data references into image ({len(internal)}) ---")
            for a in sorted(internal):
                out.append(f"  {self.name(a):20s} ${a:06X}  from: "
                           + ", ".join(f"${r:06X}" for r in sorted(internal[a])[:8]))
            out.append("")

        if self.strings:
            out.append(f"--- Strings ({len(self.strings)}) ---")
            for a, text, pas in self.strings[:400]:
                out.append(f"  ${a:06X} {'[P] ' if pas else ''}{text[:70]}")
            out.append("")
        return "\n".join(out)

    # ---------------- call graph ----------------

    def callees(self, sub: int, ext: dict = None) -> list:
        seen = []
        for ins in self.body_of(sub, ext):
            for t in self.calls_from.get(ins.pc, []):
                if t not in seen:
                    seen.append(t)
        return seen

    def traps_in(self, sub: int, ext: dict = None) -> list:
        """Line-A words used by a subroutine."""
        cache = self.__dict__.setdefault("_traps_cache", {})
        if sub not in cache:
            out = []
            for ins in self.body_of(sub, ext):
                if ins.trap and ins.words[0] not in out:
                    out.append(ins.words[0])
            cache[sub] = out
        return cache[sub]

    def call_name(self, w: int) -> str:
        return self.dasm.plat.linea(w)["display"].split(" ,")[0].replace(" ", "_")

    def calls_in(self, sub: int, ext: dict = None) -> list:
        """Names of the traps and system calls a subroutine makes."""
        cache = self.__dict__.setdefault("_calls_cache", {})
        if sub not in cache:
            out = []
            for ins in self.body_of(sub, ext):
                if ins.trap:
                    n = self.call_name(ins.words[0])
                elif ins.pc in self.dasm.tos_calls:
                    sysname, name, _fn = self.dasm.tos_calls[ins.pc]
                    n = name if sysname not in ("AES", "VDI") else sysname
                else:
                    continue
                if n not in out:
                    out.append(n)
            cache[sub] = out
        return cache[sub]

    def format_callgraph(self, mermaid: bool = False, max_depth: int = 10, show_traps: bool = True) -> str:
        ext = self.sub_extent()
        cache = {s: self.callees(s, ext) for s in self.local_subs()}
        roots = []
        if self.exec_addr is not None:
            roots.append(self.exec_addr)
        for t in self.local_subs():
            if not self.calls_to.get(t) and t not in roots:
                roots.append(t)

        if mermaid:
            out = ["```mermaid", "graph TD"]
            edges = set()
            for s in self.local_subs():
                for t in cache[s]:
                    edges.add((self.sub_name(s), self.sub_name(t), not self.mem.is_populated(t)))
            for a, b, ext_ in sorted(edges):
                out.append(f"    {a} --> {b}" + (f"[[{b}]]" if ext_ else ""))
            out.append("```")
            return "\n".join(out)

        out = []

        def walk(sub, prefix, depth, stack):
            kids = cache.get(sub, [])
            for i, t in enumerate(kids):
                last = i == len(kids) - 1
                branch = "└── " if last else "├── "
                tag = ""
                if not self.mem.is_populated(t):
                    tag = " [external]"
                elif t in stack:
                    tag = " [recursive]"
                traps = self.calls_in(t, ext) if show_traps and self.mem.is_populated(t) else []
                if traps:
                    tag += "  calls: " + " ".join(traps[:6])
                out.append(f"{prefix}{branch}{self.sub_name(t)} (${t:06X}){tag}")
                if self.mem.is_populated(t) and t not in stack and depth < max_depth:
                    walk(t, prefix + ("    " if last else "│   "), depth + 1, stack | {t})

        for r in roots:
            traps = self.calls_in(r, ext) if show_traps else []
            out.append(f"{self.sub_name(r)} (${r:06X})"
                       + ("  calls: " + " ".join(traps[:6]) if traps else ""))
            walk(r, "", 1, {r})
            out.append("")
        leaves = [s for s in self.local_subs() if not cache[s]]
        out.append(f"Subroutines: {len(self.local_subs())}, leaf: {len(leaves)}, "
                   f"traps used: {len(self.trap_calls)}, system calls: {len(self.sys_calls)}, "
                   f"external targets: {len(self.ext_calls)}")
        return "\n".join(out)

    # ---------------- sections ----------------

    def format_sections(self, chunk_target: int = 500, max_chunks: int = None) -> str:
        """JSON section map for chunked annotation. Sections start at
        subroutine entries and range starts, so chunks never split a
        subroutine; adjacent sections merge greedily up to ~1.3x
        chunk_target listing lines."""
        ranges = self.mem.get_contiguous_ranges()
        line_starts = sorted(pc for pc, *_r in self.dasm.lines)
        line_set = set(line_starts)
        boundaries = {s for s, _ in ranges} | {a for a in self.subroutines if a in line_set}
        boundaries = sorted(boundaries)

        def range_end(addr):
            for s, e in ranges:
                if s <= addr <= e:
                    return e
            return addr

        import bisect
        section_lines = []
        for i, b in enumerate(boundaries):
            end = range_end(b)
            if i + 1 < len(boundaries) and boundaries[i + 1] <= end:
                end = boundaries[i + 1] - 1
            count = bisect.bisect_right(line_starts, end) - bisect.bisect_left(line_starts, b)
            if count:
                section_lines.append((b, end, count))

        if max_chunks is not None and section_lines:
            total = sum(c for _, _, c in section_lines)
            chunk_target = max(200, total // max_chunks)

        # Oversized sections (long data areas inside one "routine") are cut
        # at data lines, so no chunk grows far past the target
        kinds = {pc: mn for pc, _hx, mn, _op, _cm in self.dasm.lines}
        limit = int(chunk_target * 1.3)
        split = []
        for start, end, count in section_lines:
            if count <= limit:
                split.append((start, end, count))
                continue
            lo = bisect.bisect_left(line_starts, start)
            hi = bisect.bisect_right(line_starts, end)
            cut_from, n = lo, 0
            for i in range(lo, hi):
                n += 1
                if n >= chunk_target and kinds.get(line_starts[i], "").startswith("DC") and i + 1 < hi:
                    split.append((line_starts[cut_from], line_starts[i + 1] - 1, i + 1 - cut_from))
                    cut_from, n = i + 1, 0
            split.append((line_starts[cut_from], end, hi - cut_from))
        section_lines = split

        chunks, cur = [], None
        for start, end, count in section_lines:
            if cur is None or cur["line_count"] + count > chunk_target * 1.3:
                if cur:
                    chunks.append(cur)
                cur = {"start_addr": start, "end_addr": end, "line_count": count, "subroutines": []}
            else:
                cur["end_addr"] = end
                cur["line_count"] += count
            if start in self.subroutines:
                cur["subroutines"].append(self.sub_name(start))
        if cur:
            chunks.append(cur)

        for i, c in enumerate(chunks):
            lo, hi = c["start_addr"], c["end_addr"]
            c["id"] = i
            c["start_addr_hex"] = f"0x{lo:06X}"
            c["end_addr_hex"] = f"0x{hi:06X}"
            c["traps"] = sorted({self.call_name(w) for w, refs in self.trap_calls.items()
                                 if any(lo <= r <= hi for r in refs)} |
                                {n for n, refs in self.sys_calls.items() if any(lo <= r <= hi for r in refs)})
            c["lowmem"] = sorted({self.name(a) for a, refs in self.lowmem.items()
                                  if any(lo <= r <= hi for r, _k in refs)})
            c["hw_accesses"] = sorted({self.name(a) for a, refs in self.hw_accesses.items()
                                       if any(lo <= r <= hi for r, _k in refs)})
            c["calls_out"] = sorted({self.sub_name(t) for cl, ts in self.calls_from.items()
                                     if lo <= cl <= hi for t in ts if not lo <= t <= hi})
            c["called_from"] = sorted({f"${cl:06X}" for t, cls in self.calls_to.items()
                                       if lo <= t <= hi for cl in cls if not lo <= cl <= hi})
            c["self_modifying"] = sorted({f"${a:06X}" for a, refs in self.stores_to_code.items()
                                          if any(lo <= r <= hi for r in refs)})
            del c["start_addr"], c["end_addr"]
        return json.dumps(chunks, indent=2)


def main():
    parser = argparse.ArgumentParser(description="68000 cross-reference builder")
    add_common_args(parser)
    parser.add_argument("--output", "-o", help="Output file")
    parser.add_argument("--sections", action="store_true", help="JSON section map for chunked annotation")
    parser.add_argument("--chunk-size", type=int, default=500,
                        help="Target listing lines per chunk for --sections (default: 500)")
    parser.add_argument("--max-chunks", type=int, default=None,
                        help="Maximum number of chunks (overrides --chunk-size)")
    parser.add_argument("--callgraph", action="store_true", help="Call tree from the entry points")
    parser.add_argument("--mermaid", action="store_true", help="With --callgraph: Mermaid diagram")
    parser.add_argument("--depth", type=int, default=10, help="Call tree depth limit (default 10)")
    args = parser.parse_args()

    dasm, _info = build_disassembler(args)
    xref = CrossReferenceBuilder(dasm)
    xref.analyze()
    if args.sections:
        result = xref.format_sections(chunk_target=args.chunk_size, max_chunks=args.max_chunks)
    elif args.callgraph:
        result = xref.format_callgraph(mermaid=args.mermaid, max_depth=args.depth)
    else:
        result = xref.format_report()
    if args.output:
        with open(args.output, "w") as f:
            f.write(result + "\n")
        print(f"Output written to {args.output}", file=sys.stderr)
    else:
        print(result)


if __name__ == "__main__":
    main()
