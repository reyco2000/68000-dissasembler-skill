#!/usr/bin/env python3
"""
annotator.py — split, annotate and merge tool for chunked 68000 disassembly
Usage:
  Split:    python3 annotator.py --split --asm file.asm --sections sections.json --output-dir chunks/
  Annotate: python3 annotator.py --annotate --manifest chunks/manifest.json --ref-dir reference/
  Merge:    python3 annotator.py --merge --manifest chunks/manifest.json --output annotated.s [--reassemble]
  Rename:   python3 annotator.py --manifest chunks/manifest.json --apply-symbols names.json

Pipeline: dasm68k.py produces the listing, xref.py --sections the chunk
boundaries, then this tool runs split -> annotate -> merge. Chunk files may
be edited in between (e.g. LLM-added comments); merge only needs the
CODE_MARKER line and everything after it to survive.

Chunk file layout (written by split, relied on by merge):
  header (copied from the listing: MC68000, trap macros, equates, ranges)
  "; CHUNK n of m ..." context block (subroutines, traps, globals, xrefs)
  CODE_MARKER line
  code body (with a synthesized ORG if the chunk didn't start with one)

--reassemble strips the address/hex columns on merge so the annotated file
assembles with vasm back to the original bytes.

The annotator's lookup tables come from the markdown tables in reference/
(mac_traps.md, mac_lowmem.md, mac_hardware.md): extend those files to
extend coverage without code changes.
"""

import sys
import os
import json
import argparse
import re

try:
    from tools import macsyms
except ImportError:
    import macsyms

CODE_MARKER = "; --- BEGIN CODE ---"

# Listing line contract (fixed columns, see dasm68k.py):
# "  AAAAAA  HEX (24 columns)            MNEMONIC OPERANDS ; comment"
LINE_RE = re.compile(r'^  ([0-9A-F]{6})  ([0-9A-F. ]{24})  (\S.*?)\s*$')
INSTR_RE = re.compile(r"^([A-Z_][A-Za-z0-9_.]*)(?:\s+((?:'[^']*'|[^;'])*?))?\s*(;.*)?$")
LABEL_RE = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*:$')
ORG_RE = re.compile(r'^\s*ORG\s+\$', re.IGNORECASE)

PACK_SELECTORS = {
    2: {0: "DIBadMount", 2: "DILoad", 4: "DIUnload", 6: "DIFormat", 8: "DIVerify", 10: "DIZero"},
    3: {1: "SFPutFile", 2: "SFGetFile", 3: "SFPPutFile", 4: "SFPGetFile"},
    6: {0: "IUDateString", 2: "IUTimeString", 4: "IUMetric", 6: "IUGetIntl", 8: "IUSetIntl",
        10: "IUMagString", 12: "IUMagIDString", 14: "IUDatePString", 16: "IUTimePString"},
    7: {0: "NumToString", 1: "StringToNum"},
}
SCC_OFFSETS = {o: (n, d) for o, n, d in macsyms.SCC_REGS}


def extract_header(asm_lines):
    for i, line in enumerate(asm_lines):
        if ORG_RE.match(line):
            return asm_lines[:i], i
    return asm_lines, len(asm_lines)


def parse_address_from_line(line: str):
    m = re.match(r'^  ([0-9A-F]{6})  ', line)
    return int(m.group(1), 16) if m else None


def find_line_for_address(asm_lines, start_idx, target_addr):
    """Index of the first line at/after target_addr, backed up over the
    label, separator and blank lines that belong to it."""
    for i in range(start_idx, len(asm_lines)):
        addr = parse_address_from_line(asm_lines[i])
        if addr is not None and addr >= target_addr:
            j = i
            while j > start_idx:
                prev = asm_lines[j - 1].strip()
                if prev == "" or prev.startswith(";") or LABEL_RE.match(prev):
                    j -= 1
                else:
                    break
            return j
    return None


def parse_line(line: str):
    """(addr, mnemonic, operand, comment) for a listing line, or None."""
    m = LINE_RE.match(line.rstrip("\n"))
    if not m:
        return None
    im = INSTR_RE.match(m.group(3))
    if not im:
        return None
    return int(m.group(1), 16), im.group(1), (im.group(2) or "").strip(), (im.group(3) or "")


def memory_ranges_from_header(lines):
    ranges = []
    for line in lines:
        m = re.match(r'^;\s+\$([0-9A-F]{6})-\$([0-9A-F]{6}) \(', line)
        if m:
            ranges.append((int(m.group(1), 16), int(m.group(2), 16)))
        if line.startswith(CODE_MARKER):
            break
    return ranges


def split_operands(op: str):
    """Split an operand string on top-level commas: '$10(A0,D0.W),D1' ->
    ['$10(A0,D0.W)', 'D1']."""
    parts, depth, cur = [], 0, ""
    for ch in op:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append(cur)
            cur = ""
        else:
            cur += ch
    if cur:
        parts.append(cur)
    return [p.strip() for p in parts]


# ============================================================
# Pattern Annotator
# ============================================================

class PatternAnnotator:
    """Deterministic, pattern-based comments for listing chunks.
    annotate_file() rewrites a chunk in place and is idempotent."""

    def __init__(self, ref_dir: str):
        self.traps = {}       # word -> (name, manager)
        self.lowmem = {}      # addr -> (name, desc)
        self.hw = {}          # addr -> (name, desc)
        self.names = {}       # name -> addr (all tables)
        self.file_names = {}
        self._load_references(ref_dir)

    @staticmethod
    def _rows(path):
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line.startswith("|") or line.startswith("|--"):
                    continue
                parts = [p.strip() for p in line.strip("|").split("|")]
                if len(parts) >= 3 and parts[0].startswith("$"):
                    yield parts[0], parts[1], parts[2]

    def _load_references(self, ref_dir):
        for fn, tbl in (("mac_traps.md", self.traps), ("mac_lowmem.md", self.lowmem),
                        ("mac_hardware.md", self.hw)):
            p = os.path.join(ref_dir, fn)
            if not os.path.exists(p):
                continue
            for key, name, desc in self._rows(p):
                m = re.match(r'^\$([0-9A-Fa-f]{2,6})$', key)
                if m:
                    tbl[int(m.group(1), 16)] = (name, desc)
        # fall back to the built-in tables when reference/ is missing
        if not self.lowmem:
            self.lowmem = {**macsyms.EXCEPTION_VECTORS, **macsyms.LOWMEM}
        if not self.hw:
            self.hw = dict(macsyms.HARDWARE)
        for tbl in (self.lowmem, self.hw):
            for a, (n, _d) in tbl.items():
                self.names.setdefault(n, a)

    # ---------------- operand parsing ----------------

    def addr_of(self, operand: str):
        """Absolute / PC-relative operand -> address, else None."""
        op = operand.strip()
        m = re.match(r'^\((\$?[A-Za-z0-9_$+]+)\)\.[WL]$', op)
        if m:
            return self._value(m.group(1))
        m = re.match(r'^([A-Za-z0-9_$+]+)\(PC(?:,[DA][0-7]\.[WL])?\)$', op)
        if m:
            return self._value(m.group(1))
        return None

    def _value(self, s: str):
        s = s.strip()
        m = re.match(r'^\$([0-9A-Fa-f]+)$', s)
        if m:
            return int(m.group(1), 16) & 0xFFFFFF
        m = re.match(r'^(?:L|SUB|D)_([0-9A-F]{6})(?:\+(\d+))?$', s)
        if m:
            return int(m.group(1), 16) + int(m.group(2) or 0)
        m = re.match(r'^([A-Za-z_][A-Za-z0-9_]*)(?:\+(\d+))?$', s)
        if m:
            base = self.file_names.get(m.group(1), self.names.get(m.group(1)))
            if base is not None:
                return base + int(m.group(2) or 0)
        return None

    @staticmethod
    def names_from_file(lines):
        """Symbol -> address from a chunk's own text: header equates and
        label lines (NAME: followed by the next listing line)."""
        names, pending, rel = {}, [], []
        for line in lines:
            m = re.match(r'^([A-Za-z_]\w*)\s+EQU\s+\$([0-9A-Fa-f]{2,8})\b', line)
            if m:
                names[m.group(1)] = int(m.group(2), 16)
                continue
            m = re.match(r'^([A-Za-z_]\w*)\s+EQU\s+([A-Za-z_]\w*)\+(\d+)\b', line)
            if m:
                rel.append((m.group(1), m.group(2), int(m.group(3))))
                continue
            if LABEL_RE.match(line.strip()):
                pending.append(line.strip()[:-1])
                continue
            a = parse_address_from_line(line)
            if a is not None and pending:
                for n in pending:
                    names[n] = a
                pending = []
        for n, base, off in rel:
            if base in names:
                names[n] = names[base] + off
        return names

    # ---------------- per-file ----------------

    def annotate_file(self, filepath: str) -> int:
        with open(filepath) as f:
            lines = f.readlines()
        self.file_names = self.names_from_file(lines)
        ranges = memory_ranges_from_header(lines)
        is_rom = any(l.startswith("; ROM image:") for l in lines[:60])
        parsed = [parse_line(l) for l in lines]
        instr_idx = [i for i, p in enumerate(parsed) if p and not p[1].startswith(("DC.", "DCB."))]
        code_addrs = {parsed[i][0] for i in instr_idx}
        notes = {}

        def in_image(addr):
            return any(s <= addr <= e for s, e in ranges)

        regs = {}           # An -> ("VIA"|"IWM"|"SCCRd"|"SCCWr"|"ScrnBase", ...)
        prev_label_idx = set()
        for i, line in enumerate(lines):
            if LABEL_RE.match(line.strip()) and i + 1 < len(lines):
                prev_label_idx.add(i + 1)
        for k, i in enumerate(instr_idx):
            addr, mn, op, cm = parsed[i]
            if i in prev_label_idx:
                regs = {}
            prev = [parsed[j] for j in instr_idx[max(0, k - 4):k]]
            nxt = [parsed[j] for j in instr_idx[k + 1:k + 8]]
            note = self._analyze(addr, mn, op, cm, prev, nxt, regs,
                                 set() if is_rom else code_addrs, in_image)
            self._track_regs(mn, op, regs)
            if note:
                notes[i] = note

        added = 0
        for i, note in notes.items():
            line = lines[i].rstrip("\n")
            text = note.lstrip("; ").strip()
            if text in line:
                continue
            if parsed[i][3]:
                lines[i] = f"{line} | {text}\n"
            else:
                lines[i] = f"{line.ljust(70)}; {text}\n"
            added += 1
        with open(filepath, "w") as f:
            f.writelines(lines)
        return added

    def _track_regs(self, mn, op, regs):
        ops = split_operands(op)
        if len(ops) != 2 or not re.match(r'^(A[0-6]|SP)$', ops[1]):
            if ops and re.match(r'^A[0-6]$', ops[-1]):
                regs.pop(ops[-1], None)
            return
        dst, src = ops[1], ops[0]
        kind = None
        a = self.addr_of(src)
        if mn == "MOVEA.L" and a is not None:
            n = self.lowmem.get(a, ("",))[0]
            if n in ("VIA", "IWM", "SCCRd", "SCCWr", "ScrnBase", "SoundBase"):
                kind = n
        elif mn in ("MOVEA.L", "LEA"):
            m = re.match(r'^#?\(?\$([0-9A-F]+)\)?(?:\.L)?$', src)
            v = int(m.group(1), 16) if m else (a if mn == "LEA" else None)
            if v == macsyms.VIA_BASE:
                kind = "VIA"
            elif v == macsyms.IWM_BASE:
                kind = "IWM"
            elif v == macsyms.SCC_RD:
                kind = "SCCRd"
            elif v == macsyms.SCC_WR:
                kind = "SCCWr"
        if kind:
            regs[dst] = kind
        else:
            regs.pop(dst, None)

    def _reg_access(self, op, regs):
        """'$1C00(A1)' with A1 = VIA -> description."""
        for part in split_operands(op):
            m = re.match(r'^(-?\$[0-9A-F]+|0)?\((A[0-6])\)$', part)
            if not m or m.group(2) not in regs:
                continue
            off = int(m.group(1).replace("$", ""), 16) if m.group(1) and m.group(1) != "0" else 0
            if m.group(1) and m.group(1).startswith("-"):
                off = -int(m.group(1)[2:], 16)
            kind = regs[m.group(2)]
            if kind == "VIA":
                r = macsyms.via_reg_by_offset(off)
                if r:
                    return kind, off, f"VIA {r[0]}: {r[1]}"
            elif kind == "IWM":
                r = macsyms.iwm_reg_by_offset(off)
                if r:
                    return kind, off, f"IWM {r[0]}: {r[1]}"
            elif kind in ("SCCRd", "SCCWr") and off in SCC_OFFSETS:
                n, d = SCC_OFFSETS[off]
                return kind, off, f"SCC {'read' if kind == 'SCCRd' else 'write'} {n}: {d}"
            elif kind == "ScrnBase":
                return kind, off, f"screen buffer + ${off:X} (row {off // 64}, byte {off % 64} at 512x342)"
        return None

    def _analyze(self, addr, mn, op, cm, prev, nxt, regs, code_addrs, in_image):
        has_comment = len(cm.lstrip("; ").strip()) > 3
        base = mn.split(".")[0]
        ops = split_operands(op)

        # Pack selectors: MOVE.W #n,-(SP) before _PackN
        m = re.match(r'^_Pack(\d)\b', mn)
        if m and prev:
            p = prev[-1]
            sm = re.match(r'^#\$([0-9A-F]+),-\(SP\)$', p[2])
            if p[1] in ("MOVE.W",) and sm:
                sel = PACK_SELECTORS.get(int(m.group(1)), {}).get(int(sm.group(1), 16))
                if sel:
                    return f"; selector {int(sm.group(1), 16)}: {sel}"
        if mn.startswith("_HFSDispatch") and prev and prev[-1][1] == "MOVEQ":
            return f"; HFS call selector in D0 ({prev[-1][2].split(',')[0]})"

        # Pascal function result space before a toolbox trap
        if (mn in ("CLR.W", "CLR.L") and op == "-(SP)") or (mn in ("SUBQ.W", "SUBQ.L") and
                                                             re.match(r'^#\$[24],SP$', op)):
            for n in nxt[:6]:
                if n[1].startswith("_") and not n[1].startswith("_Pack"):
                    return f"; reserve space for {n[1]} function result"
                if n[1] in ("JSR", "BSR.S", "BSR.W"):
                    return "; reserve space for function result (Pascal calling convention)"
        if mn == "PEA" and op == "-$4(A5)" and nxt and nxt[0][1].startswith("_InitGraf"):
            return "; @thePort: QuickDraw globals live below A5"

        # Hardware access through a base register
        r = self._reg_access(op, regs)
        if r:
            kind, off, desc = r
            bm = re.match(r'^#\$([0-9A-F]+),', op)
            if kind == "VIA" and bm and base in ("BSET", "BCLR", "BTST", "BCHG"):
                bit = int(bm.group(1), 16)
                bits = macsyms.VIA_A_BITS if off in (0x1E00, 0x0200) else \
                    macsyms.VIA_B_BITS if off == 0 else {}
                if bit in bits:
                    verb = {"BSET": "set", "BCLR": "clear", "BTST": "test", "BCHG": "toggle"}[base]
                    return f"; {desc} - {verb} bit {bit} {bits[bit]}"
            if kind == "VIA" and off == 0x1C00 and mn == "MOVE.B" and op.startswith("#$"):
                v = int(op[2:4], 16)
                return f"; {desc} - {'enable' if v & 0x80 else 'disable'} mask ${v & 0x7F:02X}"
            return f"; {desc}"

        # Status register / interrupt level
        if mn == "MOVE.W" and op.endswith(",SR") and op.startswith("#$"):
            v = int(op[2:6], 16)
            return f"; SR = ${v:04X}: {'supervisor, ' if v & 0x2000 else 'user mode, '}" \
                   f"interrupt mask {(v >> 8) & 7}"
        if mn == "ORI.W" and op.endswith(",SR") and op.startswith("#$0700"):
            return "; disable interrupts (mask level 7)"
        if mn == "ANDI.W" and op.endswith(",SR") and op.startswith("#$F8FF"):
            return "; enable all interrupts (mask level 0)"
        if mn == "MOVE.W" and op == "SR,-(SP)":
            return "; save status register (interrupt level)"
        if mn == "MOVE.W" and op == "(SP)+,SR":
            return "; restore status register (interrupt level)"

        # Frames, register saves, Pascal returns
        if mn == "LINK":
            m = re.match(r'^A6,#-\$([0-9A-F]+)$', op)
            if m:
                return f"; stack frame: {int(m.group(1), 16)} bytes of locals at -n(A6)"
        if mn == "MOVEM.L" and op.endswith(",-(SP)") and not has_comment:
            return f"; save registers {ops[0]}"
        if mn == "MOVEM.L" and op.startswith("(SP)+,") and not has_comment:
            return f"; restore registers {ops[1]}"
        if mn == "JMP" and op == "(A0)" and len(prev) >= 2 and prev[-2][1] == "MOVEA.L" \
                and prev[-2][2] == "(SP)+,A0":
            m = re.match(r'^#\$([0-9A-F]+),SP$', prev[-1][2]) if prev[-1][1].startswith(("ADDQ", "ADDA",
                                                                                         "LEA")) else None
            return "; Pascal return: pop parameters" + (f" ({int(m.group(1), 16)} bytes)" if m else "") \
                + ", jump to caller"
        if mn == "RTD":
            return None

        # Version / machine checks
        if mn == "TST.W" and "ROM85" in op and nxt and nxt[0][1].startswith(("BPL", "BMI")):
            return "; ROM85 >= 0 means 128K ROM or later (Mac Plus+); negative = 64K ROM"

        # Low-memory globals: dasm already comments symbolic operands; add
        # read/write intent for well-known hooks
        for i_op, part in enumerate(ops):
            a = self.addr_of(part)
            if a is None or in_image(a):
                continue
            if a in macsyms.EXCEPTION_VECTORS and i_op == len(ops) - 1 and base == "MOVE":
                v = macsyms.EXCEPTION_VECTORS[a]
                return f"; install handler into {v[0]}" + ("" if has_comment else f": {v[1]}")
            if a in self.lowmem and not has_comment:
                n, d = self.lowmem[a]
                return f"; {n}: {d}"
            if a in self.hw and not has_comment:
                n, d = self.hw[a]
                return f"; {n}: {d}"

        # Loops
        if base.startswith("DB"):
            cnt = ops[0] if ops else "Dn"
            body = [p[1] + " " + p[2] for p in prev[-2:]]
            kind = ""
            if any(b.startswith("CLR.") and ")+" in b for b in body):
                kind = "clear memory "
            elif any(b.startswith("MOVE.") and "(A" in b and ")+," in b and b.endswith(")+")
                     for b in body):
                kind = "copy "
            return f"; {kind}loop: {cnt} counts down, runs {cnt}+1 times"

        # Self-modifying code (RAM programs)
        if base in ("MOVE", "ADDQ", "SUBQ", "ADD", "SUB", "CLR", "OR", "AND", "EOR", "NOT") and ops:
            t = self.addr_of(ops[-1])
            if t is not None and in_image(t):
                for back in (0, 2, 4):
                    if t - back in code_addrs and t - back != addr:
                        what = "opcode" if back == 0 else "operand"
                        return f"; self-modifying code: patches {what} of instruction at ${t - back:06X}"

        if mn == "RESET":
            return "; RESET: pulse the reset line to external devices"
        if mn == "STOP":
            return "; STOP: load SR and halt until an interrupt"
        if mn == "ILLEGAL":
            return "; ILLEGAL: illegal-instruction exception (debugger break)"
        if mn == "TRAP" and not has_comment:
            return "; TRAP: software exception through vector $80+4n"
        return None


# ============================================================
# Split
# ============================================================

def do_split(args):
    with open(args.asm) as f:
        asm_lines = f.readlines()
    with open(args.sections) as f:
        sections = json.load(f)
    os.makedirs(args.output_dir, exist_ok=True)
    header_lines, first_code_idx = extract_header(asm_lines)
    header_text = "".join(header_lines)
    manifest = {"source_asm": os.path.abspath(args.asm), "source_sections": os.path.abspath(args.sections),
                "total_chunks": len(sections), "chunks": []}
    for n, section in enumerate(sections):
        chunk_id = section["id"]
        start_hex, end_hex = section["start_addr_hex"], section["end_addr_hex"]
        start_addr = int(start_hex, 16)
        chunk_start = find_line_for_address(asm_lines, first_code_idx, start_addr)
        if chunk_start is None:
            print(f"Warning: start {start_hex} not in listing, skipping chunk {chunk_id}", file=sys.stderr)
            continue
        if n == 0:
            chunk_start = first_code_idx
        if n + 1 < len(sections):
            nxt = int(sections[n + 1]["start_addr_hex"], 16)
            chunk_end = find_line_for_address(asm_lines, chunk_start + 1, nxt) or len(asm_lines)
        else:
            chunk_end = len(asm_lines)
        chunk_lines = asm_lines[chunk_start:chunk_end]
        ctx = ["; =============================================",
               f"; CHUNK {chunk_id} of {len(sections)} -- {start_hex} to {end_hex} ({len(chunk_lines)} lines)",
               "; ============================================="]
        for key, title, limit in (("subroutines", "Subroutines", 40), ("traps", "Traps", 40),
                                  ("lowmem", "Low-memory globals", 40), ("hw_accesses", "Hardware", 30),
                                  ("self_modifying", "Self-modified", 20), ("calls_out", "Calls out", 15),
                                  ("called_from", "Called from", 10)):
            vals = section.get(key) or []
            if vals:
                ctx.append(f"; {title}: {', '.join(vals[:limit])}")
                if len(vals) > limit:
                    ctx.append(f";   (+{len(vals) - limit} more)")
        ctx += ["; =============================================", ""]
        chunk_filename = f"chunk_{chunk_id:02d}_{start_addr:06X}.asm"
        chunk_path = os.path.join(args.output_dir, chunk_filename)
        with open(chunk_path, "w") as f:
            f.write(header_text)
            f.write("\n")
            f.write("\n".join(ctx) + "\n")
            f.write(CODE_MARKER + "\n")
            if not any(ORG_RE.match(l) for l in chunk_lines[:6]):
                f.write(f"                 ORG     ${start_addr:06X}\n\n")
            f.write("".join(chunk_lines))
        manifest["chunks"].append({
            "id": chunk_id, "filename": chunk_filename, "path": os.path.abspath(chunk_path),
            "start_addr": start_hex, "end_addr": end_hex, "line_count": len(chunk_lines),
            "subroutines": section.get("subroutines", []), "traps": section.get("traps", []),
            "lowmem": section.get("lowmem", []), "hw_accesses": section.get("hw_accesses", []),
            "self_modifying": section.get("self_modifying", []),
        })
    manifest_path = os.path.join(args.output_dir, "manifest.json")
    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2)
    print(f"Split into {len(manifest['chunks'])} chunks in {args.output_dir}", file=sys.stderr)
    print(f"Manifest: {manifest_path}", file=sys.stderr)
    for c in manifest["chunks"]:
        print(f"  chunk_{c['id']:02d}: {c['start_addr']}-{c['end_addr']} ({c['line_count']} lines)",
              file=sys.stderr)


def _chunk_path(chunk_info, manifest_path):
    p = chunk_info["path"]
    if not os.path.exists(p):
        p = os.path.join(os.path.dirname(os.path.abspath(manifest_path)), chunk_info["filename"])
    return p


def do_annotate(args):
    with open(args.manifest) as f:
        manifest = json.load(f)
    annotator = PatternAnnotator(args.ref_dir)
    total = 0
    for c in manifest["chunks"]:
        added = annotator.annotate_file(_chunk_path(c, args.manifest))
        total += added
        print(f"  chunk_{c['id']:02d}: +{added} comments", file=sys.stderr)
    print(f"Annotation complete: {total} comments added across {len(manifest['chunks'])} chunks",
          file=sys.stderr)


# ============================================================
# Merge
# ============================================================

def strip_hex_columns(line: str) -> str:
    """'  400000  4E75   RTS ; c' -> '                 RTS ; c'"""
    m = LINE_RE.match(line.rstrip("\n"))
    if not m:
        return line
    return f"{'':17s}{m.group(3)}\n"


def do_merge(args):
    with open(args.manifest) as f:
        manifest = json.load(f)
    with open(_chunk_path(manifest["chunks"][0], args.manifest)) as f:
        first = f.readlines()
    header = []
    for i, line in enumerate(first):
        if line.strip().startswith("; CHUNK "):
            header = first[:i]
            break
    out = list(header)
    for c in manifest["chunks"]:
        with open(_chunk_path(c, args.manifest)) as f:
            lines = f.readlines()
        body_start = 0
        for i, line in enumerate(lines):
            if line.strip() == CODE_MARKER:
                body_start = i + 1
                break
        else:
            for i, line in enumerate(lines):
                if ORG_RE.match(line):
                    body_start = i
                    break
        out.append(f"\n; ---- Chunk {c['id']}: {c['start_addr']}-{c['end_addr']} ----\n")
        out.extend(lines[body_start:])
    if getattr(args, "reassemble", False):
        out = [strip_hex_columns(l) for l in out]
    text = "".join(out)
    if args.output:
        with open(args.output, "w") as f:
            f.write(text)
        print(f"Merged {len(manifest['chunks'])} chunks to {args.output}", file=sys.stderr)
    else:
        print(text)


# ============================================================
# Apply symbols
# ============================================================

def do_apply_symbols(args):
    """Rename generated labels (L_XXXXXX / SUB_XXXXXX / D_XXXXXX) to the
    names in a symbol file, across every chunk, keeping all comments.
    Names that would collide are skipped. Re-running the pipeline with
    --symbols gives the same names, so keep the file."""
    try:
        from tools.symbols import load_symbols
    except ImportError:
        from symbols import load_symbols
    table = load_symbols(args.apply_symbols)
    with open(args.manifest) as f:
        manifest = json.load(f)
    paths = [_chunk_path(c, args.manifest) for c in manifest["chunks"]]
    texts = {p: open(p).read() for p in paths}
    corpus = "\n".join(texts.values())
    existing = set(re.findall(r'^([A-Za-z_]\w*):$', corpus, re.M)) | \
        set(re.findall(r'^([A-Za-z_]\w*)\s+EQU', corpus, re.M))
    renames = {}
    for addr, name, _c in table.items():
        if "+" in name:
            continue
        for prefix in ("SUB", "L", "D"):
            old = f"{prefix}_{addr:06X}"
            if re.search(rf'\b{old}\b', corpus):
                if name in existing and name != old:
                    print(f"  skip {old} -> {name}: name already defined", file=sys.stderr)
                    break
                renames[old] = name
                existing.add(name)
                break
    if not renames:
        print("No generated labels matched the symbol file", file=sys.stderr)
        return
    pattern = re.compile(r'\b(' + "|".join(map(re.escape, renames)) + r')\b')
    for p, text in texts.items():
        new = pattern.sub(lambda m: renames[m.group(1)], text)
        if new != text:
            with open(p, "w") as f:
                f.write(new)
    for old, new in sorted(renames.items()):
        print(f"  {old} -> {new}", file=sys.stderr)
    print(f"Renamed {len(renames)} labels across {len(paths)} chunks", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(description="68000 disassembly splitter / annotator / merger")
    parser.add_argument("--split", action="store_true")
    parser.add_argument("--annotate", action="store_true")
    parser.add_argument("--merge", action="store_true")
    parser.add_argument("--asm", help="Listing from dasm68k.py (for --split)")
    parser.add_argument("--sections", help="Sections JSON from xref.py --sections (for --split)")
    parser.add_argument("--output-dir", help="Output directory (for --split)")
    parser.add_argument("--manifest", help="Manifest JSON (for --annotate/--merge/--apply-symbols)")
    parser.add_argument("--ref-dir", help="Reference directory (for --annotate)")
    parser.add_argument("--output", "-o", help="Output file (for --merge)")
    parser.add_argument("--reassemble", action="store_true",
                        help="With --merge: strip address/hex columns so vasm can assemble the result")
    parser.add_argument("--apply-symbols", nargs="+", metavar="FILE",
                        help="With --manifest: rename generated labels to the names in these symbol files")
    args = parser.parse_args()
    if args.apply_symbols:
        if not args.manifest:
            parser.error("--apply-symbols requires --manifest")
        do_apply_symbols(args)
    elif args.split:
        if not (args.asm and args.sections and args.output_dir):
            parser.error("--split requires --asm, --sections and --output-dir")
        do_split(args)
    elif args.annotate:
        if not (args.manifest and args.ref_dir):
            parser.error("--annotate requires --manifest and --ref-dir")
        do_annotate(args)
    elif args.merge:
        if not args.manifest:
            parser.error("--merge requires --manifest")
        do_merge(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
