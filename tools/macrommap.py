#!/usr/bin/env python3
"""
macrommap.py — build a structural map of a Macintosh ROM (or any 68000 image)
Usage: python3 macrommap.py <rom> [dasm flags] [--output map.md] [--json map.json]
                                  [--min-region 64] [--max-subs 5000]

Runs the dasm68k analysis plus xref, then writes a Markdown map:
  identity (model by checksum, checksum validity, version word, reset PC,
  header jumps), the machine address map, the ROM layout as regions (code /
  tables / text / fill / data, resources and driver headers), entry points,
  drivers, embedded resources, dispatch-table candidates, vector installs,
  a subroutine table with size, callers, callees, traps, low-memory globals,
  hardware touched and inferred role tags, per-device hardware usage,
  low-memory global readers/writers, strings and the largest data blocks
  (fonts, bitmaps, tables). --json writes the same data machine-readably.

Every fact in the map comes from the bytes (checksum, decoded code,
cross-references); role tags are heuristics and say so.
"""

import argparse
import bisect
import json
import sys
from collections import defaultdict

try:
    from tools.dasm68k import build_disassembler, add_common_args
    from tools.xref import CrossReferenceBuilder
    from tools.m68k import ea_address
    from tools import macsyms
except ImportError:
    from dasm68k import build_disassembler, add_common_args
    from xref import CrossReferenceBuilder
    from m68k import ea_address
    import macsyms

BASE_GLOBALS = {0x01D4: "VIA", 0x01E0: "IWM", 0x01D8: "SCC", 0x01DC: "SCC", 0x0824: "screen",
                0x0266: "sound"}
BASE_CONSTS = {macsyms.VIA_BASE: "VIA", macsyms.IWM_BASE: "IWM", macsyms.SCC_RD: "SCC",
               macsyms.SCC_WR: "SCC", macsyms.SCSI_RD: "SCSI", macsyms.SCSI_WR: "SCSI"}

LOWMEM_TAGS = {
    "Ticks": "timing", "VBLQueue": "VBL tasks", "EventQueue": "events", "KeyMap": "keyboard",
    "KeyLast": "keyboard", "Mouse": "mouse/cursor", "RawMouse": "mouse/cursor", "MTemp": "mouse/cursor",
    "TheCrsr": "mouse/cursor", "CrsrVis": "mouse/cursor", "ScrnBase": "screen", "SoundBase": "sound",
    "SoundPtr": "sound", "SysZone": "memory", "ApplZone": "memory", "TheZone": "memory",
    "HeapEnd": "memory", "MemTop": "memory", "BufPtr": "memory", "VCBQHdr": "file system",
    "FSQHdr": "file system", "DrvQHdr": "drives", "UTableBase": "device manager",
    "SysParam": "parameter RAM", "Time": "clock", "Lvl1DT": "interrupts", "Lvl2DT": "interrupts",
    "SonyVars": "floppy (Sony)", "SysMapHndl": "resources", "TopMapHndl": "resources",
    "CurMap": "resources", "WindowList": "windows", "MenuList": "menus", "ROMBase": "ROM",
    "SCCASts": "serial", "SCCBSts": "serial", "SerialVars": "serial", "ExtStsDT": "serial",
}


def classify_bytes(d, a):
    if a in d.owner:
        return "code"
    k = d.data_kind.get(a, "byte")
    if k in ("table", "pointer"):
        return "table"
    if k in ("string", "pstring", "macsbug"):
        return "text"
    if k in ("zero", "ff"):
        return "fill"
    return "data"


def layout_regions(d, notes, min_region=64):
    """Contiguous runs of one class, small runs folded into neighbours;
    resource / driver-header regions from the loader are annotated."""
    out = []
    for s, e in d.mem.get_contiguous_ranges():
        cur, start = None, s
        for a in range(s, e + 2):
            k = classify_bytes(d, a) if a <= e else None
            if k != cur:
                if cur is not None:
                    out.append([start, a - 1, cur])
                cur, start = k, a
    # fold small runs into the previous region (keeps code islands of real size)
    merged = []
    for r in out:
        size = r[1] - r[0] + 1
        if merged and size < min_region and r[2] != "code":
            merged[-1][1] = r[1]
            if merged[-1][2] != r[2]:
                merged[-1][3] = merged[-1][3] | {r[2]}
            continue
        if merged and merged[-1][2] == r[2] and r[0] == merged[-1][1] + 1:
            merged[-1][1] = r[1]
            continue
        merged.append([r[0], r[1], r[2], set()])
    res = []
    for s, e, k, mixed in merged:
        what = [n for (ns, ne, n) in notes if ns <= e and ne >= s]
        res.append({"start": s, "end": e, "size": e - s + 1,
                    "kind": k + (" (+" + ",".join(sorted(mixed)) + ")" if mixed else ""),
                    "contents": "; ".join(what[:4]) + (" ..." if len(what) > 4 else "")})
    return res


def routine_profile(x, d, ext):
    """Per subroutine: size, traps, low-mem, hardware (direct and through a
    base register loaded from VIA/IWM/SCC/ScrnBase or a hardware constant)."""
    prof = {}
    for s in x.local_subs():
        body = x.body_of(s, ext)
        regs = {}
        hw, lm, traps, calls = defaultdict(int), defaultdict(int), [], []
        for ins in body:
            if ins.trap:
                if ins.words[0] not in traps:
                    traps.append(ins.words[0])
                continue
            for t in x.calls_from.get(ins.pc, []):
                if t not in calls:
                    calls.append(t)
            ops = ins.ops
            # base register tracking
            if ins.mnemonic in ("MOVEA.L", "LEA") and len(ops) == 2 and ops[1][0] == "A":
                src, reg = ops[0], ops[1][1]
                kind = None
                if src[0] == "absW" and ins.mnemonic == "MOVEA.L":
                    kind = BASE_GLOBALS.get(ea_address(src))
                elif src[0] in ("absL", "imm"):
                    kind = BASE_CONSTS.get(src[1] & 0xFFFFFF)
                if kind:
                    regs[reg] = kind
                else:
                    regs.pop(reg, None)
            elif ops and ops[-1][0] == "A":
                regs.pop(ops[-1][1], None)
            for op in ops:
                if op[0] in ("d16A", "(A)", "idxA") and (op[2] if op[0] != "(A)" else op[1]) in regs:
                    hw[regs[op[2] if op[0] != "(A)" else op[1]]] += 1
                elif op[0] in ("absW", "absL"):
                    a = ea_address(op)
                    if d.mem.is_populated(a):
                        continue
                    if a in macsyms.HARDWARE or (macsyms.hw_region(a) and a >= 0x580000):
                        n = macsyms.HARDWARE.get(a, ("",))[0]
                        dev = "VIA" if a >= macsyms.VIA_BASE else "IWM" if a >= macsyms.IWM_BASE else \
                            "SCC" if a >= macsyms.SCC_RD else "SCSI" if a >= macsyms.SCSI_RD else "I/O"
                        hw[dev] += 1
                        if n.startswith("v"):
                            pass
                    elif a < 0x2000:
                        name = d.known_name(a) or f"${a:04X}"
                        lm[name] += 1
                elif op[0] == "imm" and op[2] == 4 and (op[1] & 0xFFFFFF) in BASE_CONSTS:
                    hw[BASE_CONSTS[op[1] & 0xFFFFFF]] += 1
        tags = set()
        for dev in hw:
            tags.add({"VIA": "VIA", "IWM": "floppy (IWM)", "SCC": "serial (SCC)", "SCSI": "SCSI",
                      "screen": "screen", "sound": "sound"}.get(dev, dev))
        for n in lm:
            if n in LOWMEM_TAGS:
                tags.add(LOWMEM_TAGS[n])
            if n in macsyms.LOWMEM.values():
                pass
        if body and body[-1].mnemonic == "RTE":
            tags.add("interrupt/exception handler")
        managers = {macsyms.trap_info(w)["manager"] for w in traps}
        for mgr in managers:
            tags.add("calls " + mgr)
        if d.labels.get(s, "").startswith("TRAP_"):
            tags.add("trap implementation")
        if d.labels.get(s, "").startswith("DRVR_"):
            tags.add("driver routine")
        prof[s] = {"size": ext[s] - s, "traps": traps, "lowmem": dict(lm), "hw": dict(hw),
                   "calls": calls, "tags": sorted(tags)}
    return prof


def build_map(d, info, x, min_region=64, max_subs=5000):
    ext = x.sub_extent()
    starts = sorted(ext)

    def _owner_sub(_ext, pc):
        i = bisect.bisect_right(starts, pc) - 1
        if i >= 0 and pc < ext[starts[i]]:
            return starts[i]
        return None

    prof = routine_profile(x, d, ext)
    notes = [(s, e, why) for s, e, why in info.get("data_regions", [])]
    for dv in info.get("drivers", []):
        notes.append((dv["addr"], dv["addr"] + 17, f"driver {dv['name']}"))
    regions = layout_regions(d, notes, min_region)
    total = sum(e - s + 1 for s, e in d.mem.get_contiguous_ranges())
    kinds = defaultdict(int)
    for s, e in d.mem.get_contiguous_ranges():
        for a in range(s, e + 1):
            kinds[classify_bytes(d, a)] += 1
    m = {
        "file": info["file"], "size": info["size"], "format": info["format"],
        "rom": info.get("rom"), "rom_name": info.get("rom_name"),
        "ranges": d.mem.get_contiguous_ranges(), "entry": info.get("entry"),
        "coverage": dict(kinds), "total": total,
        "regions": regions,
        "entries": [(a, n) for a, n in sorted(d.named_entries.items())],
        "drivers": info.get("drivers", []),
        "resources": info.get("resources", []),
        "dispatch_tables": [{k: v for k, v in t.items() if k != "targets"} for t in d.dispatch_tables],
        "vector_installs": [(pc, vec, h, d.labels.get(h)) for pc, vec, h in d.vector_installs],
        "auto_found": d.auto_found,
        "subroutines": [], "hardware": defaultdict(list), "lowmem": {}, "traps": {},
        "strings": [(a, t[:80], p) for a, t, p in x.strings],
        "notes": info.get("notes", []),
    }
    for s in x.local_subs()[:max_subs]:
        p = prof[s]
        m["subroutines"].append({
            "addr": s, "name": x.sub_name(s), "size": p["size"],
            "callers": len(x.calls_to.get(s, [])), "calls": [x.sub_name(t) for t in p["calls"]],
            "traps": [macsyms.trap_info(w)["display"].split(" ")[0] for w in p["traps"]],
            "lowmem": sorted(p["lowmem"]), "hw": p["hw"], "tags": p["tags"],
            "desc": d.describe(s)})
        for dev in p["hw"]:
            m["hardware"][dev].append(x.sub_name(s))
    for a, refs in sorted(x.lowmem.items()):
        rd = sorted({x.sub_name(_owner_sub(ext, r)) for r, k in refs if k == "r" and _owner_sub(ext, r)})
        wr = sorted({x.sub_name(_owner_sub(ext, r)) for r, k in refs if k == "w" and _owner_sub(ext, r)})
        m["lowmem"][f"${a:04X}"] = {"name": d.known_name(a) or "", "desc": d.describe(a),
                                    "readers": rd, "writers": wr}
    for w, refs in x.trap_calls.items():
        t = macsyms.trap_info(w)
        m["traps"][f"${w:04X}"] = {"name": t["display"], "manager": t["manager"], "count": len(refs),
                                   "callers": sorted({x.sub_name(_owner_sub(ext, r)) for r in refs
                                                      if _owner_sub(ext, r)})}
    big = [r for r in regions if not r["kind"].startswith("code") and r["size"] >= 512]
    m["data_blocks"] = sorted(big, key=lambda r: -r["size"])[:40]
    return m


def to_markdown(m) -> str:
    L = []
    title = m.get("rom_name") or m["format"]
    L += [f"# ROM Map: {m['file']}", "", f"_{title}_", "",
          "Generated by `tools/macrommap.py` from the image itself. Role tags are",
          "heuristics from traps, low-memory globals and hardware accesses: verify",
          "before relying on them.", ""]
    L += ["## Identity", "", "| Field | Value |", "|-------|-------|",
          f"| File | `{m['file']}` ({m['size']} bytes) |", f"| Format | {m['format']} |"]
    r = m.get("rom")
    if r:
        L += [f"| Model (by checksum) | {m['rom_name']} |",
              f"| Stored checksum | ${r['checksum']:08X} |",
              f"| Computed checksum | ${r['checksum_computed']:08X} "
              f"({'valid' if r['checksum_ok'] else 'MISMATCH: patched or bad dump'}) |",
              f"| Version word ($08) | ${r['version']:04X} "
              f"({macsyms.ROM_VERSIONS.get(r['version'] & 0xFF, 'unrecognized')}) |",
              f"| Reset PC ($04) | ${r['reset_pc']:06X} |"]
    for s, e in m["ranges"]:
        L.append(f"| Loaded at | ${s:06X}-${e:06X} |")
    L.append("")
    for n in m["notes"]:
        L.append(f"- {n}")
    L.append("")

    if r:
        L += ["## Machine Address Map (Mac 128K / 512K / Plus)", "",
              "| Range | Device |", "|-------|--------|"]
        for lo, hi, desc in macsyms.HW_RANGES:
            L.append(f"| ${lo:06X}-${hi:06X} | {desc} |")
        L += ["", "Screen buffer = top of RAM - $5900 (alternate: - $D900); sound buffer =",
              "top of RAM - $300 (alternate: - $5F00). E.g. 128K: $01A700 / $01FD00; 512K:",
              "$07A700 / $07FD00; 1MB Plus: $0FA700 / $0FFD00; 4MB Plus: $3FA700 / $3FFD00.", ""]

    cov, total = m["coverage"], max(m["total"], 1)
    L += ["## Coverage", "", "| Class | Bytes | % |", "|-------|------:|--:|"]
    for k in ("code", "table", "text", "fill", "data"):
        if cov.get(k):
            L.append(f"| {k} | {cov[k]} | {100 * cov[k] / total:.1f} |")
    L.append("")
    if m["auto_found"]:
        L += ["Auto-detected structures:", ""] + [f"- {a}" for a in m["auto_found"]] + [""]

    L += ["## ROM Layout", "", "| Start | End | Size | Kind | Contents |", "|-------|-----|-----:|------|----------|"]
    for g in m["regions"]:
        L.append(f"| ${g['start']:06X} | ${g['end']:06X} | {g['size']} | {g['kind']} | {g['contents']} |")
    L.append("")

    if m["entries"]:
        L += ["## Named Entry Points", "", "| Address | Name |", "|---------|------|"]
        for a, n in m["entries"]:
            L.append(f"| ${a:06X} | {n} |")
        L.append("")
    if m["drivers"]:
        L += ["## Device Drivers in ROM", "", "| Header | Name | Flags | Open | Prime | Control | Status | Close |",
              "|--------|------|-------|------|-------|---------|--------|-------|"]
        for dv in m["drivers"]:
            rt = dv["routines"]
            cells = " | ".join(f"${rt[k]:06X}" if k in rt else "-" for k in
                               ("Open", "Prime", "Control", "Status", "Close"))
            L.append(f"| ${dv['addr']:06X} | {dv['name']} | ${dv['flags']:04X} | {cells} |")
        L.append("")
    if m["resources"]:
        L += ["## Embedded Resources", "", "| Type | ID | Name | Address | Length |",
              "|------|---:|------|---------|-------:|"]
        for res in m["resources"]:
            a = f"${res['addr']:06X}" if "addr" in res else "-"
            L.append(f"| `{res['type']}` | {res['id']} | {res.get('name') or ''} | {a} | {res['length']} |")
        L.append("")
    if m["dispatch_tables"]:
        L += ["## Dispatch Table Candidates", ""]
        for t in m["dispatch_tables"]:
            L.append(f"- ${t['addr']:06X}: {t['entries']} entries of {t['stride']} bytes, {t['hits']} hit "
                     f"traced routine starts" + (f"; {t['trap_map']}" if t["trap_map"] else ""))
        L.append("")
    if m["vector_installs"]:
        L += ["## Vector / Hook Installs", "", "| At | Vector | Handler |", "|----|--------|---------|"]
        for pc, vec, h, name in m["vector_installs"]:
            vn = macsyms.EXCEPTION_VECTORS.get(vec, macsyms.LOWMEM.get(vec, (f"${vec:04X}",)))[0]
            L.append(f"| ${pc:06X} | {vn} (${vec:04X}) | {name or ''} ${h:06X} |")
        L.append("")

    if m["hardware"]:
        L += ["## Hardware Usage", "", "| Device | Routines |", "|--------|----------|"]
        for dev, subs in sorted(m["hardware"].items()):
            L.append(f"| {dev} | {', '.join(subs[:30])}{' ...' if len(subs) > 30 else ''} |")
        L.append("")
    if m["traps"]:
        L += ["## A-Traps Called from ROM Code", "", "| Trap | Name | Manager | Calls | Callers |",
              "|------|------|---------|------:|---------|"]
        for w, t in sorted(m["traps"].items(), key=lambda kv: -kv[1]["count"]):
            L.append(f"| {w} | {t['name']} | {t['manager']} | {t['count']} | "
                     f"{', '.join(t['callers'][:8])}{' ...' if len(t['callers']) > 8 else ''} |")
        L.append("")
    if m["lowmem"]:
        L += ["## Low-Memory Globals", "", "| Address | Name | Description | Readers | Writers |",
              "|---------|------|-------------|---------|---------|"]
        for a, g in m["lowmem"].items():
            L.append(f"| {a} | {g['name']} | {g['desc'][:48]} | "
                     f"{', '.join(g['readers'][:6])}{' ...' if len(g['readers']) > 6 else ''}"
                     f" | {', '.join(g['writers'][:6])}{' ...' if len(g['writers']) > 6 else ''} |")
        L.append("")

    L += ["## Subroutines", "",
          "| Address | Name | Size | Callers | Traps | Low-mem | HW | Tags |",
          "|---------|------|-----:|--------:|-------|---------|----|------|"]
    for s in m["subroutines"]:
        hw = ", ".join(f"{k}x{v}" for k, v in s["hw"].items())
        L.append(f"| ${s['addr']:06X} | {s['name']} | {s['size']} | {s['callers']} | "
                 f"{' '.join(s['traps'][:5])}{' ...' if len(s['traps']) > 5 else ''} | "
                 f"{' '.join(s['lowmem'][:4])}{' ...' if len(s['lowmem']) > 4 else ''} | {hw} | "
                 f"{', '.join(s['tags'])} |")
    L.append("")
    if m["data_blocks"]:
        L += ["## Largest Non-Code Blocks", "",
              "Fonts, cursors, patterns, bitmaps and tables usually live here.", "",
              "| Start | End | Size | Kind | Contents |", "|-------|-----|-----:|------|----------|"]
        for g in m["data_blocks"]:
            L.append(f"| ${g['start']:06X} | ${g['end']:06X} | {g['size']} | {g['kind']} | {g['contents']} |")
        L.append("")
    if m["strings"]:
        L += ["## Strings", ""]
        for a, t, p in m["strings"][:300]:
            L.append(f"- `${a:06X}` {'(Pascal) ' if p else ''}`{t}`")
        L.append("")
    return "\n".join(L) + "\n"


def main():
    p = argparse.ArgumentParser(description="Structural map of a Macintosh ROM / 68000 image")
    add_common_args(p)
    p.add_argument("--output", "-o", help="Markdown output (default: stdout)")
    p.add_argument("--json", help="Also write the map as JSON")
    p.add_argument("--min-region", type=int, default=64, help="Fold non-code runs smaller than this")
    p.add_argument("--max-subs", type=int, default=5000, help="Max subroutines in the table")
    a = p.parse_args()
    d, info = build_disassembler(a)
    x = CrossReferenceBuilder(d)
    x.analyze()
    m = build_map(d, info, x, a.min_region, a.max_subs)
    md = to_markdown(m)
    if a.output:
        with open(a.output, "w") as f:
            f.write(md)
        print(f"Map written to {a.output}", file=sys.stderr)
    else:
        sys.stdout.write(md)
    if a.json:
        with open(a.json, "w") as f:
            json.dump(m, f, indent=1, default=lambda o: sorted(o) if isinstance(o, set) else str(o))
        print(f"JSON written to {a.json}", file=sys.stderr)


if __name__ == "__main__":
    main()
