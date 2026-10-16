#!/usr/bin/env python3
"""
symbols.py — user symbol files for the 68000 tools
Usage: python3 symbols.py FILE [FILE ...]      (prints the merged table)

Accepted formats (auto-detected, mix freely with repeated --symbols):

1. JSON schema v1.0 (same shape as the orchard / Apple II sibling project):
     {"schema_version": "1.0", "categories": {"<cat>": {
         "0x40A2C4": {"name": "InitMem", "size": 1, "comment": "..."}}}}
   Keys must be "0x"/"$"-prefixed addresses (an "_suffix" such as "_dup" is
   ignored). size > 1 also names addr+1.. as NAME+1.. (unless those have
   their own names).
2. Flat JSON: {"0x40A2C4": "InitMem", "$400B00": {"name": "X", "comment": "..."}}
3. Text equates, one per line (vasm / Devpac / MPW style):
     InitMem   EQU $40A2C4 ; comment
     InitMem   =   $40A2C4
     $40A2C4   InitMem  comment
   ("#" / ";" / "*" start comment lines.)

First definition wins (a warning names the conflict), so list the most
specific file first. Names must be valid assembler identifiers (letters,
digits, '_' and '.' after the first character, not a register name).
Addresses are 24-bit (the 68000 address bus); larger values are masked.
"""

import json
import re
import sys

ADDR_MASK = 0xFFFFFF
IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
# Register names can't be labels
RESERVED = {f"D{i}" for i in range(8)} | {f"A{i}" for i in range(8)} | \
    {"SP", "SR", "CCR", "USP", "PC"}


class SymbolTable:
    """addr -> (name, comment) with first-write-wins semantics."""

    def __init__(self):
        self.by_addr: dict[int, tuple[str, str]] = {}
        # NAME+n aliases from size > 1; they only fill gaps
        self.aliases: dict[int, tuple[str, str]] = {}
        self.by_name: dict[str, int] = {}
        self.sources: list[str] = []

    def add(self, addr: int, name: str, comment: str = "", source: str = "") -> bool:
        base = name.split("+")[0]
        if not IDENT_RE.match(base) or base.upper() in RESERVED:
            print(f"warning: {source}: invalid symbol name {name!r} at ${addr:06X}, skipped",
                  file=sys.stderr)
            return False
        addr &= ADDR_MASK
        if addr in self.by_addr:
            old = self.by_addr[addr][0]
            if old != name:
                print(f"warning: {source}: ${addr:06X} already named {old!r}, ignoring {name!r}",
                      file=sys.stderr)
            return False
        if "+" not in name and name in self.by_name and self.by_name[name] != addr:
            print(f"warning: {source}: {name!r} already used for ${self.by_name[name]:06X}, "
                  f"ignoring ${addr:06X}", file=sys.stderr)
            return False
        self.by_addr[addr] = (name, comment)
        if "+" not in name:
            self.by_name[name] = addr
        return True

    def get(self, addr: int):
        return self.by_addr.get(addr) or self.aliases.get(addr)

    def name(self, addr: int):
        e = self.get(addr)
        return e[0] if e else None

    def comment(self, addr: int) -> str:
        e = self.by_addr.get(addr)
        return e[1] if e else ""

    def items(self):
        for a in sorted(self.by_addr):
            yield a, self.by_addr[a][0], self.by_addr[a][1]

    def __len__(self):
        return len(self.by_addr)

    def __contains__(self, addr):
        return addr in self.by_addr or addr in self.aliases

    # ---------------- loading ----------------

    def load(self, path: str):
        with open(path, encoding="utf-8") as f:
            text = f.read()
        if text.lstrip().startswith("{"):
            self._load_json(json.loads(text), path)
        else:
            self._load_text(text, path)
        self.sources.append(path)

    @staticmethod
    def _parse_key(key: str):
        k = key.strip()
        if k.startswith("$"):
            k = "0x" + k[1:]
        if not k.lower().startswith("0x"):
            return None
        try:
            return int(k[2:].split("_")[0], 16)
        except ValueError:
            return None

    def _add_sized(self, addr, name, comment, size, source):
        if self.add(addr, name, comment, source):
            for i in range(1, min(size or 1, 0x10000)):
                self.aliases.setdefault((addr + i) & ADDR_MASK, (f"{name}+{i}", comment))

    def _load_json(self, data: dict, source: str):
        if "categories" in data:
            for _cat, entries in data["categories"].items():
                if not isinstance(entries, dict):
                    continue
                for key, e in entries.items():
                    addr = self._parse_key(key)
                    if addr is None or not isinstance(e, dict) or "name" not in e:
                        continue
                    self._add_sized(addr, e["name"], e.get("comment", ""), e.get("size", 1), source)
            return
        for key, e in data.items():
            addr = self._parse_key(key)
            if addr is None:
                continue
            if isinstance(e, str):
                self.add(addr, e, "", source)
            elif isinstance(e, dict) and "name" in e:
                self._add_sized(addr, e["name"], e.get("comment", ""), e.get("size", 1), source)

    def _load_text(self, text: str, source: str):
        for raw in text.splitlines():
            line = raw.strip()
            if not line or line[0] in ";#*":
                continue
            comment = ""
            if ";" in line:
                line, comment = line.split(";", 1)
                line, comment = line.strip(), comment.strip()
            m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*):?\s*(?:=|:=|\bEQU\b|\bSET\b)\s*"
                         r"(?:\$|0x)([0-9A-Fa-f]{1,8})$", line, re.I)
            if m:
                self.add(int(m.group(2), 16), m.group(1), comment, source)
                continue
            m = re.match(r"^(?:\$|0x)?([0-9A-Fa-f]{4,8})\s+([A-Za-z_][A-Za-z0-9_]*)\s*(.*)$", line)
            if m:
                self.add(int(m.group(1), 16), m.group(2), comment or m.group(3).strip(), source)
                continue
            print(f"warning: {source}: unrecognised line {raw!r}", file=sys.stderr)

    # ---------------- saving ----------------

    def to_json(self, name: str = "user symbols", category: str = "user") -> str:
        """Schema v1.0 JSON. NAME+n aliases are folded back into the base
        entry's size."""
        cat = {}
        for a, n, c in self.items():
            cat[f"0x{a:06X}"] = {"name": n, "size": 1, "comment": c}
        for a, (n, _c) in self.aliases.items():
            base = n.split("+")[0]
            ba = self.by_name.get(base)
            if ba is not None and f"0x{ba:06X}" in cat:
                e = cat[f"0x{ba:06X}"]
                e["size"] = max(e["size"], int(n.split("+")[1]) + 1)
        return json.dumps({"schema_version": "1.0", "name": name, "categories": {category: cat}},
                          indent=2)


def load_symbols(paths) -> SymbolTable:
    t = SymbolTable()
    for p in paths:
        t.load(p)
    return t


def main():
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        print(__doc__)
        return
    t = load_symbols(sys.argv[1:])
    for a, n, c in t.items():
        print(f"{n:24s} EQU ${a:06X}" + (f"  ; {c}" if c else ""))
    print(f"; {len(t)} symbols", file=sys.stderr)


if __name__ == "__main__":
    main()
