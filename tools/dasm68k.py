#!/usr/bin/env python3
"""
dasm68k.py — 68000 disassembler engine for Macintosh ROMs and programs
Usage: python3 dasm68k.py <file> [--org 0x400000] [--entry 0x40002A] [--rsrc CODE:1]
                          [--annotate] [--no-hex] [--output file.s]

Strategy: recursive descent from the entry points (ROM reset PC, ROM header
jumps, driver routine offsets, CODE jump-table entries, 68000 vector table,
--entry, --table targets), following BSR/JSR/Bcc/DBcc/BRA/JMP. Computed
jumps through PC-relative tables (JMP tbl(PC,Dn) into a list of BRAs, or
MOVE.W tbl(PC,Dn),Dn + JMP tbl(PC,Dn) with word offsets) are recovered.
Handlers installed into exception vectors / low-memory hooks with
LEA x(PC),An + MOVE.L An,(vec).W are traced and named. Unreached bytes:
Pascal / C strings, fills, then a validated sweep (code only where it
follows real code or is referenced, and decodes cleanly to RTS/JMP/BRA),
then long-pointer tables and ROM dispatch-table candidates, re-traced to a
fixpoint. Everything else is DC.W / DC.B data.

Output is vasm Motorola syntax (vasmm68k_mot -Fbin -no-opt -m68000).
--no-hex output reassembles byte-exact; the default hex listing is what
annotator.py --split expects. Listing line contract (fixed columns):
    "  AAAAAA  HEX WORDS (24 columns)        MNEMONIC OPERANDS ; comment"
Keep that format stable — annotator.py parses it.
"""

import sys
import argparse
from collections import defaultdict

try:
    from tools.m68k import decode, format_instr, ea_address, Instr, sext16
    from tools.macloader import load_image
    from tools.m68k import format_operand
    from tools.symbols import load_symbols
    from tools import macsyms, atarisyms, platforms
except ImportError:
    from m68k import decode, format_instr, ea_address, Instr, sext16
    from m68k import format_operand
    from macloader import load_image
    from symbols import load_symbols
    import macsyms
    import atarisyms
    import platforms

MASK = 0xFFFFFF
TERMINAL_FLOWS = ("jump", "ret", "stop", "jump_ind")
HEX_COL = 24


# ===========================================================================
# MEMORY IMAGE
# ===========================================================================

class MemoryImage:
    """Sparse 24-bit memory image built from load segments."""
    # (lookups cache the last segment hit; images have few segments)

    def __init__(self):
        self.segs: list[tuple[int, bytes]] = []
        self._last = None

    def load_segment(self, addr: int, data: bytes):
        self.segs.append((addr, bytes(data)))
        self.segs.sort()

    def _seg(self, a: int):
        s = self._last
        if s and s[0] <= a < s[0] + len(s[1]):
            return s
        for s in self.segs:
            if s[0] <= a < s[0] + len(s[1]):
                self._last = s
                return s
        return None

    def is_populated(self, a: int) -> bool:
        return self._seg(a) is not None

    def byte_at(self, a: int):
        s = self._seg(a)
        return s[1][a - s[0]] if s else None

    def word_at(self, a: int):
        if a & 1:
            return None
        s = self._seg(a)
        if not s or a + 1 >= s[0] + len(s[1]):
            return None
        o = a - s[0]
        return (s[1][o] << 8) | s[1][o + 1]

    def long_at(self, a: int):
        h, l = self.word_at(a), self.word_at(a + 2)
        if h is None or l is None:
            return None
        return (h << 16) | l

    def get_contiguous_ranges(self) -> list:
        out = []
        for a, d in self.segs:
            if out and out[-1][1] + 1 == a:
                out[-1] = (out[-1][0], a + len(d) - 1)
            else:
                out.append((a, a + len(d) - 1))
        return out

    def addresses(self):
        for s, e in self.get_contiguous_ranges():
            yield from range(s, e + 1)


# ===========================================================================
# DATA DETECTION
# ===========================================================================

def is_text(b: int) -> bool:
    return 0x20 <= b < 0x7F and b != 0x5C      # backslash: vasm string escape


def detect_data_regions(mem: MemoryImage, free: set) -> dict:
    """Pascal strings, ASCII runs and $00/$FF fills among free bytes."""
    kinds = {}
    for s, e in mem.get_contiguous_ranges():
        a = s
        while a <= e:
            if a not in free:
                a += 1
                continue
            b = mem.byte_at(a)
            # Pascal string: length byte + that many text bytes
            if 3 <= b <= 80 and a + b <= e and all((a + i) in free and is_text(mem.byte_at(a + i))
                                                   for i in range(1, b + 1)):
                txt = bytes(mem.byte_at(a + i) for i in range(1, b + 1))
                if sum(chr(c).isalpha() for c in txt) * 2 >= len(txt):
                    for i in range(b + 1):
                        kinds[a + i] = "pstring"
                    a += b + 1
                    continue
            # ASCII run (optionally NUL-terminated)
            r = a
            while r <= e and r in free and is_text(mem.byte_at(r)):
                r += 1
            if r - a >= 6:
                txt = bytes(mem.byte_at(i) for i in range(a, r))
                if sum(chr(c).isalpha() or c == 0x20 for c in txt) * 4 >= len(txt) * 3:
                    for i in range(a, r):
                        kinds[i] = "string"
                    a = r
                    continue
            # fills
            if b in (0x00, 0xFF):
                r = a
                while r <= e and r in free and mem.byte_at(r) == b:
                    r += 1
                if r - a >= 8:
                    for i in range(a, r):
                        kinds[i] = "zero" if b == 0 else "ff"
                    a = r
                    continue
            a += 1
    return kinds


def macsbug_name(mem: MemoryImage, a: int):
    """MacsBug symbol after a routine's RTS/JMP(A0)/RTE: $80+len (1-31)
    then the name, or $80 then a length byte (long form). Returns
    (name, total_bytes incl. padding and the constant-data word) or None."""
    b = mem.byte_at(a)
    if b is None or not b & 0x80:
        return None
    if b == 0x80:
        n = mem.byte_at(a + 1)
        if not n or n > 255:
            return None
        start = a + 2
    else:
        n, start = b & 0x7F, a + 1
        if not 1 <= n <= 31:
            return None
    chars = [mem.byte_at(start + i) for i in range(n)]
    if None in chars or not all(c is not None and (chr(c).isalnum() or chr(c) in "_%.$")
                                for c in chars):
        return None
    if not chr(chars[0]).isalpha() and chr(chars[0]) not in "_%.":
        return None
    end = start + n
    if end & 1:
        end += 1                       # pad byte to even
    if mem.word_at(end) is not None and mem.word_at(end) < 0x100:
        end += 2                       # literal-constant size word (usually 0)
    return bytes(chars).decode("ascii"), end - a


# ===========================================================================
# DISASSEMBLER
# ===========================================================================

class Disassembler68k:
    def __init__(self, mem: MemoryImage, entry_addr=None, entries=None, named_entries=None,
                 fill="validated", tables=None, symbols=None, data_regions=None,
                 auto_tables=True, platform="generic", rom=None, rom_base=None, jump_table=None,
                 vector_table=False, segment=None, prologues=True, prg=None, tos=None):
        self.mem = mem
        self.entry_addr = entry_addr
        self.entries = list(entries or [])
        self.named_entries = dict(named_entries or {})     # addr -> name (loader / analysis)
        self.fill = fill
        self.user_tables = list(tables or [])
        self.sym = symbols if symbols is not None else load_symbols([])
        self.forced_data = set()
        self.data_notes = []
        for s, e, *why in (data_regions or []):
            for a in range(s, e + 1):
                if mem.is_populated(a):
                    self.forced_data.add(a)
        self.auto_tables = auto_tables
        self.plat = platforms.get(platform)
        self.mac = self.plat.name == "mac"
        self.atari = self.plat.name == "atari"
        self.rom = rom
        self.tos = tos                      # TOS ROM / cartridge header info (Atari)
        self.rom_name = rom.get("rom_name") if rom else (tos.get("name") if tos else None)
        # GEMDOS executable: relocations decide which longs are addresses
        self.prg = prg
        self.relocs: set[int] = set(prg["relocs"]) if prg else set()
        self.reloc_bytes: dict[int, int] = {r + i: r for r in self.relocs for i in range(4)}
        self._reloc_ctx = None
        self._cur_pc = None
        self.tos_calls: dict[int, tuple] = {}   # pc -> (system, name, fn)
        self.rom_base = rom_base
        self.jump_table = jump_table
        self.vector_table = vector_table
        self.segment = segment              # (CODE id, load base) for A5 jump-table calls
        self.prologues = prologues          # discover unreferenced routines by prologue
        self.prologue_found = 0
        self.a5_calls: dict[int, int] = {}  # pc -> resolved target (same segment)
        self.reg_calls: dict[int, int] = {} # pc -> target of JSR/JMP (An) with An known

        self._dcache: dict[int, Instr] = {}
        self.instrs: dict[int, Instr] = {}
        self.owner: dict[int, int] = {}
        self.traced: set[int] = set()
        self.swept: set[int] = set()
        self.data_kind: dict[int, str] = {}
        self.labels: dict[int, str] = {}
        self.call_targets: set[int] = set()
        self.jump_targets: set[int] = set()
        self.data_refs: dict[int, list] = defaultdict(list)
        self.code_hints: set[int] = set()
        self.table_entries: dict[int, tuple] = {}     # addr -> (size, target, kind, base)
        self.backward_branches: set[int] = set()
        self.auto_found: list[str] = []
        self.macsbug: dict[int, tuple] = {}            # addr -> (name, length)
        self.vector_installs: list[tuple] = []         # (pc, vector addr, handler)
        self.dispatch_tables: list[dict] = []
        self.descriptions: dict[int, str] = {}
        self.used_lowmem: set[int] = set()
        self.used_hw: set[int] = set()
        self.used_user: set[int] = set()
        self.used_traps: dict[int, str] = {}           # word -> ident
        self.bss_labels: dict[int, str] = {}
        self.mid_refs: dict[int, int] = {}
        self._analyzed = False
        self.lines = []
        self.line_len = {}

    # ---------------- decoding ----------------

    linef_calls = False      # TOS 1.x: $Fxxx words are compact AES/VDI calls

    def decode(self, pc: int):
        ins = self._dcache.get(pc)
        if ins is None:
            ins = decode(pc, self.mem.word_at, self.plat.linea)
            if ins is not None and not ins.valid and self.linef_calls and ins.words[0] >= 0xF000:
                ins = Instr(pc=pc, size=2, mnemonic="DC.W", ops=[], valid=True, words=ins.words)
                ins.linef = True
            if ins is not None:
                self._dcache[pc] = ins
        return ins

    def _can_place(self, ins) -> bool:
        for a in range(ins.pc, ins.end):
            if a in self.owner or a in self.data_kind or a in self.forced_data \
                    or not self.mem.is_populated(a):
                return False
            # GEMDOS executable: a relocated long may only be a 32-bit
            # extension field of this instruction; TEXT/DATA not crossed
            r = self.reloc_bytes.get(a)
            if r is not None and (r - ins.pc not in ins.longs or r + 4 > ins.end):
                return False
        if self.prg and ins.pc < self.prg["data_start"] < ins.end:
            return False
        return True

    def _place(self, ins, traced: bool, swept: bool = False):
        self.instrs[ins.pc] = ins
        for a in range(ins.pc, ins.end):
            self.owner[a] = ins.pc
        if traced:
            self.traced.add(ins.pc)
        elif swept:
            self.swept.add(ins.pc)

    def _record_refs(self, ins):
        for i, op in enumerate(ins.ops):
            k = op[0]
            if k == "branch":
                continue
            if k in ("absW", "absL", "d16PC", "idxPC"):
                a = ea_address(op)
                if ins.target is not None and a == ins.target and ins.mnemonic in ("JMP", "JSR"):
                    continue
                if self.mem.is_populated(a):
                    self.data_refs[a].append(ins.pc)
                    if ins.mnemonic in ("LEA", "PEA") and not a & 1:
                        self.code_hints.add(a)
            elif k == "imm" and op[2] == 4 and ins.mnemonic in ("MOVEA.L", "MOVE.L"):
                a = op[1]
                if a <= MASK and self.mem.is_populated(a) and not a & 1 and a > 0xFF:
                    self.data_refs[a].append(ins.pc)
        if ins.trap:
            self.used_traps[ins.words[0]] = ins.mnemonic

    # ---------------- tracing ----------------

    def _trace(self, work, core=True):
        work = list(work)
        while work:
            pc = work.pop()
            lea = {}                        # An -> address loaded by LEA x(PC)/abs in this run
            prev = None
            pushed = []                     # in-image addresses pushed on the stack in this run
            while True:
                if pc & 1 or not self.mem.is_populated(pc) or pc in self.instrs:
                    break
                ins = self.decode(pc)
                if ins is None or not ins.valid or not self._can_place(ins):
                    break
                if ins.target is not None and (ins.target & 1):
                    break                   # flow to an odd address: not real code
                self._place(ins, traced=core, swept=not core)
                self._record_refs(ins)
                self._note_vector_install(ins, lea, work)
                if ins.flow in ("branch", "call", "jump") and ins.target is not None:
                    t = ins.target & MASK
                    if ins.flow == "call":
                        self.call_targets.add(t)
                    else:
                        self.jump_targets.add(t)
                    if t <= pc:
                        self.backward_branches.add(pc)
                    if self.mem.is_populated(t):
                        work.append(t)
                if ins.flow == "jump_ind":
                    self._computed_jump(ins, prev, work)
                if ins.flow == "call_ind" and self.jump_table and self.segment:
                    self._a5_call(ins, work)
                if ins.flow in ("call_ind", "jump_ind") and ins.ops[0][0] == "(A)" \
                        and ins.ops[0][1] in lea:
                    t = lea[ins.ops[0][1]]
                    if not t & 1 and self.mem.is_populated(t):
                        self.reg_calls[ins.pc] = t
                        (self.call_targets if ins.flow == "call_ind" else self.jump_targets).add(t)
                        work.append(t)
                if ins.flow in ("ret", "jump_ind", "stop") or ins.mnemonic == "JMP":
                    self._check_macsbug(ins.end)
                if ins.flow in TERMINAL_FLOWS:
                    break
                if self.atari:
                    a = self._pushed_address(ins)
                    if a is not None:
                        pushed.append(a)
                    if ins.mnemonic == "TRAP":
                        call = self._tos_call(ins, prev)
                        if call:
                            self.tos_calls[ins.pc] = call
                            if self._tos_callback(call, pushed, work, ins.pc):
                                pushed = []
                            if call[0] == "GEMDOS" and call[2] in atarisyms.GEMDOS_NORETURN:
                                self._check_macsbug(ins.end)
                                break       # Pterm / Pterm0 / Ptermres
                prev = ins
                pc = ins.end

    # ---------------- Atari TOS calls ----------------

    def _pushed_address(self, ins):
        """PEA x / MOVE.L #x,-(SP) of an even in-image address."""
        a = None
        if ins.mnemonic == "PEA" and ins.ops[0][0] in ("d16PC", "absL"):
            a = ea_address(ins.ops[0])
        elif ins.mnemonic == "MOVE.L" and ins.ops[1] == ("-(A)", 7) and ins.ops[0][0] == "imm":
            a = ins.ops[0][1]
        if a is not None and a <= MASK and not a & 1 and self.mem.is_populated(a):
            return a
        return None

    def _tos_call(self, ins, prev):
        """(system, name, fn) for TRAP #1/#13/#14 after MOVE.W #fn,-(SP)
        (or CLR.W -(SP) = function 0), and TRAP #2 after D0 = 200 / 115."""
        n = ins.ops[0][1]
        if prev is None:
            return None
        if n == 2:
            if prev.mnemonic in ("MOVE.W", "MOVEQ", "MOVE.L") and prev.ops[0][0] in ("imm", "simm") \
                    and prev.ops[1] == ("D", 0) and prev.ops[0][1] in atarisyms.GEM_CALLS:
                g = atarisyms.GEM_CALLS[prev.ops[0][1]]
                return (g, f"{g} call", prev.ops[0][1])
            return None
        fn = None
        if prev.mnemonic == "MOVE.W" and prev.ops[1] == ("-(A)", 7) and prev.ops[0][0] == "imm":
            fn = prev.ops[0][1]
        elif prev.mnemonic == "CLR.W" and prev.ops[0] == ("-(A)", 7):
            fn = 0
        if fn is None:
            return None
        r = atarisyms.call_name(n, fn)
        return (r[0], r[1], fn) if r else None

    def _tos_callback(self, call, pushed, work, pc) -> bool:
        """Supexec(func), Setexc(n, vec), Xbtimer(.., vec), Mfpint(n, vec):
        the pushed routine address is code."""
        if not pushed or (call[0], call[1]) not in (("XBIOS", "Supexec"), ("BIOS", "Setexc"),
                                                    ("XBIOS", "Xbtimer"), ("XBIOS", "Mfpint")):
            return False
        a = pushed[-1]
        name = {"Supexec": "Supexec_Func", "Setexc": "Setexc_Handler", "Xbtimer": "Xbtimer_Handler",
                "Mfpint": "Mfpint_Handler"}[call[1]]
        if a not in self.named_entries:
            self.named_entries[a] = name
            self.descriptions[a] = f"passed to {call[0]} {call[1]} at ${pc:06X}"
        self.call_targets.add(a)
        work.append(a)
        return True

    def _find_tos_calls(self):
        """TOS calls in swept / filled code (the tracer records traced ones)."""
        for pc, ins in self.instrs.items():
            if ins.mnemonic == "TRAP" and pc not in self.tos_calls:
                p = self.owner.get(pc - 1)
                prev = self.instrs.get(p) if p is not None else None
                if prev is not None and prev.end == pc:
                    call = self._tos_call(ins, prev)
                    if call:
                        self.tos_calls[pc] = call

    def _note_vector_install(self, ins, lea, work):
        """LEA x(PC),An / MOVE.L An,(vec).W  or  MOVE.L #x,(vec).W:
        handler x is installed into an exception vector or low-memory hook."""
        m, ops = ins.mnemonic, ins.ops
        if m == "LEA":
            if ops[0][0] in ("d16PC", "absL", "absW"):
                lea[ops[1][1]] = ea_address(ops[0])
            else:
                lea.pop(ops[1][1], None)
            return
        if m == "MOVEA.L" and ops[1][0] == "A":
            if ops[0][0] == "imm" and ops[0][1] <= MASK:
                lea[ops[1][1]] = ops[0][1]
            else:
                lea.pop(ops[1][1], None)
            return
        if m != "MOVE.L" or len(ops) != 2 or ops[1][0] not in ("absW", "absL"):
            if ops and ops[-1][0] == "A":
                lea.pop(ops[-1][1], None)         # An overwritten
            return
        vec = ea_address(ops[1])
        src = ops[0]
        handler = None
        if src[0] == "A" and src[1] in lea:
            handler = lea[src[1]]
        elif src[0] == "imm" and src[1] <= MASK:
            handler = src[1]
        if handler is None or handler & 1 or not self.mem.is_populated(handler):
            return
        name = None
        if vec in self.plat.vectors and (self.plat.name != "generic" or self.vector_table or vec < 0x100):
            name = self.plat.vectors[vec][0].replace("Vct", "").replace("Vec", "") + "_Handler"
        elif vec in self.plat.hooks:
            name = self.plat.lowmem[vec][0] + "_Proc"
        if name is None:
            return
        self.vector_installs.append((ins.pc, vec, handler))
        if handler not in self.named_entries:
            self.named_entries[handler] = name
            self.descriptions[handler] = f"installed into {self.plat.lowmem_name(vec)}" \
                                         f" (${vec:04X}) at ${ins.pc:06X}"
        self.call_targets.add(handler)
        work.append(handler)

    def _a5_call(self, ins, work):
        """JSR d16(A5) through the application jump table: resolve calls
        into the segment being disassembled."""
        op = ins.ops[0]
        if op[0] != "d16A" or op[2] != 5:
            return
        seg, base = self.segment
        for e in self.jump_table:
            if e["a5_offset"] == op[1] and e["segment"] == seg:
                t = base + 4 + e["offset"]
                if self.mem.is_populated(t) and not t & 1:
                    self.a5_calls[ins.pc] = t
                    self.call_targets.add(t)
                    work.append(t)
                return

    def _check_macsbug(self, a: int):
        if a in self.owner or a in self.macsbug:
            return
        r = macsbug_name(self.mem, a)
        if r:
            name, n = r
            self.macsbug[a] = r
            for i in range(n):
                self.data_kind[a + i] = "macsbug"

    def _computed_jump(self, ins, prev, work):
        """JMP tbl(PC,Xn): a list of BRA/JMP instructions at tbl, or a word
        offset table read by the preceding MOVE.W tbl2(PC,Xn),Xm."""
        op = ins.ops[0]
        if op[0] != "idxPC":
            return
        base = op[1]
        first = self.decode(base)
        if first and first.valid and (first.mnemonic.startswith("BRA") or
                                      (first.mnemonic == "JMP" and first.target is not None)):
            a, n = base, 0
            while n < 256:
                e = self.decode(a)
                if not e or not e.valid or not (e.mnemonic.startswith("BRA") or
                                                (e.mnemonic == "JMP" and e.target is not None)):
                    break
                work.append(a)
                self.jump_targets.add(a)
                a, n = e.end, n + 1
            if n >= 2:
                self.auto_found.append(f"branch table at ${base:06X}: {n} entries (JMP at ${ins.pc:06X})")
            return
        if not (prev and prev.mnemonic == "MOVE.W" and prev.ops[0][0] == "idxPC"
                and prev.ops[1][0] == "D" and op[2] == (False, prev.ops[1][1])):
            return
        tbl = prev.ops[0][1]
        a, targets, lo = tbl, [], None
        while len(targets) < 512:
            w = self.mem.word_at(a)
            if w is None or a in self.owner or (a != tbl and (a in self.jump_targets or a in self.call_targets)):
                break
            t = base + sext16(w)
            if t & 1 or not self.mem.is_populated(t) or tbl <= t < a + 2:
                break
            if lo is not None and a >= lo:
                break
            targets.append((a, t))
            if t > tbl:
                lo = t if lo is None else min(lo, t)
            a += 2
        if len(targets) < 2:
            return
        for a, t in targets:
            self.table_entries[a] = (2, t, "rel", base)
            self.data_kind[a] = self.data_kind[a + 1] = "table"
            self.jump_targets.add(t)
            work.append(t)
        self.labels.setdefault(base, f"L_{base:06X}")
        self.auto_found.append(f"word offset table at ${tbl:06X}: {len(targets)} entries "
                               f"relative to ${base:06X} (JMP at ${ins.pc:06X})")

    # ---------------- tables ----------------

    def _mark_user_tables(self) -> list:
        work = []
        for t in self.user_tables:
            a, kind = t["addr"], t["kind"]
            for i in range(t["count"]):
                if kind == "long":
                    v = self.mem.long_at(a)
                    size, tgt, tb = 4, (v or 0) & MASK, None
                elif kind == "word":
                    v = self.mem.word_at(a)
                    size, tgt, tb = 2, (v | 0xFF0000 if v and v & 0x8000 else (v or 0)), None
                else:
                    v = self.mem.word_at(a)
                    base = t["base"] if t["base"] is not None else t["addr"]
                    size, tgt, tb = 2, base + sext16(v or 0), base
                if v is None:
                    break
                self.table_entries[a] = (size, tgt, kind, tb)
                for j in range(size):
                    self.data_kind[a + j] = "table"
                if tb is not None:
                    self.labels.setdefault(tb, f"L_{tb:06X}")
                if not tgt & 1 and self.mem.is_populated(tgt):
                    work.append(tgt)
                    self.jump_targets.add(tgt)
                a += size
        return work

    def _free(self, a: int) -> bool:
        return a not in self.owner and a not in self.data_kind and a not in self.forced_data

    def routine_starts(self) -> set:
        s = set(self.call_targets) | set(self.named_entries)
        s |= {t for _sz, t, _k, _b in self.table_entries.values()}
        for pc, ins in self.instrs.items():
            if ins.flow in TERMINAL_FLOWS and ins.end in self.instrs:
                s.add(ins.end)
        return s

    def _detect_pointer_tables(self) -> list:
        """Runs of >= 4 longs whose first 4 entries all point at known routine
        entries in the image; later entries continue while they are even
        in-image addresses."""
        starts = self.routine_starts()
        work = []
        for s, e in self.mem.get_contiguous_ranges():
            a = s + (s & 1)
            while a + 16 <= e:
                if not all(self._free(a + i) for i in range(16)):
                    a += 2
                    continue
                vals = [self.mem.long_at(a + 4 * i) for i in range(4)]
                if not all(v is not None and (v & MASK) in starts and v <= MASK for v in vals) \
                        and not self._near_code_pointers(a, vals):
                    a += 2
                    continue
                while a - 4 >= s and all(self._free(a - 4 + i) for i in range(4)):
                    v = self.mem.long_at(a - 4)
                    if v is None or v > MASK or v & 1 or v not in self.instrs:
                        break
                    a -= 4
                n, b = 0, a
                while b + 4 <= e + 1 and all(self._free(b + i) for i in range(4)):
                    v = self.mem.long_at(b)
                    if v is None or v > MASK or v & 1 or not self.mem.is_populated(v):
                        break
                    if v not in starts and v not in self.instrs:
                        ins = self.decode(v)
                        if not ins or not ins.valid or not self._free(v):
                            break
                    self.table_entries[b] = (4, v, "long", None)
                    for i in range(4):
                        self.data_kind[b + i] = "pointer"
                    work.append(v)
                    (self.call_targets if v in starts else self.jump_targets).add(v)
                    n, b = n + 1, b + 4
                self.auto_found.append(f"pointer table at ${a:06X}: {n} longs")
                a = b
        return work

    def _near_code_pointers(self, a: int, vals) -> bool:
        """Four longs that look like a switch table: even, inside the image
        and within 32K of the table, each decoding to a valid instruction
        on free or instruction-start bytes. Only for images whose base is
        >= $10000 (at 0, small integers would look like pointers)."""
        base = self.mem.get_contiguous_ranges()[0][0]
        if base < 0x10000:
            return False
        for v in vals:
            if v is None or v > MASK or v & 1 or not self.mem.is_populated(v) or abs(v - a) > 0x8000:
                return False
            if not (v in self.instrs or self._free(v)):
                return False
            ins = self.decode(v)
            if not ins or not ins.valid:
                return False
        return len(set(vals)) >= 2

    def _detect_dispatch_tables(self) -> list:
        """ROM images: tables of 16-bit offsets from the ROM base, or 32-bit
        addresses, where most entries land on routine starts found by
        tracing. A 512-entry word table in a 64K ROM matches the 64K-ROM trap
        dispatch table layout (OS traps $00-$4F, Toolbox $50-$1FF)."""
        if self.rom_base is None:
            return []
        starts = self.routine_starts()
        work = []
        (s, e), = self.mem.get_contiguous_ranges()[:1] or [(0, -1)]
        for stride in (2, 4):
            for phase in range(0, stride, 2):
                a = s + phase
                run_start, hits, n, misses_tail = None, 0, 0, 0
                while a + stride <= e + 1:
                    if stride == 2:
                        w = self.mem.word_at(a)
                        t = self.rom_base + w if w is not None else None
                    else:
                        v = self.mem.long_at(a)
                        t = v & MASK if v is not None and v <= MASK else None
                    ok_free = self._free(a)
                    hit = ok_free and t is not None and t in starts
                    if run_start is None:
                        if hit:
                            run_start, hits, n, misses_tail = a, 1, 1, 0
                    else:
                        if not ok_free:
                            misses_tail = 99
                        n += 1
                        if hit:
                            hits += 1
                            misses_tail = 0
                        else:
                            misses_tail += 1
                        if misses_tail > 6:
                            n -= misses_tail
                            if n >= 64 and hits >= 0.6 * n:
                                work += self._register_dispatch(run_start, n, stride, starts)
                            run_start = None
                    a += stride
                if run_start is not None and n >= 64 and hits >= 0.6 * n:
                    work += self._register_dispatch(run_start, n - misses_tail, stride, starts)
        return work

    def _register_dispatch(self, start, n, stride, starts) -> list:
        work, hits = [], 0
        kind = "romword" if stride == 2 else "long"
        entries = []
        for i in range(n):
            a = start + i * stride
            if stride == 2:
                t = self.rom_base + self.mem.word_at(a)
            else:
                t = self.mem.long_at(a) & MASK
            entries.append(t)
            hits += t in starts
            self.table_entries[a] = (stride, t, kind, None)
            for j in range(stride):
                self.data_kind[a + j] = "table"
            if not t & 1 and self.mem.is_populated(t):
                ins = self.decode(t)
                if ins and ins.valid:
                    work.append(t)
        info = {"addr": start, "entries": n, "stride": stride, "hits": hits, "targets": entries,
                "trap_map": None}
        rom_size = sum(len(d) for _a, d in self.mem.segs)
        if stride == 2 and n == 512 and rom_size == 0x10000 and self.mac:
            info["trap_map"] = "64K ROM layout: index < $50 = OS trap, else Toolbox trap (inferred)"
            for i, t in enumerate(entries):
                name = macsyms.OS_TRAPS.get(i) if i < 0x50 else macsyms.TOOL_TRAPS.get(i)
                if name and self.mem.is_populated(t) and t not in self.named_entries:
                    self.named_entries[t] = "TRAP_" + name
                    self.descriptions[t] = f"_{name} implementation (from dispatch table at ${start:06X})"
        self.dispatch_tables.append(info)
        self.auto_found.append(f"dispatch table candidate at ${start:06X}: {n} "
                               f"{'ROM-relative words' if stride == 2 else 'longs'}, "
                               f"{hits} hit traced routine starts"
                               + (f"; {info['trap_map']}" if info["trap_map"] else ""))
        return work

    # ---------------- sweep ----------------

    def _vouched(self, a: int) -> bool:
        if a in self.jump_targets or a in self.call_targets or a in self.code_hints \
                or a in self.named_entries:
            return True
        p = self.owner.get(a - 2)
        if p is not None and p in self.instrs:
            ins = self.instrs[p]
            if ins.end == a and ins.flow in TERMINAL_FLOWS and (p in self.traced or p in self.swept):
                return True
        # right after a MacsBug name that follows real code
        return False

    def _block_ok(self, start: int, end: int) -> bool:
        pc, n = start, 0
        while pc <= end:
            ins = self.decode(pc)
            if ins is None or not ins.valid or ins.end - 1 > end:
                return False
            if ins.target is not None and (ins.target & 1 or not self.mem.is_populated(ins.target)):
                return False
            for a in range(ins.pc, ins.end):
                if not self._free(a):
                    return False
            n += 1
            if ins.flow in TERMINAL_FLOWS:
                if n < 2:
                    return False
                raw = [self.mem.byte_at(a) for a in range(start, ins.end)]
                letters = sum(chr(b).isalpha() or b == 0x20 for b in raw)
                return not (len(raw) >= 8 and letters * 10 >= len(raw) * 9)   # reads as text
            pc = ins.end
        return False

    def _fill_validated(self):
        for _ in range(50):
            changed = False
            for s, e in self.mem.get_contiguous_ranges():
                a = s + (s & 1)
                while a <= e:
                    if not self._free(a):
                        a += 2 if not a & 1 else 1
                        continue
                    if a & 1:
                        a += 1
                        continue
                    gap = a
                    while a <= e and self._free(a):
                        a += 1
                    start = gap
                    if self._vouched(gap):
                        # alignment padding ($0000 / NOP / $FFFF words) before a routine
                        while start + 2 < a and start - gap < 16 and \
                                self.mem.word_at(start) in (0x0000, 0x4E71, 0xFFFF) and \
                                not self._block_ok(start, a - 1):
                            start += 2
                    if self._vouched(gap) and self._block_ok(start, a - 1):
                        before = len(self.instrs)
                        self._trace([start], core=False)
                        if len(self.instrs) > before:
                            changed = True
                            a = gap             # rest of the gap may hold more routines
            if not changed:
                break

    def _is_prologue(self, a: int) -> bool:
        """LINK An,#-n (n >= 0, even) or MOVEM.L <regs>,-(SP) saving at least
        two registers: how compiled and hand-written routines usually start."""
        ins = self.decode(a)
        if ins is None or not ins.valid:
            return False
        if ins.mnemonic == "LINK":
            disp = ins.ops[1][1]
            return disp <= 0 and not disp & 1
        if ins.mnemonic == "MOVEM.L" and ins.ops[1] == ("-(A)", 7):
            return bin(ins.ops[0][1]).count("1") >= 2
        return False

    def _prologue_scan(self) -> bool:
        """Trace unreferenced routines that start with a prologue inside data
        gaps, when the block decodes cleanly to a terminal."""
        found = False
        for s, e in self.mem.get_contiguous_ranges():
            a = s + (s & 1)
            while a < e:
                w = self.mem.word_at(a)
                if w in (0x4E56, 0x48E7) and self._free(a) and self._is_prologue(a):
                    g = a
                    while g <= e and self._free(g):
                        g += 1
                    if self._block_ok(a, g - 1):
                        before = len(self.instrs)
                        self._trace([a], core=False)
                        if len(self.instrs) > before:
                            self.call_targets.add(a)
                            self.prologue_found += 1
                            found = True
                a += 2
        return found

    def _fill_linear(self):
        for s, e in self.mem.get_contiguous_ranges():
            pc = s + (s & 1)
            while pc <= e:
                if not self._free(pc) or pc & 1:
                    pc += 1
                    continue
                ins = self.decode(pc)
                if ins is None or not ins.valid or ins.end - 1 > e or not self._can_place(ins):
                    pc += 2
                    continue
                self._place(ins, traced=False)
                self._record_refs(ins)
                pc = ins.end

    # ---------------- analysis ----------------

    def analyze(self):
        if self._analyzed:
            return
        self._analyzed = True
        entries = []
        if self.entry_addr is not None:
            entries.append(self.entry_addr)
            self.call_targets.add(self.entry_addr)
        for a in self.entries:
            entries.append(a)
            self.call_targets.add(a)
        for a in self.named_entries:
            entries.append(a)
            self.call_targets.add(a)
        entries += self._mark_user_tables()
        for r in self.relocs:
            t = self.mem.long_at(r)
            if t is not None and not t & 1 and self.prg["text_start"] <= t < self.prg["data_start"]:
                self.code_hints.add(t)
        if not entries:
            r = self.mem.get_contiguous_ranges()
            if r:
                entries.append(r[0][0] + (r[0][0] & 1))
        self._trace(list(reversed(entries)))

        def free_set():
            return {a for a in self.mem.addresses() if self._free(a) and a not in self.reloc_bytes}

        # Sweep before string detection: 68000 code is often printable
        # ("Nu" = RTS), so text detection only gets what the sweep rejects
        for rnd in range(10):
            before = len(self.instrs)
            if self.fill == "validated":
                self._fill_validated()
                if self.prologues and self._prologue_scan():
                    self._fill_validated()
            self.data_kind.update(detect_data_regions(self.mem, free_set()))
            if self.auto_tables:
                self._trace(self._detect_pointer_tables(), core=False)
                self._trace(self._detect_dispatch_tables(), core=False)
            if len(self.instrs) == before and rnd:
                break
        if self.fill == "all":
            self._fill_linear()
        if self.atari:
            self._find_tos_calls()
        # GEMDOS executable: relocated longs outside code are pointers
        for r in sorted(self.relocs):
            if r not in self.owner and all(r + i not in self.owner for i in range(4)):
                t = self.mem.long_at(r)
                self.table_entries[r] = (4, t, "long", None)
                for i in range(4):
                    self.data_kind[r + i] = "pointer"
        for a in self.mem.addresses():
            if a not in self.owner:
                self.data_kind.setdefault(a, "byte")
        self._make_labels()

    def in_bss(self, addr: int) -> bool:
        return bool(self.prg) and self.prg["bss_start"] <= addr <= self.prg["bss_end"]

    def _make_labels(self):
        if self.prg:
            for r in self.relocs:
                t = self.mem.long_at(r)
                if t is None:
                    continue
                if self.mem.is_populated(t):
                    self.data_refs[t].append(self.owner.get(r, r))
                else:
                    self.bss_labels.setdefault(t, None)
            for pc, ins in self.instrs.items():
                for op in ins.ops:
                    if op[0] in ("d16PC", "idxPC", "branch"):
                        a = ea_address(op)
                        if not self.mem.is_populated(a):
                            self.bss_labels.setdefault(a, None)
            for a in list(self.bss_labels):
                n = self.sym.name(a) if self.sym.name(a) and "+" not in self.sym.name(a) else None
                self.bss_labels[a] = n or self.named_entries.get(a) or f"B_{a:06X}"
        for addr in list(self.data_refs):
            if not self.mem.is_populated(addr) or addr in self.labels:
                continue
            if addr in self.named_entries:
                self.labels[addr] = self.named_entries[addr]
            elif addr in self.owner and self.owner[addr] == addr:
                self.labels[addr] = f"L_{addr:06X}"
            elif addr in self.owner:
                self.labels[addr] = f"L_{addr:06X}"
            else:
                self.labels[addr] = f"D_{addr:06X}"
        for addr in sorted(self.call_targets | self.jump_targets | set(self.named_entries)):
            if not self.mem.is_populated(addr):
                continue
            if addr in self.named_entries:
                self.labels[addr] = self.named_entries[addr]
            elif addr not in self.labels or self.labels[addr].startswith(("L_", "D_")):
                if addr in self.call_targets and self.owner.get(addr) == addr:
                    self.labels[addr] = f"SUB_{addr:06X}"
                else:
                    self.labels.setdefault(addr, f"L_{addr:06X}")
        for _size, tgt, _k, base in self.table_entries.values():
            if self.mem.is_populated(tgt):
                self.labels.setdefault(tgt, f"L_{tgt:06X}")
            if base is not None and self.mem.is_populated(base):
                self.labels.setdefault(base, f"L_{base:06X}")
        # MacsBug names name the routine they close (if still generic)
        for a, (name, _n) in self.macsbug.items():
            start = max((s for s in self.call_targets if s < a and self.owner.get(s) == s), default=None)
            if start is not None and self.labels.get(start, "").startswith(("SUB_", "L_", "JT_")) \
                    and name.isidentifier() and name not in self.labels.values():
                self.labels[start] = name
        # user symbols win
        for addr, name, _c in self.sym.items():
            if "+" in name or not self.mem.is_populated(addr):
                continue
            if addr in self.owner and self.owner[addr] != addr and addr not in self.labels:
                continue
            self.labels[addr] = name
        # make names unique (keep the first)
        seen = {}
        for addr in sorted(self.labels):
            n = self.labels[addr]
            if n in seen and seen[n] != addr:
                self.labels[addr] = f"{n}_{addr:06X}"
            else:
                seen[n] = addr
        self.mid_refs = {}
        for addr in list(self.labels):
            cover = self.owner.get(addr)
            if cover is not None and cover != addr:
                self.mid_refs[addr] = cover
                self.labels.setdefault(cover, f"L_{cover:06X}")

    # ---------------- naming ----------------

    def _vectors_on(self) -> bool:
        return self.plat.name != "generic" or self.vector_table

    def known_name(self, addr: int):
        """Name of an address outside generated labels: user > built-in."""
        n = self.sym.name(addr)
        if n:
            return n
        if addr in self.named_entries:
            return self.named_entries[addr]
        if addr in self.bss_labels:
            return self.bss_labels[addr]
        if not self.mem.is_populated(addr):
            if addr in self.plat.vectors and self._vectors_on():
                return self.plat.vectors[addr][0]
            if addr in self.plat.lowmem:
                return self.plat.lowmem[addr][0]
            if addr in self.plat.hardware:
                return self.plat.hardware[addr][0]
        return None

    def describe(self, addr: int) -> str:
        c = self.sym.comment(addr)
        if c:
            return c
        if addr in self.descriptions:
            return self.descriptions[addr]
        if not self.mem.is_populated(addr):
            if addr in self.plat.vectors and self._vectors_on():
                return self.plat.vectors[addr][1]
            for tbl in (self.plat.lowmem, self.plat.hardware):
                if addr in tbl:
                    return tbl[addr][1]
        return ""

    def addr_label(self, addr: int) -> str:
        return self.labels.get(addr) or self.known_name(addr) or f"${addr:06X}"

    def _user_ref(self, addr: int):
        n = self.sym.name(addr)
        if not n:
            return None
        base = n.split("+")[0]
        base_addr = self.sym.by_name.get(base)
        if base_addr is None:
            return None
        if self.mem.is_populated(base_addr):
            if self.labels.get(base_addr) != base:
                return None
        else:
            self.used_user.add(base_addr)
        return n

    def _sym(self, addr: int, kind: str):
        plat = self.plat
        # sign-extended hardware equates ($FFFF8240): usable as (x).W and (x).L
        if kind == "absL" and addr > MASK:
            a = addr & MASK
            if plat.hw_sext and a in plat.hardware and plat.hw_equate(a) == addr:
                self.used_hw.add(a)
                return plat.hardware[a][0]
            return None
        if addr > MASK:
            return None
        if kind == "absW" and addr >= 0x8000:
            if plat.hw_sext and addr in plat.hardware:
                self.used_hw.add(addr)
                return plat.hardware[addr][0]
            return None
        # GEMDOS executable: only relocated longs may name image / BSS addresses
        if self.prg and kind in ("absL", "imm") and not self._reloc_ctx and \
                (self.mem.is_populated(addr) or self.in_bss(addr)):
            return None
        if self.mem.is_populated(addr):
            if addr in self.labels:
                return self.labels[addr]
            return self._user_ref(addr)
        if addr in self.bss_labels:
            return self.bss_labels[addr]
        if self.prg and kind in ("pc", "branch") and self._cur_pc is not None:
            d = addr - self._cur_pc
            return f"*+${d:X}" if d >= 0 else f"*-${-d:X}"
        u = self._user_ref(addr)
        if u:
            return u
        if kind in ("absW", "absL"):
            if self._vectors_on() and addr in plat.vectors:
                self.used_lowmem.add(addr)
                return plat.vectors[addr][0]
            if addr in plat.lowmem:
                self.used_lowmem.add(addr)
                return plat.lowmem[addr][0]
            if kind == "absL" and addr in plat.hardware and not plat.hw_sext:
                self.used_hw.add(addr)
                return plat.hardware[addr][0]
        return None

    def _format(self, ins):
        """(mnemonic, operands) with relocation context per long operand."""
        if not ins.valid or ins.trap:
            return format_instr(ins, self._sym)
        if ins.mnemonic == "DC.W":                       # line-F word traced as code
            return "DC.W", f"${ins.words[0]:04X}"
        self._cur_pc = ins.pc
        parts, li = [], 0
        for op in ins.ops:
            if op[0] == "absL" or (op[0] == "imm" and op[2] == 4):
                pos = ins.pc + ins.longs[li] if li < len(ins.longs) else None
                li += 1
                self._reloc_ctx = pos in self.relocs if self.prg else None
            else:
                self._reloc_ctx = None
            parts.append(format_operand(op, self._sym))
        self._reloc_ctx = None
        self._cur_pc = None
        return ins.mnemonic, ",".join(parts)

    def operand_comment(self, ins) -> str:
        if ins.trap:
            t = ins.trap
            extra = ""
            if self.mac and t["name"].startswith("Pack") and t["name"][4:].isdigit():
                extra = f": {macsyms.PACK_NAMES.get(int(t['name'][4:]), '')}"
            elif t.get("desc"):
                extra = f": {t['desc']}"
            return f"; {t['display']} ({t['manager']}{extra})"
        if ins.pc in self.tos_calls:
            sysname, name, fn = self.tos_calls[ins.pc]
            if sysname in ("AES", "VDI"):
                return f"; {sysname} call (parameter block in D1)"
            d = atarisyms.CALL_DESC.get(name)
            return f"; {sysname} {name} (function ${fn:02X})" + (f": {d}" if d else "")
        if getattr(ins, "linef", False):
            return "; line-F word (TOS 1.x: compact AES/VDI subroutine call)"
        for op in ins.ops:
            if op[0] in ("absW", "absL"):
                a = ea_address(op)
                if self.mem.is_populated(a):
                    continue
                c = self.sym.comment(a)
                if c:
                    return f"; {c}"
                d = self.describe(a)
                if d:
                    return f"; {d}"
                d = self.plat.hw_desc(a) if a >= 0x400000 else None
                if d:
                    return f"; {d}"
            elif op[0] == "d16A" and op[2] == 5 and self.jump_table:
                for e in self.jump_table:
                    if e["a5_offset"] == op[1] and ins.mnemonic in ("JSR", "JMP", "PEA"):
                        return f"; jump table entry {e['index']}: CODE {e['segment']} +${e['offset']:04X}"
        return ""

    # ---------------- output ----------------

    def instr_hex(self, ins) -> str:
        h = " ".join(f"{w:04X}" for w in ins.words)
        if len(h) > HEX_COL:
            h = h[:HEX_COL - 4] + " ..."
        return h

    @staticmethod
    def _quote(raw: bytes) -> str:
        """vasm DC.B operand list: quoted text runs, numbers for the rest."""
        parts, buf = [], ""
        for b in raw:
            if is_text(b):
                buf += "''" if b == 0x27 else chr(b)
            else:
                if buf:
                    parts.append(f"'{buf}'")
                    buf = ""
                parts.append(f"${b:02X}")
        if buf:
            parts.append(f"'{buf}'")
        return ",".join(parts)

    @staticmethod
    def _bytes_hex(raw: bytes) -> str:
        groups = [raw[i:i + 2].hex().upper() for i in range(0, len(raw), 2)]
        h = " ".join(groups[:4])
        return h + (" ..." if len(groups) > 4 else "")

    def _build_lines(self, annotate: bool):
        self.lines = []
        ranges = self.mem.get_contiguous_ranges()
        for rs, re_ in ranges:
            pc = rs
            while pc <= re_:
                if pc in self.instrs:
                    ins = self.instrs[pc]
                    mn, opnd = self._format(ins)
                    comment = self.operand_comment(ins)
                    if annotate:
                        if ins.mnemonic in ("JSR", "BSR.S", "BSR.W", "JMP") and ins.target is not None \
                                and not comment:
                            d = self.describe(ins.target)
                            comment = f"; {d}" if d else ""
                        overlaps = [a for a, c in self.mid_refs.items() if c == pc]
                        if overlaps:
                            what = ", ".join(f"{self.labels[a]} (+{a - pc})" for a in sorted(overlaps))
                            note = f"overlapping entry/ref: {what}"
                            comment = f"{comment} | {note}" if comment else f"; {note}"
                        if pc in self.backward_branches:
                            comment = (comment + " (loop)") if comment else "; loop back"
                    self.lines.append((pc, self.instr_hex(ins), mn, opnd, comment))
                    pc = ins.end
                    continue
                if pc in self.table_entries:
                    size, tgt, kind, base = self.table_entries[pc]
                    if kind == "rel":
                        s = self.labels.get(tgt) or f"${tgt:06X}"
                    else:
                        self._reloc_ctx = (pc in self.relocs) if self.prg else None
                        s = self._sym(tgt, "absL") or f"${tgt:06X}"
                        self._reloc_ctx = None
                    raw = bytes(self.mem.byte_at(pc + i) for i in range(size))
                    if kind == "rel":
                        bl = self.labels.get(base) or f"${base:06X}"
                        self.lines.append((pc, raw.hex().upper(), "DC.W", f"{s}-{bl}",
                                           "; jump table offset"))
                    elif kind == "romword":
                        self.lines.append((pc, raw.hex().upper(), "DC.W", f"{s}-${self.rom_base:06X}",
                                           "; ROM-relative routine offset"))
                    elif kind == "word":
                        self.lines.append((pc, raw.hex().upper(), "DC.W", f"${raw.hex().upper()}",
                                           f"; -> {s}"))
                    else:
                        v = self.mem.long_at(pc)
                        opnd = s if v <= MASK else f"${v:08X}"
                        self.lines.append((pc, raw.hex().upper(), "DC.L", opnd, "; pointer"))
                    pc += size
                    continue
                kind = self.data_kind.get(pc, "byte")
                if kind == "macsbug" and pc in self.macsbug:
                    name, n = self.macsbug[pc]
                    raw = bytes(self.mem.byte_at(pc + i) for i in range(n))
                    self.lines.append((pc, self._bytes_hex(raw), "DC.B", self._quote(raw),
                                       f"; MacsBug symbol: {name}"))
                    pc += n
                    continue
                if kind in ("string", "pstring"):
                    a = pc
                    limit = 1 + self.mem.byte_at(pc) if kind == "pstring" else 48
                    while a <= re_ and self.data_kind.get(a) == kind and (a == pc or a not in self.labels) \
                            and a - pc < max(limit, 1) and not (kind == "pstring" and a - pc >= 64):
                        a += 1
                    raw = bytes(self.mem.byte_at(i) for i in range(pc, a))
                    what = "Pascal string" if kind == "pstring" and self.mem.byte_at(pc) == a - pc - 1 \
                        else "ASCII"
                    self.lines.append((pc, self._bytes_hex(raw), "DC.B", self._quote(raw), f"; {what}"))
                    pc = a
                    continue
                if kind in ("zero", "ff"):
                    a = pc
                    while a <= re_ and self.data_kind.get(a) == kind and (a == pc or a not in self.labels):
                        a += 1
                    fill = 0 if kind == "zero" else 0xFF
                    if a - pc >= 4:
                        self.lines.append((pc, f"{fill:02X}{fill:02X} ...", "DCB.B", f"{a - pc},${fill:02X}",
                                           f"; {a - pc} bytes of ${fill:02X}"))
                        pc = a
                        continue
                # plain data: DC.W at even addresses (up to 4 words), DC.B otherwise
                def plain(a):
                    return a <= re_ and a not in self.instrs and a not in self.table_entries \
                        and (self.data_kind.get(a, "byte") in ("byte", "table", "pointer", "macsbug")
                             or (a == pc)) and (a == pc or a not in self.labels)
                a = pc
                while plain(a) and a - pc < 8:
                    a += 1
                n = a - pc
                if pc & 1 or n < 2:
                    raw = bytes([self.mem.byte_at(pc)])
                    self.lines.append((pc, raw.hex().upper(), "DC.B", f"${raw[0]:02X}", self._txt(raw)))
                    pc += 1
                    continue
                n &= ~1
                raw = bytes(self.mem.byte_at(pc + i) for i in range(n))
                words = [f"${raw[i]:02X}{raw[i + 1]:02X}" for i in range(0, n, 2)]
                self.lines.append((pc, self._bytes_hex(raw), "DC.W", ",".join(words), self._txt(raw)))
                pc += n
        ends = {s: e for s, e in ranges}
        starts = sorted(ends)
        pcs = [ln[0] for ln in self.lines]
        self.line_len = {}
        for i, pc in enumerate(pcs):
            rng_end = next(ends[s] for s in reversed(starts) if s <= pc)
            nxt = pcs[i + 1] if i + 1 < len(pcs) and pcs[i + 1] <= rng_end else rng_end + 1
            self.line_len[pc] = nxt - pc

    @staticmethod
    def _txt(raw: bytes) -> str:
        return "; " + "".join(chr(b) if is_text(b) else "." for b in raw)

    def disassemble(self, show_hex: bool = True, annotate: bool = False) -> str:
        self.analyze()
        self._build_lines(annotate)
        return self._format_output(show_hex, annotate)

    def _format_output(self, show_hex: bool, annotate: bool) -> str:
        out = []
        line_starts = {pc for (pc, *_r) in self.lines}
        out.append("; =============================================")
        if self.prg:
            flags = f" -tos-flags={self.prg['flags']}" if self.prg["flags"] else ""
            out.append(f"; 68000 disassembly (vasm Motorola syntax: vasmm68k_mot -Ftos -nosym -no-opt"
                       f" -m68000{flags})")
        else:
            out.append("; 68000 disassembly (vasm Motorola syntax: vasmm68k_mot -Fbin -no-opt -m68000)")
        out.append("; =============================================")
        out.append(f"; Platform: {self.plat.name} ({self.plat.title})")
        if self.rom_name and self.rom:
            r = self.rom
            out.append(f"; ROM image: {self.rom_name}")
            out.append(f"; ROM checksum ${r['checksum']:08X} ({'valid' if r['checksum_ok'] else 'mismatch'}),"
                       f" version ${r['version']:04X}, reset PC ${r['reset_pc']:06X}")
        elif self.rom_name and self.tos:
            out.append(f"; ROM image: {self.rom_name}")
            for line in self.tos.get("summary", []):
                out.append(f"; {line}")
        if self.prg:
            p = self.prg
            out.append("; Relocatable GEMDOS executable (TEXT/DATA/BSS sections)")
            out.append(f"; TEXT ${p['text_len']:X} bytes, DATA ${p['data_len']:X}, BSS ${p['bss_len']:X},"
                       f" {len(self.relocs)} relocations, program flags ${p['flags']:X}"
                       + (f", symbol table ${p['sym_len']:X} bytes (not rebuilt)" if p["sym_len"] else ""))
        out.append("                 MC68000")
        out.append("")

        if self.used_traps:
            out.append("; =============================================")
            out.append({"mac": "; A-line traps (Macintosh Toolbox / OS)",
                        "atari": "; Line-A graphics calls"}.get(self.plat.name, "; Line-A words"))
            out.append("; =============================================")
            for word in sorted(self.used_traps):
                t = self.plat.linea(word)
                out.append(f"{t['ident']:16s} MACRO")
                out.append(f"                 DC.W    ${word:04X}          ; {t['display']} - {t['manager']}")
                out.append("                 ENDM")
            out.append("")

        def equ_block(title, addrs, table):
            if not addrs:
                return
            out.append("; =============================================")
            out.append(f"; {title}")
            out.append("; =============================================")
            for a in addrs:
                n, d = table[a]
                v = self.plat.hw_equate(a) if table is self.plat.hardware else a
                fmt = f"${v:04X}" if v < 0x10000 else (f"${v:06X}" if v <= MASK else f"${v:08X}")
                out.append(f"{n:16s} EQU     {fmt}" + (f"  ; {d}" if d else ""))
            out.append("")

        plat = self.plat
        lm = sorted(a for a in self.used_lowmem if not self.mem.is_populated(a))
        vecs = [a for a in lm if a in plat.vectors and self._vectors_on()]
        equ_block("Exception vectors", vecs, plat.vectors)
        equ_block({"mac": "Low-memory system globals", "atari": "TOS system variables"}.get(
            plat.name, "System variables"), [a for a in lm if a not in vecs], plat.lowmem)
        equ_block(f"Hardware ({plat.title})",
                  sorted(a for a in self.used_hw if not self.mem.is_populated(a)), plat.hardware)
        ue = sorted(a for a in self.used_user if not self.mem.is_populated(a))
        equ_block("User symbols", ue, {a: (self.sym.name(a), self.sym.comment(a)) for a in ue})

        mid = sorted(a for a, name in self.labels.items()
                     if a not in line_starts and self.mem.is_populated(a))
        if mid:
            out.append("; =============================================")
            out.append("; Mid-instruction / mid-data references")
            out.append("; =============================================")
            for addr in mid:
                cover = self.mid_refs.get(addr)
                if cover is not None and cover in line_starts and cover in self.instrs:
                    out.append(f"{self.labels[addr]:16s} EQU     {self.labels[cover]}+{addr - cover}"
                               f"  ; inside {self.instrs[cover].mnemonic} at ${cover:06X}")
                elif self.prg:
                    base = max((a for a in line_starts if a <= addr and a in self.labels), default=None)
                    out.append(f"{self.labels[addr]:16s} EQU     {self.labels[base]}+{addr - base}"
                               if base is not None else f"{self.labels[addr]:16s} EQU     ${addr:06X}")
                else:
                    out.append(f"{self.labels[addr]:16s} EQU     ${addr:06X}")
            out.append("")

        ranges = self.mem.get_contiguous_ranges()
        out.append("; =============================================")
        out.append(f"; Memory ranges: {len(ranges)}")
        for s, e in ranges:
            out.append(f";   ${s:06X}-${e:06X} ({e - s + 1} bytes)")
        if self.entry_addr is not None:
            out.append(f"; Entry: ${self.entry_addr:06X}")
        n_swept = len(self.swept)
        n_filled = len(self.instrs) - len(self.traced) - n_swept
        out.append(f"; Traced instructions: {len(self.traced)}, swept: {n_swept}, filled: {n_filled}"
                   f" (fill mode: {self.fill})")
        code_bytes = len(self.owner)
        total = sum(e - s + 1 for s, e in ranges)
        out.append(f"; Code bytes: {code_bytes} of {total} ({100 * code_bytes // max(total, 1)}%)")
        if self.prologue_found:
            out.append(f"; Routines found by prologue (LINK / MOVEM.L -(SP)): {self.prologue_found}")
        for note in self.auto_found:
            out.append(f"; Auto-detected {note}")
        for pc, vec, h in self.vector_installs:
            out.append(f"; Vector install at ${pc:06X}: ${vec:04X} <- {self.labels.get(h, hex(h))}")
        if self.sym.sources:
            out.append(f"; Symbols: {', '.join(self.sym.sources)} ({len(self.sym)} entries)")
        out.append("; =============================================")
        out.append("")

        prev_end = None
        prev_was_data = False
        for (pc, hex_bytes, mnemonic, operand, comment) in self.lines:
            if self.prg:
                if prev_end is None or pc == self.prg["data_start"]:
                    out.append("")
                    out.append("                 " + ("TEXT" if prev_end is None and
                                                     pc < self.prg["data_start"] else "DATA"))
                    out.append("")
            elif prev_end is None or pc > prev_end + 1:
                out.append("")
                out.append(f"                 ORG     ${pc:06X}")
                out.append("")
            label_str = self.labels.get(pc, "")
            if annotate:
                is_data = mnemonic.startswith(("DC.", "DCB.")) and pc not in self.instrs
                if label_str.startswith("SUB_") or (label_str and pc in self.call_targets
                                                    and not label_str.startswith(("L_", "D_"))):
                    d = self.describe(pc)
                    out.append("")
                    out.append(f"; ---- {label_str}{': ' + d if d else ''} ----")
                if is_data and not prev_was_data:
                    if "string" in comment or "ASCII" in comment:
                        out.append("; ---- Data: text ----")
                    elif mnemonic == "DCB.B":
                        out.append(f"; ---- Data: fill ({operand}) ----")
                    elif "pointer" in comment or "offset" in comment:
                        out.append("; ---- Table ----")
                    elif "MacsBug" not in comment:
                        out.append("; ---- Data ----")
                prev_was_data = is_data
            instr = f"{mnemonic:8s}{operand}" if operand else mnemonic
            if len(mnemonic) >= 8 and operand:
                instr = f"{mnemonic} {operand}"
            instr = instr.ljust(34) if len(instr) < 34 else instr + " "
            if show_hex:
                if label_str:
                    out.append(f"{label_str}:")
                out.append(f"  {pc:06X}  {hex_bytes:{HEX_COL}s}  {instr}{comment}")
            else:
                if label_str and len(label_str) > 15:
                    out.append(f"{label_str}:")
                    label_str = ""
                lab = f"{label_str}:" if label_str else ""
                out.append(f"{lab:16s} {instr}{comment}")
            prev_end = pc + self.line_len[pc] - 1
        if self.prg:
            out += self._bss_lines(show_hex)
        return "\n".join(line.rstrip() for line in out) + "\n"

    def _bss_lines(self, show_hex: bool) -> list:
        """BSS section: DS.B runs with a label at every referenced address;
        references past the end become EQUs relative to the last label."""
        p = self.prg
        out = ["", "                 BSS", ""]
        start, end = p["bss_start"], p["bss_start"] + p["bss_len"]
        pos = start
        inside = sorted(a for a in self.bss_labels if start <= a <= end)
        beyond = sorted(a for a in self.bss_labels if a > end or a < start)
        for a in sorted(set(inside) | {end}):
            if a > pos:
                txt = f"{'':16s} DS.B    {a - pos}"
                out.append(f"  {pos:06X}  {'':{HEX_COL}s}  DS.B    {a - pos}" if show_hex else txt)
                pos = a
            if a in self.bss_labels:
                out.append(f"{self.bss_labels[a]}:")
        if beyond:
            anchor = self.bss_labels.get(end)
            if anchor is None:
                anchor = "BSS_END"
                out.append(f"{anchor}:")
            for a in beyond:
                out.append(f"{self.bss_labels[a]:16s} EQU     {anchor}{a - end:+d}")
        return out


# ===========================================================================
# CLI
# ===========================================================================

def _addr(s: str) -> int:
    s = s.strip()
    if s.startswith("$"):
        return int(s[1:], 16)
    return int(s, 16) if not s.lower().startswith("0x") else int(s, 16)


def parse_table_spec(spec: str) -> dict:
    """ADDR:COUNT[:long|word|rel|rel=BASE] (hex ADDR / BASE).
    long = 32-bit absolute addresses (default); word = 16-bit absolute
    (sign-extended); rel = 16-bit offsets from the table start; rel=BASE =
    offsets from BASE."""
    parts = spec.split(":")
    if len(parts) < 2:
        raise argparse.ArgumentTypeError(f"bad --table spec {spec!r}: need ADDR:COUNT")
    t = {"addr": _addr(parts[0]), "count": int(parts[1], 0), "kind": "long", "base": None}
    for opt in parts[2:]:
        if opt in ("long", "word", "rel"):
            t["kind"] = opt
        elif opt.startswith("rel="):
            t["kind"], t["base"] = "rel", _addr(opt[4:])
        else:
            raise argparse.ArgumentTypeError(f"bad --table option {opt!r}")
    return t


def parse_range(spec: str) -> tuple:
    a, b = spec.split("-", 1)
    s_, e_ = _addr(a), _addr(b)
    if e_ < s_:
        raise argparse.ArgumentTypeError(f"bad range {spec!r}")
    return s_, e_, "--data-region"


def build_disassembler(args):
    segments, info = load_image(args.file, org=args.org, raw=args.raw, rsrc=args.rsrc, rom=args.rom)
    mem = MemoryImage()
    for org, data in segments:
        mem.load_segment(org, data)
    named = {}
    for a, n in info.get("entries", []):
        named.setdefault(a, n)
    regions = list(info.get("data_regions", [])) + [parse_range(r) for r in args.data_region]
    tables = [parse_table_spec(t) for t in args.table]
    fill = "none" if args.no_fill else args.fill
    rom_base = info["segments"][0]["org"] if info.get("is_rom") else None
    platform = getattr(args, "platform", "auto") or "auto"
    if args.mac:
        platform = "mac"
    if getattr(args, "atari", False):
        platform = "atari"
    if platform == "auto":
        platform = info.get("platform") or ("mac" if info.get("mac") else "generic")
    info["platform"] = platform
    dasm = Disassembler68k(
        mem, entry_addr=info.get("entry"), entries=args.entry, named_entries=named, fill=fill,
        tables=tables, symbols=load_symbols(args.symbols), data_regions=regions,
        auto_tables=not args.no_auto_tables, platform=platform,
        prg=info.get("prg"), tos=info.get("tos"),
        rom=info.get("rom"), rom_base=rom_base, jump_table=info.get("jump_table"),
        vector_table=bool(info.get("vector_table")), prologues=not args.no_prologues,
        segment=(info["resource"]["id"], info["segments"][0]["org"])
        if info.get("resource", {}).get("type") == "CODE" else None)
    # GEMDOS symbol table: names for everything, code hints for TEXT symbols
    for a, n, seg in info.get("prg_symbols", []):
        if a not in dasm.sym.by_addr and n not in dasm.sym.by_name:
            dasm.sym.by_addr[a] = (n, f"{seg} symbol")
            dasm.sym.by_name[n] = a
        if seg == "text":
            dasm.code_hints.add(a)
    tos = info.get("tos") or {}
    dasm.linef_calls = tos.get("kind") == "rom" and tos.get("version", 0x200) < 0x200 and not tos.get("emutos")
    if info.get("entry") is not None and info.get("is_rom"):
        dasm.named_entries.setdefault(info["entry"], "ResetEntry")
        dasm.descriptions.setdefault(info["entry"], "reset entry (ROM header reset PC)")
    for dv in info.get("drivers", []):
        for r, a in dv["routines"].items():
            dasm.descriptions.setdefault(a, f"driver {dv['name']} {r} routine")
    return dasm, info


def add_common_args(parser):
    parser.add_argument("file", help="Mac ROM, Atari TOS ROM / cartridge / PRG / boot sector, resource "
                                     "file / MacBinary, S-record, Intel HEX or raw binary")
    parser.add_argument("--org", type=lambda x: int(x, 0), default=None,
                        help="Load address (e.g. 0x400000); auto for ROMs, S-records; $10000 for "
                             "resources, GEMDOS executables and boot sectors")
    parser.add_argument("--raw", action="store_true", help="Skip ROM / container detection")
    parser.add_argument("--rom", action="store_true", help="Treat a raw image as a Mac ROM (no checksum match)")
    parser.add_argument("--rsrc", metavar="TYPE:ID", help="Resource to disassemble from a resource fork")
    parser.add_argument("--platform", choices=["auto", "mac", "atari", "generic"], default="auto",
                        help="Symbol set: Mac or Atari ST system variables, hardware and line-A "
                             "meaning (default: from the input format)")
    parser.add_argument("--mac", action="store_true", help="Same as --platform mac")
    parser.add_argument("--atari", action="store_true", help="Same as --platform atari")
    parser.add_argument("--entry", type=lambda x: int(x, 0), action="append", default=[],
                        help="Extra entry point to trace from (repeatable)")
    parser.add_argument("--table", action="append", default=[], metavar="ADDR:COUNT[:long|word|rel|rel=BASE]",
                        help="Dispatch table (hex ADDR): trace its targets and emit DC.L / DC.W entries")
    parser.add_argument("--symbols", action="append", default=[], metavar="FILE",
                        help="Symbol file (repeatable): JSON schema v1.0, flat JSON, or 'NAME EQU $XXXXXX' "
                             "lines. First definition wins; overrides built-in and generated names")
    parser.add_argument("--data-region", action="append", default=[], metavar="START-END",
                        help="Force an inclusive hex range to be data (repeatable), e.g. 40F000-40F7FF")
    parser.add_argument("--fill", choices=["validated", "all", "none"], default="validated",
                        help="Unreached bytes: 'validated' (default) = code only where it follows "
                             "traced code or is referenced and decodes cleanly to RTS/JMP/BRA; "
                             "'all' = decode everything decodable; 'none' = data")
    parser.add_argument("--no-fill", action="store_true", help="Same as --fill none")
    parser.add_argument("--no-auto-tables", action="store_true",
                        help="Disable pointer / dispatch table detection")
    parser.add_argument("--no-prologues", action="store_true",
                        help="Don't trace unreferenced routines found by their prologue "
                             "(LINK An,#-n / MOVEM.L regs,-(SP)) in data gaps")


def main():
    parser = argparse.ArgumentParser(description="68000 disassembler for Macintosh ROMs and programs")
    add_common_args(parser)
    parser.add_argument("--output", "-o", help="Output file (default: stdout)")
    parser.add_argument("--no-hex", action="store_true",
                        help="Omit address/hex columns (reassemblable vasm source)")
    parser.add_argument("--annotate", action="store_true",
                        help="Subroutine separators, call descriptions, loop markers")
    args = parser.parse_args()

    dasm, info = build_disassembler(args)
    print(f"; Format: {info['format']}" + (f" ({info['rom_name']})" if info.get("rom_name") else ""),
          file=sys.stderr)
    for s in info["segments"]:
        print(f";   ${s['org']:06X}-${s['org'] + s['length'] - 1:06X} ({s['length']} bytes)", file=sys.stderr)
    if info.get("entry") is not None:
        print(f"; Entry: ${info['entry']:06X}", file=sys.stderr)
    for n in info["notes"]:
        print(f"; {n}", file=sys.stderr)
    output = dasm.disassemble(show_hex=not args.no_hex, annotate=args.annotate)
    if args.output:
        with open(args.output, "w") as f:
            f.write(output)
        print(f"Output written to {args.output}", file=sys.stderr)
    else:
        sys.stdout.write(output)


if __name__ == "__main__":
    main()
