#!/usr/bin/env python3
"""
m68k.py — Motorola 68000 instruction decoder (MC68000 only, no 68010+)
Usage: python3 m68k.py 4E75 41FA 0010 ...   (decode hex words at $000000)

decode(pc, read_word) returns an Instr, or None when the opcode word itself
is not populated. Instr.valid is False for anything that is not a legal
68000 instruction *or* that an assembler would not reproduce bit-for-bit
(non-zero reserved bits, 68020 index scaling, byte immediates with a
non-zero high byte, empty MOVEM lists, bit numbers out of range, ...).
That strictness is what lets dasm68k.py promise byte-exact reassembly:
anything rejected here is emitted as DC.W instead.

Operands are tuples so the disassembler can symbolize them later:
  ("D", n) ("A", n) ("(A)", n) ("(A)+", n) ("-(A)", n)
  ("d16A", disp, n) ("idxA", disp8, n, xreg, xlong)       xreg = (is_a, n)
  ("absW", value16) ("absL", value32)
  ("d16PC", target) ("idxPC", target, xreg, xlong)
  ("imm", value, size)  ("simm", value)  ("SR",) ("CCR",) ("USP",)
  ("list", mask)        mask bit 0 = D0 ... bit 15 = A7 (already normalized)
  ("branch", target)    ("trap", word)
"""

import sys
from dataclasses import dataclass, field
from typing import Optional

try:
    from tools.macsyms import trap_info
except ImportError:
    from macsyms import trap_info

ADDR_MASK = 0xFFFFFF

# EA mode classes
M_DN, M_AN, M_IND, M_POST, M_PRE, M_D16, M_IDX = 1, 2, 4, 8, 16, 32, 64
M_ABSW, M_ABSL, M_PCD, M_PCI, M_IMM = 128, 256, 512, 1024, 2048
EA_ALL = 4095
EA_DATA = EA_ALL & ~M_AN
EA_MEM = EA_ALL & ~(M_DN | M_AN)
EA_CTRL = M_IND | M_D16 | M_IDX | M_ABSW | M_ABSL | M_PCD | M_PCI
EA_ALT = M_DN | M_AN | M_IND | M_POST | M_PRE | M_D16 | M_IDX | M_ABSW | M_ABSL
EA_DALT = EA_ALT & ~M_AN
EA_MALT = EA_ALT & ~(M_DN | M_AN)
EA_CALT = EA_CTRL & EA_ALT

CC = ["T", "F", "HI", "LS", "CC", "CS", "NE", "EQ", "VC", "VS", "PL", "MI", "GE", "LT", "GT", "LE"]
SIZE_SUFFIX = {1: ".B", 2: ".W", 4: ".L"}


@dataclass
class Instr:
    pc: int
    size: int = 2                   # bytes
    mnemonic: str = "DC.W"
    ops: list = field(default_factory=list)
    valid: bool = False
    flow: str = "seq"               # seq | branch | jump | call | ret | stop | jump_ind | call_ind
    target: Optional[int] = None    # static flow target
    words: list = field(default_factory=list)
    trap: Optional[dict] = None     # A-line trap info
    opsize: int = 0                 # operand size in bytes (0 = unsized)

    @property
    def end(self) -> int:
        return self.pc + self.size


class _Bad(Exception):
    pass


def sext8(v: int) -> int:
    return v - 0x100 if v & 0x80 else v


def sext16(v: int) -> int:
    return v - 0x10000 if v & 0x8000 else v


def ea_address(op) -> Optional[int]:
    """Static memory address an operand refers to (24-bit), or None."""
    k = op[0]
    if k == "absW":
        return (op[1] | 0xFFFF0000 if op[1] & 0x8000 else op[1]) & ADDR_MASK
    if k == "absL":
        return op[1] & ADDR_MASK
    if k in ("d16PC", "idxPC", "branch"):
        return op[1] & ADDR_MASK
    return None


class _Decoder:
    def __init__(self, pc: int, read_word):
        self.pc = pc
        self.rw = read_word
        self.words = []

    def word(self) -> int:
        a = self.pc + 2 * len(self.words)
        w = self.rw(a)
        if w is None:
            raise _Bad()
        self.words.append(w)
        return w

    def long(self) -> int:
        return (self.word() << 16) | self.word()

    def ext_addr(self) -> int:
        """Address of the next extension word (base for PC-relative)."""
        return self.pc + 2 * len(self.words)

    def ea(self, mode: int, reg: int, size: int, allowed: int):
        """Decode an effective address; raise _Bad if not in `allowed`."""
        if mode == 0:
            cls, op = M_DN, ("D", reg)
        elif mode == 1:
            if size == 1:
                raise _Bad()              # no byte access to address registers
            cls, op = M_AN, ("A", reg)
        elif mode == 2:
            cls, op = M_IND, ("(A)", reg)
        elif mode == 3:
            cls, op = M_POST, ("(A)+", reg)
        elif mode == 4:
            cls, op = M_PRE, ("-(A)", reg)
        elif mode == 5:
            cls = M_D16
            if not allowed & cls:
                raise _Bad()
            op = ("d16A", sext16(self.word()), reg)
        elif mode == 6:
            cls = M_IDX
            if not allowed & cls:
                raise _Bad()
            x = self.word()
            if x & 0x0700:                # scale / full-format bits: 68020+
                raise _Bad()
            op = ("idxA", sext8(x & 0xFF), reg, (bool(x & 0x8000), (x >> 12) & 7), bool(x & 0x0800))
        else:
            if reg == 0:
                cls = M_ABSW
                if not allowed & cls:
                    raise _Bad()
                op = ("absW", self.word())
            elif reg == 1:
                cls = M_ABSL
                if not allowed & cls:
                    raise _Bad()
                op = ("absL", self.long())
            elif reg == 2:
                cls = M_PCD
                if not allowed & cls:
                    raise _Bad()
                base = self.ext_addr()
                t = base + sext16(self.word())
                if t < 0:
                    raise _Bad()
                op = ("d16PC", t)
            elif reg == 3:
                cls = M_PCI
                if not allowed & cls:
                    raise _Bad()
                base = self.ext_addr()
                x = self.word()
                if x & 0x0700:
                    raise _Bad()
                t = base + sext8(x & 0xFF)
                if t < 0:
                    raise _Bad()
                op = ("idxPC", t, (bool(x & 0x8000), (x >> 12) & 7), bool(x & 0x0800))
            elif reg == 4:
                cls = M_IMM
                if not allowed & cls:
                    raise _Bad()
                op = ("imm", self.imm(size), size)
            else:
                raise _Bad()
        if not allowed & cls:
            raise _Bad()
        return op

    def imm(self, size: int) -> int:
        if size == 1:
            w = self.word()
            if w & 0xFF00:
                raise _Bad()              # assemblers always write $00xx
            return w
        if size == 2:
            return self.word()
        if size == 4:
            return self.long()
        raise _Bad()


def decode(pc: int, read_word) -> Optional[Instr]:
    """Decode one instruction at pc. read_word(addr) -> 16-bit int or None."""
    first = read_word(pc)
    if first is None:
        return None
    d = _Decoder(pc, read_word)
    try:
        ins = _decode(d)
    except _Bad:
        ins = None
    if ins is None:
        return Instr(pc=pc, size=2, mnemonic="DC.W", ops=[("imm", first, 2)], valid=False, words=[first])
    ins.pc = pc
    ins.words = d.words
    ins.size = 2 * len(d.words)
    ins.valid = True
    return ins


def _sized(name: str, size: int) -> str:
    return name + SIZE_SUFFIX[size]


def _mk(mn, ops, size=0, flow="seq", target=None, trap=None) -> Instr:
    return Instr(pc=0, mnemonic=mn, ops=ops, opsize=size, flow=flow, target=target, trap=trap)


def _decode(d: _Decoder) -> Optional[Instr]:
    w = d.word()
    hi = w >> 12
    reg9 = (w >> 9) & 7
    mode = (w >> 3) & 7
    reg = w & 7
    sz2 = (w >> 6) & 3          # 00 B, 01 W, 10 L (standard size field)
    size_std = {0: 1, 1: 2, 2: 4}.get(sz2)

    # ---------------- 0000: bit / MOVEP / immediate ----------------
    if hi == 0x0:
        if (w & 0x0138) == 0x0108:
            opm = (w >> 6) & 7
            size = 2 if opm in (4, 6) else 4
            disp = sext16(d.word())
            mem = ("d16A", disp, reg)
            if opm in (4, 5):
                return _mk(_sized("MOVEP", size), [mem, ("D", reg9)], size)
            return _mk(_sized("MOVEP", size), [("D", reg9), mem], size)
        if w & 0x0100:
            typ = (w >> 6) & 3
            name = ["BTST", "BCHG", "BCLR", "BSET"][typ]
            allowed = (EA_DATA if typ == 0 else EA_DALT)
            dst = d.ea(mode, reg, 1 if mode else 4, allowed)
            return _mk(name, [("D", reg9), dst], 4 if mode == 0 else 1)
        op = reg9
        if op == 4:                       # static bit operation
            typ = (w >> 6) & 3
            name = ["BTST", "BCHG", "BCLR", "BSET"][typ]
            num = d.word()
            if num & 0xFF00:
                raise _Bad()
            if num > (31 if mode == 0 else 7):
                raise _Bad()
            allowed = (EA_DATA & ~M_IMM) if typ == 0 else EA_DALT
            dst = d.ea(mode, reg, 1 if mode else 4, allowed)
            return _mk(name, [("simm", num), dst], 4 if mode == 0 else 1)
        if op == 7:
            raise _Bad()                  # MOVES (68010)
        name = {0: "ORI", 1: "ANDI", 2: "SUBI", 3: "ADDI", 5: "EORI", 6: "CMPI"}[op]
        if op in (0, 1, 5) and (w & 0xFF) == 0x3C:
            v = d.imm(1)
            return _mk(name + ".B", [("imm", v, 1), ("CCR",)], 1)
        if op in (0, 1, 5) and (w & 0xFF) == 0x7C:
            v = d.imm(2)
            return _mk(name + ".W", [("imm", v, 2), ("SR",)], 2)
        if size_std is None:
            raise _Bad()
        v = d.imm(size_std)
        dst = d.ea(mode, reg, size_std, EA_DALT)
        return _mk(_sized(name, size_std), [("imm", v, size_std), dst], size_std)

    # ---------------- 0001/0010/0011: MOVE / MOVEA ----------------
    if hi in (1, 2, 3):
        size = {1: 1, 3: 2, 2: 4}[hi]
        dmode = (w >> 6) & 7
        src = d.ea(mode, reg, size, EA_ALL)
        if dmode == 1:
            if size == 1:
                raise _Bad()
            return _mk(_sized("MOVEA", size), [src, ("A", reg9)], size)
        dst = d.ea(dmode, reg9, size, EA_DALT)
        return _mk(_sized("MOVE", size), [src, dst], size)

    # ---------------- 0100: miscellaneous ----------------
    if hi == 0x4:
        return _decode_misc(d, w, reg9, mode, reg, sz2, size_std)

    # ---------------- 0101: ADDQ / SUBQ / Scc / DBcc ----------------
    if hi == 0x5:
        cond = (w >> 8) & 0xF
        if sz2 == 3:
            if mode == 1:
                base = d.ext_addr()
                t = base + sext16(d.word())
                if t < 0:
                    raise _Bad()
                return _mk("DB" + CC[cond], [("D", reg), ("branch", t)], 0, "branch", t)
            dst = d.ea(mode, reg, 1, EA_DALT)
            return _mk("S" + CC[cond], [dst], 1)
        q = reg9 or 8
        name = "SUBQ" if w & 0x0100 else "ADDQ"
        dst = d.ea(mode, reg, size_std, EA_ALT)
        return _mk(_sized(name, size_std), [("simm", q), dst], size_std)

    # ---------------- 0110: Bcc / BRA / BSR ----------------
    if hi == 0x6:
        cond = (w >> 8) & 0xF
        disp8 = w & 0xFF
        if disp8 == 0xFF:
            raise _Bad()                  # 32-bit displacement: 68020+
        if disp8 == 0:
            base = d.ext_addr()
            t = base + sext16(d.word())
            suffix = ".W"
        else:
            t = d.pc + 2 + sext8(disp8)
            suffix = ".S"
        if t < 0:
            raise _Bad()
        name = "BRA" if cond == 0 else ("BSR" if cond == 1 else "B" + CC[cond])
        flow = "jump" if cond == 0 else ("call" if cond == 1 else "branch")
        return _mk(name + suffix, [("branch", t)], 0, flow, t)

    # ---------------- 0111: MOVEQ ----------------
    if hi == 0x7:
        if w & 0x0100:
            raise _Bad()
        return _mk("MOVEQ", [("simm", sext8(w & 0xFF)), ("D", reg9)], 4)

    # ---------------- 1000: OR / DIVU / DIVS / SBCD ----------------
    if hi == 0x8:
        opm = (w >> 6) & 7
        if opm == 3:
            src = d.ea(mode, reg, 2, EA_DATA)
            return _mk("DIVU.W", [src, ("D", reg9)], 2)
        if opm == 7:
            src = d.ea(mode, reg, 2, EA_DATA)
            return _mk("DIVS.W", [src, ("D", reg9)], 2)
        if (w & 0x01F0) == 0x0100:
            return _bcd(d, "SBCD", w, reg9, reg)
        return _logic(d, "OR", opm, mode, reg, reg9)

    # ---------------- 1001 / 1101: SUB / ADD ----------------
    if hi in (0x9, 0xD):
        name = "SUB" if hi == 0x9 else "ADD"
        opm = (w >> 6) & 7
        if opm in (3, 7):
            size = 2 if opm == 3 else 4
            src = d.ea(mode, reg, size, EA_ALL)
            return _mk(_sized(name + "A", size), [src, ("A", reg9)], size)
        size = {0: 1, 1: 2, 2: 4, 4: 1, 5: 2, 6: 4}[opm]
        if opm >= 4 and mode in (0, 1):
            if mode == 0:
                return _mk(_sized(name + "X", size), [("D", reg), ("D", reg9)], size)
            return _mk(_sized(name + "X", size), [("-(A)", reg), ("-(A)", reg9)], size)
        if opm < 4:
            src = d.ea(mode, reg, size, EA_ALL)
            return _mk(_sized(name, size), [src, ("D", reg9)], size)
        dst = d.ea(mode, reg, size, EA_MALT)
        return _mk(_sized(name, size), [("D", reg9), dst], size)

    # ---------------- 1010: line A (Macintosh traps) ----------------
    if hi == 0xA:
        t = trap_info(w)
        return _mk(t["ident"], [("trap", w)], 0, "stop" if t["noreturn"] else "seq", trap=t)

    # ---------------- 1011: CMP / CMPA / CMPM / EOR ----------------
    if hi == 0xB:
        opm = (w >> 6) & 7
        if opm in (3, 7):
            size = 2 if opm == 3 else 4
            src = d.ea(mode, reg, size, EA_ALL)
            return _mk(_sized("CMPA", size), [src, ("A", reg9)], size)
        size = {0: 1, 1: 2, 2: 4, 4: 1, 5: 2, 6: 4}[opm]
        if opm < 4:
            src = d.ea(mode, reg, size, EA_ALL)
            return _mk(_sized("CMP", size), [src, ("D", reg9)], size)
        if mode == 1:
            return _mk(_sized("CMPM", size), [("(A)+", reg), ("(A)+", reg9)], size)
        dst = d.ea(mode, reg, size, EA_DALT)
        return _mk(_sized("EOR", size), [("D", reg9), dst], size)

    # ---------------- 1100: AND / MULU / MULS / ABCD / EXG ----------------
    if hi == 0xC:
        opm = (w >> 6) & 7
        if opm == 3:
            src = d.ea(mode, reg, 2, EA_DATA)
            return _mk("MULU.W", [src, ("D", reg9)], 2)
        if opm == 7:
            src = d.ea(mode, reg, 2, EA_DATA)
            return _mk("MULS.W", [src, ("D", reg9)], 2)
        if (w & 0x01F0) == 0x0100:
            return _bcd(d, "ABCD", w, reg9, reg)
        if (w & 0x01F8) == 0x0140:
            return _mk("EXG", [("D", reg9), ("D", reg)], 4)
        if (w & 0x01F8) == 0x0148:
            return _mk("EXG", [("A", reg9), ("A", reg)], 4)
        if (w & 0x01F8) == 0x0188:
            return _mk("EXG", [("D", reg9), ("A", reg)], 4)
        return _logic(d, "AND", opm, mode, reg, reg9)

    # ---------------- 1110: shifts / rotates ----------------
    if hi == 0xE:
        left = bool(w & 0x0100)
        if sz2 == 3:
            typ = (w >> 9) & 7
            if typ > 3:
                raise _Bad()              # bit field: 68020+
            name = ["AS", "LS", "ROX", "RO"][typ] + ("L" if left else "R")
            dst = d.ea(mode, reg, 2, EA_MALT)
            return _mk(name + ".W", [dst], 2)
        typ = (w >> 3) & 3
        name = ["AS", "LS", "ROX", "RO"][typ] + ("L" if left else "R")
        if w & 0x0020:
            src = ("D", reg9)
        else:
            src = ("simm", reg9 or 8)
        return _mk(_sized(name, size_std), [src, ("D", reg)], size_std)

    # 1111: line F (no FPU / coprocessor on the 68000)
    raise _Bad()


def _bcd(d, name, w, rx, ry):
    if w & 0x0008:
        return _mk(name, [("-(A)", ry), ("-(A)", rx)], 1)
    return _mk(name, [("D", ry), ("D", rx)], 1)


def _logic(d, name, opm, mode, reg, reg9):
    size = {0: 1, 1: 2, 2: 4, 4: 1, 5: 2, 6: 4}.get(opm)
    if size is None:
        raise _Bad()
    if opm < 4:
        src = d.ea(mode, reg, size, EA_DATA)
        return _mk(_sized(name, size), [src, ("D", reg9)], size)
    dst = d.ea(mode, reg, size, EA_MALT)
    return _mk(_sized(name, size), [("D", reg9), dst], size)


def _movem_mask(mask: int, predec: bool) -> int:
    if not predec:
        return mask
    return int(f"{mask:016b}"[::-1], 2)     # -(An): bit 0 = A7 ... bit 15 = D0


def _decode_misc(d, w, reg9, mode, reg, sz2, size_std):
    if w == 0x4AFC:
        return _mk("ILLEGAL", [], 0, "stop")
    fixed = {0x4E70: ("RESET", "seq"), 0x4E71: ("NOP", "seq"), 0x4E73: ("RTE", "ret"),
             0x4E75: ("RTS", "ret"), 0x4E76: ("TRAPV", "seq"), 0x4E77: ("RTR", "ret")}
    if w in fixed:
        mn, flow = fixed[w]
        return _mk(mn, [], 0, flow)
    if w == 0x4E72:
        return _mk("STOP", [("imm", d.word(), 2)], 0)
    if (w & 0xFFF0) == 0x4E40:
        return _mk("TRAP", [("trapnum", w & 0xF)], 0)
    if (w & 0xFFF8) == 0x4E50:
        return _mk("LINK", [("A", reg), ("simm", sext16(d.word()))], 0)
    if (w & 0xFFF8) == 0x4E58:
        return _mk("UNLK", [("A", reg)], 0)
    if (w & 0xFFF8) == 0x4E60:
        return _mk("MOVE.L", [("A", reg), ("USP",)], 4)
    if (w & 0xFFF8) == 0x4E68:
        return _mk("MOVE.L", [("USP",), ("A", reg)], 4)
    if (w & 0xFFC0) == 0x4E80:
        dst = d.ea(mode, reg, 0, EA_CTRL)
        t = ea_address(dst) if dst[0] in ("absW", "absL", "d16PC") else None
        return _mk("JSR", [dst], 0, "call" if t is not None else "call_ind", t)
    if (w & 0xFFC0) == 0x4EC0:
        dst = d.ea(mode, reg, 0, EA_CTRL)
        t = ea_address(dst) if dst[0] in ("absW", "absL", "d16PC") else None
        return _mk("JMP", [dst], 0, "jump" if t is not None else "jump_ind", t)
    if (w & 0xF1C0) == 0x41C0:
        src = d.ea(mode, reg, 0, EA_CTRL)
        return _mk("LEA", [src, ("A", reg9)], 4)
    if (w & 0xF1C0) == 0x4180:
        src = d.ea(mode, reg, 2, EA_DATA)
        return _mk("CHK.W", [src, ("D", reg9)], 2)
    if (w & 0xF100) == 0x4100:
        raise _Bad()                      # CHK.L / other 68020 forms
    top = w & 0xFFC0
    if top == 0x40C0:
        dst = d.ea(mode, reg, 2, EA_DALT)
        return _mk("MOVE.W", [("SR",), dst], 2)
    if top == 0x42C0:
        raise _Bad()                      # MOVE CCR,<ea>: 68010
    if top == 0x44C0:
        src = d.ea(mode, reg, 2, EA_DATA)
        return _mk("MOVE.W", [src, ("CCR",)], 2)
    if top == 0x46C0:
        src = d.ea(mode, reg, 2, EA_DATA)
        return _mk("MOVE.W", [src, ("SR",)], 2)
    if (w & 0xFF00) in (0x4000, 0x4200, 0x4400, 0x4600) and size_std:
        name = {0x4000: "NEGX", 0x4200: "CLR", 0x4400: "NEG", 0x4600: "NOT"}[w & 0xFF00]
        dst = d.ea(mode, reg, size_std, EA_DALT)
        return _mk(_sized(name, size_std), [dst], size_std)
    if top == 0x4800:
        dst = d.ea(mode, reg, 1, EA_DALT)
        return _mk("NBCD", [dst], 1)
    if top == 0x4840:
        if mode == 0:
            return _mk("SWAP", [("D", reg)], 4)
        if mode == 1:
            raise _Bad()                  # BKPT: 68010
        src = d.ea(mode, reg, 0, EA_CTRL)
        return _mk("PEA", [src], 4)
    if top in (0x4880, 0x48C0):
        size = 2 if top == 0x4880 else 4
        if mode == 0:
            return _mk(_sized("EXT", size), [("D", reg)], size)
        mask = d.word()
        if mask == 0:
            raise _Bad()
        dst = d.ea(mode, reg, size, EA_CALT | M_PRE)
        return _mk(_sized("MOVEM", size), [("list", _movem_mask(mask, mode == 4)), dst], size)
    if top in (0x4C80, 0x4CC0):
        size = 2 if top == 0x4C80 else 4
        mask = d.word()
        if mask == 0:
            raise _Bad()
        src = d.ea(mode, reg, size, EA_CTRL | M_POST)
        return _mk(_sized("MOVEM", size), [src, ("list", mask)], size)
    if (w & 0xFF00) == 0x4A00:
        if sz2 == 3:
            dst = d.ea(mode, reg, 1, EA_DALT)
            return _mk("TAS", [dst], 1)
        dst = d.ea(mode, reg, size_std, EA_DALT)
        return _mk(_sized("TST", size_std), [dst], size_std)
    raise _Bad()


# ===========================================================================
# PLAIN FORMATTING (no symbols) — dasm68k.py has the symbolic version
# ===========================================================================

def hexs(v: int, digits: int = 0) -> str:
    return f"${v:0{digits}X}" if digits else f"${v:X}"


def shex(v: int) -> str:
    return f"-${-v:X}" if v < 0 else f"${v:X}"


def reg_name(is_a: bool, n: int) -> str:
    if is_a:
        return "SP" if n == 7 else f"A{n}"
    return f"D{n}"


def reglist(mask: int) -> str:
    parts = []
    for base, prefix in ((0, "D"), (8, "A")):
        i = 0
        while i < 8:
            if mask >> (base + i) & 1:
                j = i
                while j + 1 < 8 and mask >> (base + j + 1) & 1:
                    j += 1
                parts.append(f"{prefix}{i}" if i == j else f"{prefix}{i}-{prefix}{j}")
                i = j + 1
            else:
                i += 1
    return "/".join(parts)


def format_operand(op, sym=None) -> str:
    """Render an operand. sym(addr, kind) may return a symbol name for an
    address (kind: 'absW', 'absL', 'pc', 'branch', 'imm') or None."""
    k = op[0]

    def s(addr, kind, default):
        if sym:
            n = sym(addr, kind)
            if n:
                return n
        return default

    if k == "D":
        return f"D{op[1]}"
    if k == "A":
        return reg_name(True, op[1])
    if k == "(A)":
        return f"({reg_name(True, op[1])})"
    if k == "(A)+":
        return f"({reg_name(True, op[1])})+"
    if k == "-(A)":
        return f"-({reg_name(True, op[1])})"
    if k == "d16A":
        return f"{shex(op[1])}({reg_name(True, op[2])})"
    if k == "idxA":
        x = reg_name(*op[3]) + (".L" if op[4] else ".W")
        return f"{shex(op[1])}({reg_name(True, op[2])},{x})"
    if k == "absW":
        v = op[1]
        n = sym(v, "absW") if (sym and v < 0x8000) else None
        if n:
            return f"({n}).W"
        return (f"(${v:04X})" if v < 0x8000 else f"($FFFF{v:04X})") + ".W"
    if k == "absL":
        v = op[1]
        n = sym(v, "absL") if (sym and v <= ADDR_MASK) else None
        return f"({n}).L" if n else f"(${v:08X}).L"
    if k == "d16PC":
        return f"{s(op[1], 'pc', hexs(op[1]))}(PC)"
    if k == "idxPC":
        x = reg_name(*op[2]) + (".L" if op[3] else ".W")
        return f"{s(op[1], 'pc', hexs(op[1]))}(PC,{x})"
    if k == "imm":
        v, size = op[1], op[2]
        if sym and size == 4:
            n = sym(v, "imm")
            if n:
                return f"#{n}"
        return f"#${v:0{2 * size}X}"
    if k == "simm":
        return f"#{shex(op[1])}"
    if k == "trapnum":
        return f"#{op[1]}"
    if k == "SR":
        return "SR"
    if k == "CCR":
        return "CCR"
    if k == "USP":
        return "USP"
    if k == "list":
        return reglist(op[1])
    if k == "branch":
        return s(op[1], "branch", hexs(op[1]))
    if k == "trap":
        return ""
    raise ValueError(k)


def format_instr(ins: Instr, sym=None) -> tuple[str, str]:
    """(mnemonic, operand text)."""
    if not ins.valid:
        return "DC.W", f"${ins.words[0]:04X}"
    if ins.trap:
        return ins.mnemonic, ""
    return ins.mnemonic, ",".join(format_operand(o, sym) for o in ins.ops)


def main():
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        print(__doc__)
        return
    words = [int(x, 16) for x in sys.argv[1:]]
    data = {2 * i: w for i, w in enumerate(words)}
    pc = 0
    while pc < 2 * len(words):
        ins = decode(pc, lambda a: data.get(a))
        mn, op = format_instr(ins)
        extra = f"  ; {ins.trap['display']}" if ins.trap else ""
        print(f"{pc:06X}  {' '.join(f'{w:04X}' for w in ins.words):24s}  {mn:8s} {op}{extra}")
        pc += ins.size


if __name__ == "__main__":
    main()
