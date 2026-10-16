#!/usr/bin/env python3
"""
platforms.py — per-machine symbol sets for the 68000 tools.

A Platform bundles what differs between machines that share the 68000:
exception-vector names, low-memory system variables, hardware registers,
what a line-A word means, which low-memory longs are code hooks, and the
machine address map. The loader picks one (Mac ROM / resource -> mac,
TOS ROM / cartridge / PRG / boot sector -> atari, otherwise generic) and
--platform overrides it.
"""

try:
    from tools import macsyms, atarisyms
except ImportError:
    import macsyms
    import atarisyms

MASK = 0xFFFFFF


def _generic_linea(word: int):
    if (word & 0xF000) != 0xA000:
        return None
    return {"name": f"A{word:04X}", "num": word & 0xFFF, "os": False, "flags": [],
            "manager": "line-A exception", "display": f"line-A ${word:04X}",
            "ident": f"_LINEA_{word:04X}", "noreturn": False, "known": False}


GENERIC_VECTORS = {
    0x000: ("ResetSSP", "reset: initial supervisor stack pointer"),
    0x004: ("ResetPC", "reset: initial program counter"),
    0x008: ("BusErrVct", "bus error"), 0x00C: ("AdrErrVct", "address error"),
    0x010: ("IllegalVct", "illegal instruction"), 0x014: ("ZeroDivVct", "divide by zero"),
    0x018: ("ChkVct", "CHK instruction"), 0x01C: ("TrapVVct", "TRAPV"),
    0x020: ("PrivlgVct", "privilege violation"), 0x024: ("TraceVct", "trace"),
    0x028: ("Line1010", "line-A exception"), 0x02C: ("Line1111", "line-F exception"),
    0x060: ("SpurVct", "spurious interrupt"),
}
for _i in range(1, 8):
    GENERIC_VECTORS[0x60 + 4 * _i] = (f"AutoInt{_i}", f"level {_i} autovector")
for _i in range(16):
    GENERIC_VECTORS[0x80 + 4 * _i] = (f"Trap{_i}Vct", f"TRAP #{_i}")


class Platform:
    def __init__(self, name, title, vectors, lowmem, hardware, linea, hooks=(),
                 hw_sext=False, address_map=(), lowmem_limit=0x2000):
        self.name = name
        self.title = title
        self.vectors = vectors            # addr -> (name, desc)
        self.lowmem = lowmem              # addr -> (name, desc), system variables
        self.hardware = hardware          # 24-bit addr -> (name, desc)
        self.linea = linea                # word -> info dict
        self.hooks = set(hooks)           # low-memory code-pointer hooks
        self.hw_sext = hw_sext            # hardware above $FF8000: equates written $FFFFxxxx
        self.address_map = list(address_map)
        self.lowmem_limit = lowmem_limit

    def lowmem_name(self, addr):
        e = self.vectors.get(addr) or self.lowmem.get(addr)
        return e[0] if e else None

    def lowmem_desc(self, addr):
        e = self.vectors.get(addr) or self.lowmem.get(addr)
        return e[1] if e else None

    def hw_equate(self, addr: int) -> int:
        """Value to write in the EQU for a hardware register."""
        return (addr | 0xFF000000) if self.hw_sext and addr >= 0xFF8000 else addr

    def device(self, addr: int):
        if self.name == "atari":
            return atarisyms.device_of(addr)
        if self.name == "mac":
            if addr >= macsyms.VIA_BASE:
                return "VIA"
            if addr >= macsyms.IWM_BASE:
                return "IWM"
            if addr >= macsyms.SCC_RD:
                return "SCC"
            if addr >= macsyms.SCSI_RD and addr < 0x600000:
                return "SCSI"
        return None

    def hw_desc(self, addr: int):
        if addr in self.hardware:
            return self.hardware[addr][1]
        if self.name == "mac":
            r = macsyms.hw_region(addr)
            return r[1] if r else None
        d = self.device(addr)
        return f"{d} register" if d else None


MAC = Platform("mac", "Macintosh 128K / 512K / Plus", macsyms.EXCEPTION_VECTORS, macsyms.LOWMEM,
               macsyms.HARDWARE, macsyms.trap_info,
               hooks={a for a, (n, _d) in macsyms.LOWMEM.items()
                      if n.startswith("J") or n.endswith(("Proc", "Hook", "Trans", "Task"))},
               address_map=macsyms.HW_RANGES)
ATARI = Platform("atari", "Atari ST / STE", atarisyms.VECTORS, atarisyms.SYSVARS, atarisyms.HARDWARE,
                 atarisyms.linea_info, hooks=atarisyms.HOOKS, hw_sext=True,
                 address_map=atarisyms.ADDRESS_MAP, lowmem_limit=0x800)
GENERIC = Platform("generic", "generic 68000", GENERIC_VECTORS, {}, {}, _generic_linea,
                   lowmem_limit=0x400)

PLATFORMS = {"mac": MAC, "atari": ATARI, "generic": GENERIC}


def get(name):
    return PLATFORMS.get(name or "generic", GENERIC)
