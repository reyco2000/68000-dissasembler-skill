#!/usr/bin/env python3
"""
build_fixtures.py — regenerate the synthetic test inputs in roms/ (needs vasm)
Usage: python3 tests/fixtures/build_fixtures.py

Builds (all original code, no Apple ROM content):
  roms/allmodes.bin  every 68000 instruction form (tests/fixtures/allmodes.s), org $10000
  roms/fakerom.bin   a 64K "Mac-style" ROM: valid checksum, reset PC, version
                     word $0069, header jumps, a .Test driver, vector installs,
                     jump/branch tables, a pointer table, a 512-entry
                     ROM-relative dispatch table, an embedded resource map,
                     Pascal strings and a MacsBug symbol
  roms/demo.rsrc     a resource fork with CODE 0 (jump table), CODE 1 and STR
"""

import os
import struct
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, ROOT)
from tools.macsyms import mac_rom_checksum   # noqa: E402

VASM = os.environ.get("VASM", "vasmm68k_mot")


def assemble(src: str) -> bytes:
    with tempfile.TemporaryDirectory() as d:
        s, b = os.path.join(d, "x.s"), os.path.join(d, "x.bin")
        with open(s, "w") as f:
            f.write(src)
        subprocess.run([VASM, "-quiet", "-Fbin", "-no-opt", "-m68000", "-o", b, s], check=True)
        return open(b, "rb").read()


def fakerom_source() -> str:
    impl = []
    for i in range(512):
        impl.append(f"Impl{i:03X}: MOVEQ   #${i & 0x7F:02X},D0\n        RTS")
    disp = "\n".join(f"        DC.W    Impl{i:03X}-$400000" for i in range(512))

    # embedded mini resource file: header, data (2 resources), map
    return f"""
        MC68000
        ORG     $400000
        DC.L    $00000000               ; checksum (patched by the builder)
        DC.L    Reset                   ; reset PC
        DC.W    $0069                   ; version word
        JMP     BootEntry(PC)           ; header jump vector
        JMP     Critical(PC)            ; header jump vector
        DCB.B   $2A-$12,$00
Reset:  MOVE.W  #$2700,SR
        MOVE.L  #$EFE1FE,($01D4).W      ; VIA base into low memory
        LEA     TrapDisp(PC),A0
        MOVE.L  A0,($0028).W            ; Line1010: trap dispatcher
        LEA     Lvl1Int(PC),A1
        MOVE.L  A1,($0064).W            ; level-1 (VIA) interrupt
        MOVEA.L ($01D4).W,A1
        MOVE.B  #$7F,$1C00(A1)          ; vIER: disable all
        BCLR    #4,$1E00(A1)            ; vBufA: overlay off
        MOVE.B  ($00EFE1FE).L,D0        ; vBufB
        BSR.W   InitStuff
        MOVEQ   #2,D0
        BSR.W   Dispatch
        DC.W    $A86E                   ; _InitGraf
        DC.W    $A9F4                   ; _ExitToShell (does not return)
        DC.B    'not code after ExitToShell'
        EVEN
BootEntry:
        MOVE.L  ($016A).W,D0            ; Ticks
        BRA.S   BootEntry
Critical:
        MOVEQ   #-1,D0
        STOP    #$2700
        BRA.S   Critical
InitStuff:
        LINK    A6,#-8
        MOVEM.L D3-D7/A2-A4,-(SP)
        LEA     Msg(PC),A0
        MOVE.L  ($016A).W,D0
        MOVEM.L (SP)+,D3-D7/A2-A4
        UNLK    A6
        RTS
        DC.B    $89,'InitStuff'
        EVEN
        DC.W    0
Dispatch:
        ADD.W   D0,D0
        MOVE.W  JTab(PC,D0.W),D0
        JMP     JTab(PC,D0.W)
JTab:   DC.W    Case0-JTab,Case1-JTab,Case2-JTab
Case0:  MOVEQ   #0,D1
        RTS
Case1:  MOVEQ   #1,D1
        RTS
Case2:  ADD.W   D1,D1
        ADD.W   D1,D1
        JMP     BrTab(PC,D1.W)
BrTab:  BRA.W   Case0
        BRA.W   Case1
        BRA.W   Case3
Case3:  MOVEQ   #3,D1
        RTS
TrapDisp:
        MOVEM.L D0-D2/A0-A1,-(SP)
        MOVEM.L (SP)+,D0-D2/A0-A1
        RTE
Lvl1Int:
        RTE
Msg:    DC.B    11,'Hello World'
        EVEN
PtrTab: DC.L    Case0,Case1,Case2,InitStuff,Dispatch
Drvr:   DC.W    $4F00,0,0,0
        DC.W    DOpen-Drvr,DPrime-Drvr,DCtl-Drvr,DStat-Drvr,DClose-Drvr
        DC.B    5,'.Test'
        EVEN
DOpen:  MOVEQ   #0,D0
        RTS
DPrime: MOVEQ   #-17,D0
        RTS
DCtl:   MOVEQ   #-18,D0
        RTS
DStat:  MOVEQ   #-18,D0
        RTS
DClose: MOVEQ   #0,D0
        RTS
{chr(10).join(impl)}
DispTab:
{disp}
RsrcFile:
        DC.L    RData-RsrcFile,RMap-RsrcFile,RMap-RData,RMapEnd-RMap
RData:  DC.L    4
        DC.B    3,'ROM'
        DC.L    4
        MOVEQ   #4,D0
        RTS
RMap:   DC.L    RData-RsrcFile,RMap-RsrcFile,RMap-RData,RMapEnd-RMap
        DC.L    0
        DC.W    0,$0080
        DC.W    28,RNames-RMap
        DC.W    1                       ; 2 types
        DC.B    'STR '
        DC.W    0,RRefs1-RMap-28
        DC.B    'PACK'
        DC.W    0,RRefs2-RMap-28
RRefs1: DC.W    -16384,$FFFF
        DC.L    $00000000
        DC.L    0
RRefs2: DC.W    4,$FFFF
        DC.L    $00000008
        DC.L    0
RNames:
RMapEnd:
        EVEN
        DCB.B   $410000-*,$FF
"""


def build_fakerom() -> bytes:
    rom = bytearray(assemble(fakerom_source()))
    assert len(rom) == 0x10000, len(rom)
    struct.pack_into(">I", rom, 0, mac_rom_checksum(bytes(rom)))
    return bytes(rom)


def build_rsrc() -> bytes:
    """Resource fork: CODE 0 (jump table, 2 entries in segment 1), CODE 1, STR 128."""
    code1 = assemble("""
        MC68000
        ORG     $0
Main:   LINK    A6,#0
        DC.W    $A86E                   ; _InitGraf
        JSR     $2A(A5)                 ; jump table entry 1 -> Helper
        MOVE.L  ($016A).W,D0            ; Ticks
        UNLK    A6
        DC.W    $A9F4                   ; _ExitToShell
Helper: MOVEQ   #1,D0
        RTS
        DC.B    $86,'Helper'
        DC.W    0
""")
    helper = code1.index(bytes.fromhex("7001"))
    seg1 = struct.pack(">HH", 0, 2) + code1
    jt = struct.pack(">IIII", 0x100, 0x20, 16, 32)
    jt += struct.pack(">HHHH", 0, 0x3F3C, 1, 0xA9F0)
    jt += struct.pack(">HHHH", helper, 0x3F3C, 1, 0xA9F0)
    strres = bytes([5]) + b"Hello"
    resources = [(b"CODE", [(0, jt), (1, seg1)]), (b"STR ", [(128, strres)])]
    data = bytearray()
    refs = []
    for rtype, items in resources:
        lst = []
        for rid, payload in items:
            lst.append((rid, len(data)))
            data += struct.pack(">I", len(payload)) + payload
        refs.append((rtype, lst))
    mp = bytearray(16 + 4 + 2 + 2 + 2 + 2)
    tl = bytearray(struct.pack(">H", len(refs) - 1))
    reflists = bytearray()
    ref_base = 2 + 8 * len(refs)
    for rtype, lst in refs:
        tl += rtype + struct.pack(">HH", len(lst) - 1, ref_base + len(reflists))
        for rid, off in lst:
            reflists += struct.pack(">hHI", rid, 0xFFFF, off & 0xFFFFFF) + b"\0\0\0\0"
    typelist = tl + reflists
    mp += typelist
    struct.pack_into(">HH", mp, 24, 28, len(mp))
    doff, moff = 256, 256 + len(data)
    hdr = struct.pack(">IIII", doff, moff, len(data), len(mp))
    mp[0:16] = hdr
    out = bytearray(hdr) + bytes(240) + data + mp
    return bytes(out)


def main():
    roms = os.path.join(ROOT, "roms")
    os.makedirs(roms, exist_ok=True)
    with open(os.path.join(HERE, "allmodes.s")) as f:
        open(os.path.join(roms, "allmodes.bin"), "wb").write(assemble(f.read()))
    open(os.path.join(roms, "fakerom.bin"), "wb").write(build_fakerom())
    open(os.path.join(roms, "demo.rsrc"), "wb").write(build_rsrc())
    print("built roms/allmodes.bin roms/fakerom.bin roms/demo.rsrc")


if __name__ == "__main__":
    main()
