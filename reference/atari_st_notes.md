# Atari ST / STE Notes

Background for disassembling Atari ST software and TOS ROMs: the 520ST /
1040ST / Mega ST (TOS 1.00-1.04) and the STE / Mega STE (TOS 1.06, 1.62,
2.0x). TT (TOS 3) and Falcon (TOS 4) ROMs load too, but their extra hardware
is only partly named. Atari TOS ROMs are copyrighted; EmuTOS
(https://emutos.sourceforge.io, GPL) is a free replacement ROM that is handy
for practice.

Facts the tools read from the image (OSHEADER fields, PRG header, relocation
and symbol tables, traced code) are reliable. Items marked *(typical)* are
general knowledge to confirm in the listing.

## Inputs the Loader Recognizes

| Input | Detection | Load address | Entries |
|-------|-----------|--------------|---------|
| TOS / EmuTOS ROM | `BRA` at 0, `os_beg` at 8 = $FC0000 or $E00000, reset handler inside | `os_beg` | reset handler (`ResetEntry`), `os_entry` BRA target |
| ROM cartridge | $ABCDEF42 at 0 (application headers) or $FA52235F (diagnostic) | $FA0000 | each application's init / run address |
| GEMDOS executable (.PRG .TOS .TTP .APP .ACC) | $601A header | $10000 (`--org`) | TEXT start (`PrgStart`), DRI symbols |
| Boot sector / .ST image | first 512 bytes sum to $1234 (big-endian words) | $10000 | offset 0 (BRA to the boot code) |

## TOS ROM Header (OSHEADER)

| Offset | Field | Contents |
|-------:|-------|----------|
| $00 | os_entry | `BRA` to the reset code (the 68000 fetches SSP / PC from the first 8 ROM bytes, mirrored at 0) |
| $02 | os_version | TOS version (e.g. $0104, $0206) |
| $04 | reseth | reset handler address |
| $08 | os_beg | ROM base ($FC0000 for 192K TOS 1.0x, $E00000 for 256K TOS 1.06+ / 2.x) |
| $0C | os_end | first free RAM address after the OS variables |
| $10 | os_rsv1 | reserved |
| $14 | os_magic | GEM memory parameter block pointer |
| $18 | os_date | build date, BCD $MMDDYYYY |
| $1C | os_conf | bit 0 = PAL, bits 1-15 = country (0 USA, 1 Germany, 2 France, 3 UK, ...) |
| $1E | os_dosdate | build date in GEMDOS format |
| $20 | p_root | TOS 1.02+: GEMDOS memory pool pointer |
| $24 | pkbshift | TOS 1.02+: keyboard shift-state variable pointer |
| $28 | p_run | TOS 1.02+: pointer to the current process basepage pointer |

EmuTOS puts `ETOS` at $2C; the loader reports it.

## GEMDOS Executable Format

28-byte header: `$601A`, TEXT length, DATA length, BSS length, symbol table
length, reserved long, program flags (fastload, TT-RAM bits ...), absolute
flag (word, 0 = relocation table present). Then TEXT, DATA, the symbol table
(DRI: 14-byte entries: 8-char name, type word, value long; GST long names use
type $0048 plus a continuation entry), then the relocation table: a long with
the first offset (0 = none) followed by bytes: 1 = advance 254, n = advance n
and relocate, 0 = end. Every relocated long holds an offset from the TEXT
start; GEMDOS adds the load address.

How the tools use this:
- TEXT+DATA load at $10000 with the relocations applied.
- **A relocated long is always an address** (it becomes a label, even into
  BSS) and **an unrelocated long never is** (it stays a number). The decoder
  also rejects instructions that would split a relocated long, which keeps
  data out of the code.
- Output uses `TEXT` / `DATA` / `BSS` sections. Rebuild with
  `vasmm68k_mot -Ftos -nosym -no-opt -m68000 [-tos-flags=N]`; vasm regenerates
  the header and relocation table, so the result is byte-identical to the
  original without its symbol table (and with `res1` = 0).

## System Calls

Arguments are pushed right to left, the function number last, then a TRAP;
the caller pops the stack afterwards. Results come back in D0.

```
        PEA     message(PC)
        MOVE.W  #9,-(SP)        ; Cconws
        TRAP    #1              ; GEMDOS
        ADDQ.L  #6,SP
```

| TRAP | System | Notes |
|------|--------|-------|
| #1 | GEMDOS | files, memory, processes, console; `CLR.W -(SP)` / `TRAP #1` = Pterm0 |
| #2 | AES / VDI | D0 = 200 ($C8) AES, D0 = 115 ($73) VDI, D1 = parameter block |
| #13 | BIOS | character devices, sectors, exception vectors (Setexc) |
| #14 | XBIOS | screen, palette, floppy, sound, keyboard, Supexec |

The disassembler names the call from the `MOVE.W #fn,-(SP)` (or `CLR.W
-(SP)`) immediately before the TRAP, treats `Pterm0` / `Pterm` / `Ptermres`
as not returning, and traces the routine passed to `Supexec`, `Setexc`,
`Xbtimer` or `Mfpint` (named `Supexec_Func`, `Setexc_Handler`, ...).

## Line-A and Line-F

- **Line-A** $A000-$A00F are the Line-A graphics primitives (`$A000` = init:
  returns A0 = Line-A variables, A1 = system font headers, A2 = routine
  table). They become macros such as `_LineA_Init`.
- **Line-F**: TOS 1.0x uses $Fxxx words in the AES/VDI as compact subroutine
  calls through the line-F vector. In TOS 1.x ROMs the disassembler traces
  through them (emitted as `DC.W $Fxxx` with a comment); elsewhere they are
  data.

## Interrupts *(typical)*

| Level | Source | Vector |
|-------|--------|--------|
| 2 | HBL (horizontal blank) | $68, normally just masked |
| 4 | VBL (vertical blank, 50 / 60 / 71 Hz) | $70: VBL handler, `_vbclock`, VBL queue |
| 6 | MFP 68901 (vectored, base $40 → $100-$13C) | Timer C = 200 Hz system tick (`_hz_200`), ACIA = keyboard / MIDI, FDC / DMA, Timer B = HBL counter |
| 7 | NMI | $7C |

TOS runs with interrupt mask 3 so only VBL and MFP get through. MFP
interrupts need an end-of-interrupt write to `isra` / `isrb` when software
EOI is selected in `vr` (bit 3).

## Hardware Quick Facts

- Video: `dbaseh` / `dbasel` ($FF8201/03, + `dbaselo` $FF820D on the STE) set
  the screen base; `shiftmd` ($FF8260): 0 = 320x200x16, 1 = 640x200x4,
  2 = 640x400 mono; palette $FF8240-$FF825E (0RGB, 3 bits per gun, 4 on the
  STE); `syncmode` bit 1 = 50 Hz.
- YM2149 ($FF8800 / $FF8802): select a register with `giselect`, write with
  `giwrite`. Register 14 (port A) also drives floppy side / drive select.
- DMA / FDC ($FF8604-$FF860D): `dmamode` selects the WD1772 or hard disk
  register reached through `diskctl`.
- MFP ($FFFA01-$FFFA2F, odd addresses): GPIP, interrupt enable / pending /
  in-service / mask A and B, vector register, timers A-D, USART.
- ACIAs ($FFFC00 keyboard, $FFFC04 MIDI): the keyboard processor (IKBD)
  sends key, mouse and joystick packets; commands go to `keybd`.
- STE: DMA sound ($FF8901-$FF8921), Microwire volume / tone ($FF8922/24),
  blitter ($FF8A00-$FF8A3D), joypads ($FF9200).

All I/O is supervisor-only (a user-mode access raises a bus error), which is
why programs call `Super` or `Supexec` before touching hardware.

## Common Program Idioms

| Code | Meaning |
|------|---------|
| `MOVEA.L 4(SP),A5` at the program start | basepage pointer |
| `Mshrink` early in the program | release the unused part of the TPA |
| `CLR.L -(SP)` / `MOVE.W #$20,-(SP)` / `TRAP #1` | `Super(0)`: enter supervisor mode (D0 = old SSP) |
| `MOVE.L #handler,($70).W` | install a VBL handler (demos, games) |
| `MOVE.B #n,($FFFF8800).W` / `MOVE.B #v,($FFFF8802).W` | write YM2149 register n |
| `MOVE.W #$777,($FFFF8240).W` | set background color |
