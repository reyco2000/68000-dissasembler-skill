# Macintosh 128K / 512K / Plus ROM Notes

Background for mapping the 64K ROM (Macintosh 128K and 512K) and the 128K ROM
(Macintosh Plus and 512Ke). Apple ROMs are copyrighted: they are not in this
repository. Use dumps of machines you own.

Facts the tools read straight from the image (checksum, reset PC, version word,
driver headers, resource maps, traced code) are reliable. Items marked
*(typical)* describe how these ROMs are usually organized; confirm them in your
listing before relying on them.

## ROM Families

| Stored checksum | Machine | Size | Version word ($08) |
|-----------------|---------|------|--------------------|
| $28BA61CE | Macintosh 128K (first release) | 64K | $0069 |
| $28BA4E50 | Macintosh 512K (revised 64K ROM) | 64K | $0069 |
| $4D1EEEE1 | Macintosh Plus v1 "Lonely Hearts" | 128K | $0075 |
| $4D1EEAE1 | Macintosh Plus v2 "Lonely Heifers" | 128K | $0075 |
| $4D1F8172 | Macintosh Plus v3 "Loud Harmonicas" (also 512Ke) | 128K | $0075 |
| $B2E362A8 | Macintosh SE (identified only; not covered in depth) | 256K | - |

The checksum is the 32-bit sum of the big-endian words from offset 4 to the end
of the ROM, stored in the first long. `macloader.py` recomputes it: a mismatch
means a bad dump, a byte-swapped or interleaved dump (two 8-bit EPROM halves),
or a patched ROM.

**Split dumps:** Mac ROMs sit in two 8-bit chips (high byte / low byte). If you
read the chips separately, interleave them (`hi[0] lo[0] hi[1] lo[1] ...`) before
analysis. The checksum check fails until the order is right.

## ROM Header

| Offset | Size | Contents |
|--------|------|----------|
| $00 | long | checksum (also the initial SSP the 68000 fetches at reset) |
| $04 | long | reset PC (the 68000 fetches it at reset while ROM is overlaid at 0) |
| $08 | word | ROM version ($0069 = 64K ROM, $0075 = 128K ROM) |
| $0A | ... | jump vectors to boot / error entry points *(typical)*: `macloader.py` lists every `JMP`/`BRA` here and the disassembler names them `HdrJmp_xx` (slot) and `HDR_xx` (target) |

At reset the ROM is overlaid at address 0 so the 68000 can fetch its vectors.
The reset code clears the overlay with VIA port A bit 4 (`vOverlay`), after
which RAM appears at 0 and the ROM at $400000.

## Address Map

| Range | Device |
|-------|--------|
| $000000-$3FFFFF | RAM (128K, 512K, up to 4MB on the Plus) |
| $400000-$4FFFFF | ROM (mirrored through the range) |
| $580000-$5FFFFF | NCR 5380 SCSI (Mac Plus): read base $580000, write base $580001, registers $10 apart, pseudo-DMA at $580200 |
| $9FFFF8 | SCC (Z8530) read base: bCtl +0, aCtl +2, bData +4, aData +6 |
| $BFFFF9 | SCC write base: same offsets |
| $DFE1FF | IWM floppy controller: 16 registers $200 apart (ph0L ... q7H) |
| $EFE1FE | VIA 6522: 16 registers $200 apart (vBufB +$0000 ... vIER +$1C00, vBufA +$1E00) |
| $FFFFF0-$FFFFFF | interrupt acknowledge (autovectors) |

Screen buffer: top of RAM - $5900 (alternate - $D900). Sound/PWM buffer: top of
RAM - $300 (alternate - $5F00). The screen is 512 x 342, 64 bytes per row.

Interrupts *(typical)*: level 1 = VIA (60.15 Hz VBL, one-second clock, keyboard
shift register, timers), level 2 = SCC (serial, mouse quadrature), level 4 =
interrupt (programmer's) switch on the 128K/512K/Plus. Handlers are installed
into the autovectors ($64-$7C) and dispatch through `Lvl1DT` ($192) / `Lvl2DT`
($1B2).

VIA port A: bits 0-2 sound volume, 3 alternate sound buffer, 4 ROM overlay,
5 disk head select, 6 alternate screen buffer, 7 SCC wait/request. Port B:
bits 0-2 real-time clock (data, clock, enable), 3 mouse button, 4-5 mouse
quadrature, 6 horizontal blank, 7 sound enable.

## 64K ROM vs 128K ROM

| | 64K ROM (128K, 512K) | 128K ROM (Plus, 512Ke) |
|--|----------------------|-------------------------|
| Trap dispatch table | one table of 512 words at $400; OS traps use numbers $00-$4F, Toolbox traps $50-$1FF *(typical)* | OS table: 256 longs at $400; Toolbox table: 512 longs at $C00 |
| File system | MFS | HFS (and MFS) |
| SCSI | none | NCR 5380 + SCSI Manager |
| ROM resources | none | fonts, drivers, packages and definition procedures as resources in ROM (`ROMMapInsert` $B9E links the ROM map into the resource chain) |
| `ROM85` ($28E) | $FFFF | $7FFF (bit 15 clear = 128K ROM or later) |

`macrommap.py` reports a "dispatch table candidate" when it finds a long run of
words (offsets from the ROM base) or longs whose targets land on routine starts
found independently by tracing. A 512-entry word table in a 64K ROM matches the
64K dispatch-table layout, and its entries are then named `TRAP_<name>` with
the table index mapped to the trap name. That mapping is inferred: check a few
entries (e.g. `TRAP_BlockMove` should copy memory, `TRAP_TickCount` should read
`Ticks`).

The 128K ROM builds its RAM tables from a packed form in ROM, so the detector
usually finds nothing there. To recover trap addresses in the 128K ROM:

1. Find the trap dispatcher: the disassembler names whatever is installed into
   the line-A vector `Line1010_Handler` (from `LEA x(PC),An` /
   `MOVE.L An,($28).W`).
2. Read how it indexes the tables at $400 / $C00 (bit 11 of the trap word picks
   OS vs Toolbox).
3. Find the initialization code that fills $400-$7FF and $C00-$13FF (search the
   xref report for stores into `OSTable` / `ToolTable`, or `LEA ($0400).W,An`)
   and decode the ROM table it reads.
4. Put the recovered `TRAP_<name>` addresses in a symbols file and rerun with
   `--symbols`.

## How Traps Work

An A-line word ($Axxx) is not a 68000 instruction: it raises the line-1010
exception (vector $28). The ROM's dispatcher looks at the trap word:

- **OS traps** ($A0xx-$A7xx, bit 11 = 0): register-based. Parameters in A0
  (usually a parameter block) and D0, result code in D0. Bits 9-10 are flags
  (`ASYNC`/`SYS`, `IMMED`/`CLEAR`/`HFS`); bit 8 set = the trap returns a value in
  A0 (A0 is not restored).
- **Toolbox traps** ($A8xx-$ABxx, bit 11 = 1): stack-based, Pascal calling
  convention. Bit 10 = auto-pop (return to the caller's caller, used by glue).

The disassembler emits each distinct trap word as an MPW-style macro (`_Read`,
`_NewPtr_SYS`, `_GetResource`), defined in the listing header as `DC.W $Axxx`,
so the source stays assemblable.

## Calling Conventions

- **Pascal (Toolbox, most applications):** the caller reserves space for a
  function result (`CLR.W -(SP)` / `SUBQ.L #4,SP`), pushes parameters left to
  right, then calls. The callee pops the parameters: `MOVEA.L (SP)+,A0`,
  `ADDQ.L #n,SP`, `JMP (A0)`. Frames use `LINK A6,#-locals` / `UNLK A6`.
- **OS traps and many ROM internals:** registers (A0 = parameter block, D0 =
  result / selector). Routines preserve D3-D7/A2-A6 with `MOVEM.L`.
- **A5 world (applications):** A5 points between the application globals
  (negative offsets; QuickDraw globals at the very bottom, `thePort` at
  -4(A5)) and the jump table (positive offsets from 32(A5)). `JSR n(A5)`
  calls through the jump table. With a resource fork input, the disassembler
  resolves these to the CODE segment being disassembled.

## Parameter Block (File / Device Manager)

| Offset | Field | Offset | Field |
|-------:|-------|-------:|-------|
| 0 | qLink | 24 | ioRefNum (word) |
| 4 | qType (word) | 26 | ioVersNum (byte) |
| 6 | ioTrap (word) | 27 | ioPermssn (byte) |
| 8 | ioCmdAddr | 28 | ioMisc |
| 12 | ioCompletion | 32 | ioBuffer |
| 16 | ioResult (word) | 36 | ioReqCount |
| 18 | ioNamePtr | 40 | ioActCount |
| 22 | ioVRefNum (word) | 44 | ioPosMode (word), 46 ioPosOffset |

Control / Status calls use `csCode` at 26 and `csParam` at 28.

## Device Drivers

A driver starts with a header: flags (word), delay (word), event mask (word),
menu ID (word), offsets to Open, Prime, Control, Status and Close (words,
relative to the header), then the name as a Pascal string beginning with `.`.
The ROM contains drivers such as `.Sony` (floppy), `.Sound`, and the serial
drivers `.AIn`/`.AOut`/`.BIn`/`.BOut`; the 128K ROM also has AppleTalk
drivers *(typical)*. `macloader.py` scans the whole image for this header
shape and names each routine `DRVR_<name>_<Open|Prime|Control|Status|Close>`.

## Mapping Checklist

1. `python3 tools/macloader.py rom.bin`: identity, checksum, reset PC, header
   jumps, drivers, resources.
2. `python3 tools/macrommap.py rom.bin -o output/<name>_map.md --json output/<name>_map.json`.
3. Read the Coverage table: in a full ROM, code should be the bulk. Large
   "data" areas next to code usually mean missing entry points (dispatch
   tables): look for `JMP` through tables, installed vectors, and the trap
   table.
4. Name what you identify in `output/<name>_symbols.json` and rerun every tool
   with `--symbols` so the names propagate to the listing, xref and map.
