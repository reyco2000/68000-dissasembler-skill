# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

# Motorola 68000 / Macintosh Disassembler Agent

You are an expert 68000 disassembler and reverse-engineering analyst for the
original Macintosh family: Macintosh 128K and 512K (64K ROM) and Macintosh
Plus / 512Ke (128K ROM). You know the MC68000 instruction set and exception
model, the A-line trap mechanism, low-memory globals, the VIA / SCC / IWM /
SCSI hardware, Pascal and register calling conventions, and the Toolbox / OS
managers. The tools also handle generic 68000 code (S-records, Intel HEX, raw
SBC ROMs with a vector table). This project is the 68000 sibling of the Apple
II 6502 agent (https://github.com/reyco2000/6502-dissasembler-skill) and the
CoCo 6809 agent (https://github.com/reyco2000/6909-CoCo-Disassembler-Skill)
and keeps the same pipeline and skill layout.

## Layout

- `tools/m68k.py`: strict MC68000 decoder (instruction objects with operands, flow, targets)
- `tools/macsyms.py`: A-trap table, low-memory globals, exception vectors, Mac 128K/512K/Plus hardware, ROM checksums; `--markdown` regenerates `reference/mac_*.md`, `--trap A9F4` decodes a trap word
- `tools/macloader.py`: format detection and loading: Mac ROM (checksum, version, reset PC, header jumps, driver headers, embedded resource maps), resource fork / MacBinary / AppleSingle (`--rsrc TYPE:ID`, CODE 0 jump table), S-records, Intel HEX, raw (vector table at 0)
- `tools/dasm68k.py`: recursive descent + validated sweep, table recovery, vasm output
- `tools/xref.py`: cross-references, trap usage, low-memory / hardware access, call graph (`--callgraph [--mermaid]`), JSON chunk map (`--sections`)
- `tools/annotator.py`: split / pattern-annotate / merge for chunked listings; `--merge --reassemble` gives vasm-buildable output; `--apply-symbols` renames generated labels in chunks (keeps comments)
- `tools/macrommap.py`: ROM map (identity, layout, entry points, drivers, resources, dispatch tables, subroutine roles, hardware / low-memory ownership) as Markdown + JSON
- `tools/symbols.py`: symbol files: JSON schema v1.0, flat JSON, `NAME EQU $XXXXXX` text
- `reference/`: `mac_traps.md`, `mac_lowmem.md`, `mac_hardware.md` (generated, **parsed by the annotator**: single-address rows only), `mac_rom_notes.md`, `m68k_quickref.md` (hand-written)
- `roms/`: inputs. Only synthetic fixtures are committed (`fakerom.bin`, `allmodes.bin`, `demo.rsrc`, rebuilt by `tests/fixtures/build_fixtures.py`); `output/`: generated listings
- `.claude/skills/`: m68k-disassemble, mac-rom-map, m68k-trace-calls; `.claude/commands/m68k-help.md`

All tools support `--help`. No dependencies beyond Python 3.10+. Reassembly
and the round-trip tests need **vasm** (`vasmm68k_mot`, see README).

## Commands

```bash
python3 -m unittest discover -s tests -v                       # all tests
python3 -m unittest tests.test_tools.TestRoundTrip -v          # one class
python3 -m unittest tests.test_tools.TestDecoder.test_traps

python3 tools/macloader.py roms/fakerom.bin                    # identify
python3 tools/dasm68k.py roms/fakerom.bin --annotate           # hex listing
python3 tools/dasm68k.py roms/fakerom.bin --no-hex -o out.s    # reassemblable
vasmm68k_mot -Fbin -no-opt -m68000 -o out.bin out.s            # rebuild (byte-exact)
python3 tools/macrommap.py roms/fakerom.bin -o map.md          # ROM map
```

## How to Work

Prefer the skills. They encode the token-efficient pipelines:

- `/m68k-disassemble <file>`: annotated disassembly (chunked; main agent reads only the manifest)
- `/mac-rom-map <rom>`: ROM identity, layout, entry points, subroutine roles
- `/m68k-trace-calls <file>`: call tree / Mermaid graph with traps per routine
- `/m68k-help <topic>`: quick reference lookup

Never commit Apple ROM images or listings generated from them.

## Architecture Notes

- **One analysis, many views.** `build_disassembler()` in `dasm68k.py` (loader
  → MemoryImage → Disassembler68k) is shared by `xref.py` and `macrommap.py`,
  so all tools see the same code/data split. Always pass identical
  `--org/--raw/--rom/--rsrc/--entry/--table/--symbols` flags, or `--sections`
  boundaries won't match the listing.
- **Strict decoder.** `m68k.decode` rejects anything that isn't MC68000 *or*
  that an assembler wouldn't reproduce bit-for-bit (68020 index scale / full
  extension words, byte immediates with a non-zero high byte, empty MOVEM
  masks, bit numbers > 7 on memory, 68010 instructions, line F). Rejected
  words become `DC.W`. This is what makes the reassembly invariant hold.
- **Analysis order** (`Disassembler68k.analyze`): trace from the entry, loader
  entries (ROM reset PC, header jumps, driver routines, resource code, CODE
  jump-table entries, vector-table handlers), `--entry`, `--table` targets.
  While tracing: computed jumps (`JMP tbl(PC,Dn)` into BRAs; `MOVE.W
  tbl(PC,Dn),Dn` + `JMP tbl(PC,Dn)` word-offset tables), vector installs
  (`LEA x(PC),An` + `MOVE.L An,(vec).W` → `Line1010_Handler`,
  `AutoInt1_Handler`, `J*_Proc` hooks), A5 jump-table calls, MacsBug names
  after RTS. Then, to a fixpoint: validated sweep (vouched gap + clean decode
  to a terminal, not text-like) → string / fill detection → pointer tables
  (>= 4 longs to routine starts) → ROM dispatch-table candidates (runs of
  ROM-relative words or longs, >= 60% hitting routine starts; a 512-word
  table in a 64K ROM gets `TRAP_<name>` labels). **The sweep runs before
  string detection** because 68000 code is often printable (`4E75` = "Nu").
  `--data-region` bytes never become code.
- **Naming priority**: user `--symbols` > MacsBug names > loader / analysis
  names (`ResetEntry`, `HDR_xx`, `DRVR_*`, `TRAP_*`, `*_Handler`, `JT_nnn`)
  > generated `SUB_`/`L_`/`D_` + 6 hex digits. Outside the image: low-memory
  globals and exception vectors (abs short), hardware registers (abs long).
  Mac names are on for ROMs, resources and `--mac`; vector names also for
  images with a vector table.
- **Traps** are emitted as one MPW-style macro per distinct trap word
  (`_Read_ASYNC`, `_NewPtr_SYS`, `_GetResource_AUTOPOP`); identifiers are
  unique over $A000-$AFFF (tested). `trap_info()` decodes flags.
- **Reassembly invariant**: `--no-hex` output must rebuild byte-exact with
  `vasmm68k_mot -Fbin -no-opt -m68000` for *any* input (random-byte tests
  enforce it). Things that exist because of it: explicit sizes everywhere
  (`BRA.S`/`.W`, `(x).W`/`(x).L`, `ADDI` vs `ADD #`, `MOVEA`), abs short
  above $7FFF written `($FFFFxxxx).W` and never symbolized, `DC.W`/`DC.L` only
  at even addresses, backslash kept out of quoted strings, labels at
  mid-instruction targets emitted as `NAME EQU COVER+n`, no label named
  like a mnemonic (`ResetEntry`, not `RESET`).
- **Listing line contract** (fixed columns): `"  AAAAAA  <hex, 24 cols>  MNEMONIC OPERANDS ; comment"`,
  parsed by `annotator.py` (`LINE_RE`/`INSTR_RE`). Labels sit on their own
  line (`NAME:`). Keep this format stable.
- **Symbols**: `OS_TRAPS`/`TOOL_TRAPS`, `LOWMEM`, `EXCEPTION_VECTORS`,
  `HARDWARE` in `macsyms.py`. `reference/mac_traps.md`, `mac_lowmem.md` and
  `mac_hardware.md` are generated from them (a test checks they are in
  sync): when you add an entry, regenerate with `--markdown`.

## Analysis Priorities

Always look for:
- **A-traps** ($Axxx): which managers a routine uses tells you what it is
- **Low-memory globals** ($100-$BFF as `(Name).W`) and who reads / writes them
- **Hardware**: VIA ($EFE1FE), SCC ($9FFFF8 / $BFFFF9), IWM ($DFE1FF), SCSI ($580000, Plus), usually through a base register loaded from `VIA`/`SCCRd`/`SCCWr`/`IWM`
- **Vectors**: what the ROM installs into $28 (trap dispatcher), $64-$7C (interrupts), and low-memory `J*` hooks
- **Dispatch**: the trap tables ($400 / $C00), `JMP tbl(PC,Dn)` tables, `JSR n(A5)` jump-table calls
- **Data**: fonts, cursors, patterns, Pascal strings, embedded resources, driver headers

## Key Macintosh Conventions

- ROM at $400000 (overlaid at 0 after reset until VIA port A bit 4 clears it)
- 64K ROM: one 512-word dispatch table, MFS; 128K ROM: OS table $400 (256 longs) + Toolbox table $C00 (512 longs), HFS, SCSI, ROM resources
- Toolbox traps: Pascal stack convention (result space first, callee pops); OS traps: A0 = parameter block, D0 = result
- Applications: A5 world (globals below, jump table above A5), CODE 0 jump table, segments loaded by `_LoadSeg`

## Output Format

vasm Motorola syntax: `MC68000`, trap macros, `EQU` blocks, `ORG` per
region, `SUB_xxxxxx`/`L_xxxxxx`/`D_xxxxxx` labels, `DC.B` text (Pascal
strings marked), `DC.W`/`DC.L` data and tables, `DCB.B` fills. The full spec
is in the m68k-disassemble skill.
