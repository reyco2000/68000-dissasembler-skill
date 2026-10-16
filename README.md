# Motorola 68000 Disassembler (Macintosh and Atari ST) — Code Agent

A Claude Code agent for 68000 disassembly and reverse engineering of two
68000 families:

- **Macintosh 128K / 512K (64K ROM)** and **Macintosh Plus / 512Ke (128K ROM)**:
  ROMs, applications and resources
- **Atari ST / STE**: TOS ROMs (1.x, 2.x, EmuTOS), ROM cartridges, GEMDOS
  programs (`.PRG` `.TOS` `.TTP` `.APP` `.ACC`) and boot sectors

It disassembles them into reassemblable source and builds a structural
**map of a ROM**. It also works on generic 68000 code: S-records, Intel HEX,
and raw SBC ROMs with a vector table.

It is the 68000 sibling of the
[Apple II 6502 Disassembler Skill](https://github.com/reyco2000/6502-dissasembler-skill)
and the [CoCo 6809 Disassembler Skill](https://github.com/reyco2000/6909-CoCo-Disassembler-Skill),
with the same pipeline and skill layout.

## Quick Start

```bash
cd 68000-dissasembler-skill
claude

/mac-rom-map roms/MacPlus.rom      # Mac ROM: identity, layout, entry points, subroutine roles
/atari-tos-map roms/tos104uk.img   # Atari TOS ROM: version, handlers, hardware ownership
/m68k-disassemble roms/GAME.PRG    # annotated vasm disassembly (chunked), any supported input
/m68k-trace-calls roms/MacPlus.rom # call tree / Mermaid graph with traps / system calls per routine
/m68k-help Supexec                 # quick reference ("_GetResource", "Ticks", "vIER", "_hz_200", "DBF")
```

Try it on the synthetic fixtures first: `roms/fakerom.bin` (a Mac-style test
ROM with a valid checksum, driver, tables and resource map),
`roms/demo.rsrc` (a resource fork with CODE 0 / CODE 1), `roms/faketos.img`
(a TOS 1.04-style ROM header and init code), `roms/hello.prg` (a GEMDOS
program with relocations and BSS; `hello_sym.prg` adds a symbol table) and
`roms/allmodes.bin` (every 68000 instruction form). EmuTOS
(https://emutos.sourceforge.io) is a free, real TOS ROM to practice on.

To use the skills from any directory, copy `.claude/skills/*` into
`~/.claude/skills/` and `.claude/commands/*` into `~/.claude/commands/`. The
skills run the tools from this repository's root.

Natural-language requests work too:
- *"Map my Mac Plus ROM and tell me where the Sony driver is"*
- *"Disassemble CODE 1 of this application and explain the event loop"*
- *"Which ROM routines touch the IWM?"*
- *"Disassemble this ST demo and find its VBL and Timer B handlers"*
- *"Which GEMDOS calls does this PRG make?"*

## Inputs

| Input | How it is loaded |
|-------|------------------|
| Mac ROM image (64K, 128K; 256K/512K identified) | checksum in the first long → model; $400000; reset PC + header jumps + drivers + resources traced |
| Resource fork, MacBinary, AppleSingle / AppleDouble | `--rsrc TYPE:ID` (default lowest CODE ≥ 1); CODE 0 jump table gives entries; loaded at $10000 |
| Atari TOS / EmuTOS ROM | OSHEADER (`BRA`, `os_beg` $FC0000 / $E00000, reset handler) → version, date, country; traced from the reset handler |
| Atari ROM cartridge | $ABCDEF42 / $FA52235F magic; $FA0000; application init / run entries |
| GEMDOS executable (.PRG .TOS .TTP .APP .ACC) | $601A header; TEXT+DATA at $10000 with relocations; DRI / GST symbols |
| Atari boot sector / `.ST` image | executable checksum $1234; $10000 |
| Motorola S-records / Intel HEX | record addresses and start address |
| Raw binary | `--org`; a 68000 vector table at 0 is traced (reset PC, handlers) |

Apple and Atari ROMs are copyrighted and not included. Put your own dumps in
`roms/` (git-ignored). Dumps read from the two ROM chips separately must be
interleaved (high byte, low byte) first: the loader's checksum check tells
you when the order is right.

## Tools

| Tool | Purpose |
|------|---------|
| `tools/macloader.py` | Format detection, ROM identification (checksum, version, reset PC), driver / resource scan |
| `tools/dasm68k.py` | Recursive-descent 68000 disassembler with table recovery and vasm output |
| `tools/xref.py` | Cross-references, trap / low-memory / hardware usage, call graph, chunk map |
| `tools/annotator.py` | Split / pattern-annotate / merge chunked listings, apply symbol names |
| `tools/rommap.py` | ROM map: identity, layout, entry points, drivers, resources, subroutine roles (`macrommap.py` = same tool) |
| `tools/m68k.py` | Standalone decoder (`python3 tools/m68k.py 4E75 41FA 0010`) |
| `tools/macsyms.py` | Mac trap / low-memory / hardware tables (`--trap A51E` decodes a trap word) |
| `tools/atarisyms.py` | Atari TOS calls, Line-A, system variables, ST/STE hardware (`--call 1 0x3D`) |
| `tools/platforms.py` | Per-machine symbol sets (`--platform mac|atari|generic`) |

## What the Agent Knows

- The full MC68000 instruction set and addressing modes, decoded strictly
  (68010/68020 forms and non-canonical encodings stay data)
- ~600 A-line traps with flag decoding (`_Read ,ASYNC`, `_NewPtr ,SYS`,
  `,AUTOPOP`) and their managers; `_Pack` selectors for Standard File,
  International Utilities, Binary-Decimal and Disk Init
- Low-memory globals ($100-$BFF) and exception vectors, VIA / SCC / IWM /
  Mac Plus SCSI registers, VIA port bit meanings
- ROM structure: checksum, header, reset/overlay, 64K vs 128K ROM dispatch
  tables, ROM resources, device-driver headers
- Idioms: Pascal calling convention, A5 world and jump table, `LINK`/`MOVEM`
  frames, `JMP tbl(PC,Dn)` dispatch, vector installs, interrupt masking,
  MacsBug symbol names
- Atari ST: GEMDOS / BIOS / XBIOS calls named from the pushed function number
  (with `Pterm` ending the flow and `Supexec`/`Setexc`/`Xbtimer`/`Mfpint`
  callbacks traced), AES / VDI traps, Line-A graphics, TOS 1.x line-F calls,
  system variables ($400-$5B3), MFP vectors, and the ST / STE registers
  (video, palette, DMA / FDC, YM2149, DMA sound, blitter, MFP 68901, ACIAs)
- GEMDOS executables: the relocation table decides exactly which longs are
  addresses, and output rebuilds as a `.PRG` with TEXT / DATA / BSS sections

## Coverage and Naming

- **Recursive descent plus a validated sweep.** Unreached bytes become code
  only when they follow real code (or are referenced) and decode cleanly to
  RTS/RTE/JMP/BRA. `--fill all` gives a linear decode.
- **Recovered automatically:** PC-relative jump tables (word offsets and
  branch lists), pointer tables, handlers installed into vectors
  (`Line1010_Handler` = trap dispatcher), driver routines, header jumps, A5
  jump-table calls, MacsBug names, and ROM dispatch-table candidates (a
  512-entry table in a 64K ROM names the `TRAP_*` routines).
- **`--symbols FILE`:** your own names (JSON schema v1.0, flat JSON, or
  `NAME EQU $XXXXXX`); `annotator.py --apply-symbols` renames labels in an
  annotated project without losing comments.
- **`--data-region START-END`:** forces bytes to stay data (fonts, bitmaps).

## Output

vasm Motorola syntax. `--no-hex` output (or `annotator.py --merge
--reassemble`) rebuilds to identical bytes:

```bash
python3 tools/dasm68k.py roms/fakerom.bin --no-hex -o fake.s
vasmm68k_mot -Fbin -no-opt -m68000 -o fake.bin fake.s
cmp fake.bin roms/fakerom.bin

python3 tools/dasm68k.py roms/hello.prg --no-hex -o hello.s     # GEMDOS program
vasmm68k_mot -Ftos -nosym -no-opt -m68000 -o hello2.prg hello.s
cmp hello2.prg roms/hello.prg
```

A program that carries a symbol table rebuilds to the same file without it.

### Installing vasm

vasm is not packaged by most distributions; build it from source
(http://sun.hasenbraten.de/vasm/):

```bash
curl -LO http://sun.hasenbraten.de/vasm/release/vasm.tar.gz
tar xzf vasm.tar.gz && cd vasm && make CPU=m68k SYNTAX=mot
sudo cp vasmm68k_mot /usr/local/bin/
```

## Tests

```bash
python3 -m unittest discover -s tests -v        # round-trip tests skip without vasm
python3 tests/fixtures/build_fixtures.py        # rebuild roms/ fixtures (needs vasm)
```

## License

MIT
Built for the CoCoByte Club
by Reinaldo Torres (Chipshift) https://github.com/reyco2000
reyco2000@cocobyte.co
