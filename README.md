# Motorola 68000 / Macintosh Disassembler — Code Agent

A Claude Code agent for 68000 disassembly and reverse engineering, focused on
the original Macintosh: the **Macintosh 128K / 512K (64K ROM)** and the
**Macintosh Plus / 512Ke (128K ROM)**. It disassembles ROMs and Mac programs
into reassemblable source and builds a structural **map of the ROM**. It also
works on generic 68000 code: S-records, Intel HEX, and raw SBC ROMs with a
vector table.

It is the 68000 sibling of the
[Apple II 6502 Disassembler Skill](https://github.com/reyco2000/6502-dissasembler-skill)
and the [CoCo 6809 Disassembler Skill](https://github.com/reyco2000/6909-CoCo-Disassembler-Skill),
with the same pipeline and skill layout.

## Quick Start

```bash
cd 68000-dissasembler-skill
claude

/mac-rom-map roms/MacPlus.rom      # identity, layout, entry points, subroutine roles
/m68k-disassemble roms/MacPlus.rom # annotated vasm disassembly (chunked)
/m68k-trace-calls roms/MacPlus.rom # call tree / Mermaid graph with traps per routine
/m68k-help _GetResource            # quick reference ("Ticks", "vIER", "DBF", "ROM85")
```

Try it on the synthetic fixtures first: `roms/fakerom.bin` (a Mac-style test
ROM with a valid checksum, driver, tables and resource map),
`roms/demo.rsrc` (a resource fork with CODE 0 / CODE 1) and
`roms/allmodes.bin` (every 68000 instruction form).

To use the skills from any directory, copy `.claude/skills/*` into
`~/.claude/skills/` and `.claude/commands/*` into `~/.claude/commands/`. The
skills run the tools from this repository's root.

Natural-language requests work too:
- *"Map my Mac Plus ROM and tell me where the Sony driver is"*
- *"Disassemble CODE 1 of this application and explain the event loop"*
- *"Which ROM routines touch the IWM?"*

## Inputs

| Input | How it is loaded |
|-------|------------------|
| Mac ROM image (64K, 128K; 256K/512K identified) | checksum in the first long → model; $400000; reset PC + header jumps + drivers + resources traced |
| Resource fork, MacBinary, AppleSingle / AppleDouble | `--rsrc TYPE:ID` (default lowest CODE ≥ 1); CODE 0 jump table gives entries; loaded at $10000 |
| Motorola S-records / Intel HEX | record addresses and start address |
| Raw binary | `--org`; a 68000 vector table at 0 is traced (reset PC, handlers) |

Apple ROMs are copyrighted and not included. Put your own dumps in `roms/`
(git-ignored). Dumps read from the two ROM chips separately must be
interleaved (high byte, low byte) first: the loader's checksum check tells
you when the order is right.

## Tools

| Tool | Purpose |
|------|---------|
| `tools/macloader.py` | Format detection, ROM identification (checksum, version, reset PC), driver / resource scan |
| `tools/dasm68k.py` | Recursive-descent 68000 disassembler with table recovery and vasm output |
| `tools/xref.py` | Cross-references, trap / low-memory / hardware usage, call graph, chunk map |
| `tools/annotator.py` | Split / pattern-annotate / merge chunked listings, apply symbol names |
| `tools/macrommap.py` | ROM map: identity, layout, entry points, drivers, resources, subroutine roles |
| `tools/m68k.py` | Standalone decoder (`python3 tools/m68k.py 4E75 41FA 0010`) |
| `tools/macsyms.py` | Trap / low-memory / hardware tables (`--trap A51E` decodes a trap word) |

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
```

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
