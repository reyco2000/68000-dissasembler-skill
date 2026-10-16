---
name: mac-rom-map
description: "Use when the user asks to identify, analyze or map a Macintosh ROM (Mac 128K, 512K, Plus, 512Ke; also identifies SE/Classic dumps): model and checksum, header, address map, ROM layout, entry points, drivers, resources, trap dispatch table, subroutine map with roles."
---

# Map a Macintosh ROM

Builds a structural map of a 64K (Mac 128K/512K) or 128K (Mac Plus/512Ke) ROM
from the image itself. Run every command from the repository root.

## Steps

1. **Identify**: `python3 tools/macloader.py <rom>`
   - Model comes from the stored checksum (first long); the tool also
     recomputes the checksum. `MISMATCH` = bad dump, wrong byte order, two
     chip halves not interleaved, or a patched ROM. Fix the dump or pass
     `--rom` to analyze it anyway.
   - Version word at offset 8: $0069 = 64K ROM, $0075 = 128K ROM.
   - Reports the reset PC, header `JMP`/`BRA` vectors, device-driver headers
     found anywhere in the image (`.Sony`, `.Sound`, serial ...) and
     embedded resource maps.

2. **Build the map**:
   `python3 tools/macrommap.py <rom> <flags> --output output/<name>_map.md --json output/<name>_map.json`
   (`<flags>` as for disassembly: usually none for a ROM; add `--symbols
   output/<name>_symbols.json` once it exists.) Read the map, not the full
   listing. It contains:
   - Identity, the machine address map (RAM, ROM, SCSI, SCC, IWM, VIA) and
     screen / sound buffer locations by RAM size
   - Coverage (code / table / text / fill / data) and auto-detected tables
   - ROM layout as regions with contents (header, drivers, resources)
   - Named entry points: `ResetEntry`, `HdrJmp_xx`/`HDR_xx`, `DRVR_*`,
     handlers installed into vectors (`Line1010_Handler` = trap dispatcher,
     `AutoInt1_Handler` = VIA interrupt ...), `TRAP_*` when a dispatch table
     was recognized
   - Subroutine table: size, callers, traps called, low-memory globals,
     hardware touched and role tags (floppy (IWM), serial (SCC), VIA, SCSI,
     screen, sound, interrupt handler, memory, file system ...). Tags are
     heuristics.
   - Hardware usage per device, A-traps called from ROM code, low-memory
     global readers / writers, strings, largest non-code blocks (fonts,
     cursors, patterns, bitmaps).

3. **Improve coverage** if the Coverage table shows large `data` areas that
   should be code (a full ROM is mostly code):
   - Follow `Line1010_Handler` in the listing (`python3 tools/dasm68k.py <rom> --annotate -o output/<name>.asm`,
     then read only that routine with offset/limit) to see how the dispatch
     tables at $400 / $C00 are indexed, then find the code that fills them.
     See "64K ROM vs 128K ROM" in `reference/mac_rom_notes.md`.
   - For the 64K ROM, a "dispatch table candidate" with 512 ROM-relative
     words names `TRAP_*` routines automatically: spot-check a few.
   - Add discovered entry points with `--entry` or tables with `--table`,
     record names in `output/<name>_symbols.json` (schema v1.0), and rerun
     step 2 with the same flags.

4. **Full annotated listing** (optional): follow the `m68k-disassemble`
   skill with the same flags.

5. **Report**: model and checksum status, size and version, reset PC and
   header vectors, coverage percentages, drivers and resources found,
   dispatch table status, the main functional areas (group subroutines by
   tag and address range), hardware ownership (which routines drive the
   VIA, IWM, SCC, SCSI), and the output paths. Say which statements are
   inferred (tags, trap mapping) and which are read from the bytes.

## Tips

- Low-memory globals ($100-$BFF) appear as `(Name).W` operands; the map's
  readers / writers table shows which routines own which global, which is
  the quickest way to find the Memory Manager (`SysZone`, `ApplZone`,
  `TheZone`), Event Manager (`EventQueue`), cursor code (`Mouse`,
  `CrsrVis`), the Sony driver (`SonyVars`) and the file system (`VCBQHdr`,
  `FSQHdr`).
- ROM code usually reaches hardware through a base register loaded from
  `VIA` ($1D4), `SCCRd`/`SCCWr` ($1D8/$1DC) or `IWM` ($1E0); the map and the
  annotator track these.
- Fonts in the ROM (and in the 128K ROM's resources) are large non-code
  blocks: mark them with `--data-region` if the sweep picks up bytes there.
- Never commit ROM images or generated listings: `roms/` and `output/` are
  git-ignored except the synthetic fixtures.
