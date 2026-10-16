---
name: atari-tos-map
description: "Use when the user asks to identify, analyze or map an Atari ST / STE ROM (TOS 1.x / 2.x, EmuTOS, also TT/Falcon TOS dumps) or a ROM cartridge: TOS version, date, country, header, address map, layout, handlers, hardware ownership, subroutine roles."
---

# Map an Atari ST TOS ROM

Builds a structural map of a TOS ROM (or EmuTOS, or a cartridge) from the
image itself. Run every command from the repository root.

## Steps

1. **Identify**: `python3 tools/macloader.py <rom>`
   - A TOS ROM is recognized by its OSHEADER: `BRA` at 0, `os_beg` at offset
     8 ($FC0000 for 192K TOS 1.00-1.04, $E00000 for 256K TOS 1.06 / 1.62 /
     2.0x and EmuTOS) and the reset handler at offset 4. The report shows
     version, build date, country, PAL / NTSC and whether it is EmuTOS.
   - Dumps from two 8-bit EPROMs (or 6 chips on early 192K STs) must be
     interleaved high / low byte first; if the loader reports `raw`, the
     header is not where it should be. A ROM at another address: pass
     `--org` with the `os_beg` value.
   - Cartridges ($ABCDEF42 or diagnostic $FA52235F) load at $FA0000 with
     each application's init / run entry.

2. **Build the map**:
   `python3 tools/rommap.py <rom> <flags> --output output/<name>_map.md --json output/<name>_map.json`
   Read the map, not the full listing. It contains:
   - Identity (TOS version word, date, country, video standard, os_beg,
     reset handler, EmuTOS flag) and the ST address map
   - Coverage and auto-detected tables (jump tables, pointer tables)
   - Layout regions (header, code, text, fonts / data)
   - Named entry points: `ResetEntry`, `OS_Entry`, handlers named from the
     vectors they are installed into (`VBL_Handler`, `MFP_TimerC_Handler`,
     `GEMDOS_Handler`, `BIOS_Handler`, `XBIOS_Handler`, `LineA_Handler`,
     `hdv_boot_Proc`, `etv_timer_Proc` ...)
   - Subroutines with size, callers, system calls / Line-A used, system
     variables, hardware touched and role tags (video, sound (YM2149), disk
     (DMA / FDC), MFP, keyboard / MIDI (ACIA), blitter, VBL, timing ...)
   - Hardware usage per device, system-variable readers / writers, strings,
     largest data blocks (system fonts, mouse forms, desktop resources)

3. **Find the OS layers** *(typical layout)*: the BIOS / XBIOS dispatchers
   are the `BIOS_Handler` / `XBIOS_Handler` installed into $B4 / $B8 (each
   indexes a function table: once you find it, pass it with
   `--table ADDR:COUNT:long` to name and trace every function), GEMDOS
   is `GEMDOS_Handler` ($84), AES / VDI enter through `GEM_Handler` ($88).
   Hardware initialization runs from `ResetEntry` (memory sizing with
   `memconf`, MFP / ACIA / YM setup, video).

4. **Improve coverage**: large `data` regions in the middle of code usually
   mean dispatch tables. Add `--table` / `--entry`, record names in
   `output/<name>_symbols.json` (schema v1.0) and rerun with
   `--symbols output/<name>_symbols.json`. TOS 1.x AES / VDI code uses
   line-F words as compact calls; the tracer continues past them.

5. **Full annotated listing** (optional): follow the `m68k-disassemble`
   skill with the same flags.

6. **Report**: TOS version / date / country, size and base, coverage, the
   handler set (which vectors the ROM installs and where), dispatcher and
   table locations found, hardware ownership by device, main functional
   areas by address range, output paths. Say which statements are inferred
   (role tags, layer boundaries) and which are read from the bytes.

## Tips

- Hardware is addressed with absolute short addressing:
  `MOVE.W #$777,($FFFF8240).W`; listings show `(color0).W` with
  `color0 EQU $FFFF8240`.
- System variables ($400-$5B3) appear as `(_hz_200).W`, `(_v_bas_ad).W`; the
  map's readers / writers table quickly separates the VBL code, the disk
  layer (`hdv_*`, `flock`) and memory setup (`phystop`, `_membot`,
  `_memtop`).
- See `reference/atari_st_notes.md` for the OSHEADER, interrupts and
  hardware summary.
- Never commit ROM images or listings made from them (`roms/` and `output/`
  are git-ignored apart from the synthetic fixtures).
