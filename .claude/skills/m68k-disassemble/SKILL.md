---
name: m68k-disassemble
description: "Use when the user asks to disassemble, reverse-engineer, or annotate Motorola 68000 code: Macintosh 128K/512K/Plus ROMs, Mac applications / resources (CODE, DRVR, PACK, INIT ...), MacBinary or AppleSingle files, Atari ST TOS ROMs, cartridges, GEMDOS programs (.PRG/.TOS/.TTP/.APP/.ACC) and boot sectors, S-records, Intel HEX, or raw 68000 binaries and SBC ROMs."
---

# Disassemble 68000 / Macintosh / Atari ST Code

Produces annotated **vasm Motorola-syntax** assembly via a chunked pipeline
that keeps the main agent's context small: read only tool stdout and the
manifest, never the full listing or xref output.

Run every command from the repository root (the directory with `tools/`).
`<name>` = input file basename. `<flags>` = the load flags from step 1. Pass
the **same** `<flags>` to steps 2 and 3, or the chunk boundaries won't match
the listing.

**Fast mode**: if the user says "fast" or passes `--fast`, skip step 7.

## Steps

1. **Identify**: `python3 tools/macloader.py <file>`
   - **Mac ROM** (64K = Mac 128K/512K, 128K = Mac Plus/512Ke): detected by
     the checksum in the first long, loaded at $400000, traced from the reset
     PC, the header jumps, driver headers and embedded resources. No flags.
     If the checksum doesn't validate (patched ROM), pass `--rom`. A split
     two-chip dump must be interleaved first (see
     `reference/mac_rom_notes.md`). For a ROM, also run the `mac-rom-map`
     skill.
   - **Atari TOS ROM / EmuTOS** (OSHEADER at 0, base $FC0000 or $E00000) and
     **cartridges** ($FA0000): detected automatically; traced from the reset
     handler and cartridge entries. Also run the `atari-tos-map` skill.
   - **Atari GEMDOS executable** (`.PRG` `.TOS` `.TTP` `.APP` `.ACC`, $601A
     header): TEXT+DATA load at $10000 with relocations applied. Relocated
     longs become labels and nothing else does; a DRI / GST symbol table
     names routines and variables. Output uses TEXT / DATA / BSS sections.
   - **Atari boot sector** (512 bytes, or the first sector of a `.ST` image)
     with the executable checksum $1234: loads at $10000.
   - **Resource fork / MacBinary / AppleSingle**: the loader lists resources.
     Pick one with `--rsrc TYPE:ID` (default: lowest CODE >= 1). CODE
     segments get their jump-table entries (from CODE 0) as `JT_nnn` entry
     points, and `JSR n(A5)` calls into the same segment are resolved.
     Resources load at $10000 so low-memory globals stay distinct; use
     `--org` to change it.
   - **S-records / Intel HEX**: addresses and the start record are used.
   - **Raw binary**: pass `--org <addr>`. An image at 0 that starts with a
     68000 vector table (SSP, PC) gets its reset PC and vectors traced
     (typical for 68000 SBC ROMs). Ask the user for the load address if it
     isn't obvious. Add `--platform mac` / `--platform atari` (or `--mac`,
     `--atari`) for Mac or Atari code: system variables, hardware names,
     line-A meaning and TOS call names.
   - **Extra entry points**: `--entry 0xNNNNNN` (repeatable) for code reached
     only indirectly (trap implementations, callbacks, handlers patched into
     RAM). Recognized automatically: handlers installed into vectors or
     hooks, `JSR (An)` after `LEA x,An`, Atari `Supexec` / `Setexc` /
     `Xbtimer` / `Mfpint` callbacks, and routines that start with a
     `LINK` / `MOVEM.L ...,-(SP)` prologue (`--no-prologues` turns that off).
   - **Dispatch tables**: `--table ADDR:COUNT[:long|word|rel|rel=BASE]`
     (hex ADDR): `long` = 32-bit addresses, `rel` = 16-bit offsets from the
     table (or from BASE). Recognized automatically: `JMP tbl(PC,Dn)` into a
     list of `BRA`s, `MOVE.W tbl(PC,Dn),Dn` + `JMP tbl(PC,Dn)` word-offset
     tables, runs of >= 4 longs pointing at known routines, and (ROMs) long
     runs of ROM-relative words / longs that hit traced routine starts. Each
     appears as an `; Auto-detected ...` header line: sanity-check them;
     `--no-auto-tables` turns this off.
   - **Symbols**: `--symbols FILE` (repeatable; first definition wins).
     JSON schema v1.0, flat JSON `{"0x40A2C4": "InitMem"}`, or
     `NAME EQU $XXXXXX ; comment` lines. If `output/<name>_symbols.json`
     exists from an earlier session, always pass it.
   - **Force data**: `--data-region START-END` (hex, inclusive, repeatable)
     for fonts, bitmaps or tables that the sweep mistakes for code.
   - **Fill mode**: default `--fill validated` turns unreached bytes into code
     only where they follow real code (or are referenced) and decode cleanly
     to RTS/RTE/JMP/BRA. `--fill all` decodes everything decodable (useful to
     eyeball, wrong for data).

2. **Disassemble**: `python3 tools/dasm68k.py <file> <flags> --annotate --output output/<name>.asm`
   - Check the header lines `; Traced instructions: N, swept: S` and
     `; Code bytes: X of Y`. Large data areas between code usually mean
     missing entry points. Find them by: (a) `JMP (An)` / `JSR (An)` /
     `JMP tbl(PC,Dn)` dispatchers in traced code, (b) handlers installed
     into vectors or low-memory hooks (`; Vector install` lines name them
     automatically), (c) the largest runs of `DC.W` that look like code.
     Rerun with `--entry` / `--table`. Keep the final flags in one variable
     and reuse them in every step.

3. **Section map**: `python3 tools/xref.py <file> <flags> --sections --max-chunks N --output output/<name>_sections.json`
   - N ≈ listing lines / 500 (`grep -c . output/<name>.asm`). A full ROM
     listing runs to tens of thousands of lines; chunks should stay ≤ 35KB.

4. **Split**: `python3 tools/annotator.py --split --asm output/<name>.asm --sections output/<name>_sections.json --output-dir output/<name>_chunks/`

5. **Read the manifest**: `output/<name>_chunks/manifest.json` (per chunk:
   subroutines, traps, low-memory globals, hardware, self-modifying code).

6. **Python annotation**: `python3 tools/annotator.py --annotate --manifest output/<name>_chunks/manifest.json --ref-dir reference/`
   - Zero-LLM-token pattern rules: hardware register access through a base
     register (Mac `MOVEA.L (VIA).W,A1` then `$1C00(A1)` = vIER, including
     VIA port bit names; Atari `LEA ($FFFFFA00).W,A1` then `$17(A1)` = MFP
     vr), YM2149 register selects, resolution / palette writes, IKBD
     commands, interrupt masking via SR, vector installs,
     `_Pack` selectors, Pascal result space and returns, frames and register
     saves, copy / clear loops, ROM85 version checks, self-modifying code.

7. **Optional LLM annotation** (skip in fast mode): pick up to 2 chunks with
   the most subroutines + traps + hardware accesses. Dispatch one
   **foreground** subagent per chunk, in parallel (never background /
   `run_in_background`, they must be able to prompt for permissions). Each
   subagent (~30KB context budget):
   - Reads its chunk file (already Python-annotated) and
     `reference/mac_rom_notes.md` if it needs Mac context.
   - Adds `;` commentary: routine purpose, register / stack inputs and
     outputs, Pascal vs register calling convention, block behaviour
     (memory manager, file system, QuickDraw, Sony driver, interrupt
     handling), and 68000 techniques (jump tables, DBF loops, bit fiddling,
     self-modifying code).
   - Must not change the address / hex / instruction columns: only append
     comments or insert `;` lines. Writes the chunk back with the Write tool.
   - Give each subagent the facts you established (dispatch tables, entry
     protocols, what a register holds) and tell it to hedge inferences.
   - Ask it to end its report with names it is confident about, as
     `NAME EQU $XXXXXX ; one-line purpose` (valid identifiers, no guesses).
   - **Name propagation**: verify the names against the code, add them to
     `output/<name>_symbols.json` (schema v1.0) and run
     `python3 tools/annotator.py --manifest output/<name>_chunks/manifest.json --apply-symbols output/<name>_symbols.json`.
     This renames `SUB_xxxxxx` / `L_xxxxxx` / `D_xxxxxx` in every chunk and
     keeps all comments. Append `--symbols output/<name>_symbols.json` to the
     saved flags.
   - Before the subagents run, copy the Python-annotated chunks; afterwards
     check that every code line is unchanged apart from comments, then merge.

8. **Merge**: `python3 tools/annotator.py --merge --manifest output/<name>_chunks/manifest.json --output output/<name>_annotated.asm`
   - For a rebuildable copy add `--reassemble --output output/<name>_annotated.s`;
     `vasmm68k_mot -Fbin -no-opt -m68000 -o x.bin output/<name>_annotated.s`
     gives back the original bytes (`-no-opt` is required). GEMDOS
     executables rebuild with `-Ftos -nosym` instead of `-Fbin` (the exact
     command is in the listing header).

9. **Save the flags** to `output/<name>_flags.txt`.

10. **Present findings** from the manifest and tool stdout only: format and
    load address, ROM identity / checksum, chunk count and total lines, key
    subroutines, traps / TOS system calls used, low-memory globals or system
    variables and hardware touched, vector installs, auto-detected tables,
    output paths.

## References

- `reference/mac_traps.md`: every A-trap with its manager (parsed by the annotator)
- `reference/atari_tos_calls.md`: GEMDOS / BIOS / XBIOS functions, AES / VDI, Line-A
- `reference/atari_sysvars.md`, `reference/atari_hardware.md`: Atari vectors, system variables, ST / STE registers (parsed)
- `reference/atari_st_notes.md`: TOS header, PRG format, calls, interrupts, hardware
- `reference/mac_lowmem.md`: exception vectors and system globals (parsed)
- `reference/mac_hardware.md`: VIA, IWM, SCC, SCSI registers (parsed)
- `reference/mac_rom_notes.md`: ROM families, header, address map, trap dispatch, calling conventions
- `reference/m68k_quickref.md`: addressing modes, opcode map, condition codes, vectors, idioms

## Output

vasm Motorola syntax: `MC68000`, one macro per line-A word (Mac traps such as
`_GetResource`, `_Read_ASYNC`; Atari `_LineA_Init`), `EQU` blocks for
vectors, system variables, hardware (Atari: sign-extended `$FFFF8240`) and
user symbols, `ORG` per region (TEXT / DATA / BSS for GEMDOS executables), `SUB_xxxxxx` / `L_xxxxxx` / `D_xxxxxx` labels
(or real names), explicit sizes everywhere (`BRA.S`, `($016A).W`,
`($00400000).L`), `DC.B` text with Pascal strings marked, `DC.W` / `DC.L` data
and tables, `DCB.B` fills.
