---
name: m68k-trace-calls
description: "Use when the user asks for a call graph, call tree, execution flow or control-flow map of 68000 code: a Macintosh ROM, a Mac application CODE resource, a driver, an Atari ST TOS ROM or GEMDOS program, or a raw 68000 binary."
---

# Trace 68000 Call Graph

Run from the repository root. Use the same flags as for disassembly
(`--org`, `--rsrc`, `--entry`, `--table`, `--symbols`, `--data-region`,
`--raw`, `--rom`, `--platform`; reuse `output/<name>_flags.txt` if it exists). See
the `m68k-disassemble` skill, step 1.

## Steps

1. **Call tree**: `python3 tools/xref.py <file> <flags> --callgraph [--depth N]`
   - Roots: the entry point (reset PC / CODE entry) plus every routine
     nothing calls (vector handlers, driver routines, header jumps, table
     targets, `--entry` addresses).
   - Each node lists the traps and system calls the routine makes, so the
     tree reads as "what does this do" (Mac: `calls: _NewPtr _BlockMove`;
     Atari: `calls: Fopen Fread Fclose`, `Supexec`, `LineA_Init`).
   - `[external]` = target outside the image (e.g. an application calling
     into ROM), `[recursive]` = already on the current path.
   - `JSR n(A5)` jump-table calls are resolved when the input is a resource
     fork with CODE 0.
2. **Mermaid**: `python3 tools/xref.py <file> <flags> --callgraph --mermaid`
   (external targets drawn as `[[subroutine]]` nodes). For a whole ROM this
   is large: restrict the story to one subtree.
3. **Details**: `python3 tools/xref.py <file> <flags>` gives callers per
   subroutine, traps with call sites, low-memory globals (reads / writes),
   hardware registers, vector installs and data references. Read specific
   ranges of `output/<name>.asm` for loop structure (backward branches are
   marked `; loop back`).
4. **Classify routines**:
   - **Leaf**: no calls out
   - **Trap wrappers / glue**: thin routines around one A-trap
   - **Interrupt / exception handlers**: installed into `$64-$7C` / `$28`,
     end in `RTE`
   - **Trap implementations**: reached only through the dispatch table
     (`TRAP_*` names when the table is recognized)
   - **Dispatchers**: `JMP (An)`, `JSR (An)`, `JMP tbl(PC,Dn)`, A-trap
     dispatch. The static graph can't follow register-indirect calls: name
     the targets and rerun with `--entry` / `--table`.
5. **Explain the flow**: for a Mac ROM, reset → overlay off and hardware
   init → low memory and dispatch tables → managers → boot from disk. For a
   Mac application: `InitGraf` / `InitFonts` / `InitWindows` ... → event
   loop (`_GetNextEvent` / `_WaitNextEvent`) → handlers → `_ExitToShell`.
   For a TOS ROM: reset → memory sizing and hardware init → vectors and
   system variables → BIOS / GEMDOS init → boot (floppy / hard disk / AUTO
   folder) → AES / desktop. For a GEMDOS program: basepage / `Mshrink` →
   `Super` or `Supexec` for hardware → main loop → `Pterm`.

## Caveats

- Trap calls are not call edges: they go through the dispatcher. Use the
  map's trap table (`mac-rom-map`) to connect `_Name` call sites to
  `TRAP_Name` implementations when the dispatch table is known.
- Self-modifying code and patched vectors change targets at run time; treat
  those edges as best-effort.
