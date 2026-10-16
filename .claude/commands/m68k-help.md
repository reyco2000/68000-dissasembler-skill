Look up quick reference information for 68000, Macintosh (128K / 512K / Plus) and Atari ST / STE programming. Read and use the files in the `reference/` directory to answer questions about:

- **A-line traps**: `reference/mac_traps.md`: every trap word with its manager. Decode any trap word with `python3 tools/macsyms.py --trap A9F4` (shows flags such as ,ASYNC ,SYS ,CLEAR ,AUTOPOP)
- **Low memory**: `reference/mac_lowmem.md`: 68000 exception vectors and system globals ($100-$BFF)
- **Hardware**: `reference/mac_hardware.md`: VIA, IWM, SCC and Mac Plus SCSI registers; VIA port bit meanings are in `reference/mac_rom_notes.md`
- **ROMs and conventions**: `reference/mac_rom_notes.md`: ROM checksums and versions, header, address map, 64K vs 128K ROM, trap dispatch, Pascal / register calling conventions, parameter blocks, driver headers
- **Atari TOS calls**: `reference/atari_tos_calls.md`: GEMDOS (TRAP #1), BIOS (#13), XBIOS (#14), AES / VDI (#2), Line-A. Name a call with `python3 tools/atarisyms.py --call 1 0x3D`
- **Atari memory and hardware**: `reference/atari_sysvars.md` (vectors incl. MFP, system variables $400-$5B3), `reference/atari_hardware.md` (video, DMA / FDC, YM2149, DMA sound, blitter, MFP, ACIA)
- **Atari formats and conventions**: `reference/atari_st_notes.md`: TOS header, PRG format and relocation, calling convention, interrupts
- **68000**: `reference/m68k_quickref.md`: addressing modes, opcode map, condition codes, exception vectors, idioms. Decode raw words with `python3 tools/m68k.py 4E75 41FA 0010`

When answering, always provide:
1. The hex address, trap word or opcode
2. The symbolic name
3. What it does, including register / stack inputs and outputs
4. Example usage in vasm Motorola-syntax 68000 assembly if relevant

$arguments: topic — what to look up (e.g. "_GetResource", "Ticks", "vIER", "IWM q7H", "Fopen", "Supexec", "_hz_200", "shiftmd", "MFP Timer C", "MOVEM", "DBF")
