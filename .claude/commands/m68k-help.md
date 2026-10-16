Look up quick reference information for 68000 and Macintosh (128K / 512K / Plus) programming. Read and use the files in the `reference/` directory to answer questions about:

- **A-line traps**: `reference/mac_traps.md`: every trap word with its manager. Decode any trap word with `python3 tools/macsyms.py --trap A9F4` (shows flags such as ,ASYNC ,SYS ,CLEAR ,AUTOPOP)
- **Low memory**: `reference/mac_lowmem.md`: 68000 exception vectors and system globals ($100-$BFF)
- **Hardware**: `reference/mac_hardware.md`: VIA, IWM, SCC and Mac Plus SCSI registers; VIA port bit meanings are in `reference/mac_rom_notes.md`
- **ROMs and conventions**: `reference/mac_rom_notes.md`: ROM checksums and versions, header, address map, 64K vs 128K ROM, trap dispatch, Pascal / register calling conventions, parameter blocks, driver headers
- **68000**: `reference/m68k_quickref.md`: addressing modes, opcode map, condition codes, exception vectors, idioms. Decode raw words with `python3 tools/m68k.py 4E75 41FA 0010`

When answering, always provide:
1. The hex address, trap word or opcode
2. The symbolic name
3. What it does, including register / stack inputs and outputs
4. Example usage in vasm Motorola-syntax 68000 assembly if relevant

$arguments: topic — what to look up (e.g. "_GetResource", "Ticks", "vIER", "IWM q7H", "MOVEM", "ROM85", "DBF")
