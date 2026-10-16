#!/usr/bin/env python3
"""
atarisyms.py — Atari ST / STE symbol tables: TOS system calls (GEMDOS,
BIOS, XBIOS, AES/VDI), Line-A graphics opcodes, system variables,
exception / MFP vectors, ST and STE hardware registers, TOS versions.
Usage: python3 atarisyms.py --markdown calls|sysvars|hardware   (regenerates
       the tables in reference/; the annotator parses those rows)
       python3 atarisyms.py --call 1 0x3D                       (TRAP #1 function $3D)

Sources: the Atari ST BIOS / GEMDOS / XBIOS references and the ST hardware
register documentation as commonly reproduced (Atari Compendium, ST
Internals, Hatari / EmuTOS sources for cross-checking names).
"""

import argparse
import sys

# ===========================================================================
# SYSTEM CALLS: TRAP #1 GEMDOS, TRAP #13 BIOS, TRAP #14 XBIOS
# ===========================================================================
GEMDOS = {
    0x00: "Pterm0", 0x01: "Cconin", 0x02: "Cconout", 0x03: "Cauxin", 0x04: "Cauxout",
    0x05: "Cprnout", 0x06: "Crawio", 0x07: "Crawcin", 0x08: "Cnecin", 0x09: "Cconws",
    0x0A: "Cconrs", 0x0B: "Cconis", 0x0E: "Dsetdrv", 0x10: "Cconos", 0x11: "Cprnos",
    0x12: "Cauxis", 0x13: "Cauxos", 0x14: "Maddalt", 0x19: "Dgetdrv", 0x1A: "Fsetdta",
    0x20: "Super", 0x2A: "Tgetdate", 0x2B: "Tsetdate", 0x2C: "Tgettime", 0x2D: "Tsettime",
    0x2F: "Fgetdta", 0x30: "Sversion", 0x31: "Ptermres", 0x36: "Dfree", 0x39: "Dcreate",
    0x3A: "Ddelete", 0x3B: "Dsetpath", 0x3C: "Fcreate", 0x3D: "Fopen", 0x3E: "Fclose",
    0x3F: "Fread", 0x40: "Fwrite", 0x41: "Fdelete", 0x42: "Fseek", 0x43: "Fattrib",
    0x44: "Mxalloc", 0x45: "Fdup", 0x46: "Fforce", 0x47: "Dgetpath", 0x48: "Malloc",
    0x49: "Mfree", 0x4A: "Mshrink", 0x4B: "Pexec", 0x4C: "Pterm", 0x4E: "Fsfirst",
    0x4F: "Fsnext", 0x56: "Frename", 0x57: "Fdatime",
}
GEMDOS_NORETURN = {0x00, 0x31, 0x4C}

BIOS = {
    0: "Getmpb", 1: "Bconstat", 2: "Bconin", 3: "Bconout", 4: "Rwabs", 5: "Setexc",
    6: "Tickcal", 7: "Getbpb", 8: "Bcostat", 9: "Mediach", 10: "Drvmap", 11: "Kbshift",
}

XBIOS = {
    0: "Initmous", 1: "Ssbrk", 2: "Physbase", 3: "Logbase", 4: "Getrez", 5: "Setscreen",
    6: "Setpalette", 7: "Setcolor", 8: "Floprd", 9: "Flopwr", 10: "Flopfmt", 11: "Dbmsg",
    12: "Midiws", 13: "Mfpint", 14: "Iorec", 15: "Rsconf", 16: "Keytbl", 17: "Random",
    18: "Protobt", 19: "Flopver", 20: "Scrdmp", 21: "Cursconf", 22: "Settime", 23: "Gettime",
    24: "Bioskeys", 25: "Ikbdws", 26: "Jdisint", 27: "Jenabint", 28: "Giaccess",
    29: "Offgibit", 30: "Ongibit", 31: "Xbtimer", 32: "Dosound", 33: "Setprt", 34: "Kbdvbase",
    35: "Kbrate", 36: "Prtblk", 37: "Vsync", 38: "Supexec", 39: "Puntaes", 41: "Floprate",
    42: "DMAread", 43: "DMAwrite", 44: "Bconmap", 46: "NVMaccess", 64: "Blitmode",
    80: "EsetShift", 81: "EgetShift", 82: "EsetBank", 83: "EsetColor", 84: "EsetPalette",
    85: "EgetPalette", 86: "EsetGray", 87: "EsetSmear", 88: "VsetMode", 89: "mon_type",
    90: "VsetSync", 91: "VgetSize", 93: "VsetRGB", 94: "VgetRGB",
    128: "locksnd", 129: "unlocksnd", 130: "soundcmd", 131: "setbuffer", 132: "setmode",
    133: "settracks", 134: "setmontracks", 135: "setinterrupt", 136: "buffoper",
    137: "dsptristate", 138: "gpio", 139: "devconnect", 140: "sndstatus", 141: "buffptr",
}

TRAP_SYSTEMS = {1: ("GEMDOS", GEMDOS), 13: ("BIOS", BIOS), 14: ("XBIOS", XBIOS)}

CALL_DESC = {
    "Pterm0": "terminate the program (exit code 0)", "Pterm": "terminate the program with an exit code",
    "Ptermres": "terminate and stay resident", "Cconin": "read a character from the console",
    "Cconout": "write a character to the console", "Cconws": "write a C string to the console",
    "Cconrs": "read an edited line from the console", "Cconis": "console input status",
    "Crawio": "raw console I/O", "Crawcin": "raw console input (wait for a key)",
    "Cnecin": "console input without echo", "Super": "switch supervisor / user mode (D0 = old SSP)",
    "Dsetdrv": "set the default drive", "Dgetdrv": "get the default drive",
    "Fsetdta": "set the disk transfer address", "Fgetdta": "get the disk transfer address",
    "Sversion": "GEMDOS version", "Dfree": "free disk space", "Dcreate": "create a directory",
    "Ddelete": "delete a directory", "Dsetpath": "set the current directory",
    "Dgetpath": "get the current directory", "Fcreate": "create a file (D0 = handle or error)",
    "Fopen": "open a file (D0 = handle or error)", "Fclose": "close a file", "Fread": "read from a file",
    "Fwrite": "write to a file", "Fdelete": "delete a file", "Fseek": "seek in a file",
    "Fattrib": "get / set file attributes", "Fsfirst": "find the first matching file",
    "Fsnext": "find the next matching file", "Frename": "rename a file",
    "Fdatime": "get / set file date and time", "Malloc": "allocate memory (-1 = largest free block)",
    "Mxalloc": "allocate ST / alternate RAM", "Mfree": "free memory", "Mshrink":
    "shrink a memory block (programs release unused TPA at startup)", "Pexec": "load / execute a program",
    "Tgetdate": "get the date", "Tgettime": "get the time", "Tsetdate": "set the date", "Tsettime": "set the time",
    "Getmpb": "get the memory parameter block", "Bconstat": "device input status", "Bconin":
    "read a character from a device", "Bconout": "write a character to a device",
    "Rwabs": "read / write disk sectors", "Setexc": "set or read an exception vector",
    "Tickcal": "milliseconds per timer tick", "Getbpb": "get a drive's BIOS parameter block",
    "Bcostat": "device output status", "Mediach": "media change status", "Drvmap": "mounted drives bit map",
    "Kbshift": "keyboard shift state", "Initmous": "initialize mouse packet handling",
    "Physbase": "physical screen address", "Logbase": "logical screen address",
    "Getrez": "current resolution", "Setscreen": "set screen addresses and resolution",
    "Setpalette": "load a 16-color palette at the next VBL", "Setcolor": "set / read one palette color",
    "Floprd": "read floppy sectors", "Flopwr": "write floppy sectors", "Flopfmt": "format a floppy track",
    "Midiws": "send bytes to MIDI", "Mfpint": "set an MFP interrupt vector", "Iorec": "serial / keyboard / MIDI buffer records",
    "Rsconf": "configure the serial port", "Keytbl": "set keyboard translation tables",
    "Random": "24-bit pseudo-random number", "Protobt": "build a boot sector",
    "Scrdmp": "screen dump", "Cursconf": "cursor configuration", "Settime": "set the keyboard clock",
    "Gettime": "read the keyboard clock", "Bioskeys": "restore default key tables",
    "Ikbdws": "send bytes to the keyboard processor (IKBD)", "Jdisint": "disable an MFP interrupt",
    "Jenabint": "enable an MFP interrupt", "Giaccess": "read / write a YM2149 register",
    "Offgibit": "clear a bit in YM2149 port A", "Ongibit": "set a bit in YM2149 port A",
    "Xbtimer": "set up an MFP timer and its handler", "Dosound": "play a YM2149 sound list (VBL driven)",
    "Setprt": "printer configuration", "Kbdvbase": "keyboard / MIDI / mouse vector table",
    "Kbrate": "key repeat rate", "Vsync": "wait for the next vertical blank",
    "Supexec": "run a function in supervisor mode", "Blitmode": "blitter configuration",
    "EsetShift": "set TT shifter mode", "VsetMode": "set Falcon video mode",
}
GEM_CALLS = {0xC8: "AES", 0x73: "VDI"}   # TRAP #2 with D0 = 200 / 115


def call_name(trapno: int, fn: int):
    """('GEMDOS', 'Fopen') for TRAP #1 function $3D; None if not a TOS trap."""
    sysname, table = TRAP_SYSTEMS.get(trapno, (None, None))
    if sysname is None:
        return None
    return sysname, table.get(fn, f"{sysname.lower()}_{fn:02X}")


# ===========================================================================
# LINE-A ($A000-$A00F): graphics primitives
# ===========================================================================
LINEA = {
    0x0: ("Init", "initialize: A0 = Line-A variables, A1 = font headers, A2 = routine table"),
    0x1: ("PutPixel", "plot a pixel"), 0x2: ("GetPixel", "read a pixel"),
    0x3: ("ArbLine", "draw an arbitrary line"), 0x4: ("HorLine", "draw a horizontal line"),
    0x5: ("FilledRect", "fill a rectangle"), 0x6: ("FilledPoly", "fill a polygon scan line"),
    0x7: ("BitBlt", "bit block transfer"), 0x8: ("TextBlt", "text block transfer"),
    0x9: ("ShowMouse", "show the mouse pointer"), 0xA: ("HideMouse", "hide the mouse pointer"),
    0xB: ("TransformMouse", "change the mouse pointer form"),
    0xC: ("UndrawSprite", "remove a sprite"), 0xD: ("DrawSprite", "draw a sprite"),
    0xE: ("CopyRaster", "copy raster form"), 0xF: ("SeedFill", "seed fill"),
}


def linea_info(word: int):
    """Line-A word -> trap-style info dict (same keys as macsyms.trap_info)."""
    if (word & 0xF000) != 0xA000:
        return None
    n = word & 0x0FFF
    if n in LINEA:
        name, desc = LINEA[n]
        return {"name": name, "num": n, "os": False, "flags": [], "manager": "Line-A graphics",
                "display": f"LineA {name}", "ident": f"_LineA_{name}", "noreturn": False,
                "known": True, "desc": desc}
    return {"name": f"A{word:04X}", "num": n, "os": False, "flags": [], "manager": "Line-A (unknown)",
            "display": f"LineA ${word:04X}", "ident": f"_LineA_{word:04X}", "noreturn": False,
            "known": False, "desc": ""}


# ===========================================================================
# VECTORS ($000-$13F) and SYSTEM VARIABLES ($400-$5B3)
# ===========================================================================
VECTORS = {
    0x000: ("ResetSSP", "reset: initial SSP (first ROM long mirrored at 0)"),
    0x004: ("ResetPC", "reset: initial PC (second ROM long mirrored at 4)"),
    0x008: ("BusErrVct", "bus error (also: access to I/O area from user mode)"),
    0x00C: ("AdrErrVct", "address error"), 0x010: ("IllegalVct", "illegal instruction"),
    0x014: ("ZeroDivVct", "divide by zero"), 0x018: ("ChkVct", "CHK instruction"),
    0x01C: ("TrapVVct", "TRAPV"), 0x020: ("PrivlgVct", "privilege violation"),
    0x024: ("TraceVct", "trace"), 0x028: ("LineAVct", "line-A: Atari graphics primitives"),
    0x02C: ("LineFVct", "line-F (AES dispatch in TOS 1.x)"), 0x060: ("SpurVct", "spurious interrupt"),
    0x064: ("AutoInt1", "level 1 autovector (unused on the ST)"),
    0x068: ("HBLVec", "level 2: horizontal blank"), 0x06C: ("AutoInt3", "level 3 autovector (unused)"),
    0x070: ("VBLVec", "level 4: vertical blank"), 0x074: ("AutoInt5", "level 5 autovector (unused)"),
    0x078: ("AutoInt6", "level 6 autovector (MFP is vectored)"), 0x07C: ("NMIVec", "level 7: NMI"),
    0x080: ("Trap0Vct", "TRAP #0"), 0x084: ("GEMDOSVec", "TRAP #1: GEMDOS"),
    0x088: ("GEMVec", "TRAP #2: AES / VDI"), 0x0B4: ("BIOSVec", "TRAP #13: BIOS"),
    0x0B8: ("XBIOSVec", "TRAP #14: XBIOS"),
}
for _i in range(3, 16):
    if 0x80 + 4 * _i not in VECTORS:
        VECTORS[0x80 + 4 * _i] = (f"Trap{_i}Vct", f"TRAP #{_i}")
MFP_SOURCES = ["CentBusy", "DCD", "CTS", "Blitter", "TimerD", "TimerC", "ACIA", "FDC",
               "TimerB", "TxError", "TxEmpty", "RxError", "RxFull", "TimerA", "Ring", "MonoDetect"]
MFP_DESC = ["Centronics busy (GPIP 0)", "RS232 carrier detect (GPIP 1)", "RS232 clear to send (GPIP 2)",
            "blitter done (GPIP 3)", "Timer D: RS232 baud rate", "Timer C: 200 Hz system clock",
            "keyboard / MIDI ACIAs (GPIP 4)", "FDC / hard disk DMA (GPIP 5)",
            "Timer B: horizontal blank counter", "RS232 transmit error", "RS232 transmit buffer empty",
            "RS232 receive error", "RS232 receive buffer full", "Timer A (free, used by DMA sound)",
            "RS232 ring indicator (GPIP 6)", "monochrome monitor detect (GPIP 7)"]
for _i in range(16):
    VECTORS[0x100 + 4 * _i] = (f"MFP_{MFP_SOURCES[_i]}", f"MFP interrupt {_i}: {MFP_DESC[_i]}")

SYSVARS = {
    0x400: ("etv_timer", "timer handoff vector (called from the 200 Hz interrupt every 4th tick)"),
    0x404: ("etv_critic", "critical error handler"), 0x408: ("etv_term", "process terminate handler"),
    0x40C: ("etv_xtra", "5 reserved logical vectors ($40C-$41F)"),
    0x420: ("memvalid", "$752019F3 when the memory configuration is valid"),
    0x424: ("memcntlr", "byte: memory controller configuration"),
    0x426: ("resvalid", "$31415926: jump through resvector on reset"),
    0x42A: ("resvector", "reset handler (used when resvalid is set)"),
    0x42E: ("phystop", "physical top of ST RAM"), 0x432: ("_membot", "bottom of available memory"),
    0x436: ("_memtop", "top of available memory"), 0x43A: ("memval2", "$237698AA when memory is valid"),
    0x43E: ("flock", "word: floppy / DMA lock (non-zero while in use)"),
    0x440: ("seekrate", "word: floppy seek rate"), 0x442: ("_timr_ms", "word: milliseconds per timer tick (20)"),
    0x444: ("_fverify", "word: floppy write verify flag"), 0x446: ("_bootdev", "word: boot device"),
    0x448: ("palmode", "word: non-zero = PAL (50 Hz)"), 0x44A: ("defshiftmd", "byte: default resolution"),
    0x44C: ("sshiftmd", "word: shadow of the shifter mode (resolution)"),
    0x44E: ("_v_bas_ad", "logical screen base"), 0x452: ("vblsem", "word: VBL semaphore (0 = VBL routines off)"),
    0x454: ("nvbls", "word: number of VBL slots"), 0x456: ("_vblqueue", "pointer to the VBL slot list"),
    0x45A: ("colorptr", "palette to load at the next VBL (0 = none)"),
    0x45E: ("screenpt", "screen base to set at the next VBL (0 = none)"),
    0x462: ("_vbclock", "VBL interrupt count"), 0x466: ("_frclock", "VBL count (not blocked by vblsem)"),
    0x46A: ("hdv_init", "hard disk initialization vector"), 0x46E: ("swv_vec", "monitor change vector"),
    0x472: ("hdv_bpb", "Getbpb vector"), 0x476: ("hdv_rw", "Rwabs vector"),
    0x47A: ("hdv_boot", "hard disk boot vector"), 0x47E: ("hdv_mediach", "Mediach vector"),
    0x482: ("_cmdload", "word: non-zero = load COMMAND.PRG at boot"),
    0x484: ("conterm", "byte: console flags (bit 0 click, 1 repeat, 2 bell, 3 Kbshift in Bconin)"),
    0x486: ("trp14ret", "saved return address for TRAP #14"), 0x48A: ("criticret", "saved return for etv_critic"),
    0x48E: ("themd", "GEMDOS memory descriptor (16 bytes)"), 0x49E: ("____md", "space for more descriptors"),
    0x4A2: ("savptr", "BIOS register save area pointer"), 0x4A6: ("_nflops", "word: number of floppy drives"),
    0x4A8: ("con_state", "console output state vector"), 0x4AC: ("save_row", "word: saved cursor row"),
    0x4AE: ("sav_context", "pointer to the exception context save area"),
    0x4B2: ("_bufl", "two GEMDOS buffer list headers"), 0x4BA: ("_hz_200", "200 Hz system tick counter"),
    0x4BE: ("the_env", "default environment string"), 0x4C2: ("_drvbits", "bit mask of mounted drives"),
    0x4C6: ("_dskbufp", "pointer to the 1K disk buffer"), 0x4CA: ("_autopath", "AUTO folder path pointer"),
    0x4CE: ("_vbl_list", "8 default VBL slots"), 0x4EE: ("_prt_cnt", "word: screen dump flag (Alt-Help)"),
    0x4F0: ("_prtabt", "word: printer abort flag"), 0x4F2: ("_sysbase", "pointer to the OS header"),
    0x4F6: ("_shell_p", "shell-specific context pointer"), 0x4FA: ("end_os", "first byte after OS RAM"),
    0x4FE: ("exec_os", "shell (AES) start address"), 0x502: ("scr_dump", "screen dump vector"),
    0x506: ("prv_lsto", "printer output status vector"), 0x50A: ("prv_lst", "printer output vector"),
    0x50E: ("prv_auxo", "aux output status vector"), 0x512: ("prv_aux", "aux output vector"),
    0x516: ("pun_ptr", "hard disk driver unit info"), 0x51A: ("memval3", "$5555AAAA when memory is valid"),
    0x51E: ("xconstat", "8 Bconstat vectors"), 0x53E: ("xconin", "8 Bconin vectors"),
    0x55E: ("xcostat", "8 Bcostat vectors"), 0x57E: ("xconout", "8 Bconout vectors"),
    0x59E: ("_longframe", "word: non-zero if the CPU uses long exception frames"),
    0x5A0: ("_p_cookies", "cookie jar pointer (TOS 1.6+)"), 0x5A4: ("ramtop", "top of TT / alternate RAM"),
    0x5A8: ("ramvalid", "$1357BD13 when ramtop is valid"), 0x5AC: ("bell_hook", "bell sound vector"),
    0x5B0: ("kcl_hook", "key click vector"),
}
# Low-memory longs that hold code pointers (installs into them name a handler)
HOOKS = {0x400, 0x404, 0x408, 0x42A, 0x46A, 0x46E, 0x472, 0x476, 0x47A, 0x47E, 0x4FE, 0x502,
         0x506, 0x50A, 0x50E, 0x512, 0x5AC, 0x5B0}

# ===========================================================================
# HARDWARE ($FF8000-$FFFFFF; write as ($FFFFxxxx).W in source)
# ===========================================================================
HARDWARE = {
    0xFF8001: ("memconf", "MMU memory configuration"),
    0xFF8201: ("dbaseh", "video base address high byte"), 0xFF8203: ("dbasel", "video base address mid byte"),
    0xFF8205: ("vcounthi", "video address counter high"), 0xFF8207: ("vcountmid", "video address counter mid"),
    0xFF8209: ("vcountlo", "video address counter low"), 0xFF820A: ("syncmode", "sync mode (bit 1: 50 Hz)"),
    0xFF820D: ("dbaselo", "video base address low byte (STE)"),
    0xFF820F: ("linewid", "extra words per scan line (STE)"),
    0xFF8260: ("shiftmd", "shifter resolution: 0 low, 1 medium, 2 high"),
    0xFF8265: ("hscroll", "horizontal pixel scroll (STE)"),
    0xFF8604: ("diskctl", "FDC / hard disk register access (via dmamode)"),
    0xFF8606: ("dmamode", "DMA mode (write) / DMA status (read)"),
    0xFF8609: ("dmahigh", "DMA address high"), 0xFF860B: ("dmamid", "DMA address mid"),
    0xFF860D: ("dmalow", "DMA address low"),
    0xFF8800: ("giselect", "YM2149: select register (write) / read data"),
    0xFF8802: ("giwrite", "YM2149: write data to the selected register"),
    0xFF8901: ("sndmactl", "DMA sound control (STE)"),
    0xFF8903: ("sndbashi", "DMA sound frame start high (STE)"), 0xFF8905: ("sndbasmi", "frame start mid"),
    0xFF8907: ("sndbaslo", "frame start low"), 0xFF8909: ("sndadrhi", "DMA sound address counter high"),
    0xFF890B: ("sndadrmi", "address counter mid"), 0xFF890D: ("sndadrlo", "address counter low"),
    0xFF890F: ("sndendhi", "DMA sound frame end high"), 0xFF8911: ("sndendmi", "frame end mid"),
    0xFF8913: ("sndendlo", "frame end low"), 0xFF8921: ("sndmode", "DMA sound mode: rate / mono (STE)"),
    0xFF8922: ("mwdata", "Microwire data (STE volume / tone)"), 0xFF8924: ("mwmask", "Microwire mask"),
    0xFF8A20: ("src_xinc", "blitter source X increment"), 0xFF8A22: ("src_yinc", "blitter source Y increment"),
    0xFF8A24: ("src_addr", "blitter source address"), 0xFF8A28: ("endmask1", "blitter left end mask"),
    0xFF8A2A: ("endmask2", "blitter middle end mask"), 0xFF8A2C: ("endmask3", "blitter right end mask"),
    0xFF8A2E: ("dst_xinc", "blitter destination X increment"),
    0xFF8A30: ("dst_yinc", "blitter destination Y increment"),
    0xFF8A32: ("dst_addr", "blitter destination address"), 0xFF8A36: ("x_count", "blitter X count (words)"),
    0xFF8A38: ("y_count", "blitter Y count (lines)"), 0xFF8A3A: ("hop", "blitter halftone operation"),
    0xFF8A3B: ("op", "blitter logic operation"),
    0xFF8A3C: ("line_num", "blitter control: busy, hog, smudge, halftone line"),
    0xFF8A3D: ("skew", "blitter skew: FXSR, NFSR, shift"),
    0xFF9200: ("joy_fire", "STE joypad fire buttons"), 0xFF9202: ("joy_dir", "STE joypad directions"),
    0xFFFA01: ("gpip", "MFP general purpose I/O data"), 0xFFFA03: ("aer", "MFP active edge register"),
    0xFFFA05: ("ddr", "MFP data direction"), 0xFFFA07: ("iera", "MFP interrupt enable A"),
    0xFFFA09: ("ierb", "MFP interrupt enable B"), 0xFFFA0B: ("ipra", "MFP interrupt pending A"),
    0xFFFA0D: ("iprb", "MFP interrupt pending B"), 0xFFFA0F: ("isra", "MFP interrupt in-service A"),
    0xFFFA11: ("isrb", "MFP interrupt in-service B"), 0xFFFA13: ("imra", "MFP interrupt mask A"),
    0xFFFA15: ("imrb", "MFP interrupt mask B"), 0xFFFA17: ("vr", "MFP vector register (vector base, S bit)"),
    0xFFFA19: ("tacr", "MFP Timer A control"), 0xFFFA1B: ("tbcr", "MFP Timer B control"),
    0xFFFA1D: ("tcdcr", "MFP Timers C / D control"), 0xFFFA1F: ("tadr", "MFP Timer A data"),
    0xFFFA21: ("tbdr", "MFP Timer B data"), 0xFFFA23: ("tcdr", "MFP Timer C data"),
    0xFFFA25: ("tddr", "MFP Timer D data"), 0xFFFA27: ("scr", "MFP USART sync character"),
    0xFFFA29: ("ucr", "MFP USART control"), 0xFFFA2B: ("rsr", "MFP USART receiver status"),
    0xFFFA2D: ("tsr", "MFP USART transmitter status"), 0xFFFA2F: ("udr", "MFP USART data"),
    0xFFFC00: ("keyctl", "keyboard ACIA control / status"), 0xFFFC02: ("keybd", "keyboard ACIA data"),
    0xFFFC04: ("midictl", "MIDI ACIA control / status"), 0xFFFC06: ("midi", "MIDI ACIA data"),
}
for _i in range(16):
    HARDWARE[0xFF8240 + 2 * _i] = (f"color{_i}", f"palette register {_i} (0RGB, 3 bits per gun on the ST)")
for _i in range(16):
    HARDWARE[0xFF8A00 + 2 * _i] = (f"halftone{_i}", f"blitter halftone RAM word {_i}")

YM_REGS = ["channel A fine tune", "channel A coarse tune", "channel B fine tune", "channel B coarse tune",
           "channel C fine tune", "channel C coarse tune", "noise period", "mixer (tone / noise enable)",
           "channel A volume", "channel B volume", "channel C volume", "envelope period fine",
           "envelope period coarse", "envelope shape",
           "port A: floppy side / drive select, RTS, DTR, strobe, GPO", "port B: printer data"]

DEVICE_RANGES = [
    (0xFF8000, 0xFF8001, "MMU"), (0xFF8200, 0xFF82FF, "video"), (0xFF8600, 0xFF860F, "DMA / FDC"),
    (0xFF8800, 0xFF88FF, "YM2149 sound"), (0xFF8900, 0xFF893F, "DMA sound"), (0xFF8A00, 0xFF8A3F, "blitter"),
    (0xFF9200, 0xFF9203, "joypad"), (0xFFFA00, 0xFFFA3F, "MFP"), (0xFFFC00, 0xFFFC07, "ACIA"),
]
ADDRESS_MAP = [
    (0x000000, 0x000007, "ROM mirror at reset (SSP, PC)"),
    (0x000008, 0x0003FF, "exception and MFP vectors"), (0x000400, 0x0005FF, "TOS system variables"),
    (0x000000, 0x3FFFFF, "ST RAM (up to 4MB)"), (0xE00000, 0xEFFFFF, "TOS 1.06+/2.x ROM (256K), EmuTOS"),
    (0xFA0000, 0xFBFFFF, "cartridge ROM (128K)"), (0xFC0000, 0xFEFFFF, "TOS 1.00-1.04 ROM (192K)"),
    (0xFF8000, 0xFFFFFF, "I/O (supervisor mode only)"),
]


def device_of(addr: int):
    for lo, hi, name in DEVICE_RANGES:
        if lo <= addr <= hi:
            return name
    return None


# ===========================================================================
# TOS VERSIONS
# ===========================================================================
TOS_VERSIONS = {
    0x0100: "TOS 1.00 (520/1040ST, 1985)", 0x0102: "TOS 1.02 (Mega ST, 1987)",
    0x0104: "TOS 1.04 (Rainbow TOS, 1989)", 0x0106: "TOS 1.06 (STE)", 0x0162: "TOS 1.62 (STE)",
    0x0201: "TOS 2.01", 0x0202: "TOS 2.02", 0x0205: "TOS 2.05 (Mega STE)", 0x0206: "TOS 2.06 (ST/STE)",
    0x0301: "TOS 3.01 (TT)", 0x0305: "TOS 3.05 (TT)", 0x0306: "TOS 3.06 (TT)",
    0x0400: "TOS 4.00 (Falcon)", 0x0401: "TOS 4.01 (Falcon)", 0x0402: "TOS 4.02 (Falcon)",
    0x0404: "TOS 4.04 (Falcon)",
}
COUNTRIES = ["USA", "Germany", "France", "UK", "Spain", "Italy", "Sweden", "Switzerland (French)",
             "Switzerland (German)", "Turkey", "Finland", "Norway", "Denmark", "Saudi Arabia",
             "Netherlands", "Czech Republic", "Hungary"]


def bcd_date(v: int) -> str:
    """os_date $MMDDYYYY (BCD) -> 'YYYY-MM-DD'."""
    s = f"{v:08X}"
    return f"{s[4:8]}-{s[0:2]}-{s[2:4]}"


# ===========================================================================
# MARKDOWN EXPORT
# ===========================================================================

def markdown_calls() -> str:
    out = ["## GEMDOS (TRAP #1)", "",
           "Function number pushed last: `MOVE.W #n,-(SP)` / `TRAP #1`; result in D0.", "",
           "| Function | Name | System |", "|----------|------|--------|"]
    for n, name in sorted(GEMDOS.items()):
        out.append(f"| ${n:02X} | {name} | GEMDOS{' (does not return)' if n in GEMDOS_NORETURN else ''} |")
    out += ["", "## BIOS (TRAP #13)", "", "| Function | Name | System |", "|----------|------|--------|"]
    for n, name in sorted(BIOS.items()):
        out.append(f"| {n} | {name} | BIOS |")
    out += ["", "## XBIOS (TRAP #14)", "", "| Function | Name | System |", "|----------|------|--------|"]
    for n, name in sorted(XBIOS.items()):
        out.append(f"| {n} | {name} | XBIOS |")
    out += ["", "## AES / VDI (TRAP #2)", "",
            "D0 = 200 ($C8): AES call, D1 = AES parameter block; D0 = 115 ($73): VDI call, "
            "D1 = VDI parameter block.", "",
            "## Line-A ($A000-$A00F)", "", "| Opcode | Name | Description |", "|--------|------|-------------|"]
    for n, (name, desc) in sorted(LINEA.items()):
        out.append(f"| ${0xA000 + n:04X} | {name} | {desc} |")
    return "\n".join(out) + "\n"


def markdown_sysvars() -> str:
    out = ["## Exception and MFP Vectors ($000-$13F)", "",
           "| Address | Name | Description |", "|---------|------|-------------|"]
    for a, (n, d) in sorted(VECTORS.items()):
        out.append(f"| ${a:04X} | {n} | {d} |")
    out += ["", "## System Variables ($400-$5B3)", "",
            "Supervisor-only memory, referenced as `(_hz_200).W` etc.", "",
            "| Address | Name | Description |", "|---------|------|-------------|"]
    for a, (n, d) in sorted(SYSVARS.items()):
        out.append(f"| ${a:04X} | {n} | {d} |")
    return "\n".join(out) + "\n"


def markdown_hardware() -> str:
    out = ["| Address | Name | Description |", "|---------|------|-------------|"]
    for a, (n, d) in sorted(HARDWARE.items()):
        out.append(f"| ${a:06X} | {n} | {d} |")
    out += ["", "## YM2149 Registers (select with giselect, write with giwrite)", "",
            "| Register | Function |", "|----------|----------|"]
    for i, d in enumerate(YM_REGS):
        out.append(f"| {i} | {d} |")
    return "\n".join(out) + "\n"


def main():
    p = argparse.ArgumentParser(description="Atari ST symbol tables")
    p.add_argument("--markdown", choices=["calls", "sysvars", "hardware"])
    p.add_argument("--call", nargs=2, metavar=("TRAP", "FN"), help="Name a TOS call, e.g. 1 0x3D")
    a = p.parse_args()
    if a.call:
        r = call_name(int(a.call[0], 0), int(a.call[1], 0))
        print(f"{r[0]} {r[1]}" if r else "not a GEMDOS/BIOS/XBIOS trap")
    elif a.markdown:
        sys.stdout.write({"calls": markdown_calls, "sysvars": markdown_sysvars,
                          "hardware": markdown_hardware}[a.markdown]())
    else:
        p.print_help()


if __name__ == "__main__":
    main()
