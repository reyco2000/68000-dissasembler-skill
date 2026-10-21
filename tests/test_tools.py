#!/usr/bin/env python3
"""Tests for the 68000 / Macintosh disassembler tools.

python3 -m unittest discover -s tests -v
Round-trip tests need vasm (vasmm68k_mot on PATH, or VASM=/path/to/it);
they are skipped otherwise. Fixtures in roms/ are synthetic (built by
tests/fixtures/build_fixtures.py), no Apple ROM content.
"""

import io
import json
import os
import random
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from argparse import Namespace

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from tools import macsyms, atarisyms                          # noqa: E402
from tools.m68k import decode, format_instr                   # noqa: E402
from tools.macloader import (identify_file, parse_srecord, parse_ihex,  # noqa: E402
                             parse_macbinary)
from tools.dasm68k import build_disassembler, MemoryImage, Disassembler68k  # noqa: E402
from tools.xref import CrossReferenceBuilder                  # noqa: E402
from tools.rommap import build_map, to_markdown               # noqa: E402
from tools import annotator                                   # noqa: E402
from tools.symbols import load_symbols                        # noqa: E402

ROMS = os.path.join(ROOT, "roms")
FAKEROM = os.path.join(ROMS, "fakerom.bin")
ALLMODES = os.path.join(ROMS, "allmodes.bin")
DEMO_RSRC = os.path.join(ROMS, "demo.rsrc")
HELLO_PRG = os.path.join(ROMS, "hello.prg")
HELLO_SYM = os.path.join(ROMS, "hello_sym.prg")
FAKETOS = os.path.join(ROMS, "faketos.img")
VASM = os.environ.get("VASM") or shutil.which("vasmm68k_mot")


def dis(words, pc=0x1000):
    data = {pc + 2 * i: w for i, w in enumerate(words)}
    ins = decode(pc, lambda a: data.get(a))
    mn, op = format_instr(ins)
    return ins, f"{mn} {op}".strip()


def args_for(path, **kw):
    a = dict(file=path, org=None, raw=False, rom=False, rsrc=None, mac=False, atari=False,
             platform="auto", entry=[], table=[],
             symbols=[], data_region=[], fill="validated", no_fill=False, no_auto_tables=False,
             no_prologues=False)
    a.update(kw)
    return Namespace(**a)


def slurp(path, mode="r"):
    with open(path, mode) as f:
        return f.read()


def assemble(src_path, out_path):
    subprocess.run([VASM, "-quiet", "-Fbin", "-no-opt", "-m68000", "-o", out_path, src_path],
                   check=True, capture_output=True)


# ======================================================================
class TestDecoder(unittest.TestCase):
    def test_known_encodings(self):
        cases = [
            ([0x4E75], "RTS"),
            ([0x203C, 0x1234, 0x5678], "MOVE.L #$12345678,D0"),
            ([0x3238, 0x016A], "MOVE.W ($016A).W,D1"),
            ([0x41EE, 0x0004], "LEA $4(A6),A0"),
            ([0x1430, 0x10FE], "MOVE.B -$2(A0,D1.W),D2"),
            ([0x70FF], "MOVEQ #-$1,D0"),
            ([0x508F], "ADDQ.L #$8,SP"),
            ([0x48E7, 0xFFFE], "MOVEM.L D0-D7/A0-A6,-(SP)"),
            ([0x4CDF, 0x0101], "MOVEM.L (SP)+,D0/A0"),
            ([0x003C, 0x001F], "ORI.B #$1F,CCR"),
            ([0x027C, 0xF8FF], "ANDI.W #$F8FF,SR"),
            ([0xC300], "ABCD D0,D1"),
            ([0xC189], "EXG D0,A1"),
            ([0x0800, 0x0003], "BTST #$3,D0"),
            ([0xE140], "ASL.W #$8,D0"),
            ([0xE1D0], "ASL.W (A0)"),
            ([0x4E60], "MOVE.L A0,USP"),
            ([0x0108, 0x0010], "MOVEP.W $10(A0),D0"),
            ([0xB308], "CMPM.B (A0)+,(A1)+"),
            ([0x3250], "MOVEA.W (A0),A1"),
            ([0xD388], "ADDX.L -(A0),-(A1)"),
            ([0x4E72, 0x2700], "STOP #$2700"),
            ([0x4E4F], "TRAP #15"),
            ([0x4E56, 0xFFF0], "LINK A6,#-$10"),
            ([0x4AFC], "ILLEGAL"),
            ([0x2038, 0x8000], "MOVE.L ($FFFF8000).W,D0"),
            ([0x40C0], "MOVE.W SR,D0"),
            ([0x46FC, 0x2700], "MOVE.W #$2700,SR"),
            ([0x4840], "SWAP D0"),
            ([0x48C1], "EXT.L D1"),
            ([0x57C1], "SEQ D1"),
        ]
        for words, text in cases:
            ins, got = dis(words)
            self.assertTrue(ins.valid, text)
            self.assertEqual(got, text)
            self.assertEqual(ins.size, 2 * len(words), text)

    def test_branches(self):
        ins, txt = dis([0x6000, 0x0010], pc=0x1000)
        self.assertEqual((txt, ins.flow, ins.target), ("BRA.W $1012", "jump", 0x1012))
        ins, txt = dis([0x6106], pc=0x1000)
        self.assertEqual((ins.mnemonic, ins.flow, ins.target), ("BSR.S", "call", 0x1008))
        ins, txt = dis([0x51C8, 0xFFFE], pc=0x1000)
        self.assertEqual((ins.mnemonic, ins.flow, ins.target), ("DBF", "branch", 0x1000))
        ins, _ = dis([0x4EBA, 0x0010], pc=0x1000)
        self.assertEqual((ins.mnemonic, ins.flow, ins.target), ("JSR", "call", 0x1012))
        ins, _ = dis([0x4ED0])
        self.assertEqual(ins.flow, "jump_ind")

    def test_rejects_non_68000_or_non_canonical(self):
        for words in ([0xF000], [0x4E7A, 0x0801],     # line F, MOVEC (68010)
                      [0x7100],                      # MOVEQ with bit 8 set
                      [0x1030, 0x0200],              # index scale x2 (68020)
                      [0x1030, 0x0100],              # full-format extension (68020)
                      [0x0000, 0x0100],              # ORI.B with non-zero high byte
                      [0x48E7, 0x0000],              # MOVEM with empty list
                      [0x0810, 0x0008],              # BTST #8,(A0): bit number > 7
                      [0x60FF, 0x0000, 0x0000],      # BRA.L (68020)
                      [0x1048],                      # MOVE.B A0,D0
                      [0x42C0],                      # MOVE CCR,D0 (68010)
                      [0x4E74, 0x0000],              # RTD (68010)
                      [0x4AFB], [0x4A3A, 0x0000]):   # TST PC-relative (68020)
            ins, _ = dis(words)
            self.assertFalse(ins.valid, [hex(w) for w in words])
            self.assertEqual(ins.size, 2)

    def test_traps(self):
        ins, _ = dis([0xA9F4])
        self.assertEqual((ins.mnemonic, ins.flow), ("_ExitToShell", "stop"))
        self.assertEqual(macsyms.trap_info(0xA11E)["ident"], "_NewPtr")
        self.assertEqual(macsyms.trap_info(0xA51E)["display"], "_NewPtr ,SYS")
        self.assertEqual(macsyms.trap_info(0xA31E)["ident"], "_NewPtr_CLEAR")
        self.assertEqual(macsyms.trap_info(0xA402)["display"], "_Read ,ASYNC")
        self.assertEqual(macsyms.trap_info(0xA205)["ident"], "_Status_IMMED")
        self.assertEqual(macsyms.trap_info(0xAA00)["os"], False)
        self.assertEqual(macsyms.trap_info(0xA9A0)["name"], "GetResource")
        self.assertEqual(macsyms.trap_info(0xADA0)["display"], "_GetResource ,AUTOPOP")
        self.assertEqual(macsyms.trap_info(0xA850)["manager"], "QuickDraw cursor")
        self.assertIsNone(macsyms.trap_info(0x4E75))

    def test_trap_idents_unique(self):
        seen = {}
        for w in range(0xA000, 0xB000):
            ident = macsyms.trap_info(w)["ident"]
            self.assertNotIn(ident, seen, f"{w:04X} and {seen.get(ident, 0):04X}")
            seen[ident] = w


class TestMacSyms(unittest.TestCase):
    def test_checksum(self):
        data = bytearray(64)
        data[4:8] = b"\x00\x40\x00\x2A"
        data[10] = 1
        self.assertEqual(macsyms.mac_rom_checksum(bytes(data)), 0x0040 + 0x002A + 0x0100)

    def test_hardware_spacing(self):
        self.assertEqual(macsyms.HARDWARE[0xEFE1FE][0], "vBufB")
        self.assertEqual(macsyms.HARDWARE[0xEFE1FE + 0x1C00][0], "vIER")
        self.assertEqual(macsyms.HARDWARE[0xDFE1FF + 0x1E00][0], "iwm_q7H")
        self.assertEqual(macsyms.HARDWARE[0x9FFFF8 + 2][0], "sccR_aCtl")
        self.assertEqual(macsyms.via_reg_by_offset(0x1E00)[0], "vBufA")

    def test_reference_tables_in_sync(self):
        """reference/*.md tables are generated from macsyms.py."""
        for gen_fn, fn in ((macsyms.markdown_traps, "mac_traps.md"), (macsyms.markdown_lowmem, "mac_lowmem.md"),
                           (macsyms.markdown_hardware, "mac_hardware.md"),
                           (atarisyms.markdown_calls, "atari_tos_calls.md"),
                           (atarisyms.markdown_sysvars, "atari_sysvars.md"),
                           (atarisyms.markdown_hardware, "atari_hardware.md")):
            gen = gen_fn()
            with open(os.path.join(ROOT, "reference", fn)) as f:
                self.assertIn(gen.strip(), f.read(), f"regenerate reference/{fn}")


# ======================================================================
class TestLoader(unittest.TestCase):
    def test_fakerom_identity(self):
        info = identify_file(FAKEROM)
        self.assertEqual(info["format"], "mac-rom")
        self.assertTrue(info["rom"]["checksum_ok"])
        self.assertEqual(info["rom"]["version"], 0x0069)
        self.assertEqual(info["entry"], 0x40002A)
        names = dict((n, a) for a, n in info["entries"])
        self.assertEqual(names["HDR_0A"], 0x400084)
        self.assertIn("DRVR_Test_Open", names)
        self.assertEqual([d["name"] for d in info["drivers"]], [".Test"])
        types = sorted((r["type"], r["id"]) for r in info["resources"])
        self.assertEqual(types, [("PACK", 4), ("STR ", -16384)])

    def test_bad_checksum_is_not_a_rom(self):
        with open(FAKEROM, "rb") as f:
            data = bytearray(f.read())
        data[0x2000] ^= 0xFF
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as t:
            t.write(data)
        try:
            self.assertEqual(identify_file(t.name)["format"], "raw")
            self.assertEqual(identify_file(t.name, rom=True)["format"], "mac-rom")
        finally:
            os.unlink(t.name)

    def test_resource_fork(self):
        info = identify_file(DEMO_RSRC)
        self.assertTrue(info["format"].startswith("resource fork CODE 1"))
        self.assertEqual(info["entry"], 0x10004)
        self.assertEqual(len(info["jump_table"]), 2)
        info = identify_file(DEMO_RSRC, rsrc="STR :128")
        self.assertEqual(info["segments"][0]["length"], 6)

    def test_macbinary(self):
        with open(DEMO_RSRC, "rb") as f:
            rsrc = f.read()
        hdr = bytearray(128)
        hdr[1] = 4
        hdr[2:6] = b"Demo"
        hdr[65:73] = b"APPLDEMO"
        struct.pack_into(">II", hdr, 83, 0, len(rsrc))
        blob = bytes(hdr) + rsrc + bytes((-len(rsrc)) % 128)
        mb = parse_macbinary(blob)
        self.assertEqual((mb["name"], mb["type"], mb["rsrc"]), ("Demo", "APPL", rsrc))
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as t:
            t.write(blob)
        try:
            self.assertTrue(identify_file(t.name)["format"].startswith("MacBinary"))
        finally:
            os.unlink(t.name)

    def test_srecord_and_ihex(self):
        def srec(t, addr, data, alen):
            body = bytes([alen + len(data) + 1]) + addr.to_bytes(alen, "big") + data
            return f"S{t}" + body.hex().upper() + f"{(~sum(body)) & 0xFF:02X}"
        text = "\n".join([srec(2, 0x020000, bytes.fromhex("4E714E75"), 3), srec(8, 0x020000, b"", 3)])
        segs, entry = parse_srecord(text)
        self.assertEqual((segs, entry), ({0x20000: bytes.fromhex("4E714E75")}, 0x20000))
        rec = bytes([4, 0x10, 0x00, 0]) + bytes.fromhex("4E714E75")
        line = ":" + rec.hex().upper() + f"{(-sum(rec)) & 0xFF:02X}"
        segs, _ = parse_ihex(line + "\n:00000001FF")
        self.assertEqual(segs, {0x1000: bytes.fromhex("4E714E75")})

    def test_vector_table_image(self):
        img = bytearray(0x200)
        struct.pack_into(">II", img, 0, 0x8000, 0x100)
        struct.pack_into(">I", img, 0x64, 0x110)
        img[0x100:0x104] = bytes.fromhex("4E714E75")
        img[0x110:0x112] = bytes.fromhex("4E73")
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as t:
            t.write(img)
        try:
            info = identify_file(t.name, org=0)
            self.assertEqual(info["entry"], 0x100)
            names = {n: a for a, n in info["entries"]}
            self.assertEqual(names["AutoInt1_handler"], 0x110)
        finally:
            os.unlink(t.name)


# ======================================================================
class TestAnalysis(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.d, cls.info = build_disassembler(args_for(FAKEROM))
        cls.listing = cls.d.disassemble(show_hex=True, annotate=True)

    def test_tables_and_installs(self):
        notes = "\n".join(self.d.auto_found)
        self.assertIn("word offset table at $4000C0: 3 entries", notes)
        self.assertIn("branch table at $4000D6: 3 entries", notes)
        self.assertIn("pointer table at $4000FE: 5 longs", notes)
        self.assertIn("512 ROM-relative words, 512 hit", notes)
        self.assertEqual({self.d.labels[h] for _pc, _v, h in self.d.vector_installs},
                         {"Line1010_Handler", "AutoInt1_Handler"})

    def test_names(self):
        labels = set(self.d.labels.values())
        for n in ("ResetEntry", "InitStuff", "TRAP_Open", "TRAP_InitCursor", "TRAP_Debugger",
                  "DRVR_Test_Close", "R_PACK_4", "HdrJmp_0A"):
            self.assertIn(n, labels)

    def test_listing(self):
        self.assertIn("MOVE.L  (Ticks).W,D0", self.listing)
        self.assertIn("MOVEA.L (VIA).W,A1", self.listing)
        self.assertIn("MOVE.B  (vBufB).L,D0", self.listing)
        self.assertIn("_ExitToShell", self.listing)
        self.assertIn("DC.B    'not code after ExitToShell'", self.listing)
        self.assertIn("DC.B    $0B,'Hello World'", self.listing)
        self.assertIn("; MacsBug symbol: InitStuff", self.listing)
        self.assertIn("DC.W    TRAP_Open-$400000", self.listing)
        for line in self.listing.splitlines():
            p = annotator.parse_line(line)
            if p and p[0] & 1:
                self.assertTrue(p[1].startswith("DC"), line)   # nothing but data at odd addresses

    def test_line_contract(self):
        n = 0
        for line in self.listing.splitlines():
            if line.startswith("  4") and len(line) > 36:
                self.assertIsNotNone(annotator.parse_line(line), line)
                n += 1
        self.assertGreater(n, 1000)

    def test_symbols_override(self):
        with tempfile.NamedTemporaryFile("w", suffix=".s", delete=False) as t:
            t.write("MyCase EQU $4000C6 ; first case\nTicksAlias EQU $016A\n")
        try:
            d, _ = build_disassembler(args_for(FAKEROM, symbols=[t.name]))
            out = d.disassemble()
            self.assertIn("MyCase:", out)
            self.assertIn("DC.W    MyCase-L_4000C0", out)
            self.assertIn("(TicksAlias).W", out)
            self.assertIn("TicksAlias       EQU     $016A", out)
        finally:
            os.unlink(t.name)

    def test_resource_a5_calls(self):
        d, _ = build_disassembler(args_for(DEMO_RSRC))
        out = d.disassemble(annotate=True)
        self.assertIn("Helper:", out)
        self.assertIn("jump table entry 1: CODE 1", out)
        x = CrossReferenceBuilder(d)
        x.analyze()
        self.assertIn("└── Helper ($010016)", x.format_callgraph())


class TestXrefAndMap(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.d, cls.info = build_disassembler(args_for(FAKEROM))
        cls.x = CrossReferenceBuilder(cls.d)
        cls.x.analyze()

    def test_report(self):
        r = self.x.format_report()
        self.assertIn("_InitGraf", r)
        self.assertIn("Ticks", r)
        self.assertIn("Line1010 ($0028) <- Line1010_Handler", r)
        self.assertIn("vBufB", r)

    def test_sections_cover_listing(self):
        secs = json.loads(self.x.format_sections(max_chunks=4))
        self.assertGreaterEqual(len(secs), 2)
        self.assertEqual(int(secs[0]["start_addr_hex"], 16), 0x400000)
        self.assertEqual(int(secs[-1]["end_addr_hex"], 16), 0x40FFFF)
        for a, b in zip(secs, secs[1:]):
            self.assertEqual(int(a["end_addr_hex"], 16) + 1, int(b["start_addr_hex"], 16))

    def test_map(self):
        m = build_map(self.d, self.info, self.x)
        md = to_markdown(m)
        self.assertIn("| Computed checksum |", md)
        self.assertIn("## Device Drivers in ROM", md)
        self.assertIn(".Test", md)
        reset = next(s for s in m["subroutines"] if s["name"] == "ResetEntry")
        self.assertIn("VIA", reset["tags"])
        self.assertEqual(m["lowmem"]["$0028"]["writers"], ["ResetEntry"])


class TestAnnotatorPipeline(unittest.TestCase):
    def test_split_annotate_merge(self):
        with tempfile.TemporaryDirectory() as tmp:
            d, _ = build_disassembler(args_for(FAKEROM))
            asm = os.path.join(tmp, "f.asm")
            with open(asm, "w") as f:
                f.write(d.disassemble(show_hex=True, annotate=True))
            d2, _ = build_disassembler(args_for(FAKEROM))
            x = CrossReferenceBuilder(d2)
            x.analyze()
            sec = os.path.join(tmp, "s.json")
            with open(sec, "w") as f:
                f.write(x.format_sections(max_chunks=4))
            cdir = os.path.join(tmp, "chunks")
            err = io.StringIO()
            sys_err, sys.stderr = sys.stderr, err
            try:
                annotator.do_split(Namespace(asm=asm, sections=sec, output_dir=cdir))
                man = os.path.join(cdir, "manifest.json")
                annotator.do_annotate(Namespace(manifest=man, ref_dir=os.path.join(ROOT, "reference")))
                annotator.do_annotate(Namespace(manifest=man, ref_dir=os.path.join(ROOT, "reference")))
                out = os.path.join(tmp, "m.s")
                annotator.do_merge(Namespace(manifest=man, output=out, reassemble=True))
            finally:
                sys.stderr = sys_err
            text = slurp(out)
            self.assertIn("VIA vIER: interrupt enable register - disable mask $7F", text)
            self.assertIn("clear bit 4 vOverlay", text)
            self.assertIn("SR = $2700: supervisor, interrupt mask 7", text)
            self.assertIn("stack frame: 8 bytes of locals", text)
            self.assertEqual(text.count("disable mask $7F"), 1)        # idempotent
            # every original instruction survives unchanged
            orig = [l.split(";")[0].rstrip()[36:] for l in slurp(asm).splitlines() if annotator.parse_line(l)]
            merged = [l.split(";")[0].strip() for l in text.splitlines()]
            merged_set = set(merged)
            for o in orig:
                self.assertIn(o.strip(), merged_set)

    def test_apply_symbols(self):
        with tempfile.TemporaryDirectory() as tmp:
            chunk = os.path.join(tmp, "chunk_00_400000.asm")
            with open(chunk, "w") as f:
                f.write("; --- BEGIN CODE ---\nSUB_4000B6:\n  4000B6  D040    ADD.W D0,D0\n"
                        "  400062  6100 0052   BSR.W   SUB_4000B6   ; keep me\n")
            man = os.path.join(tmp, "manifest.json")
            with open(man, "w") as f:
                json.dump({"chunks": [{"id": 0, "filename": os.path.basename(chunk), "path": chunk,
                                       "start_addr": "0x400000", "end_addr": "0x4000FF"}]}, f)
            sym = os.path.join(tmp, "s.json")
            with open(sym, "w") as f:
                json.dump({"0x4000B6": "Dispatch"}, f)
            err, sys.stderr = sys.stderr, io.StringIO()
            try:
                annotator.do_apply_symbols(Namespace(manifest=man, apply_symbols=[sym]))
            finally:
                sys.stderr = err
            text = slurp(chunk)
            self.assertIn("Dispatch:", text)
            self.assertIn("BSR.W   Dispatch   ; keep me", text)


class TestSymbols(unittest.TestCase):
    def test_formats(self):
        with tempfile.TemporaryDirectory() as tmp:
            a = os.path.join(tmp, "a.json")
            with open(a, "w") as f:
                json.dump({"schema_version": "1.0", "categories": {"x": {
                    "0x40A000": {"name": "InitMem", "size": 4, "comment": "c"}}}}, f)
            b = os.path.join(tmp, "b.s")
            with open(b, "w") as f:
                f.write("* comment\nFoo EQU $400100 ; foo\nBar = $400200\n$400300 Baz the baz\nD0 EQU $1\n")
            err, sys.stderr = sys.stderr, io.StringIO()
            try:
                t = load_symbols([a, b])
            finally:
                sys.stderr = err
            self.assertEqual(t.name(0x40A000), "InitMem")
            self.assertEqual(t.name(0x40A002), "InitMem+2")
            self.assertEqual(t.name(0x400100), "Foo")
            self.assertEqual(t.comment(0x400300), "the baz")
            self.assertNotIn(1, t)                  # register names rejected


# ======================================================================
class TestAtari(unittest.TestCase):
    def test_tos_identity(self):
        info = identify_file(FAKETOS)
        self.assertEqual(info["format"], "atari-tos-rom")
        t = info["tos"]
        self.assertEqual((t["version"], t["date"], t["country"], t["pal"], t["os_beg"]),
                         (0x0104, "1989-04-06", "UK", True, 0xFC0000))
        self.assertEqual(info["entry"], 0xFC0034)

    def test_tos_listing(self):
        d, _ = build_disassembler(args_for(FAKETOS))
        out = d.disassemble(annotate=True)
        self.assertIn("; Platform: atari", out)
        self.assertIn("color0           EQU     $FFFF8240", out)
        self.assertIn("MOVE.B  #$02,(shiftmd).W", out)
        self.assertIn("MOVE.L  #MFP_TimerC_Handler,(MFP_TimerC).W", out)
        self.assertIn("CMP.L   (resvalid).W,D0", out)
        self.assertIn("BCLR    #$5,(isrb).W", out)
        self.assertIn("line-F word", out)
        self.assertIn("MOVE.W  #$2300,SR", out)          # tracing continued past line-F
        self.assertIn("_LineA", "".join(atarisyms.linea_info(0xA000)["ident"]))

    def test_prg_loader(self):
        info = identify_file(HELLO_PRG)
        self.assertEqual(info["format"], "atari-gemdos-executable")
        p = info["prg"]
        self.assertEqual((p["text_len"], p["data_len"], p["bss_len"], len(p["relocs"])), (154, 48, 260, 9))
        info = identify_file(HELLO_SYM)
        names = {n for _a, n, _s in info["prg_symbols"]}
        self.assertTrue({"start", "super_init", "hello", "counter", "bufend"} <= names)

    def test_prg_listing(self):
        d, _ = build_disassembler(args_for(HELLO_PRG))
        out = d.disassemble(annotate=True)
        self.assertIn("TRAP    #1                        ; GEMDOS Cconws (function $09)", out)
        self.assertIn("PEA     Supexec_Func(PC)", out)
        self.assertIn("MOVE.L  #VBL_Handler,(VBLVec).W", out)
        self.assertIn("MOVE.L  #B_0100CA,D0", out)              # relocated immediate -> BSS label
        self.assertIn("DC.L    L_01008E", out)                  # relocated data pointer
        self.assertIn("DC.W    $0001,$0000", out)               # unrelocated long stays a number
        self.assertIn("DC.B    'never reached'", out)           # nothing traced after Pterm0
        self.assertIn("\n                 BSS\n", out)
        d, _ = build_disassembler(args_for(HELLO_SYM))
        out = d.disassemble()
        for n in ("super_init:", "dispatch:", "counter:", "MOVE.L  #counter,D0"):
            self.assertIn(n, out)
        x = CrossReferenceBuilder(d)
        x.analyze()
        self.assertEqual(sorted(x.sys_calls), ["GEMDOS Cconws", "GEMDOS Crawcin", "GEMDOS Pterm0",
                                               "XBIOS Supexec"])

    def test_cartridge_and_boot_sector(self):
        cart = bytearray(0x200)
        struct.pack_into(">IIII", cart, 0, 0xABCDEF42, 0, 0x08FA0040, 0x00FA0040)
        cart[24:24 + 8] = b"DEMO.PRG"
        cart[0x40:0x44] = bytes.fromhex("70014E75")
        boot = bytearray(512)
        boot[0:2] = bytes.fromhex("6038")
        boot[0x3A:0x40] = bytes.fromhex("4E714E714E75")
        struct.pack_into(">H", boot, 510, (0x1234 - sum(struct.unpack(">255H", boot[:510]))) & 0xFFFF)
        with tempfile.TemporaryDirectory() as tmp:
            c, b = os.path.join(tmp, "c.stc"), os.path.join(tmp, "boot.bin")
            with open(c, "wb") as f:
                f.write(cart)
            with open(b, "wb") as f:
                f.write(boot)
            info = identify_file(c)
            self.assertEqual(info["format"], "atari-cartridge")
            self.assertIn((0xFA0040, "CA_DEMO_PRG_Run"), info["entries"])
            info = identify_file(b)
            self.assertEqual(info["format"], "atari-boot-sector")
            d, _ = build_disassembler(args_for(b))
            self.assertIn("NOP", d.disassemble())

    def test_atari_annotator(self):
        with tempfile.TemporaryDirectory() as tmp:
            d, _ = build_disassembler(args_for(FAKETOS))
            asm = os.path.join(tmp, "t.asm")
            with open(asm, "w") as f:
                f.write(d.disassemble(annotate=True))
            man = os.path.join(tmp, "manifest.json")
            with open(man, "w") as f:
                json.dump({"chunks": [{"id": 0, "filename": "t.asm", "path": asm,
                                       "start_addr": "0xFC0000", "end_addr": "0xFC1FFF"}]}, f)
            err, sys.stderr = sys.stderr, io.StringIO()
            try:
                annotator.do_annotate(Namespace(manifest=man, ref_dir=os.path.join(ROOT, "reference")))
            finally:
                sys.stderr = err
            text = slurp(asm)
        self.assertIn("vr: MFP vector register", text)
        self.assertIn("ierb: MFP interrupt enable B", text)
        self.assertIn("YM2149 select register 7: mixer", text)
        self.assertIn("resolution = high (640x400 mono)", text)

    def test_map(self):
        d, info = build_disassembler(args_for(FAKETOS))
        x = CrossReferenceBuilder(d)
        x.analyze()
        md = to_markdown(build_map(d, info, x))
        self.assertIn("| TOS version word ($02) | $0104 |", md)
        self.assertIn("Machine Address Map (Atari ST / STE)", md)
        self.assertIn("| MFP |", md)


# ======================================================================
@unittest.skipUnless(VASM, "vasmm68k_mot not installed")
class TestRoundTrip(unittest.TestCase):
    def roundtrip(self, path, **kw):
        d, _ = build_disassembler(args_for(path, **kw))
        src = d.disassemble(show_hex=False)
        with tempfile.TemporaryDirectory() as tmp:
            s, b = os.path.join(tmp, "x.s"), os.path.join(tmp, "x.bin")
            with open(s, "w") as f:
                f.write(src)
            assemble(s, b)
            with open(b, "rb") as f:
                out = f.read()
        with open(path, "rb") as f:
            data = f.read()
        self.assertEqual(out, data, f"{path} {kw}")
        return src

    def test_allmodes(self):
        src = self.roundtrip(ALLMODES, org=0x10000, entry=[0x10000])
        code = src.split("ORG")[1]
        body = code[:code.index("RTS")]
        self.assertNotIn("DC.W", body.replace("DC.W    $A", ""))     # every form decoded

    def test_fakerom(self):
        self.roundtrip(FAKEROM)
        self.roundtrip(FAKEROM, fill="all")

    def test_resource_segment(self):
        d, _ = build_disassembler(args_for(DEMO_RSRC))
        src = d.disassemble(show_hex=False)
        with tempfile.TemporaryDirectory() as tmp:
            s, b = os.path.join(tmp, "x.s"), os.path.join(tmp, "x.bin")
            with open(s, "w") as f:
                f.write(src)
            assemble(s, b)
            seg = slurp(b, "rb")
        self.assertEqual(seg[:4], bytes.fromhex("00000002"))
        self.assertEqual(seg, d.mem.segs[0][1])

    def test_random_bytes(self):
        """Any byte sequence must reassemble byte-exact, in every mode."""
        modes = [dict(raw=True, org=0x10000, fill="all", mac=True),
                 dict(raw=True, org=0x400000),
                 dict(raw=True, org=0, fill="all", mac=True),
                 dict(raw=True, org=0x10000, fill="all", atari=True),
                 dict(raw=True, org=0xFC0000, atari=True)]
        for seed in range(10):
            r = random.Random(seed)
            data = bytes(r.randrange(256) for _ in range(6000 + seed))
            with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as t:
                t.write(data)
            try:
                self.roundtrip(t.name, **modes[seed % len(modes)])
            finally:
                os.unlink(t.name)

    def test_atari_tos_rom(self):
        self.roundtrip(FAKETOS)

    def test_gemdos_executable(self):
        for path in (HELLO_PRG, HELLO_SYM):
            d, _ = build_disassembler(args_for(path))
            src = d.disassemble(show_hex=False)
            with tempfile.TemporaryDirectory() as tmp:
                s_, b = os.path.join(tmp, "x.s"), os.path.join(tmp, "x.prg")
                with open(s_, "w") as f:
                    f.write(src)
                subprocess.run([VASM, "-quiet", "-Ftos", "-nosym", "-no-opt", "-m68000", "-o", b, s_],
                               check=True, capture_output=True)
                out = slurp(b, "rb")
            # the symbol-table build compares against the stripped original
            self.assertEqual(out, slurp(HELLO_PRG, "rb"), path)

    def test_packed_trap_table_and_patches(self):
        """64K-ROM style packed trap table init + _SetTrapAddress patches."""
        src = """
        MC68000
        ORG     $400000
        DC.L    0,Reset
        DC.W    $0069
Reset:  LEA     ($0400).W,A1
        LEA     Unimpl(PC),A0
        SUBA.L  ($02AE).W,A0
        MOVE.L  A0,D0
        LSR.W   #1,D0
        MOVEA.L A1,A0
        MOVE.W  #$01FF,D1
.fill:  MOVE.W  D0,(A0)+
        DBF     D1,.fill
        LEA     Packed(PC),A0
        MOVEQ   #0,D2
.next:  MOVE.B  (A0)+,D0
        BMI.S   .delta
        ASL.W   #8,D0
        MOVE.B  (A0)+,D0
.store: MOVE.W  D0,D2
        BEQ.S   .done
        MOVE.W  D0,(A1)
.skip:  ADDQ.W  #2,A1
        BRA.S   .next
.delta: ANDI.W  #$007F,D0
        BEQ.S   .skip
        ADD.W   D2,D0
        BRA.S   .store
.done:  LEA     MyRead(PC),A0
        MOVE.W  #$0002,D0
        DC.W    $A047                   ; _SetTrapAddress
        RTS
Unimpl: MOVEQ   #12,D0
        RTS
ImplOpen:
        MOVEQ   #0,D0
        RTS
ImplClose:
        MOVEQ   #1,D0
        RTS
MyRead: MOVEQ   #2,D0
        RTS
Packed: DC.B    (ImplOpen-$400000)>>9,((ImplOpen-$400000)>>1)&$FF
        DC.B    $82                     ; Close = Open + 2 words
"""
        src += "        DC.B    " + ",".join(["$80"] * 62) + "\n"
        src += "        DC.B    0,0\n        EVEN\n        DCB.B   $400400-*,$FF\n"
        with tempfile.TemporaryDirectory() as tmp:
            s_, b = os.path.join(tmp, "x.s"), os.path.join(tmp, "x.bin")
            with open(s_, "w") as f:
                f.write(src)
            subprocess.run([VASM, "-quiet", "-Fbin", "-no-opt", "-m68000", "-o", b, s_], check=True,
                           capture_output=True)
            d, _ = build_disassembler(args_for(b, rom=True))
            out = d.disassemble()
        self.assertIn("packed trap table", out)
        self.assertIn("TRAP_Open:", out)
        self.assertIn("TRAP_Close:", out)
        self.assertIn("TRAP_Unimplemented:", out)
        self.assertIn("PATCH_Read:", out)
        self.assertIn("; Trap patch at", out)

    def test_annotated_pipeline_reassembles(self):
        here = os.getcwd()
        with tempfile.TemporaryDirectory() as tmp:
            os.chdir(ROOT)
            try:
                asm = os.path.join(tmp, "f.asm")
                sec = os.path.join(tmp, "s.json")
                cdir = os.path.join(tmp, "chunks")
                py = sys.executable
                subprocess.run([py, "tools/dasm68k.py", FAKEROM, "--annotate", "-o", asm],
                               check=True, capture_output=True)
                subprocess.run([py, "tools/xref.py", FAKEROM, "--sections", "--max-chunks", "5", "-o", sec],
                               check=True, capture_output=True)
                subprocess.run([py, "tools/annotator.py", "--split", "--asm", asm, "--sections", sec,
                                "--output-dir", cdir], check=True, capture_output=True)
                man = os.path.join(cdir, "manifest.json")
                subprocess.run([py, "tools/annotator.py", "--annotate", "--manifest", man, "--ref-dir",
                                "reference"], check=True, capture_output=True)
                out = os.path.join(tmp, "m.s")
                subprocess.run([py, "tools/annotator.py", "--merge", "--manifest", man, "--reassemble",
                                "-o", out], check=True, capture_output=True)
                b = os.path.join(tmp, "m.bin")
                assemble(out, b)
                self.assertEqual(slurp(b, "rb"), slurp(FAKEROM, "rb"))
            finally:
                os.chdir(here)


if __name__ == "__main__":
    unittest.main()
