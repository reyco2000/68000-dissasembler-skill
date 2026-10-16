#!/usr/bin/env python3
"""
macloader.py — input detection and loading for the 68000 tools
Usage: python3 macloader.py <file> [--org 0x400000] [--raw] [--rsrc CODE:1] [--json]

Recognized inputs:
  Macintosh ROM image  64K (Mac 128K/512K), 128K (Mac Plus/512Ke), 256K, 512K.
                       Identified by the ROM checksum (first long = sum of
                       big-endian words from offset 4), the known-checksum
                       table and the version word at offset 8. Loaded at
                       $400000; the reset PC (long at offset 4) is the entry.
  Resource fork        (.rsrc, MacBinary, AppleSingle/AppleDouble): one
                       resource is loaded with --rsrc TYPE:ID (default: the
                       lowest CODE >= 1, else the first code-bearing type).
                       CODE 0 (jump table) gives entry points for segments.
  Motorola S-records   S1/S2/S3 data records, S7/S8/S9 start address.
  Intel HEX            types 00/01/02/04/05.
  Raw binary           --org (default 0). An image at 0 whose first longs
                       look like a 68000 vector table (SSP, PC in image)
                       gets its reset PC and exception vectors traced.

load_image() returns (segments, info): segments = [(org, bytes)], info =
dict(format, entry, entries[(addr, name)], data_regions[(start, end, why)],
is_rom, rom_name, mac, notes, tables, resources, drivers, jump_table, ...).
"""

import argparse
import json
import os
import struct
import sys

try:
    from tools import macsyms, atarisyms
    from tools.m68k import decode
except ImportError:
    import macsyms
    import atarisyms
    from m68k import decode

ROM_BASE = 0x400000
ROM_SIZES = (0x10000, 0x20000, 0x40000, 0x80000)
CODE_TYPES = {"CODE", "DRVR", "PACK", "MDEF", "WDEF", "CDEF", "LDEF", "INIT", "cdev",
              "FKEY", "PTCH", "ROvr", "ADBS", "proc", "XCMD", "XFCN", "PDEF", "RDEV",
              "dcmd", "boot", "snth", "DSAT", "CACH", "ptch", "SERD", "itl2", "itl4", "lmgr"}


def be16(b: bytes, o: int) -> int:
    return (b[o] << 8) | b[o + 1]


def be32(b: bytes, o: int) -> int:
    return struct.unpack_from(">I", b, o)[0]


def printable_type(t: bytes) -> bool:
    return len(t) == 4 and all(0x20 <= c < 0x7F for c in t)


# ===========================================================================
# CONTAINERS
# ===========================================================================

def parse_macbinary(data: bytes):
    """MacBinary I/II/III -> dict(name, type, creator, data, rsrc) or None."""
    if len(data) < 128 or data[0] != 0 or data[74] != 0 or data[82] != 0:
        return None
    nlen = data[1]
    if not 1 <= nlen <= 63:
        return None
    dlen, rlen = be32(data, 83), be32(data, 87)
    if dlen > 0x7FFFFFFF or rlen > 0x7FFFFFFF:
        return None
    dstart = 128
    rstart = dstart + ((dlen + 127) // 128) * 128
    if rstart + rlen > len(data) + 127 or dlen + rlen == 0:
        return None
    if not printable_type(data[65:69]):
        return None
    return {"name": data[2:2 + nlen].decode("mac_roman", "replace"),
            "type": data[65:69].decode("mac_roman"), "creator": data[69:73].decode("mac_roman"),
            "data": data[dstart:dstart + dlen], "rsrc": data[rstart:rstart + rlen]}


def parse_applesingle(data: bytes):
    """AppleSingle ($00051600) / AppleDouble ($00051607) -> dict(data, rsrc)."""
    if len(data) < 26 or be32(data, 0) not in (0x00051600, 0x00051607):
        return None
    n = be16(data, 24)
    out = {"data": b"", "rsrc": b"", "double": be32(data, 0) == 0x00051607}
    for i in range(n):
        off = 26 + 12 * i
        if off + 12 > len(data):
            return None
        eid, eoff, elen = be32(data, off), be32(data, off + 4), be32(data, off + 8)
        if eid == 1:
            out["data"] = data[eoff:eoff + elen]
        elif eid == 2:
            out["rsrc"] = data[eoff:eoff + elen]
    return out


def parse_resource_fork(data: bytes):
    """Standard resource fork -> list of dict(type, id, name, attrs, offset, data)
    or None if the header/map don't validate."""
    if len(data) < 256:
        return None
    doff, moff, dlen, mlen = struct.unpack_from(">IIII", data, 0)
    if doff < 16 or moff < 16 or doff + dlen > len(data) or moff + mlen > len(data) or mlen < 30:
        return None
    return parse_resource_map(data, moff, doff)


def parse_resource_map(data: bytes, moff: int, doff: int):
    """Parse a resource map at moff whose data offsets are relative to doff."""
    try:
        tl = moff + be16(data, moff + 24)
        nl = moff + be16(data, moff + 26)
        ntypes = be16(data, tl) + 1
        if ntypes > 512 or ntypes == 0x10000:
            return None
        res = []
        for t in range(ntypes):
            e = tl + 2 + 8 * t
            rtype = data[e:e + 4]
            if not printable_type(rtype):
                return None
            count = be16(data, e + 4) + 1
            rl = tl + be16(data, e + 6)
            for r in range(count):
                re_ = rl + 12 * r
                rid = struct.unpack_from(">h", data, re_)[0]
                noff = be16(data, re_ + 2)
                attrs = data[re_ + 4]
                roff = (data[re_ + 5] << 16) | (data[re_ + 6] << 8) | data[re_ + 7]
                pos = doff + roff
                if pos + 4 > len(data):
                    return None
                ln = be32(data, pos)
                if pos + 4 + ln > len(data):
                    return None
                name = None
                if noff != 0xFFFF:
                    p = nl + noff
                    if p < len(data):
                        name = data[p + 1:p + 1 + data[p]].decode("mac_roman", "replace")
                res.append({"type": rtype.decode("mac_roman"), "id": rid, "name": name,
                            "attrs": attrs, "offset": pos + 4, "length": ln,
                            "data": data[pos + 4:pos + 4 + ln]})
        return res
    except (IndexError, struct.error):
        return None


def find_resource_maps(data: bytes, base_addr: int):
    """Scan an image (e.g. a ROM) for embedded standard resource maps.
    A map has its type list at offset 28 (be16(map+24) == 28); data offsets
    are tried relative to the implied file start and to the image start.
    Returns [dict(map_addr, data_base, resources)]."""
    found = []
    for p in range(0, len(data) - 32, 2):
        if be16(data, p + 24) != 28:
            continue
        nl = be16(data, p + 26)
        if nl <= 28 or p + nl > len(data):
            continue
        ntypes = be16(data, p + 28) + 1
        if not 1 <= ntypes <= 128:
            continue
        if not printable_type(data[p + 30:p + 34]):
            continue
        # header copy at the start of the map: data offset, map offset
        cands = []
        hdr_doff, hdr_moff = be32(data, p), be32(data, p + 4)
        if 0 < hdr_moff <= p:
            cands.append(p - hdr_moff + hdr_doff)
        cands += [0, hdr_doff]
        for db in cands:
            if not 0 <= db < len(data):
                continue
            res = parse_resource_map(data, p, db)
            if res:
                for r in res:
                    r["addr"] = base_addr + r["offset"]
                    del r["data"]
                found.append({"map_addr": base_addr + p, "data_base": base_addr + db, "resources": res})
                break
    return found


# ===========================================================================
# DRIVER HEADERS
# ===========================================================================

DRVR_ROUTINES = ["Open", "Prime", "Control", "Status", "Close"]


def find_drivers(data: bytes, base_addr: int):
    """Scan for device-driver headers: flags, delay, emask, menu, 5 routine
    offsets, then a Pascal name starting with '.' at +18 (e.g. .Sony,
    .Sound, .AIn). Each routine offset must decode to a valid instruction."""
    out = []
    rw = _reader(data, base_addr)
    for p in range(0, len(data) - 24, 2):
        nlen = data[p + 18]
        if not 2 <= nlen <= 31 or data[p + 19] != 0x2E:      # '.'
            continue
        name = data[p + 19:p + 19 + nlen]
        if len(name) < nlen or not all(0x21 <= c < 0x7F for c in name):
            continue
        offs = [be16(data, p + 8 + 2 * i) for i in range(5)]
        if not offs[0] or not offs[4] or any(o & 1 or o >= len(data) - p for o in offs if o):
            continue
        if any(o and o < 18 + 1 + nlen for o in offs):
            continue
        ok = True
        for o in offs:
            if o:
                ins = decode(base_addr + p + o, rw)
                if ins is None or not ins.valid:
                    ok = False
                    break
        if not ok:
            continue
        out.append({"addr": base_addr + p, "name": name.decode("ascii"), "flags": be16(data, p),
                    "routines": {DRVR_ROUTINES[i]: base_addr + p + o for i, o in enumerate(offs) if o}})
    return out


def _reader(data: bytes, base: int):
    n = len(data)

    def rw(a):
        o = a - base
        if 0 <= o and o + 1 < n and not o & 1:
            return (data[o] << 8) | data[o + 1]
        return None
    return rw


# ===========================================================================
# TEXT FORMATS
# ===========================================================================

def parse_srecord(text: str):
    segs, entry = {}, None
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("S") or len(line) < 4:
            continue
        t = line[1]
        try:
            raw = bytes.fromhex(line[2:])
        except ValueError:
            return None
        if sum(raw) & 0xFF != 0xFF:
            return None
        alen = {"1": 2, "2": 3, "3": 4, "7": 4, "8": 3, "9": 2}.get(t)
        if alen is None:
            continue
        addr = int.from_bytes(raw[1:1 + alen], "big")
        if t in "123":
            segs[addr] = raw[1 + alen:-1]
        else:
            entry = addr
    return (segs, entry) if segs else None


def parse_ihex(text: str):
    segs, entry, upper = {}, None, 0
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith(":"):
            continue
        raw = bytes.fromhex(line[1:])
        if sum(raw) & 0xFF:
            return None
        n, addr, t = raw[0], be16(raw, 1), raw[3]
        payload = raw[4:4 + n]
        if t == 0:
            segs[upper + addr] = payload
        elif t == 2:
            upper = be16(payload, 0) << 4
        elif t == 4:
            upper = be16(payload, 0) << 16
        elif t in (3, 5):
            entry = int.from_bytes(payload, "big")
    return (segs, entry) if segs else None


def coalesce(segs: dict):
    out = []
    for a in sorted(segs):
        d = segs[a]
        if out and out[-1][0] + len(out[-1][1]) == a:
            out[-1] = (out[-1][0], out[-1][1] + d)
        else:
            out.append((a, bytes(d)))
    return out


# ===========================================================================
# MAC ROM
# ===========================================================================

def identify_mac_rom(data: bytes) -> dict | None:
    if len(data) not in ROM_SIZES:
        return None
    stored = be32(data, 0)
    computed = macsyms.mac_rom_checksum(data)
    version = be16(data, 8)
    known = macsyms.KNOWN_ROMS.get(stored)
    pc = be32(data, 4) & 0xFFFFFF
    pc_ok = ROM_BASE <= pc < ROM_BASE + len(data) or pc < len(data)
    if not (stored == computed or known) or not pc_ok:
        return None
    if pc < len(data):
        pc += ROM_BASE
    if known:
        name = known[0]
    else:
        name = f"unknown {len(data) // 1024}K Mac ROM (version ${version:04X}: " \
               f"{macsyms.ROM_VERSIONS.get(version & 0xFF, 'unrecognized')})"
    return {"rom_name": name, "checksum": stored, "checksum_computed": computed,
            "checksum_ok": stored == computed, "version": version, "reset_pc": pc,
            "known": bool(known)}


def rom_header_entries(data: bytes, base: int, code_start: int):
    """JMP/BRA instructions in the ROM header (between the version word and
    the reset code): boot / critical-error jump vectors."""
    out = []
    rw = _reader(data, base)
    off = 0x0A
    while off < min(code_start - base, 0x100):
        ins = decode(base + off, rw)
        if ins and ins.valid and ins.mnemonic in ("JMP", "BRA.W", "BRA.S") and ins.target is not None:
            out.append((base + off, ins.target, ins.mnemonic))
            off += ins.size
        else:
            off += 2
    return out


# ===========================================================================
# IDENTIFY / LOAD
# ===========================================================================

def _vector_table(data: bytes, org: int):
    """68000 vector table at address 0: SSP + reset PC + exception vectors.
    Plausible when the reset PC is even and inside the image."""
    if org != 0 or len(data) < 8:
        return None
    pc = be32(data, 4)
    if pc & 1 or not 8 <= pc < len(data):
        return None
    vecs = [(0x004, pc, "ResetPC")]
    for i in range(2, min(64, len(data) // 4)):
        v = be32(data, 4 * i)
        if v and not v & 1 and 0x100 <= v < len(data):
            vecs.append((4 * i, v, macsyms.EXCEPTION_VECTORS.get(4 * i, (f"Vector{i}",))[0]))
    return vecs


def identify_file(path: str, org: int | None = None, raw: bool = False,
                  rsrc: str | None = None, rom: bool = False) -> dict:
    with open(path, "rb") as f:
        data = f.read()
    info = {"file": path, "size": len(data), "format": "raw", "entry": None, "entries": [],
            "data_regions": [], "is_rom": False, "rom_name": None, "mac": False, "notes": [],
            "segments": [], "tables": [], "resources": [], "drivers": [], "jump_table": None,
            "cpu": "68000"}

    def done(segs):
        info["segments"] = [{"org": a, "length": len(d)} for a, d in segs]
        info["_segs"] = segs
        return info

    if not raw:
        # ---- Mac ROM ----
        rid = identify_mac_rom(data) if (org in (None, ROM_BASE) or rom) else None
        if rid or rom:
            base = ROM_BASE if org is None else org
            if not rid:
                rid = {"rom_name": "68000 ROM (forced with --rom)", "checksum": be32(data, 0),
                       "checksum_computed": macsyms.mac_rom_checksum(data), "checksum_ok": False,
                       "version": be16(data, 8), "reset_pc": be32(data, 4) & 0xFFFFFF, "known": False}
            info.update(format="mac-rom", is_rom=True, mac=True, rom=rid, rom_name=rid["rom_name"])
            entry = rid["reset_pc"]
            info["entry"] = entry if base <= entry < base + len(data) else None
            info["data_regions"].append((base, base + 9, "ROM header: checksum, reset PC, version"))
            info["notes"].append(f"ROM checksum ${rid['checksum']:08X} "
                                 f"({'valid' if rid['checksum_ok'] else 'computed $%08X' % rid['checksum_computed']})"
                                 f", version word ${rid['version']:04X}")
            if info["entry"] is not None:
                for at, tgt, mn in rom_header_entries(data, base, info["entry"]):
                    info["entries"].append((at, f"HdrJmp_{at - base:02X}"))
                    info["entries"].append((tgt, f"HDR_{at - base:02X}"))
                    info["notes"].append(f"Header {mn} at ${at:06X} -> ${tgt:06X}")
            drv = find_drivers(data, base)
            info["drivers"] = drv
            for dv in drv:
                info["data_regions"].append((dv["addr"], dv["addr"] + 18 + len(dv["name"]),
                                             f"driver header {dv['name']}"))
                for r, a in dv["routines"].items():
                    info["entries"].append((a, f"DRVR_{dv['name'][1:]}_{r}"))
                info["notes"].append(f"Driver {dv['name']} header at ${dv['addr']:06X}")
            maps = find_resource_maps(data, base)
            for m in maps:
                mo = m["map_addr"] - base
                mlen = be32(data, mo + 12) if mo + 16 <= len(data) else 0
                if 30 <= mlen <= len(data) - mo:
                    info["data_regions"].append((m["map_addr"], m["map_addr"] + mlen - 1, "resource map"))
                info["notes"].append(f"Resource map at ${m['map_addr']:06X} "
                                     f"({len(m['resources'])} resources, data base ${m['data_base']:06X})")
                info["resources"] += m["resources"]
                for r in m["resources"]:
                    info["data_regions"].append((r["addr"] - 4, r["addr"] - 1, f"resource length {r['type']}"))
                    if r["type"] not in CODE_TYPES:
                        info["data_regions"].append((r["addr"], r["addr"] + max(r["length"], 1) - 1,
                                                     f"resource {r['type']} {r['id']}"))
                    elif r["type"] != "DRVR":
                        info["entries"].append((r["addr"], _ident(f"R_{r['type']}_{r['id']}")))
            return done([(base, data)])

        # ---- Atari: TOS ROM, cartridge, GEMDOS executable, boot sector ----
        tos = identify_tos_rom(data, org)
        if tos:
            base = tos["os_beg"]
            info.update(format="atari-tos-rom", is_rom=True, platform="atari", tos=tos,
                        rom_name=tos["name"], entry=tos["reseth"])
            info["entries"] += [(tos["reseth"], "ResetEntry")]
            if tos["entry_bra"] != tos["reseth"]:
                info["entries"].append((tos["entry_bra"], "OS_Entry"))
            info["entries"].append((base, "OS_Header"))
            info["data_regions"].append((base + 2, base + tos["header_end"] - 1, "TOS header (OSHEADER)"))
            info["notes"] += tos["summary"]
            return done([(base, data)])
        cart = identify_cartridge(data) if org in (None, CART_BASE) else None
        if cart:
            info.update(format="atari-cartridge", is_rom=True, platform="atari", tos=cart,
                        rom_name=cart["name"])
            info["entries"] += cart["entries"]
            for a, b in cart["headers"]:
                info["data_regions"].append((CART_BASE + a, CART_BASE + b, "cartridge header"))
            for app in cart["apps"]:
                info["notes"].append(f"Cartridge application '{app['name']}': init ${app['init']:08X}, "
                                     f"run ${app['run']:08X}, size {app['size']}")
            if cart["entries"]:
                info["entry"] = cart["entries"][0][0]
            return done([(CART_BASE, data)])
        prg = parse_prg(data)
        if prg:
            return _load_prg(info, prg, org, done)
        if is_boot_sector(data[:512]) and (len(data) == 512 or (len(data) % 512 == 0 and len(data) >= 0x5A000)):
            base = org if org is not None else EXEC_BASE
            sector = data[:512]
            tgt = _bra_target(sector, 0)
            info.update(format="atari-boot-sector", platform="atari", entry=base)
            if tgt is not None and 2 < tgt < 512:
                info["data_regions"].append((base + 2, base + min(tgt, 0x1E) - 1,
                                             "boot sector BPB: OEM, serial, bytes/sector ..."))
            info["data_regions"].append((base + 0x1FE, base + 0x1FF, "boot sector checksum word"))
            info["notes"].append("Executable boot sector (word sum $1234)"
                                 + ("" if len(data) == 512 else ": first sector of a disk image"))
            return done([(base, sector)])

        # ---- S-records / Intel HEX ----
        if data[:1] in (b"S", b":"):
            try:
                text = data.decode("ascii")
            except UnicodeDecodeError:
                text = None
            if text:
                parsed = parse_srecord(text) if text[0] == "S" else parse_ihex(text)
                if parsed:
                    segs, entry = parsed
                    info["format"] = "srecord" if text[0] == "S" else "ihex"
                    segs = coalesce(segs)
                    if entry is not None and any(a <= entry < a + len(d) for a, d in segs):
                        info["entry"] = entry
                    _vectors_into(info, segs)
                    return done(segs)

        # ---- resource-bearing containers ----
        rdata, container = None, None
        mb = parse_macbinary(data)
        if mb:
            container = f"MacBinary '{mb['name']}' type {mb['type']} creator {mb['creator']}"
            rdata = mb["rsrc"] or None
            if not rdata:
                info["format"] = "macbinary-data"
                info["notes"].append(container + " (data fork only)")
                data = mb["data"]
        else:
            asg = parse_applesingle(data)
            if asg:
                container = "AppleDouble" if asg["double"] else "AppleSingle"
                rdata = asg["rsrc"] or None
                if not rdata:
                    info["format"] = container.lower() + "-data"
                    data = asg["data"]
            elif parse_resource_fork(data) is not None:
                container, rdata = "resource fork", data
        if rdata:
            res = parse_resource_fork(rdata)
            if res is None:
                info["notes"].append(f"{container}: resource fork does not validate")
            else:
                return _load_resource(info, res, rsrc, org, container, done)

    base = org if org is not None else 0
    segs = [(base, data)]
    if org is None:
        info["notes"].append("Raw binary: no --org given, loading at $000000")
    _vectors_into(info, segs)
    return done(segs)


def _ident(s: str) -> str:
    return "".join(c if c.isalnum() or c == "_" else "_" for c in s)


def _vectors_into(info, segs):
    for a, d in segs:
        vt = _vector_table(d, a)
        if vt:
            info["vector_table"] = True
            info["data_regions"].append((0, min(len(d), 0x400) - 1 if len(d) >= 0x400 else 7,
                                         "68000 exception vector table"))
            for va, tgt, name in vt:
                info["entries"].append((tgt, name.replace("Vct", "") + "_handler"
                                        if name != "ResetPC" else "ResetEntry"))
            info["entry"] = vt[0][1]
            info["notes"].append(f"68000 vector table: reset PC ${vt[0][1]:06X}, "
                                 f"{len(vt) - 1} other vectors in image")


def _load_prg(info, prg, org, done):
    """Load TEXT+DATA at base with relocations applied (they are the ground
    truth for which longs are addresses)."""
    base = org if org is not None else EXEC_BASE
    body = bytearray(prg["body"])
    for off in prg["relocs_off"]:
        v = (be32(body, off) + base) & 0xFFFFFFFF
        struct.pack_into(">I", body, off, v)
    tlen, dlen, blen = prg["text_len"], prg["data_len"], prg["bss_len"]
    info.update(format="atari-gemdos-executable", platform="atari", entry=base)
    info["entries"].append((base, "PrgStart"))
    info["prg"] = {"relocs": [base + o for o in prg["relocs_off"]], "text_start": base,
                   "data_start": base + tlen, "bss_start": base + tlen + dlen,
                   "bss_end": base + tlen + dlen + blen, "text_len": tlen, "data_len": dlen,
                   "bss_len": blen, "flags": prg["flags"], "sym_len": prg["sym_len"]}
    syms = parse_dri_symbols(prg["symtab"], tlen, dlen)
    info["prg_symbols"] = [(base + o, n, seg) for o, n, seg in syms]
    info["notes"].append(f"GEMDOS executable: TEXT ${tlen:X}, DATA ${dlen:X}, BSS ${blen:X}, "
                         f"{len(prg['relocs_off'])} relocations, flags ${prg['flags']:X}"
                         + (f", {len(syms)} symbols" if syms else "")
                         + (f", res1 ${prg['res1']:X}" if prg["res1"] else ""))
    if prg["trailing"]:
        info["notes"].append(f"{prg['trailing']} bytes after the relocation table (not loaded)")
    if not tlen + dlen:
        raise SystemExit("GEMDOS executable has no TEXT or DATA")
    return done([(base, bytes(body))])


def _load_resource(info, res, rsrc, org, container, done):
    info["mac"] = True
    info["resources"] = [{k: v for k, v in r.items() if k != "data"} for r in res]
    want = None
    if rsrc:
        t, _, i = rsrc.partition(":")
        t = t.ljust(4)[:4]
        cand = [r for r in res if r["type"] == t and (not i or r["id"] == int(i, 0))]
        if not cand:
            raise SystemExit(f"resource {rsrc} not found; available: "
                             + ", ".join(f"{r['type']}:{r['id']}" for r in res))
        want = cand[0]
    else:
        codes = sorted((r for r in res if r["type"] == "CODE" and r["id"] >= 1), key=lambda r: r["id"])
        if codes:
            want = codes[0]
        else:
            for r in res:
                if r["type"] in CODE_TYPES:
                    want = r
                    break
    if want is None:
        raise SystemExit(f"{container}: no code resource; use --rsrc TYPE:ID. Available: "
                         + ", ".join(f"{r['type']}:{r['id']}" for r in res))
    # default $10000 keeps resource code clear of low-memory globals ($0000-$1FFF)
    base = org if org is not None else 0x10000
    d = want["data"]
    info["format"] = f"{container} {want['type']} {want['id']}" + (f" '{want['name']}'" if want["name"] else "")
    info["resource"] = {"type": want["type"], "id": want["id"], "name": want["name"]}
    if want["type"] == "CODE" and want["id"] >= 1 and len(d) >= 4:
        jt_off, n = be16(d, 0), be16(d, 2)
        info["data_regions"].append((base, base + 3, "CODE segment header"))
        info["notes"].append(f"CODE {want['id']}: first jump table entry offset ${jt_off:04X}, {n} entries")
        info["entry"] = base + 4
        jt = [r for r in res if r["type"] == "CODE" and r["id"] == 0]
        if jt:
            info["jump_table"] = _parse_jump_table(jt[0]["data"])
            for e in info["jump_table"]:
                if e["segment"] == want["id"]:
                    info["entries"].append((base + 4 + e["offset"], f"JT_{e['index']:03d}"))
    elif want["type"] == "DRVR" and len(d) >= 20:
        info["data_regions"].append((base, base + 18 + d[18], "driver header"))
        nm = d[19:19 + d[18]].decode("mac_roman", "replace")
        for i, r in enumerate(DRVR_ROUTINES):
            o = be16(d, 8 + 2 * i)
            if o and o < len(d):
                info["entries"].append((base + o, _ident(f"DRVR_{nm.lstrip('.')}_{r}")))
        info["notes"].append(f"Driver {nm}")
    else:
        info["entry"] = base
    return done([(base, d)])


def _parse_jump_table(d: bytes):
    """CODE 0: above-A5 size, globals size, JT size, JT offset, then 8-byte
    entries: offset, MOVE.W #seg,-(SP) ($3F3C), _LoadSeg ($A9F0)."""
    out = []
    if len(d) < 16:
        return out
    jt_len = be32(d, 8)
    for i in range(min(jt_len, len(d) - 16) // 8):
        e = 16 + 8 * i
        off, op, seg, trap = be16(d, e), be16(d, e + 2), be16(d, e + 4), be16(d, e + 6)
        if op == 0x3F3C and trap == 0xA9F0:
            out.append({"index": i, "offset": off, "segment": seg, "a5_offset": 32 + 8 * i + 2})
    return out


# ===========================================================================
# ATARI ST
# ===========================================================================

TOS_BASES = (0xFC0000, 0xE00000)
CART_BASE = 0xFA0000
EXEC_BASE = 0x10000          # default load address for PRG files and boot sectors


def _bra_target(data: bytes, off: int = 0):
    w = be16(data, off)
    if w & 0xFF00 != 0x6000:
        return None
    d = w & 0xFF
    if d == 0:
        return off + 2 + struct.unpack_from(">h", data, off + 2)[0]
    if d == 0xFF:
        return None
    return off + 2 + (d - 256 if d & 0x80 else d)


def identify_tos_rom(data: bytes, org: int | None = None):
    """TOS (or EmuTOS) ROM: BRA at 0, os_beg at 8 = $FC0000 / $E00000 (or
    --org), reset handler at 4 inside the image."""
    if len(data) < 0x30:
        return None
    tgt = _bra_target(data, 0)
    os_beg, reseth = be32(data, 8), be32(data, 4) & 0xFFFFFF
    if tgt is None or not 4 <= tgt < 0x100:
        return None
    if os_beg not in TOS_BASES and os_beg != org:
        return None
    if org is not None and org != os_beg:
        return None
    if not os_beg <= reseth < os_beg + len(data) or reseth & 1:
        return None
    version, date, conf = be16(data, 2), be32(data, 0x18), be16(data, 0x1C)
    emutos = data[0x2C:0x30] == b"ETOS"
    country = conf >> 1
    cname = "multilanguage" if country == 127 else (atarisyms.COUNTRIES[country]
                                                    if country < len(atarisyms.COUNTRIES) else f"country {country}")
    vname = atarisyms.TOS_VERSIONS.get(version, f"TOS {version >> 8}.{version & 0xFF:02X}")
    name = (f"EmuTOS (reports {vname.split(' (')[0]})" if emutos else vname) + \
        f", {cname}, {'PAL' if conf & 1 else 'NTSC'}, {len(data) // 1024}K"
    summary = [f"TOS header: version ${version:04X}, date {atarisyms.bcd_date(date)}, "
               f"os_beg ${os_beg:06X}, reset handler ${reseth:06X}, os_conf ${conf:04X}"]
    return {"name": name, "version": version, "date": atarisyms.bcd_date(date), "country": cname,
            "pal": bool(conf & 1), "os_beg": os_beg, "reseth": reseth, "entry_bra": os_beg + tgt,
            "header_end": tgt, "emutos": emutos, "os_end": be32(data, 0x0C), "summary": summary,
            "kind": "rom"}


def identify_cartridge(data: bytes):
    """ROM cartridge at $FA0000: $ABCDEF42 + application headers, or the
    $FA52235F diagnostic cartridge (code at +4)."""
    if len(data) < 8:
        return None
    magic = be32(data, 0)
    if magic == 0xFA52235F:
        return {"name": "diagnostic cartridge", "kind": "cartridge", "apps": [],
                "entries": [(CART_BASE + 4, "Diag_Entry")], "headers": [(0, 3)], "summary": []}
    if magic != 0xABCDEF42:
        return None
    apps, entries, headers = [], [], []
    off, seen = 4, set()
    while 0 <= off < len(data) - 34 and off not in seen:
        seen.add(off)
        nxt, init, run = be32(data, off), be32(data, off + 4), be32(data, off + 8)
        size = be32(data, off + 16)
        fname = data[off + 20:off + 34].split(b"\0")[0].decode("latin-1", "replace")
        apps.append({"name": fname, "init": init, "run": run, "size": size})
        headers.append((off, off + 33))
        ident = "".join(c if c.isalnum() else "_" for c in fname) or f"app{len(apps)}"
        for a, kind in ((run & 0xFFFFFF, "Run"), (init & 0xFFFFFF, "Init")):
            if CART_BASE <= a < CART_BASE + len(data) and not a & 1:
                entries.append((a, f"CA_{ident}_{kind}"))
        if not nxt:
            break
        off = (nxt & 0xFFFFFF) - CART_BASE
    return {"name": f"ROM cartridge: {', '.join(a['name'] for a in apps)}", "kind": "cartridge",
            "apps": apps, "entries": entries, "headers": [(0, 3)] + headers, "summary": []}


def parse_prg(data: bytes):
    """GEMDOS executable: 28-byte header ($601A), TEXT, DATA, symbol table,
    relocation table. Returns a dict or None."""
    if len(data) < 28 or be16(data, 0) != 0x601A:
        return None
    tlen, dlen, blen, slen = struct.unpack_from(">IIII", data, 2)
    res1, flags, absflag = be32(data, 18), be32(data, 22), be16(data, 26)
    if 28 + tlen + dlen + slen > len(data) or tlen > 0x1000000 or blen > 0x1000000:
        return None
    body = data[28:28 + tlen + dlen]
    sym = data[28 + tlen + dlen:28 + tlen + dlen + slen]
    p = 28 + tlen + dlen + slen
    relocs = []
    if absflag == 0 and p + 4 <= len(data):
        off = be32(data, p)
        p += 4
        if off:
            if off + 4 > len(body) or off & 1:
                return None
            relocs.append(off)
            while p < len(data):
                b = data[p]
                p += 1
                if b == 0:
                    break
                if b == 1:
                    off += 254
                    continue
                off += b
                if off + 4 > len(body) or b & 1:
                    return None
                relocs.append(off)
    return {"text_len": tlen, "data_len": dlen, "bss_len": blen, "sym_len": slen, "res1": res1,
            "flags": flags, "absflag": absflag, "body": body, "symtab": sym, "relocs_off": relocs,
            "trailing": max(0, len(data) - p)}


DRI_TEXT, DRI_DATA, DRI_BSS, DRI_GSTLONG = 0x0200, 0x0400, 0x0100, 0x0048


def parse_dri_symbols(sym: bytes, tlen: int, dlen: int):
    """DRI / GST symbol table -> [(offset from TEXT start, name, segment)].
    Data / BSS values may be section- or text-relative; both are handled."""
    out, i = [], 0
    while i + 14 <= len(sym):
        name = sym[i:i + 8]
        typ = be16(sym, i + 8)
        val = be32(sym, i + 10)
        i += 14
        if typ & DRI_GSTLONG == DRI_GSTLONG and i + 14 <= len(sym):
            name += sym[i:i + 14]
            i += 14
        name = name.split(b"\0")[0].decode("latin-1", "replace")
        if typ & DRI_TEXT:
            seg, off = "text", val
        elif typ & DRI_DATA:
            seg, off = "data", val if val >= tlen else tlen + val
        elif typ & DRI_BSS:
            seg, off = "bss", val if val >= tlen + dlen else tlen + dlen + val
        else:
            continue
        ident = "".join(c if c.isalnum() or c == "_" else "_" for c in name)
        if ident and not ident[0].isdigit():
            out.append((off, ident, seg))
    return out


def is_boot_sector(sector: bytes) -> bool:
    return len(sector) >= 512 and sum(be16(sector, i) for i in range(0, 512, 2)) & 0xFFFF == 0x1234


def load_image(path: str, org: int | None = None, raw: bool = False, rsrc: str | None = None,
               rom: bool = False):
    info = identify_file(path, org=org, raw=raw, rsrc=rsrc, rom=rom)
    segs = info.pop("_segs")
    return segs, info


def print_report(info: dict):
    print(f"File:    {info['file']} ({info['size']} bytes)")
    print(f"Format:  {info['format']}")
    if info.get("tos"):
        print(f"Atari:   {info['rom_name'] or info['tos'].get('name')}")
    if info.get("prg"):
        p = info["prg"]
        print(f"PRG:     TEXT ${p['text_start']:06X} ({p['text_len']}), DATA ${p['data_start']:06X} "
              f"({p['data_len']}), BSS ${p['bss_start']:06X} ({p['bss_len']}), "
              f"{len(p['relocs'])} relocations, flags ${p['flags']:X}")
    if info.get("rom_name") and info.get("rom"):
        r = info["rom"]
        print(f"ROM:     {info['rom_name']}")
        print(f"         checksum ${r['checksum']:08X} ({'valid' if r['checksum_ok'] else 'MISMATCH'}), "
              f"version ${r['version']:04X}, reset PC ${r['reset_pc']:06X}")
    for s in info["segments"]:
        print(f"Segment: ${s['org']:06X}-${s['org'] + s['length'] - 1:06X} ({s['length']} bytes)")
    if info["entry"] is not None:
        print(f"Entry:   ${info['entry']:06X}")
    for a, n in info["entries"]:
        print(f"Entry:   ${a:06X} {n}")
    for s, e, why in info["data_regions"]:
        print(f"Data:    ${s:06X}-${e:06X} {why}")
    if info["resources"]:
        print(f"Resources ({len(info['resources'])}):")
        for r in info["resources"][:200]:
            nm = f" '{r['name']}'" if r.get("name") else ""
            where = f" at ${r['addr']:06X}" if "addr" in r else ""
            print(f"   {r['type']:4s} {r['id']:6d}{nm} ({r['length']} bytes){where}")
    if info.get("jump_table"):
        print(f"Jump table: {len(info['jump_table'])} entries (CODE 0)")
    for n in info["notes"]:
        print(f"Note:    {n}")


def main():
    p = argparse.ArgumentParser(description="Identify / load a 68000 binary, Mac ROM or resource file")
    p.add_argument("file")
    p.add_argument("--org", type=lambda x: int(x, 0), default=None)
    p.add_argument("--raw", action="store_true", help="Skip container / ROM detection")
    p.add_argument("--rom", action="store_true", help="Treat as a Mac ROM even if the checksum fails")
    p.add_argument("--rsrc", help="Resource to load from a resource fork, e.g. CODE:1 or DRVR:-15872")
    p.add_argument("--json", action="store_true")
    a = p.parse_args()
    _segs, info = load_image(a.file, a.org, a.raw, a.rsrc, a.rom)
    if a.json:
        print(json.dumps(info, indent=2, default=lambda o: o.hex() if isinstance(o, bytes) else str(o)))
    else:
        print_report(info)


if __name__ == "__main__":
    main()
