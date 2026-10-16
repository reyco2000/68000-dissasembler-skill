#!/usr/bin/env python3
"""
macsyms.py — Macintosh (68000) symbol tables: A-line traps, low-memory
globals, 68000 exception vectors, Mac 128K/512K/Plus hardware and ROM IDs.
Usage: python3 macsyms.py --markdown traps|lowmem|hardware   (regenerates
       the tables in reference/; the annotator parses those markdown rows)
       python3 macsyms.py --trap A9F4                        (decode a trap word)

Sources: Inside Macintosh I-IV and the MPW equate files (Traps.a,
SysEqu.a, HardwareEqu.a) as commonly reproduced. Only the 64K ROM
(Mac 128K / 512K) and 128K ROM (Mac Plus / 512Ke) era is covered in depth;
later traps are listed where well known so application code still reads.
"""

import argparse
import sys

# ===========================================================================
# A-LINE TRAPS
# ===========================================================================
# OS traps: $A000-$A0FF (+ flag bits 8-10). Number = low byte.
OS_TRAPS = {
    0x00: "Open", 0x01: "Close", 0x02: "Read", 0x03: "Write", 0x04: "Control",
    0x05: "Status", 0x06: "KillIO", 0x07: "GetVolInfo", 0x08: "Create", 0x09: "Delete",
    0x0A: "OpenRF", 0x0B: "Rename", 0x0C: "GetFileInfo", 0x0D: "SetFileInfo",
    0x0E: "UnmountVol", 0x0F: "MountVol", 0x10: "Allocate", 0x11: "GetEOF", 0x12: "SetEOF",
    0x13: "FlushVol", 0x14: "GetVol", 0x15: "SetVol", 0x16: "FInitQueue", 0x17: "Eject",
    0x18: "GetFPos", 0x19: "InitZone", 0x1A: "GetZone", 0x1B: "SetZone", 0x1C: "FreeMem",
    0x1D: "MaxMem", 0x1E: "NewPtr", 0x1F: "DisposPtr", 0x20: "SetPtrSize", 0x21: "GetPtrSize",
    0x22: "NewHandle", 0x23: "DisposHandle", 0x24: "SetHandleSize", 0x25: "GetHandleSize",
    0x26: "HandleZone", 0x27: "ReallocHandle", 0x28: "RecoverHandle", 0x29: "HLock",
    0x2A: "HUnlock", 0x2B: "EmptyHandle", 0x2C: "InitApplZone", 0x2D: "SetApplLimit",
    0x2E: "BlockMove", 0x2F: "PostEvent", 0x30: "OSEventAvail", 0x31: "GetOSEvent",
    0x32: "FlushEvents", 0x33: "VInstall", 0x34: "VRemove", 0x35: "OffLine",
    0x36: "MoreMasters", 0x37: "ReadParam", 0x38: "WriteParam", 0x39: "ReadDateTime",
    0x3A: "SetDateTime", 0x3B: "Delay", 0x3C: "CmpString", 0x3D: "DrvrInstall",
    0x3E: "DrvrRemove", 0x3F: "InitUtil", 0x40: "ResrvMem", 0x41: "SetFilLock",
    0x42: "RstFilLock", 0x43: "SetFilType", 0x44: "SetFPos", 0x45: "FlushFile",
    0x46: "GetTrapAddress", 0x47: "SetTrapAddress", 0x48: "PtrZone", 0x49: "HPurge",
    0x4A: "HNoPurge", 0x4B: "SetGrowZone", 0x4C: "CompactMem", 0x4D: "PurgeMem",
    0x4E: "AddDrive", 0x4F: "RDrvrInstall", 0x50: "RelString", 0x51: "ReadXPRam",
    0x52: "WriteXPRam", 0x53: "ClkNoMem", 0x54: "UprString", 0x55: "StripAddress",
    0x57: "SetApplBase", 0x58: "InsTime", 0x59: "RmvTime", 0x5A: "PrimeTime",
    0x5C: "MemoryDispatch", 0x5D: "SwapMMUMode", 0x5E: "NMInstall", 0x5F: "NMRemove",
    0x60: "HFSDispatch", 0x61: "MaxBlock", 0x62: "PurgeSpace", 0x63: "MaxApplZone",
    0x64: "MoveHHi", 0x65: "StackSpace", 0x66: "NewEmptyHandle", 0x67: "HSetRBit",
    0x68: "HClrRBit", 0x69: "HGetState", 0x6A: "HSetState", 0x6C: "InitFS",
    0x6D: "InitEvents", 0x6E: "SlotManager", 0x6F: "SlotVInstall", 0x70: "SlotVRemove",
    0x71: "AttachVBL", 0x72: "DoVBLTask", 0x75: "SIntInstall", 0x76: "SIntRemove",
    0x77: "CountADBs", 0x78: "GetIndADB", 0x79: "GetADBInfo", 0x7A: "SetADBInfo",
    0x7B: "ADBReInit", 0x7C: "ADBOp", 0x7D: "GetDefaultStartup", 0x7E: "SetDefaultStartup",
    0x7F: "InternalWait", 0x80: "GetVideoDefault", 0x81: "SetVideoDefault",
    0x82: "DTInstall", 0x83: "SetOSDefault", 0x84: "GetOSDefault", 0x90: "SysEnvirons",
}

# OS traps whose bit 10 means SYS (system heap) and bit 9 CLEAR, rather than ASYNC / IMMED-HFS
MEMORY_TRAPS = set(range(0x19, 0x2E)) | {0x36, 0x40, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D,
                                         0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A}
DEVICE_IMMED_TRAPS = {0x04, 0x05, 0x06}          # Control, Status, KillIO: bit 9 = IMMED
FILE_TRAPS = set(range(0x00, 0x19)) - DEVICE_IMMED_TRAPS | {0x35, 0x41, 0x42, 0x43, 0x44, 0x45}
# OS traps that return a result in A0, so their canonical word has bit 8 set
# ($A11E _NewPtr, $A122 _NewHandle, ...)
A0_RESULT_TRAPS = {0x1A, 0x1E, 0x22, 0x26, 0x28, 0x46, 0x48, 0x66}

# Toolbox traps: $A800-$ABFF (bit 10 = auto-pop). Number = word & $3FF.
TOOL_TRAPS = {
    0x000: "SoundDispatch", 0x001: "SndDisposeChannel", 0x002: "SndAddModifier",
    0x003: "SndDoCommand", 0x004: "SndDoImmediate", 0x005: "SndPlay", 0x006: "SndControl",
    0x007: "SndNewChannel", 0x008: "InitProcMenu", 0x009: "GetCVariant", 0x00A: "GetWVariant",
    0x00B: "PopUpMenuSelect", 0x00C: "RGetResource", 0x00D: "Count1Resources",
    0x00E: "Get1IxResource", 0x00F: "Get1IxType", 0x010: "Unique1ID", 0x011: "TESelView",
    0x012: "TEPinScroll", 0x013: "TEAutoView", 0x015: "SCSIDispatch", 0x016: "Pack8",
    0x017: "CopyMask", 0x018: "FixAtan2", 0x01C: "Count1Types", 0x01F: "Get1Resource",
    0x020: "Get1NamedResource", 0x021: "MaxSizeRsrc", 0x026: "InsMenuItem",
    0x027: "HideDItem", 0x028: "ShowDItem", 0x02B: "Pack9", 0x02C: "Pack10", 0x02D: "Pack11",
    0x02E: "Pack12", 0x02F: "Pack13", 0x030: "Pack14", 0x031: "Pack15",
    0x034: "SetFScaleDisable", 0x035: "FontMetrics", 0x037: "MeasureText", 0x038: "CalcMask",
    0x039: "SeedFill", 0x03A: "ZoomWindow", 0x03B: "TrackBox", 0x03C: "TEGetOffset",
    0x03D: "TEDispatch", 0x03E: "TEStyleNew", 0x03F: "Long2Fix", 0x040: "Fix2Long",
    0x041: "Fix2Frac", 0x042: "Frac2Fix", 0x043: "Fix2X", 0x044: "X2Fix", 0x045: "Frac2X",
    0x046: "X2Frac", 0x047: "FracCos", 0x048: "FracSin", 0x049: "FracSqrt", 0x04A: "FracMul",
    0x04B: "FracDiv", 0x04D: "FixDiv", 0x04E: "GetItemCmd", 0x04F: "SetItemCmd",
    0x050: "InitCursor", 0x051: "SetCursor", 0x052: "HideCursor", 0x053: "ShowCursor",
    0x055: "ShieldCursor", 0x056: "ObscureCursor", 0x058: "BitAnd", 0x059: "BitXor",
    0x05A: "BitNot", 0x05B: "BitOr", 0x05C: "BitShift", 0x05D: "BitTst", 0x05E: "BitSet",
    0x05F: "BitClr", 0x060: "WaitNextEvent", 0x061: "Random", 0x062: "ForeColor", 0x063: "BackColor",
    0x064: "ColorBit", 0x065: "GetPixel", 0x066: "StuffHex", 0x067: "LongMul",
    0x068: "FixMul", 0x069: "FixRatio", 0x06A: "HiWord", 0x06B: "LoWord", 0x06C: "FixRound",
    0x06D: "InitPort", 0x06E: "InitGraf", 0x06F: "OpenPort", 0x070: "LocalToGlobal",
    0x071: "GlobalToLocal", 0x072: "GrafDevice", 0x073: "SetPort", 0x074: "GetPort",
    0x075: "SetPBits", 0x076: "PortSize", 0x077: "MovePortTo", 0x078: "SetOrigin",
    0x079: "SetClip", 0x07A: "GetClip", 0x07B: "ClipRect", 0x07C: "BackPat",
    0x07D: "ClosePort", 0x07E: "AddPt", 0x07F: "SubPt", 0x080: "SetPt", 0x081: "EqualPt",
    0x082: "StdText", 0x083: "DrawChar", 0x084: "DrawString", 0x085: "DrawText",
    0x086: "TextWidth", 0x087: "TextFont", 0x088: "TextFace", 0x089: "TextMode",
    0x08A: "TextSize", 0x08B: "GetFontInfo", 0x08C: "StringWidth", 0x08D: "CharWidth",
    0x08E: "SpaceExtra", 0x090: "StdLine", 0x091: "LineTo", 0x092: "Line", 0x093: "MoveTo",
    0x094: "Move", 0x095: "ShutDown", 0x096: "HidePen", 0x097: "ShowPen",
    0x098: "GetPenState", 0x099: "SetPenState", 0x09A: "GetPen", 0x09B: "PenSize",
    0x09C: "PenMode", 0x09D: "PenPat", 0x09E: "PenNormal", 0x09F: "Unimplemented",
    0x0A0: "StdRect", 0x0A1: "FrameRect", 0x0A2: "PaintRect", 0x0A3: "EraseRect",
    0x0A4: "InverRect", 0x0A5: "FillRect", 0x0A6: "EqualRect", 0x0A7: "SetRect",
    0x0A8: "OffsetRect", 0x0A9: "InsetRect", 0x0AA: "SectRect", 0x0AB: "UnionRect",
    0x0AC: "Pt2Rect", 0x0AD: "PtInRect", 0x0AE: "EmptyRect", 0x0AF: "StdRRect",
    0x0B0: "FrameRoundRect", 0x0B1: "PaintRoundRect", 0x0B2: "EraseRoundRect",
    0x0B3: "InverRoundRect", 0x0B4: "FillRoundRect", 0x0B5: "ScriptUtil", 0x0B6: "StdOval",
    0x0B7: "FrameOval", 0x0B8: "PaintOval", 0x0B9: "EraseOval", 0x0BA: "InvertOval",
    0x0BB: "FillOval", 0x0BC: "SlopeFromAngle", 0x0BD: "StdArc", 0x0BE: "FrameArc",
    0x0BF: "PaintArc", 0x0C0: "EraseArc", 0x0C1: "InvertArc", 0x0C2: "FillArc",
    0x0C3: "PtToAngle", 0x0C4: "AngleFromSlope", 0x0C5: "StdPoly", 0x0C6: "FramePoly",
    0x0C7: "PaintPoly", 0x0C8: "ErasePoly", 0x0C9: "InvertPoly", 0x0CA: "FillPoly",
    0x0CB: "OpenPoly", 0x0CC: "ClosePgon", 0x0CD: "KillPoly", 0x0CE: "OffsetPoly",
    0x0CF: "PackBits", 0x0D0: "UnpackBits", 0x0D1: "StdRgn", 0x0D2: "FrameRgn",
    0x0D3: "PaintRgn", 0x0D4: "EraseRgn", 0x0D5: "InverRgn", 0x0D6: "FillRgn",
    0x0D7: "BitMapRgn", 0x0D8: "NewRgn", 0x0D9: "DisposRgn", 0x0DA: "OpenRgn",
    0x0DB: "CloseRgn", 0x0DC: "CopyRgn", 0x0DD: "SetEmptyRgn", 0x0DE: "SetRecRgn",
    0x0DF: "RectRgn", 0x0E0: "OfsetRgn", 0x0E1: "InsetRgn", 0x0E2: "EmptyRgn",
    0x0E3: "EqualRgn", 0x0E4: "SectRgn", 0x0E5: "UnionRgn", 0x0E6: "DiffRgn",
    0x0E7: "XorRgn", 0x0E8: "PtInRgn", 0x0E9: "RectInRgn", 0x0EA: "SetStdProcs",
    0x0EB: "StdBits", 0x0EC: "CopyBits", 0x0ED: "StdTxMeas", 0x0EE: "StdGetPic",
    0x0EF: "ScrollRect", 0x0F0: "StdPutPic", 0x0F1: "StdComment", 0x0F2: "PicComment",
    0x0F3: "OpenPicture", 0x0F4: "ClosePicture", 0x0F5: "KillPicture", 0x0F6: "DrawPicture",
    0x0F8: "ScalePt", 0x0F9: "MapPt", 0x0FA: "MapRect", 0x0FB: "MapRgn", 0x0FC: "MapPoly",
    0x0FD: "PrGlue", 0x0FE: "InitFonts", 0x0FF: "GetFName", 0x100: "GetFNum",
    0x101: "FMSwapFont", 0x102: "RealFont", 0x103: "SetFontLock", 0x104: "DrawGrowIcon",
    0x105: "DragGrayRgn", 0x106: "NewString", 0x107: "SetString", 0x108: "ShowHide",
    0x109: "CalcVis", 0x10A: "CalcVBehind", 0x10B: "ClipAbove", 0x10C: "PaintOne",
    0x10D: "PaintBehind", 0x10E: "SaveOld", 0x10F: "DrawNew", 0x110: "GetWMgrPort",
    0x111: "CheckUpdate", 0x112: "InitWindows", 0x113: "NewWindow", 0x114: "DisposWindow",
    0x115: "ShowWindow", 0x116: "HideWindow", 0x117: "GetWRefCon", 0x118: "SetWRefCon",
    0x119: "GetWTitle", 0x11A: "SetWTitle", 0x11B: "MoveWindow", 0x11C: "HiliteWindow",
    0x11D: "SizeWindow", 0x11E: "TrackGoAway", 0x11F: "SelectWindow", 0x120: "BringToFront",
    0x121: "SendBehind", 0x122: "BeginUpdate", 0x123: "EndUpdate", 0x124: "FrontWindow",
    0x125: "DragWindow", 0x126: "DragTheRgn", 0x127: "InvalRgn", 0x128: "InvalRect",
    0x129: "ValidRgn", 0x12A: "ValidRect", 0x12B: "GrowWindow", 0x12C: "FindWindow",
    0x12D: "CloseWindow", 0x12E: "SetWindowPic", 0x12F: "GetWindowPic", 0x130: "InitMenus",
    0x131: "NewMenu", 0x132: "DisposMenu", 0x133: "AppendMenu", 0x134: "ClearMenuBar",
    0x135: "InsertMenu", 0x136: "DeleteMenu", 0x137: "DrawMenuBar", 0x138: "HiliteMenu",
    0x139: "EnableItem", 0x13A: "DisableItem", 0x13B: "GetMenuBar", 0x13C: "SetMenuBar",
    0x13D: "MenuSelect", 0x13E: "MenuKey", 0x13F: "GetItmIcon", 0x140: "SetItmIcon",
    0x141: "GetItmStyle", 0x142: "SetItmStyle", 0x143: "GetItmMark", 0x144: "SetItmMark",
    0x145: "CheckItem", 0x146: "GetItem", 0x147: "SetItem", 0x148: "CalcMenuSize",
    0x149: "GetMHandle", 0x14A: "SetMFlash", 0x14B: "PlotIcon", 0x14C: "FlashMenuBar",
    0x14D: "AddResMenu", 0x14E: "PinRect", 0x14F: "DeltaPoint", 0x150: "CountMItems",
    0x151: "InsertResMenu", 0x152: "DelMenuItem", 0x153: "UpdtControl", 0x154: "NewControl",
    0x155: "DisposControl", 0x156: "KillControls", 0x157: "ShowControl",
    0x158: "HideControl", 0x159: "MoveControl", 0x15A: "GetCRefCon", 0x15B: "SetCRefCon",
    0x15C: "SizeControl", 0x15D: "HiliteControl", 0x15E: "GetCTitle", 0x15F: "SetCTitle",
    0x160: "GetCtlValue", 0x161: "GetMinCtl", 0x162: "GetMaxCtl", 0x163: "SetCtlValue",
    0x164: "SetMinCtl", 0x165: "SetMaxCtl", 0x166: "TestControl", 0x167: "DragControl",
    0x168: "TrackControl", 0x169: "DrawControls", 0x16A: "GetCtlAction",
    0x16B: "SetCtlAction", 0x16C: "FindControl", 0x16D: "Draw1Control", 0x16E: "Dequeue",
    0x16F: "Enqueue", 0x170: "GetNextEvent", 0x171: "EventAvail", 0x172: "GetMouse",
    0x173: "StillDown", 0x174: "Button", 0x175: "TickCount", 0x176: "GetKeys",
    0x177: "WaitMouseUp", 0x178: "UpdtDialog", 0x179: "CouldDialog", 0x17A: "FreeDialog",
    0x17B: "InitDialogs", 0x17C: "GetNewDialog", 0x17D: "NewDialog", 0x17E: "SelIText",
    0x17F: "IsDialogEvent", 0x180: "DialogSelect", 0x181: "DrawDialog", 0x182: "CloseDialog",
    0x183: "DisposDialog", 0x184: "FindDItem", 0x185: "Alert", 0x186: "StopAlert",
    0x187: "NoteAlert", 0x188: "CautionAlert", 0x189: "CouldAlert", 0x18A: "FreeAlert",
    0x18B: "ParamText", 0x18C: "ErrorSound", 0x18D: "GetDItem", 0x18E: "SetDItem",
    0x18F: "SetIText", 0x190: "GetIText", 0x191: "ModalDialog", 0x192: "DetachResource",
    0x193: "SetResPurge", 0x194: "CurResFile", 0x195: "InitResources", 0x196: "RsrcZoneInit",
    0x197: "OpenResFile", 0x198: "UseResFile", 0x199: "UpdateResFile",
    0x19A: "CloseResFile", 0x19B: "SetResLoad", 0x19C: "CountResources",
    0x19D: "GetIndResource", 0x19E: "CountTypes", 0x19F: "GetIndType", 0x1A0: "GetResource",
    0x1A1: "GetNamedResource", 0x1A2: "LoadResource", 0x1A3: "ReleaseResource",
    0x1A4: "HomeResFile", 0x1A5: "SizeRsrc", 0x1A6: "GetResAttrs", 0x1A7: "SetResAttrs",
    0x1A8: "GetResInfo", 0x1A9: "SetResInfo", 0x1AA: "ChangedResource",
    0x1AB: "AddResource", 0x1AC: "AddReference", 0x1AD: "RmveResource",
    0x1AE: "RmveReference", 0x1AF: "ResError", 0x1B0: "WriteResource",
    0x1B1: "CreateResFile", 0x1B2: "SystemEvent", 0x1B3: "SystemClick", 0x1B4: "SystemTask",
    0x1B5: "SystemMenu", 0x1B6: "OpenDeskAcc", 0x1B7: "CloseDeskAcc", 0x1B8: "GetPattern",
    0x1B9: "GetCursor", 0x1BA: "GetString", 0x1BB: "GetIcon", 0x1BC: "GetPicture",
    0x1BD: "GetNewWindow", 0x1BE: "GetNewControl", 0x1BF: "GetRMenu", 0x1C0: "GetNewMBar",
    0x1C1: "UniqueID", 0x1C2: "SysEdit", 0x1C3: "KeyTrans", 0x1C4: "OpenRFPerm",
    0x1C5: "RsrcMapEntry", 0x1C6: "Secs2Date", 0x1C7: "Date2Secs", 0x1C8: "SysBeep",
    0x1C9: "SysError", 0x1CB: "TEGetText", 0x1CC: "TEInit", 0x1CD: "TEDispose",
    0x1CE: "TextBox", 0x1CF: "TESetText", 0x1D0: "TECalText", 0x1D1: "TESetSelect",
    0x1D2: "TENew", 0x1D3: "TEUpdate", 0x1D4: "TEClick", 0x1D5: "TECopy", 0x1D6: "TECut",
    0x1D7: "TEDelete", 0x1D8: "TEActivate", 0x1D9: "TEDeactivate", 0x1DA: "TEIdle",
    0x1DB: "TEPaste", 0x1DC: "TEKey", 0x1DD: "TEScroll", 0x1DE: "TEInsert",
    0x1DF: "TESetJust", 0x1E0: "Munger", 0x1E1: "HandToHand", 0x1E2: "PtrToXHand",
    0x1E3: "PtrToHand", 0x1E4: "HandAndHand", 0x1E5: "InitPack", 0x1E6: "InitAllPacks",
    0x1E7: "Pack0", 0x1E8: "Pack1", 0x1E9: "Pack2", 0x1EA: "Pack3", 0x1EB: "Pack4",
    0x1EC: "Pack5", 0x1ED: "Pack6", 0x1EE: "Pack7", 0x1EF: "PtrAndHand", 0x1F0: "LoadSeg",
    0x1F1: "UnloadSeg", 0x1F2: "Launch", 0x1F3: "Chain", 0x1F4: "ExitToShell",
    0x1F5: "GetAppParms", 0x1F6: "GetResFileAttrs", 0x1F7: "SetResFileAttrs",
    0x1F9: "InfoScrap", 0x1FA: "UnlodeScrap", 0x1FB: "LodeScrap", 0x1FC: "ZeroScrap",
    0x1FD: "GetScrap", 0x1FE: "PutScrap", 0x1FF: "Debugger",
    0x3FF: "DebugStr",
}

PACK_NAMES = {0: "List Manager", 1: "reserved", 2: "Disk Initialization", 3: "Standard File",
              4: "Floating-Point Arithmetic (SANE FP68K)", 5: "Transcendental Functions (Elems68K)",
              6: "International Utilities", 7: "Binary-Decimal Conversion"}

# Traps that never return to the instruction after them
NORETURN_TOOL = {0x1F2, 0x1F3, 0x1F4, 0x1C9}   # Launch, Chain, ExitToShell, SysError

# Toolbox manager by trap number range (for descriptions)
_TOOL_RANGES = [
    (0x000, 0x007, "Sound Manager"), (0x008, 0x00B, "Menu/Control (later ROMs)"),
    (0x00C, 0x010, "Resource Manager"), (0x011, 0x013, "TextEdit"), (0x015, 0x015, "SCSI Manager"),
    (0x016, 0x016, "Package"), (0x017, 0x018, "QuickDraw / math"), (0x01C, 0x021, "Resource Manager"),
    (0x026, 0x026, "Menu Manager"), (0x027, 0x028, "Dialog Manager"), (0x02B, 0x031, "Package"),
    (0x034, 0x035, "Font Manager"), (0x037, 0x039, "QuickDraw"), (0x03A, 0x03B, "Window Manager"),
    (0x03C, 0x03E, "TextEdit"), (0x03F, 0x04D, "Fixed-point math"), (0x04E, 0x04F, "Menu Manager"),
    (0x050, 0x056, "QuickDraw cursor"), (0x058, 0x05F, "Toolbox Utilities (bit ops)"), (0x060, 0x060, "Event Manager"),
    (0x061, 0x0FC, "QuickDraw"), (0x0FD, 0x0FD, "Printing"), (0x0FE, 0x103, "Font Manager"),
    (0x104, 0x12F, "Window Manager"), (0x130, 0x152, "Menu Manager"),
    (0x153, 0x16D, "Control Manager"), (0x16E, 0x16F, "OS Utilities (queues)"),
    (0x170, 0x177, "Event Manager"), (0x178, 0x191, "Dialog Manager"),
    (0x192, 0x1B1, "Resource Manager"), (0x1B2, 0x1B7, "Desk Manager"),
    (0x1B8, 0x1C2, "Toolbox Utilities / Resource getters"), (0x1C3, 0x1C3, "Event Manager"),
    (0x1C4, 0x1C5, "Resource Manager"), (0x1C6, 0x1C7, "OS Utilities (date)"),
    (0x1C8, 0x1C9, "Sound / System Error Handler"), (0x1CB, 0x1DF, "TextEdit"),
    (0x1E0, 0x1E4, "Toolbox Utilities"), (0x1E5, 0x1EE, "Package Manager"),
    (0x1EF, 0x1EF, "Toolbox Utilities"), (0x1F0, 0x1F5, "Segment Loader"),
    (0x1F6, 0x1F7, "Resource Manager"), (0x1F9, 0x1FE, "Scrap Manager"),
    (0x1FF, 0x1FF, "Debugger"), (0x3FF, 0x3FF, "Debugger"),
]


def os_manager(num: int) -> str:
    if num in FILE_TRAPS or num == 0x60:
        return "File Manager"
    if num in DEVICE_IMMED_TRAPS or num in (0x3D, 0x3E, 0x4F, 0x17):
        return "Device Manager"
    if num in MEMORY_TRAPS or num == 0x2E:
        return "Memory Manager"
    if num in (0x2F, 0x30, 0x31, 0x32, 0x6D):
        return "OS Event Manager"
    if num in (0x33, 0x34, 0x58, 0x59, 0x5A, 0x6F, 0x70, 0x71, 0x72):
        return "Vertical Retrace / Time Manager"
    if num in (0x46, 0x47):
        return "Trap Dispatcher"
    return "Operating System Utilities"


def tool_manager(num: int) -> str:
    for lo, hi, name in _TOOL_RANGES:
        if lo <= num <= hi:
            return name
    return "Toolbox"


def trap_info(word: int):
    """Decode an A-line word -> dict(name, display, ident, manager, os, num,
    flags, noreturn) or None when not a $Axxx word. Unknown numbers get a
    generic name (the word is still a valid trap)."""
    if (word & 0xF000) != 0xA000:
        return None
    if word & 0x0800:
        num = word & 0x03FF
        base = TOOL_TRAPS.get(num)
        flags = ["AUTOPOP"] if word & 0x0400 else []
        name = base or f"Tool{num:03X}"
        mgr = tool_manager(num) if base else "Toolbox (unknown)"
        return {"name": name, "num": num, "os": False, "flags": flags, "manager": mgr,
                "display": "_" + name + (" ,AUTOPOP" if flags else ""),
                "ident": "_" + name + ("_AUTOPOP" if flags else ""),
                "noreturn": num in NORETURN_TOOL, "known": base is not None}
    num = word & 0xFF
    base = OS_TRAPS.get(num)
    flags = []
    if word & 0x0400:
        flags.append("SYS" if num in MEMORY_TRAPS else "ASYNC")
    if word & 0x0200:
        if num in MEMORY_TRAPS:
            flags.append("CLEAR")
        elif num in DEVICE_IMMED_TRAPS:
            flags.append("IMMED")
        else:
            flags.append("HFS")
    name = base or f"OS{num:02X}"
    mgr = os_manager(num) if base else "OS (unknown)"
    ident = "_" + name + "".join("_" + f for f in flags)
    # bit 8 = A0 not preserved; only a non-canonical choice shows in the name
    if word & 0x0100 and num not in A0_RESULT_TRAPS:
        ident += "_NA0"
    elif not word & 0x0100 and num in A0_RESULT_TRAPS:
        ident += "_SAVEA0"
    return {"name": name, "num": num, "os": True, "flags": flags, "manager": mgr,
            "display": "_" + name + (" ," + ",".join(flags) if flags else ""),
            "ident": ident, "noreturn": False, "known": base is not None}


# ===========================================================================
# LOW-MEMORY GLOBALS  (addr -> (name, description))
# ===========================================================================
EXCEPTION_VECTORS = {
    0x000: ("ResetSSP", "68000 reset: initial supervisor stack pointer"),
    0x004: ("ResetPC", "68000 reset: initial program counter"),
    0x008: ("BusErrVct", "bus error vector"), 0x00C: ("AdrErrVct", "address error vector"),
    0x010: ("IllegalVct", "illegal instruction vector"),
    0x014: ("ZeroDivVct", "divide-by-zero vector"), 0x018: ("ChkVct", "CHK instruction vector"),
    0x01C: ("TrapVVct", "TRAPV vector"), 0x020: ("PrivlgVct", "privilege violation vector"),
    0x024: ("TraceVct", "trace vector"),
    0x028: ("Line1010", "line-A (A-trap) vector: the Mac trap dispatcher"),
    0x02C: ("Line1111", "line-F vector"), 0x060: ("SpurVct", "spurious interrupt vector"),
    0x064: ("AutoInt1", "level 1 autovector: VIA interrupt"),
    0x068: ("AutoInt2", "level 2 autovector: SCC interrupt"),
    0x06C: ("AutoInt3", "level 3 autovector (VIA+SCC)"), 0x070: ("AutoInt4", "level 4 autovector: interrupt (programmer's) switch"),
    0x074: ("AutoInt5", "level 5 autovector"), 0x078: ("AutoInt6", "level 6 autovector"),
    0x07C: ("AutoInt7", "level 7 autovector (NMI)"),
}
for _i in range(16):
    EXCEPTION_VECTORS[0x80 + 4 * _i] = (f"Trap{_i}Vct", f"TRAP #{_i} vector")

LOWMEM = {
    0x0100: ("MonkeyLives", "word: >= 0 when the Monkey (event tester) is running"),
    0x0102: ("ScrVRes", "word: screen vertical dots per inch"),
    0x0104: ("ScrHRes", "word: screen horizontal dots per inch"),
    0x0106: ("ScreenRow", "word: rowBytes of the screen"),
    0x0108: ("MemTop", "long: top of RAM + 1"), 0x010C: ("BufPtr", "long: top of application memory"),
    0x0110: ("StkLowPt", "long: lowest stack pointer value seen (stack sniffer)"),
    0x0114: ("HeapEnd", "long: end of application heap zone"),
    0x0118: ("TheZone", "long: current heap zone"), 0x011C: ("UTableBase", "long: unit table base"),
    0x0120: ("MacJmp", "long: debugger entry point"), 0x0124: ("DskRtnAdr", "long: disk driver temp return address"),
    0x0128: ("PollRtnAddr", "long: SCC poll return address"),
    0x012C: ("DskVerify", "byte: verify writes flag (Sony driver)"),
    0x012D: ("LoadTrap", "byte: trap before launch flag"),
    0x012E: ("MmInOK", "byte: initial memory manager checks ok"),
    0x012F: ("CPUFlag", "byte: CPU type (0 = 68000)"),
    0x0130: ("ApplLimit", "long: application heap limit"), 0x0134: ("SonyVars", "long: Sony driver variables"),
    0x0138: ("PWMValue", "word: current PWM (disk speed) value"),
    0x013A: ("PollStack", "long: SCC poll data start address"), 0x013E: ("PollProc", "long: SCC poll procedure"),
    0x0142: ("DskErr", "word: disk routine result code"), 0x0144: ("SysEvtMask", "word: system event mask"),
    0x0146: ("SysEvtBuf", "long: system event queue element buffer"),
    0x014A: ("EventQueue", "10 bytes: event queue header"), 0x0154: ("EvtBufCnt", "word: max events in SysEvtBuf - 1"),
    0x0156: ("RndSeed", "long: random number seed"), 0x015A: ("SysVersion", "word: system file version"),
    0x015C: ("SEvtEnb", "byte: SystemEvent enable"), 0x015D: ("DSWndUpdate", "byte: GetNextEvent not to paint the DS window"),
    0x015E: ("FontFlag", "byte: font manager loop flag"), 0x015F: ("IntFlag", "byte: reduce interrupt disable time"),
    0x0160: ("VBLQueue", "10 bytes: vertical retrace queue header"),
    0x016A: ("Ticks", "long: tick count (60.15 Hz) since startup"),
    0x016E: ("MBTicks", "long: tick count at last mouse button change"),
    0x0172: ("MBState", "byte: current mouse button state"), 0x0173: ("Tocks", "byte: lisa sub-tick count"),
    0x0174: ("KeyMap", "8 bytes: bitmap of keys down"), 0x017C: ("KeypadMap", "8 bytes: keypad bitmap"),
    0x0184: ("KeyLast", "word: last key hit"), 0x0186: ("KeyTime", "long: tick count when KeyLast was hit"),
    0x018A: ("KeyRepTime", "long: tick count when key was last repeated"),
    0x018E: ("KeyThresh", "word: threshold for key repeat"), 0x0190: ("KeyRepThresh", "word: key repeat speed"),
    0x0192: ("Lvl1DT", "32 bytes: level-1 (VIA) interrupt dispatch table"),
    0x01B2: ("Lvl2DT", "32 bytes: level-2 (SCC) interrupt dispatch table"),
    0x01D2: ("UnitNtryCnt", "word: count of entries in unit table"),
    0x01D4: ("VIA", "long: VIA base address"), 0x01D8: ("SCCRd", "long: SCC read base address"),
    0x01DC: ("SCCWr", "long: SCC write base address"), 0x01E0: ("IWM", "long: IWM base address"),
    0x01E4: ("Scratch20", "20 bytes: scratch (GetParam buffer)"),
    0x01F8: ("SysParam", "20 bytes: copy of parameter RAM (SPValid)"),
    0x01F9: ("SPATalkA", "byte: AppleTalk node ID hint, port A"),
    0x01FA: ("SPATalkB", "byte: AppleTalk node ID hint, port B"),
    0x01FB: ("SPConfig", "byte: serial port configuration"), 0x01FC: ("SPPortA", "word: SCC port A configuration"),
    0x01FE: ("SPPortB", "word: SCC port B configuration"), 0x0200: ("SPAlarm", "long: alarm time"),
    0x0204: ("SPFont", "word: default application font - 1"), 0x0206: ("SPKbd", "byte: keyboard repeat threshold/rate"),
    0x0207: ("SPPrint", "byte: print stuff"), 0x0208: ("SPVolCtl", "byte: speaker volume"),
    0x0209: ("SPClikCaret", "byte: double-click / caret blink times"), 0x020A: ("SPMisc1", "byte: miscellaneous"),
    0x020B: ("SPMisc2", "byte: mouse scaling, startup disk, menu blink"),
    0x020C: ("Time", "long: clock time (seconds since 1 Jan 1904), extrapolated"),
    0x0210: ("BootDrive", "word: drive number of boot drive"), 0x0212: ("JShell", "word: journaling shell state"),
    0x0214: ("SFSaveDisk", "word: Standard File: negative of volume reference number"),
    0x0216: ("HiKeyLast", "word: same as KbdVars"), 0x0218: ("KbdLast", "byte: same as KbdVars+2"),
    0x021A: ("JKybdTask", "long: keyboard VBL task hook"), 0x021E: ("KbdType", "byte: keyboard model number"),
    0x021F: ("AlarmState", "byte: alarm bit flags"), 0x0220: ("MemErr", "word: last memory manager error"),
    0x0260: ("SdVolume", "byte: global volume (sound) control"), 0x0262: ("SoundPtr", "long: pointer to four-tone record"),
    0x0266: ("SoundBase", "long: sound buffer base address"), 0x026A: ("SoundVBL", "16 bytes: sound VBL task"),
    0x027A: ("SoundDCE", "long: sound driver DCE"), 0x027E: ("SoundActive", "byte: sound is active"),
    0x027F: ("SoundLevel", "byte: current level in buffer"), 0x0280: ("CurPitch", "word: current pitch value"),
    0x028E: ("ROM85", "word: $7FFF = 128K ROM or later, $FFFF = 64K ROM"),
    0x0290: ("PortAUse", "byte: port A use (bit 7 = in use)"), 0x0291: ("PortBUse", "byte: port B use"),
    0x029A: ("JGNEFilter", "long: GetNextEvent filter proc"), 0x029E: ("Key1Trans", "long: keyboard translator procedure"),
    0x02A2: ("Key2Trans", "long: numeric keypad translator procedure"),
    0x02A6: ("SysZone", "long: system heap zone"), 0x02AA: ("ApplZone", "long: application heap zone"),
    0x02AE: ("ROMBase", "long: ROM base address"), 0x02B2: ("RAMBase", "long: RAM base address"),
    0x02B6: ("BasicGlob", "long: basic globals"), 0x02BA: ("DSAlertTab", "long: system error alerts table"),
    0x02BE: ("ExtStsDT", "16 bytes: SCC external/status interrupt dispatch table"),
    0x02CE: ("SCCASts", "byte: SCC read reg 0 last ext/sts rupt - A"),
    0x02CF: ("SCCBSts", "byte: SCC read reg 0 last ext/sts rupt - B"),
    0x02D0: ("SerialVars", "16 bytes: async driver variables"), 0x02D8: ("ABusVars", "long: AppleTalk variables"),
    0x02DC: ("ABusDCE", "long: AppleTalk DCE"), 0x02E0: ("FinderName", "16 bytes: name of the shell (String[15])"),
    0x02F0: ("DoubleTime", "long: double-click interval in ticks"), 0x02F4: ("CaretTime", "long: caret blink interval in ticks"),
    0x02F8: ("ScrDmpEnb", "byte: screen dump (cmd-shift-n) enabled"), 0x02F9: ("ScrDmpType", "byte: FF dumps screen, FE dumps front window"),
    0x02FA: ("TagData", "word: sector tag info for disk drivers"), 0x02FC: ("BufTgFNum", "long: file tags buffer: file number"),
    0x0300: ("BufTgFFlg", "word: file tags buffer: flags"), 0x0302: ("BufTgFBkNum", "word: file tags buffer: logical block number"),
    0x0304: ("BufTgDate", "long: file tags buffer: date/time of last change"),
    0x0308: ("DrvQHdr", "10 bytes: drive queue header"), 0x0312: ("PWMBuf2", "long: PWM buffer 1 (or 2 if sound)"),
    0x0316: ("MacPgm", "long: Macintosh program (?) / HpChk"), 0x031A: ("Lo3Bytes", "long: constant $00FFFFFF"),
    0x031E: ("MinStack", "long: minimum stack size used in InitApplZone"),
    0x0322: ("DefltStack", "long: default size of stack"), 0x0326: ("MMDefFlags", "word: default zone flags"),
    0x0328: ("GZRootHnd", "long: root handle for GrowZone"), 0x032C: ("GZRootPtr", "long: root pointer for GrowZone"),
    0x0330: ("GZMoveHnd", "long: moving handle for GrowZone"), 0x0334: ("DSDrawProc", "long: alternate SysError draw procedure"),
    0x0338: ("EjectNotify", "long: eject notify procedure"), 0x033C: ("IAZNotify", "long: world swaps notify procedure"),
    0x034E: ("FCBSPtr", "long: pointer to file control block buffer"),
    0x0352: ("DefVCBPtr", "long: pointer to default volume control block"),
    0x0356: ("VCBQHdr", "10 bytes: volume control block queue header"),
    0x0360: ("FSQHdr", "10 bytes: file I/O queue header (FSBusy)"), 0x0362: ("FSQHead", "long: file I/O queue head"),
    0x0366: ("FSQTail", "long: file I/O queue tail"), 0x0372: ("WDCBsPtr", "long: working directory queue (HFS)"),
    0x0392: ("HFSDSErr", "word: final gasp: error code (HFS)"), 0x0398: ("CurDirStore", "long: directory ID of last directory opened"),
    0x03A2: ("ErCode", "word: file system error code"), 0x03A4: ("Params", "50 bytes: file system parameter block"),
    0x03E2: ("FSQueueHook", "long: file system queue hook"), 0x03E6: ("ExtFSHook", "long: external file system hook"),
    0x03EA: ("DskSwtchHook", "long: disk-switch hook"), 0x03EE: ("ReqstVol", "long: offline volume VCB pointer"),
    0x03F2: ("ToExtFS", "long: external file system dispatch"), 0x03F6: ("FSFCBLen", "word: size of an FCB (-1 = MFS-only ROM)"),
    0x03F8: ("DSAlertRect", "8 bytes: rectangle for the system error alert"),
    0x0400: ("OSTable", "trap dispatch table: OS traps (64K ROM: the single 512-word table)"),
    0x0800: ("JHideCursor", "long: HideCursor vector"), 0x0804: ("JShowCursor", "long: ShowCursor vector"),
    0x0808: ("JShieldCursor", "long: ShieldCursor vector"), 0x080C: ("JScrnAddr", "long: ScreenAddress vector"),
    0x0810: ("JScrnSize", "long: ScreenSize vector"), 0x0814: ("JInitCrsr", "long: InitCursor vector"),
    0x0818: ("JSetCrsr", "long: SetCursor vector"), 0x081C: ("JCrsrObscure", "long: ObscureCursor vector"),
    0x0820: ("JUpdateProc", "long: update procedure vector"),
    0x0824: ("ScrnBase", "long: address of main screen buffer"),
    0x0828: ("MTemp", "long: low-level mouse location"), 0x082C: ("RawMouse", "long: un-jerked mouse coordinates"),
    0x0830: ("Mouse", "long: processed mouse coordinates"), 0x0834: ("CrsrPin", "8 bytes: cursor pinning rectangle"),
    0x083C: ("CrsrRect", "8 bytes: cursor hit rectangle"), 0x0844: ("TheCrsr", "68 bytes: current cursor record"),
    0x0888: ("CrsrAddr", "long: address of data under cursor"), 0x088C: ("CrsrSave", "64 bytes: data under cursor"),
    0x08CC: ("CrsrVis", "byte: cursor visible flag"), 0x08CD: ("CrsrBusy", "byte: cursor locked out"),
    0x08CE: ("CrsrNew", "byte: cursor changed flag"), 0x08CF: ("CrsrCouple", "byte: cursor coupled to mouse"),
    0x08D0: ("CrsrState", "word: cursor nesting level"), 0x08D2: ("CrsrObscure", "byte: cursor obscure semaphore"),
    0x08D3: ("CrsrScale", "byte: cursor scaled"), 0x08D6: ("MouseMask", "long: V-H mask for ANDing with mouse"),
    0x08DA: ("MouseOffset", "long: V-H offset for adding after ANDing"),
    0x08DE: ("JournalFlag", "word: journaling state"), 0x08E8: ("JournalRef", "word: journalling driver refnum"),
    0x08EC: ("CrsrThresh", "word: mouse-scaling threshold"), 0x08EE: ("JCrsrTask", "long: address of CrsrVBLTask"),
    0x08F2: ("WWExist", "byte: window manager initialized ($00 = yes)"),
    0x08F3: ("QDExist", "byte: QuickDraw initialized ($00 = yes)"),
    0x08F4: ("JFetch", "long: fetch-a-byte routine for drivers"), 0x08F8: ("JStash", "long: stash-a-byte routine for drivers"),
    0x08FC: ("JIODone", "long: IODone entry for drivers"), 0x0900: ("CurApRefNum", "word: refnum of application's resource file"),
    0x0902: ("LaunchFlag", "byte: from launch or chain"), 0x0904: ("CurrentA5", "long: current application's A5 world"),
    0x0908: ("CurStackBase", "long: current stack base"), 0x0910: ("CurApName", "32 bytes: name of application"),
    0x0934: ("CurJTOffset", "word: current jump table offset"), 0x0936: ("CurPageOption", "word: current page 2 configuration"),
    0x0938: ("HiliteMode", "byte: set to use highlight colour"), 0x093A: ("LoaderPBlock", "10 bytes: param block for ExitToShell"),
    0x0944: ("PrintErr", "word: print manager error code"), 0x0960: ("ScrapSize", "long: scrap length"),
    0x0964: ("ScrapHandle", "long: memory scrap"), 0x0968: ("ScrapCount", "word: validation byte"),
    0x096A: ("ScrapState", "word: scrap state"), 0x096C: ("ScrapName", "long: pointer to scrap name"),
    0x0980: ("ROMFont0", "long: handle to system font"), 0x0984: ("ApFontID", "word: resource ID of application font"),
    0x09CE: ("ToolScratch", "8 bytes: scratch area"), 0x09D6: ("WindowList", "long: list of windows"),
    0x09DA: ("SaveUpdate", "word: enable update events"), 0x09DC: ("PaintWhite", "word: erase windows before update"),
    0x09DE: ("WMgrPort", "long: window manager's grafPort"), 0x09E6: ("OldStructure", "long: handle to saved structure region"),
    0x09EA: ("OldContent", "long: handle to saved content region"), 0x09EE: ("GrayRgn", "long: rounded gray desk region"),
    0x09F2: ("SaveVisRgn", "long: handle to saved visRgn"), 0x09F6: ("DragHook", "long: user hook during dragging"),
    0x09FA: ("Scratch8", "8 bytes: scratch area"), 0x0A02: ("OneOne", "long: constant $00010001"),
    0x0A06: ("MinusOne", "long: constant $FFFFFFFF"), 0x0A0A: ("TopMenuItem", "word: pixel value of top of scrollable menu"),
    0x0A0C: ("AtMenuBottom", "word: flag for menu scrolling"), 0x0A1C: ("MenuList", "long: current menu list"),
    0x0A20: ("MBarEnable", "word: menubar enable for desk accessories"), 0x0A24: ("MenuFlash", "word: flash feedback count"),
    0x0A26: ("TheMenu", "word: menu ID of currently highlighted menu"), 0x0A28: ("SavedHandle", "long: handle to data under a menu"),
    0x0A2C: ("MBarHook", "long: user hook during MenuSelect"), 0x0A30: ("MenuHook", "long: user hook during menu tracking"),
    0x0A34: ("DragPattern", "8 bytes: pattern for dragging outlines"), 0x0A3C: ("DeskPattern", "8 bytes: desktop pattern"),
    0x0A4A: ("FPState", "6 bytes: floating point state"), 0x0A50: ("TopMapHndl", "long: topmost resource map"),
    0x0A54: ("SysMapHndl", "long: system resource map handle"), 0x0A58: ("SysMap", "word: refnum of system resource map"),
    0x0A5A: ("CurMap", "word: refnum of current resource map"), 0x0A5C: ("ResReadOnly", "word: read-only flag"),
    0x0A5E: ("ResLoad", "word: auto-load resources"), 0x0A60: ("ResErr", "word: resource manager error code"),
    0x0A62: ("TaskLock", "byte: re-entering SystemTask"), 0x0A63: ("FScaleDisable", "byte: disable font scaling"),
    0x0A64: ("CurActivate", "long: window slated for activate event"),
    0x0A68: ("CurDeactive", "long: window slated for deactivate event"), 0x0A6C: ("DeskHook", "long: hook for painting desk"),
    0x0A70: ("TEDoText", "long: TextEdit doText hook"), 0x0A74: ("TERecal", "long: TextEdit recalText hook"),
    0x0A78: ("ApplScratch", "12 bytes: application scratch"), 0x0A84: ("GhostWindow", "long: window never to be considered frontmost"),
    0x0A88: ("CloseOrnHook", "long: hook for closing desk ornaments"), 0x0A8C: ("ResumeProc", "long: Resume procedure from InitDialogs"),
    0x0A90: ("SaveProc", "long: address of Save failsafe procedure"), 0x0A94: ("SaveSP", "long: safe SP for restart or save"),
    0x0A98: ("ANumber", "word: active alert ID"), 0x0A9A: ("ACount", "word: alert stage number"),
    0x0A9C: ("DABeeper", "long: beeper routine"), 0x0AA0: ("DAStrings", "16 bytes: paramText substitution strings"),
    0x0AB0: ("TEScrpLength", "word: TextEdit scrap length"), 0x0AB4: ("TEScrpHandle", "long: TextEdit scrap"),
    0x0AB8: ("AppPacks", "32 bytes: handles to PACK resources 0-7"), 0x0AD8: ("SysResName", "20 bytes: name of system resource file"),
    0x0AEC: ("AppParmHandle", "long: handle to hold application parameters"),
    0x0AF0: ("DSErrCode", "word: last system error alert ID"), 0x0AF2: ("ResErrProc", "long: resource error procedure"),
    0x0AF6: ("TEWdBreak", "long: default word break routine"), 0x0AFA: ("DlgFont", "word: current font for dialogs"),
    0x0AFC: ("LastTGlobal", "long: address of last global"), 0x0B9E: ("ROMMapInsert", "byte: link ROM map into resource chain"),
    0x0B9F: ("TmpResLoad", "byte: temporary ResLoad value"), 0x0BA0: ("IntlSpec", "long: international software installed if <> -1"),
    0x0BA6: ("SysFontFam", "word: system font family"), 0x0BA8: ("SysFontSize", "word: system font size"),
    0x0BAA: ("MBarHeight", "word: height of menu bar"),
    0x0C00: ("ToolTable", "trap dispatch table: Toolbox traps (128K ROM, 512 longs)"),
}

# ===========================================================================
# HARDWARE: Mac 128K / 512K / Plus (addr -> (name, description))
# ===========================================================================
VIA_BASE = 0xEFE1FE
VIA_REGS = [("vBufB", "port B data"), ("vBufAH", "port A data (with handshake)"),
            ("vDirB", "port B direction"), ("vDirA", "port A direction"),
            ("vT1C", "timer 1 counter low"), ("vT1CH", "timer 1 counter high"),
            ("vT1L", "timer 1 latch low"), ("vT1LH", "timer 1 latch high"),
            ("vT2C", "timer 2 counter low"), ("vT2CH", "timer 2 counter high"),
            ("vSR", "shift register (keyboard)"), ("vACR", "auxiliary control register"),
            ("vPCR", "peripheral control register"), ("vIFR", "interrupt flag register"),
            ("vIER", "interrupt enable register"), ("vBufA", "port A data (no handshake)")]
IWM_BASE = 0xDFE1FF
IWM_REGS = [("ph0L", "CA0 off"), ("ph0H", "CA0 on"), ("ph1L", "CA1 off"), ("ph1H", "CA1 on"),
            ("ph2L", "CA2 off"), ("ph2H", "CA2 on"), ("ph3L", "LSTRB off"), ("ph3H", "LSTRB on"),
            ("mtrOff", "disk enable off"), ("mtrOn", "disk enable on"),
            ("intDrive", "select internal drive"), ("extDrive", "select external drive"),
            ("q6L", "Q6 off"), ("q6H", "Q6 on"), ("q7L", "Q7 off"), ("q7H", "Q7 on")]
SCC_RD = 0x9FFFF8
SCC_WR = 0xBFFFF9
SCC_REGS = [(0, "bCtl", "channel B control"), (2, "aCtl", "channel A control"),
            (4, "bData", "channel B data"), (6, "aData", "channel A data")]
SCSI_RD = 0x580000      # Mac Plus only
SCSI_WR = 0x580001
SCSI_REGS = [("sCDR", "current data (rd) / output data (wr)"), ("sICR", "initiator command"),
             ("sMR", "mode"), ("sTCR", "target command"),
             ("sCSR", "current SCSI bus status (rd) / select enable (wr)"),
             ("sBSR", "bus and status (rd) / start DMA send (wr)"),
             ("sIDR", "input data (rd) / start DMA target receive (wr)"),
             ("sRESET", "reset parity/interrupt (rd) / start DMA initiator receive (wr)")]

VIA_A_BITS = {0: "vSound0", 1: "vSound1", 2: "vSound2", 3: "vSndPg2 (0 = alternate sound buffer)",
              4: "vOverlay (1 = ROM overlay at 0)", 5: "vHeadSel (disk SEL line)",
              6: "vPage2 (0 = alternate screen buffer)", 7: "vSCCWReq (SCC wait/request)"}
VIA_B_BITS = {0: "rTCData (RTC serial data)", 1: "rTCClk (RTC clock)", 2: "rTCEnb (RTC enable, 0 = on)",
              3: "vSW (mouse switch, 0 = down)", 4: "vX2 (mouse X2)", 5: "vY2 (mouse Y2)",
              6: "vH4 (horizontal blank)", 7: "vSndEnb (0 = sound on)"}

HARDWARE = {}
for _i, (_n, _d) in enumerate(VIA_REGS):
    HARDWARE[VIA_BASE + _i * 0x200] = (_n, f"VIA 6522 {_d}")
for _i, (_n, _d) in enumerate(IWM_REGS):
    HARDWARE[IWM_BASE + _i * 0x200] = ("iwm_" + _n, f"IWM floppy controller: {_d}")
for _o, _n, _d in SCC_REGS:
    HARDWARE[SCC_RD + _o] = ("sccR_" + _n, f"Z8530 SCC read: {_d}")
    HARDWARE[SCC_WR + _o] = ("sccW_" + _n, f"Z8530 SCC write: {_d}")
for _i, (_n, _d) in enumerate(SCSI_REGS):
    HARDWARE[SCSI_RD + _i * 0x10] = ("scsiR_" + _n, f"NCR 5380 SCSI read (Mac Plus): {_d}")
    HARDWARE[SCSI_WR + _i * 0x10] = ("scsiW_" + _n, f"NCR 5380 SCSI write (Mac Plus): {_d}")
HARDWARE[0x580200] = ("scsiDMA", "NCR 5380 SCSI pseudo-DMA base (Mac Plus, /DACK)")

HW_RANGES = [
    (0x000000, 0x3FFFFF, "RAM (ROM overlaid at 0 after reset until vOverlay is cleared)"),
    (0x400000, 0x4FFFFF, "ROM (64K or 128K, mirrored)"),
    (0x580000, 0x5FFFFF, "SCSI NCR 5380 (Mac Plus)"),
    (0x600000, 0x7FFFFF, "RAM (while ROM overlay is on)"),
    (0x9FFFF8, 0x9FFFFF, "SCC read"), (0xBFFFF9, 0xBFFFFF, "SCC write"),
    (0xDFE1FF, 0xDFFFFF, "IWM"), (0xEFE1FE, 0xEFFFFF, "VIA"),
    (0xF00000, 0xF7FFFF, "phase read / test"), (0xFFFFF0, 0xFFFFFF, "interrupt autovectors"),
]


def hw_region(addr: int):
    """Exact hardware register (name, desc) or the containing region."""
    if addr in HARDWARE:
        return HARDWARE[addr]
    for lo, hi, desc in HW_RANGES:
        if lo <= addr <= hi and lo >= 0x580000:
            return None, desc
    return None


def via_reg_by_offset(off: int):
    """VIA register for a displacement from VIA_BASE (as used with An = VIA)."""
    if off % 0x200 == 0 and 0 <= off < 0x2000:
        return VIA_REGS[off // 0x200]
    return None


def iwm_reg_by_offset(off: int):
    if off % 0x200 == 0 and 0 <= off < 0x2000:
        return IWM_REGS[off // 0x200]
    return None


# ===========================================================================
# ROM IDENTIFICATION
# ===========================================================================
# checksum (first long of the ROM) -> (machine, size, notes)
KNOWN_ROMS = {
    0x28BA61CE: ("Macintosh 128K (64K ROM, first release)", 0x10000),
    0x28BA4E50: ("Macintosh 512K (64K ROM, revised)", 0x10000),
    0x4D1EEEE1: ("Macintosh Plus v1 'Lonely Hearts' (128K ROM)", 0x20000),
    0x4D1EEAE1: ("Macintosh Plus v2 'Lonely Heifers' (128K ROM)", 0x20000),
    0x4D1F8172: ("Macintosh Plus v3 'Loud Harmonicas' (128K ROM, also 512Ke)", 0x20000),
    0xB2E362A8: ("Macintosh SE (256K ROM)", 0x40000),
    0xA49F9914: ("Macintosh Classic (512K ROM)", 0x80000),
}
ROM_VERSIONS = {0x69: "64K ROM (Mac 128K/512K)", 0x75: "128K ROM (Mac Plus / 512Ke)"}


def mac_rom_checksum(data: bytes) -> int:
    """Sum of big-endian words from offset 4 to the end, modulo 2^32
    (the value stored in the ROM's first long)."""
    s = 0
    for i in range(4, len(data) - 1, 2):
        s += (data[i] << 8) | data[i + 1]
    return s & 0xFFFFFFFF


# ===========================================================================
# MARKDOWN EXPORT (reference/*.md tables are generated from these)
# ===========================================================================

def markdown_traps() -> str:
    out = ["## OS Traps ($A000-$A0FF)", "",
           "Bits 8-10 of an OS trap word are flags: bit 10 = ASYNC (file/device) or SYS",
           "(memory), bit 9 = IMMED (Control/Status/KillIO), CLEAR (memory) or HFS (file),",
           "bit 8 = A0 not preserved (the trap returns a result in A0).", "",
           "| Trap | Name | Manager |", "|------|------|---------|"]
    for n, name in sorted(OS_TRAPS.items()):
        out.append(f"| $A0{n:02X} | _{name} | {os_manager(n)} |")
    out += ["", "## Toolbox Traps ($A800-$ABFF)", "",
            "Bit 10 ($AC00) = auto-pop (return to the caller's caller).", "",
            "| Trap | Name | Manager |", "|------|------|---------|"]
    for n, name in sorted(TOOL_TRAPS.items()):
        out.append(f"| ${0xA800 + n:04X} | _{name} | {tool_manager(n)} |")
    out += ["", "## Packages (_Pack0-_Pack7 = $A9E7-$A9EE)", "",
            "| Pack | Name | Contents |", "|------|------|----------|"]
    for n, desc in PACK_NAMES.items():
        out.append(f"| {n} | _Pack{n} | {desc} |")
    return "\n".join(out) + "\n"


def markdown_lowmem() -> str:
    out = ["## 68000 Exception Vectors ($000-$0FF)", "",
           "| Address | Name | Description |", "|---------|------|-------------|"]
    for a, (n, d) in sorted(EXCEPTION_VECTORS.items()):
        out.append(f"| ${a:04X} | {n} | {d} |")
    out += ["", "## System Globals ($100-$BFF)", "",
            "Referenced with absolute short addressing, e.g. `MOVE.L (Ticks).W,D0`.", "",
            "| Address | Name | Description |", "|---------|------|-------------|"]
    for a, (n, d) in sorted(LOWMEM.items()):
        out.append(f"| ${a:04X} | {n} | {d} |")
    return "\n".join(out) + "\n"


def markdown_hardware() -> str:
    out = ["| Address | Name | Description |", "|---------|------|-------------|"]
    for a, (n, d) in sorted(HARDWARE.items()):
        out.append(f"| ${a:06X} | {n} | {d} |")
    return "\n".join(out) + "\n"


def main():
    p = argparse.ArgumentParser(description="Macintosh 68000 symbol tables")
    p.add_argument("--markdown", choices=["traps", "lowmem", "hardware"], help="Print a markdown table")
    p.add_argument("--trap", help="Decode a trap word (hex), e.g. A9F4 or A51E")
    a = p.parse_args()
    if a.trap:
        t = trap_info(int(a.trap.lstrip("$"), 16))
        if not t:
            print("not an A-line word")
            sys.exit(1)
        print(f"${int(a.trap.lstrip('$'), 16):04X}  {t['display']}  ({t['manager']}"
              f"{', does not return' if t['noreturn'] else ''})")
    elif a.markdown == "traps":
        print(markdown_traps(), end="")
    elif a.markdown == "lowmem":
        print(markdown_lowmem(), end="")
    elif a.markdown == "hardware":
        print(markdown_hardware(), end="")
    else:
        p.print_help()


if __name__ == "__main__":
    main()
