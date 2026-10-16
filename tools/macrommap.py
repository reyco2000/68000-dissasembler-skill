#!/usr/bin/env python3
"""
macrommap.py — original name of rommap.py (Macintosh, Atari ST and generic
68000 ROM maps). Kept so existing commands and skills keep working.
Usage: python3 macrommap.py <rom> [dasm flags] [--output map.md] [--json map.json]
"""

try:
    from tools.rommap import main, build_map, to_markdown   # noqa: F401
except ImportError:
    from rommap import main, build_map, to_markdown          # noqa: F401

if __name__ == "__main__":
    main()
