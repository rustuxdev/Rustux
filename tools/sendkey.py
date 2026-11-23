#!/usr/bin/env python3
"""Send keystrokes to a QEMU guest via the human monitor socket.

Usage: sendkey.py <unix-socket> <item> [item ...]

Each item is either a QEMU key name (a, b, ..., 0-9, ret, spc,
slash, ...) sent as `sendkey <name>`, or a literal string of the
form `str:<text>` typed character by character — the guest sees
real PS/2 make/break sequences either way, which is what the demo
menu and shells read.
"""
import socket
import sys
import time

# Printable chars -> QEMU key names (letters/digits pass through).
CHARKEY = {
    " ": "spc", "/": "slash", "-": "minus", "=": "equal",
    ".": "dot", ",": "comma", ";": "semicolon", "'": "apostrophe",
    "[": "bracket_left", "]": "bracket_right", "\\": "backslash",
    "`": "grave_accent", "|": "shift-backslash", "_": "shift-minus",
    ":": "shift-semicolon", "\"": "shift-apostrophe", "<": "shift-comma",
    ">": "shift-dot", "?": "shift-slash", "!": "shift-1",
    "@": "shift-2", "#": "shift-3", "$": "shift-4", "%": "shift-5",
    "^": "shift-6", "&": "shift-7", "*": "shift-8", "(": "shift-9",
    ")": "shift-0", "+": "shift-equal", "~": "shift-grave_accent",
    "{": "shift-bracket_left", "}": "shift-bracket_right",
}


def main() -> int:
    if len(sys.argv) < 3:
        print(__doc__, file=sys.stderr)
        return 2
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(sys.argv[1])
    s.settimeout(2)
    try:
        s.recv(4096)  # monitor banner
    except socket.timeout:
        pass
    for item in sys.argv[2:]:
        keys = [item]
        if item.startswith("str:"):
            keys = [CHARKEY.get(c, c) for c in item[4:]]
        for key in keys:
            s.sendall(f"sendkey {key}\n".encode())
            time.sleep(0.06)
    s.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
