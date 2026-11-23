#!/usr/bin/env python3
"""Send keystrokes to a QEMU guest via the human monitor socket.

Usage: sendkey.py <unix-socket> <key> [key ...]

Each argument is a QEMU key name (a, b, ..., 0-9, ret, spc, ...) sent
as `sendkey <name>` — the guest sees real PS/2 make/break sequences,
which is what the demo menu and shells read.
"""
import socket
import sys
import time


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
    for key in sys.argv[2:]:
        s.sendall(f"sendkey {key}\n".encode())
        time.sleep(0.15)
    s.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
