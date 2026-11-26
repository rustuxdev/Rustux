#!/usr/bin/env python3
"""kbdfeed.py — QMP send-key injector for `make run`.

Connects to the QMP unix socket, completes the capabilities
handshake, then taps "shift" every 300ms. Shift was chosen because
it produces evdev press/release records on EVERY keyboard path
(virtio-input and i8042 alike) while emitting no tty bytes, so the
injection can't disturb console readers. QEMU drops keys sent
before the guest posts virtio-input event buffers, so the feed
runs long enough for the kernel selftest and vintest's poll window
to catch live ones. Exits when QEMU closes the socket.
"""
import json, socket, sys, time

SOCK = "/tmp/vkbd-qmp.sock"
KEY = "shift"


def qmp(s, cmd):
    s.sendall((json.dumps(cmd) + "\r\n").encode())
    buf = b""
    while b"\r\n" not in buf and b"\n" not in buf:
        chunk = s.recv(4096)
        if not chunk:
            raise OSError("peer closed")
        buf += chunk
    return buf


def main() -> None:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    deadline = time.time() + 30
    while True:
        try:
            s.connect(SOCK)
            break
        except OSError:
            if time.time() > deadline:
                sys.exit(1)
            time.sleep(0.05)
    s.settimeout(5)
    try:
        s.recv(4096)  # greeting
        qmp(s, {"execute": "qmp_capabilities"})
        taps = 0
        while taps < 60:
            qmp(s, {
                "execute": "send-key",
                "arguments": {
                    "keys": [{"type": "qcode", "data": KEY}],
                    "hold-time": 80,
                },
            })
            taps += 1
            time.sleep(0.3)
    except OSError:
        pass
    s.close()


if __name__ == "__main__":
    main()
