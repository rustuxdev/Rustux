#!/usr/bin/env python3
"""hvcfeed.py — virtio-console chardev peer for `make run`.

QEMU's socket chardev listens on /tmp/hvc.sock; this client connects
(with retries while QEMU comes up), feeds a repeating RX line into
the guest's console input, and captures whatever the guest writes
back to /tmp/hvc_captured.log. Exits when QEMU closes the socket.
"""
import socket, sys, time

SOCK = "/tmp/hvc.sock"
LOG = "/tmp/hvc_captured.log"
FEED = b"rx-proof-line\n"


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
    s.setblocking(False)
    out = open(LOG, "wb")
    last_feed = 0.0
    feeds = 0
    while True:
        try:
            data = s.recv(4096)
            if data == b"":
                break  # peer closed — QEMU exited
            out.write(data)
            out.flush()
        except BlockingIOError:
            pass
        except OSError:
            break
        now = time.time()
        if now - last_feed >= 0.25 and feeds < 40:
            try:
                s.sendall(FEED)
            except OSError:
                break
            last_feed = now
            feeds += 1
        time.sleep(0.01)
    out.close()


if __name__ == "__main__":
    main()
