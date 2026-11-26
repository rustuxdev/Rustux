#!/usr/bin/env python3
"""balloonfeed.py — QMP balloon exerciser for `make run`.

Sets the balloon target (HMP `balloon`, in MiB), then polls
`query-balloon` until the guest's reported `actual` confirms the
inflate — `num_pages` stays latched in the device config, so this is
safe even when the guest hasn't probed the driver yet (a fixed sleep
raced guest boot once: the restore ran before the first config read
and the inflate was never seen). Then `balloon 1024` drives the
deflate path until `actual` returns to full RAM, so the run's
zero-leak gate still holds. Proofs land in /tmp/balloon_proof.log.
Exits when QEMU closes the socket.
"""
import json, socket, sys, time

SOCK = "/tmp/balloon-qmp.sock"
LOG = "/tmp/balloon_proof.log"
MIB = 1024 * 1024


def qmp(s, cmd):
    s.sendall((json.dumps(cmd) + "\r\n").encode())
    # QMP interleaves async events with command returns — keep
    # reading lines until a message with "return" or "error" lands.
    buf = b""
    while True:
        while b"\n" not in buf:
            chunk = s.recv(4096)
            if not chunk:
                raise OSError("peer closed")
            buf += chunk
        line, buf = buf.split(b"\n", 1)
        try:
            msg = json.loads(line)
        except ValueError:
            continue
        if "return" in msg or "error" in msg:
            return msg


def hmp(s, cmdline):
    return qmp(s, {
        "execute": "human-monitor-command",
        "arguments": {"command-line": cmdline},
    })


def actual_bytes(s):
    r = qmp(s, {"execute": "query-balloon"})
    return r.get("return", {}).get("actual")


def wait_actual(s, want, timeout_s):
    end = time.time() + timeout_s
    a = None
    while time.time() < end:
        a = actual_bytes(s)
        if a == want:
            return a, True
        time.sleep(0.25)
    return a, False


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
    s.settimeout(10)
    out = open(LOG, "w")
    try:
        s.recv(4096)  # greeting
        qmp(s, {"execute": "qmp_capabilities"})
        hmp(s, "balloon 1008")  # latched target: 4096 pages to inflate
        out.write("== balloon 1008 — waiting for guest inflate ==\n")
        a, ok = wait_actual(s, 1008 * MIB, 25)
        out.write(f"query-balloon actual={a} ({'inflated' if ok else 'TIMEOUT'})\n")
        hmp(s, "balloon 1024")
        out.write("== balloon 1024 — waiting for guest deflate ==\n")
        a, ok = wait_actual(s, 1024 * MIB, 25)
        out.write(f"query-balloon actual={a} ({'deflated' if ok else 'TIMEOUT'})\n")
        out.write(json.dumps(hmp(s, "info balloon")) + "\n")
    except OSError:
        pass
    out.close()
    s.close()


if __name__ == "__main__":
    main()
