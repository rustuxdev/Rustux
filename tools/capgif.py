#!/usr/bin/env python3
"""Capture a QEMU boot to an animated GIF via HMP monitor screendump polling.

Usage: capgif.py <out.gif> <qemu args...>
Launches qemu with a unix monitor socket headless (-display none), polls
screendump on the emulated GPU framebuffer, dedupes, writes a GIF.
"""
import os, socket, subprocess, sys, tempfile, time
from PIL import Image

POLL = 0.35        # seconds between screendump requests
MAXFRAMES = 900

def hmp(mon, cmd):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(mon); s.settimeout(2)
    # drain greeting
    try:
        s.recv(4096)
    except socket.timeout:
        pass
    s.sendall((cmd + "\n").encode())
    time.sleep(0.02)
    try:
        s.recv(65536)
    except socket.timeout:
        pass
    s.close()

def main():
    out = sys.argv[1]
    qargs = sys.argv[2:]
    # Private scratch dir (mode 0700): a shared predictable /tmp path
    # lets a local attacker plant symlinks that QEMU's screendump —
    # or our own reads — would follow into the invoker's files.
    frd = tempfile.mkdtemp(prefix="capgif-")
    mon = os.path.join(frd, "mon.sock")
    cmd = ["qemu-system-x86_64",
           "-monitor", f"unix:{mon},server,nowait",
           "-display", "none"] + qargs
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    # wait for monitor socket
    for _ in range(100):
        if os.path.exists(mon): break
        time.sleep(0.1)
    frames = []
    n = 0
    try:
        while proc.poll() is None and n < MAXFRAMES:
            p = f"{frd}/f{n:04d}.ppm"
            hmp(mon, f"screendump {p}")
            if os.path.exists(p) and os.path.getsize(p) > 100:
                frames.append(p); n += 1
            time.sleep(POLL)
    finally:
        time.sleep(0.3)
        try: proc.terminate()
        except Exception: pass
    # final frame — the monitor socket is gone once QEMU exits
    try:
        p = f"{frd}/f{n:04d}.ppm"; hmp(mon, f"screendump {p}")
        if os.path.exists(p) and os.path.getsize(p) > 100: frames.append(p)
    except OSError:
        pass

    imgs, last = [], None
    for fp in frames:
        im = Image.open(fp).convert("RGB")
        if im.tobytes() == last: continue
        last = im.tobytes()
        imgs.append(im)
    if not imgs:
        print("no frames captured"); sys.exit(1)
    # hold the last frame longer so the summary is readable
    dur = [350] * len(imgs); dur[-1] = 4000
    q = [im.quantize(colors=256, method=Image.MEDIANCUT) for im in imgs]
    q[0].save(out, save_all=True, append_images=q[1:], duration=dur,
              loop=0, optimize=True)
    print(f"{out}: {len(imgs)} frames, {os.path.getsize(out)} bytes")

if __name__ == "__main__":
    main()
