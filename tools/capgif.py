#!/usr/bin/env python3
"""Capture a QEMU boot to an animated GIF via HMP monitor screendump polling.

Usage: capgif.py <out.gif> <qemu args...>
Launches qemu with a unix monitor socket headless (-display none), polls
screendump on the emulated GPU framebuffer, dedupes, writes a GIF.
"""
import os, socket, subprocess, sys, time, glob
from PIL import Image

MON = f"/tmp/capgif-mon.{os.getpid()}.sock"  # pid-random: a fixed name is squattable
FRD = "/tmp/capgif-frames"
POLL = 0.35        # seconds between screendump requests
MAXFRAMES = 900

def hmp(cmd):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(MON); s.settimeout(2)
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
    for f in glob.glob(FRD + "/*"): os.unlink(f)
    os.makedirs(FRD, exist_ok=True)
    if os.path.exists(MON): os.unlink(MON)
    cmd = ["qemu-system-x86_64",
           "-monitor", f"unix:{MON},server,nowait",
           "-display", "none"] + qargs
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    # wait for monitor socket
    for _ in range(100):
        if os.path.exists(MON): break
        time.sleep(0.1)
    frames = []
    n = 0
    try:
        while proc.poll() is None and n < MAXFRAMES:
            p = f"{FRD}/f{n:04d}.ppm"
            hmp(f"screendump {p}")
            if os.path.exists(p) and os.path.getsize(p) > 100:
                frames.append(p); n += 1
            time.sleep(POLL)
    finally:
        time.sleep(0.3)
        try: proc.terminate()
        except Exception: pass
    # final frame — the monitor socket is gone once QEMU exits
    try:
        p = f"{FRD}/f{n:04d}.ppm"; hmp(f"screendump {p}")
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
