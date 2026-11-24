#!/usr/bin/env python3
"""Capture a QEMU session to an animated GIF via HMP monitor screendump polling.

Usage: capgif.py <out.gif> [options] -- <qemu args...>
       capgif.py <out.gif> <qemu args...>          (legacy form)

Options:
  --seconds N     wall-clock capture length (default: run until QEMU exits)
  --poll S        delay between screendump requests (default 0.02)
  --fps F         playback speed: GIF frame duration = 1000/F ms (default 12)
  --size WxH      resize every frame (nearest neighbor — keeps pixel-art crisp)
  --crop X,Y,W,H  crop before resizing
  --maxframes N   stop after N accepted frames (default 4000)
  --skip N        drop the first N unique frames (skip boot noise)

A single persistent monitor connection is kept open; screendump latency is
~50 ms for a 1280x800 framebuffer, so --poll 0.02 yields ~15-18 fps capture.
PNG dumps (QEMU >= 7.1) are used when available — ~10x smaller than PPM.
"""
import os, shutil, socket, subprocess, sys, tempfile, time
from PIL import Image

def parse_size(s):
    w, h = s.lower().split("x")
    return int(w), int(h)

class Mon:
    """Persistent HMP connection. Reads until the '(qemu) ' prompt so each
    command is synchronous — when it returns, the screendump file is done."""
    def __init__(self, path):
        self.s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.s.connect(path)
        self.s.settimeout(10)
        self.buf = b""
        self._prompt()          # consume greeting + first prompt
    def _prompt(self):
        while b"(qemu) " not in self.buf:
            self.buf += self.s.recv(65536)
        # keep anything after the prompt (partial echo of next cmd)
        _, _, self.buf = self.buf.rpartition(b"(qemu) ")
    def cmd(self, c):
        self.s.sendall((c + "\n").encode())
        self._prompt()

def main():
    argv = sys.argv[1:]
    if not argv:
        print(__doc__); sys.exit(2)
    out = argv[0]; argv = argv[1:]
    seconds = 0.0; poll = 0.02; fps = 12.0; size = None; crop = None
    maxframes = 4000; skip = 0
    qargs = []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--":
            qargs = argv[i + 1:]; break
        elif a.startswith("--"):
            v = argv[i + 1]; i += 1
            if a == "--seconds": seconds = float(v)
            elif a == "--poll": poll = float(v)
            elif a == "--fps": fps = float(v)
            elif a == "--size": size = parse_size(v)
            elif a == "--crop": crop = tuple(int(x) for x in v.split(","))
            elif a == "--maxframes": maxframes = int(v)
            elif a == "--skip": skip = int(v)
            else: print(f"unknown option {a}"); sys.exit(2)
        else:
            qargs = argv[i:]; break          # legacy: rest = qemu args
        i += 1
    if not qargs:
        print("no qemu args"); sys.exit(2)

    # Private scratch dir: a shared predictable /tmp path lets a local
    # attacker plant symlinks QEMU's screendump would follow.
    frd = tempfile.mkdtemp(prefix="capgif-", dir="/dev/shm"
                           if os.path.isdir("/dev/shm") else None)
    mon_path = os.path.join(frd, "mon.sock")
    cmd = ["qemu-system-x86_64",
           "-monitor", f"unix:{mon_path},server,nowait",
           "-display", "none"] + qargs
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                            stderr=subprocess.STDOUT)
    for _ in range(200):
        if os.path.exists(mon_path): break
        time.sleep(0.1)
    mon = Mon(mon_path)

    # probe PNG screendump support once
    probe = f"{frd}/probe.png"
    try:
        mon.cmd(f"screendump {probe} -f png")
        use_png = os.path.exists(probe) and os.path.getsize(probe) > 100
    except Exception:
        use_png = False
    ext = "png" if use_png else "ppm"

    frames, stamps = [], []
    n = 0
    t0 = time.monotonic()
    try:
        while proc.poll() is None and n < maxframes:
            if seconds and time.monotonic() - t0 > seconds:
                break
            p = f"{frd}/f{n:05d}.{ext}"
            mon.cmd(f"screendump {p}" + (" -f png" if use_png else ""))
            if os.path.exists(p) and os.path.getsize(p) > 100:
                frames.append(p); stamps.append(time.monotonic())
                n += 1
            time.sleep(poll)
    except (socket.timeout, ConnectionResetError, BrokenPipeError):
        pass
    finally:
        try: proc.terminate(); proc.wait(5)
        except Exception:
            try: proc.kill()
            except Exception: pass

    imgs, deltas, last, last_t = [], [], None, None
    for fp, ts in zip(frames, stamps):
        im = Image.open(fp).convert("RGB")
        b = im.tobytes()
        if b == last: continue
        last = b
        if last_t is not None:
            deltas.append(ts - last_t)
        last_t = ts
        imgs.append(im)
    del imgs[:skip]
    if not imgs:
        print("no frames captured"); sys.exit(1)

    if crop:
        imgs = [im.crop((crop[0], crop[1], crop[0] + crop[2], crop[1] + crop[3]))
                for im in imgs]
    # letterbox mixed-size frames (VGA text screen vs GOP mode)
    w = max(im.width for im in imgs); h = max(im.height for im in imgs)
    imgs = [im if (im.width, im.height) == (w, h) else _lb(im, w, h)
            for im in imgs]
    if size and (w, h) != size:
        imgs = [im.resize(size, Image.NEAREST) for im in imgs]

    dur = int(1000 / fps)
    durlist = [dur] * len(imgs); durlist[-1] = 3000
    q = [im.quantize(colors=256, method=Image.MEDIANCUT) for im in imgs]
    q[0].save(out, save_all=True, append_images=q[1:], duration=durlist,
              loop=0, optimize=True)
    print(f"{out}: {len(imgs)} frames, {os.path.getsize(out)} bytes"
          f" ({1/(sum(deltas)/max(len(deltas),1)):.1f} fps capture)")

def _lb(im, w, h):
    c = Image.new("RGB", (w, h)); c.paste(im, (0, 0)); return c

if __name__ == "__main__":
    main()
