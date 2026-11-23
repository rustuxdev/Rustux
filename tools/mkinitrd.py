#!/usr/bin/env python3
# Emit a newc ("070701") cpio archive to stdout.
# Usage: mkinitrd.py <file> <arcname> [<file> <arcname> ...]
# Format per entry: 110-byte ascii-hex header, NUL-terminated name,
# 4-align, data, 4-align; a TRAILER!!! record ends the archive.
import gzip
import os
import sys

# A .gz source is decompressed into the archive; used for PE binaries
# that host AV quarantines on sight (e.g. winheap.exe.gz -> "winheap").
def load(path):
    if path.endswith(".gz"):
        return gzip.open(path, "rb").read()
    return open(path, "rb").read()

def entry(name, data, ino, mode=0o100644):
    hdr = b"070701" + b"".join(b"%08x" % v for v in [
        ino, mode, 0, 0, 1, 0, len(data), 0, 1, 0, 0, len(name) + 1, 0])
    out = hdr + name.encode() + b"\0"
    out += b"\0" * ((4 - len(out) % 4) % 4)
    out += data + b"\0" * ((4 - len(data) % 4) % 4)
    return out

out = b""
ino = 1
for path, arc in zip(sys.argv[1::2], sys.argv[2::2]):
    # A "link:<target>" source emits a symlink entry — multicall
    # binaries (busybox) get their applet names without duplicating
    # the binary per alias.
    if path.startswith("link:"):
        out += entry(arc, path[5:].encode(), ino, 0o120777)
        ino += 1
        continue
    data = load(path)
    # Record the source's real perm bits — stat/access/exec on the
    # archive member honor them. ELF payloads get the exec bit
    # regardless (a quarantined .gz source may carry 0644).
    mode = os.stat(path).st_mode & 0o7777
    if data[:4] == b"\x7fELF":
        mode |= 0o111
    out += entry(arc, data, ino, 0o100000 | mode)
    ino += 1
out += entry("TRAILER!!!", b"", ino)
sys.stdout.buffer.write(out)
