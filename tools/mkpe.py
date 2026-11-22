#!/usr/bin/env python3
# Wrap a flat code blob into a minimal PE32+ (Windows x64) image:
# one .text section (R|W|X), no imports, no relocations. Enough for
# the Rustux NT personality to parse, map, and run — a real "MZ".
# Usage: mkpe.py <flat.bin> <out.exe>
import struct
import sys

FILE_ALIGN = 0x200
SECT_ALIGN = 0x1000
OPT_SIZE = 0xF0  # PE32+ optional header: 112 + 16 dirs * 8


def main():
    data = open(sys.argv[1], "rb").read()
    out = sys.argv[2]

    hdrs = 0x40 + 4 + 20 + OPT_SIZE + 40  # dos + sig + coff + opt + 1 sectab
    size_headers = (hdrs + FILE_ALIGN - 1) & ~(FILE_ALIGN - 1)
    raw = size_headers
    raw_len = (len(data) + FILE_ALIGN - 1) & ~(FILE_ALIGN - 1)
    vsize = len(data)
    sect_va = 0x1000
    size_image = sect_va + ((vsize + SECT_ALIGN - 1) & ~(SECT_ALIGN - 1))
    image_base = 0x140000000  # informational; kernel loads at its bias

    b = bytearray()
    # DOS header: MZ + e_lfanew @0x3c pointing at the PE signature.
    b += b"MZ" + bytes(0x3A) + struct.pack("<I", 0x40)
    b += b"PE\0\0"
    # COFF: AMD64, 1 section, executable, large-address-aware.
    b += struct.pack("<HHIIIHH", 0x8664, 1, 0, 0, 0, OPT_SIZE, 0x0022)
    opt = bytearray(OPT_SIZE)
    struct.pack_into("<H", opt, 0, 0x020B)       # Magic: PE32+
    struct.pack_into("<I", opt, 4, vsize)       # SizeOfCode
    struct.pack_into("<I", opt, 16, sect_va)    # AddressOfEntryPoint
    struct.pack_into("<I", opt, 20, sect_va)    # BaseOfCode
    struct.pack_into("<Q", opt, 24, image_base)
    struct.pack_into("<I", opt, 32, SECT_ALIGN)
    struct.pack_into("<I", opt, 36, FILE_ALIGN)
    struct.pack_into("<I", opt, 56, size_image)
    struct.pack_into("<I", opt, 60, size_headers)
    struct.pack_into("<H", opt, 68, 3)          # Subsystem: console
    struct.pack_into("<Q", opt, 72, 0x100000)   # SizeOfStackReserve
    struct.pack_into("<Q", opt, 80, 0x1000)     # SizeOfStackCommit
    struct.pack_into("<Q", opt, 88, 0x100000)   # SizeOfHeapReserve
    struct.pack_into("<Q", opt, 96, 0x1000)     # SizeOfHeapCommit
    struct.pack_into("<I", opt, 108, 16)        # NumberOfRvaAndSizes
    b += opt
    # Section header: .text, all permissions (test image — real
    # binaries split .text/.data and keep W^X).
    b += b".text\0\0\0"
    b += struct.pack("<IIIIIIHHI", vsize, sect_va, raw_len, raw,
                     0, 0, 0, 0, 0xE0000020)
    b += bytes(size_headers - len(b))
    b += data
    b += bytes(raw_len - len(data))
    open(out, "wb").write(b)


if __name__ == "__main__":
    main()
