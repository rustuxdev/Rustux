#!/usr/bin/env python3
"""mkgpt.py — build a GPT-partitioned test disk for the kernel's
partition scan: protective MBR, primary GPT header + entries with
real CRC32s, one Linux-filesystem partition at lba 2048 holding
the ext4 test image. Usage: mkgpt.py <out.img> <ext4.img>
"""
import struct, sys, zlib

SECTOR = 512
DISK_SECTORS = 32768  # 16 MiB, same as the MBR test disk
PART_LBA = 2048
# Linux filesystem data GUID (0FC63DAF-8483-4772-8E79-3D69D8477DE4),
# stored in GPT's mixed-endian byte order.
LINUX_FS_GUID = bytes.fromhex("af3dc60f838447728e793d69d8477de4")


def main() -> None:
    out, ext4 = sys.argv[1], sys.argv[2]
    ext4_data = open(ext4, "rb").read()
    part_sectors = (len(ext4_data) + SECTOR - 1) // SECTOR
    last_lba = PART_LBA + part_sectors - 1
    backup = DISK_SECTORS - 1

    # Partition entries: 128 x 128B at LBA 2 (sectors 2..33).
    entries = bytearray(128 * 128)
    e = bytearray(128)
    e[0:16] = LINUX_FS_GUID
    e[16:32] = bytes.fromhex("aaf03d4273a34b008b1e5c9e0a0f9c05")
    struct.pack_into("<QQ", e, 32, PART_LBA, last_lba)
    struct.pack_into("<Q", e, 48, 0)  # attrs
    e[56:56 + len("root".encode("utf-16-le"))] = "root".encode("utf-16-le")
    entries[0:128] = e
    entries_crc = zlib.crc32(bytes(entries))

    # GPT header at LBA 1.
    hdr = bytearray(SECTOR)
    hdr[0:8] = b"EFI PART"
    struct.pack_into("<I", hdr, 8, 0x10000)      # rev 1.0
    struct.pack_into("<I", hdr, 12, 92)         # header size
    struct.pack_into("<I", hdr, 20, 0)          # reserved
    struct.pack_into("<Q", hdr, 24, 1)          # my lba
    struct.pack_into("<Q", hdr, 32, backup)     # alternate lba
    struct.pack_into("<Q", hdr, 40, 34)         # first usable
    struct.pack_into("<Q", hdr, 48, backup - 33)  # last usable
    hdr[56:72] = bytes.fromhex("00112233445566778899aabbccddeeff")
    struct.pack_into("<Q", hdr, 72, 2)          # entries lba
    struct.pack_into("<I", hdr, 80, 128)        # num entries
    struct.pack_into("<I", hdr, 84, 128)        # entry size
    struct.pack_into("<I", hdr, 88, entries_crc)
    struct.pack_into(
        "<I", hdr, 16, zlib.crc32(bytes(hdr[:16] + b"\0\0\0\0" + hdr[20:92])))

    # Protective MBR at LBA 0.
    mbr = bytearray(SECTOR)
    mbr[446 + 4] = 0xEE
    struct.pack_into("<II", mbr, 446 + 8, 1, min(DISK_SECTORS - 1, 0xFFFFFFFF))
    mbr[510] = 0x55
    mbr[511] = 0xAA

    img = bytearray(DISK_SECTORS * SECTOR)
    img[0:SECTOR] = mbr
    img[SECTOR:2 * SECTOR] = hdr
    img[2 * SECTOR:2 * SECTOR + len(entries)] = entries
    img[PART_LBA * SECTOR:PART_LBA * SECTOR + len(ext4_data)] = ext4_data
    # Backup entries + header at the end (real disks carry them).
    img[(backup - 32) * SECTOR:backup * SECTOR] = entries[: 33 * SECTOR]
    bh = bytearray(hdr)
    struct.pack_into("<Q", bh, 24, backup)
    struct.pack_into("<Q", bh, 32, 1)
    struct.pack_into("<Q", bh, 72, backup - 32)
    struct.pack_into("<I", bh, 16, 0)
    struct.pack_into(
        "<I", bh, 16, zlib.crc32(bytes(bh[:16] + b"\0\0\0\0" + bh[20:92])))
    img[backup * SECTOR:(backup + 1) * SECTOR] = bh
    with open(out, "wb") as f:
        f.write(img)


if __name__ == "__main__":
    main()
