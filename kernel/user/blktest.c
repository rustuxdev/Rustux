// blktest — compiled block-device ABI proof: the /dev layer over the
// virtio-blk (major 254, /dev/vda) and NVMe (major 259,
// /dev/nvme0n1) transports. Covers open gates, stat/rdev, lseek
// SEEK_END capacity, the BLKGETSIZE/BLKSSZGET/BLKGETSIZE64 ioctl
// trio, pread/pwrite through the bounce-buffered byte interface,
// and an unaligned read-modify-write edge. Writes land at lba 64 —
// the MBR gap before the test image's ext4 partition, and QEMU runs
// -snapshot so the host image never changes. Same check()
// convention as iotest — exit status is the failure count.
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <linux/fs.h>

static int fails;

static void say(const char *s) {
    if (write(1, s, strlen(s)) < 0) { /* ignore */ }
}

static void check(int ok, const char *what) {
    char buf[80];
    int n = snprintf(buf, sizeof(buf), "blktest: %-28s %s\n",
                     what, ok ? "ok" : "FAIL");
    say(buf);
    if (!ok) fails++;
}

// Write a tag at lba 64, verify, restore the original bytes — the
// whole-disk write path's user-visible round trip.
static int rw_roundtrip(int fd, const char *tag) {
    char orig[512], pat[512], back[512];
    off_t off = 64 * 512;
    memset(pat, 0, sizeof(pat));
    memcpy(pat, tag, strlen(tag));
    if (pread(fd, orig, 512, off) != 512) return 0;
    if (pwrite(fd, pat, 512, off) != 512) return 0;
    if (pread(fd, back, 512, off) != 512) return 0;
    if (memcmp(back, pat, 512) != 0) return 0;
    if (pwrite(fd, orig, 512, off) != 512) return 0;
    if (pread(fd, back, 512, off) != 512) return 0;
    return memcmp(back, orig, 512) == 0;
}

int main(void) {
    struct stat st;
    char sec[512], edge[8];
    unsigned long long cap = 0;
    unsigned int sz = 0, secs = 0;
    int fd;

    // ---- /dev/vda (virtio-blk, major 254) ----
    fd = open("/dev/vda", O_RDWR);
    check(fd >= 0, "open vda");
    if (fd >= 0) {
        check(fstat(fd, &st) == 0 && S_ISBLK(st.st_mode)
              && major(st.st_rdev) == 254 && minor(st.st_rdev) == 0,
              "fstat S_IFBLK 254:0");
        check(lseek(fd, 0, SEEK_END) > 0, "SEEK_END capacity");
        check(ioctl(fd, BLKGETSIZE64, &cap) == 0 && cap > 0,
              "BLKGETSIZE64");
        check(ioctl(fd, BLKSSZGET, &sz) == 0 && sz == 512,
              "BLKSSZGET 512");
        check(ioctl(fd, BLKGETSIZE, &secs) == 0 && secs == cap / 512,
              "BLKGETSIZE sectors");
        check(pread(fd, sec, 512, 0) == 512
              && (unsigned char)sec[510] == 0x55
              && (unsigned char)sec[511] == 0xaa,
              "pread sector0 55AA");
        // Unaligned read crossing the sector boundary — the bounce
        // path must splice the two sectors cleanly.
        check(pread(fd, edge, 4, 510) == 4
              && (unsigned char)edge[0] == 0x55
              && (unsigned char)edge[1] == 0xaa,
              "pread edge splice");
        check(rw_roundtrip(fd, "vda-tag"), "pwrite/verify/restore");
        close(fd);
    }

    // ---- /dev/vda1 — the MBR partition node (254:1) ----
    fd = open("/dev/vda1", O_RDWR);
    check(fd >= 0, "open vda1");
    if (fd >= 0) {
        check(fstat(fd, &st) == 0 && S_ISBLK(st.st_mode)
              && major(st.st_rdev) == 254 && minor(st.st_rdev) == 1,
              "fstat S_IFBLK 254:1");
        check(ioctl(fd, BLKGETSIZE64, &cap) == 0 && cap > 0
              && cap < 64 * 1024 * 1024ULL,
              "part BLKGETSIZE64");
        // Partition offset 0 is the ext4 superblock page — the
        // 0xEF53 magic at +1080 (sb+56) proves the window starts
        // at the partition base, not the disk's.
        check(pread(fd, sec, 4, 1080) == 4
              && (unsigned char)sec[0] == 0x53
              && (unsigned char)sec[1] == 0xef,
              "pread ext4 magic");
        // Last sector of the partition — inside the window but
        // past the filesystem's structures on this test image.
        check(pread(fd, sec, 512, cap - 512) == 512,
              "pread last sector");
        close(fd);
    }

    // ---- /dev/nvme0n1 (NVMe, major 259) ----
    fd = open("/dev/nvme0n1", O_RDWR);
    check(fd >= 0, "open nvme0n1");
    if (fd >= 0) {
        check(fstat(fd, &st) == 0 && S_ISBLK(st.st_mode)
              && major(st.st_rdev) == 259 && minor(st.st_rdev) == 0,
              "fstat S_IFBLK 259:0");
        check(ioctl(fd, BLKGETSIZE64, &cap) == 0 && cap > 0,
              "BLKGETSIZE64");
        check(pread(fd, sec, 512, 0) == 512
              && (unsigned char)sec[510] == 0x55
              && (unsigned char)sec[511] == 0xaa,
              "pread sector0 55AA");
        check(rw_roundtrip(fd, "nvme-tag"), "pwrite/verify/restore");
        close(fd);
    }

    // ---- /dev/nvme0n2 — the second namespace (259:16) ----
    fd = open("/dev/nvme0n2", O_RDWR);
    check(fd >= 0, "open nvme0n2");
    if (fd >= 0) {
        check(fstat(fd, &st) == 0 && S_ISBLK(st.st_mode)
              && major(st.st_rdev) == 259 && minor(st.st_rdev) == 16,
              "fstat S_IFBLK 259:16");
        check(ioctl(fd, BLKGETSIZE64, &cap) == 0 && cap > 0,
              "ns2 BLKGETSIZE64");
        check(pread(fd, sec, 512, 0) == 512
              && (unsigned char)sec[510] == 0x55
              && (unsigned char)sec[511] == 0xaa,
              "ns2 pread sector0");
        check(rw_roundtrip(fd, "ns2-tag"), "ns2 pwrite/restore");
        close(fd);
    }

    // ---- /dev/nvme0n3 — the GPT-partitioned namespace (259:32) ----
    fd = open("/dev/nvme0n3", O_RDWR);
    check(fd >= 0, "open nvme0n3");
    if (fd >= 0) {
        check(fstat(fd, &st) == 0 && S_ISBLK(st.st_mode)
              && major(st.st_rdev) == 259 && minor(st.st_rdev) == 32,
              "fstat S_IFBLK 259:32");
        // Sector 0 carries the protective MBR, not a partition.
        check(pread(fd, sec, 512, 0) == 512
              && (unsigned char)sec[510] == 0x55
              && (unsigned char)sec[511] == 0xaa
              && (unsigned char)sec[446 + 4] == 0xee,
              "ns3 protective MBR");
        close(fd);
    }

    // ---- /dev/nvme0n3p1 — the GPT partition window (259:33) ----
    fd = open("/dev/nvme0n3p1", O_RDWR);
    check(fd >= 0, "open nvme0n3p1");
    if (fd >= 0) {
        check(fstat(fd, &st) == 0 && S_ISBLK(st.st_mode)
              && major(st.st_rdev) == 259 && minor(st.st_rdev) == 33,
              "fstat S_IFBLK 259:33");
        check(ioctl(fd, BLKGETSIZE64, &cap) == 0 && cap > 0,
              "gpt part BLKGETSIZE64");
        check(pread(fd, sec, 4, 1080) == 4
              && (unsigned char)sec[0] == 0x53
              && (unsigned char)sec[1] == 0xef,
              "gpt part ext4 magic");
        check(pread(fd, sec, 512, cap - 512) == 512,
              "gpt part last sector");
        close(fd);
    }
    // GPT minor 2 was never registered — the entry table holds
    // one partition, so p2 must ENXIO.
    check(mknod("n3p2.nod", S_IFBLK | 0600, makedev(259, 34)) == 0
          && open("n3p2.nod", O_RDWR) < 0 && errno == ENXIO,
          "gpt unregistered minor ENXIO");

    // ---- /dev/nvme0n1p1 — the NVMe partition node (259:1) ----
    fd = open("/dev/nvme0n1p1", O_RDWR);
    check(fd >= 0, "open nvme0n1p1");
    if (fd >= 0) {
        check(fstat(fd, &st) == 0 && S_ISBLK(st.st_mode)
              && major(st.st_rdev) == 259 && minor(st.st_rdev) == 1,
              "fstat S_IFBLK 259:1");
        check(ioctl(fd, BLKGETSIZE64, &cap) == 0 && cap > 0,
              "part BLKGETSIZE64");
        check(pread(fd, sec, 4, 1080) == 4
              && (unsigned char)sec[0] == 0x53
              && (unsigned char)sec[1] == 0xef,
              "pread ext4 magic");
        close(fd);
    }

    // ---- /dev/sdb — the virtio-scsi disk (major 65) ----
    fd = open("/dev/sdb", O_RDWR);
    check(fd >= 0, "open sdb");
    if (fd >= 0) {
        check(fstat(fd, &st) == 0 && S_ISBLK(st.st_mode)
              && major(st.st_rdev) == 65 && minor(st.st_rdev) == 0,
              "fstat S_IFBLK 65:0");
        check(ioctl(fd, BLKGETSIZE64, &cap) == 0 && cap > 0,
              "scsi BLKGETSIZE64");
        check(pread(fd, sec, 512, 0) == 512
              && (unsigned char)sec[510] == 0x55
              && (unsigned char)sec[511] == 0xaa,
              "scsi pread MBR sig");
        check(pread(fd, sec, 4, 2048 * 512 + 1080) == 4
              && (unsigned char)sec[0] == 0x53
              && (unsigned char)sec[1] == 0xef,
              "scsi ext4 magic");
        check(rw_roundtrip(fd, "scsi-tag"), "scsi pwrite/verify/restore");
        close(fd);
    }

    // ---- /dev/sdb1 — the scsi partition node (65:1) ----
    fd = open("/dev/sdb1", O_RDWR);
    check(fd >= 0, "open sdb1");
    if (fd >= 0) {
        check(fstat(fd, &st) == 0 && S_ISBLK(st.st_mode)
              && major(st.st_rdev) == 65 && minor(st.st_rdev) == 1,
              "fstat S_IFBLK 65:1");
        check(ioctl(fd, BLKGETSIZE64, &cap) == 0 && cap > 0,
              "scsi part BLKGETSIZE64");
        check(pread(fd, sec, 4, 1080) == 4
              && (unsigned char)sec[0] == 0x53
              && (unsigned char)sec[1] == 0xef,
              "scsi part ext4 magic");
        close(fd);
    }

    // A crafted partition node with no registered partition must
    // answer ENXIO — vda5 does not exist on the test disk.
    unlink("vda5.nod");
    check(mknod("vda5.nod", S_IFBLK | 0600, makedev(254, 5)) == 0,
          "mknod vda5");
    check(open("vda5.nod", O_RDONLY) < 0 && errno == ENXIO,
          "open vda5 -> ENXIO");
    unlink("vda5.nod");

    // ---- gate answers ----
    // A crafted vd node for a disk that doesn't exist must answer
    // ENXIO, like a driverless sd minor.
    unlink("vdb.nod");
    check(mknod("vdb.nod", S_IFBLK | 0600, makedev(254, 16)) == 0,
          "mknod vdb");
    check(open("vdb.nod", O_RDONLY) < 0 && errno == ENXIO,
          "open vdb -> ENXIO");
    unlink("vdb.nod");

    // Block ioctls on a character device are ENOTTY.
    fd = open("/dev/null", O_RDONLY);
    check(fd >= 0 && ioctl(fd, BLKGETSIZE64, &cap) < 0 && errno == ENOTTY,
          "BLKGETSIZE64 null ENOTTY");
    if (fd >= 0) close(fd);

    // ---- write-cache flush: BLKFLSBUF + fsync on block nodes ----
    fd = open("/dev/vda", O_RDWR);
    check(fd >= 0 && ioctl(fd, BLKFLSBUF, 0) == 0, "BLKFLSBUF vda");
    if (fd >= 0) {
        check(fsync(fd) == 0, "fsync vda");
        close(fd);
    }
    fd = open("/dev/nvme0n1", O_RDWR);
    check(fd >= 0 && ioctl(fd, BLKFLSBUF, 0) == 0, "BLKFLSBUF nvme0n1");
    if (fd >= 0) {
        check(fdatasync(fd) == 0, "fdatasync nvme0n1");
        close(fd);
    }
    // Same gate on a non-block node: ENOTTY, no hardware.
    fd = open("/dev/null", O_RDONLY);
    check(fd >= 0 && ioctl(fd, BLKFLSBUF, 0) < 0 && errno == ENOTTY,
          "BLKFLSBUF null ENOTTY");
    if (fd >= 0) close(fd);
    // And a node with no registered hardware: ENXIO.
    unlink("vdc.nod");
    check(mknod("vdc.nod", S_IFBLK | 0600, makedev(254, 32)) == 0,
          "mknod vdc");
    fd = open("vdc.nod", O_RDONLY);
    check(fd < 0 && errno == ENXIO, "open vdc -> ENXIO");
    if (fd >= 0) close(fd);
    unlink("vdc.nod");

    // ---- discard: BLKDISCARD/BLKSECDISCARD on real hardware ----
    {
        unsigned long long range[2] = {128 * 512, 4 * 512};
        fd = open("/dev/vda", O_RDWR);
        check(fd >= 0 && ioctl(fd, BLKDISCARD, range) == 0,
              "BLKDISCARD vda");
        if (fd >= 0) close(fd);
        fd = open("/dev/nvme0n1", O_RDWR);
        check(fd >= 0 && ioctl(fd, BLKDISCARD, range) == 0,
              "BLKDISCARD nvme0n1");
        if (fd >= 0) close(fd);
        // Sector-granular variant.
        unsigned long long srange[2] = {130, 2};
        fd = open("/dev/nvme0n1", O_RDWR);
        check(fd >= 0 && ioctl(fd, BLKSECDISCARD, srange) == 0,
              "BLKSECDISCARD nvme0n1");
        if (fd >= 0) close(fd);
        // Misaligned and zero-length ranges are EINVAL.
        unsigned long long bad[2] = {128 * 512 + 1, 4 * 512};
        fd = open("/dev/nvme0n1", O_RDWR);
        check(fd >= 0 && ioctl(fd, BLKDISCARD, bad) < 0
              && errno == EINVAL, "BLKDISCARD misalign EINVAL");
        if (fd >= 0) close(fd);
        unsigned long long zero[2] = {128 * 512, 0};
        fd = open("/dev/nvme0n1", O_RDWR);
        check(fd >= 0 && ioctl(fd, BLKDISCARD, zero) < 0
              && errno == EINVAL, "BLKDISCARD len0 EINVAL");
        if (fd >= 0) close(fd);
        // A transport without a discard path: EOPNOTSUPP.
        fd = open("/dev/sda", O_RDWR);
        check(fd >= 0 && ioctl(fd, BLKDISCARD, range) < 0
              && errno == EOPNOTSUPP, "BLKDISCARD sda EOPNOTSUPP");
        if (fd >= 0) close(fd);
        // And the non-block gate.
        fd = open("/dev/null", O_RDONLY);
        check(fd >= 0 && ioctl(fd, BLKDISCARD, range) < 0
              && errno == ENOTTY, "BLKDISCARD null ENOTTY");
        if (fd >= 0) close(fd);
    }

    char out[64];
    int n = snprintf(out, sizeof(out), "blktest: %d failure%s\n",
                     fails, fails == 1 ? "" : "s");
    say(out);
    return fails;
}
