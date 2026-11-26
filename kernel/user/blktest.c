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

    char out[64];
    int n = snprintf(out, sizeof(out), "blktest: %d failure%s\n",
                     fails, fails == 1 ? "" : "s");
    say(out);
    return fails;
}
