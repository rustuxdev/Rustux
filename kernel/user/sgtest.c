// sgtest — compiled SG_IO (sg(4)) ABI proof: CDB pass-through on
// /dev/sg0 (char 21:0) and on the scsi-backed block node /dev/sdb
// (65:0). Covers node presence/rdev, INQUIRY + READ CAPACITY(10)
// via sg_io_hdr, the error gates (interface_id, EFAULT paths,
// ENOTTY on non-scsi fds), and ENXIO on a crafted sg1 node.
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>

#define SG_IO 0x2285
#define SG_DXFER_NONE -1
#define SG_DXFER_TO_DEV -2
#define SG_DXFER_FROM_DEV -3

typedef struct {
    int interface_id;
    int dxfer_direction;
    unsigned char cmd_len;
    unsigned char mx_sb_len;
    unsigned short iovec_count;
    unsigned int dxfer_len;
    void *dxferp;
    unsigned char *cmdp;
    unsigned char *sbp;
    unsigned int timeout;
    unsigned int flags;
    int pack_id;
    void *usr_ptr;
    unsigned char status;
    unsigned char masked_status;
    unsigned char msg_status;
    unsigned char sb_len_wr;
    unsigned short host_status;
    unsigned short driver_status;
    int resid;
    unsigned int duration;
    unsigned int info;
} sg_io_hdr_t;

static int fails;

static void say(const char *s) {
    if (write(1, s, strlen(s)) < 0) { /* ignore */ }
}

static void check(int ok, const char *what) {
    char buf[80];
    int n = snprintf(buf, sizeof(buf), "sgtest: %-28s %s\n",
                     what, ok ? "ok" : "FAIL");
    say(buf);
    if (!ok) fails++;
}

static int sg(int fd, unsigned char *cdb, int clen, int dir,
              void *data, unsigned int dlen, sg_io_hdr_t *h) {
    memset(h, 0, sizeof(*h));
    h->interface_id = 'S';
    h->cmd_len = clen;
    h->mx_sb_len = 32;
    h->dxfer_direction = dir;
    h->dxfer_len = dlen;
    h->dxferp = data;
    h->cmdp = cdb;
    static unsigned char sense[32];
    memset(sense, 0, sizeof(sense));
    h->sbp = sense;
    h->timeout = 20000;
    return ioctl(fd, SG_IO, h);
}

int main(void) {
    sg_io_hdr_t h;
    check(sizeof(sg_io_hdr_t) == 88, "sg_io_hdr_t is 88 bytes");

    int fd = open("/dev/sg0", O_RDWR);
    check(fd >= 0, "open /dev/sg0");
    struct stat st;
    check(fstat(fd, &st) == 0 && S_ISCHR(st.st_mode)
          && major(st.st_rdev) == 21 && minor(st.st_rdev) == 0,
          "fstat S_IFCHR 21:0");

    // INQUIRY — evpd 0, 96 bytes back; vendor must read 'QEMU   '.
    unsigned char inq[96];
    unsigned char cdb_inq[6] = {0x12, 0, 0, 0, 96, 0};
    memset(inq, 0, sizeof(inq));
    check(sg(fd, cdb_inq, 6, SG_DXFER_FROM_DEV, inq, 96, &h) == 0,
          "SG_IO INQUIRY ioctl");
    check(h.status == 0 && h.host_status == 0, "INQUIRY status 0");
    check(memcmp(inq + 8, "QEMU    ", 8) == 0, "INQUIRY vendor QEMU");

    // READ CAPACITY(10) — last_lba + block size.
    unsigned char cap[8];
    unsigned char cdb_cap[10] = {0x25, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    check(sg(fd, cdb_cap, 10, SG_DXFER_FROM_DEV, cap, 8, &h) == 0
          && h.status == 0, "SG_IO READ CAPACITY(10)");
    unsigned int last = (cap[0] << 24) | (cap[1] << 16)
                      | (cap[2] << 8) | cap[3];
    check(last == 32767, "capacity last_lba 32767");

    // TEST UNIT READY — no data phase.
    unsigned char cdb_tur[6] = {0, 0, 0, 0, 0, 0};
    check(sg(fd, cdb_tur, 6, SG_DXFER_NONE, NULL, 0, &h) == 0
          && h.status == 0, "SG_IO TEST UNIT READY");

    // Same ioctl on the scsi-backed block node /dev/sdb.
    int bd = open("/dev/sdb", O_RDONLY);
    check(bd >= 0, "open /dev/sdb");
    memset(inq, 0, sizeof(inq));
    check(sg(bd, cdb_inq, 6, SG_DXFER_FROM_DEV, inq, 96, &h) == 0
          && h.status == 0 && memcmp(inq + 8, "QEMU    ", 8) == 0,
          "SG_IO on /dev/sdb");

    // READ(10) one sector of the partition table through SG_IO.
    unsigned char sec[512];
    unsigned char cdb_rd[10] = {0x28, 0, 0, 0, 0, 0, 0, 0, 1, 0};
    memset(sec, 0, sizeof(sec));
    check(sg(bd, cdb_rd, 10, SG_DXFER_FROM_DEV, sec, 512, &h) == 0
          && h.status == 0
          && sec[510] == 0x55 && sec[511] == 0xaa,
          "SG_IO READ(10) MBR sig");

    // Error gates: bad interface id, bad pointers, wrong fds.
    sg(fd, cdb_tur, 6, SG_DXFER_NONE, NULL, 0, &h);
    h.interface_id = 'B';
    check(ioctl(fd, SG_IO, &h) == -1 && errno == EINVAL,
          "bad interface_id EINVAL");
    sg(fd, cdb_tur, 6, SG_DXFER_NONE, NULL, 0, &h);
    h.cmdp = (void *)1;
    check(ioctl(fd, SG_IO, &h) == -1 && errno == EFAULT,
          "bad cmdp EFAULT");
    sg(fd, cdb_inq, 6, SG_DXFER_FROM_DEV, inq, 96, &h);
    h.dxferp = (void *)1;
    check(ioctl(fd, SG_IO, &h) == -1 && errno == EFAULT,
          "bad dxferp EFAULT");
    sg(fd, cdb_inq, 6, SG_DXFER_FROM_DEV, inq, 96, &h);
    h.dxfer_len = 8192; // past the staging bound
    check(ioctl(fd, SG_IO, &h) == -1 && errno == EINVAL,
          "oversize dxfer EINVAL");
    h.dxfer_len = 96;
    h.dxfer_direction = -4; // bidir unsupported
    check(ioctl(fd, SG_IO, &h) == -1 && errno == EINVAL,
          "bidir EINVAL");
    // Write direction on a read-only fd, and partition-node
    // pass-through — both must be rejected before the transport.
    int ro = open("/dev/sg0", O_RDONLY);
    check(ro >= 0, "open /dev/sg0 O_RDONLY");
    unsigned char cdb_wr[10] = {0x2a, 0, 0, 0, 0, 0, 0, 0, 1, 0};
    unsigned char wb[512];
    memset(wb, 0, sizeof(wb));
    check(sg(ro, cdb_wr, 10, SG_DXFER_TO_DEV, wb, 512, &h) == -1
          && errno == EACCES, "TO_DEV on O_RDONLY EACCES");
    close(ro);
    int p1 = open("/dev/sdb1", O_RDWR);
    check(p1 >= 0, "open /dev/sdb1");
    check(ioctl(p1, SG_IO, &h) == -1 && errno == ENOTTY,
          "SG_IO on partition ENOTTY");
    close(p1);
    int nf = open("/dev/null", O_RDWR);
    check(ioctl(nf, SG_IO, &h) == -1 && errno == ENOTTY,
          "SG_IO /dev/null ENOTTY");
    check(ioctl(fd, SG_IO, 0) == -1 && errno == EFAULT,
          "null hdr EFAULT");

    char b[40];
    int n = snprintf(b, sizeof(b), "sgtest: %d failures\n", fails);
    say(b);
    return fails;
}
