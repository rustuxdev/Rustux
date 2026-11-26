// nvmtest — compiled NVMe pass-through ABI proof:
// NVME_IOCTL_ADMIN_CMD (0x41B5) on /dev/nvme0 (char 243) and
// NVME_IOCTL_IO_CMD (0x41B7) on /dev/nvme0n1 (block 259:0).
// Covers IDENTIFY controller + namespace, a READ through the I/O
// queue, and the gate set (ENOTTY/EACCES/EINVAL/EFAULT).
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>

#define NVME_IOCTL_ADMIN_CMD 0x41B5
#define NVME_IOCTL_IO_CMD    0x41B7

struct nvme_passthru_cmd {
    unsigned char opcode;
    unsigned char flags;
    unsigned short rsvd1;
    unsigned int nsid;
    unsigned int cdw2;
    unsigned int cdw3;
    unsigned long long metadata;
    unsigned long long addr;
    unsigned int metadata_len;
    unsigned int data_len;
    unsigned int cdw10;
    unsigned int cdw11;
    unsigned int cdw12;
    unsigned int cdw13;
    unsigned int cdw14;
    unsigned int cdw15;
    unsigned int timeout_ms;
    unsigned int result;
};

static int fails;

static void say(const char *s) {
    if (write(1, s, strlen(s)) < 0) { /* ignore */ }
}

static void check(int ok, const char *what) {
    char buf[80];
    int n = snprintf(buf, sizeof(buf), "nvmtest: %-30s %s\n",
                     what, ok ? "ok" : "FAIL");
    say(buf);
    if (!ok) fails++;
}

static int pass(int fd, unsigned long req, struct nvme_passthru_cmd *c) {
    c->timeout_ms = 1000;
    return ioctl(fd, req, c);
}

int main(void) {
    struct nvme_passthru_cmd c;
    check(sizeof(struct nvme_passthru_cmd) == 72, "passthru cmd 72B");

    int fd = open("/dev/nvme0", O_RDWR);
    check(fd >= 0, "open /dev/nvme0");
    struct stat st;
    check(fstat(fd, &st) == 0 && S_ISCHR(st.st_mode)
          && major(st.st_rdev) == 243 && minor(st.st_rdev) == 0,
          "fstat S_IFCHR 243:0");

    // IDENTIFY controller — opcode 0x06, nsid 0, CNS=1 in cdw10.
    unsigned char id[4096];
    memset(id, 0, sizeof(id));
    memset(&c, 0, sizeof(c));
    c.opcode = 0x06;
    c.cdw10 = 1;
    c.addr = (unsigned long long)id;
    c.data_len = 4096;
    check(pass(fd, NVME_IOCTL_ADMIN_CMD, &c) == 0, "IDENTIFY ctrl");
    check((id[0] | id[1] << 8) == 0x1b36, "vendor id 0x1b36");
    check(memcmp(id + 4, "nv0", 3) == 0, "serial nv0");

    // IDENTIFY namespace 1 — nsid 1, CNS=0.
    memset(id, 0, sizeof(id));
    memset(&c, 0, sizeof(c));
    c.opcode = 0x06;
    c.nsid = 1;
    c.cdw10 = 0;
    c.addr = (unsigned long long)id;
    c.data_len = 4096;
    check(pass(fd, NVME_IOCTL_ADMIN_CMD, &c) == 0, "IDENTIFY nsid 1");
    unsigned long long nsze;
    memcpy(&nsze, id, 8);
    check(nsze == 32768, "nsze 32768");

    // Same command through the block node — whole-disk only.
    int bd = open("/dev/nvme0n1", O_RDWR);
    check(bd >= 0, "open /dev/nvme0n1");
    memset(&c, 0, sizeof(c));
    c.opcode = 0x06;
    c.cdw10 = 1;
    c.addr = (unsigned long long)id;
    c.data_len = 4096;
    check(pass(bd, NVME_IOCTL_ADMIN_CMD, &c) == 0
          && memcmp(id + 4, "nv0", 3) == 0, "ADMIN_CMD on nvme0n1");

    // NVME_IOCTL_IO_CMD READ — opcode 0x02 on the ns node; lba 0,
    // one sector -> MBR signature at 510.
    unsigned char sec[512];
    memset(sec, 0, sizeof(sec));
    memset(&c, 0, sizeof(c));
    c.opcode = 0x02;
    c.addr = (unsigned long long)sec;
    c.data_len = 512;
    c.cdw10 = 0;            // slba low
    c.cdw11 = 0;            // slba high
    c.cdw12 = 0;            // nlb-1 = 0 -> 1 block
    check(pass(bd, NVME_IOCTL_IO_CMD, &c) == 0
          && sec[510] == 0x55 && sec[511] == 0xaa,
          "IO_CMD READ MBR sig");

    // Gates: partition node, read-only fd, bad fields, wrong fd.
    int p1 = open("/dev/nvme0n1p1", O_RDWR);
    check(p1 >= 0, "open /dev/nvme0n1p1");
    check(pass(p1, NVME_IOCTL_ADMIN_CMD, &c) == -1
          && errno == ENOTTY, "partition node ENOTTY");
    close(p1);
    int ro = open("/dev/nvme0", O_RDONLY);
    check(ro >= 0, "open /dev/nvme0 O_RDONLY");
    memset(&c, 0, sizeof(c));
    c.opcode = 0x06;
    c.cdw10 = 1;
    c.addr = (unsigned long long)id;
    c.data_len = 4096;
    check(pass(ro, NVME_IOCTL_ADMIN_CMD, &c) == -1
          && errno == EACCES, "read-only fd EACCES");
    close(ro);
    c.data_len = 8192;
    check(pass(fd, NVME_IOCTL_ADMIN_CMD, &c) == -1
          && errno == EINVAL, "oversize data EINVAL");
    c.data_len = 4096;
    c.addr = 1;
    check(pass(fd, NVME_IOCTL_ADMIN_CMD, &c) == -1
          && errno == EFAULT, "bad addr EFAULT");
    c.addr = 0;
    check(pass(fd, NVME_IOCTL_ADMIN_CMD, &c) == -1
          && errno == EFAULT, "null addr EFAULT");
    c.data_len = 0;
    check(pass(fd, NVME_IOCTL_IO_CMD, &c) == -1
          && errno == ENOTTY, "IO_CMD on ctrl ENOTTY");
    int nf = open("/dev/null", O_RDWR);
    check(pass(nf, NVME_IOCTL_ADMIN_CMD, &c) == -1
          && errno == ENOTTY, "SG-less fd ENOTTY");
    close(nf);
    check(ioctl(fd, NVME_IOCTL_ADMIN_CMD, 0) == -1
          && errno == EFAULT, "null cmd EFAULT");

    char b[40];
    int n = snprintf(b, sizeof(b), "nvmtest: %d failures\n", fails);
    say(b);
    return fails;
}
