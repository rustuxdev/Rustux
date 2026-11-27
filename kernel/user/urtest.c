// urtest — io_uring(425-427): setup params/flags/EINVAL ladder,
// the three fixed mmap offsets, SQE->CQE synchronous completions
// (NOP/READ/WRITE/bad-op), eventfd notification, PROBE +
// REGISTER_BUFFERS ENXIO, EBADF on a non-uring fd.
#define _GNU_SOURCE
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/eventfd.h>
#include <sys/types.h>

static int fails;
static void check(int ok, const char *what) {
    if (!ok) {
        printf("FAIL: %s\n", what);
        fails++;
    }
}

static long uring_setup(unsigned entries, void *params) {
    return syscall(425, entries, params, 0, 0, 0, 0);
}
static long uring_enter(int fd, unsigned to_submit, unsigned min,
                        unsigned flags) {
    return syscall(426, fd, to_submit, min, flags, 0, 0);
}
static long uring_register(int fd, unsigned op, void *arg, unsigned n) {
    return syscall(427, fd, op, arg, n, 0);
}

// io_uring_params (120B) — only the fields we read back.
struct u_params {
    uint32_t sq_entries, cq_entries, flags, sq_thread_cpu,
             sq_thread_idle, features, wq_fd, resv[3];
    uint32_t sq_off[8];   // head,tail,mask,entries,flags,dropped,array,resv1
    uint64_t sq_resv2;
    uint32_t cq_off[6];   // head,tail,mask,entries,overflow,cqes
    uint64_t cq_resv[2];
};

struct sqe {
    uint8_t opcode, flags;
    uint16_t ioprio;
    int32_t fd;
    uint64_t off, addr;
    uint32_t len, rw_flags;
    uint64_t user_data;
    uint16_t buf_index, personality;
    int32_t splice_fd_in;
    uint64_t __pad2[2];
};

static void put_sqe(void *sqes, uint32_t i, uint8_t op, int32_t fd,
                    uint64_t off, uint64_t addr, uint32_t len,
                    uint32_t rwf, uint64_t ud) {
    struct sqe *s = (struct sqe *)((char *)sqes + i * 64);
    memset(s, 0, 64);
    s->opcode = op;
    s->fd = fd;
    s->off = off;
    s->addr = addr;
    s->len = len;
    s->rw_flags = rwf;
    s->user_data = ud;
}

static uint32_t rd32(void *p) { return *(volatile uint32_t *)p; }
static void wr32(void *p, uint32_t v) { *(volatile uint32_t *)p = v; }

int main(void) {
    printf("urtest: begin\n");
    struct u_params p;

    // ---------- EINVAL ladder ----------
    memset(&p, 0, sizeof(p));
    check(uring_setup(0, &p) == -1 && errno == EINVAL, "setup: 0 -> EINVAL");
    check(uring_setup(7, &p) == -1 && errno == EINVAL, "setup: !pow2 -> EINVAL");
    check(uring_setup(4096, &p) == -1 && errno == EINVAL, "setup: >256 -> EINVAL");
    p.flags = 1; // IORING_SETUP_IOPOLL
    check(uring_setup(8, &p) == -1 && errno == EINVAL, "setup: flags -> EINVAL");
    check(uring_setup(8, (void *)0x1) == -1 && errno == EFAULT,
          "setup: bad params -> EFAULT");

    // ---------- setup + params ----------
    memset(&p, 0, sizeof(p));
    int fd = (int)uring_setup(8, &p);
    check(fd >= 0, "setup: fd minted");
    if (fd < 0) goto out;
    check(p.sq_entries == 8 && p.cq_entries == 16, "setup: counts");
    check(p.sq_off[0] == 0 && p.sq_off[1] == 4 && p.sq_off[6] == 32,
          "setup: sq offsets");
    check(p.cq_off[0] == 0 && p.cq_off[1] == 4 && p.cq_off[5] == 32,
          "setup: cq offsets");

    // ---------- mmap the three fixed offsets ----------
    void *sq = mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    check(sq != MAP_FAILED, "mmap: sq ring");
    void *cq = mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd,
                    0x8000000);
    check(cq != MAP_FAILED, "mmap: cq ring");
    void *sqes = mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd,
                      0x10000000);
    check(sqes != MAP_FAILED, "mmap: sqes");
    check(mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0x4000)
              == MAP_FAILED && errno == ENODEV,
          "mmap: bad offset -> ENODEV");
    if (sq == MAP_FAILED || cq == MAP_FAILED || sqes == MAP_FAILED) {
        close(fd);
        goto out;
    }

    {
        // ---------- submit NOP + READ + NOP ----------
        int rfd = open("/motd.txt", O_RDONLY);
        check(rfd >= 0, "open motd");
        char buf[32];
        memset(buf, 0, sizeof(buf));
        uint32_t *arr = (uint32_t *)((char *)sq + 32);
        put_sqe(sqes, 0, 0, -1, 0, 0, 0, 0, 0xaaa);
        put_sqe(sqes, 1, 22, rfd, 0, (uint64_t)buf, 16, 0, 0xbbb);
        put_sqe(sqes, 2, 0, -1, 0, 0, 0, 0, 0xccc);
        arr[0] = 0; arr[1] = 1; arr[2] = 2;
        wr32((char *)sq + 4, 3); // sq.tail = 3

        long r = uring_enter(fd, 3, 0, 0);
        check(r == 3, "enter: submits 3");
        check(rd32((char *)sq + 0) == 3, "enter: sq head advanced");

        uint64_t ud; int32_t res;
        ud = *(uint64_t *)((char *)cq + 32);
        res = *(int32_t *)((char *)cq + 32 + 8);
        check(ud == 0xaaa && res == 0, "cqe0: NOP user_data+res");
        ud = *(uint64_t *)((char *)cq + 48);
        res = *(int32_t *)((char *)cq + 48 + 8);
        check(ud == 0xbbb && res == 16 && buf[0] == 'M',
              "cqe1: READ into buf, res=16");
        ud = *(uint64_t *)((char *)cq + 64);
        res = *(int32_t *)((char *)cq + 64 + 8);
        check(ud == 0xccc && res == 0, "cqe2: NOP");
        check(rd32((char *)cq + 4) == 3, "cq tail advanced");
        close(rfd);
    }

    // ---------- bad opcode completes EINVAL ----------
    {
        uint32_t *arr = (uint32_t *)((char *)sq + 32);
        put_sqe(sqes, 3, 99, -1, 0, 0, 0, 0, 0xddd);
        arr[3] = 3;
        wr32((char *)sq + 4, 4); // tail = 4 (head already 3)
        long r = uring_enter(fd, 1, 0, 0);
        check(r == 1, "enter: 1 more");
        uint32_t ct = rd32((char *)cq + 4);
        int32_t res = *(int32_t *)((char *)cq + 32 + 16 * (ct - 1) + 8);
        check(res == -EINVAL, "bad opcode -> cqe EINVAL");
    }

    // ---------- enter arg surface ----------
    {
        errno = 0;
        check(uring_enter(fd, 0, 0, 4) == -1 && errno == EINVAL,
              "enter: bad flags -> EINVAL");
        check(uring_enter(fd, 0, 0, 1) == 0,
              "enter: GETEVENTS harmless");
        errno = 0;
        check(uring_enter(0, 1, 0, 0) == -1 && errno == EBADF,
              "enter: non-uring fd -> EBADF");
    }

    // ---------- register: PROBE / EVENTFD / fixed-table ENXIO ----
    {
        unsigned char probe[8 + 24 * 8];
        memset(probe, 0, sizeof(probe));
        check(uring_register(fd, 8, probe, 24) == 0, "register: PROBE ok");
        check(probe[8 + 2] == 1 && probe[8 + 22 * 8 + 2] == 1
              && probe[8 + 23 * 8 + 2] == 1 && probe[8 + 5 * 8 + 2] == 0,
              "probe: supported-op flags");
        int efd = eventfd(0, 0);
        check(efd >= 0, "eventfd minted");
        check(uring_register(fd, 4, &efd, 1) == 0,
              "register: EVENTFD ok");
        errno = 0;
        check(uring_register(fd, 0, probe, 1) == -1 && errno == ENXIO,
              "register: BUFFERS -> ENXIO");
        errno = 0;
        check(uring_register(fd, 99, 0, 0) == -1 && errno == EINVAL,
              "register: bad opcode -> EINVAL");
        // submit one NOP; the eventfd count must bump by 1
        uint32_t *arr = (uint32_t *)((char *)sq + 32);
        uint32_t t = rd32((char *)sq + 4);
        put_sqe(sqes, 4, 0, -1, 0, 0, 0, 0, 0xeee);
        arr[4] = 4;
        wr32((char *)sq + 4, t + 1);
        check(uring_enter(fd, 1, 0, 0) == 1, "enter: eventfd batch");
        uint64_t cnt = 0;
        check(read(efd, &cnt, 8) == 8 && cnt == 1,
              "eventfd: +1 per cqe batch");
        check(uring_register(fd, 5, 0, 0) == 0, "register: UNREG_EFD");
        close(efd);
    }

    // ---------- poll: POLLIN while cq unread ----------
    {
        struct pollfd pf = { .fd = fd, .events = POLLIN };
        // cq head hasn't been consumed -> POLLIN asserted
        int r = poll(&pf, 1, 0);
        check(r == 1 && (pf.revents & POLLIN), "poll: cq POLLIN");
        // consume all cqes -> empty
        wr32((char *)cq + 0, rd32((char *)cq + 4));
        pf.revents = 0;
        r = poll(&pf, 1, 0);
        check(r == 0 || !(pf.revents & POLLIN), "poll: drained -> quiet");
    }

    // ---------- unmapped ring -> EINVAL ----------
    {
        struct u_params p2;
        memset(&p2, 0, sizeof(p2));
        int f2 = (int)uring_setup(8, &p2);
        check(f2 >= 0, "setup: second fd");
        errno = 0;
        check(uring_enter(f2, 1, 0, 0) == -1 && errno == EINVAL,
              "enter: unmapped rings -> EINVAL");
        close(f2);
    }

    close(fd);
out:
    printf("urtest: %d failures\n", fails);
    return fails;
}
