// ufftest — userfaultfd(323): real missing-page monitor.
// Flow: API handshake -> child registers its own pml4's range ->
// child faults (blocked) -> parent reads the uffd_msg -> UFFDIO_COPY
// resolves -> child resumes with the data. Phase 2: UNREGISTER +
// WAKE on a blocked faulter -> it re-faults -> SIGSEGV.
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static int fails;
static void check(int ok, const char *msg) {
    if (!ok) { fails++; printf("FAIL: %s\n", msg); }
}

#define UFFDIO_API        0xC018AA3F
#define UFFDIO_REGISTER   0xC020AA00
#define UFFDIO_UNREGISTER 0x8010AA01
#define UFFDIO_WAKE       0x8010AA02
#define UFFDIO_COPY       0xC028AA03
#define UFFDIO_ZEROPAGE   0xC020AA04

struct uffd_msg {                 // 32 bytes
    uint8_t event, r1; uint16_t r2; uint32_t r3;
    uint64_t pf_flags, pf_addr, r4;
};
struct uffdio_api { uint64_t api, features, ioctls; };
struct uffdio_range { uint64_t start, len; };
struct uffdio_register { struct uffdio_range range; uint64_t mode, ioctls; };
struct uffdio_copy { uint64_t dst, src, len, mode; int64_t copy; };
struct uffdio_zeropage { struct uffdio_range range; uint64_t mode; int64_t zeropage; };

static long uffd(long flags) { return syscall(323, flags); }

int main(void) {
    printf("uffdtest: begin\n");

    // --- surface checks ------------------------------------------------
    check(uffd(0x100) == -1 && errno == EINVAL, "create: bad flags EINVAL");
    int fd = (int)uffd(O_CLOEXEC); // blocking — exercises UffdRead
    check(fd >= 0, "userfaultfd create");
    check(read(fd, (char[64]){0}, 16) == -1 && errno == EINVAL,
          "read: short buffer EINVAL");
    check(ioctl(fd, UFFDIO_API,
                &(struct uffdio_api){ .api = 0xAA - 1 }) == -1
              && errno == EINVAL,
          "UFFDIO_API: wrong api EINVAL");
    check(ioctl(0, UFFDIO_API,
                &(struct uffdio_api){ .api = 0xAA }) == -1
              && errno == ENOTTY,
          "UFFDIO_API: non-uffd fd ENOTTY");
    struct uffdio_api ap = { .api = 0xAA };
    check(ioctl(fd, UFFDIO_API, &ap) == 0 && ap.api == 0xAA
              && (ap.ioctls & 0x1f) == 0x1f,
          "UFFDIO_API: handshake + ioctl mask");
    // Nonblock read on an empty ring -> EAGAIN.
    {
        int v = 1;
        ioctl(fd, FIONBIO, &v);
        check(read(fd, (char[64]){0}, 64) == -1 && errno == EAGAIN,
              "read: empty nonblock EAGAIN");
        v = 0;
        ioctl(fd, FIONBIO, &v);
    }
    // UFFD_NONBLOCK at create time -> same EAGAIN on an empty ring.
    {
        int nfd = (int)uffd(O_CLOEXEC | O_NONBLOCK);
        int rr = (int)read(nfd, (char[64]){0}, 64);
        check(nfd >= 0 && rr == -1 && errno == EAGAIN,
              "create: UFFD_NONBLOCK empty read EAGAIN");
        close(nfd);
    }
    check(ioctl(fd, UFFDIO_REGISTER,
                &(struct uffdio_register){ .range = {0x900000, 4096},
                                           .mode = 2 }) == -1
              && errno == EINVAL,
          "REGISTER: bad mode EINVAL");
    check(ioctl(fd, UFFDIO_REGISTER,
                &(struct uffdio_register){ .range = {0x900001, 4096},
                                           .mode = 1 }) == -1
              && errno == EINVAL,
          "REGISTER: unaligned EINVAL");

    // --- phase 1: child faults, parent COPYs ---------------------------
    // The blocking phases need a child slot — retry for headroom as
    // suite members exit; a still-full table skips (minimal always
    // has room) rather than deadlocking on read().
    pid_t p = -1;
    for (int i = 0; i < 300 && (p = fork()) < 0; i++) usleep(10 * 1000);
    if (p == 0) {
        // Reserve a VA window then free it — a registered-missing
        // uffd range must fault MAPERR (not-present), and our eager
        // PROT_NONE pages fault ACCERR instead.
        char *m = mmap(0, 8192, PROT_NONE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (m == MAP_FAILED) _exit(7);
        if (munmap(m, 8192) != 0) _exit(8);
        struct uffdio_register r = { .range = {(uint64_t)m, 8192},
                                     .mode = 1 };
        if (ioctl(fd, UFFDIO_REGISTER, &r) != 0) _exit(9);
        if ((r.ioctls & 0x1f) != 0x1f) _exit(10);
        volatile char c = m[0]; // read fault -> monitor COPYs "hello"
        if (c != 'h') _exit(11);
        m[4096] = 2; // write fault -> monitor ZEROPAGEs -> store lands
        if (m[4096] != 2) _exit(12);
        _exit(0);
    }
    if (p <= 0) {
        printf("uffdtest: SKIP blocking phases (task table full)\n");
        printf("uffdtest: %d failures\n", fails);
        _exit(fails);
    }
    struct uffd_msg msg;
    check(read(fd, &msg, 32) == 32 && msg.event == 0
              && (msg.pf_flags & 1) == 0,
          "read: PAGEFAULT read event lands");
    static char hello[4096] = "hello uffd world";
    struct uffdio_copy cp = { .dst = msg.pf_addr, .src = (uint64_t)hello,
                              .len = 4096 };
    check(ioctl(fd, UFFDIO_COPY, &cp) == 0 && cp.copy == 4096,
          "UFFDIO_COPY: resolves + wakes");
    struct uffd_msg msg2;
    check(read(fd, &msg2, 32) == 32 && msg2.event == 0
              && (msg2.pf_flags & 1) != 0,
          "read: PAGEFAULT write event lands");
    struct uffdio_zeropage zp = { .range = {msg2.pf_addr, 4096} };
    long zr = ioctl(fd, UFFDIO_ZEROPAGE, &zp);
    if (zr != 0 || zp.zeropage != 4096)
        printf("  zeropage: ret=%ld errno=%d zeropage=%ld addr=%lx\n",
               zr, errno, zp.zeropage, msg2.pf_addr);
    check(zr == 0 && zp.zeropage == 4096,
          "UFFDIO_ZEROPAGE: resolves + wakes");
    int st;
    waitpid(p, &st, 0);
    check(WIFEXITED(st) && WEXITSTATUS(st) == 0,
          "child: COPY data + ZEROPAGE zero visible");
    check(ioctl(fd, UFFDIO_COPY,
                &(struct uffdio_copy){ .dst = msg.pf_addr,
                                       .src = (uint64_t)hello,
                                       .len = 2048 }) == -1
              && errno == EINVAL,
          "UFFDIO_COPY: unaligned len EINVAL");
    check(ioctl(fd, UFFDIO_COPY,
                &(struct uffdio_copy){ .dst = 0x7fff0000,
                                       .src = (uint64_t)hello,
                                       .len = 4096 }) == -1
              && errno == EAGAIN,
          "UFFDIO_COPY: outside ranges EAGAIN");
    // UNREGISTER is mm-scoped like Linux — the parent's pml4 doesn't
    // own the child's range.
    check(ioctl(fd, UFFDIO_UNREGISTER,
                &(struct uffdio_range){ msg.pf_addr, 8192 }) == -1
              && errno == EINVAL,
          "UNREGISTER: foreign mm EINVAL");

    // --- phase 2: SIGKILL reaches a blocked faulter ---------------------
    pid_t p2 = -1;
    for (int i = 0; i < 300 && (p2 = fork()) < 0; i++) usleep(10 * 1000);
    if (p2 == 0) {
        char *m = mmap(0, 4096, PROT_NONE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (m == MAP_FAILED) _exit(7);
        if (munmap(m, 4096) != 0) _exit(8);
        struct uffdio_register r = { .range = {(uint64_t)m, 4096},
                                     .mode = 1 };
        if (ioctl(fd, UFFDIO_REGISTER, &r) != 0) _exit(9);
        m[0] = 1; // faults -> blocks on WaitOn::Uffd
        _exit(13); // unreachable while blocked
    }
    if (p2 < 0) {
        printf("uffdtest: SKIP phase 2 (task table full)\n");
        printf("uffdtest: %d failures\n", fails);
        _exit(fails);
    }
    struct uffd_msg msg3;
    check(read(fd, &msg3, 32) == 32 && msg3.event == 0,
          "read: phase-2 PAGEFAULT event lands");
    // The monitor can also UNREGISTER nothing here — the range is
    // mm-scoped to the child. A fatal signal must still reach the
    // blocked faulter (generic -EINTR wake + pick-time delivery).
    kill(p2, SIGKILL);
    int st2;
    waitpid(p2, &st2, 0);
    check(WIFSIGNALED(st2) && WTERMSIG(st2) == SIGKILL,
          "faulter: SIGKILL delivered while uffd-blocked");

    close(fd);
    printf("uffdtest: %d failures\n", fails);
    _exit(fails);
}
