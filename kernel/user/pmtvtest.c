// pmtvtest — process_madvise(440) + mlock family (149-152, 325)
// proof. process_madvise takes a pidfd + iovec list and counts
// committed-overlap bytes per range (holes advise nothing). Our
// advice set is inert, so the ABI surface under test is the gate
// ladder + byte accounting. mlock pins nothing physically here
// (no eviction) but its ENOMEM-on-unmapped gate is real.
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>

static int fails;
#define check(c, msg) do { \
    if (c) printf("pmtvtest: %-34s ok\n", msg); \
    else { printf("pmtvtest: %-34s FAIL\n", msg); fails++; } \
} while (0)

#ifndef SYS_mlock
#define SYS_mlock    149
#endif
#define SYS_munlock      150
#define SYS_mlockall     151
#define SYS_munlockall   152
#define SYS_mlock2       325
#define SYS_process_madvise 440
#define SYS_pidfd_open   434
#define MADV_COLD        20
#define MADV_PAGEOUT     21
#define MADV_COLLAPSE    25
#define MCL_ONFAULT      4
#define MLOCK_ONFAULT    1

int main(void) {
    printf("pmtvtest: process_madvise + mlock checks\n");
    char *a = mmap(0, 0x10000, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    check(a != MAP_FAILED, "mmap 64K");
    a[0] = 1; a[0x8000] = 2; // fault some pages in

    // ---- mlock(149) ----
    check(mlock(a, 0x8000) == 0, "mlock committed");
    errno = 0;
    // 0x7f00.. is inside user VA but nothing ever maps it — a real
    // hole (PROT_NONE would still be a committed VMA).
    char *hole = (char *)0x7f0000000000UL;
    check(mlock(a, 0) == 0, "mlock len 0");
    errno = 0;
    check(mlock(hole, 0x1000) < 0 && errno == ENOMEM,
          "mlock uncommitted ENOMEM");
    // unaligned addr rounds down — still committed
    check(mlock(a + 0x123, 0x1000) == 0, "mlock unaligned rounds");

    // ---- mlock2(325) ----
    errno = 0;
    check(syscall(SYS_mlock2, a, 0x1000, 0x40) < 0 && errno == EINVAL,
          "mlock2 bad flags EINVAL");
    check(syscall(SYS_mlock2, a, 0x1000, MLOCK_ONFAULT) == 0,
          "mlock2 ONFAULT ok");

    // ---- mlockall/munlockall(151/152) ----
    errno = 0;
    check(mlockall(0x8) < 0 && errno == EINVAL,
          "mlockall bad flags EINVAL");
    check(mlockall(1 | 2 | MCL_ONFAULT) == 0, "mlockall all flags");
    check(munlockall() == 0, "munlockall");

    // ---- munlock(150) ----
    check(munlock(a, 0x1000) == 0, "munlock committed");
    errno = 0;
    check(munlock(hole, 0x1000) < 0 && errno == ENOMEM,
          "munlock uncommitted ENOMEM");

    // ---- process_madvise(440) gates ----
    int self = syscall(SYS_pidfd_open, getpid(), 0);
    check(self > 0, "pidfd_open self");
    struct iovec iov = { .iov_base = a, .iov_len = 0x8000 };
    errno = 0;
    check(syscall(SYS_process_madvise, self, &iov, 1, MADV_COLD, 1) < 0
          && errno == EINVAL, "pmadv flags EINVAL");
    errno = 0;
    check(syscall(SYS_process_madvise, self, &iov, 1, 4 /*DONTNEED*/,
                  0) < 0 && errno == EINVAL, "pmadv bad advice EINVAL");
    errno = 0;
    check(syscall(SYS_process_madvise, self, &iov, 1025, MADV_COLD, 0)
          < 0 && errno == EINVAL, "pmadv iovcnt>1024 EINVAL");
    errno = 0;
    check(syscall(SYS_process_madvise, self, 0, 1, MADV_COLD, 0) < 0
          && errno == EINVAL, "pmadv NULL iov EINVAL");
    errno = 0;
    check(syscall(SYS_process_madvise, 0, &iov, 1, MADV_COLD, 0) < 0
          && errno == EBADF, "pmadv non-pidfd EBADF");
    errno = 0;
    check(syscall(SYS_process_madvise, self, (void *)1, 1, MADV_COLD,
                  0) < 0 && errno == EFAULT, "pmadv iov EFAULT");
    check(syscall(SYS_process_madvise, self, 0, 0, MADV_COLD, 0) == 0,
          "pmadv iovcnt 0 -> 0");

    // ---- process_madvise byte accounting ----
    check(syscall(SYS_process_madvise, self, &iov, 1, MADV_COLD, 0)
          == 0x8000, "pmadv counts committed bytes");
    // unaligned iov EINVAL
    struct iovec bad = { .iov_base = a + 1, .iov_len = 0x1000 };
    errno = 0;
    check(syscall(SYS_process_madvise, self, &bad, 1, MADV_COLD, 0)
          < 0 && errno == EINVAL, "pmadv unaligned iov EINVAL");
    // holes advise nothing — iov over unmapped VA counts 0
    struct iovec h = { .iov_base = hole, .iov_len = 0x1000 };
    check(syscall(SYS_process_madvise, self, &h, 1, MADV_COLD, 0) == 0,
          "pmadv hole counts 0");
    // mixed iov list: committed + hole + committed
    struct iovec list[3] = {
        { a, 0x4000 }, { hole, 0x1000 }, { a + 0x4000, 0x4000 },
    };
    check(syscall(SYS_process_madvise, self, list, 3, MADV_PAGEOUT,
                  0) == 0x8000,
          "pmadv list skips holes");

    // ---- dead target ESRCH: a zombie still has a task slot (so
    // pidfd_open succeeds) but no live mm — pmadv ESRCHs.
    pid_t c = fork();
    if (c == 0) _exit(0);
    usleep(200000); // let the child die
    int dead = syscall(SYS_pidfd_open, c, 0);
    check(dead > 0, "pidfd_open zombie child");
    errno = 0;
    check(syscall(SYS_process_madvise, dead, &iov, 1, MADV_COLD, 0)
          < 0 && errno == ESRCH, "pmadv dead target ESRCH");
    close(dead);
    waitpid(c, 0, 0); // reap now
    close(self);

    printf("pmtvtest: %d failure(s)\n", fails);
    return fails;
}
