// seltest — select(23) + msync(26) + getcpu(309) +
// sched_setattr/getattr(314/315) ABI proof. select is the
// timeval-timed pselect with remaining-time writeback; msync is
// validate-then-inert (eager private copies); sched_attr reports
// the fixed normal-class scheduler params.
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <sys/select.h>
#include <sys/mman.h>
#include <sys/time.h>

static int fails;
#define check(c, msg) do { \
    if (c) printf("seltest: %-36s ok\n", msg); \
    else { printf("seltest: %-36s FAIL\n", msg); fails++; } \
} while (0)

#ifndef SYS_select
#define SYS_select        23
#define SYS_msync         26
#define SYS_getcpu        309
#define SYS_sched_setattr 314
#define SYS_sched_getattr 315
#endif
#ifndef MS_ASYNC
#define MS_ASYNC      1
#define MS_INVALIDATE 2
#define MS_SYNC       4
#endif

struct sched_attr {
    uint32_t size, policy;
    uint64_t flags;
    int32_t  nice;
    uint32_t priority;
    uint64_t runtime, deadline, period;
};

int main(void) {
    printf("seltest: select + msync + getcpu + sched_attr checks\n");

    // ---- select(23) ----
    int p[2];
    check(pipe(p) == 0, "pipe minted");
    fd_set rset;
    struct timeval tv;
    FD_ZERO(&rset);
    FD_SET(p[0], &rset);
    tv.tv_sec = 0; tv.tv_usec = 200000;
    long r = syscall(SYS_select, p[0] + 1, &rset, 0, 0, &tv);
    check(r == 0, "select timeout no writer");
    check(tv.tv_sec == 0 && tv.tv_usec < 200000,
          "select remaining-time writeback");
    check(write(p[1], "x", 1) == 1, "pipe write");
    FD_ZERO(&rset);
    FD_SET(p[0], &rset);
    tv.tv_sec = 5; tv.tv_usec = 0;
    r = syscall(SYS_select, p[0] + 1, &rset, 0, 0, &tv);
    check(r == 1 && FD_ISSET(p[0], &rset), "select read ready");
    check(tv.tv_sec > 0 || tv.tv_usec > 0, "select keeps remainder");
    // NULL tv blocks-ready case is just an immediate readiness.
    FD_ZERO(&rset);
    FD_SET(p[0], &rset);
    r = syscall(SYS_select, p[0] + 1, &rset, 0, 0, 0);
    check(r == 1, "select NULL tv ready");
    errno = 0;
    tv.tv_sec = -1; tv.tv_usec = 0;
    FD_ZERO(&rset);
    r = syscall(SYS_select, 1, &rset, 0, 0, &tv);
    check(r < 0 && errno == EINVAL, "select negative tv EINVAL");
    tv.tv_sec = 0; tv.tv_usec = 1000000;
    errno = 0;
    r = syscall(SYS_select, 1, &rset, 0, 0, &tv);
    check(r < 0 && errno == EINVAL, "select usec>=1e6 EINVAL");
    errno = 0;
    r = syscall(SYS_select, 1, (void *)0x7f0000000000UL, 0, 0, 0);
    check(r < 0 && errno == EFAULT, "select bad rset EFAULT");
    close(p[0]); close(p[1]);

    // ---- msync(26) ----
    char *m = mmap(0, 0x4000, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    check(m != MAP_FAILED, "mmap 16K");
    m[0] = 1;
    errno = 0;
    check(syscall(SYS_msync, m + 1, 0x1000, MS_SYNC) < 0
          && errno == EINVAL, "msync unaligned EINVAL");
    errno = 0;
    check(syscall(SYS_msync, m, 0x1000, MS_SYNC | MS_ASYNC) < 0
          && errno == EINVAL, "msync SYNC|ASYNC EINVAL");
    errno = 0;
    check(syscall(SYS_msync, m, 0x1000, 8) < 0 && errno == EINVAL,
          "msync unknown flag EINVAL");
    check(syscall(SYS_msync, m, 0x4000, MS_SYNC) == 0,
          "msync committed range");
    check(syscall(SYS_msync, m, 0x4000, MS_INVALIDATE) == 0,
          "msync INVALIDATE ok");
    check(syscall(SYS_msync, m, 0, MS_SYNC) == 0, "msync len 0");
    errno = 0;
    check(syscall(SYS_msync, (void *)0x7f0000000000UL, 0x1000,
                  MS_SYNC) < 0 && errno == ENOMEM,
          "msync unmapped ENOMEM");

    // ---- getcpu(309) ----
    unsigned cpu = 9, node = 9;
    check(syscall(SYS_getcpu, &cpu, &node, 0) == 0
          && cpu == 0 && node == 0, "getcpu zeros");
    check(syscall(SYS_getcpu, 0, 0, 0) == 0, "getcpu NULLs ok");
    errno = 0;
    check(syscall(SYS_getcpu, (void *)0x7f0000000000UL, 0, 0) < 0
          && errno == EFAULT, "getcpu bad ptr EFAULT");

    // ---- sched_getattr(315) ----
    struct sched_attr sa;
    memset(&sa, 0xa5, sizeof sa);
    check(syscall(SYS_sched_getattr, 0, &sa, sizeof sa, 0) == 0,
          "sched_getattr self");
    check(sa.size >= 48 && sa.policy == 0 && sa.priority == 0,
          "getattr fixed OTHER params");
    errno = 0;
    check(syscall(SYS_sched_getattr, 0, &sa, 40, 0) < 0
          && errno == EINVAL, "getattr size<48 EINVAL");
    errno = 0;
    check(syscall(SYS_sched_getattr, 0, &sa, sizeof sa, 1) < 0
          && errno == EINVAL, "getattr flags EINVAL");
    errno = 0;
    check(syscall(SYS_sched_getattr, 0, (void *)0x7f0000000000UL,
                  48, 0) < 0 && errno == EFAULT,
          "getattr bad ptr EFAULT");
    errno = 0;
    check(syscall(SYS_sched_getattr, 0x7fffffff, &sa, sizeof sa,
                  0) < 0 && errno == ESRCH, "getattr dead pid ESRCH");

    // ---- sched_setattr(314) ----
    memset(&sa, 0, sizeof sa);
    sa.size = sizeof sa;
    sa.policy = 0; // SCHED_OTHER
    check(syscall(SYS_sched_setattr, 0, &sa, sizeof sa, 0) == 0,
          "setattr OTHER accepted");
    sa.policy = 2; // FIFO
    errno = 0;
    check(syscall(SYS_sched_setattr, 0, &sa, sizeof sa, 0) < 0
          && errno == EINVAL, "setattr FIFO EINVAL");
    sa.policy = 0; sa.nice = -30;
    errno = 0;
    check(syscall(SYS_sched_setattr, 0, &sa, sizeof sa, 0) < 0
          && errno == EINVAL, "setattr nice range EINVAL");
    sa.nice = 0; sa.priority = 5;
    errno = 0;
    check(syscall(SYS_sched_setattr, 0, &sa, sizeof sa, 0) < 0
          && errno == EINVAL, "setattr rt prio EINVAL");
    sa.priority = 0;
    errno = 0;
    check(syscall(SYS_sched_setattr, 0, &sa, sizeof sa, 4) < 0
          && errno == EINVAL, "setattr flags EINVAL");
    errno = 0;
    check(syscall(SYS_sched_setattr, 0, &sa, 40, 0) < 0
          && errno == EINVAL, "setattr size<48 EINVAL");
    errno = 0;
    check(syscall(SYS_sched_setattr, 0x7fffffff, &sa, sizeof sa,
                  0) < 0 && errno == ESRCH, "setattr dead pid ESRCH");

    printf("seltest: %d failures\n", fails);
    return fails;
}
