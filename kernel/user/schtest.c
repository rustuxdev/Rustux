// schtest — sched policy gates (142-148) + ioprio (251/252) +
// readahead(187) + tkill(200) + NUMA policy (237/238/239).
// All are validation gates over an inert single-policy core:
// SCHED_OTHER-only kernel, so the checks are the errno ladder.
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <sched.h>

static int fails;
#define check(c, msg) do { \
    if (c) printf("schtest: %-40s ok\n", msg); \
    else { printf("schtest: %-40s FAIL\n", msg); fails++; } \
} while (0)

#ifndef SYS_sched_setparam
#define SYS_sched_setparam        142
#define SYS_sched_getparam        143
#define SYS_sched_setscheduler    144
#define SYS_sched_getscheduler    145
#define SYS_sched_get_priority_max 146
#define SYS_sched_get_priority_min 147
#define SYS_sched_rr_get_interval 148
#define SYS_readahead             187
#define SYS_tkill                 200
#define SYS_mbind                 237
#define SYS_set_mempolicy         238
#define SYS_get_mempolicy         239
#define SYS_ioprio_set            251
#define SYS_ioprio_get            252
#endif

int main(void) {
    printf("schtest: sched + ioprio + readahead + tkill + numa\n");

    // --- sched_setparam/getparam
    int pri = 0;
    errno = 0;
    check(syscall(SYS_sched_setparam, 0, &pri) == 0,
          "setparam self pri 0");
    pri = 5;
    errno = 0;
    long r = syscall(SYS_sched_setparam, 0, &pri);
    check(r == -1 && errno == EINVAL, "setparam pri!=0 EINVAL");
    errno = 0;
    r = syscall(SYS_sched_setparam, 999999, &pri);
    check(r == -1 && errno == ESRCH, "setparam dead pid ESRCH");
    errno = 0;
    r = syscall(SYS_sched_setparam, 0, (void *)0x100);
    check(r == -1 && errno == EFAULT, "setparam bad ptr EFAULT");
    pri = 99;
    check(syscall(SYS_sched_getparam, 0, &pri) == 0 && pri == 0,
          "getparam writes {0}");
    errno = 0;
    r = syscall(SYS_sched_getparam, 999999, &pri);
    check(r == -1 && errno == ESRCH, "getparam dead pid ESRCH");
    errno = 0;
    r = syscall(SYS_sched_getparam, 0, (void *)0x100);
    check(r == -1 && errno == EFAULT, "getparam bad ptr EFAULT");

    // --- sched_setscheduler/getscheduler
    pri = 0;
    errno = 0;
    check(syscall(SYS_sched_setscheduler, 0, 0, &pri) == 0,
          "setscheduler OTHER ok");
    errno = 0;
    r = syscall(SYS_sched_setscheduler, 0, 1, &pri); // FIFO
    check(r == -1 && errno == EINVAL, "setscheduler FIFO EINVAL");
    errno = 0;
    r = syscall(SYS_sched_setscheduler, 999999, 0, &pri);
    check(r == -1 && errno == ESRCH, "setscheduler dead pid ESRCH");
    check(syscall(SYS_sched_getscheduler, 0) == 0,
          "getscheduler -> OTHER");
    errno = 0;
    r = syscall(SYS_sched_getscheduler, 999999);
    check(r == -1 && errno == ESRCH, "getscheduler dead pid ESRCH");

    // --- priority bounds + rr interval
    check(syscall(SYS_sched_get_priority_max, 1) == 99,
          "pri max FIFO -> 99");
    check(syscall(SYS_sched_get_priority_max, 0) == 0,
          "pri max OTHER -> 0");
    check(syscall(SYS_sched_get_priority_min, 1) == 1,
          "pri min FIFO -> 1");
    check(syscall(SYS_sched_get_priority_min, 2) == 1,
          "pri min RR -> 1");
    errno = 0;
    r = syscall(SYS_sched_get_priority_max, 9);
    check(r == -1 && errno == EINVAL, "pri max bad policy EINVAL");
    struct timespec ts = {9, 9};
    errno = 0;
    check(syscall(SYS_sched_rr_get_interval, 0, &ts) == 0
              && ts.tv_sec == 0 && ts.tv_nsec == 0,
          "rr_interval writes zeros");
    errno = 0;
    r = syscall(SYS_sched_rr_get_interval, 999999, &ts);
    check(r == -1 && errno == ESRCH, "rr_interval dead pid ESRCH");
    errno = 0;
    r = syscall(SYS_sched_rr_get_interval, 0, (void *)0x100);
    check(r == -1 && errno == EFAULT, "rr_interval bad ptr EFAULT");

    // --- ioprio set/get
    errno = 0;
    check(syscall(SYS_ioprio_set, 1, 0, (2 << 13) | 4) == 0,
          "ioprio_set BE/4 self");
    errno = 0;
    check(syscall(SYS_ioprio_get, 1, 0) == ((2 << 13) | 4),
          "ioprio_get -> BE/4");
    errno = 0;
    r = syscall(SYS_ioprio_set, 4, 0, 0);
    check(r == -1 && errno == EINVAL, "ioprio which>3 EINVAL");
    errno = 0;
    r = syscall(SYS_ioprio_set, 1, 0, (4 << 13));
    check(r == -1 && errno == EINVAL, "ioprio class>3 EINVAL");
    errno = 0;
    r = syscall(SYS_ioprio_set, 1, 0, (2 << 13) | 8);
    check(r == -1 && errno == EINVAL, "ioprio data>7 EINVAL");
    errno = 0;
    r = syscall(SYS_ioprio_set, 1, 999999, 0);
    check(r == -1 && errno == ESRCH, "ioprio dead pid ESRCH");
    errno = 0;
    r = syscall(SYS_ioprio_get, 4, 0);
    check(r == -1 && errno == EINVAL, "ioprio_get which>3 EINVAL");

    // --- readahead
    int fd = open("/tmp_ra", O_RDWR | O_CREAT | O_TRUNC, 0600);
    check(fd >= 0, "open /tmp_ra");
    check(syscall(SYS_readahead, fd, 0, 4096) == 0,
          "readahead valid fd");
    close(fd);
    fd = open("/tmp_ra", O_WRONLY);
    errno = 0;
    r = syscall(SYS_readahead, fd, 0, 4096);
    check(r == -1 && errno == EBADF, "readahead WRONLY EBADF");
    close(fd);
    errno = 0;
    r = syscall(SYS_readahead, 99, 0, 4096);
    check(r == -1 && errno == EBADF, "readahead bad fd EBADF");
    unlink("/tmp_ra");

    // --- tkill
    errno = 0;
    check(syscall(SYS_tkill, getpid(), 0) == 0, "tkill self sig0");
    errno = 0;
    r = syscall(SYS_tkill, 999999, 1);
    check(r == -1 && errno == ESRCH, "tkill dead ESRCH");
    errno = 0;
    r = syscall(SYS_tkill, getpid(), 40);
    check(r == -1 && errno == EINVAL, "tkill bad sig EINVAL");

    // --- NUMA policy
    errno = 0;
    check(syscall(SYS_mbind, 0, 0, 0, 0, 0, 0) == 0, "mbind default");
    errno = 0;
    r = syscall(SYS_mbind, 0, 0, 5, 0, 0, 0);
    check(r == -1 && errno == EINVAL, "mbind mode>4 EINVAL");
    errno = 0;
    check(syscall(SYS_set_mempolicy, 0, 0, 64) == 0,
          "set_mempolicy default");
    errno = 0;
    r = syscall(SYS_set_mempolicy, 5, 0, 64);
    check(r == -1 && errno == EINVAL, "set_mempolicy mode>4 EINVAL");
    errno = 0;
    r = syscall(SYS_set_mempolicy, 0, 0, 99999);
    check(r == -1 && errno == EINVAL, "set_mempolicy huge maxnode");
    unsigned pol = 9;
    unsigned long mask = ~0UL;
    errno = 0;
    check(syscall(SYS_get_mempolicy, &pol, &mask, 64, 0, 0) == 0
              && pol == 0 && mask == 0,
          "get_mempolicy -> DEFAULT + empty mask");
    errno = 0;
    r = syscall(SYS_get_mempolicy, &pol, 0, 0, 0, 2); // ADDR sans NODE
    check(r == -1 && errno == EINVAL, "get_mempolicy ADDR-no-NODE");
    // NODE|ADDR is the legal pair — must NOT EINVAL
    check(syscall(SYS_get_mempolicy, &pol, 0, 0, 0, 3) == 0,
          "get_mempolicy NODE|ADDR ok");
    errno = 0;
    r = syscall(SYS_get_mempolicy, &pol, 0, 0, 0, 8); // unknown flag
    check(r == -1 && errno == EINVAL, "get_mempolicy bad flag");
    errno = 0;
    r = syscall(SYS_get_mempolicy, (void *)0x100, 0, 0, 0, 0);
    check(r == -1 && errno == EFAULT, "get_mempolicy bad ptr EFAULT");

    printf("schtest: %d failures\n", fails);
    return fails;
}
