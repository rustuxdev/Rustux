// fxvtest — compiled futex_waitv(449)/fchmodat2(452) ABI proof.
// waitv parses the {val,uaddr,flags,res} 24B array: nr bounds,
// syscall flags, FUTEX_32 waiter flag, EFAULTs and EAGAIN on the
// upfront compares; wakes return the hit INDEX under a shared-mm
// waker; timeouts are absolute on REALTIME or MONOTONIC.
// fchmodat2 gates unknown flags, follows NOFOLLOW into the link's
// own inode, and EMPTY_PATH chmods the dirfd itself.
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <sched.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <sys/wait.h>

static int fails;
#define check(c, msg) do { \
    if (c) printf("fxvtest: %-34s ok\n", msg); \
    else { printf("fxvtest: %-34s FAIL\n", msg); fails++; } \
} while (0)

#ifndef SYS_futex_waitv
#define SYS_futex_waitv 449
#endif
#ifndef SYS_fchmodat2
#define SYS_fchmodat2 452
#endif
#ifndef SYS_futex
#define SYS_futex 202
#endif
#define FUTEX_WAKE 1
#define FUTEX_32   2

struct fwv { uint64_t val, uaddr; uint32_t flags, res; };

static volatile unsigned int w0, w1;
static char stk[8192] __attribute__((aligned(16)));
static volatile int go;

static int waker(void *a) {
    (void)a;
    while (!go) sched_yield();
    usleep(150000); // let the parent actually reach the sleep
    syscall(SYS_futex, (void *)&w1, FUTEX_WAKE, 1, 0, 0, 0);
    return 0;
}

int main(void) {
    printf("fxvtest: futex_waitv + fchmodat2 checks\n");

    // ---- waitv gate ladder ----
    w0 = 0; w1 = 0;
    struct fwv v[2] = {
        { .val = 0, .uaddr = (uint64_t)&w0, .flags = FUTEX_32 },
        { .val = 0, .uaddr = (uint64_t)&w1, .flags = FUTEX_32 },
    };
    errno = 0;
    check(syscall(SYS_futex_waitv, v, 0, 0, 0, 1) < 0 && errno == EINVAL,
          "waitv nr=0 EINVAL");
    errno = 0;
    check(syscall(SYS_futex_waitv, v, 129, 0, 0, 1) < 0 && errno == EINVAL,
          "waitv nr>128 EINVAL");
    errno = 0;
    check(syscall(SYS_futex_waitv, v, 2, 1, 0, 1) < 0 && errno == EINVAL,
          "waitv flags!=0 EINVAL");
    errno = 0;
    check(syscall(SYS_futex_waitv, v, 2, 0, 0, 99) < 0 && errno == EINVAL,
          "waitv bad clockid EINVAL");
    errno = 0;
    check(syscall(SYS_futex_waitv, (void *)1, 2, 0, 0, 1) < 0
          && errno == EFAULT, "waitv array EFAULT");
    struct fwv bad = { .val = 0, .uaddr = (uint64_t)&w0, .flags = 0 };
    errno = 0;
    check(syscall(SYS_futex_waitv, &bad, 1, 0, 0, 1) < 0 && errno == EINVAL,
          "waiter no FUTEX_32 EINVAL");
    bad.flags = 4;
    errno = 0;
    check(syscall(SYS_futex_waitv, &bad, 1, 0, 0, 1) < 0 && errno == EINVAL,
          "waiter unknown flag EINVAL");
    bad.flags = FUTEX_32; bad.uaddr = 1;
    errno = 0;
    check(syscall(SYS_futex_waitv, &bad, 1, 0, 0, 1) < 0 && errno == EFAULT,
          "waiter uaddr EFAULT");
    v[0].val = 1; // *uaddr is 0 -> mismatch
    errno = 0;
    check(syscall(SYS_futex_waitv, v, 2, 0, 0, 1) < 0 && errno == EAGAIN,
          "waitv val mismatch EAGAIN");
    v[0].val = 0;
    errno = 0;
    check(syscall(SYS_futex_waitv, v, 2, 0, (void *)1, 1) < 0
          && errno == EFAULT, "waitv timeout ptr EFAULT");

    // ---- waitv absolute timeout (MONOTONIC) ----
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    errno = 0; // a deadline in the past ETIMEDOUTs immediately
    check(syscall(SYS_futex_waitv, v, 2, 0, &ts, 1) < 0
          && errno == ETIMEDOUT, "waitv past deadline ETIMEDOUT");
    ts.tv_nsec += 60000000;
    if (ts.tv_nsec >= 1000000000L) { ts.tv_sec++; ts.tv_nsec -= 1000000000L; }
    errno = 0;
    check(syscall(SYS_futex_waitv, v, 2, 0, &ts, 1) < 0
          && errno == ETIMEDOUT, "waitv 60ms deadline ETIMEDOUT");
    // ---- REALTIME deadline ----
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_nsec += 50000000;
    if (ts.tv_nsec >= 1000000000L) { ts.tv_sec++; ts.tv_nsec -= 1000000000L; }
    errno = 0;
    check(syscall(SYS_futex_waitv, v, 2, 0, &ts, 0) < 0
          && errno == ETIMEDOUT, "waitv REALTIME deadline ETIMEDOUT");
    struct timespec badts = { .tv_sec = 0, .tv_nsec = 2000000000L };
    errno = 0;
    check(syscall(SYS_futex_waitv, v, 2, 0, &badts, 1) < 0
          && errno == EINVAL, "waitv nsec range EINVAL");

    // ---- waitv wake returns the hit index ----
    go = 0;
    long t = clone(waker, stk + sizeof(stk),
                   CLONE_VM | CLONE_SIGHAND | CLONE_THREAD, 0, 0, 0, 0);
    check(t > 0, "clone waker thread");
    go = 1;
    long r = syscall(SYS_futex_waitv, v, 2, 0, 0, 1);
    check(r == 1, "waitv woke -> index 1");

    // ---- fchmodat2 ----
    int fd = open("/tmp_fxv", O_CREAT | O_RDWR, 0600);
    check(fd >= 0, "tmp file");
    close(fd);
    errno = 0;
    check(syscall(SYS_fchmodat2, AT_FDCWD, "/tmp_fxv", 0600, 0x200) < 0
          && errno == EINVAL, "fchmodat2 unknown flag EINVAL");
    struct stat st;
    check(syscall(SYS_fchmodat2, AT_FDCWD, "/tmp_fxv", 0640, 0) == 0,
          "fchmodat2 plain chmod");
    check(stat("/tmp_fxv", &st) == 0
          && (st.st_mode & 0777) == 0640, "mode applied");

    unlink("/tmp_fxvlnk");
    check(symlink("/tmp_fxv", "/tmp_fxvlnk") == 0, "link minted");
    check(syscall(SYS_fchmodat2, AT_FDCWD, "/tmp_fxvlnk", 0600,
                  AT_SYMLINK_NOFOLLOW) == 0, "NOFOLLOW on link ok");
    check(lstat("/tmp_fxvlnk", &st) == 0
          && (st.st_mode & 0777) == 0600, "link's own mode changed");
    check(stat("/tmp_fxv", &st) == 0
          && (st.st_mode & 0777) == 0640, "target mode untouched");
    check(syscall(SYS_fchmodat2, AT_FDCWD, "/tmp_fxvlnk", 0600, 0) == 0,
          "follow reaches target");
    check(stat("/tmp_fxv", &st) == 0
          && (st.st_mode & 0777) == 0600, "target chmod'd through link");
    unlink("/tmp_fxvlnk");

    // AT_EMPTY_PATH on the open fd — the fchmod shape.
    fd = open("/tmp_fxv", O_RDWR);
    check(fd >= 0, "reopen tmp");
    check(syscall(SYS_fchmodat2, fd, "", 0644, AT_EMPTY_PATH) == 0,
          "EMPTY_PATH chmods the fd");
    check(stat("/tmp_fxv", &st) == 0
          && (st.st_mode & 0777) == 0644, "fd inode mode applied");
    errno = 0;
    check(syscall(SYS_fchmodat2, fd, "", 0600, 0) < 0 && errno == ENOENT,
          "empty path sans EMPTY_PATH ENOENT");
    close(fd);
    unlink("/tmp_fxv");

    printf("fxvtest: %d failure(s)\n", fails);
    return fails;
}
