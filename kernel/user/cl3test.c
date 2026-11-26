// cl3test — compiled clone3/close_range/epoll_pwait2 ABI proof.
// clone3 parses the 88-byte clone_args: signal bits in flags,
// unknown flags, bad exit_signal, set_tid/cgroup, PIDFD+SETTID,
// stack-without-size, and nonzero struct tails all EINVAL/E2BIG.
// A fork-shape clone3 reaps like fork; CLONE_PIDFD mints a live
// pidfd that rides the run-296 machinery. close_range closes and
// marks ranges; UNSHARE detaches a CLONE_FILES-shared table so
// the parent's fd survives. epoll_pwait2 takes a timespec.
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <poll.h>
#include <sched.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sys/epoll.h>
#include <sys/stat.h>
#include <time.h>
#include <linux/close_range.h>

#ifndef SYS_clone3
#define SYS_clone3 435
#endif
#ifndef SYS_close_range
#define SYS_close_range 436
#endif
#ifndef SYS_epoll_pwait2
#define SYS_epoll_pwait2 441
#endif
#ifndef CLONE_PIDFD
#define CLONE_PIDFD 0x1000
#endif
#ifndef CLONE_PARENT_SETTID
#define CLONE_PARENT_SETTID 0x100000
#endif

static int fails;
static void say(const char *s) { write(1, s, strlen(s)); }
static void check(int ok, const char *what) {
    char buf[80];
    int n = snprintf(buf, sizeof(buf), "cl3test: %-34s %s\n",
                     what, ok ? "ok" : "FAIL");
    say(buf);
    if (!ok) fails++;
}

struct cl_args {
    unsigned long long flags, pidfd, ctid, ptid, esig;
    unsigned long long stack, stack_size, tls, settid, settid_n, cgroup;
};

static int cl3(struct cl_args *a, unsigned long sz) {
    return syscall(SYS_clone3, a, sz);
}

static volatile int thr_done;
static int thr_fd;
static int thr_entry(void *p) {
    (void)p;
    /* Detach into a private table, then close OUR copy only. */
    syscall(SYS_close_range, thr_fd, thr_fd, CLOSE_RANGE_UNSHARE);
    thr_done = 1;
    return 0; /* glibc clone() exits the child with this status */
}

int main(void) {
    struct cl_args a;
    memset(&a, 0, sizeof(a));

    // ---- size + field gates ----
    check(cl3(&a, 0) < 0 && errno == EINVAL, "size 0 EINVAL");
    check(cl3(&a, 8) < 0 && errno == EINVAL, "size 8 EINVAL");
    check(cl3(&a, 4097) < 0 && errno == E2BIG, "size huge E2BIG");
    a.flags = 17;               // signal bits in flags — clone3 rejects
    check(cl3(&a, sizeof(a)) < 0 && errno == EINVAL,
          "sigbits in flags EINVAL");
    a.flags = 1ULL << 60;       // unknown flag bit
    check(cl3(&a, sizeof(a)) < 0 && errno == EINVAL,
          "unknown flag EINVAL");
    a.flags = 0; a.esig = 64;
    check(cl3(&a, sizeof(a)) < 0 && errno == EINVAL,
          "exit_signal >63 EINVAL");
    a.esig = 10;                // SIGUSR1: valid but undeliverable here
    check(cl3(&a, sizeof(a)) < 0 && errno == ENOSYS,
          "odd exit_signal ENOSYS");
    a.esig = 17; a.settid_n = 1;
    check(cl3(&a, sizeof(a)) < 0 && errno == EINVAL, "set_tid EINVAL");
    a.settid_n = 0; a.cgroup = 1;
    check(cl3(&a, sizeof(a)) < 0 && errno == EINVAL, "cgroup EINVAL");
    a.cgroup = 0; a.stack = 0x7000000;
    check(cl3(&a, sizeof(a)) < 0 && errno == EINVAL,
          "stack sans size EINVAL");
    a.stack = 0;

    // ---- struct tail rules ----
    char big[96]; memset(big, 0, sizeof(big));
    memcpy(big, &a, sizeof(a));
    big[95] = 1;
    check(cl3((struct cl_args *)big, 96) < 0 && errno == E2BIG,
          "nonzero tail E2BIG");
    big[95] = 0;

    // ---- CLONE_PIDFD pairing ----
    int pidfd = -1;
    memset(&a, 0, sizeof(a)); a.esig = 17;
    a.flags = CLONE_PIDFD | CLONE_PARENT_SETTID;
    a.pidfd = (unsigned long)&pidfd;
    check(cl3(&a, sizeof(a)) < 0 && errno == EINVAL,
          "PIDFD+SETTID EINVAL");
    a.flags = CLONE_PIDFD;
    a.pidfd = 4;                // unwritable — EFAULT, not EFAULT-of-check
    check(cl3(&a, sizeof(a)) < 0 && errno == EFAULT,
          "bad pidfd ptr EFAULT");

    // ---- fork-shape clone3: child reaps like fork ----
    memset(&a, 0, sizeof(a)); a.esig = 17;
    int p = cl3(&a, sizeof(a));
    if (p == 0) _exit(42);
    check(p > 0, "clone3 fork child");
    int wst = 0;
    check(waitpid(p, &wst, 0) == p && WEXITSTATUS(wst) == 42,
          "clone3 child reaped");

    // ---- CLONE_PIDFD: child pidfd minted + drives run-296 ----
    memset(&a, 0, sizeof(a)); a.esig = 17;
    a.flags = CLONE_PIDFD; a.pidfd = (unsigned long)&pidfd;
    pidfd = -1;
    p = cl3(&a, sizeof(a));
    if (p == 0) { for (;;) pause(); }
    check(p > 0 && pidfd >= 0, "CLONE_PIDFD mints");
    struct pollfd pp = { .fd = pidfd, .events = POLLIN };
    check(poll(&pp, 1, 0) == 0, "live clone3 pidfd silent");
    check(syscall(SYS_pidfd_send_signal, pidfd, SIGKILL, 0, 0) == 0,
          "pidfd SIGKILL lands");
    wst = 0;
    check(waitpid(p, &wst, 0) == p && WIFSIGNALED(wst),
          "clone3 child signaled");
    check(poll(&pp, 1, 0) == 1 && (pp.revents & POLLIN),
          "dead clone3 pidfd POLLIN");
    close(pidfd);

    // ---- close_range gates ----
    check(syscall(SYS_close_range, 5, 3, 0) < 0 && errno == EINVAL,
          "first>last EINVAL");
    check(syscall(SYS_close_range, 0, 3, 8) < 0 && errno == EINVAL,
          "bad flag EINVAL");
    check(syscall(SYS_close_range, 0, 3,
                  CLOSE_RANGE_UNSHARE | CLOSE_RANGE_CLOEXEC) < 0
          && errno == EINVAL, "UNSHARE|CLOEXEC EINVAL");

    // ---- close_range closes a span, edges survive ----
    int f0 = open("/dev/null", O_RDONLY);
    int f1 = open("/dev/null", O_RDONLY);
    int f2 = open("/dev/null", O_RDONLY);
    check(f0 >= 0 && f1 == f0 + 1 && f2 == f0 + 2, "three opens land");
    check(syscall(SYS_close_range, f1, f1, 0) == 0,
          "close_range one fd");
    check(fcntl(f1, F_GETFD) < 0 && errno == EBADF, "closed EBADF");
    struct stat st;
    check(fstat(f0, &st) == 0 && fstat(f2, &st) == 0,
          "range edges survive");

    // ---- CLOSE_RANGE_CLOEXEC marks, does not close ----
    check(syscall(SYS_close_range, f2, f2, CLOSE_RANGE_CLOEXEC) == 0,
          "CLOEXEC range");
    check((fcntl(f2, F_GETFD) & FD_CLOEXEC) != 0, "cloexec lands");
    check(fstat(f2, &st) == 0, "cloexec fd still open");

    // ---- UNSHARE: shared-table thread's close spares parent ----
    static char stk[8192] __attribute__((aligned(16)));
    thr_done = 0; thr_fd = f2;
    int tp = clone(thr_entry, stk + sizeof(stk),
                   CLONE_VM | CLONE_SIGHAND | CLONE_THREAD | CLONE_FILES,
                   0);
    check(tp > 0, "CLONE_FILES thread");
    if (tp > 0) {
        int spins = 50000000;
        while (!thr_done && --spins) ;
        check(thr_done, "thread detached + closed");
        check(fstat(f2, &st) == 0, "parent fd survives UNSHARE");
        close(f2);
    } else {
        check(0, "thread detached + closed");
        check(0, "parent fd survives UNSHARE");
    }
    close(f0);

    // ---- epoll_pwait2: timespec timeout ----
    int ep = epoll_create1(0);
    int pipes[2];
    check(pipe(pipes) == 0, "pipe for epoll");
    struct epoll_event ee = { .events = EPOLLIN, .data.u64 = 9 };
    check(epoll_ctl(ep, EPOLL_CTL_ADD, pipes[0], &ee) == 0,
          "epoll add pipe");
    struct epoll_event out;
    struct timespec z = { 0, 0 };
    check(syscall(SYS_epoll_pwait2, ep, &out, 4, &z, 0, 0) == 0,
          "pwait2 empty timeout");
    check(write(pipes[1], "q", 1) == 1, "pipe byte");
    struct timespec half = { 0, 500000000 };
    check(syscall(SYS_epoll_pwait2, ep, &out, 4, &half, 0, 0) == 1
          && out.data.u64 == 9, "pwait2 delivers event");
    struct timespec bad = { 0, 1000000000 };
    check(syscall(SYS_epoll_pwait2, ep, &out, 4, &bad, 0, 0) < 0
          && errno == EINVAL, "bad nsec EINVAL");
    struct timespec neg = { -1, 0 };
    check(syscall(SYS_epoll_pwait2, ep, &out, 4, &neg, 0, 0) < 0
          && errno == EINVAL, "neg sec EINVAL");
    close(pipes[0]); close(pipes[1]); close(ep);

    say(fails ? "cl3test: failures\n" : "cl3test: 0 failure(s)\n");
    return fails;
}
