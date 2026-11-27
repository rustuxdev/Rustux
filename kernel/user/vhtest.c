// vhtest — vhangup(153) + ctty drop/re-acquire coverage.
// Destructive paths run in disposable children; the run ends with
// the console unowned (last member — nothing after depends on a ctty).
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static int fails;
static void check(int ok, const char *msg) {
    if (!ok) { fails++; printf("FAIL: %s\n", msg); }
}

static int child_st(void (*fn)(void), int want) {
    pid_t p = fork();
    if (p == 0) { fn(); _exit(0); }
    if (p < 0) { printf("  fork err=%d\n", errno); return 126; }
    int st;
    pid_t w = waitpid(p, &st, 0);
    if (w < 0) { printf("  waitpid err=%d\n", errno); return 125; }
    return WIFEXITED(st) ? WEXITSTATUS(st) : 127;
}

// T1: nonroot -> EPERM (CAP_SYS_TTY_CONFIG). Suite tasks may spawn
// nonroot already — only setuid when we actually need to drop.
static void t1(void) {
    if (getuid() == 0 && setuid(1) != 0) _exit(11);
    int r = vhangup(), e = errno;
    fprintf(stderr, "t1: uid=%d r=%d e=%d\n", getuid(), r, e);
    _exit(r == -1 && e == EPERM ? 0 : 12);
}

// T2: own session, no ctty -> silent 0 like Linux (uid0 only — a
// nonroot caller gets EPERM for the wrong reason; skip then).
static void t2(void) {
    if (getuid() != 0) _exit(0);
    if (setsid() < 0) _exit(11);
    int r = vhangup(), e = errno;
    fprintf(stderr, "t2: r=%d e=%d\n", r, e);
    _exit(r == 0 ? 0 : 12);
}

static volatile sig_atomic_t hupped;
static void on_hup(int s) { (void)s; hupped = 1; }

// T3: real hangup — own fg pgrp gets SIGHUP+SIGCONT, ctty drops.
static void t3(void) {
    struct sigaction sa = {0};
    sa.sa_handler = on_hup;
    sigaction(SIGHUP, &sa, 0);
    signal(SIGTTOU, SIG_IGN);
    if (setpgid(0, 0) != 0) _exit(11);          // own pgrp
    pid_t g = getpid();
    if (ioctl(0, TIOCSPGRP, &g) != 0) _exit(12); // become foreground
    if (vhangup() != 0) _exit(13);              // the hangup
    if (!hupped) _exit(14);                     // SIGHUP landed
    int t = open("/dev/tty", O_RDWR);
    if (t >= 0 || errno != ENXIO) _exit(15);    // ctty gone
    int out;
    if (ioctl(0, TIOCGPGRP, &out) == 0 || errno != ENOTTY) _exit(16);
    if (vhangup() != 0) _exit(17);              // no ctty now -> 0
    _exit(0);
}

// T4: re-acquire — a ctty-less session leader adopts the console on
// open, /dev/tty works again, then a second hangup drops it clean.
static void t4(void) {
    struct sigaction sa = {0};
    sa.sa_handler = on_hup;
    sigaction(SIGHUP, &sa, 0);                  // own hangup SIGHUPs us
    if (setsid() < 0) _exit(11);
    int c = open("/dev/console", O_RDWR);
    if (c < 0) _exit(12);
    int t = open("/dev/tty", O_RDWR);
    if (t < 0) _exit(13);                       // adopted ctty
    if (vhangup() != 0) _exit(14);              // drop it again
    if (!hupped) _exit(15);                     // leader SIGHUP landed
    _exit(0);
}

int main(void) {
    printf("vhtest: begin\n");
    check(child_st(t1, 0) == 0, "nonroot EPERM");
    check(child_st(t2, 0) == 0, "no-ctty -> 0");
    // The hangup drops the console ctty for the WHOLE owning session —
    // in the full suite other sid-1 tasks (job-control checks) still
    // depend on it, so the destructive path only runs in the minimal
    // image where this binary is the session's only member (low pid).
    if (getpid() >= 10) {
        printf("vhtest: %d failures (destructive path skipped in-suite)\n",
               fails);
        return fails;
    }
    int s3 = child_st(t3, 0);
    check(s3 == 0, "hangup: SIGHUP + ctty drop");
    if (s3 != 0) printf("  t3 exit %d\n", s3);
    // Parent's own ctty was dropped by t3 too (same session).
    errno = 0;
    int t = open("/dev/tty", O_RDWR);
    check(t < 0 && errno == ENXIO, "parent ctty lost");
    int s4 = child_st(t4, 0);
    check(s4 == 0, "leader re-acquire + second hangup");
    if (s4 != 0) printf("  t4 exit %d\n", s4);
    printf("vhtest: %d failures\n", fails);
    return fails;
}
