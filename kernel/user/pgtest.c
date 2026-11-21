// pgtest — process groups, sessions, and job control: real pgrp/sid
// identity through setpgid/getpgid/getsid/getpgrp/setsid, negative-
// pid kill() group broadcast, stop/continue states with WUNTRACED/
// WCONTINUED wait4, group wait selectors, tcsetpgrp foreground, and
// the SIGTTIN background-read gate (plus the orphaned-group EIO).
#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <poll.h>
#include <sched.h>

static int fails;
static volatile sig_atomic_t got_usr1;
static void usr1_hit(int s) { (void)s; got_usr1 = 1; }
static void check(int ok, const char *what) {
    printf("  %-46s %s\n", what, ok ? "ok" : "FAIL");
    if (!ok) fails++;
}

int main(void) {
    setbuf(stdout, NULL);
    printf("pgtest: process groups + job control\n");

    /* --- identity ------------------------------------------------ */
    pid_t me = getpid();
    check(getpgrp() == me, "getpgrp = own pid (spawn = group leader)");
    check(getpgid(0) == getpgrp(), "getpgid(0) = getpgrp");
    check(getsid(0) > 0, "getsid(0) reports a session");
    errno = 0;
    check(getpgid(0x7ffffff0) == -1 && errno == ESRCH,
          "getpgid(bad pid) -> ESRCH");
    errno = 0;
    check(getsid(0x7ffffff0) == -1 && errno == ESRCH,
          "getsid(bad pid) -> ESRCH");

    /* --- setsid rules -------------------------------------------- */
    errno = 0;
    check(setsid() == -1 && errno == EPERM,
          "setsid on group leader -> EPERM");

    pid_t s = fork();
    if (s == 0) {
        pid_t ns = setsid();
        pid_t fg = -2;
        int tr = tcgetpgrp(0); /* must lose the ctty: new session */
        if (ns == getpid() && getsid(0) == getpid() &&
            getpgid(0) == getpid() && tr == -1 && errno == ENOTTY)
            _exit(0);
        _exit(30);
    }
    int st = 0;
    check(s > 0 && waitpid(s, &st, 0) == s && WIFEXITED(st) &&
          WEXITSTATUS(st) == 0,
          "setsid child: new sid+pgrp, ctty lost -> ENOTTY");

    /* --- setpgid identity ---------------------------------------- */
    pid_t c1 = fork();
    if (c1 == 0) {
        for (;;)
            ;
    }
    check(c1 > 0 && setpgid(c1, c1) == 0, "setpgid(child, child) ok");
    check(getpgid(c1) == c1, "getpgid(child) = new group leader");

    pid_t c2 = fork();
    if (c2 == 0) {
        for (;;)
            ;
    }
    check(c2 > 0 && setpgid(c2, c1) == 0,
          "setpgid(child2 -> group c1)");
    check(getpgid(c2) == c1, "getpgid(child2) = c1's group");
    errno = 0;
    check(setpgid(c2, 0x10000) == -1 && errno == EPERM,
          "setpgid -> nonexistent group -> EPERM");
    errno = 0;
    check(setpgid(0x7ffffff0, c1) == -1 && errno == ESRCH,
          "setpgid bad pid -> ESRCH");
    errno = 0;
    check(setpgid(c2, c1) == 0 && setpgid(c2, c1) == 0,
          "setpgid same group is a no-op");

    /* --- kill(-pgid) group broadcast ------------------------------ */
    check(kill(-c1, 0) == 0, "kill(-pgid, 0) probes a live group");
    errno = 0;
    check(kill(-0x10000, 0) == -1 && errno == ESRCH,
          "kill(-badpgid, 0) -> ESRCH");
    errno = 0;
    check(kill(0, 0) == 0, "kill(0, 0) probes own group");

    check(kill(-c1, SIGTERM) == 0, "kill(-pgid, SIGTERM)");
    int got = 0;
    for (int i = 0; i < 2; i++) {
        int ws = 0;
        pid_t w = waitpid(-c1, &ws, 0);
        if (w > 0 && WIFSIGNALED(ws) && WTERMSIG(ws) == SIGTERM)
            got++;
    }
    check(got == 2, "waitpid(-pgid) collected both group children");
    errno = 0;
    check(waitpid(-c1, &st, WNOHANG) == -1 && errno == ECHILD,
          "waitpid(-pgid) drained -> ECHILD");

    /* --- stop/continue + WUNTRACED/WCONTINUED --------------------- */
    pid_t c3 = fork();
    if (c3 == 0) {
        for (;;)
            ;
    }
    check(kill(c3, SIGTSTP) == 0, "kill(child, SIGTSTP)");
    int stopped = 0;
    for (int i = 0; i < 2000 && !stopped; i++) {
        st = 0;
        pid_t w = waitpid(c3, &st, WUNTRACED | WNOHANG);
        if (w == c3 && WIFSTOPPED(st) && WSTOPSIG(st) == SIGTSTP)
            stopped = 1;
        else
            sched_yield();
    }
    check(stopped, "WUNTRACED reports WIFSTOPPED + stopsig TSTP");
    /* The stop was consumed: a second traced wait must not repeat. */
    check(waitpid(c3, &st, WUNTRACED | WNOHANG) == 0,
          "reported stop is consumed (no duplicate)");

    check(kill(c3, SIGCONT) == 0, "kill(child, SIGCONT)");
    int cont = 0;
    for (int i = 0; i < 2000 && !cont; i++) {
        st = 0;
        pid_t w = waitpid(c3, &st, WCONTINUED | WNOHANG);
        if (w == c3 && WIFCONTINUED(st))
            cont = 1;
        else
            sched_yield();
    }
    check(cont, "WCONTINUED reports the resume (0xffff)");
    check(kill(c3, SIGKILL) == 0, "SIGKILL a continued child");
    check(waitpid(c3, &st, 0) == c3 && WIFSIGNALED(st) &&
          WTERMSIG(st) == SIGKILL,
          "killed child reaps as signaled");
    errno = 0;
    check(waitpid(c3, &st, WNOHANG) == -1 && errno == ECHILD,
          "reaped child -> ECHILD");

    /* --- SIGSTOP is uncatchable + unmaskable ---------------------- */
    struct sigaction sa = {.sa_handler = SIG_IGN};
    sigemptyset(&sa.sa_mask);
    check(sigaction(SIGSTOP, &sa, NULL) == -1 && errno == EINVAL,
          "sigaction SIGSTOP -> EINVAL (uncatchable)");
    sigset_t block;
    sigemptyset(&block);
    sigaddset(&block, SIGSTOP);
    check(sigprocmask(SIG_BLOCK, &block, NULL) == 0,
          "sigprocmask accepts SIGSTOP (mask-wise)");

    pid_t c4 = fork();
    if (c4 == 0) {
        sigset_t b;
        sigemptyset(&b);
        sigaddset(&b, SIGSTOP);
        sigprocmask(SIG_BLOCK, &b, NULL); /* Linux: can't help you */
        for (;;)
            ;
    }
    check(kill(c4, SIGSTOP) == 0, "SIGSTOP on masked child");
    int stp = 0;
    for (int i = 0; i < 2000 && !stp; i++) {
        st = 0;
        if (waitpid(c4, &st, WUNTRACED | WNOHANG) == c4 &&
            WIFSTOPPED(st) && WSTOPSIG(st) == SIGSTOP)
            stp = 1;
        else
            sched_yield();
    }
    check(stp, "SIGSTOP stops despite the mask");
    /* KILL pulls a stopped task out directly. */
    check(kill(c4, SIGKILL) == 0, "SIGKILL a stopped child");
    check(waitpid(c4, &st, 0) == c4 && WIFSIGNALED(st) &&
          WTERMSIG(st) == SIGKILL,
          "stopped child dies by SIGKILL");

    /* --- wait4 selectors ------------------------------------------ */
    pid_t c5 = fork();
    if (c5 == 0)
        _exit(7);
    check(waitpid(0, &st, 0) == c5 && WIFEXITED(st) &&
          WEXITSTATUS(st) == 7,
          "waitpid(0) = own-group child");
    errno = 0;
    check(waitpid(-1, &st, 0x100) == -1 && errno == EINVAL,
          "waitpid bad flags -> EINVAL");

    /* --- tty foreground group ------------------------------------- */
    pid_t fg = tcgetpgrp(0);
    check(fg == getpgrp(), "tcgetpgrp = own pgrp (console owner)");
    check(tcsetpgrp(0, getpgrp()) == 0, "tcsetpgrp own pgrp");
    errno = 0;
    check(tcsetpgrp(0, 0x10000) == -1 && errno == EPERM,
          "tcsetpgrp bad group -> EPERM");

    /* A background-group child reading the tty gets SIGTTIN'd.
       Re-assert our fg right before — a concurrent job-control
       shell's tcsetpgrp could have moved it meanwhile. And gate
       the child on a pipe so its tty read always lands AFTER the
       parent has moved it into its own group. */
    tcsetpgrp(0, getpgrp());
    int sp[2];
    check(pipe(sp) == 0, "ttin gate pipe");
    pid_t c6 = fork();
    if (c6 == 0) {
        char d;
        if (read(sp[0], &d, 1) < 0) {
        }
        volatile char b;
        if (read(0, (void *)&b, 1) < 0) {
        }
        _exit(0);
    }
    check(setpgid(c6, c6) == 0, "child moved behind the fg group");
    close(sp[0]);
    check(write(sp[1], "x", 1) == 1, "ttin child released");
    int ttin = 0;
    for (int i = 0; i < 4000 && !ttin; i++) {
        st = 0;
        if (waitpid(c6, &st, WUNTRACED | WNOHANG) == c6 &&
            WIFSTOPPED(st) && WSTOPSIG(st) == SIGTTIN)
            ttin = 1;
        else
            sched_yield();
    }
    check(ttin, "background tty read -> SIGTTIN stop");
    kill(c6, SIGKILL);
    waitpid(c6, &st, 0);

    /* --- orphaned group: read -> EIO (not SIGTTIN) ---------------- */
    /* A group is orphaned when no member's parent is alive in the
       same session but a different group — the classic recipe is a
       grandchild whose parent dies. G reads stdin only after its
       p1 read hits EOF (A's exit released the last writer), then
       reports the read errno back through p2. */
    tcsetpgrp(0, getpgrp()); /* same re-assert as the TTIN check */
    int p2[2];
    check(pipe(p2) == 0, "orphan report pipe");
    pid_t a = fork();
    if (a == 0) {
        close(p2[0]);
        pid_t g = fork();
        if (g == 0) {
            /* Orphanhood is getppid()==0: the kernel clears G's
               parent at A's exit, which can land before G's first
               getppid — so poll for 0 directly; a "changed from
               apid" test spins forever when apid is already 0. */
            for (long i = 0; i < 800000 && getppid() != 0; i++)
                sched_yield();
            if (getppid() != 0)
                _exit(97); /* bridge never died — distinct report */
            unsigned short gp = (unsigned short)getpid();
            if (write(p2[1], &gp, 2) != 2)
                _exit(96);
            volatile char b;
            errno = 0;
            int r = read(0, (void *)&b, 1);
            char res = r < 0 ? (char)errno : 99;
            if (write(p2[1], &res, 1) != 1)
                _exit(98);
            _exit(0);
        }
        setpgid(g, g); /* G's own group; A's exit orphans it */
        _exit(0);
    }
    close(p2[1]);
    check(a > 0 && waitpid(a, &st, 0) == a && WIFEXITED(st),
          "orphan bridge parent exits");
    /* Bounded wait for G's report — a gate miss (dead fg) blocks G
       on stdin, which must degrade to FAIL, not a suite hang. G
       reports its pid first so a stuck stray can be reaped. */
    char res = 0;
    unsigned short gpid = 0;
    int got_res = 0;
    for (int i = 0; i < 4000 && !got_res; i++) {
        int r = waitpid(-1, NULL, WNOHANG); /* reap strays cheaply */
        (void)r;
        struct pollfd pf = {.fd = p2[0], .events = POLLIN};
        if (poll(&pf, 1, 5) <= 0)
            continue;
        if (gpid == 0) {
            if (read(p2[0], &gpid, 2) == 2)
                continue;
        }
        if (read(p2[0], &res, 1) == 1)
            got_res = 1;
    }
    if (!got_res && gpid != 0)
        kill(gpid, SIGKILL); /* don't leave a blocked stray behind */
    if (!(got_res && res == EIO))
        printf("    debug: got_res=%d res=%d\n", got_res, res);
    check(got_res && res == EIO, "orphaned-group tty read -> EIO");

    /* --- signal waits: sigpending(127), sigsuspend(130), pause(34) - */
    struct sigaction hu = {.sa_handler = usr1_hit};
    check(sigaction(SIGUSR1, &hu, NULL) == 0, "SIGUSR1 handler arms");

    sigset_t blk1, empty, pend, pprev;
    sigemptyset(&blk1); sigaddset(&blk1, SIGUSR1);
    sigemptyset(&empty);
    check(sigprocmask(SIG_BLOCK, &blk1, &pprev) == 0,
          "block SIGUSR1 for pending test");
    check(kill(getpid(), SIGUSR1) == 0, "self-kill SIGUSR1");
    check(sigpending(&pend) == 0 && sigismember(&pend, SIGUSR1),
          "sigpending sees blocked SIGUSR1");

    /* sigsuspend with SIGUSR1 unmasked delivers it — and the block
       mask must be restored on the way out. */
    got_usr1 = 0;
    errno = 0;
    check(sigsuspend(&empty) == -1 && errno == EINTR && got_usr1,
          "sigsuspend wakes on pending SIGUSR1 -> EINTR");
    check(sigprocmask(SIG_SETMASK, NULL, &pend) == 0 &&
          sigismember(&pend, SIGUSR1),
          "sigsuspend restored the block mask");
    sigprocmask(SIG_SETMASK, &pprev, NULL);

    /* pause(34): a child's signal interrupts the sleep with EINTR. */
    got_usr1 = 0;
    pid_t sc = fork();
    if (sc == 0) {
        struct timespec ts = {0, 20000000}; /* 20ms */
        nanosleep(&ts, NULL);
        kill(getppid(), SIGUSR1);
        _exit(0);
    }
    errno = 0;
    check(sc > 0 && pause() == -1 && errno == EINTR && got_usr1,
          "pause() interrupted by SIGUSR1 -> EINTR");
    waitpid(sc, &st, 0);

    printf("pgtest: %d failures, done\n", fails);
    return fails;
}
