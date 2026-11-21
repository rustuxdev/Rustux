// ttoutest — the TOSTOP write-side job-control gate: with TOSTOP
// armed on the console termios, a background pgrp's tty write is
// SIGTTOU'd (stop, the Linux tty_check_change(SIGTTOU) semantics), an
// orphaned group's write fails EIO, a blocked/ignored SIGTTOU lets
// the write through, and clearing TOSTOP restores free writing.
//
// Runs as a SOLO initrd (make run-ttout): while TOSTOP is armed,
// ANY task of the console's session writing from a non-foreground
// pgrp is stopped — a shared-suite run would leave mid-printf tasks
// Stopped forever (nobody fg's them), so this test owns the machine.
#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <termios.h>
#include <poll.h>
#include <sched.h>

static int fails;
static void check(int ok, const char *what) {
    printf("  %-46s %s\n", what, ok ? "ok" : "FAIL");
    if (!ok) fails++;
}

/* Wait bounded for child c to stop; returns its WSTOPSIG or -1. */
static int wait_stop(pid_t c) {
    int st;
    for (int i = 0; i < 4000; i++) {
        st = 0;
        if (waitpid(c, &st, WUNTRACED | WNOHANG) == c && WIFSTOPPED(st))
            return WSTOPSIG(st);
        sched_yield();
    }
    return -1;
}

int main(void) {
    setbuf(stdout, NULL);
    printf("ttoutest: TOSTOP + SIGTTOU write gate\n");

    /* Take the console foreground — this binary IS the shell here. */
    check(tcsetpgrp(0, getpgrp()) == 0, "tcsetpgrp own pgrp");

    struct termios tio;
    check(tcgetattr(0, &tio) == 0, "tcgetattr");
    check((tio.c_lflag & TOSTOP) == 0, "TOSTOP clear by default");
    tio.c_lflag |= TOSTOP;
    check(tcsetattr(0, TCSANOW, &tio) == 0, "tcsetattr set TOSTOP");
    struct termios tio2;
    check(tcgetattr(0, &tio2) == 0 && (tio2.c_lflag & TOSTOP),
          "TOSTOP persists after tcsetattr");
    check(write(1, "  fg-write: passes under TOSTOP\n", 32) == 32,
          "foreground write passes with TOSTOP");

    /* --- background child: write -> SIGTTOU stop -------------------
       Gate the child on a pipe so its tty write always lands AFTER
       the parent moved it behind the foreground group. */
    int sp[2];
    check(pipe(sp) == 0, "ttou gate pipe");
    pid_t c = fork();
    if (c == 0) {
        char d;
        if (read(sp[0], &d, 1) < 0) {
        }
        if (write(1, "z", 1) < 0) {
        }
        _exit(0); /* a passing write is fine; the stop is the check */
    }
    check(setpgid(c, c) == 0, "child moved behind the fg group");
    close(sp[0]);
    check(write(sp[1], "x", 1) == 1, "ttou child released");
    int sig = wait_stop(c);
    check(sig == SIGTTOU, "background tty write -> SIGTTOU stop");
    if (sig == -1) printf("    debug: child did not stop\n");
    kill(c, SIGKILL);
    int st;
    waitpid(c, &st, 0);

    /* --- SIGTTOU ignored: the write goes through ------------------ */
    int sp2[2], rp[2];
    check(pipe(sp2) == 0 && pipe(rp) == 0, "ignore gate/report pipes");
    pid_t d = fork();
    if (d == 0) {
        signal(SIGTTOU, SIG_IGN);
        char g;
        if (read(sp2[0], &g, 1) < 0) {
        }
        errno = 0;
        int r = write(1, "  ign-write: SIG_IGN lets it through\n", 37);
        char res = r == 37 ? 0 : (r < 0 ? (char)errno : 77);
        if (write(rp[1], &res, 1) != 1)
            _exit(96);
        _exit(0);
    }
    check(setpgid(d, d) == 0, "ignoring child moved behind fg");
    close(sp2[0]);
    close(rp[1]);
    check(write(sp2[1], "x", 1) == 1, "ignoring child released");
    char res = 66;
    check(read(rp[0], &res, 1) == 1, "ignoring child reported");
    check(res == 0, "SIG_IGN SIGTTOU: background write succeeds");
    waitpid(d, &st, 0);

    /* --- orphaned group: write -> EIO ------------------------------
       Same recipe as pgtest: a grandchild whose bridge parent dies
       is orphaned; its tty write must fail EIO, not SIGTTOU-stop. */
    int p2[2];
    check(pipe(p2) == 0, "orphan report pipe");
    pid_t a = fork();
    if (a == 0) {
        close(p2[0]);
        pid_t g = fork();
        if (g == 0) {
            /* Orphanhood lands when the kernel clears ppid at A's
               exit — it can precede G's first getppid, so poll for
               0 directly rather than a change from a snapshot. */
            for (long i = 0; i < 800000 && getppid() != 0; i++)
                sched_yield();
            if (getppid() != 0)
                _exit(97);
            unsigned short gp = (unsigned short)getpid();
            if (write(p2[1], &gp, 2) != 2)
                _exit(96);
            errno = 0;
            int r = write(1, "z", 1);
            char ores = r < 0 ? (char)errno : 99;
            if (write(p2[1], &ores, 1) != 1)
                _exit(98);
            _exit(0);
        }
        setpgid(g, g); /* G's own group; A's exit orphans it */
        _exit(0);
    }
    close(p2[1]);
    check(a > 0 && waitpid(a, &st, 0) == a && WIFEXITED(st),
          "orphan bridge parent exits");
    char ores = 0;
    unsigned short gpid = 0;
    int got = 0;
    for (int i = 0; i < 4000 && !got; i++) {
        waitpid(-1, NULL, WNOHANG);
        struct pollfd pf = {.fd = p2[0], .events = POLLIN};
        if (poll(&pf, 1, 5) <= 0)
            continue;
        if (gpid == 0) {
            if (read(p2[0], &gpid, 2) == 2)
                continue;
        }
        if (read(p2[0], &ores, 1) == 1)
            got = 1;
    }
    if (!got && gpid != 0)
        kill(gpid, SIGKILL);
    check(got && ores == EIO, "orphaned-group tty write -> EIO");

    /* --- TOSTOP cleared: background writes pass again ------------- */
    tio.c_lflag &= ~TOSTOP;
    check(tcsetattr(0, TCSANOW, &tio) == 0, "tcsetattr clear TOSTOP");
    int sp3[2], rp3[2];
    check(pipe(sp3) == 0 && pipe(rp3) == 0, "cleared gate/report pipes");
    pid_t e = fork();
    if (e == 0) {
        char g;
        if (read(sp3[0], &g, 1) < 0) {
        }
        errno = 0;
        int r = write(1, "  clr-write: no gate without TOSTOP\n", 36);
        char cres = r == 36 ? 0 : (r < 0 ? (char)errno : 88);
        if (write(rp3[1], &cres, 1) != 1)
            _exit(96);
        _exit(0);
    }
    check(setpgid(e, e) == 0, "cleared-mode child behind fg");
    close(sp3[0]);
    close(rp3[1]);
    check(write(sp3[1], "x", 1) == 1, "cleared child released");
    char cres = 66;
    check(read(rp3[0], &cres, 1) == 1, "cleared child reported");
    check(cres == 0, "no TOSTOP: background write succeeds");
    waitpid(e, &st, 0);

    printf("ttoutest: %d failures, done\n", fails);
    return fails;
}
