// ptrtest — ptrace(101) classic subset: TRACEME, ATTACH(+reparent)/
// DETACH, CONT/KILL/SINGLESTEP, SYSCALL entry+exit stops, PEEK/POKE
// data+user, GETREGS/SETREGS, GETSIGINFO, exec-stop, foreign-EPERM.
#define _GNU_SOURCE
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/user.h>
#include <signal.h>
#include <stdlib.h>
#include <time.h>

static int fails;
static void check(int ok, const char *what) {
    if (!ok) {
        printf("FAIL: %s\n", what);
        fails++;
    }
}

#define PT_TRACEME      0
#define PT_PEEKDATA     2
#define PT_PEEKUSER     3
#define PT_POKEDATA     5
#define PT_POKEUSER     6
#define PT_CONT         7
#define PT_KILL         8
#define PT_SINGLESTEP   9
#define PT_GETREGS      12
#define PT_SETREGS      13
#define PT_ATTACH       16
#define PT_DETACH       17
#define PT_SYSCALL      24
#define PT_GETSIGINFO   0x4202

static long ptrace(long req, long pid, void *addr, void *data) {
    return syscall(101, req, pid, addr, data, 0, 0);
}

// block forever until killed
static void spin_forever(void) {
    for (;;) pause();
}

// a pipe-based rendezvous: parent blocks on read until child writes
static int pipe_fds[2];
static void tell_parent(void) { char c = 'x'; write(pipe_fds[1], &c, 1); }
static void wait_child_ready(void) { char c; read(pipe_fds[0], &c, 1); }

// a stop-report for pid?
static int stopped_at(pid_t c, int *st) {
    return waitpid(c, st, WUNTRACED) == c && WIFSTOPPED(*st);
}
static int stop_sig(int st) { return WSTOPSIG(st); }

int main(int argc, char **argv) {
    (void)argv;
    if (argc > 1) return 42; // exec'd dummy image
    printf("ptrtest: begin\n");

    // ---------- TRACEME + exec-stop ----------
    // child declares itself traced, raises SIGSTOP, execs; parent
    // sees the signal-stop then the exec SIGTRAP.
    {
        pid_t c = fork();
        int st;
        if (c == 0) {
            ptrace(PT_TRACEME, 0, 0, 0);
            raise(SIGSTOP);
            execl("/ptrtest", "ptrtest", "dummy", (void *)0);
            _exit(9);
        }
        check(stopped_at(c, &st) && stop_sig(st) == SIGSTOP,
              "traceme: signal-stop (SIGSTOP) reported");
        // resume; the exec-stop must land before the image's first insn
        ptrace(PT_CONT, c, 0, 0);
        check(stopped_at(c, &st) && stop_sig(st) == SIGTRAP,
              "traceme: exec-stop (SIGTRAP) at new image");
        // resume — the dummy ptrtest image exits 42
        ptrace(PT_CONT, c, 0, 0);
        check(waitpid(c, &st, 0) == c && WIFEXITED(st)
              && WEXITSTATUS(st) == 42,
              "traceme: exec'd image runs and exits");
    }

    // ---------- ATTACH + GETREGS/SETREGS + PEEK/POKE ----------
    {
        pipe(pipe_fds);
        static volatile long probe = 0x1122334455667788L;
        probe = 0x1122334455667788L;
        pid_t c = fork();
        if (c == 0) {
            tell_parent();
            spin_forever();
        }
        wait_child_ready();
        check(ptrace(PT_ATTACH, c, 0, 0) == 0, "attach: ok");
        int st;
        check(stopped_at(c, &st) && stop_sig(st) == SIGSTOP,
              "attach: SIGSTOP delivery-stop reported");
        // reparented while traced: tracee's getppid should be us —
        // proven indirectly: wait4 WUNTRACED only reports for
        // children, and it just did.

        struct user_regs_struct rg;
        check(ptrace(PT_GETREGS, c, 0, &rg) == 0, "getregs: ok");
        check(rg.rip != 0 && rg.rsp != 0, "getregs: rip/rsp sane");

        // SETREGS: bump orig_rax, read back via GETREGS
        rg.orig_rax = 0x5a5a;
        check(ptrace(PT_SETREGS, c, 0, &rg) == 0, "setregs: ok");
        memset(&rg, 0, sizeof(rg));
        ptrace(PT_GETREGS, c, 0, &rg);
        check(rg.orig_rax == 0x5a5a, "setregs: orig_rax landed");

        // PEEKUSER at the orig_rax offset (15*8) agrees
        long v = ptrace(PT_PEEKUSER, c, (void *)(15 * 8), 0);
        check(v == 0x5a5a, "peekuser: orig_rax window");

        // PEEKDATA the child's `probe` — same binary, same address
        v = ptrace(PT_PEEKDATA, c, (void *)&probe, 0);
        check(v == 0x1122334455667788L, "peekdata: reads child mem");
        check(ptrace(PT_POKEDATA, c, (void *)&probe,
                     (void *)0xaabbccddeeff0011L) == 0,
              "pokedata: ok");
        v = ptrace(PT_PEEKDATA, c, (void *)&probe, 0);
        check(v == (long)0xaabbccddeeff0011L,
              "pokedata: write lands");

        // GETSIGINFO for the stop
        unsigned char si[128];
        memset(si, 0, sizeof(si));
        check(ptrace(PT_GETSIGINFO, c, 0, si) == 0, "getsiginfo: ok");
        check(*(int *)si == SIGSTOP, "getsiginfo: signo=SIGSTOP");

        // run-354: an out-of-range inject must EIO -- sig==32 used
        // to slip the `> 32` bound into pend_src[31] OOB (kernel
        // panic reachable from any tracer).
        errno = 0;
        check(ptrace(PT_CONT, c, 0, (void *)32) == -1 && errno == EIO,
              "CONT sig=32 -> EIO (out-of-range inject)");
        // no NEW wait event -> the EIO'd CONT left the stop standing
        // (a blocking waitpid would hang on the consumed report)
        check(waitpid(c, &st, WUNTRACED | WNOHANG) == 0,
              "sig=32 CONT leaves tracee stopped");

        // DETACH(32): the EIO must precede the detach side-effects
        // (Linux validates the signal first) — the trace stays
        // ours, so GETREGS still answers instead of ESRCH
        errno = 0;
        check(ptrace(PT_DETACH, c, 0, (void *)32) == -1 && errno == EIO,
              "DETACH sig=32 -> EIO, no detach");
        check(ptrace(PT_GETREGS, c, 0, &rg) == 0,
              "sig=32 DETACH leaves the trace attached");

        // SINGLESTEP: two steps must advance rip (or at least each
        // stop must report SIGTRAP)
        ptrace(PT_SINGLESTEP, c, 0, 0);
        check(stopped_at(c, &st) && stop_sig(st) == SIGTRAP,
              "singlestep: SIGTRAP after one insn");
        struct user_regs_struct rg2;
        ptrace(PT_GETREGS, c, 0, &rg2);
        ptrace(PT_SINGLESTEP, c, 0, 0);
        check(stopped_at(c, &st) && stop_sig(st) == SIGTRAP,
              "singlestep: second step stops");
        struct user_regs_struct rg3;
        ptrace(PT_GETREGS, c, 0, &rg3);
        check(rg3.rip != rg2.rip, "singlestep: rip advanced");

        // CONT with an injected signal — SIGUSR1 default kills? No:
        // inject SIGCONT which is benign, task resumes; then KILL.
        ptrace(PT_CONT, c, 0, 0);
        check(ptrace(PT_KILL, c, 0, 0) == 0, "kill: ok");
        // first wait may be the SIGKILL delivery-stop
        int st2;
        waitpid(c, &st2, WUNTRACED);
        if (WIFSTOPPED(st2) && stop_sig(st2) == SIGKILL) {
            ptrace(PT_CONT, c, 0, (void *)SIGKILL);
            waitpid(c, &st2, 0);
        }
        check(WIFSIGNALED(st2) && WTERMSIG(st2) == SIGKILL,
              "kill: dies by SIGKILL");
    }

    // ---------- SYSCALL entry/exit stops ----------
    {
        pipe(pipe_fds);
        pid_t c = fork();
        if (c == 0) {
            ptrace(PT_TRACEME, 0, 0, 0);
            raise(SIGSTOP);
            getpid();
            getpid();
            _exit(0);
        }
        int st;
        check(stopped_at(c, &st) && stop_sig(st) == SIGSTOP,
              "syscall: traceme signal-stop");
        int sysstops = 0, exitc = 0;
        for (int i = 0; i < 16; i++) {
            check(ptrace(PT_SYSCALL, c, 0, 0) == 0,
                  "syscall: resume ok");
            if (waitpid(c, &st, WUNTRACED) != c) break;
            if (WIFEXITED(st)) { exitc = WEXITSTATUS(st); break; }
            if (WIFSTOPPED(st) && stop_sig(st) == (SIGTRAP | 0x80))
                sysstops++;
            else if (WIFSTOPPED(st))
                ptrace(PT_CONT, c, 0, 0); // sail past other stops
        }
        check(sysstops >= 2, "syscall: entry+exit stops observed");
        check(exitc == 0, "syscall: child exits cleanly");
        // orig_rax during a syscall stop should be a syscall nr —
        // grab one via PEEKUSER mid-stop (best-effort: already
        // exited by now; check the loop instead recorded stops)
    }

    // ---------- orig_rax during a syscall-stop ----------
    {
        pipe(pipe_fds);
        pid_t c = fork();
        if (c == 0) {
            ptrace(PT_TRACEME, 0, 0, 0);
            raise(SIGSTOP);
            getpid();           // nr 39
            _exit(0);
        }
        int st;
        waitpid(c, &st, WUNTRACED);
        long orig = -1;
        for (int i = 0; i < 16; i++) {
            ptrace(PT_SYSCALL, c, 0, 0);
            if (waitpid(c, &st, WUNTRACED) != c || WIFEXITED(st)) break;
            if (WIFSTOPPED(st) && stop_sig(st) == (SIGTRAP | 0x80)) {
                orig = ptrace(PT_PEEKUSER, c, (void *)(15 * 8), 0);
                if (orig == 39) break; // saw getpid's entry-stop
            }
        }
        check(orig == 39, "syscall: orig_rax names getpid(39)");
        // detach — let it finish
        if (!WIFEXITED(st))
            ptrace(PT_DETACH, c, 0, 0), waitpid(c, &st, 0);
    }

    // ---------- suppression: CONT(0) drops the stopped signal ------
    {
        pipe(pipe_fds);
        pid_t c = fork();
        if (c == 0) {
            ptrace(PT_TRACEME, 0, 0, 0);
            raise(SIGUSR1);   // default-fatal unless the tracer eats it
            tell_parent();   // reached only if CONT(0) suppressed it
            _exit(0);
        }
        int st;
        check(stopped_at(c, &st) && stop_sig(st) == SIGUSR1,
              "suppress: SIGUSR1 delivery-stop");
        ptrace(PT_CONT, c, 0, 0); // suppress
        // tell_parent proves the suppressed fatal never landed
        wait_child_ready();
        check(waitpid(c, &st, 0) == c && WIFEXITED(st)
              && WEXITSTATUS(st) == 0, "suppress: child exits clean");
    }

    // ---------- reinjection: CONT(sig) re-delivers a replacement --
    {
        pid_t c = fork();
        if (c == 0) {
            ptrace(PT_TRACEME, 0, 0, 0);
            raise(SIGUSR1);      /* delivery-stop; gets replaced */
            _exit(0);
        }
        int st;
        check(stopped_at(c, &st) && stop_sig(st) == SIGUSR1,
              "reinject: SIGUSR1 delivery-stop");
        /* reinject a different default-fatal signal — the tracee
           must die by SIGUSR2, not stay stopped (bounded poll: a
           regression that leaves it Stopped fails, not hangs). */
        ptrace(PT_CONT, c, 0, (void *)SIGUSR2);
        struct timespec tp = {0, 100000000};
        int done = 0, tr = 0;
        while (tr++ < 50 && (done = waitpid(c, &st, WNOHANG)) == 0)
            nanosleep(&tp, NULL);
        check(done == c && WIFSIGNALED(st) && WTERMSIG(st) == SIGUSR2,
              "reinject: CONT(SIGUSR2) delivers fatal replacement");
        kill(c, SIGKILL);
        waitpid(c, &st, 0);
    }

    // ---------- delivery-stop on an armed suspend ends it ---------
    {
        pipe(pipe_fds);
        pid_t c = fork();
        if (c == 0) {
            ptrace(PT_TRACEME, 0, 0, 0);
            tell_parent();
            pause();            /* the SIGSTOP interrupts this wait */
            tell_parent();      /* suspend must EINTR out, not re-block */
            _exit(0);
        }
        wait_child_ready();
        int st;
        /* tiny race: SIGSTOP can land in the child's write->pause
           window, delivering before the suspend arms — then CONT
           resumes into a FRESH pause and this fails (bounded), so a
           flake here is the race, not necessarily a regression. */
        kill(c, SIGSTOP);       /* delivery-stop while suspended */
        check(stopped_at(c, &st) && stop_sig(st) == SIGSTOP,
              "suspend-stop: delivery-stop reported");
        ptrace(PT_CONT, c, 0, 0); /* suppress — suspend returns EINTR */
        /* bounded: the child exits only if the suspend EINTR'd —
           a wrongly re-blocked wait fails here instead of hanging */
        struct timespec tp = {0, 100000000};
        int done = 0, tr = 0;
        while (tr++ < 50 && (done = waitpid(c, &st, WNOHANG)) == 0)
            nanosleep(&tp, NULL);
        check(done == c && WIFEXITED(st),
              "suspend-stop: CONT ends suspend with EINTR");
        kill(c, SIGKILL);
        waitpid(c, &st, 0);
    }

    // ---------- error surface ----------
    {
        errno = 0;
        check(ptrace(PT_ATTACH, 99999, 0, 0) == -1 && errno == ESRCH,
              "attach: nonexistent -> ESRCH");
        errno = 0;
        check(ptrace(PT_ATTACH, getpid(), 0, 0) == -1 && errno == EPERM,
              "attach: self -> EPERM");
        errno = 0;
        check(ptrace(PT_CONT, 99999, 0, 0) == -1 && errno == ESRCH,
              "cont: nonexistent -> ESRCH");
        // not-our-tracee -> ESRCH
        pid_t c = fork();
        if (c == 0) { for (;;) pause(); }
        errno = 0;
        check(ptrace(PT_GETREGS, c, 0, (void *)pipe_fds) == -1
              && errno == ESRCH, "regs: untraced -> ESRCH");
        kill(c, SIGKILL);
        waitpid(c, 0, 0);
    }

    // ---------- DETACH restores the real parent ----------
    {
        pipe(pipe_fds);
        pid_t c = fork();
        if (c == 0) {
            tell_parent();
            for (;;) pause();
        }
        wait_child_ready();
        check(ptrace(PT_ATTACH, c, 0, 0) == 0, "detach: attach");
        int st;
        stopped_at(c, &st);
        check(ptrace(PT_DETACH, c, 0, 0) == 0, "detach: ok");
        // after detach the child runs free — kill it normally
        kill(c, SIGKILL);
        check(waitpid(c, &st, 0) == c && WIFSIGNALED(st),
              "detach: reparented child reapable");
    }

    printf("ptrtest: %d failures\n", fails);
    return fails;
}
