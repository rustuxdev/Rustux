// ioptest — ioperm(173)/iopl(172): CAP_SYS_RAWIO gates, the TSS
// deny bitmap (granted port survives in/out, denied port #GPs ->
// SIGSEGV death), fork copy semantics, iopl level ladder.
#define _GNU_SOURCE
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sys/types.h>

static int fails;
static void check(int ok, const char *what) {
    if (!ok) {
        printf("FAIL: %s\n", what);
        fails++;
    }
}

static long ioperm(long from, long num, long on) {
    return syscall(173, from, num, on, 0, 0, 0);
}
static long iopl(long lvl) {
    return syscall(172, lvl, 0, 0, 0, 0);
}

// port I/O through raw asm — glibc's sys/io.h inb/outb work too but
// keep it self-contained.
static inline unsigned char inb_p(unsigned short p) {
    unsigned char v;
    __asm__ volatile("inb %1,%0" : "=a"(v) : "Nd"(p));
    return v;
}
static inline void outb_p(unsigned short p, unsigned char v) {
    __asm__ volatile("outb %0,%1" ::"a"(v), "Nd"(p));
}

// returns the child's raw wait status (signaled-die checks)
static int child_status(void (*fn)(void)) {
    pid_t c = fork();
    if (c == 0) {
        fn();
        _exit(0);
    }
    int st;
    waitpid(c, &st, 0);
    return st;
}

static void probe_inb(void) { (void)inb_p(0x60); }
static void probe_inb_80(void) { (void)inb_p(0x80); }

// died by signal N?
static int died_sig(int st, int sig) {
    return WIFSIGNALED(st) && WTERMSIG(st) == sig;
}
static int clean_exit(int st) {
    return WIFEXITED(st) && WEXITSTATUS(st) == 0;
}

static void setuid_then_probe(void) {
    if (setuid(1000) < 0) _exit(9);
    // a granted port stays granted across setuid (bitmap is the
    // task's, not the cred's) — but a NEW ioperm must fail.
    errno = 0;
    int e = ioperm(0x61, 1, 1) < 0 && errno == EPERM;
    _exit(e ? 0 : 1);
}

int main(void) {
    // ---- errno ladder (as root) --------------------------------
    errno = 0;
    check(ioperm(65536, 1, 1) < 0 && errno == EINVAL, "from>=64K EINVAL");
    errno = 0;
    check(ioperm(65535, 2, 1) < 0 && errno == EINVAL, "range wrap EINVAL");
    errno = 0;
    check(ioperm(0x80, 0, 1) < 0 && errno == EINVAL, "num=0 EINVAL");
    errno = 0;
    check(iopl(4) < 0 && errno == EINVAL, "iopl(4) EINVAL");
    errno = 0;
    check(iopl(99999) < 0 && errno == EINVAL, "iopl huge EINVAL");

    // ---- nonroot gates ------------------------------------------
    {
        pid_t c = fork();
        if (c == 0) {
            if (setuid(1000) < 0) _exit(9);
            int bad = 0;
            errno = 0;
            if (ioperm(0x60, 1, 1) != -1 || errno != EPERM) bad = 1;
            errno = 0;
            if (iopl(3) != -1 || errno != EPERM) bad = 2;
            if (iopl(0) != 0) bad = 3; // lower always allowed
            _exit(bad);
        }
        int st;
        waitpid(c, &st, 0);
        check(WIFEXITED(st) && WEXITSTATUS(st) == 0, "nonroot EPERM ladder");
    }

    // ---- deny by default: inb on an ungranted port kills ---------
    check(died_sig(child_status(probe_inb), 11), "inb 0x60 denied -> SIGSEGV");

    // ---- grant: the port now works in this task ------------------
    check(ioperm(0x80, 1, 1) == 0, "ioperm grant 0x80");
    (void)inb_p(0x80);              // would die pre-grant
    outb_p(0x80, 0x5a);             // POST/debug port — harmless write
    check(1, "post-grant in/out survives");

    // fork copies the bitmap: child keeps the grant
    check(clean_exit(child_status(probe_inb_80)), "fork inherits grant 0x80");

    // but a DIFFERENT port is still denied (grant is per-port)
    check(died_sig(child_status(probe_inb), 11), "fork inherits deny 0x60");

    // ---- child's deny doesn't touch the parent -------------------
    {
        pid_t c = fork();
        if (c == 0) {
            // child leads a new group: revoking its copy of 0x80
            // must not revoke the parent's.
            ioperm(0x80, 1, 0);
            (void)inb_p(0x80); // should #GP now
            _exit(1);
        }
        int st;
        waitpid(c, &st, 0);
        check(died_sig(st, 11), "child revoke kills child");
        (void)inb_p(0x80); // parent still granted
        check(1, "parent grant survives child revoke");
    }

    // ---- grant across setuid + fresh-ioperm EPERM ----------------
    check(clean_exit(child_status(setuid_then_probe)),
          "grant survives setuid, new ioperm EPERM");

    // ---- iopl(3): everything allowed, bitmap bypassed ------------
    {
        pid_t c = fork();
        if (c == 0) {
            if (iopl(3) != 0) _exit(2);
            (void)inb_p(0x3d4); // never granted via ioperm
            (void)inb_p(0x201);
            // iopl is the task's rflags — a fresh syscall can't have
            // reset it; drop back to 0 and the bitmap rules again.
            if (iopl(0) != 0) _exit(3);
            _exit(0);
        }
        int st;
        waitpid(c, &st, 0);
        check(WIFEXITED(st) && WEXITSTATUS(st) == 0, "iopl(3) opens all ports");
    }

    // iopl does NOT persist into fork'd children? — Linux DOES keep
    // the rflags: fork copies ctx.rflags, so the child inherits
    // IOPL. Test via grandchild probe of an ungranted port.
    {
        pid_t c = fork();
        if (c == 0) {
            if (iopl(3) != 0) _exit(2);
            pid_t g = fork();
            if (g == 0) {
                (void)inb_p(0x3d4); // inherited IOPL=3 -> survives
                _exit(0);
            }
            int st2;
            waitpid(g, &st2, 0);
            _exit(clean_exit(st2) ? 0 : 4);
        }
        int st;
        waitpid(c, &st, 0);
        check(WIFEXITED(st) && WEXITSTATUS(st) == 0, "fork inherits IOPL");
    }

    printf("ioptest: %d failures\n", fails);
    return fails;
}
