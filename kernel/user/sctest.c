// sctest — seccomp(317) + prctl arms: strict kills, cBPF filter
// ERRNO/TRAP/KILL verdicts, stacking, inheritance, errno ladder.
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/prctl.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>

static int fails;
static void check(int ok, const char *what) {
    if (!ok) {
        printf("FAIL: %s\n", what);
        fails++;
    }
}

static long sec3(long op, long flags, void *u) {
    return syscall(317, op, flags, u);
}

// errno on <nr>, KILL on <nr2>, allow rest
static void mk_errnokill(struct sock_filter *f, int n1, int n2) {
    struct sock_filter p[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, n1, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, n2, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    memcpy(f, p, sizeof(p));
}

static int wait_child(pid_t c) {
    int st;
    waitpid(c, &st, 0);
    return st;
}

int main(void) {
    // ---- GET_ACTION_AVAIL / NOTIF_SIZES -------------------------
    check(sec3(2, SECCOMP_RET_ALLOW, 0) == 0, "avail ALLOW");
    check(sec3(2, SECCOMP_RET_KILL_PROCESS, 0) == 0, "avail KILL_P");
    check(sec3(2, SECCOMP_RET_ERRNO, 0) == 0, "avail ERRNO");
    check(sec3(2, SECCOMP_RET_TRAP, 0) == 0, "avail TRAP");
    check(sec3(2, SECCOMP_RET_LOG, 0) == 0, "avail LOG");
    errno = 0;
    check(sec3(2, SECCOMP_RET_TRACE, 0) < 0 && errno == EOPNOTSUPP,
          "TRACE unsupported");
    errno = 0;
    check(sec3(2, SECCOMP_RET_USER_NOTIF, 0) < 0
          && errno == EOPNOTSUPP, "NOTIF unsupported");
    unsigned short sz[3] = {0};
    check(sec3(3, 0, sz) == 0 && sz[0] == 80 && sz[1] == 32
          && sz[2] == 64, "notif sizes");

    // ---- errno ladder (non-installing inputs first) ------------
    errno = 0;
    check(sec3(9, 0, 0) < 0 && errno == EINVAL, "bad op EINVAL");
    errno = 0;
    check(sec3(0, 1, 0) < 0 && errno == EINVAL,
          "strict flags EINVAL");
    errno = 0;
    check(sec3(0, 0, (void*)1) < 0 && errno == EINVAL,
          "strict uargs EINVAL");
    errno = 0;
    check(sec3(1, 1, 0) < 0 && errno == EINVAL,
          "filter flags EINVAL");
    errno = 0;
    check(sec3(1, 0, (void*)0xdead) < 0 && errno == EFAULT,
          "filter bad fprog EFAULT");
    struct sock_filter allow1[] = {
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog fp = { 1, allow1 };
    struct sock_fprog bad = { 0, allow1 };
    errno = 0;
    check(sec3(1, 0, &bad) < 0 && errno == EINVAL,
          "len 0 EINVAL");
    struct sock_fprog bad2 = { 600, allow1 };
    errno = 0;
    check(sec3(1, 0, &bad2) < 0 && errno == EINVAL,
          "oversize EINVAL");
    struct sock_filter noret[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 0),
    };
    struct sock_fprog bad3 = { 1, noret };
    errno = 0;
    check(sec3(1, 0, &bad3) < 0 && errno == EINVAL,
          "no-RET EINVAL");
    struct sock_filter oob[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 80),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog bad4 = { 2, oob };
    errno = 0;
    check(sec3(1, 0, &bad4) < 0 && errno == EINVAL,
          "OOB-load EINVAL");
    struct sock_filter bj[] = {
        BPF_JUMP(BPF_JMP | BPF_JA, 99, 0, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog bad5 = { 2, bj };
    errno = 0;
    check(sec3(1, 0, &bad5) < 0 && errno == EINVAL,
          "bad-JA EINVAL");

    // ---- children run BEFORE main mutates its own state ----------

    // filter verdict: ERRNO
    pid_t c = fork();
    if (c == 0) {
        struct sock_filter ins[6];
        mk_errnokill(ins, __NR_getpid, __NR_getuid + 1000);
        struct sock_fprog p = { 6, ins };
        if (sec3(1, 0, &p) != 0) _exit(90);
        // raw syscall(): glibc's getpid can't fail and never
        // installs errno — syscall(2) does.
        errno = 0;
        if (syscall(__NR_getpid) != -1 || errno != EPERM) _exit(91);
        if (getppid() <= 0) _exit(92);
        _exit(0);
    }
    int st = wait_child(c);
    check(WIFEXITED(st) && WEXITSTATUS(st) == 0,
          "filter ERRNO verdict");

    // filter verdict: KILL kills the child
    c = fork();
    if (c == 0) {
        struct sock_filter ins[6];
        mk_errnokill(ins, 9999, __NR_getpid);
        struct sock_fprog p = { 6, ins };
        if (sec3(1, 0, &p) != 0) _exit(90);
        getpid();               // -> KILL_PROCESS verdict
        _exit(95);              // unreachable
    }
    st = wait_child(c);
    check(WIFSIGNALED(st) && WTERMSIG(st) == 9,
          "filter KILL_PROCESS");

    // inherited filter hits the grandchild
    c = fork();
    if (c == 0) {
        struct sock_filter ins[6];
        mk_errnokill(ins, __NR_getpid, __NR_getuid + 1000);
        struct sock_fprog p = { 6, ins };
        if (sec3(1, 0, &p) != 0) _exit(90);
        pid_t g = fork();
        if (g == 0) {
            errno = 0;
            if (syscall(__NR_getpid) != -1 || errno != EPERM)
                _exit(93);
            _exit(0);
        }
        int st2 = wait_child(g);
        _exit(WIFEXITED(st2) ? WEXITSTATUS(st2) : 96);
    }
    st = wait_child(c);
    check(WIFEXITED(st) && WEXITSTATUS(st) == 0,
          "filter inherited across fork");

    // TRAP verdict delivers SIGSYS
    c = fork();
    if (c == 0) {
        struct sock_filter ins[] = {
            BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 0),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_getppid, 0, 1),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        };
        struct sock_fprog p = { 4, ins };
        if (sec3(1, 0, &p) != 0) _exit(90);
        getppid();              // -> TRAP -> SIGSYS
        _exit(95);
    }
    st = wait_child(c);
    check(WIFSIGNALED(st) && WTERMSIG(st) == SIGSYS,
          "filter TRAP SIGSYS");

    // strict mode kills any non-allowed syscall
    c = fork();
    if (c == 0) {
        if (sec3(0, 0, 0) != 0) _exit(90);
        getpid();               // not in {r,w,exit,sigret} -> dead
        _exit(95);
    }
    st = wait_child(c);
    check(WIFSIGNALED(st) && WTERMSIG(st) == 9,
          "strict kills foreign syscall");

    // nonroot install needs nnp
    c = fork();
    if (c == 0) {
        if (setuid(1000) != 0) _exit(9);
        int bad = 0;
        errno = 0;
        if (sec3(0, 0, 0) != -1 || errno != EACCES)
            bad++;
        if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0)
            bad++;
        if (sec3(0, 0, 0) != 0) // strict installs fine with nnp
            bad++;
        _exit(bad);
    }
    st = wait_child(c);
    check(WIFEXITED(st) && WEXITSTATUS(st) == 0,
          "nonroot EACCES then nnp-ok");

    // ---- main mutates its own state LAST -------------------------
    check(prctl(PR_GET_SECCOMP, 0, 0, 0, 0) == 0,
          "PR_GET_SECCOMP = disabled");
    check(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0,
          "SET_NO_NEW_PRIVS");
    check(prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) == 1,
          "GET_NO_NEW_PRIVS");
    errno = 0;
    check(prctl(PR_SET_NO_NEW_PRIVS, 0, 0, 0, 0) < 0
          && errno == EINVAL, "nnp arg EINVAL");
    check(sec3(1, 0, &fp) == 0, "allow-all install ok");
    check(sec3(1, 0, &fp) == 0, "stacked second filter ok");
    check(prctl(PR_GET_SECCOMP, 0, 0, 0, 0) == 2,
          "PR_GET_SECCOMP = filter");
    check(prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &fp, 0, 0) == 0,
          "PR_SET_SECCOMP filter");
    // ratchet: strict under filter is EINVAL, and a bad-mode call too
    errno = 0;
    check(sec3(0, 0, 0) < 0 && errno == EINVAL,
          "strict-over-filter EINVAL");
    errno = 0;
    check(prctl(PR_SET_SECCOMP, 9, 0, 0, 0) < 0 && errno == EINVAL,
          "prctl bad mode EINVAL");
    check(getpid() > 0, "main still runs filtered");

    printf("sctest: %d failures\n", fails);
    return fails;
}
