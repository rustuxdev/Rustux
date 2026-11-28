// credtest — credentials block (102/104-108/113-120/125/126)
// + execveat (322). The uid stores to t.uid (setuid's value is
// observable); gid/groups/caps collapse to the root model.
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <signal.h>
#include <time.h>

/* no sys/capability.h in this toolchain — raw ABI values */
#define CAP_V1 0x19980330u
#define CAP_V3 0x20080522u

static int fails;
static volatile sig_atomic_t cred_pgot;
static void cred_usr2(int s) { (void)s; cred_pgot = 1; }
static volatile sig_atomic_t cred_cgot;
static void cred_cusr2(int s) { (void)s; cred_cgot = 1; }
#define check(c, msg) do { \
    if (c) printf("credtest: %-40s ok\n", msg); \
    else { printf("credtest: %-40s FAIL\n", msg); fails++; } \
} while (0)

#ifndef SYS_execveat
#define SYS_execveat 322
#endif

int main(int argc, char **argv) {
    if (argc > 1 && !strcmp(argv[1], "--execd")) {
        return 42; /* execveat positive path proof */
    }
    printf("credtest: uid/gid/groups/caps + execveat\n");

    // --- uid/gid getters
    check(syscall(SYS_getuid) == 0, "getuid root 0");
    check(syscall(SYS_geteuid) == 0, "geteuid root 0");
    check(syscall(SYS_getgid) == 0, "getgid root 0");
    check(syscall(SYS_getegid) == 0, "getegid root 0");

    // --- setuid stores; getuid reports it
    check(syscall(SYS_setuid, 1000L) == 0, "setuid 1000 ok");
    check(syscall(SYS_getuid) == 1000, "getuid after setuid");
    errno = 0;
    check(syscall(SYS_setuid, 4294967295L) == -1 && errno == EINVAL,
          "setuid -1 EINVAL");
    // --- setreuid/setresuid: -1 keeps, effective wins
    check(syscall(SYS_setreuid, -1L, 1001L) == 0, "setreuid euid");
    check(syscall(SYS_getuid) == 1001, "setreuid effective wins");
    check(syscall(SYS_setresuid, -1L, -1L, -1L) == 0, "setresuid all-keep");
    check(syscall(SYS_getuid) == 1001, "setresuid keep leaves uid");
    check(syscall(SYS_setresuid, -1L, -1L, 0L) == 0, "setresuid suid");
    check(syscall(SYS_getuid) == 0, "setresuid suid restores");
    check(syscall(SYS_setuid, 0L) == 0, "setuid back to 0");
    // fork inherits the stored uid — Linux creds copy at fork
    check(syscall(SYS_setuid, 1002L) == 0, "setuid 1002 for fork");
    pid_t fp = fork();
    if (fp == 0) {
        _exit(syscall(SYS_getuid) == 1002 ? 7 : 8);
    }
    int fst = 0;
    waitpid(fp, &fst, 0);
    check(WIFEXITED(fst) && WEXITSTATUS(fst) == 7, "fork inherits uid");
    check(syscall(SYS_setuid, 0L) == 0, "setuid back to 0 post");

    // --- getresuid/getresgid write-back
    uint32_t r = 9, e = 9, s = 9;
    check(syscall(SYS_getresuid, &r, &e, &s) == 0 && r == 0 && e == 0 && s == 0,
          "getresuid triple 0");
    errno = 0;
    check(syscall(SYS_getresuid, (uint32_t *)0x1, &e, &s) == -1 && errno == EFAULT,
          "getresuid bad ptr EFAULT");
    r = 9; e = 9; s = 9;
    check(syscall(SYS_getresgid, &r, &e, &s) == 0 && r == 0 && e == 0 && s == 0,
          "getresgid triple 0");

    // --- gid/groups setters collapse
    check(syscall(SYS_setgid, 0L) == 0, "setgid 0 ok");
    errno = 0;
    check(syscall(SYS_setgid, 4294967295L) == -1 && errno == EINVAL,
          "setgid -1 EINVAL");
    check(syscall(SYS_setregid, -1L, -1L) == 0, "setregid keep");
    check(syscall(SYS_setresgid, -1L, -1L, -1L) == 0, "setresgid keep");
    gid_t g[1] = {0};
    check(syscall(SYS_setgroups, 0L, 0) == 0, "setgroups empty");
    check(syscall(SYS_setgroups, 1L, g) == 0, "setgroups one");
    errno = 0;
    check(syscall(SYS_setgroups, 70000L, g) == -1 && errno == EINVAL,
          "setgroups > NGROUPS_MAX EINVAL");
    errno = 0;
    check(syscall(SYS_setgroups, 1L, (gid_t *)0x1) == -1 && errno == EFAULT,
          "setgroups bad ptr EFAULT");
    check(syscall(SYS_getgroups, 8, g) == 0, "getgroups empty list");

    // --- capget/capset
    struct { uint32_t version; int32_t pid; } hdr = { CAP_V3, 0 };
    uint32_t dat[6] = {0};
    check(syscall(SYS_capget, &hdr, dat) == 0, "capget v3");
    /* {eff,perm,inh} interleaved per u32s: 0-2 low, 3-5 high */
    check(dat[0] == 0xffffffffu, "capget effective lo all-set");
    check((dat[3] & 0x1ff) == 0x1ff, "capget effective hi 40 bits");
    check(dat[1] == 0xffffffffu, "capget permitted lo all-set");
    check(dat[2] == 0 && dat[5] == 0, "capget inheritable 0");
    errno = 0;
    check(syscall(SYS_capget, (void *)0x1, dat) == -1 && errno == EFAULT,
          "capget bad hdr EFAULT");
    hdr.version = 0xdeadbeef;
    errno = 0;
    check(syscall(SYS_capget, &hdr, dat) == -1 && errno == EINVAL,
          "capget bad version EINVAL");
    check(hdr.version == CAP_V3, "capget rewrites version");
    hdr.version = CAP_V3;
    hdr.pid = 99999; /* dead pid */
    errno = 0;
    check(syscall(SYS_capget, &hdr, dat) == -1 && errno == ESRCH,
          "capget dead pid ESRCH");
    hdr.pid = 0;
    check(syscall(SYS_capget, &hdr, 0) == 0, "capget hdr only");
    check(syscall(SYS_capset, &hdr, dat) == 0, "capset self");
    hdr.pid = 1; /* another task */
    errno = 0;
    check(syscall(SYS_capset, &hdr, dat) == -1 && errno == EPERM,
          "capset other pid EPERM");
    hdr.pid = 0;
    errno = 0;
    check(syscall(SYS_capset, &hdr, 0) == -1 && errno == EFAULT,
          "capset NULL datap EFAULT");

    // --- execveat: errno ladder
    errno = 0;
    check(syscall(SYS_execveat, -100, "hello", 0, 0, 0x200) == -1 && errno == EINVAL,
          "execveat bad flags EINVAL");
    errno = 0;
    check(syscall(SYS_execveat, -100, "", 0, 0, 0) == -1 && errno == ENOENT,
          "execveat empty no-flag ENOENT");
    errno = 0;
    check(syscall(SYS_execveat, 7, "", 0, 0, 0x1000) == -1 && errno == EBADF,
          "execveat empty bad fd EBADF");
    // positive: fork + execveat self with a marker arg
    pid_t p = fork();
    if (p == 0) {
        char *const a[] = { (char *)"credtest", (char *)"--execd", 0 };
        syscall(SYS_execveat, -100, "credtest", a, 0, 0);
        _exit(111);
    }
    int st = 0;
    waitpid(p, &st, 0);
    check(WIFEXITED(st) && WEXITSTATUS(st) == 42, "execveat relative exec");
    // AT_EMPTY_PATH: open self, exec the fd
    int fd = open("credtest", O_RDONLY);
    check(fd >= 0, "open credtest for EMPTY_PATH");
    p = fork();
    if (p == 0) {
        char *const a[] = { (char *)"credtest", (char *)"--execd", 0 };
        syscall(SYS_execveat, fd, "", a, 0, 0x1000);
        printf("credtest: EMPTY_PATH errno=%d\n", errno);
        _exit(112);
    }
    st = 0;
    waitpid(p, &st, 0);
    check(WIFEXITED(st) && WEXITSTATUS(st) == 42, "execveat AT_EMPTY_PATH");
    close(fd);

    /* --- run-357: signal permission checks (kill_ok_by_cred) --
       Linux: uid0 signals all; same-uid + same-tgid pass; SIGCONT
       to a same-session task is the one cross-uid allowance; the
       sig0 probe answers EPERM for found-but-denied. ---------- */
    {
        /* nonroot child vs uid-0 parent: send + probe EPERM,
           SIGCONT same-session allowed, self-probe ok. */
        pid_t c = fork();
        if (c == 0) {
            if (syscall(SYS_setuid, 1000L) != 0) _exit(9);
            pid_t p0 = getppid();
            long r1, r2, r3, r4;
            errno = 0; r1 = syscall(SYS_kill, p0, 10); int e1 = errno;
            errno = 0; r2 = syscall(SYS_kill, p0, 0);  int e2 = errno;
            errno = 0; r3 = syscall(SYS_kill, p0, 18); /* SIGCONT */
            errno = 0; r4 = syscall(SYS_kill, getpid(), 0);
            _exit(r1 == -1 && e1 == EPERM &&
                  r2 == -1 && e2 == EPERM &&
                  r3 == 0 && r4 == 0 ? 0 : 1);
        }
        int st2 = 0;
        waitpid(c, &st2, 0);
        check(WEXITSTATUS(st2) == 0,
              "kill cred: cross-uid EPERM, SIGCONT same-session ok");
        /* tgkill: 0 ids EINVAL; tid outside tgid ESRCH; cross-uid
           EPERM. All from a nonroot child. */
        c = fork();
        if (c == 0) {
            if (syscall(SYS_setuid, 1000L) != 0) _exit(9);
            errno = 0;
            long r1 = syscall(SYS_tgkill, 0, getpid(), 10);
            int e1 = errno;
            errno = 0;
            long r2 = syscall(SYS_tgkill, getppid(), getpid(), 10);
            int e2 = errno;
            errno = 0;
            long r3 = syscall(SYS_tkill, getppid(), 10);
            int e3 = errno;
            errno = 0;
            long r4 = syscall(SYS_tgkill, getpid(), getpid(), 0);
            errno = 0;
            /* negative ids are Linux pid_t <=0 -> EINVAL, never the
               kill() broadcast/group selectors via tgkill. */
            long r5 = syscall(SYS_tgkill, getpid(), -1L, 10);
            int e5 = errno;
            errno = 0;
            long r6 = syscall(SYS_tgkill, getpid(), -2L, 10);
            int e6 = errno;
            errno = 0;
            long r7 = syscall(SYS_tkill, -1L, 10);
            int e7 = errno;
            _exit(r1 == -1 && e1 == EINVAL &&
                  r2 == -1 && e2 == ESRCH &&
                  r3 == -1 && e3 == EPERM &&
                  r4 == 0 &&
                  r5 == -1 && e5 == EINVAL &&
                  r6 == -1 && e6 == EINVAL &&
                  r7 == -1 && e7 == EINVAL ? 0 : 1);
        }
        st2 = 0;
        waitpid(c, &st2, 0);
        check(WEXITSTATUS(st2) == 0,
              "tgkill: 0 EINVAL, wrong-tgid ESRCH, cross-uid EPERM");
        /* kill(-1): filters per-target permission — a uid-1000
           sibling gets the broadcast, the uid-0 parent must not. */
        {
            struct sigaction sa2 = {0};
            sa2.sa_handler = cred_usr2;
            sigaction(SIGUSR2, &sa2, NULL);
            /* arm pipe: C1 broadcasts only after C2's setuid ran
               — the uid filter is evaluated at SEND time, so an
               unarmed sibling is denied, not pended. */
            int arm[2];
            check(pipe(arm) == 0, "kill-1 arm pipe");
            pid_t c1 = fork(); /* sender */
            if (c1 == 0) {
                close(arm[1]);
                syscall(SYS_setuid, 1000L);
                char r;
                ssize_t _r = read(arm[0], &r, 1);
                (void)_r;
                long rr = syscall(SYS_kill, -1, SIGUSR2);
                _exit(rr == 0 ? 0 : 2);
            }
            close(arm[0]);
            pid_t c2 = fork(); /* same-uid receiver */
            if (c2 == 0) {
                struct sigaction sc = {0};
                sc.sa_handler = cred_cusr2;
                sigaction(SIGUSR2, &sc, NULL);
                syscall(SYS_setuid, 1000L);
                char r = 'R';
                if (write(arm[1], &r, 1)) {}
                close(arm[1]);
                for (int i = 0; i < 150 && !cred_cgot; i++) {
                    struct timespec ts = {0, 10000000};
                    nanosleep(&ts, NULL);
                }
                _exit(cred_cgot ? 0 : 1);
            }
            close(arm[1]);
            waitpid(c1, &st2, 0);
            check(WEXITSTATUS(st2) == 0, "kill(-1) returns 0");
            st2 = 0;
            waitpid(c2, &st2, 0);
            check(WEXITSTATUS(st2) == 0, "kill(-1) reaches same-uid");
            check(!cred_pgot, "kill(-1) skips denied uid0 task");
        }
        /* group-kill ret: Linux __kill_pgrp_info answers 0 when
           ANY member is permitted — a denied uid-0 sibling in the
           same pgid must not flip it to EPERM. */
        {
            int arm[2];
            check(pipe(arm) == 0, "grpkill arm pipe");
            pid_t s = fork(); /* nonroot sender */
            if (s == 0) {
                syscall(SYS_setuid, 1000L);
                close(arm[1]);
                char r;
                ssize_t _r = read(arm[0], &r, 1);
                (void)_r;
                long rr = syscall(SYS_kill, -getpgrp(), SIGURG);
                _exit(rr == 0 ? 0 : 2);
            }
            close(arm[0]);
            pid_t b = fork(); /* uid-0 sibling, same pgid */
            if (b == 0) {
                char r = 'R';
                if (write(arm[1], &r, 1)) {}
                close(arm[1]);
                pause();
                _exit(0);
            }
            close(arm[1]);
            st2 = 0;
            waitpid(s, &st2, 0);
            check(WEXITSTATUS(st2) == 0,
                  "kill(-pgid): permitted member answers 0");
            kill(b, SIGKILL);
            waitpid(b, NULL, 0);
        }
        /* rt_sigqueueinfo rides the same cred gate: cross-uid
           send to the uid-0 parent EPERMs. */
        {
            pid_t q = fork();
            if (q == 0) {
                if (syscall(SYS_setuid, 1000L) != 0) _exit(9);
                siginfo_t si;
                memset(&si, 0, sizeof si);
                si.si_signo = SIGUSR1;
                si.si_code = SI_QUEUE;
                si.si_pid = getpid();
                si.si_uid = getuid();
                errno = 0;
                long r = syscall(SYS_rt_sigqueueinfo,
                                 getppid(), SIGUSR1, &si);
                _exit(r == -1 && errno == EPERM ? 0 : 1);
            }
            st2 = 0;
            waitpid(q, &st2, 0);
            check(WEXITSTATUS(st2) == 0,
                  "rt_sigqueueinfo: cross-uid EPERM");
        }
    }

    printf("credtest: %d failures\n", fails);
    return fails;
}
