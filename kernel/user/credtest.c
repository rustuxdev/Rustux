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

/* no sys/capability.h in this toolchain — raw ABI values */
#define CAP_V1 0x19980330u
#define CAP_V3 0x20080522u

static int fails;
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

    printf("credtest: %d failures\n", fails);
    return fails;
}
