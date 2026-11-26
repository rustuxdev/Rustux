// oa2test — compiled openat2(437)/process_mrelease(448) ABI proof.
// openat2's open_how {flags,mode,resolve}: size windows like
// clone3, unknown resolve bits + BENEATH|IN_ROOT EINVAL, and the
// scoped-resolution gates — BENEATH pins to dirfd (abs path and
// '..' escape EXDEV), IN_ROOT clamps '..' at the dirfd-as-root
// floor, NO_SYMLINKS ELOOPs a traversed link, NO_MAGICLINKS
// ELOOPs /proc/self/fd/<n>. process_mrelease EINVALs flags and
// live targets, ESRCHs reaped ones, returns 0 on a zombie.
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <poll.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sys/stat.h>

#ifndef SYS_openat2
#define SYS_openat2 437
#endif
#ifndef SYS_process_mrelease
#define SYS_process_mrelease 448
#endif
#ifndef RESOLVE_NO_XDEV
#define RESOLVE_NO_XDEV        0x01
#define RESOLVE_NO_MAGICLINKS  0x02
#define RESOLVE_NO_SYMLINKS    0x04
#define RESOLVE_BENEATH        0x08
#define RESOLVE_IN_ROOT        0x10
#define RESOLVE_CACHED         0x20
#endif

static int fails;
static void say(const char *s) { write(1, s, strlen(s)); }
static void check(int ok, const char *what) {
    char buf[80];
    snprintf(buf, sizeof(buf), "oa2test: %-34s %s\n",
             what, ok ? "ok" : "FAIL");
    say(buf);
    if (!ok) fails++;
}

struct how { unsigned long long flags, mode, resolve; };

static int oa2(int dfd, const char *p, struct how *h, unsigned long sz) {
    return syscall(SYS_openat2, dfd, p, h, sz);
}

int main(void) {
    struct how h = { O_RDONLY, 0, 0 };
    struct stat st;

    // ---- open_how shape gates ----
    check(oa2(AT_FDCWD, "/dev/null", &h, 8) < 0 && errno == EINVAL,
          "size<24 EINVAL");
    check(oa2(AT_FDCWD, "/dev/null", &h, 4097) < 0 && errno == E2BIG,
          "size>page E2BIG");
    char big[32]; memset(big, 0, sizeof(big));
    memcpy(big, &h, 24); big[30] = 7;
    check(oa2(AT_FDCWD, "/dev/null", (struct how *)big, 32) < 0
          && errno == E2BIG, "nonzero tail E2BIG");
    big[30] = 0;
    int fd = oa2(AT_FDCWD, "/dev/null", (struct how *)big, 32);
    check(fd >= 0, "zero tail ok");
    close(fd);
    h.resolve = 0x40;
    check(oa2(AT_FDCWD, "/dev/null", &h, 24) < 0 && errno == EINVAL,
          "unknown resolve EINVAL");
    h.resolve = RESOLVE_BENEATH | RESOLVE_IN_ROOT;
    check(oa2(AT_FDCWD, "/dev/null", &h, 24) < 0 && errno == EINVAL,
          "BENEATH|IN_ROOT EINVAL");

    // ---- basic open through openat2 ----
    h.flags = O_RDONLY; h.mode = 0; h.resolve = 0;
    fd = oa2(AT_FDCWD, "/motd.txt", &h, 24);
    check(fd >= 0, "openat2 plain open");
    check(fd >= 0 && fstat(fd, &st) == 0, "opened fd valid");
    close(fd);

    // ---- BENEATH: pinned to dirfd ----
    int dd = open("/dev", O_RDONLY | O_DIRECTORY);
    check(dd >= 0, "dirfd /dev");
    h.resolve = RESOLVE_BENEATH;
    fd = oa2(dd, "null", &h, 24);
    check(fd >= 0, "BENEATH inside ok");
    close(fd);
    check(oa2(dd, "../etc/passwd", &h, 24) < 0 && errno == EXDEV,
          "BENEATH .. escape EXDEV");
    check(oa2(dd, "/null", &h, 24) < 0 && errno == EXDEV,
          "BENEATH absolute EXDEV");
    check(oa2(dd, "..", &h, 24) < 0 && errno == EXDEV,
          "BENEATH lone .. EXDEV");
    fd = oa2(dd, ".", &h, 24);
    check(fd >= 0, "BENEATH dot ok");
    close(fd);
    // A link INSIDE the subtree whose target escapes it is the
    // same class of escape: the resolved name must stay under
    // the dirfd.
    check(symlink("/motd.txt", "/dev/oa2esc") == 0, "esc link minted");
    check(oa2(dd, "oa2esc", &h, 24) < 0 && errno == EXDEV,
          "BENEATH link-escape EXDEV");
    unlink("/dev/oa2esc");
    check(symlink("../motd.txt", "/dev/oa2esc") == 0,
          "esc rel link minted");
    check(oa2(dd, "oa2esc", &h, 24) < 0 && errno == EXDEV,
          "BENEATH rel-link escape EXDEV");
    unlink("/dev/oa2esc");
    check(symlink("null", "/dev/oa2ok") == 0, "inside link minted");
    fd = oa2(dd, "oa2ok", &h, 24);
    check(fd >= 0, "BENEATH inside link ok");
    close(fd);
    unlink("/dev/oa2ok");

    // ---- IN_ROOT: dirfd is the root ----
    h.resolve = RESOLVE_IN_ROOT;
    fd = oa2(dd, "/null", &h, 24);
    check(fd >= 0, "IN_ROOT absolute-under-root ok");
    close(fd);
    fd = oa2(dd, "../null", &h, 24);
    check(fd >= 0, "IN_ROOT .. clamps at floor");
    close(fd);
    fd = oa2(dd, "../../null", &h, 24);
    check(fd >= 0, "IN_ROOT deep .. clamps");
    close(fd);
    close(dd);

    // ---- NO_XDEV / CACHED: structurally satisfied ----
    h.resolve = RESOLVE_NO_XDEV | RESOLVE_CACHED;
    fd = oa2(AT_FDCWD, "/dev/null", &h, 24);
    check(fd >= 0, "NO_XDEV|CACHED accepted");
    close(fd);

    // ---- NO_SYMLINKS ----
    unlink("/oa2lnk");
    check(symlink("motd.txt", "/oa2lnk") == 0, "symlink minted");
    h.resolve = RESOLVE_NO_SYMLINKS;
    check(oa2(AT_FDCWD, "/oa2lnk", &h, 24) < 0 && errno == ELOOP,
          "NO_SYMLINKS ELOOP");
    fd = oa2(AT_FDCWD, "/motd.txt", &h, 24);
    check(fd >= 0, "NO_SYMLINKS non-link ok");
    close(fd);
    h.resolve = 0;
    fd = oa2(AT_FDCWD, "/oa2lnk", &h, 24);
    check(fd >= 0, "link follows w/o gate");
    close(fd);
    unlink("/oa2lnk");

    // ---- NO_MAGICLINKS ----
    h.resolve = RESOLVE_NO_MAGICLINKS;
    check(oa2(AT_FDCWD, "/proc/self/fd/0", &h, 24) < 0
          && errno == ELOOP, "NO_MAGICLINKS ELOOP");
    h.resolve = 0;
    fd = oa2(AT_FDCWD, "/proc/self/fd/0", &h, 24);
    check(fd >= 0, "magic link opens w/o gate");
    close(fd);

    // ---- process_mrelease gates ----
    int cfd = syscall(434, getpid(), 0); // pidfd_open
    check(syscall(SYS_process_mrelease, cfd, 1) < 0 && errno == EINVAL,
          "mrelease flags EINVAL");
    check(syscall(SYS_process_mrelease, 0, 0) < 0 && errno == EBADF,
          "mrelease non-pidfd EBADF");
    check(syscall(SYS_process_mrelease, cfd, 0) < 0 && errno == EINVAL,
          "mrelease live EINVAL");
    close(cfd);

    int pid = fork();
    if (pid == 0) { for (;;) pause(); }
    cfd = syscall(434, pid, 0);
    check(syscall(424, cfd, SIGKILL, 0, 0) == 0, "SIGKILL child");
    struct pollfd zp = { .fd = cfd, .events = POLLIN };
    check(poll(&zp, 1, 5000) == 1, "child dead (pidfd POLLIN)");
    int wst = 0;
    check(syscall(SYS_process_mrelease, cfd, 0) == 0,
          "mrelease zombie 0");
    check(waitpid(pid, &wst, 0) == pid, "zombie reaped");
    check(syscall(SYS_process_mrelease, cfd, 0) < 0 && errno == ESRCH,
          "mrelease reaped ESRCH");
    close(cfd);

    say(fails ? "oa2test: failures\n" : "oa2test: 0 failure(s)\n");
    return fails;
}
