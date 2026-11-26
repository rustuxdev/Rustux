// chrtest — chroot(161) ABI proof: FsTab root + canon floor-clamped
// '..' + root-aware getcwd + symlink targets re-rooted. Runs the
// in-jail checks in a child so the parent suite stays un-jailed.
// check() convention; exit = failures.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/syscall.h>

static int fails;
#define check(c, msg) do { \
    if (c) printf("chrtest: %-44s ok\n", msg); \
    else { printf("chrtest: %-44s FAIL\n", msg); fails++; } \
} while (0)

static int slurp(const char *p, char *buf, int cap) {
    int fd = open(p, O_RDONLY);
    if (fd < 0) return -1;
    int n = read(fd, buf, cap - 1);
    close(fd);
    if (n < 0) return -1;
    buf[n] = 0;
    return n;
}

int main(void) {
    // ---- scaffolding ---------------------------------------------------
    mkdir("/jail", 0755);
    mkdir("/jail/etc", 0755);
    mkdir("/jail/sub", 0755);
    int wfd = open("/jail/etc/motd", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    check(wfd >= 0, "jail motd creat");
    if (wfd >= 0) { int _w = write(wfd, "jailed!", 7); (void)_w; close(wfd); }
    int _sl1 = symlink("/etc/motd", "/jail/abslink");     // absolute target -> re-roots
    int _sl2 = symlink("../../etc/resolv.conf", "/jail/esclink"); // '..' clamps at jail
    char buf[64];
    check(_sl1 == 0 && _sl2 == 0, "jail symlinks minted");

    // ---- error ladder (un-jailed) --------------------------------------
    errno = 0;
    check(chroot("/jail/etc/motd") == -1 && errno == ENOTDIR,
          "file target ENOTDIR");
    errno = 0;
    check(chroot("/jail/no_such_dir") == -1 && errno == ENOENT,
          "missing target ENOENT");
    // Successful chroots run in a child — inside a jail "/" is the
    // jail, so there's no way back and the parent must stay clean.
    pid_t r = fork();
    if (r == 0) {
        _exit(chroot("/jail") == 0 && chroot("/") == 0 &&
                      chroot(".") == 0
                  ? 0
                  : 1);
    }
    int st0 = 0;
    waitpid(r, &st0, 0);
    check(WIFEXITED(st0) && WEXITSTATUS(st0) == 0,
          "chroot / re-root / chroot('.') all ok");

    // ---- EPERM for non-root --------------------------------------------
    pid_t u = fork();
    if (u == 0) {
        if (setuid(1000) != 0) _exit(9);
        _exit(chroot("/jail") == -1 && errno == EPERM ? 0 : 1);
    }
    int st = 0;
    waitpid(u, &st, 0);
    check(WIFEXITED(st) && WEXITSTATUS(st) == 0, "uid!=0 EPERM");

    // ---- in-jail checks (child so the suite stays un-jailed) ------------
    pid_t c = fork();
    if (c == 0) {
        int f = 0;
        if (chdir("/jail") != 0 || chroot(".") != 0) _exit(10);
        // absolute path re-roots: jail's motd, not the real one.
        if (slurp("/etc/motd", buf, sizeof buf) != 7 ||
            strcmp(buf, "jailed!") != 0)
            f |= 1;
        // a real-root file is invisible inside.
        errno = 0;
        if (open("/etc/resolv.conf", O_RDONLY) != -1 || errno != ENOENT)
            f |= 2;
        // relative '..' clamps at the jail — reads jail's motd.
        if (slurp("../etc/motd", buf, sizeof buf) != 7 ||
            strcmp(buf, "jailed!") != 0)
            f |= 4;
        // getcwd is jail-relative — "/sub" inside the jail lands on
        // jail/sub ("/jail/sub" would double-root to ENOENT).
        if (chdir("/sub") == 0) {
            char cw[64];
            if (!getcwd(cw, sizeof cw) || strcmp(cw, "/sub") != 0)
                f |= 8;
        } else f |= 8;
        // absolute symlink target resolves inside the jail.
        if (slurp("/abslink", buf, sizeof buf) != 7 ||
            strcmp(buf, "jailed!") != 0)
            f |= 16;
        // '..' in a link target clamps — resolv.conf absent in jail.
        errno = 0;
        if (open("/esclink", O_RDONLY) != -1 || errno != ENOENT)
            f |= 32;
        _exit(f);
    }
    st = 0;
    waitpid(c, &st, 0);
    check(WIFEXITED(st) && WEXITSTATUS(st) == 0, "in-jail resolve/getcwd/links");

    // ---- escaped-cwd semantics -----------------------------------------
    // chroot while cwd sits above the jail: the classic Linux escape
    // stays possible (cwd keeps its global view), and getcwd says so.
    pid_t e = fork();
    if (e == 0) {
        char pre[128], cw[128];
        if (!getcwd(pre, sizeof pre)) _exit(10);
        if (chroot("/jail") != 0) _exit(10);
        // glibc getcwd masks "(unreachable)" — buf[0] != '/' sends it
        // down generic_getcwd's openat("..") walk which lands "/" —
        // so the raw syscall is the only way to see the marker.
        long r = syscall(SYS_getcwd, cw, sizeof cw);
        char want[160];
        snprintf(want, sizeof want, "(unreachable)%s", pre);
        if (r <= 0 || strcmp(cw, want) != 0) {
            printf("chrtest: escaped getcwd r=%ld '%s' want='%s'\n",
                   r, cw, want);
            _exit(1);
        }
        // The glibc path still answers — the '..' walk is reachable.
        if (!getcwd(cw, sizeof cw)) _exit(2);
        _exit(0);
    }
    st = 0;
    waitpid(e, &st, 0);
    check(WIFEXITED(st) && WEXITSTATUS(st) == 0,
          "escaped cwd: global view + (unreachable)");

    // A forked child's chroot is invisible to the parent (fork does
    // not share the FsTab) — the parent still resolves globally.
    pid_t s = fork();
    if (s == 0) { int _c = chroot("/jail"); if (_c) _exit(1); _exit(0); }
    waitpid(s, NULL, 0);
    check(slurp("/etc/resolv.conf", buf, sizeof buf) >= 0,
          "fork does not share root");

    // Cleanup — ramfs file data holds KIND_DIRECT buddy frames while
    // the inode lives; the suite's frames-after-reap metric counts
    // them unless we drop the whole jail tree here.
    unlink("/jail/abslink");
    unlink("/jail/esclink");
    unlink("/jail/etc/motd");
    rmdir("/jail/etc");
    rmdir("/jail/sub");
    rmdir("/jail");

    printf("chrtest: %d failures\n", fails);
    return fails;
}
