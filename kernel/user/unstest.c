// unstest — unshare(272), modify_ldt(154), pkey(329/330/331) checks.
// Exit status = number of failed checks.
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/syscall.h>

static int fails;
static void check(int ok, const char *what) {
    if (!ok) {
        printf("FAIL: %s\n", what);
        fails++;
    }
}

static long sys_unshare(long flags) { return syscall(272, flags); }
static long sys_kcmp(long p1, long p2, long type, long i1, long i2) {
    return syscall(312, p1, p2, type, i1, i2);
}
static long sys_modify_ldt(long f, long p, long c) {
    return syscall(154, f, p, c);
}

struct cl_arg { int code; int fd; };

// CLONE_VM child: shares mm; flags select which tables clone shares.
static int thr_entry(void *a) {
    struct cl_arg *g = a;
    pid_t par = getppid(), me = getpid();
    int ok = 1;
    if (g->code == 0) {
        // FILES(2)+FS(3) shared: unshare dissociates both.
        ok &= sys_kcmp(par, me, 2, 0, 0) == 0;   // KCMP_FILES shared
        ok &= sys_kcmp(par, me, 3, 0, 0) == 0;   // KCMP_FS shared
        ok &= sys_unshare(CLONE_FILES | CLONE_FS) == 0;
        ok &= sys_kcmp(par, me, 2, 0, 0) != 0;   // now private
        ok &= sys_kcmp(par, me, 3, 0, 0) != 0;
        // Closing the private copy must not touch the parent's fd.
        ok &= close(g->fd) == 0;
        ok &= chdir("/t_un/sub") == 0;
    } else {
        // SIGHAND(4) shared (VM clone): unshare dissociates it.
        ok &= sys_kcmp(par, me, 4, 0, 0) == 0;   // KCMP_SIGHAND shared
        ok &= sys_unshare(CLONE_SIGHAND) == 0;
        ok &= sys_kcmp(par, me, 4, 0, 0) != 0;
    }
    _exit(ok ? 0 : 1);
}

int main(void) {
    mkdir("/t_un", 0777);
    mkdir("/t_un/sub", 0777);
    char cwd[256];
    check(getcwd(cwd, sizeof(cwd)) != NULL, "cwd captured");

    // ---- flag validation ---------------------------------------
    check(sys_unshare(0) == 0, "unshare(0) ok");
    errno = 0;
    check(sys_unshare(CLONE_VM) == -1 && errno == EINVAL,
          "unshare CLONE_VM -> EINVAL");
    errno = 0;
    check(sys_unshare(CLONE_THREAD) == -1 && errno == EINVAL,
          "unshare CLONE_THREAD -> EINVAL");
    errno = 0;
    check(sys_unshare(CLONE_NEWNS) == -1 && errno == EINVAL,
          "unshare CLONE_NEWNS -> EINVAL");
    errno = 0;
    check(sys_unshare(0x80000000) == -1 && errno == EINVAL,
          "unshare unknown bit -> EINVAL");
    check(sys_unshare(CLONE_SYSVSEM) == 0, "unshare SYSVSEM inert");

    // ---- CLONE_FILES + CLONE_FS dissociation --------------------
    int fd = open("/t_un/f", O_CREAT | O_RDWR, 0666);
    check(fd >= 0, "shared fd opened");
    struct cl_arg g = {0, fd};
    void *stk = malloc(64 * 1024);
    pid_t c = clone(thr_entry, stk + 64 * 1024,
                    CLONE_VM | CLONE_FILES | CLONE_FS | SIGCHLD, &g);
    check(c > 0, "files/fs clone queued");
    int ws;
    check(c > 0 && waitpid(c, &ws, 0) == c && WIFEXITED(ws)
          && WEXITSTATUS(ws) == 0, "files/fs unshare ladder");
    // the shared fd survived the child's private close
    check(write(fd, "x", 1) == 1, "parent fd survives child close");
    char after[256];
    check(getcwd(after, sizeof(after)) != NULL
          && strcmp(cwd, after) == 0,
          "child chdir never moved parent cwd");

    // ---- CLONE_SIGHAND dissociation -----------------------------
    g.code = 1;
    void *stk2 = malloc(64 * 1024);
    c = clone(thr_entry, stk2 + 64 * 1024,
              CLONE_VM | CLONE_SIGHAND | SIGCHLD, &g);
    check(c > 0, "sighand clone queued");
    check(c > 0 && waitpid(c, &ws, 0) == c && WIFEXITED(ws)
          && WEXITSTATUS(ws) == 0, "sighand unshare ladder");

    // ---- modify_ldt(154) -----------------------------------------
    check(sys_modify_ldt(0, 0, 0) == 0, "modify_ldt read -> empty");
    check(sys_modify_ldt(2, 0, 0) == 0, "modify_ldt read-default -> empty");
    errno = 0;
    check(sys_modify_ldt(1, 0, 0) == -1 && errno == EINVAL,
          "modify_ldt write -> EINVAL");
    errno = 0;
    check(sys_modify_ldt(0x11, 0, 0) == -1 && errno == EINVAL,
          "modify_ldt write-default -> EINVAL");

    // ---- pkey (329/330/331) --------------------------------------
    errno = 0;
    check(syscall(330, 0, 0) == -1 && errno == EINVAL,
          "pkey_alloc -> EINVAL");
    errno = 0;
    check(syscall(329, 0, 0, 0) == -1 && errno == EINVAL,
          "pkey_mprotect -> EINVAL");
    errno = 0;
    check(syscall(331, 0) == -1 && errno == EINVAL,
          "pkey_free -> EINVAL");

    // ---- cleanup (leak gate) ----
    free(stk); free(stk2);
    close(fd);
    unlink("/t_un/f");
    rmdir("/t_un/sub");
    rmdir("/t_un");

    printf("unstest: %d failures\n", fails);
    return fails;
}
