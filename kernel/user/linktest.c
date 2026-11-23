// linktest — run-133 syscall coverage: hardlinks (link/linkat) with
// shared-inode semantics, directory rename (dpkg's .dpkg-new move),
// recorded archive modes driving access(X_OK) and exec EACCES,
// futimens via utimensat's NULL path, and fcntl/flock byte-range
// locks including fork-conflict. check() convention, exit = fails.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/syscall.h>

static int fails;

static void say(const char *s) {
    if (write(1, s, strlen(s)) < 0) { /* ignore */ }
}

static void check(int ok, const char *what) {
    char buf[96];
    snprintf(buf, sizeof(buf), "linktest: %-38s %s\n",
             what, ok ? "ok" : "FAIL");
    say(buf);
    if (!ok) fails++;
}

static int put(const char *p, const char *data, int mode) {
    int fd = open(p, O_CREAT | O_WRONLY | O_TRUNC, mode);
    if (fd < 0) return -1;
    if (data) (void)!write(fd, data, strlen(data));
    close(fd);
    return 0;
}

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
    char buf[64];
    struct stat sa, sb;
    int fd, r;

    /* ---- hardlinks ---- */
    put("/lk_a", "hello", 0644);
    check(link("/lk_a", "/lk_b") == 0, "link creates second name");
    check(stat("/lk_a", &sa) == 0 && stat("/lk_b", &sb) == 0
          && sa.st_ino == sb.st_ino && sa.st_nlink == 2
          && sb.st_nlink == 2,
          "aliases share ino, nlink==2");
    check(link("/lk_a", "/lk_b") < 0 && errno == EEXIST,
          "link onto existing EEXIST");
    check(link("/lk_zzz", "/lk_c") < 0 && errno == ENOENT,
          "link missing ENOENT");
    check(link("/busybox", "/lk_arc") < 0
          && (errno == EROFS || errno == EPERM || errno == EXDEV),
          "archive member refuses hardlink");
    check(link("/lk_a", "/busybox") < 0
          && (errno == EEXIST || errno == EPERM || errno == EROFS),
          "link onto archive name refused");
    fd = open("/lk_b", O_WRONLY | O_APPEND);
    check(fd >= 0 && write(fd, "!", 1) == 1, "write through alias");
    if (fd >= 0) close(fd);
    check(slurp("/lk_a", buf, sizeof(buf)) == 6
          && !strcmp(buf, "hello!"),
          "alias writes reach one inode");
    check(unlink("/lk_a") == 0, "unlink first name");
    check(stat("/lk_b", &sb) == 0 && sb.st_nlink == 1
          && slurp("/lk_b", buf, sizeof(buf)) == 6,
          "data survives with one name left");
    /* open-at-unlink lifetime: remove the last name while open */
    fd = open("/lk_b", O_RDONLY);
    check(unlink("/lk_b") == 0 && stat("/lk_b", &sb) < 0,
          "last name drops, path gone");
    check(fd >= 0 && read(fd, buf, 6) == 6,
          "open OFD outlives last name");
    if (fd >= 0) close(fd);
    /* linkat */
    put("/lk_at", "x", 0600);
    check(linkat(AT_FDCWD, "/lk_at", AT_FDCWD, "/lk_at2", 0) == 0
          && stat("/lk_at2", &sb) == 0 && sb.st_nlink == 2,
          "linkat works");
    unlink("/lk_at"); unlink("/lk_at2");

    /* ---- directory rename ---- */
    mkdir("/dr", 0755);
    mkdir("/dr/sub", 0755);
    put("/dr/f", "data", 0644);
    check(rename("/dr", "/dr2") == 0, "rename dir");
    check(slurp("/dr2/f", buf, sizeof(buf)) == 4
          && stat("/dr/sub", &sb) < 0 && stat("/dr2/sub", &sb) == 0,
          "subtree moved with the dir");
    put("/dr_file", "x", 0644);
    check(rename("/dr2", "/dr_file") < 0 && errno == ENOTDIR,
          "dir onto file ENOTDIR");
    check(rename("/dr_file", "/dr2") < 0 && errno == EISDIR,
          "file onto dir EISDIR");
    check(rename("/dr2", "/dr2/deep") < 0 && errno == EINVAL,
          "dir into own subtree EINVAL");
    mkdir("/dr_dst", 0755);
    put("/dr_dst/keep", "y", 0644);
    check(rename("/dr2", "/dr_dst") < 0 && errno == ENOTEMPTY,
          "onto non-empty dir ENOTEMPTY");
    unlink("/dr_dst/keep");
    check(rename("/dr2", "/dr_dst") == 0
          && stat("/dr_dst/sub", &sb) == 0,
          "onto empty dir replaces it");
    check(unlink("/dr_dst/f") == 0 && rmdir("/dr_dst/sub") == 0
          && rmdir("/dr_dst") == 0, "moved tree removes cleanly");
    unlink("/dr_file");

    /* ---- recorded modes: access + exec bit ---- */
    put("/m_x", "x", 0755);
    put("/m_nx", "x", 0644);
    check(access("/m_x", X_OK) == 0, "access X_OK on 0755");
    check(access("/m_nx", X_OK) < 0 && errno == EACCES,
          "access X_OK on 0644 EACCES");
    check(faccessat(AT_FDCWD, "/m_x", X_OK, 0) == 0,
          "faccessat X_OK");
    check(access("/busybox", X_OK) == 0,
          "archive member records exec mode");
    check(access("/busybox", W_OK) < 0 && errno == EROFS,
          "archive member W_OK EROFS");
    check(access("/m_nx", R_OK | W_OK) == 0,
          "vfile RW access ok");
    /* execve of a non-executable file is EACCES, not ENOEXEC */
    {
        pid_t p = fork();
        if (p == 0) {
            execve("/m_nx", (char *const[]){"m_nx", 0}, 0);
            _exit(errno == EACCES ? 77 : 78);
        }
        int st = 0;
        waitpid(p, &st, 0);
        check(WIFEXITED(st) && WEXITSTATUS(st) == 77,
              "exec of 0644 file EACCES");
    }
    unlink("/m_x"); unlink("/m_nx");

    /* ---- utimensat NULL path = futimens ---- */
    fd = open("/ut_f", O_CREAT | O_RDWR, 0644);
    {
        struct timespec ts[2] = {{1111111111, 0}, {1222222222, 0}};
        r = syscall(SYS_utimensat, fd, NULL, ts, 0);
        check(r == 0, "utimensat NULL path (futimens)");
        check(fstat(fd, &sb) == 0 && sb.st_mtime == 1222222222,
              "futimens stamps mtime");
        check(syscall(SYS_utimensat, fd, NULL, ts, AT_SYMLINK_NOFOLLOW) < 0
              && errno == EINVAL,
              "futimens NOFOLLOW EINVAL");
        check(syscall(SYS_utimensat, AT_FDCWD, NULL, ts, 0) < 0 && errno == EFAULT,
              "NULL path at AT_FDCWD EFAULT");
    }
    close(fd);
    unlink("/ut_f");

    /* ---- byte-range locks ---- */
    fd = open("/lk_l", O_CREAT | O_RDWR, 0644);
    {
        struct flock fl = {0};
        fl.l_type = F_WRLCK;
        fl.l_whence = SEEK_SET;
        check(fcntl(fd, F_SETLK, &fl) == 0, "F_SETLK WRLCK");
        check(fcntl(fd, F_OFD_SETLK, &fl) == 0, "F_OFD_SETLK WRLCK");
        /* a second process conflicts on the POSIX lock */
        pid_t p = fork();
        if (p == 0) {
            struct flock c = {0};
            c.l_type = F_WRLCK;
            c.l_whence = SEEK_SET;
            int f2 = open("/lk_l", O_RDWR);
            int rc = fcntl(f2, F_SETLK, &c);
            _exit(rc < 0 && (errno == EACCES || errno == EAGAIN)
                      ? 77 : 78);
        }
        int st = 0;
        waitpid(p, &st, 0);
        check(WIFEXITED(st) && WEXITSTATUS(st) == 77,
              "conflicting F_SETLK EAGAIN");
        /* F_GETLK reports our own compatible lock as UNLCK */
        struct flock g = {0};
        g.l_type = F_WRLCK;
        g.l_whence = SEEK_SET;
        check(fcntl(fd, F_GETLK, &g) == 0 && g.l_type == F_UNLCK,
              "F_GETLK no foreign conflict");
        fl.l_type = F_UNLCK;
        check(fcntl(fd, F_SETLK, &fl) == 0, "F_UNLCK releases");
        check(flock(fd, LOCK_EX | LOCK_NB) == 0, "flock LOCK_EX");
        check(flock(fd, LOCK_UN) == 0, "flock LOCK_UN");
    }
    close(fd);
    unlink("/lk_l");

    printf("linktest: %d failures\n", fails);
    return fails;
}
