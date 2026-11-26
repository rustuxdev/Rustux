// hdltest — name_to_handle_at(303) + open_by_handle_at(304):
// handle kinds (1=vfile inode w/ gen, 3=root, 4=archive ptr,
// 5=dir path), ESTALE on dead/gen-mismatch, EOPNOTSUPP proc+dev,
// EPERM non-root open, EOVERFLOW capacity. check(); exit = fails.
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <dirent.h>

static int fails;
#define check(c, msg) do { \
    if (c) printf("hdltest: %-46s ok\n", msg); \
    else { printf("hdltest: %-46s FAIL\n", msg); fails++; } \
} while (0)

#define NR_N2H 303
#define NR_OBH 304
#ifndef AT_SYMLINK_FOLLOW
#define AT_SYMLINK_FOLLOW 0x400
#endif
#ifndef AT_EMPTY_PATH
#define AT_EMPTY_PATH 0x1000
#endif
#ifndef EOPNOTSUPP
#define EOPNOTSUPP 95
#endif
#ifndef EOVERFLOW
#define EOVERFLOW 75
#endif
#ifndef ESTALE
#define ESTALE 116
#endif

struct fh { unsigned int bytes; int type; unsigned char h[128]; };

static long n2h(int dfd, const char *p, struct fh *f, int *mnt,
                int fl) {
    return syscall(NR_N2H, dfd, p, f, mnt, fl);
}
static long obh(int mfd, struct fh *f, int flags) {
    return syscall(NR_OBH, mfd, f, flags);
}

int main(void) {
    // ---- scaffold ----
    mkdir("/t_hdl", 0777);
    int fa = open("/t_hdl/a", O_CREAT | O_RDWR, 0666);
    check(fa >= 0 && write(fa, "hello-hdl", 9) == 9,
          "scaffold file");
    int mfd = open("/", O_RDONLY | O_DIRECTORY);
    check(mfd >= 0, "mount fd");

    // ---- basic file handle ----
    struct fh h = { .bytes = sizeof h.h };
    int mnt = -1;
    check(n2h(AT_FDCWD, "/t_hdl/a", &h, &mnt, 0) == 0
          && mnt == 1 && h.bytes == 8 && h.type == 1,
          "file handle minted (kind1, 8B, mnt 1)");
    errno = 0;
    int g = obh(mfd, &h, O_RDONLY);
    char buf[16] = {0};
    check(g >= 0 && read(g, buf, 15) == 9
          && !strcmp(buf, "hello-hdl"), "handle opens -> read data");
    close(g);

    // ---- hardlink shares the inode handle ----
    check(link("/t_hdl/a", "/t_hdl/b") == 0, "hardlink");
    struct fh h2 = { .bytes = sizeof h2.h };
    check(n2h(AT_FDCWD, "/t_hdl/b", &h2, &mnt, 0) == 0
          && h2.bytes == 8 && !memcmp(h.h, h2.h, 8),
          "hard alias -> same inode handle");

    // ---- rename keeps the handle; unlink keeps it while pinned ----
    check(rename("/t_hdl/a", "/t_hdl/c") == 0, "rename");
    errno = 0;
    g = obh(mfd, &h, O_RDONLY);
    check(g >= 0 && read(g, buf, 15) == 9,
          "handle survives rename");
    close(g);
    check(unlink("/t_hdl/b") == 0 && unlink("/t_hdl/c") == 0,
          "unlinked both names");
    errno = 0;
    g = obh(mfd, &h, O_RDONLY);
    check(g >= 0, "handle survives unlink (fd pins inode)");
    close(g); close(fa); fa = -1;

    // ---- dead slot + generation: ESTALE ----
    errno = 0;
    check(obh(mfd, &h, O_RDONLY) == -1 && errno == ESTALE,
          "dead inode -> ESTALE");
    int f2 = open("/t_hdl/c", O_CREAT | O_RDWR, 0666);
    check(f2 >= 0, "recreate same path");
    close(f2);
    errno = 0;
    check(obh(mfd, &h, O_RDONLY) == -1 && errno == ESTALE,
          "slot reuse w/ old gen -> ESTALE");

    // ---- dirs: kind5 path handle, kind3 root ----
    struct fh dh = { .bytes = sizeof dh.h };
    check(n2h(AT_FDCWD, "/t_hdl", &dh, &mnt, 0) == 0
          && dh.bytes == 6 && dh.h[0] == 5,
          "dir handle (kind5 path)");
    errno = 0;
    g = obh(mfd, &dh, O_RDONLY | O_DIRECTORY);
    DIR *dd = g >= 0 ? fdopendir(g) : NULL;
    struct dirent *de = dd ? readdir(dd) : NULL;
    check(dd != NULL && de != NULL,
          "dir handle opens -> readdir");
    if (dd) closedir(dd);
    errno = 0;
    check(obh(mfd, &dh, O_RDWR) == -1 && errno == EISDIR,
          "dir handle O_RDWR -> EISDIR");
    struct fh rh = { .bytes = sizeof rh.h };
    check(n2h(AT_FDCWD, "/", &rh, &mnt, 0) == 0
          && rh.bytes == 1 && rh.h[0] == 3,
          "root handle (kind3)");
    g = obh(mfd, &rh, O_RDONLY | O_DIRECTORY);
    check(g >= 0, "root handle opens");
    if (g >= 0) close(g);

    // ---- archive file: kind4 pointer handle ----
    struct fh ah = { .bytes = sizeof ah.h };
    check(n2h(AT_FDCWD, "init", &ah, &mnt, 0) == 0
          && ah.bytes == 9 && ah.h[0] == 4,
          "archive handle (kind4)");
    errno = 0;
    g = obh(mfd, &ah, O_RDONLY);
    memset(buf, 0, sizeof buf);
    check(g >= 0 && read(g, buf, 8) > 0,
          "archive handle opens -> read");
    if (g >= 0) close(g);

    // ---- symlink: nofollow names the link inode, follow the target
    check(symlink("/t_hdl/c", "/t_hdl/l") == 0, "symlink");
    struct fh lh = { .bytes = sizeof lh.h };
    struct fh th = { .bytes = sizeof th.h };
    check(n2h(AT_FDCWD, "/t_hdl/l", &lh, &mnt, 0) == 0,
          "handle on link (nofollow)");
    check(n2h(AT_FDCWD, "/t_hdl/l", &th, &mnt,
              AT_SYMLINK_FOLLOW) == 0,
          "handle on link (follow)");
    struct fh ch = { .bytes = sizeof ch.h };
    check(n2h(AT_FDCWD, "/t_hdl/c", &ch, &mnt, 0) == 0,
          "handle on target");
    check(lh.bytes == 8 && memcmp(lh.h, ch.h, 8) != 0,
          "nofollow handle names the link inode");
    check(th.bytes == 8 && !memcmp(th.h, ch.h, 8),
          "follow handle == target handle");

    // ---- AT_EMPTY_PATH ----
    int fd2 = open("/t_hdl/c", O_RDONLY);
    struct fh eh = { .bytes = sizeof eh.h };
    check(n2h(fd2, "", &eh, &mnt, AT_EMPTY_PATH) == 0
          && eh.bytes == 8 && !memcmp(eh.h, ch.h, 8),
          "AT_EMPTY_PATH on file fd");
    close(fd2);
    int dd2 = open("/t_hdl", O_RDONLY | O_DIRECTORY);
    memset(&eh, 0, sizeof eh); eh.bytes = sizeof eh.h;
    check(n2h(dd2, "", &eh, &mnt, AT_EMPTY_PATH) == 0
          && eh.h[0] == 5 && !memcmp(eh.h, dh.h, eh.bytes),
          "AT_EMPTY_PATH on dir fd");
    close(dd2);
    memset(&eh, 0, sizeof eh); eh.bytes = sizeof eh.h;
    check(n2h(AT_FDCWD, "", &eh, &mnt, AT_EMPTY_PATH) == 0
          && eh.h[0] == 3,
          "AT_EMPTY_PATH on cwd (root)");

    // ---- error gates ----
    errno = 0;
    check(n2h(AT_FDCWD, "/proc/self", &h, &mnt, 0) == -1
          && errno == EOPNOTSUPP, "proc -> EOPNOTSUPP");
    errno = 0;
    check(n2h(AT_FDCWD, "/dev/null", &h, &mnt, 0) == -1
          && errno == EOPNOTSUPP, "dev node -> EOPNOTSUPP");
    errno = 0;
    check(n2h(AT_FDCWD, "/t_hdl/ghost", &h, &mnt, 0) == -1
          && errno == ENOENT, "missing -> ENOENT");
    errno = 0;
    check(n2h(AT_FDCWD, "/t_hdl/c", &h, &mnt, 8) == -1
          && errno == EINVAL, "bad flags -> EINVAL");
    errno = 0;
    struct fh tiny = { .bytes = 4 };
    check(n2h(AT_FDCWD, "/t_hdl/c", &tiny, &mnt, 0) == -1
          && errno == EOVERFLOW && tiny.bytes == 8,
          "small capacity -> EOVERFLOW + needed size");
    errno = 0;
    check(n2h(AT_FDCWD, "", &h, &mnt, 0) == -1 && errno == ENOENT,
          "empty path w/o EMPTY_PATH -> ENOENT");
    errno = 0;
    check(obh(9999, &ch, O_RDONLY) == -1 && errno == EBADF,
          "bad mount fd -> EBADF");
    int pp[2];
    if (pipe(pp) < 0) _exit(4);
    errno = 0;
    check(obh(pp[0], &ch, O_RDONLY) == -1 && errno == EINVAL,
          "non-fs mount fd -> EINVAL");
    close(pp[0]); close(pp[1]);
    struct fh bad = ch;
    bad.h[0] = 99;
    errno = 0;
    check(obh(mfd, &bad, O_RDONLY) == -1 && errno == EINVAL,
          "forged kind -> EINVAL");
    struct fh st = ch;
    st.h[6] ^= 0xff; /* corrupt gen */
    errno = 0;
    check(obh(mfd, &st, O_RDONLY) == -1 && errno == ESTALE,
          "corrupt gen -> ESTALE");
    errno = 0;
    check(obh(mfd, &ch, O_CREAT) == -1 && errno == EINVAL,
          "O_CREAT flag -> EINVAL");

    // ---- EPERM: nonroot caller ----
    pid_t e = fork();
    if (e == 0) {
        if (setuid(1000) < 0) _exit(9);
        long r = obh(mfd, &ch, O_RDONLY);
        _exit(r == -1 && errno == EPERM ? 0 : 7);
    }
    int ws;
    check(e > 0 && waitpid(e, &ws, 0) == e && WIFEXITED(ws)
          && WEXITSTATUS(ws) == 0, "nonroot open -> EPERM");

    // ---- cleanup (leak gate) ----
    unlink("/t_hdl/l"); unlink("/t_hdl/c");
    rmdir("/t_hdl");
    close(mfd);

    printf("hdltest: %d failures\n", fails);
    return fails;
}
