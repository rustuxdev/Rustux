// xattest — xattr family (188-199) ABI proof. A per-vfile
// user.* table: set/get/list/remove through path (follows the
// final link), l* (acts on the link), and f* (by fd) forms, with
// the Linux errno ladder — ERANGE names, EOPNOTSUPP namespaces,
// EEXIST/ENODATA flags, EPERM specials, ERANGE short buffers.
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <sys/stat.h>

static int fails;
#define check(c, msg) do { \
    if (c) printf("xattest: %-36s ok\n", msg); \
    else { printf("xattest: %-36s FAIL\n", msg); fails++; } \
} while (0)

#ifndef SYS_setxattr
#define SYS_setxattr    188
#define SYS_lsetxattr   189
#define SYS_fsetxattr   190
#define SYS_getxattr    191
#define SYS_lgetxattr   192
#define SYS_fgetxattr   193
#define SYS_listxattr   194
#define SYS_llistxattr  195
#define SYS_flistxattr  196
#define SYS_removexattr 197
#define SYS_lremovexattr 198
#define SYS_fremovexattr 199
#endif

#ifndef XATTR_CREATE
#define XATTR_CREATE  1
#define XATTR_REPLACE 2
#endif

static int setx(int nr, long t, const char *n,
                const char *v, long s, int f) {
    return syscall(nr, t, n, v, s, f);
}
static int getx(int nr, long t, const char *n, void *v, long s) {
    return syscall(nr, t, n, v, s);
}

int main(void) {
    printf("xattest: xattr family checks\n");
    unlink("/tmp_xa");
    unlink("/tmp_xa_l");
    int fd = open("/tmp_xa", O_RDWR | O_CREAT, 0600);
    check(fd >= 0, "open scratch file");
    if (fd < 0) return 1;
    if (write(fd, "seed", 4) < 0) return 1;
    check(symlink("/tmp_xa", "/tmp_xa_l") == 0, "link minted");

    // ---- set gates ----
    errno = 0;
    check(setx(SYS_setxattr, (long)"/tmp_xa", "user.k", "v", 1, 7) < 0
          && errno == EINVAL, "setxattr bad flags EINVAL");
    errno = 0;
    check(setx(SYS_setxattr, (long)"/tmp_xa", "trusted.k", "v", 1, 0) < 0
          && errno == EOPNOTSUPP, "setxattr ns EOPNOTSUPP");
    errno = 0;
    check(setx(SYS_setxattr, (long)"/tmp_xa", "", "v", 1, 0) < 0
          && errno == ERANGE, "setxattr empty name ERANGE");
    errno = 0;
    check(setx(SYS_setxattr, (long)"/nope", "user.k", "v", 1, 0) < 0
          && errno == ENOENT, "setxattr bad path ENOENT");
    errno = 0;
    check(setx(SYS_lsetxattr, (long)"/tmp_xa_l", "user.lk", "lv", 2, 0) < 0
          && errno == EPERM, "lsetxattr link EPERM");
    errno = 0;
    check(setx(SYS_fsetxattr, (long)9999, "user.k", "v", 1, 0) < 0
          && errno == EBADF, "fsetxattr bad fd EBADF");

    // ---- set + get round trip ----
    check(setx(SYS_setxattr, (long)"/tmp_xa", "user.key1", "v1", 2, 0) == 0,
          "setxattr user.key1");
    check(setx(SYS_setxattr, (long)"/tmp_xa", "user.key2", "", 0, 0) == 0,
          "setxattr empty value");
    check(setx(SYS_fsetxattr, fd, "user.fdkey", "fdv", 3, 0) == 0,
          "fsetxattr");
    char buf[128];
    memset(buf, 0, sizeof buf);
    long n = getx(SYS_getxattr, (long)"/tmp_xa", "user.key1", buf, sizeof buf);
    check(n == 2 && memcmp(buf, "v1", 2) == 0, "getxattr value");
    n = getx(SYS_getxattr, (long)"/tmp_xa", "user.key2", buf, sizeof buf);
    check(n == 0, "getxattr empty value");
    n = getx(SYS_fgetxattr, fd, "user.fdkey", buf, sizeof buf);
    check(n == 3 && memcmp(buf, "fdv", 3) == 0, "fgetxattr value");
    n = getx(SYS_getxattr, (long)"/tmp_xa", "user.key1", 0, 0);
    check(n == 2, "getxattr size probe");

    // ---- get gates ----
    errno = 0;
    check(getx(SYS_getxattr, (long)"/tmp_xa", "user.miss", buf, 64) < 0
          && errno == ENODATA, "getxattr miss ENODATA");
    errno = 0;
    check(getx(SYS_getxattr, (long)"/tmp_xa", "user.key1", buf, 1) < 0
          && errno == ERANGE, "getxattr short buf ERANGE");
    errno = 0;
    check(getx(SYS_getxattr, (long)"/nope", "user.k", buf, 64) < 0
          && errno == ENOENT, "getxattr bad path ENOENT");
    errno = 0;
    check(getx(SYS_fgetxattr, (long)9999, "user.k", buf, 64) < 0
          && errno == EBADF, "fgetxattr bad fd EBADF");

    // ---- create/replace flags ----
    errno = 0;
    check(setx(SYS_setxattr, (long)"/tmp_xa", "user.key1", "x", 1,
               XATTR_CREATE) < 0 && errno == EEXIST,
          "XATTR_CREATE existing EEXIST");
    errno = 0;
    check(setx(SYS_setxattr, (long)"/tmp_xa", "user.newk", "x", 1,
               XATTR_REPLACE) < 0 && errno == ENODATA,
          "XATTR_REPLACE missing ENODATA");
    check(setx(SYS_setxattr, (long)"/tmp_xa", "user.key1", "ZZ", 2,
               XATTR_REPLACE) == 0, "XATTR_REPLACE existing");
    memset(buf, 0, sizeof buf);
    getx(SYS_getxattr, (long)"/tmp_xa", "user.key1", buf, sizeof buf);
    check(memcmp(buf, "ZZ", 2) == 0, "replace wrote value");

    // ---- list ----
    char lbuf[256];
    memset(lbuf, 0, sizeof lbuf);
    n = syscall(SYS_listxattr, "/tmp_xa", lbuf, sizeof lbuf);
    check(n > 0, "listxattr returns names");
    int have1 = 0, have2 = 0, havefd = 0;
    for (long i = 0; i < n; i += strlen(lbuf + i) + 1) {
        if (!strcmp(lbuf + i, "user.key1")) have1 = 1;
        if (!strcmp(lbuf + i, "user.key2")) have2 = 1;
        if (!strcmp(lbuf + i, "user.fdkey")) havefd = 1;
    }
    check(have1 && have2 && havefd, "listxattr all three names");
    n = syscall(SYS_listxattr, "/tmp_xa", 0, 0);
    check(n > 0, "listxattr size probe");
    memset(lbuf, 0, sizeof lbuf);
    errno = 0;
    check(syscall(SYS_listxattr, "/tmp_xa", lbuf, 2) < 0
          && errno == ERANGE, "listxattr short buf ERANGE");
    memset(lbuf, 0, sizeof lbuf);
    n = syscall(SYS_flistxattr, fd, lbuf, sizeof lbuf);
    check(n > 0, "flistxattr");

    // ---- l* forms act on the link itself: a link inode holds no
    // attrs so get/list ENODATA/empty even when the target has them.
    memset(buf, 0, sizeof buf);
    errno = 0;
    check(getx(SYS_lgetxattr, (long)"/tmp_xa_l", "user.key1", buf, 64) < 0
          && errno == ENODATA, "lgetxattr link inode ENODATA");
    memset(lbuf, 0, sizeof lbuf);
    n = syscall(SYS_llistxattr, "/tmp_xa_l", lbuf, sizeof lbuf);
    check(n == 0, "llistxattr link empty");
    // a directory link in the middle of a path still resolves:
    // /tmp_dir_l -> /tmp_dir, so /tmp_dir_l/f reads f's attrs.
    check(mkdir("/tmp_dir", 0700) == 0, "mkdir scratch dir");
    check(symlink("/tmp_dir", "/tmp_dir_l") == 0, "dir link minted");
    int dfd = open("/tmp_dir/f", O_RDWR | O_CREAT, 0600);
    check(dfd >= 0, "open through real dir");
    if (dfd >= 0) {
        setx(SYS_fsetxattr, dfd, "user.dkey", "dv", 2, 0);
        close(dfd);
        memset(buf, 0, sizeof buf);
        n = getx(SYS_getxattr, (long)"/tmp_dir_l/f", "user.dkey",
                 buf, sizeof buf);
        check(n == 2 && memcmp(buf, "dv", 2) == 0,
              "interior link resolves");
        unlink("/tmp_dir/f");
    }
    unlink("/tmp_dir_l");
    rmdir("/tmp_dir");

    // ---- remove ----
    errno = 0;
    check(syscall(SYS_removexattr, "/tmp_xa", "user.miss") < 0
          && errno == ENODATA, "removexattr miss ENODATA");
    check(syscall(SYS_removexattr, "/tmp_xa", "user.key2") == 0,
          "removexattr user.key2");
    errno = 0;
    check(getx(SYS_getxattr, (long)"/tmp_xa", "user.key2", buf, 64) < 0
          && errno == ENODATA, "gone after remove");
    check(syscall(SYS_fremovexattr, fd, "user.fdkey") == 0,
          "fremovexattr");
    errno = 0;
    check(getx(SYS_fgetxattr, fd, "user.fdkey", buf, 64) < 0
          && errno == ENODATA, "fd attr gone");
    errno = 0;
    check(syscall(SYS_lremovexattr, "/tmp_xa_l", "user.key1") < 0
          && errno == ENODATA, "lremovexattr link ENODATA");
    check(syscall(SYS_removexattr, "/tmp_xa", "user.key1") == 0,
          "removexattr user.key1");
    errno = 0;
    check(getx(SYS_getxattr, (long)"/tmp_xa", "user.key1", buf, 64) < 0
          && errno == ENODATA, "target attr gone too");
    memset(lbuf, 0, sizeof lbuf);
    n = syscall(SYS_listxattr, "/tmp_xa", lbuf, sizeof lbuf);
    check(n == 0, "listxattr empty after purge");

    // ---- attr survives close; dies with the inode ----
    check(setx(SYS_fsetxattr, fd, "user.keep", "stay", 4, 0) == 0,
          "set before close");
    close(fd);
    memset(buf, 0, sizeof buf);
    n = getx(SYS_getxattr, (long)"/tmp_xa", "user.keep", buf, sizeof buf);
    check(n == 4 && memcmp(buf, "stay", 4) == 0,
          "attr outlives fd close");
    unlink("/tmp_xa");
    unlink("/tmp_xa_l");
    fd = open("/tmp_xa", O_RDWR | O_CREAT, 0600);
    check(fd >= 0, "recreate after unlink");
    if (fd >= 0) {
        memset(buf, 0, sizeof buf);
        errno = 0;
        check(getx(SYS_fgetxattr, fd, "user.keep", buf, 64) < 0
              && errno == ENODATA, "new inode inherits nothing");
        close(fd);
        unlink("/tmp_xa");
    }

    printf("xattest: %d failures\n", fails);
    return fails;
}
