// dtest — hierarchical path/VFS checks: mkdir/mkdirat create real
// dirs, chdir/fchdir move the shared cwd, relative + dirfd paths
// resolve, getdents lists per-dir components (not the flat world),
// rmdir honors ENOTEMPTY, and the honesty table stays sharp.
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <poll.h>
#include <sys/stat.h>
#include <sys/syscall.h>

static int fails;
static void check(int ok, const char *what) {
    printf("  %-46s %s\n", what, ok ? "ok" : "FAIL");
    if (!ok) fails++;
}

static int dir_has(const char *dir, const char *want) {
    int d = open(dir, O_RDONLY | O_DIRECTORY);
    char buf[2048];
    int found = 0;
    if (d < 0) return -1;
    long got;
    while ((got = syscall(SYS_getdents64, d, buf, sizeof(buf))) > 0) {
        for (long off = 0; off + 19 <= got; ) {
            struct { unsigned long ino, off; unsigned short len;
                     unsigned char type; char name[]; } *e =
                (void *)(buf + off);
            if (strcmp(e->name, want) == 0) found = e->type;
            off += e->len;
        }
    }
    close(d);
    return found;
}

int main(void) {
    char buf[128];
    struct stat st;
    printf("dtest: path/VFS semantics\n");

    check(getcwd(buf, sizeof(buf)) && strcmp(buf, "/") == 0,
          "getcwd starts at /");
    check(syscall(SYS_mkdir, "/vtmp", 0755) == 0, "mkdir /vtmp");
    check(syscall(SYS_mkdirat, AT_FDCWD, "/vtmp/sub", 0755) == 0,
          "mkdirat /vtmp/sub");
    check(stat("/vtmp", &st) == 0 && S_ISDIR(st.st_mode),
          "stat /vtmp is S_IFDIR");
    check(stat("/vtmp/sub", &st) == 0 && S_ISDIR(st.st_mode),
          "stat /vtmp/sub is S_IFDIR");
    check(stat("/proc", &st) == 0 && S_ISDIR(st.st_mode),
          "stat /proc is S_IFDIR");

    check(chdir("/vtmp") == 0, "chdir /vtmp");
    check(getcwd(buf, sizeof(buf)) && strcmp(buf, "/vtmp") == 0,
          "getcwd = /vtmp");
    check(chdir("sub") == 0, "chdir sub (relative)");
    check(getcwd(buf, sizeof(buf)) && strcmp(buf, "/vtmp/sub") == 0,
          "getcwd = /vtmp/sub");
    check(chdir("..") == 0, "chdir .. pops");
    check(getcwd(buf, sizeof(buf)) && strcmp(buf, "/vtmp") == 0,
          "getcwd back to /vtmp");
    check(chdir("/") == 0 && chdir("..") == 0 &&
          getcwd(buf, sizeof(buf)) && strcmp(buf, "/") == 0,
          ".. at root stays root");

    /* cwd-relative + dirfd-relative creation. */
    check(chdir("/vtmp") == 0, "chdir back into /vtmp");
    int f = open("rel.tmp", O_CREAT | O_RDWR, 0644);
    check(f >= 0, "open rel.tmp cwd-relative");
    if (f >= 0) { write(f, "hi", 2); close(f); }
    check(access("/vtmp/rel.tmp", F_OK) == 0,
          "rel.tmp exists under /vtmp");
    int dd = open("/vtmp", O_RDONLY | O_DIRECTORY);
    check(dd >= 0, "open /vtmp O_DIRECTORY");
    int f2 = openat(dd, "rel2.tmp", O_CREAT | O_WRONLY, 0644);
    check(f2 >= 0, "openat rel2.tmp dirfd-relative");
    if (f2 >= 0) close(f2);
    check(access("/vtmp/rel2.tmp", F_OK) == 0,
          "rel2.tmp exists under /vtmp");
    check(access("sub", F_OK) == 0, "access sub cwd-relative");
    check(access("/vtmp/../motd.txt", F_OK) == 0,
          "/vtmp/../motd.txt resolves");

    /* getdents is per-dir: /vtmp lists its children only. */
    check(dir_has("/vtmp", ".") == 4, "vtmp lists . (DT_DIR)");
    check(dir_has("/vtmp", "..") == 4, "vtmp lists .. (DT_DIR)");
    check(dir_has("/vtmp", "sub") == 4, "vtmp lists sub (DT_DIR)");
    check(dir_has("/vtmp", "rel.tmp") == 8,
          "vtmp lists rel.tmp (DT_REG)");
    check(dir_has("/vtmp", "motd.txt") == 0,
          "vtmp does NOT list motd.txt");
    check(dir_has("/", "vtmp") == 4, "root lists vtmp (DT_DIR)");
    check(dir_has("/", "proc") == 4, "root lists proc (DT_DIR)");

    /* fchdir through a dir fd; unlinkat dirfd-relative. */
    check(fchdir(dd) == 0, "fchdir back to /vtmp");
    check(getcwd(buf, sizeof(buf)) && strcmp(buf, "/vtmp") == 0,
          "getcwd = /vtmp after fchdir");
    check(unlinkat(dd, "rel2.tmp", 0) == 0,
          "unlinkat dirfd-relative");
    check(access("/vtmp/rel2.tmp", F_OK) != 0, "rel2.tmp gone");
    check(unlink("rel.tmp") == 0, "unlink rel.tmp");

    /* Honesty table. */
    errno = 0;
    check(syscall(SYS_mkdir, "/vtmp", 0) == -1 && errno == EEXIST,
          "mkdir existing -> EEXIST");
    errno = 0;
    check(syscall(SYS_mkdir, "/vtmp/nope/kid", 0) == -1 &&
          errno == ENOENT, "mkdir missing parent -> ENOENT");
    errno = 0;
    check(rmdir("/vtmp") == -1 && errno == ENOTEMPTY,
          "rmdir non-empty -> ENOTEMPTY");
    errno = 0;
    check(chdir("/definitely/absent") == -1 && errno == ENOENT,
          "chdir missing -> ENOENT");
    errno = 0;
    check(chdir("/motd.txt") == -1 && errno == ENOTDIR,
          "chdir to file -> ENOTDIR");
    errno = 0;
    check(open("/vtmp", O_WRONLY) == -1 && errno == EISDIR,
          "open dir O_WRONLY -> EISDIR");
    errno = 0;
    check(open("/motd.txt/kid", O_RDONLY) == -1 && errno == ENOTDIR,
          "path through file -> ENOTDIR");
    errno = 0;
    check(unlink("/vtmp") == -1 && errno == EISDIR,
          "unlink a dir -> EISDIR");

    /* run-345: O_TMPFILE mints an unnamed inode in the naming
       directory — writable, stat-able, never path-reachable. */
    {
        int tf = open("/vtmp", O_TMPFILE | O_RDWR, 0640);
        check(tf >= 0, "O_TMPFILE creates unnamed inode");
        if (tf >= 0) {
            struct stat ts;
            ssize_t w = write(tf, "tf", 2);
            check(w == 2, "O_TMPFILE writable");
            check(fstat(tf, &ts) == 0 && S_ISREG(ts.st_mode) &&
                  (ts.st_mode & 0777) == 0640,
                  "O_TMPFILE fstat: regular, mode honored");
            check(pread(tf, buf, 2, 0) == 2 && buf[0] == 't',
                  "O_TMPFILE read-back");
            close(tf);
        }
        errno = 0;
        check(open("/vtmp", O_TMPFILE | O_RDONLY, 0640) == -1 &&
              errno == EINVAL,
              "O_TMPFILE O_RDONLY -> EINVAL");
        errno = 0;
        check(open("/vtmp", O_TMPFILE | O_CREAT | O_RDWR, 0640) == -1 &&
              errno == EINVAL,
              "O_TMPFILE|O_CREAT -> EINVAL");
        /* O_EXCL is meaningless on a nameless inode — ignored. */
        errno = 0;
        int xf = open("/vtmp", O_TMPFILE | O_EXCL | O_RDWR, 0640);
        check(xf >= 0, "O_TMPFILE|O_EXCL accepted");
        if (xf >= 0) close(xf);
        errno = 0;
        check(open("/vtmp/nofile", O_TMPFILE | O_RDWR, 0640) == -1 &&
              errno == ENOENT,
              "O_TMPFILE missing dir -> ENOENT");
        /* O_PATH wins outright on Linux: no tmpfile is minted, the
           dir opens as a write-inert path reference. */
        errno = 0;
        int pf = open("/vtmp", O_TMPFILE | O_RDWR | O_PATH, 0640);
        check(pf >= 0, "O_TMPFILE|O_PATH -> path fd");
        if (pf >= 0) {
            struct stat ps;
            check(fstat(pf, &ps) == 0 && S_ISDIR(ps.st_mode),
                  "O_TMPFILE|O_PATH fstat: dir");
            check(write(pf, "x", 1) == -1,
                  "O_TMPFILE|O_PATH write fails");
            close(pf);
        }
        /* procfs can't host an inode — EACCES on Linux. */
        errno = 0;
        check(open("/proc", O_TMPFILE | O_RDWR, 0640) == -1 &&
              errno == EACCES,
              "O_TMPFILE /proc -> EACCES");

    /* run-346: real O_PATH — a dentry reference, not a stream.
       I/O answers EBADF, stat/dirfd/fchdir work through it. */
    {
        int op = open("/vtmp", O_PATH | O_DIRECTORY);
        struct stat os;
        check(op >= 0, "O_PATH opens a dir");
        if (op >= 0) {
            char z[4];
            errno = 0;
            check(read(op, z, 1) == -1 && errno == EBADF,
                  "O_PATH read -> EBADF");
            errno = 0;
            check(write(op, z, 1) == -1 && errno == EBADF,
                  "O_PATH write -> EBADF");
            errno = 0;
            check(syscall(SYS_getdents64, op, z, 4) == -1 &&
                  errno == EBADF,
                  "O_PATH getdents -> EBADF");
            check(fstat(op, &os) == 0 && S_ISDIR(os.st_mode),
                  "O_PATH fstat: dir");
            check(fcntl(op, F_GETFL) & O_PATH,
                  "O_PATH F_GETFL bit");
            /* dirfd use: openat relative to the path fd. */
            int rf2 = open("/vtmp/opath_tgt", O_CREAT | O_RDWR, 0600);
            check(rf2 >= 0 && close(rf2) == 0, "seed opath_tgt");
            int rel = openat(op, "opath_tgt", O_RDONLY);
            check(rel >= 0, "openat via O_PATH dirfd");
            if (rel >= 0) close(rel);
            /* AT_EMPTY_PATH stat through the fd. */
            errno = 0;
            check(fstatat(op, "", &os, AT_EMPTY_PATH) == 0 &&
                  S_ISDIR(os.st_mode),
                  "O_PATH fstatat EMPTY_PATH");
            /* fchdir through it, then back. */
            int sv = open(".", O_PATH | O_DIRECTORY);
            check(fchdir(op) == 0, "fchdir via O_PATH dir");
            if (sv >= 0) { fchdir(sv); close(sv); }
            /* poll says POLLNVAL. */
            struct pollfd pf2 = { op, POLLIN, 0 };
            errno = 0;
            check(poll(&pf2, 1, 0) == 1 && pf2.revents == POLLNVAL,
                  "O_PATH poll -> POLLNVAL");
            close(op);
        }
        /* O_PATH on a file: stat works, fchdir ENOTDIR. */
        int fp = open("/vtmp/opath_tgt", O_PATH);
        check(fp >= 0, "O_PATH opens a file");
        if (fp >= 0) {
            struct stat fs2;
            errno = 0;
            check(fstat(fp, &fs2) == 0 && S_ISREG(fs2.st_mode),
                  "O_PATH file fstat: reg");
            check(fchdir(fp) == -1 && errno == ENOTDIR,
                  "fchdir O_PATH file -> ENOTDIR");
            close(fp);
        }
        unlink("/vtmp/opath_tgt");
        /* O_PATH|O_NOFOLLOW on a symlink — lstat view, dangling ok. */
        check(syscall(SYS_symlink, "/vtmp", "/vtmp/oplnk") == 0,
              "seed symlink");
        check(syscall(SYS_symlink, "/vtmp/gone", "/vtmp/opdang") == 0,
              "seed dangling symlink");
        int lp = open("/vtmp/oplnk", O_PATH | O_NOFOLLOW);
        check(lp >= 0, "O_PATH|NOFOLLOW opens link");
        if (lp >= 0) {
            struct stat ls;
            check(fstat(lp, &ls) == 0 && S_ISLNK(ls.st_mode),
                  "O_PATH|NOFOLLOW fstat: link");
            close(lp);
        }
        int dp = open("/vtmp/opdang", O_PATH | O_NOFOLLOW);
        check(dp >= 0, "O_PATH|NOFOLLOW dangling mints");
        if (dp >= 0) {
            struct stat ds;
            check(fstat(dp, &ds) == 0 && S_ISLNK(ds.st_mode),
                  "dangling link fstat: link");
            close(dp);
        }
        unlink("/vtmp/oplnk");
        unlink("/vtmp/opdang");
        errno = 0;
        check(open("/vtmp/nothere", O_PATH) == -1 && errno == ENOENT,
              "O_PATH missing -> ENOENT");
    }
        /* A file as the naming path is ENOTDIR. */
        int rf = open("/vtmp/regf.tmp", O_CREAT | O_RDWR, 0600);
        check(rf >= 0 && close(rf) == 0, "seed regular file");
        errno = 0;
        check(open("/vtmp/regf.tmp", O_TMPFILE | O_RDWR, 0640) == -1 &&
              errno == ENOTDIR,
              "O_TMPFILE on file -> ENOTDIR");
        check(unlink("/vtmp/regf.tmp") == 0, "unlink regf.tmp");
        /* The unnamed inode never appears in its directory. */
        int d2 = open("/vtmp", O_RDONLY | O_DIRECTORY);
        char db[2048];
        int leaked = 0;
        long g2;
        while (d2 >= 0 &&
               (g2 = syscall(SYS_getdents64, d2, db, sizeof(db))) > 0) {
            for (long o = 0; o + 19 <= g2; ) {
                struct { unsigned long ino, off; unsigned short len;
                         unsigned char type; char name[]; } *e =
                    (void *)(db + o);
                if (strncmp(e->name, "tmpfile:", 8) == 0) leaked = 1;
                o += e->len;
            }
        }
        if (d2 >= 0) close(d2);
        check(d2 >= 0 && leaked == 0,
              "unnamed inode stays out of getdents");
    }

    /* Cleanup: rmdir leaf-first, then back to root. */
    check(rmdir("/vtmp/sub") == 0, "rmdir /vtmp/sub");
    check(chdir("/") == 0 && rmdir("/vtmp") == 0,
          "rmdir /vtmp");
    check(access("/vtmp", F_OK) != 0, "/vtmp gone");
    close(dd);

    printf("dtest: %d failure%s, done\n", fails, fails == 1 ? "" : "s");
    return fails;
}
