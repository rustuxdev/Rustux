// memfdtest — compiled memfd_create + sealing ABI proof:
// memfd_create() mints an anonymous O_RDWR file born unlinked
// (path-invisible, "/memfd:name (deleted)" fd link); seals via
// fcntl F_ADD_SEALS/F_GET_SEALS gate ftruncate/grow/write; seals
// are inode state shared over dup/fork/SCM_RIGHTS; the gate set
// (EINVAL bad flags/non-memfd/unknown bits, EPERM sealed ops).
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <wait.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>

#ifndef MFD_ALLOW_SEALING
#define MFD_ALLOW_SEALING 2
#define MFD_CLOEXEC 1
#endif
#ifndef F_ADD_SEALS
#define F_ADD_SEALS 1033
#define F_GET_SEALS 1034
#endif
#ifndef F_SEAL_SEAL
#define F_SEAL_SEAL 0x01
#define F_SEAL_SHRINK 0x02
#define F_SEAL_GROW 0x04
#define F_SEAL_WRITE 0x08
#define F_SEAL_FUTURE_WRITE 0x10
#endif

static int fails;

static void say(const char *s) {
    if (write(1, s, strlen(s)) < 0) { /* ignore */ }
}

static void check(int ok, const char *what) {
    char buf[80];
    int n = snprintf(buf, sizeof(buf), "memfdtest: %-34s %s\n",
                     what, ok ? "ok" : "FAIL");
    say(buf);
    if (!ok) fails++;
}

static int mfd(const char *nm, unsigned flags) {
    return syscall(SYS_memfd_create, nm, flags);
}

int main(void) {
    char buf[256];
    int n;

    // ---- mint + identity ----
    int fd = mfd("basic", 0);
    check(fd >= 0, "memfd_create basic");
    check((fcntl(fd, F_GETFL) & O_ACCMODE) == O_RDWR, "fd is O_RDWR");
    struct stat st;
    check(fstat(fd, &st) == 0 && S_ISREG(st.st_mode),
          "fstat S_IFREG");
    n = snprintf(buf, sizeof(buf), "/proc/self/fd/%d", fd);
    char link[128];
    n = readlink(buf, link, sizeof(link) - 1);
    if (n > 0) link[n] = 0;
    check(n > 0 && strcmp(link, "/memfd:basic (deleted)") == 0,
          "fd link memfd:name (deleted)");
    check(open("/memfd:basic", O_RDONLY) < 0 && errno == ENOENT,
          "path-invisible inode");

    // ---- plain I/O ----
    check(write(fd, "hello", 5) == 5, "write ok");
    check(lseek(fd, 0, SEEK_SET) == 0, "lseek home");
    memset(buf, 0, sizeof(buf));
    check(read(fd, buf, 4) == 4 && memcmp(buf, "hell", 4) == 0,
          "read back");
    check(pwrite(fd, "Y", 1, 1) == 1, "pwrite in bounds");
    check(ftruncate(fd, 4096) == 0, "ftruncate grow");

    // ---- flag gates ----
    check(mfd("x", 0x4) < 0 && errno == EINVAL,
          "MFD_HUGETLB EINVAL");
    check(mfd("x", 0xffff) < 0 && errno == EINVAL,
          "unknown flags EINVAL");
    check(mfd("x", MFD_CLOEXEC) >= 0, "MFD_CLOEXEC ok");
    {
        int c = mfd("x", MFD_CLOEXEC);
        check(fcntl(c, F_GETFD) & FD_CLOEXEC, "cloexec lands");
        close(c);
    }
    {
        char longnm[256];
        memset(longnm, 'a', 250); longnm[250] = 0;
        longnm[249] = 0;  // 249-char name
        check(mfd(longnm, 0) >= 0, "249-char name ok");
        longnm[249] = 'a'; longnm[250] = 0;  // 250-char name
        check(mfd(longnm, 0) < 0 && errno == EINVAL,
              "250-char name EINVAL");
    }

    // ---- seals: the no-ALLOW_SEALING file is born SEAL_SEAL ----
    check(fcntl(fd, F_GET_SEALS) == F_SEAL_SEAL,
          "unsealable memfd seals");
    check(fcntl(fd, F_ADD_SEALS, F_SEAL_WRITE) < 0 && errno == EPERM,
          "ADD_SEALS EPERM sealed");

    // ---- seal fcntls refuse non-memfd fds ----
    int reg = open("/tmp_mfd_reg", O_CREAT | O_RDWR, 0600);
    check(reg >= 0, "create regular file");
    check(fcntl(reg, F_GET_SEALS) < 0 && errno == EINVAL,
          "GET_SEALS non-memfd EINVAL");
    check(fcntl(reg, F_ADD_SEALS, F_SEAL_WRITE) < 0 &&
          errno == EINVAL, "ADD_SEALS non-memfd EINVAL");
    close(fd);

    // ---- a sealable memfd ----
    int s = mfd("sealed", MFD_ALLOW_SEALING);
    check(s >= 0, "memfd_create sealable");
    check(fcntl(s, F_GET_SEALS) == 0, "born with no seals");
    check(fcntl(s, F_ADD_SEALS, 0x20) < 0 && errno == EINVAL,
          "unknown seal bits EINVAL");
    check(write(s, "12345678", 8) == 8, "pre-seal write");

    // GROW + SHRINK: the size is frozen at 8 in both directions.
    check(fcntl(s, F_ADD_SEALS, F_SEAL_GROW | F_SEAL_SHRINK) == 0,
          "add GROW|SHRINK");
    check(fcntl(s, F_GET_SEALS) ==
          (F_SEAL_GROW | F_SEAL_SHRINK), "seals accumulate");
    check(ftruncate(s, 4096) < 0 && errno == EPERM,
          "ftruncate grow EPERM");
    check(ftruncate(s, 2) < 0 && errno == EPERM,
          "ftruncate shrink EPERM");
    check(pwrite(s, "x", 1, 100) < 0 && errno == EPERM,
          "extending pwrite EPERM");
    check(pwrite(s, "x", 1, 0) == 1, "in-bounds pwrite ok");
    check(lseek(s, 0, SEEK_END) == 8 &&
          write(s, "!", 1) < 0 && errno == EPERM,
          "write at EOF EPERM");
    check(lseek(s, 0, SEEK_SET) == 0 && write(s, "Z", 1) == 1,
          "in-bounds write ok");

    // seals are inode state: dup'd and regular-file views share it.
    int d = dup(s);
    check(fcntl(d, F_GET_SEALS) == (F_SEAL_GROW | F_SEAL_SHRINK),
          "dup shares seals");
    check(ftruncate(d, 64) < 0 && errno == EPERM,
          "dup seal enforced");
    check(ftruncate(reg, 9999) == 0,
          "regular file unaffected");
    close(reg);
    unlink("/tmp_mfd_reg");  // no VFile litter — frames must reap clean

    // WRITE: all mutation dies; reads still flow.
    check(fcntl(s, F_ADD_SEALS, F_SEAL_WRITE) == 0, "add WRITE");
    check(write(s, "x", 1) < 0 && errno == EPERM,
          "write EPERM sealed");
    check(pwrite(s, "x", 1, 0) < 0 && errno == EPERM,
          "pwrite EPERM sealed");
    memset(buf, 0, sizeof(buf));
    check(pread(s, buf, 8, 0) == 8 && buf[0] == 'Z',
          "read still works");

    // SEAL_SEAL locks the set itself.
    check(fcntl(s, F_ADD_SEALS, F_SEAL_SEAL) == 0, "add SEAL_SEAL");
    check(fcntl(s, F_ADD_SEALS, F_SEAL_SHRINK) < 0 && errno == EPERM,
          "sealed set EPERM");

    // fork: the child sees the same inode seals.
    int pid = fork();
    if (pid == 0) {
        int ok = fcntl(s, F_GET_SEALS) ==
            (F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_WRITE | F_SEAL_SEAL)
            && write(s, "x", 1) < 0 && errno == EPERM;
        _exit(ok ? 0 : 40);
    }
    int wst = 0;
    waitpid(pid, &wst, 0);
    check(WIFEXITED(wst) && WEXITSTATUS(wst) == 0,
          "fork inherits seals");
    close(d);

    // SCM_RIGHTS: a memfd passed over a unix dgram arrives with its
    // seals and contents — the dbus/real-user-space pairing.
    int sp[2];
    check(socketpair(AF_UNIX, SOCK_DGRAM, 0, sp) == 0, "socketpair");
    {
        char cbuf[CMSG_SPACE(sizeof(int))];
        struct msghdr mh; memset(&mh, 0, sizeof(mh));
        struct iovec io = { .iov_base = (void *)"S", .iov_len = 1 };
        mh.msg_iov = &io; mh.msg_iovlen = 1;
        mh.msg_control = cbuf;
        mh.msg_controllen = sizeof(cbuf);
        struct cmsghdr *c = CMSG_FIRSTHDR(&mh);
        c->cmsg_level = SOL_SOCKET;
        c->cmsg_type = SCM_RIGHTS;
        c->cmsg_len = CMSG_LEN(sizeof(int));
        memcpy(CMSG_DATA(c), &s, sizeof(int));
        mh.msg_controllen = CMSG_SPACE(sizeof(int));
        check(sendmsg(sp[0], &mh, 0) == 1, "sendmsg memfd");
    }
    {
        char cbuf[CMSG_SPACE(sizeof(int))];
        struct msghdr mh; memset(&mh, 0, sizeof(mh));
        struct iovec io = { .iov_base = buf, .iov_len = 1 };
        mh.msg_iov = &io; mh.msg_iovlen = 1;
        mh.msg_control = cbuf;
        mh.msg_controllen = sizeof(cbuf);
        check(recvmsg(sp[1], &mh, 0) == 1, "recvmsg memfd");
        struct cmsghdr *c = CMSG_FIRSTHDR(&mh);
        int got = -1;
        if (c && c->cmsg_type == SCM_RIGHTS)
            memcpy(&got, CMSG_DATA(c), sizeof(int));
        check(got >= 0, "SCM_RIGHTS delivered fd");
        check(fcntl(got, F_GET_SEALS) ==
              (F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_WRITE |
               F_SEAL_SEAL), "passed fd shares seals");
        memset(buf, 0, sizeof(buf));
        check(pread(got, buf, 8, 0) == 8 && buf[0] == 'Z',
              "passed fd reads content");
        close(got);
    }
    close(sp[0]); close(sp[1]); close(s);

    // MAP_PRIVATE on a sealed file still maps (private copies are
    // not a seal concern — only shared writable maps are).
    s = mfd("map", MFD_ALLOW_SEALING);
    check(write(s, "mapped!", 7) == 7, "map memfd write");
    check(fcntl(s, F_ADD_SEALS, F_SEAL_WRITE | F_SEAL_GROW |
          F_SEAL_SHRINK | F_SEAL_FUTURE_WRITE) == 0,
          "seal all incl FUTURE_WRITE");
    void *m = mmap(0, 4096, PROT_READ, MAP_PRIVATE, s, 0);
    check(m != MAP_FAILED && memcmp(m, "mapped!", 7) == 0,
          "MAP_PRIVATE reads sealed memfd");
    munmap(m, 4096);
    check(write(s, "x", 1) < 0 && errno == EPERM,
          "FUTURE_WRITE blocks writes");
    close(s);

    n = snprintf(buf, sizeof(buf), "memfdtest: %d failure(s)\n",
                 fails);
    say(buf);
    return fails;
}
