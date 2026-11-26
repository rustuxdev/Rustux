// pidfdtest — compiled pidfd ABI proof:
// pidfd_open() mints an anon-inode fd naming a task; poll fires
// POLLIN at its death (blocked-poll wake too); pidfd_send_signal
// rides kill() with zombie/gone -> ESRCH; pidfd_getfd clones an
// fd out of a live target's table; the gate set (EINVAL bad
// flags/non-pid/info, ESRCH dead, EBADF non-pidfd/empty slot).
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
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

#ifndef F_GET_SEALS
#define F_GET_SEALS 1034
#endif
#ifndef F_SEAL_SEAL
#define F_SEAL_SEAL 0x01
#endif

static int fails;

static void say(const char *s) {
    if (write(1, s, strlen(s)) < 0) { /* ignore */ }
}

static void check(int ok, const char *what) {
    char buf[80];
    int n = snprintf(buf, sizeof(buf), "pidfdtest: %-34s %s\n",
                     what, ok ? "ok" : "FAIL");
    say(buf);
    if (!ok) fails++;
}

static int pfd_open(int pid, unsigned flags) {
    return syscall(SYS_pidfd_open, pid, flags);
}
static int pfd_sig(int fd, int sig, void *info, unsigned flags) {
    return syscall(SYS_pidfd_send_signal, fd, sig, info, flags);
}
static int pfd_getfd(int fd, int tfd, unsigned flags) {
    return syscall(SYS_pidfd_getfd, fd, tfd, flags);
}
static int mfd(const char *nm, unsigned flags) {
    return syscall(SYS_memfd_create, nm, flags);
}

int main(void) {
    char buf[256];
    int n;

    // ---- mint + gates ----
    int self = pfd_open(getpid(), 0);
    check(self >= 0, "pidfd_open self");
    check(pfd_open(getpid(), 1) < 0 && errno == EINVAL,
          "flags EINVAL");
    check(pfd_open(0, 0) < 0 && errno == EINVAL, "pid 0 EINVAL");
    check(pfd_open(-1, 0) < 0 && errno == EINVAL, "pid -1 EINVAL");
    check(pfd_open(999999, 0) < 0 && errno == ESRCH,
          "missing pid ESRCH");

    // ---- fd shape: anon-inode stat + link, no io surface ----
    struct stat st;
    check(fstat(self, &st) == 0 && S_ISCHR(st.st_mode),
          "fstat anon_inode chr");
    n = snprintf(buf, sizeof(buf), "/proc/self/fd/%d", self);
    char link[128];
    n = readlink(buf, link, sizeof(link) - 1);
    if (n > 0) link[n] = 0;
    check(n > 0 && strcmp(link, "anon_inode:[pidfd]") == 0,
          "fd link anon_inode:[pidfd]");
    check(read(self, buf, 8) < 0 && errno == EINVAL, "read EINVAL");
    check(write(self, "x", 1) < 0 && errno == EINVAL, "write EINVAL");
    check(lseek(self, 0, SEEK_SET) < 0 && errno == ESPIPE,
          "lseek ESPIPE");

    // ---- live self: poll silent, probes + getfd work ----
    struct pollfd p = { .fd = self, .events = POLLIN };
    check(poll(&p, 1, 0) == 0, "live pidfd silent");
    check(pfd_sig(self, 0, 0, 0) == 0, "sig 0 liveness probe");
    check(pfd_sig(self, 999, 0, 0) < 0 && errno == EINVAL,
          "bad sig EINVAL");
    check(pfd_sig(self, 0, buf, 0) < 0 && errno == EINVAL,
          "non-null info EINVAL");
    check(pfd_sig(self, 0, 0, 1) < 0 && errno == EINVAL,
          "signal flags EINVAL");
    int dupfd = pfd_getfd(self, 0, 0);
    check(dupfd >= 0 && (fcntl(dupfd, F_GETFD) & FD_CLOEXEC) == 0,
          "getfd clones fd");
    check(pfd_getfd(self, 15, 0) < 0 && errno == EBADF,
          "getfd empty slot EBADF");
    check(pfd_getfd(self, 0, 4) < 0 && errno == EINVAL,
          "getfd flags EINVAL");
    check(pfd_sig(STDIN_FILENO, 0, 0, 0) < 0 && errno == EBADF,
          "non-pidfd signal EBADF");
    close(dupfd);

    // ---- signal a live child dead; poll + gates flip ----
    int pid = fork();
    if (pid == 0) {
        for (;;) pause();        // killed by SIGTERM mid-pause
        _exit(77);
    }
    int cf = pfd_open(pid, 0);
    check(cf >= 0, "pidfd_open child");
    struct pollfd cp = { .fd = cf, .events = POLLIN };
    check(poll(&cp, 1, 0) == 0, "live child silent");
    check(pfd_sig(cf, SIGTERM, 0, 0) == 0, "send_signal SIGTERM");
    int wst = 0;
    check(waitpid(pid, &wst, 0) == pid, "child reaped");
    check(poll(&cp, 1, 0) == 1 && (cp.revents & POLLIN),
          "dead child POLLIN");
    check(pfd_sig(cf, 0, 0, 0) < 0 && errno == ESRCH,
          "dead target ESRCH");
    check(pfd_getfd(cf, 0, 0) < 0 && errno == ESRCH,
          "dead getfd ESRCH");
    close(cf);

    // ---- blocked-poll wake: poll(-1) must fire when the target
    // dies — exit_bookkeeping's wake_pollers does the rescan ----
    int pid2 = fork();
    if (pid2 == 0) {
        usleep(60000);           // ~60ms — parent blocks first
        _exit(0);
    }
    int cf2 = pfd_open(pid2, 0);
    struct pollfd cp2 = { .fd = cf2, .events = POLLIN };
    check(poll(&cp2, 1, 5000) == 1 && (cp2.revents & POLLIN),
          "blocked poll wakes on exit");
    int wst2 = 0;
    waitpid(pid2, &wst2, 0);
    close(cf2);

    // ---- getfd across a live child: steal a memfd, read it ----
    int up[2], dn[2];
    check(pipe(up) == 0 && pipe(dn) == 0, "sync pipes");
    int pid3 = fork();
    if (pid3 == 0) {
        int m = mfd("loot", 0);
        if (write(m, "treasure", 8) < 0) { }
        char fdch = (char)m;
        if (write(up[1], &fdch, 1) < 0) { }
        char c;
        if (read(dn[0], &c, 1) < 0) { } // hold alive until released
        _exit(0);
    }
    close(up[1]); close(dn[0]);
    char fdch = -1;
    check(read(up[0], &fdch, 1) == 1, "child reports fd");
    int cfd = pfd_open(pid3, 0);
    check(cfd >= 0, "pidfd_open child3");
    int stolen = pfd_getfd(cfd, (unsigned char)fdch, 0);
    check(stolen >= 0, "getfd steals memfd");
    memset(buf, 0, sizeof(buf));
    check(stolen >= 0 && pread(stolen, buf, 8, 0) == 8 &&
          memcmp(buf, "treasure", 8) == 0,
          "stolen fd reads content");
    check(stolen >= 0 && fcntl(stolen, F_GET_SEALS) == F_SEAL_SEAL,
          "stolen memfd keeps seals");
    close(stolen);
    char c = 'q';
    if (write(dn[1], &c, 1) < 0) { }
    close(dn[1]); close(up[0]);
    int wst3 = 0;
    waitpid(pid3, &wst3, 0);
    close(cfd);

    // ---- SCM_RIGHTS: a passed pidfd works in the receiver ----
    int sp[2];
    check(socketpair(AF_UNIX, SOCK_DGRAM, 0, sp) == 0, "socketpair");
    {
        char cbuf[CMSG_SPACE(sizeof(int))];
        struct msghdr mh; memset(&mh, 0, sizeof(mh));
        struct iovec io = { .iov_base = (void *)"P", .iov_len = 1 };
        mh.msg_iov = &io; mh.msg_iovlen = 1;
        mh.msg_control = cbuf;
        mh.msg_controllen = sizeof(cbuf);
        struct cmsghdr *cm = CMSG_FIRSTHDR(&mh);
        cm->cmsg_level = SOL_SOCKET;
        cm->cmsg_type = SCM_RIGHTS;
        cm->cmsg_len = CMSG_LEN(sizeof(int));
        memcpy(CMSG_DATA(cm), &self, sizeof(int));
        mh.msg_controllen = CMSG_SPACE(sizeof(int));
        check(sendmsg(sp[0], &mh, 0) == 1, "sendmsg pidfd");
    }
    {
        char cbuf[CMSG_SPACE(sizeof(int))];
        struct msghdr mh; memset(&mh, 0, sizeof(mh));
        struct iovec io = { .iov_base = buf, .iov_len = 1 };
        mh.msg_iov = &io; mh.msg_iovlen = 1;
        mh.msg_control = cbuf;
        mh.msg_controllen = sizeof(cbuf);
        check(recvmsg(sp[1], &mh, 0) == 1, "recvmsg pidfd");
        struct cmsghdr *cm = CMSG_FIRSTHDR(&mh);
        int got = -1;
        if (cm && cm->cmsg_type == SCM_RIGHTS)
            memcpy(&got, CMSG_DATA(cm), sizeof(int));
        check(got >= 0 && pfd_sig(got, 0, 0, 0) == 0,
              "passed pidfd probes self");
        if (got >= 0) close(got);
    }
    close(sp[0]); close(sp[1]); close(self);

    n = snprintf(buf, sizeof(buf), "pidfdtest: %d failure(s)\n",
                 fails);
    say(buf);
    return fails;
}
