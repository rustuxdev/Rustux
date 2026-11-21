// iotest — compiled file-I/O ABI proof: the syscalls a real glibc
// program actually uses for file work: openat(257) behind fopen,
// pread64(17), lseek(8), fcntl(72) FD flags, dup3(292), and the
// archive's honest EROFS/EINVAL answers. Same check() convention
// as parent.c — exit status is the failure count.
// motd.txt = "MOTD: greetings from the Rustux initrd filesystem\r\n"
// so "greetings" sits at byte 6 and "from" at byte 16.
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/select.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <poll.h>
#include <signal.h>
#include <sys/epoll.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>

static int fails;

static void say(const char *s) {
    if (write(1, s, strlen(s)) < 0) { /* ignore */ }
}

static void check(int ok, const char *what) {
    char buf[80];
    int n = snprintf(buf, sizeof(buf), "iotest: %-28s %s\n",
                     what, ok ? "ok" : "FAIL");
    say(buf);
    if (!ok) fails++;
}

int main(void) {
    char buf[128];

    say("iotest: file-io abi checks\n");

    /* fopen -> openat(AT_FDCWD, "motd.txt", O_RDONLY|O_CLOEXEC) */
    FILE *f = fopen("motd.txt", "r");
    check(f != NULL, "fopen motd.txt");
    if (f) {
        char line[64] = {0};
        check(fgets(line, sizeof(line), f) != NULL &&
              strstr(line, "greetings") != NULL, "fgets motd line");
        check(fclose(f) == 0, "fclose");
    }

    /* openat + O_CLOEXEC + pread (no offset movement) */
    int fd = openat(AT_FDCWD, "motd.txt", O_RDONLY | O_CLOEXEC);
    check(fd >= 0, "openat O_CLOEXEC");
    if (fd >= 0) {
        memset(buf, 0, sizeof(buf));
        long n = pread(fd, buf, 9, 6);
        check(n == 9 && memcmp(buf, "greetings", 9) == 0, "pread offset 6");
        /* pread must NOT have moved the shared position */
        check(lseek(fd, 0, SEEK_CUR) == 0, "pread keeps pos");
        /* lseek SET/CUR/END + read */
        check(lseek(fd, 16, SEEK_SET) == 16, "lseek SEEK_SET");
        memset(buf, 0, sizeof(buf));
        n = read(fd, buf, 4);
        check(n == 4 && memcmp(buf, "from", 4) == 0, "read after lseek");
        check(lseek(fd, -1, SEEK_END) > 0, "lseek SEEK_END");

        /* fcntl: F_GETFD sees the CLOEXEC bit set at open */
        check(fcntl(fd, F_GETFD) == FD_CLOEXEC, "fcntl GETFD cloexec");
        check(fcntl(fd, F_SETFD, 0) == 0, "fcntl SETFD clear");
        check(fcntl(fd, F_GETFD) == 0, "fcntl GETFD clear");
        check(fcntl(fd, F_GETFL) == O_RDONLY, "fcntl GETFL rdonly");

        /* dup3 O_CLOEXEC: new fd carries the bit */
        int fd2 = dup3(fd, fd + 1, O_CLOEXEC);
        check(fd2 == fd + 1, "dup3 slot");
        check(fd2 >= 0 && fcntl(fd2, F_GETFD) == FD_CLOEXEC,
              "dup3 keeps cloexec");
        /* plain dup must NOT inherit the bit */
        int fd3 = dup(fd);
        check(fd3 >= 0 && fcntl(fd3, F_GETFD) == 0, "dup clears cloexec");
        close(fd2); close(fd3); close(fd);
    }

    /* /dev/tty — the controlling terminal device: this session owns
       the console so it must open and answer tty ioctls. */
    int tfd = open("/dev/tty", O_RDWR);
    check(tfd >= 0, "open /dev/tty");
    if (tfd >= 0) {
        struct termios tio;
        check(ioctl(tfd, TCGETS, &tio) == 0, "tcgets on /dev/tty");
        close(tfd);
    }

    /* openat relative through a real Dir dirfd (".") */
    int dfd = open(".", O_RDONLY | O_DIRECTORY);
    check(dfd >= 0, "open dir O_DIRECTORY");
    if (dfd >= 0) {
        int r = openat(dfd, "motd.txt", O_RDONLY);
        check(r >= 0, "openat via dirfd");
        if (r >= 0) close(r);
        close(dfd);
    }

    /* honest refusals */
    errno = 0;
    check(open("definitely-missing", O_RDONLY) < 0 && errno == ENOENT,
          "missing -> ENOENT");
    errno = 0;
    check(open("motd.txt", O_WRONLY) < 0 && errno == EROFS,
          "write open -> EROFS");
    errno = 0;
    check(openat(AT_FDCWD, "motd.txt", O_RDONLY | 0x2000) < 0 &&
          errno == EINVAL, "unknown flag -> EINVAL");
    check(pread(9999, buf, 1, 0) < 0, "pread bad fd");

    /* pselect6(270) — readline's input wait. A ready pipe's bit
       comes back set, an empty one with a zero timeout clears it;
       writefds report writable the same way. */
    int p[2] = {-1, -1};
    check(pipe(p) == 0, "pipe for pselect");
    if (p[0] >= 0 && p[1] >= 0) {
        fd_set rs, ws;
        struct timespec zt = {0, 0};
        FD_ZERO(&rs); FD_ZERO(&ws);
        FD_SET(p[0], &rs); FD_SET(p[1], &ws);
        int n2 = pselect(p[1] + 1, &rs, &ws, NULL, &zt, NULL);
        check(n2 == 1 && !FD_ISSET(p[0], &rs) && FD_ISSET(p[1], &ws),
              "pselect idle pipe");
        if (write(p[1], "x", 1) == 1) {
            FD_ZERO(&rs); FD_SET(p[0], &rs);
            check(pselect(p[0] + 1, &rs, NULL, NULL, &zt, NULL) == 1 &&
                  FD_ISSET(p[0], &rs), "pselect ready pipe");
        }
        errno = 0;
        check(pselect(9999, &rs, NULL, NULL, &zt, NULL) < 0 &&
              errno == EINVAL, "pselect huge nfds");

        /* ppoll(271) — poll + timespec + atomic mask swap. A ready
           pipe reports POLLIN, an idle one times out with revents
           zeroed, and a sigmask swap restores on return. The pselect
           block left one byte queued — drain it for the idle cases. */
        char c;
        check(read(p[0], &c, 1) == 1 && c == 'x', "drain pselect byte");
        struct pollfd pf = { .fd = p[0], .events = POLLIN };
        pf.revents = 0xffff;
        if (write(p[1], "y", 1) == 1) {
            errno = 0;
            check(ppoll(&pf, 1, &zt, NULL) == 1 && (pf.revents & POLLIN),
                  "ppoll ready pipe");
            char c2;
            read(p[0], &c2, 1);
        }
        pf.revents = 0xffff;
        check(ppoll(&pf, 1, &zt, NULL) == 0 && pf.revents == 0,
              "ppoll idle pipe timeout");
        sigset_t blk, prev;
        sigemptyset(&blk); sigaddset(&blk, SIGUSR1);
        check(sigprocmask(SIG_SETMASK, NULL, &prev) == 0 &&
              ppoll(&pf, 1, &zt, &blk) == 0 &&
              sigprocmask(SIG_SETMASK, NULL, &blk) == 0 &&
              !sigismember(&blk, SIGUSR1),
              "ppoll sigmask restored after wait");
        sigprocmask(SIG_SETMASK, &prev, NULL);
        struct timespec bad = {0, -1};
        errno = 0;
        check(ppoll(&pf, 1, &bad, NULL) < 0 && errno == EINVAL,
              "ppoll bad nsec -> EINVAL");
        close(p[0]); close(p[1]);
    }

    /* epoll(7) — create1/ctl/wait/pwait, the readiness-multiplexing
       family real daemons prefer. Interest sets pin the file
       description, report the caller's data cookie, and level-
       trigger like the defaults say. */
    int ep = epoll_create1(0);
    check(ep >= 0, "epoll_create1");
    int epfd[2] = {-1, -1};
    check(pipe(epfd) == 0, "pipe for epoll");
    if (ep >= 0 && epfd[0] >= 0 && epfd[1] >= 0) {
        struct epoll_event ee, out[4];
        memset(&ee, 0, sizeof(ee));
        ee.events = EPOLLIN;
        ee.data.u64 = 0x5ca1ab1eULL;
        check(epoll_ctl(ep, EPOLL_CTL_ADD, epfd[0], &ee) == 0,
              "epoll_ctl ADD");
        check(write(epfd[1], "e", 1) == 1, "epoll pipe write");
        memset(out, 0, sizeof(out));
        int nw = epoll_wait(ep, out, 4, 0);
        check(nw == 1 && (out[0].events & EPOLLIN) &&
              out[0].data.u64 == 0x5ca1ab1eULL,
              "epoll_wait ready+cookie");
        char ec;
        check(read(epfd[0], &ec, 1) == 1, "drain epoll byte");
        check(epoll_wait(ep, out, 4, 0) == 0, "epoll idle -> 0");
        check(epoll_wait(ep, out, 4, 30) == 0, "epoll timeout -> 0");

        /* ctl errors: dup ADD -> EEXIST, MOD missing -> ENOENT,
           DEL twice -> ENOENT, ctl on a non-epoll fd -> EINVAL,
           self-watch -> EINVAL, bad op -> EINVAL. */
        errno = 0;
        check(epoll_ctl(ep, EPOLL_CTL_ADD, epfd[0], &ee) < 0 &&
              errno == EEXIST, "epoll dup ADD -> EEXIST");
        errno = 0;
        check(epoll_ctl(ep, EPOLL_CTL_MOD, epfd[1], &ee) < 0 &&
              errno == ENOENT, "epoll MOD missing -> ENOENT");
        check(epoll_ctl(ep, EPOLL_CTL_DEL, epfd[0], NULL) == 0,
              "epoll_ctl DEL");
        errno = 0;
        check(epoll_ctl(ep, EPOLL_CTL_DEL, epfd[0], NULL) < 0 &&
              errno == ENOENT, "epoll DEL twice -> ENOENT");
        errno = 0;
        check(epoll_ctl(epfd[0], EPOLL_CTL_ADD, epfd[0], &ee) < 0 &&
              errno == EINVAL, "ctl non-epoll -> EINVAL");
        errno = 0;
        check(epoll_ctl(ep, EPOLL_CTL_ADD, ep, &ee) < 0,
              "epoll self-watch refused");
        errno = 0;
        check(epoll_ctl(ep, 99, epfd[0], &ee) < 0 && errno == EINVAL,
              "epoll bad op -> EINVAL");

        /* MOD actually changes the mask: EPOLLOUT on a pipe read
           end never fires — a queued byte stays invisible until
           MOD back to EPOLLIN reports it. */
        check(epoll_ctl(ep, EPOLL_CTL_ADD, epfd[0], &ee) == 0,
              "epoll_ctl re-ADD");
        ee.events = EPOLLOUT;
        check(epoll_ctl(ep, EPOLL_CTL_MOD, epfd[0], &ee) == 0,
              "epoll_ctl MOD");
        check(write(epfd[1], "f", 1) == 1 &&
              epoll_wait(ep, out, 4, 0) == 0,
              "MOD'd mask hides the byte");
        ee.events = EPOLLIN;
        check(epoll_ctl(ep, EPOLL_CTL_MOD, epfd[0], &ee) == 0 &&
              epoll_wait(ep, out, 4, 0) == 1,
              "MOD back reports it");
        char ec2;
        read(epfd[0], &ec2, 1);

        /* epoll_pwait(281): the mask swap restores on return, same
           discipline as ppoll. */
        sigset_t eblk, eprev;
        sigemptyset(&eblk); sigaddset(&eblk, SIGUSR1);
        check(sigprocmask(SIG_SETMASK, NULL, &eprev) == 0 &&
              epoll_pwait(ep, out, 4, 0, &eblk) == 0 &&
              sigprocmask(SIG_SETMASK, NULL, &eblk) == 0 &&
              !sigismember(&eblk, SIGUSR1),
              "epoll_pwait mask restored");

        /* The blocked-wait wake path: a forking writer delivers a
           byte while the parent sleeps in epoll_wait — the rescan
           must report it, not time out. */
        pid_t kid = fork();
        check(kid >= 0, "epoll wake fork");
        if (kid == 0) {
            struct timespec d = {0, 40000000};
            nanosleep(&d, NULL);
            write(epfd[1], "w", 1);
            _exit(0);
        }
        if (kid > 0) {
            int nw2 = epoll_wait(ep, out, 4, 2000);
            check(nw2 == 1 && (out[0].events & EPOLLIN),
                  "epoll_wait blocked wake");
            char ec3;
            read(epfd[0], &ec3, 1);
            waitpid(kid, NULL, 0);
        }

        /* fstat type + the read-side EINVAL Linux gives epoll fds. */
        struct stat est;
        check(fstat(ep, &est) == 0 && S_ISCHR(est.st_mode),
              "epoll fstat chrdev");
        errno = 0;
        check(read(ep, &ec, 1) < 0 && errno == EINVAL,
              "epoll read -> EINVAL");
        close(epfd[0]); close(epfd[1]);
        close(ep);
    }

    int n = snprintf(buf, sizeof(buf), "iotest: %d failures, done\n", fails);
    say(buf);
    return fails;
}
