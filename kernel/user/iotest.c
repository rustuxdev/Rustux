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
#include <sys/inotify.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/eventfd.h>
#include <sys/timerfd.h>
#include <sys/syscall.h>
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

        /* eventfd + timerfd — the anon-inode fd family glibc's
           event loop wants. eventfd is a u64 semaphore: write
           adds, read drains (or decrements under EFD_SEMAPHORE),
           zero-counter reads block or EAGAIN. */
        int efd = eventfd(0, EFD_NONBLOCK);
        check(efd >= 0, "eventfd create");
        uint64_t ev = 0;
        errno = 0;
        check(efd >= 0 && read(efd, &ev, 8) < 0 && errno == EAGAIN,
              "eventfd empty -> EAGAIN");
        ev = 5;
        check(write(efd, &ev, 8) == 8, "eventfd write 5");
        struct pollfd epf = { .fd = efd, .events = POLLIN };
        check(poll(&epf, 1, 0) == 1 && (epf.revents & POLLIN),
              "eventfd poll ready");
        ev = 0;
        check(read(efd, &ev, 8) == 8 && ev == 5, "eventfd drain 5");
        errno = 0;
        check(read(efd, &ev, 8) < 0 && errno == EAGAIN,
              "eventfd drained -> EAGAIN");
        ev = ~0ULL;
        errno = 0;
        check(write(efd, &ev, 8) < 0 && errno == EINVAL,
              "eventfd write MAX -> EINVAL");
        errno = 0;
        check(write(efd, &ev, 4) < 0 && errno == EINVAL,
              "eventfd short write EINVAL");
        check(fstat(efd, &est) == 0 && S_ISCHR(est.st_mode),
              "eventfd fstat chrdev");

        /* EFD_SEMAPHORE: each read returns 1 and decrements. */
        int sefd = eventfd(2, EFD_SEMAPHORE | EFD_NONBLOCK);
        ev = 0;
        check(sefd >= 0 &&
              read(sefd, &ev, 8) == 8 && ev == 1 &&
              read(sefd, &ev, 8) == 8 && ev == 1 &&
              (errno = 0, read(sefd, &ev, 8) < 0 && errno == EAGAIN),
              "eventfd semaphore count");
        if (sefd >= 0) close(sefd);

        /* epoll watching an eventfd — the composition real event
           loops build on. */
        check(epoll_ctl(ep, EPOLL_CTL_ADD, efd, &ee) == 0,
              "epoll ADD eventfd");
        ev = 7;
        check(write(efd, &ev, 8) == 8 &&
              epoll_wait(ep, out, 4, 0) == 1 &&
              (out[0].events & EPOLLIN),
              "epoll sees eventfd");
        ev = 0;
        read(efd, &ev, 8);
        close(efd);

        /* Blocked eventfd read: a forking writer delivers while
           the parent sleeps — the wake deposits the value, not a
           spurious EAGAIN or zero. */
        int befd = eventfd(0, 0);
        check(befd >= 0, "blocking eventfd create");
        pid_t ekid = befd >= 0 ? fork() : -1;
        if (ekid == 0) {
            struct timespec d = {0, 40000000};
            nanosleep(&d, NULL);
            uint64_t one = 9;
            write(befd, &one, 8);
            _exit(0);
        }
        if (ekid > 0) {
            ev = 0;
            check(read(befd, &ev, 8) == 8 && ev == 9,
                  "eventfd blocked read wake");
            waitpid(ekid, NULL, 0);
        }
        if (befd >= 0) close(befd);

        /* timerfd: arm a one-shot, block for it, then a periodic
           and the overrun count. */
        int tfd = timerfd_create(CLOCK_MONOTONIC, 0);
        check(tfd >= 0, "timerfd_create");
        struct itimerspec its;
        memset(&its, 0, sizeof(its));
        its.it_value.tv_nsec = 30000000; /* 30 ms */
        check(tfd >= 0 &&
              timerfd_settime(tfd, 0, &its, NULL) == 0,
              "timerfd arm 30ms");
        ev = 0;
        check(read(tfd, &ev, 8) == 8 && ev == 1,
              "timerfd read expires");
        check(fstat(tfd, &est) == 0 && S_ISCHR(est.st_mode),
              "timerfd fstat chrdev");

        /* Periodic: 20ms value + 20ms interval; ~75ms of suite
           time later the count must be >=2 (overruns fold in). */
        its.it_interval.tv_nsec = 20000000;
        its.it_value.tv_nsec = 20000000;
        check(timerfd_settime(tfd, 0, &its, NULL) == 0,
              "timerfd arm periodic");
        struct timespec nap = {0, 75000000};
        nanosleep(&nap, NULL);
        ev = 0;
        check(read(tfd, &ev, 8) == 8 && ev >= 2,
              "timerfd periodic >=2");

        /* Disarm via zero it_value; gettime then reports zeros;
           settime on a non-timerfd is EINVAL. */
        memset(&its, 0, sizeof(its));
        check(timerfd_settime(tfd, 0, &its, NULL) == 0,
              "timerfd disarm");
        struct itimerspec cur;
        check(timerfd_gettime(tfd, &cur) == 0 &&
              cur.it_value.tv_sec == 0 && cur.it_value.tv_nsec == 0,
              "timerfd gettime disarmed");
        errno = 0;
        check(timerfd_settime(epfd[1], 0, &its, NULL) < 0 &&
              errno == EINVAL, "settime non-timerfd EINVAL");
        close(tfd);
        errno = 0;
        check(read(ep, &ec, 1) < 0 && errno == EINVAL,
              "epoll read -> EINVAL");
        close(epfd[0]); close(epfd[1]);
        close(ep);
    }

    /* ---- /proc: generated files, pid dirs, stat content ---- */
    {
        char pbuf[256];
        struct stat pst;

        /* /proc/self is a live pid dir; its files are generated. */
        int fd = open("/proc/self/stat", O_RDONLY);
        check(fd >= 0, "open /proc/self/stat");
        int n2 = fd >= 0 ? read(fd, pbuf, sizeof(pbuf) - 1) : -1;
        check(n2 > 0, "read /proc/self/stat");
        if (n2 > 0) {
            long rpid, rppid;
            char rcomm[64], rstate;
            pbuf[n2] = 0;
            check(sscanf(pbuf, "%ld (%63[^)]) %c %ld",
                         &rpid, rcomm, &rstate, &rppid) == 4,
                  "stat parse pid/comm/state/ppid");
            check(rpid == getpid() && rstate == 'R',
                  "stat self pid+state");
            /* ppid is 0 — suite tasks are spawned, not forked. */
            check(rppid == 0, "stat self ppid");
        }
        if (fd >= 0) close(fd);

        /* comm and cmdline carry the image identity. */
        fd = open("/proc/self/comm", O_RDONLY);
        n2 = fd >= 0 ? read(fd, pbuf, sizeof(pbuf)) : -1;
        check(fd >= 0 && n2 == 7 &&
              memcmp(pbuf, "iotest\n", 7) == 0, "comm iotest");
        if (fd >= 0) close(fd);

        fd = open("/proc/self/cmdline", O_RDONLY);
        n2 = fd >= 0 ? read(fd, pbuf, sizeof(pbuf)) : -1;
        check(fd >= 0 && n2 > 0 &&
              memcmp(pbuf, "iotest", 6) == 0 && pbuf[n2 - 1] == 0,
              "cmdline exe+NUL");
        if (fd >= 0) close(fd);

        /* The exe link: readlink resolves it, stat follows it. */
        n2 = readlink("/proc/self/exe", pbuf, sizeof(pbuf));
        check(n2 == 7 && memcmp(pbuf, "/iotest", 7) == 0,
              "readlink self/exe");
        check(stat("/proc/self/exe", &pst) == 0 &&
              S_ISREG(pst.st_mode) && pst.st_size > 0,
              "stat self/exe -> image");

        /* Global files. */
        fd = open("/proc/uptime", O_RDONLY);
        n2 = fd >= 0 ? read(fd, pbuf, sizeof(pbuf) - 1) : -1;
        if (n2 > 0) pbuf[n2] = 0;
        unsigned long us, is;
        check(fd >= 0 && n2 > 0 &&
              sscanf(pbuf, "%lu.%*u %lu.%*u", &us, &is) == 2,
              "uptime parses");
        if (fd >= 0) close(fd);

        fd = open("/proc/meminfo", O_RDONLY);
        n2 = fd >= 0 ? read(fd, pbuf, sizeof(pbuf) - 1) : -1;
        if (n2 > 0) pbuf[n2] = 0;
        check(fd >= 0 && n2 > 0 &&
              strstr(pbuf, "MemTotal:") != NULL &&
              strstr(pbuf, "MemFree:") != NULL,
              "meminfo fields");
        if (fd >= 0) close(fd);

        fd = open("/proc/version", O_RDONLY);
        n2 = fd >= 0 ? read(fd, pbuf, sizeof(pbuf) - 1) : -1;
        if (n2 > 0) pbuf[n2] = 0;
        check(fd >= 0 && n2 > 0 &&
              strstr(pbuf, "Rustux") != NULL,
              "version names rustux");
        if (fd >= 0) close(fd);

        /* fstat shape: a 0444 regular with the snapshot size;
           lseek/pread walk it like a file. */
        fd = open("/proc/self/stat", O_RDONLY);
        check(fd >= 0 && fstat(fd, &pst) == 0 &&
              S_ISREG(pst.st_mode) && (pst.st_mode & 0777) == 0444,
              "proc fstat 0444 reg");
        if (fd >= 0) {
            check(lseek(fd, 5, SEEK_SET) == 5 &&
                  read(fd, pbuf, 3) == 3, "proc lseek+read");
            check(pread(fd, pbuf, 4, 0) == 4, "proc pread");
        }
        if (fd >= 0) close(fd);

        /* Directory shapes. */
        check(stat("/proc", &pst) == 0 && S_ISDIR(pst.st_mode),
              "stat /proc dir");
        check(stat("/proc/self", &pst) == 0 && S_ISDIR(pst.st_mode),
              "stat /proc/self dir");

        /* /proc lists numeric pid dirs + the synthetic names. */
        int dfd = open("/proc", O_RDONLY | O_DIRECTORY);
        check(dfd >= 0, "open /proc dir");
        if (dfd >= 0) {
            char dbuf[1024];
            int dl = syscall(SYS_getdents64, dfd, dbuf, sizeof(dbuf));
            check(dl > 0, "getdents /proc");
            int saw_self = 0, saw_pid = 0, saw_uptime = 0;
            char pp[16];
            snprintf(pp, sizeof(pp), "%d", getpid());
            for (int off = 0; dl > 0 && off < dl; ) {
                struct {
                    unsigned long ino, off2;
                    unsigned short rlen;
                    unsigned char type;
                    char name[];
                } *de = (void *)(dbuf + off);
                if (strcmp(de->name, "self") == 0) saw_self = 1;
                if (strcmp(de->name, "uptime") == 0) saw_uptime = 1;
                if (strcmp(de->name, pp) == 0) saw_pid = 1;
                off += de->rlen;
            }
            check(saw_self && saw_uptime, "proc lists self+uptime");
            check(saw_pid, "proc lists own pid");
            close(dfd);
        }

        /* The pid dir lists the per-task files. */
        dfd = open("/proc/self", O_RDONLY | O_DIRECTORY);
        check(dfd >= 0, "open /proc/self dir");
        if (dfd >= 0) {
            char dbuf[512];
            int dl = syscall(SYS_getdents64, dfd, dbuf, sizeof(dbuf));
            int saw_stat = 0, saw_exe = 0;
            for (int off = 0; dl > 0 && off < dl; ) {
                struct {
                    unsigned long ino, off2;
                    unsigned short rlen;
                    unsigned char type;
                    char name[];
                } *de = (void *)(dbuf + off);
                if (strcmp(de->name, "stat") == 0) saw_stat = 1;
                if (strcmp(de->name, "exe") == 0) saw_exe = 1;
                off += de->rlen;
            }
            check(saw_stat && saw_exe, "pid dir lists stat+exe");
            close(dfd);
        }

        /* A child's stat is visible under its own pid while it
           lives — fork, read /proc/<kid>/stat in the parent. */
        pid_t kid = fork();
        if (kid == 0) {
            struct timespec nap = {0, 200000000};
            nanosleep(&nap, NULL);
            _exit(0);
        }
        if (kid > 0) {
            char kp[64];
            snprintf(kp, sizeof(kp), "/proc/%d/stat", kid);
            fd = open(kp, O_RDONLY);
            n2 = fd >= 0 ? read(fd, pbuf, sizeof(pbuf) - 1) : -1;
            check(fd >= 0 && n2 > 0, "read child stat");
            if (n2 > 0) {
                long rpid, rppid;
                char rc[64], rs;
                pbuf[n2] = 0;
                check(sscanf(pbuf, "%ld (%63[^)]) %c %ld",
                             &rpid, rc, &rs, &rppid) == 4 &&
                      rpid == kid && rppid == getpid(),
                      "child stat pid+ppid");
            }
            if (fd >= 0) close(fd);
            /* Reaped: the dir and its files go ENOENT. */
            waitpid(kid, NULL, 0);
            check(open(kp, O_RDONLY) < 0 && errno == ENOENT,
                  "reaped pid stat ENOENT");
            snprintf(kp, sizeof(kp), "/proc/%d", kid);
            check(open(kp, O_RDONLY | O_DIRECTORY) < 0 &&
                  errno == ENOENT, "reaped pid dir ENOENT");
        }

        /* Error paths. */
        errno = 0;
        check(open("/proc/definitely-not-a-file", O_RDONLY) < 0 &&
              errno == ENOENT, "proc miss ENOENT");
        errno = 0;
        check(open("/proc/999999", O_RDONLY | O_DIRECTORY) < 0 &&
              errno == ENOENT, "dead pid dir ENOENT");
        errno = 0;
        check(open("/proc/uptime", O_WRONLY) < 0 &&
              errno == EROFS, "proc file EROFS write");
        errno = 0;
        check(open("/proc/x", O_RDWR | O_CREAT, 0600) < 0 &&
              errno == EROFS, "proc O_CREAT EROFS");

        /* run-97 breadth: system files, links, fd view. */
        fd = open("/proc/stat", O_RDONLY);
        n2 = fd >= 0 ? read(fd, pbuf, sizeof(pbuf) - 1) : -1;
        check(fd >= 0 && n2 > 0, "open+read /proc/stat");
        if (n2 > 0) {
            pbuf[n2] = 0;
            check(strncmp(pbuf, "cpu ", 4) == 0 &&
                  strstr(pbuf, "\nprocesses ") != NULL &&
                  strstr(pbuf, "ctxt") != NULL,
                  "proc/stat cpu+counts");
        }
        if (fd >= 0) close(fd);

        fd = open("/proc/cpuinfo", O_RDONLY);
        n2 = fd >= 0 ? read(fd, pbuf, sizeof(pbuf) - 1) : -1;
        check(fd >= 0 && n2 > 0, "open+read cpuinfo");
        if (n2 > 0) {
            pbuf[n2] = 0;
            check(strstr(pbuf, "processor") != NULL &&
                  strstr(pbuf, "vendor_id") != NULL &&
                  strstr(pbuf, "model name") != NULL,
                  "cpuinfo fields");
        }
        if (fd >= 0) close(fd);

        fd = open("/proc/filesystems", O_RDONLY);
        n2 = fd >= 0 ? read(fd, pbuf, sizeof(pbuf) - 1) : -1;
        check(fd >= 0 && n2 > 0 && (pbuf[n2] = 0,
              strstr(pbuf, "proc") != NULL), "filesystems has proc");
        if (fd >= 0) close(fd);

        fd = open("/proc/mounts", O_RDONLY);
        n2 = fd >= 0 ? read(fd, pbuf, sizeof(pbuf) - 1) : -1;
        check(fd >= 0 && n2 > 0 && (pbuf[n2] = 0,
              strstr(pbuf, "/proc") != NULL), "mounts has proc");
        if (fd >= 0) close(fd);

        fd = open("/proc/self/statm", O_RDONLY);
        n2 = fd >= 0 ? read(fd, pbuf, sizeof(pbuf) - 1) : -1;
        check(fd >= 0 && n2 > 0, "open+read statm");
        if (n2 > 0) {
            unsigned long vsz, rss;
            pbuf[n2] = 0;
            check(sscanf(pbuf, "%lu %lu", &vsz, &rss) == 2 && rss > 0,
                  "statm size+rss");
        }
        if (fd >= 0) close(fd);

        fd = open("/proc/self/environ", O_RDONLY);
        n2 = fd >= 0 ? read(fd, pbuf, sizeof(pbuf)) : -1;
        check(fd >= 0 && n2 == 0, "environ empty");
        if (fd >= 0) close(fd);

        fd = open("/proc/self/io", O_RDONLY);
        n2 = fd >= 0 ? read(fd, pbuf, sizeof(pbuf) - 1) : -1;
        check(fd >= 0 && n2 > 0 && (pbuf[n2] = 0,
              strstr(pbuf, "rchar:") != NULL), "io counters");
        if (fd >= 0) close(fd);

        /* cmdline holds NUL-joined argv — spawn gave us argv0. */
        fd = open("/proc/self/cmdline", O_RDONLY);
        n2 = fd >= 0 ? read(fd, pbuf, sizeof(pbuf)) : -1;
        check(fd >= 0 && n2 > 1 && pbuf[n2 - 1] == 0 &&
              strstr(pbuf, "iotest") != NULL, "cmdline argv");
        if (fd >= 0) close(fd);

        /* Link targets. */
        n2 = readlink("/proc/self", pbuf, sizeof(pbuf) - 1);
        check(n2 > 0 && (pbuf[n2] = 0, atoi(pbuf) == getpid()),
              "readlink self -> pid");
        n2 = readlink("/proc/self/cwd", pbuf, sizeof(pbuf) - 1);
        check(n2 == 1 && pbuf[0] == '/', "readlink cwd -> /");
        n2 = readlink("/proc/self/root", pbuf, sizeof(pbuf) - 1);
        check(n2 == 1 && pbuf[0] == '/', "readlink root -> /");

        /* fd dir: our std streams appear by number. */
        fd = open("/proc/self/fd", O_RDONLY | O_DIRECTORY);
        check(fd >= 0, "open self/fd dir");
        if (fd >= 0) {
            char db[2048];
            int dl = syscall(SYS_getdents64, fd, db, sizeof(db));
            int saw0 = 0, saw2 = 0;
            for (int o = 0; dl > 0 && o < dl;) {
                struct {
                    unsigned long ino, off2;
                    unsigned short rlen;
                    unsigned char type;
                    char name[];
                } *de = (void *)(db + o);
                if (!strcmp(de->name, "0")) saw0 = 1;
                if (!strcmp(de->name, "2")) saw2 = 1;
                o += de->rlen;
            }
            check(saw0 && saw2, "self/fd lists streams");
            close(fd);
        }
        n2 = readlink("/proc/self/fd/1", pbuf, sizeof(pbuf) - 1);
        check(n2 > 0 && (pbuf[n2] = 0,
              strcmp(pbuf, "/dev/console") == 0),
              "fd/1 -> console");

        /* fdinfo is a generated 0400 file with pos+flags. */
        fd = open("/proc/self/fdinfo/2", O_RDONLY);
        n2 = fd >= 0 ? read(fd, pbuf, sizeof(pbuf) - 1) : -1;
        check(fd >= 0 && n2 > 0 && (pbuf[n2] = 0,
              strstr(pbuf, "pos:") != NULL &&
              strstr(pbuf, "flags:") != NULL), "fdinfo fields");
        if (fd >= 0) close(fd);

        /* open() of an fd link shares the description — a pipe's
           read end opened through /proc/self/fd reads the bytes. */
        {
            int pf[2];
            check(pipe(pf) == 0, "pipe for fd-open");
            if (pf[0] >= 0) {
                write(pf[1], "z", 1);
                char fp[64];
                snprintf(fp, sizeof(fp), "/proc/self/fd/%d", pf[0]);
                int d = open(fp, O_RDONLY);
                check(d >= 0, "open self/fd link");
                if (d >= 0) {
                    char c = 0;
                    check(read(d, &c, 1) == 1 && c == 'z',
                          "fd-open shares OFD");
                    close(d);
                }
                close(pf[0]);
                close(pf[1]);
            }
        }

        /* utime/stime are real counters — at least utime must have
           ticked for this long-running task. */
        fd = open("/proc/self/stat", O_RDONLY);
        n2 = fd >= 0 ? read(fd, pbuf, sizeof(pbuf) - 1) : -1;
        check(fd >= 0 && n2 > 0, "stat for utime");
        if (n2 > 0) {
            /* field 14 after the ')' — count space-separated words. */
            char *q = strrchr(pbuf, ')');
            unsigned long fv[20]; int fc = 0;
            if (q) {
                char *w = strtok(q + 2, " ");
                while (w && fc < 20) {
                    fv[fc++] = strtoul(w, NULL, 10);
                    w = strtok(NULL, " ");
                }
            }
            check(fc >= 12 && fv[11] > 0, "utime ticked");
        }
        if (fd >= 0) close(fd);
    }


    /* run-100: inotify — watch/add/report/rm around a ram file. */
    {
        const char *ip = "inotest.txt";
        unlink(ip);
        int ifd = inotify_init1(IN_NONBLOCK);
        check(ifd >= 0, "inotify_init1 create");
        char evbuf[512];
        errno = 0;
        check(read(ifd, evbuf, sizeof(evbuf)) == -1 && errno == EAGAIN,
              "inotify empty read -> EAGAIN");
        check(inotify_add_watch(ifd, "/nonexistent-xyz", IN_ALL_EVENTS)
              == -1 && errno == ENOENT,
              "add_watch missing path -> ENOENT");
        check(inotify_add_watch(0, ip, IN_ALL_EVENTS) == -1 &&
              errno == EINVAL,
              "add_watch non-inotify fd -> EINVAL");

        /* file watch: open/modify/close events on the object. */
        int wd = inotify_add_watch(ifd, ip, 0);
        check(wd == -1 && errno == ENOENT,
              "add_watch before create -> ENOENT");
        int f = open(ip, O_CREAT | O_RDWR, 0644);
        check(f >= 0, "inotest file create");
        close(f);
        wd = inotify_add_watch(ifd, ip, IN_ALL_EVENTS);
        check(wd >= 1, "add_watch returns wd");

        f = open(ip, O_WRONLY);
        write(f, "x", 1);
        close(f);
        struct pollfd ipf = {ifd, POLLIN, 0};
        check(poll(&ipf, 1, 0) == 1 && (ipf.revents & POLLIN),
              "inotify poll POLLIN after modify");
        struct inotify_event *ev;
        int n1 = read(ifd, evbuf, sizeof(evbuf));
        check(n1 == 16, "first event is a 16B record");
        ev = (struct inotify_event *)evbuf;
        check(ev->wd == wd && (ev->mask & IN_OPEN),
              "event 1: IN_OPEN on our wd");
        n1 = read(ifd, evbuf, sizeof(evbuf));
        ev = (struct inotify_event *)evbuf;
        check(n1 == 16 && (ev->mask & IN_MODIFY),
              "event 2: IN_MODIFY");
        n1 = read(ifd, evbuf, sizeof(evbuf));
        ev = (struct inotify_event *)evbuf;
        check(n1 == 16 && (ev->mask & IN_CLOSE_WRITE),
              "event 3: IN_CLOSE_WRITE");

        /* rm_watch -> IN_IGNORED is the wd's last word. */
        check(inotify_rm_watch(ifd, wd) == 0, "rm_watch ok");
        n1 = read(ifd, evbuf, sizeof(evbuf));
        ev = (struct inotify_event *)evbuf;
        check(n1 == 16 && (ev->mask & IN_IGNORED) && ev->wd == wd,
              "rm_watch yields IN_IGNORED");

        /* dir watch on /: child create+delete arrive named. */
        wd = inotify_add_watch(ifd, "/", IN_CREATE | IN_DELETE |
                                 IN_MOVED_FROM | IN_MOVED_TO |
                                 IN_MODIFY | IN_OPEN |
                                 IN_CLOSE_WRITE | IN_CLOSE_NOWRITE |
                                 IN_ACCESS | IN_ATTRIB |
                                 IN_DELETE_SELF | IN_MOVE_SELF);
        check(wd >= 1, "dir watch on /");
        f = open("inochild.tmp", O_CREAT | O_WRONLY, 0644);
        close(f);
        n1 = read(ifd, evbuf, sizeof(evbuf));
        ev = (struct inotify_event *)evbuf;
        check(n1 > 16 && (ev->mask & IN_CREATE) &&
              ev->len > 0 && strcmp(ev->name, "inochild.tmp") == 0,
              "dir watch: IN_CREATE named inochild.tmp");
        /* drain any extra events from the open+close (OPEN,
           CLOSE_NOWRITE) before the delete check. */
        while (read(ifd, evbuf, sizeof(evbuf)) > 0) {}
        check(rename("inochild.tmp", "inochild2.tmp") == 0,
              "rename for cookie pair");
        n1 = read(ifd, evbuf, sizeof(evbuf));
        ev = (struct inotify_event *)evbuf;
        unsigned ck = ev->cookie;
        check(n1 > 16 && (ev->mask & IN_MOVED_FROM) &&
              strcmp(ev->name, "inochild.tmp") == 0,
              "rename: IN_MOVED_FROM named old");
        n1 = read(ifd, evbuf, sizeof(evbuf));
        ev = (struct inotify_event *)evbuf;
        check(n1 > 16 && (ev->mask & IN_MOVED_TO) &&
              strcmp(ev->name, "inochild2.tmp") == 0 &&
              ev->cookie == ck && ck != 0,
              "rename: IN_MOVED_TO same cookie");
        unlink("inochild2.tmp");
        /* drain to the DELETE record */
        int seen_del = 0;
        for (int i = 0; i < 8; i++) {
            n1 = read(ifd, evbuf, sizeof(evbuf));
            if (n1 <= 0) break;
            ev = (struct inotify_event *)evbuf;
            if (ev->mask & IN_DELETE) {
                seen_del = 1;
                break;
            }
        }
        check(seen_del, "dir watch: IN_DELETE arrives");
        close(ifd);

        /* blocked-read wake: a child's write wakes the sleeper. */
        int bifd = inotify_init1(0);
        check(bifd >= 0, "blocking inotify create");
        inotify_add_watch(bifd, ip, IN_ALL_EVENTS);
        pid_t ic = fork();
        if (ic == 0) {
            struct timespec ts = {0, 20000000};
            nanosleep(&ts, NULL);
            int cf = open(ip, O_WRONLY);
            write(cf, "y", 1);
            close(cf);
            _exit(0);
        }
        int bn = read(bifd, evbuf, sizeof(evbuf));
        ev = (struct inotify_event *)evbuf;
        check(bn >= 16 && (ev->mask & (IN_MODIFY | IN_CLOSE_WRITE |
                                     IN_OPEN)),
              "inotify blocked read wakes on child write");
        waitpid(ic, NULL, 0);
        close(bifd);
        unlink(ip);
    }

    int n = snprintf(buf, sizeof(buf), "iotest: %d failures, done\n", fails);
    say(buf);
    return fails;
}
