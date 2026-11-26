// aiotest — Linux AIO (206-210 + 333): io_setup/destroy/submit/
// cancel/getevents/pgetevents over the synchronous engine +
// kernel-side completion rings.
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/eventfd.h>
#include <poll.h>
#include <linux/aio_abi.h>

static int fails;
static void check(int ok, const char *what) {
    if (!ok) {
        printf("FAIL: %s\n", what);
        fails++;
    }
}

static long sc(long nr, long a1, long a2, long a3, long a4, long a5, long a6) {
    return syscall(nr, a1, a2, a3, a4, a5, a6);
}

static void mk_iocb(struct iocb *io, unsigned op, unsigned fd,
                    unsigned long buf, unsigned long n, long off) {
    memset(io, 0, sizeof(*io));
    io->aio_lio_opcode = op;
    io->aio_fildes = fd;
    io->aio_buf = buf;
    io->aio_nbytes = n;
    io->aio_offset = off;
}

int main(void) {
    aio_context_t ctx = 0, ctx2 = 0;
    struct iocb io, io2, ios[4];
    struct iocb *pp[4];
    struct io_event ev[8];
    struct timespec ts;
    char buf[64];
    int fd, i;

    // ---- setup ladder ------------------------------------------
    check(sc(206, 0, &ctx, 0,0,0,0) < 0 && errno == EINVAL,
          "setup nr=0 EINVAL");
    check(sc(206, 200, &ctx, 0,0,0,0) < 0 && errno == EINVAL,
          "setup over-cap EINVAL");
    check(sc(206, 4, 0, 0,0,0,0) < 0 && errno == EFAULT,
          "setup bad ctxp EFAULT");
    check(sc(206, 8, &ctx, 0,0,0,0) == 0 && ctx != 0, "setup ok");

    // ---- op on a foreign/dead ctx -------------------------------
    check(sc(210, ctx + 99, 0, 4, ev, 0, 0) < 0 && errno == EINVAL,
          "getevents bad ctx EINVAL");
    check(sc(208, ctx + 99, 1, &pp, 0,0,0) < 0 && errno == EINVAL,
          "submit bad ctx EINVAL");
    check(sc(207, ctx + 99, 0,0,0,0,0) < 0 && errno == EINVAL,
          "destroy bad ctx EINVAL");

    // ---- submit ladder ------------------------------------------
    mk_iocb(&io, IOCB_CMD_PREAD, 0, (unsigned long)buf, 8, 0);
    check(sc(208, ctx, 0, pp, 0,0,0) == 0, "submit nr=0 -> 0");
    check(sc(208, ctx, 1, 0, 0,0,0) < 0 && errno == EFAULT,
          "submit NULL iocbpp EFAULT");

    // PREAD on a real file
    fd = open("/motd.txt", O_RDONLY);
    if (fd < 0) fd = open("/init", O_RDONLY);
    check(fd >= 0, "open test file");
    memset(buf, 0, sizeof(buf));
    mk_iocb(&io, IOCB_CMD_PREAD, fd, (unsigned long)buf, 16, 0);
    pp[0] = &io;
    check(sc(208, ctx, 1, pp, 0,0,0) == 1, "submit PREAD 1");

    // getevents — min satisfied
    memset(ev, 0, sizeof(ev));
    check(sc(210, ctx, 1, 4, ev, 0, 0) == 1, "getevents 1");
    check(ev[0].data == io.aio_data && ev[0].obj == (unsigned long)&io
          && ev[0].res == 16 && ev[0].res2 == 0, "event fields");
    check(buf[0] != 0, "pread landed data");

    // EINVAL ladders: min_nr > nr, bad events VA
    check(sc(210, ctx, 5, 2, ev, 0, 0) < 0 && errno == EINVAL,
          "min>nr EINVAL");
    check(sc(210, ctx, 1, 4, (void*)1, 0, 0) < 0 && errno == EFAULT,
          "bad events EFAULT");

    // queue drains to empty
    check(sc(210, ctx, 0, 4, ev, 0, 0) == 0, "empty getevents 0");

    // ---- write + fsync + noop + poll ----------------------------
    {
        int wfd = open("/aio_out.txt", O_CREAT | O_RDWR, 0644);
        check(wfd >= 0, "open write file");
        char w[] = "aio-write-ok";
        mk_iocb(&ios[0], IOCB_CMD_PWRITE, wfd,
                (unsigned long)w, sizeof(w), 0);
        mk_iocb(&ios[1], IOCB_CMD_FSYNC, wfd, 0, 0, 0);
        mk_iocb(&ios[2], IOCB_CMD_NOOP, wfd, 0, 0, 0);
        int pfd[2]; pipe(pfd);
        mk_iocb(&ios[3], IOCB_CMD_POLL, pfd[0],
                (unsigned long)POLLIN, 0, 0);
        for (i = 0; i < 4; i++) pp[i] = &ios[i];
        check(sc(208, ctx, 4, pp, 0,0,0) == 4, "submit 4 ops");
        memset(ev, 0, sizeof(ev));
        check(sc(210, ctx, 4, 8, ev, 0, 0) == 4, "getevents 4");
        check(ev[0].res == (long)sizeof(w), "pwrite res");
        check(ev[1].res == 0, "fsync res");
        check(ev[2].res == 0, "noop res");
        check((ev[3].res & POLLIN) == 0, "poll empty pipe");
        // preadv reads it back
        struct iovec iov = { buf, 4 };
        mk_iocb(&io, IOCB_CMD_PREADV, wfd,
                (unsigned long)&iov, 1, 0);
        pp[0] = &io;
        check(sc(208, ctx, 1, pp, 0,0,0) == 1, "submit PREADV");
        check(sc(210, ctx, 1, 2, ev, 0, 0) == 1
              && ev[0].res == 4, "preadv res");
        check(memcmp(buf, "aio-", 4) == 0, "preadv data");
        close(wfd);
        unlink("/aio_out.txt");
    }

    // bad-fd iocb: submission succeeds, completion carries -EBADF
    mk_iocb(&io2, IOCB_CMD_PREAD, 99, (unsigned long)buf, 8, 0);
    pp[0] = &io2;
    check(sc(208, ctx, 1, pp, 0,0,0) == 1, "submit badfd ok");
    check(sc(210, ctx, 1, 2, ev, 0, 0) == 1
          && ev[0].res == -EBADF, "badfd event -EBADF");

    // invalid opcode fails the batch
    mk_iocb(&io2, 99, fd, (unsigned long)buf, 8, 0);
    pp[0] = &io2;
    check(sc(208, ctx, 1, pp, 0,0,0) < 0 && errno == EINVAL,
          "bad opcode EINVAL");

    // ---- cancel ---------------------------------------------------
    mk_iocb(&io2, IOCB_CMD_NOOP, 0, 0, 0, 0);
    pp[0] = &io2;
    check(sc(208, ctx, 1, pp, 0,0,0) == 1, "submit noop for cancel");
    // completion already queued -> cancel answers EAGAIN
    check(sc(209, ctx, &io2, ev, 0,0,0) < 0 && errno == EAGAIN,
          "cancel completed EAGAIN");
    sc(210, ctx, 1, 1, ev, 0, 0); // drain
    // never-submitted iocb -> EINVAL; bad VA -> EFAULT
    mk_iocb(&io2, IOCB_CMD_NOOP, 0, 0, 0, 0);
    check(sc(209, ctx, &io2, ev, 0,0,0) < 0 && errno == EINVAL,
          "cancel unknown EINVAL");
    check(sc(209, ctx, 1, ev, 0,0,0) < 0 && errno == EFAULT,
          "cancel bad iocb EFAULT");

    // ---- RESFD: eventfd bump on completion ----------------------
    {
        int efd = eventfd(0, 0);
        check(efd >= 0, "eventfd");
        mk_iocb(&io2, IOCB_CMD_NOOP, 0, 0, 0, 0);
        io2.aio_flags = IOCB_FLAG_RESFD;
        io2.aio_resfd = efd;
        pp[0] = &io2;
        check(sc(208, ctx, 1, pp, 0,0,0) == 1, "submit resfd");
        unsigned long long cnt = 0;
        check(read(efd, &cnt, 8) == 8 && cnt == 1,
              "eventfd bumped");
        sc(210, ctx, 1, 1, ev, 0, 0);
        close(efd);
        // RESFD on a non-eventfd -> EINVAL
        io2.aio_resfd = fd;
        pp[0] = &io2;
        check(sc(208, ctx, 1, pp, 0,0,0) < 0 && errno == EINVAL,
              "resfd non-efd EINVAL");
    }

    // ---- ring-full partial --------------------------------------
    check(sc(206, 2, &ctx2, 0,0,0,0) == 0, "setup ctx2 cap2");
    mk_iocb(&ios[0], IOCB_CMD_NOOP, 0, 0, 0, 0);
    mk_iocb(&ios[1], IOCB_CMD_NOOP, 0, 0, 0, 0);
    mk_iocb(&ios[2], IOCB_CMD_NOOP, 0, 0, 0, 0);
    for (i = 0; i < 3; i++) pp[i] = &ios[i];
    check(sc(208, ctx2, 3, pp, 0,0,0) == 2,
          "full ring partial 2/3");
    check(sc(210, ctx2, 2, 8, ev, 0, 0) == 2, "drain 2");
    check(sc(207, ctx2, 0,0,0,0,0) == 0, "destroy ctx2");

    // ---- timeout + blocking across a fork -----------------------
    ts.tv_sec = 0; ts.tv_nsec = 0;
    check(sc(210, ctx, 1, 1, ev, &ts, 0) == 0,
          "zero-timeout drains nothing");
    ts.tv_sec = 0; ts.tv_nsec = 1;
    check(sc(210, ctx, 1, 1, ev, &ts, 0) == 0,
          "tiny timeout -> 0");
    {
        pid_t c = fork();
        if (c == 0) {
            // child shares the tgid? no — fresh process, fresh
            // tgid -> sees EINVAL on the parent's ctx.
            exit(sc(210, ctx, 0, 1, ev, 0, 0) < 0
                 && errno == EINVAL ? 0 : 1);
        }
        int st; waitpid(c, &st, 0);
        check(WIFEXITED(st) && WEXITSTATUS(st) == 0,
              "foreign ctx EINVAL in child");
    }
    // blocking getevents woken by a sibling thread is covered by
    // the tgid scope; here: signal interrupts -> EINTR or partial
    {
        pid_t c = fork();
        if (c == 0) {
            usleep(40000);
            kill(getppid(), SIGUSR1);
            usleep(40000);
            // then post a completion into the shared tgid? child
            // has its own tgid — instead just exit; parent wakes
            // on the signal.
            _exit(0);
        }
        signal(SIGUSR1, SIG_IGN);
        ts.tv_sec = 2; ts.tv_nsec = 0;
        long r = sc(210, ctx, 1, 1, ev, &ts, 0);
        check(r == 0 || (r < 0 && errno == EINTR),
              "getevents signal/timeout sane");
        waitpid(c, &i, 0);
    }

    // ---- destroy + pgetevents usig ------------------------------
    {
        struct { void *mask; unsigned long sz; } usig = { 0, 8 };
        check(sc(333, ctx, 0, 1, ev, 0, &usig) == 0,
              "pgetevents null mask");
        unsigned long m = 0;
        usig.mask = &m;
        check(sc(333, ctx, 0, 1, ev, 0, &usig) == 0,
              "pgetevents empty mask");
        usig.sz = 7;
        check(sc(333, ctx, 0, 1, ev, 0, &usig) < 0
              && errno == EINVAL, "usig bad size EINVAL");
    }
    check(sc(207, ctx, 0,0,0,0,0) == 0, "destroy ok");
    check(sc(210, ctx, 0, 1, ev, 0, 0) < 0 && errno == EINVAL,
          "dead ctx EINVAL");

    close(fd);
    printf("aiotest: %d failures\n", fails);
    return fails;
}
