// mqtest — POSIX message queues (mq_open 240 / mq_timedsend 241 /
// mq_timedreceive 242 / mq_unlink 243 / mq_notify 244 /
// mq_getsetattr 245). check() convention; exit = failures.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include <mqueue.h>
#include <sys/wait.h>

static int fails;
#define check(c, msg) do { \
    if (c) printf("mqtest: %-44s ok\n", msg); \
    else { printf("mqtest: %-44s FAIL\n", msg); fails++; } \
} while (0)

static void die(int s) { _exit(s); }
static volatile sig_atomic_t hits;
static void handler(int s, siginfo_t *i, void *u) {
    (void)s; (void)u;
    if (i && i->si_value.sival_int == 77) hits++;
}

static void msleep(int ms) {
    struct timespec ts = { ms / 1000, (ms % 1000) * 1000000L };
    while (nanosleep(&ts, &ts) < 0 && errno == EINTR) {}
}

int main(void) {
    printf("mqtest: posix message queues\n");

    // Pid-derived name — concurrent suite instances stay private.
    char name[64];
    snprintf(name, sizeof name, "/mq_%d", getpid());

    // --- open/create ladders
    errno = 0;
    check(mq_open("/mq_no_such_name", O_RDONLY) == (mqd_t)-1
          && errno == ENOENT, "open missing ENOENT");
    errno = 0;
    check(mq_open("mq_nolead", O_CREAT | O_RDWR, 0600, NULL) == (mqd_t)-1
          && errno == EINVAL, "name without / EINVAL");
    errno = 0;
    check(mq_open("/a/b", O_CREAT | O_RDWR, 0600, NULL) == (mqd_t)-1
          && errno == EACCES, "name with inner / EACCES");
    mqd_t q = mq_open(name, O_CREAT | O_EXCL | O_RDWR, 0600, NULL);
    check(q != (mqd_t)-1, "open create defaults");
    check(mq_open(name, O_CREAT | O_EXCL | O_RDWR, 0600, NULL) == (mqd_t)-1
          && errno == EEXIST, "EXCL existing EEXIST");
    errno = 0;
    struct mq_attr bad = { 0, 0, 64, 0 };
    check(mq_open("/mq_badattr", O_CREAT | O_RDWR, 0600, &bad)
          == (mqd_t)-1 && errno == EINVAL, "maxmsg 0 EINVAL");

    struct mq_attr at;
    check(mq_getattr(q, &at) == 0 && at.mq_maxmsg == 10
          && at.mq_msgsize == 8192 && at.mq_curmsgs == 0,
          "getattr defaults 10x8192");

    // --- send/recv basics + prio ordering
    errno = 0;
    check(mq_send(q, "hello", 6, 5) == 0, "send prio 5");
    check(mq_send(q, "second", 7, 9) == 0, "send prio 9");
    check(mq_send(q, "third", 6, 5) == 0, "send prio 5 (fifo)");
    char buf[8192];
    unsigned prio = 0;
    ssize_t n = mq_receive(q, buf, sizeof buf, &prio);
    check(n == 7 && prio == 9 && memcmp(buf, "second", 7) == 0,
          "highest prio first");
    n = mq_receive(q, buf, sizeof buf, &prio);
    check(n == 6 && prio == 5 && memcmp(buf, "hello", 6) == 0,
          "then prio 5");
    n = mq_receive(q, buf, sizeof buf, &prio);
    check(n == 6 && memcmp(buf, "third", 6) == 0,
          "same prio fifo");
    errno = 0;
    check(mq_timedreceive(q, buf, sizeof buf, &prio,
                          &(struct timespec){0, 0}) == -1
          && errno == ETIMEDOUT, "empty + epoch abstime ETIMEDOUT");

    // --- errno ladders
    errno = 0;
    check(mq_send(q, buf, 9000, 0) == -1 && errno == EMSGSIZE,
          "oversize EMSGSIZE");
    errno = 0;
    check(mq_send(q, "x", 1, 32768) == -1 && errno == EINVAL,
          "prio 32768 EINVAL");
    errno = 0;
    check(mq_receive(q, buf, 16, &prio) == -1 && errno == EMSGSIZE,
          "small buf EMSGSIZE");
    errno = 0;
    check(mq_send(0, "x", 1, 0) == -1 && errno == EBADF,
          "send bad fd EBADF");
    errno = 0;
    check(mq_receive(0, buf, sizeof buf, &prio) == -1
          && errno == EBADF, "recv bad fd EBADF");
    errno = 0;
    struct timespec badts = { 0, 1000000000L };
    check(mq_timedsend(q, "x", 1, 0, &badts) == -1 && errno == EINVAL,
          "send nsec EINVAL");
    check(mq_timedreceive(q, buf, sizeof buf, &prio, &badts) == -1
          && errno == EINVAL, "recv nsec EINVAL");

    // --- accmode gates
    mqd_t ro = mq_open(name, O_RDONLY);
    check(ro != (mqd_t)-1, "open O_RDONLY");
    errno = 0;
    check(mq_send(ro, "x", 1, 0) == -1 && errno == EBADF,
          "send on O_RDONLY EBADF");
    mqd_t wo = mq_open(name, O_WRONLY | O_NONBLOCK);
    errno = 0;
    check(mq_receive(wo, buf, sizeof buf, &prio) == -1
          && errno == EBADF, "recv on O_WRONLY EBADF");
    mq_close(ro);
    mq_close(wo);

    // --- full queue blocks
    int sent = 0;
    for (int i = 0; i < 10; i++)
        if (mq_send(q, "full", 5, i % 3) == 0)
            sent++;
    check(sent == 10, "filled 10 slots");
    check(mq_getattr(q, &at) == 0 && at.mq_curmsgs == 10,
          "queue filled to maxmsg");
    errno = 0;
    check(mq_timedsend(q, "x", 1, 0,
                       &(struct timespec){0, 0}) == -1
          && errno == ETIMEDOUT, "full + abstime-now ETIMEDOUT");

    // blocking send wakes on a receive (fork w/o printing checks)
    int pf[2];
    if (pipe(pf) != 0) die(2);
    pid_t c = fork();
    if (c == 0) {
        close(pf[0]);
        int r = mq_send(q, "blocked-send", 13, 1);
        char a = r == 0 ? 'K' : 'F';
        { ssize_t w = write(pf[1], &a, 1); (void)w; }
        die(r == 0 ? 0 : 9);
    }
    close(pf[1]);
    msleep(60); // let the child block
    n = mq_receive(q, buf, sizeof buf, &prio);
    check(n >= 0, "receive frees a slot");
    char tag;
    check(read(pf[0], &tag, 1) == 1 && tag == 'K',
          "blocked send landed");
    int st;
    check(waitpid(c, &st, 0) > 0 && WEXITSTATUS(st) == 0,
          "send child exit 0");
    close(pf[0]);

    // Drain the fill leftovers so the child really blocks on an
    // empty queue — otherwise it pops a stale message immediately.
    mq_getattr(q, &at);
    while (at.mq_curmsgs > 0) {
        mq_receive(q, buf, sizeof buf, &prio);
        mq_getattr(q, &at);
    }

    // --- blocking receive wakes on a send
    if (pipe(pf) != 0) die(2);
    c = fork();
    if (c == 0) {
        close(pf[0]);
        char b[8192];
        unsigned p2;
        ssize_t r = mq_receive(q, b, sizeof b, &p2);
        char a = (r == 4 && p2 == 3 && memcmp(b, "wake", 4) == 0)
            ? 'K' : 'F';
        { ssize_t w = write(pf[1], &a, 1); (void)w; }
        die(r > 0 ? 0 : 9);
    }
    close(pf[1]);
    msleep(60);
    check(mq_send(q, "wake", 4, 3) == 0, "send wakes receiver");
    check(read(pf[0], &tag, 1) == 1 && tag == 'K',
          "receiver got payload+prio");
    check(waitpid(c, &st, 0) > 0 && WEXITSTATUS(st) == 0,
          "recv child exit 0");
    close(pf[0]);

    // --- ETIMEDOUT on a blocking receive
    struct timespec dl;
    struct sigaction al;
    memset(&al, 0, sizeof al);
    al.sa_sigaction = handler;
    al.sa_flags = SA_SIGINFO;
    sigaction(SIGALRM, &al, NULL);
    mq_getattr(q, &at);
    while (at.mq_curmsgs > 0) { // drain leftovers for the empty case
        mq_receive(q, buf, sizeof buf, &prio);
        mq_getattr(q, &at);
    }
    /* SIGALRM-bounded: a concurrent writer's backward clock jump
       legitimately stretches an epoch abstime (Linux's realtime
       rebase) — the alarm interrupts the wait and the retry
       re-anchors on the settled wall. */
    int trc = -1;
    for (int tr = 0; tr < 4; tr++) {
        clock_gettime(CLOCK_REALTIME, &dl);
        dl.tv_nsec += 30 * 1000000L;
        if (dl.tv_nsec >= 1000000000L) {
            dl.tv_sec++;
            dl.tv_nsec -= 1000000000L;
        }
        alarm(1);
        errno = 0;
        trc = mq_timedreceive(q, buf, sizeof buf, &prio, &dl);
        alarm(0);
        if (!(trc < 0 && errno == EINTR))
            break;
    }
    check(trc == -1 && errno == ETIMEDOUT,
          "empty + abstime ETIMEDOUT");

    // --- mq_notify edge + once semantics
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = handler;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGUSR2, &sa, NULL);
    struct sigevent se;
    memset(&se, 0, sizeof se);
    se.sigev_notify = SIGEV_SIGNAL;
    se.sigev_signo = SIGUSR2;
    se.sigev_value.sival_int = 77;
    check(mq_notify(q, &se) == 0, "mq_notify registers");
    check(mq_notify(q, &se) == 0, "same-process re-register");
    check(mq_send(q, "n1", 3, 1) == 0, "send triggers edge");
    msleep(30);
    check(hits == 1, "notify signal fired once");
    check(mq_send(q, "n2", 3, 1) == 0, "send again");
    msleep(30);
    check(hits == 1, "no refire without re-register");
    while (mq_timedreceive(q, buf, sizeof buf, &prio,
                           &(struct timespec){0, 0}) >= 0) {}

    // --- getsetattr O_NONBLOCK round trip
    struct mq_attr newat = { 0 };
    newat.mq_flags = O_NONBLOCK;
    check(mq_setattr(q, &newat, &at) == 0 && at.mq_flags == 0,
          "setattr reports old flags");
    check(mq_getattr(q, &at) == 0 && (at.mq_flags & O_NONBLOCK),
          "getattr sees O_NONBLOCK");
    errno = 0;
    check(mq_timedreceive(q, buf, sizeof buf, &prio, &dl) == -1
          && errno == EAGAIN, "nonblock empty EAGAIN");
    newat.mq_flags = 0;
    mq_setattr(q, &newat, NULL);

    // --- unlink: name dies now, queue lives while open
    check(mq_unlink(name) == 0, "unlink");
    errno = 0;
    check(mq_open(name, O_RDONLY) == (mqd_t)-1 && errno == ENOENT,
          "unlinked name ENOENT");
    check(mq_send(q, "ghost", 6, 0) == 0, "open mqd still works");
    check(mq_unlink(name) == -1 && errno == ENOENT,
          "double unlink ENOENT");
    check(mq_close(q) == 0, "last close frees");

    // --- non-mqd fd gate
    errno = 0;
    check(mq_notify(0, &se) == -1 && errno == EBADF,
          "notify non-mqd EBADF");

    printf("mqtest: %d failures, done\n", fails);
    return fails;
}
