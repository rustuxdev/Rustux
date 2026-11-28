// unixtest — compiled AF_UNIX ABI proof:
// socket(AF_UNIX, SOCK_STREAM/SOCK_DGRAM), socketpair(), sockaddr_un
// bind (path + \0-abstract), listen/connect/accept, stream duplex
// + shutdown EOF/EPIPE, datagram named delivery + recvfrom source
// name, FIONREAD/poll, and the gate set (ESOCKTNOSUPPORT/
// EAFNOSUPPORT/EADDRINUSE/ECONNREFUSED/EISCONN/EDESTADDRREQ/ENOENT).
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <poll.h>
#include <sched.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>

static int fails;

static void say(const char *s) {
    if (write(1, s, strlen(s)) < 0) { /* ignore */ }
}

static void check(int ok, const char *what) {
    char buf[80];
    int n = snprintf(buf, sizeof(buf), "unixtest: %-32s %s\n",
                     what, ok ? "ok" : "FAIL");
    say(buf);
    if (!ok) fails++;
}

/* CLONE_FILES thread parked in a unix op; the shared-table parent
   closes BOTH conn ends underneath it — pre-fix unix_sock_close
   freed the conn before unix_wake ran, whose dead-slot early-return
   stranded the armed waiter forever. sop: 0=send->EPIPE,
   1=recv->EOF, 2=sendmsg+rights->EPIPE, 3=poll->ready,
   4=connect->EBADF. */
static volatile int sfd, sop, sdone, saux, sarm;
static volatile long sres;
static struct sockaddr_un ssun;
static socklen_t ssunlen;
static int strand_thr(void *p) {
    (void)p;
    long r;
    sarm = 1;        /* at the syscall boundary — parent may act */
    if (sop == 0) {
        char one = 's';
        r = send(sfd, &one, 1, 0);
    } else if (sop == 1) {
        char one;
        r = recv(sfd, &one, 1, 0);
    } else if (sop == 3) {
        struct pollfd pf;
        pf.fd = sfd; pf.events = POLLIN; pf.revents = 0;
        r = poll(&pf, 1, -1);
        if (r > 0 && !pf.revents)
            r = -77; /* claimed ready but nothing reported */
    } else if (sop == 4) {
        r = connect(sfd, (struct sockaddr *)&ssun, ssunlen);
    } else {
        struct msghdr m;
        struct iovec io;
        char one = 'k';
        char ct[CMSG_SPACE(sizeof(int))];
        memset(&m, 0, sizeof(m));
        memset(ct, 0, sizeof(ct));
        io.iov_base = &one; io.iov_len = 1;
        m.msg_iov = &io; m.msg_iovlen = 1;
        m.msg_control = ct; m.msg_controllen = sizeof(ct);
        struct cmsghdr *h = CMSG_FIRSTHDR(&m);
        h->cmsg_level = SOL_SOCKET;
        h->cmsg_type = SCM_RIGHTS;
        h->cmsg_len = CMSG_LEN(sizeof(int));
        int af = saux;
        memcpy(CMSG_DATA(h), &af, sizeof(int));
        r = sendmsg(sfd, &m, 0);
    }
    sres = r < 0 ? errno : r;
    sdone = 1;
    return 0;
}

static socklen_t unaddr(struct sockaddr_un *u, const char *path) {
    memset(u, 0, sizeof(*u));
    u->sun_family = AF_UNIX;
    strcpy(u->sun_path, path);
    return sizeof(*u);
}

// Abstract name: sun_path[0] = NUL, name = the raw tail bytes.
static socklen_t unabs(struct sockaddr_un *u, const char *name, int n) {
    memset(u, 0, sizeof(*u));
    u->sun_family = AF_UNIX;
    memcpy(u->sun_path + 1, name, n);
    return 2 + 1 + n;
}

int main(void) {
    struct sockaddr_un un;
    struct pollfd pfd;
    char buf[128];
    ssize_t n;
    int sv[2];

    check(socketpair(AF_INET, SOCK_STREAM, 0, sv) < 0 &&
          errno == EAFNOSUPPORT, "socketpair INET refused");
    // --- SOCK_SEQPACKET via socketpair ---
    {
        check(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sv) == 0,
              "seqpacket pair");
        int ty = 0; socklen_t tl = sizeof(ty);
        check(getsockopt(sv[0], SOL_SOCKET, SO_TYPE, &ty, &tl) == 0 &&
              ty == SOCK_SEQPACKET, "SO_TYPE seqpacket");
        // Records keep their boundaries: two sends, two recvs.
        check(write(sv[0], "aa", 2) == 2, "seq send a");
        check(write(sv[0], "bbbbb", 5) == 5, "seq send b");
        memset(buf, 0, sizeof(buf));
        check(read(sv[1], buf, sizeof(buf)) == 2 &&
              !memcmp(buf, "aa", 2), "seq record a");
        memset(buf, 0, sizeof(buf));
        check(read(sv[1], buf, sizeof(buf)) == 5 &&
              !memcmp(buf, "bbbbb", 5), "seq record b");
        // A short read discards the record's tail — the NEXT
        // recv gets the next record, not the leftover bytes.
        check(write(sv[0], "first-second", 12) == 12,
              "seq send long");
        memset(buf, 0, sizeof(buf));
        check(read(sv[1], buf, 5) == 5 && !memcmp(buf, "first", 5),
              "seq short read truncates");
        check(write(sv[0], "next", 4) == 4, "seq send next");
        memset(buf, 0, sizeof(buf));
        check(read(sv[1], buf, sizeof(buf)) == 4 &&
              !memcmp(buf, "next", 4), "seq tail discarded");
        // FIONREAD = pending record payload size.
        check(write(sv[0], "1234567", 7) == 7, "seq send c");
        int inq = 0;
        check(ioctl(sv[1], FIONREAD, &inq) == 0 && inq == 7,
              "seq FIONREAD record len");
        memset(buf, 0, sizeof(buf));
        check(read(sv[1], buf, sizeof(buf)) == 7, "seq drain c");
        // Oversized send -> EMSGSIZE.
        static char big[8192];
        errno = 0;
        check(write(sv[0], big, sizeof(big)) < 0 &&
              errno == EMSGSIZE, "seq EMSGSIZE");
        // recvmsg on a short iovec reports MSG_TRUNC.
        check(write(sv[0], "0123456789", 10) == 10, "seq send d");
        struct msghdr mh; struct iovec io;
        char small[4];
        memset(&mh, 0, sizeof(mh));
        io.iov_base = small; io.iov_len = sizeof(small);
        mh.msg_iov = &io; mh.msg_iovlen = 1;
        check(recvmsg(sv[1], &mh, 0) == 4 &&
              (mh.msg_flags & MSG_TRUNC), "seq MSG_TRUNC flag");
        close(sv[0]); close(sv[1]);

        // seq client can't reach a stream listener and vice
        // versa — mismatched types are refused like Linux's
        // ECONNREFUSED on a wrong-kind peer.
        struct sockaddr_un un;
        memset(&un, 0, sizeof(un));
        un.sun_family = AF_UNIX;
        strcpy(un.sun_path, "\0utseq");
        int sfd = socket(AF_UNIX, SOCK_STREAM, 0);
        int qfd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
        check(qfd >= 0, "seq socket mint");
        check(bind(sfd, (struct sockaddr *)&un, 10) == 0 &&
              listen(sfd, 1) == 0, "stream listener up");
        check(connect(qfd, (struct sockaddr *)&un, 10) < 0 &&
              errno == ECONNREFUSED, "seq->stream refused");
        close(sfd); close(qfd);
    }

    // --- SOCK_STREAM via socketpair ---
    check(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "stream pair");
    int ty = 0; socklen_t tl = sizeof(ty);
    check(getsockopt(sv[0], SOL_SOCKET, SO_TYPE, &ty, &tl) == 0 &&
          ty == SOCK_STREAM, "SO_TYPE stream");
    check(write(sv[0], "hello", 5) == 5, "pair write a->b");
    memset(buf, 0, sizeof(buf));
    check(read(sv[1], buf, 5) == 5 && !memcmp(buf, "hello", 5),
          "pair read b");
    check(write(sv[1], "world", 5) == 5, "pair write b->a");
    memset(buf, 0, sizeof(buf));
    check(read(sv[0], buf, 5) == 5 && !memcmp(buf, "world", 5),
          "pair read a");
    pfd.fd = sv[0]; pfd.events = POLLIN; pfd.revents = 0;
    check(write(sv[1], "z", 1) == 1 &&
          poll(&pfd, 1, 0) == 1 && (pfd.revents & POLLIN),
          "pair poll POLLIN");
    check(read(sv[0], buf, 1) == 1, "pair poll drain");
    check(shutdown(sv[1], SHUT_WR) == 0, "shutdown peer wr");
    check(read(sv[0], buf, 1) == 0, "peer read EOF");
    /* peer SHUT_WR: its READ half is still open — my write
       succeeds on Linux (send EPIPEs only on peer close or
       peer SHUT_RD). */
    check(write(sv[0], "x", 1) == 1, "write to shutwr peer ok");
    /* peer SHUT_RD: my write EPIPEs. */
    check(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "re-pair");
    check(shutdown(sv[1], SHUT_RD) == 0, "shutdown peer rd");
    check(write(sv[0], "x", 1) < 0 && errno == EPIPE,
          "write to shutrd peer EPIPE");
    close(sv[0]); close(sv[1]);
    /* own SHUT_WR kills MY send half too — EPIPE on the same
       socket whose peer can still read. */
    check(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "re-pair3");
    check(shutdown(sv[0], SHUT_WR) == 0, "own shut wr");
    check(write(sv[0], "x", 1) < 0 && errno == EPIPE,
          "send on own shutwr EPIPE");
    check(read(sv[1], buf, 1) == 0, "peer reads EOF after");
    close(sv[0]); close(sv[1]);
    /* peer data survives: A shut(WR) + B close keeps the conn —
       A still drains B's queued bytes before EOF. */
    check(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "re-pair2");
    check(write(sv[1], "q", 1) == 1, "queue byte");
    check(shutdown(sv[0], SHUT_WR) == 0, "A shut wr");
    check(close(sv[1]) == 0, "B close");
    check(read(sv[0], buf, 1) == 1 && buf[0] == 'q',
          "queued byte survives teardown");
    check(read(sv[0], buf, 1) == 0, "then EOF");
    close(sv[0]);

    // --- SOCK_STREAM via bind/listen/connect/accept ---
    int ls = socket(AF_UNIX, SOCK_STREAM, 0);
    check(ls >= 0, "listen socket");
    unaddr(&un, "/ux_l_test");
    check(bind(ls, (struct sockaddr *)&un, sizeof(un)) == 0,
          "bind path name");
    check(bind(ls, (struct sockaddr *)&un, sizeof(un)) < 0 &&
          errno == EINVAL, "re-bind EINVAL");
    int ls2 = socket(AF_UNIX, SOCK_STREAM, 0);
    check(bind(ls2, (struct sockaddr *)&un, sizeof(un)) < 0 &&
          errno == EADDRINUSE, "name collision EADDRINUSE");
    close(ls2);
    check(listen(ls, 4) == 0, "listen");
    int cs = socket(AF_UNIX, SOCK_STREAM, 0);
    unaddr(&un, "/ux_no_listener");
    check(connect(cs, (struct sockaddr *)&un, sizeof(un)) < 0 &&
          errno == ECONNREFUSED, "connect unbound ECONNREFUSED");
    unaddr(&un, "/ux_l_test");
    check(connect(cs, (struct sockaddr *)&un, sizeof(un)) == 0,
          "connect enqueues");
    check(connect(cs, (struct sockaddr *)&un, sizeof(un)) < 0 &&
          errno == EISCONN, "reconnect EISCONN");
    memset(&un, 0, sizeof(un));
    socklen_t ul = sizeof(un);
    int as = accept(ls, (struct sockaddr *)&un, &ul);
    check(as >= 0, "accept");
    check(un.sun_family == AF_UNIX, "accept addr family");
    check(write(cs, "cli->srv", 8) == 8, "stream c->s");
    memset(buf, 0, sizeof(buf));
    check(read(as, buf, 8) == 8 && !memcmp(buf, "cli->srv", 8),
          "srv reads");
    check(write(as, "srv->cli", 8) == 8, "stream s->c");
    memset(buf, 0, sizeof(buf));
    check(read(cs, buf, 8) == 8 && !memcmp(buf, "srv->cli", 8),
          "cli reads");
    memset(&un, 0, sizeof(un));
    ul = sizeof(un);
    check(getsockname(ls, (struct sockaddr *)&un, &ul) == 0 &&
          !strcmp(un.sun_path, "/ux_l_test"), "getsockname bound");
    memset(&un, 0, sizeof(un));
    ul = sizeof(un);
    check(getpeername(as, (struct sockaddr *)&un, &ul) == 0 &&
          un.sun_family == AF_UNIX, "getpeername unnamed peer");
    close(as); close(cs);
    check(read(ls, buf, 1) < 0 && errno == ENOTCONN, "listen read");

    // --- backlog holds the conn: pre-accept sends + dead
    //     connector teardown ---
    {
        int cb = socket(AF_UNIX, SOCK_STREAM, 0);
        unaddr(&un, "/ux_l_test");
        check(connect(cb, (struct sockaddr *)&un, sizeof(un)) == 0,
              "bk connect enqueues");
        /* send BEFORE accept — the backlog holds side 1 so the
           peer "exists"; bytes must queue for the acceptor. */
        check(write(cb, "b", 1) == 1, "send before accept lands");
        int ab = accept(ls, NULL, NULL);
        check(ab >= 0, "accept after queued send");
        check(read(ab, buf, 1) == 1 && buf[0] == 'b',
              "pre-accept byte delivered");
        close(ab);
        /* connector dies while still backlogged: the conn must
           survive for accept (Linux: accepted fd reads EOF,
           writes EPIPE) — and a fresh socketpair reusing the conn
           slot must NOT splice its data into the accept. */
        int cd = socket(AF_UNIX, SOCK_STREAM, 0);
        check(connect(cd, (struct sockaddr *)&un, sizeof(un)) == 0,
              "bk connect2");
        close(cd); /* dies on the backlog */
        int sv2[2];
        check(socketpair(AF_UNIX, SOCK_STREAM, 0, sv2) == 0,
              "slot-reuse pair");
        check(write(sv2[0], "S", 1) == 1, "splice probe byte");
        int ad = accept(ls, NULL, NULL);
        check(ad >= 0, "accept dead connector");
        /* reads EOF — if the conn index spliced into sv2's conn,
           this would deliver 'S' instead */
        check(read(ad, buf, 1) == 0, "dead connector EOF no splice");
        check(read(sv2[1], buf, 1) == 1 && buf[0] == 'S',
              "pair byte still owns conn");
        close(ad); close(sv2[0]); close(sv2[1]);
        close(cb);
        /* own SHUT_RD: reads EOF even with the peer alive */
        check(socketpair(AF_UNIX, SOCK_STREAM, 0, sv2) == 0,
              "shutrd pair");
        check(shutdown(sv2[0], SHUT_RD) == 0, "own shut rd");
        check(read(sv2[0], buf, 1) == 0, "own shutrd reads EOF");
        close(sv2[0]); close(sv2[1]);
    }

    // --- listener close: backlogged conns lose their side-1
    //     prospect — connector reads EOF, sends EPIPE ---
    {
        int cc = socket(AF_UNIX, SOCK_STREAM, 0);
        unaddr(&un, "/ux_l_test");
        check(connect(cc, (struct sockaddr *)&un, sizeof(un)) == 0,
              "lc connect backlogged");
        check(close(ls) == 0, "listener close");
        /* nonblocking so a regression answers EAGAIN not a hang */
        fcntl(cc, F_SETFL, O_NONBLOCK);
        check(read(cc, buf, 1) == 0, "lc connector reads EOF");
        check(write(cc, "x", 1) < 0 && errno == EPIPE,
              "lc connector sends EPIPE");
        close(cc);
    }

    // --- parked connect whose fd dies via the shared table ---
    {
        int ls3 = socket(AF_UNIX, SOCK_STREAM, 0);
        unaddr(&un, "/ux_l3_test");
        check(bind(ls3, (struct sockaddr *)&un, sizeof(un)) == 0 &&
              listen(ls3, 4) == 0, "lc3 listener");
        int fill[4];
        for (int i = 0; i < 4; i++) {
            fill[i] = socket(AF_UNIX, SOCK_STREAM, 0);
            check(connect(fill[i], (struct sockaddr *)&un,
                          sizeof(un)) == 0, "fill backlog");
        }
        /* backlog full — this connect parks */
        sfd = socket(AF_UNIX, SOCK_STREAM, 0);
        memcpy(&ssun, &un, sizeof(un));
        ssunlen = sizeof(un);
        sop = 4; sres = -7; sdone = 0; sarm = 0;
        static char sstk2[8192] __attribute__((aligned(16)));
        int tp = clone(strand_thr, sstk2 + sizeof(sstk2),
                       CLONE_VM | CLONE_SIGHAND | CLONE_THREAD
                       | CLONE_FILES, 0);
        check(tp > 0, "conn thread cloned");
        struct timespec y = {0, 5 * 1000 * 1000};
        for (int k = 0; k < 400 && !sarm; k++)
            nanosleep(&y, NULL);     /* wait for syscall boundary */
        nanosleep(&y, NULL);         /* let it park */
        close(sfd);                  /* sock dies under the wait */
        for (int k = 0; k < 400 && !sdone; k++)
            nanosleep(&y, NULL);
        check(sdone && sres == EBADF,
              "parked connect dead-fd EBADF");
        close(ls3);
        for (int i = 0; i < 4; i++) close(fill[i]);
    }

    // --- SOCK_DGRAM named + abstract ---
    int da = socket(AF_UNIX, SOCK_DGRAM, 0);
    int db = socket(AF_UNIX, SOCK_DGRAM, 0);
    check(da >= 0 && db >= 0, "dgram sockets");
    socklen_t alen = unabs(&un, "uxd1", 4);
    check(bind(da, (struct sockaddr *)&un, alen) == 0,
          "bind abstract");
    alen = unabs(&un, "uxd2", 4);
    check(bind(db, (struct sockaddr *)&un, alen) == 0,
          "bind abstract b");
    check(send(db, "x", 1, 0) < 0 && errno == EDESTADDRREQ,
          "send no dest");
    alen = unabs(&un, "nobody", 6);
    check(sendto(db, "x", 1, 0, (struct sockaddr *)&un, alen) < 0 &&
          errno == ENOENT, "sendto unbound ENOENT");
    alen = unabs(&un, "uxd1", 4);
    check(sendto(db, "dgram!", 6, 0, (struct sockaddr *)&un, alen)
          == 6, "sendto named");
    int avail = 0;
    check(ioctl(da, FIONREAD, &avail) == 0 && avail == 6,
          "FIONREAD dgram");
    pfd.fd = da; pfd.events = POLLIN; pfd.revents = 0;
    check(poll(&pfd, 1, 0) == 1 && (pfd.revents & POLLIN),
          "dgram poll POLLIN");
    memset(&un, 0, sizeof(un));
    memset(buf, 0, sizeof(buf));
    n = recvfrom(da, buf, sizeof(buf), 0,
                 (struct sockaddr *)&un, &alen);
    check(n == 6 && !memcmp(buf, "dgram!", 6), "dgram payload");
    check(un.sun_family == AF_UNIX && un.sun_path[0] == 0 &&
          !memcmp(un.sun_path + 1, "uxd2", 4), "recvfrom src name");

    // connected dgram: send() pins the peer
    alen = unabs(&un, "uxd1", 4);
    check(connect(db, (struct sockaddr *)&un, alen) == 0,
          "dgram connect");
    check(send(db, "conn!", 5, 0) == 5, "connected send");
    memset(buf, 0, sizeof(buf));
    check(read(da, buf, 5) == 5 && !memcmp(buf, "conn!", 5),
          "dgram read");
    close(da); close(db);

    // --- SOCK_DGRAM socketpair ---
    check(socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) == 0, "dgram pair");
    check(send(sv[0], "ab", 2, 0) == 2, "pair dgram a->b");
    memset(buf, 0, sizeof(buf));
    check(recv(sv[1], buf, 2, 0) == 2 && !memcmp(buf, "ab", 2),
          "pair dgram recv");
    check(send(sv[1], "cd", 2, 0) == 2, "pair dgram b->a");
    memset(buf, 0, sizeof(buf));
    check(recv(sv[0], buf, 2, 0) == 2 && !memcmp(buf, "cd", 2),
          "pair dgram recv 2");
    close(sv[0]); close(sv[1]);

    // --- cross-task stream delivery via fork ---
    check(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0,
          "fork pair mint");
    pid_t pid = fork();
    if (pid == 0) {
        if (write(sv[1], "K", 1) < 0) { _exit(1); }
        _exit(0);
    }
    check(pid > 0, "fork");
    memset(buf, 0, sizeof(buf));
    check(read(sv[0], buf, 1) == 1 && buf[0] == 'K',
          "cross-task read");
    int wst; waitpid(pid, &wst, 0);
    close(sv[0]); close(sv[1]);

    // --- recvmsg + SCM_RIGHTS fd passing ---
    {
        int sp[2], dp[2], rx = -1;
        struct msghdr mh;
        struct iovec io;
        struct cmsghdr *cm;
        char ctrl[CMSG_SPACE(sizeof(int))];
        char c, rb;
        check(socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == 0,
              "scm pair");
        check(socketpair(AF_UNIX, SOCK_DGRAM, 0, dp) == 0,
              "donor pair");
        memset(&mh, 0, sizeof(mh));
        memset(ctrl, 0, sizeof(ctrl));
        c = 'f';
        io.iov_base = &c; io.iov_len = 1;
        mh.msg_iov = &io; mh.msg_iovlen = 1;
        mh.msg_control = ctrl; mh.msg_controllen = sizeof(ctrl);
        cm = CMSG_FIRSTHDR(&mh);
        cm->cmsg_level = SOL_SOCKET;
        cm->cmsg_type = SCM_RIGHTS;
        cm->cmsg_len = CMSG_LEN(sizeof(int));
        memcpy(CMSG_DATA(cm), &dp[1], sizeof(int));
        check(sendmsg(sp[0], &mh, 0) == 1, "sendmsg stream rights");
        memset(&mh, 0, sizeof(mh));
        memset(ctrl, 0, sizeof(ctrl));
        rb = 0;
        io.iov_base = &rb; io.iov_len = 1;
        mh.msg_iov = &io; mh.msg_iovlen = 1;
        mh.msg_control = ctrl; mh.msg_controllen = sizeof(ctrl);
        check(recvmsg(sp[1], &mh, 0) == 1 && rb == 'f',
              "recvmsg stream data");
        cm = CMSG_FIRSTHDR(&mh);
        check(cm && cm->cmsg_level == SOL_SOCKET &&
              cm->cmsg_type == SCM_RIGHTS &&
              cm->cmsg_len == CMSG_LEN(sizeof(int)),
              "recvmsg cmsg shape");
        if (cm) memcpy(&rx, CMSG_DATA(cm), sizeof(int));
        check(rx >= 0 && rx != dp[1], "fd minted new slot");
        check(write(rx, "Q", 1) == 1 &&
              read(dp[0], buf, 1) == 1 && buf[0] == 'Q',
              "passed fd works");
        check(!(mh.msg_flags & MSG_CTRUNC), "no ctrunc");

        // MSG_CTRUNC: no control room -> rights dropped + flag.
        memset(&mh, 0, sizeof(mh));
        c = 't';
        io.iov_base = &c; io.iov_len = 1;
        mh.msg_iov = &io; mh.msg_iovlen = 1;
        mh.msg_control = ctrl; mh.msg_controllen = sizeof(ctrl);
        cm = CMSG_FIRSTHDR(&mh);
        cm->cmsg_level = SOL_SOCKET;
        cm->cmsg_type = SCM_RIGHTS;
        cm->cmsg_len = CMSG_LEN(sizeof(int));
        memcpy(CMSG_DATA(cm), &dp[1], sizeof(int));
        check(sendmsg(sp[0], &mh, 0) == 1, "sendmsg rights 2");
        memset(&mh, 0, sizeof(mh));
        rb = 0;
        io.iov_base = &rb; io.iov_len = 1;
        mh.msg_iov = &io; mh.msg_iovlen = 1;
        check(recvmsg(sp[1], &mh, 0) == 1 && rb == 't',
              "ctrunc data arrives");
        check(mh.msg_flags & MSG_CTRUNC, "MSG_CTRUNC set");

        // Dgram socket fd pass.
        int dv[2], rx2 = -1;
        check(socketpair(AF_UNIX, SOCK_DGRAM, 0, dv) == 0,
              "dgram scm pair");
        memset(&mh, 0, sizeof(mh));
        memset(ctrl, 0, sizeof(ctrl));
        c = 'g';
        io.iov_base = &c; io.iov_len = 1;
        mh.msg_iov = &io; mh.msg_iovlen = 1;
        mh.msg_control = ctrl; mh.msg_controllen = sizeof(ctrl);
        cm = CMSG_FIRSTHDR(&mh);
        cm->cmsg_level = SOL_SOCKET;
        cm->cmsg_type = SCM_RIGHTS;
        cm->cmsg_len = CMSG_LEN(sizeof(int));
        memcpy(CMSG_DATA(cm), &dp[0], sizeof(int));
        check(sendmsg(dv[0], &mh, 0) == 1, "sendmsg dgram rights");
        memset(&mh, 0, sizeof(mh));
        memset(ctrl, 0, sizeof(ctrl));
        rb = 0;
        io.iov_base = &rb; io.iov_len = 1;
        mh.msg_iov = &io; mh.msg_iovlen = 1;
        mh.msg_control = ctrl; mh.msg_controllen = sizeof(ctrl);
        check(recvmsg(dv[1], &mh, 0) == 1 && rb == 'g',
              "recvmsg dgram data");
        cm = CMSG_FIRSTHDR(&mh);
        if (cm) memcpy(&rx2, CMSG_DATA(cm), sizeof(int));
        check(rx2 >= 0 && write(rx2, "R", 1) == 1 &&
              read(dp[1], buf, 1) == 1 && buf[0] == 'R',
              "dgram passed fd works");
        close(rx); close(rx2);
        close(dv[0]); close(dv[1]);
        close(sp[0]); close(sp[1]);

        // Scatter/gather: two iovecs in, two out.
        check(socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == 0,
              "scatter pair");
        char a1 = 'H', a2 = 'i', b1 = 0, b2 = 0;
        struct iovec si2[2] =
            {{&a1, 1}, {&a2, 1}};
        struct iovec ri2[2] =
            {{&b1, 1}, {&b2, 1}};
        memset(&mh, 0, sizeof(mh));
        mh.msg_iov = si2; mh.msg_iovlen = 2;
        check(sendmsg(sp[0], &mh, 0) == 2, "sendmsg 2-iov");
        memset(&mh, 0, sizeof(mh));
        mh.msg_iov = ri2; mh.msg_iovlen = 2;
        check(recvmsg(sp[1], &mh, 0) == 2 &&
              b1 == 'H' && b2 == 'i', "recvmsg scatter");
        close(sp[0]); close(sp[1]);

        // Blocked recvmsg: parent parks on the empty ring, the
        // child's sendmsg + rights deliver through the waker.
        check(socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == 0,
              "blocked recvmsg pair");
        pid_t p2 = fork();
        if (p2 == 0) {
            struct msghdr cm2;
            struct iovec io2;
            char cc = 'm';
            char ct2[CMSG_SPACE(sizeof(int))];
            memset(&cm2, 0, sizeof(cm2));
            memset(ct2, 0, sizeof(ct2));
            io2.iov_base = &cc; io2.iov_len = 1;
            cm2.msg_iov = &io2; cm2.msg_iovlen = 1;
            cm2.msg_control = ct2; cm2.msg_controllen = sizeof(ct2);
            struct cmsghdr *h2 = CMSG_FIRSTHDR(&cm2);
            h2->cmsg_level = SOL_SOCKET;
            h2->cmsg_type = SCM_RIGHTS;
            h2->cmsg_len = CMSG_LEN(sizeof(int));
            memcpy(CMSG_DATA(h2), &dp[1], sizeof(int));
            _exit(sendmsg(sp[1], &cm2, 0) == 1 ? 0 : 1);
        }
        memset(&mh, 0, sizeof(mh));
        memset(ctrl, 0, sizeof(ctrl));
        rb = 0; int rx3 = -1;
        io.iov_base = &rb; io.iov_len = 1;
        mh.msg_iov = &io; mh.msg_iovlen = 1;
        mh.msg_control = ctrl; mh.msg_controllen = sizeof(ctrl);
        check(recvmsg(sp[0], &mh, 0) == 1 && rb == 'm',
              "blocked recvmsg wakes");
        cm = CMSG_FIRSTHDR(&mh);
        if (cm) memcpy(&rx3, CMSG_DATA(cm), sizeof(int));
        check(rx3 >= 0, "waker delivered rights");
        if (rx3 >= 0) close(rx3);
        int ws2; waitpid(p2, &ws2, 0);
        check(WIFEXITED(ws2) && WEXITSTATUS(ws2) == 0,
              "child sendmsg ok");
        close(sp[0]); close(sp[1]);
        close(dp[0]); close(dp[1]);
    }

    // --- SCM_RIGHTS through a PARKED sendmsg ---
    // Sender blocks on a full ring: the rights ride the staged
    // record and the waker attaches them where the bytes land.
    {
        int sp[2], dp[2], rx = -1;
        struct msghdr mh;
        struct iovec io;
        char ctrl[CMSG_SPACE(sizeof(int))];
        char rb = 0, fb[1024], db[8192];
        check(socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == 0,
              "parked sendmsg pair");
        check(socketpair(AF_UNIX, SOCK_DGRAM, 0, dp) == 0,
              "parked donor pair");
        fcntl(sp[0], F_SETFL, O_NONBLOCK);
        memset(fb, 'z', sizeof(fb));
        ssize_t w;
        do {
            w = write(sp[0], fb, sizeof(fb));
        } while (w > 0);
        check(w == -1 && errno == EAGAIN, "ring filled");
        fcntl(sp[0], F_SETFL, 0);
        pid_t p3 = fork();
        if (p3 == 0) {
            struct msghdr cm3;
            struct iovec io3;
            char cc = 'm';
            char ct3[CMSG_SPACE(sizeof(int))];
            memset(&cm3, 0, sizeof(cm3));
            memset(ct3, 0, sizeof(ct3));
            io3.iov_base = &cc; io3.iov_len = 1;
            cm3.msg_iov = &io3; cm3.msg_iovlen = 1;
            cm3.msg_control = ct3; cm3.msg_controllen = sizeof(ct3);
            struct cmsghdr *h3 = CMSG_FIRSTHDR(&cm3);
            h3->cmsg_level = SOL_SOCKET;
            h3->cmsg_type = SCM_RIGHTS;
            h3->cmsg_len = CMSG_LEN(sizeof(int));
            memcpy(CMSG_DATA(h3), &dp[1], sizeof(int));
            _exit(sendmsg(sp[0], &cm3, 0) == 1 ? 0 : 1);
        }
        struct timespec tp = {0, 100 * 1000 * 1000};
        nanosleep(&tp, NULL); /* let the child park on the ring */
        check(read(sp[1], db, sizeof(db)) > 0, "drain frees ring");
        memset(&mh, 0, sizeof(mh));
        memset(ctrl, 0, sizeof(ctrl));
        io.iov_base = &rb; io.iov_len = 1;
        mh.msg_iov = &io; mh.msg_iovlen = 1;
        mh.msg_control = ctrl; mh.msg_controllen = sizeof(ctrl);
        check(recvmsg(sp[1], &mh, 0) == 1 && rb == 'm',
              "parked sendmsg delivered byte");
        struct cmsghdr *cm = CMSG_FIRSTHDR(&mh);
        if (cm) memcpy(&rx, CMSG_DATA(cm), sizeof(int));
        check(rx >= 0 && write(rx, "W", 1) == 1 &&
              read(dp[0], buf, 1) == 1 && buf[0] == 'W',
              "staged rights delivered");
        if (rx >= 0) close(rx);
        int ws3; waitpid(p3, &ws3, 0);
        check(WIFEXITED(ws3) && WEXITSTATUS(ws3) == 0,
              "parked sendmsg returned 1");
        close(dp[0]); close(dp[1]);
        close(sp[0]); close(sp[1]);
    }

    // --- parked-send abort: staged rights must release ---
    // >MAX_OFDS cycles of a parked sendmsg+rights killed by a
    // peer close; a leaked batch ref pins one OFD per pass.
    {
        int ok = 1, sp[2], dp[2];
        char fb[1024];
        memset(fb, 'z', sizeof(fb));
        for (int i = 0; i < 150 && ok; i++) {
            if (socketpair(AF_UNIX, SOCK_STREAM, 0, sp) < 0 ||
                socketpair(AF_UNIX, SOCK_DGRAM, 0, dp) < 0) {
                ok = 0;
                break;
            }
            fcntl(sp[0], F_SETFL, O_NONBLOCK);
            ssize_t w;
            do {
                w = write(sp[0], fb, sizeof(fb));
            } while (w > 0);
            fcntl(sp[0], F_SETFL, 0);
            pid_t q = fork();
            if (q == 0) {
                close(sp[1]); /* let the parent's close EPIPE us */
                struct msghdr cm3;
                struct iovec io3;
                char cc = 'x';
                char ct3[CMSG_SPACE(sizeof(int))];
                memset(&cm3, 0, sizeof(cm3));
                memset(ct3, 0, sizeof(ct3));
                io3.iov_base = &cc; io3.iov_len = 1;
                cm3.msg_iov = &io3; cm3.msg_iovlen = 1;
                cm3.msg_control = ct3; cm3.msg_controllen = sizeof(ct3);
                struct cmsghdr *h3 = CMSG_FIRSTHDR(&cm3);
                h3->cmsg_level = SOL_SOCKET;
                h3->cmsg_type = SCM_RIGHTS;
                h3->cmsg_len = CMSG_LEN(sizeof(int));
                memcpy(CMSG_DATA(h3), &dp[1], sizeof(int));
                sendmsg(sp[0], &cm3, 0); /* parks then EPIPEs */
                _exit(0);
            }
            struct timespec tp = {0, 5 * 1000 * 1000};
            nanosleep(&tp, NULL);
            close(sp[1]); /* peer death -> EPIPE frees staged fp */
            int ws;
            waitpid(q, &ws, 0);
            close(sp[0]); close(dp[0]); close(dp[1]);
        }
        check(ok, "parked-send rights release x150");
        check(socketpair(AF_UNIX, SOCK_DGRAM, 0, dp) == 0,
              "ofds not exhausted");
        close(dp[0]); close(dp[1]);
    }

    // --- shared-table close resolves parked waiters ---
    // Pre-fix the conn was taken before unix_wake, whose dead-slot
    // early-return stranded armed waiters (and leaked the stage).
    {
        char fb2[1024];
        memset(fb2, 's', sizeof(fb2));
        static char sstk[8192] __attribute__((aligned(16)));
        static const struct {
            int op; long want; const char *what;
        } cases[4] = {
            {0, EPIPE, "shared-close parked send EPIPE"},
            {1, 0, "shared-close parked recv EOF"},
            {2, EPIPE, "shared-close parked sendmsg EPIPE"},
            {3, -1, "shared-close parked poll wakes"},
        };
        for (int i = 0; i < 4; i++) {
            int sp[2], aux[2];
            check(socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == 0 &&
                  socketpair(AF_UNIX, SOCK_DGRAM, 0, aux) == 0,
                  "strand pair");
            if (cases[i].op != 1) {
                /* fill the ring so the send parks */
                fcntl(sp[0], F_SETFL, O_NONBLOCK);
                ssize_t w;
                do {
                    w = write(sp[0], fb2, sizeof(fb2));
                } while (w > 0);
                fcntl(sp[0], F_SETFL, 0);
            }
            sfd = sp[0]; saux = aux[1];
            sop = cases[i].op; sres = -7; sdone = 0; sarm = 0;
            int tp = clone(strand_thr, sstk + sizeof(sstk),
                           CLONE_VM | CLONE_SIGHAND | CLONE_THREAD
                           | CLONE_FILES, 0);
            check(tp > 0, "strand thread cloned");
            struct timespec y = {0, 5 * 1000 * 1000};
            for (int k = 0; k < 400 && !sarm; k++)
                nanosleep(&y, NULL); /* wait for syscall boundary */
            nanosleep(&y, NULL);         /* let it park */
            close(sp[0]);                /* own side first... */
            close(sp[1]);                /* ...peer frees the conn */
            for (int k = 0; k < 400 && !sdone; k++)
                nanosleep(&y, NULL);
            check(sdone &&
                  (cases[i].op == 3 ? sres >= 1
                                    : sres == cases[i].want),
                  cases[i].what);
            close(aux[0]); close(aux[1]);
        }
    }

    // --- parked poller wakes on stream data arrival ---
    // unix_wake funnels every push; pre-fix nothing re-armed the
    // epoll edge / re-evaled blocked pollers, so a poll(-1) on a
    // stream fd slept until the peer closed.
    {
        int sp[2];
        check(socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == 0,
              "wake-poll pair");
        static char sstk3[8192] __attribute__((aligned(16)));
        sfd = sp[0]; sop = 3; sres = -7; sdone = 0; sarm = 0;
        int tp = clone(strand_thr, sstk3 + sizeof(sstk3),
                       CLONE_VM | CLONE_SIGHAND | CLONE_THREAD
                       | CLONE_FILES, 0);
        check(tp > 0, "wake-poll thread");
        struct timespec y = {0, 5 * 1000 * 1000};
        for (int k = 0; k < 400 && !sarm; k++)
            nanosleep(&y, NULL);     /* wait for syscall boundary */
        nanosleep(&y, NULL);            /* let it park */
        check(write(sp[1], "d", 1) == 1, "wake-poll push");
        for (int k = 0; k < 400 && !sdone; k++)
            nanosleep(&y, NULL);
        check(sdone && sres >= 1,
              "parked poll wakes on stream data");
        char b;
        check(read(sp[0], &b, 1) == 1 && b == 'd',
              "wake-poll byte");
        close(sp[0]); close(sp[1]);
    }

    close(ls);

    // --- recvmmsg (NR 299) ---
    {
        check(socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) == 0,
              "recvmmsg pair");
        check(write(sv[0], "x1", 2) == 2, "mmsg dgram 1");
        check(write(sv[0], "y22", 3) == 3, "mmsg dgram 2");
        check(write(sv[0], "z333", 4) == 4, "mmsg dgram 3");
        struct mmsghdr mv[3]; struct iovec io[3];
        char b1[8], b2[8], b3[8];
        memset(mv, 0, sizeof(mv));
        io[0].iov_base = b1; io[0].iov_len = 8;
        io[1].iov_base = b2; io[1].iov_len = 8;
        io[2].iov_base = b3; io[2].iov_len = 8;
        for (int i = 0; i < 3; i++) {
            mv[i].msg_hdr.msg_iov = &io[i];
            mv[i].msg_hdr.msg_iovlen = 1;
        }
        // Nonblocking so the drained queue can't park the suite.
        fcntl(sv[1], F_SETFL, O_NONBLOCK);
        n = recvmmsg(sv[1], mv, 3, 0, NULL);
        check(n == 3, "recvmmsg count");
        check(mv[0].msg_len == 2 && !memcmp(b1, "x1", 2) &&
              mv[1].msg_len == 3 && !memcmp(b2, "y22", 3) &&
              mv[2].msg_len == 4 && !memcmp(b3, "z333", 4),
              "recvmmsg payloads + msg_len");
        check(recvmmsg(sv[1], mv, 1, 0, NULL) < 0 &&
              errno == EAGAIN, "recvmmsg drained EAGAIN");
        close(sv[0]); close(sv[1]);
    }

    // --- SO_RCVTIMEO / SO_SNDTIMEO ---
    {
        int sv2[2];
        struct timeval tv = {0, 100000}; /* 100ms */
        struct timespec a, z;
        check(socketpair(AF_UNIX, SOCK_STREAM, 0, sv2) == 0,
              "timeo stream pair");
        check(setsockopt(sv2[1], SOL_SOCKET, SO_RCVTIMEO,
                         &tv, sizeof tv) == 0,
              "SO_RCVTIMEO set");
        struct timeval gt = {0, 0};
        socklen_t gl = sizeof gt;
        check(getsockopt(sv2[1], SOL_SOCKET, SO_RCVTIMEO,
                         &gt, &gl) == 0 && gt.tv_usec == 100000,
              "SO_RCVTIMEO get");
        char b;
        clock_gettime(CLOCK_MONOTONIC, &a);
        errno = 0;
        ssize_t r = read(sv2[1], &b, 1);
        clock_gettime(CLOCK_MONOTONIC, &z);
        long ms = (z.tv_sec - a.tv_sec) * 1000 +
                  (z.tv_nsec - a.tv_nsec) / 1000000;
        check(r == -1 && errno == EAGAIN,
              "SO_RCVTIMEO recv -> EAGAIN");
        check(ms >= 20 && ms < 5000, "SO_RCVTIMEO ~100ms bound");
        /* optlen < sizeof(timeval) EINVALs like Linux
           sock_set_timeout, not a zero-padded apply */
        check(setsockopt(sv2[1], SOL_SOCKET, SO_RCVTIMEO,
                         &tv, 8) == -1 && errno == EINVAL,
              "SO_RCVTIMEO optlen 8 EINVAL");
        /* send side: fill the ring, then a bounded write must
           answer EAGAIN, not park forever */
        fcntl(sv2[0], F_SETFL, O_NONBLOCK);
        char wb[4096];
        memset(wb, 'w', sizeof wb);
        ssize_t w;
        do {
            w = write(sv2[0], wb, sizeof wb);
        } while (w > 0);
        check(w == -1 && errno == EAGAIN, "stream ring filled");
        fcntl(sv2[0], F_SETFL, 0);
        struct timeval stv = {0, 50000}; /* 50ms */
        check(setsockopt(sv2[0], SOL_SOCKET, SO_SNDTIMEO,
                         &stv, sizeof stv) == 0,
              "SO_SNDTIMEO set");
        clock_gettime(CLOCK_MONOTONIC, &a);
        errno = 0;
        w = write(sv2[0], wb, 1);
        clock_gettime(CLOCK_MONOTONIC, &z);
        ms = (z.tv_sec - a.tv_sec) * 1000 +
             (z.tv_nsec - a.tv_nsec) / 1000000;
        check(w == -1 && errno == EAGAIN && ms < 5000,
              "SO_SNDTIMEO send -> EAGAIN");
        close(sv2[0]); close(sv2[1]);
        check(socketpair(AF_UNIX, SOCK_DGRAM, 0, sv2) == 0,
              "timeo dgram pair");
        setsockopt(sv2[1], SOL_SOCKET, SO_RCVTIMEO,
                   &tv, sizeof tv);
        struct sockaddr_un su;
        socklen_t sl = sizeof su;
        errno = 0;
        r = recvfrom(sv2[1], &b, 1, 0, (void *)&su, &sl);
        check(r == -1 && errno == EAGAIN,
              "SO_RCVTIMEO dgram -> EAGAIN");
        close(sv2[0]); close(sv2[1]);
    }

    char fin[64];
    int m = snprintf(fin, sizeof(fin),
                     "unixtest: %d failure(s)\n", fails);
    say(fin);
    return fails;
}
