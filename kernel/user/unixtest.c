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
    check(write(sv[0], "x", 1) < 0 && errno == EPIPE, "write EPIPE");
    close(sv[0]); close(sv[1]);

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
