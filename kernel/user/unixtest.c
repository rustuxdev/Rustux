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
    check(socket(AF_UNIX, SOCK_SEQPACKET, 0) < 0 &&
          errno == ESOCKTNOSUPPORT, "seqpacket refused");

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

    close(ls);
    char fin[64];
    int m = snprintf(fin, sizeof(fin),
                     "unixtest: %d failure(s)\n", fails);
    say(fin);
    return fails;
}
