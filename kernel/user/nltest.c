// nltest — compiled AF_NETLINK/NETLINK_ROUTE ABI proof:
// socket/bind sockaddr_nl, RTM_GETLINK/GETADDR/GETROUTE dumps
// parsed for lo+eth0/127.0.0.1+10.0.2.15/default route, the
// NLMSG_ERROR path, plus the real-binary check: busybox `ip`
// (iplink/ipaddr/iproute) over the socket.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

static int fails;

static void say(const char *s) {
    if (write(1, s, strlen(s)) < 0) { /* ignore */ }
}

static void check(int ok, const char *what) {
    char buf[80];
    int n = snprintf(buf, sizeof(buf), "nltest: %-32s %s\n",
                     what, ok ? "ok" : "FAIL");
    say(buf);
    if (!ok) fails++;
}

/* Walk a dump blob: for each nlmsghdr invoke cb(ty, payload). */
static void nl_walk(const char *b, int n,
                    void (*cb)(int ty, const char *p, int len, void *a),
                    void *a) {
    int off = 0;
    while (off + (int)sizeof(struct nlmsghdr) <= n) {
        const struct nlmsghdr *h = (const struct nlmsghdr *)(b + off);
        if (h->nlmsg_len < sizeof(*h) || off + h->nlmsg_len > n)
            break;
        cb(h->nlmsg_type, (const char *)h + sizeof(*h),
           h->nlmsg_len - sizeof(*h), a);
        off += NLMSG_ALIGN(h->nlmsg_len);
    }
}

struct links { int n, lo, eth; };
static void link_cb(int ty, const char *p, int len, void *a) {
    struct links *L = a;
    if (ty != RTM_NEWLINK || len < (int)sizeof(struct ifinfomsg))
        return;
    L->n++;
    const struct ifinfomsg *i = (const struct ifinfomsg *)p;
    int off = sizeof(*i);
    while (off + 4 <= len) {
        const struct rtattr *r = (const struct rtattr *)(p + off);
        if (r->rta_type == IFLA_IFNAME) {
            const char *nm = (const char *)r + 4;
            if (!strcmp(nm, "lo")) L->lo = i->ifi_index;
            if (!strcmp(nm, "eth0")) L->eth = i->ifi_index;
        }
        off += RTA_ALIGN(r->rta_len);
    }
}

struct addrs { int n, lo, eth; };
static void addr_cb(int ty, const char *p, int len, void *a) {
    struct addrs *A = a;
    if (ty != RTM_NEWADDR || len < (int)sizeof(struct ifaddrmsg))
        return;
    A->n++;
    const struct ifaddrmsg *i = (const struct ifaddrmsg *)p;
    int off = sizeof(*i);
    while (off + 4 <= len) {
        const struct rtattr *r = (const struct rtattr *)(p + off);
        if (r->rta_type == IFA_LOCAL) {
            const unsigned char *ip = (const unsigned char *)r + 4;
            if (ip[0] == 127 && ip[1] == 0 && ip[2] == 0 && ip[3] == 1
                && i->ifa_index == 1) A->lo = 1;
            if (ip[0] == 10 && ip[1] == 0 && ip[2] == 2 && ip[3] == 15
                && i->ifa_index == 2) A->eth = 1;
        }
        off += RTA_ALIGN(r->rta_len);
    }
}

struct routes { int n, gw, oif; };
static void route_cb(int ty, const char *p, int len, void *a) {
    struct routes *R = a;
    if (ty != RTM_NEWROUTE || len < (int)sizeof(struct rtmsg))
        return;
    R->n++;
    const struct rtmsg *m = (const struct rtmsg *)p;
    int off = sizeof(*m);
    while (off + 4 <= len) {
        const struct rtattr *r = (const struct rtattr *)(p + off);
        if (r->rta_type == RTA_GATEWAY) {
            const unsigned char *g = (const unsigned char *)r + 4;
            if (g[0] == 10 && g[1] == 0 && g[2] == 2 && g[3] == 2)
                R->gw = 1;
        }
        if (r->rta_type == RTA_OIF && m->rtm_dst_len == 0) {
            unsigned o; memcpy(&o, (const char *)r + 4, 4);
            if (o == 2) R->oif = 1;
        }
        off += RTA_ALIGN(r->rta_len);
    }
}

struct done { int seen, err; };
static void done_cb(int ty, const char *p, int len, void *a) {
    struct done *D = a;
    (void)p; (void)len;
    if (ty == NLMSG_DONE) D->seen = 1;
    if (ty == NLMSG_ERROR && len >= 4)
        memcpy(&D->err, p, 4);
}

/* One request round-trip: sendmsg the nlmsghdr, recvmsg the blob. */
static int nl_req(int fd, int type, int flags, int seq,
                  void *extra, int elen, char *out, int cap) {
    char req[64];
    memset(req, 0, sizeof(req));
    struct nlmsghdr *h = (struct nlmsghdr *)req;
    h->nlmsg_len = sizeof(*h) + elen;
    h->nlmsg_type = type;
    h->nlmsg_flags = flags;
    h->nlmsg_seq = seq;
    if (extra) memcpy(req + sizeof(*h), extra, elen);
    struct iovec io = { req, h->nlmsg_len };
    struct msghdr mh;
    memset(&mh, 0, sizeof(mh));
    mh.msg_iov = &io; mh.msg_iovlen = 1;
    if (sendmsg(fd, &mh, 0) < 0) return -errno;
    memset(&mh, 0, sizeof(mh));
    struct sockaddr_nl from;
    char buf[4096];
    io.iov_base = buf; io.iov_len = sizeof(buf);
    mh.msg_iov = &io; mh.msg_iovlen = 1;
    mh.msg_name = &from; mh.msg_namelen = sizeof(from);
    int n = recvmsg(fd, &mh, 0);
    if (n < 0) return -errno;
    if (from.nl_family != AF_NETLINK || from.nl_pid != 0)
        return -1000;
    memcpy(out, buf, n < cap ? n : cap);
    return n;
}

/* Run busybox with the given argv; capture stdout into buf. */
static int bb_run(char *const argv[], char *buf, size_t cap,
                  int *exit_code) {
    int p[2];
    if (pipe(p) < 0) goto fail;
    pid_t pid = fork();
    if (pid < 0) { close(p[0]); close(p[1]); goto fail; }
    if (pid == 0) {
        dup2(p[1], 1); dup2(p[1], 2);
        close(p[0]); close(p[1]);
        execve("/busybox", argv, NULL);
        _exit(127);
    }
    close(p[1]);
    size_t n = 0;
    ssize_t r;
    while (n < cap - 1 &&
           (r = read(p[0], buf + n, cap - 1 - n)) > 0)
        n += (size_t)r;
    buf[n] = 0;
    close(p[0]);
    int st = 0;
    waitpid(pid, &st, 0);
    if (exit_code) *exit_code = WIFEXITED(st) ? WEXITSTATUS(st) : -1;
    return (int)n;
fail:
    buf[0] = 0;
    if (exit_code) *exit_code = -1;
    return -1;
}

int main(void) {
    char blob[4096];
    int n;

    check(socket(AF_NETLINK, SOCK_STREAM, 0) < 0 &&
          errno == ESOCKTNOSUPPORT, "nl stream refused");
    check(socket(AF_NETLINK, SOCK_RAW, 9) < 0 &&
          errno == EPROTONOSUPPORT, "nl proto 9 refused");
    int fd = socket(AF_NETLINK, SOCK_RAW, 0);
    check(fd >= 0, "nl sock raw");

    struct sockaddr_nl sa;
    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;
    check(bind(fd, (struct sockaddr *)&sa, sizeof(sa)) == 0,
          "bind pid=auto");
    socklen_t sl = sizeof(sa);
    check(getsockname(fd, (struct sockaddr *)&sa, &sl) == 0 &&
          sa.nl_family == AF_NETLINK && sa.nl_pid == getpid(),
          "getsockname pid");
    int fd2 = socket(AF_NETLINK, SOCK_DGRAM, 0);
    check(fd2 >= 0, "nl sock dgram");
    sa.nl_pid = getpid();
    check(bind(fd2, (struct sockaddr *)&sa, sizeof(sa)) < 0 &&
          errno == EADDRINUSE, "pid collision EADDRINUSE");
    close(fd2);

    // RTM_GETLINK dump: ifinfomsg tail, NLM_F_DUMP.
    struct ifinfomsg ii;
    memset(&ii, 0, sizeof(ii));
    n = nl_req(fd, RTM_GETLINK, NLM_F_REQUEST | NLM_F_DUMP, 1,
               &ii, sizeof(ii), blob, sizeof(blob));
    check(n > 0, "getlink reply");
    struct links L = {0, 0, 0};
    nl_walk(blob, n > 0 ? n : 0, link_cb, &L);
    check(L.n == 2 && L.lo == 1 && L.eth == 2, "links lo+eth0");
    struct done D = {0, 0};
    nl_walk(blob, n > 0 ? n : 0, done_cb, &D);
    check(D.seen, "getlink DONE");

    // RTM_GETADDR.
    struct ifaddrmsg ia;
    memset(&ia, 0, sizeof(ia));
    n = nl_req(fd, RTM_GETADDR, NLM_F_REQUEST | NLM_F_DUMP, 2,
               &ia, sizeof(ia), blob, sizeof(blob));
    check(n > 0, "getaddr reply");
    struct addrs A = {0, 0, 0};
    nl_walk(blob, n > 0 ? n : 0, addr_cb, &A);
    check(A.n == 2 && A.lo && A.eth, "addrs 127/10.0.2.15");

    // RTM_GETROUTE.
    struct rtmsg rm;
    memset(&rm, 0, sizeof(rm));
    n = nl_req(fd, RTM_GETROUTE, NLM_F_REQUEST | NLM_F_DUMP, 3,
               &rm, sizeof(rm), blob, sizeof(blob));
    check(n > 0, "getroute reply");
    struct routes R = {0, 0, 0};
    nl_walk(blob, n > 0 ? n : 0, route_cb, &R);
    check(R.n == 3 && R.gw && R.oif, "routes gw+oif");

    // Unknown request type -> NLMSG_ERROR(-EOPNOTSUPP).
    n = nl_req(fd, 0x7777, NLM_F_REQUEST, 4, NULL, 0,
               blob, sizeof(blob));
    struct done E = {0, 0};
    nl_walk(blob, n > 0 ? n : 0, done_cb, &E);
    check(E.err == -EOPNOTSUPP, "unknown -> EOPNOTSUPP");

    // Nonblock recv on the drained queue -> EAGAIN.
    fcntl(fd, F_SETFL, O_NONBLOCK);
    check(recv(fd, blob, sizeof(blob), 0) < 0 && errno == EAGAIN,
          "drained EAGAIN");

    // SO_RCVTIMEO: a blocking recv on the drained queue answers
    // EAGAIN at the deadline, not a permanent park.
    fcntl(fd, F_SETFL, 0);
    struct timeval ntv = {0, 50000}; /* 50ms */
    check(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &ntv,
                     sizeof(ntv)) == 0,
          "SO_RCVTIMEO set");
    errno = 0;
    check(recv(fd, blob, sizeof(blob), 0) < 0 && errno == EAGAIN,
          "SO_RCVTIMEO recv -> EAGAIN");
    // Short optlen EINVALs like Linux sock_set_timeout.
    check(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &ntv, 8) < 0 &&
          errno == EINVAL, "SO_RCVTIMEO optlen 8 EINVAL");

    // poll + FIONREAD after a fresh request.
    memset(&ii, 0, sizeof(ii));
    n = nl_req(fd, RTM_GETLINK, NLM_F_REQUEST | NLM_F_DUMP, 5,
               &ii, sizeof(ii), blob, sizeof(blob));
    int fd3 = socket(AF_NETLINK, SOCK_DGRAM, 0);
    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;
    bind(fd3, (struct sockaddr *)&sa, sizeof(sa));
    struct { struct nlmsghdr h; struct ifinfomsg i; } q;
    memset(&q, 0, sizeof(q));
    q.h.nlmsg_len = sizeof(q);
    q.h.nlmsg_type = RTM_GETLINK;
    q.h.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    q.h.nlmsg_seq = 9;
    check(send(fd3, &q, sizeof(q), 0) == (ssize_t)sizeof(q),
          "send(2) request");
    struct pollfd pfd = { fd3, POLLIN, 0 };
    check(poll(&pfd, 1, 500) == 1 && (pfd.revents & POLLIN),
          "poll POLLIN");
    int av = 0;
    check(ioctl(fd3, FIONREAD, &av) == 0 && av > 0, "FIONREAD");
    n = recv(fd3, blob, sizeof(blob), 0);
    check(n > 0, "recv() reply");
    close(fd3);

    // Real-binary proof: busybox ip parses the socket.
    char out[4096];
    int ec = -1;
    char *a_link[] = { "busybox", "ip", "link", NULL };
    n = bb_run(a_link, out, sizeof(out), &ec);
    check(n > 0 && ec == 0 && strstr(out, "eth0") &&
          strstr(out, "lo"), "busybox ip link");
    char *a_addr[] = { "busybox", "ip", "addr", NULL };
    n = bb_run(a_addr, out, sizeof(out), &ec);
    check(n > 0 && ec == 0 && strstr(out, "10.0.2.15") &&
          strstr(out, "127.0.0.1"), "busybox ip addr");
    char *a_route[] = { "busybox", "ip", "route", NULL };
    n = bb_run(a_route, out, sizeof(out), &ec);
    check(n > 0 && ec == 0 && strstr(out, "10.0.2.2"),
          "busybox ip route");

    close(fd);
    char fin[64];
    int m = snprintf(fin, sizeof(fin),
                     "nltest: %d failure(s)\n", fails);
    say(fin);
    return fails;
}
