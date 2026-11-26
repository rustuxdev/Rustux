// tuntest — compiled /dev/net/tun ABI proof:
// open(), TUNSETIFF/TUNGETIFF, outbound IPv4 to the iface's fixed
// 10.200.i.0/24 subnet landing in the read queue (PI + IFF_NO_PI),
// write() injecting inbound packets a bound UDP socket then sees,
// TAP whole-frame mode, FIONREAD/poll, a fork'd blocked reader,
// and the gate set (EIO pre-setiff, EBUSY re-setiff, EINVAL flags,
// EAGAIN empty queue).
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <poll.h>
#include <wait.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <linux/if.h>
#include <linux/if_tun.h>

static int fails;

static void say(const char *s) {
    if (write(1, s, strlen(s)) < 0) { /* ignore */ }
}

static void check(int ok, const char *what) {
    char buf[80];
    int n = snprintf(buf, sizeof(buf), "tuntest: %-34s %s\n",
                     what, ok ? "ok" : "FAIL");
    say(buf);
    if (!ok) fails++;
}

static int tun_open(void) {
    return open("/dev/net/tun", O_RDWR);
}

static int tun_iff(int fd, short flags, const char *nm) {
    struct ifreq r;
    memset(&r, 0, sizeof(r));
    if (nm) memcpy(r.ifr_name, nm, strlen(nm));
    r.ifr_flags = flags;
    return ioctl(fd, TUNSETIFF, &r);
}

// A UDP sendto — the outbound frame for the read side to catch.
static int tx_udp(int d3, const void *pay, int paylen) {
    int u = socket(AF_INET, SOCK_DGRAM, 0);
    if (u < 0) return -1;
    struct sockaddr_in d;
    memset(&d, 0, sizeof(d));
    d.sin_family = AF_INET;
    d.sin_port = htons(7777);
    unsigned char a[4] = {10, 200, (unsigned char)d3, 9};
    memcpy(&d.sin_addr.s_addr, a, 4);
    int r = sendto(u, pay, paylen, 0,
                   (struct sockaddr *)&d, sizeof(d));
    close(u);
    return r;
}

// Build an IPv4+UDP packet (udp cksum 0 — accepted as "off").
static int ip_udp(unsigned char *p, const unsigned char src[4],
                  const unsigned char dst[4], unsigned short sport,
                  unsigned short dport, const void *pay, int paylen) {
    int tot = 28 + paylen;
    memset(p, 0, tot);
    p[0] = 0x45;
    p[2] = tot >> 8; p[3] = tot & 0xff;
    p[4] = 0; p[5] = 1;
    p[8] = 64; p[9] = 17;
    memcpy(p + 12, src, 4);
    memcpy(p + 16, dst, 4);
    unsigned s = 0;
    for (int i = 0; i < 20; i += 2) s += (p[i] << 8) | p[i + 1];
    s = (s >> 16) + (s & 0xffff);
    s = (s >> 16) + (s & 0xffff);
    unsigned c = ~s & 0xffff;
    p[10] = c >> 8; p[11] = c & 0xff;
    p[20] = sport >> 8; p[21] = sport & 0xff;
    p[22] = dport >> 8; p[23] = dport & 0xff;
    p[24] = (8 + paylen) >> 8; p[25] = (8 + paylen) & 0xff;
    memcpy(p + 28, pay, paylen);
    return tot;
}

int main(void) {
    unsigned char buf[1600];
    struct ifreq ifr;
    struct pollfd pfd;
    ssize_t n;
    int f;

    // ---- open + pre-attach gates ----
    int t0 = tun_open();
    check(t0 >= 0, "open /dev/net/tun");
    errno = 0;
    check(read(t0, buf, sizeof(buf)) < 0 && errno == EIO,
          "read pre-TUNSETIFF is EIO");
    check(tun_iff(t0, 0, "x") < 0 && errno == EINVAL,
          "no-mode flags EINVAL");
    check(tun_iff(t0, IFF_TUN | IFF_TAP, "x") < 0 && errno == EINVAL,
          "TUN+TAP flags EINVAL");

    // ---- tun0: IFF_TUN | IFF_NO_PI on slot 0 (10.200.0.0/24) ----
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    check(ioctl(t0, TUNSETIFF, &ifr) == 0, "TUNSETIFF tun no_pi");
    check(tun_iff(t0, IFF_TUN, "y") < 0 && errno == EBUSY,
          "re-attach is EBUSY");
    memset(&ifr, 0, sizeof(ifr));
    check(ioctl(t0, TUNGETIFF, &ifr) == 0 &&
          (ifr.ifr_flags & (IFF_TUN | IFF_NO_PI)) ==
              (IFF_TUN | IFF_NO_PI),
          "TUNGETIFF reports flags");

    // outbound IPv4 to the slot's subnet lands in the read queue
    check(tx_udp(0, "ping0", 5) == 5, "udp to tun0 subnet sent");
    pfd.fd = t0; pfd.events = POLLIN | POLLOUT;
    check(poll(&pfd, 1, 0) == 1 &&
          (pfd.revents & (POLLIN | POLLOUT)) == (POLLIN | POLLOUT),
          "poll shows queued packet");
    int avail = 0;
    check(ioctl(t0, FIONREAD, &avail) == 0 && avail > 20,
          "FIONREAD packet len");
    n = read(t0, buf, sizeof(buf));
    check(n >= 33 && buf[0] >> 4 == 4 && buf[9] == 17 &&
          buf[16] == 10 && buf[17] == 200 && buf[18] == 0 &&
          buf[19] == 9 && memcmp(buf + 28, "ping0", 5) == 0,
          "tun read got the IP packet");

    // empty queue + O_NONBLOCK -> EAGAIN
    f = fcntl(t0, F_SETFL, O_NONBLOCK);
    check(f == 0 && read(t0, buf, sizeof(buf)) < 0 &&
          errno == EAGAIN, "empty queue EAGAIN");
    fcntl(t0, F_SETFL, 0);

    // ---- inbound injection: write() feeds the socket layer ----
    unsigned char me[4] = {10, 0, 2, 15}; // QEMU slirp lease
    int rx = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(5555);
    sa.sin_addr.s_addr = htonl(INADDR_ANY);
    check(bind(rx, (struct sockaddr *)&sa, sizeof(sa)) == 0,
          "bind rx udp :5555");
    unsigned char src4[4] = {10, 200, 0, 5};
    int pl = ip_udp(buf, src4, me, 4444, 5555, "hello-tun", 9);
    check(write(t0, buf, pl) == pl, "tun write injected packet");
    memset(&sa, 0, sizeof(sa));
    socklen_t sl = sizeof(sa);
    n = recvfrom(rx, buf, sizeof(buf), 0,
                 (struct sockaddr *)&sa, &sl);
    check(n == 9 && memcmp(buf, "hello-tun", 9) == 0 &&
          ((unsigned char *)&sa.sin_addr.s_addr)[0] == 10 &&
          ((unsigned char *)&sa.sin_addr.s_addr)[1] == 200,
          "socket saw injected packet");
    close(rx);

    // ---- blocked reader: fork'd child parks on TunRecv ----
    int rp[2];
    check(pipe(rp) == 0, "pipe for wake sync");
    pid_t kid = fork();
    if (kid == 0) {
        close(rp[0]);
        if (write(rp[1], "r", 1) != 1) _exit(9);
        unsigned char rb[200];
        ssize_t rn = read(t0, rb, sizeof(rb));
        _exit(rn >= 32 && memcmp(rb + 28, "wake", 4) == 0
                  ? 0
                  : 10);
    }
    close(rp[1]);
    check(read(rp[0], buf, 1) == 1, "child parked on read");
    close(rp[0]);
    check(tx_udp(0, "wake", 4) == 4, "udp wakes the reader");
    int st = 0;
    waitpid(kid, &st, 0);
    check(WIFEXITED(st) && WEXITSTATUS(st) == 0,
          "blocked read delivered the packet");

    // ---- tun1: PI header mode (slot 1, 10.200.1.0/24) ----
    int t1 = tun_open();
    check(t1 >= 0 && tun_iff(t1, IFF_TUN, "p0") == 0,
          "tun1 TUNSETIFF with PI");
    check(tx_udp(1, "pi", 2) == 2, "udp to tun1 subnet sent");
    n = read(t1, buf, sizeof(buf));
    check(n >= 26 && buf[0] == 0 && buf[1] == 0 && buf[2] == 0x08 &&
          buf[3] == 0 && buf[4] >> 4 == 4 && buf[13] == 17 &&
          buf[20] == 10 && buf[21] == 200 && buf[22] == 1,
          "PI header + IP packet");

    // ---- tap2: IFF_TAP whole frames (slot 2, 10.200.2.0/24) ----
    int t2 = tun_open();
    check(t2 >= 0 && tun_iff(t2, IFF_TAP | IFF_NO_PI, "p1") == 0,
          "tap TUNSETIFF");
    check(tx_udp(2, "tap", 3) == 3, "udp to tap subnet sent");
    n = read(t2, buf, sizeof(buf));
    check(n >= 47 && buf[12] == 0x08 && buf[13] == 0x00 &&
          buf[14] >> 4 == 4 && buf[30] == 10 && buf[31] == 200 &&
          buf[32] == 2 && memcmp(buf + 42, "tap", 3) == 0,
          "tap read got eth+ip frame");

    // TAP inbound: a whole eth frame demuxes like wire traffic.
    int rx2 = socket(AF_INET, SOCK_DGRAM, 0);
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(6666);
    sa.sin_addr.s_addr = htonl(INADDR_ANY);
    check(bind(rx2, (struct sockaddr *)&sa, sizeof(sa)) == 0,
          "bind rx2 udp :6666");
    unsigned char fr[1600];
    memset(fr, 0, 14);
    memset(fr, 0xff, 6);
    fr[6] = 0x02; fr[7] = 0xaa; fr[8] = 0xbb;
    fr[12] = 0x08; fr[13] = 0x00;
    unsigned char src2[4] = {10, 200, 2, 5};
    pl = ip_udp(fr + 14, src2, me, 8888, 6666, "hello-tap", 9);
    check(write(t2, fr, 14 + pl) == 14 + pl,
          "tap write injected frame");
    n = recvfrom(rx2, buf, sizeof(buf), 0,
                 (struct sockaddr *)&sa, &sl);
    check(n == 9 && memcmp(buf, "hello-tap", 9) == 0 &&
          ((unsigned char *)&sa.sin_addr.s_addr)[1] == 200 &&
          ((unsigned char *)&sa.sin_addr.s_addr)[2] == 2,
          "socket saw injected frame");
    close(rx2);

    // ---- teardown: a reopened slot comes back fresh ----
    close(t0);
    int t3 = tun_open();
    check(t3 >= 0 && tun_iff(t3, IFF_TUN | IFF_NO_PI, "z") == 0,
          "reopen after close");
    check(tx_udp(0, "x", 1) == 1, "send to reopened subnet");
    n = read(t3, buf, sizeof(buf));
    check(n >= 29 && buf[19] == 9, "reopened tun reads again");
    close(t1); close(t2); close(t3);

    n = snprintf((char *)buf, sizeof(buf),
                 "tuntest: %d failure(s)\n", fails);
    say((char *)buf);
    return fails;
}
