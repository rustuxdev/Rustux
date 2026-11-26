// pkttest — compiled AF_PACKET ABI proof:
// socket(AF_PACKET, SOCK_RAW/SOCK_DGRAM, htons(proto)), bind() with
// sockaddr_ll, recvfrom/read/poll delivery of captured frames, the
// cooked strip, sendto() raw transmit, and the gate set
// (ESOCKTNOSUPPORT/EAFNOSUPPORT/ENODEV/EINVAL/EAGAIN).
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
#include <netinet/in.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>

static int fails;

static void say(const char *s) {
    if (write(1, s, strlen(s)) < 0) { /* ignore */ }
}

static void check(int ok, const char *what) {
    char buf[80];
    int n = snprintf(buf, sizeof(buf), "pkttest: %-34s %s\n",
                     what, ok ? "ok" : "FAIL");
    say(buf);
    if (!ok) fails++;
}

// A UDP self-transmit so the TX tap has a frame to capture: send a
// datagram to the QEMU gateway (10.0.2.2) — it leaves via tx_eth.
static int tx_udp(void) {
    int u = socket(AF_INET, SOCK_DGRAM, 0);
    if (u < 0) return -1;
    struct sockaddr_in d;
    memset(&d, 0, sizeof(d));
    d.sin_family = AF_INET;
    d.sin_port = htons(9999);
    d.sin_addr.s_addr = htonl(0x0a000202); // 10.0.2.2 — QEMU's gw
    int r = sendto(u, "x", 1, 0,
                 (struct sockaddr *)&d, sizeof(d));
    close(u);
    return r;
}

int main(void) {
    unsigned char fr[1600];
    struct sockaddr_ll sll;
    struct pollfd pfd;
    ssize_t n;

    check(socket(AF_PACKET, SOCK_STREAM, htons(ETH_P_ALL)) < 0 &&
          errno == ESOCKTNOSUPPORT, "stream type refused");
    int bad = socket(99, SOCK_RAW, htons(ETH_P_ALL));
    check(bad < 0 && errno == EAFNOSUPPORT, "bad domain refused");

    int p = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    check(p >= 0, "socket raw ETH_P_ALL");
    if (p < 0) return 1;

    struct stat st;
    check(fstat(p, &st) == 0 && S_ISSOCK(st.st_mode), "fstat is sock");

    // bind(): sockaddr_ll filter — proto ALL, ifindex 0 = any iface.
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex = 0;
    check(bind(p, (struct sockaddr *)&sll, sizeof(sll)) == 0,
          "bind ifindex 0");
    sll.sll_ifindex = 99;
    check(bind(p, (struct sockaddr *)&sll, sizeof(sll)) < 0 &&
          errno == ENODEV, "bind bad ifindex ENODEV");
    sll.sll_family = AF_INET;
    sll.sll_ifindex = 0;
    check(bind(p, (struct sockaddr *)&sll, sizeof(sll)) < 0 &&
          errno == EAFNOSUPPORT, "bind wrong family");

    socklen_t al = sizeof(sll);
    memset(&sll, 0, sizeof(sll));
    check(getsockname(p, (struct sockaddr *)&sll, &al) == 0 &&
          sll.sll_family == AF_PACKET &&
          sll.sll_protocol == htons(ETH_P_ALL),
          "getsockname sockaddr_ll");
    check(getpeername(p, (struct sockaddr *)&sll, &al) < 0 &&
          errno == ENOTCONN, "getpeername ENOTCONN");

    // Drain anything queued during boot, then prove the filter:
    // an IPv6-only socket must see nothing we generate.
    int v6 = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IPV6));
    check(v6 >= 0, "socket raw ETH_P_IPV6");
    fcntl(v6, F_SETFL, O_NONBLOCK);
    fcntl(p, F_SETFL, O_NONBLOCK);
    while (recvfrom(p, fr, sizeof(fr), 0, NULL, NULL) > 0) {}

    check(tx_udp() > 0, "udp tx for the tap");

    memset(&sll, 0, sizeof(sll));
    al = sizeof(sll);
    n = recvfrom(p, fr, sizeof(fr), 0,
                 (struct sockaddr *)&sll, &al);
    check(n >= 60, "tx frame captured");
    if (n >= 14) {
        check(fr[12] == 0x08 && fr[13] == 0x00, "ethertype IPv4");
        check(sll.sll_family == AF_PACKET &&
              sll.sll_protocol == htons(ETH_P_IP) &&
              sll.sll_pkttype == PACKET_OUTGOING &&
              sll.sll_ifindex == 2 &&
              sll.sll_halen == 6,
              "sockaddr_ll outgoing fields");
        check(memcmp(sll.sll_addr, fr + 6, 6) == 0,
              "sll_addr is frame src");
    }
    int len0 = 0;
    check(ioctl(p, FIONREAD, &len0) == 0 &&
          (len0 == 0 || len0 > 0), "FIONREAD answered");
    check(recvfrom(v6, fr, sizeof(fr), 0, NULL, NULL) < 0 &&
          errno == EAGAIN, "ipv6 filter sees nothing");

    // poll() readability after a fresh TX.
    tx_udp();
    pfd.fd = p;
    pfd.events = POLLIN;
    check(poll(&pfd, 1, 0) == 1 && (pfd.revents & POLLIN),
          "poll POLLIN on capture");

    // read() form + cooked sibling strips the L2 header.
    n = read(p, fr, sizeof(fr));
    check(n >= 60, "read() captures");

    int ck = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_ALL));
    check(ck >= 0, "socket cooked");
    tx_udp();
    memset(&sll, 0, sizeof(sll));
    n = recvfrom(ck, fr, sizeof(fr), 0,
                 (struct sockaddr *)&sll, NULL);
    check(n >= 46 && fr[0] == 0x45, "cooked strips l2");

    // sendto() raw: craft a full frame and transmit it.
    memset(fr, 0, 60);
    memset(fr, 0xff, 6);               // broadcast dst
    memcpy(fr + 6, "\x52\x54\x00\x12\x34\x56", 6);
    fr[12] = 0x08; fr[13] = 0x00;      // IPv4 proto
    n = sendto(p, fr, 60, 0, NULL, 0);
    check(n == 60, "sendto raw frame");
    check(sendto(p, fr, 10, 0, NULL, 0) < 0 && errno == EINVAL,
          "short frame EINVAL");

    // The outgoing sendto frame we just transmitted lands in our
    // own queue too — drain both and confirm at least one more
    // OUTGOING frame arrived.
    int seen = 0;
    while ((n = recvfrom(p, fr, sizeof(fr), 0,
                         (struct sockaddr *)&sll, &al)) > 0) {
        if (sll.sll_pkttype == PACKET_OUTGOING) seen++;
    }
    check(seen >= 1, "outgoing frames queued");

    close(p);
    close(ck);
    close(v6);

    char buf[48];
    int m = snprintf(buf, sizeof(buf), "pkttest: %d failures\n", fails);
    say(buf);
    return fails;
}
