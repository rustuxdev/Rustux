// nettest — QEMU slirp end-to-end proof: DNS resolution through the
// built-in 10.0.2.3 resolver, then a real TCP connect + HTTP GET to
// the resolved address. Boots with no NIC report "skip" cleanly so
// the plain `make run` suite stays hermetic; `make run-net` attaches
// -netdev user + e1000e and exercises the full wire path.
// Exit status = failure count (0 also when skipped).
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int fails;

static void say(const char *s) {
    if (write(1, s, strlen(s)) < 0) { /* ignore */ }
}

static void check(int ok, const char *what) {
    char buf[96];
    snprintf(buf, sizeof(buf), "nettest: %-34s %s\n",
             what, ok ? "ok" : "FAIL");
    say(buf);
    if (!ok) fails++;
}

/* Encode "a.b.c" labels into a DNS qname. Returns length or -1. */
static int put_qname(uint8_t *out, const char *name) {
    int n = 0;
    const char *p = name;
    while (*p) {
        const char *dot = strchr(p, '.');
        int len = dot ? (int)(dot - p) : (int)strlen(p);
        if (len == 0 || len > 63 || n + len + 2 > 250) return -1;
        out[n++] = (uint8_t)len;
        memcpy(out + n, p, len);
        n += len;
        if (!dot) break;
        p = dot + 1;
    }
    out[n++] = 0;
    return n;
}

/* Skip a DNS name (labels or compression pointer). */
static int skip_name(const uint8_t *p, int len, int at) {
    while (at < len) {
        int c = p[at];
        if (c == 0) return at + 1;
        if ((c & 0xc0) == 0xc0) return at + 2;
        at += c + 1;
    }
    return -1;
}

static int wait_fd(int fd, short events, int ms) {
    struct pollfd p = { .fd = fd, .events = events };
    return poll(&p, 1, ms);
}

int main(void) {
    say("nettest: slirp end-to-end\n");

    /* DNS query for deb.debian.org -> slirp's resolver 10.0.2.3. */
    const char *qname = "deb.debian.org";
    uint8_t q[256];
    memset(q, 0, sizeof(q));
    q[2] = 0x01; /* RD */
    q[5] = 0x01; /* QDCOUNT=1 */
    int ql = put_qname(q + 12, qname);
    check(ql > 0, "dns query encode");
    q[12 + ql + 1] = 0x01; /* QTYPE=A */
    q[12 + ql + 3] = 0x01; /* QCLASS=IN */
    int qlen = 12 + ql + 4;

    int u = socket(AF_INET, SOCK_DGRAM, 0);
    check(u >= 0, "udp socket");
    struct sockaddr_in dns = {
        .sin_family = AF_INET,
        .sin_port = htons(53),
        .sin_addr.s_addr = htonl(0x0a000203), /* 10.0.2.3 */
    };
    ssize_t s = sendto(u, q, qlen, 0,
                       (struct sockaddr *)&dns, sizeof(dns));
    if (s < 0 && errno == EHOSTUNREACH) {
        say("nettest: no nic — skip (run-net attaches e1000e)\n");
        return 0;
    }
    check(s == qlen, "dns query sendto");

    uint8_t r[512];
    check(wait_fd(u, POLLIN, 5000) > 0, "dns reply poll");
    ssize_t rl = recvfrom(u, r, sizeof(r), 0, NULL, NULL);
    check(rl > 12, "dns reply recvfrom");
    if (rl <= 12) { say("nettest: done\n"); return fails; }

    int an = (r[6] << 8) | r[7];
    check((r[3] & 0x0f) == 0 && an > 0, "dns rcode=0 ancount>0");

    /* Walk answers for the first A record. */
    uint32_t ip = 0;
    int at = 12 + ql + 4;
    for (int i = 0; i < an && at > 0 && at < rl; i++) {
        at = skip_name(r, (int)rl, at);
        if (at < 0 || at + 10 > rl) break;
        int type = (r[at] << 8) | r[at + 1];
        int rdlen = (r[at + 8] << 8) | r[at + 9];
        at += 10;
        if (type == 1 && rdlen == 4 && at + 4 <= rl) {
            memcpy(&ip, r + at, 4);
            break;
        }
        at += rdlen;
    }
    check(ip != 0, "dns A record");
    char ipb[64];
    struct in_addr ia = { .s_addr = ip };
    snprintf(ipb, sizeof(ipb), "nettest: %s -> %s\n", qname, inet_ntoa(ia));
    say(ipb);

    /* TCP connect to the resolved address on :80 + HTTP GET. */
    int c = socket(AF_INET, SOCK_STREAM, 0);
    check(c >= 0, "tcp socket");
    struct sockaddr_in dst = {
        .sin_family = AF_INET,
        .sin_port = htons(80),
        .sin_addr.s_addr = ip,
    };
    int cr = connect(c, (struct sockaddr *)&dst, sizeof(dst));
    check(cr == 0, "tcp connect :80");

    char req[160];
    int reql = snprintf(req, sizeof(req),
                        "GET / HTTP/1.0\r\nHost: %s\r\n\r\n", qname);
    check(send(c, req, reql, 0) == reql, "http GET send");

    char resp[1024];
    int got = 0, total = 0;
    while (total < (int)sizeof(resp) - 1) {
        if (wait_fd(c, POLLIN, 5000) <= 0) break;
        ssize_t n = recv(c, resp + total, sizeof(resp) - 1 - total, 0);
        if (n <= 0) break;
        total += (int)n;
    }
    resp[total] = 0;
    got = total;
    check(got > 0, "http reply recv");
    check(got > 4 && memcmp(resp, "HTTP/", 5) == 0, "http status line");
    char lb[80];
    char *eol = strchr(resp, '\r');
    if (eol) *eol = 0;
    snprintf(lb, sizeof(lb), "nettest: %.60s\n", resp);
    say(lb);

    close(c);
    close(u);
    snprintf(lb, sizeof(lb), "nettest: %d failures, done\n", fails);
    say(lb);
    return fails;
}
