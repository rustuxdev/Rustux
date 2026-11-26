// hvctest — compiled virtio-console ABI proof: /dev/hvc0 (char
// major 229) over the virtio-serial port-0 queues. Covers the
// open/stat gates, the TX write path (bytes land in QEMU's chardev
// backend — the host-side capture is the external proof), and the
// RX path where tools/hvcfeed.py injects "rx-proof-line" through
// the socket backend every 250ms. Reads are non-blocking — the
// device reports what's drained — so the proof polls a bounded
// window. Same check() convention as iotest — exit status is the
// failure count.
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <poll.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>

static int fails;

static void say(const char *s) {
    if (write(1, s, strlen(s)) < 0) { /* ignore */ }
}

static void check(int ok, const char *what) {
    char buf[80];
    int n = snprintf(buf, sizeof(buf), "hvctest: %-28s %s\n",
                     what, ok ? "ok" : "FAIL");
    say(buf);
    if (!ok) fails++;
}

int main(void) {
    struct stat st;
    char acc[512];
    int fd, accn = 0, i;

    // ---- open + stat gates ----
    fd = open("/dev/hvc0", O_RDWR);
    check(fd >= 0, "open hvc0");
    if (fd < 0) {
        printf("hvctest: %d failures, done\n", fails);
        return fails;
    }
    check(fstat(fd, &st) == 0, "fstat hvc0");
    check(S_ISCHR(st.st_mode), "mode is S_IFCHR");
    check(major(st.st_rdev) == 229 && minor(st.st_rdev) == 0,
          "rdev 229:0");

    // ---- TX: bytes out the port-0 transmit queue ----
    check(write(fd, "hvc-user-tx-proof\n", 18) == 18,
          "write tx-proof 18B");

    // ---- RX: hvcfeed.py injects rx-proof-line every 250ms; the
    // kernel drains device completions into a FIFO, and poll()
    // reports POLLIN once bytes queue. ----
    {
        struct pollfd pfd;
        int n;

        memset(&pfd, 0, sizeof(pfd));
        pfd.fd = fd;
        pfd.events = POLLIN;
        check(poll(&pfd, 1, 4000) == 1 && (pfd.revents & POLLIN),
              "poll POLLIN on input");
        memset(acc, 0, sizeof(acc));
        for (i = 0; i < 30 && accn < 400; i++) {
            n = read(fd, acc + accn, sizeof(acc) - 1 - accn);
            if (n > 0) accn += n;
            if (strstr(acc, "rx-proof")) break;
            usleep(100 * 1000);
        }
        check(accn > 0, "read rx bytes");
        check(strstr(acc, "rx-proof") != NULL,
              "rx-proof-line arrived");
    }

    close(fd);
    printf("hvctest: %d failures, done\n", fails);
    return fails;
}
