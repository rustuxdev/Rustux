// ptytest: Unix98 pty pair — posix_openpt/unlockpt/ptsname through
// /dev/ptmx + dev/pts/N, bidirectional byte flow, poll readiness,
// TIOCGPTPEER, and EIO-on-hangup semantics.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <unistd.h>

static int fails;

static void say(const char *s) {
    if (write(1, s, strlen(s)) < 0) { /* ignore */ }
}

static void check(int ok, const char *what) {
    char buf[96];
    snprintf(buf, sizeof(buf), "ptytest: %-38s %s\n",
             what, ok ? "ok" : "FAIL");
    say(buf);
    if (!ok) fails++;
}

static void checke(long r, const char *what) {
    if (r >= 0) { check(1, what); return; }
    char buf[96];
    snprintf(buf, sizeof(buf), "ptytest: %-34s FAIL errno=%d\n",
             what, errno);
    say(buf);
    fails++;
}

int main(void) {
    int m = posix_openpt(O_RDWR | O_NOCTTY);
    check(m >= 0, "posix_openpt");
    if (m < 0) return 1;

    check(isatty(m), "master isatty");

    /* slave name resolution through TIOCGPTN. */
    unsigned int n = 0;
    check(ioctl(m, TIOCGPTN, &n) == 0, "ioctl TIOCGPTN");
    char *nm = ptsname(m);
    check(nm != NULL && n < 8, "ptsname returns a name");
    char expect[32];
    snprintf(expect, sizeof(expect), "/dev/pts/%u", n);
    check(nm && strcmp(nm, expect) == 0, "ptsname matches /dev/pts/N");

    /* locked slave refuses opens with EIO. */
    errno = 0;
    check(open(expect, O_RDWR | O_NOCTTY) < 0 && errno == EIO,
          "locked slave open -> EIO");

    check(unlockpt(m) == 0, "unlockpt");
    int s = open(expect, O_RDWR | O_NOCTTY);
    check(s >= 0, "slave open");
    if (s < 0) return ++fails;
    check(isatty(s), "slave isatty");

    /* TIOCGPTPEER mints a second slave fd. */
    int s2 = ioctl(m, TIOCGPTPEER, O_RDWR | O_CLOEXEC);
    check(s2 >= 0, "ioctl TIOCGPTPEER");
    if (s2 >= 0) close(s2);

    /* bidirectional flow: master -> slave and slave -> master. */
    checke(write(m, "abc", 3) - 3, "master write");
    char buf[32] = {0};
    checke(read(s, buf, 3) - 3, "slave read"); check(memcmp(buf, "abc", 3) == 0,
          "slave reads master bytes");
    checke(write(s, "xy", 2) - 2, "slave write");
    memset(buf, 0, sizeof(buf));
    checke(read(m, buf, 2) - 2, "master read"); check(memcmp(buf, "xy", 2) == 0,
          "master reads slave bytes");

    /* poll: master readable after slave writes, writable always. */
    checke(write(s, "q", 1) - 1, "slave write for poll");
    struct pollfd pfd = { .fd = m, .events = POLLIN | POLLOUT };
    check(poll(&pfd, 1, 0) == 1 && (pfd.revents & POLLIN)
              && (pfd.revents & POLLOUT),
          "poll master POLLIN|POLLOUT");
    char drain[4];
    check(read(m, drain, 1) == 1, "drain poll byte");

    /* termios round-trip on the slave. */
    struct termios tio;
    check(tcgetattr(s, &tio) == 0, "tcgetattr slave");
    tio.c_lflag &= ~ECHO;
    check(tcsetattr(s, TCSANOW, &tio) == 0, "tcsetattr slave");

    /* hangup: closing the last master OFD turns slave io into EIO. */
    check(close(m) == 0, "master close");
    char c;
    errno = 0;
    check(read(s, &c, 1) < 0 && errno == EIO,
          "slave read after master close -> EIO");
    errno = 0;
    check(write(s, "z", 1) < 0 && errno == EIO,
          "slave write after master close -> EIO");
    close(s);

    /* a fresh pair works after teardown (index reuse). */
    int m2 = posix_openpt(O_RDWR);
    check(m2 >= 0 && unlockpt(m2) == 0, "second pair opens");
    if (m2 >= 0) close(m2);

    /* a master open that fails AFTER the pair is minted must roll
       it back — a leaked pair (mopen=1 forever) never retires, and
       four leaks exhaust the pty table plus its vfile nodes. */
    for (int i = 0; i < 6; i++) {
        errno = 0;
        int r = open("/dev/ptmx", O_RDWR | O_NOCTTY | O_DIRECTORY);
        check(r < 0 && errno == ENOTDIR, "ptmx O_DIRECTORY -> ENOTDIR");
    }
    for (int i = 0; i < 6; i++) {
        int dummies[16], nd = 0;
        while (nd < 16) {
            int d = open("/dev/null", O_RDONLY);
            if (d < 0) break;
            dummies[nd++] = d;
        }
        errno = 0;
        int r = open("/dev/ptmx", O_RDWR | O_NOCTTY);
        check(r < 0 && errno == EMFILE, "ptmx with full fdt -> EMFILE");
        for (int j = 0; j < nd; j++) close(dummies[j]);
    }
    int m3 = posix_openpt(O_RDWR | O_NOCTTY);
    check(m3 >= 0, "ptmx opens after failed opens");
    if (m3 >= 0) {
        check(unlockpt(m3) == 0, "unlockpt after aborts");
        close(m3);
    }

    say(fails ? "ptytest: FAILURES\n" : "ptytest: all ok\n");
    return fails;
}
