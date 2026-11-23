// termtest — compiled terminal-ABI proof: isatty()/tcgetattr through
// the TCGETS ioctl, tcsetattr round-trip, TIOCGWINSZ grid, TIOCGPGRP,
// FIONREAD on a pipe and a file, and honest ENOTTY/EBADF/EINVAL
// refusals. Same check() convention — exit status = failure count.
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <termios.h>
#include <sys/ioctl.h>

static int fails;

static void say(const char *s) {
    if (write(1, s, strlen(s)) < 0) { /* ignore */ }
}

static void check(int ok, const char *what) {
    char buf[96];
    int n = snprintf(buf, sizeof(buf), "termtest: %-28s %s\n",
                     what, ok ? "ok" : "FAIL");
    say(buf);
    if (!ok) fails++;
}

int main(void) {
    struct termios tio, tio2;
    struct winsize ws;
    int pfd[2], n;

    say("termtest: terminal abi checks\n");

    /* isatty = TCGETS ioctl under the hood */
    check(isatty(0) == 1, "isatty stdin");
    check(isatty(1) == 1, "isatty stdout");
    int fd = open("motd.txt", O_RDONLY);
    check(fd >= 0, "open motd");
    if (fd >= 0) {
        errno = 0;
        check(isatty(fd) == 0 && errno == ENOTTY,
              "isatty file -> ENOTTY");
    }

    /* termios get/set round-trip on the console fd */
    check(tcgetattr(1, &tio) == 0, "tcgetattr stdout");
    check((tio.c_lflag & ICANON) != 0, "lflag ICANON");
    check((tio.c_lflag & ECHO) != 0, "lflag ECHO");
    check(tio.c_cc[VMIN] == 1 && tio.c_cc[VTIME] == 0,
          "cc VMIN/VTIME");
    tio.c_lflag &= ~(tcflag_t)ECHO;
    check(tcsetattr(1, TCSANOW, &tio) == 0, "tcsetattr ECHO off");
    check(tcgetattr(1, &tio2) == 0 &&
          (tio2.c_lflag & ECHO) == 0, "tcgetattr sees change");
    tio.c_lflag |= ECHO;
    tcsetattr(1, TCSANOW, &tio); /* restore */

    /* winsize: the fbcon grid — nonzero rows/cols */
    n = ioctl(1, TIOCGWINSZ, &ws);
    {
        char wbuf[64];
        int wn = snprintf(wbuf, sizeof(wbuf),
                          "termtest: winsize %dx%d\n", ws.ws_col, ws.ws_row);
        (void)wn;
        say(wbuf);
    }
    check(n == 0 && ws.ws_col > 0 && ws.ws_row > 0, "TIOCGWINSZ grid");

    /* foreground pgrp is our own pid in the single-pgrp model */
    int pgrp = -1;
    check(ioctl(0, TIOCGPGRP, &pgrp) == 0 && pgrp == getpid(),
          "TIOCGPGRP = pid");

    /* FIONREAD: pipe fill + file remainder */
    check(pipe(pfd) == 0, "pipe");
    if (pfd[0] >= 0) {
        n = -1;
        check(ioctl(pfd[0], FIONREAD, &n) == 0 && n == 0,
              "FIONREAD empty pipe");
        if (write(pfd[1], "abcde", 5) == 5) {
            n = -1;
            check(ioctl(pfd[0], FIONREAD, &n) == 0 && n == 5,
                  "FIONREAD 5 queued");
        }
        close(pfd[0]); close(pfd[1]);
    }
    if (fd >= 0) {
        n = -1;
        check(ioctl(fd, FIONREAD, &n) == 0 && n > 0,
              "FIONREAD file remaining");
        close(fd);
    }

    /* refusals */
    n = -1;
    errno = 0;
    check(ioctl(9999, FIONREAD, &n) < 0 && errno == EBADF,
          "ioctl bad fd -> EBADF");
    errno = 0;
    check(ioctl(0, FIONBIO, &n) < 0 && errno == EINVAL,
          "FIONBIO -> EINVAL");

    /* Terminal-reply round-trip: write \e[6n to the console, the
       fbcon CSI parser injects "\e[<r>;<c>R" into stdin like a real
       terminal. \e[c (DA) answers "\e[?1;2c". The fbcon exists
       whenever the GOP grid is nonzero (TIOCGWINSZ above). */
    tcgetattr(0, &tio);
    tio2 = tio;
    tio2.c_lflag &= ~(tcflag_t)(ICANON | ECHO);
    tcsetattr(0, TCSANOW, &tio2);
    /* flush any queued input */
    for (;;) {
        int avail = 0;
        if (ioctl(0, FIONREAD, &avail) < 0 || avail == 0) break;
        char j[64];
        if (read(0, j, sizeof(j)) <= 0) break;
    }
    /* The input queue is shared like a real tty: another blocked
       reader (e.g. rsh doing read(0,&c,1)) may consume bytes of the
       reply — most visibly the leading ESC. Accept the reply with or
       without it; retry a few exchanges for the same reason. */
    char rep[32];
    int rr = -1, cc = -1, ok = 0;
    for (int attempt = 0; attempt < 4 && !ok; attempt++) {
        say("\x1b[6n");
        memset(rep, 0, sizeof(rep));
        n = read(0, rep, sizeof(rep) - 1);
        char *e = rep;
        if (n > 0 && rep[0] == 0x1b) e++;
        if (*e == '[') e++;
        for (rr = 0; *e >= '0' && *e <= '9'; e++) rr = rr * 10 + *e - '0';
        if (*e == ';') {
            e++;
            for (cc = 0; *e >= '0' && *e <= '9'; e++) cc = cc * 10 + *e - '0';
        }
        ok = *e == 'R' && rr > 0 && cc > 0 && rr <= ws.ws_row && cc <= ws.ws_col;
    }
    check(ok, "DSR \\e[6n -> \\e[r;cR");
    ok = 0;
    for (int attempt = 0; attempt < 4 && !ok; attempt++) {
        say("\x1b[c");
        memset(rep, 0, sizeof(rep));
        n = read(0, rep, sizeof(rep) - 1);
        /* expect "\e[?1;2c", tolerating a stolen leading ESC */
        const char *want = "[?1;2c";
        int off = (n > 0 && rep[0] == 0x1b) ? 1 : 0;
        ok = n - off >= 6 && memcmp(rep + off, want, 6) == 0;
    }
    check(ok, "DA \\e[c -> \\e[?1;2c");
    tcsetattr(0, TCSANOW, &tio); /* restore */

    char buf[64];
    int m = snprintf(buf, sizeof(buf),
                     "termtest: %d failures, done\n", fails);
    (void)m;
    say(buf);
    return fails;
}
