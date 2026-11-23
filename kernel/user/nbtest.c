// nbtest — run-135 syscall coverage: pipe O_NONBLOCK semantics.
// pipe2 flags, empty-read EAGAIN, atomic-write EAGAIN, short writes
// past PIPE_BUF, F_GETFL/F_SETFL status-flag toggling, and the
// blocking wake path once nonblock is cleared. check() convention,
// exit = fails.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int fails;

static void say(const char *s) {
    if (write(1, s, strlen(s)) < 0) { /* ignore */ }
}

static void check(int ok, const char *what) {
    char buf[96];
    snprintf(buf, sizeof(buf), "nbtest: %-38s %s\n",
             what, ok ? "ok" : "FAIL");
    say(buf);
    if (!ok) fails++;
}

static void msleep(long ms) {
    struct timespec ts = { ms / 1000, (ms % 1000) * 1000000L };
    while (nanosleep(&ts, &ts) < 0 && errno == EINTR) {
    }
}

int main(void) {
    int fds[2];

    /* pipe2 accepts O_NONBLOCK now. */
    check(pipe2(fds, O_NONBLOCK | O_CLOEXEC) == 0,
          "pipe2(O_NONBLOCK|O_CLOEXEC)");
    int rfd = fds[0], wfd = fds[1];

    /* Bad flags still EINVAL. */
    errno = 0;
    check(pipe2(fds, 0x200) == -1 && errno == EINVAL,
          "pipe2 unknown flag -> EINVAL");

    /* F_GETFL reports O_NONBLOCK on both ends. */
    check((fcntl(rfd, F_GETFL) & O_NONBLOCK) != 0,
          "F_GETFL rfd has NONBLOCK");
    check((fcntl(wfd, F_GETFL) & O_NONBLOCK) != 0,
          "F_GETFL wfd has NONBLOCK");

    /* Empty nonblocking read: EAGAIN, not a sleep. */
    char c;
    errno = 0;
    check(read(rfd, &c, 1) == -1 && errno == EAGAIN,
          "empty nonblock read -> EAGAIN");

    /* A byte written is still readable. */
    check(write(wfd, "x", 1) == 1, "write 1 byte");
    check(read(rfd, &c, 1) == 1 && c == 'x', "read it back");

    /* Fill the ring (4096): the next <=PIPE_BUF write must fail
     * atomically with EAGAIN. */
    static char big[8192];
    memset(big, 'A', sizeof(big));
    ssize_t n = write(wfd, big, 4096);
    check(n == 4096, "write fills ring");
    errno = 0;
    check(write(wfd, big, 1) == -1 && errno == EAGAIN,
          "full nonblock write -> EAGAIN");

    /* Free one byte: a 100-byte write still can't fit atomically. */
    char tmp[128];
    check(read(rfd, tmp, 1) == 1, "drain 1 byte");
    errno = 0;
    check(write(wfd, big, 100) == -1 && errno == EAGAIN,
          "oversize write still EAGAIN (atomic)");

    /* Free 101 bytes: a >PIPE_BUF write takes what fits — short
     * count, not EAGAIN, not a block. */
    check(read(rfd, tmp, 100) == 100, "drain 100 bytes");
    n = write(wfd, big, 5000);
    check(n == 101, ">PIPE_BUF nonblock write -> short count");

    /* Drain everything. */
    while (read(rfd, tmp, sizeof(tmp)) > 0) {
    }

    /* F_SETFL toggles the OFD flag: clearing NONBLOCK makes the
     * empty read block until a writer arrives (child proves it);
     * re-setting restores EAGAIN. */
    check(fcntl(rfd, F_SETFL, fcntl(rfd, F_GETFL) & ~O_NONBLOCK) == 0,
          "F_SETFL clear NONBLOCK");
    check((fcntl(rfd, F_GETFL) & O_NONBLOCK) == 0,
          "F_GETFL reports clear");
    pid_t kid = fork();
    if (kid == 0) {
        msleep(300); // parent must actually sleep on the read
        _exit(write(wfd, "z", 1) == 1 ? 0 : 7);
    }
    n = read(rfd, &c, 1);
    int st;
    waitpid(kid, &st, 0);
    check(n == 1 && c == 'z', "blocking read wakes on write");
    check(WIFEXITED(st) && WEXITSTATUS(st) == 0, "writer child ok");
    check(fcntl(rfd, F_SETFL, fcntl(rfd, F_GETFL) | O_NONBLOCK) == 0,
          "F_SETFL set NONBLOCK");
    errno = 0;
    check(read(rfd, &c, 1) == -1 && errno == EAGAIN,
          "nonblock read -> EAGAIN again");

    /* Classic pipe() is unaffected: blocking ends (verify flags). */
    check(pipe(fds) == 0, "plain pipe()");
    check((fcntl(fds[0], F_GETFL) & O_NONBLOCK) == 0,
          "plain pipe ends blocking");
    close(fds[0]); close(fds[1]);
    close(rfd); close(wfd);

    char buf[64];
    snprintf(buf, sizeof(buf), "nbtest: %d failures\n", fails);
    say(buf);
    return fails;
}
