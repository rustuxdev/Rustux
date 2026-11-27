// alarmtest — run-134 syscall coverage: alarm(2)/setitimer(2)/
// getitimer(2) interval timers. One-shot + periodic arming, leftover
// reporting, disarm, EINVAL/EFAULT edges, EINTR out of pause(), and
// fork non-inheritance. check() convention, exit = fails.
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int fails;
static volatile sig_atomic_t alrm_hits;
static volatile sig_atomic_t vtalrm_hits;

static void say(const char *s) {
    if (write(1, s, strlen(s)) < 0) { /* ignore */ }
}

static void check(int ok, const char *what) {
    char buf[96];
    snprintf(buf, sizeof(buf), "alarmtest: %-38s %s\n",
             what, ok ? "ok" : "FAIL");
    say(buf);
    if (!ok) fails++;
}

static void on_alrm(int sig) {
    (void)sig;
    alrm_hits++;
}

static void on_vtalrm(int sig) {
    (void)sig;
    vtalrm_hits++;
}

/* nanosleep for `ms` — the busy loop alternative would be
 * unbounded; a timer IRQ tick is 10ms so 30ms of slack is safe. */
static void msleep(long ms) {
    struct timespec ts = { ms / 1000, (ms % 1000) * 1000000L };
    while (nanosleep(&ts, &ts) < 0 && errno == EINTR) {
    }
}

int main(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_alrm;
    sigaction(SIGALRM, &sa, NULL);

    /* alarm(1) + pause: the signal interrupts the wait, handler
     * runs, pause returns EINTR. */
    errno = 0;
    alarm(1);
    int prc = pause();
    check(prc == -1 && errno == EINTR, "alarm(1) -> pause EINTR");
    check(alrm_hits == 1, "SIGALRM handler ran once");

    /* leftover: arm 2s then re-arm 1s — Linux reports the previous
     * remaining whole seconds (>=1 within a tick of arming). */
    unsigned left = alarm(2);
    check(left == 0, "alarm(2) prev-none -> 0");
    left = alarm(1);
    check(left >= 1 && left <= 2, "alarm re-arm reports leftover");

    /* alarm(0) disarms — sleep past the deadline, no hit. */
    alarm(0);
    int before = alrm_hits;
    msleep(1200);
    check(alrm_hits == before, "alarm(0) disarms (no SIGALRM)");

    /* Periodic setitimer: 50ms value + 50ms interval must hit
     * several times inside ~1s. */
    struct itimerval it = {{0, 50000}, {0, 50000}};
    check(setitimer(ITIMER_REAL, &it, NULL) == 0, "setitimer periodic");
    for (int i = 0; i < 100 && alrm_hits < before + 3; i++)
        msleep(10);
    check(alrm_hits >= before + 3, "interval fires repeatedly");

    /* old= on re-arm reports the live interval. */
    struct itimerval old;
    memset(&old, 0, sizeof(old));
    it.it_interval.tv_sec = 0; it.it_interval.tv_usec = 100000;
    it.it_value.tv_sec = 5; it.it_value.tv_usec = 0;
    check(setitimer(ITIMER_REAL, &it, &old) == 0, "setitimer old=");
    check(old.it_interval.tv_usec == 50000, "old reports interval");

    /* getitimer sees the armed one-shot value — 5s leaves slack for
     * a descheduled timeslice under suite round-robin. */
    struct itimerval cur;
    memset(&cur, 0, sizeof(cur));
    check(getitimer(ITIMER_REAL, &cur) == 0, "getitimer armed");
    check((cur.it_value.tv_sec > 0 || cur.it_value.tv_usec > 0) &&
          cur.it_value.tv_sec <= 5,
          "getitimer remaining 0<r<=5s");
    check(cur.it_interval.tv_usec == 100000, "getitimer interval");
    alarm(0); /* leave REAL disarmed for the rest */

    /* Error paths. */
    errno = 0;
    check(getitimer(3, &cur) == -1 && errno == EINVAL,
          "getitimer bad which -> EINVAL");
    errno = 0;
    check(getitimer(0, (void *)1) == -1 && errno == EFAULT,
          "getitimer bad ptr -> EFAULT");
    errno = 0;
    check(setitimer(3, &it, NULL) == -1 && errno == EINVAL,
          "setitimer bad which -> EINVAL");
    errno = 0;
    check(setitimer(0, (void *)1, NULL) == -1 && errno == EFAULT,
          "setitimer bad new -> EFAULT");
    struct itimerval bad = {{0, 0}, {0, 1000000}};
    errno = 0;
    check(setitimer(0, &bad, NULL) == -1 && errno == EINVAL,
          "usec>=1e6 -> EINVAL");
    bad.it_value.tv_usec = 0; bad.it_value.tv_sec = -1;
    errno = 0;
    check(setitimer(0, &bad, NULL) == -1 && errno == EINVAL,
          "negative tv_sec -> EINVAL");

    /* VIRTUAL: set/get roundtrip + a fired signal under pure user
     * burn. utime bills per tick so 30ms of burn is >=3 ticks. */
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_vtalrm;
    sigaction(SIGVTALRM, &sa, NULL);
    it.it_interval.tv_sec = 0; it.it_interval.tv_usec = 0;
    it.it_value.tv_sec = 0; it.it_value.tv_usec = 30000;
    check(setitimer(ITIMER_VIRTUAL, &it, NULL) == 0,
          "setitimer VIRTUAL");
    for (int i = 0; i < 60 && !vtalrm_hits; i++) {
        for (volatile long j = 0; j < 2000000; j++) { /* user burn */ }
        msleep(5);
    }
    check(vtalrm_hits >= 1, "SIGVTALRM fired on user burn");

    /* Fork does not inherit timers: parent arms REAL, child's
     * getitimer must read disarmed. */
    alarm(1);
    pid_t c = fork();
    if (c == 0) {
        struct itimerval kid;
        memset(&kid, 0xff, sizeof(kid));
        getitimer(ITIMER_REAL, &kid);
        _exit(kid.it_value.tv_sec == 0 && kid.it_value.tv_usec == 0
              ? 0 : 7);
    }
    int st;
    waitpid(c, &st, 0);
    check(WIFEXITED(st) && WEXITSTATUS(st) == 0,
          "fork does not inherit timer");
    alarm(0); /* consume nothing — parent's own alarm may hit */

    char buf[64];
    snprintf(buf, sizeof(buf), "alarmtest: %d failures\n", fails);
    say(buf);
    return fails;
}
