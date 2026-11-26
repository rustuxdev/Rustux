// ptmtest — POSIX per-process timers (timer_create 222 /
// timer_settime 223 / timer_gettime 224 / timer_getoverrun 225 /
// timer_delete 226). Expiry rides ptimer_expire -> pend_one.
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static int fails;
static volatile sig_atomic_t hits;

static void say(const char *s) {
    if (write(1, s, strlen(s)) < 0) { /* ignore */ }
}

static void check(int ok, const char *what) {
    char buf[96];
    snprintf(buf, sizeof(buf), "ptmtest: %-40s %s\n",
             what, ok ? "ok" : "FAIL");
    say(buf);
    if (!ok) fails++;
}

static void on_sig(int sig) { (void)sig; hits++; }

static void msleep(long ms) {
    struct timespec ts = { ms / 1000, (ms % 1000) * 1000000L };
    while (nanosleep(&ts, &ts) < 0 && errno == EINTR) {
    }
}

int main(void) {
    say("ptmtest: posix timers\n");
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_sig;
    sigaction(SIGALRM, &sa, NULL);
    sigaction(SIGUSR1, &sa, NULL);

    // --- create ladders
    timer_t tid;
    errno = 0;
    check(timer_create(9, NULL, &tid) == -1 && errno == EINVAL,
          "create bad clock EINVAL");
    struct sigevent se;
    memset(&se, 0, sizeof se);
    se.sigev_notify = 9;
    errno = 0;
    check(timer_create(CLOCK_REALTIME, &se, &tid) == -1
          && errno == EINVAL, "create bad notify EINVAL");
    se.sigev_notify = SIGEV_SIGNAL;
    se.sigev_signo = 0;
    errno = 0;
    check(timer_create(CLOCK_REALTIME, &se, &tid) == -1
          && errno == EINVAL, "create bad signo EINVAL");

    // --- default sevp -> SIGALRM one-shot
    hits = 0;
    check(timer_create(CLOCK_MONOTONIC, NULL, &tid) == 0,
          "create default -> SIGALRM");
    struct itimerspec it;
    memset(&it, 0, sizeof it);
    it.it_value.tv_nsec = 30 * 1000 * 1000; // 30ms
    check(timer_settime(tid, 0, &it, NULL) == 0, "arm 30ms one-shot");
    msleep(80);
    check(hits >= 1, "SIGALRM fired");

    // --- gettime on a longer arm reports sane remaining
    it.it_value.tv_sec = 5;
    it.it_value.tv_nsec = 0;
    check(timer_settime(tid, 0, &it, NULL) == 0, "arm 5s");
    struct itimerspec cur;
    memset(&cur, 0, sizeof cur);
    check(timer_gettime(tid, &cur) == 0
          && cur.it_value.tv_sec >= 3 && cur.it_value.tv_sec <= 5,
          "gettime remaining 3..5s");
    memset(&it, 0, sizeof it);
    check(timer_settime(tid, 0, &it, NULL) == 0, "disarm {0,0}");
    check(timer_gettime(tid, &cur) == 0 && cur.it_value.tv_sec == 0
          && cur.it_value.tv_nsec == 0, "gettime disarmed zero");
    check(timer_delete(tid) == 0, "delete");
    errno = 0;
    check(timer_settime(tid, 0, &it, NULL) == -1 && errno == EINVAL,
          "stale timerid EINVAL");

    // --- SIGEV_SIGNAL custom signo + interval rearm
    memset(&se, 0, sizeof se);
    se.sigev_notify = SIGEV_SIGNAL;
    se.sigev_signo = SIGUSR1;
    se.sigev_value.sival_int = 0x42;
    check(timer_create(CLOCK_REALTIME, &se, &tid) == 0,
          "create SIGEV_SIGNAL USR1");
    memset(&it, 0, sizeof it);
    it.it_interval.tv_nsec = 20 * 1000 * 1000; // 20ms
    it.it_value.tv_nsec = 20 * 1000 * 1000;
    hits = 0;
    check(timer_settime(tid, 0, &it, NULL) == 0, "arm 20ms interval");
    msleep(90);
    // Under suite load the task can sleep through several
    // expirations — Linux coalesces them into overrun while one
    // notification pends, so hits+overrun proves rearming.
    int over = timer_getoverrun(tid);
    if (hits + over < 2) {
        char db[48];
        snprintf(db, sizeof db, "ptmtest: hits=%d over=%d\n", hits, over);
        say(db);
    }
    check(hits >= 1 && hits + over >= 2, "interval rearms (hits+overrun)");
    // disarm stops the flow
    memset(&it, 0, sizeof it);
    check(timer_settime(tid, 0, &it, NULL) == 0, "interval disarm");
    int after = hits;
    msleep(60);
    check(hits == after, "no fires after disarm");

    // --- EINVAL ladders on settime
    it.it_value.tv_nsec = 1000000000L;
    errno = 0;
    check(timer_settime(tid, 0, &it, NULL) == -1 && errno == EINVAL,
          "settime nsec EINVAL");
    memset(&it, 0, sizeof it);
    errno = 0;
    check(timer_settime(tid, 8, &it, NULL) == -1 && errno == EINVAL,
          "settime bad flags EINVAL");

    // --- TIMER_ABSTIME: absolute = now+30ms fires
    struct timespec now;
    check(clock_gettime(CLOCK_MONOTONIC, &now) == 0, "clock_gettime");
    memset(&it, 0, sizeof it);
    it.it_value.tv_sec = now.tv_sec;
    it.it_value.tv_nsec = now.tv_nsec + 30 * 1000 * 1000;
    if (it.it_value.tv_nsec >= 1000000000L) {
        it.it_value.tv_sec++;
        it.it_value.tv_nsec -= 1000000000L;
    }
    hits = 0;
    check(timer_settime(tid, TIMER_ABSTIME, &it, NULL) == 0,
          "ABSTIME arm +30ms");
    msleep(90);
    check(hits >= 1, "ABSTIME fired");

    // --- overrun + delete
    check(timer_getoverrun(tid) == 0, "getoverrun 0");
    check(timer_delete(tid) == 0, "delete 2");
    errno = 0;
    check(timer_delete(tid) == -1 && errno == EINVAL,
          "double delete EINVAL");

    char buf[48];
    snprintf(buf, sizeof buf, "ptmtest: %d failures, done\n", fails);
    say(buf);
    return fails;
}
