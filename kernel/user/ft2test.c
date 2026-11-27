// ft2test — compiled futex2 ops (454/455/456) + membarrier(324)
// ABI proof. futex_wait shares FUTEX_WAIT's compare-then-block but
// takes an absolute clockid deadline; futex_wake rides the keyed
// scan; futex_requeue wakes nr_wake then moves nr_requeue sleepers
// src->dst atomically. membarrier QUERY reports the supported set,
// everything else is accepted-noop on a uniprocessor.
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sched.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <signal.h>

static int fails;
#define check(c, msg) do { \
    if (c) printf("ft2test: %-34s ok\n", msg); \
    else { printf("ft2test: %-34s FAIL\n", msg); fails++; } \
} while (0)

#ifndef SYS_futex_waitv
#define SYS_futex_waitv  449
#endif
#define SYS_futex_wake    454
#define SYS_futex_wait    455
#define SYS_futex_requeue 456
#define SYS_membarrier    324
#ifndef SYS_futex
#define SYS_futex         202
#endif
#define FUTEX_32   2
#define MBR_QUERY  0
#define MBR_GLOBAL 1
#define MBR_PRVEXP 8

struct fwv { uint64_t val, uaddr; uint32_t flags, res; };

static volatile unsigned int wa, wb;
static char st1[8192] __attribute__((aligned(16)));
static char st2[8192] __attribute__((aligned(16)));
static volatile int armed_a, armed_b, done_a, done_b;
static volatile long waitret_a;

static void on_usr1(int s) { (void)s; }

static int sleeper_a(void *x) {
    (void)x;
    armed_a = 1;
    syscall(SYS_futex_wait, (void *)&wa, 0u, ~0u, FUTEX_32, 0, 1);
    done_a = 1;
    return 0;
}
static int sleeper_b(void *x) {
    (void)x;
    armed_b = 1;
    waitret_a = syscall(SYS_futex_wait, (void *)&wa, 0u, ~0u,
                        FUTEX_32, 0, 1);
    done_b = 1;
    return 0;
}

static void wait_armed(volatile int *a) {
    for (int i = 0; i < 500 && !*a; i++) usleep(20000);
    usleep(200000); // let it get inside the futex_wait syscall
}

int main(void) {
    printf("ft2test: futex2 ops + membarrier checks\n");
    wa = 0; wb = 0;

    // ---- futex_wake(454) gates ----
    errno = 0;
    check(syscall(SYS_futex_wake, (void *)&wa, ~0u, 1, 0) < 0
          && errno == EINVAL, "wake bad flags EINVAL");
    errno = 0;
    check(syscall(SYS_futex_wake, (void *)&wa, ~0u, 1, 3) < 0
          && errno == EINVAL, "wake size!=U32 EINVAL");
    check(syscall(SYS_futex_wake, (void *)&wa, ~0u, 0, FUTEX_32) == 0,
          "wake nr=0 -> 0 woken");

    // ---- futex_wait(455) gates ----
    errno = 0;
    check(syscall(SYS_futex_wait, (void *)&wa, 0u, ~0u, 0, 0, 1) < 0
          && errno == EINVAL, "wait bad flags EINVAL");
    errno = 0;
    check(syscall(SYS_futex_wait, (void *)&wa, 0u, ~0u, FUTEX_32, 0, 9)
          < 0 && errno == EINVAL, "wait bad clockid EINVAL");
    errno = 0;
    check(syscall(SYS_futex_wait, (void *)1, 0u, ~0u, FUTEX_32, 0, 1)
          < 0 && errno == EFAULT, "wait uaddr EFAULT");
    wa = 5;
    errno = 0;
    check(syscall(SYS_futex_wait, (void *)&wa, 0u, ~0u, FUTEX_32, 0, 1)
          < 0 && errno == EAGAIN, "wait val mismatch EAGAIN");
    wa = 0;
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts); // deadline in the past
    errno = 0;
    check(syscall(SYS_futex_wait, (void *)&wa, 0u, ~0u, FUTEX_32,
                  &ts, 1) < 0 && errno == ETIMEDOUT,
          "wait past deadline ETIMEDOUT");
    /* epoch-past REALTIME abstime: deterministic ETIMEDOUT under any
       suite-written wall — a forward arm legitimately slides on a
       concurrent writer's backward jump (Linux's realtime rebase). */
    ts.tv_sec = 1;
    ts.tv_nsec = 0;
    errno = 0;
    check(syscall(SYS_futex_wait, (void *)&wa, 0u, ~0u, FUTEX_32,
                  &ts, 0) < 0 && errno == ETIMEDOUT,
          "wait REALTIME deadline ETIMEDOUT");

    // ---- futex_wait wake path (454 wakes it) ----
    armed_a = 0; done_a = 0; waitret_a = -1;
    long t1 = clone(sleeper_a, st1 + sizeof(st1),
                    CLONE_VM | CLONE_SIGHAND | CLONE_THREAD, 0,0,0,0);
    check(t1 > 0, "clone sleeper A");
    wait_armed(&armed_a);
    long wk = -1;
    for (int i = 0; i < 20 && wk != 1; i++) {
        errno = 0;
        wk = syscall(SYS_futex_wake, (void *)&wa, ~0u, 1, FUTEX_32);
        if (wk != 1) usleep(100000);
    }
    if (wk != 1) printf("ft2test: wake ret=%ld errno=%d\n", wk, errno);
    check(wk == 1, "futex2 wake -> 1 woken");
    for (int i = 0; i < 50 && !done_a; i++) usleep(20000);
    if (!done_a) printf("ft2test: sleeper waitret=%ld\n", waitret_a);
    check(done_a == 1, "sleeper woke via futex_wake");

    // ---- futex_requeue(456) gates ----
    struct fwv rq[2] = {
        { .val = 0, .uaddr = (uint64_t)&wa, .flags = FUTEX_32 },
        { .val = 0, .uaddr = (uint64_t)&wb, .flags = FUTEX_32 },
    };
    errno = 0;
    check(syscall(SYS_futex_requeue, 0, 0, 1, 1) < 0 && errno == EINVAL,
          "requeue NULL waiters EINVAL");
    errno = 0;
    check(syscall(SYS_futex_requeue, rq, 1, 1, 1) < 0 && errno == EINVAL,
          "requeue flags EINVAL");
    rq[1].res = 1;
    errno = 0;
    check(syscall(SYS_futex_requeue, rq, 0, 1, 1) < 0 && errno == EINVAL,
          "requeue reserved EINVAL");
    rq[1].res = 0;
    rq[0].uaddr = 1;
    errno = 0;
    check(syscall(SYS_futex_requeue, rq, 0, 1, 1) < 0 && errno == EFAULT,
          "requeue bad src EFAULT");
    rq[0].uaddr = (uint64_t)&wa;
    rq[0].val = 9; // *wa is 0 -> cmpval mismatch
    errno = 0;
    check(syscall(SYS_futex_requeue, rq, 0, 1, 1) < 0 && errno == EAGAIN,
          "requeue cmpval EAGAIN");
    rq[0].val = 0;
    rq[1].flags = FUTEX_32 | 128; // mixed privacy -> EINVAL (31554)
    errno = 0;
    check(syscall(SYS_futex_requeue, rq, 0, 1, 1) < 0 && errno == EINVAL,
          "requeue mixed flags EINVAL");
    rq[1].flags = FUTEX_32;
    rq[1].uaddr = (uint64_t)&wa; // src == dst -> EINVAL (3153)
    errno = 0;
    check(syscall(SYS_futex_requeue, rq, 0, 1, 1) < 0 && errno == EINVAL,
          "requeue src==dst EINVAL");
    rq[1].uaddr = (uint64_t)&wb;

    // ---- requeue wake+move: sleeper on A gets moved to B ----
    armed_b = 0; done_b = 0; waitret_a = -1;
    t1 = clone(sleeper_b, st2 + sizeof(st2),
               CLONE_VM | CLONE_SIGHAND | CLONE_THREAD, 0,0,0,0);
    check(t1 > 0, "clone requeue sleeper");
    wait_armed(&armed_b);
    check(syscall(SYS_futex_requeue, rq, 0, 0, 1) == 1,
          "requeue moves 1 sleeper A->B");
    // The sleeper now waits on wb: waking wa must NOT free it.
    check(syscall(SYS_futex_wake, (void *)&wa, ~0u, 1, FUTEX_32) == 0,
          "moved sleeper not on A");
    check(syscall(SYS_futex_wake, (void *)&wb, ~0u, 1, FUTEX_32) == 1,
          "moved sleeper wakes on B");
    for (int i = 0; i < 50 && !done_b; i++) usleep(20000);
    check(done_b == 1, "requeued sleeper woke via B");

    // ---- classic futex WAIT_BITSET absolute timeout (202) ----
    // BITSET's timespec is ABSOLUTE (MONOTONIC by default —
    // CLOCK_REALTIME only with flag 0x100), unlike plain WAIT's
    // relative one. A past instant must return ETIMEDOUT at once.
    #define FB_WAIT_BITSET 9
    #define FB_CLK_RT 256
    clock_gettime(CLOCK_MONOTONIC, &ts);
    ts.tv_sec -= 5; // absolute deadline in the past -> no sleep
    errno = 0;
    check(syscall(SYS_futex, (void *)&wb, 9u, 0, &ts, 0, ~0u) < 0
          && errno == ETIMEDOUT, "BITSET abs mono past ETIMEDOUT");
    // a REALTIME epoch deadline needs FUTEX_CLOCK_REALTIME —
    // without it the epoch reads as boot-time (still valid abs:
    // epoch >> uptime, so it just blocks; use past-instant here)
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec -= 5; // epoch in the past -> immediate ETIMEDOUT
    errno = 0;
    check(syscall(SYS_futex, (void *)&wb, 9u | FB_CLK_RT, 0, &ts,
                  0, ~0u) < 0 && errno == ETIMEDOUT,
          "BITSET RT past ETIMEDOUT");
    // Sanity fork: same {5s,0} timespec is ~5s RELATIVE under plain
    // WAIT but 5-seconds-after-boot ABSOLUTE under BITSET (past ->
    // ETIMEDOUT). Boot is >5s old by the time ft2test runs.
    struct timespec tiny = { 5, 0 };
    errno = 0;
    check(syscall(SYS_futex, (void *)&wb, 9u, 0, &tiny, 0, ~0u) < 0
          && errno == ETIMEDOUT, "BITSET {5s} abs past ETIMEDOUT");

    // ---- TIMED futex_wait is never-restart (run-352 correction) --
    // A TIMED FUTEX_WAIT arms -ERESTART_RESTARTBLOCK: an SA_RESTART
    // handler still surfaces EINTR at the interrupt — the restart
    // block only serves the no-handler stop/cont resume
    // (host-verified: EINTR ~400ms). Untimed waits and futex_waitv
    // are -ERESTARTSYS instead — restarted; checked below.
    {
        struct sigaction rsa = {0};
        rsa.sa_handler = on_usr1;
        rsa.sa_flags = SA_RESTART;
        sigaction(SIGUSR1, &rsa, NULL);

        pid_t fk = fork();
        if (fk == 0) {
            struct timespec pre, post, tmo = { 2, 0 };
            clock_gettime(CLOCK_MONOTONIC, &pre);
            errno = 0;
            long r = syscall(SYS_futex, (void *)&wa, 0u, 0u, &tmo,
                             0, 0);
            int e = errno;
            clock_gettime(CLOCK_MONOTONIC, &post);
            double ms = (post.tv_sec - pre.tv_sec) * 1000.0 +
                        (post.tv_nsec - pre.tv_nsec) / 1e6;
            /* EINTR ~400ms; a restart would land ~2s+. */
            _exit(r < 0 && e == EINTR && ms < 1500 ? 0 : 1);
        }
        struct timespec nap = { 0, 400000000 };
        nanosleep(&nap, NULL);
        kill(fk, SIGUSR1);
        int fst = 0;
        check(waitpid(fk, &fst, 0) == fk && WIFEXITED(fst) &&
              WEXITSTATUS(fst) == 0,
              "SA_RESTART futex_wait EINTRs (never restarted)");

        // run-352 audit correction (host-verified): the restart
        // classes split INSIDE futex — an UNTIMED futex_wait is
        // -ERESTARTSYS (SA_RESTART replays it; the wait survives
        // the signal), while futex_waitv is -ERESTARTSYS too and
        // also replays. Only a TIMED futex_wait is never-restart.
        // A child can't be futex-woken across fork (private queues
        // are mm-keyed), so the restart proof is negative: EINTR'd
        // -> exit(3) ~400ms; restarted -> still blocked at ~900ms.
        fk = fork();
        if (fk == 0) {
            errno = 0;
            long r = syscall(SYS_futex, (void *)&wa, 0u, 0u,
                             NULL, 0, 0);
            _exit(r < 0 && errno == EINTR ? 3 : 4);
        }
        nanosleep(&nap, NULL);
        kill(fk, SIGUSR1);
        { struct timespec d2 = { 0, 500000000 }; nanosleep(&d2, NULL); }
        fst = 0;
        int still = (waitpid(fk, &fst, WNOHANG) == 0);
        if (still) { kill(fk, SIGKILL); waitpid(fk, &fst, 0); }
        check(still,
              "SA_RESTART untimed futex_wait restarts (blocks past signal)");

        fk = fork();
        if (fk == 0) {
            struct fwv wv =
                { .val = 0, .uaddr = (uint64_t)&wa,
                  .flags = FUTEX_32, .res = 0 };
            struct timespec pre2, at;
            clock_gettime(CLOCK_MONOTONIC, &pre2);
            at = pre2;
            at.tv_sec += 2;
            errno = 0;
            long r = syscall(SYS_futex_waitv, &wv, 1, 0, &at, 1);
            _exit(r < 0 && errno == EINTR ? 3 : 4);
        }
        nanosleep(&nap, NULL);
        kill(fk, SIGUSR1);
        { struct timespec d2 = { 0, 500000000 }; nanosleep(&d2, NULL); }
        fst = 0;
        still = (waitpid(fk, &fst, WNOHANG) == 0);
        if (still) { kill(fk, SIGKILL); waitpid(fk, &fst, 0); }
        check(still,
              "SA_RESTART futex_waitv restarts (blocks past signal)");

        // Without SA_RESTART the same interrupt is also EINTR —
        // the disposition doesn't change the outcome here.
        {
            struct sigaction dfl2 = {0};
            dfl2.sa_handler = on_usr1;
            dfl2.sa_flags = 0;
            sigaction(SIGUSR1, &dfl2, NULL);
        }
        fk = fork();
        if (fk == 0) {
            errno = 0;
            long r = syscall(SYS_futex, (void *)&wa, 0u, 0u, NULL,
                             0, 0);
            _exit(r < 0 && errno == EINTR ? 0 : 1);
        }
        nanosleep(&nap, NULL);
        kill(fk, SIGUSR1);
        fst = 0;
        check(waitpid(fk, &fst, 0) == fk && WIFEXITED(fst) &&
              WEXITSTATUS(fst) == 0,
              "futex_wait EINTR without SA_RESTART");
    }

    // ---- membarrier(324) ----
    long sup = syscall(SYS_membarrier, MBR_QUERY, 0, 0);
    check(sup > 0 && (sup & MBR_GLOBAL) && (sup & MBR_PRVEXP),
          "membarrier QUERY bitmask");
    check(syscall(SYS_membarrier, MBR_GLOBAL, 0, 0) == 0,
          "membarrier GLOBAL noop");
    errno = 0;
    check(syscall(SYS_membarrier, MBR_GLOBAL, 1, 0) < 0
          && errno == EINVAL, "membarrier flags EINVAL");
    errno = 0;
    check(syscall(SYS_membarrier, 0x8000, 0, 0) < 0
          && errno == ENOSYS, "membarrier unknown cmd ENOSYS");

    printf("ft2test: %d failure(s)\n", fails);
    return fails;
}
