// fxtest — futex FUTEX_WAIT/WAKE across a CLONE_VM share, plus the
// CHILD_CLEARTID exit hook: a ctid-registered child's death zeroes
// its tid word and futex-wakes it, which is exactly how glibc's
// pthread_join waits for thread death.
#define _GNU_SOURCE
#include <sched.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <errno.h>

#define FUTEX_WAIT 0
#define FUTEX_WAKE 1
#define FUTEX_PRIVATE 128
#define CLONE_CHILD_CLEARTID 0x00200000
#define CLONE_CHILD_SETTID 0x01000000

static int fails;
static void check(int ok, const char *what) {
    printf("  %-46s %s\n", what, ok ? "ok" : "FAIL");
    if (!ok) fails++;
}

static volatile int word;
static volatile int started;
static volatile int join_word;
static char st1[8192] __attribute__((aligned(16)));
static char st2[8192] __attribute__((aligned(16)));

static int fwait(void *a) {
    *(volatile int *)a = 1; // tell the parent I'm at the wait
    syscall(SYS_futex, (void *)&word, FUTEX_WAIT, 0, 0, 0, 0);
    return 5;
}

int main(void) {
    printf("fxtest: futex + ctid checks\n");

    // A CLONE_VM child blocks on the shared word; the parent stores
    // then wakes. (If the store lands before the child's wait, the
    // child takes the EAGAIN path — both routes must exit 5.)
    word = 0;
    started = 0;
    pid_t p = clone(fwait, st1 + sizeof(st1), CLONE_VM, (void *)&started);
    check(p > 0, "clone for futex waiter");
    while (!started) sched_yield();
    word = 1;
    long w = syscall(SYS_futex, (void *)&word, FUTEX_WAKE, 1, 0, 0, 0);
    check(w >= 0, "futex_wake returned a count");
    int st = 0;
    check(waitpid(p, &st, 0) == p && WEXITSTATUS(st) == 5,
          "waited child exited 5 after store+wake");

    // CHILD_CLEARTID join: SETTID lands the child's pid in join_word
    // at clone; on exit the kernel zeroes it and futex-wakes — the
    // pthread_join mechanism verbatim.
    join_word = 0;
    word = 0; // phase-2 child must BLOCK, not EAGAIN off phase-1's 1
    pid_t j = clone(fwait, st2 + sizeof(st2),
                    CLONE_VM | CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID,
                    (void *)&started, 0, 0, (void *)&join_word);
    check(j > 0 && join_word == (int)j, "SETTID wrote child pid");
    int tid = join_word;
    word = 1;
    syscall(SYS_futex, (void *)&word, FUTEX_WAKE, 1, 0, 0, 0);
    while (join_word == tid && tid != 0)
        syscall(SYS_futex, (void *)&join_word, FUTEX_WAIT, tid, 0, 0, 0);
    check(join_word == 0, "CLEARTID zeroed the tid word + woke us");
    st = 0;
    check(waitpid(j, &st, 0) == j && WEXITSTATUS(st) == 5,
          "joined child exited 5");

    // Honesty table: EAGAIN on value mismatch, ETIMEDOUT on a timed
    // wait, EFAULT on an unmapped word, ENOSYS on unknown ops,
    // WAKE on an untouched word returns 0.
    errno = 0;
    int wv = 7;
    check(syscall(SYS_futex, &wv, FUTEX_WAIT, 5, 0, 0, 0) == -1 &&
              errno == EAGAIN,
          "FUTEX_WAIT value mismatch -> EAGAIN");
    struct { long sec, nsec; } ts = { 0, 1000000 };
    errno = 0;
    check(syscall(SYS_futex, &wv, FUTEX_WAIT, 7, &ts, 0, 0) == -1 &&
              errno == ETIMEDOUT,
          "FUTEX_WAIT 1ms -> ETIMEDOUT");
    errno = 0;
    check(syscall(SYS_futex, (void *)0x1000, FUTEX_WAIT, 0, 0, 0, 0) == -1 &&
              errno == EFAULT,
          "FUTEX_WAIT bad uaddr -> EFAULT");
    errno = 0;
    check(syscall(SYS_futex, &wv, 6 /*FUTEX_REQUEUE*/, 0, 0, 0, 0) == -1 &&
              errno == ENOSYS,
          "unknown futex op -> ENOSYS");
    check(syscall(SYS_futex, &wv, FUTEX_WAKE, 1, 0, 0, 0) == 0,
          "FUTEX_WAKE on empty word -> 0");
    errno = 0;
    check(syscall(SYS_futex, &wv, FUTEX_WAIT | FUTEX_PRIVATE, 5, 0, 0, 0) ==
                  -1 &&
              errno == EAGAIN,
          "FUTEX_WAIT|PRIVATE -> EAGAIN");

    printf("fxtest: %d failure%s, done\n", fails, fails == 1 ? "" : "s");
    return fails;
}
