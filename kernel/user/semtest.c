// semtest — SysV semaphores (semget 64 / semop 65 / semctl 66 /
// semtimedop 220). Atomic multi-op arrays ride the WaitOn
// machinery; ids are gen<<16|slot like SHM/MSG.
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include <signal.h>
#include <time.h>

static int fails;
static void on_usr1(int s) { (void)s; }
#define check(c, msg) do { \
    if (c) printf("semtest: %-44s ok\n", msg); \
    else { printf("semtest: %-44s FAIL\n", msg); fails++; } \
} while (0)

union semun {
    int val;
    struct semid_ds *buf;
    unsigned short *array;
};

static void die(int s) { _exit(s); }

int main(void) {
    printf("semtest: sysv semaphores\n");

    // The suite can run several semtest instances concurrently —
    // a pid-derived key keeps each instance's sets private.
    key_t k = 0x23456 + getpid() * 16;

    // --- semget
    errno = 0;
    check(semget(k, 1, 0) == -1 && errno == ENOENT, "semget missing ENOENT");
    int s = semget(k, 2, IPC_CREAT | 0600);
    check(s >= 0, "semget create nsems=2");
    errno = 0;
    check(semget(k, 3, 0) == -1 && errno == EINVAL,
          "semget nsems>set EINVAL");
    errno = 0;
    check(semget(k, 1, IPC_CREAT | IPC_EXCL) == -1 && errno == EEXIST,
          "semget EXCL EEXIST");
    errno = 0;
    check(semget(k + 1, 33, IPC_CREAT) == -1 && errno == EINVAL,
          "semget nsems>SEMMSL EINVAL");
    int sp = semget(IPC_PRIVATE, 1, 0600);
    check(sp >= 0, "semget PRIVATE mints");

    // --- semctl SETVAL/GETVAL/GETALL/SETALL/STAT
    union semun u;
    u.val = 5;
    check(semctl(s, 0, SETVAL, u) == 0, "SETVAL 5");
    check(semctl(s, 0, GETVAL, u) == 5, "GETVAL reads 5");
    errno = 0;
    check(semctl(s, 0, SETVAL, (union semun){ .val = 40000 }) == -1
          && errno == ERANGE, "SETVAL>SEMVMX ERANGE");
    unsigned short arr[2] = {3, 7};
    u.array = arr;
    check(semctl(s, 0, SETALL, u) == 0, "SETALL {3,7}");
    memset(arr, 0, sizeof arr);
    check(semctl(s, 0, GETALL, u) == 0 && arr[0] == 3 && arr[1] == 7,
          "GETALL {3,7}");
    unsigned short over[2] = {1, 40000};
    u.array = over;
    errno = 0;
    check(semctl(s, 0, SETALL, u) == -1 && errno == ERANGE,
          "SETALL over ERANGE");
    struct semid_ds ds;
    memset(&ds, 0, sizeof ds);
    u.buf = &ds;
    check(semctl(s, 0, IPC_STAT, u) == 0 && ds.sem_nsems == 2,
          "IPC_STAT nsems=2");
    errno = 0;
    check(semctl(s, 5, GETVAL, u) == -1 && errno == EINVAL,
          "GETVAL bad num EINVAL");

    // --- semop atomic ops
    struct sembuf op;
    op.sem_num = 0; op.sem_op = 1; op.sem_flg = 0;
    check(semop(s, &op, 1) == 0 && semctl(s, 0, GETVAL, u) == 4,
          "semop +1 -> 4");
    op.sem_op = -2;
    check(semop(s, &op, 1) == 0 && semctl(s, 0, GETVAL, u) == 2,
          "semop -2 -> 2");
    op.sem_op = -3; op.sem_flg = IPC_NOWAIT;
    errno = 0;
    check(semop(s, &op, 1) == -1 && errno == EAGAIN,
          "semop -3 NOWAIT EAGAIN");
    // multi-op atomicity: {-1 on sem0, -8 on sem1} can't go (sem1=7)
    // — nothing may land.
    struct sembuf pair[2] = {
        {0, -1, IPC_NOWAIT}, {1, -8, IPC_NOWAIT}
    };
    errno = 0;
    check(semop(s, pair, 2) == -1 && errno == EAGAIN
          && semctl(s, 0, GETVAL, u) == 2 && semctl(s, 1, GETVAL, u) == 7,
          "multi-op atomic (nothing landed)");
    // a satisfiable array lands both ops in one call -> {1, 0}
    pair[1].sem_op = -7;
    pair[0].sem_flg = pair[1].sem_flg = 0;
    check(semop(s, pair, 2) == 0 && semctl(s, 0, GETVAL, u) == 1
          && semctl(s, 1, GETVAL, u) == 0, "multi-op lands both");
    // restore sem0 to 2 for the zero/undo tests below
    op.sem_num = 0; op.sem_op = +1; op.sem_flg = 0;
    check(semop(s, &op, 1) == 0 && semctl(s, 0, GETVAL, u) == 2,
          "semop +1 restores 2");
    // wait-for-zero op on sem1 (now 0) passes immediately
    op.sem_num = 1; op.sem_op = 0; op.sem_flg = IPC_NOWAIT;
    check(semop(s, &op, 1) == 0, "wait-for-zero on 0 passes");
    op.sem_num = 0; op.sem_op = 0;
    errno = 0;
    check(semop(s, &op, 1) == -1 && errno == EAGAIN,
          "wait-for-zero on 2 EAGAIN");
    // EFBIG/EINVAL/ERANGE ladders
    op.sem_num = 9; op.sem_op = 1;
    errno = 0;
    check(semop(s, &op, 1) == -1 && errno == EFBIG, "semop bad num EFBIG");
    op.sem_num = 0; op.sem_flg = 0x40;
    errno = 0;
    check(semop(s, &op, 1) == -1 && errno == EINVAL, "semop bad flg EINVAL");
    op.sem_flg = 0; op.sem_op = 32766;
    errno = 0;
    check(semop(s, &op, 1) == -1 && errno == ERANGE,
          "semop overflow ERANGE");
    errno = 0;
    check(semop(s, &op, 0) == -1 && errno == EINVAL, "nsops=0 EINVAL");

    // --- blocking proof: child waits -1 on val 0, parent +1 wakes.
    // GETNCNT doubles as the arm-proof: poll until the child's
    // staged -1 registers before adding the val.
    int pfd[2];
    check(pipe(pfd) == 0, "pipe for sync");
    int sc = semget(IPC_PRIVATE, 1, 0600);
    check(sc >= 0, "semget for block test");
    pid_t c = fork();
    if (c == 0) {
        close(pfd[0]);
        struct sembuf w = {0, -1, 0};
        die(semop(sc, &w, 1) == 0 ? 0 : 10);
    }
    for (int i = 0; i < 500 && semctl(sc, 0, GETNCNT, u) != 1; i++)
        usleep(1000);
    check(semctl(sc, 0, GETNCNT, u) == 1, "GETNCNT sees blocked -1");
    struct sembuf up = {0, +1, 0};
    check(semop(sc, &up, 1) == 0, "parent +1 wakes blocked -1");
    int st;
    check(c > 0, "fork blocker");
    check(waitpid(c, &st, 0) == c && WIFEXITED(st) && WEXITSTATUS(st) == 0,
          "blocked -1 completed after +1");
    check(semctl(sc, 0, GETVAL, u) == 0, "val back to 0 after -1");

    // --- wait-for-zero wake: child sets 3, signals via pipe, then
    // waits sem==0; GETZCNT proves the arm before SETVAL 0.
    c = fork();
    if (c == 0) {
        union semun zu; zu.val = 3;
        semctl(sc, 0, SETVAL, zu);
        if (write(pfd[1], "z", 1) != 1) die(14);
        struct sembuf w = {0, 0, 0};
        die(semop(sc, &w, 1) == 0 ? 0 : 11);
    }
    char zb;
    check(read(pfd[0], &zb, 1) == 1, "zwait child armed SETVAL");
    for (int i = 0; i < 500 && semctl(sc, 0, GETZCNT, u) != 1; i++)
        usleep(1000);
    check(semctl(sc, 0, GETZCNT, u) == 1, "GETZCNT sees blocked 0-wait");
    union semun zu; zu.val = 0;
    check(semctl(sc, 0, SETVAL, zu) == 0, "parent SETVAL 0");
    check(c > 0, "fork zwait");
    check(waitpid(c, &st, 0) == c && WIFEXITED(st) && WEXITSTATUS(st) == 0,
          "wait-for-zero completed");

    // --- SEM_UNDO: child takes -2 with UNDO then exits -> restored
    zu.val = 2;
    semctl(sc, 0, SETVAL, zu);
    c = fork();
    if (c == 0) {
        struct sembuf w = {0, -2, SEM_UNDO};
        die(semop(sc, &w, 1) == 0 ? 0 : 12);
    }
    check(c > 0, "fork undo child");
    check(waitpid(c, &st, 0) == c && WEXITSTATUS(st) == 0, "undo child ran");
    check(semctl(sc, 0, GETVAL, u) == 2, "SEM_UNDO restored on exit");

    // --- semtimedop EAGAIN on a dead wait (val 0 makes -1 block;
    //     Linux answers EAGAIN, never ETIME)
    zu.val = 0;
    semctl(sc, 0, SETVAL, zu);
    struct sembuf w = {0, -1, 0};
    struct timespec ts = {0, 20 * 1000 * 1000}; // 20ms
    errno = 0;
    check(semtimedop(sc, &w, 1, &ts) == -1 && errno == EAGAIN,
          "semtimedop 20ms EAGAIN");
    // NULL timeout is plain semop — lands, val 0 -> 1
    w.sem_op = +1;
    check(semtimedop(sc, &w, 1, NULL) == 0 && semctl(sc, 0, GETVAL, u) == 1,
          "semtimedop NULL == semop");
    w.sem_op = -1;

    // --- EIDRM: blocked waiter dies with the queue
    int srd = semget(IPC_PRIVATE, 1, 0600);
    check(srd >= 0, "semget for rmid test");
    c = fork();
    if (c == 0) {
        struct sembuf wb = {0, -1, 0};
        errno = 0;
        die(semop(srd, &wb, 1) == -1 && errno == EIDRM ? 0 : 13);
    }
    for (int i = 0; i < 500 && semctl(srd, 0, GETNCNT, u) != 1; i++)
        usleep(1000);
    check(semctl(srd, 0, GETNCNT, u) == 1, "GETNCNT before RMID");
    check(semctl(srd, 0, IPC_RMID, u) == 0, "IPC_RMID");
    check(c > 0, "fork rmid waiter");
    check(waitpid(c, &st, 0) == c && WEXITSTATUS(st) == 0,
          "RMID woke waiter with EIDRM");
    errno = 0;
    check(semop(srd, &w, 1) == -1 && errno == EINVAL,
          "stale id EINVAL after RMID");

    // --- SA_RESTART semtimedop is never restarted: SysV IPC is
    // in Linux's never-restart set (signal(7)) — an interrupted
    // wait surfaces EINTR immediately even under SA_RESTART
    // (host-verified: EINTR at ~400ms, no replay).
    {
        int sr = semget(IPC_PRIVATE, 1, 0600);
        check(sr >= 0, "restart sem mint");
        struct sigaction rsa = {0};
        rsa.sa_handler = on_usr1;
        rsa.sa_flags = SA_RESTART;
        sigaction(SIGUSR1, &rsa, NULL);
        pid_t fk = fork();
        if (fk == 0) {
            struct sembuf d = { 0, -1, 0 };
            struct timespec pre, post, tmo = { 2, 0 };
            clock_gettime(CLOCK_MONOTONIC, &pre);
            errno = 0;
            long r = syscall(SYS_semtimedop, sr, &d, 1, &tmo);
            int e = errno;
            clock_gettime(CLOCK_MONOTONIC, &post);
            double ms = (post.tv_sec - pre.tv_sec) * 1000.0 +
                        (post.tv_nsec - pre.tv_nsec) / 1e6;
            /* Never-restart EINTR ~400ms; a restart would land
               ~2s (EAGAIN). */
            _exit(r < 0 && e == EINTR && ms < 1500 ? 0 : 1);
        }
        struct timespec nap = { 0, 400000000 };
        nanosleep(&nap, NULL);
        kill(fk, SIGUSR1);
        int fst = 0;
        check(waitpid(fk, &fst, 0) == fk && WIFEXITED(fst) &&
              WEXITSTATUS(fst) == 0,
              "SA_RESTART semtimedop EINTRs (never restarted)");
        semctl(sr, 0, IPC_RMID, u);
    }

    // --- cleanup (persistent objects, like SysV semantics)
    semctl(s, 0, IPC_RMID, u);
    semctl(sp, 0, IPC_RMID, u);
    semctl(sc, 0, IPC_RMID, u);
    close(pfd[0]); close(pfd[1]);

    printf("semtest: %d failures, done\n", fails);
    return fails;
}
