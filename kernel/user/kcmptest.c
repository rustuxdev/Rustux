// kcmptest — kcmp(312) kernel-object identity comparisons.
// FILE ordering via OFD slots; VM/FILES/FS/SIGHAND via table-index
// identity; IO always equal; SYSVSEM via pid-keyed undo. check()
// convention; exit = failures.
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sched.h>
#include <sys/wait.h>
#include <sys/syscall.h>

static int fails;
#define check(c, msg) do { \
    if (c) printf("kcmptest: %-44s ok\n", msg); \
    else { printf("kcmptest: %-44s FAIL\n", msg); fails++; } \
} while (0)

#define NR_KCMP 312
#define KCMP_FILE    0
#define KCMP_VM      1
#define KCMP_FILES   2
#define KCMP_FS      3
#define KCMP_SIGHAND 4
#define KCMP_IO      5
#define KCMP_SYSVSEM 6

static long kcmp2(pid_t a, pid_t b, int t, unsigned long i1,
                  unsigned long i2) {
    return syscall(NR_KCMP, a, b, t, i1, i2);
}

static volatile int thr_hold;
static int thr_entry(void *p) {
    (void)p;
    while (!thr_hold) usleep(1000);
    return 0; /* glibc clone() exits the child with this status */
}

int main(void) {
    pid_t self = getpid();

    // ---- self comparisons ----
    check(kcmp2(self, self, KCMP_FILE, 0, 0) == 0,
          "FILE self/self == 0");
    int f0 = open("/dev/null", O_RDONLY);
    int f1 = open("/dev/null", O_RDONLY);
    int dd = dup(f0);
    check(f0 >= 0 && f1 >= 0 && dd >= 0, "fd scaffold");
    check(kcmp2(self, self, KCMP_FILE, f0, f0) == 0,
          "same fd == 0");
    check(kcmp2(self, self, KCMP_FILE, f0, dd) == 0,
          "dup shares OFD -> 0");
    check(kcmp2(self, self, KCMP_FILE, f0, f1) != 0,
          "distinct opens -> nonzero order");
    errno = 0;
    int emp = open("/dev/null", O_RDONLY);
    close(emp);
    check(kcmp2(self, self, KCMP_FILE, emp, f0) == -1
          && errno == EBADF, "empty fd EBADF");
    errno = 0;
    check(kcmp2(self, self, KCMP_FILE, f0, 99) == -1
          && errno == EBADF, "idx >= MAX_FDS EBADF");
    close(dd); close(f1); close(f0);

    check(kcmp2(self, self, KCMP_VM, 0, 0) == 0, "VM self == 0");
    check(kcmp2(self, self, KCMP_FILES, 0, 0) == 0,
          "FILES self == 0");
    check(kcmp2(self, self, KCMP_FS, 0, 0) == 0, "FS self == 0");
    check(kcmp2(self, self, KCMP_SIGHAND, 0, 0) == 0,
          "SIGHAND self == 0");
    check(kcmp2(self, self, KCMP_IO, 0, 0) == 0,
          "IO NULL==NULL -> 0");
    check(kcmp2(self, self, KCMP_SYSVSEM, 0, 0) == 0,
          "SYSVSEM self == 0");

    // ---- error gates ----
    errno = 0;
    check(kcmp2(self, self, 7, 0, 0) == -1 && errno == EINVAL,
          "type > 6 EINVAL");
    errno = 0;
    check(kcmp2(99999, self, KCMP_VM, 0, 0) == -1 && errno == ESRCH,
          "dead pid1 ESRCH");
    errno = 0;
    check(kcmp2(self, 99998, KCMP_VM, 0, 0) == -1 && errno == ESRCH,
          "dead pid2 ESRCH");

    // ---- fork: separate tables, inherited OFDs ----
    int gate[2];
    check(pipe(gate) == 0, "pipe gate");
    pid_t c = fork();
    if (c == 0) {
        char b;
        close(gate[1]); /* drop my writer copy -> parent EOF works */
        if (read(gate[0], &b, 1) < 0) _exit(3); /* gate blocks */
        _exit(0);
    }
    check(c > 0, "fork child");
    usleep(20000);
    check(kcmp2(self, c, KCMP_VM, 0, 0) != 0,
          "fork: VM differs");
    check(kcmp2(self, c, KCMP_FILES, 0, 0) != 0,
          "fork: FILES differs");
    check(kcmp2(self, c, KCMP_FS, 0, 0) != 0,
          "fork: FS differs");
    check(kcmp2(self, c, KCMP_SIGHAND, 0, 0) != 0,
          "fork: SIGHAND differs");
    check(kcmp2(self, c, KCMP_SYSVSEM, 0, 0) != 0,
          "fork: SYSVSEM (pid) differs");
    check(kcmp2(self, c, KCMP_FILE, 0, 0) == 0,
          "fork: inherited fd -> same OFD");
    close(gate[1]);
    int ws;
    waitpid(c, &ws, 0);
    close(gate[0]);

    // ---- EPERM: nonroot caller vs root target ----
    pid_t e = fork();
    if (e == 0) {
        if (setuid(1000) < 0) _exit(9);
        long r = kcmp2(getpid(), getppid(), KCMP_VM, 0, 0);
        _exit(r == -1 && errno == EPERM ? 0 : 7);
    }
    check(e > 0 && waitpid(e, &ws, 0) == e && WIFEXITED(ws)
          && WEXITSTATUS(ws) == 0,
          "uid-mismatch caller EPERM");

    // ---- clone(CLONE_VM|SIGHAND|FILES|FS): four tables shared ----
    char *stk = malloc(64 * 1024);
    check(stk != NULL, "clone stack");
    thr_hold = 0;
    pid_t th = clone(thr_entry, stk + 64 * 1024,
                     CLONE_VM | CLONE_SIGHAND | CLONE_FILES
                     | CLONE_FS | SIGCHLD, NULL);
    check(th > 0, "clone shared-table child");
    usleep(20000);
    check(kcmp2(self, th, KCMP_VM, 0, 0) == 0,
          "CLONE_VM -> pml4 shared");
    check(kcmp2(self, th, KCMP_FILES, 0, 0) == 0,
          "CLONE_FILES -> fdi shared");
    check(kcmp2(self, th, KCMP_FS, 0, 0) == 0,
          "CLONE_FS -> fsi shared");
    check(kcmp2(self, th, KCMP_SIGHAND, 0, 0) == 0,
          "CLONE_SIGHAND -> sigh shared");
    check(kcmp2(self, th, KCMP_FILE, 0, 0) == 0,
          "shared table -> FILE 0");
    check(kcmp2(self, th, KCMP_SYSVSEM, 0, 0) != 0,
          "distinct pid -> undo differs");
    thr_hold = 1;
    waitpid(th, &ws, 0);
    free(stk);

    printf("kcmptest: %d failures\n", fails);
    return fails;
}
