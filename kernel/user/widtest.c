// widtest — waitid(247) ABI proof: siginfo reports (si_signo /
// si_code / si_pid / si_uid / si_status), the P_* idtype ladder
// incl. P_PIDFD, WNOHANG zero-report, WNOWAIT peek, blocked wakes
// on exit + stop + continue, EINTR. check() convention; exit = fails.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include <sys/wait.h>
#include <sys/syscall.h>

static int fails;
#define check(c, msg) do { \
    if (c) printf("widtest: %-44s ok\n", msg); \
    else { printf("widtest: %-44s FAIL\n", msg); fails++; } \
} while (0)

static void die(int s) { _exit(s); }
static volatile sig_atomic_t alarmed;
static void onalrm(int s) { (void)s; alarmed = 1; }

static void msleep(int ms) {
    struct timespec ts = { ms / 1000, (ms % 1000) * 1000000L };
    while (nanosleep(&ts, &ts) < 0 && errno == EINTR) {}
}

static int pidfd_open(pid_t pid) { return (int)syscall(434, pid, 0); }

int main(void) {
    siginfo_t si;
    memset(&si, 0, sizeof si);

    // ---- errno ladder -------------------------------------------------
    errno = 0;
    check(waitid(P_ALL, 0, &si, 0) == -1 && errno == EINVAL,
          "no event class EINVAL");
    errno = 0;
    check(waitid(P_ALL, 0, &si, WEXITED | 0x400) == -1 && errno == EINVAL,
          "bad option bit EINVAL");
    errno = 0;
    check(waitid((idtype_t)9, 1, &si, WEXITED) == -1 && errno == EINVAL,
          "bad idtype EINVAL");
    errno = 0;
    check(waitid(P_PID, 0, &si, WEXITED) == -1 && errno == EINVAL,
          "P_PID id 0 EINVAL");
    errno = 0;
    check(waitid(P_PIDFD, -1, &si, WEXITED) == -1 && errno == EBADF,
          "P_PIDFD bad fd EBADF");
    int pfd_non[2];
    check(pipe(pfd_non) == 0, "pipe for non-pidfd");
    errno = 0;
    check(waitid(P_PIDFD, pfd_non[0], &si, WEXITED) == -1 && errno == EINVAL,
          "P_PIDFD non-pidfd EINVAL");
    close(pfd_non[0]);
    close(pfd_non[1]);
    errno = 0;
    check(waitid(P_PID, 99999, &si, WEXITED) == -1 && errno == ECHILD,
          "non-child ECHILD");
    // NULL infop is legal — WNOHANG with no children still ECHILD.
    errno = 0;
    check(waitid(P_ALL, 0, NULL, WEXITED | WNOHANG) == -1 && errno == ECHILD,
          "null infop ECHILD");
    // A bad infop only faults when a report would land — with no
    // children at all the answer is ECHILD, like Linux.
    pid_t c0 = fork();
    if (c0 == 0) die(0);
    msleep(40);
    errno = 0;
    check(waitid(P_PID, c0, (siginfo_t *)0xdead, WEXITED) == -1 &&
              errno == EFAULT,
          "bad infop EFAULT on report");
    errno = 0;
    check(waitid(P_PID, c0, &si, WEXITED) == 0, "c0 reaped after fault");

    // ---- WEXITED report -----------------------------------------------
    pid_t c1 = fork();
    if (c1 == 0) die(42);
    memset(&si, 0, sizeof si);
    check(waitid(P_PID, c1, &si, WEXITED) == 0, "waitid P_PID reaped");
    check(si.si_signo == SIGCHLD && si.si_code == CLD_EXITED &&
              si.si_pid == c1 && si.si_status == 42 &&
              si.si_uid == getuid(),
          "siginfo signo/code/pid/status/uid");

    // Signal-death maps CLD_KILLED + the killing signal.
    pid_t c2 = fork();
    if (c2 == 0) { for (;;) pause(); }
    kill(c2, SIGKILL);
    memset(&si, 0, sizeof si);
    check(waitid(P_PID, c2, &si, WEXITED) == 0 &&
              si.si_code == CLD_KILLED && si.si_status == SIGKILL,
          "CLD_KILLED + killing sig");

    // ---- WNOHANG zero report -------------------------------------------
    pid_t c3 = fork();
    if (c3 == 0) { msleep(200); die(3); }
    si.si_pid = c3; // sentinel — the kernel zeroes it
    check(waitid(P_PID, c3, &si, WEXITED | WNOHANG) == 0 && si.si_pid == 0,
          "WNOHANG live child zeroes si_pid");
    memset(&si, 0, sizeof si);
    check(waitid(P_PID, c3, &si, WEXITED) == 0 && si.si_status == 3,
          "blocked waitid wakes on exit");

    // ---- WNOWAIT: report without consuming -----------------------------
    pid_t c4 = fork();
    if (c4 == 0) die(9);
    memset(&si, 0, sizeof si);
    check(waitid(P_PID, c4, &si, WEXITED | WNOWAIT) == 0 &&
              si.si_pid == c4 && si.si_status == 9,
          "WNOWAIT peeks zombie");
    memset(&si, 0, sizeof si);
    check(waitid(P_PID, c4, &si, WEXITED | WNOHANG | WNOWAIT) == 0 &&
              si.si_pid == c4,
          "WNOWAIT leaves report consumable");
    int st = 0;
    errno = 0;
    pid_t wr = waitpid(c4, &st, 0);
    if (wr != c4 || !WIFEXITED(st) || WEXITSTATUS(st) != 9)
        printf("widtest: waitpid -> %d errno %d st %#x\n", (int)wr, errno, st);
    check(wr == c4 && WIFEXITED(st) && WEXITSTATUS(st) == 9,
          "wait4 still reaps the peeked zombie");

    // ---- WSTOPPED / WCONTINUED ------------------------------------------
    pid_t c5 = fork();
    if (c5 == 0) { raise(SIGSTOP); msleep(50); die(5); }
    memset(&si, 0, sizeof si);
    check(waitid(P_PID, c5, &si, WSTOPPED) == 0 &&
              si.si_code == CLD_STOPPED && si.si_status == SIGSTOP,
          "WSTOPPED reports CLD_STOPPED");
    memset(&si, 0, sizeof si);
    check(waitid(P_PID, c5, &si, WSTOPPED | WNOHANG) == 0 && si.si_pid == 0,
          "stop already reported -> no re-report");
    kill(c5, SIGCONT);
    // CONT delivery schedules the child before cont_report is
    // visible — poll WCONTINUED briefly.
    int cont = 0;
    for (int i = 0; i < 40 && !cont; i++) {
        memset(&si, 0, sizeof si);
        if (waitid(P_PID, c5, &si, WCONTINUED | WNOHANG) == 0 &&
            si.si_code == CLD_CONTINUED && si.si_status == SIGCONT)
            cont = 1;
        else
            msleep(10);
    }
    check(cont, "WCONTINUED reports CLD_CONTINUED");
    memset(&si, 0, sizeof si);
    check(waitid(P_PID, c5, &si, WEXITED) == 0 && si.si_status == 5,
          "resumed child exits");

    // ---- WSTOPPED-only mask sleeps through an exit ----------------------
    pid_t c6 = fork();
    if (c6 == 0) { msleep(150); die(6); }
    memset(&si, 0, sizeof si);
    msleep(250); // let c6 die first
    check(waitid(P_PID, c6, &si, WSTOPPED | WNOHANG) == 0 && si.si_pid == 0,
          "WSTOPPED mask sees no exit");
    memset(&si, 0, sizeof si);
    check(waitid(P_PID, c6, &si, WEXITED | WNOHANG) == 0 && si.si_pid == c6,
          "WEXITED sees the same zombie");

    // ---- P_PGID ----------------------------------------------------------
    pid_t c7 = fork();
    if (c7 == 0) { setpgid(0, 0); die(7); }
    msleep(60);
    memset(&si, 0, sizeof si);
    check(waitid(P_PGID, c7, &si, WEXITED) == 0 && si.si_pid == c7 &&
              si.si_status == 7,
          "P_PGID on child's new group");

    // ---- P_PIDFD ----------------------------------------------------------
    pid_t c8 = fork();
    if (c8 == 0) die(8);
    int pfd = pidfd_open(c8);
    check(pfd >= 0, "pidfd_open mints fd");
    memset(&si, 0, sizeof si);
    check(waitid(P_PIDFD, pfd, &si, WEXITED) == 0 && si.si_pid == c8 &&
              si.si_status == 8,
          "P_PIDFD waits through the fd");
    close(pfd);

    // ---- EINTR -----------------------------------------------------------
    pid_t c9 = fork();
    if (c9 == 0) { msleep(3000); die(1); }
    struct sigaction sa = { .sa_handler = onalrm };
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0; // no SA_RESTART — the wait must interrupt
    sigaction(SIGALRM, &sa, NULL);
    alarmed = 0;
    alarm(1);
    memset(&si, 0, sizeof si);
    int r = waitid(P_PID, c9, &si, WEXITED);
    check(r == -1 && errno == EINTR && alarmed, "blocked waitid EINTR");
    kill(c9, SIGKILL);
    memset(&si, 0, sizeof si);
    waitid(P_PID, c9, &si, WEXITED); // reap

    printf("widtest: %d failures\n", fails);
    return fails;
}
