// stest — sigaltstack(131)/SA_ONSTACK + get_robust_list(274) +
// settimeofday(164) + syncfs(306) + the NR_RENAMEAT2=316 fix.
// The altstack proof is real delivery: an SA_ONSTACK USR1 handler
// checks its own frame pointer lands inside the installed window.
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/time.h>

static int fails;
#define check(c, msg) do { \
    if (c) printf("stest: %-40s ok\n", msg); \
    else { printf("stest: %-40s FAIL\n", msg); fails++; } \
} while (0)

#ifndef SYS_renameat2
#define SYS_renameat2 316
#endif
#ifndef SYS_sigaltstack
#define SYS_sigaltstack     131
#define SYS_settimeofday    164
#define SYS_get_robust_list 274
#define SYS_syncfs          306
#endif
#define TEE_NR 276 // Linux tee — must NOT alias renameat2

static stack_t alt;
static volatile sig_atomic_t on_alt;
static volatile sig_atomic_t disable_eperm;

static void usr1_handler(int sig) {
    (void)sig;
    char local;
    uintptr_t p = (uintptr_t)&local;
    uintptr_t lo = (uintptr_t)alt.ss_sp;
    on_alt = p >= lo && p < lo + alt.ss_size;
    // modifying the stack while running on it must EPERM
    stack_t off = { .ss_flags = SS_DISABLE };
    disable_eperm = syscall(SYS_sigaltstack, &off, 0) == -1 && errno == EPERM;
}

int main(void) {
    printf("stest: sigaltstack + settimeofday + syncfs + robust_list + NR fix\n");

    // --- NR_RENAMEAT2 fix: 316 is the real number; 276 is tee.
    int fd = open("/tmp_st_a", O_CREAT | O_RDWR | O_TRUNC, 0644);
    int rc = (int)write(fd, "x", 1);
    close(fd);
    errno = 0;
    long r = syscall(SYS_renameat2, AT_FDCWD, "/tmp_st_a",
                     AT_FDCWD, "/tmp_st_b", 0);
    check(r == 0 && access("/tmp_st_b", F_OK) == 0,
          "renameat2(316) renames");
    errno = 0;
    check(syscall(TEE_NR, 0, 0, 0, 0) == -1 && errno == ENOSYS,
          "nr 276 is tee, not renameat2");
    // RENAME_NOREPLACE against an existing target.
    fd = open("/tmp_st_c", O_CREAT | O_RDWR | O_TRUNC, 0644);
    close(fd);
    errno = 0;
    r = syscall(SYS_renameat2, AT_FDCWD, "/tmp_st_b",
                AT_FDCWD, "/tmp_st_c", 1 /*RENAME_NOREPLACE*/);
    check(r == -1 && errno == EEXIST, "NOREPLACE on existing -> EEXIST");
    unlink("/tmp_st_b");
    unlink("/tmp_st_c");

    // --- sigaltstack: install via a private mmap window.
    alt.ss_size = SIGSTKSZ;
    alt.ss_sp = mmap(0, alt.ss_size, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    check(alt.ss_sp != MAP_FAILED, "altstack window mapped");
    alt.ss_flags = 0;
    check(syscall(SYS_sigaltstack, &alt, 0) == 0, "sigaltstack install");
    // old_ss readback reports enabled state.
    stack_t cur;
    check(syscall(SYS_sigaltstack, 0, &cur) == 0
              && cur.ss_sp == alt.ss_sp && cur.ss_flags == 0,
          "oss reports installed stack");
    // SA_ONSTACK handler delivers onto the alt window.
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = usr1_handler;
    sa.sa_flags = SA_ONSTACK;
    sigemptyset(&sa.sa_mask);
    check(sigaction(SIGUSR1, &sa, 0) == 0, "SA_ONSTACK installed");
    raise(SIGUSR1);
    check(on_alt == 1, "handler frame lands on altstack");
    check(disable_eperm == 1, "ss modify while on-stack -> EPERM");
    // Size gates.
    stack_t tiny = { .ss_sp = alt.ss_sp, .ss_size = 100, .ss_flags = 0 };
    errno = 0;
    check(syscall(SYS_sigaltstack, &tiny, 0) == -1 && errno == ENOMEM,
          "size < MINSIGSTKSZ -> ENOMEM");
    stack_t badf = { .ss_sp = alt.ss_sp, .ss_size = SIGSTKSZ,
                     .ss_flags = SS_ONSTACK };
    errno = 0;
    check(syscall(SYS_sigaltstack, &badf, 0) == -1 && errno == EINVAL,
          "SS_ONSTACK in ss_flags -> EINVAL");
    // Disable and confirm the next delivery is off-stack.
    stack_t off = { .ss_flags = SS_DISABLE };
    check(syscall(SYS_sigaltstack, &off, 0) == 0, "SS_DISABLE clears");
    on_alt = 0;
    raise(SIGUSR1);
    check(on_alt == 0, "disabled stack ignored");

    // --- get_robust_list: empty-list answer + gates.
    void *head = (void *)0x1;
    size_t hlen = 99;
    check(syscall(SYS_get_robust_list, 0, &head, &hlen) == 0
              && head == 0 && hlen == 0,
          "robust list reports empty");
    errno = 0;
    check(syscall(SYS_get_robust_list, 999999, &head, &hlen) == -1
              && errno == ESRCH,
          "dead pid -> ESRCH");
    errno = 0;
    check(syscall(SYS_get_robust_list, 0, (void *)0x10, &hlen) == -1
              && errno == EFAULT,
          "bad head ptr -> EFAULT");

    // --- settimeofday: same wall write as clock_settime.
    struct timeval tv = { .tv_sec = 1740000000, .tv_usec = 500000 };
    check(syscall(SYS_settimeofday, &tv, 0) == 0, "settimeofday ok");
    struct timespec now;
    clock_gettime(CLOCK_REALTIME, &now);
    check(now.tv_sec >= 1740000000 && now.tv_sec < 1740000100,
          "wall clock moved");
    struct timeval bad = { .tv_sec = 1, .tv_usec = 1000000 };
    errno = 0;
    check(syscall(SYS_settimeofday, &bad, 0) == -1 && errno == EINVAL,
          "usec >= 1e6 -> EINVAL");
    struct timezone tz = { .tz_minuteswest = 0, .tz_dsttime = 0 };
    check(syscall(SYS_settimeofday, 0, &tz) == 0,
          "tv NULL tz-only form -> 0");

    // --- syncfs: fd gate + inert.
    fd = open("/tmp_st_syncfs", O_CREAT | O_RDWR, 0644);
    check(syscall(SYS_syncfs, fd) == 0, "syncfs valid fd -> 0");
    errno = 0;
    check(syscall(SYS_syncfs, 9999) == -1 && errno == EBADF,
          "bad fd -> EBADF");
    close(fd);
    unlink("/tmp_st_syncfs");

    (void)rc;
    printf("stest: %d failure%s\n", fails, fails == 1 ? "" : "s");
    return fails;
}
