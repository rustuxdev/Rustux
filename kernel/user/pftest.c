// pftest — perf_event_open(298) oracle: counting-mode counters.
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <sys/poll.h>
#include <signal.h>
#include <setjmp.h>
#include <linux/perf_event.h>

static sigjmp_buf jb;
static void segv(int s) { (void)s; siglongjmp(jb, 1); }

static int fails = 0;
static void check(int ok, const char *name) {
    if (!ok) { printf("pftest: FAIL %s\n", name); fails++; }
}

static long pe_open(struct perf_event_attr *a, pid_t pid, int cpu,
                    int group, unsigned long flags) {
    return syscall(298, a, pid, cpu, group, flags);
}

static uint64_t rd(int fd) {
    uint64_t v = (uint64_t)-1;
    if (read(fd, &v, 8) != 8) return (uint64_t)-2;
    return v;
}

static struct perf_event_attr mk(uint32_t type, uint64_t cfg) {
    struct perf_event_attr a;
    memset(&a, 0, sizeof(a));
    a.type = type;
    a.size = sizeof(a);
    a.config = cfg;
    return a;
}

int main(void) {
    printf("pftest: begin\n");

    // --- EINVAL / ENODEV / ESRCH ladder --------------------------------
    {
        struct perf_event_attr a = mk(PERF_TYPE_SOFTWARE,
                                      PERF_COUNT_SW_PAGE_FAULTS);
        a.size = 8;
        check(pe_open(&a, 0, -1, -1, 0) == -1 && errno == EINVAL,
              "attr: size<64 EINVAL");
        a = mk(PERF_TYPE_SOFTWARE, PERF_COUNT_SW_PAGE_FAULTS);
        a.sample_type = PERF_SAMPLE_IP;
        check(pe_open(&a, 0, -1, -1, 0) == -1 && errno == EINVAL,
              "attr: sample_type EINVAL");
        a = mk(PERF_TYPE_SOFTWARE, PERF_COUNT_SW_PAGE_FAULTS);
        a.read_format = PERF_FORMAT_TOTAL_TIME_ENABLED;
        check(pe_open(&a, 0, -1, -1, 0) == -1 && errno == EINVAL,
              "attr: read_format EINVAL");
        a = mk(PERF_TYPE_SOFTWARE, PERF_COUNT_SW_PAGE_FAULTS);
        a.mmap = 1;
        check(pe_open(&a, 0, -1, -1, 0) == -1 && errno == EINVAL,
              "attr: mmap bit EINVAL");
        a = mk(PERF_TYPE_TRACEPOINT, 42);
        errno = 0;
        long r = pe_open(&a, 0, -1, -1, 0);
        printf("pftest: tracepoint ret=%ld errno=%d\n", r, errno);
        check(r == -1 && errno == ENODEV,
              "attr: tracepoint type ENODEV");
        a = mk(PERF_TYPE_SOFTWARE, 99);
        check(pe_open(&a, 0, -1, -1, 0) == -1 && errno == ENODEV,
              "attr: bad sw config ENODEV");
        a = mk(PERF_TYPE_HARDWARE, PERF_COUNT_HW_INSTRUCTIONS);
        check(pe_open(&a, 0, -1, -1, 0) == -1 && errno == ENODEV,
              "attr: hw instructions ENODEV");
        a = mk(PERF_TYPE_SOFTWARE, PERF_COUNT_SW_PAGE_FAULTS);
        check(pe_open(&a, -1, -1, -1, 0) == -1 && errno == EINVAL,
              "args: pid=-1 cpu=-1 EINVAL");
        check(pe_open(&a, -1, 3, -1, 0) == -1 && errno == ENODEV,
              "args: cpu>0 ENODEV");
        check(pe_open(&a, 0, 0, -1, 0) == -1 && errno == ENODEV,
              "args: pid=0 cpu>=0 ENODEV");
        check(pe_open(&a, 999999, -1, -1, 0) == -1 && errno == ESRCH,
              "args: bad pid ESRCH");
        check(pe_open(&a, 0, -1, 3, 0) == -1 && errno == EINVAL,
              "args: group_fd EINVAL");
        check(pe_open(&a, 0, -1, -1, 0x100) == -1 && errno == EINVAL,
              "args: bad flags EINVAL");
    }

    // --- read surface --------------------------------------------------
    struct perf_event_attr pa = mk(PERF_TYPE_SOFTWARE,
                                   PERF_COUNT_SW_PAGE_FAULTS);
    int fd = (int)pe_open(&pa, 0, -1, -1, PERF_FLAG_FD_CLOEXEC);
    if (fd < 0) printf("pftest: pf open errno=%d\n", errno);
    check(fd >= 0, "open: page-faults counter");
    {
        char b4[4];
        check(read(fd, b4, 4) == -1 && errno == EINVAL,
              "read: len<8 EINVAL");
        check(read(fd, (char *)1, 8) == -1 && errno == EFAULT,
              "read: bad buf EFAULT");
    }
    struct pollfd pf = { .fd = fd, .events = POLLIN };
    check(poll(&pf, 1, 0) == 1 && (pf.revents & POLLIN),
          "poll: counting fd POLLIN");
    check(ioctl(fd, 0x2499, 0) == -1 && errno == EINVAL,
              "ioctl: bad req EINVAL");
    check(ioctl(0, 0x2400, 0) == -1 && errno == ENOTTY,
              "ioctl: non-perf fd ENOTTY");
    check(ioctl(fd, PERF_EVENT_IOC_REFRESH, 0) == 0, "ioctl: REFRESH 0");

    // --- PAGE_FAULTS actually counts: a real #PF -> SIGSEGV -> ----
    // handler->longjmp must tick the counter (in-parent, fork-free —
    // the ldttest NP oracle pattern).
    {
        struct sigaction sa = { .sa_handler = segv };
        sigaction(SIGSEGV, &sa, 0);
        uint64_t before = rd(fd);
        check(before != (uint64_t)-2, "read: initial count sane");
        if (sigsetjmp(jb, 1) == 0) {
            volatile char *p = (volatile char *)0x500000000000ull;
            (void)*p; // #PF -> SIGSEGV -> segv() -> longjmp
            check(0, "fault oracle fell through");
        }
        uint64_t after = rd(fd);
        check(after > before, "page-fault count advanced on real #PF");
    }

    // --- DISABLE freezes, ENABLE resumes, RESET re-bases ---------------
    {
        check(ioctl(fd, PERF_EVENT_IOC_DISABLE, 0) == 0, "IOC_DISABLE");
        uint64_t a = rd(fd), b = rd(fd);
        check(a == b && a != (uint64_t)-2, "disabled count frozen");
        check(ioctl(fd, PERF_EVENT_IOC_RESET, 0) == 0, "IOC_RESET");
        check(rd(fd) == 0, "reset count zero while disabled");
        check(ioctl(fd, PERF_EVENT_IOC_ENABLE, 0) == 0, "IOC_ENABLE");
    }
    close(fd);

    // --- CYCLES monotonic ----------------------------------------------
    {
        struct perf_event_attr a = mk(PERF_TYPE_HARDWARE,
                                      PERF_COUNT_HW_CPU_CYCLES);
        int f2 = (int)pe_open(&a, 0, -1, -1, 0);
        check(f2 >= 0, "open: cycles counter");
        uint64_t c1 = rd(f2), c2 = rd(f2);
        check(c2 > c1 && c1 > 0, "cycles monotonic + nonzero");
        close(f2);
    }

    // --- TASK_CLOCK / CPU_CLOCK / CTX_SWITCHES / MIGRATIONS ------------
    {
        struct perf_event_attr a = mk(PERF_TYPE_SOFTWARE,
                                      PERF_COUNT_SW_TASK_CLOCK);
        int f2 = (int)pe_open(&a, 0, -1, -1, 0);
        check(f2 >= 0 && rd(f2) != (uint64_t)-2, "task_clock reads");
        close(f2);
        a = mk(PERF_TYPE_SOFTWARE, PERF_COUNT_SW_CPU_CLOCK);
        f2 = (int)pe_open(&a, 0, -1, -1, 0);
        // Counters measure delta-since-enable — a yield makes the
        // elapsed window nonzero (3 ticks of wall + >=1 switch).
        check(f2 >= 0 && rd(f2) != (uint64_t)-2, "cpu_clock reads");
        uint64_t cc1 = rd(f2);
        usleep(30 * 1000);
        check(rd(f2) > cc1, "cpu_clock advances over a yield");
        close(f2);
        a = mk(PERF_TYPE_SOFTWARE, PERF_COUNT_SW_CONTEXT_SWITCHES);
        f2 = (int)pe_open(&a, 0, -1, -1, 0);
        check(f2 >= 0, "ctx_switches opens");
        usleep(30 * 1000);
        check(rd(f2) > 0, "ctx_switches count after a yield");
        close(f2);
        a = mk(PERF_TYPE_SOFTWARE, PERF_COUNT_SW_CPU_MIGRATIONS);
        f2 = (int)pe_open(&a, 0, -1, -1, 0);
        check(f2 >= 0 && rd(f2) == 0, "cpu_migrations 0 (one cpu)");
        close(f2);
    }

    // --- pid>0 target + freeze-on-death + system-wide ------------------
    {
        struct perf_event_attr a = mk(PERF_TYPE_SOFTWARE,
                                      PERF_COUNT_SW_CONTEXT_SWITCHES);
        pid_t p = -1;
        for (int i = 0; i < 300 && (p = fork()) < 0; i++)
            usleep(10 * 1000);
        if (p == 0) { for (;;) pause(); }
        if (p < 0) {
            printf("pftest: SKIP target phase (task table full)\n");
        } else {
            int f2 = (int)pe_open(&a, p, -1, -1, 0);
            check(f2 >= 0, "open: counter on child pid");
            usleep(30 * 1000);
            uint64_t v1 = rd(f2);
            kill(p, 9);
            waitpid(p, 0, 0);
            uint64_t v2 = rd(f2), v3 = rd(f2);
            check(v2 == v3 && v2 != (uint64_t)-2,
                  "dead target frozen");
            (void)v1;
            close(f2);
        }
        // system-wide: pid=-1 cpu=0 — the sum includes every task's
        // counts so it must be >= any single-task counter's value.
        int fw = (int)pe_open(&a, -1, 0, -1, 0);
        check(fw >= 0 && rd(fw) != (uint64_t)-2,
              "open: cpu0 system-wide counter");
        close(fw);
        a = mk(PERF_TYPE_SOFTWARE, PERF_COUNT_SW_PAGE_FAULTS);
        fw = (int)pe_open(&a, -1, 0, -1, 0);
        check(fw >= 0, "open: system-wide page-faults");
        close(fw);
    }

    printf("pftest: %d failures\n", fails);
    _exit(fails);
}
