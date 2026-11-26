// systest — system-management syscalls: sysinfo(99), sysfs(139),
// reboot(169) error/CAD paths (real restart not exercised).
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/sysinfo.h>

static int fails;
static void check(int ok, const char *what) {
    if (!ok) {
        printf("FAIL: %s\n", what);
        fails++;
    }
}

static long sysfs3(long op, long a2, long a3) {
    return syscall(139, op, a2, a3);
}
static long reboot4(long m1, long m2, long cmd) {
    return syscall(169, m1, m2, cmd, 0);
}

int main(void) {
    // ---- sysinfo(99) ------------------------------------------
    struct sysinfo si;
    memset(&si, 0xa5, sizeof(si));
    check(syscall(99, &si) == 0, "sysinfo returns 0");
    check(si.uptime >= 0, "sysinfo uptime sane");
    check(si.mem_unit == 1, "sysinfo mem_unit=1");
    check(si.totalram >= 512UL << 20, "sysinfo totalram >= 512M");
    check(si.freeram > 0 && si.freeram <= si.totalram,
          "sysinfo freeram within total");
    check(si.procs >= 1, "sysinfo procs >= 1");
    check(si.loads[0] == 0 && si.totalswap == 0
          && si.totalhigh == 0 && si.sharedram == 0,
          "sysinfo unsourced fields zeroed");
    // padding tail must be deterministic zero too
    check(si._f[0] == 0, "sysinfo pad zeroed");
    errno = 0;
    check(syscall(99, 0xdead) == -1 && errno == EFAULT,
          "sysinfo bad buf EFAULT");
    struct sysinfo si2;
    sysinfo(&si2); // glibc path same ABI
    check(si2.uptime >= si.uptime, "uptime nondecreasing");

    // ---- sysfs(139) --------------------------------------------
    long n = sysfs3(3, 0, 0);
    check(n >= 3, "sysfs option 3 count");
    char name[64];
    memset(name, 0, sizeof(name));
    check(sysfs3(2, 0, (long)name) == 0, "sysfs index 0 ok");
    check(strcmp(name, "rustux") == 0, "sysfs index 0 is rustux");
    memset(name, 0, sizeof(name));
    check(sysfs3(2, 1, (long)name) == 0
          && strcmp(name, "tmpfs") == 0, "sysfs index 1 is tmpfs");
    errno = 0;
    check(sysfs3(2, n + 5, (long)name) == -1 && errno == EINVAL,
          "sysfs bad index EINVAL");
    errno = 0;
    check(sysfs3(2, 0, 0xdead) == -1 && errno == EFAULT,
          "sysfs bad buf EFAULT");
    check(sysfs3(1, (long)"tmpfs", 0) == 1,
          "sysfs name->index round-trip");
    errno = 0;
    check(sysfs3(1, (long)"nosuchfs", 0) == -1 && errno == EINVAL,
          "sysfs unknown name EINVAL");
    errno = 0;
    check(sysfs3(9, 0, 0) == -1 && errno == EINVAL,
          "sysfs bad option EINVAL");

    // ---- reboot(169) --------------------------------------------
    errno = 0;
    check(reboot4(0, 0, 0) == -1 && errno == EINVAL,
          "reboot no magic EINVAL");
    errno = 0;
    check(reboot4(0xfee1dead, 0, 0) == -1 && errno == EINVAL,
          "reboot magic1 only EINVAL");
    errno = 0;
    check(reboot4(0xfee1dead, 672274793, 0xfeed) == -1
          && errno == EINVAL, "reboot unknown cmd EINVAL");
    check(reboot4(0xfee1dead, 672274793, 0x89abcdef) == 0,
          "reboot CAD_ON ok");
    check(reboot4(0xfee1dead, 85072278, 0) == 0,
          "reboot CAD_OFF alt magic ok");
    // nonroot can't even CAD
    pid_t c = fork();
    if (c == 0) {
        if (setuid(1000) != 0) _exit(9);
        int bad = 0;
        errno = 0;
        if (reboot4(0xfee1dead, 672274793, 0x89abcdef) != -1
            || errno != EPERM)
            bad++;
        errno = 0;
        if (reboot4(0xfee1dead, 672274793, 0x01234567) != -1
            || errno != EPERM)
            bad++;
        // bad magic still EINVAL before the perm check
        errno = 0;
        if (reboot4(0, 0, 0) != -1 || errno != EINVAL)
            bad++;
        _exit(bad);
    }
    int st;
    waitpid(c, &st, 0);
    check(WIFEXITED(st) && WEXITSTATUS(st) == 0,
          "reboot nonroot EPERM, EINVAL precedence");

    printf("systest: %d failures\n", fails);
    return fails;
}
