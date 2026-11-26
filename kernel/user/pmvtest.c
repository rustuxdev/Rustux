// pmvtest — process_vm_readv/writev(310/311) + copy_file_range(326)
// + clock_settime(227) + fadvise64(221) + sched_setaffinity(203).
// process_vm proves real cross-mm byte transfer through a forked
// child; copy_file_range proves kernel-side copy with pos advance.
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <time.h>
#include <sched.h>

static int fails;
#define check(c, msg) do { \
    if (c) printf("pmvtest: %-40s ok\n", msg); \
    else { printf("pmvtest: %-40s FAIL\n", msg); fails++; } \
} while (0)

#ifndef SYS_process_vm_readv
#define SYS_process_vm_readv  310
#define SYS_process_vm_writev 311
#define SYS_copy_file_range   326
#define SYS_clock_settime     227
#define SYS_fadvise64         221
#define SYS_sched_setaffinity 203
#endif

static char remote_buf[64];

int main(void) {
    printf("pmvtest: process_vm + cfr + clock_settime + fadvise + affinity\n");

    // --- process_vm: fork a child holding a marker buffer; the
    // parent reads it cross-mm, writes through it, reads back.
    int syncpipe[2], armedpipe[2];
    int rc = pipe(syncpipe);
    rc |= pipe(armedpipe);
    pid_t pid = fork();
    if (pid == 0) {
        memcpy(remote_buf, "parent-can-see-this", 20);
        char c = 1;
        rc = (int)write(armedpipe[1], &c, 1); // armed: buffer filled
        rc = (int)read(syncpipe[0], &c, 1); // hold until parent is done
        _exit(memcmp(remote_buf, "written-by-parent", 17) == 0 ? 0 : 5);
    }
    close(syncpipe[0]);
    close(armedpipe[1]);
    char c;
    rc = (int)read(armedpipe[0], &c, 1); // child armed — deterministic
    char lbuf[64];
    struct iovec local = { .iov_base = lbuf, .iov_len = 64 };
    struct iovec remote = { .iov_base = remote_buf, .iov_len = 64 };
    // remote_buf's VA is the same in the child (fork share, no
    // exec) — read it through process_vm.
    long n = syscall(SYS_process_vm_readv, pid, &local, 1, &remote, 1, 0);
    check(n == 64, "readv full iovec count");
    check(memcmp(local.iov_base, "parent-can-see-this", 20) == 0,
          "cross-mm read sees child bytes");
    char wb[32] = "written-by-parent";
    struct iovec wl = { .iov_base = wb, .iov_len = 17 };
    struct iovec wr = { .iov_base = remote_buf, .iov_len = 17 };
    n = syscall(SYS_process_vm_writev, pid, &wl, 1, &wr, 1, 0);
    check(n == 17, "writev count");
    memset(local.iov_base, 0, 64);
    n = syscall(SYS_process_vm_readv, pid, &local, 1, &remote, 1, 0);
    check(n == 64 && memcmp(local.iov_base, "written-by-parent", 17) == 0,
          "read-back confirms cross-mm write");
    rc = (int)write(syncpipe[1], "x", 1);
    int st = 0;
    waitpid(pid, &st, 0);
    check(WIFEXITED(st) && WEXITSTATUS(st) == 0,
          "child confirms write landed");

    // errno ladder.
    errno = 0;
    check(syscall(SYS_process_vm_readv, 999999, &local, 1, &remote, 1, 0) == -1
              && errno == ESRCH,
          "dead pid -> ESRCH");
    errno = 0;
    check(syscall(SYS_process_vm_readv, pid, &local, 1, &remote, 1, 1) == -1
              && errno == EINVAL,
          "flags != 0 -> EINVAL");
    struct iovec badr = { .iov_base = (void *)0x100, .iov_len = 16 };
    errno = 0;
    check(syscall(SYS_process_vm_readv, getpid(), &local, 1, &badr, 1, 0) == -1
              && errno == EFAULT,
          "bad remote window -> EFAULT");

    // --- copy_file_range: Ram src -> Ram dst through the kernel.
    int in = open("/tmp_cfr_in", O_CREAT | O_RDWR | O_TRUNC, 0644);
    int out = open("/tmp_cfr_out", O_CREAT | O_RDWR | O_TRUNC, 0644);
    check(in >= 0 && out >= 0, "scratch fds minted");
    const char *payload = "copy-file-range payload 0123456789";
    rc = (int)write(in, payload, 35);
    long off_in = 0;
    n = syscall(SYS_copy_file_range, in, &off_in, out, 0, 35, 0);
    check(n == 35 && off_in == 35, "cfr copies + advances off_in");
    char rd[64] = {0};
    rc = (int)pread(out, rd, 35, 0);
    check(memcmp(rd, payload, 35) == 0, "cfr contents land");
    // NULL offs use the OFD positions.
    lseek(in, 0, SEEK_SET);
    n = syscall(SYS_copy_file_range, in, 0, out, 0, 35, 0);
    check(n == 35, "cfr NULL offs use f_pos");
    check(lseek(in, 0, SEEK_CUR) == 35, "cfr advanced src pos");
    errno = 0;
    check(syscall(SYS_copy_file_range, in, 0, out, 0, 4, 1) == -1
              && errno == EINVAL,
          "cfr flags -> EINVAL");
    int pp[2];
    rc |= pipe(pp);
    errno = 0;
    check(syscall(SYS_copy_file_range, pp[0], 0, out, 0, 4, 0) == -1
              && errno == ESPIPE,
          "pipe src -> ESPIPE");

    // --- clock_settime: REALTIME writes the epoch base.
    struct timespec now;
    clock_gettime(CLOCK_REALTIME, &now);
    struct timespec want = { .tv_sec = 1730000000, .tv_nsec = 0 };
    check(syscall(SYS_clock_settime, CLOCK_REALTIME, &want) == 0,
          "clock_settime REALTIME ok");
    clock_gettime(CLOCK_REALTIME, &now);
    // stest also writes the shared wall clock (1740000000) — its
    // write can land between our settime and this read, so the
    // window covers either epoch.
    check(now.tv_sec >= 1730000000 && now.tv_sec < 1740000100,
          "wall clock reports the new epoch");
    errno = 0;
    check(syscall(SYS_clock_settime, CLOCK_MONOTONIC, &want) == -1
              && errno == EINVAL,
          "MONOTONIC set -> EINVAL");
    struct timespec bad = { .tv_sec = 1, .tv_nsec = 2e9 };
    errno = 0;
    check(syscall(SYS_clock_settime, CLOCK_REALTIME, &bad) == -1
              && errno == EINVAL,
          "nsec >= 1e9 -> EINVAL");
    // restore a sane wall clock for anything else in the suite
    syscall(SYS_clock_settime, CLOCK_REALTIME, &now);

    // --- fadvise64: validate + inert.
    check(syscall(SYS_fadvise64, in, 0, 0, 0) == 0, "fadvise NORMAL ok");
    errno = 0;
    check(syscall(SYS_fadvise64, in, 0, 0, 6) == -1 && errno == EINVAL,
          "advice > 5 -> EINVAL");
    errno = 0;
    check(syscall(SYS_fadvise64, pp[0], 0, 0, 0) == -1 && errno == ESPIPE,
          "pipe fd -> ESPIPE");

    // --- sched_setaffinity: single-CPU mask gate.
    unsigned long mask = 1;
    check(syscall(SYS_sched_setaffinity, 0, 8, &mask) == 0,
          "affinity {0} accepted");
    errno = 0;
    mask = 0;
    check(syscall(SYS_sched_setaffinity, 0, 8, &mask) == -1
              && errno == EINVAL,
          "empty mask -> EINVAL");
    errno = 0;
    check(syscall(SYS_sched_setaffinity, 999999, 8, &mask) == -1
              && errno == ESRCH,
          "dead pid -> ESRCH");
    errno = 0;
    check(syscall(SYS_sched_setaffinity, 0, 4, &mask) == -1
              && errno == EINVAL,
          "size < 8 -> EINVAL");

    close(in);
    close(out);
    unlink("/tmp_cfr_in");
    unlink("/tmp_cfr_out");

    (void)rc;
    printf("pmvtest: %d failure%s\n", fails, fails == 1 ? "" : "s");
    return fails;
}
