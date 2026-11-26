// shmtest — SysV SHM ABI proof: shmget(29) keyed + IPC_PRIVATE
// mint, shmat(30) attach semantics, shmctl(31) IPC_STAT/RMID,
// shmdt(67) detach. The kernel's shmid = (gen << 16) | slot, so
// a freed-then-reused slot refuses stale ids.
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <sys/syscall.h>
#include <sys/wait.h>

static int fails;
#define check(c, msg) do { \
    if (c) printf("shmtest: %-40s ok\n", msg); \
    else { printf("shmtest: %-40s FAIL\n", msg); fails++; } \
} while (0)

#ifndef SYS_shmget
#define SYS_shmget 29
#define SYS_shmat  30
#define SYS_shmctl 31
#define SYS_shmdt  67
#endif

#define IPC_PRIVATE  0
#define IPC_CREAT    01000
#define IPC_EXCL     02000
#define IPC_RMID     0
#define IPC_SET      1
#define IPC_STAT     2
#define SHM_RDONLY   010000
#define SHM_RND      020000
#define SHM_REMAP    040000

static long shmget(int key, long size, int flg) {
    return syscall(SYS_shmget, key, size, flg);
}
static void *shmat(long id, const void *addr, int flg) {
    return (void *)syscall(SYS_shmat, id, addr, flg);
}
static long shmctl(long id, int cmd, void *buf) {
    return syscall(SYS_shmctl, id, cmd, buf);
}
static long shmdt(const void *addr) {
    return syscall(SYS_shmdt, addr);
}

int main(void) {
    printf("shmtest: sysv shmget/shmat/shmctl/shmdt checks\n");

    // Keyed mint + lookup.
    long id = shmget(0x5a01, 4096, IPC_CREAT | 0600);
    check(id >= 0, "shmget keyed mint");
    errno = 0;
    check(shmget(0x5a01, 4096, IPC_CREAT | 0600) == id,
          "same key -> same id");
    errno = 0;
    check(shmget(0x5a01, 4096, IPC_CREAT | IPC_EXCL | 0600) == -1 &&
              errno == EEXIST,
          "EXCL on existing -> EEXIST");
    errno = 0;
    check(shmget(0x5a01, 8192, 0) == -1 && errno == EINVAL,
          "size > existing -> EINVAL");
    errno = 0;
    check(shmget(0x9999, 4096, 0) == -1 && errno == ENOENT,
          "missing key sans CREAT -> ENOENT");

    // Create-size bounds.
    errno = 0;
    check(shmget(IPC_PRIVATE, 0, IPC_CREAT | 0600) == -1 &&
              errno == EINVAL,
          "size 0 -> EINVAL");
    errno = 0;
    check(shmget(IPC_PRIVATE, 8 << 20, IPC_CREAT | 0600) == -1 &&
              errno == EINVAL,
          "size > 2MiB -> EINVAL");
    long p1 = shmget(IPC_PRIVATE, 4096, IPC_CREAT | 0600);
    long p2 = shmget(IPC_PRIVATE, 4096, IPC_CREAT | 0600);
    check(p1 >= 0 && p2 >= 0 && p1 != p2,
          "IPC_PRIVATE mints distinct ids");

    // Attach + cross-process sharing: child attaches, reads the
    // parent's marker, writes its own; parent sees it.
    char *a = shmat(id, 0, 0);
    check(a != (void *)-1, "shmat addr=0 attaches");
    memcpy(a, "hello-shm", 10);
    pid_t pid = fork();
    if (pid == 0) {
        char *b = shmat(id, 0, 0);
        if (b == (void *)-1) _exit(3);
        if (memcmp(b, "hello-shm", 10) != 0) _exit(4);
        memcpy(b, "child-was-here", 15);
        _exit(0);
    }
    int st = 0;
    waitpid(pid, &st, 0);
    check(WIFEXITED(st) && WEXITSTATUS(st) == 0,
          "child attach saw parent marker");
    check(memcmp(a, "child-was-here", 15) == 0,
          "parent sees child's shm writes");

    // IPC_STAT: zero-filled 112B shmid_ds, stamped fields.
    unsigned char ds[112];
    errno = 0;
    check(shmctl(id, IPC_STAT, ds) == 0, "IPC_STAT ok");
    check(*(int *)ds == 0x5a01 && *(uint64_t *)(ds + 48) == 4096 &&
              *(uint64_t *)(ds + 88) >= 1,
          "stat key/size/nattch");

    // A second readonly attach reads the same bytes.
    char *ro = shmat(id, 0, SHM_RDONLY);
    check(ro != (void *)-1 && memcmp(ro, "child-was-here", 15) == 0,
          "SHM_RDONLY attach sees contents");

    // Flag + id validation.
    errno = 0;
    check((long)shmat(id, 0, 0x200000) == -1 && errno == EINVAL,
          "shmat unknown flag -> EINVAL");
    errno = 0;
    check((long)shmat(0xffffff, 0, 0) == -1 && errno == EINVAL,
          "shmat bad id -> EINVAL");
    errno = 0;
    check(shmdt((void *)0x400000) == -1 && errno == EINVAL,
          "shmdt nothing-attached -> EINVAL");

    // IPC_RMID: the id dies at mark, frames at last detach.
    check(shmctl(id, IPC_RMID, 0) == 0, "IPC_RMID ok");
    errno = 0;
    check((long)shmat(id, 0, 0) == -1 && errno == EINVAL,
          "attach after RMID -> EINVAL");
    errno = 0;
    check(shmctl(id, IPC_STAT, ds) == -1 && errno == EINVAL,
          "stat after RMID -> EINVAL");
    // still-attached VMAs keep working after RMID
    check(memcmp(a, "child-was-here", 15) == 0,
          "attached VMA survives RMID");
    check(shmdt(ro) == 0, "shmdt readonly attach");
    check(shmdt(a) == 0, "shmdt writable attach");
    errno = 0;
    check(shmdt(a) == -1 && errno == EINVAL,
          "double shmdt -> EINVAL");

    // Stale-id gen: an RMID'd id dies at mark; a later mint may
    // reuse the slot but the old id still refuses.
    check(shmctl(p1, IPC_RMID, 0) == 0, "RMID first private");
    check(shmctl(p2, IPC_RMID, 0) == 0, "RMID second private");
    long p3 = shmget(IPC_PRIVATE, 4096, IPC_CREAT | 0600);
    check(p3 >= 0, "fresh mint after frees");
    errno = 0;
    check((long)shmat(p1, 0, 0) == -1 && errno == EINVAL,
          "stale id -> EINVAL (gen mismatch)");
    if (p3 >= 0) shmctl(p3, IPC_RMID, 0);

    printf("shmtest: %d failure%s\n", fails, fails == 1 ? "" : "s");
    return fails;
}
