// msltest — mseal(462) + cachestat(451) ABI proof. A sealed range
// EPERMs every layout/content mutator (munmap, mprotect, mremap,
// MAP_FIXED-over, madvise DONTNEED/FREE, brk shrink) but reads and
// non-mutating advice pass. cachestat reports VFile residency —
// all-RAM backing so nr_cache is the size-clamped page count.
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/stat.h>

static int fails;
#define check(c, msg) do { \
    if (c) printf("msltest: %-36s ok\n", msg); \
    else { printf("msltest: %-36s FAIL\n", msg); fails++; } \
} while (0)

#ifndef SYS_mremap
#define SYS_mremap     25
#endif
#define SYS_cachestat  451
#define SYS_mseal      462
#define MREMAP_MAYMOVE 1
#define MREMAP_FIXED   2

struct cs_range { uint64_t off, len; };
struct cstat {
    uint64_t nr_cache, nr_dirty, nr_writeback, nr_evicted, nr_evict2;
};

int main(void) {
    printf("msltest: mseal + cachestat checks\n");
    char *a = mmap(0, 0x20000, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    check(a != MAP_FAILED, "mmap 128K");
    a[0] = 7;

    // ---- mseal(462) gates ----
    errno = 0;
    check(syscall(SYS_mseal, a, 0x1000, 1) < 0 && errno == EINVAL,
          "mseal flags EINVAL");
    errno = 0;
    check(syscall(SYS_mseal, a + 1, 0x1000, 0) < 0 && errno == EINVAL,
          "mseal unaligned EINVAL");
    check(syscall(SYS_mseal, a, 0, 0) == 0, "mseal len 0");
    errno = 0;
    check(syscall(SYS_mseal, (void *)0x7f0000000000UL, 0x1000, 0) < 0
          && errno == ENOENT, "mseal unmapped ENOENT");

    // ---- seal coverage ----
    check(syscall(SYS_mseal, a, 0x10000, 0) == 0,
          "mseal committed range");
    check(syscall(SYS_mseal, a, 0x10000, 0) == 0, "mseal idempotent");

    // ---- mutators EPERM ----
    errno = 0;
    check(munmap(a, 0x1000) < 0 && errno == EPERM,
          "munmap sealed EPERM");
    errno = 0;
    check(mprotect(a, 0x1000, PROT_READ) < 0 && errno == EPERM,
          "mprotect sealed EPERM");
    errno = 0;
    check(madvise(a, 0x1000, MADV_DONTNEED) < 0 && errno == EPERM,
          "madvise DONTNEED sealed EPERM");
    errno = 0;
    check(syscall(SYS_mremap, a, 0x8000, 0x10000, MREMAP_MAYMOVE,
                  0) < 0 && errno == EPERM,
          "mremap sealed src EPERM");
    errno = 0;
    check(mmap(a, 0x1000, PROT_READ | PROT_WRITE,
               MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0)
          == MAP_FAILED && errno == EPERM,
          "MAP_FIXED over seal EPERM");
    // non-mutating ops still pass
    check(madvise(a, 0x1000, MADV_NORMAL) == 0,
          "madvise NORMAL ok on seal");
    check(a[0] == 7, "sealed page still readable");

    // ---- partial seal: the unsealed half still unmmaps ----
    check(syscall(SYS_mseal, a + 0x10000, 0x8000, 0) == 0,
          "mseal partial range");
    errno = 0;
    check(munmap(a + 0x18000, 0x8000) == 0,
          "munmap unsealed tail ok");
    errno = 0;
    check(munmap(a + 0x10000, 0x8000) < 0 && errno == EPERM,
          "munmap sealed half EPERM");

    // ---- mremap FIXED onto sealed dst ----
    char *b = mmap(0, 0x8000, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    check(b != MAP_FAILED, "mmap movable");
    check(syscall(SYS_mseal, b + 0x4000, 0x4000, 0) == 0,
          "seal dst half");
    errno = 0;
    check(syscall(SYS_mremap, b, 0x4000, 0x4000,
                  MREMAP_MAYMOVE | MREMAP_FIXED, b + 0x4000) < 0
          && errno == EPERM,
          "mremap FIXED onto seal EPERM");

    // ---- cachestat(451) ----
    int fd = open("/msl_cs", O_CREAT | O_RDWR, 0600);
    check(fd >= 0, "create cachestat file");
    write(fd, a, 0x5000);
    struct cs_range r = { .off = 0, .len = 0x8000 };
    struct cstat cs;
    memset(&cs, 0xaa, sizeof(cs));
    check(syscall(SYS_cachestat, fd, &r, &cs) == 0
          && cs.nr_cache == 5 /*0x5000 -> 5 pages*/
          && cs.nr_dirty == 0 && cs.nr_writeback == 0
          && cs.nr_evicted == 0 && cs.nr_evict2 == 0,
          "cachestat residency bits");
    r.off = 0x9000; // beyond EOF -> nothing resident
    memset(&cs, 0xaa, sizeof(cs));
    check(syscall(SYS_cachestat, fd, &r, &cs) == 0
          && cs.nr_cache == 0, "cachestat past EOF -> 0");
    errno = 0;
    check(syscall(SYS_cachestat, fd, (void *)1, &cs) < 0
          && errno == EFAULT, "cachestat bad range EFAULT");
    errno = 0;
    check(syscall(SYS_cachestat, fd, &r, (void *)1) < 0
          && errno == EFAULT, "cachestat bad out EFAULT");
    errno = 0;
    int pfd[2];
    pipe(pfd);
    check(syscall(SYS_cachestat, pfd[0], &r, &cs) < 0
          && errno == EBADF, "cachestat pipe EBADF");
    close(pfd[0]); close(pfd[1]);
    close(fd);
    unlink("/msl_cs");

    printf("msltest: %d failure(s)\n", fails);
    return fails;
}
