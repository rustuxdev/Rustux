// mm3test — compiled mremap(25)/madvise(28)/mincore(227) ABI proof.
// mremap: flag/EINVAL ladder, EFAULT on unmapped/reserved old,
// shrink keeps base + zaps tail (mprotect ENOMEM probe), MAYMOVE
// grow relocates preserving bytes, FIXED honors the target.
// madvise: DONTNEED zeroes, hints accepted-inert, EINVAL/ENOMEM
// gates. mincore: residency bits, ENOMEM on uncommitted range.
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/syscall.h>

static int fails;
#define check(c, msg) do { \
    if (c) printf("mm3test: %-34s ok\n", msg); \
    else { printf("mm3test: %-34s FAIL\n", msg); fails++; } \
} while (0)

#ifndef MREMAP_MAYMOVE
#define MREMAP_MAYMOVE 1
#define MREMAP_FIXED   2
#endif
#define P 4096L

int main(void) {
    printf("mm3test: mremap + madvise + mincore checks\n");

    // ---- mremap gates ----
    void *p = mmap(0, 4 * P, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    check(p != MAP_FAILED, "mmap 4p");
    memset(p, 0x5a, 4 * P);
    errno = 0;
    check(mremap(p, 4 * P, 8 * P, MREMAP_FIXED) == MAP_FAILED
          && errno == EINVAL, "FIXED sans MAYMOVE EINVAL");
    errno = 0;
    check(mremap(p, 4 * P, 8 * P, 0x40) == MAP_FAILED && errno == EINVAL,
          "unknown flag EINVAL");
    errno = 0;
    check(mremap(p, 4 * P, 8 * P, 0) == MAP_FAILED && errno == ENOMEM,
          "grow sans MAYMOVE ENOMEM");
    errno = 0;
    check(mremap(p, 4 * P, 0, MREMAP_MAYMOVE) == MAP_FAILED
          && errno == EINVAL, "new_len 0 EINVAL");
    errno = 0;
    check(mremap((void *)((char *)p + 1), P, 2 * P, MREMAP_MAYMOVE)
          == MAP_FAILED && errno == EINVAL, "unaligned old EINVAL");
    errno = 0;
    check(mremap((void *)0x60000000, P, 2 * P, MREMAP_MAYMOVE)
          == MAP_FAILED && errno == EFAULT, "unmapped old EFAULT");

    // ---- shrink keeps base, tail unmapped ----
    void *q = mremap(p, 4 * P, 2 * P, MREMAP_MAYMOVE);
    check(q == p, "shrink keeps base");
    check(((char *)q)[0] == 0x5a, "shrink keeps head bytes");
    errno = 0;
    check(mprotect((char *)q + 2 * P, P, PROT_READ | PROT_WRITE) < 0
          && errno == ENOMEM, "shrink tail is unmapped");

    // ---- grow+MAYMOVE relocates, content follows ----
    void *r = mremap(q, 2 * P, 6 * P, MREMAP_MAYMOVE);
    check(r != MAP_FAILED && r != q, "grow MAYMOVE moves");
    check(((char *)r)[0] == 0x5a && ((char *)r)[2 * P - 1] == 0x5a,
          "old bytes preserved");
    memset((char *)r + 2 * P, 0xa5, 4 * P);
    check(((unsigned char *)r)[5 * P] == 0xa5, "grown tail writable");
    errno = 0;
    check(mprotect(q, P, PROT_READ | PROT_WRITE) < 0 && errno == ENOMEM,
          "old VA released");

    // ---- FIXED honors the destination ----
    void *hint = mmap(0, 8 * P, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    check(hint != MAP_FAILED, "dst hint mmap");
    munmap(hint, 8 * P);
    void *fx = mremap(r, 6 * P, 6 * P, MREMAP_MAYMOVE | MREMAP_FIXED,
                      hint);
    check(fx == hint, "FIXED same-size moves to target");
    check(((char *)fx)[0] == 0x5a, "FIXED move preserves bytes");
    p = fx;

    // ---- madvise ----
    errno = 0;
    check(madvise((char *)p + 1, P, MADV_DONTNEED) < 0
          && errno == EINVAL, "madvise unaligned EINVAL");
    errno = 0;
    check(madvise(p, P, 99) < 0 && errno == EINVAL,
          "madvise unknown advice EINVAL");
    errno = 0;
    check(madvise((void *)0x60000000, P, MADV_DONTNEED) < 0
          && errno == ENOMEM, "madvise unmapped ENOMEM");
    check(madvise(p, P, MADV_SEQUENTIAL) == 0, "hint accepted-inert");
    memset(p, 0x7f, P);
    check(madvise(p, P, MADV_DONTNEED) == 0, "DONTNEED ok");
    check(((char *)p)[0] == 0 && ((char *)p)[P - 1] == 0,
          "DONTNEED zeroed the page");
    check(madvise(p, 0, MADV_DONTNEED) == 0, "madvise len 0 ok");

    // ---- mincore ----
    unsigned char vec[4] = {0};
    errno = 0;
    check(mincore((char *)p + 1, P, vec) < 0 && errno == EINVAL,
          "mincore unaligned EINVAL");
    errno = 0;
    check(mincore(p, P, (void *)1) < 0 && errno == EFAULT,
          "mincore vec EFAULT");
    errno = 0;
    check(mincore((void *)0x60000000, P, vec) < 0 && errno == ENOMEM,
          "mincore uncommitted ENOMEM");
    ((char *)p)[0] = 1; ((char *)p)[2 * P] = 1; // touch pages 0 and 2
    memset(vec, 0, sizeof vec);
    check(mincore(p, 3 * P, vec) == 0, "mincore ok");
    check((vec[0] & 0x7) == 0x7, "residency bits all present");

    munmap(p, 8 * P);
    printf("mm3test: %d failure(s)\n", fails);
    return fails;
}
