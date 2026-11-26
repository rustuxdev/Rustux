// xat2test — xattrat family (463-466) + memfd_secret(447) ABI proof.
// xattrat = dfd-relative xattr with AT_SYMLINK_NOFOLLOW/AT_EMPTY_PATH;
// set/get pack the tail in struct xattr_args {value,size,flags} with
// copy_struct_from_user sizing. memfd_secret mints a sealed anonymous
// O_RDWR inode.
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <sys/mman.h>

static int fails;
#define check(c, msg) do { \
    if (c) printf("xat2test: %-36s ok\n", msg); \
    else { printf("xat2test: %-36s FAIL\n", msg); fails++; } \
} while (0)

#ifndef SYS_setxattrat
#define SYS_setxattrat    463
#define SYS_getxattrat    464
#define SYS_listxattrat   465
#define SYS_removexattrat 466
#endif
#ifndef SYS_memfd_secret
#define SYS_memfd_secret  447
#endif
#ifndef AT_SYMLINK_NOFOLLOW
#define AT_SYMLINK_NOFOLLOW 0x100
#endif
#ifndef AT_EMPTY_PATH
#define AT_EMPTY_PATH 0x1000
#endif
#ifndef AT_FDCWD
#define AT_FDCWD (-100)
#endif
#define XATTR_CREATE  1
#define XATTR_REPLACE 2

struct xattr_args {
    uint64_t value;
    uint32_t size;
    uint32_t flags;
};

int main(void) {
    printf("xat2test: xattrat + memfd_secret checks\n");
    unlink("/tmp_x2");
    unlink("/tmp_x2_l");
    int fd = open("/tmp_x2", O_RDWR | O_CREAT, 0600);
    check(fd >= 0, "open scratch file");
    if (fd < 0) return 1;
    check(symlink("/tmp_x2", "/tmp_x2_l") == 0, "link minted");

    struct xattr_args a = {0};
    char val[64];
    memset(val, 0, sizeof val);

    // ---- arg gates ----
    errno = 0;
    check(syscall(SYS_setxattrat, AT_FDCWD, "/tmp_x2", 0x200,
                  "user.k", &a, sizeof a) < 0 && errno == EINVAL,
          "setxattrat bad at_flags EINVAL");
    errno = 0;
    check(syscall(SYS_setxattrat, AT_FDCWD, "/tmp_x2", 0,
                  "user.k", &a, 15) < 0 && errno == EINVAL,
          "setxattrat usize<16 EINVAL");
    errno = 0;
    check(syscall(SYS_setxattrat, AT_FDCWD, "/tmp_x2", 0,
                  "user.k", &a, 5000) < 0 && errno == E2BIG,
          "setxattrat usize>page E2BIG");
    errno = 0;
    check(syscall(SYS_getxattrat, AT_FDCWD, "/tmp_x2", 0,
                  "user.k", (void *)0x7f0000000000UL, 16) < 0
          && errno == EFAULT, "getxattrat args EFAULT");
    a.flags = 1;
    errno = 0;
    check(syscall(SYS_getxattrat, AT_FDCWD, "/tmp_x2", 0,
                  "user.k", &a, sizeof a) < 0 && errno == EINVAL,
          "getxattrat flags!=0 EINVAL");
    a.flags = 0;

    // ---- set/get through AT_FDCWD path ----
    a.value = (uint64_t)(uintptr_t)"hello";
    a.size = 5;
    a.flags = 0;
    check(syscall(SYS_setxattrat, AT_FDCWD, "/tmp_x2", 0,
                  "user.k1", &a, sizeof a) == 0, "setxattrat basic");
    a.flags = XATTR_CREATE;
    errno = 0;
    check(syscall(SYS_setxattrat, AT_FDCWD, "/tmp_x2", 0,
                  "user.k1", &a, sizeof a) < 0 && errno == EEXIST,
          "setxattrat CREATE EEXIST");
    a.flags = 0;
    memset(val, 0, sizeof val);
    a.value = (uint64_t)(uintptr_t)val;
    a.size = sizeof val;
    long n = syscall(SYS_getxattrat, AT_FDCWD, "/tmp_x2", 0,
                     "user.k1", &a, sizeof a);
    check(n == 5 && memcmp(val, "hello", 5) == 0, "getxattrat value");

    // ---- EMPTY_PATH operates on dfd itself ----
    a.value = (uint64_t)(uintptr_t)"ep";
    a.size = 2;
    a.flags = 0;
    check(syscall(SYS_setxattrat, fd, 0, AT_EMPTY_PATH,
                  "user.ep", &a, sizeof a) == 0,
          "setxattrat EMPTY_PATH null path");
    memset(val, 0, sizeof val);
    a.value = (uint64_t)(uintptr_t)val;
    a.size = sizeof val;
    n = syscall(SYS_getxattrat, fd, 0, AT_EMPTY_PATH,
                "user.ep", &a, sizeof a);
    check(n == 2 && memcmp(val, "ep", 2) == 0,
          "getxattrat EMPTY_PATH");
    // empty-string path + EMPTY_PATH is the same thing.
    memset(val, 0, sizeof val);
    n = syscall(SYS_getxattrat, fd, "", AT_EMPTY_PATH,
                "user.ep", &a, sizeof a);
    check(n == 2, "EMPTY_PATH empty string");
    // EMPTY_PATH on a bad fd EBADFs.
    errno = 0;
    check(syscall(SYS_getxattrat, 9999, 0, AT_EMPTY_PATH,
                  "user.ep", &a, sizeof a) < 0 && errno == EBADF,
          "EMPTY_PATH bad fd EBADF");

    // ---- NOFOLLOW keeps the link inode ----
    memset(val, 0, sizeof val);
    a.value = (uint64_t)(uintptr_t)val;
    a.size = sizeof val;
    errno = 0;
    check(syscall(SYS_getxattrat, AT_FDCWD, "/tmp_x2_l",
                  AT_SYMLINK_NOFOLLOW, "user.k1", &a, sizeof a) < 0
          && errno == ENODATA, "NOFOLLOW reads link inode");
    a.value = (uint64_t)(uintptr_t)"lv";
    a.size = 2;
    errno = 0;
    check(syscall(SYS_setxattrat, AT_FDCWD, "/tmp_x2_l",
                  AT_SYMLINK_NOFOLLOW, "user.lk", &a, sizeof a) < 0
          && errno == EPERM, "NOFOLLOW set on link EPERM");

    // ---- list + remove ----
    char lb[256];
    memset(lb, 0, sizeof lb);
    n = syscall(SYS_listxattrat, AT_FDCWD, "/tmp_x2", 0, lb, sizeof lb);
    int have_k1 = 0, have_ep = 0;
    for (long i = 0; i < n; i += strlen(lb + i) + 1) {
        if (!strcmp(lb + i, "user.k1")) have_k1 = 1;
        if (!strcmp(lb + i, "user.ep")) have_ep = 1;
    }
    check(have_k1 && have_ep, "listxattrat both names");
    check(syscall(SYS_removexattrat, AT_FDCWD, "/tmp_x2", 0,
                  "user.ep") == 0, "removexattrat");
    memset(val, 0, sizeof val);
    a.value = (uint64_t)(uintptr_t)val;
    a.size = sizeof val;
    errno = 0;
    check(syscall(SYS_getxattrat, AT_FDCWD, "/tmp_x2", 0,
                  "user.ep", &a, sizeof a) < 0 && errno == ENODATA,
          "removed attr ENODATA");
    errno = 0;
    check(syscall(SYS_listxattrat, AT_FDCWD, "/nope", 0, lb, 64) < 0
          && errno == ENOENT, "listxattrat bad path ENOENT");

    close(fd);
    unlink("/tmp_x2");
    unlink("/tmp_x2_l");

    // ---- memfd_secret(447) ----
    errno = 0;
    check(syscall(SYS_memfd_secret, 1) < 0 && errno == EINVAL,
          "memfd_secret flags EINVAL");
    int s = syscall(SYS_memfd_secret, 0);
    check(s >= 0, "memfd_secret mint");
    if (s >= 0) {
        struct stat st;
        check(fstat(s, &st) == 0 && S_ISREG(st.st_mode),
              "secret is a regular file");
        check(write(s, "shh", 3) == 3, "secret write");
        check(ftruncate(s, 4096) == 0, "secret ftruncate");
        check(lseek(s, 0, SEEK_SET) == 0, "secret lseek");
        char rb[4] = {0};
        check(read(s, rb, 3) == 3 && memcmp(rb, "shh", 3) == 0,
              "secret read-back");
        char *m = mmap(0, 4096, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE, s, 0);
        if (m != MAP_FAILED) {
            check(m[0] == 's' && m[1] == 'h', "secret mmap content");
            munmap(m, 4096);
        }
        // sealing is never supported on secretmem.
        check(fcntl(s, 0x409 /* F_ADD_SEALS */, 1) < 0,
              "F_ADD_SEALS refused");
        close(s);
    }

    printf("xat2test: %d failures\n", fails);
    return fails;
}
