// fatest — fallocate(285) + preadv(295)/pwritev(296) +
// get/setpriority(140/141) + sethostname(170)/setdomainname(171).
// fallocate proves mode-0 extension + seal gates; the *v pair proves
// positioned scatter/gather over an iovec; priority is the inert
// nice pair; hostname/domainname write the live utsname fields.
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/utsname.h>
#include <sys/resource.h>

static int fails;
#define check(c, msg) do { \
    if (c) printf("fatest: %-40s ok\n", msg); \
    else { printf("fatest: %-40s FAIL\n", msg); fails++; } \
} while (0)

#ifndef SYS_fallocate
#define SYS_fallocate       285
#define SYS_preadv          295
#define SYS_pwritev         296
#define SYS_getpriority     140
#define SYS_setpriority     141
#define SYS_sethostname     170
#define SYS_setdomainname   171
#endif

int main(void) {
    printf("fatest: fallocate + p{read,write}v + priority + uts\n");

    // --- fallocate on a memfd-like Ram file
    int fd = open("/tmp_fa", O_RDWR | O_CREAT | O_TRUNC, 0600);
    check(fd >= 0, "open /tmp_fa");
    check(write(fd, "AB", 2) == 2, "seed file");
    errno = 0;
    check(syscall(SYS_fallocate, fd, 0, 8, 16) == 0, "fallocate mode 0 grow");
    check(lseek(fd, 0, SEEK_END) == 24, "i_size extended to off+len");
    char b[8] = {0};
    long pr = pread(fd, b, 4, 8);
    check(pr == 4, "pread probe");
    check(b[0] == 0 && b[3] == 0, "new extent zero-filled");
    errno = 0;
    check(syscall(SYS_fallocate, fd, 0, 0, 4) == 0, "fallocate inside EOF");
    errno = 0;
    long r = syscall(SYS_fallocate, fd, 0, -1L, 4);
    check(r == -1 && errno == EINVAL, "fallocate off<0 EINVAL");
    r = syscall(SYS_fallocate, fd, 0, 4, 0);
    check(r == -1 && errno == EINVAL, "fallocate len<=0 EINVAL");
    r = syscall(SYS_fallocate, fd, 4, 0, 8); // PUNCH_HOLE|KEEP_SIZE unsupported
    check(r == -1 && errno == EINVAL, "fallocate nonzero mode EINVAL");
    int rofd = open("/tmp_fa", O_RDONLY);
    errno = 0;
    r = syscall(SYS_fallocate, rofd, 0, 0, 8);
    check(r == -1 && errno == EBADF, "fallocate O_RDONLY EBADF");
    close(rofd);
    int pfd[2];
    check(pipe(pfd) == 0, "pipe for ESPIPE probe");
    errno = 0;
    r = syscall(SYS_fallocate, pfd[1], 0, 0, 8);
    check(r == -1 && errno == ESPIPE, "fallocate pipe ESPIPE");
    close(pfd[0]); close(pfd[1]);
    close(fd);
    unlink("/tmp_fa");

    // --- preadv / pwritev on a positioned file
    int vfd = open("/tmp_fa_v", O_RDWR | O_CREAT | O_TRUNC, 0600);
    check(vfd >= 0, "open /tmp_fa_v");
    struct iovec iov[3];
    char s1[4] = "one", s2[4] = "two", s3[4] = "tri";
    iov[0] = (struct iovec){s1, 3};
    iov[1] = (struct iovec){s2, 3};
    iov[2] = (struct iovec){s3, 4};
    errno = 0;
    long w = syscall(SYS_pwritev, vfd, iov, 3, 4);
    check(w == 10, "pwritev 3 iov at pos 4");
    check(lseek(vfd, 0, SEEK_CUR) == 0, "pwritev leaves file pos");
    char d1[4] = {0}, d2[4] = {0}, d3[4] = {0};
    struct iovec riov[3] = {
        {d1, 3}, {d2, 3}, {d3, 4}
    };
    long rd = syscall(SYS_preadv, vfd, riov, 3, 4);
    check(rd == 10, "preadv round-trip len");
    check(memcmp(d1, "one", 3) == 0 && memcmp(d3, "tri\0", 4) == 0,
          "preadv round-trip data");
    // offset-4 prefix bytes untouched by the vec write
    check(lseek(vfd, 0, SEEK_END) == 14, "vec write extends to 14");
    errno = 0;
    r = syscall(SYS_preadv, vfd, riov, 3, -1L);
    check(r == -1 && errno == EINVAL, "preadv pos<0 EINVAL");
    errno = 0;
    r = syscall(SYS_pwritev, vfd, (void *)0x100, 3, 0);
    check(r == -1 && errno == EINVAL, "pwritev bad iov EINVAL");
    errno = 0;
    r = syscall(SYS_pwritev, vfd, iov, 0, 0);
    check(r == 0, "pwritev cnt 0 -> 0");
    close(vfd);
    unlink("/tmp_fa_v");

    // --- get/setpriority: inert nice pair
    errno = 0;
    long g = syscall(SYS_getpriority, 0, 0); // PRIO_PROCESS, self
    check(g == 20, "getpriority self = 20 (nice 0)");
    errno = 0;
    r = syscall(SYS_setpriority, 0, 0, 5);
    check(r == 0, "setpriority self inert ok");
    errno = 0;
    r = syscall(SYS_getpriority, 3, 0);
    check(r == -1 && errno == EINVAL, "getpriority which>2 EINVAL");
    errno = 0;
    r = syscall(SYS_setpriority, 3, 0, 5);
    check(r == -1 && errno == EINVAL, "setpriority which>2 EINVAL");
    errno = 0;
    r = syscall(SYS_getpriority, 0, 999999);
    check(r == -1 && errno == ESRCH, "getpriority dead pid ESRCH");
    errno = 0;
    r = syscall(SYS_setpriority, 0, 999999, 5);
    check(r == -1 && errno == ESRCH, "setpriority dead pid ESRCH");

    // --- sethostname / setdomainname: live utsname fields
    struct utsname u;
    check(uname(&u) == 0, "uname before set");
    check(strcmp(u.nodename, "rustux") == 0, "default nodename");
    check(strcmp(u.domainname, "(none)") == 0, "default domainname");
    const char hn[] = "testbox";
    errno = 0;
    check(syscall(SYS_sethostname, hn, 7) == 0, "sethostname ok");
    errno = 0;
    check(syscall(SYS_setdomainname, "lab", 3) == 0, "setdomainname ok");
    check(uname(&u) == 0, "uname after set");
    check(strcmp(u.nodename, "testbox") == 0, "nodename changed");
    check(strcmp(u.domainname, "lab") == 0, "domainname changed");
    errno = 0;
    r = syscall(SYS_sethostname, hn, 65);
    check(r == -1 && errno == EINVAL, "sethostname len>64 EINVAL");
    errno = 0;
    r = syscall(SYS_sethostname, (void *)0x100, 4);
    check(r == -1 && errno == EFAULT, "sethostname bad ptr EFAULT");
    // restore so other tests see a stable nodename
    const char rst[] = "rustux";
    syscall(SYS_sethostname, rst, 6);
    const char dft[] = "(none)";
    syscall(SYS_setdomainname, dft, 6);

    printf("fatest: %d failures\n", fails);
    return fails;
}
