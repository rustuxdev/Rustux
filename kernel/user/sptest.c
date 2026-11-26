// sptest — splice(275) + tee(276) + vmsplice(278) +
// preadv2(327)/pwritev2(328). splice proves file->pipe, pipe->file
// and pipe->pipe byte motion with offset handling; tee proves
// non-consuming pipe->pipe; vmsplice pushes iovecs into a ring.
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <sys/uio.h>

static int fails;
#define check(c, msg) do { \
    if (c) printf("sptest: %-40s ok\n", msg); \
    else { printf("sptest: %-40s FAIL\n", msg); fails++; } \
} while (0)

#ifndef SYS_splice
#define SYS_splice     275
#define SYS_tee        276
#define SYS_vmsplice   278
#define SYS_preadv2    327
#define SYS_pwritev2   328
#endif

int main(void) {
    printf("sptest: splice + tee + vmsplice + pv2\n");

    // --- file -> pipe
    int fd = open("/tmp_sp", O_RDWR | O_CREAT | O_TRUNC, 0600);
    check(fd >= 0, "open /tmp_sp");
    check(write(fd, "0123456789", 10) == 10, "seed 10 bytes");
    check(lseek(fd, 0, SEEK_SET) == 0, "rewind after seed");
    int p[2];
    check(pipe(p) == 0, "pipe");
    errno = 0;
    long n = syscall(SYS_splice, fd, 0, p[1], 0, 5, 0);
    check(n == 5, "splice file->pipe 5 bytes");
    check(lseek(fd, 0, SEEK_CUR) == 5, "splice advanced src pos");
    char rb[16] = {0};
    check(read(p[0], rb, 5) == 5, "pipe holds 5");
    check(memcmp(rb, "01234", 5) == 0, "spliced content");
    // explicit offset pointer: no pos advance, written back
    off_t off = 8;
    n = syscall(SYS_splice, fd, &off, p[1], 0, 2, 0);
    check(n == 2 && off == 10, "off_in used + written back");
    check(lseek(fd, 0, SEEK_CUR) == 5, "off_in leaves pos alone");
    check(read(p[0], rb, 2) == 2 && memcmp(rb, "89", 2) == 0,
          "offset splice content");
    errno = 0;
    n = syscall(SYS_splice, fd, 0, p[1], &off, 2, 0);
    check(n == -1 && errno == ESPIPE, "off_out on pipe -> ESPIPE");
    errno = 0;
    n = syscall(SYS_splice, fd, 0, fd, 0, 2, 0);
    check(n == -1 && errno == EINVAL, "file->file EINVAL");
    errno = 0;
    n = syscall(SYS_splice, fd, 0, p[1], 0, 2, 0x40);
    check(n == -1 && errno == EINVAL, "bad flags EINVAL");
    // EOF
    n = syscall(SYS_splice, fd, 0, p[1], 0, 99, 0);
    check(n == 5, "splice to EOF shorts at avail");
    check(read(p[0], rb, 5) == 5, "drained 5");
    n = syscall(SYS_splice, fd, 0, p[1], 0, 1, 0);
    check(n == 0, "splice at EOF -> 0");
    close(fd); close(p[0]); close(p[1]);
    unlink("/tmp_sp");

    // --- pipe -> file
    int p2[2], fd2 = open("/tmp_sp2", O_RDWR | O_CREAT | O_TRUNC, 0600);
    check(pipe(p2) == 0 && fd2 >= 0, "pipe2 + file2");
    check(write(p2[1], "HELLO", 5) == 5, "fill src pipe");
    n = syscall(SYS_splice, p2[0], 0, fd2, 0, 5, 0);
    check(n == 5, "splice pipe->file");
    check(lseek(fd2, 0, SEEK_CUR) == 5, "pipe->file advanced pos");
    char fb[8] = {0};
    check(pread(fd2, fb, 5, 0) == 5, "readback after pipe->file");
    check(memcmp(fb, "HELLO", 5) == 0, "file got pipe bytes");
    // source was consumed
    int flags0 = fcntl(p2[0], F_GETFL);
    fcntl(p2[0], F_SETFL, flags0 | O_NONBLOCK);
    check(read(p2[0], fb, 1) == -1 && errno == EAGAIN,
          "src pipe consumed");
    fcntl(p2[0], F_SETFL, flags0);
    close(p2[0]); close(p2[1]); close(fd2);
    unlink("/tmp_sp2");

    // --- pipe -> pipe
    int pa[2], pb[2];
    check(pipe(pa) == 0 && pipe(pb) == 0, "two pipes");
    check(write(pa[1], "ABCDEF", 6) == 6, "fill pipe A");
    n = syscall(SYS_splice, pa[0], 0, pb[1], 0, 6, 0);
    check(n == 6, "splice pipe->pipe");
    char pb8[8] = {0};
    check(read(pb[0], pb8, 6) == 6 && memcmp(pb8, "ABCDEF", 6) == 0,
          "pipe->pipe content");
    n = syscall(SYS_splice, pa[0], 0, pa[1], 0, 1, 0);
    check(n == -1 && errno == EINVAL, "same-pipe EINVAL");
    n = syscall(SYS_splice, pa[0], 0, pb[1], 0, 1, 0);
    check(n == 0, "empty src -> 0");
    close(pa[0]); close(pa[1]); close(pb[0]); close(pb[1]);

    // --- tee: duplicate without consuming
    int tc[2], td[2];
    check(pipe(tc) == 0 && pipe(td) == 0, "tee pipes");
    check(write(tc[1], "XYZW", 4) == 4, "fill tee src");
    n = syscall(SYS_tee, tc[0], td[1], 4, 0);
    check(n == 4, "tee duplicates 4");
    check(read(tc[0], pb8, 4) == 4 && memcmp(pb8, "XYZW", 4) == 0,
          "tee source NOT consumed");
    check(read(td[0], pb8, 4) == 4 && memcmp(pb8, "XYZW", 4) == 0,
          "tee dest got copy");
    errno = 0;
    int fd3 = open("/tmp_sp3", O_RDWR | O_CREAT | O_TRUNC, 0600);
    n = syscall(SYS_tee, fd3, td[1], 4, 0);
    check(n == -1 && errno == EINVAL, "tee non-pipe EINVAL");
    close(fd3); unlink("/tmp_sp3");
    close(tc[0]); close(tc[1]); close(td[0]); close(td[1]);

    // --- vmsplice: iovecs into a pipe
    int vp[2];
    check(pipe(vp) == 0, "vmsplice pipe");
    char a1[] = "foo", a2[] = "bar";
    struct iovec viov[2] = {{a1, 3}, {a2, 3}};
    n = syscall(SYS_vmsplice, vp[1], viov, 2, 0);
    check(n == 6, "vmsplice 2 iov");
    check(read(vp[0], pb8, 6) == 6 && memcmp(pb8, "foobar", 6) == 0,
          "vmsplice content");
    errno = 0;
    n = syscall(SYS_vmsplice, vp[0], viov, 2, 0);
    check(n == -1 && errno == EBADF, "vmsplice read end EBADF");
    errno = 0;
    n = syscall(SYS_vmsplice, vp[1], (void *)0x100, 1, 0);
    check(n == -1 && errno == EINVAL, "vmsplice bad iov EINVAL");
    close(vp[0]); close(vp[1]);

    // --- preadv2/pwritev2
    int vfd = open("/tmp_pv2", O_RDWR | O_CREAT | O_TRUNC, 0600);
    check(vfd >= 0, "open pv2");
    char w1[] = "cd", w2[] = "ef";
    struct iovec wiov[2] = {{w1, 2}, {w2, 2}};
    errno = 0;
    n = syscall(SYS_pwritev2, vfd, wiov, 2, -1L, 0);
    check(n == 4, "pwritev2 pos -1 uses file pos");
    check(lseek(vfd, 0, SEEK_CUR) == 4, "pwritev2 -1 advances pos");
    char g1[4] = {0}, g2[4] = {0};
    struct iovec giov[2] = {{g1, 2}, {g2, 2}};
    lseek(vfd, 0, SEEK_SET);
    n = syscall(SYS_preadv2, vfd, giov, 2, -1L, 0);
    check(n == 4 && memcmp(g1, "cd", 2) == 0 && memcmp(g2, "ef", 2) == 0,
          "preadv2 pos -1 read");
    errno = 0;
    n = syscall(SYS_preadv2, vfd, giov, 2, 0, 0x40);
    check(n == -1 && errno == EINVAL, "preadv2 bad flags EINVAL");
    errno = 0;
    n = syscall(SYS_preadv2, vfd, giov, 2, -2L, 0);
    check(n == -1 && errno == EINVAL, "preadv2 pos<-1 EINVAL");
    errno = 0;
    n = syscall(SYS_pwritev2, vfd, wiov, 2, 0, 0x10); // RWF_APPEND
    check(n == 4, "pwritev2 RWF_APPEND");
    check(lseek(vfd, 0, SEEK_END) == 8, "append landed at EOF");
    close(vfd);
    unlink("/tmp_pv2");

    printf("sptest: %d failures\n", fails);
    return fails;
}
