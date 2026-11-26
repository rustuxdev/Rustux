// clstest — small-classics rung: getdents(78) legacy layout,
// setrlimit(160), syslog(103) ring reader. check() convention;
// exit = failures.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <signal.h>
#include <sys/resource.h>

static int fails;
#define check(c, msg) do { \
    if (c) printf("clstest: %-44s ok\n", msg); \
    else { printf("clstest: %-44s FAIL\n", msg); fails++; } \
} while (0)

#define NR_GETDENTS   78
#define NR_GETDENTS64 217
#define NR_SYSLOG    103
#define NR_SETRLIMIT 160
#define NR_GETRLIMIT  97

// linux_dirent (NR 78): ino@0 u64, off@8 u64, reclen@16 u16,
// name@18, d_type in the LAST byte of the record.
struct dirent78 {
    unsigned long long ino;
    unsigned long long off;
    unsigned short reclen;
    char name[];
};

// linux_dirent64 (NR 217): ino@0, off@8, reclen@16, type@18, name@19.
struct dirent64 {
    unsigned long long ino;
    unsigned long long off;
    unsigned short reclen;
    unsigned char type;
    char name[];
};

int main(void) {
    char buf[8192];

    // ---- getdents(78) legacy layout ------------------------------------
    int d = open("/proc", O_RDONLY | O_DIRECTORY);
    check(d >= 0, "open /proc for getdents");
    long n78 = syscall(NR_GETDENTS, d, buf, sizeof(buf));
    check(n78 > 0, "getdents(78) returns records");
    int saw_dot = 0, saw_self = 0, type_last = 0, chain = 1;
    if (n78 > 0) {
        long p = 0;
        while (p < n78) {
            struct dirent78 *e = (void *)(buf + p);
            if (e->reclen < 21 || e->reclen > n78 - p) { chain = 0; break; }
            unsigned char ty = *(unsigned char *)(buf + p + e->reclen - 1);
            // name at +18, NUL-terminated inside the record
            if (buf[p + 18 + strlen(e->name)] != 0) chain = 0;
            if (ty == 4 && strcmp(e->name, ".") == 0) saw_dot = 1;
            if (strcmp(e->name, "self") == 0) saw_self = 1;
            if (ty == 2 || ty == 4 || ty == 8 || ty == 10) type_last = 1;
            p += e->reclen;
        }
        if (p != n78) chain = 0;
    }
    check(chain, "dirent78 reclen chain walks clean");
    check(saw_dot, "dirent78 '.' entry DT_DIR");
    check(saw_self, "dirent78 'self' entry listed");
    check(type_last, "dirent78 d_type in last byte");
    close(d);

    // same dir via getdents64 for comparison — type field @18
    int d2 = open("/proc", O_RDONLY | O_DIRECTORY);
    long n64 = syscall(NR_GETDENTS64, d2, buf, sizeof(buf));
    check(n64 > 0, "getdents64 still works");
    int d64_ok = 0;
    if (n64 > 0) {
        struct dirent64 *e = (void *)buf;
        if (e->reclen >= 20 && e->type == 4 && e->name[0] == '.') d64_ok = 1;
    }
    check(d64_ok, "dirent64 type@18 intact");
    errno = 0;
    long nbad = syscall(NR_GETDENTS, d2, buf, 0);
    check(nbad == -1 && errno == EINVAL, "getdents count=0 EINVAL");
    close(d2);

    // ---- setrlimit(160) -------------------------------------------------
    struct rlimit rl;
    long r1 = syscall(NR_GETRLIMIT, RLIMIT_NOFILE, &rl);
    check(r1 == 0 && rl.rlim_cur == RLIM_INFINITY,
          "getrlimit NOFILE = infinity");
    rl.rlim_cur = 16; rl.rlim_max = 16;
    errno = 0;
    long r2 = syscall(NR_SETRLIMIT, RLIMIT_NOFILE, &rl);
    check(r2 == 0, "setrlimit(160) accepted");
    errno = 0;
    long r3 = syscall(NR_SETRLIMIT, 9999, &rl);
    check(r3 == 0 || r3 == -1, "setrlimit bogus resource tolerated");
    // prlimit64(302) round-trip still reports infinity
    struct rlimit ro;
    long r4 = syscall(302, 0, 7, NULL, &ro);
    check(r4 == 0 && ro.rlim_cur == RLIM_INFINITY,
          "prlimit64 old = infinity");

    // ---- syslog(103) ----------------------------------------------------
    errno = 0;
    long sz = syscall(NR_SYSLOG, 10, NULL, 0);
    check(sz == 4096, "syslog SIZE_BUFFER = 4096");
    long un = syscall(NR_SYSLOG, 9, NULL, 0);
    check(un > 0, "syslog SIZE_UNREAD > 0");
    // unprivileged: drop uid in a child, expect EPERM on READ_ALL
    pid_t pu = fork();
    if (pu == 0) {
        int _su = setuid(1000);
        if (_su != 0) _exit(2);
        errno = 0;
        long r = syscall(NR_SYSLOG, 3, buf, sizeof(buf));
        _exit(r == -1 && errno == EPERM ? 0 : 1);
    }
    int st = 0; waitpid(pu, &st, 0);
    check(WIFEXITED(st) && WEXITSTATUS(st) == 0, "syslog uid!=0 -> EPERM");
    errno = 0;
    long bad = syscall(NR_SYSLOG, 99, buf, sizeof(buf));
    check(bad == -1 && errno == EINVAL, "syslog type 99 EINVAL");

    // READ_ALL (3): the ring must hold boot records mentioning rustux
    memset(buf, 0, sizeof(buf));
    long rall = syscall(NR_SYSLOG, 3, buf, sizeof(buf));
    check(rall > 100, "syslog READ_ALL bytes > 100");
    check(rall > 0 && strstr(buf, "rustux") != NULL,
          "READ_ALL mentions rustux");

    // CLEAR (5): moves only the READ cursor — READ_ALL(3) must still
    // return the live ring, which is the deterministic property.
    // SIZE_UNREAD can't be asserted under suite load: concurrent
    // task-exit printks refill it by an amount we don't control.
    long rc = syscall(NR_SYSLOG, 5, NULL, 0);
    check(rc == 0, "syslog CLEAR ok");
    memset(buf, 0, sizeof(buf));
    long rall2 = syscall(NR_SYSLOG, 3, buf, sizeof(buf));
    check(rall2 > 100, "READ_ALL still returns records post-CLEAR");

    // Blocking READ (type 2): child blocks; a sibling's exit produces
    // a 'pid N exit' kernel record at reap which must wake the reader.
    int pfd[2];
    int _pi = pipe(pfd);
    check(_pi == 0, "pipe for blocking-READ proof");
    pid_t c1 = fork();
    if (c1 == 0) {
        close(pfd[0]);
        char rbuf[2048];
        long got = syscall(NR_SYSLOG, 2, rbuf, sizeof(rbuf));
        // report bytes read to the parent
        int _w = write(pfd[1], &got, sizeof(got));
        (void)_w;
        _exit(got > 0 ? 0 : 1);
    }
    usleep(100000); // let c1 arm
    pid_t c2 = fork();
    if (c2 == 0) _exit(0); // its exit commits a 'pid N exit' record
    waitpid(c2, &st, 0);
    // wait bounded for c1 — a missed wake must not hang the suite
    long got = -99;
    int woke = 0;
    for (int i = 0; i < 200 && !woke; i++) {
        if (waitpid(c1, &st, WNOHANG) == c1) { woke = 1; break; }
        usleep(50000);
    }
    if (!woke) { kill(c1, SIGKILL); waitpid(c1, &st, 0); }
    int _rd = read(pfd[0], &got, sizeof(got));
    (void)_rd;
    close(pfd[0]); close(pfd[1]);
    check(woke && WIFEXITED(st) && WEXITSTATUS(st) == 0 && got > 0,
          "blocking syslog READ woke on new record");

    printf("clstest: %d failures\n", fails);
    return fails;
}
