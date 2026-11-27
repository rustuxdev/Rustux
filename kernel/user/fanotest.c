// fanotest — compiled fanotify ABI proof (run-343):
// fanotify_init(NOTIF|REPORT_FID) mints an anon-inode group fd;
// fanotify_mark(ADD, INODE) subscribes a file and a dir
// (+EVENT_ON_CHILD); open/read/write/close each fire an event;
// every event is metadata(24B) + a FID info record (fsid +
// file_handle, fd==-1, pid==caller); read drains whole blobs,
// poll reports POLLIN, and a full ring surfaces FAN_Q_OVERFLOW
// as a bare 24-byte metadata record.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef SYS_fanotify_init
#define SYS_fanotify_init 300
#define SYS_fanotify_mark 301
#endif

#define FAN_CLOEXEC          0x1
#define FAN_NONBLOCK         0x2
#define FAN_CLASS_CONTENT    0x4
#define FAN_UNLIMITED_QUEUE  0x10
#define FAN_REPORT_FID       0x200

#define FAN_MARK_ADD         0x01
#define FAN_MARK_REMOVE      0x02
#define FAN_MARK_ONLYDIR     0x08
#define FAN_MARK_MOUNT       0x10
#define FAN_MARK_FLUSH       0x80
#define FAN_MARK_FILESYSTEM  0x100
#define FAN_MARK_INODE       0x00

#define FAN_ACCESS           0x1
#define FAN_MODIFY           0x2
#define FAN_CLOSE_WRITE      0x8
#define FAN_CLOSE_NOWRITE    0x10
#define FAN_OPEN             0x20
#define FAN_Q_OVERFLOW       0x4000
#define FAN_ONDIR            0x40000000ULL
#define FAN_EVENT_ON_CHILD   0x08000000ULL

#define FAN_INFO_FID         2
#define FAN_NOFD             -1

struct fan_meta {
    uint32_t event_len;
    uint8_t vers, res;
    uint16_t metadata_len;
    uint64_t mask;
    int32_t fd, pid;
};

static int fails;

static void say(const char *s) {
    if (write(1, s, strlen(s)) < 0) { /* ignore */ }
}

static void check(int ok, const char *what) {
    char buf[96];
    int n = snprintf(buf, sizeof(buf), "fanotest: %-38s %s\n",
                     what, ok ? "ok" : "FAIL");
    say(buf);
    if (!ok) fails++;
}

static int f_init(unsigned flags, unsigned ef) {
    return syscall(SYS_fanotify_init, flags, ef);
}
static int f_mark(int fd, unsigned mf, uint64_t mask, int dfd,
                  const char *path) {
    return syscall(SYS_fanotify_mark, fd, mf, mask, dfd, path);
}

/* Walk one read blob; returns OR of every event mask seen, and
 * sets *fid_ok false if any record is malformed. */
static uint64_t drain(const char *buf, int n, int *fid_ok) {
    uint64_t seen = 0;
    int off = 0;
    while (off + 24 <= n) {
        const struct fan_meta *m = (const struct fan_meta *)(buf + off);
        if (m->event_len < 24 || m->event_len > (uint32_t)(n - off)) {
            *fid_ok = 0;
            return seen;
        }
        seen |= m->mask;
        if (m->mask & FAN_Q_OVERFLOW) {
            if (m->event_len != 24 || m->fd != -1) *fid_ok = 0;
        } else {
            const uint8_t *info = (const uint8_t *)m + 24;
            /* info hdr: type u8, pad u8, len u16 — len covers the
             * whole record including its own header. */
            if (info[0] != FAN_INFO_FID) *fid_ok = 0;
            uint16_t ilen = info[2] | (info[3] << 8);
            if (24 + ilen > m->event_len || ilen < 20) *fid_ok = 0;
            /* hdr(4) + fsid(8) then file_handle{bytes, type} */
            uint32_t hbytes =
                info[12] | (info[13] << 8) | (info[14] << 16)
                | ((uint32_t)info[15] << 24);
            int32_t htype =
                info[16] | (info[17] << 8) | (info[18] << 16)
                | ((uint32_t)info[19] << 24);
            if (hbytes == 0 || hbytes > 129 || htype <= 0)
                *fid_ok = 0;
        }
        if (m->vers != 3 || m->metadata_len != 24 || m->fd != -1)
            *fid_ok = 0;
        off += m->event_len;
    }
    return seen;
}

int main(void) {
    char buf[8192];
    int n;

    // ---- init gates ----
    check(f_init(FAN_CLASS_CONTENT | FAN_REPORT_FID, O_RDONLY) < 0
          && errno == EOPNOTSUPP, "CONTENT class EOPNOTSUPP");
    check(f_init(0, O_RDONLY) < 0 && errno == EOPNOTSUPP,
          "no-FID group EOPNOTSUPP");
    check(f_init(FAN_REPORT_FID, O_WRONLY) < 0 && errno == EINVAL,
          "O_WRONLY event fd EINVAL");
    check(f_init(FAN_REPORT_FID | 0x80000000, O_RDONLY) < 0
          && errno == EINVAL, "unknown flag EINVAL");
    int g = f_init(FAN_REPORT_FID | FAN_NONBLOCK | FAN_UNLIMITED_QUEUE,
                   O_RDONLY);
    check(g >= 0, "init NOTIF|FID|NONBLOCK");

    // ---- fd shape ----
    struct stat st;
    check(fstat(g, &st) == 0 && S_ISCHR(st.st_mode),
          "fstat anon_inode chr");
    n = snprintf(buf, sizeof(buf), "/proc/self/fd/%d", g);
    char link[128];
    n = readlink(buf, link, sizeof(link) - 1);
    if (n > 0) link[n] = 0;
    check(n > 0 && strcmp(link, "anon_inode:[fanotify]") == 0,
          "fd link anon_inode:[fanotify]");
    check(write(g, "x", 1) < 0 && errno == EINVAL, "write EINVAL");
    check(read(g, buf, 8) < 0 && errno == EINVAL,
          "undersized read EINVAL");
    check(read(g, buf, sizeof(buf)) < 0 && errno == EAGAIN,
          "empty nonblock EAGAIN");

    // ---- mark gates ----
    check(f_mark(0, FAN_MARK_ADD, FAN_OPEN, FAN_NOFD, "fanotest_file")
          < 0 && errno == EINVAL, "mark on non-group EINVAL");
    check(f_mark(g, FAN_MARK_ADD | FAN_MARK_REMOVE, FAN_OPEN,
                 FAN_NOFD, "fanotest_file") < 0 && errno == EINVAL,
          "ADD|REMOVE EINVAL");
    check(f_mark(g, FAN_MARK_ADD | FAN_MARK_MOUNT, FAN_OPEN,
                 FAN_NOFD, "fanotest_file") < 0
          && errno == EOPNOTSUPP, "MOUNT type EOPNOTSUPP");
    check(f_mark(g, FAN_MARK_ADD, 0, FAN_NOFD, "fanotest_file")
          < 0 && errno == EINVAL, "empty mask EINVAL");
    check(f_mark(g, FAN_MARK_ADD, FAN_OPEN, FAN_NOFD,
                 "fanotest_nothere") < 0 && errno == ENOENT,
          "missing path ENOENT");

    // ---- file events ----
    int f = open("fanotest_file", O_CREAT | O_RDWR, 0600);
    check(f >= 0, "create fanotest_file");
    if (f >= 0) { write(f, "hi", 2); close(f); }
    uint64_t all = FAN_OPEN | FAN_ACCESS | FAN_MODIFY
                 | FAN_CLOSE_WRITE | FAN_CLOSE_NOWRITE;
    check(f_mark(g, FAN_MARK_ADD, all, FAN_NOFD, "fanotest_file")
          == 0, "mark ADD file");
    f = open("fanotest_file", O_RDWR);
    write(f, "xy", 2);
    lseek(f, 0, SEEK_SET);
    char rd[4];
    read(f, rd, 2);
    struct pollfd pfd = { .fd = g, .events = POLLIN };
    check(poll(&pfd, 1, 0) == 1 && (pfd.revents & POLLIN),
          "poll POLLIN with queued events");
    int fid_ok = 1;
    uint64_t seen = 0;
    close(f);
    while ((n = read(g, buf, sizeof(buf))) > 0)
        seen |= drain(buf, n, &fid_ok);
    check(fid_ok, "event records well-formed (meta+FID)");
    check((seen & FAN_OPEN) && (seen & FAN_MODIFY)
          && (seen & FAN_ACCESS) && (seen & FAN_CLOSE_WRITE),
          "OPEN+ACCESS+MODIFY+CLOSE_WRITE fired");
    check(!(seen & FAN_ONDIR), "file events have no ONDIR");

    // ---- dir mark + EVENT_ON_CHILD ----
    mkdir("fanodir", 0700);
    f = open("fanodir/kid", O_CREAT | O_RDWR, 0600);
    if (f >= 0) close(f);
    check(f_mark(g, FAN_MARK_ADD, FAN_OPEN | FAN_EVENT_ON_CHILD,
                 FAN_NOFD, "fanodir") == 0,
          "mark ADD dir+ON_CHILD");
    f = open("fanodir/kid", O_RDONLY);
    if (f >= 0) close(f);
    f = open("fanodir", O_RDONLY | O_DIRECTORY);
    if (f >= 0) close(f);
    fid_ok = 1;
    seen = 0;
    while ((n = read(g, buf, sizeof(buf))) > 0)
        seen |= drain(buf, n, &fid_ok);
    check(fid_ok, "dir events well-formed");
    check((seen & FAN_OPEN) != 0, "child OPEN fired");
    check((seen & FAN_ONDIR) != 0, "dir-self OPEN has ONDIR");

    // ---- REMOVE ----
    check(f_mark(g, FAN_MARK_REMOVE, all, FAN_NOFD,
                 "fanotest_file") == 0, "mark REMOVE");
    check(f_mark(g, FAN_MARK_REMOVE, all, FAN_NOFD,
                 "fanotest_file") < 0 && errno == ENOENT,
          "second REMOVE ENOENT");

    // ---- overflow ring ----
    check(f_mark(g, FAN_MARK_ADD, FAN_OPEN | FAN_CLOSE_NOWRITE,
                 FAN_NOFD, "fanotest_file") == 0, "mark ADD again");
    for (int i = 0; i < 12; i++) {
        f = open("fanotest_file", O_RDONLY);
        if (f >= 0) close(f);   /* 2 events per cycle -> 24 > 16 */
    }
    fid_ok = 1;
    int saw_ovf = 0;
    while ((n = read(g, buf, sizeof(buf))) > 0) {
        uint64_t s = drain(buf, n, &fid_ok);
        if (s & FAN_Q_OVERFLOW) saw_ovf = 1;
    }
    check(fid_ok, "overflow-era records well-formed");
    check(saw_ovf, "Q_OVERFLOW after 16-event ring fills");

    // ---- FLUSH ----
    check(f_mark(g, FAN_MARK_ADD | FAN_MARK_FLUSH, FAN_OPEN,
                 FAN_NOFD, "fanotest_file") < 0 && errno == EINVAL,
          "ADD|FLUSH combo EINVAL");
    check(f_mark(g, FAN_MARK_FLUSH, 0, FAN_NOFD,
                 "fanotest_file") == 0, "mark FLUSH");
    f = open("fanotest_file", O_RDONLY);
    if (f >= 0) close(f);
    check(read(g, buf, sizeof(buf)) < 0 && errno == EAGAIN,
          "no events after FLUSH");

    close(g);
    unlink("fanotest_file");
    unlink("fanodir/kid");
    rmdir("fanodir");

    n = snprintf(buf, sizeof(buf), "fanotest: %d failure(s)\n",
                 fails);
    say(buf);
    return fails;
}
