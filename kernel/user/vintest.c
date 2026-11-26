// vintest — compiled virtio-input ABI proof: /dev/input/event0
// (char 13:64) carrying EV_KEY records drained from the
// virtio-input eventq (QEMU virtio-keyboard-pci fed by QMP
// send-key taps from tools/kbdfeed.py — "shift" taps every 300ms,
// chosen because a modifier makes evdev records but no tty bytes).
// The i8042 path also reports the taps, so this proves the evdev
// end-to-end; the virtio queue itself is proven kernel-side by
// the VIN_EVENTS counter in vinput_selftest. Same check()
// convention as iotest — exit status is the failure count.
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <poll.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>

#define KEY_LEFTSHIFT 42
#define EV_KEY 1

static int fails;

static void say(const char *s) {
    if (write(1, s, strlen(s)) < 0) { /* ignore */ }
}

static void check(int ok, const char *what) {
    char buf[80];
    int n = snprintf(buf, sizeof(buf), "vintest: %-28s %s\n",
                     what, ok ? "ok" : "FAIL");
    say(buf);
    if (!ok) fails++;
}

int main(void) {
    struct stat st;
    struct pollfd pfd;
    char buf[24 * 8], tiny[8];
    int fd, n, i, saw_press = 0, saw_release = 0;

    fd = open("/dev/input/event0", O_RDONLY);
    check(fd >= 0, "open event0");
    if (fd < 0) {
        printf("vintest: %d failures, done\n", fails);
        return fails;
    }
    check(fstat(fd, &st) == 0, "fstat event0");
    check(S_ISCHR(st.st_mode), "mode is S_IFCHR");
    check(major(st.st_rdev) == 13 && minor(st.st_rdev) == 64,
          "rdev 13:64");

    // Sub-record read is EINVAL on a real evdev node.
    check(read(fd, tiny, sizeof(tiny)) == -1 && errno == EINVAL,
          "short read EINVAL");

    // kbdfeed taps shift from host t=0; QEMU drops taps sent before
    // the guest posts eventq buffers, later ones land. Poll a wide
    // window, then read the queued records.
    memset(&pfd, 0, sizeof(pfd));
    pfd.fd = fd;
    pfd.events = POLLIN;
    check(poll(&pfd, 1, 8000) == 1 && (pfd.revents & POLLIN),
          "poll POLLIN on input");

    memset(buf, 0, sizeof(buf));
    n = read(fd, buf, sizeof(buf));
    check(n > 0 && n % 24 == 0, "read whole input_event records");
    if (n > 0) {
        for (i = 0; i + 24 <= n; i += 24) {
            uint16_t ty, code;
            int32_t val;
            memcpy(&ty, buf + i + 16, 2);
            memcpy(&code, buf + i + 18, 2);
            memcpy(&val, buf + i + 20, 4);
            if (ty == EV_KEY && code == KEY_LEFTSHIFT && val == 1)
                saw_press = 1;
            if (ty == EV_KEY && code == KEY_LEFTSHIFT && val == 0)
                saw_release = 1;
        }
    }
    check(saw_press, "KEY_LEFTSHIFT press arrived");
    check(saw_release, "KEY_LEFTSHIFT release arrived");

    close(fd);
    printf("vintest: %d failures, done\n", fails);
    return fails;
}
