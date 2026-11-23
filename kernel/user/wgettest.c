// wgettest — real busybox wget through QEMU slirp: the guest libc
// resolver reads /etc/resolv.conf -> nameserver 10.0.2.3, resolves
// deb.debian.org, opens TCP :80 and the HTTP body lands in a VFile
// via O_CREAT. Skips cleanly on a NIC-less boot like nettest does.
// Exit status = failure count (0 also when skipped).
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

static int fails;

static void say(const char *s) {
    if (write(1, s, strlen(s)) < 0) { /* ignore */ }
}

static void check(int ok, const char *what) {
    char buf[96];
    snprintf(buf, sizeof(buf), "wgettest: %-34s %s\n",
             what, ok ? "ok" : "FAIL");
    say(buf);
    if (!ok) fails++;
}

/* One UDP datagram to slirp's resolver — EHOSTUNREACH means no NIC,
   so the whole test skips the same way nettest does. */
static int nic_up(void) {
    int u = socket(AF_INET, SOCK_DGRAM, 0);
    if (u < 0) return 0;
    struct sockaddr_in dns = {
        .sin_family = AF_INET,
        .sin_port = htons(53),
        .sin_addr.s_addr = htonl(0x0a000203), /* 10.0.2.3 */
    };
    int r = sendto(u, "x", 1, 0, (struct sockaddr *)&dns, sizeof(dns));
    close(u);
    return r >= 0;
}

/* Run busybox with the given argv; wait for exit code. */
static int bb_run(char *const argv[]) {
    pid_t pid = fork();
    if (pid == 0) {
        execve("/busybox", argv, NULL);
        _exit(127);
    }
    if (pid < 0) return -1;
    int st = 0;
    waitpid(pid, &st, 0);
    return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
}

int main(void) {
    say("wgettest: busybox wget over slirp\n");

    if (!nic_up()) {
        say("wgettest: no nic — skip (run-net attaches e1000e)\n");
        return 0;
    }

    /* The real fetch: DNS via resolv.conf, TCP :80, O_CREAT output. */
    unlink("/wget_out");
    char *a[] = {"wget", "-T", "15", "-q", "-O", "/wget_out",
                 "http://deb.debian.org/debian/", NULL};
    int code = bb_run(a);
    check(code == 0, "wget exit 0");

    int f = open("/wget_out", O_RDONLY);
    check(f >= 0, "wget_out created");
    if (f < 0) {
        say("wgettest: done\n");
        return fails;
    }
    char buf[8192];
    ssize_t n = read(f, buf, sizeof(buf) - 1);
    close(f);
    if (n < 0) n = 0;
    buf[n] = 0;
    check(n > 100, "wget body received");
    check(strstr(buf, "Index of /debian") != NULL,
          "index page marker");

    char lb[96];
    snprintf(lb, sizeof(lb), "wgettest: %zd bytes from deb.debian.org\n", n);
    say(lb);

    unlink("/wget_out");
    snprintf(lb, sizeof(lb), "wgettest: %d failures, done\n", fails);
    say(lb);
    return fails;
}
