// debtest — real Debian package install path: busybox dpkg-deb -x
// unpacks a genuine .deb (ar container + xz-compressed data.tar)
// into /pkgout, then we exec the freshly installed dynamic binary
// and check its output. Exercises the tree the installer needs:
// mkdir of ~95 nested dirs, O_CREAT file writes, chmod modes,
// sendfile/read-write payload copies — then rm -rf cleanup so the
// suite's frame accounting stays at zero leak.
// Exit status = failure count.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static int fails;

static void say(const char *s) {
    if (write(1, s, strlen(s)) < 0) { /* ignore */ }
}

static void check(int ok, const char *what) {
    char buf[96];
    snprintf(buf, sizeof(buf), "debtest: %-40s %s\n",
             what, ok ? "ok" : "FAIL");
    say(buf);
    if (!ok) fails++;
}

/* Run busybox with argv; return the exit code. */
static int bb(char *const argv[]) {
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
    say("debtest: dpkg-deb extract + run installed binary\n");

    /* The install: ar header walk, in-process xz decode, mkdir of
       the package's nested dir tree, O_CREAT + chmod per member. */
    char *a[] = {"dpkg-deb", "-x",
                 "/hello-traditional_2.10-6_amd64.deb",
                 "/pkgout", NULL};
    int rc = bb(a);
    check(rc == 0, "dpkg-deb -x exit 0");

    /* The installed program is there with its mode applied. */
    struct stat sb;
    check(stat("/pkgout/usr/bin/hello", &sb) == 0, "usr/bin/hello exists");
    check((sb.st_mode & 0111) != 0, "usr/bin/hello is executable");

    /* Run it through a pipe — hello is DYNAMIC, so this also proves
       an extracted binary loads via the staged /lib64 ld.so + libc. */
    int pfd[2];
    check(pipe(pfd) == 0, "capture pipe");
    pid_t pid = fork();
    check(pid >= 0, "fork hello");
    if (pid == 0) {
        dup2(pfd[1], 1);
        close(pfd[0]);
        close(pfd[1]);
        char *h[] = {"/pkgout/usr/bin/hello", NULL};
        execve(h[0], h, NULL);
        _exit(127);
    }
    close(pfd[1]);
    char out[256];
    ssize_t n = read(pfd[0], out, sizeof(out) - 1);
    close(pfd[0]);
    if (n < 0) n = 0;
    out[n] = 0;
    int st = 0;
    waitpid(pid, &st, 0);
    check(WIFEXITED(st) && WEXITSTATUS(st) == 0, "hello exit 0");
    check(strstr(out, "Hello, world!") != NULL, "hello prints greeting");
    if (!strstr(out, "Hello, world!")) {
        say("debtest: hello output was: ");
        say(out);
        say("\n");
    }

    /* Cleanup — every extracted file+dir back out of the flat VFS
       so reap's frame accounting sees zero growth. rm -rf walks
       getdents + unlinkat/AT_REMOVEDIR the way real users do. */
    char *r[] = {"rm", "-rf", "/pkgout", NULL};
    check(bb(r) == 0, "rm -rf /pkgout");
    check(stat("/pkgout/usr/bin/hello", &sb) != 0 && errno == ENOENT,
          "extracted tree removed");

    char lb[80];
    snprintf(lb, sizeof(lb), "debtest: %d failures, done\n", fails);
    say(lb);
    return fails;
}
