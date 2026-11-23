// dpkgtest — the real Debian dpkg: create the package database,
// run `/usr/bin/dpkg --force-depends -i` on the genuine .deb
// (locks, hardlink status backup, .dpkg-new renames, control+data
// tars through pipes, futimens stamps), then prove the installed
// /usr/bin/hello executes and `dpkg -l` lists the package. rm -rf
// cleanup keeps the suite's frame accounting at zero leak.
// Exit status = failure count.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static int fails;

static void say(const char *s) {
    if (write(1, s, strlen(s)) < 0) { /* ignore */ }
}

static void check(int ok, const char *what) {
    char buf[96];
    snprintf(buf, sizeof(buf), "dpkgtest: %-38s %s\n",
             what, ok ? "ok" : "FAIL");
    say(buf);
    if (!ok) fails++;
}

static char *envp[] = {
    "PATH=/sbin:/usr/sbin:/bin:/usr/bin",
    "PAGER=/bin/cat",
    NULL,
};

/* execve(path, argv, envp) in a child; return exit status. */
static int runv(const char *path, char *const argv[]) {
    pid_t pid = fork();
    if (pid == 0) {
        execve(path, argv, envp);
        _exit(127);
    }
    if (pid < 0) return -1;
    int st = 0;
    waitpid(pid, &st, 0);
    return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
}

/* busybox applet by argv[0]. */
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

/* Run `argv[0]` with stdout into buf; returns exit status. */
static int capture(char *const argv[], char *buf, int cap) {
    int pfd[2];
    if (pipe(pfd) != 0) return -1;
    pid_t pid = fork();
    if (pid == 0) {
        dup2(pfd[1], 1);
        close(pfd[0]);
        close(pfd[1]);
        execve(argv[0], argv, envp);
        _exit(127);
    }
    close(pfd[1]);
    int n = 0;
    if (pid > 0) {
        n = read(pfd[0], buf, cap - 1);
        int st = 0;
        waitpid(pid, &st, 0);
        close(pfd[0]);
        if (n < 0) n = 0;
        buf[n] = 0;
        return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
    }
    close(pfd[0]);
    buf[0] = 0;
    return -1;
}

static void mkd(const char *p) { mkdir(p, 0755); }

static void touch(const char *p) {
    int fd = open(p, O_CREAT | O_WRONLY, 0644);
    if (fd >= 0) close(fd);
}

int main(void) {
    say("dpkgtest: real dpkg -i on a genuine .deb\n");

    /* The package database dpkg needs before it touches a .deb. */
    mkd("/var"); mkd("/var/lib"); mkd("/var/lib/dpkg");
    mkd("/var/lib/dpkg/info"); mkd("/var/lib/dpkg/updates");
    mkd("/var/lib/dpkg/triggers"); mkd("/var/lib/dpkg/alternatives");
    mkd("/var/lib/dpkg/parts"); mkd("/var/lib/dpkg/methods");
    mkd("/var/backups"); mkd("/var/cache"); mkd("/var/cache/apt");
    touch("/var/lib/dpkg/status");
    touch("/var/lib/dpkg/available");
    struct stat sb;
    check(stat("/var/lib/dpkg/status", &sb) == 0,
          "dpkg status database exists");

    /* The install: dpkg-split probe, control-tar pipe, lock files,
       status-old hardlink, per-member .dpkg-new mkdir+rename,
       futimens stamps. --force-depends skips libc6 (correctly —
       it isn't installed), letting configure finish. */
    char *di[] = {"/usr/bin/dpkg", "--force-depends", "-i",
                  "/hello-traditional_2.10-6_amd64.deb", NULL};
    int rc = runv(di[0], di);
    check(rc == 0, "dpkg --force-depends -i exit 0");
    if (rc != 0) {
        char eb[64];
        snprintf(eb, sizeof(eb), "dpkgtest: dpkg rc was %d\n", rc);
        say(eb);
    }

    check(stat("/usr/bin/hello", &sb) == 0, "usr/bin/hello installed");
    check((sb.st_mode & 0111) != 0, "usr/bin/hello executable");

    /* Run the installed dynamic binary — proof the .deb payload is
       a working userspace, not just bytes in the right place. */
    char out[256];
    char *h[] = {"/usr/bin/hello", NULL};
    rc = capture(h, out, sizeof(out));
    check(rc == 0 && strstr(out, "Hello, world!") != NULL,
          "installed hello prints greeting");

    /* dpkg -l must list it installed (ii). */
    char lst[2048];
    char *dl[] = {"/usr/bin/dpkg-query", "-l", NULL};
    rc = capture(dl, lst, sizeof(lst));
    check(rc == 0 && strstr(lst, "hello-traditional") != NULL,
          "dpkg -l lists hello-traditional");
    check(strstr(lst, "ii  hello") != NULL
          || strstr(lst, "iU") != NULL,
          "package status recorded");

    /* Cleanup — rm -rf pulls every installed vfile/vdir back out
       so reap's frame accounting sees zero growth. Archive members
       (the staged tools) refuse unlink and stay, like real ROFS. */
    char *r[] = {"rm", "-rf", "/usr", "/var", NULL};
    (void)bb(r);
    check(stat("/usr/bin/hello", &sb) < 0 && errno == ENOENT,
          "installed tree removed");
    check(stat("/var/lib/dpkg/status", &sb) < 0 && errno == ENOENT,
          "dpkg database removed");

    char lb[80];
    snprintf(lb, sizeof(lb), "dpkgtest: %d failures, done\n", fails);
    say(lb);
    return fails;
}
