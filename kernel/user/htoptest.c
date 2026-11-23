// htoptest — real htop smoke run: spawn the Debian htop 3.x binary
// (dynamic, ncursesw) with TERM=xterm, feed 'q' on a pipe'd stdin
// after a draw interval, and require a clean ncurses lifecycle exit.
// Proves: ELF/ld.so loading of libncursesw+libtinfo+libm+libnl,
// terminfo lookup, /proc scraping, TIOCGWINSZ, and the fbcon escape
// engine surviving a full screen paint. Exit status = failure count.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int fails;

static void say(const char *s) {
    if (write(1, s, strlen(s)) < 0) { /* ignore */ }
}

static void check(int ok, const char *what) {
    char buf[96];
    int n = snprintf(buf, sizeof(buf), "htoptest: %-30s %s\n",
                     what, ok ? "ok" : "FAIL");
    say(buf);
    if (!ok) fails++;
}

int main(void) {
    say("htoptest: real htop run\n");

    /* htop reads keys from fd 0; a pipe gives us scripted input while
       stdout/stderr stay on the console (the tty it measures). */
    int pfd[2];
    check(pipe(pfd) == 0, "pipe");

    pid_t pid = fork();
    check(pid >= 0, "fork htop");
    if (pid == 0) {
        dup2(pfd[0], 0);
        close(pfd[0]);
        close(pfd[1]);
        setenv("TERM", "xterm", 1);
        setenv("TERMINFO", "/usr/share/terminfo", 1);
        setenv("HOME", "/", 1);
        setenv("PATH", "/bin", 1);
        char *argv[] = { "/bin/htop", NULL };
        execv(argv[0], argv);
        /* exec failed — report via exit code the parent can see */
        _exit(127);
    }
    close(pfd[0]);

    /* Let ncurses init + paint a few frames, then quit like a user. */
    struct timespec ts = { .tv_sec = 2, .tv_nsec = 0 };
    nanosleep(&ts, NULL);
    ssize_t w = write(pfd[1], "q", 1);
    check(w == 1, "sent q");
    close(pfd[1]);

    int st = 0;
    pid_t wpid = waitpid(pid, &st, 0);
    check(wpid == pid, "waitpid htop");
    if (wpid == pid) {
        if (WIFEXITED(st)) {
            char buf[80];
            int n = snprintf(buf, sizeof(buf),
                             "htoptest: htop exited %d\n", WEXITSTATUS(st));
            say(buf);
            check(WEXITSTATUS(st) == 0, "htop clean exit");
        } else {
            check(0, "htop clean exit");
        }
    }

    /* htop persists ~/.config/htop/htoprc on clean exit (HOME=/). The
       flat VFS is kernel-lifetime — drop the file so its data frames
       don't read as a leak in the suite's frame accounting. */
    unlink("/.config/htop/htoprc");

    char buf[64];
    int m = snprintf(buf, sizeof(buf),
                     "htoptest: %d failures, done\n", fails);
    (void)m;
    say(buf);
    return fails;
}
