// demodrv — the docs-GIF demo driver: a scripted session that shows
// real GNU bash running on rustux. It runs as the SOLO initrd task
// (make run-demo) and for each demo command prints the interactive
// prompt + "typed" line to the console, then forks real /bin/bash
// -c so every visible byte of output is produced by actual bash
// code paths (fork/exec, job builtins, dynamic ld.so).
//
// Real interactive input works too (run-bash + serial console) —
// this scripted variant exists because headless QEMU 8.2.2 cannot
// feed UART input while a capture channel (monitor/QMP/VNC) is up.
#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/wait.h>

// The rustux console renders one log line per write() call, so the
// prompt + command must go out in a single write to sit on one line —
// no per-char typing animation is possible at the byte level.
static int run(const char *cmd) {
    usleep(450000);
    printf("-bash-5.2# %s\n", cmd);
    fflush(stdout);
    usleep(350000);
    pid_t c = fork();
    if (c == 0) {
        execl("/bin/bash", "bash", "-c", cmd, NULL);
        _exit(127);
    }
    int st;
    waitpid(c, &st, 0);
    usleep(400000);
    return st;
}

int main(void) {
    usleep(300000);
    run("echo GNU bash $BASH_VERSION on rustux");
    run("busybox cat motd.txt");
    run("busybox ls / | busybox cat");
    run("busybox uname -a");
    run("busybox sleep 30 <motd.txt & jobs; kill %1; jobs");
    run("echo tty job control: SIGTTIN SIGTTOU TOSTOP all real");
    usleep(450000);
    printf("-bash-5.2# exit\n");
    fflush(stdout);
    usleep(600000);
    printf("logout\n");
    fflush(stdout);
    usleep(800000);
    return 0;
}
