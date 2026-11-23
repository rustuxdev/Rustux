// demomenu — Rustux demo pid1: boot menu + raw-disk installer.
//
// Live mode drops into a real shell (fork/exec/waitpid — pid1
// loops back to the menu when the shell exits). Install mode
// streams /hd.img — a ready-made FAT boot image — to /dev/sda
// sector-by-sector, verifies the first sector back, then reboots.
// Running from CD/ESP the pair exists; on an installed boot /hd.img
// is gone and the option hides itself.

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#define IMG_PATH "/hd.img"
#define SD_PATH "/dev/sda"

static void banner(void)
{
    printf("\n");
    printf("  ____            _              \n");
    printf(" |  _ \\ _   _ ___| |_ _   ___  __\n");
    printf(" | |_) | | | / __| __| | | \\ \\/ /\n");
    printf(" |  _ <| |_| \\__ \\ |_| |_| |>  < \n");
    printf(" |_| \\_\\\\__,_|___/\\__|\\__,_/_/\\_\\\n");
    printf("\n");
    printf(" a Linux-compatible kernel in Rust — demo media\n");
    printf("\n");
}

static void live_shell(void)
{
    pid_t p = fork();
    if (p == 0) {
        execl("/bin/sh", "sh", NULL);
        printf("demomenu: exec /bin/sh: %s\n", strerror(errno));
        _exit(127);
    }
    if (p < 0) {
        printf("demomenu: fork: %s\n", strerror(errno));
        return;
    }
    int st;
    while (waitpid(p, &st, 0) < 0 && errno == EINTR)
        ;
    printf("\n(demomenu: shell exited, back to the menu)\n");
}

// Copy `n` bytes img->sd in 64 KiB chunks with a progress line.
static int copy_image(int img, int sd, off_t n)
{
    static char buf[64 * 1024];
    off_t done = 0;
    while (done < n) {
        ssize_t r = read(img, buf, sizeof buf);
        if (r <= 0) {
            printf("install: read %s: %s\n", IMG_PATH,
                   r < 0 ? strerror(errno) : "short file");
            return -1;
        }
        for (ssize_t w = 0; w < r;) {
            ssize_t k = write(sd, buf + w, r - w);
            if (k <= 0) {
                printf("install: write %s: %s\n", SD_PATH, strerror(errno));
                return -1;
            }
            w += k;
        }
        done += r;
        if ((done & (4 * 1024 * 1024 - 1)) == 0 || done == n)
            printf("install: %lld / %lld MiB\n",
                   (long long)(done >> 20), (long long)(n >> 20));
    }
    return 0;
}

static void install(void)
{
    int img = open(IMG_PATH, O_RDONLY);
    if (img < 0) {
        printf("install: open %s: %s\n", IMG_PATH, strerror(errno));
        return;
    }
    struct stat st;
    if (fstat(img, &st) < 0 || st.st_size <= 0) {
        printf("install: fstat %s failed\n", IMG_PATH);
        close(img);
        return;
    }
    int sd = open(SD_PATH, O_RDWR);
    if (sd < 0) {
        printf("install: open %s: %s\n", SD_PATH, strerror(errno));
        close(img);
        return;
    }
    printf("install: writing %lld MiB image to %s ...\n",
           (long long)(st.st_size >> 20), SD_PATH);
    if (lseek(sd, 0, SEEK_SET) < 0 || copy_image(img, sd, st.st_size) < 0) {
        close(img);
        close(sd);
        return;
    }
    // Verify: the first sector on disk must match the image's.
    char a[512], b[512];
    int ok = lseek(sd, 0, SEEK_SET) == 0 && read(sd, a, 512) == 512
        && lseek(img, 0, SEEK_SET) == 0 && read(img, b, 512) == 512
        && memcmp(a, b, 512) == 0;
    printf("install: verify first sector: %s\n", ok ? "ok" : "MISMATCH");
    close(img);
    close(sd);
    if (!ok)
        return;
    sync();
    printf("install: complete — rebooting into the installed system\n");
    sleep(1);
    reboot(RB_AUTOBOOT);
    printf("install: reboot: %s\n", strerror(errno));
}

int main(void)
{
    banner();
    for (;;) {
        int can_install = access(IMG_PATH, R_OK) == 0
            && access(SD_PATH, R_OK | W_OK) == 0;
        printf("[1] live session\n");
        if (can_install)
            printf("[2] install Rustux to disk\n");
        printf("> ");
        fflush(stdout);
        char line[64];
        if (!fgets(line, sizeof line, stdin)) {
            sleep(1);
            continue;
        }
        switch (line[0]) {
        case '1':
            live_shell();
            break;
        case '2':
            if (can_install)
                install();
            break;
        default:
            break;
        }
        printf("\n");
    }
}
