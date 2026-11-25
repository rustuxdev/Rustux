// livemenu — Rustux demo pid1: boot menu + raw-disk installer.
//
// Live mode drops into a real shell (exec — pid1 becomes
// loops back to the menu when the shell exits). Install mode
// streams /hd.img — a ready-made FAT boot image — to /dev/sda
// sector-by-sector, verifies the first sector back, then reboots.
// Running from CD/ESP the pair exists; on an installed boot /hd.img
// is gone and the option hides itself.

#include <crypt.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <termios.h>
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

// The directories apt/dpkg expect (mirrors aptprobe's setup) — made
// once per live session so `apt update` works out of the box.
static void apt_dirs(void)
{
    static const char *dirs[] = {
        "/tmp", "/var", "/var/lib", "/var/lib/apt", "/var/lib/apt/lists",
        "/var/lib/apt/lists/partial", "/var/lib/dpkg", "/var/lib/dpkg/info",
        "/var/lib/dpkg/updates", "/var/lib/dpkg/alternatives",
        "/var/lib/dpkg/parts", "/var/lib/dpkg/triggers",
        "/var/cache", "/var/cache/apt", "/var/cache/apt/archives",
        "/var/cache/apt/archives/partial", "/var/log", "/var/log/apt",
        "/etc/apt/sources.list.d", "/etc/apt/preferences.d",
        "/etc/apt/trusted.gpg.d",
    };
    for (size_t i = 0; i < sizeof(dirs) / sizeof(dirs[0]); i++)
        mkdir(dirs[i], 0755);
    chmod("/tmp", 01777);

    // dpkg status must reflect the payload: every .so we ship on the
    // media is "installed", so `apt install <pkg>` resolves to just
    // the leaf instead of trying to overwrite an initrd file (dpkg's
    // backup-link step can't hardlink a cpio entry).
    struct stat st;
    if (stat("/var/lib/dpkg/status", &st) == 0)
        return;
    FILE *f = fopen("/var/lib/dpkg/status", "w");
    if (!f)
        return;
    static const char *pkgs[][2] = {
        {"libc6", "2.36-9+deb12u14"},
        {"libgcc-s1", "12.2.0-14+deb12u1"},
        {"gcc-12-base", "12.2.0-14+deb12u1"},
        {"libidn2-0", "2.3.3-1+b1"},
        {"libunistring2", "1.0-2"},
        {"libncursesw6", "6.4-4"},
        {"libtinfo6", "6.4-4"},
        {"libnl-3-200", "3.7.0-0.2+b1"},
        {"libnl-genl-3-200", "3.7.0-0.2+b1"},
        {"libselinux1", "3.4-1+b6"},
        {"libpcre2-8-0", "10.42-1"},
        {"libacl1", "2.3.1-3"},
        {"zlib1g", "1:1.2.13.dfsg-1"},
        {"liblzma5", "5.4.1-0.2"},
        {"libzstd1", "1.5.4+dfsg2-5"},
        {"libbz2-1.0", "1.0.8-5+b1"},
        {"libmd0", "1.0.4-2"},
        {"liblz4-1", "1.9.4-1"},
        {"libxxhash0", "0.8.1-1"},
        {"libstdc++6", "12.2.0-14+deb12u1"},
        {"libsystemd0", "252.30-1~deb12u2"},
        {"libudev1", "252.30-1~deb12u2"},
        {"libcap2", "1:2.66-4"},
        {"libgcrypt20", "1.10.1-3"},
        {"libgpg-error0", "1.46-1"},
        {"libgnutls30", "3.7.9-2+deb12u3"},
        {"libnettle8", "3.8.1-2"},
        {"libhogweed6", "3.8.1-2"},
        {"libgmp10", "2:6.2.1+dfsg1-1.1"},
        {"libp11-kit0", "0.24.1-2"},
        {"libtasn1-6", "4.19.0-2"},
        {"libffi8", "3.4.4-1"},
        {"libseccomp2", "2.5.4-1+deb12u1"},
        {"libassuan0", "2.5.5-5"},
        {"libnpth0", "1.6-3"},
    };
    for (size_t i = 0; i < sizeof(pkgs) / sizeof(pkgs[0]); i++)
        fprintf(f,
                "Package: %s\n"
                "Status: install ok installed\n"
                "Priority: optional\n"
                "Section: libs\n"
                "Installed-Size: 1\n"
                "Maintainer: Rustux demo <root@localhost>\n"
                "Architecture: amd64\n"
                "Multi-Arch: same\n"
                "Version: %s\n"
                "Description: staged on the demo media\n"
                "\n",
                pkgs[i][0], pkgs[i][1]);
    fclose(f);
}

// A passwd/shadow record — the authentic account fields login
// needs: credentials from /etc/shadow, session fields from
// /etc/passwd.
struct acct {
    char name[32];
    char hash[128];
    char home[64];
    char shell[64];
};

// Scan a colon-field file for `user` and copy field `idx` out.
static int field_of(const char *path, const char *user, int idx,
                    char *out, size_t n)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return -1;
    char line[256];
    int ok = -1;
    while (fgets(line, sizeof line, f)) {
        char *save = NULL;
        char *name = strtok_r(line, ":\n", &save);
        if (!name || strcmp(name, user))
            continue;
        char *fld = NULL;
        for (int i = 1; i < idx; i++)
            fld = strtok_r(NULL, ":\n", &save);
        if (fld) {
            snprintf(out, n, "%s", fld);
            ok = 0;
        }
        break;
    }
    fclose(f);
    return ok;
}

static int account(const char *user, struct acct *a)
{
    snprintf(a->name, sizeof a->name, "%s", user);
    // /etc/shadow field 2 is the crypt hash; /etc/passwd carries the
    // session fields (home col 6, shell col 7).
    if (field_of("/etc/shadow", user, 2, a->hash, sizeof a->hash) ||
        field_of("/etc/passwd", user, 6, a->home, sizeof a->home) ||
        field_of("/etc/passwd", user, 7, a->shell, sizeof a->shell))
        return -1;
    return 0;
}

// Read a password with echo off — termios ECHO, restored after.
static void read_secret(char *buf, size_t n)
{
    struct termios t, save;
    int ok = tcgetattr(0, &t) == 0;
    if (ok) {
        save = t;
        t.c_lflag &= ~(tcflag_t)ECHO;
        ok = tcsetattr(0, TCSANOW, &t) == 0;
    }
    if (!ok)
        printf("login: termios unavailable (%s)\n", strerror(errno));
    if (!fgets(buf, (int)n, stdin))
        buf[0] = 0;
    if (ok)
        tcsetattr(0, TCSANOW, &save);
    printf("\n");
    buf[strcspn(buf, "\n")] = 0;
}

// init -> login -> shell: real /etc/passwd + /etc/shadow + crypt
// verification, then exec the account shell. pid 1 runs this, so
// when the shell exits the kernel halts the VM.
static void run_login(void)
{
    apt_dirs();
    for (;;) {
        char user[64], pw[128];
        struct acct a;
        printf("rustux login: ");
        fflush(stdout);
        if (!fgets(user, sizeof user, stdin)) {
            sleep(1);
            continue;
        }
        user[strcspn(user, "\n")] = 0;
        printf("Password: ");
        fflush(stdout);
        read_secret(pw, sizeof pw);
        // Constant-shape failure: unknown user and bad password
        // both land on "Login incorrect" like real login.
        int good = account(user, &a) == 0 && a.hash[0] &&
            strcmp(crypt(pw, a.hash), a.hash) == 0;

        memset(pw, 0, sizeof pw);
        if (!good) {
            printf("Login incorrect\n\n");
            continue;
        }
        setenv("TERM", "xterm", 1);
        setenv("TERMINFO", "/usr/share/terminfo", 1);
        setenv("HOME", a.home, 1);
        setenv("USER", a.name, 1);
        setenv("LOGNAME", a.name, 1);
        setenv("SHELL", a.shell, 1);
        setenv("PATH", "/bin:/sbin:/usr/bin:/usr/sbin", 1);
        chdir(a.home);
        execl(a.shell, a.shell, NULL);
        // Account shell missing is a payload bug — fall back.
        execl("/bin/sh", "sh", NULL);
        printf("login: exec %s: %s\n", a.shell, strerror(errno));
    }
}

// Copy `n` bytes img->sd in 64 KiB chunks with a progress line.
// Reads are looped to fill the buffer — a short read is legal —
// so each write() carries the full 64 KiB: one multi-sector ATA
// command and one cache flush per chunk instead of per-page.
static int copy_image(int img, int sd, off_t n)
{
    static char buf[64 * 1024];
    off_t done = 0;
    while (done < n) {
        size_t got = 0;
        while (got < sizeof buf) {
            ssize_t r = read(img, buf + got, sizeof buf - got);
            if (r < 0) {
                printf("install: read %s: %s\n", IMG_PATH, strerror(errno));
                return -1;
            }
            if (r == 0)
                break;
            got += (size_t)r;
        }
        if (got == 0) {
            printf("install: read %s: short file\n", IMG_PATH);
            return -1;
        }
        for (size_t w = 0; w < got;) {
            ssize_t k = write(sd, buf + w, got - w);
            if (k <= 0) {
                printf("install: write %s: %s\n", SD_PATH, strerror(errno));
                return -1;
            }
            w += (size_t)k;
        }
        done += got;
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
    if (!ok) {
        printf("install: FAILED — disk image did not verify\n");
        return;
    }
    sync();
    // Eject the installation medium like a real installer — after
    // this the reboot lands on the installed disk, not the ISO.
    {
        int cd = open("/dev/sr0", O_RDONLY);
        if (cd >= 0) {
            if (ioctl(cd, 0x5309 /* CDROMEJECT */, 0) == 0)
                printf("install: installation medium ejected\n");
            close(cd);
        }
    }
    printf("\n");
    printf("Rustux has been installed to the disk successfully.\n");
    printf("Remove the installation medium if present, then press\n");
    printf("ENTER to reboot into the installed system.\n");
    fflush(stdout);
    {
        char buf[8];
        if (!fgets(buf, sizeof buf, stdin))
            sleep(1);
    }
    // The installed disk carries a payload-free initrd (no /hd.img),
    // so it boots straight to login. But if the installation medium
    // is still attached the firmware will boot THAT again and the
    // menu reappears — which reads as "the install did nothing".
    printf("\ninstall: done. REMOVE the installation media now.\n");
    printf("install: rebooting in 5s — the disk boots straight to login.\n");
    for (int i = 0; i < 5; i++)
        sleep(1);
    printf("install: rebooting into the installed system\n");
    reboot(RB_AUTOBOOT);
    printf("install: reboot: %s\n", strerror(errno));
}

int main(void)
{
    banner();
    // The menu is installation media only: hd.img is in the initrd
    // solely on the booted ISO. An installed disk has no payload,
    // so skip straight to the init -> login -> shell chain.
    if (access(IMG_PATH, R_OK) != 0)
        run_login();
    for (;;) {
        int can_install = access(SD_PATH, R_OK | W_OK) == 0;
        // Install is the primary action and the default (bare Enter):
        // this is installation media, the live session is the rescue
        // path. The option is always shown — hiding it behind the
        // access() probe made the installer look absent on machines
        // where the node or its mode was unexpected; selecting it now
        // reports the real reason instead.
        printf("[1] install Rustux to disk%s\n",
               can_install ? "" : "  (no writable disk detected)");
        printf("[2] live session\n");
        printf("> ");
        fflush(stdout);
        char line[64];
        if (!fgets(line, sizeof line, stdin)) {
            sleep(1);
            continue;
        }
        switch (line[0]) {
        case '\n':
        case '\r':
        case '1':
            if (can_install) {
                install();
            } else {
                printf("install: no writable disk at %s\n", SD_PATH);
            }
            break;
        case '2':
            run_login();
            break;
        default:
            break;
        }
        printf("\n");
    }
}
