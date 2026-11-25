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

#include "mke2.c"

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

// Every lib the payload ships is staged as an installed package in
// /var/lib/dpkg/status — `apt install <pkg>` then resolves to just
// the leaf instead of trying to overwrite an initrd file.
static const char *const BASE_PKGS[][2] = {
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
    for (size_t i = 0; i < sizeof BASE_PKGS / sizeof BASE_PKGS[0]; i++)
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
                BASE_PKGS[i][0], BASE_PKGS[i][1]);
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
        if ((done & (4 * 1024 * 1024 - 1)) == 0 || done == n) {
            printf("install: %lld / %lld MiB\n",
                   (long long)(done >> 20), (long long)(n >> 20));
            // stdout is block-buffered when it is not a tty: without
            // this the progress sits in the buffer and the install
            // looks hung.
            fflush(stdout);
        }
    }
    return 0;
}

// Write an MBR describing one partition. Today the layout matches the
// image (FAT at LBA 0 covering the disk), so nothing that boots
// changes — but the installer now OWNS the partition table, which is
// the hook the layout choice will use (ESP at 1 MiB, root after it).
static void mbr_entry(unsigned char *e, unsigned int start_lba,
                      unsigned long long sectors, unsigned char type, int active)
{
    e[0] = active ? 0x80 : 0x00;
    unsigned int c = start_lba / (255 * 63);
    unsigned int h = (start_lba / 63) % 255;
    unsigned int sec = (start_lba % 63) + 1;
    e[1] = (unsigned char)h;
    e[2] = (unsigned char)(((c >> 2) & 0xc0) | (sec & 0x3f));
    e[3] = (unsigned char)(c & 0xff);
    e[4] = type;
    e[5] = 0xfe; e[6] = 0xff; e[7] = 0xff;   // LBA-only end marker
    for (int i = 0; i < 4; i++)
        e[8 + i] = (unsigned char)((start_lba >> (8 * i)) & 0xff);
    for (int i = 0; i < 4; i++)
        e[12 + i] = (unsigned char)((sectors >> (8 * i)) & 0xff);
}

// mke2's source: absolute byte reads from an open file — lets the
// installer place a 1 MiB binary from the initrd without holding it.
static int file_reader(void *ctx, uint32_t off, void *buf, uint32_t len)
{
    // ctx is the initrd source path — open per call so a large payload
    // never holds more than one fd at a time (MAX_FDS is 16 and the
    // std/img/sd fds already hold five).
    int fd = open((const char *)ctx, O_RDONLY);
    if (fd < 0)
        return 1;
    if (lseek(fd, (off_t)off, SEEK_SET) < 0) {
        close(fd);
        return 1;
    }
    ssize_t r = read(fd, buf, len);
    close(fd);
    return r == (ssize_t)len ? 0 : 1;
}

// mke2's sink: absolute byte writes to the target fd.
static int mke2_sink(void *ctx, uint64_t off, const void *buf, uint32_t len)
{
    int fd = *(int *)ctx;
    if (lseek(fd, (off_t)off, SEEK_SET) < 0)
        return 1;
    return write(fd, buf, len) == (ssize_t)len ? 0 : 1;
}

static int write_mbr2(int sd, unsigned int esp_lba, unsigned long long esp_secs,
                      unsigned int root_lba, unsigned long long root_secs)
{
    unsigned char mbr[512];
    memset(mbr, 0, sizeof mbr);
    mbr_entry(mbr + 446, esp_lba, esp_secs, 0xef, 1);   // ESP, active
    if (root_secs > 0)
        mbr_entry(mbr + 462, root_lba, root_secs, 0x83, 0); // Linux root
    mbr[510] = 0x55;
    mbr[511] = 0xaa;
    if (lseek(sd, 0, SEEK_SET) < 0)
        return -1;
    return write(sd, mbr, 512) == 512 ? 0 : -1;
}

static int write_mbr(int sd, unsigned int start_lba, unsigned long long sectors, unsigned char type)
{
    unsigned char mbr[512];
    memset(mbr, 0, sizeof mbr);
    unsigned char *e = mbr + 446;
    e[0] = 0x80;              // bootable
    // CHS start must agree with the LBA start: some firmware validates
    // the pair. 255 heads / 63 sectors per track.
    unsigned int c = start_lba / (255 * 63);
    unsigned int h = (start_lba / 63) % 255;
    unsigned int sec = (start_lba % 63) + 1;
    e[1] = (unsigned char)h;
    e[2] = (unsigned char)(((c >> 2) & 0xc0) | (sec & 0x3f));
    e[3] = (unsigned char)(c & 0xff);
    e[4] = type;              // 0x06 FAT16, 0x0c FAT32 LBA, 0xef EFI
    e[5] = 0xfe; e[6] = 0xff; e[7] = 0xff;   // CHS end: LBA-only marker
    unsigned int start = start_lba;
    for (int i = 0; i < 4; i++)
        e[8 + i] = (unsigned char)((start >> (8 * i)) & 0xff);
    for (int i = 0; i < 4; i++)
        e[12 + i] = (unsigned char)((sectors >> (8 * i)) & 0xff);
    mbr[510] = 0x55;
    mbr[511] = 0xaa;
    if (lseek(sd, 0, SEEK_SET) < 0)
        return -1;
    return write(sd, mbr, 512) == 512 ? 0 : -1;
}

static void install(const char *path)
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
    int sd = open(path, O_RDWR);
    if (sd < 0) {
        printf("install: open %s: %s\n", path, strerror(errno));
        close(img);
        return;
    }
    // State exactly what will be destroyed and require an explicit
    // yes. This is the last point before the disk is written.
    unsigned long long chosen_root_secs = 0;
    {
        off_t cap0 = lseek(sd, 0, SEEK_END);
        unsigned long long esp_secs =
            (unsigned long long)(st.st_size / 512) - 2048;
        unsigned long long root_secs = 0;
        if (cap0 > 0) {
            unsigned long long total = (unsigned long long)cap0 / 512;
            if (total > 2048 + esp_secs + 2048) {
                root_secs = total - 2048 - esp_secs;
            }
        }
        printf("\n  target : %s (%llu MiB)\n", path,
               (unsigned long long)((cap0 > 0 ? cap0 : 0) >> 20));
        printf("  THIS WILL DESTROY EVERYTHING ON IT.\n");
        printf("  partition 1  ESP   %llu MiB at LBA 2048 (FAT, boot files)\n",
               esp_secs >> 11);
        if (root_secs) {
            printf("  partition 2  root  %llu MiB at LBA %llu (ext2)\n",
                   root_secs >> 11, 2048 + esp_secs);
        } else {
            printf("  partition 2  root  (not enough space left)\n");
        }
        // A real choice: the root size. Bare Enter uses everything
        // left; a number leaves the remainder unpartitioned, which is
        // what a dual-boot or a shared data disk needs.
        printf("  root size in MiB (Enter = all %llu): ",
               root_secs >> 11);
        fflush(stdout);
        char sz[32];
        if (fgets(sz, sizeof sz, stdin) && sz[0] >= '1' && sz[0] <= '9') {
            unsigned long long want = 0;
            for (int i = 0; sz[i] >= '0' && sz[i] <= '9'; i++)
                want = want * 10 + (unsigned long long)(sz[i] - '0');
            unsigned long long want_secs = want * 2048;
            if (want_secs < 8192) {
                printf("  install: root must be at least 4 MiB\n");
                fflush(stdout);
                close(img);
                close(sd);
                return;
            }
            if (want_secs > root_secs) {
                printf("  install: only %llu MiB is available\n",
                       root_secs >> 11);
                fflush(stdout);
                close(img);
                close(sd);
                return;
            }
            root_secs = want_secs;
        }
        chosen_root_secs = root_secs;
        // The size prompt has no trailing newline, so the confirmation
        // used to land on the same line and swallow the typed size.
        printf("\n  root partition: %llu MiB\n", root_secs >> 11);
        printf("  type 'yes' to continue: ");
        fflush(stdout);
        char line[16];
        if (!fgets(line, sizeof line, stdin) || strncmp(line, "yes", 3) != 0) {
            printf("\ninstall: cancelled - nothing was written.\n");
            fflush(stdout);
            close(img);
            close(sd);
            return;
        }
        printf("\n");
        fflush(stdout);
    }
    printf("install: writing %lld MiB image to %s ...\n",
           (long long)(st.st_size >> 20), path);
    fflush(stdout);
    // The image is a FILESYSTEM image (mkfs.fat made it to sit at
    // LBA 0 with hidden-sectors 0), not a partition VBR. Copying it
    // into a partition at LBA 2048 produced a disk that does NOT
    // boot (the firmware found no BOOTX64.EFI), so the copy stays at
    // LBA 0 and the table describes that. A partitioned layout needs
    // an image built for a partition offset first — see HANDOVER.
    // hd.img is now a whole DISK image: its ESP lives at LBA 2048
    // (mkfs.fat --offset, hidden-sectors 2048). Copy the image at LBA 0
    // and have the MBR describe the partition at 2048.
    const unsigned int COPY_LBA = 0;
    const unsigned int PART_LBA = 2048;
    if (lseek(sd, (off_t)COPY_LBA * 512, SEEK_SET) < 0
        || copy_image(img, sd, st.st_size) < 0) {
        close(img);
        close(sd);
        return;
    }
    // Verify: the first sector on disk must match the image's.
    char a[512], b[512];
    memset(a, 0xaa, sizeof a);
    memset(b, 0xbb, sizeof b);
    long l1 = lseek(sd, (off_t)COPY_LBA * 512, SEEK_SET);
    long r1 = read(sd, a, 512);
    long l2 = lseek(img, 0, SEEK_SET);
    long r2 = read(img, b, 512);
    int same = r1 == 512 && r2 == 512 && memcmp(a, b, 512) == 0;
    printf("install: verify disk lseek=%lld read=%lld [%02x %02x %02x %02x]"
           " img lseek=%lld read=%lld [%02x %02x %02x %02x]\n",
           (long long)l1, (long long)r1,
           (unsigned char)a[0], (unsigned char)a[1],
           (unsigned char)a[2], (unsigned char)a[3],
           (long long)l2, (long long)r2,
           (unsigned char)b[0], (unsigned char)b[1],
           (unsigned char)b[2], (unsigned char)b[3]);
    fflush(stdout);
    printf("install: verify first sector: %s\n", same ? "ok" : "MISMATCH");
    fflush(stdout);
    if (same) {
        // Partition 1: the ESP we just wrote (it starts at PART_LBA and
        // runs to the end of the image).
        unsigned long long esp_secs = (unsigned long long)(st.st_size / 512) - PART_LBA;
        // Partition 2: everything after the ESP, formatted ext2. The
        // kernel mounts ext2 read-only, so formatting happens here over
        // raw writes — the same split real installers use.
        // Capacity comes from SEEK_END: fstat on a block device does not
        // report it, which is why the first attempt produced a zero-sized
        // root partition.
        unsigned long long root_secs = 0;
        off_t cap = lseek(sd, 0, SEEK_END);
        if (cap > 0) {
            unsigned long long total = (unsigned long long)cap / 512;
            unsigned int root_lba = PART_LBA + (unsigned int)esp_secs;
            if (total > root_lba + 2048) {
                root_secs = total - root_lba;
                // Honour a size the user chose at the prompt; bare
                // Enter keeps everything that is left.
                if (chosen_root_secs > 0 && chosen_root_secs < root_secs) {
                    root_secs = chosen_root_secs;
                }
                unsigned int blocks = (unsigned int)(root_secs / 2); // 1 KiB blocks
                printf("install: formatting ext2 root at LBA %u (%u blocks)...\n",
                       root_lba, blocks);
                fflush(stdout);
                // Seed the root with a marker file: it proves the
                // installed root is a real filesystem the kernel can
                // read, not just a formatted empty partition.
                static const char marker[] =
                    "Rustux ext2 root\n";
                struct mke2_file files[MKE2_MAX_FILES];
                // Entries without .read stream .data; an uninitialized
                // fn pointer on the stack crashed the formatter with
                // a near-null call (cr2=0xfffffffffffff8).
                memset(files, 0, sizeof files);
                files[0].path = "README";
                files[0].data = marker;
                files[0].len = sizeof marker - 1;
                // A file inside a directory, so the installed root has a
                // real tree rather than a flat listing.
                static const char motd[] =
                    "Welcome to Rustux.\n";
                files[1].path = "etc/motd";
                files[1].data = motd;
                files[1].len = sizeof motd - 1;
                // busybox init runs this when there is no /etc/inittab,
                // so the installed system boots a real init script
                // rather than just a shell.
                static const char rcs[] =
                    "#!/bin/sh\n"
                    "echo 'Rustux: init script running from the ext2 root'\n"
                    "echo 'uname:' `uname -s`\n"
                    "exec /bin/busybox sh\n";
                files[2].path = "etc/rcS";
                files[2].data = rcs;
                files[2].len = sizeof rcs - 1;
                // Without an inittab busybox init opens /dev/tty1..4,
                // which this kernel does not provide, and exits 1. Pin
                // it to the console only.
                static const char inittab[] =
                    "::sysinit:/etc/rcS\n"
                    "::askfirst:/bin/busybox sh\n";
                files[3].path = "etc/inittab";
                files[3].data = inittab;
                files[3].len = sizeof inittab - 1;
                uint32_t nf = 4;
                // Small text seeds: resolver config and the state dirs
                // apt/dpkg expect. A .keep file materializes an
                // otherwise-empty directory (the RAM-fs copy-up only
                // carries files, so these must be non-empty to arrive).
                static const char *const SEEDS[][2] = {
                    { "etc/resolv.conf",
                      "nameserver 10.0.2.3\n" },
                    { "etc/nsswitch.conf",
                      "passwd: files\ngroup: files\nshadow: files\n"
                      "hosts: files dns\nnetworks: files\n" },
                    { "etc/hosts",
                      "127.0.0.1 localhost\n::1 localhost\n" },
                    { "etc/apt/sources.list",
                      "deb [trusted=yes] http://deb.debian.org/debian"
                      " bookworm main\n" },
                    { "etc/apt/apt.conf.d/99rustux",
                      "APT::Get::AllowUnauthenticated \"true\";\n"
                      "Acquire::AllowInsecureRepositories \"true\";\n"
                      "Acquire::Languages \"none\";\n"
                      "Acquire::GzipIndexes \"true\";\n"
                      "APT::Cache-Start \"100000000\";\n"
                      "APT::Sandbox::User \"root\";\n"
                      "Dpkg::Use-Pty \"true\";\n"
                      "Dir::Cache::pkgcache \"\";\n"
                      "Dir::Cache::srcpkgcache \"\";\n" },
                    { "tmp/.keep", "\n" },
                    { "root/.keep", "\n" },
                    { "var/lib/apt/lists/partial/.keep", "\n" },
                    { "var/cache/apt/archives/partial/.keep", "\n" },
                    { "var/lib/dpkg/info/.keep", "\n" },
                    { "var/lib/dpkg/updates/.keep", "\n" },
                    { "var/lib/dpkg/triggers/.keep", "\n" },
                    { "var/log/apt/.keep", "\n" },
                    { "etc/apt/sources.list.d/.keep", "\n" },
                    { "etc/apt/preferences.d/.keep", "\n" },
                    { "etc/apt/trusted.gpg.d/.keep", "\n" },
                };
                for (uint32_t i = 0;
                     i < sizeof SEEDS / sizeof SEEDS[0]; i++) {
                    files[nf].path = SEEDS[i][0];
                    files[nf].data = SEEDS[i][1];
                    files[nf].len = strlen(SEEDS[i][1]);
                    nf++;
                }
                // /var/lib/dpkg/status must be a real dpkg database —
                // a blank file fails MergeList with "no Package:
                // header". Stage every shipped lib as installed.
                static char statusbuf[96 * 1024];
                {
                    size_t so = 0;
                    for (uint32_t i = 0;
                         i < sizeof BASE_PKGS / sizeof BASE_PKGS[0]
                             && so + 512 < sizeof statusbuf;
                         i++) {
                        int n = snprintf(statusbuf + so,
                                sizeof statusbuf - so,
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
                                BASE_PKGS[i][0], BASE_PKGS[i][1]);
                        if (n < 0)
                            break;
                        so += (size_t)n;
                    }
                    files[nf].path = "var/lib/dpkg/status";
                    files[nf].data = statusbuf;
                    files[nf].len = (uint32_t)so;
                    nf++;
                }
                // Real binaries, streamed straight from the initrd.
                // Source path -> path in the installed root. Missing
                // entries are skipped silently.
                static const char *const PAYLOAD[][2] = {
                    { "/bin/busybox", "bin/busybox" },
                    { "/bin/bash", "bin/bash" },
                    { "/bin/dash", "bin/dash" },
                    { "/bin/htop", "bin/htop" },
                    { "/bin/tar", "bin/tar" },
                    { "/sbin/ldconfig", "sbin/ldconfig" },
                    { "/usr/bin/apt-get", "usr/bin/apt-get" },
                    { "/usr/lib/apt/apt-helper",
                      "usr/lib/apt/apt-helper" },
                    { "/usr/lib/apt/methods/http",
                      "usr/lib/apt/methods/http" },
                    { "/usr/lib/apt/methods/gpgv",
                      "usr/lib/apt/methods/gpgv" },
                    { "/usr/lib/apt/methods/store",
                      "usr/lib/apt/methods/store" },
                    { "/usr/lib/apt/methods/copy",
                      "usr/lib/apt/methods/copy" },
                    { "/usr/lib/apt/methods/file",
                      "usr/lib/apt/methods/file" },
                    { "/usr/bin/gpgv", "usr/bin/gpgv" },
                    { "/usr/bin/dpkg", "usr/bin/dpkg" },
                    { "/usr/bin/dpkg-deb", "usr/bin/dpkg-deb" },
                    { "/usr/bin/dpkg-split", "usr/bin/dpkg-split" },
                    { "/usr/bin/dpkg-query", "usr/bin/dpkg-query" },
                    { "/usr/share/dpkg/cputable",
                      "usr/share/dpkg/cputable" },
                    { "/usr/share/dpkg/ostable",
                      "usr/share/dpkg/ostable" },
                    { "/usr/share/dpkg/tupletable",
                      "usr/share/dpkg/tupletable" },
                    { "/usr/share/dpkg/abitable",
                      "usr/share/dpkg/abitable" },
                    { "/usr/share/terminfo/x/xterm",
                      "usr/share/terminfo/x/xterm" },
                    { "/etc/passwd", "etc/passwd" },
                    { "/etc/shadow", "etc/shadow" },
                    { "/etc/group", "etc/group" },
                    { "/etc/securetty", "etc/securetty" },
                    { "/lib64/ld-linux-x86-64.so.2",
                      "lib64/ld-linux-x86-64.so.2" },
                    { "/lib/x86_64-linux-gnu/libc.so.6",
                      "lib/x86_64-linux-gnu/libc.so.6" },
                    { "/lib/x86_64-linux-gnu/libnss_dns.so.2",
                      "lib/x86_64-linux-gnu/libnss_dns.so.2" },
                    { "/lib/x86_64-linux-gnu/libnss_files.so.2",
                      "lib/x86_64-linux-gnu/libnss_files.so.2" },
                    { "/lib/x86_64-linux-gnu/libresolv.so.2",
                      "lib/x86_64-linux-gnu/libresolv.so.2" },
                    { "/lib/x86_64-linux-gnu/libapt-pkg.so.6.0",
                      "lib/x86_64-linux-gnu/libapt-pkg.so.6.0" },
                    { "/lib/x86_64-linux-gnu/libapt-private.so.0.0",
                      "lib/x86_64-linux-gnu/libapt-private.so.0.0" },
                    { "/lib/x86_64-linux-gnu/libstdc++.so.6",
                      "lib/x86_64-linux-gnu/libstdc++.so.6" },
                    { "/lib/x86_64-linux-gnu/libgcc_s.so.1",
                      "lib/x86_64-linux-gnu/libgcc_s.so.1" },
                    { "/lib/x86_64-linux-gnu/libz.so.1",
                      "lib/x86_64-linux-gnu/libz.so.1" },
                    { "/lib/x86_64-linux-gnu/libzstd.so.1",
                      "lib/x86_64-linux-gnu/libzstd.so.1" },
                    { "/lib/x86_64-linux-gnu/liblzma.so.5",
                      "lib/x86_64-linux-gnu/liblzma.so.5" },
                    { "/lib/x86_64-linux-gnu/libbz2.so.1.0",
                      "lib/x86_64-linux-gnu/libbz2.so.1.0" },
                    { "/lib/x86_64-linux-gnu/liblz4.so.1",
                      "lib/x86_64-linux-gnu/liblz4.so.1" },
                    { "/lib/x86_64-linux-gnu/libxxhash.so.0",
                      "lib/x86_64-linux-gnu/libxxhash.so.0" },
                    { "/lib/x86_64-linux-gnu/libudev.so.1",
                      "lib/x86_64-linux-gnu/libudev.so.1" },
                    { "/lib/x86_64-linux-gnu/libsystemd.so.0",
                      "lib/x86_64-linux-gnu/libsystemd.so.0" },
                    { "/lib/x86_64-linux-gnu/libgcrypt.so.20",
                      "lib/x86_64-linux-gnu/libgcrypt.so.20" },
                    { "/lib/x86_64-linux-gnu/libseccomp.so.2",
                      "lib/x86_64-linux-gnu/libseccomp.so.2" },
                    { "/lib/x86_64-linux-gnu/libassuan.so.0",
                      "lib/x86_64-linux-gnu/libassuan.so.0" },
                    { "/lib/x86_64-linux-gnu/libnpth.so.0",
                      "lib/x86_64-linux-gnu/libnpth.so.0" },
                    { "/lib/x86_64-linux-gnu/libgpg-error.so.0",
                      "lib/x86_64-linux-gnu/libgpg-error.so.0" },
                    { "/lib/x86_64-linux-gnu/libgnutls.so.30",
                      "lib/x86_64-linux-gnu/libgnutls.so.30" },
                    { "/lib/x86_64-linux-gnu/libgmp.so.10",
                      "lib/x86_64-linux-gnu/libgmp.so.10" },
                    { "/lib/x86_64-linux-gnu/libhogweed.so.6",
                      "lib/x86_64-linux-gnu/libhogweed.so.6" },
                    { "/lib/x86_64-linux-gnu/libnettle.so.8",
                      "lib/x86_64-linux-gnu/libnettle.so.8" },
                    { "/lib/x86_64-linux-gnu/libtasn1.so.6",
                      "lib/x86_64-linux-gnu/libtasn1.so.6" },
                    { "/lib/x86_64-linux-gnu/libp11-kit.so.0",
                      "lib/x86_64-linux-gnu/libp11-kit.so.0" },
                    { "/lib/x86_64-linux-gnu/libunistring.so.5",
                      "lib/x86_64-linux-gnu/libunistring.so.5" },
                    { "/lib/x86_64-linux-gnu/libidn2.so.0",
                      "lib/x86_64-linux-gnu/libidn2.so.0" },
                    { "/lib/x86_64-linux-gnu/libffi.so.8",
                      "lib/x86_64-linux-gnu/libffi.so.8" },
                    { "/lib/x86_64-linux-gnu/libselinux.so.1",
                      "lib/x86_64-linux-gnu/libselinux.so.1" },
                    { "/lib/x86_64-linux-gnu/libpcre2-8.so.0",
                      "lib/x86_64-linux-gnu/libpcre2-8.so.0" },
                    { "/lib/x86_64-linux-gnu/libacl.so.1",
                      "lib/x86_64-linux-gnu/libacl.so.1" },
                    { "/lib/x86_64-linux-gnu/libmd.so.0",
                      "lib/x86_64-linux-gnu/libmd.so.0" },
                    { "/lib/x86_64-linux-gnu/libcap.so.2",
                      "lib/x86_64-linux-gnu/libcap.so.2" },
                    { "/lib/x86_64-linux-gnu/libncursesw.so.6",
                      "lib/x86_64-linux-gnu/libncursesw.so.6" },
                    { "/lib/x86_64-linux-gnu/libtinfo.so.6",
                      "lib/x86_64-linux-gnu/libtinfo.so.6" },
                    { "/lib/x86_64-linux-gnu/libm.so.6",
                      "lib/x86_64-linux-gnu/libm.so.6" },
                    { "/lib/x86_64-linux-gnu/libnl-3.so.200",
                      "lib/x86_64-linux-gnu/libnl-3.so.200" },
                    { "/lib/x86_64-linux-gnu/libnl-genl-3.so.200",
                      "lib/x86_64-linux-gnu/libnl-genl-3.so.200" },
                };
                // busybox applets and duplicated binaries land as
                // hardlinks — a dirent pointing at an existing inode
                // instead of another copy of the file. Target must be
                // an earlier PAYLOAD entry.
                static const char *const ALIASES[][2] = {
                    { "bin/sh", "bin/busybox" },
                    { "bin/ash", "bin/busybox" },
                    { "bin/ls", "bin/busybox" },
                    { "bin/cat", "bin/busybox" },
                    { "bin/cp", "bin/busybox" },
                    { "bin/mv", "bin/busybox" },
                    { "bin/rm", "bin/busybox" },
                    { "bin/mkdir", "bin/busybox" },
                    { "bin/touch", "bin/busybox" },
                    { "bin/echo", "bin/busybox" },
                    { "bin/pwd", "bin/busybox" },
                    { "bin/df", "bin/busybox" },
                    { "bin/du", "bin/busybox" },
                    { "bin/free", "bin/busybox" },
                    { "bin/ps", "bin/busybox" },
                    { "bin/top", "bin/busybox" },
                    { "bin/uname", "bin/busybox" },
                    { "bin/hostname", "bin/busybox" },
                    { "bin/date", "bin/busybox" },
                    { "bin/mount", "bin/busybox" },
                    { "bin/umount", "bin/busybox" },
                    { "bin/dd", "bin/busybox" },
                    { "bin/sync", "bin/busybox" },
                    { "bin/grep", "bin/busybox" },
                    { "bin/sed", "bin/busybox" },
                    { "bin/diff", "bin/busybox" },
                    { "bin/find", "bin/busybox" },
                    { "bin/xargs", "bin/busybox" },
                    { "bin/sort", "bin/busybox" },
                    { "bin/tr", "bin/busybox" },
                    { "bin/md5sum", "bin/busybox" },
                    { "bin/chown", "bin/busybox" },
                    { "bin/chmod", "bin/busybox" },
                    { "bin/ln", "bin/busybox" },
                    { "bin/rmdir", "bin/busybox" },
                    { "bin/test", "bin/busybox" },
                    { "bin/install", "bin/busybox" },
                    { "bin/mkfifo", "bin/busybox" },
                    { "bin/sleep", "bin/busybox" },
                    { "bin/expr", "bin/busybox" },
                    { "bin/head", "bin/busybox" },
                    { "bin/tail", "bin/busybox" },
                    { "bin/wc", "bin/busybox" },
                    { "bin/more", "bin/busybox" },
                    { "bin/less", "bin/busybox" },
                    { "bin/vi", "bin/busybox" },
                    { "bin/clear", "bin/busybox" },
                    { "bin/which", "bin/busybox" },
                    { "bin/dmesg", "bin/busybox" },
                    { "bin/whoami", "bin/busybox" },
                    { "bin/gzip", "bin/busybox" },
                    { "bin/gunzip", "bin/busybox" },
                    { "usr/bin/id", "bin/busybox" },
                    { "usr/bin/logname", "bin/busybox" },
                    { "usr/bin/groups", "bin/busybox" },
                    { "sbin/reboot", "bin/busybox" },
                    { "sbin/poweroff", "bin/busybox" },
                    { "sbin/halt", "bin/busybox" },
                    { "sbin/start-stop-daemon", "bin/busybox" },
                    { "usr/sbin/start-stop-daemon", "bin/busybox" },
                    { "usr/bin/apt", "usr/bin/apt-get" },
                    { "usr/sbin/ldconfig", "sbin/ldconfig" },
                };
                static struct stat pst[MKE2_MAX_FILES];
                for (uint32_t i = 0; i < sizeof PAYLOAD / sizeof PAYLOAD[0] && nf < MKE2_MAX_FILES; i++) {
                    int fd = open(PAYLOAD[i][0], O_RDONLY);
                    if (fd < 0 || fstat(fd, &pst[i]) != 0 || pst[i].st_size <= 0) {
                        if (fd >= 0)
                            close(fd);
                        continue;
                    }
                    close(fd); // file_reader re-opens per block — no
                    // payload fd survives the loop (MAX_FDS is 16)
                    if ((unsigned long long)pst[i].st_size >= (unsigned long long)blocks * 1024)
                        continue; // would not fit
                    files[nf].path = PAYLOAD[i][1];
                    files[nf].data = 0;
                    files[nf].len = (uint32_t)pst[i].st_size;
                    files[nf].read = file_reader;
                    files[nf].rctx = (void *)PAYLOAD[i][0];
                    nf++;
                }
                for (uint32_t i = 0; i < sizeof ALIASES / sizeof ALIASES[0] && nf < MKE2_MAX_FILES; i++) {
                    // Skip an alias whose target never landed — the
                    // formatter would fail the whole image on a
                    // dangling hardlink.
                    int found = 0;
                    for (uint32_t j = 0; j < nf; j++) {
                        if (files[j].path &&
                            strcmp(files[j].path, ALIASES[i][1]) == 0) {
                            found = 1;
                            break;
                        }
                    }
                    if (!found)
                        continue;
                    files[nf].path = ALIASES[i][0];
                    files[nf].alias = ALIASES[i][1];
                    nf++;
                }
                int fr = mke2_format(mke2_sink, &sd, (uint64_t)root_lba * 512,
                                     blocks, files, nf);
                if (fr == 0) {
                    printf("install: ext2 root formatted\n");
                } else {
                    printf("install: ext2 format FAILED code=%d\n", fr);
                    root_secs = 0;
                }
                fflush(stdout);
            }
        }
        if (write_mbr2(sd, PART_LBA, esp_secs,
                       (unsigned int)(PART_LBA + esp_secs), root_secs) == 0)
            printf("install: partition table written (ESP at %u +%llu, root at %u +%llu)\n",
                   PART_LBA, esp_secs, PART_LBA + (unsigned int)esp_secs, root_secs);
        else
            printf("install: partition table write failed: %s\n", strerror(errno));
        fflush(stdout);
    }
    close(img);
    close(sd);
    if (!same) {
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
    // Disk picker: every /dev/sd* that exists and is writable is a
    // candidate. Hardcoding /dev/sda meant a machine whose only disk
    // enumerated as sdb reported "no writable disk".
    static const char *const CAND[] = { "/dev/sda", "/dev/sdb", "/dev/sdc", "/dev/sdd" };
    for (;;) {
        const char *target = 0;
        int ndisk = 0;
        for (size_t i = 0; i < sizeof CAND / sizeof CAND[0]; i++) {
            if (access(CAND[i], R_OK | W_OK) == 0) {
                if (!target)
                    target = CAND[i];
                ndisk++;
            }
        }
        int can_install = target != 0;
        // Install is the primary action and the default (bare Enter):
        // this is installation media, the live session is the rescue
        // path. The option is always shown — hiding it behind the
        // access() probe made the installer look absent on machines
        // where the node or its mode was unexpected; selecting it now
        // reports the real reason instead.
        if (can_install) {
            printf("[1] install Rustux to %s%s\n", target,
                   ndisk > 1 ? "  (first of several disks)" : "");
        } else {
            printf("[1] install Rustux to disk  (no writable disk detected)\n");
        }
        printf("[2] live session\n");
        printf("> ");
        fflush(stdout);
        // Single-key input: fgets() is line-based and blocks until
        // Enter, so pressing "1" at the prompt echoed the key and then
        // did nothing at all — which reads as a dead menu.
        char line[2];
        ssize_t got = read(0, line, 1);
        if (got <= 0) {
            sleep(1);
            continue;
        }
        switch (line[0]) {
        case '\n':
        case '\r':
        case '1':
            if (can_install) {
                install(target);
            } else {
                printf("install: no writable disk at /dev/sd[abcd]\n");
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
