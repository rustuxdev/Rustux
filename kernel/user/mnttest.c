// mnttest — syscall(165 mount, 166 umount2) + mount-table checks.
// Exit status = number of failed checks.
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/mount.h>
#include <sys/syscall.h>

static int fails;
static void check(int ok, const char *what) {
    if (!ok) {
        printf("FAIL: %s\n", what);
        fails++;
    }
}

#ifndef MS_REMOUNT
#define MS_REMOUNT 32
#endif
#define RAMFS_MAGIC  0x858458f6L
#define PROC_MAGIC   0x9fa0L
#define TMPFS_MAGIC  0x1021994L
#ifndef ST_RDONLY
#define ST_RDONLY 1
#define ST_NOSUID 2
#define ST_NODEV 4
#define ST_NOEXEC 8
#endif

static int has_mount(const char *src, const char *path, const char *fs,
                     const char *opt) {
    FILE *f = fopen("/proc/mounts", "r");
    if (!f) return 0;
    char line[256];
    int hit = 0;
    char want[256];
    snprintf(want, sizeof(want), "%s %s %s %s", src, path, fs, opt);
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, want, strlen(want)) == 0) { hit = 1; break; }
    }
    fclose(f);
    return hit;
}

static int has_fstype(const char *fs) {
    FILE *f = fopen("/proc/filesystems", "r");
    if (!f) return 0;
    char line[64];
    int hit = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, fs)) { hit = 1; break; }
    }
    fclose(f);
    return hit;
}

static long n2h_mid(const char *path) {
    struct { unsigned int b; int t; unsigned char h[128]; } fh;
    int mid = -1;
    fh.b = sizeof(fh.h);
    if (syscall(303, AT_FDCWD, path, &fh, &mid, 0) < 0)
        return -1;
    return mid;
}

int main(void) {
    // ---- seeded table reads ----------------------------------
    check(has_mount("rustux", "/", "rustux", "rw"),
          "proc/mounts seeds root rustux rw");
    check(has_mount("proc", "/proc", "proc", "ro"),
          "proc/mounts seeds proc ro");
    check(has_mount("devtmpfs", "/dev", "devtmpfs", "rw"),
          "proc/mounts seeds dev rw");
    check(has_fstype("rustux") && has_fstype("proc")
          && has_fstype("devtmpfs"),
          "proc/filesystems lists seeded types");

    struct statfs sf;
    check(statfs("/", &sf) == 0 && sf.f_type == RAMFS_MAGIC
          && !(sf.f_flags & ST_RDONLY),
          "statfs / = ramfs rw");
    check(statfs("/proc", &sf) == 0 && sf.f_type == PROC_MAGIC
          && (sf.f_flags & ST_RDONLY) && (sf.f_flags & ST_NOSUID)
          && (sf.f_flags & ST_NODEV) && (sf.f_flags & ST_NOEXEC),
          "statfs /proc = procfs ro+nosuid+nodev+noexec");

    // ---- mount(165) ------------------------------------------
    check(mkdir("/t_mnt", 0755) == 0, "mkdir /t_mnt");
    errno = 0;
    check(mount("tmpfs", "/t_mnt", "bogusfs", 0, 0) < 0
          && errno == ENODEV, "mount unknown fstype ENODEV");
    errno = 0;
    check(mount("tmpfs", "/no_such_dir_x", "tmpfs", 0, 0) < 0
          && errno == ENOENT, "mount missing target ENOENT");
    {
        int fd = open("/t_mnt_file", O_CREAT | O_WRONLY, 0644);
        check(fd >= 0, "create plain file for ENOTDIR probe");
        if (fd >= 0) close(fd);
        errno = 0;
        check(mount("tmpfs", "/t_mnt_file", "tmpfs", 0, 0) < 0
              && errno == ENOTDIR, "mount over file ENOTDIR");
        unlink("/t_mnt_file");
    }
    errno = 0;
    check(mount("tmpfs", "/t_mnt", "tmpfs", 1 << 18, 0) < 0
          && errno == EINVAL, "mount unknown flags EINVAL");
    check(mount("tmpfs", "/t_mnt", "tmpfs", 0, 0) == 0,
          "mount tmpfs rw");
    check(has_mount("tmpfs", "/t_mnt", "tmpfs", "rw"),
          "proc/mounts shows tmpfs rw");
    check(statfs("/t_mnt", &sf) == 0 && sf.f_type == TMPFS_MAGIC,
          "statfs /t_mnt = tmpfs magic");
    check(n2h_mid("/t_mnt") > 1,
          "name_to_handle_at mints the mount's id");
    errno = 0;
    check(mount("tmpfs", "/t_mnt", "tmpfs", 0, 0) < 0
          && errno == EBUSY, "mount over mount point EBUSY");

    // writable while rw
    {
        int fd = open("/t_mnt/wf", O_CREAT | O_RDWR, 0644);
        check(fd >= 0, "create file under rw tmpfs mount");
        if (fd >= 0) {
            check(write(fd, "x", 1) == 1, "write under rw mount");
            close(fd);
        }
    }

    // ---- MS_RDONLY enforcement --------------------------------
    check(mkdir("/t_ro", 0755) == 0, "mkdir /t_ro");
    {
        int fd = open("/t_ro/f", O_CREAT | O_RDWR, 0644);
        check(fd >= 0, "create /t_ro/f before ro mount");
        if (fd >= 0) { check(write(fd, "d", 1) == 1, "pre-write"); }
        // keep fd open across the ro mount for the ftruncate probe
        check(mount("rofs", "/t_ro", "tmpfs", MS_RDONLY, 0) == 0,
              "mount tmpfs ro");
        check(has_mount("rofs", "/t_ro", "tmpfs", "ro"),
              "proc/mounts shows ro");
        check(statfs("/t_ro", &sf) == 0
              && sf.f_type == TMPFS_MAGIC
              && (sf.f_flags & ST_RDONLY),
              "statfs covered dir = tmpfs ST_RDONLY");
        check(statfs("/t_ro/f", &sf) == 0
              && sf.f_type == TMPFS_MAGIC,
              "statfs covered child = tmpfs magic");

        errno = 0;
        int w = open("/t_ro/g", O_CREAT | O_WRONLY, 0644);
        check(w < 0 && errno == EROFS, "O_CREAT under ro EROFS");
        errno = 0;
        w = open("/t_ro/f", O_WRONLY);
        check(w < 0 && errno == EROFS, "O_WRONLY existing under ro EROFS");
        int r = open("/t_ro/f", O_RDONLY);
        check(r >= 0, "O_RDONLY under ro still works");
        if (r >= 0) close(r);

        errno = 0;
        check(unlink("/t_ro/f") < 0 && errno == EROFS,
              "unlink under ro EROFS");
        errno = 0;
        check(mkdir("/t_ro/d", 0755) < 0 && errno == EROFS,
              "mkdir under ro EROFS");
        errno = 0;
        check(rmdir("/t_ro") < 0 && errno == EROFS,
              "rmdir on covered point EROFS");
        errno = 0;
        check(symlink("x", "/t_ro/l") < 0 && errno == EROFS,
              "symlink under ro EROFS");
        errno = 0;
        check(link("/t_ro/f", "/t_ro/h") < 0 && errno == EROFS,
              "link under ro EROFS");
        errno = 0;
        check(rename("/t_ro/f", "/t_ro/f2") < 0 && errno == EROFS,
              "rename under ro EROFS");
        errno = 0;
        check(chmod("/t_ro/f", 0600) < 0 && errno == EROFS,
              "chmod under ro EROFS");
        errno = 0;
        check(truncate("/t_ro/f", 0) < 0 && errno == EROFS,
              "truncate under ro EROFS");
        if (fd >= 0) {
            errno = 0;
            check(ftruncate(fd, 0) < 0 && errno == EROFS,
                  "ftruncate via pre-open fd EROFS");
            close(fd);
        }

        // MS_REMOUNT flips it back writable, then ro again.
        check(mount("rofs", "/t_ro", "tmpfs",
                    MS_REMOUNT, 0) == 0,
              "remount rw");
        {
            int w2 = open("/t_ro/g", O_CREAT | O_WRONLY, 0644);
            check(w2 >= 0, "create works after remount rw");
            if (w2 >= 0) close(w2);
            unlink("/t_ro/g");
        }
        check(mount("rofs", "/t_ro", "tmpfs",
                    MS_REMOUNT | MS_RDONLY, 0) == 0,
              "remount ro");
        errno = 0;
        check(unlink("/t_ro/f") < 0 && errno == EROFS,
              "EROFS again after remount ro");
        check(umount2("/t_ro", 0) == 0, "umount ro mount");
        errno = 0;
        check(unlink("/t_ro/f") == 0, "writes pass after umount");
        check(rmdir("/t_ro") == 0, "cleanup /t_ro");
    }

    // ---- umount2(166) -----------------------------------------
    errno = 0;
    check(umount2("/", 0) < 0 && errno == EBUSY,
          "umount root EBUSY");
    errno = 0;
    check(umount2("/proc/self", 0) < 0 && errno == EINVAL,
          "umount covered proc child EINVAL");
    errno = 0;
    check(umount2("/t_mnt/wf", 0) < 0 && errno == EINVAL,
          "umount covered child EINVAL");
    errno = 0;
    check(umount2("/t_mnt", 1 << 4) < 0 && errno == EINVAL,
          "umount unknown flags EINVAL");
    check(umount2("/t_mnt", 0) == 0, "umount tmpfs");
    check(!has_mount("tmpfs", "/t_mnt", "tmpfs", "rw"),
          "proc/mounts loses the row");
    errno = 0;
    check(umount2("/t_mnt", 0) < 0 && errno == EINVAL,
          "double umount EINVAL");
    check(unlink("/t_mnt/wf") == 0 && rmdir("/t_mnt") == 0,
          "cleanup /t_mnt");

    // ---- statmount(457) + listmount(458) ----------------------
    struct mnt_id_req {
        unsigned int size, spare;
        unsigned long long mnt_id, param;
    };
    struct statmount {
        unsigned int size, _s1;
        unsigned long long mask;
        unsigned int dev_maj, dev_min;
        unsigned long long sb_magic;
        unsigned int sb_flags, fs_type;
        unsigned long long mnt_id, parent_id;
        unsigned int mnt_id_old, parent_old;
        unsigned long long mnt_attr, propagation, peer_group;
        unsigned long long master, propagate_from;
        unsigned int mnt_root, mnt_point;
        unsigned long long _s2[50];
        char str[];
    };
    const char *sm_str(const struct statmount *sm, unsigned int off) {
        return sm->str + off;
    }
    struct statmount *sm;
    struct mnt_id_req rq;

    memset(&rq, 0, sizeof(rq));
    rq.size = sizeof(rq);
    rq.mnt_id = 1;             // seeded root mount
    rq.param = 0x3f;           // all groups
    char smbuf[768];
    sm = (struct statmount *)smbuf;
    memset(smbuf, 0, sizeof(smbuf));
    check(syscall(457, &rq, sm, sizeof(smbuf), 0) == 0,
          "statmount root succeeds");
    check(sm->mnt_id == 1 && sm->parent_id == 1
          && sm->sb_magic == RAMFS_MAGIC
          && !(sm->sb_flags & 1)
          && strcmp(sm_str(sm, sm->fs_type), "rustux") == 0
          && strcmp(sm_str(sm, sm->mnt_point), "/") == 0
          && strcmp(sm_str(sm, sm->mnt_root), "/") == 0,
          "statmount root fields");
    rq.mnt_id = 2;             // seeded proc mount
    memset(smbuf, 0, sizeof(smbuf));
    check(syscall(457, &rq, sm, sizeof(smbuf), 0) == 0
          && sm->sb_magic == PROC_MAGIC
          && (sm->sb_flags & 1)
          && strcmp(sm_str(sm, sm->fs_type), "proc") == 0
          && strcmp(sm_str(sm, sm->mnt_point), "/proc") == 0,
          "statmount proc fields");
    rq.mnt_id = 0xdead;
    errno = 0;
    check(syscall(457, &rq, sm, sizeof(smbuf), 0) < 0
          && errno == ENOENT, "statmount bad id ENOENT");
    rq.mnt_id = 1; rq.param = 1 << 8;
    errno = 0;
    check(syscall(457, &rq, sm, sizeof(smbuf), 0) < 0
          && errno == EINVAL, "statmount unknown mask EINVAL");
    rq.param = 0x3f; rq.spare = 1;
    errno = 0;
    check(syscall(457, &rq, sm, sizeof(smbuf), 0) < 0
          && errno == EINVAL, "statmount nonzero spare EINVAL");
    rq.spare = 0;
    memset(smbuf, 0, sizeof(smbuf));
    check(syscall(457, &rq, sm, 516, 0) < 0 && errno == EOVERFLOW
          && sm->size > 512,
          "statmount small buf EOVERFLOW + size");

    // listmount: children of root
    {
        unsigned long long kids[8];
        memset(&rq, 0, sizeof(rq));
        rq.size = sizeof(rq);
        rq.mnt_id = ~0ULL;     // LSMT_ROOT
        long n = syscall(458, &rq, kids, 8, 0);
        check(n == 2 && kids[0] == 2 && kids[1] == 3,
              "listmount root children = proc+dev");
        rq.mnt_id = 0xdead;
        errno = 0;
        check(syscall(458, &rq, kids, 8, 0) < 0 && errno == ENOENT,
              "listmount bad parent ENOENT");
        rq.mnt_id = ~0ULL;
        errno = 0;
        check(syscall(458, &rq, kids, 8, 1) < 0 && errno == EINVAL,
              "listmount nonzero flags EINVAL");
        // a fresh mount appears under root's children
        check(mkdir("/t_sm", 0755) == 0, "mkdir /t_sm");
        check(mount("s", "/t_sm", "tmpfs", 0, 0) == 0,
              "mount for listmount");
        n = syscall(458, &rq, kids, 8, 0);
        check(n == 3 && kids[2] > 3,
              "listmount sees new minted mount");
        unsigned long long newid = kids[2];
        // paginate: last id resumes after it
        rq.param = kids[0];
        n = syscall(458, &rq, kids, 8, 0);
        check(n == 2 && kids[0] == 3 && kids[1] == newid,
              "listmount param pagination");
        rq.param = 0;
        // statmount the new mount
        memset(&rq, 0, sizeof(rq));
        rq.size = sizeof(rq);
        rq.mnt_id = newid;
        rq.param = 0x3f;
        memset(smbuf, 0, sizeof(smbuf));
        check(syscall(457, &rq, sm, sizeof(smbuf), 0) == 0
              && sm->sb_magic == TMPFS_MAGIC
              && sm->parent_id == 1
              && strcmp(sm_str(sm, sm->fs_type), "tmpfs") == 0
              && strcmp(sm_str(sm, sm->mnt_point), "/t_sm") == 0,
              "statmount minted tmpfs mount");
        check(umount2("/t_sm", 0) == 0 && rmdir("/t_sm") == 0,
              "cleanup /t_sm");
        memset(&rq, 0, sizeof(rq));
        rq.size = sizeof(rq);
        rq.mnt_id = ~0ULL;
        n = syscall(458, &rq, kids, 8, 0);
        check(n == 2, "listmount loses unmounted");
    }

    // ---- quotactl(179) — quota-less surface --------------------
    // QCMD(subop, type) = subop<<8 | type
    errno = 0;
    check(syscall(179, (0x800007L << 8) | 9, "/", 0, 0) < 0
          && errno == EINVAL, "quotactl bad type EINVAL");
    errno = 0;
    check(syscall(179, 0x800007L << 8, "/", 0, 0) < 0
          && errno == ESRCH, "quotactl Q_GETQUOTA ESRCH");
    errno = 0;
    check(syscall(179, 0x800001L << 8, "/", 0, 0) == 0,
          "quotactl Q_SYNC ok");
    errno = 0;
    check(syscall(179, 0x800007L << 8, "/no_such_x", 0, 0) < 0
          && errno == ENOENT, "quotactl bad special ENOENT");
    errno = 0;
    check(syscall(179, 0x1234L << 8, "/", 0, 0) < 0
          && errno == EINVAL, "quotactl unknown subop EINVAL");

    // ---- open_tree(428)/move_mount(429)/fspick(433)/mount_setattr(442)
    {
        const long AEP = 0x1000;  // AT_EMPTY_PATH
        const long AREC = 0x8000; // AT_RECURSIVE
        unsigned long long attr[4];

        check(mkdir("/t_mm", 0755) == 0, "mkdir /t_mm");
        check(mkdir("/t_mm2", 0755) == 0, "mkdir /t_mm2");
        check(mkdir("/t_ot", 0755) == 0, "mkdir /t_ot");
        check(mount("tmpfs", "/t_ot", "tmpfs", 0, 0) == 0,
              "mount clone source");
        // open_tree errno ladder first
        errno = 0;
        check(syscall(428, AT_FDCWD, "/t_ot", 1L << 20) < 0
              && errno == EINVAL, "open_tree bad flags EINVAL");
        errno = 0;
        check(syscall(428, AT_FDCWD, "/no_such_x", 1) < 0
              && errno == ENOENT, "open_tree ENOENT");
        errno = 0;
        check(syscall(428, AT_FDCWD, 0, 0) < 0
              && errno == ENOENT, "open_tree null path no EMPTY_PATH");
        // clone the /t_mnt tmpfs, attach it at /t_mm
        int mf = syscall(428, AT_FDCWD, "/t_ot", 1);
        check(mf >= 0, "open_tree clone tmpfs");
        errno = 0;
        check(syscall(429, 0 /*stdin*/, "", AT_FDCWD, "/t_mm", 4) < 0
              && errno == EBADF, "move_mount non-mount fd EBADF");
        errno = 0;
        check(syscall(429, mf, "", AT_FDCWD, "/t_mm2",
                      4 | 0x100) < 0 && errno == EINVAL,
              "move_mount SET_GROUP EINVAL");
        check(syscall(429, mf, "", AT_FDCWD, "/t_mm", 4) == 0,
              "move_mount attaches detached clone");
        check(has_mount("tmpfs", "/t_mm", "tmpfs", "rw"),
              "/proc/mounts has moved clone");
        // closed+re-attached fd: mf still valid but mount moved on
        errno = 0;
        check(syscall(429, mf, "", AT_FDCWD, "/t_mm2", 4) == 0,
              "move_mount re-attach via stale-ish fd");
        check(has_mount("tmpfs", "/t_mm2", "tmpfs", "rw"),
              "clone now at /t_mm2");
        check(umount2("/t_mm2", 0) == 0, "umount re-attached clone");
        errno = 0;
        check(syscall(429, mf, "", AT_FDCWD, "/t_mm2", 4) < 0
              && errno == ENOENT, "move_mount dead mount fd ENOENT");
        close(mf);
        // fspick + mount_setattr ro<->rw
        check(mount("tmpfs", "/t_mm", "tmpfs", 0, 0) == 0,
              "mount for fspick/setattr");
        int pf = syscall(433, AT_FDCWD, "/t_mm", 0);
        check(pf >= 0, "fspick /t_mm");
        errno = 0;
        check(mkdir("/t_dir", 0755) == 0, "mkdir /t_dir");
        check(syscall(433, AT_FDCWD, "/t_dir", 0) < 0 && errno == EINVAL,
              "fspick non-mount dir EINVAL");
        check(rmdir("/t_dir") == 0, "rmdir /t_dir");
        errno = 0;
        check(syscall(433, AT_FDCWD, "/t_mm", 0x20) < 0 && errno == EINVAL,
              "fspick bad flags EINVAL");
        memset(attr, 0, sizeof(attr));
        attr[0] = 1; // MOUNT_ATTR_RDONLY
        check(syscall(442, pf, "", AEP, attr, 32) == 0,
              "mount_setattr rdonly via fspick fd");
        errno = 0;
        check(open("/t_mm/x", O_CREAT | O_WRONLY, 0644) < 0
              && errno == EROFS, "EROFS after mount_setattr rdonly");
        check(has_mount("tmpfs", "/t_mm", "tmpfs", "ro"),
              "/proc/mounts shows ro");
        // attr-set error ladder
        errno = 0;
        attr[0] = 3; attr[1] = 3; // set & clr overlap
        check(syscall(442, pf, "", AEP, attr, 32) < 0 && errno == EINVAL,
              "mount_setattr set/clr overlap EINVAL");
        errno = 0;
        check(syscall(442, pf, "", AEP, attr, 8) < 0 && errno == EINVAL,
              "mount_setattr short size EINVAL");
        errno = 0;
        attr[0] = 0; attr[1] = 1;
        attr[2] = 1 << 14;         // propagation: MS_SHARED|MS_PRIVATE both set
        check(syscall(442, pf, "", AEP, attr, 32) < 0 && errno == EINVAL,
              "mount_setattr bad propagation EINVAL");
        attr[2] = 0;
        check(syscall(442, AT_FDCWD, "/t_mm", 0, attr, 32) == 0,
              "mount_setattr clr rdonly by path");
        int wfd = open("/t_mm/x", O_CREAT | O_WRONLY, 0644);
        check(wfd >= 0, "writable after attr_clr");
        if (wfd >= 0) close(wfd);
        // AT_RECURSIVE applies under the target too
        check(mkdir("/t_mm/inner", 0755) == 0, "mkdir inner");
        errno = 0;
        check(syscall(429, AT_FDCWD, "/", AT_FDCWD, "/t_mm2", 0) < 0
              && errno == EBUSY, "move_mount root EBUSY");
        check(mkdir("/t_mm/sub", 0755) == 0, "mkdir /t_mm/sub");
        errno = 0;
        check(syscall(429, AT_FDCWD, "/t_mm", AT_FDCWD,
                      "/t_mm/sub", 0) < 0 && errno == EINVAL,
              "move_mount under self EINVAL");
        check(rmdir("/t_mm/sub") == 0, "rmdir /t_mm/sub");
        check(mount("tmpfs", "/t_mm/inner", "tmpfs", 0, 0) == 0,
              "mount inner for recursive setattr");
        memset(attr, 0, sizeof(attr));
        attr[0] = 8; // MOUNT_ATTR_NOEXEC
        check(syscall(442, AT_FDCWD, "/t_mm", AREC, attr, 32) == 0,
              "mount_setattr recursive noexec");
        check(has_mount("tmpfs", "/t_mm/inner", "tmpfs", "rw,noexec")
              || has_mount("tmpfs", "/t_mm/inner", "tmpfs", "noexec"),
              "recursive setattr hit inner mount");
        // stale fspick fd after umount -> ENOENT not wrong-mount
        close(pf);
        check(umount2("/t_mm/inner", 0) == 0, "umount inner");
        check(umount2("/t_mm", 0) == 0, "umount /t_mm");
        check(umount2("/t_ot", 0) == 0 && rmdir("/t_ot") == 0,
              "umount clone source");
        errno = 0;
        check(syscall(433, AT_FDCWD, "/t_mm", 0) < 0 && errno == EINVAL,
              "fspick after umount EINVAL");
        check(unlink("/t_mm/x") == 0
              && rmdir("/t_mm/inner") == 0 && rmdir("/t_mm") == 0
              && rmdir("/t_mm2") == 0, "rmdir mount dirs");
    }

    // ---- privilege gate ----------------------------------------
    pid_t c = fork();
    if (c == 0) {
        if (setuid(1000) != 0) _exit(9);
        int bad = 0;
        if (mount("x", "/tmp", "tmpfs", 0, 0) != -1 || errno != EPERM)
            bad++;
        if (umount2("/dev", 0) != -1 || errno != EPERM)
            bad++;
        unsigned long long zattr[4] = {0, 0, 0, 0};
        if (syscall(428, AT_FDCWD, "/", 0) != -1 || errno != EPERM)
            bad |= 4;
        if (syscall(429, 0, "", AT_FDCWD, "/", 4) != -1
            || errno != EPERM)
            bad |= 8;
        if (syscall(442, AT_FDCWD, "/", 0, zattr, 32) != -1
            || errno != EPERM)
            bad |= 16;
        int pf2 = syscall(433, AT_FDCWD, "/", 0);
        if (pf2 < 0) bad |= 32; else close(pf2);
        _exit(bad);
    }
    int st;
    waitpid(c, &st, 0);
    check(WIFEXITED(st) && WEXITSTATUS(st) == 0,
          "nonroot mount-API EPERM");

    printf("mnttest: %d failures\n", fails);
    return fails;
}
