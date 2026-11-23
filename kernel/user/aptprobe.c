// aptprobe: stage a minimal apt+dpkg configuration, then run the
// real Debian apt-get update and apt-get install hello-traditional
// over slirp networking. trusted=yes keeps the probe independent of
// a keyring we do not ship; a seeded dpkg status marks libc6
// installed (we stage its real .so anyway) so the only real fetch
// is the target package.
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>

static void mkd(const char *p) { mkdir(p, 0755); }

static void writef(const char *path, const char *s) {
    FILE *f = fopen(path, "w");
    if (f) { fputs(s, f); fclose(f); }
}

static char *envp[] = {
    "PATH=/sbin:/usr/sbin:/bin:/usr/bin",
    "HOME=/root",
    NULL,
};

static int run(char *const argv[]) {
    pid_t pid = fork();
    if (pid == 0) {
        // headless install semantics: stdin EOF so apt's input
        // feeder and any conffile reads terminate immediately
        int z = open("/dev/null", O_RDONLY);
        if (z >= 0) { dup2(z, 0); if (z > 0) close(z); }
        execve(argv[0], argv, envp);
        perror("aptprobe: execv");
        _exit(127);
    }
    int st = 0;
    if (pid < 0 || waitpid(pid, &st, 0) < 0) return 127;
    if (WIFEXITED(st)) return WEXITSTATUS(st);
    return 128;
}

int main(void) {
    mkd("/tmp");
    chmod("/tmp", 01777);
    mkd("/etc");
    mkd("/etc/apt");
    mkd("/etc/apt/sources.list.d");
    mkd("/etc/apt/apt.conf.d");
    mkd("/etc/apt/preferences.d");
    mkd("/etc/apt/trusted.gpg.d");
    mkd("/var");
    mkd("/var/lib");
    mkd("/var/lib/apt");
    mkd("/var/lib/apt/lists");
    mkd("/var/lib/apt/lists/partial");
    mkd("/var/lib/dpkg");
    mkd("/var/lib/dpkg/info");
    mkd("/var/lib/dpkg/updates");
    mkd("/var/lib/dpkg/alternatives");
    mkd("/var/lib/dpkg/parts");
    mkd("/var/lib/dpkg/triggers");
    mkd("/var/cache");
    mkd("/var/cache/apt");
    mkd("/var/cache/apt/archives");
    mkd("/var/cache/apt/archives/partial");
    mkd("/var/log");
    mkd("/var/log/apt");
    mkd("/usr/lib");
    mkd("/usr/lib/apt");
    mkd("/usr/lib/apt/methods");
    mkd("/usr/bin");
    mkd("/usr/share");
    mkd("/usr/share/doc");
    writef("/etc/apt/sources.list",
           "deb [trusted=yes] http://deb.debian.org/debian bookworm main\n");
    writef("/etc/resolv.conf", "nameserver 10.0.2.3\n");
    // apt needs its arch tables to know what to fetch
    writef("/etc/apt/apt.conf.d/99rustux",
           "APT::Get::AllowUnauthenticated \"true\";\n"
           "Acquire::AllowInsecureRepositories \"true\";\n"
           "Acquire::Languages \"none\";\n"
           "Acquire::GzipIndexes \"true\";\n"
           "APT::Cache-Start \"100000000\";\n"
           "APT::Sandbox::User \"root\";\n"
           // The pty wrap is now real — dpkg runs under
           // posix_openpt with output tee'd to term.log.
           "Dpkg::Use-Pty \"true\";\n"
           "Dir::Cache::pkgcache \"\";\n"
           "Dir::Cache::srcpkgcache \"\";\n");
    // libc6 is the only dependency of hello-traditional; we already
    // stage the real .so, so mark it installed and the fetch list is
    // just the target package.
    writef("/var/lib/dpkg/status",
           "Package: libc6\n"
           "Status: install ok installed\n"
           "Priority: required\n"
           "Section: libs\n"
           "Installed-Size: 13038\n"
           "Maintainer: GNU Libc Maintainers <debian-glibc@lists.debian.org>\n"
           "Architecture: amd64\n"
           "Multi-Arch: same\n"
           "Source: glibc\n"
           "Version: 2.36-9+deb12u13\n"
           "Description: GNU C Library: Shared libraries\n"
           "\n");
    int fails = 0;
    char *u[] = {"/usr/bin/apt-get", "update", NULL};
    int rc = run(u);
    printf("aptprobe: apt-get update -> %d\n", rc);
    if (rc != 0) fails++;
    char *i[] = {"/usr/bin/apt-get", "-y", "install",
                 "--no-install-recommends", "hello-traditional", NULL};
    rc = run(i);
    printf("aptprobe: apt-get install -> %d\n", rc);
    if (rc != 0) fails++;
    char *h[] = {"/usr/bin/hello", NULL};
    rc = run(h);
    printf("aptprobe: hello -> %d\n", rc);
    if (rc != 0) fails++;
    printf("aptprobe: %d failures\n", fails);
    return fails;
}
