// aptprobe: stage a minimal apt configuration, then run the real
// Debian apt-get update over slirp networking. Trusted=yes keeps the
// probe independent of a keyring we do not ship.
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
    mkd("/var/cache");
    mkd("/var/cache/apt");
    mkd("/var/cache/apt/archives");
    mkd("/var/cache/apt/archives/partial");
    mkd("/var/log");
    mkd("/var/log/apt");
    mkd("/usr/lib");
    mkd("/usr/lib/apt");
    mkd("/usr/lib/apt/methods");
    writef("/etc/apt/sources.list",
           "deb [trusted=yes] http://deb.debian.org/debian bookworm main\n");
    writef("/var/lib/dpkg/status", "");
    writef("/etc/resolv.conf", "nameserver 10.0.2.3\n");
    // apt needs its arch tables to know what to fetch
    writef("/etc/apt/apt.conf.d/99rustux",
           "APT::Get::AllowUnauthenticated \"true\";\n"
           "Acquire::AllowInsecureRepositories \"true\";\n"
           "Acquire::Languages \"none\";\n"
           "Acquire::GzipIndexes \"true\";\n"
           "APT::Cache-Start \"100000000\";\n"
           "Dir::Cache::pkgcache \"\";\n"
           "Dir::Cache::srcpkgcache \"\";\n");
    char *argv[] = {"/usr/bin/apt-get", "update", NULL};
    execv(argv[0], argv);
    perror("aptprobe: execv apt-get");
    return 127;
}
