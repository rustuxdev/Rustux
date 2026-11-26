// keytest — keyctl ABI checks (add_key 248, request_key 249,
// keyctl 250): ring resolution, lifecycle, search chain, perms.
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sys/types.h>

static int fails;
static void check(int ok, const char *what) {
    if (!ok) {
        printf("FAIL: %s\n", what);
        fails++;
    }
}

#define K_THREAD   (-1)
#define K_PROCESS  (-2)
#define K_SESSION  (-3)
#define K_USER     (-4)
#define K_USESSION (-5)
#define K_GROUP    (-6)
#define K_REQAUTH  (-7)

static long addkey(const char *t, const char *d,
                   const void *p, unsigned pl, long ring) {
    return syscall(248, t, d, p, pl, ring);
}
static long reqkey(const char *t, const char *d,
                   const char *info, long dest) {
    return syscall(249, t, d, info, dest);
}
static long keyctl(long cmd, long a2, long a3, long a4, long a5) {
    return syscall(250, cmd, a2, a3, a4, a5);
}

int main(void) {
    // ---- add_key basics --------------------------------------
    errno = 0;
    check(addkey("bogus", "d", "x", 1, K_PROCESS) < 0
          && errno == ENODEV, "add_key bad type ENODEV");
    errno = 0;
    check(addkey("user", "", "x", 1, K_PROCESS) < 0
          && errno == EINVAL, "add_key empty desc EINVAL");
    errno = 0;
    check(addkey("user", "d", "x", 2048, K_PROCESS) < 0
          && errno == EINVAL, "add_key oversize payload EINVAL");
    errno = 0;
    check(addkey("user", "d", (void*)0xdead, 8, K_PROCESS) < 0
          && errno == EFAULT, "add_key bad payload ptr EFAULT");
    errno = 0;
    check(addkey("user", "d", "x", 1, K_GROUP) < 0
          && errno == EINVAL, "add_key group ring EINVAL");

    long k1 = addkey("user", "k1", "hello", 5, K_PROCESS);
    check(k1 > 0, "add_key process ring");
    long k2 = addkey("user", "k2", "worldwide", 9, K_USER);
    check(k2 > 0 && k2 != k1, "add_key user ring");
    // duplicate desc in the same ring updates, doesn't dup
    long k1b = addkey("user", "k1", "HELLO2", 6, K_PROCESS);
    check(k1b == k1, "add_key dup desc updates");

    // ---- GET_KEYRING_ID ---------------------------------------
    long pr = keyctl(0, K_PROCESS, 0, 0, 0);
    check(pr > 0, "get_keyring_id process");
    long ur = keyctl(0, K_USER, 1, 0, 0);
    check(ur > 0 && ur != pr, "get_keyring_id user");
    long pr2 = keyctl(0, K_PROCESS, 0, 0, 0);
    check(pr2 == pr, "ring id stable");
    long badser = keyctl(0, 0xbeef, 0, 0, 0);
    check(badser < 0 && errno == ENOKEY, "bad ring serial ENOKEY");
    long groupring = keyctl(0, K_GROUP, 0, 0, 0);
    check(groupring < 0 && errno == EINVAL, "group ring EINVAL");

    // ---- READ / DESCRIBE --------------------------------------
    char buf[512];
    long n = keyctl(11, k1, buf, sizeof(buf), 0);
    check(n == 6 && memcmp(buf, "HELLO2", 6) == 0,
          "read updated payload");
    n = keyctl(11, k1, buf, 3, 0);
    check(n == 6 && memcmp(buf, "HEL", 3) == 0,
          "read truncates but reports full");
    n = keyctl(11, k1, buf, 0, 0);
    check(n == 6, "read size probe");
    // keyring READ returns member serials
    unsigned ks[16];
    n = keyctl(11, ur, ks, sizeof(ks), 0);
    check(n == 4 && ks[0] == (unsigned)k2, "ring read serials");
    memset(buf, 0, sizeof(buf));
    n = keyctl(6, k1, buf, sizeof(buf), 0);
    check(n > 0 && strstr(buf, "user;") == buf
          && strstr(buf, ";k1") != NULL, "describe format");
    // dead serial
    errno = 0;
    check(keyctl(11, 0xabcd, buf, sizeof(buf), 0) < 0
          && errno == ENOKEY, "read dead serial ENOKEY");

    // ---- UPDATE / REVOKE --------------------------------------
    errno = 0;
    check(keyctl(2, k1, "NEWDATA", 7, 0) == 0, "update payload");
    n = keyctl(11, k1, buf, sizeof(buf), 0);
    check(n == 7 && memcmp(buf, "NEWDATA", 7) == 0,
          "update visible");
    errno = 0;
    check(keyctl(3, k1, 0, 0, 0) == 0, "revoke");
    errno = 0;
    check(keyctl(11, k1, buf, sizeof(buf), 0) < 0
          && errno == ENOKEY, "read revoked ENOKEY");
    // re-add after revoke -> fresh serial
    k1 = addkey("user", "k1", "again", 5, K_PROCESS);
    check(k1 > 0, "re-add after revoke");

    // ---- SEARCH / LINK / UNLINK / CLEAR -----------------------
    long sr = keyctl(10, pr, "user", "k1", 0);
    check(sr == k1, "search finds k1 in process ring");
    errno = 0;
    check(keyctl(10, pr, "user", "nope", 0) < 0
          && errno == ENOKEY, "search miss ENOKEY");
    // link user-ring key into process ring
    check(keyctl(8, k2, pr, 0, 0) == 0, "link key to second ring");
    errno = 0;
    check(keyctl(8, k2, pr, 0, 0) < 0 && errno == EEXIST,
          "relink EEXIST");
    check(keyctl(10, pr, "user", "k2", 0) == k2,
          "search finds linked key");
    check(keyctl(9, k2, pr, 0, 0) == 0, "unlink from process ring");
    errno = 0;
    check(keyctl(9, k2, pr, 0, 0) < 0 && errno == ENOKEY,
          "double unlink ENOKEY");
    // k2 still lives in the user ring
    check(keyctl(10, ur, "user", "k2", 0) == k2,
          "key survives in other ring");
    check(keyctl(7, pr, 0, 0, 0) == 0, "clear process ring");
    errno = 0;
    check(keyctl(10, pr, "user", "k2", 0) < 0 && errno == ENOKEY,
          "cleared ring empty");
    // k1 lived only in the process ring — clear killed it
    errno = 0;
    check(keyctl(11, k1, buf, sizeof(buf), 0) < 0
          && errno == ENOKEY, "cleared key GC'd");

    // ---- request_key chain ------------------------------------
    long k3 = addkey("user", "want", "v3", 2, K_USER);
    check(k3 > 0, "add for request_key");
    check(reqkey("user", "want", 0, 0) == k3,
          "request_key hits user ring");
    errno = 0;
    check(reqkey("user", "absent", 0, 0) < 0 && errno == ENOKEY,
          "request_key miss ENOKEY");
    // request_key links the hit into the dest ring
    check(reqkey("user", "want", 0, K_PROCESS) == k3,
          "request_key dest");
    check(keyctl(10, pr, "user", "want", 0) == k3,
          "request_key linked into process ring");

    // ---- JOIN_SESSION_KEYRING ---------------------------------
    long jr = keyctl(1, "sess1", 0, 0, 0);
    check(jr > 0, "join named session ring");
    long jr2 = keyctl(1, "sess1", 0, 0, 0);
    check(jr2 == jr, "join same name same ring");
    // session-spec ring now resolves to the joined ring
    check(keyctl(0, K_SESSION, 0, 0, 0) == jr,
          "session spec resolves joined ring");
    check(addkey("user", "sk", "sv", 2, K_SESSION) > 0,
          "add via session ring");
    long ksk = keyctl(10, K_SESSION, "user", "sk", 0);
    check(ksk > 0, "search via session spec");

    // ---- CHOWN / SETPERM / INVALIDATE --------------------------
    check(keyctl(4, k3, 1000, -1, 0) == 0, "chown to uid 1000");
    check(keyctl(4, k3, 0, -1, 0) == 0, "chown back to 0");
    check(keyctl(5, k3, 0x3f3f0000, 0, 0) == 0, "setperm");
    errno = 0;
    check(keyctl(21, k3, 0, 0, 0) == 0, "invalidate");
    errno = 0;
    check(keyctl(11, k3, buf, sizeof(buf), 0) < 0
          && errno == ENOKEY, "invalidated gone");

    // ---- SET_REQKEY_KEYRING ------------------------------------
    long oldm = keyctl(14, 4, 0, 0, 0);   // USER ring only
    check(oldm == 0, "reqkey default mode");
    k3 = addkey("user", "want2", "v3b", 3, K_USER);
    check(k3 > 0, "re-add after invalidate");
    check(reqkey("user", "want2", 0, 0) == k3,
          "reqkey user-only mode hits user ring");
    long knothere = addkey("user", "onlyproc", "x", 1, K_PROCESS);
    check(knothere > 0, "add proc-only key");
    errno = 0;
    check(reqkey("user", "onlyproc", 0, 0) < 0 && errno == ENOKEY,
          "reqkey user-only misses proc key");
    keyctl(14, 0, 0, 0, 0);               // restore default chain
    check(reqkey("user", "onlyproc", 0, 0) == knothere,
          "default chain finds proc key");

    // ---- CAPABILITIES -------------------------------------------
    unsigned char caps[8] = {0};
    n = keyctl(31, caps, 8, 0, 0);
    check(n == 8 && caps[0] & 1, "capabilities");

    // ---- unknown ops -------------------------------------------
    errno = 0;
    check(keyctl(99, 0, 0, 0, 0) < 0 && errno == EINVAL,
          "unknown keyctl cmd EINVAL");

    // ---- perms: other-uid key hidden ---------------------------
    long ksec = addkey("user", "secret", "shh", 3, K_USER);
    check(ksec > 0, "add secret key");
    check(keyctl(5, ksec, 0x3f000000, 0, 0) == 0,
          "setperm possessor-only");
    pid_t c = fork();
    if (c == 0) {
        if (setuid(1000) != 0) _exit(9);
        int bad = 0;
        char tb[64];
        errno = 0;
        if (keyctl(11, ksec, tb, sizeof(tb), 0) != -1
            || errno != ENOKEY)
            bad++;
        errno = 0;
        if (keyctl(10, K_USER, "user", "secret", 0) != -1
            || errno != ENOKEY)
            bad++;
        errno = 0;
        if (keyctl(4, ksec, 1000, -1, 0) != -1 || errno != EPERM)
            bad++;
        _exit(bad);
    }
    int st;
    waitpid(c, &st, 0);
    check(WIFEXITED(st) && WEXITSTATUS(st) == 0,
          "other-uid key hidden+chown EPERM");

    printf("keytest: %d failures\n", fails);
    return fails;
}
