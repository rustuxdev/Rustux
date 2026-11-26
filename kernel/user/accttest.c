// accttest — syscall(163 acct, 135 personality, 159 adjtimex) checks.
// Exit status = number of failed checks.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/personality.h>
#include <sys/timex.h>
#include <sys/prctl.h>
#include <sys/syscall.h>

static int fails;
static void check(int ok, const char *what) {
    if (!ok) {
        printf("FAIL: %s\n", what);
        fails++;
    }
}

// acct has no glibc wrapper.
static int sys_acct(const char *p) {
    return (int)syscall(163, (long)p);
}

int main(void) {
    // ---- personality(135) -------------------------------------
    errno = 0;
    int p0 = personality(0xffffffff);
    check(errno == 0 && p0 >= 0, "personality query works");
    int prev = personality(0x12345);
    check(prev == p0, "personality set returns previous");
    check(personality(0xffffffff) == 0x12345,
          "personality set landed");
    // fork inherits
    pid_t c = fork();
    if (c == 0) {
        _exit(personality(0xffffffff) == 0x12345 ? 0 : 1);
    }
    int ws;
    check(c > 0 && waitpid(c, &ws, 0) == c && WIFEXITED(ws)
          && WEXITSTATUS(ws) == 0, "personality inherited at fork");
    personality(0); // restore

    // ---- adjtimex(159) ----------------------------------------
    struct timex tx;
    memset(&tx, 0, sizeof(tx));
    tx.modes = 0; // read-only query — unprivileged OK
    int st = adjtimex(&tx);
    check(st == 5, "adjtimex query -> TIME_ERROR (unsync)");
    check(tx.status & STA_UNSYNC, "status has STA_UNSYNC");
    check(tx.time.tv_sec > 1000000000, "wall time filled");
    // unknown mode bit -> EINVAL
    memset(&tx, 0, sizeof(tx));
    tx.modes = 0x00040000;
    errno = 0;
    check(adjtimex(&tx) == -1 && errno == EINVAL,
          "adjtimex unknown mode -> EINVAL");
    // set STATUS minus UNSYNC (root) -> next query TIME_OK
    memset(&tx, 0, sizeof(tx));
    tx.modes = ADJ_STATUS;
    tx.status = STA_PLL; // clears UNSYNC
    check(adjtimex(&tx) != -1, "adjtimex set status (root)");
    memset(&tx, 0, sizeof(tx));
    tx.modes = 0;
    check(adjtimex(&tx) == 0 && !(tx.status & STA_UNSYNC),
          "adjtimex set->query round-trip, TIME_OK");
    // TICK round-trip
    memset(&tx, 0, sizeof(tx));
    tx.modes = ADJ_TICK;
    tx.tick = 9999;
    check(adjtimex(&tx) != -1, "adjtimex set tick");
    memset(&tx, 0, sizeof(tx));
    check(adjtimex(&tx) != -1 && tx.tick == 9999,
          "adjtimex tick round-trip");

    // ---- acct(163) ---------------------------------------------
    mkdir("/t_ac", 0777);
    // not-yet-existing path -> ENOENT (no O_CREAT)
    errno = 0;
    check(sys_acct("/t_ac/nope") == -1 && errno == ENOENT,
          "acct missing file -> ENOENT");
    // dir -> EISDIR
    errno = 0;
    check(sys_acct("/t_ac") == -1 && errno == EISDIR,
          "acct dir -> EISDIR");
    // real file -> on
    int afd = open("/t_ac/log", O_CREAT | O_WRONLY, 0666);
    check(afd >= 0, "acct file created");
    close(afd);
    check(sys_acct("/t_ac/log") == 0, "acct on");
    // a uniquely named child exits -> a record lands
    pid_t k = fork();
    if (k == 0) {
        prctl(15 /*PR_SET_NAME*/, "acm", 0, 0, 0);
        _exit(42);
    }
    check(k > 0, "acct child forked");
    waitpid(k, &ws, 0);
    check(WIFEXITED(ws) && WEXITSTATUS(ws) == 42,
          "acct child exit 42");
    // the record may lag the reap a tick — poll the file size
    struct stat sb;
    int grew = 0;
    for (int i = 0; i < 100 && !grew; i++) {
        if (stat("/t_ac/log", &sb) == 0 && sb.st_size >= 64)
            grew = 1;
        else
            usleep(10 * 1000);
    }
    check(grew, "acct record emitted at exit");
    // parse the tail records for our comm + exitcode
    int found = 0;
    afd = open("/t_ac/log", O_RDONLY);
    if (afd >= 0) {
        unsigned char rec[64];
        while (read(afd, rec, 64) == 64) {
            // comm @48, 16B; exitcode @4 (u32); version @1; pid @16
            if (memcmp(&rec[48], "acm", 3) == 0) {
                unsigned int ec;
                memcpy(&ec, &rec[4], 4);
                unsigned int rp;
                memcpy(&rp, &rec[16], 4);
                check((ec >> 8) == 42,
                      "acct record exitcode = 42 << 8");
                check(rp == (unsigned)k, "acct record pid");
                check(rec[1] == 2, "acct record version");
                check(rec[0] & 0x01, "acct record AFORK (no exec)");
                found = 1;
            }
        }
        close(afd);
    }
    check(found, "acct record comm 'acm' present");
    // off
    check(sys_acct(NULL) == 0, "acct off");
    // after off, another exit appends nothing
    stat("/t_ac/log", &sb);
    long before = sb.st_size;
    pid_t k2 = fork();
    if (k2 == 0) _exit(0);
    waitpid(k2, &ws, 0);
    usleep(150 * 1000);
    stat("/t_ac/log", &sb);
    check(sb.st_size == before, "acct off -> no growth");

    // ---- permission gates (drop to uid 1000 last) --------------
    c = fork();
    if (c == 0) {
        if (setuid(1000)) _exit(9);
        errno = 0;
        int r1 = sys_acct("/t_ac/log");
        int e1 = errno;
        memset(&tx, 0, sizeof(tx));
        tx.modes = ADJ_STATUS;
        int r2 = adjtimex(&tx);
        int e2 = errno;
        _exit(r1 == -1 && e1 == EPERM && r2 == -1 && e2 == EPERM
                  ? 0
                  : 1);
    }
    check(c > 0 && waitpid(c, &ws, 0) == c && WIFEXITED(ws)
          && WEXITSTATUS(ws) == 0, "nonroot acct/adjtimex -> EPERM");

    // ---- cleanup (leak gate) ----
    unlink("/t_ac/log");
    unlink("/t_ac/nope");
    rmdir("/t_ac");

    printf("accttest: %d failures\n", fails);
    return fails;
}
