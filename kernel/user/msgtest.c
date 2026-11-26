// msgtest — SysV message queues (msgget 68 / msgsnd 69 /
// msgrcv 70 / msgctl 71). Blocking send/receive ride the
// WaitOn machinery; ids are gen<<16|slot like SHM.
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sys/ipc.h>
#include <sys/msg.h>

static int fails;
#define check(c, msg) do { \
    if (c) printf("msgtest: %-40s ok\n", msg); \
    else { printf("msgtest: %-40s FAIL\n", msg); fails++; } \
} while (0)

struct mbuf { long mtype; char text[64]; };

int main(void) {
    printf("msgtest: sysv message queues\n");

    // --- msgget (pid-derived key: concurrent suite instances
    // must not share the queue)
    key_t k = 0x12345 + getpid() * 16;
    errno = 0;
    check(msgget(k, 0) == -1 && errno == ENOENT, "msgget missing ENOENT");
    int q = msgget(k, IPC_CREAT | 0600);
    check(q >= 0, "msgget create");
    check(msgget(k, IPC_CREAT | IPC_EXCL) == -1 && errno == EEXIST,
          "msgget EXCL EEXIST");
    int q2 = msgget(k, 0);
    check(q2 == q, "msgget same key same id");
    int qpv = msgget(IPC_PRIVATE, 0600);
    check(qpv >= 0, "msgget PRIVATE mints");

    // --- msgsnd/msgrcv basics
    struct mbuf m = {0};
    m.mtype = 1; strcpy(m.text, "hello");
    check(msgsnd(q, &m, 6, 0) == 0, "msgsnd type1");
    m.mtype = 2; strcpy(m.text, "world");
    check(msgsnd(q, &m, 6, 0) == 0, "msgsnd type2");
    memset(&m, 0, sizeof m);
    check(msgrcv(q, &m, sizeof(m.text), 2, IPC_NOWAIT) == 6 && m.mtype == 2
          && !strcmp(m.text, "world"), "msgrcv type match");
    memset(&m, 0, sizeof m);
    check(msgrcv(q, &m, sizeof(m.text), 0, IPC_NOWAIT) == 6 && m.mtype == 1
          && !strcmp(m.text, "hello"), "msgrcv fifo first");
    errno = 0;
    check(msgrcv(q, &m, sizeof(m.text), 0, IPC_NOWAIT) == -1 && errno == ENOMSG,
          "msgrcv empty ENOMSG");

    // --- mtype<0: lowest type <= |mtype|
    m.mtype = 5; strcpy(m.text, "five"); msgsnd(q, &m, 5, 0);
    m.mtype = 2; strcpy(m.text, "two");  msgsnd(q, &m, 4, 0);
    m.mtype = 7; strcpy(m.text, "seven"); msgsnd(q, &m, 6, 0);
    memset(&m, 0, sizeof m);
    check(msgrcv(q, &m, sizeof(m.text), -5, IPC_NOWAIT) == 4 && m.mtype == 2
          && !strcmp(m.text, "two"), "msgrcv lowest <= |mtype|");
    memset(&m, 0, sizeof m);
    check(msgrcv(q, &m, sizeof(m.text), -5, IPC_NOWAIT) == 5 && m.mtype == 5,
          "msgrcv next lowest");

    // --- MSG_EXCEPT / MSG_NOERROR / errno gates
    errno = 0;
    check(msgrcv(q, &m, sizeof(m.text), 7, IPC_NOWAIT | MSG_EXCEPT) == -1
          && errno == ENOMSG, "msgrcv EXCEPT only-7 ENOMSG");
    m.mtype = 7;
    memset(m.text, 0, sizeof m.text); strcpy(m.text, "seven");
    check(msgrcv(q, &m, 3, 0, IPC_NOWAIT | MSG_NOERROR) == 3
          && !strncmp(m.text, "sev", 3), "msgrcv NOERROR truncates");
    m.mtype = 9; strcpy(m.text, "overflowed");
    msgsnd(q, &m, 10, 0);
    errno = 0;
    check(msgrcv(q, &m, 3, 0, IPC_NOWAIT) == -1 && errno == E2BIG,
          "msgrcv oversize E2BIG");
    msgrcv(q, &m, sizeof(m.text), 0, IPC_NOWAIT); /* drain */
    errno = 0;
    m.mtype = 0;
    check(msgsnd(q, &m, 1, 0) == -1 && errno == EINVAL, "msgsnd type0 EINVAL");
    m.mtype = 1;
    errno = 0;
    check(msgsnd(q, &m, 9000, 0) == -1 && errno == EINVAL, "msgsnd >msgmax EINVAL");
    errno = 0;
    check(msgsnd(0xdead, &m, 1, 0) == -1 && errno == EINVAL, "msgsnd bad id EINVAL");
    errno = 0;
    check(msgrcv(q, &m, 4, -1, MSG_EXCEPT) == -1 && errno == EINVAL,
          "msgrcv EXCEPT type<=0 EINVAL");

    // --- msgctl IPC_STAT / IPC_SET / IPC_RMID
    struct msqid_ds ds;
    memset(&ds, 0, sizeof ds);
    check(msgctl(q, IPC_STAT, &ds) == 0, "msgctl IPC_STAT");
    check(ds.msg_qbytes == 16384, "stat qbytes 16384");
    check(ds.msg_qnum == 0, "stat qnum 0 drained");
    m.mtype = 1; strcpy(m.text, "q");
    msgsnd(q, &m, 2, 0);
    memset(&ds, 0, sizeof ds);
    msgctl(q, IPC_STAT, &ds);
    check(ds.msg_qnum == 1 && ds.msg_cbytes == 2, "stat qnum+cbytes");
    check(msgctl(q, IPC_SET, &ds) == 0, "msgctl IPC_SET");
    errno = 0;
    check(msgctl(0xdead, IPC_STAT, &ds) == -1 && errno == EINVAL,
          "msgctl bad id EINVAL");
    check(msgctl(q, IPC_RMID, 0) == 0, "msgctl IPC_RMID");
    errno = 0;
    check(msgsnd(q, &m, 1, 0) == -1 && errno == EINVAL,
          "msgsnd after RMID EINVAL");

    // --- blocking receive: child sleeps, parent sends
    int q3 = msgget(IPC_PRIVATE, 0600);
    pid_t p = fork();
    if (p == 0) {
        struct mbuf r = {0};
        long n = msgrcv(q3, &r, sizeof(r.text), 0, 0); /* blocks */
        _exit(n == 5 && r.mtype == 3 && !strcmp(r.text, "wake") ? 9 : 8);
    }
    usleep(40000);
    m.mtype = 3; strcpy(m.text, "wake");
    check(msgsnd(q3, &m, 5, 0) == 0, "msgsnd wakes blocked rcv");
    int st = 0;
    waitpid(p, &st, 0);
    check(WIFEXITED(st) && WEXITSTATUS(st) == 9, "msgrcv blocked got msg");

    // --- blocking send: fill the qbytes ceiling, child blocks,
    // parent drains one to wake it
    int q4 = msgget(IPC_PRIVATE, 0600);
    m.mtype = 1;
    int sent = 0;
    while (msgsnd(q4, &m, 512, IPC_NOWAIT) == 0) { sent++; }
    check(sent == 32, "queue fills at 16KiB");
    p = fork();
    if (p == 0) {
        long r = msgsnd(q4, &m, 512, 0); /* blocks */
        _exit(r == 0 ? 9 : 8);
    }
    usleep(40000);
    struct { long t; char x[512]; } big = {0};
    check(msgrcv(q4, &big, sizeof(big.x), 0, IPC_NOWAIT) == 512,
          "drain one wakes blocked snd");
    st = 0;
    waitpid(p, &st, 0);
    check(WIFEXITED(st) && WEXITSTATUS(st) == 9, "msgsnd blocked linked");

    // --- RMID wakes a blocked receiver with EIDRM
    int q5 = msgget(IPC_PRIVATE, 0600);
    p = fork();
    if (p == 0) {
        struct mbuf r3 = {0};
        errno = 0;
        long n = msgrcv(q5, &r3, sizeof(r3.text), 0, 0); /* blocks */
        _exit(n == -1 && errno == EIDRM ? 9 : 8);
    }
    usleep(40000);
    check(msgctl(q5, IPC_RMID, 0) == 0, "RMID with blocked rcv");
    st = 0;
    waitpid(p, &st, 0);
    check(WIFEXITED(st) && WEXITSTATUS(st) == 9, "blocked rcv sees EIDRM");

    // queues persist like Linux — RMID what we minted so the
    // frame accounting sees a clean reap
    msgctl(qpv, IPC_RMID, 0);
    msgctl(q3, IPC_RMID, 0);
    msgctl(q4, IPC_RMID, 0);

    printf("msgtest: %d failures\n", fails);
    return fails;
}
