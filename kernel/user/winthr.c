// winthr.c -- NT thread test for Rustux. Exercises:
//  * CreateThread (two workers) + WaitForSingleObject joins
//  * GetExitCodeThread: STILL_ACTIVE while running, real code after
//  * Per-thread TLS slots (TlsAlloc/TlsSetValue) and __thread storage
//  * GetThreadId / GetCurrentThreadId: unique tids, shared process
//  * CREATE_SUSPENDED + wait-timeout + ResumeThread
//  * Cross-thread handle use: a worker waits on a leader-opened handle
//  * CloseHandle on thread handles
// Built with x86_64-w64-mingw32-gcc, run inside the Rustux boot test.
#include <windows.h>
#include <stdio.h>
#include <stdint.h>

static __thread int thr_val = 7; /* compiled TLS template (slot 0) */

static volatile int vals[2];
static volatile DWORD tids[2];
static volatile int join_res;

typedef struct {
    int idx;
    DWORD code;
} Arg;

typedef struct {
    HANDLE h;
    DWORD want;
} JoinArg;

/* Waits on a handle the MAIN thread opened: Windows handles are
   process objects, so a thread must resolve the same table. */
static DWORD WINAPI joiner(LPVOID p)
{
    JoinArg *a = (JoinArg *)p;
    DWORD c = 0;

    if (WaitForSingleObject(a->h, 5000) != WAIT_OBJECT_0) {
        join_res = -1;
        return 6;
    }
    if (!GetExitCodeThread(a->h, &c) || c != a->want) {
        join_res = -2;
        return 7;
    }
    join_res = 1;
    return 43;
}

static DWORD WINAPI worker(LPVOID p)
{
    Arg *a = (Arg *)p;
    DWORD slot;

    thr_val = 100 + a->idx; /* must not touch the main thread's copy */
    slot = TlsAlloc();
    if (slot == TLS_OUT_OF_INDEXES) {
        vals[a->idx] = -1;
        return 5;
    }
    TlsSetValue(slot, (LPVOID)(uintptr_t)(0xA0 + a->idx));
    if ((DWORD)(uintptr_t)TlsGetValue(slot) != (DWORD)(0xA0 + a->idx)) {
        vals[a->idx] = -2;
        return 6;
    }
    TlsFree(slot);
    if (thr_val != 100 + a->idx) {
        vals[a->idx] = -3;
        return 7;
    }
    vals[a->idx] = 1;
    tids[a->idx] = GetCurrentThreadId();
    return a->code; /* returns into the kernel's ExitThread stub */
}

int main(void)
{
    int bad = 0;
    static Arg a0 = {0, 41}, a1 = {1, 42}, a2 = {0, 9};
    HANDLE h0, h1, h2;
    DWORD c0 = 0, c1 = 0, c2 = 0, st = 0;

    thr_val = 3;
    h0 = CreateThread(NULL, 0, worker, &a0, 0, NULL);
    h1 = CreateThread(NULL, 0, worker, &a1, 0, NULL);
    if (!h0 || !h1) {
        printf("winthr: CreateThread failed\n");
        return 1;
    }
    if (h0 == h1)
        bad |= 0x2;

    /* h0 may still be running: its exit code is either pending or 41. */
    GetExitCodeThread(h0, &st);
    if (st != STILL_ACTIVE && st != 41)
        bad |= 0x4;

    if (WaitForSingleObject(h0, 5000) != WAIT_OBJECT_0)
        bad |= 0x8;
    if (WaitForSingleObject(h1, 5000) != WAIT_OBJECT_0)
        bad |= 0x10;

    if (!GetExitCodeThread(h0, &c0) || c0 != 41)
        bad |= 0x20;
    if (!GetExitCodeThread(h1, &c1) || c1 != 42)
        bad |= 0x40;
    if (vals[0] != 1 || vals[1] != 1)
        bad |= 0x80;
    if (tids[0] == 0 || tids[0] == tids[1] ||
        tids[0] == GetCurrentThreadId())
        bad |= 0x100;
    if (thr_val != 3) /* workers must not leak into our TLS copy */
        bad |= 0x200;

    /* CREATE_SUSPENDED: wait times out, ResumeThread wakes it. */
    h2 = CreateThread(NULL, 0, worker, &a2, CREATE_SUSPENDED, NULL);
    if (!h2) {
        bad |= 0x400;
    } else {
        if (WaitForSingleObject(h2, 50) != WAIT_TIMEOUT)
            bad |= 0x800;
        vals[0] = 0;
        if (ResumeThread(h2) == (DWORD)-1)
            bad |= 0x1000;
        if (WaitForSingleObject(h2, 5000) != WAIT_OBJECT_0)
            bad |= 0x2000;
        if (!GetExitCodeThread(h2, &c2) || c2 != 9)
            bad |= 0x4000;
        if (vals[0] != 1)
            bad |= 0x8000;
        CloseHandle(h2);
    }

    /* Cross-thread handle use: a worker waits on h0 — a handle the
       leader opened — and reads its exit code. */
    {
        static JoinArg ja;
        HANDLE hJ;
        DWORD cj = 0;

        ja.h = h0;
        ja.want = 41;
        join_res = 0;
        hJ = CreateThread(NULL, 0, joiner, &ja, 0, NULL);
        if (!hJ) {
            bad |= 0x20000;
        } else {
            if (WaitForSingleObject(hJ, 5000) != WAIT_OBJECT_0)
                bad |= 0x40000;
            if (!GetExitCodeThread(hJ, &cj) || cj != 43)
                bad |= 0x80000;
            if (join_res != 1)
                bad |= 0x100000;
            CloseHandle(hJ);
        }
    }

    if (!CloseHandle(h0) || !CloseHandle(h1))
        bad |= 0x10000;

    if (bad) {
        printf("winthr: FAIL %x\n", bad);
        return bad; /* raw mask shows in the kernel exit log */
    }
    puts("winthr: CreateThread/wait/exitcode/TLS/suspend/xhandle all ok");
    return 37;
}
