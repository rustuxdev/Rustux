#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

/*
 * Thread-lifetime DllMain notifications: every loaded module must see
 * DLL_THREAD_ATTACH (forward/load order) before a new thread's start
 * routine runs, and DLL_THREAD_DETACH (reverse order) when the thread
 * exits - on both the return path and an explicit ExitThread.
 *
 * wbase writes 'b' and wchain 'c' into the seq buffer on each
 * notification, so "bc" proves forward attach order and "cb" the
 * reverse detach order; the counters must each read exactly 1 per
 * thread or a doubled/missed callback is caught. Their TLS
 * directory callbacks write 'B'/'C': the loader calls TLS cbs
 * before DllMain on every reason (the real loader calls
 * LdrpCallTlsInitializers first), so one thread's full sequence
 * is "BbCcCcBb"; the exe's own TLS cbs fire last both ways.
 */

static int *bw_att, *bw_det, *cw_att, *cw_det;
static int *bw_tatt, *bw_tdet, *cw_tatt, *cw_tdet, *bw_patt, *cw_patt;
static char seq[64];
static char *seqcur = seq;
typedef void (*regfn)(char **);

/* The exe's own TLS cbs: no ledger slot, invoked from the thread
 * trampoline and the ExitProcess path (exe runs last on detach). */
static int exe_tls_att, exe_tls_det, exe_tls_patt, exe_tls_pdet;
static void NTAPI exe_tls(PVOID h, DWORD r, LPVOID v)
{
    (void)h; (void)v;
    if (r == DLL_PROCESS_ATTACH) {
        exe_tls_patt += 1;
    } else if (r == DLL_PROCESS_DETACH) {
        exe_tls_pdet += 1;
        puts("winthrnt: tls detach");
    } else if (r == DLL_THREAD_ATTACH) {
        exe_tls_att += 1;
        puts("winthrnt: tls thr-attach");
    } else if (r == DLL_THREAD_DETACH) {
        exe_tls_det += 1;
        puts("winthrnt: tls thr-detach");
    }
}
static PIMAGE_TLS_CALLBACK exe_tls_arr[1]
    __attribute__((section(".CRT$XLC"), used)) = { exe_tls };

static DWORD WINAPI worker_ret(LPVOID p)
{
    (void)p;
    /* If we can read these, THREAD_ATTACH already ran. */
    if (*bw_att != 1 || *cw_att != 1)
        return 0xee;
    return 7;
}

static DWORD WINAPI worker_exit(LPVOID p)
{
    (void)p;
    ExitThread(9);
    return 0;
}

static int fail(const char *m, int c)
{
    puts(m);
    return c;
}

int main(void)
{
    HMODULE bw = LoadLibraryA("wbase.dll");
    HMODULE cw = LoadLibraryA("wchain.dll");
    regfn reg;
    HANDLE h;
    DWORD code = 0;

    if (!bw || !cw)
        return fail("winthrnt: dll load failed", 1);
    bw_att = (int *)GetProcAddress(bw, "thr_att");
    bw_det = (int *)GetProcAddress(bw, "thr_det");
    cw_att = (int *)GetProcAddress(cw, "thr_att");
    cw_det = (int *)GetProcAddress(cw, "thr_det");
    if (!bw_att || !bw_det || !cw_att || !cw_det)
        return fail("winthrnt: thread counters missing", 2);
    bw_tatt = (int *)GetProcAddress(bw, "tls_att");
    bw_tdet = (int *)GetProcAddress(bw, "tls_det");
    cw_tatt = (int *)GetProcAddress(cw, "tls_att");
    cw_tdet = (int *)GetProcAddress(cw, "tls_det");
    bw_patt = (int *)GetProcAddress(bw, "tls_patt");
    cw_patt = (int *)GetProcAddress(cw, "tls_patt");
    if (!bw_tatt || !bw_tdet || !cw_tatt || !cw_tdet
        || !bw_patt || !cw_patt)
        return fail("winthrnt: tls counters missing", 12);
    /* LoadLibrary must have run each DLL's TLS cbs with reason 1
     * (CRT may also self-invoke it, so >= 1 not == 1). */
    if (*bw_patt < 1)
        return fail("winthrnt: bw_patt=0", 16);
    if (*cw_patt < 1)
        return fail("winthrnt: cw_patt=0", 17);
    if (exe_tls_patt < 1)
        return fail("winthrnt: exe_patt=0", 18);
    if ((reg = (regfn)GetProcAddress(bw, "seq_reg")))
        reg(&seqcur);
    if ((reg = (regfn)GetProcAddress(cw, "seq_reg")))
        reg(&seqcur);

    /* Thread 1: return path - the trampoline drains detach itself. */
    h = CreateThread(0, 0, worker_ret, 0, 0, 0);
    if (!h)
        return fail("winthrnt: create failed", 3);
    {
        DWORD wr = WaitForSingleObject(h, 5000);
        if (wr != WAIT_OBJECT_0) {
            char mbuf[64];
            snprintf(mbuf, sizeof mbuf,
                     "winthrnt: wait=%lx h=%lx att=%d,%d,%d,%d exe=%d",
                     (unsigned long)wr, (unsigned long)(uintptr_t)h,
                     *bw_att, *cw_att, *bw_tatt, *cw_tatt, exe_tls_att);
            puts(mbuf);
            return fail("winthrnt: wait failed", 4);
        }
    }
    GetExitCodeThread(h, &code);
    CloseHandle(h);
    if (code != 7)
        return fail("winthrnt: worker_ret bad code (att not run?)", 5);
    if (*bw_att != 1 || *cw_att != 1 || *bw_det != 1 || *cw_det != 1)
        return fail("winthrnt: counters wrong after thread 1", 6);
    if (*bw_tatt != 1 || *cw_tatt != 1 || *bw_tdet != 1 || *cw_tdet != 1
        || exe_tls_att != 1 || exe_tls_det != 1)
        return fail("winthrnt: tls counters wrong after thread 1", 14);
    if (strcmp(seq, "BbCcCcBb") != 0) {
        char mbuf[80];
        snprintf(mbuf, sizeof mbuf, "winthrnt: seq='%s' want 'BbCcCcBb'", seq);
        puts(mbuf);
        return 7;
    }

    /* Thread 2: explicit ExitThread - the thunk arm drains detach. */
    h = CreateThread(0, 0, worker_exit, 0, 0, 0);
    if (!h)
        return fail("winthrnt: create2 failed", 8);
    {
        DWORD wr2 = WaitForSingleObject(h, 5000);
        if (wr2 != WAIT_OBJECT_0) {
            char mbuf[64];
            snprintf(mbuf, sizeof mbuf, "winthrnt: wait2=%lx h=%lx",
                     (unsigned long)wr2, (unsigned long)(uintptr_t)h);
            puts(mbuf);
        }
    }
    code = 0;
    GetExitCodeThread(h, &code);
    CloseHandle(h);
    if (code != 9)
        return fail("winthrnt: ExitThread code wrong", 9);
    if (*bw_att != 2 || *cw_att != 2 || *bw_det != 2 || *cw_det != 2)
        return fail("winthrnt: counters wrong after thread 2", 10);
    if (*bw_tatt != 2 || *cw_tatt != 2 || *bw_tdet != 2 || *cw_tdet != 2
        || exe_tls_att != 2 || exe_tls_det != 2)
        return fail("winthrnt: tls counters wrong after thread 2", 15);
    if (strcmp(seq, "BbCcCcBbBbCcCcBb") != 0) {
        char mbuf[96];
        snprintf(mbuf, sizeof mbuf,
                 "winthrnt: seq2='%s' want 'BbCcCcBbBbCcCcBb'", seq);
        puts(mbuf);
        return 11;
    }

    puts("winthrnt: thread + tls attach/detach notifications all ok");
    return 43;
}
