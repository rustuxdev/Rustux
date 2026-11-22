#include <windows.h>
#include <stdio.h>
#include <string.h>

/*
 * Thread-lifetime DllMain notifications: every loaded module must see
 * DLL_THREAD_ATTACH (forward/load order) before a new thread's start
 * routine runs, and DLL_THREAD_DETACH (reverse order) when the thread
 * exits — on both the return path and an explicit ExitThread.
 *
 * wbase writes 'b' and wchain 'c' into the seq buffer on each
 * notification, so "bc" proves forward attach order and "cb" the
 * reverse detach order; the counters must each read exactly 1 per
 * thread or a doubled/missed callback is caught.
 */

static int *bw_att, *bw_det, *cw_att, *cw_det;
static char seq[64];
static char *seqcur = seq;
typedef void (*regfn)(char **);

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
    if ((reg = (regfn)GetProcAddress(bw, "seq_reg")))
        reg(&seqcur);
    if ((reg = (regfn)GetProcAddress(cw, "seq_reg")))
        reg(&seqcur);

    /* Thread 1: return path — the trampoline drains detach itself. */
    h = CreateThread(0, 0, worker_ret, 0, 0, 0);
    if (!h)
        return fail("winthrnt: create failed", 3);
    if (WaitForSingleObject(h, 5000) != WAIT_OBJECT_0)
        return fail("winthrnt: wait failed", 4);
    GetExitCodeThread(h, &code);
    CloseHandle(h);
    if (code != 7)
        return fail("winthrnt: worker_ret bad code (att not run?)", 5);
    if (*bw_att != 1 || *cw_att != 1 || *bw_det != 1 || *cw_det != 1)
        return fail("winthrnt: counters wrong after thread 1", 6);
    if (strcmp(seq, "bccb") != 0) {
        printf("winthrnt: seq='%s' want 'bccb'\n", seq);
        return 7;
    }

    /* Thread 2: explicit ExitThread — the thunk arm drains detach. */
    h = CreateThread(0, 0, worker_exit, 0, 0, 0);
    if (!h)
        return fail("winthrnt: create2 failed", 8);
    WaitForSingleObject(h, 5000);
    code = 0;
    GetExitCodeThread(h, &code);
    CloseHandle(h);
    if (code != 9)
        return fail("winthrnt: ExitThread code wrong", 9);
    if (*bw_att != 2 || *cw_att != 2 || *bw_det != 2 || *cw_det != 2)
        return fail("winthrnt: counters wrong after thread 2", 10);
    if (strcmp(seq, "bccbbccb") != 0) {
        printf("winthrnt: seq2='%s' want 'bccbbccb'\n", seq);
        return 11;
    }

    puts("winthrnt: thread attach/detach notifications all ok");
    return 43;
}
