/* winmisc.c — real MinGW fixture for run-113 process-parameter
 * and memory-info fidelity on Rustux's PERS_NT personality.
 *
 * Exercises: GetCommandLineW (real UTF-16 from the PEB),
 * GetCurrentProcessId/ThreadId (TEB ClientId), 64-slot TLS via the
 * gs:[0x58] slot array, GetEnvironmentStringsA, GetStartupInfoA,
 * VirtualQuery/VirtualProtect backed by real NT services, and the
 * PE TLS directory — a .CRT$XL callback plus a __thread template.
 * Returns 31 on success so the QEMU log shows a distinct exit.
 */
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <winnt.h>

static int cb_ran;
static void NTAPI tls_cb(void *h, unsigned long reason, void *r) {
    (void)h; (void)r;
    if (reason == DLL_PROCESS_ATTACH)
        cb_ran = 42;
}
/* MinGW-w64 forms the TLS callback array from .CRT$XL* sections. */
static PIMAGE_TLS_CALLBACK cb_slot
    __attribute__((section(".CRT$XLD"), used)) = tls_cb;

static __thread int tvar = 7;

/* tiny wide-substring scan — no wcsstr dependency */
static int whas(const WCHAR *s, const char *pat) {
    if (!s) return 0;
    for (; *s; s++) {
        const WCHAR *q = s;
        const char *p = pat;
        while (*p && *q == (WCHAR)*p) { q++; p++; }
        if (!*p) return 1;
    }
    return 0;
}

int main(void) {
    int bad = 0;

    if (!whas(GetCommandLineW(), "winmisc")) bad |= 0x1;
    if (GetCurrentProcessId() == 0 || GetCurrentThreadId() == 0)
        bad |= 0x2;

    DWORD a = TlsAlloc(), b = TlsAlloc();
    if (a == TLS_OUT_OF_INDEXES || b == TLS_OUT_OF_INDEXES || a == b)
        bad |= 0x4;
    if (!TlsSetValue(a, (LPVOID)0x1234) || TlsGetValue(a) != (LPVOID)0x1234)
        bad |= 0x8;
    if (!TlsSetValue(b, (LPVOID)0x5678) || TlsGetValue(a) != (LPVOID)0x1234)
        bad |= 0x10;
    if (!TlsFree(a) || !TlsFree(b)) bad |= 0x20;

    DWORD slots[64]; int n = 0, hi = -1;
    for (int i = 0; i < 40; i++) {
        DWORD s = TlsAlloc();
        if (s != TLS_OUT_OF_INDEXES) slots[n++] = s;
    }
    for (int i = 0; i < n; i++)
        if ((int)slots[i] > hi) hi = slots[i];
    if (hi < 30) bad |= 0x40; /* must reach past the old 8-slot cap */
    for (int i = 0; i < n; i++) TlsFree(slots[i]);

    char *env = GetEnvironmentStringsA();
    if (!env || !strstr(env, "RUSTUX=1")) bad |= 0x80;
    FreeEnvironmentStringsA(env);

    STARTUPINFOA si;
    GetStartupInfoA(&si);
    if (si.cb != sizeof(si)) bad |= 0x100;

    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(&mbi, &mbi, sizeof(mbi)) != sizeof(mbi))
        bad |= 0x200;
    else if (mbi.State != MEM_COMMIT ||
             !(mbi.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE)))
        bad |= 0x400;

    char *pg = VirtualAlloc(0, 0x2000, MEM_COMMIT | MEM_RESERVE,
                            PAGE_READWRITE);
    if (!pg) {
        bad |= 0x800;
    } else {
        DWORD old = 0;
        pg[0] = 5;
        if (!VirtualProtect(pg, 0x1000, PAGE_READONLY, &old) ||
            old != PAGE_READWRITE)
            bad |= 0x1000;
        memset(&mbi, 0, sizeof(mbi));
        if (VirtualQuery(pg, &mbi, sizeof(mbi)) == sizeof(mbi) &&
            (mbi.Protect & 0xff) != PAGE_READONLY)
            bad |= 0x2000;
        if (!VirtualProtect(pg, 0x1000, PAGE_READWRITE, &old))
            bad |= 0x4000;
        pg[1] = 6;
        VirtualFree(pg, 0, MEM_RELEASE);
    }

    if (cb_ran != 42) bad |= 0x8000;  /* TLS callback ran */
    if (tvar != 7) bad |= 0x10000;    /* __thread template value */
    tvar = 9;
    if (tvar != 9) bad |= 0x20000;    /* writable TLS slot */

    if (bad) {
        printf("winmisc: FAIL %x\n", bad);
        return bad; /* exit code carries the failure bitmask */
    }
    puts("winmisc: cmdlineW/pids/TLS64/env/startup/VQuery/VProtect/TLSdir all ok");
    return 31;
}
