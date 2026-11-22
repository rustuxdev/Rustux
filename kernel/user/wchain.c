#include <windows.h>
#include <stdio.h>

extern int base_add(int, int);
__declspec(dllexport) int chain_state = 0;
__declspec(dllexport) int chain_add(int a, int b)
{
    return base_add(a, b) + chain_state;
}

static int *detach_probe;
__declspec(dllexport) void chain_reg(int *p) { detach_probe = p; }

__declspec(dllexport) int thr_att = 0;
__declspec(dllexport) int thr_det = 0;
__declspec(dllexport) int tls_att = 0;
__declspec(dllexport) int tls_det = 0;
__declspec(dllexport) int tls_patt = 0;
__declspec(dllexport) int tls_pdet = 0;
static char **seq_p;
__declspec(dllexport) void seq_reg(char **p) { seq_p = p; }

static void NTAPI wchain_tls(PVOID h, DWORD r, PVOID v);
/* .CRT$XL* lands in the image's PIMAGE_TLS_CALLBACK array. */
static PIMAGE_TLS_CALLBACK wchain_tls_arr[1]
    __attribute__((section(".CRT$XLC"), used)) = { wchain_tls };

static void NTAPI wchain_tls(PVOID h, DWORD r, LPVOID v)
{
    (void)h; (void)v;
    /* Process reasons only count - CRT stdio isn't up when a
     * reason-1 callback runs (it precedes DllMain). */
    if (r == DLL_PROCESS_ATTACH) {
        tls_patt += 1;
    } else if (r == DLL_PROCESS_DETACH) {
        tls_pdet += 1;
    } else if (r == DLL_THREAD_ATTACH || r == DLL_THREAD_DETACH) {
        puts(r == DLL_THREAD_ATTACH ? "wchain: tls thr-attach"
                                    : "wchain: tls thr-detach");
        if (r == DLL_THREAD_ATTACH) tls_att += 1; else tls_det += 1;
        /* 'C' runs before 'c' both ways - TLS cbs precede the
         * init routine for every reason on the real loader. */
        if (seq_p) { **seq_p = 'C'; (*seq_p)++; **seq_p = 0; }
    }
}

BOOL WINAPI DllMain(HMODULE h, DWORD r, LPVOID v)
{
    (void)h; (void)v;
    if (r == DLL_PROCESS_ATTACH) {
        chain_state = 20;
    } else if (r == DLL_PROCESS_DETACH) {
        /* Re-entrant FreeLibrary on an in-flight module must be a
         * no-op - it must not re-arm or re-run this pipeline. */
        FreeLibrary(GetModuleHandleA("wchain.dll"));
        /* += so a second DETACH call is observable (0x86 != 0x43). */
        puts("wchain: detach");
        if (detach_probe) *detach_probe += 0x43;
    } else if (r == DLL_THREAD_ATTACH || r == DLL_THREAD_DETACH) {
        puts(r == DLL_THREAD_ATTACH ? "wchain: thr-attach"
                                    : "wchain: thr-detach");
        if (r == DLL_THREAD_ATTACH) thr_att += 1; else thr_det += 1;
        if (seq_p) { **seq_p = 'c'; (*seq_p)++; **seq_p = 0; }
    }
    return TRUE;
}
