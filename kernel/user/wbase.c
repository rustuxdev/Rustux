#include <windows.h>
#include <stdio.h>

__declspec(dllexport) int base_state = 0;
__declspec(dllexport) int base_add(int a, int b) { return a + b + 1000; }

static int *detach_probe;
__declspec(dllexport) void base_reg(int *p) { detach_probe = p; }

__declspec(dllexport) int thr_att = 0;
__declspec(dllexport) int thr_det = 0;
__declspec(dllexport) int tls_att = 0;
__declspec(dllexport) int tls_det = 0;
__declspec(dllexport) int tls_patt = 0;
__declspec(dllexport) int tls_pdet = 0;
static char **seq_p;
__declspec(dllexport) void seq_reg(char **p) { seq_p = p; }

static void NTAPI wbase_tls(PVOID h, DWORD r, PVOID v);
/* A pointer in a .CRT$XL* section lands in the image's
 * PIMAGE_TLS_CALLBACK array - how a module registers TLS
 * directory callbacks the loader then invokes. */
static PIMAGE_TLS_CALLBACK wbase_tls_arr[1]
    __attribute__((section(".CRT$XLC"), used)) = { wbase_tls };

static void NTAPI wbase_tls(PVOID h, DWORD r, LPVOID v)
{
    (void)h; (void)v;
    /* CRT stdio isn't up when reason 1 runs (TLS cbs precede
     * DllMain, before the CRT entry), so process reasons only
     * count; puts is safe by the time thread reasons arrive. */
    if (r == DLL_PROCESS_ATTACH) {
        tls_patt += 1;
    } else if (r == DLL_PROCESS_DETACH) {
        tls_pdet += 1;
    } else if (r == DLL_THREAD_ATTACH || r == DLL_THREAD_DETACH) {
        puts(r == DLL_THREAD_ATTACH ? "wbase: tls thr-attach"
                                    : "wbase: tls thr-detach");
        if (r == DLL_THREAD_ATTACH) tls_att += 1; else tls_det += 1;
        /* 'B' marks this module's TLS cb in the order probe -
         * the loader calls TLS cbs before DllMain both ways. */
        if (seq_p) { **seq_p = 'B'; (*seq_p)++; **seq_p = 0; }
    }
}

BOOL WINAPI DllMain(HMODULE h, DWORD r, LPVOID v)
{
    (void)h; (void)v;
    if (r == DLL_PROCESS_ATTACH) {
        base_state = 7;
    } else if (r == DLL_PROCESS_DETACH) {
        /* += so a second DETACH call is observable (0x84 != 0x42). */
        puts("wbase: detach");
        if (detach_probe) *detach_probe += 0x42;
    } else if (r == DLL_THREAD_ATTACH || r == DLL_THREAD_DETACH) {
        /* 'b' marks this module in the order probe - attach walks
         * forward ("bc") and detach reverse ("cb"). */
        puts(r == DLL_THREAD_ATTACH ? "wbase: thr-attach"
                                    : "wbase: thr-detach");
        if (r == DLL_THREAD_ATTACH) thr_att += 1; else thr_det += 1;
        if (seq_p) { **seq_p = 'b'; (*seq_p)++; **seq_p = 0; }
    }
    return TRUE;
}
