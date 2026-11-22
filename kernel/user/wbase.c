#include <windows.h>
#include <stdio.h>

__declspec(dllexport) int base_state = 0;
__declspec(dllexport) int base_add(int a, int b) { return a + b + 1000; }

static int *detach_probe;
__declspec(dllexport) void base_reg(int *p) { detach_probe = p; }

__declspec(dllexport) int thr_att = 0;
__declspec(dllexport) int thr_det = 0;
static char **seq_p;
__declspec(dllexport) void seq_reg(char **p) { seq_p = p; }

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
        /* 'b' marks this module in the order probe — attach walks
         * forward ("bc") and detach reverse ("cb"). */
        puts(r == DLL_THREAD_ATTACH ? "wbase: thr-attach"
                                    : "wbase: thr-detach");
        if (r == DLL_THREAD_ATTACH) thr_att += 1; else thr_det += 1;
        if (seq_p) { **seq_p = 'b'; (*seq_p)++; **seq_p = 0; }
    }
    return TRUE;
}
