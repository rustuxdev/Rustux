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

BOOL WINAPI DllMain(HMODULE h, DWORD r, LPVOID v)
{
    (void)h; (void)v;
    if (r == DLL_PROCESS_ATTACH) {
        chain_state = 20;
    } else if (r == DLL_PROCESS_DETACH) {
        /* Re-entrant FreeLibrary on an in-flight module must be a
         * no-op — it must not re-arm or re-run this pipeline. */
        FreeLibrary(GetModuleHandleA("wchain.dll"));
        /* += so a second DETACH call is observable (0x86 != 0x43). */
        puts("wchain: detach");
        if (detach_probe) *detach_probe += 0x43;
    }
    return TRUE;
}
