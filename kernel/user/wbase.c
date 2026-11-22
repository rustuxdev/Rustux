#include <windows.h>
#include <stdio.h>

__declspec(dllexport) int base_state = 0;
__declspec(dllexport) int base_add(int a, int b) { return a + b + 1000; }

static int *detach_probe;
__declspec(dllexport) void base_reg(int *p) { detach_probe = p; }

BOOL WINAPI DllMain(HMODULE h, DWORD r, LPVOID v)
{
    (void)h; (void)v;
    if (r == DLL_PROCESS_ATTACH) {
        base_state = 7;
    } else if (r == DLL_PROCESS_DETACH) {
        /* += so a second DETACH call is observable (0x84 != 0x42). */
        puts("wbase: detach");
        if (detach_probe) *detach_probe += 0x42;
    }
    return TRUE;
}
