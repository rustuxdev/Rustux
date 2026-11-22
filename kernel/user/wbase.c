#include <windows.h>

__declspec(dllexport) int base_state = 0;
__declspec(dllexport) int base_add(int a, int b) { return a + b + 1000; }

BOOL WINAPI DllMain(HMODULE h, DWORD r, LPVOID v)
{
    (void)h; (void)v;
    if (r == DLL_PROCESS_ATTACH) base_state = 7;
    return TRUE;
}
