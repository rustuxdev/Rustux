#include <windows.h>

extern int base_add(int, int);
__declspec(dllexport) int chain_state = 0;
__declspec(dllexport) int chain_add(int a, int b)
{
    return base_add(a, b) + chain_state;
}

BOOL WINAPI DllMain(HMODULE h, DWORD r, LPVOID v)
{
    (void)h; (void)v;
    if (r == DLL_PROCESS_ATTACH) chain_state = 20;
    return TRUE;
}
