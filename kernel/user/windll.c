/* Run-118 fixture module: a real MinGW-built DLL. The loader maps
 * it via LoadLibraryA, binds its own imports, and runs DllMain —
 * dll_state proves the attach call happened. */
#include <windows.h>

__declspec(dllexport) int dll_add(int a, int b) { return a + b + 1; }
__declspec(dllexport) int dll_state = 0;

BOOL WINAPI DllMain(HMODULE hinst, DWORD reason, LPVOID reserved)
{
    (void)hinst;
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH)
        dll_state = 41;
    return TRUE;
}
