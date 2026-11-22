#include <windows.h>
#include <stdio.h>

/* Run-122 fixture: ExitProcess must run every surviving module's
 * DllMain(DLL_PROCESS_DETACH) in reverse-load order — the detach
 * markers print during the exit drain, after main's own output.
 * wchain is freed explicitly first: its detach runs inside
 * FreeLibrary and must NOT repeat at exit; wbase survives on its own
 * ref, so its detach is owed by the exit path itself. */
int main(void)
{
    HMODULE cw = LoadLibraryA("wchain.dll");
    if (!cw)
        return 1;
    HMODULE bw = LoadLibraryA("wbase.dll");
    if (!bw)
        return 2;
    int *bs = (int *)GetProcAddress(bw, "base_state");
    int *cs = (int *)GetProcAddress(cw, "chain_state");
    if (!bs || !cs || *bs != 7 || *cs != 20)
        return 3;
    if (!FreeLibrary(cw)) /* wchain detaches now; wbase stays alive */
        return 4;
    if (!GetModuleHandleA("wbase.dll"))
        return 5;
    puts("windexit: free done, exiting - wbase detach owed at ExitProcess");
    return 42;
}
