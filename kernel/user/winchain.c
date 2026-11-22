/* Run-119 fixture: a DLL statically importing another DLL — the
 * loader must map the dependency recursively, bind its exports,
 * dedup a later explicit load, and cascade refs on FreeLibrary. */
#include <windows.h>
#include <stdio.h>

typedef int (*add_fn)(int, int);

int main(void)
{
    HMODULE c = LoadLibraryA("wchain.dll");
    if (!c) return 1;
    FARPROC f = GetProcAddress(c, "chain_add");
    if (!f) return 2;
    if (((add_fn)f)(5, 6) != 1031) return 3;

    int *cs = (int *)GetProcAddress(c, "chain_state");
    if (!cs || *cs != 20) return 4;

    HMODULE b = LoadLibraryA("wbase.dll");
    if (!b) return 5;
    FARPROC bf = GetProcAddress(b, "base_add");
    if (!bf || ((add_fn)bf)(1, 1) != 1002) return 6;
    int *bs = (int *)GetProcAddress(b, "base_state");
    if (!bs || *bs != 7) return 7;

    if (!FreeLibrary(b)) return 8;
    if (!FreeLibrary(c)) return 9;

    HMODULE c2 = LoadLibraryA("wchain.dll");
    if (!c2) return 10;
    FARPROC f2 = GetProcAddress(c2, "chain_add");
    if (!f2 || ((add_fn)f2)(1, 2) != 1023) return 11;
    if (!FreeLibrary(c2)) return 12;

    puts("winchain: dependent-DLL map/bind/dedup/cascade all ok");
    return 34;
}
