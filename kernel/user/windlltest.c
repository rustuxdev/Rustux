/* Run-118 fixture: LoadLibraryA/GetProcAddress/FreeLibrary driving
 * the RUX_LOAD_DLL/RUX_GET_PROC/RUX_FREE_DLL services — a real DLL
 * mapped, IAT-bound, DllMain'd, deduped, and unmapped. */
#include <windows.h>
#include <stdio.h>

typedef int (*add_fn)(int, int);

int main(void)
{
    HMODULE m = LoadLibraryA("windll.dll");
    if (!m) return 1;

    FARPROC f = GetProcAddress(m, "dll_add");
    if (!f) return 2;
    if (((add_fn)f)(2, 3) != 6) return 3;

    /* dll_state == 41 proves DllMain(PROCESS_ATTACH) ran. */
    int *st = (int *)GetProcAddress(m, "dll_state");
    if (!st || *st != 41) return 4;

    if (GetProcAddress(m, "no_such_export")) return 5;

    /* Second load of the same name: same HMODULE, refs++. */
    HMODULE m2 = LoadLibraryA("windll.dll");
    if (m2 != m) return 6;
    if (!FreeLibrary(m2)) return 7;
    if (!FreeLibrary(m)) return 8;

    /* Reload after the last ref dropped — a fresh mapping. */
    HMODULE m3 = LoadLibraryA("windll.dll");
    if (!m3) return 9;
    FARPROC f3 = GetProcAddress(m3, "dll_add");
    if (!f3 || ((add_fn)f3)(4, 5) != 10) return 10;
    if (!FreeLibrary(m3)) return 11;

    if (LoadLibraryA("no_such.dll")) return 12;

    puts("windll: LoadLibrary/GetProcAddress/DllMain/dedup/FreeLibrary all ok");
    return 33;
}
