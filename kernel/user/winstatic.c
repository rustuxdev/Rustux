#include <windows.h>
#include <stdio.h>
#include <string.h>

/* Statically import the wbase -> wchain chain: binding wchain pulls
 * wbase in as a dependency at spawn time, and the exe's own wbase
 * descriptor must dedup onto that live module either way. Both
 * DllMains have to run before this entry — the startup drain, not a
 * LoadLibrary call, is what reaches them here. */
__declspec(dllimport) int base_add(int, int);
__declspec(dllimport) int base_state;
__declspec(dllimport) int chain_add(int, int);
__declspec(dllimport) int chain_state;

int main(void)
{
    if (base_state != 7)
        return 1;
    if (chain_state != 20)
        return 2;
    if (base_add(1, 2) != 1003)
        return 3;
    if (chain_add(3, 4) != 1027)
        return 4;

    HMODULE cw = GetModuleHandleA("wchain.dll");
    if (!cw || cw != GetModuleHandleW(L"wchain.dll"))
        return 5;
    HMODULE bw = GetModuleHandleA("wbase.dll");
    if (!bw || bw == cw)
        return 6;
    if (!GetModuleHandleA(NULL))
        return 7;
    if (GetModuleHandleA("notthere.dll"))
        return 8;
    /* Path-ish name reduces to basename like LoadLibrary does. */
    if (GetModuleHandleA("C:\\some\\dir\\wbase.dll") != bw)
        return 9;

    puts("winstatic: static-dep chain + GetModuleHandle all ok");
    return 36;
}
