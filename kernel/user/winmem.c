// winmem.c — MEM_RESERVE/MEM_COMMIT fidelity check for the NT VM
// layer. A 1 GiB reservation proves laziness (eager commit would
// need ~262k frames, far past the pool), then commit/query/
// decommit/release transitions are checked through VirtualQuery.
// Exit 29 on full pass; a bitmask of failed checks otherwise.
#include <windows.h>
#include <stdio.h>
#include <string.h>

int main(void)
{
    int bad = 0;
    MEMORY_BASIC_INFORMATION mi;
    const SIZE_T RSZ = (SIZE_T)1 << 30;

    // Reserve 1 GiB — succeeds only if no frames are touched.
    char *base = (char *)VirtualAlloc(0, RSZ, MEM_RESERVE, PAGE_READWRITE);
    if (base == 0)
        bad |= 0x1;
    if (base) {
        memset(&mi, 0, sizeof mi);
        if (VirtualQuery(base, &mi, sizeof mi) == 0 ||
            mi.State != MEM_RESERVE)
            bad |= 0x2;
    }
    // Commit 3 pages inside the reservation.
    if (base &&
        VirtualAlloc(base + 0x4000, 0x3000, MEM_COMMIT, PAGE_READWRITE) == 0)
        bad |= 0x4;
    if (!(bad & 0x4) && base) {
        base[0x4000] = 42;
        base[0x6fff] = 43;
        if (base[0x4000] != 42 || base[0x6fff] != 43)
            bad |= 0x8;
    }
    if (base && !(bad & 0x4)) {
        memset(&mi, 0, sizeof mi);
        if (VirtualQuery(base + 0x5000, &mi, sizeof mi) == 0 ||
            mi.State != MEM_COMMIT || mi.Protect != PAGE_READWRITE)
            bad |= 0x10;
    }
    // VirtualProtect over still-reserved VA must fail honestly.
    if (base) {
        DWORD op = 0;
        if (VirtualProtect(base + 0x8000, 0x1000, PAGE_READONLY, &op))
            bad |= 0x20;
    }
    // Decommit one page of the committed window -> back to RESERVE.
    if (base && !(bad & 0x4)) {
        if (!VirtualFree(base + 0x5000, 0x1000, MEM_DECOMMIT))
            bad |= 0x40;
        memset(&mi, 0, sizeof mi);
        if (VirtualQuery(base + 0x5000, &mi, sizeof mi) == 0 ||
            mi.State != MEM_RESERVE)
            bad |= 0x40;
    }
    // Release the whole reservation -> FREE.
    if (base) {
        if (!VirtualFree(base, RSZ, MEM_RELEASE))
            bad |= 0x80;
        memset(&mi, 0, sizeof mi);
        if (VirtualQuery(base + 0x10000, &mi, sizeof mi) == 0 ||
            mi.State != MEM_FREE)
            bad |= 0x80;
    }
    // Combined RESERVE|COMMIT and commit-only bump still work.
    char *p2 = (char *)VirtualAlloc(0, 0x2000,
                                    MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (p2 == 0) {
        bad |= 0x100;
    } else {
        p2[0x1fff] = 7;
        memset(&mi, 0, sizeof mi);
        if (VirtualQuery(p2, &mi, sizeof mi) == 0 || mi.State != MEM_COMMIT)
            bad |= 0x100;
        // size-0 release names the whole region.
        if (!VirtualFree(p2, 0, MEM_RELEASE))
            bad |= 0x100;
    }
    char *p3 = (char *)VirtualAlloc(0, 0x1000, MEM_COMMIT, PAGE_READWRITE);
    if (p3 == 0) {
        bad |= 0x200;
    } else {
        p3[0] = 9;
        if (p3[0] != 9)
            bad |= 0x200;
        VirtualFree(p3, 0, MEM_RELEASE);
    }
    if (bad) {
        printf("winmem: FAIL %x\n", bad);
        return bad;
    }
    puts("winmem: RESERVE/COMMIT/decommit/Query/Protect/RELEASE all ok");
    return 29;
}
