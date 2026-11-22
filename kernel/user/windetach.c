#include <windows.h>
#include <stdio.h>

/* FreeLibrary + DllMain(DLL_PROCESS_DETACH): the final release runs
 * the module's DllMain importer-first in userland, then unmaps. A
 * shared dep stays loaded (and undetached) while another module's
 * load still references it. The *_reg probes write through a pointer
 * the DLL stored at attach time — into this exe's stack — so detach
 * is observable after the module's own image is gone. */
typedef void (*reg_t)(int *);

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
    reg_t breg = (reg_t)GetProcAddress(bw, "base_reg");
    reg_t creg = (reg_t)GetProcAddress(cw, "chain_reg");
    if (!bs || !cs || !breg || !creg)
        return 3;
    volatile int bprobe = 0, cprobe = 0;
    breg((int *)&bprobe);
    creg((int *)&cprobe);
    if (*bs != 7 || *cs != 20)
        return 4;
    if (!FreeLibrary(cw))
        return 5;
    if (cprobe != 0x43)                 /* wchain detached */
        return 6;
    if (bprobe != 0)                    /* wbase still referenced */
        return 7;
    if (GetModuleHandleA("wchain.dll")) /* unmapped + slot freed */
        return 8;
    if (!GetModuleHandleA("wbase.dll"))
        return 9;
    if (*bs != 7)                       /* no premature detach */
        return 10;
    if (!FreeLibrary(bw))
        return 11;
    if (bprobe != 0x42)
        return 12;
    if (GetModuleHandleA("wbase.dll"))
        return 13;
    /* A non-final release must not detach: two refs, free once.
     * The reload is a fresh map — re-fetch the registrar and
     * re-register the probe (the old instance's pointer died with
     * its image, and the new base may differ). */
    bw = LoadLibraryA("wbase.dll");
    if (!bw || LoadLibraryA("wbase.dll") != bw)
        return 14;
    breg = (reg_t)GetProcAddress(bw, "base_reg");
    if (!breg)
        return 15;
    bprobe = 0;
    breg((int *)&bprobe);
    if (!FreeLibrary(bw))
        return 16;
    if (bprobe != 0)
        return 17;
    if (!GetModuleHandleA("wbase.dll"))
        return 18;
    if (!FreeLibrary(bw))
        return 19;
    if (bprobe != 0x42)
        return 20;
    puts("windetach: DllMain(DETACH) order/refs/probes all ok");
    return 41;
}
