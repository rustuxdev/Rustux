/* winmap.c — NT section/view proof: a CRT-linked MinGW binary
 * driving CreateFileMappingA/MapViewOfFile/UnmapViewOfFile/
 * FlushViewOfFile through kernel32 thunks into NtCreateSection/
 * NtMapViewOfSection/NtUnmapViewOfSection/NtFlushVirtualMemory.
 * Covers file-backed RW write-back, FILE_MAP_COPY discard,
 * anonymous sections, read-only initrd views, offset views and
 * the denied paths. Exit 39 on success; 1..20 name the stage.
 */
#include <windows.h>
#include <stdio.h>
#include <string.h>

int main(void) {
    char buf[64];
    DWORD n = 0;
    LARGE_INTEGER pos;

    /* -- stage 1: make a writable file with a known pattern -- */
    HANDLE f = CreateFileA("winmap.bin", GENERIC_READ | GENERIC_WRITE,
                           0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE) return 1;
    const char *pat = "WMAP-SEED-0123456789abcdefwmap-tail----";
    if (!WriteFile(f, pat, 40, &n, NULL) || n != 40) return 2;

    /* -- stage 2: RW map -> view write -> unmap -> read back -- */
    HANDLE m = CreateFileMappingA(f, NULL, PAGE_READWRITE, 0, 0, NULL);
    if (!m) return 3;
    char *v = MapViewOfFile(m, FILE_MAP_ALL_ACCESS, 0, 0, 0);
    if (!v) return 4;
    if (memcmp(v, pat, 40) != 0) return 5;   /* file bytes seeded */
    memcpy(v, "RWVIEW", 6);                  /* write via the view */
    memcpy(v + 16, "TAIL16", 6);
    if (!UnmapViewOfFile(v)) return 6;       /* flushes on unmap  */
    pos.QuadPart = 0;
    if (!SetFilePointerEx(f, pos, NULL, FILE_BEGIN)) return 7;
    memset(buf, 0, sizeof buf);
    if (!ReadFile(f, buf, 40, &n, NULL) || n != 40) return 8;
    if (memcmp(buf, "RWVIEW", 6) != 0) return 9;   /* persisted */
    if (memcmp(buf + 16, "TAIL16", 6) != 0) return 10;

    /* -- stage 3: FILE_MAP_COPY writes must NOT reach the file -- */
    v = MapViewOfFile(m, FILE_MAP_COPY, 0, 0, 0);
    if (!v) return 11;
    memcpy(v, "COWXXX", 6);                  /* private copy only  */
    if (!UnmapViewOfFile(v)) return 12;
    pos.QuadPart = 0;
    if (!SetFilePointerEx(f, pos, NULL, FILE_BEGIN)) return 13;
    memset(buf, 0, sizeof buf);
    if (!ReadFile(f, buf, 8, &n, NULL) || n != 8) return 14;
    if (memcmp(buf, "RWVIEW", 6) != 0) return 15;  /* unchanged   */

    /* -- stage 4: FlushViewOfFile without unmap -- */
    v = MapViewOfFile(m, FILE_MAP_ALL_ACCESS, 0, 0, 0);
    if (!v) return 16;
    memcpy(v + 24, "FLUSH!", 6);
    if (!FlushViewOfFile(v, 0)) return 17;   /* 0 size = whole view */
    pos.QuadPart = 24;
    if (!SetFilePointerEx(f, pos, NULL, FILE_BEGIN)) return 18;
    memset(buf, 0, sizeof buf);
    if (!ReadFile(f, buf, 8, &n, NULL) || n != 8) return 19;
    if (memcmp(buf, "FLUSH!", 6) != 0) return 20;
    if (!UnmapViewOfFile(v)) return 21;

    /* -- stage 5: offset view sees file[8..] -- */
    v = MapViewOfFile(m, FILE_MAP_ALL_ACCESS, 0, 8, 16);
    if (!v) return 22;
    pos.QuadPart = 8;
    if (!SetFilePointerEx(f, pos, NULL, FILE_BEGIN)) return 23;
    memset(buf, 0, sizeof buf);
    if (!ReadFile(f, buf, 16, &n, NULL) || n != 16) return 24;
    if (memcmp(v, buf, 16) != 0) return 25;
    if (!UnmapViewOfFile(v)) return 26;

    /* -- stage 6: anonymous (pagefile) section -- */
    HANDLE a = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL,
                                  PAGE_READWRITE, 0, 4096, NULL);
    if (!a) return 27;
    v = MapViewOfFile(a, FILE_MAP_ALL_ACCESS, 0, 0, 0);
    if (!v) return 28;
    strcpy(v, "anon-view-ok");               /* zero-filled + RW   */
    if (strcmp(v, "anon-view-ok") != 0) return 29;
    if (!UnmapViewOfFile(v)) return 30;
    if (!CloseHandle(a)) return 31;
    if (!CloseHandle(m)) return 32;

    /* -- stage 7: denied paths on the read-only seed file -- */
    HANDLE r = CreateFileA("winseed.txt", GENERIC_READ, FILE_SHARE_READ,
                           NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (r == INVALID_HANDLE_VALUE) return 33;
    if (CreateFileMappingA(r, NULL, PAGE_READWRITE, 0, 0, NULL))
        return 34;                           /* RW on RO: deny */
    HANDLE rm = CreateFileMappingA(r, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!rm) return 35;
    char *rv = MapViewOfFile(rm, FILE_MAP_READ, 0, 0, 0);
    if (!rv) return 36;
    if (memcmp(rv, "winseed", 7) != 0) return 37;  /* seed bytes */
    if (!UnmapViewOfFile(rv)) return 38;
    if (!CloseHandle(rm)) return 39;
    if (!CloseHandle(r)) return 40;
    if (!CloseHandle(f)) return 41;
    if (!DeleteFileA("winmap.bin")) return 42;

    puts("winmap: file RW/COW/offset views + anon + RO + flush all ok");
    return 39;
}
