/* winfs2.c — NT filesystem round-2 proof: cwd get/set, full-path
 * canonicalisation, mkdir/rmdir, file attributes, GetFileType,
 * SetEndOfFile/FlushFileBuffers, GlobalMemoryStatusEx,
 * GetComputerName — all through the kernel32 thunk layer to
 * RUX_PATH (0x100). Exit 46 on success; 1..20 name the stage.
 */
#include <windows.h>
#include <stdio.h>

static int wseq(const WCHAR *a, const WCHAR *b) {
    while (*a && *a == *b) { a++; b++; }
    return *a == *b;
}

int main(void) {
    char cd[260], fp[260], cn[64], msg[160];
    WCHAR wcd[260];
    DWORD n, attrs, cap;
    HANDLE h;
    MEMORYSTATUSEX ms;
    LARGE_INTEGER sz;

    /* cwd starts at the DOS root. */
    n = GetCurrentDirectoryA(sizeof cd, cd);
    if (n != 3 || strcmp(cd, "C:\\") != 0)
        return 1;
    n = GetCurrentDirectoryW(260, wcd);
    if (n != 3 || !wseq(wcd, L"C:\\"))
        return 2;

    /* mkdir round-trip + collision status. */
    if (!CreateDirectoryA("wtmp", NULL))
        return 3;
    if (CreateDirectoryA("wtmp", NULL))
        return 4; /* EEXIST -> FALSE */
    if (!SetCurrentDirectoryA("wtmp"))
        return 5;
    n = GetCurrentDirectoryA(sizeof cd, cd);
    if (n != 7 || strcmp(cd, "C:\\wtmp") != 0)
        return 6;

    /* full-path canonicalisation vs cwd and "..". */
    n = GetFullPathNameA(".", sizeof fp, fp, NULL);
    if (n == 0 || strcmp(fp, "C:\\wtmp") != 0)
        return 7;
    n = GetFullPathNameA("..\\x.txt", sizeof fp, fp, NULL);
    if (n == 0 || strcmp(fp, "C:\\x.txt") != 0)
        return 8;

    /* create a file inside wtmp; attr + type + truncate ops. */
    h = CreateFileA("f.bin", GENERIC_READ | GENERIC_WRITE, 0, NULL,
                    CREATE_ALWAYS, 0, NULL);
    if (h == INVALID_HANDLE_VALUE)
        return 9;
    if (!WriteFile(h, "abcd", 4, &n, NULL) || n != 4)
        return 10;
    if (GetFileType(h) != FILE_TYPE_DISK)
        return 11;
    attrs = GetFileAttributesA("f.bin");
    if (attrs == INVALID_FILE_ATTRIBUTES || !(attrs & FILE_ATTRIBUTE_ARCHIVE))
        return 12;
    attrs = GetFileAttributesA("..");
    if (!(attrs & FILE_ATTRIBUTE_DIRECTORY))
        return 13;
    if (GetFileAttributesA("no-such.bin") != INVALID_FILE_ATTRIBUTES)
        return 14;
    /* SetEndOfFile truncates at the shared position (4 -> 2). */
    { LARGE_INTEGER off; off.QuadPart = 2;
        if (!SetFilePointerEx(h, off, NULL, FILE_BEGIN))
            return 15;
    }
    if (!SetEndOfFile(h))
        return 16;
    if (!GetFileSizeEx(h, &sz) || sz.QuadPart != 2)
        return 17;
    if (!FlushFileBuffers(h))
        return 18;
    CloseHandle(h);
    if (GetFileType(GetStdHandle(STD_OUTPUT_HANDLE)) != FILE_TYPE_CHAR)
        return 19;

    /* system/status household APIs. */
    memset(&ms, 0, sizeof ms);
    ms.dwLength = sizeof ms;
    if (!GlobalMemoryStatusEx(&ms)
        || ms.ullTotalPhys == 0 || ms.ullAvailPhys > ms.ullTotalPhys
        || ms.dwMemoryLoad > 100)
        return 20;
    cap = sizeof cn;
    if (!GetComputerNameA(cn, &cap) || cap != 6
        || strcmp(cn, "RUSTUX") != 0)
        return 21;

    /* non-empty rmdir fails; empty rmdir succeeds; wide chdir home. */
    if (RemoveDirectoryA("."))
        return 22;
    if (!SetCurrentDirectoryW(L"C:\\"))
        return 23;
    if (!DeleteFileA("wtmp\\f.bin"))
        return 24;
    if (!RemoveDirectoryA("wtmp"))
        return 25;
    if (GetFileAttributesA("wtmp") != INVALID_FILE_ATTRIBUTES)
        return 26;

    sprintf(msg,
        "winfs2: cwd mkdir attrs type eof gms %llu/%lluMB name %s ok",
        (unsigned long long)(ms.ullAvailPhys >> 20),
        (unsigned long long)(ms.ullTotalPhys >> 20), cn);
    puts(msg);
    return 46;
}
