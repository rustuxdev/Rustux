// windir.c — run-111: directory enumeration via the real Win32
// find API. FindFirstFileA("*") lists the flat VFS; "*.txt"
// exercises the wildcard store/filter; FindClose drops the dir
// handle. Exit code = number of *.txt files seen (clamped).
#include <windows.h>
#include <stdio.h>
#include <string.h>

int main(void)
{
    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA("*", &fd);
    if (h == INVALID_HANDLE_VALUE) {
        puts("windir: FindFirstFileA failed");
        return 1;
    }
    int total = 0, saw_seed = 0, dirs = 0;
    char line[260];
    do {
        line[0] = (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ? 'D' : 'F';
        line[1] = ' ';
        int i = 0;
        while (fd.cFileName[i] && i < 250) { line[i + 2] = fd.cFileName[i]; i++; }
        line[i + 2] = 0;
        puts(line);
        if (line[0] == 'D') { dirs++; continue; }
        total++;
        if (strcmp(fd.cFileName, "winseed.txt") == 0)
            saw_seed = 1;
    } while (FindNextFileA(h, &fd));
    if (!FindClose(h))
        return 2;
    if (!saw_seed || total < 5)
        return 3;

    // Wildcard: "*.txt" must match winseed.txt and no .exe.
    h = FindFirstFileA("*.txt", &fd);
    if (h == INVALID_HANDLE_VALUE)
        return 4;
    int txts = 0, bad = 0;
    do {
        line[0] = (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ? 'D' : 'F';
        line[1] = ' ';
        line[2] = '2'; line[3] = ' ';
        int i = 0;
        while (fd.cFileName[i] && i < 250) { line[i + 4] = fd.cFileName[i]; i++; }
        line[i + 4] = 0;
        puts(line);
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            continue;
        txts++;
        int l = (int)strlen(fd.cFileName);
        if (l < 4 || strcmp(fd.cFileName + l - 4, ".txt") != 0)
            bad++;
    } while (FindNextFileA(h, &fd));
    FindClose(h);
    if (bad || txts < 1)
        return 5;

    puts("windir: FindFirstFile/FindNextFile/FindClose all ok");
    return 11;
}
