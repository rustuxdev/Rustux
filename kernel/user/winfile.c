/* winfile.c — NT file-API proof: a normal CRT-linked MinGW binary
 * driving CreateFileA/GetFileSizeEx/ReadFile/SetFilePointerEx/
 * WriteFile/CloseHandle through the kernel32 thunk layer into
 * NtCreateFile/NtReadFile/NtQueryInformationFile/
 * NtSetInformationFile/NtWriteFile/NtClose against the Rustux VFS.
 * Exit 42 on success; 1..9 name the failed stage.
 */
#include <windows.h>
#include <stdio.h>

int main(void) {
    char buf[64];
    DWORD n = 0;
    LARGE_INTEGER sz, pos, off;

    HANDLE h = CreateFileA("winseed.txt", GENERIC_READ, FILE_SHARE_READ,
                           NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return 1;
    if (!GetFileSizeEx(h, &sz) || sz.QuadPart != 19) return 2;
    if (!ReadFile(h, buf, 63, &n, NULL) || n != 19) return 3;
    buf[n] = 0;
    puts(buf);                    /* prints the seed's own bytes */

    off.QuadPart = 0;             /* FILE_BEGIN -> absolute 0 */
    if (!SetFilePointerEx(h, off, NULL, FILE_BEGIN)) return 4;
    if (!ReadFile(h, buf, 7, &n, NULL) || n != 7) return 5;
    buf[n] = 0;
    puts(buf);                    /* "winseed" again, from offset 0 */

    off.QuadPart = -4;            /* FILE_END - 4 -> pos 15 */
    if (!SetFilePointerEx(h, off, &pos, FILE_END) || pos.QuadPart != 15)
        return 6;
    if (!ReadFile(h, buf, 4, &n, NULL) || n != 4) return 7;
    buf[n] = 0;
    puts(buf);                    /* "NT!\n" tail */
    if (!CloseHandle(h)) return 8;

    HANDLE w = CreateFileA("winout.txt", GENERIC_WRITE, 0, NULL,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (w == INVALID_HANDLE_VALUE) return 8;
    const char *msg = "winfile: nt fs round trip ok\n";
    if (!WriteFile(w, msg, 29, &n, NULL) || n != 29) return 9;
    if (!CloseHandle(w)) return 9;
    if (!DeleteFileA("winout.txt")) return 10;

    puts("winfile: CreateFile/Read/Seek/Write/Delete all ok");
    return 42;
}
