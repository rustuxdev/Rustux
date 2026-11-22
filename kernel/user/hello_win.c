/* Minimal real-compiler PE test for the NT personality.
 * Built with: x86_64-w64-mingw32-gcc -nostdlib -Os \
 *   -Wl,-e,WinMainCRTStartup,-subsystem,console,--emit-relocs \
 *   -o hello_win.exe hello_win.c -lkernel32
 * The committed .exe is the artifact of that command — kernel32
 * imports only: GetStdHandle, WriteFile, ExitProcess.
 */
typedef void* HANDLE;
typedef unsigned long DWORD;
typedef int BOOL;
typedef unsigned int UINT;

__declspec(dllimport) HANDLE GetStdHandle(DWORD);
__declspec(dllimport) BOOL WriteFile(HANDLE, const void*, DWORD, DWORD*, void*);
__declspec(dllimport) void ExitProcess(UINT);

static const char msg[] = "hello_win: real MinGW-compiled .exe via kernel32\n";

void WinMainCRTStartup(void) {
    DWORD written = 0;
    WriteFile(GetStdHandle((DWORD)-11), msg, sizeof(msg) - 1, &written, (void*)0);
    ExitProcess(written == sizeof(msg) - 1 ? 0 : 1);
}
