/* Real-CRT MinGW test for the NT personality's Win32 thunk layer.
 * Built with: x86_64-w64-mingw32-gcc -O2 -o crt_hello.exe crt_hello.c
 * The committed .exe is the artifact of that command — a default
 * mingw CRT link: mainCRTStartup runs __getmainargs/_initterm/ctors
 * before main, so it exercises 10 kernel32 + 24 msvcrt imports,
 * all resolved by kernel-embedded translation thunks.
 */
#include <stdio.h>
int main(void) {
    puts("crt_hello: real CRT .exe — mingw startup ran");
    return 7;
}
