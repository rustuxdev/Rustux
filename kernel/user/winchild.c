/* winchild.c — CreateProcess child image: reports its command line
 * and exits 42 when "arg42" is in it, 7 otherwise. The standalone
 * boot-spawn run uses the default "<name>.exe" CommandLine -> 7;
 * a parent's CreateProcess(..., "winchild.exe arg42", ...) -> 42.
 */
#include <windows.h>
#include <stdio.h>
#include <string.h>

int main(void) {
    char mbuf[256];
    const char *cl = GetCommandLineA();
    snprintf(mbuf, sizeof mbuf, "winchild: cmdline '%s'", cl);
    puts(mbuf);
    return strstr(cl, "arg42") != NULL ? 42 : 7;
}
