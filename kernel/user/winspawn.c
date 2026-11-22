/* winspawn.c — CreateProcess proof: spawn a PE child from a PE
 * parent through the kernel32 thunk -> RUX_SPAWN_PROC -> a fresh
 * NT task, then drive the process object (wait, exit code) and the
 * thread object (suspended state, resume) the handles name.
 * Exit 44 on success; 1..11 name the failed stage.
 */
#include <windows.h>
#include <stdio.h>

int main(void) {
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    DWORD code = 0;

    /* 1. normal spawn: handles + ids must all be real, the child
     *    must see its lpCommandLine (winchild exits 42 on "arg42"),
     *    and the process object must signal + report the code. */
    memset(&si, 0, sizeof si);
    memset(&pi, 0, sizeof pi);
    si.cb = sizeof si;
    if (!CreateProcessA("winchild.exe", "winchild.exe arg42",
                        NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi))
        return 1;
    if (!pi.hProcess || !pi.hThread)
        return 2;
    if (!pi.dwProcessId || !pi.dwThreadId)
        return 3;
    if (WaitForSingleObject(pi.hProcess, 5000) != WAIT_OBJECT_0)
        return 4;
    if (!GetExitCodeProcess(pi.hProcess, &code) || code != 42)
        return 5;
    if (!CloseHandle(pi.hProcess) || !CloseHandle(pi.hThread))
        return 6;

    /* 2. suspended spawn: STILL_ACTIVE until ResumeThread, then the
     *    child runs to the same exit code; a zero-time wait on the
     *    live thread object must time out, not signal. */
    memset(&pi, 0, sizeof pi);
    if (!CreateProcessA("winchild.exe", "winchild.exe arg42",
                        NULL, NULL, FALSE, CREATE_SUSPENDED,
                        NULL, NULL, &si, &pi))
        return 7;
    if (!GetExitCodeProcess(pi.hProcess, &code) || code != STILL_ACTIVE)
        return 8;
    if (WaitForSingleObject(pi.hThread, 0) != WAIT_TIMEOUT)
        return 9;
    if (ResumeThread(pi.hThread) == (DWORD)-1)
        return 10;
    if (WaitForSingleObject(pi.hProcess, 5000) != WAIT_OBJECT_0)
        return 11;
    if (!GetExitCodeProcess(pi.hProcess, &code) || code != 42)
        return 12;
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    puts("winspawn: create/wait/exitcode/suspend-resume all ok");
    return 44;
}
