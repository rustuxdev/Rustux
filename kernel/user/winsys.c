/* winsys.c — time & system-info services proof: SYSTEM_INFO fields,
 * GetTickCount monotonicity, QueryPerformance counter/frequency,
 * GetSystemTimeAsFileTime/GetSystemTime/GetLocalTime wall clock, and
 * GetVersion/GetVersionEx — all through the kernel32 thunk layer to
 * RUX_SYS_INFO (0xFF). Exit 45 on success; 1..14 name the stage.
 */
#include <windows.h>
#include <stdio.h>

int main(void) {
    SYSTEM_INFO si;
    LARGE_INTEGER f, c1, c2;
    FILETIME ft;
    SYSTEMTIME st, lt;
    OSVERSIONINFOA oi;
    ULONGLONG t1, t2;
    DWORD v;

    memset(&si, 0, sizeof si);
    GetSystemInfo(&si);
    if (si.dwPageSize != 4096)
        return 1;
    if (si.dwNumberOfProcessors != 1)
        return 2;
    if (si.wProcessorArchitecture != PROCESSOR_ARCHITECTURE_AMD64)
        return 3;
    if (!si.lpMinimumApplicationAddress
        || si.lpMaximumApplicationAddress <= si.lpMinimumApplicationAddress)
        return 4;

    /* tick-ms: monotonic and moves at least the slept interval. */
    t1 = GetTickCount64();
    if (!t1 && !GetTickCount())
        return 5;
    Sleep(30);
    t2 = GetTickCount64();
    if (t2 <= t1 || t2 - t1 < 15)
        return 6;

    /* QPC: real frequency, strictly increasing counter. */
    memset(&f, 0, sizeof f);
    if (!QueryPerformanceFrequency(&f) || f.QuadPart < 1000000)
        return 7;
    if (!QueryPerformanceCounter(&c1))
        return 8;
    Sleep(15);
    if (!QueryPerformanceCounter(&c2) || c2.QuadPart <= c1.QuadPart)
        return 9;

    /* wall clock: FILETIME must be in this century (1601-epoch,
     * 100 ns units — 2015-01-01 is 130861728000000000). */
    memset(&ft, 0, sizeof ft);
    GetSystemTimeAsFileTime(&ft);
    if (((ULARGE_INTEGER *)&ft)->QuadPart < 130861728000000000ULL)
        return 10;
    memset(&st, 0, sizeof st);
    memset(&lt, 0, sizeof lt);
    GetSystemTime(&st);
    GetLocalTime(&lt);
    if (st.wYear < 2020 || st.wMonth < 1 || st.wMonth > 12
        || st.wDay < 1 || st.wDay > 31 || st.wHour > 23
        || st.wMinute > 59 || st.wSecond > 59)
        return 11;
    if (lt.wYear != st.wYear || lt.wDay != st.wDay) /* no TZ yet */
        return 12;

    /* version: 10.0.19045 NT. */
    v = GetVersion();
    if (LOBYTE(LOWORD(v)) != 10 || HIWORD(v) != 19045)
        return 13;
    memset(&oi, 0, sizeof oi);
    oi.dwOSVersionInfoSize = sizeof oi;
    if (!GetVersionExA(&oi) || oi.dwMajorVersion != 10
        || oi.dwBuildNumber != 19045)
        return 14;

    {
        char msg[160];
        sprintf(msg,
            "winsys: sysinfo %uC pg%u tick perf %lluHz ft %u sys %04u-%02u-%02u ver %u.%u.%u ok",
            (unsigned)si.dwNumberOfProcessors, (unsigned)si.dwPageSize,
            (unsigned long long)f.QuadPart, (unsigned)ft.dwHighDateTime,
            (unsigned)st.wYear, (unsigned)st.wMonth, (unsigned)st.wDay,
            (unsigned)oi.dwMajorVersion, (unsigned)oi.dwMinorVersion,
            (unsigned)oi.dwBuildNumber);
        puts(msg);
    }
    return 45;
}
