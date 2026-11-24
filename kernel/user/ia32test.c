// 32-bit compat-mode proof for the ia32 rung: built ELFCLASS32 /
// EM_386, runs in IA-32e compatibility mode — its image maps at the
// canonical i386 link base 0x08048000 (the physmap made the whole
// below-4GiB compat window safe) and syscalls arrive on int 0x80's
// ia32 numbering (write=4, getpid=20, brk=45, uname=122, mmap2=192,
// munmap=91, gettid=224, getrandom=355, exit=1).
// check() convention like the 64-bit suite: exit status = failures.

static int fails;
static void check(int c) { if (!c) fails++; }

static long sc0(long n) {
    long r;
    __asm__ volatile("int $0x80" : "=a"(r) : "a"(n));
    return r;
}
static long sc1(long n, long a1) {
    long r;
    __asm__ volatile("int $0x80" : "=a"(r) : "a"(n), "b"(a1));
    return r;
}
static long sc3(long n, long a1, long a2, long a3) {
    long r;
    __asm__ volatile("int $0x80" : "=a"(r) : "a"(n), "b"(a1), "c"(a2), "d"(a3));
    return r;
}
static long sc6(long n, long a1, long a2, long a3, long a4, long a5, long a6) {
    long r;
    __asm__ volatile(
        "push %%ebp\n\t"
        "movl %7, %%ebp\n\t"
        "int $0x80\n\t"
        "pop %%ebp"
        : "=a"(r)
        : "a"(n), "b"(a1), "c"(a2), "d"(a3), "S"(a4), "D"(a5), "r"(a6));
    return r;
}

static const char msg[] = "ia32: compat task alive\n";

// The ABI stack must be read BEFORE any C prologue runs — a naked
// _start stashes argc/argv, then main32 does the checking in C.
long abi_argc;
long abi_argv0;
__attribute__((naked)) void _start(void) {
    __asm__ volatile(
        "movl (%esp), %eax\n\t"       // argc
        "movl %eax, abi_argc\n\t"
        "movl 4(%esp), %eax\n\t"      // argv[0] pointer
        "movl %eax, abi_argv0\n\t"
        "call main32\n\t");
}

void main32(void) {
    check(abi_argc == 1);
    check(abi_argv0 != 0);
    check(*(volatile char *)abi_argv0 == 'i'); // "ia32test"

    // write(1, msg, sizeof-1) — ia32 nr 4.
    check(sc3(4, 1, (long)msg, sizeof(msg) - 1) == (long)sizeof(msg) - 1);

    // getpid / gettid — ia32 nr 20 / 224; same task reports both.
    long pid = sc0(20);
    check(pid > 0);
    check(sc0(224) == pid);

    // brk — ia32 nr 45: query, grow 16 KiB, touch the new page.
    long b0 = sc1(45, 0);
    check(b0 > 0);
    check(sc1(45, b0 + 0x4000) == b0 + 0x4000);
    *(volatile char *)b0 = 42;
    check(*(volatile char *)b0 == 42);
    *(volatile char *)(b0 + 0x3fff) = 7;
    check(*(volatile char *)(b0 + 0x3fff) == 7);

    // uname — ia32 nr 122; machine field (offset 4*65) is "i686".
    char un[390];
    check(sc1(122, (long)un) == 0);
    check(un[260] == 'i' && un[261] == '6' && un[262] == '8' && un[263] == '6');

    // mmap2 — ia32 nr 192: anon rw 8 KiB (offset in 4K units).
    long m = sc6(192, 0, 0x2000, 3, 0x22, -1, 0);
    check(m > 0 && (m & 0xfff) == 0);
    *(volatile char *)m = 5;
    check(*(volatile char *)(m + 0x1fff) == 0);
    check(*(volatile char *)m == 5);
    // munmap — ia32 nr 91; the freed page must fault afterwards is
    // out of scope (no ia32 signal ABI yet) — just check the call.
    check(sc3(91, m, 0x2000, 0) == 0);

    // getrandom — ia32 nr 355: 16 bytes into a validated range.
    char rnd[16];
    check(sc3(355, (long)rnd, 16, 0) == 16);

    // Unknown ia32 number -> -ENOSYS (38), not a crash.
    check(sc0(999) == -38);

    // exit — ia32 nr 1.
    sc1(1, fails);
    for (;;) {}
}
