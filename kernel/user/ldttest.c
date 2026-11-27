// ldttest — modify_ldt(154): real per-task LDT + lldt on switch.
// Oracles: lsl/lar/verr/`mov ds` against LDT selectors — these only
// resolve if the LDTR points at a live descriptor table.
#include <errno.h>
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static int fails;
static void check(int ok, const char *msg) {
    if (!ok) { fails++; printf("FAIL: %s\n", msg); }
}

struct udesc {
    uint32_t entry, base, limit, flags;
};
// flags: bit0 seg_32bit, bits1-2 contents, bit3 read_exec_only,
// bit4 limit_in_pages, bit5 seg_not_present, bit6 useable, bit7 lm.

static long mldt(long func, void *ptr, unsigned long bc) {
    return syscall(154, func, ptr, bc);
}

static unsigned long lsl(unsigned short sel, int *ok) {
    unsigned long lim = 0; unsigned char zf;
    __asm__ volatile("lsl %2, %0; setz %1"
                     : "=r"(lim), "=q"(zf) : "rm"(sel) : "cc");
    *ok = zf;
    return lim;
}
static int verw(unsigned short sel) {
    unsigned char zf;
    __asm__ volatile("verw %1; setz %0" : "=q"(zf) : "rm"(sel) : "cc");
    return zf;
}
static int verr(unsigned short sel) {
    unsigned char zf;
    __asm__ volatile("verr %1; setz %0" : "=q"(zf) : "rm"(sel) : "cc");
    return zf;
}
static void mov_ds(unsigned short sel) {
    __asm__ volatile("mov %0, %%ds" :: "rm"(sel));
}
static sigjmp_buf np_env;
static void np_h(int sig) { (void)sig; siglongjmp(np_env, 1); }

int main(void) {
    printf("ldttest: begin\n");

    check(mldt(2, 0, 64) == 0, "func2: empty default ldt");
    check(mldt(0, (char[64]){0}, 64) == 0, "func0: empty task ldt");

    // Write slot 0: data r/w, base 0x50000, byte-granule limit 0xABCDE.
    struct udesc d = { 0, 0x50000, 0xABCDE, (1u << 0) | (0u << 1)
                       | (0u << 3) | (0u << 4) | (0u << 5) | (1u << 6) };
    check(mldt(1, &d, 16) == 0, "func1: write slot 0");

    unsigned short sel0 = 0 * 8 | 7; // TI=1 | RPL3
    int ok;
    unsigned long lim = lsl(sel0, &ok);
    check(ok && lim == 0xABCDE, "lsl: limit round-trips through LDT");
    check(verw(sel0), "verw: writable data selector");
    mov_ds(sel0); // loads — would #GP without a live LDT
    check(1, "mov ds: LDT selector accepted");

    // Read the table back — 8 bytes, nonzero, limit field intact.
    unsigned char buf[64] = {0};
    long rn = mldt(0, buf, sizeof(buf));
    check(rn == 8, "func0: reads 8 bytes (1 slot)");
    check(buf[0] == 0xDE && buf[1] == 0xBC
          && buf[4] == 0x05 && buf[5] == 0xf3,
          "func0: descriptor bytes (limit/type/DPL/base-high)");

    // entry_number=-1 -> kernel allocates the first free slot.
    struct udesc a = { 0xFFFFFFFFu, 0x90000, 0x1111, (1u << 6) };
    check(mldt(1, &a, 16) == 0 && a.entry >= 1 && a.entry < 16,
          "func1(-1): allocated slot written back");
    unsigned long lim2 = lsl(a.entry * 8 | 7, &ok);
    check(ok && lim2 == 0x1111, "lsl: allocated slot live");

    // func 0x11 = same write path; slot 2.
    struct udesc o = { 2, 0x70000, 0x2222, (1u << 6) };
    check(mldt(0x11, &o, 16) == 0, "func 0x11 write");
    unsigned long lim3 = lsl(2 * 8 | 7, &ok);
    check(ok && lim3 == 0x2222, "lsl: 0x11 slot live");

    // Out-of-range slot + an untouched slot's selector is not valid.
    struct udesc bad = { 16, 0, 0, (1u << 6) };
    check(mldt(1, &bad, 16) == -1 && errno == EINVAL, "slot 16 -> EINVAL");
    check(!verr(5 * 8 | 7), "verr: empty slot not readable");

    // seg_not_present -> present bit clear: lsl fails.
    struct udesc np = { 6, 0x1000, 0x3333, (1u << 5) | (1u << 6) };
    check(mldt(1, &np, 16) == 0, "func1: not-present write");
    // lsl/verw don't consult the present bit on this cpu — a real
    // segment load is the oracle: mov ds on the NP slot #NP (SIGSEGV).
    // Fork-free so a full task table can't make the check un-runnable.
    struct sigaction sa = {0};
    sa.sa_handler = np_h;
    sigaction(SIGSEGV, &sa, 0);
    int np_faulted;
    if (sigsetjmp(np_env, 1) == 0) {
        mov_ds(6 * 8 | 7);
        np_faulted = 0; // load succeeded — no fault
    } else {
        np_faulted = 1; // siglongjmp from the SIGSEGV handler
    }
    sa.sa_handler = SIG_DFL;
    sigaction(SIGSEGV, &sa, 0);
    check(np_faulted, "mov ds: not-present slot -> #NP");

    // Fork inherits a copy of the LDT.
    pid_t p = fork();
    if (p == 0) {
        unsigned char cb[64] = {0};
        long cn = mldt(0, cb, sizeof(cb));
        unsigned long cl = lsl(sel0, &ok);
        _exit(cn == 56 && ok && cl == 0xABCDE ? 0 : 9);
    }
    int st;
    waitpid(p, &st, 0);
    check(WIFEXITED(st) && WEXITSTATUS(st) == 0, "fork: child sees LDT");

    printf("ldttest: %d failures\n", fails);
    return fails;
}
