//! SYSCALL/SYSRET path: the ring-3 <-> ring-0 boundary.
//!
//! SYSCALL itself does NOT save or switch rsp, so the entry stub's
//! first act is swapping to a dedicated kernel stack. It then
//! marshals the Linux syscall ABI (nr=rax, args rdi/rsi/rdx) into a
//! Rust call, restores the user registers sysretq needs (rcx=rip,
//! r11=rflags), and returns.
//!
//! user_enter drops to ring 3 via iretq after saving a kernel frame;
//! sys_exit unwinds that frame (user_terminate) so control returns to
//! the caller of user::run — a one-shot process model until a real
//! task scheduler exists.

use crate::{elf, log, user};
use core::arch::global_asm;

/// Kernel stack top for the CURRENT task's syscall entries, set by
/// user::run before each ring-3 drop. SYSCALL doesn't touch TSS.rsp0,
/// so the stub loads this explicitly. TSS.rsp0 separately serves
/// interrupts arriving while CPL=3.
#[no_mangle]
static mut CUR_KSTACK: u64 = 0;

/// Where the stub stashes the user rsp for the return leg.
#[no_mangle]
static mut USER_RSP: u64 = 0;
/// Kernel rsp/cr3 saved by user_enter, restored by user_terminate.
#[no_mangle]
static mut KSP: u64 = 0;
#[no_mangle]
static mut KCR3: u64 = 0;

/// Point the entry stub at `top` — the current task's private kernel
/// stack. Called by user::run immediately before each ring-3 entry;
/// the serial run-to-completion model makes the singleton sound.
pub fn set_kstack(top: u64) {
    // SAFETY: sole writer, main context, before any user code runs.
    unsafe { *core::ptr::addr_of_mut!(CUR_KSTACK) = top };
}

global_asm!(
    "
    .globl syscall_entry
syscall_entry:
    // rcx=user rip, r11=user rflags; rsp is still the USER stack.
    mov qword ptr [rip + USER_RSP], rsp
    mov rsp, qword ptr [rip + CUR_KSTACK]
    and rsp, -16               // kstack top is 16-aligned; belt&braces
    // Build a full UCtx on the kstack — every user register plus the
    // iret frame — so a syscall can copy it (fork) or rewrite it
    // (exec) with exactly the semantics a task switch resumes.
    push 0x2b                  // ss
    push qword ptr [rip + USER_RSP]
    push r11                   // rflags
    push 0x33                  // cs
    push rcx                   // rip
    push rax                   // ctx.rax = nr (handler overwrites w/ ret)
    push rcx                   // ctx.rcx = cpu-saved rip (user rcx = rip)
    push rdx
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11                   // ctx.r11 = user rflags value
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov rcx, rsp               // arg: &mut UCtx (Windows x64 ABI)
    call handle_syscall
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rax                    // ctx.rax = the return value
    pop rcx                    // frame rip — exec may have redirected it
    add rsp, 8                 // skip cs slot
    pop r11                    // frame rflags
    pop rsp                    // back to the user stack
    sysretq

    .globl int80_entry
int80_entry:
    // ia32 compat syscall vector. The CPU pushed the privilege frame
    // [eip][cs][eflags][esp][ss] onto TSS.rsp0's stack (INTR_STACK,
    // not the task kstack); nr is in eax. Rebuild the full UCtx on
    // the task's kstack — same shape syscall_entry makes — copying
    // the frame down with push [rax+n] so NO user GPR is clobbered
    // (ia32 code may hold live state in r8-r15 via REX). iretq to
    // return — never sysretq, which cannot load a compat CS.
    push rax                     // save user eax (nr) below the frame
    mov rax, qword ptr [rip + CUR_KSTACK]
    and rax, -16                 // kstack top is 16-aligned; belt&braces
    xchg rax, rsp                // rsp=kstack, rax=&saved-eax/frame
    push qword ptr [rax + 40]    // user ss
    push qword ptr [rax + 32]    // user esp
    push qword ptr [rax + 24]    // user eflags
    push qword ptr [rax + 16]    // user cs (the compat CS)
    push qword ptr [rax + 8]     // user eip
    push qword ptr [rax]         // ctx.rax = user eax = nr
    push rcx                     // ctx.rcx = ia32 a2
    push rdx                     // a3
    push rsi                     // a4
    push rdi                     // a5
    push r8
    push r9
    push r10
    push r11
    push rbx                     // ctx.rbx = ia32 a1
    push rbp                     // a6
    push r12
    push r13
    push r14
    push r15
    mov rcx, rsp                 // arg: &mut UCtx (Windows x64 ABI)
    call handle_int80
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rax                      // ctx.rax = the return value
    iretq                        // frame cs restores compat mode

    .globl sched_launch
sched_launch:
    // First scheduler entry. Windows x64 args: rcx = &UCtx,
    // rdx = pml4. Saves the kernel context the last task's exit
    // unwinds to — Windows callee-saves rbx,rbp,rdi,rsi,r12-r15 and
    // the caller may hold live pointers in rdi/rsi across this call.
    push rbx
    push rbp
    push rdi
    push rsi
    push r12
    push r13
    push r14
    push r15
    mov rax, cr3
    mov [rip + KCR3], rax
    mov [rip + KSP], rsp
    // Fall into sched_iret — rcx/rdx still carry the arguments.
    .globl sched_iret
sched_iret:
    // The single resume path for every switch: adopt the target
    // task's page table, pop its saved GPRs, iretq into its frame.
    mov cr3, rdx
    mov rsp, rcx
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rax
    iretq

    .globl user_terminate
user_terminate:
    // Called from sys_exit while on the syscall stack. Unwind to the
    // frame user_enter saved: kernel page table, kernel stack, the
    // callee-saved set, then return to user::run's caller.
    mov rax, qword ptr [rip + KCR3]
    mov cr3, rax
    mov rsp, qword ptr [rip + KSP]
    pop r15
    pop r14
    pop r13
    pop r12
    pop rsi
    pop rdi
    pop rbp
    pop rbx
    ret
"
);

unsafe extern "win64" {
    fn user_terminate() -> !;
    fn syscall_entry();
    fn int80_entry();
    /// Resume a task ctx: cr3 = pml4, rsp = ctx, pop GPRs, iretq.
    /// Never returns — the caller's stack is abandoned.
    pub fn sched_iret(ctx: *const user::UCtx, pml4: u64) -> !;
    /// First scheduler entry — saves the kernel continuation the
    /// final exit unwinds to. Returns only via user_terminate.
    pub fn sched_launch(ctx: *const user::UCtx, pml4: u64);
}

/// Address the LSTAR MSR should point at.
pub fn entry_addr() -> u64 {
    syscall_entry as *const () as u64
}

/// Address the IDT's int 0x80 gate should point at.
pub fn int80_addr() -> u64 {
    int80_entry as *const () as u64
}

/// Unwind to the kernel frame sched_launch saved — the last task's
/// exit path back to main. Never returns to its caller's frame.
pub fn terminate() -> ! {
    unsafe { user_terminate() }
}

// Linux syscall numbers.
const NR_READ: u64 = 0;
const NR_WRITE: u64 = 1;
const NR_OPEN: u64 = 2;
const NR_CLOSE: u64 = 3;
const NR_SIGACTION: u64 = 13;
const NR_SIGRETURN: u64 = 15;
const NR_PIPE: u64 = 22;
const NR_MMAP: u64 = 9;
const NR_MPROTECT: u64 = 10;
const NR_MUNMAP: u64 = 11;
const NR_MREMAP: u64 = 25;
const NR_MADVISE: u64 = 28;
const NR_MINCORE: u64 = 27;
const NR_BRK: u64 = 12;
const NR_RT_SIGPROCMASK: u64 = 14;
const NR_LSEEK: u64 = 8;
const NR_DUP: u64 = 32;
const NR_DUP2: u64 = 33;
const NR_GETPID: u64 = 39;
const NR_FORK: u64 = 57;
const NR_EXECVE: u64 = 59;
const NR_EXIT: u64 = 60;
const NR_WAIT4: u64 = 61;
const NR_KILL: u64 = 62;
const NR_GETPPID: u64 = 110;
const NR_PIPE2: u64 = 293;
const NR_GETDENTS: u64 = 217;
const NR_NEWFSTATAT: u64 = 262;
const NR_STATX: u64 = 332;
const NR_POLL: u64 = 7;
const NR_SOCKET: u64 = 41;
const NR_CONNECT: u64 = 42;
const NR_ACCEPT: u64 = 43;
const NR_SENDTO: u64 = 44;
const NR_RECVFROM: u64 = 45;
const NR_SENDMSG: u64 = 46;
const NR_RECVMSG: u64 = 47;
const NR_SOCKETPAIR: u64 = 53;
const NR_SETSOCKOPT: u64 = 54;
const NR_SENDMMSG: u64 = 307;
const NR_RECVMMSG: u64 = 299;
const NR_SHUTDOWN: u64 = 48;
const NR_BIND: u64 = 49;
const NR_LISTEN: u64 = 50;
const NR_GETSOCKNAME: u64 = 51;
const NR_GETPEERNAME: u64 = 52;
const NR_READV: u64 = 19;
const NR_WRITEV: u64 = 20;
const NR_IOCTL: u64 = 16;
const NR_NANOSLEEP: u64 = 35;
const NR_UNAME: u64 = 63;
const NR_GETTIMEOFDAY: u64 = 96;
const NR_GETUID: u64 = 102;
const NR_GETGID: u64 = 104;
const NR_GETEUID: u64 = 107;
const NR_GETEGID: u64 = 108;
const NR_ARCH_PRCTL: u64 = 158;
const NR_GETTID: u64 = 186;
const NR_FUTEX: u64 = 202;
const NR_SET_TID_ADDRESS: u64 = 218;
const NR_CLOCK_GETTIME: u64 = 228;
const NR_CLOCK_NANOSLEEP: u64 = 230;
const NR_EXIT_GROUP: u64 = 231;
const NR_SET_ROBUST_LIST: u64 = 273;
const NR_PRLIMIT64: u64 = 302;
const NR_GETRANDOM: u64 = 318;
const NR_MEMFD_CREATE: u64 = 319;
const NR_PIDFD_OPEN: u64 = 434;
const NR_PIDFD_SEND_SIGNAL: u64 = 424;
const NR_PIDFD_GETFD: u64 = 438;
const NR_CLONE3: u64 = 435;
const NR_CLOSE_RANGE: u64 = 436;
const NR_EPOLL_PWAIT2: u64 = 441;
const NR_OPENAT2: u64 = 437;
const NR_PROCESS_MRELEASE: u64 = 448;
const NR_FUTEX_WAITV: u64 = 449;
const NR_FCHMODAT2: u64 = 452;
const NR_FUTEX_WAKE: u64 = 454;
const NR_FUTEX_WAIT: u64 = 455;
const NR_FUTEX_REQUEUE: u64 = 456;
const NR_MEMBARRIER: u64 = 324;
const NR_MLOCK: u64 = 149;
const NR_MUNLOCK: u64 = 150;
const NR_MLOCKALL: u64 = 151;
const NR_MUNLOCKALL: u64 = 152;
const NR_MLOCK2: u64 = 325;
const NR_PROCESS_MADVISE: u64 = 440;
const NR_CACHESTAT: u64 = 451;
const NR_MSEAL: u64 = 462;
const NR_RSEQ: u64 = 334;
const NR_SENDFILE: u64 = 40;
const NR_STAT: u64 = 4;
const NR_FSTAT: u64 = 5;
const NR_LSTAT: u64 = 6;
const NR_ACCESS: u64 = 21;
const NR_SCHED_YIELD: u64 = 24;
const NR_UMASK: u64 = 95;
const NR_SYSINFO: u64 = 99;
const NR_TIMES: u64 = 100;
const NR_TIME: u64 = 201;
const NR_GETRUSAGE: u64 = 98;
const NR_STATFS: u64 = 137;
const NR_FSTATFS: u64 = 138;
const NR_PRCTL: u64 = 157;
const NR_VFORK: u64 = 58;
const NR_GETGROUPS: u64 = 115;
const NR_SCHED_GETAFFINITY: u64 = 204;
const NR_SYNC: u64 = 162;
const NR_REBOOT: u64 = 169;
const NR_CHDIR: u64 = 80;
const NR_FCHDIR: u64 = 81;
const NR_MKDIR: u64 = 83;
const NR_RMDIR: u64 = 84;
const NR_MKNOD: u64 = 133;
const NR_MKDIRAT: u64 = 258;
const NR_MKNODAT: u64 = 259;
const NR_CLONE: u64 = 56;
const NR_GETCWD: u64 = 79;
const NR_SYMLINK: u64 = 88;
const NR_READLINK: u64 = 89;
const NR_GETRLIMIT: u64 = 97;
const NR_SETPGID: u64 = 109;
const NR_GETPGRP: u64 = 111;
const NR_SETSID: u64 = 112;
const NR_GETPGID: u64 = 121;
const NR_GETSID: u64 = 124;
const NR_GETPRIORITY: u64 = 140;
const NR_SETPRIORITY: u64 = 141;
const NR_CLOCK_GETRES: u64 = 229;
const NR_TGKILL: u64 = 234;
const NR_SYMLINKAT: u64 = 266;
const NR_READLINKAT: u64 = 267;
const NR_FACCESSAT: u64 = 269;
const NR_PREAD64: u64 = 17;
const NR_PWRITE64: u64 = 18;
const NR_FCNTL: u64 = 72;
const NR_FLOCK: u64 = 73;
const NR_LINK: u64 = 86;
const NR_LINKAT: u64 = 265;
const NR_OPENAT: u64 = 257;
const NR_DUP3: u64 = 292;
const NR_ACCEPT4: u64 = 288;
const NR_FSYNC: u64 = 74;
const NR_SYNC_FILE_RANGE: u64 = 277;
const NR_FDATASYNC: u64 = 75;
const NR_TRUNCATE: u64 = 76;
const NR_FTRUNCATE: u64 = 77;
const NR_RENAME: u64 = 82;
const NR_CREAT: u64 = 85;
const NR_UNLINK: u64 = 87;
const NR_UNLINKAT: u64 = 263;
const NR_RENAMEAT: u64 = 264;
const NR_RENAMEAT2: u64 = 316;
const NR_CHMOD: u64 = 90;
const NR_FCHMOD: u64 = 91;
const NR_CHOWN: u64 = 92;
const NR_FCHOWN: u64 = 93;
const NR_LCHOWN: u64 = 94;
const NR_UTIME: u64 = 132;
const NR_UTIMES: u64 = 235;
const NR_FCHOWNAT: u64 = 260;
const NR_FUTIMESAT: u64 = 261;
const NR_FCHMODAT: u64 = 268;
const NR_UTIMENSAT: u64 = 280;

// errno values (negative returns per the kernel ABI).
const ENOENT: u64 = (-2i64) as u64;
const EFAULT: u64 = (-14i64) as u64;
const EINVAL: u64 = (-22i64) as u64;
const ENAMETOOLONG: u64 = (-36i64) as u64;
const ENOEXEC: u64 = (-8i64) as u64;
const ENOSYS: u64 = (-38i64) as u64;

/// Longest single copy from user space — a hostile len can't stall
/// the kernel or exhaust memory.
const MAX_COPY: u64 = 4096;

/// Longest single read result — separate from MAX_COPY because big
/// reads are just a bounded memcpy in every fd_read arm (each arm
/// already min()s against what the source holds). Linux caps at
/// MAX_RW_COUNT and returns short; 1 MiB keeps the same honest
/// shape without forcing 4 KiB-per-syscall file copies.
const MAX_READ: u64 = 1 << 20;

/// ctx=rcx — the asm stub pushed a full UCtx and hands us &mut to it
/// (Windows x64 call convention). Args live in ctx.{rdi,rsi,rdx}; the
/// return value goes back through ctx.rax. Handlers may also copy the
/// whole ctx (fork), rewrite it (exec), block on it (wait4), or
/// diverge entirely (exit).
#[no_mangle]
extern "win64" fn handle_syscall(c: *mut user::UCtx) {
    // SAFETY: the stub built this UCtx on the current task's kstack.
    let ctx = unsafe { &mut *c };
    // NT-personality tasks share this stub but speak the Windows
    // convention (r10=arg1, stack args, NTSTATUS in rax) — route
    // before the Linux number table reads rdi-args that aren't set.
    if user::task_is_nt() {
        ctx.rax = crate::nt::dispatch(ctx, ctx.rax as u32);
        return;
    }
    if user::task_is_compat() {
        // A compat-mode `syscall` insn reaching the x86_64 LSTAR
        // (AMD executes it from compat mode; Intel #UDs first):
        // there is no x86_64 ABI contract here to honor — the
        // task's args aren't even in the right registers.
        ctx.rax = ENOSYS;
        return;
    }
    let (nr, a1, a2, a3) = (ctx.rax, ctx.rdi, ctx.rsi, ctx.rdx);
    // First-syscall marker per task slot: on firmware where a task
    // goes silent after spawn (the VMware stall) this separates
    // "never reached ring-3" from "runs but produces nothing".
    static mut SYS_SEEN: [u64; 2] = [0; 2];
    let ci = user::cur_index();
    if ci < 128 {
        // SAFETY: syscall entry masks IF — single accessor.
        let (w, b) = (ci / 64, ci % 64);
        if unsafe { SYS_SEEN[w] } & (1 << b) == 0 {
            unsafe { SYS_SEEN[w] |= 1 << b };
            crate::log::printk(format_args!(
                "rustux: sched: first syscall nr={} from slot {}",
                nr, ci
            ));
            crate::log::drain_task();
        }
    }
    // Args 4-6 ride r10/r8/r9 per the syscall ABI (arg4 is r10,
    // never rcx — that's the CPU-clobbered return address).
    let (a4, a5, a6) = (ctx.r10, ctx.r8, ctx.r9);
    ctx.rax = match nr {
        // fd_read validates the write-target range itself because only
        // it knows how many bytes the source will actually produce.
        // Linux clamps count to MAX_RW_COUNT and returns what it can —
        // never EINVAL on a big buffer (a 128KiB stdio read must not
        // fail). Our cap is the same copy budget sys_write uses; every
        // fd_read arm already min()s against available data.
        NR_READ => user::fd_read(ctx, a1, a2, a3.min(MAX_READ)),
        NR_WRITE => sys_write(ctx, a1, a2, a3),
        NR_PIPE => user::fd_pipe(a1, 0),
        NR_PIPE2 => user::fd_pipe(a1, a2),
        NR_MMAP => user::sys_mmap(a1, a2, a3, a4, a5, a6),
        NR_MPROTECT => user::sys_mprotect(a1, a2, a3),
        NR_MUNMAP => user::sys_munmap(a1, a2),
        NR_MREMAP => user::sys_mremap(a1, a2, a3, a4, a5),
        NR_MADVISE => user::sys_madvise(a1, a2, a3),
        NR_MINCORE => user::sys_mincore(a1, a2, a3),
        NR_BRK => user::sys_brk(a1),
        NR_RT_SIGPROCMASK => user::sys_rt_sigprocmask(a1, a2, a3, a4),
        NR_POLL => user::fd_poll(ctx, a1, a2, a3 as i64),
        34 => user::sys_pause(ctx),
        36 => user::sys_getitimer(a1, a2),
        37 => user::sys_alarm(a1),
        38 => user::sys_setitimer(a1, a2, a3),
        127 => user::sys_sigpending(a1, a2),
        130 => user::sys_sigsuspend(ctx, a1, a2),
        // rt_sigtimedwait(set,info,ts,sigsize): glibc sigwaitinfo
        // reaches it with ts=NULL — there is no nr-129 sigwaitinfo.
        129 => user::rt_sigqueueinfo(a1 as i64, a2, a3),
        297 => user::rt_tgsigqueueinfo(a1, a2 as i64, a3, a4),
        128 => user::sys_rt_sigtimedwait(ctx, a1, a2, a3, a4),
        270 => user::fd_pselect(ctx, a1, a2, a3, a4, a5, a6),
        271 => user::fd_ppoll(ctx, a1, a2, a3, a4, a5),
        // epoll: create(213) is legacy-size, create1(291) is flags.
        213 => user::fd_epoll_create(a1, true),
        291 => user::fd_epoll_create(a1, false),
        233 => user::fd_epoll_ctl(a1, a2, a3, a4),
        232 => user::fd_epoll_wait(ctx, a1, a2, a3, a4 as i64, 0, 0),
        281 => user::fd_epoll_wait(ctx, a1, a2, a3, a4 as i64, a5, a6),
        // anon-inode semaphores + tick timers.
        284 => user::fd_eventfd(a1, 0),  // eventfd: no flags
        290 => user::fd_eventfd(a1, a2), // eventfd2
        // signalfd(fd,mask,sizemask) / signalfd4 +flags arg —
        // fd<0 creates a new instance, fd>=0 updates the mask.
        282 => user::fd_signalfd(a1, a2, a3),
        289 => user::fd_signalfd4(a1, a2, a3, a4),
        // inotify: init/init1 create; add_watch needs a canon path
        // like the open family; rm_watch is wd-by-number.
        253 => user::fd_inotify_init1(0),
        294 => user::fd_inotify_init1(a1),
        254 => sys_inotify_add(a1, a2, a3),
        255 => user::inotify_rm_watch(a1, a2),
        283 => user::fd_timerfd_create(a1, a2),
        286 => user::fd_timerfd_settime(a1, a2, a3, a4),
        287 => user::fd_timerfd_gettime(a1, a2),
        NR_SOCKET => user::fd_socket(a1, a2, a3),
        NR_CONNECT => user::fd_connect(ctx, a1, a2, a3),
        NR_ACCEPT => user::fd_accept(ctx, a1, a2, a3, 0),
        NR_ACCEPT4 => user::fd_accept(ctx, a1, a2, a3, a4),
        NR_BIND => user::fd_bind(a1, a2, a3),
        NR_LISTEN => user::fd_listen(a1, a2),
        NR_GETSOCKNAME => user::fd_getsockname(a1, a2, a3),
        NR_GETPEERNAME => user::fd_getpeername(a1, a2, a3),
        NR_SHUTDOWN => user::fd_shutdown(a1, a2),
        NR_SENDTO => user::fd_sendto(ctx, a1, a2, a3, a4, a5, a6),
        NR_RECVFROM => user::fd_recvfrom(ctx, a1, a2, a3, a4, a5, a6),
        NR_SENDMSG => user::fd_sendmsg(ctx, a1, a2, a3),
        NR_RECVMSG => user::fd_recvmsg(ctx, a1, a2, a3),
        NR_SOCKETPAIR => user::fd_socketpair(a1, a2, a3, a4),
        NR_SETSOCKOPT => user::fd_setsockopt(a1, a2, a3, a4, a5),
        55 => user::fd_getsockopt(a1, a2, a3, a4, a5),
        NR_SENDMMSG => user::fd_sendmmsg(ctx, a1, a2, a3, a4),
        NR_RECVMMSG => user::fd_recvmmsg(ctx, a1, a2, a3, a4, a5),
        NR_OPEN => sys_open(a1, a2, a3),
        NR_OPENAT => sys_openat(a1, a2, a3, a4),
        NR_PREAD64 => user::fd_pread(a1, a2, a3, a4 as i64),
        NR_PWRITE64 => user::fd_pwrite(a1, a2, a3, a4 as i64),
        NR_FCNTL => user::sys_fcntl(a1, a2, a3),
        NR_FLOCK => user::sys_flock(a1, a2),
        NR_LINK => sys_linkat(u64::MAX, a1, u64::MAX, a2, 0),
        NR_LINKAT => sys_linkat(a1, a2, a3, a4, a5),
        NR_DUP3 => user::fd_dup3(a1, a2, a3),
        NR_CLOSE => user::fd_close(a1),
        // off arrives as u64; the fd layer interprets it as i64 —
        // negative seeks are how SEEK_CUR/END move backwards.
        NR_LSEEK => user::fd_lseek(a1, a2 as i64, a3),
        NR_SIGACTION => user::sigaction(a1, a2, a3, a4),
        NR_SIGRETURN => user::sigreturn(ctx),
        NR_DUP => user::fd_dup(a1),
        NR_DUP2 => user::fd_dup2(a1, a2),
        NR_GETPID => user::getpid(),
        NR_FORK => user::fork(ctx, false, false),
        // wait4's first arg is pid_t (i32) on the ABI: glibc's wait
        // wrappers zero-extend `mov edi,-1` to 0xffffffff — Linux's
        // SYSCALL_DEFINE truncates pid args to 32 bits and
        // sign-extends. Without the i32 cast, wait4(-1) becomes a
        // search for pid 4294967295 -> ECHILD (found by real dash).
        NR_WAIT4 => user::wait4(ctx, a1 as i32 as i64, a2, a3),
        // waitid(idtype, id, infop, options): id is uid_t/fd-sized —
        // truncate to u32 like the pid args so a stray high bit can't
        // fabricate a selector the caller didn't pass.
        247 => user::waitid(ctx, a1 as u32 as u64, a2 as u32 as u64, a3, a4),
        NR_KILL => user::kill(a1 as i32 as i64, a2),
        NR_GETPPID => user::getppid(),
        NR_GETDENTS => user::fd_getdents(a1, a2, a3, false),
        // getdents (legacy 78): linux_dirent — same header but the
        // name starts at 18 and d_type rides the record's last byte.
        78 => user::fd_getdents(a1, a2, a3, true),
        // syslog/klogctl: the kernel-log-ring reader.
        103 => user::sys_syslog(ctx, a1, a2, a3),
        // setrlimit is prlimit64's pid-0/no-old subset.
        160 => user::sys_setrlimit(a1, a2),
        // newfstatat(dirfd, path, buf, flags): dirfd is ABI-shape
        // only; flags carry AT_SYMLINK_NOFOLLOW (0x100).
        NR_NEWFSTATAT => sys_newfstatat(a1, a2, a3, a4),
        NR_STATX => sys_statx(a1, a2, a3, a4, a5),
        NR_EXECVE => sys_execve(ctx, a1, a2, a3),
        NR_READV => user::fd_readv(ctx, a1, a2, a3),
        NR_WRITEV => sys_writev(ctx, a1, a2, a3),
        NR_IOCTL => user::sys_ioctl(a1, a2, a3),
        NR_NANOSLEEP => user::sys_nanosleep(ctx, a1, a2),
        NR_UNAME => user::sys_uname(a1),
        NR_GETTIMEOFDAY => user::sys_gettimeofday(a1, a2),
        NR_GETUID => user::sys_getuid(),
        NR_GETGID => user::sys_getgid(),
        NR_GETEUID => user::sys_geteuid(),
        NR_GETEGID => user::sys_getegid(),
        NR_ARCH_PRCTL => user::sys_arch_prctl(a1, a2),
        NR_GETTID => user::sys_gettid(),
        NR_FUTEX => user::sys_futex(ctx, a1, a2, a3, a4, a5, a6),
        NR_SET_TID_ADDRESS => user::sys_set_tid_address(),
        NR_CLOCK_GETTIME => user::sys_clock_gettime(a1, a2),
        NR_CLOCK_NANOSLEEP => user::sys_clock_nanosleep(ctx, a1, a2, a3, a4),
        // No threads — the group is the task.
        NR_EXIT_GROUP => sys_exit(a1),
        NR_SET_ROBUST_LIST => user::sys_set_robust_list(a1, a2),
        NR_PRLIMIT64 => user::sys_prlimit64(a1, a2, a3, a4),
        NR_GETRANDOM => user::sys_getrandom(a1, a2, a3),
        NR_MEMFD_CREATE => user::fd_memfd_create(a1, a2),
        NR_PIDFD_OPEN => user::fd_pidfd_open(a1 as u32 as i32 as i64, a2),
        NR_PIDFD_SEND_SIGNAL => user::fd_pidfd_send_signal(a1, a2, a3, a4),
        NR_PIDFD_GETFD => user::fd_pidfd_getfd(a1, a2, a3),
        NR_CLONE3 => user::sys_clone3(ctx, a1, a2),
        NR_CLOSE_RANGE => user::fd_close_range(a1, a2, a3),
        NR_EPOLL_PWAIT2 => user::fd_epoll_pwait2(ctx, a1, a2, a3, a4, a5, a6),
        NR_OPENAT2 => sys_openat2(a1, a2, a3, a4),
        NR_PROCESS_MRELEASE => user::fd_process_mrelease(a1, a2),
        NR_FUTEX_WAITV => user::sys_futex_waitv(ctx, a1, a2, a3, a4, a5),
        NR_FCHMODAT2 => sys_fchmodat2(a1, a2, a3, a4),
        // xattr family: path (follow final link), l* (no follow),
        // f* (by fd); core logic lives in user.rs's XATTRS table.
        188 => sys_setxattr(a1, a2, a3, a4, a5),
        189 => sys_lsetxattr(a1, a2, a3, a4, a5),
        190 => sys_fsetxattr(a1, a2, a3, a4, a5),
        191 => sys_getxattr(a1, a2, a3, a4),
        192 => sys_lgetxattr(a1, a2, a3, a4),
        193 => sys_fgetxattr(a1, a2, a3, a4),
        194 => sys_listxattr(a1, a2, a3),
        195 => sys_llistxattr(a1, a2, a3),
        196 => sys_flistxattr(a1, a2, a3),
        197 => sys_removexattr(a1, a2),
        198 => sys_lremovexattr(a1, a2),
        199 => sys_fremovexattr(a1, a2),
        // xattrat family: dfd-relative with AT_SYMLINK_NOFOLLOW +
        // AT_EMPTY_PATH; set/get pack the tail args in xattr_args.
        463 => sys_setxattrat(a1, a2, a3, a4, a5, a6),
        464 => sys_getxattrat(a1, a2, a3, a4, a5, a6),
        465 => sys_listxattrat(a1, a2, a3, a4, a5),
        466 => sys_removexattrat(a1, a2, a3, a4),
        447 => user::fd_memfd_secret(a1),
        // small classics: select is pselect with a timeval
        // converted in place; msync validates then no-ops (eager
        // private copies); getcpu/getattr/setattr report the fixed
        // single-CPU normal-class scheduler.
        23 => user::fd_select(ctx, a1, a2, a3, a4, a5),
        26 => user::sys_msync(a1, a2, a3),
        309 => user::sys_getcpu(a1, a2, a3),
        314 => user::sys_sched_setattr(a1, a2, a3, a4),
        315 => user::sys_sched_getattr(a1, a2, a3, a4),
        // SysV SHM over the SHMSEGS machinery — shmid encodes
        // (gen << 16) | slot so stale ids EINVAL.
        29 => user::sys_shmget(a1, a2, a3),
        30 => user::sys_shmat(a1, a2, a3),
        31 => user::sys_shmctl(a1, a2, a3),
        67 => user::sys_shmdt(a1),
        // small classics II: cross-mm iovec copy, kernel-side file
        // copy, wall clock write, inert hints + affinity gate.
        310 => user::sys_process_vm_readv(a1, a2, a3, a4, a5, a6),
        311 => user::sys_process_vm_writev(a1, a2, a3, a4, a5, a6),
        326 => user::sys_copy_file_range(a1, a2, a3, a4, a5, a6),
        227 => user::sys_clock_settime(a1, a2),
        221 => user::sys_fadvise64(a1, a2, a3, a4),
        203 => user::sys_sched_setaffinity(a1, a2, a3),
        // small classics III: alt stack + robust-list peer read +
        // wall clock write + inert fsync-all.
        131 => user::sys_sigaltstack(a1, a2, ctx),
        164 => user::sys_settimeofday(a1, a2),
        274 => user::sys_get_robust_list(a1, a2, a3),
        306 => user::sys_syncfs(a1),
        170 => user::sys_sethostname(a1, a2),
        171 => user::sys_setdomainname(a1, a2),
        285 => user::sys_fallocate(a1, a2, a3 as i64, a4 as i64),
        295 => user::fd_preadv(a1, a2, a3, a4 as i64),
        296 => user::fd_pwritev(a1, a2, a3, a4 as i64),
        275 => user::sys_splice(a1, a2, a3, a4, a5, a6),
        276 => user::sys_tee(a1, a2, a3, a4),
        278 => user::sys_vmsplice(a1, a2, a3, a4),
        327 => user::fd_preadv2(a1, a2, a3, a4 as i64, a5),
        328 => user::fd_pwritev2(a1, a2, a3, a4 as i64, a5),
        142 => user::sys_sched_setparam(a1, a2),
        143 => user::sys_sched_getparam(a1, a2),
        144 => user::sys_sched_setscheduler(a1, a2 as i64, a3),
        145 => user::sys_sched_getscheduler(a1),
        146 => user::sys_sched_get_priority_max(a1 as i64),
        147 => user::sys_sched_get_priority_min(a1 as i64),
        148 => user::sys_sched_rr_get_interval(a1, a2),
        187 => user::sys_readahead(a1, a2 as i64, a3),
        200 => user::sys_tkill(a1, a2),
        237 => user::sys_mbind(a1, a2, a3, a4, a5, a6),
        238 => user::sys_set_mempolicy(a1, a2, a3),
        239 => user::sys_get_mempolicy(a1, a2, a3, a4, a5),
        251 => user::sys_ioprio_set(a1, a2, a3),
        252 => user::sys_ioprio_get(a1, a2),
        // The credentials block — uid stores to t.uid, gid and
        // groups collapse to the single-user root model.
        105 => user::sys_setuid(a1),
        106 => user::sys_setgid(a1),
        113 => user::sys_setreuid(a1, a2),
        114 => user::sys_setregid(a1, a2),
        116 => user::sys_setgroups(a1, a2),
        117 => user::sys_setresuid(a1, a2, a3),
        118 => user::sys_getresuid(a1, a2, a3),
        119 => user::sys_setresgid(a1, a2, a3),
        120 => user::sys_getresgid(a1, a2, a3),
        125 => user::sys_capget(a1, a2),
        126 => user::sys_capset(a1, a2),
        322 => sys_execveat(ctx, a1, a2, a3, a4, a5),
        // SysV message queues — same gen<<16|slot id model as SHM.
        // SysV semaphore family — the third sibling of 29-31/68-71.
        64 => user::sys_semget(a1, a2, a3),
        65 => user::sys_semop(ctx, a1, a2, a3),
        66 => user::sys_semctl(a1, a2, a3, a4),
        220 => user::sys_semtimedop(ctx, a1, a2, a3, a4),
        // POSIX per-process timers.
        222 => user::sys_timer_create(a1, a2, a3),
        223 => user::sys_timer_settime(a1, a2, a3, a4),
        224 => user::sys_timer_gettime(a1, a2),
        225 => user::sys_timer_getoverrun(a1),
        226 => user::sys_timer_delete(a1),
        // POSIX message queues.
        240 => user::sys_mq_open(a1, a2, a3, a4),
        241 => user::sys_mq_unlink(a1),
        242 => user::sys_mq_timedsend(ctx, a1, a2, a3, a4, a5),
        243 => user::sys_mq_timedreceive(ctx, a1, a2, a3, a4, a5),
        244 => user::sys_mq_notify(a1, a2),
        245 => user::sys_mq_getsetattr(a1, a2, a3),
        68 => user::sys_msgget(a1, a2),
        69 => user::sys_msgsnd(ctx, a1, a2, a3, a4),
        70 => user::sys_msgrcv(ctx, a1, a2, a3, a4, a5),
        71 => user::sys_msgctl(a1, a2, a3),

        NR_FUTEX_WAKE => user::sys_futex_wake(a1, a2, a3, a4),
        NR_FUTEX_WAIT => user::sys_futex_wait(ctx, a1, a2, a3, a4, a5, a6),
        NR_FUTEX_REQUEUE => user::sys_futex_requeue(a1, a2, a3, a4),
        NR_MEMBARRIER => user::sys_membarrier(a1, a2, a3),
        NR_MLOCK | NR_MUNLOCK => user::sys_mlock(a1, a2),
        NR_MLOCKALL => user::sys_mlockall(a1),
        NR_MUNLOCKALL => 0, // no args — rdi is user garbage
        NR_MLOCK2 => user::sys_mlock2(a1, a2, a3),
        NR_PROCESS_MADVISE => user::fd_process_madvise(a1, a2, a3, a4, a5),
        NR_CACHESTAT => user::sys_cachestat(a1, a2, a3),
        NR_MSEAL => user::sys_mseal(a1, a2, a3),
        NR_CLONE => user::sys_clone(ctx, a1, a2, a3, a4, a5),
        NR_TGKILL => user::sys_tgkill(a1, a2, a3),
        NR_GETCWD => user::sys_getcwd(a1, a2),
        // stat follows; lstat is nofollow — proc links exist now.
        NR_STAT => sys_stat_path(a1, a2, false),
        NR_LSTAT => sys_stat_path(a1, a2, true),
        NR_FSTAT => user::sys_fstat(a1, a2),
        NR_ACCESS => sys_access(u64::MAX, a1, a2),
        NR_FACCESSAT => sys_access(a1, a2, a3),
        // faccessat2's extra flags arg: AT_EACCESS is inert in a
        // single-user world; AT_SYMLINK_NOFOLLOW is the same edge
        // faccessat already documents. Same answer either way.
        439 => sys_access(a1, a2, a3),
        NR_SYMLINK => sys_symlink(a1, a2),
        NR_SYMLINKAT => sys_symlinkat(a1, a2, a3),
        NR_READLINK => sys_readlink(a1, a2, a3),
        NR_READLINKAT => sys_readlinkat(a1, a2, a3, a4),
        NR_FSYNC | NR_FDATASYNC => user::fd_fsync(a1),
        // Writeback hint — dpkg issues one per extracted file. No
        // writeback exists to schedule; valid flags + valid fd = 0.
        NR_SYNC_FILE_RANGE => {
            if a4 & !7 != 0 {
                EINVAL
            } else {
                user::fd_fsync(a1) // validates fd, returns 0
            }
        }
        NR_TRUNCATE => sys_truncate(a1, a2),
        NR_FTRUNCATE => user::fd_ftruncate(a1, a2),
        NR_RENAME => sys_renameat2(u64::MAX, a1, u64::MAX, a2, 0),
        NR_RENAMEAT => sys_renameat2(a1, a2, a3, a4, 0),
        NR_RENAMEAT2 => sys_renameat2(a1, a2, a3, a4, a5),
        // creat(path, mode) = open(path, O_CREAT|O_WRONLY|O_TRUNC).
        NR_CREAT => sys_openat(u64::MAX, a1, 0o1101, a2),
        NR_UNLINK => sys_unlinkat(u64::MAX, a1, 0),
        NR_UNLINKAT => sys_unlinkat(a1, a2, a3),
        NR_GETRLIMIT => user::sys_prlimit64(0, a1, 0, a2),
        NR_CLOCK_GETRES => user::sys_clock_getres(a1, a2),
        NR_SCHED_YIELD => user::sys_sched_yield(ctx),
        NR_GETPGRP => user::sys_getpgrp(),
        NR_GETPGID => user::sys_getpgid(a1),
        NR_GETSID => user::sys_getsid(a1),
        NR_SETSID => user::sys_setsid(),
        NR_SETPGID => user::sys_setpgid(a1, a2),
        NR_SETPRIORITY => user::sys_setpriority(a1, a2, a3 as i64),
        NR_GETPRIORITY => user::sys_getpriority(a1, a2),
        NR_UMASK => user::sys_umask(a1),
        NR_SYSINFO => user::sys_sysinfo(a1),
        NR_TIMES => user::sys_times(a1),
        NR_TIME => user::sys_time(a1),
        NR_GETRUSAGE => user::sys_getrusage(a1, a2),
        NR_STATFS => sys_statfs(a1, a2),
        NR_FSTATFS => user::sys_fstatfs(a1, a2),
        NR_PRCTL => user::sys_prctl(a1, a2),
        NR_GETGROUPS => user::sys_getgroups(a1, a2),
        NR_SCHED_GETAFFINITY => user::sys_sched_getaffinity(a1, a2, a3),
        // Real vfork: shared mm + uninterruptible parent wait until
        // the child execs or exits (sys_vfork in user.rs).
        NR_VFORK => user::sys_vfork(ctx),
        NR_RSEQ => user::sys_rseq(a1, a2, a3, a4),
        NR_SENDFILE => user::sys_sendfile(a1, a2, a3, a4),
        NR_SYNC => 0,
        NR_REBOOT => user::sys_reboot(a1, a2, a3),
        NR_CHDIR => sys_chdir(a1),
        NR_FCHDIR => user::sys_fchdir(a1),
        161 => sys_chroot(a1),
        163 => sys_acct(a1),
        155 => sys_pivot_root(a1, a2),
        165 => sys_mount(a1, a2, a3, a4),
        430 => sys_fsopen(a1, a2),
        431 => sys_fsconfig(a1, a2, a3, a4, a5),
        432 => user::sys_fsmount(a1, a2, a3),
        443 => user::sys_quotactl_fd(a1, a2, a3, a4),
        428 => sys_open_tree(a1, a2, a3),
        429 => sys_move_mount(a1, a2, a3, a4, a5),
        433 => sys_fspick(a1, a2, a3),
        442 => sys_mount_setattr(a1, a2, a3, a4, a5),
        179 => sys_quotactl(a1, a2, a3, a4),
        166 => sys_umount2(a1, a2),
        457 => user::sys_statmount(a1, a2, a3, a4),
        458 => user::sys_listmount(a1, a2, a3, a4),
        272 => user::sys_unshare(a1),
        154 => user::sys_modify_ldt(a1, a2, a3),
        329..=331 => user::sys_pkey(a1, a2, a3),
        135 => user::sys_personality(a1),
        159 => user::sys_adjtimex(a1),
        305 => user::sys_clock_adjtime(a1, a2),
        303 => sys_name_to_handle_at(a1, a2, a3, a4, a5),
        304 => user::sys_open_by_handle_at(a1, a2, a3),
        312 => user::sys_kcmp(a1, a2, a3, a4, a5),
        NR_CHMOD => sys_chmod(a1, a2),
        NR_FCHMOD => user::fd_chmod(a1, a2),
        NR_FCHMODAT => sys_fchmodat(a1, a2, a3),
        NR_CHOWN => sys_chown_path(u64::MAX, a1, a2, a3, false),
        NR_FCHOWN => user::fd_chown(a1, a2, a3),
        NR_LCHOWN => sys_chown_path(u64::MAX, a1, a2, a3, true),
        NR_FCHOWNAT => sys_fchownat(a1, a2, a3, a4, a5),
        NR_UTIME => sys_utime(a1, a2),
        NR_UTIMES => sys_utimes_path(u64::MAX, a1, a2),
        NR_FUTIMESAT => sys_utimes_path(a1, a2, a3),
        NR_UTIMENSAT => sys_utimensat(a1, a2, a3, a4),
        NR_MKDIR => sys_mkdirat(u64::MAX, a1, a2),
        NR_MKDIRAT => sys_mkdirat(a1, a2, a3),
        NR_MKNOD => sys_mknodat(u64::MAX, a1, a2, a3),
        NR_MKNODAT => sys_mknodat(a1, a2, a3, a4),
        NR_RMDIR => sys_rmdir(a1),
        NR_EXIT => sys_exit(a1),
        // setfsuid/setfsgid: single-uid kernel — the fs credentials
        // are 0 and stay 0; the ABI returns the previous value.
        122 | 123 => 0,
        _ => {
            // Bring-up aid: real binaries probe ABI surface. Linux
            // returns ENOSYS the same way; we just name the number.
            log::printk(format_args!("rustux: enosys: nr {nr}"));
            ENOSYS
        }
    };
    // Signals deliver on the way back to user mode — a handler
    // redirects this ctx; a default-fatal signal never returns.
    user::deliver_current(ctx);
}

/// int 0x80 — the ia32 compat syscall table. nr in eax, args
/// ebx/ecx/edx/esi/edi/ebp; -errno in eax like the 64-bit ABI.
/// Every wired number shares its argument shapes with the 64-bit
/// impl — calls whose ABI structs differ (timeval32, iovec32,
/// stat64, linux_dirent, old rlimit) are ENOSYS until their compat
/// shims land; fork/clone/exec and all signal calls are out of
/// scope for compat tasks this rung.
#[no_mangle]
extern "win64" fn handle_int80(c: *mut user::UCtx) {
    // SAFETY: int80_entry built this UCtx on the current kstack.
    let ctx = unsafe { &mut *c };
    // Linux's compat entry loads the arg registers as 32-bit values —
    // high halves a REX-literate compat task could have set never
    // reach the ABI. nr likewise (eax's write already zero-extends,
    // this is belt-and-braces).
    let (nr, a1, a2, a3, a4, a5, a6) = (
        ctx.rax as u32 as u64,
        ctx.rbx as u32 as u64,
        ctx.rcx as u32 as u64,
        ctx.rdx as u32 as u64,
        ctx.rsi as u32 as u64,
        ctx.rdi as u32 as u64,
        ctx.rbp as u32 as u64,
    );
    ctx.rax = match nr {
        1 | 252 => sys_exit(a1),                 // exit / exit_group
        3 => user::fd_read(ctx, a1, a2, a3.min(MAX_READ)),
        4 => sys_write(ctx, a1, a2, a3),
        5 => sys_open(a1, a2, a3),
        6 => user::fd_close(a1),
        10 => sys_unlinkat(u64::MAX, a1, 0),
        15 => sys_chmod(a1, a2),
        // lseek's off is i32 — sign-extend like the wait4 pid fix.
        19 => user::fd_lseek(a1, a2 as u32 as i32 as i64, a3),
        20 => user::getpid(),
        24 | 199..=202 => 0,                  // {g,u,eu,eg}id{,32}
        33 => sys_access(u64::MAX, a1, a2),
        37 => user::kill(a1 as u32 as i32 as i64, a2),
        39 => sys_mkdirat(u64::MAX, a1, a2),
        40 => sys_rmdir(a1),
        41 => user::fd_dup(a1),
        42 => user::fd_pipe(a1, 0),
        45 => user::sys_brk(a1),
        54 => user::sys_ioctl(a1, a2, a3),
        55 => user::sys_fcntl(a1, a2, a3),
        60 => user::sys_umask(a1),
        63 => user::fd_dup2(a1, a2),
        64 => user::getppid(),
        85 => sys_readlink(a1, a2, a3),
        91 => user::sys_munmap(a1, a2),
        93 => user::fd_ftruncate(a1, a2),
        118 => user::fd_fsync(a1),
        122 => user::sys_uname(a1),
        125 => user::sys_mprotect(a1, a2, a3),
        158 => user::sys_sched_yield(ctx),
        183 => user::sys_getcwd(a1, a2),
        // mmap2's offset is in 4KiB units — byte offset shifts 12.
        192 => match a6.checked_shl(12) {
            Some(off) => user::sys_mmap(a1, a2, a3, a4, a5, off),
            None => (-12i64) as u64, // ENOMEM
        },
        // getdents64: linux_dirent64 keeps u64 fields on both ABIs.
        220 => user::fd_getdents(a1, a2, a3, false),
        // i386 signal surface: sigaction(67), sigprocmask(126),
        // sigreturn(119), rt_sigaction(174), rt_sigprocmask(175),
        // rt_sigreturn(173). Struct sigaction is 16 bytes and the
        // sigset is 4 bytes under this ABI.
        67 | 174 => user::sigaction32(a1, a2, a3),
        // compat struct shims: timeval32/timespec32 are two i32,
        // iovec32 is 8 bytes, and struct pollfd is ABI-identical.
        78 => user::sys_gettimeofday32(a1, a2),
        145 => user::fd_readv32(ctx, a1, a2, a3),
        146 => sys_writev32(ctx, a1, a2, a3),
        162 => user::sys_nanosleep32(ctx, a1, a2),
        168 => user::fd_poll(ctx, a1, a2, a3 as i32 as i64),
        // fcntl64: modern i386 (glibc/busybox) uses it for
        // F_DUPFD_CLOEXEC, which the old 32-bit fcntl cannot express.
        221 => user::sys_fcntl(a1, a2, a3),
        // pipe2: modern i386 (glibc/busybox) creates pipeline pairs
        // with it; flags carry O_CLOEXEC/O_NONBLOCK.
        331 => user::fd_pipe(a1, a2),
        119 | 173 => user::rt_sigreturn32(ctx),
        126 | 175 => user::rt_sigprocmask32(a1, a2, a3, if nr == 175 { a4 } else { 4 }),
        // i386 process creation: fork(2), waitpid(7), execve(11).
        2 => user::fork(ctx, false, false),
        7 => user::wait4(ctx, a1 as u32 as i32 as i64, a2, a3),
        // wait4: the 4-arg form busybox ash uses to reap a pipeline.
        114 => user::wait4(ctx, a1 as u32 as i32 as i64, a2, a3),
        11 => sys_execve(ctx, a1, a2, a3),
        // clone(flags, stack, ptid, tls, ctid) — i386 passes TLS in
        // esi and ctid in edi, the reverse of the x86_64 order.
        120 => user::sys_clone(ctx, a1, a2, a3, a5, a4),
        // vfork: busybox ash and glibc's i386 spawn path use it.
        190 => user::sys_vfork(ctx),
        172 => user::sys_prctl(a1, a2),
        // ugetrlimit(resource, rlim) — the i386 form takes TWO args;
        // passing the resource as the pointer made every probe EFAULT.
        191 => user::sys_ugetrlimit(a2),
        // i386 stat64 family — glibc's stat/lstat/fstat land on 195/
        // 196/197 (and fstatat64 300); struct stat64 is the packed
        // 96-byte i386 layout, not the 144-byte x86_64 one.
        195 => sys_fstatat64(u64::MAX, a1, a2, 0),
        196 => sys_fstatat64(u64::MAX, a1, a2, 0x100),
        197 => match user::fill_fstat(a1) {
            Ok(st) => user::emit_stat64(&st, a2),
            Err(e) => e,
        },
        265 => user::sys_clock_gettime32(a1, a2),
        295 => sys_openat(a1, a2, a3, a4),
        300 => sys_fstatat64(a1, a2, a3, a4),
        // statx: same 256-byte struct on both ABIs.
        383 => sys_statx(a1, a2, a3, a4, a5),
        // clock_gettime64 — timespec64 is the x86_64 layout.
        403 => user::sys_clock_gettime(a1, a2),
        224 => user::sys_gettid(),
        // i386 TLS install — glibc's startup calls this before it
        // touches %gs-based errno/TCB.
        243 => user::sys_set_thread_area(a1),
        // i386 robust-futex list head is 12 bytes (3 x u32).
        311 => user::sys_set_robust_list32(a1, a2),
        // i386 readlinkat — same dirfd/path/buf/len shape.
        305 => sys_readlinkat(a1, a2, a3, a4),
        // rseq: the 32-byte struct rseq layout is ABI-identical.
        386 => user::sys_rseq(a1, a2, a3, a4),
        258 => user::sys_set_tid_address(),
        340 => user::sys_prlimit64(a1, a2, a3, a4),
        355 => user::sys_getrandom(a1, a2, a3),
        _ => {
            log::printk(format_args!("rustux: enosys: ia32 nr {nr}"));
            ENOSYS
        }
    };



    user::deliver_current(ctx);
}

/// Copy a NUL-terminated user pathname into `name` under the pointer
/// gate — the getname discipline (CVE-2025-68814 class): byte-wise
/// validation, bounded, EFAULT on unmapped bytes, ENAMETOOLONG past
/// the cap. Returns the name length (excluding the NUL) or an errno.
fn copy_user_path(path: u64, name: &mut [u8; 257]) -> Result<usize, u64> {
    let mut n = 0usize;
    loop {
        if n == 256 {
            return Err(ENAMETOOLONG);
        }
        if !user::range_ok(path + n as u64, 1) {
            return Err(EFAULT);
        }
        // SAFETY: range_ok proved this byte is inside a mapped range.
        let b = unsafe { *((path + n as u64) as *const u8) };
        if b == 0 {
            break;
        }
        name[n] = b;
        n += 1;
    }
    Ok(n)
}

/// newfstatat(dirfd, path, statbuf, flags): same getname discipline
/// as open, then a fixed 144-byte stat write into user space.
fn sys_newfstatat(dirfd: u64, path: u64, statbuf: u64, flags: u64) -> u64 {
    let mut name = [0u8; 257];
    let n = match copy_user_path(path, &mut name) {
        Ok(n) => n,
        Err(e) => return e,
    };
    let (cb, cn) = match user::canon_path(dirfd, &name[..n]) {
        Ok(x) => x,
        Err(e) => return e,
    };
    user::newfstatat(&cb[..cn], statbuf, flags & 0x100 != 0)
}

/// fstatat64(dirfd, path, statbuf, flags) for i386 — getname+canon
/// then the stat64 shim. A NULL path is legal only with AT_EMPTY_PATH
/// (glibc's fstat reaches here that way).
fn sys_fstatat64(dirfd: u64, path: u64, statbuf: u64, flags: u64) -> u64 {
    if path == 0 {
        if flags & 0x1000 == 0 {
            return EFAULT;
        }
        return user::newfstatat32(dirfd, &[], statbuf, flags);
    }
    let mut name = [0u8; 257];
    let n = match copy_user_path(path, &mut name) {
        Ok(n) => n,
        Err(e) => return e,
    };
    if n == 0 {
        return user::newfstatat32(dirfd, &[], statbuf, flags);
    }
    let (cb, cn) = match user::canon_path(dirfd, &name[..n]) {
        Ok(x) => x,
        Err(e) => return e,
    };
    user::newfstatat32(dirfd, &cb[..cn], statbuf, flags)
}

/// statx(dirfd, path, flags, mask, statxbuf): the modern stat ABI —
/// 256-byte struct statx. Shares newfstatat's getname+canon
/// discipline and its metadata pipeline (fill_stat); AT_EMPTY_PATH
/// resolves through statx_dirfd_stat (FDCWD -> cwd, fd -> fstat).
/// Unknown AT_* flag bits are EINVAL like Linux; the STATX sync and
/// automount/removedir bits are accepted but inert on a flat VFS.
fn sys_statx(dirfd: u64, path: u64, flags: u64, mask: u64, statxbuf: u64) -> u64 {
    const AT_SYMLINK_NOFOLLOW: u64 = 0x100;
    const AT_REMOVEDIR: u64 = 0x200;
    const AT_SYMLINK_FOLLOW: u64 = 0x400;
    const AT_NO_AUTOMOUNT: u64 = 0x800;
    const AT_EMPTY_PATH: u64 = 0x1000;
    const AT_STATX_SYNC: u64 = 0x6000;
    const KNOWN: u64 = AT_SYMLINK_NOFOLLOW
        | AT_REMOVEDIR
        | AT_SYMLINK_FOLLOW
        | AT_NO_AUTOMOUNT
        | AT_EMPTY_PATH
        | AT_STATX_SYNC;
    if flags & !KNOWN != 0 {
        return EINVAL;
    }
    let nofollow = flags & AT_SYMLINK_NOFOLLOW != 0;
    let mut name = [0u8; 257];
    let n = match copy_user_path(path, &mut name) {
        Ok(n) => n,
        Err(e) => return e,
    };
    let st = if n == 0 {
        if flags & AT_EMPTY_PATH == 0 {
            return ENOENT;
        }
        match user::statx_dirfd_stat(dirfd, nofollow) {
            Ok(s) => s,
            Err(e) => return e,
        }
    } else {
        let (cb, cn) = match user::canon_path(dirfd, &name[..n]) {
            Ok(x) => x,
            Err(e) => return e,
        };
        match user::fill_stat(&cb[..cn], nofollow) {
            Ok(s) => s,
            Err(e) => return e,
        }
    };
    user::statx_emit(&st, mask, statxbuf)
}

/// inotify_add_watch(fd, path, mask): canon like open's getname.
fn sys_inotify_add(fd: u64, path: u64, mask: u64) -> u64 {
    let mut name = [0u8; 257];
    let n = match copy_user_path(path, &mut name) {
        Ok(n) => n,
        Err(e) => return e,
    };
    let (cb, cn) = match user::canon_path(u64::MAX, &name[..n]) {
        Ok(x) => x,
        Err(e) => return e,
    };
    user::inotify_add_watch(fd, &cb[..cn], mask as u32)
}

fn sys_open(path: u64, flags: u64, mode: u64) -> u64 {
    sys_openat(u64::MAX, path, flags, mode)
}

/// openat(dirfd, path, flags, mode): AT_FDCWD(-100) or an absolute
/// path resolves in the flat archive; any other dirfd must name a
/// Dir OFD — since there is exactly one directory, a valid dirfd
/// resolves the same way, and a non-dir dirfd is ENOTDIR like Linux.
/// openat(dirfd, path, flags, mode): dirfd validation + cwd join
/// happen inside canon_path — AT_FDCWD or absolute resolve against
/// cwd/root, a real dirfd against the dir it names (EBADF bad fd,
/// ENOTDIR non-dir). The canonical flat name feeds fd_open.
fn sys_openat(dirfd: u64, path: u64, flags: u64, mode: u64) -> u64 {
    let mut name = [0u8; 257];
    let n = match copy_user_path(path, &mut name) {
        Ok(n) => n,
        Err(e) => return e,
    };
    let (cb, cn) = match user::canon_path(dirfd, &name[..n]) {
        Ok(x) => x,
        Err(e) => return e,
    };
    user::fd_open(&cb[..cn], flags, mode)
}

/// openat2(dirfd, path, how, size): read the 24-byte open_how
/// {flags, mode, resolve}; size < 24 EINVALs, > PAGE_SIZE E2BIGs,
/// and a longer struct must carry an all-zero tail (the same
/// forward-compat rule clone3 applies). Everything after the
/// struct read is fd_openat2's resolve-scoped walk in user.rs.
fn sys_openat2(dirfd: u64, path: u64, how: u64, size: u64) -> u64 {
    const E2BIG_: u64 = (-7i64) as u64;
    const EFAULT_: u64 = (-14i64) as u64;
    if size < 24 {
        return EINVAL;
    }
    if size > 4096 {
        return E2BIG_;
    }
    if !user::range_ok(how, size) {
        return EFAULT_;
    }
    for i in 24..size {
        if unsafe { ((how + i) as *const u8).read_unaligned() } != 0 {
            return E2BIG_;
        }
    }
    // SAFETY: how range validated readable above.
    let (flags, mode, resolve) = unsafe {
        (
            (how as *const u64).read_unaligned(),
            ((how + 8) as *const u64).read_unaligned(),
            ((how + 16) as *const u64).read_unaligned(),
        )
    };
    let mut name = [0u8; 257];
    let n = match copy_user_path(path, &mut name) {
        Ok(n) => n,
        Err(e) => return e,
    };
    user::fd_openat2(dirfd, &name[..n], flags, mode, resolve)
}

/// execve(path, argv, envp): resolve the name in the initrd, verify it
/// is a loadable ELF BEFORE touching the address space, then let
/// user::exec rebuild it — including the real initial stack
/// (argc/argv/envp/auxv) that ELF entry code reads at [rsp]
/// (CVE-2022-49264's argv==NULL discipline: argc=0 gets the binary
/// name as argv0, matching what glibc launchers always produce).
fn sys_execve(ctx: &mut user::UCtx, path: u64, argv: u64, envp: u64) -> u64 {
    sys_execveat(ctx, u64::MAX, path, argv, envp, 0)
}

/// execveat(dirfd, path, argv, envp, flags): dirfd resolves a
/// relative path exactly like openat (canon_path's Dir-OFD base).
/// AT_EMPTY_PATH + an empty path execs the file dirfd names —
/// resolved through the fd's /proc link target (real path for
/// file OFDs, anonymous names → ENOENT). AT_SYMLINK_NOFOLLOW skips the
/// link-follow step — a flat-VFS link body then fails ELF parse
/// and reports ENOEXEC, matching Linux's refuse-to-follow.
fn sys_execveat(
    ctx: &mut user::UCtx,
    dirfd: u64,
    path: u64,
    argv: u64,
    envp: u64,
    flags: u64,
) -> u64 {
    const EINVAL_: u64 = (-22i64) as u64;
    const EBADF_: u64 = (-9i64) as u64;
    const ENOENT_: u64 = (-2i64) as u64;
    const AT_SYMLINK_NOFOLLOW: u64 = 0x100;
    const AT_EMPTY_PATH: u64 = 0x1000;
    if flags & !(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH) != 0 {
        return EINVAL_;
    }
    let mut name = [0u8; 257];
    let n = match copy_user_path(path, &mut name) {
        Ok(n) => n,
        Err(e) => return e,
    };
    let mut fdname = [0u8; 160];
    let (cb, cn) = if n == 0 {
        if flags & AT_EMPTY_PATH == 0 {
            return ENOENT_;
        }
        let d = dirfd as u32 as i32;
        if d < 0 || !user::fd_is_open(d as u64) {
            return EBADF_;
        }
        // The fd's own link target — the real path for File/Ram
        // OFDs (stats with the real mode, so the EACCES exec-bit
        // check below sees the file's own bits); anonymous kinds
        // ("pipe:[0]") miss at fs_lookup → ENOENT.
        let Some(pl) = user::fd_link_target(d, &mut fdname) else {
            return EBADF_;
        };
        match user::canon_path(u64::MAX, &fdname[..pl]) {
            Ok(x) => x,
            Err(e) => return e,
        }
    } else {
        match user::canon_path(dirfd, &name[..n]) {
            Ok(x) => x,
            Err(e) => return e,
        }
    };
    // execve follows links — the image under the resolved name is
    // what runs; an unresolvable chain reports its error (ELOOP/...).
    // AT_SYMLINK_NOFOLLOW takes the literal canonical name.
    let (rb, rn, _) = if flags & AT_SYMLINK_NOFOLLOW != 0 {
        (cb, cn, false)
    } else {
        match user::resolve_links(&cb[..cn], true) {
            Ok(x) => x,
            Err(e) => return e,
        }
    };
    let name = &rb[..rn];
    // A regular file with no exec bit is EACCES even for root —
    // this is the check dpkg's helper probe actually reads.
    if let Ok(st) = user::fill_stat(name, false) {
        if st[3] & 0o170000 == 0o100000 && st[3] & 0o111 == 0 {
            return (-13i64) as u64; // EACCES
        }
    }
    // #! scripts: exec the interpreter and hand it the script path as
    // its first argument. Without this an installed init cannot run
    // /etc/rcS (busybox reports "can't run ... No such file").
    let mut had_shebang = false;
    let mut script = [0u8; 128];
    let mut script_len = 0usize;
    let mut interp = [0u8; 128];
    let mut interp_len = 0usize;
    let mut lname = [0u8; 128];
    let mut lname_len = name.len().min(127);
    lname[..lname_len].copy_from_slice(&name[..lname_len]);
    {
        let mut cur = &lname[..lname_len];
        for _ in 0..4 {
            let Some(body) = user::fs_lookup(cur) else {
                return ENOENT;
            };
            if body.starts_with(b"#!") {
                // Interpreter path: everything after "#!" up to space or
                // newline.
                let mut i = 2usize;
                while i < body.len() && (body[i] == b' ') {
                    i += 1;
                }
                let start = i;
                while i < body.len() && body[i] != b' ' && body[i] != b'\n' && i - start < 127 {
                    i += 1;
                }
                if i == start {
                    return ENOEXEC;
                }
                interp[..i - start].copy_from_slice(&body[start..i]);
                interp_len = i - start;
                had_shebang = true;
                if script_len == 0 {
                    let n2 = cur.len().min(127);
                    script[..n2].copy_from_slice(&cur[..n2]);
                    script_len = n2;
                }
                // The interpreter may itself be a link ("bin/sh" ->
                // /bin/busybox), so follow it before looking for an
                // ELF; reading the link's target text as an image is
                // what made exec report ENOENT. A shebang names an
                // absolute path ("/bin/sh"), but the namespace is
                // canonical slashless — strip it first or every
                // component lookup misses and the script exec fails.
                if interp_len > 0 && interp[0] == b'/' {
                    interp.copy_within(1..interp_len, 0);
                    interp_len -= 1;
                }
                let resolved = match user::resolve_links(&interp[..interp_len], true) {
                    Ok((b2, n2, _)) => {
                        lname_len = n2.min(127);
                        lname[..lname_len].copy_from_slice(&b2[..lname_len]);
                        true
                    }
                    Err(_) => {
                        lname_len = interp_len.min(127);
                        lname[..lname_len].copy_from_slice(&interp[..lname_len]);
                        false
                    }
                };
                let _ = resolved;
                cur = &lname[..lname_len];
                continue;
            }
            break;
        }
        if elf::parse(user::fs_lookup(&lname[..lname_len]).unwrap_or(&[])).is_none() {
            return ENOEXEC;
        }
    }
    let name = &lname[..lname_len];
    let Some(img) = user::fs_lookup(name) else {
        return ENOENT;
    };
    // Parse before reset: a bad image must not cost the task its
    // address space — Linux returns ENOEXEC and the process lives.
    if elf::parse(img).is_none() {
        return ENOEXEC;
    }
    // Copy argv/envp out of the OLD address space before exec tears
    // it down — collect_exec_args gate-checks every slot and string.
    let args = user::exec_args_scratch();
    let r = user::collect_exec_args(argv, envp, args);
    if r != 0 {
        return r;
    }
    if args.argc == 0 {
        let n = name.len().min(user::EXEC_STR_CAP - 1);
        args.argv[0][..n].copy_from_slice(&name[..n]);
        args.argv_len[0] = n + 1;
        args.argc = 1;
    }
    if had_shebang && script_len > 0 {
        // Linux rewrites argv to [interp, script, original argv[1..]]:
        // the interpreter is argv[0] (busybox picks its applet from it)
        // and the script is argv[1].
        let max = user::MAX_EXEC_ARGS.min(args.argc + 1);
        let mut i = max;
        while i > 1 {
            i -= 1;
            args.argv[i] = args.argv[i - 1];
            args.argv_len[i] = args.argv_len[i - 1];
        }
        // argv[0] is the shebang's interpreter name, not the resolved
        // image — busybox picks its applet from it ("sh" here; the
        // resolved "bin/busybox" would dispatch on the script path).
        let base = interp[..interp_len]
            .iter()
            .rposition(|&c| c == b'/')
            .map(|p| p + 1)
            .unwrap_or(0);
        let bn = (interp_len - base).min(user::EXEC_STR_CAP - 2);
        args.argv[0][..bn].copy_from_slice(&interp[base..base + bn]);
        args.argv[0][bn] = 0; // shorter name over a longer old arg —
                            // the tail byte is not NUL by accident
        args.argv_len[0] = bn + 1;
        let sn = script_len.min(user::EXEC_STR_CAP - 2);
        args.argv[1][..sn].copy_from_slice(&script[..sn]);
        args.argv[1][sn] = 0;
        args.argv_len[1] = sn + 1;
        args.argc = max;
    }
    if !user::exec(img, ctx, args, name) {
        // The address space is already torn down; the task cannot
        // safely resume. Kill it — the run() loop reaps as usual.
        sys_exit(127);
    }
    0 // unreachable on success — sysret lands in the new image
}

/// stat/lstat(path, statbuf): same lookup and writer as newfstatat;
/// `nofollow` makes lstat report links themselves where they exist
/// (the proc link family — the flat archive has none).
fn sys_stat_path(path: u64, statbuf: u64, nofollow: bool) -> u64 {
    let mut name = [0u8; 257];
    let n = match copy_user_path(path, &mut name) {
        Ok(n) => n,
        Err(e) => return e,
    };
    let (cb, cn) = match user::canon_path(u64::MAX, &name[..n]) {
        Ok(x) => x,
        Err(e) => return e,
    };
    user::newfstatat(&cb[..cn], statbuf, nofollow)
}

/// statfs(path, buf): canon the path, ENOENT on a miss, then the
/// per-fs fill — /proc reports procfs, everything else ramfs.
fn sys_statfs(path: u64, buf: u64) -> u64 {
    let mut name = [0u8; 257];
    let n = match copy_user_path(path, &mut name) {
        Ok(n) => n,
        Err(e) => return e,
    };
    let (cb, cn) = match user::canon_path(u64::MAX, &name[..n]) {
        Ok(x) => x,
        Err(e) => return e,
    };
    user::statfs_path(&cb[..cn], buf)
}

/// access/faccessat(path, mode): existence plus real mode checks.
/// Root bypasses R/W permission bits (CAP_DAC_OVERRIDE); the one
/// check even root can't skip is X_OK on a file with no exec bit.
/// faccessat's flags arg is ignored — AT_SYMLINK_NOFOLLOW is the
/// only defined bit and our resolution follows links anyway.
fn sys_access(dirfd: u64, path: u64, mode: u64) -> u64 {
    let mut name = [0u8; 257];
    let n = match copy_user_path(path, &mut name) {
        Ok(n) => n,
        Err(e) => return e,
    };
    let (cb, cn) = match user::canon_path(dirfd, &name[..n]) {
        Ok(x) => x,
        Err(e) => return e,
    };
    // access follows links — the question is about the target.
    let (rb, rn, _) = match user::resolve_links(&cb[..cn], true) {
        Ok(x) => x,
        Err(e) => return e,
    };
    const X_OK: u64 = 1;
    const W_OK: u64 = 2;
    const EACCES_: u64 = (-13i64) as u64;
    let st = match user::fill_stat(&rb[..rn], false) {
        Ok(s) => s,
        Err(e) => return e,
    };
    let m = st[3];
    if m & 0o170000 != 0o100000 {
        return 0; // dirs/links/devs: searchable, writable by root
    }
    if mode & X_OK != 0 && m & 0o111 == 0 {
        return EACCES_;
    }
    // W_OK: the archive is a read-only namespace — MAY_WRITE on
    // an ro mount is EROFS like Linux. RAM files answer by their
    // write bits (root already bypassed the R/X questions above,
    // but even root can't write a file with no write bits anywhere
    // — the mode check stands for both).
    if mode & W_OK != 0 {
        if user::fs_is_archive(&rb[..rn]) {
            return (-30i64) as u64; // EROFS
        }
        if m & 0o222 == 0 {
            return EACCES_;
        }
    }
    0
}

/// unlink/unlinkat(dirfd, path, flags): one flat directory, so dirfd
/// is ABI-shape (FDCWD or a dir fd — same resolution either way).
/// flags with AT_REMOVEDIR → EISDIR here; rmdir doesn't exist yet.
/// unlink/unlinkat(dirfd, path, flags): AT_REMOVEDIR routes to
/// fs_rmdir; anything else nonzero EINVALs. canon_path does the
/// dirfd validation and cwd join.
/// linkat(olddirfd, old, newdirfd, new, flags): each side
/// canonicalizes against its own dirfd like renameat2; flags pass
/// through for AT_SYMLINK_FOLLOW validation in the fs layer.
fn sys_linkat(odfd: u64, old: u64, ndfd: u64, new: u64, flags: u64) -> u64 {
    let mut op = [0u8; 257];
    let on = match copy_user_path(old, &mut op) {
        Ok(n) => n,
        Err(e) => return e,
    };
    let mut np = [0u8; 257];
    let nn = match copy_user_path(new, &mut np) {
        Ok(n) => n,
        Err(e) => return e,
    };
    let (ob, ocn) = match user::canon_path(odfd, &op[..on]) {
        Ok(x) => x,
        Err(e) => return e,
    };
    let (nb, ncn) = match user::canon_path(ndfd, &np[..nn]) {
        Ok(x) => x,
        Err(e) => return e,
    };
    user::fs_linkat(&ob[..ocn], &nb[..ncn], flags)
}

fn sys_unlinkat(dirfd: u64, path: u64, flags: u64) -> u64 {
    const AT_REMOVEDIR: u64 = 0x200;
    if flags & !(AT_REMOVEDIR) != 0 {
        return EINVAL;
    }
    let mut name = [0u8; 257];
    let n = match copy_user_path(path, &mut name) {
        Ok(n) => n,
        Err(e) => return e,
    };
    if flags & AT_REMOVEDIR != 0 {
        return user::fs_rmdir(dirfd, &name[..n]);
    }
    let (cb, cn) = match user::canon_path(dirfd, &name[..n]) {
        Ok(x) => x,
        Err(e) => return e,
    };
    user::fs_unlink(&cb[..cn])
}

/// renameat2(olddirfd, old, newdirfd, new, flags): flat namespace —
/// both dirfds only gate on dir-ness like openat's; nonzero flags
/// (RENAME_EXCHANGE/NOREPLACE/WHITEOUT) are EINVAL, renameat passes 0.
/// renameat2(olddirfd, old, newdirfd, new, flags): each path
/// canonicalizes against its own dirfd; nonzero flags EINVAL.
fn sys_renameat2(odfd: u64, old: u64, ndfd: u64, new: u64, flags: u64) -> u64 {
    // RENAME_NOREPLACE(1) is honored; EXCHANGE/WHITEOUT need fs
    // machinery that doesn't exist — honest EINVAL like Linux's
    // unsupported-flag answer.
    if flags & !1 != 0 {
        return EINVAL;
    }
    let mut oname = [0u8; 257];
    let on = match copy_user_path(old, &mut oname) {
        Ok(n) => n,
        Err(e) => return e,
    };
    let mut nname = [0u8; 257];
    let nn = match copy_user_path(new, &mut nname) {
        Ok(n) => n,
        Err(e) => return e,
    };
    let (ob, oc) = match user::canon_path(odfd, &oname[..on]) {
        Ok(x) => x,
        Err(e) => return e,
    };
    let (nb, nc) = match user::canon_path(ndfd, &nname[..nn]) {
        Ok(x) => x,
        Err(e) => return e,
    };
    user::fs_rename(&ob[..oc], &nb[..nc], flags == 1)
}

/// truncate(path, len): getname then the shared VFile truncate.
fn sys_truncate(path: u64, len: u64) -> u64 {
    let mut name = [0u8; 257];
    let n = match copy_user_path(path, &mut name) {
        Ok(n) => n,
        Err(e) => return e,
    };
    let (cb, cn) = match user::canon_path(u64::MAX, &name[..n]) {
        Ok(x) => x,
        Err(e) => return e,
    };
    user::fs_truncate(&cb[..cn], len)
}

/// chdir(path): user string then the shared-table update.
fn sys_chdir(path: u64) -> u64 {
    let mut name = [0u8; 257];
    let n = match copy_user_path(path, &mut name) {
        Ok(n) => n,
        Err(e) => return e,
    };
    user::sys_chdir(&name[..n])
}

/// chroot(path): user string then the shared-table root update.
fn sys_chroot(path: u64) -> u64 {
    let mut name = [0u8; 257];
    let n = match copy_user_path(path, &mut name) {
        Ok(n) => n,
        Err(e) => return e,
    };
    user::sys_chroot(&name[..n])
}

/// acct(path): NULL disables — the empty slice is the kernel's
/// off-signal; otherwise the same copy-then-delegate flow.
fn sys_acct(path: u64) -> u64 {
    if path == 0 {
        return user::sys_acct(&[]);
    }
    let mut name = [0u8; 257];
    let n = match copy_user_path(path, &mut name) {
        Ok(n) => n,
        Err(e) => return e,
    };
    user::sys_acct(&name[..n])
}

/// mount(165): three user strings (source, target, fstype) then the
/// flags word; data is ignored (no fstype consumes it).
fn sys_mount(src: u64, tgt: u64, fstype: u64, flags: u64) -> u64 {
    let mut sb = [0u8; 257];
    let mut tb = [0u8; 257];
    let mut fb = [0u8; 257];
    let sn = match copy_user_path(src, &mut sb) {
        Ok(n) => n,
        Err(e) => return e,
    };
    let tn = match copy_user_path(tgt, &mut tb) {
        Ok(n) => n,
        Err(e) => return e,
    };
    let fn_ = match copy_user_path(fstype, &mut fb) {
        Ok(n) => n,
        Err(e) => return e,
    };
    user::sys_mount(&sb[..sn], &tb[..tn], &fb[..fn_], flags)
}

/// quotactl(179): user `special` path string; id/addr are opaque
/// to the quota-less surface (ESRCH after resolution anyway).
fn sys_quotactl(cmd: u64, special: u64, id: u64, addr: u64) -> u64 {
    let mut sb = [0u8; 257];
    let sn = match copy_user_path(special, &mut sb) {
        Ok(n) => n,
        Err(e) => return e,
    };
    user::sys_quotactl(cmd, &sb[..sn], id, addr)
}

/// umount2(166): user target string + flags word.
fn sys_umount2(tgt: u64, flags: u64) -> u64 {
    let mut tb = [0u8; 257];
    let tn = match copy_user_path(tgt, &mut tb) {
        Ok(n) => n,
        Err(e) => return e,
    };
    user::sys_umount2(&tb[..tn], flags)
}

/// pivot_root(155): two canonicalized user path strings.
fn sys_pivot_root(new_root: u64, put_old: u64) -> u64 {
    let mut nb = [0u8; 257];
    let mut ob = [0u8; 257];
    let nn = match copy_user_path(new_root, &mut nb) {
        Ok(n) => n,
        Err(e) => return e,
    };
    let on = match copy_user_path(put_old, &mut ob) {
        Ok(n) => n,
        Err(e) => return e,
    };
    user::sys_pivot_root(&nb[..nn], &ob[..on])
}

/// fsopen(430): fstype name string + flags.
fn sys_fsopen(name: u64, flags: u64) -> u64 {
    let mut nb = [0u8; 257];
    let n = match copy_user_path(name, &mut nb) {
        Ok(n) => n,
        Err(e) => return e,
    };
    user::sys_fsopen(&nb[..n], flags)
}

/// fsconfig(431): key/value strings — NULL maps to empty (SET_FLAG
/// passes key only; SET_EMPTY has no value).
fn sys_fsconfig(
    fd: u64, cmd: u64, key: u64, value: u64, aux: u64,
) -> u64 {
    let mut kb = [0u8; 257];
    let mut vb = [0u8; 257];
    let kn = if key == 0 {
        0
    } else {
        match copy_user_path(key, &mut kb) {
            Ok(n) => n,
            Err(e) => return e,
        }
    };
    let vn = if value == 0 {
        0
    } else {
        match copy_user_path(value, &mut vb) {
            Ok(n) => n,
            Err(e) => return e,
        }
    };
    user::sys_fsconfig(fd, cmd, &kb[..kn], &vb[..vn], aux)
}

/// open_tree(428): dirfd + possibly-NULL path (EMPTY_PATH) + flags.
fn sys_open_tree(dfd: u64, path: u64, flags: u64) -> u64 {
    let mut name = [0u8; 257];
    if path == 0 {
        return user::sys_open_tree(dfd, &name[..0], flags);
    }
    let n = match copy_user_path(path, &mut name) {
        Ok(n) => n,
        Err(e) => return e,
    };
    user::sys_open_tree(dfd, &name[..n], flags)
}

/// move_mount(429): two dirfd+path pairs, both NULL-tolerant under
/// their own *_EMPTY_PATH flag, plus the flag word.
fn sys_move_mount(
    fdfd: u64, fpath: u64, tdfd: u64, tpath: u64, flags: u64,
) -> u64 {
    let mut fb = [0u8; 257];
    let mut tb = [0u8; 257];
    let fn_ = if fpath == 0 {
        0
    } else {
        match copy_user_path(fpath, &mut fb) {
            Ok(n) => n,
            Err(e) => return e,
        }
    };
    let tn = if tpath == 0 {
        0
    } else {
        match copy_user_path(tpath, &mut tb) {
            Ok(n) => n,
            Err(e) => return e,
        }
    };
    user::sys_move_mount(fdfd, &fb[..fn_], tdfd, &tb[..tn], flags)
}

/// fspick(433): dirfd + possibly-NULL path (EMPTY_PATH) + flags.
fn sys_fspick(dfd: u64, path: u64, flags: u64) -> u64 {
    let mut name = [0u8; 257];
    if path == 0 {
        return user::sys_fspick(dfd, &name[..0], flags);
    }
    let n = match copy_user_path(path, &mut name) {
        Ok(n) => n,
        Err(e) => return e,
    };
    user::sys_fspick(dfd, &name[..n], flags)
}

/// mount_setattr(442): path + mount_attr user ptr + struct size.
fn sys_mount_setattr(
    dfd: u64, path: u64, flags: u64, attr: u64, size: u64,
) -> u64 {
    let mut name = [0u8; 257];
    if path == 0 {
        return user::sys_mount_setattr(dfd, &name[..0], flags, attr, size);
    }
    let n = match copy_user_path(path, &mut name) {
        Ok(n) => n,
        Err(e) => return e,
    };
    user::sys_mount_setattr(dfd, &name[..n], flags, attr, size)
}

/// name_to_handle_at(303): copy the path then delegate — the
/// handle/mount_id pointers stay userspace-side.
fn sys_name_to_handle_at(
    dirfd: u64, path: u64, handle: u64, mount_id: u64, flags: u64,
) -> u64 {
    let mut name = [0u8; 257];
    let n = match copy_user_path(path, &mut name) {
        Ok(n) => n,
        Err(e) => return e,
    };
    user::sys_name_to_handle_at(dirfd, &name[..n], handle, mount_id, flags)
}

/// mkdir/mkdirat(dirfd, path, mode): mode is the new dir's stored
/// permission bits after the caller's umask.
fn sys_mkdirat(dirfd: u64, path: u64, mode: u64) -> u64 {
    let mut name = [0u8; 257];
    let n = match copy_user_path(path, &mut name) {
        Ok(n) => n,
        Err(e) => return e,
    };
    user::fs_mkdir(dirfd, &name[..n], mode)
}

/// mknodat(dirfd, path, mode, dev): canon inside fs_mknod.
fn sys_mknodat(dirfd: u64, path: u64, mode: u64, dev: u64) -> u64 {
    let mut name = [0u8; 257];
    let n = match copy_user_path(path, &mut name) {
        Ok(n) => n,
        Err(e) => return e,
    };
    user::fs_mknod(dirfd, &name[..n], mode, dev)
}

/// rmdir(path): cwd-relative — canon inside fs_rmdir.
fn sys_rmdir(path: u64) -> u64 {
    let mut name = [0u8; 257];
    let n = match copy_user_path(path, &mut name) {
        Ok(n) => n,
        Err(e) => return e,
    };
    user::fs_rmdir(u64::MAX, &name[..n])
}

/// readlink(path, buf, len): canon then the shared link core —
/// VFile links report their stored target, proc magic links theirs,
/// a non-link EINVALs and a miss ENOENTs like Linux.
fn sys_readlink(path: u64, buf: u64, len: u64) -> u64 {
    let mut name = [0u8; 257];
    let n = match copy_user_path(path, &mut name) {
        Ok(n) => n,
        Err(e) => return e,
    };
    let (cb, cn) = match user::canon_path(u64::MAX, &name[..n]) {
        Ok(x) => x,
        Err(e) => return e,
    };
    user::fs_readlink(&cb[..cn], buf, len)
}

/// readlinkat(dirfd, path, buf, len): canon resolves dirfd/cwd, then
/// the same link core answers.
fn sys_readlinkat(dirfd: u64, path: u64, buf: u64, len: u64) -> u64 {
    let mut name = [0u8; 257];
    let n = match copy_user_path(path, &mut name) {
        Ok(n) => n,
        Err(e) => return e,
    };
    let (cb, cn) = match user::canon_path(dirfd, &name[..n]) {
        Ok(x) => x,
        Err(e) => return e,
    };
    user::fs_readlink(&cb[..cn], buf, len)
}

/// symlink(target, linkpath): cwd-relative — canon inside fs_symlink.
fn sys_symlink(target: u64, linkpath: u64) -> u64 {
    let mut tp = [0u8; 257];
    let tn = match copy_user_path(target, &mut tp) {
        Ok(n) => n,
        Err(e) => return e,
    };
    let mut lp = [0u8; 257];
    let ln = match copy_user_path(linkpath, &mut lp) {
        Ok(n) => n,
        Err(e) => return e,
    };
    user::fs_symlink(u64::MAX, &tp[..tn], &lp[..ln])
}

/// symlinkat(target, dirfd, linkpath): dirfd canon inside fs_symlink.
fn sys_symlinkat(target: u64, dirfd: u64, linkpath: u64) -> u64 {
    let mut tp = [0u8; 257];
    let tn = match copy_user_path(target, &mut tp) {
        Ok(n) => n,
        Err(e) => return e,
    };
    let mut lp = [0u8; 257];
    let ln = match copy_user_path(linkpath, &mut lp) {
        Ok(n) => n,
        Err(e) => return e,
    };
    user::fs_symlink(dirfd, &tp[..tn], &lp[..ln])
}

/// chmod(path, mode): canon then the resolved-name chmod — the
/// final link follows like Linux (no lchmod exists).
fn sys_chmod(path: u64, mode: u64) -> u64 {
    let mut name = [0u8; 257];
    let n = match copy_user_path(path, &mut name) {
        Ok(n) => n,
        Err(e) => return e,
    };
    let (cb, cn) = match user::canon_path(u64::MAX, &name[..n]) {
        Ok(x) => x,
        Err(e) => return e,
    };
    user::fs_chmod(&cb[..cn], mode, false)
}

/// fchmodat(dirfd, path, mode): the x86_64 ABI takes no flags arg —
/// fchmodat2's AT_SYMLINK_NOFOLLOW isn't in this number.
fn sys_fchmodat(dirfd: u64, path: u64, mode: u64) -> u64 {
    let mut name = [0u8; 257];
    let n = match copy_user_path(path, &mut name) {
        Ok(n) => n,
        Err(e) => return e,
    };
    let (cb, cn) = match user::canon_path(dirfd, &name[..n]) {
        Ok(x) => x,
        Err(e) => return e,
    };
    user::fs_chmod(&cb[..cn], mode, false)
}

/// fchmodat2(dirfd, path, mode, flags): fchmodat plus flag
/// support — AT_SYMLINK_NOFOLLOW acts on the link itself (the
/// lchmod shape), AT_EMPTY_PATH with an empty path acts on the
/// dirfd's own inode like fchmod. Unknown bits EINVAL.
fn sys_fchmodat2(dirfd: u64, path: u64, mode: u64, flags: u64) -> u64 {
    const AT_SYMLINK_NOFOLLOW: u64 = 0x100;
    const AT_EMPTY_PATH: u64 = 0x1000;
    if flags & !(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH) != 0 {
        return EINVAL;
    }
    let mut name = [0u8; 257];
    let n = match copy_user_path(path, &mut name) {
        Ok(n) => n,
        Err(e) => return e,
    };
    if n == 0 {
        return if flags & AT_EMPTY_PATH != 0 {
            user::fd_chmod(dirfd, mode)
        } else {
            ENOENT
        };
    }
    let (cb, cn) = match user::canon_path(dirfd, &name[..n]) {
        Ok(x) => x,
        Err(e) => return e,
    };
    user::fs_chmod(&cb[..cn], mode, flags & AT_SYMLINK_NOFOLLOW != 0)
}


/// copy_user_name: an xattr name is a bounded C string, not a path —
/// >255 bytes ERANGEs like Linux instead of ENAMETOOLONG.
fn copy_user_name(p: u64, name: &mut [u8; 256]) -> Result<usize, u64> {
    const ERANGE_: u64 = (-34i64) as u64;
    const EFAULT_: u64 = (-14i64) as u64;
    let mut n = 0usize;
    loop {
        if n == 256 {
            return Err(ERANGE_);
        }
        if !user::range_ok(p + n as u64, 1) {
            return Err(EFAULT_);
        }
        // SAFETY: range_ok proved this byte is inside a mapped range.
        let b = unsafe { *((p + n as u64) as *const u8) };
        if b == 0 {
            return Ok(n);
        }
        name[n] = b;
        n += 1;
    }
}

/// Shared path+name resolve for the path-form xattr calls:
/// `follow` splits setxattr from lsetxattr (final link kept).
fn xattr_path(path: u64, name: u64, follow: bool) -> Result<(usize, [u8; 256], usize), u64> {
    let mut pbuf = [0u8; 257];
    let pn = copy_user_path(path, &mut pbuf)?;
    let vfi = user::xattr_vfi(u64::MAX, &pbuf[..pn], follow)?;
    let mut nb = [0u8; 256];
    let nn = copy_user_name(name, &mut nb)?;
    Ok((vfi, nb, nn))
}

fn sys_setxattr(path: u64, name: u64, value: u64, size: u64, flags: u64) -> u64 {
    match xattr_path(path, name, true) {
        Ok((vfi, nb, nn)) => user::fs_setxattr(vfi, &nb[..nn], value, size, flags),
        Err(e) => e,
    }
}

fn sys_lsetxattr(path: u64, name: u64, value: u64, size: u64, flags: u64) -> u64 {
    match xattr_path(path, name, false) {
        Ok((vfi, nb, nn)) => user::fs_setxattr(vfi, &nb[..nn], value, size, flags),
        Err(e) => e,
    }
}

fn sys_fsetxattr(fd: u64, name: u64, value: u64, size: u64, flags: u64) -> u64 {
    let mut nb = [0u8; 256];
    let nn = match copy_user_name(name, &mut nb) {
        Ok(n) => n,
        Err(e) => return e,
    };
    match user::fd_xattr_vfi(fd) {
        Ok(vfi) => user::fs_setxattr(vfi, &nb[..nn], value, size, flags),
        Err(e) => e,
    }
}

fn sys_getxattr(path: u64, name: u64, value: u64, size: u64) -> u64 {
    match xattr_path(path, name, true) {
        Ok((vfi, nb, nn)) => user::fs_getxattr(vfi, &nb[..nn], value, size),
        Err(e) => e,
    }
}

fn sys_lgetxattr(path: u64, name: u64, value: u64, size: u64) -> u64 {
    match xattr_path(path, name, false) {
        Ok((vfi, nb, nn)) => user::fs_getxattr(vfi, &nb[..nn], value, size),
        Err(e) => e,
    }
}

fn sys_fgetxattr(fd: u64, name: u64, value: u64, size: u64) -> u64 {
    let mut nb = [0u8; 256];
    let nn = match copy_user_name(name, &mut nb) {
        Ok(n) => n,
        Err(e) => return e,
    };
    match user::fd_xattr_vfi(fd) {
        Ok(vfi) => user::fs_getxattr(vfi, &nb[..nn], value, size),
        Err(e) => e,
    }
}

fn sys_listxattr(path: u64, list: u64, size: u64) -> u64 {
    let mut pbuf = [0u8; 257];
    let pn = match copy_user_path(path, &mut pbuf) {
        Ok(n) => n,
        Err(e) => return e,
    };
    match user::xattr_vfi(u64::MAX, &pbuf[..pn], true) {
        Ok(vfi) => user::fs_listxattr(vfi, list, size),
        Err(e) => e,
    }
}

fn sys_llistxattr(path: u64, list: u64, size: u64) -> u64 {
    let mut pbuf = [0u8; 257];
    let pn = match copy_user_path(path, &mut pbuf) {
        Ok(n) => n,
        Err(e) => return e,
    };
    match user::xattr_vfi(u64::MAX, &pbuf[..pn], false) {
        Ok(vfi) => user::fs_listxattr(vfi, list, size),
        Err(e) => e,
    }
}

fn sys_flistxattr(fd: u64, list: u64, size: u64) -> u64 {
    match user::fd_xattr_vfi(fd) {
        Ok(vfi) => user::fs_listxattr(vfi, list, size),
        Err(e) => e,
    }
}

fn sys_removexattr(path: u64, name: u64) -> u64 {
    match xattr_path(path, name, true) {
        Ok((vfi, nb, nn)) => user::fs_removexattr(vfi, &nb[..nn]),
        Err(e) => e,
    }
}

fn sys_lremovexattr(path: u64, name: u64) -> u64 {
    match xattr_path(path, name, false) {
        Ok((vfi, nb, nn)) => user::fs_removexattr(vfi, &nb[..nn]),
        Err(e) => e,
    }
}

fn sys_fremovexattr(fd: u64, name: u64) -> u64 {
    let mut nb = [0u8; 256];
    let nn = match copy_user_name(name, &mut nb) {
        Ok(n) => n,
        Err(e) => return e,
    };
    match user::fd_xattr_vfi(fd) {
        Ok(vfi) => user::fs_removexattr(vfi, &nb[..nn]),
        Err(e) => e,
    }
}


/// struct xattr_args { u64 value; u32 size; u32 flags } — the
/// extensible packer setxattrat/getxattrat use for arg 5+6.
/// copy_struct_from_user discipline: usize below VER0 (16) EINVAL,
/// past a page E2BIG, and any nonzero tail past our 16 is E2BIG.
fn copy_xattr_args(uargs: u64, usize_: u64) -> Result<(u64, u32, u32), u64> {
    const E2BIG_: u64 = (-7i64) as u64;
    if usize_ < 16 {
        return Err(EINVAL);
    }
    if usize_ > 4096 {
        return Err(E2BIG_);
    }
    if !user::range_ok(uargs, usize_) {
        return Err(EFAULT);
    }
    // SAFETY: range_ok proved the window under the caller's cr3.
    let (value, size, flags) = unsafe {
        (
            *(uargs as *const u64),
            *((uargs + 8) as *const u32),
            *((uargs + 12) as *const u32),
        )
    };
    for i in 16..usize_ {
        // SAFETY: same validated window.
        if unsafe { *((uargs + i) as *const u8) } != 0 {
            return Err(E2BIG_);
        }
    }
    Ok((value, size, flags))
}

/// Shared dfd/path/at_flags resolution for the xattrat family:
/// EMPTY_PATH on an empty-or-NULL path operates on dfd's own file;
/// NOFOLLOW keeps the final link like the l* forms.
fn xattrat_vfi(dfd: u64, path: u64, at_flags: u64) -> Result<usize, u64> {
    const AT_EMPTY_PATH: u64 = 0x1000;
    const AT_SYMLINK_NOFOLLOW: u64 = 0x100;
    const EFAULT_: u64 = (-14i64) as u64;
    if at_flags & AT_EMPTY_PATH != 0 {
        let empty = if path == 0 {
            true
        } else {
            if !user::range_ok(path, 1) {
                return Err(EFAULT_);
            }
            // SAFETY: range_ok proved the byte.
            unsafe { *(path as *const u8) == 0 }
        };
        if empty {
            return user::fd_xattr_vfi(dfd);
        }
    }
    let mut pbuf = [0u8; 257];
    let pn = copy_user_path(path, &mut pbuf)?;
    user::xattr_vfi(dfd, &pbuf[..pn], at_flags & AT_SYMLINK_NOFOLLOW == 0)
}

fn xattrat_flags_ok(at_flags: u64) -> bool {
    at_flags & !(0x100 | 0x1000) == 0 // NOFOLLOW | EMPTY_PATH only
}

fn sys_setxattrat(
    dfd: u64,
    path: u64,
    at_flags: u64,
    name: u64,
    uargs: u64,
    usize_: u64,
) -> u64 {
    if !xattrat_flags_ok(at_flags) {
        return EINVAL;
    }
    let (value, size, flags) = match copy_xattr_args(uargs, usize_) {
        Ok(x) => x,
        Err(e) => return e,
    };
    let mut nb = [0u8; 256];
    let nn = match copy_user_name(name, &mut nb) {
        Ok(n) => n,
        Err(e) => return e,
    };
    match xattrat_vfi(dfd, path, at_flags) {
        Ok(vfi) => user::fs_setxattr(vfi, &nb[..nn], value, size as u64, flags as u64),
        Err(e) => e,
    }
}

fn sys_getxattrat(
    dfd: u64,
    path: u64,
    at_flags: u64,
    name: u64,
    uargs: u64,
    usize_: u64,
) -> u64 {
    if !xattrat_flags_ok(at_flags) {
        return EINVAL;
    }
    let (value, size, flags) = match copy_xattr_args(uargs, usize_) {
        Ok(x) => x,
        Err(e) => return e,
    };
    if flags != 0 {
        return EINVAL;
    }
    let mut nb = [0u8; 256];
    let nn = match copy_user_name(name, &mut nb) {
        Ok(n) => n,
        Err(e) => return e,
    };
    match xattrat_vfi(dfd, path, at_flags) {
        Ok(vfi) => user::fs_getxattr(vfi, &nb[..nn], value, size as u64),
        Err(e) => e,
    }
}

fn sys_listxattrat(dfd: u64, path: u64, at_flags: u64, list: u64, size: u64) -> u64 {
    if !xattrat_flags_ok(at_flags) {
        return EINVAL;
    }
    match xattrat_vfi(dfd, path, at_flags) {
        Ok(vfi) => user::fs_listxattr(vfi, list, size),
        Err(e) => e,
    }
}

fn sys_removexattrat(dfd: u64, path: u64, at_flags: u64, name: u64) -> u64 {
    if !xattrat_flags_ok(at_flags) {
        return EINVAL;
    }
    let mut nb = [0u8; 256];
    let nn = match copy_user_name(name, &mut nb) {
        Ok(n) => n,
        Err(e) => return e,
    };
    match xattrat_vfi(dfd, path, at_flags) {
        Ok(vfi) => user::fs_removexattr(vfi, &nb[..nn]),
        Err(e) => e,
    }
}

/// chown/lchown(dirfd-less and dirfd variants share this): canon
/// then fs_chown — `nofollow` is the lchown/AT_SYMLINK_NOFOLLOW
/// split, acting on the link itself.
fn sys_chown_path(dirfd: u64, path: u64, uid: u64, gid: u64, nofollow: bool) -> u64 {
    let mut name = [0u8; 257];
    let n = match copy_user_path(path, &mut name) {
        Ok(n) => n,
        Err(e) => return e,
    };
    let (cb, cn) = match user::canon_path(dirfd, &name[..n]) {
        Ok(x) => x,
        Err(e) => return e,
    };
    user::fs_chown(&cb[..cn], uid, gid, nofollow)
}

/// fchownat(dirfd, path, uid, gid, flags): AT_SYMLINK_NOFOLLOW and
/// AT_EMPTY_PATH only — an empty path with EMPTY_PATH operates on
/// the dirfd's own inode like Linux.
fn sys_fchownat(dirfd: u64, path: u64, uid: u64, gid: u64, flags: u64) -> u64 {
    const AT_SYMLINK_NOFOLLOW: u64 = 0x100;
    const AT_EMPTY_PATH: u64 = 0x1000;
    if flags & !(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH) != 0 {
        return EINVAL;
    }
    let mut name = [0u8; 257];
    let n = match copy_user_path(path, &mut name) {
        Ok(n) => n,
        Err(e) => return e,
    };
    if n == 0 && flags & AT_EMPTY_PATH != 0 {
        return user::fd_chown(dirfd, uid, gid);
    }
    sys_chown_path(dirfd, path, uid, gid, flags & AT_SYMLINK_NOFOLLOW != 0)
}

/// utime(path, times): utimbuf {actime,modtime} seconds pairs;
/// NULL means "now" like utimensat's NULL times.
fn sys_utime(path: u64, times: u64) -> u64 {
    let mut name = [0u8; 257];
    let n = match copy_user_path(path, &mut name) {
        Ok(n) => n,
        Err(e) => return e,
    };
    let (cb, cn) = match user::canon_path(u64::MAX, &name[..n]) {
        Ok(x) => x,
        Err(e) => return e,
    };
    let ts = if times == 0 {
        None
    } else {
        if !user::range_ok(times, 16) {
            return EFAULT;
        }
        // SAFETY: [times, times+16) validated readable user memory.
        let a = unsafe { (times as *const u64).read_unaligned() };
        let m = unsafe { (times as *const u64).add(1).read_unaligned() };
        Some([[a, 0], [m, 0]])
    };
    user::fs_utimens(&cb[..cn], ts, false)
}

/// utimes/futimesat(dirfd, path, timeval[2]): each spec is
/// {sec, usec} — usec must be <1e6 like Linux, NULL means now.
fn sys_utimes_path(dirfd: u64, path: u64, times: u64) -> u64 {
    let mut name = [0u8; 257];
    let n = match copy_user_path(path, &mut name) {
        Ok(n) => n,
        Err(e) => return e,
    };
    let (cb, cn) = match user::canon_path(dirfd, &name[..n]) {
        Ok(x) => x,
        Err(e) => return e,
    };
    let ts = if times == 0 {
        None
    } else {
        if !user::range_ok(times, 32) {
            return EFAULT;
        }
        let mut t = [[0u64; 2]; 2];
        for i in 0..2 {
            // SAFETY: [times, times+32) validated readable.
            let s = unsafe { (times as *const u64).add(i * 2).read_unaligned() };
            let u =
                unsafe { (times as *const u64).add(i * 2 + 1).read_unaligned() };
            if u >= 1_000_000 {
                return EINVAL;
            }
            t[i] = [s, u * 1000];
        }
        Some(t)
    };
    user::fs_utimens(&cb[..cn], ts, false)
}

/// Copy a utimensat-style timespec[2] out of user memory — raw
/// sec/nsec pairs; fs_utimens validates the NOW/OMIT sentinels.
/// NULL means both-NOW.
fn utimens_read(times: u64) -> Result<Option<[[u64; 2]; 2]>, u64> {
    if times == 0 {
        return Ok(None);
    }
    if !user::range_ok(times, 32) {
        return Err(EFAULT);
    }
    let mut t = [[0u64; 2]; 2];
    for (i, e) in t.iter_mut().enumerate() {
        // SAFETY: [times, times+32) validated readable.
        *e = [
            unsafe { (times as *const u64).add(i * 2).read_unaligned() },
            unsafe {
                (times as *const u64).add(i * 2 + 1).read_unaligned()
            },
        ];
    }
    Ok(Some(t))
}

/// utimensat(dirfd, path, timespec[2], flags): AT_SYMLINK_NOFOLLOW +
/// AT_EMPTY_PATH; NULL times is both-NOW. A NULL path is futimens:
/// the dirfd itself is the target (tar stamps extracted files it
/// still holds open) — NOFOLLOW is EINVAL there like Linux since
/// there's no link to not follow, and NULL at AT_FDCWD is EFAULT.
fn sys_utimensat(dirfd: u64, path: u64, times: u64, flags: u64) -> u64 {
    const AT_SYMLINK_NOFOLLOW: u64 = 0x100;
    const AT_EMPTY_PATH: u64 = 0x1000;
    if flags & !(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH) != 0 {
        return EINVAL;
    }
    if path == 0 {
        if flags & AT_SYMLINK_NOFOLLOW != 0 {
            return EINVAL;
        }
        if dirfd as i32 == -100 {
            return EFAULT;
        }
        return user::fd_utimens(
            dirfd,
            match utimens_read(times) {
                Ok(t) => t,
                Err(e) => return e,
            },
        );
    }
    let mut name = [0u8; 257];
    let n = match copy_user_path(path, &mut name) {
        Ok(n) => n,
        Err(e) => return e,
    };
    // Path copied before the times pointer is touched — a bad path
    // outranks a bad times pointer like Linux's getname ordering.
    let ts = match utimens_read(times) {
        Ok(t) => t,
        Err(e) => return e,
    };
    if n == 0 && flags & AT_EMPTY_PATH != 0 {
        return user::fd_utimens(dirfd, ts);
    }
    let (cb, cn) = match user::canon_path(dirfd, &name[..n]) {
        Ok(x) => x,
        Err(e) => return e,
    };
    user::fs_utimens(&cb[..cn], ts, flags & AT_SYMLINK_NOFOLLOW != 0)
}

/// write(fd, buf, len): console fds only, buffer fully validated
/// against the process's mapped user ranges before a single byte is
/// read — this is the trust boundary, not a convenience check.
fn sys_write(ctx: &mut user::UCtx, fd: u64, buf: u64, len: u64) -> u64 {
    if !user::fd_is_console(fd) {
        return user::fd_write(ctx, fd, buf, len);
    }
    // Job control: with TOSTOP set, a background pgrp writing the
    // tty is SIGTTOU'd (or EIO when orphaned) before a byte moves.
    let gate = user::tty_tostop_gate();
    if gate != 0 {
        return gate;
    }
    if len == 0 {
        return 0;
    }
    if len > MAX_COPY {
        return EINVAL;
    }
    if !user::range_ok(buf, len) {
        return EFAULT;
    }
    // SAFETY: range_ok proved [buf, buf+len) lies inside a mapped
    // user range under the current (process) page table.
    let s = unsafe { core::slice::from_raw_parts(buf as *const u8, len as usize) };
    match core::str::from_utf8(s) {
        // tty semantics: user bytes reach the console verbatim — no
        // kernel-log record framing (the timestamp prefix would corrupt
        // cursor-addressed full-screen apps).
        Ok(t) => log::user_out(t),
        Err(_) => log::printk(format_args!("rustux: user write: {len}B non-utf8")),
    }
    // Flush now — main is parked in sched_launch for the whole task
    // phase, so without a syscall-side drain the small ring wraps and
    // user output is lost before it reaches the console.
    log::drain_task();
    len
}

/// writev for i386: struct iovec32 is {base: u32, len: u32}.
fn sys_writev32(ctx: &mut user::UCtx, fd: u64, iov: u64, cnt: u64) -> u64 {
    if cnt == 0 {
        return 0;
    }
    if cnt > 32 || !user::range_ok(iov, cnt * 8) {
        return EINVAL;
    }
    let mut done = 0u64;
    for i in 0..cnt {
        let (base, len) = unsafe {
            (
                ((iov + i * 8) as *const u32).read_unaligned() as u64,
                ((iov + i * 8 + 4) as *const u32).read_unaligned() as u64,
            )
        };
        if len == 0 {
            continue;
        }
        let n = sys_write(ctx, fd, base, len);
        if (n as i64) < 0 {
            return if done > 0 { done } else { n };
        }
        done += n;
        if n < len {
            break;
        }
    }
    done
}

/// writev(fd, iov, cnt): gather-write each iovec through sys_write —
/// the console-fanout and pipe paths stay identical to write(). The
/// vector itself is gate-checked; each element re-validates its own
/// buffer inside sys_write. (readv lives in user.rs with fd_read.)
fn sys_writev(ctx: &mut user::UCtx, fd: u64, iov: u64, cnt: u64) -> u64 {
    if cnt == 0 {
        return 0;
    }
    if cnt > 32 || !user::range_ok(iov, cnt * 16) {
        return EINVAL;
    }
    let mut done = 0u64;
    for i in 0..cnt {
        // SAFETY: range_ok proved the iovec array readable user memory.
        let (base, len) = unsafe {
            (
                ((iov + i * 16) as *const u64).read_unaligned(),
                ((iov + i * 16 + 8) as *const u64).read_unaligned(),
            )
        };
        if len == 0 {
            continue;
        }
        let n = sys_write(ctx, fd, base, len);
        if (n as i64) < 0 {
            return if done > 0 { done } else { n };
        }
        done += n;
        if n < len {
            break;
        }
    }
    done
}

/// exit(code): hand off to the scheduler — resume the next Runnable
/// task's ctx, or unwind to the saved kernel frame when none remain.
fn sys_exit(code: u64) -> ! {
    let (ou, tu, slots, refs, tcps) = user::fd_telemetry();
    log::printk(format_args!(
        "rustux: user: pid {} {} exit({code}) ofds {ou} tabs {tu} slots {slots} refs {refs} tcps {tcps}",
        user::getpid(),
        user::cur_exe()
    ));
    log::drain_task();
    user::task_exit(code)
}
