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

unsafe extern "C" {
    fn user_terminate() -> !;
    fn syscall_entry();
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
const NR_POLL: u64 = 7;
const NR_SOCKET: u64 = 41;
const NR_CONNECT: u64 = 42;
const NR_ACCEPT: u64 = 43;
const NR_SENDTO: u64 = 44;
const NR_RECVFROM: u64 = 45;
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
const NR_MKDIRAT: u64 = 258;
const NR_CLONE: u64 = 56;
const NR_GETCWD: u64 = 79;
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
const NR_READLINKAT: u64 = 267;
const NR_FACCESSAT: u64 = 269;
const NR_PREAD64: u64 = 17;
const NR_FCNTL: u64 = 72;
const NR_OPENAT: u64 = 257;
const NR_DUP3: u64 = 292;
const NR_ACCEPT4: u64 = 288;
const NR_FSYNC: u64 = 74;
const NR_FDATASYNC: u64 = 75;
const NR_TRUNCATE: u64 = 76;
const NR_FTRUNCATE: u64 = 77;
const NR_RENAME: u64 = 82;
const NR_CREAT: u64 = 85;
const NR_UNLINK: u64 = 87;
const NR_UNLINKAT: u64 = 263;
const NR_RENAMEAT: u64 = 264;
const NR_RENAMEAT2: u64 = 276;

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

/// ctx=rcx — the asm stub pushed a full UCtx and hands us &mut to it
/// (Windows x64 call convention). Args live in ctx.{rdi,rsi,rdx}; the
/// return value goes back through ctx.rax. Handlers may also copy the
/// whole ctx (fork), rewrite it (exec), block on it (wait4), or
/// diverge entirely (exit).
#[no_mangle]
extern "C" fn handle_syscall(c: *mut user::UCtx) {
    // SAFETY: the stub built this UCtx on the current task's kstack.
    let ctx = unsafe { &mut *c };
    let (nr, a1, a2, a3) = (ctx.rax, ctx.rdi, ctx.rsi, ctx.rdx);
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
        NR_READ => user::fd_read(ctx, a1, a2, a3.min(MAX_COPY)),
        NR_WRITE => sys_write(ctx, a1, a2, a3),
        NR_PIPE => user::fd_pipe(a1, 0),
        NR_PIPE2 => user::fd_pipe(a1, a2),
        NR_MMAP => user::sys_mmap(a1, a2, a3, a4, a5, a6),
        NR_MPROTECT => user::sys_mprotect(a1, a2, a3),
        NR_MUNMAP => user::sys_munmap(a1, a2),
        NR_BRK => user::sys_brk(a1),
        NR_RT_SIGPROCMASK => user::sys_rt_sigprocmask(a1, a2, a3, a4),
        NR_POLL => user::fd_poll(ctx, a1, a2, a3 as i64),
        34 => user::sys_pause(ctx),
        127 => user::sys_sigpending(a1, a2),
        130 => user::sys_sigsuspend(ctx, a1, a2),
        // rt_sigtimedwait(set,info,ts,sigsize): glibc sigwaitinfo
        // reaches it with ts=NULL — there is no nr-129 sigwaitinfo.
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
        NR_SENDTO => user::fd_sendto(a1, a2, a3, a4, a5, a6),
        NR_RECVFROM => user::fd_recvfrom(ctx, a1, a2, a3, a4, a5, a6),
        NR_OPEN => sys_open(a1, a2, a3),
        NR_OPENAT => sys_openat(a1, a2, a3, a4),
        NR_PREAD64 => user::fd_pread(a1, a2, a3, a4 as i64),
        NR_FCNTL => user::sys_fcntl(a1, a2, a3),
        NR_DUP3 => user::fd_dup3(a1, a2, a3),
        NR_CLOSE => user::fd_close(a1),
        // off arrives as u64; the fd layer interprets it as i64 —
        // negative seeks are how SEEK_CUR/END move backwards.
        NR_LSEEK => user::fd_lseek(a1, a2 as i64, a3),
        NR_SIGACTION => user::sigaction(a1, a2, a3),
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
        NR_KILL => user::kill(a1 as i32 as i64, a2),
        NR_GETPPID => user::getppid(),
        NR_GETDENTS => user::fd_getdents(a1, a2, a3),
        // newfstatat(dirfd, path, buf, flags): dirfd is ABI-shape
        // only; flags carry AT_SYMLINK_NOFOLLOW (0x100).
        NR_NEWFSTATAT => sys_newfstatat(a1, a2, a3, a4),
        NR_EXECVE => sys_execve(ctx, a1, a2, a3),
        NR_READV => user::fd_readv(ctx, a1, a2, a3),
        NR_WRITEV => sys_writev(ctx, a1, a2, a3),
        NR_IOCTL => user::sys_ioctl(a1, a2, a3),
        NR_NANOSLEEP => user::sys_nanosleep(ctx, a1, a2),
        NR_UNAME => user::sys_uname(a1),
        NR_GETTIMEOFDAY => user::sys_gettimeofday(a1, a2),
        NR_GETUID | NR_GETGID | NR_GETEUID | NR_GETEGID => 0,
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
        NR_CLONE => user::sys_clone(ctx, a1, a2, a3, a4, a5),
        NR_TGKILL => user::sys_tgkill(a1, a2, a3),
        NR_GETCWD => user::sys_getcwd(a1, a2),
        // stat follows; lstat is nofollow — proc links exist now.
        NR_STAT => sys_stat_path(a1, a2, false),
        NR_LSTAT => sys_stat_path(a1, a2, true),
        NR_FSTAT => user::sys_fstat(a1, a2),
        NR_ACCESS => sys_access(u64::MAX, a1),
        NR_FACCESSAT => sys_access(a1, a2),
        NR_READLINK => sys_readlink(a1, a2, a3),
        NR_READLINKAT => sys_readlinkat(a1, a2, a3, a4),
        NR_FSYNC | NR_FDATASYNC => user::fd_fsync(a1),
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
        NR_SETPRIORITY => 0,
        NR_GETPRIORITY => 0,
        NR_UMASK => user::sys_umask(a1),
        NR_SYSINFO => user::sys_sysinfo(a1),
        NR_TIMES => user::sys_times(a1),
        NR_TIME => user::sys_time(a1),
        NR_GETRUSAGE => user::sys_getrusage(a1, a2),
        NR_STATFS | NR_FSTATFS => user::sys_statfs(a2),
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
        NR_MKDIR => sys_mkdirat(u64::MAX, a1),
        NR_MKDIRAT => sys_mkdirat(a1, a2),
        NR_RMDIR => sys_rmdir(a1),
        NR_EXIT => sys_exit(a1),
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
fn sys_openat(dirfd: u64, path: u64, flags: u64, _mode: u64) -> u64 {
    let mut name = [0u8; 257];
    let n = match copy_user_path(path, &mut name) {
        Ok(n) => n,
        Err(e) => return e,
    };
    let (cb, cn) = match user::canon_path(dirfd, &name[..n]) {
        Ok(x) => x,
        Err(e) => return e,
    };
    user::fd_open(&cb[..cn], flags)
}

/// execve(path, argv, envp): resolve the name in the initrd, verify it
/// is a loadable ELF BEFORE touching the address space, then let
/// user::exec rebuild it — including the real initial stack
/// (argc/argv/envp/auxv) that ELF entry code reads at [rsp]
/// (CVE-2022-49264's argv==NULL discipline: argc=0 gets the binary
/// name as argv0, matching what glibc launchers always produce).
fn sys_execve(ctx: &mut user::UCtx, path: u64, argv: u64, envp: u64) -> u64 {
    let mut name = [0u8; 257];
    let n = match copy_user_path(path, &mut name) {
        Ok(n) => n,
        Err(e) => return e,
    };
    let (cb, cn) = match user::canon_path(u64::MAX, &name[..n]) {
        Ok(x) => x,
        Err(e) => return e,
    };
    let name = &cb[..cn];
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
    let mut args = user::ExecArgs::empty();
    let r = user::collect_exec_args(argv, envp, &mut args);
    if r != 0 {
        return r;
    }
    if args.argc == 0 {
        let n = name.len().min(user::EXEC_STR_CAP - 1);
        args.argv[0][..n].copy_from_slice(&name[..n]);
        args.argv_len[0] = n + 1;
        args.argc = 1;
    }
    if !user::exec(img, ctx, &args, name) {
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

/// access/faccessat(path, mode): a flat namespace only has
/// existence to report — root, archive members, RAM files.
fn sys_access(dirfd: u64, path: u64) -> u64 {
    let mut name = [0u8; 257];
    let n = match copy_user_path(path, &mut name) {
        Ok(n) => n,
        Err(e) => return e,
    };
    let (cb, cn) = match user::canon_path(dirfd, &name[..n]) {
        Ok(x) => x,
        Err(e) => return e,
    };
    if user::fs_exists(&cb[..cn]) {
        0
    } else {
        ENOENT
    }
}

/// unlink/unlinkat(dirfd, path, flags): one flat directory, so dirfd
/// is ABI-shape (FDCWD or a dir fd — same resolution either way).
/// flags with AT_REMOVEDIR → EISDIR here; rmdir doesn't exist yet.
/// unlink/unlinkat(dirfd, path, flags): AT_REMOVEDIR routes to
/// fs_rmdir; anything else nonzero EINVALs. canon_path does the
/// dirfd validation and cwd join.
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
    if flags != 0 {
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
    user::fs_rename(&ob[..oc], &nb[..nc])
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

/// mkdir/mkdirat(dirfd, path, mode): mode is accepted and ignored.
fn sys_mkdirat(dirfd: u64, path: u64) -> u64 {
    let mut name = [0u8; 257];
    let n = match copy_user_path(path, &mut name) {
        Ok(n) => n,
        Err(e) => return e,
    };
    user::fs_mkdir(dirfd, &name[..n])
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

/// readlink/readlinkat(path, buf, len): "/proc/self/exe" is the only
/// link that resolves (to the image's cpio name). No other symlinks
/// exist — ENOENT like a procfs miss.
fn sys_readlink(path: u64, buf: u64, len: u64) -> u64 {
    let mut name = [0u8; 257];
    let n = match copy_user_path(path, &mut name) {
        Ok(n) => n,
        Err(e) => return e,
    };
    if name[..n].starts_with(b"/proc/") {
        return match user::proc_readlink(&name[1..n], buf, len) {
            x if x == usize::MAX as u64 => ENOENT,
            x => x,
        };
    }
    ENOENT
}

/// readlinkat(dirfd, path, buf, len): canon resolves dirfd/cwd —
/// proc/self/exe is the only link that answers.
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
    if cb[..cn].starts_with(b"proc/") {
        return match user::proc_readlink(&cb[..cn], buf, len) {
            x if x == usize::MAX as u64 => ENOENT,
            x => x,
        };
    }
    ENOENT
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
        Ok(t) => log::printk(format_args!("{t}")),
        Err(_) => log::printk(format_args!("rustux: user write: {len}B non-utf8")),
    }
    // Flush now — main is parked in sched_launch for the whole task
    // phase, so without a syscall-side drain the small ring wraps and
    // user output is lost before it reaches the console.
    log::drain_task();
    len
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
    log::printk(format_args!("rustux: user: pid {} exit({code})", user::getpid()));
    log::drain_task();
    user::task_exit(code)
}
