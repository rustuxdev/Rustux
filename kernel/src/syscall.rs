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
const NR_STATX: u64 = 332;
const NR_POLL: u64 = 7;
const NR_SOCKET: u64 = 41;
const NR_CONNECT: u64 = 42;
const NR_ACCEPT: u64 = 43;
const NR_SENDTO: u64 = 44;
const NR_RECVFROM: u64 = 45;
const NR_SENDMSG: u64 = 46;
const NR_SETSOCKOPT: u64 = 54;
const NR_SENDMMSG: u64 = 307;
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
const NR_RENAMEAT2: u64 = 276;
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
extern "C" fn handle_syscall(c: *mut user::UCtx) {
    // SAFETY: the stub built this UCtx on the current task's kstack.
    let ctx = unsafe { &mut *c };
    // NT-personality tasks share this stub but speak the Windows
    // convention (r10=arg1, stack args, NTSTATUS in rax) — route
    // before the Linux number table reads rdi-args that aren't set.
    if user::task_is_nt() {
        ctx.rax = crate::nt::dispatch(ctx, ctx.rax as u32);
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
        NR_SENDTO => user::fd_sendto(a1, a2, a3, a4, a5, a6),
        NR_RECVFROM => user::fd_recvfrom(ctx, a1, a2, a3, a4, a5, a6),
        NR_SENDMSG => user::fd_sendmsg(a1, a2, a3),
        NR_SETSOCKOPT => user::fd_setsockopt(a1, a2, a3, a4, a5),
        55 => user::fd_getsockopt(a1, a2, a3, a4, a5),
        NR_SENDMMSG => user::fd_sendmmsg(a1, a2, a3, a4),
        NR_OPEN => sys_open(a1, a2, a3),
        NR_OPENAT => sys_openat(a1, a2, a3, a4),
        NR_PREAD64 => user::fd_pread(a1, a2, a3, a4 as i64),
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
        NR_KILL => user::kill(a1 as i32 as i64, a2),
        NR_GETPPID => user::getppid(),
        NR_GETDENTS => user::fd_getdents(a1, a2, a3),
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
        NR_ACCESS => sys_access(u64::MAX, a1, a2),
        NR_FACCESSAT => sys_access(a1, a2, a3),
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
        NR_SETPRIORITY => 0,
        NR_GETPRIORITY => 0,
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
    // execve follows links — the image under the resolved name is
    // what runs; an unresolvable chain reports its error (ELOOP/...).
    let (rb, rn, _) = match user::resolve_links(&cb[..cn], true) {
        Ok(x) => x,
        Err(e) => return e,
    };
    let name = &rb[..rn];
    // A regular file with no exec bit is EACCES even for root —
    // this is the check dpkg's helper probe actually reads.
    if let Ok(st) = user::fill_stat(name, false) {
        if st[3] & 0o170000 == 0o100000 && st[3] & 0o111 == 0 {
            return (-13i64) as u64; // EACCES
        }
    }
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
    user::fs_chmod(&cb[..cn], mode)
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
    user::fs_chmod(&cb[..cn], mode)
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
    log::printk(format_args!(
        "rustux: user: pid {} {} exit({code})",
        user::getpid(),
        user::cur_exe()
    ));
    log::drain_task();
    user::task_exit(code)
}
