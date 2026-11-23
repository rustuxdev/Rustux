//! Ring-3 process support: per-task page tables (kernel entries
//! copied supervisor-only), PT_LOAD mapping from the ELF image, a user
//! stack, a per-task kernel stack for SYSCALL entries, and the
//! iretq/sysretq privilege-transition pair.
//!
//! Task model: one resident task at a time, run to completion. A Task
//! owns every frame it was allocated — page tables, data pages, stacks
//! — in a ledger that reap() returns to the buddy wholesale, so task
//! exit leaks nothing (the CVE-2022-50661 discipline: teardown freeing
//! is designed in, not patched on).
//!
//! The user page table shares the kernel's low PML4 slots (copied
//! verbatim — they were created supervisor-only, so user code cannot
//! touch kernel memory through them), while user pages land in PML4
//! slots 128..256 (elf::USER_VA_LO..HI). There is no scheduler yet:
//! run() is a synchronous drop — the image's exit syscall unwinds the
//! kernel frame saved by user_enter and control returns here.

use crate::{cpu, elf, kalloc, syscall};

const PAGE: u64 = 0x1000;
const PRESENT: u64 = 1;
const WRITE: u64 = 2;
const USER: u64 = 4;
const NX: u64 = 1 << 63;
/// Physical-address bits of a PTE: strip flags AND the NX bit — a
/// plain `& !0xfff` would keep NX set and fabricate a non-canonical
/// "address" out of any read-only mapping.
const PHYS_MASK: u64 = 0x000f_ffff_ffff_f000;

/// User stack: 16 pages high in the user window.
/// Syscall personalities — Task.pers selects the dispatch table.
pub const PERS_LINUX: u8 = 0;
pub const PERS_NT: u8 = 1;

/// NT anonymous-VM arena — above the PEB/TEB/stub/heap pages,
/// still inside the user window and clear of the image bias.
pub const NT_ALLOC_VA: u64 = crate::pe::HEAP_MAX;

const USTACK_VA: u64 = 0x5556_0000_0000;
/// mmap's first-fit arena — 4 TiB of user window kept free of the
/// ELF image (~0x4000…) and the stack (0x5556…).
const MMAP_LO: u64 = 0x6000_0000_0000;
const MMAP_HI: u64 = 0x7000_0000_0000;
const USTACK_PAGES: u64 = 16;

/// Signal restorer trampoline: one user-RX page mapped just below
/// the user stack at exec. Delivery points the handler's return
/// address at SIGTRAMP_VA so a plain `ret` runs the rt_sigreturn
/// stub — the Linux vsyscall/vDSO role, minus the vDSO.
const SIGTRAMP_VA: u64 = USTACK_VA - PAGE;
/// mov $15,%rax; syscall — rt_sigreturn. The rest of the page stays
/// zeroed (ud2-equivalent landing pad for off-stub jumps).
const SIGTRAMP_CODE: [u8; 9] = [0x48, 0xc7, 0xc0, 0x0f, 0, 0, 0, 0x0f, 0x05];

/// Per-task kernel stack for SYSCALL entries — replaces the shared
/// static stack so a task's kernel state can't bleed into the next.
const KSTACK_SIZE: usize = 49152;

/// Maximum distinct user VA ranges recorded for syscall validation —
/// the vm_max_map_count analog: mmap/mprotect splits consume slots,
/// brk/ELF/stack hold permanent ones. Overflow fails the op (ENOMEM),
/// never silently maps unvalidated VA.
// Sized for the NT module ledger's own ceiling: NT_MAX_MODS=16
// images of ~11 mapped sections each + the exe's + system VMAs.
const MAX_RANGES: usize = 128;

/// Max resident tasks — a hard bound so spawn can't exhaust the
/// kernel heap by enqueueing forever. 48 was fork-EAGAIN-tight
/// for the 39-task suite + concurrent children (observed on VM).
const MAX_TASKS: usize = 64;

/// A resumable user-mode context: the 15 GPRs in sched_dispatch's
/// push order plus the iret frame. Every task transition — first
/// launch, timer preemption, exit — is the same operation: point
/// rsp at a UCtx, pop, iretq.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct UCtx {
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub rbp: u64,
    pub rbx: u64,
    pub r11: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rdx: u64,
    pub rcx: u64,
    pub rax: u64,
    pub rip: u64,
    pub cs: u64,
    pub rflags: u64,
    pub rsp: u64,
    pub ss: u64,
}

impl UCtx {
    const ZERO: UCtx = UCtx {
        r15: 0, r14: 0, r13: 0, r12: 0, rbp: 0, rbx: 0,
        r11: 0, r10: 0, r9: 0, r8: 0,
        rdi: 0, rsi: 0, rdx: 0, rcx: 0, rax: 0,
        rip: 0, cs: 0, rflags: 0, rsp: 0, ss: 0,
    };
    /// The fabricated ctx of a never-run task: clean GPRs, user
    /// segments, IF set, entry + fresh stack — same shape a timer
    /// IRQ snapshot would leave.
    fn launch(rip: u64, rsp: u64) -> UCtx {
        UCtx {
            rip,
            cs: 0x33,
            rflags: 0x202,
            rsp,
            ss: 0x2b,
            ..UCtx::ZERO
        }
    }
}

/// The scheduler's state model: Runnable tasks can be picked; Exited
/// ones persist as zombies until their parent's wait4 collects them
/// (or they're orphaned); Blocked tasks sleep inside a syscall whose
/// resume ctx is already saved — a matching child exit wakes them.
#[derive(Clone, Copy, PartialEq, Eq)]
enum TaskState {
    Runnable,
    Exited,
    Blocked,
    /// Job-control stop (SIGSTOP/TSTP/TTIN/TTOU, default disp):
    /// never picked, never a zombie — SIGCONT resumes it, SIGKILL
    /// pulls it out to die. wait4 reports it under WUNTRACED.
    Stopped,
}

/// What a Blocked task sleeps on — wait4's child, or a pipe's
/// read/write side. The waker writes the syscall result into
/// `ctx.rax` and marks the task Runnable.
#[derive(Clone, Copy, PartialEq, Eq)]
enum WaitOn {
    None,
    /// wait4(-1): any child of this task.
    Any,
    /// wait4 on a specific child pid.
    Child(u64),
    /// read() on an empty pipe: `wait_ptr/len` is the user buffer.
    PipeRead(usize),
    /// write() on a full pipe: `wait_ptr/len` is the user buffer.
    PipeWrite(usize),
    /// poll(): `wait_ptr` is the user pollfd array, `wait_len` the
    /// fd count. Any pipe-state change re-scans it; wait_deadline
    /// ticks (0 = none) bounds the sleep.
    Poll,
    /// recvfrom() on an empty UDP socket: `wait_ptr` is the user
    /// buffer, `wait_len` its cap, `wait_ptr2` the sockaddr out ptr.
    UdpRecv(usize),
    /// nanosleep(): pure deadline wait — wait_deadline bounds it,
    /// the return is always 0.
    Timer,
    /// connect() awaiting SYN-ACK; wait_deadline bounds it.
    TcpConn(usize),
    /// accept() awaiting an established child on the listener.
    TcpAccept(usize),
    /// recv/read on an empty TCP stream: `wait_ptr/len` the buffer,
    /// `wait_ptr2` the optional peer sockaddr out ptr.
    TcpRecv(usize),
    /// read() on an empty tty input queue: `wait_ptr/len` is the
    /// user buffer — the waker copies through the sleeper's tables
    /// and deposits the count in ctx.rax, like PipeRead.
    Stdin,
    /// futex(FUTEX_WAIT) on a user word at this VA — the wake also
    /// matches the sleeper's pml4 so same-VA waits in different
    /// address spaces stay distinct.
    Futex(u64),
    /// vfork() parent suspended until the child (this pid) execs or
    /// exits — Linux's vfork_done completion. Uninterruptible by
    /// signals (kill() skips it; pending delivers after resume).
    Vfork(u64),
    /// wait4(-pgid)/wait4(0): any child in this process group.
    Group(u64),
    /// pselect6(): `wait_ptr/2/3` are the user read/write/except
    /// fd_set VAs, `wait_len` the nfds; wait_deadline bounds it like
    /// Poll. Ready bits are rewritten through the sleeper's tables.
    Pselect,
    /// pause()/sigsuspend(): wake on signal delivery only — no
    /// deadline, no resource to poll. The generic signal-wake path
    /// supplies the -EINTR these calls always return.
    SigWait,
    /// sigwaitinfo/sigtimedwait/signalfd-read: wait_len is the wait
    /// set, wait_ptr the record VA (siginfo_t or signalfd_siginfo),
    /// wait_ptr2 nonzero picks the signalfd record shape (rax=128).
    /// An in-set signal is CONSUMED at wake, never delivered;
    /// wait_deadline is sigtimedwait's EAGAIN bound.
    SigTimed,
    /// epoll_wait(): the payload is the EPOLLS index; `wait_ptr` is
    /// the user epoll_event array, `wait_len` maxevents. Any
    /// fd-state change re-scans the interest set like Poll.
    Epoll(usize),
    /// eventfd read on a zero counter — the waker deposits the
    /// u64 value through the sleeper's tables like PipeRead.
    EventfdR(usize),
    /// eventfd write that would overflow EFD_MAX — wait_len is the
    /// value to add, re-evaluated at wake like PipeWrite's fit.
    EventfdW(usize),
    /// timerfd read before expiry — woken by timerfd_expire at the
    /// deadline tick (10 ms granularity, the kernel's resolution).
    Timerfd(usize),
    /// inotify read on an empty queue — ino_report wakes the sleeper
    /// by depositing the head event's record like PipeRead.
    Inotify(usize),
    /// CREATE_SUSPENDED NT thread — created Blocked and only
    /// NtResumeThread flips it Runnable; nothing else wakes it.
    NtSuspend,
    /// NtWaitForSingleObject on an NT thread object — the payload
    /// is the NT_THREADS ledger index plus the tid recorded at arm
    /// time — a freed-and-reallocated slot can't satisfy the wait —
    /// wait_deadline bounds it (0 = infinite). nt_wait_expire
    /// re-checks the object each tick: dead -> STATUS_SUCCESS,
    /// expired -> STATUS_TIMEOUT.
    NtWait(usize, u64),
    /// Same wait on an NT process object — payload is the
    /// NT_PROCS ledger index plus the tgid recorded at arm time, so
    /// a freed-and-reallocated slot can't satisfy the wait.
    NtWaitProc(usize, u64),
}

/// Max fds per task — a hard bound so a hostile process cannot
/// exhaust kernel space by opening forever or force the table to
/// grow by a user-chosen size (the CVE-2025-39756 class: dup2 must
/// never size an allocation from its target fd number).
const MAX_FDS: usize = 16;
// fd_cloexec is a u16 bitmask — a MAX_FDS bump past 16 must widen it.
const _: () = assert!(MAX_FDS <= 16);

/// A canonical directory path stored on a Dir OFD ("" = root).
#[derive(Clone, Copy)]
pub struct DirPath {
    b: [u8; 128],
    n: u8,
}

impl DirPath {
    fn of(path: &[u8]) -> DirPath {
        let mut d = DirPath { b: [0; 128], n: 0 };
        d.n = path.len().min(128) as u8;
        d.b[..d.n as usize].copy_from_slice(&path[..d.n as usize]);
        d
    }
    pub fn bytes(&self) -> &[u8] {
        &self.b[..self.n as usize]
    }
}

/// The object an fd slot names — Linux's inode-level identity.
enum FdKind {
    /// fd 0: reads return EOF, writes fail EBADF.
    Stdin,
    /// fds 1/2: writes go to the serial ring, reads fail EBADF.
    Console,
    /// Initrd-backed read-only file. Borrows LOADER_DATA — immortal,
    /// so no refcount on the backing bytes is needed.
    File(&'static [u8]),
    /// RAM-backed scratch file — VFILES[i]. The OFD owns no copy;
    /// unlink marks the VFile and the last close frees it.
    Ram(usize),
    /// A directory — the canonical path it names ("" = root).
    /// pos is the index of the next stream entry getdents64 should
    /// emit — Linux dir offsets are opaque cookies, ours just
    /// happens to be an index.
    Dir(DirPath),
    /// One end of a pipe — the ring lives in PIPES[id], shared by
    /// whatever tasks inherited the fds. `write` selects the end.
    Pipe { id: usize, write: bool },
    /// An AF_INET/SOCK_DGRAM socket — the state lives in UDPSOCKS[id],
    /// dup'd/fork'd fds share the one endpoint like pipe ends.
    Udp(usize),
    /// An AF_INET/SOCK_STREAM endpoint — listener or connection —
    /// the state machine lives in TCPSOCKS[id].
    Tcp(usize),
    /// An epoll instance — the interest set lives in EPOLLS[id];
    /// dup'd fds share it like socket endpoints.
    Epoll(usize),
    /// An eventfd counter — the semaphore lives in EVENTFDS[id].
    Eventfd(usize),
    /// A signalfd — the wait mask lives in SIGNALFDS[id]; reads
    /// dequeue the READER's pending signals in that mask.
    Signalfd(usize),
    /// An inotify instance — watches + event queue in INOTIFY[id].
    Inotify(usize),
    /// A timerfd — arming/expiry state lives in TIMERFDS[id].
    Timerfd(usize),
    /// A generated /proc file — contents are rendered into a
    /// kernel frame at open (Linux's seq_file snapshot model), so
    /// reads and stats see one consistent image even if the task
    /// it describes exits before the last read.
    Proc { buf: u64, len: usize },
    /// A character-device node — VFILES[i] holds the node (name,
    /// metadata, rdev). Data lives in driver semantics: null/zero/
    /// full/random sink or mint bytes, tty/console bridge the
    /// serial pair. Block devs and fifos never reach this — ENODEV /
    /// ENXIO at fd_open like Linux without a driver.
    Dev(usize),
}

/// Max concurrent pipes — a hard bound on kernel frame pressure,
/// same discipline as the fd/OFD tables. 8 was exhaustible under
/// concurrent test load (multiple pipelining tasks + dash's own
/// substitution pipes) — ENFILE is honest but the bound was low.
const MAX_PIPES: usize = 32;
/// Ring capacity: one frame per pipe, exactly PIPE_BUF — writes of
/// up to this size are atomic (the Linux promise).
const PIPE_SIZE: usize = 4096;

/// A pipe's shared state: a kernel-owned frame used as a ring with
/// monotonic head/tail (data = tail-head, offset = pos % PIPE_SIZE).
/// Endpoint counts are tracked here, NOT in OFD refs — dup'd fds
/// share one endpoint, so only the LAST close of an end decrements.
struct Pipe {
    /// phys frame, identity-mapped kernel side. Zeroed at alloc and
    /// never aliases file/page-cache memory — the Dirty Pipe
    /// (CVE-2022-0847) uninitialized-flags class doesn't exist here.
    buf: u64,
    head: usize,
    tail: usize,
    readers: usize,
    writers: usize,
}

static mut PIPES: [Option<Pipe>; MAX_PIPES] = [const { None }; MAX_PIPES];

/// Max concurrent epoll instances — same fixed-table discipline as
/// pipes/sockets; ENFILE is the honest answer past the bound.
const MAX_EPOLLS: usize = 8;
/// Max interests per epoll set. Linux's rbtree is unbounded; our
/// fixed array returns ENOMEM (E12) when full — an honest refusal,
/// never a silent drop.
const MAX_EPOLL_FDS: usize = 16;

/// One registered interest: `ofd` pins the OPEN FILE DESCRIPTION
/// (Linux's epitem → file, surviving fd close if a dup lives on);
/// `fd` is the registered number for ctl lookup only. `events` is
/// the EPOLL* mask (low bits alias POLL*); `data` is the user cookie
/// returned verbatim in epoll_event.
#[derive(Clone, Copy)]
struct EpollEnt {
    fd: i32,
    ofd: u8,
    events: u32,
    data: u64,
}

/// An epoll instance's interest set — a bounded array, not a tree.
struct Epoll {
    ents: [Option<EpollEnt>; MAX_EPOLL_FDS],
}

static mut EPOLLS: [Option<Epoll>; MAX_EPOLLS] = [const { None }; MAX_EPOLLS];

/// Max eventfd instances — same fixed-table discipline; ENFILE
/// is the honest answer past the bound.
const MAX_EVENTFDS: usize = 8;
/// The semaphore ceiling: a write may add while count + v fits
/// below 2^64-1 — u64::MAX itself is EINVAL outright (Linux).
const EFD_MAX: u64 = u64::MAX - 1;

/// An eventfd: a u64 kernel semaphore. read returns the count and
/// drains it (1 and decrements under EFD_SEMAPHORE); write adds.
/// `nonblock` is per-INSTANCE like the rest of our fd flags —
/// dup'd fds share it, matching Linux's file-status flags.
struct Eventfd {
    count: u64,
    sema: bool,
    nonblock: bool,
}

static mut EVENTFDS: [Option<Eventfd>; MAX_EVENTFDS] =
    [const { None }; MAX_EVENTFDS];

/// Max timerfd instances.
const MAX_TIMERFDS: usize = 8;

/// A timerfd: one armed deadline in TICKS (100 Hz — 10 ms is the
/// timer resolution) plus an optional periodic interval. read()
/// collects the unread expiry count.
struct Timerfd {
    armed: bool,
    deadline: u64,
    interval: u64,
    expirations: u64,
    nonblock: bool,
}

static mut TIMERFDS: [Option<Timerfd>; MAX_TIMERFDS] =
    [const { None }; MAX_TIMERFDS];

/// Max signalfd instances.
const MAX_SIGNALFDS: usize = 8;

/// A signalfd: a per-instance signal mask. read() dequeues the
/// READER's pending signals in the mask into signalfd_siginfo
/// records — the object is just the mask, the queue is the task's.
struct Signalfd {
    mask: u32,
    nonblock: bool,
}

static mut SIGNALFDS: [Option<Signalfd>; MAX_SIGNALFDS] =
    [const { None }; MAX_SIGNALFDS];

/// Max inotify instances / watches per instance / queued events.
const MAX_INOTIFY: usize = 4;
const MAX_IWATCHES: usize = 16;
const MAX_IEVS: usize = 8;

/// inotify event bits (Linux uapi values).
const IN_ACCESS: u32 = 0x1;
const IN_MODIFY: u32 = 0x2;
const IN_ATTRIB: u32 = 0x4;
const IN_CLOSE_WRITE: u32 = 0x8;
const IN_CLOSE_NOWRITE: u32 = 0x10;
const IN_OPEN: u32 = 0x20;
const IN_MOVED_FROM: u32 = 0x40;
const IN_MOVED_TO: u32 = 0x80;
const IN_CREATE: u32 = 0x100;
const IN_DELETE: u32 = 0x200;
const IN_DELETE_SELF: u32 = 0x400;
const IN_MOVE_SELF: u32 = 0x800;
const IN_ALL_EVENTS: u32 = 0xfff;
const IN_Q_OVERFLOW: u32 = 0x4000;
const IN_IGNORED: u32 = 0x8000;
const IN_ISDIR: u32 = 0x4000_0000;

/// A watch on a canonical path. dir=true means the path is a
/// directory and the watch also receives events for its children
/// (named in the event record); a file watch sees self events only.
/// Watches are path-keyed, not inode-keyed — a rename emits
/// IN_MOVE_SELF + IN_IGNORED and drops the watch (divergence: Linux
/// keeps the watch on the moved inode).
#[derive(Clone, Copy)]
struct IWatch {
    path: [u8; 128],
    nlen: u8,
    dir: bool,
    mask: u32,
}

/// A queued event record — the name is the CHILD component for
/// dir-watch events, empty for self events.
#[derive(Clone, Copy)]
struct InoEv {
    wd: i32,
    mask: u32,
    cookie: u32,
    name: [u8; 128],
    nlen: u8,
}

/// An inotify instance: fixed watch table + event ring. `overflow`
/// folds the Linux IN_Q_OVERFLOW record into the next drain.
struct Inotify {
    watches: [Option<IWatch>; MAX_IWATCHES],
    q: [Option<InoEv>; MAX_IEVS],
    overflow: bool,
    nonblock: bool,
}

static mut INOTIFY: [Option<Inotify>; MAX_INOTIFY] =
    [const { None }; MAX_INOTIFY];

/// The 512-byte fxsave64 image — per-task FPU/SSE state. 16-aligned
/// per the instruction's contract. Every context switch does
/// fxsave(old)/fxrstor(new) so SSE registers stay per-task: without
/// this, one task's xmm writes leak into the next task (NV-55-1).
#[repr(align(16))]
#[derive(Clone, Copy)]
struct FxState([u8; 512]);

/// The architectural fninit+fxsave capture taken once at boot —
/// every fresh task and every exec'd image starts from it.
static mut INIT_FX: FxState = FxState([0; 512]);

/// Capture INIT_FX and arm SSE. Called once before the first task
/// spawns; cpu::init already set CR0.MP + CR4.OSFXSR/OSXMMEXCPT.
pub fn fpu_init() {
    unsafe {
        core::arch::asm!("fninit");
        core::arch::asm!(
            "fxsave64 [{}]",
            in(reg) (*core::ptr::addr_of_mut!(INIT_FX)).0.as_mut_ptr()
        );
    }
}

/// Save the live FPU/SSE registers into the task's buffer.
fn fxsave(t: &mut Task) {
    // SAFETY: t.fx is 16-aligned, 512 bytes — the fxsave64 contract.
    unsafe { core::arch::asm!("fxsave64 [{}]", in(reg) t.fx.0.as_mut_ptr()) }
}

/// Restore a task's FPU/SSE registers — done on every resume so the
/// task sees only its own state.
fn fxrstor(fx: &FxState) {
    // SAFETY: fx is a valid 16-aligned 512-byte fxsave image.
    unsafe { core::arch::asm!("fxrstor64 [{}]", in(reg) fx.0.as_ptr()) }
}

// ---- signals ----

const SIG_DFL: u64 = 0;
const SIG_IGN: u64 = 1;
const SIGCHLD: usize = 17;
const SIGCONT: usize = 18;
const SIGKILL: usize = 9;
const SIGSTOP: usize = 19;
const SIGSEGV: usize = 11;
/// si_code values — negative codes are user/queued, SI_KERNEL is
/// the kernel's own (Linux reserves positives for kernel events;
/// userspace pends only <= 0).
const SI_USER: i32 = 0;
const SI_KERNEL: i32 = 0x80;
const SI_TKILL: i32 = -6;
/// SIGCHLD si_code (CLD_*) — mapped from the child's wstatus.
const CLD_EXITED: i32 = 1;
const CLD_KILLED: i32 = 2;
const CLD_DUMPED: i32 = 3;
const CLD_STOPPED: i32 = 5;
const CLD_CONTINUED: i32 = 6;
/// sigaction sa_flags bits we honor.
const SA_NODEFER: u32 = 0x4000_0000;
const SA_RESETHAND: u32 = 0x8000_0000;
/// The si fields attached to a pending bit. Standard signals
/// coalesce — a second pend while the bit is set drops its info
/// like Linux's standard-signal merge, so one record per bit is
/// the exact model. aux is si_value for SI_QUEUE, si_status for
/// SIGCHLD, si_addr for fault signals.
#[derive(Clone, Copy)]
struct SigSrc {
    code: i32,
    pid: u32,
    uid: u32,
    aux: u64,
}
const SIGSRC_NONE: SigSrc = SigSrc {
    code: SI_KERNEL,
    pid: 0,
    uid: 0,
    aux: 0,
};
/// wait4 option bits (Linux ABI): don't block, report stopped
/// children, report continued children.
const WNOHANG: u64 = 1;
const WUNTRACED: u64 = 2;
const WCONTINUED: u64 = 8;
/// Bytes pushed on the task's user stack per delivered signal:
/// restorer (8) + signo (8) + the interrupted UCtx (160) +
/// siginfo_t (128) + the pre-delivery sigmask (8).
const SIGFRAME_SIZE: u64 = 312;
// The frame layout is only sound while UCtx stays 20 u64s — a size
// change must grow the frame and both copy sites with it.
const _: () = assert!(core::mem::size_of::<UCtx>() == 160);

/// Signals whose default is to do nothing — informational only;
/// everything else kills (or stops, below) by default. 17=SIGCHLD,
/// 18=SIGCONT, 23=SIGURG, 28=SIGWINCH.
fn sig_default_ignore(sig: usize) -> bool {
    matches!(sig, 17 | 18 | 23 | 28)
}

/// Signals whose default is job-control stop: SIGSTOP(19, also
/// uncatchable/unblockable), SIGTSTP(20), SIGTTIN(21), SIGTTOU(22).
fn sig_default_stop(sig: usize) -> bool {
    matches!(sig, 19 | 20 | 21 | 22)
}

/// Write `data` into `pml4`'s user space byte-wise — each byte
/// translated through that task's tables (which may be inactive).
/// Returns false on the first unmapped or unwritable byte.
fn write_task_bytes(pml4: u64, va: u64, data: &[u8]) -> bool {
    for (i, &b) in data.iter().enumerate() {
        let Some(pa) = translate(pml4, va + i as u64) else {
            return false;
        };
        // SAFETY: pa is a present, writable user frame in pml4.
        unsafe { (pa as *mut u8).write(b) };
    }
    true
}

/// write_task_bytes without the user writable bit: kernel fill of
/// freshly-allocated PRIVATE pages is legitimate on read-only maps —
/// translate_r walks present-only, exactly the folio-fill privilege.
fn write_task_bytes_force(pml4: u64, va: u64, data: &[u8]) -> bool {
    for (i, &b) in data.iter().enumerate() {
        let Some(pa) = translate_r(pml4, va + i as u64) else {
            return false;
        };
        // SAFETY: pa is a present user frame in pml4.
        unsafe { (pa as *mut u8).write(b) };
    }
    true
}

/// Apply one pending signal to `ctx` — the resume image of task `t`.
/// Handler installed: push [signo][interrupted UCtx] onto the task's
/// own stack, redirect rip to the handler, rdi=signo — sigreturn
/// pops it back. Ignore-default signals drop; every other default
/// kills with wait status = bare signo (the Linux wstatus shape).
/// An unwritable stack kills the task like Linux's delivery SEGV.
/// Lowest-numbered deliverable signal: pending AND unmasked. SIGKILL
/// and SIGSTOP are always deliverable — the mask can't stop them
/// (Linux semantics: sig_kernel_only signals ignore the blocked
/// set on delivery).
#[inline]
fn unmasked_pending(t: &Task) -> Option<usize> {
    const FORCE: u32 = (1 << (SIGKILL - 1)) | (1 << (SIGSTOP - 1));
    let unmasked = t.pending & (!t.sigmask | FORCE);
    (unmasked != 0).then(|| unmasked.trailing_zeros() as usize + 1)
}

/// A signal that can be delivered NOW — pending and unmasked.
#[inline]
fn deliverable(t: &Task) -> bool {
    unmasked_pending(t).is_some()
}

/// SIG_IGN or a default-ignore disposition — the signal is a
/// non-event: no wake, no collect, no EINTR (Linux drops these at
/// send; we keep the bit but treat it as noise everywhere).
fn sig_ignored(t: &Task, sig: u64) -> bool {
    let h = sigt(t)
        .handlers
        .get(sig as usize - 1)
        .copied()
        .unwrap_or(SIG_DFL);
    h == SIG_IGN || (h == SIG_DFL && sig_default_ignore(sig as usize))
}

/// Render a SigSrc into the 128-byte siginfo_t (fd=false) or
/// signalfd_siginfo (fd=true) record. The union fields land at
/// their layout offsets: pid/uid, then si_status (SIGCHLD) /
/// si_value (queued) / si_addr (fault).
fn fill_sig_rec(sig: u64, si: SigSrc, fd: bool) -> [u8; 128] {
    let mut rec = [0u8; 128];
    rec[..4].copy_from_slice(&(sig as u32).to_le_bytes());
    rec[8..12].copy_from_slice(&si.code.to_le_bytes());
    let (pio, uio) = if fd { (12usize, 16usize) } else { (16, 20) };
    rec[pio..pio + 4].copy_from_slice(&si.pid.to_le_bytes());
    rec[uio..uio + 4].copy_from_slice(&si.uid.to_le_bytes());
    if matches!(sig as usize, 4 | 5 | 7 | 8 | 11) {
        // si_addr — siginfo@16 / signalfd@72.
        let fo = if fd { 72 } else { 16 };
        rec[fo..fo + 8].copy_from_slice(&si.aux.to_le_bytes());
    } else if sig == SIGCHLD as u64 {
        // si_status — siginfo@24 / signalfd@40.
        let so = if fd { 40 } else { 24 };
        rec[so..so + 4].copy_from_slice(&(si.aux as u32).to_le_bytes());
    } else {
        // si_value — siginfo@24; signalfd fills ssi_int@44 + ssi_ptr@48.
        if fd {
            rec[44..48].copy_from_slice(&(si.aux as u32).to_le_bytes());
            rec[48..56].copy_from_slice(&si.aux.to_le_bytes());
        } else {
            rec[24..32].copy_from_slice(&si.aux.to_le_bytes());
        }
    }
    rec
}

/// Consume the pend_src behind `sig` into a record — used by the
/// dequeue paths that pop a pending bit themselves.
fn sig_record(t: &mut Task, sig: u64, fd: bool) -> [u8; 128] {
    let si = core::mem::replace(&mut t.pend_src[sig as usize - 1], SIGSRC_NONE);
    fill_sig_rec(sig, si, fd)
}

fn maybe_deliver(t: &mut Task, ctx: &mut UCtx) {
    while let Some(sig) = unmasked_pending(t) {
        t.pending &= !(1u32 << (sig - 1));
        let src = core::mem::replace(&mut t.pend_src[sig - 1], SIGSRC_NONE);
        match sigt(t).handlers.get(sig - 1).copied().unwrap_or(SIG_DFL) {
            SIG_IGN => {}
            SIG_DFL => {
                if sig_default_stop(sig) {
                    // A stop dequeues a pending SIGCONT, transitions
                    // to Stopped, and tells the parent via the
                    // WUNTRACED machinery + SIGCHLD.
                    t.pending &= !(1u32 << (SIGCONT as u8 - 1));
                    t.pend_src[SIGCONT - 1] = SIGSRC_NONE;
                    t.state = TaskState::Stopped;
                    t.stop_sig = sig as u8;
                    let (cp, cg, cpp) = (t.pid, t.pgid, t.ppid);
                    child_change(cp, cg, cpp, ((sig as u64) << 8) | 0x7f, WUNTRACED);
                    return;
                }
                if sig_default_ignore(sig) {
                    continue;
                }
                t.state = TaskState::Exited;
                t.exit_status = sig as u64;
                return;
            }
            handler => {
                // [restorer][signo][UCtx][siginfo_t][saved sigmask]:
                // a C handler that returns pops the restorer —
                // SIGTRAMP_VA's `mov $15; syscall` stub — so ret IS
                // rt_sigreturn (the handler runs at rsp=frame; the
                // stub sees the UCtx at rsp+8).
                let frame = (ctx.rsp.wrapping_sub(SIGFRAME_SIZE)) & !15;
                let sig64 = sig as u64;
                let i = sig - 1;
                let (fl, hm) = {
                    let s = sigt(t);
                    (
                        s.flags.get(i).copied().unwrap_or(0),
                        s.masks.get(i).copied().unwrap_or(0),
                    )
                };
                // siginfo_t for an SA_SIGINFO handler — the union
                // fields land at their layout offsets.
                let info = fill_sig_rec(sig64, src, false);
                // SAFETY: reinterprets the UCtx as its repr(C) bytes —
                // written verbatim into the task's own stack.
                let raw = unsafe {
                    core::slice::from_raw_parts(ctx as *const UCtx as *const u8, 160)
                };
                // The mask the frame restores on sigreturn: normally
                // the pre-delivery sigmask, but an in-wake delivery
                // with an owed psel restore rides the ORIGINAL mask —
                // the handler's sigreturn is the suspend's return.
                let saved_mask = if t.frame_mask != u64::MAX {
                    t.frame_mask as u32
                } else {
                    t.sigmask
                };
                t.frame_mask = u64::MAX;
                let ok = write_task_bytes(t.pml4, frame, &SIGTRAMP_VA.to_le_bytes())
                    && write_task_bytes(t.pml4, frame + 8, &sig64.to_le_bytes())
                    && write_task_bytes(t.pml4, frame + 16, raw)
                    && write_task_bytes(t.pml4, frame + 176, &info)
                    && write_task_bytes(
                        t.pml4,
                        frame + 304,
                        &(saved_mask as u64).to_le_bytes(),
                    );
                if !ok {
                    t.state = TaskState::Exited;
                    t.exit_status = SIGSEGV as u64;
                    return;
                }
                // SA_RESETHAND resets to default at entry; the
                // handler runs under oldmask | sa_mask | self unless
                // SA_NODEFER — sigreturn restores the saved mask.
                if fl & SA_RESETHAND != 0 {
                    sigt(t).handlers[i] = SIG_DFL;
                }
                let mut add = hm;
                if fl & SA_NODEFER == 0 {
                    add |= 1u32 << i;
                }
                t.sigmask |= add;
                ctx.rsp = frame;
                ctx.rip = handler;
                ctx.rdi = sig64;
                ctx.rsi = frame + 176; // &siginfo_t
                ctx.rdx = frame + 16; // &ucontext (the saved UCtx)
                return; // one signal per resume, Linux-style
            }
        }
    }
}

/// A user-mode CPU fault whose signal is CAUGHT becomes real signal
/// delivery: cpu.rs rebuilt the interrupted UCtx from the trap
/// stubs' saved registers, we pend the signo and run it through the
/// same maybe_deliver frame-push/redirect a kill() would get. The
/// returned (rip, rsp, rdi) is spliced into the trap frame so the
/// exception iretq lands in the handler — sigreturn later restores
/// the fault-time context (re-faulting if unfixed, exactly like
/// Linux). A default or ignored disposition dies synchronously —
/// IGN on a synchronous fault can't resume (Linux force_sig).
pub fn fault_signal(signo: u64, code: i32, addr: u64, ctx: &mut UCtx) -> (u64, u64, u64) {
    let cur = unsafe { *core::ptr::addr_of!(CUR_I) };
    let tasks = unsafe { &mut *core::ptr::addr_of_mut!(TASKS) };
    if let Some(t) = tasks.get_mut(cur).and_then(|s| s.as_mut()) {
        let caught = sigt(t)
            .handlers
            .get(signo.saturating_sub(1) as usize)
            .copied()
            .unwrap_or(SIG_DFL)
            > SIG_IGN;
        if caught {
            let i = (signo - 1).min(31) as usize;
            if t.pending & (1u32 << i) == 0 {
                t.pend_src[i] = SigSrc {
                    code,
                    pid: 0,
                    uid: 0,
                    aux: addr,
                };
            }
            t.pending |= 1u32 << i;
            maybe_deliver(t, ctx);
            if t.state == TaskState::Runnable {
                return (ctx.rip, ctx.rsp, ctx.rdi);
            }
            if t.state == TaskState::Stopped {
                // A job-control stop won the delivery race: resume
                // at the faulting ctx so SIGCONT re-faults into the
                // handler path. Diverges — the CONT'd task restarts
                // from t.ctx via switch_to, never unwinds back here.
                t.ctx = *ctx;
                block_switch();
            }
            // Frame push failed — maybe_deliver already set
            // exit_status=SIGSEGV.
        } else {
            // Default-fatal or IGN on a synchronous fault — die with
            // the bare signo (Linux force_sig semantics).
            t.exit_status = signo;
        }
    }
    task_exit_inner()
}

/// Deliver pending signals into task n's saved ctx for a pick-time
/// resume; false when the delivery killed it (caller re-picks).
fn deliver_for(n: usize) -> bool {
    let st = {
        let t = unsafe { (*core::ptr::addr_of_mut!(TASKS))[n].as_mut().unwrap() };
        if deliverable(t) {
            let mut c = t.ctx;
            maybe_deliver(t, &mut c);
            t.ctx = c;
        }
        t.state
    };
    if st == TaskState::Exited {
        // A fatal signal landed at pick — task_exit_inner's whole
        // zombie/wake side still has to run or a wait4-blocked
        // parent sleeps forever. NT tasks bypass task_exit/die_signal
        // on this path, so record the ledger death here too or object
        // waiters sleep forever and the NT_PROCS slot leaks.
        {
            let t = unsafe { (*core::ptr::addr_of_mut!(TASKS))[n].as_mut().unwrap() };
            if t.pers == PERS_NT {
                let code = nt_sig_ntstatus(t.exit_status & 0x7f);
                nt_thread_dead(t.pid, code);
                nt_proc_dead(t.tgid, t.pid, code);
            }
        }
        exit_bookkeeping(n);
        return false;
    }
    st == TaskState::Runnable
}

/// pick_next + signal delivery: the chosen task's ctx is rewritten
/// before resume — a default-fatal signal marks it Exited and the
/// loop picks again.
fn pick_ready() -> Option<usize> {
    reap_dead_threads();
    loop {
        let n = pick_next()?;
        if deliver_for(n) {
            return Some(n);
        }
    }
}

/// At the end of a syscall, apply pending signals to the return ctx.
/// A handler redirects the resume image; a default-fatal signal
/// dies exactly like exit() — this never returns to the dead task.
pub fn deliver_current(ctx: &mut UCtx) {
    let cur = unsafe { *core::ptr::addr_of!(CUR_I) };
    if cur == usize::MAX {
        return;
    }
    let (dead, stopped) = {
        let tasks = unsafe { &mut *core::ptr::addr_of_mut!(TASKS) };
        match tasks.get_mut(cur).and_then(|s| s.as_mut()) {
            Some(t) => {
                maybe_deliver(t, ctx);
                if t.state == TaskState::Stopped {
                    // Resume image = the post-syscall ctx — rax keeps
                    // the syscall's result across the stop.
                    t.ctx = *ctx;
                }
                (t.state == TaskState::Exited, t.state == TaskState::Stopped)
            }
            None => (false, false),
        }
    };
    if dead {
        task_exit_inner() // exit_status already carries the signo
    }
    if stopped {
        // Never returns — SIGCONT makes us Runnable again later.
        block_switch();
    }
}

/// Per-target signal pendent shared by kill()/kill_pgrp: pends the
/// signal, applies the SIGCONT/STOP/KILL state transitions, and
/// wakes a Blocked target with -EINTR when the signal interrupts.
/// Returns Some((pid, pgid, ppid)) when it resumed a Stopped task —
/// the caller reports the WCONTINUED event to the parent after the
/// iteration (re-walking TASKS mid-loop would alias the borrow).
fn pend_one(t: &mut Task, sig: u64, src: SigSrc) -> Option<(u64, u64, u64)> {
    if t.state == TaskState::Exited {
        return None;
    }
    let mut contd = None;
    if sig as usize == SIGCONT {
        // CONT dequeues pending stops, resumes a stopped task, and
        // still pends itself — a caught handler wants the event.
        t.pending &= !(0xfu32 << (SIGSTOP - 1)); // sigs 19..22
        for i in SIGSTOP - 1..SIGSTOP + 3 {
            t.pend_src[i] = SIGSRC_NONE;
        }
        if t.pending & (1u32 << (SIGCONT - 1)) == 0 {
            t.pend_src[SIGCONT - 1] = src;
        }
        t.pending |= 1u32 << (SIGCONT - 1);
        if t.state == TaskState::Stopped {
            t.state = TaskState::Runnable;
            t.cont_report = true;
            contd = Some((t.pid, t.pgid, t.ppid));
        }
    } else {
        if sig as usize == SIGSTOP {
            t.pending &= !(1u32 << (SIGCONT - 1)); // STOP drops CONT
            t.pend_src[SIGCONT - 1] = SIGSRC_NONE;
        }
        if t.pending & (1u32 << (sig - 1)) == 0 {
            t.pend_src[sig as usize - 1] = src;
        }
        t.pending |= 1u32 << (sig - 1);
        if t.state == TaskState::Stopped && sig as usize == SIGKILL {
            // A stopped task resumes only to die on the next pick.
            t.state = TaskState::Runnable;
        }
    }
    // Wake a blocked target only when the signal actually interrupts:
    // an ignored disposition (SIG_IGN, or a default-ignore signal)
    // must not turn a sleeping syscall into a spurious EINTR.
    let ignored = sig_ignored(t, sig);
    // SigTimed (sigwait*/signalfd): an in-set signal is CONSUMED —
    // dequeued into the record buffer, never delivered. Out-of-set
    // signals that can't be delivered (masked, or ignored) leave the
    // sleeper alone; a deliverable one falls through to the generic
    // -EINTR wake like any other wait.
    if t.state == TaskState::Blocked && matches!(t.wait_on, WaitOn::SigTimed) {
        if !ignored && t.wait_len & (1u64 << (sig - 1)) != 0 {
            t.pending &= !(1u32 << (sig - 1));
            let fd_shape = t.wait_ptr2 != 0;
            if t.wait_ptr != 0 {
                // siginfo_t and signalfd_siginfo share s[i]_signo@0;
                // the union fields land at their layout offsets.
                let rec = sig_record(t, sig, fd_shape);
                write_task_bytes(t.pml4, t.wait_ptr, &rec);
            } else {
                t.pend_src[sig as usize - 1] = SIGSRC_NONE;
            }
            // sigwait* returns the signo; signalfd-read returns 128.
            t.ctx.rax = if t.wait_ptr2 != 0 { 128 } else { sig };
            t.wait_on = WaitOn::None;
            t.wait_ptr = 0;
            t.wait_len = 0;
            t.wait_deadline = 0;
            t.wait_ptr2 = 0;
            t.state = TaskState::Runnable;
            return contd;
        }
        if !deliverable(t) {
            return contd;
        }
    }
    if t.state == TaskState::Blocked && !ignored && !matches!(t.wait_on, WaitOn::Vfork(_)) {
        // A nanosleep interrupted by this signal reports the unslept
        // remainder in rem (stored in wait_ptr) — Linux semantics.
        let mut rax: u64 = (-4i64) as u64; // -EINTR
        if matches!(t.wait_on, WaitOn::Timer) {
            if t.wait_ptr != 0 {
                let now = crate::apic::TICKS.load(core::sync::atomic::Ordering::Relaxed);
                let left = t.wait_deadline.saturating_sub(now);
                let rem = t.wait_ptr;
                write_task_bytes(t.pml4, rem, &(left / 100).to_le_bytes());
                write_task_bytes(t.pml4, rem + 8, &((left % 100) * 10_000_000).to_le_bytes());
            }
            // clock_nanosleep's ABI returns EINTR positive.
            if t.wait_ptr2 != 0 {
                rax = 4;
            }
        }
        t.ctx.rax = rax;
        // SigWait (pause/sigsuspend) ordering matters: the waking
        // signal must be DELIVERED while the temporary mask is still
        // installed — Linux runs the handler inside the suspend, then
        // restores the mask on the -EINTR return. Delivering after
        // psel_restore would re-mask the pending signal and the
        // handler would never run. SigTimed wakes this way only on
        // an out-of-set signal — in-set ones were consumed above.
        if matches!(t.wait_on, WaitOn::SigWait | WaitOn::SigTimed) {
            // If a psel/sigsuspend mask restore is owed and a handler
            // frame gets pushed, the restore rides IN THE FRAME —
            // the handler's sigreturn is the suspend's return point.
            // Handler runs under temp|sa_mask|self meanwhile.
            t.frame_mask = t.psel_mask;
            let mut c = t.ctx;
            maybe_deliver(t, &mut c);
            t.ctx = c;
            if t.frame_mask == u64::MAX && t.psel_mask != u64::MAX {
                // A frame consumed the owed restore — nothing left
                // for psel_restore to do below.
                t.psel_mask = u64::MAX;
            }
            t.frame_mask = u64::MAX;
        }
        t.wait_on = WaitOn::None;
        t.wait_ptr = 0;
        t.wait_len = 0;
        t.wait_deadline = 0;
        t.wait_ptr2 = 0;
        psel_restore(t);
        // maybe_deliver can take the task straight to Exited or
        // Stopped (fatal/stop default) — only resume the survivors.
        if t.state == TaskState::Blocked {
            t.state = TaskState::Runnable;
        }
    }
    contd
}

/// Parent-side notification of a child's stop/continue event: wake
/// a wait4 caller whose option flags (carried in wait_len) cover
/// this event class and whose pid/pgrp selector matches, then
/// raise the parent's SIGCHLD — Linux's do_notify_parent pair.
fn child_change(cpid: u64, cpgid: u64, cppid: u64, status: u64, flag: u64) {
    if cppid == 0 {
        return;
    }
    let tasks = unsafe { &mut *core::ptr::addr_of_mut!(TASKS) };
    let mut delivered = false;
    for s in tasks.iter_mut() {
        let Some(p) = s else { continue };
        if p.state == TaskState::Blocked
            && p.pid == cppid
            && p.wait_len & flag != 0
            && (p.wait_on == WaitOn::Any
                || p.wait_on == WaitOn::Child(cpid)
                || p.wait_on == WaitOn::Group(cpgid))
        {
            p.ctx.rax = cpid;
            if p.wait_ptr != 0 {
                if let Some(pa) = translate(p.pml4, p.wait_ptr) {
                    // SAFETY: pa is a writable user dword in p's map.
                    unsafe { (pa as *mut u32).write_unaligned(status as u32) };
                }
            }
            p.state = TaskState::Runnable;
            p.wait_on = WaitOn::None;
            p.wait_ptr = 0;
            p.wait_len = 0;
            delivered = true;
        }
    }
    // A delivered report is consumed — without this, the child's
    // still-set flag makes the NEXT wait4 re-emit the same event.
    if delivered {
        if let Some(c) = tasks.iter_mut().flatten().find(|t| t.pid == cpid) {
            if flag == WUNTRACED {
                c.stop_sig = 0;
            }
            if flag == WCONTINUED {
                c.cont_report = false;
            }
        }
    }
    // SIGCHLD carries the real CLD_* si_code + si_status: the stop
    // signal for CLD_STOPPED, SIGCONT for CLD_CONTINUED.
    let (code, st) = if flag == WUNTRACED {
        (CLD_STOPPED, ((status >> 8) & 0xff) as i32)
    } else if flag == WCONTINUED {
        (CLD_CONTINUED, SIGCONT as i32)
    } else {
        cld_code(status)
    };
    if let Some(p) = tasks.iter_mut().flatten().find(|t| t.pid == cppid) {
        pend_one(
            p,
            SIGCHLD as u64,
            SigSrc {
                code,
                pid: cpid as u32,
                uid: 0,
                aux: st as u64,
            },
        );
    }
}

/// Signal every member of a process group — shared by kill(-pgid),
/// the tty ^C/^\/^Z path, and the SIGTTIN job-control gate.
fn kill_pgrp(pgid: u64, sig: u64) {
    let tasks = unsafe { &mut *core::ptr::addr_of_mut!(TASKS) };
    let mut conts = [(0u64, 0u64, 0u64); MAX_TASKS];
    let mut ncont = 0usize;
    for s in tasks.iter_mut() {
        let Some(t) = s else { continue };
        if t.pgid == pgid {
            if let Some(c) = pend_one(t, sig, SIGSRC_NONE) {
                conts[ncont] = c;
                ncont += 1;
            }
        }
    }
    for c in conts.iter().take(ncont) {
        child_change(c.0, c.1, c.2, 0xffff, WCONTINUED);
    }
}

/// kill(pid, sig): pend a signal on the target set. pid > 0 is one
/// task; pid == 0 the caller's own group; pid == -1 every task but
/// the caller; pid < -1 the group -pid. sig 0 is the existence
/// probe — 0 when a target exists, ESRCH otherwise. Zombie targets
/// accept the signal silently like Linux.
pub fn kill(pid: i64, sig: u64) -> u64 {
    const ESRCH: u64 = (-3i64) as u64;
    if sig > 31 {
        return EINVAL;
    }
    let tasks = unsafe { &mut *core::ptr::addr_of_mut!(TASKS) };
    let cur = unsafe { *core::ptr::addr_of!(CUR_I) };
    let (my_pid, my_pgid) = tasks
        .get(cur)
        .and_then(|s| s.as_ref())
        .map(|t| (t.pid, t.pgid))
        .unwrap_or((0, 0));
    let hits = |t: &Task| {
        if pid > 0 {
            t.pid == pid as u64
        } else if pid == 0 {
            t.pgid == my_pgid
        } else if pid == -1 {
            t.pid != my_pid
        } else {
            t.pgid == (-pid) as u64
        }
    };
    if sig == 0 {
        return if tasks.iter().flatten().any(|t| hits(t)) {
            0
        } else {
            ESRCH
        };
    }
    let mut conts = [(0u64, 0u64, 0u64); MAX_TASKS];
    let mut ncont = 0usize;
    let mut found = false;
    let src = SigSrc {
        code: SI_USER,
        pid: my_pid as u32,
        uid: 0,
        aux: 0,
    };
    for s in tasks.iter_mut() {
        let Some(t) = s else { continue };
        if hits(t) {
            found = true;
            if let Some(c) = pend_one(t, sig, src) {
                conts[ncont] = c;
                ncont += 1;
            }
        }
    }
    if !found {
        return ESRCH;
    }
    for c in conts.iter().take(ncont) {
        child_change(c.0, c.1, c.2, 0xffff, WCONTINUED);
    }
    0
}

/// rt_sigaction(sig, act, oldact, sigsetsize): read/swap the kernel
/// sigaction {handler@0, flags@8, restorer@16, mask@24} — handler is
/// 0=SIG_DFL, 1=SIG_IGN, else a user VA (validated at delivery, like
/// Linux). The restorer field is accepted but ignored — delivery
/// always returns through SIGTRAMP_VA. SIGKILL/SIGSTOP stay
/// uncatchable.
pub fn sigaction(sig: u64, act: u64, oldact: u64, sigsetsize: u64) -> u64 {
    if sig == 0 || sig > 31 || sigsetsize != 8 {
        return EINVAL;
    }
    let Some(t) = cur_mut() else { return EINVAL };
    let i = (sig - 1) as usize;
    if oldact != 0 {
        if !range_ok_w(oldact, 32) {
            return EFAULT;
        }
        let (h, f, m) = {
            let s = sigt(t);
            (
                s.handlers[i],
                s.flags.get(i).copied().unwrap_or(0) as u64,
                s.masks.get(i).copied().unwrap_or(0) as u64,
            )
        };
        // SAFETY: validated writable user range.
        unsafe {
            (oldact as *mut u64).write_unaligned(h);
            (oldact as *mut u64).add(1).write_unaligned(f);
            (oldact as *mut u64).add(2).write_unaligned(0);
            (oldact as *mut u64).add(3).write_unaligned(m);
        }
    }
    if act != 0 {
        if !range_ok(act, 32) {
            return EFAULT;
        }
        // SAFETY: validated readable user range.
        let (h, f, m) = unsafe {
            (
                (act as *const u64).read_unaligned(),
                (act as *const u64).add(1).read_unaligned(),
                (act as *const u64).add(3).read_unaligned(),
            )
        };
        // SIGKILL/SIGSTOP refuse every disposition change — a task
        // that could ignore SIGKILL would be unkillable by signal.
        if sig as usize == SIGKILL || sig as usize == SIGSTOP {
            return EINVAL;
        }
        let s = sigt(t);
        s.handlers[i] = h;
        s.flags[i] = f as u32;
        s.masks[i] = m as u32;
    }
    0
}

/// rt_sigreturn: restore the interrupted ctx the delivery pushed
/// above the restorer word — rsp at stub entry is frame+8, so the
/// UCtx sits at rsp+8 (frame layout [restorer][signo][UCtx]).
/// Every byte is user-owned, so
/// the privilege fields are pinned, not trusted — cs=0x33, ss=0x2b,
/// rip inside a user range, rsp inside a writable one, TF/NT/IOPL
/// cleared (the CVE-2014-9322 / SROP hardening). A bad frame kills
/// with SIGSEGV, like Linux.
pub fn sigreturn(ctx: &mut UCtx) -> u64 {
    let frame = ctx.rsp;
    if !range_ok(frame, SIGFRAME_SIZE) {
        die_signal(SIGSEGV as u64);
    }
    let mut saved = UCtx::ZERO;
    // SAFETY: validated user range in the current (caller's) space.
    unsafe {
        core::ptr::copy_nonoverlapping(
            (frame + 8) as *const u8,
            &mut saved as *mut UCtx as *mut u8,
            160,
        )
    };
    saved.cs = 0x33;
    saved.ss = 0x2b;
    saved.rflags = (saved.rflags | 0x2) & !(0x100 | 0x3000 | 0x4000);
    // rsp == stack_top is legal (empty stack): require the byte
    // BELOW rsp — the first push target — to be writable user space.
    if saved.rip >= 0x8000_0000_0000
        || saved.rsp >= 0x8000_0000_0000
        || !range_ok(saved.rip, 1)
        || !range_ok_w(saved.rsp.wrapping_sub(1), 1)
    {
        die_signal(SIGSEGV as u64);
    }
    // The pre-delivery sigmask sits at frame+304 (rsp+296): delivery
    // saved it before applying sa_mask|self; restoring it is both
    // the handler-scope block and Linux's let-user-edit-uc_sigmask
    // semantic in one.
    if let Some(t) = cur_mut() {
        // SAFETY: validated user range in the caller's space.
        let m = unsafe { ((frame + 296) as *const u64).read_unaligned() };
        t.sigmask = m as u32;
    }
    *ctx = saved;
    ctx.rax // restored rax IS the return value
}

/// An open file description — the Linux `struct file` analog. fds
/// are only slots pointing here; dup'd slots share one OFD, which is
/// why the seek offset lives here and not in the slot.
struct OpenFile {
    kind: FdKind,
    pos: usize,
    /// fd slots pointing at this OFD; freed at zero.
    refs: usize,
    /// O_APPEND: every write lands at end-of-file regardless of pos.
    append: bool,
    /// O_ACCMODE at open (0 rdonly/1 wronly/2 rdwr) — f_mode analogue.
    accmode: u8,
}

/// A resident task: every resource it owns, in one owned bundle.
pub struct Task {
    /// Physical base of the process PML4.
    pml4: u64,
    entry: u64,
    stack_top: u64,
    /// kmalloc'd syscall stack; top is the rsp the entry stub loads.
    kstack_base: u64,
    kstack_top: u64,
    /// [lo, hi) address ranges user pointers may legally reference,
    /// with access bits (RNG_R=1 / RNG_W=2). The syscall layer's
    /// user-pointer gate walks exactly this table — PROT_NONE entries
    /// (flags 0) reserve VA but fail both gates, like Linux EFAULT.
    ranges: [(u64, u64, u8); MAX_RANGES],
    nranges: usize,
    /// Program break bookkeeping: brk_base is the aligned end of the
    /// loaded image (heap start), brk_cur the current break in bytes
    /// (page granularity underneath, like Linux VMAs).
    brk_base: u64,
    brk_cur: u64,
    /// Index into FDTABS — this task fd table. CLONE_FILES
    /// children share the parent index; fork duplicates it.
    fdi: u8,
    /// Index into SIGTABS — the disposition table. CLONE_SIGHAND
    /// children share the parent index; fork duplicates it.
    sigh: u8,
    /// Index into FSTABS — the fs_struct analogue (umask today,
    /// cwd/root when the fs grows them). CLONE_FS shares the index;
    /// fork duplicates it.
    fsi: u8,
    /// Thread-group id: the leader's pid. getpid() reports tgid,
    /// gettid() reports pid; a non-leader thread has tgid != pid.
    tgid: u64,
    /// Saved user context for switches — fabricated at spawn, then
    /// snapshotted by the timer IRQ on every preemption.
    ctx: UCtx,
    state: TaskState,
    /// Process identity — Linux-visible pid and parent pid (0 = none).
    pid: u64,
    ppid: u64,
    /// The wait status wait4 reports: (exit_code << 8) normally, or
    /// the raw signo in the low byte for a signal death — the real
    /// Linux wstatus layout.
    exit_status: u64,
    /// What this task is Blocked on (None when not Blocked).
    wait_on: WaitOn,
    /// wait4 status VA, or the user buffer for a blocked pipe io.
    wait_ptr: u64,
    /// Blocked pipe io length (unused by wait4).
    wait_len: u64,
    /// Second wait pointer — recvfrom's sockaddr out VA (0 = none).
    wait_ptr2: u64,
    /// Third wait pointer — pselect6's exceptfds VA (0 = none).
    wait_ptr3: u64,
    /// pselect6's saved sigmask — u64::MAX when no restore is owed.
    /// The syscall applies the caller's set for the sleep and the
    /// wake paths restore this one before userspace resumes.
    psel_mask: u64,
    /// Mask a delivered signal frame should restore on sigreturn
    /// when it differs from t.sigmask at push time — set for
    /// in-wake deliveries where a psel restore is owed (the
    /// handler's sigreturn IS the suspend's return point), cleared
    /// by the frame push. u64::MAX when no override is set.
    frame_mask: u64,
    /// apic::TICKS deadline for a timed Poll wait — 0 means none.
    wait_deadline: u64,
    /// Pending signal bitmask — bit (sig-1), sigs 1..=31.
    pending: u32,
    /// si_code/pid/uid/aux behind each pending bit — written on the
    /// 0->1 transition so first-pend info wins the standard-signal
    /// merge, consumed at delivery into the siginfo record.
    pend_src: [SigSrc; 31],
    /// rt_sigprocmask mask — set bits block delivery of the matching
    /// pending signal (masked-pending stays pending for later). Fork
    /// inherits it, exec preserves it. The mask may contain SIGKILL's
    /// bit like Linux, but delivery ignores it — see unmasked_pending.
    sigmask: u32,
    /// comm — argv0 basename / PR_SET_NAME. Copied at spawn,
    /// inherited at fork, replaced at exec.
    name: [u8; 16],
    /// The image's canonical path — /proc/self/exe resolves to it.
    /// Copied at spawn, inherited at fork, replaced at exec. Separate
    /// from comm: a forked "sh" re-execing /proc/self/exe must get
    /// the real binary path, not the applet name.
    exe: [u8; 128],
    exe_len: u8,
    /// The task's user FS base (TLS pointer) — set via arch_prctl,
    /// restored to MSR_FS_BASE on every switch like the fx image.
    /// Users can't desync it: FSGSBASE is never enabled.
    fs_base: u64,
    /// Registered rseq area VA (0 = none). Per-task like Linux —
    /// not inherited at fork, implicitly dropped at exec.
    rseq_va: u64,
    /// CLONE_CHILD_CLEARTID address in this task's address space —
    /// zeroed at exit with a futex wake on it (pthread_join's wait).
    clear_ctid: u64,
    /// Process-group id (pid of the group's leader). Fork/clone
    /// inherit; setpgid moves a task within its own session.
    pgid: u64,
    /// Session id (pid of the session leader). Fork inherits;
    /// setsid starts a new one and drops the controlling tty.
    sid: u64,
    /// Exec'd at least once since fork — blocks a parent's later
    /// setpgid on it (Linux's EACCES rule).
    did_exec: bool,
    /// Syscall personality: PERS_LINUX (the whole table above) or
    /// PERS_NT (nt::dispatch — NTSTATUS, r10-arg1, stack args at
    /// rsp+0x28). Set by the image format at exec/spawn.
    pers: u8,
    /// The task's user GS base — NT tasks point it at their TEB
    /// page (Windows threads read TEB fields via gs:[]); restored
    /// to MSR_GS_BASE on every switch like fs_base.
    gs_base: u64,
    /// NT handle table — small indices like the real one; slots
    /// hold nt::NTH_* object tags. Fork copies it (a cloned
    /// handle stays open in the child like DuplicateHandle).
    nth: [u8; crate::nt::MAX_NTH],
    /// The task fd a NTH_FILE handle slot owns (0xff = none).
    nth_fd: [u8; crate::nt::MAX_NTH],
    /// Directory wildcard stored by the FileName arg of the first
    /// NtQueryDirectoryFile on a dir handle — [0]=len, [1..]=bytes.
    nth_dirpat: [[u8; 96]; crate::nt::MAX_NTH],
    /// Process-heap block table: [addr, size, state] where state is
    /// 0 empty / 1 live / 2 free-block. Kernel-side metadata means
    /// an app can corrupt its heap CONTENTS but never the block
    /// structure — invalid/double frees return FALSE like real
    /// Windows instead of poisoning a userspace free list.
    heap_blk: [[u64; 3]; 128],
    /// Heap bump cursor (next unallocated VA) and committed top;
    /// pages are mapped lazily as allocs cross HEAP_VA upward.
    heap_bump: u64,
    heap_commit: u64,
    /// NT anonymous-VM bump cursor — NtAllocateVirtualMemory
    /// hands out pages upward from NT_ALLOC_VA.
    nt_alloc: u64,
    /// .tls template VA/span for per-thread copies (0 when the
    /// image has no TLS directory) and the emitted thread-exit
    /// stub's VA — set at PE load, used by nt_thread_create.
    tls_tmpl_va: u64,
    tls_tmpl_sz: u64,
    thr_exit_va: u64,
    thr_entry_va: u64,
    /// Thunk-stub bump cursor — the exe's import thunks start at
    /// STUB_VA and every later-mapped DLL continues from here (0 =
    /// uninitialized, lazily set to STUB_VA on first emit).
    nt_stub: u64,
    /// The signal that stopped this task (0 = not stop-reported).
    /// wait4 WUNTRACED consumes it once per stop.
    stop_sig: u8,
    /// Resumed by SIGCONT since the last WCONTINUED report —
    /// consumed once per continue, like stop_sig.
    cont_report: bool,
    /// apic::TICKS at spawn — /proc/<pid>/stat's starttime (field 22)
    /// is in ticks-since-boot like Linux's jiffies figure.
    start_ticks: u64,
    /// Ticks preempted on a user frame (utime) or a kernel frame
    /// (stime) — tick() bills CUR_I each interrupt. These feed
    /// /proc/<pid>/stat fields 14/15 and the /proc/stat cpu row,
    /// so `top` shows real utilization. Children start at zero
    /// (Linux forks fresh accounting).
    utime: u64,
    stime: u64,
    /// NUL-joined argv captured at exec() — /proc/<pid>/cmdline's
    /// real content. Bounded: extra args are truncated at the cap,
    /// so a malformed execve can't grow kernel memory. Empty until
    /// the first exec — proc falls back to the exe path then.
    cmdline: [u8; 256],
    cmdline_len: u8,
    /// Per-task FPU/SSE state -- fxsave'd on every way out,
    /// fxrstor'd on every resume so xmm state never crosses tasks.
    fx: FxState,
}

/// Max open file descriptions system-wide — a hard bound so fd
/// pressure from one task can't exhaust kernel memory. OFDs are
/// GLOBAL (not per-task) because fork MUST share them: a child's
/// fds name the same descriptions — same offsets, same refs —
/// exactly like Linux's files_struct sharing of struct file.
static mut OFDS: [Option<OpenFile>; MAX_OFDS] = [const { None }; MAX_OFDS];
/// Per-OFD delete-pending — Windows FileDispositionInformation.
/// An OFD flagged here unlinks its vfile at last close, the
/// FILE_DELETE_ON_CLOSE semantic (POSIX unlink-while-open falls
/// out of vfile_remove's live-OFD check for free).
static mut OFD_DEL: [u8; MAX_OFDS] = [0; MAX_OFDS];

/// A task fd table — the files_struct analogue. The table is the OFD
/// owner: users counts referencing TASKS, and each fd slot points at
/// a global OFD whose refs count one per TABLE, not per task.
/// CLONE_FILES shares the index (users++); fork duplicates the slots
/// and bumps each named OFD.
#[derive(Clone, Copy)]
struct FdTab {
    users: u8,
    /// Per-fd O_CLOEXEC bits — fd-level state, so dup clears it and
    /// fcntl F_SETFD owns it; exec closes every set fd. MAX_FDS=16
    /// fits a u16.
    cloexec: u16,
    /// fd slots -> GLOBAL OFD indices; 0/1/2 pre-seeded std streams.
    fds: [Option<u8>; MAX_FDS],
}
const FDT_EMPTY: FdTab = FdTab { users: 0, cloexec: 0, fds: [None; MAX_FDS] };
/// Task-slot parity plus CLONE_FILES slack (threads share the
/// leader's table) — a full table ENOMEMs, never
/// corrupts, same discipline as MM_REFS.
const MAX_FDTABS: usize = 64;
/// Task.fdi sentinel after release — makes a second release_fds a
/// no-op instead of a double-decrement.
const FDI_NONE: u8 = u8::MAX;
static mut FDTABS: [FdTab; MAX_FDTABS] = [FDT_EMPTY; MAX_FDTABS];

/// The task live fd table. Returns &mut into a global — callers
/// hold no borrow on FDTABS itself, mirroring the TASKS discipline.
#[allow(clippy::mut_from_ref)]
fn fdt(t: &Task) -> &mut FdTab {
    unsafe { &mut (*core::ptr::addr_of_mut!(FDTABS))[t.fdi as usize] }
}

/// Take a free table slot (users=1). None means the table is full.
fn fdtab_alloc() -> Option<u8> {
    let ts = unsafe { &mut *core::ptr::addr_of_mut!(FDTABS) };
    ts.iter().position(|x| x.users == 0).map(|i| {
        ts[i] = FDT_EMPTY;
        ts[i].users = 1;
        i as u8
    })
}

/// Duplicate src slots into a fresh table and bump every named OFD —
/// the fork side of files_struct sharing.
fn fdtab_dup(src: u8) -> Option<u8> {
    let i = fdtab_alloc()? as usize;
    let ts = unsafe { &mut *core::ptr::addr_of_mut!(FDTABS) };
    ts[i] = FdTab { users: 1, ..ts[src as usize] };
    let ofds = unsafe { &mut *core::ptr::addr_of_mut!(OFDS) };
    for s in ts[i].fds.iter().flatten() {
        if let Some(o) = ofds.get_mut(*s as usize).and_then(|x| x.as_mut()) {
            o.refs += 1;
        }
    }
    Some(i as u8)
}

/// CLONE_FILES: another task points at the same table.
fn fdtab_share(i: u8) {
    unsafe { (*core::ptr::addr_of_mut!(FDTABS))[i as usize].users += 1 };
}

/// exit_files: drop this task reference; the LAST user releases
/// each slot OFD exactly like put_files_struct.
fn fdtab_release(i: u8) {
    if i == FDI_NONE {
        return;
    }
    let ts = unsafe { &mut *core::ptr::addr_of_mut!(FDTABS) };
    let tb = &mut ts[i as usize];
    tb.users -= 1;
    if tb.users != 0 {
        return;
    }
    for s in tb.fds.iter_mut() {
        if let Some(o) = s.take() {
            ofd_release(o as usize);
        }
    }
    tb.cloexec = 0;
}

/// A task signal-disposition table — the sighand_struct analogue.
/// CLONE_SIGHAND shares the index (users++); fork duplicates it.
/// sigaction on one thread is visible to every sharer.
#[derive(Clone, Copy)]
struct SigTab {
    users: u8,
    handlers: [u64; 31],
    /// rt_sigaction sa_flags per signal (SA_SIGINFO/NODEFER/
    /// RESETHAND are the honored bits).
    flags: [u32; 31],
    /// rt_sigaction sa_mask per signal — extra signals blocked
    /// while the handler runs (the sig bit itself joins unless
    /// SA_NODEFER).
    masks: [u32; 31],
}
const SIGH_EMPTY: SigTab = SigTab {
    users: 0,
    handlers: [0; 31],
    flags: [0; 31],
    masks: [0; 31],
};
const MAX_SIGTABS: usize = 64;
/// Task.sigh sentinel after release — second release is a no-op.
const SIGH_NONE: u8 = u8::MAX;
static mut SIGTABS: [SigTab; MAX_SIGTABS] = [SIGH_EMPTY; MAX_SIGTABS];

/// The task live disposition table — same global-table discipline
/// as fdt().
#[allow(clippy::mut_from_ref)]
fn sigt(t: &Task) -> &mut SigTab {
    unsafe { &mut (*core::ptr::addr_of_mut!(SIGTABS))[t.sigh as usize] }
}

fn sigtab_alloc() -> Option<u8> {
    let ts = unsafe { &mut *core::ptr::addr_of_mut!(SIGTABS) };
    ts.iter().position(|x| x.users == 0).map(|i| {
        ts[i] = SIGH_EMPTY;
        ts[i].users = 1;
        i as u8
    })
}

/// Fork side: private copy of the parent's dispositions.
fn sigtab_dup(src: u8) -> Option<u8> {
    let i = sigtab_alloc()? as usize;
    let ts = unsafe { &mut *core::ptr::addr_of_mut!(SIGTABS) };
    ts[i] = SigTab { users: 1, ..ts[src as usize] };
    Some(i as u8)
}

/// CLONE_SIGHAND: another task points at the same table.
fn sigtab_share(i: u8) {
    unsafe { (*core::ptr::addr_of_mut!(SIGTABS))[i as usize].users += 1 };
}

fn sigtab_release(i: u8) {
    if i == SIGH_NONE {
        return;
    }
    let ts = unsafe { &mut *core::ptr::addr_of_mut!(SIGTABS) };
    ts[i as usize].users -= 1;
}

/// The shared fs_struct analogue (CLONE_FS): what would be root +
/// pwd + umask on Linux. Our fs is flat (no cwd/root state yet), so
/// the table carries umask alone — the shape is right for the day
/// real cwd lands. Same ledger discipline as FDTABS/SIGTABS.
#[derive(Clone, Copy)]
struct FsTab {
    users: u8,
    umask: u16,
    /// Working directory — the canonical flat name ("" = root).
    /// CLONE_FS shares it, so a sibling chdir moves the group.
    cwd: [u8; 128],
    cwdlen: u8,
}
const FS_EMPTY: FsTab = FsTab { users: 0, umask: 0, cwd: [0; 128], cwdlen: 0 };
const MAX_FSTABS: usize = 64;
/// Task.fsi sentinel after release.
const FSI_NONE: u8 = u8::MAX;
static mut FSTABS: [FsTab; MAX_FSTABS] = [FS_EMPTY; MAX_FSTABS];

/// The task live fs table — same global-table discipline as fdt().
#[allow(clippy::mut_from_ref)]
fn fst(t: &Task) -> &mut FsTab {
    unsafe { &mut (*core::ptr::addr_of_mut!(FSTABS))[t.fsi as usize] }
}

fn fstab_alloc(umask: u16) -> Option<u8> {
    let ts = unsafe { &mut *core::ptr::addr_of_mut!(FSTABS) };
    ts.iter().position(|x| x.users == 0).map(|i| {
        ts[i] = FsTab { users: 1, umask, cwd: [0; 128], cwdlen: 0 };
        i as u8
    })
}

/// Fork side: private copy (umask included) of the parent's table.
fn fstab_dup(src: u8) -> Option<u8> {
    let i = fstab_alloc(0)? as usize;
    let ts = unsafe { &mut *core::ptr::addr_of_mut!(FSTABS) };
    ts[i] = FsTab { users: 1, ..ts[src as usize] };
    Some(i as u8)
}

/// CLONE_FS: another task points at the same table.
fn fstab_share(i: u8) {
    unsafe { (*core::ptr::addr_of_mut!(FSTABS))[i as usize].users += 1 };
}

fn fstab_release(i: u8) {
    if i == FSI_NONE {
        return;
    }
    let ts = unsafe { &mut *core::ptr::addr_of_mut!(FSTABS) };
    ts[i as usize].users -= 1;
}

/// The shared open-file-description table. 64 tasks hold 3 std OFDs
/// each (192 worst case) before a single pipe/socket exists — 64
/// and 192 were both real transient-ENOMEMs under
/// scheduling-dependent occupancy.
const MAX_OFDS: usize = 256;

/// RAM-backed scratch files — the writable half of the flat
/// namespace. Linux mounts a tmpfs; our tmpfs is this table:
/// cpio names are read-only, VFILES names are created, written,
/// truncated, renamed and unlinked. Bounded so untrusted fd churn
/// can't exhaust frames.
const MAX_VFILES: usize = 32;
/// Per-file ceiling — an honest ENOSPC, not an unbounded grow.
const VFILE_MAX: usize = 1 << 20;

/// A scratch file: kmalloc'd contents + a fixed name slot. `unlinked`
/// survives removal while fds still name it — Linux's open-unlink
/// semantics: the OFD keeps working until its last close frees data.
/// `is_link` marks a symlink: `data` then holds the raw target text
/// (no NUL — readlink echoes bytes verbatim). mode/uid/gid and the
/// three timestamps are stored like a real inode — chmod/chown/
/// utimensat mutate them and stat reports them.
struct VFile {
    name: [u8; 128],
    nlen: usize,
    data: *mut u8,
    len: usize,
    cap: usize,
    unlinked: bool,
    is_link: bool,
    /// S_IFMT bits — S_IFREG for regulars and (harmlessly) links,
    /// S_IFCHR/S_IFBLK/S_IFIFO for mknod'd nodes.
    fmt: u32,
    /// Device id for S_IFCHR/S_IFBLK nodes — makedev(major<<8|minor).
    rdev: u32,
    mode: u16,
    uid: u32,
    gid: u32,
    atime: u64,
    atime_ns: u32,
    mtime: u64,
    mtime_ns: u32,
    ctime: u64,
    ctime_ns: u32,
}
// SAFETY: VFILES slots own their buffers; single-CPU, IF-masked
// context means no concurrent access. Raw ptr never escapes.
static mut VFILES: [Option<VFile>; MAX_VFILES] = [const { None }; MAX_VFILES];

/// Slot of the live VFile named `path`, or None.
fn vfile_find(path: &[u8]) -> Option<usize> {
    let vs = unsafe { &*core::ptr::addr_of!(VFILES) };
    vs.iter().position(|v| {
        v.as_ref().is_some_and(|v| !v.unlinked && &v.name[..v.nlen] == path)
    })
}

/// The VFile backing OFD index `i` — FdKind::Ram names VFILES[i].
fn vfile(i: usize) -> Option<&'static mut VFile> {
    let vs = unsafe { &mut *core::ptr::addr_of_mut!(VFILES) };
    vs.get_mut(i)?.as_mut()
}

/// Create a VFile named `path` — ENOSPC at the table bound,
/// ENAMETOOLONG past the name slot. Returns the slot index.
fn vfile_create(path: &[u8]) -> u64 {
    const ENOSPC_: u64 = (-28i64) as u64;
    const ENAMETOOLONG_: u64 = (-36i64) as u64;
    if path.is_empty() || path.len() > 128 {
        return ENAMETOOLONG_;
    }
    let vs = unsafe { &mut *core::ptr::addr_of_mut!(VFILES) };
    let Some(i) = vs.iter().position(Option::is_none) else {
        return ENOSPC_;
    };
    let mut v = VFile {
        name: [0; 128],
        nlen: path.len(),
        data: core::ptr::null_mut(),
        len: 0,
        cap: 0,
        unlinked: false,
        is_link: false,
        fmt: 0o100000, // S_IFREG
        rdev: 0,
        mode: 0,
        uid: 0,
        gid: 0,
        atime: 0,
        atime_ns: 0,
        mtime: 0,
        mtime_ns: 0,
        ctime: 0,
        ctime_ns: 0,
    };
    v.name[..path.len()].copy_from_slice(path);
    vs[i] = Some(v);
    i as u64
}

/// Current wall time as (sec, nsec): TICKS is 100 Hz so subsecond
/// granularity is an honest 10 ms — no fake nanosecond noise.
fn now() -> (u64, u32) {
    let t = crate::apic::TICKS.load(core::sync::atomic::Ordering::Relaxed);
    (t / 100, (t % 100) as u32 * 10_000_000)
}

/// Fresh-object metadata: creation mode with the caller's umask
/// applied (umask only ever masks 0o777, setuid bits pass like
/// Linux), owner 0:0, all three timestamps "now".
fn vfile_stamp(v: &mut VFile, mode: u64, umask: u16) {
    let (s, ns) = now();
    v.mode = (mode & 0o7777 & !(umask as u64)) as u16;
    v.uid = 0;
    v.gid = 0;
    v.atime = s;
    v.atime_ns = ns;
    v.mtime = s;
    v.mtime_ns = ns;
    v.ctime = s;
    v.ctime_ns = ns;
}

/// Grow a VFile's buffer to at least `need` bytes — zeroed fresh
/// region, old bytes copied, old buffer kfree'd. ENOSPC past the cap.
fn vfile_grow(v: &mut VFile, need: usize) -> u64 {
    const ENOSPC_: u64 = (-28i64) as u64;
    if need <= v.cap {
        return 0;
    }
    if need > VFILE_MAX {
        return ENOSPC_;
    }
    let ncap = need.next_power_of_two().clamp(4096, VFILE_MAX);
    let p = kalloc::kmalloc(ncap);
    if p.is_null() {
        return ENOSPC_;
    }
    // SAFETY: fresh buffer owns ncap bytes; copy stays inside both.
    unsafe {
        core::ptr::write_bytes(p, 0, ncap);
        if !v.data.is_null() {
            core::ptr::copy_nonoverlapping(v.data, p, v.len);
            kalloc::kfree(v.data);
        }
    }
    v.data = p;
    v.cap = ncap;
    0
}

/// Process-id allocator — monotonically increasing, never reused.
static mut NEXT_PID: u64 = 0;
fn next_pid() -> u64 {
    unsafe {
        let p = core::ptr::addr_of_mut!(NEXT_PID);
        *p += 1;
        *p
    }
}

impl Task {
    /// free_pgtables, Rustux style: walk the user half of the page
    /// table and return every frame — leaf and table alike — to the
    /// buddy. The page table IS the ledger (CVE-2022-50661 discipline:
    /// teardown freeing is designed in). Slots 0..128 are shared
    /// kernel mappings and must NOT be freed; slots 128..256 are the
    /// user window, entirely task-owned.
    /// Free every frame under user PML4 slots 128..256 — leaf, PT,
    /// PD, PDPT — and clear the slots so the address space can be
    /// reused (exec) or the table freed (reap). Shared kernel slots
    /// 0..127 are never touched.
    fn free_user_mappings(&mut self) {
        for i in 128..256u64 {
            let e = rd64(self.pml4 + 8 * i);
            if e & PRESENT == 0 {
                continue;
            }
            let pdpt = e & PHYS_MASK;
            for j in 0..512u64 {
                let de = rd64(pdpt + 8 * j);
                if de & PRESENT == 0 {
                    continue;
                }
                let pd = de & PHYS_MASK;
                for k in 0..512u64 {
                    let te = rd64(pd + 8 * k);
                    if te & PRESENT == 0 {
                        continue;
                    }
                    let pt = te & PHYS_MASK;
                    for l in 0..512u64 {
                        let leaf = rd64(pt + 8 * l);
                        if leaf & PRESENT != 0 {
                            kalloc::free_frame(leaf & PHYS_MASK);
                        }
                    }
                    kalloc::free_frame(pt);
                }
                kalloc::free_frame(pd);
            }
            kalloc::free_frame(pdpt);
            wr64(self.pml4 + 8 * i, 0);
        }
    }

    /// Drop every fd's reference on its (global) OFD — Linux's
    /// exit_files: shared descriptions outlive the task when
    /// another task still points at them.
    fn release_fds(&mut self) {
        // CLONE_FILES tables are shared: users counts tasks, and the
        // last user drops the slots' OFD refs (put_files_struct).
        // FDI_NONE makes the reap-time second call a no-op.
        let i = self.fdi;
        self.fdi = FDI_NONE;
        fdtab_release(i);
    }

    fn release_sighand(&mut self) {
        let i = self.sigh;
        self.sigh = SIGH_NONE;
        sigtab_release(i);
    }

    fn release_fstab(&mut self) {
        let i = self.fsi;
        self.fsi = FSI_NONE;
        fstab_release(i);
    }

    fn reap(&mut self) {
        self.release_fds();
        self.release_sighand();
        self.release_fstab();
        // NT handle table dies with the Task: refdown whatever its
        // slots still name or the NT_THREADS/NT_PROCS/NT_SECTIONS
        // ledgers leak an entry per abandoned handle. Idempotent —
        // exit_bookkeeping's last-standing sweep already zeroed the
        // table when it ran. NTH_FILE slots need nothing: the fd
        // release above covers them.
        for i in 0..crate::nt::MAX_NTH {
            match self.nth[i] {
                crate::nt::NTH_THREAD => nt_thr_refdown(self.nth_fd[i] as usize),
                crate::nt::NTH_SECTION => nt_sec_refdown(self.nth_fd[i] as usize),
                crate::nt::NTH_PROCESS => nt_proc_refdown(self.nth_fd[i] as usize),
                _ => {}
            }
            self.nth[i] = 0;
            self.nth_fd[i] = 0xff;
        }
        // A shared mm (CLONE_VM) outlives its users — only the last
        // one frees the mappings and the pml4 frame itself.
        if mm_release(self.pml4) {
            self.free_user_mappings();
            kalloc::free_frame(self.pml4);
        }
        if self.kstack_base != 0 {
            // SAFETY: kstack_base came from kmalloc, freed once here.
            unsafe { kalloc::kfree(self.kstack_base as *mut u8) };
            self.kstack_base = 0;
            self.kstack_top = 0;
        }
    }
}

/// The task table — the scheduler's world. Tasks are never moved
/// once slotted: ctx pointers handed to the asm must stay stable.
static mut TASKS: [Option<Task>; MAX_TASKS] = [const { None }; MAX_TASKS];
/// A non-leader thread exited — its slot waits for the sweep; the
/// exit path must not free the kstack/cr3 it still runs on.
static mut DEAD_THREADS: bool = false;

/// Reap exited non-leader threads: fds/sighand already released at
/// exit; this drops the mm user count, frees kstack + slot. Called
/// from the scheduler — never on the dead task's own context.
fn reap_dead_threads() {
    if !unsafe { *core::ptr::addr_of!(DEAD_THREADS) } {
        return;
    }
    unsafe { *core::ptr::addr_of_mut!(DEAD_THREADS) = false };
    let cur = unsafe { *core::ptr::addr_of!(CUR_I) };
    let tasks = unsafe { &mut *core::ptr::addr_of_mut!(TASKS) };
    for (i, s) in tasks.iter_mut().enumerate() {
        if i == cur {
            continue; // never self-reap — our own stack is in use
        }
        let dead = matches!(
            s.as_ref(),
            Some(t) if t.state == TaskState::Exited && t.tgid != t.pid
        );
        if dead {
            if let Some(t) = s.as_mut() {
                t.reap();
            }
            *s = None;
        }
    }
}

/// Index of the running task; usize::MAX when the scheduler isn't
/// running (before launch / after the last exit unwound to main).
static mut CUR_I: usize = usize::MAX;

/// Lifetime task creations — /proc/stat's "processes" counter.
static PROCS_CREATED: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);
/// Completed context switches — /proc/stat's "ctxt" counter.
/// resume_ctx is the only switch path (launch inits CUR_I directly).
static CTXT_SW: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);

/// Shared-address-space ledger (CLONE_VM): (pml4, users) pairs.
/// A pml4 enters the first time it is shared, leaves when its last
/// user dies. A pml4 NOT in the table is singly owned — its task
/// frees it outright at reap. At most MAX_TASKS shared mms exist.
static mut MM_REFS: [(u64, u16); MAX_TASKS] = [(0, 0); MAX_TASKS];

/// Record that `pml4` now has one more user — registers the pair
/// (owner + new sharer = 2) on first share. False only if the table
/// is full (provably unreachable: every entry implies >=2 live
/// tasks, so MAX_TASKS slots can't be exhausted while a free task
/// slot existed for the child — but a silent miss would corrupt the
/// count, so the caller fails honestly).
fn mm_share(pml4: u64) -> bool {
    let t = unsafe { &mut *core::ptr::addr_of_mut!(MM_REFS) };
    for e in t.iter_mut() {
        if e.0 == pml4 {
            e.1 += 1;
            return true;
        }
    }
    for e in t.iter_mut() {
        if e.0 == 0 {
            *e = (pml4, 2);
            return true;
        }
    }
    false
}

/// Is `pml4` a shared mm? (peek — used where the decrement must
/// happen after a fallible allocation.)
fn mm_is_shared(pml4: u64) -> bool {
    let t = unsafe { &*core::ptr::addr_of!(MM_REFS) };
    t.iter().any(|e| e.0 == pml4)
}

/// One user of `pml4` is gone. True when the caller must free the
/// address space — either it was never shared or it was the last
/// user. False means siblings still run on it.
fn mm_release(pml4: u64) -> bool {
    let t = unsafe { &mut *core::ptr::addr_of_mut!(MM_REFS) };
    for e in t.iter_mut() {
        if e.0 == pml4 {
            e.1 -= 1;
            if e.1 == 0 {
                *e = (0, 0);
                return true;
            }
            return false;
        }
    }
    true
}

/// The initrd archive as a flat read-only filesystem — set once at
/// boot before the first task runs. It names LOADER_DATA pages the
/// buddy never pools, so the slice is valid for the kernel's life.
static mut INITRD: Option<&'static [u8]> = None;

/// Point fd_open at the archive. Called once from main context.
pub fn set_initrd(img: &'static [u8]) {
    // SAFETY: sole writer, before any task exists.
    unsafe { *core::ptr::addr_of_mut!(INITRD) = Some(img) };
}

/// Resolve a flat name to archive bytes — the filesystem lookup used
/// by open and execve alike.
pub fn fs_lookup(name: &[u8]) -> Option<&'static [u8]> {
    let arc = unsafe { *core::ptr::addr_of!(INITRD) }?;
    // /proc/<pid-or-self>/exe resolves to that task's executable
    // image — busybox's FEATURE_PREFER_APPLETS re-exec path and
    // /proc/pid/exe consumers alike depend on it.
    if let Some(ProcEnt::Task(slot, b"exe")) = proc_parse(name) {
        let tasks = unsafe { &*core::ptr::addr_of!(TASKS) };
        let t = tasks.get(slot).and_then(|s| s.as_ref())?;
        return crate::cpio::find(arc, &t.exe[..t.exe_len as usize]);
    }
    // execve("/proc/<pid>/fd/<n>") runs the executable the link
    // names — resolves like the exe link but through the fd table.
    // Only archive-backed File OFDs have image bytes to run.
    if let Some(ProcEnt::TaskFd(slot, n)) = proc_parse(name) {
        let tasks = unsafe { &*core::ptr::addr_of!(TASKS) };
        let t = tasks.get(slot).and_then(|s| s.as_ref())?;
        if t.fdi == FDI_NONE {
            return None;
        }
        let tab =
            unsafe { &(*core::ptr::addr_of!(FDTABS))[t.fdi as usize] };
        let oi = tab.fds[n]? as usize;
        let ofds = unsafe { &*core::ptr::addr_of!(OFDS) };
        if let FdKind::File(d) = &ofds.get(oi)?.as_ref()?.kind {
            return Some(d);
        }
        return None;
    }
    crate::cpio::find(arc, name)
}

/// Borrow the running task immutably — fault/log-path accessor.
pub(crate) fn cur_exe() -> &'static str {
    let i = unsafe { *core::ptr::addr_of!(CUR_I) };
    unsafe {
        match (*core::ptr::addr_of!(TASKS)).get(i).and_then(|t| t.as_ref()) {
            Some(t) => core::str::from_utf8(&t.exe[..(t.exe_len as usize).min(128)])
                .unwrap_or("?"),
            None => "?",
        }
    }
}

/// Borrow the running task mutably — syscall-context accessor.
fn cur_mut() -> Option<&'static mut Task> {
    // SAFETY: single CPU, IF-masked syscall path — sole accessor.
    let i = unsafe { *core::ptr::addr_of!(CUR_I) };
    unsafe { (*core::ptr::addr_of_mut!(TASKS)).get_mut(i)?.as_mut() }
}

/// The task index whose ranges/heap ledger is authoritative for
/// the running task's address space: an NT thread (pers==NT,
/// tgid != pid) defers to its process leader. Threads share the
/// pml4 — a ledger copied at create would go stale the moment a
/// sibling mutates the map, letting a probe pass on freed VA.
fn mm_owner_i() -> Option<usize> {
    let cur = unsafe { *core::ptr::addr_of!(CUR_I) };
    let tasks = unsafe { &*core::ptr::addr_of!(TASKS) };
    let ct = tasks.get(cur)?.as_ref()?;
    if ct.pers == PERS_NT && ct.tgid != ct.pid {
        let want = ct.tgid;
        tasks
            .iter()
            .position(|s| s.as_ref().is_some_and(|t| t.pid == want))
    } else {
        Some(cur)
    }
}

/// mm_owner_i resolved to a mutable Task ref.
fn mm_owner_mut() -> Option<&'static mut Task> {
    let i = mm_owner_i()?;
    unsafe { (*core::ptr::addr_of_mut!(TASKS))[i].as_mut() }
}

fn rd64(p: u64) -> u64 {
    // SAFETY: callers only name page-table frames inside the identity
    // map; the kernel runs under an identity mapping.
    unsafe { (p as *const u64).read_volatile() }
}

fn wr64(p: u64, v: u64) {
    // SAFETY: see rd64.
    unsafe { (p as *mut u64).write_volatile(v) }
}

/// Map `va` -> a fresh zeroed frame under `t.pml4`, creating PDPT/PD/PT
/// tables on demand and tracking every allocation in the task ledger.
/// Intermediate entries get PRESENT|RW|USER (CPL3 traversal needs U/S
/// at every level); the leaf carries `flags`. Returns the backing
/// frame's physical address. A page already present keeps its frame
/// and ORs in the new permissions — union semantics for overlapping
/// segments.
fn map_page(t: &mut Task, va: u64, flags: u64) -> Option<u64> {
    let mut tab = t.pml4;
    for shift in [39u64, 30, 21] {
        let idx = ((va >> shift) & 0x1ff) as usize;
        let e = rd64(tab + 8 * idx as u64);
        if e & PRESENT != 0 {
            if e & (1 << 7) != 0 {
                return None; // collides with a huge page
            }
            tab = e & PHYS_MASK;
        } else {
            let f = kalloc::alloc_frame()?;
            wr64(tab + 8 * idx as u64, f | PRESENT | WRITE | USER);
            tab = f;
        }
    }
    let idx = ((va >> 12) & 0x1ff) as usize;
    let ent = tab + 8 * idx as u64;
    let e = rd64(ent);
    if e & PRESENT != 0 {
        wr64(ent, (e & PHYS_MASK) | flags | PRESENT);
        return Some(e & PHYS_MASK);
    }
    let f = kalloc::alloc_frame()?;
    wr64(ent, f | flags | PRESENT);
    Some(f)
}

/// Populate `t`'s address space from the ELF image's PT_LOAD
/// segments and record their VMAs. All header fields are hostile —
/// every extent is checked before use. `track_brk` extends the break
/// past the highest segment end — false for a PT_INTERP interpreter,
/// whose span sits in the mmap arena and must not move the main
/// binary's break.
fn map_loads(t: &mut Task, e: &elf::Elf, img: &[u8], track_brk: bool) -> bool {
    for p in e.phdrs(img) {
        if p.ty != elf::PT_LOAD {
            continue;
        }
        // filesz<=memsz, file range inside the image, virtual range
        // inside user space — all checked, checked arithmetic only.
        if p.filesz > p.memsz {
            return false;
        }
        let Some(fend) = p.off.checked_add(p.filesz) else {
            return false;
        };
        if fend > img.len() as u64 {
            return false;
        }
        let Some(mend) = p.va.checked_add(p.memsz) else {
            return false;
        };
        if p.memsz == 0 {
            continue;
        }
        if p.va < elf::USER_VA_LO || mend > elf::USER_VA_HI {
            return false;
        }
        let mut fl = USER;
        if p.flags & elf::PF_W != 0 {
            fl |= WRITE;
        }
        if p.flags & elf::PF_X == 0 {
            fl |= NX;
        }
        // mend < 2^47, so +0xfff is safe after the range check above.
        let va0 = p.va & !0xfff;
        let va1 = (mend + 0xfff) & !0xfff;
        let mut v = va0;
        while v < va1 {
            let Some(frame) = map_page(t, v, fl) else {
                return false;
            };
            // Copy the overlap of this page with [va, va+filesz).
            let lo = core::cmp::max(v, p.va);
            let hi = core::cmp::min(v + PAGE, p.va + p.filesz);
            if lo < hi {
                let src = p.off + (lo - p.va);
                // SAFETY: frame is an owned page in the identity map;
                // n <= PAGE and src..src+n <= img.len() (fend check).
                unsafe {
                    ((frame + (lo - v)) as *mut u8)
                        .copy_from(img.as_ptr().add(src as usize), (hi - lo) as usize);
                }
            }
            v += PAGE;
        }
        if t.nranges >= MAX_RANGES {
            return false;
        }
        let fl = ((p.flags & elf::PF_R != 0) as u8)
            | ((p.flags & elf::PF_W != 0) as u8) << 1;
        // The VMA covers the whole mapped page range, not just the
        // segment extent — Linux VMAs are page-aligned too. (Without
        // this, mprotect on a RELRO sub-page range ENOMEMs on the
        // page slack before p.va.)
        t.ranges[t.nranges] = (va0, va1, fl);
        t.nranges += 1;
        if track_brk {
            t.brk_base = t.brk_base.max((mend + PAGE - 1) & !(PAGE - 1));
        }
    }
    true
}

fn load_inner(t: &mut Task, e: &elf::Elf, img: &[u8]) -> bool {
    t.brk_base = 0;
    t.brk_cur = 0;
    // Copy the kernel PML4 — its entries are supervisor-only, so user
    // code can't reach kernel memory through them even though the
    // mappings are shared. User-window slots (128..256) are skipped:
    // under a syscall caller's cr3 (CreateProcess) they'd alias the
    // caller's tables by reference, and teardown of either mm would
    // free frames the other still walks.
    let kpml4 = cpu::read_cr3() & !0xfff;
    for i in (0..128u64).chain(256..512) {
        let ent = rd64(kpml4 + 8 * i);
        if ent & PRESENT != 0 {
            wr64(t.pml4 + 8 * i, ent);
        }
    }
    if !map_loads(t, e, img, true) {
        return false;
    }
    for i in 0..USTACK_PAGES {
        if map_page(t, USTACK_VA + i * PAGE, USER | WRITE | NX).is_none() {
            return false;
        }
    }
    let Some(tp) = map_page(t, SIGTRAMP_VA, USER) else {
        return false;
    };
    // SAFETY: tp is an identity-mapped frame we just allocated.
    unsafe { (tp as *mut u8).copy_from_nonoverlapping(SIGTRAMP_CODE.as_ptr(), SIGTRAMP_CODE.len()) };
    t.stack_top = USTACK_VA + USTACK_PAGES * PAGE;
    if t.nranges >= MAX_RANGES {
        return false;
    }
    t.ranges[t.nranges] = (USTACK_VA, t.stack_top, RNG_R | RNG_W);
    t.nranges += 1;
    t.brk_cur = t.brk_base;
    true
}

/// PE32+ counterpart to load_inner: sections map at the image bias
/// with per-section permissions, then TEB/PEB pages + a stack land
/// above it. The NT task gets no auxv — it reads its own PEB.
fn pe_load_inner(t: &mut Task, p: &crate::pe::Pe, img: &[u8]) -> bool {
    t.brk_base = 0;
    t.brk_cur = 0;
    let kpml4 = cpu::read_cr3() & !0xfff;
    for i in (0..128u64).chain(256..512) {
        let ent = rd64(kpml4 + 8 * i);
        if ent & PRESENT != 0 {
            wr64(t.pml4 + 8 * i, ent);
        }
    }
    // The headers page maps too — real Windows maps the whole image
    // including DOS/PE headers at the base.
    if map_page(t, p.bias, USER | NX).is_none() {
        return false;
    }
    let hdrlen = (p.sections[0].raw as usize).min(img.len()).min(4096);
    if !write_task_bytes_force(t.pml4, p.bias, &img[..hdrlen]) {
        return false;
    }
    for s in p.sections.iter().take(p.nsec) {
        // DISCARDABLE sections (.debug_*) are not part of the loaded
        // image — skipping them also keeps the ranges[] ledger from
        // exhausting MAX_RANGES on debug-linked MinGW builds. MinGW
        // marks .reloc discardable too, so a discardable section
        // that carries the base-reloc directory is still kept.
        if s.chars & 0x0200_0000 != 0
            && !(p.reloc_rva >= s.va && p.reloc_rva < s.va + s.vsize.max(1))
        {
            continue;
        }
        let va0 = (p.bias + s.va) & !0xfff;
        let va1 = (p.bias + s.va + s.vsize.max(1) + 0xfff) & !0xfff;
        // IMAGE_SCN_MEM_{EXECUTE,READ,WRITE} → our page flags.
        let mut fl = USER;
        if s.chars & 0x8000_0000 != 0 {
            fl |= WRITE;
        }
        if s.chars & 0x2000_0000 == 0 {
            fl |= NX;
        }
        for va in (va0..va1).step_by(4096) {
            if map_page(t, va, fl).is_none() {
                return false;
            }
        }
        let rend = s.raw.saturating_add(s.raw_len) as usize;
        if s.raw as usize > img.len() || rend > img.len() {
            return false;
        }
        if !write_task_bytes_force(
            t.pml4,
            p.bias + s.va,
            &img[s.raw as usize..rend],
        ) {
            return false;
        }
        if t.nranges >= MAX_RANGES {
            return false;
        }
        let mut rfl = 0u8;
        if s.chars & 0x4000_0000 != 0 {
            rfl |= RNG_R;
        }
        if s.chars & 0x8000_0000 != 0 {
            rfl |= RNG_W;
        }
        if s.chars & 0x2000_0000 != 0 {
            rfl |= RNG_X;
        }
        t.ranges[t.nranges] = (va0, va1, rfl);
        t.nranges += 1;
    }
    // Register the fixed regions FIRST — dep images bound during
    // import resolution place via nt_place_ok, which walks ranges[];
    // without these entries a dep could land on the stack, stubs,
    // or TEB before they're even mapped. Mapping still happens in
    // order below; the ledger just reserves the spans.
    t.stack_top = USTACK_VA + USTACK_PAGES * PAGE;
    for r in [
        (USTACK_VA, t.stack_top, RNG_R | RNG_W),
        (crate::pe::PEB_VA, crate::pe::PEB_VA + 0x1000, RNG_R | RNG_W),
        (crate::pe::TEB_VA, crate::pe::TEB_VA + 0x1000, RNG_R | RNG_W),
        (crate::pe::STUB_VA, crate::pe::STUB_DATA_VA, RNG_R | RNG_X),
        (
            crate::pe::STUB_DATA_VA,
            crate::pe::STUB_DATA_VA + 0x1000,
            RNG_R | RNG_W,
        ),
    ] {
        if t.nranges >= MAX_RANGES {
            return false;
        }
        t.ranges[t.nranges] = r;
        t.nranges += 1;
    }
    // Rebase against the load bias, then bind imports — both must
    // run before the image executes, and both honestly fail the load.
    // The exe's dep mask is unused: implicitly loaded deps live for
    // the process's span and sweep with it.
    let mut exe_deps = 0u32;
    if !pe_apply_relocs(t, p) || !pe_resolve_imports(t, p, true, 0, &mut exe_deps) {
        return false;
    }
    nt_lock_stubs(t);
    for i in 0..USTACK_PAGES {
        if map_page(t, USTACK_VA + i * PAGE, USER | WRITE | NX).is_none() {
            return false;
        }
    }
    if !teb_peb_init(t, p) {
        return false;
    }
    // The Win32 thunk layer's writable state page (argv/envp/FILE[]/
    // TLS) — mapped for every PE task; thunks use it, ntdll-level
    // images just ignore it.
    if map_page(t, crate::pe::STUB_DATA_VA, USER | WRITE | NX).is_none() {
        return false;
    }
    k32_data_init(t);
    if !pe_tls_init(t, p) {
        return false;
    }
    t.pers = PERS_NT;
    t.gs_base = crate::pe::TEB_VA;
    // Spawn-time deps may have already bumped the alloc cursor.
    t.nt_alloc = t.nt_alloc.max(NT_ALLOC_VA);
    // Std handles are PEB-published NT handles, not fds — the NT
    // task's fd table stays empty (its std streams are handles
    // 1/2/3 in nth, resolved by the NT syscall layer). The table is
    // zeroed first: exec reuses the task and must not leak a prior
    // image's handles into the new one.
    t.nth = [0; crate::nt::MAX_NTH];
    t.nth_fd = [0xff; crate::nt::MAX_NTH];
    t.nth_dirpat = [[0; 96]; crate::nt::MAX_NTH];
    t.heap_blk = [[0; 3]; 128];
    t.heap_bump = crate::pe::HEAP_VA;
    t.heap_commit = crate::pe::HEAP_VA;
    t.nth[0] = crate::nt::NTH_STDIN;
    t.nth[1] = crate::nt::NTH_STDOUT;
    t.nth[2] = crate::nt::NTH_STDERR;
    true
}

/// .reloc rebase: walk base-relocation blocks, adding
/// (bias - image_base) to each DIR64 slot. Blocks/entries read
/// through the task's own tables; type-10 is the only real x64
/// fixup, anything else is an honest load failure.
fn pe_apply_relocs(t: &mut Task, p: &crate::pe::Pe) -> bool {
    if p.reloc_size == 0 {
        return true;
    }
    let delta = p.bias.wrapping_sub(p.image_base);
    let mut va = p.bias + p.reloc_rva;
    let end = va + p.reloc_size;
    while va + 8 <= end {
        let (Some(page), Some(bsz)) =
            (read_task_u(t.pml4, va, 4), read_task_u(t.pml4, va + 4, 4))
        else {
            return false;
        };
        if bsz < 8 || va + bsz > end {
            return false;
        }
        for i in 0..(bsz - 8) / 2 {
            let Some(e) = read_task_u(t.pml4, va + 8 + i * 2, 2) else {
                return false;
            };
            match e >> 12 {
                0 => {} // ABSOLUTE — alignment padding
                10 => {
                    let off = page + (e & 0xfff);
                    if off + 8 > p.size {
                        return false;
                    }
                    let slot = p.bias + off;
                    let Some(v) = read_task_u(t.pml4, slot, 8) else {
                        return false;
                    };
                    let nv = v.wrapping_add(delta).to_le_bytes();
                    if !write_task_bytes_force(t.pml4, slot, &nv) {
                        return false;
                    }
                }
                _ => return false,
            }
        }
        va += bsz;
    }
    true
}

/// Map a PE image as a loadable module (LoadLibrary's kernel half):
/// the preferred base when free, else the next NT-arena window;
/// headers + per-section pages at their RVAs, base relocations and
/// IAT binding — pe_load_inner's mapping half, minus process state.
/// Returns (HMODULE base, page-rounded span), or unwinds + None.
/// Map a PE image into the caller's address space. Returns
/// (base, span, dep_mask, entry_va) — dep_mask marks the
/// module-ledger slots this image bound imports against. `depth`
/// bounds recursive dependent-DLL loads.
fn pe_map_image(t: &mut Task, img: &[u8], depth: u8) -> Option<(u64, u64, u32, u64)> {
    let mut p = crate::pe::parse(img)?;

    let size = (p.size + 0xfff) & !0xfff;
    let mut base = p.image_base & !0xfff;
    if !(base >= elf::USER_VA_LO && nt_place_ok(t, base, size)) {
        base = t.nt_alloc.max(NT_ALLOC_VA);
        loop {
            if base + size >= elf::USER_VA_HI || base < NT_ALLOC_VA {
                return None;
            }
            if nt_place_ok(t, base, size) {
                break;
            }
            base += PAGE;
        }
    }
    p.bias = base;
    let mut deps = 0u32;
    let mut mapped_hi = base + PAGE;
    let ok = (|| {
        map_page(t, base, USER | NX)?;
        let hdrlen = (p.sections[0].raw as usize).min(img.len()).min(4096);
        if !write_task_bytes_force(t.pml4, base, &img[..hdrlen]) {
            return None;
        }
        for s in p.sections.iter().take(p.nsec) {
            // DISCARDABLE sections (.debug_*, .drectve) are not part
            // of the loaded image — the Windows loader skips them
            // too. Mapping them would also burn one ranges[] slot
            // each and exhaust MAX_RANGES on debug builds. MinGW
            // marks .reloc discardable, so a discardable section
            // that carries the base-reloc directory is still kept.
            if s.chars & 0x0200_0000 != 0
                && !(p.reloc_rva >= s.va && p.reloc_rva < s.va + s.vsize.max(1))
            {
                continue;
            }
            let va0 = (base + s.va) & !0xfff;
            let va1 = (base + s.va + s.vsize.max(1) + 0xfff) & !0xfff;
            let mut fl = USER;
            if s.chars & 0x8000_0000 != 0 {
                fl |= WRITE;
            }
            if s.chars & 0x2000_0000 == 0 {
                fl |= NX;
            }
            for va in (va0..va1).step_by(4096) {
                map_page(t, va, fl)?;
            }
            let rend = s.raw.saturating_add(s.raw_len) as usize;
            if s.raw as usize > img.len() || rend > img.len() {
                return None;
            }
            if !write_task_bytes_force(
                t.pml4,
                base + s.va,
                &img[s.raw as usize..rend],
            ) {
                return None;
            }
            if t.nranges >= MAX_RANGES {
                return None;
            }
            let mut rfl = 0u8;
            if s.chars & 0x4000_0000 != 0 {
                rfl |= RNG_R;
            }
            if s.chars & 0x8000_0000 != 0 {
                rfl |= RNG_W;
            }
            if s.chars & 0x2000_0000 != 0 {
                rfl |= RNG_X;
            }
            t.ranges[t.nranges] = (va0, va1, rfl);
            t.nranges += 1;
            mapped_hi = mapped_hi.max(va1);
        }
        (pe_apply_relocs(t, &p)
            && pe_resolve_imports(t, &p, false, depth, &mut deps))
        .then_some(())
    })();
    if ok.is_none() {
        // Import binding may have claimed dep refs before failing —
        // release them so a bad image can't strand mappings.
        nt_deps_release(deps);
        nt_free_pages_t(t, base, mapped_hi - base);
        return None;
    }
    t.nt_alloc = (base + size).max(t.nt_alloc);
    // The ledger span is the mapped extent, not SizeOfImage: the
    // tail of a debug build's image is discardable sections we never
    // mapped, and another module may legitimately sit in that gap —
    // FreeLibrary's unmap must not reach past our own last page.
    Some((base, mapped_hi - base, deps, base + p.entry - crate::pe::PE_LOAD_BIAS))
}

/// Loaded-module ledger: (owner_pid, base, span, refs, entry_va,
/// nlen, name, dep_mask, pend_st). LoadLibrary dedups by name —
/// a second load of the same module bumps refs and hands back the
/// same HMODULE, like Windows. dep_mask's bit i marks slot i as an
/// import dependency: a module freed to refs==0 refdowns each dep,
/// so unload cascades like the real loader's. pend_st is the
/// DllMain state: 1 = DllMain(DLL_PROCESS_ATTACH) pending (the
/// LoadLibrary thunk drains these — deps land in lower slots, so
/// ascending order runs deps before their importer), 2 =
/// DllMain(DLL_PROCESS_DETACH) pending (the FreeLibrary thunk drains
/// these descending — importer first), 3 = detached, awaiting the
/// finalize unmap.
const NT_MAX_MODS: usize = 16;
static mut NT_MODS: [(u64, u64, u64, u64, u64, u8, [u8; 32], u32, u8);
    NT_MAX_MODS] = [(0, 0, 0, 0, 0, 0, [0; 32], 0, 0); NT_MAX_MODS];

/// Find a live module for the caller's process by name.
fn nt_mod_find(owner: u64, name: &[u8]) -> Option<usize> {
    let tab = unsafe { &*core::ptr::addr_of!(NT_MODS) };
    tab.iter().position(|e| {
        e.3 != 0 && e.0 == owner && &e.6[..e.5 as usize] == name
    })
}

/// Find a live module for the caller's process by base address.
fn nt_mod_find_base(owner: u64, base: u64) -> Option<usize> {
    let tab = unsafe { &*core::ptr::addr_of!(NT_MODS) };
    tab.iter()
        .position(|e| e.3 != 0 && e.0 == owner && e.1 == base)
}

/// Record a freshly-mapped module. Caller already holds nothing —
/// the slot is claimed here. `dep_mask` marks which ledger slots
/// this image bound imports against. A nonzero `entry` flags the
/// slot pending DllMain(DLL_PROCESS_ATTACH).
fn nt_mod_add(
    owner: u64,
    base: u64,
    size: u64,
    entry: u64,
    name: &[u8],
    dep_mask: u32,
) -> bool {
    if name.is_empty() || name.len() > 32 {
        return false;
    }
    let tab = unsafe { &mut *core::ptr::addr_of_mut!(NT_MODS) };
    // Sweep slots whose owning process is fully gone — except the
    // caller's own: a spawning task registers its import deps before
    // it lands in TASKS, and a later dep's sweep must not reap the
    // earlier deps its dep_mask is about to point at. "Gone" means
    // no live task in the thread group: an exited-but-unreaped
    // leader already ran its exit detaches and can never touch the
    // table again, so zombie slots must not hold the (tiny) ledger
    // hostage until a reaper gets scheduled.
    let tasks = unsafe { &*core::ptr::addr_of!(TASKS) };
    for e in tab.iter_mut() {
        if e.3 != 0 && e.0 != owner
            && !tasks.iter().flatten().any(|t| {
                t.tgid == e.0 && t.state != TaskState::Exited
            })
        {
            *e = (0, 0, 0, 0, 0, 0, [0; 32], 0, 0);
        }
    }
    // Slot order IS load order: the thr/detach enums walk the table
    // linearly, so a fresh module must land after the owner's last
    // live entry — a swept low slot reused early would invert the
    // attach/detach sequences for every later drain. "Free" is
    // base==0, not refs==0: a zero-ref module still owns its slot
    // until the detach pipeline unmaps it.
    let start = tab
        .iter()
        .enumerate()
        .filter(|(_, e)| e.0 == owner && e.1 != 0)
        .map(|(i, _)| i + 1)
        .max()
        .unwrap_or(0);
    let Some(i) = tab[start..]
        .iter()
        .position(|e| e.1 == 0)
        .map(|p| p + start)
    else {
        return false;
    };
    let mut nm = [0u8; 32];
    nm[..name.len()].copy_from_slice(name);
    tab[i] = (
        owner,
        base,
        size,
        1,
        entry,
        name.len() as u8,
        nm,
        dep_mask,
        (entry != 0) as u8,
    );
    true
}

/// LoadLibraryA/W kernel half: read the module name off the user
/// stack (ANSI, or UTF-16 when `wide`), dedup against live modules
/// of this process, resolve backing bytes (VFILES "/name" first,
/// then the initrd), map the image and record it. HMODULE or 0.
/// Read a module name (ANSI or UTF-16) from the caller's address
/// space and reduce it to a basename — the flat VFS has no search
/// path to honor. Some((buf, len)) where buf[..len] is the basename.
fn nt_mod_name(pml4: u64, name_va: u64, wide: bool) -> Option<([u8; 64], usize)> {
    if !range_ok(name_va, 2) {
        return None;
    }
    let mut nb = [0u8; 64];
    let nl = if wide {
        let mut i = 0usize;
        while i < 63 {
            let Some(c) = read_task_u(pml4, name_va + i as u64 * 2, 2) else {
                return None;
            };
            if c == 0 {
                break;
            }
            if c > 0x7f {
                return None;
            }
            nb[i] = c as u8;
            i += 1;
        }
        i
    } else {
        read_task_str(pml4, name_va, &mut nb)
    };
    if nl == 0 {
        return None;
    }
    let st = nb[..nl]
        .iter()
        .rposition(|&c| c == b'\\' || c == b'/')
        .map(|i| i + 1)
        .unwrap_or(0);
    if st == nl {
        return None;
    }
    nb.copy_within(st..nl, 0);
    Some((nb, nl - st))
}

pub fn nt_load_dll(name_va: u64, wide: bool) -> u64 {
    let Some(t) = mm_owner_mut() else { return 0 };
    let Some((nb, nl)) = nt_mod_name(t.pml4, name_va, wide) else {
        return 0;
    };
    let name = &nb[..nl];
    let r = nt_mod_resolve(t, name, 0);
    // Top of the load call stack — seal the thunk pages on both
    // outcomes. A failed resolve may have emitted thunks (and
    // reopened the pages USER|WRITE) before bailing; leaving them
    // unlocked would keep the shared stub region writable+executable
    // for the rest of the process's life.
    nt_lock_stubs(t);
    let Some((i, fresh)) = r else {
        return 0;
    };
    let tab = unsafe { &*core::ptr::addr_of!(NT_MODS) };
    // Bit 63 tells the thunk this is a fresh map — DllMain's
    // DLL_PROCESS_ATTACH runs only then, not on dedup hits.
    tab[i].1 | if fresh { 1 << 63 } else { 0 }
}

/// GetModuleHandle: return a live module's base without bumping
/// refs — a handle lookup, not a load. A NULL name is the exe
/// itself, always mapped at PE_LOAD_BIAS; its exports stay
/// unreachable to nt_get_proc since the exe holds no ledger slot.
pub fn nt_mod_handle(name_va: u64, wide: bool) -> u64 {
    let (pml4, owner) = match mm_owner_mut() {
        Some(t) => (t.pml4, t.pid),
        None => return 0,
    };
    if name_va == 0 {
        return crate::pe::PE_LOAD_BIAS;
    }
    let Some((nb, nl)) = nt_mod_name(pml4, name_va, wide) else {
        return 0;
    };
    match nt_mod_find(owner, &nb[..nl]) {
        Some(i) => {
            let tab = unsafe { &*core::ptr::addr_of!(NT_MODS) };
            tab[i].1
        }
        None => 0,
    }
}

/// Resolve a module name to (slot index, fresh): dedup hits bump
/// refs and return the live slot; a miss loads the image from the
/// VFS or initrd into `t`'s address space — taken as a param, not
/// mm_owner_mut(), because spawn-time import resolution runs before
/// the task is current. `depth` bounds recursive dependent-DLL
/// loads — a chain (or cycle) deeper than 4 fails honestly rather
/// than walking the import graph forever.
fn nt_mod_resolve(t: &mut Task, name: &[u8], depth: u8) -> Option<(usize, bool)> {
    let owner = t.pid;
    if let Some(i) = nt_mod_find(owner, name) {
        let tab = unsafe { &mut *core::ptr::addr_of_mut!(NT_MODS) };
        tab[i].3 += 1;
        return Some((i, false));
    }
    if depth >= 4 || name.is_empty() || name.len() > 32 {
        return None;
    }
    let mut full = [0u8; 64];
    full[0] = b'/';
    full[1..1 + name.len()].copy_from_slice(name);
    let img: Option<&[u8]> =
        if let Some(v) = vfile_find(&full[..1 + name.len()]).and_then(vfile) {
            (!v.data.is_null() && v.len != 0)
                .then(|| unsafe { core::slice::from_raw_parts(v.data, v.len) })
        } else {
            unsafe { *core::ptr::addr_of!(INITRD) }
                .and_then(|arc| crate::cpio::find(arc, name))
        };
    let img = img?;
    let (base, size, dep_mask, entry) = pe_map_image(t, img, depth + 1)?;
    if !nt_mod_add(owner, base, size, entry, name, dep_mask) {
        nt_deps_release(dep_mask);
        nt_free_pages_t(t, base, size);
        return None;
    }
    let tab = unsafe { &*core::ptr::addr_of!(NT_MODS) };
    tab.iter().position(|e| e.3 != 0 && e.0 == owner && e.1 == base)
        .map(|i| (i, true))
}

/// Pop the caller's oldest module still pending its
/// DllMain(DLL_PROCESS_ATTACH) call: clears the flag, returns the
/// HMODULE, or 0 when nothing is pending. The LoadLibrary thunk
/// drains this queue after a fresh map — deps sit in lower slots
/// (they're claimed before their importer's), so ascending order
/// runs attach in load order, like Windows.
pub fn nt_next_attach() -> u64 {
    let owner = nt_owner_pid();
    if owner == 0 {
        return 0;
    }
    let tab = unsafe { &mut *core::ptr::addr_of_mut!(NT_MODS) };
    for e in tab.iter_mut() {
        if e.3 != 0 && e.0 == owner && e.8 == 1 {
            e.8 = 0;
            return e.1;
        }
    }
    0
}

/// Release the dep refs a failed or aborted load claimed — mirror
/// of the cascade in nt_mod_refdown for the not-yet-ledgered case.
fn nt_deps_release(mask: u32) {
    for d in 0..NT_MAX_MODS {
        if mask & (1 << d) != 0 {
            nt_mod_refdown(d);
        }
    }
}

/// Walk a mapped image's export directory for `name`; returns the
/// export's VA or 0 (no dir, no match, forwarder, out-of-image RVA).
/// Shared by GetProcAddress and dependent-DLL import binding.
fn nt_export_lookup(pml4: u64, base: u64, span: u64, name: &[u8]) -> u64 {
    let rd = |off: u64, w: u64| read_task_u(pml4, base + off, w);
    let Some(peoff) = rd(0x3c, 4) else { return 0 };
    let opt = peoff + 24;
    let (Some(erva), Some(esz)) = (rd(opt + 112, 4), rd(opt + 116, 4)) else {
        return 0;
    };
    if erva == 0 {
        return 0;
    }
    let (Some(nnames), Some(af), Some(an), Some(ao)) = (
        rd(erva + 0x18, 4),
        rd(erva + 0x1c, 4),
        rd(erva + 0x20, 4),
        rd(erva + 0x24, 4),
    ) else {
        return 0;
    };
    for i in 0..nnames.min(8192) {
        let Some(nrva) = rd(an + i * 4, 4) else { return 0 };
        let mut cmpb = [0u8; 64];
        let cl = read_task_str(pml4, base + nrva, &mut cmpb);
        if cl == 0 || &cmpb[..cl] != name {
            continue;
        }
        let Some(ord) = rd(ao + i * 2, 2) else { return 0 };
        let Some(frva) = rd(af + ord * 4, 4) else { return 0 };
        if frva >= erva && frva < erva + esz {
            return 0; // forwarded export — not supported
        }
        if frva >= span {
            return 0; // export RVA outside the image — malformed
        }
        return base + frva;
    }
    0
}

/// GetProcAddress kernel half: `hmod` must be a live module of the
/// caller's process; walks its export directory by name. Returns
/// the export's VA or 0 (unknown module, bad name, forwarder — a
/// forwarded export needs another module's machinery we don't run).
pub fn nt_get_proc(hmod: u64, name_va: u64) -> u64 {
    let (pml4, owner) = match mm_owner_mut() {
        Some(t) => (t.pml4, t.pid),
        None => return 0,
    };
    let Some(mi) = nt_mod_find_base(owner, hmod) else {
        return 0;
    };
    let span = unsafe { &*core::ptr::addr_of!(NT_MODS) }[mi].2;
    if !range_ok(name_va, 1) {
        return 0;
    }
    let mut nb = [0u8; 64];
    let nl = read_task_str(pml4, name_va, &mut nb);
    if nl == 0 {
        return 0;
    }
    nt_export_lookup(pml4, hmod, span, &nb[..nl])
}

/// refs-- on ledger slot `i`; the last ref unmaps the image span,
/// clears the slot, and refdowns every recorded import dependency —
/// freeing a DLL drops the refs its imports held, like the real
/// loader's unload cascade. Recursion is bounded by the slot count.
fn nt_mod_refdown(i: usize) {
    let e = {
        let tab = unsafe { &mut *core::ptr::addr_of_mut!(NT_MODS) };
        tab[i].3 = tab[i].3.saturating_sub(1);
        if tab[i].3 != 0 {
            return;
        }
        let e = tab[i];
        tab[i] = (0, 0, 0, 0, 0, 0, [0; 32], 0, 0);
        e
    };
    nt_free_pages(e.1, e.2);
    for d in 0..NT_MAX_MODS {
        if e.7 & (1 << d) != 0 {
            nt_mod_refdown(d);
        }
    }
}

/// FreeLibrary kernel half: refs-- on the caller's module. The last
/// ref does not unmap here — it simulates the cascade and marks
/// every module reaching zero pend_detach, returning 1|1<<63 so the
/// thunk drains DllMain(DLL_PROCESS_DETACH) calls importer-first via
/// RUX_DLL_DETACH, then RUX_FREE_FIN performs the unmaps and the
/// surviving dep ref fix-ups. A plain refdown returns 1; a bad
/// hmod 0.
pub fn nt_free_dll(hmod: u64) -> u64 {
    let owner = nt_owner_pid();
    let Some(i) = nt_mod_find_base(owner, hmod) else {
        return 0;
    };
    let tab = unsafe { &mut *core::ptr::addr_of_mut!(NT_MODS) };
    if tab[i].3 > 1 {
        tab[i].3 -= 1;
        return 1;
    }
    // A cascade already in flight for this owner — a re-entrant
    // FreeLibrary from inside a DllMain(DETACH): merge the
    // zero-reaching set into the live pipeline but return without
    // the pend bit, so the nested thunk does no drain or finalize.
    // Only the outermost FREE_FIN unmaps — otherwise a nested fin
    // would unmap modules whose DllMain is still on the stack.
    let in_flight = tab.iter().any(|e| e.0 == owner && e.8 >= 2);
    // Which modules reach zero through the cascade? Worklist over a
    // simulated refcount drop: freeing a marked module subtracts one
    // ref from each dep it bound; deps hitting zero join the set.
    // Entries already mid-detach are excluded — the live cascade
    // already accounted for their dep release.
    let mut sim = [0u64; NT_MAX_MODS];
    for (k, e) in tab.iter().enumerate() {
        sim[k] = if e.0 == owner { e.3 } else { 0 };
    }
    let mut marked = 0u32;
    let mut stack = [0usize; NT_MAX_MODS];
    let mut sp = 0;
    if tab[i].8 < 2 {
        marked |= 1 << i;
        sim[i] = 0;
        stack[sp] = i;
        sp += 1;
    }
    while sp > 0 {
        sp -= 1;
        let s = stack[sp];
        for d in 0..NT_MAX_MODS {
            if tab[s].7 & (1 << d) != 0 && sim[d] > 0 {
                sim[d] -= 1;
                if sim[d] == 0 && marked & (1 << d) == 0 && tab[d].8 < 2 {
                    marked |= 1 << d;
                    stack[sp] = d;
                    sp += 1;
                }
            }
        }
    }
    for (k, e) in tab.iter_mut().enumerate() {
        if marked & (1 << k) != 0 {
            // A module still pending its ATTACH call never ran
            // DllMain — skip its detach call (state 3) but keep it
            // in the finalize set.
            e.8 = match e.8 {
                1 => 3,
                0 => 2,
                s => s,
            };
        }
    }
    if in_flight {
        1
    } else {
        1 | (1 << 63)
    }
}

/// Pop the caller's most-recently-loaded module pending its
/// DllMain(DLL_PROCESS_DETACH): marks it detached, returns the
/// HMODULE, or 0. Descending slot order runs the importer before
/// its deps — the reverse of the attach drain, like the real
/// unloader's reverse-init-order calls.
pub fn nt_next_detach() -> u64 {
    let owner = nt_owner_pid();
    if owner == 0 {
        return 0;
    }
    let tab = unsafe { &mut *core::ptr::addr_of_mut!(NT_MODS) };
    for e in tab.iter_mut().rev() {
        if e.3 != 0 && e.0 == owner && e.8 == 2 {
            e.8 = 3;
            return e.1;
        }
    }
    0
}

/// ExitProcess drain: mark every live module this owner still holds
/// pend_detach (never-attached ones skip their call via state 3),
/// then pop the next pending — the ExitProcess thunk loops this
/// calling DllMain(DETACH) in reverse-load order before terminating.
/// Each pop returns a base once (2 -> 3); the images stay mapped —
/// the whole address space dies with the task anyway.
pub fn nt_exit_detach() -> u64 {
    let owner = nt_owner_pid();
    if owner == 0 {
        return 0;
    }
    let tab = unsafe { &mut *core::ptr::addr_of_mut!(NT_MODS) };
    for e in tab.iter_mut() {
        if e.0 == owner && e.1 != 0 && e.3 != 0 && e.8 < 2 {
            e.8 = match e.8 {
                1 => 3,
                _ => 2,
            };
        }
    }
    for e in tab.iter_mut().rev() {
        if e.3 != 0 && e.0 == owner && e.8 == 2 {
            e.8 = 3;
            return e.1;
        }
    }
    0
}

/// Pure iterator the thread-notification drains loop on: returns the
/// next live, fully-initialised (pend_st == 0) owner module base
/// after `prev` — dir 0 forward (load order, DLL_THREAD_ATTACH),
/// dir 1 reverse (DLL_THREAD_DETACH). prev == 0 starts the walk; a
/// prev whose slot was cleared mid-drain ends it early (a detach
/// callback freeing the just-visited module stops the walk — no
/// loader lock, recorded divergence).
pub fn nt_thr_enum(prev: u64, dir: u64) -> u64 {
    let owner = nt_owner_pid();
    if owner == 0 {
        return 0;
    }
    let tab = unsafe { &*core::ptr::addr_of!(NT_MODS) };
    let i = if prev == 0 {
        None
    } else {
        match tab.iter().position(|e| e.0 == owner && e.1 == prev) {
            Some(i) => Some(i),
            None => return 0,
        }
    };
    let live = |e: &(u64, u64, u64, u64, u64, u8, [u8; 32], u32, u8)| {
        if e.0 == owner && e.1 != 0 && e.8 == 0 {
            Some(e.1)
        } else {
            None
        }
    };
    if dir == 0 {
        for e in &tab[i.map_or(0, |i| i + 1)..] {
            if let Some(b) = live(e) {
                return b;
            }
        }
    } else {
        for e in tab[..i.unwrap_or(NT_MAX_MODS)].iter().rev() {
            if let Some(b) = live(e) {
                return b;
            }
        }
    }
    0
}

/// Finish a FreeLibrary after the thunk drained the DllMain(DETACH)
/// calls: drop one ref from each surviving dep per marked importer
/// (two freed modules sharing a dep release two refs, so a union
/// dep mask is not enough), then unmap every marked module and free
/// its slot.
pub fn nt_detach_fin() -> u64 {
    let Some(t) = mm_owner_mut() else { return 0 };
    let owner = t.pid;
    let tab = unsafe { &mut *core::ptr::addr_of_mut!(NT_MODS) };
    let mut marked = 0u32;
    for (k, e) in tab.iter().enumerate() {
        if e.3 != 0 && e.0 == owner && e.8 >= 2 {
            marked |= 1 << k;
        }
    }
    if marked == 0 {
        return 0;
    }
    for k in 0..NT_MAX_MODS {
        if marked & (1 << k) != 0 {
            for d in 0..NT_MAX_MODS {
                if tab[k].7 & (1 << d) != 0 && marked & (1 << d) == 0 {
                    tab[d].3 = tab[d].3.saturating_sub(1);
                }
            }
        }
    }
    for k in 0..NT_MAX_MODS {
        if marked & (1 << k) != 0 {
            let e = tab[k];
            tab[k] = (0, 0, 0, 0, 0, 0, [0; 32], 0, 0);
            nt_free_pages_t(t, e.1, e.2);
        }
    }
    // A live module whose refs just reached zero — a re-entrant
    // FreeLibrary mid-cascade consumed a ref the sim still counted —
    // joins the pipeline so its DllMain(DETACH) runs; the thunk loops
    // drain/fin while we keep reporting pending work.
    let mut again = 0u64;
    for e in tab.iter_mut() {
        if e.0 == owner && e.1 != 0 && e.3 == 0 && e.8 < 2 {
            e.8 = match e.8 {
                1 => 3,
                _ => 2,
            };
            again = 1;
        }
    }
    again
}

/// Read a NUL-terminated string out of a task's space into `out`;
/// returns the string length, 0 on unmapped/unterminated.
fn read_task_str(pml4: u64, va: u64, out: &mut [u8]) -> usize {
    for (i, o) in out.iter_mut().enumerate() {
        let Some(pa) = translate_r(pml4, va + i as u64) else {
            return 0;
        };
        // SAFETY: pa is a present user frame in pml4.
        let b = unsafe { (pa as *const u8).read() };
        if b == 0 {
            return i;
        }
        *o = b;
    }
    0
}

/// Byte emitter for the Win32 thunk bodies — lets immediates bake
/// real constants (STUB_DATA_VA fields, TEB offsets) and patches
/// short branches after their targets are known.
struct Emit<'a> {
    b: &'a mut [u8],
    n: usize,
}
impl<'a> Emit<'a> {
    fn raw(&mut self, s: &[u8]) {
        if self.n + s.len() > self.b.len() {
            // Overflow poisons the count — k32_emit's caller maps
            // a count past the buffer to an honest load failure
            // rather than a kernel panic on image input.
            self.n = self.b.len() + 1;
            return;
        }
        self.b[self.n..self.n + s.len()].copy_from_slice(s);
        self.n += s.len();
    }
    /// mov rax, imm64
    fn rax_imm(&mut self, v: u64) {
        self.raw(&[0x48, 0xb8]);
        self.raw(&v.to_le_bytes());
    }
    /// mov rdx, imm64
    fn rdx_imm(&mut self, v: u64) {
        self.raw(&[0x48, 0xba]);
        self.raw(&v.to_le_bytes());
    }
    /// jcc rel32 (0x0f 0x8|cc) with a 4-byte fix-up slot. Always the
    /// near form: a thunk past ~127 bytes between branch and target
    /// silently truncates a short-jcc displacement into a backward
    /// jump mid-instruction — there is no cheap range check at emit
    /// time, so every conditional here pays 4 bytes for correctness.
    fn jcc(&mut self, cc: u8) -> usize {
        self.raw(&[0x0f, 0x80 | cc, 0, 0, 0, 0]);
        self.n - 4
    }
    /// jmp rel32 with a 4-byte fix-up slot (backward jumps too).
    fn jmp(&mut self) -> usize {
        self.raw(&[0xe9, 0, 0, 0, 0]);
        self.n - 4
    }
    /// Patch the rel32 at `at` (first displacement byte) so the
    /// branch lands on `target` — either direction.
    fn fix_to(&mut self, at: usize, target: usize) {
        if at + 4 > self.b.len() {
            return;
        }
        let d = (target as i64 - at as i64 - 4) as i32;
        self.b[at..at + 4].copy_from_slice(&d.to_le_bytes());
    }
    /// Patch a slot to land on the emit head — the usual case.
    fn fix(&mut self, at: usize) {
        self.fix_to(at, self.n);
    }
}

/// Emit the shared detach drain used by the FreeLibrary and
/// ExitProcess thunks: loop `svc` (RUX_DLL_DETACH / RUX_EXIT_DETACH)
/// popping a pending-detach module base, read its PE entry RVA, call
/// it (hinst, DETACH, 0) in userland, repeat until 0. Returns the
/// loop head so a caller can re-enter after a finalize pass. The
/// caller owns the stack frame and what runs after the drain.
fn emit_detach_drain(e: &mut Emit, svc: u8) -> usize {
    let drain = e.n;
    e.raw(&[
        0xb8, svc, 0, 0, 0, //           mov eax,svc
        0x0f, 0x05, //                   syscall
        0x48, 0x85, 0xc0, //             test rax,rax
    ]);
    let done = e.jcc(0x4);
    e.raw(&[
        0x48, 0x89, 0xc3, //             mov rbx,rax    module base
    ]);
    // The loader calls LdrpCallTlsInitializers before the init
    // routine for EVERY reason — detach included.
    emit_tls_cb_walk(e, 0);
    e.raw(&[
        0x8b, 0x4b, 0x3c, //             mov ecx,[rbx+0x3c]     peoff
        0x8b, 0x4c, 0x0b, 0x28, //       mov ecx,[rbx+rcx+0x28] entry_rva
        0x85, 0xc9, //                   test ecx,ecx
    ]);
    let noent = e.jcc(0x4); //       no entry -> next
    e.raw(&[
        0x48, 0x01, 0xd9, //           add rcx,rbx   entry_va
        0x49, 0x89, 0xc9, //           mov r9,rcx
        0x48, 0x89, 0xd9, //           mov rcx,rbx   hinst
        0x31, 0xd2, //                 xor edx,edx   DLL_PROCESS_DETACH
        0x45, 0x31, 0xc0, //           xor r8d,r8d
        0x41, 0xff, 0xd1, //           call r9       DllMain
    ]);
    e.fix_to(noent, drain);
    let back = e.jmp();
    e.fix_to(back, drain);
    e.fix(done);
    drain
}

/// Emit the PIMAGE_TLS_CALLBACK array walk shared by every drain:
/// r14 = the module's AddressOfCallBacks VA (NULL-terminated),
/// r15 = hinst - both callee-saved so the callbacks keep them
/// alive. Calls each cb (hinst, reason, 0) in userland. Caller
/// owns the frame and the registers.
fn emit_tls_walk(e: &mut Emit, reason: u8) {
    e.raw(&[0x4d, 0x85, 0xf6]); //        test r14,r14
    let empty = e.jcc(0x4);
    let lp = e.n;
    e.raw(&[
        0x49, 0x8b, 0x06, //             mov rax,[r14]
        0x48, 0x85, 0xc0, //             test rax,rax
    ]);
    let done = e.jcc(0x4);
    e.raw(&[
        0x4c, 0x89, 0xf9, //             mov rcx,r15   hinst
        0xba, reason, 0, 0, 0, //       mov edx,reason
        0x45, 0x31, 0xc0, //             xor r8d,r8d
        0xff, 0xd0, //                   call rax
        0x49, 0x83, 0xc6, 0x08, //       add r14,8
    ]);
    let back = e.jmp();
    e.fix_to(back, lp);
    e.fix(empty);
    e.fix(done);
}

/// Emit the per-module TLS-callback walk used by the DllMain
/// drains: rbx = module base - read the image's TLS directory
/// (optional-header directory 9, at peoff+0xd0 for PE32+) for its
/// AddressOfCallBacks array, then walk it like the loader does.
/// A module with no TLS directory skips cleanly.
fn emit_tls_cb_walk(e: &mut Emit, reason: u8) {
    e.raw(&[
        0x8b, 0x4b, 0x3c, //                mov ecx,[rbx+0x3c]    peoff
        0x8b, 0x8c, 0x0b, 0xd0, 0, 0, 0, // mov ecx,[rbx+rcx+0xd0] tls rva
        0x85, 0xc9, //                      test ecx,ecx
    ]);
    let nodir = e.jcc(0x4);
    e.raw(&[
        0x4c, 0x8d, 0x34, 0x0b, //          lea r14,[rbx+rcx]     &dir
        0x4d, 0x8b, 0x76, 0x18, //          mov r14,[r14+0x18]    cbs VA
        // The array must name bytes inside the image: a malformed
        // directory could point the walk at anything else. The
        // compare against the base rejects undershoot; size vs
        // (cbs+8-base) rejects overshoot — wrap-safe since a wrapped
        // r11 is huge and fails the size test.
        0x49, 0x39, 0xde, //                cmp r14,rbx
    ]);
    let under = e.jcc(0x2); //              jb nodir (cbs < base)
    e.raw(&[
        0x8b, 0x4b, 0x3c, //                mov ecx,[rbx+0x3c]    peoff
        0x8b, 0x44, 0x0b, 0x50, //          mov eax,[rbx+rcx+0x50] imgsize
        0x4d, 0x8d, 0x5e, 0x08, //          lea r11,[r14+8]
        0x49, 0x29, 0xdb, //                sub r11,rbx
        0x4c, 0x39, 0xd8, //                cmp rax,r11
    ]);
    let oob = e.jcc(0x2); //                jb nodir (carry: size < off+8)
    e.raw(&[
        0x4c, 0x8b, 0xfb, //                mov r15,rbx           hinst
    ]);
    emit_tls_walk(e, reason);
    e.fix(nodir);
    e.fix(under);
    e.fix(oob);
}

/// Emit the exe's own TLS-callback walk for paths where the exe -
/// which holds no ledger slot - needs its callbacks run: the array
/// VA lives at data+0x108 (published by pe_tls_init), hinst is the
/// PEB's ImageBaseAddress. Both reads go through r11 since the
/// data page and PEB sit above the 4G line disp32 can't reach.
fn emit_exe_tls(e: &mut Emit, reason: u8) {
    e.raw(&[0x49, 0xbb]); //              mov r11,imm64 - cbs slot
    e.raw(&(crate::pe::STUB_DATA_VA + 0x108).to_le_bytes());
    e.raw(&[0x4d, 0x8b, 0x33]); //        mov r14,[r11]
    e.raw(&[0x49, 0xbb]); //              mov r11,imm64 - peb+0x10
    e.raw(&(crate::pe::PEB_VA + 0x10).to_le_bytes());
    e.raw(&[0x4d, 0x8b, 0x3b]); //        mov r15,[r11]
    emit_tls_walk(e, reason);
}

/// Emit the thread-notification drain used by the thread-entry
/// trampoline and ExitThread: loop RUX_THR_ENUM(prev=rbx, dir)
/// over the owner's live modules, read each PE entry RVA, call it
/// (hinst, reason, 0) in userland, repeat until 0. rbx is the walk
/// cursor — callee-saved, so DllMain keeps it alive; the callers
/// never return, so clobbering it is free. Caller owns the frame.
fn emit_thr_drain(e: &mut Emit, dir: u8, reason: u8) {
    let head = e.n;
    e.raw(&[
        0x49, 0x89, 0xda, //           mov r10,rbx     prev base
        0xba, dir, 0, 0, 0, //         mov edx,dir
        0xb8, 0xfc, 0, 0, 0, //        mov eax,0xFC    RUX_THR_ENUM
        0x0f, 0x05, //                 syscall
        0x48, 0x85, 0xc0, //           test rax,rax
    ]);
    let done = e.jcc(0x4);
    e.raw(&[0x48, 0x89, 0xc3]); //     mov rbx,rax     next prev
    // The loader calls LdrpCallTlsInitializers before the init
    // routine for EVERY reason — detach included.
    emit_tls_cb_walk(e, reason);
    e.raw(&[
        0x8b, 0x4b, 0x3c, //           mov ecx,[rbx+0x3c]    peoff
        0x8b, 0x4c, 0x0b, 0x28, //     mov ecx,[rbx+rcx+0x28] entry_rva
        0x85, 0xc9, //               test ecx,ecx
    ]);
    let noent = e.jcc(0x4); //     no entry -> next
    e.raw(&[
        0x48, 0x01, 0xd9, //         add rcx,rbx   entry_va
        0x49, 0x89, 0xc9, //         mov r9,rcx
        0x48, 0x89, 0xd9, //         mov rcx,rbx   hinst
        0xba, reason, 0, 0, 0, //   mov edx,reason
        0x45, 0x31, 0xc0, //         xor r8d,r8d
        0x41, 0xff, 0xd1, //         call r9       DllMain
    ]);
    e.fix_to(noent, head);
    let back = e.jmp();
    e.fix_to(back, head);
    e.fix(done);
}

/// Emit the thread-entry trampoline — a secondary thread's initial
/// rip: parks start_fn/param, drains DLL_THREAD_ATTACH forward
/// (load order) like the real loader does before the start routine,
/// calls start_fn(param), then drains DLL_THREAD_DETACH reverse and
/// terminates via NtTerminateThread(0, status). Exe-only; the VA is
/// published as t.thr_entry_va for nt_thread_create. Entry context:
/// rcx=start_fn, rdx=param, rsp has a synthetic thr_exit_va on top.
fn emit_thr_entry(t: &mut Task, stub_next: &mut u64) -> Option<()> {
    let mut buf = [0u8; 768];
    let mut e = Emit { b: &mut buf, n: 0 };
    e.raw(&[
        0x48, 0x83, 0xe4, 0xf0, //    and rsp,-16
        // 0x40 keeps every `call` site below 16-aligned: a fresh
        // thread rsp is normalised to 0 mod 16 first, so the frame
        // size itself must be a multiple of 16 (0x28 would leave
        // DllMain entered with rsp % 16 == 0 — an ABI misalign).
        0x48, 0x83, 0xec, 0x40, //    sub rsp,0x40
        0x48, 0x89, 0x4c, 0x24, 0x20, // mov [rsp+0x20],rcx  start
        0x48, 0x89, 0x54, 0x24, 0x28, // mov [rsp+0x28],rdx  param
        0x31, 0xdb, //                xor ebx,ebx          enum cursor
    ]);
    emit_thr_drain(&mut e, 0, 2); // DLL_THREAD_ATTACH, forward
    // The loader skips the exe's ldr entry in its module walk and
    // fires its TLS callbacks last — after every module's.
    emit_exe_tls(&mut e, 2);
    e.raw(&[
        0x48, 0x8b, 0x4c, 0x24, 0x28, // mov rcx,[rsp+0x28]  param
        0x48, 0x8b, 0x44, 0x24, 0x20, // mov rax,[rsp+0x20]  start
        0xff, 0xd0, //                call rax -> rax = exit code
        0x48, 0x89, 0x44, 0x24, 0x20, // mov [rsp+0x20],rax  park code
        0x31, 0xdb, //                xor ebx,ebx          enum cursor
    ]);
    emit_thr_drain(&mut e, 1, 3); // DLL_THREAD_DETACH, reverse
    emit_exe_tls(&mut e, 3); // exe TLS cbs run last (reverse order)
    e.raw(&[
        0x48, 0x8b, 0x54, 0x24, 0x20, // mov rdx,[rsp+0x20]  status
        0x45, 0x31, 0xd2, //          xor r10d,r10d        self
        0xb8, 0x53, 0, 0, 0, //      mov eax,0x53  NT_TERMINATE_THREAD
        0x0f, 0x05, 0xcc, //          syscall; int3
    ]);
    let n = e.n;
    if n > buf.len() {
        return None;
    }
    let used = (n as u64 + 15) & !15;
    if *stub_next + used > crate::pe::STUB_DATA_VA
        || !write_task_bytes(t.pml4, *stub_next, &buf[..n])
    {
        return None;
    }
    t.thr_entry_va = *stub_next;
    *stub_next += used;
    Some(())
}

/// Emit the shared 9-arg NtReadFile/NtWriteFile frame: caller has
/// already placed handle in r10, buf VA in [rsp+0x30], length in
/// [rsp+0x38], and subbed 0x60 of frame. Finishes with the syscall;
/// the iosb pointer at [rsp+0x28] names a 16-byte scratch at
/// [rsp+0x50]. `nr` = 8 write, 6 read.
fn emit_xfile_tail(e: &mut Emit, nr: u32) {
    e.raw(&[
        0x48, 0x8d, 0x44, 0x24, 0x50, // lea rax,[rsp+0x50] iosb
        0x48, 0x89, 0x44, 0x24, 0x28, // mov [rsp+0x28],rax
        0x48, 0xc7, 0x44, 0x24, 0x40, 0, 0, 0, 0, // byteoffset=0
        0x48, 0xc7, 0x44, 0x24, 0x48, 0, 0, 0, 0, // key=0
        0x31, 0xd2, //                xor edx,edx   (event)
        0x45, 0x31, 0xc0, //          xor r8d,r8d   (apc)
        0x45, 0x31, 0xc9, //          xor r9d,r9d   (apcctx)
    ]);
    e.raw(&[0xb8]);
    e.raw(&nr.to_le_bytes()); // mov eax,nr
    e.raw(&[0x0f, 0x05]); //     syscall
}

/// Emit the NtAllocateVirtualMemory block: (base cell,size cell)
/// at [rsp+0x40/+0x48] inside a sub-rsp-0x50 frame, args r10=-1,
/// zerobits=0, type/protect from the caller's stack slots.
/// Shared tail of VirtualAlloc/malloc/calloc. With `hdr` the
/// success path also writes the page-aligned size at base+8 and
/// returns base+16 — the 16-byte header free() reads back.
fn emit_valloc_tail(e: &mut Emit, hdr: bool) {
    e.raw(&[
        0x49, 0xc7, 0xc2, 0xff, 0xff, 0xff, 0xff, // mov r10,-1
        0x48, 0x8d, 0x54, 0x24, 0x40, // lea rdx,[rsp+0x40] &base
        0x45, 0x31, 0xc0, //          xor r8d,r8d
        0x4c, 0x8d, 0x4c, 0x24, 0x48, // lea r9,[rsp+0x48] &size
        0xb8, 0x18, 0, 0, 0, //       mov eax,0x18
        0x0f, 0x05, //                syscall
        0x85, 0xc0, //                test eax,eax
    ]);
    let fail = e.jcc(0x8); // js fail
    e.raw(&[0x48, 0x8b, 0x44, 0x24, 0x40]); // mov rax,[rsp+0x40]
    if hdr {
        e.raw(&[
            0x48, 0x8b, 0x4c, 0x24, 0x48, // mov rcx,[rsp+0x48]
            0x48, 0x89, 0x48, 0x08, //     mov [rax+8],rcx
            0x48, 0x83, 0xc0, 0x10, //     add rax,0x10
        ]);
    }
    let done = e.jmp();
    e.fix(fail);
    e.raw(&[0x31, 0xc0]); //           xor eax,eax
    e.fix(done);
    e.raw(&[0x48, 0x83, 0xc4, 0x50, 0xc3]); // add rsp,0x50; ret
}

/// Emit a repne-scasb strlen reading the pointer in rcx, leaving
/// the length in rcx. rdi is callee-saved in the Win64 ABI — the
/// callers' loop bounds live in it — so it is saved/restored
/// around scasb. Clobbers rax/rcx (caller-saved).
fn emit_strlen_rcx(e: &mut Emit) {
    e.raw(&[
        0x57, //                            push rdi
        0x48, 0x89, 0xcf, //                mov rdi,rcx
        0x48, 0xc7, 0xc1, 0xff, 0xff, 0xff, 0xff, // mov rcx,-1
        0x31, 0xc0, //                      xor eax,eax
        0xf2, 0xae, //                      repne scasb
        0x48, 0xf7, 0xd1, //                not rcx
        0x48, 0xff, 0xc9, //                dec rcx  (len, sans NUL)
        0x5f, //                            pop rdi
    ]);
}

/// Emit the 5-arg NtQueryInformationFile call inside a frame that
/// already stashed the handle at [rsp+0x60]: iosb at [rsp+0x10],
/// info buffer at [rsp+buf], `len`/`class` immediate. Ends with
/// syscall + `test eax,eax` — caller emits the branch.
fn emit_qinfo(e: &mut Emit, buf: u8, len: u8, class: u8) {
    e.raw(&[
        0x4c, 0x8b, 0x54, 0x24, 0x60, // mov r10,[rsp+0x60] h
        0x48, 0x8d, 0x54, 0x24, 0x10, // lea rdx,[rsp+0x10] iosb
        0x4c, 0x8d, 0x44, 0x24, buf, //  lea r8,[rsp+buf]
        0x41, 0xb9, len, 0, 0, 0, //    mov r9d,len
        0x48, 0xc7, 0x44, 0x24, 0x28, class, 0, 0, 0, // [+0x28]=class
        0xb8, 0x11, 0, 0, 0, //         mov eax,0x11
        0x0f, 0x05, //                  syscall
        0x85, 0xc0, //                  test eax,eax
    ]);
}

/// Emit the shared CreateFileA/W body: a 0xc8 frame carrying the
/// UNICODE_STRING + OBJECT_ATTRIBUTES + 7 stack args for the 11-arg
/// NtCreateFile. `wide` skips the ANSI->UTF-16 conversion (buf is
/// then the caller's W name; A converts into data+0x400, capped at
/// 126 chars). Returns the minted handle or -1 with the raw
/// NTSTATUS in TEB.LastError (Win32-code mapping is a divergence).
fn emit_openpath(e: &mut Emit, wide: bool, d: u64, delete: bool) {
    e.raw(&[
        0x48, 0x81, 0xec, 0xc8, 0, 0, 0, // sub rsp,0xc8
        0x48, 0x89, 0x4c, 0x24, 0x60, //   mov [rsp+0x60],rcx name
    ]);
    if delete {
        // DeleteFileA/W(name): open GENERIC_READ, share 0,
        // OPEN_EXISTING, attr 0 — all constant.
        e.raw(&[
            0x48, 0xc7, 0x44, 0x24, 0x68, 0, 0, 0, 0x80, // access
            0x48, 0xc7, 0x44, 0x24, 0x70, 0, 0, 0, 0, //    share
            0x48, 0xc7, 0x44, 0x24, 0x78, 3, 0, 0, 0, //    disp
            0x48, 0xc7, 0x84, 0x24, 0x80, 0, 0, 0, 0, 0, 0, 0, // attr
        ]);
    } else {
        e.raw(&[
            0x48, 0x89, 0x54, 0x24, 0x68, //   mov [rsp+0x68],rdx access
            0x4c, 0x89, 0x44, 0x24, 0x70, //   mov [rsp+0x70],r8  share
            0x48, 0x8b, 0x84, 0x24, 0xf0, 0, 0, 0, // mov rax,[rsp+0xf0] disp
            0x48, 0x89, 0x44, 0x24, 0x78, //   mov [rsp+0x78],rax
            0x48, 0x8b, 0x84, 0x24, 0xf8, 0, 0, 0, // mov rax,[rsp+0xf8] attr
            0x48, 0x89, 0x84, 0x24, 0x80, 0, 0, 0, // mov [rsp+0x80],rax
        ]);
    }
    e.raw(&[
        0x48, 0x8b, 0x4c, 0x24, 0x60, //   mov rcx,[rsp+0x60] name
        0x31, 0xc0, //                     xor eax,eax
    ]);
    if wide {
        // wcslen: chars*2 = byte length; buf = name itself.
        let lp = e.n;
        e.raw(&[0x66, 0x83, 0x3c, 0x41, 0x00]); // cmp word[rcx+rax*2],0
        let dn = e.jcc(0x4); //                   je done
        e.raw(&[0x48, 0x83, 0xc0, 0x01]); //     add rax,1
        let back = e.jmp();
        e.fix_to(back, lp);
        e.fix(dn);
        e.raw(&[
            0x48, 0x89, 0xca, // mov rdx,rcx       buf=name
            0x48, 0xd1, 0xe0, // shl rax,1         chars->bytes
        ]);
    } else {
        // ANSI->UTF-16 into the 256B scratch at d+0x400.
        e.rdx_imm(d + 0x400);
        let lp = e.n;
        e.raw(&[
            0x44, 0x0f, 0xb6, 0x1c, 0x01, // movzx r11d,byte[rcx+rax]
            0x66, 0x44, 0x89, 0x1c, 0x42, // mov [rdx+rax*2],r11w
            0x45, 0x84, 0xdb, //           test r11b,r11b
        ]);
        let dn = e.jcc(0x4); // je done
        e.raw(&[
            0x48, 0xff, 0xc0, // inc rax
            0x48, 0x83, 0xf8, 0x7e, // cmp rax,0x7e  (126-char cap)
        ]);
        let capped = e.jcc(0x3); // jae done
        let back = e.jmp();
        e.fix_to(back, lp);
        e.fix(dn);
        e.fix(capped);
        e.raw(&[
            0x66, 0xc7, 0x04, 0x42, 0x00, 0x00, // mov word[rdx+rax*2],0
            0x48, 0xd1, 0xe0, //                 shl rax,1
        ]);
    }
    e.raw(&[
        // UNICODE_STRING at [rsp+0x88]: {len, cap, pad, buf}
        0x66, 0x89, 0x84, 0x24, 0x88, 0, 0, 0, // mov [rsp+0x88],ax len
        0x66, 0x89, 0x84, 0x24, 0x8a, 0, 0, 0, // mov [rsp+0x8a],ax cap
        0xc7, 0x84, 0x24, 0x8c, 0, 0, 0, 0, 0, 0, 0, // [rsp+0x8c]=0
        0x48, 0x89, 0x94, 0x24, 0x90, 0, 0, 0, // mov [rsp+0x90],rdx buf
        // OBJECT_ATTRIBUTES at [rsp+0x98]
        0xc7, 0x84, 0x24, 0x98, 0, 0, 0, 0x30, 0, 0, 0, // oa.len=48
        0x48, 0xc7, 0x84, 0x24, 0xa0, 0, 0, 0, 0, 0, 0, 0, // root=0
        0x48, 0x8d, 0x84, 0x24, 0x88, 0, 0, 0, // lea rax,[rsp+0x88]
        0x48, 0x89, 0x84, 0x24, 0xa8, 0, 0, 0, // oa.name=&us
        0xc7, 0x84, 0x24, 0xb0, 0, 0, 0, 0, 0, 0, 0, // oa.attrs=0
        0x48, 0xc7, 0x84, 0x24, 0xb8, 0, 0, 0, 0, 0, 0, 0, // sd=0
        0x48, 0xc7, 0x84, 0x24, 0xc0, 0, 0, 0, 0, 0, 0, 0, // sqos=0
        0x48, 0xc7, 0x44, 0x24, 0x08, 0, 0, 0, 0, // hout=0
        0x48, 0xc7, 0x44, 0x24, 0x10, 0, 0, 0, 0, // iosb=0
        0x48, 0xc7, 0x44, 0x24, 0x18, 0, 0, 0, 0,
        0x48, 0xc7, 0x44, 0x24, 0x28, 0, 0, 0, 0, // a4 allocsize=0
        0x48, 0x8b, 0x84, 0x24, 0x80, 0, 0, 0, // mov rax,[rsp+0x80] attr
        0x48, 0x89, 0x44, 0x24, 0x30, //               a5 attr
        0x48, 0x8b, 0x44, 0x24, 0x70, //         mov rax,[rsp+0x70] share
        0x48, 0x89, 0x44, 0x24, 0x38, //               a6 share
        0x48, 0x8b, 0x44, 0x24, 0x78, //         mov rax,[rsp+0x78] disp
        0x48, 0x89, 0x44, 0x24, 0x40, //               a7 disp
        0x48, 0xc7, 0x44, 0x24, 0x48, 0, 0, 0, 0, // a8 options=0
        0x48, 0xc7, 0x44, 0x24, 0x50, 0, 0, 0, 0, // a9 ea=0
        0x48, 0xc7, 0x44, 0x24, 0x58, 0, 0, 0, 0, // a10 ealen=0
        0x4c, 0x8d, 0x54, 0x24, 0x08, //        lea r10,[rsp+0x08] &hout
        0x48, 0x8b, 0x54, 0x24, 0x68, //        mov rdx,[rsp+0x68] access
        0x4c, 0x8d, 0x84, 0x24, 0x98, 0, 0, 0, // lea r8,[rsp+0x98] &oa
        0x4c, 0x8d, 0x4c, 0x24, 0x10, //        lea r9,[rsp+0x10] &iosb
        0xb8, 0x55, 0, 0, 0, //                 mov eax,0x55
        0x0f, 0x05, //                          syscall
        0x85, 0xc0, //                          test eax,eax
    ]);
    let fail = e.jcc(0x8); // js fail
    if delete {
        // Open succeeded: FileDispositionInformation(TRUE) then
        // NtClose — the file unlinks when the handle drops.
        e.raw(&[
            0x48, 0x8b, 0x44, 0x24, 0x08, // mov rax,[rsp+0x08] h
            0x48, 0x89, 0x84, 0x24, 0x88, 0, 0, 0, // [rsp+0x88]=h stash
            0xc6, 0x84, 0x24, 0x90, 0, 0, 0, 1, // mov byte[rsp+0x90],1
            0x4c, 0x8b, 0x94, 0x24, 0x88, 0, 0, 0, // mov r10,[+0x88] h
            0x48, 0x8d, 0x54, 0x24, 0x10, //   lea rdx,[rsp+0x10] iosb
            0x4c, 0x8d, 0x84, 0x24, 0x90, 0, 0, 0, // lea r8,[+0x90] &bool
            0x41, 0xb9, 0x01, 0, 0, 0, //    mov r9d,1
            0x48, 0xc7, 0x44, 0x24, 0x28, 0x0d, 0, 0, 0, // [+0x28]=13
            0xb8, 0x27, 0, 0, 0, //         mov eax,0x27
            0x0f, 0x05, //                  syscall
            // Close either way — a failed mark still drops the handle.
            0x4c, 0x8b, 0x94, 0x24, 0x88, 0, 0, 0, // mov r10,[+0x88]
            0xb8, 0x0f, 0, 0, 0, //         mov eax,0x0f
            0x0f, 0x05, //                  syscall
            0xb8, 1, 0, 0, 0, //           mov eax,1
            0x48, 0x81, 0xc4, 0xc8, 0, 0, 0, // add rsp,0xc8
            0xc3,
        ]);
    } else {
        e.raw(&[
            0x48, 0x8b, 0x44, 0x24, 0x08, // mov rax,[rsp+0x08] hout
            0x48, 0x81, 0xc4, 0xc8, 0, 0, 0, // add rsp,0xc8
            0xc3,
        ]);
    }
    e.fix(fail);
    e.raw(&[0x65, 0x89, 0x04, 0x25, 0x68, 0, 0, 0]); // mov gs:[0x68],eax
    if delete {
        e.raw(&[0x31, 0xc0]); // xor eax,eax
    } else {
        e.raw(&[0x48, 0x83, 0xc8, 0xff]); // or rax,-1
    }
    e.raw(&[
        0x48, 0x81, 0xc4, 0xc8, 0, 0, 0, // add rsp,0xc8
        0xc3,
    ]);
}

/// Emit the FILE_DIRECTORY_INFORMATION -> WIN32_FIND_DATA copy for
/// the record at data+0x600; wfd is the pointer at [rsp+0x60].
/// A converts the name to ANSI (cFileName@0x30, alt@0x134), W
/// passes it through as UTF-16 (cFileName@0x30, alt@0x238).
/// Clobbers only caller-saved registers.
fn emit_find_xlat(e: &mut Emit, wide: bool, d: u64) {
    e.raw(&[0x49, 0xba]);
    e.raw(&(d + 0x600).to_le_bytes()); // mov r10,data+0x600 rec
    e.raw(&[
        0x4c, 0x8b, 0x44, 0x24, 0x60, // mov r8,[rsp+0x60] wfd
        0x41, 0x8b, 0x42, 0x38, //       mov eax,[r10+0x38] attrs
        0x41, 0x89, 0x00, //             mov [r8],eax
        0x41, 0x8b, 0x42, 0x08, //       mov eax,[r10+8]
        0x41, 0x89, 0x40, 0x04, //       mov [r8+4],eax lo creation
        0x41, 0x8b, 0x42, 0x0c,
        0x41, 0x89, 0x40, 0x08,
        0x41, 0x8b, 0x42, 0x10,
        0x41, 0x89, 0x40, 0x0c, //       last access
        0x41, 0x8b, 0x42, 0x14,
        0x41, 0x89, 0x40, 0x10,
        0x41, 0x8b, 0x42, 0x18,
        0x41, 0x89, 0x40, 0x14, //       last write
        0x41, 0x8b, 0x42, 0x1c,
        0x41, 0x89, 0x40, 0x18,
        0x41, 0x8b, 0x42, 0x28, //       mov eax,[r10+0x28] size lo
        0x89, 0xc2, //                   mov edx,eax
        0x41, 0x8b, 0x42, 0x2c, //       mov eax,[r10+0x2c] size hi
        0x41, 0x89, 0x40, 0x1c, //       mov [r8+0x1c],eax nFileSizeHigh
        0x41, 0x89, 0x50, 0x20, //       mov [r8+0x20],edx nFileSizeLow
        0x41, 0x8b, 0x4a, 0x3c, //       mov ecx,[r10+0x3c] namelen bytes
        0xd1, 0xe9, //                   shr ecx,1  -> chars
        0x81, 0xf9, 0x03, 0x01, 0, 0, // cmp ecx,259
    ]);
    let ok = e.jcc(0x6); // jbe ok
    e.raw(&[0xb9, 0x03, 0x01, 0, 0]); // mov ecx,259
    e.fix(ok);
    e.raw(&[
        0x4d, 0x8d, 0x4a, 0x40, //       lea r9,[r10+0x40] name src
        0x4d, 0x8d, 0x58, 0x2c, //       lea r11,[r8+0x2c] cFileName
        0x31, 0xc0, //                   xor eax,eax
    ]);
    let lp = e.n;
    e.raw(&[0x39, 0xc8]); // cmp eax,ecx
    let dn = e.jcc(0x3); // jae done
    if wide {
        e.raw(&[
            0x66, 0x41, 0x8b, 0x14, 0x41, // mov dx,[r9+rax*2]
            0x66, 0x43, 0x89, 0x14, 0x43, // mov [r11+rax*2],dx
        ]);
    } else {
        e.raw(&[
            0x41, 0x0f, 0xb7, 0x14, 0x41, // movzx edx,word[r9+rax*2]
            0x41, 0x88, 0x14, 0x03, //       mov [r11+rax],dl
        ]);
    }
    e.raw(&[0x48, 0xff, 0xc0]); // inc rax
    let back = e.jmp();
    e.fix_to(back, lp);
    e.fix(dn);
    if wide {
        e.raw(&[
            0x66, 0x41, 0xc7, 0x04, 0x43, 0, 0, // word[r11+rax*2]=0
            0x66, 0x41, 0xc7, 0x80, 0x30, 0x02, 0, 0, 0, 0, // alt NUL
        ]);
    } else {
        e.raw(&[
            0x41, 0xc6, 0x04, 0x03, 0x00, // byte[r11+rax]=0
            0x41, 0xc6, 0x80, 0x30, 0x01, 0, 0, 0, // alt NUL
        ]);
    }
}

/// Emit FindFirstFileA/W (first=true) or FindNextFileA/W — the
/// Win32 find layer over NtCreateFile + NtQueryDirectoryFile.
/// FindFirst opens "." with FILE_DIRECTORY_FILE, stores the
/// pattern via the FileName UNICODE_STRING arg, and returns the
/// dir handle itself as the find handle; FindNextFile re-queries
/// it pattern-less. Frame 0x1d0: wfd@0x60, pattern@0x68, dir h@0x70,
/// pattern US@0x88, OA@0x98, "." US@0xd0, A's UTF-16 buf@0xe0.
fn emit_find(e: &mut Emit, wide: bool, first: bool, d: u64) {
    e.raw(&[
        0x48, 0x81, 0xec, 0xd0, 0x01, 0, 0, // sub rsp,0x1d0
        0x48, 0x89, 0x54, 0x24, 0x60, //   mov [rsp+0x60],rdx wfd
    ]);
    let mut ofail = usize::MAX;
    if first {
        e.raw(&[
            0x48, 0x89, 0x4c, 0x24, 0x68, // mov [rsp+0x68],rcx pattern
            // US "." at [rsp+0xd0]: {len 2, cap 2, pad, buf}
            0x66, 0xc7, 0x84, 0x24, 0xd0, 0, 0, 0, 2, 0,
            0x66, 0xc7, 0x84, 0x24, 0xd2, 0, 0, 0, 2, 0,
            0xc7, 0x84, 0x24, 0xd4, 0, 0, 0, 0, 0, 0, 0,
        ]);
        e.rax_imm(d + 0x780);
        e.raw(&[
            0x48, 0x89, 0x84, 0x24, 0xd8, 0, 0, 0, // buf=d+0x780
            // OA at [rsp+0x98]: len 48, root 0, name=&"." US
            0xc7, 0x84, 0x24, 0x98, 0, 0, 0, 0x30, 0, 0, 0,
            0x48, 0xc7, 0x84, 0x24, 0xa0, 0, 0, 0, 0, 0, 0, 0,
            0x48, 0x8d, 0x84, 0x24, 0xd0, 0, 0, 0,
            0x48, 0x89, 0x84, 0x24, 0xa8, 0, 0, 0,
            0xc7, 0x84, 0x24, 0xb0, 0, 0, 0, 0, 0, 0, 0,
            0x48, 0xc7, 0x84, 0x24, 0xb8, 0, 0, 0, 0, 0, 0, 0,
            0x48, 0xc7, 0x84, 0x24, 0xc0, 0, 0, 0, 0, 0, 0, 0,
            // hout + iosb zeroed; 7 NT stack args
            0x48, 0xc7, 0x44, 0x24, 0x08, 0, 0, 0, 0,
            0x48, 0xc7, 0x44, 0x24, 0x10, 0, 0, 0, 0,
            0x48, 0xc7, 0x44, 0x24, 0x18, 0, 0, 0, 0,
            0x48, 0xc7, 0x44, 0x24, 0x28, 0, 0, 0, 0,
            0x48, 0xc7, 0x44, 0x24, 0x30, 0, 0, 0, 0,
            0x48, 0xc7, 0x44, 0x24, 0x38, 0, 0, 0, 0,
            0x48, 0xc7, 0x44, 0x24, 0x40, 3, 0, 0, 0, // disp
            0x48, 0xc7, 0x44, 0x24, 0x48, 1, 0, 0, 0, // DIR opt
            0x48, 0xc7, 0x44, 0x24, 0x50, 0, 0, 0, 0,
            0x48, 0xc7, 0x44, 0x24, 0x58, 0, 0, 0, 0,
            0x4c, 0x8d, 0x54, 0x24, 0x08, // lea r10,[rsp+0x08] hout
            0xba, 0, 0, 0, 0x80, //       mov edx,0x80000000
            0x4c, 0x8d, 0x84, 0x24, 0x98, 0, 0, 0, // lea r8,&oa
            0x4c, 0x8d, 0x4c, 0x24, 0x10, // lea r9,&iosb
            0xb8, 0x55, 0, 0, 0, //       mov eax,0x55
            0x0f, 0x05, //                syscall
            0x85, 0xc0, //                test eax,eax
        ]);
        ofail = e.jcc(0x8); // js open_fail
        e.raw(&[
            0x48, 0x8b, 0x44, 0x24, 0x08, // mov rax,[rsp+0x08] h
            0x48, 0x89, 0x44, 0x24, 0x70, // [rsp+0x70]=dir handle
        ]);
        // Pattern UNICODE_STRING at [rsp+0x88]; buf=[rsp+0xe0].
        if wide {
            e.raw(&[
                0x48, 0x8b, 0x4c, 0x24, 0x68, // mov rcx,[rsp+0x68]
                0x31, 0xc0,
            ]);
            let lp = e.n;
            e.raw(&[0x66, 0x83, 0x3c, 0x41, 0x00]); // cmp word[rcx+rax*2]
            let dn = e.jcc(0x4);
            e.raw(&[0x48, 0x83, 0xc0, 0x01]);
            let back = e.jmp();
            e.fix_to(back, lp);
            e.fix(dn);
            e.raw(&[
                0x48, 0x89, 0xca, // mov rdx,rcx  buf = caller's
                0x48, 0xd1, 0xe0, // shl rax,1
            ]);
        } else {
            e.raw(&[
                0x48, 0x8b, 0x4c, 0x24, 0x68, // mov rcx,[rsp+0x68]
                0x48, 0x8d, 0x94, 0x24, 0xe0, 0, 0, 0, // lea rdx,[+0xe0]
                0x31, 0xc0,
            ]);
            let lp = e.n;
            e.raw(&[
                0x44, 0x0f, 0xb6, 0x1c, 0x01, // movzx r11d,[rcx+rax]
                0x66, 0x44, 0x89, 0x1c, 0x42, // mov [rdx+rax*2],r11w
                0x45, 0x84, 0xdb,
            ]);
            let dn = e.jcc(0x4);
            e.raw(&[
                0x48, 0xff, 0xc0,
                0x48, 0x83, 0xf8, 0x5e, // cap 94 chars
            ]);
            let capped = e.jcc(0x3);
            let back = e.jmp();
            e.fix_to(back, lp);
            e.fix(dn);
            e.fix(capped);
            e.raw(&[
                0x66, 0xc7, 0x04, 0x42, 0, 0, // mov word[rdx+rax*2],0
                0x48, 0xd1, 0xe0, //             shl rax,1
            ]);
        }
        e.raw(&[
            0x66, 0x89, 0x84, 0x24, 0x88, 0, 0, 0, // [+0x88]=ax len
            0x66, 0x89, 0x84, 0x24, 0x8a, 0, 0, 0, // cap
            0xc7, 0x84, 0x24, 0x8c, 0, 0, 0, 0, 0, 0, 0,
            0x48, 0x89, 0x94, 0x24, 0x90, 0, 0, 0, // buf
        ]);
    } else {
        // FindNextFile: handle arrives in rcx, no pattern arg.
        e.raw(&[
            0x48, 0x89, 0x4c, 0x24, 0x70, // mov [rsp+0x70],rcx h
        ]);
    }
    // Shared NtQueryDirectoryFile call: r10=h, rdx/r8/r9=0,
    // stack args iosb/info/len/class/single/fname/restart.
    e.raw(&[
        0x48, 0xc7, 0x44, 0x24, 0x10, 0, 0, 0, 0, // iosb=0
        0x48, 0xc7, 0x44, 0x24, 0x18, 0, 0, 0, 0,
        0x4c, 0x8b, 0x54, 0x24, 0x70, //   mov r10,[rsp+0x70] h
        0x31, 0xd2, //                    xor edx,edx
        0x45, 0x31, 0xc0, //              xor r8d,r8d
        0x45, 0x31, 0xc9, //              xor r9d,r9d
        0x48, 0x8d, 0x44, 0x24, 0x10, //   lea rax,[rsp+0x10]
        0x48, 0x89, 0x44, 0x24, 0x28, //   [+0x28]=&iosb
    ]);
    e.rax_imm(d + 0x600);
    e.raw(&[
        0x48, 0x89, 0x44, 0x24, 0x30, //   [+0x30]=info d+0x600
        0x48, 0xc7, 0x44, 0x24, 0x38, 0, 0x02, 0, 0, // len 0x200
        0x48, 0xc7, 0x44, 0x24, 0x40, 1, 0, 0, 0, // class 1
        0x48, 0xc7, 0x44, 0x24, 0x48, 1, 0, 0, 0, // single
    ]);
    if first {
        e.raw(&[
            0x48, 0x8d, 0x84, 0x24, 0x88, 0, 0, 0, // lea rax,[+0x88]
            0x48, 0x89, 0x44, 0x24, 0x50, // [+0x50]=&us_pattern
            0x48, 0xc7, 0x44, 0x24, 0x58, 1, 0, 0, 0, // restart 1
        ]);
    } else {
        e.raw(&[
            0x48, 0xc7, 0x44, 0x24, 0x50, 0, 0, 0, 0, // fname 0
            0x48, 0xc7, 0x44, 0x24, 0x58, 0, 0, 0, 0, // restart 0
        ]);
    }
    e.raw(&[
        0xb8, 0x35, 0, 0, 0, // mov eax,0x35
        0x0f, 0x05, //         syscall
        0x85, 0xc0, //         test eax,eax
    ]);
    let qfail = e.jcc(0x8); // js qfail
    emit_find_xlat(e, wide, d);
    if first {
        e.raw(&[0x48, 0x8b, 0x44, 0x24, 0x70]); // rax = dir handle
    } else {
        e.raw(&[0xb8, 1, 0, 0, 0]); // mov eax,1
    }
    let done = e.jmp();
    e.fix(qfail);
    e.raw(&[0x65, 0x89, 0x04, 0x25, 0x68, 0, 0, 0]); // mov gs:[0x68],eax
    if first {
        // The dir handle we opened dies with the failed find —
        // real FindFirstFile leaves nothing behind on failure.
        e.raw(&[
            0x4c, 0x8b, 0x54, 0x24, 0x70, // mov r10,[rsp+0x70]
            0xb8, 0x0f, 0, 0, 0, //       mov eax,0x0f
            0x0f, 0x05, //                syscall
            0x48, 0x83, 0xc8, 0xff, //    or rax,-1 (INVALID_HANDLE)
        ]);
    } else {
        e.raw(&[0x31, 0xc0]); // xor eax,eax
    }
    e.fix(done);
    e.raw(&[
        0x48, 0x81, 0xc4, 0xd0, 0x01, 0, 0, // add rsp,0x1d0
        0xc3,
    ]);
    if first {
        e.fix(ofail);
        e.raw(&[
            0x65, 0x89, 0x04, 0x25, 0x68, 0, 0, 0, // gs:[0x68]=eax
            0x48, 0x83, 0xc8, 0xff, //              or rax,-1
            0x48, 0x81, 0xc4, 0xd0, 0x01, 0, 0,
            0xc3,
        ]);
    }
}

/// Emit FindClose(h): NtClose — the dir handle IS the find handle.
fn emit_findclose(e: &mut Emit) {
    e.raw(&[
        0x49, 0x89, 0xca, // mov r10,rcx
        0xb8, 0x0f, 0, 0, 0, // mov eax,0x0f
        0x0f, 0x05,
        0x85, 0xc0,
    ]);
    let fail = e.jcc(0x8);
    e.raw(&[0xb8, 1, 0, 0, 0, 0xc3]);
    e.fix(fail);
    e.raw(&[0x31, 0xc0, 0xc3]);
}

/// Win32 translation thunk emitter: given a kernel32/kernelbase/
/// api-ms-*/msvcrt export name, emits a real Win64 function that
/// re-marshals the caller's arguments into the NT service
/// convention — compiled `call [rip+IAT]` code lands on native code
/// behaving like the export. Returns the byte count (not aligned).
/// The data-page constants (argv/envp/FILE[]/TLS slots) live at
/// STUB_DATA_VA, laid out by k32_data_init below.
fn k32_emit(buf: &mut [u8], name: &[u8]) -> Option<usize> {
    let d = crate::pe::STUB_DATA_VA;
    let mut e = Emit { b: buf, n: 0 };
    match name {
        // --- void functions: nothing to marshal -----------------
        b"DeleteCriticalSection" | b"EnterCriticalSection"
        | b"LeaveCriticalSection" | b"InitializeCriticalSection"
        | b"__set_app_type" | b"__setusermatherr" | b"_cexit" => {
            e.raw(&[0xc3]);
        }
        // --- inert stubs: resolve but are never expected to run.
        // fprintf/vfprintf take varargs a thunk cannot format —
        // CRT startup imports them without calling on this path.
        b"__C_specific_handler" | b"fprintf" | b"vfprintf" | b"signal" => {
            e.raw(&[0x31, 0xc0, 0xc3]);
        }
        // _fpreset: CRT's FPU reset — real msvcrt fninit+mxcsr reset;
        // fninit restores the INIT_FX x87 state tasks already run.
        b"_fpreset" => {
            e.raw(&[0xdb, 0xe3, 0xc3]); // fninit; ret
        }
        // TEB LastErrorValue lives at gs:[0x68] (real TEB offset).
        b"GetLastError" => e.raw(&[0x65, 0x8b, 0x04, 0x25, 0x68, 0, 0, 0, 0xc3]),
        b"SetLastError" => e.raw(&[0x65, 0x89, 0x0c, 0x25, 0x68, 0, 0, 0, 0xc3]),
        // SetUnhandledExceptionFilter(f) -> previous at data+0x100.
        b"SetUnhandledExceptionFilter" => {
            e.rax_imm(d + 0x100);
            e.raw(&[0x48, 0x8b, 0x10, 0x48, 0x89, 0x08, 0x48, 0x89, 0xd0, 0xc3]);
        }
        // GetStdHandle(-10/-11/-12) -> NT std handles 1/2/3.
        b"GetStdHandle" => {
            e.raw(&[
                0x83, 0xf9, 0xf6, 0x74, 0x0d, 0x83, 0xf9, 0xf5, 0x74, 0x0e,
                0x83, 0xf9, 0xf4, 0x74, 0x0f, 0x31, 0xc0, 0xc3, 0xb8, 1,
                0, 0, 0, 0xc3, 0xb8, 2, 0, 0, 0, 0xc3, 0xb8, 3, 0, 0, 0,
                0xc3,
            ]);
        }
        // GetModuleHandleA(name): NULL -> PEB.ImageBaseAddress; a
        // real name -> RUX_MOD_HANDLE ledger lookup (no ref bump).
        b"GetModuleHandleA" => {
            e.raw(&[
                0x48, 0x85, 0xc9, // test rcx,rcx
            ]);
            let named = e.jcc(0x5); // jnz named
            e.raw(&[
                0x65, 0x48, 0x8b, 0x04, 0x25, 0x60, 0, 0, 0, // mov rax,gs:[0x60]
                0x48, 0x8b, 0x40, 0x10, // mov rax,[rax+0x10]
                0xc3, //               ret
            ]);
            e.fix(named);
            e.raw(&[
                0x4c, 0x8b, 0xd1, //     mov r10,rcx
                0x31, 0xd2, //           xor edx,edx
                0xb8, 0xf8, 0, 0, 0, // mov eax,0xF8
                0x0f, 0x05, //           syscall
                0xc3, //                 ret
            ]);
        }
        // CreateProcessA(app,cmd,sa,tsa,inh,flags,env,cwd,si,pi):
        // args 5..10 ride the caller's stack — flags@+0x30, pi@+0x50.
        // Marshal (app, cmd, pi, flags) -> RUX_SPAWN_PROC and map
        // NTSTATUS to BOOL (0 -> TRUE like every thunk that returns
        // success rather than a value).
        b"CreateProcessA" => {
            e.raw(&[
                0x4c, 0x8b, 0xd1, //             mov r10,rcx   (app)
                0x4c, 0x8b, 0x44, 0x24, 0x50, // mov r8,[rsp+0x50] (pi)
                0x4c, 0x8b, 0x4c, 0x24, 0x30, // mov r9,[rsp+0x30] (flags)
                0xb8, 0xfd, 0, 0, 0, //         mov eax,0xFD
                0x0f, 0x05, //                   syscall
                0x85, 0xc0, //                   test eax,eax
                0x0f, 0x94, 0xc0, //             sete al
                0x0f, 0xb6, 0xc0, //             movzx eax,al
                0xc3, //                         ret
            ]);
        }
        // GetExitCodeProcess(h,&code) -> RUX_PROC_QUERY (h, &code);
        // the service writes STILL_ACTIVE while the group lives.
        b"GetExitCodeProcess" => {
            e.raw(&[
                0x4c, 0x8b, 0xd1, //             mov r10,rcx
                0xb8, 0xfe, 0, 0, 0, //         mov eax,0xFE
                0x0f, 0x05, //                   syscall
                0x85, 0xc0, //                   test eax,eax
                0x0f, 0x94, 0xc0, //             sete al
                0x0f, 0xb6, 0xc0, //             movzx eax,al
                0xc3, //                         ret
            ]);
        }
        // Time/system-info services — RUX_SYS_INFO 0xFF:
        // r10 = sub, rdx = out pointer (arg0).
        // GetSystemInfo/GetNativeSystemInfo(lpSI) -> sub 0, void.
        b"GetSystemInfo" | b"GetNativeSystemInfo" => {
            e.raw(&[
                0x48, 0x89, 0xca, //             mov rdx,rcx
                0x41, 0xba, 0, 0, 0, 0, //      mov r10d,0
                0xb8, 0xff, 0, 0, 0, //         mov eax,0xFF
                0x0f, 0x05, 0xc3, //             syscall; ret
            ]);
        }
        // GetTickCount{,64} -> sub 1, ms in rax.
        b"GetTickCount" | b"GetTickCount64" => {
            e.raw(&[
                0x41, 0xba, 1, 0, 0, 0, //      mov r10d,1
                0xb8, 0xff, 0, 0, 0, //         mov eax,0xFF
                0x0f, 0x05, 0xc3, //             syscall; ret
            ]);
        }
        // GetSystemTimeAsFileTime(lp) -> sub 2, void.
        b"GetSystemTimeAsFileTime" => {
            e.raw(&[
                0x48, 0x89, 0xca, //             mov rdx,rcx
                0x41, 0xba, 2, 0, 0, 0, //      mov r10d,2
                0xb8, 0xff, 0, 0, 0, //         mov eax,0xFF
                0x0f, 0x05, 0xc3, //             syscall; ret
            ]);
        }
        // GetSystemTime/GetLocalTime(lp) -> sub 3, void (no TZ
        // database — LocalTime == SystemTime, recorded divergence).
        b"GetSystemTime" | b"GetLocalTime" => {
            e.raw(&[
                0x48, 0x89, 0xca, //             mov rdx,rcx
                0x41, 0xba, 3, 0, 0, 0, //      mov r10d,3
                0xb8, 0xff, 0, 0, 0, //         mov eax,0xFF
                0x0f, 0x05, 0xc3, //             syscall; ret
            ]);
        }
        // QueryPerformanceCounter/Frequency(lp) -> subs 4/5, BOOL.
        b"QueryPerformanceCounter" => {
            e.raw(&[
                0x48, 0x89, 0xca, //             mov rdx,rcx
                0x41, 0xba, 4, 0, 0, 0, //      mov r10d,4
                0xb8, 0xff, 0, 0, 0, //         mov eax,0xFF
                0x0f, 0x05, //                   syscall
                0x85, 0xc0, //                   test eax,eax
                0x0f, 0x94, 0xc0, //             sete al
                0x0f, 0xb6, 0xc0, //             movzx eax,al
                0xc3,
            ]);
        }
        b"QueryPerformanceFrequency" => {
            e.raw(&[
                0x48, 0x89, 0xca, //             mov rdx,rcx
                0x41, 0xba, 5, 0, 0, 0, //      mov r10d,5
                0xb8, 0xff, 0, 0, 0, //         mov eax,0xFF
                0x0f, 0x05, //                   syscall
                0x85, 0xc0, //                   test eax,eax
                0x0f, 0x94, 0xc0, //             sete al
                0x0f, 0xb6, 0xc0, //             movzx eax,al
                0xc3,
            ]);
        }
        // GetVersion -> sub 6, packed dword in eax.
        b"GetVersion" => {
            e.raw(&[
                0x41, 0xba, 6, 0, 0, 0, //      mov r10d,6
                0xb8, 0xff, 0, 0, 0, //         mov eax,0xFF
                0x0f, 0x05, 0xc3, //             syscall; ret
            ]);
        }
        // GetVersionExA/W(lpOSVI) -> subs 7/8, BOOL.
        b"GetVersionExA" => {
            e.raw(&[
                0x48, 0x89, 0xca, //             mov rdx,rcx
                0x41, 0xba, 7, 0, 0, 0, //      mov r10d,7
                0xb8, 0xff, 0, 0, 0, //         mov eax,0xFF
                0x0f, 0x05, //                   syscall
                0x85, 0xc0, //                   test eax,eax
                0x0f, 0x94, 0xc0, //             sete al
                0x0f, 0xb6, 0xc0, //             movzx eax,al
                0xc3,
            ]);
        }
        b"GetVersionExW" => {
            e.raw(&[
                0x48, 0x89, 0xca, //             mov rdx,rcx
                0x41, 0xba, 8, 0, 0, 0, //      mov r10d,8
                0xb8, 0xff, 0, 0, 0, //         mov eax,0xFF
                0x0f, 0x05, //                   syscall
                0x85, 0xc0, //                   test eax,eax
                0x0f, 0x94, 0xc0, //             sete al
                0x0f, 0xb6, 0xc0, //             movzx eax,al
                0xc3,
            ]);
        }
        // Path/directory/file services — RUX_PATH 0x100:
        // r10 = sub, rdx/r8/r9 = a1/a2/a3 (same marshalling as
        // RUX_SYS_INFO). GetCurrentDirectory*(len,buf) ->
        // sub 0, DWORD chars.
        b"GetCurrentDirectoryA" => {
            e.raw(&[
                0x49, 0x89, 0xc8, //             mov r8,rcx (len)
                0x45, 0x31, 0xc9, //             xor r9d,r9d (ansi)
                0x41, 0xba, 0, 0, 0, 0, //      mov r10d,0
                0xb8, 0x00, 0x01, 0, 0, //       mov eax,0x100
                0x0f, 0x05, 0xc3, //             syscall; ret
            ]);
        }
        b"GetCurrentDirectoryW" => {
            e.raw(&[
                0x49, 0x89, 0xc8, //             mov r8,rcx (len)
                0x41, 0xb9, 1, 0, 0, 0, //      mov r9d,1 (wide)
                0x41, 0xba, 0, 0, 0, 0, //      mov r10d,0
                0xb8, 0x00, 0x01, 0, 0, //       mov eax,0x100
                0x0f, 0x05, 0xc3, //             syscall; ret
            ]);
        }
        // SetCurrentDirectory*(path) -> sub 1, BOOL.
        b"SetCurrentDirectoryA" => {
            e.raw(&[
                0x48, 0x89, 0xca, //             mov rdx,rcx
                0x45, 0x31, 0xc0, //             xor r8d,r8d (ansi)
                0x41, 0xba, 1, 0, 0, 0, //      mov r10d,1
                0xb8, 0x00, 0x01, 0, 0, //       mov eax,0x100
                0x0f, 0x05, //                   syscall
                0x85, 0xc0, //                   test eax,eax
                0x0f, 0x94, 0xc0, //             sete al
                0x0f, 0xb6, 0xc0, //             movzx eax,al
                0xc3,
            ]);
        }
        b"SetCurrentDirectoryW" => {
            e.raw(&[
                0x48, 0x89, 0xca, //             mov rdx,rcx
                0x41, 0xb8, 1, 0, 0, 0, //      mov r8d,1 (wide)
                0x41, 0xba, 1, 0, 0, 0, //      mov r10d,1
                0xb8, 0x00, 0x01, 0, 0, //       mov eax,0x100
                0x0f, 0x05, //                   syscall
                0x85, 0xc0, //                   test eax,eax
                0x0f, 0x94, 0xc0, //             sete al
                0x0f, 0xb6, 0xc0, //             movzx eax,al
                0xc3,
            ]);
        }
        // GetFullPathName*(path,len,buf,fp) -> sub 2, DWORD chars.
        // a3 packs (len<<1)|wide; filepart arg ignored (NULL use).
        b"GetFullPathNameA" => {
            e.raw(&[
                0x4c, 0x8d, 0x0c, 0x12, //        lea r9,[rdx+rdx] (len*2)
                0x48, 0x89, 0xca, //             mov rdx,rcx (path)
                0x41, 0xba, 2, 0, 0, 0, //      mov r10d,2
                0xb8, 0x00, 0x01, 0, 0, //       mov eax,0x100
                0x0f, 0x05, 0xc3, //             syscall; ret
            ]);
        }
        b"GetFullPathNameW" => {
            e.raw(&[
                0x4c, 0x8d, 0x0c, 0x12, //        lea r9,[rdx+rdx] (len*2)
                0x49, 0x83, 0xc9, 0x01, //        or r9,1 (wide)
                0x48, 0x89, 0xca, //             mov rdx,rcx (path)
                0x41, 0xba, 2, 0, 0, 0, //      mov r10d,2
                0xb8, 0x00, 0x01, 0, 0, //       mov eax,0x100
                0x0f, 0x05, 0xc3, //             syscall; ret
            ]);
        }
        // Create/RemoveDirectory*(path[,sa]) -> subs 3/4, BOOL.
        b"CreateDirectoryA" | b"CreateDirectoryW" => {
            let wide = name == b"CreateDirectoryW";
            e.raw(&[0x48, 0x89, 0xca]); //         mov rdx,rcx
            if wide {
                e.raw(&[0x41, 0xb8, 1, 0, 0, 0]); // mov r8d,1
            } else {
                e.raw(&[0x45, 0x31, 0xc0]); //     xor r8d,r8d
            }
            e.raw(&[
                0x41, 0xba, 3, 0, 0, 0, //      mov r10d,3
                0xb8, 0x00, 0x01, 0, 0, //       mov eax,0x100
                0x0f, 0x05, //                   syscall
                0x85, 0xc0, //                   test eax,eax
                0x0f, 0x94, 0xc0, //             sete al
                0x0f, 0xb6, 0xc0, //             movzx eax,al
                0xc3,
            ]);
        }
        b"RemoveDirectoryA" | b"RemoveDirectoryW" => {
            let wide = name == b"RemoveDirectoryW";
            e.raw(&[0x48, 0x89, 0xca]); //         mov rdx,rcx
            if wide {
                e.raw(&[0x41, 0xb8, 1, 0, 0, 0]); // mov r8d,1
            } else {
                e.raw(&[0x45, 0x31, 0xc0]); //     xor r8d,r8d
            }
            e.raw(&[
                0x41, 0xba, 4, 0, 0, 0, //      mov r10d,4
                0xb8, 0x00, 0x01, 0, 0, //       mov eax,0x100
                0x0f, 0x05, //                   syscall
                0x85, 0xc0, //                   test eax,eax
                0x0f, 0x94, 0xc0, //             sete al
                0x0f, 0xb6, 0xc0, //             movzx eax,al
                0xc3,
            ]);
        }
        // GetFileAttributes*(path) -> sub 5, DWORD attrs.
        b"GetFileAttributesA" => {
            e.raw(&[
                0x48, 0x89, 0xca, //             mov rdx,rcx
                0x45, 0x31, 0xc0, //             xor r8d,r8d (ansi)
                0x41, 0xba, 5, 0, 0, 0, //      mov r10d,5
                0xb8, 0x00, 0x01, 0, 0, //       mov eax,0x100
                0x0f, 0x05, 0xc3, //             syscall; ret
            ]);
        }
        b"GetFileAttributesW" => {
            e.raw(&[
                0x48, 0x89, 0xca, //             mov rdx,rcx
                0x41, 0xb8, 1, 0, 0, 0, //      mov r8d,1 (wide)
                0x41, 0xba, 5, 0, 0, 0, //      mov r10d,5
                0xb8, 0x00, 0x01, 0, 0, //       mov eax,0x100
                0x0f, 0x05, 0xc3, //             syscall; ret
            ]);
        }
        // GetFileType(h) -> sub 6, DWORD type.
        b"GetFileType" => {
            e.raw(&[
                0x48, 0x89, 0xca, //             mov rdx,rcx
                0x41, 0xba, 6, 0, 0, 0, //      mov r10d,6
                0xb8, 0x00, 0x01, 0, 0, //       mov eax,0x100
                0x0f, 0x05, 0xc3, //             syscall; ret
            ]);
        }
        // SetEndOfFile(h) -> sub 7, BOOL.
        b"SetEndOfFile" => {
            e.raw(&[
                0x48, 0x89, 0xca, //             mov rdx,rcx
                0x41, 0xba, 7, 0, 0, 0, //      mov r10d,7
                0xb8, 0x00, 0x01, 0, 0, //       mov eax,0x100
                0x0f, 0x05, //                   syscall
                0x85, 0xc0, //                   test eax,eax
                0x0f, 0x94, 0xc0, //             sete al
                0x0f, 0xb6, 0xc0, //             movzx eax,al
                0xc3,
            ]);
        }
        // FlushFileBuffers(h) -> sub 8, BOOL.
        b"FlushFileBuffers" => {
            e.raw(&[
                0x48, 0x89, 0xca, //             mov rdx,rcx
                0x41, 0xba, 8, 0, 0, 0, //      mov r10d,8
                0xb8, 0x00, 0x01, 0, 0, //       mov eax,0x100
                0x0f, 0x05, //                   syscall
                0x85, 0xc0, //                   test eax,eax
                0x0f, 0x94, 0xc0, //             sete al
                0x0f, 0xb6, 0xc0, //             movzx eax,al
                0xc3,
            ]);
        }
        // GlobalMemoryStatusEx(buf) -> sub 9, BOOL.
        b"GlobalMemoryStatusEx" => {
            e.raw(&[
                0x48, 0x89, 0xca, //             mov rdx,rcx
                0x41, 0xba, 9, 0, 0, 0, //      mov r10d,9
                0xb8, 0x00, 0x01, 0, 0, //       mov eax,0x100
                0x0f, 0x05, //                   syscall
                0x85, 0xc0, //                   test eax,eax
                0x0f, 0x94, 0xc0, //             sete al
                0x0f, 0xb6, 0xc0, //             movzx eax,al
                0xc3,
            ]);
        }
        // GetComputerName*(buf,size*) -> sub 10, BOOL.
        b"GetComputerNameA" => {
            e.raw(&[
                0x49, 0x89, 0xd0, //             mov r8,rdx (size*)
                0x48, 0x89, 0xca, //             mov rdx,rcx (buf)
                0x45, 0x31, 0xc9, //             xor r9d,r9d (ansi)
                0x41, 0xba, 10, 0, 0, 0, //     mov r10d,10
                0xb8, 0x00, 0x01, 0, 0, //       mov eax,0x100
                0x0f, 0x05, //                   syscall
                0x85, 0xc0, //                   test eax,eax
                0x0f, 0x94, 0xc0, //             sete al
                0x0f, 0xb6, 0xc0, //             movzx eax,al
                0xc3,
            ]);
        }
        b"GetComputerNameW" => {
            e.raw(&[
                0x49, 0x89, 0xd0, //             mov r8,rdx (size*)
                0x48, 0x89, 0xca, //             mov rdx,rcx (buf)
                0x41, 0xb9, 1, 0, 0, 0, //      mov r9d,1 (wide)
                0x41, 0xba, 10, 0, 0, 0, //     mov r10d,10
                0xb8, 0x00, 0x01, 0, 0, //       mov eax,0x100
                0x0f, 0x05, //                   syscall
                0x85, 0xc0, //                   test eax,eax
                0x0f, 0x94, 0xc0, //             sete al
                0x0f, 0xb6, 0xc0, //             movzx eax,al
                0xc3,
            ]);
        }
        // IsDebuggerPresent -> PEB.BeingDebugged.
        b"IsDebuggerPresent" => {
            e.raw(&[
                0x65, 0x48, 0x8b, 0x04, 0x25, 0x60, 0, 0, 0,
                0x0f, 0xb6, 0x40, 0x02, 0xc3,
            ]);
        }
        // GetCommandLineA -> ANSI full command line in the data
        // page (0xa00; argv0 itself stays at 0x40).
        b"GetCommandLineA" => {
            e.rax_imm(d + 0xa00);
            e.raw(&[0xc3]);
        }
        // GetCommandLineW -> the real UNICODE_STRING buffer in
        // PEB.ProcessParameters.CommandLine (UTF-16 "<exe>.exe").
        b"GetCommandLineW" => {
            e.raw(&[
                0x65, 0x48, 0x8b, 0x04, 0x25, 0x60, 0, 0, 0, // mov rax,gs:[0x60]
                0x48, 0x8b, 0x40, 0x20, // mov rax,[rax+0x20] ProcessParameters
                0x48, 0x8b, 0x80, 0x88, 0, 0, 0, // mov rax,[rax+0x88] CmdLine.Buffer
                0xc3,
            ]);
        }
        // Process/thread identity from TEB.ClientId {pid@0x40,tid@0x48}.
        b"GetCurrentProcessId" => {
            e.raw(&[0x65, 0x8b, 0x04, 0x25, 0x40, 0, 0, 0, 0xc3]); // mov eax,gs:[0x40]; ret
        }
        b"GetCurrentThreadId" => {
            e.raw(&[0x65, 0x8b, 0x04, 0x25, 0x48, 0, 0, 0, 0xc3]); // mov eax,gs:[0x48]; ret
        }
        b"GetCurrentProcess" => {
            e.raw(&[0x48, 0xc7, 0xc0, 0xff, 0xff, 0xff, 0xff, 0xc3]); // rax=-1; ret
        }
        b"GetCurrentThread" => {
            e.raw(&[0x48, 0xc7, 0xc0, 0xfe, 0xff, 0xff, 0xff, 0xc3]); // rax=-2; ret
        }
        // GetModuleHandleW — same shape as the A arm, wide name.
        b"GetModuleHandleW" => {
            e.raw(&[
                0x48, 0x85, 0xc9, // test rcx,rcx
            ]);
            let named = e.jcc(0x5); // jnz named
            e.raw(&[
                0x65, 0x48, 0x8b, 0x04, 0x25, 0x60, 0, 0, 0,
                0x48, 0x8b, 0x40, 0x10,
                0xc3,
            ]);
            e.fix(named);
            e.raw(&[
                0x4c, 0x8b, 0xd1, //     mov r10,rcx
                0xba, 1, 0, 0, 0, //   mov edx,1
                0xb8, 0xf8, 0, 0, 0, // mov eax,0xF8
                0x0f, 0x05, //           syscall
                0xc3, //                 ret
            ]);
        }
        // Environment blocks in the data page (ANSI 0x800, UTF-16 0x820).
        b"GetEnvironmentStringsA" | b"GetEnvironmentStrings" => {
            e.rax_imm(d + 0x800);
            e.raw(&[0xc3]);
        }
        b"GetEnvironmentStringsW" => {
            e.rax_imm(d + 0x820);
            e.raw(&[0xc3]);
        }
        b"FreeEnvironmentStringsA" | b"FreeEnvironmentStringsW" => {
            e.raw(&[0xb8, 1, 0, 0, 0, 0xc3]); // mov eax,1; ret
        }
        // GetEnvironmentVariable*(name,buf,len): only RUSTUX exists —
        // report not-found honestly (LastError=ERROR_ENVVAR_NOT_FOUND).
        b"GetEnvironmentVariableA" | b"GetEnvironmentVariableW" => {
            e.raw(&[
                0x65, 0xc7, 0x04, 0x25, 0x68, 0, 0, 0, 0xcb, 0, 0, 0, // gs:[0x68]=203
                0x31, 0xc0, 0xc3, // xor eax,eax; ret
            ]);
        }
        // GetStartupInfoA/W(&si): rep-movsb the canned 104B STARTUPINFO.
        b"GetStartupInfoA" | b"GetStartupInfoW" => {
            e.raw(&[
                0x48, 0x89, 0xcf, // mov rdi,rcx
                0x48, 0xbe, //    mov rsi,<d+0x840>
            ]);
            e.raw(&(d + 0x840).to_le_bytes());
            e.raw(&[
                0xb9, 0x68, 0, 0, 0, // mov ecx,104
                0xf3, 0xa4, //           rep movsb
                0xc3,
            ]);
        }
        // TLS: 64 slots — the pointer array gs:[0x58] points at
        // (leader: data+0x200; worker TEB: teb+0x200 — values are
        // per-thread), process-global 64-bit alloc bitmap at
        // data+0x1f8 shared by every thread's TlsAlloc/TlsFree.
        b"TlsGetValue" | b"FlsGetValue" => {
            e.raw(&[0x83, 0xf9, 0x40]); // cmp ecx,0x40
            let fail = e.jcc(0x3); //       jae
            e.raw(&[
                0x65, 0x48, 0x8b, 0x04, 0x25, 0x58, 0, 0, 0, // mov rax,gs:[0x58]
                0x48, 0x8b, 0x04, 0xc8, 0xc3, // mov rax,[rax+rcx*8]; ret
            ]);
            e.fix(fail);
            e.raw(&[0x31, 0xc0, 0xc3]);
        }
        b"TlsSetValue" | b"FlsSetValue" => {
            e.raw(&[0x83, 0xf9, 0x40]);
            let fail = e.jcc(0x3);
            e.raw(&[
                0x65, 0x48, 0x8b, 0x04, 0x25, 0x58, 0, 0, 0, // mov rax,gs:[0x58]
                0x48, 0x89, 0x14, 0xc8, // mov [rax+rcx*8],rdx
                0xb8, 1, 0, 0, 0, 0xc3, // mov eax,1; ret
            ]);
            e.fix(fail);
            e.raw(&[0x31, 0xc0, 0xc3]);
        }
        b"TlsAlloc" | b"FlsAlloc" => {
            // TLS indexes are process-global on Windows — only the
            // slot VALUES are per-thread. Allocate out of the shared
            // bitmap in the data page (STUB_DATA_VA+0x1f8): a worker
            // thread consulting its own map would re-issue an index
            // the CRT (or another thread) already owns, and the CRT's
            // TLS-detach destructor pass would then deref the foreign
            // value as a pointer. lock bts keeps concurrent allocs
            // from two threads from returning the same index.
            e.rax_imm(crate::pe::STUB_DATA_VA + 0x1f8);
            e.raw(&[0x31, 0xd2]); // xor edx,edx
            let lp = e.n;
            e.raw(&[0x83, 0xfa, 0x40]); // cmp edx,0x40
            let full = e.jcc(0x3); //       jae full
            e.raw(&[0xf0, 0x48, 0x0f, 0xab, 0x10]); // lock bts [rax],rdx
            let got = e.jcc(0x3); //         jae/jnc got (CF = old bit)
            e.raw(&[0xff, 0xc2]); //         inc edx
            let back = e.jmp(); //           jmp lp
            e.fix_to(back, lp);
            e.fix(got);
            // A fresh index reads NULL in the calling thread — stale
            // values left by a freed index must not leak into the
            // next owner (CRT detach machinery derefs its slots).
            e.raw(&[
                0x65, 0x4c, 0x8b, 0x1c, 0x25, 0x58, 0, 0, 0, // mov r11,gs:[0x58]
                0x49, 0xc7, 0x44, 0xd3, 0x00, 0, 0, 0, 0, // mov qword [r11+rdx*8],0
                0x89, 0xd0, 0xc3, //      mov eax,edx; ret
            ]);
            e.fix(full);
            e.raw(&[0xb8, 0xff, 0xff, 0xff, 0xff, 0xc3]); // mov eax,-1; ret
        }
        b"TlsFree" | b"FlsFree" => {
            e.raw(&[0x83, 0xf9, 0x40]);
            let fail = e.jcc(0x3);
            e.rax_imm(crate::pe::STUB_DATA_VA + 0x1f8);
            e.raw(&[
                0xf0, 0x48, 0x0f, 0xb3, 0x08, // lock btr [rax],rcx
            ]);
            // Windows fails TlsFree on an index that was never
            // allocated — btr's CF carries the old bit.
            let unset = e.jcc(0x3); //         jnc fail
            // Clear the slot value in the freeing thread too — a
            // stale pointer must not survive into a later owner of
            // the reissued index. (Windows also clears it in every
            // other thread; that sweep needs a TEB walk we don't do.)
            e.raw(&[
                0x65, 0x4c, 0x8b, 0x1c, 0x25, 0x58, 0, 0, 0, // mov r11,gs:[0x58]
                0x49, 0xc7, 0x44, 0xcb, 0x00, 0, 0, 0, 0, // mov qword [r11+rcx*8],0
                0xb8, 1, 0, 0, 0, 0xc3, //       mov eax,1; ret
            ]);
            e.fix(fail);
            e.fix(unset);
            e.raw(&[0x31, 0xc0, 0xc3]);
        }
        // ---- threads ------------------------------------------------
        // CreateThread(sa, stacksz, fn, param, flags, &tid) and the
        // msvcrt _beginthreadex (same ABI): marshal onto
        // NtCreateThreadEx(&h, 0x1fffff, 0, -1, fn, param, flags, 0,
        // 0, stacksz, 0), then NtQueryInformationThread for the
        // caller's tid out-param. The new thread's own stack carries
        // a synthetic return address into the thread-exit stub.
        b"CreateThread" | b"_beginthreadex" | b"_beginthread" => {
            e.raw(&[
                0x48, 0x83, 0xec, 0x68, // sub rsp,0x68
                0x4c, 0x89, 0x44, 0x24, 0x28, // mov [rsp+0x28],r8 (start)
                0x4c, 0x89, 0x4c, 0x24, 0x30, // mov [rsp+0x30],r9 (param)
                0x48, 0x8b, 0x84, 0x24, 0x90, 0, 0, 0, // mov rax,[rsp+0x90] flags
                0x48, 0x89, 0x44, 0x24, 0x38, // mov [rsp+0x38],rax
                0x48, 0xc7, 0x44, 0x24, 0x40, 0, 0, 0, 0, // arg8 zerobits=0
                0x48, 0x89, 0x54, 0x24, 0x48, // mov [rsp+0x48],rdx (reserve)
                0x48, 0xc7, 0x44, 0x24, 0x50, 0, 0, 0, 0, // arg11 attr=0
                0x4c, 0x8d, 0x54, 0x24, 0x60, // lea r10,[rsp+0x60] &h
                0xba, 0xff, 0xff, 0x1f, 0, // mov edx,0x1fffff access
                0x45, 0x31, 0xc0, //          xor r8d,r8d    oa=0
                0x49, 0xc7, 0xc1, 0xff, 0xff, 0xff, 0xff, // mov r9,-1 proch
                0xb8, 0xc1, 0, 0, 0, //       mov eax,0xc1
                0x0f, 0x05, //               syscall
            ]);
            let fail = e.jcc(0x8); //          js fail
            // ThreadBasicInformation query for the tid out-param.
            e.raw(&[
                0x4c, 0x8b, 0x54, 0x24, 0x60, // mov r10,[rsp+0x60] h
                0x31, 0xd2, //               xor edx,edx  class 0
                0x4c, 0x8d, 0x44, 0x24, 0x10, // lea r8,[rsp+0x10] tbi
                0x41, 0xb9, 0x30, 0, 0, 0, // mov r9d,48
                0x48, 0xc7, 0x44, 0x24, 0x28, 0, 0, 0, 0, // arg5 retsz=0
                0xb8, 0x25, 0, 0, 0, //       mov eax,0x25
                0x0f, 0x05, //               syscall
            ]);
            let skip = e.jcc(0x8); //          js skip tid store
            e.raw(&[
                0x48, 0x8b, 0x84, 0x24, 0x98, 0, 0, 0, // mov rax,[rsp+0x98] &tid
                0x48, 0x85, 0xc0, //          test rax,rax
            ]);
            let null = e.jcc(0x4); //          jz null
            e.raw(&[
                0x48, 0x8b, 0x54, 0x24, 0x28, // mov rdx,[rsp+0x28] UniqueThread
                0x89, 0x10, //               mov [rax],edx
            ]);
            e.fix(null);
            e.fix(skip);
            e.raw(&[0x48, 0x8b, 0x44, 0x24, 0x60]); // mov rax,[rsp+0x60] h
            e.fix(fail); // on create failure rax is already 0? No —
            // NTSTATUS sits in rax; force 0 like Win32's NULL return.
            e.raw(&[
                0x0f, 0x89, 2, 0, 0, 0, //    jns +2 (success keeps rax)
                0x31, 0xc0, //               xor eax,eax
                0x48, 0x83, 0xc4, 0x68, 0xc3, // add rsp,0x68; ret
            ]);
        }
        // ExitThread(code): every live module gets DllMain(
        // DLL_THREAD_DETACH) reverse-order first, like the real
        // ExitThread — then NtTerminateThread(0, code). Never
        // returns; the int3 canaries any path that slips past.
        b"ExitThread" => {
            e.raw(&[
                0x48, 0x83, 0xec, 0x28, // sub rsp,0x28
                0x48, 0x89, 0x4c, 0x24, 0x20, // mov [rsp+0x20],rcx code
                0x31, 0xdb, //               xor ebx,ebx     enum cursor
            ]);
            emit_thr_drain(&mut e, 1, 3); // DLL_THREAD_DETACH reverse
            emit_exe_tls(&mut e, 3); //       exe TLS cbs last
            e.raw(&[
                0x48, 0x8b, 0x54, 0x24, 0x20, // mov rdx,[rsp+0x20] status
                0x48, 0x83, 0xc4, 0x28, //    add rsp,0x28
                0x45, 0x31, 0xd2, //          xor r10d,r10d (self)
                0xb8, 0x53, 0, 0, 0, //       mov eax,0x53
                0x0f, 0x05, 0xcc, //          syscall; int3
            ]);
        }
        // GetThreadId(h) -> TBI.UniqueThread via the query service.
        b"GetThreadId" => {
            e.raw(&[
                0x48, 0x83, 0xec, 0x48, // sub rsp,0x48
                0x49, 0x89, 0xca, //          mov r10,rcx   handle
                0x31, 0xd2, //               xor edx,edx   class 0
                0x4c, 0x8d, 0x44, 0x24, 0x08, // lea r8,[rsp+8] tbi
                0x41, 0xb9, 0x30, 0, 0, 0, // mov r9d,48
                0x48, 0xc7, 0x44, 0x24, 0x28, 0, 0, 0, 0, // retsz=0
                0xb8, 0x25, 0, 0, 0, 0x0f, 0x05, // mov eax,0x25; syscall
            ]);
            let fail = e.jcc(0x8); //          js fail
            e.raw(&[0x48, 0x8b, 0x44, 0x24, 0x20]); // rax=[tbi+0x18] tid
            e.fix(fail);
            e.raw(&[
                0x0f, 0x89, 2, 0, 0, 0, 0x31, 0xc0, // jns +2; xor eax,eax
                0x48, 0x83, 0xc4, 0x48, 0xc3, // add rsp,0x48; ret
            ]);
        }
        // GetExitCodeThread(h, &code) -> ExitStatus (or STILL_ACTIVE
        // 0x103 for a running thread) via the same TBI query.
        b"GetExitCodeThread" => {
            e.raw(&[
                0x48, 0x83, 0xec, 0x50, // sub rsp,0x50
                0x48, 0x89, 0x54, 0x24, 0x48, // mov [rsp+0x48],rdx &code
                0x49, 0x89, 0xca, //          mov r10,rcx
                0x31, 0xd2, //               xor edx,edx
                0x4c, 0x8d, 0x44, 0x24, 0x10, // lea r8,[rsp+0x10] tbi
                0x41, 0xb9, 0x30, 0, 0, 0, // mov r9d,48
                0x48, 0xc7, 0x44, 0x24, 0x28, 0, 0, 0, 0, // retsz=0
                0xb8, 0x25, 0, 0, 0, 0x0f, 0x05,
            ]);
            let fail = e.jcc(0x8); //          js fail
            e.raw(&[
                0x48, 0x8b, 0x44, 0x24, 0x48, // mov rax,[rsp+0x48] &code
                0x48, 0x8b, 0x54, 0x24, 0x10, // mov rdx,[tbi+0] ExitStatus
                0x89, 0x10, //               mov [rax],edx
                0xb8, 1, 0, 0, 0, //          mov eax,1
            ]);
            e.fix(fail);
            e.raw(&[
                0x0f, 0x89, 2, 0, 0, 0, 0x31, 0xc0, // jns +2; xor eax,eax
                0x48, 0x83, 0xc4, 0x50, 0xc3,
            ]);
        }
        // WaitForSingleObject(h, ms) -> NtWaitForSingleObject(h, 0,
        // &tmo|NULL). INFINITE (0xffffffff) means a NULL interval ptr.
        b"WaitForSingleObject" => {
            e.raw(&[
                0x48, 0x83, 0xec, 0x38, // sub rsp,0x38
                0x49, 0x89, 0xca, //          mov r10,rcx   handle
                0x83, 0xfa, 0xff, //          cmp edx,-1    INFINITE?
            ]);
            let tmo = e.jcc(0x5); //           jne tmo
            e.raw(&[
                0x31, 0xd2, //               xor edx,edx   alertable=0
                0x45, 0x31, 0xc0, //          xor r8d,r8d   timeout=NULL
                0xb8, 4, 0, 0, 0, 0x0f, 0x05, // mov eax,4; syscall
                0x48, 0x83, 0xc4, 0x38, 0xc3, // add rsp,0x38; ret
            ]);
            e.fix(tmo);
            e.raw(&[
                0x89, 0xd0, //               mov eax,edx
                0x48, 0xf7, 0xd8, //          neg rax
                0x48, 0x69, 0xc0, 0x10, 0x27, 0, 0, // imul rax,rax,10000
                0x48, 0x89, 0x44, 0x24, 0x30, // mov [rsp+0x30],rax
                0x4c, 0x8d, 0x44, 0x24, 0x30, // lea r8,[rsp+0x30] &tmo
                0x31, 0xd2, //               xor edx,edx   alertable=0
                0xb8, 4, 0, 0, 0, 0x0f, 0x05, // mov eax,4; syscall
                0x48, 0x83, 0xc4, 0x38, 0xc3, // add rsp,0x38; ret
            ]);
        }
        // ResumeThread(h) -> previous suspend count, -1 on failure.
        b"ResumeThread" => {
            e.raw(&[
                0x48, 0x83, 0xec, 0x38, // sub rsp,0x38
                0x49, 0x89, 0xca, //          mov r10,rcx
                0x48, 0x8d, 0x54, 0x24, 0x30, // lea rdx,[rsp+0x30] &prev
                0xb8, 0x52, 0, 0, 0, 0x0f, 0x05, // mov eax,0x52; syscall
                0x85, 0xc0, //               test eax,eax
                0x0f, 0x89, 5, 0, 0, 0, //    jns +5 keep eax
                0xb8, 0xff, 0xff, 0xff, 0xff, // mov eax,-1
                0x48, 0x83, 0xc4, 0x38, 0xc3,
            ]);
        }
        // SwitchToThread: honest "no hint" — 0 like a missed yield.
        b"SwitchToThread" => {
            e.raw(&[0x31, 0xc0, 0xc3]);
        }
        // CreateFileMappingA/W(hfile, sa, prot, sizeHi, sizeLo, name)
        //   -> NtCreateSection(&hout, 0xF001F, 0, size, prot,
        //      SEC_COMMIT, hfile). size64 = sizeHi<<32 | sizeLo; a
        //      combined size of 0 passes MaximumSize=NULL which the
        //      kernel reads as "whole file" (real semantic too).
        //      Sections are unnamed — the name arg is ignored like a
        //      real anonymous mapping. A and W share the marshal.
        b"CreateFileMappingA" | b"CreateFileMappingW" => {
            e.raw(&[
                0x48, 0x83, 0xec, 0x58, // sub rsp,0x58
                0x48, 0x89, 0x4c, 0x24, 0x08, // mov [rsp+0x08],rcx  hfile
                0x4c, 0x89, 0x44, 0x24, 0x10, // mov [rsp+0x10],r8   prot
                0x49, 0xc1, 0xe1, 0x20, //       shl r9,0x20        sizeHi<<32
                0x4c, 0x0b, 0x8c, 0x24, 0x80, 0, 0, 0, // or r9,[rsp+0x80] sizeLo
                0x4c, 0x89, 0x4c, 0x24, 0x20, // mov [rsp+0x20],r9   size64
                0x4d, 0x85, 0xc9, //             test r9,r9
            ]);
            let null = e.jcc(0x4); //           jz -> pass r9=NULL
            e.raw(&[
                0x4c, 0x8d, 0x4c, 0x24, 0x20, // lea r9,[rsp+0x20]  &size64
            ]);
            let have = e.jmp();
            e.fix(null);
            e.raw(&[0x45, 0x31, 0xc9]); //       xor r9d,r9d
            e.fix(have);
            e.raw(&[
                0x4c, 0x8d, 0x54, 0x24, 0x18, // lea r10,[rsp+0x18] &hout
                0xba, 0x1f, 0x00, 0x0f, 0x00, // mov edx,0xF001F    all access
                0x45, 0x31, 0xc0, //            xor r8d,r8d        oa=0
                0x48, 0x8b, 0x44, 0x24, 0x10, // mov rax,[rsp+0x10] prot
                0x48, 0x89, 0x44, 0x24, 0x28, // mov [rsp+0x28],rax a4
                0x48, 0xc7, 0x44, 0x24, 0x30, 0x00, 0x00, 0x00, 0x08, // a5 SEC_COMMIT
                0x48, 0x8b, 0x44, 0x24, 0x08, // mov rax,[rsp+0x08] hfile
                0x48, 0x89, 0x44, 0x24, 0x38, // mov [rsp+0x38],rax a6
                0xb8, 0x4a, 0, 0, 0, //         mov eax,0x4a
                0x0f, 0x05, //                  syscall
                0x85, 0xc0, //                  test eax,eax
            ]);
            let fail = e.jcc(0x8); //           js fail
            e.raw(&[
                0x48, 0x8b, 0x44, 0x24, 0x18, // mov rax,[rsp+0x18] hout
                0x48, 0x83, 0xc4, 0x58, 0xc3, // add rsp,0x58; ret
            ]);
            e.fix(fail);
            e.raw(&[
                0x31, 0xc0, //                  xor eax,eax
                0x48, 0x83, 0xc4, 0x58, 0xc3, // add rsp,0x58; ret
            ]);
        }
        // MapViewOfFile(hsec, access, offHi, offLo, bytes)
        //   -> NtMapViewOfSection(hsec, -1, &base, 0, 0, &off64,
        //      &viewsize, 1, 0, prot). FILE_MAP_* access maps to
        //      PAGE_*: WRITE(2)->READWRITE, COPY(1)->WRITECOPY,
        //      READ(4)->READONLY; ALL_ACCESS (0xF001F) takes WRITE.
        //   Frame: 0x08 hsec / 0x10 off64 / 0x18 viewsize /
        //   0x20 prot / 0x58 base-out; stack args at 0x28..0x50.
        b"MapViewOfFile" => {
            e.raw(&[
                0x48, 0x83, 0xec, 0x68, // sub rsp,0x68
                0x48, 0x89, 0x4c, 0x24, 0x08, // mov [rsp+0x08],rcx hsec
                0x48, 0x89, 0x54, 0x24, 0x28, // mov [rsp+0x28],rdx access(save)
                0x49, 0xc1, 0xe0, 0x20, //       shl r8,0x20        offHi<<32
                0x4d, 0x0b, 0xc1, //             or r8,r9           |offLo (REX.B!)
                0x4c, 0x89, 0x44, 0x24, 0x10, // mov [rsp+0x10],r8  off64 cell
                0x48, 0x8b, 0x84, 0x24, 0x90, 0, 0, 0, // mov rax,[rsp+0x90] bytes
                0x48, 0x89, 0x44, 0x24, 0x18, // mov [rsp+0x18],rax viewsize cell
                0x48, 0x8b, 0x44, 0x24, 0x28, // mov rax,[rsp+0x28] access
                0xb9, 2, 0, 0, 0, //             mov ecx,2          RO
                0xa8, 0x02, //                   test al,2         WRITE bit
            ]);
            let cow = e.jcc(0x4); //            jz -> check COPY bit
            e.raw(&[0xb9, 4, 0, 0, 0]); //      mov ecx,4          RW
            let pdone = e.jmp();
            e.fix(cow);
            e.raw(&[0xa8, 0x01]); //            test al,1          COPY bit
            let pdone2 = e.jcc(0x4); //         jz -> keep RO
            e.raw(&[0xb9, 8, 0, 0, 0]); //      mov ecx,8          COW
            e.fix(pdone2);
            e.fix(pdone);
            e.raw(&[
                0x48, 0x89, 0x4c, 0x24, 0x20, // mov [rsp+0x20],rcx prot cell
                // stack args a4..a9:
                0x48, 0xc7, 0x44, 0x24, 0x28, 0, 0, 0, 0, // a4 commitsize=0
                0x48, 0x8d, 0x44, 0x24, 0x10, // lea rax,[rsp+0x10]
                0x48, 0x89, 0x44, 0x24, 0x30, // mov [rsp+0x30],rax a5 &off
                0x48, 0x8d, 0x44, 0x24, 0x18, // lea rax,[rsp+0x18]
                0x48, 0x89, 0x44, 0x24, 0x38, // mov [rsp+0x38],rax a6 &viewsize
                0x48, 0xc7, 0x44, 0x24, 0x40, 1, 0, 0, 0, // a7 ViewShare
                0x48, 0xc7, 0x44, 0x24, 0x48, 0, 0, 0, 0, // a8 alloctype=0
                0x48, 0x8b, 0x44, 0x24, 0x20, // mov rax,[rsp+0x20] prot
                0x48, 0x89, 0x44, 0x24, 0x50, // mov [rsp+0x50],rax a9
                // register args:
                0x4c, 0x8b, 0x54, 0x24, 0x08, // mov r10,[rsp+0x08] hsec
                0x48, 0xc7, 0xc2, 0xff, 0xff, 0xff, 0xff, // mov rdx,-1
                0x4c, 0x8d, 0x44, 0x24, 0x58, // lea r8,[rsp+0x58]   &base
                0x45, 0x31, 0xc9, //            xor r9d,r9d         zerobits
                0xb8, 0x28, 0, 0, 0, //         mov eax,0x28
                0x0f, 0x05, //                  syscall
                0x85, 0xc0, //                  test eax,eax
            ]);
            let fail = e.jcc(0x8); //           js fail
            e.raw(&[
                0x48, 0x8b, 0x44, 0x24, 0x58, // mov rax,[rsp+0x58] mapped base
                0x48, 0x83, 0xc4, 0x68, 0xc3, // add rsp,0x68; ret
            ]);
            e.fix(fail);
            e.raw(&[
                0x31, 0xc0, //                  xor eax,eax
                0x48, 0x83, 0xc4, 0x68, 0xc3, // add rsp,0x68; ret
            ]);
        }
        // UnmapViewOfFile(base) -> NtUnmapViewOfSection(-1, base),
        // BOOL out.
        b"UnmapViewOfFile" => {
            e.raw(&[
                0x48, 0x89, 0xca, //               mov rdx,rcx       base
                0x49, 0xc7, 0xc2, 0xff, 0xff, 0xff, 0xff, // mov r10,-1
                0xb8, 0x2a, 0, 0, 0, //           mov eax,0x2a
                0x0f, 0x05, //                     syscall
                0x85, 0xc0, //                     test eax,eax
            ]);
            let fail = e.jcc(0x8); //           js fail
            e.raw(&[0xb8, 1, 0, 0, 0, 0xc3]); // mov eax,1; ret
            e.fix(fail);
            e.raw(&[0x31, 0xc0, 0xc3]); //      xor eax,eax; ret
        }
        // FlushViewOfFile(base, size) -> NtFlushVirtualMemory(-1,
        // &base, &size, iosb-cell), BOOL out.
        b"FlushViewOfFile" => {
            e.raw(&[
                0x48, 0x83, 0xec, 0x38, // sub rsp,0x38
                0x48, 0x89, 0x4c, 0x24, 0x08, // mov [rsp+0x08],rcx base
                0x48, 0x89, 0x54, 0x24, 0x10, // mov [rsp+0x10],rdx size
                0x48, 0xc7, 0x44, 0x24, 0x18, 0, 0, 0, 0, // iosb=0
                0x49, 0xc7, 0xc2, 0xff, 0xff, 0xff, 0xff, // mov r10,-1
                0x48, 0x8d, 0x54, 0x24, 0x08, // lea rdx,[rsp+0x08] &base
                0x4c, 0x8d, 0x44, 0x24, 0x10, // lea r8,[rsp+0x10] &size
                0x4c, 0x8d, 0x4c, 0x24, 0x18, // lea r9,[rsp+0x18] iosb
                0xb8, 0x3b, 0, 0, 0, //         mov eax,0x3b
                0x0f, 0x05, //                  syscall
                0x85, 0xc0, //                  test eax,eax
            ]);
            let fail = e.jcc(0x8); //           js fail
            e.raw(&[
                0xb8, 1, 0, 0, 0, //             mov eax,1
                0x48, 0x83, 0xc4, 0x38, 0xc3, // add rsp,0x38; ret
            ]);
            e.fix(fail);
            e.raw(&[
                0x31, 0xc0, //                  xor eax,eax
                0x48, 0x83, 0xc4, 0x38, 0xc3, // add rsp,0x38; ret
            ]);
        }
        // Sleep(ms) -> NtDelayExecution(0, &(-ms*10000)).
        // LoadLibraryA/W(name) -> RUX_LOAD_DLL: the kernel maps the
        // module; the thunk then drains the pending-attach queue
        // (RUX_DLL_ATTACH -> next hmod or 0) calling each entry's
        // DllMain(hmod, ATTACH, 0) in userland — deps land in lower
        // ledger slots so they initialize before their importer,
        // and kernel code never invokes user code directly.
        b"LoadLibraryA" => {
            e.raw(&[
                0x4c, 0x8b, 0xd1, //       mov r10,rcx
                0x31, 0xd2, //             xor edx,edx   wide=0
                0xb8, 0xf4, 0, 0, 0, //   mov eax,0xF4
                0x0f, 0x05, //             syscall
                0x48, 0x85, 0xc0, //       test rax,rax
            ]);
            let nul = e.jcc(0x4); //        NULL -> ret
            let fresh = e.jcc(0x8); //      sign (FRESH bit) -> drain
            e.raw(&[0xc3]); //             dedup hit -> ret as-is
            e.fix(fresh);
            e.raw(&[
                0x48, 0x0f, 0xba, 0xf0, 0x3f, // btr rax,63  clear FRESH
                // The drain calls DllMain plus the module's TLS
                // callbacks and then returns - preserve the
                // callee-saved registers it walks with.
                0x53, //                     push rbx
                0x41, 0x56, //               push r14
                0x41, 0x57, //               push r15
                // 3 pushes + 0x30 keeps every call site 16-aligned
                // from a call-entered (rsp%16==8) thunk.
                0x48, 0x83, 0xec, 0x30, //   sub rsp,0x30
                0x48, 0x89, 0x44, 0x24, 0x20, // mov [rsp+0x20],rax hmod
            ]);
            let drain = e.n; //              drain: next pending attach
            e.raw(&[
                0xb8, 0xf7, 0, 0, 0, //     mov eax,0xF7
                0x0f, 0x05, //             syscall
                0x48, 0x85, 0xc0, //       test rax,rax
            ]);
            let done = e.jcc(0x4); //       queue empty -> done
            e.raw(&[0x48, 0x89, 0xc3]); // mov rbx,rax  module base
            // Load order per module: TLS cbs before DllMain(ATTACH).
            emit_tls_cb_walk(&mut e, 1);
            e.raw(&[
                0x8b, 0x4b, 0x3c, //          mov ecx,[rbx+0x3c]    peoff
                0x8b, 0x4c, 0x0b, 0x28, //    mov ecx,[rbx+rcx+0x28] entry_rva
                0x85, 0xc9, //                test ecx,ecx
            ]);
            let noent = e.jcc(0x4); //      no entry -> next
            e.raw(&[
                0x48, 0x01, 0xd9, //       add rcx,rbx   entry_va
                0x49, 0x89, 0xc9, //       mov r9,rcx
                0x48, 0x89, 0xd9, //       mov rcx,rbx   hinst
                0xba, 0x01, 0, 0, 0, //   mov edx,1     DLL_PROCESS_ATTACH
                0x45, 0x31, 0xc0, //       xor r8d,r8d
                0x41, 0xff, 0xd1, //       call r9       DllMain
            ]);
            e.fix_to(noent, drain);
            let back = e.jmp();
            e.fix_to(back, drain);
            e.fix(done);
            e.raw(&[
                0x48, 0x8b, 0x44, 0x24, 0x20, // mov rax,[rsp+0x20]
                0x48, 0x83, 0xc4, 0x30, //    add rsp,0x30
                0x41, 0x5f, //                pop r15
                0x41, 0x5e, //                pop r14
                0x5b, //                      pop rbx
            ]);
            e.fix(nul);
            e.raw(&[0xc3]); //             ret
        }
        b"LoadLibraryW" => {
            e.raw(&[
                0x4c, 0x8b, 0xd1, //       mov r10,rcx
                0xba, 0x01, 0, 0, 0, //   mov edx,1     wide=1
                0xb8, 0xf4, 0, 0, 0, //   mov eax,0xF4
                0x0f, 0x05, //             syscall
                0x48, 0x85, 0xc0, //       test rax,rax
            ]);
            let nul = e.jcc(0x4); //        NULL -> ret
            let fresh = e.jcc(0x8); //      sign (FRESH bit) -> drain
            e.raw(&[0xc3]); //             dedup hit -> ret as-is
            e.fix(fresh);
            e.raw(&[
                0x48, 0x0f, 0xba, 0xf0, 0x3f, // btr rax,63  clear FRESH
                // The drain calls DllMain plus the module's TLS
                // callbacks and then returns - preserve the
                // callee-saved registers it walks with.
                0x53, //                     push rbx
                0x41, 0x56, //               push r14
                0x41, 0x57, //               push r15
                // 3 pushes + 0x30 keeps every call site 16-aligned
                // from a call-entered (rsp%16==8) thunk.
                0x48, 0x83, 0xec, 0x30, //   sub rsp,0x30
                0x48, 0x89, 0x44, 0x24, 0x20, // mov [rsp+0x20],rax hmod
            ]);
            let drain = e.n;
            e.raw(&[
                0xb8, 0xf7, 0, 0, 0, //     mov eax,0xF7
                0x0f, 0x05, //             syscall
                0x48, 0x85, 0xc0, //       test rax,rax
            ]);
            let done = e.jcc(0x4);
            e.raw(&[0x48, 0x89, 0xc3]); // mov rbx,rax  module base
            // Load order per module: TLS cbs before DllMain(ATTACH).
            emit_tls_cb_walk(&mut e, 1);
            e.raw(&[
                0x8b, 0x4b, 0x3c, //          mov ecx,[rbx+0x3c]
                0x8b, 0x4c, 0x0b, 0x28, //    mov ecx,[rbx+rcx+0x28]
                0x85, 0xc9, //                test ecx,ecx
            ]);
            let noent = e.jcc(0x4);
            e.raw(&[
                0x48, 0x01, 0xd9, //       add rcx,rbx
                0x49, 0x89, 0xc9, //       mov r9,rcx
                0x48, 0x89, 0xd9, //       mov rcx,rbx
                0xba, 0x01, 0, 0, 0, //   mov edx,1
                0x45, 0x31, 0xc0, //       xor r8d,r8d
                0x41, 0xff, 0xd1, //       call r9
            ]);
            e.fix_to(noent, drain);
            let back = e.jmp();
            e.fix_to(back, drain);
            e.fix(done);
            e.raw(&[
                0x48, 0x8b, 0x44, 0x24, 0x20, // mov rax,[rsp+0x20]
                0x48, 0x83, 0xc4, 0x30, //    add rsp,0x30
                0x41, 0x5f, //                pop r15
                0x41, 0x5e, //                pop r14
                0x5b, //                      pop rbx
            ]);
            e.fix(nul);
            e.raw(&[0xc3]); //             ret
        }
        // GetProcAddress(hmod,name) -> RUX_GET_PROC: kernel walks the
        // module's export directory; rdx already carries arg1.
        b"GetProcAddress" => {
            e.raw(&[
                0x4c, 0x8b, 0xd1, //       mov r10,rcx
                0xb8, 0xf5, 0, 0, 0, //   mov eax,0xF5
                0x0f, 0x05, //             syscall
                0xc3, //                   ret
            ]);
        }
        // FreeLibrary(hmod) -> RUX_FREE_DLL: on the final ref the
        // kernel marks the cascade set pend_detach (bit63) — the
        // thunk drains RUX_DLL_DETACH calling DllMain(DETACH)
        // importer-first in userland, then RUX_FREE_FIN unmaps.
        b"FreeLibrary" => {
            e.raw(&[
                0x4c, 0x8b, 0xd1, //       mov r10,rcx
                0xb8, 0xf6, 0, 0, 0, //   mov eax,0xF6
                0x0f, 0x05, //             syscall
                0x48, 0x85, 0xc0, //       test rax,rax
            ]);
            let fail = e.jcc(0x4); //        0 -> ret FALSE
            let pend = e.jcc(0x8); //       sign -> detach drain
            e.raw(&[0xc3]); //              refdown only -> ret TRUE
            e.fix(pend);
            e.raw(&[
                // The drain walks TLS arrays too - rbx/r14/r15 are
                // callee-saved and this thunk returns to its caller.
                0x53, //                     push rbx
                0x41, 0x56, //               push r14
                0x41, 0x57, //               push r15
                // 3 pushes + 0x30 keeps the drain's call sites
                // 16-aligned from a call-entered (rsp%16==8) thunk.
                0x48, 0x83, 0xec, 0x30, //   sub rsp,0x30
            ]);
            let drain = emit_detach_drain(&mut e, 0xf9);
            e.raw(&[
                0xb8, 0xfa, 0, 0, 0, //   mov eax,0xFA  RUX_FREE_FIN
                0x0f, 0x05, //             syscall
                0x48, 0x85, 0xc0, //       test rax,rax
            ]);
            let again = e.jcc(0x5); //   deps hit zero late -> re-drain
            e.fix_to(again, drain);
            e.raw(&[
                0x48, 0x83, 0xc4, 0x30, // add rsp,0x30
                0x41, 0x5f, //             pop r15
                0x41, 0x5e, //             pop r14
                0x5b, //                   pop rbx
                0xb8, 1, 0, 0, 0, //       mov eax,1   TRUE
            ]);
            e.fix(fail);
            e.raw(&[0xc3]); //             ret
        }
        b"Sleep" => {
            e.raw(&[
                0x48, 0x83, 0xec, 0x38, // sub rsp,0x38
                0x89, 0xc8, //           mov eax,ecx
                0x48, 0xf7, 0xd8, //     neg rax
                0x48, 0x69, 0xc0, 0x10, 0x27, 0, 0, // imul rax,rax,10000
                0x48, 0x89, 0x44, 0x24, 0x30, // mov [rsp+0x30],rax
                0x48, 0x8d, 0x54, 0x24, 0x30, // lea rdx,[rsp+0x30]
                0x45, 0x31, 0xd2, //    xor r10d,r10d
                0xb8, 0x34, 0, 0, 0, // mov eax,0x34
                0x0f, 0x05, //          syscall
                0x48, 0x83, 0xc4, 0x38, 0xc3, // add rsp,0x38; ret
            ]);
        }
        // VirtualProtect(addr,size,newprot,&oldprot) ->
        // NtProtectVirtualMemory(-1,&base,&size,newprot,&oldcell) —
        // the kernel rewrites PTEs and ranges[] flags for real.
        b"VirtualProtect" => {
            e.raw(&[
                0x48, 0x83, 0xec, 0x38, // sub rsp,0x38
                0x48, 0x89, 0x4c, 0x24, 0x10, // mov [rsp+0x10],rcx  base
                0x48, 0x89, 0x54, 0x24, 0x18, // mov [rsp+0x18],rdx  size
                0x4c, 0x89, 0x4c, 0x24, 0x20, // mov [rsp+0x20],r9   save &oldprot
                0x49, 0xc7, 0xc2, 0xff, 0xff, 0xff, 0xff, // mov r10,-1
                0x48, 0x8d, 0x54, 0x24, 0x10, // lea rdx,[rsp+0x10] &base
                0x4d, 0x89, 0xc1, //             mov r9,r8         newprot
                0x4c, 0x8d, 0x44, 0x24, 0x18, // lea r8,[rsp+0x18] &size
                0x48, 0x8d, 0x44, 0x24, 0x30, // lea rax,[rsp+0x30] &oldcell
                0x48, 0x89, 0x44, 0x24, 0x28, // mov [rsp+0x28],rax arg5
                0xb8, 0x50, 0, 0, 0, //       mov eax,0x50
                0x0f, 0x05, //                  syscall
                0x85, 0xc0, //                  test eax,eax
            ]);
            let fail = e.jcc(0x8); //           js fail
            e.raw(&[
                0x48, 0x8b, 0x4c, 0x24, 0x20, // mov rcx,[rsp+0x20] caller's ptr
                0x48, 0x85, 0xc9, //            test rcx,rcx
            ]);
            let done = e.jcc(0x4); //           jz done
            e.raw(&[
                0x8b, 0x54, 0x24, 0x30, // mov edx,[rsp+0x30] oldprot
                0x89, 0x11, //             mov [rcx],edx
            ]);
            e.fix(done);
            e.raw(&[
                0xb8, 1, 0, 0, 0, // mov eax,1
                0x48, 0x83, 0xc4, 0x38, 0xc3, // add rsp,0x38; ret
            ]);
            e.fix(fail);
            e.raw(&[0x31, 0xc0, 0x48, 0x83, 0xc4, 0x38, 0xc3]); // eax=0; ret
        }
        // VirtualQuery(addr,buf,len) ->
        // NtQueryVirtualMemory(-1,addr,0,buf,len,&retlen) — real
        // MEMORY_BASIC_INFORMATION from the ranges ledger; returns
        // the kernel's written length.
        b"VirtualQuery" => {
            e.raw(&[
                0x48, 0x83, 0xec, 0x38, // sub rsp,0x38
                0x4c, 0x89, 0x44, 0x24, 0x28, // mov [rsp+0x28],r8  arg5 len
                0x48, 0x8d, 0x44, 0x24, 0x10, // lea rax,[rsp+0x10] &retlen
                0x48, 0x89, 0x44, 0x24, 0x30, // mov [rsp+0x30],rax arg6
                0x49, 0x89, 0xd1, //           mov r9,rdx        buf
                0x48, 0x89, 0xca, //           mov rdx,rcx       base
                0x45, 0x31, 0xc0, //           xor r8d,r8d       class 0
                0x49, 0xc7, 0xc2, 0xff, 0xff, 0xff, 0xff, // mov r10,-1
                0xb8, 0x23, 0, 0, 0, //       mov eax,0x23
                0x0f, 0x05, //                  syscall
                0x85, 0xc0, //                  test eax,eax
            ]);
            let fail = e.jcc(0x8); //           js fail
            e.raw(&[
                0x48, 0x8b, 0x44, 0x24, 0x10, // mov rax,[rsp+0x10] retlen
                0x48, 0x83, 0xc4, 0x38, 0xc3, // add rsp,0x38; ret
            ]);
            e.fix(fail);
            e.raw(&[0x31, 0xc0, 0x48, 0x83, 0xc4, 0x38, 0xc3]); // rax=0; ret
        }
        // --- file API -------------------------------------------
        // CloseHandle(h) -> NtClose; BOOL out.
        b"CloseHandle" => {
            e.raw(&[
                0x4c, 0x8b, 0xd1, // mov r10,rcx
                0xb8, 0x0f, 0, 0, 0, // mov eax,0x0f
                0x0f, 0x05, //          syscall
                0x85, 0xc0, //          test eax,eax
            ]);
            let fail = e.jcc(0x8); // js fail
            e.raw(&[0xb8, 1, 0, 0, 0, 0xc3]); // mov eax,1; ret
            e.fix(fail);
            e.raw(&[0x31, 0xc0, 0xc3]);
        }
        // GetFileSizeEx(h,&out): NtQueryInformationFile
        // FileStandardInformation(5) -> EndOfFile copied to *out.
        b"GetFileSizeEx" => {
            e.raw(&[
                0x48, 0x83, 0xec, 0x68, // sub rsp,0x68
                0x48, 0x89, 0x54, 0x24, 0x60, // mov [rsp+0x60],rdx
                0x4c, 0x8b, 0xd1, //           mov r10,rcx
                0x48, 0x8d, 0x54, 0x24, 0x10, // lea rdx,[rsp+0x10] iosb
                0x4c, 0x8d, 0x44, 0x24, 0x48, // lea r8,[rsp+0x48] buf
                0x41, 0xb9, 0x18, 0, 0, 0, //    mov r9d,24
                0x48, 0xc7, 0x44, 0x24, 0x28, 0x05, 0, 0, 0, // [rsp+0x28]=5
                0xb8, 0x11, 0, 0, 0, //         mov eax,0x11
                0x0f, 0x05, //                  syscall
                0x85, 0xc0, //                  test eax,eax
            ]);
            let fail = e.jcc(0x8);
            e.raw(&[
                0x48, 0x8b, 0x44, 0x24, 0x50, // mov rax,[rsp+0x50] eof
                0x48, 0x8b, 0x4c, 0x24, 0x60, // mov rcx,[rsp+0x60] out
                0x48, 0x89, 0x01, //           mov [rcx],rax
                0xb8, 1, 0, 0, 0, //           mov eax,1
                0x48, 0x83, 0xc4, 0x68, //     add rsp,0x68
                0xc3,
            ]);
            e.fix(fail);
            e.raw(&[
                0x65, 0x89, 0x04, 0x25, 0x68, 0, 0, 0, // mov gs:[0x68],eax
                0x31, 0xc0, //                         xor eax,eax
                0x48, 0x83, 0xc4, 0x68, 0xc3, //        add rsp,0x68; ret
            ]);
        }
        // SetFilePointerEx(h, li, out, method): method 0=BEGIN is a
        // direct FilePositionInformation set; 1/2 compose
        // current-pos/eof + li via NtQueryInformationFile first.
        b"SetFilePointerEx" => {
            let mut fails = [0usize; 4];
            let mut nf = 0;
            e.raw(&[
                0x48, 0x83, 0xec, 0x78, // sub rsp,0x78
                0x48, 0x89, 0x4c, 0x24, 0x60, // mov [rsp+0x60],rcx h
                0x4c, 0x89, 0x44, 0x24, 0x68, // mov [rsp+0x68],r8  out
                0x48, 0x89, 0x54, 0x24, 0x70, // mov [rsp+0x70],rdx li
                0x4d, 0x85, 0xc9, //           test r9,r9
            ]);
            let begin = e.jcc(0x4); // jz FILE_BEGIN
            e.raw(&[0x49, 0x83, 0xf9, 0x01]); // cmp r9,1
            let cur = e.jcc(0x4); //           je FILE_CURRENT
            e.raw(&[0x49, 0x83, 0xf9, 0x02]); // cmp r9,2
            fails[nf] = e.jcc(0x5); //         jne fail
            nf += 1;
            // FILE_END: query FileStandardInformation(24B).
            emit_qinfo(&mut e, 0x48, 24, 5);
            fails[nf] = e.jcc(0x8); // js fail
            nf += 1;
            e.raw(&[0x48, 0x8b, 0x44, 0x24, 0x50]); // mov rax,[+0x50] eof
            let to_add1 = e.jmp();
            // FILE_CURRENT: query FilePositionInformation(8B).
            e.fix(cur);
            emit_qinfo(&mut e, 0x48, 8, 14);
            fails[nf] = e.jcc(0x8);
            nf += 1;
            e.raw(&[0x48, 0x8b, 0x44, 0x24, 0x48]); // mov rax,[+0x48] pos
            e.fix(to_add1);
            e.raw(&[
                0x48, 0x03, 0x44, 0x24, 0x70, // add rax,[rsp+0x70]
            ]);
            let to_set = e.jmp();
            // FILE_BEGIN: pos = li.
            e.fix(begin);
            e.raw(&[0x48, 0x8b, 0x44, 0x24, 0x70]); // mov rax,[+0x70]
            // .set: store composed pos, NtSetInformationFile(14).
            e.fix(to_set);
            e.raw(&[
                0x48, 0x89, 0x44, 0x24, 0x48, // mov [rsp+0x48],rax
                0x4c, 0x8b, 0x54, 0x24, 0x60, // mov r10,[rsp+0x60] h
                0x48, 0x8d, 0x54, 0x24, 0x10, // lea rdx,[rsp+0x10] iosb
                0x4c, 0x8d, 0x44, 0x24, 0x48, // lea r8,[rsp+0x48] pos
                0x41, 0xb9, 0x08, 0, 0, 0, //    mov r9d,8
                0x48, 0xc7, 0x44, 0x24, 0x28, 0x0e, 0, 0, 0, // [+0x28]=14
                0xb8, 0x27, 0, 0, 0, //         mov eax,0x27
                0x0f, 0x05, //                  syscall
                0x85, 0xc0, //                  test eax,eax
            ]);
            fails[nf] = e.jcc(0x8);
            nf += 1;
            e.raw(&[
                0x48, 0x8b, 0x4c, 0x24, 0x68, // mov rcx,[rsp+0x68] out
                0x48, 0x85, 0xc9, //           test rcx,rcx
            ]);
            let noout = e.jcc(0x4); // jz no out ptr
            e.raw(&[
                0x48, 0x8b, 0x44, 0x24, 0x48, // mov rax,[rsp+0x48]
                0x48, 0x89, 0x01, //           mov [rcx],rax
            ]);
            e.fix(noout);
            e.raw(&[
                0xb8, 1, 0, 0, 0, // mov eax,1
                0x48, 0x83, 0xc4, 0x78, 0xc3, // add rsp,0x78; ret
            ]);
            for f in fails.iter().take(nf) {
                e.fix(*f);
            }
            e.raw(&[
                0x65, 0x89, 0x04, 0x25, 0x68, 0, 0, 0, // mov gs:[0x68],eax
                0x31, 0xc0, //                         xor eax,eax
                0x48, 0x83, 0xc4, 0x78, 0xc3, //        add rsp,0x78; ret
            ]);
        }
        // CreateFileA/W: build OBJECT_ATTRIBUTES+UNICODE_STRING in
        // a local frame, ANSI names converted to UTF-16 in the data
        // page's 256B name scratch. -> NtCreateFile; HANDLE or -1.
        b"CreateFileA" => emit_openpath(&mut e, false, d, false),
        b"CreateFileW" => emit_openpath(&mut e, true, d, false),
        // DeleteFileA/W(name): same OA frame as CreateFile but
        // constant args — open + FileDispositionInformation + close.
        b"DeleteFileA" => emit_openpath(&mut e, false, d, true),
        b"DeleteFileW" => emit_openpath(&mut e, true, d, true),
        // FindFirstFile* opens "." and stores its pattern via the
        // query's FileName arg; the returned handle IS the dir
        // handle FindNextFile/FindClose talk to.
        b"FindFirstFileA" => emit_find(&mut e, false, true, d),
        b"FindFirstFileW" => emit_find(&mut e, true, true, d),
        b"FindNextFileA" => emit_find(&mut e, false, false, d),
        b"FindNextFileW" => emit_find(&mut e, true, false, d),
        b"FindClose" => emit_findclose(&mut e),
        // --- msvcrt startup ------------------------------------
        // __getmainargs(&argc,&argv,&envp,dowildcard,si).
        b"__getmainargs" => {
            e.raw(&[0xc7, 0x01, 0x01, 0, 0, 0]); // mov dword[rcx],1
            e.rax_imm(d); //                      argv array
            e.raw(&[0x48, 0x89, 0x02]); //        mov [rdx],rax
            e.rax_imm(d + 0x150); //              envp array
            e.raw(&[0x49, 0x89, 0x00, 0x31, 0xc0, 0xc3]);
        }
        // __iob_func -> fake FILE[3] of {u64 fd} at data+0x20.
        b"__iob_func" => {
            e.rax_imm(d + 0x20);
            e.raw(&[0xc3]);
        }
        // __p__* accessors return addresses of the data cells.
        b"__p__fmode" => {
            e.rax_imm(d + 0x1c);
            e.raw(&[0xc3]);
        }
        b"__p__commode" => {
            e.rax_imm(d + 0x18);
            e.raw(&[0xc3]);
        }
        b"__p__environ" | b"__p__initenv" => {
            e.rax_imm(d + 0x10);
            e.raw(&[0xc3]);
        }
        b"_errno" | b"__errno" => {
            e.rax_imm(d + 0x138);
            e.raw(&[0xc3]);
        }
        b"__doserrno" => {
            e.rax_imm(d + 0x13c);
            e.raw(&[0xc3]);
        }
        // _initterm(first,last): call each non-null fn ptr — real
        // ctor dispatch so static initializers actually run.
        b"_initterm" => {
            e.raw(&[0x53, 0x48, 0x89, 0xcb]); // push rbx; mov rbx,rcx
            let lp = e.n;
            e.raw(&[0x48, 0x39, 0xd3]); // cmp rbx,rdx
            let done = e.jcc(0x3); //      jae done
            e.raw(&[
                0x48, 0x8b, 0x03, // mov rax,[rbx]
                0x48, 0x85, 0xc0, // test rax,rax
            ]);
            let sk = e.jcc(0x4); //        jz +2
            e.raw(&[0xff, 0xd0]); //      call rax
            e.fix(sk);
            e.raw(&[0x48, 0x83, 0xc3, 0x08]); // add rbx,8
            let back = e.jmp();
            e.fix_to(back, lp);
            e.fix(done);
            e.raw(&[0x5b, 0x31, 0xc0, 0xc3]);
        }
        // _onexit(f) -> f (registration accepted; atexit calls are
        // skipped — a groundwork divergence).
        b"_onexit" | b"__dllonexit" => e.raw(&[0x48, 0x89, 0xc8, 0xc3]),
        // abort -> exit(3); _amsg_exit/exit -> ExitProcess(code).
        b"abort" => {
            e.raw(&[0xb9, 3, 0, 0, 0]); // mov ecx,3
            e.raw(&[
                0x89, 0xca, //             mov edx,ecx
                0x49, 0xc7, 0xc2, 0xff, 0xff, 0xff, 0xff, // mov r10,-1
                0xb8, 0x2c, 0, 0, 0, //    mov eax,0x2C
                0x0f, 0x05, 0xc3,
            ]);
        }
        b"exit" | b"_amsg_exit" | b"ExitProcess" => {
            // ExitProcess runs every surviving module's
            // DllMain(DETACH) reverse-load-order before terminating
            // (TerminateProcess deliberately does not). The exit
            // code rides rcx — park it across the drain calls.
            e.raw(&[
                0x48, 0x83, 0xec, 0x28, // sub rsp,0x28
                0x48, 0x89, 0x4c, 0x24, 0x20, // mov [rsp+0x20],rcx
            ]);
            emit_detach_drain(&mut e, 0xfb); // RUX_EXIT_DETACH
            emit_exe_tls(&mut e, 0); //        exe TLS cbs last
            e.raw(&[
                0x48, 0x8b, 0x54, 0x24, 0x20, // mov rdx,[rsp+0x20]  code
                0x48, 0x83, 0xc4, 0x28, //    add rsp,0x28
                0x49, 0xc7, 0xc2, 0xff, 0xff, 0xff, 0xff, // mov r10,-1
                0xb8, 0x2c, 0, 0, 0, //    mov eax,0x2C
                0x0f, 0x05, 0xc3,
            ]);
        }
        // --- heap: RUX_HEAP_* services back the Win32 heap API ---
        // The block table is kernel-side; hHeap is ignored (one
        // shared process heap, like real HeapAlloc on the default).
        b"GetProcessHeap" => {
            e.rax_imm(crate::pe::HEAP_VA);
            e.raw(&[0xc3]);
        }
        // HeapCreate returns a fresh-looking fake handle; all our
        // heap services ignore the handle arg (documented).
        b"HeapCreate" => e.raw(&[0xb8, 2, 0, 0, 0, 0xc3]),
        // Inert TRUE stubs — HeapWalk is intentionally absent so
        // no caller can spin on a never-false iterator.
        b"HeapDestroy" | b"HeapValidate" | b"HeapLock"
        | b"HeapUnlock" | b"HeapCompact" | b"HeapQueryInformation"
        | b"HeapSetInformation" => {
            e.raw(&[0xb8, 1, 0, 0, 0, 0xc3]);
        }
        // HeapAlloc(h,f,sz) -> RUX_HEAP_ALLOC(f&HEAP_ZERO_MEMORY,sz).
        b"HeapAlloc" => {
            e.raw(&[
                0x83, 0xe2, 0x08, //         and edx,8
                0x49, 0x89, 0xd2, //         mov r10,rdx
                0x4c, 0x89, 0xc2, //         mov rdx,r8
                0xb8, 0xf0, 0, 0, 0, //     mov eax,0xF0
                0x0f, 0x05, 0xc3,
            ]);
        }
        // HeapReAlloc(h,f,p,s) -> RUX_HEAP_REALLOC(p,s,f&8). Order
        // matters: save lpMem before clobbering r8 with the flag.
        b"HeapReAlloc" => {
            e.raw(&[
                0x4d, 0x89, 0xc2, //         mov r10,r8
                0x49, 0x89, 0xd0, //         mov r8,rdx
                0x49, 0x83, 0xe0, 0x08, //   and r8,8
                0x4c, 0x89, 0xca, //         mov rdx,r9
                0xb8, 0xf1, 0, 0, 0, //     mov eax,0xF1
                0x0f, 0x05, 0xc3,
            ]);
        }
        // HeapFree/HeapSize(h,f,p) — ptr is the third arg.
        b"HeapFree" => {
            e.raw(&[
                0x4d, 0x89, 0xc2, //         mov r10,r8
                0xb8, 0xf2, 0, 0, 0, //     mov eax,0xF2
                0x0f, 0x05, 0xc3,
            ]);
        }
        b"HeapSize" => {
            e.raw(&[
                0x4d, 0x89, 0xc2, //         mov r10,r8
                0xb8, 0xf3, 0, 0, 0, //     mov eax,0xF3
                0x0f, 0x05, 0xc3,
            ]);
        }
        // Local/GlobalAlloc(uFlags, uBytes): LMEM_ZEROINIT is 0x40.
        b"LocalAlloc" | b"GlobalAlloc" => {
            e.raw(&[
                0x83, 0xe1, 0x40, //         and ecx,0x40
                0x49, 0x89, 0xca, //         mov r10,rcx
                0xb8, 0xf0, 0, 0, 0, //     mov eax,0xF0
                0x0f, 0x05, 0xc3,
            ]);
        }
        b"LocalFree" | b"GlobalFree" => {
            e.raw(&[0x48, 0x85, 0xc9]); // test rcx,rcx
            let done = e.jcc(0x4); //       jz ret (NULL is a no-op)
            e.raw(&[
                0x49, 0x89, 0xca, //         mov r10,rcx
                0xb8, 0xf2, 0, 0, 0, //     mov eax,0xF2
                0x0f, 0x05,
            ]);
            e.fix(done);
            e.raw(&[0xc3]);
        }
        // msvcrt allocators — same heap, plus the ucrtbase _base
        // spellings real CRTs also import.
        // malloc(sz) -> alloc(0, sz).
        b"malloc" | b"_malloc_base" => {
            e.raw(&[
                0x48, 0x89, 0xca, //         mov rdx,rcx
                0x45, 0x31, 0xd2, //         xor r10d,r10d
                0xb8, 0xf0, 0, 0, 0, //     mov eax,0xF0
                0x0f, 0x05, 0xc3,
            ]);
        }
        // calloc(n,sz) -> alloc(1, n*sz) with an overflow trap.
        b"calloc" | b"_calloc_base" => {
            e.raw(&[0x48, 0x0f, 0xaf, 0xd1]); // imul rdx,rcx
            let ovf = e.jcc(0x0); //           jo fail
            e.raw(&[
                0x41, 0xba, 1, 0, 0, 0, //   mov r10d,1
                0xb8, 0xf0, 0, 0, 0, //     mov eax,0xF0
                0x0f, 0x05, 0xc3,
            ]);
            e.fix(ovf);
            e.raw(&[0x31, 0xc0, 0xc3]);
        }
        // realloc(p,s) -> realloc(p, s, 0).
        b"realloc" | b"_realloc_base" => {
            e.raw(&[
                0x49, 0x89, 0xca, //         mov r10,rcx
                0x45, 0x31, 0xc0, //         xor r8d,r8d
                0xb8, 0xf1, 0, 0, 0, //     mov eax,0xF1
                0x0f, 0x05, 0xc3,
            ]);
        }
        // free(p): NULL is a no-op before the syscall.
        b"free" | b"_free_base" => {
            e.raw(&[0x48, 0x85, 0xc9]); // test rcx,rcx
            let done = e.jcc(0x4); //       jz ret
            e.raw(&[
                0x49, 0x89, 0xca, //         mov r10,rcx
                0xb8, 0xf2, 0, 0, 0, //     mov eax,0xF2
                0x0f, 0x05,
            ]);
            e.fix(done);
            e.raw(&[0xc3]);
        }
        // _msize(p) -> HeapSize equivalent.
        b"_msize" => {
            e.raw(&[
                0x49, 0x89, 0xca, //         mov r10,rcx
                0xb8, 0xf3, 0, 0, 0, //     mov eax,0xF3
                0x0f, 0x05, 0xc3,
            ]);
        }
        // strlen/memcpy/strncmp — real C-string routines.
        b"strlen" => {
            emit_strlen_rcx(&mut e);
            e.raw(&[0x48, 0x89, 0xc8, 0xc3]); // mov rax,rcx; ret
        }
        b"memcpy" => {
            e.raw(&[
                0x56, 0x57, //          push rsi; push rdi
                0x48, 0x89, 0xc8, // mov rax,rcx (dst -> ret)
                0x48, 0x89, 0xd6, // mov rsi,rdx (src)
                0x48, 0x89, 0xcf, // mov rdi,rcx (dst)
                0x4c, 0x89, 0xc1, // mov rcx,r8  (n)
                0xf3, 0xa4, //      rep movsb
                0x5f, 0x5e, //      pop rdi; pop rsi
                0xc3,
            ]);
        }
        // strcmp(a,b): unsigned byte compare — <0/0/>0.
        b"strcmp" => {
            let lp = e.n;
            e.raw(&[
                0x8a, 0x01, //       mov al,[rcx]
                0x44, 0x8a, 0x1a, // mov r11b,[rdx]
                0x44, 0x38, 0xd8, // cmp al,r11b
            ]);
            let diff = e.jcc(0x5);
            e.raw(&[0x84, 0xc0]); // test al,al
            let eq = e.jcc(0x4);
            e.raw(&[
                0x48, 0xff, 0xc1, // inc rcx
                0x48, 0xff, 0xc2, // inc rdx
            ]);
            let back = e.jmp();
            e.fix_to(back, lp);
            e.fix(eq);
            e.raw(&[0x31, 0xc0, 0xc3]);
            e.fix(diff);
            e.raw(&[
                0x0f, 0xb6, 0xc0, // movzx eax,al
                0x44, 0x0f, 0xb6, 0xda, // movzx r11d,r11b
                0x44, 0x29, 0xd8, // sub eax,r11d
                0xc3,
            ]);
        }
        b"strncmp" => {
            let lp = e.n;
            e.raw(&[0x4d, 0x85, 0xc0]); // test r8,r8
            let eq = e.jcc(0x4);
            e.raw(&[
                0x44, 0x8a, 0x09, // mov r9b,[rcx]
                0x44, 0x8a, 0x12, // mov r10b,[rdx]
                0x45, 0x38, 0xd1, // cmp r9b,r10b
            ]);
            let diff = e.jcc(0x5);
            e.raw(&[0x45, 0x84, 0xc9]); // test r9b,r9b
            let eq2 = e.jcc(0x4);
            e.raw(&[
                0x48, 0xff, 0xc1, 0x48, 0xff, 0xc2, 0x49, 0xff, 0xc8,
            ]);
            let back = e.jmp();
            e.fix_to(back, lp);
            e.fix(eq);
            e.fix(eq2);
            e.raw(&[0x31, 0xc0, 0xc3]); // xor eax,eax; ret
            e.fix(diff);
            e.raw(&[
                0x41, 0x0f, 0xb6, 0xc1, // movzx eax,r9b
                0x41, 0x0f, 0xb6, 0xd2, // movzx edx,r10b
                0x29, 0xd0, //          sub eax,edx
                0xc3,
            ]);
        }
        // memcmp(a,b,n): unsigned byte compare over n — <0/0/>0.
        b"memcmp" => {
            let lp = e.n;
            e.raw(&[0x4d, 0x85, 0xc0]); // test r8,r8
            let eq = e.jcc(0x4);
            e.raw(&[
                0x44, 0x8a, 0x09, // mov r9b,[rcx]
                0x44, 0x8a, 0x12, // mov r10b,[rdx]
                0x45, 0x38, 0xd1, // cmp r9b,r10b
            ]);
            let diff = e.jcc(0x5);
            e.raw(&[
                0x48, 0xff, 0xc1, 0x48, 0xff, 0xc2, 0x49, 0xff, 0xc8,
            ]);
            let back = e.jmp();
            e.fix_to(back, lp);
            e.fix(eq);
            e.raw(&[0x31, 0xc0, 0xc3]); // xor eax,eax; ret
            e.fix(diff);
            e.raw(&[
                0x41, 0x0f, 0xb6, 0xc1, // movzx eax,r9b
                0x41, 0x0f, 0xb6, 0xd2, // movzx edx,r10b
                0x29, 0xd0, //          sub eax,edx
                0xc3,
            ]);
        }
        // strcpy(dst,src): byte copy through the NUL; returns dst.
        b"strcpy" => {
            e.raw(&[0x48, 0x89, 0xc8]); // mov rax,rcx
            let lp = e.n;
            e.raw(&[
                0x44, 0x8a, 0x1a, // mov r11b,[rdx]
                0x44, 0x88, 0x19, // mov [rcx],r11b
                0x48, 0xff, 0xc1, // inc rcx
                0x48, 0xff, 0xc2, // inc rdx
                0x45, 0x84, 0xdb, // test r11b,r11b
            ]);
            let back = e.jcc(0x5); // jnz loop
            e.fix_to(back, lp);
            e.raw(&[0xc3]); //           ret
        }
        // memset(dst,c,n): rep stosb — r9 keeps dst for the return.
        b"memset" => {
            e.raw(&[
                0x49, 0x89, 0xc9, // mov r9,rcx
                0x48, 0x89, 0xcf, // mov rdi,rcx
                0x89, 0xd0, //       mov eax,edx  c
                0x4c, 0x89, 0xc1, // mov rcx,r8   n
                0xf3, 0xaa, //       rep stosb
                0x4c, 0x89, 0xc8, // mov rax,r9
                0xc3,
            ]);
        }
        // wcslen(s): u16 scan — chars, not bytes.
        b"wcslen" => {
            e.raw(&[0x48, 0x89, 0xc8]); // mov rax,rcx
            let lp = e.n;
            e.raw(&[0x66, 0x83, 0x38, 0x00]); // cmp word[rax],0
            let done = e.jcc(0x4);
            e.raw(&[0x48, 0x83, 0xc0, 0x02]); // add rax,2
            let back = e.jmp();
            e.fix_to(back, lp);
            e.fix(done);
            e.raw(&[0x48, 0x29, 0xc8, 0xc3]); // sub rax,rcx; ret
        }
        // strstr(hay,needle): O(nm) scan — p in rax, inner cursors
        // r9 (hay) / r10 (needle), chars cl / r11b.
        b"strstr" => {
            e.raw(&[0x48, 0x89, 0xc8]); // mov rax,rcx   p
            let outer = e.n;
            e.raw(&[
                0x8a, 0x08, //       mov cl,[rax]
                0x84, 0xc9, //       test cl,cl
            ]);
            let nf = e.jcc(0x4); //     jz notfound
            e.raw(&[
                0x49, 0x89, 0xc1, // mov r9,rax     q
                0x49, 0x89, 0xd2, // mov r10,rdx    n
            ]);
            let inner = e.n;
            e.raw(&[
                0x41, 0x8a, 0x09, // mov cl,[r9]
                0x45, 0x8a, 0x1a, // mov r11b,[r10]
                0x45, 0x84, 0xdb, // test r11b,r11b
            ]);
            let found = e.jcc(0x4); // needle ended → match at p
            e.raw(&[0x44, 0x38, 0xd9]); // cmp cl,r11b
            let next = e.jcc(0x5); //    jne next
            e.raw(&[
                0x49, 0xff, 0xc1, // inc r9
                0x49, 0xff, 0xc2, // inc r10
            ]);
            let ib = e.jmp();
            e.fix_to(ib, inner);
            e.fix(next);
            e.raw(&[0x48, 0xff, 0xc0]); // inc rax
            let ob = e.jmp();
            e.fix_to(ob, outer);
            e.fix(found);
            e.raw(&[0xc3]); //           ret (rax=p)
            e.fix(nf);
            e.raw(&[0x31, 0xc0, 0xc3]); // xor eax,eax; ret
        }
        // VirtualFree(addr,size,type) -> NtFreeVirtualMemory.
        b"VirtualFree" => {
            e.raw(&[
                0x48, 0x83, 0xec, 0x38, // sub rsp,0x38
                0x48, 0x89, 0x4c, 0x24, 0x10, // [rsp+0x10]=base
                0x48, 0x89, 0x54, 0x24, 0x18, // [rsp+0x18]=size
                0x49, 0xc7, 0xc2, 0xff, 0xff, 0xff, 0xff, // r10=-1
                0x48, 0x8d, 0x54, 0x24, 0x10, // rdx=&base
                0x4d, 0x89, 0xc1, //           r9=type
                0x4c, 0x8d, 0x44, 0x24, 0x18, // r8=&size
                0xb8, 0x1e, 0, 0, 0, //      eax=0x1e
                0x0f, 0x05, //               syscall
                0x85, 0xc0, //               test eax,eax
            ]);
            let fail = e.jcc(0x8);
            e.raw(&[
                0xb8, 1, 0, 0, 0, // mov eax,1
                0x48, 0x83, 0xc4, 0x38, 0xc3, // add rsp,0x38; ret
            ]);
            e.fix(fail);
            e.raw(&[0x31, 0xc0, 0x48, 0x83, 0xc4, 0x38, 0xc3]);
        }
        // fputc(c,stream): one byte via the stream's fd cell — the
        // byte itself lives in a data-page scratch cell.
        b"fputc" => {
            e.raw(&[
                0x53, //                push rbx
                0x48, 0x89, 0xcb, //    mov rbx,rcx   char
                0x4c, 0x8b, 0x12, //    mov r10,[rdx] fd
                0x48, 0x83, 0xec, 0x60, // sub rsp,0x60
            ]);
            e.rax_imm(d + 0x918);
            e.raw(&[
                0x88, 0x08, //                       mov [rax],cl
                0x48, 0x89, 0x44, 0x24, 0x30, // [rsp+0x30]=buf
                0x48, 0xc7, 0x44, 0x24, 0x38, 0x01, 0, 0, 0, // len 1
            ]);
            emit_xfile_tail(&mut e, 8);
            e.raw(&[0x85, 0xc0]); // test eax,eax
            let fail = e.jcc(0x8);
            e.raw(&[0x0f, 0xb6, 0xc3]); // movzx eax,bl — return c
            let done = e.jmp();
            e.fix(fail);
            e.raw(&[0xb8, 0xff, 0xff, 0xff, 0xff]); // mov eax,-1 EOF
            e.fix(done);
            e.raw(&[0x48, 0x83, 0xc4, 0x60, 0x5b, 0xc3]);
        }
        // Locale/charset CRT plumbing — honest minimal answers:
        // no DBCS, cp1252, MB_CUR_MAX 1, static lconv, canned error.
        b"IsDBCSLeadByteEx" | b"IsDBCSLeadByte" => {
            e.raw(&[0x31, 0xc0, 0xc3]); // xor eax,eax; ret
        }
        b"___lc_codepage_func" => {
            e.raw(&[0xb8, 0xa4, 0x04, 0, 0, 0xc3]); // mov eax,1252; ret
        }
        b"___mb_cur_max_func" => {
            e.raw(&[0xb8, 1, 0, 0, 0, 0xc3]); // mov eax,1; ret
        }
        b"localeconv" => {
            e.rax_imm(d + 0x8b0);
            e.raw(&[0xc3]);
        }
        b"strerror" => {
            e.rax_imm(d + 0x910);
            e.raw(&[0xc3]);
        }
        // _lock/_unlock — CRT lock sections; single-threaded → inert.
        b"_lock" | b"_unlock" => {
            e.raw(&[0xc3]);
        }
        // MultiByteToWideChar(cp,fl,src r8,srclen r9,dst +0x28,
        // dstlen +0x30): ASCII-only copy — every char <0x80 here.
        // Returns chars written including a copied NUL.
        b"MultiByteToWideChar" => {
            e.raw(&[
                0x4c, 0x8b, 0x54, 0x24, 0x28, // mov r10,[rsp+0x28] dst
                0x4c, 0x8b, 0x5c, 0x24, 0x30, // mov r11,[rsp+0x30] dstlen
                0x31, 0xc0, //                 xor eax,eax
            ]);
            let lp = e.n;
            e.raw(&[0x49, 0x39, 0xc3]); // cmp r11,rax
            let d1 = e.jcc(0x6); //        jbe done
            e.raw(&[0x4c, 0x39, 0xc8]); // cmp rax,r9
            let d2 = e.jcc(0x3); //        jae done
            e.raw(&[
                0x41, 0x8a, 0x0c, 0x00, // mov cl,[r8+rax]
                0x66, 0x41, 0x89, 0x0c, 0x42, // mov [r10+rax*2],cx
                0x84, 0xc9, //             test cl,cl
            ]);
            let fin = e.jcc(0x4); //        jz fin (NUL copied)
            e.raw(&[0x48, 0xff, 0xc0]); // inc rax
            let back = e.jmp();
            e.fix_to(back, lp);
            e.fix(fin);
            e.raw(&[0x48, 0xff, 0xc0]); // inc rax — count the NUL
            e.fix(d1);
            e.fix(d2);
            e.raw(&[0xc3]);
        }
        // WideCharToMultiByte(cp,fl,src r8,srclen r9,dst +0x28,
        // dstlen +0x30,...): the ASCII inverse — low byte per u16.
        b"WideCharToMultiByte" => {
            e.raw(&[
                0x4c, 0x8b, 0x54, 0x24, 0x28, // mov r10,[rsp+0x28] dst
                0x4c, 0x8b, 0x5c, 0x24, 0x30, // mov r11,[rsp+0x30] dstlen
                0x31, 0xc0, //                 xor eax,eax
            ]);
            let lp = e.n;
            e.raw(&[0x49, 0x39, 0xc3]); // cmp r11,rax
            let d1 = e.jcc(0x6); //        jbe done
            e.raw(&[0x4c, 0x39, 0xc8]); // cmp rax,r9
            let d2 = e.jcc(0x3); //        jae done
            e.raw(&[
                0x66, 0x41, 0x8b, 0x0c, 0x40, // mov cx,[r8+rax*2]
                0x41, 0x88, 0x0c, 0x02, // mov [r10+rax],cl
                0x66, 0x85, 0xc9, //        test cx,cx
            ]);
            let fin = e.jcc(0x4); //        jz fin
            e.raw(&[0x48, 0xff, 0xc0]); // inc rax
            let back = e.jmp();
            e.fix_to(back, lp);
            e.fix(fin);
            e.raw(&[0x48, 0xff, 0xc0]); // inc rax
            e.fix(d1);
            e.fix(d2);
            e.raw(&[0xc3]);
        }
        // WriteFile(h,buf,len,&w,ovl)/WriteConsoleA — 9-arg
        // NtWriteFile, iosb.info written back to &written.
        b"WriteFile" | b"WriteConsoleA" => {
            e.raw(&[
                0x48, 0x83, 0xec, 0x60, //     sub rsp,0x60
                // &written must outlive the syscall — r11 is dead
                // (syscall sets r11=rflags), so it parks at +0x20.
                0x4c, 0x89, 0x4c, 0x24, 0x20, // mov [rsp+0x20],r9
                0x48, 0x89, 0x54, 0x24, 0x30, // buf
                0x4c, 0x89, 0x44, 0x24, 0x38, // len
                0x4c, 0x8b, 0xd1, //           mov r10,rcx (handle)
            ]);
            emit_xfile_tail(&mut e, 8);
            e.raw(&[
                0x48, 0x8b, 0x4c, 0x24, 0x20, // mov rcx,[rsp+0x20]
                0x48, 0x85, 0xc9, 0x74, 0x06, // test rcx,rcx; jz +6
                0x8b, 0x44, 0x24, 0x58, //      mov eax,[rsp+0x58] iosb.info
                0x89, 0x01, //                 mov [rcx],eax
                0x48, 0x83, 0xc4, 0x60, 0xc3,
            ]);
        }
        // ReadFile/ReadConsoleA — same shape on NtReadFile.
        b"ReadFile" | b"ReadConsoleA" => {
            e.raw(&[
                0x48, 0x83, 0xec, 0x60,
                0x4c, 0x89, 0x4c, 0x24, 0x20,
                0x48, 0x89, 0x54, 0x24, 0x30,
                0x4c, 0x89, 0x44, 0x24, 0x38,
                0x4c, 0x8b, 0xd1,
            ]);
            emit_xfile_tail(&mut e, 6);
            e.raw(&[
                0x48, 0x8b, 0x4c, 0x24, 0x20,
                0x48, 0x85, 0xc9, 0x74, 0x06,
                0x8b, 0x44, 0x24, 0x58,
                0x89, 0x01,
                0x48, 0x83, 0xc4, 0x60, 0xc3,
            ]);
        }
        // VirtualAlloc(addr,size,type,prot) -> committed base.
        b"VirtualAlloc" => {
            e.raw(&[
                0x48, 0x83, 0xec, 0x50,
                0x48, 0x89, 0x4c, 0x24, 0x40,
                0x48, 0x89, 0x54, 0x24, 0x48,
                0x4c, 0x89, 0x44, 0x24, 0x28,
                0x4c, 0x89, 0x4c, 0x24, 0x30,
            ]);
            emit_valloc_tail(&mut e, false);
        }
        // fwrite(ptr,size,nmemb,stream) -> items written; FILE* is
        // our fake {u64 fd} record.
        b"fwrite" => {
            e.raw(&[
                0x53, //                push rbx
                0x41, 0x54, //          push r12
                0x48, 0x89, 0xcb, //    mov rbx,rcx   (buf)
                0x49, 0x89, 0xc4, //    mov r12,r8    (nmemb)
                0x48, 0x89, 0xd0, //    mov rax,rdx
                0x49, 0x0f, 0xaf, 0xc0, // imul rax,r8 (total)
                0x49, 0x89, 0xc0, //    mov r8,rax
                0x4d, 0x8b, 0x11, //    mov r10,[r9]  (fd)
                0x48, 0x83, 0xec, 0x60, // sub rsp,0x60
                0x48, 0x89, 0x5c, 0x24, 0x30,
                0x4c, 0x89, 0x44, 0x24, 0x38,
            ]);
            emit_xfile_tail(&mut e, 8);
            e.raw(&[0x85, 0xc0]); // test eax,eax
            let fail = e.jcc(0x8); // js fail
            e.raw(&[0x4c, 0x89, 0xe0]); // mov rax,r12
            let done = e.jmp();
            e.fix(fail);
            e.raw(&[0x31, 0xc0]); // xor eax,eax
            e.fix(done);
            e.raw(&[
                0x48, 0x83, 0xc4, 0x60, 0x41, 0x5c, 0x5b, 0xc3,
            ]);
        }
        // fputs(str,stream) -> strlen + write to stream's fd.
        b"fputs" => {
            e.raw(&[
                0x53, 0x48, 0x89, 0xcb, // push rbx; mov rbx,rcx
                0x4c, 0x8b, 0x12, //       mov r10,[rdx]  (fd)
            ]);
            emit_strlen_rcx(&mut e); // len -> rcx (rdi=rax clobbered)
            e.raw(&[
                0x48, 0x83, 0xec, 0x60,
                0x48, 0x89, 0x5c, 0x24, 0x30,
                0x48, 0x89, 0x4c, 0x24, 0x38,
            ]);
            emit_xfile_tail(&mut e, 8);
            e.raw(&[0x48, 0x83, 0xc4, 0x60, 0x5b, 0xc3]);
        }
        // puts(str) -> write str + '\n' to stdout handle 2.
        b"puts" => {
            e.raw(&[0x53, 0x48, 0x89, 0xcb]); // push rbx; mov rbx,rcx
            emit_strlen_rcx(&mut e);
            e.raw(&[
                0x48, 0x83, 0xec, 0x60,
                0x48, 0x89, 0x5c, 0x24, 0x30,
                0x48, 0x89, 0x4c, 0x24, 0x38,
            ]);
            e.raw(&[0x41, 0xba, 0x02, 0, 0, 0]); // mov r10d,2
            emit_xfile_tail(&mut e, 8);
            e.rax_imm(d + 0x38); //              newline byte
            e.raw(&[
                0x48, 0x89, 0x44, 0x24, 0x30,
                0x48, 0xc7, 0x44, 0x24, 0x38, 0x01, 0, 0, 0,
                0xb8, 0x08, 0, 0, 0,
                0x0f, 0x05, //                    syscall (r10 still 2)
                0x48, 0x83, 0xc4, 0x60, 0x5b, 0xc3,
            ]);
        }
        _ => return None,
    }
    (e.n <= e.b.len()).then_some(e.n)
}

/// msvcrt's DATA exports: the IAT slot must hold the variable's
/// own address, not a thunk — CRT code does `mov rax,[__imp_X]`
/// then dereferences/writes rax as the global. Each name maps to a
/// cell in the data page holding the right value/shape.
fn k32_data_sym(name: &[u8]) -> Option<u64> {
    let d = crate::pe::STUB_DATA_VA;
    Some(match name {
        // int globals — the cell IS the variable.
        b"_fmode" => d + 0x1c,
        b"_commode" => d + 0x18,
        b"__argc" => d + 0x118,
        // pointer globals — cell holds a pointer into the page.
        b"__initenv" | b"_environ" | b"_wenviron" => d + 0x10,
        b"__argv" | b"__wargv" => d + 0x120,
        b"_pgmptr" | b"_wpgmptr" => d + 0x128,
        b"_acmdln" | b"_wcmdln" => d + 0x130,
        _ => return None,
    })
}

/// Data-page init for the Win32 thunk layer: argv = {&argv0,NULL},
/// envp = {NULL}, commode/fmode ints, fake FILE[3] carrying NT std
/// fds, the '\n' byte puts writes, and argv0 = "<exe>\0" (ANSI —
/// good enough for ASCII names; GetCommandLineW reads the UTF-16
/// UNICODE_STRING the PEB process parameters point at.
fn k32_data_init(t: &mut Task) {
    let d = crate::pe::STUB_DATA_VA;
    // argv[0] pointer + terminator. envp = {"RUSTUX=1", NULL} at
    // 0x150 (0x10 only holds the unused envp pointer slot) — CRT's
    // env walk strlen()s each entry, so a bare {NULL} envp is a
    // latent strlen(NULL); one harmless var keeps it honest.
    let _ = write_task_bytes(t.pml4, d, &(d + 0x40).to_le_bytes());
    let _ = write_task_bytes(t.pml4, d + 0x08, &0u64.to_le_bytes());
    let _ = write_task_bytes(t.pml4, d + 0x10, &(d + 0x150).to_le_bytes());
    let _ = write_task_bytes(t.pml4, d + 0x150, &(d + 0x140).to_le_bytes());
    let _ = write_task_bytes(t.pml4, d + 0x158, &0u64.to_le_bytes());
    let _ = write_task_bytes(t.pml4, d + 0x140, b"RUSTUX=1\0");
    // commode/fmode.
    let _ = write_task_bytes(t.pml4, d + 0x18, &0u32.to_le_bytes());
    let _ = write_task_bytes(t.pml4, d + 0x1c, &0u32.to_le_bytes());
    // Fake FILE[3]: {u64 fd} — stdin 1, stdout 2, stderr 3.
    for (i, fd) in [1u64, 2, 3].iter().enumerate() {
        let _ = write_task_bytes(t.pml4, d + 0x20 + i as u64 * 8, &fd.to_le_bytes());
    }
    // putc newline byte.
    let _ = write_task_bytes(t.pml4, d + 0x38, &[0x0au8]);
    // argv0 = exe name + ".exe" (already NUL-free), clamped.
    let mut a0 = [0u8; 120];
    let el = (t.exe_len as usize).min(115);
    a0[..el].copy_from_slice(&t.exe[..el]);
    a0[el..el + 4].copy_from_slice(b".exe");
    let _ = write_task_bytes(t.pml4, d + 0x40, &a0[..el + 5]);
    // The full command line lives in its own cell at 0xa00 —
    // CreateProcess overwrites it with lpCommandLine post-spawn;
    // GetCommandLineA and _acmdln resolve here.
    let _ = write_task_bytes(t.pml4, d + 0xa00, &a0[..el + 5]);
    // Data-export cells (see k32_data_sym): environ ptr, argc=1,
    // argv ptr, pgmptr, acmdln, errno/doserrno ints.
    for (off, v) in [
        (0x118, 1u64),
        (0x120, d),
        (0x128, d + 0x40),
        (0x130, d + 0xa00),
        (0x138, 0),
        (0x13c, 0),
    ] {
        let _ = write_task_bytes(t.pml4, d + off, &v.to_le_bytes());
    }
    // UTF-16 "." at 0x780 — FindFirstFile's NtCreateFile name.
    let _ = write_task_bytes(t.pml4, d + 0x780, &[0x2e, 0]);
    // Environment blocks for GetEnvironmentStrings: ANSI at 0x800,
    // UTF-16 at 0x820 — both double-NUL terminated.
    let _ = write_task_bytes(t.pml4, d + 0x800, b"RUSTUX=1\0\0");
    let _ = write_task_bytes(t.pml4, d + 0x820, b"R\0U\0S\0T\0U\0X\0=\01\0\0\0\0");
    // STARTUPINFO at 0x840 — cb=104 (x64), rest zeroed.
    let _ = write_task_bytes(t.pml4, d + 0x840, &104u32.to_le_bytes());
    // localeconv's static lconv at 0x8b0: decimal_point → "." at
    // 0x900, the other nine string fields → the empty string at
    // 0x908; numeric fields stay zeroed.
    for i in 0..10u64 {
        let p = if i == 0 { d + 0x900 } else { d + 0x908 };
        let _ = write_task_bytes(t.pml4, d + 0x8b0 + i * 8, &p.to_le_bytes());
    }
    let _ = write_task_bytes(t.pml4, d + 0x900, b".\0");
    let _ = write_task_bytes(t.pml4, d + 0x908, &[0u8]);
    // strerror's canned message + fputc's scratch byte.
    let _ = write_task_bytes(t.pml4, d + 0x910, b"error\0");
}

/// Import resolution against the synthetic ntdll stub page: walk
/// IMAGE_IMPORT_DESCRIPTORs (ntdll.dll only — other DLLs are an
/// honest load failure), map each ILT name to a service number, emit
/// `mov r10,rcx; mov eax,nr; syscall; ret` (the real ntdll shape),
/// and patch the IAT so compiled `call [rip+IAT]` code just works.
/// Bind an image's IAT to emitted thunks. `primary` (the process
/// exe) also gets the TLS-attach trampoline — which rewrites
/// `t.entry` — and the thread-exit stub; a later-loaded DLL must
/// touch neither.
fn pe_resolve_imports(
    t: &mut Task,
    p: &crate::pe::Pe,
    primary: bool,
    depth: u8,
    dep_mask: &mut u32,
) -> bool {
    // Stub pages map unconditionally — import thunks and the TLS
    // callback trampoline both live there.
    if map_page(t, crate::pe::STUB_VA, USER | WRITE).is_none()
        || map_page(t, crate::pe::STUB_VA + 0x1000, USER | WRITE)
            .is_none()
        || map_page(t, crate::pe::STUB_VA + 0x2000, USER | WRITE)
            .is_none()
    {
        return false;
    }
    // The cursor persists on the task: the exe's thunks start at
    // STUB_VA and each later-mapped DLL continues from where the
    // last image left off — shared stub space, one bump pointer.
    if t.nt_stub == 0 {
        t.nt_stub = crate::pe::STUB_VA;
    }
    let mut stub_next = t.nt_stub;
    if p.import_size != 0 {
        let mut i = 0u64;
        loop {
        if i >= 64 {
            return false;
        }
        let d = p.bias + p.import_rva + i * 20;
        let (Some(ilt_rva), Some(name_rva), Some(iat_rva)) = (
            read_task_u(t.pml4, d, 4),
            read_task_u(t.pml4, d + 12, 4),
            read_task_u(t.pml4, d + 16, 4),
        ) else {
            return false;
        };
        if ilt_rva == 0 && name_rva == 0 && iat_rva == 0 {
            break;
        }
        // All descriptor RVAs must name bytes inside the image --
        // a descriptor pointing elsewhere is malformed, not a
        // request to patch arbitrary task memory.
        if name_rva >= p.size || ilt_rva >= p.size || iat_rva >= p.size {
            return false;
        }
        let mut nb = [0u8; 32];
        let nl = read_task_str(t.pml4, p.bias + name_rva, &mut nb);
        let dll = &nb[..nl];
        let k32 = nl != 0
            && (dll.eq_ignore_ascii_case(b"kernel32.dll")
                || dll.eq_ignore_ascii_case(b"kernelbase.dll")
                || dll.eq_ignore_ascii_case(b"msvcrt.dll")
                || dll.eq_ignore_ascii_case(b"ucrtbase.dll")
                || dll.len() > 12 && dll[..12].eq_ignore_ascii_case(b"api-ms-win-"));
        let ntdll = nl != 0 && dll.eq_ignore_ascii_case(b"ntdll.dll");
        // A descriptor naming neither the system set nor ntdll is a
        // module import — resolve it through the module ledger like
        // the real loader's dependency walk. Dedup bumps refs; a
        // miss maps the image recursively (depth-bounded).
        let mut dep_base = 0u64;
        let mut dep_span = 0u64;
        if nl != 0 && !k32 && !ntdll {
            // The dep's own resolve bumps t.nt_stub — publish our
            // cursor first so its thunks append past ours, then
            // resync so ours append past its.
            t.nt_stub = stub_next;
            let Some((di, _)) = nt_mod_resolve(t, dll, depth) else {
                return false;
            };
            if *dep_mask & (1 << di) != 0 {
                // Same dep bound by a second descriptor — resolve
                // bumped refs but the mask releases once, so undo
                // the surplus bump or the dep strands a reference.
                let tab = unsafe { &mut *core::ptr::addr_of_mut!(NT_MODS) };
                tab[di].3 -= 1;
            } else {
                *dep_mask |= 1 << di;
            }
            let e = unsafe { &*core::ptr::addr_of!(NT_MODS) }[di];
            dep_base = e.1;
            dep_span = e.2;
            stub_next = t.nt_stub;
        } else if nl == 0 {
            return false;
        }
        let ilt = if ilt_rva != 0 { ilt_rva } else { iat_rva };
        for j in 0..256u64 {
            let Some(e) = read_task_u(t.pml4, p.bias + ilt + j * 8, 8) else {
                return false;
            };
            if e == 0 {
                break;
            }
            if e & (1 << 63) != 0 {
                return false; // ordinal imports unsupported
            }
            let ibn = e & 0x7fff_ffff;
            if ibn + 3 > p.size {
                return false;
            }
            let mut fname = [0u8; 48];
            // IMAGE_IMPORT_BY_NAME: u16 hint, then the name.
            let fl = read_task_str(t.pml4, p.bias + ibn + 2, &mut fname);
            if dep_base != 0 {
                // Module import — the IAT slot gets the dependency's
                // export VA directly, no thunk.
                if fl == 0 {
                    return false;
                }
                let va =
                    nt_export_lookup(t.pml4, dep_base, dep_span, &fname[..fl]);
                if va == 0
                    || !write_task_bytes_force(
                        t.pml4,
                        p.bias + iat_rva + j * 8,
                        &va.to_le_bytes(),
                    )
                {
                    return false;
                }
                continue;
            }
            // ntdll exports get a direct syscall stub; kernel32 /
            // msvcrt get a Win32-signature translation thunk — except
            // DATA exports, whose IAT slot must hold the variable's
            // own address (a cell in the data page), not code.
            if k32 && fl != 0 {
                if let Some(dv) = k32_data_sym(&fname[..fl]) {
                    if !write_task_bytes_force(
                        t.pml4,
                        p.bias + iat_rva + j * 8,
                        &dv.to_le_bytes(),
                    ) {
                        return false;
                    }
                    continue;
                }
            }
            let mut buf = [0u8; 768];
            let used = if k32 {
                k32_emit(&mut buf, &fname[..fl])
            } else if fl != 0 {
                crate::nt::service_for_name(&fname[..fl]).map(|nr| {
                    buf[0..3].copy_from_slice(&[0x4c, 0x8b, 0xd1]); // mov r10,rcx
                    buf[3] = 0xb8; // mov eax, imm32
                    buf[4..8].copy_from_slice(&nr.to_le_bytes());
                    buf[8] = 0x0f;
                    buf[9] = 0x05; // syscall
                    buf[10] = 0xc3; // ret
                    16
                })
            } else {
                None
            };
            let Some(used) = used else {
                return false;
            };
            let used = ((used as u64) + 15) & !15;
            if stub_next + used > crate::pe::STUB_DATA_VA
                || !write_task_bytes(t.pml4, stub_next, &buf[..used as usize])
            {
                return false;
            }
            if !write_task_bytes_force(
                t.pml4,
                p.bias + iat_rva + j * 8,
                &stub_next.to_le_bytes(),
            ) {
                return false;
            }
            stub_next += used;
        }
        i += 1;
        }
    }
    // TLS-callback trampoline (DLL_PROCESS_ATTACH) shares the stub
    // pages — it must land before the read+execute lock-down.
    // Exe-only: a DLL's callbacks fire from the LoadLibrary path,
    // and `t.entry` already names the running image.
    if primary {
        if emit_tls_tramp(t, p, &mut stub_next).is_none() {
            return false;
        }
        // The thread-exit stub too: a secondary thread's start_fn
        // "returns" here — rax's value becomes the thread exit
        // status via NtTerminateThread(0, status).
        if emit_thr_exit(t, &mut stub_next).is_none() {
            return false;
        }
        // Thread-entry trampoline: secondary threads start here so
        // every loaded module sees DLL_THREAD_ATTACH before the
        // start routine and DLL_THREAD_DETACH after it returns.
        if emit_thr_entry(t, &mut stub_next).is_none() {
            return false;
        }
        // An exe that statically bound module imports has pending
        // attaches — drain them at startup so dep DllMains run
        // before the image's TLS callbacks and entry, like Windows.
        if *dep_mask != 0 && emit_attach_drain(t, &mut stub_next).is_none() {
            return false;
        }
    }
    // Publish the cursor so the next mapped module appends, not
    // overwrites. Locking the stubs to read+execute is the
    // OUTERMOST caller's job — a dep image resolving inside the
    // exe's (or a LoadLibrary's) descriptor loop must not seal the
    // shared stub pages mid-fill; nt_lock_stubs runs at the top of
    // the load call stack only.
    t.nt_stub = stub_next;
    true
}

/// Seal the thunk/trampoline pages to read+execute after a top-level
/// image load — the exe path in pe_load_inner and LoadLibrary's
/// nt_load_dll each call this once the whole import graph is bound.
fn nt_lock_stubs(t: &mut Task) {
    for i in 0..3u64 {
        map_page(t, crate::pe::STUB_VA + i * 0x1000, USER);
    }
}

/// Emit the shared thread-exit stub: `NtTerminateThread(0, rax)` —
/// a secondary thread's synthetic return address points here so a
/// start_fn that returns dies with its return value as the status.
/// NtTerminateThread never returns; the trailing int3 is a canary.
fn emit_thr_exit(t: &mut Task, stub_next: &mut u64) -> Option<()> {
    const NT_TERMINATE_THREAD: u8 = 0x53;
    let code = [
        0x48, 0x89, 0xc2, //             mov rdx,rax  (status)
        0x45, 0x31, 0xd2, //             xor r10d,r10d (self)
        0xb8, NT_TERMINATE_THREAD, 0, 0, 0, // mov eax,0x53
        0x0f, 0x05, //                   syscall
        0xcc, //                         int3 (unreachable)
    ];
    if *stub_next + 16 > crate::pe::STUB_DATA_VA
        || !write_task_bytes(t.pml4, *stub_next, &code)
    {
        return None;
    }
    t.thr_exit_va = *stub_next;
    *stub_next += 16;
    Some(())
}

/// Emit the startup attach drain: an exe that bound module imports
/// runs this trampoline first — it loops RUX_DLL_ATTACH calling each
/// pending module's DllMain(hmod, ATTACH, 0), then tail-jumps to
/// `t.entry` (the TLS trampoline's, if one was emitted). Deps land in
/// lower ledger slots, so they initialize before their importer —
/// the same order the LoadLibrary thunk's drain produces.
fn emit_attach_drain(t: &mut Task, stub_next: &mut u64) -> Option<()> {
    let mut buf = [0u8; 192];
    let mut e = Emit { b: &mut buf, n: 0 };
    e.raw(&[
        0x48, 0x83, 0xe4, 0xf0, //    and rsp,-16
        // Multiple of 16: rsp is 0 mod 16 here, and each `call r9`
        // below must leave DllMain at rsp % 16 == 8 like the ABI
        // expects — a 0x28 frame would enter it misaligned.
        0x48, 0x83, 0xec, 0x30, //    sub rsp,0x30
    ]);
    let drain = e.n;
    e.raw(&[
        0xb8, 0xf7, 0, 0, 0, //     mov eax,0xF7  RUX_DLL_ATTACH
        0x0f, 0x05, //             syscall
        0x48, 0x85, 0xc0, //       test rax,rax
    ]);
    let done = e.jcc(0x4); //       queue empty -> entry
    e.raw(&[0x48, 0x89, 0xc3]); // mov rbx,rax    module base
    // Same per-module order as the runtime-load drains: each dep's
    // TLS callbacks run before its DllMain(DLL_PROCESS_ATTACH).
    emit_tls_cb_walk(&mut e, 1);
    e.raw(&[
        0x8b, 0x4b, 0x3c, //       mov ecx,[rbx+0x3c]     peoff
        0x8b, 0x4c, 0x0b, 0x28, // mov ecx,[rbx+rcx+0x28] entry_rva
        0x85, 0xc9, //             test ecx,ecx
    ]);
    let noent = e.jcc(0x4); //     no entry -> next
    e.raw(&[
        0x48, 0x01, 0xd9, //       add rcx,rbx    entry_va
        0x49, 0x89, 0xc9, //       mov r9,rcx
        0x48, 0x89, 0xd9, //       mov rcx,rbx    hinst
        0xba, 0x01, 0, 0, 0, //   mov edx,1      DLL_PROCESS_ATTACH
        0x45, 0x31, 0xc0, //       xor r8d,r8d
        0x41, 0xff, 0xd1, //       call r9        DllMain
    ]);
    e.fix_to(noent, drain);
    let back = e.jmp();
    e.fix_to(back, drain);
    e.fix(done);
    e.raw(&[0x48, 0xb8]); //        mov rax,imm64 — saved entry
    e.raw(&t.entry.to_le_bytes());
    e.raw(&[0xff, 0xe0]); //        jmp rax
    let n = e.n;
    if n > buf.len() {
        return None;
    }
    let used = (n as u64 + 15) & !15;
    if *stub_next + used > crate::pe::STUB_DATA_VA
        || !write_task_bytes(t.pml4, *stub_next, &buf[..n])
    {
        return None;
    }
    t.entry = *stub_next;
    *stub_next += used;
    Some(())
}

/// TLS directory (IMAGE_TLS_DIRECTORY32/64): emit a process-attach
/// trampoline into the stub page that calls each PIMAGE_TLS_CALLBACK
/// in the AddressOfCallBacks array with (hinst, DLL_PROCESS_ATTACH,
/// NULL), then tail-jumps to the real image entry. Sets `t.entry`
/// to the trampoline. Some(()) with the cursor bumped, None on
/// malformed directory or stub-space exhaustion.
fn emit_tls_tramp(t: &mut Task, p: &crate::pe::Pe, stub_next: &mut u64) -> Option<()> {
    if p.tls_rva == 0 || p.tls_size < 0x20 {
        // A directory too short for AddressOfCallBacks (+0x18) has
        // no callbacks to run.
        return Some(());
    }
    let cb = read_task_u(t.pml4, p.bias + p.tls_rva + 0x18, 8)?;
    if cb == 0 {
        return Some(());
    }
    // The callback array must live inside the image — anything else
    // is malformed, not a request to run arbitrary VA. Subtract
    // rather than add so a bias-sized cb can't wrap the compare.
    if !(p.size >= 8 && cb >= p.bias && cb - p.bias <= p.size - 8) {
        return None;
    }
    let mut buf = [0u8; 128];
    let mut e = Emit { b: &mut buf, n: 0 };
    e.raw(&[0x49, 0xbe]); // mov r14,imm64 — callbacks array
    e.raw(&cb.to_le_bytes());
    e.raw(&[
        0x48, 0x83, 0xe4, 0xf0, // and rsp,-16
        0x48, 0x83, 0xec, 0x20, // sub rsp,0x20
    ]);
    let lp = e.n;
    e.raw(&[
        0x49, 0x8b, 0x06, // mov rax,[r14]
        0x48, 0x85, 0xc0, // test rax,rax
    ]);
    let done = e.jcc(0x4); //   jz done
    e.raw(&[0x48, 0xb9]); //   mov rcx,imm64 — hinst
    e.raw(&p.bias.to_le_bytes());
    e.raw(&[
        0xba, 1, 0, 0, 0, //       mov edx,1  DLL_PROCESS_ATTACH
        0x4d, 0x31, 0xc0, //       xor r8d,r8d
        0xff, 0xd0, //             call rax
        0x49, 0x83, 0xc6, 0x08, // add r14,8
    ]);
    let back = e.jmp();
    e.fix_to(back, lp);
    e.fix(done);
    e.raw(&[
        0x48, 0x83, 0xc4, 0x20, // add rsp,0x20
        0x48, 0xb8, //            mov rax,imm64 — real entry
    ]);
    e.raw(&t.entry.to_le_bytes());
    e.raw(&[0xff, 0xe0]); //     jmp rax
    let n = e.n;
    if n > buf.len() {
        return None;
    }
    let used = (n as u64 + 15) & !15;
    if *stub_next + used > crate::pe::STUB_DATA_VA
        || !write_task_bytes(t.pml4, *stub_next, &buf[..n])
    {
        return None;
    }
    t.entry = *stub_next;
    *stub_next += used;
    Some(())
}

/// TLS data side: set *AddressOfIndex = 0 and point slot 0 at the
/// image's own .tls template span — correct for a single-threaded
/// process; per-thread copies wait for real NT threads. The
/// callback trampoline is emitted by emit_tls_tramp inside
/// pe_resolve_imports.
fn pe_tls_init(t: &mut Task, p: &crate::pe::Pe) -> bool {
    if p.tls_rva == 0 {
        // No TLS directory — make sure the exe-callback slot is 0 so
        // a stale array pointer can never be walked on detach paths.
        let _ = write_task_bytes(t.pml4, crate::pe::STUB_DATA_VA + 0x108, &0u64.to_le_bytes());
        return true;
    }
    if p.tls_size < 0x18 {
        return false; // can't even name template span + index
    }
    let dir = p.bias + p.tls_rva;
    let (Some(start), Some(end), Some(idx)) = (
        read_task_u(t.pml4, dir, 8),
        read_task_u(t.pml4, dir + 8, 8),
        read_task_u(t.pml4, dir + 0x10, 8),
    ) else {
        return false;
    };
    // Publish the exe's TLS-callback array for the thread and
    // process-detach notification paths, which invoke it with
    // hinst = image base. A missing or out-of-image array just
    // means no callbacks (emit_tls_tramp does the strict check).
    let cbs = if p.tls_size >= 0x20 {
        read_task_u(t.pml4, dir + 0x18, 8).unwrap_or(0)
    } else {
        0
    };
    let cbs = if p.size >= 8 && cbs >= p.bias && cbs - p.bias <= p.size - 8 {
        cbs
    } else {
        0
    };
    let _ = write_task_bytes(
        t.pml4,
        crate::pe::STUB_DATA_VA + 0x108,
        &cbs.to_le_bytes(),
    );
    // Every VA the directory names must land inside the image.
    if idx != 0 && !(p.size >= 4 && idx >= p.bias && idx - p.bias <= p.size - 4) {
        return false;
    }
    if end > start && (start < p.bias || end > p.bias + p.size) {
        return false;
    }
    if idx != 0 && !write_task_bytes_force(t.pml4, idx, &0u32.to_le_bytes()) {
        return false;
    }
    if end > start {
        if !write_task_bytes(
            t.pml4,
            crate::pe::STUB_DATA_VA + 0x200,
            &start.to_le_bytes(),
        ) {
            return false;
        }
        // Slot 0 is the compiled-TLS index — TlsAlloc must never
        // hand it back out or it would clobber the template ptr.
        // The bitmap at data+0x1f8 is the process-global map every
        // thread's TlsAlloc/TlsFree shares (slot values stay
        // per-thread under each thread's own gs:[0x58] array).
        let _ = write_task_bytes(t.pml4, crate::pe::STUB_DATA_VA + 0x1f8, &1u64.to_le_bytes());
        t.tls_tmpl_va = start;
        t.tls_tmpl_sz = end - start;
    }
    true
}

/// Write the minimal TEB/PEB a Windows binary's startup reads:
/// TEB.Self @0x30, TEB.Peb @0x60; PEB.ImageBaseAddress @0x10,
/// PEB.ProcessParameters @0x20 → a params block carrying the std
/// handles and a real UNICODE_STRING command line.
fn teb_peb_init(t: &mut Task, p: &crate::pe::Pe) -> bool {
    if map_page(t, crate::pe::PEB_VA, USER | WRITE | NX).is_none()
        || map_page(t, crate::pe::TEB_VA, USER | WRITE | NX).is_none()
    {
        return false;
    }
    let teb = crate::pe::TEB_VA;
    let peb = crate::pe::PEB_VA;
    if !write_task_bytes(t.pml4, teb + 0x30, &teb.to_le_bytes())
        || !write_task_bytes(t.pml4, teb + 0x60, &peb.to_le_bytes())
        || !write_task_bytes(t.pml4, peb + 0x10, &p.bias.to_le_bytes())
        || !write_task_bytes(t.pml4, peb + 0x20, &(peb + 0x400).to_le_bytes())
    {
        return false;
    }
    // TEB.ThreadLocalStoragePointer @0x58 → the 64-pointer slot
    // array in the data page — the same layout compiled TLS access
    // (gs:[0x58] indexing) and our Tls* thunks both use.
    if !write_task_bytes(t.pml4, teb + 0x58, &(crate::pe::STUB_DATA_VA + 0x200).to_le_bytes()) {
        return false;
    }
    let params = peb + 0x400;
    for (off, v) in [
        (0x020u64, 1u64), // StandardInput
        (0x028, 2),       // StandardOutput
        (0x030, 3),       // StandardError
    ] {
        if !write_task_bytes(t.pml4, params + off, &v.to_le_bytes()) {
            return false;
        }
    }
    true
}

/// Late PEB/TEB state that depends on fields populated only after
/// load() returns: TEB.ClientId {pid,tid} and the CommandLine
/// UNICODE_STRING at params+0x80 → UTF-16 text at peb+0x600, built
/// from t.exe (+ ".exe", the same spelling argv0 uses).
fn pe_late_init(t: &Task) -> bool {
    let teb = crate::pe::TEB_VA;
    // TEB.ClientId {UniqueProcess, UniqueThread} — read by the
    // GetCurrentProcessId/ThreadId thunks via gs:[0x40]/[0x48]. A
    // fresh TEB page (spawn or PE exec) carries zeros until now.
    if !write_task_bytes(t.pml4, teb + 0x40, &t.pid.to_le_bytes())
        || !write_task_bytes(t.pml4, teb + 0x48, &t.pid.to_le_bytes())
    {
        return false;
    }
    // Default CommandLine is just the image name — CreateProcess
    // overwrites it with the caller's lpCommandLine after spawn.
    let mut s = [0u8; 132];
    let el = (t.exe_len as usize).min(127);
    s[..el].copy_from_slice(&t.exe[..el]);
    s[el..el + 4].copy_from_slice(b".exe");
    peb_cmdline_write(t.pml4, &s[..el + 4])
}

/// PT_INTERP: when `e` names an interpreter, load that ELF too —
/// Linux's load_elf_interp analogue. The interp is another ET_DYN
/// image; it goes into the mmap arena via the same first-fit VMA
/// allocator user mmap uses, so it can never collide with a later
/// mmap. Returns (entry to start at, AT_BASE) — the image's own
/// entry and base 0 when it has no interp, None on failure (a
/// missing or malformed interpreter fails the exec like ENOENT on
/// Linux's open_exec).
fn interp_load(t: &mut Task, e: &elf::Elf, img: &[u8]) -> Option<(u64, u64)> {
    let Some(path) = e.interp(img) else {
        return Some((e.entry, 0));
    };
    // The fs names archive members without the leading '/'.
    let name = path.strip_prefix(b"/").unwrap_or(path);
    // The interpreter may itself sit behind a link — follow fully;
    // an unresolvable chain fails the exec like the ENOENT below.
    let (rb, rn, _) = resolve_links(name, true).ok()?;
    let iimg = fs_lookup(&rb[..rn])?;
    // Measure the span at a probe bias (bias-0 would fail parse's
    // entry-in-window check; the span itself is bias-independent),
    // first-fit a gap in the mmap arena, then map so the lowest
    // PT_LOAD page lands exactly there — Linux's total_mapping_size
    // dance over mmap_base.
    let raw = elf::parse_at(iimg, MMAP_LO)?;
    let (mut lo, mut hi) = (u64::MAX, 0u64);
    for p in raw.phdrs(iimg) {
        if p.ty != elf::PT_LOAD || p.memsz == 0 {
            continue;
        }
        let mend = p.va.checked_add(p.memsz)?;
        lo = lo.min(p.va & !0xfff);
        hi = hi.max((mend + 0xfff) & !0xfff);
    }
    if lo >= hi {
        return None;
    }
    let base = mmap_find(t, hi - lo)?;
    // Shift the measured image so its lowest page sits at `base`:
    // real bias = base - raw_lo = base - (lo - MMAP_LO).
    let ie = elf::parse_at(iimg, base.checked_add(MMAP_LO)?.checked_sub(lo)?)?;
    if !map_loads(t, &ie, iimg, false) {
        return None;
    }
    Some((ie.entry, base))
}

/// Load `img` into a fresh Task. Any malformed input or allocation
/// failure reaps the partial task — nothing half-allocated escapes.
fn load(img: &[u8]) -> Option<Task> {
    // Image format selects the personality: MZ → PE32+/NT, else the
    // ELF path. Both leave `entry` filled for the literal below.
    let pe_img = if img.starts_with(b"MZ") {
        crate::pe::parse(img)
    } else {
        None
    };
    let elf_img = if pe_img.is_none() { elf::parse(img) } else { None };
    let entry = pe_img
        .as_ref()
        .map(|p| p.entry)
        .or(elf_img.as_ref().map(|e| e.entry))?;
    let pml4 = kalloc::alloc_frame()?;
    let Some(fdi) = fdtab_alloc() else {
        kalloc::free_frame(pml4);
        return None;
    };
    let Some(sigh) = sigtab_alloc() else {
        fdtab_release(fdi);
        kalloc::free_frame(pml4);
        return None;
    };
    let Some(fsi) = fstab_alloc(0o022) else {
        sigtab_release(sigh);
        fdtab_release(fdi);
        kalloc::free_frame(pml4);
        return None;
    };
    let mut t = Task {
        pml4,
        fdi,
        sigh,
        fsi,
        tgid: 0, // spawn() sets tgid = pid once the pid exists
        entry,
        stack_top: 0,
        kstack_base: 0,
        kstack_top: 0,
        ranges: [(0, 0, 0); MAX_RANGES],
        nranges: 0,
        brk_base: 0,
        brk_cur: 0,

        ctx: UCtx::ZERO,
        state: TaskState::Runnable,
        // Assigned here, not in spawn(): PE import resolution inside
        // pe_load_inner registers dependent modules under the owning
        // pid — it must exist before the image load runs.
        pid: next_pid(),
        ppid: 0,
        exit_status: 0,
        wait_on: WaitOn::None,
        wait_ptr: 0,
        wait_ptr2: 0,
        wait_ptr3: 0,
        psel_mask: u64::MAX,
        frame_mask: u64::MAX,
        wait_len: 0,
        wait_deadline: 0,
        pending: 0,
        pend_src: [SIGSRC_NONE; 31],
        sigmask: 0,
        // SAFETY: read of the init-time capture.
        fx: unsafe { *core::ptr::addr_of!(INIT_FX) },
        name: [0; 16],
        exe: [0; 128],
        exe_len: 0,
        fs_base: 0,
        rseq_va: 0,
        clear_ctid: 0,
        // Boot session: every spawned task is its own group leader
        // inside session 1 — the console's owning session.
        pgid: 0,
        sid: 1,
        did_exec: true,
        pers: PERS_LINUX,
        gs_base: 0,
        nth: [0; crate::nt::MAX_NTH],
        nth_fd: [0xff; crate::nt::MAX_NTH],
        nth_dirpat: [[0; 96]; crate::nt::MAX_NTH],
        heap_blk: [[0; 3]; 128],
        heap_bump: 0,
        heap_commit: 0,
        nt_alloc: 0,
        tls_tmpl_va: 0,
        tls_tmpl_sz: 0,
        thr_exit_va: 0,
        thr_entry_va: 0,
        nt_stub: 0,
        stop_sig: 0,
        cont_report: false,
        start_ticks: crate::apic::TICKS
            .load(core::sync::atomic::Ordering::Relaxed),
        utime: 0,
        stime: 0,
        cmdline: [0; 256],
        cmdline_len: 0,
    };
    // std streams: 0=stdin (EOF), 1/2=serial console — each a fresh
    // global OFD, like separate opens of /dev/console.
    {
        let ofds = unsafe { &mut *core::ptr::addr_of_mut!(OFDS) };
        for i in 0..3usize {
            let Some(oi) = ofds.iter().position(Option::is_none) else {
                t.reap();
                return None;
            };
            ofds[oi] = Some(OpenFile {
                kind: if i == 0 { FdKind::Stdin } else { FdKind::Console },
                pos: 0,
                refs: 1,
                append: false,
                accmode: if i == 0 { 0 } else { 1 },
            });
            fdt(&t).fds[i] = Some(oi as u8);
        }
    }
    let ok = if let Some(p) = &pe_img {
        pe_load_inner(&mut t, p, img)
    } else {
        load_inner(&mut t, elf_img.as_ref().unwrap(), img)
    };
    if !ok {
        t.reap();
        return None;
    }
    let ks = kalloc::kmalloc(KSTACK_SIZE) as u64;
    if ks == 0 {
        t.reap();
        return None;
    }
    t.kstack_base = ks;
    t.kstack_top = ks + KSTACK_SIZE as u64;
    Some(t)
}

/// Range-table access bits — mirror PROT_READ/PROT_WRITE.
const RNG_R: u8 = 1;
const RNG_W: u8 = 2;
const RNG_X: u8 = 4;
/// Reserved-but-uncommitted VMA (NtAllocateVirtualMemory
/// MEM_RESERVE): occupies VA in the ledger but maps no pages. The
/// low bits carry the reservation's placeholder protection for
/// AllocationProtect fidelity, so probes must exclude RNG_RES
/// explicitly — RNG_R|RNG_W on it must NOT pass.
const RNG_RES: u8 = 8;

/// Is `[va, va+len)` wholly inside a mapped user range? This is THE
/// user-pointer gate for the syscall layer — checked arithmetic only.
/// `need_write` demands RNG_W (kernel writes into the buffer);
/// otherwise RNG_R suffices — a PROT_NONE VMA fails both, and so
/// does a reserved-not-committed one.
fn range_check(va: u64, len: u64, need_write: bool) -> bool {
    if len == 0 {
        return false;
    }
    let Some(end) = va.checked_add(len) else {
        return false;
    };
    // SAFETY: read-only walk of the task table; NT threads probe
    // the leader's ledger — the shared mm's authoritative map.
    let Some(i) = mm_owner_i() else { return false };
    let cur = unsafe { (*core::ptr::addr_of!(TASKS)).get(i).and_then(|s| s.as_ref()) };
    let want = if need_write { RNG_W } else { RNG_R };
    cur.is_some_and(|p| {
        p.ranges[..p.nranges]
            .iter()
            .any(|&(lo, hi, fl)| va >= lo && end <= hi && fl & want != 0 && fl & RNG_RES == 0)
    })
}

/// Read-side gate: [va, va+len) inside a mapped user range.
pub fn range_ok(va: u64, len: u64) -> bool {
    range_check(va, len, false)
}

/// Write-side gate: same range check, but the range must be
/// user-writable — the Linux rule for read()-target buffers.
pub fn range_ok_w(va: u64, len: u64) -> bool {
    range_check(va, len, true)
}

// --- memory management (brk/mmap/munmap/mprotect) -------------------
//
// VMAs are the `ranges` table itself: every mapped interval has an
// entry, so the syscall gate, first-fit allocation, and teardown all
// see the same truth. Pages are mapped eagerly (alloc_frame zeroes);
// PROT_NONE is a present-but-supervisor leaf — the VMA reserves the
// VA, user access faults, mprotect can restore USER later.

/// Flush the TLB after user-page-table edits on the current address
/// space — same reload exec uses (user leaves carry no GLOBAL bit).
fn flush_tlb() {
    // SAFETY: reloading the current cr3 only flushes the TLB.
    unsafe { core::arch::asm!("mov {0}, cr3", "mov cr3, {0}", out(reg) _) };
}

/// Drop `va`'s leaf mapping in `t`'s address space: free the backing
/// frame and clear the PTE. Intermediate tables stay allocated —
/// teardown (reap/exec's free_user_mappings) reclaims them in bulk.
/// No-op on an absent or huge mapping.
fn unmap_page(t: &mut Task, va: u64) {
    let mut tab = t.pml4;
    for shift in [39u64, 30, 21] {
        let e = rd64(tab + 8 * ((va >> shift) & 0x1ff));
        if e & PRESENT == 0 || e & (1 << 7) != 0 {
            return;
        }
        tab = e & PHYS_MASK;
    }
    let ent = tab + 8 * ((va >> 12) & 0x1ff);
    let e = rd64(ent);
    if e & PRESENT != 0 {
        kalloc::free_frame(e & PHYS_MASK);
        wr64(ent, 0);
    }
}

/// PTE address of `va`'s present leaf under `t.pml4` — mprotect's
/// rewrite target. None on absent or huge-page traversal.
fn leaf_ent(t: &Task, va: u64) -> Option<u64> {
    let mut tab = t.pml4;
    for shift in [39u64, 30, 21] {
        let e = rd64(tab + 8 * ((va >> shift) & 0x1ff));
        if e & PRESENT == 0 || e & (1 << 7) != 0 {
            return None;
        }
        tab = e & PHYS_MASK;
    }
    let ent = tab + 8 * ((va >> 12) & 0x1ff);
    (rd64(ent) & PRESENT != 0).then_some(ent)
}

/// Append a range entry; false when the table is full — callers
/// pre-check capacity before mutating page tables so ops stay atomic.
fn range_add(t: &mut Task, lo: u64, hi: u64, fl: u8) -> bool {
    if lo >= hi {
        return true; // empty VMA is a no-op
    }
    if t.nranges >= MAX_RANGES {
        return false;
    }
    t.ranges[t.nranges] = (lo, hi, fl);
    t.nranges += 1;
    true
}

/// Compact `t`'s range table after a rewrite — drops empty entries
/// and merges adjacent intervals with identical flags, so repeated
/// split cycles can't permanently consume the bounded table.
fn range_compact(t: &mut Task) {
    let mut w = 0usize;
    let mut out = [(0u64, 0u64, 0u8); MAX_RANGES];
    for &(lo, hi, fl) in &t.ranges[..t.nranges] {
        if lo >= hi {
            continue;
        }
        out[w] = (lo, hi, fl);
        w += 1;
    }
    // Entries aren't kept sorted — splits append at the tail — so
    // merges need ordering first; insertion sort is fine at this
    // table's fixed small size.
    out[..w].sort_unstable();
    let mut k = 0usize;
    for i in 1..w {
        if out[k].1 == out[i].0 && out[k].2 == out[i].2 {
            out[k].1 = out[i].1;
        } else {
            k += 1;
            out[k] = out[i];
        }
    }
    t.ranges = out;
    t.nranges = if w == 0 { 0 } else { k + 1 };
}

/// Entries needed after clipping [a,b) out of `t`'s table — partial
/// intersections split in two. Used to fail ops atomically before a
/// single page table entry is touched (no half-applied munmap).
fn clip_entry_count(t: &Task, a: u64, b: u64) -> usize {
    let mut n = 0usize;
    for &(lo, hi, _) in &t.ranges[..t.nranges] {
        if lo >= b || hi <= a {
            n += 1; // untouched
        } else {
            n += (lo < a) as usize + (hi > b) as usize;
        }
    }
    n
}

/// Remove [a,b) from every range entry — splits partial overlaps,
/// drops covered ones, then compacts. Caller pre-checked capacity.
fn range_clip(t: &mut Task, a: u64, b: u64) {
    for i in 0..t.nranges {
        let (lo, hi, fl) = t.ranges[i];
        if lo >= b || hi <= a {
            continue;
        }
        t.ranges[i] = if lo < a {
            (lo, a, fl) // left remnant; right piece appended below
        } else if hi > b {
            (b, hi, fl)
        } else {
            (0, 0, 0)
        };
        if lo < a && hi > b {
            // Middle cut — the right remnant needs a fresh slot.
            t.ranges[t.nranges] = (b, hi, fl);
            t.nranges += 1;
        }
    }
    range_compact(t);
}

/// Is [a,b) fully covered by (possibly several) range entries?
/// mprotect's precondition — Linux ENOMEMs over unmapped VA.
fn range_covered(t: &Task, a: u64, b: u64) -> bool {
    let mut cur = a;
    while cur < b {
        let mut adv = cur;
        for &(lo, hi, _) in &t.ranges[..t.nranges] {
            if lo <= cur && hi > adv {
                adv = hi;
            }
        }
        if adv == cur {
            return false;
        }
        cur = adv;
    }
    true
}

/// Committed-only coverage: like range_covered, but RNG_RES
/// (reserved-not-committed) entries don't count — VirtualProtect
/// and decommit need pages that actually exist.
fn range_committed(t: &Task, a: u64, b: u64) -> bool {
    let mut cur = a;
    while cur < b {
        let mut adv = cur;
        for &(lo, hi, fl) in &t.ranges[..t.nranges] {
            if fl & RNG_RES == 0 && lo <= cur && hi > adv {
                adv = hi;
            }
        }
        if adv == cur {
            return false;
        }
        cur = adv;
    }
    true
}

/// Set access bits on the intersection of every range with [a,b).
/// Precondition: range_covered passed and capacity was pre-checked.
fn range_protect(t: &mut Task, a: u64, b: u64, fl: u8) {
    for i in 0..t.nranges {
        let (lo, hi, ofl) = t.ranges[i];
        if lo >= b || hi <= a || ofl == fl {
            continue;
        }
        // Emit up to three pieces: unchanged left, reprotected middle,
        // unchanged right — the extra slots were counted up front.
        if lo < a {
            t.ranges[i] = (lo, a, ofl);
            t.ranges[t.nranges] = (a, hi.min(b), fl);
            t.nranges += 1;
            if hi > b {
                t.ranges[t.nranges] = (b, hi, ofl);
                t.nranges += 1;
            }
        } else {
            t.ranges[i] = (a.max(lo), hi.min(b), fl);
            if hi > b {
                t.ranges[t.nranges] = (b, hi, ofl);
                t.nranges += 1;
            }
        }
    }
    range_compact(t);
}

/// Slots needed if [a,b) is reprotected on top of `t`'s table —
/// worst case one clipped entry becomes three.
fn protect_entry_count(t: &Task, a: u64, b: u64) -> usize {
    let mut n = 0usize;
    for &(lo, hi, _) in &t.ranges[..t.nranges] {
        if lo >= b || hi <= a {
            n += 1;
        } else {
            n += 1 + (lo < a) as usize + (hi > b) as usize;
        }
    }
    n
}

/// First-fit a `len`-page VMA in the mmap arena — holes are just
/// space between recorded ranges, so munmap'd VA is reused naturally.
fn mmap_find(t: &Task, len: u64) -> Option<u64> {
    let mut c = MMAP_LO;
    loop {
        let end = c.checked_add(len)?;
        if end > MMAP_HI {
            return None;
        }
        let mut bump = 0u64;
        for &(lo, hi, _) in &t.ranges[..t.nranges] {
            if lo < end && hi > c {
                bump = bump.max(hi);
            }
        }
        if bump == 0 {
            return Some(c);
        }
        c = (bump + PAGE - 1) & !(PAGE - 1);
    }
}

/// prot → leaf-flag bits for user PTEs: PROT_NONE yields a
/// present-supervisor page (no USER bit) — VMA-reserved, faulting.
fn prot_leaf(prot: u64) -> u64 {
    if prot == 0 {
        return 0; // PRESENT only — supervisor leaf
    }
    let mut fl = USER;
    if prot & 2 != 0 {
        fl |= WRITE;
    }
    if prot & 4 == 0 {
        fl |= NX;
    }
    fl
}

/// prot → range access bits for the syscall-pointer gate.
fn prot_rng(prot: u64) -> u8 {
    ((prot & 1 != 0) as u8) | ((prot & 2 != 0) as u8) << 1
}

/// brk(addr): set the program break — page-granular growth at
/// brk_base. Returns the NEW break on success, the CURRENT one on
/// any failure (the Linux contract — never an errno).
pub fn sys_brk(addr: u64) -> u64 {
    const BRK_CAP: u64 = 256 << 20; // bounded heap: 256 MiB
    let Some(t) = cur_mut() else { return 0 };
    if t.brk_base == 0 || addr < t.brk_base {
        return t.brk_cur;
    }
    let Some(new_end) = addr
        .checked_add(PAGE - 1)
        .map(|v| v & !(PAGE - 1))
    else {
        return t.brk_cur;
    };
    if new_end < t.brk_base || new_end - t.brk_base > BRK_CAP {
        return t.brk_cur;
    }
    // The heap may not grow into another mapping (Linux's collision
    // check) — the heap's own VMA (lo == brk_base) doesn't count.
    let old_end = (t.brk_cur + PAGE - 1) & !(PAGE - 1);
    if new_end > old_end
        && t.ranges[..t.nranges].iter().any(|&(lo, hi, _)| {
            lo != t.brk_base && lo < new_end && hi > old_end
        })
    {
        return t.brk_cur;
    }
    if new_end > old_end {
        // Grow: the heap VMA grows in place or is re-added (a munmap
        // may have eaten it). Ensure the slot exists BEFORE mapping
        // so a full table can't leave pages mapped-but-ungated.
        let has_vma = t.ranges[..t.nranges]
            .iter()
            .any(|&(lo, _, _)| lo == t.brk_base);
        if !has_vma && t.nranges >= MAX_RANGES {
            return t.brk_cur;
        }
        let mut v = old_end.max(t.brk_base);
        while v < new_end {
            if map_page(t, v, USER | WRITE | NX).is_none() {
                // Roll back this syscall's partial growth.
                let mut u = old_end.max(t.brk_base);
                while u < v {
                    unmap_page(t, u);
                    u += PAGE;
                }
                flush_tlb();
                return t.brk_cur;
            }
            v += PAGE;
        }
        if has_vma {
            for r in t.ranges[..t.nranges].iter_mut() {
                if r.0 == t.brk_base {
                    r.1 = r.1.max(new_end);
                    r.2 = RNG_R | RNG_W;
                }
            }
        } else {
            range_add(t, t.brk_base, new_end, RNG_R | RNG_W);
        }
    } else if new_end < old_end {
        let mut v = new_end;
        while v < old_end {
            unmap_page(t, v);
            v += PAGE;
        }
        for r in t.ranges[..t.nranges].iter_mut() {
            if r.0 == t.brk_base {
                r.1 = new_end;
            }
        }
        flush_tlb();
    }
    t.brk_cur = addr;
    addr
}

/// mmap(addr, len, prot, flags, fd, off): anonymous private mappings
/// only — the malloc substrate. FD-backed and shared mappings are
/// ENODEV until file-backed VMAs exist. MAP_FIXED replaces whatever
/// is at `addr` (inside the user window — kernel slots are off
/// limits unconditionally).
pub fn sys_mmap(
    addr: u64,
    len: u64,
    prot: u64,
    flags: u64,
    fd: u64,
    off: u64,
) -> u64 {
    const EACCES: u64 = (-13i64) as u64;
    const ENODEV: u64 = (-19i64) as u64;
    const ENOMEM: u64 = (-12i64) as u64;
    const MAP_PRIVATE: u64 = 0x02;
    const MAP_FIXED: u64 = 0x10;
    const MAP_ANON: u64 = 0x20;
    const MAP_SHARED: u64 = 0x01;
    let Some(t) = cur_mut() else { return ENOMEM };
    // MAP_SHARED is honest ENODEV even without MAP_PRIVATE — shared
    // writable mappings would need writeback we do not have.
    if flags & MAP_SHARED != 0 {
        return ENODEV;
    }
    if len == 0 || prot > 7 || flags & MAP_PRIVATE == 0 {
        return EINVAL;
    }
    // File-backed MAP_PRIVATE: pages are private copies eager-filled
    // from the fd — COW is trivially exact since nothing aliases the
    // file. Past-EOF bytes are zeros (Linux would SIGBUS — divergence).
    let mut backing: Option<(*const u8, usize)> = None;
    if flags & MAP_ANON == 0 {
        if off & (PAGE - 1) != 0 {
            return EINVAL;
        }
        let Some(o) = ofd(t, fd) else { return EBADF };
        if o.accmode == 1 {
            return EACCES; // fd not open for reading
        }
        backing = Some(match &o.kind {
            FdKind::File(d) => (d.as_ptr(), d.len()),
            FdKind::Ram(i) => match vfile(*i) {
                Some(v) => (v.data as *const u8, v.len),
                None => return EBADF,
            },
            _ => return ENODEV, // non-regular: pipes/sockets/dirs
        });
    }
    let Some(len) = len.checked_add(PAGE - 1).map(|v| v & !(PAGE - 1))
    else {
        return ENOMEM;
    };
    let va = if addr != 0 {
        if addr & (PAGE - 1) != 0
            || addr < elf::USER_VA_LO
            || addr.checked_add(len).is_none_or(|e| e > elf::USER_VA_HI)
        {
            return if flags & MAP_FIXED != 0 { EINVAL } else { ENOMEM };
        }
        if flags & MAP_FIXED != 0 {
            // Replace semantics: free the overlapped pages AND clip
            // their VMA entries — map_page would otherwise union-keep
            // the stale frames. Atomic: capacity checked up front.
            if clip_entry_count(t, addr, addr + len) >= MAX_RANGES {
                return ENOMEM;
            }
            let mut v = addr;
            while v < addr + len {
                unmap_page(t, v);
                v += PAGE;
            }
            range_clip(t, addr, addr + len);
            // Freed frames' stale translations must go before user
            // code can run — else they alias whatever the buddy hands
            // those frames to next (cross-task UAF).
            flush_tlb();
            addr
        } else if t.ranges[..t.nranges]
            .iter()
            .any(|&(lo, hi, _)| lo < addr + len && hi > addr)
        {
            // Hint collides — fall back to first-fit like Linux.
            let Some(v) = mmap_find(t, len) else { return ENOMEM };
            v
        } else {
            addr
        }
    } else {
        let Some(v) = mmap_find(t, len) else { return ENOMEM };
        v
    };
    if t.nranges >= MAX_RANGES {
        return ENOMEM;
    }
    let leaf = prot_leaf(prot);
    let mut v = va;
    while v < va + len {
        if map_page(t, v, leaf).is_none() {
            let mut u = va;
            while u < v {
                unmap_page(t, u);
                u += PAGE;
            }
            flush_tlb();
            return ENOMEM;
        }
        v += PAGE;
    }
    if let Some((data, dlen)) = backing {
        let avail = dlen.saturating_sub(off as usize).min(len as usize);
        if avail > 0 {
            // SAFETY: data is a live cpio slice or a kmalloc'd VFile
            // buffer of dlen bytes; off < dlen checked by the sub.
            let s = unsafe {
                core::slice::from_raw_parts(data.add(off as usize), avail)
            };
            write_task_bytes_force(t.pml4, va, s);
        }
    }
    range_add(t, va, va + len, prot_rng(prot));
    va
}

/// munmap(addr, len): Linux never fails on an aligned range — holes
/// and foreign areas are silent no-ops. Pages are freed, range
/// entries clipped/split, one TLB flush at the end.
pub fn sys_munmap(addr: u64, len: u64) -> u64 {
    let Some(t) = cur_mut() else { return EINVAL };
    if len == 0 || addr & (PAGE - 1) != 0 {
        return EINVAL;
    }
    // Clip to the user window — wild VA is not an error, just
    // nothing-to-do (Linux's permissive semantic). Length rounds UP
    // to whole pages like Linux: unmapping 1 byte still zaps the page.
    let lo = addr.max(elf::USER_VA_LO);
    let len = match len.checked_add(PAGE - 1) {
        Some(v) => v & !(PAGE - 1),
        None => u64::MAX - (PAGE - 1),
    };
    let hi = addr.saturating_add(len).min(elf::USER_VA_HI);
    if lo >= hi {
        return 0;
    }
    if clip_entry_count(t, lo, hi) > MAX_RANGES {
        return (-12i64) as u64; // ENOMEM — atomic bail before touching
    }
    let mut v = lo;
    while v < hi {
        unmap_page(t, v);
        v += PAGE;
    }
    range_clip(t, lo, hi);
    flush_tlb();
    0
}

/// mprotect(addr, len, prot): every page in the range must be mapped
/// (Linux ENOMEMs over holes); flags flip on leaf and VMA alike,
/// with VMA splits where the coverage is partial.
pub fn sys_mprotect(addr: u64, len: u64, prot: u64) -> u64 {
    const ENOMEM: u64 = (-12i64) as u64;
    let Some(t) = cur_mut() else { return ENOMEM };
    if addr & (PAGE - 1) != 0 || prot > 7 {
        return EINVAL;
    }
    if len == 0 {
        return 0;
    }
    let Some(end) = addr.checked_add(len) else { return ENOMEM };
    if addr < elf::USER_VA_LO || end > elf::USER_VA_HI {
        return ENOMEM;
    }
    let hi = (end + PAGE - 1) & !(PAGE - 1);
    if !range_covered(t, addr, hi)
        || protect_entry_count(t, addr, hi) > MAX_RANGES
    {
        return ENOMEM;
    }
    let leaf = prot_leaf(prot);
    let mut v = addr;
    while v < hi {
        // A covered range implies a mapped page — an absent leaf
        // here means the invariant broke; fail rather than guess.
        let Some(ent) = leaf_ent(t, v) else { return ENOMEM };
        let e = rd64(ent);
        wr64(ent, (e & PHYS_MASK) | PRESENT | leaf);
        v += PAGE;
    }
    range_protect(t, addr, hi, prot_rng(prot));
    flush_tlb();
    0
}

// --- process image: exec stack, arch_prctl, misc ABI ----------------
//
// Real binaries need the Linux initial-stack contract: argc at [rsp],
// argv pointers, NULL, envp pointers, NULL, auxv pairs, AT_NULL — and
// %fs as TLS via arch_prctl. Collected argv strings must be copied
// BEFORE exec frees the old address space.

/// Bounded exec vectors — kernel-side copies made while the OLD
/// address space is still mapped. Limits are honest EINVAL/E2BIG
/// boundaries, not Linux's multi-MB ARG_MAX.
pub const MAX_EXEC_ARGS: usize = 16;
pub const MAX_EXEC_ENVS: usize = 8;
pub const EXEC_STR_CAP: usize = 256;

pub struct ExecArgs {
    pub argv: [[u8; EXEC_STR_CAP]; MAX_EXEC_ARGS],
    pub argv_len: [usize; MAX_EXEC_ARGS],
    pub argc: usize,
    pub envp: [[u8; EXEC_STR_CAP]; MAX_EXEC_ENVS],
    pub envp_len: [usize; MAX_EXEC_ENVS],
    pub envc: usize,
}

impl ExecArgs {
    pub const fn empty() -> Self {
        ExecArgs {
            argv: [[0; EXEC_STR_CAP]; MAX_EXEC_ARGS],
            argv_len: [0; MAX_EXEC_ARGS],
            argc: 0,
            envp: [[0; EXEC_STR_CAP]; MAX_EXEC_ENVS],
            envp_len: [0; MAX_EXEC_ENVS],
            envc: 0,
        }
    }
}

/// Read a NUL-terminated string from `pml4`'s address space —
/// translate-per-byte like the sleeper paths, so an unmapped string
/// can't fault the kernel. None on bad memory or overflow.
fn copy_task_str(pml4: u64, va: u64, dst: &mut [u8]) -> Option<usize> {
    for (i, slot) in dst.iter_mut().enumerate() {
        let b = read_task_u(pml4, va + i as u64, 1)? as u8;
        *slot = b;
        if b == 0 {
            return Some(i);
        }
    }
    None
}

/// Collect one NUL-terminated pointer array (argv or envp) from the
/// caller's address space — bounded, every pointer slot gate-checked
/// before the string walk.
fn collect_strs(
    pml4: u64,
    va_base: u64,
    dest: &mut [[u8; EXEC_STR_CAP]],
    destlen: &mut [usize],
) -> Result<usize, u64> {
    const E2BIG: u64 = (-7i64) as u64;
    if va_base == 0 {
        return Ok(0);
    }
    let mut n = 0usize;
    loop {
        if n >= dest.len() {
            return Err(E2BIG);
        }
        let slot = va_base + (n as u64) * 8;
        if !range_ok(slot, 8) {
            return Err(EFAULT);
        }
        let Some(ptr) = read_task_u(pml4, slot, 8) else {
            return Err(EFAULT);
        };
        if ptr == 0 {
            return Ok(n);
        }
        let Some(l) = copy_task_str(pml4, ptr, &mut dest[n]) else {
            return Err(EFAULT);
        };
        destlen[n] = l + 1;
        n += 1;
    }
}

/// Collect execve's argv/envp pointer arrays into `out` — bounded,
/// read while the OLD address space is still mapped.
pub fn collect_exec_args(argv_va: u64, envp_va: u64, out: &mut ExecArgs) -> u64 {
    const E2BIG: u64 = (-7i64) as u64;
    let Some(t) = cur_mut() else { return E2BIG };
    match collect_strs(t.pml4, argv_va, &mut out.argv, &mut out.argv_len) {
        Ok(n) => out.argc = n,
        Err(e) => return e,
    }
    match collect_strs(t.pml4, envp_va, &mut out.envp, &mut out.envp_len) {
        Ok(n) => out.envc = n,
        Err(e) => return e,
    }
    0
}

/// Build the Linux initial stack: strings top-down, 16B AT_RANDOM,
/// then [argc][argv ptrs][NULL][envp ptrs][NULL][auxv][AT_NULL].
/// Returns the final rsp — launch's ctx needs exactly this.
fn setup_stack(
    t: &mut Task,
    e: &elf::Elf,
    img: &[u8],
    args: &ExecArgs,
    at_base: u64,
) -> Option<u64> {
    let mut sp = t.stack_top;
    let mut str_va = |s: &[u8]| -> u64 {
        sp -= s.len() as u64;
        write_task_bytes(t.pml4, sp, s);
        sp
    };
    let mut argv = [0u64; MAX_EXEC_ARGS];
    for (i, (s, &l)) in args.argv.iter().zip(args.argv_len.iter()).enumerate().take(args.argc) {
        argv[i] = str_va(&s[..l]);
    }
    let mut envv = [0u64; MAX_EXEC_ENVS];
    for (i, (s, &l)) in args.envp.iter().zip(args.envp_len.iter()).enumerate().take(args.envc) {
        envv[i] = str_va(&s[..l]);
    }
    // AT_RANDOM: 16 real bytes — glibc seeds its stack canary here.
    sp -= 16;
    let mut rnd = [0u8; 16];
    rnd[..8].copy_from_slice(&crate::rand::next_u64().to_le_bytes());
    rnd[8..].copy_from_slice(&crate::rand::next_u64().to_le_bytes());
    write_task_bytes(t.pml4, sp, &rnd);
    let at_random = sp;
    sp &= !15u64;
    // AT_PHDR needs the VA where the phdr table was mapped — the
    // PT_LOAD covering e_phoff (headers land in the first segment).
    let mut at_phdr = 0u64;
    for p in e.phdrs(img) {
        if p.ty == elf::PT_LOAD
            && (p.off..p.off + p.filesz).contains(&(e.phoff() as u64))
        {
            at_phdr = p.va + (e.phoff() as u64 - p.off);
        }
    }
    let auxv: [(u64, u64); 16] = [
        (3, at_phdr),          // AT_PHDR
        (4, e.phentsize() as u64),
        (5, e.phnum() as u64),
        (6, PAGE),             // AT_PAGESZ
        (7, at_base),          // AT_BASE (0 = no interp)
        (8, 0),                // AT_FLAGS
        (9, e.entry),          // AT_ENTRY
        (11, 0),               // AT_UID
        (12, 0),               // AT_EUID
        (13, 0),               // AT_GID
        (14, 0),               // AT_EGID
        (16, 0),               // AT_HWCAP
        (17, 100),             // AT_CLKTCK — apic runs at 100Hz
        (23, 0),               // AT_SECURE
        (25, at_random),       // AT_RANDOM
        (0, 0),                // AT_NULL
    ];
    let slots = 1 + args.argc + 1 + args.envc + 1 + auxv.len() * 2;
    sp -= (slots as u64) * 8;
    sp &= !15u64; // ABI: rsp 16-aligned at entry
    let w = |v: u64, i: usize| {
        write_task_bytes(t.pml4, sp + (i as u64) * 8, &v.to_le_bytes());
    };
    let mut i = 0;
    w(args.argc as u64, i);
    i += 1;
    for &a in argv.iter().take(args.argc) {
        w(a, i);
        i += 1;
    }
    w(0, i);
    i += 1;
    for &e in envv.iter().take(args.envc) {
        w(e, i);
        i += 1;
    }
    w(0, i);
    i += 1;
    for (k, v) in auxv {
        w(k, i);
        w(v, i + 1);
        i += 2;
    }
    Some(sp)
}

/// arch_prctl(code, addr): x86_64 TLS control. SET_FS installs the
/// task's FS base (validated inside the user window or zero); GET_FS
/// writes it through a validated pointer. GS ops are EINVAL — no user
/// GS protocol exists in this ABI.
pub fn sys_arch_prctl(code: u64, addr: u64) -> u64 {
    const EPERM: u64 = (-1i64) as u64;
    let Some(t) = cur_mut() else { return EPERM };
    match code {
        0x1002 => {
            // ARCH_SET_FS — non-canonical or outside the user window
            // can't be a TLS block.
            if addr != 0 && !(elf::USER_VA_LO..elf::USER_VA_HI).contains(&addr) {
                return EPERM;
            }
            t.fs_base = addr;
            // SAFETY: MSR write of the running task's own FS base.
            unsafe { cpu::wrmsr(cpu::MSR_FS_BASE, addr) };
            0
        }
        0x1003 => {
            // ARCH_GET_FS
            if !range_ok_w(addr, 8) {
                return EFAULT;
            }
            // SAFETY: validated writable user range, current task.
            unsafe { (addr as *mut u64).write_unaligned(t.fs_base) };
            0
        }
        _ => EINVAL,
    }
}

/// uname(buf): Linux struct utsname — 6 fields ?-- 65 bytes.
pub fn sys_uname(buf: u64) -> u64 {
    if !range_ok_w(buf, 390) {
        return EFAULT;
    }
    let fields: [&[u8]; 6] = [
        b"Rustux",
        b"rustux",
        b"0.1.0",
        b"rustux kernel",
        b"x86_64",
        b"(none)",
    ];
    for (i, f) in fields.iter().enumerate() {
        // SAFETY: buf validated writable for 390 bytes; each field
        // starts zeroed at its 65-byte slot.
        unsafe {
            core::ptr::write_bytes((buf + i as u64 * 65) as *mut u8, 0, 65);
            core::ptr::copy_nonoverlapping(
                f.as_ptr(),
                (buf + i as u64 * 65) as *mut u8,
                f.len().min(64),
            );
        }
    }
    0
}

/// getrandom(buf, len, flags): ChaCha20 bytes into a validated user
/// range — capped per call like the copy paths.
pub fn sys_getrandom(buf: u64, len: u64, _flags: u64) -> u64 {
    if len > 4096 {
        return EINVAL;
    }
    if len != 0 && !range_ok_w(buf, len) {
        return EFAULT;
    }
    let mut i = 0u64;
    while i < len {
        let v = crate::rand::next_u64().to_le_bytes();
        let n = ((len - i) as usize).min(8);
        // SAFETY: buf validated writable for len bytes.
        unsafe {
            core::ptr::copy_nonoverlapping(
                v.as_ptr(),
                (buf + i) as *mut u8,
                n,
            )
        };
        i += n as u64;
    }
    len
}

/// The console's termios — 36-byte kernel ABI (4 u32 c_*flag, c_line,
/// c_cc[19]). Cooked-mode defaults like a fresh Linux tty: ICRNL|IXON,
/// OPOST|ONLCR, B38400|CS8|CREAD|HUPCL, ISIG|ICANON|ECHO|ECHOE|ECHOK|
/// ECHOCTL|ECHOKE|IEXTEN, then VINTR/VERASE/VMIN&co in c_cc order.
static mut TERMIOS: [u8; 36] = [
    0x00, 0x05, 0x00, 0x00, // c_iflag = ICRNL|IXON
    0x03, 0x00, 0x00, 0x00, // c_oflag = OPOST|ONLCR
    0xbf, 0x04, 0x00, 0x00, // c_cflag = B38400|CS8|CREAD|HUPCL
    0x3b, 0x8a, 0x00, 0x00, // c_lflag = ISIG|ICANON|ECHO|...
    0,                      // c_line  = N_TTY
    3, 0x1c, 0x7f, 0x15, 4, 0, 1, 0, 0x11, 0x13, 0x1a, 0,
    0x12, 0x0f, 0x17, 0x16, 0, 0, 0,  // c_cc[19]
];

/// The console's owning session and its foreground process group —
/// Linux's tty->session / tty->pgrp pair. Spawned tasks all start
/// in session 1; setsid leaves it (losing the ctty), tcsetpgrp
/// moves the foreground. FG_PGID 0 = unset (console behaves like a
/// session leader's own group — no job-control gates apply).
static mut CONSOLE_SID: u64 = 1;
static mut FG_PGID: u64 = 0;

// --- tty input side: scancode -> ldisc -> read() ------------------
/// Canonical edit buffer (the line being typed) and the completed-
/// byte queue reads drain. Linux splits these the same way: in
/// ICANON mode nothing is readable until a newline or VEOF submits.
const STDIN_LINE: usize = 256;
const STDIN_READY: usize = 4096;
static mut LINEBUF: [u8; STDIN_LINE] = [0; STDIN_LINE];
static mut LINE_LEN: usize = 0;
static mut READY: [u8; STDIN_READY] = [0; STDIN_READY];
static mut RD_LEN: usize = 0;
/// VEOF (^D) on an empty line — one-shot end-of-file for the next
/// read, which is exactly Linux's empty-flush semantics.
static mut STDIN_EOF: bool = false;

/// c_lflag as a u32 — the ldisc's view of termios.
fn t_lflag() -> u32 {
    // SAFETY: TERMIOS[12..16] is c_lflag, little-endian on x86_64.
    unsafe {
        u32::from_le_bytes(
            *((core::ptr::addr_of!(TERMIOS) as *const u8).add(12) as *const [u8; 4]),
        )
    }
}

/// c_iflag as a u32 — ICRNL lives here (0x100) for the serial input
/// path: a terminal's Enter is CR, mapped to NL when ICRNL is set.
fn t_iflag() -> u32 {
    // SAFETY: TERMIOS[0..4] is c_iflag, little-endian on x86_64.
    unsafe {
        u32::from_le_bytes(
            *((core::ptr::addr_of!(TERMIOS) as *const u8) as *const [u8; 4]),
        )
    }
}

/// A c_cc byte by index — VINTR 0, VERASE 2, VKILL 3, VEOF 4...
fn t_cc(i: usize) -> u8 {
    // SAFETY: c_cc starts at byte 17 in the 36-byte termios ABI.
    unsafe { *(core::ptr::addr_of!(TERMIOS) as *const u8).add(17 + i) }
}

/// Echo one byte through the printk ring — IRQ-safe (irq_save inside)
/// and identical to how user console writes reach the screen.
fn stdin_echo(b: u8) {
    crate::log::printk(format_args!("{}", b as char));
}

/// Signal the foreground process group — Linux's ldisc sends ^C/
/// ^\/^Z to the WHOLE foreground pgrp. When no fg group is set we
/// fall back to the blocked-reader heuristic (single-group boot
/// tasks, before any shell takes job control).
fn stdin_sig(sig: u64) {
    let (fg, csid) = unsafe { (FG_PGID, CONSOLE_SID) };
    if fg != 0 {
        let tasks = unsafe { &*core::ptr::addr_of!(TASKS) };
        if tasks
            .iter()
            .flatten()
            .any(|t| t.pgid == fg && t.sid == csid)
        {
            kill_pgrp(fg, sig);
            return;
        }
        // Stale fg group (its last member died) — fall through to
        // the reader heuristic rather than drop the keystroke.
    }
    let tasks = unsafe { &*core::ptr::addr_of!(TASKS) };
    let Some(pid) = tasks.iter().flatten().find_map(|t| {
        (t.state == TaskState::Blocked && t.wait_on == WaitOn::Stdin)
            .then_some(t.pid)
    }) else {
        return;
    };
    let _ = kill(pid as i64, sig);
}

/// Submit the edit buffer to the ready queue — drops the excess if
/// the queue can't hold it (Linux discards on a full input queue).
fn stdin_flush_line() {
    let (n, cap) = unsafe { (LINE_LEN, RD_LEN) };
    let space = STDIN_READY - cap;
    let k = n.min(space);
    if k > 0 {
        // SAFETY: disjoint static buffers; k <= space by min.
        unsafe {
            core::ptr::copy_nonoverlapping(
                core::ptr::addr_of!(LINEBUF) as *const u8,
                (core::ptr::addr_of_mut!(READY) as *mut u8).add(cap),
                k,
            );
            RD_LEN = cap + k;
        }
    }
    unsafe { LINE_LEN = 0 };
    stdin_wake();
}

/// Feed one decoded key through the line discipline. Canonical mode
/// edits LINEBUF (VERASE/VKILL) and submits on '\n'/VEOF; raw mode
/// pushes straight to the ready queue. ISIG turns VINTR/VQUIT into
/// signals for the blocked reader — echo honors ECHO/ECHOE.
fn stdin_key(c: u8) {
    let lf = t_lflag();
    let (isig, icanon, echo, echoe) =
        (lf & 1 != 0, lf & 2 != 0, lf & 8 != 0, lf & 0x10 != 0);
    let intr = t_cc(0) != 0 && c == t_cc(0); // VINTR  ^C -> SIGINT
    let quit = t_cc(1) != 0 && c == t_cc(1); // VQUIT  ^\ -> SIGQUIT
    let susp = t_cc(10) != 0 && c == t_cc(10); // VSUSP ^Z -> SIGTSTP
    if isig && (intr || quit || susp) {
        // Linux flushes input unless NOFLSH; we always flush (the
        // flag is unset in the cooked defaults).
        unsafe {
            LINE_LEN = 0;
            RD_LEN = 0;
        };
        if echo {
            stdin_echo(b'^');
            stdin_echo(if intr { b'C' } else if quit { b'\\' } else { b'Z' });
            stdin_echo(b'\n');
        }
        stdin_sig(if intr { 2 } else if quit { 3 } else { 20 });
        return;
    }
    if !icanon {
        let cap = unsafe { RD_LEN };
        if cap < STDIN_READY {
            unsafe {
                *(core::ptr::addr_of_mut!(READY) as *mut u8).add(cap) = c;
                RD_LEN = cap + 1;
            }
            stdin_wake();
        }
        if echo {
            stdin_echo(c);
        }
        return;
    }
    if c == t_cc(2) && t_cc(2) != 0 {
        // VERASE
        if unsafe { LINE_LEN } > 0 {
            unsafe { LINE_LEN -= 1 };
            if echo && echoe {
                for b in [0x08u8, b' ', 0x08] {
                    stdin_echo(b);
                }
            }
        }
        return;
    }
    if c == t_cc(3) && t_cc(3) != 0 {
        // VKILL — discard the line being edited.
        unsafe { LINE_LEN = 0 };
        if echo {
            stdin_echo(b'\n');
        }
        return;
    }
    if c == t_cc(4) && t_cc(4) != 0 {
        // VEOF — submit without a newline; empty line is EOF.
        if unsafe { LINE_LEN } == 0 {
            unsafe { STDIN_EOF = true };
            stdin_wake();
        } else {
            stdin_flush_line();
        }
        return;
    }
    if unsafe { LINE_LEN } < STDIN_LINE {
        unsafe {
            *(core::ptr::addr_of_mut!(LINEBUF) as *mut u8).add(LINE_LEN) = c;
            LINE_LEN += 1;
        }
    }
    if echo {
        stdin_echo(c);
    }
    if c == b'\n' {
        stdin_flush_line();
    }
}

/// Bytes a reader can take right now — completed queue plus the
/// EOF flag (poll sees it readable like Linux at tty EOF).
fn stdin_ready() -> usize {
    if unsafe { STDIN_EOF } {
        unsafe { RD_LEN.max(1) }
    } else {
        unsafe { RD_LEN }
    }
}

/// Consume up to `len` ready bytes into `dst` — kernel-side copy for
/// both the direct path and the sleeper's translate-write path.
/// Canonical reads stop at the first newline like Linux (one line
/// per read); raw reads take whatever waits. Returns the count, or
/// usize::MAX for "would block".
fn stdin_take(len: usize) -> usize {
    let avail = unsafe { RD_LEN };
    if avail == 0 {
        return if unsafe { STDIN_EOF } {
            unsafe { STDIN_EOF = false };
            0
        } else {
            usize::MAX
        };
    }
    let mut n = len.min(avail);
    if t_lflag() & 2 != 0 {
        // ICANON: at most one line — find the first '\n' inside n.
        let mut i = 0;
        while i < n {
            if unsafe { *(core::ptr::addr_of!(READY) as *const u8).add(i) } == b'\n' {
                n = i + 1;
                break;
            }
            i += 1;
        }
    }
    n
}

/// Move `n` consumed bytes out of the ready queue.
fn stdin_consume(n: usize) {
    let cap = unsafe { RD_LEN };
    if n >= cap {
        unsafe { RD_LEN = 0 };
        return;
    }
    // SAFETY: n < cap; memmove inside the owned queue.
    unsafe {
        core::ptr::copy(
            (core::ptr::addr_of!(READY) as *const u8).add(n),
            core::ptr::addr_of_mut!(READY) as *mut u8,
            cap - n,
        );
        RD_LEN = cap - n;
    }
}

/// The waiter side: a blocked Stdin reader gets bytes copied through
/// ITS page tables (same discipline as pipe wakes) and the count in
/// rax; the EOF flag wakes it with 0.
fn stdin_wake() {
    let tasks = unsafe { &mut *core::ptr::addr_of_mut!(TASKS) };
    for s in tasks.iter_mut() {
        let Some(t) = s.as_mut() else { continue };
        if t.state != TaskState::Blocked || t.wait_on != WaitOn::Stdin {
            continue;
        }
        let n = stdin_take(t.wait_len as usize);
        if n == usize::MAX {
            continue; // still nothing — keep sleeping
        }
        let mut done = 0usize;
        while done < n {
            let b = unsafe { *(core::ptr::addr_of!(READY) as *const u8).add(done) };
            match translate(t.pml4, t.wait_ptr + done as u64) {
                // SAFETY: pa is a present user frame in t's tables.
                Some(pa) => unsafe { (pa as *mut u8).write(b) },
                None => break,
            }
            done += 1;
        }
        stdin_consume(done);
        t.ctx.rax = if done == 0 && n > 0 {
            (-14i64) as u64 // EFAULT: buffer vanished mid-sleep
        } else {
            done as u64 // 0 for the EOF wake, n otherwise
        };
        t.wait_on = WaitOn::None;
        t.state = TaskState::Runnable;
    }
}

/// Pump decoded keys into the ldisc — called from the timer tick
/// (IRQ-safe: printk and kill both are) so typing echoes live, and
/// lazily from read/poll so a stale queue never fools a syscall.
/// Bounded by the 64-entry scancode ring.
pub fn stdin_pump() {
    let mut fed = false;
    while let Some(c) = crate::kbd::poll() {
        stdin_key(c as u8);
        fed = true;
    }
    // Serial-console input: `-serial stdio` lands host keystrokes in
    // the UART RX FIFO — drain it through the same ldisc as the PS/2
    // path, CR->NL per ICRNL like a real tty. Bounded: FIFO drain.
    let icrnl = t_iflag() & 0x100 != 0;
    let mut u = unsafe { crate::uart::Uart16550::new(crate::uart::COM1) };
    let mut drained = 0u32;
    while let Some(b) = u.get_byte() {
        stdin_key(if b == b'\r' && icrnl { b'\n' } else { b });
        fed = true;
        drained += 1;
        if drained == 64 {
            break;
        }
    }
    // Any input-state change may satisfy a poll(0) waiter the way a
    // pipe change does — one re-scan per pump, not per key.
    if fed {
        wake_pollers();
    }
}

/// ioctl(fd, req, arg): the console pair is our one tty — Stdin and
/// Console OFDs answer the termios/winsize/pgrp family; FIONREAD
/// reports bytes available per kind on any fd. glibc's isatty() is
/// just "does TCGETS succeed", so the tty gate on Stdin|Console is
/// the whole answer. Unknown requests are ENOTTY like a device that
/// doesn't speak them.
pub fn sys_ioctl(fd: u64, req: u64, arg: u64) -> u64 {
    const ENOTTY_: u64 = (-25i64) as u64;
    const TCGETS: u64 = 0x5401;
    const TCSETS: u64 = 0x5402;
    const TCSETSW: u64 = 0x5403;
    const TCSETSF: u64 = 0x5404;
    const TIOCGWINSZ: u64 = 0x5413;
    const TIOCSWINSZ: u64 = 0x5414;
    const TIOCGPGRP: u64 = 0x540f;
    const TIOCSPGRP: u64 = 0x5410;
    const FIONREAD: u64 = 0x541b;
    const FIONBIO: u64 = 0x5421;
    let Some(t) = cur_mut() else { return EBADF };
    let Some(o) = ofd(t, fd) else { return EBADF };
    let tty = matches!(o.kind, FdKind::Stdin | FdKind::Console)
        || matches!(&o.kind, FdKind::Dev(i)
            if vfile(*i).is_some_and(|v| v.rdev >> 8 == 5));
    match req {
        TCGETS => {
            if !tty {
                return ENOTTY_;
            }
            if !range_ok_w(arg, 36) {
                return EFAULT;
            }
            // SAFETY: arg is a validated 36-byte user window; TERMIOS
            // is a fixed 36-byte source.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    core::ptr::addr_of!(TERMIOS) as *const u8,
                    arg as *mut u8,
                    36,
                )
            };
            0
        }
        TCSETS | TCSETSW | TCSETSF => {
            if !tty {
                return ENOTTY_;
            }
            if !range_ok(arg, 36) {
                return EFAULT;
            }
            // SAFETY: arg validated readable for 36 bytes; the flags
            // live in one shared cell — terminal state is per-tty,
            // not per-fd, like Linux.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    arg as *const u8,
                    core::ptr::addr_of_mut!(TERMIOS) as *mut u8,
                    36,
                )
            };
            0
        }
        TIOCGWINSZ => {
            if !tty {
                return ENOTTY_;
            }
            if !range_ok_w(arg, 8) {
                return EFAULT;
            }
            let (c, r) = crate::fbcon::tty_dims();
            let (c, r) = if c == 0 { (80u16, 25u16) } else { (c, r) };
            // SAFETY: arg is a validated 8-byte user window — the
            // winsize struct is {ws_row, ws_col, ws_xpixel, ws_ypixel}.
            unsafe {
                (arg as *mut u16).write_unaligned(r);
                ((arg + 2) as *mut u16).write_unaligned(c);
                ((arg + 4) as *mut u16).write_unaligned(0);
                ((arg + 6) as *mut u16).write_unaligned(0);
            }
            0
        }
        TIOCSWINSZ => {
            if !tty {
                return ENOTTY_;
            }
            if !range_ok(arg, 8) {
                return EFAULT;
            }
            0 // the GOP grid can't change size — accepted, ignored
        }
        TIOCGPGRP => {
            if !tty {
                return ENOTTY_;
            }
            // Linux's rule: the fd must be OUR controlling tty —
            // a task outside the console's session gets ENOTTY.
            if t.sid != unsafe { CONSOLE_SID } {
                return ENOTTY_;
            }
            if !range_ok_w(arg, 4) {
                return EFAULT;
            }
            // No fg set yet = the caller's own group (a session
            // leader's console always fronts its own pgrp).
            let fg = unsafe { FG_PGID };
            let g = if fg == 0 { t.pgid } else { fg };
            // SAFETY: arg validated writable for 4 bytes.
            unsafe { (arg as *mut u32).write_unaligned(g as u32) };
            0
        }
        TIOCSPGRP => {
            if !tty {
                return ENOTTY_;
            }
            if t.sid != unsafe { CONSOLE_SID } {
                return ENOTTY_;
            }
            // Linux's tiocspgrp checks tty_check_change(SIGTTOU)
            // before touching arg: a background pgrp asking to move
            // the foreground is stopped (or EIO when orphaned),
            // never silently allowed.
            let gate = tty_spgrp_gate();
            if gate != 0 {
                return gate;
            }
            if !range_ok(arg, 4) {
                return EFAULT;
            }
            // SAFETY: arg validated readable for 4 bytes.
            let g = unsafe { (arg as *const u32).read_unaligned() } as u64;
            // The new foreground must be a group inside OUR session
            // (Linux: EINVAL not-our-tty, EPERM wrong-session group).
            let tasks = unsafe { &*core::ptr::addr_of!(TASKS) };
            let ok = tasks
                .iter()
                .flatten()
                .any(|x| x.pgid == g && x.sid == t.sid);
            if !ok {
                return (-1i64) as u64; // EPERM
            }
            unsafe { FG_PGID = g };
            0
        }
        FIONREAD => {
            if !range_ok_w(arg, 4) {
                return EFAULT;
            }
            let avail = match &o.kind {
                // TTY input queue depth — Linux counts the whole
                // queue here (canonical or not). The write half has
                // no input side: honest 0 like a tty asked that way.
                FdKind::Stdin => (unsafe { RD_LEN }) as u64,
                FdKind::Dev(i) => {
                    if vfile(*i).is_some_and(|v| v.rdev >> 8 == 5) {
                        (unsafe { RD_LEN }) as u64
                    } else {
                        0
                    }
                }
                FdKind::Console => 0u64,
                FdKind::File(d) => d.len().saturating_sub(o.pos) as u64,
                FdKind::Proc { len, .. } => {
                    len.saturating_sub(o.pos) as u64
                }
                FdKind::Ram(i) => vfile(*i)
                    .map_or(0, |v| v.len.saturating_sub(o.pos))
                    as u64,
                FdKind::Pipe { id, write } => {
                    if *write {
                        return EINVAL; // write end has nothing to read
                    }
                    let pipes = unsafe { &*core::ptr::addr_of!(PIPES) };
                    pipes
                        .get(*id)
                        .and_then(|s| s.as_ref())
                        .map_or(0, |p| (p.tail - p.head) as u64)
                }
                FdKind::Tcp(i) => {
                    let socks = unsafe { &*core::ptr::addr_of!(TCPSOCKS) };
                    socks
                        .get(*i)
                        .and_then(|s| s.as_ref())
                        .map_or(0, |k| k.rxl as u64)
                }
                // FIONREAD on a datagram socket is the next pending
                // datagram's size (Linux semantics), 0 when empty.
                FdKind::Udp(i) => {
                    let socks = unsafe { &*core::ptr::addr_of!(UDPSOCKS) };
                    socks
                        .get(*i)
                        .and_then(|s| s.as_ref())
                        .map_or(0, |k| {
                            k.q.as_ref().map_or(0, |d| d.len as u64)
                        })
                }
                FdKind::Dir(_) => return EINVAL,
                // An epoll fd has no readable stream — same EINVAL
                // Linux gives read-side ioctls on it.
                FdKind::Epoll(_) => return EINVAL,
                // FIONREAD on eventfd/timerfd is sizeof(u64) once
                // they're readable, 0 before (Linux's answer).
                FdKind::Eventfd(i) => {
                    let evs = unsafe { &*core::ptr::addr_of!(EVENTFDS) };
                    evs.get(*i)
                        .and_then(|s| s.as_ref())
                        .map_or(0, |e| if e.count > 0 { 8 } else { 0 })
                }
                FdKind::Timerfd(i) => {
                    let tfs = unsafe { &*core::ptr::addr_of!(TIMERFDS) };
                    let now = crate::apic::TICKS
                        .load(core::sync::atomic::Ordering::Relaxed);
                    tfs.get(*i)
                        .and_then(|s| s.as_ref())
                        .map_or(0, |tf| {
                            if tf.expirations > 0
                                || (tf.armed && tf.deadline <= now)
                            {
                                8
                            } else {
                                0
                            }
                        })
                }
                // signalfd: 128 when a masked signal pends on the
                // reader, else 0 (one record at a time).
                FdKind::Signalfd(i) => {
                    let sfs = unsafe { &*core::ptr::addr_of!(SIGNALFDS) };
                    let pend = cur_mut().map_or(0, |t| t.pending);
                    sfs.get(*i)
                        .and_then(|s| s.as_ref())
                        .map_or(0, |s| {
                            if pend & s.mask != 0 { 128 } else { 0 }
                        })
                }
                // inotify: Linux sums every queued record's size
                // (16 + padded name), plus 16 for a pending
                // overflow record.
                FdKind::Inotify(i) => {
                    let ins = unsafe { &*core::ptr::addr_of!(INOTIFY) };
                    ins.get(*i)
                        .and_then(|s| s.as_ref())
                        .map_or(0, |s| {
                            let mut n = 0u64;
                            for e in s.q.iter().flatten() {
                                n += if e.nlen == 0 {
                                    16
                                } else {
                                    16 + ((e.nlen as u64 + 1 + 15) & !15)
                                };
                            }
                            if s.overflow {
                                n += 16;
                            }
                            n
                        })
                }
            };
            // SAFETY: arg validated writable for 4 bytes.
            unsafe {
                (arg as *mut u32)
                    .write_unaligned(avail.min(u32::MAX as u64) as u32)
            };
            0
        }
        // No nonblocking mode exists to toggle — EINVAL, not a
        // silently-dropped flag a caller would trust.
        FIONBIO => EINVAL,
        _ => ENOTTY_,
    }
}

/// gettid: no threads — the thread id is the process id.
pub fn sys_gettid() -> u64 {
    cur_mut().map(|t| t.pid).unwrap_or(0)
}

/// clone(flags, stack, ptid, ctid, tls): the fork-shaped subset plus
/// CLONE_VM shared-address threads. An exit-signal of SIGCHLD (or 0),
/// the child-TID writes glibc asks for (PARENT_SETTID -> *ptid in our
/// space, CHILD_SETTID -> *ctid through the child's pml4 — shared or
/// copied), and CHILD_CLEARTID honored-as-noop like a task that dies
/// with no futex address. CLONE_VM needs a caller stack (running a
/// thread on its parent's rsp is unbootable); CLONE_SETTLS lands the
/// child's fs_base. CLONE_FILES shares the fd table in either mode.
/// SIGHAND/THREAD combos honestly ENOSYS.
/// glibc's fork() lands here, not on nr 57.
pub fn sys_clone(
    ctx: &mut UCtx,
    flags: u64,
    stack: u64,
    ptid: u64,
    ctid: u64,
    tls: u64,
) -> u64 {
    const ENOSYS_: u64 = (-38i64) as u64;
    const CLONE_VM: u64 = 0x0000_0100;
    const CLONE_FS: u64 = 0x0000_0200;
    const CLONE_FILES: u64 = 0x0000_0400;
    const CLONE_SIGHAND: u64 = 0x0000_0800;
    const CLONE_THREAD: u64 = 0x0001_0000;
    const CLONE_SYSVSEM: u64 = 0x0004_0000;
    const CLONE_SETTLS: u64 = 0x0008_0000;
    const PARENT_SETTID: u64 = 0x0010_0000;
    const CHILD_CLEARTID: u64 = 0x0020_0000;
    const CHILD_SETTID: u64 = 0x0100_0000;
    const SIGMASK: u64 = 0xff;
    const KNOWN: u64 = SIGMASK
        | CLONE_FILES
        | CLONE_SIGHAND
        | CLONE_THREAD
        | CLONE_VM
        | CLONE_FS
        | CLONE_SYSVSEM
        | CLONE_SETTLS
        | PARENT_SETTID
        | CHILD_CLEARTID
        | CHILD_SETTID;
    if flags & !KNOWN != 0 {
        return ENOSYS_;
    }
    // A new stack only means something for a shared-mm thread.
    if stack != 0 && flags & CLONE_VM == 0 {
        return ENOSYS_;
    }
    // CLONE_VM without a stack would run the child on its parent's
    // live user rsp — unbootable, so Linux callers always pass one.
    if stack == 0 && flags & CLONE_VM != 0 {
        return EINVAL;
    }
    // The exit signal must be SIGCHLD or none — wait4 keys on it.
    if flags & SIGMASK != 0 && flags & SIGMASK != 17 {
        return ENOSYS_;
    }
    if ptid != 0 && flags & PARENT_SETTID != 0 && !range_ok_w(ptid, 4) {
        return EFAULT;
    }
    // Linux pairs: shared dispositions need a shared mm, and a
    // thread-group member must share dispositions (EINVALs, not
    // ENOSYS — the combo is invalid, not unimplemented).
    if flags & CLONE_SIGHAND != 0 && flags & CLONE_VM == 0 {
        return EINVAL;
    }
    if flags & CLONE_THREAD != 0 && flags & CLONE_SIGHAND == 0 {
        return EINVAL;
    }
    let files = flags & CLONE_FILES != 0;
    let fs = flags & CLONE_FS != 0;
    // CLONE_SYSVSEM shares the sem-undo list — no SysV semaphore
    // syscalls exist, so sharing the empty list is a true no-op.
    let child = if flags & CLONE_VM != 0 {
        clone_vm(
            ctx,
            stack,
            tls,
            flags & CLONE_SETTLS != 0,
            files,
            flags & CLONE_SIGHAND != 0,
            flags & CLONE_THREAD != 0,
            fs,
        )
    } else {
        fork(ctx, files, fs)
    };
    if (child as i64) < 0 {
        return child;
    }
    if ptid != 0 && flags & PARENT_SETTID != 0 {
        // SAFETY: ptid validated writable above.
        unsafe { (ptid as *mut u32).write_unaligned(child as u32) };
    }
    let needs_child_fix = (ctid != 0
        && flags & (CHILD_SETTID | CHILD_CLEARTID) != 0)
        || (flags & CLONE_SETTLS != 0 && flags & CLONE_VM == 0);
    if needs_child_fix {
        let tasks = unsafe { &mut *core::ptr::addr_of_mut!(TASKS) };
        if let Some(c) = tasks.iter_mut().flatten().find(|t| t.pid == child) {
            if ctid != 0 && flags & CHILD_SETTID != 0 {
                // *ctid lives in the child's address space — write
                // through its page tables (shared or copied).
                write_task_bytes(c.pml4, ctid, &(child as u32).to_ne_bytes());
            }
            if ctid != 0 && flags & CHILD_CLEARTID != 0 {
                // Registered on the child: at exit the kernel zeroes
                // *ctid and futex-wakes it — pthread_join's wait.
                c.clear_ctid = ctid;
            }
            if flags & CLONE_SETTLS != 0 && flags & CLONE_VM == 0 {
                // SETTLS on a plain fork-shaped clone still lands —
                // the VM path sets fs_base at construction.
                c.fs_base = tls;
            }
        }
    }
    child
}

/// vfork(): clone_vm on the caller's own user rsp — the child shares
/// every byte of the parent's address space and runs until exec or
/// exit while the parent waits uninterruptibly (Linux's vfork_done
/// completion). Private fd/sighand/fs copies, matching Linux's
/// clone(CLONE_VM|CLONE_VFORK|SIGCHLD,0) flag semantics. The same
/// stack is safe: the parent is suspended, so the child pushing
/// below its rsp cannot corrupt anything the parent still needs.
pub fn sys_vfork(ctx: &mut UCtx) -> u64 {
    let child = clone_vm(ctx, ctx.rsp, 0, false, false, false, false, false);
    if (child as i64) < 0 {
        return child;
    }
    let tasks = unsafe { &mut *core::ptr::addr_of_mut!(TASKS) };
    let cur = unsafe { *core::ptr::addr_of!(CUR_I) };
    if let Some(t) = tasks.get_mut(cur).and_then(|s| s.as_mut()) {
        // The saved ctx already carries the child pid in rax (the
        // clone_vm return path) — the exec/exit waker resumes us.
        t.wait_on = WaitOn::Vfork(child);
        t.ctx = *ctx;
        t.ctx.rax = child;
        t.state = TaskState::Blocked;
        block_switch()
    }
    child
}

/// A vfork parent sleeps in WaitOn::Vfork(child_pid) until the child
/// execs (mm swap in exec()) or exits (task_exit_inner's wake match
/// covers Vfork too). Resuming it returns the child's pid — exactly
/// vfork's own success value.
fn wake_vfork_parent_of(child_pid: u64) {
    let tasks = unsafe { &mut *core::ptr::addr_of_mut!(TASKS) };
    for s in tasks.iter_mut() {
        let Some(p) = s else { continue };
        if p.state == TaskState::Blocked && p.wait_on == WaitOn::Vfork(child_pid) {
            p.ctx.rax = child_pid;
            p.wait_on = WaitOn::None;
            p.state = TaskState::Runnable;
        }
    }
}

/// tgkill(tgid, tid, sig): no threads — tgid == tid == pid, so this
/// is kill() with an extra ABI arg. glibc's abort() lands here.
pub fn sys_tgkill(tgid: u64, tid: u64, sig: u64) -> u64 {
    // With threads, tid names the target task; a bare tgid hits the
    // leader (tgid == leader pid), matching Linux tgkill semantics.
    kill(if tid != 0 { tid } else { tgid } as i64, sig)
}

/// Shared rt_sigqueueinfo/rt_tgsigqueueinfo body: pend `sig` on the
/// target with the user's si_code + si_value. Linux lets userspace
/// send only negative si_codes (except SI_TKILL, which would fake a
/// tkill's provenance) — anything else is EPERM, so a caller can't
/// impersonate kernel-sourced or other-task-sourced siginfo.
fn sigqueue_one(pid: i64, tgid: u64, sig: u64, uinfo: u64) -> u64 {
    const ESRCH: u64 = (-3i64) as u64;
    const EPERM_: u64 = (-1i64) as u64;
    if sig == 0 || sig > 31 {
        return EINVAL;
    }
    if !range_ok(uinfo, 128) {
        return EFAULT;
    }
    // SAFETY: validated readable user range; the fields we need are
    // si_code@8 and si_value@24.
    let (code, val) = unsafe {
        (
            (uinfo as *const i32).add(2).read_unaligned(),
            ((uinfo + 24) as *const u64).read_unaligned(),
        )
    };
    if code >= 0 || code == SI_TKILL {
        return EPERM_;
    }
    let sender = cur_mut().map(|t| t.pid).unwrap_or(0) as u32;
    let tasks = unsafe { &mut *core::ptr::addr_of_mut!(TASKS) };
    let hits = |t: &Task| {
        t.pid == pid as u64 && (tgid == u64::MAX || t.tgid == tgid)
    };
    let mut conts = [(0u64, 0u64, 0u64); MAX_TASKS];
    let mut ncont = 0usize;
    let mut found = false;
    for s in tasks.iter_mut() {
        let Some(t) = s else { continue };
        if hits(t) {
            found = true;
            if let Some(c) = pend_one(
                t,
                sig,
                SigSrc {
                    code,
                    pid: sender,
                    uid: 0,
                    aux: val,
                },
            ) {
                conts[ncont] = c;
                ncont += 1;
            }
        }
    }
    if !found {
        return ESRCH;
    }
    for c in conts.iter().take(ncont) {
        child_change(c.0, c.1, c.2, 0xffff, WCONTINUED);
    }
    0
}

/// rt_sigqueueinfo(pid, sig, uinfo): glibc's sigqueue() — a queued
/// signal carrying a siginfo_t whose si_value rides to the handler.
pub fn rt_sigqueueinfo(pid: i64, sig: u64, uinfo: u64) -> u64 {
    sigqueue_one(pid, u64::MAX, sig, uinfo)
}

/// rt_tgsigqueueinfo(tgid, pid, sig, uinfo): the same but addressed
/// to a thread inside a group — target must match both ids.
pub fn rt_tgsigqueueinfo(tgid: u64, pid: i64, sig: u64, uinfo: u64) -> u64 {
    sigqueue_one(pid, tgid, sig, uinfo)
}

/// rt_sigprocmask(how, set, oldset, sigsetsize): the per-task signal
/// mask. SIG_BLOCK=0 / SIG_UNBLOCK=1 / SIG_SETMASK=2; `how` is only
/// validated when set is non-NULL, matching kernel behavior. We
/// track 31 signals, so the u64 set is truncated — high bits are
/// harmless. A masked signal stays pending for later delivery; the
/// next syscall/schedule boundary runs it through maybe_deliver.
pub fn sys_rt_sigprocmask(how: u64, set: u64, old: u64, sigsetsize: u64) -> u64 {
    if sigsetsize != 8 {
        return EINVAL;
    }
    let Some(t) = cur_mut() else { return ENOENT };
    if old != 0 {
        if !range_ok_w(old, 8) {
            return EFAULT;
        }
        // SAFETY: old validated writable for 8 bytes.
        unsafe { (old as *mut u64).write_unaligned(t.sigmask as u64) };
    }
    if set != 0 {
        if !range_ok(set, 8) {
            return EFAULT;
        }
        // SAFETY: set validated readable for 8 bytes.
        let m = unsafe { (set as *const u64).read_unaligned() } as u32;
        t.sigmask = match how {
            0 => t.sigmask | m,
            1 => t.sigmask & !m,
            2 => m,
            _ => return EINVAL,
        };
    }
    0
}

/// getcwd(buf, len): "/" + the shared cwd bytes + NUL; ERANGE
/// when the caller's buffer can't hold it — Linux semantics.
pub fn sys_getcwd(buf: u64, len: u64) -> u64 {
    const ERANGE_: u64 = (-34i64) as u64;
    let Some(t) = cur_mut() else { return EBADF };
    let f = fst(t);
    let n = f.cwdlen as usize;
    if len < n as u64 + 2 {
        return ERANGE_;
    }
    if !range_ok_w(buf, n as u64 + 2) {
        return EFAULT;
    }
    // SAFETY: buf validated writable for n+2 bytes.
    unsafe {
        (buf as *mut u8).write(b'/');
        core::ptr::copy_nonoverlapping(
            f.cwd.as_ptr(),
            (buf + 1) as *mut u8,
            n,
        );
        ((buf + 1 + n as u64) as *mut u8).write(0);
    }
    n as u64 + 2
}

/// clock_getres(clk, res): the APIC ticks at 100Hz — 10ms.
pub fn sys_clock_getres(_clk: u64, res: u64) -> u64 {
    if res == 0 {
        return 0;
    }
    if !range_ok_w(res, 16) {
        return EFAULT;
    }
    // SAFETY: res validated writable for 16 bytes.
    unsafe {
        (res as *mut u64).write_unaligned(0);
        (res as *mut u64).add(1).write_unaligned(10_000_000);
    }
    0
}

/// sched_yield(): ctx-save then switch to another runnable task if
/// one exists — self just returns 0 when it wins the pick again.
pub fn sys_sched_yield(ctx: &mut UCtx) -> u64 {
    ctx.rax = 0;
    let Some(t) = cur_mut() else { return 0 };
    t.ctx = *ctx;
    let cur = unsafe { *core::ptr::addr_of!(CUR_I) };
    if let Some(n) = pick_ready() {
        if n != cur {
            switch_to(n)
        }
    }
    0
}

/// rseq(rseq, rseq_len, flags, sig): restartable-sequences
/// registration — glibc calls this once at startup and a 0 return
/// makes it engage its rseq fast paths. Single-CPU: cpu_id is
/// always 0, so the kernel only writes the two leading cpu_id
/// fields once (userspace maintains rseq_cs itself). Per-task:
/// not inherited at fork, implicitly dropped at exec.
/// EINVAL on short len/unaligned area/unknown flags/bad sig,
/// EBUSY on double registration, EINVAL on mismatched unregister.
pub fn sys_rseq(uaddr: u64, len: u64, flags: u64, sig: u64) -> u64 {
    const EINVAL_: u64 = (-22i64) as u64;
    const EBUSY_: u64 = (-16i64) as u64;
    const EFAULT_: u64 = (-14i64) as u64;
    const RSEQ_SIG: u64 = 0x53053053;
    const UNREG: u64 = 1;
    let Some(t) = cur_mut() else { return EINVAL_ };
    if len < 32 || uaddr & 31 != 0 || flags & !UNREG != 0 || sig != RSEQ_SIG {
        return EINVAL_;
    }
    if flags & UNREG != 0 {
        if t.rseq_va == 0 || t.rseq_va != uaddr {
            return EINVAL_;
        }
        t.rseq_va = 0;
        return 0;
    }
    if t.rseq_va != 0 {
        return EBUSY_;
    }
    if !range_ok_w(uaddr, 8) {
        return EFAULT_;
    }
    // cpu_id_start then cpu_id — Linux's write order; both stay 0
    // on a single CPU (no migration events ever occur).
    unsafe {
        (uaddr as *mut u32).write_unaligned(0);
        ((uaddr + 4) as *mut u32).write_unaligned(0);
    }
    t.rseq_va = uaddr;
    0
}

/// The (mode, size, ino) an OFD presents in stat — shared by
/// sys_fstat and newfstatat's /proc/<pid>/fd/N followed-link arm so
/// an fd link stats exactly like the fd itself.
fn ofd_stat_shape(kind: &FdKind) -> (u64, u64, u64) {
    match kind {
        FdKind::Stdin | FdKind::Console => (0o20644u64, 0u64, 0), // S_IFCHR
        FdKind::Dir(dp) => {
            let m = vdir_find(dp.bytes())
                .and_then(|i| unsafe {
                    (*core::ptr::addr_of!(VDIRS))[i]
                })
                .map_or(0o755u64, |d| d.mode as u64);
            (0o40000 | m, 0, 0)
        }
        FdKind::File(d) => {
            let ino = (unsafe { *core::ptr::addr_of!(INITRD) })
                .and_then(|arc| {
                    crate::cpio::entries(arc).position(|(_, m)| {
                        m.as_ptr() == d.as_ptr() && m.len() == d.len()
                    })
                })
                .map_or(0, |i| i as u64 + 1);
            (0o100644, d.len() as u64, ino)
        }
        FdKind::Ram(i) => {
            let arc_n = (unsafe { *core::ptr::addr_of!(INITRD) })
                .map_or(0, |a| crate::cpio::entries(a).count());
            let vidx = unsafe { &*core::ptr::addr_of!(VFILES) }[..*i]
                .iter()
                .filter(|s| s.as_ref().is_some_and(|v| !v.unlinked))
                .count();
            let (mode, len) = vfile(*i).map_or((0o644u64, 0usize), |v| {
                (
                    (if v.is_link { 0o120000 } else { v.fmt as u64 })
                        | v.mode as u64,
                    v.len,
                )
            });
            (mode, len as u64, (arc_n + vidx) as u64 + 1)
        }
        FdKind::Dev(i) => {
            // A device node stats S_IFCHR|mode with a vfile-space
            // ino — the rdev slot is filled by sys_fstat's meta arm.
            let arc_n = (unsafe { *core::ptr::addr_of!(INITRD) })
                .map_or(0, |a| crate::cpio::entries(a).count());
            let vidx = unsafe { &*core::ptr::addr_of!(VFILES) }[..*i]
                .iter()
                .filter(|s| s.as_ref().is_some_and(|v| !v.unlinked))
                .count();
            let mode = vfile(*i)
                .map_or(0o20644u64, |v| 0o20000 | v.mode as u64);
            (mode, 0, (arc_n + vidx) as u64 + 1)
        }
        // proc files stat as read-only regulars; the rendered
        // length is the honest size of this snapshot.
        FdKind::Proc { buf, len } => {
            (0o100444, *len as u64, buf / 4096)
        }
        FdKind::Pipe { .. } => (0o10644, 0, 0), // S_IFIFO
        FdKind::Udp(_) | FdKind::Tcp(_) => (0o140777, 0, 0), // S_IFSOCK
        // anon_inodefs objects stat as a chrdev — Linux shows
        // S_IFCHR|0600 for epoll/eventfd/timerfd alike.
        FdKind::Epoll(_)
        | FdKind::Eventfd(_)
        | FdKind::Timerfd(_)
        | FdKind::Signalfd(_)
        | FdKind::Inotify(_) => (0o20600, 0, 0),
    }
}

/// fstat(fd, statbuf): same 144B stat as newfstatat, mode by OFD
/// kind — chr for console, fifo for pipes, sock for sockets,
/// reg/dir for archive entries.
pub fn sys_fstat(fd: u64, statbuf: u64) -> u64 {
    const STAT_LEN: u64 = 144;
    if !range_ok_w(statbuf, STAT_LEN) {
        return EFAULT;
    }
    let Some(t) = cur_mut() else { return EBADF };
    let Some(o) = ofd(t, fd) else { return EBADF };
    // ld.so dedupes opened shared objects by (st_dev, st_ino) — a
    // zero ino makes libc look "already mapped" (aliased to ld.so or
    // the main object) and version checks fail. Same idx+1 scheme
    // newfstatat uses so stat and fstat agree on one file.
    let (mode, size, ino) = ofd_stat_shape(&o.kind);
    let mut st = [0u64; 18];
    st[1] = ino;
    st[2] = 1;
    st[3] = mode;
    st[6] = size;
    st[7] = 4096;
    st[8] = size.div_ceil(512);
    // Stored inode metadata — only Ram inodes and explicit dirs
    // carry it; everything else reports zeros like Linux initramfs.
    match &o.kind {
        FdKind::Ram(i) => {
            if let Some(v) = vfile(*i) {
                stat_meta(
                    &mut st,
                    v.uid,
                    v.gid,
                    (v.atime, v.atime_ns),
                    (v.mtime, v.mtime_ns),
                    (v.ctime, v.ctime_ns),
                );
            }
        }
        FdKind::Dev(i) => {
            if let Some(v) = vfile(*i) {
                st[5] = v.rdev as u64; // st_rdev
                stat_meta(
                    &mut st,
                    v.uid,
                    v.gid,
                    (v.atime, v.atime_ns),
                    (v.mtime, v.mtime_ns),
                    (v.ctime, v.ctime_ns),
                );
            }
        }
        FdKind::Dir(dp) => {
            if let Some(i) = vdir_find(dp.bytes()) {
                let ds = unsafe { &*core::ptr::addr_of!(VDIRS) };
                if let Some(d) = ds[i].as_ref() {
                    stat_meta(
                        &mut st,
                        d.uid,
                        d.gid,
                        (d.atime, d.atime_ns),
                        (d.mtime, d.mtime_ns),
                        (d.ctime, d.ctime_ns),
                    );
                }
            }
        }
        _ => {}
    }
    // SAFETY: statbuf validated writable for 144 bytes.
    unsafe {
        core::ptr::copy_nonoverlapping(
            st.as_ptr() as *const u8,
            statbuf as *mut u8,
            STAT_LEN as usize,
        )
    };
    0
}

/// set_tid_address(ptr): we don't store the pointer (no clear-thread-
/// tid futex wake yet) — the return is the tid, which is our pid.
pub fn sys_set_tid_address() -> u64 {
    cur_mut().map(|t| t.pid).unwrap_or(0)
}

/// set_robust_list(head, len): record nothing — robust futex wake on
/// death needs futexes first. Linux EINVALs a wrong struct size.
pub fn sys_set_robust_list(_head: u64, len: u64) -> u64 {
    if len != 24 {
        return EINVAL;
    }
    0
}

/// prlimit64(pid, res, new, old): report RLIM_INFINITY for `old`;
/// `new` is accepted and ignored (bounded resources are enforced by
/// the allocator tables, not rlimit).
pub fn sys_prlimit64(_pid: u64, _res: u64, _new: u64, old: u64) -> u64 {
    if old != 0 {
        if !range_ok_w(old, 16) {
            return EFAULT;
        }
        // SAFETY: validated writable user range.
        unsafe {
            (old as *mut u64).write_unaligned(u64::MAX);
            (old as *mut u64).add(1).write_unaligned(u64::MAX);
        }
    }
    0
}

/// clock_gettime(clk, ts): CLOCK_REALTIME-family ids get the
/// CMOS-anchored wall clock; everything else rides the 100 Hz
/// monotonic tick (no per-process/thread cputime domains yet).
pub fn sys_clock_gettime(clk: u64, ts: u64) -> u64 {
    if !range_ok_w(ts, 16) {
        return EFAULT;
    }
    // 0=REALTIME, 5=REALTIME_COARSE, 8=REALTIME_ALARM; 1=MONOTONIC,
    // 4=MONOTONIC_RAW, 6=MONOTONIC_COARSE, 7=BOOTTIME all share TICKS.
    let (s, ns) = if matches!(clk, 0 | 5 | 8) {
        crate::rtc::wall_now()
    } else {
        let t = crate::apic::TICKS.load(core::sync::atomic::Ordering::Relaxed);
        (t / 100, (t % 100) * 10_000_000)
    };
    // SAFETY: ts validated writable for 16 bytes.
    unsafe {
        (ts as *mut u64).write_unaligned(s);
        (ts as *mut u64).add(1).write_unaligned(ns);
    }
    0
}

/// mkdir/mkdirat(dirfd, path, mode): create an explicit VDIRS dir —
/// mode is accepted and ignored (no per-file modes yet). EEXIST on
/// any existing name; the parent must already be a directory.
pub fn fs_mkdir(dfd: u64, path: &[u8], mode: u64) -> u64 {
    const EEXIST_: u64 = (-17i64) as u64;
    const ENOSPC_: u64 = (-28i64) as u64;
    const ENOTDIR_: u64 = (-20i64) as u64;
    const ENAMETOOLONG_: u64 = (-36i64) as u64;
    let (buf, n) = match canon_path(dfd, path) {
        Ok(x) => x,
        Err(e) => return e,
    };
    // Intermediates resolve — the dir to create inside may sit
    // behind a link. The final component stays literal: an existing
    // link there is EEXIST like Linux.
    let (rb, rn, _) = match resolve_links(&buf[..n], false) {
        Ok(x) => x,
        Err(e) => return e,
    };
    let p = &rb[..rn];
    if p.len() > 128 {
        return ENAMETOOLONG_;
    }
    if p.is_empty() || is_file(p) || dir_exists(p) {
        return EEXIST_;
    }
    if let Some(pi) = p.iter().rposition(|&c| c == b'/') {
        let par = &p[..pi];
        if !dir_exists(par) {
            return if is_file(par) { ENOTDIR_ } else { ENOENT };
        }
    }
    let ds = unsafe { &mut *core::ptr::addr_of_mut!(VDIRS) };
    let Some(i) = ds.iter().position(Option::is_none) else {
        return ENOSPC_;
    };
    let umask = cur_mut().map_or(0, |t| fst(t).umask);
    let (s, ns) = now();
    let mut d = VDir {
        path: [0; 128],
        nlen: p.len(),
        mode: (mode & 0o7777 & !(umask as u64)) as u16,
        uid: 0,
        gid: 0,
        atime: s,
        atime_ns: ns,
        mtime: s,
        mtime_ns: ns,
        ctime: s,
        ctime_ns: ns,
    };
    d.path[..p.len()].copy_from_slice(p);
    ds[i] = Some(d);
    ino_report(p, IN_CREATE | IN_ISDIR, 0);
    0
}

/// rmdir/unlinkat(AT_REMOVEDIR): remove an EMPTY explicit dir —
/// implicit dirs vanish with their last entry, so only VDIRS can
/// rmdir. ENOTEMPTY when anything still lives underneath.
pub fn fs_rmdir(dfd: u64, path: &[u8]) -> u64 {
    const ENOTDIR_: u64 = (-20i64) as u64;
    const ENOTEMPTY_: u64 = (-39i64) as u64;
    const EBUSY_: u64 = (-16i64) as u64;
    let (buf, n) = match canon_path(dfd, path) {
        Ok(x) => x,
        Err(e) => return e,
    };
    // Intermediates resolve; the final component stays literal —
    // rmdir on a link is ENOTDIR like Linux.
    let (rb, rn, _) = match resolve_links(&buf[..n], false) {
        Ok(x) => x,
        Err(e) => return e,
    };
    let p = &rb[..rn];
    if is_file(p) {
        return ENOTDIR_;
    }
    if p.is_empty() {
        return EBUSY_; // rmdir("/")
    }
    if !dir_exists(p) {
        return ENOENT;
    }
    let mut pre = [0u8; 256];
    pre[..p.len()].copy_from_slice(p);
    pre[p.len()] = b'/';
    let pre = &pre[..p.len() + 1];
    if let Some(arc) = unsafe { *core::ptr::addr_of!(INITRD) } {
        if crate::cpio::entries(arc).any(|(nm, _)| nm.starts_with(pre)) {
            return ENOTEMPTY_;
        }
    }
    if unsafe { &*core::ptr::addr_of!(VFILES) }.iter().flatten().any(|v| {
        !v.unlinked && v.name[..v.nlen].starts_with(pre)
    }) || unsafe { &*core::ptr::addr_of!(VDIRS) }.iter().flatten().any(|d| {
        d.path[..d.nlen].starts_with(pre)
    }) {
        return ENOTEMPTY_;
    }
    match vdir_find(p) {
        Some(i) => {
            vdir_remove(i);
            ino_report(p, IN_DELETE | IN_ISDIR, 0);
            ino_report_self_loss(p, IN_DELETE_SELF, 0);
            0
        }
        None => ENOTEMPTY_, // implicit dir still has children
    }
}

/// chdir(path): store the canonical dir in the shared fs table —
/// a CLONE_FS sibling's chdir moves the whole group, like Linux.
pub fn sys_chdir(path: &[u8]) -> u64 {
    const ENOTDIR_: u64 = (-20i64) as u64;
    let (buf, n) = match canon_path(u64::MAX, path) {
        Ok(x) => x,
        Err(e) => return e,
    };
    // chdir follows links all the way — cwd lands on the real dir.
    let (rb, rn, _) = match resolve_links(&buf[..n], true) {
        Ok(x) => x,
        Err(e) => return e,
    };
    if is_file(&rb[..rn]) {
        return ENOTDIR_;
    }
    if !dir_exists(&rb[..rn]) {
        return ENOENT;
    }
    if rn > 128 {
        return (-36i64) as u64; // ENAMETOOLONG: cwd field is 128
    }
    let Some(t) = cur_mut() else { return EBADF };
    let f = fst(t);
    f.cwd[..rn].copy_from_slice(&rb[..rn]);
    f.cwdlen = rn as u8;
    0
}

/// fchdir(fd): the fd must name a Dir OFD — its path becomes cwd.
pub fn sys_fchdir(fd: u64) -> u64 {
    const ENOTDIR_: u64 = (-20i64) as u64;
    let Some((pb, pn)) = fd_dir_path(fd) else {
        let Some(t) = cur_mut() else { return EBADF };
        return if ofd(t, fd).is_some() { ENOTDIR_ } else { EBADF };
    };
    if pn > 128 {
        return (-36i64) as u64;
    }
    let Some(t) = cur_mut() else { return EBADF };
    let f = fst(t);
    f.cwd[..pn].copy_from_slice(&pb[..pn]);
    f.cwdlen = pn as u8;
    0
}

/// time(tloc): wall-clock seconds — the CMOS RTC anchored at boot,
/// boot-relative when there is no clock. tloc mirrors the return
/// like Linux; a bad pointer is EFAULT.
pub fn sys_time(tloc: u64) -> u64 {
    let (s, _) = crate::rtc::wall_now();
    if tloc != 0 {
        if !range_ok_w(tloc, 8) {
            return EFAULT;
        }
        // SAFETY: tloc validated writable for 8 bytes.
        unsafe { (tloc as *mut u64).write_unaligned(s) };
    }
    s
}

/// umask(mask): set the creation mask, return the old one — the
/// full ABI, no stubbing needed since the field exists.
pub fn sys_umask(mask: u64) -> u64 {
    let Some(t) = cur_mut() else { return 0o022 };
    let f = fst(t);
    let old = f.umask as u64;
    f.umask = (mask & 0o777) as u16;
    old
}

/// sysinfo(buf): uptime + memory totals — real counters where we
/// have them, honest zeros elsewhere (loadavg always 0.0).
pub fn sys_sysinfo(buf: u64) -> u64 {
    if !range_ok_w(buf, 112) {
        return EFAULT;
    }
    let up = crate::apic::TICKS.load(core::sync::atomic::Ordering::Relaxed) / 100;
    let tasks = unsafe { &*core::ptr::addr_of!(TASKS) };
    let procs = tasks.iter().flatten().count() as u16;
    // Zero the whole struct first — callers multiply totalram by
    // mem_unit, so an uninitialized tail field becomes a garbage
    // multiplier (busybox free printed ~2^54 once).
    // SAFETY: buf validated writable for 112 bytes.
    unsafe {
        core::ptr::write_bytes(buf as *mut u8, 0, 112);
        (buf as *mut u64).write_unaligned(up); // uptime secs
        // loads[0..3] stay 0 — no load accounting, same as loadavg.
        (buf as *mut u64).add(4)
            .write_unaligned(kalloc::total_frames() * 4096); // totalram
        (buf as *mut u64).add(5)
            .write_unaligned(kalloc::free_frames() * 4096); // freeram
        (buf as *mut u16).add(40).write_unaligned(procs); // procs@80
        (buf as *mut u32).add(26).write_unaligned(1); // mem_unit@104
    }
    0
}

/// times(buf): per-task user/system tick accounting in {tms}.
/// Cooperative single-CPU: a task's utime is its runnable ticks —
/// tracked crudely as TICKS at syscall time (0 stime split, like a
/// kernel that never accounts system time).
pub fn sys_times(buf: u64) -> u64 {
    let t = crate::apic::TICKS.load(core::sync::atomic::Ordering::Relaxed);
    if buf != 0 {
        if !range_ok_w(buf, 32) {
            return EFAULT;
        }
        // SAFETY: buf validated writable for 4 longs.
        unsafe {
            (buf as *mut u64).write_unaligned(t);
            (buf as *mut u64).add(1).write_unaligned(0);
            (buf as *mut u64).add(2).write_unaligned(0);
            (buf as *mut u64).add(3).write_unaligned(0);
        }
    }
    t
}

/// getrusage(who, ru): RUSAGE_SELF -> utime/stime zeroed except the
/// real tick count in ru_utime; RUSAGE_CHILDREN -> zeros.
pub fn sys_getrusage(who: u64, ru: u64) -> u64 {
    // RUSAGE_SELF=0, RUSAGE_CHILDREN=-1, RUSAGE_THREAD=1 — anything
    // else is EINVAL on Linux, not a silent zero.
    let ticks = match who {
        0 | 1 => crate::apic::TICKS.load(core::sync::atomic::Ordering::Relaxed),
        u64::MAX => 0, // -1: CHILDREN — no accounting, honest zeros
        _ => return EINVAL,
    };
    if !range_ok_w(ru, 144) {
        return EFAULT;
    }
    // SAFETY: ru validated writable; zero the struct then fill the
    // two timeval pairs we can honestly report.
    unsafe {
        core::ptr::write_bytes(ru as *mut u8, 0, 144);
        (ru as *mut u64).write_unaligned(ticks / 100); // ru_utime sec
        (ru as *mut u64)
            .add(1)
            .write_unaligned((ticks % 100) * 10_000); // ru_utime usec
    }
    0
}

/// Shared statfs body: honest numbers. The root fs is memory-backed
/// — capacity IS the frame allocator (4KiB blocks, total/free frames)
/// and the inode count is the dynamic vfile table. /proc reports its
/// own superblock: PROC_SUPER_MAGIC, read-only, no storage. struct
/// statfs: type@0 bsize@8 blocks@16 bfree@24 bavail@32 files@40
/// ffree@48 fsid@56 namelen@64 frsize@72 flags@80 spare@88.
fn fill_statfs(buf: u64, proc: bool) {
    // SAFETY: buf validated writable for 120 bytes by the caller.
    unsafe {
        core::ptr::write_bytes(buf as *mut u8, 0, 120);
        let w = |i: usize, v: u64| (buf as *mut u64).add(i).write_unaligned(v);
        if proc {
            w(0, 0x9fa0); // PROC_SUPER_MAGIC
            w(1, 4096);
            w(8, 255);
            // ST_RDONLY | ST_NOSUID | ST_NODEV | ST_NOEXEC
            w(10, 0x1 | 0x2 | 0x4 | 0x8);
        } else {
            let vfree = (*core::ptr::addr_of!(VFILES))
                .iter()
                .filter(|s| s.is_none())
                .count() as u64;
            let free = kalloc::free_frames();
            w(0, 0x8584_58f6); // RAMFS_MAGIC
            w(1, 4096); // f_bsize
            w(2, kalloc::total_frames());
            w(3, free);
            w(4, free); // no root-reserved blocks
            w(5, MAX_VFILES as u64);
            w(6, vfree);
            w(8, 255);
            w(9, 4096); // f_frsize
        }
    }
}

/// statfs(path, buf): cpath is the canonical path — ENOENT on a
/// miss like Linux, proc paths report the procfs superblock.
pub fn statfs_path(cpath: &[u8], buf: u64) -> u64 {
    // statfs follows links — the mount underneath is what reports.
    let (rb, rn, _) = match resolve_links(cpath, true) {
        Ok(x) => x,
        Err(e) => return e,
    };
    let cpath = &rb[..rn];
    if !fs_exists(cpath) {
        return ENOENT;
    }
    if !range_ok_w(buf, 120) {
        return EFAULT;
    }
    fill_statfs(buf, cpath == b"proc" || cpath.starts_with(b"proc/"));
    0
}

/// fstatfs(fd, buf): the fs backing the fd — Proc OFDs and Dir OFDs
/// that name /proc report procfs, everything else the ramfs.
pub fn sys_fstatfs(fd: u64, buf: u64) -> u64 {
    if !range_ok_w(buf, 120) {
        return EFAULT;
    }
    let Some(t) = cur_mut() else { return EBADF };
    let Some(o) = ofd(t, fd) else { return EBADF };
    let proc = match &o.kind {
        FdKind::Proc { .. } => true,
        FdKind::Dir(d) => {
            let b = d.bytes();
            b == b"proc" || b.starts_with(b"proc/")
        }
        _ => false,
    };
    fill_statfs(buf, proc);
    0
}

/// getgroups(n, list): single-user model — the task is in no
/// supplementary groups; size 0 either way.
pub fn sys_getgroups(_n: u64, _list: u64) -> u64 {
    0
}

/// sched_getaffinity(pid, size, mask): one CPU — the mask is 1,
/// truncated honestly to the caller's size like Linux.
pub fn sys_sched_getaffinity(_pid: u64, size: u64, mask: u64) -> u64 {
    if size == 0 || !range_ok_w(mask, size.min(128)) {
        return EINVAL;
    }
    let n = size.min(8);
    // SAFETY: mask validated writable for size bytes.
    unsafe {
        core::ptr::write_bytes(mask as *mut u8, 0, size.min(128) as usize);
        *(mask as *mut u8) = 1;
    }
    n
}

/// prctl(option, ...): PR_SET_NAME (15) truncates into the task's
/// 15-byte name like Linux comm; everything else is honest EINVAL.
pub fn sys_prctl(op: u64, a2: u64) -> u64 {
    let Some(t) = cur_mut() else { return EINVAL };
    match op {
        15 => {
            // PR_SET_NAME — copy ≤15 bytes from the user string.
            let mut i = 0usize;
            while i < 15 {
                if !range_ok(a2 + i as u64, 1) {
                    break;
                }
                // SAFETY: validated single user byte.
                let c = unsafe { ((a2 + i as u64) as *const u8).read_unaligned() };
                if c == 0 {
                    break;
                }
                t.name[i] = c;
                i += 1;
            }
            if i < 16 {
                t.name[i.min(15)] = 0;
            }
            0
        }
        _ => EINVAL,
    }
}

/// reboot(magic1, magic2, cmd): Linux requires the double magic;
/// CAD_ON/CAD_OFF are acknowledged no-ops, the rest trigger a real
/// chipset reset through port 0xCF9 (under -no-reboot QEMU exits).
pub fn sys_reboot(magic1: u64, magic2: u64, cmd: u64) -> u64 {
    // magic2 accepts Linux's full set (some callers use the alternates).
    if magic1 != 0xfee1dead
        || !matches!(magic2, 672274793 | 85072278 | 369367448 | 537993216)
    {
        return EINVAL;
    }
    match cmd {
        0x89abcdef | 0 => 0, // CAD_ON / CAD_OFF — acknowledged no-ops
        0x01234567 | 0xcdef0123 | 0x4321fedc | 0xa1b2c3d4 => {
            // RB_AUTOBOOT/RESTART/HALT/POWER_OFF/RESTART2 — one real
            // 0xCF9 reset for all of them; under -no-reboot QEMU exits.
            // SAFETY: 0xCF9 is the standard x86 reset-control port;
            // if the machine somehow survives, fall through to success.
            unsafe {
                core::arch::asm!("out dx, al", in("dx") 0xcf9u16, in("al") 0x0eu8);
            }
            0
        }
        _ => EINVAL, // unknown commands EINVAL like Linux
    }
}

/// gettimeofday(tv, tz): wall clock, {sec,usec} layout.
pub fn sys_gettimeofday(tv: u64, _tz: u64) -> u64 {
    if tv != 0 {
        if !range_ok_w(tv, 16) {
            return EFAULT;
        }
        let (s, ns) = crate::rtc::wall_now();
        // SAFETY: tv validated writable for 16 bytes.
        unsafe {
            (tv as *mut u64).write_unaligned(s);
            (tv as *mut u64).add(1).write_unaligned(ns / 1000);
        }
    }
    0
}

/// nanosleep(req, rem): block until the deadline — WaitOn::Timer
/// ages in poll_expire alongside the other deadline waits. Signals
/// interrupt it (rem is zeroed — partial-remain bookkeeping needs
/// the deadline stored, which we keep simple).
pub fn sys_nanosleep(ctx: &mut UCtx, req: u64, rem: u64) -> u64 {
    const EINTR: u64 = (-4i64) as u64;
    if !range_ok(req, 16) {
        return EFAULT;
    }
    let Some(t) = cur_mut() else { return EINVAL };
    let sec = unsafe { (req as *const u64).read_unaligned() };
    let nsec = unsafe { (req as *const u64).add(1).read_unaligned() };
    if nsec >= 1_000_000_000 {
        return EINVAL;
    }
    let ticks = sec
        .saturating_mul(100)
        .saturating_add(nsec.div_ceil(10_000_000));
    if ticks == 0 {
        return 0;
    }
    if rem != 0 && !range_ok_w(rem, 16) {
        return EFAULT;
    }
    if deliverable(t) {
        return EINTR;
    }
    t.wait_on = WaitOn::Timer;
    // wait_ptr carries `rem` — the signal-wake path fills it with
    // the unslept remainder on EINTR (Linux semantics); a normal
    // deadline wake leaves it untouched.
    t.wait_ptr = rem;
    t.wait_ptr2 = 0; // kernel-style -errno returns
    t.wait_deadline = crate::apic::TICKS
        .load(core::sync::atomic::Ordering::Relaxed)
        .saturating_add(ticks);
    t.ctx = *ctx;
    t.state = TaskState::Blocked;
    block_switch()
}

/// clock_nanosleep(clk, flags, req, rem): glibc's nanosleep() lands
/// here, not on nr 35. Unlike every other syscall this ABI returns
/// POSITIVE errno values (EINTR, EINVAL, EFAULT) directly — the
/// signal-wake path must know that, so wait_ptr2 flags the mode.
/// flags bit0 = TIMER_ABSTIME (req is an absolute deadline).
pub fn sys_clock_nanosleep(
    ctx: &mut UCtx,
    _clk: u64,
    flags: u64,
    req: u64,
    rem: u64,
) -> u64 {
    const EFAULT_P: u64 = 14;
    const EINVAL_P: u64 = 22;
    if !range_ok(req, 16) {
        return EFAULT_P;
    }
    let sec = unsafe { (req as *const u64).read_unaligned() };
    let nsec = unsafe { (req as *const u64).add(1).read_unaligned() };
    if nsec >= 1_000_000_000 || flags & !1 != 0 {
        return EINVAL_P;
    }
    let now = crate::apic::TICKS.load(core::sync::atomic::Ordering::Relaxed);
    let ticks = if flags & 1 != 0 {
        // Absolute deadline measured in boot-time ticks.
        sec.saturating_mul(100)
            .saturating_add(nsec.div_ceil(10_000_000))
            .saturating_sub(now)
    } else {
        sec.saturating_mul(100)
            .saturating_add(nsec.div_ceil(10_000_000))
    };
    if ticks == 0 {
        return 0;
    }
    if rem != 0 && !range_ok_w(rem, 16) {
        return EFAULT_P;
    }
    let Some(t) = cur_mut() else { return EINVAL_P };
    if deliverable(t) {
        return 4; // EINTR, positive per this ABI
    }
    t.wait_on = WaitOn::Timer;
    t.wait_ptr = rem;
    t.wait_ptr2 = 1; // positive-errno wake
    t.wait_deadline = now.saturating_add(ticks);
    t.ctx = *ctx;
    t.state = TaskState::Blocked;
    block_switch()
}

/// readv — iovec {base:u64, len:u16 pairs as u64s}. Scatters one
/// logical read across the vector: after the first element, continue
/// only while the fd still reports data-ready — a second BLOCKING
/// read would exceed Linux's "return what's available" semantic.
/// (writev lives in syscall.rs where the console write path is.)
pub fn fd_readv(ctx: &mut UCtx, fd: u64, iov: u64, cnt: u64) -> u64 {
    if cnt == 0 {
        return 0;
    }
    if cnt > 32 || !range_ok(iov, cnt * 16) {
        return EINVAL;
    }
    let mut done = 0u64;
    for i in 0..cnt {
        let (base, len) = unsafe {
            (
                ((iov + i * 16) as *const u64).read_unaligned(),
                ((iov + i * 16 + 8) as *const u64).read_unaligned(),
            )
        };
        if len == 0 {
            continue;
        }
        if done > 0 {
            // POLLIN|POLLERR|POLLHUP = readable-or-terminal — anything
            // else means the next read would block.
            let ready = cur_mut()
                .map(|t| poll_revents(t, fd as i32, 1) & (1 | 8 | 16) != 0)
                .unwrap_or(false);
            if !ready {
                break;
            }
        }
        let n = fd_read(ctx, fd, base, len);
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

// --- fd layer -----------------------------------------------------
// errno values are returned to syscall.rs as negative u64s.
const EBADF: u64 = (-9i64) as u64;
const EFAULT: u64 = (-14i64) as u64;
const ENOENT: u64 = (-2i64) as u64;
const EINVAL: u64 = (-22i64) as u64;
const EMFILE: u64 = (-24i64) as u64;
const ESPIPE: u64 = (-29i64) as u64;
const ENOTDIR: u64 = (-20i64) as u64;
const EISDIR: u64 = (-21i64) as u64;

/// Resolve an fd slot to its OFD in the global table.
fn ofd(t: &mut Task, fd: u64) -> Option<&'static mut OpenFile> {
    let i = *fdt(t).fds.get(fd as usize)?.as_ref()?;
    unsafe { (*core::ptr::addr_of_mut!(OFDS)).get_mut(i as usize)?.as_mut() }
}

/// May `fd` be a write() target? Only the console streams.
pub fn fd_is_console(fd: u64) -> bool {
    let Some(t) = cur_mut() else { return false };
    matches!(ofd(t, fd).map(|o| &o.kind), Some(FdKind::Console))
        || matches!(ofd(t, fd).map(|o| &o.kind), Some(FdKind::Dev(i))
            if vfile(*i).is_some_and(|v| v.rdev >> 8 == 5))
}

/// PRNG state for /dev/{,u}random — a plain xorshift64* seeded at
/// first use from rdtsc. Good enough for urandom semantics; nothing
/// in the kernel depends on it being unpredictable to a local observer.
static mut RNG_SEED: u64 = 0;

fn rng_seed() -> u64 {
    let s = unsafe { *core::ptr::addr_of!(RNG_SEED) };
    if s != 0 {
        return s;
    }
    // SAFETY: rdtsc is always readable; mixed with the boot tick for
    // a non-constant first state.
    let t = unsafe { core::arch::x86_64::_rdtsc() }
        ^ crate::apic::TICKS.load(core::sync::atomic::Ordering::Relaxed)
            .wrapping_mul(0x9e37_79b9_7f4a_7c15);
    let s = if t == 0 { 0x2545_f491_4f6c_dd1d } else { t };
    unsafe { *core::ptr::addr_of_mut!(RNG_SEED) = s };
    s
}

/// tty-input read shared by fd 0 and the /dev/tty|console nodes —
/// job-control gate, ldisc drain, block-on-empty are identical.
fn tty_input_read(
    t: &mut Task,
    ctx: &mut UCtx,
    buf: u64,
    len: u64,
) -> u64 {
    // Job control: a background pgrp of the console's own
    // session gets SIGTTIN'd on a tty read — the signal
    // stops the group so `fg` can bring it forward. An
    // orphaned group gets EIO; a blocked/ignored SIGTTIN
    // reads through — Linux's tty_check_change(SIGTTIN).
    let (fg, csid) = unsafe { (FG_PGID, CONSOLE_SID) };
    let fg_live = fg != 0
        && unsafe { &*core::ptr::addr_of!(TASKS) }
            .iter()
            .flatten()
            .any(|x| x.pgid == fg);
    if t.sid == csid && fg_live && t.pgid != fg {
        let h = sigt(t)
            .handlers
            .get(20) // SIGTTIN - 1
            .copied()
            .unwrap_or(SIG_DFL);
        let bypass = h == SIG_IGN || t.sigmask & (1 << 20) != 0;
        if !bypass {
            const EIO_: u64 = (-5i64) as u64;
            if pgrp_orphaned(t.pgid, t.sid) {
                return EIO_;
            }
            kill_pgrp(t.pgid, 21);
            if deliverable(t) {
                return (-4i64) as u64; // -EINTR: stop lands
            }
        }
    }
    let n = stdin_take(len as usize);
    match n {
        usize::MAX => {
            // Empty input queue — block like PipeRead: the
            // waker copies through our tables and lands the
            // count in ctx.rax.
            if len == 0 {
                return 0;
            }
            if !range_ok_w(buf, 1) {
                return EFAULT;
            }
            if deliverable(t) {
                return (-4i64) as u64; // -EINTR before sleep
            }
            t.wait_on = WaitOn::Stdin;
            t.wait_ptr = buf;
            t.wait_len = len;
            t.ctx = *ctx;
            t.state = TaskState::Blocked;
            block_switch()
        }
        0 => 0, // VEOF on an empty line — tty EOF
        _ => {
            if !range_ok_w(buf, n as u64) {
                return EFAULT;
            }
            for i in 0..n {
                let b = unsafe { *(core::ptr::addr_of!(READY) as *const u8).add(i) };
                // SAFETY: validated user window, cur cr3.
                unsafe { ((buf + i as u64) as *mut u8).write(b) };
            }
            stdin_consume(n);
            n as u64
        }
    }
}

// --- NT personality helpers ----------------------------------------
// Backing functions for nt.rs handlers — they share the Linux side's
// primitives (ldisc queue, console printk, WaitOn::Timer) rather than
// growing a parallel I/O stack.

/// The running task's syscall personality — syscall.rs routes on it.
pub fn task_is_nt() -> bool {
    cur_mut().is_some_and(|t| t.pers == PERS_NT)
}

/// nt::NTH_* tag for handle h (1-based slot), 0 when free/invalid.
/// Windows handles are process objects: an NT thread resolves the
/// leader's table so a handle opened by any thread works for all.
pub fn nt_handle_kind(h: u64) -> u8 {
    let Some(t) = mm_owner_mut() else { return 0 };
    if h == 0 || h > crate::nt::MAX_NTH as u64 {
        return 0;
    }
    t.nth[h as usize - 1]
}

/// NtClose: drop the handle's slot — closing the fd an NTH_FILE
/// slot owns first. Free slots and out-of-range handles fail
/// like a real INVALID_HANDLE.
pub fn nt_handle_close(h: u64) -> bool {
    let Some(t) = mm_owner_mut() else { return false };
    if h == 0 || h > crate::nt::MAX_NTH as u64 {
        return false;
    }
    let i = h as usize - 1;
    if t.nth[i] == 0 {
        return false;
    }
    if t.nth[i] == crate::nt::NTH_FILE {
        fd_close(t.nth_fd[i] as u64);
    }
    if t.nth[i] == crate::nt::NTH_THREAD {
        nt_thr_refdown(t.nth_fd[i] as usize);
    }
    if t.nth[i] == crate::nt::NTH_SECTION {
        nt_sec_refdown(t.nth_fd[i] as usize);
    }
    if t.nth[i] == crate::nt::NTH_PROCESS {
        nt_proc_refdown(t.nth_fd[i] as usize);
    }
    t.nth[i] = 0;
    t.nth_fd[i] = 0xff;
    true
}

/// NT handle-table sweep for a dead process: refdown every ledger
/// object the tgid leader's nth still names. A Task that dies with
/// open NT handles would otherwise pin the global NT_THREADS/
/// NT_PROCS/NT_SECTIONS ledgers forever — NTH_FILE slots need
/// nothing since release_fds already closed the fds underneath.
/// Called only once no same-tgid thread survives: live siblings
/// still resolve their handles through this table.
fn nt_handle_sweep(tasks: &mut [Option<Task>], tgid: u64) {
    let Some(t) = tasks.iter_mut().flatten().find(|t| t.pid == tgid) else {
        return;
    };
    for i in 0..crate::nt::MAX_NTH {
        match t.nth[i] {
            crate::nt::NTH_THREAD => nt_thr_refdown(t.nth_fd[i] as usize),
            crate::nt::NTH_SECTION => nt_sec_refdown(t.nth_fd[i] as usize),
            crate::nt::NTH_PROCESS => nt_proc_refdown(t.nth_fd[i] as usize),
            _ => {}
        }
        t.nth[i] = 0;
        t.nth_fd[i] = 0xff;
    }
}

/// Bind the first free handle slot to task fd `fd` (NTH_FILE) and
/// return its 1-based handle, or None when the table is full.
pub fn nt_handle_alloc_file(fd: u64) -> Option<u64> {
    let t = mm_owner_mut()?;
    for i in 0..crate::nt::MAX_NTH {
        if t.nth[i] == 0 {
            t.nth[i] = crate::nt::NTH_FILE;
            t.nth_fd[i] = fd as u8;
            t.nth_dirpat[i][0] = 0;
            return Some(i as u64 + 1);
        }
    }
    None
}

/// The task fd an NTH_FILE handle resolves to.
pub fn nt_handle_fd(h: u64) -> Option<u64> {
    let t = mm_owner_mut()?;
    if h == 0 || h > crate::nt::MAX_NTH as u64 {
        return None;
    }
    let i = h as usize - 1;
    (t.nth[i] == crate::nt::NTH_FILE).then_some(t.nth_fd[i] as u64)
}

// ---- NT thread objects --------------------------------------------
// A Windows thread handle must stay valid after the thread's task
// slot is reaped (a waiter can hold it indefinitely), so the
// waitable object's state lives in this small global ledger keyed
// by tid — task slots may be recycled, entries here are not, and a
// handle slot stores the ledger index in `nth_fd`.
const NT_MAX_THREADS: usize = 16;
/// (tgid, tid, teb, exit_status, state, handle_refs, stack_va,
/// window_sz, owner_pid) — state 0=free 1=alive 2=dead; refs counts
/// open handles. stack_va/window_sz name the single contiguous
/// [stack|teb|tls] window so the creator's ledger can free it once
/// the thread is dead (task slots reap, ranges don't).
static mut NT_THREADS: [(u64, u64, u64, u64, u8, u8, u64, u64, u64); NT_MAX_THREADS] =
    [(0, 0, 0, 0, 0, 0, 0, 0, 0); NT_MAX_THREADS];

fn nt_thr_alloc(tgid: u64, tid: u64, teb: u64, stk: u64, stksz: u64, owner: u64) -> Option<usize> {
    let tab = unsafe { &mut *core::ptr::addr_of_mut!(NT_THREADS) };
    let i = tab.iter().position(|e| e.4 == 0)?;
    tab[i] = (tgid, tid, teb, 0, 1, 0, stk, stksz, owner);
    Some(i)
}

/// A dying NT thread records its raw exit status here — task slots
/// recycle, thread handles don't. Called from task_exit with the
/// pre-wstatus code.
pub fn nt_thread_dead(tid: u64, status: u64) {
    let tab = unsafe { &mut *core::ptr::addr_of_mut!(NT_THREADS) };
    for e in tab.iter_mut() {
        if e.1 == tid && e.4 == 1 {
            e.3 = status;
            e.4 = 2;
            if e.5 == 0 {
                *e = (0, 0, 0, 0, 0, 0, 0, 0, 0);
            }
            return;
        }
    }
}

/// (tgid, tid, teb, status, alive) for a ledger index.
pub fn nt_thr_info(idx: usize) -> Option<(u64, u64, u64, u64, bool)> {
    let tab = unsafe { &*core::ptr::addr_of!(NT_THREADS) };
    let e = *tab.get(idx)?;
    (e.4 != 0).then_some((e.0, e.1, e.2, e.3, e.4 == 1))
}

/// One fewer handle on the object; frees a dead unreferenced entry.
fn nt_thr_refdown(idx: usize) {
    let tab = unsafe { &mut *core::ptr::addr_of_mut!(NT_THREADS) };
    if let Some(e) = tab.get_mut(idx) {
        if e.4 != 0 {
            e.5 = e.5.saturating_sub(1);
            if e.4 == 2 && e.5 == 0 {
                *e = (0, 0, 0, 0, 0, 0, 0, 0, 0);
            }
        }
    }
}

/// NtWaitForSingleObject's tick service: a blocked NtWait(idx)
/// sleeper wakes with STATUS_SUCCESS in ctx.rax when its object
/// dies, STATUS_TIMEOUT when wait_deadline expires, or
/// STATUS_INVALID_HANDLE if the ledger entry ever vanishes. The
/// sleeper resumes in userland with that rax — the same
/// abandoned-kernel-frame wake model every blocking call uses.
pub fn nt_wait_expire() {
    let now = crate::apic::TICKS.load(core::sync::atomic::Ordering::Relaxed);
    let tasks = unsafe { &mut *core::ptr::addr_of_mut!(TASKS) };
    let tab = unsafe { &*core::ptr::addr_of!(NT_THREADS) };
    for s in tasks.iter_mut() {
        let Some(t) = s.as_mut() else { continue };
        if t.state != TaskState::Blocked {
            continue;
        }
        let rax = match t.wait_on {
            WaitOn::NtWait(idx, tid) => match tab.get(idx) {
                // A freed or reallocated slot no longer names the
                // waited thread — wake as an invalid handle.
                Some(e) if e.1 != tid => crate::nt::STATUS_INVALID_HANDLE,
                Some(e) if e.4 == 2 => crate::nt::STATUS_SUCCESS,
                Some(e) if e.4 == 1 => {
                    if t.wait_deadline != 0 && now >= t.wait_deadline {
                        crate::nt::STATUS_TIMEOUT
                    } else {
                        continue;
                    }
                }
                _ => crate::nt::STATUS_INVALID_HANDLE,
            },
            WaitOn::NtWaitProc(idx, tgid) => {
                let ptab = unsafe { &*core::ptr::addr_of!(NT_PROCS) };
                match ptab.get(idx) {
                    // A freed or reallocated slot no longer names the
                    // waited process — wake as an invalid handle.
                    Some(e) if e.0 != tgid => crate::nt::STATUS_INVALID_HANDLE,
                    Some(e) if e.2 == 2 => crate::nt::STATUS_SUCCESS,
                    Some(e) if e.2 == 1 => {
                        if t.wait_deadline != 0 && now >= t.wait_deadline {
                            crate::nt::STATUS_TIMEOUT
                        } else {
                            continue;
                        }
                    }
                    _ => crate::nt::STATUS_INVALID_HANDLE,
                }
            }
            _ => continue,
        };
        t.ctx.rax = rax;
        t.wait_on = WaitOn::None;
        t.wait_deadline = 0;
        t.state = TaskState::Runnable;
    }
}

/// Block the current task on an NT thread object (ledger idx):
/// deadline_ticks bounds it (0 = infinite). Never returns — the
/// wake resumes userland with nt_wait_expire's ctx.rax.
pub fn nt_wait_block(ctx: &mut UCtx, idx: usize, deadline_ticks: u64) -> ! {
    // Pin the waited thread's identity: idx alone is reusable once a
    // handle close frees the ledger slot, and a later CreateThread
    // could satisfy a stale wait on a foreign object.
    let tid = unsafe { &*core::ptr::addr_of!(NT_THREADS) }
        .get(idx)
        .map(|e| e.1)
        .unwrap_or(0);
    if let Some(t) = cur_mut() {
        t.wait_on = WaitOn::NtWait(idx, tid);
        t.wait_deadline = deadline_ticks;
        t.ctx = *ctx;
        t.state = TaskState::Blocked;
    }
    block_switch()
}

/// Resume a CREATE_SUSPENDED thread: blocked-on-NtSuspend -> Runnable.
/// Returns the previous suspend count (1 resumed, 0 wasn't suspended).
pub fn nt_thr_resume(tid: u64) -> u64 {
    let tasks = unsafe { &mut *core::ptr::addr_of_mut!(TASKS) };
    for s in tasks.iter_mut() {
        if let Some(t) = s.as_mut() {
            if t.pid == tid && t.state == TaskState::Blocked && t.wait_on == WaitOn::NtSuspend {
                t.wait_on = WaitOn::None;
                t.state = TaskState::Runnable;
                return 1;
            }
        }
    }
    0
}

/// True while at least one handle slot is free — CreateThreadEx
/// pre-checks so a created thread can't outlive its missing handle.
pub fn nt_handle_free_slot() -> bool {
    mm_owner_mut().is_some_and(|t| t.nth.iter().any(|&s| s == 0))
}

/// Bind a thread-object handle in the process handle table; the
/// slot's nth_fd byte carries the NT_THREADS ledger index.
pub fn nt_handle_alloc_thread(idx: usize) -> Option<u64> {
    let tab = unsafe { &mut *core::ptr::addr_of_mut!(NT_THREADS) };
    let t = mm_owner_mut()?;
    for i in 0..crate::nt::MAX_NTH {
        if t.nth[i] == 0 {
            t.nth[i] = crate::nt::NTH_THREAD;
            t.nth_fd[i] = idx as u8;
            tab[idx].5 = tab[idx].5.saturating_add(1);
            return Some(i as u64 + 1);
        }
    }
    None
}

/// The NT_THREADS index an NTH_THREAD handle names.
pub fn nt_handle_thr_idx(h: u64) -> Option<usize> {
    let t = mm_owner_mut()?;
    if h == 0 || h > crate::nt::MAX_NTH as u64 {
        return None;
    }
    let i = h as usize - 1;
    (t.nth[i] == crate::nt::NTH_THREAD).then_some(t.nth_fd[i] as usize)
}

// ---- NT process objects -------------------------------------------
// A process handle must outlive the child's task slot the same way a
// thread handle does, so process waitable state lives in a small
// global ledger keyed by tgid. Only CreateProcess'd children get an
// entry — boot-spawned PE tasks don't need handles. A process object
// is signaled when the LAST thread of the group dies (Windows' rule);
// the exit code it reports is the leader's.
const NT_MAX_PROCS: usize = 8;
/// (tgid, exit_status, state, handle_refs) — state 0=free 1=alive 2=dead.
static mut NT_PROCS: [(u64, u64, u8, u8); NT_MAX_PROCS] = [(0, 0, 0, 0); NT_MAX_PROCS];

fn nt_proc_alloc(tgid: u64) -> Option<usize> {
    let tab = unsafe { &mut *core::ptr::addr_of_mut!(NT_PROCS) };
    let i = tab.iter().position(|e| e.2 == 0)?;
    tab[i] = (tgid, 0, 1, 0);
    Some(i)
}

/// Free entries remain in the process ledger — CreateProcess
/// prechecks this before spawning so post-spawn steps can't fail.
fn nt_proc_slot_free() -> bool {
    let tab = unsafe { &*core::ptr::addr_of!(NT_PROCS) };
    tab.iter().any(|e| e.2 == 0)
}

/// (exit_status, alive) for a ledger index.
pub fn nt_proc_status(idx: usize) -> Option<(u64, bool)> {
    let tab = unsafe { &*core::ptr::addr_of!(NT_PROCS) };
    let e = *tab.get(idx)?;
    (e.2 != 0).then_some((e.1, e.2 == 1))
}

fn nt_proc_refdown(idx: usize) {
    let tab = unsafe { &mut *core::ptr::addr_of_mut!(NT_PROCS) };
    if let Some(e) = tab.get_mut(idx) {
        if e.2 != 0 {
            e.3 = e.3.saturating_sub(1);
            if e.2 == 2 && e.3 == 0 {
                *e = (0, 0, 0, 0);
            }
        }
    }
}

/// Bind a process-object handle in the caller's table; nth_fd
/// carries the NT_PROCS index and the entry gains one handle ref.
pub fn nt_handle_alloc_proc(idx: usize) -> Option<u64> {
    let tab = unsafe { &mut *core::ptr::addr_of_mut!(NT_PROCS) };
    let t = mm_owner_mut()?;
    for i in 0..crate::nt::MAX_NTH {
        if t.nth[i] == 0 {
            t.nth[i] = crate::nt::NTH_PROCESS;
            t.nth_fd[i] = idx as u8;
            tab[idx].3 = tab[idx].3.saturating_add(1);
            return Some(i as u64 + 1);
        }
    }
    None
}

/// The NT_PROCS index an NTH_PROCESS handle names.
pub fn nt_handle_proc_idx(h: u64) -> Option<usize> {
    let t = mm_owner_mut()?;
    if h == 0 || h > crate::nt::MAX_NTH as u64 {
        return None;
    }
    let i = h as usize - 1;
    (t.nth[i] == crate::nt::NTH_PROCESS).then_some(t.nth_fd[i] as usize)
}

/// A dying NT task may end its process: when the dying pid is the
/// leader (pid == tgid) its status becomes the process exit code —
/// recorded at leader death even while workers still run — and the
/// object signals once no other task of the group stays alive.
/// Called for EVERY NT task death: the last survivor ends it. The
/// dying task isn't Exited yet at the call site; excluding it by
/// pid handles that.
pub fn nt_proc_dead(tgid: u64, pid: u64, status: u64) {
    let tab = unsafe { &mut *core::ptr::addr_of_mut!(NT_PROCS) };
    let Some(e) = tab.iter_mut().find(|e| e.0 == tgid && e.2 == 1) else {
        return;
    };
    if pid == tgid {
        e.1 = status;
    }
    let tasks = unsafe { &*core::ptr::addr_of!(TASKS) };
    let alive = tasks.iter().flatten().any(|o| {
        o.tgid == tgid && o.pid != pid && o.state != TaskState::Exited
    });
    if !alive {
        e.2 = 2;
        if e.3 == 0 {
            *e = (0, 0, 0, 0);
        }
    }
}

/// CreateProcess's kernel half: resolve the image name in the
/// caller's space (narrow ANSI), fetch the image through the same
/// VFS/initrd source nt_mod_resolve uses, spawn it as a peer NT
/// task, and return process + thread handles plus the ids in the
/// caller's PROCESS_INFORMATION. flags honors CREATE_SUSPENDED (4);
/// every other flag bit is ignored like a minimal kernel32 would.
pub fn nt_create_process(app_va: u64, cmd_va: u64, pi_va: u64, flags: u64) -> u64 {
    use crate::nt::*;
    let Some(ct) = mm_owner_mut() else { return STATUS_INVALID_HANDLE };
    let pml4 = ct.pml4;
    // Command line first — a NULL lpApplicationName resolves to its
    // first whitespace-delimited token, like real CreateProcess.
    let mut cmd = [0u8; 200];
    let cmdl = if cmd_va != 0 && range_ok(cmd_va, 1) {
        read_task_str(pml4, cmd_va, &mut cmd).min(cmd.len() - 1)
    } else {
        0
    };
    let (nb, nl) = if app_va != 0 {
        let Some(x) = nt_mod_name(pml4, app_va, false) else {
            return STATUS_OBJECT_NAME_INVALID;
        };
        x
    } else {
        if cmdl == 0 {
            return STATUS_OBJECT_NAME_INVALID;
        }
        let tl = cmd[..cmdl]
            .iter()
            .position(|&c| c == b' ' || c == b'\t')
            .unwrap_or(cmdl);
        let st = cmd[..tl]
            .iter()
            .rposition(|&c| c == b'\\' || c == b'/')
            .map(|i| i + 1)
            .unwrap_or(0);
        let n2 = (tl - st).min(63);
        let mut b2 = [0u8; 64];
        b2[..n2].copy_from_slice(&cmd[st..st + n2]);
        if n2 == 0 {
            return STATUS_OBJECT_NAME_INVALID;
        }
        (b2, n2)
    };
    let name = &nb[..nl];
    if !range_ok_w(pi_va, 24) {
        return STATUS_ACCESS_VIOLATION;
    }
    let mut full = [0u8; 40];
    if name.is_empty() || name.len() > full.len() - 1 {
        return STATUS_OBJECT_NAME_INVALID;
    }
    full[0] = b'/';
    full[1..1 + name.len()].copy_from_slice(name);
    let img: Option<&[u8]> =
        if let Some(v) = vfile_find(&full[..1 + name.len()]).and_then(vfile) {
            (!v.data.is_null() && v.len != 0)
                .then(|| unsafe { core::slice::from_raw_parts(v.data, v.len) })
        } else {
            unsafe { *core::ptr::addr_of!(INITRD) }
                .and_then(|arc| crate::cpio::find(arc, name))
        };
    let Some(img) = img else { return STATUS_OBJECT_NAME_NOT_FOUND };
    if !img.starts_with(b"MZ") {
        return STATUS_INVALID_PARAMETER;
    }
    // Prechecks make every post-spawn step infallible: two handle
    // slots (process + thread) and one entry in each waitable ledger.
    if ct.nth.iter().filter(|&&s| s == 0).count() < 2
        || !nt_thr_slot_free()
        || !nt_proc_slot_free()
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    let Some(si) = spawn_idx(img, core::str::from_utf8(name).unwrap_or("winproc"), true) else {
        return STATUS_INSUFFICIENT_RESOURCES;
    };
    let tasks = unsafe { &mut *core::ptr::addr_of_mut!(TASKS) };
    let Some(c) = tasks.get_mut(si).and_then(|s| s.as_mut()) else {
        return STATUS_INSUFFICIENT_RESOURCES;
    };
    let cpid = c.pid;
    if cmdl != 0 {
        nt_set_cmdline(c.pml4, &cmd[..cmdl]);
    }
    // Infallible after the prechecks: the child's leader gets a
    // thread-ledger entry (no stack window — the task owns it) so
    // hThread is a real waitable object, and the group gets the
    // process object the parent waits on. A failure past this point
    // leaves a suspended child — degraded, never panicked.
    let (Some(tidx), Some(pidx)) = (
        nt_thr_alloc(cpid, cpid, crate::pe::TEB_VA, 0, 0, cpid),
        nt_proc_alloc(cpid),
    ) else {
        return STATUS_INSUFFICIENT_RESOURCES;
    };
    if flags & 4 == 0 {
        // The spawn inserted the child suspended so it couldn't run
        // and be reaped mid-wiring; a non-CREATE_SUSPENDED launch
        // releases it now that the ledgers exist.
        c.state = TaskState::Runnable;
        c.wait_on = WaitOn::None;
    }
    let (Some(ht), Some(hp)) =
        (nt_handle_alloc_thread(tidx), nt_handle_alloc_proc(pidx))
    else {
        return STATUS_INSUFFICIENT_RESOURCES;
    };
    let mut pi = [0u8; 24];
    pi[0..8].copy_from_slice(&hp.to_le_bytes());
    pi[8..16].copy_from_slice(&ht.to_le_bytes());
    pi[16..20].copy_from_slice(&(cpid as u32).to_le_bytes());
    pi[20..24].copy_from_slice(&(cpid as u32).to_le_bytes());
    if !write_task_bytes(pml4, pi_va, &pi) {
        return STATUS_ACCESS_VIOLATION;
    }
    STATUS_SUCCESS
}

/// Write a process object's status into the caller's buffer —
/// STILL_ACTIVE (259) while the group lives, the leader's exit code
/// after. GetExitCodeProcess's backing service.
pub fn nt_proc_query(h: u64, out_va: u64) -> u64 {
    use crate::nt::*;
    if !range_ok_w(out_va, 4) {
        return STATUS_ACCESS_VIOLATION;
    }
    let Some(idx) = nt_handle_proc_idx(h) else {
        return STATUS_INVALID_HANDLE;
    };
    let Some((status, alive)) = nt_proc_status(idx) else {
        return STATUS_INVALID_HANDLE;
    };
    let code = if alive { STATUS_STILL_ACTIVE as u32 } else { status as u32 };
    let Some(ct) = mm_owner_mut() else {
        return STATUS_INVALID_HANDLE;
    };
    if !write_task_bytes(ct.pml4, out_va, &code.to_le_bytes()) {
        return STATUS_ACCESS_VIOLATION;
    }
    STATUS_SUCCESS
}

/// RUX_SYS_INFO(sub, out): the time/system-info services the Win32
/// thunk layer serves. Subs 1 and 6 return the value in rax; the
/// rest write a struct at `out` and return NTSTATUS.
///   0 SYSTEM_INFO 48B   1 tick-ms (rax)        2 FILETIME u64
///   3 SYSTEMTIME 16B    4 QPC counter u64      5 QPC frequency u64
///   6 packed version (rax)  7 OSVERSIONINFOA   8 OSVERSIONINFOW
pub fn nt_sysinfo(sub: u64, out: u64) -> u64 {
    use crate::nt::*;
    if sub == 1 {
        return crate::apic::TICKS.load(core::sync::atomic::Ordering::Relaxed) * 10;
    }
    if sub == 6 {
        // GetVersion's packed dword: major | minor<<8 | build<<16.
        return 10 | (19045u64) << 16;
    }
    let Some(ct) = mm_owner_mut() else {
        return STATUS_INVALID_HANDLE;
    };
    let pml4 = ct.pml4;
    let ok = match sub {
        0 => {
            // SYSTEM_INFO — honest values: one CPU, our real user
            // window, page-granule commits (no 64K reservation step).
            let mut s = [0u8; 48];
            s[0..2].copy_from_slice(&9u16.to_le_bytes()); // ARCH_AMD64
            s[4..8].copy_from_slice(&4096u32.to_le_bytes());
            s[8..16].copy_from_slice(&crate::elf::USER_VA_LO.to_le_bytes());
            s[16..24].copy_from_slice(&crate::elf::USER_VA_HI.to_le_bytes());
            s[24..32].copy_from_slice(&1u64.to_le_bytes());
            s[32..36].copy_from_slice(&1u32.to_le_bytes());
            s[36..40].copy_from_slice(&8664u32.to_le_bytes());
            s[40..44].copy_from_slice(&4096u32.to_le_bytes());
            s[44..46].copy_from_slice(&6u16.to_le_bytes());
            range_ok_w(out, 48) && write_task_bytes(pml4, out, &s)
        }
        2 => {
            let (s, ns) = crate::rtc::wall_now();
            let ft = (s + 11_644_473_600) * 10_000_000 + ns / 100;
            range_ok_w(out, 8) && write_task_bytes(pml4, out, &ft.to_le_bytes())
        }
        3 => {
            let (y, mo, d, h, mi, s, w, ms) = crate::rtc::wall_datetime();
            let mut b = [0u8; 16];
            for (i, v) in [y, mo, w, d, h, mi, s, ms].iter().enumerate() {
                b[i * 2..i * 2 + 2].copy_from_slice(&(*v as u16).to_le_bytes());
            }
            range_ok_w(out, 16) && write_task_bytes(pml4, out, &b)
        }
        4 => {
            // SAFETY: rdtsc is always readable in ring 0.
            let c = unsafe { core::arch::x86_64::_rdtsc() };
            range_ok_w(out, 8) && write_task_bytes(pml4, out, &c.to_le_bytes())
        }
        5 => {
            let f = crate::rtc::tsc_hz();
            range_ok_w(out, 8) && write_task_bytes(pml4, out, &f.to_le_bytes())
        }
        7 | 8 => {
            // OSVERSIONINFO A/W: 10.0.19045, NT platform, empty
            // CSDVersion (the tail of the struct stays zeroed).
            let sz = if sub == 7 { 148u64 } else { 276u64 };
            if !range_ok_w(out, sz) {
                return STATUS_ACCESS_VIOLATION;
            }
            let mut b = [0u8; 276];
            b[0..4].copy_from_slice(&(sz as u32).to_le_bytes());
            b[4..8].copy_from_slice(&10u32.to_le_bytes());
            b[8..12].copy_from_slice(&0u32.to_le_bytes());
            b[12..16].copy_from_slice(&19045u32.to_le_bytes());
            b[16..20].copy_from_slice(&2u32.to_le_bytes()); // WIN32_NT
            write_task_bytes(pml4, out, &b[..sz as usize])
        }
        _ => return STATUS_INVALID_PARAMETER,
    };
    if ok {
        STATUS_SUCCESS
    } else {
        STATUS_ACCESS_VIOLATION
    }
}

/// Read an NT path argument — ANSI cstring or UTF-16 (wide=true) —
/// and normalize to our unix form: '\' -> '/', a DOS drive prefix
/// or \??\ gone. ASCII only like nt_create_file; empty/bad reads
/// and non-ASCII wides fail None.
fn nt_read_path(pml4: u64, va: u64, wide: bool) -> Option<([u8; 256], usize)> {
    let mut b = [0u8; 256];
    let n = if wide {
        let mut n = 0usize;
        loop {
            if n >= 255 {
                return None;
            }
            // Each byte is gated separately: a u16 straddling a
            // page end must not read into the next physical frame.
            let lo = translate_r(pml4, va + 2 * n as u64)?;
            let hi = translate_r(pml4, va + 2 * n as u64 + 1)?;
            // SAFETY: both are present user bytes in pml4.
            let u = unsafe {
                *(lo as *const u8) as u16 | (*(hi as *const u8) as u16) << 8
            };
            if u == 0 {
                break;
            }
            if u > 0x7f {
                return None;
            }
            b[n] = u as u8;
            n += 1;
        }
        n
    } else {
        read_task_str(pml4, va, &mut b)
    };
    if n == 0 {
        return None;
    }
    for c in b[..n].iter_mut() {
        if *c == b'\\' {
            *c = b'/';
        }
    }
    let mut st = 0usize;
    if n >= 4 && &b[..4] == b"/??/" {
        st = 4;
    }
    if n - st >= 2 && b[st + 1] == b':' && b[st].is_ascii_alphabetic() {
        st += 2;
    }
    if st >= n {
        return None;
    }
    let mut out = [0u8; 256];
    out[..n - st].copy_from_slice(&b[st..n]);
    Some((out, n - st))
}

/// unix flat path ("" = root) -> DOS form "C:\a\b" in `out`.
fn nt_dos_path(upath: &[u8], out: &mut [u8; 260]) -> usize {
    // "C:\" + path must fit: clamp so a future long caller can't
    // run past `out` (current callers bound upath <= 256).
    let upath = &upath[..upath.len().min(257)];
    out[0] = b'C';
    out[1] = b':';
    out[2] = b'\\';
    let mut n = 3;
    for &c in upath {
        out[n] = if c == b'/' { b'\\' } else { c };
        n += 1;
    }
    n
}

/// Write a DOS path to a user buffer, ANSI or UTF-16. Windows
/// semantics for the get-dir/get-name APIs: returns the char count
/// written EXCLUDING the NUL; when the buffer is too small returns
/// the required size INCLUDING the NUL (caller sees > buflen).
fn nt_dos_write(
    pml4: u64,
    buf: u64,
    buflen: u64,
    wide: bool,
    dos: &[u8],
) -> u64 {
    // w[520]/b[260] bound the copy: clamp callers' input to fit.
    let dos = &dos[..dos.len().min(259)];
    let need = dos.len() as u64 + 1; // in TCHARs
    if buflen < need {
        return need;
    }
    let ok = if wide {
        let mut w = [0u8; 520];
        for (i, &c) in dos.iter().enumerate() {
            w[i * 2] = c;
        }
        range_ok_w(buf, dos.len() as u64 * 2 + 2)
            && write_task_bytes(pml4, buf, &w[..dos.len() * 2 + 2])
    } else {
        range_ok_w(buf, need) && {
            let mut b = [0u8; 260];
            b[..dos.len()].copy_from_slice(dos);
            write_task_bytes(pml4, buf, &b[..dos.len() + 1])
        }
    };
    if ok {
        dos.len() as u64
    } else {
        0
    }
}

/// RUX_PATH(sub, a1, a2, a3): the path/directory/file-attribute
/// services the Win32 thunk layer serves. String subs return a
/// DWORD char count, attribute subs a DWORD, the rest NTSTATUS.
///   0 GetCurrentDirectory(buf,len,wide)     1 SetCurrentDirectory(path,wide)
///   2 GetFullPathName(in,out,len<<1|wide)   3 CreateDirectory(path,wide)
///   4 RemoveDirectory(path,wide)            5 GetFileAttributes(path,wide)
///   6 GetFileType(handle)                   7 SetEndOfFile(handle)
///   8 FlushFileBuffers(handle)              9 GlobalMemoryStatusEx(buf)
///  10 GetComputerName(buf,lenptr,wide)
pub fn nt_pathop(sub: u64, a1: u64, a2: u64, a3: u64) -> u64 {
    use crate::nt::*;
    let Some(ct) = mm_owner_mut() else {
        return STATUS_INVALID_HANDLE;
    };
    let pml4 = ct.pml4;
    match sub {
        0 => {
            // GetCurrentDirectory: "C:\" + cwd with backslashes.
            let f = fst(ct);
            let mut dos = [0u8; 260];
            let dn = nt_dos_path(&f.cwd[..f.cwdlen as usize], &mut dos);
            nt_dos_write(pml4, a1, a2, a3 != 0, &dos[..dn])
        }
        2 => {
            // GetFullPathName: canon vs cwd -> DOS form. a3 low bit
            // is the wide flag, the rest is the buffer length.
            let (wide, buflen) = (a3 & 1 != 0, a3 >> 1);
            let Some((p, n)) = nt_read_path(pml4, a1, wide) else {
                return 0;
            };
            let Ok((cp, cn)) = canon_path(u64::MAX, &p[..n]) else {
                return 0;
            };
            let mut dos = [0u8; 260];
            let dn = nt_dos_path(&cp[..cn], &mut dos);
            nt_dos_write(pml4, a2, buflen, wide, &dos[..dn])
        }
        1 | 3 | 4 | 5 => {
            let Some((p, n)) = nt_read_path(pml4, a1, a2 != 0) else {
                return if sub == 5 { u64::MAX } else { STATUS_OBJECT_NAME_INVALID };
            };
            let Ok((cp, cn)) = canon_path(u64::MAX, &p[..n]) else {
                return if sub == 5 { u64::MAX } else { STATUS_NAME_TOO_LONG };
            };
            match sub {
                1 => {
                    // SetCurrentDirectory: canonical must name a dir;
                    // the resolved form becomes the new cwd.
                    let Ok((rp, rn, _)) = resolve_links(&cp[..cn], true) else {
                        return STATUS_OBJECT_NAME_NOT_FOUND;
                    };
                    if !dir_exists(&rp[..rn]) {
                        return STATUS_OBJECT_NAME_NOT_FOUND;
                    }
                    if rn > 128 {
                        return STATUS_NAME_TOO_LONG;
                    }
                    let t = mm_owner_mut().unwrap();
                    let f = fst(t);
                    f.cwd[..rn].copy_from_slice(&rp[..rn]);
                    f.cwdlen = rn as u8;
                    STATUS_SUCCESS
                }
                3 => fs_mkdir_status(&cp[..cn]),
                4 => fs_rmdir_status(&cp[..cn]),
                5 => {
                    // GetFileAttributes: dir -> DIRECTORY, file ->
                    // ARCHIVE, nothing -> INVALID_FILE_ATTRIBUTES.
                    if let Ok((rp, rn, _)) = resolve_links(&cp[..cn], true) {
                        if dir_exists(&rp[..rn]) {
                            return 0x10; // FILE_ATTRIBUTE_DIRECTORY
                        }
                        if is_file(&rp[..rn]) {
                            return 0x20; // FILE_ATTRIBUTE_ARCHIVE
                        }
                    }
                    u64::MAX // INVALID_FILE_ATTRIBUTES
                }
                _ => unreachable!(),
            }
        }
        6..=8 => {
            // Handle ops: nth must name a file-backed handle.
            let kind = nt_handle_kind(a1);
            if sub == 6
                && (kind == NTH_STDIN || kind == NTH_STDOUT || kind == NTH_STDERR)
            {
                // Console/std streams report FILE_TYPE_CHAR.
                return 2;
            }
            let fd = (kind == NTH_FILE)
                .then(|| nt_handle_fd(a1))
                .flatten();
            let Some(fd) = fd else {
                return if sub == 6 { 0 } else { STATUS_INVALID_HANDLE };
            };
            match sub {
                6 => {
                    // GetFileType: console/std -> CHAR, pipe -> PIPE,
                    // regular storage -> DISK, the rest UNKNOWN.
                    let t = mm_owner_mut().unwrap();
                    let Some(o) = ofd(t, fd) else { return 0 };
                    match &o.kind {
                        FdKind::Stdin | FdKind::Console | FdKind::Dev(_) => 2,
                        FdKind::Pipe { .. } => 3,
                        FdKind::File(_) | FdKind::Ram(_) | FdKind::Dir(_) => 1,
                        _ => 0,
                    }
                }
                7 => {
                    // SetEndOfFile: truncate at the shared position.
                    let pos = fd_lseek(fd, 0, 1);
                    if (pos as i64) < 0 {
                        return STATUS_INVALID_HANDLE;
                    }
                    let r = fd_ftruncate(fd, pos);
                    if (r as i64) < 0 {
                        STATUS_ACCESS_DENIED
                    } else {
                        STATUS_SUCCESS
                    }
                }
                _ => {
                    // FlushFileBuffers: the VFS is synchronous RAM —
                    // nothing dirty exists, so a valid handle is
                    // always an honest success.
                    STATUS_SUCCESS
                }
            }
        }
        9 => {
            // GlobalMemoryStatusEx: 64B struct — real frame counters,
            // user window for virtual, no paging file.
            if !range_ok_w(a1, 64) {
                return STATUS_ACCESS_VIOLATION;
            }
            let total = crate::kalloc::total_frames() * 4096;
            let avail = crate::kalloc::free_frames() * 4096;
            let load = (total - avail)
                .checked_mul(100)
                .and_then(|v| v.checked_div(total))
                .unwrap_or(0);
            let mut b = [0u8; 64];
            b[0..4].copy_from_slice(&64u32.to_le_bytes());
            b[4..8].copy_from_slice(&(load as u32).to_le_bytes());
            for (off, v) in [
                (8usize, total),
                (16, avail),
                // TotalPageFile/AvailPageFile stay 0 — no paging.
                (40, crate::elf::USER_VA_HI - crate::elf::USER_VA_LO),
                (48, crate::elf::USER_VA_HI - crate::elf::USER_VA_LO),
            ] {
                b[off..off + 8].copy_from_slice(&v.to_le_bytes());
            }
            if write_task_bytes(pml4, a1, &b) {
                STATUS_SUCCESS
            } else {
                STATUS_ACCESS_VIOLATION
            }
        }
        10 => {
            // GetComputerName: "RUSTUX" — the caller's *size is the
            // in/out buffer length (chars, no NUL on input).
            if !range_ok_w(a2, 4) || !range_ok_w(a1, 1) {
                return STATUS_ACCESS_VIOLATION;
            }
            let Some(pa) = translate_r(pml4, a2) else {
                return STATUS_ACCESS_VIOLATION;
            };
            // SAFETY: pa is a present user frame in pml4.
            let cap = unsafe { (pa as *const u32).read_unaligned() } as u64;
            if cap < 7 {
                return STATUS_BUFFER_TOO_SMALL;
            }
            if nt_dos_write(pml4, a1, cap, a3 != 0, b"RUSTUX") != 6 {
                return STATUS_ACCESS_VIOLATION;
            }
            let _ = write_task_bytes(pml4, a2, &6u32.to_le_bytes());
            STATUS_SUCCESS
        }
        _ => STATUS_INVALID_PARAMETER,
    }
}

/// mkdir for the NT service: canon already applied, errno->NTSTATUS.
fn fs_mkdir_status(cpath: &[u8]) -> u64 {
    use crate::nt::*;
    if cpath.len() > 255 {
        return STATUS_NAME_TOO_LONG;
    }
    // fs_mkdir resolves a canonical absolute path straight through —
    // feed it as a root-led path so no second cwd join happens.
    let mut abs = [0u8; 256];
    abs[0] = b'/';
    abs[1..1 + cpath.len()].copy_from_slice(cpath);
    let r = fs_mkdir(u64::MAX, &abs[..1 + cpath.len()], 0);
    nt_errno(r)
}

/// rmdir twin of fs_mkdir_status.
fn fs_rmdir_status(cpath: &[u8]) -> u64 {
    use crate::nt::*;
    if cpath.len() > 255 {
        return STATUS_NAME_TOO_LONG;
    }
    let mut abs = [0u8; 256];
    abs[0] = b'/';
    abs[1..1 + cpath.len()].copy_from_slice(cpath);
    let r = fs_rmdir(u64::MAX, &abs[..1 + cpath.len()]);
    nt_errno(r)
}

/// A Linux -errno return to NTSTATUS for the path services.
fn nt_errno(r: u64) -> u64 {
    use crate::nt::*;
    if (r as i64) >= 0 {
        return STATUS_SUCCESS;
    }
    match r as i64 {
        -2 => STATUS_OBJECT_NAME_NOT_FOUND,
        -9 => STATUS_INVALID_HANDLE,
        -13 | -30 => STATUS_ACCESS_DENIED,
        -17 => STATUS_OBJECT_NAME_COLLISION,
        -20 => STATUS_OBJECT_PATH_NOT_FOUND,
        -24 => STATUS_INSUFFICIENT_RESOURCES,
        -36 => STATUS_NAME_TOO_LONG,
        -39 => STATUS_DIRECTORY_NOT_EMPTY,
        _ => STATUS_INVALID_PARAMETER,
    }
}

/// CreateProcess's cmdline override: ANSI text at STUB_DATA_VA+0xa00
/// (the cell GetCommandLineA/_acmdln resolve to) and the UTF-16
/// UNICODE_STRING PEB ProcessParameters.CommandLine points at.
/// Without a cmdline the default ("<name>.exe") stays.
fn nt_set_cmdline(pml4: u64, s: &[u8]) {
    let d = crate::pe::STUB_DATA_VA;
    let cl = s.len().min(230);
    let mut b = [0u8; 232];
    b[..cl].copy_from_slice(&s[..cl]);
    let _ = write_task_bytes(pml4, d + 0xa00, &b[..cl + 1]);
    peb_cmdline_write(pml4, &s[..cl]);
}

/// Write PEB ProcessParameters.CommandLine — the UTF-16 buffer at
/// PEB+0x600 and its UNICODE_STRING at params+0x80. Shared by
/// pe_late_init (default "<name>.exe") and nt_set_cmdline.
fn peb_cmdline_write(pml4: u64, s: &[u8]) -> bool {
    let peb = crate::pe::PEB_VA;
    let params = peb + 0x400;
    let mut u16b = [0u8; 256];
    let wl = s.len().min(123);
    for (i, &c) in s[..wl].iter().enumerate() {
        u16b[i * 2..i * 2 + 2].copy_from_slice(&(c as u16).to_le_bytes());
    }
    if !write_task_bytes(pml4, peb + 0x600, &u16b[..wl * 2 + 2]) {
        return false;
    }
    let cmdlen = (wl * 2) as u16;
    let cmdptr = peb + 0x600;
    // UNICODE_STRING is {u16 len, u16 maxlen, pad, *ptr} — pack it.
    let mut usb = [0u8; 16];
    usb[0..2].copy_from_slice(&cmdlen.to_le_bytes());
    usb[2..4].copy_from_slice(&(cmdlen + 2).to_le_bytes());
    usb[8..16].copy_from_slice(&cmdptr.to_le_bytes());
    write_task_bytes(pml4, params + 0x80, &usb)
}

/// Block the current task on an NT process object (ledger idx):
/// same abandoned-kernel-frame wake model as nt_wait_block. The
/// entry's tgid is recorded so a freed-and-reallocated slot can't
/// satisfy the wait (a sibling closing the last handle mid-wait).
pub fn nt_wait_block_proc(ctx: &mut UCtx, idx: usize, deadline_ticks: u64) -> ! {
    let tgid = unsafe { &*core::ptr::addr_of!(NT_PROCS) }
        .get(idx)
        .map(|e| e.0)
        .unwrap_or(0);
    if let Some(t) = cur_mut() {
        t.wait_on = WaitOn::NtWaitProc(idx, tgid);
        t.wait_deadline = deadline_ticks;
        t.ctx = *ctx;
        t.state = TaskState::Blocked;
    }
    block_switch()
}

/// Free entries remain in the thread ledger — CreateProcess
/// prechecks it alongside the process table.
fn nt_thr_slot_free() -> bool {
    let tab = unsafe { &*core::ptr::addr_of!(NT_THREADS) };
    tab.iter().any(|e| e.4 == 0)
}

// ---- NT section objects + mapped views ---------------------------
// CreateFileMapping's backing object. A section names an OFD (or
// nothing for pagefile-backed SEC_COMMIT) and survives via handle
// refs only — a mapped VIEW self-contains its write-back target
// (oi + file offset) so it needs no section alive at unmap.
const NT_MAX_SECTIONS: usize = 16;
/// (oi_or_0xFF, max_size, win32prot, state, refs) — 0=free 1=live.
static mut NT_SECTIONS: [(u64, u64, u8, u8, u8); NT_MAX_SECTIONS] =
    [(0xff, 0, 0, 0, 0); NT_MAX_SECTIONS];

pub fn nt_sec_new(oi: u64, size: u64, prot: u8) -> Option<usize> {
    let tab = unsafe { &mut *core::ptr::addr_of_mut!(NT_SECTIONS) };
    let i = tab.iter().position(|e| e.3 == 0)?;
    tab[i] = (oi, size, prot, 1, 0);
    Some(i)
}

/// Clear a section slot outright — used when handle allocation
/// fails before the entry ever gains a ref.
pub fn nt_sec_free(idx: usize) {
    let tab = unsafe { &mut *core::ptr::addr_of_mut!(NT_SECTIONS) };
    if let Some(e) = tab.get_mut(idx) {
        *e = (0xff, 0, 0, 0, 0);
    }
}

/// (oi_or_0xFF, size, prot) for a live ledger index.
pub fn nt_sec_get(idx: usize) -> Option<(u64, u64, u8)> {
    let tab = unsafe { &*core::ptr::addr_of!(NT_SECTIONS) };
    let e = *tab.get(idx)?;
    (e.3 != 0).then_some((e.0, e.1, e.2))
}

fn nt_sec_refdown(idx: usize) {
    let tab = unsafe { &mut *core::ptr::addr_of_mut!(NT_SECTIONS) };
    if let Some(e) = tab.get_mut(idx) {
        if e.3 != 0 {
            e.4 = e.4.saturating_sub(1);
            if e.4 == 0 {
                // The section's OFD pin dies with it — a file-backed
                // section released its handle for good.
                let oi = e.0;
                *e = (0xff, 0, 0, 0, 0);
                if oi != 0xff {
                    nt_oi_release(oi as usize);
                }
            }
        }
    }
}

/// Bind a section handle in the process table; nth_fd carries the
/// NT_SECTIONS index and the entry gains one handle ref.
pub fn nt_handle_alloc_sec(idx: usize) -> Option<u64> {
    let tab = unsafe { &mut *core::ptr::addr_of_mut!(NT_SECTIONS) };
    let t = mm_owner_mut()?;
    for i in 0..crate::nt::MAX_NTH {
        if t.nth[i] == 0 {
            t.nth[i] = crate::nt::NTH_SECTION;
            t.nth_fd[i] = idx as u8;
            tab[idx].4 = tab[idx].4.saturating_add(1);
            return Some(i as u64 + 1);
        }
    }
    None
}

/// The NT_SECTIONS index an NTH_SECTION handle names.
pub fn nt_handle_sec_idx(h: u64) -> Option<usize> {
    let t = mm_owner_mut()?;
    if h == 0 || h > crate::nt::MAX_NTH as u64 {
        return None;
    }
    let i = h as usize - 1;
    (t.nth[i] == crate::nt::NTH_SECTION).then_some(t.nth_fd[i] as usize)
}

/// Resolve an NTH_FILE handle to (ofd_index, accmode) and bump the
/// OFD's refcount — the section/view holds the ref until released.
pub fn nt_handle_file_oi(h: u64) -> Option<(usize, u8)> {
    let fd = nt_handle_fd(h)?;
    let t = mm_owner_mut()?;
    let oi = *fdt(t).fds.get(fd as usize)?.as_ref()? as usize;
    let o = unsafe { (*core::ptr::addr_of_mut!(OFDS)).get_mut(oi)?.as_mut()? };
    let ram_or_ro = matches!(o.kind, FdKind::File(_) | FdKind::Ram(_));
    if !ram_or_ro {
        return None;
    }
    o.refs += 1;
    Some((oi, o.accmode))
}

/// (content_ptr, len, is_ram) for a live OFD's backing bytes.
fn ofd_content(oi: usize) -> Option<(*const u8, usize, bool)> {
    let o = unsafe { &*core::ptr::addr_of!(OFDS) }.get(oi)?.as_ref()?;
    match &o.kind {
        FdKind::File(d) => Some((d.as_ptr(), d.len(), false)),
        FdKind::Ram(i) => {
            let v = vfile(*i)?;
            Some((v.data as *const u8, v.len, true))
        }
        _ => None,
    }
}

/// Drop the ref nt_handle_file_oi/nt_view_add bumped on `oi`.
pub fn nt_oi_release(oi: usize) {
    ofd_release(oi);
}

/// Bump OFD `oi`'s refcount — a mapped view's own ref, held until
/// unmap so its write-back target can't die mid-flight.
pub fn nt_oi_addref(oi: usize) -> bool {
    let Some(o) =
        unsafe { &mut *core::ptr::addr_of_mut!(OFDS) }.get_mut(oi).and_then(|s| s.as_mut())
    else {
        return false;
    };
    o.refs += 1;
    true
}

/// Current content length of OFD `oi` — the section's natural size
/// when MaximumSize is NULL.
pub fn nt_oi_len(oi: usize) -> u64 {
    ofd_content(oi).map(|(_, l, _)| l as u64).unwrap_or(0)
}

/// Copy `n` bytes of OFD `oi`'s content at `off` into the committed
/// user VA `dst` (bounds clamped to the file length). Returns the
/// byte count actually copied — the tail beyond EOF stays zeroed.
pub fn nt_oi_copyin(oi: usize, off: u64, dst: u64, n: u64) -> usize {
    let Some((p, len, _)) = ofd_content(oi) else { return 0 };
    let avail = (len as u64).saturating_sub(off);
    let n = core::cmp::min(n, avail) as usize;
    if n == 0 {
        return 0;
    }
    // Route through the physical frame: a PAGE_READONLY view's PTEs
    // deny the kernel's VA write too (CR0.WP), exactly like the PE
    // loader's read-only section fill — write_task_bytes_force is
    // that same folio-fill privilege.
    let src = unsafe { core::slice::from_raw_parts(p.add(off as usize), n) };
    let pml4 = mm_owner_mut().map(|t| t.pml4).unwrap_or(0);
    if pml4 == 0 || !write_task_bytes_force(pml4, dst, src) {
        return 0;
    }
    n
}

/// Per-process view ledger: (owner_pid, base, va_size, oi_or_0xFF,
/// file_off, file_span, writable, write_back, state). va_size is the
/// committed window (page-rounded); file_span is the count of bytes
/// that name file content — the write-back bound, so a page-round
/// tail can never grow the file. A view's write-back path reads the
/// user VA at unmap/flush and writes it into the file —
/// FILE_MAP_COPY views set write_back=0 and are discard-on-unmap.
const NT_MAX_VIEWS: usize = 16;
static mut NT_VIEWS: [(u64, u64, u64, u64, u64, u64, u8, u8, u8); NT_MAX_VIEWS] =
    [(0, 0, 0, 0, 0, 0, 0, 0, 0); NT_MAX_VIEWS];

/// The process id of the current task's address-space owner.
fn nt_owner_pid() -> u64 {
    mm_owner_i()
        .and_then(|i| unsafe { &*core::ptr::addr_of!(TASKS) }[i].as_ref())
        .map(|t| t.pid)
        .unwrap_or(0)
}

/// Reclaim view entries whose owner process is fully gone — dead
/// owners can never unmap, so their OFD refs and slots leak until
/// the next map sweeps (same lazy pattern as thread windows).
fn nt_view_gc() {
    let tasks = unsafe { &*core::ptr::addr_of!(TASKS) };
    let tab = unsafe { &mut *core::ptr::addr_of_mut!(NT_VIEWS) };
    for e in tab.iter_mut() {
        if e.8 == 0 {
            continue;
        }
        let alive = tasks.iter().flatten().any(|t| t.pid == e.0);
        if !alive {
            if e.3 != 0xff {
                nt_oi_release(e.3 as usize);
            }
            *e = (0, 0, 0, 0, 0, 0, 0, 0, 0);
        }
    }
}

/// Record a fresh view; OFD ref was bumped by the caller.
/// `file_span` is the file-byte count the view names (bounded by
/// the section), distinct from the page-rounded `va_size`.
pub fn nt_view_add(
    base: u64,
    va_size: u64,
    oi: u64,
    off: u64,
    file_span: u64,
    wr: bool,
    wb: bool,
) -> bool {
    nt_view_gc();
    let owner = nt_owner_pid();
    let tab = unsafe { &mut *core::ptr::addr_of_mut!(NT_VIEWS) };
    let Some(i) = tab.iter().position(|e| e.8 == 0) else { return false };
    tab[i] = (owner, base, va_size, oi, off, file_span, wr as u8, wb as u8, 1);
    true
}

/// Write a write-back view's dirty bytes into its file: grow the
/// VFile to cover [file_off, file_off+file_span) then copy the
/// user VA over it. No-op for anonymous/readonly views.
fn nt_view_writeback(e: (u64, u64, u64, u64, u64, u64, u8, u8, u8)) {
    if e.3 == 0xff || e.7 == 0 || e.5 == 0 {
        return;
    }
    let oi = e.3 as usize;
    let vi = match unsafe { &*core::ptr::addr_of!(OFDS) }
        .get(oi)
        .and_then(|s| s.as_ref())
        .map(|o| &o.kind)
    {
        Some(FdKind::Ram(vi)) => *vi,
        _ => return, // initrd slices are immutable — RO/COPY only
    };
    let Some(v) = vfile(vi) else { return };
    let Some(need) = e.4.checked_add(e.5).map(|x| x as usize) else { return };
    if vfile_grow(v, need) != 0 {
        return;
    }
    // SAFETY: v.data owns `need` bytes post-grow; the source is the
    // view's committed window under the current (shared) cr3.
    unsafe {
        core::ptr::copy_nonoverlapping(e.1 as *const u8, v.data.add(e.4 as usize), e.5 as usize)
    };
    v.len = v.len.max(need);
}

/// Unmap the view at `base` for the current process: write back if
/// the view asks, free the VA window on the owner's ledger, drop
/// the OFD ref, free the entry. Returns false for no such view.
pub fn nt_view_unmap(base: u64) -> bool {
    let owner = nt_owner_pid();
    let tab = unsafe { &mut *core::ptr::addr_of_mut!(NT_VIEWS) };
    let Some(i) = tab.iter().position(|e| e.8 != 0 && e.0 == owner && e.1 == base) else {
        return false;
    };
    let e = tab[i];
    tab[i] = (0, 0, 0, 0, 0, 0, 0, 0, 0);
    nt_view_writeback(e);
    nt_free_pages(e.1, e.2);
    if e.3 != 0xff {
        nt_oi_release(e.3 as usize);
    }
    true
}

/// Flush any write-back views intersecting [base, base+size).
/// size==0 with base inside a view names "the whole view" (the
/// FlushViewOfFile(p,0) form); (0,0) flushes all of them.
pub fn nt_view_flush(base: u64, size: u64) {
    let owner = nt_owner_pid();
    let tab = unsafe { &mut *core::ptr::addr_of_mut!(NT_VIEWS) };
    for i in 0..NT_MAX_VIEWS {
        let e = tab[i];
        if e.8 == 0 || e.0 != owner || e.7 == 0 {
            continue;
        }
        let hit = if size == 0 {
            base == 0 || (base >= e.1 && base < e.1 + e.2)
        } else {
            base < e.1 + e.2 && e.1 < base.saturating_add(size)
        };
        if hit {
            nt_view_writeback(e);
        }
    }
}

/// CreateThread's kernel half: a CLONE_VM|THREAD-shaped child on the
/// shared pml4 with its own kernel stack, user stack, TEB and TLS
/// copy. Returns (NT_THREADS index, tid) or None on failure.
/// `cflags` understands CREATE_SUSPENDED (4) only — everything else
/// fails honestly.
pub fn nt_thread_create(
    ctx: &mut UCtx,
    start: u64,
    param: u64,
    cflags: u64,
    stack_sz: u64,
) -> Option<(usize, u64)> {
    if !(elf::USER_VA_LO..elf::USER_VA_HI).contains(&start) || cflags & !4 != 0 {
        return None;
    }
    reap_dead_threads();
    let cur = unsafe { *core::ptr::addr_of!(CUR_I) };
    let tasks = unsafe { &mut *core::ptr::addr_of_mut!(TASKS) };
    let Some(slot) = tasks.iter().position(Option::is_none) else {
        return None;
    };
    let p = tasks.get_mut(cur)?.as_mut()?;
    let ks = kalloc::kmalloc(KSTACK_SIZE) as u64;
    if ks == 0 {
        return None;
    }
    if !mm_share(p.pml4) {
        unsafe { kalloc::kfree(ks as *mut u8) };
        return None;
    }
    // Threads share every refcounted table: files, signal
    // dispositions, fs root/cwd (the CLONE_FILES|SIGHAND|FS shape
    // CLONE_THREAD implies).
    sigtab_share(p.sigh);
    let csigh = p.sigh;
    fdtab_share(p.fdi);
    let cfdi = p.fdi;
    fstab_share(p.fsi);
    let cfsi = p.fsi;
    // First: reclaim dead threads' VA windows on THIS task's ledger —
    // a dead thread's task slot is reaped but its shared-mm pages
    // and range entries persist until the owner frees them here.
    {
        let tab = unsafe { &mut *core::ptr::addr_of_mut!(NT_THREADS) };
        for e in tab.iter_mut() {
            if e.8 == p.pid && e.4 == 2 && e.6 != 0 {
                nt_free_pages(e.6, e.7);
                e.6 = 0;
                e.7 = 0;
            }
        }
    }
    // Stack + TEB + TLS copy land in ONE contiguous window in the
    // shared address space — a single range-ledger entry per live
    // thread, allocated before the Task build so the child's copied
    // ledger already covers its own stack probes.
    let (rfl, pfl) = (RNG_R | RNG_W, USER | WRITE | NX);
    let ssz = if stack_sz == 0 { 0x1_0000 } else { stack_sz };
    let ssz = ssz.clamp(0x1000, 0x10_0000) & !0xfff;
    let tls_sz = (p.tls_tmpl_sz + 0xfff) & !0xfff;
    let total = ssz + 0x1000 + tls_sz;
    let Some(win) = nt_alloc_pages(0, total, true, rfl, pfl) else {
        fstab_release(cfsi);
        fdtab_release(cfdi);
        sigtab_release(csigh);
        mm_release(p.pml4);
        unsafe { kalloc::kfree(ks as *mut u8) };
        return None;
    };
    let (stack, teb) = (win, win + ssz);
    let tls_pg = if tls_sz != 0 { win + ssz + 0x1000 } else { 0 };
    let mut c = Task {
        pml4: p.pml4,
        entry: p.entry,
        stack_top: stack + ssz,
        kstack_base: ks,
        kstack_top: ks + KSTACK_SIZE as u64,
        ranges: p.ranges,
        nranges: p.nranges,
        brk_base: p.brk_base,
        brk_cur: p.brk_cur,
        fdi: cfdi,
        sigh: csigh,
        fsi: cfsi,
        tgid: p.tgid,
        ctx: {
            let mut x = *ctx;
            // Threads start on the emitted trampoline (DllMain
            // THREAD_ATTACH -> start_fn -> THREAD_DETACH -> exit);
            // rcx=start_fn, rdx=param there. A missing trampoline
            // (older/no stub) falls back to the bare start.
            x.rip = if p.thr_entry_va != 0 {
                x.rcx = start;
                x.rdx = param;
                p.thr_entry_va
            } else {
                x.rcx = param;
                start
            };
            x.rsp = stack + ssz - 8;
            x.rax = 0;
            x
        },
        state: if cflags & 4 != 0 {
            TaskState::Blocked
        } else {
            TaskState::Runnable
        },
        pid: next_pid(),
        ppid: p.ppid,
        exit_status: 0,
        wait_on: if cflags & 4 != 0 {
            WaitOn::NtSuspend
        } else {
            WaitOn::None
        },
        wait_ptr: 0,
        wait_ptr2: 0,
        wait_ptr3: 0,
        psel_mask: u64::MAX,
        frame_mask: u64::MAX,
        wait_len: 0,
        wait_deadline: 0,
        pending: 0,
        pend_src: [SIGSRC_NONE; 31],
        sigmask: p.sigmask,
        fx: p.fx,
        name: p.name,
        exe: p.exe,
        exe_len: p.exe_len,
        fs_base: p.fs_base,
        rseq_va: 0,
        clear_ctid: 0,
        pgid: p.pgid,
        sid: p.sid,
        did_exec: false,
        pers: p.pers,
        gs_base: teb,
        // Windows handles are process objects: the table lives on
        // the leader only (mm_owner routes there), so a thread's
        // own nth must stay empty — a copied snapshot could be
        // consulted by nothing but would look alive.
        nth: [0; crate::nt::MAX_NTH],
        nth_fd: [0xff; crate::nt::MAX_NTH],
        nth_dirpat: [[0; 96]; crate::nt::MAX_NTH],
        heap_blk: p.heap_blk,
        heap_bump: p.heap_bump,
        heap_commit: p.heap_commit,
        nt_alloc: p.nt_alloc,
        tls_tmpl_va: p.tls_tmpl_va,
        tls_tmpl_sz: p.tls_tmpl_sz,
        thr_exit_va: p.thr_exit_va,
        thr_entry_va: p.thr_entry_va,
        nt_stub: p.nt_stub,
        stop_sig: 0,
        cont_report: false,
        start_ticks: crate::apic::TICKS.load(core::sync::atomic::Ordering::Relaxed),
        utime: 0,
        stime: 0,
        cmdline: p.cmdline,
        cmdline_len: p.cmdline_len,
    };
    let tid = c.pid;
    // Synthetic return address: start_fn "returns" into the
    // thread-exit stub -> NtTerminateThread(0, rax).
    let pml4 = p.pml4;
    let okw = write_task_bytes(pml4, c.ctx.rsp, &p.thr_exit_va.to_le_bytes())
        // TEB: Self @0x30, ClientId (pid,tid) @0x40/0x48, TLS slots
        // ptr @0x58 -> teb+0x200, PEB @0x60, lasterr @0x68.
        && write_task_bytes(pml4, teb + 0x30, &teb.to_le_bytes())
        && write_task_bytes(pml4, teb + 0x40, &p.tgid.to_le_bytes())
        && write_task_bytes(pml4, teb + 0x48, &tid.to_le_bytes())
        && write_task_bytes(pml4, teb + 0x58, &(teb + 0x200).to_le_bytes())
        && write_task_bytes(pml4, teb + 0x60, &crate::pe::PEB_VA.to_le_bytes());
    if !okw {
        nt_free_pages(win, total);
        fstab_release(cfsi);
        fdtab_release(cfdi);
        sigtab_release(csigh);
        mm_release(pml4);
        unsafe { kalloc::kfree(ks as *mut u8) };
        return None;
    }
    // Per-thread copy of the PE .tls template into the TLS page;
    // slot 0 names it (compiled __thread reads gs:[0x58] -> [0]).
    if tls_pg != 0 {
        let mut i = 0u64;
        let mut cp_ok = true;
        while i < p.tls_tmpl_sz {
            let w = read_task_u64(pml4, p.tls_tmpl_va + i).unwrap_or(0);
            if !write_task_bytes(pml4, tls_pg + i, &w.to_le_bytes()) {
                cp_ok = false;
                break;
            }
            i += 8;
        }
        if !cp_ok || !write_task_bytes(pml4, teb + 0x200, &tls_pg.to_le_bytes()) {
            nt_free_pages(win, total);
            fstab_release(cfsi);
            fdtab_release(cfdi);
            sigtab_release(csigh);
            mm_release(pml4);
            unsafe { kalloc::kfree(ks as *mut u8) };
            return None;
        }
    }
    let Some(idx) = nt_thr_alloc(p.tgid, tid, teb, win, total, p.pid) else {
        nt_free_pages(win, total);
        fstab_release(cfsi);
        fdtab_release(cfdi);
        sigtab_release(csigh);
        mm_release(pml4);
        unsafe { kalloc::kfree(ks as *mut u8) };
        return None;
    };
    c.stack_top = c.ctx.rsp;
    tasks[slot] = Some(c);
    PROCS_CREATED.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    Some((idx, tid))
}

/// Read one aligned qword out of a task's address space (the TLS
/// template copy reads the shared mm).
fn read_task_u64(pml4: u64, va: u64) -> Option<u64> {
    let mut v = 0u64;
    for i in 0..8u64 {
        let pa = translate_r(pml4, va + i)?;
        // SAFETY: pa is a present user frame in pml4.
        v |= ((unsafe { (pa as *const u8).read() }) as u64) << (i * 8);
    }
    Some(v)
}

/// (size, OFD position, is-dir) for an open fd — the
/// QueryInformationFile backing data.
pub fn nt_file_info(fd: u64) -> Option<(u64, u64, bool)> {
    let t = cur_mut()?;
    let o = ofd(t, fd)?;
    let (_, size, _) = ofd_stat_shape(&o.kind);
    Some((size, o.pos as u64, matches!(o.kind, FdKind::Dir(_))))
}

/// Set or clear the delete-pending flag on fd's OFD — Windows
/// FileDispositionInformation. Only regular vfiles can die;
/// the flag is ignored elsewhere.
pub fn nt_fd_delete_pending(fd: u64, on: bool) -> bool {
    let Some(t) = cur_mut() else { return false };
    let Some(&oi) = fdt(t).fds.get(fd as usize).and_then(|s| s.as_ref())
    else {
        return false;
    };
    unsafe { OFD_DEL[oi as usize] = on as u8 };
    true
}

/// Windows wildcard match: `*` any run, `?` one char, ASCII
/// case-insensitive — the FindFirstFile pattern language. An
/// empty pattern matches everything.
fn wild_match(pat: &[u8], name: &[u8]) -> bool {
    let (mut p, mut s, mut star, mut mark) =
        (0usize, 0usize, usize::MAX, 0usize);
    while s < name.len() {
        if p < pat.len()
            && (pat[p] == b'?'
                || pat[p].to_ascii_lowercase() == name[s].to_ascii_lowercase())
        {
            p += 1;
            s += 1;
        } else if p < pat.len() && pat[p] == b'*' {
            star = p;
            mark = s;
            p += 1;
        } else if star != usize::MAX {
            p = star + 1;
            mark += 1;
            s = mark;
        } else {
            return false;
        }
    }
    while p < pat.len() && pat[p] == b'*' {
        p += 1;
    }
    p == pat.len()
}

/// Store the FileName wildcard an NtQueryDirectoryFile carried on
/// dir handle `h` — later pattern-less calls reuse it.
pub fn nt_dir_pattern_set(h: u64, pat: &[u8]) {
    let Some(t) = mm_owner_mut() else { return };
    let i = h as usize;
    if i == 0
        || i > crate::nt::MAX_NTH
        || t.nth[i - 1] != crate::nt::NTH_FILE
        || pat.len() > 95
    {
        return;
    }
    t.nth_dirpat[i - 1][0] = pat.len() as u8;
    t.nth_dirpat[i - 1][1..1 + pat.len()].copy_from_slice(pat);
}

/// Copy the stored wildcard out; 0 len when unset — wild_match
/// treats that as match-all, which is the right default anyway.
pub fn nt_dir_pattern(h: u64, out: &mut [u8; 96]) -> usize {
    let Some(t) = mm_owner_mut() else { return 0 };
    let i = h as usize;
    if i == 0 || i > crate::nt::MAX_NTH || t.nth[i - 1] != crate::nt::NTH_FILE
    {
        return 0;
    }
    let n = (t.nth_dirpat[i - 1][0] as usize).min(95);
    out[..n].copy_from_slice(&t.nth_dirpat[i - 1][1..1 + n]);
    n
}

/// The dir OFD's stream cursor — None for non-dirs.
pub fn nt_dir_pos(fd: u64) -> Option<usize> {
    let t = cur_mut()?;
    let o = ofd(t, fd)?;
    matches!(o.kind, FdKind::Dir(_)).then_some(o.pos)
}

/// Seek the dir stream — RestartScan resets it to 0.
pub fn nt_dir_seek(fd: u64, pos: usize) {
    let Some(t) = cur_mut() else { return };
    let Some(o) = ofd(t, fd) else { return };
    if matches!(o.kind, FdKind::Dir(_)) {
        o.pos = pos;
    }
}

/// The first entry at stream index >= idx matching the wildcard:
/// the same first-component enumeration getdents64 synthesizes,
/// minus the /proc pid expansion (POSIX-side only). Does not move
/// the cursor — the caller commits it via nt_dir_seek once the
/// record actually fit the user buffer. Returns (name bytes, size,
/// is_dir, next_idx).
pub fn nt_dir_next(
    fd: u64,
    idx: usize,
    pat: &[u8],
    out: &mut [u8; 256],
) -> Option<(usize, u64, bool, usize)> {
    let t = cur_mut()?;
    let o = ofd(t, fd)?;
    let FdKind::Dir(dp) = &o.kind else { return None };
    let dpath = dp.bytes();
    let mut names: [Option<&[u8]>; 384] = [None; 384];
    names[0] = Some(b".");
    names[1] = Some(b"..");
    let mut n = 2usize;
    dir_add(dpath, &mut names, &mut n, b"proc");
    dir_add(dpath, &mut names, &mut n, b"proc/self");
    dir_add(dpath, &mut names, &mut n, b"proc/self/exe");
    if let Some(arc) = unsafe { *core::ptr::addr_of!(INITRD) } {
        for (name, _) in crate::cpio::entries(arc) {
            dir_add(dpath, &mut names, &mut n, name);
        }
    }
    for v in unsafe { &*core::ptr::addr_of!(VFILES) }.iter().flatten() {
        if !v.unlinked {
            dir_add(dpath, &mut names, &mut n, &v.name[..v.nlen]);
        }
    }
    for d in unsafe { &*core::ptr::addr_of!(VDIRS) }.iter().flatten() {
        dir_add(dpath, &mut names, &mut n, &d.path[..d.nlen]);
    }
    let mut i = idx;
    while i < n {
        let name = names[i]?;
        i += 1;
        if name.len() > 250 || !wild_match(pat, name) {
            continue;
        }
        // Same probes getdents uses for type: canonical full path,
        // dir_exists, then a size lookup (vfiles first, archive).
        let mut full = [0u8; 256];
        let mut fn_ = dpath.len();
        if fn_ + 1 + name.len() > 256 {
            continue;
        }
        full[..fn_].copy_from_slice(dpath);
        if fn_ > 0 {
            full[fn_] = b'/';
            fn_ += 1;
        }
        full[fn_..fn_ + name.len()].copy_from_slice(name);
        fn_ += name.len();
        let full = &full[..fn_];
        let isdir = i - 1 < 2 || dir_exists(full);
        let size = if isdir {
            0
        } else if let Some(v) = vfile_find(full).and_then(vfile) {
            v.len as u64
        } else if let Some(arc) = unsafe { *core::ptr::addr_of!(INITRD) }
        {
            crate::cpio::find(arc, full).map_or(0, |d| d.len() as u64)
        } else {
            0
        };
        out[..name.len()].copy_from_slice(name);
        return Some((name.len(), size, isdir, i));
    }
    None
}

/// NtWriteFile on a console handle — the same printk path
/// sys_write's Console arm uses, minus POSIX job-control gates
/// (NT tasks carry no pgrp).
pub fn nt_console_write(_ctx: &mut UCtx, buf: u64, len: u64) -> u64 {
    if len == 0 {
        return 0;
    }
    if len > 4096 || !range_ok(buf, len) {
        return 0;
    }
    let s = unsafe { core::slice::from_raw_parts(buf as *const u8, len as usize) };
    match core::str::from_utf8(s) {
        Ok(txt) => crate::log::printk(format_args!("{txt}")),
        Err(_) => crate::log::printk(format_args!("rustux: nt write: {len}B non-utf8")),
    }
    len
}

/// NtReadFile on the stdin handle — shares the ldisc queue with
/// fd 0. Returns (NTSTATUS, bytes); a block parks ctx inside
/// tty_input_read exactly like a Linux read() would.
pub fn nt_stdin_read(ctx: &mut UCtx, buf: u64, len: u64) -> (u64, u64) {
    if len > 0 && !range_ok_w(buf, len) {
        return (crate::nt::STATUS_ACCESS_VIOLATION, 0);
    }
    let Some(t) = cur_mut() else {
        return (crate::nt::STATUS_END_OF_FILE, 0);
    };
    // tty_input_read returns a count, a negative-errno u64, or parks
    // ctx and switches away on an empty queue. NT reads have no
    // POSIX signal layer to interrupt them, so the only non-count
    // outcome that can surface is a fault pre-check — already done.
    let n = tty_input_read(t, ctx, buf, len);
    if n == 0 {
        return (crate::nt::STATUS_END_OF_FILE, 0);
    }
    if n > i32::MAX as u64 {
        // -errno leaked through (unreachable for NT tasks: no
        // deliverable POSIX signals, buf pre-validated).
        return (crate::nt::STATUS_ACCESS_VIOLATION, 0);
    }
    (crate::nt::STATUS_SUCCESS, n)
}

/// Is [va, va+size) placeable by the NT VM layer? Bounds-checked to
/// the user window, clear of the heap arena (committed or not — a
/// VirtualAlloc hint must never alias a future heap block), and
/// overlapping no existing ledger range. No pages are touched.
fn nt_place_ok(t: &Task, va: u64, size: u64) -> bool {
    if va < elf::USER_VA_LO || va + size >= elf::USER_VA_HI || va + size <= va {
        return false;
    }
    if va < crate::pe::HEAP_MAX && va + size > crate::pe::HEAP_VA {
        return false;
    }
    for i in 0..t.nranges {
        let (a, b, _) = t.ranges[i];
        if va < b && va + size > a {
            return false;
        }
    }
    true
}

/// NtAllocateVirtualMemory backing: `size` zeroed bytes at `hint`
/// if the window is free, else bump-allocate upward from
/// t.nt_alloc (the NT arena, disjoint from mmap/brk space).
/// `commit` maps pages now (`pfl` leaf flags, `rfl` ledger access);
/// otherwise the entry is RNG_RES|placeholder — VA held, no frames.
pub fn nt_alloc_pages(hint: u64, size: u64, commit: bool, rfl: u8, pfl: u64) -> Option<u64> {
    let t = mm_owner_mut()?;
    let mut va = hint & !0xfff;
    if hint == 0 || !nt_place_ok(t, va, size) {
        va = t.nt_alloc.max(NT_ALLOC_VA);
        loop {
            if va + size >= elf::USER_VA_HI || va < NT_ALLOC_VA {
                return None;
            }
            if nt_place_ok(t, va, size) {
                break;
            }
            va += size;
        }
    }
    if commit {
        let mut cur = va;
        while cur < va + size {
            map_page(t, cur, pfl)?;
            cur += PAGE;
        }
    }
    t.nt_alloc = (va + size).max(t.nt_alloc);
    if t.nranges < MAX_RANGES {
        let fl = if commit { rfl } else { RNG_RES | rfl };
        t.ranges[t.nranges] = (va, va + size, fl);
        t.nranges += 1;
        return Some(va);
    }
    // Ledger full: undo the mapping so frames don't leak.
    if commit {
        let mut cur = va;
        while cur < va + size {
            unmap_page(t, cur);
            cur += PAGE;
        }
        flush_tlb();
    }
    None
}

/// Commit [base,base+size): RNG_RES pieces inside become committed
/// (ledger split at window edges, pages mapped with `pfl`), already-
/// committed pieces are left alone (re-commit is a no-op like real
/// Windows), and unowned gaps become new committed entries — a
/// MEM_COMMIT at unreserved VA is an implicit reserve. Fails only
/// on ledger exhaustion or OOM; on OOM the earlier pieces stay
/// committed, matching the partial-success Windows also permits.
pub fn nt_commit_window(t: &mut Task, base: u64, size: u64, rfl: u8, pfl: u64) -> bool {
    let Some(end) = base.checked_add(size) else {
        return false;
    };
    if size == 0
        || base & 0xfff != 0
        || base < elf::USER_VA_LO
        || end > elf::USER_VA_HI
    {
        return false;
    }
    // The heap arena self-manages — committing inside it would
    // hand the allocator pages it never reserved.
    if base < crate::pe::HEAP_MAX && end > crate::pe::HEAP_VA {
        return false;
    }
    // Pre-flight the ledger: each overlapped RNG_RES piece can split
    // into three and each gap adds one — refuse before mutating.
    let mut need = 0usize;
    {
        let mut cur = base;
        while cur < end {
            let mut cov: Option<(u64, u64)> = None;
            let mut next_lo = end;
            for &(lo, hi, fl) in &t.ranges[..t.nranges] {
                if lo <= cur && hi > cur {
                    cov = Some((lo, hi));
                    if fl & RNG_RES != 0 {
                        // The committed piece reuses the slot — only
                        // the two possible RES remnants are new.
                        need += (lo < cur) as usize + (hi > end) as usize;
                    }
                } else if lo > cur && lo < next_lo {
                    next_lo = lo;
                }
            }
            let piece_end = cov.map(|(_, hi)| hi.min(end)).unwrap_or(next_lo);
            if cov.is_none() {
                need += 1;
            }
            cur = piece_end;
        }
    }
    if t.nranges + need > MAX_RANGES {
        return false;
    }
    let mut cur = base;
    while cur < end {
        // Find the range covering cur, if any.
        let mut i = None;
        let mut next_lo = end;
        for (j, &(lo, hi, _)) in t.ranges[..t.nranges].iter().enumerate() {
            if lo <= cur && hi > cur {
                i = Some(j);
            } else if lo > cur && lo < next_lo {
                next_lo = lo;
            }
        }
        let pend = i.map_or(next_lo, |j| t.ranges[j].1.min(end));
        if let Some(j) = i {
            let (lo, hi, fl) = t.ranges[j];
            if fl & RNG_RES != 0 {
                // Map first — a mapped-but-still-RES page is an
                // inconsistent ledger; on OOM unwind what's mapped.
                let mut va = cur;
                while va < pend {
                    if map_page(t, va, pfl).is_none() {
                        let mut u = cur;
                        while u < va {
                            unmap_page(t, u);
                            u += PAGE;
                        }
                        flush_tlb();
                        return false;
                    }
                    va += PAGE;
                }
                let res = RNG_RES | (fl & !RNG_RES);
                t.ranges[j] = (cur, pend, rfl);
                if lo < cur {
                    t.ranges[t.nranges] = (lo, cur, res);
                    t.nranges += 1;
                }
                if hi > pend {
                    t.ranges[t.nranges] = (pend, hi, res);
                    t.nranges += 1;
                }
            }
        } else {
            let mut va = cur;
            while va < pend {
                if map_page(t, va, pfl).is_none() {
                    let mut u = cur;
                    while u < va {
                        unmap_page(t, u);
                        u += PAGE;
                    }
                    flush_tlb();
                    return false;
                }
                va += PAGE;
            }
            t.ranges[t.nranges] = (cur, pend, rfl);
            t.nranges += 1;
        }
        cur = pend;
    }
    range_compact(t);
    true
}

/// Decommit [base,base+size): every ledger piece in the window must
/// exist (a gap is STATUS_MEMORY_NOT_ALLOCATED upstream); committed
/// pieces drop their pages and become RNG_RES keeping their access
/// bits as placeholder, reserved pieces are a no-op — matching
/// Windows, where decommitting a decommitted page succeeds.
pub fn nt_decommit_window(t: &mut Task, base: u64, size: u64) -> bool {
    let Some(end) = base.checked_add(size) else {
        return false;
    };
    if size == 0
        || base & 0xfff != 0
        || base < elf::USER_VA_LO
        || end > elf::USER_VA_HI
    {
        return false;
    }
    // The heap arena self-manages like everywhere else — a
    // decommit would leave HeapAlloc handing out unmapped pages
    // marked RNG_RES.
    if base < crate::pe::HEAP_MAX && end > crate::pe::HEAP_VA {
        return false;
    }
    if !range_covered(t, base, end) {
        return false;
    }
    // Same split worst case as protect: bounded first, mutate after.
    if protect_entry_count(t, base, end) > MAX_RANGES {
        return false;
    }
    let mut va = base;
    while va < end {
        unmap_page(t, va);
        va += PAGE;
    }
    // unmap_page doesn't invlpg — the mm stays live across sibling
    // threads and the caller's own VA window, so one flush here.
    flush_tlb();
    for i in 0..t.nranges {
        let (lo, hi, fl) = t.ranges[i];
        if lo >= end || hi <= base || fl & RNG_RES != 0 {
            continue;
        }
        let res = RNG_RES | fl;
        if lo < base && hi > end {
            t.ranges[i] = (base, end, res);
            t.ranges[t.nranges] = (lo, base, fl);
            t.nranges += 1;
            t.ranges[t.nranges] = (end, hi, fl);
            t.nranges += 1;
        } else if lo < base {
            t.ranges[i] = (base, hi.min(end), res);
            t.ranges[t.nranges] = (lo, base, fl);
            t.nranges += 1;
        } else if hi > end {
            t.ranges[i] = (lo.max(base), end, res);
            t.ranges[t.nranges] = (end, hi, fl);
            t.nranges += 1;
        } else {
            t.ranges[i] = (lo, hi, res);
        }
    }
    range_compact(t);
    true
}

/// nt_commit_window on the current task.
pub fn nt_commit_window_cur(base: u64, size: u64, rfl: u8, pfl: u64) -> bool {
    mm_owner_mut().is_some_and(|t| nt_commit_window(t, base, size, rfl, pfl))
}

/// nt_decommit_window on the current task.
pub fn nt_decommit_window_cur(base: u64, size: u64) -> bool {
    mm_owner_mut().is_some_and(|t| nt_decommit_window(t, base, size))
}

/// Extent of the ledger region containing `base` — for a
/// MEM_RELEASE whose caller passed size 0 (the common form: the
/// runtime hands back only the base it was given).
pub fn nt_region_extent(base: u64) -> Option<u64> {
    let t = mm_owner_mut()?;
    t.ranges[..t.nranges]
        .iter()
        .find(|&&(lo, hi, _)| base >= lo && base < hi)
        .map(|&(_, hi, _)| hi - base)
}

/// NtFreeVirtualMemory backing: unmap every page in
/// [base, base+size). Work walks the task's mapping ledger, so it
/// is proportional to pages actually mapped — never to the
/// user-supplied extent (a u64::MAX size would otherwise walk the
/// entire user window page by page inside the IF-masked syscall
/// path, a one-syscall machine hang). Freed range entries are
/// shrunk/split rather than dropped so the reap ledger still
/// accounts for their still-mapped remnants. The nt_alloc bump
/// cursor is NOT rewound (real heaps don't reclaim VA space on
/// free either — only the frames).
pub fn nt_free_pages(base: u64, size: u64) {
    let Some(t) = mm_owner_mut() else { return };
    nt_free_pages_t(t, base, size);
}

/// nt_free_pages on an already-resolved owner task — the module
/// loader's failure unwind can't re-borrow through mm_owner_mut.
fn nt_free_pages_t(t: &mut Task, base: u64, size: u64) {
    let end = base.saturating_add(size);
    let mut i = 0;
    while i < t.nranges {
        let (lo, hi, fl) = t.ranges[i];
        if hi <= base || lo >= end {
            i += 1;
            continue;
        }
        // The heap arena is owned by HeapAlloc/HeapFree, not
        // VirtualFree — a range inside [HEAP_VA,HEAP_MAX) skips.
        if lo >= crate::pe::HEAP_VA && hi <= crate::pe::HEAP_MAX {
            i += 1;
            continue;
        }
        let mut va = lo.max(base);
        let vend = hi.min(end);
        while va < vend {
            unmap_page(t, va);
            va += PAGE;
        }
        // Adjust the entry to cover only the still-mapped
        // remainder: left remnant [lo,base), right remnant
        // [end,hi). A middle free splits the entry when the table
        // has room; if it's full we keep the wider entry —
        // over-tracking is safe (reap's unmap is idempotent),
        // under-tracking leaks frames.
        if lo < base && end < hi {
            t.ranges[i] = (lo, base, fl);
            if t.nranges < MAX_RANGES {
                t.ranges[t.nranges] = (end, hi, fl);
                t.nranges += 1;
            } else {
                t.ranges[i] = (lo, hi, fl);
            }
            i += 1;
        } else if lo < base {
            t.ranges[i].1 = base;
            i += 1;
        } else if end < hi {
            t.ranges[i].0 = end;
            i += 1;
        } else {
            t.ranges.copy_within(i + 1..t.nranges, i);
            t.nranges -= 1;
        }
    }
    // unmap_page doesn't invlpg — the freed window's old translations
    // must die before any sibling (or a later same-mm touch) can write
    // through them into recycled frames. One flush for the whole op.
    flush_tlb();
}

/// PAGE_* constant for a range's RNG flags — what NtQueryVirtualMemory
/// reports and what VirtualProtect's old-protect readback returns.
fn prot_from_rng(fl: u8) -> u32 {
    // RNG_RES rides along with placeholder access bits on reserved
    // entries — the PAGE_* value reports access, not reservation.
    let fl = fl & !RNG_RES;
    match (fl & RNG_R != 0, fl & RNG_W != 0, fl & RNG_X != 0) {
        (_, _, true) => {
            if fl & RNG_W != 0 {
                0x40 // EXECUTE_READWRITE
            } else if fl & RNG_R != 0 {
                0x20 // EXECUTE_READ
            } else {
                0x10 // EXECUTE
            }
        }
        (true, true, false) => 0x04,  // READWRITE
        (true, false, false) => 0x02, // READONLY
        (false, true, false) => 0x04, // degenerate W-only → RW
        (false, false, false) => 0x01, // NOACCESS
    }
}

/// RNG flags + PTE leaf flags for a PAGE_* protection value.
/// Modifier bits (GUARD/NOCACHE/WRITECOMBINE) are stripped — we
/// honor the base protection only; unknown bases fail honestly.
pub fn rng_from_prot(prot: u32) -> Option<(u8, u64)> {
    match prot & 0xff {
        0x01 => Some((0, 0)),                        // NOACCESS
        0x02 => Some((RNG_R, USER | NX)),            // READONLY
        0x04 | 0x08 => Some((RNG_R | RNG_W, USER | WRITE | NX)),
        0x10 => Some((RNG_X, USER)),                 // EXECUTE
        0x20 => Some((RNG_R | RNG_X, USER)),         // EXECUTE_READ
        0x40 | 0x80 => Some((RNG_R | RNG_W | RNG_X, USER | WRITE)),
        _ => None,
    }
}

/// Fill a 48-byte MEMORY_BASIC_INFORMATION at `buf` (validated
/// writable by the syscall layer) describing `base` against the
/// ranges ledger: committed range fields, or MEM_FREE up to the
/// next registered region.
pub fn nt_query_vm(base: u64, buf: u64) {
    let Some(t) = mm_owner_mut() else { return };
    let mut hit: Option<(u64, u64, u8)> = None;
    let mut next_lo = u64::MAX;
    for &(lo, hi, fl) in &t.ranges[..t.nranges] {
        if base >= lo && base < hi {
            hit = Some((lo, hi, fl));
        } else if lo > base && lo < next_lo {
            next_lo = lo;
        }
    }
    let w = |off: u64, v: u64| {
        // SAFETY: buf's 48B window was write-validated by the caller.
        unsafe { ((buf + off) as *mut u64).write_unaligned(v) }
    };
    match hit {
        Some((lo, hi, fl)) => {
            let p = prot_from_rng(fl) as u64;
            w(0x00, lo);
            w(0x08, lo);
            w(0x10, p); // AllocationProtect (low u32)
            w(0x18, hi - lo);
            if fl & RNG_RES != 0 {
                // Reserved: state MEM_RESERVE, page Protect 0.
                w(0x20, 0x2000);
            } else {
                w(0x20, 0x1000 | (p << 32)); // MEM_COMMIT | Protect
            }
            w(0x28, 0x2_0000); // MEM_PRIVATE
        }
        None => {
            let lo = base & !0xfff;
            let hi = if next_lo == u64::MAX {
                elf::USER_VA_HI
            } else {
                next_lo
            };
            w(0x00, lo);
            w(0x08, 0);
            w(0x10, 0);
            w(0x18, hi.saturating_sub(lo));
            w(0x20, 0x10000); // MEM_FREE, Protect 0
            w(0x28, 0);
        }
    }
}

/// NtProtectVirtualMemory workhorse: page-align [base,base+size),
/// require full committed coverage, write the old protection of the
/// first range to `old_ptr` (validated by the caller), then rewrite
/// every leaf PTE and the range flags. The heap arena self-manages
/// and is rejected outright.
pub fn nt_protect_vm(base: u64, size: u64, prot: u32, old_ptr: u64) -> u64 {
    let Some((rfl, pfl)) = rng_from_prot(prot) else {
        return crate::nt::STATUS_INVALID_PARAMETER;
    };
    if size == 0 {
        return crate::nt::STATUS_INVALID_PARAMETER;
    }
    let Some(end) = base.checked_add(size) else {
        return crate::nt::STATUS_INVALID_PARAMETER;
    };
    let lo = base & !0xfff;
    let hi = (end + 0xfff) & !0xfff;
    if hi <= lo || lo < elf::USER_VA_LO || hi > elf::USER_VA_HI {
        return crate::nt::STATUS_INVALID_PARAMETER;
    }
    // The heap arena is HeapAlloc's — VirtualProtect doesn't apply.
    if lo < crate::pe::HEAP_MAX && hi > crate::pe::HEAP_VA {
        return crate::nt::STATUS_INVALID_PARAMETER;
    }
    let Some(t) = mm_owner_mut() else {
        return crate::nt::STATUS_INVALID_HANDLE;
    };
    if !range_committed(t, lo, hi)
        || protect_entry_count(t, lo, hi) > MAX_RANGES
    {
        return crate::nt::STATUS_MEMORY_NOT_ALLOCATED;
    }
    // Old protection = the flags of the first covered range.
    let old = t.ranges[..t.nranges]
        .iter()
        .find(|&&(rlo, rhi, _)| base >= rlo && base < rhi)
        .map(|&(_, _, fl)| prot_from_rng(fl))
        .unwrap_or(0);
    if old_ptr != 0 {
        // SAFETY: old_ptr's 4B window was write-validated upstream.
        unsafe { (old_ptr as *mut u32).write_unaligned(old) };
    }
    let mut v = lo;
    while v < hi {
        // Covered implies mapped — an absent leaf breaks the
        // invariant; fail rather than guess.
        let Some(ent) = leaf_ent(t, v) else {
            return crate::nt::STATUS_MEMORY_NOT_ALLOCATED;
        };
        let e = rd64(ent);
        wr64(ent, (e & PHYS_MASK) | pfl | PRESENT);
        v += PAGE;
    }
    range_protect(t, lo, hi, rfl);
    flush_tlb();
    crate::nt::STATUS_SUCCESS
}

/// Map heap pages up to `to` (page-rounded) and grow the registered
/// arena range so range_ok sees exactly the committed region —
/// never the reserved tail, so a bad pointer can't make the kernel
/// write an uncommitted heap page on the task's behalf.
fn heap_commit_to(t: &mut Task, to: u64) -> bool {
    let to = (to + PAGE - 1) & !(PAGE - 1);
    if to <= t.heap_commit {
        return true;
    }
    if to > crate::pe::HEAP_MAX {
        return false;
    }
    let mut va = t.heap_commit;
    while va < to {
        if map_page(t, va, USER | WRITE | NX).is_none() {
            return false;
        }
        va += PAGE;
    }
    t.heap_commit = to;
    // The committed-prefix range is found by its arena base, not a
    // cached index — nt_free_pages compacts the ledger and would
    // silently re-point any slot index we stored.
    if let Some(i) = t.ranges[..t.nranges]
        .iter()
        .position(|r| r.0 == crate::pe::HEAP_VA)
    {
        t.ranges[i].1 = to;
    } else {
        if t.nranges >= MAX_RANGES {
            return false;
        }
        t.ranges[t.nranges] = (crate::pe::HEAP_VA, to, RNG_R | RNG_W);
        t.nranges += 1;
    }
    true
}

/// HeapAlloc backing: best-fit over free blocks in the kernel block
/// table, else bump-allocate while lazily committing pages. `zero`
/// implements HEAP_ZERO_MEMORY. The arena lives at
/// [HEAP_VA,HEAP_MAX) — block metadata stays kernel-side, so heap
/// structure is unforgeable from user space.
pub fn nt_heap_alloc(size: u64, zero: bool) -> Option<u64> {
    if size >= crate::pe::HEAP_MAX - crate::pe::HEAP_VA {
        return None;
    }
    let want = size.max(1) + 15 & !15;
    let t = mm_owner_mut()?;
    let mut best = usize::MAX;
    for i in 0..t.heap_blk.len() {
        let b = t.heap_blk[i];
        if b[2] == 2
            && b[1] >= want
            && (best == usize::MAX || b[1] < t.heap_blk[best][1])
        {
            best = i;
        }
    }
    if best != usize::MAX {
        let b = t.heap_blk[best];
        let rem = b[1] - want;
        if rem >= 32 {
            // Split: this entry becomes the live `want` block, the
            // remainder lands in an empty slot — or the whole block
            // is taken when the table is full.
            if let Some(slot) =
                t.heap_blk.iter().position(|e| e[2] == 0)
            {
                t.heap_blk[best] = [b[0], want, 1];
                t.heap_blk[slot] = [b[0] + want, rem, 2];
            } else {
                t.heap_blk[best][2] = 1;
            }
        } else {
            t.heap_blk[best][2] = 1;
        }
        if zero {
            // SAFETY: inside the committed heap arena, our cr3.
            unsafe { core::ptr::write_bytes(b[0] as *mut u8, 0, want as usize) };
        }
        return Some(b[0]);
    }
    let slot = t.heap_blk.iter().position(|e| e[2] == 0)?;
    let va = t.heap_bump;
    if va + want > crate::pe::HEAP_MAX || !heap_commit_to(t, va + want) {
        return None;
    }
    t.heap_blk[slot] = [va, want, 1];
    t.heap_bump = va + want;
    if zero {
        unsafe { core::ptr::write_bytes(va as *mut u8, 0, want as usize) };
    }
    Some(va)
}

/// HeapFree: mark the live block free and coalesce with adjacent
/// free blocks — the table scan is bounded by the fixed 128 slots.
/// FALSE when `ptr` isn't a live heap block, which is also real
/// Windows' answer to an invalid or double free.
pub fn nt_heap_free(ptr: u64) -> bool {
    if ptr == 0 {
        return false;
    }
    let Some(t) = mm_owner_mut() else { return false };
    let Some(i) = t
        .heap_blk
        .iter()
        .position(|e| e[2] == 1 && e[0] == ptr)
    else {
        return false;
    };
    t.heap_blk[i][2] = 2;
    loop {
        let (a, s) = (t.heap_blk[i][0], t.heap_blk[i][1]);
        let mut merged = false;
        for j in 0..t.heap_blk.len() {
            if j == i || t.heap_blk[j][2] != 2 {
                continue;
            }
            let (ja, js) = (t.heap_blk[j][0], t.heap_blk[j][1]);
            if ja + js == a {
                t.heap_blk[i] = [ja, s + js, 2];
            } else if a + s == ja {
                t.heap_blk[i][1] = s + js;
            } else {
                continue;
            }
            t.heap_blk[j][2] = 0;
            merged = true;
            break;
        }
        if !merged {
            return true;
        }
    }
}

/// HeapSize: the live block's granted size, or None when `ptr`
/// isn't a live heap block (the thunk maps that to SIZE_T(-1)).
pub fn nt_heap_size(ptr: u64) -> Option<u64> {
    let t = mm_owner_mut()?;
    t.heap_blk
        .iter()
        .find(|e| e[2] == 1 && e[0] == ptr)
        .map(|e| e[1])
}

/// HeapReAlloc: shrink splits the tail into a free block; grow
/// absorbs the adjacent free block when it covers the delta, else
/// alloc-copy-free. `size == 0` collapses to the minimum block
/// (real Windows' treatment is implementation-defined — ours keeps
/// a valid pointer, the least surprising answer for callers that
/// use realloc(p,0) as shrink-to-fit).
pub fn nt_heap_realloc(ptr: u64, size: u64, zero: bool) -> Option<u64> {
    if ptr == 0 {
        return nt_heap_alloc(size, zero);
    }
    let want = size.max(1) + 15 & !15;
    // Shrink/grow-in-place paths return early; needing a move
    // falls through with `old` bound for the copy.
    let old = {
        let t = mm_owner_mut()?;
        let i = t.heap_blk.iter().position(|e| e[2] == 1 && e[0] == ptr)?;
        let old = t.heap_blk[i][1];
        if want <= old {
            if old - want >= 32 {
                if let Some(slot) =
                    t.heap_blk.iter().position(|e| e[2] == 0)
                {
                    t.heap_blk[slot] = [ptr + want, old - want, 2];
                    t.heap_blk[i][1] = want;
                }
            }
            return Some(ptr);
        }
        if let Some(j) = t
            .heap_blk
            .iter()
            .position(|e| e[2] == 2 && e[0] == ptr + old)
        {
            if t.heap_blk[j][1] >= want - old {
                let rem = t.heap_blk[j][1] - (want - old);
                if rem >= 32 {
                    t.heap_blk[j] = [ptr + want, rem, 2];
                    t.heap_blk[i][1] = want;
                } else {
                    t.heap_blk[i][1] = old + t.heap_blk[j][1];
                    t.heap_blk[j][2] = 0;
                }
                if zero {
                    // HEAP_ZERO_MEMORY zeroes the grown tail.
                    // SAFETY: inside the committed heap arena.
                    unsafe {
                        core::ptr::write_bytes(
                            (ptr + old) as *mut u8,
                            0,
                            (want - old) as usize,
                        )
                    };
                }
                return Some(ptr);
            }
        }
        old
    };
    let n = nt_heap_alloc(size, zero)?;
    // SAFETY: both blocks live in the committed heap arena.
    unsafe { core::ptr::copy(ptr as *const u8, n as *mut u8, old.min(size) as usize) };
    nt_heap_free(ptr);
    Some(n)
}

/// NtDelayExecution backing: pure deadline wait in 10ms ticks, the
/// WaitOn::Timer mechanism nanosleep uses. NT sleeps aren't
/// signal-interruptible on this stack.
pub fn sleep_ms(ctx: &mut UCtx, ms: u64) {
    let Some(t) = cur_mut() else { return };
    let ticks = ms.div_ceil(10);
    if ticks == 0 {
        return;
    }
    t.wait_on = WaitOn::Timer;
    t.wait_ptr = 0;
    t.wait_ptr2 = 0;
    t.wait_deadline = crate::apic::TICKS
        .load(core::sync::atomic::Ordering::Relaxed)
        .saturating_add(ticks);
    t.ctx = *ctx;
    t.state = TaskState::Blocked;
    block_switch();
}

/// read(fd, buf, len): File yields up to `len` bytes from its shared
/// position; Stdin drains the tty input queue or blocks until a key
/// feed wakes the task; Console and closed slots are EBADF.
/// The kernel validates that [buf, buf+n) is user-writable before
/// copying — checked arithmetic, no partial writes past the gate.
pub fn fd_read(ctx: &mut UCtx, fd: u64, buf: u64, len: u64) -> u64 {
    // Drain any decoded keys sitting in the scancode ring before the
    // ready check — the tick pump also runs, but a read should never
    // stall on input that's already decoded.
    stdin_pump();
    let Some(t) = cur_mut() else { return EBADF };
    let Some(o) = ofd(t, fd) else { return EBADF };
    match &o.kind {
        FdKind::Stdin => tty_input_read(t, ctx, buf, len),
        FdKind::Console => EBADF,
        FdKind::Dev(i) => {
            if o.accmode == 1 {
                return EBADF; // O_WRONLY
            }
            let Some(v) = vfile(*i) else { return EBADF };
            let (ts, tns) = now();
            v.atime = ts;
            v.atime_ns = tns;
            match v.rdev {
                // /dev/null reads EOF.
                0x103 => 0,
                // /dev/zero and /dev/full both read zeroes.
                0x105 | 0x107 => {
                    let n = len as usize;
                    if n > 0 && !range_ok_w(buf, len) {
                        return EFAULT;
                    }
                    // SAFETY: validated user window under cur cr3.
                    unsafe {
                        core::ptr::write_bytes(buf as *mut u8, 0, n)
                    };
                    n as u64
                }
                // /dev/random and /dev/urandom — ChaCha-free xorshift
                // seeded from rdtsc jitter; urandom-grade entropy is
                // honest, blocking-on-entropy is a pool we lack.
                0x108 | 0x109 => {
                    let n = len as usize;
                    if n > 0 && !range_ok_w(buf, len) {
                        return EFAULT;
                    }
                    let mut s = rng_seed();
                    for i in 0..n {
                        s ^= s << 13;
                        s ^= s >> 7;
                        s ^= s << 17;
                        // SAFETY: validated user window.
                        unsafe {
                            ((buf + i as u64) as *mut u8)
                                .write(s as u8)
                        };
                    }
                    unsafe { *core::ptr::addr_of_mut!(RNG_SEED) = s };
                    n as u64
                }
                // /dev/tty and /dev/console read the ldisc queue —
                // the same path fd 0 takes, job-control gate and all.
                0x500 | 0x501 => tty_input_read(t, ctx, buf, len),
                // Unreachable while open() whitelists rdevs — belt
                // and braces against a future arm forgetting this.
                _ => EINVAL,
            }
        }
        FdKind::Dir(_) => EISDIR,
        // read() on an epoll fd has no stream to read — EINVAL like
        // Linux, not EBADF (the fd is real).
        FdKind::Epoll(_) => EINVAL,
        FdKind::Eventfd(i) => eventfd_read(ctx, *i, buf, len),
        FdKind::Timerfd(i) => timerfd_read(ctx, *i, buf, len),
        FdKind::Signalfd(i) => signalfd_read(ctx, *i, buf, len),
        FdKind::Inotify(i) => inotify_read(ctx, *i, buf, len),
        FdKind::Udp(i) => udp_recv_or_block(ctx, *i, buf, len, 0),
        FdKind::Tcp(i) => tcp_recv_or_block(ctx, *i, buf, len, 0),
        FdKind::File(data) => {
            if o.accmode == 1 {
                return EBADF; // O_WRONLY
            }
            // pos may sit past EOF after lseek — saturating, not panicking.
            let avail = data.len().saturating_sub(o.pos);
            let n = core::cmp::min(len as usize, avail);
            if n == 0 {
                return 0;
            }
            if !range_ok_w(buf, n as u64) {
                return EFAULT;
            }
            // SAFETY: range_ok_w proved [buf, buf+n) lies in a writable
            // user range under the current (task) page table.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    data.as_ptr().add(o.pos),
                    buf as *mut u8,
                    n,
                )
            };
            o.pos += n;
            n as u64
        }
        FdKind::Proc { buf: kbuf, len: dlen } => {
            if o.accmode == 1 {
                return EBADF; // O_WRONLY
            }
            let avail = dlen.saturating_sub(o.pos);
            let n = core::cmp::min(len as usize, avail);
            if n == 0 {
                return 0;
            }
            if !range_ok_w(buf, n as u64) {
                return EFAULT;
            }
            // SAFETY: same user-window proof as File; the proc frame
            // is kernel-owned, identity-mapped, OFD-lifetime.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    (*kbuf as *const u8).add(o.pos),
                    buf as *mut u8,
                    n,
                )
            };
            o.pos += n;
            n as u64
        }
        FdKind::Ram(i) => {
            if o.accmode == 1 {
                return EBADF; // O_WRONLY
            }
            let Some(v) = vfile(*i) else { return EBADF };
            let avail = v.len.saturating_sub(o.pos);
            let n = core::cmp::min(len as usize, avail);
            if n == 0 {
                return 0;
            }
            if !range_ok_w(buf, n as u64) {
                return EFAULT;
            }
            // SAFETY: v.data is valid for v.len bytes (vfile_grow
            // invariant); buf is the validated user window.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    v.data.add(o.pos),
                    buf as *mut u8,
                    n,
                )
            };
            o.pos += n;
            let (ts, tns) = now();
            v.atime = ts;
            v.atime_ns = tns;
            let mut nm = [0u8; 128];
            nm[..v.nlen].copy_from_slice(&v.name[..v.nlen]);
            ino_report(&nm[..v.nlen], IN_ACCESS, 0);
            n as u64
        }
        FdKind::Pipe { id, write } => {
            let (id, write) = (*id, *write);
            if write {
                return EBADF; // wrong end
            }
            let pipes = unsafe { &mut *core::ptr::addr_of_mut!(PIPES) };
            let Some(p) = pipes.get_mut(id).and_then(|s| s.as_mut()) else {
                return EBADF;
            };
            let avail = p.tail - p.head;
            if avail == 0 {
                if p.writers == 0 {
                    return 0; // EOF — every writer is gone
                }
                if len == 0 {
                    return 0;
                }
                // Block until a writer delivers. The waker copies
                // through OUR tables and deposits the count in
                // ctx.rax; wait_ptr's validity was verified now.
                if !range_ok_w(buf, 1) {
                    return EFAULT;
                }
                if deliverable(t) {
                    return (-4i64) as u64; // -EINTR: signal before sleep
                }
                t.wait_on = WaitOn::PipeRead(id);
                t.wait_ptr = buf;
                t.wait_len = len;
                t.ctx = *ctx;
                t.state = TaskState::Blocked;
                block_switch()
            }
            let n = core::cmp::min(len as usize, avail);
            if !range_ok_w(buf, n as u64) {
                return EFAULT;
            }
            for i in 0..n {
                // SAFETY: ring index wraps inside the pipe-owned frame;
                // buf is validated user memory under the current cr3.
                unsafe {
                    let b = ((p.buf + ((p.head + i) % PIPE_SIZE) as u64) as *const u8).read();
                    ((buf + i as u64) as *mut u8).write(b);
                }
            }
            p.head += n;
            pipe_wake(id); // freed space may unblock writers
            n as u64
        }
    }
}

/// write(fd, buf, len) for non-console fds — pipes only; everything
/// else (initrd files are read-only, dirs, stdin, read-end) is EBADF.
/// Blocks when the ring can't take the write atomically.
pub fn fd_write(ctx: &mut UCtx, fd: u64, buf: u64, len: u64) -> u64 {
    const EPIPE: u64 = (-32i64) as u64;
    let Some(t) = cur_mut() else { return EBADF };
    let Some(o) = ofd(t, fd) else { return EBADF };
    if let FdKind::Tcp(i) = &o.kind {
        return tcp_send(*i, buf, len);
    }
    if let FdKind::Eventfd(i) = &o.kind {
        return eventfd_write(ctx, *i, buf, len);
    }
    if let FdKind::Timerfd(_) = &o.kind {
        return EINVAL; // timerfds aren't writable — Linux's answer
    }
    if let FdKind::Signalfd(_) = &o.kind {
        return EINVAL; // signalfds aren't writable either
    }
    if let FdKind::Inotify(_) = &o.kind {
        return EINVAL;
    }
    if let FdKind::Dev(i) = &o.kind {
        if o.accmode == 0 {
            return EBADF; // O_RDONLY
        }
        if len > 0 && !range_ok(buf, len) {
            return EFAULT;
        }
        let Some(v) = vfile(*i) else { return EBADF };
        const ENOSPC_: u64 = (-28i64) as u64;
        return match v.rdev {
            // /dev/full is the one dev that answers a write —
            // ENOSPC on every byte, like a full disk.
            0x107 => ENOSPC_,
            // Everything else sinks the bytes: null/zero discard,
            // random/urandom fold them into the pool (Linux's
            // write-to-urandom is accepted and never fails),
            // and major-5 tty writes never reach here — they
            // take sys_write's console path via fd_is_console.
            _ => len,
        };
    }
    if let FdKind::Ram(i) = &o.kind {
        if o.accmode == 0 {
            return EBADF; // O_RDONLY
        }
        // A zero-length write is a pure no-op — no grow, no len
        // extension, no pointer validation (Linux semantics).
        if len == 0 {
            return 0;
        }
        let Some(v) = vfile(*i) else { return EBADF };
        // O_APPEND lands every write at EOF; pos arithmetic must not
        // wrap — Linux's answer to overflow is EINVAL.
        let pos = if o.append { v.len } else { o.pos };
        let Some(need) = pos.checked_add(len as usize) else {
            return EINVAL;
        };
        if len > 0 && !range_ok(buf, len) {
            return EFAULT;
        }
        let r = vfile_grow(v, need);
        if r != 0 {
            return r;
        }
        // SAFETY: v.data owns `need` bytes (grow succeeded); buf is
        // the validated user window. Gap bytes are already zero —
        // vfile_grow zero-fills fresh capacity every time.
        unsafe {
            core::ptr::copy_nonoverlapping(
                buf as *const u8,
                v.data.add(pos),
                len as usize,
            )
        };
        v.len = v.len.max(need);
        o.pos = need;
        let (ts, tns) = now();
        v.mtime = ts;
        v.mtime_ns = tns;
        v.ctime = ts;
        v.ctime_ns = tns;
        let mut nm = [0u8; 128];
        nm[..v.nlen].copy_from_slice(&v.name[..v.nlen]);
        ino_report(&nm[..v.nlen], IN_MODIFY, 0);
        return len;
    }
    if matches!(o.kind, FdKind::File(_)) {
        // Open already refuses writable archive files (EROFS), so a
        // File OFD is always O_RDONLY — write() answers EBADF, the
        // fmode check, not the filesystem answer.
        return EBADF;
    }
    let FdKind::Pipe { id, write } = &o.kind else {
        return EBADF;
    };
    let (id, write) = (*id, *write);
    if !write {
        return EBADF; // wrong end
    }
    if len > PIPE_SIZE as u64 {
        return EINVAL; // single-frame ring; larger writes rejected
    }
    let pipes = unsafe { &mut *core::ptr::addr_of_mut!(PIPES) };
    let Some(p) = pipes.get_mut(id).and_then(|s| s.as_mut()) else {
        return EBADF;
    };
    if p.readers == 0 {
        return EPIPE; // SIGPIPE would fire here once signals exist
    }
    if PIPE_SIZE - (p.tail - p.head) < len as usize {
        // Doesn't fit — <=PIPE_BUF writes are atomic, so block until
        // the ring drains enough. The waker pulls our buffer through
        // OUR tables and deposits the count in ctx.rax.
        if len > 0 && !range_ok(buf, 1) {
            return EFAULT;
        }
        if deliverable(t) {
            return (-4i64) as u64; // -EINTR: signal before sleep
        }
        t.wait_on = WaitOn::PipeWrite(id);
        t.wait_ptr = buf;
        t.wait_len = len;
        t.ctx = *ctx;
        t.state = TaskState::Blocked;
        block_switch()
    }
    if !range_ok(buf, len) {
        return EFAULT;
    }
    for i in 0..len as usize {
        // SAFETY: buf is validated user memory under the current cr3;
        // the ring index wraps inside the pipe-owned frame.
        unsafe {
            let b = ((buf + i as u64) as *const u8).read();
            ((p.buf + ((p.tail + i) % PIPE_SIZE) as u64) as *mut u8).write(b);
        }
    }
    p.tail += len as usize;
    pipe_wake(id); // new data may unblock readers
    len
}

/// sendfile(out_fd, in_fd, off_t*, count): fd-to-fd copy without a
/// user bounce — busybox cp/cat and friends reach for this. in must
/// be a regular file or VFile (Linux EINVALs non-regular input);
/// out must be a writable pipe end (fd_write's only writable kind —
/// other sinks EINVAL honestly). The copy is synchronous into the
/// ring: a short count means the ring filled (legal sendfile
/// semantics — callers loop); EAGAIN means the ring had zero room
/// with input remaining, where Linux would block (documented
/// divergence — a mid-copy block can't resume the copy loop).
/// off=NULL consumes in's pos; non-NULL uses/updates *off only.
pub fn sys_sendfile(out_fd: u64, in_fd: u64, off_va: u64, count: u64) -> u64 {
    const EINVAL_: u64 = (-22i64) as u64;
    const EBADF_: u64 = (-9i64) as u64;
    const EFAULT_: u64 = (-14i64) as u64;
    const EAGAIN_: u64 = (-11i64) as u64;
    const EPIPE_: u64 = (-32i64) as u64;
    let Some(t) = cur_mut() else { return EBADF_ };
    let pi = {
        let Some(o) = ofd(t, out_fd) else { return EBADF_ };
        let FdKind::Pipe { id, write } = o.kind else {
            return EINVAL_; // unsupported out kind
        };
        if !write {
            return EBADF_; // out is the read end
        }
        id
    };
    let (src, slen, spos) = {
        let Some(o) = ofd(t, in_fd) else { return EBADF_ };
        if o.accmode == 1 {
            return EBADF_; // input not open for reading
        }
        let (p, l) = match &o.kind {
            FdKind::File(d) => (d.as_ptr(), d.len()),
            FdKind::Ram(i) => match vfile(*i) {
                Some(v) => (v.data as *const u8, v.len),
                None => return EBADF_,
            },
            _ => return EINVAL_, // non-regular input, like Linux
        };
        if off_va != 0 {
            if !range_ok(off_va, 8) {
                return EFAULT_;
            }
            // SAFETY: validated user range under current cr3; off_t
            // is i64 so a negative offset EINVALs like Linux.
            let v = unsafe { (off_va as *const i64).read_unaligned() };
            if v < 0 {
                return EINVAL_;
            }
            (p, l, v as usize)
        } else {
            (p, l, o.pos)
        }
    };
    let avail = slen.saturating_sub(spos);
    let want = core::cmp::min(count as usize, avail);
    if want == 0 {
        return 0; // input at EOF — nothing to move
    }
    let pipes = unsafe { &mut *core::ptr::addr_of_mut!(PIPES) };
    let Some(p) = pipes.get_mut(pi).and_then(|s| s.as_mut()) else {
        return EBADF_;
    };
    if p.readers == 0 {
        return EPIPE_;
    }
    let room = PIPE_SIZE - (p.tail - p.head);
    let n = core::cmp::min(want, room);
    if n == 0 {
        return EAGAIN_; // full ring, input remains — Linux blocks
    }
    for i in 0..n {
        // SAFETY: src names slen bytes of stable kernel-visible
        // storage (cpio slice or VFile buffer); the ring index wraps
        // inside the pipe-owned frame.
        unsafe {
            let b = src.add(spos + i).read();
            ((p.buf + ((p.tail + i) % PIPE_SIZE) as u64) as *mut u8).write(b);
        }
    }
    p.tail += n;
    pipe_wake(pi); // new data may unblock readers
    if off_va != 0 {
        if !range_ok_w(off_va, 8) {
            return EFAULT_;
        }
        // SAFETY: same validated user range as the read above.
        unsafe { (off_va as *mut i64).write_unaligned((spos + n) as i64) };
    } else if let Some(o) = ofd(t, in_fd) {
        o.pos += n;
    }
    n as u64
}

/// pipe2(fds, flags): a kernel ring with a read end and a write end,
/// each an OFD so the pair can be dup'd and fork-shared. O_CLOEXEC
/// marks both ends for exec-close; O_NONBLOCK remains unsupported
/// (no nonblocking pipe io — EINVAL, flagged NV). ENFILE at the
/// pool bound, EMFILE at the fd/OFD bounds.
pub fn fd_pipe(fdptr: u64, flags: u64) -> u64 {
    const ENFILE_: u64 = (-23i64) as u64;
    const O_NONBLOCK: u64 = 0o4000;
    if flags & !(O_CLOEXEC | O_NONBLOCK) != 0 || flags & O_NONBLOCK != 0 {
        return EINVAL;
    }
    if !range_ok_w(fdptr, 8) {
        return EFAULT;
    }
    let Some(t) = cur_mut() else { return EBADF };
    let Some(pi) = (unsafe { &*core::ptr::addr_of!(PIPES) })
        .iter()
        .position(Option::is_none)
    else {
        return ENFILE_;
    };
    let Some(buf) = kalloc::alloc_frame() else {
        return (-12i64) as u64;
    };
    let ofds = unsafe { &mut *core::ptr::addr_of_mut!(OFDS) };
    // Need two OFD slots and two fd slots — collect before committing.
    let mut ois = ofds
        .iter()
        .enumerate()
        .filter(|(_, s)| s.is_none())
        .map(|(i, _)| i);
    let (Some(ro), Some(wo)) = (ois.next(), ois.next()) else {
        kalloc::free_frame(buf);
        return EMFILE;
    };
    let mut fis = fdt(t)
        .fds
        .iter()
        .enumerate()
        .filter(|(_, s)| s.is_none())
        .map(|(i, _)| i);
    let (Some(rf), Some(wf)) = (fis.next(), fis.next()) else {
        kalloc::free_frame(buf);
        return EMFILE;
    };
    {
        let pipes = unsafe { &mut *core::ptr::addr_of_mut!(PIPES) };
        pipes[pi] = Some(Pipe {
            buf,
            head: 0,
            tail: 0,
            readers: 1,
            writers: 1,
        });
    }
    ofds[ro] = Some(OpenFile {
        kind: FdKind::Pipe { id: pi, write: false },
        pos: 0,
        refs: 1,
        append: false,
        accmode: 0,
    });
    ofds[wo] = Some(OpenFile {
        kind: FdKind::Pipe { id: pi, write: true },
        pos: 0,
        refs: 1,
        append: false,
        accmode: 1,
    });
    fdt(t).fds[rf] = Some(ro as u8);
    fdt(t).fds[wf] = Some(wo as u8);
    let ce = flags & O_CLOEXEC != 0;
    cloexec_set(t, rf, ce);
    cloexec_set(t, wf, ce);
    // SAFETY: fdptr validated writable for 8 bytes above.
    unsafe {
        (fdptr as *mut u32).write_unaligned(rf as u32);
        ((fdptr + 4) as *mut u32).write_unaligned(wf as u32);
    }
    0
}

/// Fill the uid/gid + timestamp region of the 144-byte stat record
/// (offsets: uid@28 folds into st[3]'s top half, gid@32, times at
/// 72/88/104 with nsec at +8). Callers set st[3]'s low half first.
fn stat_meta(
    st: &mut [u64; 18],
    uid: u32,
    gid: u32,
    atime: (u64, u32),
    mtime: (u64, u32),
    ctime: (u64, u32),
) {
    st[3] |= (uid as u64) << 32;
    st[4] = gid as u64;
    st[9] = atime.0;
    st[10] = atime.1 as u64;
    st[11] = mtime.0;
    st[12] = mtime.1 as u64;
    st[13] = ctime.0;
    st[14] = ctime.1 as u64;
}

/// newfstatat(dirfd, path, statbuf, flags) -> Linux struct stat
/// (144 bytes, x86_64 layout) at a user pointer. The cpio archive
/// is the whole fs: ino is the entry's archive index, mode is
/// synthesized (S_IFREG|0644, S_IFDIR|0755 for "."), sizes come
/// from the member header. dirfd/flags are accepted for ABI shape —
/// a flat archive has no symlinks or per-dirfd namespaces to honor.
pub fn newfstatat(path: &[u8], statbuf: u64, nofollow: bool) -> u64 {
    const STAT_LEN: u64 = 144;
    if !range_ok_w(statbuf, STAT_LEN) {
        return EFAULT;
    }
    let mut st = [0u64; 18];
    // Link resolution: intermediates always; the final component
    // follows only when statting (nofollow == lstat). A real VFile
    // link under lstat reports S_IFLNK|0777 with the target length —
    // the same shape the proc magic links take below.
    let rbuf;
    let rn;
    if nofollow {
        let (b, n, link) = match resolve_links(path, false) {
            Ok(x) => x,
            Err(e) => return e,
        };
        rbuf = b;
        rn = n;
        if link {
            let Some(i) = vfile_find(&rbuf[..rn]) else {
                return ENOENT;
            };
            let Some(v) = vfile(i) else { return ENOENT };
            let arc_n = (unsafe { *core::ptr::addr_of!(INITRD) })
                .map_or(0, |a| crate::cpio::entries(a).count());
            let vidx = unsafe { &*core::ptr::addr_of!(VFILES) }[..i]
                .iter()
                .filter(|s| s.as_ref().is_some_and(|v| !v.unlinked))
                .count();
            st[1] = (arc_n + vidx + 1) as u64; // st_ino — vfile space
            st[2] = 1;
            st[3] = 0o120777; // S_IFLNK | 0777
            st[6] = v.len as u64; // st_size = target length
            st[7] = 4096;
            stat_meta(
                &mut st,
                v.uid,
                v.gid,
                (v.atime, v.atime_ns),
                (v.mtime, v.mtime_ns),
                (v.ctime, v.ctime_ns),
            );
            // SAFETY: range_ok_w proved statbuf writable.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    st.as_ptr() as *const u8,
                    statbuf as *mut u8,
                    STAT_LEN as usize,
                )
            };
            return 0;
        }
    } else {
        match resolve_links(path, true) {
            Ok((b, n, _)) => {
                rbuf = b;
                rn = n;
            }
            Err(e) => return e,
        }
    }
    let path = &rbuf[..rn];
    // lstat: proc link paths report S_IFLNK|0777 with the target
    // length — self, exe, cwd, root, and every fd/<n> are links on
    // Linux; stat (follow) resolves them instead.
    if nofollow {
        let is_link = path == b"proc/self"
            || match proc_parse(path) {
                Some(ProcEnt::Task(_, l)) => {
                    l == b"exe" || l == b"cwd" || l == b"root"
                }
                Some(ProcEnt::TaskFd(..)) => true,
                _ => false,
            };
        if is_link {
            let mut scratch = [0u8; 160];
            let n = proc_link_target(path, &mut scratch).unwrap_or(0);
            st[2] = 1;
            st[3] = 0o120777; // S_IFLNK | 0777 — magic proc links
            st[6] = n as u64; // st_size = target length
            st[7] = 4096;
            // SAFETY: range_ok_w proved statbuf writable.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    st.as_ptr() as *const u8,
                    statbuf as *mut u8,
                    STAT_LEN as usize,
                )
            };
            return 0;
        }
    }
    if !is_file(path) && dir_exists(path) {
        // Any directory — root, VDIRS, implicit prefix, virtual proc.
        st[2] = 2; // st_nlink
        if let Some(i) = vdir_find(path) {
            // An explicit mkdir'd dir reports its stored metadata.
            let ds = unsafe { &*core::ptr::addr_of!(VDIRS) };
            let Some(d) = ds[i].as_ref() else { return ENOENT };
            st[3] = 0o40000 | d.mode as u64; // S_IFDIR | stored mode
            stat_meta(
                &mut st,
                d.uid,
                d.gid,
                (d.atime, d.atime_ns),
                (d.mtime, d.mtime_ns),
                (d.ctime, d.ctime_ns),
            );
        } else {
            st[3] = 0o40755; // st_mode: S_IFDIR | 0755
        }
    } else if let Some(i) = vfile_find(path) {
        // RAM files shadow the archive — same lookup order as open.
        let Some(v) = vfile(i) else { return ENOENT };
        let arc_n = (unsafe { *core::ptr::addr_of!(INITRD) })
            .map_or(0, |a| crate::cpio::entries(a).count());
        let vidx = unsafe { &*core::ptr::addr_of!(VFILES) }[..i]
            .iter()
            .filter(|s| s.as_ref().is_some_and(|v| !v.unlinked))
            .count();
        st[1] = (arc_n + vidx) as u64 + 1; // st_ino — getdents order
        st[2] = 1; // st_nlink
        st[3] = if v.is_link {
            0o120000 | v.mode as u64 // S_IFLNK | stored (followed-into case)
        } else {
            v.fmt as u64 | v.mode as u64 // stored S_IFMT | stored mode
        };
        st[5] = v.rdev as u64; // st_rdev — 0 on regular files
        st[6] = v.len as u64; // st_size
        st[8] = (v.len as u64).div_ceil(512); // st_blocks
        stat_meta(
            &mut st,
            v.uid,
            v.gid,
            (v.atime, v.atime_ns),
            (v.mtime, v.mtime_ns),
            (v.ctime, v.ctime_ns),
        );
    } else if let Some(pe) = proc_parse(path) {
        // The exe link stats its target like a followed symlink;
        // the generated files show Linux's 0444/size-0 proc shape.
        if let ProcEnt::Task(slot, b"exe") = pe {
            let tasks = unsafe { &*core::ptr::addr_of!(TASKS) };
            let Some(t) = tasks.get(slot).and_then(|s| s.as_ref())
            else {
                return ENOENT;
            };
            let Some(arc) = (unsafe { *core::ptr::addr_of!(INITRD) })
            else {
                return ENOENT;
            };
            let Some((idx, (_, data))) = crate::cpio::entries(arc)
                .enumerate()
                .find(|(_, (n, _))| *n == &t.exe[..t.exe_len as usize])
            else {
                return ENOENT;
            };
            st[1] = idx as u64 + 1;
            st[2] = 1;
            st[3] = 0o100777;
            st[6] = data.len() as u64;
            st[8] = (data.len() as u64).div_ceil(512);
        } else if let ProcEnt::Task(_, leaf) = pe {
            if leaf == b"cwd" || leaf == b"root" {
                // stat follows the link — cwd and root both name "/".
                st[2] = 2;
                st[3] = 0o40755;
            } else {
                st[2] = 1;
                st[3] = 0o100444; // S_IFREG | 0444 — proc files are ro
            }
        } else if let ProcEnt::TaskFd(slot, n) = pe {
            // stat follows the fd link: the target OFD's own shape.
            let tasks = unsafe { &*core::ptr::addr_of!(TASKS) };
            let Some(t) = tasks.get(slot).and_then(|s| s.as_ref())
            else {
                return ENOENT;
            };
            if t.fdi == FDI_NONE || n >= MAX_FDS {
                return ENOENT;
            }
            let tab =
                unsafe { &(*core::ptr::addr_of!(FDTABS))[t.fdi as usize] };
            let Some(oi) = tab.fds[n] else { return ENOENT };
            let ofds = unsafe { &*core::ptr::addr_of!(OFDS) };
            let Some(o) = ofds.get(oi as usize).and_then(|s| s.as_ref())
            else {
                return ENOENT;
            };
            let (mode, size, ino) = ofd_stat_shape(&o.kind);
            st[1] = ino;
            st[2] = 1;
            st[3] = mode;
            st[6] = size;
            st[8] = size.div_ceil(512);
        } else if let ProcEnt::TaskFdi(..) = pe {
            st[2] = 1;
            st[3] = 0o100400; // S_IFREG | 0400 like Linux fdinfo
        }
    } else {
        let Some(arc) = (unsafe { *core::ptr::addr_of!(INITRD) }) else {
            return ENOENT;
        };
        let Some((idx, (_, data))) = crate::cpio::entries(arc)
            .enumerate()
            .find(|(_, (n, _))| *n == path)
        else {
            return ENOENT;
        };
        st[1] = idx as u64 + 1; // st_ino
        st[2] = 1; // st_nlink
        st[3] = 0o100644; // st_mode: S_IFREG | 0644
        st[6] = data.len() as u64; // st_size
        st[8] = (data.len() as u64).div_ceil(512); // st_blocks
    }
    st[7] = 4096; // st_blksize
    // SAFETY: range_ok_w proved statbuf is a writable user range;
    // st is the 144-byte Linux x86_64 stat layout verbatim.
    unsafe {
        core::ptr::copy_nonoverlapping(
            st.as_ptr() as *const u8,
            statbuf as *mut u8,
            STAT_LEN as usize,
        )
    };
    0
}

/// Explicitly-created directories — the ram layer's mkdir.
/// Implicit dirs (a file's path prefix) never live here.
#[derive(Clone, Copy)]
struct VDir {
    path: [u8; 128],
    nlen: usize,
    mode: u16,
    uid: u32,
    gid: u32,
    atime: u64,
    atime_ns: u32,
    mtime: u64,
    mtime_ns: u32,
    ctime: u64,
    ctime_ns: u32,
}
static mut VDIRS: [Option<VDir>; 16] = [None; 16];

fn vdir_find(path: &[u8]) -> Option<usize> {
    unsafe { &*core::ptr::addr_of!(VDIRS) }
        .iter()
        .position(|d| d.as_ref().is_some_and(|d| &d.path[..d.nlen] == path))
}

fn vdir_remove(i: usize) {
    let ds = unsafe { &mut *core::ptr::addr_of_mut!(VDIRS) };
    ds[i] = None;
}

/// Canonical path resolution: join base+path, split on '/', skip
/// empty and "." components, ".." pops the last (at root it stays
/// root — the Linux rule). Output is the flat-name convention:
/// no leading '/', root = "". None on overflow (ENAMETOOLONG).
fn canon(base: &[u8], path: &[u8], out: &mut [u8; 256]) -> Option<usize> {
    let mut n = 0usize;
    fn push(out: &mut [u8; 256], n: &mut usize, comp: &[u8]) -> bool {
        if comp.is_empty() || comp == b"." {
            return true;
        }
        if comp == b".." {
            if *n > 0 {
                while *n > 0 && out[*n - 1] != b'/' {
                    *n -= 1;
                }
                if *n > 0 {
                    *n -= 1; // drop the '/'
                }
            }
            return true;
        }
        if *n + comp.len() + usize::from(*n > 0) > out.len() {
            return false;
        }
        if *n > 0 {
            out[*n] = b'/';
            *n += 1;
        }
        out[*n..*n + comp.len()].copy_from_slice(comp);
        *n += comp.len();
        true
    }
    if !path.starts_with(b"/") {
        for comp in base.split(|&c| c == b'/') {
            if !push(out, &mut n, comp) {
                return None;
            }
        }
    }
    for comp in path.split(|&c| c == b'/') {
        if !push(out, &mut n, comp) {
            return None;
        }
    }
    Some(n)
}

/// Resolve a raw user path against dirfd-or-cwd into the canonical
/// flat name. `dfd` is the raw dirfd register value: u64::MAX and
/// zero-extended -100 (AT_FDCWD) both mean cwd-relative; any other
/// value must name a Dir OFD (EBADF bad fd, ENOTDIR non-dir).
/// Absolute paths ignore dirfd, matching Linux.
pub fn canon_path(dfd: u64, path: &[u8]) -> Result<([u8; 256], usize), u64> {
    const ENAMETOOLONG: u64 = (-36i64) as u64;
    const ENOTDIR_: u64 = (-20i64) as u64;
    if path.is_empty() {
        return Err(ENOENT);
    }
    let dfd_i = dfd as u32 as i32;
    let base: ([u8; 128], usize) = if path[0] == b'/' {
        ([0; 128], 0)
    } else if dfd_i != -100 && dfd != u64::MAX {
        let Some(t) = cur_mut() else { return Err(EBADF) };
        let Some(o) = ofd(t, dfd_i as u64) else { return Err(EBADF) };
        let FdKind::Dir(dp) = &o.kind else { return Err(ENOTDIR_) };
        (dp.b, dp.n as usize)
    } else {
        let Some(t) = cur_mut() else { return Err(EBADF) };
        let f = fst(t);
        (f.cwd, f.cwdlen as usize)
    };
    let mut out = [0u8; 256];
    match canon(&base.0[..base.1], path, &mut out) {
        Some(n) => Ok((out, n)),
        None => Err(ENAMETOOLONG),
    }
}

/// Follow symlinks inside a canonical flat name. Every component
/// prefix that names a link VFile is replaced by canon(link's dir +
/// stored target) — an absolute target ignores the dir, exactly like
/// Linux's namei. `last` says whether the FINAL component follows
/// too: lstat/readlink/unlink callers pass false, ordinary lookups
/// true. Depth-capped at 40 hops like Linux's MAXSYMLINKS -> ELOOP.
/// The bool in the Ok triple reports "the settled name's final
/// component is itself a link" — only meaningful with last=false
/// (a followed final can never settle on a link).
pub fn resolve_links(
    cpath: &[u8],
    last: bool,
) -> Result<([u8; 256], usize, bool), u64> {
    const ELOOP_: u64 = (-40i64) as u64;
    const ENAMETOOLONG_: u64 = (-36i64) as u64;
    let mut cur = [0u8; 256];
    let mut cn = cpath.len().min(256);
    cur[..cn].copy_from_slice(&cpath[..cn]);
    for _ in 0..40 {
        let mut i = 0usize;
        let mut hit = false;
        while i < cn {
            let end = cur[i..cn]
                .iter()
                .position(|&b| b == b'/')
                .map(|p| i + p)
                .unwrap_or(cn);
            if end == cn && !last {
                break; // the final component stays literal
            }
            // Prefix cur[..end] a link? The target must be copied to
            // the stack — VFILES is borrowed mutably during lookup
            // and the rewrite overwrites cur itself.
            let mut tgt = [0u8; 256];
            let mut tl = 0usize;
            if let Some(vi) = vfile_find(&cur[..end]) {
                if let Some(v) = vfile(vi) {
                    if v.is_link && !v.data.is_null() {
                        tl = v.len.min(256);
                        // SAFETY: data is a live kmalloc buffer of
                        // len bytes; tl is clamped to both sides.
                        unsafe {
                            core::ptr::copy_nonoverlapping(
                                v.data,
                                tgt.as_mut_ptr(),
                                tl,
                            )
                        };
                    }
                }
            }
            if tl > 0 {
                // A relative target joins the link's own directory —
                // canon already discards the base on '/'-led input.
                let dir_end =
                    cur[..end].iter().rposition(|&b| b == b'/').unwrap_or(0);
                let mut nb = [0u8; 256];
                let Some(nn) = canon(&cur[..dir_end], &tgt[..tl], &mut nb)
                else {
                    return Err(ENAMETOOLONG_);
                };
                // Resolved prefix + the untouched tail (leading '/'
                // included when present) re-forms the working path.
                let tail = cn - end;
                if nn + tail > 256 {
                    return Err(ENAMETOOLONG_);
                }
                let mut n2 = [0u8; 256];
                n2[..nn].copy_from_slice(&nb[..nn]);
                n2[nn..nn + tail].copy_from_slice(&cur[end..cn]);
                cur = n2;
                cn = nn + tail;
                hit = true;
                break;
            }
            if end == cn {
                break;
            }
            i = end + 1;
        }
        if !hit {
            let fl = vfile_find(&cur[..cn])
                .is_some_and(|j| vfile(j).is_some_and(|v| v.is_link));
            return Ok((cur, cn, fl));
        }
    }
    Err(ELOOP_)
}

/// symlinkat(target, linkpath@dirfd): a link is a VFile whose data
/// holds the raw target text. It lands only where a file could be
/// created — parent dir exists, nothing owns the name, proc stays
/// synthetic (EROFS). An empty target is ENOENT like Linux; the
/// target's own path validity is never checked (links may dangle).
pub fn fs_symlink(dfd: u64, target: &[u8], linkpath: &[u8]) -> u64 {
    const EEXIST_: u64 = (-17i64) as u64;
    const EROFS_: u64 = (-30i64) as u64;
    const ENOTDIR_: u64 = (-20i64) as u64;
    const ENAMETOOLONG_: u64 = (-36i64) as u64;
    if target.is_empty() {
        return ENOENT;
    }
    let (buf, n) = match canon_path(dfd, linkpath) {
        Ok(x) => x,
        Err(e) => return e,
    };
    // Intermediates resolve — a symlink inside a dir reached through
    // another link lands on the real path, like Linux.
    let (rb, rn, _) = match resolve_links(&buf[..n], false) {
        Ok(x) => x,
        Err(e) => return e,
    };
    let p = &rb[..rn];
    if p.len() > 128 {
        return ENAMETOOLONG_;
    }
    // "" is the canon root — a live dir, so EEXIST like Linux.
    if is_file(p) || dir_exists(p) {
        return EEXIST_;
    }
    if p.starts_with(b"proc/") {
        return EROFS_;
    }
    if let Some(pi) = p.iter().rposition(|&c| c == b'/') {
        let par = &p[..pi];
        if !dir_exists(par) {
            return if is_file(par) { ENOTDIR_ } else { ENOENT };
        }
    }
    let r = vfile_create(p);
    if (r as i64) < 0 {
        return r;
    }
    let i = r as usize;
    let g = {
        let Some(v) = vfile(i) else { return (-12i64) as u64 };
        // Linux links are always 0o777 — umask never applies.
        vfile_stamp(v, 0o777, 0);
        let g = vfile_grow(v, target.len());
        if g == 0 {
            // SAFETY: grow owns >= target.len() writable bytes.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    target.as_ptr(),
                    v.data,
                    target.len(),
                )
            };
            v.len = target.len();
            v.is_link = true;
            v.fmt = 0o120000;
        }
        g
    };
    if g != 0 {
        // Roll the slot back — a link with no target must not exist.
        unsafe { (*core::ptr::addr_of_mut!(VFILES))[i] = None };
        return g;
    }
    ino_report(p, IN_CREATE, 0);
    0
}

/// mknod/mknodat on a canonical-ish path: intermediates resolve,
/// the final component must be free — a link there is EEXIST like
/// Linux. The node is a VFile that carries no data; `fmt`/`rdev`
/// record what it is. Type bits allowed by Linux mknod: S_IFREG,
/// S_IFCHR, S_IFBLK, S_IFIFO, and mode==0 which means a regular.
pub fn fs_mknod(dfd: u64, path: &[u8], mode: u64, rdev: u64) -> u64 {
    const EEXIST_: u64 = (-17i64) as u64;
    const EROFS_: u64 = (-30i64) as u64;
    const ENOTDIR_: u64 = (-20i64) as u64;
    const ENAMETOOLONG_: u64 = (-36i64) as u64;
    const ENOSPC_: u64 = (-28i64) as u64;
    let (buf, n) = match canon_path(dfd, path) {
        Ok(x) => x,
        Err(e) => return e,
    };
    let (rb, rn, _) = match resolve_links(&buf[..n], false) {
        Ok(x) => x,
        Err(e) => return e,
    };
    let p = &rb[..rn];
    if p.len() > 128 {
        return ENAMETOOLONG_;
    }
    let fmt = (mode & 0o170000) as u32;
    if !matches!(fmt, 0 | 0o100000 | 0o20000 | 0o60000 | 0o10000 | 0o140000)
    {
        return EINVAL;
    }
    if is_file(p) || dir_exists(p) {
        return EEXIST_;
    }
    if p.starts_with(b"proc/") {
        return EROFS_;
    }
    if let Some(pi) = p.iter().rposition(|&c| c == b'/') {
        let par = &p[..pi];
        if !dir_exists(par) {
            return if is_file(par) { ENOTDIR_ } else { ENOENT };
        }
    }
    let r = vfile_create(p);
    if (r as i64) < 0 {
        return r;
    }
    let umask = cur_mut().map_or(0, |t| fst(t).umask);
    let Some(v) = vfile(r as usize) else { return ENOSPC_ };
    vfile_stamp(v, mode & 0o7777, umask);
    v.fmt = if fmt == 0 { 0o100000 } else { fmt };
    v.rdev = rdev as u32;
    ino_report(p, IN_CREATE, 0);
    0
}

/// Mint the boot /dev population — called once from main context
/// before the first task, so no locking and no canon needed. The
/// nodes are plain VFiles; their semantics live in the Dev OFD arm.
pub fn dev_init() {
    let ds = unsafe { &mut *core::ptr::addr_of_mut!(VDIRS) };
    if let Some(i) = ds.iter().position(Option::is_none) {
        let (s, ns) = now();
        let mut d = VDir {
            path: [0; 128],
            nlen: 3,
            mode: 0o755,
            uid: 0,
            gid: 0,
            atime: s,
            atime_ns: ns,
            mtime: s,
            mtime_ns: ns,
            ctime: s,
            ctime_ns: ns,
        };
        d.path[..3].copy_from_slice(b"dev");
        ds[i] = Some(d);
    }
    // (path, rdev = major<<8|minor, perms) — the classic mem/tty set.
    for (name, rdev, mode) in [
        (b"dev/null" as &[u8], 0x103u32, 0o666u64),
        (b"dev/zero", 0x105, 0o666),
        (b"dev/full", 0x107, 0o666),
        (b"dev/random", 0x108, 0o666),
        (b"dev/urandom", 0x109, 0o666),
        (b"dev/tty", 0x500, 0o666),
        (b"dev/console", 0x501, 0o600),
    ] {
        let r = vfile_create(name);
        if (r as i64) < 0 {
            continue;
        }
        if let Some(v) = vfile(r as usize) {
            vfile_stamp(v, mode, 0);
            v.fmt = 0o20000; // S_IFCHR
            v.rdev = rdev;
        }
    }
    // The /dev convenience links real Linux images carry.
    for (link, tgt) in [
        (b"dev/fd" as &[u8], b"/proc/self/fd" as &[u8]),
        (b"dev/stdin", b"/proc/self/fd/0"),
        (b"dev/stdout", b"/proc/self/fd/1"),
        (b"dev/stderr", b"/proc/self/fd/2"),
    ] {
        let r = vfile_create(link);
        if (r as i64) < 0 {
            continue;
        }
        if let Some(v) = vfile(r as usize) {
            vfile_stamp(v, 0o777, 0);
            let g = vfile_grow(v, tgt.len());
            if g == 0 {
                // SAFETY: grow owns >= tgt.len() writable bytes.
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        tgt.as_ptr(),
                        v.data,
                        tgt.len(),
                    )
                };
                v.len = tgt.len();
                v.is_link = true;
                v.fmt = 0o120000;
            } else {
                unsafe { (*core::ptr::addr_of_mut!(VFILES))[r as usize] = None };
            }
        }
    }
}

/// readlink/readlinkat on a canonical name: intermediates resolve,
/// the final component must itself be a link — VFile links answer
/// with their stored target, proc magic links via proc_link_target.
/// Linux EINVALs readlink on an existing non-link, ENOENT on a miss.
pub fn fs_readlink(cpath: &[u8], buf: u64, len: u64) -> u64 {
    const EINVAL_: u64 = (-22i64) as u64;
    if len != 0 && !range_ok_w(buf, len) {
        return EFAULT;
    }
    let (rb, rn, was_link) = match resolve_links(cpath, false) {
        Ok(x) => x,
        Err(e) => return e,
    };
    let p = &rb[..rn];
    if was_link {
        let Some(i) = vfile_find(p) else { return ENOENT };
        let Some(v) = vfile(i) else { return ENOENT };
        let n = v.len.min(len as usize);
        // SAFETY: buf is validated writable for len; data holds len.
        if n > 0 {
            unsafe { core::ptr::copy_nonoverlapping(v.data, buf as *mut u8, n) };
        }
        return n as u64;
    }
    if p.starts_with(b"proc/") {
        let mut out = [0u8; 160];
        return match proc_link_target(p, &mut out) {
            Some(tn) => {
                let total = tn.min(len as usize);
                // SAFETY: buf is validated writable for len bytes.
                unsafe { (buf as *mut u8).copy_from(out.as_ptr(), total) };
                total as u64
            }
            None => {
                if fs_exists(p) {
                    EINVAL_
                } else {
                    ENOENT
                }
            }
        };
    }
    if fs_exists(p) {
        EINVAL_
    } else {
        ENOENT
    }
}

/// Does `p` (canonical) name a regular file in either namespace?
fn is_file(p: &[u8]) -> bool {
    if vfile_find(p).is_some() || fs_lookup(p).is_some() {
        return true;
    }
    // Every proc ent is openable except the synthetic subdirs —
    // fd links stat/open their target, so they count as files.
    !matches!(proc_parse(p), Some(ProcEnt::TaskDir) | None)
}

/// Does `p` (canonical) name a directory? Root always exists;
/// "proc"/"proc/self" are virtual; VDIRS are explicit; and any
/// entry deeper under `p/` makes p an implicit dir.
fn dir_exists(p: &[u8]) -> bool {
    if p.is_empty() || vdir_find(p).is_some() {
        return true;
    }
    if p == b"proc" || p == b"proc/self" {
        return true;
    }
    // "proc/<pid>" is a dir while the task lives (zombies included,
    // like Linux's pre-reap /proc entries); fd/fdinfo subdirs too.
    if let Some(rest) = p.strip_prefix(b"proc/") {
        if !rest.contains(&b'/') && proc_pid_slot(rest).is_some() {
            return true;
        }
        if matches!(proc_parse(p), Some(ProcEnt::TaskDir)) {
            return true;
        }
    }
    let mut pre = [0u8; 256];
    if p.len() + 1 > pre.len() {
        return false;
    }
    pre[..p.len()].copy_from_slice(p);
    pre[p.len()] = b'/';
    let pre = &pre[..p.len() + 1];
    if let Some(arc) = unsafe { *core::ptr::addr_of!(INITRD) } {
        for (n, _) in crate::cpio::entries(arc) {
            if n.starts_with(pre) {
                return true;
            }
        }
    }
    if unsafe { &*core::ptr::addr_of!(VFILES) }.iter().flatten().any(|v| {
        !v.unlinked && v.name[..v.nlen].starts_with(pre)
    }) {
        return true;
    }
    unsafe { &*core::ptr::addr_of!(VDIRS) }.iter().flatten().any(|d| {
        d.path[..d.nlen].starts_with(pre)
    })
}

/// ---- /proc -------------------------------------------------------------
/// The virtual process/system view. File contents are generated at
/// open() into a kernel frame the OFD owns — Linux's seq_file snapshot
/// model — so a reader sees one consistent image even when the task it
/// describes exits mid-read, and no separate reader state is needed.
///
/// `proc/<pid>` directories exist for every task slot, Exited zombies
/// included (Linux keeps them until the reap, and so do we); "self" is
/// the caller's pid resolved eagerly at lookup.

/// Leaf entries a per-task dir exports. "exe"/"cwd"/"root" aren't
/// rendered text — they resolve like symlinks; "fd"/"fdinfo" are
/// directories of the task's live fd table.
const PROC_TFILES: [&[u8]; 13] = [
    b"stat", b"status", b"comm", b"cmdline", b"statm", b"environ",
    b"wchan", b"io", b"exe", b"cwd", b"root", b"fd", b"fdinfo",
];
/// Synthetic system files under /proc itself.
const PROC_GFILES: [&[u8]; 8] = [
    b"uptime", b"meminfo", b"loadavg", b"version", b"stat", b"cpuinfo",
    b"filesystems", b"mounts",
];

/// What a canonical "proc/..." path names — global file by PROC_GFILES
/// index, a per-task leaf on a task slot, a pid subdir, or a numbered
/// entry under the fd/fdinfo dirs.
enum ProcEnt {
    Global(usize),
    Task(usize, &'static [u8]),
    /// proc/<pid>/{fd,fdinfo} — directories over the task's FdTab.
    /// Unit: the subdir name is only needed at parse time — dir
    /// existence and getdents re-derive it from the path.
    TaskDir,
    /// proc/<pid>/fd/<n> — a link naming the OFD; open() shares it.
    TaskFd(usize, usize),
    /// proc/<pid>/fdinfo/<n> — a generated file.
    TaskFdi(usize, usize),
}

/// A zombie nobody can still wait4 — collected via a wait4 wake
/// (ppid zeroed) or orphaned of a dead parent — is dead to /proc
/// even though its slot lingers until the next pick_next reap (the
/// exiting task can't free its own kstack mid-pick). Mirrors
/// pick_next's reapability test exactly.
fn proc_dead(t: &Task, tasks: &[Option<Task>; MAX_TASKS]) -> bool {
    t.state == TaskState::Exited
        && (t.ppid == 0
            || !tasks
                .iter()
                .flatten()
                .any(|p| p.pid == t.ppid && p.state != TaskState::Exited))
}

/// The task slot holding `pid`, zombies included (see the /proc note).
fn task_slot_by_pid(pid: u64) -> Option<usize> {
    let tasks = unsafe { &*core::ptr::addr_of!(TASKS) };
    (0..tasks.len()).find(|&i| {
        tasks[i]
            .as_ref()
            .is_some_and(|t| t.pid == pid && !proc_dead(t, tasks))
    })
}

/// Resolve a pid-dir component — decimal pid or "self" (the caller) —
/// to a live task slot.
fn proc_pid_slot(comp: &[u8]) -> Option<usize> {
    if comp == b"self" {
        return Some(unsafe { *core::ptr::addr_of!(CUR_I) });
    }
    // Strictly decimal, 1..=20 digits, no sign — anything else is
    // just an odd filename, not a pid.
    if comp.is_empty()
        || comp.len() > 20
        || !comp.iter().all(|c| c.is_ascii_digit())
    {
        return None;
    }
    let mut pid = 0u64;
    for &c in comp {
        pid = pid * 10 + (c - b'0') as u64;
    }
    task_slot_by_pid(pid)
}

/// Parse "proc/<file>", "proc/<pid-or-self>/<file>", and
/// "proc/<pid>/{fd,fdinfo}/<n>" paths. The fd level resolves against
/// the target's live fd table — a closed fd number is ENOENT.
fn proc_parse(p: &[u8]) -> Option<ProcEnt> {
    let rest = p.strip_prefix(b"proc/")?;
    let Some(i) = rest.iter().position(|&c| c == b'/') else {
        return PROC_GFILES
            .iter()
            .position(|f| *f == rest)
            .map(ProcEnt::Global);
    };
    let leaf = &rest[i + 1..];
    let slot = proc_pid_slot(&rest[..i])?;
    let Some(j) = leaf.iter().position(|&c| c == b'/') else {
        return PROC_TFILES.iter().find(|f| **f == leaf).map(|f| {
            if *f == b"fd" || *f == b"fdinfo" {
                ProcEnt::TaskDir
            } else {
                ProcEnt::Task(slot, *f)
            }
        });
    };
    // Third level — only fd/fdinfo hold numbered children, and only
    // for slots whose fd table still lives (a reaped one releases
    // it — its fd dir reads empty like Linux).
    let name = &leaf[j + 1..];
    if name.is_empty()
        || name.len() > 3
        || name.contains(&b'/')
        || !name.iter().all(|c| c.is_ascii_digit())
    {
        return None;
    }
    let mut n = 0usize;
    for &c in name {
        n = n * 10 + (c - b'0') as usize;
    }
    let tasks = unsafe { &*core::ptr::addr_of!(TASKS) };
    let t = tasks.get(slot)?.as_ref()?;
    if t.fdi == FDI_NONE || n >= MAX_FDS {
        return None;
    }
    let tab = unsafe { &(*core::ptr::addr_of!(FDTABS))[t.fdi as usize] };
    if tab.fds[n].is_none() {
        return None;
    }
    let sub = &leaf[..j];
    if sub == b"fd" {
        Some(ProcEnt::TaskFd(slot, n))
    } else if sub == b"fdinfo" {
        Some(ProcEnt::TaskFdi(slot, n))
    } else {
        None
    }
}

/// Count resident 4K leaf pages in `pml4`'s user half — the RSS
/// figure /proc/<pid>/stat field 24 reports (in pages, like Linux).
/// The page table is the allocation ledger, so this walk IS the
/// honest count; user-space tables are identity-mapped for us.
fn task_rss_pages(pml4: u64) -> u64 {
    let mut n = 0u64;
    for i in 0..256u64 {
        let e = rd64(pml4 + 8 * i);
        if e & PRESENT == 0 {
            continue;
        }
        let pdpt = e & PHYS_MASK;
        for j in 0..512u64 {
            let e = rd64(pdpt + 8 * j);
            if e & PRESENT == 0 || e & (1 << 7) != 0 {
                continue; // user space never gets a 1G leaf
            }
            let pd = e & PHYS_MASK;
            for k in 0..512u64 {
                let e = rd64(pd + 8 * k);
                if e & PRESENT == 0 || e & (1 << 7) != 0 {
                    continue; // ... nor a 2M one
                }
                let pt = e & PHYS_MASK;
                for l in 0..512u64 {
                    if rd64(pt + 8 * l) & PRESENT != 0 {
                        n += 1;
                    }
                }
            }
        }
    }
    n
}

/// 'R'/'S'/'T'/'Z' — the ps state column for a TaskState.
fn proc_state_char(st: TaskState) -> u8 {
    match st {
        TaskState::Runnable => b'R',
        TaskState::Blocked => b'S',
        TaskState::Stopped => b'T',
        TaskState::Exited => b'Z',
    }
}

/// Render one proc file's text into `s`.
fn proc_fill(ent: &ProcEnt, s: &mut klib::seqbuf::SeqBuf) {
    use klib::fmt::Arg;
    match *ent {
        ProcEnt::Global(gi) => match PROC_GFILES[gi] {
            b"uptime" => {
                let t = crate::apic::TICKS
                    .load(core::sync::atomic::Ordering::Relaxed);
                // <uptime> <idle> — centiseconds, 100Hz ticks.
                s.printf(
                    b"%u.%02u %u.%02u\n",
                    &[
                        Arg::U(t / 100),
                        Arg::U(t % 100),
                        Arg::U(t / 100),
                        Arg::U(t % 100),
                    ],
                );
            }
            b"meminfo" => {
                let total = kalloc::total_frames() * 4;
                let free = kalloc::free_frames() * 4;
                s.printf(
                    b"MemTotal:       %u kB\n\
                      MemFree:        %u kB\n\
                      MemAvailable:   %u kB\n\
                      Buffers:               0 kB\n\
                      Cached:                0 kB\n\
                      SwapTotal:             0 kB\n\
                      SwapFree:              0 kB\n",
                    &[Arg::U(total), Arg::U(free), Arg::U(free)],
                );
            }
            b"loadavg" => {
                // <l1> <l5> <l15> <running+sleeping>/<total> <lastpid>
                // — no real load accounting yet, honest 0.00s.
                let tasks = unsafe { &*core::ptr::addr_of!(TASKS) };
                let (mut live, mut last) = (0u64, 0u64);
                for t in tasks.iter().flatten() {
                    live += 1;
                    last = last.max(t.pid);
                }
                s.printf(
                    b"0.00 0.00 0.00 %u/%u %u\n",
                    &[Arg::U(live), Arg::U(live), Arg::U(last)],
                );
            }
            b"version" => {
                s.puts(b"Rustux version 0.1.0\n");
            }
            b"stat" => {
                // Real per-task accounting: user/system tick sums,
                // live state counts, the switch and fork counters.
                // idle is the remainder — ticks no task owned.
                let t = crate::apic::TICKS
                    .load(core::sync::atomic::Ordering::Relaxed);
                let tasks = unsafe { &*core::ptr::addr_of!(TASKS) };
                let (mut u, mut sy, mut run, mut blk) =
                    (0u64, 0u64, 0u64, 0u64);
                for tk in tasks.iter().flatten() {
                    u += tk.utime;
                    sy += tk.stime;
                    match tk.state {
                        TaskState::Runnable => run += 1,
                        TaskState::Blocked => blk += 1,
                        _ => {}
                    }
                }
                let idle = t.saturating_sub(u + sy);
                let cx = CTXT_SW.load(core::sync::atomic::Ordering::Relaxed);
                let pr = PROCS_CREATED
                    .load(core::sync::atomic::Ordering::Relaxed);
                s.printf(
                    b"cpu  %u 0 %u %u 0 0 0 0 0 0\n\
                      cpu0 %u 0 %u %u 0 0 0 0 0 0\n\
                      intr %u\nctxt %u\nbtime 0\n\
                      processes %u\nprocs_running %u\nprocs_blocked %u\n",
                    &[
                        Arg::U(u), Arg::U(sy), Arg::U(idle),
                        Arg::U(u), Arg::U(sy), Arg::U(idle),
                        Arg::U(t), Arg::U(cx), Arg::U(pr),
                        Arg::U(run), Arg::U(blk),
                    ],
                );
            }
            b"cpuinfo" => {
                // One processor: vendor + brand from CPUID, topology
                // honest zeros, a compact real flags line.
                let r0 = core::arch::x86_64::__cpuid(0);
                let mut vend = [0u8; 12];
                for (d, v) in
                    [(r0.ebx, 0), (r0.edx, 4), (r0.ecx, 8)].iter()
                {
                    vend[*v..*v + 4]
                        .copy_from_slice(&d.to_le_bytes());
                }
                let r1 = core::arch::x86_64::__cpuid(1);
                let eax = r1.eax;
                let fam = ((eax >> 8) & 0xf)
                    + if (eax >> 8) & 0xf == 0xf { (eax >> 20) & 0xff } else { 0 };
                let model = ((eax >> 4) & 0xf)
                    | if (eax >> 8) & 0xf >= 6 {
                        ((eax >> 16) & 0xf) << 4
                    } else {
                        0
                    };
                let maxext = core::arch::x86_64::__cpuid(0x80000000).eax;
                let mut brand = [0u8; 48];
                if maxext >= 0x8000_0004 {
                    for (i, l) in
                        [0x8000_0002u32, 0x8000_0003, 0x8000_0004]
                            .iter()
                            .enumerate()
                    {
                        let r = core::arch::x86_64::__cpuid(*l);
                        for (o, v) in
                            [r.eax, r.ebx, r.ecx, r.edx].iter().enumerate()
                        {
                            brand[i * 16 + o * 4..i * 16 + o * 4 + 4]
                                .copy_from_slice(&v.to_le_bytes());
                        }
                    }
                }
                let brand_end = brand
                    .iter()
                    .rposition(|&c| c != 0 && c != b' ')
                    .map_or(0, |p| p + 1);
                let mut bstart = 0usize;
                while bstart < brand_end && brand[bstart] == b' ' {
                    bstart += 1;
                }
                s.printf(
                    b"processor\t: 0\nvendor_id\t: %s\ncpu family\t: %u\n\
                      model\t\t: %u\nmodel name\t: %s\nstepping\t: %u\n\
                      cpu MHz\t\t: 0.000\ncache size\t: 0 KB\n\
                      flags\t\t: fpu tsc msr cx8 cmov fxsr sse sse2\n\
                      bogomips\t: 0.00\n",
                    &[
                        Arg::S(&vend),
                        Arg::U(fam as u64),
                        Arg::U(model as u64),
                        Arg::S(&brand[bstart..brand_end]),
                        Arg::U((eax & 0xf) as u64),
                    ],
                );
            }
            b"filesystems" => {
                // The two filesystem interfaces this kernel serves —
                // both are pseudo (no block device exists).
                s.puts(b"nodev\trustux\nnodev\tproc\n");
            }
            b"mounts" => {
                s.puts(b"rustux / rustux rw,relatime 0 0\n\
                      proc /proc proc rw,relatime 0 0\n");
            }
            _ => {}
        },
        ProcEnt::Task(slot, leaf) => {
            let tasks = unsafe { &*core::ptr::addr_of!(TASKS) };
            let Some(t) = tasks.get(slot).and_then(|s| s.as_ref()) else {
                return;
            };
            let name_end = t
                .name
                .iter()
                .position(|&c| c == 0)
                .unwrap_or(t.name.len());
            let name = &t.name[..name_end];
            let state = proc_state_char(t.state);
            match leaf {
                b"stat" => {
                    // Field 22 (starttime) is ticks-since-boot;
                    // utime/stime are 0 (no per-task accounting);
                    // rss is the real leaf-page count.
                    let tpgid = if t.sid
                        == unsafe { *core::ptr::addr_of!(CONSOLE_SID) }
                    {
                        unsafe { *core::ptr::addr_of!(FG_PGID) }
                    } else {
                        0
                    };
                    let nthr = tasks
                        .iter()
                        .flatten()
                        .filter(|x| x.tgid == t.tgid)
                        .count() as u64;
                    let vsize = t.brk_cur;
                    let rss = task_rss_pages(t.pml4);
                    s.printf(
                        b"%d (%s) %c %d %d %d 0 %d \
                          0 0 0 0 0 %u %u 0 0 \
                          20 0 %d 0 \
                          %u %u %d %u \
                          0 0 %u \
                          0 0 %u %u 0 0 \
                          0 0 0 \
                          17 \
                          0 0 0 0 0 0 \
                          0 0 %u \
                          0 0 0 0 0\n",
                        &[
                            Arg::I(t.pid as i64),      // 1 pid
                            Arg::S(name),              // 2 comm
                            Arg::C(state as i64),      // 3 state
                            Arg::I(t.ppid as i64),     // 4 ppid
                            Arg::I(t.pgid as i64),     // 5 pgrp
                            Arg::I(t.sid as i64),      // 6 session
                            Arg::I(tpgid as i64),      // 8 tty_pgrp
                            Arg::U(t.utime),           // 14 utime
                            Arg::U(t.stime),           // 15 stime
                            Arg::I(nthr as i64),       // 20 num_threads
                            Arg::U(t.start_ticks),     // 22 starttime
                            Arg::U(vsize),             // 23 vsize
                            Arg::I(rss as i64),        // 24 rss
                            Arg::U(u64::MAX),          // 25 rsslim
                            Arg::U(t.stack_top),       // 28 startstack
                            Arg::U(t.pending as u64),  // 31 signal
                            Arg::U(t.sigmask as u64),  // 32 blocked
                            Arg::U(t.brk_base),        // 47 start_brk
                        ],
                    );
                }
                b"statm" => {
                    // <size> <resident> <shared> <text> <lib> <data>
                    // <dt> — in pages. vsize covers the VA span; the
                    // page-table walk is the resident truth. No shared
                    // mappings exist (fork copies, never shares).
                    s.printf(
                        b"%u %u 0 0 0 0 0\n",
                        &[
                            Arg::U(t.brk_cur / 4096),
                            Arg::U(task_rss_pages(t.pml4)),
                        ],
                    );
                }
                b"environ" => {
                    // Rustux tasks run with an empty envp — the honest
                    // file is zero bytes.
                }
                b"wchan" => {
                    // Wait-channel symbol name on Linux; our waits are
                    // WaitOn variants, not kernel VAs — report '0'
                    // like a runnable Linux task does.
                    s.puts(b"0");
                }
                b"io" => {
                    // No I/O counters are kept — Linux emits zeros
                    // for a task that never touched the block layer.
                    s.puts(
                        b"rchar: 0\nwchar: 0\nsyscr: 0\nsyscw: 0\n\
                          read_bytes: 0\nwrite_bytes: 0\n\
                          cancelled_write_bytes: 0\n",
                    );
                }
                b"status" => {
                    s.printf(
                        b"Name:\t%s\nState:\t%c\nTgid:\t%d\nPid:\t%d\n\
                          PPid:\t%d\nUid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\n",
                        &[
                            Arg::S(name),
                            Arg::C(state as i64),
                            Arg::I(t.tgid as i64),
                            Arg::I(t.pid as i64),
                            Arg::I(t.ppid as i64),
                        ],
                    );
                }
                b"comm" => {
                    s.printf(b"%s\n", &[Arg::S(name)]);
                }
                b"cmdline" => {
                    // The exec-time NUL-joined argv snapshot; a task
                    // that never exec'd (spawned) already carries
                    // argv0. Fallback: the exe path like a kthread.
                    if t.cmdline_len > 0 {
                        s.putmem(&t.cmdline[..t.cmdline_len as usize]);
                    } else {
                        s.putmem(&t.exe[..t.exe_len as usize]);
                        s.putc(0);
                    }
                }
                _ => {}
            }
        }
        ProcEnt::TaskFdi(slot, n) => {
            // proc/<pid>/fdinfo/<n>: the OFD's position and the open
            // flags it was created with (accmode+append+cloexec live
            // on the fd/OFD; cloexec sits on the fd slot).
            let tasks = unsafe { &*core::ptr::addr_of!(TASKS) };
            let Some(t) = tasks.get(slot).and_then(|s| s.as_ref()) else {
                return;
            };
            if t.fdi == FDI_NONE || n >= MAX_FDS {
                return;
            }
            let tab = unsafe { &(*core::ptr::addr_of!(FDTABS))[t.fdi as usize] };
            let Some(oi) = tab.fds[n] else { return };
            let ofds = unsafe { &*core::ptr::addr_of!(OFDS) };
            let Some(o) = ofds.get(oi as usize).and_then(|s| s.as_ref())
            else {
                return;
            };
            let mut fl = o.accmode as u64;
            if o.append {
                fl |= 0o2000;
            }
            if tab.cloexec & (1 << n) != 0 {
                fl |= 0o2000000;
            }
            s.printf(
                b"pos:\t%u\nflags:\t0%o\nmnt_id:\t0\n",
                &[Arg::U(o.pos as u64), Arg::U(fl)],
            );
        }
        // fd links and subdirs have no content of their own.
        ProcEnt::TaskFd(..) | ProcEnt::TaskDir => {}
    }
}

/// open() of a proc file: render the snapshot or resolve the exe
/// link to its image. None when `path` isn't a proc file.
fn proc_open(path: &[u8]) -> Option<FdKind> {
    let ent = proc_parse(path)?;
    if let ProcEnt::Task(slot, b"exe") = ent {
        // The exe link opens its target — the image in the initrd,
        // exactly what fs_lookup's proc/self/exe case does for self.
        let tasks = unsafe { &*core::ptr::addr_of!(TASKS) };
        let t = tasks.get(slot).and_then(|s| s.as_ref())?;
        let arc = unsafe { *core::ptr::addr_of!(INITRD) }?;
        return crate::cpio::find(arc, &t.exe[..t.exe_len as usize])
            .map(FdKind::File);
    }
    let buf = kalloc::alloc_frame()?;
    let len = {
        // SAFETY: buf is a fresh 4096-byte frame, identity-mapped.
        let dst =
            unsafe { core::slice::from_raw_parts_mut(buf as *mut u8, 4096) };
        let mut s = klib::seqbuf::SeqBuf::new(dst);
        proc_fill(&ent, &mut s);
        s.used()
    };
    Some(FdKind::Proc { buf, len })
}

/// The name a proc link resolves to — exe's "/"+image, cwd/root's
/// "/", fd/N's target description, self's decimal pid. Rendered into
/// `out`; returns the length (pre-cap).
fn proc_link_target(path: &[u8], out: &mut [u8]) -> Option<usize> {
    if path == b"proc/self" {
        // The magic link names the CALLER's pid, decimal.
        let cur = unsafe { *core::ptr::addr_of!(CUR_I) };
        let tasks = unsafe { &*core::ptr::addr_of!(TASKS) };
        let t = tasks.get(cur)?.as_ref()?;
        let mut s = klib::seqbuf::SeqBuf::new(out);
        s.printf(b"%d", &[klib::fmt::Arg::I(t.pid as i64)]);
        return Some(s.used());
    }
    match proc_parse(path)? {
        ProcEnt::Task(slot, b"exe") => {
            let tasks = unsafe { &*core::ptr::addr_of!(TASKS) };
            let t = tasks.get(slot)?.as_ref()?;
            let n = (t.exe_len as usize + 1).min(out.len());
            if n == 0 {
                return Some(0);
            }
            out[0] = b'/';
            out[1..n]
                .copy_from_slice(&t.exe[..(n - 1).min(t.exe_len as usize)]);
            Some(n)
        }
        ProcEnt::Task(_, leaf) if leaf == b"cwd" || leaf == b"root" => {
            // A flat namespace is always cwd=/ root=/.
            if out.is_empty() {
                return Some(0);
            }
            out[0] = b'/';
            Some(1)
        }
        ProcEnt::TaskFd(slot, n) => {
            let tasks = unsafe { &*core::ptr::addr_of!(TASKS) };
            let t = tasks.get(slot)?.as_ref()?;
            if t.fdi == FDI_NONE {
                return None;
            }
            let tab =
                unsafe { &(*core::ptr::addr_of!(FDTABS))[t.fdi as usize] };
            let oi = tab.fds[n]? as usize;
            let ofds = unsafe { &*core::ptr::addr_of!(OFDS) };
            let o = ofds.get(oi)?.as_ref()?;
            Some(fd_link_name(&o.kind, out))
        }
        _ => None,
    }
}

/// The /proc/<pid>/fd/N link text for an OFD — Linux's shapes:
/// paths for real files, "pipe:[n]"/"socket:[n]" for the anonymous
/// endpoints, "anon_inode:[x]" for the anon-inode kinds.
fn fd_link_name(kind: &FdKind, out: &mut [u8]) -> usize {
    let mut s = klib::seqbuf::SeqBuf::new(out);
    match kind {
        FdKind::Stdin | FdKind::Console => {
            s.puts(b"/dev/console");
        }
        FdKind::File(d) => {
            // Contents back to a name: walk the archive for the
            // member whose data this OFD borrows.
            let arc = unsafe { *core::ptr::addr_of!(INITRD) };
            let found = arc.and_then(|a| {
                crate::cpio::entries(a)
                    .find(|(_, data)| data.as_ptr() == d.as_ptr())
                    .map(|(n, _)| n)
            });
            if let Some(n) = found {
                s.putc(b'/');
                s.putmem(n);
            } else {
                s.puts(b"/deleted");
            }
        }
        FdKind::Ram(i) | FdKind::Dev(i) => {
            let name = unsafe { &*core::ptr::addr_of!(VFILES) }
                .get(*i)
                .and_then(|v| v.as_ref())
                .map(|v| &v.name[..v.nlen]);
            match name {
                Some(n) => {
                    s.putc(b'/');
                    s.putmem(n);
                }
                None => {
                    s.puts(b"/deleted");
                }
            }
        }
        FdKind::Dir(dp) => {
            s.putc(b'/');
            s.putmem(&dp.b[..dp.n as usize]);
        }
        FdKind::Pipe { id, .. } => {
            s.printf(b"pipe:[%u]", &[klib::fmt::Arg::U(*id as u64)]);
        }
        FdKind::Udp(id) | FdKind::Tcp(id) => {
            s.printf(b"socket:[%u]", &[klib::fmt::Arg::U(*id as u64)]);
        }
        FdKind::Epoll(_) => {
            s.puts(b"anon_inode:[eventpoll]");
        }
        FdKind::Eventfd(_) => {
            s.puts(b"anon_inode:[eventfd]");
        }
        FdKind::Timerfd(_) => {
            s.puts(b"anon_inode:[timerfd]");
        }
        FdKind::Signalfd(_) => {
            s.puts(b"anon_inode:[signalfd]");
        }
        FdKind::Inotify(_) => {
            s.puts(b"anon_inode:[inotify]");
        }
        FdKind::Proc { .. } => {
            s.puts(b"anon_inode:[proc]");
        }
    }
    s.used()
}

/// The canonical path a Dir OFD names — for dirfd resolution.
pub fn fd_dir_path(fd: u64) -> Option<([u8; 128], usize)> {
    let t = cur_mut()?;
    let o = ofd(t, fd)?;
    match &o.kind {
        FdKind::Dir(dp) => Some((dp.b, dp.n as usize)),
        _ => None,
    }
}

/// Open-flag values we honor or refuse — O_ACCMODE(3) is the access
/// mask, O_CLOEXEC the fd flag, O_DIRECTORY a kind check. Anything
/// writable is EROFS on an archive file; anything else unknown EINVAL.
const O_CREAT: u64 = 0o100;
const O_EXCL: u64 = 0o200;
const O_TRUNC: u64 = 0o1000;
const O_APPEND: u64 = 0o2000;
const O_CLOEXEC: u64 = 0o2000000;
const O_DIRECTORY: u64 = 0o200000;
const O_NOFOLLOW: u64 = 0o400000;
const O_PATH: u64 = 0o10000000;
const O_LARGEFILE: u64 = 0o100000;
const O_NOCTTY: u64 = 0o400;
const O_NONBLOCK: u64 = 0o4000;
const O_ACCMODE: u64 = 3;

#[inline]
fn cloexec_set(t: &mut Task, fi: usize, on: bool) {
    if on {
        fdt(t).cloexec |= 1 << fi;
    } else {
        fdt(t).cloexec &= !(1 << fi);
    }
}

/// open(path, flags, mode): "" and "." name the namespace root (a Dir
/// OFD); names resolve VFILES first then cpio — a scratch file may
/// shadow an archive name the same way a mount does. Writable
/// opens land on Ram files only; cpio writes are EROFS, like a
/// read-only mount. O_CREAT mints a VFile whose stored mode is
/// `mode & ~umask` like Linux; O_EXCL with it is EEXIST
/// on either namespace; O_TRUNC needs write access (ignored on
/// O_RDONLY per Linux); O_APPEND sets per-OFD append. Unknown flag
/// bits → EINVAL, ENOENT when absent, EMFILE at the table bounds.
pub fn fd_open(path: &[u8], flags: u64, mode: u64) -> u64 {
    const EROFS: u64 = (-30i64) as u64;
    const ENOTDIR: u64 = (-20i64) as u64;
    const EEXIST: u64 = (-17i64) as u64;
    const KNOWN: u64 = O_ACCMODE | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW
        | O_PATH | O_CREAT | O_EXCL | O_TRUNC | O_APPEND | O_LARGEFILE
        | O_NONBLOCK | O_NOCTTY;
    if flags & !KNOWN != 0 {
        return EINVAL;
    }
    let acc = flags & O_ACCMODE;
    let writing = acc != 0;
    let Some(t) = cur_mut() else { return EBADF };
    // Symlink resolution: intermediates always, the final component
    // unless O_NOFOLLOW (ELOOP — O_PATH included, a documented
    // divergence). O_CREAT|O_EXCL sees the link itself and EEXISTs
    // like Linux; plain O_CREAT through a dangling link mints the
    // TARGET. The resolved name drives every arm below, so a link
    // may point anywhere — vfiles, the archive, dirs, even proc.
    let (mut rb, mut rn, was_link) = match resolve_links(path, false) {
        Ok(x) => x,
        Err(e) => return e,
    };
    if was_link {
        if flags & (O_CREAT | O_EXCL) == (O_CREAT | O_EXCL) {
            return EEXIST;
        }
        if flags & O_NOFOLLOW != 0 {
            return (-40i64) as u64; // ELOOP
        }
        match resolve_links(&rb[..rn], true) {
            Ok((b, n, _)) => {
                rb = b;
                rn = n;
            }
            Err(e) => return e,
        }
    }
    let path = &rb[..rn];
    // /proc/<pid>/fd/<n> opens the named open description itself —
    // a cross-task dup: same OFD, same pos, refs+1. Sockets refuse
    // like Linux (ENXIO); an O_WRONLY ask on a read-only OFD is
    // EACCES. Rendered proc files share fine — the snapshot frame
    // is OFD-owned, not fd-owned.
    if let Some(ProcEnt::TaskFd(slot, n)) = proc_parse(path) {
        // The link exists, so O_CREAT|O_EXCL fails like any
        // existing path — checked before the share happens.
        if flags & (O_CREAT | O_EXCL) == (O_CREAT | O_EXCL) {
            return EEXIST;
        }
        let tasks = unsafe { &*core::ptr::addr_of!(TASKS) };
        let Some(tgt) = tasks.get(slot).and_then(|s| s.as_ref()) else {
            return ENOENT;
        };
        let tab =
            unsafe { &(*core::ptr::addr_of!(FDTABS))[tgt.fdi as usize] };
        let Some(oi) = tab.fds.get(n).copied().flatten() else {
            return ENOENT;
        };
        let ofds = unsafe { &mut *core::ptr::addr_of_mut!(OFDS) };
        let Some(o) = ofds.get_mut(oi as usize).and_then(|s| s.as_mut())
        else {
            return ENOENT;
        };
        if matches!(o.kind, FdKind::Udp(_) | FdKind::Tcp(_)) {
            return (-6i64) as u64; // ENXIO
        }
        if acc != 0
            && (o.accmode == 0 || (acc == 2 && o.accmode != 2))
        {
            return (-13i64) as u64; // EACCES
        }
        if flags & O_DIRECTORY != 0 && !matches!(o.kind, FdKind::Dir(_)) {
            return ENOTDIR;
        }
        o.refs += 1;
        let Some(fi) = fdt(t).fds.iter().position(Option::is_none) else {
            o.refs -= 1;
            return EMFILE;
        };
        fdt(t).fds[fi] = Some(oi as u8);
        cloexec_set(t, fi, flags & O_CLOEXEC != 0);
        return fi as u64;
    }
    let kind = if let Some(i) = vfile_find(path) {
        // RAM file wins over the archive — mount-shadowing order.
        if flags & (O_CREAT | O_EXCL) == (O_CREAT | O_EXCL) {
            return EEXIST;
        }
        let dev_node = vfile(i).is_some_and(|v| v.fmt != 0o100000);
        if flags & O_TRUNC != 0 && writing && !dev_node {
            let Some(v) = vfile(i) else { return ENOENT };
            v.len = 0;
            let (ts, tns) = now();
            v.mtime = ts;
            v.mtime_ns = tns;
            v.ctime = ts;
            v.ctime_ns = tns;
            ino_report(path, IN_MODIFY, 0);
        }
        if dev_node {
            const ENODEV: u64 = (-19i64) as u64;
            const ENXIO: u64 = (-6i64) as u64;
            let v = vfile(i).unwrap();
            match v.fmt {
                // No block driver exists to claim the node —
                // Linux's answer opening a driverless block dev.
                0o60000 => return ENODEV,
                // A fifo node exists but no fifo semantics live
                // here yet — ENXIO is the documented divergence
                // (Linux blocks for a peer; there is no peer).
                0o10000 | 0o140000 => return ENXIO,
                0o20000 => match v.rdev >> 8 {
                    // mem family — only the minors we actually
                    // implement; a crafted node on another minor
                    // must not fall through to a driver it isn't.
                    1 => match v.rdev & 0xff {
                        3 | 5 | 7 | 8 | 9 => {}
                        _ => return ENXIO,
                    },
                    // /dev/tty is the ctty — only the console's
                    // own session has one, ENXIO otherwise.
                    5 => match v.rdev & 0xff {
                        // /dev/tty is the ctty — only the console's
                        // own session has one, ENXIO otherwise.
                        0 => {
                            if t.sid
                                != unsafe { *core::ptr::addr_of!(CONSOLE_SID) }
                            {
                                return ENXIO;
                            }
                        }
                        // /dev/console — same driver.
                        1 => {}
                        _ => return ENXIO,
                    },
                    _ => return ENODEV,
                },
                _ => return ENODEV,
            }
            FdKind::Dev(i)
        } else {
            FdKind::Ram(i)
        }
    } else if (unsafe { *core::ptr::addr_of!(INITRD) })
        .is_some_and(|arc| crate::cpio::find(arc, path).is_some())
        && !dir_exists(path)
    {
        // A cpio member names a file only when nothing lives beneath
        // it — an entry that is also a path prefix is a directory.
        if writing {
            return EROFS;
        }
        if flags & (O_CREAT | O_EXCL) == (O_CREAT | O_EXCL) {
            return EEXIST;
        }
        let arc = unsafe { *core::ptr::addr_of!(INITRD) }.unwrap();
        FdKind::File(crate::cpio::find(arc, path).unwrap())
    } else if !matches!(proc_parse(path), None | Some(ProcEnt::TaskDir))
    {
        // Generated /proc files are read-only like the archive —
        // checked BEFORE the snapshot frame is rendered so an
        // EROFS/EEXIST miss never owns one. TaskDir parses too but
        // is a directory — it falls through to dir_exists.
        if writing {
            return EROFS;
        }
        if flags & (O_CREAT | O_EXCL) == (O_CREAT | O_EXCL) {
            return EEXIST;
        }
        let Some(kind) = proc_open(path) else {
            return (-12i64) as u64; // ENOMEM — the frame alloc failed
        };
        kind
    } else if dir_exists(path) {
        // A real directory: read-only opens only, like Linux.
        if writing || flags & O_CREAT != 0 {
            return EISDIR;
        }
        FdKind::Dir(DirPath::of(path))
    } else if flags & O_CREAT != 0 {
        // procfs is fully synthetic — nothing may be created under
        // it even though its pid dirs read as directories.
        if path.starts_with(b"proc/") {
            return EROFS;
        }
        // The parent must be a real directory; a file in a path
        // component is ENOTDIR like Linux.
        if let Some(pi) = path.iter().rposition(|&c| c == b'/') {
            let par = &path[..pi];
            if !dir_exists(par) {
                return if is_file(par) { ENOTDIR } else { ENOENT };
            }
        }
        let r = vfile_create(path);
        if (r as i64) < 0 {
            return r;
        }
        if let Some(v) = vfile(r as usize) {
            vfile_stamp(v, mode, fst(t).umask);
        }
        ino_report(path, IN_CREATE, 0);
        FdKind::Ram(r as usize)
    } else {
        // Miss — ENOTDIR when a path component names a file.
        for i in (0..path.len()).rev() {
            if path[i] == b'/' && is_file(&path[..i]) {
                return ENOTDIR;
            }
        }
        return ENOENT;
    };
    if flags & O_DIRECTORY != 0 && !matches!(kind, FdKind::Dir(_)) {
        if let FdKind::Proc { buf, .. } = kind {
            kalloc::free_frame(buf);
        }
        return ENOTDIR;
    }
    let ofds = unsafe { &mut *core::ptr::addr_of_mut!(OFDS) };
    let Some(oi) = ofds.iter().position(Option::is_none) else {
        if let FdKind::Proc { buf, .. } = kind {
            kalloc::free_frame(buf);
        }
        return EMFILE;
    };
    let Some(fi) = fdt(t).fds.iter().position(Option::is_none) else {
        if let FdKind::Proc { buf, .. } = kind {
            kalloc::free_frame(buf);
        }
        return EMFILE;
    };
    ofds[oi] = Some(OpenFile {
        kind,
        pos: 0,
        refs: 1,
        append: flags & O_APPEND != 0,
        accmode: acc as u8,
    });
    fdt(t).fds[fi] = Some(oi as u8);
    cloexec_set(t, fi, flags & O_CLOEXEC != 0);
    ino_report(path, IN_OPEN, 0);
    fi as u64
}

/// Does `path` name anything in either namespace — access(2)'s only
/// real question on a flat namespace.
pub fn fs_exists(path: &[u8]) -> bool {
    dir_exists(path) || is_file(path)
}

/// Drop a VFile's name. Storage dies immediately when no OFD still
/// references it; otherwise ofd_release frees it at last close —
/// Linux's open-unlink-keep-working semantics.
fn vfile_remove(i: usize) {
    let (data, nm, nlen) = {
        let Some(v) = vfile(i) else { return };
        v.unlinked = true;
        let mut n = [0u8; 128];
        n[..v.nlen].copy_from_slice(&v.name[..v.nlen]);
        (v.data, n, v.nlen)
    };
    ino_report(&nm[..nlen], IN_DELETE, 0);
    ino_report_self_loss(&nm[..nlen], IN_DELETE_SELF, 0);
    let live = unsafe { &*core::ptr::addr_of!(OFDS) }
        .iter()
        .flatten()
        .any(|o| matches!(o.kind, FdKind::Ram(j) | FdKind::Dev(j) if j == i));
    if !live {
        if !data.is_null() {
            // SAFETY: data was kmalloc'd at cap; the slot is cleared
            // right after so nothing can reach it.
            unsafe { kalloc::kfree(data) };
        }
        unsafe { (*core::ptr::addr_of_mut!(VFILES))[i] = None };
    }
}

/// unlink(path): the dir and archive are unwritable namespaces —
/// EISDIR and EROFS. A VFile loses its name; its bytes outlive the
/// name while any OFD (or fd) still names it.
pub fn fs_unlink(path: &[u8]) -> u64 {
    const EISDIR_: u64 = (-21i64) as u64;
    const EROFS_: u64 = (-30i64) as u64;
    // Intermediates resolve; the final component never does — unlink
    // removes the link itself, like Linux.
    let (rb, rn, _) = match resolve_links(path, false) {
        Ok(x) => x,
        Err(e) => return e,
    };
    let path = &rb[..rn];
    if dir_exists(path) {
        return EISDIR_;
    }
    let Some(i) = vfile_find(path) else {
        return if fs_lookup(path).is_some() { EROFS_ } else { ENOENT };
    };
    vfile_remove(i);
    0
}

/// rename(old, new): VFile names only — the archive can't be renamed
/// (EROFS). Renaming over a live VFile unlinks it; renaming over an
/// archive name just shadows it (the VFile wins lookups anyway).
pub fn fs_rename(old: &[u8], new: &[u8]) -> u64 {
    const EROFS_: u64 = (-30i64) as u64;
    const EINVAL_: u64 = (-22i64) as u64;
    const ENAMETOOLONG_: u64 = (-36i64) as u64;
    if old.is_empty() || new.is_empty() || old == b"." || new == b"." {
        return EINVAL_;
    }
    if new.len() > 128 {
        return ENAMETOOLONG_;
    }
    // Intermediates resolve on both names; the final components stay
    // literal — rename moves the link itself, like Linux. The RESOLVED
    // new name must still fit the 128-byte name slot (its input-side
    // check above can't see a longer resolution).
    let (ob, oc, _) = match resolve_links(old, false) {
        Ok(x) => x,
        Err(e) => return e,
    };
    let old = &ob[..oc];
    let (nb, nc, _) = match resolve_links(new, false) {
        Ok(x) => x,
        Err(e) => return e,
    };
    if nc > 128 {
        return ENAMETOOLONG_;
    }
    let new = &nb[..nc];
    let Some(i) = vfile_find(old) else {
        return if fs_lookup(old).is_some() { EROFS_ } else { ENOENT };
    };
    if let Some(j) = vfile_find(new) {
        if j == i {
            return 0; // rename onto self is a no-op
        }
        vfile_remove(j); // rename replaces the target
    }
    let Some(v) = vfile(i) else { return ENOENT };
    v.name = [0; 128];
    v.name[..new.len()].copy_from_slice(new);
    v.nlen = new.len();
    let (ts, tns) = now();
    v.ctime = ts;
    v.ctime_ns = tns;
    let cookie = INO_COOKIE
        .fetch_add(1, core::sync::atomic::Ordering::Relaxed) as u32;
    ino_report_self_loss(old, IN_MOVE_SELF, cookie);
    ino_report(old, IN_MOVED_FROM, cookie);
    ino_report(new, IN_MOVED_TO, cookie);
    0
}

/// Move/close pairing counter — Linux inotify cookies correlate
/// FROM and TO halves of one rename.
static INO_COOKIE: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(1);

/// Shared truncate core: shrink drops len; grow zero-fills the gap
/// (vfile_grow's fresh capacity is pre-zeroed; same-cap regrow is
/// not — write_bytes covers both). EFBIG past the per-file ceiling.
fn vfile_truncate(v: &mut VFile, len: u64) -> u64 {
    const EFBIG_: u64 = (-27i64) as u64;
    if len > VFILE_MAX as u64 {
        return EFBIG_;
    }
    let need = len as usize;
    let r = vfile_grow(v, need);
    if r != 0 {
        return r;
    }
    if need > v.len {
        // SAFETY: grow made [0, need) valid; v.len <= need here.
        unsafe { core::ptr::write_bytes(v.data.add(v.len), 0, need - v.len) };
    }
    v.len = need;
    let (ts, tns) = now();
    v.mtime = ts;
    v.mtime_ns = tns;
    v.ctime = ts;
    v.ctime_ns = tns;
    0
}

/// truncate(path, len): VFiles only — archive members are EROFS.
pub fn fs_truncate(path: &[u8], len: u64) -> u64 {
    const EROFS_: u64 = (-30i64) as u64;
    const EISDIR_: u64 = (-21i64) as u64;
    if path.is_empty() || path == b"." {
        return EISDIR_;
    }
    // truncate(2) follows the final link — the target takes the size.
    let (rb, rn, _) = match resolve_links(path, true) {
        Ok(x) => x,
        Err(e) => return e,
    };
    let path = &rb[..rn];
    let Some(i) = vfile_find(path) else {
        return if fs_lookup(path).is_some() { EROFS_ } else { ENOENT };
    };
    let Some(v) = vfile(i) else { return ENOENT };
    // Device nodes and fifos have no size to set — Linux EINVAL.
    if v.fmt != 0o100000 && !v.is_link {
        return EINVAL;
    }
    let r = vfile_truncate(v, len);
    if r == 0 {
        ino_report(path, IN_MODIFY, 0);
    }
    r
}

/// ftruncate(fd, len): writable Ram OFD only. Linux's fmode check
/// gives EINVAL on O_RDONLY; a cpio-file OFD isn't a regular
/// writable file either — EINVAL there too.
pub fn fd_ftruncate(fd: u64, len: u64) -> u64 {
    let Some(t) = cur_mut() else { return EBADF };
    let Some(o) = ofd(t, fd) else { return EBADF };
    if o.accmode == 0 {
        return EINVAL;
    }
    let FdKind::Ram(i) = o.kind else { return EINVAL };
    let Some(v) = vfile(i) else { return EBADF };
    let mut nm = [0u8; 128];
    nm[..v.nlen].copy_from_slice(&v.name[..v.nlen]);
    let r = vfile_truncate(v, len);
    if r == 0 {
        ino_report(&nm[..v.nlen], IN_MODIFY, 0);
    }
    r
}

/// chmod core on a resolved name: ramfs objects take new permission
/// bits + a ctime bump; archive/proc are read-only mounts (EROFS);
/// a miss is ENOENT. `p` names the object — links already resolved
/// (or deliberately not, for the fd path on a Ram link inode).
fn chmod_obj(p: &[u8], mode: u64) -> u64 {
    const EROFS_: u64 = (-30i64) as u64;
    let (s, ns) = now();
    if let Some(i) = vfile_find(p) {
        let Some(v) = vfile(i) else { return ENOENT };
        v.mode = (mode & 0o7777) as u16;
        v.ctime = s;
        v.ctime_ns = ns;
        ino_report(p, IN_ATTRIB, 0);
        return 0;
    }
    if let Some(i) = vdir_find(p) {
        let ds = unsafe { &mut *core::ptr::addr_of_mut!(VDIRS) };
        let Some(d) = ds[i].as_mut() else { return ENOENT };
        d.mode = (mode & 0o7777) as u16;
        d.ctime = s;
        d.ctime_ns = ns;
        ino_report(p, IN_ATTRIB, 0);
        return 0;
    }
    if fs_exists(p) {
        EROFS_
    } else {
        ENOENT
    }
}

/// chmod(path, mode)/fchmodat(dirfd, path, mode): follows the final
/// link like Linux — there is no lchmod.
pub fn fs_chmod(cpath: &[u8], mode: u64) -> u64 {
    let (rb, rn, _) = match resolve_links(cpath, true) {
        Ok(x) => x,
        Err(e) => return e,
    };
    chmod_obj(&rb[..rn], mode)
}

/// fchmod(fd, mode): Ram OFDs act on their inode directly (unlinked
/// files still take a mode like Linux); Dir OFDs on an explicit dir.
pub fn fd_chmod(fd: u64, mode: u64) -> u64 {
    const EROFS_: u64 = (-30i64) as u64;
    const EINVAL_: u64 = (-22i64) as u64;
    let Some(t) = cur_mut() else { return EBADF };
    let Some(o) = ofd(t, fd) else { return EBADF };
    let (s, ns) = now();
    match &o.kind {
        FdKind::Ram(i) | FdKind::Dev(i) => {
            let Some(v) = vfile(*i) else { return EBADF };
            v.mode = (mode & 0o7777) as u16;
            v.ctime = s;
            v.ctime_ns = ns;
            let mut nm = [0u8; 128];
            nm[..v.nlen].copy_from_slice(&v.name[..v.nlen]);
            ino_report(&nm[..v.nlen], IN_ATTRIB, 0);
            0
        }
        FdKind::Dir(dp) => {
            let Some(i) = vdir_find(dp.bytes()) else { return EROFS_ };
            let ds = unsafe { &mut *core::ptr::addr_of_mut!(VDIRS) };
            let Some(d) = ds[i].as_mut() else { return ENOENT };
            d.mode = (mode & 0o7777) as u16;
            d.ctime = s;
            d.ctime_ns = ns;
            let mut nm = [0u8; 128];
            nm[..d.nlen].copy_from_slice(&d.path[..d.nlen]);
            ino_report(&nm[..d.nlen], IN_ATTRIB, 0);
            0
        }
        FdKind::File(_) | FdKind::Proc { .. } => EROFS_,
        _ => EINVAL_,
    }
}

/// chown core on a resolved name — u32::MAX is the "keep" sentinel
/// (userspace -1). ctime bumps like Linux; IN_ATTRIB emits.
fn chown_obj(p: &[u8], uid: u32, gid: u32) -> u64 {
    const EROFS_: u64 = (-30i64) as u64;
    let (s, ns) = now();
    if let Some(i) = vfile_find(p) {
        let Some(v) = vfile(i) else { return ENOENT };
        if uid != u32::MAX {
            v.uid = uid;
        }
        if gid != u32::MAX {
            v.gid = gid;
        }
        v.ctime = s;
        v.ctime_ns = ns;
        ino_report(p, IN_ATTRIB, 0);
        return 0;
    }
    if let Some(i) = vdir_find(p) {
        let ds = unsafe { &mut *core::ptr::addr_of_mut!(VDIRS) };
        let Some(d) = ds[i].as_mut() else { return ENOENT };
        if uid != u32::MAX {
            d.uid = uid;
        }
        if gid != u32::MAX {
            d.gid = gid;
        }
        d.ctime = s;
        d.ctime_ns = ns;
        ino_report(p, IN_ATTRIB, 0);
        return 0;
    }
    if fs_exists(p) {
        EROFS_
    } else {
        ENOENT
    }
}

/// chown/lchown/fchownat on a canonical name: `nofollow` is the
/// lchown + AT_SYMLINK_NOFOLLOW split — the link itself takes the
/// new owner. Register args truncate to u32 like Linux's uid_t.
pub fn fs_chown(cpath: &[u8], uid: u64, gid: u64, nofollow: bool) -> u64 {
    let (rb, rn, _) = match resolve_links(cpath, !nofollow) {
        Ok(x) => x,
        Err(e) => return e,
    };
    chown_obj(&rb[..rn], uid as u32, gid as u32)
}

/// fchown(fd, uid, gid): the OFD's inode — same mapping as fchmod.
pub fn fd_chown(fd: u64, uid: u64, gid: u64) -> u64 {
    const EROFS_: u64 = (-30i64) as u64;
    const EINVAL_: u64 = (-22i64) as u64;
    let Some(t) = cur_mut() else { return EBADF };
    let Some(o) = ofd(t, fd) else { return EBADF };
    let (s, ns) = now();
    let uid = uid as u32;
    let gid = gid as u32;
    match &o.kind {
        FdKind::Ram(i) | FdKind::Dev(i) => {
            let Some(v) = vfile(*i) else { return EBADF };
            if uid != u32::MAX {
                v.uid = uid;
            }
            if gid != u32::MAX {
                v.gid = gid;
            }
            v.ctime = s;
            v.ctime_ns = ns;
            let mut nm = [0u8; 128];
            nm[..v.nlen].copy_from_slice(&v.name[..v.nlen]);
            ino_report(&nm[..v.nlen], IN_ATTRIB, 0);
            0
        }
        FdKind::Dir(dp) => {
            let Some(i) = vdir_find(dp.bytes()) else { return EROFS_ };
            let ds = unsafe { &mut *core::ptr::addr_of_mut!(VDIRS) };
            let Some(d) = ds[i].as_mut() else { return ENOENT };
            if uid != u32::MAX {
                d.uid = uid;
            }
            if gid != u32::MAX {
                d.gid = gid;
            }
            d.ctime = s;
            d.ctime_ns = ns;
            let mut nm = [0u8; 128];
            nm[..d.nlen].copy_from_slice(&d.path[..d.nlen]);
            ino_report(&nm[..d.nlen], IN_ATTRIB, 0);
            0
        }
        FdKind::File(_) | FdKind::Proc { .. } => EROFS_,
        _ => EINVAL_,
    }
}

/// utimensat sentinels (Linux uapi).
const UTIME_NOW: u64 = 0x3fffffff;
const UTIME_OMIT: u64 = 0x3ffffffe;

/// Apply one (sec, nsec) spec: OMIT keeps, NOW stamps, anything else
/// is literal. `cur`/`nw` are (sec, nsec) pairs.
fn utspec(spec: (u64, u64), cur: (u64, u32), nw: (u64, u32)) -> (u64, u32) {
    match spec.1 {
        UTIME_OMIT => cur,
        UTIME_NOW => nw,
        n => (spec.0, n as u32),
    }
}

/// utimensat core on a canonical name: `ts` is the two-spec array
/// (None == NULL pointer == both NOW); `nofollow` honors
/// AT_SYMLINK_NOFOLLOW. Spec nsec must be <1e9 or a sentinel —
/// EINVAL otherwise like Linux.
pub fn fs_utimens(
    cpath: &[u8],
    ts: Option<[[u64; 2]; 2]>,
    nofollow: bool,
) -> u64 {
    let (at, mt) = match ts {
        Some([[as_, an], [ms, mn]]) => ((as_, an), (ms, mn)),
        None => ((0, UTIME_NOW), (0, UTIME_NOW)),
    };
    let (rb, rn, _) = match resolve_links(cpath, !nofollow) {
        Ok(x) => x,
        Err(e) => return e,
    };
    // Linux validates the timespecs only after the inode is found —
    // a missing path outranks a bad nsec.
    for n in [at.1, mt.1] {
        if n != UTIME_NOW && n != UTIME_OMIT && n >= 1_000_000_000 {
            return EINVAL;
        }
    }
    let p = &rb[..rn];
    const EROFS_: u64 = (-30i64) as u64;
    let nw = now();
    if let Some(i) = vfile_find(p) {
        let Some(v) = vfile(i) else { return ENOENT };
        (v.atime, v.atime_ns) =
            utspec(at, (v.atime, v.atime_ns), nw);
        (v.mtime, v.mtime_ns) =
            utspec(mt, (v.mtime, v.mtime_ns), nw);
        v.ctime = nw.0;
        v.ctime_ns = nw.1;
        ino_report(p, IN_ATTRIB, 0);
        return 0;
    }
    if let Some(i) = vdir_find(p) {
        let ds = unsafe { &mut *core::ptr::addr_of_mut!(VDIRS) };
        let Some(d) = ds[i].as_mut() else { return ENOENT };
        (d.atime, d.atime_ns) =
            utspec(at, (d.atime, d.atime_ns), nw);
        (d.mtime, d.mtime_ns) =
            utspec(mt, (d.mtime, d.mtime_ns), nw);
        d.ctime = nw.0;
        d.ctime_ns = nw.1;
        ino_report(p, IN_ATTRIB, 0);
        return 0;
    }
    if fs_exists(p) {
        EROFS_
    } else {
        ENOENT
    }
}

/// futimens via utimensat(AT_EMPTY_PATH): the OFD's inode — same
/// mapping as fchmod. `ts` semantics identical to fs_utimens.
pub fn fd_utimens(fd: u64, ts: Option<[[u64; 2]; 2]>) -> u64 {
    const EROFS_: u64 = (-30i64) as u64;
    const EINVAL_: u64 = (-22i64) as u64;
    let (at, mt) = match ts {
        Some([[as_, an], [ms, mn]]) => ((as_, an), (ms, mn)),
        None => ((0, UTIME_NOW), (0, UTIME_NOW)),
    };
    let Some(t) = cur_mut() else { return EBADF };
    let Some(o) = ofd(t, fd) else { return EBADF };
    for n in [at.1, mt.1] {
        if n != UTIME_NOW && n != UTIME_OMIT && n >= 1_000_000_000 {
            return EINVAL_;
        }
    }
    let nw = now();
    match &o.kind {
        FdKind::Ram(i) | FdKind::Dev(i) => {
            let Some(v) = vfile(*i) else { return EBADF };
            (v.atime, v.atime_ns) =
                utspec(at, (v.atime, v.atime_ns), nw);
            (v.mtime, v.mtime_ns) =
                utspec(mt, (v.mtime, v.mtime_ns), nw);
            v.ctime = nw.0;
            v.ctime_ns = nw.1;
            let mut nm = [0u8; 128];
            nm[..v.nlen].copy_from_slice(&v.name[..v.nlen]);
            ino_report(&nm[..v.nlen], IN_ATTRIB, 0);
            0
        }
        FdKind::Dir(dp) => {
            let Some(i) = vdir_find(dp.bytes()) else { return EROFS_ };
            let ds = unsafe { &mut *core::ptr::addr_of_mut!(VDIRS) };
            let Some(d) = ds[i].as_mut() else { return ENOENT };
            (d.atime, d.atime_ns) =
                utspec(at, (d.atime, d.atime_ns), nw);
            (d.mtime, d.mtime_ns) =
                utspec(mt, (d.mtime, d.mtime_ns), nw);
            d.ctime = nw.0;
            d.ctime_ns = nw.1;
            let mut nm = [0u8; 128];
            nm[..d.nlen].copy_from_slice(&d.path[..d.nlen]);
            ino_report(&nm[..d.nlen], IN_ATTRIB, 0);
            0
        }
        FdKind::File(_) | FdKind::Proc { .. } => EROFS_,
        _ => EINVAL_,
    }
}

/// fsync/fdatasync(fd): RAM files have nothing to flush and archive
/// files nothing to dirty — the honest answer to a valid fd is 0.
pub fn fd_fsync(fd: u64) -> u64 {
    let Some(t) = cur_mut() else { return EBADF };
    if ofd(t, fd).is_none() {
        return EBADF;
    }
    0
}

/// lseek(fd, off, whence): regular files only — Stdin/Console return
/// ESPIPE like Linux devices. SEEK_SET/CUR/END with signed arithmetic;
/// a negative result is EINVAL, seeking past EOF is legal and reads
/// simply hit EOF (Linux semantics).
pub fn fd_lseek(fd: u64, off: i64, whence: u64) -> u64 {
    let Some(t) = cur_mut() else { return EBADF };
    let Some(o) = ofd(t, fd) else { return EBADF };
    // A directory may only be rewound to the start — dir offsets are
    // opaque cookies, so a nonzero seek target is meaningless here.
    if matches!(o.kind, FdKind::Dir(_)) {
        if whence == 0 && off == 0 {
            o.pos = 0;
            return 0;
        }
        return EINVAL;
    }
    // Character devices are noop_llseek — the "position" exists but
    // lseek answers 0 without moving anything.
    if let FdKind::Dev(_) = &o.kind {
        return 0;
    }
    let dlen = match &o.kind {
        FdKind::File(d) => d.len(),
        FdKind::Proc { len, .. } => *len,
        FdKind::Ram(i) => match vfile(*i) {
            Some(v) => v.len,
            None => return EBADF,
        },
        _ => return ESPIPE,
    };
    let base = match whence {
        0 => 0i64,                       // SEEK_SET
        1 => o.pos as i64,               // SEEK_CUR
        2 => dlen as i64,                // SEEK_END
        _ => return EINVAL,
    };
    let Some(np) = base.checked_add(off) else {
        return EINVAL;
    };
    if np < 0 {
        return EINVAL;
    }
    o.pos = np as usize;
    np as u64
}

/// pread(fd, buf, len, pos): read `len` bytes at file offset `pos`
/// WITHOUT moving the shared OFD position — the whole point of the
/// call. Files only: everything else ESPIPEs like Linux; a negative
/// pos is EINVAL. The buffer gets the same range gate fd_read uses.
pub fn fd_pread(fd: u64, buf: u64, len: u64, pos: i64) -> u64 {
    const ESPIPE_: u64 = (-29i64) as u64;
    if pos < 0 {
        return EINVAL;
    }
    let Some(t) = cur_mut() else { return EBADF };
    let Some(o) = ofd(t, fd) else { return EBADF };
    if o.accmode == 1 {
        return EBADF; // O_WRONLY — fmode check precedes kind checks
    }
    let (data, dlen) = match &o.kind {
        FdKind::File(d) => (d.as_ptr(), d.len()),
        FdKind::Proc { buf, len } => (*buf as *const u8, *len),
        FdKind::Ram(i) => match vfile(*i) {
            Some(v) => (v.data as *const u8, v.len),
            None => return EBADF,
        },
        _ => return ESPIPE_,
    };
    if len > 0 && !range_ok_w(buf, len) {
        return EFAULT;
    }
    let p = (pos as usize).min(dlen);
    let n = (len as usize).min(dlen - p);
    if n == 0 {
        return 0; // also skips .add on a null VFile buffer
    }
    // SAFETY: buf validated writable for len >= n bytes; data is a
    // live cpio slice or a kmalloc'd VFile buffer of dlen bytes.
    unsafe { (buf as *mut u8).copy_from(data.add(p), n) };
    n as u64
}

/// fcntl(fd, cmd, arg): the fd-metadata surface. F_GETFD/F_SETFD own
/// the per-fd O_CLOEXEC bit (the only fd flag Linux has); F_GETFL
/// reports O_RDONLY — the honest status of an archive fd; F_SETFL
/// accepts 0 as a no-op (no O_APPEND/O_NONBLOCK toggles exist) and
/// EINVALs anything else rather than silently succeeding; F_DUPFD
/// rides fd_dup_at's min-slot scan, F_DUPFD_CLOEXEC the same plus the
/// bit. Unknown cmds EINVAL — never a fake success.
pub fn sys_fcntl(fd: u64, cmd: u64, arg: u64) -> u64 {
    const F_DUPFD: u64 = 0;
    const F_GETFD: u64 = 1;
    const F_SETFD: u64 = 2;
    const F_GETFL: u64 = 3;
    const F_SETFL: u64 = 4;
    const F_DUPFD_CLOEXEC: u64 = 1030;
    let Some(t) = cur_mut() else { return EBADF };
    match cmd {
        F_GETFD => {
            if fd as usize >= MAX_FDS || fdt(t).fds[fd as usize].is_none() {
                return EBADF;
            }
            ((fdt(t).cloexec >> fd) & 1) as u64
        }
        F_SETFD => {
            if fd as usize >= MAX_FDS || fdt(t).fds[fd as usize].is_none() {
                return EBADF;
            }
            cloexec_set(t, fd as usize, arg & 1 != 0);
            0
        }
        F_GETFL => {
            if fd as usize >= MAX_FDS || fdt(t).fds[fd as usize].is_none() {
                return EBADF;
            }
            0 // O_RDONLY — the only access mode an archive fd has
        }
        F_SETFL => {
            if fd as usize >= MAX_FDS || fdt(t).fds[fd as usize].is_none() {
                return EBADF;
            }
            if arg == 0 { 0 } else { EINVAL }
        }
        F_DUPFD => fd_dup_at(fd, arg),
        F_DUPFD_CLOEXEC => {
            let r = fd_dup_at(fd, arg);
            if (r as i64) >= 0 {
                cloexec_set(t, r as usize, true);
            }
            r
        }
        _ => EINVAL,
    }
}

/// dup(fd): lowest free slot names the same OFD — shared offset,
/// exactly like Linux, and the new fd is never O_CLOEXEC (fd flags
/// don't survive dup). EMFILE at the table bound.
pub fn fd_dup(fd: u64) -> u64 {
    fd_dup_at(fd, 0)
}

/// Shared dup core: lowest free slot >= `min` names fd's OFD; the
/// new slot's cloexec bit is always clear. F_DUPFD's min-arg rides
/// the same path.
pub fn fd_dup_at(fd: u64, min: u64) -> u64 {
    if min as usize >= MAX_FDS {
        return EINVAL;
    }
    let Some(t) = cur_mut() else { return EBADF };
    let Some(&oi) = fdt(t).fds.get(fd as usize).and_then(|s| s.as_ref()) else {
        return EBADF;
    };
    let Some(fi) = fdt(t).fds[min as usize..].iter().position(Option::is_none) else {
        return EMFILE;
    };
    let fi = fi + min as usize;
    let ofds = unsafe { &mut *core::ptr::addr_of_mut!(OFDS) };
    if let Some(o) = ofds.get_mut(oi as usize).and_then(|s| s.as_mut()) {
        o.refs += 1;
    }
    fdt(t).fds[fi] = Some(oi);
    cloexec_set(t, fi, false);
    fi as u64
}

/// dup2(old, new): `new` names old's OFD, silently closing whatever it
/// held first. A huge target can't grow the table — the CVE-2025-39756
/// class is structurally dead here (fixed bound, EBADF).
pub fn fd_dup2(old: u64, new: u64) -> u64 {
    let Some(t) = cur_mut() else { return EBADF };
    let Some(&oi) = fdt(t).fds.get(old as usize).and_then(|s| s.as_ref()) else {
        return EBADF;
    };
    if new as usize >= MAX_FDS {
        return EBADF;
    }
    if old == new {
        return new;
    }
    // Release whatever `new` held, then point it at old's OFD.
    if let Some(prev) = fdt(t).fds[new as usize].take() {
        ofd_release(prev as usize);
    }
    let ofds = unsafe { &mut *core::ptr::addr_of_mut!(OFDS) };
    if let Some(o) = ofds.get_mut(oi as usize).and_then(|s| s.as_mut()) {
        o.refs += 1;
    }
    fdt(t).fds[new as usize] = Some(oi);
    cloexec_set(t, new as usize, false);
    new
}

/// dup3(old, new, flags): dup2 with the O_CLOEXEC option — and a
/// real difference from dup2: old==new is EINVAL, not a no-op.
pub fn fd_dup3(old: u64, new: u64, flags: u64) -> u64 {
    if old == new {
        return EINVAL;
    }
    if flags & !O_CLOEXEC != 0 {
        return EINVAL;
    }
    let r = fd_dup2(old, new);
    if (r as i64) < 0 {
        return r;
    }
    if flags & O_CLOEXEC != 0 {
        if let Some(t) = cur_mut() {
            cloexec_set(t, new as usize, true);
        }
    }
    r
}

/// close(fd): drops one reference; the OFD dies with its last slot.
/// Linux lets you close std streams, so we do too — the next use
/// gets EBADF, which is correct.
pub fn fd_close(fd: u64) -> u64 {
    let Some(t) = cur_mut() else { return EBADF };
    let Some(slot) = fdt(t).fds.get_mut(fd as usize) else {
        return EBADF;
    };
    let Some(oi) = slot.take() else { return EBADF };
    ofd_release(oi as usize);
    0
}

/// Drop one reference on OFD `oi`; at zero, retire it — pipe ends
/// then run endpoint accounting (a dup'd end only counts once).
fn ofd_release(oi: usize) {
    let ofds = unsafe { &mut *core::ptr::addr_of_mut!(OFDS) };
    let Some(o) = ofds.get_mut(oi).and_then(|s| s.as_mut()) else {
        return;
    };
    o.refs -= 1;
    if o.refs > 0 {
        return;
    }
    // Take the kind out before clearing so endpoint teardown runs
    // after the OFD is already gone; accmode feeds close events.
    let accmode = o.accmode;
    let kind = core::mem::replace(&mut o.kind, FdKind::Stdin);
    ofds[oi] = None;
    // An OFD's death retires every epoll interest pinning it —
    // Linux drops the epitem on file teardown the same way.
    {
        let eps = unsafe { &mut *core::ptr::addr_of_mut!(EPOLLS) };
        for inst in eps.iter_mut().flatten() {
            for e in inst.ents.iter_mut() {
                if e.is_some_and(|x| x.ofd == oi as u8) {
                    *e = None;
                }
            }
        }
    }
    if let FdKind::Epoll(i) = kind {
        unsafe { (*core::ptr::addr_of_mut!(EPOLLS))[i] = None };
    }
    if let FdKind::Eventfd(i) = kind {
        unsafe { (*core::ptr::addr_of_mut!(EVENTFDS))[i] = None };
    }
    if let FdKind::Timerfd(i) = kind {
        unsafe { (*core::ptr::addr_of_mut!(TIMERFDS))[i] = None };
    }
    if let FdKind::Signalfd(i) = kind {
        unsafe { (*core::ptr::addr_of_mut!(SIGNALFDS))[i] = None };
    }
    if let FdKind::Inotify(i) = kind {
        unsafe { (*core::ptr::addr_of_mut!(INOTIFY))[i] = None };
    }
    if let FdKind::Pipe { id, write } = kind {
        pipe_end_closed(id, write);
    }
    if let FdKind::Udp(i) = kind {
        // The endpoint dies with its last fd — queued dgrams free
        // with it. A blocked recvfrom on this socket can't exist:
        // the blocker's own fd pins the endpoint alive.
        unsafe { (*core::ptr::addr_of_mut!(UDPSOCKS))[i] = None };
    }
    if let FdKind::Tcp(i) = kind {
        tcp_sock_close(i);
    }
    if let FdKind::Proc { buf, .. } = kind {
        // The rendered snapshot frame — OFD-owned, freed with it.
        kalloc::free_frame(buf);
    }
    let ram_i = match kind {
        FdKind::Ram(i) | FdKind::Dev(i) => Some(i),
        _ => None,
    };
    if let Some(i) = ram_i {
        // Delete-pending (Windows FileDispositionInformation): the
        // vfile loses its name at last close; its storage lives on
        // while other OFDs share it — unlink-while-open for free.
        let del = unsafe { OFD_DEL[oi] };
        if del != 0 {
            unsafe { OFD_DEL[oi] = 0 };
            vfile_remove(i);
        }
        // inotify close events: CLOSE_WRITE iff the file was opened
        // for writing, CLOSE_NOWRITE otherwise (Linux's rule).
        if let Some(v) = vfile(i) {
            let mut nm = [0u8; 128];
            nm[..v.nlen].copy_from_slice(&v.name[..v.nlen]);
            let m = if accmode != 0 { IN_CLOSE_WRITE } else {
                IN_CLOSE_NOWRITE
            };
            ino_report(&nm[..v.nlen], m, 0);
        }
        // unlinked-while-open storage dies with its last OFD; a
        // still-linked file is owned by the VFS slot and stays.
        if let Some(v) = vfile(i) {
            if v.unlinked {
                if !v.data.is_null() {
                    // SAFETY: v.data was kmalloc'd at v.cap; the slot
                    // goes None right after so nothing can touch it.
                    unsafe { kalloc::kfree(v.data) };
                }
                unsafe { (*core::ptr::addr_of_mut!(VFILES))[i] = None };
            }
        }
    }
}

/// The last fd naming one pipe end went away. Decrement the endpoint
/// count; free the ring when both ends are gone; otherwise wake the
/// opposite side — writers see EPIPE with no readers left, readers
/// see EOF (0) when the writers are all gone.
fn pipe_end_closed(id: usize, write: bool) {
    let pipes = unsafe { &mut *core::ptr::addr_of_mut!(PIPES) };
    let Some(p) = pipes.get_mut(id).and_then(|s| s.as_mut()) else {
        return;
    };
    if write {
        p.writers -= 1;
    } else {
        p.readers -= 1;
    }
    let gone = if write { p.writers == 0 } else { p.readers == 0 };
    if p.readers == 0 && p.writers == 0 {
        kalloc::free_frame(p.buf);
        pipes[id] = None;
        return;
    }
    if gone {
        // EOF to readers / EPIPE to writers.
        wake_pipe_waiters(
            if write {
                WaitOn::PipeRead(id)
            } else {
                WaitOn::PipeWrite(id)
            },
            if write { 0 } else { (-32i64) as u64 },
        );
    }
}

/// Wake every task blocked on `on` with `ret` as its syscall result
/// — the endpoint-teardown wake (EOF/EPIPE), no data moves.
fn wake_pipe_waiters(on: WaitOn, ret: u64) {
    let tasks = unsafe { &mut *core::ptr::addr_of_mut!(TASKS) };
    for s in tasks.iter_mut() {
        if let Some(t) = s.as_mut() {
            if t.state == TaskState::Blocked && t.wait_on == on {
                t.ctx.rax = ret;
                t.wait_on = WaitOn::None;
                t.wait_deadline = 0;
                t.state = TaskState::Runnable;
            }
        }
    }
    // Endpoint teardown also changes poll readiness (POLLHUP/ERR).
    wake_pollers();
}

/// Feed blocked readers from pipe `id`'s ring, greedily: each waiter
/// gets min(its len, available) bytes copied through its own page
/// tables (per-byte translate — the sleeping task's space isn't
/// mapped under the waker's cr3). Returns how many tasks woke.
fn wake_pipe_readers(id: usize) -> usize {
    let tasks = unsafe { &mut *core::ptr::addr_of_mut!(TASKS) };
    let pipes = unsafe { &mut *core::ptr::addr_of_mut!(PIPES) };
    let mut woke = 0;
    for s in tasks.iter_mut() {
        let Some(t) = s.as_mut() else { continue };
        if t.state != TaskState::Blocked || t.wait_on != WaitOn::PipeRead(id) {
            continue;
        }
        let Some(p) = pipes.get_mut(id).and_then(|x| x.as_mut()) else {
            break;
        };
        let avail = p.tail - p.head;
        if avail == 0 {
            break; // nothing left to hand out
        }
        let n = core::cmp::min(t.wait_len as usize, avail);
        let mut done = 0usize;
        while done < n {
            // SAFETY: ring frame is pipe-owned, index wraps in bounds.
            let b = unsafe {
                ((p.buf + ((p.head + done) % PIPE_SIZE) as u64) as *const u8).read()
            };
            match translate(t.pml4, t.wait_ptr + done as u64) {
                // SAFETY: pa is a present user frame in t's tables.
                Some(pa) => unsafe { (pa as *mut u8).write(b) },
                None => break,
            }
            done += 1;
        }
        p.head += done;
        t.ctx.rax = if done == 0 { (-14i64) as u64 } else { done as u64 };
        t.wait_on = WaitOn::None;
        t.state = TaskState::Runnable;
        woke += 1;
    }
    woke
}

/// Drain blocked writers into pipe `id`'s ring. A writer unblocks
/// only when its whole len fits — writes <= PIPE_BUF are atomic,
/// and len is capped at the frame size, so full-space means empty.
/// Returns how many tasks woke.
fn wake_pipe_writers(id: usize) -> usize {
    let tasks = unsafe { &mut *core::ptr::addr_of_mut!(TASKS) };
    let pipes = unsafe { &mut *core::ptr::addr_of_mut!(PIPES) };
    let mut woke = 0;
    for s in tasks.iter_mut() {
        let Some(t) = s.as_mut() else { continue };
        if t.state != TaskState::Blocked || t.wait_on != WaitOn::PipeWrite(id) {
            continue;
        }
        let Some(p) = pipes.get_mut(id).and_then(|x| x.as_mut()) else {
            break;
        };
        if PIPE_SIZE - (p.tail - p.head) < t.wait_len as usize {
            continue; // still doesn't fit — stays blocked
        }
        let len = t.wait_len as usize;
        let mut done = 0usize;
        while done < len {
            match translate(t.pml4, t.wait_ptr + done as u64) {
                // SAFETY: pa is a present user frame in t's tables;
                // the ring index wraps inside our frame.
                Some(pa) => unsafe {
                    let b = (pa as *const u8).read();
                    ((p.buf + ((p.tail + done) % PIPE_SIZE) as u64) as *mut u8)
                        .write(b)
                },
                None => break,
            }
            done += 1;
        }
        p.tail += done;
        t.ctx.rax = if done == 0 { (-14i64) as u64 } else { done as u64 };
        t.wait_on = WaitOn::None;
        t.state = TaskState::Runnable;
        woke += 1;
    }
    woke
}

/// After a pipe's fill level changes, settle both wait directions.
/// A woken reader frees space (writers may fit); a woken writer adds
/// data (more readers may be fed). Every wake clears wait_on, so
/// this loop is monotonically terminating within MAX_TASKS. Poll
/// waiters re-scan on any pipe change (their fd set may name it).
fn pipe_wake(id: usize) {
    loop {
        if wake_pipe_readers(id) + wake_pipe_writers(id) == 0 {
            break;
        }
    }
    wake_pollers();
}

/// poll() event bits — the standard Linux POLL* values.
const POLLIN: u16 = 0x0001;
const POLLOUT: u16 = 0x0004;
const POLLERR: u16 = 0x0008;
const POLLHUP: u16 = 0x0010;
const POLLNVAL: u16 = 0x0020;
/// Bounded pollfd array — same fixed-table discipline as MAX_FDS.
const MAX_POLL: u64 = 32;

/// Read `len` user bytes from another space via per-byte translate —
/// small (<=8B) structured reads for pollfd fields on a sleeping task.
fn read_task_u(pml4: u64, va: u64, len: u64) -> Option<u64> {
    let mut v = 0u64;
    for i in 0..len {
        let pa = translate_r(pml4, va + i)?;
        // SAFETY: pa is a present user frame in pml4.
        v |= (unsafe { (pa as *const u8).read() } as u64) << (i * 8);
    }
    Some(v)
}

/// Write one u16 into another space (pollfd.revents on a sleeper).
fn write_task_u16(pml4: u64, va: u64, v: u16) {
    for i in 0..2u64 {
        if let Some(pa) = translate(pml4, va + i) {
            // SAFETY: pa is a present user frame in pml4.
            unsafe { (pa as *mut u8).write((v >> (i * 8)) as u8) };
        }
    }
}

/// Write one u32 into another space (epoll_event.events).
fn write_task_u32(pml4: u64, va: u64, v: u32) {
    for i in 0..4u64 {
        if let Some(pa) = translate(pml4, va + i) {
            // SAFETY: pa is a present user frame in pml4.
            unsafe { (pa as *mut u8).write((v >> (i * 8)) as u8) };
        }
    }
}

/// Write one u64 into another space (pselect6 fd_set words).
fn write_task_u64(pml4: u64, va: u64, v: u64) {
    for i in 0..8u64 {
        if let Some(pa) = translate(pml4, va + i) {
            // SAFETY: pa is a present user frame in pml4.
            unsafe { (pa as *mut u8).write((v >> (i * 8)) as u8) };
        }
    }
}

/// Evaluate one pollfd's revents against kernel state. Requested
/// events are masked in; ERR/HUP/NVAL report unconditionally like
/// Linux (they describe the fd, not the request).
fn poll_revents(t: &Task, fd: i32, events: u16) -> u16 {
    if !(0..MAX_FDS as i32).contains(&fd) {
        return POLLNVAL;
    }
    let Some(oi) = fdt(t).fds[fd as usize] else {
        return POLLNVAL;
    };
    ofd_revents(t.pending, oi, events)
}

/// The task-light core: revents of an OPEN FILE DESCRIPTION. epoll
/// pins the OFD, so its scan evaluates this directly — the fd
/// number only matters at ctl time. `pend` is the polling task's
/// signal mask (signalfd readiness is per-reader).
fn ofd_revents(pend: u32, oi: u8, events: u16) -> u16 {
    let ofds = unsafe { &*core::ptr::addr_of!(OFDS) };
    let Some(o) = ofds.get(oi as usize).and_then(|s| s.as_ref()) else {
        return POLLNVAL;
    };
    let pipes = unsafe { &*core::ptr::addr_of!(PIPES) };
    let r = match &o.kind {
        // Console writes never block; stdin is readable when the
        // input queue has bytes (or the EOF flag is pending — Linux
        // reports POLLIN at tty EOF too).
        FdKind::Stdin => {
            if stdin_ready() > 0 {
                POLLIN
            } else {
                0
            }
        }
        FdKind::Dev(i) => {
            if vfile(*i).is_some_and(|v| v.rdev >> 8 == 5) {
                // tty: writable always, readable when input queues.
                let mut r = POLLOUT;
                if stdin_ready() > 0 {
                    r |= POLLIN;
                }
                r
            } else {
                // null/zero/full/random never block either way.
                POLLIN | POLLOUT
            }
        }
        FdKind::Console => POLLOUT,
        // File, dir and proc reads never block (EOF reads return 0).
        FdKind::File(_) | FdKind::Dir(_) | FdKind::Proc { .. } => POLLIN,
        // A RAM file is a regular file: reads never block at EOF and
        // writes never block — Linux polls both ready always.
        FdKind::Ram(_) => POLLIN | POLLOUT,
        // UDP: readable when a datagram queues; send never blocks.
        FdKind::Udp(i) => {
            let socks = unsafe { &*core::ptr::addr_of!(UDPSOCKS) };
            let mut r = POLLOUT;
            if socks.get(*i).and_then(|s| s.as_ref()).is_some_and(|k| k.q.is_some()) {
                r |= POLLIN;
            }
            r
        }
        // TCP: listener readable when a child waits; a connection
        // readable on data/EOF, writable once established, ERR on
        // RST, HUP once fully closed.
        FdKind::Tcp(i) => {
            let socks = unsafe { &*core::ptr::addr_of!(TCPSOCKS) };
            match socks.get(*i).and_then(|s| s.as_ref()) {
                None => POLLNVAL,
                Some(k) if k.state == TcpState::Listen => {
                    if k.blen > 0 { POLLIN } else { 0 }
                }
                Some(k) => {
                    let mut r = 0;
                    if k.dead {
                        r |= POLLERR;
                    }
                    if k.rxl > 0 || k.fin_rx || k.state == TcpState::Closed {
                        r |= POLLIN;
                    }
                    if matches!(k.state, TcpState::Estab | TcpState::CloseWait) {
                        r |= POLLOUT;
                    }
                    if k.state == TcpState::Closed {
                        r |= POLLHUP;
                    }
                    r
                }
            }
        }
        FdKind::Pipe { id, write } => {
            match pipes.get(*id).and_then(|s| s.as_ref()) {
                None => POLLERR, // peer's frame freed — torn down
                Some(p) if !write => {
                    let mut r = 0;
                    if p.tail > p.head {
                        r |= POLLIN;
                    }
                    if p.writers == 0 {
                        r |= POLLHUP; // every writer gone — read won't block
                    }
                    r
                }
                Some(p) => {
                    let mut r = 0;
                    if p.readers == 0 {
                        r |= POLLERR; // write would EPIPE
                    }
                    if PIPE_SIZE - (p.tail - p.head) > 0 {
                        r |= POLLOUT;
                    }
                    r
                }
            }
        }
        // poll() on an epoll fd: readable when any interest is.
        // ctl rejects epoll-kind members (ELOOP), so this arm can
        // never recurse into itself.
        FdKind::Epoll(ei) => {
            let eps = unsafe { &*core::ptr::addr_of!(EPOLLS) };
            let mut r = 0;
            if let Some(inst) = eps.get(*ei).and_then(|s| s.as_ref()) {
                for e in inst.ents.iter().flatten() {
                    let x = ofd_revents(pend, e.ofd, e.events as u16);
                    if x != 0 && x & POLLNVAL == 0 {
                        r = POLLIN;
                        break;
                    }
                }
            }
            r
        }
        // eventfd: readable when the counter is nonzero, writable
        // while an add of at least 1 still fits under the ceiling.
        FdKind::Eventfd(i) => {
            let evs = unsafe { &*core::ptr::addr_of!(EVENTFDS) };
            match evs.get(*i).and_then(|s| s.as_ref()) {
                None => POLLNVAL,
                Some(e) => {
                    let mut r = 0;
                    if e.count > 0 {
                        r |= POLLIN;
                    }
                    if e.count < EFD_MAX {
                        r |= POLLOUT;
                    }
                    r
                }
            }
        }
        // timerfd: readable once expirations are pending — or the
        // deadline already passed and the tick hasn't folded it in
        // yet (a poll right at the boundary must not report cold).
        FdKind::Timerfd(i) => {
            let tfs = unsafe { &*core::ptr::addr_of!(TIMERFDS) };
            match tfs.get(*i).and_then(|s| s.as_ref()) {
                None => POLLNVAL,
                Some(tf) => {
                    let now = crate::apic::TICKS
                        .load(core::sync::atomic::Ordering::Relaxed);
                    if tf.expirations > 0 || (tf.armed && tf.deadline <= now) {
                        POLLIN
                    } else {
                        0
                    }
                }
            }
        }
        // signalfd: readable when the POLLING task has a pending
        // signal in the instance's mask — the queue is the reader's.
        FdKind::Signalfd(i) => {
            let sfs = unsafe { &*core::ptr::addr_of!(SIGNALFDS) };
            match sfs.get(*i).and_then(|s| s.as_ref()) {
                None => POLLNVAL,
                Some(s) => {
                    if pend & s.mask != 0 { POLLIN } else { 0 }
                }
            }
        }
        // inotify: readable with a queued event (or a pending
        // overflow record that drains as one).
        FdKind::Inotify(i) => {
            let ins = unsafe { &*core::ptr::addr_of!(INOTIFY) };
            match ins.get(*i).and_then(|s| s.as_ref()) {
                None => POLLNVAL,
                Some(s) => {
                    if s.q.iter().any(|e| e.is_some()) || s.overflow {
                        POLLIN
                    } else {
                        0
                    }
                }
            }
        }
    };
    (r & events) | (r & (POLLERR | POLLHUP | POLLNVAL))
}

/// Scan a task's pollfd array through ITS page tables, writing each
/// revents. Returns the count of nonzero revents — works on the
/// current task and on a blocked one (translate walks the pml4).
fn poll_scan(t: &Task, fds: u64, nfds: u64) -> u64 {
    let mut ready = 0;
    for i in 0..nfds {
        let va = fds + i * 8;
        let (fd, events) = match (
            read_task_u(t.pml4, va, 4),
            read_task_u(t.pml4, va + 4, 2),
        ) {
            (Some(f), Some(e)) => (f as u32 as i32, e as u16),
            _ => {
                write_task_u16(t.pml4, va + 6, POLLNVAL);
                ready += 1;
                continue;
            }
        };
        let r = poll_revents(t, fd, events);
        write_task_u16(t.pml4, va + 6, r);
        if r != 0 {
            ready += 1;
        }
    }
    ready
}

/// Wake any blocked poller whose fd set is now ready — called after
/// every pipe-state change. The scan rewrites revents through the
/// sleeper's tables and the ready count lands in its syscall rax.
fn wake_pollers() {
    let tasks = unsafe { &mut *core::ptr::addr_of_mut!(TASKS) };
    for s in tasks.iter_mut() {
        let Some(t) = s.as_mut() else { continue };
        if t.state != TaskState::Blocked {
            continue;
        }
        let n = match t.wait_on {
            WaitOn::Poll => poll_scan(t, t.wait_ptr, t.wait_len),
            WaitOn::Pselect => {
                pselect_scan(t, t.wait_ptr, t.wait_ptr2, t.wait_ptr3, t.wait_len)
            }
            WaitOn::Epoll(ei) => epoll_scan(t, ei, t.wait_ptr, t.wait_len),
            _ => continue,
        };
        if n > 0 {
            t.ctx.rax = n;
            t.wait_on = WaitOn::None;
            t.wait_deadline = 0;
            psel_restore(t);
            t.state = TaskState::Runnable;
        }
    }
}

/// Wake up to `n` tasks futex-waiting on `uaddr` in `pml4`'s space.
/// The key is (pml4, va) so a shared-mm thread and an unrelated
/// process waiting on the same VA don't collide — an approximation
/// of Linux's physical-address keying that is exact while no memory
/// is shared between different mms.
fn futex_wake(pml4: u64, uaddr: u64, n: u64) -> u64 {
    let tasks = unsafe { &mut *core::ptr::addr_of_mut!(TASKS) };
    let mut woke = 0u64;
    for s in tasks.iter_mut() {
        if woke == n {
            break;
        }
        let Some(t) = s.as_mut() else { continue };
        if t.state == TaskState::Blocked
            && t.wait_on == WaitOn::Futex(uaddr)
            && t.pml4 == pml4
        {
            t.ctx.rax = 0;
            t.wait_on = WaitOn::None;
            t.wait_deadline = 0;
            t.state = TaskState::Runnable;
            woke += 1;
        }
    }
    woke
}

/// futex(uaddr, op, val, timeout, uaddr2, val3): the WAIT/WAKE pair
/// every userspace lock builds on — pthread mutexes, conds, join's
/// ctid wait. PRIVATE/CLOCK flags are hints we collapse (single
/// key space, one clock); everything else is honest ENOSYS.
pub fn sys_futex(
    ctx: &mut UCtx,
    uaddr: u64,
    op: u64,
    val: u64,
    timeout: u64,
    _uaddr2: u64,
    _val3: u64,
) -> u64 {
    const ENOSYS_: u64 = (-38i64) as u64;
    const EAGAIN_: u64 = (-11i64) as u64;
    const ETIMEDOUT_: u64 = (-110i64) as u64;
    match op & 0x7f {
        0 => {
            // FUTEX_WAIT: sleep only while *uaddr == val — the
            // compare-then-block is atomic because syscalls run
            // IF-masked on the single CPU.
            let Some(t) = cur_mut() else { return EAGAIN_ };
            if !range_ok(uaddr, 4) {
                return EFAULT;
            }
            // SAFETY: uaddr is a validated user word under cur cr3.
            let cur = unsafe { (uaddr as *const u32).read_unaligned() };
            if cur != val as u32 {
                return EAGAIN_;
            }
            let mut deadline = 0u64;
            if timeout != 0 {
                if !range_ok(timeout, 16) {
                    return EFAULT;
                }
                // SAFETY: validated user timespec under cur cr3.
                let (sec, nsec) = unsafe {
                    (
                        (timeout as *const i64).read_unaligned(),
                        (timeout as *const i64)
                            .add(1)
                            .read_unaligned(),
                    )
                };
                let ticks = (sec.max(0) as u64)
                    .saturating_mul(100)
                    .saturating_add((nsec.max(0) as u64) / 10_000_000);
                if ticks == 0 {
                    return ETIMEDOUT_;
                }
                deadline = crate::apic::TICKS
                    .load(core::sync::atomic::Ordering::Relaxed)
                    .saturating_add(ticks);
            }
            if deliverable(t) {
                return (-4i64) as u64; // -EINTR before sleep
            }
            t.wait_on = WaitOn::Futex(uaddr);
            t.wait_deadline = deadline;
            t.ctx = *ctx;
            t.state = TaskState::Blocked;
            block_switch()
        }
        1 => {
            // FUTEX_WAKE: wake up to `val` waiters on our mm's word.
            let Some(t) = cur_mut() else { return 0 };
            let pml4 = t.pml4;
            futex_wake(pml4, uaddr, val)
        }
        _ => ENOSYS_,
    }
}

/// Timer tick: expire timed poll waits — the return is 0 with
/// revents zeroed, the Linux timeout shape.
fn poll_expire() {
    let now = crate::apic::TICKS.load(core::sync::atomic::Ordering::Relaxed);
    let tasks = unsafe { &mut *core::ptr::addr_of_mut!(TASKS) };
    for s in tasks.iter_mut() {
        let Some(t) = s.as_mut() else { continue };
        if t.state == TaskState::Blocked
            && t.wait_deadline != 0
            && now >= t.wait_deadline
        {
            match t.wait_on {
                WaitOn::Poll => {
                    for i in 0..t.wait_len {
                        write_task_u16(t.pml4, t.wait_ptr + i * 8 + 6, 0);
                    }
                    t.ctx.rax = 0;
                    psel_restore(t); // no-op for plain poll
                }
                WaitOn::Pselect => {
                    // Timed out: every output word reads zero — the
                    // same "nothing ready" shape poll writes.
                    for va in [t.wait_ptr, t.wait_ptr2, t.wait_ptr3] {
                        if va == 0 {
                            continue;
                        }
                        for w in 0..t.wait_len {
                            write_task_u64(t.pml4, va + w * 8, 0);
                        }
                    }
                    t.ctx.rax = 0;
                    psel_restore(t);
                }
                WaitOn::Epoll(_) => {
                    // Timed out: 0 events, buffer untouched, and a
                    // pwait temporary mask still owed back.
                    t.ctx.rax = 0;
                    psel_restore(t);
                }
                WaitOn::TcpConn(si) => {
                    // connect() timed out: ETIMEDOUT, the socket
                    // marked dead so further io fails fast.
                    t.ctx.rax = (-110i64) as u64;
                    if let Some(k) = tcp_socks()[si].as_mut() {
                        k.dead = true;
                        k.state = TcpState::Closed;
                    }
                }
                WaitOn::Timer => t.ctx.rax = 0, // nanosleep elapsed
                // sigtimedwait deadline: nothing arrived — EAGAIN
                // is Linux's timeout answer (not EINTR).
                WaitOn::SigTimed => t.ctx.rax = (-11i64) as u64,
                WaitOn::Futex(_) => {
                    t.ctx.rax = (-110i64) as u64 // ETIMEDOUT
                }
                _ => continue,
            }
            t.wait_on = WaitOn::None;
            t.wait_deadline = 0;
            t.state = TaskState::Runnable;
        }
    }
}

/// poll(fds, nfds, timeout_ms): Linux pollfd {fd,events,revents} is
/// 8 bytes; revents write back through the caller's own tables.
/// Readiness is honest kernel state — pipes by ring level and
/// endpoint counts, files/dirs/console statically. timeout<0 waits
/// forever; nfds=0 with timeout>0 is a plain sleep.
pub fn fd_poll(ctx: &mut UCtx, fds: u64, nfds: u64, timeout_ms: i64) -> u64 {
    const EINTR: u64 = (-4i64) as u64;
    if nfds > MAX_POLL {
        return EINVAL;
    }
    let Some(t) = cur_mut() else { return EINVAL };
    if nfds > 0 && !range_ok_w(fds, nfds * 8) {
        return EFAULT;
    }
    let ready = if nfds == 0 { 0 } else { poll_scan(t, fds, nfds) };
    if ready > 0 || timeout_ms == 0 {
        return ready;
    }
    if deliverable(t) {
        return EINTR; // a signal landed before we slept
    }
    t.wait_on = WaitOn::Poll;
    t.wait_ptr = fds;
    t.wait_len = nfds;
    t.wait_deadline = if timeout_ms < 0 {
        0
    } else {
        crate::apic::TICKS.load(core::sync::atomic::Ordering::Relaxed)
            + (timeout_ms as u64).div_ceil(10)
    };
    t.ctx = *ctx;
    t.state = TaskState::Blocked;
    block_switch()
}

/// sigpending(set, sigsetsize): report the pending-signal bitmask.
/// Linux returns the full sigset_t; our signal space is 32 so the
/// mask is exact.
pub fn sys_sigpending(set: u64, sigsize: u64) -> u64 {
    if sigsize != 8 {
        return EINVAL;
    }
    if !range_ok_w(set, 8) {
        return EFAULT;
    }
    let Some(t) = cur_mut() else { return EINVAL };
    // SAFETY: validated user VA under cur cr3.
    unsafe { (set as *mut u64).write_unaligned(t.pending as u64) };
    0
}

/// pause(): sleep until any signal arrives — always -EINTR to user.
/// SigWait carries no deadline or resource; the generic signal-wake
/// path clears it and supplies the return value.
pub fn sys_pause(ctx: &mut UCtx) -> u64 {
    const EINTR: u64 = (-4i64) as u64;
    let Some(t) = cur_mut() else { return EINVAL };
    if deliverable(t) {
        return EINTR;
    }
    t.wait_on = WaitOn::SigWait;
    t.wait_deadline = 0;
    t.ctx = *ctx;
    t.state = TaskState::Blocked;
    block_switch()
}

/// sigsuspend(mask, sigsetsize): atomically swap the sigmask and
/// sleep until a signal — Linux's primitive for race-free signal
/// waits. The saved mask rides psel_mask so the shared restore path
/// puts it back on the signal wake; the return is always -EINTR.
pub fn sys_sigsuspend(ctx: &mut UCtx, mask: u64, sigsize: u64) -> u64 {
    const EINTR: u64 = (-4i64) as u64;
    if sigsize != 8 {
        return EINVAL;
    }
    if !range_ok(mask, 8) {
        return EFAULT;
    }
    let Some(t) = cur_mut() else { return EINVAL };
    // SAFETY: validated user sigset under cur cr3.
    let newmask = unsafe { (mask as *const u64).read_unaligned() } as u32;
    let saved = t.sigmask;
    t.sigmask = newmask;
    if deliverable(t) {
        // Linux runs the handler inside the suspend: deliver under
        // the temporary mask (the frame captures rax=-EINTR), then
        // restore. The syscall's own return also yields -EINTR if no
        // handler frame redirected the resume path.
        ctx.rax = EINTR;
        // Same frame-mask rule as the blocked wake: the frame's
        // saved mask is the ORIGINAL, not the temporary suspend
        // mask — the handler's sigreturn is the suspend's return.
        t.frame_mask = saved as u64;
        maybe_deliver(t, ctx);
        t.frame_mask = u64::MAX;
        t.sigmask = saved;
        return EINTR;
    }
    t.psel_mask = saved as u64;
    t.wait_on = WaitOn::SigWait;
    t.wait_deadline = 0;
    t.ctx = *ctx;
    t.state = TaskState::Blocked;
    block_switch()
}

/// Restore a pselect6-saved sigmask if one is owed — the swap lives
/// only for the sleep, and block_switch diverges so every wake path
/// (ready, timeout, signal) must put the original back first.
fn psel_restore(t: &mut Task) {
    if t.psel_mask != u64::MAX {
        t.sigmask = t.psel_mask as u32;
        t.psel_mask = u64::MAX;
    }
}

// --- synchronous signals: sigwait*, signalfd -------------------------
// The wait consumes pending signals from a set rather than running
// handlers — signals to wait on must be blocked by the caller so
// they STAY pending (POSIX). The waiter is WaitOn::SigTimed:
// pend_one collects an in-set arrival into the record buffer, an
// out-of-set deliverable signal interrupts like any wait, and the
// deadline arm answers EAGAIN for sigtimedwait timeouts.

/// Shared core of rt_sigwaitinfo/rt_sigtimedwait: dequeue the
/// lowest pending in-set signal into a 128-byte siginfo_t
/// (signo@0, rest zero — SI_USER kill() provenance is all zeros
/// beyond signo). Blocks in SigTimed when the set is cold.
fn sig_wait(ctx: &mut UCtx, set: u64, info: u64, ts: u64, timed: bool) -> u64 {
    const EAGAIN: u64 = (-11i64) as u64;
    const EINTR: u64 = (-4i64) as u64;
    if !range_ok(set, 8) {
        return EFAULT;
    }
    // SAFETY: validated user sigset under cur cr3.
    // SIGKILL/SIGSTOP can't be waited for — Linux strips them from
    // the set (do_sigtimedwait's sigdelsetmask), matching here.
    let wset = unsafe { (set as *const u64).read_unaligned() } as u32
        & !((1u32 << (SIGKILL - 1)) | (1u32 << (SIGSTOP - 1)));
    if info != 0 && !range_ok_w(info, 128) {
        return EFAULT;
    }
    let mut deadline = 0u64;
    if timed && ts != 0 {
        if !range_ok(ts, 16) {
            return EFAULT;
        }
        // SAFETY: validated user timespec {sec,nsec} under cur cr3.
        let (sec, nsec) = unsafe {
            (
                (ts as *const u64).read_unaligned(),
                (ts as *const u64).add(1).read_unaligned(),
            )
        };
        if nsec >= 1_000_000_000 {
            return EINVAL;
        }
        let now = crate::apic::TICKS.load(core::sync::atomic::Ordering::Relaxed);
        deadline = now
            .saturating_add(sec.saturating_mul(100))
            .saturating_add(nsec.div_ceil(10_000_000));
    }
    let Some(t) = cur_mut() else { return EINVAL };
    // Collect a signal that's already pending — ignored-disposition
    // bits are noise, skip them like pend_one does.
    let mut p = t.pending & wset;
    while p != 0 {
        let sig = p.trailing_zeros() as u64 + 1;
        p &= !(1u32 << (sig - 1));
        if sig_ignored(t, sig) {
            continue;
        }
        t.pending &= !(1u32 << (sig - 1));
        if info != 0 {
            let rec = sig_record(t, sig, false);
            // SAFETY: info validated writable for 128 bytes.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    rec.as_ptr(),
                    info as *mut u8,
                    128,
                )
            };
        } else {
            t.pend_src[sig as usize - 1] = SIGSRC_NONE;
        }
        return sig;
    }
    if timed && deadline <= crate::apic::TICKS
        .load(core::sync::atomic::Ordering::Relaxed)
    {
        return EAGAIN; // ts={0,0} polls once — no sleep
    }
    if deliverable(t) {
        return EINTR;
    }
    t.wait_on = WaitOn::SigTimed;
    t.wait_len = wset as u64;
    t.wait_ptr = info;
    t.wait_ptr2 = 0; // siginfo_t shape — rax = signo at wake
    t.wait_deadline = deadline;
    t.ctx = *ctx;
    t.state = TaskState::Blocked;
    block_switch()
}

/// rt_sigtimedwait(set, info, timespec, sigsetsize) — nr 128 is
/// the ONLY sigwait syscall on x86_64: glibc's sigwaitinfo calls
/// it with a NULL timespec, which is the infinite-wait path here.
pub fn sys_rt_sigtimedwait(
    ctx: &mut UCtx,
    set: u64,
    info: u64,
    ts: u64,
    sigsize: u64,
) -> u64 {
    if sigsize != 8 {
        return EINVAL;
    }
    sig_wait(ctx, set, info, ts, true)
}

/// signalfd4(fd, mask, sizemask, flags): fd<0 creates an instance,
/// fd>=0 replaces its mask. sizemask must be 8 like the sigset
/// family; signalfd(282) is the same minus the flags arg.
pub fn fd_signalfd4(fd: u64, mask_ptr: u64, sigsize: u64, flags: u64) -> u64 {
    const ENFILE_: u64 = (-23i64) as u64;
    const SFD_NONBLOCK: u64 = 0o4000;
    const SFD_CLOEXEC: u64 = 0o2000000;
    if sigsize != 8 || flags & !(SFD_NONBLOCK | SFD_CLOEXEC) != 0 {
        return EINVAL;
    }
    if !range_ok(mask_ptr, 8) {
        return EFAULT;
    }
    // SAFETY: validated user sigset under cur cr3.
    // SIGKILL/SIGSTOP can't be caught — strip them like Linux's
    // dequeue_signal sig_kernel_only skip, or a parked reader could
    // swallow a fatal signal and become unkillable.
    let mask = unsafe { (mask_ptr as *const u64).read_unaligned() } as u32
        & !((1u32 << (SIGKILL - 1)) | (1u32 << (SIGSTOP - 1)));
    let Some(t) = cur_mut() else { return EINVAL };
    // fd is an int: user space's -1 arrives zero-extended as
    // 0xFFFFFFFF, not u64::MAX — compare the low word.
    if fd as i32 != -1 {
        // Update an existing signalfd's mask (the only valid reuse).
        let Some(o) = ofd(t, fd) else { return EBADF };
        let FdKind::Signalfd(i) = o.kind else { return EINVAL };
        let sfs = unsafe { &mut *core::ptr::addr_of_mut!(SIGNALFDS) };
        let Some(s) = sfs.get_mut(i).and_then(|s| s.as_mut()) else {
            return EBADF;
        };
        s.mask = mask;
        return fd;
    }
    let sfs = unsafe { &mut *core::ptr::addr_of_mut!(SIGNALFDS) };
    let Some(i) = sfs.iter().position(Option::is_none) else {
        return ENFILE_;
    };
    sfs[i] = Some(Signalfd {
        mask,
        nonblock: flags & SFD_NONBLOCK != 0,
    });
    let nfd = anon_fd(FdKind::Signalfd(i), flags & SFD_CLOEXEC != 0);
    if (nfd as i64) < 0 {
        sfs[i] = None; // fd table full — don't leak the instance
    }
    nfd
}

/// signalfd(fd, mask, sizemask) — the pre-flags call; SFD_NONBLOCK
/// can't be requested here (glibc fcntls it on when needed).
pub fn fd_signalfd(fd: u64, mask_ptr: u64, sigsize: u64) -> u64 {
    fd_signalfd4(fd, mask_ptr, sigsize, 0)
}

/// signalfd read: dequeue the reader's lowest pending in-mask
/// signal into a 128-byte signalfd_siginfo (signo@0, rest zero).
/// Empty queue: EAGAIN nonblock, else WaitOn::SigTimed — the waker
/// deposits the record and answers 128 like a PipeRead deposit.
fn signalfd_read(ctx: &mut UCtx, i: usize, buf: u64, len: u64) -> u64 {
    const EAGAIN: u64 = (-11i64) as u64;
    const EINTR: u64 = (-4i64) as u64;
    if len < 128 {
        return EINVAL;
    }
    if !range_ok_w(buf, 128) {
        return EFAULT;
    }
    let sfs = unsafe { &*core::ptr::addr_of!(SIGNALFDS) };
    let Some(mask) = sfs
        .get(i)
        .and_then(|s| s.as_ref())
        .map(|s| s.mask)
    else {
        return EBADF;
    };
    let Some(t) = cur_mut() else { return EBADF };
    let mut p = t.pending & mask;
    while p != 0 {
        let sig = p.trailing_zeros() as u64 + 1;
        p &= !(1u32 << (sig - 1));
        if sig_ignored(t, sig) {
            continue;
        }
        t.pending &= !(1u32 << (sig - 1));
        let rec = sig_record(t, sig, true);
        // SAFETY: buf validated writable for 128 bytes.
        unsafe {
            core::ptr::copy_nonoverlapping(rec.as_ptr(), buf as *mut u8, 128)
        };
        return 128;
    }
    let nonblock = sfs
        .get(i)
        .and_then(|s| s.as_ref())
        .map_or(false, |s| s.nonblock);
    if nonblock {
        return EAGAIN;
    }
    if deliverable(t) {
        return EINTR;
    }
    t.wait_on = WaitOn::SigTimed;
    t.wait_len = mask as u64;
    t.wait_ptr = buf;
    t.wait_ptr2 = 1; // signalfd_siginfo shape — rax = 128 at wake
    t.wait_deadline = 0;
    t.ctx = *ctx;
    t.state = TaskState::Blocked;
    block_switch()
}

// --- inotify ----------------------------------------------------------
// Watch table keyed on canonical path; events route to self watchers
// (nameless) and parent-dir watchers (named). The queue is bounded —
// overflow folds into one IN_Q_OVERFLOW record at next drain, the
// same shape Linux reports under event pressure.

/// Queue one event on an instance; overflow marks the flag rather
/// than dropping silently.
fn ino_q_push(i: usize, ev: InoEv) {
    let Some(inst) = (unsafe { &mut *core::ptr::addr_of_mut!(INOTIFY) })
        .get_mut(i)
        .and_then(|s| s.as_mut())
    else {
        return;
    };
    if let Some(s) = inst.q.iter_mut().find(|s| s.is_none()) {
        *s = Some(ev);
    } else {
        inst.overflow = true;
    }
}

/// Emit a filesystem event: `path` is canonical (no leading '/').
/// Self watchers on the path get a nameless record; watchers on the
/// parent dir get one named by the final component. `del` flags a
/// self-delete: IN_IGNORED follows and the watch dies (Linux drops
/// the wd on object destruction).
fn ino_report(path: &[u8], mask: u32, cookie: u32) {
    let base = match path.iter().rposition(|&c| c == b'/') {
        Some(p) => &path[p + 1..],
        None => path,
    };
    let parent = &path[..path.len() - base.len() - (base.len() < path.len()) as usize];
    let selfmask = mask & (IN_DELETE_SELF | IN_MOVE_SELF);
    let mut queued = false;
    let insts = unsafe { &mut *core::ptr::addr_of_mut!(INOTIFY) };
    for ii in 0..MAX_INOTIFY {
        let Some(inst) = insts[ii].as_mut() else { continue };
        for wi in 0..MAX_IWATCHES {
            let Some(w) = inst.watches[wi].as_ref() else { continue };
            let wpath = &w.path[..w.nlen as usize];
            if wpath == path {
                // Self watch: self events always land; dir-style
                // events need the mask bit like Linux filtering.
                let m = if selfmask != 0 { selfmask } else { mask };
                if m & w.mask & IN_ALL_EVENTS != 0 || selfmask != 0 {
                    ino_q_push(ii, InoEv {
                        wd: wi as i32 + 1, mask: m, cookie,
                        name: [0; 128], nlen: 0,
                    });
                    queued = true;
                }
            } else if w.dir && wpath == parent {
                if mask & w.mask & IN_ALL_EVENTS != 0 {
                    let mut ev = InoEv {
                        wd: wi as i32 + 1, mask, cookie,
                        name: [0; 128], nlen: 0,
                    };
                    let n = base.len().min(128);
                    ev.name[..n].copy_from_slice(&base[..n]);
                    ev.nlen = n as u8;
                    ino_q_push(ii, ev);
                    queued = true;
                }
            }
        }
    }
    // Wake blocked readers only when an event actually landed —
    // emitters call this from mid-syscall borrows of the task
    // table, so the scan must stay out of the common no-watch path.
    if !queued {
        return;
    }
    let tasks = unsafe { &mut *core::ptr::addr_of_mut!(TASKS) };
    for s in tasks.iter_mut() {
        let Some(t) = s.as_mut() else { continue };
        if t.state == TaskState::Blocked {
            if let WaitOn::Inotify(ii) = t.wait_on {
                ino_deposit(t, ii);
            }
        }
    }
}

/// Self-watch teardown: queue IN_IGNORED and free the wd — the
/// object's lifetime ended (delete, rename-away, rm_watch).
fn ino_watch_kill(ii: usize, wi: usize) {
    ino_q_push(ii, InoEv {
        wd: wi as i32 + 1, mask: IN_IGNORED, cookie: 0,
        name: [0; 128], nlen: 0,
    });
    let Some(inst) = (unsafe { &mut *core::ptr::addr_of_mut!(INOTIFY) })
        .get_mut(ii)
        .and_then(|s| s.as_mut())
    else {
        return;
    };
    inst.watches[wi] = None;
}

/// Drop every watch that sits on `path` (self-delete or move).
fn ino_report_self_loss(path: &[u8], selfmask: u32, cookie: u32) {
    let insts = unsafe { &mut *core::ptr::addr_of_mut!(INOTIFY) };
    for ii in 0..MAX_INOTIFY {
        let Some(inst) = insts[ii].as_mut() else { continue };
        for wi in 0..MAX_IWATCHES {
            let kill = inst.watches[wi]
                .as_ref()
                .is_some_and(|w| &w.path[..w.nlen as usize] == path);
            if kill {
                ino_q_push(ii, InoEv {
                    wd: wi as i32 + 1, mask: selfmask, cookie,
                    name: [0; 128], nlen: 0,
                });
                ino_watch_kill(ii, wi);
            }
        }
    }
}

/// Render an event into a fixed buffer — {i32 wd, u32 mask,
/// u32 cookie, u32 len} + name padded to a 16-byte record total,
/// the userspace ABI. Returns the record length.
fn ino_record(out: &mut [u8; 288], ev: &InoEv) -> usize {
    let len = if ev.nlen == 0 {
        0usize
    } else {
        (ev.nlen as usize + 1 + 15) & !15
    };
    out[..4].copy_from_slice(&ev.wd.to_le_bytes());
    out[4..8].copy_from_slice(&ev.mask.to_le_bytes());
    out[8..12].copy_from_slice(&ev.cookie.to_le_bytes());
    out[12..16].copy_from_slice(&(len as u32).to_le_bytes());
    for b in out[16..16 + len].iter_mut() {
        *b = 0;
    }
    if ev.nlen > 0 {
        out[16..16 + ev.nlen as usize]
            .copy_from_slice(&ev.name[..ev.nlen as usize]);
    }
    16 + len
}

/// Deposit the head event to a sleeping reader's wait_ptr; returns
/// the record length (rax). Queue-empty is a no-wake.
fn ino_deposit(t: &mut Task, ii: usize) {
    let Some(inst) = (unsafe { &mut *core::ptr::addr_of_mut!(INOTIFY) })
        .get_mut(ii)
        .and_then(|s| s.as_mut())
    else {
        return;
    };
    let head = inst.q.iter().position(|e| e.is_some());
    let Some(hi) = head else { return };
    let mut rec = [0u8; 288];
    let n = ino_record(&mut rec, inst.q[hi].as_ref().unwrap());
    if n as u64 > t.wait_len {
        return; // Linux: a record that can't fit stays queued
    }
    inst.q[hi] = None;
    inst.q.copy_within(hi + 1.., hi); // compact FIFO left
    inst.q[MAX_IEVS - 1] = None;
    write_task_bytes(t.pml4, t.wait_ptr, &rec[..n]);
    t.ctx.rax = n as u64;
    t.wait_on = WaitOn::None;
    t.wait_ptr = 0;
    t.wait_len = 0;
    t.wait_deadline = 0;
    t.state = TaskState::Runnable;
}

/// inotify_init/init1(flags): an anon-inode fd over the instance
/// table. flags are IN_NONBLOCK|IN_CLOEXEC (O_ values).
pub fn fd_inotify_init1(flags: u64) -> u64 {
    const ENFILE_: u64 = (-23i64) as u64;
    const IN_NONBLOCK: u64 = 0o4000;
    const IN_CLOEXEC: u64 = 0o2000000;
    if flags & !(IN_NONBLOCK | IN_CLOEXEC) != 0 {
        return EINVAL;
    }
    let insts = unsafe { &mut *core::ptr::addr_of_mut!(INOTIFY) };
    let Some(i) = insts.iter().position(Option::is_none) else {
        return ENFILE_;
    };
    insts[i] = Some(Inotify {
        watches: [const { None }; MAX_IWATCHES],
        q: [const { None }; MAX_IEVS],
        overflow: false,
        nonblock: flags & IN_NONBLOCK != 0,
    });
    let fd = anon_fd(FdKind::Inotify(i), flags & IN_CLOEXEC != 0);
    if (fd as i64) < 0 {
        insts[i] = None;
    }
    fd
}

/// inotify_add_watch(fd, path, mask): path must exist (Linux
/// ENOENT). Re-adding a watched path replaces the mask and keeps
/// the wd — the wd is slot+1 so 0 never leaks as a real id.
pub fn inotify_add_watch(fd: u64, path: &[u8], mask: u32) -> u64 {
    const ENOSPC_: u64 = (-28i64) as u64;
    let Some(t) = cur_mut() else { return EINVAL };
    let Some(o) = ofd(t, fd) else { return EBADF };
    let FdKind::Inotify(i) = o.kind else { return EINVAL };
    // add_watch follows links — the watch keys the target's name.
    let (rb, rn, _) = match resolve_links(path, true) {
        Ok(x) => x,
        Err(e) => return e,
    };
    let path = &rb[..rn];
    if !fs_exists(path) || path.len() > 128 {
        return ENOENT;
    }
    if mask & IN_ALL_EVENTS == 0 {
        return EINVAL; // Linux: a watch needs at least one event bit
    }
    let dir = dir_exists(path) && !is_file(path);
    let insts = unsafe { &mut *core::ptr::addr_of_mut!(INOTIFY) };
    let Some(inst) = insts.get_mut(i).and_then(|s| s.as_mut()) else {
        return EBADF;
    };
    if let Some(wi) = inst.watches.iter_mut().position(|w| {
        w.as_ref()
            .is_some_and(|w| &w.path[..w.nlen as usize] == path)
    }) {
        inst.watches[wi].as_mut().unwrap().mask = mask;
        return wi as u64 + 1;
    }
    let Some(wi) = inst.watches.iter_mut().position(|w| w.is_none())
    else {
        return ENOSPC_;
    };
    let mut w = IWatch {
        path: [0; 128],
        nlen: path.len() as u8,
        dir,
        mask,
    };
    w.path[..path.len()].copy_from_slice(path);
    inst.watches[wi] = Some(w);
    wi as u64 + 1
}

/// inotify_rm_watch(fd, wd): drop the watch and queue its
/// IN_IGNORED record — Linux's final event for a wd.
pub fn inotify_rm_watch(fd: u64, wd: u64) -> u64 {
    let Some(t) = cur_mut() else { return EINVAL };
    let Some(o) = ofd(t, fd) else { return EBADF };
    let FdKind::Inotify(i) = o.kind else { return EINVAL };
    let insts = unsafe { &*core::ptr::addr_of!(INOTIFY) };
    let wi = wd as usize;
    match insts.get(i).and_then(|s| s.as_ref()) {
        Some(inst)
            if wi >= 1
                && wi <= MAX_IWATCHES
                && inst.watches[wi - 1].is_some() =>
        {
            ino_watch_kill(i, wi - 1);
            0
        }
        _ => EINVAL,
    }
}

/// inotify read: one event record per call (Linux-valid minimum —
/// records are {wd,mask,cookie,len} + name padded to 16). Overflow
/// drains as a final {wd=-1, IN_Q_OVERFLOW} record.
fn inotify_read(ctx: &mut UCtx, i: usize, buf: u64, len: u64) -> u64 {
    const EAGAIN: u64 = (-11i64) as u64;
    const EINTR: u64 = (-4i64) as u64;
    if len < 16 {
        return EINVAL;
    }
    if !range_ok_w(buf, len.min(288)) {
        return EFAULT;
    }
    let insts = unsafe { &mut *core::ptr::addr_of_mut!(INOTIFY) };
    let Some(inst) = insts.get_mut(i).and_then(|s| s.as_mut()) else {
        return EBADF;
    };
    let hi = inst.q.iter().position(|e| e.is_some());
    if let Some(hi) = hi {
        let mut rec = [0u8; 288];
        let n = ino_record(&mut rec, inst.q[hi].as_ref().unwrap());
        if n as u64 > len {
            return EINVAL; // Linux: a record must fit or the read fails
        }
        inst.q[hi] = None;
        inst.q.copy_within(hi + 1.., hi);
        inst.q[MAX_IEVS - 1] = None;
        // SAFETY: buf validated writable for n <= len.
        unsafe {
            core::ptr::copy_nonoverlapping(
                rec.as_ptr(),
                buf as *mut u8,
                n,
            )
        };
        return n as u64;
    }
    if inst.overflow {
        inst.overflow = false;
        let rec: [u8; 16] = {
            let mut r = [0u8; 16];
            r[..4].copy_from_slice(&(-1i32).to_le_bytes());
            r[4..8].copy_from_slice(&IN_Q_OVERFLOW.to_le_bytes());
            r
        };
        // SAFETY: buf validated writable for 16 bytes.
        unsafe {
            core::ptr::copy_nonoverlapping(rec.as_ptr(), buf as *mut u8, 16)
        };
        return 16;
    }
    let nonblock = inst.nonblock;
    if nonblock {
        return EAGAIN;
    }
    let Some(t) = cur_mut() else { return EBADF };
    if deliverable(t) {
        return EINTR;
    }
    t.wait_on = WaitOn::Inotify(i);
    t.wait_ptr = buf;
    t.wait_len = len;
    t.wait_deadline = 0;
    t.ctx = *ctx;
    t.state = TaskState::Blocked;
    block_switch()
}

// --- epoll -----------------------------------------------------------
// Interest sets pin the OFD (Linux's file*), so readiness survives
// the registering fd closing while a dup lives on; ofd_release
// purges interests whose OFD dies, like Linux's file teardown.
// Divergence: EPOLLET/EPOLLONESHOT accepted but level-triggered;
// no nested epoll fds (ctl ELOOPs epoll-kind members).

/// Scan one epoll instance's interest set, writing epoll_event
/// records ({u32 events, u64 data} — 12 packed bytes) through t's
/// tables. Works on the current task or a blocked one. Stale
/// entries (a reused OFD slot can't exist — purge runs at free —
/// so staleness only means "evaluate", never "trust").
fn epoll_scan(t: &Task, ei: usize, out: u64, max: u64) -> u64 {
    let eps = unsafe { &*core::ptr::addr_of!(EPOLLS) };
    let Some(inst) = eps.get(ei).and_then(|s| s.as_ref()) else {
        return 0;
    };
    let mut n = 0u64;
    for e in inst.ents.iter().flatten() {
        if n == max {
            break;
        }
        let r = ofd_revents(t.pending, e.ofd, e.events as u16);
        // NVAL means the interest's OFD is dead — the purge in
        // ofd_release normally beats this; either way Linux would
        // never report EPOLLNVAL to epoll_wait.
        if r == 0 || r & POLLNVAL != 0 {
            continue;
        }
        write_task_u32(t.pml4, out + n * 12, r as u32);
        write_task_u64(t.pml4, out + n * 12 + 4, e.data);
        n += 1;
    }
    n
}

/// epoll_create(size)/epoll_create1(flags): a bounded interest set
/// behind an OFD. size only guards the legacy >0 contract; flags
/// takes EPOLL_CLOEXEC (O_CLOEXEC) alone.
pub fn fd_epoll_create(flags: u64, legacy_size: bool) -> u64 {
    const ENFILE_: u64 = (-23i64) as u64;
    if legacy_size {
        if flags == 0 {
            return EINVAL;
        }
    } else if flags & !0o2000000 != 0 {
        return EINVAL;
    }
    let Some(t) = cur_mut() else { return EBADF };
    let ofds = unsafe { &mut *core::ptr::addr_of_mut!(OFDS) };
    let (Some(oi), Some(fi)) = (
        ofds.iter().position(Option::is_none),
        fdt(t).fds.iter().position(Option::is_none),
    ) else {
        return EMFILE;
    };
    let eps = unsafe { &mut *core::ptr::addr_of_mut!(EPOLLS) };
    let Some(ei) = eps.iter().position(Option::is_none) else {
        return ENFILE_;
    };
    eps[ei] = Some(Epoll {
        ents: [None; MAX_EPOLL_FDS],
    });
    ofds[oi] = Some(OpenFile {
        kind: FdKind::Epoll(ei),
        pos: 0,
        refs: 1,
        append: false,
        accmode: 2,
    });
    fdt(t).fds[fi] = Some(oi as u8);
    if !legacy_size {
        cloexec_set(t, fi, flags != 0);
    }
    fi as u64
}

/// epoll_ctl(epfd, op, fd, event): manage the interest set. Ops are
/// ADD=1 DEL=2 MOD=3 like Linux. The interest keys on fd but pins
/// the OFD it resolves to right now — a later close() can't make
/// the entry point at a recycled slot.
pub fn fd_epoll_ctl(epfd: u64, op: u64, fd: u64, ev: u64) -> u64 {
    const EEXIST: u64 = (-17i64) as u64;
    const ENOENT_: u64 = (-2i64) as u64;
    const EPERM: u64 = (-1i64) as u64;
    const ELOOP: u64 = (-40i64) as u64;
    const ENOMEM_: u64 = (-12i64) as u64;
    if !(1..=3).contains(&op) {
        return EINVAL;
    }
    if fd as usize >= MAX_FDS {
        return EBADF;
    }
    let Some(t) = cur_mut() else { return EBADF };
    // epfd must be an epoll instance; the target must be a live fd.
    let Some(epoi) = fdt(t).fds.get(epfd as usize).copied().flatten() else {
        return EBADF;
    };
    let Some(foi) = fdt(t).fds[fd as usize] else {
        return EBADF;
    };
    let eps = unsafe { &mut *core::ptr::addr_of_mut!(EPOLLS) };
    let ofds = unsafe { &mut *core::ptr::addr_of_mut!(OFDS) };
    let Some(ei) = (match ofds.get(epoi as usize).and_then(|s| s.as_ref()) {
        Some(o) => match o.kind {
            FdKind::Epoll(i) => Some(i),
            _ => None,
        },
        None => None,
    }) else {
        return EINVAL; // epfd isn't an epoll fd — Linux's answer
    };
    if fd as u64 == epfd {
        return EINVAL; // can't watch itself
    }
    let Some(inst) = eps.get_mut(ei).and_then(|s| s.as_mut()) else {
        return EINVAL;
    };
    // Reject targets poll can't evaluate: directories (EPERM like
    // Linux) and epoll fds themselves — nesting would let a cycle
    // recurse ofd_revents forever, so ELOOP is the honest no.
    match ofds.get(foi as usize).and_then(|s| s.as_ref()) {
        Some(o) => match o.kind {
            FdKind::Dir(_) => return EPERM,
            FdKind::Epoll(_) => return ELOOP,
            _ => {}
        },
        None => return EBADF,
    }
    let slot = inst
        .ents
        .iter()
        .position(|e| e.is_some_and(|x| x.fd == fd as i32));
    // ADD/MOD read the 12-byte packed epoll_event; DEL ignores it.
    let (events, data) = if op == 2 {
        (0, 0)
    } else {
        if ev == 0 || !range_ok(ev, 12) {
            return EFAULT;
        }
        // SAFETY: validated user record under cur cr3.
        unsafe {
            (
                (ev as *const u32).read_unaligned(),
                ((ev + 4) as *const u64).read_unaligned(),
            )
        }
    };
    match op {
        1 => {
            if slot.is_some() {
                return EEXIST;
            }
            let Some(free) = inst.ents.iter().position(Option::is_none) else {
                return ENOMEM_;
            };
            inst.ents[free] = Some(EpollEnt {
                fd: fd as i32,
                ofd: foi,
                events,
                data,
            });
            0
        }
        3 => {
            let Some(i) = slot else { return ENOENT_ };
            inst.ents[i] = Some(EpollEnt {
                fd: fd as i32,
                ofd: foi,
                events,
                data,
            });
            0
        }
        _ => {
            let Some(i) = slot else { return ENOENT_ };
            inst.ents[i] = None;
            0
        }
    }
}

/// epoll_wait(epfd, events, maxevents, timeout_ms) — and
/// epoll_pwait when sigmask != 0: scan the interest set now; block
/// on WaitOn::Epoll when empty. The temporary mask rides psel_mask
/// exactly like ppoll — restored on every wake path.
pub fn fd_epoll_wait(
    ctx: &mut UCtx,
    epfd: u64,
    events: u64,
    maxevents: u64,
    timeout_ms: i64,
    sigmask: u64,
    sigsize: u64,
) -> u64 {
    const EINTR: u64 = (-4i64) as u64;
    if maxevents == 0 || maxevents > MAX_EPOLL_FDS as u64 {
        return EINVAL;
    }
    let Some(t) = cur_mut() else { return EBADF };
    let Some(ei) = (match ofd(t, epfd).map(|o| &o.kind) {
        Some(FdKind::Epoll(i)) => Some(*i),
        _ => None,
    }) else {
        // A valid fd that isn't epoll gets EINVAL; no fd gets EBADF.
        return if fdt(t).fds.get(epfd as usize).is_some_and(|s| s.is_some()) {
            EINVAL
        } else {
            EBADF
        };
    };
    if !range_ok_w(events, maxevents * 12) {
        return EFAULT;
    }
    let saved_mask = t.sigmask;
    if sigmask != 0 {
        if sigsize != 8 || !range_ok(sigmask, 8) {
            return EINVAL;
        }
        // SAFETY: validated user sigset under cur cr3.
        t.sigmask = unsafe { (sigmask as *const u64).read_unaligned() } as u32;
    }
    let ready = epoll_scan(t, ei, events, maxevents);
    if ready > 0 {
        t.sigmask = saved_mask;
        return ready;
    }
    let now = crate::apic::TICKS.load(core::sync::atomic::Ordering::Relaxed);
    let deadline = if timeout_ms < 0 {
        0
    } else {
        now + (timeout_ms as u64).div_ceil(10)
    };
    if timeout_ms == 0 || (deadline != 0 && deadline <= now) {
        t.sigmask = saved_mask;
        return 0;
    }
    if deliverable(t) {
        t.sigmask = saved_mask;
        return EINTR;
    }
    t.psel_mask = saved_mask as u64;
    t.wait_on = WaitOn::Epoll(ei);
    t.wait_ptr = events;
    t.wait_len = maxevents;
    t.wait_deadline = deadline;
    t.ctx = *ctx;
    t.state = TaskState::Blocked;
    block_switch()
}

// --- eventfd + timerfd -------------------------------------------
// The anon-inode fd family: a u64 semaphore and a tick-deadline
// clock behind OFDs. read/write are exactly-8-byte ops; nonblock
// is per-instance like Linux file-status flags (dup'd fds share).

/// Shared OFD+fd-slot claim for the anon-inode family — EMFILE if
/// either table is full, like the socket alloc preamble.
fn anon_fd(kind: FdKind, cloexec: bool) -> u64 {
    let Some(t) = cur_mut() else { return EBADF };
    let ofds = unsafe { &mut *core::ptr::addr_of_mut!(OFDS) };
    let (Some(oi), Some(fi)) = (
        ofds.iter().position(Option::is_none),
        fdt(t).fds.iter().position(Option::is_none),
    ) else {
        return EMFILE;
    };
    ofds[oi] = Some(OpenFile {
        kind,
        pos: 0,
        refs: 1,
        append: false,
        accmode: 2,
    });
    fdt(t).fds[fi] = Some(oi as u8);
    cloexec_set(t, fi, cloexec);
    fi as u64
}

/// eventfd(initval)/eventfd2(initval, flags): a u64 kernel
/// semaphore behind an OFD. Flags are EFD_SEMAPHORE|EFD_NONBLOCK|
/// EFD_CLOEXEC; the legacy call is just flags==0.
pub fn fd_eventfd(initval: u64, flags: u64) -> u64 {
    const ENFILE_: u64 = (-23i64) as u64;
    const EFD_NONBLOCK: u64 = 0o4000;
    const EFD_CLOEXEC: u64 = 0o2000000;
    const EFD_SEMAPHORE: u64 = 1;
    if flags & !(EFD_NONBLOCK | EFD_CLOEXEC | EFD_SEMAPHORE) != 0 {
        return EINVAL;
    }
    let evs = unsafe { &mut *core::ptr::addr_of_mut!(EVENTFDS) };
    let Some(i) = evs.iter().position(Option::is_none) else {
        return ENFILE_;
    };
    evs[i] = Some(Eventfd {
        count: initval,
        sema: flags & EFD_SEMAPHORE != 0,
        nonblock: flags & EFD_NONBLOCK != 0,
    });
    let fd = anon_fd(FdKind::Eventfd(i), flags & EFD_CLOEXEC != 0);
    if (fd as i64) < 0 {
        evs[i] = None; // fd table full — don't leak the instance
    }
    fd
}

/// The read side of eventfd: drain the counter (or decrement by 1
/// under EFD_SEMAPHORE). Zero counter: EAGAIN when nonblock, else
/// WaitOn::EventfdR — the waker deposits through our tables.
fn eventfd_read(ctx: &mut UCtx, i: usize, buf: u64, len: u64) -> u64 {
    const EAGAIN: u64 = (-11i64) as u64;
    const EINTR: u64 = (-4i64) as u64;
    if len < 8 {
        return EINVAL;
    }
    if !range_ok_w(buf, 8) {
        return EFAULT;
    }
    let Some(t) = cur_mut() else { return EBADF };
    let evs = unsafe { &mut *core::ptr::addr_of_mut!(EVENTFDS) };
    let Some(e) = evs.get_mut(i).and_then(|s| s.as_mut()) else {
        return EBADF;
    };
    if e.count == 0 {
        if e.nonblock {
            return EAGAIN;
        }
        if deliverable(t) {
            return EINTR;
        }
        t.wait_on = WaitOn::EventfdR(i);
        t.wait_ptr = buf;
        t.wait_len = 8;
        t.ctx = *ctx;
        t.state = TaskState::Blocked;
        block_switch()
    }
    let v = if e.sema { 1 } else { e.count };
    e.count -= v;
    // SAFETY: buf validated writable for 8 bytes under cur cr3.
    unsafe { (buf as *mut u64).write_unaligned(v) };
    eventfd_wake_writers(i); // the drain may now fit a blocked add
    8
}

/// The write side: add v to the counter — u64::MAX itself is
/// EINVAL, and an add that would pass 2^64-2 blocks (EAGAIN when
/// nonblock) until a read drains room.
fn eventfd_write(ctx: &mut UCtx, i: usize, buf: u64, len: u64) -> u64 {
    const EAGAIN: u64 = (-11i64) as u64;
    const EINTR: u64 = (-4i64) as u64;
    if len < 8 {
        return EINVAL;
    }
    if !range_ok(buf, 8) {
        return EFAULT;
    }
    // SAFETY: validated user u64 under cur cr3.
    let v = unsafe { (buf as *const u64).read_unaligned() };
    if v == u64::MAX {
        return EINVAL;
    }
    let Some(t) = cur_mut() else { return EBADF };
    let evs = unsafe { &mut *core::ptr::addr_of_mut!(EVENTFDS) };
    let Some(e) = evs.get_mut(i).and_then(|s| s.as_mut()) else {
        return EBADF;
    };
    if v > EFD_MAX - e.count {
        if e.nonblock {
            return EAGAIN;
        }
        if deliverable(t) {
            return EINTR;
        }
        t.wait_on = WaitOn::EventfdW(i);
        t.wait_len = v; // re-checked at wake, like PipeWrite's fit
        t.ctx = *ctx;
        t.state = TaskState::Blocked;
        block_switch()
    }
    e.count += v;
    eventfd_wake_readers(i);
    8
}

/// A write added count: wake EventfdR waiters FIFO — each gets
/// its share (sema: 1; else the whole count) through its tables.
fn eventfd_wake_readers(i: usize) {
    let tasks = unsafe { &mut *core::ptr::addr_of_mut!(TASKS) };
    let evs = unsafe { &mut *core::ptr::addr_of_mut!(EVENTFDS) };
    for s in tasks.iter_mut() {
        let Some(t) = s.as_mut() else { continue };
        if t.state != TaskState::Blocked || t.wait_on != WaitOn::EventfdR(i) {
            continue;
        }
        let Some(e) = evs.get_mut(i).and_then(|s| s.as_mut()) else {
            return;
        };
        if e.count == 0 {
            return; // drained — later readers keep sleeping
        }
        let v = if e.sema { 1 } else { e.count };
        e.count -= v;
        write_task_u64(t.pml4, t.wait_ptr, v);
        t.ctx.rax = 8;
        t.wait_on = WaitOn::None;
        t.state = TaskState::Runnable;
    }
}

/// A read freed count space: wake EventfdW waiters whose add now
/// fits under EFD_MAX — same re-check-at-wake shape as PipeWrite.
fn eventfd_wake_writers(i: usize) {
    let tasks = unsafe { &mut *core::ptr::addr_of_mut!(TASKS) };
    let evs = unsafe { &mut *core::ptr::addr_of_mut!(EVENTFDS) };
    for s in tasks.iter_mut() {
        let Some(t) = s.as_mut() else { continue };
        if t.state != TaskState::Blocked || t.wait_on != WaitOn::EventfdW(i) {
            continue;
        }
        let Some(e) = evs.get_mut(i).and_then(|s| s.as_mut()) else {
            return;
        };
        if t.wait_len > EFD_MAX - e.count {
            continue; // still can't fit — next writer might
        }
        e.count += t.wait_len;
        t.ctx.rax = 8;
        t.wait_on = WaitOn::None;
        t.state = TaskState::Runnable;
    }
}

/// timerfd_create(clockid, flags): a tick-deadline timer behind an
/// OFD. CLOCK_REALTIME(0) and CLOCK_MONOTONIC(1) both ride TICKS —
/// we have one clock; the split is a documented divergence.
pub fn fd_timerfd_create(clockid: u64, flags: u64) -> u64 {
    const ENFILE_: u64 = (-23i64) as u64;
    const TFD_NONBLOCK: u64 = 0o4000;
    const TFD_CLOEXEC: u64 = 0o2000000;
    if clockid > 1 {
        return EINVAL;
    }
    if flags & !(TFD_NONBLOCK | TFD_CLOEXEC) != 0 {
        return EINVAL;
    }
    let tfs = unsafe { &mut *core::ptr::addr_of_mut!(TIMERFDS) };
    let Some(i) = tfs.iter().position(Option::is_none) else {
        return ENFILE_;
    };
    tfs[i] = Some(Timerfd {
        armed: false,
        deadline: 0,
        interval: 0,
        expirations: 0,
        nonblock: flags & TFD_NONBLOCK != 0,
    });
    let fd = anon_fd(FdKind::Timerfd(i), flags & TFD_CLOEXEC != 0);
    if (fd as i64) < 0 {
        tfs[i] = None;
    }
    fd
}

/// Resolve an fd to a TIMERFDS index — EBADF for a bad/missing fd,
/// EINVAL for a valid fd that isn't a timerfd (Linux's answer).
fn timerfd_idx(fd: u64) -> Result<usize, u64> {
    let Some(t) = cur_mut() else { return Err(EBADF) };
    let Some(oi) = fdt(t).fds.get(fd as usize).copied().flatten() else {
        return Err(EBADF);
    };
    let ofds = unsafe { &*core::ptr::addr_of!(OFDS) };
    match ofds.get(oi as usize).and_then(|s| s.as_ref()) {
        Some(o) => match o.kind {
            FdKind::Timerfd(i) => Ok(i),
            _ => Err(EINVAL),
        },
        None => Err(EBADF),
    }
}

/// ns -> ticks at 100 Hz, rounding up like Linux's tick-boundary
/// timers (a sub-tick request must not fire early).
fn ns_to_ticks(sec: i64, nsec: i64) -> u64 {
    (sec.max(0) as u64)
        .saturating_mul(100)
        .saturating_add((nsec.max(0) as u64).div_ceil(10_000_000))
}

/// timerfd_settime(fd, flags, new, old): arm/disarm + report the
/// prior state. itimerspec is {it_interval, it_value} — two
/// timespecs, 32 bytes. TFD_TIMER_ABSTIME(1) makes it_value an
/// absolute ns-since-boot deadline.
pub fn fd_timerfd_settime(fd: u64, flags: u64, new: u64, old: u64) -> u64 {
    const TFD_ABSTIME: u64 = 1;
    if flags & !TFD_ABSTIME != 0 {
        return EINVAL;
    }
    if new == 0 {
        return EFAULT;
    }
    if !range_ok(new, 32) {
        return EFAULT;
    }
    if old != 0 && !range_ok_w(old, 32) {
        return EFAULT;
    }
    let i = match timerfd_idx(fd) {
        Ok(i) => i,
        Err(e) => return e,
    };
    // SAFETY: validated itimerspec under cur cr3.
    let (isec, insec, vsec, vnsec) = unsafe {
        (
            (new as *const i64).read_unaligned(),
            ((new + 8) as *const i64).read_unaligned(),
            ((new + 16) as *const i64).read_unaligned(),
            ((new + 24) as *const i64).read_unaligned(),
        )
    };
    if isec < 0 || vsec < 0 || !(0..1_000_000_000).contains(&insec)
        || !(0..1_000_000_000).contains(&vnsec)
    {
        return EINVAL;
    }
    let now = crate::apic::TICKS.load(core::sync::atomic::Ordering::Relaxed);
    let tfs = unsafe { &mut *core::ptr::addr_of_mut!(TIMERFDS) };
    let Some(tf) = tfs.get_mut(i).and_then(|s| s.as_mut()) else {
        return EINVAL;
    };
    if old != 0 {
        // Prior interval + remaining time to the old deadline.
        let rem = if tf.armed { tf.deadline.saturating_sub(now) } else { 0 };
        // SAFETY: old validated writable for 32 bytes under cur cr3.
        unsafe {
            (old as *mut i64).write_unaligned((tf.interval / 100) as i64);
            ((old + 8) as *mut i64)
                .write_unaligned(((tf.interval % 100) * 10_000_000) as i64);
            ((old + 16) as *mut i64).write_unaligned((rem / 100) as i64);
            ((old + 24) as *mut i64)
                .write_unaligned(((rem % 100) * 10_000_000) as i64);
        }
    }
    tf.interval = ns_to_ticks(isec, insec);
    if vsec == 0 && vnsec == 0 {
        tf.armed = false; // disarm — pending expirations survive
    } else {
        let v = ns_to_ticks(vsec, vnsec).max(1);
        tf.deadline = if flags & TFD_ABSTIME != 0 {
            v
        } else {
            now.saturating_add(v)
        };
        tf.armed = true;
    }
    timerfd_expire(); // a past/now deadline may fire immediately
    0
}

/// timerfd_gettime(fd, cur): report {interval, remaining}. The
/// same ticks->timespec shape settime writes for `old`.
pub fn fd_timerfd_gettime(fd: u64, cur: u64) -> u64 {
    if cur == 0 || !range_ok_w(cur, 32) {
        return EFAULT;
    }
    let i = match timerfd_idx(fd) {
        Ok(i) => i,
        Err(e) => return e,
    };
    timerfd_expire(); // the report must be as-of-now
    let now = crate::apic::TICKS.load(core::sync::atomic::Ordering::Relaxed);
    let tfs = unsafe { &*core::ptr::addr_of!(TIMERFDS) };
    let Some(tf) = tfs.get(i).and_then(|s| s.as_ref()) else {
        return EINVAL;
    };
    let rem = if tf.armed { tf.deadline.saturating_sub(now) } else { 0 };
    // SAFETY: cur validated writable for 32 bytes under cur cr3.
    unsafe {
        (cur as *mut i64).write_unaligned((tf.interval / 100) as i64);
        ((cur + 8) as *mut i64)
            .write_unaligned(((tf.interval % 100) * 10_000_000) as i64);
        ((cur + 16) as *mut i64).write_unaligned((rem / 100) as i64);
        ((cur + 24) as *mut i64)
            .write_unaligned(((rem % 100) * 10_000_000) as i64);
    }
    0
}

/// The read side: collect the unread expiry count. Before expiry:
/// EAGAIN when nonblock, else WaitOn::Timerfd — timerfd_expire
/// deposits through the sleeper's tables at the deadline tick.
fn timerfd_read(ctx: &mut UCtx, i: usize, buf: u64, len: u64) -> u64 {
    const EAGAIN: u64 = (-11i64) as u64;
    const EINTR: u64 = (-4i64) as u64;
    if len < 8 {
        return EINVAL;
    }
    if !range_ok_w(buf, 8) {
        return EFAULT;
    }
    timerfd_expire(); // a deadline that passed may not have ticked
    let Some(t) = cur_mut() else { return EBADF };
    let tfs = unsafe { &mut *core::ptr::addr_of_mut!(TIMERFDS) };
    let Some(tf) = tfs.get_mut(i).and_then(|s| s.as_mut()) else {
        return EBADF;
    };
    if tf.expirations == 0 {
        if tf.nonblock {
            return EAGAIN;
        }
        if deliverable(t) {
            return EINTR;
        }
        t.wait_on = WaitOn::Timerfd(i);
        t.wait_ptr = buf;
        t.wait_len = 8;
        t.ctx = *ctx;
        t.state = TaskState::Blocked;
        block_switch()
    }
    let n = tf.expirations;
    tf.expirations = 0;
    // SAFETY: buf validated writable for 8 bytes under cur cr3.
    unsafe { (buf as *mut u64).write_unaligned(n) };
    8
}

/// Service elapsed timerfd deadlines — one-shots expire once and
/// disarm; periodics fold missed cycles into the count (Linux's
/// overruns) and re-arm forward. Then wake blocked readers.
/// Runs from the timer tick and lazily at timerfd syscall entry.
pub fn timerfd_expire() {
    let now = crate::apic::TICKS.load(core::sync::atomic::Ordering::Relaxed);
    {
        let tfs = unsafe { &mut *core::ptr::addr_of_mut!(TIMERFDS) };
        for tf in tfs.iter_mut().flatten() {
            if !tf.armed || tf.deadline > now {
                continue;
            }
            if tf.interval == 0 {
                tf.expirations = tf.expirations.saturating_add(1);
                tf.armed = false;
            } else {
                let missed = 1 + (now - tf.deadline) / tf.interval;
                tf.expirations = tf.expirations.saturating_add(missed);
                tf.deadline += tf.interval * missed;
            }
        }
    }
    // Unread expirations wake WaitOn::Timerfd sleepers — deposit
    // the count through the sleeper's tables like a pipe read.
    let tasks = unsafe { &mut *core::ptr::addr_of_mut!(TASKS) };
    let tfs = unsafe { &mut *core::ptr::addr_of_mut!(TIMERFDS) };
    for s in tasks.iter_mut() {
        let Some(t) = s.as_mut() else { continue };
        if t.state != TaskState::Blocked {
            continue;
        }
        let WaitOn::Timerfd(i) = t.wait_on else {
            continue;
        };
        let Some(tf) = tfs.get_mut(i).and_then(|s| s.as_mut()) else {
            continue;
        };
        if tf.expirations == 0 {
            continue;
        }
        let n = tf.expirations;
        tf.expirations = 0;
        write_task_u64(t.pml4, t.wait_ptr, n);
        t.ctx.rax = 8;
        t.wait_on = WaitOn::None;
        t.state = TaskState::Runnable;
    }
}

/// Scan one task's three pselect fd_sets through ITS page tables,
/// writing back only the ready bits (Linux overwrites the input
/// sets). Returns the count of ready fds — works on the current
/// task and on a blocked one via translate walks.
fn pselect_scan(t: &Task, rfd: u64, wfd: u64, efd: u64, nwords: u64) -> u64 {
    let mut ready = 0u64;
    for w in 0..nwords {
        let mut rout = 0u64;
        let mut wout = 0u64;
        let rin = if rfd != 0 {
            read_task_u(t.pml4, rfd + w * 8, 8).unwrap_or(0)
        } else {
            0
        };
        let win = if wfd != 0 {
            read_task_u(t.pml4, wfd + w * 8, 8).unwrap_or(0)
        } else {
            0
        };
        for b in 0..64u64 {
            let fd = (w * 64 + b) as i32;
            let rv = poll_revents(t, fd, POLLIN | POLLOUT);
            if rv & POLLNVAL != 0 {
                continue;
            }
            if rin & (1 << b) != 0 && rv & (POLLIN | POLLERR | POLLHUP) != 0 {
                rout |= 1 << b;
                ready += 1;
            }
            if win & (1 << b) != 0 && rv & (POLLOUT | POLLERR) != 0 {
                wout |= 1 << b;
                ready += 1;
            }
        }
        if rfd != 0 {
            write_task_u64(t.pml4, rfd + w * 8, rout);
        }
        if wfd != 0 {
            write_task_u64(t.pml4, wfd + w * 8, wout);
        }
        // exceptfds never signals here — no OOB source exists.
        if efd != 0 {
            write_task_u64(t.pml4, efd + w * 8, 0);
        }
    }
    ready
}

/// pselect6(nfds, rfd, wfd, efd, timespec, {sigmask,len}): select
/// with a timespec deadline and an atomic mask swap — bash's
/// readline waits on input through this, so ENOSYS reads as EOF.
/// Semantics follow Linux: the input sets are overwritten with the
/// ready bits, the timeout is not updated, sigmask applies for the
/// duration of the sleep only. nfds is FD_SETSIZE-capped like the
/// kernel's own fd_set limit.
pub fn fd_pselect(
    ctx: &mut UCtx,
    nfds: u64,
    rfd: u64,
    wfd: u64,
    efd: u64,
    ts: u64,
    sig: u64,
) -> u64 {
    const EINTR: u64 = (-4i64) as u64;
    if nfds > 1024 {
        return EINVAL;
    }
    let Some(t) = cur_mut() else { return EINVAL };
    let nwords = nfds.div_ceil(64);
    let nbytes = nwords * 8;
    for va in [rfd, wfd, efd] {
        if va != 0 && !range_ok_w(va, nbytes) {
            return EFAULT;
        }
    }
    let mut deadline = 0u64;
    if ts != 0 {
        if !range_ok(ts, 16) {
            return EFAULT;
        }
        // SAFETY: validated user timespec under cur cr3.
        let (sec, nsec) = unsafe {
            (
                (ts as *const i64).read_unaligned(),
                (ts as *const i64).add(1).read_unaligned(),
            )
        };
        if nsec < 0 || nsec >= 1_000_000_000 {
            return EINVAL;
        }
        deadline = crate::apic::TICKS
            .load(core::sync::atomic::Ordering::Relaxed)
            .saturating_add((sec.max(0) as u64).saturating_mul(100))
            .saturating_add((nsec as u64) / 10_000_000);
        if deadline == crate::apic::TICKS.load(core::sync::atomic::Ordering::Relaxed)
            && (sec > 0 || nsec > 0)
        {
            deadline += 1; // any positive wait is at least one tick
        }
    }
    // sigmask arg is {const sigset_t *ss, size_t ss_len} — swap for
    // the duration of the wait, restore on every way out.
    let saved_mask = t.sigmask;
    if sig != 0 {
        if !range_ok(sig, 16) {
            return EFAULT;
        }
        // SAFETY: validated user {ptr,len} pair under cur cr3.
        let (ss, ss_len) = unsafe {
            (
                (sig as *const u64).read_unaligned(),
                (sig as *const u64).add(1).read_unaligned(),
            )
        };
        if ss != 0 {
            if ss_len != 8 || !range_ok(ss, 8) {
                return EINVAL;
            }
            // SAFETY: validated user sigset under cur cr3.
            t.sigmask = unsafe { (ss as *const u64).read_unaligned() } as u32;
        }
    }
    let ready = pselect_scan(t, rfd, wfd, efd, nwords);
    if ready > 0 {
        t.sigmask = saved_mask;
        return ready;
    }
    if ts != 0 && deadline <= crate::apic::TICKS.load(core::sync::atomic::Ordering::Relaxed) {
        t.sigmask = saved_mask;
        return 0;
    }
    if deliverable(t) {
        t.sigmask = saved_mask;
        return EINTR;
    }
    t.psel_mask = saved_mask as u64;
    t.wait_on = WaitOn::Pselect;
    t.wait_ptr = rfd;
    t.wait_ptr2 = wfd;
    t.wait_ptr3 = efd;
    t.wait_len = nwords;
    t.wait_deadline = deadline;
    t.ctx = *ctx;
    t.state = TaskState::Blocked;
    block_switch()
}

/// Parse a user timespec {sec, nsec} into a tick deadline — shared
/// by ppoll and any future timespec wait. 0 means wait forever;
/// any positive wait rounds up to at least one tick.
fn ts_deadline(ts: u64) -> Option<u64> {
    if ts == 0 {
        return Some(0);
    }
    if !range_ok(ts, 16) {
        return None;
    }
    // SAFETY: validated user timespec under cur cr3.
    let (sec, nsec) = unsafe {
        (
            (ts as *const i64).read_unaligned(),
            (ts as *const i64).add(1).read_unaligned(),
        )
    };
    if nsec < 0 || nsec >= 1_000_000_000 {
        return None;
    }
    let now = crate::apic::TICKS.load(core::sync::atomic::Ordering::Relaxed);
    let mut d = now
        .saturating_add((sec.max(0) as u64).saturating_mul(100))
        .saturating_add((nsec as u64) / 10_000_000);
    if d == now && (sec > 0 || nsec > 0) {
        d += 1;
    }
    Some(d)
}

/// ppoll(fds, nfds, tmo_p, sigmask, sigsetsize): poll with a
/// timespec deadline and an atomic mask swap — pselect6's sibling
/// over pollfd records. The mask swap rides psel_mask like pselect;
/// every wake path restores it before userspace resumes.
pub fn fd_ppoll(
    ctx: &mut UCtx,
    fds: u64,
    nfds: u64,
    ts: u64,
    sigmask: u64,
    sigsize: u64,
) -> u64 {
    const EINTR: u64 = (-4i64) as u64;
    if nfds > MAX_POLL {
        return EINVAL;
    }
    let Some(t) = cur_mut() else { return EINVAL };
    if nfds > 0 && !range_ok_w(fds, nfds * 8) {
        return EFAULT;
    }
    let Some(deadline) = ts_deadline(ts) else {
        return if ts != 0 && range_ok(ts, 16) { EINVAL } else { EFAULT };
    };
    let saved_mask = t.sigmask;
    if sigmask != 0 {
        if sigsize != 8 || !range_ok(sigmask, 8) {
            return EINVAL;
        }
        // SAFETY: validated user sigset under cur cr3.
        t.sigmask = unsafe { (sigmask as *const u64).read_unaligned() } as u32;
    }
    let ready = if nfds == 0 { 0 } else { poll_scan(t, fds, nfds) };
    if ready > 0 {
        t.sigmask = saved_mask;
        return ready;
    }
    if ts != 0 && deadline <= crate::apic::TICKS.load(core::sync::atomic::Ordering::Relaxed) {
        t.sigmask = saved_mask;
        return 0;
    }
    if deliverable(t) {
        t.sigmask = saved_mask;
        return EINTR;
    }
    t.psel_mask = saved_mask as u64;
    t.wait_on = WaitOn::Poll;
    t.wait_ptr = fds;
    t.wait_len = nfds;
    t.wait_deadline = deadline;
    t.ctx = *ctx;
    t.state = TaskState::Blocked;
    block_switch()
}

// ---- UDP sockets ---------------------------------------------------
// AF_INET/SOCK_DGRAM over the e1000 live ring. One datagram queue per
// socket — honest UDP: excess drops. The blocking recvfrom borrows the
// pipe-wait machinery: the waker (rx demux on the live ring) copies
// payload + sockaddr through the SLEEPER's page tables.

/// Max UDP sockets — same fixed-table discipline as MAX_PIPES.
const MAX_SOCKS: usize = 8;
/// A datagram payload cap: fits a full-size ethernet frame.
const MAX_DGRAM: usize = 1600;
/// First ephemeral port, Linux's default range start.
const EPHEM_BASE: u16 = 49152;

/// One queued datagram: payload + sender sockaddr for recvfrom.
struct Dgram {
    src: [u8; 4],
    sport: u16,
    len: u16,
    data: [u8; MAX_DGRAM],
}

/// A UDP endpoint: the bound local port (0 = unbound, assigned on
/// first send/bind) plus a one-deep receive queue.
struct UdpSock {
    port: u16,
    q: Option<Dgram>,
}

static mut UDPSOCKS: [Option<UdpSock>; MAX_SOCKS] = [const { None }; MAX_SOCKS];

/// Linux struct sockaddr_in, all 16 bytes initialized before the
/// copy (the CVE-2021-47597 uninit-struct copy_to_user class).
fn sockaddr_in(port: u16, ip: [u8; 4]) -> [u8; 16] {
    let mut s = [0u8; 16];
    s[0..2].copy_from_slice(&2u16.to_ne_bytes()); // AF_INET
    s[2..4].copy_from_slice(&port.to_be_bytes());
    s[4..8].copy_from_slice(&ip);
    s
}

/// Parse the first 8 bytes of a sockaddr_in at `sa` in pml4's space:
/// (port, ip). None on untranslatable or non-INET input.
fn parse_sockaddr(pml4: u64, sa: u64) -> Option<(u16, [u8; 4])> {
    let v = read_task_u(pml4, sa, 8)?;
    if v & 0xffff != 2 {
        return None; // sin_family must be AF_INET
    }
    let port = u16::from_be(((v >> 16) & 0xffff) as u16);
    let ip = ((v >> 32) as u32).to_le_bytes();
    Some((port, ip))
}

/// Lowest unbound local port >= EPHEM_BASE.
fn ephemeral_port() -> Option<u16> {
    let socks = unsafe { &*core::ptr::addr_of!(UDPSOCKS) };
    (EPHEM_BASE..=u16::MAX)
        .find(|&p| !socks.iter().flatten().any(|s| s.port == p))
}

/// RX-side demux, called from e1000::drain_desc on the live ring.
/// A blocked recvfrom gets the datagram copied straight into its
/// buffer (through ITS tables); otherwise it queues one deep —
/// a second arrival displaces it, honest UDP loss.
pub fn udp_rx(src_ip: [u8; 4], sport: u16, dport: u16, p: &[u8]) {
    let socks = unsafe { &mut *core::ptr::addr_of_mut!(UDPSOCKS) };
    let Some(si) = socks.iter().position(|s| {
        s.as_ref().is_some_and(|k| k.port == dport)
    }) else {
        return; // nobody bound to this port — drop
    };
    // A blocked receiver first: payload + sockaddr straight through
    // the sleeper's tables, count into its rax — same wake shape as
    // the pipe paths.
    let tasks = unsafe { &mut *core::ptr::addr_of_mut!(TASKS) };
    for s in tasks.iter_mut() {
        let Some(t) = s.as_mut() else { continue };
        if t.state == TaskState::Blocked && t.wait_on == WaitOn::UdpRecv(si) {
            let n = core::cmp::min(p.len(), t.wait_len as usize);
            write_task_bytes(t.pml4, t.wait_ptr, &p[..n]);
            if t.wait_ptr2 != 0 {
                write_task_bytes(
                    t.pml4,
                    t.wait_ptr2,
                    &sockaddr_in(sport, src_ip),
                );
            }
            t.ctx.rax = n as u64;
            t.wait_on = WaitOn::None;
            t.wait_deadline = 0;
            t.wait_ptr2 = 0;
            t.state = TaskState::Runnable;
            return;
        }
    }
    // Queue one deep — an occupied slot drops the new datagram.
    let Some(sock) = socks[si].as_mut() else { return };
    if sock.q.is_none() {
        let mut d = Dgram {
            src: src_ip,
            sport,
            len: 0,
            data: [0; MAX_DGRAM],
        };
        let n = core::cmp::min(p.len(), MAX_DGRAM);
        d.data[..n].copy_from_slice(&p[..n]);
        d.len = n as u16;
        sock.q = Some(d);
    }
    wake_pollers(); // POLLIN may have just become true
}

/// Shared recv path for recvfrom() and read() on a socket fd —
/// `sa` is the sockaddr_out VA (0 = none). Queued dgram or block;
/// the waker fills buf/sa through our tables.
fn udp_recv_or_block(
    ctx: &mut UCtx,
    si: usize,
    buf: u64,
    len: u64,
    sa: u64,
) -> u64 {
    const EINTR_: u64 = (-4i64) as u64;
    let Some(t) = cur_mut() else { return EBADF };
    // A datagram already in the ring? Drain once before looking.
    crate::e1000::rx_drain();
    let take = {
        let socks = unsafe { &mut *core::ptr::addr_of_mut!(UDPSOCKS) };
        socks.get_mut(si).and_then(|s| s.as_mut()).and_then(|k| k.q.take())
    };
    if let Some(d) = take {
        let n = core::cmp::min(len as usize, d.len as usize);
        if n > 0 && !range_ok_w(buf, n as u64) {
            return EFAULT;
        }
        if sa != 0 && !range_ok_w(sa, 16) {
            return EFAULT;
        }
        // SAFETY: both ranges validated writable under the current
        // (this task's) page table.
        unsafe {
            core::ptr::copy_nonoverlapping(
                d.data.as_ptr(),
                buf as *mut u8,
                n,
            );
        }
        if sa != 0 {
            unsafe {
                core::ptr::copy_nonoverlapping(
                    sockaddr_in(d.sport, d.src).as_ptr(),
                    sa as *mut u8,
                    16,
                );
            }
        }
        return n as u64;
    }
    // Empty queue — validate the targets BEFORE sleeping, then
    // block: the demux writes through OUR tables on arrival.
    if !range_ok_w(buf, len.min(MAX_DGRAM as u64).max(1)) {
        return EFAULT;
    }
    if sa != 0 && !range_ok_w(sa, 16) {
        return EFAULT;
    }
    if deliverable(t) {
        return EINTR_; // a signal landed before we slept
    }
    t.wait_on = WaitOn::UdpRecv(si);
    t.wait_ptr = buf;
    t.wait_len = len.min(MAX_DGRAM as u64);
    t.wait_ptr2 = sa;
    t.ctx = *ctx;
    t.state = TaskState::Blocked;
    block_switch()
}

/// socket(AF_INET, type): a kernel endpoint behind an OFD, so it
/// dups/fork-shares like every other fd. SOCK_DGRAM -> UDPSOCKS,
/// SOCK_STREAM -> TCPSOCKS in the Init state.
/// socket() type carries SOCK_NONBLOCK(0o4000)|SOCK_CLOEXEC(0o2000000)
/// flags — same values as the O_ bits. CLOEXEC we honor; NONBLOCK we
/// refuse honestly (no nonblocking socket io exists).
const SOCK_NONBLOCK: u64 = 0o4000;
const SOCK_CLOEXEC: u64 = 0o2000000;

pub fn fd_socket(domain: u64, ty: u64, _proto: u64) -> u64 {
    const EAFNOSUPPORT: u64 = (-97i64) as u64;
    const ENFILE_: u64 = (-23i64) as u64;
    if ty & !(0x7 | SOCK_NONBLOCK | SOCK_CLOEXEC) != 0 {
        return EINVAL;
    }
    if ty & SOCK_NONBLOCK != 0 {
        return EINVAL;
    }
    let base = ty & 0x7;
    if domain != 2 || !(base == 1 || base == 2) {
        return EAFNOSUPPORT;
    }
    let Some(t) = cur_mut() else { return EBADF };
    let ofds = unsafe { &mut *core::ptr::addr_of_mut!(OFDS) };
    let (Some(oi), Some(fi)) = (
        ofds.iter().position(Option::is_none),
        fdt(t).fds.iter().position(Option::is_none),
    ) else {
        return EMFILE;
    };
    let kind = if ty == 2 {
        let socks = unsafe { &mut *core::ptr::addr_of_mut!(UDPSOCKS) };
        let Some(si) = socks.iter().position(Option::is_none) else {
            return ENFILE_;
        };
        socks[si] = Some(UdpSock { port: 0, q: None });
        FdKind::Udp(si)
    } else {
        let socks = tcp_socks();
        let Some(si) = socks.iter().position(Option::is_none) else {
            return ENFILE_;
        };
        socks[si] = Some(TcpSock {
            port: 0,
            peer_ip: [0; 4],
            peer_port: 0,
            peer_mac: [0; 6],
            state: TcpState::Init,
            snd_nxt: 0,
            rcv_nxt: 0,
            fin_acked: false,
            fin_rx: false,
            backlog: [usize::MAX; TCP_BACKLOG],
            blen: 0,
            parent: usize::MAX,
            orphan: false,
            dead: false,
            rxb: [0; TCP_RX_CAP],
            rxl: 0,
        });
        FdKind::Tcp(si)
    };
    ofds[oi] = Some(OpenFile { kind, pos: 0, refs: 1, append: false, accmode: 2 });
    fdt(t).fds[fi] = Some(oi as u8);
    cloexec_set(t, fi, ty & SOCK_CLOEXEC != 0);
    fi as u64
}

/// bind(fd, sockaddr_in, len): claim a local port for a socket —
/// required before its datagrams demux. Port 0 picks an ephemeral.
pub fn fd_bind(fd: u64, sa: u64, len: u64) -> u64 {
    const EAFNOSUPPORT: u64 = (-97i64) as u64;
    const EADDRINUSE: u64 = (-98i64) as u64;
    const EADDRNOTAVAIL: u64 = (-99i64) as u64;
    let Some(t) = cur_mut() else { return EBADF };
    if len < 8 {
        return EINVAL;
    }
    if !range_ok(sa, 8) {
        return EFAULT;
    }
    enum SockId {
        U(usize),
        T(usize),
    }
    let Some(sid) = (match ofd(t, fd).map(|o| &o.kind) {
        Some(FdKind::Udp(i)) => Some(SockId::U(*i)),
        Some(FdKind::Tcp(i)) => Some(SockId::T(*i)),
        _ => None,
    }) else {
        return EBADF;
    };
    let Some((port, _ip)) = parse_sockaddr(t.pml4, sa) else {
        return EAFNOSUPPORT;
    };
    match sid {
        SockId::U(si) => {
            let socks = unsafe { &mut *core::ptr::addr_of_mut!(UDPSOCKS) };
            if socks[si].as_ref().is_none_or(|k| k.port != 0) {
                // None can't happen (the OFD pins the slot); a
                // nonzero port is a re-bind — EINVAL like Linux.
                return EINVAL;
            }
            let p = if port == 0 {
                let Some(e) = ephemeral_port() else {
                    return EADDRNOTAVAIL;
                };
                e
            } else {
                if socks.iter().flatten().any(|s| s.port == port) {
                    return EADDRINUSE;
                }
                port
            };
            if let Some(k) = socks[si].as_mut() {
                k.port = p;
            }
        }
        SockId::T(si) => {
            let socks = tcp_socks();
            if socks[si].as_ref().is_none_or(|k| k.port != 0) {
                return EINVAL;
            }
            let p = if port == 0 {
                let Some(e) = tcp_ephemeral() else {
                    return EADDRNOTAVAIL;
                };
                e
            } else {
                if socks.iter().flatten().any(|s| s.port == port) {
                    return EADDRINUSE;
                }
                port
            };
            if let Some(k) = socks[si].as_mut() {
                k.port = p;
            }
        }
    }
    0
}

/// getsockname/getpeername(fd, sockaddr_out, *addrlen): the local
/// or remote endpoint. *addrlen is in/out — we copy at most the
/// caller's size then report the full sockaddr_in length (16),
/// Linux's truncate-copy/report-full convention.
fn sock_name(fd: u64, sa: u64, alen: u64, peer: bool) -> u64 {
    const ENOTSOCK: u64 = (-88i64) as u64;
    const ENOTCONN: u64 = (-107i64) as u64;
    let Some(t) = cur_mut() else { return EBADF };
    if sa == 0 || alen == 0 {
        return EFAULT;
    }
    if !range_ok_w(alen, 4) {
        return EFAULT;
    }
    // SAFETY: alen validated writable under this task's page table.
    let ulen = unsafe { (alen as *const u32).read_unaligned() };
    // The endpoint this socket is attached to, if it has one.
    // port/ip are already wire-order for sockaddr_in.
    let ep: Option<(u16, [u8; 4])> = match ofd(t, fd).map(|o| &o.kind) {
        Some(FdKind::Tcp(i)) => {
            let socks = unsafe { &*core::ptr::addr_of!(TCPSOCKS) };
            let Some(k) = socks[*i].as_ref() else { return EBADF };
            if peer {
                match k.state {
                    TcpState::Estab
                    | TcpState::CloseWait
                    | TcpState::FinWait
                    | TcpState::LastAck => Some((k.peer_port, k.peer_ip)),
                    _ => return ENOTCONN,
                }
            } else {
                let ip = match k.state {
                    TcpState::Estab
                    | TcpState::CloseWait
                    | TcpState::FinWait
                    | TcpState::LastAck => crate::e1000::our_ip(),
                    _ => [0; 4], // bound-to-any: INADDR_ANY
                };
                Some((k.port, ip))
            }
        }
        Some(FdKind::Udp(i)) => {
            let socks = unsafe { &*core::ptr::addr_of!(UDPSOCKS) };
            let Some(k) = socks[*i].as_ref() else { return EBADF };
            if peer {
                return ENOTCONN; // our datagram socks never connect()
            }
            Some((k.port, [0; 4]))
        }
        _ => return ENOTSOCK,
    };
    let Some((port, ip)) = ep else { return EBADF };
    let s = sockaddr_in(port, ip);
    let n = core::cmp::min(ulen as usize, 16);
    if n > 0 {
        if !range_ok_w(sa, n as u64) {
            return EFAULT;
        }
        // SAFETY: sa validated writable for n under this task's
        // page table; s is a fully-initialized local.
        unsafe {
            core::ptr::copy_nonoverlapping(s.as_ptr(), sa as *mut u8, n);
        }
    }
    // SAFETY: same validated alen slot — report the real length.
    unsafe { (alen as *mut u32).write_unaligned(16) };
    0
}

pub fn fd_getsockname(fd: u64, sa: u64, alen: u64) -> u64 {
    sock_name(fd, sa, alen, false)
}

pub fn fd_getpeername(fd: u64, sa: u64, alen: u64) -> u64 {
    sock_name(fd, sa, alen, true)
}

/// sendto(fd, buf, len, flags, sockaddr_in, alen): one datagram out —
/// the destination MAC resolves via the ARP cache/gateway.
pub fn fd_sendto(
    fd: u64,
    buf: u64,
    len: u64,
    _flags: u64,
    sa: u64,
    alen: u64,
) -> u64 {
    const EAFNOSUPPORT: u64 = (-97i64) as u64;
    const EHOSTUNREACH: u64 = (-113i64) as u64;
    const EADDRNOTAVAIL: u64 = (-99i64) as u64;
    const EMSGSIZE: u64 = (-90i64) as u64;
    let Some(t) = cur_mut() else { return EBADF };
    // sendto on a stream socket is a plain send; a non-null
    // destination on a connected socket is EISCONN like Linux.
    match ofd(t, fd).map(|o| &o.kind) {
        Some(FdKind::Tcp(i)) => {
            const EISCONN: u64 = (-106i64) as u64;
            return if sa == 0 { tcp_send(*i, buf, len) } else { EISCONN };
        }
        Some(FdKind::Udp(_)) => {}
        _ => return EBADF,
    }
    let Some(si) = (match ofd(t, fd).map(|o| &o.kind) {
        Some(FdKind::Udp(i)) => Some(*i),
        _ => None,
    }) else {
        return EBADF;
    };
    if sa == 0 || alen < 8 {
        return EINVAL;
    }
    if !range_ok(sa, 8) {
        return EFAULT;
    }
    if len == 0 {
        return EINVAL;
    }
    // One ethernet frame: 14 + 20 + 8 + payload must fit a 1600B
    // staging buffer in udp_tx.
    if len > 1400 {
        return EMSGSIZE;
    }
    if !range_ok(buf, len) {
        return EFAULT;
    }
    let Some((dport, dip)) = parse_sockaddr(t.pml4, sa) else {
        return EAFNOSUPPORT;
    };
    if !crate::e1000::net_up() {
        return EHOSTUNREACH;
    }
    // Auto-bind on first send, like Linux.
    let sport = {
        let socks = unsafe { &mut *core::ptr::addr_of_mut!(UDPSOCKS) };
        let Some(k) = socks[si].as_mut() else { return EBADF };
        if k.port == 0 {
            let Some(e) = ephemeral_port() else {
                return EADDRNOTAVAIL;
            };
            k.port = e;
        }
        k.port
    };
    // Stage the payload kernel-side — the user buffer is read once.
    let mut pay = [0u8; 1400];
    // SAFETY: buf validated readable for len bytes under the
    // current page table.
    unsafe {
        core::ptr::copy_nonoverlapping(
            buf as *const u8,
            pay.as_mut_ptr(),
            len as usize,
        );
    }
    // Resolve the link-layer target: broadcast -> ff:ff; on-subnet
    // -> ARP the host; off-subnet or unresolved -> the gateway.
    let our = crate::e1000::our_ip();
    let mask = crate::e1000::our_mask();
    let mac = if dip == [0xff; 4] {
        Some([0xff; 6])
    } else {
        let on_link = (0..4).all(|i| dip[i] & mask[i] == our[i] & mask[i]);
        let r = if on_link {
            crate::e1000::arp_resolve(dip)
        } else {
            None
        };
        r.or_else(crate::e1000::gw_mac)
    };
    let Some(mac) = mac else { return EHOSTUNREACH };
    if !crate::e1000::udp_tx(mac, dip, sport, dport, &pay[..len as usize]) {
        return (-5i64) as u64; // EIO — tx ring rejected
    }
    len
}

/// recvfrom(fd, buf, len, flags, sockaddr_out, alen): the next queued
/// datagram, or block until the demux wakes us. alen is accepted for
/// ABI shape — the sockaddr is always written at full 16 bytes when
/// requested.
pub fn fd_recvfrom(
    ctx: &mut UCtx,
    fd: u64,
    buf: u64,
    len: u64,
    _flags: u64,
    sa: u64,
    _alen: u64,
) -> u64 {
    let Some(t) = cur_mut() else { return EBADF };
    match ofd(t, fd).map(|o| &o.kind) {
        Some(FdKind::Udp(i)) => udp_recv_or_block(ctx, *i, buf, len, sa),
        Some(FdKind::Tcp(i)) => tcp_recv_or_block(ctx, *i, buf, len, sa),
        _ => EBADF,
    }
}

// ---- TCP sockets (SOCK_STREAM) ----
//
// Minimal in-order stack: no retransmit, no out-of-order queue —
// out-of-window segments drop and that's honest loss. States are
// the textbook ones. Accepted children are first-class TCPSOCKS
// slots; the listener's backlog holds only indices, so nothing is
// cloned and there is no association to inherit (CVE-2026-99116's
// accept-clone UAF class is absent by design). Listener state is
// never carried across calls either — no stale-error accepts
// (CVE-2026-90138 class). ISNs come from the same SipHash-
// keyed construction as the wire selftest.

/// Bounds: endpoints, per-conn stream buffer, accept backlog.
const MAX_TCPS: usize = 8;
const TCP_RX_CAP: usize = 2048;
const TCP_BACKLOG: usize = 4;
/// connect() timeout, ~10s at 100Hz ticks.
const TCP_CONN_TICKS: u64 = 1000;

#[derive(Clone, Copy, PartialEq, Eq)]
enum TcpState {
    /// Fresh socket — bound or not, never connected.
    Init,
    Listen,
    /// connect() sent SYN, awaiting SYN-ACK.
    SynSent,
    /// Listener child: SYN seen, SYN-ACK sent, awaiting the ACK.
    SynRecv,
    Estab,
    /// Peer's FIN arrived — our send side still open.
    CloseWait,
    /// We sent FIN; awaiting its ACK and/or the peer's FIN.
    FinWait,
    /// FINs crossed: ours ACKs the peer's, awaiting ours.
    LastAck,
    Closed,
}

struct TcpSock {
    port: u16,
    peer_ip: [u8; 4],
    peer_port: u16,
    peer_mac: [u8; 6],
    state: TcpState,
    snd_nxt: u32,
    rcv_nxt: u32,
    /// Our FIN was ACKed (FinWait/LastAck bookkeeping).
    fin_acked: bool,
    /// Peer FIN'd — reads hit EOF once the buffer drains.
    fin_rx: bool,
    /// Listener: established children not yet accept()ed.
    backlog: [usize; TCP_BACKLOG],
    blen: usize,
    /// SynRecv child: the listener slot that spawned us.
    parent: usize,
    /// All fds gone — teardown completes asynchronously.
    orphan: bool,
    /// RST seen — reads fail ECONNRESET, writes EPIPE.
    dead: bool,
    rxb: [u8; TCP_RX_CAP],
    rxl: usize,
}

static mut TCPSOCKS: [Option<TcpSock>; MAX_TCPS] = [const { None }; MAX_TCPS];

fn tcp_socks() -> &'static mut [Option<TcpSock>; MAX_TCPS] {
    unsafe { &mut *core::ptr::addr_of_mut!(TCPSOCKS) }
}

/// Predictable-ISN rejection: SipHash of the 4-tuple + a timestamp
/// under the per-boot key — same construction as tcp_selftest.
fn tcp_isn(dip: [u8; 4], sport: u16, dport: u16) -> u32 {
    let our = crate::e1000::our_ip();
    let t = unsafe { core::arch::x86_64::_rdtsc() } as u32;
    klib::hash::siphash_3u32(
        u32::from_be_bytes(our) ^ u32::from_be_bytes(dip),
        ((sport as u32) << 16) | dport as u32,
        t,
        crate::rand::isn_key(),
    ) as u32
}

/// Lowest unbound local TCP port >= EPHEM_BASE (separate namespace
/// from UDP, like Linux).
fn tcp_ephemeral() -> Option<u16> {
    let socks = unsafe { &*core::ptr::addr_of!(TCPSOCKS) };
    (EPHEM_BASE..=u16::MAX)
        .find(|&p| !socks.iter().flatten().any(|s| s.port == p))
}

/// Emit one segment for a connection slot.
fn tcp_seg(
    k: &TcpSock,
    flags: u8,
    payload: &[u8],
) -> bool {
    crate::e1000::tcp_tx(
        k.peer_mac, k.peer_ip, k.port, k.peer_port, k.snd_nxt,
        k.rcv_nxt, flags, payload,
    )
}

/// RST answering a segment nobody owns — never RST an RST.
#[allow(clippy::too_many_arguments)]
fn tcp_rst(
    src_ip: [u8; 4],
    src_mac: [u8; 6],
    sport: u16,
    dport: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    plen: usize,
) {
    if flags & crate::net::TCP_RST != 0 {
        return;
    }
    let (s, a, fl) = if flags & crate::net::TCP_ACK != 0 {
        (ack, 0, crate::net::TCP_RST)
    } else {
        let used = plen as u32
            + (flags & crate::net::TCP_SYN != 0) as u32
            + (flags & crate::net::TCP_FIN != 0) as u32;
        (0, seq.wrapping_add(used), crate::net::TCP_RST | crate::net::TCP_ACK)
    };
    let _ = crate::e1000::tcp_tx(
        src_mac, src_ip, dport, sport, s, a, fl, &[],
    );
}

/// Drop the first runnable task sleeping on `on`, hand it `ret`
/// and mark it Runnable — the generic non-data wake.
fn wake_waiter(on: WaitOn, ret: u64) {
    let tasks = unsafe { &mut *core::ptr::addr_of_mut!(TASKS) };
    for s in tasks.iter_mut() {
        let Some(t) = s.as_mut() else { continue };
        if t.state == TaskState::Blocked && t.wait_on == on {
            t.ctx.rax = ret;
            t.wait_on = WaitOn::None;
            t.wait_deadline = 0;
            t.state = TaskState::Runnable;
            return;
        }
    }
}

/// Mint a Tcp OFD+fd inside task `t` for connection `ci`.
/// Returns the fd, or EMFILE/ENFILE without consuming `ci`.
fn tcp_mint_fd(t: &mut Task, ci: usize, ce: bool) -> Result<u64, u64> {
    const ENFILE_: u64 = (-23i64) as u64;
    let ofds = unsafe { &mut *core::ptr::addr_of_mut!(OFDS) };
    let Some(oi) = ofds.iter().position(Option::is_none) else {
        return Err(ENFILE_);
    };
    let Some(fi) = fdt(t).fds.iter().position(Option::is_none) else {
        return Err(EMFILE);
    };
    ofds[oi] = Some(OpenFile {
        kind: FdKind::Tcp(ci),
        pos: 0,
        refs: 1,
        append: false,
        accmode: 2,
    });
    fdt(t).fds[fi] = Some(oi as u8);
    cloexec_set(t, fi, ce);
    Ok(fi as u64)
}

/// A connection reached Estab or died — wake a blocked accept() on
/// listener `li` by minting its fd inside the sleeper's table.
fn wake_accept(li: usize) {
    let tasks = unsafe { &mut *core::ptr::addr_of_mut!(TASKS) };
    for s in tasks.iter_mut() {
        let Some(t) = s.as_mut() else { continue };
        if t.state == TaskState::Blocked && t.wait_on == WaitOn::TcpAccept(li) {
            let socks = tcp_socks();
            let Some(k) = socks[li].as_mut() else { return };
            if k.blen == 0 {
                continue;
            }
            let ci = k.backlog[0];
            for j in 1..k.blen {
                k.backlog[j - 1] = k.backlog[j];
            }
            k.blen -= 1;
            match tcp_mint_fd(t, ci, t.wait_len & SOCK_CLOEXEC != 0) {
                Ok(fd) => t.ctx.rax = fd,
                Err(e) => {
                    k.backlog[k.blen] = ci;
                    k.blen += 1;
                    t.ctx.rax = e;
                }
            }
            if t.wait_ptr2 != 0 {
                // sockaddr_out requested — the peer's address.
                let socks = unsafe { &*core::ptr::addr_of!(TCPSOCKS) };
                if let Some(c) = socks[ci].as_ref() {
                    let _ = write_task_bytes(
                        t.pml4,
                        t.wait_ptr2,
                        &sockaddr_in(c.peer_port, c.peer_ip),
                    );
                }
                t.wait_ptr2 = 0;
            }
            t.wait_on = WaitOn::None;
            t.state = TaskState::Runnable;
            return;
        }
    }
}

/// Feed a blocked TcpRecv sleeper straight from the connection's
/// stream buffer through ITS page tables — or EOF/error without
/// data, matching what a re-run recv() would return.
fn wake_tcp_recv(ci: usize) {
    const ECONNRESET: u64 = (-104i64) as u64;
    let tasks = unsafe { &mut *core::ptr::addr_of_mut!(TASKS) };
    for s in tasks.iter_mut() {
        let Some(t) = s.as_mut() else { continue };
        if t.state == TaskState::Blocked && t.wait_on == WaitOn::TcpRecv(ci) {
            let socks = tcp_socks();
            let Some(k) = socks[ci].as_mut() else { return };
            if k.dead {
                t.ctx.rax = ECONNRESET;
            } else if k.rxl > 0 {
                let n = core::cmp::min(k.rxl, t.wait_len as usize);
                if !write_task_bytes(t.pml4, t.wait_ptr, &k.rxb[..n]) {
                    return; // sleeper's pages vanished — leave it
                }
                k.rxb.copy_within(n..k.rxl, 0);
                k.rxl -= n;
                t.ctx.rax = n as u64;
            } else if k.fin_rx {
                t.ctx.rax = 0;
            } else {
                return;
            }
            if t.wait_ptr2 != 0 {
                // recvfrom asked for the peer's sockaddr.
                let _ = write_task_bytes(
                    t.pml4,
                    t.wait_ptr2,
                    &sockaddr_in(k.peer_port, k.peer_ip),
                );
                t.wait_ptr2 = 0;
            }
            t.wait_on = WaitOn::None;
            t.wait_deadline = 0;
            t.state = TaskState::Runnable;
            return;
        }
    }
}

/// Free a connection slot, unlinking it from a listener backlog.
fn tcp_free(ci: usize) {
    let socks = tcp_socks();
    let parent = socks[ci].as_ref().map_or(usize::MAX, |k| k.parent);
    socks[ci] = None;
    if parent != usize::MAX {
        if let Some(l) = socks[parent].as_mut() {
            if let Some(j) = l.backlog[..l.blen].iter().position(|&c| c == ci)
            {
                for x in j + 1..l.blen {
                    l.backlog[x - 1] = l.backlog[x];
                }
                l.blen -= 1;
            }
        }
    }
}

/// Per-connection segment handling — the state machine proper.
/// `src_mac` is the sender's link address, kept as peer_mac so
/// replies track the freshest ARP truth.
#[allow(clippy::too_many_arguments)]
fn tcp_rx_conn(
    ci: usize,
    _src_ip: [u8; 4],
    src_mac: [u8; 6],
    seq: u32,
    ack: u32,
    flags: u8,
    payload: &[u8],
) {
    let socks = tcp_socks();
    let Some(k) = socks[ci].as_mut() else { return };
    k.peer_mac = src_mac;
    if flags & crate::net::TCP_RST != 0 {
        let was = k.state;
        k.dead = true;
        k.state = TcpState::Closed;
        if k.orphan || matches!(was, TcpState::SynRecv) {
            tcp_free(ci); // nothing else references it
            return;
        }
        wake_waiter(WaitOn::TcpConn(ci), (-111i64) as u64); // ECONNREFUSED
        wake_tcp_recv(ci);
        wake_pollers();
        return;
    }
    match k.state {
        TcpState::SynSent => {
            if flags & crate::net::TCP_SYN != 0
                && flags & crate::net::TCP_ACK != 0
                && ack == k.snd_nxt
            {
                k.rcv_nxt = seq.wrapping_add(1);
                k.state = TcpState::Estab;
                let _ = tcp_seg(k, crate::net::TCP_ACK, &[]);
                wake_waiter(WaitOn::TcpConn(ci), 0);
                wake_pollers();
            }
        }
        TcpState::SynRecv => {
            if flags & crate::net::TCP_ACK != 0 && ack == k.snd_nxt {
                let li = k.parent;
                let ok = {
                    let l = socks[li].as_mut();
                    l.is_some_and(|l| {
                        if l.state == TcpState::Listen && l.blen < TCP_BACKLOG {
                            l.backlog[l.blen] = ci;
                            l.blen += 1;
                            true
                        } else {
                            false
                        }
                    })
                };
                if ok {
                    socks[ci].as_mut().unwrap().state = TcpState::Estab;
                    wake_accept(li);
                    wake_pollers();
                } else {
                    // Listener gone or backlog full — RST the child.
                    let (pm, pi, sp, dp, sn) = {
                        let k = socks[ci].as_ref().unwrap();
                        (k.peer_mac, k.peer_ip, k.port, k.peer_port,
                         k.snd_nxt)
                    };
                    let _ = crate::e1000::tcp_tx(
                        pm, pi, sp, dp, sn, 0, crate::net::TCP_RST, &[],
                    );
                    tcp_free(ci);
                }
            }
        }
        TcpState::Estab | TcpState::CloseWait | TcpState::FinWait => {
            // ACK bookkeeping for our FIN before data handling.
            if ack == k.snd_nxt && k.state == TcpState::FinWait {
                k.fin_acked = true;
            }
            let mut close_me = false;
            if seq == k.rcv_nxt {
                let mut adv = 0u32;
                if !payload.is_empty()
                    && k.rxl + payload.len() <= TCP_RX_CAP
                {
                    k.rxb[k.rxl..k.rxl + payload.len()]
                        .copy_from_slice(payload);
                    k.rxl += payload.len();
                    adv += payload.len() as u32;
                }
                if flags & crate::net::TCP_FIN != 0 {
                    // FIN only counts once preceding bytes are ours.
                    if adv as usize == payload.len() {
                        adv += 1;
                        k.fin_rx = true;
                    }
                }
                if adv > 0 {
                    k.rcv_nxt = k.rcv_nxt.wrapping_add(adv);
                    let _ = tcp_seg(k, crate::net::TCP_ACK, &[]);
                }
                if k.fin_rx && k.state == TcpState::Estab {
                    k.state = TcpState::CloseWait;
                } else if k.fin_rx
                    && k.state == TcpState::FinWait
                    && k.fin_acked
                {
                    k.state = TcpState::Closed;
                    close_me = k.orphan;
                }
                wake_tcp_recv(ci);
                wake_pollers();
            }
            if close_me {
                tcp_free(ci);
            }
        }
        TcpState::LastAck if ack == k.snd_nxt => {
            let orphan = k.orphan;
            k.state = TcpState::Closed;
            if orphan {
                tcp_free(ci);
            } else {
                wake_tcp_recv(ci);
                wake_pollers();
            }
        }
        _ => {}
    }
}

/// TCP demux entry — wire path via e1000::ip_demux, loopback via
/// the same demux on injected frames. First match wins: an
/// established-ish 4-tuple connection, else a listener takes SYNs,
/// else we answer RST like a closed port should.
#[allow(clippy::too_many_arguments)]
pub fn tcp_rx(
    src_ip: [u8; 4],
    src_mac: [u8; 6],
    sport: u16,
    dport: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    payload: &[u8],
) {
    let socks = tcp_socks();
    if let Some(ci) = socks.iter().position(|s| {
        s.as_ref().is_some_and(|k| {
            !matches!(k.state, TcpState::Listen | TcpState::Init)
                && k.port == dport
                && k.peer_port == sport
                && k.peer_ip == src_ip
        })
    }) {
        tcp_rx_conn(ci, src_ip, src_mac, seq, ack, flags, payload);
        return;
    }
    if flags & crate::net::TCP_SYN != 0 && flags & crate::net::TCP_ACK == 0 {
        let Some(li) = socks.iter().position(|s| {
            s.as_ref().is_some_and(|k| {
                k.state == TcpState::Listen && k.port == dport
            })
        }) else {
            // SYN to a closed port — refuse, so connect() sees it.
            tcp_rst(src_ip, src_mac, sport, dport, seq, ack, flags,
                    payload.len());
            return;
        };
        // Bound half-open + accepted children per listener.
        let kids = socks.iter().flatten()
            .filter(|k| k.parent == li).count();
        let Some(ci) = socks.iter().position(Option::is_none) else {
            return; // no slots — drop
        };
        if kids >= TCP_BACKLOG {
            return; // backlog bound — honest drop
        }
        let isn = tcp_isn(src_ip, dport, sport);
        socks[ci] = Some(TcpSock {
            port: dport,
            peer_ip: src_ip,
            peer_port: sport,
            peer_mac: src_mac,
            state: TcpState::SynRecv,
            snd_nxt: isn.wrapping_add(1),
            rcv_nxt: seq.wrapping_add(1),
            fin_acked: false,
            fin_rx: false,
            backlog: [usize::MAX; TCP_BACKLOG],
            blen: 0,
            parent: li,
            orphan: false,
            dead: false,
            rxb: [0; TCP_RX_CAP],
            rxl: 0,
        });
        // SYN-ACK from the child: seq=isn, ack=their seq+1.
        let _ = crate::e1000::tcp_tx(
            src_mac, src_ip, dport, sport, isn,
            seq.wrapping_add(1),
            crate::net::TCP_SYN | crate::net::TCP_ACK, &[],
        );
        // If the peer vanishes the child reaps when the listener
        // closes; the ACK completing it moves it to the backlog.
        return;
    }
    // Nothing to catch it — closed-port RST.
    tcp_rst(src_ip, src_mac, sport, dport, seq, ack, flags,
            payload.len());
}

/// Initiate a connection: SYN out, then block (with a ~10s
/// deadline) for the SYN-ACK — unless loopback completed it inline.
pub fn fd_connect(ctx: &mut UCtx, fd: u64, sa: u64, len: u64) -> u64 {
    const EAFNOSUPPORT: u64 = (-97i64) as u64;
    const EADDRNOTAVAIL: u64 = (-99i64) as u64;
    const ECONNREFUSED: u64 = (-111i64) as u64;
    const EHOSTUNREACH: u64 = (-113i64) as u64;
    const EISCONN: u64 = (-106i64) as u64;
    const EINTR_: u64 = (-4i64) as u64;
    let Some(t) = cur_mut() else { return EBADF };
    if len < 8 || !range_ok(sa, 8) {
        return EFAULT;
    }
    let Some(si) = (match ofd(t, fd).map(|o| &o.kind) {
        Some(FdKind::Tcp(i)) => Some(*i),
        _ => None,
    }) else {
        return EBADF;
    };
    let Some((dport, dip)) = parse_sockaddr(t.pml4, sa) else {
        return EAFNOSUPPORT;
    };
    if !crate::e1000::net_up() {
        return EHOSTUNREACH;
    }
    let Some(mac) = crate::e1000::route_mac(dip) else {
        return EHOSTUNREACH;
    };
    // Loopback peers canonicalize to our own address — replies on
    // the injected path carry our IP as their source, so the
    // 4-tuple match stays exact.
    let peer = if dip[0] == 127 { crate::e1000::our_ip() } else { dip };
    {
        let socks = tcp_socks();
        let Some(k) = socks[si].as_mut() else { return EBADF };
        if k.state != TcpState::Init {
            return EISCONN; // already connected/connecting
        }
        if k.port == 0 {
            let Some(e) = tcp_ephemeral() else {
                return EADDRNOTAVAIL;
            };
            k.port = e;
        }
        k.peer_ip = peer;
        k.peer_port = dport;
        k.peer_mac = mac;
        k.snd_nxt = tcp_isn(peer, k.port, dport).wrapping_add(1);
        k.state = TcpState::SynSent;
        let isn = k.snd_nxt.wrapping_sub(1);
        let _ = crate::e1000::tcp_tx(
            mac, dip, k.port, dport, isn, 0, crate::net::TCP_SYN, &[],
        );
        // Loopback may have completed the handshake inside the tx.
        match k.state {
            TcpState::Estab => return 0,
            _ if k.dead => return ECONNREFUSED,
            _ => {}
        }
    }
    let Some(t) = cur_mut() else { return EBADF };
    if deliverable(t) {
        return EINTR_;
    }
    t.wait_on = WaitOn::TcpConn(si);
    t.wait_deadline = crate::apic::TICKS
        .load(core::sync::atomic::Ordering::Relaxed)
        + TCP_CONN_TICKS;
    t.ctx = *ctx;
    t.state = TaskState::Blocked;
    block_switch()
}

/// listen(fd, backlog): a bound Init socket becomes passive.
/// backlog is capped at our queue depth, like Linux clamps it.
pub fn fd_listen(fd: u64, backlog: u64) -> u64 {
    const EADDRNOTAVAIL: u64 = (-99i64) as u64;
    const EOPNOTSUPP: u64 = (-95i64) as u64;
    let Some(t) = cur_mut() else { return EBADF };
    let Some(si) = (match ofd(t, fd).map(|o| &o.kind) {
        Some(FdKind::Tcp(i)) => Some(*i),
        _ => None,
    }) else {
        return EOPNOTSUPP; // non-TCP or bad fd
    };
    let socks = tcp_socks();
    let Some(k) = socks[si].as_mut() else { return EOPNOTSUPP };
    match k.state {
        TcpState::Listen => {
            k.blen = k.blen.min(TCP_BACKLOG.min(backlog as usize));
            return 0; // re-listen just shrinks the queue
        }
        TcpState::Init => {}
        _ => return EINVAL, // listened after connecting — EINVAL
    }
    if k.port == 0 {
        let Some(e) = tcp_ephemeral() else {
            return EADDRNOTAVAIL;
        };
        k.port = e;
    }
    k.blen = 0;
    k.state = TcpState::Listen;
    0
}

/// accept(fd, sockaddr_out, alen[, flags]): the oldest established
/// child becomes a fresh fd; empty backlog blocks until one
/// completes. accept4's flags ride wait_len through the blocked
/// path — SOCK_CLOEXEC marks the minted fd, SOCK_NONBLOCK refuses
/// honestly (no nonblocking sockets).
pub fn fd_accept(ctx: &mut UCtx, fd: u64, sa: u64, _alen: u64, flags: u64) -> u64 {
    const EOPNOTSUPP: u64 = (-95i64) as u64;
    const EINTR_: u64 = (-4i64) as u64;
    if flags & !(SOCK_CLOEXEC | SOCK_NONBLOCK) != 0 || flags & SOCK_NONBLOCK != 0 {
        return EINVAL;
    }
    let Some(t) = cur_mut() else { return EBADF };
    if sa != 0 && !range_ok_w(sa, 16) {
        return EFAULT;
    }
    let Some(li) = (match ofd(t, fd).map(|o| &o.kind) {
        Some(FdKind::Tcp(i)) => Some(*i),
        _ => None,
    }) else {
        return EOPNOTSUPP;
    };
    crate::e1000::rx_drain();
    let socks = tcp_socks();
    let Some(k) = socks[li].as_mut() else { return EOPNOTSUPP };
    if k.state != TcpState::Listen {
        return EINVAL;
    }
    if k.blen > 0 {
        let ci = k.backlog[0];
        for j in 1..k.blen {
            k.backlog[j - 1] = k.backlog[j];
        }
        k.blen -= 1;
        let (pip, pport) = {
            let c = socks[ci].as_ref().unwrap();
            (c.peer_ip, c.peer_port)
        };
        let Some(t) = cur_mut() else { return EBADF };
        let fd = match tcp_mint_fd(t, ci, flags & SOCK_CLOEXEC != 0) {
            Ok(f) => f,
            Err(e) => {
                let k = tcp_socks()[li].as_mut().unwrap();
                k.backlog[k.blen] = ci;
                k.blen += 1;
                return e;
            }
        };
        if sa != 0 {
            // SAFETY: sa validated writable above; all 16 bytes
            // come from the zeroed sockaddr_in.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    sockaddr_in(pport, pip).as_ptr(),
                    sa as *mut u8,
                    16,
                );
            }
        }
        return fd;
    }
    let Some(t) = cur_mut() else { return EBADF };
    if deliverable(t) {
        return EINTR_;
    }
    t.wait_on = WaitOn::TcpAccept(li);
    t.wait_ptr2 = sa;
    t.wait_len = flags; // accept4's SOCK_CLOEXEC rides the wake
    t.ctx = *ctx;
    t.state = TaskState::Blocked;
    block_switch()
}

/// Stream receive shared by read()/recvfrom() on a TCP fd.
/// `sa` (when nonzero) gets the peer's sockaddr.
fn tcp_recv_or_block(
    ctx: &mut UCtx,
    si: usize,
    buf: u64,
    len: u64,
    sa: u64,
) -> u64 {
    const ENOTCONN: u64 = (-107i64) as u64;
    const ECONNRESET: u64 = (-104i64) as u64;
    const EINTR_: u64 = (-4i64) as u64;
    if cur_mut().is_none() {
        return EBADF;
    }
    crate::e1000::rx_drain();
    {
        let socks = tcp_socks();
        let Some(k) = socks[si].as_mut() else { return EBADF };
        if k.dead {
            return ECONNRESET;
        }
        match k.state {
            TcpState::Estab
            | TcpState::CloseWait
            | TcpState::FinWait
            | TcpState::LastAck
            | TcpState::Closed => {}
            _ => return ENOTCONN, // no data stream yet
        }
        if k.rxl > 0 {
            let n = core::cmp::min(k.rxl, len as usize);
            if n > 0 && !range_ok_w(buf, n as u64) {
                return EFAULT;
            }
            // SAFETY: buf validated writable under this task's
            // page table; rxb holds received bytes only.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    k.rxb.as_ptr(),
                    buf as *mut u8,
                    n,
                );
            }
            k.rxb.copy_within(n..k.rxl, 0);
            k.rxl -= n;
            return n as u64;
        }
        if k.fin_rx || k.state == TcpState::Closed {
            return 0; // EOF
        }
    }
    if !range_ok_w(buf, len.min(TCP_RX_CAP as u64).max(1)) {
        return EFAULT;
    }
    let Some(t) = cur_mut() else { return EBADF };
    if deliverable(t) {
        return EINTR_;
    }
    t.wait_on = WaitOn::TcpRecv(si);
    t.wait_ptr = buf;
    t.wait_len = len.min(TCP_RX_CAP as u64);
    t.wait_ptr2 = sa;
    t.ctx = *ctx;
    t.state = TaskState::Blocked;
    block_switch()
}

/// Stream send shared by write()/sendto() on a TCP fd.
fn tcp_send(si: usize, buf: u64, len: u64) -> u64 {
    const ENOTCONN: u64 = (-107i64) as u64;
    const EMSGSIZE: u64 = (-90i64) as u64;
    const EPIPE_: u64 = (-32i64) as u64;
    if cur_mut().is_none() {
        return EBADF;
    }
    if len == 0 {
        return 0;
    }
    if len > 1400 {
        return EMSGSIZE;
    }
    if !range_ok(buf, len) {
        return EFAULT;
    }
    let (state, dead) = {
        let socks = unsafe { &*core::ptr::addr_of!(TCPSOCKS) };
        match socks[si].as_ref() {
            Some(k) => (k.state, k.dead),
            None => return EBADF,
        }
    };
    if dead {
        return EPIPE_;
    }
    if !matches!(state, TcpState::Estab | TcpState::CloseWait) {
        return ENOTCONN;
    }
    // SAFETY: buf validated readable for len under this task's
    // page table; the slice is consumed by tcp_tx before any
    // re-entrant drain could disturb it.
    let pay = unsafe {
        core::slice::from_raw_parts(buf as *const u8, len as usize)
    };
    // Snapshot what the segment needs — the tx path can re-enter
    // the table (loopback drain) so no borrow crosses it.
    let (pm, pi, sp, dp, sn, rn) = {
        let socks = unsafe { &*core::ptr::addr_of!(TCPSOCKS) };
        let k = socks[si].as_ref().unwrap();
        (k.peer_mac, k.peer_ip, k.port, k.peer_port, k.snd_nxt,
         k.rcv_nxt)
    };
    if !crate::e1000::tcp_tx(
        pm, pi, sp, dp, sn, rn,
        crate::net::TCP_PSH | crate::net::TCP_ACK,
        pay,
    ) {
        return (-5i64) as u64; // EIO — tx ring rejected
    }
    let socks = tcp_socks();
    match socks[si].as_mut() {
        Some(k) => {
            k.snd_nxt = k.snd_nxt.wrapping_add(len as u32);
            len
        }
        None => EPIPE_, // loopback teardown freed it mid-send
    }
}

/// shutdown(fd, how): how&2 closes the send side with a FIN.
/// how==1 alone marks reads EOF; how==2 does both.
pub fn fd_shutdown(fd: u64, how: u64) -> u64 {
    const ENOTCONN: u64 = (-107i64) as u64;
    let Some(t) = cur_mut() else { return EBADF };
    let Some(si) = (match ofd(t, fd).map(|o| &o.kind) {
        Some(FdKind::Tcp(i)) => Some(*i),
        _ => None,
    }) else {
        return EBADF;
    };
    if how > 2 {
        return EINVAL;
    }
    let socks = tcp_socks();
    let Some(k) = socks[si].as_mut() else { return EBADF };
    if how == 0 || how == 2 {
        k.fin_rx = true; // reads EOF now
    }
    if how >= 1 {
        match k.state {
            TcpState::Estab => {
                let _ = tcp_seg(k, crate::net::TCP_FIN | crate::net::TCP_ACK, &[]);
                let k = tcp_socks()[si].as_mut().unwrap();
                k.snd_nxt = k.snd_nxt.wrapping_add(1);
                k.state = TcpState::FinWait;
            }
            TcpState::CloseWait => {
                let _ = tcp_seg(k, crate::net::TCP_FIN | crate::net::TCP_ACK, &[]);
                let k = tcp_socks()[si].as_mut().unwrap();
                k.snd_nxt = k.snd_nxt.wrapping_add(1);
                k.state = TcpState::LastAck;
            }
            _ => return ENOTCONN,
        }
    }
    0
}

/// Last-fd teardown for a TCP socket: FIN the live connection and
/// orphan it to finish asynchronously; RST the half-open; listeners
/// drop their incomplete children. Established backlog children
/// survive — they're connections in their own right.
fn tcp_sock_close(si: usize) {
    enum A {
        Free,
        Fin(TcpState),
        Orphan,
    }
    let socks = tcp_socks();
    let Some(k) = socks[si].as_mut() else { return };
    let act = match k.state {
        TcpState::Estab => A::Fin(TcpState::FinWait),
        TcpState::CloseWait => A::Fin(TcpState::LastAck),
        TcpState::FinWait | TcpState::LastAck => A::Orphan,
        TcpState::SynSent | TcpState::SynRecv => {
            let _ = tcp_seg(k, crate::net::TCP_RST, &[]);
            A::Free
        }
        TcpState::Listen => {
            // RST + free the listener's incomplete children.
            let kids: [usize; MAX_TCPS] = {
                let mut v = [usize::MAX; MAX_TCPS];
                let mut n = 0;
                for (i, s) in socks.iter().enumerate() {
                    if s.as_ref().is_some_and(|c| c.parent == si
                        && c.state == TcpState::SynRecv)
                    {
                        v[n] = i;
                        n += 1;
                    }
                }
                v
            };
            for ci in kids {
                if ci != usize::MAX {
                    if let Some(c) = socks[ci].as_mut() {
                        let _ = tcp_seg(c, crate::net::TCP_RST, &[]);
                    }
                    tcp_free(ci);
                }
            }
            A::Free
        }
        _ => A::Free,
    };
    match act {
        A::Free => socks[si] = None,
        A::Orphan => {
            if let Some(k) = socks[si].as_mut() {
                k.orphan = true;
            }
        }
        A::Fin(next) => {
            let Some(k) = socks[si].as_mut() else { return };
            let _ = tcp_seg(k, crate::net::TCP_FIN | crate::net::TCP_ACK, &[]);
            let k = socks[si].as_mut().unwrap();
            k.snd_nxt = k.snd_nxt.wrapping_add(1);
            k.state = next;
            k.orphan = true;
        }
    }
}

/// First path component of `name` under `dir` ("" = root) — the
/// dedup unit for flat-VFS directory enumeration.
fn dir_child<'a>(dir: &[u8], name: &'a [u8]) -> Option<&'a [u8]> {
    let rest = if dir.is_empty() {
        name
    } else if name.len() > dir.len()
        && name.starts_with(dir)
        && name[dir.len()] == b'/'
    {
        &name[dir.len() + 1..]
    } else {
        return None;
    };
    if rest.is_empty() {
        return None;
    }
    let end = rest.iter().position(|&c| c == b'/').unwrap_or(rest.len());
    Some(&rest[..end])
}

/// Push name's first component under dir into the dedup'd list.
fn dir_add<'a>(
    dir: &[u8],
    names: &mut [Option<&'a [u8]>; 384],
    n: &mut usize,
    name: &'a [u8],
) {
    if let Some(comp) = dir_child(dir, name) {
        if *n < names.len()
            && !names[..*n].iter().flatten().any(|e| *e == comp)
        {
            names[*n] = Some(comp);
            *n += 1;
        }
    }
}

/// getdents64(fd, dirp, count): emit linux_dirent64 records for the
/// archive entries from `pos` on, filling at most `count` bytes. The
/// whole user buffer is validated writable up front — a record is
/// only ever written inside it, and never partially (each record's
/// reclen is checked against the remaining space before the write).
/// EINVAL when count can't hold even the next record; 0 at the end.
pub fn fd_getdents(fd: u64, buf: u64, count: u64) -> u64 {
    const MAX: u64 = 1 << 20;
    let Some(t) = cur_mut() else { return EBADF };
    let Some(o) = ofd(t, fd) else { return EBADF };
    if !matches!(o.kind, FdKind::Dir(_)) {
        return ENOTDIR;
    }
    if count == 0 || count > MAX {
        return EINVAL;
    }
    if !range_ok_w(buf, count) {
        return EFAULT;
    }
    let FdKind::Dir(dp) = &o.kind else { return ENOTDIR };
    let dir = *dp;
    let dpath = dir.bytes();
    let mut off = 0usize;
    let mut idx = o.pos;
    // The stream: ".", "..", then each unique first component under
    // this dir — deduped, since "usr/bin/x" and "usr/bin/y" both
    // contribute "usr". Pseudo-dirs /proc + /proc/self fold in.
    let mut names: [Option<&[u8]>; 384] = [None; 384];
    names[0] = Some(b".");
    names[1] = Some(b"..");
    let mut n = 2usize;
    dir_add(dpath, &mut names, &mut n, b"proc");
    dir_add(dpath, &mut names, &mut n, b"proc/self");
    dir_add(dpath, &mut names, &mut n, b"proc/self/exe");
    // /proc enumeration — task slots can't be reaped mid-syscall, so
    // the pid set is stable across this pass. pidbuf backs the
    // rendered pid names names[] borrows; files under a pid dir are
    // the static PROC_TFILES leaves.
    let mut pidbuf = [[0u8; 26]; MAX_TASKS];
    let mut fdbuf = [[0u8; 3]; MAX_FDS];
    if dpath == b"proc" {
        for f in PROC_GFILES {
            if n < names.len() && !names[..n].iter().flatten().any(|e| *e == f) {
                names[n] = Some(f);
                n += 1;
            }
        }
        let tasks = unsafe { &*core::ptr::addr_of!(TASKS) };
        for (i, pb) in pidbuf.iter_mut().enumerate() {
            let Some(t) = tasks[i].as_ref() else { continue };
            if proc_dead(t, tasks) {
                continue;
            }
            // Render "proc/<pid>" into pidbuf and feed it through
            // add() so the pid component lands like any other name.
            let b = &mut *pb;
            b[..5].copy_from_slice(b"proc/");
            let mut m = 5usize;
            let mut v = t.pid;
            let mut d = [0u8; 20];
            let mut dl = 0usize;
            loop {
                d[dl] = b'0' + (v % 10) as u8;
                v /= 10;
                dl += 1;
                if v == 0 {
                    break;
                }
            }
            while dl > 0 {
                dl -= 1;
                b[m] = d[dl];
                m += 1;
            }
            dir_add(dpath, &mut names, &mut n, &pb[..m]);
        }
    } else if let Some(rest) = dpath.strip_prefix(b"proc/") {
        // "proc/<pid>" lists the static leaves; "proc/<pid>/fd" and
        // ".../fdinfo" list the target's live fd numbers — the same
        // contents, fdinfo's names just stat as 0400 files.
        let j = rest.iter().position(|&c| c == b'/').unwrap_or(rest.len());
        if let Some(slot) = proc_pid_slot(&rest[..j]) {
            if j == rest.len() {
                // A live pid dir — bare leaf names, pushed directly
                // (add() extracts components of FULL paths).
                for f in PROC_TFILES {
                    if n < names.len() {
                        names[n] = Some(f);
                        n += 1;
                    }
                }
            } else if &rest[j + 1..] == b"fd" || &rest[j + 1..] == b"fdinfo" {
                let tasks = unsafe { &*core::ptr::addr_of!(TASKS) };
                if let Some(t) = tasks.get(slot).and_then(|s| s.as_ref()) {
                    if t.fdi != FDI_NONE {
                        let tab = unsafe {
                            &(*core::ptr::addr_of!(FDTABS))[t.fdi as usize]
                        };
                        for (i, fb) in fdbuf.iter_mut().enumerate() {
                            if tab.fds[i].is_none() || n >= names.len() {
                                continue;
                            }
                            // fd number, decimal — fds < 100 always
                            // fit the 3-byte scratch.
                            if i >= 10 {
                                fb[0] = b'0' + (i / 10) as u8;
                                fb[1] = b'0' + (i % 10) as u8;
                                names[n] = Some(&fb[..2]);
                            } else {
                                fb[0] = b'0' + i as u8;
                                names[n] = Some(&fb[..1]);
                            }
                            n += 1;
                        }
                    }
                }
            }
        }
    }
    if let Some(arc) = unsafe { *core::ptr::addr_of!(INITRD) } {
        for (name, _data) in crate::cpio::entries(arc) {
            dir_add(dpath, &mut names, &mut n, name);
        }
    }
    for v in unsafe { &*core::ptr::addr_of!(VFILES) }.iter().flatten() {
        if !v.unlinked {
            dir_add(dpath, &mut names, &mut n, &v.name[..v.nlen]);
        }
    }
    for d in unsafe { &*core::ptr::addr_of!(VDIRS) }.iter().flatten() {
        dir_add(dpath, &mut names, &mut n, &d.path[..d.nlen]);
    }
    for name in names[..n].iter().flatten().skip(o.pos) {
        // linux_dirent64: ino@0 u64, off@8 u64, reclen@16 u16,
        // type@18 u8, name@19 NUL-terminated — padded to 8.
        let reclen = (19 + name.len() + 1 + 7) & !7;
        if off + reclen > count as usize {
            if off == 0 {
                return EINVAL; // buffer can't hold even one record
            }
            break;
        }
        let base = buf + off as u64;
        // SAFETY: [buf, buf+count) is validated writable user memory
        // and off+reclen <= count. write_unaligned for the packed
        // fields; the name copy stays inside reclen by construction.
        unsafe {
            ((base) as *mut u64).write_unaligned(idx as u64 + 1);
            ((base + 8) as *mut u64).write_unaligned(idx as u64 + 1);
            ((base + 16) as *mut u16).write_unaligned(reclen as u16);
            // DT_DIR(4) when the component is itself a dir — the
            // . / .. entries (stream positions 0/1) always are.
            let mut full = [0u8; 256];
            let mut fn_ = dpath.len();
            full[..fn_].copy_from_slice(dpath);
            if fn_ > 0 {
                full[fn_] = b'/';
                fn_ += 1;
            }
            full[fn_..fn_ + name.len()].copy_from_slice(name);
            fn_ += name.len();
            let ty = if idx < 2 || dir_exists(&full[..fn_]) {
                4u8
            } else {
                match vfile_find(&full[..fn_]).and_then(|i| {
                    vfile(i).map(|v| (v.is_link, v.fmt))
                }) {
                    Some((true, _)) => 10u8,  // DT_LNK
                    Some((false, 0o20000)) => 2u8,  // DT_CHR
                    Some((false, 0o60000)) => 6u8,  // DT_BLK
                    Some((false, 0o10000)) => 1u8,  // DT_FIFO
                    Some((false, 0o140000)) => 12u8, // DT_SOCK
                    _ => 8u8,                        // DT_REG
                }
            };
            ((base + 18) as *mut u8).write(ty);
            core::ptr::copy_nonoverlapping(
                name.as_ptr(),
                (base + 19) as *mut u8,
                name.len(),
            );
            ((base + 19 + name.len() as u64) as *mut u8).write(0);
            // Zero the pad tail so kernel stack garbage can't leak.
            let pad_end = off + reclen;
            let mut z = off + 19 + name.len() + 1;
            while z < pad_end {
                ((buf + z as u64) as *mut u8).write(0);
                z += 1;
            }
        }
        off += reclen;
        idx += 1;
    }
    o.pos = idx;
    off as u64
}

/// execve: replace the resident task's image. Frees every user
/// mapping (the SAME pml4/kstack/fds persist — fds surviving exec is
/// the Linux semantic), reloads from `img`, and rewrites the syscall
/// ctx so the return leg lands on the new entry with a clean
/// register file — the same UCtx every switch resumes through. The
/// caller parses the ELF first, so the only post-reset failure is
/// allocator exhaustion — treated as fatal by the caller since the
/// old program's code pages are already gone.
pub fn exec(img: &[u8], ctx: &mut UCtx, args: &ExecArgs, name: &[u8]) -> bool {
    let Some(t) = cur_mut() else { return false };
    // execve on a .exe swaps personalities mid-task — the image
    // format check mirrors load(): MZ → PE32+/NT, else ELF.
    let pe_img = if img.starts_with(b"MZ") {
        crate::pe::parse(img)
    } else {
        None
    };
    let e = if pe_img.is_none() { elf::parse(img) } else { None };
    if e.is_none() && pe_img.is_none() {
        return false;
    }
    // O_CLOEXEC dies here: drop each marked fd before the image
    // swap — Linux semantics, and a real leak otherwise (a pipe or
    // socket would survive into a binary that never opened it).
    let mut ce = fdt(t).cloexec;
    while ce != 0 {
        let fi = ce.trailing_zeros() as usize;
        ce &= !(1 << fi);
        if let Some(oi) = fdt(t).fds[fi].take() {
            ofd_release(oi as usize);
        }
    }
    fdt(t).cloexec = 0;
    // exec() must not destroy a shared mm: when siblings still run
    // on this pml4 (CLONE_VM), the exec'ing thread detaches into a
    // fresh pml4 — Linux's exec_mmap gives it a new mm and the old
    // one dies only with its last user. The replacement frame is
    // allocated BEFORE the refcount drops so an alloc failure can't
    // corrupt it.
    let shared = mm_is_shared(t.pml4);
    let np = if shared {
        match kalloc::alloc_frame() {
            Some(f) => f,
            None => return false,
        }
    } else {
        0
    };
    if mm_release(t.pml4) {
        if shared {
            kalloc::free_frame(np); // sole survivor — reuse old pml4
        }
        t.free_user_mappings();
    } else {
        // np is a fresh zeroed table: it needs the shared kernel
        // slots (identity map, slots 0..127) before adoption, and
        // CR3 must switch NOW — the syscall path never reloads it,
        // so returning on the old shared table would exec-fetch
        // fault at entry. Loading np early also keeps load_inner's
        // read_cr3 slot-copy a self-copy: without the switch it
        // would import the SHARED user page tables by reference and
        // map the new image into the still-shared mm.
        let opml4 = t.pml4;
        t.pml4 = np;
        for i in 0..128u64 {
            let e = rd64(opml4 + 8 * i);
            if e & PRESENT != 0 {
                wr64(np + 8 * i, e);
            }
        }
        // SAFETY: np carries the kernel slots copied above.
        unsafe { core::arch::asm!("mov cr3, {0}", in(reg) np) };
    }
    // vfork contract: the exec'ing task just left its parent's
    // address space — resume the suspended vfork parent (Linux's
    // vfork_done completes at exec_mmap, before the new image
    // finishes loading). A later load failure exits the child, but
    // the parent no longer shares its mm so the wake is correct.
    wake_vfork_parent_of(t.pid);
    t.nranges = 0;
    t.stack_top = 0;
    t.fs_base = 0; // TLS dies with the old image — new one SET_FSs
    t.rseq_va = 0; // exec implicitly unregisters rseq
    t.did_exec = true; // pgid/sid persist; parent setpgid now EACCES
    if let Some(p) = &pe_img {
        if !pe_load_inner(t, p, img) {
            return false;
        }
        t.name = [0; 16];
        let nl = name.len().min(15);
        t.name[..nl].copy_from_slice(&name[..nl]);
        t.exe = [0; 128];
        let el = name.len().min(128);
        t.exe[..el].copy_from_slice(&name[..el]);
        t.exe_len = el as u8;
        if !pe_late_init(t) {
            return false;
        }
        unsafe { core::arch::asm!("mov {0}, cr3", "mov cr3, {0}", out(reg) _) };
        for h in sigt(t).handlers.iter_mut() {
            if *h != SIG_IGN {
                *h = SIG_DFL;
            }
        }
        t.fx = unsafe { *core::ptr::addr_of!(INIT_FX) };
        *ctx = UCtx::launch(t.entry, t.stack_top - 0x28);
        return true;
    }
    let e = e.unwrap();
    if !load_inner(t, &e, img) {
        return false;
    }
    t.name = [0; 16];
    let nl = name.len().min(15);
    t.name[..nl].copy_from_slice(&name[..nl]);
    t.exe = [0; 128];
    let el = name.len().min(128);
    t.exe[..el].copy_from_slice(&name[..el]);
    t.exe_len = el as u8;
    // /proc/<pid>/cmdline is NUL-joined argv — snapshot it whole
    // while args still live; an arg that won't fit truncates the
    // line (Linux caps the page too). argv_len counts each arg's
    // NUL already, so the join is a straight copy.
    t.cmdline = [0; 256];
    let mut cl = 0usize;
    for i in 0..args.argc {
        let l = args.argv_len[i];
        if cl + l > t.cmdline.len() {
            break;
        }
        t.cmdline[cl..cl + l].copy_from_slice(&args.argv[i][..l]);
        cl += l;
    }
    t.cmdline_len = cl.min(255) as u8;
    // PT_INTERP: a dynamic image's interpreter maps next, into the
    // mmap arena — its VMAs land after the main binary's so the
    // first-fit gap comes after them. Userspace starts at the
    // interp's entry; it hands control to AT_ENTRY.
    let Some((entry, at_base)) = interp_load(t, &e, img) else {
        return false;
    };
    let Some(rsp) = setup_stack(t, &e, img, args, at_base) else {
        return false;
    };
    t.entry = entry;
    // The pml4 address is unchanged but its contents are entirely
    // new — the TLB still caches the OLD user translations and must
    // be flushed or user code could run on freed frames.
    // SAFETY: reloading the current cr3 only flushes the TLB.
    unsafe { core::arch::asm!("mov {0}, cr3", "mov cr3, {0}", out(reg) _) };
    // exec resets caught handlers to default (SIG_IGN survives) —
    // a handler in the OLD image would be unmapped garbage here.
    for h in sigt(t).handlers.iter_mut() {
        if *h != SIG_IGN {
            *h = SIG_DFL;
        }
    }
    // SAFETY: read of the init-time capture -- exec resets FPU too.
    t.fx = unsafe { *core::ptr::addr_of!(INIT_FX) };
    *ctx = UCtx::launch(t.entry, rsp);
    true
}

// --- scheduler ----------------------------------------------------
// Round-robin over TASKS, driven by the LAPIC timer's dedicated
// dispatch path. Every switch is a UCtx resume; syscall context is
// non-preemptible (IF is masked on entry, and a tick landing on
// kernel CS never switches).

/// Enqueue `img` as a Runnable task — build its real initial stack
/// (argv0 = `name`, no env) and take the first free table slot.
/// False on bad image or full table.
pub fn spawn(img: &[u8], name: &str) -> bool {
    spawn_idx(img, name, false).is_some()
}

/// spawn's task-index form: CreateProcess needs the child's slot to
/// read its pid and apply the suspended flag before it can run.
/// `hold` inserts the child suspended — a CreateProcess caller wires
/// handles/ledgers/cmdline after this returns, and a Runnable child
/// could run, exit and be reaped (slot + pml4 frames recycled)
/// before that wiring lands.
fn spawn_idx(img: &[u8], name: &str, hold: bool) -> Option<usize> {
    let is_pe = img.starts_with(b"MZ");
    let e = elf::parse(img);
    if e.is_none() && !is_pe {
        return None;
    }
    let Some(mut t) = load(img) else {
        return None;
    };
    let mut args = ExecArgs::empty();
    let n = name.len().min(EXEC_STR_CAP - 1);
    args.argv[0][..n].copy_from_slice(&name.as_bytes()[..n]);
    args.argv_len[0] = n + 1;
    args.argc = 1;
    let nl = name.len().min(15);
    t.name[..nl].copy_from_slice(&name.as_bytes()[..nl]);
    let el = name.len().min(128);
    t.exe[..el].copy_from_slice(&name.as_bytes()[..el]);
    t.exe_len = el as u8;
    // Spawn's argv is just argv0 — the cmdline snapshot is name+NUL.
    let cl = (el + 1).min(255);
    t.cmdline[..el.min(255)].copy_from_slice(&name.as_bytes()[..el.min(255)]);
    t.cmdline_len = cl as u8;
    if t.pers == PERS_NT {
        // NT tasks start at the PE entry on a bare stack — no
        // argv/auxv, they read their PEB (gs:[] already points
        // at the TEB via t.gs_base).
        t.ctx = UCtx::launch(t.entry, t.stack_top - 0x28);
    } else {
        let e = e.unwrap();
        let Some((entry, at_base)) = interp_load(&mut t, &e, img) else {
            t.reap();
            return None;
        };
        t.entry = entry;
        let Some(rsp) = setup_stack(&mut t, &e, img, &args, at_base) else {
            t.reap();
            return None;
        };
        t.ctx = UCtx::launch(t.entry, rsp);
    }
    t.tgid = t.pid;
    t.pgid = t.pid; // each spawned task leads its own group in sid 1
    if t.pers == PERS_NT {
        let _ = pe_late_init(&t);
    }
    if hold {
        t.state = TaskState::Blocked;
        t.wait_on = WaitOn::NtSuspend;
    }
    let tasks = unsafe { &mut *core::ptr::addr_of_mut!(TASKS) };
    for (i, s) in tasks.iter_mut().enumerate() {
        if s.is_none() {
            *s = Some(t);
            PROCS_CREATED.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            return Some(i);
        }
    }
    t.reap(); // table full — drop the task cleanly
    None
}

/// Reap reapable zombies — Exited tasks whose parent can't collect
/// them (ppid==0 means orphaned, spawned, or already collected) —
/// except the running one (its kstack may be underfoot). Zombies
/// with a living parent persist until wait4 or the parent's exit.
fn pick_next() -> Option<usize> {
    let cur = unsafe { *core::ptr::addr_of!(CUR_I) };
    let tasks = unsafe { &mut *core::ptr::addr_of_mut!(TASKS) };
    // Snapshot living pids — a zombie is reapable only when no living
    // task can still wait4 it. Blocked counts as living.
    let mut live = [0u64; MAX_TASKS];
    for (i, s) in tasks.iter().enumerate() {
        if let Some(t) = s {
            if t.state != TaskState::Exited {
                live[i] = t.pid;
            }
        }
    }
    for (i, s) in tasks.iter_mut().enumerate() {
        let reapable = s.as_ref().is_some_and(|t| {
            t.state == TaskState::Exited && (t.ppid == 0 || !live.contains(&t.ppid))
        });
        if i != cur && reapable {
            s.as_mut().unwrap().reap();
            *s = None;
        }
    }
    for k in 1..=MAX_TASKS {
        let i = if cur == usize::MAX {
            k - 1
        } else {
            (cur + k) % MAX_TASKS
        };
        if tasks[i].as_ref().is_some_and(|t| t.state == TaskState::Runnable) {
            return Some(i);
        }
    }
    None
}

/// Enter the scheduler: pick the first task and resume its ctx.
/// Returns only when the run queue is empty — the last task's exit
/// unwinds to the kernel context sched_launch saved.
pub fn launch() {
    let Some(n) = pick_ready() else {
        return;
    };
    unsafe { *core::ptr::addr_of_mut!(CUR_I) = n };
    cpu::init_syscall(syscall::entry_addr());
    let (ctx, pml4, kst) = {
        let t = unsafe { (*core::ptr::addr_of!(TASKS))[n].as_ref().unwrap() };
        fxrstor(&t.fx);
        // SAFETY: MSR write of a task-owned user FS base.
        unsafe { cpu::wrmsr(cpu::MSR_FS_BASE, t.fs_base) };
        unsafe { cpu::wrmsr(cpu::MSR_GS_BASE, t.gs_base) };
        (&t.ctx as *const UCtx, t.pml4, t.kstack_top)
    };
    syscall::set_kstack(kst);
    unsafe { syscall::sched_launch(ctx, pml4) };
}

/// Resume the chosen task: set its kstack for syscalls and iret
/// into its saved ctx. Never returns to the caller's context.
fn switch_to(n: usize) -> ! {
    // The outgoing task's FPU state is live in the registers --
    // save it before restoring n's (a dead task's save is harmless).
    let cur = unsafe { *core::ptr::addr_of!(CUR_I) };
    if let Some(t) = unsafe { (*core::ptr::addr_of_mut!(TASKS))[cur].as_mut() } {
        fxsave(t);
    }
    unsafe { *core::ptr::addr_of_mut!(CUR_I) = n };
    let (ctx, pml4, kst) = {
        let t = unsafe { (*core::ptr::addr_of!(TASKS))[n].as_ref().unwrap() };
        fxrstor(&t.fx);
        // SAFETY: MSR write of a task-owned user FS base.
        unsafe { cpu::wrmsr(cpu::MSR_FS_BASE, t.fs_base) };
        unsafe { cpu::wrmsr(cpu::MSR_GS_BASE, t.gs_base) };
        (&t.ctx as *const UCtx, t.pml4, t.kstack_top)
    };
    syscall::set_kstack(kst);
    unsafe { syscall::sched_iret(ctx, pml4) }
}

/// The running task exited: mark it Exited, orphan its children
/// (ppid=0 -> their zombies reap immediately), and wake a parent
/// blocked in wait4 on it — the child's status goes into the
/// parent's user buffer via physical translation, the pid into its
/// rax. Then switch to the next Runnable task, or unwind to the
/// kernel context sched_launch saved when the queue is empty.
pub fn task_exit(code: u64) -> ! {
    let cur = unsafe { *core::ptr::addr_of!(CUR_I) };
    if let Some(t) = unsafe { (*core::ptr::addr_of_mut!(TASKS))[cur].as_mut() } {
        if t.pers == PERS_NT {
            // Record the RAW status before waitstatus-encoding.
            // nt_thread_dead covers secondary threads and any
            // CreateProcess'd leader (it has a ledger entry too);
            // nt_proc_dead signals the process object when the
            // group's last thread is gone.
            nt_thread_dead(t.pid, code & 0xffff_ffff);
            nt_proc_dead(t.tgid, t.pid, code & 0xffff_ffff);
        }
        t.exit_status = (code & 0xff) << 8;
    }
    task_exit_inner()
}

/// The running task died to a signal: same teardown as exit, but the
/// wait status is the bare signo in the low byte — real wstatus.
/// Map a fatal signal number to the nearest NTSTATUS exception
/// code, like a Windows crash exit status.
fn nt_sig_ntstatus(signo: u64) -> u64 {
    match signo {
        11 => 0xC000_0005, // SIGSEGV -> ACCESS_VIOLATION
        4 => 0xC000_001D,  // SIGILL  -> ILLEGAL_INSTRUCTION
        8 => 0xC000_0094,  // SIGFPE  -> INTEGER_DIVIDE_BY_ZERO
        5 => 0x8000_0003,  // SIGTRAP -> BREAKPOINT
        _ => 0xC000_0000 | signo,
    }
}

fn die_signal(signo: u64) -> ! {
    let cur = unsafe { *core::ptr::addr_of!(CUR_I) };
    crate::log::printk(format_args!(
        "rustux: user: pid {} {} sig-death({signo})",
        getpid(),
        cur_exe()
    ));
    if let Some(t) = unsafe { (*core::ptr::addr_of_mut!(TASKS))[cur].as_mut() } {
        if t.pers == PERS_NT {
            // Crashed NT task: waiters on its thread/process objects
            // must still wake.
            let code = nt_sig_ntstatus(signo);
            nt_thread_dead(t.pid, code);
            nt_proc_dead(t.tgid, t.pid, code);
        }
        t.exit_status = signo;
    }
    task_exit_inner()
}

/// Shared exit/signal-death teardown: mark Exited, wake a matching
/// wait4 parent (status + pid), SIGCHLD the parent if it lives,
/// orphan children, then switch away or unwind.
/// The exit bookkeeping for task index n — fd/sighand/fstab
/// release, ctid wake, parent wait4 wake + SIGCHLD, child
/// orphaning. task_exit_inner runs it for cur; deliver_for runs it
/// when a pick-time signal delivery kills a runnable task — a
/// signal death at pick would otherwise skip the whole zombie/wake
/// side and strand a wait4-blocked parent forever.
fn exit_bookkeeping(n: usize) {
    let tasks = unsafe { &mut *core::ptr::addr_of_mut!(TASKS) };
    let Some(t) = tasks.get_mut(n).and_then(|s| s.as_mut()) else {
        return;
    };
    t.state = TaskState::Exited;
    let (cpid, cppid, wstatus, is_thread, cpgid, ctgid) =
        (t.pid, t.ppid, t.exit_status, t.tgid != t.pid, t.pgid, t.tgid);
    // exit_files(2): the dying task's fds release NOW, not at reap —
    // a pipe writer's OFD must hit refs=0 here so blocked readers
    // see EOF instead of waiting for the scheduler's reaper pass.
    // Scoped before the parent-wake loop: ofd_release can wake other
    // tasks (pipe_end_closed -> wake_pipe_waiters walks TASKS).
    {
        let t = tasks.get_mut(n).and_then(|s| s.as_mut()).unwrap();
        t.release_fds();
        t.release_sighand();
        t.release_fstab();
    }
    // CHILD_CLEARTID: zero *ctid through the dying task's tables and
    // futex-wake whoever sleeps on it — this is exactly pthread_join's
    // wait (glibc futex-waits on the child's tid word).
    let (ctva, tpml4) = tasks
        .get_mut(n)
        .and_then(|s| s.as_mut())
        .map(|t| (t.clear_ctid, t.pml4))
        .unwrap_or((0, 0));
    if ctva != 0 {
        write_task_bytes(tpml4, ctva, &0u32.to_ne_bytes());
        futex_wake(tpml4, ctva, 1);
    }
    // A non-leader thread is invisible to wait4 and raises no
    // SIGCHLD — pthread_join already got its ctid wake above. Mark
    // the sweep and skip the parent bookkeeping entirely.
    if is_thread {
        unsafe { *core::ptr::addr_of_mut!(DEAD_THREADS) = true };
        for s in tasks.iter_mut() {
            if let Some(t) = s.as_mut() {
                if t.ppid == cpid && t.state != TaskState::Exited {
                    t.ppid = 0;
                }
            }
        }
        if let Some(t) = tasks.get_mut(n).and_then(|s| s.as_mut()) {
            t.ppid = 0; // never a waitable zombie
        }
        // A non-leader thread can outlive a zombie leader — when it
        // is the group's last, no leader-path sweep will ever run,
        // so the dead leader's nth table would pin its NT ledger
        // objects forever. Sweep here under the same last-standing
        // condition the leader path uses.
        if !tasks.iter().flatten().any(|t| {
            t.pid != cpid && t.tgid == ctgid && t.state != TaskState::Exited
        }) {
            nt_handle_sweep(tasks, ctgid);
        }
        return;
    }
    // NT module ledger: a dead leader's entries are inert — its
    // detaches already ran in the ExitProcess drain, or never will
    // on a forced kill. Free the slots now unless a same-tgid thread
    // still runs; a zombie must not hold the 8-slot table hostage
    // until some reaper pass gets scheduled.
    if !tasks.iter().flatten().any(|t| {
        t.pid != cpid && t.tgid == cpid && t.state != TaskState::Exited
    }) {
        let tab = unsafe { &mut *core::ptr::addr_of_mut!(NT_MODS) };
        for e in tab.iter_mut() {
            if e.0 == cpid {
                *e = (0, 0, 0, 0, 0, 0, [0; 32], 0, 0);
            }
        }
        // Same last-standing condition: the leader's nth handle
        // table is released with the process — refs it held on
        // thread/process/section ledger objects refdown now or the
        // global ledgers leak a slot per dead handle.
        nt_handle_sweep(tasks, cpid);
    }
    // Wake a wait-blocked parent whose target just exited.
    let mut collected = false;
    for s in tasks.iter_mut() {
        let Some(p) = s else { continue };
        if p.state == TaskState::Blocked
            && p.pid == cppid
            && (p.wait_on == WaitOn::Any
                || p.wait_on == WaitOn::Child(cpid)
                || p.wait_on == WaitOn::Group(cpgid)
                || p.wait_on == WaitOn::Vfork(cpid))
        {
            // wait4 returns the child's pid; its status was already
            // validated writable when the parent blocked.
            p.ctx.rax = cpid;
            if p.wait_ptr != 0 {
                if let Some(pa) = translate(p.pml4, p.wait_ptr) {
                    // SAFETY: pa is a translated, present user frame.
                    unsafe {
                        ((pa) as *mut u32)
                            .write_unaligned((wstatus & 0xffff) as u32)
                    };
                }
            }
            // A Vfork wake only resumes the suspended parent — it
            // collected no status, so the zombie stays waitable for
            // the parent's own wait4. wait4 wakes mark the zombie
            // collected so a second wait can't see it twice.
            collected = p.wait_on != WaitOn::Vfork(cpid);
            p.state = TaskState::Runnable;
            p.wait_on = WaitOn::None;
            p.wait_ptr = 0;
        }
    }
    // The parent collected the status — this zombie reaps free.
    if collected {
        if let Some(t) = tasks.get_mut(n).and_then(|x| x.as_mut()) {
            t.ppid = 0;
        }
    }
    // Orphan n's children — no one can wait on them now.
    for s in tasks.iter_mut() {
        if let Some(t) = s.as_mut() {
            if t.ppid == cpid && t.state != TaskState::Exited {
                t.ppid = 0;
            }
        }
    }
    // SIGCHLD to the parent — pend_one gives a caught disposition
    // the same EINTR wake kill() gets, so a handler can break a
    // parent blocked in a non-wait4 syscall. Default disposition
    // ignores it; a handler sees it on the parent's next resume.
    if cppid != 0 {
        if let Some(p) = tasks.iter_mut().flatten().find(|t| t.pid == cppid) {
            let (code, st) = cld_code(wstatus);
            pend_one(
                p,
                SIGCHLD as u64,
                SigSrc {
                    code,
                    pid: cpid as u32,
                    uid: 0,
                    aux: st as u64,
                },
            );
        }
    }
}

/// Map a child wstatus to (CLD_* si_code, si_status): a low byte of
/// 0 is a clean exit (status in the high byte), a core-dump bit in
/// the low byte is CLD_DUMPED, otherwise the low byte is the killing
/// signal (CLD_KILLED).
fn cld_code(wstatus: u64) -> (i32, i32) {
    let lo = wstatus & 0x7f;
    if lo == 0 {
        (CLD_EXITED, ((wstatus >> 8) & 0xff) as i32)
    } else if wstatus & 0x80 != 0 {
        (CLD_DUMPED, lo as i32)
    } else {
        (CLD_KILLED, lo as i32)
    }
}

fn task_exit_inner() -> ! {
    let cur = unsafe { *core::ptr::addr_of!(CUR_I) };
    {
        let tasks = unsafe { &mut *core::ptr::addr_of_mut!(TASKS) };
        if let Some(t) = tasks.get_mut(cur).and_then(|s| s.as_mut()) {
            t.state = TaskState::Exited;
        }
    }
    exit_bookkeeping(cur);
    if let Some(n) = pick_ready() {
        switch_to(n)
    }
    {
        let tasks = unsafe { &*core::ptr::addr_of!(TASKS) };
        if run_over(tasks) {
            syscall::terminate()
        }
    }
    // Stopped/Blocked tasks remain that a serviced wake or a signal
    // can still revive — "no runnable" is not "run over".
    block_switch()
}

/// End-of-run predicate: every task has Exited, or the survivors can
/// never run again without console input — a getty-style shell parked
/// in read(0) can't be woken by anything inside a scripted run, so it
/// must not hold the suite open. Timer/pipe/Stopped states still idle
/// (a serviced deadline, an OFD wake, or a SIGCONT can revive them).
fn run_over(tasks: &[Option<Task>]) -> bool {
    tasks.iter().flatten().all(|t| {
        t.state == TaskState::Exited
            || (t.state == TaskState::Blocked
                && matches!(
                    t.wait_on,
                    WaitOn::Stdin | WaitOn::Poll | WaitOn::Pselect | WaitOn::Epoll(_)
                ))
    })
}

/// The running task blocked in wait4: its syscall ctx is already
/// stored in `ctx`. Switch to any Runnable task; if none exists,
/// idle on hlt until a tick re-arms the pick loop.
fn block_switch() -> ! {
    loop {
        if let Some(n) = pick_ready() {
            switch_to(n)
        }
        // Nothing runnable — sleep one tick. A child exiting or any
        // wake makes the next pick find a Runnable task.
        // SAFETY: halts with interrupts enabled, masks again after.
        unsafe { core::arch::asm!("sti", "hlt", "cli", options(nostack)) };
    }
}

/// Resume task n from the IRQ path: set kstack + cr3 and return its
/// ctx for the dispatch stub to pop+iret.
fn resume_ctx(n: usize) -> *const UCtx {
    CTXT_SW.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    unsafe { *core::ptr::addr_of_mut!(CUR_I) = n };
    let t = unsafe { (*core::ptr::addr_of_mut!(TASKS))[n].as_mut().unwrap() };
    syscall::set_kstack(t.kstack_top);
    // Switch address space before returning the new task's ctx —
    // shared kernel slots make the swap safe mid-function.
    // SAFETY: pml4 is a live task-owned PML4.
    unsafe { core::arch::asm!("mov cr3, {}", in(reg) t.pml4) };
    // The tick saved the outgoing task's live FPU state before the
    // pick — restore the incoming task's image or it resumes with
    // the previous task's xmm registers. switch_to/launch do the
    // same; this path was missing it.
    fxrstor(&t.fx);
    // SAFETY: MSR write of a task-owned user FS base — TLS follows
    // the task across switches, same as launch/switch_to.
    unsafe { cpu::wrmsr(cpu::MSR_FS_BASE, t.fs_base) };
    unsafe { cpu::wrmsr(cpu::MSR_GS_BASE, t.gs_base) };
    &t.ctx
}

/// Timer IRQ — called from the sched dispatch stub with the full
/// context image it pushed. A kernel frame (cs&3==0 — mid-syscall,
/// where IF is masked anyway, or any kernel context) just ticks.
/// A CPL3 frame is a preemptible task: snapshot its ctx, deliver
/// pending signals (a default-fatal one kills it here), round-robin
/// with delivery at the pick, and return the ctx to resume.
pub fn tick(img: &mut UCtx) -> *const UCtx {
    // Service deferred wake sources on EVERY tick — including the
    // kernel-CS frames the hlt-idle loops take, where skipping them
    // would freeze every Blocked task's deadline and input feed.
    poll_expire(); // timed poll waits age one tick
    timerfd_expire(); // armed timerfds fire + wake their readers
    nt_wait_expire(); // NT thread-object waits: dead/timeout wakes
    crate::e1000::rx_drain(); // feed socket queues from the live ring
    stdin_pump(); // feed the tty input queue from the scancode ring
    let cur = unsafe { *core::ptr::addr_of!(CUR_I) };
    // Bill the tick: a kernel-CS frame means the task was inside a
    // syscall when the timer hit (stime); a CPL3 frame is user time.
    // This is the accounting /proc/<pid>/stat and /proc/stat print.
    if img.cs & 3 != 3 {
        if cur != usize::MAX {
            if let Some(t) =
                unsafe { (*core::ptr::addr_of_mut!(TASKS))[cur].as_mut() }
            {
                t.stime += 1;
            }
        }
        return img;
    }
    if cur == usize::MAX {
        return img;
    }
    // Snapshot the preempted task for a later resume -- GPRs into
    // ctx, the live FPU/SSE registers into its fx buffer.
    if let Some(t) = unsafe { (*core::ptr::addr_of_mut!(TASKS))[cur].as_mut() } {
        t.utime += 1;
        t.ctx = *img;
        fxsave(t);
    }
    deliver_for(cur);
    let Some(n) = pick_ready() else {
        // Nothing else runnable: if cur survived delivery it's the
        // only task — resume its (possibly redirected) ctx. The run
        // is over only when every task has Exited; Stopped/Blocked
        // tasks can still be revived (SIGCONT, a serviced deadline,
        // fed input), so idle on hlt until one is runnable again.
        let tasks = unsafe { &*core::ptr::addr_of!(TASKS) };
        match tasks[cur].as_ref() {
            Some(t) if t.state == TaskState::Runnable => return &t.ctx,
            _ => {
                if run_over(tasks) {
                    syscall::terminate()
                }
                loop {
                    // SAFETY: halts with interrupts enabled, masks
                    // again after — same idiom as block_switch.
                    unsafe { core::arch::asm!("sti", "hlt", "cli", options(nostack)) };
                    if let Some(n) = pick_ready() {
                        return resume_ctx(n);
                    }
                }
            }
        }
    };
    if n == cur {
        let tasks = unsafe { &*core::ptr::addr_of!(TASKS) };
        return &tasks[cur].as_ref().unwrap().ctx;
    }
    resume_ctx(n)
}

/// Translate a user VA to its identity-mapped physical address under
/// `pml4` — used to write into another task's address space while a
/// different task's tables are active (wait4 status, pipe io, signal
/// frames). Requires the leaf's WRITE bit: every caller writes, and
/// a read-only page must not be modified through this path.
/// Walk `va` to its PA for a WRITABLE user page. Every caller is a
/// task-user-memory access, so the bound is applied here: the task's
/// pml4 shares kernel upper-half slots by reference, and a kernel VA
/// here would otherwise translate fine — a user-controlled pointer
/// (clone's ctid, a sigframe rsp, an argv walker) must never reach
/// kernel memory through this path.
fn translate(pml4: u64, va: u64) -> Option<u64> {
    if !(elf::USER_VA_LO..elf::USER_VA_HI).contains(&va) {
        return None;
    }
    let mut tab = pml4;
    for shift in [39u64, 30, 21] {
        let e = rd64(tab + 8 * ((va >> shift) & 0x1ff));
        if e & PRESENT == 0 || e & (1 << 7) != 0 {
            return None;
        }
        tab = e & PHYS_MASK;
    }
    let e = rd64(tab + 8 * ((va >> 12) & 0x1ff));
    if e & PRESENT == 0 || e & WRITE == 0 {
        return None;
    }
    Some((e & PHYS_MASK) | (va & 0xfff))
}

/// Read-side translate: same walk without the WRITE leaf gate —
/// for kernel reads of user memory (a read-only page is a legal
/// read source even though no write path may touch it). Bounded to
/// the user window for the same kernel-half reason as translate().
pub fn translate_r(pml4: u64, va: u64) -> Option<u64> {
    if !(elf::USER_VA_LO..elf::USER_VA_HI).contains(&va) {
        return None;
    }
    let mut tab = pml4;
    for shift in [39u64, 30, 21] {
        let e = rd64(tab + 8 * ((va >> shift) & 0x1ff));
        if e & PRESENT == 0 || e & (1 << 7) != 0 {
            return None;
        }
        tab = e & PHYS_MASK;
    }
    let e = rd64(tab + 8 * ((va >> 12) & 0x1ff));
    if e & PRESENT == 0 {
        return None;
    }
    Some((e & PHYS_MASK) | (va & 0xfff))
}

/// Deep-copy `ppml4`'s user half (slots 128-255) into `c`'s address
/// space, frame for frame — eager fork semantics (no COW yet; the
/// honest copy is correct and the refcount machinery isn't worth it
/// at this scale). Kernel slots are shared by reference like every
/// load. Returns false on allocation failure — caller reaps `c`.
fn fork_address_space(c: &mut Task, ppml4: u64) -> bool {
    for i in 0..128u64 {
        let e = rd64(ppml4 + 8 * i);
        if e & PRESENT != 0 {
            wr64(c.pml4 + 8 * i, e);
        }
    }
    for i in 128..256u64 {
        let e = rd64(ppml4 + 8 * i);
        if e & PRESENT == 0 {
            continue;
        }
        let Some(cpdpt) = kalloc::alloc_frame() else { return false };
        wr64(c.pml4 + 8 * i, cpdpt | PRESENT | WRITE | USER);
        let pdpt = e & PHYS_MASK;
        for j in 0..512usize {
            let pe = rd64(pdpt + 8 * j as u64);
            if pe & PRESENT == 0 {
                continue;
            }
            if pe & (1 << 7) != 0 {
                return false; // 1G page — never created for user space
            }
            let Some(cpd) = kalloc::alloc_frame() else { return false };
            wr64(cpdpt + 8 * j as u64, cpd | PRESENT | WRITE | USER);
            let pd = pe & PHYS_MASK;
            for k in 0..512usize {
                let te = rd64(pd + 8 * k as u64);
                if te & PRESENT == 0 {
                    continue;
                }
                if te & (1 << 7) != 0 {
                    return false; // 2M page — never created
                }
                let Some(cpt) = kalloc::alloc_frame() else { return false };
                wr64(cpd + 8 * k as u64, cpt | PRESENT | WRITE | USER);
                let pt = te & PHYS_MASK;
                for l in 0..512usize {
                    let le = rd64(pt + 8 * l as u64);
                    if le & PRESENT == 0 {
                        continue;
                    }
                    let Some(nf) = kalloc::alloc_frame() else { return false };
                    // SAFETY: both frames are owned, identity-mapped,
                    // full 4 KiB each — a verbatim copy.
                    unsafe {
                        (nf as *mut u8)
                            .copy_from((le & PHYS_MASK) as *const u8, 4096)
                    };
                    // Leaf flags verbatim — USER/RW/NX preserved.
                    wr64(cpt + 8 * l as u64, nf | (le & !PHYS_MASK));
                }
            }
        }
    }
    true
}

/// fork(): a new task that is a copy of the running one — deep
/// address-space copy, copied fd table pointing at the SAME global
/// OFDs (shared offsets — the Linux semantic), and a ctx equal to
/// the parent's except rax=0. Parent's rax gets the child pid.
pub fn fork(ctx: &mut UCtx, files: bool, fs: bool) -> u64 {
    const EAGAIN: u64 = (-11i64) as u64;
    const ENOMEM: u64 = (-12i64) as u64;
    reap_dead_threads(); // reclaim dead-thread slots first
    let cur = unsafe { *core::ptr::addr_of!(CUR_I) };
    let tasks = unsafe { &mut *core::ptr::addr_of_mut!(TASKS) };
    let Some(slot) = tasks.iter().position(Option::is_none) else {
        return EAGAIN;
    };
    let Some(p) = tasks.get_mut(cur).and_then(|s| s.as_mut()) else {
        return EAGAIN;
    };
    // CLONE_FILES shares the parent's table (users++); otherwise a
    // private copy with each named OFD ref bumped (fdtab_dup).
    // Dispositions always copy at fork (SIGHAND needs VM).
    let Some(csigh) = sigtab_dup(p.sigh) else {
        return ENOMEM;
    };
    let cfdi = if files {
        fdtab_share(p.fdi);
        p.fdi
    } else {
        match fdtab_dup(p.fdi) {
            Some(i) => i,
            None => {
                sigtab_release(csigh);
                return ENOMEM;
            }
        }
    };
    let cfsi = if fs {
        fstab_share(p.fsi);
        p.fsi
    } else {
        match fstab_dup(p.fsi) {
            Some(i) => i,
            None => {
                fdtab_release(cfdi);
                sigtab_release(csigh);
                return ENOMEM;
            }
        }
    };
    let mut c = Task {
        pml4: match kalloc::alloc_frame() {
            Some(f) => f,
            None => {
                fstab_release(cfsi);
                fdtab_release(cfdi);
                sigtab_release(csigh);
                return ENOMEM;
            }
        },
        entry: p.entry,
        stack_top: p.stack_top,
        kstack_base: 0,
        kstack_top: 0,
        ranges: p.ranges,
        nranges: p.nranges,
        brk_base: p.brk_base,
        brk_cur: p.brk_cur,
        fdi: cfdi,
        sigh: csigh,
        fsi: cfsi,
        tgid: 0, // set to cpid below once known
        ctx: {
            let mut x = *ctx;
            x.rax = 0; // child sees fork()==0
            x
        },
        state: TaskState::Runnable,
        pid: next_pid(),
        ppid: p.pid,
        exit_status: 0,
        wait_on: WaitOn::None,
        wait_ptr: 0,
        wait_ptr2: 0,
        wait_ptr3: 0,
        psel_mask: u64::MAX,
        frame_mask: u64::MAX,
        wait_len: 0,
        wait_deadline: 0,
        // Dispositions inherit across fork (the Linux semantic);
        // the pending set does not.
        pending: 0,
        pend_src: [SIGSRC_NONE; 31],
        sigmask: p.sigmask,
        fx: p.fx,
        name: p.name,
        exe: p.exe,
        exe_len: p.exe_len,
        fs_base: p.fs_base,
        rseq_va: 0,
        clear_ctid: 0,
        pgid: p.pgid,
        sid: p.sid,
        did_exec: false, // fork resets the child-exec'd flag
        pers: p.pers,
        gs_base: p.gs_base,
        nth: p.nth,
        nth_fd: p.nth_fd,
        nth_dirpat: p.nth_dirpat,
        heap_blk: p.heap_blk,
        heap_bump: p.heap_bump,
        heap_commit: p.heap_commit,
        nt_alloc: p.nt_alloc,
        tls_tmpl_va: p.tls_tmpl_va,
        tls_tmpl_sz: p.tls_tmpl_sz,
        thr_exit_va: p.thr_exit_va,
        thr_entry_va: p.thr_entry_va,
        nt_stub: p.nt_stub,
        stop_sig: 0,
        cont_report: false,
        start_ticks: crate::apic::TICKS
            .load(core::sync::atomic::Ordering::Relaxed),
        utime: 0,
        stime: 0,
        cmdline: p.cmdline,
        cmdline_len: p.cmdline_len,
    };
    // Either failure frees the (possibly partial) user page-table
    // tree + pml4 — NOT reap(): child's fd slots name OFDs whose refs
    // were never bumped, so release_fds would corrupt the count.
    if !fork_address_space(&mut c, p.pml4) {
        c.free_user_mappings();
        kalloc::free_frame(c.pml4);
        fstab_release(cfsi);
        fdtab_release(cfdi);
        sigtab_release(csigh);
        return ENOMEM;
    }
    let ks = kalloc::kmalloc(KSTACK_SIZE) as u64;
    if ks == 0 {
        c.free_user_mappings();
        kalloc::free_frame(c.pml4);
        fstab_release(cfsi);
        fdtab_release(cfdi);
        sigtab_release(csigh);
        return ENOMEM;
    }
    c.kstack_base = ks;
    c.kstack_top = ks + KSTACK_SIZE as u64;
    c.tgid = c.pid; // a fork child leads its own group
    let cpid = c.pid;
    tasks[slot] = Some(c);
    PROCS_CREATED.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    cpid
}

/// clone(CLONE_VM): a task that shares the parent's address space —
/// same pml4 (mm_users bookkeeping in MM_REFS), same mappings, its
/// own kernel stack, its own user rsp on the caller-supplied stack,
/// and SETTLS wiring when asked. The task is still a distinct
/// process for wait4 (no CLONE_THREAD group semantics yet).
#[allow(clippy::too_many_arguments)]
fn clone_vm(ctx: &mut UCtx, stack: u64, tls: u64, settls: bool, files: bool, sighand: bool, thread: bool, fs: bool) -> u64 {
    const EAGAIN: u64 = (-11i64) as u64;
    const ENOMEM: u64 = (-12i64) as u64;
    reap_dead_threads(); // reclaim dead-thread slots first
    let cur = unsafe { *core::ptr::addr_of!(CUR_I) };
    let tasks = unsafe { &mut *core::ptr::addr_of_mut!(TASKS) };
    let Some(slot) = tasks.iter().position(Option::is_none) else {
        return EAGAIN;
    };
    let Some(p) = tasks.get_mut(cur).and_then(|s| s.as_mut()) else {
        return EAGAIN;
    };
    let ks = kalloc::kmalloc(KSTACK_SIZE) as u64;
    if ks == 0 {
        return ENOMEM;
    }
    if !mm_share(p.pml4) {
        // SAFETY: ks was kmalloc'd above; freed once here.
        unsafe { kalloc::kfree(ks as *mut u8) };
        return ENOMEM;
    }
    // Same table rule as fork — FILES shares, else a bumped copy.
    // SIGHAND shares the disposition table; else a private copy.
    let csigh = if sighand {
        sigtab_share(p.sigh);
        p.sigh
    } else {
        match sigtab_dup(p.sigh) {
            Some(i) => i,
            None => {
                mm_release(p.pml4);
                unsafe { kalloc::kfree(ks as *mut u8) };
                return ENOMEM;
            }
        }
    };
    let cfdi = if files {
        fdtab_share(p.fdi);
        p.fdi
    } else {
        match fdtab_dup(p.fdi) {
            Some(i) => i,
            None => {
                // mm_share's +1 must go back — the child never ran.
                sigtab_release(csigh);
                mm_release(p.pml4);
                unsafe { kalloc::kfree(ks as *mut u8) };
                return ENOMEM;
            }
        }
    };
    let cfsi = if fs {
        fstab_share(p.fsi);
        p.fsi
    } else {
        match fstab_dup(p.fsi) {
            Some(i) => i,
            None => {
                fdtab_release(cfdi);
                sigtab_release(csigh);
                mm_release(p.pml4);
                unsafe { kalloc::kfree(ks as *mut u8) };
                return ENOMEM;
            }
        }
    };
    let mut c = Task {
        pml4: p.pml4, // SHARED — freed by the last mm user at reap
        entry: p.entry,
        stack_top: p.stack_top,
        kstack_base: ks,
        kstack_top: ks + KSTACK_SIZE as u64,
        // Per-task range ledger copy: a sibling's later mmap won't
        // appear in this table (syscall-side validation divergence —
        // the page tables themselves stay shared).
        ranges: p.ranges,
        nranges: p.nranges,
        brk_base: p.brk_base,
        brk_cur: p.brk_cur,
        fdi: cfdi,
        sigh: csigh,
        fsi: cfsi,
        // A CLONE_THREAD member reports the leader's group id and
        // shares the leader's parent; a VM-only clone is its own
        // process — wait4-visible, tgid = own pid.
        tgid: if thread { p.tgid } else { 0 },
        ctx: {
            let mut x = *ctx;
            x.rax = 0; // child sees clone()==0
            x.rsp = stack; // caller-made thread stack, same mm
            x
        },
        state: TaskState::Runnable,
        pid: next_pid(),
        ppid: if thread { p.ppid } else { p.pid },
        exit_status: 0,
        wait_on: WaitOn::None,
        wait_ptr: 0,
        wait_ptr2: 0,
        wait_ptr3: 0,
        psel_mask: u64::MAX,
        frame_mask: u64::MAX,
        wait_len: 0,
        wait_deadline: 0,
        pending: 0,
        pend_src: [SIGSRC_NONE; 31],
        sigmask: p.sigmask,
        fx: p.fx,
        name: p.name,
        exe: p.exe,
        exe_len: p.exe_len,
        fs_base: if settls { tls } else { p.fs_base },
        rseq_va: 0,
        clear_ctid: 0,
        pgid: p.pgid,
        sid: p.sid,
        did_exec: false,
        pers: p.pers,
        gs_base: p.gs_base,
        nth: p.nth,
        nth_fd: p.nth_fd,
        nth_dirpat: p.nth_dirpat,
        heap_blk: p.heap_blk,
        heap_bump: p.heap_bump,
        heap_commit: p.heap_commit,
        nt_alloc: p.nt_alloc,
        tls_tmpl_va: p.tls_tmpl_va,
        tls_tmpl_sz: p.tls_tmpl_sz,
        thr_exit_va: p.thr_exit_va,
        thr_entry_va: p.thr_entry_va,
        nt_stub: p.nt_stub,
        stop_sig: 0,
        cont_report: false,
        start_ticks: crate::apic::TICKS
            .load(core::sync::atomic::Ordering::Relaxed),
        utime: 0,
        stime: 0,
        cmdline: p.cmdline,
        cmdline_len: p.cmdline_len,
    };
    if c.tgid == 0 {
        c.tgid = c.pid; // a non-THREAD clone leads its own group
    }
    let cpid = c.pid;
    tasks[slot] = Some(c);
    PROCS_CREATED.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    cpid
}

/// wait4(pid, status_va, flags): collect a child's status. pid=-1
/// waits for any child; pid>0 that child; pid==0 any child in the
/// caller's own process group; pid<-1 any child in group -pid.
/// WNOHANG returns 0 when nothing is reportable; WUNTRACED also
/// reports stopped children ((stopsig << 8) | 0x7f), WCONTINUED
/// continued ones (0xffff). Blocks when matching children are
/// still running; ECHILD when there are none to wait for.
pub fn wait4(ctx: &mut UCtx, pid: i64, status_va: u64, flags: u64) -> u64 {
    const ECHILD: u64 = (-10i64) as u64;
    const EFAULT_: u64 = (-14i64) as u64;
    // __WNOTHREAD/__WALL are no-ops in the single-thread-group
    // model — accept them silently; anything else is EINVAL.
    if flags & !(WNOHANG | WUNTRACED | WCONTINUED | 0x20000000 | 0x40000000) != 0 {
        return EINVAL;
    }
    let cur = unsafe { *core::ptr::addr_of!(CUR_I) };
    let (cpid, mypgid) = unsafe {
        (*core::ptr::addr_of!(TASKS))[cur]
            .as_ref()
            .map(|t| (t.pid, t.pgid))
            .unwrap_or((0, 0))
    };
    let tasks = unsafe { &mut *core::ptr::addr_of_mut!(TASKS) };
    let relevant = |t: &Task| {
        t.ppid == cpid
            && (pid == -1
                || (pid > 0 && t.pid == pid as u64)
                || (pid == 0 && t.pgid == mypgid)
                || (pid < -1 && t.pgid == (-pid) as u64))
    };
    // A collectable zombie first — write status and free it for reap.
    if let Some(i) = tasks.iter().position(|s| {
        s.as_ref().is_some_and(|t| relevant(t) && t.state == TaskState::Exited)
    }) {
        let t = tasks[i].as_mut().unwrap();
        if status_va != 0 {
            if !range_ok_w(status_va, 4) {
                return EFAULT_;
            }
            // SAFETY: validated writable user range in cur's space.
            unsafe {
                (status_va as *mut u32)
                    .write_unaligned((t.exit_status & 0xffff) as u32)
            };
        }
        let r = t.pid;
        // Collected — reap now (Linux releases the task at wait):
        // the child's fds/map/pml4 free immediately, so shared
        // endpoint counts (pipe writers/readers) drop before we
        // return — a poll right after wait4 sees the child gone.
        t.reap();
        tasks[i] = None;
        return r;
    }
    // WUNTRACED: an unreported stopped child → (stopsig << 8) | 0x7f.
    // stop_sig clears at report — one notification per stop.
    if flags & WUNTRACED != 0 {
        if let Some(t) = tasks
            .iter_mut()
            .flatten()
            .find(|t| relevant(t) && t.state == TaskState::Stopped && t.stop_sig != 0)
        {
            if status_va != 0 {
                if !range_ok_w(status_va, 4) {
                    return EFAULT_;
                }
                // SAFETY: validated writable user dword in cur's map.
                unsafe {
                    (status_va as *mut u32).write_unaligned(((t.stop_sig as u32) << 8) | 0x7f)
                };
            }
            let r = t.pid;
            t.stop_sig = 0;
            return r;
        }
    }
    // WCONTINUED: a child resumed by SIGCONT → 0xffff, once per
    // continue (cont_report clears at report).
    if flags & WCONTINUED != 0 {
        if let Some(t) = tasks
            .iter_mut()
            .flatten()
            .find(|t| relevant(t) && t.cont_report)
        {
            if status_va != 0 {
                if !range_ok_w(status_va, 4) {
                    return EFAULT_;
                }
                // SAFETY: validated writable user dword in cur's map.
                unsafe { (status_va as *mut u32).write_unaligned(0xffff) };
            }
            let r = t.pid;
            t.cont_report = false;
            return r;
        }
    }
    if !tasks.iter().flatten().any(relevant) {
        return ECHILD;
    }
    if flags & WNOHANG != 0 {
        return 0; // children alive, nothing reportable yet
    }
    // Live children — validate the status target BEFORE blocking,
    // then sleep. wait_len carries the option flags so a stop/
    // continue notification knows which event class to report.
    if status_va != 0 && !range_ok_w(status_va, 4) {
        return EFAULT_;
    }
    {
        let t = tasks[cur].as_mut().unwrap();
        if deliverable(t) {
            return (-4i64) as u64; // -EINTR: signal before sleep
        }
        t.wait_on = if pid == -1 {
            WaitOn::Any
        } else if pid > 0 {
            WaitOn::Child(pid as u64)
        } else {
            WaitOn::Group(if pid == 0 { mypgid } else { (-pid) as u64 })
        };
        t.wait_ptr = status_va;
        t.wait_len = flags;
        t.ctx = *ctx;
        t.state = TaskState::Blocked;
    }
    block_switch()
}

/// getpid() -> current task's pid.
pub fn getpid() -> u64 {
    cur_mut().map(|t| t.tgid).unwrap_or(0)
}

/// getppid() -> current task's parent pid (0 for spawned roots).
pub fn getppid() -> u64 {
    cur_mut().map(|t| t.ppid).unwrap_or(0)
}

/// getpgrp() -> the caller's own process-group id.
pub fn sys_getpgrp() -> u64 {
    cur_mut().map(|t| t.pgid).unwrap_or(0)
}

/// getpgid(pid) -> pid's process-group id (pid 0 = self); ESRCH
/// when no such task exists.
pub fn sys_getpgid(pid: u64) -> u64 {
    const ESRCH: u64 = (-3i64) as u64;
    let tasks = unsafe { &mut *core::ptr::addr_of_mut!(TASKS) };
    if pid == 0 {
        return cur_mut().map(|t| t.pgid).unwrap_or(ESRCH);
    }
    tasks
        .iter()
        .flatten()
        .find(|t| t.pid == pid)
        .map(|t| t.pgid)
        .unwrap_or(ESRCH)
}

/// getsid(pid) -> pid's session id (pid 0 = self); ESRCH when no
/// such task exists.
pub fn sys_getsid(pid: u64) -> u64 {
    const ESRCH: u64 = (-3i64) as u64;
    let tasks = unsafe { &mut *core::ptr::addr_of_mut!(TASKS) };
    if pid == 0 {
        return cur_mut().map(|t| t.sid).unwrap_or(ESRCH);
    }
    tasks
        .iter()
        .flatten()
        .find(|t| t.pid == pid)
        .map(|t| t.sid)
        .unwrap_or(ESRCH)
}

/// setsid(): become session leader of a new session — fails EPERM
/// when the caller already leads its own process group (a group
/// leader can never setsid, like Linux).
pub fn sys_setsid() -> u64 {
    const EPERM_: u64 = (-1i64) as u64;
    let Some(t) = cur_mut() else {
        return EINVAL;
    };
    if t.pgid == t.pid {
        return EPERM_;
    }
    t.sid = t.pid;
    t.pgid = t.pid;
    // Losing the ctty is implicit: the console's owner session no
    // longer matches, so tcgetpgrp/read gates stop applying.
    t.pid
}

/// setpgid(pid, pgid): move a task into a process group within its
/// own session. pid 0 = self; pgid 0 = make target its own group.
/// Linux's rules: only self or an own child, same session, target
/// can't be a session leader, a child that already exec'd is EACCES,
/// and a pre-existing group must live in the target's session.
pub fn sys_setpgid(pid: u64, pgid: u64) -> u64 {
    const EPERM_: u64 = (-1i64) as u64;
    const ESRCH: u64 = (-3i64) as u64;
    const EACCES_: u64 = (-13i64) as u64;
    if pid > i32::MAX as u64 || pgid > i32::MAX as u64 {
        return EINVAL;
    }
    let Some(me) = cur_mut() else {
        return EINVAL;
    };
    let (my_pid, my_sid) = (me.pid, me.sid);
    let target_pid = if pid == 0 { my_pid } else { pid };
    let new_pgid = if pgid == 0 { target_pid } else { pgid };
    let tasks = unsafe { &mut *core::ptr::addr_of_mut!(TASKS) };
    let Some(i) = tasks
        .iter()
        .position(|s| s.as_ref().is_some_and(|t| t.pid == target_pid))
    else {
        return ESRCH;
    };
    let (t_ppid, t_sid, t_exec) = {
        let t = tasks[i].as_ref().unwrap();
        (t.ppid, t.sid, t.did_exec)
    };
    if target_pid != my_pid && t_ppid != my_pid {
        return ESRCH; // only self or an own child
    }
    if t_sid == target_pid {
        return EPERM_; // session leaders can't change groups
    }
    if t_sid != my_sid {
        return EPERM_; // can't move across sessions
    }
    if target_pid != my_pid && t_exec {
        return EACCES_; // child already exec'd
    }
    if new_pgid != target_pid
        && !tasks
            .iter()
            .flatten()
            .any(|x| x.pgid == new_pgid && x.sid == t_sid)
    {
        return EPERM_; // group must exist within the session
    }
    let old_pgid = tasks[i].as_ref().unwrap().pgid;
    tasks[i].as_mut().unwrap().pgid = new_pgid;
    // A child leaving group g can strand a wait4(-g)/wait4(0) parent:
    // the exit wake matches the child's pgid AT DEATH, so a departed
    // child's exit never wakes it. Linux rescans and returns ECHILD
    // — re-scan here and wake any g-waiting parent whose last child
    // just left the group.
    if new_pgid != old_pgid {
        let mut wakes = [0u64; MAX_TASKS];
        let mut nw = 0usize;
        for s in tasks.iter().flatten() {
            if s.state == TaskState::Blocked && s.wait_on == WaitOn::Group(old_pgid) {
                wakes[nw] = s.pid;
                nw += 1;
            }
        }
        for w in wakes[..nw].iter() {
            let empty = !tasks
                .iter()
                .flatten()
                .any(|c| c.ppid == *w && c.pgid == old_pgid);
            if empty {
                if let Some(p) = tasks.iter_mut().flatten().find(|t| t.pid == *w) {
                    if p.state == TaskState::Blocked
                        && p.wait_on == WaitOn::Group(old_pgid)
                    {
                        p.ctx.rax = (-10i64) as u64; // -ECHILD
                        p.state = TaskState::Runnable;
                        p.wait_on = WaitOn::None;
                        p.wait_ptr = 0;
                        p.wait_len = 0;
                    }
                }
            }
        }
    }
    0
}

/// POSIX orphaned-pgrp test: a group is orphaned when no member's
/// parent is alive AND lives in the same session but a different
/// group (the bridge that could job-control it back).
fn pgrp_orphaned(pgid: u64, sid: u64) -> bool {
    let tasks = unsafe { &mut *core::ptr::addr_of_mut!(TASKS) };
    tasks
        .iter()
        .flatten()
        .filter(|t| t.pgid == pgid)
        .all(|m| match tasks.iter().flatten().find(|p| p.pid == m.ppid) {
            Some(p) => p.state == TaskState::Exited || p.sid != sid || p.pgid == pgid,
            None => true, // dead/reaped parent
        })
}

/// TOSTOP write gate — the write-side mirror of fd_read's SIGTTIN
/// check (Linux's tty_check_change(SIGTTOU) under O_TOSTOP).
pub fn tty_tostop_gate() -> u64 {
    const TOSTOP: u32 = 0x100; // c_lflag bit — asm-generic 000400
    if t_lflag() & TOSTOP == 0 {
        return 0;
    }
    ttou_gate()
}

/// tcsetpgrp gate — Linux's tiocspgrp runs tty_check_change(SIGTTOU)
/// unconditionally: a background pgrp may not move the tty's
/// foreground without a job-control signal landing first.
pub fn tty_spgrp_gate() -> u64 {
    ttou_gate()
}

/// Shared SIGTTOU check: a task of the console's session operating
/// on the tty from a background pgrp gets its group SIGTTOU'd unless
/// the signal is blocked or ignored; an orphaned group gets EIO.
/// Returns 0 when the operation may proceed, else a negated errno.
fn ttou_gate() -> u64 {
    let Some(t) = cur_mut() else { return 0 };
    let (fg, csid) = unsafe { (FG_PGID, CONSOLE_SID) };
    let fg_live = fg != 0
        && unsafe { &*core::ptr::addr_of!(TASKS) }
            .iter()
            .flatten()
            .any(|x| x.pgid == fg);
    if t.sid != csid || !fg_live || t.pgid == fg {
        return 0;
    }
    let h = sigt(t)
        .handlers
        .get(21) // SIGTTOU - 1
        .copied()
        .unwrap_or(SIG_DFL);
    let bypass = h == SIG_IGN || t.sigmask & (1 << 21) != 0;
    if bypass {
        return 0;
    }
    if pgrp_orphaned(t.pgid, t.sid) {
        return (-5i64) as u64; // EIO
    }
    kill_pgrp(t.pgid, 22); // SIGTTOU
    if deliverable(t) {
        return (-4i64) as u64; // EINTR: the stop lands first
    }
    0
}

/// End of the scheduling run: reap whatever tasks remain — the last
/// Exited task and anything left unrunnable by a failed spawn.
pub fn reap_all() {
    let tasks = unsafe { &mut *core::ptr::addr_of_mut!(TASKS) };
    for s in tasks.iter_mut() {
        if let Some(t) = s.as_mut() {
            t.reap();
        }
        *s = None;
    }
    unsafe { *core::ptr::addr_of_mut!(CUR_I) = usize::MAX };
}
