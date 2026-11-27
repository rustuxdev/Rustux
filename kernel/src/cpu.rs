//! cpu — descriptor tables and exception dispatch.
//!
//! After ExitBootServices we still run on OVMF's GDT and IDT. This module
//! installs our own: a flat 64-bit GDT (null / kernel code / kernel data)
//! and a 256-entry IDT whose per-vector naked stubs funnel into one Rust
//! reporter. Exceptions print vector/rip/err on COM1 and either resume
//! (#UD skips the faulting instruction for the boot proof) or halt.
//!
//! extern "x86-interrupt" is nightly-only, so the stubs are `#[unsafe(naked)]`
//! shims that normalize the stack into a `TrapFrame` and jump to `dispatch`.
//! No TSS/IST yet — #DF lands on the current stack (noted for the real
//! interrupt layer).

use core::fmt::Write;

use crate::uart::{Uart16550, COM1};

const KCODE: u16 = 0x08;
const KDATA: u16 = 0x10;
/// Selector of the TSS descriptor (GDT slots 3-4; a 64-bit TSS descriptor
/// is 16 bytes wide).
const TSS_SEL: u16 = 0x18;

/// User segments at GDT slots 5-6 (after the 16-byte TSS). SYSRET
/// derives ss=(STAR base+8)|3, cs=(STAR base+16)|3, so with a STAR
/// sysret base of 0x20 the CPU lands on 0x2b/0x33 — the literals the
/// asm stub pushes for its iretq/sysretq frames.
#[allow(dead_code)]
pub const UDATA_SEL: u16 = 0x28 | 3;
#[allow(dead_code)]
pub const UCODE_SEL: u16 = 0x30 | 3;
/// 32-bit user code segment (GDT slot 7) — L=0,D=1 drops the CPU
/// into IA-32e compatibility mode on iret. Compat tasks always
/// return via iretq: SYSRET's CS is STAR-derived and can never
/// land a compat descriptor (Linux's entry_SYSCALL_compat does
/// the same). Data segments need no compat variant — DS/ES/SS
/// bases and limits are ignored in IA-32e mode.
pub const UC32_SEL: u16 = 0x38 | 3;

// Flat 64-bit segments: base/limit ignored by the CPU in long mode.
// code: P|DPL0|S|Exec|Read|L   data: P|DPL0|S|Write
// User variants are the same shapes with DPL=3 (access 0xf2/0xfa).
// Slots 3-4 hold the TSS descriptor, filled at init (needs the runtime base).
// Slots 8-11 are the i386 TLS descriptors (set_thread_area): per-task
// state installed into these slots on every switch, Linux's GDT
// TLS-entry scheme. Compat %gs bases come from the descriptor, so the
// slots must be live while the task runs. Slots 12-13 hold the
// per-task LDT descriptor (modify_ldt), installed on every switch.
static mut GDT: [u64; 14] = [
    0,
    0x00af_9a00_0000_ffff, // 0x08 kernel code
    0x00af_9200_0000_ffff, // 0x10 kernel data
    0,
    0,                     // 0x18-0x1f TSS (filled at init)
    // user data: D/B=1 like Linux's __USER_DS — ignored in 64-bit
    // mode, but a compat task's pushes on this SS take the stack
    // width from B (B=0 would truncate esp to sp, 16 bits).
    0x00cf_f200_0000_ffff, // 0x28 user data (DPL3)
    0x00af_fa00_0000_ffff, // 0x30 user code (DPL3)
    // 32-bit compat code: P|DPL3|S|Exec|Read, D=1 L=0 (0xcf/0xfa) —
    // a task iret'd here runs its ring-3 code in IA-32e compat mode.
    0x00cf_fa00_0000_ffff, // 0x38 user32 code (DPL3)
    0, // 0x40-0x5f i386 TLS slots 8-11 (set_thread_area, per task)
    0,
    0,
    0,
    0, // 0x60-0x67 per-task LDT descriptor (lldt, installed per switch)
    0,
];

/// First GDT slot of the i386 TLS entries (selectors 0x43/0x4b/0x53/0x5b
/// with RPL 3) and how many there are — Linux's GDT_ENTRY_TLS_MIN
/// analogue, sized to match the array above.
pub const TLS_SLOT_BASE: usize = 8;
pub const TLS_SLOTS: usize = 4;

/// Install one TLS descriptor into its GDT slot. Long mode reads GDT
/// entries from memory on every segment load, so no lgdt is needed —
/// the task's own `mov gs, sel` (or the switch-time reload) picks the
/// new descriptor up.
pub fn install_tls(slot: usize, desc: u64) {
    if slot >= TLS_SLOTS {
        return;
    }
    // SAFETY: single-CPU; the slot index is bounded above and the GDT
    // outlives every task.
    unsafe { (*core::ptr::addr_of_mut!(GDT))[TLS_SLOT_BASE + slot] = desc };
}

/// Load a user GS selector (0 clears the segment). CPL0 may load a
/// DPL3 data segment when RPL <= DPL, so the switch path can restore a
/// compat task's %gs on its behalf.
pub fn load_gs(sel: u16) {
    // SAFETY: sel is a validated GDT TLS selector or 0; the GDT entry
    // is a present DPL3 data descriptor by the time this runs.
    unsafe {
        core::arch::asm!("mov gs, {0:x}", in(reg) sel as u64, options(nostack, preserves_flags));
    }
}

/// x86_64 task state segment. Only the IST entries matter today: no
/// privilege transitions exist yet, so the rsp fields stay zeroed. iopb
/// past the struct end disables the I/O bitmap.
#[repr(C, packed)]
struct Tss {
    _r0: u32,
    _rsp: [u64; 3],
    _r1: u64,
    ist: [u64; 7],
    _r2: u64,
    _r3: u16,
    iopb: u16,
}

/// Dedicated double-fault stack (IST1). Without it a #DF raised on an
/// already-corrupt stack triple-faults the machine — the vector-8 gate
/// below switches here first, so the handler always has room to report.
#[repr(align(16))]
struct DfStack(#[allow(dead_code)] [u8; 8192]);

/// The TSS plus the space ioperm needs: the I/O permission bitmap is
/// addressed as an OFFSET from the TSS base, so it must sit in the
/// same static to stay contiguous. A set bit denies its port at
/// CPL3; Linux's trailing all-ones byte covers the multi-byte port
/// access that runs past bit 65535. The descriptor limit is widened
/// to include the bitmap in init() — iopb past the limit means
/// "deny all" (the no-ioperm default), which the 0xFF fill provides.
#[repr(C)]
struct TssBlock {
    tss: Tss,
    iomap: [u8; 8192],
    tail: u8,
}
static mut TSSB: TssBlock = TssBlock {
    tss: Tss { _r0: 0, _rsp: [0; 3], _r1: 0, ist: [0; 7], _r2: 0, _r3: 0, iopb: 0 },
    iomap: [0xff; 8192],
    tail: 0xff,
};

/// Swap the live I/O bitmap for the incoming task: `src` is the
/// task-group's 8K deny bitmap, or null for deny-all. Called at every
/// context-switch site; the unconditional copy is ~1µs at this scale
/// and keeps the TSS honest even after a same-tgid ioperm mutation.
pub fn load_iomap(src: *const u8) {
    let b = unsafe { &mut *core::ptr::addr_of_mut!(TSSB) };
    if src.is_null() {
        b.iomap = [0xff; 8192];
    } else {
        // SAFETY: src names a live 8K task bitmap (IOPS slot).
        unsafe { b.iomap.copy_from_slice(&*(src as *const [u8; 8192])) };
    }
}

static mut DF_STACK: DfStack = DfStack([0; 8192]);
static mut INTR_STACK: DfStack = DfStack([0; 8192]);

/// Selector of the LDT descriptor (GDT slots 12-13).
pub const LDT_SEL: u16 = 12 << 3;

/// Build the 16-byte system descriptor for an LDT (type 0x2, present).
fn ldt_descriptor(base: u64, limit: u64) -> (u64, u64) {
    let low = (limit & 0xffff)
        | ((base & 0x00ff_ffff) << 16)
        | (0b0010_u64 << 40) // type: LDT
        | (1_u64 << 47) // present
        | (((limit >> 16) & 0xf) << 48)
        | ((base & 0xff00_0000) << 32);
    let high = base >> 32;
    (low, high)
}

/// Point the GDT's LDT slot at `base`/`limit` and lldt it — or unload
/// the LDT entirely when `base` is null (lldt 0 marks LDTR invalid,
/// so every LDT selector #GPs). Called at every switch site.
pub fn load_ldt(base: *const u64, limit: u16) {
    unsafe {
        if base.is_null() {
            (*core::ptr::addr_of_mut!(GDT))[12] = 0;
            (*core::ptr::addr_of_mut!(GDT))[13] = 0;
            core::arch::asm!("lldt ax", in("ax") 0u16, options(nostack));
            return;
        }
        let (lo, hi) = ldt_descriptor(base as u64, limit as u64);
        (*core::ptr::addr_of_mut!(GDT))[12] = lo;
        (*core::ptr::addr_of_mut!(GDT))[13] = hi;
        core::arch::asm!("lldt {0:x}", in(reg) LDT_SEL as u64, options(nostack));
    }
}

/// Build the 16-byte system descriptor for a 64-bit available TSS.
fn tss_descriptor(base: u64, limit: u64) -> (u64, u64) {
    let low = (limit & 0xffff)
        | ((base & 0x00ff_ffff) << 16)
        | (0b1001_u64 << 40) // type: 64-bit TSS (available)
        | (1_u64 << 47) // present
        | (((limit >> 16) & 0xf) << 48)
        | (((base >> 24) & 0xff) << 56);
    (low, base >> 32)
}

#[repr(C, packed)]
struct TablePtr {
    limit: u16,
    base: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct IdtEntry {
    off_lo: u16,
    sel: u16,
    ist: u8,
    attr: u8,
    off_mid: u16,
    off_hi: u32,
    zero: u32,
}

#[repr(C, align(16))]
struct Idt([IdtEntry; 256]);

const EMPTY: IdtEntry = IdtEntry {
    off_lo: 0,
    sel: 0,
    ist: 0,
    attr: 0,
    off_mid: 0,
    off_hi: 0,
    zero: 0,
};

static mut IDT: Idt = Idt([EMPTY; 256]);

fn set_gate(v: usize, handler: u64, ist: u8) {
    set_gate_attr(v, handler, ist, 0x8e); // present, DPL0, int gate
}

/// `set_gate` with an explicit descriptor DPL — user-invoked gates
/// (int 0x80, the ia32 syscall vector) need DPL3 or CPL3 code #GPs.
fn set_gate_attr(v: usize, handler: u64, ist: u8, attr: u8) {
    // SAFETY: single-threaded early boot; writes stay inside the static IDT.
    unsafe {
        (*core::ptr::addr_of_mut!(IDT)).0.as_mut_ptr().add(v).write(IdtEntry {
            off_lo: handler as u16,
            sel: KCODE,
            ist,
            attr,
            off_mid: (handler >> 16) as u16,
            off_hi: (handler >> 32) as u32,
            zero: 0,
        });
    }
}

/// What a stub leaves on the stack for `dispatch`: vector, error code
/// (real or pushed dummy 0), then the hardware frame.
#[repr(C)]
struct TrapFrame {
    vec: u64,
    err: u64,
    rip: u64,
    cs: u64,
    rflags: u64,
    rsp: u64,
    ss: u64,
}

/// The 14-GPR block dispatch saves under the aligned rsp (push
/// order r11..rax,rbx,r12-r15 means the struct reads r15 at offset
/// 0). The second arg to report_frame. The interrupted rcx and rbp
/// live above the TrapFrame instead — see dispatch's push order.
#[repr(C)]
struct SavedRegs {
    r15: u64,
    r14: u64,
    r13: u64,
    r12: u64,
    rbx: u64,
    rax: u64,
    _rcx_arg: u64, // slot holds &TrapFrame, not the interrupted rcx
    rdx: u64,
    rsi: u64,
    rdi: u64,
    r8: u64,
    r9: u64,
    r10: u64,
    r11: u64,
}

const NAMES: [&str; 32] = [
    "#DE", "#DB", "NMI", "#BP", "#OF", "#BR", "#UD", "#NM", "#DF", "?", "#TS", "#NP", "#SS", "#GP",
    "#PF", "?", "#MF", "#AC", "#MC", "#XM", "#VE", "#CP", "?", "?", "?", "?", "?", "?", "?", "#VC",
    "#SX", "?",
];

/// Rust-side reporter. `rcx` carries `&mut TrapFrame` (set by `dispatch`) —
/// the UEFI target uses the Windows x64 ABI, so the first arg arrives in
/// rcx, not rdi.
extern "win64" fn report_frame(f: &mut TrapFrame, regs: *mut SavedRegs) {
    // Hardware IRQs (LAPIC timer 0xf0, PIT-via-IOAPIC 0xf1, spurious 0xff)
    // take the cheap path: no serial port setup, no printing. The u64::MAX
    // unknown-vector sentinel stays on the report path — a stray IRQ must
    // be visible, not silently EOI'd. Every other vector is an exception.
    if f.vec >= crate::apic::IRQ_TIMER && f.vec != u64::MAX {
        crate::apic::irq_dispatch(f.vec);
        return;
    }
    let mut u = unsafe { Uart16550::new(COM1) };
    u.init();
    // A fault from CPL3 is a task bug, not a kernel bug: the task
    // dies with the signal's bare-signo wait status and the kernel
    // keeps running. Without this, any user memory error halts the
    // whole machine — and crafted sigframes/int3/ud2 would be
    // trivial kernel DoS primitives (the CVE-2018-8897 lesson:
    // user-controlled exception delivery must never outrun the
    // kernel's expectations).
    let user_fault = f.cs & 3 == 3;
    match f.vec {
        // #UD boot proof: report and skip the 2-byte ud2 (kernel only).
        6 if !user_fault => {
            let _ = writeln!(
                u,
                "rustux: cpu: caught #UD rip={:#x} -- skipping",
                f.rip
            );
            f.rip += 2;
        }
        // #BP/int3 resumes in place (kernel only — a user int3 would
        // otherwise re-fault forever).
        3 if !user_fault => {
            let _ = writeln!(u, "rustux: cpu: caught #BP rip={:#x} -- resuming", f.rip);
        }
        v => {
            let name = if v == u64::MAX {
                "unknown"
            } else if v < 32 {
                NAMES[v as usize]
            } else {
                "irq"
            };
            let cr2: u64;
            // SAFETY: reading cr2 is always valid at CPL0.
            unsafe { core::arch::asm!("mov {}, cr2", out(reg) cr2) };
            if user_fault {
                // Map the vector to the Linux signal the task dies
                // with. Kernel-integrity exceptions (#DF/#MC/#CP,
                // NMI) still halt — a task-fault teardown is not a
                // trustworthy answer to a double fault.
                let signo = match v {
                    1 | 3 => 5,                      // #DB/#BP -> SIGTRAP
                    6 => 4,                          // #UD    -> SIGILL
                    0 | 4 | 7 | 16 | 19 => 8,        // #DE/#OF/#NM/#MF/#XM -> SIGFPE
                    5 | 17 => 7,                     // #BR/#AC -> SIGBUS
                    10 | 11 | 12 | 13 | 14 | 20 => 11, // #TS/#NP/#SS/#GP/#PF/#VE -> SIGSEGV
                    _ => 0,
                };
                if signo != 0 {
                    let tn = crate::user::cur_exe();
                    let _ = writeln!(
                        u,
                        "rustux: cpu: user fault {} task={} rip={:#x} err={:#x} cr2={:#x} -> sig {}",
                        name, tn, f.rip, f.err, cr2, signo
                    );
                    // Mirror to the framebuffer console: without this a
                    // faulting task is invisible on systems with no
                    // serial port (bare metal, VMware) — a real oops
                    // belongs on the console.
                    crate::log::printk(format_args!(
                        "rustux: cpu: user fault {} task={} rip={:#x} err={:#x} cr2={:#x} -> sig {}",
                        name, tn, f.rip, f.err, cr2, signo
                    ));
                    crate::log::drain_task();
                    // Rebuild the complete interrupted context from
                    // the stubs' saved registers — a caught
                    // disposition pushes [signo][UCtx] on the user
                    // stack and we splice the handler redirect into
                    // this frame, so iretq lands in the handler.
                    let r = unsafe { &*regs };
                    let ir = f as *mut TrapFrame as *const u64;
                    let mut ctx = crate::user::UCtx {
                        r15: r.r15, r14: r.r14, r13: r.r13, r12: r.r12,
                        // SAFETY: dispatch pushed interrupted rbp at
                        // f-16 and interrupted rcx at f-8.
                        rbp: unsafe { *ir.sub(2) },
                        rbx: r.rbx,
                        r11: r.r11, r10: r.r10, r9: r.r9, r8: r.r8,
                        rdi: r.rdi, rsi: r.rsi, rdx: r.rdx,
                        rcx: unsafe { *ir.sub(1) },
                        rax: r.rax,
                        rip: f.rip, cs: f.cs, rflags: f.rflags,
                        rsp: f.rsp, ss: f.ss,
                    };
                    // Returns (handler, frame rsp, signo) on delivery
                    // or tears the task down internally on a
                    // default/ignored/failed disposition — the
                    // callee-saved GPRs never left the registers, so
                    // the pops below resume the handler cleanly.
                    // si_code/si_addr for an SA_SIGINFO handler:
                    // #PF err bit0 picks MAPERR vs ACCERR, si_addr is
                    // cr2 for a page fault and the faulting rip for
                    // the rest (matching Linux's fill_sig_fault).
                    let (code, addr) = match signo {
                        11 if v == 14 => {
                            (if f.err & 1 != 0 { 2 } else { 1 }, cr2)
                        }
                        4 => (2, f.rip),  // ILL_ILLOPC
                        5 => (2, f.rip),  // TRAP_BRKPT/TRACE
                        8 => (1, f.rip),  // FPE_INTDIV
                        7 => (1, f.rip),  // BUS_ADRALN
                        _ => (0x80, f.rip), // SI_KERNEL
                    };
                    let (rip, rsp, rdi) =
                        crate::user::fault_signal(signo, code, addr, &mut ctx);
                    f.rip = rip;
                    f.rsp = rsp;
                    // SAFETY: regs names the dispatch-saved block on
                    // the live kstack; rdi's slot is what `pop rdi`
                    // hands the handler, rsi/rdx its siginfo and
                    // ucontext args.
                    unsafe {
                        (*regs).rdi = rdi;
                        (*regs).rsi = ctx.rsi;
                        (*regs).rdx = ctx.rdx;
                    }
                    return;
                }
            }
            let _ = writeln!(
                u,
                "rustux: cpu: EXCEPTION {} (vec={:#x}) rip={:#x} err={:#x} cs={:#x} cr2={:#x} rsp={:#x} fl={:#x} f={:p} -- halting",
                name, f.vec, f.rip, f.err, f.cs, cr2, f.rsp, f.rflags, f
            );
            // Caller identification: dump the interrupted stack top —
            // for a call-site fault [rsp] is the return address. Kernel
            // stacks live in the physmap post-physmap_on; identity
            // addresses cover the pre-flip era.
            let pm = crate::mm::PHYSMAP;
            let in_ram = (f.rsp >= 0x100000 && f.rsp < 0x4000_0000)
                || (f.rsp >= pm + 0x100000 && f.rsp < pm + 0x4000_0000);
            if in_ram {
                for i in 0..6u64 {
                    let a = f.rsp + i * 8;
                    // SAFETY: rsp is inside the physmap (checked above).
                    let v = unsafe { (a as *const u64).read_volatile() };
                    let _ = writeln!(u, "rustux: cpu:   stk[{a:#x}] = {v:#x}");
                }
            }
            let r = unsafe { &*regs };
            let ir = f as *mut TrapFrame as *const u64;
            // SAFETY: dispatch pushed interrupted rbp at f-16 and rcx at f-8.
            let (rbp, rcx) = unsafe { (*ir.sub(2), *ir.sub(1)) };
            let _ = writeln!(
                u,
                "rustux: cpu:   rdi={:#x} rsi={:#x} rdx={:#x} rcx={:#x} rax={:#x} rbp={:#x}",
                r.rdi, r.rsi, r.rdx, rcx, r.rax, rbp
            );
            crate::log::printk(format_args!(
                "rustux: cpu: EXCEPTION {} (vec={:#x}) rip={:#x} err={:#x} cs={:#x} cr2={:#x} rsp={:#x} fl={:#x} f={:p} -- halting",
                name, f.vec, f.rip, f.err, f.cs, cr2, f.rsp, f.rflags, f
            ));
            crate::log::drain_task();
            loop {
                // SAFETY: halting forever is the intended terminal state.
                unsafe { core::arch::asm!("cli; hlt", options(nomem, nostack)) }
            }
        }
    }
}

/// Shared tail for every stub. Stubs push ONLY immediates so the frame can
/// be located without clobbering any register: on entry rsp points at `vec`.
/// Here we save rcx (the arg register we are about to reuse) first, derive
/// `&TrapFrame` from the stack, save every other caller-saved register
/// (asynchronous IRQs must not corrupt the interrupted context), call the
/// reporter, restore, unwind to the hardware frame and iretq.
#[unsafe(naked)]
extern "C" fn dispatch() -> ! {
    core::arch::naked_asm!(
        "push rcx", // interrupted rcx -- stubs leave it untouched
        "mov rcx, rsp",
        "lea rcx, [rcx + 8]", // rcx = &TrapFrame (first arg, Windows x64 ABI)
        "push rbp",
        "mov rbp, rsp",
        "and rsp, -16",
        "push r11",
        "push r10",
        "push r9",
        "push r8",
        "push rdi",
        "push rsi",
        "push rdx",
        "push rcx",
        "push rax",
        "push rbx",
        "push r12",
        "push r13",
        "push r14",
        "push r15",
        // rdx = &SavedRegs (r15 lands at base, r11 at top) — the
        // second report_frame arg. Must come AFTER the pushes so
        // the rdx slot above holds the interrupted value.
        "mov rdx, rsp",
        "call {r}",
        "pop r15",
        "pop r14",
        "pop r13",
        "pop r12",
        "pop rbx",
        "pop rax",
        "pop rcx",
        "pop rdx",
        "pop rsi",
        "pop rdi",
        "pop r8",
        "pop r9",
        "pop r10",
        "pop r11",
        "mov rsp, rbp",
        "pop rbp",
        "pop rcx", // interrupted rcx back
        "add rsp, 16",
        "iretq",
        r = sym report_frame,
    );
}

/// Stub without CPU error code: pushes a dummy err=0 then the vector. Must
/// not write any register -- the interrupted context's rcx et al. are live.
macro_rules! stub {
    ($name:ident, $vec:expr) => {
        #[unsafe(naked)]
        extern "C" fn $name() {
            core::arch::naked_asm!(
                "push 0",
                concat!("push ", $vec),
                "jmp {d}",
                d = sym dispatch,
            );
        }
    };
}

/// Stub for vectors where the CPU already pushed the error code.
macro_rules! stub_err {
    ($name:ident, $vec:expr) => {
        #[unsafe(naked)]
        extern "C" fn $name() {
            core::arch::naked_asm!(
                concat!("push ", $vec),
                "jmp {d}",
                d = sym dispatch,
            );
        }
    };
}

stub!(stub_default, "-1"); // unknown vector sentinel
stub_err!(stub_df, 8);
stub_err!(stub_ts, 10);
stub_err!(stub_np, 11);
stub_err!(stub_ss, 12);
stub_err!(stub_gp, 13);
stub_err!(stub_pf, 14);
stub_err!(stub_ac, 17);
stub_err!(stub_cp, 21);
stub_err!(stub_vc, 29);
stub!(stub_de, 0);
stub!(stub_db, 1);
stub!(stub_nmi, 2);
stub!(stub_bp, 3);
stub!(stub_of, 4);
stub!(stub_br, 5);
stub!(stub_ud, 6);
stub!(stub_nm, 7);
stub!(stub_mf, 16);
stub!(stub_mc, 18);
stub!(stub_xm, 19);
stub!(stub_ve, 20);

/// Timer IRQ — the only vector that may switch tasks, so it can't
/// share `dispatch`: that path only saves caller-saved registers,
/// but a preempted task needs its ENTIRE register file captured to
/// be resumable. sched_dispatch pushes all 15 GPRs so the image it
/// hands the scheduler is a complete UCtx.
#[unsafe(naked)]
extern "C" fn stub_irq_timer() {
    core::arch::naked_asm!("jmp {d}", d = sym sched_dispatch);
}

/// Full-context IRQ tail for the timer: push the 15 GPRs (forming a
/// UCtx with the hardware frame), let Rust pick which ctx to resume,
/// then pop + iretq. `mov rbp/rsp` + `and rsp,-16` keeps the call
/// 16-aligned without disturbing the image pointer in rcx.
#[unsafe(naked)]
extern "C" fn sched_dispatch() -> ! {
    core::arch::naked_asm!(
        "push rax",
        "push rcx",
        "push rdx",
        "push rsi",
        "push rdi",
        "push r8",
        "push r9",
        "push r10",
        "push r11",
        "push rbx",
        "push rbp",
        "push r12",
        "push r13",
        "push r14",
        "push r15",
        "mov rcx, rsp",
        "and rsp, -16",
        "call {t}",
        "mov rsp, rax",
        "pop r15",
        "pop r14",
        "pop r13",
        "pop r12",
        "pop rbp",
        "pop rbx",
        "pop r11",
        "pop r10",
        "pop r9",
        "pop r8",
        "pop rdi",
        "pop rsi",
        "pop rdx",
        "pop rcx",
        "pop rax",
        "iretq",
        t = sym sched_tick_frame,
    );
}

/// Rust half of the timer path: tick accounting, then the scheduler
/// picks which ctx the stub resumes. rcx = &mut UCtx (Windows x64).
extern "win64" fn sched_tick_frame(
    f: &mut crate::user::UCtx,
) -> *const crate::user::UCtx {
    crate::apic::timer_tick();
    crate::user::tick(f)
}

stub!(stub_irq_pit, "0xf1");
stub!(stub_irq_kbd, "0xf2");
stub!(stub_irq_net, "0xf3");
stub!(stub_irq_vnet, "0xf4");
stub!(stub_irq_nvme, "0xf5");
stub!(stub_irq_spurious, "0xff");

/// Install our GDT (reload CS via far return, data segments via ax), TSS
/// (#DF gets a dedicated IST stack), and IDT (all 256 vectors, incl. IRQ
/// stubs for the LAPIC timer and spurious vectors). Interrupts stay
/// masked — apic::init + `sti` come later.
pub fn init() {
    // Fill the TSS descriptor and the DF IST stack before lgdt — the base
    // address only exists at runtime.
    // SAFETY: single-threaded; the statics are written once, before ltr.
    unsafe {
        let tb = core::ptr::addr_of_mut!(TSSB);
        let tss = core::ptr::addr_of_mut!((*tb).tss);
        (*tss).iopb = core::mem::size_of::<Tss>() as u16;
        (*tss).ist[0] = core::ptr::addr_of!(DF_STACK) as u64 + 8192;
        // CPL3->CPL0 interrupt entries (e.g. the LAPIC timer firing
        // while user code runs) get a dedicated kernel stack.
        (*tss)._rsp[0] = core::ptr::addr_of!(INTR_STACK) as u64 + 8192;
        let (lo, hi) =
            tss_descriptor(tss as u64, core::mem::size_of::<TssBlock>() as u64 - 1);
        let gdt = core::ptr::addr_of_mut!(GDT);
        (*gdt)[3] = lo;
        (*gdt)[4] = hi;
    }

    let gdtr = TablePtr {
        limit: (core::mem::size_of::<[u64; 14]>() - 1) as u16,
        base: core::ptr::addr_of!(GDT) as u64,
    };
    // SAFETY: gdtr points at our valid flat GDT; CS reload uses a far return
    // to the next instruction; running code/data remain reachable under the
    // identity map.
    unsafe {
        core::arch::asm!("lgdt [{}]", in(reg) &gdtr, options(readonly, nostack));
        core::arch::asm!(
            "mov rax, {sel}",
            "mov ds, ax",
            "mov es, ax",
            "mov ss, ax",
            sel = in(reg) KDATA as u64,
            out("rax") _,
            options(nostack, preserves_flags),
        );
        // Reload CS with our kernel code selector via a far return so that
        // interrupt frames carry a cs that exists in OUR GDT -- otherwise
        // iretq back to the firmware's 0x38 selector would #GP on return.
        core::arch::asm!(
            "push {sel}",
            "lea rax, [rip + 2f]",
            "push rax",
            ".byte 0x48, 0xcb", // lretq: REX.W makes it pop 8-byte rip + cs
            "2:",
            sel = in(reg) KCODE as u64,
            out("rax") _,
            options(nostack),
        );
        // Load the task register so the IST mechanism is armed; #DF gates
        // reference IST1 below.
        core::arch::asm!("ltr {0:x}", in(reg) TSS_SEL, options(nostack, preserves_flags));

        // FPU/SSE on: CR0 clear EM|TS (no emulation, no task-switch
        // traps), set MP; CR4.OSFXSR|OSXMMEXCPT so fxsave/SSE insn
        // work at CPL3. The UEFI firmware usually has these set —
        // set them explicitly instead of trusting that.
        let mut cr0: u64;
        core::arch::asm!("mov {}, cr0", out(reg) cr0);
        cr0 = (cr0 & !0xc) | 0x2;
        core::arch::asm!("mov cr0, {}", in(reg) cr0);
        let mut cr4: u64;
        core::arch::asm!("mov {}, cr4", out(reg) cr4);
        cr4 |= 0x600;
        core::arch::asm!("mov cr4, {}", in(reg) cr4);
    }

    let gates: [(usize, u64, u8); 28] = [
        (0, stub_de as *const () as u64, 0),
        (1, stub_db as *const () as u64, 0),
        (2, stub_nmi as *const () as u64, 0),
        (3, stub_bp as *const () as u64, 0),
        (4, stub_of as *const () as u64, 0),
        (5, stub_br as *const () as u64, 0),
        (6, stub_ud as *const () as u64, 0),
        (7, stub_nm as *const () as u64, 0),
        (8, stub_df as *const () as u64, 1), // IST1: dedicated DF stack
        (10, stub_ts as *const () as u64, 0),
        (11, stub_np as *const () as u64, 0),
        (12, stub_ss as *const () as u64, 0),
        (13, stub_gp as *const () as u64, 0),
        (14, stub_pf as *const () as u64, 0),
        (16, stub_mf as *const () as u64, 0),
        (17, stub_ac as *const () as u64, 0),
        (18, stub_mc as *const () as u64, 0),
        (19, stub_xm as *const () as u64, 0),
        (20, stub_ve as *const () as u64, 0),
        (21, stub_cp as *const () as u64, 0),
        (29, stub_vc as *const () as u64, 0),
        (0xf0, stub_irq_timer as *const () as u64, 0),
        (0xf1, stub_irq_pit as *const () as u64, 0),
        (0xf2, stub_irq_kbd as *const () as u64, 0),
        (0xf3, stub_irq_net as *const () as u64, 0),
        (0xf4, stub_irq_vnet as *const () as u64, 0),
        (0xf5, stub_irq_nvme as *const () as u64, 0),
        (0xff, stub_irq_spurious as *const () as u64, 0),
    ];
    for v in 0..256 {
        set_gate(v, stub_default as *const () as u64, 0);
    }
    for (v, h, ist) in gates {
        set_gate(v, h, ist);
    }
    // int 0x80 — the ia32 compat syscall vector. DPL3 interrupt gate
    // or a CPL3 caller #GPs; it enters on TSS.rsp0 like any user int.
    set_gate_attr(0x80, crate::syscall::int80_addr(), 0, 0xee);

    let idtr = TablePtr {
        limit: (256 * 16 - 1) as u16,
        base: core::ptr::addr_of!(IDT) as u64,
    };
    // SAFETY: idtr points at the fully populated 256-entry static IDT.
    unsafe {
        core::arch::asm!("cli", options(nomem, nostack));
        core::arch::asm!("lidt [{}]", in(reg) &idtr, options(readonly, nostack));
    }
}

/// Write a model-specific register.
///
/// # Safety
/// `msr` must be a valid MSR for this CPU and `val` a legal encoding.
pub unsafe fn wrmsr(msr: u32, val: u64) {
    // SAFETY: caller contract — privileged MSR write in ring 0.
    unsafe {
        core::arch::asm!(
            "wrmsr",
            in("ecx") msr,
            in("eax") val as u32,
            in("edx") (val >> 32) as u32,
            options(nostack, preserves_flags)
        );
    }
}

/// Read a model-specific register.
///
/// # Safety
/// `msr` must be a valid MSR for this CPU.
pub unsafe fn rdmsr(msr: u32) -> u64 {
    let lo: u32;
    let hi: u32;
    // SAFETY: caller contract — privileged MSR read in ring 0.
    unsafe {
        core::arch::asm!(
            "rdmsr",
            in("ecx") msr,
            out("eax") lo,
            out("edx") hi,
            options(nostack, preserves_flags, nomem)
        );
    }
    ((hi as u64) << 32) | lo as u64
}

/// Current CR3 (PML4 physical base, flags in low 12 bits).
const MSR_EFER: u32 = 0xc000_0080;
const MSR_STAR: u32 = 0xc000_0081;
const MSR_LSTAR: u32 = 0xc000_0082;
const MSR_SFMASK: u32 = 0xc000_0084;
pub const MSR_FS_BASE: u32 = 0xc000_0100;
pub const MSR_GS_BASE: u32 = 0xc000_0101;
const MSR_KGS_BASE: u32 = 0xc000_0102;

/// Enable the SYSCALL/SYSRET path: STAR segment bases, LSTAR entry
/// point, SFMASK (clear TF/IF/DF on entry), EFER SCE|NXE.
///
/// STAR layout (AMD/Intel): [47:32] = kernel CS for SYSCALL (SS =
/// that +8), [63:48] = sysret base (SS = base+8|3, CS = base+16|3).
/// With GDT kcode@0x08/kdata@0x10/udata@0x28/ucode@0x30:
/// syscall field = 0x08, sysret field = 0x20.
pub fn init_syscall(lstar: u64) {
    unsafe {
        let efer = rdmsr(MSR_EFER);
        wrmsr(MSR_EFER, efer | 0x801); // SCE + NXE
        wrmsr(MSR_STAR, (0x20u64 << 48) | (0x08u64 << 32));
        wrmsr(MSR_LSTAR, lstar);
        wrmsr(MSR_SFMASK, 0x700); // TF|IF|DF cleared on syscall entry
        // The kernel uses no FS/GS state (no swapgs, no percpu), so
        // all three bases zero cleanly: user code must not inherit
        // firmware leftovers as its TLS/segment bases.
        wrmsr(MSR_FS_BASE, 0);
        wrmsr(MSR_GS_BASE, 0);
        wrmsr(MSR_KGS_BASE, 0);
    }
}
