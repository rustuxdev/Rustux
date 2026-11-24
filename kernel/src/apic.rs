//! apic — legacy PIC masking + local APIC periodic timer.
//!
//! First step of the real interrupt layer. The LAPIC timer needs no I/O
//! APIC routing and no ACPI, so it is the minimal periodic-IRQ proof: mask
//! the legacy PIC entirely (firmware already remapped it to 0x20..0x2f),
//! enable the local APIC via the IA32_APIC_BASE MSR, calibrate its counter
//! against PIT channel 2 (the classic calibrate_APIC_clock approach — a
//! ~10 ms one-shot window), then arm a 100 Hz periodic IRQ through our own
//! IDT. Interrupts stay masked until main() executes `sti`.
//!
//! Vectors: local timer at 0xf0, spurious at 0xff (the low nibble must be
//! 0xf anyway). Both route through dedicated cpu.rs stubs into
//! `irq_dispatch`; every other vector stays on the exception path.

use crate::pio::{inb, outb};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// Local timer IRQ vector (gate installed by cpu::init).
pub const IRQ_TIMER: u64 = 0xf0;
/// Device IRQ vector for the PIT-through-IOAPIC proof.
pub const IRQ_PIT: u64 = 0xf1;
/// PS/2 keyboard IRQ vector.
pub const IRQ_KBD: u64 = 0xf2;
/// MSI vector programmed into the e1000's message data.
pub const IRQ_NET: u64 = 0xf3;
/// Spurious interrupt vector — hardware requires the low nibble be 0xf.
pub const IRQ_SPURIOUS: u64 = 0xff;

/// Timer ticks delivered so far; bumped in the IRQ path.
pub static TICKS: AtomicU64 = AtomicU64::new(0);
/// PIT channel-0 ticks delivered via the I/O APIC.
pub static PIT_TICKS: AtomicU64 = AtomicU64::new(0);

static LAPIC_BASE: AtomicU64 = AtomicU64::new(0);
/// When the CPU/firmware put the LAPIC in x2APIC mode the MMIO window is
/// dead — every register access must go through MSRs 0x800+off/16 instead.
static X2APIC: AtomicBool = AtomicBool::new(false);

const LAPIC_TPR: u64 = 0x080;
const LAPIC_ID: u64 = 0x020;
const LAPIC_EOI: u64 = 0x0b0;
const LAPIC_SVR: u64 = 0x0f0;
const LAPIC_LVT_TIMER: u64 = 0x320;
const LAPIC_TMRDIV: u64 = 0x3e0;
const LAPIC_TMRINIT: u64 = 0x380;
const LAPIC_TMRCUR: u64 = 0x390;

const PIT_HZ: u128 = 1_193_182;
/// ~10 ms calibration window in PIT channel-2 ticks.
const PIT_CAL_TICKS: u16 = 11_932;
/// Wanted periodic rate — the classic Linux CONFIG_HZ default.
const HZ: u64 = 100;

unsafe fn rdmsr(idx: u32) -> (u32, u32) {
    let (lo, hi): (u32, u32);
    unsafe {
        core::arch::asm!(
            "rdmsr",
            in("ecx") idx,
            out("eax") lo,
            out("edx") hi,
            options(nomem, nostack)
        );
    }
    (lo, hi)
}

unsafe fn wrmsr(idx: u32, lo: u32, hi: u32) {
    unsafe {
        core::arch::asm!(
            "wrmsr",
            in("ecx") idx,
            in("eax") lo,
            in("edx") hi,
            options(nomem, nostack)
        );
    }
}

#[inline]
fn lread(off: u64) -> u32 {
    if X2APIC.load(Ordering::Relaxed) {
        // SAFETY: x2APIC mode confirmed enabled in init().
        unsafe { rdmsr(0x800 + (off / 16) as u32).0 }
    } else {
        // SAFETY: base was programmed from IA32_APIC_BASE in init(); off is
        // a fixed LAPIC register offset; the physmap covers <4 GiB MMIO.
        unsafe { ((crate::mm::pmap(LAPIC_BASE.load(Ordering::Relaxed)) + off) as *const u32).read_volatile() }
    }
}

#[inline]
fn lwrite(off: u64, v: u32) {
    if X2APIC.load(Ordering::Relaxed) {
        unsafe { wrmsr(0x800 + (off / 16) as u32, v, 0) }
    } else {
        unsafe { ((crate::mm::pmap(LAPIC_BASE.load(Ordering::Relaxed)) + off) as *mut u32).write_volatile(v) }
    }
}

/// End-of-interrupt on the local APIC. Never write this on the spurious
/// vector — the EOI register is level-insensitive and harmless anyway.
fn eoi() {
    if LAPIC_BASE.load(Ordering::Relaxed) != 0 || X2APIC.load(Ordering::Relaxed) {
        lwrite(LAPIC_EOI, 0);
    }
}

/// IRQ vector -> action, called from cpu::report_frame for the vectors
/// with real IRQ stubs. Returns without printing so ticks stay cheap.
/// Timer accounting + EOI for the scheduler path — vector 0xf0's
/// dedicated stub bypasses irq_dispatch so a tick can switch tasks.
pub fn timer_tick() {
    TICKS.fetch_add(1, Ordering::Relaxed);
    eoi();
}

/// IRQ vector -> action, called from cpu::report_frame for the vectors
/// with real IRQ stubs. Returns without printing so ticks stay cheap.
pub fn irq_dispatch(vec: u64) {
    match vec {
        IRQ_PIT => {
            PIT_TICKS.fetch_add(1, Ordering::Relaxed);
            eoi();
        }
        IRQ_KBD => {
            crate::kbd::on_irq();
            eoi();
        }
        IRQ_NET => {
            crate::e1000::on_irq();
            eoi();
        }
        IRQ_SPURIOUS => {} // per spec: no EOI on a spurious interrupt
        _ => eoi(),
    }
}

/// x2APIC mode active (register access via MSRs, MMIO window dead).
pub fn is_x2apic() -> bool {
    X2APIC.load(Ordering::Relaxed)
}

/// Mask every line on the legacy PIC pair and clear any pending EOI state.
/// The PIC is not used at all once the LAPIC timer carries the tick.
fn pic_mask_all() {
    unsafe {
        outb(0x20, 0x20); // non-specific EOI, master
        outb(0xa0, 0x20); // non-specific EOI, slave
        outb(0x21, 0xff); // mask all master lines
        outb(0xa1, 0xff); // mask all slave lines
    }
}

/// Mask the legacy PIC, enable the LAPIC, calibrate the timer against the
/// PIT and arm a HZ-periodic IRQ on IRQ_TIMER. Returns the measured LAPIC
/// counter frequency in Hz, or None when no LAPIC is present.
pub fn init() -> Option<u64> {
    pic_mask_all();
    if core::arch::x86_64::__cpuid(1).edx & (1 << 9) == 0 {
        return None; // no on-chip APIC
    }
    // IA32_APIC_BASE (0x1b): enable the LAPIC (bit 11), take its MMIO base.
    // If bit 10 (x2APIC) is already set — OVMF enables it on some builds —
    // the MMIO window is dead and all register access must go through MSRs.
    let (mut lo, hi): (u32, u32);
    unsafe {
        (lo, hi) = rdmsr(0x1b);
    }
    let x2 = lo & (1 << 10) != 0;
    X2APIC.store(x2, Ordering::Relaxed);
    // Mask with !0xfff, not 0xffff_f000: bits 32..51 live in hi and a base
    // above 4 GiB must not be silently truncated into low memory.
    let base = (((hi as u64) << 32) | lo as u64) & !0xfff;
    lo |= 1 << 11; // APIC global enable
    unsafe {
        wrmsr(0x1b, lo, hi);
    }
    LAPIC_BASE.store(base, Ordering::Relaxed);

    lwrite(LAPIC_TPR, 0); // accept all interrupt priorities
    lwrite(LAPIC_SVR, 0x100 | IRQ_SPURIOUS as u32); // enable + spurious vec

    // Calibrate: free-run the LAPIC counter (masked one-shot, /16) for a
    // ~10 ms PIT channel-2 window and measure the elapsed LAPIC ticks.
    lwrite(LAPIC_LVT_TIMER, 1 << 16); // masked, one-shot
    lwrite(LAPIC_TMRDIV, 0x3); // divide by 16
    lwrite(LAPIC_TMRINIT, u32::MAX);
    unsafe {
        outb(0x43, 0xb0); // PIT ch2, lo/hi, mode 0 (one-shot)
        let a = inb(0x61);
        outb(0x61, (a & 0xfc) | 0x01); // GATE2 on, speaker off
        outb(0x42, (PIT_CAL_TICKS & 0xff) as u8);
        outb(0x42, (PIT_CAL_TICKS >> 8) as u8);
        while inb(0x61) & 0x20 == 0 {} // OUT2 goes high at terminal count
    }
    let elapsed = u32::MAX - lread(LAPIC_TMRCUR);
    let hz = (elapsed as u128 * PIT_HZ / PIT_CAL_TICKS as u128) as u64;

    // Arm the periodic timer on our IRQ vector. The .max(1) guards a
    // pathologically low measured hz: an initial count of 0 in periodic
    // mode is undefined and would storm the IRQ path.
    lwrite(LAPIC_LVT_TIMER, (1 << 17) | IRQ_TIMER as u32); // periodic
    lwrite(LAPIC_TMRINIT, (hz / HZ).max(1) as u32);
    Some(hz)
}

// ---------------------------------------------------------------------------
// I/O APIC — the real device IRQ path.
//
// The legacy PIC stays masked; ISA/PCI IRQs instead reach us through the
// I/O APIC's redirection table, programmed from MADT entries. IOAPIC MMIO
// is an indirect register file: IOREGSEL (offset 0) picks the register,
// IOWIN (offset 0x10) reads/writes it.
// ---------------------------------------------------------------------------

const IOREGSEL: u64 = 0x00;
const IOWIN: u64 = 0x10;
/// I/O APIC register indexes.
const IOAPIC_ID: u32 = 0x00;
const IOAPIC_VER: u32 = 0x01;
const IOREDTBL: u32 = 0x10; // + 2*gsi low dword, +1 high dword

static IOAPIC_BASE: AtomicU64 = AtomicU64::new(0);

fn ioapic_read(reg: u32) -> u32 {
    let base = crate::mm::pmap(IOAPIC_BASE.load(Ordering::Relaxed));
    // SAFETY: base was programmed from the MADT I/O APIC address (<4 GiB
    // on PC, covered by the physmap); IOREGSEL/IOWIN are 32-bit regs.
    unsafe {
        ((base + IOREGSEL) as *mut u32).write_volatile(reg);
        ((base + IOWIN) as *const u32).read_volatile()
    }
}

fn ioapic_write(reg: u32, v: u32) {
    let base = crate::mm::pmap(IOAPIC_BASE.load(Ordering::Relaxed));
    unsafe {
        ((base + IOREGSEL) as *mut u32).write_volatile(reg);
        ((base + IOWIN) as *mut u32).write_volatile(v);
    }
}

/// Our LAPIC ID in the form the I/O APIC redirection entries take (8-bit
/// physical destination). x2APIC IDs wider than 8 bits can't be expressed
/// — QEMU's BSP is 0 either way; documented limitation until we route
/// logical destinations.
pub fn lapic_id() -> u32 {
    if X2APIC.load(Ordering::Relaxed) {
        // SAFETY: x2APIC confirmed in init().
        unsafe { rdmsr(0x802).0 }
    } else {
        lread(LAPIC_ID) >> 24
    }
}

/// Program one I/O APIC redirection entry: `gsi` -> `vec`, fixed delivery,
/// physical destination = our LAPIC. `iso_flags` carries the MADT override
/// (bits 1:0 polarity: 1=high 3=low; bits 3:2 trigger: 1=edge 3=level;
/// 00 = conform -> ISA default edge/active-high). The entry is written
/// masked-then-unmasked so a stale line can't fire mid-program.
///
/// Returns false without touching MMIO when the MADT-supplied values are
/// implausible — a corrupt table must not turn our IOREGSEL/IOWIN writes
/// into a scribble over ordinary RAM: the base must be page-aligned in
/// the high (PCI-hole) region and the GSI inside the hardware's
/// redirection-entry count.
pub fn ioapic_route(ioapic_addr: u64, gsi: u32, vec: u64, iso_flags: u16) -> bool {
    if ioapic_addr & 0xfff != 0 || !(0x8000_0000..=0xffff_f000).contains(&ioapic_addr) {
        return false;
    }
    IOAPIC_BASE.store(ioapic_addr, Ordering::Relaxed);
    let redirs = ((ioapic_read(IOAPIC_VER) >> 16) & 0xff) + 1;
    if gsi >= redirs {
        return false;
    }

    let low = (vec as u32 & 0xff)
        | if iso_flags & 0x3 == 0x3 { 1 << 13 } else { 0 } // active-low
        | if iso_flags & 0xc == 0xc { 1 << 15 } else { 0 } // level-triggered
        | (1 << 16); // masked while we program the entry
    let high = (lapic_id() & 0xff) << 24;
    let reg = IOREDTBL + 2 * gsi;
    // Mask -> program -> unmask: the entry must never be live with a
    // half-written (new dest, old vector) combination.
    ioapic_write(reg, low);
    ioapic_write(reg + 1, high);
    ioapic_write(reg, low & !(1 << 16)); // unmask: deliver
    true
}

/// Arm PIT channel 0 as a periodic source on the IRQ0 pin — mode 2 rate
/// generator (IRQ fires each cycle), ~`hz` ticks per second. The line
/// reaches us through the I/O APIC entry routed above.
pub fn arm_pit(hz: u64) {
    let div = (PIT_HZ as u64 / hz).clamp(1, 0xffff) as u16;
    unsafe {
        outb(0x43, 0x34); // ch0, lo/hi, mode 2 rate generator
        outb(0x40, (div & 0xff) as u8);
        outb(0x40, (div >> 8) as u8);
    }
}

/// (I)OAPIC self-check value for the boot log: id register, version +
/// max redirection entry, and our destination LAPIC id.
pub fn ioapic_probe() -> (u32, u32, u32) {
    (
        ioapic_read(IOAPIC_ID),
        ioapic_read(IOAPIC_VER),
        lapic_id() & 0xff,
    )
}
