//! log — printk-style logging: a `klib::prb` ring of (text + metadata)
//! records, plus a drain that writes them to the consoles.
//!
//! This is the real printk split from Linux: writers append into the
//! ring and a separate flush pulls records to the console devices when
//! the main context runs. The C ringbuffer arbitrates concurrent
//! writers with cmpxchg; our verified port is its *sequential* model,
//! so every ring op runs inside irqsave/irqrestore — the same way
//! `kalloc` serializes its freelists. That makes `printk` callable from
//! IRQ context: an IRQ-side append can't tear a main-side reserve.
//!
//! Panic deliberately bypasses the ring — a corrupt ring must not take
//! the report down with it. The handler writes straight to the stored
//! console (or a fresh UART as fallback) and parks the CPU.

use crate::pio::{irq_restore, irq_save};
use crate::Console;
use core::fmt::Write;
use core::sync::atomic::{AtomicU64, Ordering};
use klib::prb::*;

const TEXT_BITS: u32 = 12; // 4 KiB text ring
const DESC_BITS: u32 = 4; // 16 descriptors in flight

static mut TEXT: [u8; 1 << TEXT_BITS] = [0; 1 << TEXT_BITS];
// PrintkInfo/PrbDesc Default impls are all-zero — zeroed is a valid init.
static mut DESCS: [PrbDesc; 1 << DESC_BITS] = unsafe { core::mem::zeroed() };
static mut INFOS: [PrintkInfo; 1 << DESC_BITS] = unsafe { core::mem::zeroed() };
static mut PRB: Option<Prb<'static>> = None;

/// Next sequence number the drain will read.
static NEXT_SEQ: AtomicU64 = AtomicU64::new(0);
/// Records lost before init or on a failed reserve.
static DROPPED: AtomicU64 = AtomicU64::new(0);

/// The live console, stored by main so the panic path can flush to it.
static mut PANIC_CON: *mut Console = core::ptr::null_mut();

/// Build the ring over its static backing arrays. Call once, early.
pub fn init() {
    // SAFETY: single-threaded init; the statics are written once before
    // any printk can race them (and every later access is irqsave-guarded).
    unsafe {
        *core::ptr::addr_of_mut!(PRB) = Some(Prb::new(
            (*core::ptr::addr_of_mut!(TEXT)).as_mut_slice(),
            TEXT_BITS,
            (*core::ptr::addr_of_mut!(DESCS)).as_mut_slice(),
            DESC_BITS,
            (*core::ptr::addr_of_mut!(INFOS)).as_mut_slice(),
        ));
    }
}

/// Give the panic path a way to flush to the real console.
pub fn set_console(con: *mut Console) {
    // SAFETY: written once from main before IRQs are enabled.
    unsafe {
        *core::ptr::addr_of_mut!(PANIC_CON) = con;
    }
}

/// Records the ring dropped (pre-init or reserve failure).
pub fn dropped() -> u64 {
    DROPPED.load(Ordering::Relaxed)
}

/// Records successfully drained to the console.
pub fn drained() -> u64 {
    NEXT_SEQ.load(Ordering::Relaxed)
}

const MAX_LINE: usize = 240;

/// Stack-bounded formatting sink — records never exceed one line.
struct Sink {
    buf: [u8; MAX_LINE],
    len: usize,
}
impl Write for Sink {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let n = s.len().min(MAX_LINE - self.len);
        self.buf[self.len..self.len + n].copy_from_slice(&s.as_bytes()[..n]);
        self.len += n;
        Ok(())
    }
}

/// Append a formatted record. Safe in any context: the reserve/commit
/// sequence runs with IRQs masked (sequential-model ring), and the
/// returned timestamp stamps the record at append time.
pub fn printk(args: core::fmt::Arguments) {
    let mut s = Sink {
        buf: [0; MAX_LINE],
        len: 0,
    };
    let _ = s.write_fmt(args);
    if s.len == 0 {
        return;
    }
    let f = irq_save();
    // SAFETY: IRQs masked — sole writer against a sequential-model ring.
    unsafe {
        match (*core::ptr::addr_of_mut!(PRB)).as_mut() {
            Some(prb) => {
                let mut e = PrbReservedEntry::default();
                let mut r = PrintkRecord::wr(s.len as u32);
                if prb.reserve(&mut e, &mut r) {
                    if let Some(buf) = prb.text_buf_mut(&r) {
                        buf[..s.len].copy_from_slice(&s.buf[..s.len]);
                    }
                    if let Some(info) = prb.info_mut(&r) {
                        info.text_len = s.len as u16;
                        info.ts_nsec = crate::apic::TICKS
                            .load(Ordering::Relaxed)
                            .saturating_mul(10_000_000);
                    }
                    prb.final_commit(&e);
                } else {
                    DROPPED.fetch_add(1, Ordering::Relaxed);
                }
            }
            None => {
                DROPPED.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
    // SAFETY: f was produced by the matching irq_save above.
    unsafe { irq_restore(f) };
}

/// Flush every pending record to the console — call only from the main
/// context (the panic path does its own direct write). One record per
/// critical section so a long backlog can't stall IRQ delivery.
pub fn drain(con: &mut Console) {
    let mut info = PrintkInfo::default();
    let mut buf = [0u8; MAX_LINE];
    loop {
        let f = irq_save();
        // SAFETY: IRQs masked — sole reader against the sequential ring.
        let got = unsafe {
            match (*core::ptr::addr_of_mut!(PRB)).as_mut() {
                Some(prb) => prb.read_valid(
                    NEXT_SEQ.load(Ordering::Relaxed),
                    Some(&mut info),
                    Some(&mut buf[..]),
                ),
                None => false,
            }
        };
        if got {
            NEXT_SEQ.fetch_add(1, Ordering::Relaxed);
        }
        unsafe { irq_restore(f) };
        if !got {
            break;
        }
        let text = core::str::from_utf8(&buf[..info.text_len as usize])
            .unwrap_or("<bad utf8>");
        let _ = writeln!(
            con,
            "[{:>4}.{:03}] {}",
            info.ts_nsec / 1_000_000_000,
            (info.ts_nsec / 1_000_000) % 1000,
            text
        );
    }
}

/// User-space console output (tty writes): goes straight to uart+fb
/// verbatim — no ring, no kernel-log timestamp prefix. A real tty never
/// stamps user output; without this the record prefix corrupts
/// full-screen apps' cell layout (htop's cursor-addressed draws).
/// Same context rule as drain_task: syscall entry masks IF, and the
/// sole drainer argument applies to direct console access here too.
pub fn user_out(s: &str) {
    let con = unsafe { *core::ptr::addr_of!(PANIC_CON) };
    if con.is_null() {
        return;
    }
    // SAFETY: sole writer by the argument above; con outlives tasks.
    unsafe {
        let _ = (*con).write_str(s);
    }
}

/// /dev/fb0 backend — (width, height, stride_px, bgr) or None when the
/// console is serial-only.
pub fn fb_geometry() -> Option<(u32, u32, u32, bool)> {
    let con = unsafe { *core::ptr::addr_of!(PANIC_CON) };
    if con.is_null() {
        return None;
    }
    unsafe { (*con).fb.as_ref().map(|f| f.fb_info()) }
}

/// Mapped framebuffer byte length — /dev/fb0's capacity for lseek/write.
pub fn fb_byte_len() -> usize {
    let con = unsafe { *core::ptr::addr_of!(PANIC_CON) };
    if con.is_null() {
        return 0;
    }
    unsafe { (*con).fb.as_ref().map_or(0, |f| f.fb_byte_len()) }
}

/// Copy user bytes into the framebuffer at `off`; bytes written.
/// Same sole-drainer argument as user_out: syscall entry masks IF, so
/// the LAPIC tick can't interleave a text render with a pixel blit.
pub fn fb_write(off: usize, data: &[u8]) -> usize {
    let con = unsafe { *core::ptr::addr_of!(PANIC_CON) };
    if con.is_null() {
        return 0;
    }
    unsafe { (*con).fb.as_mut().map_or(0, |f| f.fb_write_at(off, data)) }
}

/// Read framebuffer bytes back — Linux fbdev permits reads.
pub fn fb_read(off: usize, dst: &mut [u8]) -> usize {
    let con = unsafe { *core::ptr::addr_of!(PANIC_CON) };
    if con.is_null() {
        return 0;
    }
    unsafe { (*con).fb.as_ref().map_or(0, |f| f.fb_read_at(off, dst)) }
}

/// Drain pending records from task/syscall context — needed now that
/// the scheduler keeps main parked inside sched_launch for the whole
/// task phase. Safe there: syscall entry masks IF (the LAPIC tick
/// can't interleave) and no main-context drainer exists meanwhile.
pub fn drain_task() {
    let con = unsafe { *core::ptr::addr_of!(PANIC_CON) };
    if con.is_null() {
        return;
    }
    // SAFETY: sole drainer by the argument above; con outlives tasks.
    unsafe { drain(&mut *con) };
}

/// Append + flush — the drop-in replacement for `writeln!(con, ...)`.
/// IRQ code should call `crate::log::printk` alone (never drain).
#[macro_export]
macro_rules! kprintln {
    ($con:expr, $($t:tt)*) => {{
        $crate::log::printk(format_args!($($t)*));
        $crate::log::drain(&mut $con);
    }};
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    // No ring, no locks: write straight to the live console when one was
    // registered, else fall back to a fresh polling UART. Either way the
    // report lands before the CPU parks.
    unsafe {
        core::arch::asm!("cli", options(nomem, nostack));
        let con = *core::ptr::addr_of!(PANIC_CON);
        if !con.is_null() {
            let _ = writeln!(*con, "rustux: PANIC: {info}");
        } else {
            let mut u = crate::uart::Uart16550::new(crate::uart::COM1);
            u.init();
            let _ = writeln!(u, "rustux: PANIC: {info}");
        }
        loop {
            core::arch::asm!("hlt", options(nomem, nostack));
        }
    }
}

/// — syslog(2)/klogctl reader side —
/// The syslog READ cursor: next record a type-2 read returns, shared
/// across callers like Linux's global `syslog_seq`. Independent of
/// NEXT_SEQ (the console drain position) — records stay in the ring
/// until wraparound evicts them either way.
static SYSLOG_SEQ: AtomicU64 = AtomicU64::new(0);

/// One past the newest committed record (0 when no ring yet).
pub fn kmsg_next() -> u64 {
    let f = irq_save();
    // SAFETY: IRQs masked — sequential-model ring.
    let s = unsafe {
        (*core::ptr::addr_of_mut!(PRB))
            .as_mut()
            .and_then(|prb| prb.next_reserve_seq())
            .unwrap_or_default()
    };
    unsafe { irq_restore(f) };
    s
}

/// The shared syslog read cursor.
pub fn syslog_seq() -> u64 {
    SYSLOG_SEQ.load(Ordering::Relaxed)
}

/// CLEAR/READ_CLEAR advance the read cursor past everything committed.
pub fn syslog_clear() {
    SYSLOG_SEQ.store(kmsg_next(), Ordering::Relaxed);
}

/// Render records `seq .. newest` as `text\n` lines through `push`,
/// stopping before the first record that no longer fits `cap` bytes.
/// Returns (bytes pushed, one past the last emitted seq). seq is
/// clamped up to the oldest live record — asking for long-evicted
/// records yields the readable tail, like Linux.
pub fn kmsg_render(seq: u64, cap: usize, push: &mut dyn FnMut(&[u8])) -> (usize, u64) {
    let f = irq_save();
    // SAFETY: IRQs masked — sequential-model ring, sole-reader shape
    // matches drain(). The mask is held across the render so `push`
    // sees a stable seq range; records are line-bounded and the ring
    // is 16 deep, so the critical section stays short.
    let (used, q) = unsafe {
        let prb = match (*core::ptr::addr_of_mut!(PRB)).as_mut() {
            Some(p) => p,
            None => {
                irq_restore(f);
                return (0, seq);
            }
        };
        let mut q = seq.max(prb.first_seq());
        let end = prb.next_reserve_seq().unwrap_or(q);
        let mut used = 0usize;
        let mut info = PrintkInfo::default();
        let mut buf = [0u8; MAX_LINE];
        while q < end {
            if !prb.read_valid(q, Some(&mut info), Some(&mut buf[..])) {
                break;
            }
            let n = info.text_len as usize;
            // Linux never splits a record: the whole text+'\n' must
            // fit the remaining budget or reading stops here.
            if n + 1 > cap - used {
                break;
            }
            push(&buf[..n]);
            push(b"\n");
            used += n + 1;
            q = info.seq + 1;
        }
        (used, q)
    };
    unsafe { irq_restore(f) };
    (used, q)
}

/// Advance the shared read cursor — done by READ (to just past the
/// last emitted record) and CLEAR/READ_CLEAR (to the newest seq).
/// READ_ALL does NOT move it, matching Linux's syslog_seq semantics.
pub fn syslog_set_seq(s: u64) {
    SYSLOG_SEQ.store(s, Ordering::Relaxed);
}

/// Byte count of records pending at the syslog cursor (type-9 probe).
pub fn kmsg_unread() -> usize {
    let mut n = 0usize;
    kmsg_render(
        SYSLOG_SEQ.load(Ordering::Relaxed),
        usize::MAX,
        &mut |line| {
            n += line.len();
        },
    )
    .0
}

/// Ring text capacity (type-10 probe).
pub fn kmsg_size() -> usize {
    1 << TEXT_BITS
}
