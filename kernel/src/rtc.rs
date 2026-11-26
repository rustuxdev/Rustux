//! CMOS RTC wall clock + TSC frequency calibration.
//!
//! The RTC is read over ports 0x70/0x71 in BCD or binary mode (status
//! register B tells which). Port 0x70's bit 7 is the NMI mask — we
//! keep it set so reading the clock never unmasks an interrupt we do
//! not handle. `wall_epoch` anchors a boot epoch: unix seconds at
//! TICKS==0, so wall time stays monotonic with the LAPIC tick even if
//! the RTC itself jitters by a second across calls.
//!
//! `tsc_hz` measures rdtsc over the same PIT channel-2 window the
//! LAPIC calibration uses — needed for QueryPerformanceFrequency.

use crate::pio::{inb, outb};
use core::sync::atomic::{AtomicU64, Ordering};

static EPOCH_BASE: AtomicU64 = AtomicU64::new(0);
static TSC_HZ: AtomicU64 = AtomicU64::new(0);

fn rsel(r: u8) -> u8 {
    // SAFETY: port 0x70/0x71 are the RTC index/data registers; bit 7
    // of the index byte keeps NMI masked while we select registers.
    unsafe {
        outb(0x70, 0x80 | r);
        inb(0x71)
    }
}

fn dec(v: u8, bin: bool) -> u64 {
    if bin {
        v as u64
    } else {
        ((v >> 4) * 10 + (v & 0x0f)) as u64
    }
}

/// days since the Unix epoch for a civil date (Hinnant's algorithm).
fn days_from_civil(y: i64, m: u64, d: u64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = ((m + 9) % 12) as i64;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

/// (year, month, day, hour, min, sec, weekday 0=Sun) from the RTC —
/// None when the fields read back nonsense (no battery-backed clock).
pub fn rtc_datetime() -> Option<(u64, u64, u64, u64, u64, u64, u64)> {
    // Update-in-progress bit (reg A.7): the fields are only stable
    // while clear. Bound the spin so a dead RTC cannot hang boot.
    let mut spin = 0u32;
    while rsel(0x0a) & 0x80 != 0 {
        spin += 1;
        if spin > 4_000_000 {
            return None;
        }
    }
    let b = rsel(0x0b);
    let bin = b & 0x04 != 0;
    let h24 = b & 0x02 != 0;
    let sec = rsel(0x00);
    let min = rsel(0x02);
    let hr = rsel(0x04);
    let dow = rsel(0x06);
    let dom = rsel(0x07);
    let mon = rsel(0x08);
    let yr = rsel(0x09);
    let cen = rsel(0x32);
    let pm = hr & 0x80 != 0;
    let mut h = dec(hr & 0x7f, bin);
    if !h24 {
        h = match (pm, h) {
            (true, 12) => 12,
            (true, x) => x + 12,
            (false, 12) => 0,
            (false, x) => x,
        };
    }
    let y = {
        let c = dec(cen, bin);
        let yy = dec(yr, bin);
        if (19..=99).contains(&c) {
            c * 100 + yy
        } else {
            2000 + yy
        }
    };
    let (mo, d, mi, s) = (dec(mon, bin), dec(dom, bin), dec(min, bin), dec(sec, bin));
    let w = dec(dow, bin);
    if !(1..=12).contains(&mo)
        || !(1..=31).contains(&d)
        || h > 23
        || mi > 59
        || s > 59
        || !(1..=7).contains(&w)
        || !(2000..=2200).contains(&y)
    {
        return None;
    }
    Some((y, mo, d, h, mi, s, w - 1))
}

/// Unix seconds from the RTC — 0 when rtc_datetime finds no clock.
pub fn rtc_epoch() -> u64 {
    let Some((y, mo, d, h, mi, s, _)) = rtc_datetime() else {
        return 0;
    };
    (days_from_civil(y as i64, mo, d) as u64) * 86400 + h * 3600 + mi * 60 + s
}

/// Boot-anchored epoch base: unix seconds at TICKS==0. Lazily read
/// once — the tick counter then carries wall time monotonically.
/// 0 means "no RTC" and callers stay boot-relative.
fn epoch_base() -> u64 {
    let b = EPOCH_BASE.load(Ordering::Relaxed);
    if b != 0 {
        return b;
    }
    let e = rtc_epoch();
    if e == 0 {
        return 0;
    }
    let t = crate::apic::TICKS.load(Ordering::Relaxed);
    EPOCH_BASE.store(e.saturating_sub(t / 100), Ordering::Relaxed);
    EPOCH_BASE.load(Ordering::Relaxed)
}

/// clock_settime's write side: replace the epoch base so wall_now
/// reports the requested unix second forward — the tick delta keeps
/// time monotonic from there. No RTC hardware write: the base is
/// the wall clock here.
pub fn set_wall(sec: u64) {
    let t = crate::apic::TICKS.load(Ordering::Relaxed);
    EPOCH_BASE.store(sec.saturating_sub(t / 100), Ordering::Relaxed);
}

/// Wall time as (sec, nsec): epoch base + the 100 Hz tick. Without
/// an RTC this is the previous boot-relative behaviour — honest
/// fallback, not a fabricated date.
pub fn wall_now() -> (u64, u64) {
    let t = crate::apic::TICKS.load(Ordering::Relaxed);
    (epoch_base() + t / 100, (t % 100) * 10_000_000)
}

/// Inverse of days_from_civil: (year, month, day) from epoch days.
fn civil_from_days(z: i64) -> (i64, u64, u64) {
    let z = z + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m as u64, d as u64)
}

/// Wall time broken out as (y, mo, d, h, min, s, wday 0=Sun, ms).
pub fn wall_datetime() -> (u64, u64, u64, u64, u64, u64, u64, u64) {
    let (s, ns) = wall_now();
    let days = (s / 86400) as i64;
    let tod = s % 86400;
    let (y, mo, d) = civil_from_days(days);
    (
        y as u64,
        mo,
        d,
        tod / 3600,
        (tod % 3600) / 60,
        tod % 60,
        (days + 4).rem_euclid(7) as u64,
        ns / 1_000_000,
    )
}

/// rdtsc frequency in Hz, measured once over a ~10 ms PIT
/// channel-2 window (same trick apic::init uses for the LAPIC).
pub fn tsc_hz() -> u64 {
    let hz = TSC_HZ.load(Ordering::Relaxed);
    if hz != 0 {
        return hz;
    }
    const PIT_HZ: u128 = 1_193_182;
    const CAL: u64 = 11_932; // ~10 ms
    // SAFETY: PIT ch2 programming ports 0x43/0x42 + gate at 0x61; the
    // channel is unused after LAPIC calibration and this is the only
    // caller reprogramming it.
    let hz = unsafe {
        outb(0x43, 0xb0); // ch2, lo/hi, mode 0 one-shot
        let a = inb(0x61);
        outb(0x61, (a & 0xfc) | 0x01); // GATE2 on, speaker off
        outb(0x42, (CAL & 0xff) as u8);
        outb(0x42, (CAL >> 8) as u8);
        let t0 = core::arch::x86_64::_rdtsc();
        // Bound the wait on OUT2: this runs lazily from a user-
        // reachable syscall, so a dead PIT must not wedge the kernel.
        while inb(0x61) & 0x20 == 0 {
            if core::arch::x86_64::_rdtsc().wrapping_sub(t0) > 500_000_000 {
                return 0;
            }
        }
        let t1 = core::arch::x86_64::_rdtsc();
        ((t1 - t0) as u128 * PIT_HZ / CAL as u128) as u64
    };
    TSC_HZ.store(hz, Ordering::Relaxed);
    hz
}
