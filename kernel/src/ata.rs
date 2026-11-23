//! ata — ATA PIO driver for the primary IDE channel.
//!
//! QEMU's i440fx machine wires `-drive if=ide` to the PIIX3 IDE
//! controller on the classic 0x1F0/0x3F6 ports. The driver is pure
//! polled PIO: IDENTIFY at init, then LBA28 READ/WRITE SECTORS with
//! DRQ polling — no interrupts, no DMA. Every poll is hard-bounded
//! so a missing or wedged device can never hang a syscall.

use crate::pio::{inb, inl, outb, outl};

const IO: u16 = 0x1f0; // primary channel register block

const ST_ERR: u8 = 0x01;
const ST_DRQ: u8 = 0x08;
const ST_BSY: u8 = 0x80;

const CMD_READ: u8 = 0x20;
const CMD_WRITE: u8 = 0x30;
const CMD_FLUSH: u8 = 0xe7;
const CMD_IDENTIFY: u8 = 0xec;

/// LBA28 sector count from IDENTIFY — zero when no disk answered.
static mut SECTORS: u32 = 0;

fn status() -> u8 {
    // SAFETY: fixed ISA port, read-only status.
    unsafe { inb(IO + 7) }
}

/// Poll until BSY clears and, when `drq`, DRQ rises. ERR aborts.
/// The bound keeps a dead controller from spinning forever.
fn wait(drq: bool) -> bool {
    for _ in 0..4_000_000 {
        let s = status();
        if s & ST_ERR != 0 {
            return false;
        }
        if s & ST_BSY == 0 && (!drq || s & ST_DRQ != 0) {
            return true;
        }
    }
    false
}

/// Probe the primary master with IDENTIFY. Returns the LBA28 sector
/// count — 0 means no ATA disk (the count is also the `sectors()`
/// answer, so /dev/sda stays absent then).
pub fn init() -> u32 {
    // A floating bus reads 0xFF on every port — no controller at all.
    if status() == 0xff {
        return 0;
    }
    // SAFETY: classic primary-channel ports, single-threaded boot.
    unsafe {
        outb(IO + 6, 0xa0); // master, LBA preamble bits irrelevant here
        outb(IO + 2, 0);
        outb(IO + 3, 0);
        outb(IO + 4, 0);
        outb(IO + 5, 0);
        outb(IO + 7, CMD_IDENTIFY);
    }
    if status() == 0 || !wait(true) {
        return 0;
    }
    // ATAPI packet devices raise the LBA-mid/high signature — those
    // are CD-ROMs, not disks we can sector-I/O.
    if unsafe { inb(IO + 4) } != 0 || unsafe { inb(IO + 5) } != 0 {
        return 0;
    }
    let mut id = [0u32; 128];
    for w in &mut id {
        // SAFETY: DRQ says a sector of IDENTIFY data is ready.
        *w = unsafe { inl(IO) };
    }
    // SAFETY: 128 dwords is exactly the 512-byte IDENTIFY page.
    let b = unsafe { core::slice::from_raw_parts(id.as_ptr() as *const u8, 512) };
    // Words 60/61 hold the LBA28 capacity in native (little-endian)
    // byte order — byte offset 120.
    let secs = u32::from_le_bytes([b[120], b[121], b[122], b[123]]);
    if secs == 0 {
        return 0;
    }
    // LBA28 addresses 28 bits of LBA — a larger disk is clamped
    // rather than silently aliasing sector 0x10000000+ onto low LBAs.
    let secs = secs.min(0x1000_0000);
    // SAFETY: single-threaded init.
    unsafe { SECTORS = secs };
    secs
}

/// LBA28 capacity in sectors; 0 when the probe found no disk.
pub fn sectors() -> u32 {
    // SAFETY: written once at init before tasks exist.
    unsafe { SECTORS }
}

/// Capacity in bytes — the /dev/sda SEEK_END base.
pub fn capacity() -> u64 {
    sectors() as u64 * 512
}

/// Set the task registers and issue a sector command.
fn cmd(lba: u32, secs: u8, c: u8) {
    // SAFETY: primary-channel registers, serialized syscalls.
    unsafe {
        outb(IO + 6, 0xe0 | ((lba >> 24) as u8 & 0x0f)); // master + LBA28
        outb(IO + 2, secs);
        outb(IO + 3, lba as u8);
        outb(IO + 4, (lba >> 8) as u8);
        outb(IO + 5, (lba >> 16) as u8);
        outb(IO + 7, c);
    }
}

/// Read one 512-byte sector at `lba` into `buf`.
pub fn read(lba: u32, buf: &mut [u8; 512]) -> bool {
    if sectors() == 0 || lba >= sectors() || !wait(false) {
        return false;
    }
    cmd(lba, 1, CMD_READ);
    if !wait(true) {
        return false;
    }
    // SAFETY: 128 dwords is one sector; DRQ is asserted.
    let d = unsafe { core::slice::from_raw_parts_mut(buf.as_mut_ptr() as *mut u32, 128) };
    for w in d {
        *w = unsafe { inl(IO) };
    }
    true
}

/// Write `count` sectors (1..=256) starting at `lba` from `buf`
/// (count*512 bytes). One command, one FLUSH CACHE at the end —
/// flushing per sector costs a cache commit each and makes an
/// image write take minutes instead of seconds.
pub fn write(lba: u32, count: u32, buf: *const u8) -> bool {
    let total = sectors();
    if count == 0 || count > 256 || lba >= total
        || lba + count > total || !wait(false)
    {
        return false;
    }
    cmd(lba, count as u8, CMD_WRITE);
    for s in 0..count as usize {
        if !wait(true) {
            return false;
        }
        // SAFETY: DRQ is asserted for this sector; `buf` covers
        // count*512 bytes per the contract.
        let d = unsafe {
            core::slice::from_raw_parts(buf.add(s * 512) as *const u32, 128)
        };
        for w in d {
            unsafe { outl(IO, *w) };
        }
    }
    // The write completes when BSY falls after the last sector;
    // FLUSH CACHE then pushes it to the medium.
    if !wait(false) {
        return false;
    }
    unsafe { outb(IO + 7, CMD_FLUSH) };
    wait(false)
}
