//! ata — ATA PIO driver for the primary IDE channel.
//!
//! QEMU's i440fx machine wires `-drive if=ide` to the PIIX3 IDE
//! controller on the classic 0x1F0/0x3F6 ports. The driver is pure
//! polled PIO: IDENTIFY at init, then LBA28 READ/WRITE SECTORS with
//! DRQ polling — no interrupts, no DMA. Every poll is hard-bounded
//! so a missing or wedged device can never hang a syscall.

use crate::log::printk;
use crate::pio::{inb, inl, outb, outl};

const IO: u16 = 0x1f0; // primary channel register block
const ALT: u16 = 0x3f6; // alternate status / device control
const IO2: u16 = 0x170; // secondary channel — QEMU parks -cdrom here

const ST_ERR: u8 = 0x01;
const ST_DRQ: u8 = 0x08;
const ST_BSY: u8 = 0x80;

const CMD_READ: u8 = 0x20;
const CMD_WRITE: u8 = 0x30;
const CMD_FLUSH: u8 = 0xe7;
const CMD_IDENTIFY: u8 = 0xec;
const CMD_PACKET: u8 = 0xa0; // ATAPI packet command

/// LBA28 sector count from IDENTIFY — zero when no disk answered.
static mut SECTORS: u32 = 0;

fn status() -> u8 {
    // SAFETY: fixed ISA port, read-only status.
    unsafe { inb(IO + 7) }
}

/// ~400 ns of settle time after a command reaches the device —
/// the spec demands it before status is meaningful, and four
/// alternate-status reads cover it at ISA port speed.
fn pause() {
    // SAFETY: read-only alternate status register.
    unsafe {
        inb(ALT);
        inb(ALT);
        inb(ALT);
        inb(ALT);
    }
}

/// Poll until BSY clears and, when `drq`, DRQ rises. ERR aborts.
/// The bound keeps a dead controller from spinning forever.
fn wait(drq: bool) -> bool {
    for _ in 0..1_000_000 {
        let s = status();
        if s & ST_ERR != 0 {
            return false;
        }
        if s & ST_BSY == 0 && (!drq || s & ST_DRQ != 0) {
            return true;
        }
    }
    printk(format_args!("rustux: ata: poll timeout (st={:#x})\n", status()));
    false
}

/// SRST the channel after a timeout — a desynced drive answers
/// every later command with a dead DRQ and each poll burns its
/// bound; a reset gives the next command a clean state.
fn reset() {
    // SAFETY: device-control register, serialized driver.
    unsafe {
        outb(ALT, 0x04);
        pause();
        outb(ALT, 0x00);
        pause();
    }
    let _ = wait(false);
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
    pause(); // status is undefined for ~400 ns after issue
}

/// Read one 512-byte sector at `lba` into `buf`.
pub fn read(lba: u32, buf: &mut [u8; 512]) -> bool {
    if sectors() == 0 || lba >= sectors() || !wait(false) {
        return false;
    }
    cmd(lba, 1, CMD_READ);
    if !wait(true) {
        reset(); // unwedge for the next command
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
/// image write take minutes instead of seconds. A timed-out
/// attempt resets the channel and retries once — a transient
/// wedge shouldn't cost the caller a failed write.
pub fn write(lba: u32, count: u32, buf: *const u8) -> bool {
    if try_write(lba, count, buf) {
        return true;
    }
    reset();
    try_write(lba, count, buf)
}

fn try_write(lba: u32, count: u32, buf: *const u8) -> bool {
    let total = sectors();
    if count == 0 || count > 256 || lba >= total || lba + count > total || !wait(false) {
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
    pause();
    wait(false)
}

/// Eject the ATAPI drive on the secondary channel — the -cdrom
/// medium QEMU's i440fx wires as secondary master. START STOP
/// UNIT with LoEj set and Start clear opens the tray, exactly
/// like a real installer's final "remove the media" step. The
/// CDB goes out a word at a time like data-register PIO.
pub fn eject() -> bool {
    fn stat2() -> u8 {
        // SAFETY: fixed ISA port, read-only status.
        unsafe { inb(IO2 + 7) }
    }
    // No controller floats the bus at 0xFF.
    if stat2() == 0xff {
        return false;
    }
    // SAFETY: secondary-channel registers, serialized syscall path.
    unsafe {
        outb(IO2 + 6, 0xa0); // master
        outb(IO2 + 1, 0); // no DMA
        outb(IO2 + 4, 0);
        outb(IO2 + 5, 0); // byte count: unused for this packet
        outb(IO2 + 7, CMD_PACKET);
    }
    let mut drq = false;
    for _ in 0..1_000_000 {
        let s = stat2();
        if s & ST_ERR != 0 {
            return false;
        }
        if s & (ST_BSY | ST_DRQ) == ST_DRQ {
            drq = true;
            break;
        }
    }
    if !drq {
        return false;
    }
    // START STOP UNIT (0x1B): byte 4 LoEj|Start — 0b10 ejects.
    let cdb: [u16; 6] = [0x001b, 0, 0, 0x0002, 0, 0];
    for w in cdb {
        // SAFETY: DRQ is asserted for the packet's 12 bytes.
        unsafe { crate::pio::outw(IO2, w) };
    }
    for _ in 0..1_000_000 {
        let s = stat2();
        if s & ST_ERR != 0 {
            return false;
        }
        if s & ST_BSY == 0 {
            return true;
        }
    }
    false
}
