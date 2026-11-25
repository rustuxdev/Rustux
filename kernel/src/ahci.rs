//! ahci — AHCI (SATA) host controller: port scan, IDENTIFY, DMA I/O.
//!
//! q35 and real machines expose disks through AHCI, not the legacy
//! PIIX ports ata.rs drives (`if=ide` lands on AHCI there, which is
//! why ata reports sda=0MiB on q35). This module finds the controller,
//! brings up its ports and identifies each attached ATA disk so the
//! installer can offer real SATA hardware.
//!
//! MMIO goes through mm::pmap: the physmap mirrors 0..4 GiB, which
//! covers the ABAR (the e1000 driver does the same).

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use crate::kalloc;
use crate::mm;
use crate::pci;

// HBA registers.
const CAP: u64 = 0x00;
const GHC: u64 = 0x04;
const PI: u64 = 0x0c;
const PORT_BASE: u64 = 0x100;
const PORT_STRIDE: u64 = 0x80;

// Port registers.
const PXCLB: u64 = 0x00;
const PXFB: u64 = 0x08;
const PXIS: u64 = 0x10;
const PXIE: u64 = 0x14;
const PXCMD: u64 = 0x18;
const PXTFD: u64 = 0x20;
const PXSIG: u64 = 0x24;
const PXSSTS: u64 = 0x28;
const PXCI: u64 = 0x38;

const SIG_ATA: u32 = 0x0000_0101;
const CMD_ST: u32 = 1 << 0;
const CMD_FRE: u32 = 1 << 4;
const CMD_FR: u32 = 1 << 14;
const CMD_CR: u32 = 1 << 15;
const TFD_ERR: u32 = 1 << 0;
const TFD_DRQ: u32 = 1 << 3;
const TFD_BSY: u32 = 1 << 7;

/// ATA commands we issue.
const ATA_IDENTIFY: u8 = 0xec;
const ATA_READ_DMA_EXT: u8 = 0x25;
const ATA_WRITE_DMA_EXT: u8 = 0x35;

/// Up to 8 disks is plenty for an installer's target picker.
pub const MAX_DISKS: usize = 8;

static ABAR: AtomicU64 = AtomicU64::new(0);
static NDISKS: AtomicU32 = AtomicU32::new(0);
/// Port number backing each discovered disk (index -> HBA port).
static DISK_PORT: [AtomicU32; MAX_DISKS] = [
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
];
/// LBA48 sector count per discovered disk.
static DISK_SECTORS: [AtomicU32; MAX_DISKS] = [
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
];

fn r32(off: u64) -> u32 {
    let base = ABAR.load(Ordering::Relaxed);
    // SAFETY: ABAR is an MMIO window confirmed by the caller's
    // is_mmio probe; pmap maps it through the physmap mirror.
    unsafe { ((mm::pmap(base) as usize + off as usize) as *const u32).read_volatile() }
}

fn w32(off: u64, v: u32) {
    let base = ABAR.load(Ordering::Relaxed);
    // SAFETY: as above.
    unsafe { ((mm::pmap(base) as usize + off as usize) as *mut u32).write_volatile(v) }
}

fn port_reg(p: usize, off: u64) -> u64 {
    PORT_BASE + (p as u64) * PORT_STRIDE + off
}

/// Find an AHCI controller: PCI class 0x01 (storage), subclass 0x06
/// (SATA), programming interface 0x01 (AHCI).
fn find_controller() -> Option<(u8, u8, u8)> {
    for bus in 0u16..=255 {
        for dev in 0u8..32 {
            for f in 0u8..8 {
                let id = pci::read32(bus as u8, dev, f, 0);
                if id & 0xffff == 0xffff {
                    continue;
                }
                let class = pci::read32(bus as u8, dev, f, 0x08);
                let cls = (class >> 24) & 0xff;
                let sub = (class >> 16) & 0xff;
                let pi = (class >> 8) & 0xff;
                if cls == 0x01 && sub == 0x06 && pi == 0x01 {
                    return Some((bus as u8, dev, f));
                }
            }
        }
    }
    None
}

/// One port's scratch memory: command list (1 KiB), FIS (256 B) and
/// one command table (256 B) plus a data buffer. All frames come from
/// the physical allocator, so the HBA can DMA into them.
struct PortMem {
    cl: u64,   // command list phys
    fis: u64,  // FIS phys
    ct: u64,   // command table phys
    buf: u64,  // 512-byte data buffer phys
}

/// Cached scratch per disk. Allocating per command leaked four frames
/// every 4 KiB (a 64 KiB write cost 64 frames) and starved the
/// allocator mid-install.
static mut MEM: [Option<PortMem>; MAX_DISKS] = [
    None, None, None, None, None, None, None, None,
];

fn mem_for(i: usize) -> Option<&'static PortMem> {
    // SAFETY: single-threaded syscall context, like the rest of the
    // driver's statics.
    unsafe {
        let slot = &mut *core::ptr::addr_of_mut!(MEM);
        if slot[i].is_none() {
            slot[i] = port_mem();
        }
        slot[i].as_ref()
    }
}

fn port_mem() -> Option<PortMem> {
    Some(PortMem {
        cl: kalloc::alloc_frame()?,
        fis: kalloc::alloc_frame()?,
        ct: kalloc::alloc_frame()?,
        buf: kalloc::alloc_frame()?,
    })
}

fn phys_ptr(p: u64) -> *mut u8 {
    mm::pmap(p) as *mut u8
}

fn zero(p: u64, n: usize) {
    // SAFETY: p is a frame we just allocated.
    unsafe { core::ptr::write_bytes(phys_ptr(p), 0, n) }
}

/// Bring one port out of reset and park it idle.
fn port_stop(p: usize) -> bool {
    let cmd = port_reg(p, PXCMD);
    w32(cmd, r32(cmd) & !(CMD_ST | CMD_FRE));
    for _ in 0..100_000u32 {
        let c = r32(cmd);
        if c & (CMD_CR | CMD_FR) == 0 {
            return true;
        }
        core::hint::spin_loop();
    }
    false
}

/// Issue one ATA command and wait for it to finish. `write` selects
/// the direction for the DMA setup.
fn issue(p: usize, m: &PortMem, cmd: u8, lba: u64, count: u16, write: bool) -> bool {
    zero(m.cl, 1024);
    zero(m.fis, 256);
    zero(m.ct, 256);

    // Register H2D FIS: type, flags (C=1), command, LBA48 fields.
    // SAFETY: m.fis is our frame.
    unsafe {
        let f = phys_ptr(m.fis);
        *f = 0x27; // FIS_TYPE_REG_H2D
        *f.add(1) = 0x80; // C = 1 (command, not control)
        *f.add(2) = cmd;
        *f.add(4) = (lba & 0xff) as u8;
        *f.add(5) = ((lba >> 8) & 0xff) as u8;
        *f.add(6) = ((lba >> 16) & 0xff) as u8;
        *f.add(7) = 0x40; // LBA mode
        *f.add(8) = ((lba >> 24) & 0xff) as u8;
        *f.add(9) = ((lba >> 32) & 0xff) as u8;
        *f.add(10) = ((lba >> 40) & 0xff) as u8;
        *f.add(12) = (count & 0xff) as u8;
        *f.add(13) = ((count >> 8) & 0xff) as u8;
    }

    // Command list entry 0: CFL=5 dwords, one PRDT entry, prefetch.
    // SAFETY: m.cl is our frame.
    unsafe {
        let cl = phys_ptr(m.cl) as *mut u32;
        // DW0: CFL=5 dwords, PRDTL=1, P=1, and W (bit 6) for a
        // host->device transfer. Bit 5 is A (ATAPI) — setting that
        // instead marked every write as an ATAPI packet command, which
        // is why IDENTIFY (W=0, A=0) worked while every write silently
        // transferred nothing.
        let w_bit = if write { 1 << 6 } else { 0 };
        cl.write_volatile(5 | w_bit | (1 << 16) | (1 << 31));
        cl.add(1).write_volatile(0);
        cl.add(2).write_volatile(m.ct as u32);
        cl.add(3).write_volatile((m.ct >> 32) as u32);
    }

    // Command table: 64-byte CFIS, 16-byte ACMD, then the PRDT at 0x80.
    // SAFETY: m.ct is our frame; the FIS copy is 20 bytes of a 64-byte slot.
    unsafe {
        let ct = phys_ptr(m.ct);
        core::ptr::copy_nonoverlapping(phys_ptr(m.fis), ct, 20);
        let prdt = ct.add(0x80) as *mut u32;
        prdt.write_volatile(m.buf as u32);
        prdt.add(1).write_volatile((m.buf >> 32) as u32);
        prdt.add(2).write_volatile(0);
        prdt.add(3).write_volatile(((count as u32) * 512 - 1) & 0x3f_ffff);
    }

    // Per spec the command-list and FIS base registers may only be
    // written while the port is STOPPED (PxCMD.ST = 0 and CR clear);
    // writes while ST is set are ignored. Stop, program, then start
    // once — the previous order set ST and rewrote the bases on every
    // command.
    let cmd_r = port_reg(p, PXCMD);
    w32(cmd_r, r32(cmd_r) & !CMD_ST);
    for _ in 0..100_000u32 {
        if r32(cmd_r) & CMD_CR == 0 {
            break;
        }
        core::hint::spin_loop();
    }
    w32(port_reg(p, PXCLB), m.cl as u32);
    w32(port_reg(p, PXCLB) + 4, (m.cl >> 32) as u32);
    w32(port_reg(p, PXFB), m.fis as u32);
    w32(port_reg(p, PXFB) + 4, (m.fis >> 32) as u32);
    w32(cmd_r, r32(cmd_r) | CMD_FRE | CMD_ST);
    // Clear pending status, then ring the doorbell for slot 0.
    w32(port_reg(p, PXIS), 0xffff_ffff);
    w32(port_reg(p, PXCI), 1);

    // Wait for the command to retire (PxCI bit 0 clear) or an error.
    let tfd_r = port_reg(p, PXTFD);
    let ci_r = port_reg(p, PXCI);
    for _ in 0..2_000_000u32 {
        let tfd = r32(tfd_r);
        if tfd & TFD_ERR != 0 {
            return false;
        }
        if r32(ci_r) & 1 == 0 {
            return !write || true;
        }
        core::hint::spin_loop();
    }
    false
}

/// IDENTIFY a port's disk and return its LBA48 sector count.
fn identify(p: usize) -> Option<u32> {
    let m = port_mem()?;
    if !port_stop(p) {
        return None;
    }
    if !issue(p, &m, ATA_IDENTIFY, 0, 1, false) {
        return None;
    }
    // Words 100..103 hold the LBA48 sector count.
    // SAFETY: m.buf is our frame, filled by the HBA.
    let b = unsafe { core::slice::from_raw_parts(phys_ptr(m.buf), 512) };
    let w = |i: usize| u16::from_le_bytes([b[i * 2], b[i * 2 + 1]]) as u64;
    let lba48 = w(100) | (w(101) << 16) | (w(102) << 32) | (w(103) << 48);
    let lba28 = w(60) | (w(61) << 16);
    let secs = if lba48 != 0 { lba48 } else { lba28 };
    if secs == 0 {
        return None;
    }
    Some(secs.min(u32::MAX as u64) as u32)
}

/// Probe the controller and fill the disk table. Returns the disk
/// count. `is_mmio` must confirm the ABAR is device memory.
pub fn init(is_mmio: impl Fn(u64, u64) -> bool) -> u32 {
    let Some((bus, dev, fun)) = find_controller() else {
        return 0;
    };
    pci::command_or(bus, dev, fun, pci::CMD_MEM_SPACE | pci::CMD_BUS_MASTER);
    let bar = pci::bar_raw(bus, dev, fun, 5);
    if bar & 1 != 0 {
        return 0; // I/O-space BAR — not an AHCI controller
    }
    let base = (bar & !0xf) as u64;
    if base == 0 || !is_mmio(base, 0x1100) {
        return 0;
    }
    ABAR.store(base, Ordering::Relaxed);
    // AE: enable AHCI mode.
    let ghc = r32(GHC);
    w32(GHC, ghc | (1 << 31));

    let pi = r32(PI);
    let mut n = 0usize;
    for p in 0..32usize {
        if pi & (1 << p) == 0 || n >= MAX_DISKS {
            continue;
        }
        let ssts = r32(port_reg(p, PXSSTS));
        if ssts & 0xf != 3 {
            continue; // no device, or not established
        }
        if r32(port_reg(p, PXSIG)) != SIG_ATA {
            continue; // ATAPI/port multiplier — not a disk we DMA to
        }
        if let Some(secs) = identify(p) {
            DISK_PORT[n].store(p as u32, Ordering::Relaxed);
            DISK_SECTORS[n].store(secs, Ordering::Relaxed);
            n += 1;
        }
    }
    NDISKS.store(n as u32, Ordering::Relaxed);
    crate::log::printk(format_args!("rustux: ahci: {} disk(s) on {:#x}", n, base));
    n as u32
}

pub fn disks() -> u32 {
    NDISKS.load(Ordering::Relaxed)
}

pub fn disk_sectors(i: usize) -> u32 {
    if i >= MAX_DISKS {
        return 0;
    }
    DISK_SECTORS[i].load(Ordering::Relaxed)
}

pub fn disk_capacity(i: usize) -> u64 {
    disk_sectors(i) as u64 * 512
}

/// Sectors per command: the data frame is 4 KiB, so 8 sectors fit
/// one PRDT entry. Batching is what makes an image install take
/// seconds instead of minutes (one polled command per sector would be
/// ~131k commands for a 67 MB image).
pub const BATCH: usize = 8;

/// Read `count` sectors (1..=BATCH) starting at `lba` into `buf`,
/// which must hold count*512 bytes.
pub fn read_range(i: usize, lba: u64, count: usize, buf: &mut [u8]) -> bool {
    if i >= MAX_DISKS || count == 0 || count > BATCH || buf.len() < count * 512 {
        return false;
    }
    if disk_sectors(i) == 0 || lba + count as u64 > disk_sectors(i) as u64 {
        return false;
    }
    let p = DISK_PORT[i].load(Ordering::Relaxed) as usize;
    let Some(m) = mem_for(i) else { return false };
    if !issue(p, m, ATA_READ_DMA_EXT, lba, count as u16, false) {
        return false;
    }
    // SAFETY: m.buf is our 4 KiB frame, filled by the HBA.
    unsafe {
        core::ptr::copy_nonoverlapping(phys_ptr(m.buf), buf.as_mut_ptr(), count * 512);
    }
    true
}

/// Write `count` sectors (1..=BATCH) from `buf`.
pub fn write_range(i: usize, lba: u64, count: usize, buf: &[u8]) -> bool {
    if i >= MAX_DISKS || count == 0 || count > BATCH || buf.len() < count * 512 {
        return false;
    }
    if disk_sectors(i) == 0 || lba + count as u64 > disk_sectors(i) as u64 {
        return false;
    }
    let p = DISK_PORT[i].load(Ordering::Relaxed) as usize;
    let Some(m) = mem_for(i) else { return false };
    // SAFETY: m.buf is our 4 KiB frame; buf holds count*512 bytes.
    unsafe {
        core::ptr::copy_nonoverlapping(buf.as_ptr(), phys_ptr(m.buf), count * 512);
    }
    issue(p, m, ATA_WRITE_DMA_EXT, lba, count as u16, true)
}

/// Read one 512-byte sector from disk `i`.
pub fn read_sector(i: usize, lba: u64, buf: &mut [u8; 512]) -> bool {
    if i >= MAX_DISKS || disk_sectors(i) == 0 {
        return false;
    }
    let p = DISK_PORT[i].load(Ordering::Relaxed) as usize;
    let Some(m) = mem_for(i) else { return false };
    if !issue(p, m, ATA_READ_DMA_EXT, lba, 1, false) {
        return false;
    }
    // SAFETY: m.buf is our frame, filled by the HBA.
    unsafe {
        core::ptr::copy_nonoverlapping(phys_ptr(m.buf), buf.as_mut_ptr(), 512);
    }
    true
}

/// Write one 512-byte sector to disk `i`.
pub fn write_sector(i: usize, lba: u64, buf: &[u8; 512]) -> bool {
    if i >= MAX_DISKS || disk_sectors(i) == 0 {
        return false;
    }
    let p = DISK_PORT[i].load(Ordering::Relaxed) as usize;
    let Some(m) = mem_for(i) else { return false };
    // SAFETY: m.buf is our frame; the caller's buffer is 512 bytes.
    unsafe {
        core::ptr::copy_nonoverlapping(buf.as_ptr(), phys_ptr(m.buf), 512);
    }
    issue(p, m, ATA_WRITE_DMA_EXT, lba, 1, true)
}
