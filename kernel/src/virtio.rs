//! virtio-blk — transitional virtio-pci block driver.
//!
//! QEMU's `-drive if=virtio` attaches disks as PCI 1af4:1001
//! (transitional) devices with a legacy I/O-port BAR. That interface
//! needs no MSI-X and no capability-list walk: registers live in the
//! I/O BAR, requests go through one split virtqueue, and completion
//! is polled — same synchronous style as ata.rs, so this is an
//! adapter over already-proven mechanics, not a new concurrency
//! model.
//!
//! Layout of the queue at the page-aligned physical base `q`:
//!   q + 0                    descriptor table  (16 B * qsize)
//!   q + 16*qsize             available ring    (flags, idx, ring[])
//!   q + align4k(18*qsize+6)  used ring         (flags, idx, elems[])
//!
//! Requests are issued one at a time through descriptors 0..2, so the
//! ring never wraps under our use: header -> data -> status byte.
//!
//! Limits: only the transitional (legacy I/O) transport — modern-only
//! devices (1af4:1042) need the capability-list interface and are
//! skipped; only the first virtio-blk PCI function is driven.
//!
//! Everything the device reads/writes lives in zeroed
//! physically-contiguous blocks from alloc_frames; the physmap
//! covers it, so pmap() is the only address translation needed.

use crate::{kalloc, mm, pci, pio};
use core::sync::atomic::{AtomicU32, Ordering, fence};

const VENDOR: u16 = 0x1af4;
const DEV_BLK: u16 = 0x1001;

// Legacy I/O-space register offsets.
const R_FEATURES: u16 = 0x00; // ro u32 — device feature bits
const R_GFEATURES: u16 = 0x04; // wo u32 — accepted feature bits
const R_QPFN: u16 = 0x08; // wo u32 — queue physical frame number
const R_QSIZE: u16 = 0x0c; // ro u16 — descriptor count of selected queue
const R_QSEL: u16 = 0x0e; // wo u16 — queue selector
const R_QNOTIFY: u16 = 0x10; // wo u16 — write queue index to kick
const R_STATUS: u16 = 0x12; // rw u8 — device status byte
const R_ISR: u16 = 0x13; // ro u8 — interrupt status (read acks)
const R_CFG: u16 = 0x14; // device-specific config: u64 capacity (sectors)

// Status byte bits (virtio spec, legacy).
const S_ACK: u8 = 1;
const S_DRV: u8 = 2;
const S_DRVOK: u8 = 4;
const S_FEATOK: u8 = 8;
const S_FAIL: u8 = 0x80;

// Descriptor flags.
const DESC_NEXT: u16 = 1;
const DESC_WRITE: u16 = 2;

// virtio-blk request types.
const REQ_IN: u32 = 0;
const REQ_OUT: u32 = 1;

/// Largest queue depth we program — QEMU commonly hands 128..256;
/// the ring layout must use the DEVICE's qsize, not our cap.
const MAXQ: u16 = 256;
/// Sectors per single request — bounds the data staging block.
pub const BATCH: usize = 8;
/// Poll bound for one request — a QEMU virtio request is fast, so a
/// miss this long means the device wedged, not that it is slow.
const SPIN: u64 = 20_000_000;

/// One driven disk. All three phys blocks come from alloc_frames and
/// stay owned for the driver's lifetime.
struct VDisk {
    io: u16,
    qsize: u16,
    queue: u64,
    ctrl: u64,
    data: u64,
    sectors: u64,
}

static NDISKS: AtomicU32 = AtomicU32::new(0);
static mut DISKS: [Option<VDisk>; 4] = [None, None, None, None];

fn inl(p: u16) -> u32 {
    // SAFETY: p is a register in a probed device's I/O BAR.
    unsafe { pio::inl(p) }
}
fn inw(p: u16) -> u16 {
    // SAFETY: same — register space of the bound device.
    unsafe { pio::inw(p) }
}
fn inb(p: u16) -> u8 {
    // SAFETY: same.
    unsafe { pio::inb(p) }
}
fn outl(p: u16, v: u32) {
    // SAFETY: same.
    unsafe { pio::outl(p, v) }
}
fn outw(p: u16, v: u16) {
    // SAFETY: same.
    unsafe { pio::outw(p, v) }
}
fn outb(p: u16, v: u8) {
    // SAFETY: same.
    unsafe { pio::outb(p, v) }
}

fn fail(io: u16) {
    outb(io + R_STATUS, inb(io + R_STATUS) | S_FAIL);
}

/// Physical base of the used ring inside the queue block.
fn used_off(qs: usize) -> usize {
    // Avail ring = flags(2) + idx(2) + ring(2*qs) + used_event(2).
    (16 * qs + 6 + 2 * qs + 4095) & !4095
}

/// Emit one request and spin for its completion. `data` holds the
/// bytes for a write, or is filled on a read. Single outstanding
/// request: descriptors 0..2 are always free.
fn request(d: &VDisk, write: bool, sector: u64, nsec: usize) -> bool {
    let qs = d.qsize as usize;
    let q = mm::pmap(d.queue);
    let ctrl = mm::pmap(d.ctrl);
    // Request header: type u32, ioprio u32, sector u64. Status byte
    // sits at ctrl+16, clear of the header.
    let typ = if write { REQ_OUT } else { REQ_IN };
    // SAFETY: ctrl is our own DMA block, physmap-mapped.
    unsafe {
        (ctrl as *mut u32).write_volatile(typ);
        ((ctrl + 4) as *mut u32).write_volatile(0);
        ((ctrl + 8) as *mut u64).write_volatile(sector);
        ((ctrl + 16) as *mut u8).write_volatile(0xff);
        // Descriptors 0..2: header -> data -> status.
        let desc = q as *mut u8;
        let put = |i: usize, addr: u64, len: u32, flags: u16, next: u16| {
            let d0 = desc.add(i * 16);
            (d0 as *mut u64).write_volatile(addr);
            (d0.add(8) as *mut u32).write_volatile(len);
            (d0.add(12) as *mut u16).write_volatile(flags);
            (d0.add(14) as *mut u16).write_volatile(next);
        };
        put(0, d.ctrl, 16, DESC_NEXT, 1);
        put(
            1,
            d.data,
            (nsec * 512) as u32,
            DESC_NEXT | if write { 0 } else { DESC_WRITE },
            2,
        );
        put(2, d.ctrl + 16, 1, DESC_WRITE, 0);
        // Descriptors must be visible before the avail idx bumps.
        fence(Ordering::SeqCst);
        let avail = q + 16 * qs as u64;
        let aidx = ((avail + 2) as *mut u16).read_volatile();
        ((avail + 4 + 2 * (aidx as usize % qs) as u64) as *mut u16).write_volatile(0);
        fence(Ordering::SeqCst);
        ((avail + 2) as *mut u16).write_volatile(aidx.wrapping_add(1));
        fence(Ordering::SeqCst);
    }
    // Snapshot the used index BEFORE the notify write — QEMU can
    // complete in the microsecond gap, and a post-notify snapshot
    // would compare against an already-advanced index and spin out.
    let used = q + used_off(qs) as u64;
    let uidx_ptr = (used + 2) as *const u16;
    // SAFETY: uidx_ptr is the used-ring index in our own queue block.
    let prev = unsafe { uidx_ptr.read_volatile() };
    outw(d.io + R_QNOTIFY, 0);
    let mut spins = 0u64;
    // SAFETY: same — polling the index the device advances.
    while unsafe { uidx_ptr.read_volatile() } == prev {
        spins += 1;
        if spins > SPIN {
            return false;
        }
        core::hint::spin_loop();
    }
    inb(d.io + R_ISR); // read acks the interrupt line
    // SAFETY: ctrl+16 is the status byte the device just wrote.
    unsafe { ((ctrl + 16) as *const u8).read_volatile() == 0 }
}

/// Probe the first transitional virtio-blk function, set up its
/// request queue, and publish the disk count. Returns the number of
/// disks now usable via disk_* calls.
pub fn init() -> u32 {
    let Some((bus, dev, f)) = pci::find(VENDOR, DEV_BLK) else {
        return 0;
    };
    // The legacy driver needs an I/O BAR; a modern-only function
    // (capability-list transport) reports an MMIO BAR here — skip it
    // rather than drive registers that are not registers.
    let bar = pci::bar_raw(bus, dev, f, 0);
    if bar & 1 == 0 || bar == 0 || bar == u32::MAX {
        crate::log::printk(format_args!(
            "rustux: virtio: blk device lacks legacy I/O BAR ({bar:#x}) — skipped"
        ));
        return 0;
    }
    let io = (bar & !3) as u16;
    // CMD_IO_SPACE is bit 0; pci.rs names the memory/busmaster bits.
    pci::command_or(bus, dev, f, 1 | pci::CMD_BUS_MASTER);
    // Reset, then the legacy init handshake.
    outb(io + R_STATUS, 0);
    outb(io + R_STATUS, S_ACK);
    outb(io + R_STATUS, S_ACK | S_DRV);
    let feats = inl(io + R_FEATURES);
    outl(io + R_GFEATURES, 0); // negotiate none: 512 B sectors, no flush
    outb(io + R_STATUS, S_ACK | S_DRV | S_FEATOK);
    if inb(io + R_STATUS) & S_FEATOK == 0 {
        fail(io);
        crate::log::printk(format_args!("rustux: virtio: feature negotiation refused"));
        return 0;
    }
    outw(io + R_QSEL, 0);
    let qsz = inw(io + R_QSIZE);
    // The device lays its rings out at ITS queue size — honoring the
    // hardware value (not a cap) is what makes the layout line up.
    if !(8..=MAXQ).contains(&qsz) {
        fail(io);
        return 0;
    }
    // The device lays its rings out at ITS queue size — program the
    // PFN with a block big enough for that layout, not ours.
    let qs = qsz as usize;
    let need = used_off(qs) + 6 + 8 * qs;
    let mut order = 0usize;
    while (4096usize << order) < need {
        order += 1;
    }
    let (Some(queue), Some(ctrl), Some(data)) = (
        kalloc::alloc_frames(order),
        kalloc::alloc_frames(0),
        kalloc::alloc_frames(1),
    ) else {
        fail(io);
        return 0;
    };
    outl(io + R_QPFN, (queue >> 12) as u32);
    let sectors = inl(io + R_CFG) as u64 | (inl(io + R_CFG + 4) as u64) << 32;
    outb(io + R_STATUS, S_ACK | S_DRV | S_FEATOK | S_DRVOK);
    if sectors == 0 {
        fail(io);
        return 0;
    }
    // SAFETY: init runs once, before tasks exist.
    unsafe {
        (*core::ptr::addr_of_mut!(DISKS))[0] = Some(VDisk {
            io,
            qsize: qsz,
            queue,
            ctrl,
            data,
            sectors,
        });
    }
    NDISKS.store(1, Ordering::Release);
    crate::log::printk(format_args!(
        "rustux: virtio: blk {io:#x} feats={feats:#x} qsize={qsz} {} sectors ({} MiB)",
        sectors,
        sectors / 2048
    ));
    // Datapath proof at probe time: read sector 0 through the queue
    // — the same descriptor chain the block scan then drives.
    let d = disk_for(0).unwrap();
    let r = request(d, false, 0, 1);
    let (b510, b511) = unsafe {
        let p = mm::pmap(d.data) as *const u8;
        (p.add(510).read_volatile(), p.add(511).read_volatile())
    };
    crate::log::printk(format_args!(
        "rustux: virtio: datapath sector0 read {r} sig {b510:#x}{b511:#x}"
    ));
    1
}

/// Number of virtio disks the init probe bound.
pub fn disks() -> u32 {
    NDISKS.load(Ordering::Acquire)
}

fn disk_for(i: usize) -> Option<&'static VDisk> {
    // SAFETY: DISKS is written once at init (single-threaded boot)
    // and read-only after, like the other drivers' statics.
    unsafe { (*core::ptr::addr_of!(DISKS)).get(i).and_then(|o| o.as_ref()) }
}

/// Disk capacity in bytes — same contract as ata::capacity_d.
pub fn disk_capacity(i: usize) -> u64 {
    disk_for(i).map_or(0, |d| d.sectors * 512)
}

/// Read `count` sectors at `lba` into `buf` (buf >= count*512 bytes),
/// batched through the staging block. Same contract as ahci::read_range.
pub fn read_range(i: usize, lba: u64, count: usize, buf: &mut [u8]) -> bool {
    let Some(d) = disk_for(i) else { return false };
    if buf.len() < count * 512 || lba + count as u64 > d.sectors {
        return false;
    }
    let mut done = 0usize;
    while done < count {
        let n = (count - done).min(BATCH);
        if !request(d, false, lba + done as u64, n) {
            return false;
        }
        // SAFETY: data is our DMA block; the request just filled n*512.
        unsafe {
            core::ptr::copy_nonoverlapping(
                mm::pmap(d.data) as *const u8,
                buf.as_mut_ptr().add(done * 512),
                n * 512,
            );
        }
        done += n;
    }
    true
}

/// Write `count` sectors at `lba` from `buf`. Same contract as
/// ahci::write_range.
pub fn write_range(i: usize, lba: u64, count: usize, buf: &[u8]) -> bool {
    let Some(d) = disk_for(i) else { return false };
    if buf.len() < count * 512 || lba + count as u64 > d.sectors {
        return false;
    }
    let mut done = 0usize;
    while done < count {
        let n = (count - done).min(BATCH);
        // SAFETY: data is our DMA block, big enough for BATCH sectors.
        unsafe {
            core::ptr::copy_nonoverlapping(
                buf.as_ptr().add(done * 512),
                mm::pmap(d.data) as *mut u8,
                n * 512,
            );
        }
        if !request(d, true, lba + done as u64, n) {
            return false;
        }
        done += n;
    }
    true
}
