//! virtio — transitional virtio-pci drivers over the legacy I/O
//! interface (QEMU 1af4:1xxx transitional devices).
//!
//! The legacy transport needs no MSI-X and no capability-list walk:
//! registers live in the I/O BAR, requests go through split
//! virtqueues, and completion is polled — same synchronous style as
//! ata.rs. One `Vq` owns a queue's ring layout; the blk and net
//! devices each drive their queue(s) through it.
//!
//! Queue layout at the page-aligned physical base `q`, at the DEVICE's
//! queue size (QEMU hands 128 or 256 — a host cap misplaces the rings
//! and stalls all I/O):
//!   q + 0                    descriptor table  (16 B * qsize)
//!   q + 16*qsize             available ring    (flags, idx, ring[])
//!   q + align4k(18*qsize+6)  used ring         (flags, idx, elems[])
//!
//! Devices supported: virtio-blk (0x1001, queue 0) and virtio-net
//! (0x1000, queue 0 rx / queue 1 tx). Modern-only functions (cap-list
//! transport) are skipped; only the first function of each kind is
//! driven.
//!
//! Everything the device reads/writes lives in zeroed
//! physically-contiguous blocks from alloc_frames; the physmap covers
//! it, so pmap() is the only address translation needed.

use crate::{kalloc, mm, pci, pio};
use core::sync::atomic::{AtomicU32, Ordering, fence};

const VENDOR: u16 = 0x1af4;
const DEV_BLK: u16 = 0x1001;
const DEV_NET: u16 = 0x1000;

// Legacy I/O-space register offsets.
const R_FEATURES: u16 = 0x00; // ro u32 — device feature bits
const R_GFEATURES: u16 = 0x04; // wo u32 — accepted feature bits
const R_QPFN: u16 = 0x08; // wo u32 — queue physical frame number
const R_QSIZE: u16 = 0x0c; // ro u16 — descriptor count of selected queue
const R_QSEL: u16 = 0x0e; // wo u16 — queue selector
const R_QNOTIFY: u16 = 0x10; // wo u16 — write queue index to kick
const R_STATUS: u16 = 0x12; // rw u8 — device status byte
const R_ISR: u16 = 0x13; // ro u8 — interrupt status (read acks)
const R_CFG: u16 = 0x14; // device-specific config starts here
// With MSI-X enabled these two u16s occupy 0x14/0x16 and push the
// device config to 0x18 — arm MSI-X only after config reads (MAC).
const R_MSIX_CFG: u16 = 0x14; // rw u16 — config-change vector
const R_MSIX_Q: u16 = 0x16; // rw u16 — vector for the selected queue
const MSIX_NO_VEC: u16 = 0xFFFF; // VIRTIO_MSI_NO_VECTOR

// Non-transitional device id for virtio-net (virtio 1.0+).
const DEV_NET_MODERN: u16 = 0x1041;

// Modern common_cfg field offsets (virtio 1.0 section 4.1.4.3).
const C_DFEAT_SEL: u64 = 0x00; // wo u32 — device feature page
const C_DFEAT: u64 = 0x04; // ro u32 — device features, selected page
const C_GFEAT_SEL: u64 = 0x08; // wo u32 — driver feature page
const C_GFEAT: u64 = 0x0c; // wo u32 — accepted features
const C_MSIX: u64 = 0x10; // rw u16 — config-change MSI-X vector
const C_NQ: u64 = 0x12; // ro u16 — queue count
const C_STATUS: u64 = 0x14; // rw u8 — device status
const C_QSEL: u64 = 0x16; // wo u16 — queue selector
const C_QSIZE: u64 = 0x18; // ro u16 — selected queue's max size
const C_QMSIX: u64 = 0x1a; // rw u16 — selected queue's MSI-X vector
const C_QENABLE: u64 = 0x1c; // rw u16 — selected queue enable
const C_QNOTIFY: u64 = 0x1e; // ro u16 — selected queue notify offset
const C_QDESC: u64 = 0x20; // rw u64 — descriptor table phys
const C_QDRV: u64 = 0x28; // rw u64 — avail ring phys
const C_QDEV: u64 = 0x30; // rw u64 — used ring phys

// MMIO accessors over the cap-window physmap mappings.
fn cr8(p: u64) -> u8 { unsafe { (p as *const u8).read_volatile() } }
fn cr16(p: u64) -> u16 { unsafe { (p as *const u16).read_volatile() } }
fn cr32(p: u64) -> u32 { unsafe { (p as *const u32).read_volatile() } }
fn cw8(p: u64, v: u8) { unsafe { (p as *mut u8).write_volatile(v) } }
fn cw16(p: u64, v: u16) { unsafe { (p as *mut u16).write_volatile(v) } }
fn cw32(p: u64, v: u32) { unsafe { (p as *mut u32).write_volatile(v) } }
fn cw64(p: u64, v: u64) { unsafe { (p as *mut u64).write_volatile(v) } }

// Status byte bits (virtio spec, legacy).
const S_ACK: u8 = 1;
const S_DRV: u8 = 2;
const S_DRVOK: u8 = 4;
const S_FEATOK: u8 = 8;
const S_FAIL: u8 = 0x80;

// Descriptor flags.
const DESC_NEXT: u16 = 1;
const DESC_WRITE: u16 = 2;

/// Largest device queue depth we honor.
const MAXQ: u16 = 256;
/// Poll bound for one request — a QEMU virtio request is fast, so a
/// miss this long means the device wedged, not that it is slow.
const SPIN: u64 = 20_000_000;

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

/// Physical base of the used ring inside a queue block, at the
/// DEVICE's queue size — the layout QEMU computes.
fn used_off(qs: usize) -> usize {
    // Avail ring = flags(2) + idx(2) + ring(2*qs) + used_event(2).
    (16 * qs + 6 + 2 * qs + 4095) & !4095
}

/// A bound virtqueue: owns its ring block for the driver's lifetime.
struct Vq {
    io: u16,
    sel: u16,
    size: u16,
    phys: u64,
    /// Modern MMIO notify doorbell — 0 means the legacy I/O port.
    notify_va: u64,
    /// Modern ISR-ack byte — 0 means the legacy R_ISR read.
    isr_va: u64,
}

impl Vq {
    /// Select queue `sel`, allocate a ring block sized for the
    /// DEVICE's reported qsize, and publish its PFN.
    fn setup(io: u16, sel: u16) -> Option<Vq> {
        outw(io + R_QSEL, sel);
        let qsz = inw(io + R_QSIZE);
        if !(8..=MAXQ).contains(&qsz) {
            return None;
        }
        let qs = qsz as usize;
        let need = used_off(qs) + 6 + 8 * qs;
        let mut order = 0usize;
        while (4096usize << order) < need {
            order += 1;
        }
        let phys = kalloc::alloc_frames(order)?;
        outl(io + R_QPFN, (phys >> 12) as u32);
        Some(Vq {
            io,
            sel,
            size: qsz,
            phys,
            notify_va: 0,
            isr_va: 0,
        })
    }

    /// Modern-transport queue setup: select, allocate the same ring
    /// block layout, then publish each region's phys to the
    /// common_cfg window (modern names the three regions
    /// separately — no single PFN), read the queue's notify offset,
    /// and enable it.
    fn setup_modern(
        common: u64,
        notify_base: u64,
        notify_mult: u32,
        isr_va: u64,
        sel: u16,
    ) -> Option<Vq> {
        cw16(common + C_QSEL, sel);
        let qsz = cr16(common + C_QSIZE);
        if !(8..=MAXQ).contains(&qsz) {
            return None;
        }
        let qs = qsz as usize;
        let need = used_off(qs) + 6 + 8 * qs;
        let mut order = 0usize;
        while (4096usize << order) < need {
            order += 1;
        }
        let phys = kalloc::alloc_frames(order)?;
        cw64(common + C_QDESC, phys);
        cw64(common + C_QDRV, phys + 16 * qsz as u64);
        cw64(common + C_QDEV, phys + used_off(qs) as u64);
        let notify_va = notify_base + cr16(common + C_QNOTIFY) as u64 * notify_mult as u64;
        cw16(common + C_QENABLE, 1);
        Some(Vq {
            io: 0,
            sel,
            size: qsz,
            phys,
            notify_va,
            isr_va,
        })
    }

    /// Write descriptor `i`: addr u64, len u32, flags u16, next u16.
    fn put_desc(&self, i: usize, addr: u64, len: u32, flags: u16, next: u16) {
        let qs = self.size as usize;
        if i >= qs {
            return;
        }
        // SAFETY: inside our queue block's descriptor table.
        unsafe {
            let d0 = (mm::pmap(self.phys) as *mut u8).add(i * 16);
            (d0 as *mut u64).write_volatile(addr);
            (d0.add(8) as *mut u32).write_volatile(len);
            (d0.add(12) as *mut u16).write_volatile(flags);
            (d0.add(14) as *mut u16).write_volatile(next);
        }
    }

    /// Push descriptor-chain head `head` onto the avail ring and bump
    /// the index. Returns the avail idx the push used.
    fn avail_push(&self, head: u16) -> u16 {
        let qs = self.size as usize;
        let avail = mm::pmap(self.phys) + 16 * qs as u64;
        // SAFETY: avail ring fields inside our own queue block.
        unsafe {
            let aidx = ((avail + 2) as *mut u16).read_volatile();
            ((avail + 4 + 2 * (aidx as usize % qs) as u64) as *mut u16).write_volatile(head);
            fence(Ordering::SeqCst);
            ((avail + 2) as *mut u16).write_volatile(aidx.wrapping_add(1));
            fence(Ordering::SeqCst);
            aidx
        }
    }

    /// Current used-ring index.
    fn used_idx(&self) -> u16 {
        let qs = self.size as usize;
        let used = mm::pmap(self.phys) + used_off(qs) as u64;
        // SAFETY: used-ring index inside our own queue block.
        unsafe { ((used + 2) as *const u16).read_volatile() }
    }

    /// Used-ring entry `i` (descriptor id, bytes written).
    fn used_entry(&self, i: usize) -> (u32, u32) {
        let qs = self.size as usize;
        let used = mm::pmap(self.phys) + used_off(qs) as u64;
        // SAFETY: inside the used ring we own.
        unsafe {
            let e = used + 4 + 8 * (i % qs) as u64;
            (
                (e as *const u32).read_volatile(),
                ((e + 4) as *const u32).read_volatile(),
            )
        }
    }

    /// Kick the device.
    fn notify(&self) {
        if self.notify_va != 0 {
            // SAFETY: our queue's notify MMIO address.
            unsafe { (self.notify_va as *mut u16).write_volatile(self.sel) };
        } else {
            outw(self.io + R_QNOTIFY, self.sel);
        }
    }

    /// Post `head`, kick, and spin until used.idx advances past the
    /// snapshot taken BEFORE the kick — a post-notify snapshot loses
    /// the race to a microsecond-fast completion.
    fn poll_once(&self, head: u16) -> bool {
        let prev = self.used_idx();
        self.avail_push(head);
        self.notify();
        let mut spins = 0u64;
        while self.used_idx() == prev {
            spins += 1;
            if spins > SPIN {
                return false;
            }
            core::hint::spin_loop();
        }
        if self.isr_va != 0 {
            // SAFETY: the device's mapped ISR byte.
            unsafe { (self.isr_va as *const u8).read_volatile() };
        } else {
            inb(self.io + R_ISR); // read acks the interrupt line
        }
        true
    }
}

/// Shared legacy handshake: reset -> ACK|DRIVER -> features=0 ->
/// FEATURES_OK readback. Callers then set up queues and add DRIVER_OK.
fn handshake(io: u16) -> bool {
    outb(io + R_STATUS, 0);
    outb(io + R_STATUS, S_ACK);
    outb(io + R_STATUS, S_ACK | S_DRV);
    outl(io + R_GFEATURES, 0); // negotiate none: no offload paths
    outb(io + R_STATUS, S_ACK | S_DRV | S_FEATOK);
    if inb(io + R_STATUS) & S_FEATOK == 0 {
        fail(io);
        crate::log::printk(format_args!(
            "rustux: virtio: feature negotiation refused (device features {:#x})",
            inl(io + R_FEATURES)
        ));
        return false;
    }
    true
}

/// Find the first transitional function of `dev_id` with a legacy
/// I/O BAR and enable IO + bus-mastering. Returns the io base.
fn probe_io(dev_id: u16) -> Option<(u16, u32)> {
    let (bus, dev, f) = pci::find(VENDOR, dev_id)?;
    let bar = pci::bar_raw(bus, dev, f, 0);
    if bar & 1 == 0 || bar == 0 || bar == u32::MAX {
        crate::log::printk(format_args!(
            "rustux: virtio: device {dev_id:#x} lacks legacy I/O BAR ({bar:#x}) — skipped"
        ));
        return None;
    }
    // CMD bit 0 = I/O space; pci.rs names the memory/busmaster bits.
    pci::command_or(bus, dev, f, 1 | pci::CMD_BUS_MASTER);
    Some(((bar & !3) as u16, (bus as u32) << 8 | (dev as u32) << 3 | f as u32))
}

// -------------------------------------------------------------------
// virtio-blk

// virtio-blk request types.
const REQ_IN: u32 = 0;
const REQ_OUT: u32 = 1;
/// Sectors per single request — bounds the data staging block.
pub const BATCH: usize = 8;

/// One driven disk. All phys blocks come from alloc_frames and stay
/// owned for the driver's lifetime.
struct VDisk {
    vq: Vq,
    ctrl: u64,
    data: u64,
    sectors: u64,
}

static NDISKS: AtomicU32 = AtomicU32::new(0);
static mut DISKS: [Option<VDisk>; 4] = [None, None, None, None];

fn disk_for(i: usize) -> Option<&'static VDisk> {
    // SAFETY: DISKS is written once at init (single-threaded boot)
    // and read-only after, like the other drivers' statics.
    unsafe { (*core::ptr::addr_of!(DISKS)).get(i).and_then(|o| o.as_ref()) }
}

/// Emit one request and spin for its completion. `data` holds the
/// bytes for a write, or is filled on a read. Single outstanding
/// request: descriptors 0..2 are always free.
fn request(d: &VDisk, write: bool, sector: u64, nsec: usize) -> bool {
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
    }
    d.vq.put_desc(0, d.ctrl, 16, DESC_NEXT, 1);
    d.vq.put_desc(
        1,
        d.data,
        (nsec * 512) as u32,
        DESC_NEXT | if write { 0 } else { DESC_WRITE },
        2,
    );
    d.vq.put_desc(2, d.ctrl + 16, 1, DESC_WRITE, 0);
    fence(Ordering::SeqCst);
    if !d.vq.poll_once(0) {
        return false;
    }
    // SAFETY: ctrl+16 is the status byte the device just wrote.
    unsafe { ((ctrl + 16) as *const u8).read_volatile() == 0 }
}

/// Probe the first transitional virtio-blk function, set up its
/// request queue, and publish the disk count. Returns the number of
/// disks now usable via disk_* calls.
pub fn init() -> u32 {
    let Some((io, _)) = probe_io(DEV_BLK) else {
        return 0;
    };
    if !handshake(io) {
        return 0;
    }
    let Some(vq) = Vq::setup(io, 0) else {
        fail(io);
        return 0;
    };
    let (Some(ctrl), Some(data)) = (kalloc::alloc_frames(0), kalloc::alloc_frames(1)) else {
        fail(io);
        return 0;
    };
    let sectors = inl(io + R_CFG) as u64 | (inl(io + R_CFG + 4) as u64) << 32;
    if sectors == 0 {
        fail(io);
        return 0;
    }
    outb(io + R_STATUS, S_ACK | S_DRV | S_FEATOK | S_DRVOK);
    // SAFETY: init runs once, before tasks exist.
    unsafe {
        (*core::ptr::addr_of_mut!(DISKS))[0] = Some(VDisk {
            vq,
            ctrl,
            data,
            sectors,
        });
    }
    NDISKS.store(1, Ordering::Release);
    let qsz = disk_for(0).map_or(0, |d| d.vq.size);
    crate::log::printk(format_args!(
        "rustux: virtio: blk {io:#x} qsize={qsz} {sectors} sectors ({} MiB)",
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
    // Write datapath proof in the MBR gap — lba 64 sits before the
    // ext4 partition (2048+) and -snapshot keeps the host image
    // clean: read, write a pattern, verify, restore, verify.
    let mut orig = [0u8; 512];
    let mut back = [0u8; 512];
    let mut pat = [0u8; 512];
    pat[..7].copy_from_slice(b"rustux!");
    let ro = read_range(0, 64, 1, &mut orig);
    let w = ro && write_range(0, 64, 1, &pat);
    let v = w && read_range(0, 64, 1, &mut back) && back[..7] == pat[..7];
    let s = write_range(0, 64, 1, &orig);
    let s = s && read_range(0, 64, 1, &mut back) && back == orig;
    crate::log::printk(format_args!(
        "rustux: virtio: write datapath {w} verify {v} restore {s}"
    ));
    1
}

/// Number of virtio disks the init probe bound.
pub fn disks() -> u32 {
    NDISKS.load(Ordering::Acquire)
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

// -------------------------------------------------------------------
// virtio-net
//
// Queue 0 is receive (we pre-post N_RX device-writable buffers; the
// device fills them and reports used entries), queue 1 is transmit.
// With no offload features negotiated, every frame is preceded by a
// 10-byte virtio_net_hdr — all zero for our use.

/// Bytes of virtio_net_hdr prepended to every net frame.
const NET_HDR: usize = 10;
/// Per-buffer size — covers an Ethernet MTU with slack.
const NET_BUFSZ: usize = 2048;
/// Posted receive buffers / transmit slots.
const N_RX: usize = 64;
const N_TX: usize = 8;

/// Vendor-capability window addresses (physmap VAs) for a modern
/// virtio-pci function.
struct VCaps {
    common: u64,
    notify: u64,
    notify_mult: u32,
    isr: u64,
    dev: u64,
}

/// Physical base of BAR slot `i`, handling 64-bit MEM bars.
fn bar_phys(bus: u8, dev: u8, f: u8, i: u8) -> u64 {
    let lo = pci::bar_raw(bus, dev, f, i);
    if lo == u32::MAX || lo == 0 || lo & 1 != 0 {
        return 0;
    }
    if lo & 6 == 4 {
        let hi = pci::read32(bus, dev, f, 0x10 + 4 * (i + 1));
        (hi as u64) << 32 | (lo & !0xf) as u64
    } else {
        (lo & !0xf) as u64
    }
}

/// Walk the vendor cap list (id 0x09) collecting each cfg_type's
/// mapped window. Returns None unless common/notify/isr/device all
/// resolved — a partial map can't drive the device.
fn virtio_caps(bus: u8, dev: u8, f: u8) -> Option<VCaps> {
    let mut v = VCaps {
        common: 0,
        notify: 0,
        notify_mult: 0,
        isr: 0,
        dev: 0,
    };
    let mut off = pci::read8(bus, dev, f, 0x34) & !3;
    for _ in 0..32 {
        if off == 0 {
            break;
        }
        // A device-controlled cap chain: bound the field reads to
        // the 256-byte config window (off+16 is the notify
        // multiplier) and the BAR index to the six architected
        // slots — the CVE-2026-13216 class (unvalidated cap data)
        // applies to offsets too, not just lengths.
        if pci::read8(bus, dev, f, off) == 0x09 && off <= 0xe8 {
            let typ = pci::read8(bus, dev, f, off + 3);
            let bar = pci::read8(bus, dev, f, off + 4);
            if bar >= 6 {
                off = pci::read8(bus, dev, f, off + 1) & !3;
                continue;
            }
            let base = bar_phys(bus, dev, f, bar)
                + pci::read32(bus, dev, f, off + 8) as u64;
            if base != 0 {
                let va = mm::pmap(base);
                match typ {
                    1 => v.common = va,
                    2 => {
                        v.notify = va;
                        v.notify_mult = pci::read32(bus, dev, f, off + 16);
                    }
                    3 => v.isr = va,
                    4 => v.dev = va,
                    _ => {}
                }
            }
        }
        off = pci::read8(bus, dev, f, off + 1) & !3;
    }
    (v.common != 0 && v.notify != 0 && v.isr != 0 && v.dev != 0 && v.notify_mult != 0)
        .then_some(v)
}

/// Modern handshake: reset (poll status until the device clears it),
/// ACK|DRIVER, refuse unless the device offers VIRTIO_F_VERSION_1,
/// accept only VERSION_1, FEATURES_OK. Caller adds DRIVER_OK.
fn handshake_modern(common: u64) -> bool {
    cw8(common + C_STATUS, 0);
    let mut spins = 0u64;
    while cr8(common + C_STATUS) != 0 {
        spins += 1;
        if spins > SPIN {
            return false;
        }
        core::hint::spin_loop();
    }
    cw8(common + C_STATUS, S_ACK);
    cw8(common + C_STATUS, S_ACK | S_DRV);
    cw32(common + C_DFEAT_SEL, 1);
    if cr32(common + C_DFEAT) & 1 == 0 {
        cw8(common + C_STATUS, cr8(common + C_STATUS) | S_FAIL);
        crate::log::printk(format_args!(
            "rustux: virtio: modern device lacks VERSION_1 — refused"
        ));
        return false;
    }
    cw32(common + C_GFEAT_SEL, 0);
    cw32(common + C_GFEAT, 0);
    cw32(common + C_GFEAT_SEL, 1);
    cw32(common + C_GFEAT, 1); // accept VERSION_1 only
    cw8(common + C_STATUS, S_ACK | S_DRV | S_FEATOK);
    if cr8(common + C_STATUS) & S_FEATOK == 0 {
        cw8(common + C_STATUS, cr8(common + C_STATUS) | S_FAIL);
        return false;
    }
    true
}

/// Probe a non-transitional virtio-net function over the modern
/// cap-list transport. The same VNet contract results — only the
/// queue programming, notify doorbell, and ISR differ.
fn net_init_modern() -> bool {
    let Some((bus, dev, f)) = pci::find(VENDOR, DEV_NET_MODERN) else {
        return false;
    };
    NBDF.store(
        (bus as u32) << 8 | (dev as u32) << 3 | f as u32,
        Ordering::Relaxed,
    );
    pci::command_or(bus, dev, f, pci::CMD_MEM_SPACE | pci::CMD_BUS_MASTER);
    let Some(vc) = virtio_caps(bus, dev, f) else {
        crate::log::printk(format_args!(
            "rustux: virtio: modern net lacks a full cap set — skipped"
        ));
        return false;
    };
    if !handshake_modern(vc.common) {
        return false;
    }
    if cr16(vc.common + C_NQ) < 2 {
        cw8(vc.common + C_STATUS, cr8(vc.common + C_STATUS) | S_FAIL);
        return false;
    }
    let (Some(rx), Some(tx)) = (
        Vq::setup_modern(vc.common, vc.notify, vc.notify_mult, vc.isr, 0),
        Vq::setup_modern(vc.common, vc.notify, vc.notify_mult, vc.isr, 1),
    ) else {
        cw8(vc.common + C_STATUS, cr8(vc.common + C_STATUS) | S_FAIL);
        return false;
    };
    let (Some(rx_bufs), Some(tx_bufs)) =
        (kalloc::alloc_frames(5), kalloc::alloc_frames(2))
    else {
        cw8(vc.common + C_STATUS, cr8(vc.common + C_STATUS) | S_FAIL);
        return false;
    };
    let mut mac = [0u8; 6];
    for (i, b) in mac.iter_mut().enumerate() {
        *b = cr8(vc.dev + i as u64);
    }
    cw8(vc.common + C_STATUS, S_ACK | S_DRV | S_FEATOK | S_DRVOK);
    // SAFETY: init runs once, before tasks exist.
    unsafe {
        *core::ptr::addr_of_mut!(VNET) = Some(VNet {
            rx,
            tx,
            rx_bufs,
            tx_bufs,
            mac,
            rx_seen: 0,
            tx_slot: 0,
            hdr: 12, // virtio_net_hdr_v1 always carries num_buffers
            common: vc.common,
        });
    }
    let n = vnet().unwrap();
    for i in 0..N_RX {
        n.rx
            .put_desc(i, n.rx_bufs + (i * NET_BUFSZ) as u64, NET_BUFSZ as u32, DESC_WRITE, 0);
    }
    for i in 0..N_RX {
        n.rx.avail_push(i as u16);
    }
    n.rx.notify();
    NET_UP.store(1, Ordering::Release);
    crate::log::printk(format_args!(
        "rustux: virtio: net modern mac {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} rxq={} txq={}",
        n.mac[0], n.mac[1], n.mac[2], n.mac[3], n.mac[4], n.mac[5], n.rx.size, n.tx.size
    ));
    true
}

struct VNet {
    rx: Vq,
    tx: Vq,
    rx_bufs: u64,
    tx_bufs: u64,
    mac: [u8; 6],
    /// Next used-ring position the RX drain expects (absolute idx).
    rx_seen: u16,
    tx_slot: u16,
    /// virtio_net_hdr bytes this transport prepends (10 legacy /
    /// 12 for the v1 header with num_buffers).
    hdr: u16,
    /// Modern common_cfg window VA — 0 means legacy transport.
    common: u64,
}

static mut VNET: Option<VNet> = None;
static NET_UP: AtomicU32 = AtomicU32::new(0);

fn vnet() -> Option<&'static VNet> {
    // SAFETY: VNET is written once at init, read-only after.
    unsafe { (*core::ptr::addr_of!(VNET)).as_ref() }
}

/// Probe the first transitional virtio-net function, set up rx/tx
/// queues, pre-post the receive buffers. Returns true when the NIC
/// is usable via net_* calls.
/// BDF of the bound net function — the IRQ arm needs it for the
/// MSI-X capability walk.
static NBDF: AtomicU32 = AtomicU32::new(u32::MAX);

/// Vector count of RX-caused MSI-X messages — the IRQ-side proof a
/// used-buffer completion delivered an interrupt.
pub static NET_RX_IRQS: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);

pub fn net_init() -> bool {
    // A non-transitional function answers the modern cap-list
    // transport; fall back to the legacy I/O interface otherwise.
    if net_init_modern() {
        return true;
    }
    let Some((io, bdf)) = probe_io(DEV_NET) else {
        return false;
    };
    NBDF.store(bdf, Ordering::Relaxed);
    if !handshake(io) {
        return false;
    }
    let (Some(rx), Some(tx)) = (Vq::setup(io, 0), Vq::setup(io, 1)) else {
        fail(io);
        return false;
    };
    // RX: N_RX * 2048 = 128 KiB contiguous; TX: N_TX * 2048 = 16 KiB.
    let (Some(rx_bufs), Some(tx_bufs)) =
        (kalloc::alloc_frames(5), kalloc::alloc_frames(2))
    else {
        fail(io);
        return false;
    };
    let mut mac = [0u8; 6];
    for (i, b) in mac.iter_mut().enumerate() {
        *b = inb(io + R_CFG + i as u16);
    }
    outb(io + R_STATUS, S_ACK | S_DRV | S_FEATOK | S_DRVOK);
    // SAFETY: init runs once, before tasks exist.
    unsafe {
        *core::ptr::addr_of_mut!(VNET) = Some(VNet {
            rx,
            tx,
            rx_bufs,
            tx_bufs,
            mac,
            rx_seen: 0,
            tx_slot: 0,
            hdr: NET_HDR as u16,
            common: 0,
        });
    }
    let n = vnet().unwrap();
    // Post all receive buffers: one device-writable descriptor each.
    for i in 0..N_RX {
        n.rx
            .put_desc(i, n.rx_bufs + (i * NET_BUFSZ) as u64, NET_BUFSZ as u32, DESC_WRITE, 0);
    }
    for i in 0..N_RX {
        n.rx.avail_push(i as u16);
    }
    n.rx.notify();
    NET_UP.store(1, Ordering::Release);
    crate::log::printk(format_args!(
        "rustux: virtio: net {io:#x} mac {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} rxq={} txq={}",
        n.mac[0],
        n.mac[1],
        n.mac[2],
        n.mac[3],
        n.mac[4],
        n.mac[5],
        n.rx.size,
        n.tx.size
    ));
    true
}

/// Whether a virtio NIC is bound.
pub fn net_up() -> bool {
    NET_UP.load(Ordering::Acquire) != 0
}

/// The NIC's MAC, when bound.
pub fn net_mac() -> Option<[u8; 6]> {
    vnet().map(|n| n.mac)
}

/// Whether the RX used-ring holds an unconsumed entry — the peek the
/// socket layer's drain loop polls between frame copies.
pub fn net_rx_pending() -> bool {
    let Some(n) = vnet() else { return false };
    n.rx.used_idx().wrapping_sub(n.rx_seen) != 0
}

/// Copy the next received frame into `buf` (header stripped) and
/// re-post its buffer. Returns the frame length, or None when the
/// queue is empty.
pub fn net_rx(buf: &mut [u8]) -> Option<usize> {
    // SAFETY: VNET is write-once at init; rx_seen is mutated under the
    // same single-threaded call context the rest of the driver uses.
    let n = unsafe { (*core::ptr::addr_of_mut!(VNET)).as_mut()? };
    let used = n.rx.used_idx();
    if used.wrapping_sub(n.rx_seen) == 0 {
        return None;
    }
    let (id, len) = n.rx.used_entry(n.rx_seen as usize);
    n.rx_seen = n.rx_seen.wrapping_add(1);
    let id = id as usize;
    if id >= N_RX {
        return None; // consumed; the slot can't be re-posted
    }
    if len < n.hdr as u32 {
        // Malformed completion — re-post so the pool doesn't shrink.
        n.rx.put_desc(
            id,
            n.rx_bufs + (id * NET_BUFSZ) as u64,
            NET_BUFSZ as u32,
            DESC_WRITE,
            0,
        );
        n.rx.avail_push(id as u16);
        n.rx.notify();
        return None;
    }
    let take = ((len as usize) - n.hdr as usize)
        .min(buf.len())
        .min(NET_BUFSZ - n.hdr as usize);
    // SAFETY: the device filled this buffer; id indexes our rx block.
    unsafe {
        core::ptr::copy_nonoverlapping(
            (mm::pmap(n.rx_bufs) + (id * NET_BUFSZ) as u64 + n.hdr as u64) as *const u8,
            buf.as_mut_ptr(),
            take,
        );
    }
    // Re-post the same descriptor.
    n.rx.put_desc(
        id,
        n.rx_bufs + (id * NET_BUFSZ) as u64,
        NET_BUFSZ as u32,
        DESC_WRITE,
        0,
    );
    n.rx.avail_push(id as u16);
    n.rx.notify();
    Some(take)
}

/// Transmit one Ethernet frame. Pads short frames to the 60-byte
/// minimum and prepends the zeroed 10-byte net header.
pub fn net_tx(frame: &[u8]) -> bool {
    // SAFETY: VNET is write-once at init; tx_slot mutated under the
    // same single-threaded call context.
    let Some(n) = (unsafe { (*core::ptr::addr_of_mut!(VNET)).as_mut() }) else {
        return false;
    };
    if frame.is_empty() || frame.len() > NET_BUFSZ - n.hdr as usize {
        return false;
    }
    let slot = n.tx_slot % N_TX as u16;
    n.tx_slot = n.tx_slot.wrapping_add(1);
    let boff = slot as usize * NET_BUFSZ;
    let bva = mm::pmap(n.tx_bufs) + boff as u64;
    let plen = frame.len().max(60);
    // SAFETY: our own TX slot; header zeroed then frame copied.
    unsafe {
        core::ptr::write_bytes(bva as *mut u8, 0, NET_BUFSZ);
        core::ptr::copy_nonoverlapping(
            frame.as_ptr(),
            (bva + n.hdr as u64) as *mut u8,
            frame.len(),
        );
    }
    n.tx.put_desc(
        slot as usize,
        n.tx_bufs + boff as u64,
        (n.hdr as usize + plen) as u32,
        0,
        0,
    );
    n.tx.poll_once(slot)
}

/// ARP round-trip: request 10.0.2.2 (slirp gateway) and drain RX for
/// the reply — the same proof e1000 runs against its own ring.
pub fn net_selftest() -> bool {
    if !net_up() {
        return false;
    }
    let Some(mac) = net_mac() else { return false };
    // ARP request: broadcast who-has 10.0.2.2 tell <our mac>/10.0.2.15.
    let mut f = [0u8; 42];
    f[..6].copy_from_slice(&[0xff; 6]);
    f[6..12].copy_from_slice(&mac);
    f[12] = 0x08;
    f[13] = 0x06;
    // ARP payload: htype eth, ptype ip, hlen 6, plen 4, op request.
    f[14..22].copy_from_slice(&[0, 1, 8, 0, 6, 4, 0, 1]);
    f[22..28].copy_from_slice(&mac);
    f[28..32].copy_from_slice(&[10, 0, 2, 15]);
    f[38..42].copy_from_slice(&[10, 0, 2, 2]);
    if !net_tx(&f) {
        return false;
    }
    let mut buf = [0u8; 1600];
    let mut spins = 0u64;
    loop {
        if let Some(n) = net_rx(&mut buf) {
            // ARP reply (0x0806, op 2) naming 10.0.2.2 as sender.
            if n >= 42
                && buf[12] == 0x08
                && buf[13] == 0x06
                && buf[20] == 0
                && buf[21] == 2
                && buf[28..32] == [10, 0, 2, 2]
            {
                return true;
            }
        }
        spins += 1;
        if spins > SPIN {
            return false;
        }
        core::hint::spin_loop();
    }
}

/// Interrupt-status read for the net function — the read itself is
/// the acknowledge. Bit 0 marks a used-buffer completion on any
/// queue (only RX is vector-armed). Like e1000::on_irq the handler
/// only counts: draining the virtqueue mutates rx_seen and the
/// avail ring without a lock, which an IRQ context cannot do
/// safely over an interrupted syscall-side drain. The IRQ's real
/// work is waking the `sti;hlt` idle loops so a blocked socket
/// task drains the moment a frame lands instead of at next tick.
pub fn net_on_irq() {
    let Some(n) = vnet() else { return };
    let isr = if n.rx.isr_va != 0 {
        cr8(n.rx.isr_va)
    } else {
        inb(n.rx.io + R_ISR)
    };
    if isr & 1 != 0 {
        NET_RX_IRQS.fetch_add(1, Ordering::Relaxed);
    }
}

/// MSI-X receive path for the virtio NIC — mirrors
/// e1000::irq_selftest: table entry 0 carries vector IRQ_VNET to
/// this LAPIC, the device-side queue vector binds the RX queue to
/// entry 0, then the ARP probe's reply must raise the IRQ.
/// Interrupts must be live (`sti`); runs after net_init so the
/// device config (MAC at R_CFG) was already read — enabling MSI-X
/// shifts the config window +4.
pub fn net_irq_selftest() -> bool {
    let Some(n) = vnet() else { return false };
    let bdf = NBDF.load(Ordering::Relaxed);
    if bdf == u32::MAX {
        return false;
    }
    let (bus, dev, f) = (
        (bdf >> 8) as u8,
        ((bdf >> 3) & 0x1f) as u8,
        (bdf & 7) as u8,
    );
    let dest = crate::apic::lapic_id() as u8;
    let Some(cap) = pci::msix_cap(bus, dev, f) else {
        crate::log::printk(format_args!("rustux: virtio: net has no MSI-X capability"));
        return false;
    };
    // Entry 0 -> IRQ_VNET on this LAPIC; every other entry masked.
    // SAFETY: cap.table is the device MSI-X BAR window, inside the
    // identity map.
    unsafe {
        pci::msix_set(&cap, 0, crate::apic::IRQ_VNET as u8, dest, false);
        for v in 1..cap.nvec {
            pci::msix_set(&cap, v, 0, 0, true);
        }
    }
    pci::msix_enable(bus, dev, f, &cap);
    // Device side: no config-change vector, RX queue -> entry 0,
    // TX queue stays unvectorized (TX completion is polled). The
    // vector registers live in the I/O window on legacy, inside
    // common_cfg on modern.
    let bound = if n.common != 0 {
        cw16(n.common + C_MSIX, MSIX_NO_VEC);
        cw16(n.common + C_QSEL, 0);
        cw16(n.common + C_QMSIX, 0);
        cw16(n.common + C_QSEL, 1);
        cw16(n.common + C_QMSIX, MSIX_NO_VEC);
        cw16(n.common + C_QSEL, 0);
        cr16(n.common + C_QMSIX)
    } else {
        outw(n.rx.io + R_MSIX_CFG, MSIX_NO_VEC);
        outw(n.rx.io + R_QSEL, 0);
        outw(n.rx.io + R_MSIX_Q, 0);
        outw(n.rx.io + R_QSEL, 1);
        outw(n.rx.io + R_MSIX_Q, MSIX_NO_VEC);
        outw(n.rx.io + R_QSEL, 0);
        inw(n.rx.io + R_MSIX_Q)
    };
    crate::log::printk(format_args!(
        "rustux: virtio: net MSI-X on ({} vectors, table @{:#x}) -> vec {:#x} rxq-vec {bound}",
        cap.nvec,
        cap.table,
        crate::apic::IRQ_VNET
    ));

    // Same ARP probe as the polling test — this time the reply must
    // arrive through vector IRQ_VNET, not be discovered by a poll.
    let mac = n.mac;
    let mut f = [0u8; 42];
    f[..6].copy_from_slice(&[0xff; 6]);
    f[6..12].copy_from_slice(&mac);
    f[12] = 0x08;
    f[13] = 0x06;
    f[14..22].copy_from_slice(&[0, 1, 8, 0, 6, 4, 0, 1]);
    f[22..28].copy_from_slice(&mac);
    f[28..32].copy_from_slice(&[10, 0, 2, 15]);
    f[38..42].copy_from_slice(&[10, 0, 2, 2]);
    let before = NET_RX_IRQS.load(Ordering::Relaxed);
    if !net_tx(&f) {
        return false;
    }
    // Up to ~1.5s: hlt until the MSI (or any IRQ) wakes us.
    let t0 = crate::apic::TICKS.load(Ordering::Relaxed);
    while NET_RX_IRQS.load(Ordering::Relaxed) == before
        && crate::apic::TICKS.load(Ordering::Relaxed) - t0 < 150
    {
        // SAFETY: hlt wakes on any delivered IRQ; IF is set.
        unsafe { core::arch::asm!("hlt", options(nomem, nostack)) };
    }
    let delivered = NET_RX_IRQS.load(Ordering::Relaxed) - before;
    // The IRQ already fired — harvest the reply from the used ring.
    // The first wake can carry a frame other than the probe's reply
    // (slirp noise or a stale used entry pending at arm time), so
    // keep draining through a short window until it arrives.
    let mut buf = [0u8; 1600];
    let mut got_reply = false;
    while crate::apic::TICKS.load(Ordering::Relaxed) - t0 < 160 && !got_reply {
        while let Some(n) = net_rx(&mut buf) {
            if n >= 42
                && buf[12] == 0x08
                && buf[13] == 0x06
                && buf[20] == 0
                && buf[21] == 2
                && buf[28..32] == [10, 0, 2, 2]
            {
                got_reply = true;
            }
        }
        if got_reply {
            break;
        }
        // SAFETY: hlt wakes on any delivered IRQ; IF is set.
        unsafe { core::arch::asm!("hlt", options(nomem, nostack)) };
    }
    crate::log::printk(format_args!(
        "rustux: virtio: net {} MSI IRQs on vec {:#x} (rx-caused), reply {}",
        delivered,
        crate::apic::IRQ_VNET,
        if got_reply { "received" } else { "missing" }
    ));
    delivered > 0 && got_reply
}
