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
    handshake_feat(io, 0)
}

/// Shared legacy handshake with a caller-chosen feature subset —
/// same sequence as handshake() but acks `feat` instead of none.
fn handshake_feat(io: u16, feat: u32) -> bool {
    outb(io + R_STATUS, 0);
    outb(io + R_STATUS, S_ACK);
    outb(io + R_STATUS, S_ACK | S_DRV);
    outl(io + R_GFEATURES, feat & inl(io + R_FEATURES));
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
/// VIRTIO_BLK_T_FLUSH — the write-cache flush, gated on F_FLUSH.
const REQ_FLUSH: u32 = 4;
/// VIRTIO_BLK_F_FLUSH (feature bit 9): the device accepts REQ_FLUSH.
const F_BLK_FLUSH: u32 = 1 << 9;
/// Sectors per single request — bounds the data staging block.
pub const BATCH: usize = 8;

/// One driven disk. All phys blocks come from alloc_frames and stay
/// owned for the driver's lifetime.
struct VDisk {
    vq: Vq,
    ctrl: u64,
    data: u64,
    sectors: u64,
    /// F_FLUSH negotiated — blk_flush may issue REQ_FLUSH.
    flush: bool,
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
    // Prefer F_FLUSH (write-cache flush command); a device that
    // refuses it still works — blk_flush then reports unsupported
    // and callers fall back to the write completion they already
    // had. handshake_feat resets the device each pass.
    let has_flush = handshake_feat(io, F_BLK_FLUSH);
    if !has_flush && !handshake(io) {
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
            flush: has_flush,
        });
    }
    NDISKS.store(1, Ordering::Release);
    let qsz = disk_for(0).map_or(0, |d| d.vq.size);
    crate::log::printk(format_args!(
        "rustux: virtio: blk {io:#x} qsize={qsz} {sectors} sectors ({} MiB) flush={has_flush}",
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
    let f = blk_flush(0);
    crate::log::printk(format_args!(
        "rustux: virtio: write datapath {w} verify {v} restore {s} flush {f}"
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

/// VIRTIO_BLK_T_FLUSH: a 2-descriptor chain — header OUT (type
/// only, no sector semantics), status byte IN. No data phase;
/// REQ_FLUSH is defined only when F_FLUSH negotiated.
pub fn blk_flush(i: usize) -> bool {
    let Some(d) = disk_for(i) else { return false };
    if !d.flush {
        return false;
    }
    let ctrl = mm::pmap(d.ctrl);
    // SAFETY: ctrl is our own DMA block; same header as request().
    unsafe {
        (ctrl as *mut u32).write_volatile(REQ_FLUSH);
        ((ctrl + 4) as *mut u32).write_volatile(0);
        ((ctrl + 8) as *mut u64).write_volatile(0);
        ((ctrl + 16) as *mut u8).write_volatile(0xff);
    }
    d.vq.put_desc(0, d.ctrl, 16, DESC_NEXT, 1);
    d.vq.put_desc(1, d.ctrl + 16, 1, DESC_WRITE, 0);
    fence(Ordering::SeqCst);
    if !d.vq.poll_once(0) {
        return false;
    }
    // SAFETY: ctrl+16 is the status byte the device just wrote.
    unsafe { ((ctrl + 16) as *const u8).read_volatile() == 0 }
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
    handshake_modern_feat(common, 0).is_some()
}

/// handshake_modern plus low-dword device features — accepts the
/// subset of `accept_lo` the device actually offers. Returns the
/// negotiated low mask (None on refusal).
fn handshake_modern_feat(common: u64, accept_lo: u32) -> Option<u32> {
    cw8(common + C_STATUS, 0);
    let mut spins = 0u64;
    while cr8(common + C_STATUS) != 0 {
        spins += 1;
        if spins > SPIN {
            return None;
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
        return None;
    }
    cw32(common + C_DFEAT_SEL, 0);
    let offered_lo = cr32(common + C_DFEAT);
    let accepted = accept_lo & offered_lo;
    cw32(common + C_GFEAT_SEL, 0);
    cw32(common + C_GFEAT, accepted);
    cw32(common + C_GFEAT_SEL, 1);
    cw32(common + C_GFEAT, 1); // accept VERSION_1 always
    cw8(common + C_STATUS, S_ACK | S_DRV | S_FEATOK);
    if cr8(common + C_STATUS) & S_FEATOK == 0 {
        cw8(common + C_STATUS, cr8(common + C_STATUS) | S_FAIL);
        return None;
    }
    Some(accepted)
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
    // VIRTIO_NET_F_CTRL_VQ (bit 17) — the only device feature this
    // datapath asks for; it buys the control queue at sel 2.
    const F_NET_CTRL_VQ: u32 = 1 << 17;
    let Some(feat) = handshake_modern_feat(vc.common, F_NET_CTRL_VQ) else {
        return false;
    };
    let has_ctrl = feat & F_NET_CTRL_VQ != 0;
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
    // The control queue is queue NQ-1 when CTRL_VQ negotiated —
    // sel 2 for the single queue pair QEMU gives us.
    let ctl = if has_ctrl && cr16(vc.common + C_NQ) >= 3 {
        Vq::setup_modern(vc.common, vc.notify, vc.notify_mult, vc.isr, 2)
    } else {
        None
    };
    let ctl_page = if ctl.is_some() {
        kalloc::alloc_frames(0)
    } else {
        None
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
    // Control queue: publish then prove — a command must come back
    // with the device's ack byte written to the staging page.
    if let (Some(q), Some(page)) = (ctl, ctl_page) {
        unsafe {
            *core::ptr::addr_of_mut!(NCTL) = Some(q);
            *core::ptr::addr_of_mut!(NCTL_PAGE) = page;
        }
        net_ctrl_selftest();
    }
    true
}

/// The negotiated control virtqueue and its staging page.
static mut NCTL: Option<Vq> = None;
static mut NCTL_PAGE: u64 = 0;

/// Issue one virtio-net control command: {class, cmd} header +
/// data as an OUT descriptor chained to a 1-byte device-writable
/// ack descriptor. Returns true on VIRTIO_NET_OK (ack 0).
/// Layout on the staging page: hdr+data at +0, ack byte at +511.
fn net_ctrl(class: u8, cmd: u8, data: &[u8]) -> bool {
    let Some(q) = (unsafe { (*core::ptr::addr_of_mut!(NCTL)).as_mut() }) else {
        return false;
    };
    if data.len() > 256 {
        return false;
    }
    let page = unsafe { *core::ptr::addr_of!(NCTL_PAGE) };
    let va = mm::pmap(page);
    // SAFETY: our staging page; hdr+data <= 258B at +0, ack at +511.
    unsafe {
        (va as *mut u8).write_volatile(class);
        ((va + 1) as *mut u8).write_volatile(cmd);
        core::ptr::copy_nonoverlapping(data.as_ptr(), (va + 2) as *mut u8, data.len());
        ((va + 511) as *mut u8).write_volatile(0xff);
    }
    q.put_desc(0, page, 2 + data.len() as u32, DESC_NEXT, 1);
    q.put_desc(1, page + 511, 1, DESC_WRITE, 0);
    q.avail_push(0);
    q.notify();
    if !q.poll_once(0) {
        return false;
    }
    // SAFETY: our staging page.
    unsafe { ((va + 511) as *const u8).read_volatile() == 0 }
}

/// Boot proof for the control queue: RX-mode commands (promisc,
/// allmulti — class VIRTIO_NET_CTRL_RX=0) and a MAC-table set
/// (class VIRTIO_NET_CTRL_MAC=1, cmd VIRTIO_NET_CTRL_MAC_TABLE_SET=0)
/// must each ack VIRTIO_NET_OK. Poll-based — safe pre-sti.
fn net_ctrl_selftest() {
    let promisc = net_ctrl(0, 0, &[1]);
    let allmulti = net_ctrl(0, 1, &[1]);
    // MAC table: the unicast set first {u32 nuni, u8 macs[][6]},
    // then multicast {u32 nmulti, macs...}.
    let mut tbl = [0u8; 14];
    tbl[0..4].copy_from_slice(&1u32.to_le_bytes());
    if let Some(n) = vnet() {
        tbl[4..10].copy_from_slice(&n.mac);
    }
    let mactbl = net_ctrl(1, 0, &tbl);
    crate::log::printk(format_args!(
        "rustux: virtio: net ctrlq promisc {promisc} allmulti {allmulti} mac-table {mactbl}"
    ));
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

// -------------------------------------------------------------------
// virtio-rng — a hardware entropy tap for the kernel pool.

/// Transitional virtio-rng (QEMU's `virtio-rng-pci` presents this).
const DEV_RNG: u16 = 0x1005;
/// Fill buffers posted at once; each is a 64-byte single-descriptor
/// request the device writes entropy into.
const N_RNG: usize = 8;

static mut RNGQ: Option<Vq> = None;
static mut RNGPG: u64 = 0;
static mut RNG_SEEN: u16 = 0;

/// Drain completed entropy buffers into `out`, re-posting each
/// drained slot so the posted pool never shrinks. Returns bytes
/// collected. Boot-context only — the ring state is unguarded.
fn rng_collect(out: &mut [u8]) -> usize {
    // SAFETY: RNGQ/RNGPG write-once at init; same single-context
    // contract as the rest of the driver statics.
    let q = unsafe { (*core::ptr::addr_of_mut!(RNGQ)).as_mut() };
    let Some(q) = q else { return 0 };
    let pg = unsafe { *core::ptr::addr_of!(RNGPG) };
    let mut got = 0usize;
    let used = q.used_idx();
    while unsafe { *core::ptr::addr_of!(RNG_SEEN) } != used && got < out.len() {
        let seen = unsafe { *core::ptr::addr_of!(RNG_SEEN) };
        let (id, len) = q.used_entry(seen as usize);
        unsafe {
            *core::ptr::addr_of_mut!(RNG_SEEN) = seen.wrapping_add(1)
        };
        let id = id as usize;
        if id >= N_RNG {
            break; // device wrote a bogus id — nothing to re-post
        }
        let n = (len as usize).min(64).min(out.len() - got);
        // SAFETY: our fill page; the device wrote len<=64 bytes at
        // id*64.
        unsafe {
            core::ptr::copy_nonoverlapping(
                (mm::pmap(pg) + (id * 64) as u64) as *const u8,
                out[got..].as_mut_ptr(),
                n,
            );
        }
        got += n;
        q.put_desc(id, pg + (id * 64) as u64, 64, DESC_WRITE, 0);
        q.avail_push(id as u16);
    }
    if got > 0 {
        q.notify();
    }
    got
}

/// Probe a transitional virtio-rng function, post its fill buffers,
/// spin for the first draw, and fold it into the kernel pool.
/// Returns the number of entropy bytes fed — 0 when absent.
pub fn rng_init() -> u32 {
    let Some((io, _)) = probe_io(DEV_RNG) else {
        return 0;
    };
    if !handshake(io) {
        return 0;
    }
    let Some(q) = Vq::setup(io, 0) else {
        fail(io);
        return 0;
    };
    let Some(pg) = kalloc::alloc_frames(0) else {
        fail(io);
        return 0;
    };
    outb(io + R_STATUS, S_ACK | S_DRV | S_FEATOK | S_DRVOK);
    // SAFETY: init runs once, before tasks exist.
    unsafe {
        *core::ptr::addr_of_mut!(RNGPG) = pg;
        *core::ptr::addr_of_mut!(RNGQ) = Some(q);
        *core::ptr::addr_of_mut!(RNG_SEEN) = 0;
    }
    // SAFETY: RNGQ was just published above.
    let q = unsafe { (*core::ptr::addr_of!(RNGQ)).as_ref().unwrap() };
    for i in 0..N_RNG {
        q.put_desc(i, pg + (i * 64) as u64, 64, DESC_WRITE, 0);
        q.avail_push(i as u16);
    }
    q.notify();
    // The backend fills at its own pace (QEMU rate-limits to
    // ~64B/period) — spin until the used ring drains something.
    let mut spins = 0u64;
    while unsafe { *core::ptr::addr_of!(RNG_SEEN) } == q.used_idx()
        && spins < SPIN
    {
        spins += 1;
        core::hint::spin_loop();
    }
    let mut ent = [0u8; 256];
    let fed = rng_collect(&mut ent);
    // Feed the pool before the buffer is reused.
    crate::rand::reseed(&ent[..fed]);
    // Proof the feed is real entropy, not a zero page: a live device
    // never returns a constant buffer.
    let nonuniform =
        fed > 0 && ent[..fed].iter().any(|b| *b != ent[0]);
    crate::log::printk(format_args!(
        "rustux: virtio: rng {io:#x} fed {fed}B -> reseed (nonuniform {nonuniform})"
    ));
    ent.fill(0);
    fed as u32
}

// -------------------------------------------------------------------
// virtio-console — a second console channel (Linux's /dev/hvc0).
//
// Without the multiport feature the device carries one port: queue
// 0 is its receive queue (device fills posted buffers), queue 1 the
// transmit queue (guest bytes out to the chardev backend).

/// Transitional virtio-console (QEMU's `virtio-console`).
const DEV_CON: u16 = 0x1003;
/// Posted RX buffers, 128 bytes each — short lines flow, a flood
/// just leaves buffers unconsumed until the next drain.
const N_CON: usize = 8;
const CON_BUFSZ: usize = 128;

static mut CONRX: Option<Vq> = None;
static mut CONTX: Option<Vq> = None;
static mut CONRX_BUFS: u64 = 0;
static mut CONTX_BUFS: u64 = 0;
static mut CON_SEEN: u16 = 0;
/// Drained-but-unread console bytes — a small in-kernel FIFO so a
/// read() doesn't have to line up with a device completion.
const CON_RXQ: usize = 2048;
static mut CON_RXQ_BUF: [u8; CON_RXQ] = [0; CON_RXQ];
static mut CON_RXQ_LEN: usize = 0;

/// Drain completed RX buffers into the FIFO and re-post them.
/// Returns bytes newly appended. Single-context discipline, same
/// as the rest of the driver — callers serialize.
fn con_drain() -> usize {
    let Some(q) = (unsafe { (*core::ptr::addr_of_mut!(CONRX)).as_mut() }) else {
        return 0;
    };
    let bufs = unsafe { *core::ptr::addr_of!(CONRX_BUFS) };
    let mut got = 0usize;
    let seen_start = unsafe { *core::ptr::addr_of!(CON_SEEN) };
    let used = q.used_idx();
    while unsafe { *core::ptr::addr_of!(CON_SEEN) } != used {
        let seen = unsafe { *core::ptr::addr_of!(CON_SEEN) };
        let (id, len) = q.used_entry(seen as usize);
        unsafe {
            *core::ptr::addr_of_mut!(CON_SEEN) = seen.wrapping_add(1)
        };
        let id = id as usize;
        if id >= N_CON {
            break; // bogus id — slot lost, never re-posted
        }
        let n = (len as usize).min(CON_BUFSZ);
        let room = CON_RXQ - unsafe { *core::ptr::addr_of!(CON_RXQ_LEN) };
        let take = n.min(room);
        // SAFETY: our RX page and FIFO; bounds clamped above.
        unsafe {
            core::ptr::copy_nonoverlapping(
                (mm::pmap(bufs) + (id * CON_BUFSZ) as u64) as *const u8,
                core::ptr::addr_of_mut!(CON_RXQ_BUF).cast::<u8>().add(*core::ptr::addr_of!(CON_RXQ_LEN)),
                take,
            );
            *core::ptr::addr_of_mut!(CON_RXQ_LEN) += take;
        }
        got += take;
        q.put_desc(id, bufs + (id * CON_BUFSZ) as u64, CON_BUFSZ as u32, DESC_WRITE, 0);
        q.avail_push(id as u16);
    }
    // Re-posted buffers count even on a zero-length completion —
    // without the kick the device may never notice them.
    if unsafe { *core::ptr::addr_of!(CON_SEEN) } != seen_start {
        q.notify();
    }
    got
}

/// Bytes waiting after a drain — the poll path calls this so
/// POLLIN reflects the device, not just the leftover FIFO.
pub fn console_pending() -> usize {
    con_drain();
    unsafe { *core::ptr::addr_of!(CON_RXQ_LEN) }
}

/// A live console channel (for the dev-node mint).
pub fn console_present() -> bool {
    unsafe { (*core::ptr::addr_of!(CONTX)).is_some() }
}

/// read() source for /dev/hvc0: drain, then copy out up to `len`
/// bytes of queued console input. Returns bytes delivered — 0 on
/// empty (the device node reports what's there; blocking tty
/// semantics are the ldisc layer's job, not this channel's).
pub fn console_read(out: &mut [u8]) -> usize {
    con_drain();
    let have = unsafe { *core::ptr::addr_of!(CON_RXQ_LEN) };
    let n = have.min(out.len());
    if n > 0 {
        // SAFETY: our FIFO; shift the remainder down.
        unsafe {
            let p = core::ptr::addr_of_mut!(CON_RXQ_BUF).cast::<u8>();
            core::ptr::copy_nonoverlapping(p, out.as_mut_ptr(), n);
            core::ptr::copy(p.add(n), p, have - n);
            *core::ptr::addr_of_mut!(CON_RXQ_LEN) = have - n;
        }
    }
    n
}

/// write() sink for /dev/hvc0: stage the bytes into the TX page,
/// post the chain, and spin for the completion — the same
/// request/poll shape as virtio-blk's `request`.
pub fn console_write(bytes: &[u8]) -> usize {
    if bytes.is_empty() {
        return 0;
    }
    let Some(q) = (unsafe { (*core::ptr::addr_of_mut!(CONTX)).as_mut() }) else {
        return 0;
    };
    let bufs = unsafe { *core::ptr::addr_of!(CONTX_BUFS) };
    let n = bytes.len().min(4096);
    // SAFETY: our TX staging page; n <= page size.
    unsafe {
        core::ptr::copy_nonoverlapping(
            bytes.as_ptr(),
            mm::pmap(bufs) as *mut u8,
            n,
        );
    }
    // Single readable descriptor — device reads `n` bytes out.
    q.put_desc(0, bufs, n as u32, 0, 0);
    if !q.poll_once(0) {
        return 0;
    }
    n
}

/// Probe a transitional virtio-console function, set up both port-0
/// queues, post the RX buffers, and run a TX datapath proof —
/// "proof" bytes land in the chardev backend. Returns true when a
/// console channel is live.
pub fn console_init() -> bool {
    let Some((io, _)) = probe_io(DEV_CON) else {
        return false;
    };
    // VIRTIO_CONSOLE_F_MULTIPORT (bit 3) — the only feature this
    // channel needs; QEMU's virtio-serial always offers it.
    if !handshake_feat(io, 1 << 3) {
        return false;
    }
    // Queue map (proven empirically): QEMU builds an ivq/ovq pair
    // per existing port in id order — port 0 lands on sel 0,1 —
    // then the CONTROL pair (qnum 32 vs the data queues' 128),
    // then spare pairs. Ports start closed; only the control
    // protocol opens them.
    let max_ports = inl(io + R_CFG + 4).min(64);
    let (Some(civq), Some(covq)) = (Vq::setup(io, 2), Vq::setup(io, 3)) else {
        fail(io);
        return false;
    };
    let Some(cpage) = kalloc::alloc_frames(0) else {
        fail(io);
        return false;
    };
    outb(io + R_STATUS, S_ACK | S_DRV | S_FEATOK | S_DRVOK);
    // Post control-receive buffers: the device answers DEVICE_READY
    // with PORT_ADD (+NAME/READY) events into them. Buffer 0..3 at
    // cpage+0..255; sent messages stage at cpage+256.
    for i in 0..4usize {
        civq.put_desc(i, cpage + (i * 64) as u64, 64, DESC_WRITE, 0);
        civq.avail_push(i as u16);
    }
    civq.notify();
    // DEVICE_READY unlocks the control channel — the device holds
    // all events until it arrives.
    let cva = mm::pmap(cpage);
    let put_ctl = |id: u32, ev: u16, val: u16| {
        // SAFETY: cpage+256 is our staging slot, 8B message.
        unsafe {
            (cva as *mut u32).add(64).write_volatile(id);
            (cva as *mut u16).add(130).write_volatile(ev);
            (cva as *mut u16).add(131).write_volatile(val);
        }
        covq.put_desc(0, cpage + 256, 8, 0, 0);
        covq.poll_once(0)
    };
    if !put_ctl(0, 0, 1) {
        // DEVICE_READY
        fail(io);
        return false;
    }
    // Drain the event burst — PORT_ADD names the port id QEMU gave
    // the virtconsole (auto-assigned, id 0 for the first port).
    let mut port_id = u32::MAX;
    let mut seen = 0u16;
    let mut spins = 0u64;
    while seen != civq.used_idx() || spins < 1_000_000 {
        spins += 1;
        core::hint::spin_loop();
        while seen != civq.used_idx() {
            let (id, _len) = civq.used_entry(seen as usize);
            seen = seen.wrapping_add(1);
            let slot = (id as usize).min(3);
            // SAFETY: our ctrl page; the event record is 8B at
            // slot*64.
            let (pid, ev, _val) = unsafe {
                let p = cva + (slot * 64) as u64;
                (
                    (p as *const u32).read_volatile(),
                    (p as *const u16).add(2).read_volatile(),
                    (p as *const u16).add(3).read_volatile(),
                )
            };
            crate::log::printk(format_args!(
                "rustux: virtio: console ctrl ev={ev} id={pid} len={_len}"
            ));
            if ev == 1 && port_id == u32::MAX {
                // VIRTIO_CONSOLE_PORT_ADD
                port_id = pid;
            }
            civq.put_desc(slot, cpage + (slot * 64) as u64, 64, DESC_WRITE, 0);
            civq.avail_push(slot as u16);
        }
        if port_id != u32::MAX {
            break;
        }
    }
    if port_id == u32::MAX || port_id > max_ports {
        crate::log::printk(format_args!(
            "rustux: virtio: console no PORT_ADD"
        ));
        return false;
    }
    // Open the port — data only flows after PORT_OPEN.
    if !put_ctl(port_id, 6, 1) {
        fail(io);
        return false;
    }
    // The port's own queue pair: sel 2*id in, sel 2*id+1 out —
    // port 0 lands on sel 0/1, before the control pair.
    let (Some(rx), Some(tx)) = (
        Vq::setup(io, (2 * port_id) as u16),
        Vq::setup(io, (2 * port_id + 1) as u16),
    ) else {
        fail(io);
        return false;
    };
    let (Some(rx_bufs), Some(tx_bufs)) =
        (kalloc::alloc_frames(0), kalloc::alloc_frames(0))
    else {
        fail(io);
        return false;
    };
    let (rxsz, txsz) = (rx.size, tx.size);
    outb(io + R_STATUS, S_ACK | S_DRV | S_FEATOK | S_DRVOK);
    // SAFETY: init runs once, before tasks exist.
    unsafe {
        *core::ptr::addr_of_mut!(CONRX_BUFS) = rx_bufs;
        *core::ptr::addr_of_mut!(CONTX_BUFS) = tx_bufs;
        *core::ptr::addr_of_mut!(CON_SEEN) = 0;
        *core::ptr::addr_of_mut!(CON_RXQ_LEN) = 0;
        *core::ptr::addr_of_mut!(CONRX) = Some(rx);
        *core::ptr::addr_of_mut!(CONTX) = Some(tx);
    }
    // Post all RX buffers — the device fills them as backend input
    // arrives; con_drain consumes them at read time.
    // SAFETY: CONRX just published.
    let rx = unsafe { (*core::ptr::addr_of!(CONRX)).as_ref().unwrap() };
    for i in 0..N_CON {
        rx.put_desc(i, rx_bufs + (i * CON_BUFSZ) as u64, CON_BUFSZ as u32, DESC_WRITE, 0);
        rx.avail_push(i as u16);
    }
    rx.notify();
    // TX datapath proof: bytes flow out the chardev backend — with
    // QEMU's file backend they land in the proof log verbatim.
    let w = console_write(b"rustux: hvc0 console online\n");
    crate::log::printk(format_args!(
        "rustux: virtio: console {io:#x} rxq={} txq={} tx-proof {w}B",
        rxsz, txsz
    ));
    true
}

// -------------------------------------------------------------------
// virtio-input — QEMU's virtio-keyboard-pci.
//
// Queue 0 is the eventq: the device fills posted buffers with
// virtio_input_event records {u16 type, u16 code, u32 value}. Queue
// 1 is the statusq (guest -> device LED/status reports — unused).
// EV_KEY records fold into the shared kbd evdev ring; EV_SYN and
// friends carry no payload the ring can express and are dropped.

/// Transitional virtio-input / modern-only id (QEMU resolves
/// `virtio-keyboard-pci` to the non-transitional variant on q35 —
/// 0x1052 has no legacy I/O BAR).
const DEV_VINPUT: u16 = 0x1012;
const DEV_VINPUT_MODERN: u16 = 0x1052;
/// Posted eventq buffers — one 8-byte virtio_input_event each.
const N_VIN: usize = 16;
const VIN_BUFSZ: usize = 8;
const EV_KEY: u16 = 1;

static mut VINQ: Option<Vq> = None;
static mut VIN_BUFS: u64 = 0;
static mut VIN_SEEN: u16 = 0;
/// Drained EV_KEY events — the boot proof counts these.
static VIN_EVENTS: AtomicU32 = AtomicU32::new(0);

/// Drain completed eventq buffers into the kbd evdev ring and
/// re-post them. Returns EV_KEY events pushed. Same single-context
/// discipline as con_drain — callers run in syscall/idle context.
pub fn vinput_drain() -> usize {
    let Some(q) = (unsafe { (*core::ptr::addr_of_mut!(VINQ)).as_mut() }) else {
        return 0;
    };
    let bufs = unsafe { *core::ptr::addr_of!(VIN_BUFS) };
    let mut got = 0usize;
    let seen_start = unsafe { *core::ptr::addr_of!(VIN_SEEN) };
    let used = q.used_idx();
    while unsafe { *core::ptr::addr_of!(VIN_SEEN) } != used {
        let seen = unsafe { *core::ptr::addr_of!(VIN_SEEN) };
        let (id, _len) = q.used_entry(seen as usize);
        unsafe {
            *core::ptr::addr_of_mut!(VIN_SEEN) = seen.wrapping_add(1)
        };
        let id = id as usize;
        if id >= N_VIN {
            break; // bogus id — slot lost, never re-posted
        }
        // SAFETY: our event page; the record is 8B at id*8.
        let (ty, code, val) = unsafe {
            let p = mm::pmap(bufs) + (id * VIN_BUFSZ) as u64;
            (
                (p as *const u16).read_volatile(),
                (p as *const u16).add(1).read_volatile(),
                (p as *const u32).add(1).read_volatile(),
            )
        };
        if ty == EV_KEY {
            crate::kbd::ev_push_ext(code, val.min(2) as u8);
            VIN_EVENTS.fetch_add(1, Ordering::Relaxed);
            got += 1;
        }
        q.put_desc(id, bufs + (id * VIN_BUFSZ) as u64, VIN_BUFSZ as u32, DESC_WRITE, 0);
        q.avail_push(id as u16);
    }
    // Re-posted buffers count even when nothing useful arrived.
    if unsafe { *core::ptr::addr_of!(VIN_SEEN) } != seen_start {
        q.notify();
    }
    got
}

/// Live virtio-input channel (drained events counted).
pub fn vinput_present() -> bool {
    unsafe { (*core::ptr::addr_of!(VINQ)).is_some() }
}

/// Probe a virtio-input function — modern transport first (QEMU's
/// q35 `virtio-keyboard-pci` resolves non-transitional), then the
/// legacy fallback. Sets up eventq + statusq, posts the event
/// buffers, logs the device name from the config space
/// (select VIRTIO_INPUT_CFG_DEV_NAME = 0x08; layout select@0,
/// subsel@1, size@2, u@8).
pub fn vinput_init() -> bool {
    const CFG_NAME: u8 = 0x08;
    let mut name = [0u8; 32];
    let nsz: usize;
    let (evq, _stq);
    if let Some((bus, dev, f)) = pci::find(VENDOR, DEV_VINPUT_MODERN) {
        pci::command_or(bus, dev, f, pci::CMD_MEM_SPACE | pci::CMD_BUS_MASTER);
        let Some(vc) = virtio_caps(bus, dev, f) else {
            crate::log::printk(format_args!(
                "rustux: virtio: modern input lacks a full cap set — skipped"
            ));
            return false;
        };
        if !handshake_modern(vc.common) || cr16(vc.common + C_NQ) < 2 {
            cw8(vc.common + C_STATUS, cr8(vc.common + C_STATUS) | S_FAIL);
            return false;
        }
        let (Some(e), Some(s)) = (
            Vq::setup_modern(vc.common, vc.notify, vc.notify_mult, vc.isr, 0),
            Vq::setup_modern(vc.common, vc.notify, vc.notify_mult, vc.isr, 1),
        ) else {
            cw8(vc.common + C_STATUS, cr8(vc.common + C_STATUS) | S_FAIL);
            return false;
        };
        cw8(vc.dev, CFG_NAME);
        nsz = (cr8(vc.dev + 2) as usize).min(32);
        for (i, b) in name.iter_mut().enumerate().take(nsz) {
            *b = cr8(vc.dev + 8 + i as u64);
        }
        cw8(vc.common + C_STATUS, S_ACK | S_DRV | S_FEATOK | S_DRVOK);
        evq = e;
        _stq = s;
    } else {
        let Some((io, _)) = probe_io(DEV_VINPUT) else {
            return false;
        };
        if !handshake(io) {
            return false;
        }
        outb(io + R_CFG, CFG_NAME);
        outb(io + R_CFG + 1, 0);
        nsz = (inb(io + R_CFG + 2) as usize).min(32);
        for (i, b) in name.iter_mut().enumerate().take(nsz) {
            *b = inb(io + R_CFG + 8 + i as u16);
        }
        let (Some(e), Some(s)) = (Vq::setup(io, 0), Vq::setup(io, 1)) else {
            fail(io);
            return false;
        };
        outb(io + R_STATUS, S_ACK | S_DRV | S_FEATOK | S_DRVOK);
        evq = e;
        _stq = s;
    }
    let Some(bufs) = kalloc::alloc_frames(0) else {
        return false;
    };
    let qsz = evq.size;
    // SAFETY: init runs once, before tasks exist.
    unsafe {
        *core::ptr::addr_of_mut!(VIN_BUFS) = bufs;
        *core::ptr::addr_of_mut!(VIN_SEEN) = 0;
        *core::ptr::addr_of_mut!(VINQ) = Some(evq);
    }
    // Post all event buffers — device fills one record each.
    let q = unsafe { (*core::ptr::addr_of!(VINQ)).as_ref().unwrap() };
    for i in 0..N_VIN {
        q.put_desc(i, bufs + (i * VIN_BUFSZ) as u64, VIN_BUFSZ as u32, DESC_WRITE, 0);
        q.avail_push(i as u16);
    }
    q.notify();
    let nstr = core::str::from_utf8(&name[..nsz]).unwrap_or("?");
    crate::log::printk(format_args!(
        "rustux: virtio: input '{nstr}' evq={qsz}"
    ));
    true
}

/// Post-sti proof: kbdfeed.py injects shift taps via QMP — a
/// bounded wait must drain at least one EV_KEY through the queue
/// (the PS/2 path can't fill this counter).
pub fn vinput_selftest() -> bool {
    let mut spins = 0u64;
    while spins < 60_000_000 {
        if VIN_EVENTS.load(Ordering::Relaxed) > 0 {
            break;
        }
        vinput_drain();
        spins += 1;
        core::hint::spin_loop();
    }
    let n = VIN_EVENTS.load(Ordering::Relaxed);
    crate::log::printk(format_args!(
        "rustux: virtio: input {n} evdev event(s) through virtio-input"
    ));
    n > 0
}

// -------------------------------------------------------------------
// virtio-balloon — QEMU's virtio-balloon-pci (transitional slot
// 0x1002, PCI subsystem carries the real virtio id 5).
//
// Queue 0 = inflate (guest hands page-frame numbers to the host —
// those frames leave the allocator until returned); queue 1 =
// deflate (host fills a posted buffer with PFNs to give back).
// Config space at R_CFG: le32 num_pages (host's target) at +0,
// le32 actual (guest's report) at +4.

/// Transitional virtio-balloon PCI slot.
const DEV_BALLOON: u16 = 0x1002;
/// PFNs per queue posting — QEMU's conventional chunk size.
const BAL_CHUNK: usize = 256;
/// Held-page registry cap — bounds both the inflate burst and the
/// deflate verification table.
const BAL_MAX: usize = 16384;

static mut BAL_IV: Option<Vq> = None;
static mut BAL_DV: Option<Vq> = None;
/// One shared staging page: inflate PFN array at +0 (1KiB),
/// deflate buffer at +2048 (1KiB).
static mut BAL_PAGE: u64 = 0;
/// PFNs we have actually ballooned — the deflate free path
/// verifies against this so a device-returned PFN can never free
/// a frame the balloon doesn't own.
static mut BAL_HELD: [u32; BAL_MAX] = [0; BAL_MAX];
static mut BAL_HELD_N: usize = 0;
static mut BAL_IO: u16 = 0;
/// Deflate used-ring position (absolute idx).
static mut BAL_SEEN: u16 = 0;
/// PFNs riding the outstanding deflate buffer — freed on completion.
static mut BAL_DEF_PEND: usize = 0;
/// One-shot log latches so a long pump doesn't spam the ring.
/// Re-entrancy guard — the pump is callable from IRQ and syscall context.
static BAL_BUSY: AtomicU32 = AtomicU32::new(0);
static BAL_INF_LOGGED: AtomicU32 = AtomicU32::new(0);
static BAL_DEF_LOGGED: AtomicU32 = AtomicU32::new(0);

/// Remove `pfn` from the held registry — returns true when the
/// balloon actually owned it.
fn held_remove(pfn: u32) -> bool {
    let n = unsafe { *core::ptr::addr_of!(BAL_HELD_N) };
    let held = unsafe { &mut *core::ptr::addr_of_mut!(BAL_HELD) };
    if let Some(i) = held[..n].iter().position(|&p| p == pfn) {
        held[i] = held[n - 1];
        unsafe { *core::ptr::addr_of_mut!(BAL_HELD_N) = n - 1 };
        true
    } else {
        false
    }
}

/// Report the current held count in the config's `actual` field.
fn bal_report() {
    let io = unsafe { *core::ptr::addr_of!(BAL_IO) };
    if io != 0 {
        let n = unsafe { *core::ptr::addr_of!(BAL_HELD_N) } as u32;
        outl(io + R_CFG + 4, n);
    }
}

/// Periodic pump — called from stdin_pump (syscall/idle context).
/// Compares the host's num_pages target with the held registry:
/// inflates the delta in BAL_CHUNK batches, then drains any
/// deflate completions and frees verified frames.
pub fn balloon_pump() {
    let io = unsafe { *core::ptr::addr_of!(BAL_IO) };
    if io == 0 {
        return;
    }
    // The pump runs from the tick IRQ and from syscall context —
    // a timer preemption mid-inflate would race the held registry.
    // Skip a re-entrant call; the active context finishes the work.
    if BAL_BUSY
        .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        return;
    }
    balloon_pump_inner(io);
    BAL_BUSY.store(0, Ordering::Release);
}

fn balloon_pump_inner(io: u16) {
    let page = unsafe { *core::ptr::addr_of!(BAL_PAGE) };
    let va = mm::pmap(page);
    // ---- inflate toward the target ----
    let target = inl(io + R_CFG) as usize;
    while unsafe { *core::ptr::addr_of!(BAL_HELD_N) } < target
        && unsafe { *core::ptr::addr_of!(BAL_HELD_N) } < BAL_MAX
    {
        let held = unsafe { *core::ptr::addr_of!(BAL_HELD_N) };
        let want = (target - held).min(BAL_CHUNK).min(BAL_MAX - held);
        let mut n = 0usize;
        while n < want {
            let Some(p) = kalloc::alloc_frames(0) else { break };
            // SAFETY: our staging page; n < 256 -> +4n inside +0..+1024.
            unsafe {
                ((va + (n * 4) as u64) as *mut u32).write_volatile((p >> 12) as u32);
                (*core::ptr::addr_of_mut!(BAL_HELD))[held + n] = (p >> 12) as u32;
            }
            n += 1;
        }
        if n == 0 {
            break; // allocator empty — can't reach the target
        }
        unsafe { *core::ptr::addr_of_mut!(BAL_HELD_N) = held + n };
        if let Some(iv) = unsafe { (*core::ptr::addr_of!(BAL_IV)).as_ref() } {
            iv.put_desc(0, page, (n * 4) as u32, 0, 0);
            iv.poll_once(0);
        }
        bal_report();
        if BAL_INF_LOGGED.swap(1, Ordering::Relaxed) == 0 {
            crate::log::printk(format_args!(
                "rustux: virtio: balloon inflated toward target {target} pages"
            ));
        }
    }
    // ---- deflate toward the target ----
    // The deflate queue carries guest-posted PFNs (OUT buffers) —
    // the device releases them, then the completed PFNs may go back
    // to the allocator once verified against the held registry.
    let Some(dv) = (unsafe { (*core::ptr::addr_of_mut!(BAL_DV)).as_mut() }) else {
        return; // flag resets in the wrapper
    };
    let pend = unsafe { *core::ptr::addr_of!(BAL_DEF_PEND) };
    if pend != 0 && unsafe { *core::ptr::addr_of!(BAL_SEEN) } != dv.used_idx() {
        let seen = unsafe { *core::ptr::addr_of!(BAL_SEEN) };
        unsafe { *core::ptr::addr_of_mut!(BAL_SEEN) = seen.wrapping_add(1) };
        let mut freed = 0usize;
        for i in 0..pend {
            // SAFETY: we wrote the PFNs at page+2048 before posting.
            let pfn = unsafe {
                ((va + 2048 + (i * 4) as u64) as *const u32).read_volatile()
            };
            // Only free a frame the balloon actually owns.
            if held_remove(pfn) {
                kalloc::free_frame((pfn as u64) << 12);
                freed += 1;
            }
        }
        unsafe { *core::ptr::addr_of_mut!(BAL_DEF_PEND) = 0 };
        bal_report();
        if freed > 0 && BAL_DEF_LOGGED.swap(1, Ordering::Relaxed) == 0 {
            crate::log::printk(format_args!(
                "rustux: virtio: balloon deflated {freed} pages back to the allocator"
            ));
        }
    }
    let held = unsafe { *core::ptr::addr_of!(BAL_HELD_N) };
    if unsafe { *core::ptr::addr_of!(BAL_DEF_PEND) } == 0 && held > target {
        let n = (held - target).min(BAL_CHUNK);
        for i in 0..n {
            // SAFETY: held[i..] live; staging +2048..+3072 is ours.
            let pfn = unsafe { (*core::ptr::addr_of!(BAL_HELD))[held - n + i] };
            unsafe {
                ((va + 2048 + (i * 4) as u64) as *mut u32).write_volatile(pfn);
            }
        }
        dv.put_desc(0, page + 2048, (n * 4) as u32, 0, 0);
        dv.avail_push(0);
        dv.notify();
        unsafe { *core::ptr::addr_of_mut!(BAL_DEF_PEND) = n };
    }
}

/// Probe a transitional virtio-balloon function, set up both
// queues, post the deflate buffer, and leave the pump to track
/// the host's num_pages target.
pub fn balloon_init() -> bool {
    let Some((io, _)) = probe_io(DEV_BALLOON) else {
        return false;
    };
    if !handshake(io) {
        return false;
    }
    let (Some(iv), Some(dv)) = (Vq::setup(io, 0), Vq::setup(io, 1)) else {
        fail(io);
        return false;
    };
    let Some(page) = kalloc::alloc_frames(0) else {
        fail(io);
        return false;
    };
    let (ivsz, dvsz) = (iv.size, dv.size);
    outb(io + R_STATUS, S_ACK | S_DRV | S_FEATOK | S_DRVOK);
    // SAFETY: init runs once, before tasks exist.
    unsafe {
        *core::ptr::addr_of_mut!(BAL_PAGE) = page;
        *core::ptr::addr_of_mut!(BAL_HELD_N) = 0;
        *core::ptr::addr_of_mut!(BAL_SEEN) = 0;
        *core::ptr::addr_of_mut!(BAL_DEF_PEND) = 0;
        *core::ptr::addr_of_mut!(BAL_IV) = Some(iv);
        *core::ptr::addr_of_mut!(BAL_DV) = Some(dv);
        // Readiness gate LAST: a tick-IRQ pump that sees io!=0 must
        // find every static already populated.
        *core::ptr::addr_of_mut!(BAL_IO) = io;
    }
    crate::log::printk(format_args!(
        "rustux: virtio: balloon {io:#x} ivq={ivsz} dvq={dvsz} target {} pages",
        inl(io + R_CFG)
    ));
    true
}
