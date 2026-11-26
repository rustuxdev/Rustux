//! NVMe storage over PCI — polling, no MSI-X.
//!
//! QEMU's nvme device (vendor 1b36, device 0004) exposes a 64-bit
//! MMIO BAR0. The driver runs the minimum spec dance: disable ->
//! admin queue pair -> enable -> Identify Controller/Namespace ->
//! create one I/O queue pair -> NVM Read commands through a
//! command-id-tagged, phase-bit-polled completion ring.
//!
//! Device trust: the completion's `cid` field is device-written and
//! only ever checked for equality against the slot we posted — never
//! used as an index. Data lands in our own staging buffer bounded by
//! the request, so a hostile `len` can't overread.

use crate::kalloc;
use crate::mm;
use crate::pci;
use core::sync::atomic::Ordering;
use core::sync::atomic::{AtomicU32, AtomicU64};

const VENDOR: u16 = 0x1b36; // QEMU (Red Hat)
const DEVICE: u16 = 0x0010; // QEMU's nvme device (older: 0x0004)

// Register offsets in BAR0.
const CAP: u64 = 0x00; // ro u64 — controller capabilities
const CC: u64 = 0x14; // rw u32 — controller configuration
const CSTS: u64 = 0x1c; // ro u32 — controller status
const AQA: u64 = 0x24; // rw u32 — admin queue attributes
const ASQ: u64 = 0x28; // rw u64 — admin submission queue base
const ACQ: u64 = 0x30; // rw u64 — admin completion queue base
const DBL: u64 = 0x1000; // doorbell array base

// CC fields.
const CC_EN: u32 = 1;
const CC_IOSQES: u32 = 6 << 16; // 64B submission entries
const CC_IOCQES: u32 = 4 << 20; // 16B completion entries

// Admin opcodes.
const OP_CREATE_IO_SQ: u8 = 0x01;
const OP_CREATE_IO_CQ: u8 = 0x05;
const OP_IDENTIFY: u8 = 0x06;
// NVM command-set opcodes.
const OP_READ: u8 = 0x02;
const OP_WRITE: u8 = 0x01;

const AQSIZE: u16 = 16;
const IQSIZE: u16 = 32;
/// Blocks per I/O read — one page of staging, PRP1 only (no list).
const BATCH: usize = 8;

/// Spin bound on register polls (RDY transitions) and completion
/// waits — QEMU answers in microseconds; the bound turns a dead
/// device into a false return instead of a hang.
const SPIN: u64 = 40_000_000;

static BAR: AtomicU64 = AtomicU64::new(0);
static NDISKS: AtomicU32 = AtomicU32::new(0);
/// I/O-CQ MSI-X deliveries — count only: the submit path consumes
/// completions via the phase bit, so the IRQ is purely a wake /
/// wiring proof, same contract as virtio-net's handler.
static IO_IRQS: AtomicU32 = AtomicU32::new(0);

/// MSI-X delivery on the I/O completion queue. Nothing to ack —
/// completions are phase-bit events, not a latched line.
pub fn on_irq() {
    IO_IRQS.fetch_add(1, Ordering::Relaxed);
}
/// Sector counts per bound namespace (512B units — only that LBAF
/// is bound; disk index indexes both arrays).
static NS_SECTORS: [AtomicU64; 4] = [
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
];
/// Bound disk index -> real nsid (inactive/unsupported namespaces
/// are skipped, so index i is NOT necessarily nsid i+1).
static NSID: [AtomicU32; 4] = [
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
];
/// Cap on bound namespaces — QEMU test rigs present two.
const MAXNS: u32 = 4;

/// One queue pair: contiguous DMA blocks for SQ entries (64B) and
/// CQ entries (16B), plus the ring bookkeeping. Phase flips each
/// time the CQ wraps — that, not a flag, is how a new completion is
/// told apart from a stale one.
struct NvmeQ {
    sq: u64,
    cq: u64,
    tail: u16,
    head: u16,
    phase: u16,
    size: u16,
    /// Next command id to tag a submission with.
    cid: u16,
}

static mut ADMINQ: Option<NvmeQ> = None;
static mut IOQ: Option<NvmeQ> = None;
/// 4KiB identify/scratch buffer and one page of I/O staging.
static SCRATCH: AtomicU64 = AtomicU64::new(0);

fn r32(off: u64) -> u32 {
    let base = BAR.load(Ordering::Relaxed);
    // SAFETY: BAR is an MMIO window confirmed by the caller's
    // is_mmio probe; pmap mirrors it uncached.
    unsafe { ((mm::pmap(base) + off) as *const u32).read_volatile() }
}

fn w32(off: u64, v: u32) {
    let base = BAR.load(Ordering::Relaxed);
    // SAFETY: as above.
    unsafe { ((mm::pmap(base) + off) as *mut u32).write_volatile(v) }
}

fn r64(off: u64) -> u64 {
    let base = BAR.load(Ordering::Relaxed);
    // SAFETY: as above.
    unsafe { ((mm::pmap(base) + off) as *const u64).read_volatile() }
}

fn w64(off: u64, v: u64) {
    let base = BAR.load(Ordering::Relaxed);
    // SAFETY: as above.
    unsafe { ((mm::pmap(base) + off) as *mut u64).write_volatile(v) }
}

/// Doorbell offset for `qid`'s submission tail (y=2*qid) or
/// completion head (y=2*qid+1): each is 4<<DSTRD bytes apart.
fn dbl(qid: u16, cq: bool, dstrd: u32) -> u64 {
    DBL + ((2 * qid as u64 + cq as u64) * (4 << dstrd))
}

fn wait_rdy(want: u32) -> bool {
    for _ in 0..SPIN {
        if r32(CSTS) & 1 == want {
            return true;
        }
        core::hint::spin_loop();
    }
    false
}

/// Allocate one queue pair: `size` submission slots of 64B and the
/// same count of 16B completion slots, zeroed so stale phase bits
/// start known. Both fit one page at our sizes.
fn q_alloc(size: u16) -> Option<NvmeQ> {
    let sq = kalloc::alloc_frames(0)?;
    let cq = kalloc::alloc_frames(0)?;
    // SAFETY: fresh pages we own for the driver's lifetime.
    unsafe {
        core::ptr::write_bytes(mm::pmap(sq) as *mut u8, 0, 4096);
        core::ptr::write_bytes(mm::pmap(cq) as *mut u8, 0, 4096);
    }
    Some(NvmeQ {
        sq,
        cq,
        tail: 0,
        head: 0,
        phase: 1,
        size,
        cid: 0,
    })
}

impl NvmeQ {
    /// Submit a command whose caller filled `ent` (64B, cid patched
    /// here), ring the SQ tail doorbell, then poll the CQ phase bit
    /// for its completion. Returns the completion's status field —
    /// 0 is success. The id is echoed untrusted: a hostile cid that
    /// doesn't match simply isn't consumed.
    fn submit(&mut self, qid: u16, dstrd: u32, ent: &mut [u8; 64]) -> bool {
        ent[2..4].copy_from_slice(&self.cid.to_le_bytes());
        let cid = self.cid;
        self.cid = self.cid.wrapping_add(1);
        let slot = self.tail % self.size;
        // SAFETY: slot < size within our own SQ page.
        unsafe {
            core::ptr::copy_nonoverlapping(
                ent.as_ptr(),
                (mm::pmap(self.sq) + slot as u64 * 64) as *mut u8,
                64,
            );
        }
        core::sync::atomic::fence(Ordering::SeqCst);
        self.tail = self.tail.wrapping_add(1);
        // The doorbell is a RING INDEX, not a counter — QEMU rejects
        // writes >= qsize as malformed, so a monotonic tail wedges
        // the queue permanently after `size` submissions.
        w32(dbl(qid, false, dstrd), (self.tail % self.size) as u32);
        // Completion poll: DW3 = {status<<16|phase, cid} — the phase
        // bit is status-field bit0 = DW3 bit16; CID is the low half.
        for _ in 0..SPIN {
            // SAFETY: head < size within our own CQ page.
            let dw3 = unsafe {
                ((mm::pmap(self.cq) + self.head as u64 * 16 + 12) as *const u32)
                    .read_volatile()
            };
            if (dw3 >> 16) & 1 == self.phase as u32 {
                let got_cid = (dw3 & 0xffff) as u16;
                let sf = (dw3 >> 17) & 0x7ff; // SC+SCT, phase excluded
                // Consume the slot: advance head, wrap -> flip phase.
                self.head += 1;
                if self.head == self.size {
                    self.head = 0;
                    self.phase ^= 1;
                }
                w32(dbl(qid, true, dstrd), self.head as u32);
                if got_cid == cid {
                    LAST_SF.store(sf, Ordering::Relaxed);
                    return sf == 0;
                }
                // Stray completion (device can't inject these without
                // an SBUF id we issued — keep polling for ours).
            }
            core::hint::spin_loop();
        }
        LAST_SF.store(0xdead, Ordering::Relaxed); // timed out
        false
    }
}

/// Fill an identify command: opcode + nsid + PRP1 -> scratch, CNS.
fn identify(q: &mut NvmeQ, qid: u16, dstrd: u32, nsid: u32, cns: u32) -> bool {
    let mut e = [0u8; 64];
    e[0] = OP_IDENTIFY;
    e[4..8].copy_from_slice(&nsid.to_le_bytes());
    e[24..32].copy_from_slice(&SCRATCH.load(Ordering::Relaxed).to_le_bytes());
    e[40..44].copy_from_slice(&cns.to_le_bytes());
    q.submit(qid, dstrd, &mut e)
}

/// Probe QEMU's NVMe function, bring up admin+I/O queues, identify
/// namespace 1 and bind it as disk 0. Returns the disk count.
/// `is_mmio` confirms BAR0 is device memory, not RAM.
pub fn init(is_mmio: impl Fn(u64, u64) -> bool) -> u32 {
    let Some((bus, dev, f)) = pci::find(VENDOR, DEVICE)
        .or_else(|| pci::find(VENDOR, 0x0004))
    else {
        return 0;
    };
    let bar = pci::bar_raw(bus, dev, f, 0);
    if bar & 1 != 0 || bar == 0 || bar == u32::MAX {
        crate::log::printk(format_args!("rustux: nvme: bad bar {bar:#x}"));
        return 0;
    }
    // 64-bit BAR: BAR1 carries the high dword.
    let hi = pci::bar_raw(bus, dev, f, 1) as u64;
    let base = ((bar & !0xf) as u64) | (hi << 32);
    if base == 0 || !is_mmio(base, 0x4000) {
        crate::log::printk(format_args!("rustux: nvme: bar {base:#x} not mmio"));
        return 0;
    }
    pci::command_or(bus, dev, f, 0x6); // IO | MEM | busmaster
    BAR.store(base, Ordering::Relaxed);
    // Disable, wait for the controller to go quiescent.
    w32(CC, 0);
    if !wait_rdy(0) {
        crate::log::printk(format_args!("rustux: nvme: !rdy(0) csts={:#x}", r32(CSTS)));
        return 0;
    }
    let cap = r64(CAP);
    // Doorbell stride is device-reported — bound it before trusting
    // it in address math (the field is 5 bits; 0..15 is the sane end).
    let dstrd = ((cap >> 32) & 0xf).min(15) as u32;
    DSTRD.store(dstrd, Ordering::Relaxed);
    // Admin pair, then program the controller and enable.
    // SAFETY: init runs once, before tasks exist.
    unsafe {
        *core::ptr::addr_of_mut!(ADMINQ) = q_alloc(AQSIZE);
        *core::ptr::addr_of_mut!(IOQ) = q_alloc(IQSIZE);
    }
    if admin().is_none() || ioq().is_none() {
        crate::log::printk(format_args!("rustux: nvme: queue alloc failed"));
        return 0;
    }
    let aq = admin().unwrap();
    w32(AQA, ((AQSIZE as u32 - 1) << 16) | (AQSIZE as u32 - 1));
    w64(ASQ, aq.sq);
    w64(ACQ, aq.cq);
    w32(CC, CC_EN | CC_IOSQES | CC_IOCQES);
    if !wait_rdy(1) {
        crate::log::printk(format_args!("rustux: nvme: !rdy(1) csts={:#x}", r32(CSTS)));
        return 0;
    }
    let (Some(scratch), Some(data)) =
        (kalloc::alloc_frames(0), kalloc::alloc_frames(0))
    else {
        return 0;
    };
    SCRATCH.store(scratch, Ordering::Relaxed);
    DATA.store(data, Ordering::Relaxed);
    // Identify Controller: NN at byte 516, then each active
    // namespace up to MAXNS — inactive ids identify as all-zero.
    if !identify(aq, 0, dstrd, 0, 1) {
        crate::log::printk(format_args!("rustux: nvme: identify ctrl failed"));
        return 0;
    }
    // SAFETY: scratch is our own page, filled by the device.
    let nn = unsafe { ((mm::pmap(scratch) + 516) as *const u32).read_volatile() }
        .min(MAXNS);
    if nn == 0 {
        crate::log::printk(format_args!("rustux: nvme: no namespaces"));
        return 0;
    }
    // Per-namespace bounds: NSZE at +0 (u64 sectors); LBAF index at
    // +26, LBAF table at +128 with the format size as 1<<ldsf.
    let mut bound = 0u32;
    for nsid in 1..=nn {
        if !identify(aq, 0, dstrd, nsid, 0) {
            crate::log::printk(format_args!(
                "rustux: nvme: identify ns{nsid} failed — skipped"
            ));
            continue;
        }
        let (nsze, lbads) = unsafe {
            let p = mm::pmap(scratch) as *const u8;
            let n = (p as *const u64).read_volatile();
            let flbas = *p.add(26) & 0xf;
            let ldsf = *p.add(128 + flbas as usize * 4 + 2);
            (n, 1u32 << ldsf.min(15))
        };
        if nsze == 0 || lbads != 512 {
            crate::log::printk(format_args!(
                "rustux: nvme: ns{nsid} {nsze} sectors lbads={lbads} — only 512B bound, skipped"
            ));
            continue;
        }
        NS_SECTORS[bound as usize].store(nsze, Ordering::Relaxed);
        NSID[bound as usize].store(nsid, Ordering::Relaxed);
        bound += 1;
        crate::log::printk(format_args!(
            "rustux: nvme: ns{nsid} {nsze} sectors ({} MiB) -> disk{}",
            nsze / 2048,
            bound - 1
        ));
    }
    if bound == 0 {
        return 0;
    }
    // MSI-X: the admin CQ is architecturally bound to vector 0 —
    // mask that entry and route the I/O CQ to entry 1 -> IRQ_NVME.
    // The CQ's interrupt vector is fixed at create time (cdw11), so
    // the table must be programmed BEFORE Create-IOCQ.
    let mut msix_io: Option<u32> = None;
    if let Some(cap) = pci::msix_cap(bus, dev, f) {
        let dest = crate::apic::lapic_id() as u8;
        // SAFETY: cap.table is the device's MSI-X BAR window.
        unsafe {
            for v in 0..cap.nvec {
                pci::msix_set(&cap, v, 0, 0, true);
            }
            pci::msix_set(
                &cap,
                1,
                crate::apic::IRQ_NVME as u8,
                dest,
                false,
            );
        }
        pci::msix_enable(bus, dev, f, &cap);
        msix_io = Some(1);
    }
    // I/O queue pair: CQ first (its id feeds the SQ's cdw11). The
    // queue's physical base travels in PRP1 — without it QEMU binds
    // the ring at phys 0 and the datapath silently dies.
    let iq_phys = ioq().unwrap();
    let mut e = [0u8; 64];
    e[0] = OP_CREATE_IO_CQ;
    e[24..32].copy_from_slice(&iq_phys.cq.to_le_bytes());
    e[40..44].copy_from_slice(&(((IQSIZE as u32 - 1) << 16) | 1).to_le_bytes());
    // cdw11 = iv<<16 | ien<<1 | pc — when MSI-X armed, bind the CQ
    // to table entry 1; without it, interrupts stay off entirely.
    let cq11 = match msix_io {
        Some(iv) => (iv << 16) | (1 << 1) | 1,
        None => 1,
    };
    e[44..48].copy_from_slice(&cq11.to_le_bytes());
    if !aq.submit(0, dstrd, &mut e) {
        crate::log::printk(format_args!("rustux: nvme: create iocq failed"));
        return 0;
    }
    let mut e = [0u8; 64];
    e[0] = OP_CREATE_IO_SQ;
    e[24..32].copy_from_slice(&iq_phys.sq.to_le_bytes());
    e[40..44].copy_from_slice(&(((IQSIZE as u32 - 1) << 16) | 1).to_le_bytes());
    // cdw11 = cqid<<16 | qprio — QEMU refuses qprio=0 (its prio
    // range is 1-based: 1=urgent .. 4=low).
    e[44..48].copy_from_slice(&((1u32 << 16) | 1).to_le_bytes());
    if !aq.submit(0, dstrd, &mut e) {
        crate::log::printk(format_args!(
            "rustux: nvme: create iosq failed sf={:#x}",
            LAST_SF.load(Ordering::Relaxed)
        ));
        return 0;
    }
    NDISKS.store(bound, Ordering::Release);
    crate::log::printk(format_args!(
        "rustux: nvme: {base:#x} {bound} namespace(s) dstrd={dstrd} msix={}",
        msix_io.is_some()
    ));
    // Datapath proofs at probe time, per bound namespace: sector 0
    // through the I/O queue — the same path the partition scan
    // drives — then a write-verify-restore in the MBR gap (lba 64
    // sits before the ext4 partition; -snapshot keeps the host
    // image clean).
    for d in 0..bound as usize {
        let mut b = [0u8; 512];
        let r = read_range(d, 0, 1, &mut b);
        crate::log::printk(format_args!(
            "rustux: nvme: disk{d} sector0 read {r} sig {:#x}{:#x} sf={:#x}",
            b[510], b[511],
            LAST_SF.load(Ordering::Relaxed)
        ));
        let mut orig = [0u8; 512];
        let mut back = [0u8; 512];
        let mut pat = [0u8; 512];
        pat[..7].copy_from_slice(b"rustux!");
        let ro = read_range(d, 64, 1, &mut orig);
        let w = ro && write_range(d, 64, 1, &pat);
        let v = w && read_range(d, 64, 1, &mut back) && back[..7] == pat[..7];
        let s = write_range(d, 64, 1, &orig);
        let s = s && read_range(d, 64, 1, &mut back) && back == orig;
        crate::log::printk(format_args!(
            "rustux: nvme: disk{d} write datapath {w} verify {v} restore {s}"
        ));
    }
    bound
}

/// Post-sti IRQ proof: one read through the I/O queue must drop at
/// least one MSI-X delivery on IRQ_NVME — the handler counts only,
/// so the phase-bit consume stays the single completion path.
/// Returns false when MSI-X wasn't armed or no IRQ arrived.
pub fn irq_selftest() -> bool {
    if NDISKS.load(Ordering::Relaxed) == 0 {
        return false;
    }
    let before = IO_IRQS.load(Ordering::Relaxed);
    let mut b = [0u8; 512];
    if !read_range(0, 0, 1, &mut b) {
        return false;
    }
    // A completion IRQ lands before or during the poll — the read
    // itself is the wait. Give the LAPIC a moment in case the MSI
    // posted after the phase-bit consumed the slot.
    let mut irqs = IO_IRQS.load(Ordering::Relaxed);
    for _ in 0..100_000 {
        if irqs > before {
            break;
        }
        irqs = IO_IRQS.load(Ordering::Relaxed);
        core::hint::spin_loop();
    }
    let got = irqs > before;
    crate::log::printk(format_args!(
        "rustux: nvme: {} I/O-CQ MSI IRQs on vec {:#x} (read-caused)",
        irqs,
        crate::apic::IRQ_NVME
    ));
    got
}

static DSTRD: AtomicU32 = AtomicU32::new(0);
static DATA: AtomicU64 = AtomicU64::new(0);
/// Last completion status field — diagnosis for a refused command.
static LAST_SF: AtomicU32 = AtomicU32::new(0);

fn admin() -> Option<&'static mut NvmeQ> {
    // SAFETY: written once at init; the kernel's driver call-sites
    // are single-threaded polling paths.
    unsafe { (*core::ptr::addr_of_mut!(ADMINQ)).as_mut() }
}

fn ioq() -> Option<&'static mut NvmeQ> {
    // SAFETY: as above.
    unsafe { (*core::ptr::addr_of_mut!(IOQ)).as_mut() }
}

/// Bound disk count.
pub fn disks() -> u32 {
    NDISKS.load(Ordering::Acquire)
}

/// Disk `i` capacity in bytes.
pub fn disk_capacity(i: usize) -> u64 {
    if i >= NDISKS.load(Ordering::Acquire) as usize {
        0
    } else {
        NS_SECTORS[i].load(Ordering::Relaxed) * 512
    }
}

/// Read `count` 512B sectors at `lba` into `buf` through the I/O
/// queue — chunked at BATCH so PRP1 alone covers the transfer.
pub fn read_range(i: usize, lba: u64, count: usize, buf: &mut [u8]) -> bool {
    if i >= NDISKS.load(Ordering::Acquire) as usize
        || count == 0
        || buf.len() < count * 512
    {
        return false;
    }
    let sectors = NS_SECTORS[i].load(Ordering::Relaxed);
    if lba + count as u64 > sectors {
        return false;
    }
    let Some(q) = ioq() else { return false };
    let dstrd = DSTRD.load(Ordering::Relaxed);
    let data = DATA.load(Ordering::Relaxed);
    let mut done = 0usize;
    while done < count {
        let n = (count - done).min(BATCH);
        let mut e = [0u8; 64];
        e[0] = OP_READ;
        e[4..8].copy_from_slice(&NSID[i].load(Ordering::Relaxed).to_le_bytes());
        e[24..32].copy_from_slice(&data.to_le_bytes());
        e[40..48].copy_from_slice(&(lba + done as u64).to_le_bytes());
        e[48..50].copy_from_slice(&(n as u16 - 1).to_le_bytes());
        if !q.submit(1, dstrd, &mut e) {
            return false;
        }
        // SAFETY: the device filled the staging half; copy n blocks.
        unsafe {
            core::ptr::copy_nonoverlapping(
                (mm::pmap(data)) as *const u8,
                buf.as_mut_ptr().add(done * 512),
                n * 512,
            );
        }
        done += n;
    }
    true
}

/// Write `count` 512B sectors at `lba` from `buf` — the read path's
/// mirror: staging page fills from the caller, PRP1 carries it.
pub fn write_range(i: usize, lba: u64, count: usize, buf: &[u8]) -> bool {
    if i >= NDISKS.load(Ordering::Acquire) as usize
        || count == 0
        || buf.len() < count * 512
    {
        return false;
    }
    let sectors = NS_SECTORS[i].load(Ordering::Relaxed);
    if lba + count as u64 > sectors {
        return false;
    }
    let Some(q) = ioq() else { return false };
    let dstrd = DSTRD.load(Ordering::Relaxed);
    let data = DATA.load(Ordering::Relaxed);
    let mut done = 0usize;
    while done < count {
        let n = (count - done).min(BATCH);
        // SAFETY: staging page is ours; fill n blocks for the device.
        unsafe {
            core::ptr::copy_nonoverlapping(
                buf.as_ptr().add(done * 512),
                mm::pmap(data) as *mut u8,
                n * 512,
            );
        }
        core::sync::atomic::fence(Ordering::SeqCst);
        let mut e = [0u8; 64];
        e[0] = OP_WRITE;
        e[4..8].copy_from_slice(&NSID[i].load(Ordering::Relaxed).to_le_bytes());
        e[24..32].copy_from_slice(&data.to_le_bytes());
        e[40..48].copy_from_slice(&(lba + done as u64).to_le_bytes());
        e[48..50].copy_from_slice(&(n as u16 - 1).to_le_bytes());
        if !q.submit(1, dstrd, &mut e) {
            return false;
        }
        done += n;
    }
    true
}
