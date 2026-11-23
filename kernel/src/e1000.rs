//! e1000 — Intel 82574L (PCIe GbE) driver skeleton.
//!
//! Two rungs: bind the function firmware discovered (enable memory
//! space + bus mastering, read the station MAC), then prove the DMA
//! datapath — reset, a legacy TX descriptor ring carved from one buddy
//! page, one broadcast frame, and the DD write-back bit the NIC sets
//! when it has DMA'd the buffer out of RAM. The kernel's identity map
//! makes virt == phys, which is exactly what the descriptor wants.

use crate::kalloc;
use crate::log::printk;
use crate::pci;
use core::sync::atomic::Ordering;

const VENDOR: u16 = 0x8086;
const DEVICE: u16 = 0x10d3; // 82574L, QEMU's e1000e model

// Register offsets within BAR0 (82574 spec).
const CTRL: usize = 0x0000;
const STATUS: usize = 0x0008;
const IMC: usize = 0x00d8; // write 1s mask all interrupt causes
const ICR: usize = 0x00c0; // read-to-clear cause register
const TCTL: usize = 0x0400;
const TIPG: usize = 0x0410;
const RAL0: usize = 0x5400;
const RAH0: usize = 0x5404;
const TDBAL: usize = 0x3800;
const TDBAH: usize = 0x3804;
const TDLEN: usize = 0x3808;
const TDH: usize = 0x3810;
const TDT: usize = 0x3818;
const IMS: usize = 0x00d0; // write 1s unmask causes
const IVAR: usize = 0x00e4; // cause -> MSI-X vector map
const RCTL: usize = 0x0100;
const RDBAL: usize = 0x2800;
const RDBAH: usize = 0x2804;
const RDLEN: usize = 0x2808;
const RDH: usize = 0x2810;
const RDT: usize = 0x2818;

const CTRL_SLU: u32 = 1 << 6; // set link up
const CTRL_RST: u32 = 1 << 26; // device reset (self-clearing)
const TCTL_EN: u32 = 1 << 1;
const TCTL_PSP: u32 = 1 << 3;
const TCTL_CT: u32 = 0x10 << 4; // collision threshold
const TCTL_COLD: u32 = 0x40 << 12; // full-duplex backoff distance
const TIPG_DEF: u32 = 10 | (8 << 10) | (6 << 20); // spec defaults

const N_TX: usize = 8; // descriptors in the ring (16 B each)
const TXD_EOP: u8 = 0x01;
const TXD_IFCS: u8 = 0x02;
const TXD_RS: u8 = 0x08;
const TXD_STA_DD: u8 = 0x01;

const N_RX: usize = 64; // deep enough to hold a full TCP window burst between tick drains
const RX_BUF: usize = 2048; // per-descriptor packet buffer
const RCTL_EN: u32 = 1 << 1;
const RCTL_UPE: u32 = 1 << 3; // unicast promiscuous
const RCTL_MPE: u32 = 1 << 4; // multicast promiscuous
const RCTL_BAM: u32 = 1 << 15; // broadcast accept
const RXD_STA_DD: u8 = 0x01;
const RXD_STA_EOP: u8 = 0x02;

// ICR/IMS interrupt-cause bits we use (82574).
const ICR_RXDMT0: u32 = 1 << 4; // rx desc minimum threshold hit
const ICR_RXT0: u32 = 1 << 7; // rx timer expired
const ICR_RXQ0: u32 = 1 << 20; // rx queue 0 (the MSI-X-era cause)
const ICR_OTHER: u32 = 1 << 24; // link/status group

/// Device coordinates, saved at probe so late init can program MSI.
static BDF: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(u32::MAX);
/// MSI interrupts delivered — read for the boot proof.
pub static IRQS: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);
static MMIO: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(0);
/// Gateway MAC captured from the ARP reply (packed big-endian in the
/// low 48 bits) — the first entry of our ARP cache.
static GW_MAC: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);
/// Gateway IPv4 captured with it (network byte order as u32).
static GW_IP: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(0);
/// Our DHCP-leased IPv4 and netmask (network order as u32) — written
/// when the ACK lands in dhcp_selftest, read by the socket layer.
static OUR_IP: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(0);
static OUR_MASK: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(0);
/// Our MAC (packed be48) plus the live RX ring — programmed by
/// net_live once the selftests are done; rx_drain consumes it.
static OUR_MAC: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);
static LIVE_BASE: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(0);
static LIVE_RING: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(0);
static LIVE_BUFS: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(0);

/// Legacy RX descriptor (16 bytes). The NIC writes len/sta back when a
/// frame lands in the buffer we posted.
#[repr(C)]
struct RxDesc {
    addr: u64,
    len: u16,
    cksum: u16,
    sta: u8,
    err: u8,
    special: u16,
}

/// Legacy TX descriptor (16 bytes), 8254x/82574 layout.
#[repr(C)]
struct TxDesc {
    addr: u64,
    len: u16,
    cso: u8,
    cmd: u8,
    sta: u8,
    _rsv: u8,
    special: u16,
}

#[inline]
unsafe fn rd(base: usize, off: usize) -> u32 {
    unsafe { ((base + off) as *const u32).read_volatile() }
}

#[inline]
unsafe fn wr(base: usize, off: usize, v: u32) {
    unsafe { ((base + off) as *mut u32).write_volatile(v) }
}

/// Probe for the NIC. `is_mmio` must confirm the claimed BAR does not
/// overlap RAM before we touch it. On success returns (MMIO base, MAC).
pub fn probe(is_mmio: impl Fn(u64, u64) -> bool) -> Option<(usize, [u8; 6])> {
    let (bus, dev, f) = pci::find(VENDOR, DEVICE)?;
    BDF.store((bus as u32) << 8 | (dev as u32) << 3 | f as u32, Ordering::Relaxed);
    printk(format_args!(
        "rustux: e1000: found {VENDOR:04x}:{DEVICE:04x} at {bus:02x}:{dev:02x}.{f}"
    ));

    // Decode BAR0: must be a memory BAR outside conventional RAM —
    // this driver is about to *write* through it.
    let bar = pci::bar_raw(bus, dev, f, 0);
    if bar == 0 || bar == u32::MAX || bar & 1 != 0 {
        printk(format_args!("rustux: e1000: BAR0 {bar:#x} not a usable MMIO BAR"));
        return None;
    }
    let base = (bar & !0xf) as usize;
    if !is_mmio(base as u64, 0x2_0000) {
        // 82574 BAR0 is 128 KiB.
        printk(format_args!(
            "rustux: e1000: BAR0 {base:#x} overlaps RAM -- refusing to bind"
        ));
        return None;
    }

    let cmd = pci::command_or(bus, dev, f, pci::CMD_MEM_SPACE | pci::CMD_BUS_MASTER);
    if cmd & pci::CMD_MEM_SPACE == 0 {
        printk(format_args!(
            "rustux: e1000: memory space did not enable (cmd {cmd:#x})"
        ));
        return None;
    }

    // SAFETY: `base` is the firmware-assigned BAR, validated non-RAM
    // above and inside our identity map; reads are device registers.
    let (status, mac) = unsafe {
        let ral = rd(base, RAL0);
        let rah = rd(base, RAH0);
        let m = [
            ral as u8,
            (ral >> 8) as u8,
            (ral >> 16) as u8,
            (ral >> 24) as u8,
            rah as u8,
            (rah >> 8) as u8,
        ];
        (rd(base, STATUS), m)
    };
    printk(format_args!(
        "rustux: e1000: MMIO @{base:#x} status={status:#x} \
         mac {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    ));
    if status & (1 << 1) != 0 {
        printk(format_args!("rustux: e1000: link UP"));
    }
    MMIO.store(base, Ordering::Relaxed);
    Some((base, mac))
}

/// Reset the NIC: CTRL.RST self-clears when the core comes back.
fn reset(base: usize) -> bool {
    // SAFETY: base is our bound MMIO window.
    unsafe {
        wr(base, CTRL, rd(base, CTRL) | CTRL_RST);
    }
    let mut i = 0u32;
    // SAFETY: bounded poll on the same window.
    while unsafe { rd(base, CTRL) } & CTRL_RST != 0 && i < 1_000_000 {
        i += 1;
    }
    i < 1_000_000
}

/// The TX ring's page — allocated once, reused every transmit.
/// tx_once reprograms the entire ring on each call, so a persistent
/// page is correct and closes the per-frame kmalloc leak.
static TX_PAGE: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(0);

/// Transmit one frame through the legacy TX ring. `frame` is the raw
/// Ethernet frame. Returns true when the NIC reports DD (done).
pub fn tx_once(base: usize, frame: &[u8]) -> bool {
    // One page: [TxDesc x N_TX][packet buffer]. Buddy pages are
    // physically contiguous and identity-mapped, so addr == phys.
    // Single-CPU: the load-then-store race can't run concurrently.
    let mut page = TX_PAGE.load(Ordering::Relaxed) as *mut u8;
    if page.is_null() {
        page = kalloc::kmalloc(4096);
        if page.is_null() {
            printk(format_args!("rustux: e1000: tx page alloc failed"));
            return false;
        }
        TX_PAGE.store(page as usize, Ordering::Relaxed);
    }
    let ring = page as *mut TxDesc;
    // SAFETY: page names 4096 owned bytes; N_TX*16 fits the front half,
    // the packet lands at +2048 with headroom to 1518+ bytes.
    unsafe {
        core::ptr::write_bytes(ring, 0, N_TX);
    }
    let buf = unsafe { page.add(2048) };
    if frame.len() > 2048 {
        return false;
    }
    // SAFETY: buf names 2048 owned bytes in the same page.
    unsafe {
        core::ptr::copy_nonoverlapping(frame.as_ptr(), buf, frame.len());
    }

    // SAFETY: `base` is the bound MMIO window; offsets are the 82574
    // TX-block registers. Identity map => &*ring is also the DMA addr.
    // Interrupt masking is the CALLER's choice — masking here would
    // clobber an IMS unmask done before the transmit (MSI-X path).
    unsafe {
        let _ = rd(base, ICR); // drain pending causes
        wr(base, TDBAL, ring as u32);
        wr(base, TDBAH, ((ring as usize) >> 32) as u32);
        wr(base, TDLEN, (N_TX * 16) as u32);
        wr(base, TDH, 0);
        wr(base, TDT, 0);
        wr(base, TIPG, TIPG_DEF);
        wr(base, TCTL, TCTL_EN | TCTL_PSP | TCTL_CT | TCTL_COLD);
    }

    // Program descriptor 0; TDT = 1 rings the doorbell.
    // SAFETY: ring names N_TX owned descriptors in the page.
    unsafe {
        let d = &mut *ring;
        d.addr = buf as u64;
        d.len = frame.len() as u16;
        d.cso = 0;
        d.cmd = TXD_EOP | TXD_IFCS | TXD_RS;
        d.sta = 0;
        d.special = 0;
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        wr(base, TDT, 1);
    }

    // Poll DD: the NIC DMAs the frame, transmits it, writes sta back.
    let mut i = 0u32;
    // SAFETY: bounded volatile read of our own descriptor.
    let done = loop {
        if unsafe { (*ring).sta } & TXD_STA_DD != 0 {
            break true;
        }
        i += 1;
        if i == 10_000_000 {
            break false;
        }
    };
    // Per-frame success logging is deliberately absent: a serial+fbcon
    // line per TX costs ~100ms of console scroll and would throttle
    // the whole stack to ~15kB/s. Failures are rare enough to log.
    if !done {
        // SAFETY: reads on our ring + registers.
        let (tdh, tdt) = unsafe { (rd(base, TDH), rd(base, TDT)) };
        printk(format_args!(
            "rustux: e1000: tx {}-byte frame TIMEOUT (TDH {tdh}/TDT {tdt})",
            frame.len()
        ));
    }
    done
}

/// Full datapath self-test: reset, ring bring-up, one broadcast frame.
pub fn tx_selftest(base: usize, mac: [u8; 6]) -> bool {
    if !reset(base) {
        printk(format_args!("rustux: e1000: reset timed out"));
        return false;
    }
    // SAFETY: post-reset register write on the bound window — keep the
    // link forced up and mask interrupts for the polling proof.
    unsafe {
        wr(base, CTRL, rd(base, CTRL) | CTRL_SLU);
        wr(base, IMC, u32::MAX);
    }
    printk(format_args!("rustux: e1000: reset ok, IRQs masked (polling TX)"));

    // Broadcast frame, experimental ethertype 0x88b5, "rustux" payload.
    let mut frame = [0u8; 64];
    frame[..6].copy_from_slice(&[0xff; 6]);
    frame[6..12].copy_from_slice(&mac);
    frame[12] = 0x88;
    frame[13] = 0xb5;
    frame[14..20].copy_from_slice(b"rustux");
    tx_once(base, &frame[..60])
}

/// MSI interrupt handler — the device wrote to the LAPIC's message
/// window; reading ICR acknowledges the causes device-side.
pub fn on_irq() {
    let base = MMIO.load(Ordering::Relaxed);
    if base == 0 {
        return;
    }
    // SAFETY: base is the bound MMIO window; ICR is read-to-clear.
    let icr = unsafe { rd(base, ICR) };
    IRQS.fetch_add(1, Ordering::Relaxed);
    if icr & (ICR_RXDMT0 | ICR_RXT0 | ICR_RXQ0) != 0 {
        RX_IRQS.fetch_add(1, Ordering::Relaxed);
    }
}

/// RX-caused MSI count — the IRQ-side proof a packet triggered it.
pub static RX_IRQS: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);

/// Interrupt-driven receive: enable MSI-X (per-vector message writes
/// to the LAPIC instead of an IOAPIC line), IVAR-map the RXQ0 cause to
/// table vector 0, unmask it in IMS, transmit the ARP request, then
/// wait for vector IRQ_NET to fire.
/// Requires interrupts already enabled (`sti`).
pub fn irq_selftest(base: usize, mac: [u8; 6]) -> bool {
    let bdf = BDF.load(Ordering::Relaxed);
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
        printk(format_args!("rustux: e1000: no MSI-X capability"));
        return false;
    };
    // Vector 0 carries the RX interrupt; the other four stay masked.
    // SAFETY: `cap.table` is the device MSI-X BAR window the
    // capability decoded — inside our identity map.
    unsafe {
        pci::msix_set(&cap, 0, crate::apic::IRQ_NET as u8, dest, false);
        for v in 1..cap.nvec {
            pci::msix_set(&cap, v, 0, 0, true);
        }
    }
    pci::msix_enable(bus, dev, f, &cap);
    printk(format_args!(
        "rustux: e1000: MSI-X on ({} vectors, table @{:#x}) -> vec {:#x} dest-lapic {dest}",
        cap.nvec,
        cap.table,
        crate::apic::IRQ_NET
    ));

    let Some((ring, bufs)) = rx_init(base) else {
        return false;
    };
    // IVAR maps causes to vectors: RXQ0 -> entry 0 = MSI-X vector 0
    // (valid bit set). Then unmask RXQ0 + OTHER in IMS.
    // SAFETY: bound window, architected registers.
    unsafe {
        wr(base, IVAR, 0x8);
        wr(base, IMS, ICR_RXQ0 | ICR_OTHER);
        let _ = rd(base, ICR); // clear stale causes
    }

    // Same ARP probe as the polling test — this time the reply raises
    // vector 0xf3 instead of being discovered by a DD poll.
    let mut fr = [0u8; 60];
    fr[..6].copy_from_slice(&[0xff; 6]);
    fr[6..12].copy_from_slice(&mac);
    fr[12] = 0x08;
    fr[13] = 0x06;
    fr[14..22].copy_from_slice(&[0, 1, 8, 0, 6, 4, 0, 1]);
    fr[22..28].copy_from_slice(&mac);
    fr[28..32].copy_from_slice(&[10, 0, 2, 15]);
    fr[38..42].copy_from_slice(&[10, 0, 2, 2]);
    let before = IRQS.load(Ordering::Relaxed);
    if !tx_once(base, &fr) {
        return false;
    }

    // Up to ~1.5s: hlt until the MSI (or any IRQ) wakes us.
    let t0 = crate::apic::TICKS.load(Ordering::Relaxed);
    let mut got_reply = false;
    while IRQS.load(Ordering::Relaxed) == before
        && crate::apic::TICKS.load(Ordering::Relaxed) - t0 < 150
    {
        // SAFETY: hlt wakes on any delivered IRQ; IF is set.
        unsafe { core::arch::asm!("hlt", options(nomem, nostack)) };
    }
    let delivered = IRQS.load(Ordering::Relaxed) - before;
    // The IRQ already fired — now just harvest the reply descriptor.
    for d in 0..N_RX {
        // SAFETY: NIC wrote sta/len; buffer is ours.
        let (sta, len) = unsafe { ((*ring.add(d)).sta, (*ring.add(d)).len) };
        if sta & RXD_STA_DD != 0 && len >= 42 {
            let p = unsafe { bufs.add(d * RX_BUF) };
            if unsafe { *p.add(12) } == 0x08 && unsafe { *p.add(13) } == 0x06 {
                got_reply = true;
            }
        }
    }
    printk(format_args!(
        "rustux: e1000: {} MSI IRQs on vec {:#x} ({} rx-caused), reply {}",
        delivered,
        crate::apic::IRQ_NET,
        RX_IRQS.load(Ordering::Relaxed),
        if got_reply { "received" } else { "missing" }
    ));
    delivered > 0 && got_reply
}

/// Bring up the RX ring: 8 descriptors, each pointing at its own 2 KiB
/// buffer. Returns (ring, buffers) — both buddy pages, kept for the
/// device lifetime. Hardware receives into [RDH, RDT); reposting a
/// consumed descriptor d writes RDT=d so the just-freed slot becomes
/// past the last usable, the full/empty ambiguity keeps one free).
fn rx_init(base: usize) -> Option<(*mut RxDesc, *mut u8)> {
    let ring = kalloc::kmalloc(4096) as *mut RxDesc;
    let bufs = kalloc::kmalloc(N_RX * RX_BUF);
    if ring.is_null() || bufs.is_null() {
        printk(format_args!("rustux: e1000: rx ring/buf alloc failed"));
        return None;
    }
    // SAFETY: ring names a page (8*16 desc bytes fit); bufs names
    // N_RX*RX_BUF contiguous bytes — each descriptor gets its slice.
    unsafe {
        core::ptr::write_bytes(ring, 0, N_RX);
        for i in 0..N_RX {
            (*ring.add(i)).addr = bufs.add(i * RX_BUF) as u64;
        }
        wr(base, RDBAL, ring as u32);
        wr(base, RDBAH, ((ring as usize) >> 32) as u32);
        wr(base, RDLEN, (N_RX * 16) as u32);
        wr(base, RDH, 0);
        wr(base, RDT, 0);
        // Accept everything for the proof: promiscuous + broadcast.
        wr(base, RCTL, RCTL_EN | RCTL_UPE | RCTL_MPE | RCTL_BAM);
        wr(base, RDT, (N_RX - 1) as u32);
    }
    Some((ring, bufs))
}

/// Round-trip proof: broadcast an ARP who-has for QEMU's slirp gateway
/// (10.0.2.2), then poll the RX ring for the unicast reply. This is a
/// real frame leaving and a real frame arriving through our own rings.
pub fn arp_selftest(base: usize, mac: [u8; 6]) -> bool {
    let Some((ring, bufs)) = rx_init(base) else {
        return false;
    };
    printk(format_args!("rustux: e1000: rx ring up ({N_RX} descs x {RX_BUF}B)"));

    // Ethernet + ARP request, padded to the 60-byte TX minimum.
    let mut f = [0u8; 60];
    f[..6].copy_from_slice(&[0xff; 6]); // dst: broadcast
    f[6..12].copy_from_slice(&mac); // src: us
    f[12] = 0x08;
    f[13] = 0x06; // ethertype ARP
    f[14..22].copy_from_slice(&[0, 1, 8, 0, 6, 4, 0, 1]); // ht/pt/hl/pl/req
    f[22..28].copy_from_slice(&mac); // sender hw
    f[28..32].copy_from_slice(&[10, 0, 2, 15]); // sender proto (slirp guest)
    // target hw = zeros (that's the question), target proto:
    f[38..42].copy_from_slice(&[10, 0, 2, 2]); // slirp gateway
    if !tx_once(base, &f) {
        return false;
    }

    // Poll every posted descriptor for DD; report whatever arrives.
    let mut i = 0u32;
    loop {
        for d in 0..N_RX {
            // SAFETY: the NIC writes sta/len into our ring; the packet
            // lands in the buffer we posted for this descriptor.
            let (sta, len) = unsafe { ((*ring.add(d)).sta, (*ring.add(d)).len) };
            if sta & RXD_STA_DD == 0 {
                continue;
            }
            // Validate the device-written fields before touching the
            // buffer (CVE-2009-1385 class): len is untrusted — it must
            // describe a complete (EOP), minimally-sized frame that fits
            // the posted buffer. Anything else is reposted, not parsed.
            if sta & RXD_STA_EOP == 0
                || len < 14
                || len as usize > RX_BUF
            {
                printk(format_args!(
                    "rustux: e1000: rx {len}B sta{sta:#04x} invalid, dropping"
                ));
                unsafe {
                    (*ring.add(d)).sta = 0;
                    wr(base, RDT, d as u32);
                }
                continue;
            }
            let p = unsafe { bufs.add(d * RX_BUF) };
            let et = unsafe { u16::from_be_bytes([*p.add(12), *p.add(13)]) };
            if et == 0x0806 && len >= 42 {
                // ARP reply: oper at eth+20, sender hw/proto at +22/+28.
                let (op, sha, spa) = unsafe {
                    (
                        u16::from_be_bytes([*p.add(20), *p.add(21)]),
                        core::slice::from_raw_parts(p.add(22), 6),
                        core::slice::from_raw_parts(p.add(28), 4),
                    )
                };
                // Cache the responder — ARP cache entry #1.
                GW_MAC.store(
                    u64::from_be_bytes([
                        0, 0, sha[0], sha[1], sha[2], sha[3], sha[4], sha[5],
                    ]),
                    Ordering::Relaxed,
                );
                GW_IP.store(
                    u32::from_be_bytes([spa[0], spa[1], spa[2], spa[3]]),
                    Ordering::Relaxed,
                );
                printk(format_args!(
                    "rustux: e1000: rx ARP op{op} from {}.{}.{}.{} \
                     mac {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} ({len}B desc{d})",
                    spa[0], spa[1], spa[2], spa[3],
                    sha[0], sha[1], sha[2], sha[3], sha[4], sha[5]
                ));
                return op == 2;
            }
            printk(format_args!(
                "rustux: e1000: rx {len}B frame et{et:#06x} desc{d} \
                 sta{sta:#04x}{}",
                if sta & RXD_STA_EOP != 0 { " eop" } else { "" }
            ));
            // Not our ARP — recycle the descriptor so more can arrive.
            // RDT=d: the consumed slot becomes the new one-descriptor
            // gap; all other posted buffers stay inside [RDH, RDT).
            // SAFETY: reposting a consumed descriptor.
            unsafe {
                (*ring.add(d)).sta = 0;
                wr(base, RDT, d as u32);
            }
        }
        i += 1;
        if i == 20_000_000 {
            printk(format_args!("rustux: e1000: rx poll timed out"));
            return false;
        }
    }
}

/// IPv4/ICMP round-trip: ping the slirp gateway we learned via ARP.
/// First real protocol proof — the request is checksummed by us, and
/// every field of the reply is validated by net:: (length, version,
/// checksum, non-fragment, echo-reply type, id/seq match, source IP).
pub fn ping_selftest(base: usize, mac: [u8; 6]) -> bool {
    let gw = GW_MAC.load(Ordering::Relaxed);
    let gw_ip_raw = GW_IP.load(Ordering::Relaxed);
    if gw == 0 || gw_ip_raw == 0 {
        printk(format_args!("rustux: e1000: ping: no ARP cache entry"));
        return false;
    }
    let gw_mac: [u8; 6] = gw.to_be_bytes()[2..8].try_into().unwrap();
    let gw_ip: [u8; 4] = gw_ip_raw.to_be_bytes();
    let our_ip = [10, 0, 2, 15u8];
    let peer = crate::net::NetAddr { mac: gw_mac, ip: gw_ip };
    let us = crate::net::NetAddr { mac, ip: our_ip };

    let Some((ring, bufs)) = rx_init(base) else {
        return false;
    };

    const ID: u16 = 0x7278; // "rx"
    const SEQ: u16 = 1;
    let mut f = [0u8; 128];
    let flen = crate::net::build_echo_request(
        &mut f, &peer, &us, ID, SEQ, b"rustux ping",
    );
    if flen == 0 {
        return false;
    }
    // Pad to the 60-byte TX minimum; the pad isn't in IP total_len.
    if !tx_once(base, &f[..flen.max(60)]) {
        return false;
    }

    let mut i = 0u32;
    loop {
        for d in 0..N_RX {
            // SAFETY: as in arp_selftest — NIC writes sta/len, buffer
            // is ours.
            let (sta, len) = unsafe { ((*ring.add(d)).sta, (*ring.add(d)).len) };
            if sta & RXD_STA_DD == 0 {
                continue;
            }
            if sta & RXD_STA_EOP == 0 || len < 14 || len as usize > RX_BUF {
                unsafe {
                    (*ring.add(d)).sta = 0;
                    wr(base, RDT, d as u32);
                }
                continue;
            }
            let buf = unsafe {
                core::slice::from_raw_parts(bufs.add(d * RX_BUF), len as usize)
            };
            let et = u16::from_be_bytes([buf[12], buf[13]]);
            let mut done = false;
            if et == 0x0800 {
                if let Some(ip) = crate::net::parse_ipv4(&buf[14..]) {
                    if ip.proto == 1 && ip.src == gw_ip && ip.dst == our_ip {
                        if let Some(m) = crate::net::parse_icmp(ip.payload) {
                            if m.ty == 0 && m.code == 0
                                && m.id == ID && m.seq == SEQ
                            {
                                printk(format_args!(
                                    "rustux: e1000: ping reply \
                                     {}.{}.{}.{} seq={} id={:#06x} \
                                     {}B icmp_rest={}B",
                                    ip.src[0], ip.src[1], ip.src[2],
                                    ip.src[3], m.seq, m.id, len,
                                    m.rest.len()
                                ));
                                return true;
                            }
                            printk(format_args!(
                                "rustux: e1000: rx icmp ty{} id{:#06x} \
                                 seq{} (not ours)",
                                m.ty, m.id, m.seq
                            ));
                        }
                    }
                }
                done = true;
            }
            if done || et != 0x0806 {
                printk(format_args!(
                    "rustux: e1000: rx {len}B frame et{et:#06x} desc{d} \
                     (ping wait)"
                ));
            }
            // Not our reply — repost and keep waiting.
            // SAFETY: reposting a consumed descriptor.
            unsafe {
                (*ring.add(d)).sta = 0;
                wr(base, RDT, d as u32);
            }
        }
        i += 1;
        if i == 20_000_000 {
            printk(format_args!("rustux: e1000: ping timed out"));
            return false;
        }
    }
}

/// IPv8 two-node demo (draft-thain-ipv8, experimental).
/// Role is selected by our MAC's last byte: 0x01 = initiator,
/// 0x02 = responder; anything else skips (normal slirp boots).
/// The initiator broadcasts an IPv8 echo request (ARP8 does not
/// exist — its spec was never submitted); the responder learns the
/// sender's MAC from the received frame and unicasts the reply.
/// Addresses: A = RN 0.0.0.1 / 10.0.0.1, B = RN 0.0.0.2 / 10.0.0.2.
#[cfg(demo_net)]
pub fn ipv8_demo(base: usize, mac: [u8; 6], con: &mut crate::Console) {
    let role = mac[5];
    if role != 0x01 && role != 0x02 {
        return; // single-node boot: no peer configured
    }
    let us8 = crate::net::Addr8 {
        rn: u32::from_be_bytes([0, 0, 0, role]),
        local: [10, 0, 0, role],
    };
    let Some((ring, bufs)) = rx_init(base) else {
        return;
    };
    const ID: u16 = 0x8088;
    const SEQ: u16 = 1;

    if role == 0x01 {
        printk(format_args!("rustux: ipv8: initiator up, broadcast echo req"));
        let peer8 = crate::net::Addr8 {
            rn: 0x00000002,
            local: [10, 0, 0, 2],
        };
        let mut f = [0u8; 128];
        let flen = crate::net::build_ipv8_echo(
            &mut f, 8, [0xff; 6], mac, &peer8, &us8, ID, SEQ, b"rustux ipv8",
        );
        if flen == 0 {
            return;
        }
        let mut sent = false;
        let mut rounds = 0u32;
        let mut seen = 0u32;
        loop {
            for d in 0..N_RX {
                // SAFETY: same contract as arp_selftest.
                let (sta, len) =
                    unsafe { ((*ring.add(d)).sta, (*ring.add(d)).len) };
                if sta & RXD_STA_DD == 0 {
                    continue;
                }
                if sta & RXD_STA_EOP == 0 || len < 14 || len as usize > RX_BUF {
                    unsafe {
                        (*ring.add(d)).sta = 0;
                        wr(base, RDT, d as u32);
                    }
                    continue;
                }
                let buf = unsafe {
                    core::slice::from_raw_parts(
                        bufs.add(d * RX_BUF),
                        len as usize,
                    )
                };
                seen += 1;
                let et = u16::from_be_bytes([buf[12], buf[13]]);
                if et == crate::net::ET_IPV8 {
                    if let Some(ip) = crate::net::parse_ipv8(&buf[14..]) {
                        if ip.proto == 1
                            && ip.src_rn == peer8.rn
                            && ip.src == peer8.local
                            && ip.dst == us8.local
                            && ip.dst_rn == us8.rn
                        {
                            if let Some(m) =
                                crate::net::parse_icmp(ip.payload)
                            {
                                if m.ty == 0 && m.code == 0
                                    && m.id == ID && m.seq == SEQ
                                {
                                    printk(format_args!(
                                        "rustux: ipv8: echo reply \
                                         rn{:#x} {}.{}.{}.{} seq={} \
                                         ({len}B native 0x8080)",
                                        ip.src_rn, ip.src[0], ip.src[1],
                                        ip.src[2], ip.src[3], m.seq
                                    ));
                                    return;
                                }
                            }
                        }
                    }
                }
                // SAFETY: reposting a consumed descriptor.
                unsafe {
                    (*ring.add(d)).sta = 0;
                    wr(base, RDT, d as u32);
                }
            }
            rounds += 1;
            if rounds.is_multiple_of(64_000_000) {
                crate::log::printk(format_args!(
                    "rustux: ipv8: ini hb r={rounds} seen={seen}"
                ));
                crate::log::drain(con);
            }
            if rounds == u32::MAX {
                printk(format_args!("rustux: ipv8: no reply (peer down?)"));
                return;
            }
            if !sent || rounds.is_multiple_of(4_000_000) {
                let _ = tx_once(base, &f[..flen.max(60)]);
                sent = true;
            }
        }
    }

    // Responder: bounded listen for an IPv8 echo request, then reply.
    printk(format_args!("rustux: ipv8: responder listening (indef)"));
    let mut i = 0u32;
    let mut seen = 0u32;
    loop {
        for d in 0..N_RX {
            // SAFETY: same contract as arp_selftest.
            let (sta, len) =
                unsafe { ((*ring.add(d)).sta, (*ring.add(d)).len) };
            if sta & RXD_STA_DD == 0 {
                continue;
            }
            if sta & RXD_STA_EOP == 0 || len < 14 || len as usize > RX_BUF {
                unsafe {
                    (*ring.add(d)).sta = 0;
                    wr(base, RDT, d as u32);
                }
                continue;
            }
            let buf = unsafe {
                core::slice::from_raw_parts(bufs.add(d * RX_BUF), len as usize)
            };
            seen += 1;
            let et = u16::from_be_bytes([buf[12], buf[13]]);
            if et == crate::net::ET_IPV8 && buf.len() >= 14 + 28 {
                let dst_mac: [u8; 6] =
                    buf[6..12].try_into().unwrap(); // learned sender MAC
                if let Some(ip) = crate::net::parse_ipv8(&buf[14..]) {
                    if ip.proto == 1
                        && ip.dst == us8.local
                        && ip.dst_rn == us8.rn
                    {
                        if let Some(m) = crate::net::parse_icmp(ip.payload)
                        {
                            if m.ty == 8 {
                                let them = crate::net::Addr8 {
                                    rn: ip.src_rn,
                                    local: ip.src,
                                };
                                let mut r = [0u8; 128];
                                let rlen = crate::net::build_ipv8_echo(
                                    &mut r, 0, dst_mac, mac, &them, &us8,
                                    m.id, m.seq, b"rustux ipv8 reply",
                                );
                                if rlen != 0
                                    && tx_once(base, &r[..rlen.max(60)])
                                {
                                    printk(format_args!(
                                        "rustux: ipv8: echo req from \
                                         rn{:#x} {}.{}.{}.{} seq={} -> \
                                         replied",
                                        ip.src_rn, ip.src[0], ip.src[1],
                                        ip.src[2], ip.src[3], m.seq
                                    ));
                                    return;
                                }
                            }
                        }
                    }
                }
            }
            // SAFETY: reposting a consumed descriptor.
            unsafe {
                (*ring.add(d)).sta = 0;
                wr(base, RDT, d as u32);
            }
        }
        i += 1;
        if i.is_multiple_of(64_000_000) {
            crate::log::printk(format_args!(
                "rustux: ipv8: resp hb iters={i} frames={seen}"
            ));
            crate::log::drain(con);
        }
        if i == u32::MAX {
            i = 0; // dedicated demo peer: listen indefinitely
        }
    }
}

/// IPv6 two-node demo: real NDP (NS -> NA -> SLLA/TLLA) then
/// ICMPv6 echo request/reply over link-local addresses.
/// Same MAC-last-byte role gate as ipv8_demo (:01 initiator,
/// :02 responder). Runs after ipv8_demo on the socket pair.
#[cfg(demo_net)]
pub fn ipv6_selftest(base: usize, mac: [u8; 6], con: &mut crate::Console) {
    let role = mac[5];
    if role != 0x01 && role != 0x02 {
        return;
    }
    let us = crate::net::ll_addr(mac);
    let mut peer_mac = mac;
    peer_mac[5] = if role == 0x01 { 0x02 } else { 0x01 };
    let peer = crate::net::ll_addr(peer_mac);
    let Some((ring, bufs)) = rx_init(base) else {
        return;
    };
    const ID: u16 = 0x8606;
    const SEQ: u16 = 7;

    let mut f = [0u8; 128];
    // Initiator state: phase 0 = NS pending, phase 1 = echo pending.
    let mut phase = 0u8;
    let mut learned_mac = [0u8; 6];
    let mut sent = false;
    let mut rounds = 0u32;
    let mut seen = 0u32;
    let mut dbg6 = 0u32;

    if role == 0x01 {
        printk(format_args!("rustux: ipv6: initiator up, resolving peer ll"));
    } else {
        printk(format_args!("rustux: ipv6: responder listening (indef)"));
    }
    let mut i = 0u32;
    loop {
        for d in 0..N_RX {
            // SAFETY: same contract as arp_selftest.
            let (sta, len) = unsafe { ((*ring.add(d)).sta, (*ring.add(d)).len) };
            if sta & RXD_STA_DD == 0 {
                continue;
            }
            if sta & RXD_STA_EOP == 0 || len < 14 || len as usize > RX_BUF {
                unsafe {
                    (*ring.add(d)).sta = 0;
                    wr(base, RDT, d as u32);
                }
                continue;
            }
            let buf = unsafe {
                core::slice::from_raw_parts(bufs.add(d * RX_BUF), len as usize)
            };
            seen += 1;
            let et = u16::from_be_bytes([buf[12], buf[13]]);
            if et == crate::net::ET_IPV6 && buf.len() >= 54 {
                let src_mac: [u8; 6] = buf[6..12].try_into().unwrap();
                if dbg6 < 4 {
                    if let Some(ip) = crate::net::parse_ipv6(&buf[14..]) {
                        let c = crate::net::csum6(&ip.src, &ip.dst,
                            ip.payload.len() as u32, ip.next, ip.payload);
                        let fld = if ip.payload.len() >= 4 {
                            u16::from_be_bytes(
                                [ip.payload[2], ip.payload[3]])
                        } else { 0 };
                        let tw = if ip.payload.len() >= 22 {
                            u16::from_be_bytes(
                                [ip.payload[22], ip.payload[23]])
                        } else { 0 };
                        crate::log::printk(format_args!(
                            "rustux: ipv6: dbg nx={} hop={} pl={} ck={c:#x}                              fld={fld:#x} tgtlw={tw:#x} ty={} len={len}",
                            ip.next, ip.hop, ip.payload.len(),
                            if !ip.payload.is_empty() { ip.payload[0] } else { 0 }));
                        crate::log::drain(con);
                    } else {
                        crate::log::printk(format_args!(
                            "rustux: ipv6: dbg parse-fail len={len}"));
                        crate::log::drain(con);
                    }
                    dbg6 += 1;
                }
                if let Some(ip) = crate::net::parse_ipv6(&buf[14..]) {
                    if ip.next == crate::net::NH_ICMPV6
                        && crate::net::csum6_ok(crate::net::csum6(
                            &ip.src, &ip.dst,
                            ip.payload.len() as u32, ip.next, ip.payload,
                        ))
                    {
                        if let Some(m) = crate::net::parse_icmp6(ip.payload)
                        {
                            if role == 0x02 {
                                if m.ty == 135 && ip.hop == 255
                                    && m.rest.len() >= 20
                                    && m.rest[4..20] == us
                                    && ip.src != [0u8; 16]
                                {
                                    let them: [u8; 16] = ip.src;
                                    let n = crate::net::build_na(
                                        &mut f, src_mac, mac, &us, &them,
                                    );
                                    if n != 0 && tx_once(base, &f[..n.max(60)])
                                    {
                                        printk(format_args!(
                                            "rustux: ipv6: NS for us -> \
                                             sent NA (peer resolved us)"
                                        ));
                                    }
                                } else if m.ty == 128 && m.code == 0 && ip.dst == us {
                                    let id = u16::from_be_bytes(
                                        [m.rest[0], m.rest[1]]);
                                    let seq = u16::from_be_bytes(
                                        [m.rest[2], m.rest[3]]);
                                    let n = crate::net::build_echo6(
                                        &mut f, 129, src_mac, mac, &us,
                                        &ip.src, id, seq,
                                        b"rustux6 reply",
                                    );
                                    if n != 0 && tx_once(base, &f[..n.max(60)])
                                    {
                                        printk(format_args!(
                                            "rustux: ipv6: echo req \
                                             seq={seq} -> replied"
                                        ));
                                        return;
                                    }
                                }
                            } else if m.ty == 136 && ip.hop == 255
                                && phase == 0
                                && ip.src == peer
                                && ip.dst == us
                                && m.rest.len() >= 20
                                && m.rest[4..20] == peer
                            {
                                learned_mac = src_mac;
                                phase = 1;
                                sent = false;
                                printk(format_args!(
                                    "rustux: ipv6: NA received, \
                                     peer resolved"
                                ));
                            } else if m.ty == 129 && m.code == 0 && phase == 1
                                && ip.src == peer
                                && ip.dst == us
                                && m.rest.len() >= 4
                                && u16::from_be_bytes(
                                    [m.rest[0], m.rest[1]]) == ID
                                && u16::from_be_bytes(
                                    [m.rest[2], m.rest[3]]) == SEQ
                            {
                                printk(format_args!(
                                    "rustux: ipv6: echo reply seq={SEQ} \
                                     ({len}B native 0x86dd)"
                                ));
                                return;
                            }
                        }
                    }
                }
            }
            // SAFETY: reposting a consumed descriptor.
            unsafe {
                (*ring.add(d)).sta = 0;
                wr(base, RDT, d as u32);
            }
        }
        i += 1;
        if role == 0x01 {
            rounds += 1;
            if rounds.is_multiple_of(64_000_000) {
                crate::log::printk(format_args!(
                    "rustux: ipv6: ini hb r={rounds} ph={phase} seen={seen}"
                ));
                crate::log::drain(con);
            }
            if rounds == u32::MAX {
                printk(format_args!("rustux: ipv6: no reply (peer down?)"));
                return;
            }
            if !sent || rounds.is_multiple_of(4_000_000) {
                let n = if phase == 0 {
                    crate::net::build_ns(&mut f, mac, &us, &peer)
                } else {
                    crate::net::build_echo6(
                        &mut f, 128, learned_mac, mac, &us, &peer,
                        ID, SEQ, b"rustux6",
                    )
                };
                if n != 0 {
                    let _ = tx_once(base, &f[..n.max(60)]);
                }
                sent = true;
            }
        } else {
            if i.is_multiple_of(64_000_000) {
                crate::log::printk(format_args!(
                    "rustux: ipv6: resp hb iters={i} frames={seen}"
                ));
                crate::log::drain(con);
            }
            if i == u32::MAX {
                i = 0;
            }
        }
    }
}

/// DHCP client proof (slirp only — skipped on the socket-demo MACs).
/// Broadcast DISCOVER -> OFFER -> REQUEST -> ACK; a real lease.
/// BOOTP fixed part is 236B + 4B magic cookie + TLV options.
/// The XID is drawn from the CSPRNG per run — a constant XID makes
/// reply-forging trivial on a hostile LAN.
const DHCP_COOKIE: [u8; 4] = [99, 130, 83, 99];

/// Build a DHCP DISCOVER (ty=1) or REQUEST (ty=3) payload.
/// `req_ip`/`srv` are Some only for REQUEST.
fn build_dhcp(
    p: &mut [u8],
    mac: [u8; 6],
    ty: u8,
    req_ip: Option<[u8; 4]>,
    srv: Option<[u8; 4]>,
    xid: u32,
) -> usize {
    if p.len() < 300 {
        return 0;
    }
    p[..240].fill(0);
    p[0] = 1; // op request
    p[1] = 1; // htype ethernet
    p[2] = 6; // hlen
    p[4..8].copy_from_slice(&xid.to_be_bytes());
    p[10..12].copy_from_slice(&0x8000u16.to_be_bytes()); // broadcast flag
    p[28..34].copy_from_slice(&mac); // chaddr
    p[236..240].copy_from_slice(&DHCP_COOKIE);
    let mut o = 240;
    p[o] = 53;
    p[o + 1] = 1;
    p[o + 2] = ty;
    o += 3;
    // parameter request list: subnet, router, lease, server-id
    p[o] = 55;
    p[o + 1] = 4;
    p[o + 2..o + 6].copy_from_slice(&[1, 3, 51, 54]);
    o += 6;
    if let Some(ip) = req_ip {
        p[o] = 50;
        p[o + 1] = 4;
        p[o + 2..o + 6].copy_from_slice(&ip);
        o += 6;
    }
    if let Some(s) = srv {
        p[o] = 54;
        p[o + 1] = 4;
        p[o + 2..o + 6].copy_from_slice(&s);
        o += 6;
    }
    p[o] = 255;
    o + 1
}

/// Parsed DHCP reply fields we care about.
struct Lease {
    ty: u8,
    ip: [u8; 4],
    srv: [u8; 4],
    router: [u8; 4],
    mask: [u8; 4],
    secs: u32,
}

/// Hostile-input DHCP parse: BOOTP reply, our xid, cookie present,
/// option walk fully bounded (tag 255 end, tag 0 pad, len-checked).
fn parse_dhcp(p: &[u8], xid: u32) -> Option<Lease> {
    if p.len() < 241 || p[0] != 2 {
        return None;
    }
    if p[4..8] != xid.to_be_bytes() || p[236..240] != DHCP_COOKIE {
        return None;
    }
    let mut l = Lease {
        ty: 0,
        ip: p[16..20].try_into().unwrap(),
        srv: [0; 4],
        router: [0; 4],
        mask: [0; 4],
        secs: 0,
    };
    let mut o = 240;
    while o < p.len() && p[o] != 255 {
        if p[o] == 0 {
            o += 1;
            continue;
        }
        if o + 2 > p.len() || o + 2 + p[o + 1] as usize > p.len() {
            break;
        }
        let (tag, n) = (p[o], p[o + 1] as usize);
        let v = &p[o + 2..o + 2 + n];
        match tag {
            53 if n >= 1 => l.ty = v[0],
            54 if n >= 4 => l.srv.copy_from_slice(&v[..4]),
            3 if n >= 4 => l.router.copy_from_slice(&v[..4]),
            51 if n >= 4 => {
                l.secs = u32::from_be_bytes(v[..4].try_into().unwrap())
            }
            1 if n >= 4 => l.mask.copy_from_slice(&v[..4]),
            _ => {}
        }
        o += 2 + n;
    }
    Some(l)
}

/// DISCOVER -> OFFER -> REQUEST -> ACK over slirp. Returns true on
/// a valid lease; the assigned address is logged.
pub fn dhcp_selftest(base: usize, mac: [u8; 6]) -> bool {
    if mac[5] == 0x01 || mac[5] == 0x02 {
        return false; // socket-demo MACs: no DHCP server exists there
    }
    let Some((ring, bufs)) = rx_init(base) else {
        return false;
    };
    let xid = crate::rand::next_u64() as u32;
    let mut p = [0u8; 300];
    let mut f = [0u8; 360];
    let mut phase = 0u8; // 0 = need OFFER, 1 = need ACK
    let mut offer = Lease {
        ty: 0,
        ip: [0; 4],
        srv: [0; 4],
        router: [0; 4],
        mask: [0; 4],
        secs: 0,
    };
    let mut rounds = 0u32;
    loop {
        for d in 0..N_RX {
            // SAFETY: same contract as arp_selftest.
            let (sta, len) =
                unsafe { ((*ring.add(d)).sta, (*ring.add(d)).len) };
            if sta & RXD_STA_DD == 0 {
                continue;
            }
            if sta & RXD_STA_EOP == 0 || len < 14 || len as usize > RX_BUF {
                unsafe {
                    (*ring.add(d)).sta = 0;
                    wr(base, RDT, d as u32);
                }
                continue;
            }
            let buf = unsafe {
                core::slice::from_raw_parts(bufs.add(d * RX_BUF), len as usize)
            };
            if u16::from_be_bytes([buf[12], buf[13]]) == 0x0800 {
                if let Some(ip) = crate::net::parse_ipv4(&buf[14..]) {
                    if ip.proto == crate::net::NH_UDP {
                        if let Some(u) = crate::net::parse_udp(ip.payload) {
                            if u.dport == 68 && u.sport == 67
                                && (u.cksum_field == 0
                                    || crate::net::csum6_ok(
                                        crate::net::csum4(
                                            ip.src, ip.dst,
                                            crate::net::NH_UDP,
                                            &ip.payload
                                                [..8 + u.payload
                                                    .len()],
                                        )))
                            {
                                if let Some(l) = parse_dhcp(u.payload, xid) {
                                    if phase == 0 && l.ty == 2 {
                                        printk(format_args!(
                                            "rustux: dhcp: OFFER \
                                             {}.{}.{}.{} srv \
                                             {}.{}.{}.{}",
                                            l.ip[0], l.ip[1], l.ip[2],
                                            l.ip[3], l.srv[0], l.srv[1],
                                            l.srv[2], l.srv[3]
                                        ));
                                        offer = l;
                                        phase = 1;
                                        rounds = 0;
                                    } else if phase == 1 && l.ty == 5
                                        && l.ip == offer.ip
                                        && l.srv == offer.srv
                                    {
                                        printk(format_args!(
                                            "rustux: dhcp: ACK \
                                             {}.{}.{}.{} mask \
                                             {}.{}.{}.{} gw \
                                             {}.{}.{}.{} lease {}s",
                                            l.ip[0], l.ip[1], l.ip[2],
                                            l.ip[3], l.mask[0],
                                            l.mask[1], l.mask[2],
                                            l.mask[3], l.router[0],
                                            l.router[1], l.router[2],
                                            l.router[3], l.secs
                                        ));
                                        // Persist the lease — the
                                        // socket layer sources its
                                        // src-ip/mask from these.
                                        OUR_IP.store(
                                            u32::from_be_bytes(l.ip),
                                            Ordering::Relaxed,
                                        );
                                        OUR_MASK.store(
                                            u32::from_be_bytes(l.mask),
                                            Ordering::Relaxed,
                                        );
                                        return true;
                                    }
                                }
                            }
                        }
                    }
                }
            }
            // SAFETY: reposting a consumed descriptor.
            unsafe {
                (*ring.add(d)).sta = 0;
                wr(base, RDT, d as u32);
            }
        }
        rounds += 1;
        if rounds % 4_000_000 == 1 {
            let n = if phase == 0 {
                build_dhcp(&mut p, mac, 1, None, None, xid)
            } else {
                build_dhcp(&mut p, mac, 3, Some(offer.ip), Some(offer.srv), xid)
            };
            let flen = crate::net::build_udp4(
                &mut f,
                [0xff; 6],
                mac,
                [0, 0, 0, 0],
                [255, 255, 255, 255],
                68,
                67,
                &p[..n],
            );
            if flen != 0 {
                let _ = tx_once(base, &f[..flen.max(60)]);
            }
        }
        if rounds == 60_000_000 {
            printk(format_args!("rustux: dhcp: timed out phase {phase}"));
            return false;
        }
    }
}

/// TCP over IPv4 proof (socket-demo MACs only, like ipv8/ipv6).
/// Role :01 = active opener, :02 = passive listener on port 7.
/// Full handshake + one data segment each way + FIN teardown; every
/// segment's checksum, seq and ack are validated before acting.
#[cfg(demo_net)]
pub fn tcp_selftest(base: usize, mac: [u8; 6], con: &mut crate::Console) {
    let role = mac[5];
    if role != 0x01 && role != 0x02 {
        return;
    }
    let us_ip: [u8; 4] = [10, 0, 0, role];
    let peer_ip: [u8; 4] = [10, 0, 0, if role == 0x01 { 2 } else { 1 }];
    const SRV_PORT: u16 = 7;
    let our_port: u16 = if role == 0x01 { 49152 } else { SRV_PORT };
    const MSG: &[u8] = b"rustux over tcp";
    // Linux secure_tcp_seq shape: SipHash of the 4-tuple + a
    // timestamp under the per-boot CSPRNG key — unpredictable to
    // an off-path observer, stable across connections.
    let t = unsafe { core::arch::x86_64::_rdtsc() } as u32;
    let mut isn = klib::hash::siphash_3u32(
        u32::from_be_bytes(us_ip) ^ u32::from_be_bytes(peer_ip),
        ((our_port as u32) << 16) | SRV_PORT as u32,
        t,
        crate::rand::isn_key(),
    ) as u32;
    let mut conns = 0u32; // initiator: connections completed
    let Some((ring, bufs)) = rx_init(base) else {
        return;
    };
    let mut f = [0u8; 160];

    let mut peer_mac = [0u8; 6];
    let mut snd_nxt = isn.wrapping_add(1); // after SYN
    let mut rcv_nxt = 0u32; // peer's expected seq once known
    let mut phase = 0u8;
    let mut rounds = 0u32;
    let mut seen = 0u32;
    let mut i = 0u32;

    printk(format_args!(
        "rustux: tcp: {} up (isn {isn:#x})",
        if role == 0x01 { "initiator" } else { "listener" }
    ));
    crate::log::drain(con);
    loop {
        for d in 0..N_RX {
            // SAFETY: same contract as arp_selftest.
            let (sta, len) =
                unsafe { ((*ring.add(d)).sta, (*ring.add(d)).len) };
            if sta & RXD_STA_DD == 0 {
                continue;
            }
            if sta & RXD_STA_EOP == 0 || len < 14 || len as usize > RX_BUF
            {
                unsafe {
                    (*ring.add(d)).sta = 0;
                    wr(base, RDT, d as u32);
                }
                continue;
            }
            let buf = unsafe {
                core::slice::from_raw_parts(
                    bufs.add(d * RX_BUF),
                    len as usize,
                )
            };
            let et = u16::from_be_bytes([buf[12], buf[13]]);
            if et == 0x0800 && buf.len() >= 34 {
                seen += 1;
                let frm_mac: [u8; 6] = buf[6..12].try_into().unwrap();
                let to_us = buf[..6] == mac;
                if let Some(ip) = crate::net::parse_ipv4(&buf[14..]) {
                    if ip.proto == crate::net::NH_TCP
                        && crate::net::csum6_ok(crate::net::csum4(
                            ip.src,
                            ip.dst,
                            crate::net::NH_TCP,
                            ip.payload,
                        ))
                    {
                        if let Some(t) = crate::net::parse_tcp(ip.payload)
                        {
                            if t.flags & crate::net::TCP_RST != 0 {
                                printk(format_args!(
                                    "rustux: tcp: RST seq={:#x} -> abort",
                                    t.seq
                                ));
                                crate::log::drain(con);
                                return;
                            }
                            if role == 0x02 {
                                // listener: 0 wait SYN, 1 wait ACK,
                                // 2 wait data, 3 wait FIN, 4 last ACK
                                if phase == 0
                                    && t.dport == SRV_PORT
                                    && t.flags == crate::net::TCP_SYN
                                {
                                    // bounded option walk: EOL/NOP
                                    // skips, length-guarded TLVs,
                                    // unknown kinds ignored — no
                                    // wscale shifts (CVE-2026-31495).
                                    let mut mss = 0u16;
                                    let mut o = 0usize;
                                    while o < t.options.len() {
                                        match t.options[o] {
                                            0 => break,
                                            1 => o += 1,
                                            k => {
                                                if o + 2
                                                    > t.options.len()
                                                {
                                                    break;
                                                }
                                                let l = t.options
                                                    [o + 1]
                                                    as usize;
                                                if l < 2
                                                    || o + l
                                                        > t.options
                                                            .len()
                                                {
                                                    break;
                                                }
                                                if k == 2 && l == 4 {
                                                    mss = u16
                                                        ::from_be_bytes(
                                                        [
                                                            t.options
                                                                [o + 2],
                                                            t.options
                                                                [o + 3],
                                                        ],
                                                    );
                                                }
                                                o += l;
                                            }
                                        }
                                    }
                                    peer_mac = frm_mac;
                                    rcv_nxt = t.seq.wrapping_add(1);
                                    // fresh ISN per connection
                                    let t2 = unsafe {
                                        core::arch::x86_64::_rdtsc()
                                    } as u32;
                                    isn = klib::hash::siphash_3u32(
                                        u32::from_be_bytes(us_ip)
                                            ^ u32::from_be_bytes(
                                                ip.src,
                                            ),
                                        ((t.sport as u32) << 16)
                                            | SRV_PORT as u32,
                                        t2,
                                        crate::rand::isn_key(),
                                    ) as u32;
                                    snd_nxt = isn.wrapping_add(1);
                                    let n = crate::net::build_tcp4(
                                        &mut f, peer_mac, mac, us_ip,
                                        ip.src, SRV_PORT, t.sport, isn,
                                        rcv_nxt,
                                        crate::net::TCP_SYN
                                            | crate::net::TCP_ACK,
                                        &[2, 4, 5, 180], &[],
                                    );
                                    if n != 0 {
                                        let _ = tx_once(
                                            base, &f[..n.max(60)],
                                        );
                                        phase = 1;
                                        printk(format_args!(
                                            "rustux: tcp: SYN dport7 \
                                             mss={mss} -> SYN|ACK"
                                        ));
                                        crate::log::drain(con);
                                    }
                                } else if phase == 1
                                    && to_us && ip.src == peer_ip
                                    && frm_mac == peer_mac
                                    && t.flags == crate::net::TCP_ACK
                                    && t.seq == rcv_nxt
                                    && t.ack == snd_nxt
                                {
                                    phase = 2;
                                    printk(format_args!(
                                        "rustux: tcp: established"
                                    ));
                                    crate::log::drain(con);
                                } else if phase == 2
                                    && to_us && ip.src == peer_ip
                                    && frm_mac == peer_mac
                                    && t.flags
                                        & (crate::net::TCP_PSH
                                            | crate::net::TCP_ACK)
                                        == crate::net::TCP_PSH
                                            | crate::net::TCP_ACK
                                    && t.seq == rcv_nxt
                                    && t.ack == snd_nxt
                                {
                                    let n = crate::net::build_tcp4(
                                        &mut f, peer_mac, mac, us_ip,
                                        peer_ip, SRV_PORT, t.sport,
                                        snd_nxt,
                                        rcv_nxt.wrapping_add(
                                            t.payload.len() as u32,
                                        ),
                                        crate::net::TCP_PSH
                                            | crate::net::TCP_ACK,
                                        &[], t.payload,
                                    );
                                    rcv_nxt = rcv_nxt.wrapping_add(
                                        t.payload.len() as u32,
                                    );
                                    snd_nxt = snd_nxt.wrapping_add(
                                        t.payload.len() as u32,
                                    );
                                    if n != 0 {
                                        let _ = tx_once(
                                            base, &f[..n.max(60)],
                                        );
                                        phase = 3;
                                        printk(format_args!(
                                            "rustux: tcp: {}B data \
                                             -> echoed",
                                            t.payload.len()
                                        ));
                                        crate::log::drain(con);
                                    }
                                } else if phase == 3
                                    && to_us && ip.src == peer_ip
                                    && frm_mac == peer_mac
                                    && t.flags
                                        & (crate::net::TCP_FIN
                                            | crate::net::TCP_ACK)
                                        == crate::net::TCP_FIN
                                            | crate::net::TCP_ACK
                                    && t.seq == rcv_nxt
                                {
                                    let n = crate::net::build_tcp4(
                                        &mut f, peer_mac, mac, us_ip,
                                        peer_ip, SRV_PORT, t.sport,
                                        snd_nxt, rcv_nxt.wrapping_add(1),
                                        crate::net::TCP_FIN
                                            | crate::net::TCP_ACK,
                                        &[], &[],
                                    );
                                    rcv_nxt = rcv_nxt.wrapping_add(1);
                                    snd_nxt = snd_nxt.wrapping_add(1);
                                    if n != 0 {
                                        let _ = tx_once(
                                            base, &f[..n.max(60)],
                                        );
                                        phase = 4;
                                        printk(format_args!(
                                            "rustux: tcp: FIN -> FIN|ACK"
                                        ));
                                        crate::log::drain(con);
                                    }
                                } else if phase == 4
                                    && to_us && ip.src == peer_ip
                                    && frm_mac == peer_mac
                                    && t.flags == crate::net::TCP_ACK
                                    && t.seq == rcv_nxt
                                    && t.ack == snd_nxt
                                {
                                    printk(format_args!(
                                        "rustux: tcp: closed clean \
                                         -> re-listening"
                                    ));
                                    crate::log::drain(con);
                                    // persistent server: back to
                                    // LISTEN for the next SYN
                                    phase = 0;
                                    peer_mac = [0; 6];
                                }
                            } else {
                                // initiator: 0 wait SYN|ACK,
                                // 1 wait echo, 2 wait FIN|ACK
                                if phase == 0 && to_us
                                    && ip.src == peer_ip
                                    && ip.dst == us_ip
                                    && t.sport == SRV_PORT
                                    && t.dport == our_port
                                    && t.flags
                                        & (crate::net::TCP_SYN
                                            | crate::net::TCP_ACK)
                                        == crate::net::TCP_SYN
                                            | crate::net::TCP_ACK
                                    && t.ack == snd_nxt
                                    && t.wnd != 0
                                {
                                    peer_mac = frm_mac;
                                    rcv_nxt = t.seq.wrapping_add(1);
                                    let n = crate::net::build_tcp4(
                                        &mut f, peer_mac, mac, us_ip,
                                        peer_ip, our_port, SRV_PORT,
                                        snd_nxt, rcv_nxt,
                                        crate::net::TCP_ACK, &[], &[],
                                    );
                                    if n != 0 {
                                        let _ = tx_once(
                                            base, &f[..n.max(60)],
                                        );
                                    }
                                    printk(format_args!(
                                        "rustux: tcp: SYN|ACK -> \
                                         established"
                                    ));
                                    let n = crate::net::build_tcp4(
                                        &mut f, peer_mac, mac, us_ip,
                                        peer_ip, our_port, SRV_PORT,
                                        snd_nxt, rcv_nxt,
                                        crate::net::TCP_PSH
                                            | crate::net::TCP_ACK,
                                        &[], MSG,
                                    );
                                    if n != 0 {
                                        let _ = tx_once(
                                            base, &f[..n.max(60)],
                                        );
                                        snd_nxt = snd_nxt.wrapping_add(
                                            MSG.len() as u32,
                                        );
                                        phase = 1;
                                    }
                                } else if phase == 1
                                    && to_us && ip.src == peer_ip
                                    && frm_mac == peer_mac
                                    && t.sport == SRV_PORT
                                    && t.dport == our_port
                                    && t.flags
                                        & (crate::net::TCP_PSH
                                            | crate::net::TCP_ACK)
                                        == crate::net::TCP_PSH
                                            | crate::net::TCP_ACK
                                    && t.seq == rcv_nxt
                                    && t.ack == snd_nxt
                                    && t.payload == MSG
                                {
                                    rcv_nxt = rcv_nxt.wrapping_add(
                                        t.payload.len() as u32,
                                    );
                                    let n = crate::net::build_tcp4(
                                        &mut f, peer_mac, mac, us_ip,
                                        peer_ip, our_port, SRV_PORT,
                                        snd_nxt, rcv_nxt,
                                        crate::net::TCP_FIN
                                            | crate::net::TCP_ACK,
                                        &[], &[],
                                    );
                                    if n != 0 {
                                        let _ = tx_once(
                                            base, &f[..n.max(60)],
                                        );
                                        snd_nxt =
                                            snd_nxt.wrapping_add(1);
                                        phase = 2;
                                        printk(format_args!(
                                            "rustux: tcp: echo \
                                             verified -> FIN"
                                        ));
                                        crate::log::drain(con);
                                    }
                                } else if phase == 2
                                    && to_us && ip.src == peer_ip
                                    && frm_mac == peer_mac
                                    && t.flags
                                        & (crate::net::TCP_FIN
                                            | crate::net::TCP_ACK)
                                        == crate::net::TCP_FIN
                                            | crate::net::TCP_ACK
                                    && t.seq == rcv_nxt
                                    && t.ack == snd_nxt
                                {
                                    let n = crate::net::build_tcp4(
                                        &mut f, peer_mac, mac, us_ip,
                                        peer_ip, our_port, SRV_PORT,
                                        snd_nxt,
                                        rcv_nxt.wrapping_add(1),
                                        crate::net::TCP_ACK, &[], &[],
                                    );
                                    if n != 0 {
                                        let _ = tx_once(
                                            base, &f[..n.max(60)],
                                        );
                                    }
                                    conns += 1;
                                    if conns < 2 {
                                        // persistent-server proof:
                                        // open a second connection
                                        let t2 = unsafe {
                                            core::arch::x86_64::_rdtsc()
                                        } as u32;
                                        isn = klib::hash::siphash_3u32(
                                            u32::from_be_bytes(us_ip)
                                                ^ u32::from_be_bytes(
                                                    peer_ip,
                                                ),
                                            ((our_port as u32) << 16)
                                                | SRV_PORT as u32,
                                            t2,
                                            crate::rand::isn_key(),
                                        ) as u32;
                                        snd_nxt = isn.wrapping_add(1);
                                        rcv_nxt = 0;
                                        phase = 0;
                                        printk(format_args!(
                                            "rustux: tcp: conn \
                                             {conns} closed -> \
                                             reconnect (isn {isn:#x})"
                                        ));
                                        crate::log::drain(con);
                                    } else {
                                        printk(format_args!(
                                            "rustux: tcp: conn \
                                             {conns} closed clean \
                                             (persistent server \
                                             verified)"
                                        ));
                                        crate::log::drain(con);
                                        return;
                                    }
                                }
                            }
                        }
                    }
                }
            }
            // SAFETY: reposting a consumed descriptor.
            unsafe {
                (*ring.add(d)).sta = 0;
                wr(base, RDT, d as u32);
            }
        }
        i = i.wrapping_add(1);
        if role == 0x01 {
            rounds += 1;
            if rounds.is_multiple_of(64_000_000) {
                crate::log::printk(format_args!(
                    "rustux: tcp: ini hb r={rounds} ph={phase} seen={seen}"
                ));
                crate::log::drain(con);
            }
            if rounds == u32::MAX {
                printk(format_args!("rustux: tcp: no peer (down?)"));
                crate::log::drain(con);
                return;
            }
            // retransmit the outstanding segment for this phase
            if rounds.is_multiple_of(4_000_000)
                || (phase == 0 && rounds == 1)
            {
                let n = match phase {
                    0 => crate::net::build_tcp4(
                        &mut f, [0xff; 6], mac, us_ip, peer_ip,
                        our_port, SRV_PORT, isn, 0, crate::net::TCP_SYN,
                        &[2, 4, 5, 180], &[],
                    ),
                    1 => crate::net::build_tcp4(
                        &mut f, peer_mac, mac, us_ip, peer_ip,
                        our_port, SRV_PORT,
                        snd_nxt.wrapping_sub(MSG.len() as u32), rcv_nxt,
                        crate::net::TCP_PSH | crate::net::TCP_ACK,
                        &[], MSG,
                    ),
                    2 => crate::net::build_tcp4(
                        &mut f, peer_mac, mac, us_ip, peer_ip,
                        our_port, SRV_PORT, snd_nxt.wrapping_sub(1),
                        rcv_nxt,
                        crate::net::TCP_FIN | crate::net::TCP_ACK,
                        &[], &[],
                    ),
                    _ => 0,
                };
                if n != 0 {
                    let _ = tx_once(base, &f[..n.max(60)]);
                }
            }
        } else {
            if i.is_multiple_of(64_000_000) {
                crate::log::printk(format_args!(
                    "rustux: tcp: lis hb iters={i} ph={phase} \
                     frames={seen}"
                ));
                crate::log::drain(con);
            }
            // retransmit our outstanding reply while awaiting progress
            if i.is_multiple_of(4_000_000) && peer_mac != [0; 6] {
                let n = match phase {
                    1 => crate::net::build_tcp4(
                        &mut f, peer_mac, mac, us_ip, peer_ip,
                        SRV_PORT, 49152, isn, rcv_nxt,
                        crate::net::TCP_SYN | crate::net::TCP_ACK,
                        &[2, 4, 5, 180], &[],
                    ),
                    3 => crate::net::build_tcp4(
                        &mut f, peer_mac, mac, us_ip, peer_ip,
                        SRV_PORT, 49152,
                        snd_nxt.wrapping_sub(MSG.len() as u32), rcv_nxt,
                        crate::net::TCP_PSH | crate::net::TCP_ACK,
                        &[], MSG,
                    ),
                    4 => crate::net::build_tcp4(
                        &mut f, peer_mac, mac, us_ip, peer_ip,
                        SRV_PORT, 49152, snd_nxt.wrapping_sub(1), rcv_nxt,
                        crate::net::TCP_FIN | crate::net::TCP_ACK,
                        &[], &[],
                    ),
                    _ => 0,
                };
                if n != 0 {
                    let _ = tx_once(base, &f[..n.max(60)]);
                }
            }
        }
    }
}

// ---- live RX path: the socket layer's packet source ----------------

/// Bring up the persistent RX ring the socket layer drains. Must run
/// after the selftests — every rx_init reprograms RDBAL, so the last
/// one wins the device. Returns false when the ring can't allocate.
pub fn net_live(base: usize, mac: [u8; 6]) -> bool {
    let Some((ring, bufs)) = rx_init(base) else {
        return false;
    };
    OUR_MAC.store(
        u64::from_be_bytes([0, 0, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]]),
        Ordering::Relaxed,
    );
    LIVE_BASE.store(base, Ordering::Relaxed);
    LIVE_RING.store(ring as usize, Ordering::Relaxed);
    LIVE_BUFS.store(bufs as usize, Ordering::Relaxed);
    true
}

/// The leased address — [0;4] until DHCP ACKs.
pub fn our_ip() -> [u8; 4] {
    OUR_IP.load(Ordering::Relaxed).to_be_bytes()
}

/// The leased netmask.
pub fn our_mask() -> [u8; 4] {
    OUR_MASK.load(Ordering::Relaxed).to_be_bytes()
}

/// Live socket path up: ring programmed and an address leased.
pub fn net_up() -> bool {
    LIVE_BASE.load(Ordering::Relaxed) != 0 && OUR_IP.load(Ordering::Relaxed) != 0
}

/// The cached gateway MAC (None until the boot ARP reply).
pub fn gw_mac() -> Option<[u8; 6]> {
    let m = GW_MAC.load(Ordering::Relaxed);
    if m == 0 {
        None
    } else {
        Some(m.to_be_bytes()[2..8].try_into().unwrap())
    }
}


/// Is `dst` addressed to us: our address, limited broadcast, or the
/// subnet's directed broadcast.
fn for_us(dst: [u8; 4], our: [u8; 4], mask: [u8; 4]) -> bool {
    if dst == our || dst == [0xff; 4] {
        return true;
    }
    let mut host = true;
    let mut net = true;
    for i in 0..4 {
        if dst[i] | mask[i] != 0xff {
            host = false;
        }
        if dst[i] & mask[i] != our[i] & mask[i] {
            net = false;
        }
    }
    host && net
}

/// Handle one received descriptor on the live ring: ARP requests for
/// our address get a reply, ARP replies surface to the caller (for
/// arp_resolve), IPv4/UDP datagrams for us feed the socket demux.
/// The descriptor is always reposted. Returns the responder's
/// (ip, mac) when an ARP reply arrived.
fn drain_desc(d: usize) -> Option<([u8; 4], [u8; 6])> {
    let base = LIVE_BASE.load(Ordering::Relaxed);
    if base == 0 {
        return None;
    }
    let ring = LIVE_RING.load(Ordering::Relaxed) as *const RxDesc;
    let bufs = LIVE_BUFS.load(Ordering::Relaxed) as *const u8;
    // SAFETY: same contract as the selftest drains — the NIC writes
    // sta/len, the frame lands in the posted buffer.
    let (sta, len) = unsafe { ((*ring.add(d)).sta, (*ring.add(d)).len) };
    if sta & RXD_STA_DD == 0 {
        return None;
    }
    let mut out = None;
    if sta & RXD_STA_EOP != 0 && len >= 14 && len as usize <= RX_BUF {
        let p = unsafe { bufs.add(d * RX_BUF) };
        let et = unsafe { u16::from_be_bytes([*p.add(12), *p.add(13)]) };
        if et == 0x0806 && len >= 42 {
            // SAFETY: bounds checked — the ARP body spans eth+14..42.
            let (op, sha, spa, tpa) = unsafe {
                (
                    u16::from_be_bytes([*p.add(20), *p.add(21)]),
                    core::slice::from_raw_parts(p.add(22), 6),
                    core::slice::from_raw_parts(p.add(28), 4),
                    core::slice::from_raw_parts(p.add(38), 4),
                )
            };
            let our = our_ip();
            let mac64 = OUR_MAC.load(Ordering::Relaxed);
            let mac = mac64.to_be_bytes();
            if op == 1 && tpa == our && our != [0; 4] {
                // Who-has us? Answer: swap sender/target, oper=2.
                let mut f = [0u8; 60];
                f[..6].copy_from_slice(sha);
                f[6..12].copy_from_slice(&mac[2..8]);
                f[12] = 0x08;
                f[13] = 0x06;
                f[14..22].copy_from_slice(&[0, 1, 8, 0, 6, 4, 0, 2]);
                f[22..28].copy_from_slice(&mac[2..8]);
                f[28..32].copy_from_slice(&our);
                f[32..38].copy_from_slice(sha);
                f[38..42].copy_from_slice(spa);
                let _ = tx_once(base, &f);
            } else if op == 2 {
                let mut m = [0u8; 6];
                m.copy_from_slice(sha);
                let mut ip = [0u8; 4];
                ip.copy_from_slice(spa);
                out = Some((ip, m));
            }
        } else if et == 0x0800 {
            let src_mac = unsafe {
                core::slice::from_raw_parts(p.add(6), 6)
            };
            let mut m = [0u8; 6];
            m.copy_from_slice(src_mac);
            let buf = unsafe {
                core::slice::from_raw_parts(p.add(14), len as usize - 14)
            };
            ip_demux(buf, m);
        }
    }
    // Repost: the consumed slot becomes the new one-descriptor gap.
    // SAFETY: reposting a consumed descriptor.
    unsafe {
        (*(ring as *mut RxDesc).add(d)).sta = 0;
        wr(base, RDT, d as u32);
    }
    out
}

/// Drain every posted descriptor once — called from the timer tick
/// and before a socket recv blocks, so a datagram already in the
/// ring never waits for the next tick.
pub fn rx_drain() {
    if LIVE_BASE.load(Ordering::Relaxed) == 0 {
        return;
    }
    for d in 0..N_RX {
        drain_desc(d);
    }
    lo_drain();
}

/// IPv4 demux shared by the live ring and the loopback injector:
/// `pkt` is the IP packet (eth already stripped), `src_mac` the
/// sender's link address — replies and accepted children keep it
/// as their peer MAC.
fn ip_demux(pkt: &[u8], src_mac: [u8; 6]) {
    let Some(ip) = crate::net::parse_ipv4(pkt) else { return };
    let our = our_ip();
    if ip.proto == crate::net::NH_UDP && for_us(ip.dst, our, our_mask()) {
        if let Some(u) = crate::net::parse_udp(ip.payload) {
            if u.cksum_field == 0
                || crate::net::csum6_ok(crate::net::csum4(
                    ip.src,
                    ip.dst,
                    crate::net::NH_UDP,
                    &ip.payload[..8 + u.payload.len()],
                ))
            {
                crate::user::udp_rx(ip.src, u.sport, u.dport, u.payload);
            }
        }
    } else if ip.proto == crate::net::NH_TCP
        && (ip.dst == our || ip.dst[0] == 127)
    {
        // Unicast only — broadcast TCP is never a thing. Checksum
        // covers the whole segment before the parser sees it.
        if crate::net::csum6_ok(crate::net::csum4(
            ip.src,
            ip.dst,
            crate::net::NH_TCP,
            ip.payload,
        )) {
            if let Some(t) = crate::net::parse_tcp(ip.payload) {
                crate::user::tcp_rx(
                    ip.src, src_mac, t.sport, t.dport, t.seq, t.ack,
                    t.flags, t.payload,
                );
            }
        }
    }
}

/// Queued loopback frames (built eth+IP, dst self/127.x): drained
/// iteratively because nested demux->tx->demux recursion would
/// overflow the 8KiB syscall stacks — Linux's lo defers through
/// softirq the same way.
static mut LO_Q: [([u8; 1600], u16); 4] = [([0; 1600], 0); 4];
static mut LO_N: usize = 0;
static mut LO_DRAIN: bool = false;
/// Shared build/pop buffers — dead once the frame is queued or
/// demuxed; keeping 3.2KB off the task stack is what lets the
/// loopback chain live inside an 8-16KiB kstack.
static mut TX_F: [u8; 1600] = [0; 1600];
static mut DRAIN_F: [u8; 1600] = [0; 1600];

/// Pop the oldest queued loopback frame into a caller buffer.
fn lo_pop(out: &mut [u8]) -> Option<u16> {
    unsafe {
        let n = *core::ptr::addr_of!(LO_N);
        if n == 0 {
            return None;
        }
        let q = &mut *core::ptr::addr_of_mut!(LO_Q);
        let len = q[0].1;
        out[..1600].copy_from_slice(&q[0].0);
        for i in 1..n {
            q[i - 1] = q[i];
        }
        *core::ptr::addr_of_mut!(LO_N) = n - 1;
        Some(len)
    }
}

/// Drain queued loopback frames through the normal IP demux —
/// reentrant calls (a demuxed frame whose handler transmits) just
/// enqueue and let the outermost drain finish.
fn lo_drain() {
    unsafe {
        if *core::ptr::addr_of!(LO_DRAIN) {
            return;
        }
        *core::ptr::addr_of_mut!(LO_DRAIN) = true;
    }
    let fr = unsafe { &mut *core::ptr::addr_of_mut!(DRAIN_F) };
    while let Some(l) = lo_pop(fr) {
        let l = l as usize;
        if l >= 14 {
            let mut m = [0u8; 6];
            m.copy_from_slice(&fr[6..12]);
            ip_demux(&fr[14..l], m);
        }
    }
    unsafe { *core::ptr::addr_of_mut!(LO_DRAIN) = false };
}

/// Transmit one TCP segment — or queue it for the loopback drain
/// when the destination is this host (our IP or 127/8).
#[allow(clippy::too_many_arguments)]
pub fn tcp_tx(
    dst_mac: [u8; 6],
    dst_ip: [u8; 4],
    sport: u16,
    dport: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    payload: &[u8],
    wnd: u16,
) -> bool {
    let base = LIVE_BASE.load(Ordering::Relaxed);
    if base == 0 {
        return false;
    }
    let mac = OUR_MAC.load(Ordering::Relaxed).to_be_bytes();
    let mut m = [0u8; 6];
    m.copy_from_slice(&mac[2..8]);
    // Build into the shared frame buffer, not the task stack: the
    // buffer is dead the moment the frame is pushed/copied, and a
    // re-entrant call (a demuxed frame's handler transmitting) only
    // touches it after the outer caller is done with it.
    let f = unsafe { &mut *core::ptr::addr_of_mut!(TX_F) };
    let n = crate::net::build_tcp4(
        f, dst_mac, m, our_ip(), dst_ip, sport, dport, seq, ack,
        flags, &[], payload,
    );
    if n == 0 {
        return false;
    }
    if wnd != 1460 {
        // build_tcp4 fixes the advertised window at 1460 — callers
        // with a real receive-buffer answer patch the field here and
        // re-seal the checksum it is covered by.
        let t = 14 + 20; // eth + ip
        f[t + 14..t + 16].copy_from_slice(&wnd.to_be_bytes());
        f[t + 16..t + 18].copy_from_slice(&[0, 0]);
        let ck = crate::net::csum4(
            our_ip(), dst_ip, crate::net::NH_TCP, &f[t..n],
        );
        f[t + 16..t + 18].copy_from_slice(&ck.to_be_bytes());
    }
    let our = our_ip();
    if dst_ip == our || dst_ip[0] == 127 {
        unsafe {
            let q = &mut *core::ptr::addr_of_mut!(LO_Q);
            let len = *core::ptr::addr_of!(LO_N);
            if len < q.len() {
                q[len].0[..n].copy_from_slice(&f[..n]);
                q[len].1 = n as u16;
                *core::ptr::addr_of_mut!(LO_N) = len + 1;
            }
        }
        lo_drain();
        return true;
    }
    tx_once(base, &f[..n.max(60)])
}

/// Route a destination IPv4 to a link-layer MAC: self/loopback and
/// broadcast are static answers, on-link resolves via ARP, the rest
/// falls back to the cached gateway.
pub fn route_mac(dip: [u8; 4]) -> Option<[u8; 6]> {
    let our = our_ip();
    if dip == our || dip[0] == 127 {
        let m = OUR_MAC.load(Ordering::Relaxed).to_be_bytes();
        return Some(m[2..8].try_into().unwrap());
    }
    if dip == [0xff; 4] {
        return Some([0xff; 6]);
    }
    let mask = our_mask();
    if (0..4).all(|i| dip[i] & mask[i] == our[i] & mask[i]) {
        if let Some(m) = arp_resolve(dip) {
            return Some(m);
        }
    }
    gw_mac()
}

/// Resolve an on-link IPv4 to a MAC: gateway is cached from boot;
/// otherwise broadcast a who-has and spin the live ring for the
/// reply (other traffic keeps demuxing during the spin).
pub fn arp_resolve(target: [u8; 4]) -> Option<[u8; 6]> {
    let base = LIVE_BASE.load(Ordering::Relaxed);
    if base == 0 {
        return None;
    }
    let gw = GW_IP.load(Ordering::Relaxed);
    if target == gw.to_be_bytes() {
        let m = GW_MAC.load(Ordering::Relaxed);
        if m != 0 {
            return Some(m.to_be_bytes()[2..8].try_into().unwrap());
        }
    }
    let our = our_ip();
    let mac64 = OUR_MAC.load(Ordering::Relaxed);
    let mac = mac64.to_be_bytes();
    let mut f = [0u8; 60];
    f[..6].copy_from_slice(&[0xff; 6]);
    f[6..12].copy_from_slice(&mac[2..8]);
    f[12] = 0x08;
    f[13] = 0x06;
    f[14..22].copy_from_slice(&[0, 1, 8, 0, 6, 4, 0, 1]);
    f[22..28].copy_from_slice(&mac[2..8]);
    f[28..32].copy_from_slice(&our);
    f[38..42].copy_from_slice(&target);
    if !tx_once(base, &f) {
        return None;
    }
    for _ in 0..4_000_000u32 {
        for d in 0..N_RX {
            if let Some((spa, sha)) = drain_desc(d) {
                if spa == target {
                    return Some(sha);
                }
            }
        }
    }
    None
}

/// Transmit one UDP datagram through the live ring — checksums
/// computed by build_udp4, our leased address as the source.
pub fn udp_tx(dst_mac: [u8; 6], dst_ip: [u8; 4], sport: u16, dport: u16, payload: &[u8]) -> bool {
    let base = LIVE_BASE.load(Ordering::Relaxed);
    if base == 0 {
        return false;
    }
    let mac = OUR_MAC.load(Ordering::Relaxed).to_be_bytes();
    let mut m = [0u8; 6];
    m.copy_from_slice(&mac[2..8]);
    let mut f = [0u8; 1600];
    let n = crate::net::build_udp4(&mut f, dst_mac, m, our_ip(), dst_ip, sport, dport, payload);
    n != 0 && tx_once(base, &f[..n.max(60)])
}
