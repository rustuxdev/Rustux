//! pci — PCI config-space enumeration via the legacy CF8/CFC I/O ports.
//!
//! Firmware (OVMF) has already assigned bus numbers and BARs, so a
//! read-only recursive walk discovers the whole topology: bus 0
//! depth-first, following PCI-to-PCI bridges' secondary bus numbers —
//! the same shape as Linux's early pci_direct_probe. Lines go into the
//! printk ring; the caller's next drain flushes them.

use crate::log::printk;
use crate::pio;

const CFG_ADDR: u16 = 0xcf8;
const CFG_DATA: u16 = 0xcfc;

fn cfg_addr(bus: u8, dev: u8, f: u8, off: u8) -> u32 {
    0x8000_0000 | (bus as u32) << 16 | (dev as u32) << 11 | (f as u32) << 8 | (off as u32 & 0xfc)
}

pub fn read32(bus: u8, dev: u8, f: u8, off: u8) -> u32 {
    // SAFETY: CF8/CFC is the architected config mechanism; a read of a
    // nonexistent function returns 0xffffffff, never faults.
    unsafe {
        pio::outl(CFG_ADDR, cfg_addr(bus, dev, f, off));
        pio::inl(CFG_DATA)
    }
}

pub fn write32(bus: u8, dev: u8, f: u8, off: u8, v: u32) {
    // SAFETY: CF8/CFC config write; callers pick architected offsets.
    unsafe {
        pio::outl(CFG_ADDR, cfg_addr(bus, dev, f, off));
        pio::outl(CFG_DATA, v);
    }
}

/// 16-bit config write — CF8/CFC only moves whole dwords, so this is
/// a read-modify-write of the aligned dword containing `off`.
pub fn write16(bus: u8, dev: u8, f: u8, off: u8, v: u16) {
    let shift = (off as u32 & 2) * 8;
    let w = read32(bus, dev, f, off);
    let w = (w & !(0xffff_u32 << shift)) | (v as u32) << shift;
    write32(bus, dev, f, off, w);
}

/// Locate a function by vendor/device ID. Returns (bus, dev, fn).
pub fn find(vendor: u16, device: u16) -> Option<(u8, u8, u8)> {
    for bus in 0..=255u8 {
        for dev in 0..32u8 {
            let mut f = 0u8;
            loop {
                let id = read32(bus, dev, f, 0);
                if id == vendor as u32 | (device as u32) << 16 {
                    return Some((bus, dev, f));
                }
                let v = id as u16;
                if v == 0xffff || v == 0 {
                    break;
                }
                let hdr = read8(bus, dev, f, 0x0e);
                if (f == 0 && hdr & 0x80 == 0) || f == 7 {
                    break;
                }
                f += 1;
            }
        }
    }
    None
}

/// Command-register bits the PCI spec defines.
pub const CMD_MEM_SPACE: u16 = 1 << 1;
pub const CMD_BUS_MASTER: u16 = 1 << 2;

/// Read-modify-write OR of command-register bits.
pub fn command_or(bus: u8, dev: u8, f: u8, bits: u16) -> u16 {
    let v = read16(bus, dev, f, 0x04);
    let nv = v | bits;
    if nv != v {
        let w = read32(bus, dev, f, 0x04) & !(0xffff) | nv as u32;
        write32(bus, dev, f, 0x04, w);
    }
    nv
}

/// Raw BAR slot value (not decoded).
pub fn bar_raw(bus: u8, dev: u8, f: u8, slot: u8) -> u32 {
    read32(bus, dev, f, 0x10 + slot * 4)
}

/// Command bit 10: INTx emulation off (drivers using MSI set this).
pub const CMD_INTX_DISABLE: u16 = 1 << 10;

/// Walk the capability list (offset 0x34) for capability `id`.
/// Returns the capability's config offset.
pub fn find_cap(bus: u8, dev: u8, f: u8, id: u8) -> Option<u8> {
    // Status bit 4 = capability list present.
    if read16(bus, dev, f, 0x06) & (1 << 4) == 0 {
        return None;
    }
    let mut off = read8(bus, dev, f, 0x34) & !3;
    let mut hops = 0;
    while off >= 0x40 && hops < 48 {
        if read8(bus, dev, f, off) == id {
            return Some(off);
        }
        off = read8(bus, dev, f, off + 1) & !3;
        hops += 1;
    }
    None
}

/// MSI-X capability: table/PBA locations decoded and resolved to
/// physical addresses inside the BAR they live in.
pub struct MsixCap {
    /// Config offset of the capability.
    pub off: u8,
    /// Physical address of the MSI-X table (identity-mapped).
    pub table: usize,
    /// Number of table vectors (table size field + 1).
    pub nvec: u32,
}

/// Locate and decode the MSI-X capability (id 0x11).
pub fn msix_cap(bus: u8, dev: u8, f: u8) -> Option<MsixCap> {
    let off = find_cap(bus, dev, f, 0x11)?;
    let ctrl = read16(bus, dev, f, off + 2);
    let nvec = (ctrl & 0x7ff) as u32 + 1;
    let tbl = read32(bus, dev, f, off + 4);
    let bir = (tbl & 7) as u8;
    if bir > 5 {
        return None;
    }
    let bar = bar_raw(bus, dev, f, bir);
    if bar == 0 || bar == u32::MAX || bar & 1 != 0 {
        return None;
    }
    // A 64-bit BAR (type bits 0b100) holds its high dword in the
    // next BAR — dropping it pointed the table at low memory and
    // silently ate every entry write (seen on NVMe's BAR above 4G).
    let base = if bar & 6 == 4 && bir < 5 {
        ((read32(bus, dev, f, 0x10 + 4 * (bir + 1)) as u64) << 32
            | (bar & !0xf) as u64) as usize
    } else {
        (bar & !0xf) as usize
    };
    Some(MsixCap {
        off,
        table: base + (tbl & !7) as usize,
        nvec,
    })
}

/// One 16-byte MSI-X table entry: {addr_lo, addr_hi, data, ctrl}.
/// `vec` is the IDT vector the LAPIC delivers; `dest` its LAPIC ID.
/// `masked` keeps a vector quiet until software unmasks it.
pub unsafe fn msix_set(cap: &MsixCap, v: u32, vec: u8, dest: u8, masked: bool) {
    if v >= cap.nvec {
        return;
    }
    let e = (cap.table + v as usize * 16) as *mut u32;
    // SAFETY: caller guarantees `table` is the MSI-X MMIO window.
    unsafe {
        e.write_volatile(0xfee0_0000 | (dest as u32) << 12);
        e.add(1).write_volatile(0);
        e.add(2).write_volatile(vec as u32);
        e.add(3).write_volatile(masked as u32);
    }
}

/// Flip the capability on: MSI-X enable (bit15), function mask off
/// (bit14), and silence INTx on the function. The message-control
/// field is 16-bit — write16 does the aligned dword RMW it needs.
pub fn msix_enable(bus: u8, dev: u8, f: u8, cap: &MsixCap) {
    let ctrl = read16(bus, dev, f, cap.off + 2);
    write16(bus, dev, f, cap.off + 2, (ctrl | 0x8000) & !0x4000);
    command_or(bus, dev, f, CMD_INTX_DISABLE);
}

pub fn read16(bus: u8, dev: u8, f: u8, off: u8) -> u16 {
    (read32(bus, dev, f, off) >> ((off as u32 & 2) * 8)) as u16
}

pub fn read8(bus: u8, dev: u8, f: u8, off: u8) -> u8 {
    (read32(bus, dev, f, off) >> ((off as u32 & 3) * 8)) as u8
}

/// Decode one BAR slot: (is_io, base, consumes_next_slot).
fn decode_bar(bus: u8, dev: u8, f: u8, off: u8) -> Option<(bool, u64, bool)> {
    let lo = read32(bus, dev, f, off);
    if lo == 0 || lo == u32::MAX {
        return None;
    }
    if lo & 1 != 0 {
        return Some((true, (lo & !3) as u64, false));
    }
    let mem64 = (lo >> 1) & 3 == 2;
    let base = if mem64 {
        (lo & !0xf) as u64 | (read32(bus, dev, f, off + 4) as u64) << 32
    } else {
        (lo & !0xf) as u64
    };
    Some((false, base, mem64))
}

fn class_name(class: u8, sub: u8) -> &'static str {
    match (class, sub) {
        (0x00, 0x00) => "vga-compat",
        (0x01, 0x00) => "scsi",
        (0x01, 0x01) => "ide",
        (0x01, 0x06) => "sata/ahci",
        (0x02, _) => "network",
        (0x03, _) => "display",
        (0x04, _) => "multimedia",
        (0x06, 0x00) => "host bridge",
        (0x06, 0x01) => "isa bridge",
        (0x06, 0x04) => "pci-pci bridge",
        (0x06, 0x80) => "bridge",
        (0x0c, 0x03) => "usb",
        (0x0c, 0x05) => "smbus",
        _ => "device",
    }
}

/// Depth-first walk of one bus; follows bridges recursively.
fn scan_bus(bus: u8, depth: u8) -> u32 {
    if depth > 4 {
        return 0;
    }
    let mut n = 0;
    for dev in 0..32u8 {
        let mut f = 0u8;
        loop {
            let id = read32(bus, dev, f, 0);
            let vendor = id as u16;
            if vendor == 0xffff || vendor == 0 {
                break;
            }
            n += 1;
            let device = (id >> 16) as u16;
            let class = read8(bus, dev, f, 0x0b);
            let sub = read8(bus, dev, f, 0x0a);
            let progif = read8(bus, dev, f, 0x09);
            let hdr = read8(bus, dev, f, 0x0e);
            printk(format_args!(
                "rustux: pci: {bus:02x}:{dev:02x}.{f} [{vendor:04x}:{device:04x}] \
                 class {class:02x}{sub:02x}.{progif:02x} {}",
                class_name(class, sub)
            ));
            // First two implemented BARs — what a driver binds on.
            let mut off = 0x10u8;
            let mut shown = 0;
            while off <= 0x24 && shown < 2 {
                if let Some((is_io, base, mem64)) = decode_bar(bus, dev, f, off) {
                    printk(format_args!(
                        "rustux: pci:   BAR{} {} @{base:#x}",
                        (off - 0x10) / 4,
                        if is_io { "io  " } else { "mmio" }
                    ));
                    shown += 1;
                    if mem64 {
                        off += 4;
                    }
                }
                off += 4;
            }
            // Header type 1: secondary bus number at 0x19.
            if hdr & 0x7f == 1 {
                let sec = read8(bus, dev, f, 0x19);
                if sec != 0 && sec != bus {
                    printk(format_args!("rustux: pci:   -> secondary bus {sec:02x}"));
                    n += scan_bus(sec, depth + 1);
                }
            }
            // The multi-function bit lives in function 0's header type.
            if (f == 0 && hdr & 0x80 == 0) || f == 7 {
                break;
            }
            f += 1;
        }
    }
    n
}

/// Enumerate every PCI function. Returns the count found.
pub fn scan() -> u32 {
    scan_bus(0, 0)
}
