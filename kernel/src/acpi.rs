//! acpi — RSDP capture + XSDT/MADT parsing.
//!
//! The RSDP physical address lives in the UEFI system table's
//! configuration array, which is only reachable while boot services are
//! up — `grab_rsdp` snapshots it before `exit_boot_services`. The tables
//! themselves sit in ACPI/reclaim memory that stays readable afterwards,
//! so `madt` parses them post-EBS under our own page tables.
//!
//! From the MADT we keep what the interrupt layer needs: the I/O APIC's
//! MMIO base + GSI base, the LAPIC MMIO base (sanity-check vs the MSR),
//! the enabled-LAPIC count, and interrupt-source overrides — chiefly
//! IRQ0 -> GSI2, which is how ISA IRQs reach the I/O APIC on PC hardware.

use core::sync::atomic::{AtomicU64, Ordering};

static RSDP: AtomicU64 = AtomicU64::new(0);

/// One MADT interrupt-source override: ISA `src` pin -> `gsi` line.
#[derive(Clone, Copy)]
pub struct Iso {
    pub src: u8,
    pub gsi: u32,
    /// Bits 1:0 polarity, 3:2 trigger (00 = conform -> ISA edge/high).
    pub flags: u16,
}

/// What we need out of the MADT.
pub struct Madt {
    pub lapic_addr: u64,
    pub ioapic_addr: u64,
    pub ioapic_gsi_base: u32,
    /// All interrupt-source overrides found (up to 8 kept).
    pub isos: [Iso; 8],
    pub n_isos: usize,
    pub lapics: u32,
}

impl Madt {
    /// GSI + flags for an ISA IRQ line: the override when present, else
    /// identity-mapped GSI with conform (edge/active-high) flags.
    pub fn gsi_for_irq(&self, irq: u8) -> (u32, u16) {
        for iso in &self.isos[..self.n_isos] {
            if iso.src == irq {
                return (iso.gsi, iso.flags);
            }
        }
        (irq as u32, 0)
    }
}

/// Snapshot the RSDP address from the UEFI configuration table. Must run
/// before `exit_boot_services` — the system table is boot-time only.
#[cfg(target_os = "uefi")]
pub fn grab_rsdp() -> Option<u64> {
    use uefi::table::cfg::ConfigTableEntry;
    let mut rsdp = None::<u64>;
    let mut rsdp1 = None::<u64>;
    uefi::system::with_config_table(|slice| {
        for e in slice {
            if e.guid == ConfigTableEntry::ACPI2_GUID {
                rsdp = Some(e.address as u64);
            } else if e.guid == ConfigTableEntry::ACPI_GUID {
                rsdp1 = Some(e.address as u64);
            }
        }
    });
    // Prefer ACPI2 (XSDT); fall back to ACPI1 (RSDT).
    let p = rsdp.or(rsdp1)?;
    RSDP.store(p, Ordering::Relaxed);
    Some(p)
}

/// Record an RSDP address obtained outside UEFI — the BIOS entry hands
/// us the Multiboot2 ACPI tag or a firmware-area scan result.
#[cfg(not(target_os = "uefi"))]
pub fn provide_rsdp(p: u64) -> Option<u64> {
    RSDP.store(p, Ordering::Relaxed);
    Some(p)
}

#[inline]
fn rd<T>(p: u64, off: u64) -> T {
    // SAFETY: callers pass phys addresses inside firmware-provided ACPI
    // tables, reachable via the physmap; reads are unaligned-safe.
    unsafe { ((crate::mm::pmap(p) + off) as *const T).read_unaligned() }
}

/// Standard 36-byte SDT header: signature, length, revision, checksum.
fn sdt_ok(p: u64, sig: &[u8; 4]) -> Option<u32> {
    for i in 0..4u64 {
        if rd::<u8>(p, i) != sig[i as usize] {
            return None;
        }
    }
    let len = rd::<u32>(p, 4);
    // Bounds sanity: a table can't be larger than a few pages.
    if !(36..=16384).contains(&len) {
        return None;
    }
    let mut sum = 0u8;
    for i in 0..len as u64 {
        sum = sum.wrapping_add(rd::<u8>(p, i));
    }
    if sum != 0 {
        return None; // bad checksum
    }
    Some(len)
}

/// Parse the XSDT (or RSDT) chain down to the MADT. Returns None when the
/// RSDP was never grabbed, is malformed, or has no APIC table.
pub fn madt() -> Option<Madt> {
    let rsdp = RSDP.load(Ordering::Relaxed);
    if rsdp == 0 {
        return None;
    }
    // "RSD PTR " + 20-byte checksum (v1) / full-length checksum (v2+).
    for i in 0..8u64 {
        if rd::<u8>(rsdp, i) != b"RSD PTR "[i as usize] {
            return None;
        }
    }
    let mut sum = 0u8;
    for i in 0..20u64 {
        sum = sum.wrapping_add(rd::<u8>(rsdp, i));
    }
    if sum != 0 {
        return None;
    }
    let rev = rd::<u8>(rsdp, 15);

    // Walk the table-of-tables. XSDT entries are 8-byte, RSDT 4-byte.
    let (sdt, esz): (u64, u64) = if rev >= 2 {
        (rd::<u64>(rsdp, 24), 8)
    } else {
        (rd::<u32>(rsdp, 16) as u64, 4)
    };
    let len = sdt_ok(sdt, if rev >= 2 { b"XSDT" } else { b"RSDT" })?;
    let n = (len as u64 - 36) / esz;
    let mut apic = None::<u64>;
    for i in 0..n.min(64) {
        let p = if esz == 8 {
            rd::<u64>(sdt, 36 + i * 8)
        } else {
            rd::<u32>(sdt, 36 + i * 4) as u64
        };
        if p != 0 && (0..4).all(|k| rd::<u8>(p, k) == b"APIC"[k as usize]) {
            apic = Some(p);
            break;
        }
    }
    let madt = apic?;
    let len = sdt_ok(madt, b"APIC")?;

    // Controller header: LAPIC phys addr @+36, then type/len records @+44.
    let mut m = Madt {
        lapic_addr: rd::<u32>(madt, 36) as u64,
        ioapic_addr: 0,
        ioapic_gsi_base: 0,
        isos: [Iso { src: 0, gsi: 0, flags: 0 }; 8],
        n_isos: 0,
        lapics: 0,
    };
    let mut off = 44u64;
    let end = len as u64;
    while off + 2 <= end {
        let ty = rd::<u8>(madt, off);
        let l = rd::<u8>(madt, off + 1) as u64;
        if l < 2 {
            break; // corrupt record
        }
        match ty {
            // Processor Local APIC (8-byte record) — count enabled ones.
            0 if l >= 8 && off + l <= end && rd::<u32>(madt, off + 4) & 1 != 0 => {
                m.lapics += 1;
            }
            // I/O APIC (12-byte record): id, rsvd, addr u32, GSI base u32.
            1 if l >= 12 && off + l <= end && m.ioapic_addr == 0 => {
                m.ioapic_addr = rd::<u32>(madt, off + 4) as u64;
                m.ioapic_gsi_base = rd::<u32>(madt, off + 8);
            }
            // Interrupt Source Override (10-byte record): bus, source
            // IRQ, GSI u32, flags u16.
            2 if l >= 10 && off + l <= end && m.n_isos < m.isos.len() => {
                m.isos[m.n_isos] = Iso {
                    src: rd::<u8>(madt, off + 3),
                    gsi: rd::<u32>(madt, off + 4),
                    flags: rd::<u16>(madt, off + 8),
                };
                m.n_isos += 1;
            }
            _ => {}
        }
        off += l;
    }
    Some(m)
}
