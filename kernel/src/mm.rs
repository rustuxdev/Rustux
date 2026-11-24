//! mm — early memory management: own page tables + a physical frame allocator.
//!
//! After ExitBootServices we are still running on OVMF's page tables. This
//! module builds a fresh 4-level identity map covering 0..max(4 GiB, top of
//! physical memory) with 2 MiB large pages — the 4 GiB floor guarantees the
//! framebuffer BAR and other 32-bit MMIO stay reachable — then switches CR3.
//! From that point every ConventionalMemory frame (minus the table carve-out)
//! feeds a Linux-style buddy allocator: `free_area[order]` lists of
//! contiguous 2^order-page blocks, linked through each free block's first
//! u64 — so the allocator needs zero backing memory — with merge-on-free
//! and split-on-alloc semantics mirroring mm/page_alloc.c.

/// One normalized memory-map entry: the firmware-agnostic descriptor
/// every boot front end produces (UEFI memory map, Multiboot2 mmap tag).
/// `usable` marks allocator-eligible RAM — EFI CONVENTIONAL / E820 type 1.
#[derive(Clone, Copy)]
pub struct MapEnt {
    pub phys_start: u64,
    pub page_count: u64,
    pub usable: bool,
}

pub const PAGE: u64 = 4096;
const PAGE_2M: u64 = 2 * 1024 * 1024;
const GIB: u64 = 1 << 30;

const PRESENT: u64 = 1;
const RW: u64 = 1 << 1;
const PS: u64 = 1 << 7; // large page at this level

#[inline]
unsafe fn write64(addr: u64, v: u64) {
    // SAFETY: callers only touch addresses inside the active identity map
    // (table memory pre-switch, free frames post-switch).
    unsafe { (addr as *mut u64).write_volatile(v) }
}

#[inline]
unsafe fn read64(addr: u64) -> u64 {
    // SAFETY: same contract as write64.
    unsafe { (addr as *const u64).read_volatile() }
}

/// GiB of address space the identity map must cover: end of the highest
/// memory-map descriptor, rounded up, but never less than 4 GiB so 32-bit
/// BARs (framebuffer included) remain mapped.
pub fn map_gib(mmap: &[MapEnt]) -> u64 {
    let mut end = 0u64;
    for d in mmap {
        let e = d
            .phys_start
            .saturating_add(d.page_count.saturating_mul(PAGE));
        if e > end {
            end = e;
        }
    }
    core::cmp::max(4, end.div_ceil(GIB))
}

/// Number of 4 KiB table frames the identity map needs for `map_gib` GiB:
/// one PML4, one PDPT per 512 GiB, one PD per GiB.
pub fn table_frames(ngib: u64) -> u64 {
    1 + ngib.div_ceil(512) + ngib
}

/// Build the identity map in `table_frames(ngib)` frames at `table_base`
/// (physical). Returns the PML4 physical address.
///
/// Layout: [PML4][PDPT x npdpt][PD x ngib]. PML4[p] -> PDPT p; PDPT[p][i] ->
/// the PD covering GiB 512*p+i; each PD holds 512 x 2 MiB entries.
/// Everything is P|RW — this is a boot map; W^X and userspace splits belong
/// to the real page-table layer.
pub fn build_identity_map(mmap: &[MapEnt], table_base: u64) -> u64 {
    let ngib = map_gib(mmap);
    let npdpt = ngib.div_ceil(512);
    let bytes = table_frames(ngib) * PAGE;
    let mut a = table_base;
    while a < table_base + bytes {
        unsafe { write64(a, 0) };
        a += 8;
    }

    let pml4 = table_base;
    // SAFETY: all table frames are inside the carve we own, mapped pre-switch.
    for p in 0..npdpt {
        let pdpt = table_base + (1 + p) * PAGE;
        unsafe { write64(pml4 + p * 8, pdpt | PRESENT | RW) };
    }
    for g in 0..ngib {
        let pd = table_base + (1 + npdpt + g) * PAGE;
        let pdpt = table_base + (1 + g / 512) * PAGE;
        unsafe { write64(pdpt + (g % 512) * 8, pd | PRESENT | RW) };
        for i in 0..512u64 {
            let phys = g * GIB + i * PAGE_2M;
            unsafe { write64(pd + i * 8, phys | PRESENT | RW | PS) };
        }
    }
    pml4
}

/// Switch CR3 to a freshly built PML4.
pub fn load_cr3(pml4_phys: u64) {
    // SAFETY: pml4_phys is a valid 4-level root identity-mapping the address
    // space we execute in; the write implicitly flushes the TLB.
    unsafe {
        core::arch::asm!("mov cr3, {}", in(reg) pml4_phys, options(nostack));
    }
}

/// Highest block order, as in Linux mm: orders 0..=MAX_ORDER-1 give blocks
/// of up to 2^13 pages = 32 MiB — VFILE_MAX-sized contiguous requests fit.
pub const MAX_ORDER: usize = 14;

/// Buddy physical page allocator (mm/page_alloc.c shape): `free_area[o]`
/// is the intrusive list of free 2^o-page blocks — each block's first u64
/// links to the next. Blocks coalesce with their address-buddy on free
/// and split on alloc; the caller passes the order on free, exactly like
/// Linux __free_pages(page, order).
pub struct Buddy {
    free_area: [u64; MAX_ORDER],
    free: u64,
}

impl Buddy {
    pub const fn new() -> Self {
        Self {
            free_area: [0; MAX_ORDER],
            free: 0,
        }
    }

    /// Link a free block into `free_area[order]`.
    fn push(&mut self, order: usize, addr: u64) {
        // SAFETY: `addr` is a mapped, owned free block.
        unsafe { write64(addr, self.free_area[order]) };
        self.free_area[order] = addr;
    }

    /// Remove `addr` from `free_area[order]`. True when found — used by
    /// free() to test whether the merge candidate is actually free at the
    /// same order (Linux checks PageBuddy; we have no memmap yet).
    fn unlink(&mut self, order: usize, addr: u64) -> bool {
        let mut prev: u64 = 0;
        let mut cur = self.free_area[order];
        let mut guard = 0u64;
        while cur != 0 && guard < (1 << 20) {
            guard += 1;
            if cur == addr {
                let nxt = unsafe { read64(cur) };
                if prev == 0 {
                    self.free_area[order] = nxt;
                } else {
                    // SAFETY: prev is a live free block; its link is first u64.
                    unsafe { write64(prev, nxt) };
                }
                return true;
            }
            prev = cur;
            // SAFETY: cur is a live free block in this list.
            cur = unsafe { read64(cur) };
        }
        false
    }

    /// Emit `[lo, hi)` as the largest aligned power-of-2 blocks possible,
    /// keeping every free list short.
    fn seed_span(&mut self, mut lo: u64, hi: u64) {
        while lo + PAGE <= hi {
            let mut order = 0usize;
            while order + 1 < MAX_ORDER
                && lo & ((PAGE << (order + 1)) - 1) == 0
                && lo + (PAGE << (order + 1)) <= hi
            {
                order += 1;
            }
            self.push(order, lo);
            self.free += 1 << order;
            lo += PAGE << order;
        }
    }

    /// Pool every frame in `[start, end)` minus the page-aligned `reserved`
    /// spans, emitted as largest-aligned blocks.
    pub fn add_range(&mut self, start: u64, end: u64, reserved: &[(u64, u64)]) {
        let s = start.div_ceil(PAGE) * PAGE;
        let e = end / PAGE * PAGE;
        if s >= e {
            return;
        }
        // Subtract each reserved span from the working segments. Reserved
        // spans are few (the table carve today) and page-aligned.
        let mut segs = [(s, e); 8];
        let mut nseg = 1usize;
        for &(rs, re) in reserved {
            let mut i = 0;
            while i < nseg {
                let (fs, fe) = segs[i];
                if re <= fs || rs >= fe {
                    i += 1;
                } else if rs <= fs && re >= fe {
                    segs[i] = segs[nseg - 1];
                    nseg -= 1;
                } else if rs <= fs {
                    segs[i] = (re, fe);
                    i += 1;
                } else if re >= fe {
                    segs[i] = (fs, rs);
                    i += 1;
                } else {
                    segs[i] = (fs, rs);
                    if nseg < segs.len() {
                        segs[nseg] = (re, fe);
                        nseg += 1;
                    }
                    i += 1;
                }
            }
        }
        for &(fs, fe) in &segs[..nseg] {
            self.seed_span(fs, fe);
        }
    }

    /// Allocate a contiguous 2^order-page block, splitting a larger free
    /// block down when needed. None when nothing big enough is free.
    pub fn alloc(&mut self, order: usize) -> Option<u64> {
        if order >= MAX_ORDER {
            return None;
        }
        let mut o = order;
        while o < MAX_ORDER && self.free_area[o] == 0 {
            o += 1;
        }
        if o == MAX_ORDER {
            return None;
        }
        let a = self.free_area[o];
        // SAFETY: list heads are owned free blocks; link is first u64.
        let nxt = unsafe { read64(a) };
        self.free_area[o] = nxt;
        while o > order {
            o -= 1;
            self.push(o, a + (PAGE << o));
        }
        self.free -= 1 << order;
        Some(a)
    }

    /// Free a 2^order-page block previously returned by alloc(order),
    /// merging with its address-buddy while the buddy is free at the same
    /// order — Linux __free_one_page semantics.
    pub fn free_pages(&mut self, mut addr: u64, mut order: usize) {
        self.free += 1 << order;
        while order + 1 < MAX_ORDER {
            let buddy = addr ^ (PAGE << order);
            if !self.unlink(order, buddy) {
                break;
            }
            addr = addr.min(buddy);
            order += 1;
        }
        self.push(order, addr);
    }

    pub fn free_count(&self) -> u64 {
        self.free
    }
}
