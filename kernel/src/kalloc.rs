//! kalloc — kmalloc-style heap over the buddy page allocator.
//!
//! Same layering as Linux mm (page tables -> buddy -> slab -> kmalloc):
//! size-class caches from 32 to 4096 bytes are carved out of buddy blocks,
//! and anything larger goes straight to the buddy as a direct block. Every
//! allocation carries a 16-byte header recording its size class — or
//! DIRECT plus the order for big blocks — so kfree needs no size hint;
//! that header is the role struct page + kmem_cache play upstream. Free
//! objects link through their own storage. IRQs are masked for the
//! duration of every operation (irqsave/irqrestore) so an interrupt
//! arriving mid-operation cannot corrupt the freelists.

use crate::mm::{pmap, unpmap, Buddy, MapEnt, PAGE};

const HDR: u64 = 16;
/// Classes 2^5 .. 2^12; the smallest object stride (32) already covers
/// the 16-byte header, so usable payload tops out at 4096 - 16.
const N_CLASSES: usize = 8;
/// Header kind value marking a direct buddy block (header meta = order).
const KIND_DIRECT: u64 = u64::MAX;

struct Kalloc {
    buddy: Buddy,
    /// Intrusive freelist head per class; first u64 of each free slot
    /// links to the next.
    cache: [u64; N_CLASSES],
}

static mut ALLOC: Kalloc = Kalloc {
    buddy: Buddy::new(),
    cache: [0; N_CLASSES],
};

/// Conventional frames the memory map reported at init — the
/// /proc/meminfo MemTotal figure (kernel-resident frames included,
/// like Linux counting them in MemTotal).
static mut TOTAL_FRAMES: u64 = 0;

use crate::pio::{irq_restore, irq_save};

/// Size class for `size` payload bytes, or None when it needs a direct
/// buddy block (size + header > 4096).
fn class_of(size: usize) -> Option<usize> {
    // checked_add: a size near usize::MAX must fail cleanly, not wrap
    // into a bogus small class.
    let need = size.checked_add(HDR as usize)?;
    if need > 4096 {
        return None;
    }
    let mut c = 0usize;
    while (32usize << c) < need {
        c += 1;
    }
    Some(c)
}

/// Carve a fresh buddy block into same-size objects for class `c` and
/// link them into the cache freelist. Classes never exceed 4 KiB, so an
/// order-0 block always holds at least one object.
fn refill(alloc: &mut Kalloc, c: usize) {
    let obj = 32u64 << c;
    let mut order = 0usize;
    while (PAGE << order) < obj {
        order += 1;
    }
    let Some(b) = alloc.buddy.alloc(order) else { return };
    let n = (PAGE << order) / obj;
    for i in 0..n {
        let slot = pmap(b + i * obj);
        // SAFETY: slot is inside the owned block just allocated.
        unsafe { (slot as *mut u64).write_volatile(alloc.cache[c]) };
        alloc.cache[c] = slot;
    }
}

/// Seed the heap's buddy with every conventional frame minus `reserved`
/// spans (the page-table carve). Called once, post-EBS, from main.
pub fn init(mmap: &[MapEnt], reserved: &[(u64, u64)]) {
    let alloc = unsafe { &mut *core::ptr::addr_of_mut!(ALLOC) };
    let mut total = 0u64;
    for d in mmap {
        if d.usable {
            total += d.page_count;
            alloc.buddy.add_range(
                d.phys_start,
                d.phys_start + d.page_count * PAGE,
                reserved,
            );
        }
    }
    unsafe { *core::ptr::addr_of_mut!(TOTAL_FRAMES) = total };
}

/// Allocate `size` bytes (uninitialized; null on size==0 or OOM).
/// Result is 16-byte aligned.
pub fn kmalloc(size: usize) -> *mut u8 {
    if size == 0 {
        return core::ptr::null_mut();
    }
    let f = irq_save();
    let alloc = unsafe { &mut *core::ptr::addr_of_mut!(ALLOC) };
    let obj = if let Some(c) = class_of(size) {
        if alloc.cache[c] == 0 {
            refill(alloc, c);
        }
        let slot = alloc.cache[c];
        if slot != 0 {
            // SAFETY: slot is a free object linked by refill/kfree.
            alloc.cache[c] = unsafe { (slot as *const u64).read_volatile() };
            // SAFETY: same slot, now being handed out — write its header.
            unsafe {
                (slot as *mut u64).write_volatile(c as u64);
            }
            slot + HDR
        } else {
            0
        }
    } else {
        let Some(total) = (size as u64).checked_add(HDR) else {
            unsafe { irq_restore(f) };
            return core::ptr::null_mut();
        };
        let order = (total.div_ceil(PAGE) as usize)
            .next_power_of_two()
            .trailing_zeros() as usize;
        alloc.buddy.alloc(order).map_or(0, |b| {
            let lb = pmap(b);
            // SAFETY: lb is an owned block inside the physmap.
            unsafe {
                (lb as *mut u64).write_volatile(KIND_DIRECT);
                ((lb + 8) as *mut u64).write_volatile(order as u64);
            }
            lb + HDR
        })
    };
    unsafe { irq_restore(f) };
    obj as *mut u8
}

/// One zeroed 4KiB frame as a physical address — page-table and
/// user-page allocator. Deref it through mm::pmap().
pub fn alloc_frame() -> Option<u64> {
    let f = irq_save();
    let alloc = unsafe { &mut *core::ptr::addr_of_mut!(ALLOC) };
    let b = alloc.buddy.alloc(0);
    // SAFETY: f was produced by the matching irq_save above.
    unsafe { irq_restore(f) };
    if let Some(p) = b {
        // SAFETY: p is an owned frame, physmap-reachable.
        unsafe { core::ptr::write_bytes(pmap(p) as *mut u8, 0, 4096) };
    }
    b
}

/// Free a frame previously returned by alloc_frame. Same contract as
/// kfree: exactly once per allocation.
pub fn free_frame(p: u64) {
    if p == 0 {
        return;
    }
    let f = irq_save();
    let alloc = unsafe { &mut *core::ptr::addr_of_mut!(ALLOC) };
    alloc.buddy.free_pages(p, 0);
    unsafe { irq_restore(f) };
}

/// kmalloc + zero-fill (Linux kzalloc).
pub fn kmalloc_zalloc(size: usize) -> *mut u8 {
    let p = kmalloc(size);
    if !p.is_null() {
        // SAFETY: p names `size` owned bytes just allocated.
        unsafe { core::ptr::write_bytes(p, 0, size) };
    }
    p
}

/// Free a pointer previously returned by kmalloc/kmalloc_zalloc. Must be
/// called exactly once per allocation — same contract as Linux kfree.
pub unsafe fn kfree(p: *mut u8) {
    if p.is_null() {
        return;
    }
    let f = irq_save();
    let alloc = unsafe { &mut *core::ptr::addr_of_mut!(ALLOC) };
    let hdr = (p as u64) - HDR;
    // SAFETY: caller contract — p came from kmalloc, freed once.
    let kind = unsafe { (hdr as *const u64).read_volatile() };
    if kind == KIND_DIRECT {
        let order = unsafe { ((hdr + 8) as *const u64).read_volatile() } as usize;
        alloc.buddy.free_pages(unpmap(hdr), order);
    } else if (kind as usize) < N_CLASSES {
        // Reuse the header slot as the freelist link.
        unsafe { (hdr as *mut u64).write_volatile(alloc.cache[kind as usize]) };
        alloc.cache[kind as usize] = hdr;
    }
    // kind outside the valid range means a corrupt/foreign pointer —
    // leak it rather than poison a freelist. Scream, though: the only
    // way a kmalloc header reads as garbage is an overrun somewhere.
    if kind != KIND_DIRECT && (kind as usize) >= N_CLASSES {
        crate::log::printk(format_args!(
            "rustux: kfree: corrupt header kind={kind:#x} p={:#x}",
            p as u64
        ));
    }
    unsafe { irq_restore(f) };
}

/// Frames currently free in the buddy underneath (slab-resident pages
/// are cache-owned and not counted, matching slab semantics).
pub fn free_frames() -> u64 {
    unsafe { (*core::ptr::addr_of!(ALLOC)).buddy.free_count() }
}

/// Total conventional frames the firmware map reported (MemTotal).
pub fn total_frames() -> u64 {
    unsafe { *core::ptr::addr_of!(TOTAL_FRAMES) }
}
