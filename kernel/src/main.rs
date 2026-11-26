//! Rustux kernel entry point.
//!
//! Boots under UEFI (OVMF in QEMU). Serial + GOP framebuffer consoles, the
//! adopted klib unit proofs, then ExitBootServices and the firmware memory
//! map — after which we run on owned hardware only. Page tables, interrupts,
//! and the first allocator come next.

#![no_main]
#![no_std]


#[cfg(target_os = "uefi")]
use uefi::mem::memory_map::{MemoryMap, MemoryType};
#[cfg(target_os = "uefi")]
use uefi::prelude::*;

mod acpi;
mod ahci;

/// The installed root's boot binary, when a disk carries one. Set while
/// scanning partitions; consumed by the task-spawn step, which boots it
/// INSTEAD of the initrd payload (the pivot).
static mut ROOT_EXE: Option<(*const u8, usize)> = None;
mod apic;
mod ata;
mod cpu;
mod cpio;
mod e1000;
mod ext2;
mod nvme;
mod virtio;
mod elf;
mod net;
mod nt;
mod pe;
mod fbcon;
mod kalloc;
mod kbd;
mod log;
mod logo_data;
mod mm;
mod pci;
mod pio;
mod rand;
mod rtc;
mod syscall;
mod uart;
mod user;

#[cfg(not(target_os = "uefi"))]
mod bios;

/// printk-style console fan-out: every write goes to COM1 and, when the GOP
/// framebuffer is available, to the emulated display as text.
pub(crate) struct Console {
    pub(crate) uart: uart::Uart16550,
    pub(crate) fb: Option<fbcon::FbConsole>,
}

impl core::fmt::Write for Console {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let _ = self.uart.write_str(s);
        if let Some(fb) = self.fb.as_mut() {
            let _ = fb.write_str(s);
        }
        Ok(())
    }
}

/// Exit QEMU through the isa-debug-exit device (`-device isa-debug-exit,
/// iobase=0xf4`): QEMU exits with status `(code << 1) | 1`. Halts forever when
/// the device is absent (real hardware, other firmware).
fn qemu_exit(code: u32) -> ! {
    unsafe {
        core::arch::asm!("out dx, eax", in("dx") 0xf4u16, in("eax") code, options(nomem, nostack));
    }
    loop {
        unsafe { core::arch::asm!("hlt", options(nomem, nostack)) }
    }
}

/// Static slots the boot front ends fill before `rustux_main` — the
/// normalized memory map must outlive the caller's scope.
const MAX_BOOT_ENTS: usize = 512;
static mut BOOT_ENTS: [mm::MapEnt; MAX_BOOT_ENTS] =
    [mm::MapEnt { phys_start: 0, page_count: 0, usable: false }; MAX_BOOT_ENTS];
static mut BOOT_N: usize = 0;

/// Normalize one firmware map record into BOOT_ENTS. Shared by the UEFI
/// and Multiboot2 front ends; entries past the cap are dropped.
pub(crate) fn push_ent(phys_start: u64, page_count: u64, usable: bool) {
    unsafe {
        let n = *core::ptr::addr_of!(BOOT_N);
        if n < MAX_BOOT_ENTS {
            (*core::ptr::addr_of_mut!(BOOT_ENTS))[n] =
                mm::MapEnt { phys_start, page_count, usable };
            *core::ptr::addr_of_mut!(BOOT_N) = n + 1;
        }
    }
}

/// The live prefix of BOOT_ENTS — the normalized map the front end built.
pub(crate) fn boot_map() -> &'static [mm::MapEnt] {
    unsafe {
        core::slice::from_raw_parts(
            core::ptr::addr_of!(BOOT_ENTS) as *const mm::MapEnt,
            *core::ptr::addr_of!(BOOT_N),
        )
    }
}

/// Recursively copy a mounted ext2 directory into the RAM fs — the
/// namespace pivot: after this, fs_lookup resolves the installed
/// files through the normal vfile path, so a pid 1 spawned from this
/// root sees /bin, /etc and the rest of the installed filesystem
/// rather than the initrd's. `path`/`plen` carry the accumulated
/// prefix ("etc", "etc/apt"); `depth`, `budget` and `copied` bound
/// the walk, so a hostile or damaged root cannot exhaust the kernel
/// stack, the vfile table, or the heap.
/// GPT partition walk for one disk whose protective MBR carries
/// 0xEE: validate the header (signature, size, header CRC), bound
/// the entry array inside the disk, verify the entry-array CRC,
/// then fill `parts` by GPT entry index — part number = index+1,
/// so a sparse table keeps Linux's pN numbering. Only indices
/// 1..=15 fit the /dev minor nibble; later entries are skipped.
/// Nothing registers on a bad header or CRC — a malformed table
/// yields no nodes rather than wrong ones.
fn gpt_scan(io: &ext2::DiskIo, total: u64, parts: &mut [(u64, u64, u64); 15]) {
    let mut hdr = [0u8; 512];
    if !ext2::BlockIo::read(io, 512, &mut hdr) {
        crate::log::printk(format_args!("rustux: gpt: lba1 read failed"));
        return;
    }
    if &hdr[..8] != b"EFI PART" {
        crate::log::printk(format_args!(
            "rustux: gpt: bad sig {:02x}{:02x}{:02x}{:02x}",
            hdr[0], hdr[1], hdr[2], hdr[3]));
        return;
    }
    let rd32 = |o: usize| u32::from_le_bytes(hdr[o..o + 4].try_into().unwrap());
    let rd64 = |o: usize| u64::from_le_bytes(hdr[o..o + 8].try_into().unwrap());
    let hsz = rd32(12) as usize;
    if !(92..=512).contains(&hsz) {
        return;
    }
    let want_crc = rd32(16);
    let mut h = [0u8; 512];
    h[..hsz].copy_from_slice(&hdr[..hsz]);
    h[16..20].copy_from_slice(&[0; 4]);
    if !klib::crc::crc32_le(!0, &h[..hsz]) != want_crc {
        crate::log::printk(format_args!(
            "rustux: gpt: hdr crc got={:#x} want={:#x}",
            !klib::crc::crc32_le(!0, &h[..hsz]), want_crc));
        return;
    }
    let elba = rd64(72);
    let nent = rd32(80) as u64;
    let esz = rd32(84) as u64;
    let first_usable = rd64(40);
    let last_usable = rd64(48);
    // Entry size is an architected multiple of 8 >= 128; the array
    // must fit the disk and stay under a chunk-sane region size.
    if !(128..=1024).contains(&esz)
        || !esz.is_multiple_of(8)
        || nent == 0 || nent > 4096
        || elba.checked_mul(512).is_none_or(|b| b >= total)
        || nent.checked_mul(esz).is_none_or(|b| {
            b > (1 << 19)
                || elba
                    .checked_mul(512)
                    .and_then(|e| e.checked_add(b))
                    .is_none_or(|t| t > total)
        })
        // The usable range itself must be sane: entries claiming
        // first==0 (the MBR) or past the disk get rejected below,
        // but only if these fields mean anything.
        || first_usable == 0
        || last_usable < first_usable
        || last_usable
            .checked_add(1)
            .is_none_or(|l| l > total / 512)
    {
        return;
    }
    // Stream the array sector-at-a-time: accumulate the CRC and
    // parse each fully-contained entry in the same pass. A bad CRC
    // clears everything — parts are only committed on a verified
    // table.
    let ebytes = nent * esz;
    let escrc = rd32(88);
    let mut crc = !0u32;
    let mut off = 0u64;
    let mut sec = [0u8; 512];
    let mut registered = 0u32;
    let mut io_ok = true;
    while off < ebytes {
        if !ext2::BlockIo::read(io, elba * 512 + off, &mut sec) {
            io_ok = false;
            break;
        }
        let take = (ebytes - off).min(512) as usize;
        crc = klib::crc::crc32_le(crc, &sec[..take]);
        // Entries fully inside this chunk: entry i sits at i*esz
        // from the array start.
        let mut i = off.div_ceil(esz);
        while i < nent && i * esz + esz <= off + take as u64 {
            let ein = (i * esz - off) as usize;
            let e = &sec[ein..ein + esz as usize];
            if !e[..16].iter().all(|b| *b == 0) {
                let first =
                    u64::from_le_bytes(e[32..40].try_into().unwrap());
                let last =
                    u64::from_le_bytes(e[40..48].try_into().unwrap());
                // Within the usable range AND the disk — a lying
                // entry can't reach past either bound.
                if last >= first
                    && first >= first_usable
                    && last <= last_usable
                    && !last
                        .checked_add(1)
                        .is_none_or(|l| l > total / 512)
                {
                    let pidx = i + 1;
                    if pidx <= 15 {
                        parts[(pidx - 1) as usize] = (
                            first,
                            last - first + 1,
                            u32::from_le_bytes(e[0..4].try_into().unwrap())
                                as u64,
                        );
                        registered += 1;
                    }
                }
            }
            i += 1;
        }
        off += take as u64;
    }
    if !io_ok || !crc != escrc {
        parts.fill((0, 0, 0));
        crate::log::printk(format_args!(
            "rustux: gpt: entry-array CRC mismatch — table rejected"
        ));
        return;
    }
    if registered > 0 {
        crate::log::printk(format_args!(
            "rustux: gpt: {registered} partition(s) registered ({nent} entries)"
        ));
    }
}

fn copy_root_dir(
    io: &dyn ext2::BlockIo,
    sb: &ext2::Super,
    dir_ino: u32,
    path: &mut [u8; 128],
    plen: usize,
    depth: u32,
    copied: &mut u32,
    budget: &mut u64,
    seen: &mut [u32; 1024],
    nseen: &mut u32,
) {
    const MAX_COPIED: u32 = 512;
    const MAX_FILE: u64 = 32 << 20;
    const MAX_DEPTH: u32 = 8;
    if *copied >= MAX_COPIED || depth >= MAX_DEPTH {
        return;
    }
    // dir_walk reads each block into its own stack buffer before the
    // callback runs and hands over a Dirent copy — recursing inside
    // the callback does not re-enter a live read, and the sequential
    // PIO reads cannot interleave.
    let _ = ext2::dir_walk(io, sb, dir_ino, |e| {
        if *copied >= MAX_COPIED {
            return false;
        }
        let n = e.name_len as usize;
        let dot = n == 1 && e.name[0] == b'.';
        let ddot = n == 2 && e.name[0] == b'.' && e.name[1] == b'.';
        let sep = usize::from(plen > 0);
        if dot || ddot || n > 96 || plen + sep + n > path.len() {
            return true;
        }
        let mut end = plen;
        if sep == 1 {
            path[end] = b'/';
            end += 1;
        }
        path[end..end + n].copy_from_slice(&e.name[..n]);
        end += n;
        let Some(node) = ext2::inode(io, sb, e.ino) else {
            return true;
        };
        if node.is_dir() {
            // Mint a real dir, not just a name prefix — an implicit
            // dir rejects chmod/mkdir with EROFS, which is what made
            // apt's partial-dir setup warn on the installed system.
            user::root_copy_dir(&path[..end], node.mode);
            copy_root_dir(io, sb, e.ino, path, end, depth + 1, copied,
                          budget, seen, nseen);
        } else if node.is_file() {
            // Hardlinked dirents (busybox applets) share one inode —
            // copy it once; the archive underlay resolves the rest.
            if seen[..*nseen as usize].contains(&e.ino) {
                return true;
            }
            let sz = node.size as u64;
            if sz != 0 && sz <= *budget && sz <= MAX_FILE {
                let buf = crate::kalloc::kmalloc(sz as usize);
                if !buf.is_null() {
                    // SAFETY: kmalloc returned sz bytes.
                    let dst = unsafe {
                        core::slice::from_raw_parts_mut(buf, sz as usize)
                    };
                    let ok = ext2::read_file(io, sb, e.ino, dst)
                        .is_some_and(|got| got == sz as usize)
                        && user::root_copy_up(&path[..end], dst);
                    // SAFETY: root_copy_up keeps its own copy; the
                    // staging buffer is ours to release.
                    unsafe { crate::kalloc::kfree(buf) };
                    if ok {
                        *copied += 1;
                        *budget -= sz;
                        if (*nseen as usize) < seen.len() {
                            seen[*nseen as usize] = e.ino;
                            *nseen += 1;
                        }
                    }
                }
            }
        }
        *copied < MAX_COPIED
    });
}

#[cfg(target_os = "uefi")]
#[entry]
fn main() -> Status {
    let mut con = Console {
        uart: unsafe { uart::Uart16550::new(uart::COM1) },
        fb: fbcon::FbConsole::new(),
    };
    con.uart.init();
    if let Some(fb) = con.fb.as_mut() {
        fb.splash();
        fb.banner();
    }
    // printk ring up before the first line; the panic path gets the live
    // console so a fault still reaches the screen.
    log::init();
    log::set_console(&mut con);
    kprintln!(con, "rustux: Rust kernel alive under UEFI");

    // The ACPI RSDP pointer lives in the UEFI system table — boot-time
    // only. Snapshot it now; the tables themselves stay readable post-EBS.
    match acpi::grab_rsdp() {
        Some(p) => {
            kprintln!(con, "rustux: acpi: RSDP at {:#x} (from UEFI config table)", p);
        }
        None => {
            kprintln!(con, "rustux: acpi: no RSDP in UEFI config table");
        }
    }

    // Load the initrd from the ESP while boot services are still
    // legal — \initrd.cpio sits next to BOOTX64.EFI. The pages come
    // back as LOADER_DATA, which our buddy deliberately does not
    // claim, so the buffer survives EBS under the identity map.
    let (initrd, initrd_verify) = load_initrd();
    match initrd {
        Some((a, l)) => kprintln!(con, "rustux: initrd: {l}B at {a:#x}"),
        None => kprintln!(con, "rustux: initrd: none found"),
    }
    match initrd_verify {
        InitrdVerify::NoSidecar => {}
        InitrdVerify::Ok(c) => {
            kprintln!(con, "rustux: initrd crc32 = {c:#x} (verified vs initrd.crc)")
        }
        InitrdVerify::Bad { want, got } => kprintln!(
            con,
            "rustux: initrd CORRUPT — crc {got:#x} != initrd.crc {want:#x} (still bad after re-read)"
        ),
    }

    // The loaded image keeps its identity PTEs under every cr3 —
    // instruction fetch, statics, IDT/GDT/TSS all resolve at the
    // image VMA — so compat user pages may never shadow that phys
    // span. Snapshot it while the protocol is still legal.
    if let Ok(img) = uefi::boot::open_protocol_exclusive::<
        uefi::proto::loaded_image::LoadedImage,
    >(uefi::boot::image_handle())
    {
        let (base, size) = img.info();
        user::reserve_kernel_span(base as u64, base as u64 + size);
    }

    kprintln!(con, "rustux: exiting boot services...");
    // SAFETY: every firmware call this program makes happens before this
    // point; nothing afterwards touches boot or runtime services.
    let mmap = unsafe { uefi::boot::exit_boot_services(None) };
    for d in mmap.entries() {
        push_ent(d.phys_start, d.page_count, d.ty == MemoryType::CONVENTIONAL);
    }
    rustux_main(con, boot_map(), initrd, &[])
}

/// Firmware-agnostic kernel main: each boot front end (UEFI `main`,
/// Multiboot2 `bios::entry`) collects its map/framebuffer/RSDP/initrd,
/// then lands here. `con` moves in by value and is re-registered with the
/// panic path — the caller's frame stays live forever since we diverge.
pub(crate) fn rustux_main(
    mut con: Console,
    mmap: &'static [mm::MapEnt],
    initrd: Option<(u64, usize)>,
    extra_reserved: &[(u64, u64)],
) -> ! {
    log::set_console(&mut con);
    kprintln!(con, "rustux: serial console up on COM1");
    // rustux_main runs on the boot stack for the kernel's whole
    // lifetime — reserve its containing 2 MiB identity region so a
    // compat task's user page can never shadow it. rsp is a linear
    // address that equals its phys under the identity map.
    let boot_rsp: u64;
    unsafe { core::arch::asm!("mov {}, rsp", out(reg) boot_rsp, options(nomem, nostack)) };
    user::reserve_kernel_span(
        boot_rsp & !(2 * 1024 * 1024 - 1),
        (boot_rsp & !(2 * 1024 * 1024 - 1)) + 2 * 1024 * 1024,
    );
    let rng_hw = rand::init();
    kprintln!(con,
        "rustux: rand: CSPRNG seeded ({})",
        if rng_hw { "rdrand" } else { "rdtsc fallback, weak seed" }
    );
    kprintln!(con,
        "rustux: klib::math::int_sqrt(1<<40) = {} (verified port of lib/math/int_sqrt.c)",
        klib::math::int_sqrt(1 << 40)
    );
    kprintln!(con,
        "rustux: klib::math::gcd(1071,462) = {} (verified port of lib/math/gcd.c)",
        klib::math::gcd(1071, 462)
    );
    kprintln!(con,
        "rustux: klib::math::lcm(21,6) = {} (verified port of lib/math/lcm.c)",
        klib::math::lcm(21, 6)
    );
    kprintln!(con,
        "rustux: klib::math::int_pow(7,13) = {} (verified port of lib/math/int_pow.c)",
        klib::math::int_pow(7, 13)
    );
    kprintln!(con,
        "rustux: klib::math::intlog10(255) = {} (verified port of lib/math/int_log.c)",
        klib::math::intlog10(255)
    );
    kprintln!(con,
        "rustux: klib::math::mul_u64_add_u64_div_u64(2^63,2^63,0,2^63) = {} (verified port of lib/math/div64.c)",
        klib::math::mul_u64_add_u64_div_u64(1 << 63, 1 << 63, 0, 1 << 63)
    );
    let (rn, rd) = klib::math::rational_best_approximation(31415, 10000, 255, 31);
    kprintln!(con,
        "rustux: klib::math::rational_best_approximation(3.1415) = {rn}/{rd} (verified port of lib/math/rational.c)"
    );
    let rv = klib::math::reciprocal_value(7);
    kprintln!(con,
        "rustux: klib::math::reciprocal_value(7) = {:#x},{},{} (verified port of lib/math/reciprocal_div.c)",
        rv.m, rv.sh1, rv.sh2
    );
    let iq = klib::math::cordic_calc_iq(45);
    kprintln!(con,
        "rustux: klib::math::cordic_calc_iq(45) = {},{} (verified port of lib/math/cordic.c)",
        iq.i, iq.q
    );
    let terms = [
        klib::math::PolynomialTerm {
            deg: 2,
            coef: 1,
            divider: 1,
            divider_leftover: 1,
        },
        klib::math::PolynomialTerm {
            deg: 1,
            coef: 2,
            divider: 1,
            divider_leftover: 1,
        },
        klib::math::PolynomialTerm {
            deg: 0,
            coef: 3,
            divider: 1,
            divider_leftover: 1,
        },
    ];
    kprintln!(con,
        "rustux: klib::math::polynomial_calc(x^2+2x+3, x=4) = {} (verified port of lib/math/polynomial.c)",
        klib::math::polynomial_calc(&terms, 1, 4)
    );
    kprintln!(con,
        "rustux: klib::math::is_prime_number(7919) = {}, next_prime_number(65535) = {} (verified port of lib/math/prime_numbers.c)",
        klib::math::is_prime_number(7919),
        klib::math::next_prime_number(65535)
    );
    kprintln!(con,
        "rustux: klib::bcd::bcd2bin(0x45) = {}, bin2bcd(45) = {:#x} (verified port of lib/bcd.c)",
        klib::bcd::bcd2bin(0x45),
        klib::bcd::bin2bcd(45)
    );
    let mut arr = [9u32, 4, 7, 1, 8, 2, 6, 3, 5, 0];
    klib::sort::sort(&mut arr, |x, y| i32::from(x > y) - i32::from(x < y));
    kprintln!(con,
        "rustux: klib::sort::sort([9,4,7,1,8,2,6,3,5,0]) = {:?} (verified port of lib/sort.c)",
        arr
    );
    const L: usize = 8;
    let keys = [9u32, 4, 7, 1, 8, 2, 6, 3];
    let mut links = [klib::list_sort::Links::new(0, 0); L + 1];
    for (i, l) in links.iter_mut().take(L).enumerate() {
        l.next = i + 1;
        l.prev = if i == 0 { L } else { i - 1 };
    }
    links[L - 1].next = L;
    links[L] = klib::list_sort::Links::new(0, L - 1);
    {
        let mut cmp =
            |a: usize, b: usize| i32::from(keys[a] > keys[b]) - i32::from(keys[a] < keys[b]);
        klib::list_sort::list_sort(&mut links, L, &mut cmp);
    }
    let first = keys[links[L].next];
    let last = keys[links[L].prev];
    kprintln!(con,
        "rustux: klib::list_sort::list_sort({:?}) first={} last={} (verified port of lib/list_sort.c)",
        keys, first, last
    );
    kprintln!(con,
        "rustux: klib::crc::crc32_le(0,\"123456789\") = {:#x}, crc16(0,...) = {:#x}, crc4(0,0x12345678,32) = {:#x} (verified ports of lib/crc/)",
        klib::crc::crc32_le(0, b"123456789"),
        klib::crc::crc16(0, b"123456789"),
        klib::crc::crc4(0, 0x12345678, 32)
    );
    kprintln!(con,
        "rustux: klib::hash::siphash_1u64(0xdeadbeef,k) = {:#x}, xxh64(\"123456789\",0) = {:#x}, jhash_1word(1,0) = {:#x} (verified ports of siphash.c/xxhash.c/jhash.h)",
        klib::hash::siphash_1u64(0xdeadbeef, (0x0706050403020100, 0x0f0e0d0c0b0a0908)),
        klib::hash::xxh64(b"123456789", 0),
        klib::hash::jhash_1word(1, 0)
    );

    let mut bm = [0u64; 2];
    klib::bitmap::bitmap_set(&mut bm, 62, 10);
    let free = klib::bitmap::bitmap_find_free_region(&mut bm, 128, 2);
    kprintln!(con,
        "rustux: klib::bitmap: set(62..72) -> first={} free_region(4)={} weight_after_alloc={} (verified ports of find_bit.c/bitmap.c)",
        klib::bitmap::find_first_bit(&bm, 128),
        free,
        klib::bitmap::bitmap_weight(&bm, 128)
    );

    {
        use klib::rbtree::*;
        const RT: usize = 8;
        let mut nodes = [RbNode::new(); RT];
        let rk = [5u64, 3, 8, 1, 4, 7, 9, 2];
        let mut root = RbRoot::EMPTY;
        for (i, &k) in rk.iter().enumerate() {
            let mut link = Link::Root;
            let mut parent = NIL;
            let mut cur = root.rb_node;
            while cur != NIL {
                parent = cur;
                if k < rk[cur] {
                    link = Link::Left(cur);
                    cur = nodes[cur].left;
                } else {
                    link = Link::Right(cur);
                    cur = nodes[cur].right;
                }
            }
            rb_link_node(&mut nodes, i, parent, link, &mut root);
            rb_insert_color(&mut nodes, i, &mut root);
        }
        // in-order traversal should visit keys 1..9 sorted
        let mut inorder = 0u64;
        let mut i = rb_first(&nodes, &root);
        while i != NIL {
            inorder = inorder * 10 + rk[i];
            i = rb_next(&nodes, i);
        }
        // erase the middle node and verify traversal still sorted
        rb_erase(&mut nodes, 4, &mut root); // node index 4 has key 4
        let mut inorder2 = 0u64;
        let mut i = rb_first(&nodes, &root);
        while i != NIL {
            inorder2 = inorder2 * 10 + rk[i];
            i = rb_next(&nodes, i);
        }
        // ascending inserts force __rb_insert's rotation cases
        let mut n2 = [RbNode::new(); RT];
        let mut root2 = RbRoot::EMPTY;
        for i in 0..RT {
            let mut link = Link::Root;
            let mut parent = NIL;
            let mut cur = root2.rb_node;
            while cur != NIL {
                parent = cur;
                link = Link::Right(cur);
                cur = n2[cur].right;
            }
            rb_link_node(&mut n2, i, parent, link, &mut root2);
            rb_insert_color(&mut n2, i, &mut root2);
        }
        let mut h = 0usize;
        let mut i = rb_first(&n2, &root2);
        while i != NIL {
            h += 1;
            i = rb_next(&n2, i);
        }
        kprintln!(con,
            "rustux: klib::rbtree: insert(5,3,8,1,4,7,9,2) inorder={} erase(4)={} asc(1..8)->{}nodes (verified port of lib/rbtree.c)",
            inorder, inorder2, h
        );
        assert_eq!(inorder, 12345789);
        assert_eq!(inorder2, 1235789);
        assert_eq!(h, 8);
    }

    {
        use klib::string::*;
        let mut dst = [0u8; 16];
        let copied = sized_strscpy(&mut dst, b"rustux\0", 16);
        let hay = b"the quick brown fox\0";
        kprintln!(con,
            "rustux: klib::string: strscpy={} strstr(fox)={:?} memchr_inv={:?} strcasecmp={} (verified port of lib/string.c)",
            copied,
            strstr(hay, b"fox\0"),
            memchr_inv(b"aaaab", b'a', 5),
            strcasecmp(b"ReSeT\0", b"reset\0")
        );
        assert_eq!(copied, 6);
        assert_eq!(strstr(hay, b"fox\0"), Some(16));
        assert_eq!(memchr_inv(b"aaaab", b'a', 5), Some(4));
        assert_eq!(strcasecmp(b"ReSeT\0", b"reset\0"), 0);
    }

    {
        use klib::sha::*;
        let mut d = [0u8; 32];
        sha256(b"abc", 3, &mut d);
        let mut ctx = Sha1Ctx::default();
        sha1_init(&mut ctx);
        sha1_update(&mut ctx, b"a", 1);
        sha1_update(&mut ctx, b"bc", 2);
        let mut d1 = [0u8; 20];
        sha1_final(&mut ctx, &mut d1);
        let mut hkey = HmacSha256Key::default();
        hmac_sha256_preparekey(&mut hkey, b"Jefe", 4);
        let mut hm = [0u8; 32];
        hmac_sha256(&hkey, b"what do ya want for nothing?", 28, &mut hm);
        kprintln!(con,
            "rustux: klib::sha: sha256(abc)={:02x}{:02x}..{:02x}{:02x} sha1(a+bc)={:02x}{:02x}.. hmac={:02x}{:02x}.. (verified port of lib/crypto/sha*.c)",
            d[0], d[1], d[30], d[31], d1[0], d1[1], hm[0], hm[1]
        );
        assert_eq!(
            d,
            [
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
                0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
                0xf2, 0x00, 0x15, 0xad
            ]
        );
        assert_eq!(
            d1,
            [
                0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e, 0x25, 0x71, 0x78, 0x50,
                0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d
            ]
        );
        assert_eq!(hm[..4], [0x5b, 0xdc, 0xc1, 0x46]);
    }

    {
        use klib::kfifo::*;
        let mut buf = [0u8; 8];
        let mut f = Kfifo::init(&mut buf, 1).unwrap();
        let n = kfifo_in(&mut f, b"abcdef", 6);
        let mut out = [0u8; 8];
        kfifo_out(&mut f, &mut out, 4);
        kfifo_in(&mut f, b"ghij", 4); // wraps the ring
        let mut all = [0u8; 8];
        let got = kfifo_out(&mut f, &mut all, 8);
        kprintln!(con,
            "rustux: klib::kfifo: in={} wrap-drain={} -> {:?} (verified port of lib/kfifo.c)",
            n,
            got,
            &all[..8]
        );
        assert_eq!(&all[..6], b"efghij");
    }

    {
        use klib::llist::*;
        let mut head = LlistHead::new();
        let mut next = [NIL; 8];
        for i in 0..3 {
            init_llist_node(&mut next, i);
            llist_add(&mut head, &mut next, i);
        }
        let a = llist_del_first(&mut head, &mut next); // 2 (LIFO)
        let chain = llist_del_all(&mut head); // 1 -> 0
        let rev = llist_reverse_order(&mut next, chain); // 0 -> 1
        kprintln!(con,
            "rustux: klib::llist: pop={} chain={} rev-head={} (verified port of lib/llist.c)",
            a, chain, rev
        );
        assert_eq!((a, chain, rev), (2, 1, 0));
        assert_eq!(next[0], 1);
        assert_eq!(next[1], NIL);
    }

    {
        use klib::fmt::Arg;
        use klib::seqbuf::*;
        let mut buf = [0u8; 64];
        let mut s = SeqBuf::new(&mut buf);
        s.puts(b"boot\0");
        s.printf(b"=%d", &[Arg::I(33)]);
        kprintln!(con,
            "rustux: klib::seqbuf: puts+printf -> {:?} (verified port of lib/seq_buf.c)",
            s.as_slice()
        );
        assert_eq!(s.as_slice(), b"boot=33");
        assert_eq!(s.pop(), b'3' as i64);
        let mut lb = [0u8; 131];
        let n = hex_dump_to_buffer(&[0xde, 0xad], 2, 16, 1, &mut lb, false);
        assert_eq!(&lb[..n as usize], b"de ad");
    }

    {
        use klib::rhashtable::*;
        /* 8 tobj slots (48 cells each) + arena for the 64-bucket table
         * plus walker cells at the tail. */
        let mut mem = [0u64; 8 * 48 + 2048 + 64];
        let mut t = Rhashtable::new(&mut mem, 8 * 48);
        let p = Params {
            key_len: 8,
            key_offset: 24,
            head_offset: 8,
            ..Default::default()
        };
        assert_eq!(t.rhashtable_init(&p, false), 0);
        for i in 0..4usize {
            let o = Rhashtable::obj(i);
            t.mem_w(o + 24, (i as u64 + 1) * 7);
            assert_eq!(t.rhashtable_insert_fast(o + 8), 0);
        }
        let hit = t.rhashtable_lookup(Rhashtable::obj(2) + 24);
        let miss = t.rhashtable_lookup(Rhashtable::obj(5) + 24); /* key cell = 0 */
        let rm = t.rhashtable_remove_fast(Rhashtable::obj(2) + 8);
        kprintln!(con,
            "rustux: klib::rhashtable: hit={} miss={} rm={} nelems={} (verified port of lib/rhashtable.c)",
            hit,
            miss,
            rm,
            t.nelems()
        );
        assert_eq!(hit, Rhashtable::obj(2));
        assert_eq!(miss, 0);
        assert_eq!(rm, 0);
        assert_eq!(t.nelems(), 3);
        t.destroy();
    }

    {
        use klib::xarray::*;
        let mut nodes = [const { Node::new() }; 32];
        let mut xa = Xarray::new(&mut nodes, 0);
        xa.xa_store(1, 0x1000);
        xa.xa_store(100, 0x1010);
        xa.xa_store(1 << 16, 0x1020);
        let mut idx = 0;
        let f0 = xa.xa_find(&mut idx, u64::MAX, XA_PRESENT);
        let l100 = xa.xa_load(100);
        let deep = xa.xa_load(1 << 16);
        kprintln!(con,
            "rustux: klib::xarray: find={} idx={} l100={} deep={} (verified port of lib/xarray.c)",
            f0,
            idx,
            l100,
            deep
        );
        assert_eq!(f0, 0x1000);
        assert_eq!(idx, 1);
        assert_eq!(l100, 0x1010);
        assert_eq!(deep, 0x1020);
        xa.xa_destroy();
    }

    {
        use klib::radix_tree::*;
        let mut nodes = [const { klib::xarray::Node::new() }; 32];
        let mut rt = RadixTree::new(&mut nodes, GFP_KERNEL);
        rt.radix_tree_insert(3, 0x1000);
        rt.radix_tree_insert(1 << 14, 0x1010);
        rt.radix_tree_tag_set(1 << 14, 1);
        let l3 = rt.radix_tree_lookup(3);
        let deep = rt.radix_tree_lookup(1 << 14);
        let mut out = [0u64; 4];
        let gang = rt.radix_tree_gang_lookup_tag(&mut out, 0, 1);
        let del = rt.radix_tree_delete(3);
        kprintln!(con,
            "rustux: klib::radix_tree: l3={} deep={} gang={} del={} (verified port of lib/radix-tree.c)",
            l3,
            deep,
            gang,
            del
        );
        assert_eq!(l3, 0x1000);
        assert_eq!(deep, 0x1010);
        assert_eq!(gang, 1);
        assert_eq!(out[0], 0x1010);
        assert_eq!(del, 0x1000);
    }

    {
        use klib::idr::*;
        let mut nodes = [const { klib::xarray::Node::new() }; 32];
        let mut idr = Idr::new(&mut nodes);
        let a = idr.idr_alloc(0x2000, 0, 0, GFP_KERNEL);
        let b = idr.idr_alloc(0x2010, 0, 0, GFP_KERNEL);
        let f = idr.idr_find(b as u64);
        idr.idr_remove(a as u64);
        let c = idr.idr_alloc(0x2020, 0, 0, GFP_KERNEL);
        kprintln!(con,
            "rustux: klib::idr: a={} b={} f={} c={} (verified port of lib/idr.c)",
            a,
            b,
            f,
            c
        );
        assert_eq!(a, 0);
        assert_eq!(b, 1);
        assert_eq!(f, 0x2010);
        assert_eq!(c, 0);
    }

    {
        use klib::maple_tree::*;
        let mut nodes = [const { Node::new() }; 64];
        let mut sheafs = [const { Sheaf::new() }; 8];
        let mut mt = MapleTree::new(&mut nodes, &mut sheafs, 0);
        mt.mtree_store(MT_CANON, 5, 0x3000, GFP_KERNEL);
        mt.mtree_store_range(MT_CANON, 100, 109, 0x3010, GFP_KERNEL);
        mt.mtree_store(MT_CANON, 900, 0x3020, GFP_KERNEL);
        let l5 = mt.mtree_load(MT_CANON, 5);
        let l105 = mt.mtree_load(MT_CANON, 105);
        let nxt = mt.mt_next(MT_CANON, 5, u64::MAX);
        kprintln!(con,
            "rustux: klib::maple_tree: l5={} l105={} next={} (verified port of lib/maple_tree.c)",
            l5,
            l105,
            nxt
        );
        assert_eq!(l5, 0x3000);
        assert_eq!(l105, 0x3010);
        assert_eq!(nxt, 0x3010);
    }

    {
        use klib::genradix::*;
        let mut arena = [const { GNode::zeroed() }; 8];
        let mut alloc = GAlloc::new(&mut arena);
        let mut g = Genradix::new();
        // obj_size 8: 64 objects per leaf page; idx 100 grows the tree to
        // depth 1, idx 4096 to depth 2 (6 nodes total).
        let s = genradix_ptr_alloc(&mut g, &mut alloc, 3, &mut None, 8).unwrap();
        slot_u64_set(&mut alloc, s, 0x1111);
        let s = genradix_ptr_alloc(&mut g, &mut alloc, 100, &mut None, 8).unwrap();
        slot_u64_set(&mut alloc, s, 0x3333);
        let s = genradix_ptr_alloc(&mut g, &mut alloc, 4096, &mut None, 8).unwrap();
        slot_u64_set(&mut alloc, s, 0x2222);
        let l3 = genradix_ptr(&g, &alloc, 3, 8)
            .map(|s| slot_u64(&alloc, s))
            .unwrap_or(0);
        let ldeep = genradix_ptr(&g, &alloc, 4096, 8)
            .map(|s| slot_u64(&alloc, s))
            .unwrap_or(0);
        let miss = genradix_ptr(&g, &alloc, 8192, 8).is_none();
        // Iteration visits every object slot of every allocated leaf
        // page: pages 0, 1 and 64 -> 3 * 64 positions.
        let objs_per_page = GENRADIX_NODE_SIZE / 8;
        let mut it = genradix_iter_init(0, 8);
        let mut cnt = 0u64;
        while genradix_iter_peek(&mut it, &g, &alloc, objs_per_page).is_some() {
            cnt += 1;
            genradix_iter_advance(&mut it, 8);
        }
        genradix_free(&mut g, &mut alloc);
        let reused = alloc.alloc_node().is_some();
        kprintln!(con,
            "rustux: klib::genradix: l3={:#x} deep={:#x} miss={} iter={} reuse={} (verified port of lib/generic-radix-tree.c)",
            l3,
            ldeep,
            miss,
            cnt,
            reused
        );
        assert_eq!(l3, 0x1111);
        assert_eq!(ldeep, 0x2222);
        assert!(miss);
        assert_eq!(cnt, 192);
        assert!(reused);
    }

    {
        use klib::interval_tree::*;
        use klib::rbtree::{NIL, RbNode, RbRootCached};
        let mut nodes = [RbNode::new(); 6];
        let (mut start, mut last, mut sub) = ([0u64; 6], [0u64; 6], [0u64; 6]);
        let mut ctx = ItData {
            start: &mut start,
            last: &mut last,
            sub: &mut sub,
        };
        let mut root = RbRootCached::EMPTY;
        let spans = [(5u64, 10u64), (15, 20), (7, 9), (0, 3), (12, 18)];
        for (i, &(s, l)) in spans.iter().enumerate() {
            ctx.start[i] = s;
            ctx.last[i] = l;
            interval_tree_insert(&mut nodes, &mut ctx, i, &mut root);
        }
        // Query [8,16] hits nodes 0,2,4,1 in non-decreasing start order.
        let mut cnt = 0u64;
        let mut i = interval_tree_iter_first(&nodes, &ctx, &root, 8, 16);
        while i != NIL {
            cnt += 1;
            i = interval_tree_iter_next(&nodes, &ctx, i, 8, 16);
        }
        // Remove (5,10): [5,10]'s first remaining hit is (7,9) = node 2;
        // the augmented root keeps subtree_last = max last = 20.
        interval_tree_remove(&mut nodes, &mut ctx, 0, &mut root);
        let first = interval_tree_iter_first(&nodes, &ctx, &root, 5, 10);
        let subroot = ctx.sub[root.root.rb_node];
        kprintln!(con,
            "rustux: klib::interval_tree: q[8,16]={}hits rm(0)->first={} subroot={} (verified port of lib/interval_tree.c)",
            cnt,
            first,
            subroot
        );
        assert_eq!(cnt, 4);
        assert_eq!(first, 2);
        assert_eq!(subroot, 20);
    }

    {
        use klib::assoc_array::*;
        let mut nodes = [NODE0; 32];
        let mut shorts = [SC0; 16];
        let mut edits = [EDIT0; 4];
        let mut okey = [[0u64; KW]; 24];
        let mut orefs = [0i64; 24];
        let mut aa = AssocArray::new(&mut nodes, &mut shorts, &mut edits, &mut okey, &mut orefs);
        // Insert three keys (the third forces a node split), apply each
        // edit script, then find/iterate/delete through the port.
        let keys: [TKey; 3] = [[0x1111, 0], [0x2222, 0], [0xabc333, 1]];
        for (i, &k) in keys.iter().enumerate() {
            aa.okey[i] = k;
            aa.orefs[i] = 1;
            let e = assoc_array_insert(&mut aa, &k, leaf_to_ptr(i));
            if !is_err(e) {
                assoc_array_apply_edit(&mut aa, edit_i(e));
            }
        }
        let hit = assoc_array_find(&mut aa, &[0x2222, 0]);
        let mut cnt = 0u64;
        let _ = assoc_array_iterate(
            &mut aa,
            &mut |_r: &mut AssocArray, c: &mut u64, _l: u64| -> i32 {
                *c += 1;
                0
            },
            &mut cnt,
        );
        let e = assoc_array_delete(&mut aa, &[0x1111, 0]);
        if e != 0 && !is_err(e) {
            assoc_array_apply_edit(&mut aa, edit_i(e));
        }
        let after_del = aa.nr_leaves_on_tree;
        assoc_array_destroy(&mut aa);
        kprintln!(con,
            "rustux: klib::assoc_array: find={:#x} iter={} del->leaves={} root={} (verified port of lib/assoc_array.c)",
            hit, cnt, after_del, aa.root
        );
        assert_eq!(hit, leaf_to_ptr(1));
        assert_eq!(cnt, 3);
        assert_eq!(after_del, 2);
        assert_eq!(aa.root, 0);
    }

    {
        use klib::{kstrtox, seqbuf, string, string_helpers};
        let v = kstrtox::kstrtoull(b"0xdeadbeef\0", 0).unwrap();
        let e = kstrtox::kstrtouint(b"4294967296\0", 10).unwrap_err();
        let b = kstrtox::kstrtobool(Some(b"on\0")).unwrap();
        let mut lb = [0u8; 131];
        let n = seqbuf::hex_dump_to_buffer(&[0x11, 0x22], 2, 16, 2, &mut lb, false);
        let m = string::match_string(&[Some(b"one\0"), Some(b"two\0"), None], 3, b"two\0");
        let mut esb = [0u8; 64];
        let e2 = string_helpers::string_escape_str_any_np(b"a\n\x7f\0", &mut esb, None);
        let mut szb = [0u8; 32];
        let s2 = string_helpers::string_get_size(1, 1500, string_helpers::STRING_UNITS_2, &mut szb, 32);
        kprintln!(con,
            "rustux: klib::kstrtox+string_helpers: u64={:#x} err={} bool={} hex={} match={} esc={:?} size={:?} (verified ports of lib/kstrtox.c lib/hexdump.c lib/string_helpers.c)",
            v, e, b, n, m,
            core::str::from_utf8(&esb[..e2]).unwrap_or("?"),
            core::str::from_utf8(&szb[..s2 as usize]).unwrap_or("?"),
        );
        assert_eq!(v, 0xdeadbeef);
        assert_eq!(e, -34); // -ERANGE
        assert!(b);
        assert_eq!(n, 4); // "2211": LE u16 group of [0x11, 0x22]
        assert_eq!(m, 1);
        assert_eq!(&esb[..e2], b"a\\n\\177");
        assert_eq!(&szb[..s2 as usize], b"1.46 KiB");
    }

    {
        use klib::percpu_counter::PercpuCounter;
        let mut lanes = [0i64; 4];
        let mut c = PercpuCounter::new();
        c.init(&mut lanes, 10);
        c.cpu = 0;
        c.add(3);
        let sum = c.sum();
        kprintln!(con,
            "rustux: klib::percpu_counter: sum={} (verified port of lib/percpu_counter.c)",
            sum
        );
        assert_eq!(sum, 13);
    }

    {
        use klib::prb::*;
        let mut text = [0u8; 64];
        let mut descs = [PrbDesc::default(); 4];
        let mut infos = [PrintkInfo::default(); 4];
        let mut prb = Prb::new(&mut text, 6, &mut descs, 2, &mut infos);
        let mut e = PrbReservedEntry::default();
        let mut r = PrintkRecord::wr(5);
        let ok = prb.reserve(&mut e, &mut r);
        if let Some(buf) = prb.text_buf_mut(&r) {
            buf[..5].copy_from_slice(b"hello");
        }
        if let Some(info) = prb.info_mut(&r) {
            info.text_len = 5;
        }
        prb.final_commit(&e);
        let mut ri = PrintkInfo::default();
        let mut rbuf = [0u8; 64];
        let rd = prb.read_valid(0, Some(&mut ri), Some(&mut rbuf));
        kprintln!(con,
            "rustux: klib::prb: reserve={} read={} len={} (verified port of kernel/printk/printk_ringbuffer.c)",
            ok,
            rd,
            ri.text_len
        );
        assert!(ok && rd && ri.text_len == 5);
        assert_eq!(&rbuf[..5], b"hello");
    }

    // Own the CPU state the firmware still lent us. Under UEFI this ran
    // after ExitBootServices for the same reason it runs first here:
    // firmware can reload GDTR/IDTR and raise interrupts internally, and a
    // stray IRQ vectoring through our IDT whose selector doesn't exist in
    // a firmware GDT would triple-fault the boot.
    cpu::init();
    kprintln!(con, "rustux: cpu: own GDT+IDT active");
    let (mut n, mut conv, mut reserved_pages, mut largest) =
        (0usize, 0u64, 0u64, (0u64, 0u64));
    for d in mmap {
        n += 1;
        if d.usable {
            conv += d.page_count;
            if d.page_count > largest.1 {
                largest = (d.phys_start, d.page_count);
            }
        } else {
            reserved_pages += d.page_count;
        }
        kprintln!(con,
            "rustux:   map {:#010x}..{:#010x} {}",
            d.phys_start,
            d.phys_start + d.page_count * 4096,
            if d.usable { "usable" } else { "rsv" }
        );
    }
    kprintln!(con,
        "rustux: memory map: {} entries, {} MiB usable, {} KiB reserved",
        n,
        conv / 256,
        reserved_pages * 4
    );
    kprintln!(con,
        "rustux: largest free region {:#010x}..{:#010x} ({} MiB)",
        largest.0,
        largest.0 + largest.1 * 4096,
        largest.1 / 256
    );

    // Own page tables: carve table frames from the TAIL of the largest
    // usable region, build a 4-level identity map, switch CR3. Tail —
    // not head: under BIOS the kernel image sits at the head of this
    // very region (1 MiB), so a head carve would zero the executing
    // text mid-write. The carve stays reserved either way.
    let ngib = mm::map_gib(mmap);
    let tframes = mm::table_frames(ngib);
    // Keep the carve below 4 GiB: the BIOS trampoline's provisional map
    // only covers 4 GiB, and these writes go through the CURRENT map.
    let region_end = largest.0 + largest.1 * mm::PAGE;
    let carve_hi = region_end.min(4 << 30);
    let mut carve = carve_hi.saturating_sub(tframes * mm::PAGE) & !(mm::PAGE - 1);
    if carve < largest.0 {
        carve = (largest.0 + mm::PAGE - 1) & !(mm::PAGE - 1);
    }
    let carve_end = carve + tframes * mm::PAGE;
    let pml4 = mm::build_identity_map(mmap, carve);
    mm::load_cr3(pml4);
    mm::physmap_on();
    kprintln!(con,
        "rustux: own page tables active (identity map, {} GiB, {} table frames at {:#x})",
        ngib,
        mm::table_frames(ngib),
        carve
    );

    // Seed the heap — buddy underneath, slab classes on top — then prove:
    // kmalloc pattern-write survives, kfree pushes the slot back (a
    // same-class realloc returns the recycled address), and a >4 KiB
    // request takes the direct-buddy path.
    // The carve plus whatever the front end marked off-limits: under UEFI
    // that's nothing extra (image/stack live in LOADER ranges the buddy
    // never pools); under BIOS the kernel image, mbi, and initrd module
    // all sit inside usable RAM and must be excluded explicitly.
    let mut resv = [(0u64, 0u64); 8];
    resv[0] = (carve, carve_end);
    let nr = 1 + extra_reserved.len().min(resv.len() - 1);
    // Subtraction in add_range must land on page boundaries or the buddy
    // seeds blocks at unaligned bases — round each reservation outward.
    for (d, s) in resv[1..nr].iter_mut().zip(&extra_reserved[..nr - 1]) {
        *d = (s.0 & !(mm::PAGE - 1), (s.1 + mm::PAGE - 1) & !(mm::PAGE - 1));
    }
    for r in &resv[..nr] {
        kprintln!(con, "rustux:   resv {:#010x}..{:#010x}", r.0, r.1);
    }
    kalloc::init(mmap, &resv[..nr]);
    let free0 = kalloc::free_frames();
    let mut ok;
    let p1 = kalloc::kmalloc(100);
    if p1.is_null() {
        ok = false;
    } else {
        // SAFETY: p1 names 100 owned bytes.
        unsafe {
            core::ptr::write_bytes(p1, 0xa5, 100);
            kalloc::kfree(p1);
        }
        let p2 = kalloc::kmalloc_zalloc(100);
        ok = p2 == p1; // freelist reuse proves the slot was pushed back
        // SAFETY: guarded by is_null — p2 names 100 zalloc-zeroed bytes.
        ok = ok && !p2.is_null() && unsafe { (0..100).all(|i| *p2.add(i) == 0) };
        if !p2.is_null() {
            // SAFETY: p2 is a fresh live allocation of the same class.
            unsafe { kalloc::kfree(p2) };
        }
    }
    let big = kalloc::kmalloc(3 * 4096);
    if big.is_null() {
        ok = false;
    } else {
        // SAFETY: big names a 12 KiB direct block.
        unsafe {
            core::ptr::write_bytes(big, 0x5a, 3 * 4096);
            kalloc::kfree(big);
        }
    }
    kprintln!(con,
        "rustux: klib::mm: buddy+slab heap {}/{} frames free, kmalloc/kfree proof {}",
        kalloc::free_frames(),
        free0,
        ok
    );
    assert!(ok);

    // Interrupt layer step 1: mask the legacy PIC, arm the LAPIC periodic
    // timer (calibrated against the PIT), then take real IRQs through our
    // own IDT. Interrupt gates restore caller-saved registers in dispatch,
    // so the interrupted context resumes intact.
    let lapic = match apic::init() {
        Some(hz) => {
            kprintln!(con,
                "rustux: apic: lapic timer {hz} Hz counter -> 100 Hz periodic on vec {:#x} ({} mode)",
                apic::IRQ_TIMER,
                if apic::is_x2apic() { "x2apic" } else { "xapic" }
            );
            true
        }
        None => {
            kprintln!(con, "rustux: apic: no local APIC -- interrupts stay off");
            false
        }
    };
    // Interrupt layer step 2: parse the MADT (I/O APIC base + IRQ0
    // override), route the ISA PIT pin to vector IRQ_PIT through the I/O
    // APIC, and arm channel 0 — the first real device IRQ through our IDT.
    let mut pit = false;
    let mut kbd_ok = false;
    if lapic {
        match acpi::madt() {
            Some(m) if m.ioapic_addr != 0 => {
                let (g0, f0) = m.gsi_for_irq(0);
                kprintln!(con,
                    "rustux: acpi: MADT {} lapics, LAPIC @{:#x}, IOAPIC @{:#x} gsi{}, IRQ0 -> GSI{} flags {:#x} ({} ISOs)",
                    m.lapics, m.lapic_addr, m.ioapic_addr, m.ioapic_gsi_base, g0, f0, m.n_isos
                );
                if apic::ioapic_route(m.ioapic_addr, g0, apic::IRQ_PIT, f0) {
                    let (id, ver, dest) = apic::ioapic_probe();
                    kprintln!(con,
                        "rustux: apic: ioapic id={:#x} ver={:#x} redirs={} dest-lapic={} -- PIT -> vec {:#x}",
                        id, ver, ((ver >> 16) & 0xff) + 1, dest, apic::IRQ_PIT
                    );
                    apic::arm_pit(100);
                    pit = true;
                } else {
                    kprintln!(con,
                        "rustux: apic: ioapic route GSI{} -> {:#x} REJECTED (bad addr/gsi)",
                        g0, apic::IRQ_PIT
                    );
                }

                // PS/2 keyboard: ISA IRQ1 -> GSI (override-aware), same
                // I/O APIC path. The i8042 init enables the port's IRQ
                // bit and flushes stale output.
                let (g1, f1) = m.gsi_for_irq(1);
                if kbd::init() && apic::ioapic_route(m.ioapic_addr, g1, apic::IRQ_KBD, f1) {
                    kprintln!(con,
                        "rustux: kbd: i8042 up, IRQ1 -> GSI{} on vec {:#x}",
                        g1, apic::IRQ_KBD
                    );
                    kbd_ok = true;
                } else {
                    kprintln!(con, "rustux: kbd: no usable i8042/IRQ1 route");
                }
            }
            _ => {
                kprintln!(con, "rustux: acpi: no usable MADT/IOAPIC -- no device IRQs");
            }
        }
    }

    // Device discovery step 1: walk the PCI bus firmware configured —
    // every line lands in the printk ring and flushes on this drain.
    // This is the table future drivers (e1000, AHCI, virtio) bind on.
    let n_pci = pci::scan();
    kprintln!(con, "rustux: pci: {n_pci} functions on the bus");
    // Driver binding step 1: the e1000e QEMU attaches. The BAR check is
    // the promised validation — the claimed MMIO window must not overlap
    // any conventional-RAM range before the driver writes through it.
    let bar_is_mmio = |base: u64, size: u64| -> bool {
        !mmap.iter().any(|d| {
            d.usable
                && base < d.phys_start + d.page_count * 4096
                && base + size > d.phys_start
        })
    };
    // ext2 superblock parser self-test: a valid image must parse and
    // validate, a bad magic must be refused, and a truncated image must
    // fail validation. Cheap, and it pins the on-disk offsets.
    {
        let mut img = [0u8; 4096];
        const SB: usize = 1024;
        img[SB + 56..SB + 58].copy_from_slice(&ext2::MAGIC.to_le_bytes());
        img[SB..SB + 4].copy_from_slice(&128u32.to_le_bytes()); // inodes
        img[SB + 4..SB + 8].copy_from_slice(&4u32.to_le_bytes()); // blocks
        img[SB + 20..SB + 24].copy_from_slice(&1u32.to_le_bytes()); // first_data
        img[SB + 24..SB + 28].copy_from_slice(&0u32.to_le_bytes()); // log_bs = 1024
        img[SB + 32..SB + 36].copy_from_slice(&4u32.to_le_bytes()); // bpg
        img[SB + 40..SB + 40 + 4].copy_from_slice(&128u32.to_le_bytes()); // ipg
        img[SB + 76..SB + 80].copy_from_slice(&1u32.to_le_bytes()); // rev
        img[SB + 88..SB + 90].copy_from_slice(&128u16.to_le_bytes()); // inode_size
        let mio = ext2::MemIo { data: &img };
        let ok = match ext2::parse_super(&mio) {
            Some(sb) => sb.block_size() == 1024 && sb.groups() == 1 && !sb.uses_extents()
                && ext2::validate(&sb, img.len() as u64),
            None => false,
        };
        let mut bad = img;
        bad[SB + 56] ^= 0xff;
        let bmio = ext2::MemIo { data: &bad };
        let refused = ext2::parse_super(&bmio).is_none();
        kprintln!(con, "rustux: ext2: superblock parse {ok} reject {refused}");
        // Walk a minimal in-memory ext2: 1 KiB blocks, GDT at block 2,
        // inode table at block 3, inode 2 = / whose first block is 4
        // holding one entry "hi.txt" -> inode 12.
        let mut fs = [0u8; 8192];
        fs[SB + 56..SB + 58].copy_from_slice(&ext2::MAGIC.to_le_bytes());
        fs[SB..SB + 4].copy_from_slice(&16u32.to_le_bytes()); // inodes
        fs[SB + 4..SB + 8].copy_from_slice(&8u32.to_le_bytes()); // blocks
        fs[SB + 20..SB + 24].copy_from_slice(&1u32.to_le_bytes());
        fs[SB + 32..SB + 36].copy_from_slice(&8u32.to_le_bytes()); // bpg
        fs[SB + 40..SB + 40 + 4].copy_from_slice(&16u32.to_le_bytes()); // ipg
        fs[SB + 76..SB + 80].copy_from_slice(&1u32.to_le_bytes());
        fs[SB + 88..SB + 90].copy_from_slice(&128u16.to_le_bytes());
        // group 0 descriptor at block 2 (first_data_block=1 -> gdt=2)
        fs[2048 + 8..2048 + 12].copy_from_slice(&3u32.to_le_bytes()); // inode_table
        // inode 2 (root): mode dir, size 1024, block[0]=4
        let i2 = 3 * 1024 + 128;
        fs[i2..i2 + 2].copy_from_slice(&0x4000u16.to_le_bytes());
        fs[i2 + 4..i2 + 8].copy_from_slice(&1024u32.to_le_bytes());
        fs[i2 + 40..i2 + 44].copy_from_slice(&4u32.to_le_bytes());
        // block 4: one dir entry, ino 12, rec_len 1024, name "hi.txt"
        let d = 4096;
        fs[d..d + 4].copy_from_slice(&12u32.to_le_bytes());
        fs[d + 4..d + 6].copy_from_slice(&1024u16.to_le_bytes());
        fs[d + 6] = 6;
        fs[d + 8..d + 14].copy_from_slice(b"hi.txt");
        let mut found = 0u32;
        let fmio = ext2::MemIo { data: &fs };
        let walked = match ext2::parse_super(&fmio) {
            Some(sb2) => {
                let r = ext2::dir_walk(&fmio, &sb2, 2, |e| {
                    if &e.name[..e.name_len as usize] == b"hi.txt" {
                        found = e.ino;
                    }
                    true
                });
                r.is_some()
            }
            None => false,
        };
        kprintln!(con, "rustux: ext2: dir walk {walked} found {found}");
        // REAL image written by Linux's own mke2fs at build time: this
        // is the test that proves the driver reads what Linux writes,
        // not merely what our fixture assumes.
        let real: &[u8] = include_bytes!("ext2_test.img");
        let rio = ext2::MemIo { data: real };
        let mut saw = 0u32;
        let real_ok = match ext2::parse_super(&rio) {
            Some(sb3) => {
                let v = ext2::validate(&sb3, real.len() as u64);
                let w = ext2::dir_walk(&rio, &sb3, 2, |e| {
                    if &e.name[..e.name_len as usize] == b"hi.txt" {
                        saw = e.ino;
                    }
                    true
                });
                v && w.is_some()
            }
            None => false,
        };
        kprintln!(con, "rustux: ext2: real image {real_ok} hi.txt ino={saw}");
        // Read the file's CONTENT through the block map: lookup by
        // name, then walk the inode's block map for the data.
        let mut body = [0u8; 64];
        let (content_ok, got) = match ext2::parse_super(&rio) {
            Some(sb3) => match ext2::lookup(&rio, &sb3, 2, b"hi.txt") {
                Some(ino) => {
                    let n = ext2::read_file(&rio, &sb3, ino, &mut body).unwrap_or(0);
                    let expect = b"hello ext2";
                    (n >= expect.len() && &body[..expect.len()] == expect, n)
                }
                None => (false, 0),
            },
            None => (false, 0),
        };
        kprintln!(con, "rustux: ext2: content {content_ok} bytes {got}");
        // ext3: same image contract through Linux's mke2fs -t ext3 —
        // the journaled sibling must mount and read identically.
        let e3: &[u8] = include_bytes!("ext3_test.img");
        let e3io = ext2::MemIo { data: e3 };
        let e3_ok = match ext2::parse_super(&e3io) {
            Some(sb3) => {
                sb3.readable()
                    && ext2::validate(&sb3, e3.len() as u64)
                    && ext2::lookup(&e3io, &sb3, 2, b"hi.txt").is_some()
            }
            None => false,
        };
        kprintln!(con, "rustux: ext3: real image {e3_ok}");
        // ext4: extents + 64bit descriptors + flex_bg + 256-byte
        // inodes. big.bin is sparse-with-8-holes — enough extents to
        // push the tree to depth 1, so the index->leaf walk is proven
        // on a real Linux-written image, not a fixture.
        let e4: &[u8] = include_bytes!("ext4_test.img");
        let e4io = ext2::MemIo { data: e4 };
        let mut e4_body = [0u8; 64];
        let e4_ok = match ext2::parse_super(&e4io) {
            Some(sb4) => {
                let v = sb4.readable()
                    && sb4.uses_extents()
                    && ext2::validate(&sb4, e4.len() as u64);
                let small = ext2::lookup(&e4io, &sb4, 2, b"hi.txt")
                    .and_then(|i| ext2::read_file(&e4io, &sb4, i, &mut e4_body))
                    .is_some_and(|n| n >= 10 && &e4_body[..9] == b"hello ext");
                let deep = ext2::lookup(&e4io, &sb4, 2, b"big.bin")
                    .map(|i| {
                        let n = ext2::read_file(&e4io, &sb4, i, &mut e4_body)
                            .unwrap_or(0);
                        n >= 6 && &e4_body[..6] == b"chunk0"
                    })
                    .unwrap_or(false);
                v && small && deep
            }
            None => false,
        };
        kprintln!(con, "rustux: ext4: real image {e4_ok} (extents incl. depth>0)");
    }
    // Driver binding step 2: the primary-channel ATA disk, when the
    // machine has one (-drive if=ide). Pure PIO — the probe only
    // costs an IDENTIFY round-trip, so run it whether or not PCI
    // found the controller (QEMU's PIIX3 is always port-fixed).
    // Moved ahead of the partition scan: the ext2 mount below gates
    // on ata::sectors(), and probing ATA only here meant the scan
    // never ran on -machine pc (IDE only, no AHCI).
    let ata_secs = ata::init();
    if ata_secs > 0 {
        kprintln!(con, "rustux: ata: primary master {ata_secs} sectors ({} MiB)",
            ata_secs / 2048);
    } else {
        kprintln!(con, "rustux: ata: no disk on the primary channel");
    }
    // AHCI: q35 and real machines expose their disks here, not on the
    // legacy PIIX ports ata.rs drives. Same MMIO validation.
    let n_ahci = ahci::init(bar_is_mmio);
    if n_ahci > 0 {
        kprintln!(con, "rustux: ahci: {n_ahci} disk(s)");
    }
    // virtio-blk: QEMU's modern disk transport (-drive if=virtio).
    // The driver logs its own probe line; only the count matters here.
    let n_virtio = virtio::init();
    if n_virtio > 0 {
        kprintln!(con, "rustux: virtio: {n_virtio} disk(s)");
    }
    // NVMe: PCI MMIO storage (-device nvme). The driver logs its own
    // probe line; only the count matters here.
    let n_nvme = nvme::init(bar_is_mmio);
    if n_nvme > 0 {
        kprintln!(con, "rustux: nvme: {n_nvme} disk(s)");
    }
    // virtio-rng: the canonical guest entropy tap — feed the pool
    // a reseed after the one-shot rdrand seed.
    virtio::rng_init();
    // virtio-console: a second console channel (/dev/hvc0) over its
    // own virtqueue pair — the init proof writes the chardev backend.
    virtio::console_init();
    // virtio-input: QEMU's virtio-keyboard — events fold into the
    // shared evdev ring behind /dev/input/event0.
    virtio::vinput_init();
    // virtio-balloon: memory give/take with the host — the pump
    // tracks num_pages, deflate returns frames to the allocator.
    virtio::balloon_init();
    virtio::scsi_init();
    // virtio-net: second NIC next to the e1000e — its own RX/TX
    // virtqueues, ARP round-trip proves the datapath (socket-layer
    // NIC dispatch is a later rung).
    if virtio::net_init() && virtio::net_selftest() {
        kprintln!(con, "rustux: virtio: net ARP round-trip true");
    }
    // DiskIo: the adapter that reads REAL sectors (placed after the
    // disk probes so a disk is known). The boot disk is FAT, so ext2
    // must refuse it cleanly — proving the adapter reads and that the
    // parser rejects non-ext2 data instead of misparsing it.
    if ata::sectors() > 0 || ahci::disks() > 0 || virtio::disks() > 0 || nvme::disks() > 0 {
        let dio = ext2::DiskIo { disk: 0 };
        let refused_disk = ext2::parse_super(&dio).is_none();
        kprintln!(con, "rustux: ext2: disk adapter len>0 {} refuses non-ext2 {refused_disk}",
                  ext2::BlockIo::len(&dio) > 0);
        // Live-media check: the installer ISO's initrd carries the
        // hd.img payload (the disk image the installer streams); the
        // installed disk's initrd is the same archive minus hd.img.
        // When live, an attached installed disk's ext2 root is still
        // detected but NOT copied into the namespace — the live
        // environment must stay pristine, and the installer stays
        // reachable.
        let live_media = initrd.is_some_and(|(a, l)| {
            let a2 = unsafe {
                core::slice::from_raw_parts(mm::pmap(a) as *const u8, l)
            };
            cpio::find(a2, b"hd.img").is_some()
        });
        // Read each disk's partition table and try to mount every
        // partition as ext2 — the same path a root mount takes. The
        // ESP is FAT, so it is refused; the root partition is mounted
        // and its directory walked.
        for d in 0..ext2::disk_count().max(4) {
            let io = ext2::DiskIo { disk: d };
            let total = ext2::BlockIo::len(&io);
            if total < 1024 * 1024 {
                continue;
            }
            let mut mbr = [0u8; 512];
            if !ext2::BlockIo::read(&io, 0, &mut mbr) || mbr[510] != 0x55 || mbr[511] != 0xaa {
                continue;
            }
            // A FAT VBR also ends in 55AA. Treating it as an MBR parses
            // garbage partition entries and does spurious I/O, so skip
            // anything that carries a FAT BPB signature.
            if &mbr[54..57] == b"FAT" || &mbr[82..85] == b"FAT" {
                continue;
            }
            // The disk's advertised partitions: (start lba,
            // sectors, type tag). MBR fills slot order 1-4; a
            // protective 0xEE entry switches to the GPT walk, which
            // fills by GPT entry index 1-15 (the minor nibble cap).
            let mut parts = [(0u64, 0u64, 0u64); 15];
            let gpt = (0..4usize).any(|s| mbr[446 + s * 16 + 4] == 0xee);
            if gpt {
                gpt_scan(&io, total, &mut parts);
            } else {
                for slot in 0..4usize {
                    let e = &mbr[446 + slot * 16..446 + slot * 16 + 16];
                    let ptype = e[4];
                    let start =
                        u32::from_le_bytes([e[8], e[9], e[10], e[11]]) as u64;
                    let count =
                        u32::from_le_bytes([e[12], e[13], e[14], e[15]]) as u64;
                    let size = count * 512;
                    if ptype != 0 && count != 0 && start * 512 + size <= total {
                        parts[slot] = (start, count, ptype as u64);
                    }
                }
            }
            for (slot, &(start, count, ptype)) in parts.iter().enumerate() {
                if count == 0 {
                    continue;
                }
                let base = start * 512;
                let size = count * 512;
                // Register the partition's /dev minor — every valid
                // entry gets a node, mounted fs or not, like udev.
                let (tr, tdrv) = ext2::transport(d);
                let tmajor = match tr {
                    0 | 1 => 8,   // PIIX + AHCI are both sd
                    2 => 254,     // vd
                    3 => 259,     // nvme
                    _ => 65,      // virtio-scsi — sd's extended majors
                };
                user::dev_part_add(tmajor, tdrv, slot + 1, start, count);
                if let Some(m) = ext2::mount(&io, base, size) {
                    let part = ext2::PartIo { dev: &io, base, size };
                    let mut n = 0u32;
                    let walked = ext2::dir_walk(&part, &m.sb, 2, |_e| {
                        n += 1;
                        true
                    })
                    .is_some();
                    // Read a file back out of the mounted root: the
                    // end-to-end proof that the installer's filesystem
                    // is readable by this kernel.
                    let mut body = [0u8; 64];
                    // Two-level walk: /etc/motd proves the kernel can
                    // follow a directory, not just a flat root.
                    let got = match ext2::lookup(&part, &m.sb, 2, b"etc") {
                        Some(d) => match ext2::lookup(&part, &m.sb, d, b"motd") {
                            Some(ino) => ext2::read_file(&part, &m.sb, ino, &mut body)
                                .unwrap_or(0),
                            None => 0,
                        },
                        None => 0,
                    };
                    let fam = if m.sb.uses_extents() {
                        "ext4"
                    } else if m.sb.has_journal() {
                        "ext3"
                    } else {
                        "ext2"
                    };
                    kprintln!(con,
                        "rustux: {fam}: disk{d}p{slot} type={:#x} MOUNTED lba={start} block={} entries={n} walked={walked} etc/motd={got}B",
                        ptype, m.sb.block_size());
                    // The namespace pivot: copy the whole installed
                    // root into the RAM fs. fs_lookup/open/stat/getdents
                    // all resolve vfiles first, so after this a pid 1
                    // spawned from this root sees /bin, /etc and the
                    // rest of its own filesystem — not the initrd's.
                    // Skipped on live media: the installer ISO keeps a
                    // pristine namespace and stays reachable.
                    let mut copied = 0u32;
                    if !live_media {
                        let mut path = [0u8; 128];
                        let mut budget = 256u64 << 20;
                        let mut seen = [0u32; 1024];
                        let mut nseen = 0u32;
                        copy_root_dir(
                            &part, &m.sb, 2, &mut path, 0, 0, &mut copied,
                            &mut budget, &mut seen, &mut nseen,
                        );
                    }
                    kprintln!(con,
                        "rustux: root: {copied} files copied up from ext2");
                    // Remember a boot binary for the spawn step: the
                    // pivot only fires when an installed root actually
                    // supplied one — a live boot has no ext2 root and
                    // must not mistake the archive's busybox for it.
                    if copied > 0 {
                        if let Some(img) = user::fs_lookup(b"bin/busybox")
                        {
                            unsafe {
                                *core::ptr::addr_of_mut!(ROOT_EXE) =
                                    Some((img.as_ptr(), img.len()));
                            }
                        }
                    }
                }
            }
        }
    }
    let e1000_dev = e1000::probe(bar_is_mmio);
    if let Some((e_base, e_mac)) = e1000_dev {
        let tx_ok = e1000::tx_selftest(e_base, e_mac);
        kprintln!(con, "rustux: e1000: tx datapath self-test {tx_ok}");
        if tx_ok {
            let rx_ok = e1000::arp_selftest(e_base, e_mac);
            kprintln!(con, "rustux: e1000: rx round-trip (ARP) {rx_ok}");
            if rx_ok {
                let ping_ok = e1000::ping_selftest(e_base, e_mac);
                kprintln!(con, "rustux: e1000: IPv4/ICMP ping {ping_ok}");
                let dhcp_ok = e1000::dhcp_selftest(e_base, e_mac);
                kprintln!(con, "rustux: e1000: DHCP lease {dhcp_ok}");
            }
            // Socket-link protocol demos: only built with
            // RUSTFLAGS=--cfg demo_net (see Makefile `run`).
            #[cfg(demo_net)]
            {
                e1000::ipv8_demo(e_base, e_mac, &mut con);
                e1000::ipv6_selftest(e_base, e_mac, &mut con);
                e1000::tcp_selftest(e_base, e_mac, &mut con);
            }
        }
    } else {
        kprintln!(con, "rustux: e1000: no 82574L on the bus");
    }

    if lapic {
        // SAFETY: IDT gates for 0xf0/0xf1/0xff are installed; dispatch
        // saves and restores every caller-saved register around the
        // handler, and the handler sends EOI. hlt sleeps until an IRQ.
        unsafe { core::arch::asm!("sti", options(nomem, nostack)) };
        let t0 = apic::TICKS.load(core::sync::atomic::Ordering::Relaxed);
        let p0 = apic::PIT_TICKS.load(core::sync::atomic::Ordering::Relaxed);
        // ~50 ticks at 100 Hz; the spin bound keeps a broken timer from
        // hanging the boot proof.
        let mut spins = 0u64;
        while apic::TICKS.load(core::sync::atomic::Ordering::Relaxed) - t0 < 50 && spins < 3000 {
            unsafe { core::arch::asm!("hlt", options(nomem, nostack)) };
            spins += 1;
        }
        kprintln!(con,
            "rustux: apic: {} periodic timer IRQs delivered via own IDT",
            apic::TICKS.load(core::sync::atomic::Ordering::Relaxed) - t0
        );
        if pit {
            kprintln!(con,
                "rustux: apic: {} PIT ch0 IRQs delivered via I/O APIC -> own IDT",
                apic::PIT_TICKS.load(core::sync::atomic::Ordering::Relaxed) - p0
            );
        }

        // Interrupts are live now — the NIC's MSI path: a message write
        // straight to the LAPIC, no IOAPIC line. TX the ARP probe, the
        // reply raises vector 0xf3 through our IDT.
        if let Some((e_base, e_mac)) = e1000_dev {
            let msi_ok = e1000::irq_selftest(e_base, e_mac);
            kprintln!(con, "rustux: e1000: MSI receive path {msi_ok}");
            // Hand the NIC to the socket layer — the last rx_init
            // wins the device, so this runs after every selftest.
            let live = e1000::net_live(e_base, e_mac);
            let ip = e1000::our_ip();
            kprintln!(con,
                "rustux: e1000: live rx {live} ip {}.{}.{}.{}",
                ip[0], ip[1], ip[2], ip[3]
            );
        }
        // The virtio NIC's own MSI path: RX queue bound to vector
        // 0xf4 — arrivals now wake the idle hlt loops immediately
        // instead of waiting for the next tick.
        if virtio::net_up() {
            let virq = virtio::net_irq_selftest();
            kprintln!(con, "rustux: virtio: net MSI receive path {virq}");
        }
        // The NVMe I/O CQ's MSI-X path: one read must drop an IRQ
        // on 0xf5 — count-only handler, completions still consumed
        // by the phase-bit poll.
        if nvme::disks() > 0 {
            let nirq = nvme::irq_selftest();
            kprintln!(con, "rustux: nvme: I/O-CQ MSI receive path {nirq}");
        }
        // virtio-input's eventq path: QMP send-key taps must drain
        // as EV_KEY records — counted on the virtio queue itself so
        // the PS/2 keyboard can't satisfy the proof.
        if virtio::vinput_present() {
            let vin = virtio::vinput_selftest();
            kprintln!(con, "rustux: virtio: input evdev receive path {vin}");
        }
        // A virtio-only boot never ran DHCP — seed the static slirp
        // lease so the socket layer considers the NIC usable. No-op
        // when the e1000 leased an address above.
        if let Some(mac) = virtio::net_mac() {
            e1000::seed_virtio_identity(mac);
        }

        // Decoded keys now feed the tty input queue via the tick-side
        // stdin pump — read(0)/poll(0) are live for the whole suite,
        // not a boot-time echo window.
        if kbd_ok {
            kprintln!(con, "rustux: kbd: decoded input -> tty stdin queue");
        }
    }

    // Prove the new IDT: the #UD handler reports on COM1, bumps rip past the
    // 2-byte ud2, and execution resumes here.
    // SAFETY: ud2 always raises #UD; our handler makes it survivable.
    unsafe { core::arch::asm!("ud2", options(nomem, nostack)) };
    kprintln!(con, "rustux: cpu: IDT caught #UD and resumed");

    // Userspace milestone: the initrd IS the process table — every
    // cpio entry is enqueued as a Runnable task (private page tables,
    // private syscall stack, frames reclaimed on exit) and the whole
    // queue runs under the preemptive round-robin scheduler: the
    // LAPIC timer snapshots a task's ctx at 100 Hz and iretq-resumes
    // the next Runnable one; exit() switches directly task-to-task.
    // Falls back to the embedded image when no initrd was loaded or
    // the archive has no entries.
    // SAFETY: initrd names LOADER_DATA pages we allocated pre-EBS;
    // physmap-reachable and still owned.
    let arc = initrd.map(|(a, l)| unsafe {
        core::slice::from_raw_parts(mm::pmap(a) as *const u8, l)
    });
    // Boot-time /dev population — device nodes and their links are
    // kernel-lifetime objects like the initrd, so they belong outside
    // the task-leak window.
    user::dev_init();
    let before = kalloc::free_frames();
    let mut queued = 0u32;
    // Capture the fninit FPU image tasks start from — must run
    // before the first spawn copies INIT_FX into its Task.
    user::fpu_init();
    if let Some(arc) = arc {
        // The archive is the read-only underlay of the root fs —
        // installed files copied into the RAM fs resolve first (the
        // pivot), anything not installed falls back to the initrd. Set
        // unconditionally so a pivoted pid 1 gets the union view too.
        // SAFETY: `arc` names LOADER_DATA pages that are never freed,
        // so a 'static slice over them is sound.
        user::set_initrd(unsafe { core::slice::from_raw_parts(arc.as_ptr(), arc.len()) });
        // A firmware read can silently drop a sector run (observed:
        // a 35x2048B hole inside libapt-pkg.so on one boot). Stamp the
        // archive's crc at load time so a later install-time verify
        // failure can be told apart from a mid-session RAM scribble.
        // zlib convention (!seed, !result) — matches mkinitrd's
        // zlib.crc32 manifest and livemenu's verify.
        kprintln!(con, "rustux: initrd crc32 = {:#x}", !klib::crc::crc32_le(!0, arc));
    }
    let root_exe = unsafe { *core::ptr::addr_of!(ROOT_EXE) };
    if let Some((p, n)) = root_exe {
        // PIVOT: an installed root with a boot binary wins over the
        // initrd payload — this is what makes the disk a system rather
        // than a filesystem the kernel reads. Its whole tree was copied
        // into the RAM fs above, so pid 1's namespace IS the installed
        // root (with the initrd as read-only underlay).
        // pid 1 is livemenu, not a bare shell: on the installed ESP
        // /hd.img is absent so it skips the menu and runs login —
        // passwd/shadow auth, then the account shell. Without this
        // the installed system booted straight into an unauthenticated
        // root sh and never ran apt_dirs() either. A bare busybox sh
        // stays the fallback if the image somehow lacks livemenu.
        let img = unsafe { core::slice::from_raw_parts(p, n) };
        let mut spawned = false;
        match user::fs_lookup(b"livemenu") {
            None => kprintln!(con, "rustux: root: livemenu lookup miss"),
            Some(limg) => {
                spawned = user::spawn(limg, "livemenu");
                if !spawned {
                    kprintln!(con, "rustux: root: livemenu spawn refused len={}", limg.len());
                }
            }
        }
        if spawned {
            kprintln!(con, "rustux: root: booting the installed system (pid 1 = livemenu -> login)");
            queued += 1;
        } else if user::spawn(img, "sh") {
            kprintln!(con, "rustux: root: booting the installed system (pid 1 = sh from ext2)");
            queued += 1;
        } else {
            kprintln!(con, "rustux: root: spawn FAILED, falling back to the initrd");
        }
    }
    if queued == 0 {
        if let Some(arc) = arc {
        for (name, img) in cpio::entries(arc) {
            let nm = core::str::from_utf8(name).unwrap_or("?");
            // '/' names are support files (lib64/ld-linux...,
            // lib/.../libc.so.6) — ELFs, but not tasks. MZ marks a
            // PE32+ image — those spawn under the NT personality.
            // .dll files are loadable modules, not processes.
            if !(img.starts_with(b"\x7fELF") || img.starts_with(b"MZ"))
                || name.contains(&b'/')
                || name.ends_with(b".dll")
            {
                continue;
            }
            if user::spawn(img, nm) {
                kprintln!(con, "rustux: task {nm}: queued");
                queued += 1;
            } else {
                kprintln!(con, "rustux: task {nm}: spawn FAILED");
            }
        }
        }
    }
    if queued == 0 {
        kprintln!(con, "rustux: initrd: no entries, using embedded ELF");
        if user::spawn(include_bytes!("../user/hello.elf"), "hello") {
            queued = 1;
        }
    }
    // Enters the scheduler; returns when the last task has exited.
    user::launch();
    user::reap_all();
    let after = kalloc::free_frames();
    kprintln!(con, "rustux: tasks: {} ran, frames {} -> {} after reap{} (slab {})", queued, before, after,
        if after == before { " (zero leak)" } else { " (LEAK)" }, kalloc::slab_pages());
    kprintln!(
        con,
        "rustux: log: {} records through klib::prb ring, {} dropped",
        log::drained(),
        log::dropped()
    );

    // Hold the final frame ~1.5s before exiting — serial readers
    // already have the result, but the framebuffer should show it to
    // anyone watching (and to headless screendump capture, which
    // stops existing the instant we exit). rdtsc, not TICKS: the
    // LAPIC stops accumulating once the scheduler unwinds.
    let t0 = unsafe { core::arch::x86_64::_rdtsc() };
    while unsafe { core::arch::x86_64::_rdtsc() } - t0 < 4_500_000_000 {}

    // Exit code 0x10 -> QEMU exits 0x21. Anything else means we never got here.
    qemu_exit(0x10);
}



/// Load `\initrd.cpio` from the ESP via the Simple File System
/// protocol. Boot-services-only: allocate LOADER_DATA pages (our buddy
/// ignores that type, so the buffer survives EBS identity-mapped) and
/// read the file into them. Returns (phys_addr, len) or None.
#[cfg(target_os = "uefi")]
/// Outcome of the initrd crc32 sidecar check — lets the caller log
/// whether the archive verified, had no sidecar, or stayed corrupt
/// after a re-read (a transient firmware drop once zeroed 35 CD
/// sectors inside libapt-pkg.so, silently bricking apt).
#[derive(Clone, Copy)]
enum InitrdVerify {
    NoSidecar,
    Ok(u32),
    Bad { want: u32, got: u32 },
}

/// Early-boot note before the named failure stage: load_initrd runs
/// after the console exists but takes no handle — a fresh polling
/// UART on COM1 mirrors the panic path and is safe pre-scheduler.
fn initrd_fail(stage: &str) {
    use core::fmt::Write;
    unsafe {
        let mut u = uart::Uart16550::new(uart::COM1);
        u.init();
        let _ = writeln!(u, "rustux: initrd: load failed at {stage}");
    }
}

fn load_initrd() -> (Option<(u64, usize)>, InitrdVerify) {
    use uefi::proto::media::file::{File, FileAttribute, FileMode, RegularFile};

    /// Largest initrd we accept — a guard against a corrupt ESP
    /// handing us something absurd. Static-PIE test binaries are
    /// ~800KB each, so this grew with the real-binary suite. The
    /// run-130 archive crossed 30MiB; the demo ISO's initrd carries
    /// the 48MiB install image on top (~81MiB), so headroom again.
    const MAX_INITRD: usize = 128 << 20;

    let mut sfs =
        match uefi::boot::get_image_file_system(uefi::boot::image_handle()) {
            Ok(s) => s,
            Err(_) => {
                initrd_fail("get_image_file_system");
                return (None, InitrdVerify::NoSidecar);
            }
        };
    let mut root = match sfs.open_volume() {
        Ok(r) => r,
        Err(_) => {
            initrd_fail("open_volume");
            return (None, InitrdVerify::NoSidecar);
        }
    };
    // The initrd sits next to the loaded image on whatever filesystem
    // firmware mounted: a FAT ESP keeps `initrd.cpio` verbatim, but a
    // bare ISO9660 view truncates to the 8.3 `INITRD.CPI`.
    let names = [
        uefi::cstr16!("initrd.cpio"),
        uefi::cstr16!("INITRD.CPIO"),
        uefi::cstr16!("initrd.cpi"),
        uefi::cstr16!("INITRD.CPI"),
    ];
    let crc_names = [
        uefi::cstr16!("initrd.crc"),
        uefi::cstr16!("INITRD.CRC"),
    ];
    let mut open_named = |names: &[&uefi::CStr16]| -> Option<RegularFile> {
        for n in names {
            if let Ok(h) = root.open(n, FileMode::Read, FileAttribute::empty()) {
                // SAFETY: we just opened it as a plain file.
                return Some(unsafe { RegularFile::new(h) });
            }
        }
        None
    };
    let pages = MAX_INITRD / 4096;
    let base = match uefi::boot::allocate_pages(
        uefi::boot::AllocateType::AnyPages,
        MemoryType::LOADER_DATA,
        pages,
    ) {
        Ok(b) => b,
        Err(_) => {
            initrd_fail("allocate_pages");
            return (None, InitrdVerify::NoSidecar);
        }
    };
    // SAFETY: base names `pages` freshly allocated pages.
    let buf =
        unsafe { core::slice::from_raw_parts_mut(base.as_ptr(), MAX_INITRD) };
    let read_all = |f: &mut RegularFile, buf: &mut [u8]| -> Option<usize> {
        let mut off = 0usize;
        loop {
            let n = f.read(&mut buf[off..]).ok()?;
            if n == 0 {
                break;
            }
            off += n;
            if off == MAX_INITRD {
                return None;
            }
        }
        Some(off)
    };
    // Firmware file I/O on a warm reboot is flaky — a read can error
    // out or an open can miss outright; both are transient, so open
    // and read live in one two-attempt loop. The crc sidecar check
    // below still guards silent short reads.
    let mut off = 0usize;
    let mut loaded = false;
    for _ in 0..2 {
        let Some(mut f) = open_named(&names) else {
            continue;
        };
        if let Some(o) = read_all(&mut f, buf) {
            off = o;
            loaded = true;
            break;
        }
    }
    if !loaded {
        initrd_fail("open/read");
        return (None, InitrdVerify::NoSidecar);
    }
    // The sidecar holds the archive's zlib crc32, written next to
    // initrd.cpio at image-build time. A transient firmware read can
    // drop a sector run and still report success — the bytes simply
    // never arrive — so re-read the file once before believing a
    // mismatch.
    let want = open_named(&crc_names).and_then(|mut cf| {
        let mut b = [0u8; 32];
        let n = cf.read(&mut b).ok()?;
        let s = core::str::from_utf8(&b[..n]).ok()?;
        u32::from_str_radix(s.trim(), 16).ok()
    });
    let verify = match want {
        None => InitrdVerify::NoSidecar,
        Some(w) => {
            let mut got = !klib::crc::crc32_le(!0, &buf[..off]);
            if got != w {
                // Retry: firmware drops are transient; a second full
                // read into the same buffer usually lands clean.
                if let Some(mut f2) = open_named(&names) {
                    if let Some(o2) = read_all(&mut f2, buf) {
                        off = o2;
                        got = !klib::crc::crc32_le(!0, &buf[..off]);
                    }
                }
            }
            if got == w {
                InitrdVerify::Ok(got)
            } else {
                InitrdVerify::Bad { want: w, got }
            }
        }
    };
    (Some((base.as_ptr() as u64, off)), verify)
}
