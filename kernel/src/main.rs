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
mod apic;
mod ata;
mod cpu;
mod cpio;
mod e1000;
mod ext2;
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
    let initrd = load_initrd();
    match initrd {
        Some((a, l)) => kprintln!(con, "rustux: initrd: {l}B at {a:#x}"),
        None => kprintln!(con, "rustux: initrd: none found"),
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
    }
    // AHCI: q35 and real machines expose their disks here, not on the
    // legacy PIIX ports ata.rs drives. Same MMIO validation.
    let n_ahci = ahci::init(bar_is_mmio);
    if n_ahci > 0 {
        kprintln!(con, "rustux: ahci: {n_ahci} disk(s)");
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

    // Driver binding step 2: the primary-channel ATA disk, when the
    // machine has one (-drive if=ide). Pure PIO — the probe only
    // costs an IDENTIFY round-trip, so run it whether or not PCI
    // found the controller (QEMU's PIIX3 is always port-fixed).
    let ata_secs = ata::init();
    if ata_secs > 0 {
        kprintln!(con, "rustux: ata: primary master {ata_secs} sectors ({} MiB)",
            ata_secs / 2048);
    } else {
        kprintln!(con, "rustux: ata: no disk on the primary channel");
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
        // The archive doubles as the read-only root filesystem — fd
        // ops resolve paths against it for the kernel's lifetime.
        // SAFETY: `arc` names LOADER_DATA pages that are never freed,
        // so a 'static slice over them is sound.
        user::set_initrd(unsafe { core::slice::from_raw_parts(arc.as_ptr(), arc.len()) });
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
    kprintln!(con, "rustux: tasks: {} ran, frames {} -> {} after reap{}", queued, before, after,
        if after == before { " (zero leak)" } else { " (LEAK)" });
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
fn load_initrd() -> Option<(u64, usize)> {
    use uefi::proto::media::file::{File, FileAttribute, FileMode, RegularFile};

    /// Largest initrd we accept — a guard against a corrupt ESP
    /// handing us something absurd. Static-PIE test binaries are
    /// ~800KB each, so this grew with the real-binary suite. The
    /// run-130 archive crossed 30MiB; the demo ISO's initrd carries
    /// the 48MiB install image on top (~81MiB), so headroom again.
    const MAX_INITRD: usize = 128 << 20;

    let mut sfs =
        uefi::boot::get_image_file_system(uefi::boot::image_handle()).ok()?;
    let mut root = sfs.open_volume().ok()?;
    // The initrd sits next to the loaded image on whatever filesystem
    // firmware mounted: a FAT ESP keeps `initrd.cpio` verbatim, but a
    // bare ISO9660 view truncates to the 8.3 `INITRD.CPI`.
    let names = [
        uefi::cstr16!("initrd.cpio"),
        uefi::cstr16!("INITRD.CPIO"),
        uefi::cstr16!("initrd.cpi"),
        uefi::cstr16!("INITRD.CPI"),
    ];
    let mut f = None;
    for n in &names {
        if let Ok(h) = root.open(n, FileMode::Read, FileAttribute::empty()) {
            // SAFETY: we just opened it as a plain file.
            f = Some(unsafe { RegularFile::new(h) });
            break;
        }
    }
    let mut f = f?;
    let pages = MAX_INITRD / 4096;
    let base = uefi::boot::allocate_pages(
        uefi::boot::AllocateType::AnyPages,
        MemoryType::LOADER_DATA,
        pages,
    )
    .ok()?;
    // SAFETY: base names `pages` freshly allocated pages.
    let buf =
        unsafe { core::slice::from_raw_parts_mut(base.as_ptr(), MAX_INITRD) };
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
    Some((base.as_ptr() as u64, off))
}
