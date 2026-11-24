//! bios — Multiboot2 front end for legacy BIOS boot.
//!
//! GRUB's i386-pc core does the real-mode work (A20, E820, VBE, disk
//! loading); it enters `mb2_entry` in 32-bit protected mode with paging
//! off. The trampoline below builds a 4 GiB identity map (PML4 + PDPT +
//! 4 PDs of 2 MiB pages), flips on PAE/LME/paging, far-jumps to 64-bit,
//! and calls `bios_entry` with the Multiboot2 magic + info pointer.
//!
//! `bios_entry` then collects the same inputs the UEFI path provides
//! — memory map (tag 6), framebuffer (tag 8), initrd (module tag 3),
//! RSDP (tags 14/15, else the firmware-area scan) — normalizes them,
//! and hands off to the shared `rustux_main`.

use crate::{boot_map, push_ent, rustux_main, Console};
use crate::{fbcon, kprintln, log, uart};

/// Multiboot2 magic value the loader leaves in EAX.
const MB2_MAGIC: u32 = 0x36d76289;

core::arch::global_asm!(
    r#"
.intel_syntax noprefix

/* Multiboot2 header — must sit inside the image's first 32 KiB.
 * Requests a 32bpp linear framebuffer with no geometry preference. */
.section .mb2_header,"a"
.balign 8
mb2_header:
    .long 0xE85250D6                     /* magic */
    .long 0                              /* architecture: i386 */
    .long mb2_header_end - mb2_header    /* header_length */
    .long -(0xE85250D6 + (mb2_header_end - mb2_header))  /* checksum */
    .balign 8
    .short 5                             /* framebuffer tag */
    .short 1                             /* flags: optional */
    .long 20                             /* size */
    .long 0                              /* width  — no preference */
    .long 0                              /* height — no preference */
    .long 32                             /* depth  — 32bpp required */
    .balign 8
    .short 0                             /* end tag */
    .short 0
    .long 8
mb2_header_end:

/* 32-bit entry. GRUB arrives with interrupts off, flat segments, no
 * paging — every address below is physical, so the trampoline's writes
 * land exactly where the link addresses say they are. */
.section .text.boot,"ax"
.code32
.global mb2_entry
mb2_entry:
    cli
    mov esp, OFFSET mb2_stack_top
    mov dword ptr [mb2_saved], eax       /* magic */
    mov dword ptr [mb2_saved + 4], ebx   /* mbi phys addr */
    /* Stage markers on COM1's THR — QEMU's serial accepts bytes
     * before any divisor programming, so these land even if a later
     * stage dies. A=entry B=tables C=paging-on D=64-bit E=call done. */
    mov dx, 0x3f8
    mov al, 'A'
    out dx, al
    cmp dword ptr [mb2_saved], 0x36d76289
    jne .Lhang

    /* Zero the 6 pages of boot page tables. */
    mov edi, OFFSET mb2_pml4
    mov ecx, 6 * 1024
    xor eax, eax
    rep stosd

    /* PML4[0] -> PDPT */
    mov eax, OFFSET mb2_pdpt
    or eax, 3                            /* P|RW */
    mov dword ptr [mb2_pml4], eax

    /* PDPT[0..4] -> PD0..PD3 (4 GiB total). */
    mov eax, OFFSET mb2_pd0
    mov edi, OFFSET mb2_pdpt
    mov ecx, 4
.Lpdpt:
    mov edx, eax
    or edx, 3
    mov dword ptr [edi], edx
    add edi, 8
    add eax, 4096
    dec ecx
    jnz .Lpdpt

    /* 4 PDs * 512 entries = 2048 x 2 MiB identity pages. */
    mov edi, OFFSET mb2_pd0
    mov ecx, 2048
    xor eax, eax
.Lpd:
    mov edx, eax
    or edx, 0x83                         /* P|RW|PS */
    mov dword ptr [edi], edx
    mov dword ptr [edi + 4], 0
    add edi, 8
    add eax, 0x200000
    dec ecx
    jnz .Lpd

    mov dx, 0x3f8
    mov al, 'B'
    out dx, al
    mov eax, OFFSET mb2_pml4
    mov cr3, eax
    mov eax, cr4                         /* PAE */
    or eax, 1 << 5
    mov cr4, eax
    mov ecx, 0xC0000080                  /* EFER.LME */
    rdmsr
    or eax, 1 << 8
    wrmsr
    mov eax, cr0                         /* paging on */
    or eax, 0x80000000
    mov cr0, eax
    lgdt [mb2_gdt_ptr]
    mov dx, 0x3f8
    mov al, 'C'
    out dx, al
    .byte 0xea                           /* ljmp 0x08:mb2_entry64 */
    .long mb2_entry64
    .word 0x08
.Lhang:
    mov dx, 0x3f8
    mov al, '!'
    out dx, al
    hlt
    jmp .Lhang

.code64
mb2_entry64:
    mov dx, 0x3f8
    mov al, 'D'
    out dx, al
    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov fs, ax
    mov gs, ax
    mov rsp, OFFSET mb2_stack_top
    mov edi, dword ptr [mb2_saved]
    mov esi, dword ptr [mb2_saved + 4]
    call bios_entry
.Lhalt64:
    hlt
    jmp .Lhalt64

/* 32-bit-mode GDT: null + 64-bit code (0x08) + flat data (0x10). */
.section .rodata.boot,"a"
.balign 16
mb2_gdt:
    .quad 0x0000000000000000
    .quad 0x00AF9A000000FFFF             /* code64: L=1 D=0 P exec/read */
    .quad 0x00AF92000000FFFF             /* data64: P read/write */
mb2_gdt_ptr:
    .word . - mb2_gdt - 1
    .long mb2_gdt                        /* gdtr loaded in 32-bit mode */

.section .bss.boot,"aw",@nobits
.balign 4096
mb2_pml4:  .skip 4096
mb2_pdpt:  .skip 4096
mb2_pd0:   .skip 4 * 4096                /* PD0..PD3 contiguous */
.balign 16
mb2_saved: .skip 8
mb2_stack: .skip 262144
mb2_stack_top:
"#
);

extern "C" {
    static __kernel_start: u8;
    static __kernel_end: u8;
}

#[inline]
fn rd<T>(p: usize) -> T {
    // SAFETY: callers only name addresses inside the identity-mapped
    // multiboot2 info structure or the firmware area below 1 MiB.
    unsafe { (p as *const T).read_unaligned() }
}

/// Scan the legacy firmware area for an RSDP — fallback when GRUB
/// doesn't hand us tag 14/15. "RSD PTR " sits 16-byte aligned in the
/// EBDA (pointer at 0x40E) and in 0xE0000..0x100000.
fn scan_rsdp() -> Option<u64> {
    let ebda = (rd::<u16>(0x40E) as usize) << 4;
    for base in [ebda, 0xE0000] {
        let limit = if base == ebda { base + 1024 } else { 0x100000 };
        let mut p = base;
        while p + 36 <= limit {
            if rd::<u64>(p) == u64::from_le_bytes(*b"RSD PTR ") {
                return Some(p as u64);
            }
            p += 16;
        }
    }
    None
}

/// Multiboot2 boot path. `mbi` is the physical address of the info
/// structure; everything it names is identity-mapped by the trampoline.
#[no_mangle]
pub extern "C" fn bios_entry(magic: u32, mbi: u64) -> ! {
    let mut con = Console {
        uart: unsafe { uart::Uart16550::new(uart::COM1) },
        fb: None,
    };
    con.uart.init();
    log::init();
    log::set_console(&mut con);
    kprintln!(con, "rustux: Rust kernel alive under BIOS (multiboot2)");
    if magic != MB2_MAGIC {
        kprintln!(con, "rustux: bios: bad mb2 magic {magic:#x} -- halting");
        loop {
            unsafe { core::arch::asm!("hlt", options(nomem, nostack)) }
        }
    }

    // Walk the info tags. Layout: u32 total_size, u32 reserved, then
    // {u32 type, u32 size, payload} records 8-byte aligned, ended by a
    // type-0 tag. Cap the walk so a corrupt size can't run away.
    let base = mbi as usize;
    let total = rd::<u32>(base) as usize;
    let mut fb_desc = None::<(*mut u8, usize, usize, usize, usize, bool)>;
    let mut initrd = None::<(u64, usize)>;
    let mut initrd_span = (0u64, 0u64);
    let mut rsdp = None::<u64>;
    let mbi_span = (base as u64, base as u64 + total.max(8) as u64);
    if !(8..=(16 << 20)).contains(&total) {
        kprintln!(con, "rustux: bios: insane mbi size {total:#x}");
    } else {
        let mut p = base + 8;
        let end = base + total;
        while p + 8 <= end {
            let (ty, sz) = (rd::<u32>(p), rd::<u32>(p + 4) as usize);
            if ty == 0 || sz < 8 || p + sz > end + 8 {
                break;
            }
            match ty {
                // Memory map: u32 entry_size, u32 entry_version, then
                // {u64 base, u64 len, u32 type, u32 rsvd}; type 1 usable.
                6 if sz >= 16 => {
                    let (esz, ev) = (rd::<u32>(p + 8) as usize, rd::<u32>(p + 12));
                    if esz >= 20 && ev == 0 {
                        let mut e = p + 16;
                        while e + esz <= p + sz {
                            let (b, l, t) =
                                (rd::<u64>(e), rd::<u64>(e + 8), rd::<u32>(e + 16));
                            // Clamp the first MiB out of usable RAM: the
                            // IVT/BDA/real-mode area is never allocator
                            // fodder regardless of what E820 reports.
                            let (b, l) = if b < 0x100000 {
                                let cut = (0x100000 - b).min(l);
                                (b + cut, l - cut)
                            } else {
                                (b, l)
                            };
                            if l >= 4096 {
                                push_ent(b, l / 4096, t == 1);
                            }
                            e += esz;
                        }
                    }
                }
                // Framebuffer: u64 addr, u32 pitch, w, h, u8 bpp,
                // u8 type, u16 rsvd, then RGB color info (type 1).
                8 if sz >= 40 => {
                    let (a, pitch, w, h, bpp, fbt) = (
                        rd::<u64>(p + 8),
                        rd::<u32>(p + 16) as usize,
                        rd::<u32>(p + 20) as usize,
                        rd::<u32>(p + 24) as usize,
                        rd::<u8>(p + 28),
                        rd::<u8>(p + 29),
                    );
                    if bpp == 32 && fbt == 1 && pitch >= w * 4 {
                        let red_pos = rd::<u8>(p + 33);
                        let bgr = red_pos == 16;
                        if red_pos == 16 || red_pos == 0 {
                            fb_desc = Some((
                                a as *mut u8,
                                pitch * h,
                                pitch / 4,
                                w,
                                h,
                                bgr,
                            ));
                            kprintln!(con,
                                "rustux: bios: VBE LFB {w}x{h} pitch {pitch} at {a:#x} ({})",
                                if bgr { "bgr" } else { "rgb" }
                            );
                        }
                    }
                }
                // Module: u32 mod_start, u32 mod_end, cmdline\0 — the
                // first module is our initrd.cpio per grub.cfg.
                3 if sz >= 16 && initrd.is_none() => {
                    let (s, e) = (rd::<u32>(p + 8) as u64, rd::<u32>(p + 12) as u64);
                    if e > s {
                        initrd = Some((s, (e - s) as usize));
                        initrd_span = (s, e);
                    }
                }
                // RSDP copies (v1 tag 14 / v2 tag 15) — prefer v2.
                14 if rsdp.is_none() => rsdp = Some((p + 8) as u64),
                15 => rsdp = Some((p + 8) as u64),
                _ => {}
            }
            p += (sz + 7) & !7;
        }
    }

    if let Some((b, s, st, w, h, g)) = fb_desc {
        con.fb = fbcon::FbConsole::from_desc(b, s, st, w, h, g);
    }
    if let Some(fb) = con.fb.as_mut() {
        fb.splash();
        fb.banner();
    }

    match rsdp.or_else(scan_rsdp).and_then(crate::acpi::provide_rsdp) {
        Some(p) => kprintln!(con, "rustux: acpi: RSDP at {p:#x} (bios)"),
        None => kprintln!(con, "rustux: acpi: no RSDP found"),
    }
    match initrd {
        Some((a, l)) => kprintln!(con, "rustux: initrd: {l}B at {a:#x} (mb2 module)"),
        None => kprintln!(con, "rustux: initrd: none found"),
    }

    // Reserve what the loader put inside usable RAM: our image, the
    // mbi itself, and the initrd module. The first MiB is already
    // clamped out at push_ent time.
    let (ks, ke) = unsafe {
        (
            &__kernel_start as *const u8 as u64,
            &__kernel_end as *const u8 as u64,
        )
    };
    let resv = [(ks, ke), mbi_span, initrd_span];
    rustux_main(con, boot_map(), initrd, &resv)
}
