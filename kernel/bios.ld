/* bios.ld — link the kernel as a static ELF for Multiboot2/GRUB.
 *
 * VMA == LMA == physical: GRUB loads program headers at p_paddr and
 * jumps to e_entry in 32-bit protected mode. The image base is the
 * classic 1 MiB mark; the .mb2_header section must land inside the
 * first 32 KiB of the file, so .boot always comes first.
 */
ENTRY(mb2_entry)

SECTIONS {
    . = 0x100000;
    __kernel_start = .;

    .boot : ALIGN(8) {
        KEEP(*(.mb2_header))
        *(.text.boot)
        *(.rodata.boot)
        *(.bss.boot)
    }

    .text : ALIGN(4096) {
        *(.text .text.*)
    }

    .rodata : ALIGN(4096) {
        *(.rodata .rodata.*)
        *(.data.rel.ro .data.rel.ro.*)
    }

    .data : ALIGN(4096) {
        *(.data .data.*)
        *(.got .got.*)
    }

    .bss : ALIGN(4096) {
        *(COMMON)
        *(.bss .bss.*)
    }

    __kernel_end = ALIGN(4096);

    /DISCARD/ : {
        *(.comment)
        *(.note*)
        *(.eh_frame*)
    }
}
