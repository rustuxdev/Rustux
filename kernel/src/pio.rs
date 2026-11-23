//! pio — x86 port I/O primitives shared by drivers.

#[inline]
pub unsafe fn outb(port: u16, v: u8) {
    unsafe {
        core::arch::asm!("out dx, al", in("dx") port, in("al") v, options(nomem, nostack));
    }
}

#[inline]
pub unsafe fn inb(port: u16) -> u8 {
    let v: u8;
    unsafe {
        core::arch::asm!("in al, dx", out("al") v, in("dx") port, options(nomem, nostack));
    }
    v
}

#[inline]
pub unsafe fn outw(port: u16, v: u16) {
    unsafe {
        core::arch::asm!("out dx, ax", in("dx") port, in("ax") v, options(nomem, nostack));
    }
}

#[inline]
pub unsafe fn outl(port: u16, v: u32) {
    unsafe {
        core::arch::asm!("out dx, eax", in("dx") port, in("eax") v, options(nomem, nostack));
    }
}

#[inline]
pub unsafe fn inl(port: u16) -> u32 {
    let v: u32;
    unsafe {
        core::arch::asm!("in eax, dx", out("eax") v, in("dx") port, options(nomem, nostack));
    }
    v
}

/// Save flags and mask IRQs — the irqsave half of the pair. Returns the
/// popped rflags; `irq_restore` re-enables IRQs only if they were on.
#[inline]
pub fn irq_save() -> u64 {
    let f: u64;
    // SAFETY: pushes rflags, then cli; the popped value restores IF later.
    unsafe {
        core::arch::asm!("pushfq; cli; pop {}", out(reg) f, options(nomem));
    }
    f
}

/// Restore flags saved by irq_save — re-enables IRQs only if they were on.
#[inline]
pub unsafe fn irq_restore(f: u64) {
    unsafe {
        core::arch::asm!("push {}; popfq", in(reg) f, options(nomem));
    }
}
