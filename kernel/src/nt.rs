//! NT personality — the second syscall stack beside the Linux one.
//!
//! A task whose image is PE32+ runs with `pers == NT`: every
//! `syscall` it issues lands here instead of the Linux table, with
//! the real Windows x64 convention — the ntdll-style stub does
//! `mov r10, rcx; mov eax, nr; syscall`, so arg1 arrives in r10,
//! args 2-4 in rdx/r8/r9, and args 5+ on the user stack at
//! [rsp + 0x28] (the stub's return address plus four-slot shadow
//! space). Returns are NTSTATUS in rax, never -errno.
//!
//! Service numbers follow the Windows 10 x64 table; handlers are
//! honest implementations of the real signatures — 9-arg
//! NtWriteFile included — so a binary that talks the real ABI
//! works. What's not implemented answers STATUS_NOT_IMPLEMENTED,
//! which is what ntdll shows callers anyway.

use crate::user::{self, UCtx};

// NTSTATUS values this layer can return.
pub const STATUS_SUCCESS: u64 = 0x0000_0000;
pub const STATUS_INVALID_HANDLE: u64 = 0xC000_0008;
pub const STATUS_END_OF_FILE: u64 = 0xC000_0011;
pub const STATUS_NOT_IMPLEMENTED: u64 = 0xC000_0002;
pub const STATUS_INVALID_PARAMETER: u64 = 0xC000_000D;
pub const STATUS_ACCESS_VIOLATION: u64 = 0xC000_0005;
pub const STATUS_NO_MEMORY: u64 = 0xC000_0017;

// Windows 10 x64 service numbers for the implemented subset.
const NT_READ_FILE: u32 = 0x06;
const NT_WRITE_FILE: u32 = 0x08;
const NT_CLOSE: u32 = 0x0F;
const NT_ALLOCATE_VIRTUAL_MEMORY: u32 = 0x18;
const NT_FREE_VIRTUAL_MEMORY: u32 = 0x1E;
const NT_TERMINATE_PROCESS: u32 = 0x2C;
const NT_DELAY_EXECUTION: u32 = 0x34;

/// Handle table tags — a per-task `nth` slot's object kind. Real
/// handles are small indices (1-based) like the actual handle table;
/// std handles come pre-bound from the PEB process parameters.
pub const NTH_STDIN: u8 = 1;
pub const NTH_STDOUT: u8 = 2;
pub const NTH_STDERR: u8 = 3;
pub const MAX_NTH: usize = 8;

/// Read arg `i` (0-based) off the NT syscall frame: r10/rdx/r8/r9
/// then the user stack at rsp+0x28 like real KiSystemCall64.
fn arg(ctx: &UCtx, i: usize) -> u64 {
    match i {
        0 => ctx.r10,
        1 => ctx.rdx,
        2 => ctx.r8,
        3 => ctx.r9,
        _ => {
            let va = ctx.rsp + 0x28 + 8 * (i as u64 - 4);
            // SAFETY: user stack args — validated window below; a
            // bad rsp reads as 0 rather than faulting the kernel.
            if !user::range_ok(va, 8) {
                return 0;
            }
            unsafe { (va as *const u64).read_unaligned() }
        }
    }
}

fn iosb_complete(iosb: u64, status: u64, info: u64) {
    if iosb == 0 {
        return;
    }
    if !user::range_ok_w(iosb, 16) {
        return;
    }
    // SAFETY: validated user window under cur cr3.
    unsafe {
        (iosb as *mut u64).write_unaligned(status);
        ((iosb + 8) as *mut u64).write_unaligned(info);
    }
}

/// NtReadFile/NtWriteFile shared shape: (handle, event, apc, apcctx,
/// iosb, buffer, length, byteoffset, key) — event/APC/offset/key are
/// accepted-and-ignored like a synchronous call on real Windows.
fn rw_file(ctx: &mut UCtx, write: bool) -> u64 {
    let h = arg(ctx, 0);
    let iosb = arg(ctx, 4);
    let buf = arg(ctx, 5);
    let len = arg(ctx, 6);
    let kind = user::nt_handle_kind(h);
    match (kind, write) {
        (NTH_STDIN, false) => {}
        (NTH_STDOUT | NTH_STDERR, true) => {}
        (0, _) => return STATUS_INVALID_HANDLE,
        (_, w) => {
            iosb_complete(iosb, STATUS_INVALID_PARAMETER, 0);
            let _ = w;
            return STATUS_INVALID_PARAMETER;
        }
    }
    if len > 0 && !user::range_ok(buf, len) && write {
        iosb_complete(iosb, STATUS_ACCESS_VIOLATION, 0);
        return STATUS_ACCESS_VIOLATION;
    }
    let (status, n) = if write {
        (STATUS_SUCCESS, user::nt_console_write(ctx, buf, len))
    } else {
        user::nt_stdin_read(ctx, buf, len)
    };
    iosb_complete(iosb, status, n);
    status
}

/// NtClose(handle): std handles are system-owned — closing one is
/// valid and removes it from the table (Linux's close(1) analogue).
fn nt_close(ctx: &mut UCtx) -> u64 {
    let h = arg(ctx, 0);
    if !user::nt_handle_close(h) {
        return STATUS_INVALID_HANDLE;
    }
    STATUS_SUCCESS
}

/// NtAllocateVirtualMemory(process, &base, zerobits, &size, type,
/// protect): anonymous commit at a hint or a bump arena. MEM_RESERVE
/// alone isn't honored — every page is committed on demand like the
/// rest of our mm.
fn nt_alloc_vm(ctx: &mut UCtx) -> u64 {
    let base_ptr = arg(ctx, 1);
    let size_ptr = arg(ctx, 3);
    // Write-side check: results land back through these pointers —
    // a read-only probe address must fault like a real AV.
    if !user::range_ok_w(base_ptr, 8) || !user::range_ok_w(size_ptr, 8) {
        return STATUS_ACCESS_VIOLATION;
    }
    // SAFETY: validated user window.
    let (hint, mut size) = unsafe {
        (
            (base_ptr as *const u64).read_unaligned(),
            (size_ptr as *const u64).read_unaligned(),
        )
    };
    size = (size + 0xfff) & !0xfff;
    if size == 0 {
        return STATUS_INVALID_PARAMETER;
    }
    let Some(va) = user::nt_alloc_pages(hint, size) else {
        return STATUS_NO_MEMORY;
    };
    // SAFETY: both pointers validated above.
    unsafe {
        (base_ptr as *mut u64).write_unaligned(va);
        (size_ptr as *mut u64).write_unaligned(size);
    }
    STATUS_SUCCESS
}

/// NtFreeVirtualMemory(process, &base, &size, type): MEM_RELEASE
/// (0x8000) unmaps every page in [base, base+size) — the Win32
/// layer's free()/HeapFree path recovers the extent from the
/// malloc header the VirtualAlloc thunk wrote. MEM_DECOMMIT alone
/// isn't honored (no reserve/commit split in our mm).
fn nt_free_vm(ctx: &mut UCtx) -> u64 {
    if arg(ctx, 0) != u64::MAX {
        return STATUS_INVALID_PARAMETER;
    }
    let bp = arg(ctx, 1);
    let sp = arg(ctx, 2);
    if !user::range_ok_w(bp, 8) || !user::range_ok_w(sp, 8) {
        return STATUS_ACCESS_VIOLATION;
    }
    if arg(ctx, 3) & 0x8000 == 0 {
        return STATUS_NOT_IMPLEMENTED;
    }
    // SAFETY: both pointers validated above.
    let (base, size) = unsafe {
        (
            (bp as *const u64).read_unaligned(),
            (sp as *const u64).read_unaligned(),
        )
    };
    if base == 0 || base & 0xfff != 0 {
        return STATUS_INVALID_PARAMETER;
    }
    user::nt_free_pages(base, size);
    STATUS_SUCCESS
}

/// NtDelayExecution(alertable, &interval): interval is a signed
/// 100-ns duration — negative means relative to now, the common
/// form. Alertable sleeps end early on APC delivery; we have none,
/// so both forms are plain deadline waits.
fn nt_delay(ctx: &mut UCtx) -> u64 {
    let ip = arg(ctx, 1);
    if !user::range_ok(ip, 8) {
        return STATUS_ACCESS_VIOLATION;
    }
    // SAFETY: validated user window.
    let interval = unsafe { (ip as *const i64).read_unaligned() };
    let ms = if interval < 0 { (-interval) / 10_000 } else { 0 };
    if ms > 0 {
        user::sleep_ms(ctx, ms as u64);
    }
    STATUS_SUCCESS
}

/// Import resolver: an export name from a PE's ILT to its service
/// number. Only ntdll's syscall stubs exist — the names a real
/// ntdll.dll exports (Zw* aliases included, they share numbers).
pub fn service_for_name(name: &[u8]) -> Option<u32> {
    // Strip the Nt/Zw prefix — both are the same service.
    let n = name
        .strip_prefix(b"Nt")
        .or(name.strip_prefix(b"Zw"))
        .unwrap_or(name);
    Some(match n {
        b"ReadFile" => NT_READ_FILE,
        b"WriteFile" => NT_WRITE_FILE,
        b"Close" => NT_CLOSE,
        b"AllocateVirtualMemory" => NT_ALLOCATE_VIRTUAL_MEMORY,
        b"FreeVirtualMemory" => NT_FREE_VIRTUAL_MEMORY,
        b"TerminateProcess" => NT_TERMINATE_PROCESS,
        b"DelayExecution" => NT_DELAY_EXECUTION,
        _ => return None,
    })
}

/// Entry from the syscall stub: `nr` is ctx.rax. The return goes
/// back through ctx.rax as NTSTATUS.
pub fn dispatch(ctx: &mut UCtx, nr: u32) -> u64 {
    match nr {
        NT_READ_FILE => rw_file(ctx, false),
        NT_WRITE_FILE => rw_file(ctx, true),
        NT_CLOSE => nt_close(ctx),
        NT_ALLOCATE_VIRTUAL_MEMORY => nt_alloc_vm(ctx),
        NT_FREE_VIRTUAL_MEMORY => nt_free_vm(ctx),
        NT_DELAY_EXECUTION => nt_delay(ctx),
        NT_TERMINATE_PROCESS => {
            // hProcess == (HANDLE)-1 means self; anything else is a
            // kill we don't model yet — the common case is self-exit.
            let status = arg(ctx, 1);
            user::task_exit(status);
        }
        _ => STATUS_NOT_IMPLEMENTED,
    }
}
