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
pub const STATUS_INFO_LENGTH_MISMATCH: u64 = 0xC000_0004;
pub const STATUS_INVALID_INFO_CLASS: u64 = 0xC000_0003;
pub const STATUS_MEMORY_NOT_ALLOCATED: u64 = 0xC000_00A0;
pub const STATUS_ACCESS_DENIED: u64 = 0xC000_0022;
pub const STATUS_OBJECT_NAME_INVALID: u64 = 0xC000_0033;
pub const STATUS_OBJECT_NAME_NOT_FOUND: u64 = 0xC000_0034;
pub const STATUS_OBJECT_NAME_COLLISION: u64 = 0xC000_0035;
pub const STATUS_OBJECT_PATH_NOT_FOUND: u64 = 0xC000_003A;
pub const STATUS_INSUFFICIENT_RESOURCES: u64 = 0xC000_009A;
pub const STATUS_NO_MORE_FILES: u64 = 0x8000_0006;
/// STATUS_MAPPED_FILE_SIZE_ZERO — file-backed section requested
/// with no size on an empty file.
pub const STATUS_MAPPED_FILE_SIZE_ZERO: u64 = 0xC000_011E;

// Windows 10 x64 service numbers for the implemented subset.
const NT_WAIT_FOR_SINGLE_OBJECT: u32 = 0x04;
const NT_READ_FILE: u32 = 0x06;
const NT_WRITE_FILE: u32 = 0x08;
const NT_CLOSE: u32 = 0x0F;
const NT_QUERY_INFORMATION_FILE: u32 = 0x11;
const NT_ALLOCATE_VIRTUAL_MEMORY: u32 = 0x18;
const NT_FREE_VIRTUAL_MEMORY: u32 = 0x1E;
const NT_QUERY_VIRTUAL_MEMORY: u32 = 0x23;
const NT_QUERY_INFORMATION_THREAD: u32 = 0x25;
const NT_SET_INFORMATION_FILE: u32 = 0x27;
const NT_MAP_VIEW_OF_SECTION: u32 = 0x28;
const NT_UNMAP_VIEW_OF_SECTION: u32 = 0x2A;
const NT_TERMINATE_PROCESS: u32 = 0x2C;
const NT_DELAY_EXECUTION: u32 = 0x34;
const NT_QUERY_DIRECTORY_FILE: u32 = 0x35;
const NT_FLUSH_VIRTUAL_MEMORY: u32 = 0x3B;
const NT_CREATE_SECTION: u32 = 0x4A;
const NT_PROTECT_VIRTUAL_MEMORY: u32 = 0x50;
const NT_QUERY_SECTION: u32 = 0x51;
const NT_RESUME_THREAD: u32 = 0x52;
const NT_TERMINATE_THREAD: u32 = 0x53;
const NT_CREATE_FILE: u32 = 0x55;
const NT_CREATE_THREAD_EX: u32 = 0xC1;

// Rustux-private services — no real NT counterparts. Real Windows
// implements heaps in ntdll userspace (RtlAllocateHeap et al.); our
// Win32 thunk layer marshals HeapAlloc/ReAlloc/Free/Size into these
// so the block table lives kernel-side, where an app's heap
// corruption can never forge block metadata.
const RUX_HEAP_ALLOC: u32 = 0xF0;
const RUX_HEAP_REALLOC: u32 = 0xF1;
const RUX_HEAP_FREE: u32 = 0xF2;
const RUX_HEAP_SIZE: u32 = 0xF3;
/// Private module-loader services — LdrLoadDll is usermode ntdll
/// on real Windows, so these have no canonical service number.
const RUX_LOAD_DLL: u32 = 0xF4;
const RUX_GET_PROC: u32 = 0xF5;
const RUX_FREE_DLL: u32 = 0xF6;
const RUX_DLL_ATTACH: u32 = 0xF7;
const RUX_MOD_HANDLE: u32 = 0xF8;
const RUX_DLL_DETACH: u32 = 0xF9;
const RUX_FREE_FIN: u32 = 0xFA;

/// Handle table tags — a per-task `nth` slot's object kind. Real
/// handles are small indices (1-based) like the actual handle table;
/// std handles come pre-bound from the PEB process parameters.
pub const NTH_STDIN: u8 = 1;
pub const NTH_STDOUT: u8 = 2;
pub const NTH_STDERR: u8 = 3;
/// An open file — the slot's `nth_fd` holds the task fd.
pub const NTH_FILE: u8 = 4;
/// A waitable thread object — `nth_fd` holds the NT_THREADS index.
pub const NTH_THREAD: u8 = 5;
/// A section object (CreateFileMapping) — `nth_fd` holds the
/// NT_SECTIONS index.
pub const NTH_SECTION: u8 = 6;
pub const MAX_NTH: usize = 16;

/// WAIT_TIMEOUT — WaitForSingleObject's deadline answer.
pub const STATUS_TIMEOUT: u64 = 0x0000_0102;
/// The "still running" pseudo-status THREAD_BASIC_INFORMATION
/// reports — Win32's STILL_ACTIVE.
pub const STATUS_STILL_ACTIVE: u64 = 0x0000_0103;

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

/// A Linux -errno return (as u64) to NTSTATUS — the file path's
/// only error channel.
fn errno_status(r: u64) -> u64 {
    if (r as i64) >= 0 {
        return STATUS_SUCCESS;
    }
    match r as i64 {
        -2 => STATUS_OBJECT_NAME_NOT_FOUND,   // ENOENT
        -9 => STATUS_INVALID_HANDLE,          // EBADF
        -13 | -30 => STATUS_ACCESS_DENIED,    // EACCES | EROFS
        -17 => STATUS_OBJECT_NAME_COLLISION,  // EEXIST
        -20 => STATUS_OBJECT_PATH_NOT_FOUND,  // ENOTDIR
        -24 => STATUS_INSUFFICIENT_RESOURCES, // EMFILE
        _ => STATUS_INVALID_PARAMETER,
    }
}

/// NtReadFile/NtWriteFile shared shape: (handle, event, apc, apcctx,
/// iosb, buffer, length, byteoffset, key) — event/APC/key are
/// accepted-and-ignored like a synchronous call on real Windows.
/// A NULL ByteOffset reads/writes at the shared OFD position;
/// a non-NULL one maps to pread (writes return NOT_IMPLEMENTED).
fn rw_file(ctx: &mut UCtx, write: bool) -> u64 {
    let h = arg(ctx, 0);
    let iosb = arg(ctx, 4);
    let buf = arg(ctx, 5);
    let len = arg(ctx, 6);
    let kind = user::nt_handle_kind(h);
    match (kind, write) {
        (NTH_STDIN, false) | (NTH_FILE, _) => {}
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
    if kind == NTH_FILE {
        let Some(fd) = user::nt_handle_fd(h) else {
            return STATUS_INVALID_HANDLE;
        };
        let offp = arg(ctx, 7);
        let r = if offp != 0 {
            if !user::range_ok(offp, 8) {
                iosb_complete(iosb, STATUS_ACCESS_VIOLATION, 0);
                return STATUS_ACCESS_VIOLATION;
            }
            // SAFETY: validated user window.
            let off =
                unsafe { (offp as *const i64).read_unaligned() };
            if write {
                iosb_complete(iosb, STATUS_NOT_IMPLEMENTED, 0);
                return STATUS_NOT_IMPLEMENTED;
            }
            user::fd_pread(fd, buf, len, off)
        } else if write {
            user::fd_write(ctx, fd, buf, len)
        } else {
            user::fd_read(ctx, fd, buf, len)
        };
        if (r as i64) < 0 {
            let st = errno_status(r);
            iosb_complete(iosb, st, 0);
            return st;
        }
        iosb_complete(iosb, STATUS_SUCCESS, r);
        return STATUS_SUCCESS;
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

/// NtCreateFile(&handle, access, oa, iosb, allocsize, attr, share,
/// disp, options, ea, ealen): the OBJECT_ATTRIBUTES carries a
/// UNICODE_STRING name which we translate to a VFS path — `\??\`
/// and a drive prefix are stripped, `\` becomes `/`, ASCII only.
/// RootDirectory!=0 is an honest NOT_IMPLEMENTED (no dir-relative
/// opens yet). ACCESS_MASK maps GENERIC_READ/WRITE; disposition
/// maps to O_CREAT/O_EXCL/O_TRUNC; FILE_DIRECTORY_FILE to
/// O_DIRECTORY. The minted handle is an nth slot bound to the fd.
fn nt_create_file(ctx: &mut UCtx) -> u64 {
    let hout = arg(ctx, 0);
    let access = arg(ctx, 1) as u32;
    let oa = arg(ctx, 2);
    let iosb = arg(ctx, 3);
    let disp = arg(ctx, 7) as u32;
    let options = arg(ctx, 8) as u32;
    if !user::range_ok_w(hout, 8) || !user::range_ok(oa, 48) {
        return STATUS_ACCESS_VIOLATION;
    }
    // SAFETY: OA validated above — RootDirectory @8, ObjectName @16.
    let (root, us) = unsafe {
        (
            (oa as *const u64).add(1).read_unaligned(),
            (oa as *const u64).add(2).read_unaligned(),
        )
    };
    if root != 0 {
        return STATUS_NOT_IMPLEMENTED;
    }
    if !user::range_ok(us, 16) {
        return STATUS_ACCESS_VIOLATION;
    }
    // UNICODE_STRING: Length u16 @0, MaximumLength u16 @2,
    // Buffer (UTF-16) @8. Only Length is authoritative.
    let (ulen, ubuf) = unsafe {
        (
            (us as *const u16).read_unaligned() as u64,
            (us as *const u64).add(1).read_unaligned(),
        )
    };
    if ulen == 0 || ulen > 254 || ulen & 1 != 0 {
        return STATUS_OBJECT_NAME_INVALID;
    }
    if !user::range_ok(ubuf, ulen) {
        return STATUS_ACCESS_VIOLATION;
    }
    let mut path = [0u8; 256];
    let mut n = 0usize;
    for i in 0..(ulen / 2) as usize {
        // SAFETY: ubuf window validated for ulen bytes.
        let c = unsafe {
            (ubuf as *const u16).add(i).read_unaligned()
        };
        if c > 0x7f {
            return STATUS_OBJECT_NAME_INVALID;
        }
        path[n] = if c == b'\\' as u16 { b'/' } else { c as u8 };
        n += 1;
    }
    // `\??\`-style NT prefixes (already `/??/` after the slash
    // rewrite) and a DOS drive letter are namespace, not path.
    let mut st = 0usize;
    if n >= 4 && &path[..4] == b"/??/" {
        st = 4;
    }
    if n - st >= 2 && path[st + 1] == b':' && path[st].is_ascii_alphabetic() {
        st += 2;
    }
    if st >= n {
        return STATUS_OBJECT_NAME_INVALID;
    }
    // ACCESS_MASK: GENERIC_READ/WRITE sit at the top bits.
    let mut oflags = match (
        access & 0x8000_0000 != 0,
        access & 0x4000_0000 != 0,
    ) {
        (true, false) => 0u64, // O_RDONLY
        (false, true) => 1,    // O_WRONLY
        _ => 2,                // O_RDWR
    };
    // FILE_OPEN_IF..FILE_OVERWRITE_IF / CREATE / SUPERSEDE.
    match disp {
        1 => oflags |= 0o200 | 0o100,  // CREATE_NEW: O_EXCL|O_CREAT
        2 => oflags |= 0o100 | 0o1000, // CREATE_ALWAYS: O_CREAT|O_TRUNC
        3 => {}                        // OPEN_EXISTING
        4 => oflags |= 0o100,          // OPEN_ALWAYS: O_CREAT
        5 => oflags |= 0o1000,         // TRUNCATE_EXISTING: O_TRUNC
        _ => return STATUS_INVALID_PARAMETER,
    }
    if options & 1 != 0 {
        oflags |= 0o200000; // FILE_DIRECTORY_FILE -> O_DIRECTORY
    }
    // NT names go through the same `.`/`..` canon as the Linux open
    // path — without it `.` never resolves to the root dir.
    let (cpath, cn) = match user::canon_path(u64::MAX, &path[st..n]) {
        Ok(x) => x,
        Err(e) => {
            iosb_complete(iosb, errno_status(e), 0);
            return errno_status(e);
        }
    };
    let r = user::fd_open(&cpath[..cn], oflags, 0o644);
    if (r as i64) < 0 {
        iosb_complete(iosb, errno_status(r), 0);
        return errno_status(r);
    }
    let Some(h) = user::nt_handle_alloc_file(r) else {
        user::fd_close(r);
        return STATUS_INSUFFICIENT_RESOURCES;
    };
    // SAFETY: hout validated above.
    unsafe { (hout as *mut u64).write_unaligned(h) };
    iosb_complete(iosb, STATUS_SUCCESS, 2); // FILE_OPENED
    STATUS_SUCCESS
}

/// NtQueryInformationFile(handle, iosb, info, len, class): the
/// two classes the Win32 layer needs — FileStandardInformation(5)
/// for GetFileSizeEx and FilePositionInformation(14) for
/// SetFilePointerEx's FILE_CURRENT/FILE_END bases.
fn nt_query_info(ctx: &mut UCtx) -> u64 {
    let h = arg(ctx, 0);
    let iosb = arg(ctx, 1);
    let info = arg(ctx, 2);
    let ilen = arg(ctx, 3);
    let class = arg(ctx, 4) as u32;
    let Some(fd) = user::nt_handle_fd(h) else {
        return STATUS_INVALID_HANDLE;
    };
    let Some((size, pos, is_dir)) = user::nt_file_info(fd) else {
        return STATUS_INVALID_HANDLE;
    };
    match class {
        // {allocsize i64, eof i64, links u32, del u8, dir u8, pad}
        5 => {
            if ilen < 24 {
                return STATUS_INFO_LENGTH_MISMATCH;
            }
            if !user::range_ok_w(info, 24) {
                return STATUS_ACCESS_VIOLATION;
            }
            // SAFETY: validated user window.
            unsafe {
                let p = info as *mut u64;
                p.write_unaligned(size);
                p.add(1).write_unaligned(size);
                // links u32 @16 = 1, del u8 @20 = 0, dir u8 @21.
                p.add(2).write_unaligned(1 | (is_dir as u64) << 40);
            }
            iosb_complete(iosb, STATUS_SUCCESS, 24);
        }
        // {CurrentByteOffset i64}
        14 => {
            if ilen < 8 {
                return STATUS_INFO_LENGTH_MISMATCH;
            }
            if !user::range_ok_w(info, 8) {
                return STATUS_ACCESS_VIOLATION;
            }
            // SAFETY: validated user window.
            unsafe { (info as *mut u64).write_unaligned(pos) };
            iosb_complete(iosb, STATUS_SUCCESS, 8);
        }
        _ => {
            iosb_complete(iosb, STATUS_INVALID_INFO_CLASS, 0);
            return STATUS_INVALID_INFO_CLASS;
        }
    }
    STATUS_SUCCESS
}

/// UNICODE_STRING → ASCII bytes: probes the US struct and its
/// buffer, rejects non-ASCII, maps '\\' → '/'. `out`'s capacity
/// doubles as the length bound. Only Length is authoritative.
fn us_to_ascii(us: u64, out: &mut [u8]) -> Option<usize> {
    if !user::range_ok(us, 16) {
        return None;
    }
    // SAFETY: US window validated above.
    let (ulen, ubuf) = unsafe {
        (
            (us as *const u16).read_unaligned() as u64,
            (us as *const u64).add(1).read_unaligned(),
        )
    };
    if ulen == 0 || ulen & 1 != 0 || ulen as usize > out.len() * 2 {
        return None;
    }
    if !user::range_ok(ubuf, ulen) {
        return None;
    }
    for i in 0..(ulen / 2) as usize {
        // SAFETY: ubuf window validated for ulen bytes.
        let c = unsafe { (ubuf as *const u16).add(i).read_unaligned() };
        if c > 0x7f {
            return None;
        }
        out[i] = if c == b'\\' as u16 { b'/' } else { c as u8 };
    }
    Some((ulen / 2) as usize)
}

/// NtQueryDirectoryFile(h, event, apc_r, apc_c, iosb, info, len,
/// class, single, fname, restart): class 1 FileDirectoryInformation
/// only. A FileName UNICODE_STRING stores the wildcard on the
/// handle; the OFD stream cursor walks the flat-VFS component list.
fn nt_query_dir(ctx: &mut UCtx) -> u64 {
    let h = arg(ctx, 0);
    let iosb = arg(ctx, 4);
    let info = arg(ctx, 5);
    let ilen = arg(ctx, 6);
    let class = arg(ctx, 7) as u32;
    let single = arg(ctx, 8) != 0;
    let fname = arg(ctx, 9);
    let restart = arg(ctx, 10) != 0;
    let Some(fd) = user::nt_handle_fd(h) else {
        return STATUS_INVALID_HANDLE;
    };
    if class != 1 {
        iosb_complete(iosb, STATUS_INVALID_INFO_CLASS, 0);
        return STATUS_INVALID_INFO_CLASS;
    }
    if ilen == 0 || ilen > 0x100_000 || !user::range_ok_w(info, ilen) {
        return STATUS_ACCESS_VIOLATION;
    }
    if fname != 0 {
        let mut pat = [0u8; 96];
        let Some(n) = us_to_ascii(fname, &mut pat[1..]) else {
            return STATUS_OBJECT_NAME_INVALID;
        };
        user::nt_dir_pattern_set(h, &pat[1..1 + n]);
    }
    if restart {
        user::nt_dir_seek(fd, 0);
    }
    let mut pat = [0u8; 96];
    let plen = user::nt_dir_pattern(h, &mut pat);
    let pat = &pat[..plen];
    let Some(mut idx) = user::nt_dir_pos(fd) else {
        iosb_complete(iosb, STATUS_INVALID_HANDLE, 0);
        return STATUS_INVALID_HANDLE;
    };
    let mut name = [0u8; 256];
    let mut off = 0usize;
    let mut prev: Option<usize> = None;
    loop {
        let Some((nlen, size, isdir, next)) =
            user::nt_dir_next(fd, idx, pat, &mut name)
        else {
            break;
        };
        let rec = (64 + nlen * 2 + 7) & !7;
        if off + rec > ilen as usize {
            break; // cursor not committed — entry stays pending
        }
        let base = info + off as u64;
        // Backpatch the previous record's NextEntryOffset — it is
        // followed by this one.
        if let Some(p) = prev {
            // SAFETY: [info, info+ilen) validated; p+4 <= off < ilen.
            unsafe {
                ((info + p as u64) as *mut u32)
                    .write_unaligned((off - p) as u32)
            };
        }
        // SAFETY: off+rec <= ilen inside the validated window; all
        // writes land in the record's own 64+2*nlen span.
        unsafe {
            ((base) as *mut u32).write_unaligned(0); // NextEntryOffset
            ((base + 4) as *mut u32).write_unaligned(idx as u32);
            for t in 0..4u64 {
                ((base + 8 + t * 8) as *mut u64).write_unaligned(0);
            }
            ((base + 40) as *mut u64).write_unaligned(size);
            ((base + 48) as *mut u64).write_unaligned(size);
            ((base + 56) as *mut u32).write_unaligned(if isdir {
                0x10 // FILE_ATTRIBUTE_DIRECTORY
            } else {
                0x80 // FILE_ATTRIBUTE_NORMAL
            });
            ((base + 60) as *mut u32).write_unaligned((nlen * 2) as u32);
            for (i, &c) in name[..nlen].iter().enumerate() {
                ((base + 64 + i as u64 * 2) as *mut u16)
                    .write_unaligned(c as u16);
            }
        }
        prev = Some(off);
        off += rec;
        idx = next;
        if single {
            break;
        }
    }
    user::nt_dir_seek(fd, idx);
    if off == 0 {
        iosb_complete(iosb, STATUS_NO_MORE_FILES, 0);
        return STATUS_NO_MORE_FILES;
    }
    iosb_complete(iosb, STATUS_SUCCESS, off as u64);
    STATUS_SUCCESS
}

/// RUX_HEAP_ALLOC(f, sz) -> ptr|0: f != 0 is zero-memory.
fn nt_heap_alloc_svc(ctx: &mut UCtx) -> u64 {
    user::nt_heap_alloc(arg(ctx, 1), arg(ctx, 0) != 0).unwrap_or(0)
}

/// RUX_HEAP_REALLOC(p, sz, f) -> ptr|0.
fn nt_heap_realloc_svc(ctx: &mut UCtx) -> u64 {
    user::nt_heap_realloc(arg(ctx, 0), arg(ctx, 1), arg(ctx, 2) != 0)
        .unwrap_or(0)
}

/// RUX_HEAP_FREE(p) -> BOOL.
fn nt_heap_free_svc(ctx: &mut UCtx) -> u64 {
    user::nt_heap_free(arg(ctx, 0)) as u64
}

/// RUX_HEAP_SIZE(p) -> size|SIZE_T(-1).
fn nt_heap_size_svc(ctx: &mut UCtx) -> u64 {
    user::nt_heap_size(arg(ctx, 0)).unwrap_or(u64::MAX)
}

/// NtSetInformationFile(handle, iosb, info, len, class):
/// FilePositionInformation(14) sets the shared OFD position to an
/// absolute offset — SetFilePointerEx pre-composes FILE_CURRENT /
/// FILE_END via a query, so an absolute store is all we need.
fn nt_set_info(ctx: &mut UCtx) -> u64 {
    let h = arg(ctx, 0);
    let iosb = arg(ctx, 1);
    let info = arg(ctx, 2);
    let ilen = arg(ctx, 3);
    let class = arg(ctx, 4) as u32;
    let Some(fd) = user::nt_handle_fd(h) else {
        return STATUS_INVALID_HANDLE;
    };
    match class {
        // FileDispositionInformation: a BOOLEAN — the file unlinks
        // at last close; FALSE cancels a pending delete.
        13 => {
            if ilen < 1 {
                return STATUS_INFO_LENGTH_MISMATCH;
            }
            if !user::range_ok(info, 1) {
                return STATUS_ACCESS_VIOLATION;
            }
            // SAFETY: validated user window.
            let on =
                unsafe { (info as *const u8).read_unaligned() } != 0;
            if !user::nt_fd_delete_pending(fd, on) {
                return STATUS_INVALID_HANDLE;
            }
            iosb_complete(iosb, STATUS_SUCCESS, 0);
        }
        // {CurrentByteOffset i64} — absolute OFD position.
        14 => {
            if ilen < 8 {
                return STATUS_INFO_LENGTH_MISMATCH;
            }
            if !user::range_ok(info, 8) {
                return STATUS_ACCESS_VIOLATION;
            }
            // SAFETY: validated user window.
            let pos =
                unsafe { (info as *const i64).read_unaligned() };
            if pos < 0 {
                return STATUS_INVALID_PARAMETER;
            }
            let r = user::fd_lseek(fd, pos, 0);
            if (r as i64) < 0 {
                iosb_complete(iosb, errno_status(r), 0);
                return errno_status(r);
            }
            iosb_complete(iosb, STATUS_SUCCESS, 0);
        }
        _ => {
            iosb_complete(iosb, STATUS_INVALID_INFO_CLASS, 0);
            return STATUS_INVALID_INFO_CLASS;
        }
    }
    STATUS_SUCCESS
}

/// NtAllocateVirtualMemory(process, &base, zerobits, &size, type,
/// protect): MEM_RESERVE places an RNG_RES ledger entry — VA held,
/// no frames (a 1 GiB reservation costs nothing). MEM_COMMIT pages
/// in a window: inside a reservation it commits in place, at free
/// VA it's an implicit reserve+commit, over committed pages it's a
/// no-op success. Both flags place then commit, the common form.
/// `protect` is honored via rng_from_prot — the page-table flags,
/// not just bookkeeping.
fn nt_alloc_vm(ctx: &mut UCtx) -> u64 {
    const MEM_RESERVE: u64 = 0x2000;
    const MEM_COMMIT: u64 = 0x1000;
    let base_ptr = arg(ctx, 1);
    let size_ptr = arg(ctx, 3);
    // Write-side check: results land back through these pointers —
    // a read-only probe address must fault like a real AV.
    if !user::range_ok_w(base_ptr, 8) || !user::range_ok_w(size_ptr, 8) {
        return STATUS_ACCESS_VIOLATION;
    }
    let (ty, prot) = (arg(ctx, 4), arg(ctx, 5) as u32);
    let Some((rfl, pfl)) = user::rng_from_prot(prot) else {
        return STATUS_INVALID_PARAMETER;
    };
    if ty & (MEM_RESERVE | MEM_COMMIT) == 0 {
        return STATUS_INVALID_PARAMETER;
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
    let va = if ty & MEM_RESERVE != 0 {
        // Reserve the window, then commit it too if asked.
        let Some(va) = user::nt_alloc_pages(hint, size, false, rfl, pfl) else {
            return STATUS_NO_MEMORY;
        };
        if ty & MEM_COMMIT != 0 && !user::nt_commit_window_cur(va, size, rfl, pfl) {
            // Don't leave a reservation behind on a call the
            // caller believes failed.
            user::nt_free_pages(va, size);
            return STATUS_NO_MEMORY;
        }
        va
    } else {
        // Commit-only: hint lands inside a reservation or on free
        // VA — the window routine handles both plus re-commit.
        let (base, owned) = if hint != 0 {
            (hint & !0xfff, false)
        } else {
            let Some(va) = user::nt_alloc_pages(0, size, false, rfl, pfl) else {
                return STATUS_NO_MEMORY;
            };
            (va, true)
        };
        if !user::nt_commit_window_cur(base, size, rfl, pfl) {
            if owned {
                user::nt_free_pages(base, size);
            }
            return STATUS_NO_MEMORY;
        }
        base
    };
    // SAFETY: both pointers validated above.
    unsafe {
        (base_ptr as *mut u64).write_unaligned(va);
        (size_ptr as *mut u64).write_unaligned(size);
    }
    STATUS_SUCCESS
}

/// NtFreeVirtualMemory(process, &base, &size, type): MEM_RELEASE
/// drops the whole region — the recorded extent is looked up from
/// the ledger (a caller may legally pass size=0). MEM_DECOMMIT
/// returns pages but keeps the reservation. Anything else is
/// invalid like real Windows.
fn nt_free_vm(ctx: &mut UCtx) -> u64 {
    const MEM_DECOMMIT: u64 = 0x4000;
    const MEM_RELEASE: u64 = 0x8000;
    if arg(ctx, 0) != u64::MAX {
        return STATUS_INVALID_PARAMETER;
    }
    let bp = arg(ctx, 1);
    let sp = arg(ctx, 2);
    if !user::range_ok_w(bp, 8) || !user::range_ok_w(sp, 8) {
        return STATUS_ACCESS_VIOLATION;
    }
    let ty = arg(ctx, 3);
    // SAFETY: both pointers validated above.
    let (base, mut size) = unsafe {
        (
            (bp as *const u64).read_unaligned(),
            (sp as *const u64).read_unaligned(),
        )
    };
    if base == 0 || base & 0xfff != 0 {
        return STATUS_INVALID_PARAMETER;
    }
    if ty & MEM_DECOMMIT != 0 {
        size = (size + 0xfff) & !0xfff;
        return if user::nt_decommit_window_cur(base, size) {
            STATUS_SUCCESS
        } else {
            STATUS_MEMORY_NOT_ALLOCATED
        };
    }
    if ty & MEM_RELEASE == 0 {
        return STATUS_INVALID_PARAMETER;
    }
    // size==0 on release names the whole covering region.
    if size == 0 {
        let Some(ext) = user::nt_region_extent(base) else {
            return STATUS_MEMORY_NOT_ALLOCATED;
        };
        size = ext;
    }
    user::nt_free_pages(base, size);
    STATUS_SUCCESS
}

/// NtCreateSection(&hout, access, oa, &maxsize, protect, attributes,
/// file): SEC_COMMIT sections only — SEC_IMAGE needs the loader.
/// A file handle pins the OFD's backing content; a NULL/−1 file
/// handle makes a paging-file (anonymous) section that requires a
/// nonzero MaximumSize.
fn nt_create_section(ctx: &mut UCtx) -> u64 {
    const SEC_COMMIT: u64 = 0x0800_0000;
    let hout = arg(ctx, 0);
    let szp = arg(ctx, 3);
    let prot = arg(ctx, 4) as u32;
    let attrib = arg(ctx, 5);
    let fh = arg(ctx, 6);
    if !user::range_ok_w(hout, 8) {
        return STATUS_ACCESS_VIOLATION;
    }
    if szp != 0 && !user::range_ok(szp, 8) {
        return STATUS_ACCESS_VIOLATION;
    }
    if attrib & !SEC_COMMIT != 0 {
        return STATUS_NOT_IMPLEMENTED; // SEC_IMAGE/SEC_RESERVE: later
    }
    // Win32 PAGE_* low byte the section remembers.
    let page = (prot & 0xff) as u8;
    if page != 0x02 && page != 0x04 && page != 0x08 {
        return STATUS_INVALID_PARAMETER;
    }
    let (oi, accmode) = if fh == 0 || fh == u64::MAX {
        (0xffusize, 0u8)
    } else {
        match user::nt_handle_file_oi(fh) {
            Some((o, a)) => (o, a),
            None => return STATUS_INVALID_HANDLE,
        }
    };
    // A read/write section on a read-only file is denied up front.
    if page == 0x04 && oi != 0xff && accmode == 0 {
        user::nt_oi_release(oi);
        return STATUS_ACCESS_DENIED;
    }
    let size = if szp != 0 {
        // SAFETY: validated user window.
        unsafe { (szp as *const u64).read_unaligned() }
    } else {
        user::nt_oi_len(oi)
    };
    if size == 0 {
        if oi != 0xff {
            user::nt_oi_release(oi);
        }
        return STATUS_MAPPED_FILE_SIZE_ZERO;
    }
    // A section can never name a window bigger than the NT arena —
    // also keeps the view-size page round-up away from u64 wrap.
    if size > crate::elf::USER_VA_HI - user::NT_ALLOC_VA {
        if oi != 0xff {
            user::nt_oi_release(oi);
        }
        return STATUS_INVALID_PARAMETER;
    }
    let Some(idx) = user::nt_sec_new(oi as u64, size, page) else {
        if oi != 0xff {
            user::nt_oi_release(oi);
        }
        return STATUS_INSUFFICIENT_RESOURCES;
    };
    let Some(h) = user::nt_handle_alloc_sec(idx) else {
        user::nt_sec_free(idx);
        if oi != 0xff {
            user::nt_oi_release(oi);
        }
        return STATUS_INSUFFICIENT_RESOURCES;
    };
    // SAFETY: validated user window.
    unsafe { (hout as *mut u64).write_unaligned(h) };
    STATUS_SUCCESS
}

/// NtMapViewOfSection(hsection, hprocess, &base, zerobits, commitsz,
/// &secoff, &viewsize, inherit, alloctype, protect): commits a fresh
/// window on the caller's ledger, seeds it from the section's file
/// bytes, and records a view entry whose write-back on unmap reaches
/// the file only for a READWRITE mapping.
fn nt_map_view(ctx: &mut UCtx) -> u64 {
    let sech = arg(ctx, 0);
    let proch = arg(ctx, 1);
    let bp = arg(ctx, 2);
    let offp = arg(ctx, 5);
    let sizep = arg(ctx, 6);
    let prot = arg(ctx, 9) as u32;
    if proch != 0 && proch != u64::MAX {
        return STATUS_NOT_IMPLEMENTED; // only our own mm for now
    }
    if !user::range_ok_w(bp, 8) || !user::range_ok_w(sizep, 8) {
        return STATUS_ACCESS_VIOLATION;
    }
    if offp != 0 && !user::range_ok(offp, 8) {
        return STATUS_ACCESS_VIOLATION;
    }
    let Some(idx) = user::nt_handle_sec_idx(sech) else {
        return STATUS_INVALID_HANDLE;
    };
    let Some((oi, ssize, sprot)) = user::nt_sec_get(idx) else {
        return STATUS_INVALID_HANDLE;
    };
    // SAFETY: all validated user windows.
    let (hint, off, mut vsz) = unsafe {
        (
            (bp as *const u64).read_unaligned(),
            if offp != 0 { (offp as *const u64).read_unaligned() } else { 0 },
            (sizep as *const u64).read_unaligned(),
        )
    };
    if off >= ssize {
        return STATUS_INVALID_PARAMETER;
    }
    if vsz == 0 {
        vsz = ssize - off; // 0 view size maps to end of section
    }
    if vsz > ssize - off {
        return STATUS_INVALID_PARAMETER;
    }
    vsz = (vsz + 0xfff) & !0xfff;
    // View protection may never exceed the section's.
    let page = (prot & 0xff) as u8;
    let wants_w = page == 0x04 || page == 0x08;
    if page != 0x02 && !wants_w {
        return STATUS_INVALID_PARAMETER;
    }
    if wants_w && sprot != 0x04 && sprot != 0x08 {
        return STATUS_ACCESS_DENIED;
    }
    // Same flag translation VirtualAlloc uses — WRITECOPY takes the
    // writable branch (private pages), READONLY the read one.
    let Some((rfl, pfl)) = user::rng_from_prot(prot) else {
        return STATUS_INVALID_PARAMETER;
    };
    let Some(base) = user::nt_alloc_pages(hint, vsz, true, rfl, pfl) else {
        return STATUS_NO_MEMORY;
    };
    let wb = page == 0x04 && oi != 0xff; // WRITECOPY views discard
    if oi != 0xff {
        user::nt_oi_addref(oi as usize);
        user::nt_oi_copyin(oi as usize, off, base, vsz);
    }
    // file_span = file bytes the view names (pre-round, bounded by
    // the section); vsz is the committed VA span.
    let file_span = core::cmp::min(vsz, ssize - off);
    if !user::nt_view_add(base, vsz, oi, off, file_span, wants_w, wb) {
        user::nt_free_pages(base, vsz);
        if oi != 0xff {
            user::nt_oi_release(oi as usize);
        }
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    // SAFETY: both pointers validated above.
    unsafe {
        (bp as *mut u64).write_unaligned(base);
        (sizep as *mut u64).write_unaligned(vsz);
    }
    STATUS_SUCCESS
}

/// NtUnmapViewOfSection(process, base): resolves the view on the
/// caller's ledger — write-back views flush to the file first, then
/// the window frees and the view's OFD ref drops.
fn nt_unmap_view(ctx: &mut UCtx) -> u64 {
    let proch = arg(ctx, 0);
    let base = arg(ctx, 1);
    if proch != 0 && proch != u64::MAX {
        return STATUS_NOT_IMPLEMENTED;
    }
    if user::nt_view_unmap(base) {
        STATUS_SUCCESS
    } else {
        STATUS_INVALID_PARAMETER
    }
}

/// NtFlushVirtualMemory(process, &base, &size, iosb): pushes dirty
/// write-back view bytes to their file. base==0&&size==0 flushes
/// every write-back view the process owns.
fn nt_flush_vm(ctx: &mut UCtx) -> u64 {
    let proch = arg(ctx, 0);
    let bp = arg(ctx, 1);
    let sp = arg(ctx, 2);
    let iosb = arg(ctx, 3);
    if proch != 0 && proch != u64::MAX {
        return STATUS_NOT_IMPLEMENTED;
    }
    if (bp != 0 && !user::range_ok_w(bp, 8)) || (sp != 0 && !user::range_ok_w(sp, 8)) {
        return STATUS_ACCESS_VIOLATION;
    }
    // SAFETY: both validated above when nonzero.
    let (base, size) = unsafe {
        (
            if bp != 0 { (bp as *const u64).read_unaligned() } else { 0 },
            if sp != 0 { (sp as *const u64).read_unaligned() } else { 0 },
        )
    };
    user::nt_view_flush(base, size);
    iosb_complete(iosb, STATUS_SUCCESS, 0);
    STATUS_SUCCESS
}

/// NtQuerySection(h, class, buf, len, &retlen): class 0
/// SectionBasicInformation only — a 24-byte {base u64, attributes
/// u32, pad, size u64}.
fn nt_query_section(ctx: &mut UCtx) -> u64 {
    let h = arg(ctx, 0);
    let class = arg(ctx, 1);
    let buf = arg(ctx, 2);
    let blen = arg(ctx, 3);
    let rsz = arg(ctx, 4);
    if class != 0 {
        return STATUS_NOT_IMPLEMENTED;
    }
    if blen < 24 {
        return STATUS_INFO_LENGTH_MISMATCH;
    }
    if !user::range_ok_w(buf, 24) {
        return STATUS_ACCESS_VIOLATION;
    }
    if rsz != 0 && !user::range_ok_w(rsz, 8) {
        return STATUS_ACCESS_VIOLATION;
    }
    let Some(idx) = user::nt_handle_sec_idx(h) else {
        return STATUS_INVALID_HANDLE;
    };
    let Some((_, size, _)) = user::nt_sec_get(idx) else {
        return STATUS_INVALID_HANDLE;
    };
    // SAFETY: validated user window.
    unsafe {
        let p = buf as *mut u8;
        (p as *mut u64).write_unaligned(0); // BaseAddress: unknown
        (p.add(8) as *mut u32).write_unaligned(0x0800_0000); // SEC_COMMIT
        (p.add(16) as *mut u64).write_unaligned(size);
    }
    if rsz != 0 {
        // SAFETY: validated above.
        unsafe { (rsz as *mut u64).write_unaligned(24) };
    }
    STATUS_SUCCESS
}

/// NtQueryVirtualMemory(process, base, class, buf, len, &retlen):
/// class 0 MemoryBasicInformation only — a 48-byte record built
/// from the task's ranges ledger (committed range fields, or
/// MEM_FREE up to the next registered region).
fn nt_query_vm(ctx: &mut UCtx) -> u64 {
    if arg(ctx, 0) != u64::MAX {
        return STATUS_INVALID_PARAMETER;
    }
    let (base, class, buf, len, rp) = (
        arg(ctx, 1),
        arg(ctx, 2),
        arg(ctx, 3),
        arg(ctx, 4),
        arg(ctx, 5),
    );
    if class != 0 {
        return STATUS_INVALID_INFO_CLASS;
    }
    if len < 48 {
        return STATUS_INFO_LENGTH_MISMATCH;
    }
    if !user::range_ok_w(buf, 48) || (rp != 0 && !user::range_ok_w(rp, 8)) {
        return STATUS_ACCESS_VIOLATION;
    }
    user::nt_query_vm(base, buf);
    if rp != 0 {
        // SAFETY: pointer validated above.
        unsafe { (rp as *mut u64).write_unaligned(48) };
    }
    STATUS_SUCCESS
}

/// NtProtectVirtualMemory(process, &base, &size, newprot, &oldprot):
/// page-aligns the window, requires committed coverage, rewrites
/// the PTEs and ranges flags, reports the first range's old
/// protection. The self-managed heap arena is rejected inside.
fn nt_protect_vm(ctx: &mut UCtx) -> u64 {
    if arg(ctx, 0) != u64::MAX {
        return STATUS_INVALID_PARAMETER;
    }
    let (bp, sp, prot, op) = (
        arg(ctx, 1),
        arg(ctx, 2),
        arg(ctx, 3) as u32,
        arg(ctx, 4),
    );
    if !user::range_ok(bp, 8) || !user::range_ok(sp, 8) {
        return STATUS_ACCESS_VIOLATION;
    }
    if op != 0 && !user::range_ok_w(op, 4) {
        return STATUS_ACCESS_VIOLATION;
    }
    // SAFETY: both pointers validated above.
    let (base, size) = unsafe {
        (
            (bp as *const u64).read_unaligned(),
            (sp as *const u64).read_unaligned(),
        )
    };
    user::nt_protect_vm(base, size, prot, op)
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

/// NtCreateThreadEx(&handle, access, oa, proch, start, param,
/// cflags, zero, commit_sz, reserve_sz, attr): a shared-mm thread —
/// own kernel stack, own user stack (reserve_sz or 64K default),
/// own TEB/TLS, param in rcx, a synthetic return address that
/// ExitThread's the start routine's return value. proch must be
/// the pseudo-handle -1; cflags honours CREATE_SUSPENDED (4) only.
fn nt_create_thread_ex(ctx: &mut UCtx) -> u64 {
    let ph = arg(ctx, 0);
    let proch = arg(ctx, 3);
    let (start, param, cflags, rsz) = (arg(ctx, 4), arg(ctx, 5), arg(ctx, 6), arg(ctx, 9));
    if !user::range_ok_w(ph, 8) {
        return STATUS_ACCESS_VIOLATION;
    }
    if proch != u64::MAX {
        return STATUS_INVALID_HANDLE;
    }
    if cflags & !4 != 0 {
        return STATUS_NOT_IMPLEMENTED;
    }
    // A handle slot is claimed AFTER the task exists; pre-check one
    // is free so a created thread can't leak without its handle.
    if !user::nt_handle_free_slot() {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    let Some((idx, _tid)) = user::nt_thread_create(ctx, start, param, cflags, rsz) else {
        return STATUS_INSUFFICIENT_RESOURCES;
    };
    let Some(h) = user::nt_handle_alloc_thread(idx) else {
        return STATUS_INSUFFICIENT_RESOURCES;
    };
    // SAFETY: ph probed writable above.
    unsafe { (ph as *mut u64).write_unaligned(h) };
    STATUS_SUCCESS
}

/// NtWaitForSingleObject(handle, alertable, &timeout): thread
/// objects are our only waitable kind. timeout is an NT interval
/// (negative 100-ns units = relative, NULL = infinite). The wait
/// polls the ledger between 1ms sleeps — the task slot may be
/// reaped, the entry survives it.
fn nt_wait_single(ctx: &mut UCtx) -> u64 {
    let h = arg(ctx, 0);
    let tp = arg(ctx, 2);
    // timeout is an NT interval (negative 100-ns = relative,
    // NULL = infinite, 0 = poll).
    let ms = if tp == 0 {
        None
    } else {
        if !user::range_ok(tp, 8) {
            return STATUS_ACCESS_VIOLATION;
        }
        // SAFETY: validated window.
        let iv = unsafe { (tp as *const i64).read_unaligned() };
        Some(if iv < 0 { (-iv / 10_000) as u64 } else { 0 })
    };
    let Some(idx) = user::nt_handle_thr_idx(h) else {
        return STATUS_INVALID_HANDLE;
    };
    let Some((_, _, _, _, alive)) = user::nt_thr_info(idx) else {
        return STATUS_INVALID_HANDLE;
    };
    if !alive {
        return STATUS_SUCCESS; // WAIT_OBJECT_0
    }
    let Some(ms) = ms else {
        // Infinite wait: no deadline, nt_wait_expire wakes on death.
        user::nt_wait_block(ctx, idx, 0)
    };
    if ms == 0 {
        return STATUS_TIMEOUT; // zero-time poll of a live object
    }
    let ticks = crate::apic::TICKS
        .load(core::sync::atomic::Ordering::Relaxed)
        .saturating_add(ms.div_ceil(10));
    user::nt_wait_block(ctx, idx, ticks)
}

/// NtQueryInformationThread(handle, class, buf, len, &retsz):
/// ThreadBasicInformation (0) — exit status or STILL_ACTIVE, TEB
/// base, and the (process, thread) ClientId pair GetThreadId reads.
fn nt_query_thread(ctx: &mut UCtx) -> u64 {
    let h = arg(ctx, 0);
    let (class, buf, len, ret) = (arg(ctx, 1), arg(ctx, 2), arg(ctx, 3), arg(ctx, 4));
    if class != 0 {
        return STATUS_INVALID_INFO_CLASS;
    }
    if len < 48 {
        return STATUS_INFO_LENGTH_MISMATCH;
    }
    if !user::range_ok_w(buf, 48) {
        return STATUS_ACCESS_VIOLATION;
    }
    let Some(idx) = user::nt_handle_thr_idx(h) else {
        return STATUS_INVALID_HANDLE;
    };
    let Some((tgid, tid, teb, status, alive)) = user::nt_thr_info(idx) else {
        return STATUS_INVALID_HANDLE;
    };
    let mut info = [0u8; 48];
    info[0..8].copy_from_slice(&(if alive { STATUS_STILL_ACTIVE } else { status }).to_le_bytes());
    info[8..16].copy_from_slice(&teb.to_le_bytes());
    info[16..24].copy_from_slice(&tgid.to_le_bytes());
    info[24..32].copy_from_slice(&tid.to_le_bytes());
    info[32..40].copy_from_slice(&1u64.to_le_bytes()); // affinity
    // SAFETY: buf probed writable for 48 bytes.
    unsafe { core::ptr::copy_nonoverlapping(info.as_ptr(), buf as *mut u8, 48) };
    if ret != 0 && user::range_ok_w(ret, 8) {
        // SAFETY: ret probed writable.
        unsafe { (ret as *mut u64).write_unaligned(48) };
    }
    STATUS_SUCCESS
}

/// NtResumeThread(handle, &prevcount): clears a CREATE_SUSPENDED
/// block; prevcount (optional) gets 1 if it was suspended, else 0.
fn nt_resume_thread(ctx: &mut UCtx) -> u64 {
    let h = arg(ctx, 0);
    let cnt = arg(ctx, 1);
    let Some(idx) = user::nt_handle_thr_idx(h) else {
        return STATUS_INVALID_HANDLE;
    };
    let Some((_, tid, _, _, _)) = user::nt_thr_info(idx) else {
        return STATUS_INVALID_HANDLE;
    };
    let prev = user::nt_thr_resume(tid);
    if cnt != 0 {
        if !user::range_ok_w(cnt, 8) {
            return STATUS_ACCESS_VIOLATION;
        }
        // SAFETY: cnt probed writable.
        unsafe { (cnt as *mut u64).write_unaligned(prev) };
    }
    STATUS_SUCCESS
}

/// NtTerminateThread(handle, status): handle 0 or the -2
/// pseudo-handle ends THIS thread (ExitThread's path). Killing a
/// sibling thread is honest NOT_IMPLEMENTED — remote teardown needs
/// the victim's own bookkeeping, not a mark-and-reap shortcut.
fn nt_terminate_thread(ctx: &mut UCtx) -> u64 {
    let h = arg(ctx, 0);
    let status = arg(ctx, 1);
    if h == 0 || h == u64::MAX - 1 {
        user::task_exit(status);
    }
    STATUS_NOT_IMPLEMENTED
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
        b"CreateFile" => NT_CREATE_FILE,
        b"QueryInformationFile" => NT_QUERY_INFORMATION_FILE,
        b"SetInformationFile" => NT_SET_INFORMATION_FILE,
        b"AllocateVirtualMemory" => NT_ALLOCATE_VIRTUAL_MEMORY,
        b"FreeVirtualMemory" => NT_FREE_VIRTUAL_MEMORY,
        b"QueryVirtualMemory" => NT_QUERY_VIRTUAL_MEMORY,
        b"ProtectVirtualMemory" => NT_PROTECT_VIRTUAL_MEMORY,
        b"TerminateProcess" => NT_TERMINATE_PROCESS,
        b"DelayExecution" => NT_DELAY_EXECUTION,
        b"QueryDirectoryFile" => NT_QUERY_DIRECTORY_FILE,
        b"WaitForSingleObject" => NT_WAIT_FOR_SINGLE_OBJECT,
        b"QueryInformationThread" => NT_QUERY_INFORMATION_THREAD,
        b"ResumeThread" => NT_RESUME_THREAD,
        b"TerminateThread" => NT_TERMINATE_THREAD,
        b"CreateThreadEx" => NT_CREATE_THREAD_EX,
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
        NT_CREATE_FILE => nt_create_file(ctx),
        NT_QUERY_DIRECTORY_FILE => nt_query_dir(ctx),
        NT_QUERY_INFORMATION_FILE => nt_query_info(ctx),
        NT_SET_INFORMATION_FILE => nt_set_info(ctx),
        NT_ALLOCATE_VIRTUAL_MEMORY => nt_alloc_vm(ctx),
        NT_FREE_VIRTUAL_MEMORY => nt_free_vm(ctx),
        NT_QUERY_VIRTUAL_MEMORY => nt_query_vm(ctx),
        NT_PROTECT_VIRTUAL_MEMORY => nt_protect_vm(ctx),
        NT_CREATE_SECTION => nt_create_section(ctx),
        NT_MAP_VIEW_OF_SECTION => nt_map_view(ctx),
        NT_UNMAP_VIEW_OF_SECTION => nt_unmap_view(ctx),
        NT_FLUSH_VIRTUAL_MEMORY => nt_flush_vm(ctx),
        NT_QUERY_SECTION => nt_query_section(ctx),
        NT_DELAY_EXECUTION => nt_delay(ctx),
        NT_CREATE_THREAD_EX => nt_create_thread_ex(ctx),
        NT_WAIT_FOR_SINGLE_OBJECT => nt_wait_single(ctx),
        NT_QUERY_INFORMATION_THREAD => nt_query_thread(ctx),
        NT_RESUME_THREAD => nt_resume_thread(ctx),
        NT_TERMINATE_THREAD => nt_terminate_thread(ctx),
        RUX_HEAP_ALLOC => nt_heap_alloc_svc(ctx),
        RUX_HEAP_REALLOC => nt_heap_realloc_svc(ctx),
        RUX_HEAP_FREE => nt_heap_free_svc(ctx),
        RUX_HEAP_SIZE => nt_heap_size_svc(ctx),
        // LoadLibraryA(name[,wide]) / GetProcAddress / FreeLibrary —
        // private services backing the Win32 thunks.
        RUX_LOAD_DLL => user::nt_load_dll(arg(ctx, 0), arg(ctx, 1) != 0),
        RUX_GET_PROC => user::nt_get_proc(arg(ctx, 0), arg(ctx, 1)),
        RUX_FREE_DLL => user::nt_free_dll(arg(ctx, 0)),
        // Drain one pending DllMain(DLL_PROCESS_ATTACH) — the
        // LoadLibrary thunk loops on this after a fresh map so
        // dependency entry points run before their importer's.
        RUX_DLL_ATTACH => user::nt_next_attach(),
        // GetModuleHandleA/W(name[,wide]) — HMODULE lookup without
        // a ref bump; NULL name returns the exe's image base.
        RUX_MOD_HANDLE => user::nt_mod_handle(arg(ctx, 0), arg(ctx, 1) != 0),
        // FreeLibrary thunk loops on this after a final-ref free so
        // dependency exit points run after their importer's, then
        // RUX_FREE_FIN performs the unmaps + surviving dep refdowns.
        RUX_DLL_DETACH => user::nt_next_detach(),
        RUX_FREE_FIN => user::nt_detach_fin(),
        NT_TERMINATE_PROCESS => {
            // hProcess == (HANDLE)-1 means self; anything else is a
            // kill we don't model yet — the common case is self-exit.
            let status = arg(ctx, 1);
            crate::log::printk(format_args!(
                "rustux: user: pid {} {} exit({status})",
                user::getpid(),
                user::cur_exe()
            ));
            user::task_exit(status);
        }
        _ => STATUS_NOT_IMPLEMENTED,
    }
}
