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
pub const STATUS_ACCESS_DENIED: u64 = 0xC000_0022;
pub const STATUS_OBJECT_NAME_INVALID: u64 = 0xC000_0033;
pub const STATUS_OBJECT_NAME_NOT_FOUND: u64 = 0xC000_0034;
pub const STATUS_OBJECT_NAME_COLLISION: u64 = 0xC000_0035;
pub const STATUS_OBJECT_PATH_NOT_FOUND: u64 = 0xC000_003A;
pub const STATUS_INSUFFICIENT_RESOURCES: u64 = 0xC000_009A;
pub const STATUS_NO_MORE_FILES: u64 = 0x8000_0006;

// Windows 10 x64 service numbers for the implemented subset.
const NT_READ_FILE: u32 = 0x06;
const NT_WRITE_FILE: u32 = 0x08;
const NT_CLOSE: u32 = 0x0F;
const NT_QUERY_INFORMATION_FILE: u32 = 0x11;
const NT_ALLOCATE_VIRTUAL_MEMORY: u32 = 0x18;
const NT_FREE_VIRTUAL_MEMORY: u32 = 0x1E;
const NT_SET_INFORMATION_FILE: u32 = 0x27;
const NT_TERMINATE_PROCESS: u32 = 0x2C;
const NT_DELAY_EXECUTION: u32 = 0x34;
const NT_QUERY_DIRECTORY_FILE: u32 = 0x35;
const NT_CREATE_FILE: u32 = 0x55;

/// Handle table tags — a per-task `nth` slot's object kind. Real
/// handles are small indices (1-based) like the actual handle table;
/// std handles come pre-bound from the PEB process parameters.
pub const NTH_STDIN: u8 = 1;
pub const NTH_STDOUT: u8 = 2;
pub const NTH_STDERR: u8 = 3;
/// An open file — the slot's `nth_fd` holds the task fd.
pub const NTH_FILE: u8 = 4;
pub const MAX_NTH: usize = 16;

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
        b"CreateFile" => NT_CREATE_FILE,
        b"QueryInformationFile" => NT_QUERY_INFORMATION_FILE,
        b"SetInformationFile" => NT_SET_INFORMATION_FILE,
        b"AllocateVirtualMemory" => NT_ALLOCATE_VIRTUAL_MEMORY,
        b"FreeVirtualMemory" => NT_FREE_VIRTUAL_MEMORY,
        b"TerminateProcess" => NT_TERMINATE_PROCESS,
        b"DelayExecution" => NT_DELAY_EXECUTION,
        b"QueryDirectoryFile" => NT_QUERY_DIRECTORY_FILE,
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
