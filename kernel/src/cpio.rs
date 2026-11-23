//! newc ("070701"/"070702") cpio archive reader — the initrd format.
//!
//! The archive is hostile input: every header field is hex-validated,
//! every extent is checked arithmetic, and the filename MUST be
//! NUL-terminated at namesize-1 — verified, never assumed. That check
//! is the exact shape of the CVE-2024-53142 fix (Linux's initramfs
//! trusted the terminator and could read past the name).
//!
//! Scope: read-only lookup of regular files by name. No extraction,
//! no filesystem writes — this feeds bytes to the ELF loader.

/// Header: 6 magic + 13 fields of 8 ASCII-hex digits each.
const HDR_LEN: usize = 110;
/// Field offsets inside the 110-byte header.
const MODE_OFF: usize = 14;
const FILESIZE_OFF: usize = 54;
const NAMESIZE_OFF: usize = 94;
/// Saner-than-need bounds against malformed archives.
const MAX_ENTRIES: usize = 256;
const MAX_NAME: usize = 4096;

fn align4(n: usize) -> usize {
    (n + 3) & !3
}

/// Parse an 8-digit ASCII-hex field. Any non-hex byte rejects the
/// whole archive — no partial-parse tolerance.
fn hex8(b: &[u8]) -> Option<u64> {
    if b.len() < 8 {
        return None;
    }
    let mut v = 0u64;
    for &c in &b[..8] {
        let d = match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => return None,
        };
        v = (v << 4) | d as u64;
    }
    Some(v)
}

/// One validated entry: name (NUL stripped) and data.
struct Entry<'a> {
    name: &'a [u8],
    data: &'a [u8],
    /// c_mode from the header — the recorded file type+perm bits.
    mode: u32,
    /// Archive offset of the next header.
    next: usize,
    /// True for the TRAILER!!! record — ends the archive.
    trailer: bool,
}

/// Parse the entry starting at `off`. Returns None on ANY malformed
/// field — malformed archives abort the walk, never skip-and-pray.
fn entry_at<'a>(img: &'a [u8], off: usize) -> Option<Entry<'a>> {
    let hdr = img.get(off..off.checked_add(HDR_LEN)?)?;
    if hdr[0..6] != *b"070701" && hdr[0..6] != *b"070702" {
        return None;
    }
    let mode = hex8(&hdr[MODE_OFF..MODE_OFF + 8])? as u32;
    let filesize = hex8(&hdr[FILESIZE_OFF..FILESIZE_OFF + 8])? as usize;
    let namesize = hex8(&hdr[NAMESIZE_OFF..NAMESIZE_OFF + 8])? as usize;
    if namesize == 0 || namesize > MAX_NAME {
        return None;
    }
    let name = img.get(off + HDR_LEN..off.checked_add(HDR_LEN + namesize)?)?;
    // The terminator is part of namesize and must be present —
    // the CVE-2024-53142 discipline, not a convention.
    if name[namesize - 1] != 0 {
        return None;
    }
    let name = &name[..namesize - 1];
    let data_off = off.checked_add(align4(HDR_LEN + namesize))?;
    let data = img.get(data_off..data_off.checked_add(filesize)?)?;
    Some(Entry {
        name,
        data,
        mode,
        next: data_off.checked_add(align4(filesize))?,
        trailer: name == b"TRAILER!!!",
    })
}

/// Iterate (name, data) over every well-formed entry until TRAILER!!!,
/// a malformed entry, or the hard entry bound — whichever comes first.
pub fn entries(img: &[u8]) -> impl Iterator<Item = (&[u8], &[u8])> + '_ {
    let mut off = 0usize;
    let mut steps = 0usize;
    core::iter::from_fn(move || {
        if steps == MAX_ENTRIES {
            return None;
        }
        steps += 1;
        let e = entry_at(img, off)?;
        off = e.next;
        if e.trailer {
            return None;
        }
        Some((e.name, e.data))
    })
}

/// Same walk as `entries` but yields the c_mode too — stat, access,
/// and the exec permission check all honor recorded perm bits.
pub fn entries_m(
    img: &[u8],
) -> impl Iterator<Item = (&[u8], &[u8], u32)> + '_ {
    let mut off = 0usize;
    let mut steps = 0usize;
    core::iter::from_fn(move || {
        if steps == MAX_ENTRIES {
            return None;
        }
        steps += 1;
        let e = entry_at(img, off)?;
        off = e.next;
        if e.trailer {
            return None;
        }
        Some((e.name, e.data, e.mode))
    })
}

/// Look up `want` (exact filename, no leading /) and return its data
/// bytes. Returns None on any malformed entry or a missing file.
pub fn find<'a>(img: &'a [u8], want: &[u8]) -> Option<&'a [u8]> {
    entries(img).find(|(n, _)| *n == want).map(|(_, d)| d)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pad4(v: &mut Vec<u8>) {
        while v.len() % 4 != 0 {
            v.push(0);
        }
    }

    fn hdr(filesize: usize, namesize: usize) -> Vec<u8> {
        let fields: [usize; 11] = [1, 0o100644, 0, 0, 1, 0, filesize, 0, 1, 0, 0];
        let mut h = b"070701".to_vec();
        for f in fields {
            h.extend_from_slice(format!("{:08x}", f).as_bytes());
        }
        h.extend_from_slice(format!("{:08x}", namesize).as_bytes());
        h.extend_from_slice(b"00000000"); // check
        h
    }

    fn arc(entries: &[(&[u8], &[u8])], trailer: bool) -> Vec<u8> {
        let mut v = Vec::new();
        for (name, data) in entries {
            v.extend(hdr(data.len(), name.len() + 1));
            v.extend_from_slice(name);
            v.push(0);
            pad4(&mut v);
            v.extend_from_slice(data);
            pad4(&mut v);
        }
        if trailer {
            v.extend(hdr(0, 11));
            v.extend_from_slice(b"TRAILER!!!\0");
            pad4(&mut v);
        }
        v
    }

    #[test]
    fn finds_file() {
        let a = arc(&[(b"init", b"ELF"), (b"other", b"xx")], true);
        assert_eq!(find(&a, b"init"), Some(&b"ELF"[..]));
        assert_eq!(find(&a, b"other"), Some(&b"xx"[..]));
        assert_eq!(find(&a, b"nope"), None);
    }

    #[test]
    fn empty_and_tiny() {
        assert_eq!(find(&[], b"init"), None);
        assert_eq!(find(b"070701", b"init"), None);
    }

    #[test]
    fn bad_magic() {
        let mut a = arc(&[(b"init", b"d")], true);
        a[5] = b'9';
        assert_eq!(find(&a, b"init"), None);
        a[5] = b'2'; // 070702 is accepted
        assert_eq!(find(&a, b"init"), Some(&b"d"[..]));
    }

    #[test]
    fn zero_namesize() {
        let mut a = arc(&[(b"init", b"d")], true);
        a[94..102].copy_from_slice(b"00000000");
        assert_eq!(find(&a, b"init"), None);
    }

    #[test]
    fn missing_name_nul() {
        // CVE-2024-53142: namesize claims 5 but last byte is not NUL.
        let mut a = Vec::new();
        a.extend(hdr(1, 5));
        a.extend_from_slice(b"init!"); // no terminator
        pad4(&mut a);
        a.push(b'd');
        pad4(&mut a);
        assert_eq!(find(&a, b"init"), None);
    }

    #[test]
    fn namesize_past_end() {
        let mut a = Vec::new();
        a.extend(hdr(1, 0xffff_ffff));
        assert_eq!(find(&a, b"init"), None);
        a.extend_from_slice(b"init\0");
        pad4(&mut a);
        assert_eq!(find(&a, b"init"), None);
    }

    #[test]
    fn filesize_past_end() {
        let mut a = Vec::new();
        a.extend(hdr(0x1000, 5));
        a.extend_from_slice(b"init\0");
        pad4(&mut a);
        a.extend_from_slice(b"d"); // only 1 byte, claims 0x1000
        assert_eq!(find(&a, b"init"), None);
    }

    #[test]
    fn file_after_trailer_never_seen() {
        let mut a = arc(&[(b"init", b"d")], true);
        let extra = arc(&[(b"init", b"SHADOW")], false);
        a.extend(extra);
        assert_eq!(find(&a, b"init"), Some(&b"d"[..]));
    }

    #[test]
    fn truncations() {
        let a = arc(&[(b"init", b"d")], false);
        // Half a header: reject.
        assert_eq!(find(&a[..a.len() / 2], b"init"), None);
        // Cutting the trailing pad is fine — the file data is intact.
        assert_eq!(find(&a[..a.len() - 3], b"init"), Some(&b"d"[..]));
        // Cutting into the file data: reject.
        assert_eq!(find(&a[..a.len() - 4], b"init"), None);
    }

    #[test]
    fn non_hex_field() {
        let mut a = arc(&[(b"init", b"d")], true);
        a[56] = b'z'; // filesize digits
        assert_eq!(find(&a, b"init"), None);
    }
}
