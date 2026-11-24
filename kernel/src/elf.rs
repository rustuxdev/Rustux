//! ELF64 program loading: header + program-header parsing where every
//! field is validated before use. The image is hostile input — a bad
//! offset, size, or count must be rejected, never wrapped, clamped
//! silently, or trusted (the CVE-2004-1070..1072 class was unchecked
//! header arithmetic and unchecked reads in binfmt_elf).
//!
//! Scope: static ET_EXEC and ET_DYN images; a PT_INTERP header names
//! an interpreter ELF the caller loads separately (kernel/src/user.rs
//! maps it into the mmap arena — this module never touches the fs).
//! Rejected, not partially loaded. ET_DYN is mapped at LOAD_BIAS and
//! relocates itself from its own dynamic section, same as Linux's
//! binfmt.

pub const PT_LOAD: u32 = 1;
pub const PT_INTERP: u32 = 3;
pub const PF_X: u32 = 1;
pub const PF_W: u32 = 2;
#[allow(dead_code)]
pub const PF_R: u32 = 4;

const EHDR_SIZE: usize = 64;
const PHDR_SIZE: usize = 56;
const EHDR32_SIZE: usize = 52;
const PHDR32_SIZE: usize = 32;
const ET_EXEC: u16 = 2;
const ET_DYN: u16 = 3;
const EM_X86_64: u16 = 0x3e;
const EM_386: u16 = 3;
const ELFCLASS32: u8 = 1;
const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1;

/// Hard bound on program headers — a real binary needs a handful;
/// beyond this the image is malformed for our purposes.
const MAX_PHNUM: usize = 64;

/// User virtual addresses live in our dedicated user half: PML4 slots
/// 128..256 (slots <128 hold the kernel identity map and stay
/// supervisor-only; slots >=256 are non-canonical/kernel-reserved).
/// [0x4000_0000_0000, 0x8000_0000_0000) is canonical and untranslated
/// by anything else.
pub const USER_VA_LO: u64 = 0x4000_0000_0000;
pub const USER_VA_HI: u64 = 0x8000_0000_0000;

/// Load bias for ET_DYN images — the same base our test ELFs link at.
/// Any in-window base works since the image self-relocates; a fixed
/// one keeps stacks/heap deterministic across task types.
pub const LOAD_BIAS: u64 = 0x5555_0000_0000;

fn u16le(b: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([b[off], b[off + 1]])
}

fn u32le(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

fn u64le(b: &[u8], off: usize) -> u64 {
    u64::from_le_bytes([
        b[off], b[off + 1], b[off + 2], b[off + 3],
        b[off + 4], b[off + 5], b[off + 6], b[off + 7],
    ])
}

/// Validated ELF header fields of a static executable — 64-bit or
/// 32-bit (IA-32 compat). `entry` and every `phdrs()` `va` are
/// already biased — for ET_DYN (static-PIE) that's LOAD_BIAS, for
/// ET_EXEC it's 0. `is32` selects the phdr layout at iteration.
pub struct Elf {
    pub entry: u64,
    bias: u64,
    phoff: usize,
    phentsize: usize,
    phnum: usize,
    pub is32: bool,
}

/// A parsed program header.
pub struct Phdr {
    pub ty: u32,
    pub flags: u32,
    pub off: u64,
    pub va: u64,
    pub filesz: u64,
    pub memsz: u64,
    /// Alignment requirement — parsed for completeness, enforced
    /// implicitly by our per-page mapping (any alignment works).
    #[allow(dead_code)]
    pub align: u64,
}

/// Parse and validate the ELF header. Every extent check happens
/// before the bytes are touched.
pub fn parse(b: &[u8]) -> Option<Elf> {
    parse_at(b, LOAD_BIAS)
}

/// `parse` with a caller-chosen ET_DYN bias — the PT_INTERP loader
/// measures the span at bias 0, first-fits a gap in the mmap arena,
/// and re-parses there, like Linux's elf_map over mmap_base.
/// ET_EXEC ignores `dyn_bias`: its vaddrs are absolute.
pub fn parse_at(b: &[u8], dyn_bias: u64) -> Option<Elf> {
    if b.len() < EHDR32_SIZE {
        return None;
    }
    if b[0..4] != *b"\x7fELF" || b[5] != ELFDATA2LSB {
        return None;
    }
    let is32 = match b[4] {
        ELFCLASS32 => true,
        ELFCLASS64 => false,
        _ => return None,
    };
    let ty = u16le(b, 16);
    if ty != ET_EXEC && ty != ET_DYN {
        return None;
    }
    let machine = u16le(b, 18);
    if machine != if is32 { EM_386 } else { EM_X86_64 } {
        return None;
    }
    // ET_DYN self-relocates; the loader just picks a base and adds
    // it to every address. ET_EXEC keeps bias 0.
    let bias = if ty == ET_DYN { dyn_bias } else { 0 };
    if u32le(b, 20) != 1 {
        return None;
    }
    // ELF32 headers are field-identical but narrower: entry/phoff
    // are u32, sizes are u16s at different offsets.
    let (entry, phoff, phentsize, phnum) = if is32 {
        (
            u32le(b, 24) as u64,
            u32le(b, 28) as usize,
            u16le(b, 42) as usize,
            u16le(b, 44) as usize,
        )
    } else {
        if b.len() < EHDR_SIZE {
            return None;
        }
        (
            u64le(b, 24),
            u64le(b, 32) as usize,
            u16le(b, 54) as usize,
            u16le(b, 56) as usize,
        )
    };
    let phdr_min = if is32 { PHDR32_SIZE } else { PHDR_SIZE };
    if phnum == 0 || phnum > MAX_PHNUM || phentsize < phdr_min {
        return None;
    }
    // The phdr table must lie fully inside the image — checked
    // arithmetic, never trusting the count.
    let phsize = phentsize.checked_mul(phnum)?;
    let end = phoff.checked_add(phsize)?;
    if end > b.len() {
        return None;
    }
    // Entry point must be a canonical user address after the bias:
    // the 64-bit window for ELF64, the low 4 GiB a compat-mode CPU
    // can reach for ELF32.
    let entry = entry.checked_add(bias)?;
    if is32 {
        if entry >= 0x1_0000_0000 {
            return None;
        }
    } else if !(USER_VA_LO..USER_VA_HI).contains(&entry) {
        return None;
    }
    Some(Elf {
        entry,
        bias,
        phoff,
        phentsize,
        phnum,
        is32,
    })
}

impl Elf {
    /// Validated header fields for auxv construction.
    pub fn phoff(&self) -> usize {
        self.phoff
    }
    pub fn phentsize(&self) -> usize {
        self.phentsize
    }
    pub fn phnum(&self) -> usize {
        self.phnum
    }

    /// PT_INTERP's interpreter path, NUL-trimmed. None when the
    /// image has no interp (static binary) — Linux requires an
    /// absolute NUL-terminated path and so do we.
    pub fn interp<'a>(&self, img: &'a [u8]) -> Option<&'a [u8]> {
        for p in self.phdrs(img) {
            if p.ty != PT_INTERP {
                continue;
            }
            let end = p.off.checked_add(p.filesz)?;
            if end > img.len() as u64 || !(2..=4096).contains(&p.filesz) {
                return None;
            }
            let s = &img[p.off as usize..end as usize];
            if *s.first()? != b'/' || *s.last()? != 0 {
                return None;
            }
            return Some(&s[..s.len() - 1]);
        }
        None
    }

    /// Iterate the validated program headers — ELF32 entries are
    /// 32 bytes with filesz/memsz ahead of flags; ELF64 is 56 with
    /// flags second.
    pub fn phdrs<'a>(&'a self, img: &'a [u8]) -> impl Iterator<Item = Phdr> + 'a {
        (0..self.phnum).map(move |i| {
            // SAFETY: parse() proved phoff + phentsize*phnum <= img.len().
            let off = self.phoff + i * self.phentsize;
            let p = &img[off..off + if self.is32 { PHDR32_SIZE } else { PHDR_SIZE }];
            if self.is32 {
                Phdr {
                    ty: u32le(p, 0),
                    off: u32le(p, 4) as u64,
                    va: (u32le(p, 8) as u64).saturating_add(self.bias),
                    filesz: u32le(p, 16) as u64,
                    memsz: u32le(p, 20) as u64,
                    flags: u32le(p, 24),
                    align: u32le(p, 28) as u64,
                }
            } else {
                Phdr {
                    ty: u32le(p, 0),
                    flags: u32le(p, 4),
                    off: u64le(p, 8),
                    // Load-biased virtual address. Saturating keeps a
                    // hostile non-LOAD va from wrapping; consumers only
                    // act on PT_LOAD, whose range load_inner validates.
                    va: u64le(p, 16).saturating_add(self.bias),
                    filesz: u64le(p, 32),
                    memsz: u64le(p, 40),
                    align: u64le(p, 48),
                }
            }
        })
    }
}
