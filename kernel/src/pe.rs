//! PE32+ (Windows x64) image parser — the NT personality's answer to
//! elf.rs. Scope: MZ/PE/COFF/optional-header validation, section
//! table, entry, image base, import directory presence. Images load
//! at PE_LOAD_BIAS inside our user window — real Windows binaries
//! link at 0x140000000, far below USER_VA_LO, so .reloc-aware
//! rebasing is deferred until real apps need it (our test images
//! are position-tolerant and carry IMAGE_FILE_RELOCS_STRIPPED).

/// Where NT images live inside the user window. ELF statics sit at
/// 0x5555…, ET_DYN at MMAP_LO; PE gets its own corner so an address
/// alone tells you which personality an image is.
pub const PE_LOAD_BIAS: u64 = super::elf::USER_VA_LO;

/// TEB and PEB get dedicated pages just above the image arena.
pub const PEB_VA: u64 = PE_LOAD_BIAS + 0x0100_0000;
pub const TEB_VA: u64 = PEB_VA + 0x1000;

const DOS_MAGIC: u16 = 0x5a4d; // "MZ"
const PE_MAGIC: u32 = 0x0000_4550; // "PE\0\0"
const OPT_MAGIC: u16 = 0x020b; // PE32+
const MACHINE_AMD64: u16 = 0x8664;
const MAX_SECTIONS: usize = 16;

/// Image File Header Characteristics we care about.
const CHAR_EXEC: u16 = 0x0002;
const CHAR_LARGE_ADDR: u16 = 0x0020;

/// Directory-entry indices into the optional header's DataDirectory.
const DIR_IMPORT: usize = 1;
const DIR_RELOC: usize = 5;

#[derive(Clone, Copy, Default)]
pub struct Section {
    /// RVA of the section inside the image.
    pub va: u64,
    /// Virtual size (may exceed raw_len — tail is zero-fill).
    pub vsize: u64,
    /// File offset of the raw bytes.
    pub raw: u64,
    /// Size of the raw bytes in the file.
    pub raw_len: u64,
    /// IMAGE_SCN_* characteristics.
    pub chars: u32,
}

pub struct Pe {
    /// Absolute entry VA — bias + AddressOfEntryPoint.
    pub entry: u64,
    /// The image's preferred base (informational — we load at bias).
    pub image_base: u64,
    /// Total mapped size (SizeOfImage).
    pub size: u64,
    /// Subsystem field — 2 = GUI, 3 = console.
    pub subsystem: u16,
    /// Headers land at bias; section RAVAs map bias+va.
    pub bias: u64,
    pub sections: [Section; MAX_SECTIONS],
    pub nsec: usize,
    /// Import/reloc directory presence — import-less images run
    /// today; imports without a resolver are an honest load failure.
    pub has_imports: bool,
    pub has_relocs: bool,
}

fn u16le(b: &[u8], off: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(off..off + 2)?.try_into().ok()?))
}
fn u32le(b: &[u8], off: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(off..off + 4)?.try_into().ok()?))
}
fn u64le(b: &[u8], off: usize) -> Option<u64> {
    Some(u64::from_le_bytes(b.get(off..off + 8)?.try_into().ok()?))
}

/// Parse a PE32+ image — None on anything that isn't a well-formed
/// AMD64 executable. `parse` rejects images with imports (no resolver
/// exists yet) — `parse_loose` keeps them for future wiring.
pub fn parse(b: &[u8]) -> Option<Pe> {
    let p = parse_loose(b)?;
    if p.has_imports {
        return None;
    }
    Some(p)
}

pub fn parse_loose(b: &[u8]) -> Option<Pe> {
    if u16le(b, 0)? != DOS_MAGIC {
        return None;
    }
    let peoff = u32le(b, 0x3c)? as usize;
    if u32le(b, peoff)? != PE_MAGIC {
        return None;
    }
    let coff = peoff + 4;
    if u16le(b, coff)? != MACHINE_AMD64 {
        return None;
    }
    let nsec = u16le(b, coff + 2)? as usize;
    if nsec == 0 || nsec > MAX_SECTIONS {
        return None;
    }
    let opt_size = u16le(b, coff + 16)? as usize;
    let chars = u16le(b, coff + 18)?;
    if chars & (CHAR_EXEC | CHAR_LARGE_ADDR) != (CHAR_EXEC | CHAR_LARGE_ADDR) {
        return None;
    }
    let opt = coff + 20;
    if u16le(b, opt)? != OPT_MAGIC {
        return None;
    }
    let entry_rva = u32le(b, opt + 16)? as u64;
    let image_base = u64le(b, opt + 24)?;
    let size = u32le(b, opt + 56)? as u64;
    let subsystem = u16le(b, opt + 68)?;
    let ndirs = u32le(b, opt + 108)? as usize;
    let dir_base = opt + 112;
    let dir = |i: usize| -> u64 {
        if i < ndirs { u32le(b, dir_base + i * 8).unwrap_or(0) as u64 } else { 0 }
    };
    let bias = PE_LOAD_BIAS;
    if size == 0 || size > (PEB_VA - bias) {
        return None;
    }
    let mut sections = [Section::default(); MAX_SECTIONS];
    let stab = opt + opt_size;
    for (i, s) in sections.iter_mut().enumerate().take(nsec) {
        let o = stab + i * 40;
        *s = Section {
            vsize: u32le(b, o + 8)? as u64,
            va: u32le(b, o + 12)? as u64,
            raw_len: u32le(b, o + 16)? as u64,
            raw: u32le(b, o + 20)? as u64,
            chars: u32le(b, o + 36)?,
        };
        if s.va.checked_add(s.vsize.max(1)).is_none_or(|e| e > size)
            || s.raw.checked_add(s.raw_len).is_none_or(|e| e > b.len() as u64)
        {
            return None;
        }
    }
    let entry = bias.checked_add(entry_rva)?;
    if !(super::elf::USER_VA_LO..super::elf::USER_VA_HI).contains(&entry) {
        return None;
    }
    Some(Pe {
        entry,
        image_base,
        size,
        subsystem,
        bias,
        sections,
        nsec,
        has_imports: dir(DIR_IMPORT) != 0,
        has_relocs: dir(DIR_RELOC) != 0,
    })
}
