//! ext2 — read-only ext2 driver (the base ext4 builds on).
//!
//! The kernel's only filesystem so far is the initrd-backed RAM fs,
//! so it cannot mount a Linux root partition at all. ext2 is the right
//! first rung: ext4 uses the same superblock, group descriptors, inode
//! table and directory format, and differs mainly by extent trees and
//! a journal — both of which layer on top of this.
//!
//! Layout (all little-endian):
//!   block 0            boot sector (ignored)
//!   byte 1024          superblock (1024 bytes)
//!   block s_first_data_block + gdt            group descriptors
//!   ...                block/inode bitmaps, inode table, data
//!
//! Everything here is bounds-checked against the image length: this
//! parses untrusted on-disk data, so every offset is validated before
//! it is used and every failure is `None` rather than a panic.

/// ext2/3/4 superblock magic.
pub const MAGIC: u16 = 0xef53;

/// Parsed superblock — only the fields a reader needs.
#[derive(Clone, Copy)]
pub struct Super {
    pub inodes: u32,
    pub blocks: u32,
    pub first_data_block: u32,
    pub log_block_size: u32,
    pub blocks_per_group: u32,
    pub inodes_per_group: u32,
    pub inode_size: u16,
    pub rev: u32,
    pub compat: u32,
    pub incompat: u32,
    pub ro_compat: u32,
    pub first_ino: u32,
}

impl Super {
    /// Filesystem block size in bytes (1024 << log_block_size).
    pub fn block_size(&self) -> u32 {
        1024u32 << self.log_block_size
    }

    /// Group descriptor table's first byte, in blocks.
    pub fn gdt_block(&self) -> u32 {
        self.first_data_block + 1
    }

    /// Number of block groups.
    pub fn groups(&self) -> u32 {
        if self.blocks_per_group == 0 {
            return 0;
        }
        let data_blocks = self.blocks.saturating_sub(self.first_data_block);
        data_blocks.div_ceil(self.blocks_per_group)
    }

    /// ext4 with extent trees — a reader must refuse rather than
    /// misinterpret block maps as extents.
    pub fn uses_extents(&self) -> bool {
        self.incompat & 0x40 != 0 // EXT4_FEATURE_INCOMPAT_EXTENTS
    }
}

fn rd16(b: &[u8], off: usize) -> Option<u16> {
    let s = b.get(off..off + 2)?;
    Some(u16::from_le_bytes([s[0], s[1]]))
}

fn rd32(b: &[u8], off: usize) -> Option<u32> {
    let s = b.get(off..off + 4)?;
    Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

/// Parse the superblock at byte 1024 of a filesystem image.
pub fn parse_super(img: &[u8]) -> Option<Super> {
    const SB: usize = 1024;
    if rd16(img, SB + 56)? != MAGIC {
        return None;
    }
    let inodes = rd32(img, SB + 0)?;
    let blocks = rd32(img, SB + 4)?;
    let first_data_block = rd32(img, SB + 20)?;
    let log_block_size = rd32(img, SB + 24)?;
    if log_block_size > 6 {
        return None; // 64 KiB blocks are beyond ext2
    }
    let blocks_per_group = rd32(img, SB + 32)?;
    let inodes_per_group = rd32(img, SB + 40)?;
    let rev = rd32(img, SB + 76)?;
    // rev 0 has no extended fields; inode_size is fixed at 128.
    let inode_size = if rev == 0 {
        128
    } else {
        rd16(img, SB + 88).unwrap_or(128).max(128)
    };
    if blocks == 0 || inodes == 0 || blocks_per_group == 0 || inodes_per_group == 0 {
        return None;
    }
    Some(Super {
        inodes,
        blocks,
        first_data_block,
        log_block_size,
        blocks_per_group,
        inodes_per_group,
        inode_size,
        rev,
        compat: rd32(img, SB + 92)?,
        incompat: rd32(img, SB + 96)?,
        ro_compat: rd32(img, SB + 100)?,
        first_ino: rd32(img, SB + 84).unwrap_or(11),
    })
}

/// Validate that a superblock's geometry fits the image we hold.
pub fn validate(sb: &Super, img_len: u64) -> bool {
    let bs = sb.block_size() as u64;
    if bs == 0 || img_len < bs * (sb.blocks as u64) {
        return false;
    }
    // The group descriptor table must exist.
    let gdt = sb.gdt_block() as u64 * bs;
    if gdt + 32 > img_len {
        return false;
    }
    sb.groups() <= 1024
}

/// One group descriptor — the fields a reader needs.
#[derive(Clone, Copy)]
pub struct Group {
    pub block_bitmap: u32,
    pub inode_bitmap: u32,
    pub inode_table: u32,
}

/// Read group descriptor `g` from the image.
pub fn group(img: &[u8], sb: &Super, g: u32) -> Option<Group> {
    let bs = sb.block_size() as usize;
    let base = sb.gdt_block() as usize * bs + (g as usize) * 32;
    Some(Group {
        block_bitmap: rd32(img, base)?,
        inode_bitmap: rd32(img, base + 4)?,
        inode_table: rd32(img, base + 8)?,
    })
}

/// A parsed inode — block map only (ext2); extents are refused.
#[derive(Clone, Copy)]
pub struct Inode {
    pub mode: u16,
    pub size: u32,
    pub block: [u32; 15],
}

impl Inode {
    pub fn is_dir(&self) -> bool {
        self.mode & 0xf000 == 0x4000
    }
    pub fn is_file(&self) -> bool {
        self.mode & 0xf000 == 0x8000
    }
}

/// Read inode number `ino` (1-based, as on disk).
pub fn inode(img: &[u8], sb: &Super, ino: u32) -> Option<Inode> {
    if ino == 0 || ino > sb.inodes {
        return None;
    }
    let bs = sb.block_size() as usize;
    let per = sb.inodes_per_group;
    if per == 0 {
        return None;
    }
    let g = (ino - 1) / per;
    let idx = (ino - 1) % per;
    let grp = group(img, sb, g)?;
    let off = grp.inode_table as usize * bs + idx as usize * sb.inode_size as usize;
    let raw = img.get(off..off + 128)?;
    let mut block = [0u32; 15];
    for (i, b) in block.iter_mut().enumerate() {
        *b = rd32(raw, 40 + i * 4)?;
    }
    Some(Inode {
        mode: rd16(raw, 0)?,
        size: rd32(raw, 4)?,
        block,
    })
}

/// One directory entry.
pub struct Dirent {
    pub ino: u32,
    pub name: [u8; 256],
    pub name_len: u8,
}

/// Walk a directory's linear entries, calling `f` for each. ext2/3/4
/// all use this format; htree adds an index but leaves the leaves in
/// this shape.
pub fn dir_walk(
    img: &[u8],
    sb: &Super,
    ino: u32,
    mut f: impl FnMut(&Dirent) -> bool,
) -> Option<()> {
    let bs = sb.block_size() as usize;
    let inode = inode(img, sb, ino)?;
    if !inode.is_dir() {
        return None;
    }
    let mut pos = 0u32;
    while pos < inode.size {
        let blk = block_map(img, sb, &inode, pos / bs as u32)?;
        if blk == 0 {
            pos += bs as u32;
            continue;
        }
        let base = blk as usize * bs;
        let mut off = 0usize;
        while off + 8 <= bs {
            let e = img.get(base + off..base + off + 8)?;
            let e_ino = rd32(e, 0)?;
            let rec_len = rd16(e, 4)? as usize;
            let name_len = e[6] as usize;
            if rec_len < 8 || off + rec_len > bs {
                break;
            }
            if e_ino != 0 && name_len > 0 && name_len <= 255 {
                let mut name = [0u8; 256];
                name[..name_len].copy_from_slice(img.get(base + off + 8..base + off + 8 + name_len)?);
                let d = Dirent {
                    ino: e_ino,
                    name,
                    name_len: name_len as u8,
                };
                if !f(&d) {
                    return Some(());
                }
            }
            off += rec_len;
        }
        pos += bs as u32;
    }
    Some(())
}

/// Logical file block -> physical block, via direct + single indirect.
pub fn block_map(img: &[u8], sb: &Super, inode: &Inode, lblock: u32) -> Option<u32> {
    let bs = sb.block_size();
    let per = (bs / 4) as u32;
    if lblock < 12 {
        return Some(inode.block[lblock as usize]);
    }
    let l = lblock - 12;
    if l < per {
        let ind = inode.block[12];
        if ind == 0 {
            return Some(0);
        }
        let off = ind as usize * bs as usize + (l as usize) * 4;
        return rd32(img, off);
    }
    None // double/triple indirect: not needed for a root walk
}
