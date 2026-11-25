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
