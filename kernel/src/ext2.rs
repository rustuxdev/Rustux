//! ext2 — read-only ext2 driver (the base ext4 builds on).
//!
//! The kernel's only filesystem was the initrd-backed RAM fs, so it
//! could not mount a Linux root partition at all. ext2 is the right
//! first rung: ext4 uses the same superblock, group descriptors, inode
//! table and directory format, and differs mainly by extent trees and
//! a journal — both of which layer on top of this.
//!
//! Everything goes through [`BlockIo`], so the same code reads an
//! in-memory image (tests) or a real block device (a root partition).
//!
//! Layout (little-endian):
//!   block 0    boot sector (ignored)
//!   byte 1024  superblock (1024 bytes)
//!   ...        group descriptors, bitmaps, inode table, data
//!
//! This parses untrusted on-disk data: every offset is validated before
//! use and every failure is `None` rather than a panic.

/// ext2/3/4 superblock magic.
pub const MAGIC: u16 = 0xef53;

/// Largest block size we buffer (log_block_size <= 2 -> 4096).
const MAX_BLOCK: usize = 4096;

/// Random-access byte reader over a filesystem.
pub trait BlockIo {
    /// Total size in bytes.
    fn len(&self) -> u64;
    /// Fill `buf` from byte `off`. False if the range is not readable.
    fn read(&self, off: u64, buf: &mut [u8]) -> bool;
}

/// A filesystem held in memory — the test path.
pub struct MemIo<'a> {
    pub data: &'a [u8],
}

impl BlockIo for MemIo<'_> {
    fn len(&self) -> u64 {
        self.data.len() as u64
    }
    fn read(&self, off: u64, buf: &mut [u8]) -> bool {
        let start = off as usize;
        match self.data.get(start..start + buf.len()) {
            Some(s) => {
                buf.copy_from_slice(s);
                true
            }
            None => false,
        }
    }
}

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
    pub fn block_size(&self) -> u32 {
        1024u32 << self.log_block_size
    }
    pub fn gdt_block(&self) -> u32 {
        self.first_data_block + 1
    }
    pub fn groups(&self) -> u32 {
        if self.blocks_per_group == 0 {
            return 0;
        }
        self.blocks
            .saturating_sub(self.first_data_block)
            .div_ceil(self.blocks_per_group)
    }
    /// ext4 with extent trees — refuse rather than misread block maps.
    pub fn uses_extents(&self) -> bool {
        self.incompat & 0x40 != 0
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

/// Parse the superblock at byte 1024.
pub fn parse_super(io: &dyn BlockIo) -> Option<Super> {
    let mut sb_buf = [0u8; 1024];
    io.read(1024, &mut sb_buf).then_some(())?;
    if rd16(&sb_buf, 56)? != MAGIC {
        return None;
    }
    let log_block_size = rd32(&sb_buf, 24)?;
    if log_block_size > 2 {
        return None; // > 4096-byte blocks are outside what we buffer
    }
    let inodes = rd32(&sb_buf, 0)?;
    let blocks = rd32(&sb_buf, 4)?;
    let blocks_per_group = rd32(&sb_buf, 32)?;
    let inodes_per_group = rd32(&sb_buf, 40)?;
    if blocks == 0 || inodes == 0 || blocks_per_group == 0 || inodes_per_group == 0 {
        return None;
    }
    let rev = rd32(&sb_buf, 76)?;
    let inode_size = if rev == 0 {
        128
    } else {
        rd16(&sb_buf, 88).unwrap_or(128).max(128)
    };
    Some(Super {
        inodes,
        blocks,
        first_data_block: rd32(&sb_buf, 20)?,
        log_block_size,
        blocks_per_group,
        inodes_per_group,
        inode_size,
        rev,
        compat: rd32(&sb_buf, 92)?,
        incompat: rd32(&sb_buf, 96)?,
        ro_compat: rd32(&sb_buf, 100)?,
        first_ino: rd32(&sb_buf, 84).unwrap_or(11),
    })
}

/// Validate that the geometry fits the device we are reading.
pub fn validate(sb: &Super, dev_len: u64) -> bool {
    let bs = sb.block_size() as u64;
    if bs == 0 || dev_len < bs * (sb.blocks as u64) {
        return false;
    }
    if sb.gdt_block() as u64 * bs + 32 > dev_len {
        return false;
    }
    sb.groups() <= 1024
}

/// One group descriptor.
#[derive(Clone, Copy)]
pub struct Group {
    pub block_bitmap: u32,
    pub inode_bitmap: u32,
    pub inode_table: u32,
}

pub fn group(io: &dyn BlockIo, sb: &Super, g: u32) -> Option<Group> {
    let bs = sb.block_size() as u64;
    let off = sb.gdt_block() as u64 * bs + (g as u64) * 32;
    let mut b = [0u8; 32];
    io.read(off, &mut b).then_some(())?;
    Some(Group {
        block_bitmap: rd32(&b, 0)?,
        inode_bitmap: rd32(&b, 4)?,
        inode_table: rd32(&b, 8)?,
    })
}

/// A parsed inode (block map only; extents are refused).
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

/// Read inode number `ino` (1-based).
pub fn inode(io: &dyn BlockIo, sb: &Super, ino: u32) -> Option<Inode> {
    if ino == 0 || ino > sb.inodes || sb.inodes_per_group == 0 {
        return None;
    }
    let g = (ino - 1) / sb.inodes_per_group;
    let idx = (ino - 1) % sb.inodes_per_group;
    let grp = group(io, sb, g)?;
    let off = grp.inode_table as u64 * sb.block_size() as u64
        + idx as u64 * sb.inode_size as u64;
    let mut raw = [0u8; 128];
    io.read(off, &mut raw).then_some(())?;
    let mut block = [0u32; 15];
    for (i, b) in block.iter_mut().enumerate() {
        *b = rd32(&raw, 40 + i * 4)?;
    }
    Some(Inode {
        mode: rd16(&raw, 0)?,
        size: rd32(&raw, 4)?,
        block,
    })
}

/// One directory entry.
pub struct Dirent {
    pub ino: u32,
    pub name: [u8; 256],
    pub name_len: u8,
}

/// Logical block -> physical block via direct + single indirect.
pub fn block_map(io: &dyn BlockIo, sb: &Super, node: &Inode, lblock: u32) -> Option<u32> {
    let bs = sb.block_size();
    let per = bs / 4;
    if lblock < 12 {
        return Some(node.block[lblock as usize]);
    }
    let l = lblock - 12;
    if l < per {
        let ind = node.block[12];
        if ind == 0 {
            return Some(0);
        }
        let mut b = [0u8; 4];
        io.read(ind as u64 * bs as u64 + (l as u64) * 4, &mut b)
            .then_some(())?;
        return rd32(&b, 0);
    }
    // Double indirect: the block's index splits into a level-1 slot and a
    // level-2 slot. busybox is ~2.8 MiB, well past single-indirect.
    let d = l - per;
    if d < per.saturating_mul(per) {
        let dind = node.block[13];
        if dind == 0 {
            return Some(0);
        }
        let mut b = [0u8; 4];
        let l1_off = dind as u64 * bs as u64 + (d / per) as u64 * 4;
        io.read(l1_off, &mut b).then_some(())?;
        let l1 = rd32(&b, 0)?;
        if l1 == 0 {
            return Some(0);
        }
        let l2_off = l1 as u64 * bs as u64 + (d % per) as u64 * 4;
        io.read(l2_off, &mut b).then_some(())?;
        return rd32(&b, 0);
    }
    None
}

/// Walk a directory's linear entries.
pub fn dir_walk(
    io: &dyn BlockIo,
    sb: &Super,
    ino: u32,
    mut f: impl FnMut(&Dirent) -> bool,
) -> Option<()> {
    let bs = sb.block_size() as usize;
    let node = inode(io, sb, ino)?;
    if !node.is_dir() {
        return None;
    }
    let mut blk = [0u8; MAX_BLOCK];
    let mut pos = 0u32;
    while pos < node.size {
        let phys = block_map(io, sb, &node, pos / bs as u32)?;
        if phys == 0 {
            pos += bs as u32;
            continue;
        }
        io.read(phys as u64 * bs as u64, &mut blk[..bs]).then_some(())?;
        let mut off = 0usize;
        while off + 8 <= bs {
            let e_ino = rd32(&blk, off)?;
            let rec_len = rd16(&blk, off + 4)? as usize;
            let name_len = blk[off + 6] as usize;
            if rec_len < 8 || off + rec_len > bs {
                break;
            }
            if e_ino != 0 && name_len > 0 && name_len <= 255 && off + 8 + name_len <= bs {
                let mut name = [0u8; 256];
                name[..name_len].copy_from_slice(&blk[off + 8..off + 8 + name_len]);
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

/// Read up to `out.len()` bytes of inode `ino`'s content.
pub fn read_file(
    io: &dyn BlockIo,
    sb: &Super,
    ino: u32,
    out: &mut [u8],
) -> Option<usize> {
    let node = inode(io, sb, ino)?;
    if node.is_dir() {
        return None;
    }
    let bs = sb.block_size() as usize;
    let want = (node.size as usize).min(out.len());
    let mut blk = [0u8; MAX_BLOCK];
    let mut done = 0usize;
    while done < want {
        let phys = block_map(io, sb, &node, (done / bs) as u32)?;
        if phys == 0 {
            break; // sparse hole: stop rather than fabricate data
        }
        let off = done % bs;
        let take = (bs - off).min(want - done);
        io.read(phys as u64 * bs as u64 + off as u64, &mut blk[..take])
            .then_some(())?;
        out[done..done + take].copy_from_slice(&blk[..take]);
        done += take;
    }
    Some(done)
}

/// Look up `name` in directory `dir_ino`.
pub fn lookup(io: &dyn BlockIo, sb: &Super, dir_ino: u32, name: &[u8]) -> Option<u32> {
    let mut found = None;
    dir_walk(io, sb, dir_ino, |e| {
        if &e.name[..e.name_len as usize] == name {
            found = Some(e.ino);
            return false;
        }
        true
    })?;
    found
}

/// A real disk as a `BlockIo`: sector-granular reads bounced through a
/// 512-byte buffer, over whichever transport actually has the disk
/// (legacy PIIX or AHCI). Both underlying paths are already verified —
/// this is an adapter, not new I/O.
pub struct DiskIo {
    pub disk: usize,
}

impl BlockIo for DiskIo {
    fn len(&self) -> u64 {
        let p = crate::ata::capacity_d(self.disk);
        if p > 0 {
            p
        } else {
            crate::ahci::disk_capacity(self.disk)
        }
    }

    fn read(&self, off: u64, buf: &mut [u8]) -> bool {
        let total = self.len();
        if off >= total || off + buf.len() as u64 > total {
            return false;
        }
        let mut done = 0usize;
        let mut sec = [0u8; 512];
        while done < buf.len() {
            let pos = off + done as u64;
            let lba = pos / 512;
            let insec = (pos % 512) as usize;
            let ok = if crate::ata::sectors_d(self.disk) > 0 {
                crate::ata::read_d(lba as u32, &mut sec, self.disk)
            } else {
                crate::ahci::read_range(self.disk, lba, 1, &mut sec)
            };
            if !ok {
                return false;
            }
            let take = (512 - insec).min(buf.len() - done);
            buf[done..done + take].copy_from_slice(&sec[insec..insec + take]);
            done += take;
        }
        true
    }
}

/// A mounted filesystem: the superblock plus the byte offset of the
/// partition it lives in (0 for a whole-device filesystem).
pub struct Mount {
    pub sb: Super,
    pub base: u64,
}

/// An offset view of a device — a partition.
pub struct PartIo<'a> {
    pub dev: &'a dyn BlockIo,
    pub base: u64,
    pub size: u64,
}

impl BlockIo for PartIo<'_> {
    fn len(&self) -> u64 {
        self.size
    }
    fn read(&self, off: u64, buf: &mut [u8]) -> bool {
        if off + buf.len() as u64 > self.size {
            return false;
        }
        self.dev.read(self.base + off, buf)
    }
}

/// Mount the ext2/3 filesystem at `base` on `dev`. Returns None when
/// there is no ext2 there (wrong magic), when the geometry does not fit
/// the device, or when the filesystem uses ext4 extent trees — a reader
/// must refuse rather than misread them.
pub fn mount(dev: &dyn BlockIo, base: u64, size: u64) -> Option<Mount> {
    let part = PartIo { dev, base, size };
    let sb = parse_super(&part)?;
    if !validate(&sb, size) {
        return None;
    }
    if sb.uses_extents() {
        return None;
    }
    Some(Mount { sb, base })
}
