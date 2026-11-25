//! ext2/3/4 — read-only driver for the ext family.
//!
//! ext2 was the first rung: same superblock, group descriptors, inode
//! table and directory format across the family. ext3 layers a
//! journal on identical block maps — a read-only mount just skips the
//! journal inode. ext4 layers extents, 64-bit block numbers, wider
//! group descriptors and larger inode sizes — all handled per-inode
//! and per-superblock here. The journal is never replayed: read-only
//! mounts don't need it (same trade-off as Linux norecovery).
//!
//! Everything goes through [`BlockIo`], so the same code reads an
//! in-memory image (tests) or a real block device (a root partition)
//! over ATA PIO, AHCI or virtio-blk.
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

// incompat bits this reader honors. Bits outside the mask change
// on-disk semantics we do not implement (external journal, meta_bg
// descriptor placement, inline data, encryption, bigalloc cluster
// addressing, casefold) — a filesystem carrying any of them is
// refused at mount rather than misread.
const INCOMPAT_FILETYPE: u32 = 0x0002;
const INCOMPAT_RECOVER: u32 = 0x0004;
const INCOMPAT_EXTENTS: u32 = 0x0040;
const INCOMPAT_64BIT: u32 = 0x0080;
const INCOMPAT_MMP: u32 = 0x0100;
const INCOMPAT_FLEX_BG: u32 = 0x0200;
const INCOMPAT_EA_INODE: u32 = 0x0400;
const INCOMPAT_DIRDATA: u32 = 0x1000;
const INCOMPAT_CSUM_SEED: u32 = 0x2000;
const INCOMPAT_LARGEDIR: u32 = 0x4000;
const INCOMPAT_OK: u32 = INCOMPAT_FILETYPE
    | INCOMPAT_RECOVER
    | INCOMPAT_EXTENTS
    | INCOMPAT_64BIT
    | INCOMPAT_MMP
    | INCOMPAT_FLEX_BG
    | INCOMPAT_EA_INODE
    | INCOMPAT_DIRDATA
    | INCOMPAT_CSUM_SEED
    | INCOMPAT_LARGEDIR;
/// ro_compat bit that changes block addressing — clusters instead of
/// blocks — which none of the map code understands.
const ROCOMPAT_BIGALLOC: u32 = 0x0200;

/// ext4 inode flags.
const EXT4_EXTENTS_FL: u32 = 0x0008_0000;
const EXT4_INLINE_DATA_FL: u32 = 0x1000_0000;
const EXT4_ENCRYPT_FL: u32 = 0x0000_0800;

/// ext4 extent-tree node magic.
const EXTENT_MAGIC: u16 = 0xf30a;
/// Tree depth cap — on-disk depth tops out at 5; one more is corrupt.
const MAX_EXT_DEPTH: u32 = 5;

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
    /// Group-descriptor stride (ext4 64bit widens it to 64 bytes).
    pub desc_size: u16,
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
    /// ext4 fs-level extents feature — per-inode EXT4_EXTENTS_FL is
    /// what actually selects the map format.
    pub fn uses_extents(&self) -> bool {
        self.incompat & INCOMPAT_EXTENTS != 0
    }
    /// ext3/ext4 carries a journal inode; mounting read-only with a
    /// clean journal is safe — RECOVER set means the fs is dirty and
    /// the journal needs replay, which a reader skips at its own risk
    /// (same trade-off Linux's norecovery ro-mount makes).
    pub fn has_journal(&self) -> bool {
        self.compat & 0x4 != 0 // EXT3_FEATURE_COMPAT_HAS_JOURNAL
    }
    /// Feature check: every incompat bit must be in the readable
    /// mask, and bigalloc (cluster addressing) is refused outright.
    pub fn readable(&self) -> bool {
        self.incompat & !INCOMPAT_OK == 0 && self.ro_compat & ROCOMPAT_BIGALLOC == 0
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
    let incompat = rd32(&sb_buf, 96)?;
    // s_desc_size only counts when 64bit is set; ext4 expects 64.
    let desc_size = if incompat & INCOMPAT_64BIT != 0 {
        let d = rd16(&sb_buf, 0xfe).unwrap_or(32).max(32);
        if d > 1024 {
            return None;
        }
        d
    } else {
        32
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
        incompat,
        ro_compat: rd32(&sb_buf, 100)?,
        first_ino: rd32(&sb_buf, 84).unwrap_or(11),
        desc_size,
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

/// One group descriptor — block numbers stay u64 so a 64bit fs
/// resolves hi dwords; on a <=4 GiB image the hi words are 0 anyway.
#[derive(Clone, Copy)]
pub struct Group {
    pub block_bitmap: u64,
    pub inode_bitmap: u64,
    pub inode_table: u64,
}

pub fn group(io: &dyn BlockIo, sb: &Super, g: u32) -> Option<Group> {
    let bs = sb.block_size() as u64;
    let off = sb.gdt_block() as u64 * bs + (g as u64) * sb.desc_size as u64;
    let mut b = [0u8; 64];
    let n = (sb.desc_size as usize).min(64);
    io.read(off, &mut b[..n]).then_some(())?;
    let lo = |o: usize| rd32(&b, o).unwrap_or(0) as u64;
    let hi = |o: usize| -> u64 {
        if sb.desc_size >= 64 {
            (rd32(&b, o).unwrap_or(0) as u64) << 32
        } else {
            0
        }
    };
    Some(Group {
        block_bitmap: lo(0) | hi(0x20),
        inode_bitmap: lo(4) | hi(0x24),
        inode_table: lo(8) | hi(0x28),
    })
}

/// A parsed inode — `iblock` is kept raw (60 bytes) because ext4
/// reuses it as an extent-tree root while ext2/3 treat it as a block
/// map; flags pick the interpretation.
#[derive(Clone, Copy)]
pub struct Inode {
    pub mode: u16,
    pub flags: u32,
    /// Logical size in bytes (i_size_hi folded in for regular files).
    pub size: u64,
    pub iblock: [u8; 60],
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
    let off = grp.inode_table * sb.block_size() as u64
        + idx as u64 * sb.inode_size as u64;
    let mut raw = [0u8; 128];
    io.read(off, &mut raw).then_some(())?;
    let mut iblock = [0u8; 60];
    iblock.copy_from_slice(&raw[40..100]);
    let mode = rd16(&raw, 0)?;
    // i_size_high at offset 108 only counts for regular files — for
    // directories the field is i_dir_acl, for others osd scratch.
    let size = rd32(&raw, 4)? as u64
        | if mode & 0xf000 == 0x8000 {
            (rd32(&raw, 108)? as u64) << 32
        } else {
            0
        };
    Some(Inode {
        mode,
        flags: rd32(&raw, 32)?,
        size,
        iblock,
    })
}

/// One directory entry.
pub struct Dirent {
    pub ino: u32,
    pub name: [u8; 256],
    pub name_len: u8,
}

/// Logical block -> physical block. The inode's flags pick the map:
/// ext4 inodes carry an extent tree in iblock, ext2/3 inodes carry
/// the classic direct + indirect block map. 0 means sparse hole.
pub fn block_map(io: &dyn BlockIo, sb: &Super, node: &Inode, lblock: u32) -> Option<u64> {
    if node.flags & EXT4_INLINE_DATA_FL != 0 || node.flags & EXT4_ENCRYPT_FL != 0 {
        // Data lives inside the inode/xattrs or under a cipher — a
        // reader cannot produce plaintext; refuse rather than guess.
        return None;
    }
    if node.flags & EXT4_EXTENTS_FL != 0 {
        return ext_walk(io, sb, &node.iblock, lblock, MAX_EXT_DEPTH);
    }
    let bs = sb.block_size();
    let per = bs / 4;
    let blk = |i: usize| -> Option<u64> {
        Some(rd32(&node.iblock, i * 4)? as u64)
    };
    if lblock < 12 {
        return blk(lblock as usize);
    }
    let l = lblock - 12;
    if l < per {
        let ind = blk(12)? as u32;
        if ind == 0 {
            return Some(0);
        }
        let mut b = [0u8; 4];
        io.read(ind as u64 * bs as u64 + (l as u64) * 4, &mut b)
            .then_some(())?;
        return Some(rd32(&b, 0)? as u64);
    }
    // Double indirect: the block's index splits into a level-1 slot and a
    // level-2 slot. busybox is ~2.8 MiB, well past single-indirect.
    let d = l - per;
    if d < per.saturating_mul(per) {
        let dind = blk(13)? as u32;
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
        return Some(rd32(&b, 0)? as u64);
    }
    // Triple indirect: three levels of fan-out through iblock[14].
    let t = d - per.saturating_mul(per);
    if t < per.saturating_mul(per).saturating_mul(per) {
        let tind = blk(14)? as u32;
        if tind == 0 {
            return Some(0);
        }
        let mut b = [0u8; 4];
        let l0_off = tind as u64 * bs as u64 + (t / (per * per)) as u64 * 4;
        io.read(l0_off, &mut b).then_some(())?;
        let l0 = rd32(&b, 0)?;
        if l0 == 0 {
            return Some(0);
        }
        let rem = t % (per * per);
        let l1_off = l0 as u64 * bs as u64 + (rem / per) as u64 * 4;
        io.read(l1_off, &mut b).then_some(())?;
        let l1 = rd32(&b, 0)?;
        if l1 == 0 {
            return Some(0);
        }
        let l2_off = l1 as u64 * bs as u64 + (rem % per) as u64 * 4;
        io.read(l2_off, &mut b).then_some(())?;
        return Some(rd32(&b, 0)? as u64);
    }
    None
}

/// Walk one extent-tree node: `node` is the inode's 60-byte iblock at
/// the root, or a full fs block at interior levels. Header layout:
/// magic u16 @0, entries u16 @2, max u16 @4, depth u16 @6, gen u32 @8.
/// Entries are 12 B: depth 0 = extent {blk u32, len u16, start_hi u16,
/// start_lo u32}; depth >0 = index {blk u32, leaf_lo u32, leaf_hi u16,
/// unused u16}.
fn ext_walk(io: &dyn BlockIo, sb: &Super, node: &[u8], lblock: u32, depth_left: u32) -> Option<u64> {
    if depth_left == 0 || node.len() < 12 || rd16(node, 0)? != EXTENT_MAGIC {
        return None;
    }
    let entries = (rd16(node, 2)? as usize).min((node.len() - 12) / 12);
    let depth = rd16(node, 6)? as u32;
    if depth == 0 {
        for i in 0..entries {
            let e = 12 + i * 12;
            let blk = rd32(node, e)?;
            if lblock < blk {
                return Some(0); // leading hole before this extent
            }
            let raw_len = rd16(node, e + 4)? as u32;
            let len = if raw_len > 32768 {
                raw_len - 32768
            } else {
                raw_len
            };
            if lblock < blk.saturating_add(len) {
                // Unwritten extent (len > 32768 on disk): the fs hands
                // back zeroes — our hole contract is the same "0".
                if raw_len > 32768 {
                    return Some(0);
                }
                let start =
                    rd32(node, e + 8)? as u64 | (rd16(node, e + 6)? as u64) << 32;
                return Some(start + (lblock - blk) as u64);
            }
        }
        return Some(0); // hole past the last extent
    }
    // Interior node: follow the index with the largest ei_block <=
    // lblock — entries are sorted, so break on the first overshoot.
    let mut leaf = None;
    for i in 0..entries {
        let e = 12 + i * 12;
        let blk = rd32(node, e)?;
        if blk > lblock {
            break;
        }
        leaf = Some(rd32(node, e + 4)? as u64 | (rd16(node, e + 8)? as u64) << 32);
    }
    let leaf = leaf?;
    let bs = sb.block_size() as usize;
    let mut buf = [0u8; MAX_BLOCK];
    io.read(leaf * bs as u64, &mut buf[..bs]).then_some(())?;
    ext_walk(io, sb, &buf[..bs], lblock, depth_left - 1)
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
    let mut pos = 0u64;
    while pos < node.size {
        let phys = block_map(io, sb, &node, (pos / bs as u64) as u32)?;
        if phys == 0 {
            pos += bs as u64;
            continue;
        }
        io.read(phys * bs as u64, &mut blk[..bs]).then_some(())?;
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
        pos += bs as u64;
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
    let want = node.size.min(out.len() as u64) as usize;
    let mut blk = [0u8; MAX_BLOCK];
    let mut done = 0usize;
    while done < want {
        let phys = block_map(io, sb, &node, (done / bs) as u32)?;
        if phys == 0 {
            break; // sparse hole: stop rather than fabricate data
        }
        let off = done % bs;
        let take = (bs - off).min(want - done);
        io.read(phys * bs as u64 + off as u64, &mut blk[..take])
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

/// Total disk count across all transports — the bound a scanner
/// should iterate `DiskIo{disk}` over.
pub fn disk_count() -> usize {
    let n_ata = (0..2).filter(|&d| crate::ata::sectors_d(d) > 0).count();
    n_ata + crate::ahci::disks() as usize + crate::virtio::disks() as usize
}

/// Which transport owns global disk index `i`: ATA occupies the low
/// indices (its own 0/1 master/slave numbering), then AHCI disks,
/// then virtio disks.
fn transport(i: usize) -> (u8, usize) {
    let n_ata = (0..2).filter(|&d| crate::ata::sectors_d(d) > 0).count();
    if i < n_ata {
        return (0, i);
    }
    let i = i - n_ata;
    let n_ahci = crate::ahci::disks() as usize;
    if i < n_ahci {
        return (1, i);
    }
    (2, i - n_ahci)
}

impl BlockIo for DiskIo {
    fn len(&self) -> u64 {
        match transport(self.disk) {
            (0, i) => crate::ata::capacity_d(i),
            (1, i) => crate::ahci::disk_capacity(i),
            (_, i) => crate::virtio::disk_capacity(i),
        }
    }

    fn read(&self, off: u64, buf: &mut [u8]) -> bool {
        let total = self.len();
        if off >= total || off + buf.len() as u64 > total {
            return false;
        }
        let (tr, i) = transport(self.disk);
        let mut done = 0usize;
        let mut sec = [0u8; 512];
        while done < buf.len() {
            let pos = off + done as u64;
            let lba = pos / 512;
            let insec = (pos % 512) as usize;
            let ok = match tr {
                0 => crate::ata::read_d(lba as u32, &mut sec, i),
                1 => crate::ahci::read_range(i, lba, 1, &mut sec),
                _ => crate::virtio::read_range(i, lba, 1, &mut sec),
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

/// Mount the ext2/3/4 filesystem at `base` on `dev`. Returns None when
/// there is no ext* there (wrong magic), when the geometry does not fit
/// the device, or when the filesystem carries incompat features a
/// read-only walk cannot honor (journal device, meta_bg placement,
/// inline data, encryption, bigalloc) — a reader must refuse rather
/// than misread.
pub fn mount(dev: &dyn BlockIo, base: u64, size: u64) -> Option<Mount> {
    let part = PartIo { dev, base, size };
    let sb = parse_super(&part)?;
    if !validate(&sb, size) || !sb.readable() {
        return None;
    }
    Some(Mount { sb, base })
}
