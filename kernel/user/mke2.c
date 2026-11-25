// mke2 — minimal ext2 formatter, userspace.
//
// The kernel mounts ext2 read-only, so formatting happens here over raw
// block writes — the same split real installers use (mkfs writes
// blocks, the kernel only reads the result).
//
// Host-testable: everything goes through mke2_write_fn, so a test can
// write a file and run fsck.ext2 on it before a disk is ever touched.
// That is how this was debugged — the first version had group-1
// descriptors pointing into group 0, an off-by-one in the bitmap bit
// order, and no i_blocks/filetype fields.
//
// Layout (1024-byte blocks, rev 1, 128-byte inodes, FILETYPE on):
//   group 0: block 2 = GDT, 3 = block bitmap, 4 = inode bitmap,
//            5.. = inode table
//   group g: bitmaps and inode table at the START of that group
// Bit order: block bitmap bit i = the group's i-th block; inode bitmap
// bit i = inode (g * ipg + i + 1). Bits past the group's extent are set
// (padding), which fsck checks.

#include <stdint.h>
#include <string.h>

typedef int (*mke2_write_fn)(void *ctx, uint64_t off, const void *buf,
                             uint32_t len);

/// A file to place in the root directory at format time. Files live in
/// the root for now (a real installer walks a tree); the point is that
/// the same pass that lays out the metadata allocates the blocks and
/// inodes, so the bitmaps never disagree with the content.
struct mke2_file {
    const char *path; // "README" or "etc/motd" — nested directories ok
    const void *data; // inline content, or NULL when streaming
    uint32_t len;
    // Streaming source: called with an offset inside the file. Lets the
    // installer place a 1 MiB binary from the initrd without holding it
    // in memory alongside everything else.
    int (*read)(void *ctx, uint32_t off, void *buf, uint32_t len);
    void *rctx;
    // Hardlink: when set this entry carries no data — its dirent points
    // at the inode of the earlier file whose path matches. This is how
    // busybox applets land without one copy of the binary per name.
    const char *alias;
};

#define BLOCK 1024u
#define BLOCKS_PER_GROUP 8192u
#define INODES_PER_GROUP 2048u
#define INODE_SIZE 128u
#define FIRST_INO 11u
#define ITABLE_BLOCKS ((INODES_PER_GROUP * INODE_SIZE) / BLOCK) /* 256 */

static void put16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
}
static void put32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}
static void setbit(uint8_t *bm, uint32_t i) {
    bm[i / 8] |= (uint8_t)(1u << (i % 8));
}

/// Mark `n` consecutive blocks starting at `blk` inside one group's
/// bitmap. Bit i covers absolute block gs+i; blocks outside this
/// group's range are skipped, so a caller can offer every allocated
/// block to every group and only the owning group claims it. Keeping
/// this check here matters: the payload allocates during group 0's
/// pass but a ~45 MiB payload spans far past block 8192 — indexing
/// this bitmap with `blk - gs` unconditionally would write past its
/// 1 KiB buffer and leave later groups' used blocks marked free.
static void mark_used(uint8_t *bm, uint32_t gs, uint32_t bits,
                      uint32_t blk, uint32_t n) {
    for (uint32_t i = 0; i < n; i++) {
        uint32_t b = blk + i;
        if (b >= gs && b - gs < bits) {
            setbit(bm, b - gs);
        }
    }
}

#define MKE2_MAX_DIRS 64
#define MKE2_MAX_FILES 160
struct mke2_dirrec {
    char path[56]; // full prefix: "lib", "lib/x86_64-linux-gnu"
    uint32_t ino;
    uint32_t blk;
    uint32_t nblk; // blocks this directory's entries need
};

static int mke2_dir_find(struct mke2_dirrec *d, uint32_t n, const char *p,
                         uint32_t len) {
    for (uint32_t i = 0; i < n; i++) {
        if (strlen(d[i].path) == len && strncmp(d[i].path, p, len) == 0) {
            return (int)i;
        }
    }
    return -1;
}

/// Create `path` (and every ancestor) if missing. Returns the index, or
/// -1 when the table is full. Parents are created first, so a directory
/// always has a lower index than its children.
static int mke2_dir_ensure(struct mke2_dirrec *d, uint32_t *n, const char *p,
                           uint32_t len) {
    if (len == 0) {
        return -1; // the root itself
    }
    if (len >= sizeof d[0].path) {
        return -1;
    }
    int have = mke2_dir_find(d, *n, p, len);
    if (have >= 0) {
        return have;
    }
    if (*n >= MKE2_MAX_DIRS) {
        return -1;
    }
    // Ancestors first.
    // No slash left means this is a top-level name: cut must be 0, or
    // the recursion below would call itself with the same length.
    uint32_t cut = 0;
    for (uint32_t i = len; i > 0; i--) {
        if (p[i - 1] == '/') {
            cut = i - 1;
            break;
        }
    }
    if (cut > 0 && mke2_dir_ensure(d, n, p, cut) < 0) {
        return -1;
    }
    uint32_t idx = (*n)++;
    memcpy(d[idx].path, p, len);
    d[idx].path[len] = 0;
    d[idx].ino = 0;
    d[idx].blk = 0;
    return (int)idx;
}

/// Index of a directory's parent, or -1 for the root.
static int mke2_dir_parent(struct mke2_dirrec *d, uint32_t n, uint32_t idx) {
    uint32_t len = (uint32_t)strlen(d[idx].path);
    for (uint32_t i = len; i > 0; i--) {
        if (d[idx].path[i - 1] == '/') {
            return mke2_dir_find(d, n, d[idx].path, i - 1);
        }
    }
    return -1;
}

/// Data region of the group `cur` falls in: [return, *end). A group
/// loses its first meta_end blocks to its own backup super, GDT,
/// bitmaps and inode table — group 0 also loses the boot block and
/// primary super — so payload blocks must never land inside it.
static uint32_t data_range(uint32_t cur, uint32_t blocks,
                           uint32_t gdt_blocks, uint32_t *end) {
    uint32_t g = (cur - 1) / BLOCKS_PER_GROUP;
    uint32_t gs = 1 + g * BLOCKS_PER_GROUP;
    uint32_t meta_end = 2 + ITABLE_BLOCKS +
        (g == 0 ? 2 + gdt_blocks : 1 + gdt_blocks);
    uint32_t dstart = gs + meta_end;
    uint32_t dend = gs + BLOCKS_PER_GROUP;
    if (dend > blocks) {
        dend = blocks;
    }
    *end = dend;
    return cur < dstart ? dstart : cur;
}

/// Allocate `n` contiguous blocks from data regions only, skipping
/// every group's metadata span. Returns the first block, or 0 when
/// the filesystem has no room — block 0 is unreachable because it
/// always lies inside group 0's metadata.
static uint32_t alloc_contig(uint32_t *cur, uint32_t n, uint32_t blocks,
                             uint32_t gdt_blocks) {
    for (;;) {
        uint32_t dend;
        uint32_t start = data_range(*cur, blocks, gdt_blocks, &dend);
        if (start + n > dend) {
            if (dend >= blocks) {
                return 0;
            }
            *cur = dend; // lands on the next group's metadata start
            continue;
        }
        *cur = start + n;
        return start;
    }
}

/// One directory entry as it is emitted into a dir block.
struct mke2_ent {
    const char *name;
    uint32_t ino;
    uint8_t type;
};

/// How many BLOCK-sized blocks a packed entry list spans. Must mirror
/// mke2_dir_write's packing: an entry is flushed to a new block when it
/// would cross the boundary; the previous entry's rec_len absorbs the
/// slack, so an entry never straddles blocks.
static uint32_t mke2_dir_nblk(const struct mke2_ent *ents, uint32_t ne) {
    uint32_t off = 0, nblk = 1;
    for (uint32_t e = 0; e < ne; e++) {
        uint32_t nl = 0;
        while (ents[e].name[nl]) {
            nl++;
        }
        uint32_t need = (8 + nl + 3) & ~3u;
        if (off + need > BLOCK) {
            nblk++;
            off = 0;
        }
        off += need;
    }
    return nblk;
}

/// Write a packed directory: entries laid out in order, each block's
/// last rec_len extended to the block end. Returns 0 or -30/-31 on
/// overflow/write failure — never silently truncates or spills.
static int mke2_dir_write(mke2_write_fn wr, void *ctx, uint64_t base,
                          uint32_t blk0, const struct mke2_ent *ents,
                          uint32_t ne) {
    static uint8_t db[BLOCK];
    uint32_t off = 0, last = 0, b = 0;
    memset(db, 0, sizeof db);
    for (uint32_t e = 0; e < ne; e++) {
        uint32_t nl = 0;
        while (ents[e].name[nl]) {
            nl++;
        }
        uint32_t need = (8 + nl + 3) & ~3u;
        if (off + need > BLOCK) {
            if (off == 0) {
                return -30; // a single entry can never exceed a block
            }
            put16(db + last + 4, (uint16_t)(BLOCK - last));
            if (wr(ctx, base + (blk0 + b) * BLOCK, db, BLOCK)) {
                return -31;
            }
            b++;
            memset(db, 0, sizeof db);
            off = 0;
        }
        put32(db + off, ents[e].ino);
        put16(db + off + 4, (uint16_t)need);
        db[off + 6] = (uint8_t)nl;
        db[off + 7] = ents[e].type;
        memcpy(db + off + 8, ents[e].name, nl);
        last = off;
        off += need;
    }
    put16(db + last + 4, (uint16_t)(BLOCK - last));
    if (wr(ctx, base + (blk0 + b) * BLOCK, db, BLOCK)) {
        return -31;
    }
    return 0;
}

/// Format `blocks` 1024-byte blocks starting at byte `base`.
static int mke2_format(mke2_write_fn wr, void *ctx, uint64_t base,
                       uint32_t blocks, const struct mke2_file *files,
                       uint32_t nfiles) {
    uint32_t groups = (blocks + BLOCKS_PER_GROUP - 1) / BLOCKS_PER_GROUP;
    if (groups == 0) {
        groups = 1;
    }
    // Group 0 needs: boot+super(2) + gdt + bbitmap + ibitmap + itable.
    uint32_t gdt_blocks = (groups * 32 + BLOCK - 1) / BLOCK;
    uint32_t first_data = 2 + gdt_blocks + 2 + ITABLE_BLOCKS;
    if (blocks <= first_data + 2) {
        return -1; // too small
    }
    uint32_t inodes = groups * INODES_PER_GROUP;

    uint8_t z[BLOCK];
    memset(z, 0, sizeof z);

    // Per-group metadata positions.
    uint32_t g_start[64];
    uint32_t used_blocks = 0, used_inodes = 0, dirs = 0;
    for (uint32_t g = 0; g < groups && g < 64; g++) {
        g_start[g] = 1 + g * BLOCKS_PER_GROUP;
    }

    // Root (2) and lost+found (11) each own blocks right after the
    // metadata of group 0; the root's span depends on its entry count,
    // so lf_blk is fixed once the payload is known.
    uint32_t root_blk = first_data;
    uint32_t root_nblk = 1;
    uint32_t lf_blk = first_data + 1;

    // ---- superblock ----
    static uint8_t sb[BLOCK];
    memset(sb, 0, sizeof sb);
    // Count used blocks: metadata per group + root + lost+found.
    for (uint32_t g = 0; g < groups && g < 64; g++) {
        uint32_t m = 2 + ITABLE_BLOCKS; // bbitmap, ibitmap, itable
        if (g == 0) {
            m += 2 + gdt_blocks;        // boot+super + gdt
        }
        used_blocks += m;
    }
    used_blocks += 2; // root + lost+found (patched once root_nblk is known)
    used_inodes = FIRST_INO; // inodes 1..11 reserved (1 is bad-blocks)
    // One inode per real file; hardlink entries share their target's.
    for (uint32_t f = 0; f < nfiles && f < MKE2_MAX_FILES; f++) {
        if (!files[f].alias) {
            used_inodes++;
        }
    }
    dirs = 2;                // root + lost+found

    put32(sb + 0, inodes);
    put32(sb + 4, blocks);
    put32(sb + 8, 0);
    put32(sb + 12, blocks - used_blocks);
    put32(sb + 16, inodes - used_inodes);
    put32(sb + 20, 1);                       // s_first_data_block
    put32(sb + 24, 0);                       // log_block_size -> 1024
    put32(sb + 28, 0);
    put32(sb + 32, BLOCKS_PER_GROUP);
    put32(sb + 36, BLOCKS_PER_GROUP);
    put32(sb + 40, INODES_PER_GROUP);
    put32(sb + 44, 0);
    put32(sb + 48, 0);
    put16(sb + 52, 0);
    put16(sb + 54, 0xffff);
    put16(sb + 56, 0xef53);
    put16(sb + 58, 1);                       // clean
    put16(sb + 60, 1);                       // continue on error
    put32(sb + 76, 1);                       // rev 1
    put32(sb + 84, FIRST_INO);
    put16(sb + 88, INODE_SIZE);
    sb[104] = 1;                             // s_block_group_nr
    put32(sb + 96, 0x2);                     // incompat: FILETYPE
    if (wr(ctx, base + BLOCK, sb, BLOCK)) {
        return -11;
    }

    // Group descriptors are written at the end, once each bitmap's set
    // bits are known, so the free counts can never disagree with the
    // padding (the bug that made e2fsck reject the first two versions).

    // ---- bitmaps, inode tables and descriptors, per group ----
    static uint8_t gdt[BLOCK * 4];
    memset(gdt, 0, sizeof gdt);
    uint32_t total_free = 0;

    // Files are placed in group 0, immediately after the root and
    // lost+found blocks. Allocating here — in the same pass that builds
    // the bitmaps — is what keeps the bitmaps and the content in
    // agreement; a second pass would have to re-read and re-derive.
    struct placed {
        uint32_t ino;
        uint32_t blk;
        uint32_t len;
        uint32_t dir; // index into dirs[], or 0xffffffff for the root
        uint32_t ind; // single-indirect block, 0 when the file is small
        uint32_t dind; // double-indirect block, 0 when not needed
        uint32_t alias; // placed[] index this hardlinks, or 0xffffffff
        uint32_t nb;  // data blocks this file owns
        uint32_t l2n; // level-2 pointer blocks behind dind
        const char *name;
    } placed[MKE2_MAX_FILES];
    uint32_t nplaced = 0;
    if (nfiles > MKE2_MAX_FILES) {
        return -32;
    }

    // Directories come from the file paths, at any depth:
    // "lib/x86_64-linux-gnu/libc.so.6" creates lib, lib/x86_64-linux-gnu
    // and puts the file in the innermost one.
    struct mke2_dirrec subdirs[MKE2_MAX_DIRS];
    uint32_t ndirs = 0;
    for (uint32_t f = 0; f < nfiles; f++) {
        const char *p = files[f].path;
        const char *slash = 0;
        for (const char *q = p; *q; q++) {
            if (*q == '/') {
                slash = q;
            }
        }
        uint32_t d = 0xffffffffu;
        const char *base = p;
        if (slash) {
            uint32_t n = (uint32_t)(slash - p);
            int di = mke2_dir_ensure(subdirs, &ndirs, p, n);
            if (di >= 0) {
                d = (uint32_t)di;
            }
            base = slash + 1;
        }
        // Hardlink entries must name an earlier non-alias file — a
        // dangling or chained alias has no inode to share.
        uint32_t alias = 0xffffffffu;
        if (files[f].alias) {
            for (uint32_t g = 0; g < f; g++) {
                if (!files[g].alias && strcmp(files[g].path, files[f].alias) == 0) {
                    alias = g;
                    break;
                }
            }
            if (alias == 0xffffffffu) {
                return -33;
            }
        }
        placed[nplaced].len = files[f].len;
        placed[nplaced].dir = d;
        placed[nplaced].name = base;
        placed[nplaced].ino = 0;
        placed[nplaced].blk = 0;
        placed[nplaced].ind = 0;
        placed[nplaced].dind = 0;
        placed[nplaced].alias = alias;
        placed[nplaced].nb = 0;
        placed[nplaced].l2n = 0;
        nplaced++;
    }
    used_inodes += ndirs;    // one inode per created directory

    // Size every directory's span before the bitmap pass so block
    // allocation can reserve the whole range at once. Entries are
    // packed in the order the emit pass uses: ".", "..", child dirs,
    // then files — so the count here must see the same names.
    {
        struct mke2_ent probe[3 + MKE2_MAX_DIRS + MKE2_MAX_FILES];
        for (uint32_t i = 0; i < ndirs; i++) {
            uint32_t ne = 0;
            probe[ne].name = ".";   probe[ne].ino = 2; probe[ne].type = 2; ne++;
            probe[ne].name = "..";  probe[ne].ino = 2; probe[ne].type = 2; ne++;
            for (uint32_t k = 0; k < ndirs; k++) {
                if (mke2_dir_parent(subdirs, ndirs, k) != (int)i) {
                    continue;
                }
                const char *nm = subdirs[k].path;
                for (const char *q = subdirs[k].path; *q; q++) {
                    if (*q == '/') {
                        nm = q + 1;
                    }
                }
                probe[ne].name = nm;
                probe[ne].ino = 2;
                probe[ne].type = 2;
                ne++;
            }
            for (uint32_t f = 0; f < nplaced; f++) {
                if (placed[f].dir == i) {
                    probe[ne].name = placed[f].name;
                    probe[ne].ino = 2;
                    probe[ne].type = 1;
                    ne++;
                }
            }
            subdirs[i].nblk = mke2_dir_nblk(probe, ne);
        }
        // The root directory: ".", "..", "lost+found", top-level dirs,
        // files with no parent directory.
        uint32_t ne = 0;
        probe[ne].name = ".";          probe[ne].ino = 2; probe[ne].type = 2; ne++;
        probe[ne].name = "..";         probe[ne].ino = 2; probe[ne].type = 2; ne++;
        probe[ne].name = "lost+found"; probe[ne].ino = 2; probe[ne].type = 2; ne++;
        for (uint32_t i = 0; i < ndirs; i++) {
            if (mke2_dir_parent(subdirs, ndirs, i) != -1) {
                continue;
            }
            const char *nm = subdirs[i].path;
            for (const char *q = subdirs[i].path; *q; q++) {
                if (*q == '/') {
                    nm = q + 1;
                }
            }
            probe[ne].name = nm;
            probe[ne].ino = 2;
            probe[ne].type = 2;
            ne++;
        }
        for (uint32_t f = 0; f < nplaced; f++) {
            if (placed[f].dir == 0xffffffffu) {
                probe[ne].name = placed[f].name;
                probe[ne].ino = 2;
                probe[ne].type = 1;
                ne++;
            }
        }
        root_nblk = mke2_dir_nblk(probe, ne);
    }
    lf_blk = root_blk + root_nblk;
    used_blocks += root_nblk - 1; // root grew past its first block
    uint32_t next_data_blk = lf_blk + 1;
    uint32_t next_ino = FIRST_INO + 1;
    for (uint32_t g = 0; g < groups && g < 64; g++) {
        uint32_t gs = g_start[g];
        uint32_t bbitmap, ibitmap, itable;
        if (g == 0) {
            bbitmap = 2 + gdt_blocks;
            ibitmap = bbitmap + 1;
            itable = ibitmap + 1;
        } else {
            // ext2 puts a BACKUP superblock and GDT copy at the start of
            // each backup group; the bitmaps follow them. (Without this,
            // e2fsck rejects group 1 with "bad block for block bitmap"
            // and cannot use the backups it expects to find.)
            bbitmap = gs + 1 + gdt_blocks;
            ibitmap = bbitmap + 1;
            itable = ibitmap + 1;
        }
        // Blocks this group owns: it starts at `gs` and the last one is
        // blocks-1 (block 0 has no bitmap bit). A full group therefore
        // covers bpg blocks and a partial one covers blocks-gs.
        uint32_t in_group = BLOCKS_PER_GROUP;
        if (blocks - gs < in_group) {
            in_group = blocks - gs;
        }
        uint32_t bitmap_bits = in_group;

        static uint8_t bm[BLOCK];
        memset(bm, 0, sizeof bm);
        // Metadata bit indices 0..meta_end-1: the super (and GDT for
        // group 0, backups for the rest), both bitmaps, the inode table,
        // and — for group 0 — the root block, which sits immediately
        // after the table. lost+found follows it.
        uint32_t meta_end = 2 + ITABLE_BLOCKS + (g == 0 ? 2 + gdt_blocks : 1 + gdt_blocks);
        for (uint32_t i = 0; i < meta_end; i++) {
            setbit(bm, i);
        }
        if (g == 0) {
            // Allocation only: assign inos and block ranges. Bitmap
            // marking is the per-group pass below — a data block past
            // 8192 belongs to a later group's bitmap, and writing
            // `blk - gs` into group 0's 1 KiB map anyway would scribble
            // past the buffer.
            for (uint32_t i = 0; i < ndirs; i++) {
                subdirs[i].ino = next_ino++;
                subdirs[i].blk = alloc_contig(&next_data_blk,
                                              subdirs[i].nblk, blocks,
                                              gdt_blocks);
                if (subdirs[i].blk == 0) {
                    return -34;
                }
            }
            for (uint32_t f = 0; f < nplaced; f++) {
                if (placed[f].alias != 0xffffffffu) {
                    continue; // hardlink: shares its target's inode
                }
                uint32_t nb = (placed[f].len + BLOCK - 1) / BLOCK;
                if (nb == 0) {
                    nb = 1;
                }
                placed[f].ino = next_ino++;
                placed[f].nb = nb;
                placed[f].blk = alloc_contig(&next_data_blk, nb, blocks,
                                             gdt_blocks);
                if (placed[f].blk == 0) {
                    return -34; // payload larger than the partition
                }
                // Data blocks are contiguous; a file over 12 blocks also
                // needs one indirect block (256 more pointers at 1 KiB
                // blocks, so up to 268 KiB per file here).
                if (nb > 12) {
                    placed[f].ind = alloc_contig(&next_data_blk, 1,
                                                 blocks, gdt_blocks);
                    if (placed[f].ind == 0) {
                        return -34;
                    }
                }
                // Past 12 direct + 256 indirect entries, a second level
                // of indirection is needed (12 + 256 + 256*256 blocks).
                if (nb > 12 + BLOCK / 4) {
                    // The level-2 pointer blocks live right after the
                    // double-indirect block — one contiguous run so the
                    // emit pass finds them at dind + 1 + i.
                    uint32_t per2 = BLOCK / 4;
                    uint32_t rest2 = nb - (12 + per2);
                    placed[f].l2n = (rest2 + per2 - 1) / per2;
                    placed[f].dind = alloc_contig(&next_data_blk,
                                                  1 + placed[f].l2n,
                                                  blocks, gdt_blocks);
                    if (placed[f].dind == 0) {
                        return -34;
                    }
                }
            }
            // Alias entries resolve now that every real file owns an
            // inode — the dirent written later carries the target's ino.
            for (uint32_t f = 0; f < nplaced; f++) {
                if (placed[f].alias != 0xffffffffu) {
                    placed[f].ino = placed[placed[f].alias].ino;
                }
            }
        }
        // Per-group marking: claim the payload blocks inside this
        // group's range. Runs for every group, not just 0 — allocation
        // above spans the whole filesystem.
        mark_used(bm, gs, bitmap_bits, root_blk, root_nblk);
        mark_used(bm, gs, bitmap_bits, lf_blk, 1);
        for (uint32_t i = 0; i < ndirs; i++) {
            mark_used(bm, gs, bitmap_bits, subdirs[i].blk,
                      subdirs[i].nblk);
        }
        for (uint32_t f = 0; f < nplaced; f++) {
            if (placed[f].alias != 0xffffffffu) {
                continue;
            }
            mark_used(bm, gs, bitmap_bits, placed[f].blk, placed[f].nb);
            if (placed[f].ind) {
                mark_used(bm, gs, bitmap_bits, placed[f].ind, 1);
            }
            if (placed[f].dind) {
                mark_used(bm, gs, bitmap_bits, placed[f].dind,
                          1 + placed[f].l2n);
            }
        }
        // Padding: bits with no block behind them (the final bit of the
        // last group, because block 0 has no bit).
        for (uint32_t i = bitmap_bits; i < BLOCK * 8; i++) {
            setbit(bm, i);
        }
        if (wr(ctx, base + bbitmap * BLOCK, bm, BLOCK)) {
            return -12;
        }
        // Count only bits INSIDE the extent: padding bits are outside it
        // and must not reduce the free count.
        uint32_t set = 0;
        for (uint32_t i = 0; i < bitmap_bits && i < BLOCK * 8; i++) {
            if ((bm[i / 8] >> (i % 8)) & 1) {
                set++;
            }
        }
        // Free blocks. A full group's extent includes block 0, which is
        // used but has no bitmap bit; a partial group's does not.

        uint32_t gfree = in_group - set;


        static uint8_t im[BLOCK];
        memset(im, 0, sizeof im);
        // Hardlink entries share an inode, so only non-alias files take
        // an ino — the bitmap must mark exactly what was consumed.
        uint32_t nreal = 0;
        for (uint32_t f = 0; f < nplaced; f++) {
            if (placed[f].alias == 0xffffffffu) {
                nreal++;
            }
        }
        if (g == 0) {
            uint32_t upto = FIRST_INO + ndirs + nreal;
            if (upto > INODES_PER_GROUP) {
                upto = INODES_PER_GROUP;
            }
            for (uint32_t i = 0; i < upto; i++) {
                setbit(im, i);
            }
        }
        for (uint32_t i = INODES_PER_GROUP; i < BLOCK * 8; i++) {
            setbit(im, i);
        }
        if (wr(ctx, base + ibitmap * BLOCK, im, BLOCK)) {
            return -13;
        }
        uint32_t ifree =
            INODES_PER_GROUP - (g == 0 ? FIRST_INO + ndirs + nreal : 0);

        uint8_t *e = gdt + g * 32;
        put32(e + 0, bbitmap);
        put32(e + 4, ibitmap);
        put32(e + 8, itable);
        put16(e + 12, (uint16_t)gfree);
        total_free += gfree;
        put16(e + 14, (uint16_t)ifree);
        put16(e + 16, (uint16_t)(g == 0 ? dirs + ndirs : 0));

        if (g > 0) {
            // Backup superblock (same bytes, s_block_group_nr set) and a
            // copy of the group descriptor table.
            static uint8_t bsb[BLOCK];
            memcpy(bsb, sb, BLOCK);
            bsb[104] = (uint8_t)g;
            if (wr(ctx, base + gs * BLOCK, bsb, BLOCK)) {
                return -14;
            }
            if (wr(ctx, base + (gs + 1) * BLOCK, gdt, gdt_blocks * BLOCK)) {
                return -15;
            }
        }
        // Inode table: zero it, then write the two real inodes at their
        // exact offsets (inode 11 is at byte 1280 — the second block).
        for (uint32_t b = 0; b < ITABLE_BLOCKS; b++) {
            static uint8_t it[BLOCK];
            memset(it, 0, sizeof it);
            if (wr(ctx, base + (itable + b) * BLOCK, it, BLOCK)) {
                return -16;
            }
        }
        if (g == 0) {
            static uint8_t ino[INODE_SIZE];
            memset(ino, 0, sizeof ino);
            put16(ino + 0, 0x41ed);
            // links: ".", "..", lost+found, plus one per subdirectory
            // (each subdir's ".." points back here).
            {
                // Only TOP-LEVEL directories add a link to the root
                // (each contributes one ".."); nested ones do not.
                uint32_t top = 0;
                for (uint32_t k = 0; k < ndirs; k++) {
                    if (mke2_dir_parent(subdirs, ndirs, k) == -1) {
                        top++;
                    }
                }
                put16(ino + 26, (uint16_t)(3 + top));
            }
            put32(ino + 4, root_nblk * BLOCK);
            put32(ino + 28, root_nblk * (BLOCK / 512));
            for (uint32_t i = 0; i < root_nblk && i < 12; i++) {
                put32(ino + 40 + i * 4, root_blk + i);
            }
            if (wr(ctx, base + itable * BLOCK + 1 * INODE_SIZE, ino, INODE_SIZE)) {
                return -17;
            }
            memset(ino, 0, sizeof ino);
            put16(ino + 0, 0x41c0);
            put16(ino + 26, 2);
            put32(ino + 4, BLOCK);
            put32(ino + 28, 2);
            put32(ino + 40, lf_blk);
            if (wr(ctx, base + itable * BLOCK + (FIRST_INO - 1) * INODE_SIZE,
                   ino, INODE_SIZE)) {
                return -18;
            }
        }
    }
    if (wr(ctx, base + 2 * BLOCK, gdt, gdt_blocks * BLOCK)) {
        return -19;
    }
    // The superblock's totals must equal what the groups actually hold,
    // so rewrite them now that every bitmap is built (the earlier
    // estimate was off by one per group boundary).
    put32(sb + 12, total_free);
    put32(sb + 16, inodes - used_inodes);
    if (wr(ctx, base + BLOCK, sb, BLOCK)) {
        return -20;
    }

    // ---- directories: inode + block with ".", "..", and their files ----
    for (uint32_t i = 0; i < ndirs; i++) {
        static uint8_t ino[INODE_SIZE];
        memset(ino, 0, sizeof ino);
        put16(ino + 0, 0x41ed);              // S_IFDIR|0755
        {
            // "." and the parent's entry, plus one per child directory.
            uint32_t kids = 0;
            for (uint32_t k = 0; k < ndirs; k++) {
                if (mke2_dir_parent(subdirs, ndirs, k) == (int)i) {
                    kids++;
                }
            }
            put16(ino + 26, (uint16_t)(2 + kids));
        }
        put32(ino + 4, subdirs[i].nblk * BLOCK);
        put32(ino + 28, subdirs[i].nblk * (BLOCK / 512));
        for (uint32_t b = 0; b < subdirs[i].nblk && b < 12; b++) {
            put32(ino + 40 + b * 4, subdirs[i].blk + b);
        }
        if (wr(ctx, base + (2 + gdt_blocks + 2) * BLOCK
               + (subdirs[i].ino - 1) * INODE_SIZE, ino, INODE_SIZE)) {
            return -24;
        }
        // Entries: ".", "..", then the files that live here.
        struct mke2_ent ents[2 + MKE2_MAX_DIRS + MKE2_MAX_FILES];
        uint32_t ne = 0;
        ents[ne].name = ".";  ents[ne].ino = subdirs[i].ino; ents[ne].type = 2; ne++;
        // ".." is the PARENT, not always the root — nested directories
        // must point at their real parent or fsck rejects the link.
        int par = mke2_dir_parent(subdirs, ndirs, i);
        ents[ne].name = "..";
        ents[ne].ino = par < 0 ? 2 : subdirs[par].ino;
        ents[ne].type = 2;
        ne++;
        for (uint32_t k = 0; k < ndirs; k++) {
            if (mke2_dir_parent(subdirs, ndirs, k) != (int)i) {
                continue;
            }
            const char *nm = subdirs[k].path;
            for (const char *q = subdirs[k].path; *q; q++) {
                if (*q == '/') {
                    nm = q + 1;
                }
            }
            ents[ne].name = nm;
            ents[ne].ino = subdirs[k].ino;
            ents[ne].type = 2;
            ne++;
        }
        for (uint32_t f = 0; f < nplaced; f++) {
            if (placed[f].dir == i) {
                ents[ne].name = placed[f].name;
                ents[ne].ino = placed[f].ino;
                ents[ne].type = 1;
                ne++;
            }
        }
        int dr = mke2_dir_write(wr, ctx, base, subdirs[i].blk, ents, ne);
        if (dr != 0) {
            return dr;
        }
    }

    // ---- file inodes and data ----
    for (uint32_t f = 0; f < nplaced; f++) {
        if (placed[f].alias != 0xffffffffu) {
            continue; // hardlink: no inode or data of its own
        }
        static uint8_t ino[INODE_SIZE];
        memset(ino, 0, sizeof ino);
        put16(ino + 0, 0x81a4);                 // S_IFREG|0644
        // links: 1 for its own name plus every alias dirent pointing
        // at this inode — e2fsck reconciles i_links_count with the
        // dirents it sees.
        uint32_t refs = 1;
        for (uint32_t g = 0; g < nplaced; g++) {
            if (placed[g].alias == f) {
                refs++;
            }
        }
        put16(ino + 26, (uint16_t)refs);        // links
        put32(ino + 4, placed[f].len);          // size
        {
            uint32_t nb = (placed[f].len + BLOCK - 1) / BLOCK;
            if (nb == 0) {
                nb = 1;
            }
            // i_blocks counts the indirect block too, in 512-byte units.
            {
                // i_blocks counts data + indirect + double-indirect +
                // every level-2 pointer block, in 512-byte units.
                uint32_t per3 = BLOCK / 4;
                uint32_t l2n3 = 0;
                if (placed[f].dind) {
                    uint32_t rest3 = nb > 12 + per3 ? nb - (12 + per3) : 0;
                    l2n3 = (rest3 + per3 - 1) / per3;
                }
                uint32_t tot = nb + (placed[f].ind ? 1 : 0)
                    + (placed[f].dind ? 1 : 0) + l2n3;
                put32(ino + 28, tot * (BLOCK / 512));
            }
        }
        {
            // All twelve direct pointers, not just the first: leaving
            // 1..11 zero marked their blocks used but unreferenced.
            uint32_t nb3 = (placed[f].len + BLOCK - 1) / BLOCK;
            if (nb3 == 0) {
                nb3 = 1;
            }
            uint32_t ndir = nb3 < 12 ? nb3 : 12;
            for (uint32_t k = 0; k < ndir; k++) {
                put32(ino + 40 + k * 4, placed[f].blk + k);
            }
            if (placed[f].ind != 0) {
                put32(ino + 40 + 12 * 4, placed[f].ind); // block[12]
            }
            if (placed[f].dind != 0) {
                put32(ino + 40 + 13 * 4, placed[f].dind); // block[13]
            }
        }
        // The inode table starts right after group 0's two bitmaps —
        // NOT at root_blk (the first data block), which is where the
        // first version of this wrote the inode.
        if (wr(ctx, base + (2 + gdt_blocks + 2) * BLOCK
               + (placed[f].ino - 1) * INODE_SIZE, ino, INODE_SIZE)) {
            return -20;
        }
        // Data: the source buffer may be shorter than a block, so pad.
        static uint8_t db[BLOCK];
        uint32_t left = placed[f].len;
        uint32_t consumed = 0; // explicit offset for the streaming reader
        const uint8_t *src = (const uint8_t *)files[f].data;
        uint32_t b = 0;
        do {
            uint32_t take = left < BLOCK ? left : BLOCK;
            memset(db, 0, sizeof db);
            if (take > 0) {
                if (files[f].read) {
                    if (files[f].read(files[f].rctx, consumed, db, take) != 0) {
                        return -29;
                    }
                    consumed += take;
                } else {
                    memcpy(db, src, take);
                    src += take;
                }
                left -= take;
            }
            if (wr(ctx, base + (placed[f].blk + b) * BLOCK, db, BLOCK)) {
                return -21;
            }
            b++;
        } while (left > 0);
        if (placed[f].ind != 0) {
            static uint8_t ib[BLOCK];
            memset(ib, 0, sizeof ib);
            uint32_t nb2 = (placed[f].len + BLOCK - 1) / BLOCK;
            for (uint32_t k = 12; k < nb2 && k - 12 < BLOCK / 4; k++) {
                put32(ib + (k - 12) * 4, placed[f].blk + k);
            }
            if (wr(ctx, base + placed[f].ind * BLOCK, ib, BLOCK)) {
                return -26;
            }
        }
        if (placed[f].dind != 0) {
            // Level 1: pointers to level-2 blocks; level 2: data blocks.
            uint32_t nb2 = (placed[f].len + BLOCK - 1) / BLOCK;
            uint32_t per = BLOCK / 4;
            uint32_t first = 12 + per; // first block handled here
            uint32_t rest = nb2 > first ? nb2 - first : 0;
            uint32_t l2count = (rest + per - 1) / per;
            static uint8_t l1[BLOCK];
            memset(l1, 0, sizeof l1);
            for (uint32_t i = 0; i < l2count && i < per; i++) {
                static uint8_t l2[BLOCK];
                memset(l2, 0, sizeof l2);
                for (uint32_t k = 0; k < per; k++) {
                    uint32_t idx = i * per + k;
                    if (idx >= rest) {
                        break;
                    }
                    put32(l2 + k * 4, placed[f].blk + first + idx);
                }
                // Level-2 blocks are allocated contiguously after dind.
                uint32_t l2blk = placed[f].dind + 1 + i;
                if (wr(ctx, base + l2blk * BLOCK, l2, BLOCK)) {
                    return -27;
                }
                put32(l1 + i * 4, l2blk);
            }
            if (wr(ctx, base + placed[f].dind * BLOCK, l1, BLOCK)) {
                return -28;
            }
        }
    }

    // ---- root directory ----
    {
        // ".", "..", "lost+found", then the files.
        struct mke2_ent ents[3 + MKE2_MAX_DIRS + MKE2_MAX_FILES];
        uint32_t ne = 0;
        ents[ne].name = ".";          ents[ne].ino = 2;         ents[ne].type = 2; ne++;
        ents[ne].name = "..";         ents[ne].ino = 2;         ents[ne].type = 2; ne++;
        ents[ne].name = "lost+found"; ents[ne].ino = FIRST_INO; ents[ne].type = 2; ne++;
        for (uint32_t i = 0; i < ndirs; i++) {
            if (mke2_dir_parent(subdirs, ndirs, i) != -1) {
                continue; // belongs to a subdirectory, not the root
            }
            // The entry name is the last component of the path; the
            // directory's parent decides which listing it appears in.
            const char *nm = subdirs[i].path;
            for (const char *q = subdirs[i].path; *q; q++) {
                if (*q == '/') {
                    nm = q + 1;
                }
            }
            ents[ne].name = nm;
            ents[ne].ino = subdirs[i].ino;
            ents[ne].type = 2;
            ne++;
        }
        for (uint32_t f = 0; f < nplaced; f++) {
            if (placed[f].dir != 0xffffffffu) {
                continue; // lives inside its directory
            }
            ents[ne].name = placed[f].name;
            ents[ne].ino = placed[f].ino;
            ents[ne].type = 1; // regular file
            ne++;
        }
        int dr = mke2_dir_write(wr, ctx, base, root_blk, ents, ne);
        if (dr != 0) {
            return dr;
        }
    }

    // ---- lost+found ----
    static uint8_t dir[BLOCK];
    memset(dir, 0, sizeof dir);
    put32(dir + 0, FIRST_INO);
    put16(dir + 4, 12);
    dir[6] = 1;
    dir[7] = 2;
    dir[8] = '.';
    put32(dir + 12, 2);
    put16(dir + 16, (uint16_t)(BLOCK - 12));
    dir[18] = 2;
    dir[19] = 2;
    dir[20] = '.';
    dir[21] = '.';
    if (wr(ctx, base + lf_blk * BLOCK, dir, BLOCK)) {
        return -23;
    }
    return 0;
}
