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
    const char *path; // "README" or "etc/motd" — one directory level
    const void *data;
    uint32_t len;
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

    // Root (2) and lost+found (11) each own one block, placed after the
    // metadata of group 0.
    uint32_t root_blk = first_data;
    uint32_t lf_blk = first_data + 1;

    // ---- superblock ----
    uint8_t sb[BLOCK];
    memset(sb, 0, sizeof sb);
    // Count used blocks: metadata per group + root + lost+found.
    for (uint32_t g = 0; g < groups && g < 64; g++) {
        uint32_t m = 2 + ITABLE_BLOCKS; // bbitmap, ibitmap, itable
        if (g == 0) {
            m += 2 + gdt_blocks;        // boot+super + gdt
        }
        used_blocks += m;
    }
    used_blocks += 2; // root + lost+found
    used_inodes = FIRST_INO; // inodes 1..11 reserved (1 is bad-blocks)
    used_inodes += nfiles;   // one inode per placed file
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
    uint8_t gdt[BLOCK * 4];
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
        const char *name;
    } placed[16];
    uint32_t nplaced = 0;

    // Directories come from the file paths: "etc/motd" creates "etc" and
    // puts the file inside it. One level is enough for /etc, /bin, /lib.
    struct mke2_dir {
        char name[16];
        uint32_t ino;
        uint32_t blk;
    } subdirs[8];
    uint32_t ndirs = 0;
    for (uint32_t f = 0; f < nfiles && f < 16; f++) {
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
            if (n > 0 && n < sizeof subdirs[0].name) {
                for (uint32_t i = 0; i < ndirs; i++) {
                    if (strncmp(subdirs[i].name, p, n) == 0 && subdirs[i].name[n] == 0) {
                        d = i;
                        break;
                    }
                }
                if (d == 0xffffffffu && ndirs < 8) {
                    memcpy(subdirs[ndirs].name, p, n);
                    subdirs[ndirs].name[n] = 0;
                    d = ndirs++;
                }
            }
            base = slash + 1;
        }
        placed[nplaced].len = files[f].len;
        placed[nplaced].dir = d;
        placed[nplaced].name = base;
        placed[nplaced].ino = 0;
        placed[nplaced].blk = 0;
        placed[nplaced].ind = 0;
        nplaced++;
    }
    used_inodes += ndirs;    // one inode per created directory
    uint32_t next_data_blk = first_data + 2;
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

        uint8_t bm[BLOCK];
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
            setbit(bm, root_blk - gs);
            setbit(bm, lf_blk - gs);
            for (uint32_t i = 0; i < ndirs; i++) {
                subdirs[i].ino = next_ino++;
                subdirs[i].blk = next_data_blk++;
                setbit(bm, subdirs[i].blk - gs);
            }
            for (uint32_t f = 0; f < nplaced; f++) {
                uint32_t nb = (placed[f].len + BLOCK - 1) / BLOCK;
                if (nb == 0) {
                    nb = 1;
                }
                placed[f].ino = next_ino++;
                placed[f].blk = next_data_blk;
                // Data blocks are contiguous; a file over 12 blocks also
                // needs one indirect block (256 more pointers at 1 KiB
                // blocks, so up to 268 KiB per file here).
                uint32_t ndata = nb <= 12 ? nb : nb;
                for (uint32_t b = 0; b < ndata; b++) {
                    setbit(bm, placed[f].blk + b - gs);
                }
                next_data_blk += ndata;
                if (nb > 12) {
                    placed[f].ind = next_data_blk++;
                    setbit(bm, placed[f].ind - gs);
                }
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


        uint8_t im[BLOCK];
        memset(im, 0, sizeof im);
        if (g == 0) {
            uint32_t upto = FIRST_INO + ndirs + nplaced;
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
            INODES_PER_GROUP - (g == 0 ? FIRST_INO + ndirs + nplaced : 0);

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
            uint8_t bsb[BLOCK];
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
            uint8_t it[BLOCK];
            memset(it, 0, sizeof it);
            if (wr(ctx, base + (itable + b) * BLOCK, it, BLOCK)) {
                return -16;
            }
        }
        if (g == 0) {
            uint8_t ino[INODE_SIZE];
            memset(ino, 0, sizeof ino);
            put16(ino + 0, 0x41ed);
            // links: ".", "..", lost+found, plus one per subdirectory
            // (each subdir's ".." points back here).
            put16(ino + 26, (uint16_t)(3 + ndirs));
            put32(ino + 4, BLOCK);
            put32(ino + 28, 2);
            put32(ino + 40, root_blk);
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
        uint8_t ino[INODE_SIZE];
        memset(ino, 0, sizeof ino);
        put16(ino + 0, 0x41ed);              // S_IFDIR|0755
        put16(ino + 26, 2);                  // links: "." and parent's entry
        put32(ino + 4, BLOCK);               // size
        put32(ino + 28, BLOCK / 512);        // i_blocks
        put32(ino + 40, subdirs[i].blk);
        if (wr(ctx, base + (2 + gdt_blocks + 2) * BLOCK
               + (subdirs[i].ino - 1) * INODE_SIZE, ino, INODE_SIZE)) {
            return -24;
        }
        // Entries: ".", "..", then the files that live here.
        struct {
            const char *name;
            uint32_t ino;
            uint8_t type;
        } ents[2 + 16];
        uint32_t ne = 0;
        ents[ne].name = ".";  ents[ne].ino = subdirs[i].ino; ents[ne].type = 2; ne++;
        ents[ne].name = ".."; ents[ne].ino = 2;           ents[ne].type = 2; ne++;
        for (uint32_t f = 0; f < nplaced; f++) {
            if (placed[f].dir == i) {
                ents[ne].name = placed[f].name;
                ents[ne].ino = placed[f].ino;
                ents[ne].type = 1;
                ne++;
            }
        }
        uint8_t db[BLOCK];
        memset(db, 0, sizeof db);
        uint32_t off2 = 0;
        for (uint32_t e = 0; e < ne; e++) {
            uint32_t nl = 0;
            while (ents[e].name[nl]) {
                nl++;
            }
            uint32_t need = (8 + nl + 3) & ~3u;
            uint32_t rec = (e + 1 == ne) ? (BLOCK - off2) : need;
            put32(db + off2, ents[e].ino);
            put16(db + off2 + 4, (uint16_t)rec);
            db[off2 + 6] = (uint8_t)nl;
            db[off2 + 7] = ents[e].type;
            memcpy(db + off2 + 8, ents[e].name, nl);
            off2 += rec;
        }
        if (wr(ctx, base + subdirs[i].blk * BLOCK, db, BLOCK)) {
            return -25;
        }
    }

    // ---- file inodes and data ----
    for (uint32_t f = 0; f < nplaced; f++) {
        uint8_t ino[INODE_SIZE];
        memset(ino, 0, sizeof ino);
        put16(ino + 0, 0x81a4);                 // S_IFREG|0644
        put16(ino + 26, 1);                     // links
        put32(ino + 4, placed[f].len);          // size
        {
            uint32_t nb = (placed[f].len + BLOCK - 1) / BLOCK;
            if (nb == 0) {
                nb = 1;
            }
            // i_blocks counts the indirect block too, in 512-byte units.
            put32(ino + 28, (nb + (placed[f].ind ? 1 : 0)) * (BLOCK / 512));
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
        }
        // The inode table starts right after group 0's two bitmaps —
        // NOT at root_blk (the first data block), which is where the
        // first version of this wrote the inode.
        if (wr(ctx, base + (2 + gdt_blocks + 2) * BLOCK
               + (placed[f].ino - 1) * INODE_SIZE, ino, INODE_SIZE)) {
            return -20;
        }
        // Data: the source buffer may be shorter than a block, so pad.
        uint8_t db[BLOCK];
        uint32_t left = placed[f].len;
        const uint8_t *src = (const uint8_t *)files[f].data;
        uint32_t b = 0;
        do {
            uint32_t take = left < BLOCK ? left : BLOCK;
            memset(db, 0, sizeof db);
            if (take > 0) {
                memcpy(db, src, take);
                src += take;
                left -= take;
            }
            if (wr(ctx, base + (placed[f].blk + b) * BLOCK, db, BLOCK)) {
                return -21;
            }
            b++;
        } while (left > 0);
        if (placed[f].ind != 0) {
            uint8_t ib[BLOCK];
            memset(ib, 0, sizeof ib);
            uint32_t nb2 = (placed[f].len + BLOCK - 1) / BLOCK;
            for (uint32_t k = 12; k < nb2 && k - 12 < BLOCK / 4; k++) {
                put32(ib + (k - 12) * 4, placed[f].blk + k);
            }
            if (wr(ctx, base + placed[f].ind * BLOCK, ib, BLOCK)) {
                return -26;
            }
        }
    }

    // ---- root directory ----
    // Built entry by entry so the last one can absorb the slack; the
    // final rec_len must reach the end of the block.
    uint8_t dir[BLOCK];
    memset(dir, 0, sizeof dir);
    uint32_t off = 0;
    {
        // ".", "..", "lost+found", then the files.
        struct {
            const char *name;
            uint32_t ino;
            uint8_t type;
        } ents[3 + 16];
        uint32_t ne = 0;
        ents[ne].name = ".";          ents[ne].ino = 2;         ents[ne].type = 2; ne++;
        ents[ne].name = "..";         ents[ne].ino = 2;         ents[ne].type = 2; ne++;
        ents[ne].name = "lost+found"; ents[ne].ino = FIRST_INO; ents[ne].type = 2; ne++;
        for (uint32_t i = 0; i < ndirs; i++) {
            ents[ne].name = subdirs[i].name;
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
        for (uint32_t i = 0; i < ne; i++) {
            uint32_t nl = 0;
            while (ents[i].name[nl]) {
                nl++;
            }
            uint32_t need = (8 + nl + 3) & ~3u;
            uint32_t rec = (i + 1 == ne) ? (BLOCK - off) : need;
            put32(dir + off, ents[i].ino);
            put16(dir + off + 4, (uint16_t)rec);
            dir[off + 6] = (uint8_t)nl;
            dir[off + 7] = ents[i].type;
            memcpy(dir + off + 8, ents[i].name, nl);
            off += rec;
        }
    }
    if (wr(ctx, base + root_blk * BLOCK, dir, BLOCK)) {
        return -22;
    }

    // ---- lost+found ----
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
