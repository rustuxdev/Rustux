//! fbcon — framebuffer terminal over the UEFI Graphics Output Protocol.
//!
//! Two layers, like Linux's vc console: a cell grid (char+attr per row/col)
//! holding the screen model, and a renderer that paints cells through the
//! klib CP437 font. Output runs through a VT100/xterm-subset parser — CSI
//! cursor ops, SGR colors, DEC line-drawing, alt screen, scroll region —
//! so full-screen ncurses apps (htop) draw correctly. Serial gets the raw
//! byte stream in parallel; whatever it doesn't parse a real terminal does.

use core::fmt::{self, Write};
use core::ptr;

use uefi::boot;
use uefi::proto::console::gop::{GraphicsOutput, PixelFormat};

use klib::font::{FONT_8X16, FONT_8X16_H, FONT_8X16_W};

/// Terminal grid (cols, rows) for TIOCGWINSZ — recorded when the GOP
/// console initializes; (0,0) means no console exists and callers
/// fall back to the 80x25 convention.
static mut TTY_DIMS: (u16, u16) = (0, 0);

/// The console's (cols, rows), or (0,0) before init/without a GOP.
pub fn tty_dims() -> (u16, u16) {
    // SAFETY: set once at init before any syscall can run; single CPU.
    unsafe { *core::ptr::addr_of!(TTY_DIMS) }
}

/// Application-cursor mode (DECSET ?1): arrows send SS3 (\eOA..) instead
/// of CSI (\e[A..). kbd reads this to pick the sequence.
static mut APP_CURSOR: bool = false;

/// DECSET ?1 state — terminal input mode for arrow keys.
pub fn app_cursor() -> bool {
    // SAFETY: single CPU, write only in console write context.
    unsafe { *core::ptr::addr_of!(APP_CURSOR) }
}

use crate::logo_data::{LOGO_H, LOGO_RGB, LOGO_W};

const BG: u32 = 0x00000000; // black background
const FG_BOOT: u32 = 0x0000ff7f; // accent for the banner line

// xterm 16-color palette, 0x00RRGGBB.
const PALETTE: [u32; 16] = [
    0x000000, 0xcd0000, 0x00cd00, 0xcdcd00, 0x0000ee, 0xcd00cd, 0x00cdcd,
    0xe5e5e5, 0x7f7f7f, 0xff0000, 0x00ff00, 0xffff00, 0x5c5cff, 0xff00ff,
    0x00ffff, 0xffffff,
];

const MAX_COLS: usize = 160; // 1280/8
const MAX_ROWS: usize = 64; // 1024/16
const BLANK: u16 = ((0x07u16) << 8) | b' ' as u16; // ' ' with default attr

// Cell = u16: low byte CP437 glyph, high byte attr (fg[3:0] | bg[6:4] | ul[7]).
static mut GRID: [u16; MAX_COLS * MAX_ROWS] = [BLANK; MAX_COLS * MAX_ROWS];
static mut GRID_ALT: [u16; MAX_COLS * MAX_ROWS] = [BLANK; MAX_COLS * MAX_ROWS];

// DEC special-graphics charset (VT100 G0='0') → CP437 approximations,
// indexed by (ascii - 0x5f); entries 0 mean "use the ascii char".
#[rustfmt::skip]
const DEC_GFX: [u8; 32] = [
    0x20, // _ blank
    0x04, // ` diamond      0x61 a -> shaded
    0xB1, // a checker      0x09->space for controls:
    0x20, 0x20, 0x20, 0x20, // b c d e (ht/ff/cr/lf)
    0xF8, // f degree
    0xF1, // g plus-minus
    0x20, 0x20, // h i (nl/vt)
    0xD9, 0xBF, 0xDA, 0xC0, 0xC5, // j k l m n corners/cross
    0xDF, 0xDF, 0xC4, 0xDC, 0xDC, // o p q r s scan lines
    0xC3, 0xB4, 0xC1, 0xC2, 0xB3, // t u v w x tees/vert
    0xF3, 0xF2, 0xE3, 0x21, 0x9C, 0xFA, // y z { | } ~
];

#[derive(Clone, Copy, PartialEq)]
enum EscState {
    Norm,
    Got,               // bare ESC received
    Csi,               // ESC [ — collecting params
    Osc,               // ESC ] — swallow until BEL or ESC backslash
    Charset,           // ESC ( ) * + — next byte designates
    Hash,              // ESC # — DECALN etc, one more byte
}

pub struct FbConsole {
    base: *mut u8,
    size: usize,
    stride: usize, // pixels per scanline
    width: usize,
    height: usize,
    bgr: bool,
    cols: usize,
    rows: usize,
    top: usize, // first text row; rows above it (the splash) never scroll
    cx: usize,
    cy: usize,
    // terminal state
    attr: u8,
    scr_top: usize,
    scr_bot: usize,
    saved: (usize, usize, u8),
    saved_alt: (usize, usize, u8), // cursor+attr saved at ?1049h entry
    g0_gfx: bool,
    alt: bool,
    cur_vis: bool,
    bold: bool, // SGR 1 intensity — persistent until 22/reset
    last_glyph: u8, // last emitted char — REP (CSI Ps b) repeats it
    esc: EscState,
    params: [u16; 16],
    nparams: usize,
    csi_private: bool,
    utf8_cp: u32,
    utf8_need: u8,
    dirty_lo: usize,
    dirty_hi: usize,
    cur_drawn: Option<(usize, usize)>,
}

impl FbConsole {
    /// Locate the GOP framebuffer and claim it. Returns `None` when no GOP is
    /// present or the active mode is not a direct-write 32bpp format.
    pub fn new() -> Option<Self> {
        let handle = boot::get_handle_for_protocol::<GraphicsOutput>().ok()?;
        let mut gop = boot::open_protocol_exclusive::<GraphicsOutput>(handle).ok()?;
        let info = gop.current_mode_info();
        let bgr = match info.pixel_format() {
            PixelFormat::Bgr => true,
            PixelFormat::Rgb => false,
            _ => return None, // Bitmask/BltOnly: unsupported for now
        };
        let (width, height) = info.resolution();
        let stride = info.stride();
        let mut fb = gop.frame_buffer();
        let base = fb.as_mut_ptr();
        let size = fb.size();
        if base.is_null() || size < stride * 4 || width < FONT_8X16_W || height < FONT_8X16_H {
            return None;
        }
        let cols = (width / FONT_8X16_W).min(MAX_COLS);
        let rows = (height / FONT_8X16_H).min(MAX_ROWS);
        // Record the tty grid for TIOCGWINSZ before the console moves
        // out — a u16 can't overflow since GOP modes stay < 65536px.
        unsafe {
            *core::ptr::addr_of_mut!(TTY_DIMS) = (cols as u16, rows as u16)
        };
        let mut con = Self {
            base,
            size,
            stride,
            width,
            height,
            bgr,
            cols,
            rows,
            top: 0,
            cx: 0,
            cy: 0,
            attr: 0x07,
            scr_top: 0,
            scr_bot: rows - 1,
            saved: (0, 0, 0x07),
            saved_alt: (0, 0, 0x07),
            g0_gfx: false,
            alt: false,
            cur_vis: true,
            bold: false,
            last_glyph: b' ',
            esc: EscState::Norm,
            params: [0; 16],
            nparams: 0,
            csi_private: false,
            utf8_cp: 0,
            utf8_need: 0,
            dirty_lo: MAX_ROWS,
            dirty_hi: 0,
            cur_drawn: None,
        };
        con.clear_screen();
        Some(con)
    }

    #[inline]
    fn px(&mut self, x: usize, y: usize, px: u32) {
        let off = y * self.stride * 4 + x * 4;
        if off + 3 >= self.size {
            return;
        }
        // SAFETY: off+3 is inside the framebuffer per the bounds check above;
        // volatile because this is MMIO-backed memory.
        unsafe {
            let p = self.base.add(off) as *mut u32;
            // Constants are 0x00RRGGBB. Bgr memory order is [B,G,R,X] so the
            // u32 can go out as-is; Rgb wants [R,G,B,X] — swap the R/B lanes.
            let v = if self.bgr {
                px
            } else {
                (px >> 16) | (px & 0x0000_ff00) | ((px & 0xff) << 16)
            };
            ptr::write_volatile(p, v);
        }
    }

    #[inline]
    fn cell(&self, x: usize, y: usize) -> u16 {
        // SAFETY: x < cols <= MAX_COLS, y < rows <= MAX_ROWS enforced by
        // every caller; single CPU.
        unsafe { (*core::ptr::addr_of!(GRID))[y * MAX_COLS + x] }
    }

    #[inline]
    fn put_cell(&mut self, x: usize, y: usize, c: u16) {
        if x >= self.cols || y >= self.rows {
            return;
        }
        // SAFETY: in-bounds per the check above; single CPU.
        unsafe {
            (*core::ptr::addr_of_mut!(GRID))[y * MAX_COLS + x] = c;
        }
    }

    fn mark_dirty(&mut self, lo: usize, hi: usize) {
        if lo < self.dirty_lo {
            self.dirty_lo = lo;
        }
        if hi > self.dirty_hi {
            self.dirty_hi = hi;
        }
    }

    /// Paint one cell's glyph with its attr (fg/bg/underline).
    fn draw_cell(&mut self, x: usize, y: usize) {
        let cell = self.cell(x, y);
        let ch = (cell & 0xff) as u8;
        let attr = (cell >> 8) as u8;
        let fg = PALETTE[(attr & 0x0f) as usize];
        let bg = PALETTE[((attr >> 4) & 0x07) as usize];
        let ul = attr & 0x80 != 0;
        let gi = ch as usize * FONT_8X16_H;
        let x0 = x * FONT_8X16_W;
        let y0 = y * FONT_8X16_H;
        for row in 0..FONT_8X16_H {
            let mut bits = FONT_8X16[gi + row];
            if ul && row >= FONT_8X16_H - 2 {
                bits = 0xff;
            }
            for col in 0..FONT_8X16_W {
                let v = if bits & (0x80 >> col) != 0 { fg } else { bg };
                self.px(x0 + col, y0 + row, v);
            }
        }
    }

    /// Repaint all rows marked dirty, then draw the cursor (underline)
    /// when visible.
    fn paint_dirty(&mut self) {
        // Repaint the cell under the previously drawn cursor — its row
        // may not be dirty, so dropping the Option alone leaves stale
        // underline pixels on screen.
        self.erase_cursor();
        let (lo, hi) = (self.dirty_lo.min(self.rows - 1), self.dirty_hi.min(self.rows - 1));
        if lo <= hi {
            for y in lo..=hi {
                for x in 0..self.cols {
                    self.draw_cell(x, y);
                }
            }
            self.dirty_lo = MAX_ROWS;
            self.dirty_hi = 0;
        }
        if self.cur_vis {
            self.draw_cursor();
        }
    }

    /// Underline cursor at (cx, cy) — XOR the bottom two scanlines so a
    /// later cell repaint needs no bookkeeping to erase it.
    fn draw_cursor(&mut self) {
        if self.cy >= self.rows || self.cx >= self.cols {
            return;
        }
        let cell = self.cell(self.cx, self.cy);
        let attr = (cell >> 8) as u8;
        let fg = PALETTE[(attr & 0x0f) as usize];
        let y0 = self.cy * FONT_8X16_H;
        for row in FONT_8X16_H - 2..FONT_8X16_H {
            for col in 0..FONT_8X16_W {
                self.px(self.cx * FONT_8X16_W + col, y0 + row, fg);
            }
        }
        self.cur_drawn = Some((self.cx, self.cy));
    }

    /// Repaint the cell the cursor was drawn over (normal cell render).
    fn erase_cursor(&mut self) {
        if let Some((x, y)) = self.cur_drawn.take() {
            self.draw_cell(x, y);
        }
    }

    fn clear_screen(&mut self) {
        for y in 0..self.rows {
            for x in 0..self.cols {
                self.put_cell(x, y, BLANK);
            }
        }
        for y in 0..self.height {
            for x in 0..self.width {
                self.px(x, y, BG);
            }
        }
        self.cx = 0;
        self.cy = 0;
    }

    /// Move `n` screen rows of text inside [top, bot) up `dir=+1` or
    /// down `dir=-1`; framebuffer scanlines memmove, grid rows shift,
    /// the vacated edge is cleared and repainted.
    fn scroll_rows(&mut self, top: usize, bot: usize, n: usize, up: bool) {
        if n == 0 || top >= bot || bot > self.rows {
            return;
        }
        let n = n.min(bot - top);
        let rb = self.stride * 4;
        let gh = FONT_8X16_H;
        // Framebuffer move (full-width scanlines of the region).
        let (dst_px, src_px) = if up {
            (top * gh, (top + n) * gh)
        } else {
            ((top + n) * gh, top * gh)
        };
        let move_bytes = rb * gh * (bot - top - n);
        // SAFETY: both ends stay inside the region's scanlines, which are
        // all below rows*gh <= height*stride*4 <= size. memmove semantics.
        unsafe {
            ptr::copy(
                self.base.add(src_px * rb),
                self.base.add(dst_px * rb),
                move_bytes,
            );
        }
        // Grid shift.
        unsafe {
            let g = &mut *core::ptr::addr_of_mut!(GRID);
            if up {
                for y in top..bot - n {
                    for x in 0..self.cols {
                        g[y * MAX_COLS + x] = g[(y + n) * MAX_COLS + x];
                    }
                }
            } else {
                for y in ((top + n)..bot).rev() {
                    for x in 0..self.cols {
                        g[y * MAX_COLS + x] = g[(y - n) * MAX_COLS + x];
                    }
                }
            }
        }
        let (lo, hi) = if up { (bot - n, bot) } else { (top, top + n) };
        for y in lo..hi {
            for x in 0..self.cols {
                self.put_cell(x, y, BLANK);
            }
        }
        self.mark_dirty(lo, hi - 1);
    }

    /// LF/VT/FF/IND: column 0 + advance, scrolling the region when at
    /// its bottom. Linux's vc `lf()` returns the cursor to column 0 —
    /// our console has no output ldisc (no OPOST/ONLCR), so kernel
    /// printk and user writes rely on that semantic for column-0 text.
    fn linefeed(&mut self) {
        self.erase_cursor();
        self.cx = 0;
        if self.cy == self.scr_bot {
            self.scroll_rows(self.scr_top, self.scr_bot + 1, 1, true);
        } else if self.cy < self.rows - 1 {
            self.cy += 1;
        }
    }

    /// Printable byte -> cell at cursor with current attr (+DEC gfx map).
    fn put_glyph(&mut self, mut c: u8) {
        self.erase_cursor();
        if self.g0_gfx && (0x5f..=0x7e).contains(&c) {
            let m = DEC_GFX[(c - 0x5f) as usize];
            if m != 0 {
                c = m;
            }
        }
        if self.cx >= self.cols {
            self.cx = 0;
            self.linefeed();
        }
        let cell = ((self.attr as u16) << 8) | c as u16;
        self.put_cell(self.cx, self.cy, cell);
        self.draw_cell(self.cx, self.cy);
        self.cx += 1;
        self.last_glyph = c;
    }

    fn sgr(&mut self) {
        let n = self.nparams.max(1);
        let mut i = 0;
        while i < n {
            let p = self.params.get(i).copied().unwrap_or(0);
            match p {
                0 => {
                    self.attr = 0x07;
                    self.bold = false;
                }
                1 => {
                    // Bold is a persistent intensity flag: it must
                    // survive a later 30-37 (ncurses emits 0;1;30 for
                    // bright black). Brighten the current fg now too,
                    // for the color-then-bold order.
                    self.bold = true;
                    let f = self.attr & 0x0f;
                    if f < 8 {
                        self.attr = (self.attr & !0x0f) | (f + 8);
                    }
                }
                4 => self.attr |= 0x80,
                7 => {
                    let fg = self.attr & 0x0f;
                    let bg = (self.attr >> 4) & 0x07;
                    self.attr = (self.attr & 0x80) | ((fg & 0x07) << 4) | bg;
                }
                22 => {
                    self.bold = false;
                    let f = self.attr & 0x0f;
                    if f >= 8 {
                        self.attr = (self.attr & !0x0f) | (f - 8);
                    }
                }
                24 => self.attr &= !0x80,
                27 => {
                    // Reset inverse: swap back if visually swapped is
                    // ambiguous — treat as plain reset of the swap by
                    // restoring default-ish colors only when clearly
                    // inverted is impossible to detect; xterm apps send
                    // 0m before 27m anyway.
                }
                39 => {
                    self.attr = (self.attr & 0xf0)
                        | if self.bold { 15 } else { 7 };
                }
                49 => self.attr &= 0x8f,
                30..=37 => {
                    let c = (p - 30) as u8 + if self.bold { 8 } else { 0 };
                    self.attr = (self.attr & !0x0f) | c;
                }
                90..=97 => self.attr = (self.attr & !0x0f) | ((p - 90 + 8) as u8),
                40..=47 => {
                    self.attr = (self.attr & !0x70) | (((p - 40) as u8) << 4)
                }
                100..=107 => {
                    self.attr = (self.attr & !0x70) | (((p - 100) as u8) << 4)
                }
                38 | 48 => {
                    // Extended color: skip ;5;n or ;2;r;g;b args.
                    if i + 1 < n && self.params[i + 1] == 5 {
                        let c = self.params.get(i + 2).copied().unwrap_or(0);
                        let (q, base) = if p == 38 { (c % 16, 0x0f) } else { (c % 8, 0x70) };
                        let v = if p == 38 { q as u8 } else { (q as u8) << 4 };
                        self.attr = (self.attr & !base) | v;
                        i += 2;
                    } else if i + 1 < n && self.params[i + 1] == 2 {
                        i += 4;
                    }
                }
                _ => {}
            }
            i += 1;
        }
    }

    /// CSI dispatch — `final` is the command byte, params are parsed.
    fn csi(&mut self, final_: u8) {
        let prm = self.params;
        let p = |i: usize| prm.get(i).copied().unwrap_or(0) as usize;
        let p1 = |i: usize, d: usize| {
            let v = p(i);
            if v == 0 { d } else { v }
        };
        match final_ {
            b'A' => self.cy = self.cy.saturating_sub(p1(0, 1)).max(self.scr_top),
            b'B' => self.cy = (self.cy + p1(0, 1)).min(self.scr_bot),
            b'C' => self.cx = (self.cx + p1(0, 1)).min(self.cols - 1),
            b'D' => self.cx = self.cx.saturating_sub(p1(0, 1)),
            b'E' => {
                self.cy = (self.cy + p1(0, 1)).min(self.scr_bot);
                self.cx = 0;
            }
            b'F' => {
                self.cy = self.cy.saturating_sub(p1(0, 1)).max(self.scr_top);
                self.cx = 0;
            }
            b'G' | b'`' => self.cx = p1(0, 1).saturating_sub(1).min(self.cols - 1),
            b'd' => self.cy = p1(0, 1).saturating_sub(1).min(self.rows - 1),
            b'H' | b'f' => {
                self.cy = p1(0, 1).saturating_sub(1).min(self.rows - 1);
                self.cx = p1(1, 1).saturating_sub(1).min(self.cols - 1);
            }
            b'J' => match p(0) {
                0 => {
                    self.erase_in_line(self.cx, self.cols);
                    self.erase_lines(self.cy + 1, self.rows);
                }
                1 => {
                    self.erase_in_line(0, self.cx + 1);
                    self.erase_lines(0, self.cy);
                }
                _ => self.erase_lines(0, self.rows),
            },
            b'K' => match p(0) {
                0 => self.erase_in_line(self.cx, self.cols),
                1 => self.erase_in_line(0, self.cx + 1),
                _ => self.erase_in_line(0, self.cols),
            },
            b'X' => self.erase_in_line(self.cx, (self.cx + p1(0, 1)).min(self.cols)),
            b'L' => self.scroll_rows(self.cy, self.scr_bot + 1, p1(0, 1), false),
            b'M' => self.scroll_rows(self.cy, self.scr_bot + 1, p1(0, 1), true),
            b'S' => self.scroll_rows(self.scr_top, self.scr_bot + 1, p1(0, 1), true),
            b'T' => self.scroll_rows(self.scr_top, self.scr_bot + 1, p1(0, 1), false),
            b'P' => {
                // DCH: shift the line left, blank the tail.
                let n = p1(0, 1).min(self.cols - self.cx);
                unsafe {
                    let g = &mut *core::ptr::addr_of_mut!(GRID);
                    let row = &mut g[self.cy * MAX_COLS..self.cy * MAX_COLS + self.cols];
                    row.copy_within(self.cx + n.., self.cx);
                    for c in &mut row[self.cols - n..] {
                        *c = BLANK;
                    }
                }
                self.mark_dirty(self.cy, self.cy);
            }
            b'@' => {
                // ICH: shift right, blank the gap.
                let n = p1(0, 1).min(self.cols - self.cx);
                unsafe {
                    let g = &mut *core::ptr::addr_of_mut!(GRID);
                    let row = &mut g[self.cy * MAX_COLS..self.cy * MAX_COLS + self.cols];
                    row.copy_within(self.cx..self.cols - n, self.cx + n);
                    for c in &mut row[self.cx..self.cx + n] {
                        *c = BLANK;
                    }
                }
                self.mark_dirty(self.cy, self.cy);
            }
            b'r' => {
                // DECSTBM (1-based inclusive; defaults = whole screen).
                let t = p1(0, 1).saturating_sub(1).min(self.rows - 1);
                let b = p1(1, self.rows).saturating_sub(1).min(self.rows - 1);
                // Clamp into the usable region before validating so a
                // clamped top can never produce an inverted region.
                let t = t.max(self.top);
                if t < b {
                    self.scr_top = t;
                    self.scr_bot = b;
                }
                self.cx = 0;
                self.cy = self.scr_top;
            }
            b's' => self.saved = (self.cx, self.cy, self.attr),
            b'u' => {
                let (x, y, a) = self.saved;
                (self.cx, self.cy, self.attr) = (x.min(self.cols - 1), y.min(self.rows - 1), a);
            }
            b'b' => {
                // REP: repeat the preceding graphic char Ps times.
                let c = self.last_glyph;
                for _ in 0..p1(0, 1).min(self.cols * self.rows) {
                    self.put_glyph(c);
                }
            }
            b'm' => self.sgr(),
            b'h' | b'l' => {
                let set = final_ == b'h';
                if self.csi_private {
                    for i in 0..self.nparams.max(1) {
                        match p(i) {
                            1 => unsafe {
                                *core::ptr::addr_of_mut!(APP_CURSOR) = set
                            },
                            25 => self.cur_vis = set,
                            1049 => self.alt_screen(set),
                            _ => {}
                        }
                    }
                }
            }
            b'c' => crate::user::stdin_inject(b"\x1b[?1;2c"),
            b'n' => {
                if p(0) == 6 {
                    let mut buf = [0u8; 16];
                    let mut s = klib::seqbuf::SeqBuf::new(&mut buf);
                    s.printf(
                        b"\x1b[%d;%dR",
                        &[
                            klib::fmt::Arg::I(self.cy as i64 + 1),
                            klib::fmt::Arg::I(self.cx as i64 + 1),
                        ],
                    );
                    let used = s.used();
                    crate::user::stdin_inject(&buf[..used]);
                } else if p(0) == 5 {
                    crate::user::stdin_inject(b"\x1b[0n");
                }
            }
            _ => {}
        }
    }

    fn erase_in_line(&mut self, a: usize, b: usize) {
        for x in a..b {
            self.put_cell(x, self.cy, BLANK);
        }
        self.mark_dirty(self.cy, self.cy);
    }

    fn erase_lines(&mut self, a: usize, b: usize) {
        for y in a..b {
            for x in 0..self.cols {
                self.put_cell(x, y, BLANK);
            }
        }
        self.mark_dirty(a, b.saturating_sub(1));
    }

    /// DECSET ?1049: save the main grid+cursor, swap to a cleared alt
    /// screen; on leave, restore. (Full-screen apps land here.)
    fn alt_screen(&mut self, on: bool) {
        if on == self.alt {
            return;
        }
        unsafe {
            let g = &mut *core::ptr::addr_of_mut!(GRID);
            let a = &mut *core::ptr::addr_of_mut!(GRID_ALT);
            core::mem::swap(g, a);
        }
        self.alt = on;
        if on {
            self.saved_alt = (self.cx, self.cy, self.attr);
            for i in 0..self.rows * self.cols {
                unsafe {
                    (*core::ptr::addr_of_mut!(GRID))[i] = BLANK;
                }
            }
            self.cx = 0;
            self.cy = 0;
        } else {
            // Restore the position saved at ?1049h entry, like xterm.
            let (x, y, a) = self.saved_alt;
            self.cx = x.min(self.cols - 1);
            self.cy = y.min(self.rows - 1);
            self.attr = a;
        }
        self.mark_dirty(0, self.rows - 1);
    }

    /// Byte machine: VT100/xterm-subset parser over the console stream.
    fn feed(&mut self, b: u8) {
        // UTF-8 continuation (only reachable in Norm).
        if self.utf8_need > 0 && self.esc == EscState::Norm {
            if b & 0xc0 == 0x80 {
                self.utf8_cp = (self.utf8_cp << 6) | (b & 0x3f) as u32;
                self.utf8_need -= 1;
                if self.utf8_need == 0 {
                    let cp = self.utf8_cp;
                    self.utf8_cp = 0;
                    self.put_glyph(utf8_to_cp437(cp));
                }
                return;
            }
            // Malformed sequence — resync and fall through so the
            // offending byte (e.g. ESC) is reprocessed normally.
            self.utf8_need = 0;
        }
        match self.esc {
            EscState::Norm => match b {
                0x1b => self.esc = EscState::Got,
                0xc0..=0xdf => {
                    self.utf8_cp = (b & 0x1f) as u32;
                    self.utf8_need = 1;
                }
                0xe0..=0xef => {
                    self.utf8_cp = (b & 0x0f) as u32;
                    self.utf8_need = 2;
                }
                0xf0..=0xf7 => {
                    self.utf8_cp = (b & 0x07) as u32;
                    self.utf8_need = 3;
                }
                b'\n' | 0x0b | 0x0c => self.linefeed(),
                b'\r' => self.cx = 0,
                0x08 => self.cx = self.cx.saturating_sub(1),
                0x09 => self.cx = ((self.cx + 8) & !7).min(self.cols - 1),
                0x20..=0xff => self.put_glyph(b),
                _ => {} // BEL/SI/SO/other controls: drop
            },
            EscState::Got => {
                self.esc = EscState::Norm;
                match b {
                    b'[' => {
                        self.esc = EscState::Csi;
                        self.params = [0; 16];
                        self.nparams = 0;
                        self.csi_private = false;
                    }
                    b']' => self.esc = EscState::Osc,
                    b'(' | b')' | b'*' | b'+' => self.esc = EscState::Charset,
                    b'#' => self.esc = EscState::Hash,
                    b'7' => self.saved = (self.cx, self.cy, self.attr),
                    b'8' => {
                        let (x, y, a) = self.saved;
                        (self.cx, self.cy, self.attr) =
                            (x.min(self.cols - 1), y.min(self.rows - 1), a);
                    }
                    b'c' => {
                        // RIS: full reset.
                        self.clear_screen();
                        self.attr = 0x07;
                        self.bold = false;
                        self.scr_top = self.top;
                        self.scr_bot = self.rows - 1;
                        self.g0_gfx = false;
                    }
                    b'M' => {
                        // RI: up, or scroll region down at its top.
                        self.erase_cursor();
                        if self.cy == self.scr_top {
                            self.scroll_rows(self.scr_top, self.scr_bot + 1, 1, false);
                        } else {
                            self.cy = self.cy.saturating_sub(1);
                        }
                    }
                    b'D' => self.linefeed(),
                    b'E' => {
                        self.cx = 0;
                        self.linefeed();
                    }
                    _ => {}
                }
            }
            EscState::Csi => match b {
                b'0'..=b'9' => {
                    // Digits accumulate into the CURRENT param; the
                    // count only grows at the first digit and at ';'.
                    if self.nparams == 0 {
                        self.nparams = 1;
                    }
                    let i = (self.nparams - 1).min(15);
                    let v = &mut self.params[i];
                    *v = (*v).saturating_mul(10).saturating_add((b - b'0') as u16);
                }
                b';' => {
                    // An empty leading param counts too: "\e[;5" is
                    // two params [0,5], not one.
                    if self.nparams == 0 {
                        self.nparams = 1;
                    }
                    if self.nparams < 16 {
                        self.nparams += 1;
                    }
                }
                b'?' => self.csi_private = true,
                0x20..=0x2f => {} // intermediates (" q" etc.) — remember nothing
                _ => {
                    self.csi(b);
                    self.esc = EscState::Norm;
                }
            },
            EscState::Osc => {
                // Swallow until BEL or ST (ESC \).
                if b == 0x07 {
                    self.esc = EscState::Norm;
                } else if b == 0x1b {
                    self.esc = EscState::Got;
                }
            }
            EscState::Charset => {
                self.esc = EscState::Norm;
                if b == b'0' {
                    self.g0_gfx = true;
                } else if b == b'B' {
                    self.g0_gfx = false;
                }
            }
            EscState::Hash => {
                self.esc = EscState::Norm;
                if b == b'8' {
                    // DECALN: fill the screen with 'E' (alignment test).
                    for y in 0..self.rows {
                        for x in 0..self.cols {
                            self.put_cell(x, y, (0x07 << 8) | b'E' as u16);
                        }
                    }
                    self.mark_dirty(0, self.rows - 1);
                }
            }
        }
    }

    /// Boot splash: draw the generated logo image centered at the top of the
    /// screen, then place the text cursor on the first row below it.
    pub fn splash(&mut self) {
        let lw = LOGO_W.min(self.width);
        let lh = LOGO_H.min(self.height);
        let x0 = (self.width - lw) / 2;
        for y in 0..lh {
            for x in 0..lw {
                let i = (y * LOGO_W + x) * 3;
                let rgb = (u32::from(LOGO_RGB[i]) << 16)
                    | (u32::from(LOGO_RGB[i + 1]) << 8)
                    | u32::from(LOGO_RGB[i + 2]);
                self.px(x0 + x, y, rgb);
            }
        }
        self.cx = 0;
        self.top = lh.div_ceil(FONT_8X16_H).min(self.rows - 1);
        self.scr_top = self.top;
        self.cy = self.top;
    }

    /// Accent-colored banner line (proof the console is alive before any
    /// serial-fanned text arrives).
    pub fn banner(&mut self) {
        for (i, &b) in b"rustux: framebuffer console (GOP, font_8x16)".iter().enumerate() {
            if i >= self.cols {
                break;
            }
            let gi = b as usize * FONT_8X16_H;
            let x0 = i * FONT_8X16_W;
            for row in 0..FONT_8X16_H {
                let bits = FONT_8X16[gi + row];
                for col in 0..FONT_8X16_W {
                    let v = if bits & (0x80 >> col) != 0 { FG_BOOT } else { BG };
                    self.px(x0 + col, self.cy * FONT_8X16_H + row, v);
                }
            }
        }
        self.cx = 0;
        self.cy += 1;
    }
}

/// Minimal UTF-8 → CP437 map for the glyphs full-screen apps emit
/// (box drawing, blocks, bullets, arrows). Anything else becomes '?'.
fn utf8_to_cp437(cp: u32) -> u8 {
    match cp {
        0x2500 | 0x2501 | 0x2504..=0x250b => 0xC4, // horizontals
        0x2502 | 0x2503 => 0xB3,                   // │
        0x250c => 0xDA, // ┌
        0x2510 => 0xBF, // ┐
        0x2514 => 0xC0, // └
        0x2518 => 0xD9, // ┘
        0x251c => 0xC3, // ├
        0x2524 => 0xB4, // ┤
        0x252c => 0xC2, // ┬
        0x2534 => 0xC1, // ┴
        0x253c => 0xC5, // ┼
        0x250d..=0x257f => 0xC5, // heavy/mixed: nearest cross
        0x2580 => 0xDF, // ▀
        0x2584 => 0xDC, // ▄
        0x2588 => 0xDB, // █
        0x258c => 0xDD, // ▌
        0x2590 => 0xDE, // ▐
        0x2591 => 0xB0, // ░
        0x2592 => 0xB1, // ▒
        0x2593 => 0xB2, // ▓
        0x25cf | 0x2022 => 0xFE, // ●/•
        0x00b7 | 0x2219 => 0xFA, // ·
        0x2190 => 0x1B, // ←
        0x2192 => 0x1A, // →
        0x2191 => 0x18, // ↑
        0x2193 => 0x19, // ↓
        0x2194 => 0x1D, // ↔
        0x2713 | 0x2714 => 0xFB, // ✓ -> √
        0x00a0..=0x00ff => cp as u8, // Latin-1 == CP437 mostly
        _ => b'?',
    }
}

impl Write for FbConsole {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for &b in s.as_bytes() {
            self.feed(b);
        }
        self.paint_dirty();
        Ok(())
    }
}
