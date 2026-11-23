// doomgeneric platform layer for Rustux.
// Video: /dev/fb0 via FBIOGET_VSCREENINFO/FSCREENINFO + positional
// write() of a composed full-screen frame (integer-scaled, centered).
// Input: /dev/input/event0 evdev stream — struct input_event
// press/release records translated to doomkeys.h constants.
// Timing: gettimeofday/usleep.

#include "doomkeys.h"
#include "m_argv.h"
#include "doomgeneric.h"

#include <linux/fb.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/ioctl.h>

static int fbfd = -1;
static int evfd = -1;
static struct fb_var_screeninfo vinfo;
static struct fb_fix_screeninfo finfo;
static uint32_t *framebuf;	// full-screen composed frame
static int scale = 1, posx = 0, posy = 0;
static int need_swap = 0;	// RGB-ordered memory: swap R/B lanes

void DG_Init()
{
	fbfd = open("/dev/fb0", O_RDWR);
	if (fbfd < 0 || ioctl(fbfd, FBIOGET_VSCREENINFO, &vinfo) < 0 ||
	    ioctl(fbfd, FBIOGET_FSCREENINFO, &finfo) < 0) {
		printf("doom: /dev/fb0 unavailable\n");
		exit(1);
	}
	if (vinfo.bits_per_pixel != 32 || finfo.line_length < vinfo.xres * 4) {
		printf("doom: fb0 is not 32bpp\n");
		exit(1);
	}
	// doomgeneric emits 0xXXRRGGBB u32 pixels. BGR byte order maps
	// that verbatim; RGB order wants the lanes swapped.
	need_swap = (vinfo.red.offset == 0);

	scale = (int)(vinfo.xres / DOOMGENERIC_RESX);
	if ((int)(vinfo.yres / DOOMGENERIC_RESY) < scale)
		scale = (int)(vinfo.yres / DOOMGENERIC_RESY);
	if (scale < 1)
		scale = 1;
	posx = (vinfo.xres - DOOMGENERIC_RESX * scale) / 2;
	posy = (vinfo.yres - DOOMGENERIC_RESY * scale) / 2;

	framebuf = malloc((size_t)finfo.line_length * vinfo.yres);
	if (!framebuf) {
		printf("doom: frame buffer alloc failed\n");
		exit(1);
	}
	memset(framebuf, 0, (size_t)finfo.line_length * vinfo.yres);
	printf("doom: fb0 %ux%u stride=%u scale=%d swap=%d\n",
	       vinfo.xres, vinfo.yres, finfo.line_length, scale, need_swap);

	evfd = open("/dev/input/event0", O_RDONLY | O_NONBLOCK);
	if (evfd < 0)
		printf("doom: no evdev — keyboard disabled\n");
}

void DG_DrawFrame()
{
	if (!framebuf)
		return;
	uint32_t *fb = framebuf;
	uint32_t llpx = finfo.line_length / 4;
	for (int y = 0; y < DOOMGENERIC_RESY; y++) {
		uint32_t *src = DG_ScreenBuffer + y * DOOMGENERIC_RESX;
		uint32_t *row = fb + (posy + y * scale) * llpx + posx;
		for (int x = 0; x < DOOMGENERIC_RESX; x++) {
			uint32_t p = src[x];
			if (need_swap)
				p = (p & 0xff00ff00) | ((p & 0xff) << 16) | ((p >> 16) & 0xff);
			for (int s = 0; s < scale; s++)
				*row++ = p;
		}
		for (int s = 1; s < scale; s++) {
			memcpy(row, row - DOOMGENERIC_RESX * scale,
			       DOOMGENERIC_RESX * scale * 4);
			row += DOOMGENERIC_RESX * scale;
		}
	}
	lseek(fbfd, 0, SEEK_SET);
	write(fbfd, framebuf, (size_t)finfo.line_length * vinfo.yres);
}

void DG_SleepMs(uint32_t ms)
{
	usleep(ms * 1000);
}

uint32_t DG_GetTicksMs()
{
	struct timeval tp;
	gettimeofday(&tp, NULL);
	return (tp.tv_sec * 1000) + (tp.tv_usec / 1000);
}

// Pending doom keys — (pressed, doomKey) pairs drained from evdev;
// DG_GetKey returns one per call, so a coalesced burst queues here.
static struct { unsigned char pressed, key; } keyq[64];
static int keyq_head, keyq_tail;

// The kernel's evdev record: struct input_event on x86_64 —
// {u64 sec; u64 usec; u16 type; u16 code; i32 value}, 24 bytes.
struct evrec {
	uint64_t sec, usec;
	uint16_t type, code;
	int32_t value;
};
#define EVREC_KEY 1 // EV_KEY

// Linux input-event keycodes (input-event-codes.h) — LKEY_ prefix
// dodges doomkeys.h's same-named constants (its KEY_ENTER is 13,
// Linux's is 28). Set-1 scancode == keycode for unextended keys.
#define LKEY_ESC        1
#define LKEY_1          2
#define LKEY_0          11
#define LKEY_MINUS      12
#define LKEY_EQUAL      13
#define LKEY_BACKSPACE  14
#define LKEY_TAB        15
#define LKEY_Q          16
#define LKEY_P          25
#define LKEY_LEFTBRACE  26
#define LKEY_RIGHTBRACE 27
#define LKEY_ENTER      28
#define LKEY_LEFTCTRL   29
#define LKEY_A          30
#define LKEY_L          38
#define LKEY_SEMICOLON  39
#define LKEY_APOSTROPHE 40
#define LKEY_GRAVE      41
#define LKEY_LEFTSHIFT  42
#define LKEY_BACKSLASH  43
#define LKEY_Z          44
#define LKEY_M          50
#define LKEY_COMMA      51
#define LKEY_DOT        52
#define LKEY_SLASH      53
#define LKEY_RIGHTSHIFT 54
#define LKEY_LEFTALT    56
#define LKEY_SPACE      57
#define LKEY_F1         59
#define LKEY_F10        68
#define LKEY_KPENTER    96
#define LKEY_RIGHTCTRL  97
#define LKEY_RIGHTALT   100
#define LKEY_HOME       102
#define LKEY_UP         103
#define LKEY_PAGEUP     104
#define LKEY_LEFT       105
#define LKEY_RIGHT      106
#define LKEY_END        107
#define LKEY_DOWN       108
#define LKEY_PAGEDOWN   109
#define LKEY_INSERT     110
#define LKEY_DELETE     111

// Linux input-event keycode -> doomkeys.h constant (0 = unmapped).
static unsigned char doom_key(unsigned int code)
{
	switch (code) {
	case LKEY_UP:        return KEY_UPARROW;
	case LKEY_DOWN:      return KEY_DOWNARROW;
	case LKEY_LEFT:      return KEY_LEFTARROW;
	case LKEY_RIGHT:     return KEY_RIGHTARROW;
	case LKEY_ESC:       return KEY_ESCAPE;
	case LKEY_ENTER:
	case LKEY_KPENTER:   return KEY_ENTER;
	case LKEY_TAB:       return KEY_TAB;
	case LKEY_BACKSPACE: return KEY_BACKSPACE;
	// Both ctrls are DOOM's fire key — doomgeneric binds
	// key_fire to the abstract KEY_FIRE, not KEY_RCTRL.
	case LKEY_LEFTCTRL:
	case LKEY_RIGHTCTRL: return KEY_FIRE;
	case LKEY_LEFTALT:
	case LKEY_RIGHTALT:  return KEY_RALT;   // strafe modifier
	case LKEY_LEFTSHIFT:
	case LKEY_RIGHTSHIFT:return KEY_RSHIFT; // run
	case LKEY_SPACE:     return KEY_USE;    // use/open
	case LKEY_HOME:      return KEY_HOME;
	case LKEY_END:       return KEY_END;
	case LKEY_PAGEUP:    return KEY_PGUP;
	case LKEY_PAGEDOWN:  return KEY_PGDN;
	case LKEY_INSERT:    return KEY_INS;
	case LKEY_DELETE:    return KEY_DEL;
	}
	// F1..F10 are sequential in both tables.
	if (code >= LKEY_F1 && code <= LKEY_F10)
		return (unsigned char)(KEY_F1 + (code - LKEY_F1));
	if (code >= LKEY_1 && code <= LKEY_0)
		return (unsigned char)("1234567890"[code - LKEY_1]);
	if (code >= LKEY_Q && code <= LKEY_P)
		return (unsigned char)("qwertyuiop"[code - LKEY_Q]);
	if (code >= LKEY_A && code <= LKEY_L)
		return (unsigned char)("asdfghjkl"[code - LKEY_A]);
	if (code >= LKEY_Z && code <= LKEY_M)
		return (unsigned char)("zxcvbnm"[code - LKEY_Z]);
	switch (code) {
	case LKEY_MINUS:        return KEY_MINUS;
	case LKEY_EQUAL:        return KEY_EQUALS;
	case LKEY_COMMA:        return ',';
	case LKEY_DOT:          return '.';
	case LKEY_SLASH:        return '/';
	case LKEY_SEMICOLON:    return ';';
	case LKEY_APOSTROPHE:   return '\'';
	case LKEY_GRAVE:        return '`';
	case LKEY_BACKSLASH:    return '\\';
	case LKEY_LEFTBRACE:    return '[';
	case LKEY_RIGHTBRACE:   return ']';
	}
	return 0;
}

int DG_GetKey(int* pressed, unsigned char* doomKey)
{
	// Drain the evdev stream — O_NONBLOCK, so this empties the
	// kernel queue each tick; presses (1) and releases (0) both
	// enqueue, key-repeat (2) is dropped.
	if (evfd >= 0) {
		struct evrec ev[16];
		for (;;) {
			ssize_t n = read(evfd, ev, sizeof(ev));
			if (n <= 0)
				break;
			for (int i = 0; i + sizeof(ev[0]) <= (size_t)n;
			     i++) {
				if (ev[i].type != EVREC_KEY ||
				    ev[i].value > 1)
					continue;
				unsigned char k = doom_key(ev[i].code);
				if (!k)
					continue;
				int next = (keyq_tail + 1) %
					   (int)(sizeof(keyq) / sizeof(keyq[0]));
				if (next == keyq_head)
					break; // full — drop like the tty
				keyq[keyq_tail].pressed =
					(unsigned char)ev[i].value;
				keyq[keyq_tail].key = k;
				keyq_tail = next;
			}
			if ((size_t)n < sizeof(ev))
				break;
		}
	}
	if (keyq_head == keyq_tail)
		return 0;
	*pressed = keyq[keyq_head].pressed;
	*doomKey = keyq[keyq_head].key;
	keyq_head = (keyq_head + 1) %
		    (int)(sizeof(keyq) / sizeof(keyq[0]));
	return 1;
}

void DG_SetWindowTitle(const char * title)
{
	(void)title;
}

int main(int argc, char **argv)
{
	(void)argc; (void)argv;
	char *dargv[] = { "doom", "-iwad", "/doom.wad" };
	doomgeneric_Create(3, dargv);
	while (1)
		doomgeneric_Tick();
	return 0;
}
