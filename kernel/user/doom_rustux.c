// doomgeneric platform layer for Rustux.
// Video: /dev/fb0 via FBIOGET_VSCREENINFO/FSCREENINFO + positional
// write() of a composed full-screen frame (integer-scaled, centered).
// Input: stdin in raw noncanonical mode, optional — the attract demo
// needs no keys. Timing: gettimeofday/usleep.

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

int DG_GetKey(int* pressed, unsigned char* doomKey)
{
	(void)pressed; (void)doomKey;
	return 0;	// attract mode needs no input
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
