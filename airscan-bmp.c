/* sane - Scanner Access Now Easy.

   Copyright (C) 2020 Thierry HUCHARD <thierry@ordissimo.com>

   This file is part of the SANE package.

   SANE is free software; you can redistribute it and/or modify it under
   the terms of the GNU General Public License as published by the Free
   Software Foundation; either version 3 of the License, or (at your
   option) any later version.

   SANE is distributed in the hope that it will be useful, but WITHOUT
   ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
   FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
   for more details.

   You should have received a copy of the GNU General Public License
   along with sane; see the file COPYING.  If not, write to the Free
   Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

   This file implements a SANE backend for airscan scanners. */

#include "airscan.h"

// gcc -o airscan-bmp airscan-bmp.c $(pkg-config --libs --cflags gtk+-3.0) -lm

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <string.h>


/* BMP image decoder
 */
typedef struct {
    image_decoder                 decoder;   /* Base class */
    int32_t                       num_lines; /* Num of lines left to read */
    int32_t                       width; /* Width of the image in pixels. */
    int32_t                       bytes_per_pixel; /* */
    int32_t                       bytes_per_line; /*  */
    int16_t                       bits_per_pixel;
    int32_t                       real_bytes_per_line; /*  */
    int32_t                       compression; /* Compression */
    int32_t                       n_colors; /* Number of colors */
    uint8_t                       *palettes;
    int32_t                       current_line; /* Current of lines */
    unsigned char                 *mem_file; /* Position of the beginning
                                               of the tiff file. */
    int32_t                       offset_data; /* Offset in the file where
                                                  the pixel data is stored */
    int32_t                       offset_file; /* Moving the start position 
                                                  of the bmp data file. */
                                         
    size_t                        size_bmp; /* Size of the bmp file. */
    size_t                        size_file; /* Size of the bmp file. */
} image_decoder_bmp;

/* Free BMP decoder
 */
static void
image_decoder_bmp_free (image_decoder *decoder)
{
    image_decoder_bmp *bmp = (image_decoder_bmp*) decoder;
    g_free(bmp);
}

static int 
read_memory(unsigned char*dest, unsigned char *src, int size_src, int offset, int count)
{
	int i = 0, j;
	
	if (size_src < (offset + count))
	    return 0;
#if __BYTE_ORDER == __LITTLE_ENDIAN
    for (j = 0; j < count; j++) {
#elif __BYTE_ORDER == __BIG_ENDIAN
    for (j = count - 1; j > -1; j--) {
#endif
        dest[i] = src[j + offset];
        i++;
    }
    return 1;
}


static int			pow2(int a)
{
	return (a * a);
}

static int
read_data_memory(unsigned char*dest, unsigned char *src, int size_src, int offset, int count)
{
	int i = 0, j;

	if (size_src < (offset + count))
	    return 0;
    for (j = 0; j < count; j++) {
		dest[i] = src[j + offset];
        i++;
    }
    return 1;
}

/* Begin BMP decoding
 */
static error
image_decoder_bmp_begin (image_decoder *decoder, const void *data,
        size_t size)
{
    int index;
    uint32_t header_size;
    short bits_per_pixel;
    image_decoder_bmp *bmp = (image_decoder_bmp*) decoder;

    bmp->mem_file = (unsigned char*)data;
    bmp->size_file = size;
    if (!bmp->mem_file || size < 30)
        return ERROR("BMP: invalid header");
    /* Bits per pixel 2 bytes 0x1C Number of bits per pixel */
    if (!read_memory((unsigned char*)&bmp->bits_per_pixel,
                bmp->mem_file,
                bmp->size_file,
                28,
                2)) {
        return ERROR("unsupported BMP type");
    }
    bmp->bytes_per_pixel = (int32_t)bmp->bits_per_pixel / 8;
    /* Data offset 4 bytes 0x0A Offset in the file 
       where the pixel data is stored */
    if (!read_memory((unsigned char*)&bmp->offset_data,
                bmp->mem_file,
                bmp->size_file,
                10,
                4))
        return ERROR("BMP: invalid header");

    if (!read_memory((unsigned char*)&header_size,
                bmp->mem_file,
                bmp->size_file,
                14,
                4))
        return ERROR("BMP: invalid header");

    /* Width 4 bytes 0x12 Width of the image in pixels */
    if (!read_memory((unsigned char*)&bmp->width,
                bmp->mem_file,
                bmp->size_file,
                18,
                4))
        return ERROR("BMP: invalid header");
    if (bmp->width < 0)
         bmp->width = abs(bmp->width);

    /* Height 4 bytes 0x16 Height of the image in pixels */
    if (!read_memory((unsigned char*)&bmp->num_lines,
                bmp->mem_file,
                bmp->size_file,
                22,
                4))
        return ERROR("BMP: invalid header");
    if (bmp->num_lines)
         bmp->num_lines = abs(bmp->num_lines);

    /* Height 4 bytes 0x16 Height of the image in pixels */
    if (!read_memory((unsigned char*)&bmp->compression,
                bmp->mem_file,
                bmp->size_file,
                30,
                4))
        return ERROR("BMP: invalid header");

    if(bmp->bits_per_pixel <= 8) {
		if (bmp->bits_per_pixel == 8)
		  bmp->n_colors = 256;
        if(!bmp->n_colors) {
            bmp->n_colors = 1 << bmp->bits_per_pixel;
        }
        bmp->palettes = (uint8_t*)calloc(1, sizeof(uint8_t) * 4 * 256);
        if(!bmp->palettes) {
            return ERROR("out of memory");
        }
        /* read the palette information */
	for(index=0;index<bmp->n_colors;index++) {
	    bmp->palettes[index * 4 + 0] = (uint8_t)bmp->mem_file[(index * 4) + 54];
	    bmp->palettes[index * 4 + 1] = (uint8_t)bmp->mem_file[(index * 4) + 55];
	    bmp->palettes[index * 4 + 2] = (uint8_t)bmp->mem_file[(index * 4) + 56];
	    bmp->palettes[index * 4 + 3] = (uint8_t)bmp->mem_file[(index * 4) + 57];;
	}
    }
    // create_safety_palette();

    bmp->offset_file = 0;
    bmp->bytes_per_line = bmp->width * bmp->bytes_per_pixel;
    bmp->real_bytes_per_line = (int32_t)
                 (4 * ceil((float)bmp->width / 4.0f)) *
                 bmp->bytes_per_pixel;
    return NULL;
}

/* Reset BMP decoder
 */
static void
image_decoder_bmp_reset (image_decoder *decoder)
{
    image_decoder_bmp *bmp = (image_decoder_bmp*) decoder;
    bmp->offset_file = 0;
    bmp->current_line = 0;
}

/* Get bytes count per pixel
 */
static int
image_decoder_bmp_get_bytes_per_pixel (image_decoder *decoder)
{
    image_decoder_bmp *bmp = (image_decoder_bmp*) decoder;
    if (bmp->bits_per_pixel == 1) 
       return 1;
    else
       return 3;
}

/* Get image parameters
 */
static void
image_decoder_bmp_get_params (image_decoder *decoder, SANE_Parameters *params)
{
    image_decoder_bmp *bmp = (image_decoder_bmp*) decoder;

    params->last_frame = SANE_TRUE;
    params->pixels_per_line = bmp->width;
    params->lines = bmp->num_lines;
    params->depth = 8;
    if (bmp->bytes_per_pixel == 1)
       params->format = SANE_FRAME_GRAY;
    else
       params->format = SANE_FRAME_RGB;
    params->bytes_per_line = bmp->bytes_per_line;

}

/* Set clipping window
 */
static error
image_decoder_bmp_set_window (image_decoder *decoder, image_window *win)
{
    image_decoder_bmp *bmp = (image_decoder_bmp*) decoder;
// #if     1
    win->x_off = win->y_off = 0;
    win->wid = bmp->width;
    win->hei = bmp->num_lines;
    return NULL;
/*
#else
    int         x_off = win->x_off;
    int         wid = win->wid;

    if (!setjmp(jpeg->jmpb)) {
        jpeg_crop_scanline(&jpeg->cinfo, &x_off, &wid);
        if (win->y_off > 0) {
            jpeg_skip_scanlines(&jpeg->cinfo, win->y_off);
        }

        tiff->num_lines = win->hei;

        win->x_off = x_off;
        win->wid = wid;

        return NULL;
    }
    return ERROR(jpeg->errbuf);
#endif
*/
}

/* Read next line of image
 */
static error
image_decoder_bmp_read_line (image_decoder *decoder, void *buffer)
{
	unsigned char *current_data = NULL;
	unsigned char *buf = (unsigned char*)buffer;
    image_decoder_bmp *bmp = (image_decoder_bmp*) decoder;
    int bpl = 0, y = 0;
    
    if (bmp->num_lines <= (bmp->current_line + 1)) {
        return ERROR("BMP: end of file");
    }
    current_data = bmp->offset_data + bmp->mem_file;
    int rs = ((bmp->width * (int32_t)bmp->bits_per_pixel / 8) + 3) & ~3;
    switch (bmp->bits_per_pixel) {
		case 8:
		    for(bpl = 0; bpl < bmp->width; bpl++) {
                       int byt = bmp->current_line * rs + bpl;
                       uint8_t p = current_data[byt];
		       buf[(bpl * 3) + 2] = bmp->palettes[p + 0];
		       buf[(bpl * 3) + 1] = bmp->palettes[p + 1];
		       buf[(bpl * 3) + 0] = bmp->palettes[p + 2];
		    }
		    break;
		case 4:
		    for(bpl = 0; bpl < bmp->width; bpl++) {
                      int byt = bmp->current_line *  rs + (bpl >> 1);
                      uint8_t p = ( (bpl & 0x01) ? current_data[byt] : (current_data[byt] >> 4) ) & 0x0F;
                      buf[bpl + 2] = bmp->palettes[p + +0];
		      buf[bpl + 1] = bmp->palettes[p + 1];
		      buf[bpl + 0] = bmp->palettes[p + 2];
                    }
		    break;
		case 1:
                    for(bpl = 0; bpl < bmp->width; bpl++) {
                      int byt = bmp->current_line *  rs + (bpl >> 3);
                      int bit = 7 - (bpl % 8);
                      uint8_t p = (current_data[byt] & (1 << bit)) >> bit;
                      buf[bpl] = bmp->palettes[p];
                    }
		    break;
		default:
		    for(bpl = 0; bpl < bmp->width; bpl++) {
                      int p = (int)(bmp->current_line *  rs + bpl * (bmp->bits_per_pixel / 8));
                      buf[(bpl * 3) + 0] = current_data[p+2];
                      buf[(bpl * 3) + 1] = current_data[p+1];
                      buf[(bpl * 3) + 2] = current_data[p+0];
                    }
		    break;
	}
    bmp->offset_file += rs;
    bmp->current_line ++;
    return NULL;
}

/* Create BMP image decoder
 */
image_decoder*
image_decoder_bmp_new (void)
{
    image_decoder_bmp *bmp = g_new0(image_decoder_bmp, 1);

    bmp->decoder.content_type = "image/bmp";
    bmp->decoder.free = image_decoder_bmp_free;
    bmp->decoder.begin = image_decoder_bmp_begin;
    bmp->decoder.reset = image_decoder_bmp_reset;
    bmp->decoder.get_bytes_per_pixel = image_decoder_bmp_get_bytes_per_pixel;
    bmp->decoder.get_params = image_decoder_bmp_get_params;
    bmp->decoder.set_window = image_decoder_bmp_set_window;
    bmp->decoder.read_line = image_decoder_bmp_read_line;
    bmp->mem_file = NULL;
    bmp->offset_file = 0;
    bmp->size_file = 0;
    bmp->current_line = 0;

    return &bmp->decoder;
}

/* vim:ts=8:sw=4:et
 */
