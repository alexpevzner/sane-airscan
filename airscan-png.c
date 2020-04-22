/* AirScan (a.k.a. eSCL) backend for SANE
 *
 * Copyright (C) 2019 and up by Alexander Pevzner (pzz@apevzner.com)
 * See LICENSE for license terms and conditions
 *
 * PNG image decoder
 */

#include "airscan.h"

#include <png.h>
#include <setjmp.h>
#include <string.h>

/* PNG image decoder
 */
typedef struct {
    image_decoder         decoder;        /* Base class */
    png_struct            *png_ptr;       /* Underlying libpng decoder */
    png_info              *info_ptr;      /* libpng info struct */
    const uint8_t         *image_data;    /* Remaining image data */
    size_t                image_size;     /* Remaining image data */
    char                  error[1024];    /* Error message buffer */
    uint32_t              width, height;  /* Image size in pixels */
    int                   bit_depth;      /* 1/2/4/8/16 */
    int                   color_type;     /* PNG_COLOR_TYPE_XXX */
    int                   interlace_type; /* PNG_INTERLACE_XXX */
    unsigned int          num_lines;      /* Num of lines left to read */
} image_decoder_png;

/* Free PNG decoder
 */
static void
image_decoder_png_free (image_decoder *decoder)
{
    image_decoder_png *png = (image_decoder_png*) decoder;

    image_decoder_reset(decoder);
    g_free(png);
}

/* libpng error callback
 */
static void
image_decoder_png_error_fn (png_struct *png_ptr, const char *message)
{
    image_decoder_png *png = png_get_error_ptr(png_ptr);

    snprintf(png->error, sizeof(png->error), "PNG: %s", message);
}

/* libpng warning callback
 */
static void
image_decoder_png_warning_fn (png_struct *png_ptr, const char *message)
{
    (void) png_ptr;
    (void) message;
}

/* libpng malloc callback
 */
static void*
image_decoder_png_malloc_fn (png_struct *png_ptr, size_t size)
{
    (void) png_ptr;
    return g_malloc(size);
}

/* libpng free callback
 */
static void
image_decoder_png_free_fn (png_struct *png_ptr, void *p)
{
    (void) png_ptr;
    g_free(p);
}

/* libpng read callback
 */
static void
image_decoder_png_read_fn (png_struct *png_ptr, png_bytep data, size_t size)
{
    image_decoder_png *png = png_get_io_ptr(png_ptr);

    if (size > png->image_size) {
        png_error(png_ptr, "unexpected EOF");
    }

    memcpy(data, png->image_data, size);
    png->image_data += size;
    png->image_size -= size;
}

/* Begin PNG decoding
 */
static error
image_decoder_png_begin (image_decoder *decoder, const void *data,
        size_t size)
{
    image_decoder_png *png = (image_decoder_png*) decoder;

    /* Create libpng structures */
    png->png_ptr = png_create_read_struct_2(PNG_LIBPNG_VER_STRING,
        png, image_decoder_png_error_fn, image_decoder_png_warning_fn,
        png, image_decoder_png_malloc_fn, image_decoder_png_free_fn);

    if (png->png_ptr == NULL) {
        return ERROR("PNG: png_create_read_struct_2() failed");
    }

    png->info_ptr = png_create_info_struct(png->png_ptr);
    if (png->info_ptr == NULL) {
        image_decoder_reset(decoder);
        return ERROR("PNG: png_create_info_struct() failed");
    }

    /* Setup read function */
    png_set_read_fn(png->png_ptr, png, image_decoder_png_read_fn);

    png->image_data = data;
    png->image_size = size;

    /* Read image info */
    if (setjmp(png_jmpbuf(png->png_ptr))) {
        image_decoder_reset(decoder);
        return ERROR(png->error);
    }

    png_read_info(png->png_ptr, png->info_ptr);
    png_get_IHDR(png->png_ptr, png->info_ptr, &png->width, &png->height,
        &png->bit_depth, &png->color_type, &png->interlace_type, NULL, NULL);

    png->num_lines = png->height;

    /* Reject interlaced images */
    if (png->interlace_type != PNG_INTERLACE_NONE) {
        image_decoder_reset(decoder);
        return ERROR("PNG: interlaced images not supported");
    }

    /* Setup input transformations */
    if (png->color_type == PNG_COLOR_TYPE_PALETTE) {
        png_set_palette_to_rgb(png->png_ptr);
    }

    if (png->color_type == PNG_COLOR_TYPE_GRAY && png->bit_depth < 8) {
        png_set_expand_gray_1_2_4_to_8(png->png_ptr);
        png->bit_depth = 8;
    }

    if ((png->color_type & PNG_COLOR_MASK_ALPHA) != 0) {
        png_set_strip_alpha(png->png_ptr);
    }

    return NULL;
}

/* Reset PNG decoder
 */
static void
image_decoder_png_reset (image_decoder *decoder)
{
    image_decoder_png *png = (image_decoder_png*) decoder;

    if (png->png_ptr != NULL) {
        png_destroy_read_struct(&png->png_ptr, &png->info_ptr, NULL);
        png->png_ptr = NULL;
        png->info_ptr = NULL;
    }
}

/* Get bytes count per pixel
 */
static int
image_decoder_png_get_bytes_per_pixel (image_decoder *decoder)
{
    image_decoder_png *png = (image_decoder_png*) decoder;
    int               bit_depth = png->bit_depth;

    if ((png->color_type & PNG_COLOR_MASK_COLOR) != 0) {
        bit_depth *= 3;
    }

    return bit_depth / 3;
}

/* Get image parameters
 */
static void
image_decoder_png_get_params (image_decoder *decoder, SANE_Parameters *params)
{
    image_decoder_png *png = (image_decoder_png*) decoder;

    params->last_frame = SANE_TRUE;
    params->pixels_per_line = png->width;
    params->lines = png->height;
    params->depth = png->bit_depth;

    if ((png->color_type & PNG_COLOR_MASK_COLOR) != 0) {
        params->format = SANE_FRAME_RGB;
        params->bytes_per_line = params->pixels_per_line * 3;
    } else {
        params->format = SANE_FRAME_GRAY;
        params->bytes_per_line = params->pixels_per_line;
    }
}

/* Set clipping window
 */
static error
image_decoder_png_set_window (image_decoder *decoder, image_window *win)
{
    image_decoder_png *png = (image_decoder_png*) decoder;

    win->x_off = win->y_off = 0;
    win->wid = png->width;
    win->hei = png->height;
    return NULL;
}

/* Read next line of image
 */
static error
image_decoder_png_read_line (image_decoder *decoder, void *buffer)
{
    image_decoder_png *png = (image_decoder_png*) decoder;

    if (!png->num_lines) {
        return ERROR("PNG: end of file");
    }

    if (setjmp(png_jmpbuf(png->png_ptr))) {
        image_decoder_reset(decoder);
        return ERROR(png->error);
    }

    png_read_row(png->png_ptr, buffer, NULL);
    png->num_lines --;

    return NULL;
}

/* Create PNG image decoder
 */
image_decoder*
image_decoder_png_new (void)
{
    image_decoder_png *png = g_new0(image_decoder_png, 1);

    png->decoder.content_type = "image/png";
    png->decoder.free = image_decoder_png_free;
    png->decoder.begin = image_decoder_png_begin;
    png->decoder.reset = image_decoder_png_reset;
    png->decoder.get_bytes_per_pixel = image_decoder_png_get_bytes_per_pixel;
    png->decoder.get_params = image_decoder_png_get_params;
    png->decoder.set_window = image_decoder_png_set_window;
    png->decoder.read_line = image_decoder_png_read_line;

    return &png->decoder;
}

/* vim:ts=8:sw=4:et
 */
