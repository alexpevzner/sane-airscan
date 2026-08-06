/* AirScan (a.k.a. eSCL) backend for SANE
 *
 * Copyright (C) 2019 and up by Alexander Pevzner (pzz@apevzner.com)
 * See LICENSE for license terms and conditions
 *
 * Raw image decoder (application/octet-stream)
 */

#include "airscan.h"

#include <string.h>

/* Raw image decoder
 *
 * Assume by default RGB24 interleaved row-first format.
 * If some scanners use a different format, we'll need to
 * add configuration options and quirks to handle it.
 */
typedef struct {
    image_decoder decoder;   /* Base class */
    int           width;     /* Image width */
    int           height;    /* Image height */
    int           channels;  /* Number of channels (1 or 3) */
    size_t        row_size;  /* Row size in bytes */
    const uint8_t *data;     /* Data pointer */
    size_t        size;      /* Data size */
    size_t        pos;       /* Current position */
} image_decoder_raw;

/* Free Raw decoder
 */
static void
image_decoder_raw_free (image_decoder *decoder)
{
    image_decoder_raw *raw = (image_decoder_raw*) decoder;
    mem_free(raw);
}

/* Begin Raw decoding
 */
static error
image_decoder_raw_begin (image_decoder *decoder, const void *data,
        size_t size)
{
    image_decoder_raw *raw = (image_decoder_raw*) decoder;

    raw->data = data;
    raw->size = size;
    raw->pos = 0;

    return NULL;
}

/* Reset Raw decoder
 */
static void
image_decoder_raw_reset (image_decoder *decoder)
{
    image_decoder_raw *raw = (image_decoder_raw*) decoder;
    raw->data = NULL;
    raw->size = 0;
    raw->pos = 0;
}

/* Get bytes count per pixel
 */
static int
image_decoder_raw_get_bytes_per_pixel (image_decoder *decoder)
{
    image_decoder_raw *raw = (image_decoder_raw*) decoder;
    return raw->channels;
}

/* Get image parameters
 */
static void
image_decoder_raw_get_params (image_decoder *decoder, SANE_Parameters *params)
{
    image_decoder_raw *raw = (image_decoder_raw*) decoder;

    params->last_frame = SANE_TRUE;
    params->pixels_per_line = raw->width;
    params->lines = raw->height;
    params->depth = 8;

    if (raw->channels == 1) {
        params->format = SANE_FRAME_GRAY;
        params->bytes_per_line = params->pixels_per_line;
    } else {
        params->format = SANE_FRAME_RGB;
        params->bytes_per_line = params->pixels_per_line * 3;
    }
}

/* Set clipping window
 */
static error
image_decoder_raw_set_window (image_decoder *decoder, image_window *win)
{
    image_decoder_raw *raw = (image_decoder_raw*) decoder;

    win->x_off = win->y_off = 0;
    win->wid = raw->width;
    win->hei = raw->height;
    return NULL;
}

/* Read next line of image
 */
static error
image_decoder_raw_read_line (image_decoder *decoder, void *buffer)
{
    image_decoder_raw *raw = (image_decoder_raw*) decoder;
    size_t            row_size = raw->width * raw->channels;

    if (raw->pos + row_size > raw->size) {
         if (raw->pos >= raw->size) {
             return ERROR("Raw: end of file");
         }
         /* Partial line? */
         memset(buffer, 0, row_size);
         memcpy(buffer, raw->data + raw->pos, raw->size - raw->pos);
         raw->pos = raw->size;
         return NULL;
    }

    memcpy(buffer, raw->data + raw->pos, row_size);
    raw->pos += row_size;

    return NULL;
}

/* Create Raw image decoder
 */
image_decoder*
image_decoder_raw_new (void)
{
    image_decoder_raw *raw = mem_new(image_decoder_raw, 1);

    raw->decoder.content_type = "application/octet-stream";
    raw->decoder.free = image_decoder_raw_free;
    raw->decoder.begin = image_decoder_raw_begin;
    raw->decoder.reset = image_decoder_raw_reset;
    raw->decoder.get_bytes_per_pixel = image_decoder_raw_get_bytes_per_pixel;
    raw->decoder.get_params = image_decoder_raw_get_params;
    raw->decoder.set_window = image_decoder_raw_set_window;
    raw->decoder.read_line = image_decoder_raw_read_line;

    /* Default configuration */
    raw->width = 0;
    raw->height = 0;
    raw->channels = 0;

    return &raw->decoder;
}

/* Configure Raw image decoder
 */
void
image_decoder_raw_configure (image_decoder *decoder,
        int width, int height, int channels)
{
    image_decoder_raw *raw = (image_decoder_raw*) decoder;

    raw->width = width;
    raw->height = height;
    raw->channels = channels;
}

/* vim:ts=8:sw=4:et
 */
