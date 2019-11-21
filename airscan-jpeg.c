/* AirScan (a.k.a. eSCL) backend for SANE
 *
 * Copyright (C) 2019 and up by Alexander Pevzner (pzz@apevzner.com)
 * See LICENSE for license terms and conditions
 *
 * JPEG image decoder
 */

#include "airscan.h"

/* JPEG image decoder
 */
typedef struct {
    image_decoder decoder; /* Base class */
} image_decoder_jpeg;

/* Free JPEG decoder
 */
static void
image_decoder_jpeg_free (image_decoder *decoder)
{
    image_decoder_jpeg *jpeg = (image_decoder_jpeg*) decoder;

    g_free(jpeg);
}

/* Begin JPEG decoding
 */
static bool
image_decoder_jpeg_begin (image_decoder *decoder, const void *data,
        size_t size)
{
    (void) decoder;
    (void) data;
    (void) size;

    return false;
}

/* Reset JPEG decoder
 */
static void
image_decoder_jpeg_reset (image_decoder *decoder)
{
    (void) decoder;
}

/* Get image parameters
 */
static void
image_decoder_jpeg_get_params (image_decoder *decoder, SANE_Parameters *params)
{
    (void) decoder;
    (void) params;
}

/* Set clipping window
 */
static void
image_decoder_jpeg_set_window (image_decoder *decoder, image_window *win)
{
    (void) decoder;
    (void) win;
}

/* Read next row of image
 */
static bool
image_decoder_jpeg_read_row (image_decoder *decoder, void *buffer)
{
    (void) decoder;
    (void) buffer;
    return false;
}

/* Create JPEG image decoder
 */
image_decoder*
image_decoder_jpeg_new (void)
{
    image_decoder_jpeg *jpeg = g_new0(image_decoder_jpeg, 1);

    jpeg->decoder.free = image_decoder_jpeg_free;
    jpeg->decoder.begin = image_decoder_jpeg_begin;
    jpeg->decoder.reset = image_decoder_jpeg_reset;
    jpeg->decoder.get_params = image_decoder_jpeg_get_params;
    jpeg->decoder.set_window = image_decoder_jpeg_set_window;
    jpeg->decoder.read_row = image_decoder_jpeg_read_row;

    return &jpeg->decoder;
}

/* vim:ts=8:sw=4:et
 */
