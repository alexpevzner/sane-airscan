/* AirScan (a.k.a. eSCL) backend for SANE
 *
 * Copyright (C) 2019 and up by Alexander Pevzner (pzz@apevzner.com)
 * See LICENSE for license terms and conditions
 *
 * DIB image decoder stub
 */

#include "airscan.h"

/* dib image decoder
 */
typedef struct {
    image_decoder         decoder;        /* Base class */
} image_decoder_dib;

/* Free dib decoder
 */
static void
image_decoder_dib_free (image_decoder *decoder)
{
    image_decoder_dib *dib = (image_decoder_dib*) decoder;

    image_decoder_reset(decoder);
    g_free(dib);
}

/* Begin DIB decoding
 */
static error
image_decoder_dib_begin (image_decoder *decoder, const void *data,
        size_t size)
{
    image_decoder_dib *dib = (image_decoder_dib*) decoder;

    (void) dib;
    (void) data;
    (void) size;

    return ERROR("DIB decoder not implemented");
}

/* Reset dib decoder
 */
static void
image_decoder_dib_reset (image_decoder *decoder)
{
    image_decoder_dib *dib = (image_decoder_dib*) decoder;

    (void) dib;
}

/* Get bytes count per pixel
 */
static int
image_decoder_dib_get_bytes_per_pixel (image_decoder *decoder)
{
    image_decoder_dib *dib = (image_decoder_dib*) decoder;

    (void) dib;

    return 1;
}

/* Get image parameters
 */
static void
image_decoder_dib_get_params (image_decoder *decoder, SANE_Parameters *params)
{
    (void) decoder;
    (void) params;
}

/* Set clipping window
 */
static error
image_decoder_dib_set_window (image_decoder *decoder, image_window *win)
{
    (void) decoder;
    (void) win;
    return ERROR("DIB decoder not implemented");
}

/* Read next line of image
 */
static error
image_decoder_dib_read_line (image_decoder *decoder, void *buffer)
{
    (void) decoder;
    (void) buffer;
    return ERROR("DIB decoder not implemented");
}

/* Create dib image decoder
 */
image_decoder*
image_decoder_dib_new (void)
{
    image_decoder_dib *dib = g_new0(image_decoder_dib, 1);

    dib->decoder.content_type = "image/dib";
    dib->decoder.free = image_decoder_dib_free;
    dib->decoder.begin = image_decoder_dib_begin;
    dib->decoder.reset = image_decoder_dib_reset;
    dib->decoder.get_bytes_per_pixel = image_decoder_dib_get_bytes_per_pixel;
    dib->decoder.get_params = image_decoder_dib_get_params;
    dib->decoder.set_window = image_decoder_dib_set_window;
    dib->decoder.read_line = image_decoder_dib_read_line;

    return &dib->decoder;
}

/* vim:ts=8:sw=4:et
 */
