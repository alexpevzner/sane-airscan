/* AirScan (a.k.a. eSCL) backend for SANE
 *
 * Copyright (C) 2019 and up by Alexander Pevzner (pzz@apevzner.com)
 * See LICENSE for license terms and conditions
 *
 * JPEG image decoder
 */

#include "airscan.h"

#include <jpeglib.h>
#include <setjmp.h>

/* JPEG image decoder
 */
typedef struct {
    image_decoder                 decoder;   /* Base class */
    struct jpeg_decompress_struct cinfo;     /* libjpeg decoder */
    struct jpeg_error_mgr         jerr;      /* libjpeg error manager */
    jmp_buf                       jmpb;
    JDIMENSION                    num_lines; /* Num of lines left to read */
} image_decoder_jpeg;

/* Free JPEG decoder
 */
static void
image_decoder_jpeg_free (image_decoder *decoder)
{
    image_decoder_jpeg *jpeg = (image_decoder_jpeg*) decoder;

    jpeg_destroy_decompress(&jpeg->cinfo);
    g_free(jpeg);
}

/* Begin JPEG decoding
 */
static bool
image_decoder_jpeg_begin (image_decoder *decoder, const void *data,
        size_t size)
{
    image_decoder_jpeg *jpeg = (image_decoder_jpeg*) decoder;
    int                rc;

    if (!setjmp(jpeg->jmpb)) {
        jpeg_mem_src(&jpeg->cinfo, data, size);

        rc = jpeg_read_header(&jpeg->cinfo, true);
        if (rc != JPEG_HEADER_OK) {
            jpeg_abort((j_common_ptr) &jpeg->cinfo);
            return false;
        }

        if (jpeg->cinfo.num_components != 1) {
            jpeg->cinfo.out_color_space = JCS_RGB;
        }

        jpeg_start_decompress(&jpeg->cinfo);
        jpeg->num_lines = jpeg->cinfo.image_height;

        return true;
    }

    return false;
}

/* Reset JPEG decoder
 */
static void
image_decoder_jpeg_reset (image_decoder *decoder)
{
    image_decoder_jpeg *jpeg = (image_decoder_jpeg*) decoder;

    jpeg_abort((j_common_ptr) &jpeg->cinfo);
}

/* Get image parameters
 */
static void
image_decoder_jpeg_get_params (image_decoder *decoder, SANE_Parameters *params)
{
    image_decoder_jpeg *jpeg = (image_decoder_jpeg*) decoder;

    params->last_frame = SANE_TRUE;
    params->pixels_per_line = jpeg->cinfo.image_width;
    params->lines = jpeg->cinfo.image_height;
    params->depth = 8;

    if (jpeg->cinfo.num_components == 1) {
        params->format = SANE_FRAME_GRAY;
        params->bytes_per_line = params->pixels_per_line;
    } else {
        params->format = SANE_FRAME_RGB;
        params->bytes_per_line = params->pixels_per_line * 3;
    }
}

/* Set clipping window
 */
static bool
image_decoder_jpeg_set_window (image_decoder *decoder, image_window *win)
{
    image_decoder_jpeg *jpeg = (image_decoder_jpeg*) decoder;
    JDIMENSION         x_off = win->x_off;
    JDIMENSION         wid = win->wid;

    if (!setjmp(jpeg->jmpb)) {
        jpeg_crop_scanline(&jpeg->cinfo, &x_off, &wid);
        if (win->y_off > 0) {
            jpeg_skip_scanlines(&jpeg->cinfo, win->y_off);
        }

        jpeg->num_lines = win->hei;

        win->x_off = x_off;
        win->wid = wid;

        return true;
    }

    return false;
}

/* Read next line of image
 */
static bool
image_decoder_jpeg_read_line (image_decoder *decoder, void *buffer)
{
    image_decoder_jpeg *jpeg = (image_decoder_jpeg*) decoder;
    JSAMPROW           lines[1] = {buffer};

    if (!jpeg->num_lines) {
        return false;
    }

    if (!setjmp(jpeg->jmpb)) {
        if (jpeg_read_scanlines(&jpeg->cinfo, lines, 1) == 0) {
            return false;
        }

        jpeg->num_lines --;

        return true;
    }

    return false;
}

/* Dummy "output error message" callback for JPEG decoder
 */
static void
image_decoder_jpeg_output_message (j_common_ptr cinfo)
{
    (void) cinfo;
}

/* error_exit callback for JPEG decoder. The default callback
 * terminates a program, which is not good for us
 */
static void
image_decoder_jpeg_error_exit (j_common_ptr cinfo)
{
    image_decoder_jpeg *jpeg = OUTER_STRUCT(cinfo, image_decoder_jpeg, cinfo);
    jpeg_abort(cinfo);
    longjmp(jpeg->jmpb, 1);
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
    jpeg->decoder.read_line = image_decoder_jpeg_read_line;

    jpeg->cinfo.err = jpeg_std_error(&jpeg->jerr);
    jpeg->jerr.output_message = image_decoder_jpeg_output_message;
    jpeg->jerr.error_exit = image_decoder_jpeg_error_exit;
    jpeg_create_decompress(&jpeg->cinfo);

    return &jpeg->decoder;
}

/* vim:ts=8:sw=4:et
 */
