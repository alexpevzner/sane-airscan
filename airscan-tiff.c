/* sane - Scanner Access Now Easy.
 *
 * Copyright (C) 2020 Thierry HUCHARD <thierry@ordissimo.com>
 * Copyright (C) 2020 and up by Alexander Pevzner (pzz@apevzner.com)
 *
 * See LICENSE for license terms and conditions
 */

#include "airscan.h"

#include <tiffio.h>

#include <stdint.h>
#include <string.h>

/* TIFF image decoder
 */
typedef struct {
    image_decoder          decoder;         /* Base class */
    TIFF*                  tif;             /* libtiff decoder */
    uint32_t               current_line;    /* Current line */
    unsigned char         *mem_file;        /* Position of the beginning
                                               of the tiff file. */
    toff_t                 offset_file;     /* Moving the start position
                                               of the tiff file. */
    tsize_t                size_file;       /* Size of the tiff file. */
    uint16_t               bytes_per_pixel; /* Bytes per pixel */
    uint32_t               image_width;     /* Image width */
    uint32_t               image_height;    /* Image height */
} image_decoder_tiff;

/***** Forward declarations *****/
static void
image_decoder_tiff_reset (image_decoder *decoder);

/****** I/O callbacks for TIFFClientOpen() *****/

/* readproc callback for TIFFClientOpen()
 *
 * Works like read(2)
 */
static tsize_t
image_decoder_tiff_readproc (thandle_t handle, tdata_t data, tsize_t n)
{
    image_decoder_tiff *tiff = (image_decoder_tiff*) handle;
    tsize_t            n_remaining, n_copy;
    void               *src_addr;

    /* find the actual number of bytes to read (copy) */
    n_copy = n;
    if( (tsize_t) tiff->offset_file >= tiff->size_file) {
        n_remaining = 0;
    } else {
        n_remaining = tiff->size_file - tiff->offset_file;
    }

    if (n_copy > n_remaining) {
        n_copy = n_remaining;
    }

    /* EOF, return immediately */
    if (n_copy <= 0) {
        return 0;
    }

    src_addr = (void*)(&(tiff->mem_file[tiff->offset_file]));
    memcpy((void*)data, src_addr, n_copy);
    tiff->offset_file += n_copy;     /* Actualisation de l'offset */

    return n_copy;
}

/* writeproc callback for TIFFClientOpen()
 *
 * Works like write(2). Not needed for decoder
 */
static tsize_t
image_decoder_tiff_writeproc (thandle_t handle, tdata_t data, tsize_t n)
{
    (void) handle;
    (void) data;
    (void) n;

    return -1;
}

/* seekproc callback for TIFFClientOpen()
 *
 * Works like lseek(2)
 */
static toff_t
image_decoder_tiff_seekproc (thandle_t handle, toff_t ofs, int whence)
{
    image_decoder_tiff *tiff = (image_decoder_tiff*) handle;
    toff_t              new_offset;

    /* find the location we plan to seek to */
    switch (whence) {
    case SEEK_SET:
        new_offset = ofs;
        break;

    case SEEK_CUR:
        new_offset = tiff->offset_file + ofs;
        break;

    default:
        /* Not supported */
        log_internal_error(NULL);
        return -1;
    }

    /* Updating the offset */
    tiff->offset_file = new_offset;
    return tiff->offset_file;
}

/* closeproc callback for TIFFClientOpen()
 *
 * Works like close(2)
 */
static int
image_decoder_tiff_closeproc (thandle_t handle)
{
    (void) handle;
    return 0;
}

/* sizeproc callback for TIFFClientOpen()
 *
 * Returns file size, in bytes
 */
static toff_t
image_decoder_tiff_sizeproc (thandle_t handle)
{
    image_decoder_tiff *tiff = (image_decoder_tiff*) handle;

    return (toff_t) (tiff->size_file);
}

/* mapproc callback for TIFFClientOpen()
 *
 * Works like mmap(2). Not required and not implemented
 */
static int
image_decoder_tiff_mapproc (thandle_t fd, tdata_t *pbase, toff_t *psize)
{
    (void) fd;
    (void) pbase;
    (void) psize;

    return (0);
}

/* upmapproc callback for TIFFClientOpen()
 *
 * Works like munmap(2). Not required and not implemented
 */
static void
image_decoder_tiff_unmapproc (thandle_t fd, tdata_t base, toff_t size)
{
    (void) fd;
    (void) base;
    (void) size;
}

/****** image_decoder methods for TIFF decoder *****/

/* Free TIFF decoder
 */
static void
image_decoder_tiff_free (image_decoder *decoder)
{
    image_decoder_tiff *tiff = (image_decoder_tiff*) decoder;

    if (tiff->tif) {
       TIFFClose(tiff->tif);
    }

    mem_free(tiff);
}

/* Begin TIFF decoding
 */
static error
image_decoder_tiff_begin (image_decoder *decoder, const void *data,
        size_t size)
{
    image_decoder_tiff *tiff = (image_decoder_tiff*) decoder;
    error              err = NULL;

    /* Set the TiffClientOpen interface to read a file from memory. */
    tiff->mem_file = (unsigned char*)data;
    tiff->offset_file = 0;
    tiff->size_file = size;

    tiff->tif = TIFFClientOpen("airscan TIFF Interface", 
         "r", (image_decoder_tiff*)(tiff),
        image_decoder_tiff_readproc, image_decoder_tiff_writeproc,
        image_decoder_tiff_seekproc, image_decoder_tiff_closeproc,
        image_decoder_tiff_sizeproc,
        image_decoder_tiff_mapproc, image_decoder_tiff_unmapproc);
	if (tiff->tif == NULL) {
		 return ERROR("TIFF: invalid open memory");
	}

    if (tiff->tif == NULL) {
        return ERROR("TIFF: broken image");;
    }

    /* Obtain image parameters */
    if (!TIFFGetField(tiff->tif, TIFFTAG_SAMPLESPERPIXEL,
        &tiff->bytes_per_pixel)) {
        err = ERROR("TIFF: can't get TIFFTAG_SAMPLESPERPIXEL");
        goto FAIL;
    }

    if (!TIFFGetField(tiff->tif, TIFFTAG_IMAGEWIDTH, &tiff->image_width)) {
        err = ERROR("TIFF: can't get TIFFTAG_IMAGEWIDTH");
        goto FAIL;
    }

    if (!TIFFGetField(tiff->tif, TIFFTAG_IMAGELENGTH, &tiff->image_height)) {
        err = ERROR("TIFF: can't get TIFFTAG_IMAGELENGTH");
        goto FAIL;
    }

    return NULL;

    /* Error: cleanup and exit */
FAIL:
    image_decoder_tiff_reset(decoder);
    return err;
}

/* Reset TIFF decoder
 */
static void
image_decoder_tiff_reset (image_decoder *decoder)
{
    image_decoder_tiff *tiff = (image_decoder_tiff*) decoder;

    if (tiff->tif != NULL) {
        TIFFClose(tiff->tif);
        tiff->tif = NULL;
    }
}

/* Get bytes count per pixel
 */
static int
image_decoder_tiff_get_bytes_per_pixel (image_decoder *decoder)
{
    image_decoder_tiff *tiff = (image_decoder_tiff*) decoder;
    return (int) tiff->bytes_per_pixel;
}

/* Get image parameters
 */
static void
image_decoder_tiff_get_params (image_decoder *decoder, SANE_Parameters *params)
{
    image_decoder_tiff *tiff = (image_decoder_tiff*) decoder;

    params->last_frame = SANE_TRUE;
    params->pixels_per_line = (SANE_Int) tiff->image_width;
    params->lines = (SANE_Int) tiff->image_height;
    params->depth = 8;
    params->bytes_per_line = params->pixels_per_line *
            (SANE_Int) tiff->bytes_per_pixel;

    if (tiff->bytes_per_pixel == 1) {
        params->format = SANE_FRAME_GRAY;
    } else {
        params->format = SANE_FRAME_RGB;
    }
}

/* Set clipping window
 */
static error
image_decoder_tiff_set_window (image_decoder *decoder, image_window *win)
{
    image_decoder_tiff *tiff = (image_decoder_tiff*) decoder;

    win->x_off = win->y_off = 0;
    win->wid = (int) tiff->image_width;
    win->hei = (int) tiff->image_height;

    return NULL;
}

/* Read next line of image
 */
static error
image_decoder_tiff_read_line (image_decoder *decoder, void *buffer)
{
    image_decoder_tiff *tiff = (image_decoder_tiff*) decoder;
    tdata_t buf = (tdata_t) buffer;

    if (tiff->current_line >= tiff->image_height) {
        return ERROR("TIFF: end of file");
    }

    if (TIFFReadScanline(tiff->tif, buf, tiff->current_line, 0) == -1) {
       return ERROR("TIFF: read scanline error");
    }

    tiff->current_line ++;
    return NULL;
}

/* Create TIFF image decoder
 */
image_decoder*
image_decoder_tiff_new (void)
{
    image_decoder_tiff *tiff = mem_new(image_decoder_tiff, 1);

    tiff->decoder.content_type = "image/tiff";
    tiff->decoder.free = image_decoder_tiff_free;
    tiff->decoder.begin = image_decoder_tiff_begin;
    tiff->decoder.reset = image_decoder_tiff_reset;
    tiff->decoder.get_bytes_per_pixel = image_decoder_tiff_get_bytes_per_pixel;
    tiff->decoder.get_params = image_decoder_tiff_get_params;
    tiff->decoder.set_window = image_decoder_tiff_set_window;
    tiff->decoder.read_line = image_decoder_tiff_read_line;
    tiff->mem_file = NULL;
    tiff->offset_file = 0;
    tiff->size_file = 0;
    tiff->current_line = 0;

    return &tiff->decoder;
}

/* vim:ts=8:sw=4:et
 */
