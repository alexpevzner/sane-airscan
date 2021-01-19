/* sane - Scanner Access Now Easy.
 *
 * Copyright (C) 2020 Thierry HUCHARD <thierry@ordissimo.com>
 * See LICENSE for license terms and conditions
 */

#include "airscan.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <string.h>

#if defined(OS_HAVE_ENDIAN_H)
#   include <endian.h>
#elif defined(OS_HAVE_SYS_ENDIAN_H)
#   include <sys/endian.h>
#endif

/* BITMAPFILEHEADER structure, see MSDN for details
 */
#pragma pack (push,1)
typedef struct {
    uint16_t bfType;           /* File magic, always 'BM' */
    uint32_t bfSize;           /* File size in bytes */
    uint16_t bfReserved1;      /* Reserved; must be zero */
    uint16_t bfReserved2;      /* Reserved; must be zero */
    uint32_t bfOffBits;        /* Offset to bitmap bits */
} BITMAPFILEHEADER;
#pragma pack (pop)

/* BITMAPINFOHEADER structure, see MSDN for details
 */
#pragma pack (push,1)
typedef struct {
    uint32_t  biSize;          /* Header size, bytes */
    int32_t   biWidth;         /* Image width, pixels */
    int32_t   biHeight;        /* Image height, pixels */
    uint16_t  biPlanes;        /* Number of planes, always 1 */
    uint16_t  biBitCount;      /* Bits per pixel */
    uint32_t  biCompression;   /* Compression type, see MSDN */
    uint32_t  biSizeImage;     /* Image size, can be o */
    int32_t   biXPelsPerMeter; /* Horizontal resolution, pixels per meter */
    int32_t   biYPelsPerMeter; /* Vertical resolution, pixels per meter */
    uint32_t  biClrUsed;       /* Number of used palette indices */
    uint32_t  biClrImportant;  /* Number of important palette indices */
} BITMAPINFOHEADER;
#pragma pack (pop)

/* BMP image decoder
 */
typedef struct {
    image_decoder                 decoder;       /* Base class */
    char                          error[256];    /* Error message buffer */
    const uint8_t                 *image_data;   /* Image data */
    BITMAPINFOHEADER              info_header;   /* DIB header, decoded */
    size_t                        bmp_row_size;  /* Row size in BMP file */
    SANE_Frame                    format;        /* SANE_FRAME_GRAY/RBG */
    unsigned int                  next_line;     /* Next line to read */
} image_decoder_bmp;

/* Free BMP decoder
 */
static void
image_decoder_bmp_free (image_decoder *decoder)
{
    image_decoder_bmp *bmp = (image_decoder_bmp*) decoder;
    mem_free(bmp);
}

/* Begin BMP decoding
 */
static error
image_decoder_bmp_begin (image_decoder *decoder, const void *data,
        size_t size)
{
    image_decoder_bmp *bmp = (image_decoder_bmp*) decoder;
    BITMAPFILEHEADER  file_header;
    size_t            header_size, padding;
    uint64_t          size_required;

    /* Decode BMP header */
    if (size < sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER)) {
        return ERROR("BMP: header truncated");
    }

    memcpy(&file_header, data, sizeof(BITMAPFILEHEADER));
    memcpy(&bmp->info_header, ((char*) data) + sizeof(BITMAPFILEHEADER),
        sizeof(BITMAPINFOHEADER));

    file_header.bfType = le16toh(file_header.bfType);
    file_header.bfSize = le32toh(file_header.bfSize);
    file_header.bfOffBits = le32toh(file_header.bfOffBits);

    bmp->info_header.biSize = le32toh(bmp->info_header.biSize);
    bmp->info_header.biWidth = le32toh(bmp->info_header.biWidth);
    bmp->info_header.biHeight = le32toh(bmp->info_header.biHeight);
    bmp->info_header.biPlanes = le16toh(bmp->info_header.biPlanes);
    bmp->info_header.biBitCount = le16toh(bmp->info_header.biBitCount);
    bmp->info_header.biCompression = le32toh(bmp->info_header.biCompression);
    bmp->info_header.biSizeImage = le32toh(bmp->info_header.biSizeImage);
    bmp->info_header.biXPelsPerMeter = le32toh(bmp->info_header.biXPelsPerMeter);
    bmp->info_header.biYPelsPerMeter = le32toh(bmp->info_header.biYPelsPerMeter);
    bmp->info_header.biClrUsed = le32toh(bmp->info_header.biClrUsed);
    bmp->info_header.biClrImportant = le32toh(bmp->info_header.biClrImportant);

    /* Validate BMP header */
    if (file_header.bfType != ('M' << 8 | 'B')) {
        return ERROR("BMP: invalid header signature");
    }

    if (bmp->info_header.biSize < sizeof(BITMAPINFOHEADER)) {
        sprintf(bmp->error, "BMP: invalid header size %d",
            bmp->info_header.biSize);
        return ERROR(bmp->error);
    }

    if (bmp->info_header.biCompression != 0) {
        sprintf(bmp->error, "BMP: compression %d not supported",
            bmp->info_header.biCompression);
        return ERROR(bmp->error);
    }

    /* Ignore palette for 8-bit (grayscale) images, reject it otherwise */
    if (bmp->info_header.biClrUsed != 0 && bmp->info_header.biBitCount != 8) {
        return ERROR("BMP: paletted images not supported");
    }

    switch (bmp->info_header.biBitCount) {
    case 8:
        bmp->format = SANE_FRAME_GRAY;
        break;

    case 24:
    case 32:
        bmp->format = SANE_FRAME_RGB;
        break;

    default:
        sprintf(bmp->error, "BMP: %d bits per pixel not supported",
            bmp->info_header.biBitCount);
        return ERROR(bmp->error);
    }

    /* Compute BMP row size */
    bmp->bmp_row_size = bmp->info_header.biWidth;
    bmp->bmp_row_size *= bmp->info_header.biBitCount / 8;
    padding = (4 - (bmp->bmp_row_size & 3)) & 3;
    bmp->bmp_row_size += padding;

    /* Make sure image is not truncated */
    header_size = sizeof(BITMAPFILEHEADER) + bmp->info_header.biSize;
    header_size += (size_t) bmp->info_header.biClrUsed * 4;
    size_required = header_size;
    size_required += ((uint64_t) labs(bmp->info_header.biHeight)) *
        (uint64_t) bmp->bmp_row_size;
    size_required -= padding; /* Last row may be unpadded */

    if (size_required > (uint64_t) size) {
        return ERROR("BMP: image truncated");
    }

    /* Save pointer to image data */
    bmp->image_data = header_size + (const uint8_t*) data;

    return NULL;
}

/* Reset BMP decoder
 */
static void
image_decoder_bmp_reset (image_decoder *decoder)
{
    image_decoder_bmp *bmp = (image_decoder_bmp*) decoder;
    size_t            off = sizeof(bmp->decoder);

    memset(((char*) bmp) + off, 0, sizeof(*bmp) - off);
}

/* Get bytes count per pixel
 */
static int
image_decoder_bmp_get_bytes_per_pixel (image_decoder *decoder)
{
    image_decoder_bmp *bmp = (image_decoder_bmp*) decoder;

    return bmp->format == SANE_FRAME_GRAY ? 1 : 3;
}

/* Get image parameters
 */
static void
image_decoder_bmp_get_params (image_decoder *decoder, SANE_Parameters *params)
{
    image_decoder_bmp *bmp = (image_decoder_bmp*) decoder;

    params->last_frame = SANE_TRUE;
    params->pixels_per_line = bmp->info_header.biWidth;
    params->lines = labs(bmp->info_header.biHeight);
    params->depth = 8;
    params->format = bmp->format;
    params->bytes_per_line = params->pixels_per_line;
    if (params->format == SANE_FRAME_RGB) {
        params->bytes_per_line *= 3;
    }
}

/* Set clipping window
 */
static error
image_decoder_bmp_set_window (image_decoder *decoder, image_window *win)
{
    image_decoder_bmp *bmp = (image_decoder_bmp*) decoder;

    win->x_off = win->y_off = 0;
    win->wid = bmp->info_header.biWidth;
    win->hei = labs(bmp->info_header.biHeight);

    return NULL;
}

/* Read next line of image
 */
static error
image_decoder_bmp_read_line (image_decoder *decoder, void *buffer)
{
    image_decoder_bmp *bmp = (image_decoder_bmp*) decoder;
    size_t            row_num;
    const uint8_t     *row_data;
    int               i, wid = bmp->info_header.biWidth;
    uint8_t           *out = buffer;

    if (bmp->next_line == (unsigned int) labs(bmp->info_header.biHeight)) {
        return ERROR("BMP: end of file");
    }

    /* Compute row number */
    row_num = bmp->next_line ++;
    if (bmp->info_header.biHeight > 0) {
        row_num = bmp->info_header.biHeight - row_num - 1;
    }

    /* Compute row address */
    row_data = bmp->image_data + row_num * bmp->bmp_row_size;

    /* Decode the row */
    switch (bmp->info_header.biBitCount) {
    case 8:
        memcpy(out, row_data, wid);
        break;

    case 24:
        for (i = 0; i < wid; i ++) {
            out[0] = row_data[2]; /* Red */
            out[1] = row_data[1]; /* Green */
            out[2] = row_data[0]; /* Blue */
            out += 3;
            row_data += 3;
        }
        break;

    case 32:
        for (i = 0; i < wid; i ++) {
            out[0] = row_data[2]; /* Red */
            out[1] = row_data[1]; /* Green */
            out[2] = row_data[0]; /* Blue */
            out += 3;
            row_data += 4;
        }
        break;

    default:
        log_internal_error(NULL);
    }

    return NULL;
}

/* Create BMP image decoder
 */
image_decoder*
image_decoder_bmp_new (void)
{
    image_decoder_bmp *bmp = mem_new(image_decoder_bmp, 1);

    bmp->decoder.content_type = "image/bmp";
    bmp->decoder.free = image_decoder_bmp_free;
    bmp->decoder.begin = image_decoder_bmp_begin;
    bmp->decoder.reset = image_decoder_bmp_reset;
    bmp->decoder.get_bytes_per_pixel = image_decoder_bmp_get_bytes_per_pixel;
    bmp->decoder.get_params = image_decoder_bmp_get_params;
    bmp->decoder.set_window = image_decoder_bmp_set_window;
    bmp->decoder.read_line = image_decoder_bmp_read_line;

    return &bmp->decoder;
}

/* vim:ts=8:sw=4:et
 */
