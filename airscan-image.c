/* AirScan (a.k.a. eSCL) backend for SANE
 *
 * Copyright (C) 2019 and up by Alexander Pevzner (pzz@apevzner.com)
 * See LICENSE for license terms and conditions
 *
 * Image decoding
 */

#include "airscan.h"

#include <string.h>

/* image_format_magic defines magic bytes for detection of
 * particular format
 */
typedef struct {
    ID_FORMAT format;    /* Detected format */
    size_t    off, len;  /* Bytes offset and length within the image */
    uint8_t   bytes[16]; /* Bytes to match */
} image_format_magic;

/* image_format_magic_tab contains magic bytes for known formats
 */
static image_format_magic
image_format_magic_tab[] = {
    {ID_FORMAT_BMP,  0, 2, {'B', 'M'}},
    {ID_FORMAT_JPEG, 0, 2, {0xff, 0xd8}},
    {ID_FORMAT_PNG,  0, 8, {0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a}},
    {ID_FORMAT_TIFF, 0, 4, {'I', 'I', '*', '\0'}},
    {ID_FORMAT_TIFF, 0, 4, {'M', 'M', '\0', '*'}}
};

/* image_format_match matches image against the magic
 * If image matches, it returns ID_FORMAT, as defined by magic.
 * Otherwise, it returns ID_FORMAT_UNKNOWN
 */
static ID_FORMAT
image_format_match (const image_format_magic *magic,
        const void *data, size_t size)
{
    int cmp;

    if (magic->off + magic->len > size) {
        return ID_FORMAT_UNKNOWN;
    }

    cmp = memcmp(((const char*) data) + magic->off, magic->bytes, magic->len);
    if (cmp == 0) {
        return magic->format;
    }

    return ID_FORMAT_UNKNOWN;
}

/* Detect image format by image data
 */
ID_FORMAT
image_format_detect (const void *data, size_t size)
{
    size_t max = sizeof(image_format_magic_tab) /
                 sizeof(image_format_magic_tab[0]);
    size_t i;

    for (i = 0; i < max; i ++) {
        const image_format_magic *magic = &image_format_magic_tab[i];
        ID_FORMAT                format;

        format = image_format_match(magic, data, size);
        if (format != ID_FORMAT_UNKNOWN) {
            return format;
        }
    }

    return ID_FORMAT_UNKNOWN;
}

/* vim:ts=8:sw=4:et
 */
