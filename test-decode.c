/* sane-airscan image decoders test
 *
 * Copyright (C) 2019 and up by Alexander Pevzner (pzz@apevzner.com)
 * See LICENSE for license terms and conditions
 */

#include "airscan.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Print error message and exit
 */
void
die (const char *format, ...)
{
    va_list ap;

    va_start(ap, format);
    vprintf(format, ap);
    printf("\n");
    va_end(ap);

    exit(1);
}

int
main (int argc, char **argv)
{
    const char      *file, *ext;
    image_decoder   *decoder = NULL;
    FILE            *fp;
    long            size;
    int             rc;
    void            *data, *line;
    error           err;
    SANE_Parameters params;
    int             i;

    /* Parse command-line arguments */
    if (argc != 2) {
        die("usage: %s file", argv[0]);
    }

    file = argv[1];
    ext = strrchr(file, '.');
    ext = ext ? ext + 1 : "";

    /* Create decoder */
    if (!strcmp(ext, "jpeg")) {
        decoder = image_decoder_jpeg_new();
    } else if (!strcmp(ext, "tiff")) {
        decoder = image_decoder_tiff_new();
    }

    if (decoder == NULL) {
        die("can't guess image format");
    }

    /* Load the file */
    fp = fopen(file, "rb");
    if (fp == NULL) {
        die("%s: %s", file, strerror(errno));
    }

    rc = fseek(fp, 0, SEEK_END);
    if (rc < 0) {
        die("%s: %s", file, strerror(errno));
    }

    size = ftell(fp);
    if (size < 0) {
        die("%s: %s", file, strerror(errno));
    }

    rc = fseek(fp, 0, SEEK_SET);
    if (rc < 0) {
        die("%s: %s", file, strerror(errno));
    }

    data = g_malloc(size);
    if ((size_t) size != fread(data, 1, size, fp)) {
        die("%s: read error", file);
    }

    fclose(fp);

    /* Decode the image */
    err = image_decoder_begin(decoder, data, size);
    if (err != NULL) {
        die("%s", err);
    }

    image_decoder_get_params(decoder, &params);
    printf("format:      %s\n",   image_content_type(decoder));
    printf("width:       %d\n",   params.pixels_per_line);
    printf("height:      %d\n",   params.lines);
    printf("bytes/line:  %d\n", params.bytes_per_line);
    printf("bytes/pixel: %d\n", params.bytes_per_line / params.pixels_per_line);

    line = g_malloc(params.bytes_per_line);
    for (i = 0; i < params.lines; i ++) {
        err = image_decoder_read_line(decoder, line);
        if (err != NULL) {
            die("line %d: %s", i, err);
        }
    }

    return 0;
}

/* vim:ts=8:sw=4:et
 */
