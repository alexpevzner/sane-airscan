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

#include <png.h>

/* save_file represents a PNG output file, used for
 * saving decoded image
 */
typedef struct {
    const char      *name;     /* Output file name */
    FILE            *fp;       /* Output file handle */
    png_struct      *png_ptr;  /* Underlying libpng encoder */
    png_info        *info_ptr; /* libpng info struct */
} save_file;

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

/* libpng write callback
 */
void
png_write_fn (png_struct *png_ptr, png_bytep data, size_t size)
{
    save_file *file = png_get_io_ptr(png_ptr);

    if (size != fwrite(data, 1, size, file->fp)) {
        die("%s: %s", file->name, strerror(errno));
    }
}

/* libpng error callback
 */
void
png_error_fn (png_struct *png_ptr, const char *message)
{
    save_file *file = png_get_error_ptr(png_ptr);
    die("%s: %s", file->name, message);
}

/* Open the save_file
 */
save_file*
save_open (const char *name, const SANE_Parameters *params)
{
    save_file *save = g_new0(save_file, 1);
    int       color_type;

    save->name = g_strdup(name);
    save->fp = fopen(name, "wb");
    if (save->fp == NULL) {
        die("%s: %s", name, strerror(errno));
    }

    save->png_ptr = png_create_write_struct(PNG_LIBPNG_VER_STRING,
        NULL, NULL, NULL);
    if (save->png_ptr == NULL) {
        die("%s: png_create_write_struct() failed", name);
    }

    png_set_write_fn(save->png_ptr, save, png_write_fn, NULL);
    png_set_error_fn(save->png_ptr, save, png_error_fn, png_error_fn);

    save->info_ptr = png_create_info_struct(save->png_ptr);
    if (save->info_ptr == NULL) {
        die("%s: png_create_info_struct() failed", name);
    }

    if (params->format == SANE_FRAME_GRAY) {
        color_type = PNG_COLOR_TYPE_GRAY;
    } else {
        color_type = PNG_COLOR_TYPE_RGB;
    }

    png_set_IHDR(save->png_ptr, save->info_ptr,
        params->pixels_per_line, params->lines, params->depth,
        color_type, PNG_INTERLACE_NONE,
        PNG_COMPRESSION_TYPE_DEFAULT, PNG_FILTER_TYPE_DEFAULT);

    png_set_sRGB(save->png_ptr, save->info_ptr, PNG_sRGB_INTENT_PERCEPTUAL);

    png_write_info(save->png_ptr, save->info_ptr);

    return save;
}

/* Close the save file
 */
void
save_close (save_file *save)
{
    png_write_end(save->png_ptr, NULL);
    png_destroy_write_struct(&save->png_ptr, &save->info_ptr);
    fclose(save->fp);
    g_free((char*) save->name);
    g_free(save);
}

/* Write a row of image data
 */
void
save_write (save_file *save, const void *data)
{
    png_write_row(save->png_ptr, data);
}

/* The main function
 */
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
    save_file       *save;

    /* Parse command-line arguments */
    if (argc != 2) {
        die("usage: %s file", argv[0]);
    }

    file = argv[1];
    ext = strrchr(file, '.');
    ext = ext ? ext + 1 : "";

    /* Create decoder */
    if (!strcmp(ext, "jpeg") || !strcmp(ext, "jpg")) {
        decoder = image_decoder_jpeg_new();
    } else if (!strcmp(ext, "tiff") || !strcmp(ext, "tif")) {
        decoder = image_decoder_tiff_new();
    } else if (!strcmp(ext, "png")) {
        decoder = image_decoder_png_new();
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

    save = save_open("decoded.png", &params);

    line = g_malloc(params.bytes_per_line);
    for (i = 0; i < params.lines; i ++) {
        err = image_decoder_read_line(decoder, line);
        if (err != NULL) {
            die("line %d: %s", i, err);
        }

        save_write(save, line);
    }

    save_close(save);

    return 0;
}

/* vim:ts=8:sw=4:et
 */
