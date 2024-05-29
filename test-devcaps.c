/* sane-airscan device capabilities parser test
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
void __attribute__((noreturn))
die (const char *format, ...)
{
    va_list ap;

    va_start(ap, format);
    vprintf(format, ap);
    printf("\n");
    va_end(ap);

    exit(1);
}

/* The main function
 */
int
main (int argc, char **argv)
{
    char          *mode, *file;
    FILE          *fp;
    void          *data;
    long          size;
    proto_handler *proto;
    int           rc;
    error         err;
    devcaps       caps;

    /* Parse command-line arguments */
    if (argc != 3) {
        die(
                "test-devcaps - decode and print device capabilities\n"
                "usage: %s [-escl|-wsd] file.xml", argv[0]
            );
    }

    mode = argv[1];
    file = argv[2];

    if (!strcmp(mode, "-escl")) {
        proto = proto_handler_escl_new();
    } else if (!strcmp(mode, "-wsd")) {
        proto = proto_handler_wsd_new();
    } else {
        die("%s: unknown protocol", mode);
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

    data = mem_new(char, size);
    if ((size_t) size != fread(data, 1, size, fp)) {
        die("%s: read error", file);
    }

    fclose(fp);

    /* Decode device capabilities */
    memset(&caps, 0, sizeof(caps));
    devcaps_init(&caps);

    err = proto->test_decode_devcaps(proto, data, size, &caps);
    if (err != NULL) {
        die("error: %s", ESTRING(err));
    }

    /* Cleanup and exit */
    proto_handler_free(proto);
    free(data);

    return 0;
}

/* vim:ts=8:sw=4:et
 */
