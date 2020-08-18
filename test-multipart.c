/* sane-airscan HTTP multipart decoder test
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
    const char      *file;
    FILE            *fp;
    long            size;
    int             rc;
    void            *data;
    error           err;
    http_client     *client;
    http_uri        *uri;
    http_query      *q;
    int             i, cnt;

    /* Parse command-line arguments */
    if (argc != 2) {
        die("usage: %s file", argv[0]);
    }

    file = argv[1];

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

    /* Initialize logging */
    log_init();
    conf.dbg_enabled = true;
    log_configure();

    /* Decode the image */
    client = http_client_new(NULL, NULL);
    uri = http_uri_new("http://localhost", false);
    q = http_query_new(client, uri, "GET", NULL, NULL);

    err = http_query_test_decode_response(q, data, size);
    if (err != NULL) {
        die("%s", ESTRING(err));
    }

    cnt = http_query_get_mp_response_count(q);
    if (cnt > 0) {
        printf("Part    Size  Content-Type\n");
        printf("====    ====  ============\n");
        for (i = 0; i < cnt; i ++) {
            http_data *data = http_query_get_mp_response_data(q, i);
            printf("%3d %8d  %s\n", i, (int) data->size, data->content_type);
        }
    }

    return 0;
}

/* vim:ts=8:sw=4:et
 */
