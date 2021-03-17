/* AirScan (a.k.a. eSCL) backend for SANE
 *
 * Copyright (C) 2019 and up by Alexander Pevzner (pzz@apevzner.com)
 * See LICENSE for license terms and conditions
 *
 * Random bytes generator
 */

#include "airscan.h"

#pragma GCC diagnostic ignored "-Wunused-result"

#include <errno.h>
#include <stdio.h>
#include <string.h>

#define RAND_SOURCE "/dev/urandom"

static FILE *rand_fp;

/* Get N random bytes
 */
void
rand_bytes (void *buf, size_t n)
{
    log_assert(NULL, rand_fp != NULL);

    /* Read from /dev/urandom never fails
     * */
    (void) fread(buf, 1, n, rand_fp);
}

/* Initialize random bytes generator
 */
SANE_Status
rand_init (void)
{
    rand_fp = fopen(RAND_SOURCE, "rb");
    if (rand_fp == NULL) {
        log_debug(NULL, "%s: %s", RAND_SOURCE, strerror(errno));
        return SANE_STATUS_IO_ERROR;
    }

    return SANE_STATUS_GOOD;
}

/* Cleanup random bytes generator
 */
void
rand_cleanup (void)
{
    if (rand_fp != NULL) {
        fclose(rand_fp);
        rand_fp = NULL;
    }
}

/* vim:ts=8:sw=4:et
 */
