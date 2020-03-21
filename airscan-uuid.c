/* AirScan (a.k.a. eSCL) backend for SANE
 *
 * Copyright (C) 2019 and up by Alexander Pevzner (pzz@apevzner.com)
 * See LICENSE for license terms and conditions
 *
 * UUID generator
 */

#include "airscan.h"

#include <stdio.h>
#include <sys/random.h>

/* Generate new random UUID. Generated UUID has a following form:
 *    urn:uuid:ede05377-460e-4b4a-a5c0-423f9e02e8fa
 */
uuid
uuid_new (void)
{
    unsigned char rnd[16];
    uuid          u;

    getrandom(rnd, sizeof(rnd), 0);

    // urn:uuid:ede05377-460e-4b4a-a5c0-423f9e02e8fa
    sprintf(u.text,
        "urn:uuid:"
        "%.2x%.2x%.2x%.2x-%.2x%.2x-%.2x%.2x-%.2x%.2x-%.2x%.2x%.2x%.2x%.2x%.2x",
        rnd[0], rnd[1], rnd[2], rnd[3], rnd[4], rnd[5], rnd[6], rnd[7],
        rnd[8], rnd[9], rnd[10], rnd[11], rnd[12], rnd[13], rnd[14], rnd[15]);

    return u;
}

/* vim:ts=8:sw=4:et
 */
