/* AirScan (a.k.a. eSCL) backend for SANE
 *
 * Copyright (C) 2019 and up by Alexander Pevzner (pzz@apevzner.com)
 * See LICENSE for license terms and conditions
 *
 * UUID generator
 */

#include "airscan.h"

#include <ctype.h>
#include <stdio.h>
#include <sys/random.h>

#pragma GCC diagnostic ignored "-Wunused-result"

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

/* Compare two UUID strings. This function ignores all "decorations",
 * line urn:uuid: prefix and so on, and takes only hexadecimal numbers
 * into considerations, so it can be used to compare UUIDs represented
 * in different formats.
 */
bool
uuid_equal (const char *s1, const char *s2)
{
    unsigned char c1, c2;

    do {
        while ((c1 = *s1) != '\0' && !isxdigit(c1)) {
            s1 ++;
        }

        while ((c2 = *s2) != '\0' && !isxdigit(c2)) {
            s2 ++;
        }

        if (toupper(c1) != toupper(c2)) {
            return false;
        }
    } while (c1 != '\0');

    return true;
}

/* vim:ts=8:sw=4:et
 */
