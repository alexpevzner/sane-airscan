/* AirScan (a.k.a. eSCL) backend for SANE
 *
 * Copyright (C) 2019 and up by Alexander Pevzner (pzz@apevzner.com)
 * See LICENSE for license terms and conditions
 *
 * SANE_Word/SANE_String/SANE_Device* arrays
 */

#include "airscan.h"

#include <stdlib.h>
#include <string.h>

/* Compare function for sane_word_array_sort
 */
static int
sane_word_array_sort_cmp(const void *p1, const void *p2)
{
    return *(SANE_Word*) p1 - *(SANE_Word*) p2;
}

/* Sort array of SANE_Word in increasing order
 */
void
sane_word_array_sort(SANE_Word *a)
{
    SANE_Word len = a[0];

    if (len) {
        qsort(a + 1, len, sizeof(SANE_Word), sane_word_array_sort_cmp);
    }
}

/* Intersect two sorted arrays.
 */
SANE_Word*
sane_word_array_intersect_sorted (const SANE_Word *a1, const SANE_Word *a2)
{
    const SANE_Word *end1 = a1 + sane_word_array_len(a1) + 1;
    const SANE_Word *end2 = a2 + sane_word_array_len(a2) + 1;
    SANE_Word       *out = sane_word_array_new();

    a1 ++;
    a2 ++;

    while (a1 < end1 && a2 < end2) {
        if (*a1 < *a2) {
            a1 ++;
        } else if (*a1 > *a2) {
            a2 ++;
        } else {
            out = sane_word_array_append(out, *a1);
            a1 ++;
            a2 ++;
        }
    }

    return out;
}

/* Compute max string length in array of strings
 */
size_t
sane_string_array_max_strlen(const SANE_String *a)
{
    size_t max_len = 0;

    for (; *a != NULL; a ++) {
        size_t len = strlen(*a);
        if (len > max_len) {
            max_len = len;
        }
    }

    return max_len;
}

/* vim:ts=8:sw=4:et
 */
