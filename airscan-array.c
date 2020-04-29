/* AirScan (a.k.a. eSCL) backend for SANE
 *
 * Copyright (C) 2019 and up by Alexander Pevzner (pzz@apevzner.com)
 * See LICENSE for license terms and conditions
 *
 * SANE_Word/SANE_String arrays
 */

#include "airscan.h"

#include <stdlib.h>
#include <string.h>

/* Initial capacity of arrays
 */
#define ARRAY_INITIAL_CAPACITY  4

/* Create array of SANE_Word
 */
SANE_Word*
sane_word_array_new (void)
{
    return g_new0(SANE_Word, ARRAY_INITIAL_CAPACITY);
}

/* Free array of SANE_Word
 */
void
sane_word_array_free (SANE_Word *a)
{
    g_free(a);
}

/* Reset array of SANE_Word
 */
void
sane_word_array_reset (SANE_Word **a)
{
    (*a)[0] = 0;
}

/* Get length of the SANE_Word array
 */
size_t
sane_word_array_len (const SANE_Word *a)
{
    return (size_t) a[0];
}

/* Append word to array. Returns new array (old becomes invalid)
 */
SANE_Word*
sane_word_array_append (SANE_Word *a, SANE_Word w)
{
    size_t sz = sane_word_array_len(a) + 1;

    /* If sz reached the power-of-2, reallocate the array, doubling its size */
    if (sz >= ARRAY_INITIAL_CAPACITY && (sz & (sz - 1)) == 0) {
        a = g_renew(SANE_Word, a, sz + sz);
    }

    a[sz] = w;
    a[0] = sz;

    return a;
}

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

/* Create initialize array of SANE_String
 */
SANE_String*
sane_string_array_new (void)
{
    return g_new0(SANE_String, ARRAY_INITIAL_CAPACITY);
}

/* Free array of SANE_String
 */
void
sane_string_array_free (SANE_String *a)
{
    g_free(a);
}

/* Reset array of SANE_String
 */
void
sane_string_array_reset (SANE_String *a)
{
    a[0] = NULL;
}

/* Get length of the SANE_String array
 */
size_t
sane_string_array_len (const SANE_String *a)
{
    size_t sz;

    for (sz = 0; a[sz] != NULL; sz ++)
        ;

    return sz;
}

/* Append string to array Returns new array (old becomes invalid)
 */
SANE_String*
sane_string_array_append(SANE_String *a, SANE_String s)
{
    size_t sz = sane_string_array_len(a) + 1;

    /* If sz reached the power-of-2, reallocate the array, doubling its size */
    if (sz >= ARRAY_INITIAL_CAPACITY && (sz & (sz - 1)) == 0) {
        a = g_renew(SANE_String, a, sz + sz);
    }

    /* Append string */
    a[sz - 1] = s;
    a[sz] = NULL;

    return a;
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

/* Create array of SANE_Device
 */
const SANE_Device**
sane_device_array_new (void)
{
    return g_new0(const SANE_Device*, ARRAY_INITIAL_CAPACITY);
}

/* Free array of SANE_Device
 */
void
sane_device_array_free (const SANE_Device **a)
{
    g_free(a);
}

/* Get length of the SANE_Device array
 */
size_t
sane_device_array_len (const SANE_Device * const *a)
{
    size_t sz;

    for (sz = 0; a[sz] != NULL; sz ++)
        ;

    return sz;
}

/* Append device to array. Returns new array (old becomes invalid)
 */
const SANE_Device**
sane_device_array_append(const SANE_Device **a, SANE_Device *d)
{
    size_t sz = sane_device_array_len(a) + 1;

    /* If sz reached the power-of-2, reallocate the array, doubling its size */
    if (sz >= ARRAY_INITIAL_CAPACITY && (sz & (sz - 1)) == 0) {
        a = g_renew(const SANE_Device*, a, sz + sz);
    }

    /* Append a device */
    a[sz - 1] = d;
    a[sz] = NULL;

    return a;
}

/* vim:ts=8:sw=4:et
 */
