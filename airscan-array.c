/* AirScan (a.k.a. eSCL) backend for SANE
 *
 * Copyright (C) 2019 and up by Alexander Pevzner (pzz@apevzner.com)
 * See LICENSE for license terms and conditions
 *
 * SANE_Word/SANE_String arrays
 */

#include "airscan.h"

/* Initial capacity of arrays
 */
#define ARRAY_INITIAL_CAPACITY  4

/* Initialize array of SANE_Word
 */
void
sane_word_array_init (SANE_Word **a)
{
    *a = g_new0(SANE_Word, ARRAY_INITIAL_CAPACITY);
}

/* Cleanup array of SANE_Word
 */
void
sane_word_array_cleanup (SANE_Word **a)
{
    g_free(*a);
    *a = NULL;
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
sane_word_array_len (SANE_Word **a)
{
    return (size_t) (*a)[0];
}

/* Append word to array
 */
void
sane_word_array_append(SANE_Word **a, SANE_Word w)
{
    size_t sz = sane_word_array_len(a) + 1;

    /* If sz reached the power-of-2, reallocate the array, doubling its size */
    if (sz >= ARRAY_INITIAL_CAPACITY && (sz & (sz - 1)) == 0) {
        *a = g_renew(SANE_Word, (*a), sz + sz);
    }

    (*a)[sz] = w;
    (*a)[0] ++;
}

/* Compare function for sane_word_array_sort
 */
int
sane_word_array_sort_cmp(const void *p1, const void *p2)
{
    return *(SANE_Word*) p1 - *(SANE_Word*) p2;
}

/* Sort array of SANE_Word in increasing order
 */
void
sane_word_array_sort(SANE_Word **a)
{
    SANE_Word len = (*a)[0];

    if (len) {
        qsort((*a) + 1, len, sizeof(SANE_Word), sane_word_array_sort_cmp);
    }
}

/* Initialize array of SANE_String
 */
void
sane_string_array_init (SANE_String **a)
{
    *a = g_new0(SANE_String, ARRAY_INITIAL_CAPACITY);
}

/* Reset array of SANE_String
 */
void
sane_string_array_reset (SANE_String **a)
{
    (*a)[0] = NULL;
}

/* Cleanup array of SANE_String
 */
void
sane_string_array_cleanup (SANE_String **a)
{
    g_free(*a);
    *a = NULL;
}

/* Get length of the SANE_Word array
 */
size_t
sane_string_array_len (SANE_String **a)
{
    size_t sz;

    for (sz = 0; (*a)[sz]; sz ++)
        ;

    return sz;
}

/* Append string to array
 */
void
sane_string_array_append(SANE_String **a, SANE_String s)
{
    size_t sz = sane_string_array_len(a) + 1;

    /* If sz reached the power-of-2, reallocate the array, doubling its size */
    if (sz >= ARRAY_INITIAL_CAPACITY && (sz & (sz - 1)) == 0) {
        *a = g_renew(SANE_String, (*a), sz + sz);
    }

    /* Append string */
    (*a)[sz - 1] = s;
    (*a)[sz] = NULL;
}

/* Compute max string length in array of strings
 */
size_t
sane_string_array_max_strlen(SANE_String **a)
{
    size_t max_len = 0;
    SANE_String *s = *a;

    for (; *s != NULL; s ++) {
        size_t len = strlen(*s);
        if (len > max_len) {
            max_len = len;
        }
    }
    return max_len;
}

/* vim:ts=8:sw=4:et
 */
