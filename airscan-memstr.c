/* AirScan (a.k.a. eSCL) backend for SANE
 *
 * Copyright (C) 2019 and up by Alexander Pevzner (pzz@apevzner.com)
 * See LICENSE for license terms and conditions
 *
 * Memory allocation
 */

#include "airscan.h"

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* While memory block grows, its size is doubled until
 * MEM_CAP_BLOCK is reached, then it grows linearly,
 * reminding a multiple of whole MEM_CAP_BLOCKs
 */
#define MEM_CAP_BLOCK   65536

/* Each memory block allocated from here has the following
 * control record
 */
typedef struct {
    uint32_t len, cap; /* Block length and capacity in bytes */
} mem_head;

/* Check for OOM
 */
#define mem_check_oom(p,must)                   \
    do{                                         \
        if ((p) == NULL && must) {              \
            log_panic(NULL, "Out of memory");   \
            __builtin_unreachable();            \
        }                                       \
    } while(0)

/* Truncate the vector length, preserving previously allocated buffer
 */
void
mem_trunc (void *p)
{
    ((mem_head*) p)[-1].len = 0;
}

/* Free memory, previously obtained from mem_new()/mem_expand()
 */
void
mem_free (void *p)
{
    if (p != NULL) {
        free(((mem_head*) p) - 1);
    }
}

/* Get memory block length, in bytes
 */
size_t
mem_len_bytes (const void *p)
{
    return ((mem_head*) p)[-1].len;
}

/* Get memory block capacity, in bytes
 */
size_t
mem_cap_bytes (const void *p)
{
    return ((mem_head*) p)[-1].cap;
}

/* Compute allocation size, including mem_head header, in bytes
 */
static inline int
mem_alloc_size(size_t len, size_t extra, size_t elsize)
{
    size_t sz = sizeof(mem_head) * elsize * (len + extra);

    if (sz < MEM_CAP_BLOCK) {
        /* Round up to the next power of 2 */
        sz --;
        sz |= sz >> 1;
        sz |= sz >> 2;
        sz |= sz >> 4;
        sz |= sz >> 8;
        sz |= sz >> 16;
        sz ++;
    } else {
        /* Round up to the next block boundary */
        sz ++;
        sz &= ~(MEM_CAP_BLOCK - 1);
    }

    return sz;
}

/* Helper function: allocate new block of memory
 */
void*
__mem_alloc (size_t len, size_t extra, size_t elsize, bool must)
{
    size_t   sz = mem_alloc_size(len, extra, elsize);
    mem_head *h = calloc(sz, 1);

    if (h == NULL) {
        mem_check_oom(h, must);
        return NULL;
    }

    h->len = len * elsize;
    h->cap = sz - (sizeof(mem_head));

    return h + 1;
}

/* Helper function for memory allocation.
 * Allocated or resizes memory block
 */
void*
__mem_resize (void *p, size_t len, size_t extra, size_t elsize, bool must)
{
    size_t   sz;
    mem_head *h;

    /* If `p' is NULL, just call __mem_alloc() */
    if (p == NULL) {
        return __mem_alloc(len, extra, elsize, must);
    }

    /* Reallocate memory, if required */
    h = ((mem_head*) p) - 1;
    sz = mem_alloc_size(len, extra, elsize);

    if (h->cap + sizeof(mem_head) < sz) {
        h = realloc(h, sz);
        if (h == NULL) {
            mem_check_oom(h, must);
            return NULL;
        }
    }

    /* Zero-fill newly added elements */
    if (len > h->len) {
        memset(((char*) h + 1) + h->len * elsize, 0, (len - h->len) * elsize);
    }

    /* Update control header and return a block */
    h->len = len * elsize;
    h->cap = sz - (sizeof(mem_head));

    return h + 1;
}

/* vim:ts=8:sw=4:et
 */

