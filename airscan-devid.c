/* AirScan (a.k.a. eSCL) backend for SANE
 *
 * Copyright (C) 2019 and up by Alexander Pevzner (pzz@apevzner.com)
 * See LICENSE for license terms and conditions
 *
 * Unique device IDs
 */

#include "airscan.h"

#include <string.h>

/* DEVID_RANGE defines device ID range, 0 ... DEVID_RANGE-1
 * It must be power of two
 */
#define DEVID_RANGE     65536

static uint16_t devid_next;
static uint32_t devid_bits[DEVID_RANGE/32];

/* Get bit in devid_bits[]
 */
static bool
devid_bits_get(unsigned int id)
{
    uint32_t mask = 1 << (id & 31);
    return (devid_bits[id / 32] & mask) != 0;
}

/* Set bit in devid_bits[]
 */
static void
devid_bits_set(unsigned int id, bool v)
{
    uint32_t mask = 1 << (id & 31);
    if (v) {
        devid_bits[id / 32] |= mask;
    } else {
        devid_bits[id / 32] &= ~mask;
    }
}

/* Allocate unique device ID
 */
unsigned int
devid_alloc (void )
{
    while (devid_bits_get(devid_next)) {
        devid_next ++;
    }

    devid_bits_set(devid_next, true);
    return devid_next ++;
}

/* Free device ID
 */
void
devid_free (unsigned int id)
{
    devid_bits_set(id, false);
}

/* Initialize device ID allocator
 */
void
devid_init (void)
{
    devid_next = 0;
    memset(devid_bits, 0, sizeof(devid_bits));
}

/* vim:ts=8:sw=4:et
 */
