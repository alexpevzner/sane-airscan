/* AirScan (a.k.a. eSCL) backend for SANE
 *
 * Copyright (C) 2019 and up by Alexander Pevzner (pzz@apevzner.com)
 * See LICENSE for license terms and conditions
 *
 * Unique device IDs
 */

#include "airscan.h"

/* Allocate new devid
 */
devid
devid_new (void)
{
    static uint64_t next;
    devid id;

    sprintf(id.text, "%16.16lx",
        __atomic_add_fetch(&next, 1, __ATOMIC_SEQ_CST));

    return id;
}

/* vim:ts=8:sw=4:et
 */
