/* AirScan (a.k.a. eSCL) backend for SANE
 *
 * Copyright (C) 2019 and up by Alexander Pevzner (pzz@apevzner.com)
 * See LICENSE for license terms and conditions
 *
 * WS-Discovery
 */

#include "airscan.h"

/* Initialize WS-Discovery
 */
SANE_Status
wsdiscovery_init (void)
{
    return SANE_STATUS_GOOD;
}

/* Cleanup WS-Discovery
 */
void
wsdiscovery_cleanup (void)
{
}

/* vim:ts=8:sw=4:et
 */
