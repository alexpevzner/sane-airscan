/* AirScan (a.k.a. eSCL) backend for SANE
 *
 * Copyright (C) 2019 and up by Alexander Pevzner (pzz@apevzner.com)
 * See LICENSE for license terms and conditions
 *
 * Web Services Dynamic Discovery (WS-Discovery)
 */

#include "airscan.h"

static netif_notifier *wsdd_netif_notifier;

/* Network interfaces address change notification
 */
static void
wsdd_netif_notifier_callback (void *data)
{
    (void) data;
    log_debug(NULL, "WSDD: netif event");
}

/* Initialize WS-Discovery
 */
SANE_Status
wsdd_init (void)
{
    wsdd_netif_notifier = netif_notifier_create(
        wsdd_netif_notifier_callback, NULL);
    if (wsdd_netif_notifier == NULL) {
        return SANE_STATUS_IO_ERROR;
    }

    return SANE_STATUS_GOOD;
}

/* Cleanup WS-Discovery
 */
void
wsdd_cleanup (void)
{
    if (wsdd_netif_notifier != NULL) {
        netif_notifier_free(wsdd_netif_notifier);
        wsdd_netif_notifier = NULL;
    }
}

/* vim:ts=8:sw=4:et
 */
