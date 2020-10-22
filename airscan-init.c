/* AirScan (a.k.a. eSCL) backend for SANE
 *
 * Copyright (C) 2019 and up by Alexander Pevzner (pzz@apevzner.com)
 * See LICENSE for license terms and conditions
 *
 * Initialization/cleanup
 */

#include "airscan.h"

/* Initialize airscan
 */
SANE_Status
airscan_init (AIRSCAN_INIT_FLAGS flags, const char *log_msg)
{
    SANE_Status status;

    /* Initialize logging -- do it early */
    log_init();
    trace_init();
    if (log_msg != NULL) {
        log_debug(NULL, "%s", log_msg);
    }

    if ((flags & AIRSCAN_INIT_NO_CONF) == 0) {
        conf_load();
    }

    log_configure(); /* As soon, as configuration is available */

    /* Initialize all parts */
    devid_init();

    status = eloop_init();
    if (status == SANE_STATUS_GOOD) {
        status = rand_init();
    }
    if (status == SANE_STATUS_GOOD) {
        status = http_init();
    }
    if (status == SANE_STATUS_GOOD) {
        status = netif_init();
    }
    if (status == SANE_STATUS_GOOD) {
        status = zeroconf_init();
    }
    if (status == SANE_STATUS_GOOD) {
        status = mdns_init();
    }
    if (status == SANE_STATUS_GOOD) {
        status = wsdd_init();
    }

    if (status != SANE_STATUS_GOOD) {
        airscan_cleanup(NULL);
    } else if ((flags & AIRSCAN_INIT_NO_THREAD) == 0) {
        eloop_thread_start();
    }

    return status;
}

/* Cleanup airscan
 * If log_msg is not NULL, it is written to the log as late as possible
 */
void
airscan_cleanup (const char *log_msg)
{
    mdns_cleanup();
    wsdd_cleanup();
    zeroconf_cleanup();
    netif_cleanup();
    http_cleanup();
    rand_cleanup();
    eloop_cleanup();

    if (log_msg != NULL) {
        log_debug(NULL, "%s", log_msg);
    }

    conf_unload();
    trace_cleanup();
    log_cleanup(); /* Must be the last thing to do */
}

/* vim:ts=8:sw=4:et
 */
