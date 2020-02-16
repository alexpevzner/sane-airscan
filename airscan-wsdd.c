/* AirScan (a.k.a. eSCL) backend for SANE
 *
 * Copyright (C) 2019 and up by Alexander Pevzner (pzz@apevzner.com)
 * See LICENSE for license terms and conditions
 *
 * Web Services Dynamic Discovery (WS-Discovery)
 */

#include "airscan.h"

#include <stdio.h>
#include <arpa/inet.h>

static netif_notifier *wsdd_netif_notifier;
static netif_addr     *wsdd_netif_addr_list;

/* Dump list of network interfaces addresses
 */
static void
wsdd_netif_dump_addresses (const char *prefix, netif_addr *list)
{
    char buf[128];

    while (list != NULL) {
        inet_ntop(list->ipv6 ? AF_INET6 : AF_INET, &list->ip, buf, sizeof(buf));
        if (list->ipv6 && list->linklocal) {
            char *s = buf + strlen(buf);
            sprintf(s, "%%%d", list->ifindex);
        }
        log_debug(NULL, "%s%s", prefix, buf);
        list = list->next;
    }
}

/* Update network interfaces addresses
 */
static void
wsdd_netif_update_addresses (void) {
    netif_addr *addr_list = netif_addr_get();
    netif_diff diff = netif_diff_compute(wsdd_netif_addr_list, addr_list);

    log_debug(NULL, "WSDD: netif addresses update:");
    wsdd_netif_dump_addresses(" + ", diff.added);
    wsdd_netif_dump_addresses(" - ", diff.removed);

    netif_addr_free(wsdd_netif_addr_list);
    wsdd_netif_addr_list = addr_list;
}

/* Network interfaces address change notification
 */
static void
wsdd_netif_notifier_callback (void *data)
{
    (void) data;

    log_debug(NULL, "WSDD: netif event");
    wsdd_netif_update_addresses();
}

/* eloop start/stop callback
 */
static void
wsdd_start_stop_callback (bool start)
{
    if (start) {
        wsdd_netif_update_addresses();
    }
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

    eloop_add_start_stop_callback(wsdd_start_stop_callback);

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

    netif_addr_free(wsdd_netif_addr_list);
}

/* vim:ts=8:sw=4:et
 */
