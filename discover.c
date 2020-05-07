/* Discovery tool for sane-airscan compatible devices
 *
 * Copyright (C) 2019 and up by Alexander Pevzner (pzz@apevzner.com)
 * See LICENSE for license terms and conditions
 */

#include "airscan.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>

/* Print usage and exit
 */
static void
usage (char **argv)
{
    printf("Usage:\n");
    printf("    %s [options]\n", argv[0]);
    printf("\n");
    printf("Options are:\n");
    printf("    -d   enable debug mode\n");
    printf("    -t   enable protocol trace\n");
    printf("    -h   print help page\n");

    exit(0);
}

/* Print usage error end exit
 */
static void
usage_error (char **argv, char *arg)
{
    printf("Invalid argument %s\n", arg);
    printf("Try %s -h for more information\n", argv[0]);

    exit(1);
}

/* Print error message and exit
 */
void
die (const char *format, ...)
{
    va_list ap;

    va_start(ap, format);
    vprintf(format, ap);
    printf("\n");
    va_end(ap);

    exit(1);
}

/* Initialize airscan
 */
static void
airscan_init (void)
{
    SANE_Status status;

    log_init();
    log_configure();
    trace_init();
    devid_init();
    eloop_init();
    status = rand_init();
    if (status != SANE_STATUS_GOOD) {
        die("rand-init: %s", sane_strstatus(status));
    }
    http_init();
    zeroconf_init();

    status = mdns_init();
    if (status != SANE_STATUS_GOOD) {
        die("DNS-SD: %s", sane_strstatus(status));
    }

    status = wsdd_init();
    if (status != SANE_STATUS_GOOD) {
        die("WS-Discovery: %s", sane_strstatus(status));
    }

    eloop_thread_start();
}

/* The main function
 */
int
main (int argc, char **argv)
{
    int               i;
    const SANE_Device **devices;

    /* Enforce some configuration parameters */
    conf.proto_auto = false;
    conf.wsdd_mode = WSDD_FULL;

    /* Parse command-line options */
    for (i = 1; i < argc; i ++) {
        if (!strcmp(argv[i], "-d")) {
            conf.dbg_enabled = true;
        } else if (!strcmp(argv[i], "-t")) {
            conf.dbg_trace = "./";
        } else if (!strcmp(argv[i], "-h")) {
            usage(argv);
        } else {
            usage_error(argv, argv[i]);
        }
    }

    /* Initialize airscan */
    airscan_init();

    /* Get list of devices */
    eloop_mutex_lock();
    devices = zeroconf_device_list_get();
    eloop_mutex_unlock();

    /* Print list of devices */
    printf("[devices]\n");
    for (i = 0; devices[i] != NULL; i ++) {
        const SANE_Device *dev = devices[i];
        zeroconf_devinfo  *devinfo = zeroconf_devinfo_lookup(dev->name);
        zeroconf_endpoint *endpoint;

        for (endpoint = devinfo->endpoints; endpoint != NULL;
             endpoint = endpoint->next) {
            printf("  %s = %s, %s\n", devinfo->name,
                http_uri_str(endpoint->uri), id_proto_name(endpoint->proto));
        }
    }

    return 0;
}

/* vim:ts=8:sw=4:et
 */
