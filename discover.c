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
            conf.dbg_trace = str_dup("./");
        } else if (!strcmp(argv[i], "-h")) {
            usage(argv);
        } else {
            usage_error(argv, argv[i]);
        }
    }

    /* Initialize airscan */
    airscan_init(AIRSCAN_INIT_NO_CONF, NULL);

    /* Get list of devices */
    eloop_mutex_lock();
    devices = zeroconf_device_list_get();
    eloop_mutex_unlock();

    /* Print list of devices */
    printf("[devices]\n");
    for (i = 0; devices[i] != NULL; i ++) {
        const SANE_Device *dev = devices[i];
        zeroconf_devinfo  *devinfo;
        zeroconf_endpoint *endpoint;

        eloop_mutex_lock();
        devinfo = zeroconf_devinfo_lookup(dev->name);
        eloop_mutex_unlock();

        for (endpoint = devinfo->endpoints; endpoint != NULL;
             endpoint = endpoint->next) {
            printf("  %s = %s, %s\n", devinfo->name,
                http_uri_str(endpoint->uri), id_proto_name(endpoint->proto));
        }
    }

    zeroconf_device_list_free(devices);

    eloop_thread_stop();
    airscan_cleanup(NULL);

    return 0;
}

/* vim:ts=8:sw=4:et
 */
