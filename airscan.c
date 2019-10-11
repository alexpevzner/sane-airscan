/* AirScan (a.k.a. eSCL) backend for SANE
 *
 * Copyright (C) 2019 and up by Alexander Pevzner (pzz@apevzner.com)
 * See LICENSE for license terms and conditions
 */

#include <sane/sane.h>

#include <stdio.h>

#include <avahi-client/client.h>
#include <avahi-client/lookup.h>

#include <avahi-common/thread-watch.h>
#include <avahi-common/malloc.h>
#include <avahi-common/error.h>

/******************** Constants *********************/
/* Service type to look for
 */
#define AIRSCAN_ZEROCONF_SERVICE_TYPE   "_uscan._tcp"

/******************** Debugging ********************/
#define DBG(level, msg, args...)        printf(msg, ##args)

/******************** Static variables ********************/
/* List of devices
 */
static SANE_Device **airprint_device_list = NULL;

/******************** Device Discovery  ********************/
/* AVAHI stuff
 */
static AvahiThreadedPoll *dd_avahi_threaded_poll;
static AvahiClient *dd_avahi_client;
static AvahiServiceBrowser *dd_avahi_browser;

/* Forward declarations
 */
static void
dd_exit (void);

static void
dd_avahi_browser_stop (void);

static void
dd_avahi_client_stop (void);

static void
dd_avahi_client_restart_defer (void);

/* AVAHI service resolver callback
 */
static void
dd_avahi_resolver_callback (AvahiServiceResolver *r, AvahiIfIndex interface,
        AvahiProtocol protocol, AvahiResolverEvent event,
        const char *name, const char *type, const char *domain,
        const char *host_name, const AvahiAddress *addr, uint16_t port,
        AvahiStringList *txt, AvahiLookupResultFlags flags, void *userdata)
{
    (void) interface;
    (void) protocol;
    (void) name;
    (void) type;
    (void) domain;
    (void) host_name;
    (void) addr;
    (void) port;
    (void) txt;
    (void) flags;
    (void) userdata;

    if (event == AVAHI_RESOLVER_FOUND) {
        DBG(1, "resolver: name=%s, type=%s domain=%s\n", name, type, domain);
        DBG(1, "host_name=%s\n", host_name);
        char buf[128];
        DBG(1, "addr=%s\n", avahi_address_snprint(buf, sizeof(buf), addr));
        DBG(1, "port=%d\n", port);

        AvahiStringList *t;
        for (t = txt; t; t = t->next) {
            DBG(1, "  TXT: %*s\n", (int) t->size, t->text);
        }
    }

    avahi_service_resolver_free(r);
}

/* AVAHI browser callback
 */
static void
dd_avahi_browser_callback (AvahiServiceBrowser *b, AvahiIfIndex interface,
        AvahiProtocol protocol, AvahiBrowserEvent event,
        const char *name, const char *type, const char *domain,
        AvahiLookupResultFlags flags, void* userdata)
{
    (void) b;
    (void) interface;
    (void) protocol;
    (void) name;
    (void) type;
    (void) domain;
    (void) flags;
    (void) userdata;

DBG(1,"browser event=%d\n", event);

    switch (event) {
    case AVAHI_BROWSER_NEW:
        DBG(1, "name=%s type=%s domain=%s\n", name, type, domain);

        AvahiServiceResolver *r;
        r = avahi_service_resolver_new(dd_avahi_client, interface, protocol,
                name, type, domain, AVAHI_PROTO_UNSPEC, 0,
                dd_avahi_resolver_callback, NULL);

        if (r == NULL) {
            dd_avahi_client_restart_defer();
        }

        break;

    case AVAHI_BROWSER_REMOVE:
        break;

    case AVAHI_BROWSER_FAILURE:
        dd_avahi_client_restart_defer();
        break;

    case AVAHI_BROWSER_CACHE_EXHAUSTED:
    case AVAHI_BROWSER_ALL_FOR_NOW:
        break;
    }
}

/* Start/restart service browser
 */
static void
dd_avahi_browser_start (AvahiClient *client)
{
    dd_avahi_browser_stop();

    dd_avahi_browser = avahi_service_browser_new(client,
            AVAHI_IF_UNSPEC, AVAHI_PROTO_UNSPEC,
            AIRSCAN_ZEROCONF_SERVICE_TYPE, NULL,
            0, dd_avahi_browser_callback, client);

DBG(1,"browser=%p\n", dd_avahi_browser);
}

/* Stop service browser
 */
static void
dd_avahi_browser_stop (void)
{
    if (dd_avahi_browser != NULL) {
        avahi_service_browser_free(dd_avahi_browser);
        dd_avahi_browser = NULL;
    }
}

/* AVAHI client callback
 */
static void
dd_avahi_client_callback (AvahiClient *client, AvahiClientState state,
        void *userdata)
{
    (void) userdata;

    switch (state) {
    case AVAHI_CLIENT_S_REGISTERING:
    case AVAHI_CLIENT_S_RUNNING:
    case AVAHI_CLIENT_S_COLLISION:
        if (dd_avahi_browser == NULL) {
            dd_avahi_browser_start(client);
            if (dd_avahi_browser == NULL) {
                dd_avahi_client_restart_defer();
            }
        }
        break;

    case AVAHI_CLIENT_FAILURE:
        dd_avahi_client_restart_defer();
        break;

    case AVAHI_CLIENT_CONNECTING:
        break;
    }
}

/* Stop AVAHI client
 */
static void
dd_avahi_client_start (void)
{
    if (dd_avahi_client != NULL) {
        avahi_client_free(dd_avahi_client);
        dd_avahi_client = NULL;
    }
}

/* Start/restart the AVAHI client
 */
static void
dd_avahi_client_stop (void)
{
    int error;
    const AvahiPoll *poll = avahi_threaded_poll_get (dd_avahi_threaded_poll);

    dd_avahi_client_start();

    dd_avahi_client = avahi_client_new (poll, AVAHI_CLIENT_NO_FAIL,
        dd_avahi_client_callback, NULL, &error);
}

/* Deferred client restart
 */
static void
dd_avahi_client_restart_defer (void)
{
        dd_avahi_browser_stop();
        dd_avahi_client_stop();
        if (dd_avahi_client == NULL) {
            // FIXME
        }
}

/* Initialize device discovery
 */
static SANE_Status
dd_init (void)
{
    dd_avahi_threaded_poll = avahi_threaded_poll_new();
    if (dd_avahi_threaded_poll == NULL) {
        goto FAIL;
    }

    dd_avahi_client_stop();
    if (dd_avahi_client == NULL) {
        goto FAIL;
    }

    if (avahi_threaded_poll_start (dd_avahi_threaded_poll) < 0) {
        goto FAIL;
    }

    return SANE_STATUS_GOOD;

FAIL:
    dd_exit();
    return SANE_STATUS_NO_MEM;
}

/* Exit device discovery
 */
static void
dd_exit (void)
{
    if (dd_avahi_threaded_poll != NULL) {
        avahi_threaded_poll_stop(dd_avahi_threaded_poll);

        if (dd_avahi_browser != NULL) {
            avahi_service_browser_free(dd_avahi_browser);
            dd_avahi_browser = NULL;
        }

        dd_avahi_client_start();

        avahi_threaded_poll_free(dd_avahi_threaded_poll);
        dd_avahi_threaded_poll = NULL;
    }
}

/******************** SANE API ********************/
/* Initialize the backend
 */
SANE_Status
sane_init (SANE_Int *version_code, SANE_Auth_Callback authorize)
{
    SANE_Status status;

    (void) version_code;
    (void) authorize;

    status = dd_init();

    return status;
}

/* Exit the backend
 */
void
sane_exit (void) {
}

/* Get list of devices
 */
SANE_Status
sane_get_devices (const SANE_Device ***device_list, SANE_Bool local_only)
{
    (void) local_only;

    *device_list = (const SANE_Device **) airprint_device_list;

    return SANE_STATUS_GOOD;
}

/* Open the device
 */
SANE_Status
sane_open (SANE_String_Const devicename, SANE_Handle *handle)
{
    (void) devicename;
    (void) handle;

    return SANE_STATUS_INVAL;
}

/* Close the device
 */
void
sane_close (SANE_Handle handle)
{
    (void) handle;
}

/* Get option descriptor
 */
const SANE_Option_Descriptor *
sane_get_option_descriptor (SANE_Handle handle, SANE_Int option)
{
    (void) handle;
    (void) option;

    return NULL;
}

/* Get or set option value
 */
SANE_Status
sane_control_option (SANE_Handle handle, SANE_Int option, SANE_Action action,
                     void *value, SANE_Int *info)
{
    (void) handle;
    (void) option;
    (void) action;
    (void) value;
    (void) info;

    return SANE_STATUS_UNSUPPORTED;
}

/* Get current scan parameters
 */
SANE_Status
sane_get_parameters (SANE_Handle handle, SANE_Parameters *params)
{
    (void) handle;
    (void) params;

    return SANE_STATUS_INVAL;
}

/* Start scanning operation
 */
SANE_Status
sane_start (SANE_Handle handle)
{
    (void) handle;

    return SANE_STATUS_INVAL;
}

/* Read scanned image
 */
SANE_Status
sane_read (SANE_Handle handle, SANE_Byte *data,
           SANE_Int max_length, SANE_Int *length)
{
    (void) handle;
    (void) data;
    (void) max_length;
    (void) length;

    return SANE_STATUS_INVAL;
}

/* Cancel scanning operation
 */
void
sane_cancel (SANE_Handle handle)
{
    (void) handle;
}

/* Set I/O mode
 */
SANE_Status
sane_set_io_mode (SANE_Handle handle, SANE_Bool non_blocking)
{
    (void) handle;
    (void) non_blocking;

    return SANE_STATUS_GOOD;
}

/* Get select file descriptor
 */
SANE_Status
sane_get_select_fd (SANE_Handle handle, SANE_Int * fd)
{
    (void) handle;

    *fd = -1;
    return SANE_STATUS_UNSUPPORTED;
}

/* vim:ts=8:sw=4:et
 */
