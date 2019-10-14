/* AirScan (a.k.a. eSCL) backend for SANE
 *
 * Copyright (C) 2019 and up by Alexander Pevzner (pzz@apevzner.com)
 * See LICENSE for license terms and conditions
 */

#define _GNU_SOURCE

#include <sane/sane.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#include <avahi-client/client.h>
#include <avahi-client/lookup.h>

#include <avahi-common/thread-watch.h>
#include <avahi-common/malloc.h>
#include <avahi-common/error.h>

#include <curl/curl.h>

/******************** Constants *********************/
/* Service type to look for
 */
#define AIRSCAN_ZEROCONF_SERVICE_TYPE           "_uscan._tcp"

/* If failed, AVAHI client will be automatically
 * restarted after the following timeout expires,
 * in seconds
 */
#define AIRSCAN_AVAHI_CLIENT_RESTART_TIMEOUT    1

/******************** Debugging ********************/
#define DBG(level, msg, args...)        printf(msg, ##args)

/******************** Static variables ********************/
/* List of devices
 */
static SANE_Device **airprint_device_list = NULL;

/******************** Memory buffers ********************/
/* Initial buffer size
 */
#define BUF_INITIAL_SIZE        4096

/* The growable memory buffer
 */
typedef struct {
    void   *data;     /* Buffered data */
    size_t size;      /* Data's size */
    size_t allocated; /* Amount of actually allocated bytes */
} buf;

/* Create new buffer
 */
static buf*
buf_new (void)
{
    buf *b = (buf*) calloc(sizeof(buf), 1);
    if (b != NULL) {
        b->data = calloc(BUF_INITIAL_SIZE, 1);
        if (b->data != NULL) {
            b->allocated = BUF_INITIAL_SIZE;
            return b;
        }
        free(b);
    }
    return NULL;
}

/* Destroy the buffer
 */
static void
buf_destroy (buf *b)
{
    free(b->data);
    free(b);
}

/* Get buffer's data
 */
static inline const void*
buf_data (buf *b)
{
    return b->data;
}

/* Get buffer's size
 */
static inline size_t
buf_size (buf *b)
{
    return b->size;
}

/* Write some data to the buffer. In a case of allocation
 * error, may write less bytes that requested
 */
static size_t
buf_write (buf *b, const void *data, size_t size)
{
    size_t allocated = b->allocated;
    size_t needed = b->size + size;

    if (needed < b->size) {
        return 0; /* Counter overflow */
    }

    while (allocated < needed) {
        allocated += allocated;
        if (allocated < b->allocated) {
            return 0; /* Counter overflow */
        }
    }

    void *p = realloc(b->data, allocated);
    if (p == NULL) {
        return 0; /* OOM */
    }

    b->data = p;
    memcpy(b->size + (char*) b->data, data, size);
    b->size = needed;
    b->allocated = allocated;

    return size;
}

/******************** Device management ********************/
/* Device descriptor
 */
typedef struct {
    const char *name;      /* Device name */
    const char *host_name; /* Host name */
    const char *url;       /* eSCL base URL */
} airscan_device;

/* Forward declarations
 */
static void
airscan_device_destroy(airscan_device *device);

/* Create a device descriptor
 */
static airscan_device*
airscan_device_new (const char *name, const char *host_name,
        const AvahiAddress *addr, uint16_t port,
        AvahiStringList *txt)
{
    airscan_device      *device = calloc(sizeof(airscan_device), 1);

    /* Copy relevant data from AVAHI buffers to device */
    device->name = strdup(name);
    if (device->name == NULL) {
        goto FAIL;
    }

    device->host_name = strdup(host_name);
    if (device->host_name == NULL) {
        goto FAIL;
    }

    /* Build device API URL */
    AvahiStringList *rs = avahi_string_list_find(txt, "rs");
    const char *rs_text = NULL;
    if (rs != NULL && rs->size > 3) {
        rs_text = (const char*) rs->text + 3;
    }

    char *url;
    char str_addr[128];
    avahi_address_snprint(str_addr, sizeof(str_addr), addr);

    if (rs_text != NULL) {
        asprintf(&url, "http://%s:%d/%s/", str_addr, port, rs_text);
    } else {
        asprintf(&url, "http://%s:%d/", str_addr, port);
    }

    if (url == NULL) {
        goto FAIL;
    }

    device->url = url;

    return device;

FAIL:
    if (device) {
        airscan_device_destroy(device);
    }
    return NULL;
}

/* Destroy a device descriptor
 */
static void
airscan_device_destroy(airscan_device *device)
{
    free((void*) device->name);
    free((void*) device->host_name);
    free((void*) device->url);
}

/******************** Device Discovery ********************/
/* AVAHI stuff
 */
static AvahiThreadedPoll *dd_avahi_threaded_poll;
static const AvahiPoll *dd_avahi_poll;
static AvahiTimeout *dd_avahi_restart_timer;
static AvahiClient *dd_avahi_client;
static AvahiServiceBrowser *dd_avahi_browser;

/* Forward declarations
 */
static void
dd_cleanup (void);

static void
dd_avahi_browser_stop (void);

static void
dd_avahi_client_start (void);

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

        airscan_device *dev = airscan_device_new(name, host_name,
                addr, port, txt);

        DBG(1, "url=%s\n", dev->url);
        airscan_device_destroy(dev);
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

/* Timer for differed AVAHI client restart
 */
static void
dd_avahi_restart_timer_callback(AvahiTimeout *t, void *userdata)
{
    (void) t;
    (void) userdata;

    DBG(1,"TIMER\n");
    dd_avahi_client_start();
}

/* Stop AVAHI client
 */
static void
dd_avahi_client_stop (void)
{
    if (dd_avahi_client != NULL) {
        avahi_client_free(dd_avahi_client);
        dd_avahi_client = NULL;
    }
}

/* Start/restart the AVAHI client
 */
static void
dd_avahi_client_start (void)
{
    int error;

    dd_avahi_client_stop();

    dd_avahi_client = avahi_client_new (dd_avahi_poll, AVAHI_CLIENT_NO_FAIL,
        dd_avahi_client_callback, NULL, &error);
}

/* Deferred client restart
 */
static void
dd_avahi_client_restart_defer (void)
{
        struct timeval tv;

        dd_avahi_browser_stop();
        dd_avahi_client_stop();

        gettimeofday(&tv, NULL);
        tv.tv_sec += AIRSCAN_AVAHI_CLIENT_RESTART_TIMEOUT;
        dd_avahi_poll->timeout_update(dd_avahi_restart_timer, &tv);
}

/* Initialize device discovery
 */
static SANE_Status
dd_init (void)
{
    dd_avahi_threaded_poll = avahi_threaded_poll_new();
    if (dd_avahi_threaded_poll == NULL) {
        return SANE_STATUS_NO_MEM;
    }

    dd_avahi_poll = avahi_threaded_poll_get(dd_avahi_threaded_poll);

    dd_avahi_restart_timer = dd_avahi_poll->timeout_new(dd_avahi_poll, NULL,
            dd_avahi_restart_timer_callback, NULL);
    if (dd_avahi_restart_timer == NULL) {
        return SANE_STATUS_NO_MEM;
    }

    dd_avahi_client_start();
    if (dd_avahi_client == NULL) {
        return SANE_STATUS_NO_MEM;
    }

    if (avahi_threaded_poll_start (dd_avahi_threaded_poll) < 0) {
        return SANE_STATUS_NO_MEM;
    }

    return SANE_STATUS_GOOD;
}

/* Cleanup device discovery
 */
static void
dd_cleanup (void)
{
    if (dd_avahi_threaded_poll != NULL) {
        avahi_threaded_poll_stop(dd_avahi_threaded_poll);

        dd_avahi_browser_stop();
        dd_avahi_client_stop();

        if (dd_avahi_restart_timer != NULL) {
            dd_avahi_poll->timeout_free(dd_avahi_restart_timer);
            dd_avahi_restart_timer = NULL;
        }

        avahi_threaded_poll_free(dd_avahi_threaded_poll);
        dd_avahi_poll = NULL;
        dd_avahi_threaded_poll = NULL;
    }
}

/******************** HTTP client ********************/
/* LibCURL stuff
 */
static CURL *http_curl_multi;

/* Initialize HTTP client
 */
static SANE_Status
http_init (void)
{
    http_curl_multi = curl_multi_init();
    if (http_curl_multi == NULL) {
        return SANE_STATUS_NO_MEM;
    }
    return SANE_STATUS_GOOD;
}

/* Cleanup HTTP client
 */
static void
http_cleanup (void)
{
    if (http_curl_multi != NULL) {
        curl_multi_cleanup(http_curl_multi);
        http_curl_multi = NULL;
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
    if (status == SANE_STATUS_GOOD) {
        http_init();
    }

    if (status != SANE_STATUS_GOOD) {
        sane_exit();
    }

    return status;
}

/* Exit the backend
 */
void
sane_exit (void)
{
    (void) buf_new;
    (void) buf_destroy;
    (void) buf_write;

    http_cleanup();
    dd_cleanup();
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
