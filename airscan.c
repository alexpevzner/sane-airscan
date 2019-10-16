/* AirScan (a.k.a. eSCL) backend for SANE
 *
 * Copyright (C) 2019 and up by Alexander Pevzner (pzz@apevzner.com)
 * See LICENSE for license terms and conditions
 */

#include <sane/sane.h>

#include <stdio.h>
#include <sys/time.h>

#include <avahi-client/client.h>
#include <avahi-client/lookup.h>
#include <avahi-common/error.h>
#include <avahi-glib/glib-watch.h>

#include <glib.h>

#include <libsoup/soup.h>

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

/******************** Device management ********************/
/* Device descriptor
 */
typedef struct {
    const char           *name;     /* Device name */
    AvahiServiceResolver *resolver; /* Service resolver; may be NULL */
    const char           *url;      /* eSCL base URL */
} device;

/* Static variables
 */
static GTree *device_table;

/* Forward declarations
 */
static void
device_destroy(device *device);

/* Print device-related debug message
 */
#define DEVICE_DEBUG(dev, fmt, args...) \
    DBG(1, "dev: \"%s\": " fmt "\n", dev->name, ##args)

/* Compare device names, for device_table
 */
static int
device_name_compare (gconstpointer a, gconstpointer b, gpointer userdata)
{
    (void) userdata;
    return strcmp((const char *) a, (const char*) b);
}

/* Initialize device management
 */
static SANE_Status
device_management_init (void)
{
    device_table = g_tree_new_full(device_name_compare, NULL, NULL,
            (GDestroyNotify) device_destroy);
    return SANE_STATUS_GOOD;
}

/* Cleanup device management
 */
static void
device_management_cleanup (void)
{
    if (device_table != NULL) {
        g_tree_unref(device_table);
        device_table = NULL;
    }
}

/* Create a device descriptor
 */
static device*
device_new (const char *name)
{
    device      *dev = g_new0(device, 1);

    dev->name = g_strdup(name);
    DEVICE_DEBUG(dev, "created");

    return dev;
}

/* Destroy a device descriptor
 */
static void
device_destroy (device *dev)
{
    DEVICE_DEBUG(dev, "destroyed");

    g_free((void*) dev->name);
    if (dev->resolver != NULL) {
        avahi_service_resolver_free(dev->resolver);
        dev->resolver = NULL;
    }
    g_free((void*) dev->url);
    g_free(dev);
}

/* Called when AVAHI resovler is done
 */
static void
device_resolver_done (device *dev, const AvahiAddress *addr, uint16_t port,
        AvahiStringList *txt)
{
    /* Build device API URL */
    AvahiStringList *rs = avahi_string_list_find(txt, "rs");
    const char *rs_text = NULL;
    if (rs != NULL && rs->size > 3) {
        rs_text = (const char*) rs->text + 3;
    }

    char str_addr[128];
    avahi_address_snprint(str_addr, sizeof(str_addr), addr);

    if (rs_text != NULL) {
        dev->url = g_strdup_printf("http://%s:%d/%s/", str_addr, port,
                rs_text);
    } else {
        dev->url = g_strdup_printf("http://%s:%d/", str_addr, port);
    }

    DEVICE_DEBUG(dev, "url=\"%s\"", dev->url);
}

/* Find device in a table
 */
static device*
device_find (const char *name)
{
    return g_tree_lookup(device_table, name);
}

/* Add device to device table
 */
static void
device_add (device *dev)
{
    g_tree_insert(device_table, (gpointer) dev->name, dev);
}

/* Del device from device table
 */
static void
device_del (const char *name)
{
    g_tree_remove(device_table, name);
}

/******************** GLIB integration ********************/
/* GLIB stuff
 */
static GThread *glib_thread;
static GMainContext *glib_main_context;
static GMainLoop *glib_main_loop;

/* Initialize GLIB integration
 */
static SANE_Status
glib_init (void)
{
    glib_main_context = g_main_context_new();
    glib_main_loop = g_main_loop_new(glib_main_context, TRUE);
    return SANE_STATUS_GOOD;
}

/* Cleanup GLIB integration
 */
static void
glib_cleanup (void)
{
    if (glib_main_context != NULL) {
        g_main_loop_unref(glib_main_loop);
        glib_main_loop = NULL;
        g_main_context_unref(glib_main_context);
        glib_main_context = NULL;
    }
}

/* GLIB thread main function
 */
static gpointer
glib_thread_func (gpointer data)
{
    g_main_context_push_thread_default(glib_main_context);
    g_main_loop_run(glib_main_loop);

    (void) data;
    return NULL;
}

/* Start GLIB thread. All background operations (AVAHI service discovery,
 * HTTP transfers) are performed on a context of this thread
 */
static void
glib_thread_start (void) {
    glib_thread = g_thread_new("airscan", glib_thread_func, NULL);
}

/* Stop GLIB thread
 */
static void
glib_thread_stop (void) {
    if (glib_thread != NULL) {
        g_main_loop_quit(glib_main_loop);
        g_thread_join(glib_thread);
        glib_thread = NULL;
    }
}

/******************** Device Discovery ********************/
/* AVAHI stuff
 */
static AvahiGLibPoll *dd_avahi_glib_poll;
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


/* Get current AVAHI error string
 */
static const char*
dd_avahi_strerror (void)
{
    return avahi_strerror(avahi_client_errno(dd_avahi_client));
}

/* Print DD-related debug message
 */
#define DD_DEBUG(name, fmt, args...)    \
        DBG(1, "discovery: \"%s\": " fmt "\n", name, ##args)

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
    (void) type;
    (void) domain;
    (void) host_name;
    (void) flags;

    device *dev = userdata;
    dev->resolver = NULL; /* Not owned by device anymore */

    switch (event) {
    case AVAHI_RESOLVER_FOUND:
        DD_DEBUG(name, "resolver: OK");
        device_resolver_done(dev, addr, port, txt);
        break;

    case AVAHI_RESOLVER_FAILURE:
        DD_DEBUG(name, "resolver: %s", dd_avahi_strerror());
        device_del(dev->name);
        break;
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
    (void) flags;
    (void) userdata;

    switch (event) {
    case AVAHI_BROWSER_NEW:
        DD_DEBUG(name, "found");

        /* Check for duplicate device */
        if (device_find (name) ) {
            DD_DEBUG(name, "already known; ignoring");
            break;
        }

        device *dev = device_new(name);

        /* Initiate desolver */
        AvahiServiceResolver *r;
        r = avahi_service_resolver_new(dd_avahi_client, interface, protocol,
                name, type, domain, AVAHI_PROTO_UNSPEC, 0,
                dd_avahi_resolver_callback, dev);

        if (r == NULL) {
            DD_DEBUG(name, "%s", dd_avahi_strerror());
            dd_avahi_client_restart_defer();
            break;
        }

        /* Add a device */
        dev->resolver = r;
        device_add(dev);

        break;

    case AVAHI_BROWSER_REMOVE:
        DD_DEBUG(name, "removed");
        device_del(name);
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
    dd_avahi_glib_poll = avahi_glib_poll_new(glib_main_context,
            G_PRIORITY_DEFAULT);
    if (dd_avahi_glib_poll == NULL) {
        return SANE_STATUS_NO_MEM;
    }

    dd_avahi_poll = avahi_glib_poll_get(dd_avahi_glib_poll);

    dd_avahi_restart_timer = dd_avahi_poll->timeout_new(dd_avahi_poll, NULL,
            dd_avahi_restart_timer_callback, NULL);
    if (dd_avahi_restart_timer == NULL) {
        return SANE_STATUS_NO_MEM;
    }

    dd_avahi_client_start();
    if (dd_avahi_client == NULL) {
        return SANE_STATUS_NO_MEM;
    }

    return SANE_STATUS_GOOD;
}

/* Cleanup device discovery
 */
static void
dd_cleanup (void)
{
    if (dd_avahi_glib_poll != NULL) {
        dd_avahi_browser_stop();
        dd_avahi_client_stop();

        if (dd_avahi_restart_timer != NULL) {
            dd_avahi_poll->timeout_free(dd_avahi_restart_timer);
            dd_avahi_restart_timer = NULL;
        }

        avahi_glib_poll_free(dd_avahi_glib_poll);
        dd_avahi_poll = NULL;
        dd_avahi_glib_poll = NULL;
    }
}

/******************** HTTP client ********************/
/* Initialize HTTP client
 */
static SANE_Status
http_init (void)
{
    return SANE_STATUS_GOOD;
}

/* Cleanup HTTP client
 */
static void
http_cleanup (void)
{
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

    /* Initialize all parts */
    status = glib_init();
    if (status == SANE_STATUS_GOOD) {
        status = dd_init();
    }
    if (status == SANE_STATUS_GOOD) {
        http_init();
    }
    if (status == SANE_STATUS_GOOD) {
        status = device_management_init();
    }

    if (status != SANE_STATUS_GOOD) {
        sane_exit();
    }

    /* Start airscan thread */
    glib_thread_start();

    return status;
}

/* Exit the backend
 */
void
sane_exit (void)
{
    glib_thread_stop();

    device_management_cleanup();
    http_cleanup();
    dd_cleanup();
    glib_cleanup();
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
