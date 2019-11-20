/* AirScan (a.k.a. eSCL) backend for SANE
 *
 * Copyright (C) 2019 and up by Alexander Pevzner (pzz@apevzner.com)
 * See LICENSE for license terms and conditions
 *
 * Device management
 */

#include "airscan.h"

/******************** Constants *********************/
/* Max time to wait until device table is ready, in seconds
 */
#define DEVICE_TABLE_READY_TIMEOUT              5

/* Default resolution, DPI
 */
#define DEVICE_DEFAULT_RESOLUTION               300

/* How often to poll for scanner state change, in seconds
 */
#define DEVICE_SCAN_STATE_POLL_INTERVAL         1

/******************** Device management ********************/
/* Device flags
 */
enum {
    DEVICE_LISTED           = (1 << 0), /* Device listed in device_table */
    DEVICE_READY            = (1 << 2), /* Device is ready */
    DEVICE_HALTED           = (1 << 3), /* Device is halted */
    DEVICE_INIT_WAIT        = (1 << 4), /* Device was found during initial
                                           scan and not ready yet */
    DEVICE_OPENED           = (1 << 5), /* Device currently opened */
    DEVICE_ALL_FLAGS        = 0xffffffff
};

/* Scan states
 */
typedef enum {
    DEVICE_JOB_IDLE,
    DEVICE_JOB_STARTED,
    DEVICE_JOB_CHECK_STATUS,
    DEVICE_JOB_REQUESTING,
    DEVICE_JOB_LOADING,
    DEVICE_JOB_CLEANING_UP,

    DEVICE_JOB_DONE

} DEVICE_JOB_STATE;

/* Device descriptor
 */
struct device {
    /* Common part */
    volatile gint        refcnt;        /* Reference counter */
    const char           *name;         /* Device name */
    unsigned int         flags;         /* Device flags */
    devcaps              caps;          /* Device capabilities */

    /* I/O handling (AVAHI and HTTP) */
    zeroconf_addrinfo    *addresses;    /* Device addresses, NULL if
                                           device was statically added */
    zeroconf_addrinfo    *addr_current; /* Current address to probe */
    SoupURI              *uri_escl;     /* eSCL base URI */
    SoupMessage          *http_pending; /* Pending HTTP requests, NULL if none */
    trace                *trace;        /* Protocol trace */

    /* Scanning state machinery */
    DEVICE_JOB_STATE     job_state;         /* Scan job state */
    SANE_Status          job_status;        /* Job completion status */
    GString              *job_location;     /* Scanned page location */
    GPtrArray            *job_images;       /* Array of SoupBuffer* */
    eloop_event          *job_cancel_event; /* Cancel event */
    bool                 job_cancel_rq;     /* Cancel requested */
    GCond                job_state_cond;    /* Signaled when state changed */

    /* Options */
    SANE_Option_Descriptor opt_desc[NUM_OPTIONS]; /* Option descriptors */
    OPT_SOURCE             opt_src;               /* Current source */
    OPT_COLORMODE          opt_colormode;         /* Color mode */
    SANE_Word              opt_resolution;        /* Current resolution */
    SANE_Word              opt_tl_x, opt_tl_y;    /* Top-left x/y */
    SANE_Word              opt_br_x, opt_br_y;    /* Bottom-right x/y */
};

/* Static variables
 */
static GTree *device_table;
static GCond device_table_cond;

static SoupSession *device_http_session;

/* Forward declarations
 */
static void
device_add_static (const char *name, SoupURI *uri);

static void
device_scanner_capabilities_callback (device *dev, SoupMessage *msg);

static void
device_http_get (device *dev, const char *path,
        void (*callback)(device*, SoupMessage*));

static void
device_http_cancel (device *dev);

static void
device_job_set_state (device *dev, DEVICE_JOB_STATE state);

static void
device_job_set_status (device *dev, SANE_Status status);

static void
device_table_purge (void);

static void
device_escl_load_page (device *dev);

/* Compare device names, for device_table
 */
static int
device_name_compare (gconstpointer a, gconstpointer b, gpointer userdata)
{
    (void) userdata;
    return strcmp((const char *) a, (const char*) b);
}

/* Add device to the table
 */
static device*
device_add (const char *name)
{
    /* Create device */
    device      *dev = g_new0(device, 1);

    dev->refcnt = 1;
    dev->name = g_strdup(name);
    dev->flags = DEVICE_LISTED;
    devcaps_init(&dev->caps);

    dev->trace = trace_open(name);

    dev->job_location = g_string_new(NULL);
    dev->job_images = g_ptr_array_new();
    g_cond_init(&dev->job_state_cond);

    dev->opt_src = OPT_SOURCE_UNKNOWN;
    dev->opt_colormode = OPT_COLORMODE_UNKNOWN;
    dev->opt_resolution = DEVICE_DEFAULT_RESOLUTION;

    DBG_DEVICE(dev->name, "created");

    /* Add to the table */
    g_tree_insert(device_table, (gpointer) dev->name, dev);

    return dev;
}

/* Ref the device
 */
static inline device*
device_ref (device *dev)
{
    g_atomic_int_inc(&dev->refcnt);
    return dev;
}

/* Unref the device
 */
static inline void
device_unref (device *dev)
{
    if (g_atomic_int_dec_and_test(&dev->refcnt)) {
        DBG_DEVICE(dev->name, "destroyed");
        g_assert((dev->flags & DEVICE_LISTED) == 0);
        g_assert((dev->flags & DEVICE_HALTED) != 0);
        g_assert((dev->flags & DEVICE_OPENED) == 0);
        g_assert(dev->http_pending == NULL);

        /* Release all memory */
        g_free((void*) dev->name);

        devcaps_cleanup(&dev->caps);

        zeroconf_addrinfo_list_free(dev->addresses);

        if (dev->uri_escl != NULL) {
            soup_uri_free(dev->uri_escl);
        }

        g_string_free(dev->job_location, TRUE);
        g_ptr_array_free(dev->job_images, TRUE);
        g_cond_clear(&dev->job_state_cond);

        g_free(dev);
    }
}

/* Del device from the table. It implicitly halts all
 * pending I/O activity
 *
 * Note, reference to the device may still exist (device
 * may be opened), so memory can be freed later, when
 * device is not used anymore
 */
static void
device_del (device *dev)
{
    /* Remove device from table */
    DBG_DEVICE(dev->name, "removed from device table");
    g_assert((dev->flags & DEVICE_LISTED) != 0);

    dev->flags &= ~DEVICE_LISTED;
    g_tree_remove(device_table, dev->name);

    /* Stop all pending I/O activity */
    device_http_cancel(dev);
    trace_close(dev->trace);
    dev->trace = NULL;

    dev->flags |= DEVICE_HALTED;
    dev->flags &= ~DEVICE_READY;

    /* Unref the device */
    device_unref(dev);
}

/* Find device in a table
 */
static device*
device_find (const char *name)
{
    return g_tree_lookup(device_table, name);
}

/* Add statically configured device
 */
static void
device_add_static (const char *name, SoupURI *uri)
{
    /* Don't allow duplicate devices */
    device *dev = device_find(name);
    if (dev != NULL) {
        DBG_DEVICE(name, "device already exist");
        return;
    }

    /* Add a device */
    dev = device_add(name);
    dev->flags |= DEVICE_INIT_WAIT;
    dev->uri_escl = soup_uri_copy(uri);

    /* Make sure eSCL URI's path ends with '/' character */
    const char *path = soup_uri_get_path(dev->uri_escl);
    if (!g_str_has_suffix(path, "/")) {
        size_t len = strlen(path);
        char *path2 = g_alloca(len + 2);
        memcpy(path2, path, len);
        path2[len] = '/';
        path2[len+1] = '\0';
        soup_uri_set_path(dev->uri_escl, path2);
    }

    /* Fetch device capabilities */
    device_http_get(dev, "ScannerCapabilities",
            device_scanner_capabilities_callback);
}

/* Probe next device address
 */
static void
device_probe_address (device *dev, zeroconf_addrinfo *addrinfo)
{
    /* Cleanup after previous probe */
    dev->addr_current = addrinfo;
    if (dev->uri_escl != NULL) {
        soup_uri_free(dev->uri_escl);
    }

    /* Build device API URL */
    char str_addr[128], *url;

    if (addrinfo->addr.proto == AVAHI_PROTO_INET) {
        avahi_address_snprint(str_addr, sizeof(str_addr), &addrinfo->addr);
    } else {
        str_addr[0] = '[';
        avahi_address_snprint(str_addr + 1, sizeof(str_addr) - 2,
            &addrinfo->addr);
        size_t l = strlen(str_addr);

        /* Connect to link-local address requires explicit scope */
        if (addrinfo->linklocal) {
            /* Percent character in the IPv6 address literal
             * needs to be properly escaped, so it becomes %25
             * See RFC6874 for details
             */
            l += sprintf(str_addr + l, "%%25%d", addrinfo->interface);
        }

        str_addr[l++] = ']';
        str_addr[l] = '\0';
    }

    if (addrinfo->rs != NULL) {
        url = g_strdup_printf("http://%s:%d/%s/", str_addr, addrinfo->port,
                addrinfo->rs);
    } else {
        url = g_strdup_printf("http://%s:%d/", str_addr, addrinfo->port);
    }

    dev->uri_escl = soup_uri_new(url);
    g_assert(dev->uri_escl != NULL);
    DBG_DEVICE(dev->name, "url=\"%s\"", url);

    /* Fetch device capabilities */
    device_http_get(dev, "ScannerCapabilities",
            device_scanner_capabilities_callback);
}

/* Rebuild option descriptors
 */
static void
device_rebuild_opt_desc (device *dev)
{
    SANE_Option_Descriptor *desc;
    devcaps_source         *src = dev->caps.src[dev->opt_src];

    memset(dev->opt_desc, 0, sizeof(dev->opt_desc));

    /* OPT_NUM_OPTIONS */
    desc = &dev->opt_desc[OPT_NUM_OPTIONS];
    desc->name = SANE_NAME_NUM_OPTIONS;
    desc->title = SANE_TITLE_NUM_OPTIONS;
    desc->desc = SANE_DESC_NUM_OPTIONS;
    desc->type = SANE_TYPE_INT;
    desc->size = sizeof(SANE_Word);
    desc->cap = SANE_CAP_SOFT_DETECT;

    /* OPT_GROUP_STANDARD */
    desc = &dev->opt_desc[OPT_GROUP_STANDARD];
    desc->name = SANE_NAME_STANDARD;
    desc->title = SANE_TITLE_STANDARD;
    desc->desc = SANE_DESC_STANDARD;
    desc->type = SANE_TYPE_GROUP;
    desc->cap = 0;

    /* OPT_SCAN_RESOLUTION */
    desc = &dev->opt_desc[OPT_SCAN_RESOLUTION];
    desc->name = SANE_NAME_SCAN_RESOLUTION;
    desc->title = SANE_TITLE_SCAN_RESOLUTION;
    desc->desc = SANE_DESC_SCAN_RESOLUTION;
    desc->type = SANE_TYPE_INT;
    desc->size = sizeof(SANE_Word);
    desc->cap = SANE_CAP_SOFT_SELECT | SANE_CAP_SOFT_DETECT;
    desc->unit = SANE_UNIT_DPI;
    if ((src->flags & DEVCAPS_SOURCE_RES_DISCRETE) != 0) {
        desc->constraint_type = SANE_CONSTRAINT_WORD_LIST;
        desc->constraint.word_list = src->resolutions;
    } else {
        desc->constraint_type = SANE_CONSTRAINT_RANGE;
        desc->constraint.range = &src->res_range;
    }

    /* OPT_SCAN_MODE */
    desc = &dev->opt_desc[OPT_SCAN_COLORMODE];
    desc->name = SANE_NAME_SCAN_MODE;
    desc->title = SANE_TITLE_SCAN_MODE;
    desc->desc = SANE_DESC_SCAN_MODE;
    desc->type = SANE_TYPE_STRING;
    desc->size = array_of_string_max_strlen(&src->sane_colormodes) + 1;
    desc->cap = SANE_CAP_SOFT_SELECT | SANE_CAP_SOFT_DETECT;
    desc->constraint_type = SANE_CONSTRAINT_STRING_LIST;
    desc->constraint.string_list = (SANE_String_Const*) src->sane_colormodes;

    /* OPT_SCAN_SOURCE */
    desc = &dev->opt_desc[OPT_SCAN_SOURCE];
    desc->name = SANE_NAME_SCAN_SOURCE;
    desc->title = SANE_TITLE_SCAN_SOURCE;
    desc->desc = SANE_DESC_SCAN_SOURCE;
    desc->type = SANE_TYPE_STRING;
    desc->size = array_of_string_max_strlen(&dev->caps.sane_sources) + 1;
    desc->cap = SANE_CAP_SOFT_SELECT | SANE_CAP_SOFT_DETECT;
    desc->constraint_type = SANE_CONSTRAINT_STRING_LIST;
    desc->constraint.string_list = (SANE_String_Const*) dev->caps.sane_sources;

    /* OPT_GROUP_GEOMETRY */
    desc = &dev->opt_desc[OPT_GROUP_GEOMETRY];
    desc->name = SANE_NAME_GEOMETRY;
    desc->title = SANE_TITLE_GEOMETRY;
    desc->desc = SANE_DESC_GEOMETRY;
    desc->type = SANE_TYPE_GROUP;
    desc->cap = 0;

    /* OPT_SCAN_TL_X */
    desc = &dev->opt_desc[OPT_SCAN_TL_X];
    desc->name = SANE_NAME_SCAN_TL_X;
    desc->title = SANE_TITLE_SCAN_TL_X;
    desc->desc = SANE_DESC_SCAN_TL_X;
    desc->type = SANE_TYPE_FIXED;
    desc->size = sizeof(SANE_Word);
    desc->cap = SANE_CAP_SOFT_SELECT | SANE_CAP_SOFT_DETECT;
    desc->unit = SANE_UNIT_MM;
    desc->constraint_type = SANE_CONSTRAINT_RANGE;
    desc->constraint.range = &src->win_x_range;

    /* OPT_SCAN_TL_Y */
    desc = &dev->opt_desc[OPT_SCAN_TL_Y];
    desc->name = SANE_NAME_SCAN_TL_Y;
    desc->title = SANE_TITLE_SCAN_TL_Y;
    desc->desc = SANE_DESC_SCAN_TL_Y;
    desc->type = SANE_TYPE_FIXED;
    desc->size = sizeof(SANE_Word);
    desc->cap = SANE_CAP_SOFT_SELECT | SANE_CAP_SOFT_DETECT;
    desc->unit = SANE_UNIT_MM;
    desc->constraint_type = SANE_CONSTRAINT_RANGE;
    desc->constraint.range = &src->win_y_range;

    /* OPT_SCAN_BR_X */
    desc = &dev->opt_desc[OPT_SCAN_BR_X];
    desc->name = SANE_NAME_SCAN_BR_X;
    desc->title = SANE_TITLE_SCAN_BR_X;
    desc->desc = SANE_DESC_SCAN_BR_X;
    desc->type = SANE_TYPE_FIXED;
    desc->size = sizeof(SANE_Word);
    desc->cap = SANE_CAP_SOFT_SELECT | SANE_CAP_SOFT_DETECT;
    desc->unit = SANE_UNIT_MM;
    desc->constraint_type = SANE_CONSTRAINT_RANGE;
    desc->constraint.range = &src->win_x_range;

    /* OPT_SCAN_BR_Y */
    desc = &dev->opt_desc[OPT_SCAN_BR_Y];
    desc->name = SANE_NAME_SCAN_BR_Y;
    desc->title = SANE_TITLE_SCAN_BR_Y;
    desc->desc = SANE_DESC_SCAN_BR_Y;
    desc->type = SANE_TYPE_FIXED;
    desc->size = sizeof(SANE_Word);
    desc->cap = SANE_CAP_SOFT_SELECT | SANE_CAP_SOFT_DETECT;
    desc->unit = SANE_UNIT_MM;
    desc->constraint_type = SANE_CONSTRAINT_RANGE;
    desc->constraint.range = &src->win_y_range;
}

/* Set current resolution
 */
static SANE_Status
device_set_resolution (device *dev, SANE_Word opt_resolution, SANE_Word *info)
{
    devcaps_source *src = dev->caps.src[dev->opt_src];

    if (dev->opt_resolution == opt_resolution) {
        return SANE_STATUS_GOOD;
    }

    dev->opt_resolution = devcaps_source_choose_colormode(src, opt_resolution);

    *info |= SANE_INFO_RELOAD_PARAMS;
    if (dev->opt_resolution != opt_resolution) {
        *info |= SANE_INFO_INEXACT;
    }

    return SANE_STATUS_GOOD;
}

/* Set color mode
 */
static SANE_Status
device_set_colormode (device *dev, OPT_COLORMODE opt_colormode, SANE_Word *info)
{
    devcaps_source *src = dev->caps.src[dev->opt_src];

    if (dev->opt_colormode == opt_colormode) {
        return SANE_STATUS_GOOD;
    }

    if ((src->colormodes & (1 <<opt_colormode)) == 0) {
        return SANE_STATUS_INVAL;
    }

    dev->opt_colormode = opt_colormode;
    *info |= SANE_INFO_RELOAD_PARAMS;

    return SANE_STATUS_GOOD;
}

/* Set current source. Affects many other options
 */
static SANE_Status
device_set_source (device *dev, OPT_SOURCE opt_src, SANE_Word *info)
{
    devcaps_source *src = dev->caps.src[opt_src];

    if (src == NULL) {
        return SANE_STATUS_INVAL;
    }

    if (dev->opt_src == opt_src) {
        return SANE_STATUS_GOOD;
    }

    dev->opt_src = opt_src;

    /* Try to preserve current color mode */
    dev->opt_colormode = devcaps_source_choose_colormode(src,
            dev->opt_colormode);

    /* Try to preserve resolution */
    dev->opt_resolution = devcaps_source_choose_resolution(src,
            dev->opt_resolution);

    /* Reset window to maximum size */
    dev->opt_tl_x = 0;
    dev->opt_tl_y = 0;

    dev->opt_br_x = src->win_x_range.max;
    dev->opt_br_y = src->win_y_range.max;

    device_rebuild_opt_desc(dev);

    *info |= SANE_INFO_RELOAD_OPTIONS | SANE_INFO_RELOAD_PARAMS;

    return SANE_STATUS_GOOD;
}

/* Set geometry option
 */
static SANE_Status
device_set_geom (device *dev, SANE_Int option, SANE_Word val, SANE_Word *info)
{
    SANE_Word      *out = NULL;
    SANE_Range     *range = NULL;
    devcaps_source *src = dev->caps.src[dev->opt_src];

    /* Choose destination and range */
    switch (option) {
    case OPT_SCAN_TL_X:
        out = &dev->opt_tl_x;
        range = &src->win_x_range;
        break;

    case OPT_SCAN_TL_Y:
        out = &dev->opt_tl_y;
        range = &src->win_y_range;
        break;

    case OPT_SCAN_BR_X:
        out = &dev->opt_br_x;
        range = &src->win_x_range;
        break;

    case OPT_SCAN_BR_Y:
        out = &dev->opt_br_y;
        range = &src->win_y_range;
        break;

    default:
        g_assert_not_reached();
    }

    /* Update option */
    if (*out != val) {
        *out = math_range_fit(range, val);
        if (*out == val) {
            *info |= SANE_INFO_RELOAD_PARAMS;
        } else {
            *info |= SANE_INFO_RELOAD_PARAMS | SANE_INFO_INEXACT;
        }
    }

    return SANE_STATUS_GOOD;
}

/******************** Device table operations ********************/
/* Userdata passed to device_table_foreach_callback
 */
typedef struct {
    unsigned int flags;     /* Device flags */
    unsigned int count;     /* Count of devices used so far */
    device       **devlist; /* List of devices collected so far. May be NULL */
} device_table_foreach_userdata;

/* g_tree_foreach callback for traversing device table
 */
static gboolean
device_table_foreach_callback (gpointer key, gpointer value, gpointer userdata)
{
    device *dev = value;
    device_table_foreach_userdata *data = userdata;

    (void) key;

    if (!(data->flags & dev->flags)) {
        return FALSE;
    }

    if (data->devlist != NULL) {
        data->devlist[data->count] = dev;
    }

    data->count ++;

    return FALSE;
}

/* Collect devices matching the flags. Return count of
 * collected devices. If caller is only interested in
 * the count, it is safe to call with out == NULL
 *
 * It's a caller responsibility to provide big enough
 * output buffer (use device_table_size() to make a guess)
 *
 * Caller must own glib_main_loop lock
 */
static unsigned int
device_table_collect (unsigned int flags, device *out[])
{
    device_table_foreach_userdata       data = {flags, 0, out};
    g_tree_foreach(device_table, device_table_foreach_callback, &data);
    return data.count;
}

/* Get current device_table size
 */
static unsigned
device_table_size (void)
{
    g_assert(device_table);
    return g_tree_nnodes(device_table);
}

/* Purge device_table
 */
static void
device_table_purge (void)
{
    size_t  sz = device_table_size(), i;
    device  **devices = g_newa(device*, sz);

    sz = device_table_collect(DEVICE_ALL_FLAGS, devices);
    for (i = 0; i < sz; i ++) {
        device_del(devices[i]);
    }
}

/* Check if device table is ready, i.e., there is no DEVICE_INIT_WAIT
 * devices
 */
static bool
device_table_ready (void)
{
    return device_table_collect(DEVICE_INIT_WAIT, NULL) == 0;
}

/* ScannerCapabilities fetch callback
 */
static void
device_scanner_capabilities_callback (device *dev, SoupMessage *msg)
{
    DBG_DEVICE(dev->name, "ScannerCapabilities: status=%d", msg->status_code);

    const char *err = NULL;

    /* Check request status */
    if (!SOUP_STATUS_IS_SUCCESSFUL(msg->status_code)) {
        err = "failed to load ScannerCapabilities";
        goto DONE;
    }

    /* Parse XML response */
    SoupBuffer *buf = soup_message_body_flatten(msg->response_body);
    err = devcaps_parse(&dev->caps, buf->data, buf->length);
    soup_buffer_free(buf);

    if (err != NULL) {
        err = eloop_eprintf("ScannerCapabilities: %s", err);
        goto DONE;
    }

    devcaps_dump(dev->name, &dev->caps);

    /* Cleanup and exit */
DONE:
    if (err != NULL) {
        if (dev->addr_current != NULL && dev->addr_current->next != NULL) {
            device_probe_address(dev, dev->addr_current->next);
        } else {
            device_del(dev);
        }
    } else {
        /* Choose initial source */
        OPT_SOURCE opt_src = (OPT_SOURCE) 0;
        while (opt_src < NUM_OPT_SOURCE &&
                (dev->caps.src[opt_src]) == NULL) {
            opt_src ++;
        }

        g_assert(opt_src != NUM_OPT_SOURCE);

        SANE_Word unused;
        device_set_source(dev, opt_src, &unused);

        dev->flags |= DEVICE_READY;
        dev->flags &= ~DEVICE_INIT_WAIT;
    }

    g_cond_broadcast(&device_table_cond);
}

/* User data, associated with each HTTP message
 */
typedef struct {
    device *dev;
    trace  *trace;
    void   (*func)(device *dev, SoupMessage *msg);
} device_http_callback_data;

/* HTTP request completion callback. Performs required
 * cleanup operations and dispatches control to the
 * actual handler.
 */
static void
device_http_callback(SoupSession *session, SoupMessage *msg, gpointer userdata)
{
    device_http_callback_data *data = userdata;

    (void) session;
    if (DBG_ENABLED(DBG_FLG_HTTP)) {
        SoupURI *uri = soup_message_get_uri(msg);
        char *uri_str = soup_uri_to_string(uri, FALSE);

        DBG_HTTP("%s %s: %s", msg->method, uri_str,
                soup_status_get_phrase(msg->status_code));

        g_free(uri_str);
    }

    if (msg->status_code != SOUP_STATUS_CANCELLED) {
        g_assert(data->dev->http_pending == msg);
        data->dev->http_pending = NULL;

        trace_msg_hook(data->trace, msg);

        if (data->func != NULL) {
            data->func(data->dev, msg);
        }
    }

    g_free(userdata);
}

/* Initiate HTTP request
 *
 * If request != NULL, it becomes a request message body. The
 * memory ownership will be taken by this function, assuming
 * request body needs to be released with g_free() after use
 *
 * Content type of the outgoing requests assumed to be "text/xml"
 */
static void
device_http_perform (device *dev, const char *path,
        const char *method, const char *request,
        void (*callback)(device*, SoupMessage*))
{
    SoupURI *url = soup_uri_new_with_base(dev->uri_escl, path);
    g_assert(url);
    SoupMessage *msg = soup_message_new_from_uri(method, url);

    if (DBG_ENABLED(DBG_FLG_HTTP)) {
        char *uri_str = soup_uri_to_string(url, FALSE);
        DBG_HTTP("%s %s", msg->method, uri_str);
        g_free(uri_str);
    }

    soup_uri_free(url);

    if (request != NULL) {
        soup_message_set_request(msg, "text/xml", SOUP_MEMORY_TAKE,
                request, strlen(request));
    }

    /* Note, on Kyocera ECOSYS M2040dn connection keep-alive causes
     * scanned job to remain in "Processing" state about 10 seconds
     * after job has been actually completed, making scanner effectively
     * busy.
     *
     * Looks like Kyocera firmware bug. Force connection to close
     * as a workaround
     */
    soup_message_headers_append(msg->request_headers, "Connection", "close");

    device_http_callback_data *data = g_new0(device_http_callback_data, 1);
    data->dev = dev;
    data->trace = dev->trace;
    data->func = callback;

    soup_session_queue_message(device_http_session, msg,
            device_http_callback, data);

    g_assert(dev->http_pending == NULL);
    dev->http_pending = msg;
}

/* Initiate HTTP GET request
 */
static void
device_http_get (device *dev, const char *path,
        void (*callback)(device*, SoupMessage*))
{
    device_http_perform(dev, path, "GET", NULL, callback);
}

/* Cancel currently pending HTTP request, if any
 */
static void
device_http_cancel (device *dev)
{
    if (dev->http_pending != NULL) {
        soup_session_cancel_message(device_http_session, dev->http_pending,
                SOUP_STATUS_CANCELLED);

        /* Note, if message processing already finished,
         * soup_session_cancel_message() will do literally nothing,
         * and in particular will not update message status,
         * but we rely on a fact that status of cancelled
         * messages is set properly
         */
        soup_message_set_status(dev->http_pending, SOUP_STATUS_CANCELLED);
        dev->http_pending = NULL;
    }
}

/******************** ESCL protocol ********************/
/* HTTP DELETE ${dev->job_location} callback
 */
static void
device_escl_delete_callback (device *dev, SoupMessage *msg)
{
    (void) msg;

    device_job_set_state(dev, DEVICE_JOB_DONE);
}

/* ESCL: delete current job
 *
 * HTTP DELETE ${dev->job_location}
 */
static void
device_escl_delete (device *dev)
{
    device_http_perform(dev, dev->job_location->str, "DELETE", NULL,
            device_escl_delete_callback);
}

/* HTTP GET ${dev->job_location}/NextDocument callback
 */
static void
device_escl_load_page_callback (device *dev, SoupMessage *msg)
{
    /* Transport error is fatal */
    if (SOUP_STATUS_IS_TRANSPORT_ERROR(msg->status_code)) {
        device_job_set_state(dev, DEVICE_JOB_DONE);
        device_job_set_status(dev, SANE_STATUS_IO_ERROR);
        return;
    }

    /* Try to fetch next page until previous page fetched successfully */
    if (SOUP_STATUS_IS_SUCCESSFUL(msg->status_code)) {
        SoupBuffer *buf = soup_message_body_flatten(msg->response_body);
        g_ptr_array_add(dev->job_images, buf);
        device_escl_load_page(dev);
    } else if (dev->job_images->len == 0) {
        device_job_set_state(dev, DEVICE_JOB_DONE);
        device_job_set_status(dev, SANE_STATUS_IO_ERROR);
    } else {
        /* Just in case, delete the job */
        device_job_set_state(dev, DEVICE_JOB_CLEANING_UP);
        device_escl_delete(dev);
    }
}

/* ESCL: load next page
 *
 * HTTP GET ${dev->job_location}/NextDocument request
 */
static void
device_escl_load_page (device *dev)
{
    size_t sz = dev->job_location->len;
    if (sz == 0 || dev->job_location->str[sz-1] != '/') {
        g_string_append_c(dev->job_location, '/');
    }

    g_string_append(dev->job_location, "NextDocument");
    device_http_get(dev, dev->job_location->str, device_escl_load_page_callback);
    g_string_truncate(dev->job_location, sz);
}

/* * HTTP POST ${dev->uri_escl}/ScanJobs callback
 */
static void
device_escl_start_scan_callback (device *dev, SoupMessage *msg)
{
    const char *location;

    if (msg->status_code != SOUP_STATUS_CREATED) {
        goto FAIL;
    }

    location = soup_message_headers_get_one(msg->response_headers, "Location");
    if (location == NULL) {
        goto FAIL;
    }

    g_string_assign(dev->job_location, location);

    if (dev->job_cancel_rq) {
        device_job_set_state(dev, DEVICE_JOB_CLEANING_UP);
        device_job_set_status(dev, SANE_STATUS_CANCELLED);
        device_escl_delete(dev);
    } else {
        device_job_set_state(dev, DEVICE_JOB_LOADING);
        device_escl_load_page(dev);
    }

    return;

FAIL:
    device_job_set_state(dev, DEVICE_JOB_DONE);
    device_job_set_status(dev, SANE_STATUS_IO_ERROR);
}

/* ESCL: start scanning
 *
 * HTTP POST ${dev->uri_escl}/ScanJobs
 */
static void
device_escl_start_scan (device *dev)
{
    unsigned int x_off = 0;
    unsigned int y_off = 0;
    unsigned int wid, hei;
    const char   *source = "Platen";
    //const char   *source = "Feeder";
    const char   *colormode = "RGB24";
    const char   *mime = "image/jpeg";
    SANE_Word    x_resolution = 300;
    SANE_Word    y_resolution = 300;
    bool         duplex = false;

    wid = math_mm2px(dev->opt_br_x);
    hei = math_mm2px(dev->opt_br_y);

    const char *rq = g_strdup_printf(
        "<?xml version='1.0' encoding='UTF-8'?>\n"
        "<scan:ScanSettings\n"
        "    xmlns:scan=\"http://schemas.hp.com/imaging/escl/2011/05/03\"\n"
        "    xmlns:pwg=\"http://www.pwg.org/schemas/2010/12/sm\">\n"
        "  <pwg:Version>2.6</pwg:Version>\n"
        "  <pwg:ScanRegions>\n"
        "    <pwg:ScanRegion>\n"
        "      <pwg:XOffset>%d</pwg:XOffset>\n"
        "      <pwg:YOffset>%d</pwg:YOffset>\n"
        "      <pwg:Width>%d</pwg:Width>\n"
        "      <pwg:Height>%d</pwg:Height>\n"
        "      <pwg:ContentRegionUnits>escl:ThreeHundredthsOfInches</pwg:ContentRegionUnits>\n"
        "    </pwg:ScanRegion>\n"
        "  </pwg:ScanRegions>\n"
        "  <scan:InputSource>%s</scan:InputSource>\n"
        "  <pwg:InputSource>%s</pwg:InputSource>\n"
        "  <scan:ColorMode>%s</scan:ColorMode>\n"
        "  <scan:DocumentFormatExt>%s</scan:DocumentFormatExt>\n"
        "  <scan:XResolution>%d</scan:XResolution>\n"
        "  <scan:YResolution>%d</scan:YResolution>\n"
        "  <scan:Duplex>%s</scan:Duplex>\n"
        "</scan:ScanSettings>\n",
        x_off,
        y_off,
        wid,
        hei,
        source,
        source,
        colormode,
        mime,
        x_resolution,
        y_resolution,
        duplex ? "true" : "false"
    );

    device_job_set_state(dev, DEVICE_JOB_REQUESTING);
    device_http_perform(dev, "ScanJobs", "POST", rq,
            device_escl_start_scan_callback);
}


/* Parse ScannerStatus response.
 *
 * On success, returns NULL and `idle' is set to true
 * if scanner is idle
 */
static const char*
device_escl_scannerstatus_parse (const char *xml_text, size_t xml_len, bool *idle)
{
    const char *err = NULL;
    xml_iter   *iter;

    *idle = false;

    err = xml_iter_begin(&iter, xml_text, xml_len);
    if (err != NULL) {
        goto DONE;
    }

    xml_iter_enter(iter);
    for (; !xml_iter_end(iter); xml_iter_next(iter)) {
        if (xml_iter_node_name_match(iter, "pwg:State")) {
            const char *state = xml_iter_node_value(iter);
            *idle = !strcmp(state, "Idle");
            goto DONE;
        }
    }

DONE:
    xml_iter_finish(&iter);
    return err;
}


/* HTTP POST ${dev->uri_escl}/ScannerStatus callback
 */
static void
device_escl_get_scannerstatus_callback (device *dev, SoupMessage *msg)
{
    const char  *err = NULL;
    bool        idle;
    SANE_Status status = SANE_STATUS_IO_ERROR;

    /* Check request status */
    if (!SOUP_STATUS_IS_SUCCESSFUL(msg->status_code)) {
        err = "failed to load ScannerStatus";
        goto DONE;
    }

    /* Parse XML response */
    SoupBuffer *buf = soup_message_body_flatten(msg->response_body);
    err = device_escl_scannerstatus_parse(buf->data, buf->length, &idle);
    soup_buffer_free(buf);

    if (err != NULL) {
        err = eloop_eprintf("ScannerStatus: %s", err);
        goto DONE;
    }

    /* Check if scanned is idle */
    if (!idle) {
        err = "Scanner is busy";
        status = SANE_STATUS_DEVICE_BUSY;
        goto DONE;
    }

    /* Start scan job */
    device_escl_start_scan(dev);

    /* Cleanup and exit */
DONE:
    if (err != NULL) {
        device_job_set_state(dev, DEVICE_JOB_DONE);
        device_job_set_status(dev, status);
    }
}

/* ESCL: get scanner status
 *
 * HTTP POST ${dev->uri_escl}/ScannerStatus
 */
static void
device_escl_get_scannerstatus (device *dev)
{
    device_http_get(dev, "ScannerStatus",
            device_escl_get_scannerstatus_callback);
}

/******************** Scan Job management ********************/
/* Set job_state (and job_status)
 */
static void
device_job_set_state (device *dev, DEVICE_JOB_STATE state)
{
    dev->job_state = state;
    g_cond_broadcast(&dev->job_state_cond);
}

/* Set job status. If status already set, it will not be
 * changed
 */
static void
device_job_set_status (device *dev, SANE_Status status)
{
    if (dev->job_status == SANE_STATUS_GOOD) {
        dev->job_status = status;
    }
}

/* Cancel the job
 */
static void
device_job_cancel (void *data)
{
    device *dev = data;

    DBG_DEVICE(dev->name, "Cancel");

    if (dev->job_cancel_rq) {
        return; /* We are working on it */
    }


    switch (dev->job_state) {
    case DEVICE_JOB_IDLE:
    case DEVICE_JOB_DONE:
        /* Nothing to do */
        break;

    case DEVICE_JOB_STARTED:
    case DEVICE_JOB_REQUESTING:
        dev->job_cancel_rq = true;
        break;

    case DEVICE_JOB_CHECK_STATUS:
        device_http_cancel(dev);
        device_job_set_state(dev, DEVICE_JOB_DONE);
        device_job_set_status(dev, SANE_STATUS_CANCELLED);
        break;

    case DEVICE_JOB_LOADING:
        device_http_cancel(dev);
        device_job_set_state(dev, DEVICE_JOB_CLEANING_UP);
        device_escl_delete(dev);
        /* Fall through... */

    case DEVICE_JOB_CLEANING_UP:
        device_job_set_status(dev, SANE_STATUS_CANCELLED);
        break;
    }
}

/******************** API helpers ********************/
/* Wait until list of devices is ready
 */
static void
device_list_sync (void)
{
    gint64 timeout = g_get_monotonic_time() +
            DEVICE_TABLE_READY_TIMEOUT * G_TIME_SPAN_SECOND;

    while ((!device_table_ready() || zeroconf_init_scan()) &&
            g_get_monotonic_time() < timeout) {
        eloop_cond_wait_until(&device_table_cond, timeout);
    }
}

/* Get list of devices, in SANE format
 */
const SANE_Device**
device_list_get (void)
{
    /* Wait until device table is ready */
    device_list_sync();

    /* Build a list */
    device            **devices = g_newa(device*, device_table_size());
    unsigned int      count = device_table_collect(DEVICE_READY, devices);
    unsigned int      i;
    const SANE_Device **dev_list = g_new0(const SANE_Device*, count + 1);

    for (i = 0; i < count; i ++) {
        SANE_Device *info = g_new0(SANE_Device, 1);
        dev_list[i] = info;

        info->name = g_strdup(devices[i]->name);
        info->vendor = g_strdup(devices[i]->caps.vendor);
        info->model = g_strdup(devices[i]->caps.model);
        info->type = "eSCL network scanner";
    }

    return dev_list;
}

/* Free list of devices, returned by device_list_get()
 */
void
device_list_free (const SANE_Device **dev_list)
{
    if (dev_list != NULL) {
        unsigned int       i;
        const SANE_Device *info;

        for (i = 0; (info = dev_list[i]) != NULL; i ++) {
            g_free((void*) info->name);
            g_free((void*) info->vendor);
            g_free((void*) info->model);
            g_free((void*) info);
        }

        g_free(dev_list);
    }
}

/* Open a device
 */
SANE_Status
device_open (const char *name, device **out)
{
    device *dev = NULL;

    *out = NULL;

    /* Find a device */
    device_list_sync();

    if (name && *name) {
        dev = device_find(name);
    } else {
        device          **devices = g_newa(device*, device_table_size());
        unsigned int    count = device_table_collect(DEVICE_READY, devices);
        if (count > 0) {
            dev = devices[0];
        }
    }

    if (dev == NULL || (dev->flags & DEVICE_READY) == 0) {
        return SANE_STATUS_INVAL;
    }

    /* Check device state */
    if ((dev->flags & DEVICE_OPENED) != 0) {
        return SANE_STATUS_DEVICE_BUSY;
    }

    /* Proceed with open */
    dev->job_cancel_event = eloop_event_new(device_job_cancel, dev);
    if (dev->job_cancel_event == NULL) {
        return SANE_STATUS_NO_MEM;
    }

    dev->flags |= DEVICE_OPENED;
    *out = device_ref(dev);

    return SANE_STATUS_GOOD;
}

/* Close the device
 */
void
device_close (device *dev)
{
    if ((dev->flags & DEVICE_OPENED) != 0) {
        eloop_event_free(dev->job_cancel_event);
        dev->job_cancel_event = NULL;
        dev->flags &= ~DEVICE_OPENED;
        device_unref(dev);
    }
}

/* Get option descriptor
 */
const SANE_Option_Descriptor*
dev_get_option_descriptor (device *dev, SANE_Int option)
{
    if (0 <= option && option < NUM_OPTIONS) {
        return &dev->opt_desc[option];
    }

    return NULL;
}

/* Get device option
 */
SANE_Status
device_get_option (device *dev, SANE_Int option, void *value)
{
    SANE_Status status = SANE_STATUS_GOOD;

    switch (option) {
    case OPT_NUM_OPTIONS:
        *(SANE_Word*) value = NUM_OPTIONS;
        break;

    case OPT_SCAN_RESOLUTION:
        *(SANE_Word*) value = dev->opt_resolution;
        break;

    case OPT_SCAN_COLORMODE:
        strcpy(value, opt_colormode_to_sane(dev->opt_colormode));
        break;

    case OPT_SCAN_SOURCE:
        strcpy(value, opt_source_to_sane(dev->opt_src));
        break;

    case OPT_SCAN_TL_X:
        *(SANE_Word*) value = dev->opt_tl_x;
        break;

    case OPT_SCAN_TL_Y:
        *(SANE_Word*) value = dev->opt_tl_y;
        break;

    case OPT_SCAN_BR_X:
        *(SANE_Word*) value = dev->opt_br_x;
        break;

    case OPT_SCAN_BR_Y:
        *(SANE_Word*) value = dev->opt_br_y;
        break;

    default:
        status = SANE_STATUS_INVAL;
    }

    return status;
}

/* Set device option
 */
SANE_Status
device_set_option (device *dev, SANE_Int option, void *value, SANE_Word *info)
{
    SANE_Status    status = SANE_STATUS_GOOD;
    OPT_SOURCE     opt_src;
    OPT_COLORMODE  opt_colormode;

    /* Simplify life of options handlers by ensuring info != NULL  */
    if (info == NULL) {
        static SANE_Word unused;
        info = &unused;
    }

    *info = 0;

    /* Switch by option */
    switch (option) {
    case OPT_SCAN_RESOLUTION:
        status = device_set_resolution(dev, *(SANE_Word*)value, info);
        break;

    case OPT_SCAN_COLORMODE:
        opt_colormode = opt_colormode_from_sane(value);
        if (opt_colormode == OPT_COLORMODE_UNKNOWN) {
            status = SANE_STATUS_INVAL;
        } else {
            status = device_set_colormode(dev, opt_colormode, info);
        }
        break;

    case OPT_SCAN_SOURCE:
        opt_src = opt_source_from_sane(value);
        if (opt_src == OPT_SOURCE_UNKNOWN) {
            status = SANE_STATUS_INVAL;
        } else {
            status = device_set_source(dev, opt_src, info);
        }
        break;

    case OPT_SCAN_TL_X:
    case OPT_SCAN_TL_Y:
    case OPT_SCAN_BR_X:
    case OPT_SCAN_BR_Y:
        status = device_set_geom(dev, option, *(SANE_Word*)value, info);
        break;

    default:
        status = SANE_STATUS_INVAL;
    }

    return status;
}

/* Get current scan parameters
 */
SANE_Status
device_get_parameters (device *dev, SANE_Parameters *params)
{
    SANE_Word wid = math_max(0, dev->opt_br_x - dev->opt_tl_x);
    SANE_Word hei = math_max(0, dev->opt_br_y - dev->opt_tl_y);

    params->last_frame = SANE_TRUE;
    params->pixels_per_line = math_mm2px_res(wid, dev->opt_resolution);
    params->lines = math_mm2px_res(hei, dev->opt_resolution);

    switch (dev->opt_colormode) {
    case OPT_COLORMODE_COLOR:
        params->format = SANE_FRAME_RGB;
        params->depth = 8;
        params->bytes_per_line = params->pixels_per_line * 3;
        break;

    case OPT_COLORMODE_GRAYSCALE:
        params->format = SANE_FRAME_GRAY;
        params->depth = 8;
        params->bytes_per_line = params->pixels_per_line;
        break;

    case OPT_COLORMODE_LINEART:
        params->format = SANE_FRAME_GRAY;
        params->depth = 1;
        params->bytes_per_line = ((params->pixels_per_line + 7) / 8) * 8;
        break;

    default:
        g_assert(!"internal error");
    }


    return SANE_STATUS_GOOD;
}

/* Start scanning operation - runs on a context of event loop thread
 */
static gboolean
device_start_do (gpointer data)
{
    device      *dev = data;

    g_assert(dev->job_location->len == 0);

    if (dev->job_cancel_rq) {
        device_job_set_state(dev, DEVICE_JOB_DONE);
        device_job_set_status(dev, SOUP_STATUS_CANCELLED);
    } else {
        device_job_set_state(dev, DEVICE_JOB_CHECK_STATUS);
        device_escl_get_scannerstatus(dev);
    }

    return FALSE;
}

/* Start scanning operation
 */
SANE_Status
device_start (device *dev)
{
    if (dev->job_state != DEVICE_JOB_IDLE) {
        return SANE_STATUS_DEVICE_BUSY;
    }

    device_job_set_state(dev, DEVICE_JOB_STARTED);
    dev->job_status = SANE_STATUS_GOOD;
    dev->job_cancel_rq = false;

    eloop_call(device_start_do, dev);

    for (;;) {
        switch (dev->job_state) {
        case DEVICE_JOB_LOADING:
            return SANE_STATUS_GOOD;

        case DEVICE_JOB_DONE:
            device_job_set_state(dev, DEVICE_JOB_IDLE);
            return dev->job_status;

        default:
            eloop_cond_wait(&dev->job_state_cond);
        }
    }
}

/* Cancel scanning operation
 */
void
device_cancel (device *dev)
{
    if (dev->job_cancel_event != NULL) {
        eloop_event_trigger(dev->job_cancel_event);
    }
}

/******************** Device discovery events ********************/
/* Device found notification -- called by ZeroConf
 */
void
device_event_found (const char *name, bool init_scan,
        zeroconf_addrinfo *addresses)
{
    /* Don't allow duplicate devices */
    device *dev = device_find(name);
    if (dev != NULL) {
        DBG_DEVICE(name, "device already exist");
        return;
    }

    /* Add a device */
    dev = device_add(name);
    if (init_scan) {
        dev->flags |= DEVICE_INIT_WAIT;
    }
    dev->addresses = zeroconf_addrinfo_list_copy(addresses);
    device_probe_address(dev, dev->addresses);
}

/* Device removed notification -- called by ZeroConf
 */
void
device_event_removed (const char *name)
{
    device *dev = device_find(name);
    if (dev) {
        device_del(dev);
    }
}

/* Device initial scan finished notification -- called by ZeroConf
 */
void
device_event_init_scan_finished (void)
{
    g_cond_broadcast(&device_table_cond);
}


/******************** Initialization/cleanup ********************/
/* Initialize device management
 */
SANE_Status
device_management_init (void)
{
    g_cond_init(&device_table_cond);
    device_table = g_tree_new_full(device_name_compare, NULL, NULL, NULL);

    return SANE_STATUS_GOOD;
}

/* Cleanup device management
 */
void
device_management_cleanup (void)
{
    if (device_table != NULL) {
        g_assert(g_tree_nnodes(device_table) == 0);
        g_cond_clear(&device_table_cond);
        g_tree_unref(device_table);
        device_table = NULL;
    }
}

/* Start/stop devices management. Called from the airscan thread
 */
static void
device_management_start (void)
{
    conf_device *dev_conf;

    device_http_session = soup_session_new();
    for (dev_conf = conf.devices; dev_conf != NULL; dev_conf = dev_conf->next) {
        device_add_static(dev_conf->name, dev_conf->uri);
    }
}

/* Stop device management. Called from the airscan thread
 */
static void
device_management_stop (void)
{
    soup_session_abort(device_http_session);
    device_table_purge();
    g_object_unref(device_http_session);
    device_http_session = NULL;
}

/* Start/stop device management
 */
void
device_management_start_stop (bool start)
{
    if (start) {
        device_management_start();
    } else {
        device_management_stop();
    }
}


/* vim:ts=8:sw=4:et
 */
