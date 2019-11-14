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

/******************** Device management ********************/
/* Device flags
 */
enum {
    DEVICE_LISTED           = (1 << 0), /* Device listed in device_table */
    DEVICE_READY            = (1 << 2), /* Device is ready */
    DEVICE_HALTED           = (1 << 3), /* Device is halted */
    DEVICE_INIT_WAIT        = (1 << 4), /* Device was found during initial
                                           scan and not ready yet */
    DEVICE_ALL_FLAGS        = 0xffffffff
};

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
    SoupURI              *base_url;     /* eSCL base URI */
    GPtrArray            *http_pending; /* Pending HTTP requests */
    trace                *trace;        /* Protocol trace */

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
device_table_purge (void);

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

    dev->http_pending = g_ptr_array_new();
    dev->trace = trace_open(name);

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

        /* Release all memory */
        g_free((void*) dev->name);

        devcaps_cleanup(&dev->caps);

        zeroconf_addrinfo_list_free(dev->addresses);

        if (dev->base_url != NULL) {
            soup_uri_free(dev->base_url);
        }
        g_ptr_array_unref(dev->http_pending);

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
    guint i;
    for (i = 0; i < dev->http_pending->len; i ++) {
        soup_session_cancel_message(device_http_session,
                g_ptr_array_index(dev->http_pending, i), SOUP_STATUS_CANCELLED);
    }

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
    dev->base_url = soup_uri_copy(uri);

    /* Make sure URI's path ends with '/' character */
    const char *path = soup_uri_get_path(dev->base_url);
    if (!g_str_has_suffix(path, "/")) {
        size_t len = strlen(path);
        char *path2 = g_alloca(len + 2);
        memcpy(path2, path, len);
        path2[len] = '/';
        path2[len+1] = '\0';
        soup_uri_set_path(dev->base_url, path2);
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
    if (dev->base_url != NULL) {
        soup_uri_free(dev->base_url);
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

    dev->base_url = soup_uri_new(url);
    g_assert(dev->base_url != NULL);
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
static SANE_Bool
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

    xmlDoc      *doc = NULL;
    const char *err = NULL;

    /* Check request status */
    if (!SOUP_STATUS_IS_SUCCESSFUL(msg->status_code)) {
        err = "failed to load ScannerCapabilities";
        goto DONE;
    }

    /* Parse XML response */
    SoupBuffer *buf = soup_message_body_flatten(msg->response_body);
    doc = xmlParseMemory(buf->data, buf->length);
    soup_buffer_free(buf);

    if (doc == NULL) {
        err = "failed to parse ScannerCapabilities response XML";
        goto DONE;
    }

    err = devcaps_parse(&dev->caps, doc);
    if (err == NULL) {
        devcaps_dump(dev->name, &dev->caps);
    }

    /* Cleanup and exit */
DONE:
    if (doc != NULL) {
        xmlFreeDoc(doc);
    }

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
    void   (*callback)(device *dev, SoupMessage *msg);
} device_http_userdata;

/* HTTP request completion callback
 */
static void
device_http_callback(SoupSession *session, SoupMessage *msg, gpointer userdata)
{
    device_http_userdata *data = userdata;

    trace_msg_hook(data->trace, msg);

    (void) session;
    if (DBG_ENABLED(DBG_FLG_HTTP)) {
        SoupURI *uri = soup_message_get_uri(msg);
        char *uri_str = soup_uri_to_string(uri, FALSE);

        DBG_HTTP("%s %s: %s", msg->method, uri_str,
                soup_status_get_phrase(msg->status_code));

        g_free(uri_str);
    }

    if (msg->status_code != SOUP_STATUS_CANCELLED) {
        g_ptr_array_remove(data->dev->http_pending, msg);
        if (data->callback != NULL) {
            data->callback(data->dev, msg);
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
    SoupURI *url = soup_uri_new_with_base(dev->base_url, path);
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

    device_http_userdata *data = g_new0(device_http_userdata, 1);
    data->dev = dev;
    data->trace = dev->trace;
    data->callback = callback;

    soup_session_queue_message(device_http_session, msg,
            device_http_callback, data);
    g_ptr_array_add(dev->http_pending, msg);
}

/* Initiate HTTP GET request
 */
static void
device_http_get (device *dev, const char *path,
        void (*callback)(device*, SoupMessage*))
{
    device_http_perform(dev, path, "GET", NULL, callback);
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
        eloop_cond_wait(&device_table_cond, timeout);
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
device*
device_open (const char *name)
{
    device *dev = NULL;

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

    if (dev != NULL && (dev->flags & DEVICE_READY) != 0) {
        return device_ref(dev);
    }

    return NULL;
}

/* Close the device
 */
void
device_close (device *dev)
{
    device_unref(dev);
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
    unsigned int x_off = 0;
    unsigned int y_off = 0;
    unsigned int wid, hei;
    const char   *source = "Platen";
    const char   *colormode = "RGB24";
    const char   *mime = "image/jpeg";
    SANE_Word    x_resolution = 300;
    SANE_Word    y_resolution = 300;

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
        "  <scan:ColorMode>%s</scan:ColorMode>\n"
        "  <scan:DocumentFormatExt>%s</scan:DocumentFormatExt>\n"
        "  <scan:XResolution>%d</scan:XResolution>\n"
        "  <scan:YResolution>%d</scan:YResolution>\n"
        "</scan:ScanSettings>\n",
        x_off,
        y_off,
        wid,
        hei,
        source,
        colormode,
        mime,
        x_resolution,
        y_resolution
    );

    device_http_perform(dev, "ScanJobs", "POST", rq, NULL);

    return FALSE;
}

/* Start scanning operation
 */
SANE_Status
device_start (device *dev)
{
    eloop_call(device_start_do, dev);
    return SANE_STATUS_GOOD;
}

/******************** Device discovery events ********************/
/* Device found notification -- called by ZeroConf
 */
void
device_event_found (const char *name, gboolean init_scan,
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
device_management_start_stop (gboolean start)
{
    if (start) {
        device_management_start();
    } else {
        device_management_stop();
    }
}


/* vim:ts=8:sw=4:et
 */
