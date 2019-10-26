/* AirScan (a.k.a. eSCL) backend for SANE
 *
 * Copyright (C) 2019 and up by Alexander Pevzner (pzz@apevzner.com)
 * See LICENSE for license terms and conditions
 */

#include "airscan.h"

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

/* Max time to wait until device table is ready, in seconds
 */
#define DEVICE_TABLE_READY_TIMEOUT              5

/* String constants for certain SANE options values
 */
#define OPTVAL_SOURCE_PLATEN      "Flatbed"
#define OPTVAL_SOURCE_ADF_SIMPLEX "ADF"
#define OPTVAL_SOURCE_ADF_DUPLEX  "ADF Duplex"

/******************** Global variables ********************/
/* Debug flags
 */
int dbg_flags = DBG_FLG_ALL;

/******************** Device Capabilities  ********************/
/* Source flags
 */
enum {
    /* Supported color modes */
    DEVCAPS_SOURCE_COLORMODE_BW1   = (1 << 0), /* 1-bit black&white */
    DEVCAPS_SOURCE_COLORMODE_GRAY  = (1 << 1), /* Gray scale */
    DEVCAPS_SOURCE_COLORMODE_COLOR = (1 << 2), /* Color */

    /* Supported Intents */
    DEVCAPS_SOURCE_INTENT_DOCUMENT      = (1 << 3),
    DEVCAPS_SOURCE_INTENT_TXT_AND_GRAPH = (1 << 4),
    DEVCAPS_SOURCE_INTENT_PHOTO         = (1 << 5),
    DEVCAPS_SOURCE_INTENT_PREVIEW       = (1 << 6),

    /* How resolutions are defined */
    DEVCAPS_SOURCE_RES_DISCRETE = (1 << 7), /* Discrete resolutions */
    DEVCAPS_SOURCE_RES_RANGE    = (1 << 8), /* Range of resolutions */

    /* Supported document formats */
    DEVCAPS_SOURCE_FMT_JPEG = (1 << 9),  /* JPEG image */
    DEVCAPS_SOURCE_FMT_PDF  = (1 << 10), /* PDF image */
};

/* Source Capabilities (each device may contain multiple sources)
 */
typedef struct {
    unsigned int flags;                    /* Source flags */
    SANE_Word    min_width, max_width;     /* Min/max image width */
    SANE_Word    min_height, max_height;   /* Min/max image height */
    SANE_Word    *resolutions;             /* Discrete resolutions, in DPI */
    SANE_Range   res_range_x, res_range_y; /* Resolutions ranges */
} devcaps_source;

/* Device Capabilities
 */
typedef struct {
    /* Common capabilities */
    SANE_Word      *resolutions; /* Common resolutions */
    SANE_String    *sources;     /* Sources, in SANE format */
    const char     *model;       /* Device model */
    const char     *vendor;      /* Device vendor */

    /* Sources */
    devcaps_source *src_platen;      /* Platen (flatbed) scanner */
    devcaps_source *src_adf_simplex; /* ADF in simplex mode */
    devcaps_source *src_adf_duplex;  /* ADF in duplex mode */
} devcaps;

/* Allocate devcaps_source
 */
static devcaps_source*
devcaps_source_new (void)
{
    devcaps_source *src = g_new0(devcaps_source, 1 );
    array_of_word_init(&src->resolutions);
    return src;
}

/* Free devcaps_source
 */
static void
devcaps_source_free (devcaps_source *src)
{
    if (src != NULL) {
        array_of_word_cleanup(&src->resolutions);
        g_free(src);
    }
}

/* Initialize Device Capabilities
 */
static void
devcaps_init (devcaps *caps)
{
    array_of_word_init(&caps->resolutions);
    array_of_string_init(&caps->sources);
}

/* Reset Device Capabilities: free all allocated memory, clear the structure
 */
static void
devcaps_reset (devcaps *caps)
{
    array_of_word_cleanup(&caps->resolutions);
    array_of_string_cleanup(&caps->sources);
    g_free((void*) caps->vendor);
    g_free((void*) caps->model);

    devcaps_source_free(caps->src_platen);
    devcaps_source_free(caps->src_adf_simplex);
    devcaps_source_free(caps->src_adf_duplex);

    memset(caps, 0, sizeof(*caps));
}

/* Parse color modes. Returns NULL on success, error string otherwise
 */
static const char*
devcaps_source_parse_color_modes (xml_iter *iter, devcaps_source *src)
{
    xml_iter_enter(iter);
    for (; !xml_iter_end(iter); xml_iter_next(iter)) {
        if(xml_iter_node_name_match(iter, "scan:ColorMode")) {
            const char *v = xml_iter_node_value(iter);
            if (!strcmp(v, "BlackAndWhite1")) {
                src->flags |= DEVCAPS_SOURCE_COLORMODE_BW1;
            } else if (!strcmp(v, "Grayscale8")) {
                src->flags |= DEVCAPS_SOURCE_COLORMODE_GRAY;
            } else if (!strcmp(v, "RGB24")) {
                src->flags |= DEVCAPS_SOURCE_COLORMODE_COLOR;
            }
        }
    }
    xml_iter_leave(iter);

    return NULL;
}

/* Parse document formats. Returns NULL on success, error string otherwise
 */
static const char*
devcaps_source_parse_document_formats (xml_iter *iter, devcaps_source *src)
{
    xml_iter_enter(iter);
    for (; !xml_iter_end(iter); xml_iter_next(iter)) {
        if(xml_iter_node_name_match(iter, "pwg:DocumentFormat")) {
            const char *v = xml_iter_node_value(iter);
            if (!strcmp(v, "image/jpeg")) {
                src->flags |= DEVCAPS_SOURCE_FMT_JPEG;
            } else if (!strcmp(v, "application/pdf")) {
                src->flags |= DEVCAPS_SOURCE_FMT_PDF;
            }
        }
    }
    xml_iter_leave(iter);

    return NULL;
}

/* Parse discrete resolutions.
 * Returns NULL on success, error string otherwise
 */
static const char*
devcaps_source_parse_discrete_resolutions (xml_iter *iter, devcaps_source *src)
{
    const char *err = NULL;

    src->flags |= DEVCAPS_SOURCE_RES_DISCRETE;

    xml_iter_enter(iter);
    for (; err == NULL && !xml_iter_end(iter); xml_iter_next(iter)) {
        if (xml_iter_node_name_match(iter, "scan:DiscreteResolution")) {
            SANE_Word x = 0, y = 0;
            xml_iter_enter(iter);
            for (; err == NULL && !xml_iter_end(iter); xml_iter_next(iter)) {
                if (xml_iter_node_name_match(iter, "scan:XResolution")) {
                    err = xml_iter_node_value_uint(iter, &x);
                } else if (xml_iter_node_name_match(iter,
                        "scan:YResolution")) {
                    err = xml_iter_node_value_uint(iter, &y);
                }
            }
            xml_iter_leave(iter);

            if (x && y && x == y) {
                array_of_word_append(&src->resolutions, x);
            }
        }
    }
    xml_iter_leave(iter);

    array_of_word_sort(&src->resolutions);

    return err;
}

/* Parse resolutions range
 * Returns NULL on success, error string otherwise
 */
static const char*
devcaps_source_parse_resolutions_range (xml_iter *iter, devcaps_source *src)
{
    const char *err = NULL;

    src->flags |= DEVCAPS_SOURCE_RES_RANGE;

    xml_iter_enter(iter);
    for (; err == NULL && !xml_iter_end(iter); xml_iter_next(iter)) {
        SANE_Range *range = NULL;
        if (xml_iter_node_name_match(iter, "scan:XResolution")) {
            range = &src->res_range_x;
        } else if (xml_iter_node_name_match(iter, "scan:XResolution")) {
            range = &src->res_range_y;
        }

        if (range != NULL) {
            xml_iter_enter(iter);
            for (; err == NULL && !xml_iter_end(iter); xml_iter_next(iter)) {
                if (xml_iter_node_name_match(iter, "scan:Min")) {
                    err = xml_iter_node_value_uint(iter, &range->min);
                } else if (xml_iter_node_name_match(iter, "scan:Max")) {
                    err = xml_iter_node_value_uint(iter, &range->max);
                } else if (xml_iter_node_name_match(iter, "scan:Step")) {
                    err = xml_iter_node_value_uint(iter, &range->quant);
                }
            }
            xml_iter_leave(iter);
        }
    }
    xml_iter_leave(iter);

    return err;
}

/* Parse supported resolutions.
 * Returns NULL on success, error string otherwise
 */
static const char*
devcaps_source_parse_resolutions (xml_iter *iter, devcaps_source *src)
{
    const char *err = NULL;

    xml_iter_enter(iter);
    for (; err == NULL && !xml_iter_end(iter); xml_iter_next(iter)) {
        if (xml_iter_node_name_match(iter, "scan:DiscreteResolutions")) {
            err = devcaps_source_parse_discrete_resolutions(iter, src);
        } else if (xml_iter_node_name_match(iter, "scan:ResolutionRange")) {
            err = devcaps_source_parse_resolutions_range(iter, src);
        }
    }
    xml_iter_leave(iter);

    return err;
}

/* Parse setting profiles (color modes, document formats etc).
 * Returns NULL on success, error string otherwise
 */
static const char*
devcaps_source_parse_setting_profiles (xml_iter *iter, devcaps_source *src)
{
    const char *err = NULL;

    xml_iter_enter(iter);
    for (; err == NULL && !xml_iter_end(iter); xml_iter_next(iter)) {
        if (xml_iter_node_name_match(iter, "scan:SettingProfile")) {
            xml_iter_enter(iter);
            for (; err == NULL && !xml_iter_end(iter); xml_iter_next(iter)) {
                if (xml_iter_node_name_match(iter, "scan:ColorModes")) {
                    err = devcaps_source_parse_color_modes(iter, src);
                } else if (xml_iter_node_name_match(iter,
                        "scan:DocumentFormats")) {
                    err = devcaps_source_parse_document_formats(iter, src);
                } else if (xml_iter_node_name_match(iter,
                        "scan:SupportedResolutions")) {
                    err = devcaps_source_parse_resolutions(iter, src);
                }
            }
            xml_iter_leave(iter);
        }
    }
    xml_iter_leave(iter);

    return err;
}


/* Parse source capabilities. Returns NULL on success, error string otherwise
 */
static const char*
devcaps_source_parse (xml_iter *iter, devcaps_source **out)
{
    devcaps_source *src = devcaps_source_new();
    const char *err = NULL;

    xml_iter_enter(iter);
    for (; err == NULL && !xml_iter_end(iter); xml_iter_next(iter)) {
        if(xml_iter_node_name_match(iter, "scan:MinWidth")) {
            err = xml_iter_node_value_uint(iter, &src->min_width);
        } else if (xml_iter_node_name_match(iter, "scan:MaxWidth")) {
            err = xml_iter_node_value_uint(iter, &src->max_width);
        } else if (xml_iter_node_name_match(iter, "scan:MinHeight")) {
            err = xml_iter_node_value_uint(iter, &src->min_height);
        } else if (xml_iter_node_name_match(iter, "scan:MaxHeight")) {
            err = xml_iter_node_value_uint(iter, &src->max_height);
        } else if (xml_iter_node_name_match(iter, "scan:SettingProfiles")) {
            err = devcaps_source_parse_setting_profiles(iter, src);
        }
    }
    xml_iter_leave(iter);

    if (err != NULL) {
        devcaps_source_free(src);
    } else {
        if (*out == NULL) {
            *out = src;
        } else {
            /* Duplicate detected. Ignored for now */
            devcaps_source_free(src);
        }
    }

    return err;
}

/* Parse device capabilities. Returns NULL if OK, error string otherwise
 */
static const char*
devcaps_parse (devcaps *caps, xmlDoc *xml)
{
    const char *err = NULL;
    char       *model = NULL, *make_and_model = NULL;
    xml_iter   iter = XML_ITER_INIT;

    /* Parse capabilities XML */
    xml_iter_init(&iter, xmlDocGetRootElement(xml));
    if (!xml_iter_node_name_match(&iter, "scan:ScannerCapabilities")) {
        err = "XML: missed scan:ScannerCapabilities";
        goto DONE;
    }

    xml_iter_enter(&iter);
    for (; !xml_iter_end(&iter); xml_iter_next(&iter)) {
        if (xml_iter_node_name_match(&iter, "pwg:ModelName")) {
            g_free(model);
            model = g_strdup(xml_iter_node_value(&iter));
        } else if (xml_iter_node_name_match(&iter, "pwg:MakeAndModel")) {
            g_free(make_and_model);
            make_and_model = g_strdup(xml_iter_node_value(&iter));
        } else if (xml_iter_node_name_match(&iter, "scan:Platen")) {
            xml_iter_enter(&iter);
            if (xml_iter_node_name_match(&iter, "scan:PlatenInputCaps")) {
                err = devcaps_source_parse(&iter, &caps->src_platen );
            }
            xml_iter_leave(&iter);
        } else if (xml_iter_node_name_match(&iter, "scan:Adf")) {
            xml_iter_enter(&iter);
            while (!xml_iter_end(&iter)) {
                if (xml_iter_node_name_match(&iter, "scan:AdfSimplexInputCaps")) {
                    err = devcaps_source_parse(&iter, &caps->src_adf_simplex);
                } else if (xml_iter_node_name_match(&iter,
                        "scan:AdfDuplexInputCaps")) {
                    err = devcaps_source_parse(&iter, &caps->src_adf_duplex);
                }
                xml_iter_next(&iter);
            }
            xml_iter_leave(&iter);
        }

        if (err != NULL) {
            goto DONE;
        }
    }

    /* Save model, try to guess vendor */
    size_t model_len = model ? strlen(model) : 0;
    size_t make_and_model_len = make_and_model ? strlen(make_and_model) : 0;

    if (model_len && make_and_model_len > model_len &&
        g_str_has_suffix(make_and_model, model)) {

        caps->vendor = g_strndup(make_and_model,
                make_and_model_len - model_len);
        g_strchomp((char*) caps->vendor);
    }

    if (caps->vendor == NULL) {
        caps->vendor = g_strdup("Unknown");
    }

    if (model != NULL) {
        caps->model = model;
        model = NULL;
    } else if (make_and_model != NULL) {
        caps->model = make_and_model;
        make_and_model = NULL;
    }

    /* Update list of sources */
    if (caps->src_platen != NULL) {
        array_of_string_append(&caps->sources, OPTVAL_SOURCE_PLATEN);
    }

    if (caps->src_adf_simplex != NULL) {
        array_of_string_append(&caps->sources, OPTVAL_SOURCE_ADF_SIMPLEX);
    }

    if (caps->src_adf_duplex != NULL) {
        array_of_string_append(&caps->sources, OPTVAL_SOURCE_ADF_DUPLEX);
    }

DONE:
    if (err != NULL) {
        devcaps_reset(caps);
    }

    g_free(model);
    g_free(make_and_model);
    xml_iter_cleanup(&iter);

    return err;
}

/* Dump device capabilities, for debugging
 */
static void
devcaps_dump (const char *name, devcaps *caps)
{
    int i, j;
    GString *buf = g_string_new(NULL);

    DBG_PROTO(name, "===== device capabilities =====");
    DBG_PROTO(name, "  Model: %s", caps->model);
    DBG_PROTO(name, "  Vendor: %s", caps->vendor);
    g_string_truncate(buf, 0);
    for (i = 0; caps->sources[i] != NULL; i ++) {
        g_string_append_printf(buf, " \"%s\"", caps->sources[i]);
    }
    DBG_PROTO(name, "  Sources: %s", buf->str);

    struct { char *name; devcaps_source *src; } sources[] = {
        {OPTVAL_SOURCE_PLATEN, caps->src_platen},
        {OPTVAL_SOURCE_ADF_SIMPLEX, caps->src_adf_simplex},
        {OPTVAL_SOURCE_ADF_DUPLEX, caps->src_adf_duplex},
        {NULL, NULL}
    };

    for (i = 0; sources[i].name; i ++) {
        DBG_PROTO(name, "  %s:", sources[i].name);
        devcaps_source *src = sources[i].src;
        DBG_PROTO(name, "    Min Width/Height: %d/%d", src->min_width, src->min_height);
        DBG_PROTO(name, "    Max Width/Height: %d/%d", src->max_width, src->max_height);

        if (src->flags & DEVCAPS_SOURCE_RES_DISCRETE) {
            g_string_truncate(buf, 0);
            for (j = 0; j < (int) array_of_word_len(&src->resolutions); j ++) {
                g_string_append_printf(buf, " %d", src->resolutions[j+1]);
            }
            DBG_PROTO(name, "    Resolutions: %s", buf->str);
        }
    }

    g_string_free(buf, TRUE);
}

/******************** Device management ********************/
/* Device flags
 */
enum {
    DEVICE_RESOLVER_PENDING = (1 << 0), /* Pending service resolver */
    DEVICE_GETCAPS_PENDING  = (1 << 1), /* Pending get scanner capabilities */
    DEVICE_READY            = (1 << 2), /* Device is ready */
    DEVICE_HALTED           = (1 << 3), /* Device is halted */
    DEVICE_INIT_WAIT        = (1 << 4)  /* Device was found during initial
                                           scan and not ready yet */
};

/* Device descriptor
 */
typedef struct {
    /* Common part */
    volatile gint        refcnt;        /* Reference counter */
    const char           *name;         /* Device name */
    unsigned int         flags;         /* Device flags */
    devcaps              caps;          /* Device capabilities */

    /* I/O handling (AVAHI and HTTP) */
    AvahiServiceResolver *resolver;     /* Service resolver; may be NULL */
    SoupURI              *base_url;     /* eSCL base URI */
    GPtrArray            *http_pending; /* Pending HTTP requests */
} device;

/* Static variables
 */
static GTree *device_table;
static GCond device_table_cond;

static SoupSession *device_http_session;

/* Forward declarations
 */
static void
device_del_callback (gpointer p);

static void
device_scanner_capabilities_callback (device *dev, SoupMessage *msg);

static void
device_http_get (device *dev, const char *path,
        void (*callback)(device*, SoupMessage*));

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
    g_cond_init(&device_table_cond);
    device_table = g_tree_new_full(device_name_compare, NULL, NULL,
            device_del_callback);

    return SANE_STATUS_GOOD;
}

/* Cleanup device management
 */
static void
device_management_cleanup (void)
{
    g_cond_clear(&device_table_cond);
    g_tree_unref(device_table);
    device_table = NULL;
}

/* Start devices management. Called from the airscan thread
 */
static void
device_management_start (void)
{
    device_http_session = soup_session_new();
}

/* Finish device management. Called from the airscan thread
 */
static void
device_management_finish (void)
{
    soup_session_abort(device_http_session);
    g_object_unref(device_http_session);
    device_http_session = NULL;
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
    devcaps_init(&dev->caps);

    dev->http_pending = g_ptr_array_new();

    DBG_DEVICE(dev->name, "created");

    /* Add to the table */
    g_tree_insert(device_table, (gpointer) dev->name, dev);

    return dev;
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
    g_tree_remove(device_table, dev->name);
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
        g_assert(dev->flags & DEVICE_HALTED);

        /* Release all memory */
        g_free((void*) dev->name);

        devcaps_reset(&dev->caps);

        if (dev->base_url != NULL) {
            soup_uri_free(dev->base_url);
        }
        g_ptr_array_unref(dev->http_pending);

        g_free(dev);
    }
}

/* This callback is called by GTable, when device is removed
 * from device_table, either explicitly or by table destructor
 */
static void
device_del_callback (gpointer p)
{
    device *dev = p;

    /* Stop all pending I/O activity */
    if (dev->resolver != NULL) {
        avahi_service_resolver_free(dev->resolver);
        dev->resolver = NULL;
    }

    guint i;
    for (i = 0; i < dev->http_pending->len; i ++) {
        soup_session_cancel_message(device_http_session,
                g_ptr_array_index(dev->http_pending, i), SOUP_STATUS_CANCELLED);
    }

    dev->flags |= DEVICE_HALTED;
    dev->flags &= ~DEVICE_READY;

    /* Unref the device */
    device_unref(dev);
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

    char str_addr[128], *url;

    avahi_address_snprint(str_addr, sizeof(str_addr), addr);

    if (rs_text != NULL) {
        url = g_strdup_printf("http://%s:%d/%s/", str_addr, port,
                rs_text);
    } else {
        url = g_strdup_printf("http://%s:%d/", str_addr, port);
    }

    dev->base_url = soup_uri_new(url);
    DBG_DEVICE(dev->name, "url=\"%s\"", url);

    /* Fetch device capabilities */
    device_http_get(dev, "ScannerCapabilities",
            device_scanner_capabilities_callback);
}

/* Find device in a table
 */
static device*
device_find (const char *name)
{
    return g_tree_lookup(device_table, name);
}

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
        device_del(dev);
    } else {
        dev->flags |= DEVICE_READY;
        dev->flags &= ~DEVICE_INIT_WAIT;
    }

    g_cond_broadcast(&device_table_cond);
}

/* User data, associated with each HTTP message
 */
typedef struct {
    device *dev;
    void   (*callback)(device *dev, SoupMessage *msg);
} device_http_userdata;

/* HTTP request completion callback
 */
static void
device_http_callback(SoupSession *session, SoupMessage *msg, gpointer userdata)
{
    (void) session;

    if (msg->status_code != SOUP_STATUS_CANCELLED) {
        device_http_userdata *data = userdata;
        g_ptr_array_remove(data->dev->http_pending, msg);
        data->callback(data->dev, msg);
    }

    g_free(userdata);
}

/* Initiate HTTP request
 */
static void
device_http_get (device *dev, const char *path,
        void (*callback)(device*, SoupMessage*))
{
    (void) dev;
    (void) path;

    SoupURI *url = soup_uri_new_with_base(dev->base_url, path);
    SoupMessage *msg = soup_message_new_from_uri("GET", url);
    soup_uri_free(url);

    device_http_userdata *data = g_new0(device_http_userdata, 1);
    data->dev = dev;
    data->callback = callback;

    soup_session_queue_message(device_http_session, msg,
            device_http_callback, data);
    g_ptr_array_add(dev->http_pending, msg);
}

/******************** GLIB integration ********************/
/* GLIB stuff
 */
static GThread *glib_thread;
static GMainContext *glib_main_context;
static GMainLoop *glib_main_loop;
G_LOCK_DEFINE_STATIC(glib_main_loop);

/* Forward declarations
 */
static gint
glib_poll_hook (GPollFD *ufds, guint nfsd, gint timeout);

/* Initialize GLIB integration
 */
static SANE_Status
glib_init (void)
{
    glib_main_context = g_main_context_new();
    glib_main_loop = g_main_loop_new(glib_main_context, FALSE);
    g_main_context_set_poll_func(glib_main_context, glib_poll_hook);

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

/* Poll function hook
 */
static gint
glib_poll_hook (GPollFD *ufds, guint nfds, gint timeout)
{
    G_UNLOCK(glib_main_loop);
    gint ret = g_poll(ufds, nfds, timeout);
    G_LOCK(glib_main_loop);

    return ret;
}

/* GLIB thread main function
 */
static gpointer
glib_thread_func (gpointer data)
{
    (void) data;

    G_LOCK(glib_main_loop);

    g_main_context_push_thread_default(glib_main_context);
    device_management_start();
    g_main_loop_run(glib_main_loop);
    device_management_finish();

    G_UNLOCK(glib_main_loop);

    return NULL;
}

/* Start GLIB thread. All background operations (AVAHI service discovery,
 * HTTP transfers) are performed on a context of this thread
 */
static void
glib_thread_start (void) {
    glib_thread = g_thread_new("airscan", glib_thread_func, NULL);

    /* Wait until thread is started. Otherwise, g_main_loop_quit()
     * might not terminate the thread
     */
    gulong usec = 100;
    while (!g_main_loop_is_running(glib_main_loop)) {
        g_usleep(usec);
        usec += usec;
    }
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
static SANE_Bool dd_avahi_browser_init_wait;

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
    dev->flags &= ~DEVICE_RESOLVER_PENDING;

    switch (event) {
    case AVAHI_RESOLVER_FOUND:
        DBG_DISCOVERY(name, "resolver: OK");
        device_resolver_done(dev, addr, port, txt);
        break;

    case AVAHI_RESOLVER_FAILURE:
        DBG_DISCOVERY(name, "resolver: %s", dd_avahi_strerror());
        device_del(dev);
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

    device *dev;

    switch (event) {
    case AVAHI_BROWSER_NEW:
        DBG_DISCOVERY(name, "found");

        /* Check for duplicate device */
        if (device_find (name) ) {
            DBG_DISCOVERY(name, "already known; ignoring");
            break;
        }

        dev = device_add(name);
        if (dd_avahi_browser_init_wait) {
            dev->flags = DEVICE_INIT_WAIT;
        }

        /* Initiate resolver */
        AvahiServiceResolver *r;
        r = avahi_service_resolver_new(dd_avahi_client, interface, protocol,
                name, type, domain, AVAHI_PROTO_UNSPEC, 0,
                dd_avahi_resolver_callback, dev);

        if (r == NULL) {
            DBG_DISCOVERY(name, "%s", dd_avahi_strerror());
            device_del(dev);
            dd_avahi_client_restart_defer();
            break;
        }

        /* Attach resolver to device */
        dev->resolver = r;
        dev->flags |= DEVICE_RESOLVER_PENDING;
        break;

    case AVAHI_BROWSER_REMOVE:
        DBG_DISCOVERY(name, "removed");
        device *dev = device_find(name);
        if (dev != NULL) {
            device_del(dev);
        }
        break;

    case AVAHI_BROWSER_FAILURE:
        dd_avahi_client_restart_defer();
        break;

    case AVAHI_BROWSER_CACHE_EXHAUSTED:
    case AVAHI_BROWSER_ALL_FOR_NOW:
        dd_avahi_browser_init_wait = FALSE;
        g_cond_broadcast(&device_table_cond);
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

    dd_avahi_client_start();
}

/* Stop AVAHI client
 */
static void
dd_avahi_client_stop (void)
{
    if (dd_avahi_client != NULL) {
        device **unresolved = g_newa(device*, device_table_size());
        unsigned int i, count;

        count = device_table_collect(DEVICE_RESOLVER_PENDING, unresolved);
        for (i = 0; i < count; i ++) {
                unresolved[i]->resolver = NULL;
                device_del(unresolved[i]);
        }

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

        dd_avahi_browser_init_wait = FALSE;
        g_cond_broadcast(&device_table_cond);
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

    dd_avahi_browser_init_wait = TRUE;

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
        dd_avahi_browser_init_wait = FALSE;
    }
}

/******************** SANE API ********************/
/* Static variables
 */
static const SANE_Device **sane_device_list;

/* Initialize the backend
 */
SANE_Status
sane_init (SANE_Int *version_code, SANE_Auth_Callback authorize)
{
    SANE_Status status;

    DBG_API_ENTER();

    if (version_code != NULL) {
        *version_code = SANE_VERSION_CODE (SANE_CURRENT_MAJOR,
                SANE_CURRENT_MINOR, 0);
    }

    (void) authorize;

    /* Initialize all parts */
    status = glib_init();
    if (status == SANE_STATUS_GOOD) {
        device_management_init();
    }
    if (status == SANE_STATUS_GOOD) {
        status = dd_init();
    }

    if (status != SANE_STATUS_GOOD) {
        sane_exit();
    }

    /* Start airscan thread */
    glib_thread_start();

    DBG_API_LEAVE();

    return status;
}

/* Exit the backend
 */
void
sane_exit (void)
{
    DBG_API_ENTER();

    glib_thread_stop();

    dd_cleanup();
    device_management_cleanup();
    glib_cleanup();

    if (sane_device_list != NULL) {
        unsigned int i;
        const SANE_Device *info;

        for (i = 0; (info = sane_device_list[i]) != NULL; i ++) {
            g_free((void*) info->name);
            g_free((void*) info->vendor);
            g_free((void*) info->model);
            g_free((void*) info);
        }
        g_free(sane_device_list);
        sane_device_list = NULL;
    }

    DBG_API_LEAVE();
}

/* Get list of devices
 */
SANE_Status
sane_get_devices (const SANE_Device ***device_list, SANE_Bool local_only)
{
    DBG_API_ENTER();

    /* All our devices are non-local */
    if (local_only) {
        static const SANE_Device *empty_devlist[1] = { 0 };
        *device_list = empty_devlist;
        return SANE_STATUS_GOOD;
    }

    /* Acquire main loop lock */
    G_LOCK(glib_main_loop);

    /* Wait until table is ready */
    gint64 timeout = g_get_monotonic_time() +
            DEVICE_TABLE_READY_TIMEOUT * G_TIME_SPAN_SECOND;

    while ((!device_table_ready() || dd_avahi_browser_init_wait) &&
            g_get_monotonic_time() < timeout) {
        g_cond_wait_until(&device_table_cond,
                &G_LOCK_NAME(glib_main_loop), timeout);
    }

    /* Prepare response */
    device **devlist = g_newa(device*, device_table_size());
    unsigned int count = device_table_collect(DEVICE_READY, devlist);
    unsigned int i;

    sane_device_list = g_new0(const SANE_Device*, count + 1);
    for (i = 0; i < count; i ++) {
        SANE_Device *out = g_new0(SANE_Device, 1);
        sane_device_list[i] = out;

        out->name = g_strdup(devlist[i]->name);
        out->vendor = g_strdup(devlist[i]->caps.vendor);
        out->model = g_strdup(devlist[i]->caps.model);
        out->type = "eSCL network scanner";
    }

    *device_list = sane_device_list;

    /* Cleanup and exit */
    G_UNLOCK(glib_main_loop);

    DBG_API_LEAVE();

    return SANE_STATUS_GOOD;
}

/* Open the device
 */
SANE_Status
sane_open (SANE_String_Const name, SANE_Handle *handle)
{
    DBG_API_ENTER();

    G_LOCK(glib_main_loop);

    device *dev = device_find(name);
    SANE_Status status = SANE_STATUS_INVAL;
    if (dev != NULL && (dev->flags & DEVICE_READY) != 0) {
        *handle = (SANE_Handle) device_ref(dev);
        status = SANE_STATUS_GOOD;
    }

    G_UNLOCK(glib_main_loop);

    DBG_API_LEAVE();

    return status;
}

/* Close the device
 */
void
sane_close (SANE_Handle handle)
{
    DBG_API_ENTER();

    G_LOCK(glib_main_loop);
    device_unref((device*) handle);
    G_UNLOCK(glib_main_loop);

    DBG_API_LEAVE();
}

/* Get option descriptor
 */
const SANE_Option_Descriptor *
sane_get_option_descriptor (SANE_Handle handle, SANE_Int option)
{
    DBG_API_ENTER();

    (void) handle;
    (void) option;

    DBG_API_LEAVE();

    return NULL;
}

/* Get or set option value
 */
SANE_Status
sane_control_option (SANE_Handle handle, SANE_Int option, SANE_Action action,
                     void *value, SANE_Int *info)
{
    DBG_API_ENTER();

    (void) handle;
    (void) option;
    (void) action;
    (void) value;
    (void) info;

    DBG_API_LEAVE();

    return SANE_STATUS_UNSUPPORTED;
}

/* Get current scan parameters
 */
SANE_Status
sane_get_parameters (SANE_Handle handle, SANE_Parameters *params)
{
    DBG_API_ENTER();

    (void) handle;
    (void) params;

    DBG_API_LEAVE();

    return SANE_STATUS_INVAL;
}

/* Start scanning operation
 */
SANE_Status
sane_start (SANE_Handle handle)
{
    DBG_API_ENTER();

    (void) handle;

    DBG_API_LEAVE();

    return SANE_STATUS_INVAL;
}

/* Read scanned image
 */
SANE_Status
sane_read (SANE_Handle handle, SANE_Byte *data,
           SANE_Int max_length, SANE_Int *length)
{
    DBG_API_ENTER();

    (void) handle;
    (void) data;
    (void) max_length;
    (void) length;

    DBG_API_LEAVE();

    return SANE_STATUS_INVAL;
}

/* Cancel scanning operation
 */
void
sane_cancel (SANE_Handle handle)
{
    DBG_API_ENTER();

    (void) handle;

    DBG_API_LEAVE();
}

/* Set I/O mode
 */
SANE_Status
sane_set_io_mode (SANE_Handle handle, SANE_Bool non_blocking)
{
    DBG_API_ENTER();

    (void) handle;
    (void) non_blocking;

    DBG_API_LEAVE();

    return SANE_STATUS_GOOD;
}

/* Get select file descriptor
 */
SANE_Status
sane_get_select_fd (SANE_Handle handle, SANE_Int * fd)
{
    DBG_API_ENTER();

    (void) handle;

    *fd = -1;

    DBG_API_LEAVE();

    return SANE_STATUS_UNSUPPORTED;
}

/******************** API aliases for libsane-dll ********************/
SANE_Status __attribute__ ((alias ("sane_init")))
sane_airscan_init (SANE_Int *version_code, SANE_Auth_Callback authorize);

void __attribute__ ((alias ("sane_exit")))
sane_airscan_exit (void);

SANE_Status __attribute__ ((alias ("sane_get_devices")))
sane_airscan_get_devices (const SANE_Device ***device_list, SANE_Bool local_only);

SANE_Status __attribute__ ((alias ("sane_open")))
sane_airscan_open (SANE_String_Const devicename, SANE_Handle *handle);

void __attribute__ ((alias ("sane_close")))
sane_airscan_close (SANE_Handle handle);

const SANE_Option_Descriptor * __attribute__ ((alias ("sane_get_option_descriptor")))
sane_airscan_get_option_descriptor (SANE_Handle handle, SANE_Int option);

SANE_Status __attribute__ ((alias ("sane_control_option")))
sane_airscan_control_option (SANE_Handle handle, SANE_Int option,
    SANE_Action action, void *value, SANE_Int *info);

SANE_Status __attribute__ ((alias ("sane_get_parameters")))
sane_airscan_get_parameters (SANE_Handle handle, SANE_Parameters *params);

SANE_Status __attribute__ ((alias ("sane_start")))
sane_airscan_start (SANE_Handle handle);

SANE_Status __attribute__ ((alias ("sane_read")))
sane_airscan_read (SANE_Handle handle, SANE_Byte *data,
           SANE_Int max_length, SANE_Int *length);

void __attribute__ ((alias ("sane_cancel")))
sane_airscan_cancel (SANE_Handle handle);

SANE_Status __attribute__ ((alias ("sane_set_io_mode")))
sane_airscan_set_io_mode (SANE_Handle handle, SANE_Bool non_blocking);

SANE_Status __attribute__ ((alias ("sane_get_select_fd")))
sane_airscan_get_select_fd (SANE_Handle handle, SANE_Int * fd);

/* vim:ts=8:sw=4:et
 */
