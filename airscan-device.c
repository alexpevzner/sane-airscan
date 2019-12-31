/* AirScan (a.k.a. eSCL) backend for SANE
 *
 * Copyright (C) 2019 and up by Alexander Pevzner (pzz@apevzner.com)
 * See LICENSE for license terms and conditions
 *
 * Device management
 */

#include "airscan.h"

#include <stdlib.h>
#include <string.h>

/******************** Constants *********************/
/* Max time to wait until device table is ready, in seconds
 */
#define DEVICE_TABLE_READY_TIMEOUT              5

/******************** Device management ********************/
/* Device flags
 */
enum {
    DEVICE_LISTED           = (1 << 0), /* Device listed in device_table */
    DEVICE_READY            = (1 << 1), /* Device is ready */
    DEVICE_HALTED           = (1 << 2), /* Device is halted */
    DEVICE_INIT_WAIT        = (1 << 3), /* Device was found during initial
                                           scan and not ready yet */
    DEVICE_OPENED           = (1 << 4), /* Device currently opened */
    DEVICE_SCANNING         = (1 << 5), /* We are between sane_start() and
                                           final sane_read() */
    DEVICE_CLOSING          = (1 << 6), /* Close in progress */

    DEVICE_ALL_FLAGS        = 0xffffffff
};

/* Device states
 */
typedef enum {
    DEVICE_SCAN_IDLE,
    DEVICE_SCAN_STARTED,
    DEVICE_SCAN_REQUESTING,
    DEVICE_SCAN_LOADING,
    DEVICE_SCAN_CHECK_STATUS,
    DEVICE_SCAN_CLEANING_UP,

    DEVICE_SCAN_DONE

} DEVICE_STATE;

/* Device descriptor
 */
struct device {
    /* Common part */
    volatile gint        refcnt;        /* Reference counter */
    const char           *name;         /* Device name */
    unsigned int         flags;         /* Device flags */
    devopt               opt;           /* Device options */
    DEVICE_STATE         state;         /* Device state */
    GCond                state_cond;    /* Signaled when state changes */

    /* I/O handling (AVAHI and HTTP) */
    zeroconf_addrinfo    *addresses;    /* Device addresses, NULL if
                                           device was statically added */
    zeroconf_addrinfo    *addr_current; /* Current address to probe */
    http_uri             *uri_escl;     /* eSCL base URI */
    http_client          *http_client;  /* HTTP client */
    trace                *trace;        /* Protocol trace */

    /* Scanning state machinery */
    SANE_Status          job_status;          /* Job completion status */
    GString              *job_location;       /* Scanned page location */
    eloop_event          *job_cancel_event;   /* Cancel event */
    bool                 job_cancel_rq;       /* Cancel requested */
    GPtrArray            *job_images;         /* Array of SoupBuffer* */
    unsigned int         job_images_received; /* How many images received */
    SANE_Word            job_skip_x;          /* How much pixels to skip, */
    SANE_Word            job_skip_y;          /*    from left and top */

    /* Read machinery */
    SANE_Bool            read_non_blocking;  /* Non-blocking I/O mode */
    image_decoder        *read_decoder_jpeg; /* JPEG decoder */
    pollable             *read_pollable;     /* Signalled when read won't
                                                block */
    http_data            *read_image;        /* Current image */
    SANE_Byte            *read_line_buf;     /* Single-line buffer */
    SANE_Int             read_line_num;      /* Current image line 0-based */
    SANE_Int             read_line_end;      /* If read_line_num>read_line_end
                                                no more lines left in image */
    SANE_Int             read_line_off;      /* Current offset in the line */
    SANE_Int             read_skip_lines;    /* How many lines to skip */
    SANE_Int             read_skip_bytes;    /* How many bytes to skip at line
                                                beginning */
};

/* Static variables
 */
static GPtrArray *device_table;
static GCond device_table_cond;

/* Forward declarations
 */
static device*
device_find (const char *name);

static void
device_http_onerror (device *dev, error err);

static void
device_scanner_capabilities_callback (device *dev, http_query *q);

static void
device_probe_address (device *dev, zeroconf_addrinfo *addrinfo);

static void
device_job_set_status (device *dev, SANE_Status status);

static void
device_job_abort (device *dev, SANE_Status status);

static void
device_escl_load_page (device *dev);

static bool
device_read_push (device *dev);

static void
device_management_start_stop (bool start);

/******************** Device table management ********************/
/* Add device to the table
 */
static void
device_add (const char *name, zeroconf_addrinfo *addresses,
        bool init_scan, bool statically)
{
    device      *dev;

    /* Issue log message */
    log_debug(NULL, "%s adding: \"%s\"",
            statically ? "statically" : "dynamically", name);

    /* Don't allow duplicate devices */
    dev = device_find(name);
    if (dev != NULL) {
        log_debug(dev, "device already exist");
        return;
    }

    /* Create device */
    dev = g_new0(device, 1);

    dev->refcnt = 1;
    dev->name = g_strdup(name);
    dev->flags = DEVICE_LISTED | DEVICE_INIT_WAIT;
    if (init_scan) {
        dev->flags |= DEVICE_INIT_WAIT;
    }
    devopt_init(&dev->opt);

    dev->http_client = http_client_new(dev);
    dev->trace = trace_open(name);

    dev->job_location = g_string_new(NULL);
    g_cond_init(&dev->state_cond);
    dev->job_images = g_ptr_array_new();

    dev->read_decoder_jpeg = image_decoder_jpeg_new();
    dev->read_pollable = pollable_new();

    log_debug(dev, "device created");

    /* Add to the table */
    g_ptr_array_add(device_table, dev);

    /* Initialize device I/O */
    dev->addresses = zeroconf_addrinfo_list_copy(addresses);
    device_probe_address(dev, dev->addresses);

    return;
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
        log_debug(dev, "device destroyed");

        log_assert(dev, (dev->flags & DEVICE_LISTED) == 0);
        log_assert(dev, (dev->flags & DEVICE_HALTED) != 0);
        log_assert(dev, (dev->flags & DEVICE_OPENED) == 0);

        /* Release all memory */
        g_free((void*) dev->name);

        devopt_cleanup(&dev->opt);

        zeroconf_addrinfo_list_free(dev->addresses);

        http_uri_free(dev->uri_escl);
        http_client_free(dev->http_client);

        g_string_free(dev->job_location, TRUE);
        g_cond_clear(&dev->state_cond);
        g_ptr_array_free(dev->job_images, TRUE);

        image_decoder_free(dev->read_decoder_jpeg);
        pollable_free(dev->read_pollable);

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
    log_debug(dev, "removed from device table");
    log_assert(dev, (dev->flags & DEVICE_LISTED) != 0);

    dev->flags &= ~DEVICE_LISTED;
    g_ptr_array_remove(device_table, dev);

    /* Stop all pending I/O activity */
    http_client_cancel(dev->http_client);
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
    unsigned int i;

    for (i = 0; i < device_table->len; i ++) {
        device *dev = g_ptr_array_index(device_table, i);
        if (!strcmp(dev->name, name)) {
            return dev;
        }
    }

    return NULL;
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
    unsigned int x, y = 0;

    for (x = 0; x < device_table->len; x ++) {
        device *dev = g_ptr_array_index(device_table, x);
        if ((dev->flags & flags) != 0) {
            if (out != NULL) {
                out[y] = dev;
            }
            y ++;
        }
    }

    return y;
}

/* Get current device_table size
 */
static unsigned int
device_table_size (void)
{
    log_assert(NULL, device_table);
    return device_table->len;
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

/******************** Device state management ********************/
/* Get device state name, for debugging
 */
static inline const char*
device_state_name (DEVICE_STATE state)
{
    switch (state) {
    case DEVICE_SCAN_IDLE:         return "SCAN_IDLE";
    case DEVICE_SCAN_STARTED:      return "SCAN_STARTED";
    case DEVICE_SCAN_REQUESTING:   return "SCAN_REQUESTING";
    case DEVICE_SCAN_LOADING:      return "SCAN_LOADING";
    case DEVICE_SCAN_CHECK_STATUS: return "SCAN_CHECK_STATUS";
    case DEVICE_SCAN_CLEANING_UP:  return "SCAN_CLEANING_UP";
    case DEVICE_SCAN_DONE:         return "SCAN_DONE";
    }

    return "UNKNOWN";
}

/* Set device state
 */
static void
device_state_set (device *dev, DEVICE_STATE state)
{
    if (dev->state != state) {
        log_debug(dev, "state=%s", device_state_name(state));

        dev->state = state;
        g_cond_broadcast(&dev->state_cond);

        if (dev->state == DEVICE_SCAN_DONE) {
            if ((dev->flags & DEVICE_SCANNING) != 0) {
                pollable_signal(dev->read_pollable);
            }
        }
    }
}

/******************** HTTP operations ********************/
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
        const char *method, char *body,
        void (*callback)(device*, http_query *q))
{
    http_uri *uri = http_uri_new_relative(dev->uri_escl, path, true, false);
    http_query_new(dev->http_client, uri, method, body, "text/xml", callback);
}

/* Initiate HTTP GET request
 */
static void
device_http_get (device *dev, const char *path,
        void (*callback)(device*, http_query *q))
{
    device_http_perform(dev, path, "GET", NULL, callback);
}

/* http_client onerror callback
 */
static void
device_http_onerror (device *dev, error err) {
    log_debug(dev, ESTRING(err));
    device_state_set(dev, DEVICE_SCAN_DONE);
    device_job_set_status(dev, SANE_STATUS_IO_ERROR);
}

/******************** ESCL initialization ********************/
/* Probe next device address
 */
static void
device_probe_address (device *dev, zeroconf_addrinfo *addrinfo)
{
    /* Cleanup after previous probe */
    dev->addr_current = addrinfo;
    if (dev->uri_escl != NULL) {
        http_uri_free(dev->uri_escl);
    }

    /* Parse device URI */
    dev->uri_escl = http_uri_new(addrinfo->uri, true);
    log_assert(dev, dev->uri_escl != NULL);

    /* Make sure eSCL URI's path ends with '/' character */
    const char *path = http_uri_get_path(dev->uri_escl);
    if (!g_str_has_suffix(path, "/")) {
        size_t len = strlen(path);
        char *path2 = g_alloca(len + 2);
        memcpy(path2, path, len);
        path2[len] = '/';
        path2[len+1] = '\0';
        http_uri_set_path(dev->uri_escl, path2);
    }

    /* Fetch device capabilities */
    device_http_get(dev, "ScannerCapabilities",
            device_scanner_capabilities_callback);
}

/* ScannerCapabilities fetch callback
 */
static void
device_scanner_capabilities_callback (device *dev, http_query *q)
{
    error err = NULL;

    /* Check request status */
    err = http_query_error(q);
    if (err != NULL) {
        err = eloop_eprintf("ScannerCapabilities query: %s", ESTRING(err));
        goto DONE;
    }

    /* Parse XML response */
    http_data *data = http_query_get_response_data(q);
    err = devopt_import_caps(&dev->opt, data->bytes, data->size);

    if (err != NULL) {
        err = eloop_eprintf("ScannerCapabilities: %s", err);
        goto DONE;
    }

    devcaps_dump(dev->trace, &dev->opt.caps);

    /* Cleanup and exit */
DONE:
    if (err != NULL) {
        log_debug(dev, ESTRING(err));
        trace_error(dev->trace, err);

        if (dev->addr_current != NULL && dev->addr_current->next != NULL) {
            device_probe_address(dev, dev->addr_current->next);
        } else {
            device_del(dev);
        }
    } else {
        dev->flags |= DEVICE_READY;
        dev->flags &= ~DEVICE_INIT_WAIT;

        http_client_onerror(dev->http_client, device_http_onerror);
    }

    g_cond_broadcast(&device_table_cond);
}

/******************** ESCL scanning ********************/
/* HTTP DELETE ${dev->job_location} callback
 */
static void
device_escl_cleanup_callback (device *dev, http_query *q)
{
    (void) q;

    device_state_set(dev, DEVICE_SCAN_DONE);
}

/* ESCL: cleanup after scan (delete current job)
 *
 * HTTP DELETE ${dev->job_location}
 */
static void
device_escl_cleanup (device *dev)
{
    device_state_set(dev, DEVICE_SCAN_CLEANING_UP);

    device_http_perform(dev, dev->job_location->str, "DELETE", NULL,
            device_escl_cleanup_callback);
}

/* Parse ScannerStatus response.
 *
 * On success, returns NULL and `idle' is set to true
 * if scanner is idle
 */
static error
device_escl_scannerstatus_parse (const char *xml_text, size_t xml_len,
        SANE_Status *device_status, SANE_Status *adf_status)
{
    error  err = NULL;
    xml_rd *xml;

    *device_status = SANE_STATUS_GOOD;
    *adf_status = SANE_STATUS_GOOD;

    err = xml_rd_begin(&xml, xml_text, xml_len);
    if (err != NULL) {
        goto DONE;
    }

    if (!xml_rd_node_name_match(xml, "scan:ScannerStatus")) {
        err = ERROR("XML: missed scan:ScannerStatus");
        goto DONE;
    }

    xml_rd_enter(xml);
    for (; !xml_rd_end(xml); xml_rd_next(xml)) {
        if (xml_rd_node_name_match(xml, "pwg:State")) {
            const char *state = xml_rd_node_value(xml);
            if (!strcmp(state, "Idle")) {
                *device_status = SANE_STATUS_GOOD;
            }
        } else if (xml_rd_node_name_match(xml, "scan:AdfState")) {
            const char *state = xml_rd_node_value(xml);
            if (!strcmp(state, "ScannerAdfProcessing")) {
                *adf_status = SANE_STATUS_NO_DOCS;
            } else if (!strcmp(state, "ScannerAdfLoaded")) {
                *adf_status = SANE_STATUS_GOOD;
            }
        }
    }

DONE:
    xml_rd_finish(&xml);
    return err;
}

/* HTTP GET ${dev->uri_escl}/ScannerStatus callback
 */
static void
device_escl_check_status_callback (device *dev, http_query *q)
{
    error       err = NULL;
    SANE_Status status = SANE_STATUS_IO_ERROR, device_status, adf_status;

    /* Check request status */
    err = http_query_error(q);
    if (err != NULL) {
        err = eloop_eprintf("ScannerStatus query: %s", ESTRING(err));
        goto DONE;
    }

    /* Parse XML response */
    http_data *data = http_query_get_response_data(q);
    err = device_escl_scannerstatus_parse(data->bytes, data->size,
            &device_status, &adf_status);

    if (err != NULL) {
        err = eloop_eprintf("ScannerStatus: %s", err);
        goto DONE;
    }

    /* Decode scanner status */
    if (device_status != SANE_STATUS_GOOD) {
        status = device_status;
    } else if (dev->opt.src == OPT_SOURCE_PLATEN) {
        status = device_status;
        if (status == SANE_STATUS_GOOD) {
            status = SANE_STATUS_DEVICE_BUSY;
        }
    } else {
        status = adf_status;
        if (status == SANE_STATUS_GOOD) {
            status = SANE_STATUS_JAMMED;
        }
    }

    /* Cleanup and exit */
DONE:
    trace_printf(dev->trace, "-----");
    if (err != NULL) {
        trace_printf(dev->trace, "Error: %s", err);
    }

    trace_printf(dev->trace, "Device status: %s", sane_strstatus(device_status));
    trace_printf(dev->trace, "ADF status: %s", sane_strstatus(adf_status));
    trace_printf(dev->trace, "Job status: %s", sane_strstatus(status));
    trace_printf(dev->trace, "");

    device_job_set_status(dev, status);
    if (dev->job_location->len == 0) {
        device_state_set(dev, DEVICE_SCAN_DONE);
    } else {
        device_escl_cleanup(dev);
    }
}

/* ESCL: check scanner status (used after failed scan request to
 * clarify reasons)
 *
 * HTTP GET ${dev->uri_escl}/ScannerStatus
 */
static void
device_escl_check_status (device *dev)
{
    device_state_set(dev, DEVICE_SCAN_CHECK_STATUS);

    device_http_get(dev, "ScannerStatus",
            device_escl_check_status_callback);
}

/* HTTP GET ${dev->job_location}/NextDocument callback
 */
static void
device_escl_load_page_callback (device *dev, http_query *q)
{
    error err;

    /* Try to fetch next page until previous page fetched successfully */
    err = http_query_error(q);
    if (err == NULL) {
        http_data *data = http_query_get_response_data(q);

        g_ptr_array_add(dev->job_images, http_data_ref(data));
        dev->job_images_received ++;

        if (dev->job_images_received == 1) {
            if (!device_read_push(dev)) {
                device_job_abort(dev, SANE_STATUS_IO_ERROR);
                return;
            }
        }

        if (dev->opt.src == OPT_SOURCE_PLATEN) {
            device_escl_cleanup(dev);
        } else {
            device_escl_load_page(dev);
        }
    } else {
        device_escl_check_status(dev);
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

    device_state_set(dev, DEVICE_SCAN_LOADING);

    device_http_get(dev, dev->job_location->str, device_escl_load_page_callback);
    g_string_truncate(dev->job_location, sz);
}

/* HTTP POST ${dev->uri_escl}/ScanJobs callback
 */
static void
device_escl_start_scan_callback (device *dev, http_query *q)
{
    error       err;
    const char  *location;
    SANE_Status status = SANE_STATUS_GOOD;
    http_uri    *uri;

    /* Check HTTP status */
    err = http_query_transport_error(q);
    if (err != NULL) {
        err = eloop_eprintf("ScanJobs request: %s", ESTRING(err));
        status = SANE_STATUS_IO_ERROR;
        goto DONE;
    }

    if (http_query_status(q) != HTTP_STATUS_CREATED) {
        err = eloop_eprintf("ScanJobs request: unexpected HTTP status %s",
                http_query_status(q));
        goto DONE;
    }

    /* Obtain location */
    location = http_query_get_response_header(q, "Location");
    if (location == NULL || *location == '\0') {
        err = eloop_eprintf("ScanJobs request: empty location received");
        status = SANE_STATUS_IO_ERROR;
        goto DONE;
    }

    /* Validate and save location */
    uri = http_uri_new_relative(dev->uri_escl, location, true, true);
    if (uri == NULL) {
        err = eloop_eprintf("ScanJobs request: invalid location received");
        status = SANE_STATUS_IO_ERROR;
        goto DONE;
    }

    g_string_assign(dev->job_location, http_uri_get_path(uri));
    http_uri_free(uri);

    /* Check for pending cancellation */
    if (dev->job_cancel_rq) {
        device_job_set_status(dev, SANE_STATUS_CANCELLED);
        device_escl_cleanup(dev);
        return;
    }

    /* Start loading pages */
    device_escl_load_page(dev);
    return;

    /* Cleanup and exit */
DONE:
    log_debug(dev, ESTRING(err));
    trace_error(dev->trace, err);

    if (status == SANE_STATUS_GOOD) {
        device_escl_check_status(dev);
    } else {
        device_job_set_status(dev, status);
        device_state_set(dev, DEVICE_SCAN_DONE);
    }
}

/* Geometrical scan parameters
 */
typedef struct {
    SANE_Word off;   /* Requested X/Y offset, in pixels assuming 300 DPI */
    SANE_Word len;   /* Requested width/height, in pixels, assuming 300 DPI */
    SANE_Word skip;  /* Pixels to skip in returned image, in pixels assuming
                        actual resolution */
}
device_geom;

/*
 * Computing geometrical scan parameters
 *
 * Input:
 *   tl, br         - top-left, bottom-rights X/Y, in mm
 *   minlen, maxlen - device-defined min and max width or height,
 *                    in pixels, assuming 300 dpi
 *   res            - scan resolution
 *
 * Output:
 *   Filled device_geom structure
 *
 * Problem description.
 *
 *   First of all, we use 3 different units to deal with geometrical
 *   parameters:
 *     1) we communicate with frontend in millimeters
 *     2) we communicate with scanner in pixels, assuming 300 DPI
 *     3) when we deal with image, sizes are in pixels in real
 *        resolution
 *
 *   Second, scanner returns minimal and maximal window size, but
 *   to simplify frontend's life, we pretend there is no such thing,
 *   as a minimal width or height, otherwise TL and BR ranges become
 *   dependent from each other. Instead, we always request image from
 *   scanner not smaller that scanner's minimum, and clip excessive
 *   image parts, if required.
 *
 *   This all makes things non-trivial. This function handles
 *   this complexity
 */
static device_geom
device_geom_compute (SANE_Fixed tl, SANE_Fixed br,
        SANE_Word minlen, SANE_Word maxlen, SANE_Word res)
{
    device_geom geom;

    geom.off = math_mm2px(tl);
    geom.len = math_mm2px(br - tl);
    geom.skip = 0;

    minlen = math_max(minlen, 1);
    geom.len = math_bound(geom.len, minlen, maxlen);

    if (geom.off + geom.len > maxlen) {
        geom.skip = geom.off + geom.len - maxlen;
        geom.off -= geom.skip;

        geom.skip = math_muldiv(geom.skip, res, 300);
    }

    return geom;
}

/* ESCL: start scanning
 *
 * HTTP POST ${dev->uri_escl}/ScanJobs
 */
static void
device_escl_start_scan (device *dev)
{
    const char     *source = NULL;
    const char     *colormode = NULL;
    bool           duplex = false;
    const char     *mime = "image/jpeg";
    //const char     *mime = "application/pdf";
    SANE_Word      x_resolution = dev->opt.resolution;
    SANE_Word      y_resolution = dev->opt.resolution;
    devcaps_source *src = dev->opt.caps.src[dev->opt.src];
    device_geom    geom_x, geom_y;
    char           buf[64];

    /* Prepare window parameters */
    geom_x = device_geom_compute(dev->opt.tl_x, dev->opt.br_x,
        src->min_wid_px, src->max_wid_px, x_resolution);

    geom_y = device_geom_compute(dev->opt.tl_y, dev->opt.br_y,
        src->min_hei_px, src->max_hei_px, y_resolution);

    dev->job_skip_x = geom_x.skip;
    dev->job_skip_y = geom_y.skip;

    /* Prepare other parameters */
    switch (dev->opt.src) {
    case OPT_SOURCE_PLATEN:      source = "Platen"; duplex = false; break;
    case OPT_SOURCE_ADF_SIMPLEX: source = "Feeder"; duplex = false; break;
    case OPT_SOURCE_ADF_DUPLEX:  source = "Feeder"; duplex = true; break;

    default:
        log_internal_error(dev);
    }

    switch (dev->opt.colormode) {
    case OPT_COLORMODE_COLOR:     colormode = "RGB24"; break;
    case OPT_COLORMODE_GRAYSCALE: colormode = "Grayscale8"; break;
    case OPT_COLORMODE_LINEART:   colormode = "BlackAndWhite1"; break;

    default:
        log_internal_error(dev);
    }

    /* Dump parameters */
    trace_printf(dev->trace, "==============================");
    trace_printf(dev->trace, "Starting scan, using the following parameters:");
    trace_printf(dev->trace, "  source:         %s", source);
    trace_printf(dev->trace, "  colormode:      %s", colormode);
    trace_printf(dev->trace, "  tl_x:           %s mm",
            math_fmt_mm(dev->opt.tl_x, buf));
    trace_printf(dev->trace, "  tl_y:           %s mm",
            math_fmt_mm(dev->opt.tl_y, buf));
    trace_printf(dev->trace, "  br_x:           %s mm",
            math_fmt_mm(dev->opt.br_x, buf));
    trace_printf(dev->trace, "  br_y:           %s mm",
            math_fmt_mm(dev->opt.br_y, buf));
    trace_printf(dev->trace, "  image size:     %dx%d", geom_x.len, geom_y.len);
    trace_printf(dev->trace, "  image X offset: %d", geom_x.off);
    trace_printf(dev->trace, "  image Y offset: %d", geom_y.off);
    trace_printf(dev->trace, "  x_resolution:   %d", x_resolution);
    trace_printf(dev->trace, "  y_resolution:   %d", y_resolution);
    trace_printf(dev->trace, "  image format:   %s", mime);
    trace_printf(dev->trace, "  duplex:         %s", duplex ? "true" : "false");
    trace_printf(dev->trace, "");

    /* Build scan request */
    xml_wr *xml = xml_wr_begin("scan:ScanSettings");

    xml_wr_add_text(xml, "pwg:Version", "2.0");

    xml_wr_enter(xml, "pwg:ScanRegions");
    xml_wr_enter(xml, "pwg:ScanRegion");
    xml_wr_add_text(xml, "pwg:ContentRegionUnits",
            "escl:ThreeHundredthsOfInches");
    xml_wr_add_uint(xml, "pwg:XOffset", geom_x.off);
    xml_wr_add_uint(xml, "pwg:YOffset", geom_y.off);
    xml_wr_add_uint(xml, "pwg:Width", geom_x.len);
    xml_wr_add_uint(xml, "pwg:Height", geom_y.len);
    xml_wr_leave(xml); /* pwg:ScanRegion */
    xml_wr_leave(xml); /* pwg:ScanRegions */

    //xml_wr_add_text(xml, "scan:InputSource", source);
    xml_wr_add_text(xml, "pwg:InputSource", source);
    xml_wr_add_text(xml, "scan:ColorMode", colormode);
    //xml_wr_add_text(xml, "scan:DocumentFormatExt", mime);
    xml_wr_add_text(xml, "pwg:DocumentFormat", mime);
    xml_wr_add_uint(xml, "scan:XResolution", x_resolution);
    xml_wr_add_uint(xml, "scan:YResolution", y_resolution);
    if (dev->opt.src != OPT_SOURCE_PLATEN) {
        xml_wr_add_bool(xml, "scan:Duplex", duplex);
    }

    /* Send request to device */
    device_state_set(dev, DEVICE_SCAN_REQUESTING);
    device_http_perform(dev, "ScanJobs", "POST", xml_wr_finish(xml),
            device_escl_start_scan_callback);
}

/******************** Scan Job management ********************/
/* Set job status. If status already set, it will not be
 * changed
 */
static void
device_job_set_status (device *dev, SANE_Status status)
{
    if (dev->job_status == SANE_STATUS_GOOD ||
        status == SANE_STATUS_CANCELLED) {
        log_debug(dev, "JOB status=%s", sane_strstatus(status));
        dev->job_status = status;
    }
}

/* Abort the job with specified status code
 */
static void
device_job_abort (device *dev, SANE_Status status)
{
    if (dev->job_cancel_rq) {
        return; /* We are already working on it */
    }

    if (dev->state != DEVICE_SCAN_IDLE) {
        log_debug(dev, "JOB aborted: %s", sane_strstatus(status));
    }

    switch (dev->state) {
    case DEVICE_SCAN_IDLE:
    case DEVICE_SCAN_DONE:
        /* Nothing to do */
        break;

    case DEVICE_SCAN_STARTED:
    case DEVICE_SCAN_REQUESTING:
        dev->job_cancel_rq = true;
        break;

    case DEVICE_SCAN_LOADING:
    case DEVICE_SCAN_CHECK_STATUS:
        http_client_cancel(dev->http_client);
        /* Fall through...*/

    case DEVICE_SCAN_CLEANING_UP:
        device_job_set_status(dev, status);

        if (dev->state == DEVICE_SCAN_LOADING) {
            device_escl_cleanup(dev);
        }

        if (dev->state != DEVICE_SCAN_CLEANING_UP) {
            device_state_set(dev, DEVICE_SCAN_DONE);
        }
        break;
    }
}

/* dev->job_cancel_event callback
 */
static void
device_job_cancel_event_callback (void *data)
{
    device *dev = data;

    log_debug(dev, "cancel requested");
    if ((dev->flags & (DEVICE_SCANNING | DEVICE_CLOSING)) != 0) {
        device_job_abort(dev, SANE_STATUS_CANCELLED);
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

/* Compare SANE_Device*, for qsort
 */
static int
device_list_qsort_cmp (const void *p1, const void *p2)
{
    return strcmp(((SANE_Device*) p1)->name, ((SANE_Device*) p2)->name);
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
        info->vendor = g_strdup(devices[i]->opt.caps.vendor);
        info->model = g_strdup(devices[i]->opt.caps.model);
        info->type = "eSCL network scanner";
    }

    qsort(dev_list, count, sizeof(*dev_list), device_list_qsort_cmp);

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

/* Get device name (mostly for debugging
 */
const char*
device_name (device *dev)
{
    return dev->name;
}

/* Get device's trace handle
 */
trace*
device_trace (device *dev)
{
    return dev->trace;
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
    dev->job_cancel_event = eloop_event_new(device_job_cancel_event_callback, dev);
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
        /* Cancel job in progress, if any */
        if (dev->state != DEVICE_SCAN_IDLE && dev->state != DEVICE_SCAN_DONE) {
            dev->flags |= DEVICE_CLOSING;
            device_cancel(dev);

            while (dev->state != DEVICE_SCAN_DONE) {
                eloop_cond_wait(&dev->state_cond);
            }
        }

        /* Close the device */
        eloop_event_free(dev->job_cancel_event);
        dev->job_cancel_event = NULL;
        dev->flags &= ~(DEVICE_OPENED | DEVICE_CLOSING);
        device_unref(dev);
    }
}

/* Get option descriptor
 */
const SANE_Option_Descriptor*
device_get_option_descriptor (device *dev, SANE_Int option)
{
    if (0 <= option && option < NUM_OPTIONS) {
        return &dev->opt.desc[option];
    }

    return NULL;
}

/* Get device option
 */
SANE_Status
device_get_option (device *dev, SANE_Int option, void *value)
{
    return devopt_get_option(&dev->opt, option, value);
}

/* Set device option
 */
SANE_Status
device_set_option (device *dev, SANE_Int option, void *value, SANE_Word *info)
{
    if ((dev->flags & DEVICE_SCANNING) != 0) {
        return SANE_STATUS_INVAL;
    }

    return devopt_set_option(&dev->opt, option, value, info);
}

/* Get current scan parameters
 */
SANE_Status
device_get_parameters (device *dev, SANE_Parameters *params)
{
    *params = dev->opt.params;
    return SANE_STATUS_GOOD;
}

/* Start scanning operation - runs on a context of event loop thread
 */
static gboolean
device_start_do (gpointer data)
{
    device      *dev = data;

    if (dev->job_cancel_rq) {
        device_state_set(dev, DEVICE_SCAN_DONE);
        device_job_set_status(dev, SANE_STATUS_CANCELLED);
    } else {
        device_escl_start_scan(dev);
    }

    return FALSE;
}

/* Start scanning operation
 */
SANE_Status
device_start (device *dev)
{
    /* Already scanning? */
    if ((dev->flags & DEVICE_SCANNING) != 0) {
        return SANE_STATUS_INVAL;
    }

    /* Don's start if window is not valid */
    if (dev->opt.params.lines == 0 || dev->opt.params.pixels_per_line == 0) {
        return SANE_STATUS_INVAL;
    }

    /* Update state */
    dev->flags |= DEVICE_SCANNING;
    pollable_reset(dev->read_pollable);
    dev->read_non_blocking = SANE_FALSE;

    /* Previous multi-page scan job may still be running. Check
     * its state */
    if (dev->state != DEVICE_SCAN_IDLE) {
        if (dev->job_images->len != 0) {
            /* We have more buffered images */
            if (device_read_push(dev)) {
                return SANE_STATUS_GOOD;
            }

            device_job_set_status(dev, SANE_STATUS_IO_ERROR);
            device_cancel(dev);
        }

        /* Just wait until previous job completion */
        while (dev->state != DEVICE_SCAN_DONE) {
            eloop_cond_wait(&dev->state_cond);
        }

        if (dev->job_status != SANE_STATUS_GOOD) {
            goto FAIL;
        }
    }

    /* Start new scan job */
    device_state_set(dev, DEVICE_SCAN_STARTED);
    dev->job_status = SANE_STATUS_GOOD;
    g_string_truncate(dev->job_location, 0);
    dev->job_cancel_rq = false;
    dev->job_images_received = 0;

    eloop_call(device_start_do, dev);

    /* And wait until it reaches "LOADING" state */
    while (dev->state != DEVICE_SCAN_LOADING) {
        if (dev->state == DEVICE_SCAN_DONE) {
            goto FAIL;
        }

        eloop_cond_wait(&dev->state_cond);
    }

    return SANE_STATUS_GOOD;

    /* Cleanup after error */
FAIL:
    device_state_set(dev, DEVICE_SCAN_IDLE);
    dev->flags &= ~DEVICE_SCANNING;

    return dev->job_status;
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

/* Set I/O mode
 */
SANE_Status
device_set_io_mode (device *dev, SANE_Bool non_blocking)
{
    if ((dev->flags & DEVICE_SCANNING) == 0) {
        return SANE_STATUS_INVAL;
    }

    dev->read_non_blocking = non_blocking;
    return SANE_STATUS_GOOD;
}

/* Get select file descriptor
 */
SANE_Status
device_get_select_fd (device *dev, SANE_Int *fd)
{
    if ((dev->flags & DEVICE_SCANNING) == 0) {
        return SANE_STATUS_INVAL;
    }

    *fd = pollable_get_fd(dev->read_pollable);
    return SANE_STATUS_GOOD;
}


/******************** Read machinery ********************/
/* Push next image to reader. Returns false, if image
 * decoding cannot be started
 */
static bool
device_read_push (device *dev)
{
    error           err;
    size_t          line_capacity;
    SANE_Parameters params;
    image_decoder   *decoder = dev->read_decoder_jpeg;
    int             wid, hei;

    dev->read_image = g_ptr_array_remove_index(dev->job_images, 0);

    /* Start new image decoding */
    err = image_decoder_begin(decoder,
            dev->read_image->bytes, dev->read_image->size);

    if (err != NULL) {
        goto DONE;
    }

    /* Obtain and validate image parameters */
    image_decoder_get_params(decoder, &params);
    if (params.format != dev->opt.params.format) {
        /* This is what we cannot handle */
        err = ERROR("Unexpected image format");
        goto DONE;
    }

    wid = params.pixels_per_line;
    hei = params.lines;

    /* Dump parameters */
    trace_printf(dev->trace, "==============================");
    trace_printf(dev->trace, "Starting image decoding, image parameters are:");
    trace_printf(dev->trace, "  content type:   %s", image_content_type(decoder));
    trace_printf(dev->trace, "  frame format:   %s",
            params.format == SANE_FRAME_GRAY ? "Gray" : "RGB" );
    trace_printf(dev->trace, "  image size:     %dx%d", params.pixels_per_line,
            params.lines);
    trace_printf(dev->trace, "  color depth:    %d", params.depth);
    trace_printf(dev->trace, "");

    /* Setup image clipping */
    if (dev->job_skip_x >= wid || dev->job_skip_y >= hei) {
        /* Trivial case - just skip everything */
        dev->read_skip_lines = hei;
        dev->read_skip_bytes = 0;
        line_capacity = dev->opt.params.bytes_per_line;
    } else {
        image_window win;
        int          bpp = image_decoder_get_bytes_per_pixel(decoder);

        win.x_off = dev->job_skip_x;
        win.y_off = dev->job_skip_y;
        win.wid = wid - dev->job_skip_x;
        win.hei = hei - dev->job_skip_y;

        err = image_decoder_set_window(decoder, &win);
        if (err != NULL) {
            goto DONE;
        }

        dev->read_skip_bytes = 0;
        if (win.x_off != dev->job_skip_x) {
            dev->read_skip_bytes = bpp * (dev->job_skip_x - win.x_off);
        }

        dev->read_skip_lines = 0;
        if (win.y_off != dev->job_skip_y) {
            dev->read_skip_lines = dev->job_skip_y - win.y_off;
        }

        line_capacity = math_max(dev->opt.params.bytes_per_line, wid * bpp);
    }

    /* Initialize image decoding */
    dev->read_line_buf = g_malloc(line_capacity);
    memset(dev->read_line_buf, 0xff, line_capacity);

    dev->read_line_num = 0;
    dev->read_line_off = dev->opt.params.bytes_per_line;
    dev->read_line_end = hei - dev->read_skip_lines;

DONE:
    if (err != NULL) {
        log_debug(dev, ESTRING(err));
        trace_error(dev->trace, err);
        http_data_unref(dev->read_image);
        dev->read_image = NULL;
    }

    return err == NULL;
}

/* Decode next image line
 *
 * Note, actual image size, returned by device, may be slightly different
 * from an image size, computed according to scan options and requested
 * from device. So here we adjust actual image to fit the expected (and
 * promised) parameters.
 *
 * Alternatively, we could make it problem of frontend. But fronends
 * expect image parameters to be accurate just after sane_start() returns,
 * so at this case sane_start() will have to wait a long time until image
 * is fully available. Taking in account that some popular frontends
 * (read "xsane") doesn't allow to cancel scanning before sane_start()
 * return, it is not good from the user experience perspective.
 */
static SANE_Status
device_read_decode_line (device *dev)
{
    const SANE_Int n = dev->read_line_num;

    if (n == dev->opt.params.lines) {
        return SANE_STATUS_EOF;
    }

    if (n < dev->read_skip_lines || n >= dev->read_line_end) {
        memset(dev->read_line_buf, 0xff, dev->opt.params.bytes_per_line);
    } else {
        error err = image_decoder_read_line(dev->read_decoder_jpeg,
                dev->read_line_buf);

        if (err != NULL) {
            log_debug(dev, ESTRING(err));
            trace_error(dev->trace, err);
            return SANE_STATUS_IO_ERROR;
        }
    }

    dev->read_line_off = dev->read_skip_bytes;
    dev->read_line_num ++;

    return SANE_STATUS_GOOD;
}

/* Read scanned image
 */
SANE_Status
device_read (device *dev, SANE_Byte *data, SANE_Int max_len, SANE_Int *len_out)
{
    SANE_Int     len = 0;
    SANE_Status  status = SANE_STATUS_GOOD;

    *len_out = 0; /* Must return 0, if status is not GOOD */

    /* Check device state */
    if ((dev->flags & DEVICE_SCANNING) == 0) {
        return SANE_STATUS_INVAL;
    }

    /* Validate arguments */
    if (len_out == NULL) {
        return SANE_STATUS_INVAL;
    }

    /* Wait until device is ready */
    while (dev->read_image == NULL && dev->state != DEVICE_SCAN_DONE) {
        if (dev->read_non_blocking) {
            *len_out = 0;
            return SANE_STATUS_GOOD;
        }

        eloop_mutex_unlock();
        pollable_wait(dev->read_pollable);
        eloop_mutex_lock();
    }

    if (dev->job_status == SANE_STATUS_CANCELLED) {
        status = SANE_STATUS_CANCELLED;
        goto DONE;
    }

    if (dev->read_image == NULL) {
        status = dev->job_status;
        log_assert(dev, status != SANE_STATUS_GOOD);
        goto DONE;
    }

    /* Read line by line */
    for (len = 0; status == SANE_STATUS_GOOD && len < max_len; ) {
        if (dev->read_line_off == dev->opt.params.bytes_per_line) {
            status = device_read_decode_line (dev);
        } else {
            SANE_Int sz = math_min(max_len - len,
                dev->opt.params.bytes_per_line - dev->read_line_off);

            memcpy(data, dev->read_line_buf + dev->read_line_off, sz);
            data += sz;
            dev->read_line_off += sz;
            len += sz;
        }
    }

    if (status == SANE_STATUS_IO_ERROR) {
        device_job_set_status(dev, SANE_STATUS_IO_ERROR);
        device_cancel(dev);
    }

    /* Cleanup and exit */
DONE:
    if (status == SANE_STATUS_EOF && len > 0) {
        status = SANE_STATUS_GOOD;
    }

    if (status == SANE_STATUS_GOOD) {
        *len_out = len;
        return SANE_STATUS_GOOD;
    }

    /* Scan and read finished - cleanup device */
    dev->flags &= ~DEVICE_SCANNING;
    image_decoder_reset(dev->read_decoder_jpeg);
    if (dev->read_image != NULL) {
        http_data_unref(dev->read_image);
        dev->read_image = NULL;
    }
    g_free(dev->read_line_buf);
    dev->read_line_buf = NULL;

    return status;
}

/******************** Device discovery events ********************/
/* Add statically configured device
 */
static void
device_statically_configured (const char *name, const char *uri)
{
    zeroconf_addrinfo addrinfo;

    memset(&addrinfo, 0, sizeof(addrinfo));
    addrinfo.uri = uri;
    device_add(name, &addrinfo, true, true);
}

/* Device found notification -- called by ZeroConf
 */
void
device_event_found (const char *name, bool init_scan,
        zeroconf_addrinfo *addresses)
{
    device_add(name, addresses, init_scan, false);
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
    device_table = g_ptr_array_new();

    eloop_add_start_stop_callback(device_management_start_stop);

    return SANE_STATUS_GOOD;
}

/* Cleanup device management
 */
void
device_management_cleanup (void)
{
    if (device_table != NULL) {
        log_assert(NULL, device_table->len == 0);
        g_cond_clear(&device_table_cond);
        g_ptr_array_unref(device_table);
        device_table = NULL;
    }
}

/* Start/stop devices management. Called from the airscan thread
 */
static void
device_management_start (void)
{
    conf_device *dev_conf;

    for (dev_conf = conf.devices; dev_conf != NULL; dev_conf = dev_conf->next) {
        if (dev_conf->uri != NULL) {
            device_statically_configured(dev_conf->name, dev_conf->uri);
        }
    }
}

/* Stop device management. Called from the airscan thread
 */
static void
device_management_stop (void)
{
    device_table_purge();
}

/* Start/stop device management
 */
static void
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
