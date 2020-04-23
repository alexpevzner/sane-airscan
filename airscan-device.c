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

/******************** Device management ********************/
/* Device flags
 */
enum {
    DEVICE_SCANNING         = (1 << 0), /* We are between sane_start() and
                                           final sane_read() */
    DEVICE_READING          = (1 << 1)  /* sane_read() can be called */
};

/* Device state diagram
 *
 *       OPENED
 *          |
 *          V
 *       PROBING->PROBING_FAILED--------------------------------
 *          |                                                  |
 *          V                                                  |
 *     -->IDLE                                                 |
 *     |    | submit PROTO_OP_SCAN                             |
 *     |    V                                                  |
 *     |  SCANNING----------                                   |
 *     |    |              | async cancel request received,    |
 *     |    |              | dev->stm_cancel_event signalled   |
 *     |    |              V                                   |
 *     |    |           CANCEL_REQ                             |
 *     |    |              | dev->stm_cancel_event callback    |
 *     |    |              |                                   |
 *     |    |              +------                             |
 *     |    | reached      |     | PROTO_OP_SCAN still pending |
 *     |    | CLEANUP      |     V                             |
 *     |    |<----------------CANCEL_DELAYED                   |
 *     |    |              |     |  | PROTO_OP_SCAN failed     |
 *     |    |              V     V  -----------------          |
 *     |    |           CANCEL_SENT                 |          |
 *     |    |     job      |     | cancel request   |          |
 *     |    |     finished |     | finished         |          |
 *     |    |              V     V                  |          |
 *     |    |  CANCEL_JOB_DONE  CANCEL_REQ_DONE     |          |
 *     |    |              |            |           |          |
 *     |    V              |            |           |          |
 *     |  CLEANUP          |            |           |          |
 *     |    |              |            |           |          |
 *     |    V              V            V           V          |
 *     ---DONE<--------------------------------------          |
 *          |                                                  |
 *          V                                                  |
 *       CLOSED<------------------------------------------------
 */
typedef enum {
    DEVICE_STM_OPENED,
    DEVICE_STM_PROBING,
    DEVICE_STM_PROBING_FAILED,
    DEVICE_STM_IDLE,
    DEVICE_STM_SCANNING,
    DEVICE_STM_CANCEL_REQ,
    DEVICE_STM_CANCEL_DELAYED,
    DEVICE_STM_CANCEL_SENT,
    DEVICE_STM_CANCEL_JOB_DONE,
    DEVICE_STM_CANCEL_REQ_DONE,
    DEVICE_STM_CLEANUP,
    DEVICE_STM_DONE,
    DEVICE_STM_CLOSED
} DEVICE_STM_STATE;

/* Device descriptor
 */
struct device {
    /* Common part */
    zeroconf_devinfo     *devinfo;             /* Device info */
    log_ctx              *log;                 /* Logging context */
    unsigned int         flags;                /* Device flags */
    devopt               opt;                  /* Device options */
    int                  checking_http_status; /* HTTP status before CHECK_STATUS */

    /* State machinery */
    DEVICE_STM_STATE     stm_state;         /* Device state */
    GCond                stm_cond;          /* Signalled when state changes */
    eloop_event          *stm_cancel_event; /* Signalled to initiate cancel */
    http_query           *stm_cancel_query; /* CANCEL query */
    eloop_timer          *stm_timer;        /* Delay timer */

    /* Protocol handling */
    proto_ctx            proto_ctx;        /* Protocol handler context */
    PROTO_OP             proto_op_current; /* Current operation */

    /* I/O handling (AVAHI and HTTP) */
    zeroconf_endpoint    *endpoint_current; /* Current endpoint to probe */

    /* Job status */
    SANE_Status          job_status;          /* Job completion status */
    SANE_Word            job_skip_x;          /* How much pixels to skip, */
    SANE_Word            job_skip_y;          /*    from left and top */

    /* Image decoders */
    image_decoder        *decoders[NUM_ID_FORMAT]; /* Decoders by format */

    /* Read machinery */
    SANE_Bool            read_non_blocking;  /* Non-blocking I/O mode */
    pollable             *read_pollable;     /* Signalled when read won't
                                                block */
    http_data_queue      *read_queue;        /* Queue of received images */
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

/* Forward declarations
 */
static device*
device_find_by_ident (const char *ident);

static void
device_http_cancel (device *dev);

static void
device_http_onerror (void *ptr, error err);

static void
device_proto_set (device *dev, ID_PROTO proto);

static void
device_scanner_capabilities_callback (void *ptr, http_query *q);

static void
device_probe_endpoint (device *dev, zeroconf_endpoint *endpoint);

static void
device_job_set_status (device *dev, SANE_Status status);

static inline DEVICE_STM_STATE
device_stm_state_get (device *dev);

static void
device_stm_state_set (device *dev, DEVICE_STM_STATE state);

static bool
device_stm_cancel_perform (device *dev, SANE_Status status);

static void
device_stm_op_callback (void *ptr, http_query *q);

static void
device_stm_cancel_event_callback (void *data);

static void
device_management_start_stop (bool start);

/******************** Device table management ********************/
/* Create a device.
 *
 * May fail. At this case, NULL will be returned and status will be set
 */
static device*
device_new (zeroconf_devinfo *devinfo)
{
    device            *dev;

    /* Create device */
    dev = g_new0(device, 1);

    dev->devinfo = devinfo;
    dev->log = log_ctx_new(dev->devinfo->name);

    log_debug(dev->log, "device created");

    dev->proto_ctx.log = dev->log;
    dev->proto_ctx.devcaps = &dev->opt.caps;

    devopt_init(&dev->opt);

    dev->proto_ctx.http = http_client_new(dev->log, dev);

    g_cond_init(&dev->stm_cond);

    dev->read_pollable = pollable_new();
    dev->read_queue = http_data_queue_new();

    /* Add to the table */
    g_ptr_array_add(device_table, dev);

    return dev;
}

/* Destroy a device
 */
static void
device_free (device *dev)
{
    int i;

    /* Remove device from table */
    log_debug(dev->log, "removed from device table");
    g_ptr_array_remove(device_table, dev);

    /* Stop all pending I/O activity */
    device_http_cancel(dev);

    if (dev->stm_cancel_event != NULL) {
        eloop_event_free(dev->stm_cancel_event);
    }

    if (dev->stm_timer != NULL) {
        eloop_timer_cancel(dev->stm_timer);
    }

    /* Release all memory */
    device_proto_set(dev, ID_PROTO_UNKNOWN);

    devopt_cleanup(&dev->opt);

    http_client_free(dev->proto_ctx.http);
    http_uri_free(dev->proto_ctx.base_uri_nozone);
    g_free((char*) dev->proto_ctx.location);

    g_cond_clear(&dev->stm_cond);

    for (i = 0; i < NUM_ID_FORMAT; i ++) {
        image_decoder *decoder = dev->decoders[i];
        if (decoder != NULL) {
            image_decoder_free(decoder);
            log_debug(dev->log, "closed decoder: %s", id_format_short_name(i));
        }
    }

    http_data_queue_free(dev->read_queue);
    pollable_free(dev->read_pollable);

    log_debug(dev->log, "device destroyed");
    log_ctx_free(dev->log);
    zeroconf_devinfo_free(dev->devinfo);
    g_free(dev);
}

/* Start probing. Called via eloop_call
 */
static gboolean
device_start_probing (gpointer data)
{
    device      *dev = data;

    device_probe_endpoint(dev, dev->devinfo->endpoints);

    return FALSE;
}

/* Start device I/O. Called via eloop_call
 * device_start_do
 */
static SANE_Status
device_io_start (device *dev)
{
    dev->stm_cancel_event = eloop_event_new(device_stm_cancel_event_callback, dev);
    if (dev->stm_cancel_event == NULL) {
        device_close(dev);
        return SANE_STATUS_NO_MEM;
    }

    device_stm_state_set(dev, DEVICE_STM_PROBING);
    eloop_call(device_start_probing, dev);

    return SANE_STATUS_GOOD;
}

/* Find device by ident
 */
static device*
device_find_by_ident (const char *ident)
{
    unsigned int i;

    for (i = 0; i < device_table->len; i ++) {
        device *dev = g_ptr_array_index(device_table, i);
        if (!strcmp(dev->devinfo->ident, ident)) {
            return dev;
        }
    }

    return NULL;
}

/* Purge device_table
 */
static void
device_table_purge (void)
{
    while (device_table->len > 0) {
        device_free(g_ptr_array_index(device_table, 0));
    }
}

/******************** Underlying protocol operations ********************/
/* Set protocol handler
 */
static void
device_proto_set (device *dev, ID_PROTO proto)
{
    if (dev->proto_ctx.proto != NULL) {
        log_debug(dev->log, "closed protocol \"%s\"",
            dev->proto_ctx.proto->name);
        dev->proto_ctx.proto->free(dev->proto_ctx.proto);
        dev->proto_ctx.proto = NULL;
    }

    if (proto != ID_PROTO_UNKNOWN) {
        dev->proto_ctx.proto = proto_handler_new(proto);
        log_assert(dev->log, dev->proto_ctx.proto != NULL);
        log_debug(dev->log, "using protocol \"%s\"",
            dev->proto_ctx.proto->name);
    }
}

/* Query device capabilities
 */
static void
device_proto_devcaps_submit (device *dev, void (*callback) (void*, http_query*))
{
    http_query *q;

    q = dev->proto_ctx.proto->devcaps_query(&dev->proto_ctx);
    http_query_submit(q, callback);
    dev->proto_ctx.query = q;
}

/* Decode device capabilities
 */
static error
device_proto_devcaps_decode (device *dev, devcaps *caps)
{
    return dev->proto_ctx.proto->devcaps_decode(&dev->proto_ctx, caps);
}

/* Get operation name, for loging
 */
static const char*
device_proto_op_name (device *dev, PROTO_OP op)
{
    switch (op) {
    case PROTO_OP_NONE:    return "PROTO_OP_NONE";
    case PROTO_OP_SCAN:    return "PROTO_OP_SCAN";
    case PROTO_OP_LOAD:    return "PROTO_OP_LOAD";
    case PROTO_OP_CHECK:   return "PROTO_OP_CHECK";
    case PROTO_OP_CLEANUP: return "PROTO_OP_CLEANUP";
    case PROTO_OP_FINISH:  return "PROTO_OP_FINISH";
    }

    log_internal_error(dev->log);
    return NULL;
}

/* Submit operation request
 */
static void
device_proto_op_submit (device *dev, PROTO_OP op,
        void (*callback) (void*, http_query*))
{
    http_query *(*func) (const proto_ctx *ctx) = NULL;
    http_query *q;

    switch (op) {
    case PROTO_OP_NONE:    log_internal_error(dev->log); break;
    case PROTO_OP_SCAN:    func = dev->proto_ctx.proto->scan_query; break;
    case PROTO_OP_LOAD:    func = dev->proto_ctx.proto->load_query; break;
    case PROTO_OP_CHECK:   func = dev->proto_ctx.proto->status_query; break;
    case PROTO_OP_CLEANUP: func = dev->proto_ctx.proto->cleanup_query; break;
    case PROTO_OP_FINISH:  log_internal_error(dev->log); break;
    }

    log_assert(dev->log, func != NULL);

    log_debug(dev->log, "%s: submitting: attempt=%d",
        device_proto_op_name(dev, op), dev->proto_ctx.failed_attempt);
    dev->proto_op_current = op;
    q = func(&dev->proto_ctx);
    http_query_submit(q, callback);
    dev->proto_ctx.query = q;
}

/* Dummy decode for PROTO_OP_CANCEL and PROTO_OP_CLEANUP
 */
static proto_result
device_proto_dummy_decode (const proto_ctx *ctx)
{
    proto_result result = {0};

    (void) ctx;
    result.next = PROTO_OP_FINISH;

    return result;
}

/* Decode operation response
 */
static proto_result
device_proto_op_decode (device *dev, PROTO_OP op)
{
    proto_result (*func) (const proto_ctx *ctx) = NULL;
    proto_result result;

    switch (op) {
    case PROTO_OP_NONE:    log_internal_error(dev->log); break;
    case PROTO_OP_SCAN:    func = dev->proto_ctx.proto->scan_decode; break;
    case PROTO_OP_LOAD:    func = dev->proto_ctx.proto->load_decode; break;
    case PROTO_OP_CHECK:   func = dev->proto_ctx.proto->status_decode; break;
    case PROTO_OP_CLEANUP: func = device_proto_dummy_decode; break;
    case PROTO_OP_FINISH:  log_internal_error(dev->log); break;
    }

    log_assert(dev->log, func != NULL);

    log_debug(dev->log, "%s: decoding", device_proto_op_name(dev, op));
    result = func(&dev->proto_ctx);
    log_debug(dev->log, "%s: decoded: status=\"%s\" next=%s delay=%d",
        device_proto_op_name(dev, op),
        sane_strstatus(result.status),
        device_proto_op_name(dev, result.next),
        result.delay);

    if (result.next == PROTO_OP_CHECK) {
        int http_status = http_query_status(dev->proto_ctx.query);

        dev->proto_ctx.failed_op = op;
        dev->proto_ctx.failed_http_status = http_status;
    }

    if (op == PROTO_OP_CHECK) {
        dev->proto_ctx.failed_attempt ++;
    }

    return result;
}

/******************** HTTP operations ********************/
/* Cancel pending HTTP request, if any
 */
static void
device_http_cancel (device *dev)
{
    http_client_cancel(dev->proto_ctx.http);

    if (dev->stm_timer != NULL) {
        eloop_timer_cancel(dev->stm_timer);
        dev->stm_timer = NULL;
    }
}

/* http_client onerror callback
 */
static void
device_http_onerror (void *ptr, error err) {
    device *dev = ptr;

    log_debug(dev->log, ESTRING(err));

    if (!device_stm_cancel_perform(dev, SANE_STATUS_IO_ERROR)) {
        device_stm_state_set(dev, DEVICE_STM_DONE);
    }
}

/******************** Protocol initialization ********************/
/* Probe next device address
 */
static void
device_probe_endpoint (device *dev, zeroconf_endpoint *endpoint)
{
    /* Switch endpoint */
    if (dev->endpoint_current == NULL ||
        dev->endpoint_current->proto != endpoint->proto) {
        device_proto_set(dev, endpoint->proto);
    }

    dev->endpoint_current = endpoint;
    dev->proto_ctx.base_uri = endpoint->uri;

    http_uri_free(dev->proto_ctx.base_uri_nozone);
    dev->proto_ctx.base_uri_nozone = http_uri_clone(endpoint->uri);
    http_uri_strip_zone_suffux(dev->proto_ctx.base_uri_nozone);

    /* Fetch device capabilities */
    device_proto_devcaps_submit (dev, device_scanner_capabilities_callback);
}

/* Scanner capabilities fetch callback
 */
static void
device_scanner_capabilities_callback (void *ptr, http_query *q)
{
    error        err   = NULL;
    device       *dev = ptr;
    int          i;
    unsigned int formats;

    /* Check request status */
    err = http_query_error(q);
    if (err != NULL) {
        err = eloop_eprintf("scanner capabilities query: %s", ESTRING(err));
        goto DONE;
    }

    /* Parse XML response */
    err = device_proto_devcaps_decode (dev, &dev->opt.caps);
    if (err != NULL) {
        err = eloop_eprintf("scanner capabilities: %s", err);
        goto DONE;
    }

    devcaps_dump(dev->log, &dev->opt.caps);
    devopt_set_defaults(&dev->opt);

    /* Setup decoders */
    formats = 0;
    for (i = 0; i < NUM_ID_SOURCE; i ++) {
        devcaps_source *src = dev->opt.caps.src[i];
        if (src != NULL) {
            formats |= src->formats;
        }
    }

    formats &= DEVCAPS_FORMATS_SUPPORTED;
    for (i = 0; i < NUM_ID_FORMAT; i ++) {
        if ((formats & (1 << i)) != 0) {
            switch (i) {
            case ID_FORMAT_JPEG:
                dev->decoders[i] = image_decoder_jpeg_new();
                break;

            case ID_FORMAT_TIFF:
                dev->decoders[i] = image_decoder_tiff_new();
                break;

            case ID_FORMAT_PNG:
                dev->decoders[i] = image_decoder_png_new();
                break;

            case ID_FORMAT_DIB:
                dev->decoders[i] = image_decoder_dib_new();
                break;

            default:
                log_internal_error(dev->log);
            }

            log_debug(dev->log, "new decoder: %s", id_format_short_name(i));
        }
    }

    /* Cleanup and exit */
DONE:
    if (err != NULL) {
        log_debug(dev->log, ESTRING(err));

        if (dev->endpoint_current != NULL &&
            dev->endpoint_current->next != NULL) {
            device_probe_endpoint(dev, dev->endpoint_current->next);
        } else {
            device_stm_state_set(dev, DEVICE_STM_PROBING_FAILED);
        }
    } else {
        device_stm_state_set(dev, DEVICE_STM_IDLE);
        http_client_onerror(dev->proto_ctx.http, device_http_onerror);
    }
}

/******************** Scan state machinery ********************/
/* Get state name, for debugging
 */
static const char*
device_stm_state_name (DEVICE_STM_STATE state)
{
    switch (state) {
    case DEVICE_STM_OPENED:          return "DEVICE_STM_OPENED";
    case DEVICE_STM_PROBING:         return "DEVICE_STM_PROBING";
    case DEVICE_STM_PROBING_FAILED:  return "DEVICE_STM_PROBING_FAILED";
    case DEVICE_STM_IDLE:            return "DEVICE_STM_IDLE";
    case DEVICE_STM_SCANNING:        return "DEVICE_STM_SCANNING";
    case DEVICE_STM_CANCEL_REQ:      return "DEVICE_STM_CANCEL_REQ";
    case DEVICE_STM_CANCEL_DELAYED:  return "DEVICE_STM_CANCEL_DELAYED";
    case DEVICE_STM_CANCEL_SENT:     return "DEVICE_STM_CANCEL_SENT";
    case DEVICE_STM_CANCEL_JOB_DONE: return "DEVICE_STM_CANCEL_JOB_DONE";
    case DEVICE_STM_CANCEL_REQ_DONE: return "DEVICE_STM_CANCEL_REQ_DONE";
    case DEVICE_STM_CLEANUP:         return "DEVICE_STM_CLEANUP";
    case DEVICE_STM_DONE:            return "DEVICE_STM_DONE";
    case DEVICE_STM_CLOSED:          return "DEVICE_STM_CLOSED";
    }

    return NULL;
}

/* Get state
 */
static inline DEVICE_STM_STATE
device_stm_state_get (device *dev)
{
    return __atomic_load_n(&dev->stm_state, __ATOMIC_SEQ_CST);
}

/* Check if device is in working state
 */
static bool
device_stm_state_working (device *dev)
{
    DEVICE_STM_STATE state = device_stm_state_get(dev);
    return state > DEVICE_STM_IDLE && state < DEVICE_STM_DONE;
}

/* Check if CANCEL request was sent to device
 */
static bool
device_stm_state_cancel_sent (device *dev)
{
    switch (device_stm_state_get(dev)) {
    case DEVICE_STM_CANCEL_SENT:
    case DEVICE_STM_CANCEL_JOB_DONE:
    case DEVICE_STM_CANCEL_REQ_DONE:
        return true;

    default:
        return false;
    }
}

/* Set state
 */
static void
device_stm_state_set (device *dev, DEVICE_STM_STATE state)
{
    DEVICE_STM_STATE old_state = device_stm_state_get(dev);

    if (old_state != state) {
        log_debug(dev->log, "%s->%s",
            device_stm_state_name(old_state), device_stm_state_name(state));

        __atomic_store_n(&dev->stm_state, state, __ATOMIC_SEQ_CST);
        g_cond_broadcast(&dev->stm_cond);

        if (!device_stm_state_working(dev)) {
            pollable_signal(dev->read_pollable);
        }
    }
}

/* cancel_query() callback
 */
static void
device_stm_cancel_callback (void *ptr, http_query *q)
{
    device       *dev = ptr;

    (void) q;

    dev->stm_cancel_query = NULL;
    if (device_stm_state_get(dev) == DEVICE_STM_CANCEL_JOB_DONE) {
        device_stm_state_set(dev, DEVICE_STM_DONE);
    } else {
        device_stm_state_set(dev, DEVICE_STM_CANCEL_REQ_DONE);
    }
}

/* Perform cancel, if possible
 */
static bool
device_stm_cancel_perform (device *dev, SANE_Status status)
{
    proto_ctx *ctx = &dev->proto_ctx;

    device_job_set_status(dev, status);
    if (ctx->location != NULL && !device_stm_state_cancel_sent(dev)) {
        if (ctx->params.src == ID_SOURCE_PLATEN &&
            ctx->images_received > 0) {
            /* If we are not expecting more images, skip cancel
             * and simple wait until job is done
             */
            device_stm_state_set(dev, DEVICE_STM_CANCEL_REQ_DONE);
        } else {
            /* Otherwise, perform a normal cancel operation
             */
            device_stm_state_set(dev, DEVICE_STM_CANCEL_SENT);

            log_assert(dev->log, dev->stm_cancel_query == NULL);
            dev->stm_cancel_query = ctx->proto->cancel_query(ctx);

            http_query_onerror(dev->stm_cancel_query, NULL);
            http_query_submit(dev->stm_cancel_query, device_stm_cancel_callback);
        }
        return true;
    }

    return false;
}

/* stm_cancel_event callback
 */
static void
device_stm_cancel_event_callback (void *data)
{
    device *dev = data;

    log_debug(dev->log, "cancel requested");
    if (!device_stm_cancel_perform(dev, SANE_STATUS_CANCELLED)) {
        device_stm_state_set(dev, DEVICE_STM_CANCEL_DELAYED);
    }
}

/* Request cancel
 */
static void
device_stm_cancel_req (device *dev)
{
    DEVICE_STM_STATE expected = DEVICE_STM_SCANNING;
    bool ok = __atomic_compare_exchange_n(&dev->stm_state, &expected,
        DEVICE_STM_CANCEL_REQ, true, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);

    if (ok) {
        eloop_event_trigger(dev->stm_cancel_event);
    }
}

/* stm_timer callback
 */
static void
device_stm_timer_callback (void *data)
{
    device *dev = data;
    dev->stm_timer = NULL;
    device_proto_op_submit(dev, dev->proto_op_current, device_stm_op_callback);
}

/* Operation callback
 */
static void
device_stm_op_callback (void *ptr, http_query *q)
{
    device       *dev = ptr;
    proto_result result = device_proto_op_decode(dev, dev->proto_op_current);

    (void) q;

    if (result.err != NULL) {
        log_debug(dev->log, "%s", ESTRING(result.err));
    }

    /* Save useful result, if any */
    if (dev->proto_op_current == PROTO_OP_SCAN) {
        if (result.data.location != NULL) {
            g_free((char*) dev->proto_ctx.location); /* Just in case */
            dev->proto_ctx.location = result.data.location;
            dev->proto_ctx.failed_attempt = 0;
            g_cond_broadcast(&dev->stm_cond);
        }
    } else if (dev->proto_op_current == PROTO_OP_LOAD) {
        if (result.data.image != NULL) {
            http_data_queue_push(dev->read_queue, result.data.image);
            dev->proto_ctx.images_received ++;
            pollable_signal(dev->read_pollable);

            dev->proto_ctx.failed_attempt = 0;
            g_cond_broadcast(&dev->stm_cond);
        }
    }

    /* Update job status */
    device_job_set_status(dev, result.status);

    /* If CANCEL was sent, and next operation is CLEANUP or
     * current operation is CHECK, FINISH the job
     */
    if (device_stm_state_cancel_sent(dev)) {
        if (result.next == PROTO_OP_CLEANUP ||
            dev->proto_op_current == PROTO_OP_CHECK) {
            result.next = PROTO_OP_FINISH;
        }
    }

    /* Check for FINISH */
    if (result.next == PROTO_OP_FINISH) {
        if (dev->proto_ctx.images_received == 0) {
            /* If no images received, and no error status
             * yet set, use SANE_STATUS_IO_ERROR as default
             * error code
             */
            device_job_set_status(dev, SANE_STATUS_IO_ERROR);
        }

        if (device_stm_state_get(dev) == DEVICE_STM_CANCEL_SENT) {
            device_stm_state_set(dev, DEVICE_STM_CANCEL_JOB_DONE);
        } else {
            device_stm_state_set(dev, DEVICE_STM_DONE);
        }
        return;
    }

    /* Handle switch to PROTO_OP_CLEANUP state */
    if (result.next == PROTO_OP_CLEANUP) {
        device_stm_state_set(dev, DEVICE_STM_CLEANUP);
    }

    /* Handle delayed cancellation */
    if (device_stm_state_get(dev) == DEVICE_STM_CANCEL_DELAYED) {
        if (!device_stm_cancel_perform(dev, SANE_STATUS_CANCELLED)) {
            /* Finish the job, if we has not yet reached cancellable
             * state
             */
            device_stm_state_set(dev, DEVICE_STM_DONE);
            return;
        }
    }

    /* Handle delay */
    if (result.delay != 0) {
        log_assert(dev->log, dev->stm_timer == NULL);
        dev->stm_timer = eloop_timer_new(result.delay,
            device_stm_timer_callback, dev);
        dev->proto_op_current = result.next;
        return;
    }

    /* Submit next operation */
    device_proto_op_submit(dev, result.next, device_stm_op_callback);
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
 *     2) we communicate with scanner in pixels, assuming protoc-specific DPI
 *        (defined by devcaps::units)
 *     3) when we deal with image, sizes are in pixels in real resolution
 *
 *   Second, scanner returns minimal and maximal window size, but
 *   to simplify frontend's life, we pretend there is no such thing,
 *   as a minimal width or height, otherwise TL and BR ranges become
 *   dependent from each other. Instead, we always request image from
 *   scanner not smaller that scanner's minimum, and clip excessive
 *   image parts if required.
 *
 *   This all makes things non-trivial. This function handles
 *   this complexity
 */
static device_geom
device_geom_compute (SANE_Fixed tl, SANE_Fixed br,
        SANE_Word minlen, SANE_Word maxlen, SANE_Word res, SANE_Word units)
{
    device_geom geom;

    geom.off = math_mm2px_res(tl, units);
    geom.len = math_mm2px_res(br - tl, units);
    geom.skip = 0;

    minlen = math_max(minlen, 1);
    geom.len = math_bound(geom.len, minlen, maxlen);

    if (geom.off + geom.len > maxlen) {
        geom.skip = geom.off + geom.len - maxlen;
        geom.off -= geom.skip;

        geom.skip = math_muldiv(geom.skip, res, units);
    }

    return geom;
}

/* Choose image format
 */
static ID_FORMAT
device_choose_format (device *dev, devcaps_source *src)
{
    unsigned int formats = src->formats;

    formats &= DEVCAPS_FORMATS_SUPPORTED;

    if ((formats & (1 << ID_FORMAT_PNG)) != 0) {
        return ID_FORMAT_PNG;
    }

    if ((formats & (1 << ID_FORMAT_JPEG)) != 0) {
        return ID_FORMAT_JPEG;
    }

    if ((formats & (1 << ID_FORMAT_DIB)) != 0) {
        return ID_FORMAT_DIB;
    }

    if ((formats & (1 << ID_FORMAT_TIFF)) != 0) {
        return ID_FORMAT_TIFF;
    }

    log_internal_error(dev->log);
    return ID_FORMAT_UNKNOWN;
}

/* Request scan
 */
static void
device_stm_start_scan (device *dev)
{
    device_geom       geom_x, geom_y;
    proto_ctx         *ctx = &dev->proto_ctx;
    proto_scan_params *params = &ctx->params;
    devcaps_source    *src = dev->opt.caps.src[dev->opt.src];
    SANE_Word         x_resolution = dev->opt.resolution;
    SANE_Word         y_resolution = dev->opt.resolution;
    char              buf[64];

    /* Prepare window parameters */
    geom_x = device_geom_compute(dev->opt.tl_x, dev->opt.br_x,
        src->min_wid_px, src->max_wid_px, x_resolution, dev->opt.caps.units);

    geom_y = device_geom_compute(dev->opt.tl_y, dev->opt.br_y,
        src->min_hei_px, src->max_hei_px, y_resolution, dev->opt.caps.units);

    dev->job_skip_x = geom_x.skip;
    dev->job_skip_y = geom_y.skip;

    /* Fill proto_scan_params structure */
    memset(params, 0, sizeof(*params));
    params->x_off = geom_x.off;
    params->y_off = geom_y.off;
    params->wid = geom_x.len;
    params->hei = geom_y.len;
    params->x_res = x_resolution;
    params->y_res = y_resolution;
    params->src = dev->opt.src;
    params->colormode = dev->opt.colormode;
    params->format = device_choose_format(dev, src);

    /* Dump parameters */
    log_trace(dev->log, "==============================");
    log_trace(dev->log, "Starting scan, using the following parameters:");
    log_trace(dev->log, "  source:         %s", id_source_sane_name(params->src));
    log_trace(dev->log, "  colormode:      %s", id_colormode_sane_name(params->colormode));
    log_trace(dev->log, "  tl_x:           %s mm", math_fmt_mm(dev->opt.tl_x, buf));
    log_trace(dev->log, "  tl_y:           %s mm", math_fmt_mm(dev->opt.tl_y, buf));
    log_trace(dev->log, "  br_x:           %s mm", math_fmt_mm(dev->opt.br_x, buf));
    log_trace(dev->log, "  br_y:           %s mm", math_fmt_mm(dev->opt.br_y, buf));
    log_trace(dev->log, "  image size:     %dx%d", params->wid, params->hei);
    log_trace(dev->log, "  image X offset: %d", params->x_off);
    log_trace(dev->log, "  image Y offset: %d", params->y_off);
    log_trace(dev->log, "  x_resolution:   %d", params->x_res);
    log_trace(dev->log, "  y_resolution:   %d", params->y_res);
    log_trace(dev->log, "  format:         %s",
            id_format_short_name(params->format));
    log_trace(dev->log, "");

    /* Submit a request */
    device_stm_state_set(dev, DEVICE_STM_SCANNING);
    device_proto_op_submit(dev, PROTO_OP_SCAN, device_stm_op_callback);
}

/* Wait until device leaves the working state
 */
static void
device_stm_wait_while_working (device *dev)
{
    while (device_stm_state_working(dev)) {
        eloop_cond_wait(&dev->stm_cond);
    }
}


/* Cancel scanning and wait until device leaves the working state
 */
static void
device_stm_cancel_wait (device *dev)
{
    device_stm_cancel_req(dev);
    device_stm_wait_while_working(dev);
}

/******************** Scan Job management ********************/
/* Set job status. If status already set, it will not be changed
 */
static void
device_job_set_status (device *dev, SANE_Status status)
{
    /* Check status, new and present
     */
    switch (status) {
    case SANE_STATUS_GOOD:
        return;

    case SANE_STATUS_CANCELLED:
        break;

    default:
        /* If error already is pending, leave it as is
         */
        if (dev->job_status != SANE_STATUS_GOOD) {
            return;
        }
    }

    /* Update status
     */
    if (status != dev->job_status) {
        log_debug(dev->log, "JOB status=%s", sane_strstatus(status));
        dev->job_status = status;

        if (status == SANE_STATUS_CANCELLED) {
            http_data_queue_purge(dev->read_queue);
        }
    }
}

/******************** API helpers ********************/
/* Get device's logging context
 */
log_ctx*
device_log_ctx (device *dev)
{
    return dev ? dev->log : NULL;
}

/* Open a device
 */
device*
device_open (const char *ident, SANE_Status *status)
{
    device           *dev = NULL;
    zeroconf_devinfo *devinfo;

    *status = SANE_STATUS_GOOD;

    /* Validate arguments */
    if (ident == NULL || *ident == '\0') {
        log_debug(dev->log, "device_open: invalid name");
        *status = SANE_STATUS_INVAL;
        return NULL;
    }

    /* Already opened? */
    dev = device_find_by_ident(ident);
    if (dev) {
        *status = SANE_STATUS_DEVICE_BUSY;
        return NULL;
    }

    /* Obtain device endpoints */
    devinfo = zeroconf_devinfo_lookup(ident);
    if (devinfo == NULL) {
        log_debug(NULL, "device_open(%s): device not found", ident);
        *status = SANE_STATUS_INVAL;
        return NULL;
    }

    /* Create a device */
    dev = device_new(devinfo);
    *status = device_io_start(dev);
    if (*status != SANE_STATUS_GOOD) {
        device_free(dev);
        dev = NULL;
    }

    /* Wait until device is initialized */
    while (device_stm_state_get(dev) == DEVICE_STM_PROBING) {
        eloop_cond_wait(&dev->stm_cond);
    }

    if (device_stm_state_get(dev) == DEVICE_STM_PROBING_FAILED) {
        device_free(dev);
        dev = NULL;
        *status = SANE_STATUS_IO_ERROR;
    }

    return dev;
}

/* Close the device
 */
void
device_close (device *dev)
{
    /* Cancel job in progress, if any */
    if (device_stm_state_working(dev)) {
        device_stm_cancel_wait(dev);
    }

    /* Close the device */
    device_stm_state_set(dev, DEVICE_STM_CLOSED);
    device_free(dev);
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
        log_debug(dev->log, "device_set_option: already scanning");
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

    device_stm_start_scan(dev);

    return FALSE;
}

/* Start new scanning job
 */
static SANE_Status
device_start_new_job (device *dev)
{
    dev->job_status = SANE_STATUS_GOOD;
    g_free((char*) dev->proto_ctx.location);
    dev->proto_ctx.location = NULL;
    dev->proto_ctx.failed_op = PROTO_OP_NONE;
    dev->proto_ctx.failed_attempt = 0;
    dev->proto_ctx.images_received = 0;

    eloop_call(device_start_do, dev);

    while (device_stm_state_get(dev) == DEVICE_STM_IDLE) {
        eloop_cond_wait(&dev->stm_cond);
    }

    dev->flags |= DEVICE_READING;
    return SANE_STATUS_GOOD;
}

/* Start scanning operation
 */
SANE_Status
device_start (device *dev)
{
    /* Already scanning? */
    if ((dev->flags & DEVICE_SCANNING) != 0) {
        log_debug(dev->log, "device_start: already scanning");
        return SANE_STATUS_INVAL;
    }

    /* Don's start if window is not valid */
    if (dev->opt.params.lines == 0 || dev->opt.params.pixels_per_line == 0) {
        log_debug(dev->log, "device_start: invalid scan window");
        return SANE_STATUS_INVAL;
    }

    /* Update state */
    dev->flags |= DEVICE_SCANNING;
    pollable_reset(dev->read_pollable);
    dev->read_non_blocking = SANE_FALSE;

    /* Scanner idle? Start new job */
    if (device_stm_state_get(dev) == DEVICE_STM_IDLE) {
        return device_start_new_job(dev);
    }

    /* Previous job still running. Synchronize with it
     */
    while (device_stm_state_working(dev)
        && http_data_queue_len(dev->read_queue) == 0) {
        eloop_cond_wait(&dev->stm_cond);
    }

    /* If we have more buffered images, just start
     * decoding the next one
     */
    if (http_data_queue_len(dev->read_queue) > 0) {
        dev->flags |= DEVICE_READING;
        return SANE_STATUS_GOOD;
    }

    /* Seems that previous job has finished.
     *
     * If it failed by itself (but not cancelled), return its status now.
     * Otherwise, start new job
     */
    log_assert (dev->log, device_stm_state_get(dev) == DEVICE_STM_DONE);

    device_stm_state_set(dev, DEVICE_STM_IDLE);
    if (dev->job_status != SANE_STATUS_GOOD &&
        dev->job_status != SANE_STATUS_CANCELLED) {
        dev->flags &= ~DEVICE_SCANNING;
        return dev->job_status;
    }

    /* Start new scan job */
    return device_start_new_job(dev);
}

/* Cancel scanning operation
 */
void
device_cancel (device *dev)
{
    device_stm_cancel_req(dev);
}

/* Set I/O mode
 */
SANE_Status
device_set_io_mode (device *dev, SANE_Bool non_blocking)
{
    if ((dev->flags & DEVICE_SCANNING) == 0) {
        log_debug(dev->log, "device_set_io_mode: not scanning");
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
        log_debug(dev->log, "device_get_select_fd: not scanning");
        return SANE_STATUS_INVAL;
    }

    *fd = pollable_get_fd(dev->read_pollable);
    return SANE_STATUS_GOOD;
}


/******************** Read machinery ********************/
/* Pull next image from the read queue and start decoding
 */
static SANE_Status
device_read_next (device *dev)
{
    error           err;
    size_t          line_capacity;
    SANE_Parameters params;
    image_decoder   *decoder = dev->decoders[dev->proto_ctx.params.format];
    int             wid, hei;

    log_assert(dev->log, decoder != NULL);

    dev->read_image = http_data_queue_pull(dev->read_queue);
    if (dev->read_image == NULL) {
        return SANE_STATUS_EOF;
    }

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
    log_trace(dev->log, "==============================");
    log_trace(dev->log, "Starting image decoding, image parameters are:");
    log_trace(dev->log, "  content type:   %s", image_content_type(decoder));
    log_trace(dev->log, "  frame format:   %s",
            params.format == SANE_FRAME_GRAY ? "Gray" : "RGB" );
    log_trace(dev->log, "  image size:     %dx%d", params.pixels_per_line,
            params.lines);
    log_trace(dev->log, "  color depth:    %d", params.depth);
    log_trace(dev->log, "");

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

    /* Wake up reader */
    pollable_signal(dev->read_pollable);

DONE:
    if (err != NULL) {
        log_debug(dev->log, ESTRING(err));
        http_data_unref(dev->read_image);
        dev->read_image = NULL;
        return SANE_STATUS_IO_ERROR;
    }

    return SANE_STATUS_GOOD;
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
    image_decoder  *decoder = dev->decoders[dev->proto_ctx.params.format];

    log_assert(dev->log, decoder != NULL);

    if (n == dev->opt.params.lines) {
        return SANE_STATUS_EOF;
    }

    if (n < dev->read_skip_lines || n >= dev->read_line_end) {
        memset(dev->read_line_buf, 0xff, dev->opt.params.bytes_per_line);
    } else {
        error err = image_decoder_read_line(decoder, dev->read_line_buf);

        if (err != NULL) {
            log_debug(dev->log, ESTRING(err));
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
    SANE_Int      len = 0;
    SANE_Status   status = SANE_STATUS_GOOD;
    image_decoder *decoder = dev->decoders[dev->proto_ctx.params.format];

    *len_out = 0; /* Must return 0, if status is not GOOD */

    log_assert(dev->log, decoder != NULL);

    /* Check device state */
    if ((dev->flags & DEVICE_READING) == 0) {
        log_debug(dev->log, "device_read: not scanning");
        return SANE_STATUS_INVAL;
    }

    /* Validate arguments */
    if (len_out == NULL) {
        log_debug(dev->log, "device_read: zero output buffer");
        return SANE_STATUS_INVAL;
    }

    /* Wait until device is ready */
    if (dev->read_image == NULL) {
        while (device_stm_state_working(dev) &&
               http_data_queue_empty(dev->read_queue)) {
            if (dev->read_non_blocking) {
                *len_out = 0;
                return SANE_STATUS_GOOD;
            }

            eloop_cond_wait(&dev->stm_cond);
        }

        if (dev->job_status == SANE_STATUS_CANCELLED) {
            status = SANE_STATUS_CANCELLED;
            goto DONE;
        }

        if (http_data_queue_empty(dev->read_queue)) {
            status = dev->job_status;
            log_assert(dev->log, status != SANE_STATUS_GOOD);
            goto DONE;
        }

        status = device_read_next(dev);
        if (status != SANE_STATUS_GOOD) {
            goto DONE;
        }
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
    dev->flags &= ~(DEVICE_SCANNING | DEVICE_READING);
    image_decoder_reset(decoder);
    if (dev->read_image != NULL) {
        http_data_unref(dev->read_image);
        dev->read_image = NULL;
    }
    g_free(dev->read_line_buf);
    dev->read_line_buf = NULL;

    if (device_stm_state_get(dev) == DEVICE_STM_DONE &&
        (status != SANE_STATUS_EOF || dev->job_status == SANE_STATUS_GOOD)) {
        device_stm_state_set(dev, DEVICE_STM_IDLE);
    }

    return status;
}

/******************** Initialization/cleanup ********************/
/* Initialize device management
 */
SANE_Status
device_management_init (void)
{
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
        g_ptr_array_unref(device_table);
        device_table = NULL;
    }
}

/* Start/stop device management
 */
static void
device_management_start_stop (bool start)
{
    if (!start) {
        device_table_purge();
    }
}

/* vim:ts=8:sw=4:et
 */
