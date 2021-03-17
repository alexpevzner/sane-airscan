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
#include <unistd.h>

/******************** Constants ********************/
/* HTTP timeouts, by operation, in milliseconds
 */
#define DEVICE_HTTP_TIMEOUT_DEVCAPS     5000
#define DEVICE_HTTP_TIMEOUT_PRECHECK    5000
#define DEVICE_HTTP_TIMEOUT_SCAN        30000
#define DEVICE_HTTP_TIMEOUT_LOAD        -1
#define DEVICE_HTTP_TIMEOUT_CHECK       5000
#define DEVICE_HTTP_TIMEOUT_CLEANUP     30000
#define DEVICE_HTTP_TIMEOUT_CANCEL      30000

/* HTTP timeout for operation that was pending
 * in a moment of cancel (if any)
 */
#define DEVICE_HTTP_TIMEOUT_CANCELED_OP 10000

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
 *     |    |   cancel req |     | job              |          |
 *     |    |   finished   |     | finished         |          |
 *     |    V              |     |                  |          |
 *     |  CLEANUP          |     |                  |          |
 *     |    |              |     |                  |          |
 *     |    V              V     V                  V          |
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
    pthread_cond_t       stm_cond;          /* Signalled when state changes */
    eloop_event          *stm_cancel_event; /* Signalled to initiate cancel */
    http_query           *stm_cancel_query; /* CANCEL query */
    bool                 stm_cancel_sent;   /* Cancel was sent to device */
    eloop_timer          *stm_timer;        /* Delay timer */
    struct timespec      stm_last_fail_time;/* Last failed sane_start() time */

    /* Protocol handling */
    proto_ctx            proto_ctx;        /* Protocol handler context */

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
    SANE_Int             read_line_real_wid; /* Real line width */
    SANE_Int             read_line_off;      /* Current offset in the line */
    SANE_Int             read_skip_bytes;    /* How many bytes to skip at line
                                                beginning */
    bool                 read_24_to_8;       /* Resample 24 to 8 bits */
    filter               *read_filters;      /* Chain of image filters */
};

/* Static variables
 */
static device **device_table;

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
device_read_filters_setup (device *dev);

static void
device_read_filters_cleanup (device *dev);

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
    dev = mem_new(device, 1);

    dev->devinfo = devinfo;
    dev->log = log_ctx_new(dev->devinfo->name, NULL);

    log_debug(dev->log, "device created");

    dev->proto_ctx.log = dev->log;
    dev->proto_ctx.devcaps = &dev->opt.caps;

    devopt_init(&dev->opt);

    dev->proto_ctx.http = http_client_new(dev->log, dev);

    pthread_cond_init(&dev->stm_cond, NULL);

    dev->read_pollable = pollable_new();
    dev->read_queue = http_data_queue_new();

    /* Add to the table */
    device_table = ptr_array_append(device_table, dev);

    return dev;
}

/* Destroy a device
 */
static void
device_free (device *dev, const char *log_msg)
{
    int i;

    /* Remove device from table */
    log_debug(dev->log, "removed from device table");
    ptr_array_del(device_table, ptr_array_find(device_table, dev));

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
    http_uri_free(dev->proto_ctx.base_uri);
    http_uri_free(dev->proto_ctx.base_uri_nozone);
    mem_free((char*) dev->proto_ctx.location);

    pthread_cond_destroy(&dev->stm_cond);

    for (i = 0; i < NUM_ID_FORMAT; i ++) {
        image_decoder *decoder = dev->decoders[i];
        if (decoder != NULL) {
            image_decoder_free(decoder);
            log_debug(dev->log, "closed decoder: %s", id_format_short_name(i));
        }
    }

    http_data_queue_free(dev->read_queue);
    pollable_free(dev->read_pollable);
    device_read_filters_cleanup(dev);

    log_debug(dev->log, "device destroyed");
    if (log_msg != NULL) {
        log_debug(dev->log, "%s", log_msg);
    }

    log_ctx_free(dev->log);
    zeroconf_devinfo_free(dev->devinfo);
    mem_free(dev);
}

/* Start probing. Called via eloop_call
 */
static void
device_start_probing (void *data)
{
    device      *dev = data;

    device_probe_endpoint(dev, dev->devinfo->endpoints);
}

/* Start device I/O.
 */
static SANE_Status
device_io_start (device *dev)
{
    dev->stm_cancel_event = eloop_event_new(device_stm_cancel_event_callback, dev);
    if (dev->stm_cancel_event == NULL) {
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
    size_t i, len = mem_len(device_table);

    for (i = 0; i < len; i ++) {
        device *dev = device_table[i];
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
    while (mem_len(device_table) > 0) {
        device_free(device_table[0], NULL);
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

/* Set base URI. `uri' ownership is taken by this function
 */
static void
device_proto_set_base_uri (device *dev, http_uri *uri)
{
    http_uri_free(dev->proto_ctx.base_uri);
    dev->proto_ctx.base_uri = uri;

    http_uri_free(dev->proto_ctx.base_uri_nozone);
    dev->proto_ctx.base_uri_nozone = http_uri_clone(uri);
    http_uri_strip_zone_suffux(dev->proto_ctx.base_uri_nozone);
}

/* Query device capabilities
 */
static void
device_proto_devcaps_submit (device *dev, void (*callback) (void*, http_query*))
{
    http_query *q;

    q = dev->proto_ctx.proto->devcaps_query(&dev->proto_ctx);
    http_query_timeout(q, DEVICE_HTTP_TIMEOUT_DEVCAPS);
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

/* http_query_onrxhdr() callback
 */
static void
device_proto_op_onrxhdr (void *p, http_query *q)
{
    device *dev = p;

    if (dev->proto_ctx.op == PROTO_OP_LOAD && !dev->stm_cancel_sent) {
        http_query_timeout(q, -1);
    }
}

/* Submit operation request
 */
static void
device_proto_op_submit (device *dev, PROTO_OP op,
        void (*callback) (void*, http_query*))
{
    http_query *(*func) (const proto_ctx *ctx) = NULL;
    int        timeout = -1;
    http_query *q;

    switch (op) {
    case PROTO_OP_NONE:    log_internal_error(dev->log); break;
    case PROTO_OP_FINISH:  log_internal_error(dev->log); break;

    case PROTO_OP_PRECHECK:
        func = dev->proto_ctx.proto->precheck_query;
        timeout = DEVICE_HTTP_TIMEOUT_PRECHECK;
        break;

    case PROTO_OP_SCAN:
        func = dev->proto_ctx.proto->scan_query;
        timeout = DEVICE_HTTP_TIMEOUT_SCAN;
        break;

    case PROTO_OP_LOAD:
        func = dev->proto_ctx.proto->load_query;
        timeout = DEVICE_HTTP_TIMEOUT_LOAD;
        break;

    case PROTO_OP_CHECK:
        func = dev->proto_ctx.proto->status_query;
        timeout = DEVICE_HTTP_TIMEOUT_CHECK;
        break;

    case PROTO_OP_CLEANUP:
        func = dev->proto_ctx.proto->cleanup_query;
        timeout = DEVICE_HTTP_TIMEOUT_CLEANUP;
        break;
    }

    log_assert(dev->log, func != NULL);

    log_debug(dev->log, "%s: submitting: attempt=%d",
        proto_op_name(op), dev->proto_ctx.failed_attempt);
    dev->proto_ctx.op = op;

    q = func(&dev->proto_ctx);
    http_query_timeout(q, timeout);
    if (op == PROTO_OP_LOAD) {
        http_query_onrxhdr(q, device_proto_op_onrxhdr);
    }

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
    case PROTO_OP_PRECHECK:func = dev->proto_ctx.proto->precheck_decode; break;
    case PROTO_OP_SCAN:    func = dev->proto_ctx.proto->scan_decode; break;
    case PROTO_OP_LOAD:    func = dev->proto_ctx.proto->load_decode; break;
    case PROTO_OP_CHECK:   func = dev->proto_ctx.proto->status_decode; break;
    case PROTO_OP_CLEANUP: func = device_proto_dummy_decode; break;
    case PROTO_OP_FINISH:  log_internal_error(dev->log); break;
    }

    log_assert(dev->log, func != NULL);

    log_debug(dev->log, "%s: decoding", proto_op_name(op));
    result = func(&dev->proto_ctx);
    log_debug(dev->log, "%s: decoded: status=\"%s\" next=%s delay=%d",
        proto_op_name(op),
        sane_strstatus(result.status),
        proto_op_name(result.next),
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
device_http_onerror (void *ptr, error err)
{
    device      *dev = ptr;
    SANE_Status status;

    status = err == ERROR_ENOMEM ? SANE_STATUS_NO_MEM : SANE_STATUS_IO_ERROR;

    log_debug(dev->log, "cancelling job due to error: %s", ESTRING(err));

    if (!device_stm_cancel_perform(dev, status)) {
        device_stm_state_set(dev, DEVICE_STM_DONE);
    } else {
        /* Scan job known to be done, now waiting for cancel
         * completion
         */
        device_stm_state_set(dev, DEVICE_STM_CANCEL_JOB_DONE);
    }
}

/******************** Protocol initialization ********************/
/* Probe next device address
 */
static void
device_probe_endpoint (device *dev, zeroconf_endpoint *endpoint)
{
    /* Switch endpoint */
    log_assert(dev->log, endpoint->proto != ID_PROTO_UNKNOWN);

    if (dev->endpoint_current == NULL ||
        dev->endpoint_current->proto != endpoint->proto) {
        device_proto_set(dev, endpoint->proto);
    }

    dev->endpoint_current = endpoint;

    device_proto_set_base_uri(dev, http_uri_clone(endpoint->uri));

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

            case ID_FORMAT_PNG:
                dev->decoders[i] = image_decoder_png_new();
                break;

            case ID_FORMAT_BMP:
                dev->decoders[i] = image_decoder_bmp_new();
                break;

            default:
                log_internal_error(dev->log);
            }

            log_debug(dev->log, "new decoder: %s", id_format_short_name(i));
        }
    }

    /* Update endpoint address in case of HTTP redirection */
    if (!http_uri_equal(http_query_uri(q), http_query_real_uri(q))) {
        const char *uri_str = http_uri_str(http_query_uri(q));
        const char *real_uri_str = http_uri_str(http_query_real_uri(q));
        const char *base_str = http_uri_str(dev->proto_ctx.base_uri);

        if (str_has_prefix(uri_str, base_str)) {
            const char *tail = uri_str + strlen(base_str);

            if (str_has_suffix(real_uri_str, tail)) {
                size_t   l = strlen(real_uri_str) - strlen(tail);
                char     *new_uri_str = alloca(l + 1);
                http_uri *new_uri;

                memcpy(new_uri_str, real_uri_str, l);
                new_uri_str[l] = '\0';

                log_debug(dev->log, "endpoint URI changed due to redirection:");
                log_debug(dev->log, "  old URL: %s", base_str);
                log_debug(dev->log, "  new URL: %s", new_uri_str);

                new_uri = http_uri_new(new_uri_str, true);
                log_assert(dev->log, new_uri != NULL);

                device_proto_set_base_uri(dev, new_uri);
            }
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
        pthread_cond_broadcast(&dev->stm_cond);

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
    if (ctx->location != NULL && !dev->stm_cancel_sent) {
        if (ctx->params.src == ID_SOURCE_PLATEN &&
            ctx->images_received > 0) {
            /* If we are not expecting more images, skip cancel
             * and simple wait until job is done
             *
             * Otherwise Xerox VersaLink B405 remains busy for
             * a quite long time without any need
             */
            log_debug(dev->log, "cancel skipped as job is almost done");
            return false;
        } else {
            /* Otherwise, perform a normal cancel operation
             */
            device_stm_state_set(dev, DEVICE_STM_CANCEL_SENT);

            log_assert(dev->log, dev->stm_cancel_query == NULL);
            dev->stm_cancel_query = ctx->proto->cancel_query(ctx);

            http_query_onerror(dev->stm_cancel_query, NULL);
            http_query_timeout(dev->stm_cancel_query,
                    DEVICE_HTTP_TIMEOUT_CANCEL);

            http_client_timeout(dev->proto_ctx.http,
                    DEVICE_HTTP_TIMEOUT_CANCELED_OP);

            http_query_submit(dev->stm_cancel_query, device_stm_cancel_callback);

            dev->stm_cancel_sent = true;
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

    log_debug(dev->log, "cancel processing started");
    if (!device_stm_cancel_perform(dev, SANE_STATUS_CANCELLED)) {
        device_stm_state_set(dev, DEVICE_STM_CANCEL_DELAYED);
    }
}

/* Request cancel.
 *
 * Note, reason must be NULL, if cancel requested from the signal handler
 */
static void
device_stm_cancel_req (device *dev, const char *reason)
{
    DEVICE_STM_STATE expected = DEVICE_STM_SCANNING;
    bool ok = __atomic_compare_exchange_n(&dev->stm_state, &expected,
        DEVICE_STM_CANCEL_REQ, true, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);

    if (ok) {
        if (reason != NULL) {
            log_debug(dev->log, "cancel requested: %s", reason);
        }

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
    device_proto_op_submit(dev, dev->proto_ctx.op, device_stm_op_callback);
}

/* Operation callback
 */
static void
device_stm_op_callback (void *ptr, http_query *q)
{
    device       *dev = ptr;
    proto_result result = device_proto_op_decode(dev, dev->proto_ctx.op);

    (void) q;

    if (result.err != NULL) {
        log_debug(dev->log, "%s", ESTRING(result.err));
    }

    /* Save useful result, if any */
    if (dev->proto_ctx.op == PROTO_OP_SCAN) {
        if (result.data.location != NULL) {
            mem_free((char*) dev->proto_ctx.location); /* Just in case */
            dev->proto_ctx.location = result.data.location;
            dev->proto_ctx.failed_attempt = 0;
            pthread_cond_broadcast(&dev->stm_cond);
        }
    } else if (dev->proto_ctx.op == PROTO_OP_LOAD) {
        if (result.data.image != NULL) {
            http_data_queue_push(dev->read_queue, result.data.image);
            dev->proto_ctx.images_received ++;
            pollable_signal(dev->read_pollable);

            dev->proto_ctx.failed_attempt = 0;
            pthread_cond_broadcast(&dev->stm_cond);
        }
    }

    /* Update job status */
    device_job_set_status(dev, result.status);

    /* If CANCEL was sent, and next operation is CLEANUP or
     * current operation is CHECK, FINISH the job
     */
    if (dev->stm_cancel_sent) {
        if (result.next == PROTO_OP_CLEANUP ||
            dev->proto_ctx.op == PROTO_OP_CHECK) {
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
        dev->proto_ctx.op = result.next;
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
 *     2) we communicate with scanner in pixels, assuming
 *        protocol-specific DPI (defined by devcaps::units)
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

    if ((formats & (1 << ID_FORMAT_BMP)) != 0) {
        return ID_FORMAT_BMP;
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
    params->colormode = dev->opt.colormode_real;
    params->format = device_choose_format(dev, src);

    /* Dump parameters */
    log_trace(dev->log, "==============================");
    log_trace(dev->log, "Starting scan, using the following parameters:");
    log_trace(dev->log, "  source:         %s",
            id_source_sane_name(params->src));
    log_trace(dev->log, "  colormode_emul: %s",
            id_colormode_sane_name(dev->opt.colormode_emul));
    log_trace(dev->log, "  colormode_real: %s",
            id_colormode_sane_name(params->colormode));
    log_trace(dev->log, "  tl_x:           %s mm",
            math_fmt_mm(dev->opt.tl_x, buf));
    log_trace(dev->log, "  tl_y:           %s mm",
            math_fmt_mm(dev->opt.tl_y, buf));
    log_trace(dev->log, "  br_x:           %s mm",
            math_fmt_mm(dev->opt.br_x, buf));
    log_trace(dev->log, "  br_y:           %s mm",
            math_fmt_mm(dev->opt.br_y, buf));
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
    if (dev->proto_ctx.proto->precheck_query != NULL) {
        device_proto_op_submit(dev, PROTO_OP_PRECHECK, device_stm_op_callback);
    } else {
        device_proto_op_submit(dev, PROTO_OP_SCAN, device_stm_op_callback);
    }
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
device_stm_cancel_wait (device *dev, const char *reason)
{
    device_stm_cancel_req(dev, reason);
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
        log_debug(NULL, "device_open: invalid name");
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
        device_free(dev, NULL);
        return NULL;
    }

    /* Wait until device is initialized */
    while (device_stm_state_get(dev) == DEVICE_STM_PROBING) {
        eloop_cond_wait(&dev->stm_cond);
    }

    if (device_stm_state_get(dev) == DEVICE_STM_PROBING_FAILED) {
        device_free(dev, NULL);
        *status = SANE_STATUS_IO_ERROR;
        return NULL;
    }

    return dev;
}

/* Close the device
 * If log_msg is not NULL, it is written to the device log as late as possible
 */
void
device_close (device *dev, const char *log_msg)
{
    /* Cancel job in progress, if any */
    if (device_stm_state_working(dev)) {
        device_stm_cancel_wait(dev, "device close");
    }

    /* Close the device */
    device_stm_state_set(dev, DEVICE_STM_CLOSED);
    device_free(dev, log_msg);
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
    SANE_Status status;

    if ((dev->flags & DEVICE_SCANNING) != 0) {
        log_debug(dev->log, "device_set_option: already scanning");
        return SANE_STATUS_INVAL;
    }

    status = devopt_set_option(&dev->opt, option, value, info);
    if (status == SANE_STATUS_GOOD && opt_is_enhancement(option)) {
        device_read_filters_setup(dev);
    }

    return status;
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
static void
device_start_do (void *data)
{
    device      *dev = data;

    device_stm_start_scan(dev);
}

/* Wait until new job is started
 */
static SANE_Status
device_start_wait (device *dev)
{
    for (;;) {
        DEVICE_STM_STATE state = device_stm_state_get(dev);

        switch (state) {
        case DEVICE_STM_IDLE:
            break;

        case DEVICE_STM_SCANNING:
            if (dev->proto_ctx.location != NULL) {
                return SANE_STATUS_GOOD;
            }
            break;

        case DEVICE_STM_DONE:
            return dev->job_status;

        default:
            return SANE_STATUS_GOOD;
        }

        eloop_cond_wait(&dev->stm_cond);
    }
}

/* Enforce CONFIG_START_RETRY_INTERVAL
 */
static void
device_start_retry_pause (device *dev)
{
    struct timespec now;
    int64_t         pause_us;

    clock_gettime(CLOCK_MONOTONIC, &now);

    pause_us = (int64_t) (now.tv_sec - dev->stm_last_fail_time.tv_sec) *
                    1000000;
    pause_us += (int64_t) (now.tv_nsec - dev->stm_last_fail_time.tv_nsec) /
                    1000;
    pause_us = (int64_t) (CONFIG_START_RETRY_INTERVAL * 1000) - pause_us;

    if (pause_us > 1000) {
        log_debug(dev->log, "sane_start() retried too often; pausing for %d ms",
                (int) (pause_us / 1000));

        eloop_mutex_unlock();
        usleep((useconds_t) pause_us);
        eloop_mutex_lock();
    }
}

/* Start new scanning job
 */
static SANE_Status
device_start_new_job (device *dev)
{
    SANE_Status status;

    device_start_retry_pause(dev);

    dev->stm_cancel_sent = false;
    dev->job_status = SANE_STATUS_GOOD;
    mem_free((char*) dev->proto_ctx.location);
    dev->proto_ctx.location = NULL;
    dev->proto_ctx.failed_op = PROTO_OP_NONE;
    dev->proto_ctx.failed_attempt = 0;
    dev->proto_ctx.images_received = 0;

    eloop_call(device_start_do, dev);

    log_debug(dev->log, "device_start_wait: waiting");
    status = device_start_wait(dev);
    log_debug(dev->log, "device_start_wait: %s", sane_strstatus(status));

    switch (status) {
    case SANE_STATUS_GOOD:
    case SANE_STATUS_CANCELLED:
        memset(&dev->stm_last_fail_time, 0, sizeof(dev->stm_last_fail_time));
        break;

    default:
        clock_gettime(CLOCK_MONOTONIC, &dev->stm_last_fail_time);
    }

    if (status == SANE_STATUS_GOOD) {
        dev->flags |= DEVICE_READING;
    } else {
        dev->flags &= ~DEVICE_SCANNING;
        if (device_stm_state_get(dev) == DEVICE_STM_DONE) {
            device_stm_state_set(dev, DEVICE_STM_IDLE);
        }
    }

    return status;
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
        log_debug(dev->log, "device_start: waiting for background scan job");
        eloop_cond_wait(&dev->stm_cond);
    }

    /* If we have more buffered images, just start
     * decoding the next one
     */
    if (http_data_queue_len(dev->read_queue) > 0) {
        dev->flags |= DEVICE_READING;
        pollable_signal(dev->read_pollable);
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
    /* Note, xsane calls sane_cancel() after each successful
     * scan "just in case", which kills scan job running in
     * background. So ignore cancel request, if from the API
     * point of view we are not "scanning" (i.e., not between
     * sane_start() and sane_read() completion)
     */
    if ((dev->flags & DEVICE_SCANNING) == 0) {
        return;
    }

    device_stm_cancel_req(dev, NULL);
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
/* Setup read_filters
 */
static void
device_read_filters_setup (device *dev)
{
    device_read_filters_cleanup(dev);
    dev->read_filters = filter_chain_push_xlat(NULL, &dev->opt);
    filter_chain_dump(dev->read_filters, dev->log);
}

/* Cleanup read_filters
 */
static void
device_read_filters_cleanup (device *dev)
{
    filter_chain_free(dev->read_filters);
    dev->read_filters = NULL;
}

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
    int             skip_lines = 0;

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

    /* Obtain and dump image parameters */
    image_decoder_get_params(decoder, &params);

    log_trace(dev->log, "==============================");
    log_trace(dev->log, "Image received with the following parameters:");
    log_trace(dev->log, "  content type:   %s", image_content_type(decoder));
    log_trace(dev->log, "  frame format:   %s",
            params.format == SANE_FRAME_GRAY ? "Gray" : "RGB" );
    log_trace(dev->log, "  image size:     %dx%d", params.pixels_per_line,
            params.lines);
    log_trace(dev->log, "  color depth:    %d", params.depth);
    log_trace(dev->log, "");

    /* Validate image parameters */
    dev->read_24_to_8 = false;
    if (params.format == SANE_FRAME_RGB &&
        dev->opt.params.format == SANE_FRAME_GRAY) {
        dev->read_24_to_8 = true;
        log_trace(dev->log, "resampling: RGB24->Grayscale8");
    } else if (params.format != dev->opt.params.format) {
        /* This is what we cannot handle */
        err = ERROR("Unexpected image format");
        goto DONE;
    }

    wid = params.pixels_per_line;
    hei = params.lines;

    /* Setup image clipping
     *
     * The following variants are possible:
     *
     *  <------real image size------><--fill-->
     *  <---skip---><---returned image size--->
     *  <------------line capacity------------>
     *
     *  <------------real image size------------>
     *  <---skip---><--returned image size-->
     *  <-------------line capacity------------->
     *
     * Real image size is a size of image after decoder.
     * Returned image size is a size of image that we
     * return to the client
     *
     * If device for some reasons unable to handle X/Y
     * offset in hardware, we need to skip some bytes (horizontally)
     * or lines (vertically)
     *
     * If real image is smaller that expected, we need to
     * fill some bytes/lines with 0xff
     *
     * Line buffer capacity must be big enough to fit
     * real image size (we promised it do decoder) and
     * returned image size, whatever is large
     */
    if (dev->job_skip_x >= wid || dev->job_skip_y >= hei) {
        /* Trivial case - just skip everything */
        dev->read_line_end = 0;
        dev->read_skip_bytes = 0;
        dev->read_line_real_wid = 0;
        line_capacity = dev->opt.params.bytes_per_line;
    } else {
        image_window win;
        int          bpp = dev->opt.params.format == SANE_FRAME_RGB ? 3 : 1;
        int          returned_size_and_skip;

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

        if (win.y_off != dev->job_skip_y) {
            skip_lines = dev->job_skip_y - win.y_off;
        }

        line_capacity = win.wid;
        if (params.format == SANE_FRAME_RGB) {
            line_capacity *= 3;
        }

        returned_size_and_skip = dev->read_skip_bytes +
                                 dev->opt.params.bytes_per_line;

        line_capacity = math_max(line_capacity, returned_size_and_skip);
        dev->read_line_real_wid = win.wid;
    }

    /* Initialize image decoding */
    dev->read_line_buf = mem_new(SANE_Byte, line_capacity);
    memset(dev->read_line_buf, 0xff, line_capacity);

    dev->read_line_num = 0;
    dev->read_line_off = dev->opt.params.bytes_per_line;
    dev->read_line_end = hei - skip_lines;

    for (;skip_lines > 0; skip_lines --) {
        err = image_decoder_read_line(decoder, dev->read_line_buf);
        if (err != NULL) {
            goto DONE;
        }
    }

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

/* Perform 24 to 8 bit image resampling for a single line
 */
static void
device_read_24_to_8_resample (device *dev)
{
    int i, len = dev->read_line_real_wid;
    uint8_t *in = dev->read_line_buf;
    uint8_t *out = dev->read_line_buf;

    for (i = 0; i < len; i ++) {
        /* Y = R * 0.299 + G * 0.587 + B * 0.114
         *
         * 16777216 == 1 << 24
         * 16777216 * 0.299 == 5016387.584 ~= 5016387
         * 16777216 * 0.587 == 9848225.792 ~= 9848226
         * 16777216 * 0.114 == 1912602.624 ~= 1912603
         *
         * 5016387 + 9848226 + 1912603 == 16777216
         */
        unsigned long Y;

        Y = 5016387 * (unsigned long) *in ++;
        Y += 9848226 * (unsigned long) *in ++;
        Y += 1912603 * (unsigned long) *in ++;
        *out ++ = (Y + (1 << 23)) >> 24;
    }

    if (len < dev->opt.params.bytes_per_line) {
        memset(dev->read_line_buf + len, 0xff,
            dev->opt.params.bytes_per_line - len);
    }
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

    if (n >= dev->read_line_end) {
        memset(dev->read_line_buf + dev->read_skip_bytes, 0xff,
            dev->opt.params.bytes_per_line);
    } else {
        error err = image_decoder_read_line(decoder, dev->read_line_buf);

        if (err != NULL) {
            log_debug(dev->log, ESTRING(err));
            return SANE_STATUS_IO_ERROR;
        }

        if (dev->read_24_to_8) {
            device_read_24_to_8_resample(dev);
        }
    }

    filter_chain_apply(dev->read_filters,
            dev->read_line_buf, dev->opt.params.bytes_per_line);

    dev->read_line_off = 0;
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

    if (len_out != NULL) {
        *len_out = 0; /* Must return 0, if status is not GOOD */
    }

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
            status = device_read_decode_line(dev);
        } else {
            SANE_Int sz = math_min(max_len - len,
                dev->opt.params.bytes_per_line - dev->read_line_off);

            memcpy(data, dev->read_line_buf + dev->read_skip_bytes +
                dev->read_line_off, sz);

            data += sz;
            dev->read_line_off += sz;
            len += sz;
        }
    }

    if (status == SANE_STATUS_IO_ERROR) {
        device_job_set_status(dev, SANE_STATUS_IO_ERROR);
        device_stm_cancel_req(dev, "I/O error");
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
    mem_free(dev->read_line_buf);
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
    device_table = ptr_array_new(device*);
    eloop_add_start_stop_callback(device_management_start_stop);

    return SANE_STATUS_GOOD;
}

/* Cleanup device management
 */
void
device_management_cleanup (void)
{
    if (device_table != NULL) {
        log_assert(NULL, mem_len(device_table) == 0);
        mem_free(device_table);
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
