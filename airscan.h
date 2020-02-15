/* AirScan (a.k.a. eSCL) backend for SANE
 *
 * Copyright (C) 2019 and up by Alexander Pevzner (pzz@apevzner.com)
 * See LICENSE for license terms and conditions
 */

#ifndef airscan_h
#define airscan_h

#include <avahi-common/address.h>
#include <avahi-common/strlst.h>
#include <avahi-glib/glib-watch.h>

#include <sane/sane.h>
#include <sane/saneopts.h>

#include <math.h>
#include <stdio.h>
#include <stdbool.h>

/******************** Static configuration ********************/
/* Configuration path in environment
 */
#define CONFIG_PATH_ENV                 "SANE_CONFIG_DIR"

/* Standard SANE configuration directory
 */
#define CONFIG_SANE_CONFIG_DIR          "/etc/sane.d/"

/* Sane-airscan configuration file and subdirectory names
 */
#define CONFIG_AIRSCAN_CONF             "airscan.conf"
#define CONFIG_AIRSCAN_D                "airscan.d"

/* Environment variables
 */
#define CONFIG_ENV_AIRSCAN_DEBUG        "SANE_DEBUG_AIRSCAN"

/* Default resolution, DPI
 */
#define CONFIG_DEFAULT_RESOLUTION       300

/******************** Forward declarations ********************/
/* Type device represents a scanner devise
 */
typedef struct device device;

/******************** Utility macros ********************/
/* Obtain pointer to outer structure from pointer to
 * its known member
 */
#define OUTER_STRUCT(member_p,struct_t,field)                            \
    ((struct_t*)((char*)(member_p) - ((ptrdiff_t) &(((struct_t*) 0)->field))))

/******************** Error handling ********************/
/* Type error represents an error. Its value either NULL,
 * which indicates "no error" condition, or some opaque
 * non-null pointer, which can be converted to string
 * with textual description of the error, using the ESTRING()
 * function
 *
 * Caller should not attempt to free the memory, referred
 * by error or string, obtained from an error using the
 * ESTRING() function
 */
typedef struct {} *error;

/* Construct error from a string
 */
static inline error
ERROR (const char *s)
{
    return (error) s;
}

/* Obtain textual representation of the error
 */
static inline const char*
ESTRING (error err)
{
    return (const char*) err;
}

/******************** Configuration file loader ********************/
/* Device URI for manually disabled device
 */
#define CONF_DEVICE_DISABLE     "disable"

/* Device configuration, for manually added devices
 */
typedef struct conf_device conf_device;
struct conf_device {
    const char  *name; /* Device name */
    const char  *uri;  /* Device URI, parsed; NULL if device disabled */
    conf_device *next; /* Next device in the list */
};

/* Backend configuration
 */
typedef struct {
    bool        dbg_enabled;      /* Debugging enabled */
    const char  *dbg_trace;       /* Trace directory */
    conf_device *devices;         /* Manually configured devices */
    bool        discovery;        /* Scanners discovery enabled */
    bool        model_is_netname; /* Use network name instead of model */
} conf_data;

#define CONF_INIT { false, NULL, NULL, true, true }

extern conf_data conf;

/* Load configuration. It updates content of a global conf variable
 */
void
conf_load (void);

/* Free resources, allocated by conf_load, and reset configuration
 * data into initial state
 */
void
conf_unload (void);

/******************** Pollable events ********************/
/* The pollable event
 *
 * Pollable events allow to wait until some event happens
 * and can be used in combination with select()/poll()
 * system calls
 */
typedef struct pollable pollable;

/* Create new pollable event
 */
pollable*
pollable_new (void);

/* Free pollable event
 */
void
pollable_free (pollable *p);

/* Get file descriptor for poll()/select().
 *
 * When pollable event becomes "ready", this file descriptor
 * becomes readable from the select/poll point of view
 */
int
pollable_get_fd (pollable *p);

/* Make pollable event "ready"
 */
void
pollable_signal (pollable *p);

/* Make pollable event "not ready"
 */
void
pollable_reset (pollable *p);

/* Wait until pollable event is ready
 */
void
pollable_wait (pollable *p);

/******************** Event loop ********************/
/* Initialize event loop
 */
SANE_Status
eloop_init (void);

/* Cleanup event loop
 */
void
eloop_cleanup (void);

/* Add start/stop callback. This callback is called
 * on a event loop thread context, once when event
 * loop is started, and second time when it is stopped
 *
 * Start callbacks are called in the same order as
 * they were added. Stop callbacks are called in a
 * reverse order
 */
void
eloop_add_start_stop_callback (void (*callback) (bool start));

/* Start event loop thread.
 *
 * Callback is called from the thread context twice:
 *     callback(true)  - when thread is started
 *     callback(false) - when thread is about to exit
 */
void
eloop_thread_start (void);

/* Stop event loop thread and wait until its termination
 */
void
eloop_thread_stop (void);

/* Acquire event loop mutex
 */
void
eloop_mutex_lock (void);

/* Release event loop mutex
 */
void
eloop_mutex_unlock (void);

/* Wait on conditional variable under the event loop mutex
 */
void
eloop_cond_wait (GCond *cond);

/* eloop_cond_wait() with timeout in seconds
 */
bool
eloop_cond_wait_until (GCond *cond, gint64 timeout);

/* Create AvahiGLibPoll that runs in context of the event loop
 */
AvahiGLibPoll*
eloop_new_avahi_poll (void);

/* Call function on a context of event loop thread
 */
void
eloop_call (GSourceFunc func, gpointer data);

/* Event notifier. Calls user-defined function on a context
 * of event loop thread, when event is triggered. This is
 * safe to trigger the event from a context of any thread
 * or even from a signal handler
 */
typedef struct eloop_event eloop_event;

/* Create new event notifier. May return NULL
 */
eloop_event*
eloop_event_new (void (*callback)(void *), void *data);

/* Destroy event notifier
 */
void
eloop_event_free (eloop_event *event);

/* Trigger an event
 */
void
eloop_event_trigger (eloop_event *event);

/* Timer. Calls user-defined function after a specified
 * interval
 */
typedef struct eloop_timer eloop_timer;

/* Create new timer. Timeout is in milliseconds
 */
eloop_timer*
eloop_timer_new (int timeout, void (*callback)(void *), void *data);

/* Cancel a timer
 *
 * Caller SHOULD NOT cancel expired timer (timer with called
 * callback) -- this is done automatically
 */
void
eloop_timer_cancel (eloop_timer *timer);

/* Format error string, as printf() does and save result
 * in the memory, owned by the event loop
 *
 * Caller should not free returned string. This is safe
 * to use the returned string as an argument to the
 * subsequent eloop_eprintf() call.
 *
 * The returned string remains valid until next call
 * to eloop_eprintf(), which makes it usable to
 * report errors up by the stack. However, it should
 * not be assumed, that the string will remain valid
 * on a next eloop roll, so don't save this string
 * anywhere, if you need to do so, create a copy!
 */
error
eloop_eprintf(const char *fmt, ...);

/******************** HTTP Client ********************/
/* Type http_uri represents HTTP URI
 */
typedef struct http_uri http_uri;

/* Create new URI, by parsing URI string
 */
http_uri*
http_uri_new (const char *str, bool strip_fragment);

/* Create URI, relative to base URI. If `path_only' is
 * true, scheme, host and port are taken from the
 * base URI
 */
http_uri*
http_uri_new_relative (const http_uri *base, const char *path,
        bool strip_fragment, bool path_only);

/* Free the URI
 */
void
http_uri_free (http_uri *uri);

/* Get URI string
 */
const char*
http_uri_str (http_uri *uri);

/* Get URI path
 */
const char*
http_uri_get_path (const http_uri *uri);

/* Set URI path
 */
void
http_uri_set_path (http_uri *uri, const char *path);

/* HTTP data
 */
typedef struct {
    const void *bytes; /* Data bytes */
    size_t     size;  /* Data size */
} http_data;

/* Ref http_data
 */
http_data*
http_data_ref (http_data *data);

/* Unref http_data
 */
void
http_data_unref (http_data *data);

/* Type http_client represents HTTP client instance
 */
typedef struct http_client http_client;

/* Create new http_client
 */
http_client*
http_client_new (device *dev);

/* Destroy http_client
 */
void
http_client_free (http_client *client);

/* Cancel pending http_query, if any
 */
void
http_client_cancel (http_client *client);

/* Set on-error callback. If this callback is not NULL,
 * in a case of transport error it will be called instead
 * of the http_query callback
 */
void
http_client_onerror (http_client *client,
        void (*callback)(device *dev, error err));

/* Type http_query represents HTTP query (both request and response)
 */
typedef struct http_query http_query;

/* Create new http_query
 *
 * Newly created http_query takes ownership on uri and body (if not NULL).
 * The method and content_type assumed to be constant strings.
 *
 * When query is finished, callback will be called. After return from
 * callback, memory, owned by http_query will be invalidated
 */
http_query*
http_query_new (http_client *client, http_uri *uri, const char *method,
        char *body, const char *content_type,
        void (*callback) (device *dev, http_query *q));

/* Get query error, if any
 *
 * Both transport errors and erroneous HTTP response codes
 * considered as errors here
 */
error
http_query_error (http_query *q);

/* Get query transport error, if any
 *
 * Only transport errors considered errors here
 */
error
http_query_transport_error (http_query *q);

/* Get HTTP status code. Code not available, if query finished
 * with error
 */
int
http_query_status (http_query *q);

/* Get HTTP status string
 */
const char*
http_query_status_string (http_query *q);

/* Get query URI
 */
http_uri*
http_query_uri (http_query *q);

/* Get query method
 */
const char*
http_query_method (http_query *q);

/* Get request header
 */
const char*
http_query_get_request_header (http_query *q, const char *name);

/* Get response header
 */
const char*
http_query_get_response_header (http_query *q, const char *name);

/* Get request data
 */
http_data*
http_query_get_request_data (http_query *q);

/* Get request data
 */
http_data*
http_query_get_response_data (http_query *q);

/* Call callback for each request header
 */
void
http_query_foreach_request_header (http_query *q,
        void (*callback)(const char *name, const char *value, void *ptr),
        void *ptr);

/* Call callback for each response header
 */
void
http_query_foreach_response_header (http_query *q,
        void (*callback)(const char *name, const char *value, void *ptr),
        void *ptr);

/* Some HTTP status codes
 */
enum {
    HTTP_STATUS_OK                  = 200,
    HTTP_STATUS_CREATED             = 201,
    HTTP_STATUS_SERVICE_UNAVAILABLE = 503
};

/* Initialize HTTP client
 */
SANE_Status
http_init (void);

/* Initialize HTTP client
 */
void
http_cleanup (void);

/******************** UUID generator ********************/
/* Type uuid represents a random UUID string.
 *
 * It is wrapped into struct, so it can be returned
 * by value, without need to mess with memory allocation
 */
typedef struct {
    char text[sizeof("ede05377-460e-4b4a-a5c0-423f9e02e8fa")];
} uuid;

/* Generate new random UUID
 */
uuid
uuid_new (void);

/******************** Protocol trace ********************/
/* Type trace represents an opaque handle of trace
 * file
 */
typedef struct trace trace;

/* Initialize protocol trace. Called at backend initialization
 */
SANE_Status
trace_init (void);

/* Cleanup protocol trace. Called at backend unload
 */
void
trace_cleanup (void);

/* Open protocol trace
 */
trace*
trace_open (const char *device_name);

/* Close protocol trace
 */
void
trace_close (trace *t);

/* This hook is called on every http_query completion
 */
void
trace_http_query_hook (trace *t, http_query *q);

/* Printf to the trace log
 */
void
trace_printf (trace *t, const char *fmt, ...);

/* Note an error in trace log
 */
void
trace_error (trace *t, error err);

/******************** SANE_Word/SANE_String arrays ********************/
/* Initialize array of SANE_Word
 */
void
sane_word_array_init (SANE_Word **a);

/* Cleanup array of SANE_Word
 */
void
sane_word_array_cleanup (SANE_Word **a);

/* Reset array of SANE_Word
 */
void
sane_word_array_reset (SANE_Word **a);

/* Get length of the SANE_Word array
 */
size_t
sane_word_array_len (SANE_Word **a);

/* Append word to array
 */
void
sane_word_array_append(SANE_Word **a, SANE_Word w);

/* Sort array of SANE_Word in increasing order
 */
void
sane_word_array_sort(SANE_Word **a);

/* Initialize array of SANE_String
 */
void
sane_string_array_init (SANE_String **a);

/* Reset array of SANE_String
 */
void
sane_string_array_reset (SANE_String **a);

/* Cleanup array of SANE_String
 */
void
sane_string_array_cleanup (SANE_String **a);

/* Get length of the SANE_Word array
 */
size_t
sane_string_array_len (SANE_String **a);

/* Append string to array
 */
void
sane_string_array_append(SANE_String **a, SANE_String s);

/* Compute max string length in array of strings
 */
size_t
sane_string_array_max_strlen(SANE_String **a);

/******************** XML utilities ********************/
/* XML reader
 */
typedef struct xml_rd xml_rd;

/* Parse XML text and initialize reader to iterate
 * starting from the root node
 *
 * On success, saves newly constructed reader into
 * the xml parameter.
 */
error
xml_rd_begin (xml_rd **xml, const char *xml_text, size_t xml_len);

/* Finish reading, free allocated resources
 */
void
xml_rd_finish (xml_rd **xml);

/* Check for end-of-document condition
 */
bool
xml_rd_end (xml_rd *xml);

/* Shift to the next node
 */
void
xml_rd_next (xml_rd *xml);

/* Enter the current node - iterate its children
 */
void
xml_rd_enter (xml_rd *xml);

/* Leave the current node - return to its parent
 */
void
xml_rd_leave (xml_rd *xml);

/* Get name of the current node.
 *
 * The returned string remains valid, until reader is cleaned up
 * or current node is changed (by set/next/enter/leave operations).
 * You don't need to free this string explicitly
 */
const char*
xml_rd_node_name (xml_rd *xml);

/* Match name of the current node against the pattern
 */
bool
xml_rd_node_name_match (xml_rd *xml, const char *pattern);

/* Get value of the current node as text
 *
 * The returned string remains valid, until reader is cleaned up
 * or current node is changed (by set/next/enter/leave operations).
 * You don't need to free this string explicitly
 */
const char*
xml_rd_node_value (xml_rd *xml);

/* Get value of the current node as unsigned integer
 */
error
xml_rd_node_value_uint (xml_rd *xml, SANE_Word *val);

/* XML writer
 */
typedef struct xml_wr xml_wr;

/* Begin writing XML document. Root node will be created automatically
 */
xml_wr*
xml_wr_begin (const char *root);

/* Finish writing, generate document string.
 * Caller must g_free() this string after use
 */
char*
xml_wr_finish (xml_wr *xml);

/* Add node with textual value
 */
void
xml_wr_add_text (xml_wr *xml, const char *name, const char *value);

/* Add node with unsigned integer value
 */
void
xml_wr_add_uint (xml_wr *xml, const char *name, unsigned int value);

/* Add node with boolean value
 */
void
xml_wr_add_bool (xml_wr *xml, const char *name, bool value);

/* Create node with children and enter newly added node
 */
void
xml_wr_enter (xml_wr *xml, const char *name);

/* Leave the current node
 */
void
xml_wr_leave (xml_wr *xml);

/******************** Sane Options********************/
/* Options numbers, for internal use
 */
enum {
    OPT_NUM_OPTIONS,            /* Total number of options */

    /* Standard options group */
    OPT_GROUP_STANDARD,
    OPT_SCAN_RESOLUTION,
    OPT_SCAN_COLORMODE,         /* I.e. color/grayscale etc */
    OPT_SCAN_SOURCE,            /* Platem/ADF/ADF Duplex */

    /* Geometry options group */
    OPT_GROUP_GEOMETRY,
    OPT_SCAN_TL_X,
    OPT_SCAN_TL_Y,
    OPT_SCAN_BR_X,
    OPT_SCAN_BR_Y,

    /* Total count of options, computed by compiler */
    NUM_OPTIONS
};

/* Source numbers, for internal use
 */
typedef enum {
    OPT_SOURCE_UNKNOWN = -1, /* Unknown */
    OPT_SOURCE_PLATEN,       /* Flatbed (a.k.a platen) scanner */
    OPT_SOURCE_ADF_SIMPLEX,  /* ADF in simplex mode */
    OPT_SOURCE_ADF_DUPLEX,   /* ADF in duplex mode */

    NUM_OPT_SOURCE
} OPT_SOURCE;

/* Color mode numbers, for internal use
 */
typedef enum {
    OPT_COLORMODE_UNKNOWN = -1, /* Unknown */
    OPT_COLORMODE_COLOR,        /* RGB-24 */
    OPT_COLORMODE_GRAYSCALE,    /* 8-bit gray scale */
    OPT_COLORMODE_LINEART,      /* 1-bit black and white */

    NUM_OPT_COLORMODE
} OPT_COLORMODE;

/* String constants for certain SANE options values
 * (missed from sane/sameopt.h)
 */
#define OPTVAL_SOURCE_PLATEN      "Flatbed"
#define OPTVAL_SOURCE_ADF_SIMPLEX "ADF"
#define OPTVAL_SOURCE_ADF_DUPLEX  "ADF Duplex"

/* Decode OPT_SOURCE from SANE name
 */
OPT_SOURCE
opt_source_from_sane (SANE_String_Const name);

/* Get SANE name of OPT_SOURCE
 */
SANE_String_Const
opt_source_to_sane (OPT_SOURCE source);

/* Decode OPT_COLORMODE from SANE name
 */
OPT_COLORMODE
opt_colormode_from_sane (SANE_String_Const name);

/* Get SANE name of OPT_COLORMODE
 */
SANE_String_Const
opt_colormode_to_sane (OPT_COLORMODE mode);

/******************** Device Capabilities ********************/
/* Source flags
 */
enum {
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
    DEVCAPS_SOURCE_FMT_PNG  = (1 << 10), /* PNG image */
    DEVCAPS_SOURCE_FMT_PDF  = (1 << 11), /* PDF image */

    /* Miscellaneous flags */
    DEVCAPS_SOURCE_HAS_SIZE = (1 << 12), /* max_width, max_height and
                                            derivatives are valid */

    /* Protocol dialects */
    DEVCAPS_SOURCE_PWG_DOCFMT      = (1 << 13), /* pwg:DocumentFormat */
    DEVCAPS_SOURCE_SCAN_DOCFMT_EXT = (1 << 14), /* scan:DocumentFormatExt */
};

/* Source Capabilities (each device may contain multiple sources)
 */
typedef struct {
    unsigned int flags;                  /* Source flags */
    unsigned int colormodes;             /* Set of 1 << OPT_COLORMODE */
    SANE_String  *sane_colormodes;       /* Color modes, in SANE format */
    SANE_Word    min_wid_px, max_wid_px; /* Min/max width, in pixels */
    SANE_Word    min_hei_px, max_hei_px; /* Min/max height, in pixels */
    SANE_Word    *resolutions;           /* Discrete resolutions, in DPI */
    SANE_Range   res_range;              /* Resolutions range, in DPI */
    SANE_Range   win_x_range_mm;         /* Window x range, in mm */
    SANE_Range   win_y_range_mm;         /* Window y range, in mm */
} devcaps_source;

/* Device Capabilities
 */
typedef struct {
    /* Device identification */
    const char     *model;              /* Device model */
    const char     *vendor;             /* Device vendor */

    /* Sources */
    SANE_String    *sane_sources;        /* Sources, in SANE format */
    devcaps_source *src[NUM_OPT_SOURCE]; /* Missed sources are NULL */
} devcaps;

/* Initialize Device Capabilities
 */
void
devcaps_init (devcaps *caps);

/* Cleanup Device Capabilities
 */
void
devcaps_cleanup (devcaps *caps);

/* Parse device capabilities. devcaps structure must be initialized
 * before calling this function.
 */
error
devcaps_parse (devcaps *caps, const char *xml_text, size_t xml_len);

/* Dump device capabilities, for debugging
 */
void
devcaps_dump (trace *t, devcaps *caps);

/******************** Device options ********************/
/* Scan options
 */
typedef struct {
    devcaps                caps;              /* Device capabilities */
    SANE_Option_Descriptor desc[NUM_OPTIONS]; /* Option descriptors */
    OPT_SOURCE             src;               /* Current source */
    OPT_COLORMODE          colormode;         /* Color mode */
    SANE_Word              resolution;        /* Current resolution */
    SANE_Fixed             tl_x, tl_y;        /* Top-left x/y */
    SANE_Fixed             br_x, br_y;        /* Bottom-right x/y */
    SANE_Parameters        params;            /* Scan parameters */
} devopt;

/* Initialize device options
 */
void
devopt_init (devopt *opt);

/* Cleanup device options
 */
void
devopt_cleanup (devopt *opt);

/* Parse device capabilities, and set default options values
 */
error
devopt_import_caps (devopt *opt, const char *xml_text, size_t xml_len);

/* Set device option
 */
SANE_Status
devopt_set_option (devopt *opt, SANE_Int option, void *value, SANE_Word *info);

/* Get device option
 */
SANE_Status
devopt_get_option (devopt *opt, SANE_Int option, void *value);

/******************** ZeroConf (device discovery) ********************/
/* ZeroConf resolved address information
 */
typedef struct zeroconf_addrinfo zeroconf_addrinfo;
struct zeroconf_addrinfo {
    const char        *uri;      /* I.e, "http://192.168.1.1:8080/eSCL/" */
    bool              ipv6;      /* This is an IPv6 address */
    bool              linklocal; /* This is a link-local address */
    zeroconf_addrinfo *next;     /* Next address in the list */
};

/* Initialize ZeroConf
 */
SANE_Status
zeroconf_init (void);

/* Cleanup ZeroConf
 */
void
zeroconf_cleanup (void);

/* Check if initial scan still in progress
 */
bool
zeroconf_init_scan (void);

/* Create a copy of zeroconf_addrinfo list
 */
zeroconf_addrinfo*
zeroconf_addrinfo_list_copy (zeroconf_addrinfo *list);

/* Free zeroconf_addrinfo list
 */
void
zeroconf_addrinfo_list_free (zeroconf_addrinfo *list);

/******************** WS-Discovery ********************/
/* Initialize WS-Discovery
 */
SANE_Status
wsdiscovery_init (void);

/* Cleanup WS-Discovery
 */
void
wsdiscovery_cleanup (void);

/******************** Device Management ********************/
/* Get list of devices, in SANE format
 */
const SANE_Device**
device_list_get (void);

/* Free list of devices, returned by device_list_get()
 */
void
device_list_free (const SANE_Device **dev_list);

/* Get device name (mostly for debugging
 */
const char*
device_name (device *dev);

/* Get device's trace handle
 */
trace*
device_trace (device *dev);

/* Open a device
 */
SANE_Status
device_open (const char *name, device **out);

/* Close the device
 */
void
device_close (device *dev);

/* Get option descriptor
 */
const SANE_Option_Descriptor*
device_get_option_descriptor (device *dev, SANE_Int option);

/* Get device option
 */
SANE_Status
device_get_option (device *dev, SANE_Int option, void *value);

/* Set device option
 */
SANE_Status
device_set_option (device *dev, SANE_Int option, void *value, SANE_Word *info);

/* Get current scan parameters
 */
SANE_Status
device_get_parameters (device *dev, SANE_Parameters *params);

SANE_Status
device_start (device *dev);

/* Cancel scanning operation
 */
void
device_cancel (device *dev);

/* Set I/O mode
 */
SANE_Status
device_set_io_mode (device *dev, SANE_Bool non_blocking);

/* Get select file descriptor
 */
SANE_Status
device_get_select_fd (device *dev, SANE_Int *fd);

/* Read scanned image
 */
SANE_Status
device_read (device *dev, SANE_Byte *data, SANE_Int max_len, SANE_Int *len);

/* Device found notification -- called by ZeroConf
 */
void
device_event_found (const char *name, bool init_scan,
        zeroconf_addrinfo *addresses);

/* Device removed notification -- called by ZeroConf
 */
void
device_event_removed (const char *name);

/* Device initial scan finished notification -- called by ZeroConf
 */
void
device_event_init_scan_finished (void);

/* Initialize device management
 */
SANE_Status
device_management_init (void);

/* Cleanup device management
 */
void
device_management_cleanup (void);

/******************** Image decoding ********************/
/* The window withing the image
 *
 * Note, all sizes and coordinates are in pixels
 */
typedef struct {
    int x_off, y_off;  /* Top-left corner offset */
    int wid, hei;      /* Image width and height */
} image_window;

/* Image decoder, with virtual methods
 */
typedef struct image_decoder image_decoder;
struct image_decoder {
    const char *content_type;
    void  (*free) (image_decoder *decoder);
    error (*begin) (image_decoder *decoder, const void *data, size_t size);
    void  (*reset) (image_decoder *decoder);
    int   (*get_bytes_per_pixel) (image_decoder *decoder);
    void  (*get_params) (image_decoder *decoder, SANE_Parameters *params);
    error (*set_window) (image_decoder *decoder, image_window *win);
    error (*read_line) (image_decoder *decoder, void *buffer);
};

/* Create JPEG image decoder
 */
image_decoder*
image_decoder_jpeg_new (void);

/* Free image decoder
 */
static inline void
image_decoder_free (image_decoder *decoder)
{
    decoder->free(decoder);
}

/* Get content type
 */
static inline const char*
image_content_type (image_decoder *decoder)
{
    return decoder->content_type;
}

/* Begin image decoding. Decoder may assume that provided data
 * buffer remains valid during a whole decoding cycle
 */
static inline error
image_decoder_begin (image_decoder *decoder, const void *data, size_t size)
{
    return decoder->begin(decoder, data, size);
}

/* Reset image decoder after use. After reset, decoding of the
 * another image can be started
 */
static inline void
image_decoder_reset (image_decoder *decoder)
{
    decoder->reset(decoder);
}

/* Get bytes count per pixel
 */
static inline int
image_decoder_get_bytes_per_pixel (image_decoder *decoder)
{
    return decoder->get_bytes_per_pixel(decoder);
}

/* Get image parameters. Can be called at any time between
 * image_decoder_begin() and image_decoder_reset()
 *
 * Decoder must return an actual image parameters, regardless
 * of clipping window set by image_decoder_set_window()
 */
static inline void
image_decoder_get_params (image_decoder *decoder, SANE_Parameters *params)
{
    decoder->get_params(decoder, params);
}

/* Set window within the image. Only part of image that fits the
 * window needs to be decoded. Decoder may assume that window is
 * always within the actual image boundaries
 *
 * Note, if decoder cannot handle exact window boundaries, it
 * it must update window to keep actual values
 *
 * In particular, if decoder doesn't implement image clipping
 * at all, it is safe that decoder will simply set window boundaries
 * to contain an entire image
 */
static inline error
image_decoder_set_window (image_decoder *decoder, image_window *win)
{
    return decoder->set_window(decoder, win);
}

/* Read next line of image. Decoder may safely assume the provided
 * buffer is big enough to keep the entire line
 */
static inline error
image_decoder_read_line (image_decoder *decoder, void *buffer)
{
    return decoder->read_line(decoder, buffer);
}

/******************** Mathematical Functions ********************/
/* Find greatest common divisor of two positive integers
 */
SANE_Word
math_gcd (SANE_Word x, SANE_Word y);

/* Find least common multiple of two positive integers
 */
SANE_Word
math_lcm (SANE_Word x, SANE_Word y);

/* Find min of two words
 */
static inline SANE_Word
math_min (SANE_Word a, SANE_Word b)
{
    return a < b ? a : b;
}

/* Find max of two words
 */
static inline SANE_Word
math_max (SANE_Word a, SANE_Word b)
{
    return a > b ? a : b;
}

/* Bound integer within range
 */
static inline SANE_Word
math_bound (SANE_Word x, SANE_Word min, SANE_Word max)
{
    if (x < min) {
        return min;
    } else if (x > max) {
        return max;
    } else {
        return x;
    }
}

/* Compute x * mul / div, taking in account rounding
 * and integer overflow
 */
static inline SANE_Word
math_muldiv (SANE_Word x, SANE_Word mul, SANE_Word div)
{
    int64_t tmp;

    tmp = (int64_t) x * (int64_t) mul;
    tmp += div / 2;
    tmp /= div;

    return (SANE_Word) tmp;
}

/* Merge two ranges, if possible
 */
bool
math_range_merge (SANE_Range *out, const SANE_Range *r1, const SANE_Range *r2);

/* Choose nearest integer in range
 */
SANE_Word
math_range_fit (const SANE_Range *r, SANE_Word i);

/* Convert pixels to millimeters, using given resolution
 */
static inline SANE_Fixed
math_px2mm_res (SANE_Word px, SANE_Word res)
{
    return SANE_FIX((double) px * 25.4 / res);
}

/* Convert millimeters to pixels, using given resolution
 */
static inline SANE_Word
math_mm2px_res (SANE_Fixed mm, SANE_Word res)
{
    return (SANE_Word) roundl(SANE_UNFIX(mm) * res / 25.4);
}

/* Convert pixels to millimeters, assuming 300 DPI
 */
static inline SANE_Fixed
math_px2mm (SANE_Word px)
{
    return math_px2mm_res(px, 300);
}

/* Convert millimeters to pixels, assuming 300 DPI
 */
static inline SANE_Word
math_mm2px (SANE_Fixed mm)
{
    return math_mm2px_res(mm, 300);
}

/* Format millimeters, for printing
 */
char*
math_fmt_mm (SANE_Word mm, char buf[]);

/******************** Logging ********************/
/* Initialize logging
 *
 * No log messages should be generated before this call
 */
void
log_init (void);

/* Cleanup logging
 *
 * No log messages should be generated after this call
 */
void
log_cleanup (void);

/* Notify logger that configuration is loaded and
 * logger can configure itself
 *
 * This is safe to generate log messages before log_configure()
 * is called. These messages will be buffered, and after
 * logger is configured, either written or abandoned, depending
 * on configuration
 */
void
log_configure (void);

/* Write a debug message. If dev != NULL, message will
 * be written in a context of device.
 */
void
log_debug (device *dev, const char *fmt, ...);

/* Write an error message and terminate a program.
 * If dev != NULL, message will be written in a context of device.
 */
void
log_panic (device *dev, const char *fmt, ...);

/* Panic if assertion fails
 */
#define log_assert(dev,expr)                                            \
     do {                                                               \
         if (!(expr)) {                                                 \
             log_panic(dev,"file %s: line %d (%s): assertion failed: (%s)",\
                     __FILE__, __LINE__, __PRETTY_FUNCTION__, #expr);   \
         }                                                              \
     } while (0)

/* Panic if this code is reached
 */
#define log_internal_error(dev)                                         \
     do {                                                               \
         log_panic(dev,"file %s: line %d (%s): internal error",         \
                 __FILE__, __LINE__, __PRETTY_FUNCTION__);              \
     } while (0)

#endif

/* vim:ts=8:sw=4:et
 */
