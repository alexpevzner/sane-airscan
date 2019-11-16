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

#include <libsoup/soup.h>
#include <libxml/tree.h>
#include <stdio.h>

/******************** Static configuration ********************/
/* Configuration path in environment
 */
#define CONFIG_PATH_ENV         "SANE_CONFIG_DIR"

/* Standard SANE configuration directory
 */
#define CONFIG_SANE_CONFIG_DIR  "/etc/sane.d/"

/* Sane-airscan configuration file and subdirectory names
 */
#define CONFIG_AIRSCAN_CONF     "airscan.conf"
#define CONFIG_AIRSCAN_D        "airscan.d"

/******************** Configuration file loader  ********************/
/* Device configuration, for manually added devices
 */
typedef struct conf_device conf_device;
struct conf_device {
    const char  *name; /* Device name */
    SoupURI     *uri;  /* Device URI, parsed */
    conf_device *next; /* Next device in the list */
};

/* Backend configuration
 */
typedef struct {
    int         dbg_flags;  /* Combination of debug flags */
    const char  *dbg_trace; /* Trace directory */
    conf_device *devices;   /* Manually configured devices */
} conf_data;

extern conf_data conf;

/* Load configuration. It updates content of a global conf variable
 */
void
conf_load (void);

/* Free resources, allocated by conf_load, and reset configuration
 * data into initial state
 */
void
conf_free (void);

/******************** Event loop ********************/
/* Initialize event loop
 */
SANE_Status
eloop_init (void);

/* Cleanup event loop
 */
void
eloop_cleanup (void);

/* Start event loop thread.
 *
 * Callback is called from the thread context twice:
 *     callback(TRUE)  - when thread is started
 *     callback(FALSE) - when thread is about to exit
 */
void
eloop_thread_start (void (*callback)(gboolean));

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
gboolean
eloop_cond_wait (GCond *cond, gint64 timeout);

/* Create AvahiGLibPoll that runs in context of the event loop
 */
AvahiGLibPoll*
eloop_new_avahi_poll (void);

/* Call function on a context of event loop thread
 */
void
eloop_call (GSourceFunc func, gpointer data);

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
const char*
eloop_eprintf(const char *fmt, ...);

/******************** Debugging ********************/
/* Debug flags
 */
enum {
    DBG_FLG_API       = (1 << 0), /* API tracing */
    DBG_FLG_DISCOVERY = (1 << 1), /* Device discovery debugging */
    DBG_FLG_PROTO     = (1 << 2), /* Protocol */
    DBG_FLG_DEVICE    = (1 << 3), /* Device management */
    DBG_FLG_HTTP      = (1 << 4), /* HTTP tracing */
    DBG_FLG_CONF      = (1 << 5), /* Configuration file loader */
    DBG_FLG_ALL       = 0xff
};

/* Check dbg_flags
 */
#define DBG_ENABLED(flg)        ((flg) & conf.dbg_flags)

/* Print debug message
 */
#define DBG_PRINT(flg, prefix, fmt, args...)                    \
    do{                                                         \
        if (DBG_ENABLED(flg)) {                                 \
            printf("airscan: " prefix ": " fmt "\n", ##args);   \
        }                                                       \
    } while(0)

/* Shortcuts for various subsystems
 */
#define DBG_API(fmt, args...)                   \
        DBG_PRINT(DBG_FLG_API, "api", fmt, ##args)

#define DBG_API_ENTER()         DBG_API("%s", __FUNCTION__)
#define DBG_API_LEAVE(status)                   \
        DBG_API("%s -- %s", __FUNCTION__, sane_strstatus(status))

#define DBG_DISCOVERY(name, fmt, args...)       \
        DBG_PRINT(DBG_FLG_DISCOVERY, "discovery", "\"%s\": " fmt, name, ##args)

#define DBG_PROTO(name, fmt, args...)           \
        DBG_PRINT(DBG_FLG_PROTO, "proto", "\"%s\": " fmt, name, ##args)

#define DBG_DEVICE(name, fmt, args...)          \
        DBG_PRINT(DBG_FLG_DEVICE, "dev", "\"%s\": " fmt, name, ##args)

#define DBG_HTTP(fmt, args...)                  \
        DBG_PRINT(DBG_FLG_HTTP, "http", fmt, ##args)

#define DBG_CONF(fmt, args...)                  \
        DBG_PRINT(DBG_FLG_CONF, "conf", fmt, ##args)

/******************** Typed Arrays ********************/
/* Initialize array of SANE_Word
 */
void
array_of_word_init (SANE_Word **a);

/* Cleanup array of SANE_Word
 */
void
array_of_word_cleanup (SANE_Word **a);

/* Reset array of SANE_Word
 */
void
array_of_word_reset (SANE_Word **a);

/* Get length of the SANE_Word array
 */
size_t
array_of_word_len (SANE_Word **a);

/* Append word to array
 */
void
array_of_word_append(SANE_Word **a, SANE_Word w);

/* Compare function for array_of_word_sort
 */
int
array_of_word_sort_cmp(const void *p1, const void *p2);

/* Sort array of SANE_Word in increasing order
 */
void
array_of_word_sort(SANE_Word **a);

/* Initialize array of SANE_String
 */
void
array_of_string_init (SANE_String **a);

/* Reset array of SANE_String
 */
void
array_of_string_reset (SANE_String **a);

/* Cleanup array of SANE_String
 */
void
array_of_string_cleanup (SANE_String **a);

/* Get length of the SANE_Word array
 */
size_t
array_of_string_len (SANE_String **a);

/* Append string to array
 */
void
array_of_string_append(SANE_String **a, SANE_String s);

/* Compute max string length in array of strings
 */
size_t
array_of_string_max_strlen(SANE_String **a);

/******************** XML utilities ********************/
/* XML iterator
 */
typedef struct {
    xmlDoc        *doc;    /* XML document */
    xmlNode       *node;   /* Current node */
    xmlNode       *parent; /* Parent node */
    const char    *name;   /* Name of current node */
    const xmlChar *text;   /* Textual value of current node */
} xml_iter;

/* Parse XML text and initialize iterator to iterate
 * starting from the root node
 *
 * Returns NULL on success, or error text on a error
 */
const char*
xml_iter_begin (xml_iter *iter, const char *xml_text, size_t xml_len);

/* Finish iteration, free allocated resources
 */
void
xml_iter_finish (xml_iter *iter);

/* Check for end-of-document condition
 */
SANE_Bool
xml_iter_end (xml_iter *iter);

/* Shift to the next node
 */
void
xml_iter_next (xml_iter *iter);

/* Enter the current node - iterate its children
 */
void
xml_iter_enter (xml_iter *iter);

/* Leave the current node - return to its parent
 */
void
xml_iter_leave (xml_iter *iter);

/* Get name of the current node.
 *
 * The returned string remains valid, until iterator is cleaned up
 * or current node is changed (by set/next/enter/leave operations).
 * You don't need to free this string explicitly
 */
const char*
xml_iter_node_name (xml_iter *iter);

/* Match name of the current node against the pattern
 */
SANE_Bool
xml_iter_node_name_match (xml_iter *iter, const char *pattern);

/* Get value of the current node as text
 *
 * The returned string remains valid, until iterator is cleaned up
 * or current node is changed (by set/next/enter/leave operations).
 * You don't need to free this string explicitly
 */
const char*
xml_iter_node_value (xml_iter *iter);

/* Get value of the current node as unsigned integer
 * Returns error string, NULL if OK
 */
const char*
xml_iter_node_value_uint (xml_iter *iter, SANE_Word *val);

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

/******************** ZeroConf (device discovery) ********************/
/* ZeroConf resolved address information
 */
typedef struct zeroconf_addrinfo zeroconf_addrinfo;
struct zeroconf_addrinfo {
    AvahiAddress      addr;      /* Device address */
    gboolean          linklocal; /* It's a link-local address */
    uint16_t          port;      /* Device port */
    const char        *rs;       /* "rs" portion of the TXT record */
    AvahiIfIndex      interface; /* Interface index */
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
gboolean
zeroconf_init_scan (void);

/* Create a copy of zeroconf_addrinfo list
 */
zeroconf_addrinfo*
zeroconf_addrinfo_list_copy (zeroconf_addrinfo *list);

/* Free zeroconf_addrinfo list
 */
void
zeroconf_addrinfo_list_free (zeroconf_addrinfo *list);

/******************** Device Management ********************/
typedef struct device device;

/* Get list of devices, in SANE format
 */
const SANE_Device**
device_list_get (void);

/* Free list of devices, returned by device_list_get()
 */
void
device_list_free (const SANE_Device **dev_list);

/* Open a device
 */
device*
device_open (const char *name);

/* Close the device
 */
void
device_close (device *dev);

/* Get option descriptor
 */
const SANE_Option_Descriptor*
dev_get_option_descriptor (device *dev, SANE_Int option);

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

/* Device found notification -- called by ZeroConf
 */
void
device_event_found (const char *name, gboolean init_scan,
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

/* Start/stop device management
 */
void
device_management_start_stop (gboolean start);

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
    DEVCAPS_SOURCE_FMT_PNG  = (1 << 10),  /* PNG image */
    DEVCAPS_SOURCE_FMT_PDF  = (1 << 11), /* PDF image */

    /* Miscellaneous flags */
    DEVCAPS_SOURCE_HAS_SIZE = (1 << 12), /* min_width, max_height and
                                            derivatives are valid */
};

/* Source Capabilities (each device may contain multiple sources)
 */
typedef struct {
    unsigned int flags;                    /* Source flags */
    unsigned int colormodes;               /* Set of 1 << OPT_COLORMODE */
    SANE_String  *sane_colormodes;         /* Color modes, in SANE format */
    SANE_Word    min_wid_px, max_wid_px;   /* Min/max width, in pixels */
    SANE_Word    min_hei_px, max_hei_px;   /* Min/max height, in pixels */
    SANE_Word    min_wid_mm, max_wid_mm;   /* Min/max width, in millimeters */
    SANE_Word    min_hei_mm, max_hei_mm;   /* Min/max height, in millimeters */
    SANE_Word    *resolutions;             /* Discrete resolutions, in DPI */
    SANE_Range   res_range;                /* Resolutions range, in DPI */
    SANE_Range   win_x_range, win_y_range; /* Window x/y ranges */
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

/* Reset Device Capabilities into initial state
 */
void
devcaps_reset (devcaps *caps);

/* Parse device capabilities. devcaps structure must be initialized
 * before calling this function.
 *
 * Returns NULL if OK, error string otherwise
 */
const char*
devcaps_parse (devcaps *caps, const char *xml_text, size_t xml_len);

/* Dump device capabilities, for debugging
 */
void
devcaps_dump (const char *name, devcaps *caps);

/* Choose appropriate scanner resolution
 */
SANE_Word
devcaps_source_choose_resolution(devcaps_source *src, SANE_Word wanted);

/* Choose appropriate color mode
 */
OPT_COLORMODE
devcaps_source_choose_colormode(devcaps_source *src, OPT_COLORMODE wanted);

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

/* Merge two ranges, if possible
 */
SANE_Bool
math_range_merge (SANE_Range *out, const SANE_Range *r1, const SANE_Range *r2);

/* Choose nearest integer in range
 */
SANE_Word
math_range_fit (const SANE_Range *r, SANE_Word i);

/* Convert pixels to millimeters, using given resolution
 */
static inline SANE_Word
math_px2mm_res (SANE_Word px, SANE_Word res)
{
    return SANE_FIX((double) px * 25.4 / res);
}

/* Convert millimeters to pixels, using given resolution
 */
static inline SANE_Word
math_mm2px_res (SANE_Word mm, SANE_Word res)
{
    return (SANE_Word) (SANE_UNFIX(mm) * res / 24.6);
}

/* Convert pixels to millimeters, assuming 300 DPI
 */
static inline SANE_Word
math_px2mm (SANE_Word px)
{
    return math_px2mm_res(px, 300);
}

/* Convert millimeters to pixels, assuming 300 DPI
 */
static inline SANE_Word
math_mm2px (SANE_Word mm)
{
    return math_mm2px_res(mm, 300);
}

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

/* This hook needs to be called from message
 * completion callback
 */
void
trace_msg_hook (trace *t, SoupMessage *msg);

#endif

/* vim:ts=8:sw=4:et
 */
