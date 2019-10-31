/* AirScan (a.k.a. eSCL) backend for SANE
 *
 * Copyright (C) 2019 and up by Alexander Pevzner (pzz@apevzner.com)
 * See LICENSE for license terms and conditions
 */

#ifndef airscan_h
#define airscan_h

#include <stdio.h>
#include <sane/sane.h>
#include <libxml/tree.h>

/******************** Debugging ********************/
/* Debug flags
 */
enum {
    DBG_FLG_API       = (1 << 0), /* API tracing */
    DBG_FLG_DISCOVERY = (1 << 1), /* Device discovery debugging */
    DBG_FLG_PROTO     = (1 << 2), /* Protocol */
    DBG_FLG_DEVICE    = (1 << 3), /* Device management */
    DBG_FLG_ALL       = 0xff
};

extern int dbg_flags;

/* Print debug message
 */
#define DBG_PRINT(flg, prefix, fmt, args...)                    \
    do{                                                         \
        if ((flg) & dbg_flags) {                                \
            printf("airscan: " prefix ": " fmt "\n", ##args);   \
        }                                                       \
    } while(0)

/* Shortcuts for various subsystems
 */
#define DBG_API(fmt, args...)                   \
        DBG_PRINT(DBG_FLG_API, "api", fmt, ##args)

#define DBG_API_ENTER() DBG_API("%s", __FUNCTION__)
#define DBG_API_LEAVE() DBG_API("%s -- DONE", __FUNCTION__)

#define DBG_DISCOVERY(name, fmt, args...)       \
        DBG_PRINT(DBG_FLG_DISCOVERY, "discovery", "\"%s\": " fmt, name, ##args)

#define DBG_PROTO(name, fmt, args...)           \
        DBG_PRINT(DBG_FLG_PROTO, "proto", "\"%s\": " fmt, name, ##args)

#define DBG_DEVICE(name, fmt, args...)           \
        DBG_PRINT(DBG_FLG_DEVICE, "proto", "\"%s\": " fmt, name, ##args)

/******************** Typed Arrays ********************/
/* Initialize array of SANE_Word
 */
void
array_of_word_init (SANE_Word **a);

/* Cleanup array of SANE_Word
 */
void
array_of_word_cleanup (SANE_Word **a);

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

/******************** XML utilities ********************/
/* XML iterator
 */
typedef struct {
    xmlNode       *node;
    xmlNode       *parent;
    const char    *name;
    const xmlChar *text;
    const char    *err;
} xml_iter;

/* Static initializer for the XML iterator
 */
#define XML_ITER_INIT   {NULL, NULL, NULL, NULL, NULL}

/* Initialize iterator to iterate starting from the given node
 */
void
xml_iter_init (xml_iter *iter, xmlNode *node);

/* Cleanup XML iterator
 */
void
xml_iter_cleanup (xml_iter *iter);

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
/* String constants for certain SANE options values
 */
#define OPTVAL_SOURCE_PLATEN      "Flatbed"
#define OPTVAL_SOURCE_ADF_SIMPLEX "ADF"
#define OPTVAL_SOURCE_ADF_DUPLEX  "ADF Duplex"

/******************** Device Capabilities  ********************/
/* Source flags
 */
enum {
    /* Supported color modes */
    DEVCAPS_SOURCE_COLORMODE_BW1         = (1 << 0), /* 1-bit black&white */
    DEVCAPS_SOURCE_COLORMODE_GRAYSCALE8  = (1 << 1), /* 8-bit gray scale */
    DEVCAPS_SOURCE_COLORMODE_RGB24       = (1 << 2), /* 24-bit RGB color */

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
    SANE_Word    min_width, max_width;     /* Min/max image width */
    SANE_Word    min_height, max_height;   /* Min/max image height */
    SANE_Word    *resolutions;             /* Discrete resolutions, in DPI */
    SANE_Range   res_range;                /* Resolutions range, in DPI */
    SANE_Range   win_x_range, win_y_range; /* Scan window range,
                                              SANE_Fixed, in mm */
} devcaps_source;

/* Device Capabilities
 */
typedef struct {
    /* Common capabilities */
    SANE_String    *sources;     /* Sources, in SANE format */
    const char     *model;       /* Device model */
    const char     *vendor;      /* Device vendor */

    /* Sources */
    devcaps_source *src_platen;      /* Platen (flatbed) scanner */
    devcaps_source *src_adf_simplex; /* ADF in simplex mode */
    devcaps_source *src_adf_duplex;  /* ADF in duplex mode */
} devcaps;

/* Initialize Device Capabilities
 */
void
devcaps_init (devcaps *caps);

/* Reset Device Capabilities: free all allocated memory, clear the structure
 */
void
devcaps_reset (devcaps *caps);

/* Parse device capabilities. devcaps structure must be initialized
 * before calling this function.
 *
 * Returns NULL if OK, error string otherwise
 */
const char*
devcaps_parse (devcaps *caps, xmlDoc *xml);

/* Dump device capabilities, for debugging
 */
void
devcaps_dump (const char *name, devcaps *caps);

/* Choose appropriate scanner resolution
 */
SANE_Word
devcaps_source_choose_resolution(devcaps_source *src, SANE_Word wanted);

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
math_range_fit(const SANE_Range *r, SANE_Word i);

#endif

/* vim:ts=8:sw=4:et
 */
