/* AirScan (a.k.a. eSCL) backend for SANE
 *
 * Copyright (C) 2019 and up by Alexander Pevzner (pzz@apevzner.com)
 * See LICENSE for license terms and conditions
 */

#ifndef airscan_h
#define airscan_h

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

#endif

/* vim:ts=8:sw=4:et
 */
