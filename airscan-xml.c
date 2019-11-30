/* AirScan (a.k.a. eSCL) backend for SANE
 *
 * Copyright (C) 2019 and up by Alexander Pevzner (pzz@apevzner.com)
 * See LICENSE for license terms and conditions
 *
 * XML utilities
 */

#include "airscan.h"

#include <libxml/tree.h>

/* XML reader
 */
struct xml_rd {
    xmlDoc        *doc;    /* XML document */
    xmlNode       *node;   /* Current node */
    xmlNode       *parent; /* Parent node */
    const char    *name;   /* Name of current node */
    const xmlChar *text;   /* Textual value of current node */
};

/* Skip dummy nodes. This is internal function, don't call directly
 */
static void
__xml_rd_skip_dummy (xml_rd *xml)
{
    xmlNode *node = xml->node;

    while (node  != NULL &&
           (node->type == XML_COMMENT_NODE || xmlIsBlankNode (node))) {
        node = node->next;
    }

    xml->node = node;
}

/* Invalidate cached data. This is internal function, don't call directly
 */
static void
__xml_rd_invalidate_cache (xml_rd *xml)
{
    g_free((void*) xml->name);
    xmlFree((xmlChar*) xml->text);
    xml->name = NULL;
    xml->text = NULL;
}

/* Parse XML text and initialize reader to iterate
 * starting from the root node
 *
 * Returns NULL on success, or error text on a error
 */
const char*
xml_rd_begin (xml_rd **xml, const char *xml_text, size_t xml_len)
{
    *xml = g_new0(xml_rd, 1);

    (*xml)->doc = xmlParseMemory(xml_text, xml_len);
    if ((*xml)->doc == NULL) {
        xml_rd_finish(xml);
        return "Failed to parse XML";
    }

    (*xml)->node = xmlDocGetRootElement((*xml)->doc);
    __xml_rd_skip_dummy(*xml);
    __xml_rd_invalidate_cache(*xml);
    (*xml)->parent = (*xml)->node ? (*xml)->node->parent : NULL;

    return NULL;
}

/* Finish reading, free allocated resources
 */
void
xml_rd_finish (xml_rd **xml)
{
    if (*xml) {
        if ((*xml)->doc) {
            xmlFree((*xml)->doc);
        }
        __xml_rd_invalidate_cache(*xml);

        g_free(*xml);
        *xml = NULL;
    }
}

/* Check for end-of-document condition
 */
bool
xml_rd_end (xml_rd *xml)
{
    return xml->node == NULL;
}

/* Shift to the next node
 */
void
xml_rd_next (xml_rd *xml)
{
    if (xml->node) {
        xml->node = xml->node->next;
        __xml_rd_skip_dummy(xml);
        __xml_rd_invalidate_cache(xml);
    }
}

/* Enter the current node - iterate its children
 */
void
xml_rd_enter (xml_rd *xml)
{
    if (xml->node) {
        xml->parent = xml->node;
        xml->node = xml->node->children;
        __xml_rd_skip_dummy(xml);
        __xml_rd_invalidate_cache(xml);
    }
}

/* Leave the current node - return to its parent
 */
void
xml_rd_leave (xml_rd *xml)
{
    xml->node = xml->parent;
    if (xml->node) {
        xml->parent = xml->node->parent;
    }
    __xml_rd_invalidate_cache(xml);
}

/* Get name of the current node.
 *
 * The returned string remains valid, until reader is cleaned up
 * or current node is changed (by set/next/enter/leave operations).
 * You don't need to free this string explicitly
 */
const char*
xml_rd_node_name (xml_rd *xml)
{
    const char *prefix = NULL;

    if (xml->name == NULL && xml->node != NULL) {
        if (xml->node->ns != NULL) {
            prefix = (const char*) xml->node->ns->prefix;
        }

        if (prefix != NULL) {
            xml->name = g_strconcat(prefix, ":", xml->node->name, NULL);
        } else {
            xml->name = g_strdup((const char*) xml->node->name);
        }
    }

    return xml->name;
}

/* Match name of the current node against the pattern
 */
bool
xml_rd_node_name_match (xml_rd *xml, const char *pattern)
{
    return !g_strcmp0(xml_rd_node_name(xml), pattern);
}

/* Get value of the current node as text
 *
 * The returned string remains valid, until reader is cleaned up
 * or current node is changed (by set/next/enter/leave operations).
 * You don't need to free this string explicitly
 */
const char*
xml_rd_node_value (xml_rd *xml)
{
    if (xml->text == NULL && xml->node != NULL) {
        xml->text = xmlNodeGetContent(xml->node);
        g_strstrip((char*) xml->text);
    }

    return (const char*) xml->text;
}

/* Get value of the current node as unsigned integer
 * Returns error string, NULL if OK
 */
const char*
xml_rd_node_value_uint (xml_rd *xml, SANE_Word *val)
{
    const char *s = xml_rd_node_value(xml);
    char *end;
    unsigned long v;

    g_assert(s != NULL);

    v = strtoul(s, &end, 10);
    if (end == s || *end || v != (unsigned long) (SANE_Word) v) {
        return eloop_eprintf("%s: invalid numerical value",
                xml_rd_node_name(xml));
    }

    *val = (SANE_Word) v;
    return NULL;
}

/* vim:ts=8:sw=4:et
 */
