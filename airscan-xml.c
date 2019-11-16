/* AirScan (a.k.a. eSCL) backend for SANE
 *
 * Copyright (C) 2019 and up by Alexander Pevzner (pzz@apevzner.com)
 * See LICENSE for license terms and conditions
 *
 * XML utilities
 */

#include "airscan.h"

#include <libxml/tree.h>

/* XML iterator
 */
struct xml_iter {
    xmlDoc        *doc;    /* XML document */
    xmlNode       *node;   /* Current node */
    xmlNode       *parent; /* Parent node */
    const char    *name;   /* Name of current node */
    const xmlChar *text;   /* Textual value of current node */
};

/* Skip dummy nodes. This is internal function, don't call directly
 */
static void
__xml_iter_skip_dummy (xml_iter *iter)
{
    xmlNode *node = iter->node;

    while (node  != NULL &&
           (node->type == XML_COMMENT_NODE || xmlIsBlankNode (node))) {
        node = node->next;
    }

    iter->node = node;
}

/* Invalidate cached data. This is internal function, don't call directly
 */
static void
__xml_iter_invalidate_cache (xml_iter *iter)
{
    g_free((void*) iter->name);
    xmlFree((xmlChar*) iter->text);
    iter->name = NULL;
    iter->text = NULL;
}

/* Parse XML text and initialize iterator to iterate
 * starting from the root node
 *
 * Returns NULL on success, or error text on a error
 */
const char*
xml_iter_begin (xml_iter **iter, const char *xml_text, size_t xml_len)
{
    *iter = g_new0(xml_iter, 1);

    (*iter)->doc = xmlParseMemory(xml_text, xml_len);
    if ((*iter)->doc == NULL) {
        xml_iter_finish(iter);
        return "Failed to parse XML";
    }

    (*iter)->node = xmlDocGetRootElement((*iter)->doc);
    __xml_iter_skip_dummy(*iter);
    __xml_iter_invalidate_cache(*iter);
    (*iter)->parent = (*iter)->node ? (*iter)->node->parent : NULL;

    return NULL;
}

/* Finish iteration, free allocated resources
 */
void
xml_iter_finish (xml_iter **iter)
{
    if (*iter) {
        if ((*iter)->doc) {
            xmlFree((*iter)->doc);
        }
        __xml_iter_invalidate_cache(*iter);

        g_free(*iter);
        *iter = NULL;
    }
}

/* Check for end-of-document condition
 */
bool
xml_iter_end (xml_iter *iter)
{
    return iter->node == NULL;
}

/* Shift to the next node
 */
void
xml_iter_next (xml_iter *iter)
{
    if (iter->node) {
        iter->node = iter->node->next;
        __xml_iter_skip_dummy(iter);
        __xml_iter_invalidate_cache(iter);
    }
}

/* Enter the current node - iterate its children
 */
void
xml_iter_enter (xml_iter *iter)
{
    if (iter->node) {
        iter->parent = iter->node;
        iter->node = iter->node->children;
        __xml_iter_skip_dummy(iter);
        __xml_iter_invalidate_cache(iter);
    }
}

/* Leave the current node - return to its parent
 */
void
xml_iter_leave (xml_iter *iter)
{
    iter->node = iter->parent;
    if (iter->node) {
        iter->parent = iter->node->parent;
    }
    __xml_iter_invalidate_cache(iter);
}

/* Get name of the current node.
 *
 * The returned string remains valid, until iterator is cleaned up
 * or current node is changed (by set/next/enter/leave operations).
 * You don't need to free this string explicitly
 */
const char*
xml_iter_node_name (xml_iter *iter)
{
    const char *prefix = NULL;

    if (iter->name == NULL && iter->node != NULL) {
        if (iter->node->ns != NULL) {
            prefix = (const char*) iter->node->ns->prefix;
        }

        if (prefix != NULL) {
            iter->name = g_strconcat(prefix, ":", iter->node->name, NULL);
        } else {
            iter->name = g_strdup((const char*) iter->node->name);
        }
    }

    return iter->name;
}

/* Match name of the current node against the pattern
 */
bool
xml_iter_node_name_match (xml_iter *iter, const char *pattern)
{
    return !g_strcmp0(xml_iter_node_name(iter), pattern);
}

/* Get value of the current node as text
 *
 * The returned string remains valid, until iterator is cleaned up
 * or current node is changed (by set/next/enter/leave operations).
 * You don't need to free this string explicitly
 */
const char*
xml_iter_node_value (xml_iter *iter)
{
    if (iter->text == NULL && iter->node != NULL) {
        iter->text = xmlNodeGetContent(iter->node);
        g_strstrip((char*) iter->text);
    }

    return (const char*) iter->text;
}

/* Get value of the current node as unsigned integer
 * Returns error string, NULL if OK
 */
const char*
xml_iter_node_value_uint (xml_iter *iter, SANE_Word *val)
{
    const char *s = xml_iter_node_value(iter);
    char *end;
    unsigned long v;

    g_assert(s != NULL);

    v = strtoul(s, &end, 10);
    if (end == s || *end || v != (unsigned long) (SANE_Word) v) {
        return eloop_eprintf("%s: invalid numerical value",
                xml_iter_node_name(iter));
    }

    *val = (SANE_Word) v;
    return NULL;
}

/* vim:ts=8:sw=4:et
 */
