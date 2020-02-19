/* AirScan (a.k.a. eSCL) backend for SANE
 *
 * Copyright (C) 2019 and up by Alexander Pevzner (pzz@apevzner.com)
 * See LICENSE for license terms and conditions
 *
 * XML utilities
 */

#include "airscan.h"

#include <fnmatch.h>
#include <libxml/tree.h>

/******************** XML reader ********************/
/* XML reader
 */
struct xml_rd {
    xmlDoc             *doc;           /* XML document */
    xmlNode            *node;          /* Current node */
    xmlNode            *parent;        /* Parent node */
    const char         *name;          /* Name of current node */
    GString            *path;          /* Path to current node, /-separated */
    size_t             *pathlen;       /* Stack of path lengths */
    size_t             pathlen_cap;    /* pathlen capacity */
    const xmlChar      *text;          /* Textual value of current node */
    unsigned int       depth;          /* Depth of current node, 0 for root */
    const xml_ns_subst *subst_rules;   /* Substitution rules */
    xml_ns_subst       *subst_cache;   /* In the cache, glob-style patterns are
                                          replaced by exact-matching strings */
    size_t             subst_cache_len;/* Count of subst_cache elements */
    size_t             subst_cache_cap;/* subst_cache capacity */
};

/* Forward declarations */
static const char*
xml_rd_ns_subst_lookup(xml_rd *xml, const char *prefix, const char *href);

/* Skip dummy nodes. This is internal function, don't call directly
 */
static void
xml_rd_skip_dummy (xml_rd *xml)
{
    xmlNode *node = xml->node;

    while (node  != NULL &&
           (node->type == XML_COMMENT_NODE || xmlIsBlankNode (node))) {
        node = node->next;
    }

    xml->node = node;
}

/* Invalidate cached value
 */
static void
xml_rx_node_invalidate_value (xml_rd *xml)
{
    xmlFree((xmlChar*) xml->text);
    xml->text = NULL;
}

/* xml_rd_node_switched called when current node is switched.
 * It invalidates cached value and updates node name
 */
static void
xml_rd_node_switched (xml_rd *xml)
{
    size_t     pathlen;

    /* Invalidate cached value */
    xml_rx_node_invalidate_value(xml);

    /* Update node name */
    pathlen = xml->depth ? xml->pathlen[xml->depth - 1] : 0;
    g_string_truncate(xml->path, pathlen);

    if (xml->node == NULL) {
        xml->name = NULL;
    } else {
        const char *prefix = NULL;

        if (xml->node->ns != NULL) {
            prefix = (const char*) xml->node->ns->prefix;
            prefix = xml_rd_ns_subst_lookup(xml, prefix,
                    (const char*) xml->node->ns->href);
        }

        if (prefix != NULL) {
            g_string_append(xml->path, prefix);
            g_string_append_c(xml->path, ':');
        }

        g_string_append(xml->path, (const char*) xml->node->name);

        xml->name = xml->path->str + pathlen;
    }
}

/* Parse XML text and initialize reader to iterate
 * starting from the root node
 *
 * On success, saves newly constructed reader into
 * the xml parameter.
 */
error
xml_rd_begin (xml_rd **xml, const char *xml_text, size_t xml_len)
{
    xmlDoc *doc = xmlParseMemory(xml_text, xml_len);

    if (doc == NULL) {
        return ERROR("Failed to parse XML");
    }

    *xml = g_new0(xml_rd, 1);
    (*xml)->doc = doc;
    (*xml)->node = xmlDocGetRootElement((*xml)->doc);
    (*xml)->path = g_string_new(NULL);
    (*xml)->pathlen_cap = 8;
    (*xml)->pathlen = g_malloc(sizeof(*(*xml)->pathlen) * (*xml)->pathlen_cap);

    xml_rd_skip_dummy(*xml);
    xml_rd_node_switched(*xml);

    return NULL;
}

/* Finish reading, free allocated resources
 */
void
xml_rd_finish (xml_rd **xml)
{
    if (*xml) {
        if ((*xml)->doc) {
            xmlFreeDoc((*xml)->doc);
        }
        xml_rd_node_switched(*xml);

        if ((*xml)->subst_cache != NULL) {
            size_t i;
            for (i = 0; i < (*xml)->subst_cache_len; i ++) {
                g_free((char*) (*xml)->subst_cache[i].pattern);
            }
            g_free((*xml)->subst_cache);
        }

        g_free((*xml)->pathlen);
        g_string_free((*xml)->path, TRUE);
        g_free(*xml);
        *xml = NULL;
    }
}

/* Setup namespace substitution
 */
void
xml_rd_ns_subst (xml_rd *xml, const xml_ns_subst *subst)
{
    xml->subst_rules = subst;
}

/* Perform namespace prefix substitution. Is substitution
 * is not setup or no match was found, the original prefix
 * will be returned
 */
static const char*
xml_rd_ns_subst_lookup(xml_rd *xml, const char *prefix, const char *href)
{
    size_t i;

    /* Substitution enabled? */
    if (xml->subst_rules == NULL) {
        return prefix;
    }

    /* Lookup cache first */
    for (i = 0; i < xml->subst_cache_len; i ++) {
        if (!strcmp(href, xml->subst_cache[i].pattern)) {
            return xml->subst_cache[i].prefix;
        }
    }

    /* Now try glob-style rules */
    for (i = 0; xml->subst_rules[i].prefix != NULL; i ++) {
        if (!fnmatch(xml->subst_rules[i].pattern, href, 0)) {
            prefix = xml->subst_rules[i].prefix;

            /* Update cache. Grow it if required */
            if (xml->subst_cache_len == xml->subst_cache_cap) {
                if (xml->subst_cache_cap == 0) {
                    xml->subst_cache_cap = 4; /* Initial size */
                } else {
                    xml->subst_cache_cap *= 2;
                }
            }

            xml->subst_cache = g_realloc(xml->subst_cache,
                sizeof(*xml->subst_cache) * xml->subst_cache_cap);

            xml->subst_cache[xml->subst_cache_len].prefix = prefix;
            xml->subst_cache[xml->subst_cache_len].pattern = g_strdup(href);
            xml->subst_cache_len ++;

            /* Break out of loop */
            break;
        }
    }

    return prefix;
}

/* Get current node depth in the tree. Root depth is 0
 */
unsigned int
xml_rd_depth (xml_rd *xml)
{
    return xml->depth;
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
        xml_rd_skip_dummy(xml);
        xml_rd_node_switched(xml);
    }
}

/* Enter the current node - iterate its children
 */
void
xml_rd_enter (xml_rd *xml)
{
    if (xml->node) {
        /* Save current path length into pathlen stack */
        if (xml->depth == xml->pathlen_cap) {
            xml->pathlen_cap *= 2;
            xml->pathlen = g_realloc(xml->pathlen,
                sizeof(*xml->pathlen) * xml->pathlen_cap);
        }

        g_string_append_c(xml->path, '/');

        xml->pathlen[xml->depth] = xml->path->len;

        /* Enter the node */
        xml->parent = xml->node;
        xml->node = xml->node->children;
        xml_rd_skip_dummy(xml);

        /* Increment depth and recompute node name */
        xml->depth ++;
        xml_rd_node_switched(xml);
    }
}

/* Leave the current node - return to its parent
 */
void
xml_rd_leave (xml_rd *xml)
{
    if (xml->depth > 0) {
        xml->depth --;
        xml->node = xml->parent;
        if (xml->node) {
            xml->parent = xml->node->parent;
        }

        g_string_truncate(xml->path, xml->pathlen[xml->depth] - 1);
        xml_rx_node_invalidate_value(xml);
    }
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
    return xml->name;
}

/* Get full path to the current node, '/'-separated
 */
const char*
xml_rd_node_path (xml_rd *xml)
{
    return xml->node ? xml->path->str : NULL;
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
 */
error
xml_rd_node_value_uint (xml_rd *xml, SANE_Word *val)
{
    const char *s = xml_rd_node_value(xml);
    char *end;
    unsigned long v;

    log_assert(NULL, s != NULL);

    v = strtoul(s, &end, 10);
    if (end == s || *end || v != (unsigned long) (SANE_Word) v) {
        return eloop_eprintf("%s: invalid numerical value",
                xml_rd_node_name(xml));
    }

    *val = (SANE_Word) v;
    return NULL;
}

/******************** XML writer ********************/
/* XML writer node
 */
typedef struct xml_wr_node xml_wr_node;
struct xml_wr_node {
    const char *name;      /* Node name */
    const char *value;     /* Node value, if any */
    xml_wr_node *children; /* Node children, if any */
    xml_wr_node *next;     /* Next sibling node, if any */
    xml_wr_node *parent;   /* Parent node, if any */

};

/* XML writer
 */
struct xml_wr {
    xml_wr_node *root;    /* Root node */
    xml_wr_node *current; /* Current node */
};

/* Create XML writer node
 */
static xml_wr_node*
xml_wr_node_new (const char *name, const char *value)
{
    xml_wr_node *node = g_new0(xml_wr_node, 1);
    node->name = g_strdup(name);
    if (value != NULL) {
        node->value = g_strdup(value);
    }
    return node;
}

/* Free XML writer node
 */
static void
xml_wr_node_free (xml_wr_node *node)
{
    g_free((char*) node->name);
    g_free((char*) node->value);
    g_free(node);
}

/* Free XML writer node with its children
 */
static void
xml_wr_node_free_recursive (xml_wr_node *node)
{
    xml_wr_node *node2, *next;
    for (node2 = node->children; node2 != NULL; node2 = next) {
        next = node2->next;
        xml_wr_node_free_recursive(node2);
    }
    xml_wr_node_free(node);
}

/* Begin writing XML document. Root node will be created automatically
 */
xml_wr*
xml_wr_begin (const char *root)
{
    xml_wr *xml = g_new0(xml_wr, 1);
    xml->root = xml_wr_node_new(root, NULL);
    xml->current = xml->root;
    return xml;
}

/* Format indentation space
 */
static void
xml_wr_format_indent(GString *buf, unsigned int indent)
{
        unsigned int i;

        for (i = 0; i < indent; i ++) {
            g_string_append_c(buf, ' ');
            g_string_append_c(buf, ' ');
        }
}

/* Format node with its children, recursively
 */
static void
xml_wr_format_node (GString *buf, xml_wr_node *node, unsigned int indent)
{
        xml_wr_format_indent(buf, indent);

        g_string_append_printf(buf, "<%s", node->name);
        if (indent == 0) {
            /* Root node defines namespaces */
            g_string_append_c(buf, ' ');
            g_string_append(buf, "xmlns:pwg=\"http://www.pwg.org/schemas/2010/12/sm\" ");
            g_string_append(buf, "xmlns:scan=\"http://schemas.hp.com/imaging/escl/2011/05/03\"");
        }
        g_string_append_c(buf, '>');

        if (node->children) {
            xml_wr_node *node2;

            g_string_append_c(buf, '\n');
            for (node2 = node->children; node2 != NULL; node2 = node2->next) {
                xml_wr_format_node(buf, node2, indent + 1);
            }

            xml_wr_format_indent(buf, indent);
            g_string_append_printf(buf, "</%s>", node->name);
            if (indent != 0) {
                g_string_append_c(buf, '\n');
            }
        } else {
            g_string_append_printf(buf, "%s</%s>\n", node->value, node->name);
        }
}

/* Revert list of node's children, recursively
 */
static void
xml_wr_revert_children (xml_wr_node *node)
{
    xml_wr_node *next, *prev = NULL, *node2;

    for (node2 = node->children; node2 != NULL; node2 = next) {
        xml_wr_revert_children (node2);
        next = node2->next;
        node2->next = prev;
        prev = node2;
    }

    node->children = prev;
}

/* Finish writing, generate document string.
 * Caller must g_free() this string after use
 */
char*
xml_wr_finish (xml_wr *xml)
{
    GString    *buf;

    buf = g_string_new("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");

    xml_wr_revert_children(xml->root);
    xml_wr_format_node(buf, xml->root, 0);

    xml_wr_node_free_recursive(xml->root);
    g_free(xml);

    return g_string_free(buf, false);
}

/* Add XML writer node to the current node's children
 */
static void
xml_wr_add_node (xml_wr *xml, xml_wr_node *node)
{
    node->parent = xml->current;
    node->next = xml->current->children;
    xml->current->children = node;
}

/* Add node with textual value
 */
void
xml_wr_add_text (xml_wr *xml, const char *name, const char *value)
{
    xml_wr_add_node(xml, xml_wr_node_new(name, value));
}

/* Add node with unsigned integer value
 */
void
xml_wr_add_uint (xml_wr *xml, const char *name, unsigned int value)
{
    char buf[64];
    sprintf(buf, "%u", value);
    xml_wr_add_text(xml, name, buf);
}

/* Add node with boolean value
 */
void
xml_wr_add_bool (xml_wr *xml, const char *name, bool value)
{
    xml_wr_add_text(xml, name, value ? "true" : "false");
}

/* Create node with children and enter newly added node
 */
void
xml_wr_enter (xml_wr *xml, const char *name)
{
    xml_wr_node *node = xml_wr_node_new(name, NULL);
    xml_wr_add_node(xml, node);
    xml->current = node;
}

/* Leave the current node
 */
void
xml_wr_leave (xml_wr *xml)
{
    log_assert(NULL, xml->current->parent != NULL);
    xml->current = xml->current->parent;
}

/* vim:ts=8:sw=4:et
 */
