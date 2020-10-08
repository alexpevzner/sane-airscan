/* AirScan (a.k.a. eSCL) backend for SANE
 *
 * Copyright (C) 2019 and up by Alexander Pevzner (pzz@apevzner.com)
 * See LICENSE for license terms and conditions
 *
 * XML utilities
 */

#include "airscan.h"

#include <fnmatch.h>

#include <libxml/parser.h>
#include <libxml/tree.h>

/******************** XML reader ********************/
/* XML reader
 */
struct xml_rd {
    xmlDoc        *doc;           /* XML document */
    xmlNode       *node;          /* Current node */
    xmlNode       *parent;        /* Parent node */
    const char    *name;          /* Name of current node */
    char          *path;          /* Path to current node, /-separated */
    size_t        *pathlen;       /* Stack of path lengths */
    const xmlChar *text;          /* Textual value of current node */
    unsigned int  depth;          /* Depth of current node, 0 for root */
    const xml_ns  *subst_rules;   /* Substitution rules */
    xml_ns        *subst_cache;   /* In the cache, glob-style patterns are
                                     replaced by exact-matching strings. */
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

    while (node != NULL && node->type != XML_ELEMENT_NODE) {
        node = node->next;
    }

    xml->node = node;
}

/* Invalidate cached value
 */
static void
xml_rd_node_invalidate_value (xml_rd *xml)
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
    xml_rd_node_invalidate_value(xml);

    /* Update node name */
    pathlen = xml->depth ? xml->pathlen[xml->depth - 1] : 0;
    xml->path = str_resize(xml->path, pathlen);

    if (xml->node == NULL) {
        xml->name = NULL;
    } else {
        const char *prefix = NULL;

        if (xml->node->ns != NULL && xml->node->ns->prefix != NULL) {
            prefix = (const char*) xml->node->ns->prefix;
            prefix = xml_rd_ns_subst_lookup(xml, prefix,
                    (const char*) xml->node->ns->href);
        }

        if (prefix != NULL) {
            xml->path = str_append(xml->path, prefix);
            xml->path = str_append_c(xml->path, ':');
        }

        xml->path = str_append(xml->path, (const char*) xml->node->name);

        xml->name = xml->path + pathlen;
    }
}

/* XML parser error callback
 *
 * As XML parser leaves all error information in the xmlParserCtxt
 * structure, this callback does nothing; it's purpose is to
 * silence error message that libxml2 by default writes to
 * the stderr
 */
static void
xml_rd_error_callback (void *userdata, xmlErrorPtr error)
{
    (void) userdata;
    (void) error;
}

/* Parse XML document
 */
static error
xml_rd_parse (xmlDoc **doc, const char *xml_text, size_t xml_len)
{
    xmlParserCtxtPtr ctxt;
    error            err = NULL;

    /* Setup XML parser */
    ctxt = xmlNewParserCtxt();
    if (ctxt == NULL) {
        err = ERROR("not enough memory");
        goto DONE;
    }

    ctxt->sax->serror = xml_rd_error_callback;

    /* Parse the document */
    if (xmlCtxtResetPush(ctxt, xml_text, xml_len, NULL, NULL)) {
        /* It's poorly documented, but xmlCtxtResetPush() fails
         * only due to OOM.
         */
        err = ERROR("not enough memory");
        goto DONE;
    }

    xmlParseDocument(ctxt);

    if (ctxt->wellFormed) {
        *doc = ctxt->myDoc;
    } else {
        if (ctxt->lastError.message != NULL) {
            err = eloop_eprintf("XML: %s", ctxt->lastError.message);
        } else {
            err = ERROR("XML: parse error");
        }

        *doc = NULL;
    }

    /* Cleanup and exit */
DONE:
    if (err != NULL && ctxt != NULL && ctxt->myDoc != NULL) {
        xmlFreeDoc(ctxt->myDoc);
    }

    if (ctxt != NULL) {
        xmlFreeParserCtxt(ctxt);
    }

    return err;
}

/* Parse XML text and initialize reader to iterate
 * starting from the root node
 *
 * The 'ns' argument, if not NULL, points to array of substitution
 * rules. Last element must have NULL prefix and url
 *
 * Array of rules considered to be statically allocated
 * (at least, it can remain valid during reader life time)
 *
 * On success, saves newly constructed reader into
 * the xml parameter.
 */
error
xml_rd_begin (xml_rd **xml, const char *xml_text, size_t xml_len,
        const xml_ns *ns)
{
    xmlDoc *doc;
    error  err = xml_rd_parse(&doc, xml_text, xml_len);

    *xml = NULL;
    if (err != NULL) {
        return err;
    }

    *xml = mem_new(xml_rd, 1);
    (*xml)->doc = doc;
    (*xml)->node = xmlDocGetRootElement((*xml)->doc);
    (*xml)->path = str_new();
    (*xml)->pathlen = mem_new(size_t, 0);
    (*xml)->subst_rules = ns;

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
        xml_rd_node_invalidate_value(*xml);

        if ((*xml)->subst_cache != NULL) {
            size_t i, len = mem_len((*xml)->subst_cache);
            for (i = 0; i < len; i ++) {
                mem_free((char*) (*xml)->subst_cache[i].uri);
            }
            mem_free((*xml)->subst_cache);
        }

        mem_free((*xml)->pathlen);
        mem_free((*xml)->path);
        mem_free(*xml);
        *xml = NULL;
    }
}

/* Perform namespace prefix substitution. Is substitution
 * is not setup or no match was found, the original prefix
 * will be returned
 */
static const char*
xml_rd_ns_subst_lookup(xml_rd *xml, const char *prefix, const char *href)
{
    size_t i, len = mem_len(xml->subst_cache);

    /* Substitution enabled? */
    if (xml->subst_rules == NULL) {
        return prefix;
    }

    /* Lookup cache first */
    for (i = 0; i < len; i ++) {
        if (!strcmp(href, xml->subst_cache[i].uri)) {
            return xml->subst_cache[i].prefix;
        }
    }

    /* Now try glob-style rules */
    for (i = 0; xml->subst_rules[i].prefix != NULL; i ++) {
        if (!fnmatch(xml->subst_rules[i].uri, href, 0)) {
            prefix = xml->subst_rules[i].prefix;

            /* Update cache. Grow it if required */
            xml->subst_cache = mem_resize(xml->subst_cache, len + 1, 0);
            xml->subst_cache[len].prefix = prefix;
            xml->subst_cache[len].uri = str_dup(href);

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

/* Shift to the next node, visiting the nested nodes on the way
 *
 * If depth > 0, it will not return from nested nodes
 * upper the specified depth
 */
void
xml_rd_deep_next (xml_rd *xml, unsigned int depth)
{
    xml_rd_enter(xml);

    while (xml_rd_end(xml) && xml_rd_depth(xml) > depth + 1) {
        xml_rd_leave(xml);
        xml_rd_next(xml);
    }
}

/* Enter the current node - iterate its children
 */
void
xml_rd_enter (xml_rd *xml)
{
    if (xml->node) {
        /* Save current path length into pathlen stack */
        xml->path = str_append_c(xml->path, '/');

        xml->pathlen = mem_resize(xml->pathlen, xml->depth + 1, 0);
        xml->pathlen[xml->depth] = mem_len(xml->path);

        /* Enter the node */
        xml->parent = xml->node;
        xml->node = xml->node->children;
        xml_rd_skip_dummy(xml);

        /* Increment depth and recompute node name */
        xml->depth ++;
        xml_rd_skip_dummy(xml);
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

        xml_rd_node_switched(xml);
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
    return xml->node ? xml->path : NULL;
}

/* Match name of the current node against the pattern
 */
bool
xml_rd_node_name_match (xml_rd *xml, const char *pattern)
{
    return xml->name != NULL && !strcmp(xml->name, pattern);
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
        str_trim((char*) xml->text);
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
    const char     *name;     /* Node name */
    const char     *value;    /* Node value, if any */
    const xml_attr *attrs;    /* Attributes, if any */
    xml_wr_node    *children; /* Node children, if any */
    xml_wr_node    *next;     /* Next sibling node, if any */
    xml_wr_node    *parent;   /* Parent node, if any */
};

/* XML writer
 */
struct xml_wr {
    xml_wr_node  *root;    /* Root node */
    xml_wr_node  *current; /* Current node */
    const xml_ns *ns;     /* Namespace */
};

/* Create XML writer node
 */
static xml_wr_node*
xml_wr_node_new (const char *name, const char *value, const xml_attr *attrs)
{
    xml_wr_node *node = mem_new(xml_wr_node, 1);
    node->name = str_dup(name);
    node->attrs = attrs;
    if (value != NULL) {
        node->value = str_dup(value);
    }
    return node;
}

/* Free XML writer node
 */
static void
xml_wr_node_free (xml_wr_node *node)
{
    mem_free((char*) node->name);
    mem_free((char*) node->value);
    mem_free(node);
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
xml_wr_begin (const char *root, const xml_ns *ns)
{
    xml_wr *xml = mem_new(xml_wr, 1);
    xml->root = xml_wr_node_new(root, NULL, NULL);
    xml->current = xml->root;
    xml->ns = ns;
    return xml;
}

/* Format indentation space
 */
static char*
xml_wr_format_indent (char *buf, unsigned int level)
{
        unsigned int i;

        for (i = 0; i < level; i ++) {
            buf = str_append_c(buf, ' ');
            buf = str_append_c(buf, ' ');
        }

        return buf;
}

/* Format node's value
 */
static char*
xml_wr_format_value (char *buf, const char *value)
{
    for (;;) {
        char c = *value ++;
        switch (c) {
        case '&':  buf = str_append(buf, "&amp;"); break;
        case '<':  buf = str_append(buf, "&lt;"); break;
        case '>':  buf = str_append(buf, "&gt;"); break;
        case '"':  buf = str_append(buf, "&quot;"); break;
        case '\'': buf = str_append(buf, "&apos;"); break;
        case '\0': return buf;
        default:   buf = str_append_c(buf, c);
        }
    }

    return buf;
}

/* Format node with its children, recursively
 */
static char*
xml_wr_format_node (xml_wr *xml, char *buf,
        xml_wr_node *node, unsigned int level, bool compact)
{
    if (!compact) {
        buf = xml_wr_format_indent(buf, level);
    }

    buf = str_append_printf(buf, "<%s", node->name);
    if (level == 0) {
        /* Root node defines namespaces */
        int i;
        for (i = 0; xml->ns[i].uri != NULL; i ++) {
            buf = str_append_printf(buf, " xmlns:%s=\"%s\"",
                xml->ns[i].prefix, xml->ns[i].uri);
        }
    }
    if (node->attrs != NULL) {
        int i;
        for (i = 0; node->attrs[i].name != NULL; i ++) {
            buf = str_append_printf(buf, " %s=\"%s\"",
                node->attrs[i].name, node->attrs[i].value);
        }
    }
    buf = str_append_c(buf, '>');

    if (node->children) {
        xml_wr_node *node2;

        if (!compact) {
            buf = str_append_c(buf, '\n');
        }

        for (node2 = node->children; node2 != NULL; node2 = node2->next) {
            buf = xml_wr_format_node(xml, buf, node2, level + 1, compact);
        }

        if (!compact) {
            buf = xml_wr_format_indent(buf, level);
        }

        buf = str_append_printf(buf, "</%s>", node->name);
        if (!compact && level != 0) {
            buf = str_append_c(buf, '\n');
        }
    } else {
        if (node->value != NULL) {
            buf = xml_wr_format_value(buf, node->value);
        }
        buf = str_append_printf(buf,"</%s>", node->name);
        if (!compact) {
            buf = str_append_c(buf, '\n');
        }
    }

    return buf;
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

/* xml_wr_finish(), internal version
 */
static char*
xml_wr_finish_internal (xml_wr *xml, bool compact)
{
    char *buf;

    buf = str_dup("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
    if (!compact) {
        buf = str_append_c(buf, '\n');
    }

    xml_wr_revert_children(xml->root);
    buf = xml_wr_format_node(xml, buf, xml->root, 0, compact);

    xml_wr_node_free_recursive(xml->root);
    mem_free(xml);

    return buf;
}

/* Finish writing, generate document string.
 * Caller must mem_free() this string after use
 */
char*
xml_wr_finish (xml_wr *xml)
{
    return xml_wr_finish_internal(xml, false);
}

/* Like xml_wr_finish, but returns compact representation
 * of XML (without indentation and new lines)
 */
char*
xml_wr_finish_compact (xml_wr *xml)
{
    return xml_wr_finish_internal(xml, true);
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
    xml_wr_add_text_attr(xml, name, value, NULL);
}

/* Add text node with attributes
 */
void
xml_wr_add_text_attr (xml_wr *xml, const char *name, const char *value,
        const xml_attr *attrs)
{
    xml_wr_add_node(xml, xml_wr_node_new(name, value, attrs));
}

/* Add node with unsigned integer value
 */
void
xml_wr_add_uint (xml_wr *xml, const char *name, unsigned int value)
{
    xml_wr_add_uint_attr(xml, name, value, NULL);
}

/* Add node with unsigned integer value and attributes
 */
void
xml_wr_add_uint_attr (xml_wr *xml, const char *name, unsigned int value,
        const xml_attr *attrs)
{
    char buf[64];
    sprintf(buf, "%u", value);
    xml_wr_add_text_attr(xml, name, buf, attrs);
}

/* Add node with boolean value
 */
void
xml_wr_add_bool (xml_wr *xml, const char *name, bool value)
{
    xml_wr_add_bool_attr(xml, name, value, NULL);
}

/* Add node with boolean value and attributes
 */
void
xml_wr_add_bool_attr (xml_wr *xml, const char *name, bool value,
        const xml_attr *attrs)
{
    xml_wr_add_text_attr(xml, name, value ? "true" : "false", attrs);
}

/* Create node with children and enter newly added node
 */
void
xml_wr_enter (xml_wr *xml, const char *name)
{
    xml_wr_enter_attr(xml, name, NULL);
}

/* xml_wr_enter with attributes
 */
void
xml_wr_enter_attr (xml_wr *xml, const char *name, const xml_attr *attrs)
{
    xml_wr_node *node = xml_wr_node_new(name, NULL, attrs);
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

/******************** XML formatter ********************/
/* Format node name with namespace prefix
 */
static void
xml_format_node_name (FILE *fp, xmlNode *node)
{
    if (node->ns != NULL && node->ns->prefix != NULL) {
        fputs((char*) node->ns->prefix, fp);
        putc(':', fp);
    }
    fputs((char*) node->name, fp);
}

/* Format node attributes
 */
static void
xml_format_node_attrs (FILE *fp, xmlNode *node)
{
    xmlNs   *ns;
    xmlAttr *attr;

    /* Format namespace attributes */
    for (ns = node->nsDef; ns != NULL; ns = ns->next) {
        if (ns->prefix == NULL) {
            continue;
        }

        /* Write namespace name */
        putc(' ', fp);
        fputs("xmlns:", fp);
        fputs((char*) ns->prefix, fp);

        /* Write namespace value */
        putc('=', fp);
        putc('"', fp);
        fputs((char*) ns->href, fp);
        putc('"', fp);
    }

    /* Format properties */
    for (attr = node->properties; attr != NULL; attr = attr->next) {
        xmlChar *val = xmlNodeListGetString(node->doc, attr->children, 1);

        /* Write attribute name with namespace prefix */
        putc(' ', fp);
        if (attr->ns != NULL && attr->ns->prefix != NULL) {
            fputs((char*) attr->ns->prefix, fp);
            putc(':', fp);
        }
        fputs((char*) attr->name, fp);

        /* Write attribute value */
        putc('=', fp);
        putc('"', fp);
        fputs((char*) val, fp);
        putc('"', fp);

        xmlFree(val);
    }
}

/* Format indent
 */
static void
xml_format_indent (FILE *fp, int indent)
{
    int     i;

    for (i = 0; i < indent; i ++) {
        putc(' ', fp);
        putc(' ', fp);
    }
}

/* Format entire node
 */
static void
xml_format_node (FILE *fp, xmlNode *node, int indent)
{
    xmlNode *child;
    bool    with_children = false;
    bool    with_value = false;

    /* Format opening tag */
    xml_format_indent(fp, indent);

    putc('<', fp);
    xml_format_node_name(fp, node);
    xml_format_node_attrs(fp, node);

    for (child = node->children; child != NULL; child = child->next) {
        if (child->type == XML_ELEMENT_NODE) {
            if (!with_children) {
                putc('>', fp);
                putc('\n', fp);
                with_children = true;
            }
            xml_format_node(fp, child, indent + 1);
        }
    }

    if (!with_children) {
        xmlChar *val = xmlNodeGetContent(node);
        str_trim((char*) val);

        if (*val != '\0') {
            putc('>', fp);
            fputs((char*) val, fp);
            with_value = true;
        }

        xmlFree(val);
    }

    if (with_children) {
        xml_format_indent(fp, indent);
    }

    /* Format closing tag */
    if (with_children || with_value) {
        putc('<', fp);
        putc('/', fp);
        xml_format_node_name(fp, node);
        putc('>', fp);
    } else {
        putc('/', fp);
        putc('>', fp);
    }

    putc('\n', fp);
}

/* Format XML to file. It either succeeds, writes a formatted XML
 * and returns true, or fails, writes nothing to file and returns false
 */
bool
xml_format (FILE *fp, const char *xml_text, size_t xml_len)
{
    xmlDoc  *doc;
    error   err = xml_rd_parse(&doc, xml_text, xml_len);
    xmlNode *node;

    if (err != NULL) {
        return err;
    }

    for (node = doc->children; node != NULL; node = node->next) {
        xml_format_node(fp, node, 0);
    }

    xmlFreeDoc(doc);

    return true;
}

/* vim:ts=8:sw=4:et
 */
