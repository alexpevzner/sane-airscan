/* AirScan (a.k.a. eSCL) backend for SANE
 *
 * Copyright (C) 2019 and up by Alexander Pevzner (pzz@apevzner.com)
 * See LICENSE for license terms and conditions
 *
 * HTTP Client
 */
#define _GNU_SOURCE
#include <string.h>

#define NO_HTTP_STATUS

#include "airscan.h"
#include "http_parser.h"

#include <alloca.h>
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <gnutls/gnutls.h>

/******************** Constants ********************/
/* I/O buffer size
 */
#define HTTP_IOBUF_SIZE         65536

/* Limit of chained HTTP redirects
 */
#define HTTP_REDIRECT_LIMIT     8

/* Default query timeout, milliseconds
 * Disabled, if negative
 */
#define HTTP_QUERY_TIMEOUT      -1

/******************** Static variables ********************/
static gnutls_certificate_credentials_t gnutls_cred;

/******************** Forward declarations ********************/
typedef struct http_multipart http_multipart;

static http_data*
http_data_new(http_data *parent, const char *bytes, size_t size);

static void
http_data_set_content_type (http_data *data, const char *content_type);

static void
http_query_timeout_cancel (http_query *q);

static http_query*
http_query_by_ll_node (ll_node *node);

static void
http_query_complete (http_query *q, error err);

static void
http_query_connect (http_query *q, error err);

static void
http_query_disconnect (http_query *q);

static ssize_t
http_query_sock_send (http_query *q, const void *data, size_t size);

static ssize_t
http_query_sock_recv (http_query *q, void *data, size_t size);

static error
http_query_sock_err (http_query *q, int rc);

static void
http_query_cancel (http_query *q);

/******************** HTTP URI ********************/
/* Type http_uri represents HTTP URI
 */
struct http_uri {
    struct http_parser_url parsed; /* Parsed URI */
    const char             *str;   /* URI string */
    const char             *path;  /* URI path */
    HTTP_SCHEME            scheme; /* URI scheme */
    union {                 /* Host address*/
        struct sockaddr     sockaddr;
        struct sockaddr_in  in;
        struct sockaddr_in6 in6;
    } addr;
};

typedef struct {
    const char *str;
    size_t     len;
} http_uri_field;

/* Make http_uri_field
 */
static http_uri_field
http_uri_field_make (const char *str)
{
    http_uri_field field = {str, strlen(str)};
    return field;
}

/* Check if URI has a particular field
 */
static inline bool
http_uri_field_present (const http_uri *uri, int num)
{
    return (uri->parsed.field_set & (1 << num)) != 0;
}

/* Check if URI field is present and non-empty
 */
static inline bool
http_uri_field_nonempty (const http_uri *uri, int num)
{
    return uri->parsed.field_data[num].len != 0;
}

/* Get first character of the field. Returns -1, if
 * field is empty, or non-negative character code otherwise
 */
static inline int
http_uri_field_begin (const http_uri *uri, int num)
{
    if (http_uri_field_nonempty(uri, num)) {
        return (unsigned char) uri->str[uri->parsed.field_data[num].off];
    } else {
        return -1;
    }
}

/* Get field from URI
 */
static http_uri_field
http_uri_field_get (const http_uri *uri, int num)
{
    http_uri_field field = {
        uri->str + uri->parsed.field_data[num].off,
        uri->parsed.field_data[num].len
    };

    return field;
}

/* Append field to buffer, and return pointer to
 * updated buffer tail
 */
static inline char *
http_uri_field_append (http_uri_field field, char *buf)
{
    memcpy(buf, field.str, field.len);
    return buf + field.len;
}

/* Get field from URI and append to buffer
 */
static inline char*
http_uri_field_copy (const http_uri *uri, int num, char *buf)
{
    return http_uri_field_append(http_uri_field_get(uri, num), buf);
}

/* Get and strdup the field
 */
static char*
http_uri_field_strdup (const http_uri *uri, int num)
{
    http_uri_field field = http_uri_field_get(uri, num);
    char           *s = mem_new(char, field.len + 1);

    memcpy(s, field.str, field.len);
    s[field.len] = '\0';

    return s;
}

/* Check are fields of two URIs are equal
 */
static bool
http_uri_field_equal (const http_uri *uri1, const http_uri *uri2,
        int num, bool nocase)
{
    http_uri_field f1 = http_uri_field_get(uri1, num);
    http_uri_field f2 = http_uri_field_get(uri2, num);

    if (f1.len != f2.len) {
        return false;
    }

    if (nocase) {
        return !strncasecmp(f1.str, f2.str, f1.len);
    } else {
        return !memcmp(f1.str, f2.str, f1.len);
    }
}



/* Replace particular URI field with val[len] string
 */
static void
http_uri_field_replace_len (http_uri *uri, int num, const char *val, size_t len)
{
    static const struct { char *pfx; int num; char *sfx; } fields[] = {
        {"",  UF_SCHEMA, "://"},
        {"",  UF_USERINFO, "@"},
        {"",  UF_HOST, ""},
        {":", UF_PORT, ""},
        {"",  UF_PATH, ""},
        {"?", UF_QUERY, ""},
        {"#", UF_FRAGMENT, ""},
        {NULL, -1, NULL}
    };

    int      i;
    char     *buf = alloca(strlen(uri->str) + len + 4);
    char     *end = buf;
    http_uri *uri2;

    /* Rebuild URI string */
    for (i = 0; fields[i].num != -1; i ++) {
        http_uri_field field;

        if (num == fields[i].num) {
            field.str = val;
            field.len = len;
        } else {
            field = http_uri_field_get(uri, fields[i].num);
        }

        if (field.len != 0) {
            bool ip6_host = false;

            if (fields[i].num == UF_HOST) {
                ip6_host = memchr(field.str, ':', field.len) != NULL;
            }

            if (fields[i].pfx != NULL) {
                http_uri_field pfx = http_uri_field_make(fields[i].pfx);
                end = http_uri_field_append(pfx, end);
            }

            if (ip6_host) {
                *end ++ = '[';
            }

            end = http_uri_field_append(field, end);

            if (ip6_host) {
                *end ++ = ']';
            }

            if (fields[i].sfx != NULL) {
                http_uri_field sfx = http_uri_field_make(fields[i].sfx);
                end = http_uri_field_append(sfx, end);
            }
        }
    }

    *end = '\0';

    /* Reconstruct the URI */
    uri2 = http_uri_new(buf, false);
    log_assert(NULL, uri2 != NULL);

    mem_free((char*) uri->str);
    mem_free((char*) uri->path);
    *uri = *uri2;
    mem_free(uri2);
}

/* Replace particular URI field
 */
static void
http_uri_field_replace (http_uri *uri, int num, const char *val)
{
    http_uri_field_replace_len (uri, num, val, strlen(val));
}

/* Append UF_PATH part of URI to buffer up to the final '/'
 * character
 */
static char*
http_uri_field_copy_basepath (const http_uri *uri, char *buf)
{
    http_uri_field path = http_uri_field_get(uri, UF_PATH);
    const char     *end = memrchr(path.str, '/', path.len);

    path.len = end ? (size_t)(end - path.str) : 0;

    buf = http_uri_field_append(path, buf);
    *(buf ++) = '/';

    return buf;
}

/* Check if sting has an scheme prefix, where scheme
 * must be [a-zA-Z][a-zA-Z0-9+-.]*):
 *
 * If scheme is found, returns its length. 0 is returned otherwise
 */
static size_t
http_uri_parse_scheme (const char *str)
{
    char   c = *str;
    size_t i;

    if (!(('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z'))) {
        return 0;
    }

    i = 1;
    for (;;) {
        c = str[i ++];

        if (('a' <= c && c <= 'z') ||
            ('A' <= c && c <= 'Z') ||
            ('0' <= c && c <= '9') ||
            c == '+' ||
            c == '-' ||
            c == '.') {
            continue;
        }

        break;
    }

    return c == ':' ? i : 0;
}

/* Parse URI in place. The parsed URI doesn't create
 * a copy of URI string, and uses supplied string directly
 */
static error
http_uri_parse (http_uri *uri, const char *str)
{
    size_t     scheme_len = http_uri_parse_scheme(str);
    const char *normalized = str;
    const char *prefix = NULL;
    size_t     prefix_len = 0;
    size_t     path_skip = 0;

    /* Note, github.com/nodejs/http-parser fails to properly
     * parse relative URLs (URLs without scheme), so prepend
     * fake scheme, then remove it
     */
    if (scheme_len == 0) {
        char *s;

        if (str[0] == '/' && str[1] == '/') {
            prefix = "s:";
        } else if (str[0] == '/') {
            prefix = "s://h";
        } else {
            prefix = "s://h/";
            path_skip = 1;
        }

        prefix_len = strlen(prefix);
        s = alloca(prefix_len + strlen(str) + 1);
        memcpy(s, prefix, prefix_len);
        strcpy(s + prefix_len, str);

        normalized = s;
    }

    /* Parse URI */
    memset(uri, 0, sizeof(*uri));
    if (http_parser_parse_url(normalized, strlen(normalized),
            0, &uri->parsed) != 0) {
        return ERROR("Invalid URI");
    }

    uri->str = str;

    /* Adjust offsets */
    if (path_skip != 0) {
        uri->parsed.field_data[UF_PATH].off ++;
        uri->parsed.field_data[UF_PATH].len --;
    }

    if (prefix_len != 0) {
        unsigned int i;

        for (i = 0; i < UF_MAX; i ++) {
            if ((uri->parsed.field_set & (1 << i)) != 0) {
                if (uri->parsed.field_data[i].off >= (uint16_t) prefix_len) {
                    uri->parsed.field_data[i].off -= (uint16_t) prefix_len;
                } else {
                    uri->parsed.field_data[i].off = 0;
                    uri->parsed.field_data[i].len = 0;
                    uri->parsed.field_set &= ~ (1 << i);
                }
            }
        }
    }

    /* Decode scheme */
    if (!strncasecmp(str, "http://", 7)) {
        uri->scheme = HTTP_SCHEME_HTTP;
    } else if (!strncasecmp(str, "https://", 8)) {
        uri->scheme = HTTP_SCHEME_HTTPS;
    } else {
        uri->scheme = HTTP_SCHEME_UNSET;
    }

    return NULL;
}

/* Un-escape host name in place
 */
static void
http_uri_unescape_host (char *host)
{
    char *zone = strstr(host, "%25");
    if (zone != NULL) {
        memmove(zone + 1, zone + 3, strlen(zone + 3) + 1);
    }
}

/* Parse URI address
 */
static void
http_uri_parse_addr (http_uri *uri)
{
    http_uri_field field;
    char           *host = NULL, *port = NULL;
    uint16_t       portnum;
    int            rc;

    /* Reset address */
    memset(&uri->addr, 0, sizeof(uri->addr));

    /* Get host and port */
    field = http_uri_field_get(uri, UF_HOST);
    if (field.len != 0) {
        host = alloca(field.len + 1);
        memcpy(host, field.str, field.len);
        host[field.len] = '\0';
        http_uri_unescape_host(host);
    }

    field = http_uri_field_get(uri, UF_PORT);
    if (field.len != 0) {
        port = alloca(field.len + 1);
        memcpy(port, field.str, field.len);
        port[field.len] = '\0';
    }

    if (host == NULL) {
        return;
    }

    /* Parse port number */
    if (port != NULL) {
        char          *end;
        unsigned long val = strtoul(port, &end, 10);

        if (end == port || *end != '\0' || val > 0xffff) {
            return;
        }

        portnum = htons((uint16_t) val);
    } else {
        switch (uri->scheme) {
        case HTTP_SCHEME_HTTP:
            portnum = htons(80);
            break;

        case HTTP_SCHEME_HTTPS:
            portnum = htons(443);
            break;

        default:
            return;
        }
    }

    if (strchr(host, ':') != NULL) {
        struct in6_addr in6;

        /* Strip zone suffix */
        char *s = strchr(host, '%');
        if (s != NULL) {
            *s = '\0';
        }

        rc = inet_pton(AF_INET6, host, &in6);
        if (rc != 1) {
            return;
        }

        uri->addr.in6.sin6_family = AF_INET6;
        uri->addr.in6.sin6_addr = in6;
        uri->addr.in6.sin6_port = portnum;
    } else {
        struct in_addr in;

        rc = inet_pton(AF_INET, host, &in);
        if (rc != 1) {
            return;
        }

        uri->addr.in.sin_family = AF_INET;
        uri->addr.in.sin_addr = in;
        uri->addr.in.sin_port = portnum;
    }
}

/* Create new URI, by parsing URI string
 */
http_uri*
http_uri_new (const char *str, bool strip_fragment)
{
    http_uri       *uri = mem_new(http_uri, 1);
    char           *buf;

    /* Parse URI */
    if (http_uri_parse(uri, str) != NULL) {
        goto FAIL;
    }

    /* Allow only http and https schemes */
    switch (uri->scheme) {
    case HTTP_SCHEME_HTTP:
    case HTTP_SCHEME_HTTPS:
        break;

    default:
        goto FAIL;
    }

    uri->str = buf = str_dup(str);

    /* Honor strip_fragment flag */
    if (strip_fragment && http_uri_field_present(uri, UF_FRAGMENT)) {
        buf[uri->parsed.field_data[UF_FRAGMENT].off - 1] = '\0';
        uri->parsed.field_set &= ~(1 << UF_FRAGMENT);
        uri->parsed.field_data[UF_FRAGMENT].off = 0;
        uri->parsed.field_data[UF_FRAGMENT].len = 0;
    }

    /* Prepare addr, path */
    http_uri_parse_addr(uri);
    uri->path = http_uri_field_strdup(uri, UF_PATH);

    return uri;

    /* Error: cleanup and exit */
FAIL:
    mem_free(uri);
    return NULL;
}

/* Clone the URI
 */
http_uri*
http_uri_clone (const http_uri *old)
{
    http_uri *uri = mem_new(http_uri, 1);

    *uri = *old;
    uri->str = str_dup(uri->str);
    uri->path = str_dup(uri->path);

    return uri;
}

/* Check that string, defined by begin and end pointers,
 * has a specified prefix
 */
static bool
http_uri_str_prefix(const char *beg, const char *end, const char *pfx)
{
    size_t len = end - beg;
    size_t pfx_len = strlen(pfx);

    return len >= pfx_len && !memcmp(beg, pfx, pfx_len);
}

/* Check that string, defined by begin and end pointers,
 * equal to the specified pattern
 */
static bool
http_uri_str_equal(const char *beg, const char *end, const char *pattern)
{
    size_t len = end - beg;
    size_t plen = strlen(pattern);

    return len == plen && !memcmp(beg, pattern, len);
}

/* Find 1st occurrence of the character in the string,
 * defined by begin and end pointers
 */
static char *
http_uri_str_chr(const char *beg, const char *end, char c)
{
    return memchr(beg, c, end - beg);
}

/* Find last occurrence of the character in the string,
 * defined by begin and end pointers
 */
static char *
http_uri_str_rchr(const char *beg, const char *end, char c)
{
    return memrchr(beg, c, end - beg);
}

/* Remove last path segment. Returns pointer to the
 * path end
 */
static char*
http_uri_remove_last_segment (char *path, char *end)
{
    char *s = http_uri_str_rchr(path, end, '/');
    return s == NULL ? end : s;
}

/* Remove path dot segments, per rfc3986, 5.2.4.
 */
static char*
http_uri_remove_dot_segments (char *path, char *end)
{
    char *input = path;
    char *path_end = path;

    while (input != end) {
        /* A.  If the input buffer begins with a prefix of "../" or "./",
         *     then remove that prefix from the input buffer; otherwise,
         */
        if (http_uri_str_prefix(input, end, "../")) {
            input += 3;
        } else if (http_uri_str_prefix(input, end, "./")) {
            input += 2;
        /* B.  if the input buffer begins with a prefix of "/./" or "/.",
         *     where "." is a complete path segment, then replace that
         *     prefix with "/" in the input buffer; otherwise,
         */
        } else if (http_uri_str_prefix(input, end, "/./")) {
            input += 2;
        } else if (http_uri_str_equal(input, end, "/.")) {
            input ++;
            input[0] = '/';
        /* C.  if the input buffer begins with a prefix of "/../" or "/..",
         *     where ".." is a complete path segment, then replace that
         *     prefix with "/" in the input buffer and remove the last
         *     segment and its preceding "/" (if any) from the output
         *     buffer; otherwise,
         */
        } else if (http_uri_str_prefix(input, end, "/../")) {
            path_end = http_uri_remove_last_segment(path, path_end);
            input += 3;
        } else if (http_uri_str_equal(input, end, "/..")) {
            path_end = http_uri_remove_last_segment(path, path_end);
            input += 2;
            input[0] = '/';
        /* D.  if the input buffer consists only of "." or "..", then remove
         *     that from the input buffer; otherwise,
         */
        } else if (http_uri_str_equal(input, end, ".") ||
                   http_uri_str_equal(input, end, "..")) {
            input = end;
        /* E.  move the first path segment in the input buffer to the end of
         *     the output buffer, including the initial "/" character (if
         *     any) and any subsequent characters up to, but not including,
         *     the next "/" character or the end of the input buffer.
         */
        } else {
            char   *s = http_uri_str_chr(input + 1, end, '/');
            size_t sz = s ? s - input : end - input;

            memmove(path_end, input, sz);
            path_end += sz;
            input += sz;
        }
    }

    return path_end;
}

/* Create URI, relative to base URI. If `path_only' is
 * true, scheme, host and port are taken from the
 * base URI
 */
http_uri*
http_uri_new_relative (const http_uri *base, const char *path,
        bool strip_fragment, bool path_only)
{
    char           *buf = alloca(strlen(base->str) + strlen(path) + 1);
    char           *end = buf;
    http_uri       ref;
    const http_uri *uri;
    http_uri_field field;
    char           *path_beg;

    if (http_uri_parse(&ref, path) != NULL) {
        return NULL;
    }

    /* Set schema, userinfo, host and port */
    if (path_only || !http_uri_field_present(&ref, UF_SCHEMA)) {
        end = http_uri_field_copy(base, UF_SCHEMA, end);
    } else {
        end = http_uri_field_copy(&ref, UF_SCHEMA, end);
    }

    end = http_uri_field_append(http_uri_field_make("://"), end);

    if (path_only || !http_uri_field_present(&ref, UF_HOST)) {
        uri = base;
    } else {
        uri = &ref;
    }

    if (http_uri_field_present(uri, UF_USERINFO)) {
        end = http_uri_field_copy(uri, UF_USERINFO, end);
        end = http_uri_field_append(http_uri_field_make("@"), end);
    }

    field = http_uri_field_get(uri, UF_HOST);
    if (memchr(field.str, ':', field.len) != NULL) {
        *end ++ = '[';
        end = http_uri_field_append(field, end);
        *end ++ = ']';
    } else {
        end = http_uri_field_append(field, end);
    }

    if (http_uri_field_present(uri, UF_PORT)) {
        end = http_uri_field_append(http_uri_field_make(":"), end);
        end = http_uri_field_copy(uri, UF_PORT, end);
    }

    /* Set path */
    path_beg = end;
    if (!http_uri_field_nonempty(&ref, UF_PATH)) {
        end = http_uri_field_copy(base, UF_PATH, end);
    } else {
        if (http_uri_field_begin(&ref, UF_PATH) != '/') {
            end = http_uri_field_copy_basepath(base, end);
        }
        end = http_uri_field_copy(&ref, UF_PATH, end);
    }

    end = http_uri_remove_dot_segments(path_beg, end);

    /* Query and fragment */
    if (http_uri_field_present(&ref, UF_QUERY)) {
        end = http_uri_field_append(http_uri_field_make("?"), end);
        end = http_uri_field_copy(&ref, UF_QUERY, end);
    }

    if (!strip_fragment && http_uri_field_present(&ref, UF_FRAGMENT)) {
        end = http_uri_field_append(http_uri_field_make("#"), end);
        end = http_uri_field_copy(&ref, UF_FRAGMENT, end);
    }

    *end = '\0';

    return http_uri_new(buf, false);
}

/* Free the URI
 */
#ifndef __clang_analyzer__
void
http_uri_free (http_uri *uri)
{
    if (uri != NULL) {
        mem_free((char*) uri->str);
        mem_free((char*) uri->path);
        mem_free(uri);
    }
}
#endif

/* Get URI string
 */
const char*
http_uri_str (http_uri *uri)
{
    return uri->str;
}

/* Get URI's host address. If Host address is not literal, returns NULL
 */
const struct sockaddr*
http_uri_addr (http_uri *uri)
{
    if (uri->addr.sockaddr.sa_family == AF_UNSPEC) {
        return NULL;
    }

    return &uri->addr.sockaddr;
}

/* Get URI path
 */
const char*
http_uri_get_path (const http_uri *uri)
{
    return uri->path;
}

/* Set URI path
 */
void
http_uri_set_path (http_uri *uri, const char *path)
{
    http_uri_field_replace(uri, UF_PATH, path);
}

/* Fix URI host: if `match` is NULL or uri's host matches `match`,
 * replace uri's host and port with values taken from the base_uri
 */
void
http_uri_fix_host (http_uri *uri, const http_uri *base_uri, const char *match)
{
    http_uri_field schema, host, port;

    if (match != NULL) {
        host = http_uri_field_get(uri, UF_HOST);
        if (strncasecmp(host.str, match, host.len)) {
            return;
        }
    }

    schema = http_uri_field_get(base_uri, UF_SCHEMA);
    host = http_uri_field_get(base_uri, UF_HOST);
    port = http_uri_field_get(base_uri, UF_PORT);

    http_uri_field_replace_len(uri, UF_SCHEMA, schema.str, schema.len);
    http_uri_field_replace_len(uri, UF_HOST, host.str, host.len);
    http_uri_field_replace_len(uri, UF_PORT, port.str, port.len);
}

/* Fix IPv6 address zone suffix
 */
void
http_uri_fix_ipv6_zone (http_uri *uri, int ifindex)
{
    http_uri_field field;
    char           *host;

    /* Check if we need to change something */
    if (uri->addr.sockaddr.sa_family != AF_INET6) {
        return; /* Not IPv6 */
    }

    if (!ip_is_linklocal(AF_INET6, &uri->addr.in6.sin6_addr)) {
        return; /* Not link-local */
    }

    field = http_uri_field_get(uri, UF_HOST);
    if (memchr(field.str, '%', field.len)) {
        return; /* Already has zone suffix */
    }

    /* Obtain writable copy of host name */
    host = alloca(field.len + 64);
    memcpy(host, field.str, field.len);

    /* Append zone suffix */
    sprintf(host + field.len, "%%25%d", ifindex);

    /* Update URL's host */
    http_uri_field_replace(uri, UF_HOST, host);
    uri->addr.in6.sin6_scope_id = ifindex;
}

/* Strip zone suffix from literal IPv6 host address
 *
 * If address is not IPv6 or doesn't have zone suffix, it is
 * not changed
 */
void
http_uri_strip_zone_suffux (http_uri *uri)
{
    http_uri_field field;
    const char     *suffix;
    size_t         len;
    char           *host;

    /* Check if we need to change something */
    if (uri->addr.sockaddr.sa_family != AF_INET6) {
        return; /* Not IPv6 */
    }

    field = http_uri_field_get(uri, UF_HOST);
    suffix = memchr(field.str, '%', field.len);
    if (suffix == NULL) {
        return; /* No zone suffix */
    }

    len = suffix - field.str;

    /* Update host */
    host = alloca(len + 1);
    host[len] = '\0';

    http_uri_field_replace(uri, UF_HOST, host);
    uri->addr.in6.sin6_scope_id = 0;
}

/* Make sure URI's path ends with the slash character
 */
void
http_uri_fix_end_slash (http_uri *uri)
{
    const char *path = http_uri_get_path(uri);
    if (!str_has_suffix(path, "/")) {
        size_t len = strlen(path);
        char *path2 = alloca(len + 2);
        memcpy(path2, path, len);
        path2[len] = '/';
        path2[len+1] = '\0';
        http_uri_set_path(uri, path2);
    }
}

/* Check if 2 URIs are equal
 */
bool
http_uri_equal (const http_uri *uri1, const http_uri *uri2)
{
    return uri1->scheme == uri2->scheme &&
           http_uri_field_equal(uri1, uri2, UF_HOST, true) &&
           http_uri_field_equal(uri1, uri2, UF_PORT, true) &&
           http_uri_field_equal(uri1, uri2, UF_PATH, false) &&
           http_uri_field_equal(uri1, uri2, UF_QUERY, false) &&
           http_uri_field_equal(uri1, uri2, UF_FRAGMENT, false) &&
           http_uri_field_equal(uri1, uri2, UF_USERINFO, false);
}

/******************** HTTP header ********************/
/* http_hdr represents HTTP header
 */
typedef struct {
    ll_head fields;          /* List of http_hdr_field */
} http_hdr;

/* http_hdr_field represents a single HTTP header field
 */
typedef struct {
    char    *name;           /* Header name */
    char    *value;          /* Header value, may be NULL */
    ll_node chain;           /* In http_hdr::fields */
} http_hdr_field;

/* Create http_hdr_field. Name can be NULL
 */
static http_hdr_field*
http_hdr_field_new (const char *name)
{
    http_hdr_field *field = mem_new(http_hdr_field, 1);
    field->name = name ? str_dup(name) : str_new();
    return field;
}

/* Destroy http_hdr_field
 */
static void
http_hdr_field_free (http_hdr_field *field)
{
    mem_free(field->name);
    mem_free(field->value);
    mem_free(field);
}

/* Initialize http_hdr in place
 */
static void
http_hdr_init (http_hdr *hdr)
{
    ll_init(&hdr->fields);
}

/* Cleanup http_hdr in place
 */
static void
http_hdr_cleanup (http_hdr *hdr)
{
    ll_node *node;

    while ((node = ll_pop_beg(&hdr->fields)) != NULL) {
        http_hdr_field *field = OUTER_STRUCT(node, http_hdr_field, chain);
        http_hdr_field_free(field);
    }
}

/* Write header to string buffer in wire format
 */
static char*
http_hdr_write (const http_hdr *hdr, char *out)
{
    ll_node *node;

    for (LL_FOR_EACH(node, &hdr->fields)) {
        http_hdr_field *field = OUTER_STRUCT(node, http_hdr_field, chain);
        out = str_append(out, field->name);
        out = str_append(out, ": ");
        out = str_append(out, field->value);
        out = str_append(out, "\r\n");
    }

    return str_append(out, "\r\n");
}

/* Lookup field in the header
 */
static http_hdr_field*
http_hdr_lookup (const http_hdr *hdr, const char *name)
{
    ll_node *node;

    for (LL_FOR_EACH(node, &hdr->fields)) {
        http_hdr_field *field = OUTER_STRUCT(node, http_hdr_field, chain);
        if (!strcasecmp(field->name, name)) {
            return field;
        }
    }

    return NULL;
}

/* Get header field
 */
static const char*
http_hdr_get (const http_hdr *hdr, const char *name)
{
    http_hdr_field *field = http_hdr_lookup(hdr, name);

    if (field == NULL) {
        return NULL;
    }

    if (field->value == NULL) {
        return "";
    }

    return field->value;
}

/* Set header field
 */
static void
http_hdr_set (http_hdr *hdr, const char *name, const char *value)
{
    http_hdr_field *field = http_hdr_lookup(hdr, name);

    if (field == NULL) {
        field = http_hdr_field_new(name);
        ll_push_end(&hdr->fields, &field->chain);
    }

    if (field->value == NULL) {
        field->value = str_dup(value);
    } else {
        field->value = str_assign(field->value, value);
    }
}

/* Del header field
 */
static void
http_hdr_del (http_hdr *hdr, const char *name)
{
    http_hdr_field *field = http_hdr_lookup(hdr, name);

    if (field != NULL) {
        ll_del(&field->chain);
        http_hdr_field_free(field);
    }
}

/* Handle HTTP parser on_header_field callback
 * parser->data must point to the header being parsed
 */
static int
http_hdr_on_header_field (http_parser *parser,
        const char *data, size_t size)
{
    http_hdr       *hdr = parser->data;
    ll_node        *node;
    http_hdr_field *field = NULL;

    /* Get last field */
    node = ll_last(&hdr->fields);
    if (node != NULL) {
        field = OUTER_STRUCT(node, http_hdr_field, chain);
    }

    /* If there is no last field, or last field already
     * has value, create a new field
     */
    if (field == NULL || field->value != NULL) {
        field = http_hdr_field_new(NULL);
        ll_push_end(&hdr->fields, &field->chain);
    }

    /* Append data to the field name */
    field->name = str_append_mem(field->name, data, size);

    return 0;
}

/* Handle HTTP parser on_header_value callback
 * parser->data must point to the header being parsed
 */
static int
http_hdr_on_header_value (http_parser *parser,
        const char *data, size_t size)
{
    http_hdr       *hdr = parser->data;
    ll_node        *node;
    http_hdr_field *field = NULL;

    /* Get last field */
    node = ll_last(&hdr->fields);
    if (node != NULL) {
        field = OUTER_STRUCT(node, http_hdr_field, chain);
    }

    /* If there is no last field, just ignore the data.
     * Note, it actually should not happen
     */
    if (field == NULL) {
        return 0;
    }

    /* Append data to field value */
    if (field->value == NULL) {
        field->value = str_new();
    }

    field->value = str_append_mem(field->value, data, size);

    return 0;
}

/* Handle HTTP parser on_headers_complete callback
 * This is used http_hdr_parse only and returns 1 to
 * tell parser to don't attempt to parse message body
 */
static int
http_hdr_on_headers_complete (http_parser *parser)
{
    (void) parser;
    return 1;
}


/* Parse http_hdr from memory buffer
 *
 * If `skip_line' is true, first line is skipped, which
 * is useful if first line contains HTTP request/status
 * or a multipart boundary
 */
static error
http_hdr_parse (http_hdr *hdr, const char *data, size_t size, bool skip_line)
{
    static http_parser_settings callbacks = {
        .on_header_field     = http_hdr_on_header_field,
        .on_header_value     = http_hdr_on_header_value,
        .on_headers_complete = http_hdr_on_headers_complete
    };
    http_parser parser;
    static char prefix[] = "HTTP/1.1 200 OK\r\n";

    /* Skip first line, if requested */
    if (skip_line) {
        const char *s = memchr(data, '\n', size);
        if (s) {
            size_t skip = (s - data) + 1;
            data += skip;
            size -= skip;
        }
    }

    /* Initialize HTTP parser */
    http_parser_init(&parser, HTTP_RESPONSE);
    parser.data = hdr;

    /* Note, http_parser unable to parse bare HTTP
     * header, without request or status line, so
     * we insert fake status line to make it happy
     */
    http_parser_execute(&parser, &callbacks, prefix, sizeof(prefix) - 1);
    http_parser_execute(&parser, &callbacks, data, size);

    if (parser.http_errno != HPE_OK) {
        return ERROR(http_errno_description(parser.http_errno));
    }

    return NULL;
}

/* Check if character is special, for http_hdr_params_parse
 */
static bool
http_hdr_params_chr_isspec (char c)
{
    if (0x20 < c && c < 0x7f) {
        switch (c) {
        case '(': case ')': case '<': case '>':
        case '@': case ',': case ';': case ':':
        case '\\': case '\"':
        case '/': case '[': case ']': case '?':
        case '=':
            return true;

        default:
            return safe_isspace(c);
        }
    }

    return true;
}

/* Check if character is space, for http_hdr_params_parse
 */
static bool
http_hdr_params_chr_isspace (char c)
{
    switch ((unsigned char) c) {
    case '\t': case '\n': case '\v': case '\f':
    case '\r': case ' ': case 0x85: case 0xA0:
        return true;
    }

    return false;
}

/* Parse HTTP header field with parameters.
 * Result is saved into `params' as collection of name/value fields
 */
static error
http_hdr_params_parse (http_hdr *params, const char *name, const char *in)
{
    enum {
    /*  params ::= param [';' params]
     *  param  ::= SP1 NAME SP2 '=' SP3 value SP4
     *  value  ::= TOKEN | STRING
     */
        SP1, NAME, SP2, EQ, SP3, VALUE, TOKEN, STRING, STRING_BSLASH, SP4, END
    } state = SP1;
    char           c;
    http_hdr_field *field = NULL;

    /* Parameters begin after ';' */
    in = strchr(in, ';');
    if (in == NULL) {
        return NULL;
    }

    in ++;

    while ((c = *in) != '\0') {
        switch (state) {
        case SP1: case SP2: case SP3: case SP4:
            if (!http_hdr_params_chr_isspace(c)) {
                state ++;
                continue;
            }
            break;

        case NAME:
            if (!http_hdr_params_chr_isspec(c)) {
                if (field == NULL) {
                    field = http_hdr_field_new(NULL);
                    field->value = str_new();
                    ll_push_end(&params->fields, &field->chain);
                }
                field->name = str_append_c(field->name, c);
            } else if (c == ';') {
                state = SP1;
                field = NULL;
            } else {
                state = SP2;
                continue;
            }
            break;

        case EQ:
            if (c == '=') {
                state = SP3;
            } else if (c == ';') {
                state = SP1;
                field = NULL;
            } else {
                return eloop_eprintf(
                        "http %s: expected '=' or ';', got: %s", name, in);
            }
            break;

        case VALUE:
            if (c == '"') {
                state = STRING;
            } else {
                state = TOKEN;
                continue;
            }
            break;

        case STRING:
            if (c == '\\') {
                state = STRING_BSLASH;
            } else if (c == '"') {
                state = SP4;
            } else {
                field->value = str_append_c(field->value, c);
            }
            break;

        case STRING_BSLASH:
            field->value = str_append_c(field->value, c);
            state = STRING;
            break;

        case TOKEN:
            if (c != ';' && c != '"' && !safe_isspace(c)) {
                field->value = str_append_c(field->value, c);
            } else {
                state = SP4;
                continue;
            }
            break;

        case END:
            if (c != ';') {
                return eloop_eprintf(
                        "http %s: expected ';', got: %s", name, in);
            }

            state = SP1;
            field = NULL;
            break;
        }

        in ++;
    }

    if (state == STRING || state == STRING_BSLASH) {
        return eloop_eprintf( "http %s: unterminated quoted string");
    }

    return NULL;
}

/* Call callback for each header field
 */
static void
hdr_for_each (const http_hdr *hdr,
        void (*callback)(const char *name, const char *value, void *ptr),
        void *ptr)
{
    ll_node *node;

    for (LL_FOR_EACH(node, &hdr->fields)) {
        http_hdr_field *field = OUTER_STRUCT(node, http_hdr_field, chain);

        if (field->value != NULL) {
            callback(field->name, field->value, ptr);
        }
    }
}

/******************** HTTP multipart ********************/
/* http_multipart represents a decoded multipart message
 */
struct http_multipart {
    int           count;    /* Count of bodies */
    http_data     *data;    /* Response data */
    http_data     **bodies; /* Multipart bodies, var-size */
};

/* Add multipart body
 */
static void
http_multipart_add_body (http_multipart *mp, http_data *body)
{
    mp->bodies = mem_resize(mp->bodies, mp->count + 1, 0);
    mp->bodies[mp->count ++] = body;
}

/* Find boundary within the multipart message data
 */
static const char*
http_multipart_find_boundary (const char *boundary, size_t boundary_len,
        const char *data, size_t size) {

    /* Note, per RFC 2046, "the boundary delimiter MUST occur at the beginning
     * of a line, i.e., following a CRLF, and the initial CRLF is considered to
     * be attached to the boundary delimiter line rather than part of the
     * preceding part".
     *
     * However, Xerox WorkCentre 3025 violates this requirement, and
     * puts boundary delimiter without preceding CRLF, so we must relax
     * out expectations
     */
    return memmem(data, size, boundary, boundary_len);
}

/* Adjust part of multipart message:
 *   1) skip header
 *   2) fetch content type
 */
static error
http_multipart_adjust_part (http_data *part)
{
    const char *split;
    http_hdr   hdr;
    size_t     hdr_len;
    error      err;

    /* Locate end of headers */
    split = memmem(part->bytes, part->size, "\r\n\r\n", 4);
    if (split == NULL) {
        return ERROR("http multipart: can't locate end of part headers");
    }

    /* Parse headers and obtain content-type */
    http_hdr_init(&hdr);
    hdr_len = 4 + split - (char*) part->bytes;
    err = http_hdr_parse(&hdr, part->bytes, hdr_len - 2, true);

    if (err == NULL) {
        const char *ct = http_hdr_get(&hdr, "Content-Type");
        http_data_set_content_type(part, ct);
    }

    http_hdr_cleanup(&hdr);
    if (err != NULL) {
        return eloop_eprintf("http multipart: %s", ESTRING(err));
    }

    /* Cut of header */
    split += 4;
    part->size -= (split - (char*) part->bytes);
    part->bytes = split;

    /* Strip CR/LF preceding next boundary, if any */
    if (split[part->size - 2] == '\r' && split[part->size - 1] == '\n') {
        part->size -= 2;
    }

    return NULL;
}

/* Free http_multipart
 */
static void
http_multipart_free (http_multipart *mp)
{
    int i;

    for (i = 0; i < mp->count; i ++) {
        http_data_unref(mp->bodies[i]);
    }

    mem_free(mp);
}

/* Parse MIME multipart message body
 * Saves result into `out'. Result may be NULL, if no multipart
 */
static error
http_multipart_parse (http_multipart **out, log_ctx *log,
        http_data *data, const char *content_type)
{
    http_multipart *mp;
    http_hdr       params;
    const char     *boundary;
    size_t         boundary_len = 0;
    const char     *data_beg, *data_end, *data_prev;
    error          err;
    ll_node        *node;

    /* Check MIME type */
    *out = NULL;
    if (strncmp(data->content_type, "multipart/", 10)) {
        return NULL;
    }

    /* Obtain boundary */
    http_hdr_init(&params);
    err = http_hdr_params_parse(&params, "Content-Type", content_type);
    if (err != NULL) {
        http_hdr_cleanup(&params);
        return err;
    }

    log_debug(log, "http multipart parameters:");
    for (LL_FOR_EACH(node, &params.fields)) {
        http_hdr_field *field = OUTER_STRUCT(node, http_hdr_field, chain);
        log_debug(log, "  %s=\"%s\"", field->name, field->value);
    }

    boundary = http_hdr_get(&params, "boundary");
    if (boundary) {
        char *s;

        boundary_len = strlen(boundary) + 2;
        s = alloca(boundary_len + 1);

        s[0] = '-';
        s[1] = '-';
        strcpy(s + 2, boundary);
        boundary = s;
    }
    http_hdr_cleanup(&params);

    if (!boundary) {
        return ERROR("http multipart: missed boundary parameter");
    }

    /* Create http_multipart structure */
    mp = mem_new(http_multipart, 1);
    mp->data = http_data_ref(data);

    /* Split data into parts */
    data_beg = data->bytes;
    data_end = data_beg + data->size;
    data_prev = NULL;

    while (data_beg != data_end) {
        const char *part = http_multipart_find_boundary(boundary, boundary_len,
            data_beg, data_end - data_beg);
        const char *next = data_end;

        if (part != NULL) {
            if (data_prev != NULL) {
                http_data *body = http_data_new(data,
                        data_prev, part - data_prev);
                http_multipart_add_body(mp, body);

                err = http_multipart_adjust_part(body);
                if (err != NULL) {
                    http_multipart_free(mp);
                    return err;
                }
            }

            data_prev = part;

            const char *tail = part + boundary_len;
            if (data_end - tail >= 2 && tail[0] == '\r' && tail[1] == '\n') {
                next = tail + 2;
            }
        }

        data_beg = next;
    }

    if (mp->count == 0) {
        http_multipart_free(mp);
        return ERROR("http multipart: no parts found");
    }

    if (data_beg != data_end) {
        log_debug(log,
            "http multipart: found %d bytes of garbage at the end of message",
            (int)(data_end - data_beg));
    }

    *out = mp;
    return NULL;
}

/******************** HTTP data ********************/
/* http_data + SoupBuffer
 */
typedef struct {
    http_data              data;    /* HTTP data */
    volatile unsigned int  refcnt;  /* Reference counter */
    http_data              *parent; /* Parent data buffer */
} http_data_ex;


/* Create new http_data
 *
 * If parent != NULL, supplied bytes buffer must be owned by
 * parent. Otherwise, newly created http_data takes ownership
 * on the supplied data buffer
 */
static http_data*
http_data_new(http_data *parent, const char *bytes, size_t size)
{
    http_data_ex *data_ex = mem_new(http_data_ex, 1);

    if (parent != NULL) {
        log_assert(NULL, bytes >= (char*) parent->bytes);
        log_assert(NULL,
            (bytes + size) <= ((char*) parent->bytes + parent->size));
    }

    data_ex->data.content_type = str_new();
    data_ex->data.bytes = bytes;
    data_ex->data.size = size;

    data_ex->refcnt = 1;
    data_ex->parent = parent ? http_data_ref(parent) : NULL;

    return &data_ex->data;
}

/* Set Content-type
 */
static void
http_data_set_content_type (http_data *data, const char *content_type)
{
    mem_free((char*) data->content_type);

    if (content_type == NULL) {
        content_type = str_dup("text/plain");
    } else {
        char *s;

        content_type = str_dup_tolower(content_type);
        s = strchr(content_type, ';');
        if (s != NULL) {
            *s = '\0';
        }
    }

    data->content_type = content_type;
}

/* Dummy http_data in case no data is present
 */
static http_data
http_data_empty = {
    .content_type = "",
    .bytes = "",
    .size = 0
};


/* Ref http_data
 */
http_data*
http_data_ref (http_data *data)
{
    if (data != NULL && data != &http_data_empty) {
        http_data_ex *data_ex = OUTER_STRUCT(data, http_data_ex, data);
        __sync_fetch_and_add(&data_ex->refcnt, 1);
    }
    return data;
}

/* Unref http_data
 */
void
http_data_unref (http_data *data)
{
    if (data != NULL && data != &http_data_empty) {
        http_data_ex *data_ex = OUTER_STRUCT(data, http_data_ex, data);

        if (__sync_fetch_and_sub(&data_ex->refcnt, 1) == 1) {
            if (data_ex->parent != NULL) {
                http_data_unref(data_ex->parent);
            } else {
                mem_free((void*) data_ex->data.bytes);
            }

            mem_free((char*) data_ex->data.content_type);
            mem_free(data_ex);
        }
    }
}

/* Append bytes to data. http_data must be owner of its
 * own buffer, i.e. it must have no parent
 *
 * Returns true on success, false on OOM
 */
static bool
http_data_append (http_data *data, const char *bytes, size_t size)
{
    http_data_ex *data_ex = OUTER_STRUCT(data, http_data_ex, data);
    void         *p;

    log_assert(NULL, data_ex->parent == NULL);

    p = mem_try_resize((char*) data->bytes, data->size + size, 0);
    if (p == NULL) {
        return false;
    }

    data->bytes = p;
    memcpy((char*) data->bytes + data->size, bytes, size);
    data->size += size;

    return true;
}

/******************** HTTP data queue ********************/
/* http_data_queue represents a queue of http_data items
 */
struct http_data_queue {
    http_data **items; /* Array of http_data items */
};

/* Create new http_data_queue
 */
http_data_queue*
http_data_queue_new (void)
{
    http_data_queue *queue = mem_new(http_data_queue, 1);
    queue->items = ptr_array_new(http_data*);
    return queue;
}

/* Destroy http_data_queue
 */
void
http_data_queue_free (http_data_queue *queue)
{
    http_data_queue_purge(queue);
    mem_free(queue->items);
    mem_free(queue);
}

/* Push item into the http_data_queue.
 */
void
http_data_queue_push (http_data_queue *queue, http_data *data)
{
    queue->items = ptr_array_append(queue->items, data);
}

/* Pull an item from the http_data_queue. Returns NULL if queue is empty
 */
http_data*
http_data_queue_pull (http_data_queue *queue)
{
    return ptr_array_del(queue->items, 0);
}

/* Get queue length
 */
int
http_data_queue_len (const http_data_queue *queue)
{
    return (int) mem_len(queue->items);
}

/* Purge the queue
 */
void
http_data_queue_purge (http_data_queue *queue)
{
    http_data *data;

    while ((data = http_data_queue_pull(queue)) != NULL) {
        http_data_unref(data);
    }
}

/******************** HTTP client ********************/
/* Type http_client represents HTTP client instance
 */
struct http_client {
    void       *ptr;       /* Callback's user data */
    log_ctx    *log;       /* Logging context */
    ll_head    pending;    /* Pending queries */
    void       (*onerror)( /* Callback to be called on transport error */
            void *ptr, error err);
};

/* Create new http_client
 */
http_client*
http_client_new (log_ctx *log, void *ptr)
{
    http_client *client = mem_new(http_client, 1);

    client->ptr = ptr;
    client->log = log;
    ll_init(&client->pending);

    return client;
}

/* Destroy http_client
 */
void
http_client_free (http_client *client)
{
    log_assert(client->log, ll_empty(&client->pending));

    mem_free(client);
}

/* Set on-error callback. If this callback is not NULL,
 * in a case of transport error it will be called instead
 * of the http_query callback
 */
void
http_client_onerror (http_client *client,
        void (*onerror)(void *ptr, error err))
{
    client->onerror = onerror;
}

/* Cancel all pending queries, if any
 */
void
http_client_cancel (http_client *client)
{
    ll_node *node;

    while ((node = ll_pop_beg(&client->pending)) != NULL) {
         http_query *q;
         q = http_query_by_ll_node(node);
         http_query_cancel(q);
    }
}

/* Set timeout of all pending queries, if any. Timeout is in milliseconds
 */
void
http_client_timeout (http_client *client, int timeout)
{
    ll_node *node;

    while ((node = ll_pop_beg(&client->pending)) != NULL) {
         http_query *q;
         q = http_query_by_ll_node(node);
         http_query_timeout(q, timeout);
    }
}

/* Cancel all pending queries with matching address family and uintptr
 */
void
http_client_cancel_af_uintptr (http_client *client, int af, uintptr_t uintptr)
{
    ll_head leftover;
    ll_node *node;

    ll_init(&leftover);

    while ((node = ll_pop_beg(&client->pending)) != NULL) {
        http_query *q = http_query_by_ll_node(node);

        if (uintptr == http_query_get_uintptr(q) &&
            af == http_uri_af(http_query_uri(q))) {
            http_query_cancel(q);
        } else {
            ll_push_end(&leftover, node);
        }
    }

    ll_cat(&client->pending, &leftover);
}

/* Check if client has pending queries
 */
bool
http_client_has_pending (const http_client *client)
{
    return !ll_empty(&client->pending);
}

/******************** HTTP request handling ********************/
/* Type http_query represents HTTP query (both request and response)
 */
struct http_query {
    /* URI and method */
    http_uri          *uri;                     /* Query URI */
    http_uri          *real_uri;                /* Real URI, may be NULL */
    const char        *method;                  /* Request method */

    /* Request and response headers */
    http_hdr          request_header;           /* Request header */
    http_hdr          response_header;          /* Response header */
    bool              host_inserted;            /* Host: auto-inserted */

    /* HTTP redirects */
    int               redirect_count;           /* Count of redirects */
    http_uri          *orig_uri;                /* Original URI */
    const char        *orig_method;             /* Original method */

    /* Query timeout */
    eloop_timer       *timeout_timer;           /* Timeout timer */
    int               timeout_value;            /* In milliseconds */

    /* Low-level I/O */
    bool              submitted;                /* http_query_submit() called */
    uint64_t          eloop_callid;             /* For eloop_call_cancel */
    error             err;                      /* Transport error */
    struct addrinfo   *addrs;                   /* Addresses to connect to */
    struct addrinfo   *addr_next;               /* Next address to try */
    int               sock;                     /* HTTP socket */
    gnutls_session_t  tls;                      /* NULL if not TLS */
    bool              handshake;                /* TLS handshake in progress */
    bool              sending;                  /* We are now sending */
    eloop_fdpoll      *fdpoll;                  /* Polls q->sock */
    ip_straddr        straddr;                  /* q->sock peer addr, for log */

    char              *rq_buf;                  /* Formatted request */
    size_t            rq_off;                   /* send() offset in request */

    /* HTTP parser */
    http_parser       http_parser;              /* HTTP parser structure */
    bool              http_parser_done;         /* Message parsing done */

    /* Data handling */
    http_data         *request_data;            /* NULL if none */
    http_data         *response_data;           /* NULL if none */
    http_multipart    *response_multipart;      /* NULL if not multipart */

    /* Callbacks and context */
    timestamp         timestamp;                /* Submission timestamp */
    uintptr_t         uintptr;                  /* User-defined parameter */
    void              (*onerror) (void *ptr,    /* On-error callback */
                                error err);
    void              (*onredir) (void *ptr,    /* On-redirect callback */
                                http_uri *uri,
                                const http_uri *orig_uri);
    void              (*onrxhdr) (void *ptr,    /* On-header reception */
                                http_query *q);
    void              (*callback) (void *ptr,   /* Completion callback */
                                http_query *q);

    /* Linkage to http_client */
    http_client       *client;                  /* Client that owns the query */
    bool              queued;                   /* Query is queued */
    ll_node           chain;                    /* In http_client::pending or
                                                   http_client::queued */
};

/* Get http_query* by pointer to its http_query::chain */
static http_query*
http_query_by_ll_node (ll_node *node)
{
     return OUTER_STRUCT(node, http_query, chain);
}

/* Reset query into the state it had before http_query_submit()
 */
static void
http_query_reset (http_query *q)
{
    if (q->host_inserted) {
        http_hdr_del(&q->request_header, "Host");
        q->host_inserted = false;
    }

    http_hdr_cleanup(&q->response_header);

    if (q->addrs != NULL) {
        freeaddrinfo(q->addrs);
        q->addrs = NULL;
        q->addr_next = NULL;
    }

    q->handshake = q->sending = false;

    http_query_disconnect(q);

    str_trunc(q->rq_buf);
    q->rq_off = 0;

    q->http_parser_done = false;

    http_data_unref(q->response_data);
    q->response_data = NULL;

    if (q->response_multipart != NULL) {
        http_multipart_free(q->response_multipart);
        q->response_multipart = NULL;
    }
}

/* Free http_query
 */
static void
http_query_free (http_query *q)
{
    http_query_reset(q);

    http_query_timeout_cancel(q);
    http_uri_free(q->uri);
    http_uri_free(q->real_uri);
    http_uri_free(q->orig_uri);
    http_hdr_cleanup(&q->request_header);

    mem_free(q->rq_buf);

    http_data_unref(q->request_data);

    mem_free(q);
}

/* Set Host header in HTTP request
 */
static void
http_query_set_host (http_query *q)
{
    char                  *host, *end, *buf;
    size_t                len;
    const struct sockaddr *addr = http_uri_addr(q->uri);

    if (addr != NULL) {
        ip_straddr s;
        int        dport;

        switch (q->uri->scheme) {
        case HTTP_SCHEME_HTTP:
            dport = 80;
            break;

        case HTTP_SCHEME_HTTPS:
            dport = 443;
            break;

        default:
            dport = -1;
            break;
        }

        s = ip_straddr_from_sockaddr_dport(addr, dport, false);
        http_query_set_request_header(q, "Host", s.text);

        return;
    }

    host = strstr(http_uri_str(q->uri), "//") + 2;
    end = strchr(host, '/');
    len = end ? (size_t) (end - host) : strlen(host);

    buf = alloca(len + 1);
    memcpy(buf, host, len);

    buf[len] = '\0';

    http_query_set_request_header(q, "Host", buf);
}

/* Create new http_query
 *
 * Newly created http_query takes ownership on uri and body (if not NULL).
 * The method and content_type assumed to be constant strings.
 */
http_query*
http_query_new (http_client *client, http_uri *uri, const char *method,
        char *body, const char *content_type)
{
    http_query *q = mem_new(http_query, 1);

    q->client = client;
    q->uri = uri;
    q->method = method;

    http_hdr_init(&q->request_header);
    http_hdr_init(&q->response_header);

    q->sock = -1;

    q->rq_buf = str_new();

    q->onerror = client->onerror;

    http_parser_init(&q->http_parser, HTTP_RESPONSE);
    q->http_parser.data = &q->response_header;

    /* Note, on Kyocera ECOSYS M2040dn connection keep-alive causes
     * scanned job to remain in "Processing" state about 10 seconds
     * after job has been actually completed, making scanner effectively
     * busy.
     *
     * Looks like Kyocera firmware bug. Force connection to close
     * as a workaround
     */
    http_query_set_request_header(q, "Connection", "close");

    /* Save request body and set Content-Type */
    if (body != NULL) {
        q->request_data = http_data_new(NULL, body, strlen(body));
        if (content_type != NULL) {
            http_query_set_request_header(q, "Content-Type", content_type);
            http_data_set_content_type(q->request_data, content_type);
        }
    }

    /* Set default timeout */
    http_query_timeout(q, HTTP_QUERY_TIMEOUT);

    return q;
}

/* Create new http_query, relative to base URI
 *
 * Newly created http_query takes ownership on body (if not NULL).
 * The method and content_type assumed to be constant strings.
 */
http_query*
http_query_new_relative(http_client *client,
        const http_uri *base_uri, const char *path,
        const char *method, char *body, const char *content_type)
{
    http_uri *uri = http_uri_new_relative(base_uri, path, true, false);
    log_assert(client->log, uri != NULL);
    return http_query_new(client, uri, method, body, content_type);
}

/* http_query_timeout callback
 */
static void
http_query_timeout_callback (void *p)
{
    http_query *q = (http_query*) p;

    q->timeout_timer = NULL; /* to prevent eloop_timer_cancel() */
    http_query_complete(q, ERROR("timeout"));
}

/* Set query timeout, in milliseconds. Negative timeout means 'infinite'
 *
 * This function may be called multiple times (each subsequent call overrides
 * a previous one)
 */
void
http_query_timeout (http_query *q, int timeout)
{
    q->timeout_value = timeout;

    if (q->submitted) {
        http_query_timeout_cancel(q);

        if (timeout >= 0) {
            log_debug(q->client->log, "HTTP using timeout: %d ms",
                q->timeout_value);

            q->timeout_timer = eloop_timer_new(timeout,
                http_query_timeout_callback, q);
        } else {
            log_debug(q->client->log, "HTTP using timeout: none");
        }
    }
}

/* Cancel query timeout timer
 */
static void
http_query_timeout_cancel (http_query *q)
{
    if (q->timeout_timer != NULL) {
        eloop_timer_cancel(q->timeout_timer);
        q->timeout_timer = NULL;
    }
}

/* For this particular query override on-error callback, previously
 * set by http_client_onerror()
 *
 * If canllback is NULL, the completion callback, specified on a
 * http_query_submit() call, will be used even in a case of
 * transport error.
 */
void
http_query_onerror (http_query *q, void (*onerror)(void *ptr, error err))
{
    q->onerror = onerror;
}

/* Set on-redirect callback. It is called in a case of HTTP
 * redirect and may modify the supplied URI
 */
void
http_query_onredir (http_query *q,
        void (*onredir)(void *ptr, http_uri *uri, const http_uri *orig_uri))
{
    q->onredir = onredir;
}

/* Set callback that will be called, when response headers reception
 * is completed
 */
void
http_query_onrxhdr (http_query *q, void (*onrxhdr)(void *ptr, http_query *q))
{
    q->onrxhdr = onrxhdr;
}

/* Choose HTTP redirect method, based on HTTP status code
 * Returns NULL for non-redirection status code, and may
 * be used to detect if status code implies redirection
 */
static const char*
http_query_redirect_method (const http_query *q)
{
    const char *method = q->orig_method ? q->orig_method : q->method;

    switch(http_query_status(q)) {
    case 303:
        if (!strcmp(method, "POST") || !strcmp(method, "PUT")) {
            method = "GET";
        }
        break;

    case 301: case 302: case 307: case 308:
        break;

    default:
        return NULL;
    }

    return method;
}

/* Handle HTTP redirection
 */
static error
http_query_redirect (http_query *q, const char *method)
{
    const char *location;
    http_uri   *uri;

    /* Check and parse location */
    location = http_query_get_response_header(q, "Location");
    if (location == NULL || *location == '\0') {
        return ERROR("HTTP redirect: missed Location: field");
    }

    uri = http_uri_new_relative(q->uri, location, true, false);
    if (uri == NULL) {
        return ERROR("HTTP redirect: invalid Location: field");
    }

    /* Enforce redirects limit */
    q->redirect_count ++;
    if (q->redirect_count == HTTP_REDIRECT_LIMIT) {
        return ERROR("HTTP redirect: too many redirects");
    }

    /* Save original URI and method at the first redirect */
    if (q->redirect_count == 1) {
        q->orig_uri = q->uri;
        q->orig_method = q->method;
    } else {
        http_uri_free(q->uri);
        q->uri = NULL; /* Just in case */
    }

    /* Issue log message */
    log_debug(q->client->log, "HTTP redirect %d: %s %s",
        q->redirect_count, method, http_uri_str(uri));

    /* Call user hook, if any */
    if (q->onredir != NULL) {
        char *old_uri_str = alloca(strlen(uri->str) + 1);

        strcpy(old_uri_str, uri->str);
        q->onredir(q->client->ptr, uri, q->orig_uri);
        if (strcmp(old_uri_str, uri->str)) {
            log_debug(q->client->log, "HTTP redirect override: %s %s",
                method, http_uri_str(uri));
        }
    }

    /* Perform redirection */
    http_query_reset(q);

    q->method = method;
    q->uri = uri;

    http_query_submit(q, q->callback);

    return NULL;
}

/* Complete query processing
 */
static void
http_query_complete (http_query *q, error err)
{
    http_client *client = q->client;

    /* Make sure latest response header field is terminated */
    http_hdr_on_header_value(&q->http_parser, "", 0);

    /* Unlink query from a client */
    ll_del(&q->chain);

    /* Issue log messages */
    q->err = err;
    if (err != NULL) {
        log_debug(client->log, "HTTP %s %s: %s", q->method,
                http_uri_str(q->uri), http_query_status_string(q));
    } else {
        log_debug(client->log, "HTTP %s %s: %d %s", q->method,
                http_uri_str(q->uri),
                http_query_status(q), http_query_status_string(q));
    }

    trace_http_query_hook(log_ctx_trace(client->log), q);

    /* Handle redirection */
    if (err == NULL) {
        const char *method = http_query_redirect_method(q);

        if (method != NULL) {
            q->err = err = http_query_redirect(q, method);
            if (err == NULL) {
                return;
            }
        }

        log_debug(client->log, "HTTP %s %s: %s", q->method,
                http_uri_str(q->uri), http_query_status_string(q));
    }

    /* Restore original method and URI, modified in case of redirection */
    if (q->orig_uri != NULL) {
        q->real_uri = q->uri;
        q->uri = q->orig_uri;
        q->method = q->orig_method;

        q->orig_uri = NULL;
        q->orig_method = NULL;
    }

    /* Call user callback */
    if (err != NULL && q->onerror != NULL) {
        q->onerror(client->ptr, err);
    } else if (q->callback != NULL) {
        q->callback(client->ptr, q);
    }

    http_query_free(q);
}

/* HTTP parser on_body callback
 */
static int
http_query_on_body_callback (http_parser *parser,
        const char *data, size_t size)
{
    http_query *q = OUTER_STRUCT(parser, http_query, http_parser);

    if (size == 0) {
        return 0; /* Just in case */
    }

    if (q->response_data == NULL) {
        q->response_data = http_data_new(NULL, NULL, 0);
    }

    if (!http_data_append(q->response_data, data, size)) {
        q->err = ERROR_ENOMEM;
    }

    return q->err ? 1 : 0;
}

/* HTTP parser on_headers_complete callback
 */
static int
http_query_on_headers_complete (http_parser *parser)
{
    http_query *q = OUTER_STRUCT(parser, http_query, http_parser);

    if (http_query_redirect_method(q) == NULL) {
        log_debug(q->client->log,
                "HTTP %s %s: got response headers (%d)",
                q->method,
                http_uri_str(q->uri),
                http_query_status(q));

        if (q->onrxhdr != NULL) {
            q->onrxhdr(q->client->ptr, q);
        }
    }

    return 0;
}

/* HTTP parser on_message_complete callback
 */
static int
http_query_on_message_complete (http_parser *parser)
{
    http_query *q = OUTER_STRUCT(parser, http_query, http_parser);

    if (q->response_data != NULL) {
        const char *content_type;

        content_type = http_query_get_response_header(q, "Content-Type");
        if (content_type != NULL) {
            http_data_set_content_type(q->response_data, content_type);
            q->err = http_multipart_parse(
                    &q->response_multipart, q->client->log,
                    q->response_data, content_type);
        }
    }

    q->http_parser_done = true;

    return q->err ? 1 : 0;
}

/* HTTP parser callbacks
 */
static http_parser_settings
http_query_callbacks = {
    .on_header_field     = http_hdr_on_header_field,
    .on_header_value     = http_hdr_on_header_value,
    .on_body             = http_query_on_body_callback,
    .on_headers_complete = http_query_on_headers_complete,
    .on_message_complete = http_query_on_message_complete
};

/* http_query::fdpoll callback
 */
static void
http_query_fdpoll_callback (int fd, void *data, ELOOP_FDPOLL_MASK mask)
{
    http_query *q = data;
    size_t     len = mem_len(q->rq_buf) - q->rq_off;
    ssize_t    rc;

    (void) fd;
    (void) mask;

    if (q->handshake) {
        rc = gnutls_handshake(q->tls);
        if (rc < 0) {
            error err = http_query_sock_err(q, rc);

            if (err == NULL) {
                return;
            }

            log_debug(q->client->log, "HTTP %s: gnutls_handshake(): %s",
                q->straddr.text, ESTRING(err));

            /* TLS handshake failed, try another address, if any */
            http_query_disconnect(q);
            q->addr_next = q->addr_next->ai_next;
            http_query_connect(q, err);

            return;
        }

        q->handshake = false;
        eloop_fdpoll_set_mask(q->fdpoll, ELOOP_FDPOLL_BOTH);
    } else if (q->sending) {
        rc = http_query_sock_send(q, q->rq_buf + q->rq_off, len);

        if (rc < 0) {
            error err = http_query_sock_err(q, rc);

            if (err == NULL) {
                return;
            }

            log_debug(q->client->log, "HTTP %s: send(): %s",
                q->straddr.text, ESTRING(err));

            http_query_disconnect(q);

            if (q->rq_off == 0) {
                /* None sent, try another address, if any */
                q->addr_next = q->addr_next->ai_next;
                http_query_connect(q, err);
            } else {
                /* Sending started and failed */
                http_query_complete(q, err);
            }
            return;
        }

        q->rq_off += rc;

        if (q->rq_off == mem_len(q->rq_buf)) {
            q->sending = false;
            eloop_fdpoll_set_mask(q->fdpoll, ELOOP_FDPOLL_BOTH);

            /* Initialize HTTP parser */
            http_parser_init(&q->http_parser, HTTP_RESPONSE);
            q->http_parser.data = &q->response_header;
        }
    } else {
        static char io_buf[HTTP_IOBUF_SIZE];

        rc = http_query_sock_recv(q, io_buf, sizeof(io_buf));

        if (rc < 0) {
            error err = http_query_sock_err(q, rc);
            if (err != NULL) {
                http_query_complete(q, err);
            }

            return;
        }

        http_parser_execute(&q->http_parser, &http_query_callbacks,
                io_buf, rc);

        if (q->http_parser.http_errno != HPE_OK) {
            error err = q->err;
            if (err == NULL) {
                err = ERROR(http_errno_description(q->http_parser.http_errno));
            }
            http_query_complete(q, err);
        } else if (q->http_parser_done) {
            http_query_complete(q, NULL);
        } else if (rc == 0) {
            error err = ERROR("connection closed by device");
            http_query_complete(q, err);
        }
    }
}

/* Try to connect to the next address. The err parameter is a query
 * completion error in a case there are no more addresses to try
 */
static void
http_query_connect (http_query *q, error err)
{
    int        rc;

    /* Skip invalid addresses. Check that we have address to try */
AGAIN:
    while (q->addr_next != NULL &&
           q->addr_next->ai_family != AF_INET &&
           q->addr_next->ai_family != AF_INET6) {
        q->addr_next = q->addr_next->ai_next;
    }

    if (q->addr_next == NULL) {
        http_query_complete(q, err);
        return;
    }

    q->straddr = ip_straddr_from_sockaddr(q->addr_next->ai_addr, true);
    log_debug(q->client->log, "HTTP trying %s", q->straddr.text);

    /* Create socket and try to connect */
    log_assert(q->client->log, q->sock < 0);
    q->sock = socket(q->addr_next->ai_addr->sa_family,
        SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, IPPROTO_TCP);

    if (q->sock == -1) {
        err = ERROR(strerror(errno));
        log_debug(q->client->log, "HTTP %s: socket(): %s",
            q->straddr.text, ESTRING(err));

        q->addr_next = q->addr_next->ai_next;
        goto AGAIN;
    }

    do {
        rc = connect(q->sock, q->addr_next->ai_addr, q->addr_next->ai_addrlen);
    } while (rc < 0 && errno == EINTR);

    if (rc < 0 && errno != EINPROGRESS) {
        err = ERROR(strerror(errno));
        log_debug(q->client->log, "HTTP %s: connect(): %s",
            q->straddr.text, ESTRING(err));

        http_query_disconnect(q);

        q->addr_next = q->addr_next->ai_next;
        goto AGAIN;
    }

    /* Setup TLS, if required */
    if (q->uri->scheme == HTTP_SCHEME_HTTPS) {
        int rc = gnutls_init(&q->tls,
            GNUTLS_CLIENT | GNUTLS_NONBLOCK | GNUTLS_NO_SIGNAL);

        if (rc == GNUTLS_E_SUCCESS) {
            rc = gnutls_set_default_priority(q->tls);
        }

        if (rc == GNUTLS_E_SUCCESS) {
            rc = gnutls_credentials_set(q->tls, GNUTLS_CRD_CERTIFICATE,
                    gnutls_cred);
        }

        if (rc != GNUTLS_E_SUCCESS) {
            err = ERROR(gnutls_strerror(rc));
            http_query_disconnect(q);
            http_query_complete(q, err);
            return;
        }

        gnutls_transport_set_int(q->tls, q->sock);
    }

    /* Create fdpoll, and we are done */
    q->fdpoll = eloop_fdpoll_new(q->sock, http_query_fdpoll_callback, q);
    if (q->tls != NULL) {
        q->handshake = true;
    }
    q->sending = true;
    eloop_fdpoll_set_mask(q->fdpoll, ELOOP_FDPOLL_WRITE);
}

/* Close connection to the server, if any
 */
static void
http_query_disconnect (http_query *q)
{
    if (q->fdpoll != NULL) {
        eloop_fdpoll_free(q->fdpoll);
        q->fdpoll = NULL;
    }

    if (q->tls != NULL) {
        gnutls_deinit(q->tls);
        q->tls = NULL;
    }

    if (q->sock >= 0) {
        close(q->sock);
        q->sock = -1;
    }
}

/* Send data to socket (either via TCP or TLS)
 * On a error, returns negative error code. Use
 * http_query_sock_err() to decode it
 */
static ssize_t
http_query_sock_send (http_query *q, const void *data, size_t size)
{
    ssize_t rc;

    if (q->tls == NULL) {
        rc = send(q->sock, data, size, MSG_NOSIGNAL);
        if (rc < 0) {
            rc = -errno;
        }
    } else {
        rc = gnutls_record_send(q->tls, data, size);
        if (rc < 0) {
            gnutls_record_discard_queued(q->tls);
        }
    }

    return rc;
}

/* Recv data from socket (either via TCP or TLS)
 */
static ssize_t
http_query_sock_recv (http_query *q, void *data, size_t size)
{
    ssize_t rc;

    if (q->tls == NULL) {
        rc = recv(q->sock, data, size, MSG_NOSIGNAL);
        if (rc < 0) {
            rc = -errno;
        }
    } else {
        rc = gnutls_record_recv(q->tls, data, size);
    }

    return rc;
}

/* Get socket error. May return NULL if last operation
 * has failed in recoverable manner
 */
static error
http_query_sock_err (http_query *q, int rc)
{
    ELOOP_FDPOLL_MASK mask = 0;
    error             err = NULL;

    if (q->tls == NULL) {
        rc = -rc;
        switch (rc) {
        case EINTR:
            break;

        case EWOULDBLOCK:
            mask = q->sending ? ELOOP_FDPOLL_WRITE : ELOOP_FDPOLL_READ;
            break;

        default:
            err = ERROR(strerror(errno));
        }

    } else {
        switch (rc) {
        case GNUTLS_E_INTERRUPTED:
            break;

        case GNUTLS_E_AGAIN:
            mask = gnutls_record_get_direction(q->tls) ?
                    ELOOP_FDPOLL_WRITE : ELOOP_FDPOLL_READ;
            break;

        default:
            if (gnutls_error_is_fatal(rc)) {
                err = ERROR(gnutls_strerror(rc));
            }
        }
    }

    if (mask != 0) {
        eloop_fdpoll_set_mask(q->fdpoll, mask);
    }

    return err;
}

/* Start query processing. Called via eloop_call()
 */
static void
http_query_start_processing (void *p)
{
    http_query      *q = (http_query*) p;
    http_uri_field  field;
    char            *host, *port;
    struct addrinfo hints;
    int             rc;

    /* Get host name from the URI */
    field = http_uri_field_get(q->uri, UF_HOST);
    host = alloca(field.len + 1);
    memcpy(host, field.str, field.len);
    host[field.len] = '\0';
    http_uri_unescape_host(host);

    /* Get port name from the URI */
    if (http_uri_field_nonempty(q->uri, UF_PORT)) {
        field = http_uri_field_get(q->uri, UF_PORT);
        port = alloca(field.len + 1);
        memcpy(port, field.str, field.len);
        port[field.len] = '\0';
    } else {
        port = q->uri->scheme == HTTP_SCHEME_HTTP ? "80" : "443";
    }

    /* Lookup target addresses */
    log_debug(q->client->log, "HTTP resolving %s %s", host, port);
    memset(&hints, 0, sizeof(hints));
    hints.ai_flags = AI_ADDRCONFIG;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    rc = getaddrinfo(host, port, &hints, &q->addrs);
    if (rc != 0) {
        http_query_complete(q, ERROR(gai_strerror(rc)));
        return;
    }

    q->addr_next = q->addrs;

    /* Set Host: header, if not set by user */
    if (http_hdr_lookup(&q->request_header, "Host") == NULL) {
        q->host_inserted = true;
        http_query_set_host(q);
    }

    /* Format HTTP request */
    str_trunc(q->rq_buf);
    q->rq_buf = str_append_printf(q->rq_buf, "%s %s HTTP/1.1\r\n",
        q->method, http_uri_get_path(q->uri));

    if (q->request_data != NULL) {
        char buf[64];
        sprintf(buf, "%zd", q->request_data->size);
        http_hdr_set(&q->request_header, "Content-Length", buf);
    }

    q->rq_buf = http_hdr_write(&q->request_header, q->rq_buf);

    if (q->request_data != NULL) {
        q->rq_buf = str_append_mem(q->rq_buf,
            q->request_data->bytes, q->request_data->size);
    }

    /* Connect to the host */
    http_query_connect(q, ERROR("no host addresses available"));
}

/* Submit the query.
 *
 * When query is finished, callback will be called. After return from
 * callback, memory, owned by http_query will be invalidated
 */
void
http_query_submit (http_query *q, void (*callback)(void *ptr, http_query *q))
{
    q->callback = callback;

    /* Issue log message, set timestamp and start timeout timer */
    log_debug(q->client->log, "HTTP %s %s", q->method, http_uri_str(q->uri));

    if (!q->submitted) {
        q->submitted = true;
        q->timestamp = timestamp_now();

        if (q->timeout_value >= 0) {
            http_query_timeout(q, q->timeout_value);
        }
    }

    /* Submit the query */
    log_assert(q->client->log, q->sock == -1);
    ll_push_end(&q->client->pending, &q->chain);

    q->eloop_callid = eloop_call(http_query_start_processing, q);
}

/* Cancel unfinished http_query. Callback will not be called and
 * memory owned by the http_query will be released
 */
static void
http_query_cancel (http_query *q)
{
    log_debug(q->client->log, "HTTP %s %s: Cancelled", q->method,
            http_uri_str(q->uri));

    ll_del(&q->chain);
    eloop_call_cancel(q->eloop_callid);

    http_query_free(q);
}

/* Get http_query timestamp. Timestamp is set when query is
 * submitted. And this function should not be called before
 * http_query_submit()
 */
timestamp
http_query_timestamp (const http_query *q)
{
    return q->timestamp;
}

/* Set uintptr_t parameter, associated with query.
 * Completion callback may later use http_query_get_uintptr()
 * to fetch this value
 */
void
http_query_set_uintptr (http_query *q, uintptr_t u)
{
    q->uintptr = u;
}

/* Get uintptr_t parameter, previously set by http_query_set_uintptr()
 */
uintptr_t
http_query_get_uintptr (http_query *q)
{
    return q->uintptr;
}

/* Get query error, if any
 *
 * Both transport errors and erroneous HTTP response codes
 * considered as errors here
 */
error
http_query_error (const http_query *q)
{
    if (q->err == NULL) {
        int status = http_query_status(q);

        if (200 <= status && status < 300) {
            return NULL;
        }
    }

    return ERROR(http_query_status_string(q));
}

/* Get query transport error, if any
 *
 * Only transport errors considered errors here
 */
error
http_query_transport_error (const http_query *q)
{
    return q->err;
}

/* Get HTTP status code. Code not available, if query finished
 * with transport error
 */
int
http_query_status (const http_query *q)
{
    log_assert(q->client->log, q->err == NULL);
    return q->http_parser.status_code;
}

/* Get HTTP status string
 */
const char*
http_query_status_string (const http_query *q)
{
    if (q->err != NULL) {
        return ESTRING(q->err);
    }

    return http_status_str(q->http_parser.status_code);
}

/* Get query URI
 *
 * It works as http_query_orig_uri() before query is submitted
 * or after it is completed, and as http_query_real_uri() in
 * between
 *
 * This function is deprecated, use http_query_orig_uri()
 * or http_query_real_uri() instead
 */
http_uri*
http_query_uri (const http_query *q)
{
    return q->uri;
}

/* Get original URI (the same as used when http_query was created)
 */
http_uri*
http_query_orig_uri (const http_query *q)
{
    return q->orig_uri ? q->orig_uri : q->uri;
}

/* Get real URI, that can differ from the requested URI
 * in a case of HTTP redirection
 */
http_uri*
http_query_real_uri (const http_query *q)
{
    return q->real_uri ? q->real_uri : q->uri;
}

/* Get query method
 */
const char*
http_query_method (const http_query *q)
{
    return q->method;
}

/* Set request header
 */
void
http_query_set_request_header (http_query *q, const char *name,
        const char *value)
{
    http_hdr_set(&q->request_header, name, value);
}

/* Get request header
 */
const char*
http_query_get_request_header (const http_query *q, const char *name)
{
    return http_hdr_get(&q->request_header, name);
}


/* Get response header
 */
const char*
http_query_get_response_header(const http_query *q, const char *name)
{
    return http_hdr_get(&q->response_header, name);
}

/* Get request data
 */
http_data*
http_query_get_request_data (const http_query *q)
{
    return q->request_data ? q->request_data : &http_data_empty;
}

/* Get request data
 */
http_data*
http_query_get_response_data (const http_query *q)
{
    return q->response_data ? q->response_data : &http_data_empty;
}

/* Get multipart response bodies. For non-multipart response
 * returns NULL
 */
static http_multipart*
http_query_get_mp_response (const http_query *q)
{
    return q->response_multipart;
}

/* Get count of parts of multipart response
 */
int
http_query_get_mp_response_count (const http_query *q)
{
    http_multipart *mp = http_query_get_mp_response(q);
    return mp ? mp->count : 0;
}

/* Get data of Nth part of multipart response
 */
http_data*
http_query_get_mp_response_data (const http_query *q, int n)
{
    http_multipart      *mp = http_query_get_mp_response(q);

    if (mp == NULL || n < 0 || n >= mp->count) {
        return NULL;
    }

    return mp->bodies[n];
}

/* Call callback for each request header
 */
void
http_query_foreach_request_header (const http_query *q,
        void (*callback)(const char *name, const char *value, void *ptr),
        void *ptr)
{
    hdr_for_each(&q->request_header, callback, ptr);
}

/* Call callback for each response header
 */
void
http_query_foreach_response_header (const http_query *q,
        void (*callback)(const char *name, const char *value, void *ptr),
        void *ptr)
{
    hdr_for_each(&q->response_header, callback, ptr);
}

/* Decode response part of the query.
 * This function is intended for testing purposes, not for regular use
 */
error
http_query_test_decode_response (http_query *q, const void *data, size_t size)
{
    http_parser_execute(&q->http_parser, &http_query_callbacks, data, size);
    if (q->http_parser.http_errno == HPE_OK && !q->http_parser_done) {
        http_parser_execute(&q->http_parser, &http_query_callbacks, data, 0);
    }

    if (q->http_parser.http_errno != HPE_OK) {
        if (q->err != NULL) {
            return q->err;
        }
        return ERROR(http_errno_description(q->http_parser.http_errno));
    }

    if (!q->http_parser_done) {
        return ERROR("truncated response");
    }

    return NULL;
}

/******************** HTTP initialization & cleanup ********************/
/* Initialize HTTP client
 */
SANE_Status
http_init (void)
{
    int rc = gnutls_certificate_allocate_credentials(&gnutls_cred);
    return rc == GNUTLS_E_SUCCESS ? SANE_STATUS_GOOD : SANE_STATUS_NO_MEM;
}

/* Initialize HTTP client
 */
void
http_cleanup (void)
{
    if (gnutls_cred != NULL) {
        gnutls_certificate_free_credentials(gnutls_cred);
        gnutls_cred = NULL;
    }
}

/* vim:ts=8:sw=4:et
 */
