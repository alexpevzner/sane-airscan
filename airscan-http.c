/* AirScan (a.k.a. eSCL) backend for SANE
 *
 * Copyright (C) 2019 and up by Alexander Pevzner (pzz@apevzner.com)
 * See LICENSE for license terms and conditions
 *
 * HTTP Client
 */
#define _GNU_SOURCE
#include <string.h>

#include "airscan.h"

#include <arpa/inet.h>
#include <libsoup/soup.h>

/******************** Static variables ********************/
static SoupSession *http_session;
static http_query  *http_query_list;

/******************** Forward declarations ********************/
typedef struct http_multipart http_multipart;

/* http_data constructor, internal version
 */
static http_data*
http_data_new_internal(const void *bytes, size_t size,
    SoupBuffer *buf, http_multipart *mp);

static void
http_data_set_content_type (http_data *data, const char *content_type);

static void
http_query_cancel (http_query *q);

/******************** HTTP URI ********************/
/* Type http_uri represents HTTP URI
 */
struct http_uri {
    SoupURI *parsed; /* Parsed URI */
    char    *str;    /* URI string, computed on demand and cached here */
    union {          /* Host address, computed on demand and cached here */
        struct sockaddr     sockaddr;
        struct sockaddr_in  in;
        struct sockaddr_in6 in6;
    } addr;
};

/* Create new URI, by parsing URI string
 */
http_uri*
http_uri_new (const char *str, bool strip_fragment)
{
    http_uri *uri = NULL;
    SoupURI  *parsed = soup_uri_new(str);

    /* Allow only http and https schemes */
    if (parsed != NULL) {
        if (strcmp(parsed->scheme, "http") && strcmp(parsed->scheme, "https")) {
            soup_uri_free(parsed);
            parsed = NULL;
        }
    }

    if (parsed != NULL) {
        uri = g_new0(http_uri, 1);
        if (strip_fragment) {
            soup_uri_set_fragment(parsed, NULL);
        }
        uri->parsed = parsed;
        uri->addr.sockaddr.sa_family = AF_UNSPEC;
    }

    return uri;
}

/* Clone an URI
 */
http_uri*
http_uri_clone (const http_uri *old)
{
    http_uri *uri = g_new0(http_uri, 1);
    uri->parsed = soup_uri_copy(old->parsed);
    return uri;
}

/* Create URI, relative to base URI. If `path_only' is
 * true, scheme, host and port are taken from the
 * base URI
 */
http_uri*
http_uri_new_relative (const http_uri *base, const char *path,
        bool strip_fragment, bool path_only)
{
    http_uri *uri = NULL;
    SoupURI  *parsed = soup_uri_new_with_base(base->parsed, path);

    if (parsed != NULL) {
        uri = g_new0(http_uri, 1);
        if (path_only) {
            uri->parsed = soup_uri_copy(base->parsed);
            soup_uri_set_path(uri->parsed, soup_uri_get_path(parsed));
            soup_uri_free(parsed);
        } else {
            uri->parsed = parsed;
        }

        if (strip_fragment) {
            soup_uri_set_fragment(uri->parsed, NULL);
        }
    }

    return uri;
}

/* Free the URI
 */
void
http_uri_free (http_uri *uri)
{
    if (uri != NULL) {
        soup_uri_free(uri->parsed);
        g_free(uri->str);
        g_free(uri);
    }
}

/* Get URI string
 */
const char*
http_uri_str (http_uri *uri)
{
    if (uri->str == NULL) {
        uri->str = soup_uri_to_string(uri->parsed, FALSE);
    }

    return uri->str;
}

/* Get URI's host address. If Host address is not literal, returns NULL
 */
const struct sockaddr*
http_uri_addr (http_uri *uri)
{
    char    *host = uri->parsed->host;
    int     af;
    int     rc;

    /* Check cached address */
    if (uri->addr.sockaddr.sa_family != AF_UNSPEC) {
        return &uri->addr.sockaddr;
    }

    /* Try to parse */
    if (strchr(host, ':') != NULL) {
        /* Strip zone suffix */
        char *s = strchr(host, '%');
        if (s != NULL) {
            size_t sz = s - host;
            host = g_alloca(sz + 1);
            memcpy(host, uri->parsed->host, sz);
            host[sz] = '\0';
        }

        /* Parse address */
        af = AF_INET6;
        rc = inet_pton(AF_INET6, host, &uri->addr.in6.sin6_addr);
        uri->addr.in6.sin6_port = htons(uri->parsed->port);
    } else {
        af = AF_INET;
        rc = inet_pton(AF_INET, host, &uri->addr.in.sin_addr);
        uri->addr.in.sin_port = htons(uri->parsed->port);
    }

    if (rc == 1) {
        uri->addr.sockaddr.sa_family = af;
        return &uri->addr.sockaddr;
    }

    return NULL;
}

/* Get URI path
 */
const char*
http_uri_get_path (const http_uri *uri)
{
    return soup_uri_get_path(uri->parsed);
}

/* Set URI path
 */
void
http_uri_set_path (http_uri *uri, const char *path)
{
    soup_uri_set_path(uri->parsed, path);
    g_free(uri->str);
    uri->str = NULL;
}

/* Fix IPv6 address zone suffix
 */
void
http_uri_fix_ipv6_zone (http_uri *uri, int ifindex)
{
    struct in6_addr addr;
    char            *host = uri->parsed->host;

    if (!strchr(host, ':')) {
        return; /* Not IPv6 */
    }

    if (strchr(host, '%')) {
        return; /* Already has zone suffix */
    }

    if (inet_pton(AF_INET6, host, &addr) != 1) {
        return; /* Can't parse address */
    }

    if (addr.s6_addr[0] == 0xfe && (addr.s6_addr[1] & 0xc0) == 0x80) {
        char *s = g_alloca(strlen(host) + 64);
        sprintf(s, "%s%%%d", host, ifindex);
        soup_uri_set_host(uri->parsed, s);
        g_free(uri->str);
        uri->str = NULL;
    }
}

/* Strip zone suffix from literal IPv6 host address
 *
 * If address is not IPv6 or doesn't have zone suffix, it is
 * not changed
 */
void
http_uri_strip_zone_suffux (http_uri *uri)
{
    char            *host = uri->parsed->host;
    char            *suffix;

    /* Copy hostname to writable buffer */
    host = g_alloca(strlen(host) + 1);
    strcpy(host, uri->parsed->host);

    /* Is it IPv6 address? */
    if (!strchr(host, ':')) {
        return; /* Not IPv6 */
    }

    /* Check for zone suffix */
    suffix = strchr(host, '%');
    if (suffix == NULL) {
        return; /* Not IPv6 */
    }

    /* Strip zone suffix and update URI */
    *suffix = '\0';
    soup_uri_set_host(uri->parsed, host);
    g_free(uri->str);
    uri->str = NULL;
}

/* Make sure URI's path ends with the slash character
 */
void
http_uri_fix_end_slash (http_uri *uri)
{
    const char *path = http_uri_get_path(uri);
    if (!g_str_has_suffix(path, "/")) {
        size_t len = strlen(path);
        char *path2 = g_alloca(len + 2);
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
    return soup_uri_equal(uri1->parsed, uri2->parsed);
}

/******************** HTTP multipart ********************/
/* http_multipart represents a decoded multipart message
 */
struct http_multipart {
    volatile gint refcnt;   /* Reference counter */
    int           count;    /* Count of bodies */
    http_data     *data;    /* Response data */
    http_data     **bodies; /* Multipart bodies, var-size */
};

/* Add multipart body
 */
static void
http_multipart_add_body (http_multipart *mp, http_data *body) {
    /* Expand bodies array, if size is zero or reached power of two */
    if (!(mp->count & (mp->count - 1))) {
        int cap = mp->count ? mp->count * 2 : 4;
        mp->bodies = g_renew(http_data*, mp->bodies, cap);
    }

    /* Append new body */
    mp->bodies[mp->count ++] = body;
}

/* Find boundary within the multipart message data
 */
static const char*
http_multipart_find_boundary (const char *boundary, size_t boundary_len,
        const char *data, size_t size) {
    const char *found = memmem(data, size, boundary, boundary_len);

    if (found != NULL) {
        ptrdiff_t off = found - data;

        /* Boundary must be either at beginning or preceded by CR/LF */
        if (off == 0 || (off >= 2 && found[-2] == '\r' && found[-1] == '\n')) {
            return found;
        }
    }

    return NULL;
}

/* Adjust part of multipart message:
 *   1) skip header
 *   2) fetch content type
 */
static bool
http_multipart_adjust_part (http_data *part)
{
    const char         *split;
    SoupMessageHeaders *hdr;
    size_t              hdr_len;
    bool                hdr_ok;

    /* Locate end of headers */
    split = memmem(part->bytes, part->size, "\r\n\r\n", 4);
    if (split == NULL) {
        return false;
    }

    /* Parse headers and obtain content-type */
    hdr = soup_message_headers_new (SOUP_MESSAGE_HEADERS_MULTIPART);
    hdr_len = 4 + split - (char*) part->bytes;
    hdr_ok = soup_headers_parse(part->bytes, hdr_len - 2, hdr);

    if (hdr_ok) {
        const char *ct = soup_message_headers_get_content_type(hdr, NULL);
        http_data_set_content_type(part, ct);
    }

    soup_message_headers_free(hdr);
    if (!hdr_ok) {
        return false;
    }

    /* Cut of header */
    split += 4;
    part->size -= (split - (char*) part->bytes);
    part->bytes = split;

    part->size -= 2; /* CR/LF preceding next boundary */

    return true;
}

/* Ref http_multipart
 */
static http_multipart*
http_multipart_ref (http_multipart *mp)
{
    g_atomic_int_inc(&mp->refcnt);
    return mp;
}

/* Unref http_multipart
 */
static void
http_multipart_unref (http_multipart *mp)
{
    if (g_atomic_int_dec_and_test(&mp->refcnt)) {
        g_free(mp->bodies);
        http_data_unref(mp->data);
        g_free(mp);
    }
}

/* Create http_multipart
 */
static http_multipart*
http_multipart_new (SoupMessageHeaders *headers, http_data *data)
{
    http_multipart *mp;
    GHashTable     *params;
    const char     *boundary;
    size_t         boundary_len;
    const char     *data_beg, *data_end, *data_prev;
    int            i;

    /* Note, believe or not, but libsoup multipart parser is broken, so
     * we have to parse by hand
     */

    /* Check MIME type */
    if (strncmp(data->content_type, "multipart/", 10)) {
        return NULL;
    }

    /* Obtain boundary */
    if (!soup_message_headers_get_content_type(headers, &params)) {
        return NULL;
    }

    boundary = g_hash_table_lookup (params, "boundary");
    if (boundary) {
        char *s;

        boundary_len = strlen(boundary) + 2;
        s = g_alloca(boundary_len + 1);

        s[0] = '-';
        s[1] = '-';
        strcpy(s + 2, boundary);
        boundary = s;
    }
    g_hash_table_destroy(params);

    if (!boundary) {
        return NULL;
    }

    /* Create http_multipart structure */
    mp = g_new0(http_multipart, 1);
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
                http_data *body = http_data_new_internal(data_prev,
                    part - data_prev, NULL, mp);
                http_multipart_add_body(mp, body);

                if (!http_multipart_adjust_part(body)) {
                    goto ERROR;
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

    return mp;

    /* Error: cleanup and exit */
ERROR:
    http_multipart_ref(mp);
    for (i = 0; i < mp->count; i ++) {
        http_data_unref(mp->bodies[i]);
    }
    http_multipart_unref(mp);
    return NULL;
}

/******************** HTTP data ********************/
/* http_data + SoupBuffer
 */
typedef struct {
    http_data      data;    /* HTTP data */
    volatile gint  refcnt;  /* Reference counter */
    SoupBuffer     *buf;    /* Underlying SoupBuffer */
    http_multipart *mp;
} http_data_ex;

/* http_data constructor, internal version
 */
static http_data*
http_data_new_internal(const void *bytes, size_t size,
    SoupBuffer *buf, http_multipart *mp)
{
    http_data_ex *data_ex = g_new0(http_data_ex, 1);

    data_ex->data.bytes = bytes;
    data_ex->data.size = size;
    data_ex->refcnt = 1;
    data_ex->buf = buf;
    data_ex->mp = mp ? http_multipart_ref(mp) : NULL;

    return &data_ex->data;
}

/* Create http_data
 */
static http_data*
http_data_new (const char *content_type, SoupMessageBody *body)
{
    http_data  *data;
    char       *s;
    SoupBuffer *buf = soup_message_body_flatten(body);

    data = http_data_new_internal(buf->data, buf->length, buf, NULL);
    http_data_set_content_type(data, content_type);

    s = strchr(data->content_type, ';');
    if (s != NULL) {
        *s = '\0';
    }

    return data;
}

/* Set Content-type
 */
static void
http_data_set_content_type (http_data *data, const char *content_type)
{
    g_free((char*) data->content_type);
    data->content_type = g_strdup(content_type ? content_type : "text/plain");
}

/* Ref http_data
 */
http_data*
http_data_ref (http_data *data)
{
    http_data_ex *data_ex = OUTER_STRUCT(data, http_data_ex, data);
    g_atomic_int_inc(&data_ex->refcnt);
    return data;
}

/* Unref http_data
 */
void
http_data_unref (http_data *data)
{
    if (data != NULL) {
        http_data_ex *data_ex = OUTER_STRUCT(data, http_data_ex, data);
        if (g_atomic_int_dec_and_test(&data_ex->refcnt)) {
            if (data_ex->mp != NULL) {
                http_multipart_unref(data_ex->mp);
            } else if (data_ex->buf != NULL) {
                soup_buffer_free(data_ex->buf);
            }

            g_free((char*) data_ex->data.content_type);
            g_free(data_ex);
        }
    }
}

/******************** HTTP data queue ********************/
/* http_data_queue represents a queue of http_data items
 */
struct http_data_queue {
    GPtrArray *items; /* Underlying array of pointers */
};

/* Create new http_data_queue
 */
http_data_queue*
http_data_queue_new (void)
{
    http_data_queue *queue = g_new0(http_data_queue, 1);
    queue->items = g_ptr_array_new();
    return queue;
}

/* Destroy http_data_queue
 */
void
http_data_queue_free (http_data_queue *queue)
{
    http_data_queue_purge(queue);
    g_ptr_array_free(queue->items, TRUE);
    g_free(queue);
}

/* Push item into the http_data_queue.
 */
void
http_data_queue_push (http_data_queue *queue, http_data *data)
{
    g_ptr_array_add(queue->items, data);
}

/* Pull an item from the http_data_queue. Returns NULL if queue is empty
 */
http_data*
http_data_queue_pull (http_data_queue *queue)
{
    if (queue->items->len > 0) {
        return g_ptr_array_remove_index(queue->items, 0);
    }

    return NULL;
}

/* Get queue length
 */
int
http_data_queue_len (const http_data_queue *queue)
{
    return (int) queue->items->len;
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
    GPtrArray  *pending;   /* Pending queries */
    void       (*onerror)( /* Callback to be called on transport error */
            void *ptr, error err);
};

/* Create new http_client
 */
http_client*
http_client_new (log_ctx *log, void *ptr)
{
    http_client *client = g_new0(http_client, 1);
    client->ptr = ptr;
    client->log = log;
    client->pending = g_ptr_array_new();
    return client;
}

/* Destroy http_client
 */
void
http_client_free (http_client *client)
{
    log_assert(client->log, client->pending->len == 0);
    g_ptr_array_free(client->pending, TRUE);
    g_free(client);
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
    while (client->pending->len != 0) {
        http_query_cancel(client->pending->pdata[0]);
    }
}

/* Get count of pending queries
 */
int
http_client_num_pending (const http_client *client)
{
    return client->pending->len;
}

/******************** HTTP request handling ********************/
/* http_query_cached represents a cached data, computed
 * on demand and associated with the http_query. This cache
 * is mutable, even if http_query is not
 */
typedef struct {
    http_data      *request_data;        /* Request data */
    http_data      *response_data;       /* Response data */
    http_multipart *response_multipart;  /* Multipart response bodies */
} http_query_cached;

/* Type http_query represents HTTP query (both request and response)
 */
struct http_query {
    http_client       *client;                  /* Client that owns the query */
    http_uri          *uri;                     /* Query URI */
    SoupMessage       *msg;                     /* Underlying SOUP message */
    uintptr_t         uintptr;                  /* User-defined parameter */
    void              (*onerror) (void *ptr,    /* On-error callback */
                                error err);
    void              (*callback) (void *ptr,   /* Completion callback */
                                http_query *q);
    http_query_cached *cached;                  /* Cached data */
    http_query        *prev, *next;             /* In the http_query_list */
};

/* Insert http_query into http_query_list
 */
static inline void
http_query_list_ins (http_query *q)
{
    if (http_query_list == NULL) {
        http_query_list = q;
    } else {
        q->next = http_query_list;
        http_query_list->prev = q;
        http_query_list = q;
    }
}

/* Delete http_query from http_query_list
 */
static inline void
http_query_list_del (http_query *q)
{
    if (q->next != NULL) {
        q->next->prev = q->prev;
    }

    if (q->prev != NULL) {
        q->prev->next = q->next;
    } else {
        http_query_list = q->next;
    }
}

/* Free http_query
 */
static void
http_query_free (http_query *q)
{
    http_query_list_del(q);
    http_uri_free(q->uri);

    http_data_unref(q->cached->request_data);
    http_data_unref(q->cached->response_data);
    if (q->cached->response_multipart != NULL) {
        http_multipart_unref(q->cached->response_multipart);
    }

    g_free(q->cached);
    g_free(q);
}

/* soup_session_queue_message callback
 */
static void
http_query_callback (SoupSession *session, SoupMessage *msg, gpointer userdata)
{
    http_query  *q = userdata;
    http_client *client = q->client;

    (void) session;

    if (msg->status_code != SOUP_STATUS_CANCELLED) {
        error  err = http_query_transport_error(q);

        log_assert(client->log, g_ptr_array_find(client->pending, q, NULL));
        g_ptr_array_remove(client->pending, q);

        if (err != NULL) {
            log_debug(client->log, "HTTP %s %s: %s", q->msg->method,
                    http_uri_str(q->uri),
                    soup_status_get_phrase(msg->status_code));
        } else {
            log_debug(client->log, "HTTP %s %s: %d %s", q->msg->method,
                    http_uri_str(q->uri),
                    msg->status_code,
                    soup_status_get_phrase(msg->status_code));
        }

        trace_http_query_hook(log_ctx_trace(client->log), q);

        if (err != NULL && q->onerror != NULL) {
            q->onerror(client->ptr, err);
        } else if (q->callback != NULL) {
            q->callback(client->ptr, q);
        }

        http_query_free(q);
    }
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
        ip_straddr s = ip_straddr_from_sockaddr(addr);
        soup_message_headers_replace(q->msg->request_headers, "Host", s.text);
        return;
    }

    host = strstr(http_uri_str(q->uri), "//") + 2;
    end = strchr(host, '/');

    len = end - host;
    buf = g_alloca(len + 1);
    memcpy(buf, host, len);

    buf[len] = '\0';

    soup_message_headers_replace(q->msg->request_headers, "Host", buf);
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
    http_query *q = g_new0(http_query, 1);

    g_ptr_array_add(client->pending, q);

    q->client = client;
    q->uri = uri;
    q->msg = soup_message_new_from_uri(method, uri->parsed);
    q->cached = g_new0(http_query_cached, 1);
    q->onerror = client->onerror;

    if (body != NULL) {
        soup_message_set_request(q->msg, content_type, SOUP_MEMORY_TAKE,
                body, strlen(body));
    }

    http_query_list_ins(q);

    /* Build and set Host: header */
    http_query_set_host(q);

    /* Note, on Kyocera ECOSYS M2040dn connection keep-alive causes
     * scanned job to remain in "Processing" state about 10 seconds
     * after job has been actually completed, making scanner effectively
     * busy.
     *
     * Looks like Kyocera firmware bug. Force connection to close
     * as a workaround
     */
    soup_message_headers_replace(q->msg->request_headers, "Connection", "close");

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
    return http_query_new(client, uri, method, body, content_type);
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

/* Submit the query.
 *
 * When query is finished, callback will be called. After return from
 * callback, memory, owned by http_query will be invalidated
 */
void
http_query_submit (http_query *q, void (*callback)(void *ptr, http_query *q))
{
    q->callback = callback;

    log_debug(q->client->log, "HTTP %s %s", q->msg->method, http_uri_str(q->uri));

    soup_session_queue_message(http_session, q->msg, http_query_callback, q);
}

/* Cancel unfinished http_query. Callback will not be called and
 * memory owned by the http_query will be released
 */
static void
http_query_cancel (http_query *q)
{
    http_client *client = q->client;

    log_assert(client->log, g_ptr_array_find(client->pending, q, NULL));
    g_ptr_array_remove(client->pending, q);

    /* Note, if message processing already finished,
     * soup_session_cancel_message() will do literally nothing,
     * and in particular will not update message status,
     * but we rely on a fact that status of cancelled
     * messages is set properly
     */
    g_object_ref(q->msg);
    soup_session_cancel_message(http_session, q->msg, SOUP_STATUS_CANCELLED);
    soup_message_set_status(q->msg, SOUP_STATUS_CANCELLED);
    g_object_unref(q->msg);

    http_query_free(q);
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
    if (!SOUP_STATUS_IS_SUCCESSFUL(q->msg->status_code)) {
        return ERROR(soup_status_get_phrase(q->msg->status_code));
    }

    return NULL;
}

/* Get query transport error, if any
 *
 * Only transport errors considered errors here
 */
error
http_query_transport_error (const http_query *q)
{
    if (SOUP_STATUS_IS_TRANSPORT_ERROR(q->msg->status_code)) {
        return ERROR(soup_status_get_phrase(q->msg->status_code));
    }

    return NULL;
}

/* Get HTTP status code. Code not available, if query finished
 * with transport error
 */
int
http_query_status (const http_query *q)
{
    log_assert(q->client->log, !SOUP_STATUS_IS_TRANSPORT_ERROR(q->msg->status_code));

    return q->msg->status_code;
}

/* Get HTTP status string
 */
const char*
http_query_status_string (const http_query *q)
{
    return soup_status_get_phrase(http_query_status(q));
}

/* Get query URI
 */
http_uri*
http_query_uri (const http_query *q)
{
    return q->uri;
}

/* Get query method
 */
const char*
http_query_method (const http_query *q)
{
    return q->msg->method;
}

/* Set request header
 */
void
http_query_set_request_header (http_query *q, const char *name,
        const char *value)
{
    soup_message_headers_replace(q->msg->request_headers, name, value);
}

/* Get request header
 */
const char*
http_query_get_request_header (const http_query *q, const char *name)
{
    return soup_message_headers_get_one(q->msg->request_headers, name);
}


/* Get response header
 */
const char*
http_query_get_response_header(const http_query *q, const char *name)
{
    return soup_message_headers_get_one(q->msg->response_headers, name);
}

/* Get request data
 */
http_data*
http_query_get_request_data (const http_query *q)
{
    if (q->cached->request_data == NULL) {
        const char         *ct;
        SoupMessageHeaders *hdr = q->msg->request_headers;

        ct = soup_message_headers_get_content_type(hdr, NULL);
        q->cached->request_data = http_data_new(ct, q->msg->request_body);
    }

    return q->cached->request_data;
}

/* Get request data
 */
http_data*
http_query_get_response_data (const http_query *q)
{
    if (q->cached->response_data == NULL) {
        const char         *ct;
        SoupMessageHeaders *hdr = q->msg->response_headers;

        ct = soup_message_headers_get_content_type(hdr, NULL);
        q->cached->response_data = http_data_new(ct, q->msg->response_body);
    }

    return q->cached->response_data;
}

/* Get multipart response bodies. For non-multipart response
 * returns NULL
 */
static http_multipart*
http_query_get_mp_response (const http_query *q)
{
    if (q->cached->response_multipart == NULL) {
        q->cached->response_multipart = http_multipart_new(
            q->msg->response_headers,
            http_query_get_response_data(q));
    }

    return q->cached->response_multipart;
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
    soup_message_headers_foreach(q->msg->request_headers, callback, ptr);
}

/* Call callback for each response header
 */
void
http_query_foreach_response_header (const http_query *q,
        void (*callback)(const char *name, const char *value, void *ptr),
        void *ptr)
{
    soup_message_headers_foreach(q->msg->response_headers, callback, ptr);
}

/******************** HTTP initialization & cleanup ********************/
/* Start/stop HTTP client
 */
static void
http_start_stop (bool start)
{
    if (start) {
        GValue val = G_VALUE_INIT;

        http_session = soup_session_new();

        g_value_init(&val, G_TYPE_BOOLEAN);
        g_value_set_boolean(&val, false);

        g_object_set_property(G_OBJECT(http_session),
            SOUP_SESSION_SSL_USE_SYSTEM_CA_FILE, &val);

        g_object_set_property(G_OBJECT(http_session),
            SOUP_SESSION_SSL_STRICT, &val);
    } else {
        soup_session_abort(http_session);
        g_object_unref(http_session);
        http_session = NULL;

        /* Note, soup_session_abort() may leave some requests
         * pending, so we must free them here explicitly
         */
        while (http_query_list != NULL) {
            http_query_free(http_query_list);
        }
    }
}

/* Initialize HTTP client
 */
SANE_Status
http_init (void)
{
    eloop_add_start_stop_callback(http_start_stop);
    return SANE_STATUS_GOOD;
}

/* Initialize HTTP client
 */
void
http_cleanup (void)
{
}

/* vim:ts=8:sw=4:et
 */
