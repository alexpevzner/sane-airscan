/* AirScan (a.k.a. eSCL) backend for SANE
 *
 * Copyright (C) 2019 and up by Alexander Pevzner (pzz@apevzner.com)
 * See LICENSE for license terms and conditions
 *
 * HTTP Client
 */

#include "airscan.h"

#include <libsoup/soup.h>
#include <string.h>

/******************** Static variables ********************/
static SoupSession *http_session;
static http_query  *http_query_list;

/******************** Forward declarations ********************/
typedef struct http_multipart http_multipart;

static http_data*
http_data_new_from_buf (const char *content_type,
        SoupBuffer *buf, http_multipart *mp);

static void
http_query_cancel (http_query *q);

/******************** HTTP URI ********************/
/* Type http_uri represents HTTP URI
 */
struct http_uri {
    SoupURI *parsed; /* Parsed URI */
    char    *str;    /* URI string */
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

/******************** HTTP multipart ********************/
/* http_multipart represents a decoded multipart message
 */
struct http_multipart {
    volatile gint refcnt;     /* Reference counter */
    SoupMultipart *multipart; /* Underlying SoupMultipart */
    int           count;      /* Count of bodies */
    http_data     *bodies[1]; /* Multipart bodies, var-size */
};

/* Create http_multipart
 */
static http_multipart*
http_multipart_new (SoupMessageHeaders *headers, SoupMessageBody *body)
{
    SoupMultipart        *multipart;
    int                  i, count;
    http_multipart       *mp;

    multipart = soup_multipart_new_from_message(headers, body);

    if (multipart == NULL) {
        return NULL;
    }

    count = soup_multipart_get_length(multipart);
    if (count == 0) {
        soup_multipart_free(multipart);
        return NULL;
    }

    mp = g_malloc0(offsetof(http_multipart, bodies[count]));

    mp->refcnt = 0; /* Refered by bodies */
    mp->multipart = multipart;
    mp->count = count;

    for (i = 0; i < count; i ++) {
        SoupMessageHeaders  *hdr;
        SoupBuffer          *buf;
        const char          *ct;

        ct = soup_message_headers_get_content_type(hdr, NULL);

        soup_multipart_get_part(multipart, i, &hdr, &buf);
        mp->bodies[i] = http_data_new_from_buf(ct, buf, mp);
    }

    return mp;
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
        soup_multipart_free(mp->multipart);
        g_free(mp);
    }
}

/******************** HTTP data ********************/
/* http_data + SoupBuffer
 */
typedef struct {
    http_data      data;    /* HTTP data */
    volatile gint  refcnt;  /* Reference counter */
    SoupBuffer     *buf;    /* Underlying SoupBuffer */
    http_multipart *mp;     /* Multipart that owns the SoupBuffer, if any */
} http_data_ex;

/* Create http_data from SoupBuffer
 */
static http_data*
http_data_new_from_buf (const char *content_type,
        SoupBuffer *buf, http_multipart *mp)
{
    http_data_ex *data_ex = g_new0(http_data_ex, 1);
    char         *s;

    if (content_type == NULL) {
        content_type = "text/plain";
    }

    data_ex->refcnt = 1;
    data_ex->buf = buf;
    data_ex->mp = mp ? http_multipart_ref(mp) : NULL;

    data_ex->data.content_type = g_strdup(content_type);
    data_ex->data.bytes = data_ex->buf->data;
    data_ex->data.size = data_ex->buf->length;

    s = strchr(data_ex->data.content_type, ';');
    if (s != NULL) {
        *s = '\0';
    }

    return &data_ex->data;
}

/* Create http_data
 */
static http_data*
http_data_new (const char *content_type, SoupMessageBody *body)
{
    return http_data_new_from_buf(content_type,
        soup_message_body_flatten(body), NULL);
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
            } else {
                soup_buffer_free(data_ex->buf);
            }

            g_free(data_ex);
        }
    }
}

/******************** HTTP client ********************/
/* Type http_client represents HTTP client instance
 */
struct http_client {
    void       *dev;       /* Device that owns the client */
    http_query *query;     /* Current http_query, if any */
    void       (*onerror)( /* Callback to be called on transport error */
            device *dev, error err);
};

/* Create new http_client
 */
http_client*
http_client_new (device *dev)
{
    http_client *client = g_new0(http_client, 1);
    client->dev = dev;
    return client;
}

/* Destroy http_client
 */
void
http_client_free (http_client *client)
{
    log_assert(client->dev, client->query == NULL);
    g_free(client);
}

/* Set on-error callback. If this callback is not NULL,
 * in a case of transport error it will be called instead
 * of the http_query callback
 */
void
http_client_onerror (http_client *client,
        void (*callback)(device *dev, error err))
{
    client->onerror = callback;
}

/* Cancel pending http_query, if any
 */
void
http_client_cancel (http_client *client)
{
    if (client->query) {
        http_query_cancel(client->query);
        client->query = NULL;
    }
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
    void              (*callback) (device *dev, /* Completion callback */
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
    http_query *q = userdata;

    (void) session;

    if (msg->status_code != SOUP_STATUS_CANCELLED) {
        device *dev = q->client->dev;
        error  err = http_query_transport_error(q);

        log_assert(q->client->dev, q->client->query == q);
        q->client->query = NULL;

        log_debug(dev, "HTTP %s %s: %s", q->msg->method,
                http_uri_str(q->uri),
                soup_status_get_phrase(msg->status_code));

        trace_http_query_hook(device_trace(dev), q);

        if (err != NULL && q->client->onerror != NULL) {
            q->client->onerror(dev, err);
        } else if (q->callback != NULL) {
            q->callback(dev, q);
        }

        http_query_free(q);
    }
}

/* Set Host header in HTTP request
 */
static void
http_query_set_host (http_query *q)
{
    char       *host, *end, *buf;
    size_t     len;

    host = strstr(http_uri_str(q->uri), "//") + 2;
    end = strchr(host, '/');

    len = end - host;
    buf = g_alloca(len + 1);
    memcpy(buf, host, len);

    buf[len] = '\0';
    soup_message_headers_append(q->msg->request_headers, "Host", buf);
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

    log_assert(client->dev, client->query == NULL);
    client->query = q;

    q->client = client;
    q->uri = uri;
    q->msg = soup_message_new_from_uri(method, uri->parsed);
    q->cached = g_new0(http_query_cached, 1);

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
    soup_message_headers_append(q->msg->request_headers, "Connection", "close");

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

/* Submit the query.
 *
 * When query is finished, callback will be called. After return from
 * callback, memory, owned by http_query will be invalidated
 */
void
http_query_submit (http_query *q, void (*callback)(device *dev, http_query *q))
{
    q->callback = callback;

    log_debug(q->client->dev, "HTTP %s %s",
        q->msg->method, http_uri_str(q->uri));

    soup_session_queue_message(http_session, q->msg, http_query_callback, q);
}

/* Cancel unfinished http_query. Callback will not be called and
 * memory owned by the http_query will be released
 */
void
http_query_cancel (http_query *q)
{
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
    log_assert(q->client->dev,
        !SOUP_STATUS_IS_TRANSPORT_ERROR(q->msg->status_code));

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
            q->msg->response_headers, q->msg->response_body);
    }

    return q->cached->response_multipart;
}

/* Get count of parts of multipart response
 */
int
http_query_get_mp_response_count (const http_query *q)
{
    http_multipart *mp = http_query_get_mp_response(q);
    return mp ? soup_multipart_get_length(mp->multipart) : 0;
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
