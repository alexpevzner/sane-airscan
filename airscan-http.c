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
http_uri_new (const char *str)
{
    http_uri *uri = NULL;
    SoupURI  *parsed = soup_uri_new(str);

    if (parsed != NULL) {
        uri = g_new0(http_uri, 1);
        uri->parsed = parsed;
    }

    return uri;
}

/* Create URI, relative to base URI
 */
http_uri*
http_uri_new_relative (const http_uri *base, const char *path)
{
    http_uri *uri = NULL;
    SoupURI  *parsed = soup_uri_new_with_base(base->parsed, path);

    if (parsed != NULL) {
        uri = g_new0(http_uri, 1);
        uri->parsed = parsed;
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

/******************** HTTP data ********************/
/* http_data + SoupBuffer
 */
typedef struct {
    http_data     data;   /* HTTP data */
    volatile gint refcnt; /* Reference counter */
    SoupBuffer    *buf;   /* Underlying SoupBuffer */
} http_data_ex;

/* Create http_data
 */
static http_data*
http_data_new (SoupMessageBody *body)
{
    http_data_ex *data_ex = g_new0(http_data_ex, 1);

    data_ex->buf = soup_message_body_flatten(body);
    data_ex->refcnt = 1;
    data_ex->data.bytes = data_ex->buf->data;
    data_ex->data.size = data_ex->buf->length;

    return &data_ex->data;
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
            soup_buffer_free(data_ex->buf);
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
/* Type http_query represents HTTP query (both request and response)
 */
struct http_query {
    http_client *client;           /* Client that owns the query */
    http_uri    *uri;              /* Query URI */
    SoupMessage *msg;              /* Underlying SOUP message */
    void (*callback) (device *dev, /* Completion callback */
            http_query *q);
    http_data   *request_data;     /* Response data, cached */
    http_data   *response_data;    /* Response data, cached */
    http_query  *prev, *next;      /* Prev/next query in http_query_list */
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
    http_data_unref(q->request_data);
    http_data_unref(q->response_data);
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

/* Create new http_query
 *
 * Newly created http_query takes ownership on uri and body (if not NULL).
 * The method and content_type assumed to be constant strings.
 *
 * When query is finished, callback will be called. After return from
 * callback, memory, owned by http_query will be invalidated
 */
http_query*
http_query_new (http_client *client, http_uri *uri, const char *method,
        char *body, const char *content_type,
        void (*callback)(device *dev, http_query *q))
{
    http_query *q = g_new0(http_query, 1);

    log_assert(client->dev, client->query == NULL);
    client->query = q;

    q->client = client;
    q->uri = uri;
    q->msg = soup_message_new_from_uri(method, uri->parsed);

    if (body != NULL) {
        soup_message_set_request(q->msg, content_type, SOUP_MEMORY_TAKE,
                body, strlen(body));
    }

    http_query_list_ins(q);

    /* Note, on Kyocera ECOSYS M2040dn connection keep-alive causes
     * scanned job to remain in "Processing" state about 10 seconds
     * after job has been actually completed, making scanner effectively
     * busy.
     *
     * Looks like Kyocera firmware bug. Force connection to close
     * as a workaround
     */
    soup_message_headers_append(q->msg->request_headers, "Connection", "close");
    q->callback = callback;

    log_debug(client->dev, "HTTP %s %s", q->msg->method, http_uri_str(q->uri));

    soup_session_queue_message(http_session, q->msg, http_query_callback, q);

    return q;
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
http_query_error (http_query *q)
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
http_query_transport_error (http_query *q)
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
http_query_status (http_query *q)
{
    log_assert(q->client->dev,
        !SOUP_STATUS_IS_TRANSPORT_ERROR(q->msg->status_code));

    return q->msg->status_code;
}

/* Get HTTP status string
 */
const char*
http_query_status_string (http_query *q)
{
    return soup_status_get_phrase(http_query_status(q));
}

/* Get query URI
 */
http_uri*
http_query_uri (http_query *q)
{
    return q->uri;
}

/* Get query method
 */
const char*
http_query_method (http_query *q)
{
    return q->msg->method;
}

/* Get request header
 */
const char*
http_query_get_request_header (http_query *q, const char *name)
{
    return soup_message_headers_get_one(q->msg->request_headers, name);
}


/* Get response header
 */
const char*
http_query_get_response_header(http_query *q, const char *name)
{
    return soup_message_headers_get_one(q->msg->response_headers, name);
}

/* Get request data
 */
http_data*
http_query_get_request_data (http_query *q)
{
    if (q->request_data == NULL) {
        q->request_data = http_data_new(q->msg->request_body);
    }

    return q->request_data;
}

/* Get request data
 */
http_data*
http_query_get_response_data (http_query *q)
{
    if (q->response_data == NULL) {
        q->response_data = http_data_new(q->msg->response_body);
    }

    return q->response_data;
}

/* Call callback for each request header
 */
void
http_query_foreach_request_header (http_query *q,
        void (*callback)(const char *name, const char *value, void *ptr),
        void *ptr)
{
    soup_message_headers_foreach(q->msg->request_headers, callback, ptr);
}

/* Call callback for each response header
 */
void
http_query_foreach_response_header (http_query *q,
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
