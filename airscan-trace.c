/* AirScan (a.k.a. eSCL) backend for SANE
 *
 * Copyright (C) 2019 and up by Alexander Pevzner (pzz@apevzner.com)
 * See LICENSE for license terms and conditions
 *
 * Protocol Trace
 */

#include "airscan.h"

/* Trace file handle
 */
struct  trace {
    FILE        *fp;
};

/* Initialize protocol trace. Called at backend initialization
 */
SANE_Status
trace_init (void)
{
    return SANE_STATUS_GOOD;
}

/* Cleanup protocol trace. Called at backend unload
 */
void
trace_cleanup (void)
{
}

/* Open protocol trace
 */
trace*
trace_open (const char *device_name)
{
    char  *path = g_strdup_printf("%s.log", device_name);
    trace *t = g_new0(trace, 1);

    t->fp = fopen(path, "w");
    g_free(path);

    if (t->fp == NULL) {
        g_free(t);
        t = NULL;
    }

    return t;
}

/* Close protocol trace
 */
void
trace_close (trace *t)
{
    if (t != NULL) {
        fclose(t->fp);
        g_free(t);
    }
}

/* soup_message_headers_foreach callback
 */
static void
trace_message_headers_foreach_callback (const char *name, const char *value,
        gpointer ptr)
{
    trace *t = ptr;
    fprintf(t->fp, "%s: %s\n", name, value);
}

/* Dump message body
 */
static void
trace_dump_body(trace *t, SoupMessageHeaders *hdrs, SoupMessageBody *body)
{
    SoupBuffer *buf = soup_message_body_flatten(body);
    const char *content_type = soup_message_headers_get_one(hdrs, "Content-Type");

    if (buf->length == 0) {
        goto DONE;
    }

    if (strncmp(content_type, "text/", 5)) {
        fprintf(t->fp, "%ld bytes of data\n", buf->length);
    } else {
        const char *d, *end = buf->data + buf->length;
        int last = -1;

        for (d = buf->data; d < end; d ++) {
            if (*d != '\r') {
                last = *d;
                putc(last, t->fp);
            }
        }

        if (last != '\n') {
            putc('\n', t->fp);
        }
    }

    putc('\n', t->fp);

DONE:
    soup_buffer_free(buf);
}

/* This hook needs to be called from message
 * completion callback
 */
void
trace_msg_hook (trace *t, SoupMessage *msg)
{
    SoupURI *uri = soup_message_get_uri(msg);
    char *uri_str = soup_uri_to_string(uri, FALSE);

    fprintf(t->fp, "==============================\n");

    /* Dump request */
    fprintf(t->fp, "%s %s\n",  msg->method, uri_str);
    soup_message_headers_foreach(msg->request_headers,
            trace_message_headers_foreach_callback, t);
    fprintf(t->fp, "\n");
    trace_dump_body(t, msg->request_headers, msg->request_body);

    /* Dump response */
    fprintf(t->fp, "Status: %d %s\n", msg->status_code,
            soup_status_get_phrase(msg->status_code));
    soup_message_headers_foreach(msg->response_headers,
        trace_message_headers_foreach_callback, t);
    fprintf(t->fp, "\n");
    trace_dump_body(t, msg->response_headers, msg->response_body);

    g_free(uri_str);
}

/* vim:ts=8:sw=4:et
 */
