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
    FILE         *log;   /* Log file */
    FILE         *data;  /* Data file */
    unsigned int index;  /* Message index */
};

/* TAR file hader
 */
typedef struct {
    char name[100];
    char mode[8];
    char uid[8];
    char gid[8];
    char size[12];
    char mtime[12];
    char checksum[8];
    char typeflag[1];
    char linkname[100];
    char magic[6];
    char version[2];
    char uname[32];
    char gname[32];
    char devmajor[8];
    char devminor[8];
    char prefix[155];
    char pad[12];
} tar_header;

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
trace_cleanup ()
{
}

/* Open protocol trace
 */
trace*
trace_open (const char *device_name)
{
    trace *t = g_new0(trace, 1);
    char  *path;

    path = g_strdup_printf("%s.log", device_name);
    t->log = fopen(path, "w");
    g_free(path);

    path = g_strdup_printf("%s.tar", device_name);
    t->data = fopen(path, "wb");
    g_free(path);

    if (t->log != NULL && t->data != NULL) {
        return t;
    }

    trace_close(t);
    return NULL;
}

/* Close protocol trace
 */
void
trace_close (trace *t)
{
    if (t != NULL) {
        if (t->log != NULL) {
            fclose(t->log);
        }
        if (t->data != NULL) {
            fclose(t->data);
        }
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
    fprintf(t->log, "%s: %s\n", name, value);
}

/* Dump data
 */
static void
trace_dump_data (trace *t, SoupBuffer *buf)
{
    tar_header hdr;
    guint32 chsum;
    size_t i;
    static char pad[512];

    g_assert(sizeof(hdr) == 512);
    memset(&hdr, 0, sizeof(hdr));

    sprintf(hdr.name, "%8.8d", t->index ++);
    strcpy(hdr.mode, "644");
    strcpy(hdr.uid, "0");
    strcpy(hdr.gid, "0");
    sprintf(hdr.size, "%lo", buf->length);
    sprintf(hdr.mtime, "%lo", time(NULL));
    hdr.typeflag[0] = '0';
    strcpy(hdr.magic, "ustar");
    memcpy(hdr.version, "00", 2);
    strcpy(hdr.devmajor, "1");
    strcpy(hdr.devminor, "1");

    memset(hdr.checksum, ' ', sizeof(hdr.checksum));
    chsum = 0;
    for (i = 0; i < sizeof(hdr); i ++) {
        chsum += ((char*) &hdr)[i];
    }
    sprintf(hdr.checksum, "%6.6o", chsum & 0777777);

    fwrite(&hdr, sizeof(hdr), 1, t->data);
    fwrite(buf->data, buf->length, 1, t->data);

    i = 512 - (buf->length & (512-1));
    if (i != 0) {
        fwrite(pad, i, 1, t->data);
    }
}


/* Dump message body
 */
static void
trace_dump_body (trace *t, SoupMessageHeaders *hdrs, SoupMessageBody *body)
{
    SoupBuffer *buf = soup_message_body_flatten(body);
    const char *content_type = soup_message_headers_get_one(hdrs, "Content-Type");

    if (buf->length == 0) {
        goto DONE;
    }

    if (strncmp(content_type, "text/", 5)) {
        fprintf(t->log, "%ld bytes of data\n", buf->length);
        trace_dump_data(t, buf);
    } else {
        const char *d, *end = buf->data + buf->length;
        int last = -1;

        for (d = buf->data; d < end; d ++) {
            if (*d != '\r') {
                last = *d;
                putc(last, t->log);
            }
        }

        if (last != '\n') {
            putc('\n', t->log);
        }
    }

    putc('\n', t->log);

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

    fprintf(t->log, "==============================\n");

    /* Dump request */
    fprintf(t->log, "%s %s\n",  msg->method, uri_str);
    soup_message_headers_foreach(msg->request_headers,
            trace_message_headers_foreach_callback, t);
    fprintf(t->log, "\n");
    trace_dump_body(t, msg->request_headers, msg->request_body);

    /* Dump response */
    fprintf(t->log, "Status: %d %s\n", msg->status_code,
            soup_status_get_phrase(msg->status_code));
    soup_message_headers_foreach(msg->response_headers,
        trace_message_headers_foreach_callback, t);
    fprintf(t->log, "\n");
    trace_dump_body(t, msg->response_headers, msg->response_body);

    g_free(uri_str);
}

/* vim:ts=8:sw=4:et
 */
