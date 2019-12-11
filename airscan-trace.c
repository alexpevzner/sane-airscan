/* AirScan (a.k.a. eSCL) backend for SANE
 *
 * Copyright (C) 2019 and up by Alexander Pevzner (pzz@apevzner.com)
 * See LICENSE for license terms and conditions
 *
 * Protocol Trace
 */

#include "airscan.h"

#include <limits.h>
#include <stdarg.h>
#include <unistd.h>

#pragma GCC diagnostic ignored "-Wformat-truncation"

/* Trace file handle
 */
struct  trace {
    FILE         *log;      /* Log file */
    FILE         *data;     /* Data file */
    unsigned int index;     /* Message index */
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

/* Name of the process' executable
 */
static char program[PATH_MAX];

/* Full block of zero bytes
 */
static const char zero_block[512];

/* Initialize protocol trace. Called at backend initialization
 */
SANE_Status
trace_init (void)
{
    ssize_t rc = readlink("/proc/self/exe", program, sizeof(program));
    if (rc < 0) {
        strcpy(program, "unknown");
    } else {
        char *s = strrchr(program, '/');
        if (s != NULL) {
            memmove(program, s+1, strlen(s+1) + 1);
        }
    }

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
    trace *t;
    char  path[PATH_MAX];
    size_t len;

    if (conf.dbg_trace == NULL) {
        return NULL;
    }

    g_mkdir_with_parents (conf.dbg_trace, 0755);
    t = g_new0(trace, 1);

    strcpy(path, conf.dbg_trace);
    len = strlen(path);
    strcat(path, program);
    strcat(path, "-");
    strcat(path, device_name);

    for (; path[len] != '\0'; len ++) {
        switch (path[len]) {
        case ' ':
        case '/':
            path[len] = '-';
            break;
        }
    }

    strcpy(path + len, ".log");
    t->log = fopen(path, "w");

    strcpy(path + len, ".tar");
    t->data = fopen(path, "wb");

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
            if (t->log != NULL) {
                /* Normal close - write tar footer */
                fwrite(zero_block, sizeof(zero_block), 1, t->data);
                fwrite(zero_block, sizeof(zero_block), 1, t->data);
            }
            fclose(t->data);
        }
        g_free(t);
    }
}

/* http_query_foreach_request_header()/http_query_foreach_response_header()
 * callback
 */
static void
trace_message_headers_foreach_callback (const char *name, const char *value,
        gpointer ptr)
{
    trace *t = ptr;
    fprintf(t->log, "%s: %s\n", name, value);
}

/* Dump binary data. The data saved as a file into a .TAR archive.
 * Returns name of file, where data was saved
 */
static void
trace_dump_data (trace *t, http_data *data, const char *content_type)
{
    tar_header hdr;
    guint32 chsum;
    size_t i;
    const char *ext;

    log_assert(NULL, sizeof(hdr) == 512);
    memset(&hdr, 0, sizeof(hdr));

    /* Guess file extension */
    ext = "";
    if (!strncmp(content_type, "image/", 6)) {
        ext = content_type + 6;
    } else if (!strncmp(content_type, "application/", 12)) {
        ext = content_type + 12;
    } else if (!strncmp(content_type, "text/", 5)) {
        ext = content_type + 5;
    }

    if (!*ext) {
        ext = "dat";
    }

    /* Make file name */
    sprintf(hdr.name, "%8.8d.%s", t->index, ext);

    /* Make tar header */
    strcpy(hdr.mode, "644");
    strcpy(hdr.uid, "0");
    strcpy(hdr.gid, "0");
    sprintf(hdr.size, "%lo", data->size);
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

    /* Write header and file data */
    fwrite(&hdr, sizeof(hdr), 1, t->data);
    fwrite(data->bytes, data->size, 1, t->data);

    /* Write padding */
    i = 512 - (data->size & (512-1));
    if (i != 0) {
        fwrite(zero_block, i, 1, t->data);
    }

    /* Put a note into the log file */
    fprintf(t->log, "%ld bytes of data saved as %s\n", data->size, hdr.name);
}

/* Dump text data. The data will be saved directly to the log file
 */
static void
trace_dump_text (trace *t, http_data *data, const char *content_type)
{
    const char *d, *end = (char*) data->bytes + data->size;
    int last = -1;

    (void) content_type;

    for (d = data->bytes; d < end; d ++) {
        if (*d != '\r') {
            last = *d;
            putc(last, t->log);
        }
    }

    if (last != '\n') {
        putc('\n', t->log);
    }
}

/* Dump message body
 */
static void
trace_dump_body (trace *t, http_data *data, const char *content_type)
{
    if (data->size == 0) {
        goto DONE;
    }

    if (content_type == NULL) {
        content_type = "";
    }

    if (!strncmp(content_type, "text/", 5)) {
        trace_dump_text(t, data, content_type);
    } else {
        trace_dump_data(t, data, content_type);
    }

    putc('\n', t->log);

DONE:
    ;
}

/* This hook is called on every http_query completion
 */
void
trace_http_query_hook (trace *t, http_query *q)
{
    error err;

    if (t != NULL) {
        fprintf(t->log, "==============================\n");

        /* Dump request */
        fprintf(t->log, "%s %s\n", http_query_method(q),
                http_uri_str(http_query_uri(q)));
        http_query_foreach_request_header(q,
                trace_message_headers_foreach_callback, t);
        fprintf(t->log, "\n");
        trace_dump_body(t, http_query_get_request_data(q),
                http_query_get_request_header(q, "Content-Type"));

        /* Dump response */
        err = http_query_transport_error(q);
        if (err != NULL) {
            fprintf(t->log, "Error: %s\n", ESTRING(err));
        } else {
            fprintf(t->log, "Status: %d %s\n", http_query_status(q),
                    http_query_status_string(q));

            http_query_foreach_response_header(q,
                trace_message_headers_foreach_callback, t);
            fprintf(t->log, "\n");
            trace_dump_body(t, http_query_get_response_data(q),
                    http_query_get_response_header(q, "Content-Type"));
        }

        t->index ++;

        fflush(t->log);
        fflush(t->data);
    }
}

/* Printf to the trace log
 */
void
trace_printf (trace *t, const char *fmt, ...)
{
    if (t != NULL) {
        va_list ap;
        va_start(ap, fmt);
        vfprintf(t->log, fmt, ap);
        putc('\n', t->log);
        fflush(t->log);
        va_end(ap);
    }
}

/* Note an error in trace log
 */
void
trace_error (trace *t, error err)
{
    trace_printf(t, "---");
    trace_printf(t, "%s", ESTRING(err));
    trace_printf(t, "");
}

/* vim:ts=8:sw=4:et
 */
