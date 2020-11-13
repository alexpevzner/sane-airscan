/* AirScan (a.k.a. eSCL) backend for SANE
 *
 * Copyright (C) 2019 and up by Alexander Pevzner (pzz@apevzner.com)
 * See LICENSE for license terms and conditions
 *
 * Logging
 */

#include "airscan.h"

#include <ctype.h>
#include <time.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>

/* Static variables */
static char *log_buffer;
static bool log_configured;
static uint64_t log_start_time;
static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Get time for logging purposes
 */
static uint64_t
log_get_time (void)
{
    struct timespec tms;

    clock_gettime(CLOCK_MONOTONIC, &tms);
    return ((uint64_t) tms.tv_nsec) + 1000000000 * (uint64_t) tms.tv_sec;
}

/* Initialize logging
 *
 * No log messages should be generated before this call
 */
void
log_init (void)
{
    log_buffer = str_new();
    log_configured = false;
    log_start_time = log_get_time();
}

/* Cleanup logging
 *
 * No log messages should be generated after this call
 */
void
log_cleanup (void)
{
    mem_free(log_buffer);
    log_buffer = NULL;
}

/* Flush buffered log to file
 */
static void
log_flush (void)
{
    int rc = write(1, log_buffer, mem_len(log_buffer));
    (void) rc;
    str_trunc(log_buffer);
}

/* Notify logger that configuration is loaded and
 * logger can configure itself
 *
 * This is safe to generate log messages before log_configure()
 * is called. These messages will be buffered, and after
 * logger is configured, either written or abandoned, depending
 * on configuration
 */
void
log_configure (void)
{
    log_configured = true;
    if (conf.dbg_enabled) {
        log_flush();
    } else {
        str_trunc(log_buffer);
    }
}

/* Format time elapsed since logging began
 */
static void
log_fmt_time (char *buf, size_t size)
{
    uint64_t t = log_get_time() - log_start_time;
    int      hour, min, sec, msec;

    sec = (int) (t / 1000000000);
    msec = ((int) (t % 1000000000)) / 1000000;
    hour = sec / 3600;
    sec = sec % 3600;
    min = sec / 60;
    sec = sec % 60;

    snprintf(buf, size, "%2.2d:%2.2d:%2.2d.%3.3d", hour, min, sec, msec);
}

/* log_ctx represents logging context
 */
struct log_ctx {
    const char *name;  /* Log name */
    trace      *trace; /* Associated trace */
};

/* log_ctx_new creates new logging context
 * If parent != NULL, new logging context will have its own prefix,
 * but trace file will be inherited from parent
 */
log_ctx*
log_ctx_new (const char *name, log_ctx *parent)
{
    log_ctx *log = mem_new(log_ctx, 1);

    log->name = str_trim(str_dup(name));

    if (parent != NULL) {
        log->trace = trace_ref(parent->trace);
    } else {
        log->trace = trace_open(name);
    }

    return log;
}

/* log_ctx_free destroys logging context
 */
void
log_ctx_free (log_ctx *log)
{
    trace_unref(log->trace);
    mem_free((char*) log->name);
    mem_free(log);
}

/* Get protocol trace associated with logging context
 */
trace*
log_ctx_trace (log_ctx *log)
{
    return log->trace;
}

/* Write a log message
 */
static void
log_message (log_ctx *log, bool trace_only, bool force,
        const char *fmt, va_list ap)
{
    trace *t = log ? log->trace : NULL;
    char  msg[4096];
    int   len = 0, namelen = 0, required_bytes = 0;
    bool  dont_log = trace_only ||
                     (log_configured && !conf.dbg_enabled && !force);

    /* If logs suppressed and trace not in use, we have nothing
     * to do */
    if ((t == NULL) && dont_log) {
        return;
    }

    /* Format a log message */
    if (log != NULL) {
        len += sprintf(msg, "%.64s: ", log->name);
        namelen = len;
    }

    required_bytes = vsnprintf(msg + len, sizeof(msg) - len, fmt, ap);

    /* vsnprintf returns the number of bytes required for the whole message,
     * even if that exceeds the buffer size.
     * If required_bytes exceeds space remaining in msg, we know msg is full.
     * Otherwise, we can increment len by required_bytes.
     */
    if (required_bytes >= (int) sizeof(msg) - len) {
        len = sizeof(msg) - 1;
    } else {
        len += required_bytes;
    }

    while (len > 0 && isspace((unsigned char) msg[len-1])) {
        len --;
    }

    msg[len] = '\0';

    /* Write to log */
    if (!dont_log) {
        pthread_mutex_lock(&log_mutex);

        log_buffer = str_append(log_buffer, msg);
        log_buffer = str_append_c(log_buffer, '\n');

        if ((log_configured && conf.dbg_enabled) || force) {
            log_flush();
        }

        pthread_mutex_unlock(&log_mutex);
    }

    /* Write to trace */
    if (t != NULL) {
        if (len > namelen) {
            char prefix[64];
            log_fmt_time(prefix, sizeof(prefix));
            trace_printf(t, "%s: %s", prefix, msg);
        } else {
            trace_printf(t, "");
        }
    }
}

/* Write a debug message.
 */
void
log_debug (log_ctx *log, const char *fmt, ...)
{
    va_list      ap;
    va_start(ap, fmt);
    log_message(log, false, false, fmt, ap);
    va_end(ap);
}

/* Write a protocol trace message
 */
void
log_trace (log_ctx *log, const char *fmt, ...)
{
    va_list      ap;
    va_start(ap, fmt);
    log_message(log, true, false, fmt, ap);
    va_end(ap);
}

/* Write a block of data into protocol trace
 */
void
log_trace_data (log_ctx *log, const char *content_type,
        const void *bytes, size_t size)
{
    http_data data = {
        .content_type = content_type,
        .bytes        = bytes,
        .size         = size
    };

    trace_dump_body(log->trace, &data);
}

/* Write an error message and terminate a program.
 */
void
log_panic (log_ctx *log, const char *fmt, ...)
{
    va_list      ap;

    /* Note, log_buffer is not empty only if logger is not
     * configured yet, but there are pending debug messages.
     * At this case we discard these messages, but panic
     * message is written anyway
     */
    pthread_mutex_lock(&log_mutex);
    str_trunc(log_buffer);
    pthread_mutex_unlock(&log_mutex);

    va_start(ap, fmt);
    log_message(log, false, true, fmt, ap);
    va_end(ap);
    abort();
}

/* vim:ts=8:sw=4:et
 */
