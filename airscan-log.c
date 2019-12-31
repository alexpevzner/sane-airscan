/* AirScan (a.k.a. eSCL) backend for SANE
 *
 * Copyright (C) 2019 and up by Alexander Pevzner (pzz@apevzner.com)
 * See LICENSE for license terms and conditions
 *
 * Logging
 */

#include "airscan.h"

#include <time.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>

/* Static variables */
static GString *log_buffer;
static bool log_configured;
static uint64_t log_start_time;

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
    log_buffer = g_string_new(NULL);
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
    g_string_free(log_buffer, TRUE);
    log_buffer = NULL;
}

/* Flush buffered log to file
 */
static void
log_flush (void)
{
    int rc = write(1, log_buffer->str, log_buffer->len);
    (void) rc;
    g_string_truncate(log_buffer, 0);
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
        g_string_truncate(log_buffer, 0);
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

/* Write a log message
 */
static void
log_message (device *dev, bool force, const char *fmt, va_list ap)
{
    trace *t = dev ? device_trace(dev) : NULL;
    char  msg[4096];
    int   len = 0;
    bool  dont_log = log_configured && !conf.dbg_enabled && !force;

    /* If logs suppressed and trace not in use, we have nothing
     * to do */
    if ((t == NULL) && dont_log) {
        return;
    }

    /* Format a log message */
    if (dev != NULL) {
        len += sprintf(msg, "\"%.64s\": ", device_name(dev));
    }

    len += vsnprintf(msg + len, sizeof(msg) - len, fmt, ap);

    /* Write to log */
    if (!dont_log) {
        g_string_append(log_buffer, msg);
        g_string_append_c(log_buffer, '\n');

        if ((log_configured && conf.dbg_enabled) || force) {
            log_flush();
        }
    }

    /* Write to trace */
    if (t != NULL) {
        char prefix[64];
        log_fmt_time(prefix, sizeof(prefix));
        trace_printf(t, "%s: %s", prefix, msg);
    }
}

/* Write a debug message. If dev != NULL, message will
 * be written in a context of device.
 */
void
log_debug (device *dev, const char *fmt, ...)
{
    va_list      ap;
    va_start(ap, fmt);
    log_message(dev, false, fmt, ap);
    va_end(ap);
}

/* Write an error message and terminate a program.
 * If dev != NULL, message will be written in a context of device.
 */
void
log_panic (device *dev, const char *fmt, ...)
{
    va_list      ap;

    /* Note, log_buffer is not empty only if logger is not
     * configured yet, but there are pending debug messages.
     * At this case we discard these messages, but panic
     * message is written anyway
     */
    g_string_truncate(log_buffer, 0);

    va_start(ap, fmt);
    log_message(dev, true, fmt, ap);
    va_end(ap);
    abort();
}

/* vim:ts=8:sw=4:et
 */
