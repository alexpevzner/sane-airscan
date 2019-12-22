/* AirScan (a.k.a. eSCL) backend for SANE
 *
 * Copyright (C) 2019 and up by Alexander Pevzner (pzz@apevzner.com)
 * See LICENSE for license terms and conditions
 *
 * Logging
 */

#include "airscan.h"

#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>

/* Static variables */
static GString *log_buffer;
static bool log_configured;

/* Initialize logging
 *
 * No log messages should be generated before this call
 */
void
log_init (void)
{
    log_buffer = g_string_new(NULL);
    log_configured = false;
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

/* Write a log message
 */
static void
log_message (device *dev, bool force, const char *fmt, va_list ap)
{
    if (log_configured && !conf.dbg_enabled) {
        return;
    }

    if (dev != NULL) {
        g_string_append_printf(log_buffer, "\"%.64s\": ", device_name(dev));
    }

    g_string_append_vprintf(log_buffer, fmt, ap);
    g_string_append_c(log_buffer, '\n');

    if ((log_configured && conf.dbg_enabled) || force) {
        log_flush();
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
