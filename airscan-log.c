/* AirScan (a.k.a. eSCL) backend for SANE
 *
 * Copyright (C) 2019 and up by Alexander Pevzner (pzz@apevzner.com)
 * See LICENSE for license terms and conditions
 *
 * Pollable events
 */

#include "airscan.h"

#include <stdarg.h>
#include <stdlib.h>
#include <sys/uio.h>

/* Write a log message
 */
static void
log_message (device *dev, const char *fmt, va_list ap)
{
    char         buf[1024];
    int          off = 0;
    struct iovec iov[3];

    if (dev != NULL) {
        off += snprintf(buf, 64, "%.64s: ", device_name(dev));
    }

    off += vsnprintf(buf, sizeof(buf) - off, fmt, ap);

    iov[0].iov_base = "airscan: ";
    iov[0].iov_len = strlen(iov[0].iov_base);
    iov[1].iov_base = buf;
    iov[1].iov_len = off;
    iov[2].iov_base = "\n";
    iov[2].iov_len = 1;

    writev(1, iov, 3);
}

/* Write a debug message. If dev != NULL, message will
 * be written in a context of device.
 */
void
log_debug (device *dev, const char *fmt, ...)
{
    va_list      ap;
    va_start(ap, fmt);
    log_message(dev, fmt, ap);
    va_end(ap);
}

/* Write an error message and terminate a program.
 * If dev != NULL, message will be written in a context of device.
 */
void
log_panic (device *dev, const char *fmt, ...)
{
    va_list      ap;
    va_start(ap, fmt);
    log_message(dev, fmt, ap);
    va_end(ap);
    abort();
}

/* vim:ts=8:sw=4:et
 */
