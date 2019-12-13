/* AirScan (a.k.a. eSCL) backend for SANE
 *
 * Copyright (C) 2019 and up by Alexander Pevzner (pzz@apevzner.com)
 * See LICENSE for license terms and conditions
 *
 * Pollable events
 */

#include "airscan.h"

#include <sys/eventfd.h>
#include <poll.h>
#include <unistd.h>

#pragma GCC diagnostic ignored "-Wunused-result"

/* The pollable event
 */
struct pollable {
    int efd; /* Underlying eventfd handle */
};

/* Create new pollable event
 */
pollable*
pollable_new (void)
{
    int efd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    if (efd< 0) {
        return NULL;
    }

    pollable *p = g_new0(pollable, 1);
    p->efd = efd;

    return p;
}

/* Free pollable event
 */
void
pollable_free (pollable *p)
{
    close(p->efd);
    g_free(p);
}

/* Get file descriptor for poll()/select().
 */
int
pollable_get_fd (pollable *p)
{
    return p->efd;
}

/* Make pollable event "ready"
 */
void
pollable_signal (pollable *p)
{
    static uint64_t c = 1;
    write(p->efd, &c, sizeof(c));
}

/* Make pollable event "not ready"
 */
void
pollable_reset (pollable *p)
{
    uint64_t unused;

    read(p->efd, &unused, sizeof(unused));
}

/* Wait until pollable event is ready
 */
void
pollable_wait (pollable *p)
{
    int rc;

    do {
        struct pollfd pfd = {
            .fd = p->efd,
            .events = POLLIN,
            .revents = 0
        };
        rc = poll(&pfd, 1, -1);
    } while (rc < 1);
}

/* vim:ts=8:sw=4:et
 */
