/* AirScan (a.k.a. eSCL) backend for SANE
 *
 * Copyright (C) 2019 and up by Alexander Pevzner (pzz@apevzner.com)
 * See LICENSE for license terms and conditions
 *
 * Pollable events
 */

#include "airscan.h"

#ifdef OS_HAVE_EVENTFD
#include <sys/eventfd.h>
#endif
#include <poll.h>
#include <unistd.h>
#include <fcntl.h>

#pragma GCC diagnostic ignored "-Wunused-result"

/* The pollable event
 */
struct pollable {
    int efd; /* Underlying eventfd handle */
#ifndef OS_HAVE_EVENTFD
    // Without eventfd we use a pipe, so we need a second fd.
    int write_fd;
#endif
};

/* Create new pollable event
 */
pollable*
pollable_new (void)
{
#ifdef OS_HAVE_EVENTFD
    int efd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
#else
    int fds[2];
    int r = pipe2(fds, O_CLOEXEC | O_NONBLOCK);
    int efd = r < 0 ? r : fds[0];
#endif
    if (efd< 0) {
        return NULL;
    }

    pollable *p = mem_new(pollable, 1);
    p->efd = efd;
#ifndef OS_HAVE_EVENTFD
    p->write_fd = fds[1];
#endif

    return p;
}

/* Free pollable event
 */
void
pollable_free (pollable *p)
{
    close(p->efd);
#ifndef OS_HAVE_EVENTFD
    close(p->write_fd);
#endif
    mem_free(p);
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
#ifdef OS_HAVE_EVENTFD
    write(p->efd, &c, sizeof(c));
#else
    write(p->write_fd, &c, sizeof(c));
#endif
}

/* Make pollable event "not ready"
 */
void
pollable_reset (pollable *p)
{
    uint64_t unused;

    (void) read(p->efd, &unused, sizeof(unused));
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
