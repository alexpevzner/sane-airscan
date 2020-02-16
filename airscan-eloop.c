/* AirScan (a.k.a. eSCL) backend for SANE
 *
 * Copyright (C) 2019 and up by Alexander Pevzner (pzz@apevzner.com)
 * See LICENSE for license terms and conditions
 *
 * Event loop (runs in separate thread)
 */

#include "airscan.h"

#include <glib-unix.h>

/* Limits */
#define ELOOP_START_STOP_CALLBACKS_MAX  8

/* Static variables
 */
static GThread *eloop_thread;
static GMainContext *eloop_glib_main_context;
static GMainLoop *eloop_glib_main_loop;
static char *eloop_estring = NULL;
static void (*eloop_start_stop_callbacks[ELOOP_START_STOP_CALLBACKS_MAX]) (bool);
static int eloop_start_stop_callbacks_count;
G_LOCK_DEFINE_STATIC(eloop_mutex);

/* Forward declarations
 */
static gint
glib_poll_hook (GPollFD *ufds, guint nfsd, gint timeout);

/* Initialize event loop
 */
SANE_Status
eloop_init (void)
{
    eloop_glib_main_context = g_main_context_new();
    eloop_glib_main_loop = g_main_loop_new(eloop_glib_main_context, FALSE);
    g_main_context_set_poll_func(eloop_glib_main_context, glib_poll_hook);
    eloop_start_stop_callbacks_count = 0;

    return SANE_STATUS_GOOD;
}

/* Cleanup event loop
 */
void
eloop_cleanup (void)
{
    if (eloop_glib_main_context != NULL) {
        g_main_loop_unref(eloop_glib_main_loop);
        eloop_glib_main_loop = NULL;
        g_main_context_unref(eloop_glib_main_context);
        eloop_glib_main_context = NULL;
        g_free(eloop_estring);
        eloop_estring = NULL;
    }
}

/* Add start/stop callback. This callback is called
 * on a event loop thread context, once when event
 * loop is started, and second time when it is stopped
 *
 * Start callbacks are called in the same order as
 * they were added. Stop callbacks are called in a
 * reverse order
 */
void
eloop_add_start_stop_callback (void (*callback) (bool start))
{
    log_assert(NULL,
            eloop_start_stop_callbacks_count < ELOOP_START_STOP_CALLBACKS_MAX);

    eloop_start_stop_callbacks[eloop_start_stop_callbacks_count] = callback;
    eloop_start_stop_callbacks_count ++;
}

/* Poll function hook
 */
static gint
glib_poll_hook (GPollFD *ufds, guint nfds, gint timeout)
{
    G_UNLOCK(eloop_mutex);
    gint ret = g_poll(ufds, nfds, timeout);
    G_LOCK(eloop_mutex);

    return ret;
}

/* Event loop thread main function
 */
static gpointer
eloop_thread_func (gpointer data)
{
    int i;

    (void) data;

    G_LOCK(eloop_mutex);

    g_main_context_push_thread_default(eloop_glib_main_context);

    for (i = 0; i < eloop_start_stop_callbacks_count; i ++) {
        eloop_start_stop_callbacks[i](true);
    }

    g_main_loop_run(eloop_glib_main_loop);

    for (i = eloop_start_stop_callbacks_count - 1; i >= 0; i --) {
        eloop_start_stop_callbacks[i](false);
    }

    G_UNLOCK(eloop_mutex);

    return NULL;
}

/* Start event loop thread.
 *
 * Callback is called from the thread context twice:
 *     callback(true)  - when thread is started
 *     callback(false) - when thread is about to exit
 */
void
eloop_thread_start (void)
{
    eloop_thread = g_thread_new("airscan", eloop_thread_func, NULL);

    /* Wait until thread is started. Otherwise, g_main_loop_quit()
     * might not terminate the thread
     */
    gulong usec = 100;
    while (!g_main_loop_is_running(eloop_glib_main_loop)) {
        g_usleep(usec);
        usec += usec;
    }
}

/* Stop event loop thread and wait until its termination
 */
void
eloop_thread_stop (void)
{
    if (eloop_thread != NULL) {
        g_main_loop_quit(eloop_glib_main_loop);
        g_thread_join(eloop_thread);
        eloop_thread = NULL;
    }
}

/* Acquire event loop mutex
 */
void
eloop_mutex_lock (void)
{
    G_LOCK(eloop_mutex);
}

/* Release event loop mutex
 */
void
eloop_mutex_unlock (void)
{
    G_UNLOCK(eloop_mutex);
}

/* Wait on conditional variable under the event loop mutex
 */
void
eloop_cond_wait (GCond *cond)
{
    return g_cond_wait(cond, &G_LOCK_NAME(eloop_mutex));
}

/* eloop_cond_wait() with timeout
 */
bool
eloop_cond_wait_until (GCond *cond, gint64 timeout)
{
    return g_cond_wait_until(cond, &G_LOCK_NAME(eloop_mutex), timeout);
}

/* Create AvahiGLibPoll that runs in context of the event loop
 */
AvahiGLibPoll*
eloop_new_avahi_poll (void)
{
    return avahi_glib_poll_new(eloop_glib_main_context, G_PRIORITY_DEFAULT);
}

/* Call function on a context of event loop thread
 */
void
eloop_call (GSourceFunc func, gpointer data)
{
    GSource *source = g_idle_source_new ();
    g_source_set_priority(source, G_PRIORITY_DEFAULT);
    g_source_set_callback(source, func, data, NULL);
    g_source_attach(source, eloop_glib_main_context);
    g_source_unref(source);
}

/* Event notifier. Calls user-defined function on a context
 * of event loop thread, when event is triggered. This is
 * safe to trigger the event from a context of any thread
 * or even from a signal handler
 */
struct eloop_event {
    GSource  source;            /* Underlying GSource */
    pollable *p;                /* Underlying pollable event */
    void    (*callback)(void*); /* user-defined callback */
    void    *data;              /* callback's argument */
};

/* eloop_event GSource callback
 */
gboolean
eloop_event_callback (gpointer data)
{
    eloop_event *event = data;

    pollable_reset(event->p);
    event->callback(event->data);

    return G_SOURCE_CONTINUE;
}

/* eloop_event source dispatch function
 */
static gboolean
eloop_event_source_dispatch (GSource *source, GSourceFunc callback,
    gpointer data)
{
    (void) source;
    return callback(data);
}

/* Create new event notifier. May return NULL
 */
eloop_event*
eloop_event_new (void (*callback)(void *), void *data)
{
    eloop_event         *event;
    pollable            *p;
    static GSourceFuncs funcs = {
        .dispatch = eloop_event_source_dispatch,
    };

    p = pollable_new();
    if (p == NULL) {
        return NULL;
    }

    event = (eloop_event*) g_source_new(&funcs, sizeof(eloop_event));
    event->p = p;
    event->callback = callback;
    event->data = data;

    g_source_add_unix_fd(&event->source, pollable_get_fd(event->p), G_IO_IN);
    g_source_set_callback(&event->source, eloop_event_callback, event, NULL);
    g_source_attach(&event->source, eloop_glib_main_context);

    return event;
}

/* Destroy event notifier
 */
void
eloop_event_free (eloop_event *event)
{
    g_source_destroy(&event->source);
    pollable_free(event->p);
    g_source_unref(&event->source);
}

/* Trigger an event
 */
void
eloop_event_trigger (eloop_event *event)
{
    pollable_signal(event->p);
}

/* Timer. Calls user-defined function after a specified
 * interval
 */
struct eloop_timer {
    GSource *source;             /* Underlying GSource */
    void    (*callback)(void *); /* User callback */
    void    *data;               /* User data */
};

/* eloop_timer callback for GSource
 */
static gboolean
eloop_timer_callback (gpointer data)
{
    eloop_timer *timer = data;

    timer->callback(timer->data);
    eloop_timer_cancel(timer);

    return G_SOURCE_REMOVE;
}

/* Create new timer. Timeout is in milliseconds
 */
eloop_timer*
eloop_timer_new (int timeout, void (*callback)(void *), void *data)
{
    eloop_timer *timer = g_new0(eloop_timer, 1);

    timer->source = g_timeout_source_new(timeout);
    timer->callback = callback;
    timer->data = data;

    g_source_set_priority(timer->source, G_PRIORITY_DEFAULT);
    g_source_set_callback(timer->source, eloop_timer_callback, timer, NULL);
    g_source_attach(timer->source, eloop_glib_main_context);

    return timer;
}

/* Cancel a timer
 *
 * Caller SHOULD NOT cancel expired timer (timer with called
 * callback) -- this is done automatically
 */
void
eloop_timer_cancel (eloop_timer *timer)
{
    g_source_destroy(timer->source);
    g_source_unref(timer->source);
    g_free(timer);
}

/* eloop_fdpoll notifies user when file becomes
 * readable, writable or both, depending on its
 * event mask
 */
struct eloop_fdpoll {
    GSource           source;   /* Underlying GSource */
    int               fd;       /* Underlying file descriptor */
    gpointer          fd_tag;   /* Returned by g_source_add_unix_fd() */
    ELOOP_FDPOLL_MASK mask;     /* Mask of active events */
    void     (*callback)(       /* User-defined callback */
        int, void*, ELOOP_FDPOLL_MASK);
    void              *data;    /* Callback's data */
};

/* eloop_fdpoll GSource dispatch function
 */
static gboolean
eloop_fdpoll_source_dispatch (GSource *source, GSourceFunc callback,
    gpointer data)
{
    eloop_fdpoll      *fdpoll = (eloop_fdpoll*) source;
    guint             events = g_source_query_unix_fd(source, fdpoll->fd_tag);
    ELOOP_FDPOLL_MASK mask = 0;

    (void) callback;
    (void) data;

    if ((events & G_IO_IN) != 0) {
        mask |= ELOOP_FDPOLL_READ;
    }

    if ((events & G_IO_OUT) != 0) {
        mask |= ELOOP_FDPOLL_WRITE;
    }

    mask &= fdpoll->mask;
    if (mask != 0) {
        fdpoll->callback(fdpoll->fd, fdpoll->data, mask);
    }

    return G_SOURCE_CONTINUE;
}

/* Create eloop_fdpoll
 *
 * Callback will be called, when file will be ready for read/write/both,
 * depending on mask
 *
 * Initial mask value is 0, and it can be changed, using
 * eloop_fdpoll_set_mask() function
 */
eloop_fdpoll*
eloop_fdpoll_new (int fd,
        void (*callback) (int, void*, ELOOP_FDPOLL_MASK), void *data)
{
    eloop_fdpoll *fdpoll;
    static GSourceFuncs funcs = {
        .dispatch = eloop_fdpoll_source_dispatch
    };

    fdpoll = (eloop_fdpoll*) g_source_new(&funcs, sizeof(eloop_fdpoll));
    fdpoll->callback = callback;
    fdpoll->data = data;

    fdpoll->fd_tag = g_source_add_unix_fd(&fdpoll->source, fd, 0);
    g_source_attach(&fdpoll->source, eloop_glib_main_context);

    return fdpoll;
}

/* Destroy eloop_fdpoll
 */
void
eloop_fdpoll_free (eloop_fdpoll *fdpoll)
{
    g_source_destroy(&fdpoll->source);
    g_source_unref(&fdpoll->source);
}

/* Set eloop_fdpoll event mask
 */
void
eloop_fdpoll_set_mask (eloop_fdpoll *fdpoll, ELOOP_FDPOLL_MASK mask)
{
    if (fdpoll->mask != mask) {
        guint events = 0;

        if ((mask && ELOOP_FDPOLL_READ) != 0) {
            events |= G_IO_IN;
        }

        if ((mask && ELOOP_FDPOLL_WRITE) != 0) {
            events |= G_IO_OUT;
        }

        g_source_modify_unix_fd(&fdpoll->source, fdpoll->fd_tag, events);
    }
}

/* Format error string, as printf() does and save result
 * in the memory, owned by the event loop
 *
 * Caller should not free returned string. This is safe
 * to use the returned string as an argument to the
 * subsequent eloop_eprintf() call.
 *
 * The returned string remains valid until next call
 * to eloop_eprintf(), which makes it usable to
 * report errors up by the stack. However, it should
 * not be assumed, that the string will remain valid
 * on a next eloop roll, so don't save this string
 * anywhere, if you need to do so, create a copy!
 */
error
eloop_eprintf(const char *fmt, ...)
{
    gchar *estring;
    va_list ap;

    log_assert(NULL, g_thread_self() == eloop_thread);

    va_start(ap, fmt);
    estring = g_strdup_vprintf(fmt, ap);
    va_end(ap);

    g_free(eloop_estring);
    eloop_estring = estring;

    return ERROR(estring);
}

/* vim:ts=8:sw=4:et
 */
