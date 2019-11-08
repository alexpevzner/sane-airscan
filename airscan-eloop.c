/* AirScan (a.k.a. eSCL) backend for SANE
 *
 * Copyright (C) 2019 and up by Alexander Pevzner (pzz@apevzner.com)
 * See LICENSE for license terms and conditions
 *
 * Event loop (runs in separate thread)
 */

#include "airscan.h"

/* Static variables
 */
static GThread *eloop_thread;
static GMainContext *eloop_glib_main_context;
static GMainLoop *eloop_glib_main_loop;
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
    }
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
    void (*callback)(gboolean) = data;

    G_LOCK(eloop_mutex);

    g_main_context_push_thread_default(eloop_glib_main_context);
    callback(TRUE);
    g_main_loop_run(eloop_glib_main_loop);
    callback(FALSE);

    G_UNLOCK(eloop_mutex);

    return NULL;
}

/* Start event loop thread.
 *
 * Callback is called from the thread context twice:
 *     callback(TRUE)  - when thread is started
 *     callback(FALSE) - when thread is about to exit
 */
void
eloop_thread_start (void (*callback)(gboolean))
{
    eloop_thread = g_thread_new("airscan", eloop_thread_func, callback);

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
gboolean
eloop_cond_wait (GCond *cond, gint64 timeout)
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

/* vim:ts=8:sw=4:et
 */
