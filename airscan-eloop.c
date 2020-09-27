/* AirScan (a.k.a. eSCL) backend for SANE
 *
 * Copyright (C) 2019 and up by Alexander Pevzner (pzz@apevzner.com)
 * See LICENSE for license terms and conditions
 *
 * Event loop (runs in separate thread)
 */

#include "airscan.h"

#include <avahi-common/simple-watch.h>
#include <avahi-common/timeval.h>

#include <errno.h>
#include <unistd.h>

/******************** Constants *********************/
#define ELOOP_START_STOP_CALLBACKS_MAX  8

/******************** Static variables *********************/
static AvahiSimplePoll *eloop_poll;
static pthread_t eloop_thread;
static pthread_mutex_t eloop_mutex;
static bool eloop_thread_running;
static ll_head eloop_call_pending_list;
static bool eloop_poll_restart;

static __thread char eloop_estring[256];
static void (*eloop_start_stop_callbacks[ELOOP_START_STOP_CALLBACKS_MAX]) (bool);
static int eloop_start_stop_callbacks_count;

/******************** Standard errors *********************/
error ERROR_ENOMEM = (error) "Out of memory";

/******************** Forward declarations *********************/
static int
eloop_poll_func (struct pollfd *ufds, unsigned int nfds, int timeout, void *p);

static void
eloop_call_execute (void);

/* Initialize event loop
 */
SANE_Status
eloop_init (void)
{
    pthread_mutexattr_t attr;
    bool                attr_initialized = false;
    bool                mutex_initialized = false;
    SANE_Status         status = SANE_STATUS_NO_MEM;

    ll_init(&eloop_call_pending_list);
    eloop_start_stop_callbacks_count = 0;

    /* Initialize eloop_mutex */
    if (pthread_mutexattr_init(&attr)) {
        goto DONE;
    }

    attr_initialized = true;
    if (pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE)) {
        goto DONE;
    }

    if (pthread_mutex_init(&eloop_mutex, &attr)) {
        goto DONE;
    }

    mutex_initialized = true;

    /* Create AvahiSimplePoll */
    eloop_poll = avahi_simple_poll_new();
    if (eloop_poll == NULL) {
        goto DONE;
    }

    avahi_simple_poll_set_func(eloop_poll, eloop_poll_func, NULL);

    /* Update status */
    status = SANE_STATUS_GOOD;

    /* Cleanup and exit */
DONE:
    if (attr_initialized) {
        pthread_mutexattr_destroy(&attr);
    }

    if (status != SANE_STATUS_GOOD && mutex_initialized) {
        pthread_mutex_destroy(&eloop_mutex);
    }

    return status;
}

/* Cleanup event loop
 */
void
eloop_cleanup (void)
{
    if (eloop_poll != NULL) {
        avahi_simple_poll_free(eloop_poll);
        pthread_mutex_destroy(&eloop_mutex);
        eloop_poll = NULL;
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
static int
eloop_poll_func (struct pollfd *ufds, unsigned int nfds, int timeout,
        void *userdata)
{
    int     rc;

    (void) userdata;

    eloop_poll_restart = false;

    pthread_mutex_unlock(&eloop_mutex);
    rc = poll(ufds, nfds, timeout);
    pthread_mutex_lock(&eloop_mutex);

    if (eloop_poll_restart) {
        errno = ERESTART;
        return -1;
    }

    return rc;
}

/* Event loop thread main function
 */
static void*
eloop_thread_func (void *data)
{
    int i;

    (void) data;

    pthread_mutex_lock(&eloop_mutex);

    for (i = 0; i < eloop_start_stop_callbacks_count; i ++) {
        eloop_start_stop_callbacks[i](true);
    }

    __atomic_store_n(&eloop_thread_running, true, __ATOMIC_SEQ_CST);

    do {
        eloop_call_execute();
        i = avahi_simple_poll_iterate(eloop_poll, -1);
    } while (i == 0 || (i < 0 && (errno == EINTR || errno == ERESTART)));

    for (i = eloop_start_stop_callbacks_count - 1; i >= 0; i --) {
        eloop_start_stop_callbacks[i](false);
    }

    pthread_mutex_unlock(&eloop_mutex);

    return NULL;
}

/* Start event loop thread.
 */
void
eloop_thread_start (void)
{
    int        rc;
    useconds_t usec = 100;

    rc = pthread_create(&eloop_thread, NULL, eloop_thread_func, NULL);
    if (rc != 0) {
        log_panic(NULL, "pthread_create: %s", strerror(rc));
    }

    /* Wait until thread is started and all start callbacks are executed */
    while (!__atomic_load_n(&eloop_thread_running, __ATOMIC_SEQ_CST)) {
        usleep(usec);
        usec += usec;
    }
}

/* Stop event loop thread and wait until its termination
 */
void
eloop_thread_stop (void)
{
    if (__atomic_load_n(&eloop_thread_running, __ATOMIC_SEQ_CST)) {
        avahi_simple_poll_quit(eloop_poll);
        pthread_join(eloop_thread, NULL);
        __atomic_store_n(&eloop_thread_running, false, __ATOMIC_SEQ_CST);
    }
}

/* Acquire event loop mutex
 */
void
eloop_mutex_lock (void)
{
    pthread_mutex_lock(&eloop_mutex);
}

/* Release event loop mutex
 */
void
eloop_mutex_unlock (void)
{
    pthread_mutex_unlock(&eloop_mutex);
}

/* Wait on conditional variable under the event loop mutex
 */
void
eloop_cond_wait (pthread_cond_t *cond)
{
    pthread_cond_wait(cond, &eloop_mutex);
}

/* Get AvahiPoll that runs in event loop thread
 */
const AvahiPoll*
eloop_poll_get (void)
{
    return avahi_simple_poll_get(eloop_poll);
}

/* eloop_call_pending represents a pending eloop_call
 */
typedef struct {
    void     (*func)(void*); /* Function to be called */
    void     *data;          /* It's argument */
    uint64_t callid;         /* For eloop_call_cancel() */
    ll_node  node;           /* In eloop_call_pending_list */
} eloop_call_pending;

/* Execute function calls deferred by eloop_call()
 */
static void
eloop_call_execute (void)
{
    ll_node *node;

    while ((node = ll_pop_beg(&eloop_call_pending_list)) != NULL) {
        eloop_call_pending *pending;

        pending = OUTER_STRUCT(node, eloop_call_pending, node);
        pending->func(pending->data);
        mem_free(pending);
    }
}

/* Call function on a context of event loop thread
 * The returned value can be supplied as a `callid'
 * parameter for the eloop_call_cancel() function
 */
uint64_t
eloop_call (void (*func)(void*), void *data)
{
    eloop_call_pending *p = mem_new(eloop_call_pending, 1);
    static uint64_t    callid;
    uint64_t           ret;

    p->func = func;
    p->data = data;

    pthread_mutex_lock(&eloop_mutex);
    ret = ++ callid;
    p->callid = ret;
    ll_push_end(&eloop_call_pending_list, &p->node);
    pthread_mutex_unlock(&eloop_mutex);

    avahi_simple_poll_wakeup(eloop_poll);

    return ret;
}

/* Cancel pending eloop_call
 *
 * This is safe to cancel already finished call (at this
 * case nothing will happen)
 */
void
eloop_call_cancel (uint64_t callid)
{
    ll_node *node;

    for (LL_FOR_EACH(node, &eloop_call_pending_list)) {
        eloop_call_pending *p = OUTER_STRUCT(node, eloop_call_pending, node);

        if (p->callid == callid) {
            ll_del(&p->node);
            mem_free(p);
            return;
        }
    }
}

/* Event notifier. Calls user-defined function on a context
 * of event loop thread, when event is triggered. This is
 * safe to trigger the event from a context of any thread
 * or even from a signal handler
 */
struct eloop_event {
    pollable     *p;                 /* Underlying pollable event */
    eloop_fdpoll *fdpoll;            /* Underlying fdpoll */
    void         (*callback)(void*); /* user-defined callback */
    void         *data;              /* callback's argument */
};

/* eloop_event eloop_fdpoll callback
 */
static void
eloop_event_callback (int fd, void *data, ELOOP_FDPOLL_MASK mask)
{
    eloop_event *event = data;

    (void) fd;
    (void) mask;

    pollable_reset(event->p);
    event->callback(event->data);
}

/* Create new event notifier. May return NULL
 */
eloop_event*
eloop_event_new (void (*callback)(void *), void *data)
{
    eloop_event         *event;
    pollable            *p;

    p = pollable_new();
    if (p == NULL) {
        return NULL;
    }

    event = mem_new(eloop_event, 1);
    event->p = p;
    event->callback = callback;
    event->data = data;

    event->fdpoll = eloop_fdpoll_new(pollable_get_fd(p),
        eloop_event_callback, event);
    eloop_fdpoll_set_mask(event->fdpoll, ELOOP_FDPOLL_READ);

    return event;
}

/* Destroy event notifier
 */
void
eloop_event_free (eloop_event *event)
{
    eloop_fdpoll_free(event->fdpoll);
    pollable_free(event->p);
    mem_free(event);
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
    AvahiTimeout *timeout;            /* Underlying AvahiTimeout */
    void         (*callback)(void *); /* User callback */
    void         *data;               /* User data */
};

/* eloop_timer callback for AvahiTimeout
 */
static void
eloop_timer_callback (AvahiTimeout *t, void *data)
{
    eloop_timer *timer = data;

    (void) t;

    timer->callback(timer->data);
    eloop_timer_cancel(timer);
}

/* Create new timer. Timeout is in milliseconds
 */
eloop_timer*
eloop_timer_new (int timeout, void (*callback)(void *), void *data)
{
    const AvahiPoll *poll = eloop_poll_get();
    eloop_timer     *timer = mem_new(eloop_timer, 1);
    struct timeval  end;

    avahi_elapse_time(&end, timeout, 0);

    timer->timeout = poll->timeout_new(poll, &end, eloop_timer_callback, timer);
    timer->callback = callback;
    timer->data = data;

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
    const AvahiPoll *poll = eloop_poll_get();

    poll->timeout_free(timer->timeout);
    mem_free(timer);
}

/* eloop_fdpoll notifies user when file becomes
 * readable, writable or both, depending on its
 * event mask
 */
struct eloop_fdpoll {
    AvahiWatch        *watch;      /* Underlying AvahiWatch */
    int               fd;          /* Underlying file descriptor */
    ELOOP_FDPOLL_MASK mask;        /* Mask of active events */
    void              (*callback)( /* User-defined callback */
            int, void*, ELOOP_FDPOLL_MASK);
    void              *data;       /* Callback's data */
};

/* eloop_fdpoll callback for AvahiWatch
 */
static void
eloop_fdpoll_callback (AvahiWatch *w, int fd, AvahiWatchEvent event,
        void *data)
{
    eloop_fdpoll      *fdpoll = data;
    ELOOP_FDPOLL_MASK mask = 0;

    (void) w;

    if ((event & AVAHI_WATCH_IN) != 0) {
        mask |= ELOOP_FDPOLL_READ;
    }

    if ((event & AVAHI_WATCH_OUT) != 0) {
        mask |= ELOOP_FDPOLL_WRITE;
    }

    fdpoll->callback(fd, fdpoll->data, mask);
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
    const AvahiPoll *poll = eloop_poll_get();
    eloop_fdpoll    *fdpoll = mem_new(eloop_fdpoll, 1);

    fdpoll->fd = fd;
    fdpoll->callback = callback;
    fdpoll->data = data;

    eloop_poll_restart = true;
    fdpoll->watch = poll->watch_new(poll, fd, 0, eloop_fdpoll_callback, fdpoll);

    return fdpoll;
}

/* Destroy eloop_fdpoll
 */
void
eloop_fdpoll_free (eloop_fdpoll *fdpoll)
{
    const AvahiPoll *poll = eloop_poll_get();

    poll->watch_free(fdpoll->watch);
    mem_free(fdpoll);
}

/* Set eloop_fdpoll event mask
 */
void
eloop_fdpoll_set_mask (eloop_fdpoll *fdpoll, ELOOP_FDPOLL_MASK mask)
{
    if (fdpoll->mask != mask) {
        const AvahiPoll *poll = eloop_poll_get();
        AvahiWatchEvent events = 0;

        if ((mask & ELOOP_FDPOLL_READ) != 0) {
            events |= AVAHI_WATCH_IN;
        }

        if ((mask & ELOOP_FDPOLL_WRITE) != 0) {
            events |= AVAHI_WATCH_OUT;
        }

        fdpoll->mask = mask;
        poll->watch_update(fdpoll->watch, events);
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
    va_list ap;
    char    buf[sizeof(eloop_estring)];

    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    strcpy(eloop_estring, buf);
    va_end(ap);

    return ERROR(eloop_estring);
}

/* vim:ts=8:sw=4:et
 */
