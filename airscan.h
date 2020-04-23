/* AirScan (a.k.a. eSCL) backend for SANE
 *
 * Copyright (C) 2019 and up by Alexander Pevzner (pzz@apevzner.com)
 * See LICENSE for license terms and conditions
 */

#ifndef airscan_h
#define airscan_h

#include <avahi-common/address.h>
#include <avahi-common/strlst.h>
#include <avahi-glib/glib-watch.h>

#include <sane/sane.h>
#include <sane/saneopts.h>

#include <math.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include <netinet/in.h>
#include <sys/socket.h>

/******************** Static configuration ********************/
/* Configuration path in environment
 */
#define CONFIG_PATH_ENV                 "SANE_CONFIG_DIR"

/* Standard SANE configuration directory
 */
#define CONFIG_SANE_CONFIG_DIR          "/etc/sane.d/"

/* Sane-airscan configuration file and subdirectory names
 */
#define CONFIG_AIRSCAN_CONF             "airscan-wsd.conf"
#define CONFIG_AIRSCAN_D                "airscan.d"

/* Environment variables
 */
#define CONFIG_ENV_AIRSCAN_DEBUG        "SANE_DEBUG_AIRSCAN"

/* Default resolution, DPI
 */
#define CONFIG_DEFAULT_RESOLUTION       300

/******************** Forward declarations ********************/
/* log_ctx represents logging context
 */
typedef struct log_ctx log_ctx;

/* Type http_uri represents HTTP URI
 */
typedef struct http_uri http_uri;

/******************** Utility macros ********************/
/* Obtain pointer to outer structure from pointer to
 * its known member
 */
#define OUTER_STRUCT(member_p,struct_t,field)                            \
    ((struct_t*)((char*)(member_p) - ((ptrdiff_t) &(((struct_t*) 0)->field))))


/******************** Circular Linked Lists ********************/
/* ll_node represents a linked data node.
 * Data nodes are embedded into the corresponding data structures:
 *   struct data {
 *       ll_node chain; // Linked list chain
 *       ...
 *   };
 *
 * Use OUTER_STRUCT() macro to obtain pointer to containing
 * structure from the pointer to the list node
 */
typedef struct ll_node ll_node;
struct ll_node {
    ll_node *ll_prev, *ll_next;
};

/* ll_head represents a linked list head node
 * ll_head must be initialized before use with ll_init() function
 */
typedef struct {
    ll_node node;
} ll_head;

/* Initialize list head
 */
static inline void
ll_init (ll_head *head)
{
    head->node.ll_next = head->node.ll_prev = &head->node;
}

/* Check if list is empty
 */
static inline bool
ll_empty (const ll_head *head)
{
    return head->node.ll_next == &head->node;
}

/* Push node to the end of the list, represented
 * by its head node
 */
static inline void
ll_push_end (ll_head *head, ll_node *node)
{
    node->ll_prev = head->node.ll_prev;
    node->ll_next = &head->node;
    head->node.ll_prev->ll_next = node;
    head->node.ll_prev = node;
}

/* Push node to the beginning of the list, represented
 * by its head node
 */
static inline void
ll_push_beg (ll_head *head, ll_node *node)
{
    node->ll_next = head->node.ll_next;
    node->ll_prev = &head->node;
    head->node.ll_next->ll_prev = node;
    head->node.ll_next = node;
}

/* Delete node from the list
 */
static inline void
ll_del (ll_node *node)
{
    node->ll_prev->ll_next = node->ll_next;
    node->ll_next->ll_prev = node->ll_prev;

    /* Make double-delete safe */
    node->ll_next = node->ll_prev = node;
}

/* Pop node from the beginning of the list.
 * Returns NULL if list is empty
 */
static inline ll_node*
ll_pop_beg (ll_head *head)
{
    ll_node *node;

    if (ll_empty(head)) {
        return NULL;
    }

    node = head->node.ll_next;
    ll_del(node);

    return node;
}

/* Pop node from the end of the list.
 * Returns NULL if list is empty
 */
static inline ll_node*
ll_pop_end (ll_head *head)
{
    ll_node *node;

    if (ll_empty(head)) {
        return NULL;
    }

    node = head->node.ll_prev;
    ll_del(node);

    return node;
}

/* Get next (from the beginning to the end) node of
 * the list. Returns NULL, if end of list is reached
 */
static inline ll_node*
ll_next (ll_head *head, ll_node *node)
{
    node = node->ll_next;
    return node == &head->node ? NULL : node;
}

/* Get previous (from the beginning to the end) node of
 * the list. Returns NULL, if end of list is reached
 */
static inline ll_node*
ll_prev (ll_head *head, ll_node *node)
{
    node = node->ll_prev;
    return node == &head->node ? NULL : node;
}

/* Get first node of the list.
 * Returns NULL if list is empty
 */
static inline ll_node*
ll_first (ll_head *head)
{
    return ll_next(head, &head->node);
}

/* Get last node of the list.
 * Returns NULL if list is empty
 */
static inline ll_node*
ll_last (ll_head *head)
{
    return ll_prev(head, &head->node);
}

/* Concatenate lists:
 *   list1 += list2
 *   list2 = empty
 */
static inline void
ll_cat (ll_head *list1, ll_head *list2)
{
    if (ll_empty(list2)) {
        return;
    }

    list2->node.ll_prev->ll_next = &list1->node;
    list2->node.ll_next->ll_prev = list1->node.ll_prev;
    list1->node.ll_prev->ll_next = list2->node.ll_next;
    list1->node.ll_prev = list2->node.ll_prev;

    ll_init(list2);
}

/* Helper macro for list iteration.
 * Usage:
 *   for (LL_FOR_EACH(node, list)) {
 *     // do something with the node
 *   }
 */
#define LL_FOR_EACH(node,list)                          \
    node = ll_first(list); node != NULL; node = ll_next(list, node)

/******************** Error handling ********************/
/* Type error represents an error. Its value either NULL,
 * which indicates "no error" condition, or some opaque
 * non-null pointer, which can be converted to string
 * with textual description of the error, using the ESTRING()
 * function
 *
 * Caller should not attempt to free the memory, referred
 * by error or string, obtained from an error using the
 * ESTRING() function
 */
typedef struct {} *error;

/* Construct error from a string
 */
static inline error
ERROR (const char *s)
{
    return (error) s;
}

/* Obtain textual representation of the error
 */
static inline const char*
ESTRING (error err)
{
    return (const char*) err;
}

/******************** Various identifiers ********************/
/* ID_PROTO represents protocol identifier
 */
typedef enum {
    ID_PROTO_UNKNOWN = -1,
    ID_PROTO_ESCL,
    ID_PROTO_WSD,

    NUM_ID_PROTO
} ID_PROTO;

/* id_proto_name returns protocol name
 * For unknown ID returns NULL
 */
const char*
id_proto_name (ID_PROTO proto);

/* id_proto_by_name returns protocol identifier by name
 * For unknown name returns ID_PROTO_UNKNOWN
 */
ID_PROTO
id_proto_by_name (const char* name);

/* ID_SOURCE represents scanning source
 */
typedef enum {
    ID_SOURCE_UNKNOWN = -1,
    ID_SOURCE_PLATEN,
    ID_SOURCE_ADF_SIMPLEX,
    ID_SOURCE_ADF_DUPLEX,

    NUM_ID_SOURCE
} ID_SOURCE;

/* id_source_sane_name returns SANE name for the source
 * For unknown ID returns NULL
 */
const char*
id_source_sane_name (ID_SOURCE id);

/* id_source_by_sane_name returns ID_SOURCE by its SANE name
 * For unknown name returns ID_SOURCE_UNKNOWN
 */
ID_SOURCE
id_source_by_sane_name (const char *name);

/* ID_COLORMODE represents color mode
 */
typedef enum {
    ID_COLORMODE_UNKNOWN = -1,
    ID_COLORMODE_COLOR,
    ID_COLORMODE_GRAYSCALE,
    ID_COLORMODE_BW1,

    NUM_ID_COLORMODE
} ID_COLORMODE;

/* id_colormode_sane_name returns SANE name for the color mode
 * For unknown ID returns NULL
 */
const char*
id_colormode_sane_name (ID_COLORMODE id);

/* id_colormode_by_sane_name returns ID_COLORMODE by its SANE name
 * For unknown name returns ID_COLORMODE_UNKNOWN
 */
ID_COLORMODE
id_colormode_by_sane_name (const char *name);

/* ID_FORMAT represents image format
 */
typedef enum {
    ID_FORMAT_UNKNOWN = -1,
    ID_FORMAT_JPEG,
    ID_FORMAT_TIFF,
    ID_FORMAT_PNG,
    ID_FORMAT_PDF,
    ID_FORMAT_DIB,

    NUM_ID_FORMAT
} ID_FORMAT;

/* id_format_mime_name returns MIME name for the image format
 */
const char*
id_format_mime_name (ID_FORMAT id);

/* id_format_by_mime_name returns ID_FORMAT by its MIME name
 * For unknown name returns ID_FORMAT_UNKNOWN
 */
ID_FORMAT
id_format_by_mime_name (const char *name);

/* if_format_short_name returns short name for ID_FORMAT
 */
const char*
id_format_short_name (ID_FORMAT id);

/******************** Device ID ********************/
/* Allocate unique device ID
 */
unsigned int
devid_alloc (void);

/* Free device ID
 */
void
devid_free (unsigned int id);

/* Initialize device ID allocator
 */
void
devid_init (void);

/******************** UUID utilities ********************/
/* Type uuid represents a random UUID string.
 *
 * It is wrapped into struct, so it can be returned
 * by value, without need to mess with memory allocation
 */
typedef struct {
    char text[sizeof("urn:uuid:ede05377-460e-4b4a-a5c0-423f9e02e8fa")];
} uuid;

/* Check if uuid is valid
 */
static inline bool
uuid_valid (uuid u)
{
    return u.text[0] != '\0';
}

/* Generate random UUID. Generated UUID has a following form:
 *    urn:uuid:ede05377-460e-4b4a-a5c0-423f9e02e8fa
 */
uuid
uuid_rand (void);

/* Parse UUID. This function ignores all "decorations", like
 * urn:uuid: prefix and so on, and takes only hexadecimal digits
 * into considerations
 *
 * Check the returned uuid with uuid_valid() for possible parse errors
 */
uuid
uuid_parse (const char *in);

/* Generate uuid by cryptographically cacheing input string
 */
uuid
uuid_hash (const char *s);

/* Compare two uuids
 */
static inline bool
uuid_equal (uuid u1, uuid u2)
{
    return !strcmp(u1.text, u2.text);
}

/******************** Configuration file loader ********************/
/* Device URI for manually disabled device
 */
#define CONF_DEVICE_DISABLE     "disable"

/* Device configuration, for manually added devices
 */
typedef struct conf_device conf_device;
struct conf_device {
    unsigned int devid; /* Device ident */
    const char   *name; /* Device name */
    ID_PROTO     proto; /* Protocol to use */
    http_uri     *uri;  /* Device URI, parsed; NULL if device disabled */
    conf_device  *next; /* Next device in the list */
};

/* Backend configuration
 */
typedef struct {
    bool        dbg_enabled;      /* Debugging enabled */
    const char  *dbg_trace;       /* Trace directory */
    conf_device *devices;         /* Manually configured devices */
    bool        discovery;        /* Scanners discovery enabled */
    bool        model_is_netname; /* Use network name instead of model */
    bool        proto_manual;     /* Manual protocol switch */
    bool        fast_wsdd;        /* Fast WS-Discovery */
} conf_data;

#define CONF_INIT { false, NULL, NULL, true, true, false, true }

extern conf_data conf;

/* Load configuration. It updates content of a global conf variable
 */
void
conf_load (void);

/* Free resources, allocated by conf_load, and reset configuration
 * data into initial state
 */
void
conf_unload (void);

/******************** Utility functions for IP addresses ********************/
/* Address string, wrapped into structure so can
 * be passed by value
 */
typedef struct {
    char       text[64];
} ip_straddr;

/* Format ip_straddr from IP address (struct in_addr or struct in6_addr)
 * af must be AF_INET or AF_INET6
 */
ip_straddr
ip_straddr_from_ip (int af, const void *addr);

/* Format ip_straddr from struct sockaddr.
 * Both AF_INET and AF_INET6 are supported
 */
ip_straddr
ip_straddr_from_sockaddr(const struct sockaddr *addr);

/* Check if address is link-local
 * af must be AF_INET or AF_INET6
 */
bool
ip_is_linklocal (int af, const void *addr);

/* Check if sockaddr is link-local
 */
bool
ip_sockaddr_is_linklocal (const struct sockaddr *addr);

/******************** Network interfaces addresses ********************/
/* Network interface name, wrapped into structure, so
 * it can be passed by value
 */
typedef struct {
    char text[32];
} netif_name;

/* Network interface address
 */
typedef struct netif_addr netif_addr;
struct netif_addr {
    netif_addr *next;         /* Next address in the list */
    int        ifindex;       /* Interface index */
    netif_name ifname;        /* Interface name, for logging */
    bool       ipv6;          /* This is an IPv6 address */
    void       *data;         /* Placeholder for user data */
    char       straddr[64];   /* Address string */
    union {
        struct in_addr  v4;   /* IPv4 address */
        struct in6_addr v6;   /* IPv6 address */
    } ip;
};

/* Get list of network interfaces addresses
 * The returned list is sorted
 */
netif_addr*
netif_addr_get (void);

/* Free list of network interfaces addresses
 */
void
netif_addr_free (netif_addr *list);

/* netif_diff represents a difference between two
 * lists of network interface addresses
 */
typedef struct {
    netif_addr *added, *removed; /* What was added/removed */
} netif_diff;

/* Compute a difference between two lists of
 * addresses.
 *
 * It assumes, both lists are sorted, as returned
 * by netif_addr_get()
 */
netif_diff
netif_diff_compute (netif_addr *list1, netif_addr *list2);

/* Network interfaces addresses change notifier
 */
typedef struct netif_notifier netif_notifier;

/* Create netif_notifier
 */
netif_notifier*
netif_notifier_create (void (*callback) (void*), void *data);

/* Destroy netif_notifier
 */
void
netif_notifier_free (netif_notifier *notifier);

/******************** Pollable events ********************/
/* The pollable event
 *
 * Pollable events allow to wait until some event happens
 * and can be used in combination with select()/poll()
 * system calls
 */
typedef struct pollable pollable;

/* Create new pollable event
 */
pollable*
pollable_new (void);

/* Free pollable event
 */
void
pollable_free (pollable *p);

/* Get file descriptor for poll()/select().
 *
 * When pollable event becomes "ready", this file descriptor
 * becomes readable from the select/poll point of view
 */
int
pollable_get_fd (pollable *p);

/* Make pollable event "ready"
 */
void
pollable_signal (pollable *p);

/* Make pollable event "not ready"
 */
void
pollable_reset (pollable *p);

/* Wait until pollable event is ready
 */
void
pollable_wait (pollable *p);

/******************** Event loop ********************/
/* Initialize event loop
 */
SANE_Status
eloop_init (void);

/* Cleanup event loop
 */
void
eloop_cleanup (void);

/* Add start/stop callback. This callback is called
 * on a event loop thread context, once when event
 * loop is started, and second time when it is stopped
 *
 * Start callbacks are called in the same order as
 * they were added. Stop callbacks are called in a
 * reverse order
 */
void
eloop_add_start_stop_callback (void (*callback) (bool start));

/* Start event loop thread.
 *
 * Callback is called from the thread context twice:
 *     callback(true)  - when thread is started
 *     callback(false) - when thread is about to exit
 */
void
eloop_thread_start (void);

/* Stop event loop thread and wait until its termination
 */
void
eloop_thread_stop (void);

/* Acquire event loop mutex
 */
void
eloop_mutex_lock (void);

/* Release event loop mutex
 */
void
eloop_mutex_unlock (void);

/* Wait on conditional variable under the event loop mutex
 */
void
eloop_cond_wait (GCond *cond);

/* eloop_cond_wait() with timeout in seconds
 */
bool
eloop_cond_wait_until (GCond *cond, gint64 timeout);

/* Create AvahiGLibPoll that runs in context of the event loop
 */
AvahiGLibPoll*
eloop_new_avahi_poll (void);

/* Call function on a context of event loop thread
 */
void
eloop_call (GSourceFunc func, gpointer data);

/* Event notifier. Calls user-defined function on a context
 * of event loop thread, when event is triggered. This is
 * safe to trigger the event from a context of any thread
 * or even from a signal handler
 */
typedef struct eloop_event eloop_event;

/* Create new event notifier. May return NULL
 */
eloop_event*
eloop_event_new (void (*callback)(void *), void *data);

/* Destroy event notifier
 */
void
eloop_event_free (eloop_event *event);

/* Trigger an event
 */
void
eloop_event_trigger (eloop_event *event);

/* Timer. Calls user-defined function after a specified
 * interval
 */
typedef struct eloop_timer eloop_timer;

/* Create new timer. Timeout is in milliseconds
 */
eloop_timer*
eloop_timer_new (int timeout, void (*callback)(void *), void *data);

/* Cancel a timer
 *
 * Caller SHOULD NOT cancel expired timer (timer with called
 * callback) -- this is done automatically
 */
void
eloop_timer_cancel (eloop_timer *timer);

/* eloop_fdpoll notifies user when file becomes
 * readable, writable or both, depending on its
 * event mask
 */
typedef struct eloop_fdpoll eloop_fdpoll;

/* Mask of file events user interested in
 */
typedef enum {
    ELOOP_FDPOLL_READ  = (1 << 0),
    ELOOP_FDPOLL_WRITE = (1 << 1),
    ELOOP_FDPOLL_BOTH  = ELOOP_FDPOLL_READ | ELOOP_FDPOLL_WRITE
} ELOOP_FDPOLL_MASK;

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
        void (*callback) (int, void*, ELOOP_FDPOLL_MASK), void *data);

/* Destroy eloop_fdpoll
 */
void
eloop_fdpoll_free (eloop_fdpoll *fdpoll);

/* Set eloop_fdpoll event mask
 */
void
eloop_fdpoll_set_mask (eloop_fdpoll *fdpoll, ELOOP_FDPOLL_MASK mask);

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
eloop_eprintf(const char *fmt, ...);

/******************** HTTP Client ********************/
/* Create new URI, by parsing URI string
 */
http_uri*
http_uri_new (const char *str, bool strip_fragment);

/* Clone an URI
 */
http_uri*
http_uri_clone (const http_uri *old);

/* Create URI, relative to base URI. If `path_only' is
 * true, scheme, host and port are taken from the
 * base URI
 */
http_uri*
http_uri_new_relative (const http_uri *base, const char *path,
        bool strip_fragment, bool path_only);

/* Free the URI
 */
void
http_uri_free (http_uri *uri);

/* Get URI string
 */
const char*
http_uri_str (http_uri *uri);

/* Get URI's host address. If Host address is not literal, returns NULL
 */
const struct sockaddr*
http_uri_addr (http_uri *uri);

/* Get URI path
 */
const char*
http_uri_get_path (const http_uri *uri);

/* Set URI path
 */
void
http_uri_set_path (http_uri *uri, const char *path);

/* Fix IPv6 address zone suffix
 */
void
http_uri_fix_ipv6_zone (http_uri *uri, int ifindex);

/* Strip zone suffix from literal IPv6 host address
 *
 * If address is not IPv6 or doesn't have zone suffix, it is
 * not changed
 */
void
http_uri_strip_zone_suffux (http_uri *uri);

/* Make sure URI's path ends with the slash character
 */
void
http_uri_fix_end_slash (http_uri *uri);

/* Check if 2 URIs are equal
 */
bool
http_uri_equal (const http_uri *uri1, const http_uri *uri2);

/* HTTP data
 */
typedef struct {
    const char *content_type; /* Content type, with stripped directives */
    const void *bytes;        /* Data bytes */
    size_t     size;          /* Data size */
} http_data;

/* Ref http_data
 */
http_data*
http_data_ref (http_data *data);

/* Unref http_data
 */
void
http_data_unref (http_data *data);

/* http_data_queue represents a queue of http_data items
 */
typedef struct http_data_queue http_data_queue;

/* Create new http_data_queue
 */
http_data_queue*
http_data_queue_new (void);

/* Destroy http_data_queue
 */
void
http_data_queue_free (http_data_queue *queue);

/* Push item into the http_data_queue.
 */
void
http_data_queue_push (http_data_queue *queue, http_data *data);

/* Pull an item from the http_data_queue. Returns NULL if queue is empty
 */
http_data*
http_data_queue_pull (http_data_queue *queue);

/* Get queue length
 */
int
http_data_queue_len (const http_data_queue *queue);

/* Check if queue is empty
 */
static inline bool
http_data_queue_empty (const http_data_queue *queue)
{
    return http_data_queue_len(queue) == 0;
}

/* Purge the queue
 */
void
http_data_queue_purge (http_data_queue *queue);

/* Type http_client represents HTTP client instance
 */
typedef struct http_client http_client;

/* Create new http_client
 */
http_client*
http_client_new (log_ctx *log, void *ptr);

/* Destroy http_client
 */
void
http_client_free (http_client *client);

/* Set on-error callback. If this callback is not NULL,
 * in a case of transport error it will be called instead
 * of the http_query callback
 */
void
http_client_onerror (http_client *client,
        void (*callback)(void *ptr, error err));

/* Cancel all pending queries, if any
 */
void
http_client_cancel (http_client *client);

/* Get count of pending queries
 */
int
http_client_num_pending (const http_client *client);

/* Type http_query represents HTTP query (both request and response)
 */
typedef struct http_query http_query;

/* Create new http_query
 *
 * Newly created http_query takes ownership on uri and body (if not NULL).
 * The method and content_type assumed to be constant strings.
 */
http_query*
http_query_new (http_client *client, http_uri *uri, const char *method,
        char *body, const char *content_type);

/* Create new http_query, relative to base URI
 *
 * Newly created http_query takes ownership on body (if not NULL).
 * The method and content_type assumed to be constant strings.
 */
http_query*
http_query_new_relative(http_client *client,
        const http_uri *base_uri, const char *path,
        const char *method, char *body, const char *content_type);

/* For this particular query override on-error callback, previously
 * set by http_client_onerror()
 *
 * If canllback is NULL, the completion callback, specified on a
 * http_query_submit() call, will be used even in a case of
 * transport error.
 */
void
http_query_onerror (http_query *q, void (*onerror)(void *ptr, error err));

/* Submit the query.
 *
 * When query is finished, callback will be called. After return from
 * callback, memory, owned by http_query will be invalidated
 */
void
http_query_submit (http_query *q, void (*callback)(void *ptr, http_query *q));

/* Set uintptr_t parameter, associated with query.
 * Completion callback may later use http_query_get_uintptr()
 * to fetch this value
 */
void
http_query_set_uintptr (http_query *q, uintptr_t u);

/* Get uintptr_t parameter, previously set by http_query_set_uintptr()
 */
uintptr_t
http_query_get_uintptr (http_query *q);

/* Get query error, if any
 *
 * Both transport errors and erroneous HTTP response codes
 * considered as errors here
 */
error
http_query_error (const http_query *q);

/* Get query transport error, if any
 *
 * Only transport errors considered errors here
 */
error
http_query_transport_error (const http_query *q);

/* Get HTTP status code. Code not available, if query finished
 * with error
 */
int
http_query_status (const http_query *q);

/* Get HTTP status string
 */
const char*
http_query_status_string (const http_query *q);

/* Get query URI
 */
http_uri*
http_query_uri (const http_query *q);

/* Get query method
 */
const char*
http_query_method (const http_query *q);

/* Set request header
 */
void
http_query_set_request_header (http_query *q, const char *name,
        const char *value);

/* Get request header
 */
const char*
http_query_get_request_header (const http_query *q, const char *name);

/* Get response header
 */
const char*
http_query_get_response_header (const http_query *q, const char *name);

/* Get request data
 *
 * You need to http_data_ref(), if you want data to remain valid
 * after query end of life
 */
http_data*
http_query_get_request_data (const http_query *q);

/* Get request data
 *
 * You need to http_data_ref(), if you want data to remain valid
 * after query end of life
 */
http_data*
http_query_get_response_data (const http_query *q);

/* Get count of parts of multipart response
 */
int
http_query_get_mp_response_count (const http_query *q);

/* Get data of Nth part of multipart response
 *
 * You need to http_data_ref(), if you want data to remain valid
 * after query end of life
 */
http_data*
http_query_get_mp_response_data (const http_query *q, int n);

/* Call callback for each request header
 */
void
http_query_foreach_request_header (const http_query *q,
        void (*callback)(const char *name, const char *value, void *ptr),
        void *ptr);

/* Call callback for each response header
 */
void
http_query_foreach_response_header (const http_query *q,
        void (*callback)(const char *name, const char *value, void *ptr),
        void *ptr);

/* Some HTTP status codes
 */
enum {
    HTTP_STATUS_OK                  = 200,
    HTTP_STATUS_CREATED             = 201,
    HTTP_STATUS_SERVICE_UNAVAILABLE = 503
};

/* Initialize HTTP client
 */
SANE_Status
http_init (void);

/* Initialize HTTP client
 */
void
http_cleanup (void);

/******************** Protocol trace ********************/
/* Type trace represents an opaque handle of trace
 * file
 */
typedef struct trace trace;

/* Initialize protocol trace. Called at backend initialization
 */
SANE_Status
trace_init (void);

/* Cleanup protocol trace. Called at backend unload
 */
void
trace_cleanup (void);

/* Open protocol trace
 */
trace*
trace_open (const char *device_name);

/* Close protocol trace
 */
void
trace_close (trace *t);

/* This hook is called on every http_query completion
 */
void
trace_http_query_hook (trace *t, http_query *q);

/* Printf to the trace log
 */
void
trace_printf (trace *t, const char *fmt, ...);

/* Note an error in trace log
 */
void
trace_error (trace *t, error err);

/* Dump message body
 */
void
trace_dump_body (trace *t, http_data *data);

/******************** SANE_Word/SANE_String arrays ********************/
/* Create array of SANE_Word
 */
SANE_Word*
sane_word_array_new (void);

/* Free array of SANE_Word
 */
void
sane_word_array_free (SANE_Word *a);

/* Reset array of SANE_Word
 */
void
sane_word_array_reset (SANE_Word **a);

/* Get length of the SANE_Word array
 */
size_t
sane_word_array_len (const SANE_Word *a);

/* Append word to array. Returns new array (old becomes invalid)
 */
SANE_Word*
sane_word_array_append (SANE_Word *a, SANE_Word w);

/* Sort array of SANE_Word in increasing order
 */
void
sane_word_array_sort (SANE_Word *a);

/* Intersect two sorted arrays.
 */
SANE_Word*
sane_word_array_intersect_sorted ( const SANE_Word *a1, const SANE_Word *a2);

/* Create initialize array of SANE_String
 */
SANE_String*
sane_string_array_new (void);

/* Free array of SANE_String
 */
void
sane_string_array_free (SANE_String *a);

/* Reset array of SANE_String
 */
void
sane_string_array_reset (SANE_String *a);

/* Get length of the SANE_Word array
 */
size_t
sane_string_array_len (const SANE_String *a);

/* Append string to array Returns new array (old becomes invalid)
 */
SANE_String*
sane_string_array_append(SANE_String *a, SANE_String s);

/* Compute max string length in array of strings
 */
size_t
sane_string_array_max_strlen(const SANE_String *a);

/******************** XML utilities ********************/
/* xml_ns defines XML namespace.
 *
 * For XML writer namespaces are simply added to the root
 * node attributes
 *
 * XML reader performs prefix substitutions
 *
 * If namespace substitution is enabled, function, each node,
 * which name's namespace matches the pattern, will be reported
 * with name prefix defined by substitution rule,
 * regardless of prefix actually used in the document
 *
 * Example:
 *   <namespace:nodes xmlns:namespace="http://www.example.com/namespace">
 *     <namespace:node1/>
 *     <namespace:node2/>
 *     <namespace:node3/>
 *   </namespace:nodes>
 *
 *   rule: {"ns", "http://www.example.com/namespace"}
 *
 * With this rule set, all nodes will be reported as if they
 * had the "ns" prefix, though actually their prefix in document
 * is different
 *
 * XML reader interprets namespace uri as a glob-style pattern,
 * as used by fnmatch (3) function with flags = 0
 */
typedef struct {
    const char *prefix; /* Short prefix */
    const char *uri;    /* The namespace uri (glob pattern for reader) */
} xml_ns;

/* xml_attr represents an XML attribute.
 *
 * Attributes are supported by XML writer. Array of attributes
 * is terminated by the {NULL, NULL} attribute
 */
typedef struct {
    const char *name;   /* Attribute name */
    const char *value;  /* Attribute value */
} xml_attr;

/* XML reader
 */
typedef struct xml_rd xml_rd;

/* Parse XML text and initialize reader to iterate
 * starting from the root node
 *
 * The 'ns' argument, if not NULL, points to array of substitution
 * rules. Last element must have NULL prefix and url
 *
 * Array of rules considered to be statically allocated
 * (at least, it can remain valid during reader life time)
 *
 * On success, saves newly constructed reader into
 * the xml parameter.
 */
error
xml_rd_begin (xml_rd **xml, const char *xml_text, size_t xml_len,
        const xml_ns *ns);

/* Finish reading, free allocated resources
 */
void
xml_rd_finish (xml_rd **xml);

/* Get current node depth in the tree. Root depth is 0
 */
unsigned int
xml_rd_depth (xml_rd *xml);

/* Check for end-of-document condition
 */
bool
xml_rd_end (xml_rd *xml);

/* Shift to the next node
 */
void
xml_rd_next (xml_rd *xml);

/* Shift to the next node, visiting the nested nodes on the way
 *
 * If depth > 0, it will not return from nested nodes
 * upper the specified depth
 */
void
xml_rd_deep_next (xml_rd *xml, unsigned int depth);

/* Enter the current node - iterate its children
 */
void
xml_rd_enter (xml_rd *xml);

/* Leave the current node - return to its parent
 */
void
xml_rd_leave (xml_rd *xml);

/* Get name of the current node.
 *
 * The returned string remains valid, until reader is cleaned up
 * or current node is changed (by set/next/enter/leave operations).
 * You don't need to free this string explicitly
 */
const char*
xml_rd_node_name (xml_rd *xml);

/* Get full path to the current node, '/'-separated
 */
const char*
xml_rd_node_path (xml_rd *xml);

/* Match name of the current node against the pattern
 */
bool
xml_rd_node_name_match (xml_rd *xml, const char *pattern);

/* Get value of the current node as text
 *
 * The returned string remains valid, until reader is cleaned up
 * or current node is changed (by set/next/enter/leave operations).
 * You don't need to free this string explicitly
 */
const char*
xml_rd_node_value (xml_rd *xml);

/* Get value of the current node as unsigned integer
 */
error
xml_rd_node_value_uint (xml_rd *xml, SANE_Word *val);

/* XML writer
 */
typedef struct xml_wr xml_wr;

/* Begin writing XML document. Root node will be created automatically
 *
 * The ns parameter must be terminated by {NULL, NULL} structure
 */
xml_wr*
xml_wr_begin (const char *root, const xml_ns *ns);

/* Finish writing, generate document string.
 * Caller must g_free() this string after use
 */
char*
xml_wr_finish (xml_wr *xml);

/* Like xml_wr_finish, but returns compact representation
 * of XML (without indentation and new lines)
 */
char*
xml_wr_finish_compact (xml_wr *xml);

/* Add node with textual value
 */
void
xml_wr_add_text (xml_wr *xml, const char *name, const char *value);

/* Add text node with attributes
 */
void
xml_wr_add_text_attr (xml_wr *xml, const char *name, const char *value,
        const xml_attr *attrs);

/* Add node with unsigned integer value
 */
void
xml_wr_add_uint (xml_wr *xml, const char *name, unsigned int value);

/* Add node with unsigned integer value and attributes
 */
void
xml_wr_add_uint_attr (xml_wr *xml, const char *name, unsigned int value,
        const xml_attr *attrs);

/* Add node with boolean value
 */
void
xml_wr_add_bool (xml_wr *xml, const char *name, bool value);

/* Add node with boolean value and attributes
 */
void
xml_wr_add_bool_attr (xml_wr *xml, const char *name, bool value,
        const xml_attr *attrs);

/* Create node with children and enter newly added node
 */
void
xml_wr_enter (xml_wr *xml, const char *name);

/* xml_wr_enter with attributes
 */
void
xml_wr_enter_attr (xml_wr *xml, const char *name, const xml_attr *attrs);

/* Leave the current node
 */
void
xml_wr_leave (xml_wr *xml);

/* Format XML to file. It either succeeds, writes a formatted XML
 * and returns true, or fails, writes nothing to file and returns false
 */
bool
xml_format (FILE *fp, const char *xml_text, size_t xml_len);

/******************** Sane Options********************/
/* Options numbers, for internal use
 */
enum {
    OPT_NUM_OPTIONS,            /* Total number of options */

    /* Standard options group */
    OPT_GROUP_STANDARD,
    OPT_SCAN_RESOLUTION,
    OPT_SCAN_COLORMODE,         /* I.e. color/grayscale etc */
    OPT_SCAN_SOURCE,            /* Platem/ADF/ADF Duplex */

    /* Geometry options group */
    OPT_GROUP_GEOMETRY,
    OPT_SCAN_TL_X,
    OPT_SCAN_TL_Y,
    OPT_SCAN_BR_X,
    OPT_SCAN_BR_Y,

    /* Total count of options, computed by compiler */
    NUM_OPTIONS
};

/* String constants for certain SANE options values
 * (missed from sane/sameopt.h)
 */
#define OPTVAL_SOURCE_PLATEN      "Flatbed"
#define OPTVAL_SOURCE_ADF_SIMPLEX "ADF"
#define OPTVAL_SOURCE_ADF_DUPLEX  "ADF Duplex"

/******************** Device Capabilities ********************/
/* Source flags
 */
enum {
    /* Supported Intents */
    DEVCAPS_SOURCE_INTENT_DOCUMENT      = (1 << 3),
    DEVCAPS_SOURCE_INTENT_TXT_AND_GRAPH = (1 << 4),
    DEVCAPS_SOURCE_INTENT_PHOTO         = (1 << 5),
    DEVCAPS_SOURCE_INTENT_PREVIEW       = (1 << 6),

    DEVCAPS_SOURCE_INTENT_ALL =
        DEVCAPS_SOURCE_INTENT_DOCUMENT |
        DEVCAPS_SOURCE_INTENT_TXT_AND_GRAPH |
        DEVCAPS_SOURCE_INTENT_PHOTO |
        DEVCAPS_SOURCE_INTENT_PREVIEW,

    /* How resolutions are defined */
    DEVCAPS_SOURCE_RES_DISCRETE = (1 << 7), /* Discrete resolutions */
    DEVCAPS_SOURCE_RES_RANGE    = (1 << 8), /* Range of resolutions */

    DEVCAPS_SOURCE_RES_ALL =
        DEVCAPS_SOURCE_RES_DISCRETE |
        DEVCAPS_SOURCE_RES_RANGE,

    /* Miscellaneous flags */
    DEVCAPS_SOURCE_HAS_SIZE = (1 << 12), /* max_width, max_height and
                                            derivatives are valid */

    /* Protocol dialects */
    DEVCAPS_SOURCE_PWG_DOCFMT      = (1 << 13), /* pwg:DocumentFormat */
    DEVCAPS_SOURCE_SCAN_DOCFMT_EXT = (1 << 14), /* scan:DocumentFormatExt */
};

/* Supported image formats
 */
#define DEVCAPS_FORMATS_SUPPORTED       \
    ((1 << ID_FORMAT_JPEG) |            \
     (1 << ID_FORMAT_PNG)  |            \
     (1 << ID_FORMAT_DIB))

/* Supported color modes
 *
 * Note, currently the only image format we support is JPEG
 * With JPEG, ID_COLORMODE_BW1 cannot be supported
 */
#define DEVCAPS_COLORMODES_SUPPORTED    \
    ((1 << ID_COLORMODE_COLOR) |        \
     (1 << ID_COLORMODE_GRAYSCALE))

/* Source Capabilities (each device may contain multiple sources)
 */
typedef struct {
    unsigned int flags;                  /* Source flags */
    unsigned int colormodes;             /* Set of 1 << ID_COLORMODE */
    unsigned int formats;                /* Set of 1 << ID_FORMAT */
    SANE_Word    min_wid_px, max_wid_px; /* Min/max width, in pixels */
    SANE_Word    min_hei_px, max_hei_px; /* Min/max height, in pixels */
    SANE_Word    *resolutions;           /* Discrete resolutions, in DPI */
    SANE_Range   res_range;              /* Resolutions range, in DPI */
    SANE_Range   win_x_range_mm;         /* Window x range, in mm */
    SANE_Range   win_y_range_mm;         /* Window y range, in mm */
} devcaps_source;

/* Allocate devcaps_source
 */
devcaps_source*
devcaps_source_new (void);

/* Free devcaps_source
 */
void
devcaps_source_free (devcaps_source *src);

/* Clone a source
 */
devcaps_source*
devcaps_source_clone (const devcaps_source *src);

/* Merge two sources, resulting the source that contains
 * only capabilities, supported by two input sources
 *
 * Returns NULL, if sources cannot be merged
 */
devcaps_source*
devcaps_source_merge (const devcaps_source *s1, const devcaps_source *s2);

/* Device Capabilities
 */
typedef struct {
    /* Device identification */
    const char     *model;              /* Device model */
    const char     *vendor;             /* Device vendor */

    /* Fundamental values */
    const char     *protocol;            /* Protocol name */
    SANE_Word      units;                /* Size units, pixels per inch */

    /* Image compression */
    bool           compression_ok;       /* Compression params are supported */
    SANE_Range     compression_range;    /* Compression range */
    SANE_Word      compression_norm;     /* Normal compression */

    /* Sources */
    devcaps_source *src[NUM_ID_SOURCE];  /* Missed sources are NULL */
} devcaps;

/* Initialize Device Capabilities
 */
void
devcaps_init (devcaps *caps);

/* Cleanup Device Capabilities
 */
void
devcaps_cleanup (devcaps *caps);

/* Reset Device Capabilities into initial state
 */
void
devcaps_reset (devcaps *caps);

/* Dump device capabilities, for debugging
 */
void
devcaps_dump (log_ctx *log, devcaps *caps);

/******************** Device options ********************/
/* Scan options
 */
typedef struct {
    devcaps                caps;              /* Device capabilities */
    SANE_Option_Descriptor desc[NUM_OPTIONS]; /* Option descriptors */
    ID_SOURCE              src;               /* Current source */
    ID_COLORMODE           colormode;         /* Current color mode */
    SANE_Word              resolution;        /* Current resolution */
    SANE_Fixed             tl_x, tl_y;        /* Top-left x/y */
    SANE_Fixed             br_x, br_y;        /* Bottom-right x/y */
    SANE_Parameters        params;            /* Scan parameters */
    SANE_String            *sane_sources;     /* Sources, in SANE format */
    SANE_String            *sane_colormodes;  /* Color modes in SANE format */
} devopt;

/* Initialize device options
 */
void
devopt_init (devopt *opt);

/* Cleanup device options
 */
void
devopt_cleanup (devopt *opt);

/* Set default option values. Before call to this function,
 * devopt.caps needs to be properly filled.
 */
void
devopt_set_defaults (devopt *opt);

/* Set device option
 */
SANE_Status
devopt_set_option (devopt *opt, SANE_Int option, void *value, SANE_Word *info);

/* Get device option
 */
SANE_Status
devopt_get_option (devopt *opt, SANE_Int option, void *value);

/******************** ZeroConf (device discovery) ********************/
/* zeroconf_device represents a single device
 */
typedef struct zeroconf_device zeroconf_device;

/* zeroconf_endpoint represents a device endpoint
 */
typedef struct zeroconf_endpoint zeroconf_endpoint;
struct zeroconf_endpoint {
    ID_PROTO          proto;     /* The protocol */
    http_uri          *uri;      /* I.e, "http://192.168.1.1:8080/eSCL/" */
    zeroconf_endpoint *next;     /* Next endpoint in the list */
};

/* ZEROCONF_METHOD represents a method how device was discovered
 * The same device may be discovered using multiple methods
 */
typedef enum {
    /* The following findings serve as indirect signs of
     * scanner presence in the network
     */
    ZEROCONF_MDNS_HINT,   /* Hint finding from MDNS world */

    /* The following findings are expected to bring actual
     * scanner endpoints
     */
    ZEROCONF_USCAN_TCP,   /* _uscan._tcp */
    ZEROCONF_USCANS_TCP,  /* _uscans._tcp */
    ZEROCONF_WSD,         /* WS-Discovery */

    NUM_ZEROCONF_METHOD
} ZEROCONF_METHOD;

/* zeroconf_finding represents a single device discovery finding.
 * Multiple findings can point to the same device, and even
 * endpoints may duplicate between findings (say, if the same
 * device found using multiple network interfaces or using various
 * discovery methods)
 *
 * zeroconf_finding are bound to method and interface index
 */
typedef struct {
    ZEROCONF_METHOD   method;     /* Discovery method */
    const char        *name;      /* Network-unique name, NULL for WSD */
    const char        *model;     /* Model name */
    uuid              uuid;       /* Device UUID */
    int               ifindex;    /* Network interface index */
    zeroconf_endpoint *endpoints; /* List of endpoints */

    /* The following fields are reserved for zeroconf core
     * and should not be used by discovery providers
     */
    zeroconf_device   *device;    /* Device the finding points to */
    ll_node           list_node;  /* Node in device's list of findings */
} zeroconf_finding;

/* Publish the zeroconf_finding.
 *
 * Memory, referred by the finding, remains owned by
 * caller, and caller is responsible to keep this
 * memory valid until zeroconf_finding_withdraw()
 * is called
 *
 * The 'endpoinds' field may be NULL. This mechanism is
 * used by WS-Discovery to notify zeroconf that scanning
 * for particular UUID has been finished, though without
 * success.
 */
void
zeroconf_finding_publish (zeroconf_finding *finding);

/* Withdraw the finding
 */
void
zeroconf_finding_withdraw (zeroconf_finding *finding);

/* Notify zeroconf subsystem that initial scan
 * for the method is done
 */
void
zeroconf_finding_done (ZEROCONF_METHOD method);

/* zeroconf_devinfo represents a device information
 */
typedef struct {
    const char        *ident;     /* Unique ident */
    const char        *name;      /* Human-friendly name */
    zeroconf_endpoint *endpoints; /* Device endpoints */
} zeroconf_devinfo;

/* Initialize ZeroConf
 */
SANE_Status
zeroconf_init (void);

/* Cleanup ZeroConf
 */
void
zeroconf_cleanup (void);

/* Get list of devices, in SANE format
 */
const SANE_Device**
zeroconf_device_list_get (void);

/* Free list of devices, returned by zeroconf_device_list_get()
 */
void
zeroconf_device_list_free (const SANE_Device **dev_list);

/* Lookup device by ident (ident is reported as SANE_Device::name)
 * by zeroconf_device_list_get())
 *
 * Caller becomes owner of resources (name and list of endpoints),
 * referred by the returned zeroconf_devinfo
 *
 * Caller must free these resources, using zeroconf_devinfo_free()
 */
zeroconf_devinfo*
zeroconf_devinfo_lookup (const char *ident);

/* Free zeroconf_devinfo, returned by zeroconf_devinfo_lookup()
 */
void
zeroconf_devinfo_free (zeroconf_devinfo *devinfo);

/* Check if initial scan still in progress
 */
bool
zeroconf_init_scan (void);

/* Create new zeroconf_endpoint. Newly created endpoint
 * takes ownership of uri string
 */
zeroconf_endpoint*
zeroconf_endpoint_new (ID_PROTO proto, http_uri *uri);

/* Create a copy of zeroconf_endpoint list
 */
zeroconf_endpoint*
zeroconf_endpoint_list_copy (const zeroconf_endpoint *list);

/* Free zeroconf_endpoint list
 */
void
zeroconf_endpoint_list_free (zeroconf_endpoint *list);

/* Sort list of endpoints
 */
zeroconf_endpoint*
zeroconf_endpoint_list_sort (zeroconf_endpoint *list);

/* Sort list of endpoints and remove duplicates
 */
zeroconf_endpoint*
zeroconf_endpoint_list_sort_dedup (zeroconf_endpoint *list);

/******************** MDNS Discovery ********************/
/* Initialize MDNS
 */
SANE_Status
mdns_init (void);

/* Cleanup MDNS
 */
void
mdns_cleanup (void);

/******************** WS-Discovery ********************/
/* Initialize WS-Discovery
 */
SANE_Status
wsdd_init (void);

/* Cleanup WS-Discovery
 */
void
wsdd_cleanup (void);

/******************** Device Management ********************/
/* Type device represents a scanner devise
 */
typedef struct device device;

/* Open a device
 */
device*
device_open (const char *name, SANE_Status *status);

/* Close the device
 */
void
device_close (device *dev);

/* Get device's logging context
 */
log_ctx*
device_log_ctx (device *dev);

/* Get option descriptor
 */
const SANE_Option_Descriptor*
device_get_option_descriptor (device *dev, SANE_Int option);

/* Get device option
 */
SANE_Status
device_get_option (device *dev, SANE_Int option, void *value);

/* Set device option
 */
SANE_Status
device_set_option (device *dev, SANE_Int option, void *value, SANE_Word *info);

/* Get current scan parameters
 */
SANE_Status
device_get_parameters (device *dev, SANE_Parameters *params);

SANE_Status
device_start (device *dev);

/* Cancel scanning operation
 */
void
device_cancel (device *dev);

/* Set I/O mode
 */
SANE_Status
device_set_io_mode (device *dev, SANE_Bool non_blocking);

/* Get select file descriptor
 */
SANE_Status
device_get_select_fd (device *dev, SANE_Int *fd);

/* Read scanned image
 */
SANE_Status
device_read (device *dev, SANE_Byte *data, SANE_Int max_len, SANE_Int *len);

/* Initialize device management
 */
SANE_Status
device_management_init (void);

/* Cleanup device management
 */
void
device_management_cleanup (void);

/******************** Scan Protocol handling ********************/
/* PROTO_OP represents operation
 */
typedef enum {
    PROTO_OP_NONE,    /* No operation */
    PROTO_OP_SCAN,    /* New scan */
    PROTO_OP_LOAD,    /* Load image */
    PROTO_OP_CHECK,   /* Check device status */
    PROTO_OP_CLEANUP, /* Cleanup after scan */
    PROTO_OP_FINISH   /* Finish scanning */
} PROTO_OP;

/* proto_scan_params represents scan parameters
 */
typedef struct {
    int           x_off, y_off; /* Scan area X/Y offset */
    int           wid, hei;     /* Scan area width and height */
    int           x_res, y_res; /* X/Y resolution */
    ID_SOURCE     src;          /* Desired source */
    ID_COLORMODE  colormode;    /* Desired color mode */
    ID_FORMAT     format;       /* Image format */
} proto_scan_params;

/* proto_ctx represents request context
 */
typedef struct {
    /* Common context */
    log_ctx              *log;            /* Logging context */
    struct proto_handler *proto;          /* Link to proto_handler */
    const devcaps        *devcaps;        /* Device capabilities */
    http_client          *http;           /* HTTP client for sending requests */
    http_uri             *base_uri;       /* HTTP base URI for protocol */
    http_uri             *base_uri_nozone;/* base_uri without IPv6 zone */
    proto_scan_params    params;          /* Scan parameters */
    const char           *location;       /* Image location */
    unsigned int         images_received; /* Total count of received images */

    /* Extra context for xxx_decode callbacks */
    const http_query     *query;    /* Passed to xxx_decode callbacks */

    /* Extra context for status_decode callback */
    PROTO_OP             failed_op;          /* Failed operation */
    int                  failed_http_status; /* Its HTTP status */
    int                  failed_attempt;     /* Retry count, 0-based */
} proto_ctx;

/* proto_result represents decoded query results
 */
typedef struct {
    PROTO_OP          next;   /* Next operation */
    int               delay;  /* In milliseconds */
    SANE_Status       status; /* Job status */
    error             err;    /* Error string, may be NULL */
    union {
        const char *location; /* Image location, protocol-specific */
        http_data  *image;    /* Image buffer */
    } data;
} proto_result;

/* proto represents scan protocol implementation
 */
typedef struct proto_handler proto_handler;
struct proto_handler {
    const char *name;  /* Protocol name (i.e., "eSCL", "WSD", "IPP") */

    /* Free protocol handler
     */
    void         (*free) (proto_handler *proto);

    /* Query and decode device capabilities
     */
    http_query*  (*devcaps_query) (const proto_ctx *ctx);
    error        (*devcaps_decode) (const proto_ctx *ctx, devcaps *caps);

    /* Initiate scanning and decode result.
     * On success, scan_decode must set ctx->data.location
     */
    http_query*  (*scan_query) (const proto_ctx *ctx);
    proto_result (*scan_decode) (const proto_ctx *ctx);

    /* Initiate image downloading and decode result.
     * On success, load_decode must set ctx->data.image
     */
    http_query*  (*load_query) (const proto_ctx *ctx);
    proto_result (*load_decode) (const proto_ctx *ctx);

    /* Request device status and decode result
     */
    http_query*  (*status_query) (const proto_ctx *ctx);
    proto_result (*status_decode) (const proto_ctx *ctx);

    /* Cleanup after scan
     */
    http_query*  (*cleanup_query) (const proto_ctx *ctx);

    /* Cancel scan in progress
     */
    http_query*  (*cancel_query) (const proto_ctx *ctx);
};

/* proto_handler_escl_new creates new eSCL protocol handler
 */
proto_handler*
proto_handler_escl_new (void);

/* proto_handler_wsd_new creates new WSD protocol handler
 */
proto_handler*
proto_handler_wsd_new (void);

/* proto_handler_new creates new protocol handler by protocol ID
 */
static inline proto_handler*
proto_handler_new (ID_PROTO proto)
{
    switch (proto) {
    case ID_PROTO_ESCL:
        return proto_handler_escl_new();
    case ID_PROTO_WSD:
        return proto_handler_wsd_new();
    default:
        return NULL;
    }
}

/******************** Image decoding ********************/
/* The window withing the image
 *
 * Note, all sizes and coordinates are in pixels
 */
typedef struct {
    int x_off, y_off;  /* Top-left corner offset */
    int wid, hei;      /* Image width and height */
} image_window;

/* Image decoder, with virtual methods
 */
typedef struct image_decoder image_decoder;
struct image_decoder {
    const char *content_type;
    void  (*free) (image_decoder *decoder);
    error (*begin) (image_decoder *decoder, const void *data, size_t size);
    void  (*reset) (image_decoder *decoder);
    int   (*get_bytes_per_pixel) (image_decoder *decoder);
    void  (*get_params) (image_decoder *decoder, SANE_Parameters *params);
    error (*set_window) (image_decoder *decoder, image_window *win);
    error (*read_line) (image_decoder *decoder, void *buffer);
};

/* Create JPEG image decoder
 */
image_decoder*
image_decoder_jpeg_new (void);

/* Create TIFF image decoder
 */
image_decoder*
image_decoder_tiff_new (void);

/* Create PNG image decoder
 */
image_decoder*
image_decoder_png_new (void);

/* Create DIB image decoder
 */
image_decoder*
image_decoder_dib_new (void);

/* Free image decoder
 */
static inline void
image_decoder_free (image_decoder *decoder)
{
    decoder->free(decoder);
}

/* Get content type
 */
static inline const char*
image_content_type (image_decoder *decoder)
{
    return decoder->content_type;
}

/* Begin image decoding. Decoder may assume that provided data
 * buffer remains valid during a whole decoding cycle
 */
static inline error
image_decoder_begin (image_decoder *decoder, const void *data, size_t size)
{
    return decoder->begin(decoder, data, size);
}

/* Reset image decoder after use. After reset, decoding of the
 * another image can be started
 */
static inline void
image_decoder_reset (image_decoder *decoder)
{
    decoder->reset(decoder);
}

/* Get bytes count per pixel
 */
static inline int
image_decoder_get_bytes_per_pixel (image_decoder *decoder)
{
    return decoder->get_bytes_per_pixel(decoder);
}

/* Get image parameters. Can be called at any time between
 * image_decoder_begin() and image_decoder_reset()
 *
 * Decoder must return an actual image parameters, regardless
 * of clipping window set by image_decoder_set_window()
 */
static inline void
image_decoder_get_params (image_decoder *decoder, SANE_Parameters *params)
{
    decoder->get_params(decoder, params);
}

/* Set window within the image. Only part of image that fits the
 * window needs to be decoded. Decoder may assume that window is
 * always within the actual image boundaries
 *
 * Note, if decoder cannot handle exact window boundaries, it
 * it must update window to keep actual values
 *
 * In particular, if decoder doesn't implement image clipping
 * at all, it is safe that decoder will simply set window boundaries
 * to contain an entire image
 */
static inline error
image_decoder_set_window (image_decoder *decoder, image_window *win)
{
    return decoder->set_window(decoder, win);
}

/* Read next line of image. Decoder may safely assume the provided
 * buffer is big enough to keep the entire line
 */
static inline error
image_decoder_read_line (image_decoder *decoder, void *buffer)
{
    return decoder->read_line(decoder, buffer);
}

/******************** Mathematical Functions ********************/
/* Find greatest common divisor of two positive integers
 */
SANE_Word
math_gcd (SANE_Word x, SANE_Word y);

/* Find least common multiple of two positive integers
 */
SANE_Word
math_lcm (SANE_Word x, SANE_Word y);

/* Find min of two words
 */
static inline SANE_Word
math_min (SANE_Word a, SANE_Word b)
{
    return a < b ? a : b;
}

/* Find max of two words
 */
static inline SANE_Word
math_max (SANE_Word a, SANE_Word b)
{
    return a > b ? a : b;
}

/* Bound integer within range
 */
static inline SANE_Word
math_bound (SANE_Word x, SANE_Word min, SANE_Word max)
{
    if (x < min) {
        return min;
    } else if (x > max) {
        return max;
    } else {
        return x;
    }
}

/* Compute x * mul / div, taking in account rounding
 * and integer overflow
 */
static inline SANE_Word
math_muldiv (SANE_Word x, SANE_Word mul, SANE_Word div)
{
    int64_t tmp;

    tmp = (int64_t) x * (int64_t) mul;
    tmp += div / 2;
    tmp /= div;

    return (SANE_Word) tmp;
}

/* Merge two ranges, if possible
 */
bool
math_range_merge (SANE_Range *out, const SANE_Range *r1, const SANE_Range *r2);

/* Choose nearest integer in range
 */
SANE_Word
math_range_fit (const SANE_Range *r, SANE_Word i);

/* Convert pixels to millimeters, using given resolution
 */
static inline SANE_Fixed
math_px2mm_res (SANE_Word px, SANE_Word res)
{
    return SANE_FIX((double) px * 25.4 / res);
}

/* Convert millimeters to pixels, using given resolution
 */
static inline SANE_Word
math_mm2px_res (SANE_Fixed mm, SANE_Word res)
{
    return (SANE_Word) roundl(SANE_UNFIX(mm) * res / 25.4);
}

/* Format millimeters, for printing
 */
char*
math_fmt_mm (SANE_Word mm, char buf[]);

/* Genrate random 32-bit integer
 */
uint32_t
math_rand_u32 (void);

/* Generate random integer in range [0...max], inclusively
 */
uint32_t
math_rand_max (uint32_t max);

/* Generate random integer in range [min...max], inclusively
 */
uint32_t
math_rand_range (uint32_t min, uint32_t max);

/* Count nonzero bits in 32-bit integer
 */
static inline unsigned int
math_popcount (unsigned int n)
{
    unsigned int count = (n & 0x55555555) + ((n >> 1) & 0x55555555);
    count = (count & 0x33333333) + ((count >> 2) & 0x33333333);
    count = (count & 0x0F0F0F0F) + ((count >> 4) & 0x0F0F0F0F);
    count = (count & 0x00FF00FF) + ((count >> 8) & 0x00FF00FF);
    return (count & 0x0000FFFF) + ((count >> 16) & 0x0000FFFF);
}

/******************** Logging ********************/
/* Initialize logging
 *
 * No log messages should be generated before this call
 */
void
log_init (void);

/* Cleanup logging
 *
 * No log messages should be generated after this call
 */
void
log_cleanup (void);

/* Notify logger that configuration is loaded and
 * logger can configure itself
 *
 * This is safe to generate log messages before log_configure()
 * is called. These messages will be buffered, and after
 * logger is configured, either written or abandoned, depending
 * on configuration
 */
void
log_configure (void);

/* log_ctx_new creates new logging context
 */
log_ctx*
log_ctx_new (const char *name);

/* log_ctx_free destroys logging context
 */
void
log_ctx_free (log_ctx *log);

/* Get protocol trace associated with logging context
 */
trace*
log_ctx_trace (log_ctx *log);

/* Write a debug message.
 */
void
log_debug (log_ctx *log, const char *fmt, ...);

/* Write a protocol trace message
 */
void
log_trace (log_ctx *log, const char *fmt, ...);

/* Write a block of data into protocol trace
 */
void
log_trace_data (log_ctx *log, const char *content_type,
        const void *bytes, size_t size);

/* Write an error message and terminate a program.
 */
void
log_panic (log_ctx *log, const char *fmt, ...);

/* Panic if assertion fails
 */
#define log_assert(log,expr)                                            \
     do {                                                               \
         if (!(expr)) {                                                 \
             log_panic(log,"file %s: line %d (%s): assertion failed: (%s)",\
                     __FILE__, __LINE__, __PRETTY_FUNCTION__, #expr);   \
         }                                                              \
     } while (0)

/* Panic if this code is reached
 */
#define log_internal_error(log)                                         \
     do {                                                               \
         log_panic(log,"file %s: line %d (%s): internal error",         \
                 __FILE__, __LINE__, __PRETTY_FUNCTION__);              \
     } while (0)

#endif

/* vim:ts=8:sw=4:et
 */
