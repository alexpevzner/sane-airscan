/* AirScan (a.k.a. eSCL) backend for SANE
 *
 * Copyright (C) 2019 and up by Alexander Pevzner (pzz@apevzner.com)
 * See LICENSE for license terms and conditions
 *
 * ZeroConf (device discovery)
 */

#include "airscan.h"

#include <arpa/inet.h>

#include <avahi-client/client.h>
#include <avahi-client/lookup.h>
#include <avahi-common/error.h>

#include <string.h>
#include <stdarg.h>

/******************** Constants *********************/
/* Service types we are interested in
 */
#define ZEROCONF_SERVICE_USCAN                  "_uscan._tcp"

/* If failed, AVAHI client will be automatically
 * restarted after the following timeout expires,
 * in seconds
 */
#define ZEROCONF_AVAHI_CLIENT_RESTART_TIMEOUT   1

/* Max time to wait until device table is ready, in seconds
 */
#define ZEROCONF_READY_TIMEOUT                  5

/******************** Local Types *********************/
/* zeroconf_device represents a single device
 */
typedef struct {
    uuid              uuid;                     /* Device UUID */
    const char        *name;                    /* Device name */
    const char        *model;                   /* Model name */
    unsigned int      refcnt;                   /* Reference count */
    ll_node           node_list;                /* In zeroconf_device_list */
    zeroconf_endpoint *endpoints[NUM_ID_PROTO]; /* Endpoints, by protocol */
} zeroconf_device;

/* zeroconf_mdns_state represents MDNS discovery state for
 * a device. zeroconf_mdns_state is bound to device name
 * and network interface
 */
typedef struct {
    zeroconf_device   *device;     /* Owning device */
    const char        *name;       /* Device name */
    int               scope;       /* Scope (interface index) */
    const char        *model;      /* Model name */
    uuid              uuid;        /* Device UUID */
    GPtrArray         *resolvers;  /* Array of pending *AvahiServiceResolver */
    zeroconf_endpoint *endpoints;  /* Discovered endpoints */
    ll_node           node_list;   /* In zeroconf_mdns_state_list */
    bool              initscan;    /* Device discovered during initial scan */
    bool              ready;       /* Done discovery for this device */
} zeroconf_mdns_state;

/* Static variables
 */
static ll_head zeroconf_device_list;
static ll_head zeroconf_mdns_state_list;
static AvahiGLibPoll *zeroconf_avahi_glib_poll;
static const AvahiPoll *zeroconf_avahi_poll;
static AvahiTimeout *zeroconf_avahi_restart_timer;
static AvahiClient *zeroconf_avahi_client;
static AvahiServiceBrowser *zeroconf_avahi_browser;
static bool zeroconf_initscan;
static int zeroconf_initscan_count;
static GCond zeroconf_initscan_cond;

/* Forward declarations
 */
static void
zeroconf_avahi_client_start (void);

static void
zeroconf_avahi_client_restart_defer (void);

/* Print debug message
 */
static void
zeroconf_debug (const char *name, AvahiProtocol protocol, const char *action,
        const char *fmt, ...)
{
    char       prefix[128], message[1024];
    va_list    ap;
    const char *af = protocol == AVAHI_PROTO_INET ? "ipv4" : "ipv6";
    int        n;

    n = snprintf(prefix, sizeof(prefix), "%s/%s", action, af);
    if (name != NULL) {
        snprintf(prefix + n, sizeof(prefix) - n, " \"%s\"", name);
    }

    va_start(ap, fmt);
    vsnprintf(message, sizeof(message) - n, fmt, ap);
    va_end(ap);

    log_debug(NULL, "MDNS: %s: %s", prefix, message);
}

/* Print error message
 */
static void
zeroconf_perror (const char *name, AvahiProtocol protocol, const char *action)
{
    zeroconf_debug(name, protocol, action,
            avahi_strerror(avahi_client_errno(zeroconf_avahi_client)));
}


/* Get AvahiResolverEvent name, for debugging
 */
static const char*
zeroconf_avahi_resolver_event_name (AvahiResolverEvent e)
{
    static char buf[64];

    switch (e) {
    case AVAHI_RESOLVER_FOUND:   return "AVAHI_RESOLVER_FOUND";
    case AVAHI_RESOLVER_FAILURE: return "AVAHI_RESOLVER_FAILURE";
    }

    /* Safe, because used only from the work thread */
    sprintf(buf, "AVAHI_RESOLVER_UNKNOWN(%d)", e);
    return buf;
}

/* Get AvahiBrowserEvent name, for debugging
 */
static const char*
zeroconf_avahi_browser_event_name (AvahiBrowserEvent e)
{
    static char buf[64];

    switch (e) {
    case AVAHI_BROWSER_NEW:             return "AVAHI_BROWSER_NEW";
    case AVAHI_BROWSER_REMOVE:          return "AVAHI_BROWSER_REMOVE";
    case AVAHI_BROWSER_CACHE_EXHAUSTED: return "AVAHI_BROWSER_CACHE_EXHAUSTED";
    case AVAHI_BROWSER_ALL_FOR_NOW:     return "AVAHI_BROWSER_ALL_FOR_NOW";
    case AVAHI_BROWSER_FAILURE:         return "AVAHI_BROWSER_FAILURE";
    }

    /* Safe, because used only from the work thread */
    sprintf(buf, "AVAHI_BROWSER_UNKNOWN(%d)", e);
    return buf;
}

/* Get AvahiClientState name, for debugging
 */
static const char*
zeroconf_avahi_client_state_name (AvahiClientState s)
{
    static char buf[64];

    switch (s) {
    case AVAHI_CLIENT_S_REGISTERING: return "AVAHI_CLIENT_S_REGISTERING";
    case AVAHI_CLIENT_S_RUNNING:     return "AVAHI_CLIENT_S_RUNNING";
    case AVAHI_CLIENT_S_COLLISION:   return "AVAHI_CLIENT_S_COLLISION";
    case AVAHI_CLIENT_FAILURE:       return "AVAHI_CLIENT_FAILURE";
    case AVAHI_CLIENT_CONNECTING:    return "AVAHI_CLIENT_CONNECTING";
    }

    /* Safe, because used only from the work thread */
    sprintf(buf, "AVAHI_BROWSER_UNKNOWN(%d)", s);
    return buf;
}

/* Increment count of initial scan tasks
 */
static void
zeroconf_initscan_inc (void)
{
    zeroconf_initscan_count ++;
}

/* Decrement count if initial scan tasks
 */
static void
zeroconf_initscan_dec (void)
{
    log_assert(NULL, zeroconf_initscan_count > 0);
    zeroconf_initscan_count --;
    if (zeroconf_initscan_count == 0) {
        g_cond_broadcast(&zeroconf_initscan_cond);
    }
}

/* Wait intil initial scan is done
 */
static void
zeroconf_initscan_wait (void)
{
    gint64            timeout;

    timeout = g_get_monotonic_time() +
        ZEROCONF_READY_TIMEOUT * G_TIME_SPAN_SECOND;

    while (zeroconf_initscan_count != 0) {
        eloop_cond_wait_until(&zeroconf_initscan_cond, timeout);
    }
}

/* avahi_service_resolver_free adapter for GDestroyNotify
 */
static void
zeroconf_avahi_service_resolver_free_adapter(gpointer p)
{
    avahi_service_resolver_free(p);
}

/* Add new zeroconf_device
 */
static zeroconf_device*
zeroconf_device_add (uuid uuid, const char *name, const char *model)
{
    zeroconf_device *device = g_new0(zeroconf_device, 1);
    device->uuid = uuid;
    device->name = g_strdup(name);
    device->model = g_strdup(model);
    device->refcnt = 1;
    ll_push_end(&zeroconf_device_list, &device->node_list);
    return device;
}

/* Ref the zeroconf_device
 */
static inline void
zeroconf_device_ref (zeroconf_device *device)
{
    device->refcnt ++;
}

/* Unref zeroconf_device
 */
static void
zeroconf_device_unref (zeroconf_device *device)
{
    log_assert(NULL, device->refcnt > 0);

    device->refcnt --;
    if (device->refcnt == 0) {
        ll_del(&device->node_list);
        g_free((char*) device->name);
        g_free((char*) device->model);
        g_free(device);
    }
}

/* Find zeroconf_device by UUID
 */
static zeroconf_device*
zeroconf_device_find (uuid uuid)
{
    ll_node *node;

    for (LL_FOR_EACH(node, &zeroconf_device_list)) {
        zeroconf_device *device;
        device = OUTER_STRUCT(node, zeroconf_device, node_list);
        if (uuid_equal(device->uuid, uuid)) {
            return device;
        }
    }

    return NULL;
}

/* Find zeroconf_device by ident
 */
static zeroconf_device*
zeroconf_device_find_by_ident (const char *ident)
{
    ll_node *node;

    for (LL_FOR_EACH(node, &zeroconf_device_list)) {
        zeroconf_device *device;
        device = OUTER_STRUCT(node, zeroconf_device, node_list);
        if (!strcmp(device->uuid.text, ident)) {
            return device;
        }
    }

    return NULL;
}

/* Perform appropriate actions when device is found.
 *
 * Note, On multi-homed machines the same device can be
 * found multiple times, if visible from different interfaces
 */
static void
zeroconf_device_found (ID_PROTO proto, zeroconf_mdns_state *mdns_state)
{
    zeroconf_device *device;

    /* Find or create a device */
    device = zeroconf_device_find(mdns_state->uuid);
    if (device != NULL) {
        zeroconf_device_ref(device);
    } else {
        device = zeroconf_device_add(mdns_state->uuid,
                mdns_state->name, mdns_state->model);
    }

    /* Link mdns_state to device */
    log_assert(NULL, mdns_state->device == NULL);
    mdns_state->device = device;

    /* Merge endpoints */
    device->endpoints[proto] = zeroconf_endpoint_list_merge(
        device->endpoints[proto], mdns_state->endpoints);
}

/* Perform appropriate actions when device has gone
 */
static void
zeroconf_device_gone (ID_PROTO proto, zeroconf_mdns_state *mdns_state)
{
    zeroconf_device *device = mdns_state->device;

    log_assert(NULL, device != NULL);

    /* Update endpoints */
    device->endpoints[proto] = zeroconf_endpoint_list_sub(
        device->endpoints[proto], mdns_state->endpoints);

    /* Unlink mdns_state from device */
    mdns_state->device = NULL;
    zeroconf_device_unref(device);
}

/* Create new zeroconf_mdns_state structure
 */
static zeroconf_mdns_state*
zeroconf_mdns_state_new (const char *name, int scope)
{
    zeroconf_mdns_state *mdns_state = g_new0(zeroconf_mdns_state, 1);
    mdns_state->name = g_strdup(name);
    mdns_state->scope = scope;
    mdns_state->resolvers = g_ptr_array_new_with_free_func(
        zeroconf_avahi_service_resolver_free_adapter);
    mdns_state->initscan = zeroconf_initscan;
    return mdns_state;
}

/* Free zeroconf_mdns_state structure
 */
static void
zeroconf_mdns_state_free (zeroconf_mdns_state *mdns_state)
{
    g_free((char*) mdns_state->name);
    g_free((char*) mdns_state->model);

    if (mdns_state->initscan && !mdns_state->ready) {
        zeroconf_initscan_dec();
    }

    g_ptr_array_free(mdns_state->resolvers, TRUE);
    zeroconf_endpoint_list_free(mdns_state->endpoints);
    g_free(mdns_state);
}

/* Find zeroconf_mdns_state
 */
static zeroconf_mdns_state*
zeroconf_mdns_state_find (const char *name, int scope)
{
    ll_node *node;

    for (LL_FOR_EACH(node, &zeroconf_mdns_state_list)) {
        zeroconf_mdns_state *mdns_state;
        mdns_state = OUTER_STRUCT(node, zeroconf_mdns_state, node_list);
        if (mdns_state->scope == scope && !strcasecmp(mdns_state->name, name)) {
            return mdns_state;
        }
    }

    return NULL;
}

/* Get zeroconf_mdns_state: find existing or add a new one
 */
static zeroconf_mdns_state*
zeroconf_mdns_state_get (const char *name, int scope)
{
    zeroconf_mdns_state *mdns_state;

    /* Check for duplicated device */
    mdns_state = zeroconf_mdns_state_find(name, scope);
    if (mdns_state != NULL) {
        return mdns_state;
    }

    /* Add new device state */
    mdns_state = zeroconf_mdns_state_new(name, scope);
    if (mdns_state->initscan) {
        zeroconf_initscan_inc();
    }

    ll_push_end(&zeroconf_mdns_state_list, &mdns_state->node_list);

    return mdns_state;
}

/* Del a zeroconf_mdns_state
 */
static void
zeroconf_mdns_state_del (zeroconf_mdns_state *mdns_state)
{
    ll_del(&mdns_state->node_list);
    zeroconf_mdns_state_free(mdns_state);
}

/* Delete all zeroconf_mdns_state
 */
static void
zeroconf_mdns_state_del_all (void)
{
    ll_node *node;

    while ((node = ll_pop_beg(&zeroconf_mdns_state_list)) != NULL) {
        zeroconf_mdns_state *mdns_state;
        mdns_state = OUTER_STRUCT(node, zeroconf_mdns_state, node_list);
        zeroconf_mdns_state_free(mdns_state);
    }
}

/* Create new zeroconf_endpoint. Newly created endpoint
 * takes ownership of uri string
 */
zeroconf_endpoint*
zeroconf_endpoint_new (ID_PROTO proto, http_uri *uri)
{
    zeroconf_endpoint *endpoint = g_new0(zeroconf_endpoint, 1);

    endpoint->proto = proto;
    endpoint->uri = uri;

    return endpoint;
}

/* Make zeroconf_endpoint for eSCL
 */
static zeroconf_endpoint*
zeroconf_endpoint_make_escl (const AvahiAddress *addr, uint16_t port, const char *rs,
        AvahiIfIndex interface)
{
    char     str_addr[128];
    int      rs_len;
    char     *u;
    http_uri *uri;

    if (addr->proto == AVAHI_PROTO_INET) {
        avahi_address_snprint(str_addr, sizeof(str_addr), addr);
    } else {
        size_t      len;

        str_addr[0] = '[';
        avahi_address_snprint(str_addr + 1, sizeof(str_addr) - 2, addr);
        len = strlen(str_addr);

        /* Connect to link-local address requires explicit scope */
        if (ip_is_linklocal(AF_INET6, addr->data.data)) {
            /* Percent character in the IPv6 address literal
             * needs to be properly escaped, so it becomes %25
             * See RFC6874 for details
             */
            len += sprintf(str_addr + len, "%%25%d", interface);
        }

        str_addr[len++] = ']';
        str_addr[len] = '\0';
    }

    /* Normalize rs */
    rs_len = 0;
    if (rs != NULL) {
        while (*rs == '/') {
            rs ++;
        }

        rs_len = (int) strlen(rs);
        while (rs_len != 0 && rs[rs_len - 1] == '/') {
            rs_len --;
        }
    }

    /* Make eSCL URL */
    if (rs == NULL) {
        /* Assume /eSCL by default */
        u = g_strdup_printf("http://%s:%d/eSCL/", str_addr, port);
    } else if (rs_len == 0) {
        /* Empty rs, avoid double '/' */
        u = g_strdup_printf("http://%s:%d/", str_addr, port);
    } else {
        u = g_strdup_printf("http://%s:%d/%.*s/", str_addr, port, rs_len, rs);
    }

    uri = http_uri_new(u, true);
    log_assert(NULL, uri != NULL);
    g_free(u);

    return zeroconf_endpoint_new(ID_PROTO_ESCL, uri);
}

/* Clone a single zeroconf_endpoint
 */
static zeroconf_endpoint*
zeroconf_endpoint_copy_single (const zeroconf_endpoint *endpoint)
{
    zeroconf_endpoint *endpoint2 = g_new0(zeroconf_endpoint, 1);

    *endpoint2 = *endpoint;
    endpoint2->uri = http_uri_clone(endpoint->uri);
    endpoint2->next = NULL;

    return endpoint2;
}


/* Free single zeroconf_endpoint
 */
static void
zeroconf_endpoint_free_single (zeroconf_endpoint *endpoint)
{
    http_uri_free(endpoint->uri);
    g_free(endpoint);
}

/* Create a copy of zeroconf_endpoint list
 */
zeroconf_endpoint*
zeroconf_endpoint_list_copy (const zeroconf_endpoint *list)
{
    zeroconf_endpoint *newlist = NULL, *last = NULL, *endpoint;

    while (list != NULL) {
        endpoint = zeroconf_endpoint_copy_single(list);
        if (last != NULL) {
            last->next = endpoint;
        } else {
            newlist = endpoint;
        }
        last = endpoint;
        list = list->next;
    }

    return newlist;
}

/* Free zeroconf_endpoint list
 */
void
zeroconf_endpoint_list_free (zeroconf_endpoint *list)
{
    while (list != NULL) {
        zeroconf_endpoint       *next = list->next;
        zeroconf_endpoint_free_single(list);
        list = next;
    }
}

/* Compare two endpoints , for sorting
 */
static int
zeroconf_endpoint_cmp (const zeroconf_endpoint *e1, const zeroconf_endpoint *e2)
{
    const struct sockaddr *a1 = http_uri_addr(e1->uri);
    const struct sockaddr *a2 = http_uri_addr(e2->uri);

    if (a1 != NULL && a2 != NULL) {
        bool ll1 = ip_sockaddr_is_linklocal(a1);
        bool ll2 = ip_sockaddr_is_linklocal(a2);

        /* Prefer normal addresses, rather that link-local */
        if (ll1 != ll2) {
            return ll1 ? 1 : -1;
        }

        /* Be in trend: prefer IPv6 addresses */
        if (a1->sa_family != a2->sa_family) {
            return a1->sa_family == AF_INET6 ? -1 : 1;
        }
    }

    /* Otherwise, sort lexicographically */
    return strcmp(http_uri_str(e1->uri), http_uri_str(e2->uri));
}

/* Revert zeroconf_endpoint list
 */
static zeroconf_endpoint*
zeroconf_endpoint_list_revert (zeroconf_endpoint *list)
{
    zeroconf_endpoint   *prev = NULL, *next;

    while (list != NULL) {
        next = list->next;
        list->next = prev;
        prev = list;
        list = next;
    }

    return prev;
}

/* Sort list of endpoints
 */
zeroconf_endpoint*
zeroconf_endpoint_list_sort (zeroconf_endpoint *list)
{
    zeroconf_endpoint *halves[2] = {NULL, NULL};
    int               half = 0;

    if (list->next == NULL) {
        return list;
    }

    /* Split list into halves */
    while (list != NULL) {
        zeroconf_endpoint *next = list->next;

        list->next = halves[half];
        halves[half] = list;

        half ^= 1;
        list = next;
    }

    /* Sort each half, recursively */
    for (half = 0; half < 2; half ++) {
        halves[half] = zeroconf_endpoint_list_sort(halves[half]);
    }

    /* Now merge the sorted halves */
    list = NULL;
    while (halves[0] != NULL || halves[1] != NULL) {
        zeroconf_endpoint *next;

        if (halves[0] == NULL) {
            half = 1;
        } else if (halves[1] == NULL) {
            half = 0;
        } else if (zeroconf_endpoint_cmp(halves[0], halves[1]) < 0) {
            half = 0;
        } else {
            half = 1;
        }

        next = halves[half]->next;
        halves[half]->next = list;
        list = halves[half];
        halves[half] = next;
    }

    /* And revert the list, as after merging it is reverted */
    return zeroconf_endpoint_list_revert(list);
}

/* Sort list of endpoints and remove duplicates
 */
zeroconf_endpoint*
zeroconf_endpoint_list_sort_dedup (zeroconf_endpoint *list)
{
    zeroconf_endpoint   *addr, *next;

    if (list == NULL) {
        return NULL;
    }

    list = zeroconf_endpoint_list_sort(list);

    addr = list;
    while ((next = addr->next) != NULL) {
        if (zeroconf_endpoint_cmp(addr, next) == 0) {
            addr->next = next->next;
            zeroconf_endpoint_free_single(next);
        } else {
            addr = next;
        }
    }

    return list;
}

/* Compute sum of two zeroconf_endpoint lists.
 * Old list is consumed and the new list is
 * returned. New list contains entries from
 * the both list, without duplicates
 *
 * Both input lists assumed to be sorted and de-duplicated
 * Returned list is also sorted and de-duplicated
 */
zeroconf_endpoint*
zeroconf_endpoint_list_merge (zeroconf_endpoint *list,
    const zeroconf_endpoint *addendum)
{
    zeroconf_endpoint *newlist = NULL, *last = NULL;

    while (list != NULL && addendum != NULL) {
        zeroconf_endpoint *next;
        int               cmp;

        cmp = zeroconf_endpoint_cmp(list, addendum);
        if (cmp > 0) {
            next = zeroconf_endpoint_copy_single(addendum);
            addendum = addendum->next;
        } else {
            next = list;
            list = list->next;
            next->next = NULL;

            if (cmp == 0) {
                addendum = addendum->next;
            }
        }

        if (last != NULL) {
            last->next = next;
        } else {
            newlist = next;
        }

        last = next;
    }

    if (addendum != NULL) {
        log_assert(NULL, list == NULL);
        list = zeroconf_endpoint_list_copy(addendum);
    }

    if (last != NULL) {
        last->next = list;
    } else {
        newlist = list;
    }

    return newlist;
}

/* Subtract two zeroconf_endpoint lists.
 * Old list is consumed and the new list is returned.
 * New list contains only entries, found in input
 * list and not found in subtrahend
 *
 * Both input lists assumed to be sorted and de-duplicated
 * Returned list is also sorted and de-duplicated
 */
zeroconf_endpoint*
zeroconf_endpoint_list_sub (zeroconf_endpoint *list,
    const zeroconf_endpoint *subtrahend)
{
    zeroconf_endpoint *newlist = NULL, *last = NULL;

    while (list != NULL && subtrahend != NULL) {
        zeroconf_endpoint *tmp;
        int               cmp;

        cmp = zeroconf_endpoint_cmp(list, subtrahend);
        if (cmp < 0) {
            tmp = list;
            list = list->next;
            tmp->next = NULL;

            if (last != NULL) {
                last->next = tmp;
            } else {
                newlist = tmp;
            }

            last = tmp;
        } else {
            subtrahend = subtrahend->next;
            if (cmp == 0) {
                tmp = list;
                list = list->next;
                zeroconf_endpoint_free_single(tmp);
            }
        }
    }

    if (last != NULL) {
        last->next = list;
    } else {
        newlist = list;
    }

    return newlist;
}

/* Prepend zeroconf_endpoint to the list
 */
static void
zeroconf_endpoint_list_prepend (zeroconf_endpoint **list,
        zeroconf_endpoint *endpoint)
{
    endpoint->next = *list;
    *list = endpoint;
}

/* AVAHI service resolver callback
 */
static void
zeroconf_avahi_resolver_callback (AvahiServiceResolver *r,
        AvahiIfIndex interface, AvahiProtocol protocol,
        AvahiResolverEvent event, const char *name, const char *type,
        const char *domain, const char *host_name, const AvahiAddress *addr,
        uint16_t port, AvahiStringList *txt, AvahiLookupResultFlags flags,
        void *userdata)
{
    zeroconf_mdns_state *mdns_state = userdata;
    zeroconf_endpoint   *endpoint;
    AvahiStringList     *rs;
    const char          *rs_text = NULL;

    (void) domain;
    (void) host_name;
    (void) flags;

    /* Print debug message */
    zeroconf_debug(name, protocol, "resolve", "%s %s",
            zeroconf_avahi_resolver_event_name(event), type);

    if (event == AVAHI_RESOLVER_FAILURE) {
        zeroconf_perror(name, protocol, "resolve");
    }

    /* Remove resolver from list of pending ones */
    if (!g_ptr_array_remove(mdns_state->resolvers, r)) {
        zeroconf_debug(name, protocol, "resolve", "spurious avahi callback");
        return;
    }

    /* Handle event */
    switch (event) {
    case AVAHI_RESOLVER_FOUND:
        rs = avahi_string_list_find(txt, "rs");
        if (rs != NULL && rs->size > 3) {
            rs_text = (char*) (rs->text + 3);
        }

        if (mdns_state->model == NULL) {
            AvahiStringList *ty = avahi_string_list_find(txt, "ty");
            if (ty != NULL && ty->size > 3) {
                mdns_state->model = g_strdup((char*) (ty->text + 3));
            }
        }

        if (!uuid_valid(mdns_state->uuid)) {
            AvahiStringList *uuid = avahi_string_list_find(txt, "uuid");
            if (uuid != NULL && uuid->size > 5) {
                mdns_state->uuid = uuid_parse((const char*) uuid->text + 5);
            }
        }

        endpoint = zeroconf_endpoint_make_escl(addr, port, rs_text, interface);
        zeroconf_endpoint_list_prepend(&mdns_state->endpoints, endpoint);
        break;

    case AVAHI_RESOLVER_FAILURE:
        break;
    }

    /* Perform appropriate actions, if resolving is done */
    if (mdns_state->resolvers->len != 0) {
        return;
    }

    mdns_state->endpoints = zeroconf_endpoint_list_sort_dedup(
            mdns_state->endpoints);

    if (mdns_state->model == NULL) {
        /* Very unlikely, just paranoia */
        mdns_state->model = g_strdup(mdns_state->name);
    }

    if (!uuid_valid(mdns_state->uuid)) {
        /* Paranoia too
         *
         * If device UUID is not available from DNS-SD (which
         * is very unlikely), we generate a synthetic UUID,
         * based on device name hash
         */
        mdns_state->uuid = uuid_hash(mdns_state->name);
    }

    if (conf.dbg_enabled) {
        zeroconf_endpoint *endpoint;
        int               i = 1;

        log_debug(NULL, "MDNS: \"%s\" model: \"%s\"", name, mdns_state->model);
        log_debug(NULL, "MDNS: \"%s\" uuid: %s", name, mdns_state->uuid.text);
        log_debug(NULL, "MDNS: \"%s\" endpoints:", name);

        for (endpoint = mdns_state->endpoints; endpoint != NULL;
                endpoint = endpoint->next, i ++) {
            log_debug(NULL, "  %d: %s", i, http_uri_str(endpoint->uri));
        }
    }

    mdns_state->ready = true;
    if (mdns_state->initscan) {
        zeroconf_initscan_dec();
    }

    zeroconf_device_found(ID_PROTO_ESCL, mdns_state);
}

/* Look for device's static configuration by device name
 */
static conf_device*
zeroconf_find_static_by_name (const char *name)
{
    conf_device *dev_conf;

    for (dev_conf = conf.devices; dev_conf != NULL; dev_conf = dev_conf->next) {
        if (!strcasecmp(dev_conf->name, name)) {
            return dev_conf;
        }
    }

    return NULL;
}

/* Look for device's static configuration by device ident
 */
static conf_device*
zeroconf_find_static_by_ident (const char *ident)
{
    conf_device *dev_conf;

    for (dev_conf = conf.devices; dev_conf != NULL; dev_conf = dev_conf->next) {
        if (!strcmp(dev_conf->uuid.text, ident)) {
            return dev_conf;
        }
    }

    return NULL;
}

/* AVAHI browser callback
 */
static void
zeroconf_avahi_browser_callback (AvahiServiceBrowser *b, AvahiIfIndex interface,
        AvahiProtocol protocol, AvahiBrowserEvent event,
        const char *name, const char *type, const char *domain,
        AvahiLookupResultFlags flags, void* userdata)
{
    zeroconf_mdns_state *mdns_state;
    conf_device         *dev_conf;

    (void) b;
    (void) flags;
    (void) userdata;

    /* Print debug message */
    zeroconf_debug(name, protocol, "browse", "%s",
            zeroconf_avahi_browser_event_name(event));

    if (event == AVAHI_BROWSER_FAILURE) {
        zeroconf_perror(name, protocol, "browse");
    }

    switch (event) {
    case AVAHI_BROWSER_NEW:
        /* Ignore manually configured devices */
        dev_conf = zeroconf_find_static_by_name(name);
        if (dev_conf != NULL) {
            const char *msg;

            if (dev_conf->uri != NULL) {
                msg = "ignored statically configured";
            } else {
                msg = "ignored disabled";
            }

            zeroconf_debug(name, protocol, "browse", msg);
            return;
        }

        /* Add a device (or lookup for already added) */
        mdns_state = zeroconf_mdns_state_get(name, interface);

        /* Initiate resolver */
        AvahiServiceResolver *r;
        r = avahi_service_resolver_new(zeroconf_avahi_client, interface,
                protocol, name, type, domain, AVAHI_PROTO_UNSPEC, 0,
                zeroconf_avahi_resolver_callback, mdns_state);

        if (r == NULL) {
            zeroconf_perror(name, protocol, "resolve");
            zeroconf_avahi_client_restart_defer();
            break;
        }

        /* Attach resolver to device state */
        g_ptr_array_add(mdns_state->resolvers, r);
        break;

    case AVAHI_BROWSER_REMOVE:
        mdns_state = zeroconf_mdns_state_find(name, interface);
        if (mdns_state != NULL) {
            zeroconf_device_gone(ID_PROTO_ESCL, mdns_state);
            zeroconf_mdns_state_del(mdns_state);
        }
        break;

    case AVAHI_BROWSER_FAILURE:
        zeroconf_avahi_client_restart_defer();
        break;

    case AVAHI_BROWSER_CACHE_EXHAUSTED:
        break;

    case AVAHI_BROWSER_ALL_FOR_NOW:
        log_debug(NULL, "MDNS: initial scan finished");

        if (zeroconf_initscan) {
            zeroconf_initscan = false;
            zeroconf_initscan_dec();
        }
        break;
    }
}

/* Start/restart service browser
 */
static void
zeroconf_avahi_browser_start (AvahiClient *client)
{
    log_assert(NULL, zeroconf_avahi_browser == NULL);

    zeroconf_avahi_browser = avahi_service_browser_new(client,
            AVAHI_IF_UNSPEC, AVAHI_PROTO_UNSPEC,
            ZEROCONF_SERVICE_USCAN, NULL,
            0, zeroconf_avahi_browser_callback, client);

    if (zeroconf_avahi_browser == NULL) {
        log_debug(NULL, "MDNS: avahi_service_browser_new: %s",
                avahi_strerror(avahi_client_errno(zeroconf_avahi_client)));
    }
}

/* Stop service browser
 */
static void
zeroconf_avahi_browser_stop (void)
{
    if (zeroconf_avahi_browser != NULL) {
        zeroconf_mdns_state_del_all();
        avahi_service_browser_free(zeroconf_avahi_browser);
        zeroconf_avahi_browser = NULL;
    }
}

/* AVAHI client callback
 */
static void
zeroconf_avahi_client_callback (AvahiClient *client, AvahiClientState state,
        void *userdata)
{
    (void) userdata;

    log_debug(NULL, "MDNS: %s", zeroconf_avahi_client_state_name(state));

    switch (state) {
    case AVAHI_CLIENT_S_REGISTERING:
    case AVAHI_CLIENT_S_RUNNING:
    case AVAHI_CLIENT_S_COLLISION:
        if (zeroconf_avahi_browser == NULL) {
            zeroconf_avahi_browser_start(client);
            if (zeroconf_avahi_browser == NULL) {
                zeroconf_avahi_client_restart_defer();
            }
        }
        break;

    case AVAHI_CLIENT_FAILURE:
        zeroconf_avahi_client_restart_defer();
        break;

    case AVAHI_CLIENT_CONNECTING:
        break;
    }
}

/* Timer for differed AVAHI client restart
 */
static void
zeroconf_avahi_restart_timer_callback(AvahiTimeout *t, void *userdata)
{
    (void) t;
    (void) userdata;

    zeroconf_avahi_client_start();
}

/* Stop AVAHI client
 */
static void
zeroconf_avahi_client_stop (void)
{
    if (zeroconf_avahi_client != NULL) {
        avahi_client_free(zeroconf_avahi_client);
        zeroconf_avahi_client = NULL;
    }
}

/* Start/restart the AVAHI client
 */
static void
zeroconf_avahi_client_start (void)
{
    int error;

    log_assert(NULL, zeroconf_avahi_client == NULL);

    zeroconf_avahi_client = avahi_client_new (zeroconf_avahi_poll,
        AVAHI_CLIENT_NO_FAIL, zeroconf_avahi_client_callback, NULL, &error);
}

/* Deferred client restart
 */
static void
zeroconf_avahi_client_restart_defer (void)
{
    struct timeval tv;

    zeroconf_avahi_browser_stop();
    zeroconf_avahi_client_stop();

    gettimeofday(&tv, NULL);
    tv.tv_sec += ZEROCONF_AVAHI_CLIENT_RESTART_TIMEOUT;
    zeroconf_avahi_poll->timeout_update(zeroconf_avahi_restart_timer, &tv);
}

/* Initialize ZeroConf
 */
SANE_Status
zeroconf_init (void)
{
    ll_init(&zeroconf_device_list);
    ll_init(&zeroconf_mdns_state_list);

    if (!conf.discovery) {
        log_debug(NULL, "MDNS: devices discovery disabled");
        return SANE_STATUS_GOOD;
    }

    zeroconf_avahi_glib_poll = eloop_new_avahi_poll();
    if (zeroconf_avahi_glib_poll == NULL) {
        return SANE_STATUS_NO_MEM;
    }

    zeroconf_avahi_poll = avahi_glib_poll_get(zeroconf_avahi_glib_poll);

    zeroconf_avahi_restart_timer =
            zeroconf_avahi_poll->timeout_new(zeroconf_avahi_poll, NULL,
                zeroconf_avahi_restart_timer_callback, NULL);

    if (zeroconf_avahi_restart_timer == NULL) {
        return SANE_STATUS_NO_MEM;
    }

    zeroconf_avahi_client_start();
    if (zeroconf_avahi_client == NULL) {
        return SANE_STATUS_NO_MEM;
    }

    g_cond_init(&zeroconf_initscan_cond);
    zeroconf_initscan = true;
    zeroconf_initscan_count = 1;

    return SANE_STATUS_GOOD;
}

/* Cleanup ZeroConf
 */
void
zeroconf_cleanup (void)
{
    if (zeroconf_avahi_glib_poll != NULL) {
        zeroconf_avahi_browser_stop();
        zeroconf_avahi_client_stop();
        zeroconf_mdns_state_del_all();

        if (zeroconf_avahi_restart_timer != NULL) {
            zeroconf_avahi_poll->timeout_free(zeroconf_avahi_restart_timer);
            zeroconf_avahi_restart_timer = NULL;
        }

        avahi_glib_poll_free(zeroconf_avahi_glib_poll);
        zeroconf_avahi_poll = NULL;
        zeroconf_avahi_glib_poll = NULL;
        g_cond_clear(&zeroconf_initscan_cond);
    }
}

/* Compare SANE_Device*, for qsort
 */
static int
zeroconf_device_list_qsort_cmp (const void *p1, const void *p2)
{
    return strcmp(((SANE_Device*) p1)->name, ((SANE_Device*) p2)->name);
}

/* Get list of devices, in SANE format
 */
const SANE_Device**
zeroconf_device_list_get (void)
{
    size_t              dev_count, dev_count_static = 0;
    conf_device         *dev_conf;
    const SANE_Device   **dev_list;
    ll_node             *node;

    /* Wait until device table is ready */
    zeroconf_initscan_wait();

    /* Compute table size */
    dev_count = 0;

    for (dev_conf = conf.devices; dev_conf != NULL; dev_conf = dev_conf->next) {
        dev_count ++;
    }

    for (LL_FOR_EACH(node, &zeroconf_device_list)) {
        zeroconf_device *device;

        device = OUTER_STRUCT(node, zeroconf_device, node_list);
        if (device->endpoints[ID_PROTO_ESCL] != NULL) {
            dev_count ++;
        }
    }

    /* Build list of devices */
    dev_list = g_new0(const SANE_Device*, dev_count + 1);
    dev_count = 0;

    for (dev_conf = conf.devices; dev_conf != NULL; dev_conf = dev_conf->next) {
        SANE_Device *info = g_new0(SANE_Device, 1);
        const char  *proto = id_proto_name(dev_conf->proto);

        dev_list[dev_count ++] = info;

        info->name = g_strdup(dev_conf->uuid.text);
        info->vendor = g_strdup(proto);
        info->model = g_strdup(dev_conf->name);
        info->type = g_strdup_printf("%s network scanner", proto);
    }

    dev_count_static = dev_count;

    for (LL_FOR_EACH(node, &zeroconf_device_list)) {
        zeroconf_device *device;

        device = OUTER_STRUCT(node, zeroconf_device, node_list);
        if (device->endpoints[ID_PROTO_ESCL] != NULL) {
            SANE_Device     *info = g_new0(SANE_Device, 1);
            const char      *proto = id_proto_name(ID_PROTO_ESCL); // FIXME

            dev_list[dev_count ++] = info;

            info->name = g_strdup(device->uuid.text);
            info->vendor = g_strdup(proto);
            if (conf.model_is_netname) {
                info->model = g_strdup(device->name);
            } else {
                info->model = g_strdup(device->model);
            }
            info->type = g_strdup_printf("%s network scanner", proto);
        }
    }

    qsort(dev_list + dev_count_static, dev_count - dev_count_static,
        sizeof(*dev_list), zeroconf_device_list_qsort_cmp);

    return dev_list;
}

/* Free list of devices, returned by zeroconf_device_list_get()
 */
void
zeroconf_device_list_free (const SANE_Device **dev_list)
{
    if (dev_list != NULL) {
        unsigned int       i;
        const SANE_Device *info;

        for (i = 0; (info = dev_list[i]) != NULL; i ++) {
            g_free((void*) info->name);
            g_free((void*) info->vendor);
            g_free((void*) info->model);
            g_free((void*) info->type);
            g_free((void*) info);
        }

        g_free(dev_list);
    }
}


/* Lookup device by ident (ident is reported as SANE_Device::name)
 * by zeroconf_device_list_get())
 *
 * Caller becomes owner of resources (name and list of endpoints),
 * referred by the returned zeroconf_devinfo
 *
 * Caller must free these resources, using zeroconf_devinfo_free()
 */
zeroconf_devinfo*
zeroconf_devinfo_lookup (const char *ident)
{
    conf_device      *dev_conf = NULL;
    zeroconf_device  *device = NULL;
    zeroconf_devinfo *devinfo;

    /* Lookup a device, static first */
    dev_conf = zeroconf_find_static_by_ident(ident);
    if (dev_conf == NULL) {
        device = zeroconf_device_find_by_ident(ident);
        if (device == NULL) {
            return NULL;
        }
    }

    /* Build a zeroconf_devinfo */
    devinfo = g_new0(zeroconf_devinfo, 1);
    if (dev_conf) {
        devinfo->uuid = dev_conf->uuid;
        devinfo->name = g_strdup(dev_conf->name);
        devinfo->endpoints = zeroconf_endpoint_new(dev_conf->proto,
            http_uri_clone(dev_conf->uri));
    } else {
        devinfo->uuid = device->uuid;
        devinfo->name = g_strdup(device->name);
        devinfo->endpoints = zeroconf_endpoint_list_copy(
                device->endpoints[ID_PROTO_ESCL]);
    }

    return devinfo;
}

/* Free zeroconf_devinfo, returned by zeroconf_devinfo_lookup()
 */
void
zeroconf_devinfo_free (zeroconf_devinfo *devinfo)
{
    g_free((char*) devinfo->name);
    zeroconf_endpoint_list_free(devinfo->endpoints);
    g_free(devinfo);
}

/* vim:ts=8:sw=4:et
 */
