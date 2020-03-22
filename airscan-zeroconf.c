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
/* Device state
 */
typedef struct zeroconf_devstate zeroconf_devstate;
struct zeroconf_devstate {
    const char        *name;       /* Device name */
    const char        *model;      /* Model name */
    ID_PROTO          proto;       /* Protocol in use */
    GPtrArray         *resolvers;  /* Pending resolvers */
    zeroconf_endpoint *endpoints;  /* Discovered endpoints */
    zeroconf_devstate *next;       /* Next devstate in the list */
    bool              initscan;    /* Device discovered during initial scan */
    bool              ready;       /* Done discovery for this device */
};

/* Static variables
 */
static zeroconf_devstate *zeroconf_devstate_list;
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

/* Print error message
 */
static void
zeroconf_perror (const char *name, AvahiProtocol protocol, const char *action)
{
    log_debug(NULL, "MDNS: %s \"%s\" (%s): %s",
            action, name, protocol == AVAHI_PROTO_INET ? "ipv4" : "ipv6",
            avahi_strerror(avahi_client_errno(zeroconf_avahi_client)));
}

/* Print event message
 */
static void
zeroconf_pevent (const char *name, AvahiProtocol protocol, const char *action)
{
    log_debug(NULL, "MDNS: %s \"%s\" (%s)",
            action, name, protocol == AVAHI_PROTO_INET ? "ipv4" : "ipv6");
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

/* Create new zeroconf_devstate structure
 */
static zeroconf_devstate*
zeroconf_devstate_new (const char *name)
{
    zeroconf_devstate *devstate = g_new0(zeroconf_devstate, 1);
    devstate->name = g_strdup(name);
    devstate->proto = ID_PROTO_ESCL; /* FIXME */
    devstate->resolvers = g_ptr_array_new_with_free_func(
        zeroconf_avahi_service_resolver_free_adapter);
    devstate->initscan = zeroconf_initscan;
    return devstate;
}

/* Free zeroconf_devstate structure
 */
static void
zeroconf_devstate_free (zeroconf_devstate *devstate)
{
    g_free((char*) devstate->name);
    g_free((char*) devstate->model);
    if (devstate->initscan || !devstate->ready) {
        zeroconf_initscan_dec();
    }
    g_ptr_array_free(devstate->resolvers, TRUE);
    zeroconf_endpoint_list_free(devstate->endpoints);
    g_free(devstate);
}

/* Get zeroconf_devstate: find existing or add a new one
 */
static zeroconf_devstate*
zeroconf_devstate_get (const char *name, bool add)
{
    zeroconf_devstate *devstate = zeroconf_devstate_list, *prev = NULL;

    /* Check for duplicated device */
    while (devstate != NULL) {
        if (!strcasecmp(devstate->name, name)) {
            return devstate;
        }

        prev = devstate;
        devstate = devstate->next;
    }

    if (!add) {
        return NULL;
    }

    /* Add new device state */
    devstate = zeroconf_devstate_new(name);
    if (devstate->initscan) {
        zeroconf_initscan_inc();
    }

    if (prev != NULL) {
        prev->next = devstate;
    } else {
        zeroconf_devstate_list = devstate;
    }

    return devstate;
}

/* Del a zeroconf_devstate
 */
static void
zeroconf_devstate_del (const char *name)
{
    zeroconf_devstate *devstate = zeroconf_devstate_list, *prev = NULL;

    /* Look for device state */
    while (devstate != NULL) {
        if (!strcasecmp(devstate->name, name)) {
            break;
        }

        prev = devstate;
        devstate = devstate->next;
    }

    if (devstate == NULL) {
        return;
    }

    /* Delete a device state */
    if (prev != NULL) {
        prev->next = devstate->next;
    } else {
        zeroconf_devstate_list = devstate->next;
    }

    zeroconf_devstate_free(devstate);
}

/* Delete all zeroconf_devstate
 */
static void
zeroconf_devstate_del_all (void)
{
    while (zeroconf_devstate_list != NULL) {
        zeroconf_devstate       *next = zeroconf_devstate_list->next;
        zeroconf_devstate_free(zeroconf_devstate_list);
        zeroconf_devstate_list = next;
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
zeroconf_endpoint_list_copy (zeroconf_endpoint *list)
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
zeroconf_endpoint_cmp (zeroconf_endpoint *e1, zeroconf_endpoint *e2)
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
    (void) protocol;
    (void) type;
    (void) domain;
    (void) host_name;
    (void) flags;

    zeroconf_devstate *devstate = userdata;
    zeroconf_endpoint *endpoint;
    AvahiStringList   *rs;
    const char        *rs_text = NULL;

    /* Handle event */
    switch (event) {
    case AVAHI_RESOLVER_FOUND:
        rs = avahi_string_list_find(txt, "rs");
        if (rs != NULL && rs->size > 3) {
            rs_text = (char*) (rs->text + 3);
        }

        if (devstate->model == NULL) {
            AvahiStringList *ty = avahi_string_list_find(txt, "ty");
            if (ty != NULL && ty->size > 3) {
                devstate->model = g_strdup((char*) (ty->text + 3));
            }
        }

        endpoint = zeroconf_endpoint_make_escl(addr, port, rs_text, interface);
        zeroconf_endpoint_list_prepend(&devstate->endpoints, endpoint);
        break;

    case AVAHI_RESOLVER_FAILURE:
        zeroconf_perror(name, protocol, "resolve");
        break;
    }

    /* Cleanup */
    g_ptr_array_remove(devstate->resolvers, r);
    if (devstate->resolvers->len == 0 && devstate->endpoints != NULL) {
        devstate->endpoints = zeroconf_endpoint_list_sort_dedup(
                devstate->endpoints);

        if (devstate->model == NULL) {
            /* Very unlikely, just paranoia */
            devstate->model = g_strdup(name);
        }

        if (conf.dbg_enabled) {
            zeroconf_endpoint *endpoint;
            int               i = 1;

            log_debug(NULL, "MDNS: \"%s\" model: \"%s\"", name, devstate->model);
            log_debug(NULL, "MDNS: \"%s\" endpoints:", name);

            for (endpoint = devstate->endpoints; endpoint != NULL;
                    endpoint = endpoint->next, i ++) {
                log_debug(NULL, "  %d: %s", i, http_uri_str(endpoint->uri));
            }
        }

        devstate->ready = true;
        if (devstate->initscan) {
            zeroconf_initscan_dec();
        }
    }
}

/* Look for device's static configuration
 */
static conf_device*
zeroconf_find_static_configuration (const char *name)
{
    conf_device *dev_conf;

    for (dev_conf = conf.devices; dev_conf != NULL; dev_conf = dev_conf->next) {
        if (!strcasecmp(dev_conf->name, name)) {
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
    (void) b;
    (void) flags;
    (void) userdata;

    zeroconf_devstate *devstate;

    switch (event) {
    case AVAHI_BROWSER_NEW:
        zeroconf_pevent(name, protocol, "found");

        /* Ignore manually configured devices */
        conf_device *dev_conf = zeroconf_find_static_configuration(name);
        if (dev_conf != NULL) {
            const char *msg;

            if (dev_conf->uri != NULL) {
                msg = "ignored statically configured";
            } else {
                msg = "ignored disabled";
            }

            zeroconf_pevent(name, protocol, msg);
            return;
        }

        /* Add a device (or lookup for already added) */
        devstate = zeroconf_devstate_get(name, true);

        /* Initiate resolver */
        AvahiServiceResolver *r;
        r = avahi_service_resolver_new(zeroconf_avahi_client, interface,
                protocol, name, type, domain, AVAHI_PROTO_UNSPEC, 0,
                zeroconf_avahi_resolver_callback, devstate);

        if (r == NULL) {
            zeroconf_perror(name, protocol, "resolve");
            zeroconf_avahi_client_restart_defer();
            break;
        }

        /* Attach resolver to device state */
        g_ptr_array_add(devstate->resolvers, r);
        break;

    case AVAHI_BROWSER_REMOVE:
        zeroconf_pevent(name, protocol, "removed");
        zeroconf_devstate_del(name);
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
}

/* Stop service browser
 */
static void
zeroconf_avahi_browser_stop (void)
{
    if (zeroconf_avahi_browser != NULL) {
        zeroconf_devstate_del_all();
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
        zeroconf_devstate_del_all();

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
    size_t            dev_count, dev_count_static = 0;
    conf_device       *dev_conf;
    const SANE_Device **dev_list;
    zeroconf_devstate *devstate;

    /* Wait until device table is ready */
    zeroconf_initscan_wait();

    /* Compute table size */
    dev_count = 0;

    for (dev_conf = conf.devices; dev_conf != NULL; dev_conf = dev_conf->next) {
        dev_count ++;
    }

    for (devstate = zeroconf_devstate_list; devstate != NULL;
            devstate = devstate->next) {
        if (devstate->ready) {
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

        info->name = g_strdup(dev_conf->name);
        info->vendor = g_strdup(proto);
        info->model = g_strdup(dev_conf->name); // FIXME
        info->type = g_strdup_printf("%s network scanner", proto);
    }

    dev_count_static = dev_count;

    for (devstate = zeroconf_devstate_list; devstate != NULL;
            devstate = devstate->next) {
        if (devstate->ready) {
            SANE_Device *info = g_new0(SANE_Device, 1);
            const char  *proto = id_proto_name(devstate->proto);

            dev_list[dev_count ++] = info;

            info->name = g_strdup(devstate->name);
            info->vendor = g_strdup(proto);
            if (conf.model_is_netname) {
                info->model = g_strdup(devstate->name);
            } else {
                info->model = g_strdup(devstate->model);
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


/* Lookup device by name.
 *
 * Caller becomes owner of returned list of endpoints, and responsible
 * to free the list.
 */
zeroconf_endpoint*
zeroconf_device_lookup (const char *name)
{
    conf_device       *dev_conf;
    zeroconf_devstate *devstate;

    /* Try static first */
    dev_conf = zeroconf_find_static_configuration(name);
    if (dev_conf != NULL) {
        return zeroconf_endpoint_new(dev_conf->proto,
            http_uri_clone(dev_conf->uri));
    }

    /* Lookup a dynamic table */
    devstate = zeroconf_devstate_get(name, false);
    if (devstate != NULL && devstate->ready) {
        return zeroconf_endpoint_list_copy(devstate->endpoints);
    }

    return NULL;
}

/* vim:ts=8:sw=4:et
 */
