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
/* Service type to look for
 */
#define AIRSCAN_ZEROCONF_SERVICE_TYPE           "_uscan._tcp"

/* If failed, AVAHI client will be automatically
 * restarted after the following timeout expires,
 * in seconds
 */
#define AIRSCAN_AVAHI_CLIENT_RESTART_TIMEOUT    1

/******************** Local Types *********************/
/* Device state
 */
typedef struct zeroconf_devstate zeroconf_devstate;
struct zeroconf_devstate {
    const char        *name;       /* Device name */
    GPtrArray         *resolvers;  /* Pending resolvers */
    zeroconf_addrinfo *addresses;  /* Discovered addresses */
    zeroconf_devstate *next;       /* Next devstate in the list */
    bool              reported;    /* Device reported to device manager */
    bool              init_scan;   /* Device found during initial scan */
};

/* Static variables
 */
static zeroconf_devstate *zeroconf_devstate_list;
static AvahiGLibPoll *zeroconf_avahi_glib_poll;
static const AvahiPoll *zeroconf_avahi_poll;
static AvahiTimeout *zeroconf_avahi_restart_timer;
static AvahiClient *zeroconf_avahi_client;
static AvahiServiceBrowser *zeroconf_avahi_browser;
static bool zeroconf_avahi_browser_init_scan;

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
    devstate->resolvers = g_ptr_array_new_with_free_func(
        zeroconf_avahi_service_resolver_free_adapter);
    devstate->init_scan = zeroconf_avahi_browser_init_scan;
    return devstate;
}

/* Free zeroconf_devstate structure
 */
static void
zeroconf_devstate_free (zeroconf_devstate *devstate)
{
    g_free((char*) devstate->name);
    g_ptr_array_free(devstate->resolvers, TRUE);
    zeroconf_addrinfo_list_free(devstate->addresses);
    g_free(devstate);
}

/* Add new zeroconf_devstate
 */
static zeroconf_devstate*
zeroconf_devstate_add (const char *name)
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

    /* Add new device state */
    devstate = zeroconf_devstate_new(name);

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
    if (devstate->reported) {
        device_event_removed(name);
    }

    if (prev != NULL) {
        prev->next = devstate->next;
    } else {
        zeroconf_devstate_list = devstate->next;
    }

    zeroconf_devstate_free(devstate);
}

/* Delete all zeroconf_devstate and optionally notify a device manager
 */
static void
zeroconf_devstate_del_all (bool notify)
{
    while (zeroconf_devstate_list != NULL) {
        zeroconf_devstate       *next = zeroconf_devstate_list->next;
        if (notify && zeroconf_devstate_list->reported) {
            device_event_removed(zeroconf_devstate_list->name);
        }
        zeroconf_devstate_free(zeroconf_devstate_list);
        zeroconf_devstate_list = next;
    }
}

/* Create new zeroconf_addrinfo
 */
static zeroconf_addrinfo*
zeroconf_addrinfo_new (const AvahiAddress *addr, uint16_t port, const char *rs,
        AvahiIfIndex interface)
{
    zeroconf_addrinfo *addrinfo = g_new0(zeroconf_addrinfo, 1);
    char              str_addr[128];
    int               rs_len;

    if (addr->proto == AVAHI_PROTO_INET) {
        /* 169.254.0.0/16 */
        if ((ntohl(addr->data.ipv4.address) & 0xffff0000) == 0xa9fe0000) {
            addrinfo->linklocal = true;
        }

        avahi_address_snprint(str_addr, sizeof(str_addr), addr);
    } else {
        static char link_local[8] = {0xfe, 0x80};
        size_t      len;

        addrinfo->ipv6 = true;
        addrinfo->linklocal = !memcmp(addr->data.ipv6.address,
            link_local, sizeof(link_local));

        str_addr[0] = '[';
        avahi_address_snprint(str_addr + 1, sizeof(str_addr) - 2, addr);
        len = strlen(str_addr);

        /* Connect to link-local address requires explicit scope */
        if (addrinfo->linklocal) {
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
    while (*rs == '/') {
        rs ++;
    }

    rs_len = (int) strlen(rs);
    while (rs_len != 0 && rs[rs_len - 1] == '/') {
        rs_len --;
    }

    /* Make eSCL URL */
    if (rs == NULL) {
        /* Assume /eSCL by default */
        addrinfo->uri = g_strdup_printf("http://%s:%d/eSCL/", str_addr, port);
    } else if (rs_len == 0) {
        /* Empty rs, avoid double '/' */
        addrinfo->uri = g_strdup_printf("http://%s:%d/", str_addr, port);
    } else {
        addrinfo->uri = g_strdup_printf("http://%s:%d/%.*s/", str_addr, port,
                rs_len, rs);
    }

    return addrinfo;
}

/* Clone a single zeroconf_addrinfo
 */
static zeroconf_addrinfo*
zeroconf_addrinfo_copy_single (const zeroconf_addrinfo *addrinfo)
{
    zeroconf_addrinfo *addrinfo2 = g_new0(zeroconf_addrinfo, 1);

    *addrinfo2 = *addrinfo2;
    addrinfo2->uri = g_strdup(addrinfo->uri);
    addrinfo2->next = NULL;

    return addrinfo2;
}


/* Free single zeroconf_addrinfo
 */
static void
zeroconf_addrinfo_free_single (zeroconf_addrinfo *addrinfo)
{
    g_free((char*) addrinfo->uri);
    g_free(addrinfo);
}

/* Create a copy of zeroconf_addrinfo list
 */
zeroconf_addrinfo*
zeroconf_addrinfo_list_copy (zeroconf_addrinfo *list)
{
    zeroconf_addrinfo *newlist = NULL, *last = NULL, *addrinfo;

    while (list != NULL) {
        addrinfo = zeroconf_addrinfo_copy_single(list);
        if (last != NULL) {
            last->next = addrinfo;
        } else {
            newlist = addrinfo;
        }
        last = addrinfo;
        list = list->next;
    }

    return newlist;
}

/* Free zeroconf_addrinfo list
 */
void
zeroconf_addrinfo_list_free (zeroconf_addrinfo *list)
{
    while (list != NULL) {
        zeroconf_addrinfo       *next = list->next;
        zeroconf_addrinfo_free_single(list);
        list = next;
    }
}

/* Compare two zeroconf_addrinfo addresses, for sorting
 */
static int
zeroconf_addrinfo_cmp (zeroconf_addrinfo *a1, zeroconf_addrinfo *a2)
{
    /* Prefer normal addresses, rather that link-local */
    if (a1->linklocal != a2->linklocal) {
        return (int) a1->linklocal - (int) a2->linklocal;
    }

    /* Be in trend: prefer IPv6 addresses */
    if (a1->ipv6 != a2->ipv6) {
        return (int) a2->ipv6 - (int) a1->ipv6;
    }

    /* Otherwise, sort lexicographically */
    return strcmp(a1->uri, a2->uri);
}

/* Revert zeroconf_addrinfo list
 */
static zeroconf_addrinfo*
zeroconf_addrinfo_list_revert (zeroconf_addrinfo *list)
{
    zeroconf_addrinfo   *prev = NULL, *next;

    while (list != NULL) {
        next = list->next;
        list->next = prev;
        prev = list;
        list = next;
    }

    return prev;
}

/* Sort list of addresses
 */
static zeroconf_addrinfo*
zeroconf_addrinfo_list_sort (zeroconf_addrinfo *list)
{
    zeroconf_addrinfo *halves[2] = {NULL, NULL};
    int               half = 0;

    if (list->next == NULL) {
        return list;
    }

    /* Split list into halves */
    while (list != NULL) {
        zeroconf_addrinfo *next = list->next;

        list->next = halves[half];
        halves[half] = list;

        half ^= 1;
        list = next;
    }

    /* Sort each half, recursively */
    for (half = 0; half < 2; half ++) {
        halves[half] = zeroconf_addrinfo_list_sort(halves[half]);
    }

    /* Now merge the sorted halves */
    list = NULL;
    while (halves[0] != NULL || halves[1] != NULL) {
        zeroconf_addrinfo *next;

        if (halves[0] == NULL) {
            half = 1;
        } else if (halves[1] == NULL) {
            half = 0;
        } else if (zeroconf_addrinfo_cmp(halves[0], halves[1]) < 0) {
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
    return zeroconf_addrinfo_list_revert(list);
}

/* Sort list of addresses and remove duplicates
 */
static zeroconf_addrinfo*
zeroconf_addrinfo_list_sort_dedup (zeroconf_addrinfo *list)
{
    zeroconf_addrinfo   *addr, *next;

    if (list == NULL) {
        return NULL;
    }

    list = zeroconf_addrinfo_list_sort(list);

    addr = list;
    while ((next = addr->next) != NULL) {
        if (zeroconf_addrinfo_cmp(addr, next) == 0) {
            addr->next = next->next;
            zeroconf_addrinfo_free_single(next);
        } else {
            addr = next;
        }
    }

    return list;
}

/* Prepend zeroconf_addrinfo to the list
 */
static void
zeroconf_addrinfo_list_prepend (zeroconf_addrinfo **list,
        zeroconf_addrinfo *addrinfo)
{
    addrinfo->next = *list;
    *list = addrinfo;
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
    zeroconf_addrinfo *addrinfo;
    AvahiStringList   *rs;
    const char        *rs_text = NULL;

    /* Handle event */
    switch (event) {
    case AVAHI_RESOLVER_FOUND:
        rs = avahi_string_list_find(txt, "rs");
        if (rs != NULL && rs->size > 3) {
            rs_text = (char*) (rs->text + 3);
        }

        addrinfo = zeroconf_addrinfo_new(addr, port, rs_text, interface);
        zeroconf_addrinfo_list_prepend(&devstate->addresses, addrinfo);
        break;

    case AVAHI_RESOLVER_FAILURE:
        zeroconf_perror(name, protocol, "resolve");
        break;
    }

    /* Cleanup */
    g_ptr_array_remove(devstate->resolvers, r);

    if (devstate->resolvers->len == 0 && devstate->addresses != NULL) {
        devstate->addresses = zeroconf_addrinfo_list_sort_dedup(
                devstate->addresses);

        if (conf.dbg_enabled) {
            zeroconf_addrinfo *addrinfo;
            int               i = 1;

            log_debug(NULL, "MDNS: \"%s\" addresses resolved:", name);

            for (addrinfo = devstate->addresses; addrinfo != NULL;
                    addrinfo = addrinfo->next, i ++) {
                log_debug(NULL, "  %d: %s", i, addrinfo->uri);
            }
        }

        devstate->reported = true;
        device_event_found(devstate->name, devstate->init_scan,
                devstate->addresses);
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
        devstate = zeroconf_devstate_add(name);

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

        zeroconf_avahi_browser_init_scan = false;
        device_event_init_scan_finished();
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
            AIRSCAN_ZEROCONF_SERVICE_TYPE, NULL,
            0, zeroconf_avahi_browser_callback, client);
}

/* Stop service browser
 */
static void
zeroconf_avahi_browser_stop (void)
{
    if (zeroconf_avahi_browser != NULL) {
        zeroconf_devstate_del_all(true);
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
    tv.tv_sec += AIRSCAN_AVAHI_CLIENT_RESTART_TIMEOUT;
    zeroconf_avahi_poll->timeout_update(zeroconf_avahi_restart_timer, &tv);

    if (zeroconf_avahi_browser_init_scan) {
        zeroconf_avahi_browser_init_scan = false;
        device_event_init_scan_finished();
    }
}

/* Initialize ZeroConf
 */
SANE_Status
zeroconf_init (void)
{
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

    zeroconf_avahi_browser_init_scan = true;

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
        zeroconf_devstate_del_all(false);

        if (zeroconf_avahi_restart_timer != NULL) {
            zeroconf_avahi_poll->timeout_free(zeroconf_avahi_restart_timer);
            zeroconf_avahi_restart_timer = NULL;
        }

        avahi_glib_poll_free(zeroconf_avahi_glib_poll);
        zeroconf_avahi_poll = NULL;
        zeroconf_avahi_glib_poll = NULL;
        zeroconf_avahi_browser_init_scan = false;
    }
}

/* Check if initial scan still in progress
 */
bool
zeroconf_init_scan (void)
{
    if (zeroconf_avahi_browser_init_scan) {
        return true;
    }

    zeroconf_devstate *devstate;
    for (devstate = zeroconf_devstate_list; devstate != NULL;
            devstate = devstate->next) {
        if (devstate->init_scan && !devstate->reported) {
            return true;
        }
    }

    return false;
}

/* vim:ts=8:sw=4:et
 */
