/* AirScan (a.k.a. eSCL) backend for SANE
 *
 * Copyright (C) 2019 and up by Alexander Pevzner (pzz@apevzner.com)
 * See LICENSE for license terms and conditions
 *
 * MDNS device discovery
 */

#include "airscan.h"

#include <arpa/inet.h>

#include <avahi-client/client.h>
#include <avahi-client/lookup.h>
#include <avahi-common/error.h>

#include <string.h>
#include <stdarg.h>

/******************** Constants *********************/
/* If failed, AVAHI client will be automatically
 * restarted after the following timeout expires,
 * in seconds
 */
#define MDNS_AVAHI_CLIENT_RESTART_TIMEOUT       1

/* Max time to wait until device table is ready, in seconds
 */
#define MDNS_READY_TIMEOUT                      5

/******************** Local Types *********************/
/* mdns_finding represents zeroconf_finding for MDNS
 * device discovery
 */
typedef struct {
    zeroconf_finding  finding;     /* Base class */
    GPtrArray         *resolvers;  /* Array of pending *AvahiServiceResolver */
    ll_node           node_list;   /* In mdns_finding_list */
    bool              publish;     /* Should we publish this finding */
    bool              initscan;    /* Device discovered during initial scan */
} mdns_finding;

/* Static variables
 */
static ll_head mdns_finding_list;
static AvahiGLibPoll *mdns_avahi_glib_poll;
static const AvahiPoll *mdns_avahi_poll;
static AvahiTimeout *mdns_avahi_restart_timer;
static AvahiClient *mdns_avahi_client;
static bool mdns_avahi_browser_running;
static AvahiServiceBrowser *mdns_avahi_browser[NUM_ZEROCONF_METHOD];
static bool mdns_initscan[NUM_ZEROCONF_METHOD];
static int mdns_initscan_count[NUM_ZEROCONF_METHOD];

/* Forward declarations
 */
static void
mdns_avahi_browser_stop (void);

static void
mdns_avahi_client_start (void);

static void
mdns_avahi_client_restart_defer (void);

/* Print debug message
 */
static void
mdns_debug (const char *name, AvahiProtocol protocol, const char *action,
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
mdns_perror (const char *name, AvahiProtocol protocol, const char *action)
{
    mdns_debug(name, protocol, action,
            avahi_strerror(avahi_client_errno(mdns_avahi_client)));
}


/* Get AvahiResolverEvent name, for debugging
 */
static const char*
mdns_avahi_resolver_event_name (AvahiResolverEvent e)
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
mdns_avahi_browser_event_name (AvahiBrowserEvent e)
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
mdns_avahi_client_state_name (AvahiClientState s)
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
mdns_initscan_count_inc (ZEROCONF_METHOD method)
{
    mdns_initscan_count[method] ++;
}

/* Decrement count if initial scan tasks
 */
static void
mdns_initscan_count_dec (ZEROCONF_METHOD method)
{
    log_assert(NULL, mdns_initscan_count[method] > 0);
    mdns_initscan_count[method] --;
    if (mdns_initscan_count[method] == 0) {
        zeroconf_finding_done(method);
    }
}

/* avahi_service_resolver_free adapter for GDestroyNotify
 */
static void
mdns_avahi_service_resolver_free_adapter(gpointer p)
{
    avahi_service_resolver_free(p);
}

/* Create new mdns_finding structure
 */
static mdns_finding*
mdns_finding_new (ZEROCONF_METHOD method, int ifindex, const char *name)
{
    mdns_finding *mdns = g_new0(mdns_finding, 1);

    mdns->finding.method = method;
    mdns->finding.ifindex = ifindex;
    mdns->finding.name = g_strdup(name);

    mdns->resolvers = g_ptr_array_new_with_free_func(
        mdns_avahi_service_resolver_free_adapter);

    mdns->initscan = mdns_initscan[method];
    if (mdns->initscan) {
        mdns_initscan_count_inc(mdns->finding.method);
    }

    return mdns;
}

/* Free mdns_finding structure
 */
static void
mdns_finding_free (mdns_finding *mdns)
{
    g_free((char*) mdns->finding.name);
    g_free((char*) mdns->finding.model);
    zeroconf_endpoint_list_free(mdns->finding.endpoints);

    if (mdns->initscan) {
        mdns_initscan_count_dec(mdns->finding.method);
    }

    g_ptr_array_free(mdns->resolvers, TRUE);
    g_free(mdns);
}

/* Find mdns_finding
 */
static mdns_finding*
mdns_finding_find (ZEROCONF_METHOD method, int ifindex, const char *name)
{
    ll_node *node;

    for (LL_FOR_EACH(node, &mdns_finding_list)) {
        mdns_finding *mdns;
        mdns = OUTER_STRUCT(node, mdns_finding, node_list);
        if (mdns->finding.method == method &&
            mdns->finding.ifindex == ifindex &&
            !strcasecmp(mdns->finding.name, name)) {
            return mdns;
        }
    }

    return NULL;
}

/* Get mdns_finding: find existing or add a new one
 */
static mdns_finding*
mdns_finding_get (ZEROCONF_METHOD method, int ifindex, const char *name)
{
    mdns_finding *mdns;

    /* Check for duplicated device */
    mdns = mdns_finding_find(method, ifindex, name);
    if (mdns != NULL) {
        return mdns;
    }

    /* Add new mdns_finding state */
    mdns = mdns_finding_new(method, ifindex, name);

    ll_push_end(&mdns_finding_list, &mdns->node_list);

    return mdns;
}

/* Del the mdns_finding
 */
static void
mdns_finding_del (mdns_finding *mdns)
{
    if (mdns->publish) {
        zeroconf_finding_withdraw(&mdns->finding);
    }
    ll_del(&mdns->node_list);
    mdns_finding_free(mdns);
}

/* Delete all mdns_finding
 */
static void
mdns_finding_del_all (void)
{
    ll_node *node;

    while ((node = ll_first(&mdns_finding_list)) != NULL) {
        mdns_finding *mdns;
        mdns = OUTER_STRUCT(node, mdns_finding, node_list);
        mdns_finding_del(mdns);
    }
}

/* Make zeroconf_endpoint for eSCL
 */
static zeroconf_endpoint*
mdns_make_escl_endpoint (ZEROCONF_METHOD method, const AvahiAddress *addr,
        uint16_t port, const char *rs, AvahiIfIndex interface)
{
    char       str_addr[128];
    int        rs_len;
    char       *u;
    http_uri   *uri;
    const char *scheme;

    if (method == ZEROCONF_ESCL) {
        scheme = "http";
    } else {
        scheme = "https";
    }

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
        u = g_strdup_printf("%s://%s:%d/eSCL/", scheme, str_addr, port);
    } else if (rs_len == 0) {
        /* Empty rs, avoid double '/' */
        u = g_strdup_printf("%s://%s:%d/", scheme, str_addr, port);
    } else {
        u = g_strdup_printf("%s://%s:%d/%.*s/", scheme, str_addr, port,
                rs_len, rs);
    }

    uri = http_uri_new(u, true);
    log_assert(NULL, uri != NULL);
    g_free(u);

    return zeroconf_endpoint_new(ID_PROTO_ESCL, uri);
}

/* AVAHI service resolver callback
 */
static void
mdns_avahi_resolver_callback (AvahiServiceResolver *r,
        AvahiIfIndex interface, AvahiProtocol protocol,
        AvahiResolverEvent event, const char *name, const char *type,
        const char *domain, const char *host_name, const AvahiAddress *addr,
        uint16_t port, AvahiStringList *txt, AvahiLookupResultFlags flags,
        void *userdata)
{
    mdns_finding      *mdns = userdata;
    ZEROCONF_METHOD   method = mdns->finding.method;

    (void) domain;
    (void) host_name;
    (void) flags;

    /* Print debug message */
    mdns_debug(name, protocol, "resolve", "%s %s",
            mdns_avahi_resolver_event_name(event), type);

    if (event == AVAHI_RESOLVER_FAILURE) {
        mdns_perror(name, protocol, "resolve");
    }

    /* Remove resolver from list of pending ones */
    if (!g_ptr_array_remove(mdns->resolvers, r)) {
        mdns_debug(name, protocol, "resolve", "spurious avahi callback");
        return;
    }

    /* Handle event */
    switch (event) {
    case AVAHI_RESOLVER_FOUND:
        if (mdns->finding.model == NULL) {
            AvahiStringList *ty = avahi_string_list_find(txt, "ty");
            if (ty != NULL && ty->size > 3) {
                mdns->finding.model = g_strdup((char*) (ty->text + 3));
            }
        }

        if (!uuid_valid(mdns->finding.uuid)) {
            AvahiStringList *uuid = avahi_string_list_find(txt, "uuid");
            if (uuid != NULL && uuid->size > 5) {
                mdns->finding.uuid = uuid_parse((const char*) uuid->text + 5);
            }
        }

        if (method == ZEROCONF_ESCL || method == ZEROCONF_ESCL_TLS) {
            AvahiStringList   *rs;
            const char        *rs_text = NULL;
            zeroconf_endpoint *endpoint;

            rs = avahi_string_list_find(txt, "rs");
            if (rs != NULL && rs->size > 3) {
                rs_text = (char*) (rs->text + 3);
            }

            endpoint = mdns_make_escl_endpoint(method, addr, port,
                rs_text, interface);

            endpoint->next = mdns->finding.endpoints;
            mdns->finding.endpoints = endpoint;
            mdns->publish = true;
        } else {
            AvahiStringList *scan;
            const char      *val;

            scan = avahi_string_list_find(txt, "scan");
            if (scan != NULL && scan->size > 5) {
                val = (char*) (scan->text + 5);
                mdns->publish = !strcasecmp(val, "t");
            }
        }
        break;

    case AVAHI_RESOLVER_FAILURE:
        break;
    }

    /* Perform appropriate actions, if resolving is done */
    if (mdns->resolvers->len != 0) {
        return;
    }

    mdns->finding.endpoints = zeroconf_endpoint_list_sort_dedup(
            mdns->finding.endpoints);

    if (mdns->finding.model == NULL) {
        /* Very unlikely, just paranoia */
        mdns->finding.model = g_strdup(mdns->finding.name);
    }

    if (!uuid_valid(mdns->finding.uuid)) {
        /* Paranoia too
         *
         * If device UUID is not available from DNS-SD (which
         * is very unlikely), we generate a synthetic UUID,
         * based on device name hash
         */
        mdns->finding.uuid = uuid_hash(mdns->finding.name);
    }

    if (mdns->initscan) {
        mdns->initscan = false;
        mdns_initscan_count_dec(mdns->finding.method);
    }

    if (mdns->publish) {
        zeroconf_finding_publish(&mdns->finding);
    }
}

/* AVAHI browser callback
 */
static void
mdns_avahi_browser_callback (AvahiServiceBrowser *b, AvahiIfIndex interface,
        AvahiProtocol protocol, AvahiBrowserEvent event,
        const char *name, const char *type, const char *domain,
        AvahiLookupResultFlags flags, void* userdata)
{
    mdns_finding    *mdns;
    ZEROCONF_METHOD method = (ZEROCONF_METHOD) userdata;

    (void) b;
    (void) flags;

    /* Print debug message */
    mdns_debug(name, protocol, "browse", "%s %s",
            mdns_avahi_browser_event_name(event), type);

    if (event == AVAHI_BROWSER_FAILURE) {
        mdns_perror(name, protocol, "browse");
    }

    switch (event) {
    case AVAHI_BROWSER_NEW:
        /* Add a device (or lookup for already added) */
        mdns = mdns_finding_get(method, interface, name);

        /* Initiate resolver */
        AvahiServiceResolver *r;
        r = avahi_service_resolver_new(mdns_avahi_client, interface,
                protocol, name, type, domain, AVAHI_PROTO_UNSPEC, 0,
                mdns_avahi_resolver_callback, mdns);

        if (r == NULL) {
            mdns_perror(name, protocol, "resolve");
            mdns_avahi_client_restart_defer();
            break;
        }

        /* Attach resolver to device state */
        g_ptr_array_add(mdns->resolvers, r);
        break;

    case AVAHI_BROWSER_REMOVE:
        mdns = mdns_finding_find(method, interface, name);
        if (mdns != NULL) {
            mdns_finding_del(mdns);
        }
        break;

    case AVAHI_BROWSER_FAILURE:
        mdns_avahi_client_restart_defer();
        break;

    case AVAHI_BROWSER_CACHE_EXHAUSTED:
        break;

    case AVAHI_BROWSER_ALL_FOR_NOW:
        if (mdns_initscan[method]) {
            mdns_initscan[method] = false;
            mdns_initscan_count_dec(method);
        }
        break;
    }
}

/* Start browser for specified service type
 */
static bool
mdns_avahi_browser_start_for_type (ZEROCONF_METHOD method, const char *type)
{
    log_assert(NULL, mdns_avahi_browser[method] == NULL);

    mdns_avahi_browser[method] = avahi_service_browser_new(mdns_avahi_client,
            AVAHI_IF_UNSPEC, AVAHI_PROTO_UNSPEC, type, NULL,
            0, mdns_avahi_browser_callback, (void*) method);

    if (mdns_avahi_browser[method] == NULL) {
        log_debug(NULL, "MDNS: avahi_service_browser_new(%s): %s",
            type, avahi_strerror(avahi_client_errno(mdns_avahi_client)));
    }

    return mdns_avahi_browser[method] != NULL;
}

/* Start/restart service browser
 */
static bool
mdns_avahi_browser_start (void)
{
    static struct { ZEROCONF_METHOD method; const char *type; } svc[] = {
        { ZEROCONF_IPP_PRINTER,     "_ipp._tcp" },
        { ZEROCONF_IPP_PRINTER_TLS, "_ipps._tcp" },
        { ZEROCONF_ESCL,            "_uscan._tcp" },
        { ZEROCONF_ESCL_TLS,        "_uscans._tcp" },
    };

    unsigned int i;
    bool         ok = true;

    log_assert(NULL, !mdns_avahi_browser_running);

    for (i = 0; ok && i < sizeof(svc)/sizeof(svc[0]); i ++) {
        ok = mdns_avahi_browser_start_for_type(svc[i].method, svc[i].type);
    }

    return ok;
}

/* Stop service browser
 */
static void
mdns_avahi_browser_stop (void)
{
    int i;

    for (i = 0; i < NUM_ZEROCONF_METHOD; i ++) {
        if (mdns_avahi_browser[i] != NULL) {
            avahi_service_browser_free(mdns_avahi_browser[i]);
            mdns_avahi_browser[i] = NULL;
        }
    }

    mdns_finding_del_all();
    mdns_avahi_browser_running = false;
}

/* AVAHI client callback
 */
static void
mdns_avahi_client_callback (AvahiClient *client, AvahiClientState state,
        void *userdata)
{
    (void) client;
    (void) userdata;

    log_debug(NULL, "MDNS: %s", mdns_avahi_client_state_name(state));

    switch (state) {
    case AVAHI_CLIENT_S_REGISTERING:
    case AVAHI_CLIENT_S_RUNNING:
    case AVAHI_CLIENT_S_COLLISION:
        /* Note, first callback may come before avahi_client_new()
         * return, so mdns_avahi_client may be still unset.
         * Fix it here
         */
        mdns_avahi_client = client;

        if (!mdns_avahi_browser_running) {
            if (!mdns_avahi_browser_start()) {
                mdns_avahi_client_restart_defer();
            }
        }
        break;

    case AVAHI_CLIENT_FAILURE:
        mdns_avahi_client_restart_defer();
        break;

    case AVAHI_CLIENT_CONNECTING:
        break;
    }
}

/* Timer for differed AVAHI client restart
 */
static void
mdns_avahi_restart_timer_callback(AvahiTimeout *t, void *userdata)
{
    (void) t;
    (void) userdata;

    mdns_avahi_client_start();
}

/* Stop AVAHI client
 */
static void
mdns_avahi_client_stop (void)
{
    if (mdns_avahi_client != NULL) {
        avahi_client_free(mdns_avahi_client);
        mdns_avahi_client = NULL;
    }
}

/* Start/restart the AVAHI client
 */
static void
mdns_avahi_client_start (void)
{
    int error;

    log_assert(NULL, mdns_avahi_client == NULL);

    mdns_avahi_client = avahi_client_new (mdns_avahi_poll,
        AVAHI_CLIENT_NO_FAIL, mdns_avahi_client_callback, NULL, &error);
}

/* Deferred client restart
 */
static void
mdns_avahi_client_restart_defer (void)
{
    struct timeval tv;

    mdns_avahi_browser_stop();
    mdns_avahi_client_stop();

    gettimeofday(&tv, NULL);
    tv.tv_sec += MDNS_AVAHI_CLIENT_RESTART_TIMEOUT;
    mdns_avahi_poll->timeout_update(mdns_avahi_restart_timer, &tv);
}

/* Initialize MDNS
 */
SANE_Status
mdns_init (void)
{
    int i;

    ll_init(&mdns_finding_list);

    if (!conf.discovery) {
        log_debug(NULL, "MDNS: devices discovery disabled");
        zeroconf_finding_done(ZEROCONF_IPP_PRINTER);
        zeroconf_finding_done(ZEROCONF_IPP_PRINTER_TLS);
        zeroconf_finding_done(ZEROCONF_ESCL);
        zeroconf_finding_done(ZEROCONF_ESCL_TLS);
        return SANE_STATUS_GOOD;
    }

    mdns_avahi_glib_poll = eloop_new_avahi_poll();
    if (mdns_avahi_glib_poll == NULL) {
        return SANE_STATUS_NO_MEM;
    }

    mdns_avahi_poll = avahi_glib_poll_get(mdns_avahi_glib_poll);

    mdns_avahi_restart_timer =
            mdns_avahi_poll->timeout_new(mdns_avahi_poll, NULL,
                mdns_avahi_restart_timer_callback, NULL);

    if (mdns_avahi_restart_timer == NULL) {
        return SANE_STATUS_NO_MEM;
    }

    mdns_avahi_client_start();
    if (mdns_avahi_client == NULL) {
        return SANE_STATUS_NO_MEM;
    }

    for (i = 0; i < NUM_ZEROCONF_METHOD; i ++) {
        mdns_initscan[i] = true;
        mdns_initscan_count[i] = 1;
    }

    return SANE_STATUS_GOOD;
}

/* Cleanup MDNS
 */
void
mdns_cleanup (void)
{
    if (mdns_avahi_glib_poll != NULL) {
        mdns_avahi_browser_stop();
        mdns_avahi_client_stop();
        mdns_finding_del_all();

        if (mdns_avahi_restart_timer != NULL) {
            mdns_avahi_poll->timeout_free(mdns_avahi_restart_timer);
            mdns_avahi_restart_timer = NULL;
        }

        avahi_glib_poll_free(mdns_avahi_glib_poll);
        mdns_avahi_poll = NULL;
        mdns_avahi_glib_poll = NULL;
    }
}

/* vim:ts=8:sw=4:et
 */
