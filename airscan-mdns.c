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

/* MDNS_SERVICE represents numerical identifiers for
 * DNS-SD service types we are interested in
 */
typedef enum {
    MDNS_SERVICE_UNKNOWN = -1,

    MDNS_SERVICE_IPP_TCP,     /* _ipp._tcp */
    MDNS_SERVICE_IPPS_TCP,    /* _ipps._tcp */
    MDNS_SERVICE_USCAN_TCP,   /* _uscan._tcp */
    MDNS_SERVICE_USCANS_TCP,  /* _uscans._tcp */
    MDNS_SERVICE_SCANNER_TCP, /* _scanner._tcp */

    NUM_MDNS_SERVICE
} MDNS_SERVICE;

/******************** Local Types *********************/
/* mdns_finding represents zeroconf_finding for MDNS
 * device discovery
 */
typedef struct {
    zeroconf_finding     finding;        /* Base class */
    AvahiServiceResolver **resolvers;    /* Array of pending resolvers */
    ll_node              node_list;      /* In mdns_finding_list */
    bool                 should_publish; /* Should we publish this finding */
    bool                 is_published;   /* Finding actually published */
    bool                 initscan;       /* Device discovered during initial scan */
} mdns_finding;

/* Static variables
 */
static log_ctx *mdns_log;
static ll_head mdns_finding_list;
static const AvahiPoll *mdns_avahi_poll;
static AvahiTimeout *mdns_avahi_restart_timer;
static AvahiClient *mdns_avahi_client;
static bool mdns_avahi_browser_running;
static AvahiServiceBrowser *mdns_avahi_browser[NUM_MDNS_SERVICE];
static bool mdns_initscan[NUM_MDNS_SERVICE];
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

    log_debug(mdns_log, "%s: %s", prefix, message);
}

/* Print error message
 */
static void
mdns_perror (const char *name, AvahiProtocol protocol, const char *action)
{
    mdns_debug(name, protocol, action,
            avahi_strerror(avahi_client_errno(mdns_avahi_client)));
}

/* Get MDNS_SERVICE name
 */
static const char*
mdns_service_name (MDNS_SERVICE service)
{
    switch (service) {
    case MDNS_SERVICE_IPP_TCP:     return "_ipp._tcp";
    case MDNS_SERVICE_IPPS_TCP:    return "_ipps._tcp";
    case MDNS_SERVICE_USCAN_TCP:   return "_uscan._tcp";
    case MDNS_SERVICE_USCANS_TCP:  return "_uscans._tcp";
    case MDNS_SERVICE_SCANNER_TCP: return "_scanner._tcp";

    case MDNS_SERVICE_UNKNOWN:
    case NUM_MDNS_SERVICE:
        break;
    }

    log_internal_error(mdns_log);
    return NULL;
}

/* Get MDNS_SERVICE by name
 */
static MDNS_SERVICE
mdns_service_by_name (const char *name)
{
    int i;

    for (i = 0; i < NUM_MDNS_SERVICE; i ++) {
        if (!strcasecmp(name, mdns_service_name(i))) {
            return i;
        }
    }

    return MDNS_SERVICE_UNKNOWN;
}

/* Map MDNS_SERVICE to ZEROCONF_METHOD
 */
static ZEROCONF_METHOD
mdns_service_to_method (MDNS_SERVICE service)
{
    switch (service) {
        case MDNS_SERVICE_USCAN_TCP:  return ZEROCONF_USCAN_TCP;
        case MDNS_SERVICE_USCANS_TCP: return ZEROCONF_USCANS_TCP;

        default:                      return ZEROCONF_MDNS_HINT;
    }
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
    log_assert(mdns_log, mdns_initscan_count[method] > 0);
    mdns_initscan_count[method] --;
    if (mdns_initscan_count[method] == 0) {
        zeroconf_finding_done(method);
    }
}

/* Create new mdns_finding structure
 */
static mdns_finding*
mdns_finding_new (ZEROCONF_METHOD method, int ifindex, const char *name,
        bool initscan)
{
    mdns_finding *mdns = mem_new(mdns_finding, 1);

    mdns->finding.method = method;
    mdns->finding.ifindex = ifindex;
    mdns->finding.name = str_dup(name);
    mdns->finding.addrs = ip_addrset_new();

    mdns->resolvers = ptr_array_new(AvahiServiceResolver*);

    mdns->initscan = initscan;
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
    mem_free((char*) mdns->finding.name);
    mem_free((char*) mdns->finding.model);
    ip_addrset_free(mdns->finding.addrs);
    zeroconf_endpoint_list_free(mdns->finding.endpoints);

    if (mdns->initscan) {
        mdns_initscan_count_dec(mdns->finding.method);
    }

    mem_free(mdns->resolvers);
    mem_free(mdns);
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
mdns_finding_get (ZEROCONF_METHOD method, int ifindex, const char *name,
        bool initscan)
{
    mdns_finding *mdns;

    /* Check for duplicated device */
    mdns = mdns_finding_find(method, ifindex, name);
    if (mdns != NULL) {
        return mdns;
    }

    /* Add new mdns_finding state */
    mdns = mdns_finding_new(method, ifindex, name, initscan);

    ll_push_end(&mdns_finding_list, &mdns->node_list);

    return mdns;
}

/* Kill pending resolvers
 */
static void
mdns_finding_kill_resolvers (mdns_finding *mdns)
{
    size_t i, len = mem_len(mdns->resolvers);

    for (i = 0; i < len; i ++) {
        avahi_service_resolver_free(mdns->resolvers[i]);
    }

    ptr_array_trunc(mdns->resolvers);
}

/* Del the mdns_finding
 */
static void
mdns_finding_del (mdns_finding *mdns)
{
    if (mdns->is_published) {
        zeroconf_finding_withdraw(&mdns->finding);
    }
    ll_del(&mdns->node_list);
    mdns_finding_kill_resolvers(mdns);
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

    if (method == ZEROCONF_USCAN_TCP) {
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
        u = str_printf("%s://%s:%d/eSCL/", scheme, str_addr, port);
    } else if (rs_len == 0) {
        /* Empty rs, avoid double '/' */
        u = str_printf("%s://%s:%d/", scheme, str_addr, port);
    } else {
        u = str_printf("%s://%s:%d/%.*s/", scheme, str_addr, port, rs_len, rs);
    }

    uri = http_uri_new(u, true);
    log_assert(mdns_log, uri != NULL);
    mem_free(u);

    return zeroconf_endpoint_new(ID_PROTO_ESCL, uri);
}

/* Handle AVAHI_RESOLVER_FOUND event
 */
static void
mdns_avahi_resolver_found (mdns_finding *mdns, MDNS_SERVICE service,
        AvahiStringList *txt, const AvahiAddress *addr, uint16_t port,
        AvahiIfIndex interface)
{
    const char        *txt_ty = NULL;
    const char        *txt_uuid = NULL;
    const char        *txt_scan = NULL;
    const char        *txt_rs = NULL;
    AvahiStringList   *s;
    zeroconf_endpoint *endpoint;
    ZEROCONF_METHOD   method = mdns->finding.method;
    ip_addr           ip_addr = ip_addr_make(interface,
                          addr->proto == AVAHI_PROTO_INET ? AF_INET : AF_INET6, &addr->data);

    /* Decode TXT record */
    s = avahi_string_list_find(txt, "ty");
    if (s != NULL && s->size > 3) {
        txt_ty = (char*) s->text + 3;
    }

    s = avahi_string_list_find(txt, "uuid");
    if (s != NULL && s->size > 5) {
        txt_uuid = (char*) s->text + 5;
    }

    switch (service) {
    case MDNS_SERVICE_IPP_TCP:
    case MDNS_SERVICE_IPPS_TCP:
        s = avahi_string_list_find(txt, "scan");
        if (s != NULL && s->size > 5) {
            txt_scan = (char*) s->text + 5;
        }
        break;

    default:
        break;
    }

    switch (service) {
    case MDNS_SERVICE_USCAN_TCP:
    case MDNS_SERVICE_USCANS_TCP:
        s = avahi_string_list_find(txt, "rs");
        if (s != NULL && s->size > 3) {
            txt_rs = (char*) s->text + 3;
        }
        break;

    default:
        break;
    }

    /* Update finding */
    if (mdns->finding.model == NULL && txt_ty != NULL) {
        mdns->finding.model = str_dup(txt_ty);
    }

    if (!uuid_valid(mdns->finding.uuid) && txt_uuid != NULL) {
        mdns->finding.uuid = uuid_parse(txt_uuid);
    }

    ip_addrset_add(mdns->finding.addrs, ip_addr);

    /* Handle the event */
    switch (service) {
    case MDNS_SERVICE_IPP_TCP:
    case MDNS_SERVICE_IPPS_TCP:
        if (txt_scan != NULL && !strcasecmp(txt_scan, "t")) {
            mdns->should_publish = true;
        }
        break;

    case MDNS_SERVICE_USCAN_TCP:
    case MDNS_SERVICE_USCANS_TCP:
        endpoint = mdns_make_escl_endpoint(method, addr, port,
            txt_rs, interface);

        endpoint->next = mdns->finding.endpoints;
        mdns->finding.endpoints = endpoint;
        mdns->should_publish = true;
        break;

    case MDNS_SERVICE_SCANNER_TCP:
        mdns->should_publish = true;
        break;

    case MDNS_SERVICE_UNKNOWN:
    case NUM_MDNS_SERVICE:
        log_internal_error(mdns_log);
    }
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
    MDNS_SERVICE      service = mdns_service_by_name(type);

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
    if (!ptr_array_del(mdns->resolvers, ptr_array_find(mdns->resolvers, r))) {
        mdns_debug(name, protocol, "resolve", "spurious avahi callback");
        return;
    }

    avahi_service_resolver_free(r);

    /* Handle event */
    switch (event) {
    case AVAHI_RESOLVER_FOUND:
        mdns_avahi_resolver_found(mdns, service, txt, addr, port, interface);
        break;

    case AVAHI_RESOLVER_FAILURE:
        break;
    }

    /* Perform appropriate actions, if resolving is done */
    if (mdns->resolvers[0] == NULL) {
        /* Fixup endpoints */
        mdns->finding.endpoints = zeroconf_endpoint_list_sort_dedup(
                mdns->finding.endpoints);

        /* Fixup model and UUID */
        if (mdns->finding.model == NULL) {
            /* Very unlikely, just paranoia */
            mdns->finding.model = str_dup(mdns->finding.name);
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

        /* Update initscan count */
        if (mdns->initscan) {
            mdns->initscan = false;
            mdns_initscan_count_dec(mdns->finding.method);
        }

        /* Publish the finding */
        if (mdns->should_publish && !mdns->is_published) {
            mdns->is_published = true;
            zeroconf_finding_publish(&mdns->finding);
        }
    }

    /* Notify WSDD about newly discovered address */
    if (event == AVAHI_RESOLVER_FOUND) {
        int af = addr->proto == AVAHI_PROTO_INET ? AF_INET : AF_INET6;
        wsdd_send_directed_probe(interface, af, &addr->data);
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
    MDNS_SERVICE    service = (MDNS_SERVICE) userdata;
    ZEROCONF_METHOD method = mdns_service_to_method(service);
    bool            initscan = mdns_initscan[service];

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
        mdns = mdns_finding_get(method, interface, name, initscan);

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
        mdns->resolvers = ptr_array_append(mdns->resolvers, r);
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
        if (mdns_initscan[service]) {
            mdns_initscan[service] = false;
            mdns_initscan_count_dec(method);
        }
        break;
    }
}

/* Start browser for specified service type
 */
static bool
mdns_avahi_browser_start_for_type (MDNS_SERVICE service, const char *type)
{
    bool ok;

    log_assert(mdns_log, mdns_avahi_browser[service] == NULL);

    mdns_avahi_browser[service] = avahi_service_browser_new(mdns_avahi_client,
            AVAHI_IF_UNSPEC, AVAHI_PROTO_UNSPEC, type, NULL,
            0, mdns_avahi_browser_callback, (void*) service);

    ok = mdns_avahi_browser[service] != NULL;

    if (!ok) {
        log_debug(mdns_log, "avahi_service_browser_new(%s): %s",
            type, avahi_strerror(avahi_client_errno(mdns_avahi_client)));
    }

    if (ok && mdns_initscan[service]) {
        mdns_initscan_count_inc(mdns_service_to_method(service));
    }

    return mdns_avahi_browser[service] != NULL;
}

/* Start/restart service browser
 */
static bool
mdns_avahi_browser_start (void)
{
    int  i;
    bool ok = true;

    log_assert(mdns_log, !mdns_avahi_browser_running);

    for (i = 0; ok && i < NUM_MDNS_SERVICE; i ++) {
        ok = mdns_avahi_browser_start_for_type(i, mdns_service_name(i));
    }

    mdns_avahi_browser_running = true;

    return ok;
}

/* Stop service browser
 */
static void
mdns_avahi_browser_stop (void)
{
    MDNS_SERVICE service;

    for (service = 0; service < NUM_MDNS_SERVICE; service ++) {
        if (mdns_avahi_browser[service] != NULL) {
            avahi_service_browser_free(mdns_avahi_browser[service]);
            mdns_avahi_browser[service] = NULL;
            if (mdns_initscan[service]) {
                mdns_initscan_count_dec(mdns_service_to_method(service));
            }
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

    log_debug(mdns_log, "%s", mdns_avahi_client_state_name(state));

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

    log_assert(mdns_log, mdns_avahi_client == NULL);

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

/* Called by zeroconf to notify MDNS about initial scan timer expiration
 */
void
mdns_initscan_timer_expired (void)
{
}

/* Initialize MDNS
 */
SANE_Status
mdns_init (void)
{
    int i;

    mdns_log = log_ctx_new("MDNS", zeroconf_log);

    ll_init(&mdns_finding_list);

    if (!conf.discovery) {
        log_debug(mdns_log, "devices discovery disabled");
        zeroconf_finding_done(ZEROCONF_MDNS_HINT);
        zeroconf_finding_done(ZEROCONF_USCAN_TCP);
        zeroconf_finding_done(ZEROCONF_USCANS_TCP);
        return SANE_STATUS_GOOD;
    }

    for (i = 0; i < NUM_MDNS_SERVICE; i ++) {
        mdns_initscan[i] = true;
    }

    for (i = 0; i < NUM_ZEROCONF_METHOD; i ++) {
        mdns_initscan_count[i] = 0;
    }

    mdns_avahi_poll = eloop_poll_get();

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

    return SANE_STATUS_GOOD;
}

/* Cleanup MDNS
 */
void
mdns_cleanup (void)
{
    if (mdns_log == NULL) {
        return; /* MDNS not initialized */
    }

    if (mdns_avahi_poll != NULL) {
        mdns_avahi_browser_stop();
        mdns_avahi_client_stop();
        mdns_finding_del_all();

        if (mdns_avahi_restart_timer != NULL) {
            mdns_avahi_poll->timeout_free(mdns_avahi_restart_timer);
            mdns_avahi_restart_timer = NULL;
        }

        mdns_avahi_poll = NULL;
    }

    log_ctx_free(mdns_log);
    mdns_log = NULL;
}

/* vim:ts=8:sw=4:et
 */
