/* AirScan (a.k.a. eSCL) backend for SANE
 *
 * Copyright (C) 2019 and up by Alexander Pevzner (pzz@apevzner.com)
 * See LICENSE for license terms and conditions
 *
 * ZeroConf (device discovery)
 */

#include "airscan.h"

#include <arpa/inet.h>
#include <net/if.h>

#include <alloca.h>
#include <stdlib.h>
#include <string.h>

/******************** Constants *********************/
/* Max time to wait until device table is ready, in seconds
 */
#define ZEROCONF_READY_TIMEOUT                  5

/******************** Local Types *********************/
/* zeroconf_device represents a single device
 */
struct zeroconf_device {
    unsigned int    devid;      /* Unique ident */
    uuid            uuid;       /* Device UUID */
    ip_addrset      *addrs;     /* Device's addresses */
    const char      *mdns_name; /* Device's MDNS name, NULL for WSDD */
    const char      *model;     /* Device model name */
    unsigned int    protocols;  /* Supported protocols, set of 1<<ID_PROTO */
    unsigned int    methods;    /* How device was discovered, set of
                                    1 << ZEROCONF_METHOD */
    ll_node         node_list;  /* In zeroconf_device_list */
    ll_head         findings;   /* zeroconf_finding, by method */
    zeroconf_device *buddy;     /* "Buddy" device, MDNS vs WSDD */
};

/* Global variables
 */
log_ctx *zeroconf_log;

/* Static variables
 */
static ll_head zeroconf_device_list;
static pthread_cond_t zeroconf_initscan_cond;
static int zeroconf_initscan_bits;
static eloop_timer *zeroconf_initscan_timer;

/******************** Forward declarations *********************/
static zeroconf_endpoint*
zeroconf_endpoint_copy_single (const zeroconf_endpoint *endpoint);

static const char*
zeroconf_ident_split (const char *ident, unsigned int *devid, ID_PROTO *proto);

/******************** Discovery methods *********************/
/* Map ZEROCONF_METHOD to ID_PROTO
 */
static ID_PROTO
zeroconf_method_to_proto (ZEROCONF_METHOD method)
{
    switch (method) {
    case ZEROCONF_MDNS_HINT:
        return ID_PROTO_UNKNOWN;

    case ZEROCONF_USCAN_TCP:
    case ZEROCONF_USCANS_TCP:
        return ID_PROTO_ESCL;

    case ZEROCONF_WSD:
        return ID_PROTO_WSD;

    case NUM_ZEROCONF_METHOD:
        break;
    }

    return ID_PROTO_UNKNOWN;
}

/* Get ZEROCONF_METHOD, for debugging
 */
static const char*
zeroconf_method_name (ZEROCONF_METHOD method)
{
    switch (method) {
    case ZEROCONF_MDNS_HINT:  return "ZEROCONF_MDNS_HINT";
    case ZEROCONF_USCAN_TCP:  return "ZEROCONF_USCAN_TCP";
    case ZEROCONF_USCANS_TCP: return "ZEROCONF_USCANS_TCP";
    case ZEROCONF_WSD:        return "ZEROCONF_WSD";

    case NUM_ZEROCONF_METHOD:
        break;
    }

    return NULL;
}

/******************** Devices *********************/
/* Add new zeroconf_device
 */
static zeroconf_device*
zeroconf_device_add (zeroconf_finding *finding)
{
    zeroconf_device *device = mem_new(zeroconf_device, 1);

    device->devid = devid_alloc();
    device->uuid = finding->uuid;
    device->addrs = ip_addrset_new();
    if (finding->name != NULL) {
        device->mdns_name = str_dup(finding->name);
    }
    device->model = finding->model;

    ll_init(&device->findings);
    ll_push_end(&zeroconf_device_list, &device->node_list);

    return device;
}

/* Delete the device
 */
static void
zeroconf_device_del (zeroconf_device *device)
{
    ll_del(&device->node_list);
    ip_addrset_free(device->addrs);
    mem_free((char*) device->mdns_name);
    devid_free(device->devid);
    mem_free(device);
}

/* Check if device is MDNS device
 */
static bool
zeroconf_device_is_mdns (zeroconf_device *device)
{
    return device->mdns_name != NULL;
}

/* Rebuild device->ifaces, device->protocols and device->methods
 */
static void
zeroconf_device_rebuild_sets (zeroconf_device *device)
{
    ll_node *node;

    device->protocols = 0;
    device->methods = 0;

    for (LL_FOR_EACH(node, &device->findings)) {
        zeroconf_finding *finding;
        ID_PROTO         proto;

        finding = OUTER_STRUCT(node, zeroconf_finding, list_node);
        proto = zeroconf_method_to_proto(finding->method);

        if (proto != ID_PROTO_UNKNOWN) {
            device->protocols |= 1 << proto;
        }
        device->methods |= 1 << finding->method;
    }
}

/* Update device->model
 */
static void
zeroconf_device_update_model (zeroconf_device *device)
{
    ll_node          *node;
    zeroconf_finding *hint = NULL, *wsd = NULL;

    for (LL_FOR_EACH(node, &device->findings)) {
        zeroconf_finding *finding;
        finding = OUTER_STRUCT(node, zeroconf_finding, list_node);

        switch (finding->method) {
            case ZEROCONF_USCAN_TCP:
            case ZEROCONF_USCANS_TCP:
                device->model = finding->model;
                return;

            case ZEROCONF_MDNS_HINT:
                if (hint == NULL) {
                    hint = finding;
                }
                break;

            case ZEROCONF_WSD:
                if (wsd == NULL) {
                    wsd = finding;
                }
                break;

            default:
                log_internal_error(zeroconf_log);
        }
    }

    device->model =  hint ? hint->model : wsd->model;
}

/* Add zeroconf_finding to zeroconf_device
 */
static void
zeroconf_device_add_finding (zeroconf_device *device,
    zeroconf_finding *finding)
{
    log_assert(zeroconf_log, finding->device == NULL);

    finding->device = device;

    ll_push_end(&device->findings, &finding->list_node);
    ip_addrset_merge(device->addrs, finding->addrs);

    if (finding->endpoints != NULL) {
        ID_PROTO proto = zeroconf_method_to_proto(finding->method);
        if (proto != ID_PROTO_UNKNOWN) {
            device->protocols |= 1 << proto;
        }
        device->methods |= 1 << finding->method;
    }

    zeroconf_device_update_model(device);
}

/* Delete zeroconf_finding from zeroconf_device
 */
static void
zeroconf_device_del_finding (zeroconf_finding *finding)
{
    zeroconf_device *device = finding->device;

    log_assert(zeroconf_log, device != NULL);

    ll_del(&finding->list_node);
    if (ll_empty(&device->findings)) {
        zeroconf_device_del(device);
        return;
    }

    zeroconf_device_rebuild_sets(device);
    zeroconf_device_update_model(device);
}

/* Get device name
 */
static const char*
zeroconf_device_name (zeroconf_device *device)
{
    if (zeroconf_device_is_mdns(device)) {
        return device->mdns_name;
    }

    if (device->buddy != NULL) {
        return device->buddy->mdns_name;
    }

    return device->model;
}

/* Get model name
 */
static const char*
zeroconf_device_model (zeroconf_device *device)
{
    return device->model;
}

/* Get protocols, exposed by device
 */
static unsigned int
zeroconf_device_protocols (zeroconf_device *device)
{
    unsigned int protocols = device->protocols;

    if (!conf.proto_auto) {
        return protocols;
    }

    if ((protocols & (1 << ID_PROTO_ESCL)) != 0) {
        return 1 << ID_PROTO_ESCL;
    }

    if ((protocols & (1 << ID_PROTO_WSD)) != 0) {
        return 1 << ID_PROTO_WSD;
    }

    return 0;
}

/* Get device endpoints.
 * Caller is responsible to free the returned list
 */
static zeroconf_endpoint*
zeroconf_device_endpoints (zeroconf_device *device, ID_PROTO proto)
{
    zeroconf_endpoint   *endpoints = NULL;
    ll_node             *node;

    for (LL_FOR_EACH(node, &device->findings)) {
        zeroconf_finding *finding;
        finding = OUTER_STRUCT(node, zeroconf_finding, list_node);

        if (zeroconf_method_to_proto(finding->method) == proto) {
            zeroconf_endpoint *ep, *ep2;

            for (ep = finding->endpoints; ep != NULL; ep = ep->next) {
                ep2 = zeroconf_endpoint_copy_single(ep);
                ep2->next = endpoints;
                endpoints = ep2;
            }
        }
    }

    return zeroconf_endpoint_list_sort_dedup(endpoints);
}

/* Find zeroconf_device by ident
 * Protocol, encoded into ident, returned via second parameter
 */
static zeroconf_device*
zeroconf_device_find_by_ident (const char *ident, ID_PROTO *proto)
{
    unsigned int    devid;
    const char      *name;
    ll_node         *node;
    zeroconf_device *device = NULL;

    name = zeroconf_ident_split(ident, &devid, proto);
    if (name == NULL) {
        return NULL;
    }

    /* Lookup device */
    for (LL_FOR_EACH(node, &zeroconf_device_list)) {
        device = OUTER_STRUCT(node, zeroconf_device, node_list);
        if (device->devid == devid &&
            !strcmp(name, zeroconf_device_name(device))) {
            break;
        }
    }

    if (device == NULL)
        return NULL;

    /* Check that device supports requested protocol */
    if ((device->protocols & (1 << *proto)) != 0) {
        return device;
    }

    return NULL;
}

/******************** Merging devices *********************/
/* Recompute device->buddy for all devices
 */
static void
zeroconf_merge_recompute_buddies (void)
{
    ll_node         *node, *node2;
    zeroconf_device *device, *device2;

    for (LL_FOR_EACH(node, &zeroconf_device_list)) {
        device = OUTER_STRUCT(node, zeroconf_device, node_list);
        device->buddy = NULL;
    }

    for (LL_FOR_EACH(node, &zeroconf_device_list)) {
        device = OUTER_STRUCT(node, zeroconf_device, node_list);

        for (node2 = ll_next(&zeroconf_device_list, node); node2 != NULL;
             node2 = ll_next(&zeroconf_device_list, node2)) {

            device2 = OUTER_STRUCT(node2, zeroconf_device, node_list);

            if (zeroconf_device_is_mdns(device) !=
                zeroconf_device_is_mdns(device2)) {
                if (ip_addrset_is_intersect(device->addrs, device2->addrs)) {
                    device->buddy = device2;
                    device2->buddy = device;
                }
            }
        }
    }
}

/* Check that new finding should me merged with existent device
 */
static bool
zeroconf_merge_check (zeroconf_device *device, zeroconf_finding *finding)
{
    if ((device->mdns_name == NULL) != (finding->name == NULL)) {
        return false;
    }

    if (device->mdns_name != NULL &&
        strcasecmp(device->mdns_name, finding->name)) {
        return false;
    }

    if (uuid_equal(device->uuid, finding->uuid)) {
        return true;
    }

    return false;
}

/* Find device, suitable for merging with specified findind
 */
static zeroconf_device*
zeroconf_merge_find (zeroconf_finding *finding)
{
    ll_node *node;

    for (LL_FOR_EACH(node, &zeroconf_device_list)) {
        zeroconf_device *device;
        device = OUTER_STRUCT(node, zeroconf_device, node_list);

        if (zeroconf_merge_check(device, finding)) {
            return device;
        }
    }

    return NULL;
}

/******************** Ident Strings *********************/
/* Encode ID_PROTO for device ident
 */
static char
zeroconf_ident_proto_encode (ID_PROTO proto)
{
    switch (proto) {
    case ID_PROTO_ESCL: return 'e';
    case ID_PROTO_WSD:  return 'w';

    case ID_PROTO_UNKNOWN:
    case NUM_ID_PROTO:
        break;
    }

    log_internal_error(zeroconf_log);
    return 0;
}

/* Decode ID_PROTO from device ident
 */
static ID_PROTO
zeroconf_ident_proto_decode (char c)
{
    switch (c) {
    case 'e': return ID_PROTO_ESCL;
    case 'w': return ID_PROTO_WSD;
    }

    return ID_PROTO_UNKNOWN;
}

/* Make device ident string
 * The returned string must be released with mem_free()
 */
static const char*
zeroconf_ident_make (const char *name, unsigned int devid, ID_PROTO proto)
{
    return str_printf("%c%x:%s", zeroconf_ident_proto_encode(proto),
        devid, name);
}

/* Split device ident string.
 * Returns NULL on error, device name on success.
 * Device name points somewhere into the input buffer
 */
static const char*
zeroconf_ident_split (const char *ident, unsigned int *devid, ID_PROTO *proto)
{
    const char *name;
    char       *end;

    /* Find name */
    name = strchr(ident, ':');
    if (name == NULL) {
        return NULL;
    }

    name ++;

    /* Decode proto and devid */
    *proto = zeroconf_ident_proto_decode(*ident);
    if (*proto == ID_PROTO_UNKNOWN) {
        return NULL;
    }

    ident ++;
    *devid = (unsigned int) strtoul(ident, &end, 16);
    if (end == ident || *end != ':') {
        return NULL;
    }

    return name;
}

/******************** Endpoints *********************/
/* Create new zeroconf_endpoint. Newly created endpoint
 * takes ownership of uri string
 */
zeroconf_endpoint*
zeroconf_endpoint_new (ID_PROTO proto, http_uri *uri)
{
    zeroconf_endpoint *endpoint = mem_new(zeroconf_endpoint, 1);

    endpoint->proto = proto;
    endpoint->uri = uri;
    if (proto == ID_PROTO_ESCL) {
        // We own the uri, so modify without making a separate copy.
        http_uri_fix_end_slash(endpoint->uri);
    }

    return endpoint;
}

/* Clone a single zeroconf_endpoint
 */
static zeroconf_endpoint*
zeroconf_endpoint_copy_single (const zeroconf_endpoint *endpoint)
{
    zeroconf_endpoint *endpoint2 = mem_new(zeroconf_endpoint, 1);

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
    mem_free(endpoint);
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

/* Compare two endpoints, for sorting
 */
static int
zeroconf_endpoint_cmp (const zeroconf_endpoint *e1, const zeroconf_endpoint *e2)
{
    const struct sockaddr *a1 = http_uri_addr(e1->uri);
    const struct sockaddr *a2 = http_uri_addr(e2->uri);

    if (a1 != NULL && a2 != NULL) {
        bool ll1 = ip_sockaddr_is_linklocal(a1);
        bool ll2 = ip_sockaddr_is_linklocal(a2);
        int  cmp;

        /* Prefer directly reachable addresses */
        cmp = netif_distance_cmp(a1, a2);
        if (cmp != 0) {
            return cmp;
        }

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

    if (list == NULL || list->next == NULL) {
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

/* Check if endpoints list contains a non-link-local address
 * of the specified address family
 */
bool
zeroconf_endpoint_list_has_non_link_local_addr (int af,
        const zeroconf_endpoint *list)
{
    for (;list != NULL; list = list->next) {
        const struct sockaddr *addr = http_uri_addr(list->uri);
        if (addr != NULL && addr->sa_family == af) {
            if (!ip_sockaddr_is_linklocal(addr)) {
                return true;
            }
        }
    }

    return false;
}

/******************** Static configuration *********************/
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
    conf_device  *dev_conf;
    ID_PROTO     proto;
    unsigned int devid;
    const char   *name;

    name = zeroconf_ident_split(ident, &devid, &proto);
    if (name == NULL) {
        return NULL;
    }

    for (dev_conf = conf.devices; dev_conf != NULL; dev_conf = dev_conf->next) {
        if (dev_conf->devid == devid &&
            dev_conf->proto == proto &&
            !strcmp(dev_conf->name, name)) {
            return dev_conf;
        }
    }

    return NULL;
}

/******************** Events from discovery providers *********************/
/* Publish the zeroconf_finding.
 */
void
zeroconf_finding_publish (zeroconf_finding *finding)
{
    size_t            count, i;
    zeroconf_device   *device;
    char              ifname[IF_NAMESIZE];
    const ip_addr     *addrs;
    ID_PROTO          proto = zeroconf_method_to_proto(finding->method);

    /* Print log messages */
    if (if_indextoname(finding->ifindex, ifname) == NULL) {
        strcpy(ifname, "?");
    }

    log_debug(zeroconf_log, "found %s", finding->uuid.text);
    log_debug(zeroconf_log, "  method:    %s",
        zeroconf_method_name(finding->method));
    log_debug(zeroconf_log, "  interface: %d (%s)", finding->ifindex, ifname);
    log_debug(zeroconf_log, "  name:      %s",
        finding->name ? finding->name : "-");
    log_debug(zeroconf_log, "  model:     %s", finding->model);

    log_debug(zeroconf_log, "  addresses:");
    addrs = ip_addrset_addresses(finding->addrs, &count);
    for (i = 0; i < count; i ++) {
        ip_straddr straddr = ip_addr_to_straddr(addrs[i], true);
        log_debug(zeroconf_log, "    %s", straddr.text);
    }

    if (proto != ID_PROTO_UNKNOWN) {
        zeroconf_endpoint *ep;

        log_debug(zeroconf_log, "  protocol:  %s", id_proto_name(proto));
        log_debug(zeroconf_log, "  endpoints:");
        for (ep = finding->endpoints; ep != NULL; ep = ep->next) {
            log_debug(zeroconf_log, "    %s", http_uri_str(ep->uri));
        }
    }

    /* Handle new finding */
    device = zeroconf_merge_find(finding);
    if (device != NULL) {
        log_debug(zeroconf_log, "  device:    %4.4x (found)", device->devid);
    } else {
        device = zeroconf_device_add(finding);
        log_debug(zeroconf_log, "  device:    %4.4x (created)", device->devid);
    }

    zeroconf_device_add_finding(device, finding);
    zeroconf_merge_recompute_buddies();
    pthread_cond_broadcast(&zeroconf_initscan_cond);
}

/* Withdraw the finding
 */
void
zeroconf_finding_withdraw (zeroconf_finding *finding)
{
    char             ifname[IF_NAMESIZE] = "?";

    if_indextoname(finding->ifindex, ifname);

    log_debug(zeroconf_log, "device gone %s", finding->uuid.text);
    log_debug(zeroconf_log, "  method:    %s", zeroconf_method_name(finding->method));
    log_debug(zeroconf_log, "  interface: %d (%s)", finding->ifindex, ifname);

    zeroconf_device_del_finding(finding);
    zeroconf_merge_recompute_buddies();
    pthread_cond_broadcast(&zeroconf_initscan_cond);
}

/* Notify zeroconf subsystem that initial scan
 * for the method is done
 */
void
zeroconf_finding_done (ZEROCONF_METHOD method)
{
    log_debug(zeroconf_log, "%s: initial scan finished",
        zeroconf_method_name(method));

    zeroconf_initscan_bits &= ~(1 << method);
    pthread_cond_broadcast(&zeroconf_initscan_cond);
}

/******************** Support for SANE API *********************/
/* zeroconf_initscan_timer callback
 */
static void
zeroconf_initscan_timer_callback (void *unused)
{
    (void) unused;

    log_debug(zeroconf_log, "initial scan timer expired");

    mdns_initscan_timer_expired();
    wsdd_initscan_timer_expired();

    zeroconf_initscan_timer = NULL;
    pthread_cond_broadcast(&zeroconf_initscan_cond);
}

/* Check if initial scan is done
 */
static bool
zeroconf_initscan_done (void)
{
    ll_node         *node;
    zeroconf_device *device;

    /* If all discovery methods are done, we are done */
    if (zeroconf_initscan_bits == 0) {
        return true;
    }

    /* Regardless of options, all DNS-SD methods must be done */
    if ((zeroconf_initscan_bits & ~(1 << ZEROCONF_WSD)) != 0) {
        log_debug(zeroconf_log, "device_list wait: DNS-SD not finished...");
        return false;
    }

    /* If we are here, ZEROCONF_WSD is not done yet,
     * and if we are not in fast-wsdd mode, we must wait
     */
    log_assert(zeroconf_log,
        (zeroconf_initscan_bits & (1 << ZEROCONF_WSD)) != 0);

    if (conf.wsdd_mode != WSDD_FAST) {
        log_debug(zeroconf_log, "device_list wait: WSDD not finished...");
        return false;
    }

    /* Check for completion, device by device:
     *
     * In manual protocol switch mode, WSDD buddy must be
     * found for device, so we have a choice. Otherwise, it's
     * enough if device has supported protocols
     */
    for (LL_FOR_EACH(node, &zeroconf_device_list)) {
        device = OUTER_STRUCT(node, zeroconf_device, node_list);

        if (!conf.proto_auto) {
            if (zeroconf_device_is_mdns(device) && device->buddy == NULL) {
                log_debug(zeroconf_log,
                    "device_list wait: waiting for WSDD buddy for '%s' (%d)",
                    device->mdns_name, device->devid);
                return false;
            }
        } else {
            if (device->protocols == 0) {
                log_debug(zeroconf_log,
                    "device_list wait: waiting for any proto for '%s' (%d)",
                    device->mdns_name, device->devid);
                return false;
            }
        }
    }

    return true;
}

/* Wait until initial scan is done
 */
static void
zeroconf_initscan_wait (void)
{
    bool   ok = false;

    log_debug(zeroconf_log, "device_list wait: requested");

    for (;;) {
        ok = zeroconf_initscan_done();
        if (ok || zeroconf_initscan_timer == NULL) {
            break;
        }
        eloop_cond_wait(&zeroconf_initscan_cond);
    }

    log_debug(zeroconf_log, "device_list wait: %s", ok ? "OK" : "timeout" );
}

/* Compare SANE_Device*, for qsort
 */
static int
zeroconf_device_list_qsort_cmp (const void *p1, const void *p2)
{
    int   cmp;
    const SANE_Device *d1 = *(SANE_Device**) p1;
    const SANE_Device *d2 = *(SANE_Device**) p2;

    cmp = strcasecmp(d1->model, d2->model);
    if (cmp == 0) {
        cmp = strcasecmp(d1->vendor, d2->vendor);
    }
    if (cmp == 0) {
        cmp = strcmp(d1->name, d2->name);
    }

    return cmp;
}

/* Format list of protocols, for zeroconf_device_list_log
 */
static void
zeroconf_device_list_fmt_protocols (char *buf, size_t buflen, unsigned int protocols)
{
    ID_PROTO proto;
    size_t   off = 0;

    buf[0] = '\0';
    for (proto = 0; proto < NUM_ID_PROTO; proto ++) {
        if ((protocols & (1 << proto)) != 0) {
            off += snprintf(buf + off, buflen - off, " %s",
                id_proto_name(proto));
        }
    }

    if (buf[0] == '\0') {
        strcpy(buf, " none");
    }
}

/* Log device information in a context of zeroconf_device_list_get
 */
static void
zeroconf_device_list_log (zeroconf_device *device, const char *name,
    unsigned int protocols)
{
    char     can[64];
    char     use[64];

    zeroconf_device_list_fmt_protocols(can, sizeof(can), device->protocols);
    zeroconf_device_list_fmt_protocols(use, sizeof(use), protocols);

    log_debug(zeroconf_log, "%s (%d): can:%s, use:%s", name, device->devid,
        can, use);
}

/* Get list of devices, in SANE format
 */
const SANE_Device**
zeroconf_device_list_get (void)
{
    size_t      dev_count = 0, dev_count_static = 0;
    conf_device *dev_conf;
    const SANE_Device **dev_list = sane_device_array_new();
    ll_node     *node;
    int         i;

    log_debug(zeroconf_log, "zeroconf_device_list_get: requested");

    /* Wait until device table is ready */
    zeroconf_initscan_wait();

    /* Build list of devices */
    log_debug(zeroconf_log, "zeroconf_device_list_get: building list of devices");

    dev_count = 0;

    for (dev_conf = conf.devices; dev_conf != NULL; dev_conf = dev_conf->next) {
        SANE_Device *info;
        const char  *proto;

        if (dev_conf->uri == NULL) {
            continue;
        }

        info = mem_new(SANE_Device, 1);
        proto = id_proto_name(dev_conf->proto);

        dev_list = sane_device_array_append(dev_list, info);
        dev_count ++;

        info->name = zeroconf_ident_make(dev_conf->name, dev_conf->devid,
            dev_conf->proto);
        info->vendor = str_dup(proto);
        info->model = str_dup(dev_conf->name);
        info->type = str_printf("%s network scanner", proto);
    }

    dev_count_static = dev_count;

    for (LL_FOR_EACH(node, &zeroconf_device_list)) {
        zeroconf_device *device;
        ID_PROTO        proto;
        const char      *name, *model;
        unsigned int    protocols;

        device = OUTER_STRUCT(node, zeroconf_device, node_list);
        name = zeroconf_device_name(device);
        model = zeroconf_device_model(device);
        protocols = zeroconf_device_protocols(device);

        zeroconf_device_list_log(device, name, protocols);

        if (zeroconf_find_static_by_name(name) != NULL) {
            /* Static configuration overrides discovery */
            log_debug(zeroconf_log,
                "%s (%d): skipping, device clashes statically configured",
                name, device->devid);
            continue;
        }

        if (conf.proto_auto && !zeroconf_device_is_mdns(device)) {
            zeroconf_device *device2 = device->buddy;
            if (device2 != NULL && zeroconf_device_protocols(device2) != 0) {
                log_debug(zeroconf_log,
                    "%s (%d): skipping, shadowed by %s (%d)",
                    name, device->devid, device2->mdns_name, device2->devid);
                continue;
            }
        }

        if (protocols == 0) {
            log_debug(zeroconf_log,
                "%s (%d): skipping, none of supported protocols discovered",
                name, device->devid);
            continue;
        }

        for (proto = 0; proto < NUM_ID_PROTO; proto ++) {
            if ((protocols & (1 << proto)) != 0) {
                SANE_Device            *info = mem_new(SANE_Device, 1);
                const char             *proto_name = id_proto_name(proto);

                dev_list = sane_device_array_append(dev_list, info);
                dev_count ++;

                info->name = zeroconf_ident_make(name, device->devid, proto);
                info->vendor = str_dup(proto_name);
                info->model = str_dup(conf.model_is_netname ? name : model);
                info->type = str_printf("%s network scanner", proto_name);
            }
        }
    }

    qsort(dev_list + dev_count_static, dev_count - dev_count_static,
        sizeof(*dev_list), zeroconf_device_list_qsort_cmp);

    log_debug(zeroconf_log, "zeroconf_device_list_get: resulting list:");
    for (i = 0; dev_list[i] != NULL; i ++) {
        log_debug(zeroconf_log,
            "  %-4s  \"%s\"", dev_list[i]->vendor, dev_list[i]->name);
    }

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
            mem_free((void*) info->name);
            mem_free((void*) info->vendor);
            mem_free((void*) info->model);
            mem_free((void*) info->type);
            mem_free((void*) info);
        }

        sane_device_array_free(dev_list);
    }
}

/*
 * The format "protocol:name:url" is accepted to directly specify a device
 * without listing it in the config or finding it with autodiscovery.  Try
 * to parse an identifier as that format.  On success, returns a newly allocated
 * zeroconf_devinfo that the caller must free with zeroconf_devinfo_free().  On
 * failure, returns NULL.
 */
static zeroconf_devinfo*
zeroconf_parse_devinfo_from_ident(const char *ident)
{
    int              buf_size;
    char             *buf = NULL;
    ID_PROTO         proto;
    char             *name;
    char             *uri_str;
    http_uri         *uri;
    zeroconf_devinfo *devinfo;

    if (ident == NULL) {
        return NULL;
    }

    /* Copy the string so we can modify it in place while parsing. */
    buf_size = strlen(ident) + 1;
    buf = alloca(buf_size);
    memcpy(buf, ident, buf_size);

    name = strchr(buf, ':');
    if (name == NULL) {
        return NULL;
    }
    *name = '\0';
    name++;

    proto = id_proto_by_name(buf);
    if (proto == ID_PROTO_UNKNOWN) {
        return NULL;
    }

    uri_str = strchr(name, ':');
    if (uri_str == NULL) {
        return NULL;
    }
    *uri_str = '\0';
    uri_str++;

    if (*name == '\0') {
        return NULL;
    }

    uri = http_uri_new(uri_str, true);
    if (uri == NULL) {
        return NULL;
    }

    /* Build a zeroconf_devinfo */
    devinfo = mem_new(zeroconf_devinfo, 1);
    devinfo->ident = str_dup(ident);
    devinfo->name = str_dup(name);
    devinfo->endpoints = zeroconf_endpoint_new(proto, uri);
    return devinfo;
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
    ID_PROTO         proto = ID_PROTO_UNKNOWN;

    /* Check if the caller passed a direct device specification first. */
    devinfo = zeroconf_parse_devinfo_from_ident(ident);
    if (devinfo != NULL) {
        return devinfo;
    }

    /* Wait until device table is ready */
    zeroconf_initscan_wait();

    /* Lookup a device, static first */
    dev_conf = zeroconf_find_static_by_ident(ident);
    if (dev_conf == NULL) {
        device = zeroconf_device_find_by_ident(ident, &proto);
        if (device == NULL) {
            return NULL;
        }
    }

    /* Build a zeroconf_devinfo */
    devinfo = mem_new(zeroconf_devinfo, 1);
    devinfo->ident = str_dup(ident);

    if (dev_conf != NULL) {
        http_uri *uri = http_uri_clone(dev_conf->uri);
        devinfo->name = str_dup(dev_conf->name);
        devinfo->endpoints = zeroconf_endpoint_new(dev_conf->proto, uri);
    } else {
        devinfo->name = str_dup(zeroconf_device_name(device));
        devinfo->endpoints = zeroconf_device_endpoints(device, proto);
    }

    return devinfo;
}

/* Free zeroconf_devinfo, returned by zeroconf_devinfo_lookup()
 */
void
zeroconf_devinfo_free (zeroconf_devinfo *devinfo)
{
    mem_free((char*) devinfo->ident);
    mem_free((char*) devinfo->name);
    zeroconf_endpoint_list_free(devinfo->endpoints);
    mem_free(devinfo);
}

/******************** Initialization and cleanup *********************/
/* ZeroConf start/stop callback
 */
static void
zeroconf_start_stop_callback (bool start)
{
    if (start) {
        zeroconf_initscan_timer = eloop_timer_new(ZEROCONF_READY_TIMEOUT * 1000,
                zeroconf_initscan_timer_callback, NULL);
    } else {
        if (zeroconf_initscan_timer != NULL) {
            eloop_timer_cancel(zeroconf_initscan_timer);
            zeroconf_initscan_timer = NULL;
        }

        pthread_cond_broadcast(&zeroconf_initscan_cond);
    }
}

/* Initialize ZeroConf
 */
SANE_Status
zeroconf_init (void)
{
    char        *s;
    conf_device *dev;

    /* Initialize zeroconf */
    zeroconf_log = log_ctx_new("zeroconf", NULL);

    ll_init(&zeroconf_device_list);

    pthread_cond_init(&zeroconf_initscan_cond, NULL);

    if (conf.discovery) {
        zeroconf_initscan_bits = (1 << ZEROCONF_MDNS_HINT) |
                                 (1 << ZEROCONF_USCAN_TCP) |
                                 (1 << ZEROCONF_USCANS_TCP) |
                                 (1 << ZEROCONF_WSD);
    }

    eloop_add_start_stop_callback(zeroconf_start_stop_callback);

    /* Dump zeroconf configuration to the log */
    log_trace(zeroconf_log, "zeroconf configuration:");

    s = conf.discovery ? "enable" : "disable";
    log_trace(zeroconf_log, "  discovery    = %s", s);

    s = conf.model_is_netname ? "network" : "hardware";
    log_trace(zeroconf_log, "  model        = %s", s);

    s = conf.proto_auto ? "auto" : "manual";
    log_trace(zeroconf_log, "  protocol     = %s", s);

    s = "?";
    (void) s; /* Silence CLANG analyzer warning */

    switch (conf.wsdd_mode) {
    case WSDD_FAST: s = "fast"; break;
    case WSDD_FULL: s = "full"; break;
    case WSDD_OFF:  s = "OFF"; break;
    }
    log_trace(zeroconf_log, "  ws-discovery = %s", s);

    if (conf.devices != NULL) {
        log_trace(zeroconf_log, "statically configured devices:");

        for (dev = conf.devices; dev != NULL; dev = dev->next) {
            if (dev->uri != NULL) {
                log_debug(zeroconf_log, "  %s = %s, %s", dev->name,
                    http_uri_str(dev->uri), id_proto_name(dev->proto));
            } else {
                log_debug(zeroconf_log, "  %s = disable", dev->name);
            }
        }
    }

    return SANE_STATUS_GOOD;
}

/* Cleanup ZeroConf
 */
void
zeroconf_cleanup (void)
{
    if (zeroconf_log != NULL) {
        log_ctx_free(zeroconf_log);
        zeroconf_log = NULL;
        pthread_cond_destroy(&zeroconf_initscan_cond);
    }
}

/* vim:ts=8:sw=4:et
 */
