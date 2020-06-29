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

#include <stdlib.h>
#include <string.h>

/******************** Constants *********************/
/* Service types we are interested in
 */
#define ZEROCONF_SERVICE_USCAN                  "_uscan._tcp"
#define ZEROCONF_SERVICE_USCANS                 "_uscans._tcp"

/* If failed, AVAHI client will be automatically
 * restarted after the following timeout expires,
 * in seconds
 */
#define ZEROCONF_AVAHI_CLIENT_RESTART_TIMEOUT   1

/* Max time to wait until device table is ready, in seconds
 */
#define ZEROCONF_READY_TIMEOUT                  5

/* Initial size of zeroconf_device::ifaces
 */
#define ZEROCONF_DEVICE_IFACES_INITIAL_LEN      4

/******************** Local Types *********************/
/* zeroconf_device represents a single device
 */
struct zeroconf_device {
    unsigned int devid;      /* Unique ident */
    uuid         uuid;       /* Device UUID */
    const char   *name;      /* Device name */
    unsigned int protocols;  /* Protocols with endpoints, set of 1<<ID_PROTO */
    unsigned int methods;    /* How device was discovered, set of
                                1 << ZEROCONF_METHOD */
    ll_node      node_list;  /* In zeroconf_device_list */
    ll_head      findings;   /* zeroconf_finding, by method */
    int          *ifaces;    /* Set of interfaces the device is visible from */
    size_t       ifaces_len; /* Length of ifaces array */
    size_t       ifaces_cap; /* Capacity of ifaces array */
};

/* Global variables
 */
log_ctx *zeroconf_log;

/* Static variables
 */
static ll_head zeroconf_device_list;
static GCond zeroconf_initscan_cond;
static int zeroconf_initscan_bits;
static eloop_timer *zeroconf_initscan_timer;

/******************** Forward declarations *********************/
static bool
zeroconf_device_ifaces_lookup (zeroconf_device *device, int ifindex);

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
    zeroconf_device *device = g_new0(zeroconf_device, 1);

    device->devid = devid_alloc();
    device->uuid = finding->uuid;
    if (finding->name != NULL) {
        device->name = g_strdup(finding->name);
    }

    ll_init(&device->findings);

    device->ifaces_cap = ZEROCONF_DEVICE_IFACES_INITIAL_LEN;
    device->ifaces = g_malloc(device->ifaces_cap * sizeof(*device->ifaces));

    ll_push_end(&zeroconf_device_list, &device->node_list);
    return device;
}

/* Delete the device
 */
static void
zeroconf_device_del (zeroconf_device *device)
{
    g_free(device->ifaces);
    ll_del(&device->node_list);
    g_free((char*) device->name);
    devid_free(device->devid);
    g_free(device);
}

/* Find zeroconf_device by uuid and name
 */
static zeroconf_device*
zeroconf_device_find_by_uuid_and_name (uuid uuid, const char *name)
{
    ll_node *node;

    for (LL_FOR_EACH(node, &zeroconf_device_list)) {
        zeroconf_device *device;
        device = OUTER_STRUCT(node, zeroconf_device, node_list);

        if (device->name != NULL && uuid_equal(uuid, device->uuid)) {
            if (!strcasecmp(name, device->name)) {
                return device;
            }
        }
    }

    return NULL;
}

/* Find anonymous device by uuid
 */
static zeroconf_device*
zeroconf_device_find_by_uuid(uuid uuid)
{
    ll_node *node;

    for (LL_FOR_EACH(node, &zeroconf_device_list)) {
        zeroconf_device *device;
        device = OUTER_STRUCT(node, zeroconf_device, node_list);

        if (device->name == NULL && uuid_equal(uuid, device->uuid)) {
            return device;
        }
    }

    return NULL;
}

/* Find named device by uuid and interface index
 */
static zeroconf_device*
zeroconf_device_find_by_uuid_and_ifindex (uuid uuid, int ifindex)
{
    ll_node *node;

    for (LL_FOR_EACH(node, &zeroconf_device_list)) {
        zeroconf_device *device;
        device = OUTER_STRUCT(node, zeroconf_device, node_list);

        if (device->name != NULL && uuid_equal(uuid, device->uuid)) {
            if (zeroconf_device_ifaces_lookup(device, ifindex)) {
                return device;
            }
        }
    }

    return NULL;
}

/* Check if device is visible from the particular network interface
 */
static bool
zeroconf_device_ifaces_lookup (zeroconf_device *device, int ifindex)
{
    size_t i;

    for (i = 0; i < device->ifaces_len; i ++ ) {
        if (ifindex == device->ifaces[i]) {
            return true;
        }
    }

    return false;
}

/* Add interface to the set of interfaces device is seen from
 */
static void
zeroconf_device_ifaces_add (zeroconf_device *device, int ifindex)
{
    if (!zeroconf_device_ifaces_lookup(device, ifindex)) {
        if (device->ifaces_len == device->ifaces_cap) {
            device->ifaces_cap *= 2;
            device->ifaces = g_realloc(device->ifaces,
                device->ifaces_cap * sizeof(*device->ifaces));
        }

        device->ifaces[device->ifaces_len ++] = ifindex;
    }
}

/* Rebuild device->ifaces, device->protocols and device->methods
 */
static void
zeroconf_device_rebuild_sets (zeroconf_device *device)
{
    ll_node *node;

    device->protocols = 0;
    device->methods = 0;
    device->ifaces_len = 0;

    for (LL_FOR_EACH(node, &device->findings)) {
        zeroconf_finding *finding;
        ID_PROTO         proto;

        finding = OUTER_STRUCT(node, zeroconf_finding, list_node);
        proto = zeroconf_method_to_proto(finding->method);

        zeroconf_device_ifaces_add(device, finding->ifindex);
        if (proto != ID_PROTO_UNKNOWN) {
            device->protocols |= 1 << proto;
        }
        device->methods |= 1 << finding->method;
    }
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
    zeroconf_device_ifaces_add(device, finding->ifindex);

    if (finding->endpoints != NULL) {
        ID_PROTO proto = zeroconf_method_to_proto(finding->method);
        if (proto != ID_PROTO_UNKNOWN) {
            device->protocols |= 1 << proto;
        }
        device->methods |= 1 << finding->method;
    }
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
}

/* Borrow findings that belongs to the particular interface.
 * Found findings will be added to the output list. List must
 * be initialized before call to this function
 */
static void
zeroconf_device_borrow_findings (zeroconf_device *device,
    int ifindex, ll_head *output)
{
    ll_node          *node, *next;
    zeroconf_finding *finding;

    for (node = ll_first(&device->findings); node != NULL; node = next) {
        next = ll_next(&device->findings, node);

        finding = OUTER_STRUCT(node, zeroconf_finding, list_node);
        if (finding->ifindex == ifindex) {
            finding->device = NULL;
            ll_del(node);
            ll_push_end(output, node);
        }
    }

    if (ll_empty(&device->findings)) {
        zeroconf_device_del(device);
        return;
    }

    zeroconf_device_rebuild_sets(device);
}

/* Get most authoritative zeroconf_finding, that provides
 * name and model
 */
static const zeroconf_finding*
zeroconf_device_name_model_source (zeroconf_device *device)
{
    ll_node          *node;
    zeroconf_finding *hint = NULL, *wsd = NULL;

    for (LL_FOR_EACH(node, &device->findings)) {
        zeroconf_finding *finding;
        finding = OUTER_STRUCT(node, zeroconf_finding, list_node);

        switch (finding->method) {
            case ZEROCONF_USCAN_TCP:
            case ZEROCONF_USCANS_TCP:
                return finding;

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

    return hint ? hint : wsd;
}

/* Get device name and model
 */
static void
zeroconf_device_name_model (zeroconf_device *device,
        const char **name, const char **model)
{
    const zeroconf_finding *finding = zeroconf_device_name_model_source(device);
    log_assert(zeroconf_log, finding != NULL);

    /* Note, device discovery may end up in the incomplete state,
     * when neither name nor model is available. At this
     * case we return device UUID as a name, to simplify
     * outer logic that relies on a fact that name is
     * always available
     */
    *model = finding->model ? finding->model : device->uuid.text;
    *name = device->name ? device->name : *model;
}

/* Get device name
 */
static const char*
zeroconf_device_name (zeroconf_device *device)
{
    const char *name, *model;

    if (device->name) {
        return device->name;
    }

    zeroconf_device_name_model(device, &name, &model);
    return name;
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
 * The returned string must be released with g_free()
 */
static const char*
zeroconf_ident_make (const char *name, unsigned int devid, ID_PROTO proto)
{
    return g_strdup_printf("%c%x:%s", zeroconf_ident_proto_encode(proto),
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
    zeroconf_endpoint *endpoint = g_new0(zeroconf_endpoint, 1);

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
    zeroconf_device   *device;
    ID_PROTO          proto = zeroconf_method_to_proto(finding->method);
    char              ifname[IF_NAMESIZE];
    ll_head           findings;
    ll_node           *node;
    const char        *found_by = NULL;

    ll_init(&findings);
    ll_push_end(&findings, &finding->list_node);

    /* Lookup anonymous device with the same uuid.
     *
     * If such a device was found, 3 cases are possible:
     *   1. New finding as also anonymous. At this case it
     *      will be added to device
     *   2. All findings, including the new one, belongs to
     *      the same network interface. At this case,
     *      anonymous device upgraded to named and new
     *      finding is added to it
     *   3. Some of device's findings belongs to another network
     *      interfaces. At this case, findings that belongs to
     *      the new finding's interface will be borrowed from
     *      the device, and new device will be created. Old
     *      device will keep remaining anonymous findings
     */
    device = zeroconf_device_find_by_uuid(finding->uuid);
    if (device != NULL && finding->name != NULL) {
        if (device->ifaces_len == 1 && device->ifaces[0] == finding->ifindex){
            /* Case 2: all findings belongs to the same network
             * interface; upgrade anonymous device to named
             */
            device->name = g_strdup(finding->name);
            found_by = "found by uuid";
        } else {
            /* Case 3: borrow findings that belongs to the new finding's
             * interface. Leave found device to keep remaining findings
             */
            zeroconf_device_borrow_findings(device,
                finding->ifindex, &findings);

            device = NULL;
        }
    }

    /* Lookup device by name and uuid */
    if (device == NULL && finding->name != NULL) {
        found_by = "found by uuid+name";
        device = zeroconf_device_find_by_uuid_and_name(finding->uuid,
            finding->name);
    }

    /* Lookup device by uuid and interface index */
    if (device == NULL && finding->name == NULL) {
        found_by = "found by uuid+ifindex";
        device = zeroconf_device_find_by_uuid_and_ifindex(finding->uuid,
            finding->ifindex);
    }

    /* Create new device, if still not found */
    if (device == NULL) {
        found_by = "created";
        device = zeroconf_device_add(finding);
    }

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
    log_debug(zeroconf_log, "  device:    %4.4x (%s)", device->devid, found_by);

    if (proto != ID_PROTO_UNKNOWN) {
        zeroconf_endpoint *ep;

        log_debug(zeroconf_log, "  protocol:  %s", id_proto_name(proto));
        log_debug(zeroconf_log, "  endpoints:");
        for (ep = finding->endpoints; ep != NULL; ep = ep->next) {
            log_debug(zeroconf_log, "    %s", http_uri_str(ep->uri));
        }
    }

    /* Add finding to device */
    while ((node = ll_pop_beg(&findings)) != NULL) {
        finding = OUTER_STRUCT(node, zeroconf_finding, list_node);
        zeroconf_device_add_finding(device, finding);
    }

    g_cond_broadcast(&zeroconf_initscan_cond);
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
    g_cond_broadcast(&zeroconf_initscan_cond);
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
    g_cond_broadcast(&zeroconf_initscan_cond);
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
        return false;
    }

    /* If we are here, ZEROCONF_WSD is not done yet,
     * and if we are not in fast-wsdd mode, we must wait
     */
    log_assert(zeroconf_log,
        (zeroconf_initscan_bits & (1 << ZEROCONF_WSD)) != 0);

    if (conf.wsdd_mode != WSDD_FAST) {
        return false;
    }

    /* Check for completion, device by device:
     *
     * In manual protocol switch mode, WSDD must be done
     * for device, so we have a choice. Otherwise, it's
     * enough if device has supported protocols
     */
    for (LL_FOR_EACH(node, &zeroconf_device_list)) {
        device = OUTER_STRUCT(node, zeroconf_device, node_list);

        if (!conf.proto_auto) {
            if ((device->methods & (1 << ZEROCONF_WSD)) == 0) {
                return false;
            }
        } else {
            if (device->protocols == 0) {
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

    log_debug(zeroconf_log, "zeroconf_initscan_wait: requested");

    for (;;) {
        ok = zeroconf_initscan_done();
        if (ok || zeroconf_initscan_timer == NULL) {
            break;
        }
        eloop_cond_wait(&zeroconf_initscan_cond);
    }

    log_debug(zeroconf_log, "zeroconf_initscan_wait: %s",
        ok ? "OK" : "timeout" );
}

/* Compare SANE_Device*, for qsort
 */
static int
zeroconf_device_list_qsort_cmp (const void *p1, const void *p2)
{
    int   cmp;
    const SANE_Device *d1 = *(SANE_Device**) p1;
    const SANE_Device *d2 = *(SANE_Device**) p2;

    cmp = strcmp(d1->model, d2->model);
    if (cmp != 0) {
        cmp = strcmp(d1->name, d2->name);
    }

    return cmp;
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

    /* Wait until device table is ready */
    zeroconf_initscan_wait();

    /* Build list of devices */
    dev_count = 0;

    for (dev_conf = conf.devices; dev_conf != NULL; dev_conf = dev_conf->next) {
        SANE_Device *info = g_new0(SANE_Device, 1);
        const char  *proto = id_proto_name(dev_conf->proto);

        dev_list = sane_device_array_append(dev_list, info);
        dev_count ++;

        info->name = zeroconf_ident_make(dev_conf->name, dev_conf->devid,
            dev_conf->proto);
        info->vendor = g_strdup(proto);
        info->model = g_strdup(dev_conf->name);
        info->type = g_strdup_printf("%s network scanner", proto);
    }

    dev_count_static = dev_count;

    for (LL_FOR_EACH(node, &zeroconf_device_list)) {
        zeroconf_device *device;
        ID_PROTO        proto;
        const char      *name, *model;
        unsigned int    protocols;
        unsigned int    supported_protocols = 0;

        device = OUTER_STRUCT(node, zeroconf_device, node_list);
        zeroconf_device_name_model(device, &name, &model);
        protocols = zeroconf_device_protocols(device);

        if (zeroconf_find_static_by_name(name) != NULL) {
            /* Static configuration overrides discovery */
            continue;
        }

        for (proto = 0; proto < NUM_ID_PROTO; proto ++) {
            if ((protocols & (1 << proto)) != 0) {
                SANE_Device            *info = g_new0(SANE_Device, 1);
                const char             *proto_name = id_proto_name(proto);

                log_debug(zeroconf_log, "zeroconf_device_list_get: The device \'%s\' "
                    "supports %s, adding the device.",  name, proto_name);

                dev_list = sane_device_array_append(dev_list, info);
                dev_count ++;
                supported_protocols ++;

                info->name = zeroconf_ident_make(name, device->devid, proto);
                info->vendor = g_strdup(proto_name);
                info->model = g_strdup(conf.model_is_netname ? name : model);
                info->type = g_strdup_printf("%s network scanner", proto_name);
            }
        }

        if (supported_protocols == 0) {
            log_debug(zeroconf_log, "zeroconf_device_list_get: The device \'%s\' "
                "doesn't implement any of supported protocols. Skipping.", name);
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
    buf = g_alloca(buf_size);
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
    devinfo = g_new0(zeroconf_devinfo, 1);
    devinfo->ident = g_strdup(ident);
    devinfo->name = g_strdup(name);
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
    devinfo = g_new0(zeroconf_devinfo, 1);
    devinfo->ident = g_strdup(ident);

    if (dev_conf != NULL) {
        http_uri *uri = http_uri_clone(dev_conf->uri);
        devinfo->name = g_strdup(dev_conf->name);
        devinfo->endpoints = zeroconf_endpoint_new(dev_conf->proto, uri);
    } else {
        const char      *name, *model;

        zeroconf_device_name_model(device, &name, &model);
        devinfo->name = g_strdup(name);

        devinfo->endpoints = zeroconf_device_endpoints(device, proto);
    }

    return devinfo;
}

/* Free zeroconf_devinfo, returned by zeroconf_devinfo_lookup()
 */
void
zeroconf_devinfo_free (zeroconf_devinfo *devinfo)
{
    g_free((char*) devinfo->ident);
    g_free((char*) devinfo->name);
    zeroconf_endpoint_list_free(devinfo->endpoints);
    g_free(devinfo);
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

        g_cond_broadcast(&zeroconf_initscan_cond);
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
    switch (conf.wsdd_mode) {
    case WSDD_FAST: s = "fast"; break;
    case WSDD_FULL: s = "full"; break;
    case WSDD_OFF:  s = "OFF"; break;
    }
    log_trace(zeroconf_log, "  ws-discovery = %s", s);

    if (conf.devices != NULL) {
        log_trace(zeroconf_log, "statically configured devices:");

        for (dev = conf.devices; dev != NULL; dev = dev->next) {
            log_debug(zeroconf_log, "  %s = %s, %s", dev->name,
                http_uri_str(dev->uri), id_proto_name(dev->proto));
        }
    }

    return SANE_STATUS_GOOD;
}

/* Cleanup ZeroConf
 */
void
zeroconf_cleanup (void)
{
    log_ctx_free(zeroconf_log);
    zeroconf_log = NULL;
}

/* vim:ts=8:sw=4:et
 */
