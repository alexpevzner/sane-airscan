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
    devid        ident;      /* Unique ident */
    uuid         uuid;       /* Device UUID */
    const char   *name;      /* Device name */
    unsigned int protocols;  /* Supported protocols, (set of 1 << ID_PROTO) */
    ll_node      node_list;  /* In zeroconf_device_list */
    ll_head      findings;   /* zeroconf_finding, by method */
    int          *ifaces;    /* Set of interfaces the device is visible from */
    size_t       ifaces_len; /* Length of ifaces array */
    size_t       ifaces_cap; /* Capacity of ifaces array */
};

/* Static variables
 */
static ll_head zeroconf_device_list;
static GCond zeroconf_initscan_cond;
static int zeroconf_initscan_bits;

/******************** Forward declarations *********************/
static zeroconf_endpoint*
zeroconf_endpoint_copy_single (const zeroconf_endpoint *endpoint);

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

    device->ident = devid_new();
    device->uuid = finding->uuid;
    device->name = g_strdup(finding->name);

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
    g_free(device);
}

/* Find zeroconf_device to add finding to
 */
static zeroconf_device*
zeroconf_device_find (zeroconf_finding *finding)
{
    ll_node *node;

    for (LL_FOR_EACH(node, &zeroconf_device_list)) {
        zeroconf_device *device;
        device = OUTER_STRUCT(node, zeroconf_device, node_list);
        if (uuid_equal(device->uuid, finding->uuid)) {
            if (finding->name == NULL && device->name == NULL) {
                return device;
            }

            if (finding->name != NULL &&
                device->name != NULL &&
                !strcasecmp(finding->name, device->name)) {
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

/* Add zeroconf_finding to zeroconf_device
 */
static void
zeroconf_device_add_finding (zeroconf_device *device,
    zeroconf_finding *finding)
{
    log_assert(NULL, finding->device == NULL);

    finding->device = device;
    ll_push_end(&device->findings, &finding->list_node);
    zeroconf_device_ifaces_add(device, finding->ifindex);

    if (finding->endpoints != NULL) {
        ID_PROTO proto = zeroconf_method_to_proto(finding->method);
        if (proto != ID_PROTO_UNKNOWN) {
            device->protocols |= 1 << proto;
        }
    }
}

/* Delete zeroconf_finding from zeroconf_device
 */
static void
zeroconf_device_del_finding (zeroconf_finding *finding)
{
    ll_node         *node;
    zeroconf_device *device = finding->device;

    log_assert(NULL, device != NULL);

    ll_del(&finding->list_node);
    if (ll_empty(&device->findings)) {
        zeroconf_device_del(device);
        return;
    }

    /* Rebuild interfaces and protocols */
    device->protocols = 0;
    device->ifaces_len = 0;

    for (LL_FOR_EACH(node, &device->findings)) {
        ID_PROTO         proto;

        finding = OUTER_STRUCT(node, zeroconf_finding, list_node);
        proto = zeroconf_method_to_proto(finding->method);

        zeroconf_device_ifaces_add(device, finding->ifindex );
        if (proto != ID_PROTO_UNKNOWN) {
            device->protocols |= 1 << proto;
        }
    }
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
                log_internal_error(NULL);
        }
    }

    return hint ? hint : wsd;
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

/* Build device ident string by prefixing devid with protocol
 * The returned string must be released with g_free()
 */
static const char*
zeroconf_device_ident (zeroconf_device *device, ID_PROTO proto)
{
    return g_strconcat( device->ident.text, "@", id_proto_name(proto), NULL);
}

/* Find zeroconf_device by ident
 */
static zeroconf_device*
zeroconf_device_find_by_ident (const char *ident)
{
    ll_node         *node;
    char            *buf, *proto_name;
    ID_PROTO        proto;
    zeroconf_device *device = NULL;

    /* Split ident into devid and protocol */
    buf = g_alloca(strlen(ident) + 1);
    strcpy(buf, ident);
    ident = buf;
    proto_name = strchr(ident, '@');
    if (proto_name == NULL) {
        return NULL;
    }

    *(proto_name ++) = '\0';
    proto = id_proto_by_name(proto_name);
    if (proto == ID_PROTO_UNKNOWN) {
        return NULL;
    }

    /* Lookup device */
    for (LL_FOR_EACH(node, &zeroconf_device_list)) {
        device = OUTER_STRUCT(node, zeroconf_device, node_list);
        if (!strcmp(device->ident.text, ident)) {
            break;
        }
    }

    if (device == NULL)
        return NULL;

    /* Check that device supports requested protocol */
    if ((device->protocols & (1 << proto)) != 0) {
        return device;
    }

    return NULL;
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
    conf_device *dev_conf;

    for (dev_conf = conf.devices; dev_conf != NULL; dev_conf = dev_conf->next) {
        if (!strcmp(dev_conf->ident.text, ident)) {
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
    char              ifname[IF_NAMESIZE] = "?";

    if_indextoname(finding->ifindex, ifname);

    log_debug(NULL, "zeroconf: found %s", finding->uuid.text);
    log_debug(NULL, "  method:    %s", zeroconf_method_name(finding->method));
    log_debug(NULL, "  interface: %d (%s)", finding->ifindex, ifname);
    log_debug(NULL, "  name:      %s", finding->name);
    log_debug(NULL, "  model:     %s", finding->model);

    if (proto != ID_PROTO_UNKNOWN) {
        zeroconf_endpoint *ep;

        log_debug(NULL, "  protocol:  %s", id_proto_name(proto));
        log_debug(NULL, "  endpoints:");
        for (ep = finding->endpoints; ep != NULL; ep = ep->next) {
            log_debug(NULL, "    %s", http_uri_str(ep->uri));
        }
    }

    if (zeroconf_find_static_by_name(finding->name) != NULL) {
        log_debug(NULL, "ignoring statically configured device");
        return;
    }

    device = zeroconf_device_find(finding);
    if (device != NULL) {
        log_debug(NULL, "zeroconf: using device %s", device->ident.text);
    } else {
        device = zeroconf_device_add(finding);
        log_debug(NULL, "zeroconf: added device %s", device->ident.text);
    }

    zeroconf_device_add_finding(device, finding);
}

/* Withdraw the finding
 */
void
zeroconf_finding_withdraw (zeroconf_finding *finding)
{
    char             ifname[IF_NAMESIZE] = "?";

    if_indextoname(finding->ifindex, ifname);

    log_debug(NULL, "zeroconf: gone %s", finding->uuid.text);
    log_debug(NULL, "  method:    %s", zeroconf_method_name(finding->method));
    log_debug(NULL, "  interface: %d (%s)", finding->ifindex, ifname);

    zeroconf_device_del_finding(finding);
}

/* Notify zeroconf subsystem that initial scan
 * for the method is done
 */
void
zeroconf_finding_done (ZEROCONF_METHOD method)
{
    log_debug(NULL, "zeroconf: %s: initial scan finished",
        zeroconf_method_name(method));

    zeroconf_initscan_bits &= ~(1 << method);
    g_cond_broadcast(&zeroconf_initscan_cond);
}

/******************** Support for SANE API *********************/
/* Wait intil initial scan is done
 */
static void
zeroconf_initscan_wait (void)
{
    gint64            timeout;

    timeout = g_get_monotonic_time() +
        ZEROCONF_READY_TIMEOUT * G_TIME_SPAN_SECOND;

    while (zeroconf_initscan_bits != 0 &&
           eloop_cond_wait_until(&zeroconf_initscan_cond, timeout)) {
    }
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
        dev_count += math_popcount(device->protocols);
    }

    /* Build list of devices */
    dev_list = g_new0(const SANE_Device*, dev_count + 1);
    dev_count = 0;

    for (dev_conf = conf.devices; dev_conf != NULL; dev_conf = dev_conf->next) {
        SANE_Device *info = g_new0(SANE_Device, 1);
        const char  *proto = id_proto_name(dev_conf->proto);

        dev_list[dev_count ++] = info;

        info->name = g_strdup(dev_conf->ident.text);
        info->vendor = g_strdup(proto);
        info->model = g_strdup(dev_conf->name);
        info->type = g_strdup_printf("%s network scanner", proto);
    }

    dev_count_static = dev_count;

    for (LL_FOR_EACH(node, &zeroconf_device_list)) {
        zeroconf_device *device;
        ID_PROTO        proto;

        device = OUTER_STRUCT(node, zeroconf_device, node_list);
        for (proto = 0; proto < NUM_ID_PROTO; proto ++) {
            if ((device->protocols & (1 << proto)) != 0) {
                SANE_Device            *info = g_new0(SANE_Device, 1);
                const char             *proto_name = id_proto_name(proto);
                const zeroconf_finding *finding;

                dev_list[dev_count ++] = info;
                finding = zeroconf_device_name_model_source(device);
                log_assert(NULL, finding != NULL);

                info->name = zeroconf_device_ident(device, proto);
                info->vendor = g_strdup(proto_name);
                if (conf.model_is_netname) {
                    info->model = g_strdup(finding->name);
                } else {
                    info->model = g_strdup(finding->model);
                }
                info->type = g_strdup_printf("%s network scanner", proto_name);
            }
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
    devinfo->ident = g_strdup(ident);

    if (dev_conf != NULL) {
        http_uri *uri = http_uri_clone(dev_conf->uri);

        if (dev_conf->proto == ID_PROTO_ESCL) {
            http_uri_fix_end_slash(uri);
        }

        devinfo->name = g_strdup(dev_conf->name);
        devinfo->endpoints = zeroconf_endpoint_new(dev_conf->proto, uri);
    } else {
        const zeroconf_finding *finding;

        finding = zeroconf_device_name_model_source(device);
        log_assert(NULL, finding != NULL);

        devinfo->name = g_strdup(finding->name);
        devinfo->endpoints = zeroconf_device_endpoints(device, ID_PROTO_ESCL);
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
/* Initialize ZeroConf
 */
SANE_Status
zeroconf_init (void)
{
    ll_init(&zeroconf_device_list);

    zeroconf_initscan_bits = (1 << ZEROCONF_MDNS_HINT) |
                             (1 << ZEROCONF_USCAN_TCP) |
                             (1 << ZEROCONF_USCANS_TCP);

    return SANE_STATUS_GOOD;
}

/* Cleanup ZeroConf
 */
void
zeroconf_cleanup (void)
{
}

/* vim:ts=8:sw=4:et
 */
