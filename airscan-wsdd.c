/* AirScan (a.k.a. eSCL) backend for SANE
 *
 * Copyright (C) 2019 and up by Alexander Pevzner (pzz@apevzner.com)
 * See LICENSE for license terms and conditions
 *
 * Web Services Dynamic Discovery (WS-Discovery)
 */

#define _GNU_SOURCE

#include "airscan.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

/* Protocol times, in milliseconds
 */
#define WSDD_RETRANSMIT_MIN     100     /* Min retransmit time */
#define WSDD_RETRANSMIT_MAX     250     /* Max retransmit time */
#define WSDD_DISCOVERY_TIME     2500    /* Overall discovery time */

/* wsdd_resolver represents a per-interface WSDD resolver
 */
typedef struct {
    int          fd;           /* File descriptor */
    int          ifindex;      /* Interface index */
    bool         ipv6;         /* We are on IPv6 */
    eloop_fdpoll *fdpoll;      /* Socket fdpoll */
    eloop_timer  *timer;       /* Retransmit timer */
    uint32_t     total_time;   /* Total elapsed time */
    ip_straddr   str_ifaddr;   /* Interface address */
    ip_straddr   str_sockaddr; /* Per-interface socket address */
    bool         initscan;     /* Initial scan in progress */
} wsdd_resolver;

/* wsdd_finding represents zeroconf_finding for WSD
 * device discovery
 */
typedef struct {
    zeroconf_finding  finding;      /* Base class */
    const char        *address;     /* Device "address" in WS-SD sense */
    ll_head           xaddrs;       /* List of wsdd_xaddr */
    http_client       *http_client; /* HTTP client */
    ll_node           list_node;    /* In wsdd_finding_list */
    bool              published;    /* This finding is published */
} wsdd_finding;

/* wsdd_xaddr represents device transport address
 */
typedef struct {
    http_uri   *uri;      /* Device URI */
    ll_node    list_node; /* In wsdd_finding::xaddrs */
} wsdd_xaddr;

/* WSDD_ACTION represents WSDD message action
 */
typedef enum {
    WSDD_ACTION_UNKNOWN,
    WSDD_ACTION_HELLO,
    WSDD_ACTION_BYE,
    WSDD_ACTION_PROBEMATCHES
} WSDD_ACTION;

/* wsdd_message represents a parsed WSDD message
 */
typedef struct {
    WSDD_ACTION  action;     /* Message action */
    const char   *address;   /* Endpoint reference */
    ll_head      xaddrs;     /* List of wsdd_xaddr */
    bool         is_scanner; /* Device is scanner */
} wsdd_message;

/* Forward declarations
 */
static void
wsdd_message_free(wsdd_message *msg);

static void
wsdd_resolver_send_probe (wsdd_resolver *resolver);

static wsdd_resolver*
wsdd_netif_resolver_by_ifindex (int ifindex);

/* Static variables
 */
static log_ctx             *wsdd_log;
static netif_notifier      *wsdd_netif_notifier;
static netif_addr          *wsdd_netif_addr_list;
static int                 wsdd_mcsock_ipv4 = -1;
static int                 wsdd_mcsock_ipv6 = -1;
static eloop_fdpoll        *wsdd_fdpoll_ipv4;
static eloop_fdpoll        *wsdd_fdpoll_ipv6;
static char                wsdd_buf[65536];
static struct sockaddr_in  wsdd_mcast_ipv4;
static struct sockaddr_in6 wsdd_mcast_ipv6;
static ll_head             wsdd_finding_list;
static int                 wsdd_initscan_count;

/* WS-DD Probe template
 */
static const char *wsdd_probe_template =
    "<?xml version=\"1.0\" ?>\n"
    "<s:Envelope xmlns:a=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\" xmlns:d=\"http://schemas.xmlsoap.org/ws/2005/04/discovery\" xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:wsdp=\"http://schemas.xmlsoap.org/ws/2006/02/devprof\">\n"
    " <s:Header>\n"
    "  <a:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</a:Action>\n"
    "  <a:MessageID>%s</a:MessageID>\n"
    "  <a:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</a:To>\n"
    " </s:Header>\n"
    " <s:Body>\n"
    "  <d:Probe>\n"
    "   <d:Types>wsdp:Device</d:Types>\n"
    "  </d:Probe>\n"
    " </s:Body>\n"
    "</s:Envelope>\n";

/* WS-DD Get (metadata) template
 */
static const char *wsdd_get_metadata_template =
    "<?xml version=\"1.0\" ?>\n"
    "<s:Envelope xmlns:a=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\" xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\">\n"
    " <s:Header>\n"
    "  <a:Action>http://schemas.xmlsoap.org/ws/2004/09/transfer/Get</a:Action>\n"
    "  <a:MessageID>%s</a:MessageID>\n"
    "  <a:To>%s</a:To>\n"
    "  <a:ReplyTo>\n"
    "    <a:Address>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address>\n"
    "  </a:ReplyTo>\n"
    " </s:Header>\n"
    " <s:Body/>\n"
    "</s:Envelope>\n";

/* XML namespace translation
 */
static const xml_ns wsdd_ns_rules[] = {
    {"s",       "http*://schemas.xmlsoap.org/soap/envelope"}, /* SOAP 1.1 */
    {"s",       "http*://www.w3.org/2003/05/soap-envelope"},  /* SOAP 1.2 */
    {"d",       "http*://schemas.xmlsoap.org/ws/2005/04/discovery"},
    {"a",       "http*://schemas.xmlsoap.org/ws/2004/08/addressing"},
    {"devprof", "http*://schemas.xmlsoap.org/ws/2006/02/devprof"},
    {"mex",     "http*://schemas.xmlsoap.org/ws/2004/09/mex"},
    {"pnpx",    "http*://schemas.microsoft.com/windows/pnpx/2005/10"},
    {NULL, NULL}
};

/******************** wsdd_xaddr operations ********************/
/* Create new wsdd_xaddr. Newly created wsdd_xaddr takes uri ownership
 */
static wsdd_xaddr*
wsdd_xaddr_new (http_uri *uri)
{
    wsdd_xaddr *xaddr = g_new0(wsdd_xaddr, 1);
    xaddr->uri = uri;
    return xaddr;
}

/* Destroy wsdd_xaddr
 */
static void
wsdd_xaddr_free (wsdd_xaddr *xaddr)
{
    http_uri_free(xaddr->uri);
    g_free(xaddr);
}

/* Add wsdd_xaddr to the list.
 * Takes ownership on URI.
 */
static void
wsdd_xaddr_list_add (ll_head *list, http_uri *uri)
{
    wsdd_xaddr *xaddr;
    ll_node    *node;

    /* Check for duplicates */
    for (LL_FOR_EACH(node, list)) {
        xaddr = OUTER_STRUCT(node, wsdd_xaddr, list_node);
        if (http_uri_equal(xaddr->uri, uri)) {
            http_uri_free(uri);
            return;
        }
    }

    /* Add new xaddr */
    xaddr = wsdd_xaddr_new(uri);
    ll_push_end(list, &xaddr->list_node);
}

/* Purge list of wsdd_xaddr
 */
static void
wsdd_xaddr_list_purge (ll_head *list)
{
    ll_node    *node;

    while ((node = ll_first(list)) != NULL) {
        wsdd_xaddr *xaddr = OUTER_STRUCT(node, wsdd_xaddr, list_node);
        ll_del(&xaddr->list_node);
        wsdd_xaddr_free(xaddr);
    }
}

/******************** wsdd_initscan_count operations ********************/
/* Increment wsdd_initscan_count
 */
static void
wsdd_initscan_count_inc (void)
{
    wsdd_initscan_count ++;
}

/* Decrement wsdd_initscan_count
 */
static void
wsdd_initscan_count_dec (void)
{
    log_assert(wsdd_log, wsdd_initscan_count > 0);
    wsdd_initscan_count --;
    if (wsdd_initscan_count == 0) {
        zeroconf_finding_done(ZEROCONF_WSD);
    }
}

/******************** wsdd_finding operations ********************/
/* Create new wsdd_finding
 */
static wsdd_finding*
wsdd_finding_new (int ifindex, const char *address)
{
    wsdd_finding *wsdd = g_new0(wsdd_finding, 1);

    wsdd->finding.method = ZEROCONF_WSD;
    wsdd->finding.uuid = uuid_parse(address);
    if (!uuid_valid(wsdd->finding.uuid)) {
        wsdd->finding.uuid = uuid_hash(address);
    }
    wsdd->finding.ifindex = ifindex;

    wsdd->address = g_strdup(address);
    ll_init(&wsdd->xaddrs);
    wsdd->http_client = http_client_new (wsdd_log, wsdd);

    return wsdd;
}

/* Destroy wsdd_finding
 */
static void
wsdd_finding_free (wsdd_finding *wsdd)
{
    if (wsdd->published) {
        zeroconf_finding_withdraw(&wsdd->finding);
    }

    http_client_cancel(wsdd->http_client);
    http_client_free(wsdd->http_client);

    zeroconf_endpoint_list_free(wsdd->finding.endpoints);
    g_free((char*) wsdd->address);
    wsdd_xaddr_list_purge(&wsdd->xaddrs);
    g_free((char*) wsdd->finding.model);
    g_free((char*) wsdd->finding.name);
    g_free(wsdd);
}

/* Add wsdd_finding to the wsdd_finding_list.
 * If finding already present, does nothing and returns NULL
 */
static wsdd_finding*
wsdd_finding_add (int ifindex, const char *address)
{
    ll_node      *node;
    wsdd_finding *wsdd;

    /* Check for duplicates */
    for (LL_FOR_EACH(node, &wsdd_finding_list)) {
        wsdd = OUTER_STRUCT(node, wsdd_finding, list_node);
        if (wsdd->finding.ifindex == ifindex &&
            !strcmp(wsdd->address, address)) {
            return NULL;
        }
    }

    /* Add new finding */
    wsdd = wsdd_finding_new(ifindex, address);
    ll_push_end(&wsdd_finding_list, &wsdd->list_node);

    return wsdd;
}

/* Delete wsdd_finding from the wsdd_finding_list
 */
static void
wsdd_finding_del (const char *address)
{
    ll_node   *node;

    /* Lookup finding in the list */
    for (LL_FOR_EACH(node, &wsdd_finding_list)) {
        wsdd_finding *wsdd = OUTER_STRUCT(node, wsdd_finding, list_node);
        if (!strcmp(wsdd->address, address)) {
            ll_del(&wsdd->list_node);
            wsdd_finding_free(wsdd);
            return;
        }
    }
}

/* Delete all findings from the wsdd_finding_list
 */
static void
wsdd_finding_list_purge (void)
{
    ll_node   *node;

    while ((node = ll_first(&wsdd_finding_list)) != NULL) {
        wsdd_finding *wsdd = OUTER_STRUCT(node, wsdd_finding, list_node);
        ll_del(&wsdd->list_node);
        wsdd_finding_free(wsdd);
    }
}

/* Parse endpoint addresses from the devprof:Hosted section of the
 * device metadata:
 *   <devprof:Hosted>
 *     <a:EndpointReference>
 *       <a:Address>http://192.168.1.102:5358/WSDScanner</a:Address>
 *     </addressing:EndpointReference>
 *     <devprof:Types>scan:ScannerServiceType</devprof:Types>
 *     <devprof:ServiceId>uri:4509a320-00a0-008f-00b6-002507510eca/WSDScanner</devprof:ServiceId>
 *     <pnpx:CompatibleId>http://schemas.microsoft.com/windows/2006/08/wdp/scan/ScannerServiceType</pnpx:CompatibleId>
 *     <pnpx:HardwareId>VEN_0103&amp;DEV_069D</pnpx:HardwareId>
 *   </devprof:Hosted>
 *
 * It ignores all endpoints except ScannerServiceType, extracts endpoint
 * URLs and returns them as slice of strings
 */
static void
wsdd_finding_parse_endpoints (wsdd_finding *wsdd, xml_rd *xml)
{
    unsigned int      level = xml_rd_depth(xml);
    size_t            prefixlen = strlen(xml_rd_node_path(xml));
    bool              is_scanner = false;
    zeroconf_endpoint *endpoints = NULL;

    while (!xml_rd_end(xml)) {
        const char *path = xml_rd_node_path(xml) + prefixlen;
        const char *val;

        if (!strcmp(path, "/devprof:Types")) {
            val = xml_rd_node_value(xml);
            if (strstr(val, "ScannerServiceType") != NULL) {
                is_scanner = true;
            }
        } else if (!strcmp(path, "/a:EndpointReference/a:Address")) {
            http_uri          *uri;
            zeroconf_endpoint *ep;

            val = xml_rd_node_value(xml);
            uri = http_uri_new(val, true);
            if (uri != NULL) {
                http_uri_fix_ipv6_zone(uri, wsdd->finding.ifindex);
                ep = zeroconf_endpoint_new(ID_PROTO_WSD, uri);
                ep->next = endpoints;
                endpoints = ep;
            }
        }

        xml_rd_deep_next(xml, level);
    }

    if (!is_scanner) {
        zeroconf_endpoint_list_free(endpoints);
        return;
    }

    while (endpoints != NULL) {
        zeroconf_endpoint *ep = endpoints;
        endpoints = endpoints->next;
        ep->next = wsdd->finding.endpoints;
        wsdd->finding.endpoints = ep;
    }
}

/* Get metadata callback
 */
static void
wsdd_finding_get_metadata_callback (void *ptr, http_query *q)
{
    error        err;
    xml_rd       *xml = NULL;
    http_data    *data;
    wsdd_finding *wsdd = ptr;
    char         *model = NULL, *manufacturer = NULL;

    (void) ptr;

    /* Check query status */
    err = http_query_error(q);
    if (err != NULL) {
        log_trace(wsdd_log, "metadata query: %s", ESTRING(err));
        goto DONE;
    }

    /* Parse XML */
    data = http_query_get_response_data(q);
    if (data->size == 0) {
        log_trace(wsdd_log, "metadata query: no data");
        goto DONE;
    }

    err = xml_rd_begin(&xml, data->bytes, data->size, wsdd_ns_rules);
    if (err != NULL) {
        log_trace(wsdd_log, "metadata query: %s", ESTRING(err));
        goto DONE;
    }

    /* Decode XML */
    while (!xml_rd_end(xml)) {
        const char *path = xml_rd_node_path(xml);

        if (!strcmp(path, "s:Envelope/s:Body/mex:Metadata/mex:MetadataSection"
                "/devprof:Relationship/devprof:Hosted")) {
            wsdd_finding_parse_endpoints(wsdd, xml);
        } else if (!strcmp(path, "s:Envelope/s:Body/mex:Metadata/mex:MetadataSection"
                "/devprof:ThisModel/devprof:Manufacturer")) {
            if (manufacturer == NULL) {
                manufacturer = g_strdup(xml_rd_node_value(xml));
            }
        } else if (!strcmp(path, "s:Envelope/s:Body/mex:Metadata/mex:MetadataSection"
                "/devprof:ThisModel/devprof:ModelName")) {
            if (model == NULL) {
                model = g_strdup(xml_rd_node_value(xml));
            }
        }

        xml_rd_deep_next(xml, 0);
    }

    if (wsdd->finding.model == NULL) {
        if (model != NULL && manufacturer != NULL) {
            wsdd->finding.model = g_strdup_printf("%s %s", manufacturer, model);
        } else if (model != NULL) {
            wsdd->finding.model = model;
            model = NULL;
        } else if (manufacturer != NULL) {
            wsdd->finding.model = manufacturer;
            manufacturer = NULL;
        } else {
            wsdd->finding.model = g_strdup(wsdd->address);
        }
    }

    /* Cleanup and exit */
DONE:
    xml_rd_finish(&xml);
    g_free(model);
    g_free(manufacturer);

    if (http_client_num_pending(wsdd->http_client) == 0) {
        zeroconf_endpoint *endpoint;

        wsdd->finding.endpoints = zeroconf_endpoint_list_sort_dedup(
                wsdd->finding.endpoints);

        log_debug(wsdd_log, "\"%s\": address: %s",
                wsdd->finding.model, wsdd->address);
        log_debug(wsdd_log, "\"%s\": uuid: %s",
                wsdd->finding.model, wsdd->finding.uuid.text);
        log_debug(wsdd_log, "\"%s\": discovered endpoints:",
                wsdd->finding.model);

        for (endpoint = wsdd->finding.endpoints; endpoint != NULL;
            endpoint = endpoint->next) {
            log_debug(wsdd_log, "  %s", http_uri_str(endpoint->uri));
        }

        if (!wsdd->published) {
            wsdd->published = true;
            zeroconf_finding_publish(&wsdd->finding);
        }
    }
}


/* Query device metadata
 */
static void
wsdd_finding_get_metadata (wsdd_finding *wsdd, int ifindex, wsdd_xaddr *xaddr)
{
    uuid       u = uuid_rand();
    http_query *q;

    log_trace(wsdd_log, "querying metadata from %s", http_uri_str(xaddr->uri));

    sprintf(wsdd_buf, wsdd_get_metadata_template, u.text, wsdd->address);
    q = http_query_new(wsdd->http_client, http_uri_clone(xaddr->uri),
        "POST", g_strdup(wsdd_buf), "application/soap+xml; charset=utf-8");

    http_query_set_uintptr(q, ifindex);
    http_query_submit(q, wsdd_finding_get_metadata_callback);
}

/******************** wsdd_message operations ********************/
/* Parse transport addresses. Universal function
 * for Hello/Bye/ProbeMatch message
 */
static void
wsdd_message_parse_endpoint (wsdd_message *msg, xml_rd *xml)
{
    unsigned int level = xml_rd_depth(xml);
    char         *xaddrs_text = NULL;
    size_t       prefixlen = strlen(xml_rd_node_path(xml));

    while (!xml_rd_end(xml)) {
        const char *path = xml_rd_node_path(xml) + prefixlen;
        const char *val;

        if (!strcmp(path, "/d:Types")) {
            val = xml_rd_node_value(xml);
            msg->is_scanner = !!strstr(val, "ScanDeviceType");
        } else if (!strcmp(path, "/d:XAddrs")) {
            g_free(xaddrs_text);
            xaddrs_text = g_strdup(xml_rd_node_value(xml));
        } else if (!strcmp(path, "/a:EndpointReference/a:Address")) {
            g_free((char*) msg->address);
            msg->address = g_strdup(xml_rd_node_value(xml));
        }

        xml_rd_deep_next(xml, level);
    }

    if (xaddrs_text != NULL) {
        char              *tok, *saveptr;
        static const char *delim = "\t\n\v\f\r \x85\xA0";

        for (tok = strtok_r(xaddrs_text, delim, &saveptr); tok != NULL;
             tok = strtok_r(NULL, delim, &saveptr)) {

            http_uri   *uri = http_uri_new(tok, true);

            if (uri != NULL) {
                wsdd_xaddr_list_add(&msg->xaddrs, uri);
            }
        }
    }

    g_free(xaddrs_text);
}

/* Parse WSDD message
 */
static wsdd_message*
wsdd_message_parse (const char *xml_text, size_t xml_len)
{
    wsdd_message *msg = g_new0(wsdd_message, 1);
    xml_rd       *xml;
    error        err;

    ll_init(&msg->xaddrs);

    err = xml_rd_begin(&xml, xml_text, xml_len, wsdd_ns_rules);
    if (err != NULL) {
        goto DONE;
    }

    while (!xml_rd_end(xml)) {
        const char *path = xml_rd_node_path(xml);
        const char *val;

        if (!strcmp(path, "s:Envelope/s:Header/a:Action")) {
            val = xml_rd_node_value(xml);
            if (strstr(val, "Hello")) {
                msg->action = WSDD_ACTION_HELLO;
            } else if (strstr(val, "Bye")) {
                msg->action = WSDD_ACTION_BYE;
            } else if (strstr(val, "ProbeMatches")) {
                msg->action = WSDD_ACTION_PROBEMATCHES;
            }
        } else if (!strcmp(path, "s:Envelope/s:Body/d:Hello") ||
                   !strcmp(path, "s:Envelope/s:Body/d:Bye") ||
                   !strcmp(path, "s:Envelope/s:Body/d:ProbeMatches/d:ProbeMatch")) {
            wsdd_message_parse_endpoint(msg, xml);
        }
        xml_rd_deep_next(xml, 0);
    }

DONE:
    xml_rd_finish(&xml);
    if (err != NULL ||
        msg->action == WSDD_ACTION_UNKNOWN ||
        msg->address == NULL ||
        (msg->action == WSDD_ACTION_HELLO && ll_empty(&msg->xaddrs)) ||
        (msg->action == WSDD_ACTION_PROBEMATCHES && ll_empty(&msg->xaddrs))) {
        wsdd_message_free(msg);
        msg = NULL;
    }

    return msg;
}

/* Free wsdd_message
 */
static void
wsdd_message_free (wsdd_message *msg)
{
    if (msg != NULL) {
        g_free((char*) msg->address);
        wsdd_xaddr_list_purge(&msg->xaddrs);
        g_free(msg);
    }
}

/* Get message action name, for debugging
 */
static const char*
wsdd_message_action_name (const wsdd_message *msg)
{
    switch (msg->action) {
    case WSDD_ACTION_UNKNOWN:
        break;

    case WSDD_ACTION_HELLO:        return "Hello";
    case WSDD_ACTION_BYE:          return "Bye";
    case WSDD_ACTION_PROBEMATCHES: return "ProbeMatches";
    }

    return "UNKNOWN";
}

/******************** wsdd_resolver operations ********************/
/* Dispatch received WSDD message
 */
static void
wsdd_resolver_message_dispatch (wsdd_resolver *resolver, wsdd_message *msg)
{
    wsdd_finding *wsdd;
    wsdd_xaddr   *xaddr;
    ll_node      *node;

    /* Fixup ipv6 zones */
    for (LL_FOR_EACH(node, &msg->xaddrs)) {
        xaddr = OUTER_STRUCT(node, wsdd_xaddr, list_node);
        http_uri_fix_ipv6_zone(xaddr->uri, resolver->ifindex);
    }

    /* Write trace messages */
    log_trace(wsdd_log, "%s message received:",
        wsdd_message_action_name(msg));
    log_trace(wsdd_log, "  address:    %s", msg->address);
    log_trace(wsdd_log, "  is_scanner: %s", msg->is_scanner ? "yes" : "no");
    for (LL_FOR_EACH(node, &msg->xaddrs)) {
        xaddr = OUTER_STRUCT(node, wsdd_xaddr, list_node);
        log_trace(wsdd_log, "  xaddr:      %s", http_uri_str(xaddr->uri));
    }
    log_trace(wsdd_log, "");

    /* Handle the message */
    switch (msg->action) {
    case WSDD_ACTION_HELLO:
    case WSDD_ACTION_PROBEMATCHES:
        wsdd = wsdd_finding_add(resolver->ifindex, msg->address);
        if (wsdd != NULL) {
            wsdd_xaddr *xaddr;

            ll_cat(&wsdd->xaddrs, &msg->xaddrs);
            for (LL_FOR_EACH(node, &wsdd->xaddrs)) {
                xaddr = OUTER_STRUCT(node, wsdd_xaddr, list_node);
                wsdd_finding_get_metadata(wsdd, resolver->ifindex, xaddr);
            }
        }
        break;

    case WSDD_ACTION_BYE:
        wsdd_finding_del(msg->address);
        break;

    default:
        break;
    }

    wsdd_message_free(msg);
}


/* Resolver read callback
 */
static void
wsdd_resolver_read_callback (int fd, void *data, ELOOP_FDPOLL_MASK mask)
{
    struct sockaddr_storage from, to;
    socklen_t               tolen = sizeof(to);
    ip_straddr              str_from, str_to;
    int                     rc;
    wsdd_message            *msg;
    struct iovec            vec = {wsdd_buf, sizeof(wsdd_buf)};
    uint8_t                 aux[8192];
    struct cmsghdr          *cmsg;
    int                     ifindex = 0;
    wsdd_resolver           *resolver;
    struct msghdr           msghdr = {
        .msg_name = &from,
        .msg_namelen = sizeof(from),
        .msg_iov = &vec,
        .msg_iovlen = 1,
        .msg_control = aux,
        .msg_controllen = sizeof(aux)
    };

    (void) mask;
    (void) data;

    /* Receive a packet */
    rc = recvmsg(fd, &msghdr, 0);
    if (rc <= 0) {
        return;
    }

    /* Fetch interface index from auxiliary data */
    for (cmsg = CMSG_FIRSTHDR(&msghdr); cmsg != NULL;
         cmsg = CMSG_NXTHDR(&msghdr, cmsg)) {
        if (cmsg->cmsg_level == IPPROTO_IPV6 &&
            cmsg->cmsg_type == IPV6_PKTINFO) {
            struct in6_pktinfo *pkt = (struct in6_pktinfo*) CMSG_DATA(cmsg);
            ifindex = pkt->ipi6_ifindex;
        } else if (cmsg->cmsg_level == IPPROTO_IP &&
            cmsg->cmsg_type == IP_PKTINFO) {
            struct in_pktinfo *pkt = (struct in_pktinfo*) CMSG_DATA(cmsg);
            ifindex = pkt->ipi_ifindex;
        }
    }

    str_from = ip_straddr_from_sockaddr((struct sockaddr*) &from);
    getsockname(fd, (struct sockaddr*) &to, &tolen);
    str_to = ip_straddr_from_sockaddr((struct sockaddr*) &to);

    log_trace(wsdd_log, "%d bytes received: %s->%s", rc,
        str_from.text, str_to.text);
    log_trace_data(wsdd_log, "application/xml", wsdd_buf, rc);

    /* Lookup resolver by interface index */
    resolver = wsdd_netif_resolver_by_ifindex(ifindex);
    if (resolver == NULL) {
        return;
    }

    /* Parse and dispatch the message */
    msg = wsdd_message_parse(wsdd_buf, rc);
    if (msg != NULL) {
        wsdd_resolver_message_dispatch(resolver, msg);
    }
}

/* Retransmit timer callback
 */
static void
wsdd_resolver_timer_callback (void *data)
{
    wsdd_resolver *resolver = data;
    resolver->timer = NULL;

    if (resolver->total_time >= WSDD_DISCOVERY_TIME) {
        eloop_fdpoll_free(resolver->fdpoll);
        close(resolver->fd);
        resolver->fdpoll = NULL;
        resolver->fd = -1;
        log_debug(wsdd_log, "%s: done discovery", resolver->str_ifaddr.text);

        if (resolver->initscan) {
            resolver->initscan = false;
            wsdd_initscan_count_dec();
        }
    } else {
        wsdd_resolver_send_probe(resolver);
    };
}

/* Set retransmit timer
 */
static void
wsdd_resolver_timer_set (wsdd_resolver *resolver)
{
    uint32_t t;

    log_assert(wsdd_log, resolver->timer == NULL);

    if (resolver->total_time + WSDD_RETRANSMIT_MAX >= WSDD_DISCOVERY_TIME) {
        t = WSDD_DISCOVERY_TIME - resolver->total_time;
    } else {
        t = math_rand_range(WSDD_RETRANSMIT_MIN, WSDD_RETRANSMIT_MAX);
    }

    resolver->total_time += t;
    resolver->timer = eloop_timer_new(t,
            wsdd_resolver_timer_callback, resolver);
}

/* Send probe
 */
static void
wsdd_resolver_send_probe (wsdd_resolver *resolver)
{
    uuid            u = uuid_rand();
    int             n = sprintf(wsdd_buf, wsdd_probe_template, u.text);
    int             rc;
    struct sockaddr *addr;
    socklen_t       addrlen;
    ip_straddr      straddr;

    if (resolver->ipv6) {
        addr = (struct sockaddr*) &wsdd_mcast_ipv6;
        addrlen = sizeof(wsdd_mcast_ipv6);
    } else {
        addr = (struct sockaddr*) &wsdd_mcast_ipv4;
        addrlen = sizeof(wsdd_mcast_ipv4);
    }

    straddr = ip_straddr_from_sockaddr(addr);
    log_trace(wsdd_log, "probe sent: %s->%s",
        resolver->str_sockaddr.text, straddr.text);
    log_trace_data(wsdd_log, "application/xml", wsdd_buf, n);

    rc = sendto(resolver->fd, wsdd_buf, n, 0, addr, addrlen);

    if (rc < 0) {
        log_debug(wsdd_log, "send_probe: %s", strerror(errno));
    }

    wsdd_resolver_timer_set(resolver);
}

/* Create wsdd_resolver
 */
static wsdd_resolver*
wsdd_resolver_new (const netif_addr *addr, bool initscan)
{
    wsdd_resolver *resolver = g_new0(wsdd_resolver, 1);
    int           af = addr->ipv6 ? AF_INET6 : AF_INET;
    const char    *af_name = addr->ipv6 ? "AF_INET6" : "AF_INET";
    int           rc;
    static int    no = 0, yes = 1;

    /* Build resolver structure */
    resolver->ifindex = addr->ifindex;

    /* Open a socket */
    resolver->ipv6 = addr->ipv6;
    resolver->fd = socket(af, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (resolver->fd < 0) {
        log_debug(wsdd_log, "socket(%s): %s", af_name, strerror(errno));
        goto FAIL;
    }

    /* Set socket options */
    if (addr->ipv6) {
        rc = setsockopt(resolver->fd, IPPROTO_IPV6, IPV6_MULTICAST_IF,
                &addr->ifindex, sizeof(addr->ifindex));

        if (rc < 0) {
            log_debug(wsdd_log, "setsockopt(AF_INET6,IPV6_MULTICAST_IF): %s",
                strerror(errno));
            goto FAIL;
        }

        rc = setsockopt(resolver->fd, IPPROTO_IPV6, IPV6_RECVPKTINFO,
                &yes, sizeof(yes));

        if (rc < 0) {
            log_debug(wsdd_log, "setsockopt(IPPROTO_IPV6,IPV6_RECVPKTINFO): %s",
                    strerror(errno));
            goto FAIL;
        }

        /* Note: error is not a problem here */
        setsockopt(resolver->fd, IPPROTO_IPV6, IPV6_MULTICAST_LOOP,
                &no, sizeof(no));
    } else {
        rc = setsockopt(resolver->fd, IPPROTO_IP, IP_MULTICAST_IF,
                &addr->ip.v4, sizeof(&addr->ip.v4));

        if (rc < 0) {
            log_debug(wsdd_log, "setsockopt(AF_INET,IP_MULTICAST_IF): %s",
                    strerror(errno));
            goto FAIL;
        }

        rc = setsockopt(resolver->fd, IPPROTO_IP, IP_PKTINFO,
                &yes, sizeof(yes));

        if (rc < 0) {
            log_debug(wsdd_log, "setsockopt(AF_INET,IP_PKTINFO): %s",
                    strerror(errno));
            goto FAIL;
        }

        /* Note: error is not a problem here */
        setsockopt(resolver->fd, IPPROTO_IP, IP_MULTICAST_LOOP,
                &no, sizeof(no));
    }

    /* Bind the socket */
    if (addr->ipv6) {
        struct sockaddr_in6 a;
        a.sin6_family = AF_INET6;
        a.sin6_addr = addr->ip.v6;
        a.sin6_scope_id = addr->ifindex;
        resolver->str_ifaddr = ip_straddr_from_ip(AF_INET6, &addr->ip);
        resolver->str_sockaddr = ip_straddr_from_sockaddr((struct sockaddr*) &a);
        rc = bind(resolver->fd, (struct sockaddr*) &a, sizeof(a));
    } else {
        struct sockaddr_in a;
        a.sin_family = AF_INET;
        a.sin_addr = addr->ip.v4;
        resolver->str_ifaddr = ip_straddr_from_ip(AF_INET, &addr->ip);
        resolver->str_sockaddr = ip_straddr_from_sockaddr((struct sockaddr*) &a);
        rc = bind(resolver->fd, (struct sockaddr*) &a, sizeof(a));
    }

    log_debug(wsdd_log, "%s: started discovery", resolver->str_ifaddr.text);

    if (rc < 0) {
        log_debug(wsdd_log, "bind(%s): %s", resolver->str_sockaddr.text,
                strerror(errno));
        goto FAIL;
    }

    /* Setup fdpoll */
    resolver->fdpoll = eloop_fdpoll_new(resolver->fd,
        wsdd_resolver_read_callback, NULL);
    eloop_fdpoll_set_mask(resolver->fdpoll, ELOOP_FDPOLL_READ);

    wsdd_resolver_send_probe(resolver);

    /* Update wsdd_initscan_count */
    resolver->initscan = initscan;
    if (resolver->initscan) {
        wsdd_initscan_count_inc();
    }

    return resolver;

    /* Error: cleanup and exit */
FAIL:
    if (resolver->fd >= 0) {
        close(resolver->fd);
        resolver->fd = -1;
    }
    return resolver;
}

/* Destroy wsdd_resolver
 */
static void
wsdd_resolver_free (wsdd_resolver *resolver)
{
    if (resolver->initscan) {
        wsdd_initscan_count_dec();
    }

    if (resolver->fdpoll != NULL) {
        eloop_fdpoll_free(resolver->fdpoll);
        close(resolver->fd);
    }

    if (resolver->timer != NULL) {
        eloop_timer_cancel(resolver->timer);
    }

    g_free(resolver);
}

/******************** Management of multicast sockets ********************/
/* Open IPv4 or IPv6 multicast socket
 */
static int
wsdd_mcsock_open (bool ipv6)
{
    int        af = ipv6 ? AF_INET6 : AF_INET;
    int        fd, rc;
    const char *af_name = ipv6 ? "AF_INET6" : "AF_INET";
    static int yes = 1;
    ip_straddr straddr;

    /* Open a socket */
    fd = socket(af, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (fd < 0) {
        log_debug(wsdd_log, "socket(%s): %s", af_name, strerror(errno));
        return fd;
    }

    /* Set socket options */
    rc = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    if (rc < 0) {
        log_debug(wsdd_log, "setsockopt(%s, SO_REUSEADDR): %s",
                af_name, strerror(errno));
        goto FAIL;
    }

    if (ipv6) {
        rc = setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &yes, sizeof(yes));
        if (rc < 0) {
            log_debug(wsdd_log, "setsockopt(%s, IPV6_V6ONLY): %s",
                    af_name, strerror(errno));
            goto FAIL;
        }

        rc = setsockopt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &yes, sizeof(yes));
        if (rc < 0) {
            log_debug(wsdd_log, "setsockopt(%s, IPV6_RECVPKTINFO): %s",
                    af_name, strerror(errno));
            goto FAIL;
        }
    } else {
        rc = setsockopt(fd, IPPROTO_IP, IP_PKTINFO, &yes, sizeof(yes));
        if (rc < 0) {
            log_debug(wsdd_log, "setsockopt(%s, IP_PKTINFO): %s",
                    af_name, strerror(errno));
            goto FAIL;
        }
    }

    /* Bind socket to WSDD multicast port; group membership
     * will be added later on per-interface-address basis
     */
    if (ipv6) {
        struct sockaddr_in6 addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin6_family = AF_INET6;
        addr.sin6_port = wsdd_mcast_ipv6.sin6_port;
        straddr = ip_straddr_from_sockaddr((struct sockaddr*) &addr);
        rc = bind(fd, (struct sockaddr*) &addr, sizeof(addr));
    } else {
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = wsdd_mcast_ipv4.sin_port;
        straddr = ip_straddr_from_sockaddr((struct sockaddr*) &addr);
        rc = bind(fd, (struct sockaddr*) &addr, sizeof(addr));
    }
    if (rc < 0) {
        log_debug(wsdd_log,
                "bind(%s): %s", straddr.text, strerror(errno));
        goto FAIL;
    }

    return fd;

    /* Error: cleanup and exit */
FAIL:
    rc = errno;
    close(fd);
    errno = rc;

    return -1;
}

/* Add or drop multicast group membership, on
 * per-interface-address basis
 */
static void
wsdd_mcast_update_membership (int fd, netif_addr *addr, bool add)
{
    int rc, opt;

    if (addr->ipv6) {
        struct ipv6_mreq mreq6;

        memset(&mreq6, 0, sizeof(mreq6));
	mreq6.ipv6mr_multiaddr = wsdd_mcast_ipv6.sin6_addr;
	mreq6.ipv6mr_interface = addr->ifindex;

        opt = add ? IPV6_ADD_MEMBERSHIP : IPV6_DROP_MEMBERSHIP;
        rc = setsockopt(fd, IPPROTO_IPV6, opt, &mreq6, sizeof(mreq6));

        if (rc < 0) {
            log_debug(wsdd_log, "setsockopt(AF_INET6,%s): %s",
                    add ? "IPV6_ADD_MEMBERSHIP" : "IPV6_DROP_MEMBERSHIP",
                    strerror(errno));
        }
    } else {
        struct ip_mreqn  mreq4;

        memset(&mreq4, 0, sizeof(mreq4));
        mreq4.imr_multiaddr = wsdd_mcast_ipv4.sin_addr;
        mreq4.imr_address = addr->ip.v4;
        mreq4.imr_ifindex = addr->ifindex;

        opt = add ? IP_ADD_MEMBERSHIP : IP_DROP_MEMBERSHIP;
        rc = setsockopt(fd, IPPROTO_IP, opt, &mreq4, sizeof(mreq4));

        if (rc < 0) {
            log_debug(wsdd_log, "setsockopt(AF_INET,%s): %s",
                    add ? "IP_ADD_MEMBERSHIP" : "IP_DROP_MEMBERSHIP",
                    strerror(errno));
        }
    }
}

/******************** Monitoring of network interfaces ********************/
/* Dump list of network interfaces addresses
 */
static void
wsdd_netif_dump_addresses (const char *prefix, netif_addr *list)
{
    char suffix[32] = "";

    while (list != NULL) {
        if (list->ipv6 && ip_is_linklocal(AF_INET6, &list->ip)) {
            sprintf(suffix, "%%%d", list->ifindex);
        }
        log_debug(wsdd_log, "%s%s%s", prefix, list->straddr, suffix);
        list = list->next;
    }
}

/* Lookup wsdd_resolver by interface index
 */
static wsdd_resolver*
wsdd_netif_resolver_by_ifindex (int ifindex)
{
    netif_addr *addr;

    for (addr = wsdd_netif_addr_list; addr != NULL; addr = addr->next) {
        if (addr->ifindex == ifindex) {
            return addr->data;
        }
    }

    return NULL;
}

/* Update network interfaces addresses
 */
static void
wsdd_netif_update_addresses (bool initscan) {
    netif_addr *addr_list = netif_addr_get();
    netif_addr *addr;
    netif_diff diff = netif_diff_compute(wsdd_netif_addr_list, addr_list);

    log_debug(wsdd_log, "netif addresses update:");
    wsdd_netif_dump_addresses(" + ", diff.added);
    wsdd_netif_dump_addresses(" - ", diff.removed);

    netif_addr_free(wsdd_netif_addr_list);
    wsdd_netif_addr_list = addr_list;

    /* Update multicast group membership */
    for (addr = diff.removed; addr != NULL; addr = addr->next) {
        int fd = addr->ipv6 ? wsdd_mcsock_ipv6 : wsdd_mcsock_ipv4;
        wsdd_mcast_update_membership(fd, addr, false);
    }

    for (addr = diff.added; addr != NULL; addr = addr->next) {
        int fd = addr->ipv6 ? wsdd_mcsock_ipv6 : wsdd_mcsock_ipv4;
        wsdd_mcast_update_membership(fd, addr, true);
    }

    /* Start/stop per-interface-address resolvers */
    for (addr = diff.removed; addr != NULL; addr = addr->next) {
        wsdd_resolver_free(addr->data);
    }

    for (addr = wsdd_netif_addr_list; addr != NULL; addr = addr->next) {
        if (addr->data == NULL) {
            addr->data = wsdd_resolver_new(addr, initscan);
        }
    }
}

/* Network interfaces address change notification
 */
static void
wsdd_netif_notifier_callback (void *data)
{
    (void) data;

    log_debug(wsdd_log, "netif event");
    wsdd_netif_update_addresses(false);
}

/******************** Initialization and cleanup ********************/
/* eloop start/stop callback
 */
static void
wsdd_start_stop_callback (bool start)
{
    if (start) {
        /* Setup WSDD multicast reception */
        if (wsdd_mcsock_ipv4 >= 0) {
            wsdd_fdpoll_ipv4 = eloop_fdpoll_new(wsdd_mcsock_ipv4,
                wsdd_resolver_read_callback, NULL);
            eloop_fdpoll_set_mask(wsdd_fdpoll_ipv4, ELOOP_FDPOLL_READ);
        }

        if (wsdd_mcsock_ipv6 >= 0) {
            wsdd_fdpoll_ipv6 = eloop_fdpoll_new(wsdd_mcsock_ipv6,
                wsdd_resolver_read_callback, NULL);
            eloop_fdpoll_set_mask(wsdd_fdpoll_ipv6, ELOOP_FDPOLL_READ);
        }

        /* Update netif addresses */
        wsdd_netif_update_addresses(true);
    } else {
        /* Stop multicast reception */
        if (wsdd_fdpoll_ipv4 != NULL) {
            eloop_fdpoll_free(wsdd_fdpoll_ipv4);
            wsdd_fdpoll_ipv4 = NULL;
        }
        if (wsdd_fdpoll_ipv6 != NULL) {
            eloop_fdpoll_free(wsdd_fdpoll_ipv6);
            wsdd_fdpoll_ipv6 = NULL;
        }

        /* Cleanup resources */
        wsdd_finding_list_purge();
    }
}

/* Initialize WS-Discovery
 */
SANE_Status
wsdd_init (void)
{
    /* Initialize logging */
    wsdd_log = log_ctx_new("WSDD");

    /* Initialize wsdd_finding_list */
    ll_init(&wsdd_finding_list);

    /* All for now, if WS-Discovery is disabled */
    if (!conf.discovery) {
        log_debug(wsdd_log, "devices discovery disabled");
        return SANE_STATUS_GOOD;
    }

    /* Create IPv4/IPv6 multicast addresses */
    wsdd_mcast_ipv4.sin_family = AF_INET;
    inet_pton(AF_INET, "239.255.255.250", &wsdd_mcast_ipv4.sin_addr);
    wsdd_mcast_ipv4.sin_port = htons(3702);

    wsdd_mcast_ipv6.sin6_family = AF_INET6;
    inet_pton(AF_INET6, "ff02::c", &wsdd_mcast_ipv6.sin6_addr);
    wsdd_mcast_ipv6.sin6_port = htons(3702);

    /* Open multicast sockets */
    wsdd_mcsock_ipv4 = wsdd_mcsock_open(false);
    if (wsdd_mcsock_ipv4 < 0) {
        goto FAIL;
    }

    wsdd_mcsock_ipv6 = wsdd_mcsock_open(true);
    if (wsdd_mcsock_ipv6 < 0 && errno != EAFNOSUPPORT) {
        goto FAIL;
    }

    /* Create netif notifier */
    wsdd_netif_notifier = netif_notifier_create(
        wsdd_netif_notifier_callback, NULL);
    if (wsdd_netif_notifier == NULL) {
        goto FAIL;
    }

    /* Register start/stop callback */
    eloop_add_start_stop_callback(wsdd_start_stop_callback);

    return SANE_STATUS_GOOD;

    /* Error: cleanup and exit */
FAIL:
    wsdd_cleanup();
    return SANE_STATUS_IO_ERROR;
}

/* Cleanup WS-Discovery
 */
void
wsdd_cleanup (void)
{
    if (wsdd_netif_notifier != NULL) {
        netif_notifier_free(wsdd_netif_notifier);
        wsdd_netif_notifier = NULL;
    }

    netif_addr_free(wsdd_netif_addr_list);
    wsdd_netif_addr_list = NULL;

    if (wsdd_mcsock_ipv4 >= 0) {
        close(wsdd_mcsock_ipv4);
        wsdd_mcsock_ipv4 = -1;
    }

    if (wsdd_mcsock_ipv6 >= 0) {
        close(wsdd_mcsock_ipv6);
        wsdd_mcsock_ipv6 = -1;
    }

    log_assert(wsdd_log, ll_empty(&wsdd_finding_list));

    if (wsdd_log != NULL) {
        log_ctx_free(wsdd_log);
        wsdd_log = NULL;
    }
}

/* vim:ts=8:sw=4:et
 */
