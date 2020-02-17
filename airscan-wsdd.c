/* AirScan (a.k.a. eSCL) backend for SANE
 *
 * Copyright (C) 2019 and up by Alexander Pevzner (pzz@apevzner.com)
 * See LICENSE for license terms and conditions
 *
 * Web Services Dynamic Discovery (WS-Discovery)
 */

#include "airscan.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>

/* Protocol times, in milliseconds
 */
#define WSDD_RETRANSMIT_MIN     100     /* Min retransmit time */
#define WSDD_RETRANSMIT_MAX     250     /* Max retransmit time */
#define WSDD_DISCOVERY_TIME     2500    /* Overall discovery time */

/* wsdd_resolver represents a per-interface WSDD resolver
 */
typedef struct {
    char         ifname[NETIF_NAMESIZE]; /* Interface name */
    int          fd;                     /* File descriptor */
    bool         ipv6;                   /* We are on IPv6 */
    eloop_fdpoll *fdpoll;                /* Socket fdpoll */
    eloop_timer  *timer;                 /* Retransmit timer */
    uint32_t     total_time;             /* Total elapsed time */
} wsdd_resolver;

/* Static variables
 */
static netif_notifier      *wsdd_netif_notifier;
static netif_addr          *wsdd_netif_addr_list;
static int                 wsdd_mcsock_ipv4 = -1;
static int                 wsdd_mcsock_ipv6 = -1;
static eloop_fdpoll        *wsdd_fdpoll_ipv4;
static eloop_fdpoll        *wsdd_fdpoll_ipv6;
static char                wsdd_buf[65536];
static struct sockaddr_in  wsdd_mcast_ipv4;
static struct sockaddr_in6 wsdd_mcast_ipv6;

/* XML templates
 */
static const char *wsdd_probe =
        "<?xml version=\"1.0\" ?>\n"
        "<s:Envelope xmlns:a=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\" xmlns:d=\"http://schemas.xmlsoap.org/ws/2005/04/discovery\" xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\">\n"
        "	<s:Header>\n"
        "		<a:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</a:Action>\n"
        "		<a:MessageID>urn:uuid:%s</a:MessageID>\n"
        "		<a:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</a:To>\n"
        "	</s:Header>\n"
        "	<s:Body>\n"
        "		<d:Probe/>\n"
        "	</s:Body>\n"
        "</s:Envelope>\n";

/* Forward declarations */
static void
wsdd_resolver_send_probe (wsdd_resolver *resolver);

/* Resolver read callback
 */
static void
wsdd_resolver_read_callback (int fd, void *data, ELOOP_FDPOLL_MASK mask)
{
    struct sockaddr_storage addr;
    socklen_t               addrlen = sizeof(addr);
    ip_straddr              straddr;
    int                     rc;

    (void) data;
    (void) mask;

    rc = recvfrom(fd, wsdd_buf, sizeof(wsdd_buf), 0,
        (struct sockaddr*) &addr, &addrlen);
    if (rc <= 0) {
        return;
    }

    straddr = ip_straddr_from_sockaddr((struct sockaddr*) &addr);
    log_debug(NULL, "%d bytes received from %s", rc, straddr.text);

    //write(1, wsdd_buf, rc);
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
        log_debug(NULL, "WSSD: %s: done discovery", resolver->ifname);
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

    log_assert(NULL, resolver->timer == NULL);

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
    uuid            u = uuid_new();
    int             n = sprintf(wsdd_buf, wsdd_probe, u.text);
    int             rc;
    struct sockaddr *addr;
    socklen_t       addrlen;

    log_debug(NULL, "WSSD: %s: probe sent", resolver->ifname);

    if (resolver->ipv6) {
        addr = (struct sockaddr*) &wsdd_mcast_ipv6;
        addrlen = sizeof(wsdd_mcast_ipv6);
    } else {
        addr = (struct sockaddr*) &wsdd_mcast_ipv4;
        addrlen = sizeof(wsdd_mcast_ipv4);
    }

    rc = sendto(resolver->fd, wsdd_buf, n, 0, addr, addrlen);

    if (rc < 0) {
        log_debug(NULL, "WSDD: send_probe: %s", strerror(errno));
    }

    wsdd_resolver_timer_set(resolver);
}

/* Create wsdd_resolver
 */
static wsdd_resolver*
wsdd_resolver_new (const netif_addr *addr)
{
    wsdd_resolver *resolver = g_new0(wsdd_resolver, 1);
    int           af = addr->ipv6 ? AF_INET6 : AF_INET;
    const char    *af_name = addr->ipv6 ? "AF_INET6" : "AF_INET";
    int           rc;

    /* Open a socket */
    memcpy(resolver->ifname, addr->ifname, NETIF_NAMESIZE);
    resolver->ipv6 = addr->ipv6;
    resolver->fd = socket(af, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (resolver->fd < 0) {
        log_debug(NULL, "WSDD: socket(%s): %s", af_name, strerror(errno));
        goto FAIL;
    }

    /* Set socket options */
    if (addr->ipv6) {
        rc = setsockopt(resolver->fd, IPPROTO_IPV6, IPV6_MULTICAST_IF,
                &addr->ifindex, sizeof(addr->ifindex));

        if (rc < 0) {
            log_debug(NULL, "WSDD: setsockopt(AF_INET6,IPV6_MULTICAST_IF): %s",
                    strerror(errno));
        }
    } else {
        rc = setsockopt(resolver->fd, IPPROTO_IP, IP_MULTICAST_IF,
                &addr->ip.v4, sizeof(&addr->ip.v4));

        if (rc < 0) {
            log_debug(NULL, "WSDD: setsockopt(AF_INET,IP_MULTICAST_IF): %s",
                    strerror(errno));
        }
    }

    /* Setup fdpoll */
    resolver->fdpoll = eloop_fdpoll_new(resolver->fd,
        wsdd_resolver_read_callback, NULL);
    eloop_fdpoll_set_mask(resolver->fdpoll, ELOOP_FDPOLL_READ);

    wsdd_resolver_send_probe(resolver);

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
    if (resolver->fdpoll != NULL) {
        eloop_fdpoll_free(resolver->fdpoll);
        close(resolver->fd);
    }

    if (resolver->timer != NULL) {
        eloop_timer_cancel(resolver->timer);
    }

    g_free(resolver);
}

/* Read callback for multicast socket
 */
static void
wsdd_mcsock_callback (int fd, void *data, ELOOP_FDPOLL_MASK mask)
{
    int rc;

    (void) data;
    (void) mask;

    rc = read(fd, wsdd_buf, sizeof(wsdd_buf));
    if (rc <= 0) {
        return;
    }
}

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
        log_debug(NULL, "WSDD: socket(%s): %s", af_name, strerror(errno));
        return fd;
    }

    /* Set socket options */
    rc = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    if (rc < 0) {
        log_debug(NULL, "WSDD: setsockopt(%s, SO_REUSEADDR): %s",
                af_name, strerror(errno));
        goto FAIL;
    }

    if (ipv6) {
        rc = setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &yes, sizeof(yes));
        if (rc < 0) {
            log_debug(NULL, "WSDD: setsockopt(%s, IPV6_V6ONLY): %s",
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
        log_debug(NULL, "WSDD: bind(%s): %s", straddr.text, strerror(errno));
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

/* Dump list of network interfaces addresses
 */
static void
wsdd_netif_dump_addresses (const char *prefix, netif_addr *list)
{
    char suffix[32] = "";

    while (list != NULL) {
        if (list->ipv6 && list->linklocal) {
            sprintf(suffix, "%%%d", list->ifindex);
        }
        log_debug(NULL, "%s%s%s", prefix, list->straddr, suffix);
        list = list->next;
    }
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
            log_debug(NULL, "WSDD: setsockopt(AF_INET6,%s): %s",
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
            log_debug(NULL, "WSDD: setsockopt(AF_INET,%s): %s",
                    add ? "IP_ADD_MEMBERSHIP" : "IP_DROP_MEMBERSHIP",
                    strerror(errno));
        }
    }
}

/* Update network interfaces addresses
 */
static void
wsdd_netif_update_addresses (void) {
    netif_addr *addr_list = netif_addr_get();
    netif_addr *addr;
    netif_diff diff = netif_diff_compute(wsdd_netif_addr_list, addr_list);

    log_debug(NULL, "WSDD: netif addresses update:");
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
            addr->data = wsdd_resolver_new(addr);
        }
    }
}

/* Network interfaces address change notification
 */
static void
wsdd_netif_notifier_callback (void *data)
{
    (void) data;

    log_debug(NULL, "WSDD: netif event");
    wsdd_netif_update_addresses();
}

/* eloop start/stop callback
 */
static void
wsdd_start_stop_callback (bool start)
{
    if (start) {
        /* Setup WSDD multicast reception */
        if (wsdd_mcsock_ipv4 >= 0) {
            wsdd_fdpoll_ipv4 = eloop_fdpoll_new(wsdd_mcsock_ipv4,
                wsdd_mcsock_callback, NULL);
            eloop_fdpoll_set_mask(wsdd_fdpoll_ipv4, ELOOP_FDPOLL_READ);
        }

        if (wsdd_mcsock_ipv6 >= 0) {
            wsdd_fdpoll_ipv6 = eloop_fdpoll_new(wsdd_mcsock_ipv6,
                wsdd_mcsock_callback, NULL);
            eloop_fdpoll_set_mask(wsdd_fdpoll_ipv6, ELOOP_FDPOLL_READ);
        }

        /* Update netif addresses */
        wsdd_netif_update_addresses();
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
    }
}

/* Initialize WS-Discovery
 */
SANE_Status
wsdd_init (void)
{
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

    if (wsdd_mcsock_ipv4 >= 0) {
        close(wsdd_mcsock_ipv4);
        wsdd_mcsock_ipv4 = -1;
    }

    if (wsdd_mcsock_ipv6 >= 0) {
        close(wsdd_mcsock_ipv6);
        wsdd_mcsock_ipv6 = -1;
    }
}

/* vim:ts=8:sw=4:et
 */
