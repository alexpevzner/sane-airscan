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
#include <unistd.h>

#include <arpa/inet.h>

/* wssd_sock represents a per-interface socket
 */
typedef struct {
    int          fd;      /* File descriptor */
    eloop_fdpoll *fdpoll; /* Socket fdpoll */
} wssd_sock;

/* Static variables
 */
static netif_notifier      *wsdd_netif_notifier;
static netif_addr          *wsdd_netif_addr_list;
static int                 wsdd_mcsock_ipv4 = -1;
static int                 wsdd_mcsock_ipv6 = -1;
static eloop_fdpoll        *wsdd_fdpoll_ipv4;
static eloop_fdpoll        *wsdd_fdpoll_ipv6;
static char                wsdd_buf[65546];
static struct sockaddr_in  wsdd_mcast_ipv4;
static struct sockaddr_in6 wsdd_mcast_ipv6;

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
    char buf[128];

    while (list != NULL) {
        inet_ntop(list->ipv6 ? AF_INET6 : AF_INET, &list->ip, buf, sizeof(buf));
        if (list->ipv6 && list->linklocal) {
            char *s = buf + strlen(buf);
            sprintf(s, "%%%d", list->ifindex);
        }
        log_debug(NULL, "%s%s", prefix, buf);
        list = list->next;
    }
}

/* Update network interfaces addresses
 */
static void
wsdd_netif_update_addresses (void) {
    netif_addr *addr_list = netif_addr_get();
    netif_diff diff = netif_diff_compute(wsdd_netif_addr_list, addr_list);

    log_debug(NULL, "WSDD: netif addresses update:");
    wsdd_netif_dump_addresses(" + ", diff.added);
    wsdd_netif_dump_addresses(" - ", diff.removed);

    netif_addr_free(wsdd_netif_addr_list);
    wsdd_netif_addr_list = addr_list;
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
