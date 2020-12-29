/* AirScan (a.k.a. eSCL) backend for SANE
 *
 * Copyright (C) 2019 and up by Alexander Pevzner (pzz@apevzner.com)
 * See LICENSE for license terms and conditions
 *
 * Network interfaces addresses
 */

#include "airscan.h"

#include <errno.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <ifaddrs.h>
#ifdef OS_HAVE_RTNETLINK
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#endif
#ifdef OS_HAVE_AF_ROUTE
#include <net/route.h>
#endif
#include <net/if.h>
#include <sys/socket.h>

/* Static variables */
static int netif_rtnetlink_sock = -1;
static eloop_fdpoll *netif_rtnetlink_fdpoll;
static ll_head netif_notifier_list;
static struct ifaddrs *netif_ifaddrs;

/* Forward declarations */
static netif_addr*
netif_addr_list_sort (netif_addr *list);

/* Get distance to the target address
 */
NETIF_DISTANCE
netif_distance_get (const struct sockaddr *addr)
{
    struct ifaddrs         *ifa;
    struct in_addr         addr4, ifaddr4, ifmask4;
    struct in6_addr        addr6, ifaddr6, ifmask6;
    static struct in6_addr zero6;
    size_t                 i;
    NETIF_DISTANCE         distance = NETIF_DISTANCE_ROUTED;

    for (ifa = netif_ifaddrs; ifa != NULL; ifa = ifa->ifa_next) {
        /* Skip interface without address or netmask */
        if (ifa->ifa_addr == NULL || ifa->ifa_netmask == NULL) {
            continue;
        }

        /* Compare address family */
        if (addr->sa_family != ifa->ifa_addr->sa_family) {
            continue;
        }

        /* Check direct reachability */
        switch (addr->sa_family) {
        case AF_INET:
            addr4 = ((struct sockaddr_in*) addr)->sin_addr;
            ifaddr4 = ((struct sockaddr_in*) ifa->ifa_addr)->sin_addr;
            ifmask4 = ((struct sockaddr_in*) ifa->ifa_netmask)->sin_addr;

            if (addr4.s_addr == ifaddr4.s_addr) {
                return NETIF_DISTANCE_LOOPBACK;
            }

            if (((addr4.s_addr ^ ifaddr4.s_addr) & ifmask4.s_addr) == 0) {
                distance = NETIF_DISTANCE_DIRECT;
            }
            break;

        case AF_INET6:
            addr6 = ((struct sockaddr_in6*) addr)->sin6_addr;
            ifaddr6 = ((struct sockaddr_in6*) ifa->ifa_addr)->sin6_addr;
            ifmask6 = ((struct sockaddr_in6*) ifa->ifa_netmask)->sin6_addr;

            if (!memcmp(&addr6, &ifaddr6, sizeof(struct in6_addr))) {
                return NETIF_DISTANCE_LOOPBACK;
            }

            for (i = 0; i < sizeof(struct in6_addr); i ++) {
                addr6.s6_addr[i] ^= ifaddr6.s6_addr[i];
                addr6.s6_addr[i] &= ifmask6.s6_addr[i];
            }

            if (!memcmp(&addr6, &zero6, sizeof(struct in6_addr))) {
                distance = NETIF_DISTANCE_DIRECT;
            }
            break;
        }
    }

    return distance;
}

/* Check that interface has non-link-local address
 * of particular address family
 */
bool
netif_has_non_link_local_addr (int af, int ifindex)
{
    struct ifaddrs *ifa;

    for (ifa = netif_ifaddrs; ifa != NULL; ifa = ifa->ifa_next) {
        struct sockaddr *addr;

        /* Skip interface without address */
        if ((addr = ifa->ifa_addr) == NULL) {
            continue;
        }

        /* Check address family against requested */
        if (addr->sa_family != af) {
            continue;
        }

        /* Skip link-local addresses */
        if (ip_sockaddr_is_linklocal(addr)) {
            continue;
        }

        /* Check interface index */
        if (ifindex == (int) if_nametoindex(ifa->ifa_name)) {
            return true;
        }
    }

    return false;
}

/* Get list of network interfaces addresses
 */
netif_addr*
netif_addr_list_get (void)
{
    struct ifaddrs *ifa;
    netif_addr     *list = NULL, *addr;

    for (ifa = netif_ifaddrs; ifa != NULL; ifa = ifa->ifa_next) {
        /* Skip interface without address */
        if (ifa->ifa_addr == NULL) {
            continue;
        }

        /* Skip loopback interface */
        if ((ifa->ifa_flags & IFF_LOOPBACK) != 0) {
            continue;
        }

        /* Obtain interface index. Skip address, if it failed */
        int idx = if_nametoindex(ifa->ifa_name);
        if (idx <= 0) {
            continue;
        }

        /* Translate struct ifaddrs to netif_addr */
        addr = mem_new(netif_addr, 1);
        addr->next = list;
        addr->ifindex = idx;
        strncpy(addr->ifname.text, ifa->ifa_name,
            sizeof(addr->ifname.text) - 1);

        switch (ifa->ifa_addr->sa_family) {
        case AF_INET:
            addr->ip.v4 = ((struct sockaddr_in*) ifa->ifa_addr)->sin_addr;
            inet_ntop(AF_INET, &addr->ip.v4,
                addr->straddr, sizeof(addr->straddr));
            break;

        case AF_INET6:
            addr->ipv6 = true;
            addr->ip.v6 = ((struct sockaddr_in6*) ifa->ifa_addr)->sin6_addr;
            inet_ntop(AF_INET6, &addr->ip.v6,
                addr->straddr, sizeof(addr->straddr));
            break;

        default:
            /* Paranoia; should not actually happen */
            mem_free(addr);
            addr = NULL;
            break;
        }

        if (addr != NULL) {
            addr->next = list;
            list = addr;
        }
    }

    return netif_addr_list_sort(list);
}

/* Free a single netif_addr
 */
static void
netif_addr_free_single (netif_addr *addr)
{
    mem_free(addr);
}

/* Free list of network interfaces addresses
 */
void
netif_addr_list_free (netif_addr *list)
{
    while (list != NULL) {
        netif_addr *next = list->next;
        netif_addr_free_single(list);
        list = next;
    }
}

/* Compare two netif_addr addresses, for sorting
 */
static int
netif_addr_cmp (netif_addr *a1, netif_addr *a2)
{
    bool ll1, ll2;

    /* Compare interface indices */
    if (a1->ifindex != a2->ifindex) {
        return a1->ifindex - a2->ifindex;
    }

    /* Prefer normal addresses, rather that link-local */
    ll1 = ip_is_linklocal(a1->ipv6 ? AF_INET6 : AF_INET, &a1->ip);
    ll2 = ip_is_linklocal(a2->ipv6 ? AF_INET6 : AF_INET, &a2->ip);

    if (ll1 != ll2) {
        return ll1 ? 1 : -1;
    }

    /* Be in trend: prefer IPv6 addresses */
    if (a1->ipv6 != a2->ipv6) {
        return (int) a2->ipv6 - (int) a1->ipv6;
    }

    /* Otherwise, sort lexicographically */
    return strcmp(a1->straddr, a2->straddr);
}

/* Revert netif_addr list
 */
static netif_addr*
netif_addr_list_revert (netif_addr *list)
{
    netif_addr   *prev = NULL, *next;

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
static netif_addr*
netif_addr_list_sort (netif_addr *list)
{
    netif_addr *halves[2] = {NULL, NULL};
    int               half = 0;

    if (list == NULL || list->next == NULL) {
        return list;
    }

    /* Split list into halves */
    while (list != NULL) {
        netif_addr *next = list->next;

        list->next = halves[half];
        halves[half] = list;

        half ^= 1;
        list = next;
    }

    /* Sort each half, recursively */
    for (half = 0; half < 2; half ++) {
        halves[half] = netif_addr_list_sort(halves[half]);
    }

    /* Now merge the sorted halves */
    list = NULL;
    while (halves[0] != NULL || halves[1] != NULL) {
        netif_addr *next;

        if (halves[0] == NULL) {
            half = 1;
        } else if (halves[1] == NULL) {
            half = 0;
        } else if (netif_addr_cmp(halves[0], halves[1]) < 0) {
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
    return netif_addr_list_revert(list);
}

/* Compute a difference between two lists of addresses.
 *
 * It works by tossing nodes between 3 output lists:
 *   * if node is present in list2 only, it is moved
 *     to netif_diff.added
 *   * if node is present in list1 only, it is moved
 *     to netif_diff.removed
 *   * if node is present in both lists, node from
 *     list1 is moved to preserved, and node from
 *     list2 is released
 *
 * It assumes, both lists are sorted, as returned
 * by netif_addr_get(). Returned lists are also sorted
 */
netif_diff
netif_diff_compute (netif_addr *list1, netif_addr *list2)
{
    netif_diff diff = {NULL, NULL, NULL};

    while (list1 != NULL || list2 != NULL) {
        netif_addr *addr;
        int        cmp;

        if (list1 == NULL) {
            cmp = 1;
        } else if (list2 == NULL) {
            cmp = -1;
        } else {
            cmp = netif_addr_cmp(list1, list2);
        }

        if (cmp < 0) {
            addr = list1;
            list1 = list1->next;
            addr->next = diff.removed;
            diff.removed = addr;
        } else if (cmp > 0) {
            addr = list2;
            list2 = list2->next;
            addr->next = diff.added;
            diff.added = addr;
        } else {
            addr = list1;
            list1 = list1->next;
            addr->next = diff.preserved;
            diff.preserved = addr;

            addr = list2;
            list2 = list2->next;
            netif_addr_free_single(addr);
        }
    }

    diff.added = netif_addr_list_revert(diff.added);
    diff.removed = netif_addr_list_revert(diff.removed);
    diff.preserved = netif_addr_list_revert(diff.preserved);

    return diff;
}

/* Merge two lists of addresses
 *
 * Input lists are consumed and new list is created.
 *
 * Input lists are assumed to be sorted, and output
 * list will be sorted as well
 */
netif_addr*
netif_addr_list_merge (netif_addr *list1, netif_addr *list2)
{
    netif_addr *list = NULL;

    while (list1 != NULL || list2 != NULL) {
        netif_addr *addr;
        int        cmp;

        if (list1 == NULL) {
            cmp = 1;
        } else if (list2 == NULL) {
            cmp = -1;
        } else {
            cmp = netif_addr_cmp(list1, list2);
        }

        if (cmp < 0) {
            addr = list1;
            list1 = list1->next;
        } else {
            addr = list2;
            list2 = list2->next;
        }

        addr->next = list;
        list = addr;
    }

    return netif_addr_list_revert(list);
}

/* Network interfaces addresses change notifier
 */
struct netif_notifier {
    void         (*callback)(void*); /* Notification callback */
    void         *data;              /* Callback data */
    ll_node      list_node;          /* in the netif_notifier_list */
};

/* Get a new list of network interfaces and notify the callbacks
 */
static void
netif_refresh_ifaddrs (void)
{
    struct ifaddrs  *new_ifaddrs;
    ll_node         *node;
    int              rc;

    rc = getifaddrs(&new_ifaddrs);
    if (rc >= 0) {
        if (netif_ifaddrs != NULL) {
            freeifaddrs(netif_ifaddrs);
        }

        netif_ifaddrs = new_ifaddrs;
    }

    /* Call all registered callbacks */
    for (LL_FOR_EACH(node, &netif_notifier_list)) {
        netif_notifier *notifier;
        notifier = OUTER_STRUCT(node, netif_notifier, list_node);
        notifier->callback(notifier->data);
    }
}

/* netif_notifier read callback
 */
static void
netif_notifier_read_callback (int fd, void *data, ELOOP_FDPOLL_MASK mask)
{
    static uint8_t  buf[16384];
    int             rc;

    (void) fd;
    (void) data;
    (void) mask;

    /* Get rtnetlink message */
    rc = read(netif_rtnetlink_sock, buf, sizeof(buf));
    if (rc < 0) {
        return;
    }

#if defined(OS_HAVE_RTNETLINK)
    struct nlmsghdr *p;
    size_t          sz;

    /* Parse rtnetlink message, to suppress unneeded (and relatively
     * expensive) netif_refresh_ifaddrs() calls. We are only interested
     * in RTM_NEWADDR/RTM_DELADDR notifications
     */
    sz = (size_t) rc;
    for (p = (struct nlmsghdr*) buf;
        sz >= sizeof(struct nlmsghdr); p = NLMSG_NEXT(p, sz)) {

        if (!NLMSG_OK(p, sz) || sz < p->nlmsg_len) {
            return;
        }

        switch (p->nlmsg_type) {
        case NLMSG_DONE:
            return;

        case RTM_NEWADDR:
        case RTM_DELADDR:
            netif_refresh_ifaddrs();
            return;
        }
    }
#elif defined(OS_HAVE_AF_ROUTE)
    /* Note, on OpenBSD we have ROUTE_MSGFILTER, but FreeBSD lacks
     * this feature, so we have to filter received routing messages
     * manually, to avoid relatively expensive netif_refresh_ifaddrs()
     * calls
     */
    struct rt_msghdr *rtm = (struct rt_msghdr*) buf;
    if (rc >= (int) sizeof(struct rt_msghdr)) {
        switch (rtm->rtm_type) {
        case RTM_NEWADDR:
        case RTM_DELADDR:
            netif_refresh_ifaddrs();
            break;
        }
    }
#endif
}

/* Create netif_notifier
 */
netif_notifier*
netif_notifier_create (void (*callback) (void*), void *data)
{
    netif_notifier *notifier = mem_new(netif_notifier, 1);

    notifier->callback = callback;
    notifier->data = data;

    ll_push_end(&netif_notifier_list, &notifier->list_node);

    return notifier;
}

/* Destroy netif_notifier
 */
void
netif_notifier_free (netif_notifier *notifier)
{
    ll_del(&notifier->list_node);
    mem_free(notifier);
}

/* Start/stop callback
 */
static void
netif_start_stop_callback (bool start)
{
    if (start) {
        netif_rtnetlink_fdpoll = eloop_fdpoll_new(netif_rtnetlink_sock,
            netif_notifier_read_callback, NULL);
        eloop_fdpoll_set_mask(netif_rtnetlink_fdpoll, ELOOP_FDPOLL_READ);
    } else {
        eloop_fdpoll_free(netif_rtnetlink_fdpoll);
        netif_rtnetlink_fdpoll = NULL;
    }
}

/* Initialize network interfaces monitoring
 */
SANE_Status
netif_init (void)
{
    ll_init(&netif_notifier_list);

#if defined(OS_HAVE_RTNETLINK)
    struct sockaddr_nl addr;
    int                rc;

    /* Create AF_NETLINK socket */
    netif_rtnetlink_sock = socket(AF_NETLINK,
        SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK, NETLINK_ROUTE);

    if (netif_rtnetlink_sock < 0) {
        log_debug(NULL, "can't open AF_NETLINK socket: %s", strerror(errno));
        return SANE_STATUS_IO_ERROR;
    }

    /* Subscribe to notifications */
    memset(&addr, 0, sizeof(addr));
    addr.nl_family = AF_NETLINK;
    addr.nl_groups = RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR;

    rc = bind(netif_rtnetlink_sock, (struct sockaddr*) &addr, sizeof(addr));
    if (rc < 0) {
        log_debug(NULL, "can't bind AF_NETLINK socket: %s", strerror(errno));
        close(netif_rtnetlink_sock);
        return SANE_STATUS_IO_ERROR;
    }
#elif defined(OS_HAVE_AF_ROUTE)
    /* Create AF_ROUTE socket */
    netif_rtnetlink_sock = socket(AF_ROUTE,
        SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK, AF_UNSPEC);

    if (netif_rtnetlink_sock < 0) {
        log_debug(NULL, "can't open AF_ROUTE socket: %s", strerror(errno));
        return SANE_STATUS_IO_ERROR;
    }

#ifdef ROUTE_MSGFILTER
    unsigned int rtfilter =
        ROUTE_FILTER(RTM_NEWADDR) | ROUTE_FILTER(RTM_DELADDR);
    if (setsockopt(netif_rtnetlink_sock, AF_ROUTE, ROUTE_MSGFILTER,
                   &rtfilter, sizeof(rtfilter)) < 0) {
        /* Note, this error is not fatal for us, it is enough to
         * log it and continue
         */
        log_debug(NULL, "can't set ROUTE_MSGFILTER: %s", strerror(errno));
    }
#endif
#endif

    /* Initialize netif_ifaddrs */
    if (getifaddrs(&netif_ifaddrs) < 0) {
        log_debug(NULL, "getifaddrs(): %s", strerror(errno));
        close(netif_rtnetlink_sock);
        return SANE_STATUS_IO_ERROR;
    }

    /* Register start/stop callback */
    eloop_add_start_stop_callback(netif_start_stop_callback);

    return SANE_STATUS_GOOD;
}

/* Cleanup network interfaces monitoring
 */
void
netif_cleanup (void)
{
    if (netif_ifaddrs != NULL) {
        freeifaddrs(netif_ifaddrs);
        netif_ifaddrs = NULL;
    }

    if (netif_rtnetlink_sock >= 0) {
        close(netif_rtnetlink_sock);
        netif_rtnetlink_sock = -1;
    }
}

/* vim:ts=8:sw=4:et
 */
