/* AirScan (a.k.a. eSCL) backend for SANE
 *
 * Copyright (C) 2019 and up by Alexander Pevzner (pzz@apevzner.com)
 * See LICENSE for license terms and conditions
 *
 * Network interfaces addresses
 */

#include "airscan.h"

#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <sys/socket.h>

/* Forward declarations */
static netif_addr*
netif_addr_list_sort (netif_addr *list);

/* Get list of network interfaces addresses
 */
netif_addr*
netif_addr_get (void)
{
    struct ifaddrs *ifa, *ifp;
    netif_addr     *list = NULL, *addr;

    if (getifaddrs(&ifa) < 0) {
        return NULL;
    }

    for (ifp = ifa; ifp != NULL; ifp = ifp->ifa_next) {
        /* Skip loopback interface */
        if ((ifp->ifa_flags & IFF_LOOPBACK) != 0) {
            continue;
        }

        /* Obtain interface index. Skip address, if it failed */
        int idx = if_nametoindex(ifp->ifa_name);
        if (idx <= 0) {
            continue;
        }

        /* Translate struct ifaddrs to netif_addr */
        addr = g_new0(netif_addr, 1);
        addr->next = list;
        addr->ifindex = idx;
        strncpy(addr->ifname.text, ifp->ifa_name,
            sizeof(addr->ifname.text) - 1);

        switch (ifp->ifa_addr->sa_family) {
        case AF_INET:
            addr->ip.v4 = ((struct sockaddr_in*) ifp->ifa_addr)->sin_addr;
            addr->linklocal = ip_is_linklocal(AF_INET, &addr->ip);
            inet_ntop(AF_INET, &addr->ip.v4,
                addr->straddr, sizeof(addr->straddr));
            break;

        case AF_INET6:
            addr->ipv6 = true;
            addr->ip.v6 = ((struct sockaddr_in6*) ifp->ifa_addr)->sin6_addr;
            addr->linklocal = ip_is_linklocal(AF_INET6, &addr->ip);
            inet_ntop(AF_INET6, &addr->ip.v6,
                addr->straddr, sizeof(addr->straddr));
            break;

        default:
            /* Paranoia; should not actually happen */
            g_free(addr);
            addr = NULL;
            break;
        }

        if (addr != NULL) {
            addr->next = list;
            list = addr;
        }
    }

    freeifaddrs(ifa);
    return netif_addr_list_sort(list);
}

/* Clone a single netif_addr
 */
static netif_addr*
netif_addr_clone_single (const netif_addr *addr)
{
    netif_addr *addr2 = g_new0(netif_addr, 1);
    *addr2 = *addr;
    addr2->next = NULL;
    return addr2;
}

/* Free a single netif_addr
 */
static void
netif_addr_free_single (netif_addr *addr)
{
    g_free(addr);
}

/* Free list of network interfaces addresses
 */
void
netif_addr_free (netif_addr *list)
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
    /* Compare interface indices */
    if (a1->ifindex != a2->ifindex) {
        return a1->ifindex - a2->ifindex;
    }

    /* Prefer normal addresses, rather that link-local */
    if (a1->linklocal != a2->linklocal) {
        return (int) a1->linklocal - (int) a2->linklocal;
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

    if (list->next == NULL) {
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

/* Compute a difference between two lists of
 * addresses.
 */
netif_diff
netif_diff_compute (netif_addr *list1, netif_addr *list2)
{
    netif_diff diff = {NULL, NULL};

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
            addr = netif_addr_clone_single(list1);
            list1 = list1->next;
            addr->next = diff.removed;
            diff.removed = addr;
        } else if (cmp > 0) {
            addr = netif_addr_clone_single(list2);
            list2 = list2->next;
            addr->next = diff.added;
            diff.added = addr;
        } else {
            list1 = list1->next;
            list2 = list2->next;
        }
    }

    diff.added = netif_addr_list_revert(diff.added);
    diff.removed = netif_addr_list_revert(diff.removed);

    return diff;
}

/* Network interfaces addresses change notifier
 */
struct netif_notifier {
    int          rtnetlink;          /* rtnetlink socket */
    eloop_fdpoll *fdpoll;            /* fdpoll for rtnetlink */
    void         (*callback)(void*); /* Notification callback */
    void         *data;              /* Callback data */
    uint8_t      buf[16384];         /* Input buffer */
};

/* netif_notifier read callback
 */
static void
netif_notifier_read_callback (int fd, void *data, ELOOP_FDPOLL_MASK mask)
{
    netif_notifier   *notifier = (netif_notifier*) data;
    int              rc = read(fd, notifier->buf, sizeof(notifier->buf));
    struct nlmsghdr *p;
    size_t           sz;

    (void) mask;

    /* Parse rtnetlink message */
    if (rc < 0) {
        return;
    }

    sz = (size_t) rc;
    for (p = (struct nlmsghdr*) notifier->buf;
        sz >= sizeof(struct nlmsghdr); p = NLMSG_NEXT(p, sz)) {

        if (!NLMSG_OK(p, sz) || sz < p->nlmsg_len) {
            return;
        }

        switch (p->nlmsg_type) {
        case NLMSG_DONE:
            return;

        case RTM_NEWADDR:
        case RTM_DELADDR:
            notifier->callback(notifier->data);
            return;
        }
    }
}

/* Create netif_notifier
 */
netif_notifier*
netif_notifier_create (void (*callback) (void*), void *data)
{
    int                rtnetlink, rc;
    struct sockaddr_nl addr;
    netif_notifier     *notifier;

    /* Open rtnetlink socket */
    rtnetlink = socket(AF_NETLINK,
        SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK, NETLINK_ROUTE);

    if (rtnetlink < 0) {
        return NULL;
    }

    /* Subscribe to notifications */
    memset(&addr, 0, sizeof(addr));
    addr.nl_family = AF_NETLINK;
    addr.nl_groups = RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR;

    rc = bind(rtnetlink, (struct sockaddr*) &addr, sizeof(addr));
    if (rc < 0) {
        close(rtnetlink);
        return NULL;
    }

    /* Create netif_notifier structure */
    notifier = g_new0(netif_notifier, 1);
    notifier->rtnetlink = rtnetlink;
    notifier->callback = callback;
    notifier->data = data;

    /* Register in event loop */
    notifier->fdpoll = eloop_fdpoll_new(rtnetlink,
        netif_notifier_read_callback, notifier);
    eloop_fdpoll_set_mask(notifier->fdpoll, ELOOP_FDPOLL_READ);

    return notifier;
}

/* Destroy netif_notifier
 */
void
netif_notifier_free (netif_notifier *notifier)
{
    eloop_fdpoll_free(notifier->fdpoll);
    close(notifier->rtnetlink);
    g_free(notifier);
}

/* vim:ts=8:sw=4:et
 */
