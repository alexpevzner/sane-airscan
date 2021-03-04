/* AirScan (a.k.a. eSCL) backend for SANE
 *
 * Copyright (C) 2019 and up by Alexander Pevzner (pzz@apevzner.com)
 * See LICENSE for license terms and conditions
 *
 * Utility function for IP addresses
 */

#include "airscan.h"

#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/un.h>

#if defined(OS_HAVE_ENDIAN_H)
#   include <endian.h>
#elif defined(OS_HAVE_SYS_ENDIAN_H)
#   include <sys/endian.h>
#endif

/* Format ip_straddr from IP address (struct in_addr or struct in6_addr)
 * af must be AF_INET or AF_INET6
 */
ip_straddr
ip_straddr_from_ip (int af, const void *addr)
{
    ip_straddr straddr = {""};
    inet_ntop(af, addr, straddr.text, sizeof(straddr.text));
    return straddr;
}

/* Format ip_straddr from struct sockaddr.
 * AF_INET, AF_INET6, and AF_UNIX are supported
 *
 * If `withzone' is true, zone suffix will be appended, when appropriate
 */
ip_straddr
ip_straddr_from_sockaddr (const struct sockaddr *addr, bool withzone)
{
     return ip_straddr_from_sockaddr_dport(addr, -1, withzone);
}

/* Format ip_straddr from struct sockaddr.
 * AF_INET, AF_INET6, and AF_UNIX are supported
 *
 * Port will not be appended, if it matches provided default port
 * If `withzone' is true, zone suffix will be appended, when appropriate
 */
ip_straddr
ip_straddr_from_sockaddr_dport (const struct sockaddr *addr,
        int dport, bool withzone)
{
    ip_straddr straddr = {""};
    struct sockaddr_in  *addr_in = (struct sockaddr_in*) addr;
    struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6*) addr;
    struct sockaddr_un  *addr_un = (struct sockaddr_un*) addr;
    uint16_t port = 0;

    switch (addr->sa_family) {
    case AF_INET:
        inet_ntop(AF_INET, &addr_in->sin_addr,
            straddr.text, sizeof(straddr.text));
        port = addr_in->sin_port;
        break;
    case AF_INET6:
        straddr.text[0] = '[';
        inet_ntop(AF_INET6, &addr_in6->sin6_addr,
            straddr.text + 1, sizeof(straddr.text) - 2);
        if (withzone && addr_in6->sin6_scope_id != 0) {
            sprintf(straddr.text + strlen(straddr.text), "%%%d",
                addr_in6->sin6_scope_id);
        }
        strcat(straddr.text, "]");
        port = addr_in6->sin6_port;
        break;
    case AF_UNIX:
        strncpy(straddr.text, addr_un->sun_path, sizeof(straddr.text) - 1);
        straddr.text[sizeof(straddr.text)-1] = '\0';
        break;
    }

    port = htons(port);
    if (port != dport && addr->sa_family != AF_UNIX) {
        sprintf(straddr.text + strlen(straddr.text), ":%d", port);
    }

    return straddr;
}

/* Check if address is link-local
 * af must be AF_INET or AF_INET6
 */
bool
ip_is_linklocal (int af, const void *addr)
{
    if (af == AF_INET) {
        /* 169.254.0.0/16 */
        const uint32_t *a = addr;
        return (ntohl(*a) & 0xffff0000) == 0xa9fe0000;
    } else {
        const uint8_t *a = addr;
        return a[0] == 0xfe && (a[1] & 0xc0) == 0x80;
    }
}

/* Check if sockaddr is link-local
 */
bool
ip_sockaddr_is_linklocal (const struct sockaddr *addr)
{
    struct sockaddr_in  *addr_in = (struct sockaddr_in*) addr;
    struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6*) addr;

    switch (addr->sa_family) {
    case AF_INET:
        return ip_is_linklocal(AF_INET, &addr_in->sin_addr);

    case AF_INET6:
        return ip_is_linklocal(AF_INET6, &addr_in6->sin6_addr);
    }

    return false;
}

/* Check if address is loopback
 * af must be AF_INET or AF_INET6
 */
bool
ip_is_loopback (int af, const void *addr)
{
    if (af == AF_INET) {
        /* 169.254.0.0/16 */
        const uint32_t *a = addr;
        return ntohl(*a) == 0x7f000001;
    } else {
        static const uint8_t loopback[16] = {
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
        };

        return !memcmp(addr, loopback, 16);
    }
}

/* Format ip_addr into ip_straddr
 */
ip_straddr
ip_addr_to_straddr (ip_addr addr, bool withzone)
{
    ip_straddr          straddr = {""};
    struct sockaddr_in  addr_in;
    struct sockaddr_in6 addr_in6;
    struct sockaddr     *sockaddr = NULL;

    switch (addr.af) {
    case AF_INET:
        memset(&addr_in, 0, sizeof(addr_in));
        addr_in.sin_family = AF_INET;
        addr_in.sin_addr = addr.ip.v4;
        sockaddr = (struct sockaddr*) &addr_in;
        break;

    case AF_INET6:
        memset(&addr_in6, 0, sizeof(addr_in6));
        addr_in6.sin6_family = AF_INET6;
        addr_in6.sin6_addr = addr.ip.v6;
        addr_in6.sin6_scope_id = addr.ifindex;
        sockaddr = (struct sockaddr*) &addr_in6;
        break;
    }

    if (sockaddr != NULL) {
        straddr = ip_straddr_from_sockaddr_dport(sockaddr, 0, withzone);
    }

    return straddr;
}

/* Format ip_network into ip_straddr
 */
ip_straddr
ip_network_to_straddr (ip_network net)
{
    ip_straddr straddr = {""};
    size_t len;

    inet_ntop(net.addr.af, &net.addr.ip, straddr.text, sizeof(straddr.text));
    len = strlen(straddr.text);
    sprintf(straddr.text + len, "/%d", net.mask);

    return straddr;
}

/* Check if ip_network contains ip_addr
 */
bool
ip_network_contains (ip_network net, ip_addr addr)
{
    struct in_addr a4, m4;
    uint64_t       a6[2], m6[2];

    if (net.addr.af != addr.af) {
        return false;
    }

    switch (net.addr.af) {
    case AF_INET:
        a4.s_addr = net.addr.ip.v4.s_addr ^ addr.ip.v4.s_addr;
        m4.s_addr = htonl(0xffffffff << (32 - net.mask));
        return (a4.s_addr & m4.s_addr) == 0;

    case AF_INET6:
        /* a6 = net.addr.ip.v6 ^ addr.ip.v6 */
        memcpy(a6, &addr.ip.v6, 16);
        memcpy(m6, &net.addr.ip.v6, 16);
        a6[0] ^= m6[0];
        a6[1] ^= m6[1];

        /* Compute and apply netmask */
        memset(m6, 0, 16);
        if (net.mask <= 64) {
            m6[0] = htobe64(UINT64_MAX << (64 - net.mask));
            m6[1] = 0;
        } else {
            m6[0] = UINT64_MAX;
            m6[1] = htobe64(UINT64_MAX << (128 - net.mask));
        }

        a6[0] &= m6[0];
        a6[1] &= m6[1];

        /* Check result */
        return (a6[0] | a6[1]) == 0;
    }

    return false;
}

/* ip_addr_set represents a set of IP addresses
 */
struct ip_addrset {
    ip_addr *addrs;   /* Addresses in the set */
};

/* Create new ip_addrset
 */
ip_addrset*
ip_addrset_new (void)
{
    ip_addrset *addrset = mem_new(ip_addrset, 1);
    addrset->addrs = mem_new(ip_addr, 0);
    return addrset;
}

/* Free ip_addrset
 */
void
ip_addrset_free (ip_addrset *addrset)
{
    mem_free(addrset->addrs);
    mem_free(addrset);
}

/* Find address index within a set. Returns -1 if address was not found
 */
static int
ip_addrset_index (const ip_addrset *addrset, ip_addr addr)
{
    size_t i, len = mem_len(addrset->addrs);

    for (i = 0; i < len; i ++) {
        if (ip_addr_equal(addrset->addrs[i], addr)) {
            return (int) i;
        }
    }

    return -1;
}

/* Check if address is in set
 */
bool
ip_addrset_lookup (const ip_addrset *addrset, ip_addr addr)
{
    return ip_addrset_index(addrset, addr) >= 0;
}

/* Add address to the set. Returns true, if address was
 * actually added, false if it was already in the set
 */
bool
ip_addrset_add (ip_addrset *addrset, ip_addr addr)
{
    if (ip_addrset_lookup(addrset, addr)) {
        return false;
    }

    ip_addrset_add_unsafe(addrset, addr);
    return true;
}

/* Add address to the set without checking for duplicates
 */
void
ip_addrset_add_unsafe (ip_addrset *addrset, ip_addr addr)
{
    size_t len = mem_len(addrset->addrs);

    addrset->addrs = mem_resize(addrset->addrs, len + 1, 0);
    addrset->addrs[len] = addr;
}

/* Del address from the set.
 */
void
ip_addrset_del (ip_addrset *addrset, ip_addr addr)
{
    int i = ip_addrset_index(addrset, addr);

    if (i >= 0) {
        size_t len = mem_len(addrset->addrs);
        size_t tail = len - (size_t) i - 1;
        if (tail != 0) {
            tail *= sizeof(*addrset->addrs);
            memmove(&addrset->addrs[i], &addrset->addrs[i + 1], tail);
        }
        mem_shrink(addrset->addrs, len - 1);
    }
}

/* Delete all addresses from the set
 */
void
ip_addrset_purge (ip_addrset *addrset)
{
    mem_shrink(addrset->addrs, 0);
}

/* Merge two sets:
 *   addrset += addrset2
 */
void
ip_addrset_merge (ip_addrset *addrset, const ip_addrset *addrset2)
{
    size_t i, len = mem_len(addrset2->addrs);

    for (i = 0; i < len; i ++) {
        ip_addrset_add(addrset, addrset2->addrs[i]);
    }
}

/* Get access to array of addresses in the set
 */
const ip_addr*
ip_addrset_addresses (const ip_addrset *addrset, size_t *count)
{
    *count = mem_len(addrset->addrs);
    return addrset->addrs;
}

/* Check if two address sets are intersecting
 */
bool
ip_addrset_is_intersect (const ip_addrset *set, const ip_addrset *set2)
{
    size_t i, len = mem_len(set->addrs);

    for (i = 0; i < len; i ++) {
        if (ip_addrset_lookup(set2, set->addrs[i])) {
            return true;
        }
    }

    return false;
}

/* Check if some of addresses in the address set is on the
 * given network
 */
bool
ip_addrset_on_network (const ip_addrset *set, ip_network net)
{
    size_t i, len = mem_len(set->addrs);

    for (i = 0; i < len; i ++) {
        if (ip_network_contains(net, set->addrs[i])) {
            return true;
        }
    }

    return false;
}

/* Compare two ip_addrs, for sorting in ip_addrset_friendly_str()
 */
static int
ip_addrset_friendly_sort_cmp (const void *p1, const void *p2)
{
    const ip_addr *a1 = (const ip_addr*) p1;
    const ip_addr *a2 = (const ip_addr*) p2;
    bool          ll1 = ip_is_linklocal(a1->af, &a1->ip);
    bool          ll2 = ip_is_linklocal(a2->af, &a2->ip);
    ip_straddr    s1, s2;

    /* Prefer normal addresses, rather that link-local */
    if (ll1 != ll2) {
        return ll1 ? 1 : -1;
    }

    /* Put IP4 addresses first, they tell more to humans */
    if (a1->af != a2->af) {
        return a1->af == AF_INET6 ? 1 : -1;
    }

    /* Otherwise, sort lexicographically */
    s1 = ip_addr_to_straddr(*a1, true);
    s2 = ip_addr_to_straddr(*a2, true);

    return strcmp(s1.text, s2.text);
}

/* Create user-friendly string out of set of addresses, containing
 * in the ip_addrset:
 *   * addresses are sorted, IP4 addresses goes first
 *   * link-local addresses are skipped, if there are non-link-local ones
 */
char*
ip_addrset_friendly_str (const ip_addrset *set, char *s)
{
    size_t  i, j, len = mem_len(set->addrs);
    ip_addr *addrs = alloca(sizeof(ip_addr) * len);

    /* Gather addresses */
    for (i = j = 0; i < len; i ++) {
        ip_addr *addr = &set->addrs[i];
        if (!ip_is_linklocal(addr->af, &addr->ip)) {
            addrs[j ++] = *addr;
        }
    }

    if (j != 0) {
        len = j;
    } else {
        memcpy(addrs, set->addrs, sizeof(ip_addr) * len);
    }

    /* Sort addresses */
    qsort(addrs, len, sizeof(ip_addr), ip_addrset_friendly_sort_cmp);

    /* And now stringify */
    for (i = 0; i < len; i ++) {
        ip_straddr str = ip_addr_to_straddr(addrs[i], true);

        if (i != 0) {
            s = str_append(s, ", ");
        }

        if (str.text[0] != '[') {
            s = str_append(s, str.text);
        } else {
            str.text[strlen(str.text) - 1] = '\0';
            s = str_append(s, str.text + 1);
        }
    }

    return s;
}

/* vim:ts=8:sw=4:et
 */
