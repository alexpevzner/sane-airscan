/* AirScan (a.k.a. eSCL) backend for SANE
 *
 * Copyright (C) 2019 and up by Alexander Pevzner (pzz@apevzner.com)
 * See LICENSE for license terms and conditions
 *
 * Utility function for IP addresses
 */

#include "airscan.h"

#include <string.h>
#include <arpa/inet.h>

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

/* Format struct sockaddr. Both AF_INET and AF_INET6 are supported
 */
ip_straddr
ip_straddr_from_sockaddr(const struct sockaddr *addr)
{
     return ip_straddr_from_sockaddr_dport(addr, -1);
}

/* Format ip_straddr from struct sockaddr.
 * Port will not be appended, if it matches provided default port
 * Both AF_INET and AF_INET6 are supported
 */
ip_straddr
ip_straddr_from_sockaddr_dport(const struct sockaddr *addr, int dport)
{
    ip_straddr straddr = {""};
    struct sockaddr_in  *addr_in = (struct sockaddr_in*) addr;
    struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6*) addr;
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
        strcat(straddr.text, "]");
        port = addr_in6->sin6_port;
        break;
    }

    port = htons(port);
    if (port != dport) {
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

/* vim:ts=8:sw=4:et
 */
