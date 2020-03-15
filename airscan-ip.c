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

    sprintf(straddr.text + strlen(straddr.text), ":%d", ntohs(port));

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

/* vim:ts=8:sw=4:et
 */
