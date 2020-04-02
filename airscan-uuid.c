/* AirScan (a.k.a. eSCL) backend for SANE
 *
 * Copyright (C) 2019 and up by Alexander Pevzner (pzz@apevzner.com)
 * See LICENSE for license terms and conditions
 *
 * UUID utilities
 */

#include "airscan.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <sys/random.h>

#pragma GCC diagnostic ignored "-Wunused-result"

/* Invalid uuid
 */
static uuid uuid_invalid;

/* Format UUID from 16-byte binary representation into
 * the following form:
 *    urn:uuid:ede05377-460e-4b4a-a5c0-423f9e02e8fa
 */
static uuid
uuid_format (uint8_t in[16])
{
    uuid u;

    sprintf(u.text,
        "urn:uuid:"
        "%.2x%.2x%.2x%.2x-%.2x%.2x-%.2x%.2x-%.2x%.2x-%.2x%.2x%.2x%.2x%.2x%.2x",
        in[0], in[1], in[2], in[3], in[4], in[5], in[6], in[7],
        in[8], in[9], in[10], in[11], in[12], in[13], in[14], in[15]);

    return u;
}

/* Generate random UUID. Generated UUID has a following form:
 *    urn:uuid:ede05377-460e-4b4a-a5c0-423f9e02e8fa
 */
uuid
uuid_rand (void)
{
    uint8_t rnd[16];

    getrandom(rnd, sizeof(rnd), 0);
    return uuid_format(rnd);
}

/* Parse UUID. This function ignores all "decorations", like
 * urn:uuid: prefix and so on, and takes only hexadecimal digits
 * into considerations
 *
 * Check the returned uuid with uuid_valid() for possible parse errors
 */
uuid
uuid_parse (const char *in)
{
    uint8_t       buf[16];
    unsigned int  cnt = 0;
    unsigned char c;

    if (!strncasecmp(in, "urn:", 4)) {
        in += 4;
    }

    if (!strncasecmp(in, "uuid:", 5)) {
        in += 5;
    }

    while ((c = *in ++) != '\0') {
        if (isxdigit(c)) {
            unsigned int v;

            if (cnt == 32) {
                return uuid_invalid;
            }

            if (isdigit(c)) {
                v = c - '0';
            } else if (isupper(c)) {
                v = c - 'A' + 10;
            } else {
                v = c - 'a' + 10;
            }

            if ((cnt & 1) == 0) {
                buf[cnt / 2] = v << 4;
            } else {
                buf[cnt / 2] |= v;
            }

            cnt ++;
        }
    }

    if (cnt != 32) {
        return uuid_invalid;
    }

    return uuid_format(buf);
}

/* Generate uuid by cryptographically cacheing input string
 */
uuid
uuid_hash (const char *s)
{
    GChecksum *checksum = g_checksum_new(G_CHECKSUM_SHA256);
    uint8_t   buf[32];
    gsize     len = sizeof(buf);

    log_assert(NULL, checksum != NULL);
    g_checksum_update(checksum, (const void*) s, strlen(s));
    g_checksum_get_digest(checksum, buf, &len);
    g_checksum_free(checksum);

    return uuid_format(buf);
}

/* vim:ts=8:sw=4:et
 */
