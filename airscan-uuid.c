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

#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>

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

    rand_bytes(rnd, sizeof(rnd));
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
    uint8_t   buf[32];
    int       rc;

    rc = gnutls_hash_fast(GNUTLS_DIG_SHA256, s, strlen(s), buf);
    log_assert(NULL, rc == 0);

    return uuid_format(buf);
}

/* uuidset represents a set of UUIDs
 */
struct uuidset {
    uuid *uuids;
};

/* Create new uuidset
 */
uuidset*
uuidset_new (void)
{
    uuidset *set = mem_new(uuidset, 1);
    set->uuids = mem_new(uuid, 0);
    return set;
}

/* Free uuidset
 */
void
uuidset_free (uuidset *set)
{
    mem_free(set->uuids);
    mem_free(set);
}

/* Find uuid index within the set. Returns -1, if uuid was not found
 */
static int
uuidset_index (const uuidset *set, uuid uuid)
{
    size_t i, len = mem_len(set->uuids);
    for (i = 0; i < len; i ++) {
        if (uuid_equal(uuid, set->uuids[i])) {
            return (int) i;
        }
    }

    return -1;
}

/* Add uuid to uuidset
 */
void
uuidset_add (uuidset *set, uuid uuid)
{
    if (uuidset_index(set, uuid) < 0) {
        size_t len = mem_len(set->uuids);
        set->uuids = mem_resize(set->uuids, len + 1, 0);
        set->uuids[len] = uuid;
    }

}

/* Del uuid from uuidset
 */
void
uuidset_del (uuidset *set, uuid uuid)
{
    int i = uuidset_index(set, uuid);
    if (i >= 0) {
        size_t len = mem_len(set->uuids);
        size_t tail = len - (size_t) i - 1;
        if (tail != 0) {
            tail *= sizeof(*set->uuids);
            memmove(&set->uuids[i], &set->uuids[i + 1], tail);
        }
        mem_shrink(set->uuids, len - 1);
    }
}

/* Check if uuid is in the uuidset
 */
bool
uuidset_lookup (const uuidset *set, uuid uuid)
{
    return uuidset_index(set, uuid) >= 0;
}

/* Delete all addresses from the set
 */
void
uuidset_purge (uuidset *set)
{
    mem_shrink(set->uuids, 0);
}

/* Merge two sets:
 *   set += set2
 */
void
uuidset_merge (uuidset *set, const uuidset *set2)
{
    size_t i, len = mem_len(set2->uuids);

    for (i = 0; i < len; i ++) {
        uuidset_add(set, set2->uuids[i]);
    }
}

/* Check if two address sets are intersecting
 */
bool
uuidset_is_intersect (const uuidset *set, const uuidset *set2)
{
    size_t i, len = mem_len(set2->uuids);

    for (i = 0; i < len; i ++) {
        if (uuidset_lookup(set2, set->uuids[i])) {
            return true;
        }
    }

    return false;
}

/* vim:ts=8:sw=4:et
 */
