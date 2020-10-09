/* AirScan (a.k.a. eSCL) backend for SANE
 *
 * Copyright (C) 2019 and up by Alexander Pevzner (pzz@apevzner.com)
 * See LICENSE for license terms and conditions
 *
 * Image filters
 */

#include "airscan.h"

/******************** Identity filter ********************/
/* Type filter_identity represents identity filter
 */
typedef struct {
    filter base;  /* Base class */
    device *dev;  /* Link to device */
} filter_identity;

/* Read method for filter_identity
 */
static SANE_Status
filter_identity_read (filter *f, SANE_Byte *data, SANE_Int max_len,
        SANE_Int *len_out)
{
    filter_identity *filt = (filter_identity*) f;
    return device_read(filt->dev, data, max_len, len_out);
}

/* Create identity filter, that returns image without transformations
 */
static filter*
filter_identity_new (device *dev)
{
    filter_identity *filt = mem_new(filter_identity, 1);

    filt->base.free = (void (*)(filter*)) mem_free;
    filt->base.read = filter_identity_read;
    filt->dev = dev;

    return &filt->base;
}

/******************** Table filter ********************/
/* Type filter_xlat represents translation table based filter
 */
typedef struct {
    filter  base;       /* Base class */
    uint8_t table[256]; /* Transformation table */
} filter_xlat;

/* Read method for filter_xlat
 */
static SANE_Status
filter_xlat_read (filter *f, SANE_Byte *data, SANE_Int max_len,
        SANE_Int *len_out)
{
    SANE_Status  status = f->next->read(f->next, data, max_len, len_out);
    filter_xlat *filt = (filter_xlat*) f;
    int          i, len;

    if (status != SANE_STATUS_GOOD) {
        return status;
    }

    for (i = 0, len = *len_out; i < len; i ++) {
        data[i] = filt->table[data[i]];
    }

    return status;
}

/* filter_xlat
 */
static filter*
filter_xlat_new (const devopt *opt)
{
    filter_xlat *filt;
    int         i;
    double      B = opt->brightness / 2.0;
    double      C = opt->contrast + 1.0;

    if (opt->brightness == 0 &&
        opt->contrast == 0 &&
        !opt->negative) {
        return NULL;
    }

    filt = mem_new(filter_xlat, 1);
    filt->base.free = (void (*)(filter*)) mem_free;
    filt->base.read = filter_xlat_read;

    for (i = 0; i < 256; i ++) {
        double v = i / 255.0;

        v = C * (v - 0.5) + 0.5 + B;
        v = math_bound_double(v, 0.0, 1.0);

        if (opt->negative) {
            v = 1 - v;
        }

        filt->table[i] = round(v * 255.0);
    }

    return &filt->base;
}

/******************** Filter chain management ********************/
/* Create chain of filters
 */
filter*
filter_chain_new (device *dev)
{
    return filter_identity_new(dev);
}

/* Push filter into the chain of filters.
 * Takes ownership on both arguments and returns updated chain
 */
filter*
filter_chain_push (filter *old_chain, filter *new_filter)
{
    new_filter->next = old_chain;
    return new_filter;
}

/* Free chain of filters
 */
void
filter_chain_free (filter *f)
{
    while (f != NULL) {
        filter *next = f->next;
        f->free(f);
        f = next;
    }
}

/* Push translation table based filter, that handles the
 * following options:
 *     - brightness
 *     - contrast
 *     - negative
 *
 * Returns updated chain
 */
filter*
filter_chain_push_xlat (filter *old_chain, const devopt *opt)
{
    filter *f = filter_xlat_new(opt);

    if (f != NULL) {
        f->next = old_chain;
        return f;
    }

    return old_chain;
}

/* vim:ts=8:sw=4:et
 */
