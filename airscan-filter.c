/* AirScan (a.k.a. eSCL) backend for SANE
 *
 * Copyright (C) 2019 and up by Alexander Pevzner (pzz@apevzner.com)
 * See LICENSE for license terms and conditions
 *
 * Image filters
 */

#include "airscan.h"

/******************** Table filter ********************/
/* Type filter_xlat represents translation table based filter
 */
typedef struct {
    filter  base;       /* Base class */
    uint8_t table[256]; /* Transformation table */
} filter_xlat;

/* Dump filter to the log
 */
static void
filter_xlat_dump (filter *f, log_ctx *log)
{
    filter_xlat *filt = (filter_xlat*) f;
    size_t       i;

    log_debug(log, " XLAT filter:");
    for (i = 0; i < 256; i += 16) {
        uint8_t *row = filt->table + i;
        log_debug(log,
            "   "
            "%.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x "
            "%.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x",
            row[0], row[1], row[2], row[3],
            row[4], row[5], row[6], row[7],
            row[8], row[9], row[10], row[11],
            row[12], row[13], row[14], row[15]);
    }
}

/* Apply filter to the image line
 */
static void
filter_xlat_apply (filter *f, uint8_t *line, size_t size)
{
    filter_xlat *filt = (filter_xlat*) f;
    size_t      i;

    for (i = 0; i < size; i ++) {
        line[i] = filt->table[line[i]];
    }
}

/* filter_xlat
 */
static filter*
filter_xlat_new (const devopt *opt)
{
    filter_xlat *filt;
    int         i;
    double      B = SANE_UNFIX(opt->brightness) / 200.0;
    double      C = SANE_UNFIX(opt->contrast) / 100.0 + 1.0;
    double      G = SANE_UNFIX(opt->gamma);
    uint8_t     shadow = round(2.55 * SANE_UNFIX(opt->shadow));
    uint8_t     highlight = round(2.55 * SANE_UNFIX(opt->highlight));

    if (opt->brightness == SANE_FIX(0.0) &&
        opt->contrast == SANE_FIX(0.0) &&
        opt->shadow == SANE_FIX(0.0) &&
        opt->highlight == SANE_FIX(100.0) &&
        opt->gamma == SANE_FIX(1.0) &&
        !opt->negative) {
        return NULL;
    }

    filt = mem_new(filter_xlat, 1);
    filt->base.free = (void (*)(filter*)) mem_free;
    filt->base.dump = filter_xlat_dump;
    filt->base.apply = filter_xlat_apply;

    for (i = 0; i < 256; i ++) {
        uint8_t c = opt->negative ? (255 - i) : i;
        double  v = c / 255.0;

        v = C * (v - 0.5) + 0.5 + B;
        v = math_bound_double(v, 0.0, 1.0);
        v = pow(v, 1/G);

        c = round(v * 255.0);
        if (c <= shadow) {
            c = 0;
        } else if (c >= highlight) {
            c = 255;
        }

        filt->table[i] = c;
    }

    return &filt->base;
}

/******************** Filter chain management ********************/
/* Push filter into the chain of filters.
 * Takes ownership on both arguments and returns updated chain
 */
static filter*
filter_chain_push (filter *old_chain, filter *new_filter)
{
    if (old_chain == NULL) {
        return new_filter;
    }

    if (new_filter != NULL) {
        /* Nothing to do */
    } else if (old_chain->next == NULL) {
        old_chain->next = new_filter;
    } else {
        old_chain->next = filter_chain_push(old_chain->next, new_filter);
    }

    return old_chain;
}

/* Free chain of filters
 */
void
filter_chain_free (filter *chain)
{
    while (chain != NULL) {
        filter *next = chain->next;
        chain->free(chain);
        chain = next;
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
    return filter_chain_push(old_chain, filter_xlat_new(opt));
}

/* Dump filter chain to the log
 */
void
filter_chain_dump (filter *chain, log_ctx *log)
{
    log_debug(log, "image filter chain:");

    while (chain != NULL) {
        chain->dump(chain, log);
        chain = chain->next;
    }
}

/* Apply filter chain to the image line
 */
void
filter_chain_apply (filter *chain, uint8_t *line, size_t size)
{
    while (chain != NULL) {
        chain->apply(chain, line, size);
        chain = chain->next;
    }
}

/* vim:ts=8:sw=4:et
 */
