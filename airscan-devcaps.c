/* AirScan (a.k.a. eSCL) backend for SANE
 *
 * Copyright (C) 2019 and up by Alexander Pevzner (pzz@apevzner.com)
 * See LICENSE for license terms and conditions
 *
 * Device capabilities
 */

#include "airscan.h"

#include <string.h>

/* Allocate devcaps_source
 */
devcaps_source*
devcaps_source_new (void)
{
    devcaps_source *src = g_new0(devcaps_source, 1);
    sane_string_array_init(&src->sane_colormodes);
    sane_word_array_init(&src->resolutions);
    return src;
}

/* Free devcaps_source
 */
void
devcaps_source_free (devcaps_source *src)
{
    if (src != NULL) {
        sane_string_array_cleanup(&src->sane_colormodes);
        sane_word_array_cleanup(&src->resolutions);
        g_free(src);
    }
}

/* Merge two sources, resulting the source that contains
 * only capabilities, supported by two input sources
 *
 * Returns NULL, if sources cannot be merged
 */
devcaps_source*
devcaps_source_merge (const devcaps_source *s1, const devcaps_source *s2)
{
    devcaps_source *src = devcaps_source_new();

    /* Merge flags */
    src->flags = s1->flags & s2->flags;
    if ((src->flags & DEVCAPS_SOURCE_FMT_ALL) == 0) {
        goto FAIL;
    }

    /* Merge colormodes */
    src->colormodes = s1->colormodes & s2->colormodes;
    if (src->colormodes == 0) {
        goto FAIL;
    }

    opt_colormodes_to_sane(&src->sane_colormodes, src->colormodes);

    /* Merge dimensions */
    src->min_wid_px = math_max(s1->min_wid_px, s2->min_wid_px);
    src->max_wid_px = math_min(s1->max_wid_px, s2->max_wid_px);
    src->min_hei_px = math_max(s1->min_hei_px, s2->min_hei_px);
    src->max_hei_px = math_min(s1->max_hei_px, s2->max_hei_px);

    if ((src->min_wid_px > src->max_wid_px) ||
        (src->min_hei_px > src->max_hei_px)) {
        goto FAIL;
    }

    if (!math_range_merge(&src->win_x_range_mm,
            &s1->win_x_range_mm, &s2->win_x_range_mm)) {
            goto FAIL;
    }

    if (!math_range_merge(&src->win_y_range_mm,
            &s1->win_y_range_mm, &s2->win_y_range_mm)) {
            goto FAIL;
    }

    /* Merge resolutions */
    if ((src->flags & DEVCAPS_SOURCE_RES_DISCRETE) != 0) {
        sane_word_array_intersect_sorted(&src->resolutions,
            s1->resolutions, s2->resolutions);
        if (sane_word_array_len(&src->resolutions) == 0) {
            src->flags &= ~DEVCAPS_SOURCE_RES_DISCRETE;
        }
    }

    if ((src->flags & DEVCAPS_SOURCE_RES_RANGE) != 0) {
        if (!math_range_merge(&src->res_range,
            &s1->res_range, &s2->res_range)) {
            src->flags &= ~DEVCAPS_SOURCE_RES_RANGE;
        }
    }

    if ((src->flags & DEVCAPS_SOURCE_RES_ALL) == 0) {
        goto FAIL;
    }

    return src;

FAIL:
    devcaps_source_free(src);
    return NULL;
}

/* Initialize Device Capabilities
 */
void
devcaps_init (devcaps *caps)
{
    sane_string_array_init(&caps->sane_sources);
}

/* Cleanup Device Capabilities
 */
void
devcaps_cleanup (devcaps *caps)
{
    sane_string_array_cleanup(&caps->sane_sources);
    g_free((void*) caps->vendor);
    g_free((void*) caps->model);

    unsigned int i;
    for (i = 0; i < NUM_OPT_SOURCE; i ++) {
        devcaps_source_free(caps->src[i]);
    }
}

/* Reset Device Capabilities into initial state
 */
void
devcaps_reset (devcaps *caps)
{
    devcaps_cleanup(caps);
    memset(caps, 0, sizeof(*caps));
    devcaps_init(caps);
}

/* Dump device capabilities, for debugging
 */
void
devcaps_dump (trace *t, devcaps *caps)
{
    int     i;
    GString *buf = g_string_new(NULL);

    trace_printf(t, "===== device capabilities =====");
    trace_printf(t, "  Model:      \"%s\"", caps->model);
    trace_printf(t, "  Vendor:     \"%s\"", caps->vendor);
    trace_printf(t, "  Size units: %d DPI", caps->units);
    trace_printf(t, "  Protocol:   %s", caps->protocol);

    g_string_truncate(buf, 0);
    for (i = 0; caps->sane_sources[i] != NULL; i ++) {
        if (i != 0) {
            g_string_append(buf, ", ");
        }
        g_string_append_printf(buf, "%s", caps->sane_sources[i]);
    }

    trace_printf(t, "  Sources:    %s", buf->str);

    OPT_SOURCE opt_src;
    for (opt_src = (OPT_SOURCE) 0; opt_src < NUM_OPT_SOURCE; opt_src ++) {
        devcaps_source *src = caps->src[opt_src];
        char           xbuf[64], ybuf[64];

        if (src == NULL) {
            continue;
        }

        trace_printf(t, "");
        trace_printf(t, "  %s:", opt_source_to_sane(opt_src));

        math_fmt_mm(math_px2mm_res(src->min_wid_px, caps->units), xbuf);
        math_fmt_mm(math_px2mm_res(src->min_hei_px, caps->units), ybuf);

        trace_printf(t, "    Min window:  %dx%d px, %sx%s mm",
                src->min_wid_px, src->min_hei_px, xbuf, ybuf);

        math_fmt_mm(math_px2mm_res(src->max_wid_px, caps->units), xbuf);
        math_fmt_mm(math_px2mm_res(src->max_hei_px, caps->units), ybuf);

        trace_printf(t, "    Max window:  %dx%d px, %sx%s mm",
                src->max_wid_px, src->max_hei_px, xbuf, ybuf);

        if (src->flags & DEVCAPS_SOURCE_RES_DISCRETE) {
            g_string_truncate(buf, 0);
            for (i = 0; i < (int) sane_word_array_len(&src->resolutions); i ++) {
                if (i != 0) {
                    g_string_append_c(buf, ' ');
                }
                g_string_append_printf(buf, "%d", src->resolutions[i+1]);
            }

            trace_printf(t, "    Resolutions: %s", buf->str);
        }

        g_string_truncate(buf, 0);
        for (i = 0; src->sane_colormodes[i] != NULL; i ++) {
            if (i != 0) {
                g_string_append(buf, ", ");
            }
            g_string_append_printf(buf, "%s", src->sane_colormodes[i]);
        }

        trace_printf(t, "    Color modes: %s", buf->str);
    }

    g_string_free(buf, TRUE);
    trace_printf(t, "");
}

/* vim:ts=8:sw=4:et
 */
