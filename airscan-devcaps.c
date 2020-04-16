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
    src->resolutions = sane_word_array_new();
    return src;
}

/* Free devcaps_source
 */
void
devcaps_source_free (devcaps_source *src)
{
    if (src != NULL) {
        sane_word_array_free(src->resolutions);
        g_free(src);
    }
}

/* Clone a source
 */
devcaps_source*
devcaps_source_clone (const devcaps_source *src)
{
    devcaps_source *src2 = g_new0(devcaps_source, 1);
    unsigned int   i, len;

    *src2 = *src;

    src2->resolutions = sane_word_array_new();

    len = sane_word_array_len(src->resolutions);
    for (i = 1; i <= len; i ++) {
        SANE_Word res = src->resolutions[i];
        src2->resolutions = sane_word_array_append(src2->resolutions, res);
    }

    return src2;
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

    /* Merge formats */
    src->formats = s1->formats & s2->formats;
    if ((src->formats & DEVCAPS_FORMATS_SUPPORTED) == 0) {
        goto FAIL;
    }

    /* Merge colormodes */
    src->colormodes = s1->colormodes & s2->colormodes;
    if ((src->colormodes & DEVCAPS_COLORMODES_SUPPORTED) == 0) {
        goto FAIL;
    }

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
        sane_word_array_free(src->resolutions);
        src->resolutions = sane_word_array_intersect_sorted(
                s1->resolutions, s2->resolutions);
        if (sane_word_array_len(src->resolutions) == 0) {
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
    (void) caps;
}

/* Cleanup Device Capabilities
 */
void
devcaps_cleanup (devcaps *caps)
{
    g_free((void*) caps->vendor);
    g_free((void*) caps->model);

    unsigned int i;
    for (i = 0; i < NUM_ID_SOURCE; i ++) {
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
devcaps_dump (log_ctx *log, devcaps *caps)
{
    int          i;
    GString      *buf = g_string_new(NULL);

    log_trace(log, "===== device capabilities =====");
    log_trace(log, "  Model:            \"%s\"", caps->model);
    log_trace(log, "  Vendor:           \"%s\"", caps->vendor);
    log_trace(log, "  Size units:       %d DPI", caps->units);
    log_trace(log, "  Protocol:         %s", caps->protocol);

    if (caps->compression_ok) {
        log_trace(log, "  Compression min:  %d", caps->compression_range.min);
        log_trace(log, "  Compression max:  %d", caps->compression_range.max);
        log_trace(log, "  Compression step: %d", caps->compression_range.quant);
        log_trace(log, "  Compression norm: %d", caps->compression_norm);
    }

    g_string_truncate(buf, 0);
    for (i = 0; i < NUM_ID_SOURCE; i ++) {
        if (caps->src[i] != NULL) {
            if (buf->len != 0) {
                g_string_append(buf, ", ");
            }
            g_string_append(buf, id_source_sane_name(i));
        }
    }

    log_trace(log, "  Sources:          %s", buf->str);

    ID_SOURCE id_src;
    for (id_src = (ID_SOURCE) 0; id_src < NUM_ID_SOURCE; id_src ++) {
        devcaps_source *src = caps->src[id_src];
        char           xbuf[64], ybuf[64];

        if (src == NULL) {
            continue;
        }

        log_trace(log, "");
        log_trace(log, "  %s:", id_source_sane_name(id_src));

        math_fmt_mm(math_px2mm_res(src->min_wid_px, caps->units), xbuf);
        math_fmt_mm(math_px2mm_res(src->min_hei_px, caps->units), ybuf);

        log_trace(log, "    Min window:  %dx%d px, %sx%s mm",
                src->min_wid_px, src->min_hei_px, xbuf, ybuf);

        math_fmt_mm(math_px2mm_res(src->max_wid_px, caps->units), xbuf);
        math_fmt_mm(math_px2mm_res(src->max_hei_px, caps->units), ybuf);

        log_trace(log, "    Max window:  %dx%d px, %sx%s mm",
                src->max_wid_px, src->max_hei_px, xbuf, ybuf);

        if (src->flags & DEVCAPS_SOURCE_RES_DISCRETE) {
            g_string_truncate(buf, 0);
            for (i = 0; i < (int) sane_word_array_len(src->resolutions); i ++) {
                if (i != 0) {
                    g_string_append_c(buf, ' ');
                }
                g_string_append_printf(buf, "%d", src->resolutions[i+1]);
            }

            log_trace(log, "    Resolutions: %s", buf->str);
        }

        g_string_truncate(buf, 0);

        for (i = 0; i < NUM_ID_COLORMODE; i ++) {
            if ((src->colormodes & (1 << i)) != 0) {
                if (buf->len != 0) {
                    g_string_append(buf, ", ");
                }
                g_string_append(buf, id_colormode_sane_name(i));
            }
        }

        log_trace(log, "    Color modes: %s", buf->str);

        g_string_truncate(buf, 0);

        for (i = 0; i < NUM_ID_FORMAT; i ++) {
            if ((src->formats & (1 << i)) != 0) {
                if (buf->len != 0) {
                    g_string_append(buf, ", ");
                }
                g_string_append(buf, id_format_short_name(i));
            }
        }

        log_trace(log, "    Formats:     %s", buf->str);
    }

    g_string_free(buf, TRUE);
    log_trace(log, "");
}

/* vim:ts=8:sw=4:et
 */
