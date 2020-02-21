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
    trace_printf(t, "  Model:   \"%s\"", caps->model);
    trace_printf(t, "  Vendor:  \"%s\"", caps->vendor);

    g_string_truncate(buf, 0);
    for (i = 0; caps->sane_sources[i] != NULL; i ++) {
        if (i != 0) {
            g_string_append(buf, ", ");
        }
        g_string_append_printf(buf, "%s", caps->sane_sources[i]);
    }

    trace_printf(t, "  Sources: %s", buf->str);

    OPT_SOURCE opt_src;
    for (opt_src = (OPT_SOURCE) 0; opt_src < NUM_OPT_SOURCE; opt_src ++) {
        devcaps_source *src = caps->src[opt_src];
        char           xbuf[64], ybuf[64];

        if (src == NULL) {
            continue;
        }

        trace_printf(t, "");
        trace_printf(t, "  %s:", opt_source_to_sane(opt_src));

        math_fmt_mm(math_px2mm(src->min_wid_px), xbuf);
        math_fmt_mm(math_px2mm(src->min_hei_px), ybuf);

        trace_printf(t, "    Min window:  %dx%d px, %sx%s mm",
                src->min_wid_px, src->min_hei_px, xbuf, ybuf);

        math_fmt_mm(math_px2mm(src->max_wid_px), xbuf);
        math_fmt_mm(math_px2mm(src->max_hei_px), ybuf);

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
