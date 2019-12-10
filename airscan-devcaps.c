/* AirScan (a.k.a. eSCL) backend for SANE
 *
 * Copyright (C) 2019 and up by Alexander Pevzner (pzz@apevzner.com)
 * See LICENSE for license terms and conditions
 *
 * Device capabilities
 */

#include "airscan.h"

/* Allocate devcaps_source
 */
static devcaps_source*
devcaps_source_new (void)
{
    devcaps_source *src = g_new0(devcaps_source, 1);
    array_of_string_init(&src->sane_colormodes);
    array_of_word_init(&src->resolutions);
    return src;
}

/* Free devcaps_source
 */
static void
devcaps_source_free (devcaps_source *src)
{
    if (src != NULL) {
        array_of_string_cleanup(&src->sane_colormodes);
        array_of_word_cleanup(&src->resolutions);
        g_free(src);
    }
}

/* Initialize Device Capabilities
 */
void
devcaps_init (devcaps *caps)
{
    array_of_string_init(&caps->sane_sources);
}

/* Cleanup Device Capabilities
 */
void
devcaps_cleanup (devcaps *caps)
{
    array_of_string_cleanup(&caps->sane_sources);
    g_free((void*) caps->vendor);
    g_free((void*) caps->model);

    unsigned int i;
    for (i = 0; i < NUM_OPT_SOURCE; i ++) {
        devcaps_source_free(caps->src[i]);
    }
}

/* Reset Device Capabilities into initial state
 */
static void
devcaps_reset (devcaps *caps)
{
    devcaps_cleanup(caps);
    memset(caps, 0, sizeof(*caps));
    devcaps_init(caps);
}

/* Parse color modes. Returns NULL on success, error string otherwise
 */
static error
devcaps_source_parse_color_modes (xml_rd *xml, devcaps_source *src)
{
    src->colormodes = 0;
    array_of_string_reset(&src->sane_colormodes);

    xml_rd_enter(xml);
    for (; !xml_rd_end(xml); xml_rd_next(xml)) {
        if(xml_rd_node_name_match(xml, "scan:ColorMode")) {
            const char *v = xml_rd_node_value(xml);
            if (!strcmp(v, "BlackAndWhite1")) {
                src->colormodes |= 1 << OPT_COLORMODE_LINEART;
            } else if (!strcmp(v, "Grayscale8")) {
                src->colormodes |= 1 << OPT_COLORMODE_GRAYSCALE;
            } else if (!strcmp(v, "RGB24")) {
                src->colormodes |= 1 << OPT_COLORMODE_COLOR;
            }
        }
    }
    xml_rd_leave(xml);

    /* FIXME
     *
     * The only image format that we currently support is JPEG,
     * and LINEART images are not representable in JPEG, so lets
     * disable it for now (until PDF decoder will be implemented)
     */
    src->colormodes &= ~(1 << OPT_COLORMODE_LINEART);

    OPT_COLORMODE cm;
    for (cm = (OPT_COLORMODE) 0; cm < NUM_OPT_COLORMODE; cm ++) {
        if ((src->colormodes & (1 << cm)) != 0) {
            SANE_String s = (SANE_String) opt_colormode_to_sane(cm);
            array_of_string_append(&src->sane_colormodes, s);
        }
    }

    return NULL;
}

/* Parse document formats. Returns NULL on success, error string otherwise
 */
static error
devcaps_source_parse_document_formats (xml_rd *xml, devcaps_source *src)
{
    xml_rd_enter(xml);
    for (; !xml_rd_end(xml); xml_rd_next(xml)) {
        if(xml_rd_node_name_match(xml, "pwg:DocumentFormat") ||
           xml_rd_node_name_match(xml, "scan:DocumentFormatExt")) {
            const char *v = xml_rd_node_value(xml);
            if (!strcasecmp(v, "image/jpeg")) {
                src->flags |= DEVCAPS_SOURCE_FMT_JPEG;
            } else if (!strcasecmp(v, "image/png")) {
                src->flags |= DEVCAPS_SOURCE_FMT_PNG;
            } else if (!strcasecmp(v, "application/pdf")) {
                src->flags |= DEVCAPS_SOURCE_FMT_PDF;
            }
        }
    }
    xml_rd_leave(xml);

    return NULL;
}

/* Parse discrete resolutions.
 * Returns NULL on success, error string otherwise
 */
static error
devcaps_source_parse_discrete_resolutions (xml_rd *xml, devcaps_source *src)
{
    error err = NULL;

    array_of_word_reset(&src->resolutions);

    xml_rd_enter(xml);
    for (; err == NULL && !xml_rd_end(xml); xml_rd_next(xml)) {
        if (xml_rd_node_name_match(xml, "scan:DiscreteResolution")) {
            SANE_Word x = 0, y = 0;
            xml_rd_enter(xml);
            for (; err == NULL && !xml_rd_end(xml); xml_rd_next(xml)) {
                if (xml_rd_node_name_match(xml, "scan:XResolution")) {
                    err = xml_rd_node_value_uint(xml, &x);
                } else if (xml_rd_node_name_match(xml,
                        "scan:YResolution")) {
                    err = xml_rd_node_value_uint(xml, &y);
                }
            }
            xml_rd_leave(xml);

            if (x && y && x == y) {
                array_of_word_append(&src->resolutions, x);
            }
        }
    }
    xml_rd_leave(xml);

    if (array_of_word_len((&src->resolutions)) > 0) {
        src->flags |= DEVCAPS_SOURCE_RES_DISCRETE;
        array_of_word_sort(&src->resolutions);
    }

    return err;
}

/* Parse resolutions range
 * Returns NULL on success, error string otherwise
 */
static error
devcaps_source_parse_resolutions_range (xml_rd *xml, devcaps_source *src)
{
    error      err = NULL;
    SANE_Range range_x = {0, 0, 0}, range_y = {0, 0, 0};

    xml_rd_enter(xml);
    for (; err == NULL && !xml_rd_end(xml); xml_rd_next(xml)) {
        SANE_Range *range = NULL;
        if (xml_rd_node_name_match(xml, "scan:XResolution")) {
            range = &range_x;
        } else if (xml_rd_node_name_match(xml, "scan:XResolution")) {
            range = &range_y;
        }

        if (range != NULL) {
            xml_rd_enter(xml);
            for (; err == NULL && !xml_rd_end(xml); xml_rd_next(xml)) {
                if (xml_rd_node_name_match(xml, "scan:Min")) {
                    err = xml_rd_node_value_uint(xml, &range->min);
                } else if (xml_rd_node_name_match(xml, "scan:Max")) {
                    err = xml_rd_node_value_uint(xml, &range->max);
                } else if (xml_rd_node_name_match(xml, "scan:Step")) {
                    err = xml_rd_node_value_uint(xml, &range->quant);
                }
            }
            xml_rd_leave(xml);
        }
    }
    xml_rd_leave(xml);

    if (range_x.min > range_x.max) {
        err = ERROR("Invalid scan:XResolution range");
        goto DONE;
    }

    if (range_y.min > range_y.max) {
        err = ERROR("Invalid scan:YResolution range");
        goto DONE;
    }

    /* If no quantization value, SANE uses 0, not 1
     */
    if (range_x.quant == 1) {
        range_x.quant = 0;
    }

    if (range_y.quant == 1) {
        range_y.quant = 0;
    }

    /* Try to merge x/y ranges */
    if (!math_range_merge(&src->res_range, &range_x, &range_y)) {
        err = ERROR("Incompatible scan:XResolution and "
                    "scan:YResolution ranges");
        goto DONE;
    }

    src->flags |= DEVCAPS_SOURCE_RES_RANGE;

DONE:
    return err;
}

/* Parse supported resolutions.
 * Returns NULL on success, error string otherwise
 */
static error
devcaps_source_parse_resolutions (xml_rd *xml, devcaps_source *src)
{
    error err = NULL;

    xml_rd_enter(xml);
    for (; err == NULL && !xml_rd_end(xml); xml_rd_next(xml)) {
        if (xml_rd_node_name_match(xml, "scan:DiscreteResolutions")) {
            err = devcaps_source_parse_discrete_resolutions(xml, src);
        } else if (xml_rd_node_name_match(xml, "scan:ResolutionRange")) {
            err = devcaps_source_parse_resolutions_range(xml, src);
        }
    }
    xml_rd_leave(xml);

    /* Prefer discrete resolution, if both are provided */
    if (src->flags & DEVCAPS_SOURCE_RES_DISCRETE) {
        src->flags &= ~DEVCAPS_SOURCE_RES_RANGE;
    }

    if (!(src->flags & (DEVCAPS_SOURCE_RES_DISCRETE|DEVCAPS_SOURCE_RES_RANGE))){
        err = ERROR("Source resolutions are not defined");
    }

    return err;
}

/* Parse setting profiles (color modes, document formats etc).
 * Returns NULL on success, error string otherwise
 */
static error
devcaps_source_parse_setting_profiles (xml_rd *xml, devcaps_source *src)
{
    error err = NULL;

    xml_rd_enter(xml);
    for (; err == NULL && !xml_rd_end(xml); xml_rd_next(xml)) {
        if (xml_rd_node_name_match(xml, "scan:SettingProfile")) {
            xml_rd_enter(xml);
            for (; err == NULL && !xml_rd_end(xml); xml_rd_next(xml)) {
                if (xml_rd_node_name_match(xml, "scan:ColorModes")) {
                    err = devcaps_source_parse_color_modes(xml, src);
                } else if (xml_rd_node_name_match(xml,
                        "scan:DocumentFormats")) {
                    err = devcaps_source_parse_document_formats(xml, src);
                } else if (xml_rd_node_name_match(xml,
                        "scan:SupportedResolutions")) {
                    err = devcaps_source_parse_resolutions(xml, src);
                }
            }
            xml_rd_leave(xml);
        }
    }
    xml_rd_leave(xml);

    return err;
}


/* Parse source capabilities. Returns NULL on success, error string otherwise
 */
static error
devcaps_source_parse (xml_rd *xml, devcaps_source **out)
{
    devcaps_source *src = devcaps_source_new();
    error          err = NULL;

    xml_rd_enter(xml);
    for (; err == NULL && !xml_rd_end(xml); xml_rd_next(xml)) {
        if(xml_rd_node_name_match(xml, "scan:MinWidth")) {
            err = xml_rd_node_value_uint(xml, &src->min_wid_px);
        } else if (xml_rd_node_name_match(xml, "scan:MaxWidth")) {
            err = xml_rd_node_value_uint(xml, &src->max_wid_px);
        } else if (xml_rd_node_name_match(xml, "scan:MinHeight")) {
            err = xml_rd_node_value_uint(xml, &src->min_hei_px);
        } else if (xml_rd_node_name_match(xml, "scan:MaxHeight")) {
            err = xml_rd_node_value_uint(xml, &src->max_hei_px);
        } else if (xml_rd_node_name_match(xml, "scan:SettingProfiles")) {
            err = devcaps_source_parse_setting_profiles(xml, src);
        }
    }
    xml_rd_leave(xml);

    if (err != NULL) {
        goto DONE;
    }

    if (src->max_wid_px != 0 && src->max_hei_px != 0 )
    {
        /* Validate window size */
        if (src->min_wid_px >= src->max_wid_px )
        {
            err = ERROR("Invalid scan:MinWidth or scan:MaxWidth");
            goto DONE;
        }

        if (src->min_hei_px >= src->max_hei_px)
        {
            err = ERROR("Invalid scan:MinHeight or scan:MaxHeight");
            goto DONE;
        }

        src->flags |= DEVCAPS_SOURCE_HAS_SIZE;

        /* Set window ranges */
        src->win_x_range_mm.min = src->win_y_range_mm.min = 0;
        src->win_x_range_mm.max = math_px2mm(src->max_wid_px);
        src->win_y_range_mm.max = math_px2mm(src->max_hei_px);
    }

DONE:
    if (err != NULL) {
        devcaps_source_free(src);
    } else {
        if (*out == NULL) {
            *out = src;
        } else {
            /* Duplicate detected. Ignored for now */
            devcaps_source_free(src);
        }
    }

    return err;
}

/* Parse device capabilities. devcaps structure must be initialized
 * before calling this function.
 *
 * Returns NULL if OK, error string otherwise
 */
error
devcaps_parse (devcaps *caps, const char *xml_text, size_t xml_len)
{
    error  err = NULL;
    char   *model = NULL, *make_and_model = NULL;
    xml_rd *xml;

    /* Parse capabilities XML */
    err = xml_rd_begin(&xml, xml_text, xml_len);
    if (err != NULL) {
        goto DONE;
    }

    if (!xml_rd_node_name_match(xml, "scan:ScannerCapabilities")) {
        err = ERROR("XML: missed scan:ScannerCapabilities");
        goto DONE;
    }

    xml_rd_enter(xml);
    for (; !xml_rd_end(xml); xml_rd_next(xml)) {
        if (xml_rd_node_name_match(xml, "pwg:ModelName")) {
            g_free(model);
            model = g_strdup(xml_rd_node_value(xml));
        } else if (xml_rd_node_name_match(xml, "pwg:MakeAndModel")) {
            g_free(make_and_model);
            make_and_model = g_strdup(xml_rd_node_value(xml));
        } else if (xml_rd_node_name_match(xml, "scan:Platen")) {
            xml_rd_enter(xml);
            if (xml_rd_node_name_match(xml, "scan:PlatenInputCaps")) {
                err = devcaps_source_parse(xml, &caps->src[OPT_SOURCE_PLATEN]);
            }
            xml_rd_leave(xml);
        } else if (xml_rd_node_name_match(xml, "scan:Adf")) {
            xml_rd_enter(xml);
            while (!xml_rd_end(xml)) {
                if (xml_rd_node_name_match(xml, "scan:AdfSimplexInputCaps")) {
                    err = devcaps_source_parse(xml,
                        &caps->src[OPT_SOURCE_ADF_SIMPLEX]);
                } else if (xml_rd_node_name_match(xml,
                        "scan:AdfDuplexInputCaps")) {
                    err = devcaps_source_parse(xml,
                        &caps->src[OPT_SOURCE_ADF_DUPLEX]);
                }
                xml_rd_next(xml);
            }
            xml_rd_leave(xml);
        }

        if (err != NULL) {
            goto DONE;
        }
    }

    /* Save model, try to guess vendor */
    size_t model_len = model ? strlen(model) : 0;
    size_t make_and_model_len = make_and_model ? strlen(make_and_model) : 0;

    if (model_len && make_and_model_len > model_len &&
        g_str_has_suffix(make_and_model, model)) {

        caps->vendor = g_strndup(make_and_model,
                make_and_model_len - model_len);
        g_strchomp((char*) caps->vendor);
    }

    if (caps->vendor == NULL) {
        caps->vendor = g_strdup("Unknown");
    }

    if (model != NULL) {
        caps->model = model;
        model = NULL;
    } else if (make_and_model != NULL) {
        caps->model = make_and_model;
        make_and_model = NULL;
    }

    /* Update list of sources */
    OPT_SOURCE opt_src;

    array_of_string_reset(&caps->sane_sources);
    for (opt_src = (OPT_SOURCE) 0; opt_src < NUM_OPT_SOURCE; opt_src ++) {
        if (caps->src[opt_src] != NULL) {
            array_of_string_append(&caps->sane_sources,
                (SANE_String) opt_source_to_sane(opt_src));
        }
    }

DONE:
    if (err != NULL) {
        devcaps_reset(caps);
    }

    g_free(model);
    g_free(make_and_model);
    xml_rd_finish(&xml);

    return err;
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
            for (i = 0; i < (int) array_of_word_len(&src->resolutions); i ++) {
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
