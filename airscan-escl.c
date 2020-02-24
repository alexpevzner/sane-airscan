/* AirScan (a.k.a. eSCL) backend for SANE
 *
 * Copyright (C) 2019 and up by Alexander Pevzner (pzz@apevzner.com)
 * See LICENSE for license terms and conditions
 *
 * ESCL protocol handler
 */

#include "airscan.h"

/* proto_handler_escl represents eSCL protocol handler
 */
typedef struct {
    proto_handler proto; /* Base class */
} proto_handler_escl;

/* XML namespace for XML writer
 */
static const xml_ns escl_xml_wr_ns[] = {
    {"pwg",  "http://www.pwg.org/schemas/2010/12/sm"},
    {"scan", "http://schemas.hp.com/imaging/escl/2011/05/03"},
    {NULL, NULL}
};

/******************** HTTP utility functions ********************/
/* Create HTTP query
 */
static http_query*
escl_http_query (const proto_ctx *ctx, const char *path,
        const char *method, char *body)
{
    return http_query_new_relative(ctx->http, ctx->base_uri, path,
        method, body, "text/xml");
}

/* Create HTTP get query
 */
static http_query*
escl_http_get (const proto_ctx *ctx, const char *path)
{
    return escl_http_query(ctx, path, "GET", NULL);
}

/******************** Device Capabilities ********************/
/* Parse color modes
 */
static error
escl_devcaps_source_parse_color_modes (xml_rd *xml, devcaps_source *src)
{
    src->colormodes = 0;
    sane_string_array_reset(&src->sane_colormodes);

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

    if (src->colormodes == 0) {
        return ERROR("no color modes detected");
    }

    OPT_COLORMODE cm;
    for (cm = (OPT_COLORMODE) 0; cm < NUM_OPT_COLORMODE; cm ++) {
        if ((src->colormodes & (1 << cm)) != 0) {
            SANE_String s = (SANE_String) opt_colormode_to_sane(cm);
            sane_string_array_append(&src->sane_colormodes, s);
        }
    }

    return NULL;
}

/* Parse document formats
 */
static error
escl_devcaps_source_parse_document_formats (xml_rd *xml, devcaps_source *src)
{
    xml_rd_enter(xml);
    for (; !xml_rd_end(xml); xml_rd_next(xml)) {
        unsigned int flags = 0;

        if(xml_rd_node_name_match(xml, "pwg:DocumentFormat")) {
            flags |= DEVCAPS_SOURCE_PWG_DOCFMT;
        }

        if(xml_rd_node_name_match(xml, "scan:DocumentFormatExt")) {
            flags |= DEVCAPS_SOURCE_SCAN_DOCFMT_EXT;
        }

        if (flags != 0) {
            const char *v = xml_rd_node_value(xml);
            if (!strcasecmp(v, "image/jpeg")) {
                src->flags |= flags | DEVCAPS_SOURCE_FMT_JPEG;
            } else if (!strcasecmp(v, "image/png")) {
                src->flags |= flags | DEVCAPS_SOURCE_FMT_PNG;
            } else if (!strcasecmp(v, "application/pdf")) {
                src->flags |= flags | DEVCAPS_SOURCE_FMT_PDF;
            }
        }
    }
    xml_rd_leave(xml);

    return NULL;
}

/* Parse discrete resolutions.
 */
static error
escl_devcaps_source_parse_discrete_resolutions (xml_rd *xml,
        devcaps_source *src)
{
    error err = NULL;

    sane_word_array_reset(&src->resolutions);

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
                sane_word_array_append(&src->resolutions, x);
            }
        }
    }
    xml_rd_leave(xml);

    if (sane_word_array_len((&src->resolutions)) > 0) {
        src->flags |= DEVCAPS_SOURCE_RES_DISCRETE;
        sane_word_array_sort(&src->resolutions);
    }

    return err;
}

/* Parse resolutions range
 */
static error
escl_devcaps_source_parse_resolutions_range (xml_rd *xml, devcaps_source *src)
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
 */
static error
escl_devcaps_source_parse_resolutions (xml_rd *xml, devcaps_source *src)
{
    error err = NULL;

    xml_rd_enter(xml);
    for (; err == NULL && !xml_rd_end(xml); xml_rd_next(xml)) {
        if (xml_rd_node_name_match(xml, "scan:DiscreteResolutions")) {
            err = escl_devcaps_source_parse_discrete_resolutions(xml, src);
        } else if (xml_rd_node_name_match(xml, "scan:ResolutionRange")) {
            err = escl_devcaps_source_parse_resolutions_range(xml, src);
        }
    }
    xml_rd_leave(xml);

    /* Prefer discrete resolution, if both are provided */
    if (src->flags & DEVCAPS_SOURCE_RES_DISCRETE) {
        src->flags &= ~DEVCAPS_SOURCE_RES_RANGE;
    }

    if (!(src->flags & (DEVCAPS_SOURCE_RES_DISCRETE|DEVCAPS_SOURCE_RES_RANGE))){
        err = ERROR("scan resolutions are not defined");
    }

    return err;
}

/* Parse setting profiles (color modes, document formats etc).
 */
static error
escl_devcaps_source_parse_setting_profiles (xml_rd *xml, devcaps_source *src)
{
    error err = NULL;

    xml_rd_enter(xml);
    for (; err == NULL && !xml_rd_end(xml); xml_rd_next(xml)) {
        if (xml_rd_node_name_match(xml, "scan:SettingProfile")) {
            xml_rd_enter(xml);
            for (; err == NULL && !xml_rd_end(xml); xml_rd_next(xml)) {
                if (xml_rd_node_name_match(xml, "scan:ColorModes")) {
                    err = escl_devcaps_source_parse_color_modes(xml, src);
                } else if (xml_rd_node_name_match(xml,
                        "scan:DocumentFormats")) {
                    err = escl_devcaps_source_parse_document_formats(xml, src);
                } else if (xml_rd_node_name_match(xml,
                        "scan:SupportedResolutions")) {
                    err = escl_devcaps_source_parse_resolutions(xml, src);
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
escl_devcaps_source_parse (xml_rd *xml, devcaps_source **out)
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
            err = escl_devcaps_source_parse_setting_profiles(xml, src);
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
 */
error
escl_devcaps_parse (devcaps *caps, const char *xml_text, size_t xml_len)
{
    error  err = NULL;
    char   *model = NULL, *make_and_model = NULL;
    xml_rd *xml;

    /* Parse capabilities XML */
    err = xml_rd_begin(&xml, xml_text, xml_len, NULL);
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
                err = escl_devcaps_source_parse(xml,
                    &caps->src[OPT_SOURCE_PLATEN]);
            }
            xml_rd_leave(xml);
        } else if (xml_rd_node_name_match(xml, "scan:Adf")) {
            xml_rd_enter(xml);
            while (!xml_rd_end(xml)) {
                if (xml_rd_node_name_match(xml, "scan:AdfSimplexInputCaps")) {
                    err = escl_devcaps_source_parse(xml,
                        &caps->src[OPT_SOURCE_ADF_SIMPLEX]);
                } else if (xml_rd_node_name_match(xml,
                        "scan:AdfDuplexInputCaps")) {
                    err = escl_devcaps_source_parse(xml,
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
        caps->vendor = g_strdup("AirScan");
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
    bool       src_ok = false;

    sane_string_array_reset(&caps->sane_sources);
    for (opt_src = (OPT_SOURCE) 0; opt_src < NUM_OPT_SOURCE; opt_src ++) {
        if (caps->src[opt_src] != NULL) {
            sane_string_array_append(&caps->sane_sources,
                (SANE_String) opt_source_to_sane(opt_src));
            src_ok = true;
        }
    }

    if (!src_ok) {
        err = ERROR("XML: neither platen nor ADF sources detected");
        goto DONE;
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

/* Query device capabilities
 */
static http_query*
escl_devcaps_query (const proto_ctx *ctx)
{
    return escl_http_get(ctx, "ScannerCapabilities");
}

/* Decode device capabilities
 */
static error
escl_devcaps_decode (const proto_ctx *ctx, devcaps *caps)
{
    http_data *data = http_query_get_response_data(ctx->query);
    return escl_devcaps_parse(caps, data->bytes, data->size);
}

/* Initiate scanning
 */
static http_query*
escl_scan_query (const proto_ctx *ctx)
{
    const proto_scan_params *params = &ctx->params;
    const char              *source = NULL;
    const char              *colormode = NULL;
    const char              *mime = "image/jpeg";
    const devcaps_source    *src = ctx->devcaps->src[params->src];
    bool                    duplex = false;

    /* Prepare parameters */
    switch (params->src) {
    case OPT_SOURCE_PLATEN:      source = "Platen"; duplex = false; break;
    case OPT_SOURCE_ADF_SIMPLEX: source = "Feeder"; duplex = false; break;
    case OPT_SOURCE_ADF_DUPLEX:  source = "Feeder"; duplex = true; break;

    default:
        log_internal_error(ctx->dev);
    }

    switch (params->colormode) {
    case OPT_COLORMODE_COLOR:     colormode = "RGB24"; break;
    case OPT_COLORMODE_GRAYSCALE: colormode = "Grayscale8"; break;
    case OPT_COLORMODE_LINEART:   colormode = "BlackAndWhite1"; break;

    default:
        log_internal_error(ctx->dev);
    }

    /* Build scan request */
    xml_wr *xml = xml_wr_begin("scan:ScanSettings", escl_xml_wr_ns);

    xml_wr_add_text(xml, "pwg:Version", "2.0");

    xml_wr_enter(xml, "pwg:ScanRegions");
    xml_wr_enter(xml, "pwg:ScanRegion");
    xml_wr_add_text(xml, "pwg:ContentRegionUnits",
            "escl:ThreeHundredthsOfInches");
    xml_wr_add_uint(xml, "pwg:XOffset", params->x_off);
    xml_wr_add_uint(xml, "pwg:YOffset", params->y_off);
    xml_wr_add_uint(xml, "pwg:Width", params->wid);
    xml_wr_add_uint(xml, "pwg:Height", params->hei);
    xml_wr_leave(xml); /* pwg:ScanRegion */
    xml_wr_leave(xml); /* pwg:ScanRegions */

    //xml_wr_add_text(xml, "scan:InputSource", source);
    xml_wr_add_text(xml, "pwg:InputSource", source);
    xml_wr_add_text(xml, "scan:ColorMode", colormode);
    xml_wr_add_text(xml, "pwg:DocumentFormat", mime);
    if ((src->flags & DEVCAPS_SOURCE_SCAN_DOCFMT_EXT) != 0) {
        xml_wr_add_text(xml, "scan:DocumentFormatExt", mime);
    }
    xml_wr_add_uint(xml, "scan:XResolution", params->x_res);
    xml_wr_add_uint(xml, "scan:YResolution", params->y_res);
    if (params->src != OPT_SOURCE_PLATEN) {
        xml_wr_add_bool(xml, "scan:Duplex", duplex);
    }

    /* Send request to device */
    return escl_http_query(ctx, "ScanJobs", "POST", xml_wr_finish(xml));
}

/* Decode result of scan request
 */
static proto_result
escl_scan_decode (const proto_ctx *ctx)
{
    proto_result result = {0};
    error        err = NULL;
    const char   *location;
    http_uri     *uri;

    /* Check HTTP status */
    if (http_query_status(ctx->query) != HTTP_STATUS_CREATED) {
        err = eloop_eprintf("ScanJobs request: unexpected HTTP status %d",
                http_query_status(ctx->query));
        result.code = PROTO_CHECK_STATUS;
        result.err = err;
        return result;
    }

    /* Obtain location */
    location = http_query_get_response_header(ctx->query, "Location");
    if (location == NULL || *location == '\0') {
        err = eloop_eprintf("ScanJobs request: empty location received");
        goto ERROR;
    }

    /* Validate and save location */
    uri = http_uri_new_relative(ctx->base_uri, location, true, true);
    if (uri == NULL) {
        err = eloop_eprintf("ScanJobs request: invalid location received");
        goto ERROR;
    }

    result.data.location = g_strdup(http_uri_get_path(uri));
    http_uri_free(uri);

    return result;

ERROR:
    result.code = PROTO_ERROR;
    result.status = SANE_STATUS_IO_ERROR;
    result.err = err;
    return result;
}

/* Initiate image downloading
 */
static http_query*
escl_load_query (const proto_ctx *ctx)
{
    char *url, *sep;
    http_query *q;

    sep = g_str_has_suffix(ctx->location, "/") ? "" : "/";
    url = g_strconcat(ctx->location, sep, "NextDocument", NULL);

    q = escl_http_get(ctx, url);
    g_free(url);

    return q;
}

/* Decode result of image request
 */
static proto_result
escl_load_decode (const proto_ctx *ctx)
{
    proto_result result = {0};
    error        err = NULL;

    /* Check HTTP status */
    err = http_query_error(ctx->query);
    if (err != NULL) {
        result.code = PROTO_CHECK_STATUS;
        result.err = err;
        return result;
    }

    result.code = PROTO_OK;
    result.data.image = http_data_ref(http_query_get_response_data(ctx->query));
    return result;
}

/* Request device status
 */
static http_query*
escl_status_query (const proto_ctx *ctx)
{
    return escl_http_get(ctx, "ScannerStatus");
}

/* Parse ScannerStatus response.
 */
static SANE_Status
escl_decode_scanner_status (const proto_ctx *ctx,
        const char *xml_text, size_t xml_len)
{
    error       err = NULL;
    xml_rd      *xml;
    SANE_Status device_status = SANE_STATUS_UNSUPPORTED;
    SANE_Status adf_status = SANE_STATUS_UNSUPPORTED;
    SANE_Status status;

    /* Decode XML */
    err = xml_rd_begin(&xml, xml_text, xml_len, NULL);
    if (err != NULL) {
        goto DONE;
    }

    if (!xml_rd_node_name_match(xml, "scan:ScannerStatus")) {
        err = ERROR("XML: missed scan:ScannerStatus");
        goto DONE;
    }

    xml_rd_enter(xml);
    for (; !xml_rd_end(xml); xml_rd_next(xml)) {
        if (xml_rd_node_name_match(xml, "pwg:State")) {
            const char *state = xml_rd_node_value(xml);
            if (!strcmp(state, "Idle")) {
                device_status = SANE_STATUS_GOOD;
            } else if (!strcmp(state, "Processing")) {
                device_status = SANE_STATUS_DEVICE_BUSY;
            } else {
                device_status = SANE_STATUS_UNSUPPORTED;
            }
        } else if (xml_rd_node_name_match(xml, "scan:AdfState")) {
            const char *state = xml_rd_node_value(xml);
            if (!strcmp(state, "ScannerAdfLoaded")) {
                adf_status = SANE_STATUS_GOOD;
            } else if (!strcmp(state, "ScannerAdfJam")) {
                adf_status = SANE_STATUS_JAMMED;
            } else if (!strcmp(state, "ScannerAdfDoorOpen")) {
                adf_status = SANE_STATUS_COVER_OPEN;
            } else if (!strcmp(state, "ScannerAdfProcessing")) {
                /* Kyocera version */
                adf_status = SANE_STATUS_NO_DOCS;
            } else if (!strcmp(state, "ScannerAdfEmpty")) {
                /* Cannon TR4500, EPSON XP-7100 */
                adf_status = SANE_STATUS_NO_DOCS;
            } else {
                adf_status = SANE_STATUS_UNSUPPORTED;
            }
        }
    }

    /* Decode Job status */
    if (device_status != SANE_STATUS_GOOD &&
        device_status != SANE_STATUS_UNSUPPORTED) {
        status = device_status;
    } else if (ctx->params.src == OPT_SOURCE_PLATEN) {
        status = device_status;
    } else {
        status = adf_status;
    }

DONE:
    xml_rd_finish(&xml);

    trace_printf(device_trace(ctx->dev), "-----");
    if (err != NULL) {
        trace_printf(device_trace(ctx->dev), "Error: %s", ESTRING(err));
        status = SANE_STATUS_IO_ERROR;
    } else {
        trace_printf(device_trace(ctx->dev), "Device status: %s",
            sane_strstatus(device_status));
        trace_printf(device_trace(ctx->dev), "ADF status: %s",
            sane_strstatus(adf_status));
        trace_printf(device_trace(ctx->dev), "Job status: %s",
            sane_strstatus(status));
        trace_printf(device_trace(ctx->dev), "");
    }

    return status;
}

/* Decode result of device status request
 */
static proto_result
escl_status_decode (const proto_ctx *ctx)
{
    proto_result result = {0};
    error        err = NULL;
    SANE_Status  status;

    /* Decode status */
    err = http_query_error(ctx->query);
    if (err != NULL) {
        result.code = PROTO_ERROR;
        result.status = SANE_STATUS_IO_ERROR;
        result.err = err;
        return result;
    } else {
        http_data *data = http_query_get_response_data(ctx->query);
        status = escl_decode_scanner_status(ctx, data->bytes, data->size);
    }

    /* Now it's time to make a decision */
    if (ctx->failed_op == PROTO_FAILED_LOAD &&
        ctx->failed_http_status == HTTP_STATUS_SERVICE_UNAVAILABLE ) {

        /* Note, some devices may return HTTP_STATUS_SERVICE_UNAVAILABLE
         * on attempt to load page immediately after job is created
         *
         * So if status doesn't cleanly indicate any error, lets retry
         * several times
         */
        switch (status) {
        case SANE_STATUS_GOOD:
        case SANE_STATUS_UNSUPPORTED:
        case SANE_STATUS_DEVICE_BUSY:
                result.code = PROTO_OK; /* Will cause a retry */
                return result;

        default:
            break;
        }
    }

    if (status == SANE_STATUS_GOOD || status == SANE_STATUS_UNSUPPORTED) {
        status = SANE_STATUS_IO_ERROR;
    }

    /* Fill the result */
    result.code = PROTO_ERROR;
    result.status = status;
    return result;
}

/* Cancel scan in progress
 */
static http_query*
escl_cancel_query (const proto_ctx *ctx)
{
    return escl_http_query(ctx, ctx->location, "DELETE", NULL);
}

/******************** Constructor/destructor ********************/
/* Free ESCL protocol handler
 */
static void
escl_free (proto_handler *proto)
{
    g_free(proto);
}

/* proto_handler_escl_new creates new eSCL protocol handler
 */
proto_handler*
proto_handler_escl_new (void)
{
    proto_handler_escl *escl = g_new0(proto_handler_escl, 1);

    escl->proto.name = "eSCL";
    escl->proto.free = escl_free;

    escl->proto.devcaps_query = escl_devcaps_query;
    escl->proto.devcaps_decode = escl_devcaps_decode;

    escl->proto.scan_query = escl_scan_query;
    escl->proto.scan_decode = escl_scan_decode;

    escl->proto.load_query = escl_load_query;
    escl->proto.load_decode = escl_load_decode;

    escl->proto.status_query = escl_status_query;
    escl->proto.status_decode = escl_status_decode;

    escl->proto.cancel_query = escl_cancel_query;

    return &escl->proto;
}

/* vim:ts=8:sw=4:et
 */
