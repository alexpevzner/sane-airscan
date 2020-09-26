/* AirScan (a.k.a. eSCL) backend for SANE
 *
 * Copyright (C) 2019 and up by Alexander Pevzner (pzz@apevzner.com)
 * See LICENSE for license terms and conditions
 *
 * ESCL protocol handler
 */

#include "airscan.h"

/******************** Protocol constants ********************/
/* If HTTP 503 reply is received, how many retry attempts
 * to perform before giving up
 *
 *   ESCL_RETRY_ATTEMPTS_LOAD - for NextDocument request
 *   ESCL_RETRY_ATTEMPTS      - for other requests
 *
 * Note, some printers (namely, HP LaserJet MFP M28w) require
 * a lot of retry attempts when loading next page at high res
 */
#define ESCL_RETRY_ATTEMPTS_LOAD        30
#define ESCL_RETRY_ATTEMPTS             10

/* And pause between retries, in milliseconds
 */
#define ESCL_RETRY_PAUSE                1000

/* Some devices (namely, Brother MFC-L2710DW) erroneously returns
 * HTTP 404 Not Found when scanning from ADF, if next LOAD request
 * send immediately after completion the previous one, and ScannerStatus
 * returns ScannerAdfEmpty at this case, which leads to premature
 * scan job termination with SANE_STATUS_NO_DOCS status
 *
 * Introducing a small delay between subsequent LOAD requests solves
 * this problem.
 *
 * To avoid performance regression on a very fast scanners, this
 * delay is limited to some fraction of the preceding LOAD
 * query time
 *
 *   ESCL_NEXT_LOAD_DELAY     - delay between LOAD requests, milliseconds
 *   ESCL_NEXT_LOAD_DELAY_MAX - upper limit of this delay, as a fraction
 *                              of a previous LOAD time
 */
#define ESCL_NEXT_LOAD_DELAY           1000
#define ESCL_NEXT_LOAD_DELAY_MAX       0.5

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

    xml_rd_enter(xml);
    for (; !xml_rd_end(xml); xml_rd_next(xml)) {
        if(xml_rd_node_name_match(xml, "scan:ColorMode")) {
            const char *v = xml_rd_node_value(xml);
            if (!strcmp(v, "BlackAndWhite1")) {
                src->colormodes |= 1 << ID_COLORMODE_BW1;
            } else if (!strcmp(v, "Grayscale8")) {
                src->colormodes |= 1 << ID_COLORMODE_GRAYSCALE;
            } else if (!strcmp(v, "RGB24")) {
                src->colormodes |= 1 << ID_COLORMODE_COLOR;
            }
        }
    }
    xml_rd_leave(xml);

    src->colormodes &= DEVCAPS_COLORMODES_SUPPORTED;
    if (src->colormodes == 0) {
        return ERROR("no color modes detected");
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
            ID_FORMAT  fmt = id_format_by_mime_name(v);

            if (fmt != ID_FORMAT_UNKNOWN) {
                src->formats |= 1 << fmt;
                src->flags |= flags;
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
                src->resolutions = sane_word_array_append(src->resolutions, x);
            }
        }
    }
    xml_rd_leave(xml);

    if (sane_word_array_len(src->resolutions) > 0) {
        src->flags |= DEVCAPS_SOURCE_RES_DISCRETE;
        sane_word_array_sort(src->resolutions);
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

    if (src->max_wid_px != 0 && src->max_hei_px != 0)
    {
        /* Validate window size */
        if (src->min_wid_px > src->max_wid_px)
        {
            err = ERROR("Invalid scan:MinWidth or scan:MaxWidth");
            goto DONE;
        }

        if (src->min_hei_px > src->max_hei_px)
        {
            err = ERROR("Invalid scan:MinHeight or scan:MaxHeight");
            goto DONE;
        }

        src->flags |= DEVCAPS_SOURCE_HAS_SIZE;

        /* Set window ranges */
        src->win_x_range_mm.min = src->win_y_range_mm.min = 0;
        src->win_x_range_mm.max = math_px2mm_res(src->max_wid_px, 300);
        src->win_y_range_mm.max = math_px2mm_res(src->max_hei_px, 300);
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

/* Parse compression factor parameters
 */
static error
escl_devcaps_compression_parse (xml_rd *xml, devcaps *caps)
{
    for (; !xml_rd_end(xml); xml_rd_next(xml)) {
        error err = NULL;

        if (xml_rd_node_name_match(xml, "scan:Min")) {
            err = xml_rd_node_value_uint(xml, &caps->compression_range.min);
        } else if (xml_rd_node_name_match(xml, "scan:Max")) {
            err = xml_rd_node_value_uint(xml, &caps->compression_range.max);
        } else if (xml_rd_node_name_match(xml, "scan:Step")) {
            err = xml_rd_node_value_uint(xml, &caps->compression_range.quant);
        } else if (xml_rd_node_name_match(xml, "scan:Normal")) {
            err = xml_rd_node_value_uint(xml, &caps->compression_norm);
        }

        if (err != NULL) {
            return err;
        }
    }

    /* Validate obtained parameters.
     *
     * Note, errors are silently ignored starting from this point
     */
    if (caps->compression_range.min > caps->compression_range.max) {
        return NULL;
    }

    if (caps->compression_norm < caps->compression_range.min ||
        caps->compression_norm > caps->compression_range.max) {
        return NULL;
    }

    caps->compression_ok = true;

    return NULL;
}

/* Parse device capabilities. devcaps structure must be initialized
 * before calling this function.
 */
static error
escl_devcaps_parse (devcaps *caps, const char *xml_text, size_t xml_len)
{
    error  err = NULL;
    xml_rd *xml;
    bool   quirk_canon_iR2625_2630 = false;

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
        if (xml_rd_node_name_match(xml, "pwg:MakeAndModel")) {
            const char *m = xml_rd_node_value(xml);

            if (!strcmp(m, "Canon iR2625/2630")) {
                quirk_canon_iR2625_2630 = true;
            }
        } else if (xml_rd_node_name_match(xml, "scan:Platen")) {
            xml_rd_enter(xml);
            if (xml_rd_node_name_match(xml, "scan:PlatenInputCaps")) {
                err = escl_devcaps_source_parse(xml,
                    &caps->src[ID_SOURCE_PLATEN]);
            }
            xml_rd_leave(xml);
        } else if (xml_rd_node_name_match(xml, "scan:Adf")) {
            xml_rd_enter(xml);
            while (!xml_rd_end(xml)) {
                if (xml_rd_node_name_match(xml, "scan:AdfSimplexInputCaps")) {
                    err = escl_devcaps_source_parse(xml,
                        &caps->src[ID_SOURCE_ADF_SIMPLEX]);
                } else if (xml_rd_node_name_match(xml,
                        "scan:AdfDuplexInputCaps")) {
                    err = escl_devcaps_source_parse(xml,
                        &caps->src[ID_SOURCE_ADF_DUPLEX]);
                }
                xml_rd_next(xml);
            }
            xml_rd_leave(xml);
        } else if (xml_rd_node_name_match(xml, "scan:CompressionFactorSupport")) {
            xml_rd_enter(xml);
            err = escl_devcaps_compression_parse(xml, caps);
            xml_rd_leave(xml);
        }

        if (err != NULL) {
            goto DONE;
        }
    }

    /* Check that we have at least one source */
    ID_SOURCE id_src;
    bool      src_ok = false;

    for (id_src = (ID_SOURCE) 0; id_src < NUM_ID_SOURCE; id_src ++) {
        if (caps->src[id_src] != NULL) {
            src_ok = true;
        }
    }

    if (!src_ok) {
        err = ERROR("XML: neither platen nor ADF sources detected");
        goto DONE;
    }

    /* Apply quirks, if any */
    if (quirk_canon_iR2625_2630) {
        /* This device announces resolutions up to 600 DPI,
         * but actually doesn't support more that 300
         *
         * https://oip.manual.canon/USRMA-4209-zz-CSL-2600-enUV/contents/devu-apdx-sys_spec-send.html?search=600
         *
         * See #57 for details
         */
        for (id_src = (ID_SOURCE) 0; id_src < NUM_ID_SOURCE; id_src ++) {
            devcaps_source *src = caps->src[id_src];
            if (src != NULL &&
                /* paranoia: array won't be empty after quirk applied */
                sane_word_array_len(src->resolutions) > 0 &&
                src->resolutions[1] <= 300) {
                sane_word_array_bound(src->resolutions, 0, 300);
            }
        }
    }

DONE:
    if (err != NULL) {
        devcaps_reset(caps);
    }

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

    caps->units = 300;
    caps->protocol = ctx->proto->name;

    return escl_devcaps_parse(caps, data->bytes, data->size);
}

/* Fix Location: URL
 *
 * Can be used as http_query_onredir() callback
 */
static void
escl_scan_fix_location (void *p, http_uri *uri, const http_uri *orig_uri)
{
    (void) p;
    http_uri_fix_host(uri, orig_uri, "localhost");
}

/* Initiate scanning
 */
static http_query*
escl_scan_query (const proto_ctx *ctx)
{
    const proto_scan_params *params = &ctx->params;
    const char              *source = NULL;
    const char              *colormode = NULL;
    const char              *mime = id_format_mime_name(ctx->params.format);
    const devcaps_source    *src = ctx->devcaps->src[params->src];
    bool                    duplex = false;
    http_query              *query;

    /* Prepare parameters */
    switch (params->src) {
    case ID_SOURCE_PLATEN:      source = "Platen"; duplex = false; break;
    case ID_SOURCE_ADF_SIMPLEX: source = "Feeder"; duplex = false; break;
    case ID_SOURCE_ADF_DUPLEX:  source = "Feeder"; duplex = true; break;

    default:
        log_internal_error(ctx->log);
    }

    switch (params->colormode) {
    case ID_COLORMODE_COLOR:     colormode = "RGB24"; break;
    case ID_COLORMODE_GRAYSCALE: colormode = "Grayscale8"; break;
    case ID_COLORMODE_BW1:       colormode = "BlackAndWhite1"; break;

    default:
        log_internal_error(ctx->log);
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
    if (ctx->devcaps->compression_ok) {
        xml_wr_add_uint(xml, "scan:CompressionFactor",
            ctx->devcaps->compression_norm);
    }
    xml_wr_add_text(xml, "scan:ColorMode", colormode);
    xml_wr_add_text(xml, "pwg:DocumentFormat", mime);
    if ((src->flags & DEVCAPS_SOURCE_SCAN_DOCFMT_EXT) != 0) {
        xml_wr_add_text(xml, "scan:DocumentFormatExt", mime);
    }
    xml_wr_add_uint(xml, "scan:XResolution", params->x_res);
    xml_wr_add_uint(xml, "scan:YResolution", params->y_res);
    if (params->src != ID_SOURCE_PLATEN) {
        xml_wr_add_bool(xml, "scan:Duplex", duplex);
    }

    /* Send request to device */
    query = escl_http_query(ctx, "ScanJobs", "POST",
        xml_wr_finish_compact(xml));

    /* It's a dirty hack
     *
     * HP LaserJet MFP M630 doesn't allow eSCL scan, unless
     * Host is set to "localhost". It is probably bad and
     * naive attempt to enforce some access security.
     *
     * So here we forcibly set Host to "localhost". I hope
     * it will not cause problems with other devices. BTW,
     * vuescan does the same, and I believe they have tested
     * many devices.
     */
    http_query_set_request_header(query, "Host", "localhost");
    http_query_onredir(query, escl_scan_fix_location);

    return query;
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
        result.next = PROTO_OP_CHECK;
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
    uri = http_uri_new_relative(ctx->base_uri, location, true, false);
    if (uri == NULL) {
        err = eloop_eprintf("ScanJobs request: invalid location received");
        goto ERROR;
    }

    escl_scan_fix_location(NULL, uri, http_query_uri(ctx->query));
    result.data.location = str_dup(http_uri_str(uri));
    http_uri_free(uri);

    result.next = PROTO_OP_LOAD;

    return result;

ERROR:
    result.next = PROTO_OP_FINISH;
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

    sep = str_has_suffix(ctx->location, "/") ? "" : "/";
    url = str_concat(ctx->location, sep, "NextDocument", NULL);

    q = escl_http_get(ctx, url);
    mem_free(url);

    return q;
}

/* Decode result of image request
 */
static proto_result
escl_load_decode (const proto_ctx *ctx)
{
    proto_result result = {0};
    error        err = NULL;
    timestamp    t = 0;

    /* Check HTTP status */
    err = http_query_error(ctx->query);
    if (err != NULL) {
        if (ctx->params.src == ID_SOURCE_PLATEN && ctx->images_received > 0) {
            result.next = PROTO_OP_CLEANUP;
        } else {
            result.next = PROTO_OP_CHECK;
            result.err = eloop_eprintf("HTTP: %s", ESTRING(err));
        }

        return result;
    }

    /* Compute delay until next load */
    if (ctx->params.src != ID_SOURCE_PLATEN) {
        t = timestamp_now() - http_query_timestamp(ctx->query);
        t *= ESCL_NEXT_LOAD_DELAY_MAX;

        if (t > ESCL_NEXT_LOAD_DELAY) {
            t = ESCL_NEXT_LOAD_DELAY;
        }
    }

    /* Fill proto_result */
    result.next = PROTO_OP_LOAD;
    result.delay = (int) t;
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
 *
 * Returned SANE_STATUS_UNSUPPORTED means status not understood
 */
static SANE_Status
escl_decode_scanner_status (const proto_ctx *ctx,
        const char *xml_text, size_t xml_len)
{
    error       err = NULL;
    xml_rd      *xml;
    SANE_Status device_status = SANE_STATUS_UNSUPPORTED;
    SANE_Status adf_status = SANE_STATUS_UNSUPPORTED;
    SANE_Status status = SANE_STATUS_IO_ERROR;

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
            } else if (!strcmp(state, "Testing")) {
                /* HP LaserJet MFP M630 warm up */
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
    if (ctx->params.src != ID_SOURCE_PLATEN &&
        adf_status != SANE_STATUS_GOOD &&
        adf_status != SANE_STATUS_UNSUPPORTED) {
        status = adf_status;
    } else {
        status = device_status;
    }

DONE:
    xml_rd_finish(&xml);

    trace_printf(log_ctx_trace(ctx->log), "-----");
    if (err != NULL) {
        trace_printf(log_ctx_trace(ctx->log), "Error: %s", ESTRING(err));
    } else {
        trace_printf(log_ctx_trace(ctx->log), "Device status: %s",
            sane_strstatus(device_status));
        trace_printf(log_ctx_trace(ctx->log), "ADF status: %s",
            sane_strstatus(adf_status));
        trace_printf(log_ctx_trace(ctx->log), "Job status: %s",
            sane_strstatus(status));
        trace_printf(log_ctx_trace(ctx->log), "");
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
    int          max_attempts;

    /* Decode status */
    err = http_query_error(ctx->query);
    if (err != NULL) {
        status = SANE_STATUS_IO_ERROR;
        goto FAIL;
    } else {
        http_data *data = http_query_get_response_data(ctx->query);
        status = escl_decode_scanner_status(ctx, data->bytes, data->size);
    }

    /* Now it's time to make a decision */
    max_attempts = ESCL_RETRY_ATTEMPTS;
    if (ctx->failed_op == PROTO_OP_LOAD) {
        max_attempts = ESCL_RETRY_ATTEMPTS_LOAD;
    }

    if (ctx->failed_http_status == HTTP_STATUS_SERVICE_UNAVAILABLE &&
        ctx->failed_attempt < max_attempts) {

        /* Note, some devices may return HTTP 503 error core, meaning
         * that it makes sense to come back after small delay
         *
         * So if status doesn't cleanly indicate any error, lets retry
         * several times
         */
        bool retry = false;

        switch (status) {
        case SANE_STATUS_GOOD:
        case SANE_STATUS_UNSUPPORTED:
        case SANE_STATUS_DEVICE_BUSY:
            retry = true;
            break;

        case SANE_STATUS_NO_DOCS:
            /* For some devices SANE_STATUS_NO_DOCS is not
             * reliable, if we have reached SANE_STATUS_NO_DOCS
             * operation: HTTP 503 may mean "I'm temporary not
             * ready, please try again", while ADF sensor
             * raises "ADF empty" signal.
             *
             * So retry at this case
             */
            if (ctx->failed_op == PROTO_OP_LOAD) {
                retry = true;
            }
            break;

        default:
            break;
        }

        if (retry) {
            result.next = ctx->failed_op;
            result.delay = ESCL_RETRY_PAUSE;
            return result;
        }
    }

    /* If status cannot be cleanly decoded, look to HTTP status */
    if (status == SANE_STATUS_GOOD || status == SANE_STATUS_UNSUPPORTED) {
        status = SANE_STATUS_IO_ERROR;
        switch (ctx->failed_http_status) {
        case HTTP_STATUS_SERVICE_UNAVAILABLE:
            status = SANE_STATUS_DEVICE_BUSY;
            break;

        case HTTP_STATUS_NOT_FOUND:
            if (ctx->params.src != ID_SOURCE_PLATEN &&
                ctx->failed_op == PROTO_OP_LOAD) {
                status = SANE_STATUS_NO_DOCS;
            }
            break;
        }
    }

    /* Fill the result */
FAIL:
    result.next = ctx->location ? PROTO_OP_CLEANUP : PROTO_OP_FINISH;
    result.status = status;
    result.err = err;

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
    mem_free(proto);
}

/* proto_handler_escl_new creates new eSCL protocol handler
 */
proto_handler*
proto_handler_escl_new (void)
{
    proto_handler_escl *escl = mem_new(proto_handler_escl, 1);

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

    escl->proto.cleanup_query = escl_cancel_query;
    escl->proto.cancel_query = escl_cancel_query;

    return &escl->proto;
}

/* vim:ts=8:sw=4:et
 */
