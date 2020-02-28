/* AirScan (a.k.a. eSCL) backend for SANE
 *
 * Copyright (C) 2019 and up by Alexander Pevzner (pzz@apevzner.com)
 * See LICENSE for license terms and conditions
 *
 * ESCL protocol handler
 */

#include "airscan.h"

/* Protocol constants */
#define WSD_ADDR_ANONYMOUS              \
        "http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous"

#define WSD_ACTION_GET_SCANNER_ELEMENTS \
        "http://schemas.microsoft.com/windows/2006/08/wdp/scan/GetScannerElements"

#define WSD_ACTION_CREATE_SCAN_JOB      \
        "http://schemas.microsoft.com/windows/2006/08/wdp/scan/CreateScanJob"

#define WSD_ACTION_RETRIEVE_IMAGE       \
        "http://schemas.microsoft.com/windows/2006/08/wdp/scan/RetrieveImage"

#define WSD_ACTION_CANCEL_JOB           \
        "http://schemas.microsoft.com/windows/2006/08/wdp/scan/CancelJob"

/* XML namespace translation for XML reader
 */
static const xml_ns wsd_ns_rd[] = {
    {"s", "http*://schemas.xmlsoap.org/soap/envelope"}, /* SOAP 1.1 */
    {"s", "http*://www.w3.org/2003/05/soap-envelope"},  /* SOAP 1.2 */
    {"d", "http*://schemas.xmlsoap.org/ws/2005/04/discovery"},
    {"a", "http*://schemas.xmlsoap.org/ws/2004/08/addressing"},
    {NULL, NULL}
};

/* XML namespace definitions for XML writer
 */
static const xml_ns wsd_ns_wr[] = {
    {"s",    "http://www.w3.org/2003/05/soap-envelope"},  /* SOAP 1.2 */
    {"d",    "http://schemas.xmlsoap.org/ws/2005/04/discovery"},
    {"a",    "http://schemas.xmlsoap.org/ws/2004/08/addressing"},
    {"scan", "http://schemas.microsoft.com/windows/2006/08/wdp/scan"},
    {NULL, NULL}
};

/* proto_handler_wsd represents WSD protocol handler
 */
typedef struct {
    proto_handler proto; /* Base class */
} proto_handler_wsd;

/* Free ESCL protocol handler
 */
static void
wsd_free (proto_handler *proto)
{
    g_free(proto);
}

/* Create a HTTP POST request
 */
static http_query*
wsd_http_post (const proto_ctx *ctx, char *body)
{
    return http_query_new(ctx->http, http_uri_clone(ctx->base_uri),
        "POST", body, "application/soap+xml; charset=utf-8");
}

/* Query device capabilities
 */
static http_query*
wsd_devcaps_query (const proto_ctx *ctx)
{
    xml_wr *xml = xml_wr_begin("s:Envelope", wsd_ns_wr);
    uuid   u = uuid_new();

    xml_wr_enter(xml, "s:Header");
    xml_wr_add_text(xml, "a:MessageID", u.text);
    xml_wr_add_text(xml, "a:To", WSD_ADDR_ANONYMOUS);
    xml_wr_add_text(xml, "a:ReplyTo", WSD_ADDR_ANONYMOUS);
    xml_wr_add_text(xml, "a:Action", WSD_ACTION_GET_SCANNER_ELEMENTS);
    xml_wr_leave(xml);

    xml_wr_enter(xml, "s:Body");
    xml_wr_enter(xml, "scan:GetScannerElementsRequest");
    xml_wr_enter(xml, "scan:RequestedElements");
    xml_wr_add_text(xml, "scan:Name", "scan:ScannerDescription");
    xml_wr_add_text(xml, "scan:Name", "scan:ScannerConfiguration");
    xml_wr_add_text(xml, "scan:Name", "scan:DefaultScanTicket");
    //xml_wr_add_text(xml, "scan:Name", "scan:ScannerStatus");
    xml_wr_leave(xml);
    xml_wr_leave(xml);
    xml_wr_leave(xml);

    return wsd_http_post(ctx, xml_wr_finish(xml));
}

/* Parse scanner description
 */
static error
wsd_devcaps_parse_description (devcaps *caps, xml_rd *xml)
{
    unsigned int level = xml_rd_depth(xml);
    size_t       prefixlen = strlen(xml_rd_node_path(xml));

    (void) caps;

    while (!xml_rd_end(xml)) {
        const char *path = xml_rd_node_path(xml) + prefixlen;

        if (!strcmp(path, "/scan:ScannerName")) {
            if (caps->model == NULL) {
                caps->model = g_strdup(xml_rd_node_value(xml));
            }
        }

        xml_rd_deep_next(xml, level);
    }

    return NULL;
}

/* Parse supported formats
 */
static error
wsd_devcaps_parse_formats (devcaps *caps, xml_rd *xml, unsigned int *flags)
{
    error        err = NULL;
    unsigned int level = xml_rd_depth(xml);
    size_t       prefixlen = strlen(xml_rd_node_path(xml));

    (void) caps;

    while (!xml_rd_end(xml)) {
        const char *path = xml_rd_node_path(xml) + prefixlen;

        if (!strcmp(path, "/scan:FormatValue")) {
            const char *v = xml_rd_node_value(xml);

            if (!strcmp(v, "jfif")) {
                *flags |= DEVCAPS_SOURCE_FMT_JPEG;
            } else if (!strcmp(v, "pdf-a")) {
                *flags |= DEVCAPS_SOURCE_FMT_PDF;
            } else if (!strcmp(v, "png")) {
                *flags |= DEVCAPS_SOURCE_FMT_PNG;
            }
        }

        xml_rd_deep_next(xml, level);
    }

    return err;
}

/* Parse size
 */
static error
wsd_devcaps_parse_size (SANE_Word *out, xml_rd *xml)
{
    SANE_Word   val;
    error       err = xml_rd_node_value_uint(xml, &val);

    if (err == NULL && *out < 0) {
        *out = val;
    }

    return err;
}

/* Parse resolution and append it to array of resolutions
 */
static error
wsd_devcaps_parse_res (SANE_Word **res, xml_rd *xml)
{
    SANE_Word   val;
    error       err = xml_rd_node_value_uint(xml, &val);

    if (err == NULL) {
        sane_word_array_append(res, val);
    }

    return err;
}

/* Parse source configuration
 */
static error
wsd_devcaps_parse_source (devcaps *caps, xml_rd *xml, OPT_SOURCE src_id)
{
    error          err = NULL;
    unsigned int   level = xml_rd_depth(xml);
    size_t         prefixlen = strlen(xml_rd_node_path(xml));
    devcaps_source *src = devcaps_source_new();
    SANE_Word      *x_res, *y_res;
    SANE_Word      min_wid = -1, max_wid = -1, min_hei = -1, max_hei = -1;

    sane_word_array_init(&x_res);
    sane_word_array_init(&y_res);

    while (!xml_rd_end(xml)) {
        const char *path = xml_rd_node_path(xml) + prefixlen;

        if (!strcmp(path, "/scan:PlatenResolutions/scan:Widths/scan:Width") ||
            !strcmp(path, "/scan:ADFResolutions/scan:Widths/scan:Width")) {
            err = wsd_devcaps_parse_res(&x_res, xml);
        } else if (!strcmp(path, "/scan:PlatenResolutions/scan:Heights/scan:Height") ||
                   !strcmp(path, "/scan:ADFResolutions/scan:Heights/scan:Height")) {
            err = wsd_devcaps_parse_res(&y_res, xml);
        } else if (!strcmp(path, "/scan:PlatenMinimumSize/scan:Width") ||
                   !strcmp(path, "/scan:ADFMinimumSize/scan:Width")) {
            err = wsd_devcaps_parse_size(&min_wid, xml);
        } else if (!strcmp(path, "/scan:PlatenMinimumSize/scan:Height") ||
                   !strcmp(path, "/scan:ADFMinimumSize/scan:Height")) {
            err = wsd_devcaps_parse_size(&min_hei, xml);
        } else if (!strcmp(path, "/scan:PlatenMaximumSize/scan:Width") ||
                   !strcmp(path, "/scan:ADFMaximumSize/scan:Width")) {
            err = wsd_devcaps_parse_size(&max_wid, xml);
        } else if (!strcmp(path, "/scan:PlatenMaximumSize/scan:Height") ||
                   !strcmp(path, "/scan:ADFMaximumSize/scan:Height")) {
            err = wsd_devcaps_parse_size(&max_hei, xml);
        } else if (!strcmp(path, "/scan:PlatenColor/scan:ColorEntry") ||
                   !strcmp(path, "/scan:ADFColor/scan:ColorEntry")) {
            const char *v = xml_rd_node_value(xml);
            if (!strcmp(v, "BlackAndWhite1")) {
                src->colormodes |= 1 << OPT_COLORMODE_BW1;
            } else if (!strcmp(v, "Grayscale8")) {
                src->colormodes |= 1 << OPT_COLORMODE_GRAYSCALE;
            } else if (!strcmp(v, "RGB24")) {
                src->colormodes |= 1 << OPT_COLORMODE_COLOR;
            }
        }

        if (err != NULL) {
            break;
        }

        xml_rd_deep_next(xml, level);
    }

    /* Merge x/y resolutions */
    if (err == NULL) {
        sane_word_array_sort(&x_res);
        sane_word_array_sort(&y_res);

        sane_word_array_intersect_sorted(&src->resolutions, x_res, y_res);

        if (sane_word_array_len(&src->resolutions) > 0) {
            src->flags |= DEVCAPS_SOURCE_RES_DISCRETE;
        } else {
            err = ERROR("no resolutions defined");
        }
    }

    /* Check things */
    src->colormodes &= OPT_COLORMODES_SUPPORTED;
    if (err == NULL && src->colormodes == 0) {
        err = ERROR("no color modes defined");
    }

    if (err == NULL && min_wid < 0) {
        err = ERROR("minimum width not defined");
    }

    if (err == NULL && min_hei < 0) {
        err = ERROR("minimum height not defined");
    }

    if (err == NULL && max_wid < 0) {
        err = ERROR("maximum width not defined");
    }

    if (err == NULL && max_hei < 0) {
        err = ERROR("maximum height not defined");
    }

    if (err == NULL && min_wid > max_wid) {
        err = ERROR("minimum width > maximum width");
    }

    if (err == NULL && min_hei > max_hei) {
        err = ERROR("minimum height > maximum height");
    }

    /* Save min/max width and height */
    src->min_wid_px = min_wid;
    src->max_wid_px = max_wid;
    src->min_hei_px = min_hei;
    src->max_hei_px = max_hei;

    /* Save source */
    if (err == NULL) {
        if (caps->src[src_id] == NULL) {
            caps->src[src_id] = src;
        } else {
            devcaps_source_free(src);
        }
    }

    /* Cleanup and exit */
    sane_word_array_cleanup(&x_res);
    sane_word_array_cleanup(&y_res);

    return err;
}

/* Parse scanner configuration
 */
static error
wsd_devcaps_parse_configuration (devcaps *caps, xml_rd *xml)
{
    error        err = NULL;
    unsigned int level = xml_rd_depth(xml);
    size_t       prefixlen = strlen(xml_rd_node_path(xml));
    bool         adf = false, duplex = false;
    unsigned int formats = 0;
    int          i;

    /* Parse configuration */
    while (!xml_rd_end(xml)) {
        const char *path = xml_rd_node_path(xml) + prefixlen;

        if (!strcmp(path, "/scan:DeviceSettings/scan:FormatsSupported")) {
            err = wsd_devcaps_parse_formats(caps, xml, &formats);
        } else if (!strcmp(path, "/scan:Platen")) {
            err = wsd_devcaps_parse_source(caps, xml, OPT_SOURCE_PLATEN);
        } else if (!strcmp(path, "/scan:ADF/scan:ADFFront")) {
            adf = true;
            err = wsd_devcaps_parse_source(caps, xml, OPT_SOURCE_ADF_SIMPLEX);
        } else if (!strcmp(path, "/scan:ADF/scan:ADFBack")) {
            err = wsd_devcaps_parse_source(caps, xml, OPT_SOURCE_ADF_DUPLEX);
        } else if (!strcmp(path, "/scan:ADF/scan:ADFSupportsDuplex")) {
            const char *v = xml_rd_node_value(xml);
            duplex = !strcmp(v, "1") || !strcmp(v, "true");
        } else {
            //log_debug(NULL, "CONF: %s", path);
        }

        if (err != NULL) {
            return err;
        }

        xml_rd_deep_next(xml, level);
    }

    /* Adjust sources */
    for (i = 0; i < NUM_OPT_SOURCE; i ++) {
        devcaps_source *src = caps->src[i];

        if (src != NULL) {
            src->flags |= formats;
            src->win_x_range_mm.min = src->win_y_range_mm.min = 0;
            src->win_x_range_mm.max = math_px2mm_res(src->max_wid_px, 1000);
            src->win_y_range_mm.max = math_px2mm_res(src->max_hei_px, 1000);
        }
    }

    /* Note, WSD uses slightly unusual model: instead of providing
     * source configurations for simplex and duplex modes, it provides
     * source configuration for ADF front, which is required (when ADF
     * is supported by device) and for ADF back, which is optional
     *
     * So we assume, that ADF front applies to both simplex and duplex
     * modes, while ADF back applies only to duplex mode
     *
     * So if duplex is supported, we either merge front and back
     * configurations, if both are present, or simply copy front
     * to back, if back is missed
     */
    if (adf && duplex) {
        log_assert(NULL, caps->src[OPT_SOURCE_ADF_SIMPLEX] != NULL);
        if (caps->src[OPT_SOURCE_ADF_DUPLEX] == NULL) {
            caps->src[OPT_SOURCE_ADF_DUPLEX] =
                devcaps_source_clone(caps->src[OPT_SOURCE_ADF_SIMPLEX]);
        } else {
            devcaps_source *src;
            src = devcaps_source_merge(caps->src[OPT_SOURCE_ADF_SIMPLEX],
                caps->src[OPT_SOURCE_ADF_DUPLEX]);
            devcaps_source_free(caps->src[OPT_SOURCE_ADF_DUPLEX]);
            caps->src[OPT_SOURCE_ADF_DUPLEX] = src;
        }
    } else if (caps->src[OPT_SOURCE_ADF_DUPLEX] != NULL) {
        devcaps_source_free(caps->src[OPT_SOURCE_ADF_DUPLEX]);
        caps->src[OPT_SOURCE_ADF_DUPLEX] = NULL;
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
        return ERROR("neither platen nor ADF sources detected");
    }

    return NULL;
}

/* Parse device capabilities
 */
error
wsd_devcaps_parse (devcaps *caps, const char *xml_text, size_t xml_len)
{
    error  err = NULL;
    xml_rd *xml;

    /* Parse capabilities XML */
    err = xml_rd_begin(&xml, xml_text, xml_len, wsd_ns_rd);
    if (err != NULL) {
        goto DONE;
    }

    while (!xml_rd_end(xml)) {
        const char *path = xml_rd_node_path(xml);

        if (!strcmp(path, "s:Envelope/s:Body"
                 "/scan:GetScannerElementsResponse/scan:ScannerElements/"
                 "scan:ElementData/scan:ScannerDescription")) {
            err = wsd_devcaps_parse_description(caps, xml);
        } else if (!strcmp(path, "s:Envelope/s:Body"
                "/scan:GetScannerElementsResponse/scan:ScannerElements/"
                "scan:ElementData/scan:ScannerConfiguration")) {
            err = wsd_devcaps_parse_configuration(caps, xml);
        }

        if (err != NULL) {
            goto DONE;
        }

        xml_rd_deep_next(xml, 0);
    }

DONE:
    if (err != NULL) {
        devcaps_reset(caps);
    }

    xml_rd_finish(&xml);

    return err;
}

/* Decode device capabilities
 */
static error
wsd_devcaps_decode (const proto_ctx *ctx, devcaps *caps)
{
    http_data *data = http_query_get_response_data(ctx->query);
    error     err;

    caps->units = 1000;
    caps->protocol = ctx->proto->name;

    err = wsd_devcaps_parse(caps, data->bytes, data->size);
    if (err == NULL) {
        caps->vendor = caps->vendor ? caps->vendor : g_strdup("AirScan");
        caps->model = caps->model? caps->model : g_strdup("Unknown");
    }

    return err;
}

/* Initiate scanning
 */
static http_query*
wsd_scan_query (const proto_ctx *ctx)
{
    const proto_scan_params *params = &ctx->params;
    xml_wr                  *xml = xml_wr_begin("s:Envelope", wsd_ns_wr);
    uuid                    u = uuid_new();
    const char              *source = NULL;
    const char              *colormode = NULL;
    static const char       *sides_simplex[] = {"MediaFront", NULL};
    static const char       *sides_duplex[] = {"MediaFront", "MediaBack", NULL};
    const char              **sides;
    int                     i;

    /* Prepare parameters */
    switch (params->src) {
    case OPT_SOURCE_PLATEN:      source = "Platen"; break;
    case OPT_SOURCE_ADF_SIMPLEX: source = "ADF"; break;
    case OPT_SOURCE_ADF_DUPLEX:  source = "ADFDuplex"; break;

    default:
        log_internal_error(ctx->dev);
    }

    sides = params->src == OPT_SOURCE_ADF_DUPLEX ? sides_duplex : sides_simplex;

    switch (params->colormode) {
    case OPT_COLORMODE_COLOR:     colormode = "RGB24"; break;
    case OPT_COLORMODE_GRAYSCALE: colormode = "Grayscale8"; break;
    case OPT_COLORMODE_BW1:       colormode = "BlackAndWhite1"; break;

    default:
        log_internal_error(ctx->dev);
    }

    /* Create scan request */
    xml_wr_enter(xml, "s:Header");
    xml_wr_add_text(xml, "a:MessageID", u.text);
    xml_wr_add_text(xml, "a:To", WSD_ADDR_ANONYMOUS);
    xml_wr_add_text(xml, "a:Action", WSD_ACTION_CREATE_SCAN_JOB);
    xml_wr_leave(xml); // s:Header

    xml_wr_enter(xml, "s:Body");
    xml_wr_enter(xml, "scan:CreateScanJobRequest");
    xml_wr_enter(xml, "scan:ScanTicket");

    xml_wr_enter(xml, "scan:JobDescription");
    xml_wr_add_text(xml, "scan:JobName", "sane-airscan request");
    xml_wr_add_text(xml, "scan:JobOriginatingUserName", "sane-airscan");
    xml_wr_leave(xml); // scan:JobDescription

    xml_wr_enter(xml, "scan:DocumentParameters");
    xml_wr_add_text(xml, "scan:Format", "jfif"); // FIXME
    xml_wr_add_text(xml, "scan:ImagesToTransfer", "0");

    xml_wr_enter(xml, "scan:InputSize");
    xml_wr_enter(xml, "scan:InputMediaSize");
    xml_wr_add_uint(xml, "scan:Width", params->wid);
    xml_wr_add_uint(xml, "scan:Height", params->hei);
    xml_wr_leave(xml); // scan:InputMediaSize
    xml_wr_leave(xml); // scan:InputSize

    xml_wr_add_text(xml, "scan:InputSource", source);

    xml_wr_enter(xml, "scan:MediaSides");
    for (i = 0; sides[i] != NULL; i ++) {
        xml_wr_enter(xml, sides[i]);

        xml_wr_add_text(xml, "scan:ColorProcessing", colormode);

        xml_wr_enter(xml, "scan:Resolution");
        xml_wr_add_uint(xml, "scan:Width", params->x_res);
        xml_wr_add_uint(xml, "scan:Height", params->y_res);
        xml_wr_leave(xml); // scan:Resolution

        xml_wr_enter(xml, "scan:ScanRegion");
        xml_wr_add_uint(xml, "scan:ScanRegionXOffset", params->x_off);
        xml_wr_add_uint(xml, "scan:ScanRegionYOffset", params->y_off);
        xml_wr_add_uint(xml, "scan:ScanRegionWidth", params->wid);
        xml_wr_add_uint(xml, "scan:ScanRegionHeight", params->hei);
        xml_wr_leave(xml); // scan:ScanRegion

        xml_wr_leave(xml);
    }
    xml_wr_leave(xml); // scan:MediaSides

    xml_wr_leave(xml); // scan:DocumentParameters
    xml_wr_leave(xml); // scan:ScanTicket
    xml_wr_leave(xml); // scan:CreateScanJobRequest
    xml_wr_leave(xml); // s:Body

//log_debug(0, "%s", xml_wr_finish(xml)); exit(0);

    return wsd_http_post(ctx, xml_wr_finish(xml));
}

/* Decode result of scan request
 */
static proto_result
wsd_scan_decode (const proto_ctx *ctx)
{
    proto_result result = {0};
    error        err = NULL;
    xml_rd       *xml = NULL;
    http_data    *data;
    SANE_Word    job_id = -1;
    char         *job_token = NULL;

    /* Decode CreateScanJobResponse */
    err = http_query_error(ctx->query);
    if (err != NULL) {
        goto DONE;
    }

    data = http_query_get_response_data(ctx->query);
    err = xml_rd_begin(&xml, data->bytes, data->size, wsd_ns_rd);
    if (err != NULL) {
        goto DONE;
    }

    while (!xml_rd_end(xml)) {
        const char *path = xml_rd_node_path(xml);

        if (!strcmp(path, "s:Envelope/s:Body/scan:CreateScanJobResponse"
                "/scan:JobId")) {
            err = xml_rd_node_value_uint(xml, &job_id);
        } else if (!strcmp(path, "s:Envelope/s:Body/scan:CreateScanJobResponse"
                "/scan:JobToken")) {
            g_free(job_token);
            job_token = g_strdup(xml_rd_node_value(xml));
        }

        xml_rd_deep_next(xml, 0);
    }

    if (job_id == -1) {
        err = ERROR("missed JobId");
        goto DONE;
    }

    if (job_token == NULL) {
        err = ERROR("missed JobToken");
        goto DONE;
    }

    result.data.location = g_strdup_printf("%u:%s", job_id, job_token);

    /* Cleanup and exit */
DONE:
    xml_rd_finish(&xml);
    g_free(job_token);

    if (err != NULL) {
        result.code = PROTO_ERROR;
        result.status = SANE_STATUS_IO_ERROR;
        result.err = eloop_eprintf("CreateScanJobResponse: %s", ESTRING(err));
    }

    return result;
}

/* Initiate image downloading
 */
static http_query*
wsd_load_query (const proto_ctx *ctx)
{
    xml_wr *xml = xml_wr_begin("s:Envelope", wsd_ns_wr);
    uuid   u = uuid_new();
    char   *job_id, *job_token;

    /* Split location into JobId and JobToken */
    job_id = g_alloca(strlen(ctx->location) + 1);
    strcpy(job_id, ctx->location);
    job_token = strchr(job_id, ':');
    *job_token ++ = '\0';

    /* Build RetrieveImageRequest */
    xml_wr_enter(xml, "s:Header");
    xml_wr_add_text(xml, "a:MessageID", u.text);
    xml_wr_add_text(xml, "a:To", WSD_ADDR_ANONYMOUS);
    xml_wr_add_text(xml, "a:ReplyTo", WSD_ADDR_ANONYMOUS);
    xml_wr_add_text(xml, "a:Action", WSD_ACTION_RETRIEVE_IMAGE);
    xml_wr_leave(xml);

    xml_wr_enter(xml, "s:Body");
    xml_wr_enter(xml, "scan:RetrieveImageRequest");

    xml_wr_enter(xml, "scan:DocumentDescription");
    xml_wr_add_text(xml, "scan:DocumentName", "IMAGE000.JPG");
    xml_wr_leave(xml);

    xml_wr_add_text(xml, "scan:JobId", job_id);
    xml_wr_add_text(xml, "scan:JobToken", job_token);

    xml_wr_leave(xml);
    xml_wr_leave(xml);

    return wsd_http_post(ctx, xml_wr_finish(xml));
}

/* Decode result of image request
 */
static proto_result
wsd_load_decode (const proto_ctx *ctx)
{
    proto_result result;
    http_data    *data;
    error        err;

    /* Check HTTP status */
    err = http_query_error(ctx->query);
    if (err != NULL) {
        result.code = PROTO_ERROR;
        result.err = err;
        return result;
    }

    /* We expect multipart message with attached image */
    data = http_query_get_mp_response_data(ctx->query, 1);
    if (data == NULL) {
        result.code = PROTO_ERROR;
        result.err = ERROR("RetrieveImageRequest: invalid response");
        return result;
    }

    result.code = PROTO_OK;
    result.data.image = http_data_ref(data);

    return result;
}

/* Request device status
 */
static http_query*
wsd_status_query (const proto_ctx *ctx)
{
    (void) ctx;
    return NULL;
}

/* Decode result of device status request
 */
static proto_result
wsd_status_decode (const proto_ctx *ctx)
{
    proto_result result = {0};

    (void) ctx;
    return result;
}

/* Cancel scan in progress
 */
static http_query*
wsd_cancel_query (const proto_ctx *ctx)
{
    xml_wr *xml = xml_wr_begin("s:Envelope", wsd_ns_wr);
    uuid   u = uuid_new();
    char   *job_id, *job_token;

    /* Split location into JobId and JobToken */
    job_id = g_alloca(strlen(ctx->location) + 1);
    strcpy(job_id, ctx->location);
    job_token = strchr(job_id, ':');
    *job_token ++ = '\0';

    /* Build CancelJob Request */
    xml_wr_enter(xml, "s:Header");
    xml_wr_add_text(xml, "a:MessageID", u.text);
    xml_wr_add_text(xml, "a:To", WSD_ADDR_ANONYMOUS);
    xml_wr_add_text(xml, "a:ReplyTo", WSD_ADDR_ANONYMOUS);
    xml_wr_add_text(xml, "a:Action", WSD_ACTION_CANCEL_JOB);
    xml_wr_leave(xml);

    xml_wr_enter(xml, "s:Body");
    xml_wr_enter(xml, "scan:CancelJobRequest");

    xml_wr_add_text(xml, "scan:JobId", job_id);

    xml_wr_leave(xml);
    xml_wr_leave(xml);

    return wsd_http_post(ctx, xml_wr_finish(xml));
}

/* proto_handler_wsd_new creates new eSCL protocol handler
 */
proto_handler*
proto_handler_wsd_new (void)
{
    proto_handler_wsd *wsd = g_new0(proto_handler_wsd, 1);

    wsd->proto.name = "WSD";
    wsd->proto.free = wsd_free;

    wsd->proto.devcaps_query = wsd_devcaps_query;
    wsd->proto.devcaps_decode = wsd_devcaps_decode;

    wsd->proto.scan_query = wsd_scan_query;
    wsd->proto.scan_decode = wsd_scan_decode;

    wsd->proto.load_query = wsd_load_query;
    wsd->proto.load_decode = wsd_load_decode;

    wsd->proto.status_query = wsd_status_query;
    wsd->proto.status_decode = wsd_status_decode;

    wsd->proto.cancel_query = wsd_cancel_query;

    return &wsd->proto;
}

/* vim:ts=8:sw=4:et
 */
