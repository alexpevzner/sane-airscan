/* AirScan (a.k.a. eSCL) backend for SANE
 *
 * Copyright (C) 2019 and up by Alexander Pevzner (pzz@apevzner.com)
 * See LICENSE for license terms and conditions
 *
 * ESCL protocol handler
 */

#define _GNU_SOURCE
#include <string.h>

#include "airscan.h"

#include <stdlib.h>

/* Protocol constants */

/* Miscellaneous strings, used by protocol
 */
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

/* Retry parameters
 *
 * If CreateScanJobRequest is failed due to temporary reason (Calibrating,
 * LampWarming), request is retries several times
 *
 * WSD_CREATE_SCAN_JOB_RETRY_PAUSE defines pause between retries,
 * in milliseconds. WSD_CREATE_SCAN_JOB_RETRY_ATTEMPTS defines
 * an attempt limit
 */
#define WSD_CREATE_SCAN_JOB_RETRY_PAUSE         1000
#define WSD_CREATE_SCAN_JOB_RETRY_ATTEMPTS      30

/* XML namespace translation for XML reader
 */
static const xml_ns wsd_ns_rd[] = {
    {"s",    "http*://schemas.xmlsoap.org/soap/envelope"}, /* SOAP 1.1 */
    {"s",    "http*://www.w3.org/2003/05/soap-envelope"},  /* SOAP 1.2 */
    {"d",    "http*://schemas.xmlsoap.org/ws/2005/04/discovery"},
    {"a",    "http*://schemas.xmlsoap.org/ws/2004/08/addressing"},
    {"scan", "http*://schemas.microsoft.com/windows/2006/08/wdp/scan"},
    {NULL, NULL}
};

/* XML namespace definitions for XML writer
 */
static const xml_ns wsd_ns_wr[] = {
    {"soap", "http://www.w3.org/2003/05/soap-envelope"},  /* SOAP 1.2 */
    {"wsa",  "http://schemas.xmlsoap.org/ws/2004/08/addressing"},
    {"sca",  "http://schemas.microsoft.com/windows/2006/08/wdp/scan"},
    {NULL, NULL}
};

/* proto_handler_wsd represents WSD protocol handler
 */
typedef struct {
    proto_handler proto; /* Base class */

    /* Error reasons decoding */
    char          fault_code[64];

    /* Supported formats: JPEG variants */
    bool          exif;
    bool          jfif;

    /* Supported formats: TIFF variabls */
    bool          tiff_single_uncompressed;
    bool          tiff_single_g4;
    bool          tiff_single_g3mh;
    bool          tiff_single_jpeg_tn2;

    /* Other formats */
    bool          pdf_a;
    bool          png;
    bool          dib;

    /* Quirks */

    /* Scanner doesn't handle sca:ImagesToTransfer if set to "0"
     * (which means "scan until ADF is empty").
     *
     * This is the Ricoh Aficio MP 201 case.
     *
     * The workaround is to set sca:ImagesToTransfer to some big
     * arbitrary number.
     */
    bool          quirk_broken_ImagesToTransfer;
} proto_handler_wsd;

/* Forward declarations */
static http_query*
wsd_status_query (const proto_ctx *ctx);

/* Free WSD protocol handler
 */
static void
wsd_free (proto_handler *proto)
{
    mem_free(proto);
}

/* Create a HTTP POST request
 */
static http_query*
wsd_http_post (const proto_ctx *ctx, char *body)
{
    http_query *q;

    q = http_query_new(ctx->http, http_uri_clone(ctx->base_uri),
        "POST", body, "application/soap+xml");

    http_query_set_request_header(q, "Cache-Control", "no-cache");
    http_query_set_request_header(q, "Pragma", "no-cache");
    http_query_set_request_header(q, "User-Agent", "WSDAPI");

    return q;
}

/* Make SOAP header for outgoing request
 */
static void
wsd_make_request_header (const proto_ctx *ctx, xml_wr *xml, const char *action)
{
    uuid   u = uuid_rand();

    xml_wr_enter(xml, "soap:Header");
    xml_wr_add_text(xml, "wsa:MessageID", u.text);
    //xml_wr_add_text(xml, "wsa:To", WSD_ADDR_ANONYMOUS);
    xml_wr_add_text(xml, "wsa:To", http_uri_str(ctx->base_uri_nozone));
    xml_wr_enter(xml, "wsa:ReplyTo");
    xml_wr_add_text(xml, "wsa:Address", WSD_ADDR_ANONYMOUS);
    xml_wr_leave(xml);
    xml_wr_add_text(xml, "wsa:Action", action);
    xml_wr_leave(xml);
}

/* Query device capabilities
 */
static http_query*
wsd_devcaps_query (const proto_ctx *ctx)
{
    xml_wr *xml = xml_wr_begin("soap:Envelope", wsd_ns_wr);

    wsd_make_request_header(ctx, xml, WSD_ACTION_GET_SCANNER_ELEMENTS);

    xml_wr_enter(xml, "soap:Body");
    xml_wr_enter(xml, "sca:GetScannerElementsRequest");
    xml_wr_enter(xml, "sca:RequestedElements");

    /* sca:ScannerConfiguration response defines scanner capabilities,
     * such as document formats support, available sources, avaliable
     * resolutions, color modes etc.
     */
    xml_wr_add_text(xml, "sca:Name", "sca:ScannerConfiguration");

    /* These elements are only requested for logging, to provide some
     * device information for troubleshooting purposes
     */
    xml_wr_add_text(xml, "sca:Name", "sca:ScannerDescription");
    xml_wr_add_text(xml, "sca:Name", "sca:DefaultScanTicket");
    xml_wr_add_text(xml, "sca:Name", "sca:ScannerStatus");

    xml_wr_leave(xml);
    xml_wr_leave(xml);
    xml_wr_leave(xml);

    return wsd_http_post(ctx, xml_wr_finish_compact(xml));
}

/* Parse supported formats
 */
static error
wsd_devcaps_parse_formats (proto_handler_wsd *wsd,
        devcaps *caps, xml_rd *xml, unsigned int *formats_out)
{
    error        err = NULL;
    unsigned int level = xml_rd_depth(xml);
    size_t       prefixlen = strlen(xml_rd_node_path(xml));
    unsigned int formats = 0;

    (void) caps;

    /* Decode supported formats */
    while (!xml_rd_end(xml)) {
        const char *path = xml_rd_node_path(xml) + prefixlen;

        if (!strcmp(path, "/scan:FormatValue")) {
            const char *v = xml_rd_node_value(xml);

            if (!strcmp(v, "jfif")) {
                wsd->jfif = true;
            } else if (!strcmp(v, "exif")) {
                wsd->exif = true;

            } else if (!strcmp(v, "tiff-single-uncompressed")) {
                wsd->tiff_single_uncompressed = true;
            } else if (!strcmp(v, "tiff-single-g4")) {
                wsd->tiff_single_g4 = true;
            } else if (!strcmp(v, "tiff-single-g3mh")) {
                wsd->tiff_single_g3mh = true;
            } else if (!strcmp(v, "tiff-single-jpeg-tn2")) {
                wsd->tiff_single_jpeg_tn2 = true;
            } else if (!strcmp(v, "pdf-a")) {
                wsd->pdf_a = true;
            } else if (!strcmp(v, "png")) {
                wsd->png = true;
            } else if (!strcmp(v, "dib")) {
                wsd->dib = true;
            }
        }

        xml_rd_deep_next(xml, level);
    }

    /* Set formats bits */
    if (wsd->jfif || wsd->exif) {
        formats |= 1 << ID_FORMAT_JPEG;
    }

    if (wsd->pdf_a) {
        formats |= 1 << ID_FORMAT_PDF;
    }

    if (wsd->png) {
        formats |= 1 << ID_FORMAT_PNG;
    }

    if (wsd->tiff_single_g4 || wsd->tiff_single_g3mh) {
        formats |= 1 << ID_FORMAT_TIFF;
    }

    if ((formats & DEVCAPS_FORMATS_SUPPORTED) == 0) {
        /* These used as last resort */
        if (wsd->tiff_single_jpeg_tn2 || wsd->tiff_single_uncompressed) {
            formats |= 1 << ID_FORMAT_TIFF;
        }

        if (wsd->dib) {
            formats |= 1 << ID_FORMAT_BMP;
        }
    }

    *formats_out = formats;
    if (((formats) & DEVCAPS_FORMATS_SUPPORTED) == 0) {
        err = ERROR("no supported image formats");
    }

    return err;
}

/* Parse supported content types and map them to scan intents
 */
static error
wsd_devcaps_parse_content_types (devcaps *caps, xml_rd *xml,
        unsigned int *scanintents_out)
{
    error        err = NULL;
    unsigned int level = xml_rd_depth(xml);
    size_t       prefixlen = strlen(xml_rd_node_path(xml));
    unsigned int scanintents = 0;

    (void) caps;

    /* Decode supported content types */
    while (!xml_rd_end(xml)) {
        const char *path = xml_rd_node_path(xml) + prefixlen;

        if (!strcmp(path, "/scan:ContentTypeValue")) {
            const char *v = xml_rd_node_value(xml);

            if (!strcmp(v, "Auto")) {
                scanintents |= 1 << ID_SCANINTENT_AUTO;
            } else if (!strcmp(v, "Text")) {
                scanintents |= 1 << ID_SCANINTENT_DOCUMENT;
            } else if (!strcmp(v, "Photo")) {
                scanintents |= 1 << ID_SCANINTENT_PHOTO;
            } else if (!strcmp(v, "Halftone")) {
                scanintents |= 1 << ID_SCANINTENT_HALFTONE;
            } else if (!strcmp(v, "Mixed")) {
                scanintents |= 1 << ID_SCANINTENT_TEXTANDGRAPHIC;
            } else {
                log_debug(NULL, "unknown content type: %s", v);
            }
        }

        xml_rd_deep_next(xml, level);
    }

    *scanintents_out = scanintents;

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
        *res = sane_word_array_append(*res, val);
    }

    return err;
}

/* Parse source configuration
 */
static error
wsd_devcaps_parse_source (devcaps *caps, xml_rd *xml, ID_SOURCE src_id)
{
    error          err = NULL;
    unsigned int   level = xml_rd_depth(xml);
    size_t         prefixlen = strlen(xml_rd_node_path(xml));
    devcaps_source *src = devcaps_source_new();
    SANE_Word      *x_res = sane_word_array_new();
    SANE_Word      *y_res = sane_word_array_new();
    SANE_Word      min_wid = -1, max_wid = -1, min_hei = -1, max_hei = -1;

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
                src->colormodes |= 1 << ID_COLORMODE_BW1;
            } else if (!strcmp(v, "Grayscale8")) {
                src->colormodes |= 1 << ID_COLORMODE_GRAYSCALE;
            } else if (!strcmp(v, "RGB24")) {
                src->colormodes |= 1 << ID_COLORMODE_COLOR;
            }
        }

        if (err != NULL) {
            break;
        }

        xml_rd_deep_next(xml, level);
    }

    /* Merge x/y resolutions */
    if (err == NULL) {
        sane_word_array_sort(x_res);
        sane_word_array_sort(y_res);

        sane_word_array_free(src->resolutions);
        src->resolutions = sane_word_array_intersect_sorted(x_res, y_res);
        if (sane_word_array_len(src->resolutions) > 0) {
            src->flags |= DEVCAPS_SOURCE_RES_DISCRETE;
        } else {
            err = ERROR("no resolutions defined");
        }
    }

    /* Check things */
    src->colormodes &= DEVCAPS_COLORMODES_SUPPORTED;
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

    /* Fix things
     *
     * Note. Some scanners (namely, Kyocera ECOSYS M2040dn)
     * return width and height swapped. As a workaround,
     * we flip if back, if width is greater that heigh
     *
     * FIXME: more reliable detection of need to flip
     * width and height is required
     */
    if (max_wid > max_hei) {
        SANE_Word tmp;

        tmp = max_wid;
        max_wid = max_hei;
        max_hei = tmp;

        tmp = min_wid;
        min_wid = min_hei;
        min_hei = tmp;
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
    sane_word_array_free(x_res);
    sane_word_array_free(y_res);

    return err;
}

/* Parse scanner configuration
 */
static error
wsd_devcaps_parse_configuration (proto_handler_wsd *wsd,
        devcaps *caps, xml_rd *xml)
{
    error        err = NULL;
    unsigned int level = xml_rd_depth(xml);
    size_t       prefixlen = strlen(xml_rd_node_path(xml));
    bool         adf = false, duplex = false;
    unsigned int formats = 0;
    unsigned int scanintents = 0;
    int          i;

    /* Parse configuration */
    while (!xml_rd_end(xml)) {
        const char *path = xml_rd_node_path(xml) + prefixlen;

        if (!strcmp(path, "/scan:DeviceSettings/scan:FormatsSupported")) {
            err = wsd_devcaps_parse_formats(wsd, caps, xml, &formats);
        } else if (!strcmp(path, "/scan:DeviceSettings/scan:ContentTypesSupported")) {
            err = wsd_devcaps_parse_content_types(caps, xml, &scanintents);
        } else if (!strcmp(path, "/scan:Platen")) {
            err = wsd_devcaps_parse_source(caps, xml, ID_SOURCE_PLATEN);
        } else if (!strcmp(path, "/scan:ADF/scan:ADFFront")) {
            adf = true;
            err = wsd_devcaps_parse_source(caps, xml, ID_SOURCE_ADF_SIMPLEX);
        } else if (!strcmp(path, "/scan:ADF/scan:ADFBack")) {
            err = wsd_devcaps_parse_source(caps, xml, ID_SOURCE_ADF_DUPLEX);
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
    for (i = 0; i < NUM_ID_SOURCE; i ++) {
        devcaps_source *src = caps->src[i];

        if (src != NULL) {
            src->formats = formats;
            src->scanintents = scanintents;

            /* Note, as we can clip in software, we indicate
             * minimal scan region size for SANE as 0x0. But
             * maximal size is defined by hardware
             */
            src->win_x_range_mm.min = src->win_y_range_mm.min = 0;
            src->win_x_range_mm.max = math_px2mm_res(src->max_wid_px, 1000);
            src->win_y_range_mm.max = math_px2mm_res(src->max_hei_px, 1000);
        }
    }

    /* Please note that the standard model for SANE and for our implementation
     * involves having two separate configurations for the duplex ADF: one for
     * simplex mode and another for duplex mode. In duplex mode, it is assumed
     * that the front and back page scanning will have the same
     * characteristics.
     *
     * However, WSD employs a slightly different model. Instead of providing
     * separate source configurations for simplex and duplex modes, it offers a
     * source configuration for the ADF front, which is required when the ADF
     * is supported by the device, and an optional configuration for the ADF
     * back.
     *
     * According to the specification, the ADF back configuration is optional.
     * If the scanner indicates duplex support (via the ADFSupportsDuplex) but
     * does not provide a separate ADFBack element, the ADFBack should be
     * assumed to be the same as ADFFront.
     *
     * During the decoding process, we temporarily store the ADF front
     * information under the IDSOURCEADFSIMPLEX and the ADF back information
     * under the IDSOURCEADFDUPLEX slots, and then make adjustments.
     *
     * When adjusting, we assume that the ADF front applies to both simplex and
     * duplex modes, while the ADF back applies only to duplex mode.
     *
     * Therefore, if duplex is supported, we either merge the front and back
     * configurations if both are present or simply copy the front
     * configuration to the back if the back configuration is missing.
     */
    if (adf && duplex) {
        log_assert(NULL, caps->src[ID_SOURCE_ADF_SIMPLEX] != NULL);
        if (caps->src[ID_SOURCE_ADF_DUPLEX] == NULL) {
            caps->src[ID_SOURCE_ADF_DUPLEX] =
                devcaps_source_clone(caps->src[ID_SOURCE_ADF_SIMPLEX]);
        } else {
            devcaps_source *src;
            src = devcaps_source_merge(caps->src[ID_SOURCE_ADF_SIMPLEX],
                caps->src[ID_SOURCE_ADF_DUPLEX]);
            devcaps_source_free(caps->src[ID_SOURCE_ADF_DUPLEX]);
            caps->src[ID_SOURCE_ADF_DUPLEX] = src;
        }
    } else if (caps->src[ID_SOURCE_ADF_DUPLEX] != NULL) {
        devcaps_source_free(caps->src[ID_SOURCE_ADF_DUPLEX]);
        caps->src[ID_SOURCE_ADF_DUPLEX] = NULL;
    }

    /* Workaround for yet another Kyocera bug. This device doesn't
     * honor scan region settings. I.e., it understands it,
     * properly mirrors in DocumentFinalParameters, but completely
     * ignores when generating the image.
     *
     * So we can't rely on device's ability to clip the image and
     * must implement clipping in software. It can be enforced
     * in our backend by setting minimum image size equal to
     * max size.
     */
    for (i = 0; i < NUM_ID_SOURCE; i ++) {
        devcaps_source *src = caps->src[i];

        if (src != NULL) {
            src->min_wid_px = src->max_wid_px;
            src->min_hei_px = src->max_hei_px;
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
        return ERROR("neither platen nor ADF sources detected");
    }

    return NULL;
}

/* Parse device capabilities
 */
static error
wsd_devcaps_parse (proto_handler_wsd *wsd,
        devcaps *caps, const char *xml_text, size_t xml_len)
{
    error  err = NULL;
    xml_rd *xml;
    bool   found_configuration = false;

    /* Fill "constant" part of device capabilities */
    caps->units = 1000;
    caps->protocol = wsd->proto.name;
    caps->justification_x = caps->justification_y = ID_JUSTIFICATION_UNKNOWN;

    /* Parse capabilities XML */
    err = xml_rd_begin(&xml, xml_text, xml_len, wsd_ns_rd);
    if (err != NULL) {
        goto DONE;
    }

    while (!xml_rd_end(xml)) {
        const char *path = xml_rd_node_path(xml);

        if (!strcmp(path, "s:Envelope/s:Body"
                "/scan:GetScannerElementsResponse/scan:ScannerElements/"
                "scan:ElementData/scan:ScannerConfiguration")) {
            found_configuration = true;
            err = wsd_devcaps_parse_configuration(wsd, caps, xml);
        }

        if (err != NULL) {
            goto DONE;
        }

        xml_rd_deep_next(xml, 0);
    }

    /* Check things */
    if (!found_configuration) {
        err = ERROR("ScannerConfiguration missed");
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
    proto_handler_wsd *wsd = (proto_handler_wsd*) ctx->proto;
    http_data         *data = http_query_get_response_data(ctx->query);
    error             err;

    /* Setup quirks */
    if (!strcmp(ctx->devinfo->model, "RICOH Aficio MP 201")) {
        wsd->quirk_broken_ImagesToTransfer = true;
    }

    /* Parse device capabilities response */
    err = wsd_devcaps_parse(wsd, caps, data->bytes, data->size);

    return err;
}

/* Check if response is fault response without decoding it
 */
static bool
wsd_fault_check (const proto_ctx *ctx)
{
    http_data         *data;
    static const char fault[] =
        "//schemas.xmlsoap.org/ws/2004/08/addressing/fault";

    /* If we have erroneous HTTP status, we expect to see fault message
     * inside
     */
    if (http_query_error(ctx->query) != NULL) {
        return true;
    }

    /* Some devices (namely Lexmark MB2236adw and Xerox WorkCentre 3225)
     * may use HTTP status 200 to return fault response, so check for
     * the HTTP status code is not enough to distinguish between normal
     * and fault response
     *
     * So we search the response body for the following string:
     *     "//schemas.xmlsoap.org/ws/2004/08/addressing/fault"
     *
     * If this string is found, this is probably a fault response
     *
     * Note, the scheme is stripped from this string, because some
     * devices use "http://", why another may use "https://"
     *
     * Note, as optimization and to avoid searching this string
     * across the image date, we assume that if we have got MIME
     * multipart response, it is probably not fault.
     */
    if (http_query_get_mp_response_count(ctx->query) != 0) {
        return false;
    }

    data = http_query_get_response_data(ctx->query);
    if (memmem(data->bytes, data->size, fault, sizeof(fault) - 1) != NULL) {
        return true;
    }

    return false;
}

/* Decode fault response
 */
static proto_result
wsd_fault_decode (const proto_ctx *ctx, bool cleanup)
{
    proto_handler_wsd *wsd = (proto_handler_wsd*) ctx->proto;
    proto_result      result = {0};
    http_data         *data = http_query_get_response_data(ctx->query);
    xml_rd            *xml;

    /* Parse XML */
    result.err = xml_rd_begin(&xml, data->bytes, data->size, wsd_ns_rd);
    if (result.err != NULL) {
        result.next = cleanup ? PROTO_OP_CLEANUP : PROTO_OP_FINISH;
        result.status = SANE_STATUS_IO_ERROR;
        return result;
    }

    /* Decode XML, save fault code */
    while (!xml_rd_end(xml)) {
        const char *path = xml_rd_node_path(xml);

        if (!strcmp(path, "s:Envelope/s:Body/s:Fault/s:Code/s:Subcode/s:Value")) {
            const char *fault = xml_rd_node_value(xml);
            const char *s;

            /* Skip namespace prefix */
            s = strchr(fault, ':');
            if (s != NULL) {
                fault = s + 1;
            }

            /* Save the status */
            log_debug(ctx->log, "fault code: %s", fault);
            strncpy(wsd->fault_code, fault, sizeof(wsd->fault_code) - 1);
        }

        xml_rd_deep_next(xml, 0);
    }

    xml_rd_finish(&xml);

    result.next = PROTO_OP_CHECK;
    return result;
}

/* Create pre-scan check query
 */
static http_query*
wsd_precheck_query (const proto_ctx *ctx)
{
    return wsd_status_query(ctx);
}

/* Decode pre-scan check query results
 */
static proto_result
wsd_precheck_decode (const proto_ctx *ctx)
{
    proto_result result = {0};

    (void) ctx;

    result.next = PROTO_OP_SCAN;
    result.status = SANE_STATUS_GOOD;

    return result;
}

/* Initiate scanning
 */
static http_query*
wsd_scan_query (const proto_ctx *ctx)
{
    proto_handler_wsd       *wsd = (proto_handler_wsd*) ctx->proto;
    const proto_scan_params *params = &ctx->params;
    xml_wr                  *xml = xml_wr_begin("soap:Envelope", wsd_ns_wr);
    const char              *source = NULL;
    const char              *colormode = NULL;
    const char              *contenttype = NULL;
    const char              *format = NULL;
    static const char       *sides_simplex[] = {"sca:MediaFront", NULL};
    static const char       *sides_duplex[] = {"sca:MediaFront", "sca:MediaBack", NULL};
    const char              **sides;
    int                     i;

    /* Prepare parameters */
    switch (params->src) {
    case ID_SOURCE_PLATEN:      source = "Platen"; break;
    case ID_SOURCE_ADF_SIMPLEX: source = "ADF"; break;
    case ID_SOURCE_ADF_DUPLEX:  source = "ADFDuplex"; break;

    default:
        log_internal_error(ctx->log);
    }

    sides = params->src == ID_SOURCE_ADF_DUPLEX ? sides_duplex : sides_simplex;

    switch (params->colormode) {
    case ID_COLORMODE_COLOR:     colormode = "RGB24"; break;
    case ID_COLORMODE_GRAYSCALE: colormode = "Grayscale8"; break;
    case ID_COLORMODE_BW1:       colormode = "BlackAndWhite1"; break;

    default:
        log_internal_error(ctx->log);
    }

    switch (params->scanintent) {
    case ID_SCANINTENT_UNSET:          break;
    case ID_SCANINTENT_AUTO:           contenttype = "Auto"; break;
    case ID_SCANINTENT_DOCUMENT:       contenttype = "Text"; break;
    case ID_SCANINTENT_PHOTO:          contenttype = "Photo"; break;
    case ID_SCANINTENT_HALFTONE:       contenttype = "Halftone"; break;
    case ID_SCANINTENT_TEXTANDGRAPHIC: contenttype = "Mixed"; break;

    default:
        log_internal_error(ctx->log);
    }

    /* Create scan request */
    wsd_make_request_header(ctx, xml, WSD_ACTION_CREATE_SCAN_JOB);

    xml_wr_enter(xml, "soap:Body");
    xml_wr_enter(xml, "sca:CreateScanJobRequest");
    xml_wr_enter(xml, "sca:ScanTicket");

    xml_wr_enter(xml, "sca:JobDescription");
    xml_wr_add_text(xml, "sca:JobName", "sane-airscan request");
    xml_wr_add_text(xml, "sca:JobOriginatingUserName", "sane-airscan");

    /* WS-Scan specification says that this parameter is optional,
     * but without this parameter the Canon TR7500 rejects scan
     * request with the InvalidArgs error
     */
    xml_wr_add_text(xml, "sca:JobInformation", "sane-airscan");

    xml_wr_leave(xml); // sca:JobDescription

    xml_wr_enter(xml, "sca:DocumentParameters");

    switch (ctx->params.format) {
    case ID_FORMAT_JPEG:
        if (wsd->jfif) {
            format = "jfif";
        } else if (wsd->exif) {
            format = "exif";
        }
        break;

    case ID_FORMAT_TIFF:
        if (wsd->tiff_single_g4) {
            format = "tiff-single-g4";
        } else if (wsd->tiff_single_g3mh) {
            format = "tiff-single-g3mh";
        } else if (wsd->tiff_single_jpeg_tn2) {
            format = "tiff-single-jpeg-tn2";
        } else if (wsd->tiff_single_uncompressed) {
            format = "tiff-single-uncompressed";
        }
        break;

    case ID_FORMAT_PNG:
        if (wsd->png) {
            format = "png";
        }
        break;

    case ID_FORMAT_PDF:
        if (wsd->pdf_a) {
            format = "pdf-a";
        }
        break;

    case ID_FORMAT_BMP:
        if (wsd->dib) {
            format = "dib";
        }
        break;

    case ID_FORMAT_UNKNOWN:
    case NUM_ID_FORMAT:
        break;
    }

    log_assert(ctx->log, format != NULL);
    xml_wr_add_text(xml, "sca:Format", format);

    /* WS-Scan specification says unspecified scan amount should be 0
     * ( unknown amount, check for more ) and for Flatbed that is 1.
     */
    switch (params->src) {
    case ID_SOURCE_PLATEN:
        xml_wr_add_text(xml, "sca:ImagesToTransfer", "1");
        break;
    case ID_SOURCE_ADF_SIMPLEX:
    case ID_SOURCE_ADF_DUPLEX:
        if (wsd->quirk_broken_ImagesToTransfer) {
            xml_wr_add_text(xml, "sca:ImagesToTransfer", "100");
        } else {
            xml_wr_add_text(xml, "sca:ImagesToTransfer", "0");
        }
        break;
    default:
        log_internal_error(ctx->log);
    }

    if (contenttype) {
        xml_wr_add_text(xml, "sca:ContentType", contenttype);
    }

    xml_wr_enter(xml, "sca:InputSize");
    xml_wr_enter(xml, "sca:InputMediaSize");
    xml_wr_add_uint(xml, "sca:Width", params->wid);
    xml_wr_add_uint(xml, "sca:Height", params->hei);
    xml_wr_leave(xml); // sca:InputMediaSize
    xml_wr_leave(xml); // sca:InputSize

    xml_wr_add_text(xml, "sca:InputSource", source);

    xml_wr_enter(xml, "sca:MediaSides");
    for (i = 0; sides[i] != NULL; i ++) {
        xml_wr_enter(xml, sides[i]);

        xml_wr_add_text(xml, "sca:ColorProcessing", colormode);

        xml_wr_enter(xml, "sca:Resolution");
        xml_wr_add_uint(xml, "sca:Width", params->x_res);
        xml_wr_add_uint(xml, "sca:Height", params->y_res);
        xml_wr_leave(xml); // sca:Resolution

        xml_wr_enter(xml, "sca:ScanRegion");
        xml_wr_add_uint(xml, "sca:ScanRegionXOffset", params->x_off);
        xml_wr_add_uint(xml, "sca:ScanRegionYOffset", params->y_off);
        xml_wr_add_uint(xml, "sca:ScanRegionWidth", params->wid);
        xml_wr_add_uint(xml, "sca:ScanRegionHeight", params->hei);
        xml_wr_leave(xml); // sca:ScanRegion

        xml_wr_leave(xml);
    }
    xml_wr_leave(xml); // sca:MediaSides

    xml_wr_leave(xml); // sca:DocumentParameters
    xml_wr_leave(xml); // sca:ScanTicket
    xml_wr_leave(xml); // sca:CreateScanJobRequest
    xml_wr_leave(xml); // soap:Body

//log_debug(0, "%s", xml_wr_finish_compact(xml)); exit(0);

    return wsd_http_post(ctx, xml_wr_finish_compact(xml));
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

    result.next = PROTO_OP_FINISH;

    /* Decode error, if any */
    if (wsd_fault_check(ctx)) {
        return wsd_fault_decode(ctx, false);
    }

    /* Decode CreateScanJobResponse */
    data = http_query_get_response_data(ctx->query);
    err = xml_rd_begin(&xml, data->bytes, data->size, wsd_ns_rd);
    if (err != NULL) {
        err = eloop_eprintf("XML: %s", ESTRING(err));
        goto DONE;
    }

    while (!xml_rd_end(xml)) {
        const char *path = xml_rd_node_path(xml);

        if (!strcmp(path, "s:Envelope/s:Body/scan:CreateScanJobResponse"
                "/scan:JobId")) {
            err = xml_rd_node_value_uint(xml, &job_id);
        } else if (!strcmp(path, "s:Envelope/s:Body/scan:CreateScanJobResponse"
                "/scan:JobToken")) {
            mem_free(job_token);
            job_token = str_dup(xml_rd_node_value(xml));
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

    result.next = PROTO_OP_LOAD;
    result.data.location = str_printf("%u:%s", job_id, job_token);

    /* Cleanup and exit */
DONE:
    xml_rd_finish(&xml);
    mem_free(job_token);

    if (err != NULL) {
        result.err = eloop_eprintf("CreateScanJobResponse: %s", ESTRING(err));
    }

    if (result.next == PROTO_OP_FINISH) {
        result.status = SANE_STATUS_IO_ERROR;
    }

    return result;
}

/* Initiate image downloading
 */
static http_query*
wsd_load_query (const proto_ctx *ctx)
{
    xml_wr *xml = xml_wr_begin("soap:Envelope", wsd_ns_wr);
    char   *job_id, *job_token;

    /* Split location into JobId and JobToken */
    job_id = alloca(strlen(ctx->location) + 1);
    strcpy(job_id, ctx->location);
    job_token = strchr(job_id, ':');
    *job_token ++ = '\0';

    /* Build RetrieveImageRequest */
    wsd_make_request_header(ctx, xml, WSD_ACTION_RETRIEVE_IMAGE);

    xml_wr_enter(xml, "soap:Body");
    xml_wr_enter(xml, "sca:RetrieveImageRequest");

    xml_wr_enter(xml, "sca:DocumentDescription");
    xml_wr_add_text(xml, "sca:DocumentName", "IMAGE000.JPG");
    xml_wr_leave(xml);

    xml_wr_add_text(xml, "sca:JobId", job_id);
    xml_wr_add_text(xml, "sca:JobToken", job_token);

    xml_wr_leave(xml);
    xml_wr_leave(xml);

    return wsd_http_post(ctx, xml_wr_finish_compact(xml));
}

/* Decode result of image request
 */
static proto_result
wsd_load_decode (const proto_ctx *ctx)
{
    proto_result result = {0};
    http_data    *data;

    /* Check HTTP status */
    if (wsd_fault_check(ctx)) {
        return wsd_fault_decode(ctx, true);
    }

    /* We expect multipart message with attached image */
    data = http_query_get_mp_response_data(ctx->query, 1);
    if (data == NULL) {
        result.next = PROTO_OP_CLEANUP;
        result.err = ERROR("RetrieveImageRequest: invalid response");
        return result;
    }

    if (ctx->params.src == ID_SOURCE_PLATEN) {
        result.next = PROTO_OP_FINISH;
    } else {
        result.next = PROTO_OP_LOAD;
    }

    result.data.image = http_data_ref(data);

    return result;
}

/* Request device status
 */
static http_query*
wsd_status_query (const proto_ctx *ctx)
{
    xml_wr *xml = xml_wr_begin("soap:Envelope", wsd_ns_wr);

    wsd_make_request_header(ctx, xml, WSD_ACTION_GET_SCANNER_ELEMENTS);

    xml_wr_enter(xml, "soap:Body");
    xml_wr_enter(xml, "sca:GetScannerElementsRequest");
    xml_wr_enter(xml, "sca:RequestedElements");
    xml_wr_add_text(xml, "sca:Name", "sca:ScannerStatus");
    xml_wr_leave(xml);
    xml_wr_leave(xml);
    xml_wr_leave(xml);

    return wsd_http_post(ctx, xml_wr_finish_compact(xml));
}

/* Decode result of device status request
 */
static proto_result
wsd_status_decode (const proto_ctx *ctx)
{
    proto_handler_wsd *wsd = (proto_handler_wsd*) ctx->proto;
    proto_result      result = {0};
    http_data         *data = http_query_get_response_data(ctx->query);
    xml_rd            *xml;
    char              scanner_state[64] = {0};
    bool              adf = ctx->params.src == ID_SOURCE_ADF_SIMPLEX ||
                            ctx->params.src == ID_SOURCE_ADF_DUPLEX;
    bool              retry = false;

    log_debug(ctx->log, "PROTO_OP_CHECK: fault code: %s", wsd->fault_code);

    /* Initialize result */
    result.next = PROTO_OP_FINISH;
    result.status = SANE_STATUS_GOOD;

    /* Look to the saved fault code. It it is specific enough, return
     * error immediately
     */
    if (adf) {
        if (!strcmp(wsd->fault_code, "ClientErrorNoImagesAvailable")) {
            result.status = SANE_STATUS_NO_DOCS;
            return result;
        }

        /* Ricoh Aficio MP 201 reports "ADF empty" status this strange way
         */
        if (!strcmp(wsd->fault_code, "ClientErrorJobIdNotFound")) {
            result.status = SANE_STATUS_NO_DOCS;
            return result;
        }
    }

    /* Parse XML */
    result.err = xml_rd_begin(&xml, data->bytes, data->size, wsd_ns_rd);
    if (result.err != NULL) {
        return result;
    }

    /* Roll over parsed XML, until fault reason is known */
    while (!xml_rd_end(xml) && result.status == SANE_STATUS_GOOD && !retry) {
        const char *path = xml_rd_node_path(xml);
        const char *val;

        if (!strcmp(path, "s:Envelope/s:Body/scan:GetScannerElementsResponse/"
                "scan:ScannerElements/scan:ElementData/scan:ScannerStatus/"
                "scan:ScannerState")) {

            val = xml_rd_node_value(xml);
            log_debug(ctx->log, "PROTO_OP_CHECK: ScannerState: %s", val);
            strncpy(scanner_state, val, sizeof(scanner_state) - 1);
        } else if (!strcmp(path, "s:Envelope/s:Body/scan:GetScannerElementsResponse/"
                "scan:ScannerElements/scan:ElementData/scan:ScannerStatus/"
                "scan:ScannerStateReasons/scan:ScannerStateReason")) {

            val = xml_rd_node_value(xml);
            log_debug(ctx->log, "PROTO_OP_CHECK: ScannerStateReason: %s", val);

            if (!strcmp(val, "AttentionRequired")) {
                result.status = SANE_STATUS_DEVICE_BUSY;
            } else if (!strcmp(val, "Calibrating")) {
                retry = true;
            } else if (!strcmp(val, "CoverOpen")) {
                result.status = SANE_STATUS_COVER_OPEN;
            } else if (!strcmp(val, "InterlockOpen")) {
                // Note, I have no idea what is interlock, but
                // let's assume it's a kind of cover...
                result.status = SANE_STATUS_COVER_OPEN;
            } else if (!strcmp(val, "InternalStorageFull")) {
                result.status = SANE_STATUS_NO_MEM;
            } else if (!strcmp(val, "LampError")) {
                result.status = SANE_STATUS_IO_ERROR;
            } else if (!strcmp(val, "LampWarming")) {
                retry = true;
            } else if (!strcmp(val, "MediaJam")) {
                result.status = SANE_STATUS_JAMMED;
            } else if (!strcmp(val, "MultipleFeedError")) {
                result.status = SANE_STATUS_JAMMED;
            }
        }

        xml_rd_deep_next(xml, 0);
    }

    xml_rd_finish(&xml);

    /* Retry? */
    if (retry && ctx->failed_attempt < WSD_CREATE_SCAN_JOB_RETRY_ATTEMPTS) {
        result.next = PROTO_OP_SCAN;
        result.delay = WSD_CREATE_SCAN_JOB_RETRY_PAUSE;
        return result;
    }

    /* Reason was found? */
    if (result.status != SANE_STATUS_GOOD) {
        return result;
    }

    /* ServerErrorNotAcceptingJobs? */
    if (!strcmp(wsd->fault_code, "ServerErrorNotAcceptingJobs")) {
        /* Assume device not accepted jobs because require some
         * manual action/reconfiguration. For example, Kyocera
         * in the WSD mode scans only WSD scan is requested from
         * the front panel, otherwise it returns this kind
         * of error
         */
        result.status = SANE_STATUS_DEVICE_BUSY;

        /* Canon MF410 Series reports ADF empty this way */
        if (adf && !strcmp(scanner_state, "Idle")) {
            result.status = SANE_STATUS_NO_DOCS;
        }
    }

    /* Still no idea? */
    if (result.status == SANE_STATUS_GOOD) {
        result.status = SANE_STATUS_IO_ERROR;
    }

    return result;
}

/* Cancel scan in progress
 */
static http_query*
wsd_cancel_query (const proto_ctx *ctx)
{
    xml_wr *xml = xml_wr_begin("soap:Envelope", wsd_ns_wr);
    char   *job_id, *job_token;

    /* Split location into JobId and JobToken */
    job_id = alloca(strlen(ctx->location) + 1);
    strcpy(job_id, ctx->location);
    job_token = strchr(job_id, ':');
    *job_token ++ = '\0';

    /* Build CancelJob Request */
    wsd_make_request_header(ctx, xml, WSD_ACTION_CANCEL_JOB);

    xml_wr_enter(xml, "soap:Body");
    xml_wr_enter(xml, "sca:CancelJobRequest");

    xml_wr_add_text(xml, "sca:JobId", job_id);

    xml_wr_leave(xml);
    xml_wr_leave(xml);

    return wsd_http_post(ctx, xml_wr_finish_compact(xml));
}

/* Test interface: decode device capabilities
 */
static error
wsd_test_decode_devcaps (proto_handler *proto,
                         const void *xml_text, size_t xms_size,
                         devcaps *caps)
{
    proto_handler_wsd *wsd = (proto_handler_wsd*) proto;

    return wsd_devcaps_parse(wsd, caps, xml_text, xms_size);
}

/* proto_handler_wsd_new creates new WSD protocol handler
 */
proto_handler*
proto_handler_wsd_new (void)
{
    proto_handler_wsd *wsd = mem_new(proto_handler_wsd, 1);

    wsd->proto.name = "WSD";
    wsd->proto.free = wsd_free;

    wsd->proto.devcaps_query = wsd_devcaps_query;
    wsd->proto.devcaps_decode = wsd_devcaps_decode;

    wsd->proto.precheck_query = wsd_precheck_query;
    wsd->proto.precheck_decode = wsd_precheck_decode;

    wsd->proto.scan_query = wsd_scan_query;
    wsd->proto.scan_decode = wsd_scan_decode;

    wsd->proto.load_query = wsd_load_query;
    wsd->proto.load_decode = wsd_load_decode;

    wsd->proto.status_query = wsd_status_query;
    wsd->proto.status_decode = wsd_status_decode;

    wsd->proto.cleanup_query = wsd_cancel_query;
    wsd->proto.cancel_query = wsd_cancel_query;

    wsd->proto.test_decode_devcaps = wsd_test_decode_devcaps;

    return &wsd->proto;
}

/* vim:ts=8:sw=4:et
 */
