/* AirScan (a.k.a. eSCL) backend for SANE
 *
 * Copyright (C) 2019 and up by Alexander Pevzner (pzz@apevzner.com)
 * See LICENSE for license terms and conditions
 *
 * ESCL protocol handler
 */

#include "airscan.h"

/* Protocol constants */
#define WSD_ADDR_ANONYMOUS   \
        "http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous"

#define WSD_ACTION_GET_SCANNER_ELEMENTS \
        "http://schemas.microsoft.com/windows/2006/08/wdp/scan/GetScannerElements"

#if     0
/* XML namespace translation for XML reader
 */
static const xml_ns wsd_ns_rd[] = {
    {"s", "http*://schemas.xmlsoap.org/soap/envelope"}, /* SOAP 1.1 */
    {"s", "http*://www.w3.org/2003/05/soap-envelope"},  /* SOAP 1.2 */
    {"d", "http*://schemas.xmlsoap.org/ws/2005/04/discovery"},
    {"a", "http*://schemas.xmlsoap.org/ws/2004/08/addressing"},
    {NULL, NULL}
};
#endif

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
    xml_wr_add_text(xml, "scan:Name", "scan:ScannerStatus");
    xml_wr_leave(xml);
    xml_wr_leave(xml);
    xml_wr_leave(xml);

    return wsd_http_post(ctx, xml_wr_finish(xml));
}

/* Decode device capabilities
 */
static error
wsd_devcaps_decode (const proto_ctx *ctx, devcaps *caps)
{
    (void) ctx;
    (void) caps;
    return ERROR("not implemented");
}

/* Initiate scanning
 */
static http_query*
wsd_scan_query (const proto_ctx *ctx)
{
    (void) ctx;
    return NULL;
}

/* Decode result of scan request
 */
static proto_result
wsd_scan_decode (const proto_ctx *ctx)
{
    proto_result result = {0};

    (void) ctx;
    return result;
}

/* Initiate image downloading
 */
static http_query*
wsd_load_query (const proto_ctx *ctx)
{
    (void) ctx;
    return NULL;
}

/* Decode result of image request
 */
static proto_result
wsd_load_decode (const proto_ctx *ctx)
{
    proto_result result = {0};

    (void) ctx;
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
    (void) ctx;
    return NULL;
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
