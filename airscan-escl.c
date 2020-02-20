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

/* Free ESCL protocol handler
 */
static void
escl_free (proto_handler *proto)
{
    g_free(proto);
}

/* Reset protocol handler before the next operation
 */
static void
escl_reset (proto_handler *proto)
{
    g_free(proto);
}

/* Query and decode device capabilities
 */
static http_query*
escl_devcaps_query (const proto_ctx *ctx)
{
    (void) ctx;
    return NULL;
}

static error
escl_devcaps_decode (const proto_ctx *ctx, devcaps *caps)
{
    (void) ctx;
    (void) caps;
    return NULL;
}

/* Initiate scanning
 */
static http_query*
escl_scan_query (const proto_ctx *ctx)
{
    (void) ctx;
    return NULL;
}

/* Decode result of scan request
 */
static proto_result
escl_scan_decode (const proto_ctx *ctx)
{
    proto_result result = {0};

    (void) ctx;
    return result;
}

/* Initiate image downloading
 */
static http_query*
escl_image_query (const proto_ctx *ctx)
{
    (void) ctx;
    return NULL;
}

/* Decode result of image request
 */
static proto_result
escl_image_decode (const proto_ctx *ctx)
{
    proto_result result = {0};

    (void) ctx;
    return result;
}

/* Request device status
 */
static http_query*
escl_status_query (const proto_ctx *ctx)
{
    (void) ctx;
    return NULL;
}

/* Decode result of device status request
 */
static proto_result
escl_status_decode (const proto_ctx *ctx)
{
    proto_result result = {0};

    (void) ctx;
    return result;
}

/* Cancel scan in progress
 */
static http_query*
escl_cancel_query (const proto_ctx *ctx)
{
    (void) ctx;
    return NULL;
}

/* Decode result of cancel request
 */
static proto_result
escl_cancel_decode (const proto_ctx *ctx)
{
    proto_result result = {0};

    (void) ctx;
    return result;
}

/* proto_handler_escl_new creates new eSCL protocol handler
 */
proto_handler*
proto_handler_escl_new (void)
{
    proto_handler_escl *escl = g_new0(proto_handler_escl, 1);

    escl->proto.free = escl_free;
    escl->proto.reset = escl_reset;

    escl->proto.devcaps_query = escl_devcaps_query;
    escl->proto.devcaps_decode = escl_devcaps_decode;

    escl->proto.scan_query = escl_scan_query;
    escl->proto.scan_decode = escl_scan_decode;

    escl->proto.image_query = escl_image_query;
    escl->proto.image_decode = escl_image_decode;

    escl->proto.status_query = escl_status_query;
    escl->proto.status_decode = escl_status_decode;

    /* Note, for ESCL cancel and cleanup are the same */
    escl->proto.cleanup_query = escl_cancel_query;
    escl->proto.cleanup_decode = escl_cancel_decode;

    escl->proto.cancel_query = escl_cancel_query;
    escl->proto.cancel_decode = escl_cancel_decode;

    return &escl->proto;
}

/* vim:ts=8:sw=4:et
 */
