/* AirScan (a.k.a. eSCL) backend for SANE
 *
 * Copyright (C) 2019 and up by Alexander Pevzner (pzz@apevzner.com)
 * See LICENSE for license terms and conditions
 *
 * Routines for SANE options handling
 */

#include "airscan.h"

#include <string.h>

/******************** Generic functions for IDs ********************/
/* Name/value mapping entry
 */
typedef struct {
    int        id;
    const char *name;
} id_name_table;

/* Get name by ID. For unknown ID returns NULL
 */
static const char*
id_name (int id, const id_name_table *table)
{
    int i;

    for (i = 0; table[i].name != NULL; i ++) {
        if (table[i].id == id) {
            return table[i].name;
        }
    }

    return NULL;
}

/* Get ID by name. For unknown name returns -1
 */
static int
id_by_name (const char *name, int (*cmp) (const char *s1, const char *s2),
        const id_name_table *table)
{
    int i;

    for (i = 0; table[i].name != NULL; i ++) {
        if (!cmp(name, table[i].name)) {
            return table[i].id;
        }
    }

    return -1;
}

/******************** ID_PROTO ********************/
/* id_proto_name_table table represents name mapping for ID_PROTO
 */
static id_name_table id_proto_name_table[] = {
    {ID_PROTO_ESCL, "eSCL"},
    {ID_PROTO_WSD,  "WSD"},
    {-1, NULL}
};

/* id_proto_name returns protocol name
 * For unknown ID returns NULL
 */
const char*
id_proto_name (ID_PROTO proto)
{
    return id_name(proto, id_proto_name_table);
}

/* id_proto_by_name returns protocol identifier by name
 * For unknown name returns ID_PROTO_UNKNOWN
 */
ID_PROTO
id_proto_by_name (const char* name)
{
    return id_by_name(name, strcasecmp, id_proto_name_table);
}

/******************** ID_SOURCE ********************/
/* id_source_sane_name_table represents ID_SOURCE to
 * SANE name mapping
 */
static id_name_table id_source_sane_name_table[] = {
    {ID_SOURCE_PLATEN,      OPTVAL_SOURCE_PLATEN},
    {ID_SOURCE_ADF_SIMPLEX, OPTVAL_SOURCE_ADF_SIMPLEX},
    {ID_SOURCE_ADF_DUPLEX,  OPTVAL_SOURCE_ADF_DUPLEX},
    {-1, NULL}
};

/* id_source_sane_name returns SANE name for the source
 * For unknown ID returns NULL
 */
const char*
id_source_sane_name (ID_SOURCE id)
{
    return id_name(id, id_source_sane_name_table);
}

/* id_source_by_sane_name returns ID_SOURCE by its SANE name
 * For unknown name returns ID_SOURCE_UNKNOWN
 */
ID_SOURCE
id_source_by_sane_name (const char *name)
{
    return id_by_name(name, strcmp, id_source_sane_name_table);
}

/******************** ID_COLORMODE ********************/
/* id_colormode_sane_name_table represents ID_COLORMODE to
 * SANE name mapping
 */
static id_name_table id_colormode_sane_name_table[] = {
    {ID_COLORMODE_BW1,       SANE_VALUE_SCAN_MODE_HALFTONE},
    {ID_COLORMODE_GRAYSCALE, SANE_VALUE_SCAN_MODE_GRAY},
    {ID_COLORMODE_COLOR,     SANE_VALUE_SCAN_MODE_COLOR},
    {-1, NULL}
};

/* id_colormode_sane_name returns SANE name for the color mode
 * For unknown ID returns NULL
 */
const char*
id_colormode_sane_name (ID_COLORMODE id)
{
    return id_name(id, id_colormode_sane_name_table);
}

/* id_colormode_by_sane_name returns ID_COLORMODE nu its SANE name
 * For unknown name returns ID_COLORMODE_UNKNOWN
 */
ID_COLORMODE
id_colormode_by_sane_name (const char *name)
{
    return id_by_name(name, strcmp, id_colormode_sane_name_table);
}

/******************** ID_FORMAT ********************/
/* id_format_mime_name_table represents ID_FORMAT to
 * MIME name mapping
 */
static id_name_table id_format_mime_name_table[] = {
    {ID_FORMAT_JPEG, "image/jpeg"},
    {ID_FORMAT_TIFF, "image/tiff"},
    {ID_FORMAT_PNG,  "image/png"},
    {ID_FORMAT_PDF,  "application/pdf"},
    {ID_FORMAT_DIB,  "application/dib"},
    {-1, NULL}
};

/* id_format_mime_name returns MIME name for the image format
 */
const char*
id_format_mime_name (ID_FORMAT id)
{
    return id_name(id, id_format_mime_name_table);
}

/* id_format_by_mime_name returns ID_FORMAT by its MIME name
 * For unknown name returns ID_FORMAT_UNKNOWN
 */
ID_FORMAT
id_format_by_mime_name (const char *name)
{
    return id_by_name(name, strcasecmp, id_format_mime_name_table);
}

/* if_format_short_name returns short name for ID_FORMAT
 */
const char*
id_format_short_name (ID_FORMAT id)
{
    const char *mime = id_format_mime_name(id);
    const char *name = mime ? (strchr(mime, '/') + 1) : NULL;

    return name ? name : mime;
}

/* vim:ts=8:sw=4:et
 */
