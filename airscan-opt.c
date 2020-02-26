/* AirScan (a.k.a. eSCL) backend for SANE
 *
 * Copyright (C) 2019 and up by Alexander Pevzner (pzz@apevzner.com)
 * See LICENSE for license terms and conditions
 *
 * Routines for SANE options handling
 */

#include "airscan.h"

#include <string.h>

/* Name/value mapping entry
 */
typedef struct {
    SANE_String_Const name;
    SANE_Word         value;
} opt_name_map;

/* Decode SANE name string to numeric value
 */
static SANE_Word
opt_name_decode (const opt_name_map map[], size_t map_size,
        SANE_String_Const name)
{
    size_t i;
    for (i = 0; i < map_size; i ++) {
        if (!strcmp(map[i].name, name)) {
            return map[i].value;
        }
    }

    return -1;
}

/* Encode numeric value into SANE name string
 */
static SANE_String_Const
opt_name_encode (const opt_name_map map[], size_t map_size, SANE_Word value)
{
    size_t i;
    for (i = 0; i < map_size; i ++) {
        if (map[i].value == value) {
            return map[i].name;
        }
    }

    log_assert(NULL, !"internal error");

    return NULL;
}

/* Name map for OPT_SOURCE
 */
static opt_name_map
opt_source_name_map[] =
{
    { OPTVAL_SOURCE_PLATEN,      OPT_SOURCE_PLATEN },
    { OPTVAL_SOURCE_ADF_SIMPLEX, OPT_SOURCE_ADF_SIMPLEX },
    { OPTVAL_SOURCE_ADF_DUPLEX,  OPT_SOURCE_ADF_DUPLEX }
};

/* Decode OPT_SOURCE from SANE name
 */
OPT_SOURCE
opt_source_from_sane (SANE_String_Const name)
{
    return (OPT_SOURCE) opt_name_decode(
        opt_source_name_map, G_N_ELEMENTS(opt_source_name_map), name);
}

/* Get SANE name of OPT_SOURCE
 */
SANE_String_Const
opt_source_to_sane (OPT_SOURCE source)
{
    return opt_name_encode(opt_source_name_map,
        G_N_ELEMENTS(opt_source_name_map), (SANE_Word) source);
}

/* Name map for OPT_COLORMODE
 */
static opt_name_map
opt_colormode_name_map[] =
{
    { SANE_VALUE_SCAN_MODE_LINEART, OPT_COLORMODE_LINEART },
    { SANE_VALUE_SCAN_MODE_GRAY,    OPT_COLORMODE_GRAYSCALE },
    { SANE_VALUE_SCAN_MODE_COLOR,   OPT_COLORMODE_COLOR }
};

/* Decode OPT_COLORMODE from SANE name
 */
OPT_COLORMODE
opt_colormode_from_sane (SANE_String_Const name)
{
    return (OPT_COLORMODE) opt_name_decode(
        opt_colormode_name_map, G_N_ELEMENTS(opt_colormode_name_map), name);
}

/* Get SANE name of OPT_COLORMODE
 */
SANE_String_Const
opt_colormode_to_sane (OPT_COLORMODE mode)
{
    return opt_name_encode(opt_colormode_name_map,
        G_N_ELEMENTS(opt_colormode_name_map), (SANE_Word) mode);
}

/* Export set of colormodes (1 << OPT_COLORMODE) as sane
 * array of strings
 *
 * The result is appended to 'out' array -- it needs to
 * be initialized before call to this function
 */
void
opt_colormodes_to_sane (SANE_String **out, unsigned int colormodes)
{
    OPT_COLORMODE cm;
    for (cm = (OPT_COLORMODE) 0; cm < NUM_OPT_COLORMODE; cm ++) {
        if ((colormodes & (1 << cm)) != 0) {
            SANE_String s = (SANE_String) opt_colormode_to_sane(cm);
            sane_string_array_append(out, s);
        }
    }
}

/* vim:ts=8:sw=4:et
 */
