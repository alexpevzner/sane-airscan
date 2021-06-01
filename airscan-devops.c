/* AirScan (a.k.a. eSCL) backend for SANE
 *
 * Copyright (C) 2019 and up by Alexander Pevzner (pzz@apevzner.com)
 * See LICENSE for license terms and conditions
 *
 * Device options
 */

#include "airscan.h"

#include <stdlib.h>
#include <string.h>

/* Static variables */
static const SANE_Range devopt_percent_range = {
    .min = SANE_FIX(-100.0),
    .max = SANE_FIX(100.0),
    .quant = SANE_FIX(1.0)
};

static const SANE_Range devopt_nonnegative_percent_range = {
    .min = SANE_FIX(0.0),
    .max = SANE_FIX(100.0),
    .quant = SANE_FIX(1.0)
};

static const SANE_Range devopt_gamma_range = {
    .min = SANE_FIX(0.1),
    .max = SANE_FIX(4.0),
};

/* Initialize device options
 */
void
devopt_init (devopt *opt)
{
    devcaps_init(&opt->caps);
    opt->src = ID_SOURCE_UNKNOWN;
    opt->colormode_emul = ID_COLORMODE_UNKNOWN;
    opt->colormode_real = ID_COLORMODE_UNKNOWN;
    opt->resolution = CONFIG_DEFAULT_RESOLUTION;
    opt->sane_sources = sane_string_array_new();
    opt->sane_colormodes = sane_string_array_new();
}

/* Cleanup device options
 */
void
devopt_cleanup (devopt *opt)
{
    sane_string_array_free(opt->sane_sources);
    sane_string_array_free(opt->sane_colormodes);
    devcaps_cleanup(&opt->caps);
}

/* Choose default source
 */
static ID_SOURCE
devopt_choose_default_source (devopt *opt)
{
    /* Choose initial source */
    ID_SOURCE id_src = (ID_SOURCE) 0;
    while (id_src < NUM_ID_SOURCE &&
            (opt->caps.src[id_src]) == NULL) {
        id_src ++;
    }

    log_assert(NULL, id_src != NUM_ID_SOURCE);
    return id_src;
}

/* Get available color modes
 */
static unsigned int
devopt_available_colormodes (const devcaps_source *src)
{
    unsigned int colormodes = src->colormodes;
    if ((colormodes & (1 << ID_COLORMODE_COLOR)) != 0) {
        colormodes |= 1 << ID_COLORMODE_GRAYSCALE; /* We can resample! */
    }
    return colormodes;
}

/* Chose "real" color mode that can be used for emulated color mode
 */
static ID_COLORMODE
devopt_real_colormode (ID_COLORMODE emulated, const devcaps_source *src)
{
    if ((src->colormodes & (1 << emulated)) != 0) {
        return emulated;
    }

    switch (emulated) {
    case ID_COLORMODE_GRAYSCALE:
        log_assert(NULL, (src->colormodes & (1 << ID_COLORMODE_COLOR)) != 0);
        return ID_COLORMODE_COLOR;

    default:
        log_internal_error(NULL);
    }

    return ID_COLORMODE_UNKNOWN;
}

/* Choose appropriate color mode
 */
static ID_COLORMODE
devopt_choose_colormode (devopt *opt, ID_COLORMODE wanted)
{
    devcaps_source *src = opt->caps.src[opt->src];
    unsigned int   colormodes = devopt_available_colormodes(src);

    /* Prefer wanted mode if possible and if not, try to find
     * a reasonable downgrade */
    if (wanted != ID_COLORMODE_UNKNOWN) {
        while (wanted < NUM_ID_COLORMODE) {
            if ((colormodes & (1 << wanted)) != 0) {
                return wanted;
            }
            wanted ++;
        }
    }

    /* Nothing found in a previous step. Just choose the best mode
     * supported by the scanner */
    wanted = (ID_COLORMODE) 0;
    while ((colormodes & (1 << wanted)) == 0) {
        log_assert(NULL, wanted < NUM_ID_COLORMODE);
        wanted ++;
    }

    return wanted;
}

/* Choose appropriate scanner resolution
 */
static SANE_Word
devopt_choose_resolution (devopt *opt, SANE_Word wanted)
{
    devcaps_source *src = opt->caps.src[opt->src];

    if (src->flags & DEVCAPS_SOURCE_RES_DISCRETE) {
        SANE_Word res = src->resolutions[1];
        SANE_Word delta = (SANE_Word) labs(wanted - res);
        size_t i, end = sane_word_array_len(src->resolutions) + 1;

        for (i = 2; i < end; i ++) {
            SANE_Word res2 = src->resolutions[i];
            SANE_Word delta2 = (SANE_Word) labs(wanted - res2);

            if (delta2 <= delta) {
                res = res2;
                delta = delta2;
            }
        }

        return res;
    } else {
        return math_range_fit(&src->res_range, wanted);
    }
}

/* Rebuild option descriptors
 */
static void
devopt_rebuild_opt_desc (devopt *opt)
{
    SANE_Option_Descriptor  *desc;
    devcaps_source          *src = opt->caps.src[opt->src];
    unsigned int            colormodes = devopt_available_colormodes(src);
    int                     i;
    const char              *s;

    memset(opt->desc, 0, sizeof(opt->desc));

    sane_string_array_reset(opt->sane_sources);
    sane_string_array_reset(opt->sane_colormodes);

    for (i = 0; i < NUM_ID_SOURCE; i ++) {
        if (opt->caps.src[i] != NULL) {
            opt->sane_sources = sane_string_array_append(
                opt->sane_sources, (SANE_String) id_source_sane_name(i));
        }
    }

    for (i = 0; i < NUM_ID_COLORMODE; i ++) {
        if ((colormodes & (1 << i)) != 0) {
            opt->sane_colormodes =
            sane_string_array_append(
                opt->sane_colormodes, (SANE_String) id_colormode_sane_name(i));
        }
    }

    /* OPT_NUM_OPTIONS */
    desc = &opt->desc[OPT_NUM_OPTIONS];
    desc->name = SANE_NAME_NUM_OPTIONS;
    desc->title = SANE_TITLE_NUM_OPTIONS;
    desc->desc = SANE_DESC_NUM_OPTIONS;
    desc->type = SANE_TYPE_INT;
    desc->size = sizeof(SANE_Word);
    desc->cap = SANE_CAP_SOFT_DETECT;

    /* OPT_GROUP_STANDARD */
    desc = &opt->desc[OPT_GROUP_STANDARD];
    desc->name = SANE_NAME_STANDARD;
    desc->title = SANE_TITLE_STANDARD;
    desc->desc = SANE_DESC_STANDARD;
    desc->type = SANE_TYPE_GROUP;
    desc->cap = 0;

    /* OPT_SCAN_RESOLUTION */
    desc = &opt->desc[OPT_SCAN_RESOLUTION];
    desc->name = SANE_NAME_SCAN_RESOLUTION;
    desc->title = SANE_TITLE_SCAN_RESOLUTION;
    desc->desc = SANE_DESC_SCAN_RESOLUTION;
    desc->type = SANE_TYPE_INT;
    desc->size = sizeof(SANE_Word);
    desc->cap = SANE_CAP_SOFT_SELECT | SANE_CAP_SOFT_DETECT;
    desc->unit = SANE_UNIT_DPI;
    if ((src->flags & DEVCAPS_SOURCE_RES_DISCRETE) != 0) {
        desc->constraint_type = SANE_CONSTRAINT_WORD_LIST;
        desc->constraint.word_list = src->resolutions;
    } else {
        desc->constraint_type = SANE_CONSTRAINT_RANGE;
        desc->constraint.range = &src->res_range;
    }

    /* OPT_SCAN_MODE */
    desc = &opt->desc[OPT_SCAN_COLORMODE];
    desc->name = SANE_NAME_SCAN_MODE;
    desc->title = SANE_TITLE_SCAN_MODE;
    desc->desc = SANE_DESC_SCAN_MODE;
    desc->type = SANE_TYPE_STRING;
    desc->size = sane_string_array_max_strlen(opt->sane_colormodes) + 1;
    desc->cap = SANE_CAP_SOFT_SELECT | SANE_CAP_SOFT_DETECT;
    desc->constraint_type = SANE_CONSTRAINT_STRING_LIST;
    desc->constraint.string_list = (SANE_String_Const*) opt->sane_colormodes;

    /* OPT_SCAN_SOURCE */
    desc = &opt->desc[OPT_SCAN_SOURCE];
    desc->name = SANE_NAME_SCAN_SOURCE;
    desc->title = SANE_TITLE_SCAN_SOURCE;
    desc->desc = SANE_DESC_SCAN_SOURCE;
    desc->type = SANE_TYPE_STRING;
    desc->size = sane_string_array_max_strlen(opt->sane_sources) + 1;
    desc->cap = SANE_CAP_SOFT_SELECT | SANE_CAP_SOFT_DETECT;
    desc->constraint_type = SANE_CONSTRAINT_STRING_LIST;
    desc->constraint.string_list = (SANE_String_Const*) opt->sane_sources;

    /* OPT_GROUP_GEOMETRY */
    desc = &opt->desc[OPT_GROUP_GEOMETRY];
    desc->name = SANE_NAME_GEOMETRY;
    desc->title = SANE_TITLE_GEOMETRY;
    desc->desc = SANE_DESC_GEOMETRY;
    desc->type = SANE_TYPE_GROUP;
    desc->cap = 0;

    /* OPT_SCAN_TL_X */
    desc = &opt->desc[OPT_SCAN_TL_X];
    desc->name = SANE_NAME_SCAN_TL_X;
    desc->title = SANE_TITLE_SCAN_TL_X;
    desc->desc = SANE_DESC_SCAN_TL_X;
    desc->type = SANE_TYPE_FIXED;
    desc->size = sizeof(SANE_Fixed);
    desc->cap = SANE_CAP_SOFT_SELECT | SANE_CAP_SOFT_DETECT;
    desc->unit = SANE_UNIT_MM;
    desc->constraint_type = SANE_CONSTRAINT_RANGE;
    desc->constraint.range = &src->win_x_range_mm;

    /* OPT_SCAN_TL_Y */
    desc = &opt->desc[OPT_SCAN_TL_Y];
    desc->name = SANE_NAME_SCAN_TL_Y;
    desc->title = SANE_TITLE_SCAN_TL_Y;
    desc->desc = SANE_DESC_SCAN_TL_Y;
    desc->type = SANE_TYPE_FIXED;
    desc->size = sizeof(SANE_Fixed);
    desc->cap = SANE_CAP_SOFT_SELECT | SANE_CAP_SOFT_DETECT;
    desc->unit = SANE_UNIT_MM;
    desc->constraint_type = SANE_CONSTRAINT_RANGE;
    desc->constraint.range = &src->win_y_range_mm;

    /* OPT_SCAN_BR_X */
    desc = &opt->desc[OPT_SCAN_BR_X];
    desc->name = SANE_NAME_SCAN_BR_X;
    desc->title = SANE_TITLE_SCAN_BR_X;
    desc->desc = SANE_DESC_SCAN_BR_X;
    desc->type = SANE_TYPE_FIXED;
    desc->size = sizeof(SANE_Fixed);
    desc->cap = SANE_CAP_SOFT_SELECT | SANE_CAP_SOFT_DETECT;
    desc->unit = SANE_UNIT_MM;
    desc->constraint_type = SANE_CONSTRAINT_RANGE;
    desc->constraint.range = &src->win_x_range_mm;

    /* OPT_SCAN_BR_Y */
    desc = &opt->desc[OPT_SCAN_BR_Y];
    desc->name = SANE_NAME_SCAN_BR_Y;
    desc->title = SANE_TITLE_SCAN_BR_Y;
    desc->desc = SANE_DESC_SCAN_BR_Y;
    desc->type = SANE_TYPE_FIXED;
    desc->size = sizeof(SANE_Fixed);
    desc->cap = SANE_CAP_SOFT_SELECT | SANE_CAP_SOFT_DETECT;
    desc->unit = SANE_UNIT_MM;
    desc->constraint_type = SANE_CONSTRAINT_RANGE;
    desc->constraint.range = &src->win_y_range_mm;

    /* OPT_GROUP_ENHANCEMENT */
    desc = &opt->desc[OPT_GROUP_ENHANCEMENT];
    desc->name = SANE_NAME_ENHANCEMENT;
    desc->title = SANE_TITLE_ENHANCEMENT;
    desc->desc = SANE_DESC_ENHANCEMENT;
    desc->type = SANE_TYPE_GROUP;
    desc->cap = 0;

    /* OPT_BRIGHTNESS */
    desc = &opt->desc[OPT_BRIGHTNESS];
    desc->name = SANE_NAME_BRIGHTNESS;
    desc->title = SANE_TITLE_BRIGHTNESS;
    desc->desc = SANE_DESC_BRIGHTNESS;
    desc->type = SANE_TYPE_FIXED;
    desc->size = sizeof(SANE_Fixed);
    desc->cap = SANE_CAP_SOFT_SELECT | SANE_CAP_SOFT_DETECT | SANE_CAP_EMULATED;
    desc->unit = SANE_UNIT_PERCENT;
    desc->constraint_type = SANE_CONSTRAINT_RANGE;
    desc->constraint.range = &devopt_percent_range;

    /* OPT_CONTRAST */
    desc = &opt->desc[OPT_CONTRAST];
    desc->name = SANE_NAME_CONTRAST;
    desc->title = SANE_TITLE_CONTRAST;
    desc->desc = SANE_DESC_CONTRAST;
    desc->type = SANE_TYPE_FIXED;
    desc->size = sizeof(SANE_Fixed);
    desc->cap = SANE_CAP_SOFT_SELECT | SANE_CAP_SOFT_DETECT | SANE_CAP_EMULATED;
    desc->unit = SANE_UNIT_PERCENT;
    desc->constraint_type = SANE_CONSTRAINT_RANGE;
    desc->constraint.range = &devopt_percent_range;

    /* OPT_SHADOW */
    desc = &opt->desc[OPT_SHADOW];
    desc->name = SANE_NAME_SHADOW;
    desc->title = SANE_TITLE_SHADOW;
    desc->desc = SANE_DESC_SHADOW;
    desc->type = SANE_TYPE_FIXED;
    desc->size = sizeof(SANE_Fixed);
    desc->cap = SANE_CAP_SOFT_SELECT | SANE_CAP_SOFT_DETECT | SANE_CAP_EMULATED;
    desc->unit = SANE_UNIT_PERCENT;
    desc->constraint_type = SANE_CONSTRAINT_RANGE;
    desc->constraint.range = &devopt_nonnegative_percent_range;

    /* OPT_HIGHLIGHT */
    desc = &opt->desc[OPT_HIGHLIGHT];
    desc->name = SANE_NAME_HIGHLIGHT;
    desc->title = SANE_TITLE_HIGHLIGHT;
    desc->desc = SANE_DESC_HIGHLIGHT;
    desc->type = SANE_TYPE_FIXED;
    desc->size = sizeof(SANE_Fixed);
    desc->cap = SANE_CAP_SOFT_SELECT | SANE_CAP_SOFT_DETECT | SANE_CAP_EMULATED;
    desc->unit = SANE_UNIT_PERCENT;
    desc->constraint_type = SANE_CONSTRAINT_RANGE;
    desc->constraint.range = &devopt_nonnegative_percent_range;

    /* OPT_GAMMA */
    desc = &opt->desc[OPT_GAMMA];
    desc->name = SANE_NAME_ANALOG_GAMMA;
    desc->title = SANE_TITLE_ANALOG_GAMMA;
    desc->desc = SANE_DESC_ANALOG_GAMMA;
    desc->type = SANE_TYPE_FIXED;
    desc->size = sizeof(SANE_Fixed);
    desc->cap = SANE_CAP_SOFT_SELECT | SANE_CAP_SOFT_DETECT | SANE_CAP_EMULATED;
    desc->unit = SANE_UNIT_NONE;
    desc->constraint_type = SANE_CONSTRAINT_RANGE;
    desc->constraint.range = &devopt_gamma_range;

    /* OPT_NEGATIVE */
    desc = &opt->desc[OPT_NEGATIVE];
    desc->name = SANE_NAME_NEGATIVE;
    desc->title = SANE_TITLE_NEGATIVE;
    desc->desc = SANE_DESC_NEGATIVE;
    desc->type = SANE_TYPE_BOOL;
    desc->size = sizeof(SANE_Bool);
    desc->cap = SANE_CAP_SOFT_SELECT | SANE_CAP_SOFT_DETECT | SANE_CAP_EMULATED;

    /* OPT_JUSTIFICATION_X */
    desc = &opt->desc[OPT_JUSTIFICATION_X];
    desc->name = SANE_NAME_ADF_JUSTIFICATION_X;
    desc->title = SANE_TITLE_ADF_JUSTIFICATION_X;
    desc->desc = SANE_DESC_ADF_JUSTIFICATION_X;
    desc->type = SANE_TYPE_STRING;
    desc->cap = SANE_CAP_SOFT_DETECT;
    if (opt->caps.justification_x == ID_JUSTIFICATION_UNKNOWN) {
        desc->cap |= SANE_CAP_INACTIVE;
    }

    s = id_justification_sane_name(opt->caps.justification_x);
    desc->size = (s ? strlen(s) : 0) + 1;

    /* OPT_JUSTIFICATION_Y */
    desc = &opt->desc[OPT_JUSTIFICATION_Y];
    desc->name = SANE_NAME_ADF_JUSTIFICATION_Y;
    desc->title = SANE_TITLE_ADF_JUSTIFICATION_Y;
    desc->desc = SANE_DESC_ADF_JUSTIFICATION_Y;
    desc->type = SANE_TYPE_STRING;
    desc->cap = SANE_CAP_SOFT_DETECT;
    if (opt->caps.justification_y == ID_JUSTIFICATION_UNKNOWN) {
        desc->cap |= SANE_CAP_INACTIVE;
    }

    s = id_justification_sane_name(opt->caps.justification_y);
    desc->size = (s ? strlen(s) : 0) + 1;
}

/* Update scan parameters, according to the currently set
 * scan options
 */
static void
devopt_update_params (devopt *opt)
{
    SANE_Fixed wid = math_max(0, opt->br_x - opt->tl_x);
    SANE_Fixed hei = math_max(0, opt->br_y - opt->tl_y);

    opt->params.last_frame = SANE_TRUE;
    opt->params.pixels_per_line = math_mm2px_res(wid, opt->resolution);
    opt->params.lines = math_mm2px_res(hei, opt->resolution);

    switch (opt->colormode_emul) {
    case ID_COLORMODE_COLOR:
        opt->params.format = SANE_FRAME_RGB;
        opt->params.depth = 8;
        opt->params.bytes_per_line = opt->params.pixels_per_line * 3;
        break;

    case ID_COLORMODE_GRAYSCALE:
        opt->params.format = SANE_FRAME_GRAY;
        opt->params.depth = 8;
        opt->params.bytes_per_line = opt->params.pixels_per_line;
        break;

    case ID_COLORMODE_BW1:
        opt->params.format = SANE_FRAME_GRAY;
        opt->params.depth = 1;
        opt->params.bytes_per_line =
                ((opt->params.pixels_per_line + 7) / 8) * 8;
        break;

    default:
        log_assert(NULL, !"internal error");
    }
}

/* Set current resolution
 */
static SANE_Status
devopt_set_resolution (devopt *opt, SANE_Word opt_resolution, SANE_Word *info)
{
    if (opt->resolution == opt_resolution) {
        return SANE_STATUS_GOOD;
    }

    opt->resolution = devopt_choose_resolution(opt, opt_resolution);

    *info |= SANE_INFO_RELOAD_PARAMS;
    if (opt->resolution != opt_resolution) {
        *info |= SANE_INFO_INEXACT;
    }

    return SANE_STATUS_GOOD;
}

/* Set color mode
 */
static SANE_Status
devopt_set_colormode (devopt *opt, ID_COLORMODE id_colormode, SANE_Word *info)
{
    devcaps_source *src = opt->caps.src[opt->src];
    unsigned int   colormodes = devopt_available_colormodes(src);

    if (opt->colormode_emul == id_colormode) {
        return SANE_STATUS_GOOD;
    }

    if ((colormodes & (1 << id_colormode)) == 0) {
        return SANE_STATUS_INVAL;
    }

    opt->colormode_emul = id_colormode;
    opt->colormode_real = devopt_real_colormode(id_colormode, src);

    *info |= SANE_INFO_RELOAD_PARAMS;

    return SANE_STATUS_GOOD;
}

/* Set current source. Affects many other options
 */
static SANE_Status
devopt_set_source (devopt *opt, ID_SOURCE id_src, SANE_Word *info)
{
    devcaps_source *src = opt->caps.src[id_src];

    if (src == NULL) {
        return SANE_STATUS_INVAL;
    }

    if (opt->src == id_src) {
        return SANE_STATUS_GOOD;
    }

    opt->src = id_src;

    /* Try to preserve current color mode */
    opt->colormode_emul = devopt_choose_colormode(opt, opt->colormode_emul);

    /* Try to preserve resolution */
    opt->resolution = devopt_choose_resolution(opt, opt->resolution);

    /* Reset window to maximum size */
    opt->tl_x = 0;
    opt->tl_y = 0;

    opt->br_x = src->win_x_range_mm.max;
    opt->br_y = src->win_y_range_mm.max;

    *info |= SANE_INFO_RELOAD_OPTIONS | SANE_INFO_RELOAD_PARAMS;

    return SANE_STATUS_GOOD;
}

/* Set geometry option
 */
static SANE_Status
devopt_set_geom (devopt *opt, SANE_Int option, SANE_Fixed val, SANE_Word *info)
{
    SANE_Fixed     *out = NULL;
    SANE_Range     *range = NULL;
    devcaps_source *src = opt->caps.src[opt->src];

    /* Choose destination and range */
    switch (option) {
    case OPT_SCAN_TL_X:
        out = &opt->tl_x;
        range = &src->win_x_range_mm;
        break;

    case OPT_SCAN_TL_Y:
        out = &opt->tl_y;
        range = &src->win_y_range_mm;
        break;

    case OPT_SCAN_BR_X:
        out = &opt->br_x;
        range = &src->win_x_range_mm;
        break;

    case OPT_SCAN_BR_Y:
        out = &opt->br_y;
        range = &src->win_y_range_mm;
        break;

    default:
        log_internal_error(NULL);
    }

    /* Update option */
    if (*out != val) {
        *out = math_range_fit(range, val);
        if (*out == val) {
            *info |= SANE_INFO_RELOAD_PARAMS;
        } else {
            *info |= SANE_INFO_RELOAD_PARAMS | SANE_INFO_INEXACT;
        }
    }

    return SANE_STATUS_GOOD;
}

/* Set enhancement option
 */
static SANE_Status
devopt_set_enh (devopt *opt, SANE_Int option, SANE_Fixed val, SANE_Word *info)
{
    SANE_Fixed *out = NULL;
    SANE_Range range = *opt->desc[option].constraint.range;
    SANE_Fixed val_adjusted;

    switch (option) {
    case OPT_BRIGHTNESS:
        out = &opt->brightness;
        break;

    case OPT_CONTRAST:
        out = &opt->contrast;
        break;

    case OPT_SHADOW:
        out = &opt->shadow;
        range.max = opt->highlight - range.quant;
        break;

    case OPT_HIGHLIGHT:
        out = &opt->highlight;
        range.min = opt->shadow + range.quant;
        break;

    case OPT_GAMMA:
        out = &opt->gamma;
        break;

    default:
        log_internal_error(NULL);
    }

    val_adjusted = math_range_fit(&range, val);
    if (val_adjusted != val) {
        *info |= SANE_INFO_INEXACT;
    }

    *out = val_adjusted;

    return SANE_STATUS_GOOD;
}

/* Set default option values. Before call to this function,
 * devopt.caps needs to be properly filled.
 */
void
devopt_set_defaults (devopt *opt)
{
    devcaps_source *src;

    opt->src = devopt_choose_default_source(opt);
    src = opt->caps.src[opt->src];

    opt->colormode_emul = devopt_choose_colormode(opt, ID_COLORMODE_UNKNOWN);
    opt->colormode_real = devopt_real_colormode(opt->colormode_emul, src);
    opt->resolution = devopt_choose_resolution(opt, CONFIG_DEFAULT_RESOLUTION);

    opt->tl_x = 0;
    opt->tl_y = 0;
    opt->br_x = src->win_x_range_mm.max;
    opt->br_y = src->win_y_range_mm.max;

    opt->brightness = SANE_FIX(0.0);
    opt->contrast = SANE_FIX(0.0);
    opt->shadow = SANE_FIX(0.0);
    opt->highlight = SANE_FIX(100.0);
    opt->gamma = SANE_FIX(1.0);

    devopt_rebuild_opt_desc(opt);
    devopt_update_params(opt);
}

/* Set device option
 */
SANE_Status
devopt_set_option (devopt *opt, SANE_Int option, void *value, SANE_Word *info)
{
    SANE_Status    status = SANE_STATUS_GOOD;
    ID_SOURCE      id_src;
    ID_COLORMODE   id_colormode;

    /* Simplify life of options handlers by ensuring info != NULL  */
    if (info == NULL) {
        static SANE_Word unused;
        info = &unused;
    }

    *info = 0;

    /* Switch by option */
    switch (option) {
    case OPT_SCAN_RESOLUTION:
        status = devopt_set_resolution(opt, *(SANE_Word*)value, info);
        break;

    case OPT_SCAN_COLORMODE:
        id_colormode = id_colormode_by_sane_name(value);
        if (id_colormode == ID_COLORMODE_UNKNOWN) {
            status = SANE_STATUS_INVAL;
        } else {
            status = devopt_set_colormode(opt, id_colormode, info);
        }
        break;

    case OPT_SCAN_SOURCE:
        id_src = id_source_by_sane_name(value);
        if (id_src == ID_SOURCE_UNKNOWN) {
            status = SANE_STATUS_INVAL;
        } else {
            status = devopt_set_source(opt, id_src, info);
        }
        break;

    case OPT_SCAN_TL_X:
    case OPT_SCAN_TL_Y:
    case OPT_SCAN_BR_X:
    case OPT_SCAN_BR_Y:
        status = devopt_set_geom(opt, option, *(SANE_Fixed*)value, info);
        break;

    case OPT_BRIGHTNESS:
    case OPT_CONTRAST:
    case OPT_SHADOW:
    case OPT_HIGHLIGHT:
    case OPT_GAMMA:
        status = devopt_set_enh(opt, option, *(SANE_Fixed*)value, info);
        break;

    case OPT_NEGATIVE:
        opt->negative = *(SANE_Bool*)value != 0;
        break;

    default:
        status = SANE_STATUS_INVAL;
    }

    /* Rebuild option descriptors and update scan parameters, if needed */
    if ((*info & SANE_INFO_RELOAD_OPTIONS) != 0) {
        devopt_rebuild_opt_desc(opt);
    }

    if ((*info & SANE_INFO_RELOAD_PARAMS) != 0) {
        devopt_update_params(opt);
    }

    return status;
}

/* Get device option
 */
SANE_Status
devopt_get_option (devopt *opt, SANE_Int option, void *value)
{
    SANE_Status status = SANE_STATUS_GOOD;
    const char  *s;

    switch (option) {
    case OPT_NUM_OPTIONS:
        *(SANE_Word*) value = NUM_OPTIONS;
        break;

    case OPT_SCAN_RESOLUTION:
        *(SANE_Word*) value = opt->resolution;
        break;

    case OPT_SCAN_COLORMODE:
        strcpy(value, id_colormode_sane_name(opt->colormode_emul));
        break;

    case OPT_SCAN_SOURCE:
        strcpy(value, id_source_sane_name(opt->src));
        break;

    case OPT_SCAN_TL_X:
        *(SANE_Fixed*) value = opt->tl_x;
        break;

    case OPT_SCAN_TL_Y:
        *(SANE_Fixed*) value = opt->tl_y;
        break;

    case OPT_SCAN_BR_X:
        *(SANE_Fixed*) value = opt->br_x;
        break;

    case OPT_SCAN_BR_Y:
        *(SANE_Fixed*) value = opt->br_y;
        break;

    case OPT_BRIGHTNESS:
        *(SANE_Fixed*) value = opt->brightness;
        break;

    case OPT_CONTRAST:
        *(SANE_Fixed*) value = opt->contrast;
        break;

    case OPT_SHADOW:
        *(SANE_Fixed*) value = opt->shadow;
        break;

    case OPT_HIGHLIGHT:
        *(SANE_Fixed*) value = opt->highlight;
        break;

    case OPT_GAMMA:
        *(SANE_Fixed*) value = opt->gamma;
        break;

    case OPT_NEGATIVE:
        *(SANE_Bool*)value = opt->negative;
        break;

    case OPT_JUSTIFICATION_X:
        s = id_justification_sane_name(opt->caps.justification_x);
        strcpy(value, s ? s : "");
        break;

    case OPT_JUSTIFICATION_Y:
        s = id_justification_sane_name(opt->caps.justification_y);
        strcpy(value, s ? s : "");
        break;

    default:
        status = SANE_STATUS_INVAL;
    }

    return status;
}

/* vim:ts=8:sw=4:et
 */
