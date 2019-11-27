/* AirScan (a.k.a. eSCL) backend for SANE
 *
 * Copyright (C) 2019 and up by Alexander Pevzner (pzz@apevzner.com)
 * See LICENSE for license terms and conditions
 *
 * Device options
 */

#include "airscan.h"

/* Initialize device options
 */
void
devopt_init (devopt *opt)
{
    devcaps_init(&opt->caps);
    opt->src = OPT_SOURCE_UNKNOWN;
    opt->colormode = OPT_COLORMODE_UNKNOWN;
    opt->resolution = CONFIG_DEFAULT_RESOLUTION;
}

/* Cleanup device options
 */
void
devopt_cleanup (devopt *opt)
{
    devcaps_cleanup(&opt->caps);
}

/* Choose default source
 */
static OPT_SOURCE
devopt_choose_default_source (devopt *opt)
{
    /* Choose initial source */
    OPT_SOURCE opt_src = (OPT_SOURCE) 0;
    while (opt_src < NUM_OPT_SOURCE &&
            (opt->caps.src[opt_src]) == NULL) {
        opt_src ++;
    }

    g_assert(opt_src != NUM_OPT_SOURCE);
    return opt_src;
}

/* Choose appropriate color mode
 */
static OPT_COLORMODE
devopt_choose_colormode(devopt *opt, OPT_COLORMODE wanted)
{
    devcaps_source *src = opt->caps.src[opt->src];

    /* Prefer wanted mode if possible and if not, try to find
     * a reasonable downgrade */
    if (wanted != OPT_COLORMODE_UNKNOWN) {
        while (wanted < NUM_OPT_COLORMODE) {
            if ((src->colormodes & (1 << wanted)) != 0) {
                return wanted;
            }
            wanted ++;
        }
    }

    /* Nothing found in a previous step. Just choose the best mode
     * supported by the scanner */
    wanted = (OPT_COLORMODE) 0;
    while ((src->colormodes & (1 << wanted)) == 0) {
        g_assert(wanted < NUM_OPT_COLORMODE);
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
        size_t i, end = array_of_word_len(&src->resolutions) + 1;

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
    SANE_Option_Descriptor *desc;
    devcaps_source         *src = opt->caps.src[opt->src];

    memset(opt->desc, 0, sizeof(opt->desc));

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
    desc->size = array_of_string_max_strlen(&src->sane_colormodes) + 1;
    desc->cap = SANE_CAP_SOFT_SELECT | SANE_CAP_SOFT_DETECT;
    desc->constraint_type = SANE_CONSTRAINT_STRING_LIST;
    desc->constraint.string_list = (SANE_String_Const*) src->sane_colormodes;

    /* OPT_SCAN_SOURCE */
    desc = &opt->desc[OPT_SCAN_SOURCE];
    desc->name = SANE_NAME_SCAN_SOURCE;
    desc->title = SANE_TITLE_SCAN_SOURCE;
    desc->desc = SANE_DESC_SCAN_SOURCE;
    desc->type = SANE_TYPE_STRING;
    desc->size = array_of_string_max_strlen(&opt->caps.sane_sources) + 1;
    desc->cap = SANE_CAP_SOFT_SELECT | SANE_CAP_SOFT_DETECT;
    desc->constraint_type = SANE_CONSTRAINT_STRING_LIST;
    desc->constraint.string_list = (SANE_String_Const*) opt->caps.sane_sources;

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
    desc->size = sizeof(SANE_Word);
    desc->cap = SANE_CAP_SOFT_SELECT | SANE_CAP_SOFT_DETECT;
    desc->unit = SANE_UNIT_MM;
    desc->constraint_type = SANE_CONSTRAINT_RANGE;
    desc->constraint.range = &src->win_x_range;

    /* OPT_SCAN_TL_Y */
    desc = &opt->desc[OPT_SCAN_TL_Y];
    desc->name = SANE_NAME_SCAN_TL_Y;
    desc->title = SANE_TITLE_SCAN_TL_Y;
    desc->desc = SANE_DESC_SCAN_TL_Y;
    desc->type = SANE_TYPE_FIXED;
    desc->size = sizeof(SANE_Word);
    desc->cap = SANE_CAP_SOFT_SELECT | SANE_CAP_SOFT_DETECT;
    desc->unit = SANE_UNIT_MM;
    desc->constraint_type = SANE_CONSTRAINT_RANGE;
    desc->constraint.range = &src->win_y_range;

    /* OPT_SCAN_BR_X */
    desc = &opt->desc[OPT_SCAN_BR_X];
    desc->name = SANE_NAME_SCAN_BR_X;
    desc->title = SANE_TITLE_SCAN_BR_X;
    desc->desc = SANE_DESC_SCAN_BR_X;
    desc->type = SANE_TYPE_FIXED;
    desc->size = sizeof(SANE_Word);
    desc->cap = SANE_CAP_SOFT_SELECT | SANE_CAP_SOFT_DETECT;
    desc->unit = SANE_UNIT_MM;
    desc->constraint_type = SANE_CONSTRAINT_RANGE;
    desc->constraint.range = &src->win_x_range;

    /* OPT_SCAN_BR_Y */
    desc = &opt->desc[OPT_SCAN_BR_Y];
    desc->name = SANE_NAME_SCAN_BR_Y;
    desc->title = SANE_TITLE_SCAN_BR_Y;
    desc->desc = SANE_DESC_SCAN_BR_Y;
    desc->type = SANE_TYPE_FIXED;
    desc->size = sizeof(SANE_Word);
    desc->cap = SANE_CAP_SOFT_SELECT | SANE_CAP_SOFT_DETECT;
    desc->unit = SANE_UNIT_MM;
    desc->constraint_type = SANE_CONSTRAINT_RANGE;
    desc->constraint.range = &src->win_y_range;
}

/* Update scan parameters, according to the currently set
 * scan options
 */
static void
devopt_update_params (devopt *opt)
{
    SANE_Word wid = math_max(0, opt->br_x - opt->tl_x);
    SANE_Word hei = math_max(0, opt->br_y - opt->tl_y);

    opt->params.last_frame = SANE_TRUE;
    opt->params.pixels_per_line = math_mm2px_res(wid, opt->resolution);
    opt->params.lines = math_mm2px_res(hei, opt->resolution);

    switch (opt->colormode) {
    case OPT_COLORMODE_COLOR:
        opt->params.format = SANE_FRAME_RGB;
        opt->params.depth = 8;
        opt->params.bytes_per_line = opt->params.pixels_per_line * 3;
        break;

    case OPT_COLORMODE_GRAYSCALE:
        opt->params.format = SANE_FRAME_GRAY;
        opt->params.depth = 8;
        opt->params.bytes_per_line = opt->params.pixels_per_line;
        break;

    case OPT_COLORMODE_LINEART:
        opt->params.format = SANE_FRAME_GRAY;
        opt->params.depth = 1;
        opt->params.bytes_per_line =
                ((opt->params.pixels_per_line + 7) / 8) * 8;
        break;

    default:
        g_assert(!"internal error");
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
devopt_set_colormode (devopt *opt, OPT_COLORMODE opt_colormode, SANE_Word *info)
{
    devcaps_source *src = opt->caps.src[opt->src];

    if (opt->colormode == opt_colormode) {
        return SANE_STATUS_GOOD;
    }

    if ((src->colormodes & (1 <<opt_colormode)) == 0) {
        return SANE_STATUS_INVAL;
    }

    opt->colormode = opt_colormode;
    *info |= SANE_INFO_RELOAD_PARAMS;

    return SANE_STATUS_GOOD;
}

/* Set current source. Affects many other options
 */
static SANE_Status
devopt_set_source (devopt *opt, OPT_SOURCE opt_src, SANE_Word *info)
{
    devcaps_source *src = opt->caps.src[opt_src];

    if (src == NULL) {
        return SANE_STATUS_INVAL;
    }

    if (opt->src == opt_src) {
        return SANE_STATUS_GOOD;
    }

    opt->src = opt_src;

    /* Try to preserve current color mode */
    opt->colormode = devopt_choose_colormode(opt, opt->colormode);

    /* Try to preserve resolution */
    opt->resolution = devopt_choose_resolution(opt, opt->resolution);

    /* Reset window to maximum size */
    opt->tl_x = 0;
    opt->tl_y = 0;

    opt->br_x = src->win_x_range.max;
    opt->br_y = src->win_y_range.max;

    *info |= SANE_INFO_RELOAD_OPTIONS | SANE_INFO_RELOAD_PARAMS;

    return SANE_STATUS_GOOD;
}

/* Set geometry option
 */
static SANE_Status
devopt_set_geom (devopt *opt, SANE_Int option, SANE_Word val, SANE_Word *info)
{
    SANE_Word      *out = NULL;
    SANE_Range     *range = NULL;
    devcaps_source *src = opt->caps.src[opt->src];

    /* Choose destination and range */
    switch (option) {
    case OPT_SCAN_TL_X:
        out = &opt->tl_x;
        range = &src->win_x_range;
        break;

    case OPT_SCAN_TL_Y:
        out = &opt->tl_y;
        range = &src->win_y_range;
        break;

    case OPT_SCAN_BR_X:
        out = &opt->br_x;
        range = &src->win_x_range;
        break;

    case OPT_SCAN_BR_Y:
        out = &opt->br_y;
        range = &src->win_y_range;
        break;

    default:
        g_assert_not_reached();
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

/* Parse device capabilities, and set default options values
 *
 * Returns NULL if OK, error string otherwise
 */
const char*
devopt_import_caps (devopt *opt, const char *xml_text, size_t xml_len)
{
    const char     *err;
    devcaps_source *src;

    err = devcaps_parse (&opt->caps, xml_text, xml_len);
    if (err != NULL) {
        return err;
    }

    opt->src = devopt_choose_default_source(opt);
    opt->colormode = devopt_choose_colormode(opt, OPT_COLORMODE_UNKNOWN);
    opt->resolution = devopt_choose_resolution(opt, CONFIG_DEFAULT_RESOLUTION);

    src = opt->caps.src[opt->src];
    opt->tl_x = 0;
    opt->tl_y = 0;
    opt->br_x = src->win_x_range.max;
    opt->br_y = src->win_y_range.max;

    devopt_rebuild_opt_desc(opt);
    devopt_update_params(opt);

    return NULL;
}

/* Set device option
 */
SANE_Status
devopt_set_option (devopt *opt, SANE_Int option, void *value, SANE_Word *info)
{
    SANE_Status    status = SANE_STATUS_GOOD;
    OPT_SOURCE     opt_src;
    OPT_COLORMODE  opt_colormode;

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
        opt_colormode = opt_colormode_from_sane(value);
        if (opt_colormode == OPT_COLORMODE_UNKNOWN) {
            status = SANE_STATUS_INVAL;
        } else {
            status = devopt_set_colormode(opt, opt_colormode, info);
        }
        break;

    case OPT_SCAN_SOURCE:
        opt_src = opt_source_from_sane(value);
        if (opt_src == OPT_SOURCE_UNKNOWN) {
            status = SANE_STATUS_INVAL;
        } else {
            status = devopt_set_source(opt, opt_src, info);
        }
        break;

    case OPT_SCAN_TL_X:
    case OPT_SCAN_TL_Y:
    case OPT_SCAN_BR_X:
    case OPT_SCAN_BR_Y:
        status = devopt_set_geom(opt, option, *(SANE_Word*)value, info);
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

    switch (option) {
    case OPT_NUM_OPTIONS:
        *(SANE_Word*) value = NUM_OPTIONS;
        break;

    case OPT_SCAN_RESOLUTION:
        *(SANE_Word*) value = opt->resolution;
        break;

    case OPT_SCAN_COLORMODE:
        strcpy(value, opt_colormode_to_sane(opt->colormode));
        break;

    case OPT_SCAN_SOURCE:
        strcpy(value, opt_source_to_sane(opt->src));
        break;

    case OPT_SCAN_TL_X:
        *(SANE_Word*) value = opt->tl_x;
        break;

    case OPT_SCAN_TL_Y:
        *(SANE_Word*) value = opt->tl_y;
        break;

    case OPT_SCAN_BR_X:
        *(SANE_Word*) value = opt->br_x;
        break;

    case OPT_SCAN_BR_Y:
        *(SANE_Word*) value = opt->br_y;
        break;

    default:
        status = SANE_STATUS_INVAL;
    }

    return status;
}

/* vim:ts=8:sw=4:et
 */
