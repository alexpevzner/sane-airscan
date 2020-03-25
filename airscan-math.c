/* AirScan (a.k.a. eSCL) backend for SANE
 *
 * Copyright (C) 2019 and up by Alexander Pevzner (pzz@apevzner.com)
 * See LICENSE for license terms and conditions
 *
 * Miscellaneous mathematical functions
 */

#include "airscan.h"

#include <sys/random.h>

#pragma GCC diagnostic ignored "-Wunused-result"

/* Find greatest common divisor of two positive integers
 */
SANE_Word
math_gcd (SANE_Word x, SANE_Word y)
{
    log_assert(NULL, x > 0 && y > 0);

    while (x != y) {
        if (x > y) {
            x -= y;
        } else {
            y -= x;
        }
    }

    return x;
}

/* Find least common multiple of two positive integers
 */
SANE_Word
math_lcm (SANE_Word x, SANE_Word y)
{
    return (x * y) / math_gcd(x, y);
}

/* Check two ranges for equivalency
 */
static inline bool
math_range_eq (const SANE_Range *r1, const SANE_Range *r2)
{
    return r1->min == r2->min && r1->max == r2->max && r1->quant == r2->quant;
}

/* Check two ranges for overlapping
 */
static inline bool
math_range_ovp (const SANE_Range *r1, const SANE_Range *r2)
{
    return r1->max >= r2->min && r2->max >= r1->min;
}

/* Merge two ranges, if possible
 */
bool
math_range_merge (SANE_Range *out, const SANE_Range *r1, const SANE_Range *r2)
{
    /* Check for trivial cases */
    if (math_range_eq(r1, r2)) {
        *out = *r1;
        return true;
    }

    if (!math_range_ovp(r1, r2)) {
        return false;
    }

    /* Ranges have equal quantization? If yes, just adjust min and max */
    if (r1->quant == r2->quant) {
        out->min = math_max(r1->min, r2->min);
        out->max = math_min(r1->max, r2->max);
        out->quant = r1->quant;
        return true;
    }

    /* At least one of ranges don't have quantization? */
    if (!r1->quant || !r2->quant) {
        /* To avoid code duplication, normalize things, so
         * r1 does have quantization and r2 doesn't. Note,
         * situation when both ranges don't have quantization
         * was covered before, when we checked for equal quantization
         */
        if (r1->quant == 0) {
            const SANE_Range *tmp = r1;
            r1 = r2;
            r2 = tmp;
        }

        /* And fit r2 within r1 */
        out->min = math_range_fit(r1, r2->min);
        out->max = math_range_fit(r1, r2->max);
        out->quant = r1->quant;
        return true;
    }

    /* Now the most difficult case */
    SANE_Word quant = math_lcm(r1->quant, r2->quant);
    SANE_Word min, max, bounds_min, bounds_max;

    min = math_min(r1->min, r2->min);
    bounds_min = math_max(r1->min, r2->min);
    bounds_max = math_min(r1->max, r2->max);

    for (min = math_min(r1->min, r2->min); min < bounds_min; min += quant)
        ;

    if (min > bounds_max) {
        return false;
    }

    for (max = min; max + quant <= bounds_max; max += quant)
        ;

    out->min = min;
    out->max = max;
    out->quant = quant;

    return true;
}

/* Choose nearest integer in range
 */
SANE_Word
math_range_fit(const SANE_Range *r, SANE_Word i)
{
    if (i < r->min) {
        return r->min;
    }

    if (i > r->max) {
        return r->max;
    }

    if (r->quant == 0) {
        return i;
    }

    i -= r->min;
    i = ((i + r->quant / 2) / r->quant) * r->quant;
    i += r->min;

    return math_min(i, r->max);
}

/* Format millimeters, for printing
 */
char*
math_fmt_mm (SANE_Word mm, char buf[])
{
    double mmd = SANE_UNFIX(mm);
    double integer, fraction;

    integer = floor(mmd);
    fraction = mmd - integer;

    if (fraction != 0) {
        sprintf(buf, "%d.%2.2d", (int) integer, (int) round(fraction * 100));
    } else {
        sprintf(buf, "%d", (int) integer);
    }

    return buf;
}

/* Genrate random 32-bit integer
 */
uint32_t
math_rand_u32 (void)
{
    uint32_t r;
    getrandom(&r, sizeof(r), 0);
    return r;
}

/* Generate random integer in range [0...max], inclusively
 */
uint32_t
math_rand_max (uint32_t max)
{
    uint32_t mask, tmp;

    for (mask = 0, tmp = max; tmp != 0; tmp >>= 1) {
        mask |= tmp;
    }

    do {
        tmp = math_rand_u32() & mask;
    } while (tmp > max);

    return tmp;
}

/* Generate random integer in range [min...max], inclusively
 */
uint32_t
math_rand_range (uint32_t min, uint32_t max)
{
    /* Normalize range */
    if (min == max) {
        return min;
    }

    if (min > max) {
        uint32_t tmp = max;
        max = min;
        min = tmp;
    }

    /* Generate random number */
    return min + math_rand_max(max - min);
}

/* vim:ts=8:sw=4:et
 */
