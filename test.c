/* sane-airscan backend test
 *
 * Copyright (C) 2019 and up by Alexander Pevzner (pzz@apevzner.com)
 * See LICENSE for license terms and conditions
 */

#include <sane/sane.h>

#include <stdio.h>

void
main (int argc, char **argv)
{
    (void) argc;
    (void) argv;

    sane_init(NULL, NULL);
    SANE_Handle handle = NULL;
    sane_open(NULL, &handle);
    if (handle) {
        sane_start(handle);
    }
    getchar();
    sane_exit();
}

/* vim:ts=8:sw=4:et
 */
