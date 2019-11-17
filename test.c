/* sane-airscan backend test
 *
 * Copyright (C) 2019 and up by Alexander Pevzner (pzz@apevzner.com)
 * See LICENSE for license terms and conditions
 */

#include <sane/sane.h>

#include <signal.h>
#include <stdio.h>
#include <stdbool.h>

SANE_Handle handle;

void
sigint_handler (int unused)
{
    (void) unused;
    if (handle != NULL) {
        sane_cancel (handle);
    }
}

void
main (int argc, char **argv)
{
    (void) argc;
    (void) argv;

    struct sigaction act = {
        .sa_handler = sigint_handler,
    };

    sigaction(SIGINT, &act, NULL);

    sane_init(NULL, NULL);
    sane_open(NULL, &handle);
    if (handle) {
        sane_start(handle);
    }

    while (getchar() != '\n')
        ;

    sane_exit();
}

/* vim:ts=8:sw=4:et
 */
