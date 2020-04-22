/* sane-airscan backend test
 *
 * Copyright (C) 2019 and up by Alexander Pevzner (pzz@apevzner.com)
 * See LICENSE for license terms and conditions
 */

#include <sane/sane.h>

#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include "airscan.h"

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
check (SANE_Status status, const char *operation)
{
    if (status != SANE_STATUS_GOOD) {
        printf("%s: %s\n", operation, sane_strstatus(status));
        if (handle != NULL) {
            sane_close(handle);
        }
        exit(1);
    }
}

#define TRY(func, args...)                                              \
    do{                                                                 \
        printf("%s: calling\n", #func);                                 \
        SANE_Status s = func(args);                                     \
        printf("%s: done, status=%s\n", #func, sane_strstatus(s));      \
        check(s, #func);                                                \
    } while(0)

void
scan_test (void)
{
    SANE_Status s;
    SANE_Byte   buf[65536];
    int         len, count = 0;

    TRY(sane_start,handle);
    //sane_cancel (handle);

    for (;;) {
        s = sane_read(handle, buf, sizeof(buf), &len);
        if (s != SANE_STATUS_GOOD) {
            break;
        }

        count += len;
    }
    if (count != 0) {
        printf("%d bytes of data received\n", count);
    }

    //sane_cancel (handle);
}

int
main (void)
{
    SANE_Parameters params;

    struct sigaction act = {
        .sa_handler = sigint_handler,
    };

    sigaction(SIGINT, &act, NULL);

    TRY(sane_init, NULL, NULL);
    TRY(sane_open, "", &handle);
    //TRY(sane_control_option, handle, OPT_SCAN_SOURCE, SANE_ACTION_SET_VALUE, OPTVAL_SOURCE_ADF_SIMPLEX, NULL);
    TRY(sane_get_parameters, handle, &params);
    printf("image size: %dx%d\n", params.pixels_per_line, params.lines);

    scan_test();
//    scan_test();

    sane_close(handle);

    //getchar();

    sane_exit();

    return 0;
}

/* vim:ts=8:sw=4:et
 */
