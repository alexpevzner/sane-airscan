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
        exit(1);
    }
}

#define TRY(func, args...)              \
    do{                                 \
        SANE_Status s = func(args);     \
        check(s, #func);                \
    } while(0)

void
main (void)
{
    struct sigaction act = {
        .sa_handler = sigint_handler,
    };

    sigaction(SIGINT, &act, NULL);

    TRY(sane_init, NULL, NULL);
    TRY(sane_open, "", &handle);
    TRY(sane_start,handle);

    SANE_Status s;
    char        buf[65536];
    int         len, count = 0;

    for (;;) {
        s = sane_read(handle, buf, sizeof(buf), &len);
        if (s != SANE_STATUS_GOOD) {
            break;
        }

        printf("Got %d bytes of data\n", len);
        count += len;
    }

    getchar();

    sane_close(handle);
    sane_exit();
}

/* vim:ts=8:sw=4:et
 */
