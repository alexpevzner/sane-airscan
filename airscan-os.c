/* AirScan (a.k.a. eSCL) backend for SANE
 *
 * Copyright (C) 2019 and up by Alexander Pevzner (pzz@apevzner.com)
 * See LICENSE for license terms and conditions
 *
 * OS Facilities
 */

#include "airscan.h"

#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <pwd.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/stat.h>

/* Static variables */
static pthread_once_t os_homedir_once = PTHREAD_ONCE_INIT;
static char os_homedir_buf[PATH_MAX];

/* Initialize os_homedir_buf. Called once, on demand
 */
static void
os_homedir_init (void)
{
    const char    *s = getenv("HOME");
    struct passwd pwd, *result;
    char          buf[16384];

    /* Try $HOME first, so user can override it's home directory */
    if (s != NULL && s[0] && strlen(s) < sizeof(os_homedir_buf)) {
        strcpy(os_homedir_buf, s);
        return;
    }

    /* Now try getpwuid_r */
    getpwuid_r(getuid(), &pwd, buf, sizeof(buf), &result);
    if (result == NULL) {
        return;
    }

    if (result->pw_dir[0] && strlen(result->pw_dir) < sizeof(os_homedir_buf)) {
        strcpy(os_homedir_buf, result->pw_dir);
    }
}

/* Get user's home directory. There is no need to
 * free the returned string
 *
 * May return NULL in a case of error
 */
const char *
os_homedir (void)
{
    pthread_once(&os_homedir_once, os_homedir_init);
    return os_homedir_buf[0] ? os_homedir_buf : NULL;
}

/* Make directory with parents
 */
int
os_mkdir (const char *path, mode_t mode)
{
    size_t len = strlen(path);
    char   *p = alloca(len + 1), *s;

    if (len == 0) {
        errno = EINVAL;
        return -1;
    }

    strcpy(p, path);

    for (s = strchr(p + 1, '/'); s != NULL; s = strchr(s + 1, '/')) {
        *s = '\0';
        mkdir(p, mode);
        *s = '/';
    }

    return mkdir(p, mode);
}

/* vim:ts=8:sw=4:et
 */
