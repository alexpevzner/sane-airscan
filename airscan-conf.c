/* AirScan (a.k.a. eSCL) backend for SANE
 *
 * Copyright (C) 2019 and up by Alexander Pevzner (pzz@apevzner.com)
 * See LICENSE for license terms and conditions
 *
 * Configuration file loader
 */

#include "airscan.h"

#include <dirent.h>
#include <stdlib.h>
#include <string.h>

/* Configuration data
 */
conf_data conf = CONF_INIT;
static conf_data conf_init = CONF_INIT;

/* Revert conf.devices list
 */
static void
conf_device_list_revert (void)
{
    conf_device *list = conf.devices, *prev = NULL, *next;

    while (list != NULL) {
        next = list->next;
        list->next = prev;
        prev = list;
        list = next;
    }

    conf.devices = prev;
}

/* Free conf.devices list
 */
static void
conf_device_list_free (void)
{
    conf_device *list = conf.devices, *next;

    conf.devices = NULL;

    while (list != NULL) {
        next = list->next;
        mem_free((char*) list->name);
        http_uri_free(list->uri);
        devid_free(list->devid);
        mem_free(list);
        list = next;
    }
}

/* Prepend device conf.devices list
 */
static void
conf_device_list_prepend (const char *name, http_uri *uri, ID_PROTO proto)
{
    conf_device *dev = mem_new(conf_device, 1);
    dev->name = str_dup(name);
    dev->devid = devid_alloc();
    dev->proto = proto;
    dev->uri = uri;
    dev->next = conf.devices;
    conf.devices = dev;
}

/* Find device in conf.devices list
 */
static conf_device*
conf_device_list_lookup (const char *name) {
    conf_device *dev = conf.devices;
    while (dev != NULL && strcmp(dev->name, name)) {
        dev = dev->next;
    }
    return dev;
}

/* Expand path name. The returned string must be eventually
 * released with mem_free()
 */
static const char*
conf_expand_path (const char *path)
{
    const char *prefix = "";
    char       *ret;

    if (path[0] == '~' && (path[1] == '\0' || path[1] == '/')) {
        const char *home = os_homedir();
        if (home != NULL) {
            prefix = home;
            path ++;
        } else {
            return NULL;
        }
    }

    ret = str_concat(prefix, path, NULL);
    ret = str_terminate(ret, '/');

    return ret;
}

/* Report configuration file error
 */
static void
conf_perror (const inifile_record *rec, const char *format, ...)
{
    char    buf[1024];
    va_list ap;

    va_start(ap, format);
    vsnprintf(buf, sizeof(buf), format, ap);
    va_end(ap);

    log_debug(NULL, "%s:%d: %s", rec->file, rec->line, buf);
}

/* Decode a device configuration
 */
static void
conf_decode_device (const inifile_record *rec) {
    http_uri   *uri = NULL;
    ID_PROTO   proto = ID_PROTO_ESCL;
    const char *uri_name = rec->tokc > 0 ? rec->tokv[0] : NULL;
    const char *proto_name = rec->tokc > 1 ? rec->tokv[1] : NULL;

    if (conf_device_list_lookup(rec->variable) != NULL) {
        conf_perror(rec, "device already defined");
    } else if (!strcmp(rec->value, CONF_DEVICE_DISABLE)) {
        conf_device_list_prepend(rec->variable, NULL, ID_PROTO_UNKNOWN);
    } else if (rec->tokc != 1 && rec->tokc != 2) {
        conf_perror(rec, "usage: \"device name\" = URL[,protocol]");
    } else if ((uri = http_uri_new(uri_name, true)) == NULL) {
        conf_perror(rec, "invalid URL");
    } else if (proto_name != NULL&&
               (proto = id_proto_by_name(proto_name)) == ID_PROTO_UNKNOWN) {
        conf_perror(rec, "protocol must be \"escl\" or \"wsd\"");
    }

    if (uri != NULL && proto != ID_PROTO_UNKNOWN) {
        conf_device_list_prepend(rec->variable, uri, proto);
    } else {
        http_uri_free(uri);
    }
}

/* Parse binary option
 */
static void
conf_load_bool (const inifile_record *rec, bool *out,
        const char *n_true, const char *n_false)
{
    if (inifile_match_name(rec->value, n_true)) {
        *out = true;
    } else if (inifile_match_name(rec->value, n_false)) {
        *out = false;
    } else {
        conf_perror(rec, "usage: %s = %s | %s", rec->variable, n_true, n_false);
    }
}

/* Load configuration from opened inifile
 */
static void
conf_load_from_ini (inifile *ini)
{
    const inifile_record *rec;
    while ((rec = inifile_read(ini)) != NULL) {
        switch (rec->type) {
        case INIFILE_SYNTAX:
            conf_perror(rec, "syntax error");
            break;

        case INIFILE_VARIABLE:
            if (inifile_match_name(rec->section, "devices")) {
                conf_decode_device(rec);
            } else if (inifile_match_name(rec->section, "options")) {
                if (inifile_match_name(rec->variable, "discovery")) {
                    conf_load_bool(rec, &conf.discovery, "enable", "disable");
                } else if (inifile_match_name(rec->variable, "model")) {
                    conf_load_bool(rec, &conf.model_is_netname,
                        "network", "hardware");
                } else if (inifile_match_name(rec->variable, "protocol")) {
                    conf_load_bool(rec, &conf.proto_auto, "auto", "manual");
                } else if (inifile_match_name(rec->variable, "ws-discovery")) {
                    if (inifile_match_name(rec->value, "fast")) {
                        conf.wsdd_mode = WSDD_FAST;
                    } else if (inifile_match_name(rec->value, "full")) {
                        conf.wsdd_mode = WSDD_FULL;
                    } else if (inifile_match_name(rec->value, "off")) {
                        conf.wsdd_mode = WSDD_OFF;
                    } else {
                        conf_perror(rec, "usage: %s = fast | full | off",
                            rec->variable);
                    }
                } else if (inifile_match_name(rec->variable, "socket_dir")) {
                    mem_free((char*) conf.socket_dir);
                    conf.socket_dir = conf_expand_path(rec->value);
                    if (conf.socket_dir == NULL) {
                        conf_perror(rec, "failed to expand socket_dir path");
                    }
                }
            } else if (inifile_match_name(rec->section, "debug")) {
                if (inifile_match_name(rec->variable, "trace")) {
                    mem_free((char*) conf.dbg_trace);
                    conf.dbg_trace = conf_expand_path(rec->value);
                    if (conf.dbg_trace == NULL) {
                        conf_perror(rec, "failed to expand path");
                    }
                } else if (inifile_match_name(rec->variable, "enable")) {
                    conf_load_bool(rec, &conf.dbg_enabled, "true", "false");
                }
            }
            break;

        default:
            break;
        }
    }

    /* Trace implies console log
     */
    if (conf.dbg_trace != NULL) {
        conf.dbg_enabled = true;
    }
}

/* Load configuration from the particular file
 */
static void
conf_load_from_file (const char *name)
{
    log_debug(NULL, "loading configuration file %s", name);

    inifile *ini = inifile_open(name);
    if (ini != NULL) {
        conf_load_from_ini(ini);
        inifile_close(ini);
    }
}

/* Load configuration from the specified directory
 *
 * This function uses its path parameter as its temporary
 * buffer and doesn't guarantee to preserve its content
 *
 * The `path' can be reallocated by this function; old
 * value is consumed and new is returned
 */
static char*
conf_load_from_dir (char *path)
{
    path = str_terminate(path, '/');

    /* Load from CONFIG_AIRSCAN_CONF file */
    size_t len = mem_len(path);
    path = str_append(path, CONFIG_AIRSCAN_CONF);
    conf_load_from_file(path);

    /* Scan CONFIG_AIRSCAN_D directory */
    path = str_resize(path, len);
    path = str_append(path, CONFIG_AIRSCAN_D);
    path = str_terminate(path, '/');
    len = mem_len(path);

    DIR *dir = opendir(path);
    if (dir) {
        struct dirent *ent;
        while ((ent = readdir(dir)) != NULL) {
            path = str_resize(path, len);
            path = str_append(path, ent->d_name);
            conf_load_from_file(path);
        }

        closedir(dir);
    }

    return path;
}

/* Load configuration from environment
 */
static void
conf_load_from_env (void)
{
    const char *env;

    env = getenv(CONFIG_ENV_AIRSCAN_DEBUG);
    if (env != NULL) {
        if (inifile_match_name(env, "true")) {
            conf.dbg_enabled = true;
        } else if (inifile_match_name(env, "false")) {
            conf.dbg_enabled = false;
        } else {
            unsigned long v;
            char *end;

            v = strtoul(env, &end, 0);
            if (env != end && *end == '\0') {
                conf.dbg_enabled = v != 0;
            } else {
                log_debug(NULL, "usage: %s=true|false",
                        CONFIG_ENV_AIRSCAN_DEBUG);
            }
        }
    }
}

/* Load configuration. Returns non-NULL (default configuration)
 * even if configuration file cannot be loaded
 */
void
conf_load (void)
{
    char    *dir_list = str_new();
    char    *path = str_new();
    char    *s;

    /* Reset the configuration */
    conf = conf_init;
    conf.socket_dir = str_dup(CONFIG_DEFAULT_SOCKET_DIR);

    /* Look to configuration path in environment */
    s = getenv(CONFIG_PATH_ENV);
    if (s != NULL) {
        dir_list = str_assign(dir_list, s);
    }

    /* Append default directories */
    dir_list = str_terminate(dir_list, ':');
    dir_list = str_append(dir_list, CONFIG_SANE_CONFIG_DIR);

    /* Iterate over the dir_list */
    for (s = dir_list; ; s ++) {
        if (*s == ':' || *s == '\0') {
            path = conf_load_from_dir(path);
            str_trunc(path);
        } else {
            path = str_append_c(path, *s);
        }

        if (*s == '\0') {
            break;
        }
    }

    /* Load configuration from environment */
    conf_load_from_env();

    /* Cleanup and exit */
    conf_device_list_revert();

    mem_free(dir_list);
    mem_free(path);
}

/* Free resources, allocated by conf_load, and reset configuration
 * data into initial state
 */
void
conf_unload (void)
{
    conf_device_list_free();
    mem_free((char*) conf.dbg_trace);
    mem_free((char*) conf.socket_dir);
    conf = conf_init;
}

/* vim:ts=8:sw=4:et
 */

