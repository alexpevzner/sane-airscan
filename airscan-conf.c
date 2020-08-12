/* AirScan (a.k.a. eSCL) backend for SANE
 *
 * Copyright (C) 2019 and up by Alexander Pevzner (pzz@apevzner.com)
 * See LICENSE for license terms and conditions
 *
 * Configuration file parser
 */

#include "airscan.h"

#include <dirent.h>
#include <stdlib.h>
#include <string.h>

/******************** .INI-file parser ********************/
/* Types of .INI file records
 */
typedef enum {
    INIFILE_SECTION,                    /* The [section name] string */
    INIFILE_VARIABLE,                   /* The variable = value string */
    INIFILE_COMMAND,                    /* command param1 param2 ... */
    INIFILE_SYNTAX                      /* The syntax error */
} INIFILE_RECORD;

/* .INI file record
 */
typedef struct {
    INIFILE_RECORD      type;           /* Record type */
    const char          *section;       /* Section name */
    const char          *variable;      /* Variable name */
    const char          *value;         /* Variable value */
    const char          **tokv;         /* Value split to tokens */
    unsigned int        tokc;           /* Count of strings in tokv */
    const char          *file;          /* File name */
    unsigned int        line;           /* File line */
} inifile_record;

/* .INI file (opaque)
 */
typedef struct {
    const char          *file;                  /* File name */
    unsigned int        line;                   /* File handle */
    FILE                *fp;                    /* File pointer */

    bool                tk_open;                /* Token is currently open */
    char                *tk_buffer;             /* Parser buffer, tokenized */
    unsigned int        *tk_offsets;            /* Tokens offsets */
    unsigned int        tk_count;               /* Tokens count */

    char                *buffer;                /* Parser buffer */
    char                *section;               /* Section name string */
    char                *variable;              /* Variable name string */
    char                *value;                 /* Value string */
    inifile_record      record;                 /* Record buffer */
} inifile;

static const char DEFAULT_SOCKET_DIR[] = "/var/run";

/***** Functions *****/
/* Open the .INI file
 */
static inifile*
inifile_open (const char *name)
{
    FILE        *fp;
    inifile     *file;

    fp = fopen(name, "r");
    if (fp == NULL) {
        return NULL;
    }

    file = mem_new(inifile, 1);
    file->fp = fp;
    file->file = str_dup(name);
    file->line = 1;
    file->tk_buffer = str_new();
    file->buffer = str_new();
    file->section = str_new();
    file->variable = str_new();
    file->value = str_new();

    return file;
}

/* Close the .INI file
 */
static void
inifile_close (inifile *file)
{
    fclose(file->fp);
    mem_free((char*) file->file);
    mem_free(file->tk_buffer);
    mem_free(file->tk_offsets);
    mem_free(file->buffer);
    mem_free(file->section);
    mem_free(file->variable);
    mem_free(file->value);
    mem_free(file->record.tokv);
    mem_free(file);
}

/* Get next character from the file
 */
static inline int
inifile_getc (inifile *file)
{
    int c = getc(file->fp);
    if (c == '\n') {
        file->line ++;
    }
    return c;
}

/* Push character back to stream
 */
static inline void
inifile_ungetc (inifile *file, int c)
{
    if (c == '\n') {
        file->line --;
    }
    ungetc(c, file->fp);
}

/* Get next non-space character from the file
 */
static inline int
inifile_getc_nonspace (inifile *file)
{
    int c;

    while ((c = inifile_getc(file)) != EOF && safe_isspace(c))
        ;

    return c;
}

/* Read until new line or EOF
 */
static inline int
inifile_getc_nl (inifile *file)
{
    int c;

    while ((c = inifile_getc(file)) != EOF && c != '\n')
        ;

    return c;
}

/* Check for commentary character
 */
static inline bool
inifile_iscomment (int c)
{
    return c == ';' || c == '#';
}

/* Check for octal digit
 */
static inline bool
inifile_isoctal (int c)
{
    return '0' <= c && c <= '7';
}

/* Check for token-breaking character
 */
static inline bool
inifile_istkbreaker (int c)
{
    return c == ',';
}

/* Translate hexadecimal digit character to its integer value
 */
static inline unsigned int
inifile_hex2int (int c)
{
    if (isdigit(c)) {
        return c - '0';
    } else {
        return safe_toupper(c) - 'A' + 10;
    }
}

/* Reset tokeniser
 */
static inline void
inifile_tk_reset (inifile *file)
{
    file->tk_open = false;
    str_trunc(file->tk_buffer);
    file->tk_count = 0;
}

/* Push token to token array
 */
static void
inifile_tk_array_push (inifile *file)
{
    file->tk_offsets = mem_resize(file->tk_offsets, file->tk_count + 1, 0);
    file->tk_offsets[file->tk_count ++] = mem_len(file->tk_buffer);
}

/* Export token array to file->record
 */
static void
inifile_tk_array_export (inifile *file)
{
    unsigned int        i;

    file->record.tokv = mem_resize(file->record.tokv, file->tk_count, 0);
    file->record.tokc = file->tk_count;

    for (i = 0; i < file->tk_count; i ++) {
        const char      *token;

        token = file->tk_buffer + file->tk_offsets[i];
        file->record.tokv[i] = token;
    }
}

/* Open token if it is not opened yet
 */
static void
inifile_tk_open (inifile *file)
{
    if (!file->tk_open) {
        inifile_tk_array_push(file);
        file->tk_open = true;
    }
}

/* Close current token
 */
static void
inifile_tk_close (inifile *file)
{
    if (file->tk_open) {
        file->tk_buffer = str_append_c(file->tk_buffer, '\0');
        file->tk_open = false;
    }
}

/* Append character to token
 */
static inline void
inifile_tk_append (inifile *file, int c)
{
    inifile_tk_open(file);
    file->tk_buffer = str_append_c(file->tk_buffer, c);
}

/* Strip trailing space in line currently being read
 */
static inline void
inifile_strip_trailing_space (inifile *file, unsigned int *trailing_space)
{
    size_t len = mem_len(file->buffer) - *trailing_space;
    file->buffer = str_resize(file->buffer, len);
    *trailing_space = 0;
}

/* Read string until either one of following is true:
 *    - new line or EOF or read error is reached
 *    - delimiter character is reached (if specified)
 *
 * If linecont parameter is true, '\' at the end of line treated
 * as line continuation character
 */
static int
inifile_gets (inifile *file, char delimiter, bool linecont, bool *syntax)
{
    int                 c;
    unsigned int        accumulator = 0;
    unsigned int        count = 0;
    unsigned int        trailing_space = 0;
    enum {
        PRS_SKIP_SPACE,
        PRS_BODY,
        PRS_STRING,
        PRS_STRING_BSLASH,
        PRS_STRING_HEX,
        PRS_STRING_OCTAL,
        PRS_COMMENT
    } state = PRS_SKIP_SPACE;

    str_trunc(file->buffer);
    inifile_tk_reset(file);

    /* Parse the string */
    for (;;) {
        c = inifile_getc(file);

        if (c == EOF || c == '\n') {
            break;
        }

        if ((state == PRS_BODY || state == PRS_SKIP_SPACE) && c == delimiter) {
            inifile_tk_close(file);
            break;
        }

        switch(state) {
        case PRS_SKIP_SPACE:
            if (safe_isspace(c)) {
                break;
            }

            state = PRS_BODY;
            /* Fall through... */

        case PRS_BODY:
            if (c == '"') {
                state = PRS_STRING;
                inifile_tk_open(file);
            } else if (inifile_iscomment(c)) {
                state = PRS_COMMENT;
            } else if (c == '\\' && linecont) {
                int c2 = inifile_getc(file);
                if (c2 == '\n') {
                    inifile_strip_trailing_space(file, &trailing_space);
                    state = PRS_SKIP_SPACE;
                } else {
                    inifile_ungetc(file, c);
                }
            } else {
                file->buffer = str_append_c(file->buffer, c);
            }

            if (state == PRS_BODY) {
                if (safe_isspace(c)) {
                    trailing_space ++;
                    inifile_tk_close(file);
                } else {
                    trailing_space = 0;
                    if (inifile_istkbreaker(c)) {
                        inifile_tk_close(file);
                    } else {
                        inifile_tk_append(file, c);
                    }
                }
            }
            else {
                inifile_strip_trailing_space(file, &trailing_space);
            }
            break;

        case PRS_STRING:
            if (c == '\\') {
                state = PRS_STRING_BSLASH;
            } else if (c == '"') {
                state = PRS_BODY;
            } else {
                file->buffer = str_append_c(file->buffer, c);
                inifile_tk_append(file, c);
            }
            break;

        case PRS_STRING_BSLASH:
            if (c == 'x' || c == 'X') {
                state = PRS_STRING_HEX;
                accumulator = count = 0;
            } else if (inifile_isoctal(c)) {
                state = PRS_STRING_OCTAL;
                accumulator = inifile_hex2int(c);
                count = 1;
            } else {
                switch (c) {
                case 'a': c = '\a'; break;
                case 'b': c = '\b'; break;
                case 'e': c = '\x1b'; break;
                case 'f': c = '\f'; break;
                case 'n': c = '\n'; break;
                case 'r': c = '\r'; break;
                case 't': c = '\t'; break;
                case 'v': c = '\v'; break;
                }

                file->buffer = str_append_c(file->buffer, c);
                inifile_tk_append(file, c);
                state = PRS_STRING;
            }
            break;

        case PRS_STRING_HEX:
            if (safe_isxdigit(c)) {
                if (count != 2) {
                    accumulator = accumulator * 16 + inifile_hex2int(c);
                    count ++;
                }
            } else {
                state = PRS_STRING;
                inifile_ungetc(file, c);
            }

            if (state != PRS_STRING_HEX) {
                file->buffer = str_append_c(file->buffer, accumulator);
                inifile_tk_append(file, accumulator);
            }
            break;

        case PRS_STRING_OCTAL:
            if (inifile_isoctal(c)) {
                accumulator = accumulator * 8 + inifile_hex2int(c);
                count ++;
                if (count == 3) {
                    state = PRS_STRING;
                }
            } else {
                state = PRS_STRING;
                inifile_ungetc(file, c);
            }

            if (state != PRS_STRING_OCTAL) {
                file->buffer = str_append_c(file->buffer, accumulator);
                inifile_tk_append(file, accumulator);
            }
            break;

        case PRS_COMMENT:
            break;
        }
    }

    /* Remove trailing space, if any */
    inifile_strip_trailing_space(file, &trailing_space);

    /* Set syntax error flag */
    *syntax = false;
    if (state != PRS_SKIP_SPACE && state != PRS_BODY && state != PRS_COMMENT) {
        *syntax = true;
    }

    return c;
}

/* Finish reading the record. Performs common cleanup operations,
 * feels record structure etc
 */
static const inifile_record*
inifile_read_finish (inifile *file, int last_char, INIFILE_RECORD rec_type)
{
    file->record.type = rec_type;
    file->record.file = file->file;
    file->record.section = file->section;
    file->record.variable = file->record.value = NULL;

    if (rec_type == INIFILE_VARIABLE || rec_type == INIFILE_COMMAND) {
        inifile_tk_array_export(file);
        if (rec_type == INIFILE_VARIABLE) {
            file->record.variable = file->variable;
            file->record.value = file->value;
        } else {
            log_assert(NULL, file->record.tokc);
            file->record.variable = file->record.tokv[0];
            file->record.tokc --;
            if (file->record.tokc) {
                memmove((void*) file->record.tokv, file->record.tokv + 1,
                        sizeof(file->record.tokv[0]) * file->record.tokc);
            }
        }
    } else {
        file->record.tokc = 0;
    }

    if (last_char == '\n') {
        file->record.line = file->line - 1;
    } else {
        file->record.line = file->line;
        if (last_char != EOF) {
            inifile_getc_nl(file);
        }
    }

    return &file->record;
}

/* Read next record
 */
static const inifile_record*
inifile_read (inifile *file)
{
    int  c;
    bool syntax;

    c = inifile_getc_nonspace(file);
    while (inifile_iscomment(c)) {
        inifile_getc_nl(file);
        c = inifile_getc_nonspace(file);
    }

    if (c == EOF) {
        return NULL;
    }

    if (c == '[') {
        c = inifile_gets(file, ']', false, &syntax);

        if (c == ']' && !syntax)
        {
            file->section = str_assign(file->section, file->buffer);
            return inifile_read_finish(file, c, INIFILE_SECTION);
        }
    } else if (c != '=') {
        inifile_ungetc(file, c);

        c = inifile_gets(file, '=', false, &syntax);
        if(c == '=' && !syntax) {
            file->variable = str_assign(file->variable, file->buffer);
            c = inifile_gets(file, EOF, true, &syntax);
            if(!syntax) {
                file->value = str_assign(file->value, file->buffer);
                return inifile_read_finish(file, c, INIFILE_VARIABLE);
            }
        }
        else if (!syntax) {
            return inifile_read_finish(file, c, INIFILE_COMMAND);
        }
    }

    return inifile_read_finish(file, c, INIFILE_SYNTAX);
}

/* Match name of section of variable
 *   - match is case-insensitive
 *   - difference in amount of free space is ignored
 *   - leading and trailing space is ignored
 */
static bool
inifile_match_name (const char *n1, const char *n2)
{
    /* Skip leading space */
    while (safe_isspace(*n1)) {
        n1 ++;
    }

    while (safe_isspace(*n2)) {
        n2 ++;
    }

    /* Perform the match */
    while (*n1 && *n2) {
        if (safe_isspace(*n1)) {
            if (!safe_isspace(*n2)) {
                break;
            }

            do {
                n1 ++;
            } while (safe_isspace(*n1));

            do {
                n2 ++;
            } while (safe_isspace(*n2));
        }
        else if (safe_toupper(*n1) == safe_toupper(*n2)) {
            n1 ++, n2 ++;
        } else {
            break;
        }
    }

    /* Skip trailing space */
    while (safe_isspace(*n1)) {
        n1 ++;
    }

    while (safe_isspace(*n2)) {
        n2 ++;
    }

    /* Check results */
    return *n1 == '\0' && *n2 == '\0';
}

/******************** Configuration file loader  ********************/
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
    conf.socket_dir = str_dup(DEFAULT_SOCKET_DIR);

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
    conf = conf_init;
}

/* vim:ts=8:sw=4:et
 */

