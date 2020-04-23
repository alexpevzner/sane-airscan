/* AirScan (a.k.a. eSCL) backend for SANE
 *
 * Copyright (C) 2019 and up by Alexander Pevzner (pzz@apevzner.com)
 * See LICENSE for license terms and conditions
 *
 * Configuration file parser
 */

#include "airscan.h"

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
    GString             *tk_buffer;             /* Parser buffer, tokenized */
    unsigned int        *tk_offsets;            /* Tokens offsets */
    unsigned int        tk_count;               /* Tokens count */
    unsigned int        tk_count_max;           /* Max ever allocated tokens
                                                   count */

    GString             *buffer;                /* Parser buffer */
    GString             *section;               /* Section name string */
    GString             *variable;              /* Variable name string */
    GString             *value;                 /* Value string */
    inifile_record      record;                 /* Record buffer */
} inifile;

#define INIFILE_TOKEN_ARRAY_INCREMENT   32

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

    file = g_new0(inifile, 1);
    file->fp = fp;
    file->file = g_strdup(name);
    file->line = 1;
    file->tk_buffer = g_string_new(NULL);
    file->buffer = g_string_new(NULL);
    file->section = g_string_new(NULL);
    file->variable = g_string_new(NULL);
    file->value = g_string_new(NULL);

    return file;
}

/* Close the .INI file
 */
static void
inifile_close (inifile *file)
{
    fclose(file->fp);
    g_free((char*) file->file);
    g_string_free(file->tk_buffer, TRUE);
    g_free(file->tk_offsets);
    g_string_free(file->buffer, TRUE);
    g_string_free(file->section, TRUE);
    g_string_free(file->variable, TRUE);
    g_string_free(file->value, TRUE);
    g_free(file->record.tokv);
    g_free(file);
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

    while ((c = inifile_getc(file)) != EOF && g_ascii_isspace(c))
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
    if (g_ascii_isdigit(c)) {
        return c - '0';
    } else {
        return g_ascii_toupper(c) - 'A' + 10;
    }
}

/* Reset tokeniser
 */
static inline void
inifile_tk_reset (inifile *file)
{
    file->tk_open = false;
    g_string_truncate(file->tk_buffer, 0);
    file->tk_count = 0;
}

/* Push token to token array
 */
static void
inifile_tk_array_push (inifile *file)
{
    /* Grow array on demand */
    if (file->tk_count == file->tk_count_max) {
        file->tk_count_max += INIFILE_TOKEN_ARRAY_INCREMENT;
        file->tk_offsets = g_realloc(file->tk_offsets,
            sizeof(*file->tk_offsets) * file->tk_count_max);
    }

    /* Push token offset into array */
    file->tk_offsets[file->tk_count ++] = file->tk_buffer->len;
}

/* Export token array to file->record
 */
static void
inifile_tk_array_export (inifile *file)
{
    unsigned int        i;

    file->record.tokv = g_realloc(file->record.tokv,
            sizeof(*file->record.tokv) * file->tk_count_max);

    file->record.tokc = file->tk_count;
    for (i = 0; i < file->tk_count; i ++) {
        const char      *token;

        token = file->tk_buffer->str + file->tk_offsets[i];
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
        g_string_append_c(file->tk_buffer, '\0');
        file->tk_open = false;
    }
}

/* Append character to token
 */
static inline void
inifile_tk_append (inifile *file, int c)
{
    inifile_tk_open(file);
    g_string_append_c(file->tk_buffer, c);
}

/* Strip trailing space in line currently being read
 */
static inline void
inifile_strip_trailing_space (inifile *file, unsigned int *trailing_space)
{
    g_string_truncate(file->buffer, file->buffer->len - *trailing_space);
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

    g_string_truncate(file->buffer, 0);
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
            if (g_ascii_isspace(c)) {
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
                g_string_append_c(file->buffer, c);
            }

            if (state == PRS_BODY) {
                if (g_ascii_isspace(c)) {
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
                g_string_append_c(file->buffer, c);
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

                g_string_append_c(file->buffer, c);
                inifile_tk_append(file, c);
                state = PRS_STRING;
            }
            break;

        case PRS_STRING_HEX:
            if (g_ascii_isxdigit(c)) {
                if (count != 2) {
                    accumulator = accumulator * 16 + inifile_hex2int(c);
                    count ++;
                }
            } else {
                state = PRS_STRING;
                inifile_ungetc(file, c);
            }

            if (state != PRS_STRING_HEX) {
                g_string_append_c(file->buffer, accumulator);
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
                g_string_append_c(file->buffer, accumulator);
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
    file->record.section = file->section->str;
    file->record.variable = file->record.value = NULL;

    if (rec_type == INIFILE_VARIABLE || rec_type == INIFILE_COMMAND) {
        inifile_tk_array_export(file);
        if (rec_type == INIFILE_VARIABLE) {
            file->record.variable = file->variable->str;
            file->record.value = file->value->str;
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
            g_string_assign(file->section, file->buffer->str);
            return inifile_read_finish(file, c, INIFILE_SECTION);
        }
    } else if (c != '=') {
        inifile_ungetc(file, c);

        c = inifile_gets(file, '=', false, &syntax);
        if(c == '=' && !syntax) {
            g_string_assign(file->variable, file->buffer->str);
            c = inifile_gets(file, EOF, true, &syntax);
            if(!syntax) {
                g_string_assign(file->value, file->buffer->str);
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
    while (g_ascii_isspace(*n1)) {
        n1 ++;
    }

    while (g_ascii_isspace(*n2)) {
        n2 ++;
    }

    /* Perform the match */
    while (*n1 && *n2) {
        if (g_ascii_isspace(*n1)) {
            if (!g_ascii_isspace(*n2)) {
                break;
            }

            do {
                n1 ++;
            } while (g_ascii_isspace(*n1));

            do {
                n2 ++;
            } while (g_ascii_isspace(*n2));
        }
        else if (g_ascii_toupper(*n1) == g_ascii_toupper(*n2)) {
            n1 ++, n2 ++;
        } else {
            break;
        }
    }

    /* Skip trailing space */
    while (g_ascii_isspace(*n1)) {
        n1 ++;
    }

    while (g_ascii_isspace(*n2)) {
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
        g_free((char*) list->name);
        g_free((char*) list->uri);
        devid_free(list->devid);
        g_free(list);
        list = next;
    }
}

/* Prepend device conf.devices list
 */
static void
conf_device_list_prepend (const char *name, http_uri *uri, ID_PROTO proto)
{
    conf_device *dev = g_new0(conf_device, 1);
    dev->name = g_strdup(name);
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
 * released with g_free()
 */
static const char*
conf_expand_path (const char *path)
{
    const char *prefix = "", *suffix = "", *home = NULL, *end;

    if (path[0] == '~' && (path[1] == '\0' || path[1] == '/')) {
        home = g_get_home_dir();
        if (home != NULL) {
            prefix = home;
            path ++;
        } else {
            return NULL;
        }
    }

    end = path[0] ? path : prefix;
    suffix = g_str_has_suffix(end, "/") ? "" : "/";
    path = g_strconcat(home, path, suffix, NULL);

    return path;
}

/* Report configuration file error
 */
static void
conf_perror (const inifile_record *rec, const char *err)
{
    log_debug(NULL, "%s:%d: %s", rec->file, rec->line, err);
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
                    if (inifile_match_name(rec->value, "enable")) {
                        conf.discovery = true;
                    } else if (inifile_match_name(rec->value, "disable")) {
                        conf.discovery = false;
                    } else {
                        conf_perror(rec, "usage: discovery = enable | disable");
                    }
                } else if (inifile_match_name(rec->variable, "model")) {
                    if (inifile_match_name(rec->value, "network")) {
                        conf.model_is_netname = true;
                    } else if (inifile_match_name(rec->value, "hardware")) {
                        conf.model_is_netname = false;
                    } else {
                        conf_perror(rec, "usage: model = network | hardware");
                    }
                } else if (inifile_match_name(rec->variable, "protocol")) {
                    if (inifile_match_name(rec->value, "auto")) {
                        conf.proto_manual = false;
                    } else if (inifile_match_name(rec->value, "manual")) {
                        conf.proto_manual = true;
                    } else {
                        conf_perror(rec, "usage: protocol = auto | manual");
                    }
                } else if (inifile_match_name(rec->variable, "ws-discovery")) {
                    if (inifile_match_name(rec->value, "fast")) {
                        conf.fast_wsdd = true;
                    } else if (inifile_match_name(rec->value, "full")) {
                        conf.fast_wsdd = false;
                    } else {
                        conf_perror(rec, "usage: ws-discovery = fast | full");
                    }
                }
            } else if (inifile_match_name(rec->section, "debug")) {
                if (inifile_match_name(rec->variable, "trace")) {
                    g_free((char*) conf.dbg_trace);
                    conf.dbg_trace = conf_expand_path(rec->value);
                    if (conf.dbg_trace == NULL) {
                        conf_perror(rec, "failed to expand path");
                    }
                } else if (inifile_match_name(rec->variable, "enable")) {
                    if (inifile_match_name(rec->value, "true")) {
                        conf.dbg_enabled = true;
                    } else if (inifile_match_name(rec->value, "false")) {
                        conf.dbg_enabled = false;
                    } else {
                        conf_perror(rec, "usage: enable = true | false");
                    }
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
 */
static void
conf_load_from_dir (GString *path)
{
    if (path->len != 0 && path->str[path->len - 1] != '/') {
        g_string_append_c(path, '/');
    }

    /* Load from CONFIG_AIRSCAN_CONF file */
    size_t len = path->len;
    g_string_append(path, CONFIG_AIRSCAN_CONF);
    conf_load_from_file(path->str);

    /* Scan CONFIG_AIRSCAN_D directory */
    g_string_truncate(path, len);
    g_string_append(path, CONFIG_AIRSCAN_D);
    if (path->str[path->len - 1] != '/') {
        g_string_append_c(path, '/');
    }
    len = path->len;

    GDir *dir = g_dir_open(path->str, 0, NULL);
    if (dir) {
        const char *name;
        while ((name = g_dir_read_name(dir)) != NULL) {
            g_string_truncate(path, len);
            g_string_append(path, name);
            conf_load_from_file(path->str);
        }

        g_dir_close(dir);
    }
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
    GString   *dir_list = g_string_new(NULL);
    GString   *path = g_string_new(NULL);
    char      *s;

    /* Reset the configuration */
    conf = conf_init;

    /* Look to configuration path in environment */
    s = getenv(CONFIG_PATH_ENV);
    if (s != NULL) {
        g_string_assign(dir_list, s);
    }

    /* Append default directories */
    if (dir_list->len && dir_list->str[dir_list->len - 1] != ':') {
        g_string_append_c(dir_list, ':');
    }

    g_string_append(dir_list, CONFIG_SANE_CONFIG_DIR);

    /* Iterate over the dir_list */
    for (s = dir_list->str; ; s ++) {
        if (*s == ':' || *s == '\0') {
            conf_load_from_dir(path);
            g_string_truncate(path, 0);
        } else {
            g_string_append_c(path, *s);
        }

        if (*s == '\0') {
            break;
        }
    }

    /* Load configuration from environment */
    conf_load_from_env();

    /* Cleanup and exit */
    conf_device_list_revert();

    g_string_free(dir_list, TRUE);
    g_string_free(path, TRUE);
}

/* Free resources, allocated by conf_load, and reset configuration
 * data into initial state
 */
void
conf_unload (void)
{
    conf_device_list_free();
    g_free((char*) conf.dbg_trace);
    conf = conf_init;
}

/* vim:ts=8:sw=4:et
 */

