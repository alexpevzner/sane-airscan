/* AirScan (a.k.a. eSCL) backend for SANE
 *
 * Copyright (C) 2019 and up by Alexander Pevzner (pzz@apevzner.com)
 * See LICENSE for license terms and conditions
 *
 * .INI file parser
 */

#include "airscan.h"

#include <stdlib.h>
#include <string.h>

/* Open the .INI file
 */
inifile*
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
void
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
const inifile_record*
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
bool
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

/* vim:ts=8:sw=4:et
 */

