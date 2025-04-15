/* AirScan (a.k.a. eSCL) backend for SANE
 *
 * Copyright (C) 2019 and up by Alexander Pevzner (pzz@apevzner.com)
 * See LICENSE for license terms and conditions
 */

#ifndef airscan_h
#define airscan_h

#include <avahi-common/address.h>
#include <avahi-common/strlst.h>
#include <avahi-common/watch.h>

#include <sane/sane.h>
#include <sane/saneopts.h>

#include <ctype.h>
#include <math.h>
#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include <netinet/in.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/types.h>

#ifdef  __cplusplus
extern "C" {
#endif

/******************** Static configuration ********************/
/* Configuration path in environment
 */
#define CONFIG_PATH_ENV                 "SANE_CONFIG_DIR"

/* Standard SANE configuration directory
 */
#ifndef CONFIG_SANE_CONFIG_DIR
#    define CONFIG_SANE_CONFIG_DIR      "/etc/sane.d/"
#endif

/* Sane-airscan configuration file and subdirectory names
 */
#define CONFIG_AIRSCAN_CONF             "airscan.conf"
#define CONFIG_AIRSCAN_D                "airscan.d"

/* Environment variables
 */
#define CONFIG_ENV_AIRSCAN_DEBUG        "SANE_DEBUG_AIRSCAN"

/* Default resolution, DPI
 */
#define CONFIG_DEFAULT_RESOLUTION       300

/* Minimal interval between subsequent sane_start()
 * attempts, if previous sane_start was failed
 */
#define CONFIG_START_RETRY_INTERVAL     2500

/* Default directory for AF_UNIX sockets
 */
#define CONFIG_DEFAULT_SOCKET_DIR       "/var/run"

/******************** Forward declarations ********************/
/* log_ctx represents logging context
 */
typedef struct log_ctx log_ctx;

/* Type http_uri represents HTTP URI
 */
typedef struct http_uri http_uri;

/******************** Utility macros ********************/
/* Obtain pointer to outer structure from pointer to
 * its known member
 */
#define OUTER_STRUCT(member_p,struct_t,field)                            \
    ((struct_t*)((char*)(member_p) - ((ptrdiff_t) &(((struct_t*) 0)->field))))

/******************** Circular Linked Lists ********************/
/* ll_node represents a linked data node.
 * Data nodes are embedded into the corresponding data structures:
 *   struct data {
 *       ll_node chain; // Linked list chain
 *       ...
 *   };
 *
 * Use OUTER_STRUCT() macro to obtain pointer to containing
 * structure from the pointer to the list node
 */
typedef struct ll_node ll_node;
struct ll_node {
    ll_node *ll_prev, *ll_next;
};

/* ll_head represents a linked list head node
 * ll_head must be initialized before use with ll_init() function
 */
typedef struct {
    ll_node node;
} ll_head;

/* Initialize list head
 */
static inline void
ll_init (ll_head *head)
{
    head->node.ll_next = head->node.ll_prev = &head->node;
}

/* Check if list is empty
 */
static inline bool
ll_empty (const ll_head *head)
{
    return head->node.ll_next == &head->node;
}

/* Push node to the end of the list, represented
 * by its head node
 */
static inline void
ll_push_end (ll_head *head, ll_node *node)
{
    node->ll_prev = head->node.ll_prev;
    node->ll_next = &head->node;
    head->node.ll_prev->ll_next = node;
    head->node.ll_prev = node;
}

/* Push node to the beginning of the list, represented
 * by its head node
 */
static inline void
ll_push_beg (ll_head *head, ll_node *node)
{
    node->ll_next = head->node.ll_next;
    node->ll_prev = &head->node;
    head->node.ll_next->ll_prev = node;
    head->node.ll_next = node;
}

/* Delete node from the list
 */
static inline void
ll_del (ll_node *node)
{
    ll_node *p = node->ll_prev, *n = node->ll_next;

    p->ll_next = n;
    n->ll_prev = p;

    /* Make double-delete safe */
    node->ll_next = node->ll_prev = node;
}

/* Pop node from the beginning of the list.
 * Returns NULL if list is empty
 */
static inline ll_node*
ll_pop_beg (ll_head *head)
{
    ll_node *node, *next;

    node = head->node.ll_next;
    if (node == &head->node) {
        return NULL; /* List is empty if it is looped to itself */
    }

    next = node->ll_next;
    next->ll_prev = &head->node;
    head->node.ll_next = next;

    /* Make double-delete safe */
    node->ll_next = node->ll_prev = node;

    return node;
}

/* Pop node from the end of the list.
 * Returns NULL if list is empty
 */
static inline ll_node*
ll_pop_end (ll_head *head)
{
    ll_node *node, *prev;

    node = head->node.ll_prev;
    if (node == &head->node) {
        return NULL; /* List is empty if it is looped to itself */
    }

    prev = node->ll_prev;
    prev->ll_next = &head->node;
    head->node.ll_prev = prev;

    /* Make double-delete safe */
    node->ll_next = node->ll_prev = node;

    return node;
}

/* Get next (from the beginning to the end) node of
 * the list. Returns NULL, if end of list is reached
 */
static inline ll_node*
ll_next (const ll_head *head, const ll_node *node)
{
    ll_node *next = node->ll_next;
    return next == &head->node ? NULL : next;
}

/* Get previous (from the beginning to the end) node of
 * the list. Returns NULL, if end of list is reached
 */
static inline ll_node*
ll_prev (const ll_head *head, const ll_node *node)
{
    ll_node *prev = node->ll_prev;
    return prev == &head->node ? NULL : prev;
}

/* Get first node of the list.
 * Returns NULL if list is empty
 */
static inline ll_node*
ll_first (const ll_head *head)
{
    return ll_next(head, &head->node);
}

/* Get last node of the list.
 * Returns NULL if list is empty
 */
static inline ll_node*
ll_last (const ll_head *head)
{
    return ll_prev(head, &head->node);
}

/* Concatenate lists:
 *   list1 += list2
 *   list2 = empty
 */
static inline void
ll_cat (ll_head *list1, ll_head *list2)
{
    if (ll_empty(list2)) {
        return;
    }

    list2->node.ll_prev->ll_next = &list1->node;
    list2->node.ll_next->ll_prev = list1->node.ll_prev;
    list1->node.ll_prev->ll_next = list2->node.ll_next;
    list1->node.ll_prev = list2->node.ll_prev;

    ll_init(list2);
}

/* Helper macro for list iteration.
 * Usage:
 *   for (LL_FOR_EACH(node, list)) {
 *     // do something with the node
 *   }
 */
#define LL_FOR_EACH(node,list)                          \
    node = ll_first(list); node != NULL; node = ll_next(list, node)

/******************** Memory allocation ********************/
/* Allocate `len' elements of type T
 */
#define mem_new(T,len)  ((T*) __mem_alloc(len, 0, sizeof(T), true))

/* Resize memory. The returned memory block has length of `len' and
 * capacity at least of `len' + `extra'
 *
 * If p is NULL, new memory block will be allocated. Otherwise,
 * existent memory block will be resized, new pointer is returned,
 * while old becomes invalid (similar to how realloc() works).
 *
 * This function never returns NULL, it panics in a case of
 * memory allocation error.
 */
#define mem_resize(p,len,extra)         \
        ((__typeof__(p)) __mem_resize(p,len,extra,sizeof(*p),true))

/* Try to resize memory. It works like mem_resize() but may
 * return NULL if memory allocation failed.
 */
#define mem_try_resize(p,len,extra) __mem_resize(p,len,extra,sizeof(*p),false)

/* Truncate the memory block length, preserving its capacity
 */
void
mem_trunc (void *p);

/* Shrink the memory block length, preserving its capacity
 */
#define mem_shrink(p,len)       __mem_shrink(p,len, sizeof(*p))

/* Free memory block, obtained from mem_new() or mem_resize()
 * `p' can be NULL
 */
void
mem_free (void *p);

/* Get memory block length/capacity, in bytes
 * For NULL pointer return 0
 */
size_t mem_len_bytes (const void *p);
size_t mem_cap_bytes (const void *p);

/* Get memory block length/capacity, in elements
 * For NULL pointer return 0
 */
#define mem_len(v)  (mem_len_bytes(v) / sizeof(*v))
#define mem_cap(v)  (mem_cap_bytes(v) / sizeof(*v))

/* Helper functions for memory allocation, don't use directly
 */
void* __attribute__ ((__warn_unused_result__))
__mem_alloc (size_t len, size_t extra, size_t elsize, bool must);

void* __attribute__ ((__warn_unused_result__))
__mem_resize (void *p, size_t len, size_t cap, size_t elsize, bool must);

void
__mem_shrink (void *p, size_t len, size_t elsize);

/******************** Strings ********************/
/* Create new string
 */
static inline char*
str_new (void) {
    char *s = mem_resize((char*) NULL, 0, 1);
    *s = '\0';
    return s;
}

/* Create new string as a copy of existent string
 */
static inline char*
str_dup (const char *s1)
{
    size_t len = strlen(s1);
    char   *s = mem_resize((char*) NULL, len, 1);
    memcpy(s, s1, len + 1);
    return s;
}

/* Get string length in bytes, not including terminating '\0'
 */
static inline size_t
str_len (const char *s)
{
    return mem_len(s);
}

/* Create new string as a lowercase copy of existent string
 */
char*
str_dup_tolower (const char *s1);

/* Create new string and print to it
 */
char*
str_printf (const char *format, ...);

/* Create new string and print to it, va_list version
 */
char*
str_vprintf (const char *format, va_list ap);

/* Truncate the string
 */
static inline void
str_trunc (char *s)
{
    mem_trunc(s);
    *s = '\0';
}

/* Resize the string
 *
 * s1 must be previously created by some of str_XXX functions,
 * s1 will be consumed and the new pointer will be returned
 */
static inline char*
str_resize (char *s, size_t len)
{
    s = mem_resize(s, len, 1);
    s[len] = '\0';
    return s;
}

/* Append memory to string:
 *     s1 += s2[:l2]
 *
 * s1 must be previously created by some of str_XXX functions,
 * s1 will be consumed and the new pointer will be returned
 */
static inline char*
str_append_mem (char *s1, const char *s2, size_t l2)
{
    size_t l1 = str_len(s1);

    s1 = mem_resize(s1, l1 + l2, 1);
    memcpy(s1 + l1, s2, l2);
    s1[l1+l2] = '\0';

    return s1;
}

/* Append string to string:
 *     s1 += s2
 *
 * s1 must be previously created by some of str_XXX functions,
 * s1 will be consumed and the new pointer will be returned
 */
static inline char*
str_append (char *s1, const char *s2)
{
    return str_append_mem(s1, s2, strlen(s2));
}

/* Append character to string:
 *     s1 += c
 *
 * `s' must be previously created by some of str_XXX functions,
 * `s' will be consumed and the new pointer will be returned
 */
static inline char*
str_append_c (char *s, char c)
{
    return str_append_mem(s, &c, 1);
}

/* Append formatted string to string
 *
 * `s' must be previously created by some of str_XXX functions,
 * `s' will be consumed and the new pointer will be returned
 */
char*
str_append_printf (char *s, const char *format, ...);

/* Append formatted string to string -- va_list version
 */
char*
str_append_vprintf (char *s, const char *format, va_list ap);

/* Assign value to string
 *
 * `s1' must be previously created by some of str_XXX functions,
 * `s1' will be consumed and the new pointer will be returned
 */
static inline char*
str_assign (char *s1, const char *s2)
{
    mem_trunc(s1);
    return str_append(s1, s2);
}

/* Concatenate several strings. Last pointer must be NULL.
 * The returned pointer must be eventually freed by mem_free
 */
char*
str_concat (const char *s, ...);

/* Make sure that string is terminated with the `c' character:
 * if string is not empty and the last character is not `c`,
 * append `c' to the string
 *
 * `s' must be previously created by some of str_XXX functions,
 * `s' will be consumed and the new pointer will be returned
 */
static inline char*
str_terminate (char *s, char c)
{
    if (s[0] != '\0' && s[str_len(s) - 1] != c) {
        s = str_append_c(s, c);
    }

    return s;
}

/* Check if string has a specified prefix
 */
bool
str_has_prefix (const char *s, const char *prefix);

/* Check if string has a specified suffix
 */
bool
str_has_suffix (const char *s, const char *suffix);

/* Remove leading and trailing white space.
 * This function modifies string in place, and returns pointer
 * to original string, for convenience
 */
char*
str_trim (char *s);

/******************** NULL-terminated pointer arrays  ********************/
/* Create NULL-terminated array of pointers of type *T
 */
#define ptr_array_new(T)                mem_resize((T*) NULL, 0, 1)

/* Append pointer to the NULL-terminated array of pointers.
 * Returns new, potentially reallocated array
 */
#define ptr_array_append(a,p)           \
        ((__typeof__(a)) __ptr_array_append((void**)a, p))

/* Truncate NULL-terminated array of pointers
 */
#define ptr_array_trunc(a)              \
    do {                                \
        mem_trunc(a);                   \
        a[0] = NULL;                    \
    } while(0)

/* Find pointer within array of pointers.
 * Return non-negative index if pointer was found, -1 otherwise
 */
#define ptr_array_find(a,p)             __ptr_array_find((void**) a, p)

/* Delete element at given index.
 * Returns value of deleted pointer or NULL, if index is out of range
 */
#define ptr_array_del(a,i)              \
        ((__typeof__(*a)) __ptr_array_del((void**) a, i))

/* Helper function for ptr_array_append, don't use directly
 */
static inline void**
__ptr_array_append (void **a, void *p)
{
    size_t len = mem_len(a) + 1;
    a = mem_resize(a, len, 1);
    a[len - 1] = p;
    a[len] = NULL;
    return a;
}

/* Helper function for ptr_array_find, don't use directly
 */
static inline int
__ptr_array_find (void **a, void *p)
{
    size_t len = mem_len(a), i;

    for (i = 0; i < len; i ++) {
        if (a[i] == p) {
            return (int) i;
        }
    }

    return -1;
}

/* Helper function for ptr_array_del, don't use directly
 */
static inline void*
__ptr_array_del (void **a, int i)
{
    size_t len = mem_len(a);
    void   *p;

    if (i < 0 || i >= (int) len) {
        return NULL;
    }

    len --;
    p = a[i];
    memmove(&a[i], &a[i + 1], sizeof(void*) * (len - i));
    mem_shrink(a, len);
    a[len] = NULL;

    return p;
}

/******************** Safe ctype macros ********************/
#define safe_isspace(c)         isspace((unsigned char) c)
#define safe_isxdigit(c)        isxdigit((unsigned char) c)
#define safe_iscntrl(c)         iscntrl((unsigned char) c)
#define safe_isprint(c)         isprint((unsigned char) c)
#define safe_toupper(c)         toupper((unsigned char) c)
#define safe_tolower(c)         tolower((unsigned char) c)

/******************** OS Facilities ********************/
/* The following macros, if defined, indicate that OS
 * has a particular features:
 *
 *   OS_HAVE_EVENTFD      - Linux-like eventfd (2)
 *   OS_HAVE_RTNETLINK    - Linux-like rtnetlink (7)
 *   OS_HAVE_AF_ROUTE     - BSD-like AF_ROUTE
 *   OS_HAVE_LINUX_PROCFS - Linux-style procfs
 *   OS_HAVE_IP_MREQN     - OS defines struct ip_mreqn
 *   OS_HAVE_ENDIAN_H     - #include <endian.h> works
 *   OS_HAVE_SYS_ENDIAN_H - #include <sys/endian.h> works
 */
#ifdef  __linux__
#   define OS_HAVE_EVENTFD              1
#   define OS_HAVE_RTNETLINK            1
#   define OS_HAVE_LINUX_PROCFS         1
#   define OS_HAVE_IP_MREQN             1
#   define OS_HAVE_ENDIAN_H             1
#endif

#ifdef BSD
#   define OS_HAVE_AF_ROUTE             1
#   ifdef __FreeBSD__
#       define OS_HAVE_SYS_ENDIAN_H     1
#   else
#       define OS_HAVE_ENDIAN_H         1
#   endif
#endif

/* Get user's home directory. There is no need to
 * free the returned string
 *
 * May return NULL in a case of error
 */
const char *
os_homedir (void);

/* Get base name of the calling program.
 * There is no need to free the returned string
 *
 * May return NULL in a case of error
 */
const char*
os_progname (void);

/* Make directory with parents
 */
int
os_mkdir (const char *path, mode_t mode);

/******************** Error handling ********************/
/* Type error represents an error. Its value either NULL,
 * which indicates "no error" condition, or some opaque
 * non-null pointer, which can be converted to string
 * with textual description of the error, using the ESTRING()
 * function
 *
 * Caller should not attempt to free the memory, referred
 * by error or string, obtained from an error using the
 * ESTRING() function
 */
typedef struct error_s *error;

/* Standard errors
 */
extern error ERROR_ENOMEM;

/* Construct error from a string
 */
static inline error
ERROR (const char *s)
{
    return (error) s;
}

/* Obtain textual representation of the error
 */
static inline const char*
ESTRING (error err)
{
    return (const char*) err;
}

/******************** Various identifiers ********************/
/* ID_PROTO represents protocol identifier
 */
typedef enum {
    ID_PROTO_UNKNOWN = -1,
    ID_PROTO_ESCL,
    ID_PROTO_WSD,

    NUM_ID_PROTO
} ID_PROTO;

/* id_proto_name returns protocol name
 * For unknown ID returns NULL
 */
const char*
id_proto_name (ID_PROTO proto);

/* id_proto_by_name returns protocol identifier by name
 * For unknown name returns ID_PROTO_UNKNOWN
 */
ID_PROTO
id_proto_by_name (const char* name);

/* ID_SOURCE represents scanning source
 */
typedef enum {
    ID_SOURCE_UNKNOWN = -1,
    ID_SOURCE_PLATEN,
    ID_SOURCE_ADF_SIMPLEX,
    ID_SOURCE_ADF_DUPLEX,

    NUM_ID_SOURCE
} ID_SOURCE;

/* id_source_sane_name returns SANE name for the source
 * For unknown ID returns NULL
 */
const char*
id_source_sane_name (ID_SOURCE id);

/* id_source_by_sane_name returns ID_SOURCE by its SANE name
 * For unknown name returns ID_SOURCE_UNKNOWN
 */
ID_SOURCE
id_source_by_sane_name (const char *name);

/* ID_JUSTIFICATION represents hardware-defined ADF justification
 * This value exposed to the SANE API as a couple of read-only
 * options, separate for width and height justification.
 * Not all scanners provide this information
 */
typedef enum {
    ID_JUSTIFICATION_UNKNOWN = -1,
    ID_JUSTIFICATION_LEFT,
    ID_JUSTIFICATION_CENTER,
    ID_JUSTIFICATION_RIGHT,
    ID_JUSTIFICATION_TOP,
    ID_JUSTIFICATION_BOTTOM,

    NUM_ID_JUSTIFICATION
} ID_JUSTIFICATION;

/* id_justification_sane_name returns SANE name for the width justification
 * For unknown ID returns NULL
 */
const char*
id_justification_sane_name (ID_JUSTIFICATION id);

/* ID_COLORMODE represents color mode
 */
typedef enum {
    ID_COLORMODE_UNKNOWN = -1,
    ID_COLORMODE_COLOR,
    ID_COLORMODE_GRAYSCALE,
    ID_COLORMODE_BW1,

    NUM_ID_COLORMODE
} ID_COLORMODE;

/* id_colormode_sane_name returns SANE name for the color mode
 * For unknown ID returns NULL
 */
const char*
id_colormode_sane_name (ID_COLORMODE id);

/* id_colormode_by_sane_name returns ID_COLORMODE by its SANE name
 * For unknown name returns ID_COLORMODE_UNKNOWN
 */
ID_COLORMODE
id_colormode_by_sane_name (const char *name);

/* ID_FORMAT represents image format
 */
typedef enum {
    ID_FORMAT_UNKNOWN = -1,
    ID_FORMAT_JPEG,
    ID_FORMAT_TIFF,
    ID_FORMAT_PNG,
    ID_FORMAT_PDF,
    ID_FORMAT_BMP,

    NUM_ID_FORMAT
} ID_FORMAT;

/* id_format_mime_name returns MIME name for the image format
 */
const char*
id_format_mime_name (ID_FORMAT id);

/* id_format_by_mime_name returns ID_FORMAT by its MIME name
 * For unknown name returns ID_FORMAT_UNKNOWN
 */
ID_FORMAT
id_format_by_mime_name (const char *name);

/* if_format_short_name returns short name for ID_FORMAT
 */
const char*
id_format_short_name (ID_FORMAT id);

/* ID_SCANINTENT represents scan intent
 *
 * Intent hints scanner on a purpose of requested scan, which may
 * imply carious parameters tweaks depending on that purpose.
 *
 * Intent maps to the eSCL Intent (see Mopria eSCL Technical Specification, 5)
 * and WSD ContentType. The semantics of these two parameters looks very
 * similar.
 *
 * Please note, eSCL defines also the ContentType parameter, but after
 * some thinking and discussion we came to conclusion that Intent better
 * maps our need.
 *
 * Dee discussion at: https://github.com/alexpevzner/sane-airscan/pull/351
 */
typedef enum {
    ID_SCANINTENT_UNKNOWN = -1,
    ID_SCANINTENT_UNSET,          /* Intent is not set */
    ID_SCANINTENT_AUTO,           /*                        WSD: Auto */
    ID_SCANINTENT_DOCUMENT,       /* eSCL: Docoment,        WSD: Text */
    ID_SCANINTENT_TEXTANDGRAPHIC, /* eSCL: TextAndGraphic,  WSD: Mixed */
    ID_SCANINTENT_PHOTO,          /* eSCL: Photo,           WSD: Photo */
    ID_SCANINTENT_PREVIEW,        /* eSCL: Preview */
    ID_SCANINTENT_OBJECT,         /* eSCL: Objects (3d scan) */
    ID_SCANINTENT_BUSINESSCARD,   /* eSCL: BusinessCard */
    ID_SCANINTENT_HALFTONE,       /*                        WSD: Halftone */

    NUM_ID_SCANINTENT
} ID_SCANINTENT;

/* id_scanintent_sane_name returns SANE name for the scan intents
 * For unknown ID returns NULL
 */
const char*
id_scanintent_sane_name (ID_SCANINTENT id);

/* id_scanintent_by_sane_name returns ID_SCANINTENT by its SANE name
 * For unknown name returns ID_SCANINTENT_UNKNOWN
 */
ID_SCANINTENT
id_scanintent_by_sane_name (const char *name);

/******************** Device ID ********************/
/* Allocate unique device ID
 */
unsigned int
devid_alloc (void);

/* Free device ID
 */
void
devid_free (unsigned int id);

/* Initialize device ID allocator
 */
void
devid_init (void);

/******************** Random bytes ********************/
/* Get N random bytes
 */
void
rand_bytes (void *buf, size_t n);

/* Initialize random bytes generator
 */
SANE_Status
rand_init (void);

/* Cleanup random bytes generator
 */
void
rand_cleanup (void);

/******************** UUID utilities ********************/
/* Type uuid represents a random UUID string.
 *
 * It is wrapped into struct, so it can be returned
 * by value, without need to mess with memory allocation
 */
typedef struct {
    char text[sizeof("urn:uuid:ede05377-460e-4b4a-a5c0-423f9e02e8fa")];
} uuid;

/* Check if uuid is valid
 */
static inline bool
uuid_valid (uuid u)
{
    return u.text[0] != '\0';
}

/* Generate random UUID. Generated UUID has a following form:
 *    urn:uuid:ede05377-460e-4b4a-a5c0-423f9e02e8fa
 */
uuid
uuid_rand (void);

/* Parse UUID. This function ignores all "decorations", like
 * urn:uuid: prefix and so on, and takes only hexadecimal digits
 * into considerations
 *
 * Check the returned uuid with uuid_valid() for possible parse errors
 */
uuid
uuid_parse (const char *in);

/* Generate uuid by cryptographically cacheing input string
 */
uuid
uuid_hash (const char *s);

/* Compare two uuids
 */
static inline bool
uuid_equal (uuid u1, uuid u2)
{
    return !strcmp(u1.text, u2.text);
}

/******************** Generic .INI file parser ********************/
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

/* Open the .INI file
 */
inifile*
inifile_open (const char *name);

/* Close the .INI file
 */
void
inifile_close (inifile *file);

/* Read next record
 */
const inifile_record*
inifile_read (inifile *file);

/* Match name of section of variable
 *   - match is case-insensitive
 *   - difference in amount of free space is ignored
 *   - leading and trailing space is ignored
 */
bool
inifile_match_name (const char *n1, const char *n2);

/******************** Utility functions for IP addresses ********************/
/* Address string, wrapped into structure so can
 * be passed by value
 */
typedef struct {
    /* Holds sun_path from sockaddr_un plus a null byte. */
    char       text[109];
} ip_straddr;

/* Format ip_straddr from IP address (struct in_addr or struct in6_addr)
 * af must be AF_INET or AF_INET6
 */
ip_straddr
ip_straddr_from_ip (int af, const void *addr);

/* Format ip_straddr from struct sockaddr.
 * AF_INET, AF_INET6, and AF_UNIX are supported
 *
 * If `withzone' is true, zone suffix will be appended, when appropriate
 */
ip_straddr
ip_straddr_from_sockaddr(const struct sockaddr *addr, bool withzone);

/* Format ip_straddr from struct sockaddr.
 * AF_INET, AF_INET6, and AF_UNIX are supported
 *
 * Port will not be appended, if it matches provided default port
 *
 * If `withzone' is true, zone suffix will be appended, when appropriate
 *
 * If `withlocalhost` is true and address is 127.0.0.1 or ::1,
 * "localhost" will be used instead of the IP address literal
 */
ip_straddr
ip_straddr_from_sockaddr_dport (const struct sockaddr *addr,
        int dport, bool withzone, bool withlocalhost);

/* Check if address is link-local
 * af must be AF_INET or AF_INET6
 */
bool
ip_is_linklocal (int af, const void *addr);

/* Check if sockaddr is link-local
 */
bool
ip_sockaddr_is_linklocal (const struct sockaddr *addr);

/* Check if address is loopback
 * af must be AF_INET or AF_INET6
 */
bool
ip_is_loopback (int af, const void *addr);

/* ip_addr represents IPv4 or IPv6 address
 */
typedef struct {
    int                 af;      /* AF_INET or AF_INET6 */
    int                 ifindex; /* For IPv6 link-local addresses */
    union {
        struct in_addr  v4;      /* IPv4 address */
        struct in6_addr v6;      /* IPv4 address */
    } ip;
} ip_addr;

/* Make ip_addr
 */
static inline ip_addr
ip_addr_make (int ifindex, int af, const void *addr)
{
    ip_addr ip_addr;

    memset(&ip_addr, 0, sizeof(ip_addr));
    ip_addr.af = af;

    switch (ip_addr.af) {
    case AF_INET:
        memcpy(&ip_addr.ip.v4, addr, 4);
        break;

    case AF_INET6:
        memcpy(&ip_addr.ip, addr, 16);
        if (ip_is_linklocal(AF_INET6, &ip_addr.ip.v6)) {
            ip_addr.ifindex = ifindex;
        }
        break;
    }

    return ip_addr;
}

/* Extract ip_addr from sockaddr
 */
static inline ip_addr
ip_addr_from_sockaddr (const struct sockaddr *sockaddr)
{
    ip_addr addr;

    memset(&addr, 0, sizeof(addr));
    addr.af = sockaddr->sa_family;

    switch (addr.af) {
    case AF_INET:
        addr.ip.v4 = ((struct sockaddr_in*) sockaddr)->sin_addr;
        break;

    case AF_INET6:
        addr.ip.v6 = ((struct sockaddr_in6*) sockaddr)->sin6_addr;
        if (ip_is_linklocal(AF_INET6, &addr.ip.v6)) {
            addr.ifindex = ((struct sockaddr_in6*) sockaddr)->sin6_scope_id;
        }
        break;
    }

    return addr;
}

/* Format ip_addr into ip_straddr
 */
ip_straddr
ip_addr_to_straddr (ip_addr addr, bool withzone);

/* Check if two addresses are equal
 */
static inline bool
ip_addr_equal (ip_addr a1, ip_addr a2)
{
    if (a1.af != a2.af) {
        return false;
    }

    switch (a1.af) {
    case AF_INET:
        return a1.ip.v4.s_addr == a2.ip.v4.s_addr;
    case AF_INET6:
        return a1.ifindex == a2.ifindex &&
               !memcmp(a1.ip.v6.s6_addr, a2.ip.v6.s6_addr, 16);
    }

    return false;
}

/* ip_network represents IPv4 or IPv6 network (i.e., address with mask)
 */
typedef struct {
    ip_addr addr; /* Network address */
    int     mask; /* Network mask */
} ip_network;

/* Format ip_network into ip_straddr
 */
ip_straddr
ip_network_to_straddr (ip_network net);

/* Check if ip_network contains ip_addr
 */
bool
ip_network_contains (ip_network net, ip_addr addr);

/* ip_addr_set represents a set of IP addresses
 */
typedef struct ip_addrset ip_addrset;

/* Create new ip_addrset
 */
ip_addrset*
ip_addrset_new (void);

/* Free ip_addrset
 */
void
ip_addrset_free (ip_addrset *addrset);

/* Check if address is in set
 */
bool
ip_addrset_lookup (const ip_addrset *addrset, ip_addr addr);

/* Add address to the set. Returns true, if address was
 * actually added, false if it was already in the set
 */
bool
ip_addrset_add (ip_addrset *addrset, ip_addr addr);

/* Add address to the set without checking for duplicates
 */
void
ip_addrset_add_unsafe (ip_addrset *addrset, ip_addr addr);

/* Del address from the set.
 */
void
ip_addrset_del (ip_addrset *addrset, ip_addr addr);

/* Delete all addresses from the set
 */
void
ip_addrset_purge (ip_addrset *addrset);

/* Merge two sets:
 *   addrset += addrset2
 */
void
ip_addrset_merge (ip_addrset *addrset, const ip_addrset *addrset2);

/* Get access to array of addresses in the set
 */
const ip_addr*
ip_addrset_addresses (const ip_addrset *addrset, size_t *count);

/* Check if two address sets are intersecting
 */
bool
ip_addrset_is_intersect (const ip_addrset *set, const ip_addrset *set2);

/* Check if some of addresses in the address set is on the
 * given network
 */
bool
ip_addrset_on_network (const ip_addrset *set, ip_network net);

/* Check if address set has some addresses of the specified
 * address family
 */
bool
ip_addrset_has_af (const ip_addrset *set, int af);

/* Create user-friendly string out of set of addresses, containing
 * in the ip_addrset:
 *   * addresses are sorted, IP4 addresses goes first
 *   * link-local addresses are skipped, if there are non-link-local ones
 *
 * Caller must use mem_free to release the returned string when
 * it is not needed anymore
 */
char*
ip_addrset_friendly_str (const ip_addrset *set, char *s);

/******************** Network interfaces addresses ********************/
/* Network interface name, wrapped into structure, so
 * it can be passed by value
 */
typedef struct {
    char text[32];
} netif_name;

/* Network interface address
 */
typedef struct netif_addr netif_addr;
struct netif_addr {
    netif_addr *next;         /* Next address in the list */
    int        ifindex;       /* Interface index */
    netif_name ifname;        /* Interface name, for logging */
    bool       ipv6;          /* This is an IPv6 address */
    void       *data;         /* Placeholder for user data */
    char       straddr[64];   /* Address string */
    union {
        struct in_addr  v4;   /* IPv4 address */
        struct in6_addr v6;   /* IPv6 address */
    } ip;
};

/* NETIF_DISTANCE represents a distance to the target address
 */
typedef enum {
    NETIF_DISTANCE_LOOPBACK, /* Target address is host's local address */
    NETIF_DISTANCE_DIRECT,   /* Target is on a local network */
    NETIF_DISTANCE_ROUTED    /* Target is behind a router */
} NETIF_DISTANCE;

/* Get distance to the target address
 */
NETIF_DISTANCE
netif_distance_get (const struct sockaddr *addr);

/* Check that interface has non-link-local address
 * of particular address family
 */
bool
netif_has_non_link_local_addr (int af, int ifindex);

/* Compare addresses by distance. Returns:
 *   <0, if addr1 is closer that addr2
 *   >0, if addr2 is farther that addr2
 *   0 if distance is equal
 */
static inline int
netif_distance_cmp (const struct sockaddr *addr1, const struct sockaddr *addr2)
{
    int d1 = (int) netif_distance_get(addr1);
    int d2 = (int) netif_distance_get(addr2);

    return d1 - d2;
}

/* Get list of network interfaces addresses
 * The returned list is sorted
 */
netif_addr*
netif_addr_list_get (void);

/* Free list of network interfaces addresses
 */
void
netif_addr_list_free (netif_addr *list);

/* netif_diff represents a difference between two
 * lists of network interface addresses
 */
typedef struct {
    netif_addr *added, *removed; /* What was added/removed */
    netif_addr *preserved;
} netif_diff;

/* Compute a difference between two lists of addresses.
 *
 * It works by tossing nodes between 3 output lists:
 *   * if node is present in list2 only, it is moved
 *     to netif_diff.added
 *   * if node is present in list1 only, it is moved
 *     to netif_diff.removed
 *   * if node is present in both lists, node from
 *     list1 is moved to preserved, and node from
 *     list2 is released
 *
 * It assumes, both lists are sorted, as returned
 * by netif_addr_get(). Returned lists are also sorted
 */
netif_diff
netif_diff_compute (netif_addr *list1, netif_addr *list2);

/* Merge two lists of addresses
 *
 * Input lists are consumed and new list is created.
 *
 * Input lists are assumed to be sorted, and output
 * list will be sorted as well
 */
netif_addr*
netif_addr_list_merge (netif_addr *list1, netif_addr *list2);

/* Network interfaces addresses change notifier
 */
typedef struct netif_notifier netif_notifier;

/* Create netif_notifier
 */
netif_notifier*
netif_notifier_create (void (*callback) (void*), void *data);

/* Destroy netif_notifier
 */
void
netif_notifier_free (netif_notifier *notifier);

/* Initialize network interfaces monitoring
 */
SANE_Status
netif_init (void);

/* Cleanup network interfaces monitoring
 */
void
netif_cleanup (void);

/******************** Configuration file loader ********************/
/* Device URI for manually disabled device
 */
#define CONF_DEVICE_DISABLE     "disable"

/* Device configuration, for manually added devices
 */
typedef struct conf_device conf_device;
struct conf_device {
    unsigned int devid; /* Device ident */
    const char   *name; /* Device name */
    ID_PROTO     proto; /* Protocol to use */
    http_uri     *uri;  /* Device URI, parsed; NULL if device disabled */
    conf_device  *next; /* Next device in the list */
};

/* WSDD_MODE represents WS-Discovery mode
 */
typedef enum {
    WSDD_FAST,  /* Use hints from DNS-SD to speed up WSDD */
    WSDD_FULL,  /* Full discovery, slow and fair */
    WSDD_OFF    /* Disable WSDD */
} WSDD_MODE;

/* Device blacklist entry
 */
typedef struct conf_blacklist conf_blacklist;
struct conf_blacklist {
    const char     *model;   /* If not NULL, match by model */
    const char     *name;    /* If not NULL, match by network name */
    ip_network     net;      /* if net.addr.af != AF_UNSPEC, match by net */
    conf_blacklist *next;    /* Next entry in the list */
};

/* Backend configuration
 */
typedef struct {
    bool           dbg_enabled;      /* Debugging enabled */
    const char     *dbg_trace;       /* Trace directory */
    bool           dbg_hexdump;      /* Hexdump all traffic to the trace */
    conf_device    *devices;         /* Manually configured devices */
    bool           discovery;        /* Scanners discovery enabled */
    bool           model_is_netname; /* Use network name instead of model */
    bool           proto_auto;       /* Auto protocol selection */
    WSDD_MODE      wsdd_mode;        /* WS-Discovery mode */
    const char     *socket_dir;      /* Directory for AF_UNIX sockets */
    conf_blacklist *blacklist;       /* Devices blacklisted for discovery */
    bool           pretend_local;    /* Pretend devices are local */
} conf_data;

#define CONF_INIT {                     \
        .dbg_enabled = false,           \
        .dbg_trace = NULL,              \
        .dbg_hexdump = false,           \
        .devices = NULL,                \
        .discovery = true,              \
        .model_is_netname = true,       \
        .proto_auto = true,             \
        .wsdd_mode = WSDD_FAST,         \
        .socket_dir = NULL,             \
        .pretend_local = false          \
    }

extern conf_data conf;

/* Load configuration. It updates content of a global conf variable
 */
void
conf_load (void);

/* Free resources, allocated by conf_load, and reset configuration
 * data into initial state
 */
void
conf_unload (void);

/******************** Pollable events ********************/
/* The pollable event
 *
 * Pollable events allow to wait until some event happens
 * and can be used in combination with select()/poll()
 * system calls
 */
typedef struct pollable pollable;

/* Create new pollable event
 */
pollable*
pollable_new (void);

/* Free pollable event
 */
void
pollable_free (pollable *p);

/* Get file descriptor for poll()/select().
 *
 * When pollable event becomes "ready", this file descriptor
 * becomes readable from the select/poll point of view
 */
int
pollable_get_fd (pollable *p);

/* Make pollable event "ready"
 */
void
pollable_signal (pollable *p);

/* Make pollable event "not ready"
 */
void
pollable_reset (pollable *p);

/* Wait until pollable event is ready
 */
void
pollable_wait (pollable *p);

/******************** Time stamps ********************/
/* timestamp represents a monotonic time, in milliseconds
 */
typedef int64_t timestamp;

/* timestamp_now() returns a current time as timestamp
 */
static inline timestamp
timestamp_now (void)
{
    struct timespec t;

    clock_gettime(CLOCK_MONOTONIC, &t);
    return (timestamp) t.tv_sec * 1000 + (timestamp) t.tv_nsec / 1000000;
}

/******************** Event loop ********************/
/* Initialize event loop
 */
SANE_Status
eloop_init (void);

/* Cleanup event loop
 */
void
eloop_cleanup (void);

/* Add start/stop callback. This callback is called
 * on a event loop thread context, once when event
 * loop is started, and second time when it is stopped
 *
 * Start callbacks are called in the same order as
 * they were added. Stop callbacks are called in a
 * reverse order
 */
void
eloop_add_start_stop_callback (void (*callback) (bool start));

/* Start event loop thread.
 */
void
eloop_thread_start (void);

/* Stop event loop thread and wait until its termination
 */
void
eloop_thread_stop (void);

/* Acquire event loop mutex
 */
void
eloop_mutex_lock (void);

/* Release event loop mutex
 */
void
eloop_mutex_unlock (void);

/* Wait on conditional variable under the event loop mutex
 */
void
eloop_cond_wait (pthread_cond_t *cond);

/* Get AvahiPoll that runs in event loop thread
 */
const AvahiPoll*
eloop_poll_get (void);

/* ELOOP_CALL_BADID is the invalid callid which will never be returned by
 * the eloop_call().
 *
 * It is safe to use ELOOP_CALL_BADID as parameter to eloop_call_cancel().
 * Calling eloop_call_cancel(ELOOP_CALL_BADID) is guaranteed to do nothing.
 */
#define ELOOP_CALL_BADID        (~(uint64_t) 0)

/* Call function on a context of event loop thread
 * The returned value can be supplied as a `callid'
 * parameter for the eloop_call_cancel() function
 */
uint64_t
eloop_call (void (*func)(void*), void *data);

/* Cancel pending eloop_call
 *
 * This is safe to cancel already finished call (at this
 * case nothing will happen)
 */
void
eloop_call_cancel (uint64_t callid);

/* Event notifier. Calls user-defined function on a context
 * of event loop thread, when event is triggered. This is
 * safe to trigger the event from a context of any thread
 * or even from a signal handler
 */
typedef struct eloop_event eloop_event;

/* Create new event notifier. May return NULL
 */
eloop_event*
eloop_event_new (void (*callback)(void *), void *data);

/* Destroy event notifier
 */
void
eloop_event_free (eloop_event *event);

/* Trigger an event
 */
void
eloop_event_trigger (eloop_event *event);

/* Timer. Calls user-defined function after a specified
 * interval
 */
typedef struct eloop_timer eloop_timer;

/* Create new timer. Timeout is in milliseconds
 */
eloop_timer*
eloop_timer_new (int timeout, void (*callback)(void *), void *data);

/* Cancel a timer
 *
 * Caller SHOULD NOT cancel expired timer (timer with called
 * callback) -- this is done automatically
 */
void
eloop_timer_cancel (eloop_timer *timer);

/* eloop_fdpoll notifies user when file becomes
 * readable, writable or both, depending on its
 * event mask
 */
typedef struct eloop_fdpoll eloop_fdpoll;

/* Mask of file events user interested in
 */
typedef enum {
    ELOOP_FDPOLL_READ  = (1 << 0),
    ELOOP_FDPOLL_WRITE = (1 << 1),
    ELOOP_FDPOLL_BOTH  = ELOOP_FDPOLL_READ | ELOOP_FDPOLL_WRITE
} ELOOP_FDPOLL_MASK;

/* Convert ELOOP_FDPOLL_MASK to string. Used for logging.
 */
const char*
eloop_fdpoll_mask_str (ELOOP_FDPOLL_MASK mask);

/* Create eloop_fdpoll
 *
 * Callback will be called, when file will be ready for read/write/both,
 * depending on mask
 *
 * Initial mask value is 0, and it can be changed, using
 * eloop_fdpoll_set_mask() function
 */
eloop_fdpoll*
eloop_fdpoll_new (int fd,
        void (*callback) (int, void*, ELOOP_FDPOLL_MASK), void *data);

/* Destroy eloop_fdpoll
 */
void
eloop_fdpoll_free (eloop_fdpoll *fdpoll);

/* Set eloop_fdpoll event mask. It returns a previous value of event mask
 */
ELOOP_FDPOLL_MASK
eloop_fdpoll_set_mask (eloop_fdpoll *fdpoll, ELOOP_FDPOLL_MASK mask);

/* Format error string, as printf() does and save result
 * in the memory, owned by the event loop
 *
 * Caller should not free returned string. This is safe
 * to use the returned string as an argument to the
 * subsequent eloop_eprintf() call.
 *
 * The returned string remains valid until next call
 * to eloop_eprintf(), which makes it usable to
 * report errors up by the stack. However, it should
 * not be assumed, that the string will remain valid
 * on a next eloop roll, so don't save this string
 * anywhere, if you need to do so, create a copy!
 */
error
eloop_eprintf(const char *fmt, ...);

/******************** HTTP Client ********************/
/* Create new URI, by parsing URI string
 */
http_uri*
http_uri_new (const char *str, bool strip_fragment);

/* Clone an URI
 */
http_uri*
http_uri_clone (const http_uri *old);

/* Create URI, relative to base URI. If `path_only' is
 * true, scheme, host and port are taken from the
 * base URI
 */
http_uri*
http_uri_new_relative (const http_uri *base, const char *path,
        bool strip_fragment, bool path_only);

/* Free the URI
 */
void
http_uri_free (http_uri *uri);

/* Get URI string
 */
const char*
http_uri_str (http_uri *uri);

/* Get URI's host address. If Host address is not literal, returns NULL
 */
const struct sockaddr*
http_uri_addr (const http_uri *uri);

/* Get URI's address family. May return AF_UNSPEC,
 * if host address is not literal
 */
static inline int
http_uri_af (const http_uri *uri)
{
    const struct sockaddr *addr = http_uri_addr(uri);
    return addr ? addr->sa_family : AF_UNSPEC;
}

/* Tell if URI host is literal IP address
 */
static inline bool
http_uri_is_literal (const http_uri *uri)
{
    return http_uri_addr(uri) != NULL;
}

/* Tell if URI IP address is loopback
 */
static inline bool
http_uri_is_loopback (const http_uri *uri)
{
    const struct sockaddr *addr = http_uri_addr(uri);
    const void            *ip = NULL;

    if (addr == NULL) {
        return false;
    }

    switch (addr->sa_family) {
    case AF_INET:
        ip = &(((struct sockaddr_in*) addr)->sin_addr);
        break;

    case AF_INET6:
        ip = &(((struct sockaddr_in6*) addr)->sin6_addr);
        break;
    }

    if (ip != NULL) {
        return ip_is_loopback(addr->sa_family, ip);
    }

    return false;
}

/* Get URI path
 *
 * Note, if URL has empty path (i.e., "http://1.2.3.4"), the
 * empty string will be returned
 */
const char*
http_uri_get_path (const http_uri *uri);

/* Set URI path
 */
void
http_uri_set_path (http_uri *uri, const char *path);

/* Get URI host. It returns only host name, port number is
 * not included.
 *
 * IPv6 literal addresses are returned in square brackets
 * (i.e., [fe80::217:c8ff:fe7b:6a91%4])
 *
 * Note, the subsequent modifications of URI, such as http_uri_fix_host(),
 * http_uri_fix_ipv6_zone() etc, may make the returned string invalid,
 * so if you need to keep it for a long time, better make a copy
 */
const char*
http_uri_get_host (const http_uri *uri);

/* http_uri_host_is checks if URI's host name is equal to the
 * specified string.
 *
 * It does its best to compare domain names correctly, taking
 * in account only significant difference (for example, the difference
 * in upper/lower case * in domain names is not significant).
 */
bool
http_uri_host_is (const http_uri *uri, const char *host);

/* http_uri_host_is_literal returns true if URI uses literal
 * IP address
 */
bool
http_uri_host_is_literal (const http_uri *uri);

/* Set URI host into the literal IP address.
 */
void
http_uri_set_host_addr (http_uri *uri, ip_addr addr);

/* Fix URI host: if `match` is NULL or uri's host matches `match`,
 * replace uri's host and port with values taken from the base_uri
 */
void
http_uri_fix_host (http_uri *uri, const http_uri *base_uri, const char *match);

/* Fix IPv6 address zone suffix
 */
void
http_uri_fix_ipv6_zone (http_uri *uri, int ifindex);

/* Strip zone suffix from literal IPv6 host address
 *
 * If address is not IPv6 or doesn't have zone suffix, it is
 * not changed
 */
void
http_uri_strip_zone_suffux (http_uri *uri);

/* Make sure URI's path ends with the slash character
 */
void
http_uri_fix_end_slash (http_uri *uri);

/* Check if 2 URIs are equal
 */
bool
http_uri_equal (const http_uri *uri1, const http_uri *uri2);

/* HTTP data
 */
typedef struct {
    const char *content_type; /* Normalized: low-case with stripped directives */
    const void *bytes;        /* Data bytes */
    size_t     size;          /* Data size */
} http_data;

/* Ref http_data
 */
http_data*
http_data_ref (http_data *data);

/* Unref http_data
 */
void
http_data_unref (http_data *data);

/* http_data_queue represents a queue of http_data items
 */
typedef struct http_data_queue http_data_queue;

/* Create new http_data_queue
 */
http_data_queue*
http_data_queue_new (void);

/* Destroy http_data_queue
 */
void
http_data_queue_free (http_data_queue *queue);

/* Push item into the http_data_queue.
 */
void
http_data_queue_push (http_data_queue *queue, http_data *data);

/* Pull an item from the http_data_queue. Returns NULL if queue is empty
 */
http_data*
http_data_queue_pull (http_data_queue *queue);

/* Get queue length
 */
int
http_data_queue_len (const http_data_queue *queue);

/* Check if queue is empty
 */
static inline bool
http_data_queue_empty (const http_data_queue *queue)
{
    return http_data_queue_len(queue) == 0;
}

/* Purge the queue
 */
void
http_data_queue_purge (http_data_queue *queue);

/* Type http_client represents HTTP client instance
 */
typedef struct http_client http_client;

/* Create new http_client
 */
http_client*
http_client_new (log_ctx *log, void *ptr);

/* Destroy http_client
 */
void
http_client_free (http_client *client);

/* Set on-error callback. If this callback is not NULL,
 * in a case of transport error it will be called instead
 * of the http_query callback
 */
void
http_client_onerror (http_client *client,
        void (*callback)(void *ptr, error err));

/* Cancel all pending queries, if any
 */
void
http_client_cancel (http_client *client);

/* Set timeout of all pending queries, if any. Timeout is in milliseconds
 */
void
http_client_timeout (http_client *client, int timeout);

/* Check if client has pending queries
 */
bool
http_client_has_pending (const http_client *client);

/* Type http_query represents HTTP query (both request and response)
 */
typedef struct http_query http_query;

/* Create new http_query
 *
 * Newly created http_query takes ownership on uri and body (if not NULL).
 * The method and content_type assumed to be constant strings.
 */
http_query*
http_query_new (http_client *client, http_uri *uri, const char *method,
        char *body, const char *content_type);

/* Create new http_query
 *
 * Newly created http_query takes ownership on uri and body (if not NULL).
 * The method and content_type assumed to be constant strings.
 */
http_query*
http_query_new_len (http_client *client, http_uri *uri, const char *method,
        void *body, size_t body_len, const char *content_type);

/* Create new http_query, relative to base URI
 *
 * Newly created http_query takes ownership on body (if not NULL).
 * The method and content_type assumed to be constant strings.
 */
http_query*
http_query_new_relative(http_client *client,
        const http_uri *base_uri, const char *path,
        const char *method, char *body, const char *content_type);

/* Set query timeout, in milliseconds. Negative timeout means 'infinite'
 *
 * This function may be called multiple times (each subsequent call overrides
 * a previous one)
 */
void
http_query_timeout (http_query *q, int timeout);

/* Set 'no_need_response_body' flag
 *
 * This flag notifies, that http_query issued is only interested
 * in the HTTP response headers, not body
 *
 * If this flag is set, after successful reception of response
 * HTTP header, errors in fetching response body is ignored
 */
void
http_query_no_need_response_body (http_query *q);

/* Set forcing port to be added to the Host header for this query.
 *
 * This function may be called multiple times (each subsequent call overrides
 * a previous one).
 */
void
http_query_force_port(http_query *q, bool force_port);

/* For this particular query override on-error callback, previously
 * set by http_client_onerror()
 *
 * If canllback is NULL, the completion callback, specified on a
 * http_query_submit() call, will be used even in a case of
 * transport error.
 */
void
http_query_onerror (http_query *q, void (*onerror)(void *ptr, error err));

/* Set on-redirect callback. It is called in a case of HTTP
 * redirect and may modify the supplied URI
 */
void
http_query_onredir (http_query *q,
        void (*onredir)(void *ptr, http_uri *uri, const http_uri *orig_uri));

/* Set callback that will be called, when response headers reception
 * is completed
 */
void
http_query_onrxhdr (http_query *q, void (*onrxhdr)(void *ptr, http_query *q));

/* Submit the query.
 *
 * When query is finished, callback will be called. After return from
 * callback, memory, owned by http_query will be invalidated
 */
void
http_query_submit (http_query *q, void (*callback)(void *ptr, http_query *q));

/* Get http_query timestamp. Timestamp is set when query is
 * submitted. And this function should not be called before
 * http_query_submit()
 */
timestamp
http_query_timestamp (const http_query *q);

/* Set uintptr_t parameter, associated with query.
 * Completion callback may later use http_query_get_uintptr()
 * to fetch this value
 */
void
http_query_set_uintptr (http_query *q, uintptr_t u);

/* Get uintptr_t parameter, previously set by http_query_set_uintptr()
 */
uintptr_t
http_query_get_uintptr (http_query *q);

/* Get query error, if any
 *
 * Both transport errors and erroneous HTTP response codes
 * considered as errors here
 */
error
http_query_error (const http_query *q);

/* Get query transport error, if any
 *
 * Only transport errors considered errors here
 */
error
http_query_transport_error (const http_query *q);

/* Get HTTP status code. Code not available, if query finished
 * with error
 */
int
http_query_status (const http_query *q);

/* Get HTTP status string
 */
const char*
http_query_status_string (const http_query *q);

/* Get query URI
 *
 * It works as http_query_orig_uri() before query is submitted
 * or after it is completed, and as http_query_real_uri() in
 * between
 *
 * This function is deprecated, use http_query_orig_uri()
 * or http_query_real_uri() instead
 */
http_uri*
http_query_uri (const http_query *q);

/* Get original URI (the same as used when http_query was created)
 */
http_uri*
http_query_orig_uri (const http_query *q);

/* Get real URI, that can differ from the requested URI
 * in a case of HTTP redirection
 */
http_uri*
http_query_real_uri (const http_query *q);

/* Get query method
 */
const char*
http_query_method (const http_query *q);

/* Set request header
 */
void
http_query_set_request_header (http_query *q, const char *name,
        const char *value);

/* Get request header
 */
const char*
http_query_get_request_header (const http_query *q, const char *name);

/* Get response header
 */
const char*
http_query_get_response_header (const http_query *q, const char *name);

/* Get request data
 *
 * You need to http_data_ref(), if you want data to remain valid
 * after query end of life
 */
http_data*
http_query_get_request_data (const http_query *q);

/* Get request data
 *
 * You need to http_data_ref(), if you want data to remain valid
 * after query end of life
 */
http_data*
http_query_get_response_data (const http_query *q);

/* Get count of parts of multipart response
 */
int
http_query_get_mp_response_count (const http_query *q);

/* Get data of Nth part of multipart response
 *
 * You need to http_data_ref(), if you want data to remain valid
 * after query end of life
 */
http_data*
http_query_get_mp_response_data (const http_query *q, int n);

/* Call callback for each request header
 */
void
http_query_foreach_request_header (const http_query *q,
        void (*callback)(const char *name, const char *value, void *ptr),
        void *ptr);

/* Call callback for each response header
 */
void
http_query_foreach_response_header (const http_query *q,
        void (*callback)(const char *name, const char *value, void *ptr),
        void *ptr);

/* Decode response part of the query.
 * This function is intended for testing purposes, not for regular use
 */
error
http_query_test_decode_response (http_query *q, const void *data, size_t size);

/* HTTP schemes
 */
typedef enum {
    HTTP_SCHEME_UNSET = -1,
    HTTP_SCHEME_HTTP,
    HTTP_SCHEME_HTTPS,
    HTTP_SCHEME_UNIX
} HTTP_SCHEME;

/* Some HTTP status codes
 */
#ifndef NO_HTTP_STATUS
enum {
    HTTP_STATUS_OK                  = 200,
    HTTP_STATUS_CREATED             = 201,
    HTTP_STATUS_NOT_FOUND           = 404,
    HTTP_STATUS_GONE                = 410,
    HTTP_STATUS_SERVICE_UNAVAILABLE = 503
};
#endif

/* Initialize HTTP client
 */
SANE_Status
http_init (void);

/* Initialize HTTP client
 */
void
http_cleanup (void);

/******************** Protocol trace ********************/
/* Type trace represents an opaque handle of trace
 * file
 */
typedef struct trace trace;

/* Initialize protocol trace. Called at backend initialization
 */
SANE_Status
trace_init (void);

/* Cleanup protocol trace. Called at backend unload
 */
void
trace_cleanup (void);

/* Open protocol trace
 */
trace*
trace_open (const char *device_name);

/* Ref the trace
 */
trace*
trace_ref (trace *t);

/* Unref the trace. When trace is not longer in use, it will be closed
 */
void
trace_unref (trace *t);

/* This hook is called on every http_query completion
 */
void
trace_http_query_hook (trace *t, http_query *q);

/* Printf to the trace log
 */
void
trace_printf (trace *t, const char *fmt, ...);

/* Note an error in trace log
 */
void
trace_error (trace *t, error err);

/* Dump message body
 */
void
trace_dump_body (trace *t, http_data *data);

/* Dump binary data (as hex dump)
 * Each line is prefixed with the `prefix` character
 */
void
trace_hexdump (trace *t, char prefix, const void *data, size_t size);

/******************** SANE_Word/SANE_String arrays ********************/
/* Create array of SANE_Word
 */
static inline SANE_Word*
sane_word_array_new (void)
{
    return mem_new(SANE_Word,1);
}

/* Free array of SANE_Word
 */
static inline void
sane_word_array_free (SANE_Word *a)
{
    mem_free(a);
}

/* Reset array of SANE_Word
 */
static inline void
sane_word_array_reset (SANE_Word **a)
{
    (*a)[0] = 0;
}

/* Get length of the SANE_Word array
 */
static inline size_t
sane_word_array_len (const SANE_Word *a)
{
    return (size_t) a[0];
}

/* Append word to array. Returns new array (old becomes invalid)
 */
static inline SANE_Word*
sane_word_array_append (SANE_Word *a, SANE_Word w)
{
    size_t len = sane_word_array_len(a) + 1;
    a = mem_resize(a, len + 1, 0);
    a[0] = len;
    a[len] = w;
    return a;
}

/* Drop array elements that outside of specified boundary
 */
void
sane_word_array_bound (SANE_Word *a, SANE_Word min, SANE_Word max);

/* Sort array of SANE_Word in increasing order
 */
void
sane_word_array_sort (SANE_Word *a);

/* Intersect two sorted arrays.
 */
SANE_Word*
sane_word_array_intersect_sorted ( const SANE_Word *a1, const SANE_Word *a2);

/* Create array of SANE_String
 */
static inline SANE_String*
sane_string_array_new (void)
{
    return ptr_array_new(SANE_String);
}

/* Free array of SANE_String
 */
static inline void
sane_string_array_free (SANE_String *a)
{
    mem_free(a);
}

/* Reset array of SANE_String
 */
static inline void
sane_string_array_reset (SANE_String *a)
{
    ptr_array_trunc(a);
}

/* Get length of the SANE_String array
 */
static inline size_t
sane_string_array_len (const SANE_String *a)
{
    return mem_len(a);
}

/* Append string to array Returns new array (old becomes invalid)
 */
static inline SANE_String*
sane_string_array_append(SANE_String *a, SANE_String s)
{
    return ptr_array_append(a, s);
}

/* Compute max string length in array of strings
 */
size_t
sane_string_array_max_strlen(const SANE_String *a);

/* Create array of SANE_Device
 */
static inline const SANE_Device**
sane_device_array_new (void)
{
    return ptr_array_new(const SANE_Device*);
}

/* Free array of SANE_Device
 */
static inline void
sane_device_array_free (const SANE_Device **a)
{
    mem_free(a);
}

/* Get length of the SANE_Device array
 */
static inline size_t
sane_device_array_len (const SANE_Device * const *a)
{
    return mem_len(a);
}

/* Append device to array. Returns new array (old becomes invalid)
 */
static inline const SANE_Device**
sane_device_array_append(const SANE_Device **a, SANE_Device *d)
{
    return ptr_array_append(a, d);
}

/******************** XML utilities ********************/
/* xml_ns defines XML namespace.
 *
 * For XML writer namespaces are simply added to the root
 * node attributes
 *
 * XML reader performs prefix substitutions
 *
 * If namespace substitution is enabled, for each note, if its
 * namespace matches the pattern, will be reported with name prefix
 * defined by substitution rule, regardless of prefix actually used
 * in the document
 *
 * Example:
 *   <namespace:nodes xmlns:namespace="http://www.example.com/namespace">
 *     <namespace:node1/>
 *     <namespace:node2/>
 *     <namespace:node3/>
 *   </namespace:nodes>
 *
 *   rule: {"ns", "http://www.example.com/namespace"}
 *
 * With this rule set, all nodes will be reported as if they
 * had the "ns" prefix, though actually their prefix in document
 * is different
 *
 * XML reader interprets namespace uri as a glob-style pattern,
 * as used by fnmatch (3) function with flags = 0
 */
typedef struct {
    const char *prefix; /* Short prefix */
    const char *uri;    /* The namespace uri (glob pattern for reader) */
} xml_ns;

/* xml_attr represents an XML attribute.
 *
 * Attributes are supported by XML writer. Array of attributes
 * is terminated by the {NULL, NULL} attribute
 */
typedef struct {
    const char *name;   /* Attribute name */
    const char *value;  /* Attribute value */
} xml_attr;

/* XML reader
 */
typedef struct xml_rd xml_rd;

/* Parse XML text and initialize reader to iterate
 * starting from the root node
 *
 * The 'ns' argument, if not NULL, points to array of substitution
 * rules. Last element must have NULL prefix and url
 *
 * Array of rules considered to be statically allocated
 * (at least, it can remain valid during reader life time)
 *
 * On success, saves newly constructed reader into
 * the xml parameter.
 */
error
xml_rd_begin (xml_rd **xml, const char *xml_text, size_t xml_len,
        const xml_ns *ns);

/* Finish reading, free allocated resources
 */
void
xml_rd_finish (xml_rd **xml);

/* Get current node depth in the tree. Root depth is 0
 */
unsigned int
xml_rd_depth (xml_rd *xml);

/* Check for end-of-document condition
 */
bool
xml_rd_end (xml_rd *xml);

/* Shift to the next node
 */
void
xml_rd_next (xml_rd *xml);

/* Shift to the next node, visiting the nested nodes on the way
 *
 * If depth > 0, it will not return from nested nodes
 * upper the specified depth
 */
void
xml_rd_deep_next (xml_rd *xml, unsigned int depth);

/* Enter the current node - iterate its children
 */
void
xml_rd_enter (xml_rd *xml);

/* Leave the current node - return to its parent
 */
void
xml_rd_leave (xml_rd *xml);

/* Get name of the current node.
 *
 * The returned string remains valid, until reader is cleaned up
 * or current node is changed (by set/next/enter/leave operations).
 * You don't need to free this string explicitly
 */
const char*
xml_rd_node_name (xml_rd *xml);

/* Get full path to the current node, '/'-separated
 */
const char*
xml_rd_node_path (xml_rd *xml);

/* Match name of the current node against the pattern
 */
bool
xml_rd_node_name_match (xml_rd *xml, const char *pattern);

/* Get value of the current node as text
 *
 * The returned string remains valid, until reader is cleaned up
 * or current node is changed (by set/next/enter/leave operations).
 * You don't need to free this string explicitly
 */
const char*
xml_rd_node_value (xml_rd *xml);

/* Get value of the current node as unsigned integer
 */
error
xml_rd_node_value_uint (xml_rd *xml, SANE_Word *val);

/* XML writer
 */
typedef struct xml_wr xml_wr;

/* Begin writing XML document. Root node will be created automatically
 *
 * The ns parameter must be terminated by {NULL, NULL} structure
 */
xml_wr*
xml_wr_begin (const char *root, const xml_ns *ns);

/* Finish writing, generate document string.
 * Caller must g_free() this string after use
 */
char*
xml_wr_finish (xml_wr *xml);

/* Like xml_wr_finish, but returns compact representation
 * of XML (without indentation and new lines)
 */
char*
xml_wr_finish_compact (xml_wr *xml);

/* Add node with textual value
 */
void
xml_wr_add_text (xml_wr *xml, const char *name, const char *value);

/* Add text node with attributes
 */
void
xml_wr_add_text_attr (xml_wr *xml, const char *name, const char *value,
        const xml_attr *attrs);

/* Add node with unsigned integer value
 */
void
xml_wr_add_uint (xml_wr *xml, const char *name, unsigned int value);

/* Add node with unsigned integer value and attributes
 */
void
xml_wr_add_uint_attr (xml_wr *xml, const char *name, unsigned int value,
        const xml_attr *attrs);

/* Add node with boolean value
 */
void
xml_wr_add_bool (xml_wr *xml, const char *name, bool value);

/* Add node with boolean value and attributes
 */
void
xml_wr_add_bool_attr (xml_wr *xml, const char *name, bool value,
        const xml_attr *attrs);

/* Create node with children and enter newly added node
 */
void
xml_wr_enter (xml_wr *xml, const char *name);

/* xml_wr_enter with attributes
 */
void
xml_wr_enter_attr (xml_wr *xml, const char *name, const xml_attr *attrs);

/* Leave the current node
 */
void
xml_wr_leave (xml_wr *xml);

/* Format XML to file. It either succeeds, writes a formatted XML
 * and returns true, or fails, writes nothing to file and returns false
 */
bool
xml_format (FILE *fp, const char *xml_text, size_t xml_len);

/******************** Sane Options********************/
/* Options numbers, for internal use
 */
enum {
    OPT_NUM_OPTIONS,            /* Total number of options */

    /* Standard options group */
    OPT_GROUP_STANDARD,
    OPT_SCAN_RESOLUTION,
    OPT_SCAN_COLORMODE,         /* I.e. color/grayscale etc */
    OPT_SCAN_INTENT,            /* Document/Photo etc */
    OPT_SCAN_SOURCE,            /* Platem/ADF/ADF Duplex */

    /* Geometry options group */
    OPT_GROUP_GEOMETRY,
    OPT_SCAN_TL_X,
    OPT_SCAN_TL_Y,
    OPT_SCAN_BR_X,
    OPT_SCAN_BR_Y,

    /* Image enhancement group */
    OPT_GROUP_ENHANCEMENT,
    OPT_BRIGHTNESS,
    OPT_CONTRAST,
    OPT_SHADOW,
    OPT_HIGHLIGHT,
    OPT_GAMMA,
    OPT_NEGATIVE,

    /* Read-only options for ADF justification */
    OPT_JUSTIFICATION_X,
    OPT_JUSTIFICATION_Y,

    /* Total count of options, computed by compiler */
    NUM_OPTIONS
};

/* String constants for certain SANE options values
 * (missed from sane/sameopt.h)
 */
#define OPTVAL_SOURCE_PLATEN        "Flatbed"
#define OPTVAL_SOURCE_ADF_SIMPLEX   "ADF"
#define OPTVAL_SOURCE_ADF_DUPLEX    "ADF Duplex"
#define OPTVAL_JUSTIFICATION_LEFT   "left"
#define OPTVAL_JUSTIFICATION_CENTER "center"
#define OPTVAL_JUSTIFICATION_RIGHT  "right"
#define OPTVAL_JUSTIFICATION_TOP    "top"
#define OPTVAL_JUSTIFICATION_BOTTOM "bottom"

/* Define options not included in saneopts.h */
#define SANE_NAME_ADF_JUSTIFICATION_X  "adf-justification-x"
#define SANE_TITLE_ADF_JUSTIFICATION_X SANE_I18N("ADF Width Justification")
#define SANE_DESC_ADF_JUSTIFICATION_X  \
        SANE_I18N("ADF width justification (left/right/center)")

#define SANE_NAME_ADF_JUSTIFICATION_Y  "adf-justification-y"
#define SANE_TITLE_ADF_JUSTIFICATION_Y SANE_I18N("ADF Height Justification")
#define SANE_DESC_ADF_JUSTIFICATION_Y  \
        SANE_I18N("ADF height justification (top/bottom/center)")

/* Check if option belongs to image enhancement group
 */
static inline bool
opt_is_enhancement (int opt)
{
    return OPT_BRIGHTNESS <= opt && opt <= OPT_NEGATIVE;
}

/******************** Device Capabilities ********************/
/* Source flags
 */
enum {
    /* Supported Intents */
    DEVCAPS_SOURCE_INTENT_DOCUMENT      = (1 << 3),
    DEVCAPS_SOURCE_INTENT_TXT_AND_GRAPH = (1 << 4),
    DEVCAPS_SOURCE_INTENT_PHOTO         = (1 << 5),
    DEVCAPS_SOURCE_INTENT_PREVIEW       = (1 << 6),

    DEVCAPS_SOURCE_INTENT_ALL =
        DEVCAPS_SOURCE_INTENT_DOCUMENT |
        DEVCAPS_SOURCE_INTENT_TXT_AND_GRAPH |
        DEVCAPS_SOURCE_INTENT_PHOTO |
        DEVCAPS_SOURCE_INTENT_PREVIEW,

    /* How resolutions are defined */
    DEVCAPS_SOURCE_RES_DISCRETE = (1 << 7), /* Discrete resolutions */
    DEVCAPS_SOURCE_RES_RANGE    = (1 << 8), /* Range of resolutions */

    DEVCAPS_SOURCE_RES_ALL =
        DEVCAPS_SOURCE_RES_DISCRETE |
        DEVCAPS_SOURCE_RES_RANGE,

    /* Miscellaneous flags */
    DEVCAPS_SOURCE_HAS_SIZE = (1 << 12), /* max_width, max_height and
                                            derivatives are valid */

    /* Protocol dialects */
    DEVCAPS_SOURCE_PWG_DOCFMT      = (1 << 13), /* pwg:DocumentFormat */
    DEVCAPS_SOURCE_SCAN_DOCFMT_EXT = (1 << 14), /* scan:DocumentFormatExt */
};

/* Supported image formats
 */
#define DEVCAPS_FORMATS_SUPPORTED       \
    ((1 << ID_FORMAT_JPEG) |            \
     (1 << ID_FORMAT_PNG)  |            \
     (1 << ID_FORMAT_TIFF) |            \
     (1 << ID_FORMAT_BMP))

/* Supported color modes
 *
 * Note, currently the only image format we support is JPEG
 * With JPEG, ID_COLORMODE_BW1 cannot be supported
 */
#define DEVCAPS_COLORMODES_SUPPORTED    \
    ((1 << ID_COLORMODE_COLOR) |        \
     (1 << ID_COLORMODE_GRAYSCALE))

/* Source Capabilities (each device may contain multiple sources)
 */
typedef struct {
    unsigned int flags;                  /* Source flags */
    unsigned int colormodes;             /* Set of 1 << ID_COLORMODE */
    unsigned int formats;                /* Set of 1 << ID_FORMAT */
    unsigned int scanintents;            /* Set of 1 << ID_SCANINTENT */
    SANE_Word    min_wid_px, max_wid_px; /* Min/max width, in pixels */
    SANE_Word    min_hei_px, max_hei_px; /* Min/max height, in pixels */
    SANE_Word    *resolutions;           /* Discrete resolutions, in DPI */
    SANE_Range   res_range;              /* Resolutions range, in DPI */
    SANE_Range   win_x_range_mm;         /* Window x range, in mm */
    SANE_Range   win_y_range_mm;         /* Window y range, in mm */
} devcaps_source;

/* Allocate devcaps_source
 */
devcaps_source*
devcaps_source_new (void);

/* Free devcaps_source
 */
void
devcaps_source_free (devcaps_source *src);

/* Clone a source
 */
devcaps_source*
devcaps_source_clone (const devcaps_source *src);

/* Merge two sources, resulting the source that contains
 * only capabilities, supported by two input sources
 *
 * Returns NULL, if sources cannot be merged
 */
devcaps_source*
devcaps_source_merge (const devcaps_source *s1, const devcaps_source *s2);

/* Device Capabilities
 */
typedef struct {
    /* Fundamental values */
    const char     *protocol;            /* Protocol name */
    SANE_Word      units;                /* Size units, pixels per inch */

    /* Image compression */
    bool           compression_ok;       /* Compression params are supported */
    SANE_Range     compression_range;    /* Compression range */
    SANE_Word      compression_norm;     /* Normal compression */

    /* Sources */
    devcaps_source *src[NUM_ID_SOURCE];  /* Missed sources are NULL */

    /* ADF Justification */
    ID_JUSTIFICATION justification_x;   /* Width justification*/
    ID_JUSTIFICATION justification_y;   /* Height justification*/

} devcaps;

/* Initialize Device Capabilities
 */
void
devcaps_init (devcaps *caps);

/* Cleanup Device Capabilities
 */
void
devcaps_cleanup (devcaps *caps);

/* Reset Device Capabilities into initial state
 */
void
devcaps_reset (devcaps *caps);

/* Dump device capabilities, for debugging
 *
 * The 3rd parameter, 'trace' configures the debug level
 * (log_debug vs log_trace) of the generated output
 */
void
devcaps_dump (log_ctx *log, devcaps *caps, bool trace);

/******************** Device options ********************/
/* Scan options
 */
typedef struct {
    devcaps                caps;              /* Device capabilities */
    SANE_Option_Descriptor desc[NUM_OPTIONS]; /* Option descriptors */
    ID_SOURCE              src;               /* Current source */
    ID_COLORMODE           colormode_emul;    /* Current "emulated" color mode*/
    ID_COLORMODE           colormode_real;    /* Current real color mode*/
    ID_SCANINTENT          scanintent;        /* Current scan intent */
    SANE_Word              resolution;        /* Current resolution */
    SANE_Fixed             tl_x, tl_y;        /* Top-left x/y */
    SANE_Fixed             br_x, br_y;        /* Bottom-right x/y */
    SANE_Parameters        params;            /* Scan parameters */
    SANE_String            *sane_sources;     /* Sources, in SANE format */
    SANE_String            *sane_colormodes;  /* Color modes in SANE format */
    SANE_String            *sane_scanintents; /* Scan intents in SANE format */
    SANE_Fixed             brightness;        /* -100.0 ... +100.0 */
    SANE_Fixed             contrast;          /* -100.0 ... +100.0 */
    SANE_Fixed             shadow;            /* 0.0 ... +100.0 */
    SANE_Fixed             highlight;         /* 0.0 ... +100.0 */
    SANE_Fixed             gamma;             /* Small positive value */
    bool                   negative;          /* Flip black and white */

} devopt;

/* Initialize device options
 */
void
devopt_init (devopt *opt);

/* Cleanup device options
 */
void
devopt_cleanup (devopt *opt);

/* Set default option values. Before call to this function,
 * devopt.caps needs to be properly filled.
 */
void
devopt_set_defaults (devopt *opt);

/* Set device option
 */
SANE_Status
devopt_set_option (devopt *opt, SANE_Int option, void *value, SANE_Word *info);

/* Get device option
 */
SANE_Status
devopt_get_option (devopt *opt, SANE_Int option, void *value);

/******************** ZeroConf (device discovery) ********************/
/* Due to the way how device discovery is implemented, resolving
 * of device IP addresses are independent between IPv4/IPv6 protocols
 * and between different network interfaces
 *
 * It means that some of device addresses may be already discovered,
 * while others still pending
 *
 * From another hand, some of addresses that we hope to discover may
 * be not available at all. For example, device may have IPv4 address
 * but IPv6 address may be missed.
 *
 * So once we have at least one address discovered, we limit discovery
 * of another addresses by this constant.
 *
 * This parameter is common for both MDNS and WSDD worlds
 *
 * The timeout is in milliseconds
 */
#define ZEROCONF_PUBLISH_DELAY  1000

/* Common logging context for device discovery
 */
extern log_ctx *zeroconf_log;

/* zeroconf_device represents a single device
 */
typedef struct zeroconf_device zeroconf_device;

/* zeroconf_endpoint represents a device endpoint
 */
typedef struct zeroconf_endpoint zeroconf_endpoint;
struct zeroconf_endpoint {
    ID_PROTO          proto;     /* The protocol */
    http_uri          *uri;      /* I.e, "http://192.168.1.1:8080/eSCL/" */
    zeroconf_endpoint *next;     /* Next endpoint in the list */
};

/* ZEROCONF_METHOD represents a method how device was discovered
 * The same device may be discovered using multiple methods
 */
typedef enum {
    /* The following findings serve as indirect signs of
     * scanner presence in the network
     */
    ZEROCONF_MDNS_HINT,   /* Hint finding from MDNS world */

    /* The following findings are expected to bring actual
     * scanner endpoints
     */
    ZEROCONF_USCAN_TCP,   /* _uscan._tcp */
    ZEROCONF_USCANS_TCP,  /* _uscans._tcp */
    ZEROCONF_WSD,         /* WS-Discovery */

    NUM_ZEROCONF_METHOD
} ZEROCONF_METHOD;

/* zeroconf_finding represents a single device discovery finding.
 * Multiple findings can point to the same device, and even
 * endpoints may duplicate between findings (say, if the same
 * device found using multiple network interfaces or using various
 * discovery methods)
 *
 * zeroconf_finding are bound to method and interface index
 */
typedef struct {
    ZEROCONF_METHOD   method;     /* Discovery method */
    const char        *name;      /* Network-unique name, NULL for WSD */
    const char        *model;     /* Model name, may be NULL for
                                     WSDD non-scanner devices */
    uuid              uuid;       /* Device UUID */
    ip_addrset        *addrs;     /* Device addresses */
    int               ifindex;    /* Network interface index */
    zeroconf_endpoint *endpoints; /* List of endpoints */

    /* The following fields are reserved for zeroconf core
     * and should not be used by discovery providers
     */
    zeroconf_device   *device;    /* Device the finding points to */
    ll_node           list_node;  /* Node in device's list of findings */
} zeroconf_finding;

/* Compare two pointers to pointers to zeroconf_finding (zeroconf_finding**)
 * by index+name, for qsort
 */
int
zeroconf_finding_qsort_by_index_name (const void *p1, const void *p2);

/* Publish the zeroconf_finding.
 *
 * Memory, referred by the finding, remains owned by
 * caller, and caller is responsible to keep this
 * memory valid until zeroconf_finding_withdraw()
 * is called
 *
 * The 'endpoinds' field may be NULL. This mechanism is
 * used by WS-Discovery to notify zeroconf that scanning
 * for particular UUID has been finished, though without
 * success.
 */
void
zeroconf_finding_publish (zeroconf_finding *finding);

/* Withdraw the finding
 */
void
zeroconf_finding_withdraw (zeroconf_finding *finding);

/* Notify zeroconf subsystem that initial scan
 * for the method is done
 */
void
zeroconf_finding_done (ZEROCONF_METHOD method);

/* zeroconf_devinfo represents a device information
 */
typedef struct {
    const char        *ident;     /* Unique ident */
    const char        *name;      /* Human-friendly name */
    const char        *model;     /* Model name, for quirks. "" if unknown */
    zeroconf_endpoint *endpoints; /* Device endpoints */
} zeroconf_devinfo;

/* Initialize ZeroConf
 */
SANE_Status
zeroconf_init (void);

/* Cleanup ZeroConf
 */
void
zeroconf_cleanup (void);

/* Get list of devices, in SANE format
 */
const SANE_Device**
zeroconf_device_list_get (void);

/* Free list of devices, returned by zeroconf_device_list_get()
 */
void
zeroconf_device_list_free (const SANE_Device **dev_list);

/* Lookup device by ident (ident is reported as SANE_Device::name)
 * by zeroconf_device_list_get())
 *
 * Caller becomes owner of resources (name and list of endpoints),
 * referred by the returned zeroconf_devinfo
 *
 * Caller must free these resources, using zeroconf_devinfo_free()
 */
zeroconf_devinfo*
zeroconf_devinfo_lookup (const char *ident);

/* Free zeroconf_devinfo, returned by zeroconf_devinfo_lookup()
 */
void
zeroconf_devinfo_free (zeroconf_devinfo *devinfo);

/* Create new zeroconf_endpoint. Newly created endpoint
 * takes ownership of uri string
 */
zeroconf_endpoint*
zeroconf_endpoint_new (ID_PROTO proto, http_uri *uri);

/* Free single zeroconf_endpoint
 */
void
zeroconf_endpoint_free_single (zeroconf_endpoint *endpoint);

/* Create a copy of zeroconf_endpoint list
 */
zeroconf_endpoint*
zeroconf_endpoint_list_copy (const zeroconf_endpoint *list);

/* Free zeroconf_endpoint list
 */
void
zeroconf_endpoint_list_free (zeroconf_endpoint *list);

/* Sort list of endpoints
 */
zeroconf_endpoint*
zeroconf_endpoint_list_sort (zeroconf_endpoint *list);

/* Sort list of endpoints and remove duplicates
 */
zeroconf_endpoint*
zeroconf_endpoint_list_sort_dedup (zeroconf_endpoint *list);

/* Check if list of endpoints already contains the given
 * endpoint (i.e., endpoint with the same URI and protocol)
 */
bool
zeroconf_endpoint_list_contains (const zeroconf_endpoint *list,
        const zeroconf_endpoint *endpoint);

/* Check if endpoints list contains a non-link-local address
 * of the specified address family
 */
bool
zeroconf_endpoint_list_has_non_link_local_addr (int af,
        const zeroconf_endpoint *list);

/******************** MDNS Discovery ********************/
/* Called by zeroconf to notify MDNS about initial scan timer expiration
 */
void
mdns_initscan_timer_expired (void);

/* Initialize MDNS
 */
SANE_Status
mdns_init (void);

/* Cleanup MDNS
 */
void
mdns_cleanup (void);

/* mdns_resolver asynchronously resolves IP addresses using MDNS
 */
typedef struct mdns_resolver mdns_resolver;

/* mdns_query represents a single mdns_resolver query
 */
typedef struct mdns_query mdns_query;

/* mdns_resolver_new creates a new MDNS resolver
 */
mdns_resolver*
mdns_resolver_new (int ifindex);

/* mdns_resolver_free frees the mdns_resolver previously created
 * by mdns_resolver_new()
 */
void
mdns_resolver_free (mdns_resolver *resolver);

/* mdns_resolver_cancel cancels all pending queries
 */
void
mdns_resolver_cancel (mdns_resolver *resolver);

/* mdns_resolver_has_pending checks if resolver has pending queries
 */
bool
mdns_resolver_has_pending (mdns_resolver *resolver);

/* mdns_query_submit submits a new MDNS query for the specified domain
 * name. When resolving is done, successfully or not, callback will be
 * called
 *
 * The ptr parameter is passed to the callback without any interpretation
 * as a user-defined argument
 *
 * Answer is a set of discovered IP addresses. It is owned by resolver,
 * callback should not free it and should not assume that it is still
 * valid after return from callback
 */
mdns_query*
mdns_query_submit (mdns_resolver *resolver,
                   const char *name,
                   void (*callback)(const mdns_query *query),
                   void *ptr);

/* mdns_query_cancel cancels the pending query. mdns_query memory will
 * be released and callback will not be called
 *
 * Note, mdns_query pointer is valid when obtained from mdns_query_sumbit
 * and until canceled or return from callback.
 */
void
mdns_query_cancel (mdns_query *query);

/* mdns_query_get_name returns domain name, as it was specified
 * when query was submitted
 */
const char*
mdns_query_get_name (const mdns_query *query);

/* mdns_query_get_answer returns resolved addresses
 */
const ip_addrset*
mdns_query_get_answer (const mdns_query *query);

/* mdns_query_set_ptr gets the user-defined ptr, associated
 * with query when it was submitted
 */
void*
mdns_query_get_ptr (const mdns_query *query);

/* mdns_device_count_by_model returns count of distinct devices
 * with model names matching the specified parent.
 *
 * Several instances of the same device (i.e. printer vs scanner) are
 * counted only once per network interface.
 *
 * WSDD uses this function to decide when to use extended discovery
 * time (some devices are known to be hard for WD-Discovery)
 *
 * Pattern is the glob-style expression, applied to the model name
 * of discovered devices.
 */
unsigned int
mdns_device_count_by_model (int ifindex, const char *pattern);

/******************** WS-Discovery ********************/
/* Called by zeroconf to notify wsdd about initial scan timer expiration
 */
void
wsdd_initscan_timer_expired (void);

/* Send WD-Discovery directed probe
 */
void
wsdd_send_directed_probe (int ifindex, int af, const void *addr);

/* Initialize WS-Discovery
 */
SANE_Status
wsdd_init (void);

/* Cleanup WS-Discovery
 */
void
wsdd_cleanup (void);

/******************** Device Management ********************/
/* Type device represents a scanner device
 */
typedef struct device device;

/* Open a device
 */
device*
device_open (const char *name, SANE_Status *status);

/* Close the device
 * If log_msg is not NULL, it is written to the device log as late as possible
 */
void
device_close (device *dev, const char *log_msg);

/* Get device's logging context
 */
log_ctx*
device_log_ctx (device *dev);

/* Get option descriptor
 */
const SANE_Option_Descriptor*
device_get_option_descriptor (device *dev, SANE_Int option);

/* Get device option
 */
SANE_Status
device_get_option (device *dev, SANE_Int option, void *value);

/* Set device option
 */
SANE_Status
device_set_option (device *dev, SANE_Int option, void *value, SANE_Word *info);

/* Get current scan parameters
 */
SANE_Status
device_get_parameters (device *dev, SANE_Parameters *params);

SANE_Status
device_start (device *dev);

/* Cancel scanning operation
 */
void
device_cancel (device *dev);

/* Set I/O mode
 */
SANE_Status
device_set_io_mode (device *dev, SANE_Bool non_blocking);

/* Get select file descriptor
 */
SANE_Status
device_get_select_fd (device *dev, SANE_Int *fd);

/* Read scanned image
 */
SANE_Status
device_read (device *dev, SANE_Byte *data, SANE_Int max_len, SANE_Int *len);

/* Initialize device management
 */
SANE_Status
device_management_init (void);

/* Cleanup device management
 */
void
device_management_cleanup (void);

/******************** Image filters ********************/
/* Type filter represents image filter
 */
typedef struct filter filter;
struct filter {
    filter      *next;               /* Next filter in a chain */
    void        (*dump) (filter *f,  /* Dump filter to the log */
        log_ctx *log);
    void        (*free) (filter *f); /* Free the filter */
    void        (*apply) (filter *f, /* Apply filter to the line of image */
        uint8_t *line, size_t size);
};

/* Free chain of filters
 */
void
filter_chain_free (filter *chain);

/* Push translation table based filter, that handles the
 * following options:
 *     - brightness
 *     - contrast
 *     - negative
 *
 * Returns updated chain
 */
filter*
filter_chain_push_xlat (filter *old_chain, const devopt *opt);

/* Dump filter chain to the log
 */
void
filter_chain_dump (filter *chain, log_ctx *log);

/* Apply filter chain to the image line
 */
void
filter_chain_apply (filter *chain, uint8_t *line, size_t size);

/******************** Scan Protocol handling ********************/
/* PROTO_OP represents operation
 */
typedef enum {
    PROTO_OP_NONE,    /* No operation */
    PROTO_OP_PRECHECK,/* Pre-scan check */
    PROTO_OP_SCAN,    /* New scan */
    PROTO_OP_LOAD,    /* Load image */
    PROTO_OP_CHECK,   /* Check device status */
    PROTO_OP_CLEANUP, /* Cleanup after scan */
    PROTO_OP_FINISH   /* Finish scanning */
} PROTO_OP;

/* Get PROTO_OP name, for logging
 */
const char*
proto_op_name (PROTO_OP op);

/* proto_scan_params represents scan parameters
 */
typedef struct {
    int           x_off, y_off; /* Scan area X/Y offset */
    int           wid, hei;     /* Scan area width and height */
    int           x_res, y_res; /* X/Y resolution */
    ID_SOURCE     src;          /* Desired source */
    ID_COLORMODE  colormode;    /* Desired color mode */
    ID_SCANINTENT scanintent;   /* Desired scan intent */
    ID_FORMAT     format;       /* Desired image format */
} proto_scan_params;

/* proto_ctx represents request context
 */
typedef struct {
    /* Common context */
    log_ctx              *log;            /* Logging context */
    struct proto_handler *proto;          /* Link to proto_handler */
    const zeroconf_devinfo *devinfo;      /* Device info, from zeroconf */
    const devcaps        *devcaps;        /* Device capabilities */
    PROTO_OP             op;              /* Current operation */
    http_client          *http;           /* HTTP client for sending requests */
    http_uri             *base_uri;       /* HTTP base URI for protocol */
    http_uri             *base_uri_nozone;/* base_uri without IPv6 zone */
    proto_scan_params    params;          /* Scan parameters */
    const char           *location;       /* Image location */
    unsigned int         images_received; /* Total count of received images */

    /* Extra context for xxx_decode callbacks */
    const http_query     *query;    /* Passed to xxx_decode callbacks */

    /* Extra context for status_decode callback */
    PROTO_OP             failed_op;          /* Failed operation */
    int                  failed_http_status; /* Its HTTP status */
    int                  failed_attempt;     /* Retry count, 0-based */

    /* Extra context for image decoding */
    ID_FORMAT            format_detected; /* Actual image format */
} proto_ctx;

/* proto_result represents decoded query results
 */
typedef struct {
    PROTO_OP          next;   /* Next operation */
    int               delay;  /* In milliseconds */
    SANE_Status       status; /* Job status */
    error             err;    /* Error string, may be NULL */
    union {
        const char *location; /* Image location, protocol-specific */
        http_data  *image;    /* Image buffer */
    } data;
} proto_result;

/* proto represents scan protocol implementation
 */
typedef struct proto_handler proto_handler;
struct proto_handler {
    const char *name;  /* Protocol name (i.e., "eSCL", "WSD", "IPP") */

    /* Free protocol handler
     */
    void         (*free) (proto_handler *proto);

    /* Query and decode device capabilities
     */
    http_query*  (*devcaps_query) (const proto_ctx *ctx);
    error        (*devcaps_decode) (const proto_ctx *ctx, devcaps *caps);

    /* Create pre-scan check query and decode result
     * These callback are optional, set to NULL, if
     * they are not implemented by the protocol
     * handler
     */
    http_query*  (*precheck_query) (const proto_ctx *ctx);
    proto_result (*precheck_decode) (const proto_ctx *ctx);

    /* Initiate scanning and decode result.
     * On success, scan_decode must set ctx->data.location
     */
    http_query*  (*scan_query) (const proto_ctx *ctx);
    proto_result (*scan_decode) (const proto_ctx *ctx);

    /* Initiate image downloading and decode result.
     * On success, load_decode must set ctx->data.image
     */
    http_query*  (*load_query) (const proto_ctx *ctx);
    proto_result (*load_decode) (const proto_ctx *ctx);

    /* Request device status and decode result
     */
    http_query*  (*status_query) (const proto_ctx *ctx);
    proto_result (*status_decode) (const proto_ctx *ctx);

    /* Cleanup after scan
     */
    http_query*  (*cleanup_query) (const proto_ctx *ctx);

    /* Cancel scan in progress
     */
    http_query*  (*cancel_query) (const proto_ctx *ctx);

    /* Test interfaces. Not for regular use!
     */
    error        (*test_decode_devcaps) (proto_handler *proto,
                                         const void *xml_text, size_t xms_size,
                                         devcaps *caps);
};

/* proto_handler_escl_new creates new eSCL protocol handler
 */
proto_handler*
proto_handler_escl_new (void);

/* proto_handler_wsd_new creates new WSD protocol handler
 */
proto_handler*
proto_handler_wsd_new (void);

/* proto_handler_new creates new protocol handler by protocol ID
 */
static inline proto_handler*
proto_handler_new (ID_PROTO proto)
{
    switch (proto) {
    case ID_PROTO_ESCL:
        return proto_handler_escl_new();
    case ID_PROTO_WSD:
        return proto_handler_wsd_new();
    default:
        return NULL;
    }
}

/* proto_handler_free destroys protocol handler, previously
 * created by proto_handler_new/proto_handler_escl_new/
 * proto_handler_wsd_new functions
 */
static inline void
proto_handler_free (proto_handler *proto)
{
    proto->free(proto);
}

/******************** Image decoding ********************/
/* The window withing the image
 *
 * Note, all sizes and coordinates are in pixels
 */
typedef struct {
    int x_off, y_off;  /* Top-left corner offset */
    int wid, hei;      /* Image width and height */
} image_window;

/* Image decoder, with virtual methods
 */
typedef struct image_decoder image_decoder;
struct image_decoder {
    const char *content_type;
    void  (*free) (image_decoder *decoder);
    error (*begin) (image_decoder *decoder, const void *data, size_t size);
    void  (*reset) (image_decoder *decoder);
    int   (*get_bytes_per_pixel) (image_decoder *decoder);
    void  (*get_params) (image_decoder *decoder, SANE_Parameters *params);
    error (*set_window) (image_decoder *decoder, image_window *win);
    error (*read_line) (image_decoder *decoder, void *buffer);
};

/* Detect image format by image data
 */
ID_FORMAT
image_format_detect (const void *data, size_t size);

/* Create JPEG image decoder
 */
image_decoder*
image_decoder_jpeg_new (void);

/* Create PNG image decoder
 */
image_decoder*
image_decoder_png_new (void);

/* Create TIFF image decoder
 */
image_decoder*
image_decoder_tiff_new (void);

/* Create BMP image decoder
 */
image_decoder*
image_decoder_bmp_new (void);

/* Free image decoder
 */
static inline void
image_decoder_free (image_decoder *decoder)
{
    decoder->free(decoder);
}

/* Get content type
 */
static inline const char*
image_content_type (image_decoder *decoder)
{
    return decoder->content_type;
}

/* Begin image decoding. Decoder may assume that provided data
 * buffer remains valid during a whole decoding cycle
 */
static inline error
image_decoder_begin (image_decoder *decoder, const void *data, size_t size)
{
    return decoder->begin(decoder, data, size);
}

/* Reset image decoder after use. After reset, decoding of the
 * another image can be started
 */
static inline void
image_decoder_reset (image_decoder *decoder)
{
    decoder->reset(decoder);
}

/* Get bytes count per pixel
 */
static inline int
image_decoder_get_bytes_per_pixel (image_decoder *decoder)
{
    return decoder->get_bytes_per_pixel(decoder);
}

/* Get image parameters. Can be called at any time between
 * image_decoder_begin() and image_decoder_reset()
 *
 * Decoder must return an actual image parameters, regardless
 * of clipping window set by image_decoder_set_window()
 */
static inline void
image_decoder_get_params (image_decoder *decoder, SANE_Parameters *params)
{
    decoder->get_params(decoder, params);
}

/* Set window within the image. Only part of image that fits the
 * window needs to be decoded. Decoder may assume that window is
 * always within the actual image boundaries
 *
 * Note, if decoder cannot handle exact window boundaries, it
 * it must update window to keep actual values
 *
 * In particular, if decoder doesn't implement image clipping
 * at all, it is safe that decoder will simply set window boundaries
 * to contain an entire image
 */
static inline error
image_decoder_set_window (image_decoder *decoder, image_window *win)
{
    return decoder->set_window(decoder, win);
}

/* Read next line of image. Decoder may safely assume the provided
 * buffer is big enough to keep the entire line
 */
static inline error
image_decoder_read_line (image_decoder *decoder, void *buffer)
{
    return decoder->read_line(decoder, buffer);
}

/* image_decoder_create_all creates all decoders
 * and fills array of decoders, indexed by ID_FORMAT
 *
 * Note, it is not guaranteed, that for all ID_FORMAT
 * decoder will be created. Missed entries will be set
 * to NULL. Be aware when using the filled array!
 */
static inline void
image_decoder_create_all (image_decoder *decoders[NUM_ID_FORMAT])
{
    int i;

    /* Fill entire array with NULLs
     */
    for (i = 0; i < NUM_ID_FORMAT; i ++) {
        decoders[i] = NULL;
    }

    /* Create known decoders
     */
    decoders[ID_FORMAT_BMP] = image_decoder_bmp_new();
    decoders[ID_FORMAT_JPEG] = image_decoder_jpeg_new();
    decoders[ID_FORMAT_PNG] = image_decoder_png_new();
    decoders[ID_FORMAT_TIFF] = image_decoder_tiff_new();
}

/* image_decoder_free_all destroys all decoders, previously
 * created by image_decoder_create_all
 */
static inline void
image_decoder_free_all (image_decoder *decoders[NUM_ID_FORMAT])
{
    int i;

    for (i = 0; i < NUM_ID_FORMAT; i ++) {
        image_decoder *decoder = decoders[i];
        if (decoder != NULL) {
            image_decoder_free(decoder);
            decoders[i] = NULL; /* For sanity */
        }
    }
}

/******************** Mathematical Functions ********************/
/* Find greatest common divisor of two positive integers
 */
SANE_Word
math_gcd (SANE_Word x, SANE_Word y);

/* Find least common multiple of two positive integers
 */
SANE_Word
math_lcm (SANE_Word x, SANE_Word y);

/* Find min of two words
 */
static inline SANE_Word
math_min (SANE_Word a, SANE_Word b)
{
    return a < b ? a : b;
}

/* Find max of two words
 */
static inline SANE_Word
math_max (SANE_Word a, SANE_Word b)
{
    return a > b ? a : b;
}

/* Bound integer within range
 */
static inline SANE_Word
math_bound (SANE_Word x, SANE_Word min, SANE_Word max)
{
    if (x < min) {
        return min;
    } else if (x > max) {
        return max;
    } else {
        return x;
    }
}

/* Bound double within range
 */
static inline double
math_bound_double (double x, double min, double max)
{
    if (x < min) {
        return min;
    } else if (x > max) {
        return max;
    } else {
        return x;
    }
}

/* Compute x * mul / div, taking in account rounding
 * and integer overflow
 */
static inline SANE_Word
math_muldiv (SANE_Word x, SANE_Word mul, SANE_Word div)
{
    int64_t tmp;

    tmp = (int64_t) x * (int64_t) mul;
    tmp += div / 2;
    tmp /= div;

    return (SANE_Word) tmp;
}

/* Merge two ranges, if possible
 */
bool
math_range_merge (SANE_Range *out, const SANE_Range *r1, const SANE_Range *r2);

/* Choose nearest integer in range
 */
SANE_Word
math_range_fit (const SANE_Range *r, SANE_Word i);

/* Convert pixels to millimeters, using given resolution
 */
static inline SANE_Fixed
math_px2mm_res (SANE_Word px, SANE_Word res)
{
    return SANE_FIX((double) px * 25.4 / res);
}

/* Convert millimeters to pixels, using given resolution
 */
static inline SANE_Word
math_mm2px_res (SANE_Fixed mm, SANE_Word res)
{
    return (SANE_Word) roundl(SANE_UNFIX(mm) * res / 25.4);
}

/* Format millimeters, for printing
 */
char*
math_fmt_mm (SANE_Word mm, char buf[]);

/* Genrate random 32-bit integer
 */
uint32_t
math_rand_u32 (void);

/* Generate random integer in range [0...max], inclusively
 */
uint32_t
math_rand_max (uint32_t max);

/* Generate random integer in range [min...max], inclusively
 */
uint32_t
math_rand_range (uint32_t min, uint32_t max);

/* Count nonzero bits in 32-bit integer
 */
static inline unsigned int
math_popcount (unsigned int n)
{
    unsigned int count = (n & 0x55555555) + ((n >> 1) & 0x55555555);
    count = (count & 0x33333333) + ((count >> 2) & 0x33333333);
    count = (count & 0x0F0F0F0F) + ((count >> 4) & 0x0F0F0F0F);
    count = (count & 0x00FF00FF) + ((count >> 8) & 0x00FF00FF);
    return (count & 0x0000FFFF) + ((count >> 16) & 0x0000FFFF);
}

/******************** Logging ********************/
/* Initialize logging
 *
 * No log messages should be generated before this call
 */
void
log_init (void);

/* Cleanup logging
 *
 * No log messages should be generated after this call
 */
void
log_cleanup (void);

/* Notify logger that configuration is loaded and
 * logger can configure itself
 *
 * This is safe to generate log messages before log_configure()
 * is called. These messages will be buffered, and after
 * logger is configured, either written or abandoned, depending
 * on configuration
 */
void
log_configure (void);

/* log_ctx_new creates new logging context
 * If parent != NULL, new logging context will have its own prefix,
 * but trace file will be inherited from parent
 */
log_ctx*
log_ctx_new (const char *name, log_ctx *parent);

/* log_ctx_free destroys logging context
 */
void
log_ctx_free (log_ctx *log);

/* Get protocol trace associated with logging context
 */
trace*
log_ctx_trace (log_ctx *log);

/* Write a debug message.
 */
void
log_debug (log_ctx *log, const char *fmt, ...);

/* Write a protocol trace message
 */
void
log_trace (log_ctx *log, const char *fmt, ...);

/* Write a block of data into protocol trace
 */
void
log_trace_data (log_ctx *log, const char *content_type,
        const void *bytes, size_t size);

/* Write an error message and terminate a program.
 */
void
log_panic (log_ctx *log, const char *fmt, ...);

/* Panic if assertion fails
 */
#define log_assert(log,expr)                                            \
     do {                                                               \
         if (!(expr)) {                                                 \
             log_panic(log,"file %s: line %d (%s): assertion failed: (%s)",\
                     __FILE__, __LINE__, __PRETTY_FUNCTION__, #expr);   \
             __builtin_unreachable();                                   \
         }                                                              \
     } while (0)

/* Panic if this code is reached
 */
#define log_internal_error(log)                                         \
     do {                                                               \
         log_panic(log,"file %s: line %d (%s): internal error",         \
                 __FILE__, __LINE__, __PRETTY_FUNCTION__);              \
         __builtin_unreachable();                                       \
     } while (0)

/******************** Initialization/Cleanup ********************/
/* AIRSCAN_INIT_FLAGS represents airscan_init() flags
 *
 * These flags are mostly used for testing
 */
typedef enum {
    AIRSCAN_INIT_NO_CONF        = (1 << 0),     // Don't load configuration
    AIRSCAN_INIT_NO_THREAD      = (1 << 1)      // Don't start worker thread
} AIRSCAN_INIT_FLAGS;

/* Initialize airscan.
 * If log_msg is not NULL, it is written to the log early
 */
SANE_Status
airscan_init (AIRSCAN_INIT_FLAGS flags, const char *log_msg);

/* Cleanup airscan
 * If log_msg is not NULL, it is written to the log as late as possible
 */
void
airscan_cleanup (const char *log_msg);

/* Get init flags from the airscan_init call
 */
AIRSCAN_INIT_FLAGS
airscan_get_init_flags (void);

#ifdef  __cplusplus
};
#endif

#endif
/* vim:ts=8:sw=4:et
 */
