/* http_uri test
 *
 * Copyright (C) 2019 and up by Alexander Pevzner (pzz@apevzner.com)
 * See LICENSE for license terms and conditions
 */

#include "airscan.h"

#include <stdarg.h>
#include <stdlib.h>

static void
fail (const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    putchar('\n');
    exit(1);
}

/* Test URI parser
 */
static void
test_parse (const char *s, bool must_parse)
{
    http_uri *uri = http_uri_new(s, false);

    if (uri == NULL && must_parse) {
        fail("URI parse failed: %s", s);
    } else if (uri != NULL && !must_parse) {
        fail("URI parse must fail: %s", s);
    }

    http_uri_free(uri);
}

/* Test http_uri_addr
 */
static void
test_addr (const char *s, const char *expected)
{
    http_uri     *uri = http_uri_new(s, false);
    const struct sockaddr *sa;
    ip_straddr   straddr;

    if (uri == NULL) {
        fail("URI parse failed: %s", s);
    }

    sa = http_uri_addr(uri);
    if (sa == NULL) {
        fail("URI addr not understood: %s", s);
    }

    straddr = ip_straddr_from_sockaddr(sa, true);
    if (strcmp(straddr.text, expected)) {
        fail("URI addr %s != %s: %s", straddr.text, expected, s);
    }

    http_uri_free(uri);
}

/* Test http_uri_get_path
 */
static void
test_get_path (const char *s, const char *expected)
{
    http_uri     *uri = http_uri_new(s, false);
    const char   *path;

    if (uri == NULL) {
        fail("URI parse failed: %s", s);
    }

    path = http_uri_get_path(uri);
    if (strcmp(path, expected)) {
        fail("URI path %s != %s: %s", path, expected, s);
    }

    http_uri_free(uri);
}

/* Test http_uri_fix_end_slash
 */
static void
test_fix_end_slash (const char *s)
{
    http_uri     *uri = http_uri_new(s, false);
    const char   *path;

    if (uri == NULL) {
        fail("URI parse failed: %s", s);
    }

    http_uri_fix_end_slash(uri);
    path = http_uri_get_path(uri);
    if (!str_has_suffix(path, "/")) {
        fail("fix_end_slash failed: %s, path=%s", s, path);
    }

    http_uri_free(uri);
}

/* Test http_uri_set_path
 */
static void
test_set_path (const char *path, const char *expected)
{
    http_uri   *uri = http_uri_new("http://user@host:123/?q#frag", false);
    const char *path2;

    http_uri_set_path(uri, path);
    path2 = http_uri_get_path(uri);

    if (strcmp(path, path2)) {
        fail("URI set path: %s != %s", path, path2);
    }

    if (strcmp(http_uri_str(uri), expected)) {
        fail("URI set path: %s != %s", http_uri_str(uri), expected);
    }

    http_uri_free(uri);
}

/* Test http_uri_new_relative
 */
static void
test_relative (const char *base, const char *ref, const char *expected)
{
    http_uri   *uri_base, *uri_rel;
    const char *s;

    uri_base = http_uri_new(base, false);
    if (uri_base == NULL) {
        fail("URI parse failed: %s", base);
    }

    uri_rel = http_uri_new_relative(uri_base, ref, false, false);
    if (uri_rel == NULL) {
        fail("URI base=%s ref=%s: ref parse failed", base, ref);
    }

    s = http_uri_str(uri_rel);
    if (strcmp(s, expected)) {
        fail("URI base=%s ref=%s: %s != %s", base, ref, s, expected);
    }

    http_uri_free(uri_base);
    http_uri_free(uri_rel);
}

/* The main function
 */
int
main (void)
{
    log_init();

    test_parse("http://1.2.3.4/",               true);
    test_parse("http:/1.2.3.4",                 false);
    test_parse("http:1.2.3.4",                  false);
    test_parse("http://1.2.3.4:8888/",          true);
    test_parse("http://1.2.3.4:8888:9999/",     false);
    test_parse("/",                             false);
    test_parse("",                              false);

    test_parse("http://[::1]/",                 true);
    test_parse("http://[::1%255]/",             true);
    test_parse("http://[::1/",                  false);
    test_parse("http://[::1]:8888/",            true);
    test_parse("http://[::1]:8888:9999/",       false);
    test_parse("http://[A%2525]//MM",           false);
    test_parse("http://[A%2525]//MM/",          false);
    test_parse("http://[1%255]/a",              false);

    test_fix_end_slash("http://[::1%255]/a");

    test_addr("http://1.2.3.4/",                "1.2.3.4:80");
    test_addr("http://[::1]/",                  "[::1]:80");
    test_addr("https://1.2.3.4/",               "1.2.3.4:443");
    test_addr("https://[::1]/",                 "[::1]:443");
    test_addr("http://1.2.3.4:1234/",           "1.2.3.4:1234");
    test_addr("http://[::1]:1234/",             "[::1]:1234");

    test_get_path("http://1.2.3.4/",            "/");
    test_get_path("http://1.2.3.4/xxx",         "/xxx");
    test_get_path("http://1.2.3.4",             "");

    test_set_path("/xxx",                       "http://user@host:123/xxx?q#frag");

    test_relative("http://host/", "//x/path",   "http://x/path");
    test_relative("http://host/", "/path",      "http://host/path");
    test_relative("http://host/", "noroot",     "http://host/noroot");
    test_relative("http://host/", "noroot/xxx", "http://host/noroot/xxx");
    test_relative("http://host/xxx/", "noroot", "http://host/xxx/noroot");
    test_relative("http://host/xxx", "noroot",  "http://host/noroot");

    test_relative("http://host/", "/a/b/c/./../../g", "http://host/a/g");

    test_relative("http://[::1]:8080/eSCL/", "XXX", "http://[::1]:8080/eSCL/XXX");

    return 0;
}

/* vim:ts=8:sw=4:et
 */
