/* sane-airscan zeroconf test
 *
 * Copyright (C) 2019 and up by Alexander Pevzner (pzz@apevzner.com)
 * See LICENSE for license terms and conditions
 */

#include "airscan.h"

#include <errno.h>
#include <glob.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TEST_FILES      "testdata/test-zeroconf*.cfg"
#define TRACE_DIR       "testdata/logs"

static const char       *test_file;
static zeroconf_finding **findings = NULL;

/* Print error message and exit
 */
void __attribute__((noreturn))
die (const char *format, ...)
{
    va_list ap;

    va_start(ap, format);
    vprintf(format, ap);
    printf("\n");
    va_end(ap);

    exit(1);
}

/* devlist_item represents device list item
 */
typedef struct devlist_item devlist_item;
struct devlist_item {
    const char        *name;      /* Device name */
    ID_PROTO          proto;      /* Device protocol */
    zeroconf_endpoint *endpoints; /* Device endpoints */
    devlist_item      *next;      /* Next item in the list */
    const char        *file;      /* Test file */
    unsigned int      line;       /* Line in the test file */
};

/* Free device list
 */
static void
devlist_free (devlist_item *devlist)
{
    devlist_item *next;

    while (devlist != NULL) {
        next = devlist->next;
        mem_free((char*) devlist->name);
        zeroconf_endpoint_list_free(devlist->endpoints);
        mem_free(devlist);
        devlist = next;
    }
}

/* Revert device list
 */
static devlist_item*
devlist_revert (devlist_item *devlist)
{
    devlist_item *reverted = NULL, *next;

    while (devlist != NULL) {
        next = devlist->next;
        devlist->next = reverted;
        reverted = devlist;
        devlist = next;
    }

    return reverted;
}

/* Obtain list of devices from zeroconf
 */
static devlist_item*
devlist_from_zeroconf (void)
{
    const SANE_Device **devices;
    int               i;
    devlist_item      *devlist = NULL;

    devices = zeroconf_device_list_get();
    for (i = 0; devices[i] != NULL; i ++) {
        devlist_item     *item = mem_new(devlist_item, 1);
        zeroconf_devinfo *devinfo;

        devinfo = zeroconf_devinfo_lookup(devices[i]->name);
        if (devinfo == NULL) {
            die("%s: zeroconf_devinfo_lookup() failed)", devices[i]->name);
        }

        item->name = str_dup(devinfo->name);
        item->proto = id_proto_by_name(devices[i]->vendor);
        item->endpoints = devinfo->endpoints;
        devinfo->endpoints = NULL;
        zeroconf_devinfo_free(devinfo);

        item->next = devlist;
        devlist = item;
    }
    zeroconf_device_list_free(devices);

    return devlist_revert(devlist);
}

/* Parse device list item from configuration file record
 */
static devlist_item*
devlist_item_parse (const inifile_record *rec)
{
    devlist_item *item = mem_new(devlist_item, 1);
    unsigned int i;

    if (rec->tokc < 2) {
        die("%s:%d: usage: %s = protocol, endpoint, ...",
            rec->file, rec->line, rec->variable);
    }

    item->name = str_dup(rec->variable);
    item->proto = id_proto_by_name(rec->tokv[0]);
    item->file = rec->file;
    item->line = rec->line;

    if (item->proto == ID_PROTO_UNKNOWN) {
        die("%s:%d: unknown protocol %s",
            rec->file, rec->line, rec->variable, rec->tokv[0]);
    }

    for (i = 1; i < rec->tokc; i ++) {
        http_uri          *uri = http_uri_new(rec->tokv[i], true);
        zeroconf_endpoint *endpoint;
        if (uri == NULL) {
            die("%s:%d: invalid URI %s",
                rec->file, rec->line, rec->variable, rec->tokv[i]);
        }

        endpoint = zeroconf_endpoint_new(item->proto, uri);
        endpoint->next = item->endpoints;
        item->endpoints = endpoint;
    }

    item->endpoints = zeroconf_endpoint_list_sort(item->endpoints);
    return item;
}

/* Compare 2 device lists
 */
static void
devlist_compare (devlist_item *expected, devlist_item *discovered)
{
    while (expected != NULL && discovered != NULL) {
        zeroconf_endpoint *ep_expected = expected->endpoints;
        zeroconf_endpoint *ep_discovered = discovered->endpoints;

        if (strcmp(expected->name, discovered->name)) {
            die("%s:%d: name mismatch: expected '%s', discovered '%s'",
                expected->file, expected->line,
                expected->name, discovered->name);
        }

        if (expected->proto != discovered->proto) {
            die("%s:%d: proto mismatch: expected %s, discovered %s",
                expected->file, expected->line,
                id_proto_name(expected->proto),
                id_proto_name(discovered->proto));
        }

        while (ep_expected != NULL && ep_discovered != NULL) {
            if (!http_uri_equal(ep_expected->uri, ep_discovered->uri)) {
                die("%s:%d: uri mismatch: expected %s, discovered %s",
                    expected->file, expected->line,
                    http_uri_str(ep_expected->uri),
                    http_uri_str(ep_discovered->uri));
            }

            ep_expected = ep_expected->next;
            ep_discovered = ep_discovered->next;
        }

        if (ep_expected != NULL && ep_discovered == NULL) {
            die("%s:%d: uri expected but not discovered: %s",
                expected->file, expected->line,
                http_uri_str(ep_expected->uri));
        }

        if (ep_expected == NULL && ep_discovered != NULL) {
            die("%s:%d: uri not expected but discovered: %s",
                expected->file, expected->line,
                http_uri_str(ep_discovered->uri));
        }

        expected = expected->next;
        discovered = discovered->next;
    }

    if (expected != NULL && discovered == NULL) {
        die("%s:%d: device '%s' expected, but not discovered",
            expected->file, expected->line, expected->name);
    }

    if (expected == NULL && discovered != NULL) {
        die("'%s': device not expected, but discovered", discovered->name);
    }
}

/* Parse ZEROCONF_METHOD
 */
static ZEROCONF_METHOD
parse_zeroconf_method (const inifile_record *rec)
{
    static struct { const char *name; ZEROCONF_METHOD method; } methods[] = {
        {"MDNS_HINT",  ZEROCONF_MDNS_HINT},
        {"USCAN_TCP",  ZEROCONF_USCAN_TCP},
        {"USCANS_TCP", ZEROCONF_USCANS_TCP},
        {"WSD",        ZEROCONF_WSD},
        {NULL, 0}
    };
    int  i;
    char *usage;

    for (i = 0; methods[i].name != NULL; i ++) {
        if (inifile_match_name(rec->value, methods[i].name)) {
            return methods[i].method;
        }
    }

    usage = str_dup(methods[0].name);
    for (i = 1; methods[i].name != NULL; i ++) {
        usage = str_append(usage, "|");
        usage = str_append(usage, methods[i].name);
    }

    die("%s:%d: usage: %s = %s", rec->file, rec->line, rec->variable, usage);
    return -1;
}

/* Parse unsigned integer
 */
static int
parse_uint (const inifile_record *rec)
{
    char          *end;
    unsigned long n = strtoul(rec->value, &end, 0);

    if (end == rec->value || *end) {
        die("%s:%d: usage: %s = NUM", rec->file, rec->line, rec->variable);
    }

    return (int) n;
}

/* Get finding by name
 */
static zeroconf_finding*
finding_by_name(ZEROCONF_METHOD method, int ifindex, const char *name)
{
    size_t len = mem_len(findings);
    size_t i;

    for (i = 0; i < len; i ++) {
        if (findings[i]->method == method &&
            findings[i]->ifindex == ifindex &&
            !strcasecmp(findings[i]->name, name)) {
            return findings[i];
        }
    }

    return NULL;
}

/* Get finding by UUID
 */
static zeroconf_finding*
finding_by_uuid(ZEROCONF_METHOD method, int ifindex, uuid uuid)
{
    size_t len = mem_len(findings);
    size_t i;

    for (i = 0; i < len; i ++) {
        if (findings[i]->method == method &&
            findings[i]->ifindex == ifindex &&
            uuid_equal(findings[i]->uuid, uuid)) {
            return findings[i];
        }
    }

    return NULL;
}

/* Get finding by name or UUID
 */
static zeroconf_finding*
finding_find(ZEROCONF_METHOD method, int ifindex, const char *name, uuid uuid)
{
    if (name != NULL) {
        return finding_by_name(method, ifindex, name);
    } else {
        return finding_by_uuid(method, ifindex, uuid);
    }
}

/* Free the zeroconf_finding
 */
static void
finding_free (zeroconf_finding *finding)
{
    ip_addrset_free(finding->addrs);
    mem_free((char*) finding->name);
    mem_free((char*) finding->model);
    zeroconf_endpoint_list_free(finding->endpoints);
    mem_free(finding);
}

/* Parse and execute [add] or [del] section
 */
static const inifile_record*
test_section_add_del (inifile *ini, const inifile_record *rec, bool add)
{
    ZEROCONF_METHOD   method = (ZEROCONF_METHOD) -1;
    ID_PROTO          proto = ID_PROTO_UNKNOWN;
    char              *name = NULL;
    char              *model = NULL;
    uuid              uuid;
    int               ifindex = -1;
    zeroconf_endpoint *endpoints = NULL;
    const char        *section_file = rec->file;
    unsigned int      section_line = rec->line;
    zeroconf_finding  *finding;

    /* Parse the section */
    memset(&uuid, 0, sizeof(uuid));
    rec = inifile_read(ini);
    while (rec != NULL && rec->type == INIFILE_VARIABLE) {
        if (inifile_match_name(rec->variable, "method")) {
            method = parse_zeroconf_method(rec);
            switch (method) {
                case ZEROCONF_USCAN_TCP:
                case ZEROCONF_USCANS_TCP:
                    proto = ID_PROTO_ESCL;
                    break;
                case ZEROCONF_WSD:
                    proto = ID_PROTO_WSD;
                    break;
                default:
                    proto = ID_PROTO_UNKNOWN;
            }
        } else if (inifile_match_name(rec->variable, "name")) {
            mem_free(name);
            name = str_dup(rec->value);
        } else if (inifile_match_name(rec->variable, "model")) {
            mem_free(model);
            model = str_dup(rec->value);
        } else if (inifile_match_name(rec->variable, "uuid")) {
            uuid = uuid_parse(rec->value);
            if (!uuid_valid(uuid)) {
                die("%s:%d: bad UUID", rec->file, rec->line);
            }
        } else if (inifile_match_name(rec->variable, "ifindex")) {
            ifindex = parse_uint(rec);
        } else if (inifile_match_name(rec->variable, "endpoint")) {
            http_uri              *uri;
            zeroconf_endpoint     *endpoint;

            if (proto == ID_PROTO_UNKNOWN) {
                die("%s:%d: protocol not known; set method first",
                    rec->file, rec->line);
            }

            uri = http_uri_new(rec->value, true);
            if (uri == NULL) {
                die("%s:%d: invalid URI", rec->file, rec->line);
            }

            endpoint = zeroconf_endpoint_new(proto, uri);
            endpoint->next = endpoints;
            endpoints = endpoint;
        } else {
            die("%s:%d: unknown parameter %s", rec->file, rec->line,
                rec->variable);
        }

        rec = inifile_read(ini);
    }

    /* In a case of obviously broken file, return immediately */
    if (rec != NULL && rec->type != INIFILE_SECTION) {
        return rec;
    }

    /* Validate things */
    if (method == (ZEROCONF_METHOD) -1) {
        die("%s:%d: missed method", section_file, section_line);
    }

    if (method != ZEROCONF_WSD && name == NULL) {
        die("%s:%d: missed name", section_file, section_line);
    }

    if (method == ZEROCONF_WSD && name != NULL) {
        mem_free(name);
        name = NULL;
    }

    if (model == NULL && add) {
        die("%s:%d: missed model", section_file, section_line);
    }

    if (!uuid_valid(uuid)) {
        die("%s:%d: missed uuid", section_file, section_line);
    }

    if (ifindex == -1) {
        die("%s:%d: missed ifindex", section_file, section_line);
    }

    if (method != ZEROCONF_MDNS_HINT && add && endpoints == NULL) {
        die("%s:%d: missed endpoint", section_file, section_line);
    }

    /* Perform an action */
    finding = finding_find(method, ifindex, name, uuid);
    if (add) {
        zeroconf_endpoint     *endpoint;

        if (finding != NULL) {
            die("%s:%d: duplicate [add]", section_file, section_line);
        }

        finding = mem_new(zeroconf_finding, 1);
        finding->method = method;
        finding->name = name;
        finding->model = model;
        finding->uuid = uuid;
        finding->addrs = ip_addrset_new();
        finding->ifindex = ifindex;
        finding->endpoints = zeroconf_endpoint_list_sort(endpoints);

        for (endpoint = finding->endpoints; endpoint != NULL;
             endpoint = endpoint->next) {
            const struct sockaddr *sockaddr = http_uri_addr(endpoint->uri);
            if (sockaddr != NULL) {
                ip_addrset_add(finding->addrs, ip_addr_from_sockaddr(sockaddr));
            }
        }

        zeroconf_finding_publish(finding);
        findings = ptr_array_append(findings, finding);
    } else {
        if (finding == NULL) {
            die("%s:%d: can't find device to [del]", section_file, section_line);
        }
        zeroconf_finding_withdraw(finding);
        ptr_array_del(findings, ptr_array_find(findings, finding));
        finding_free(finding);

        mem_free(name);
        mem_free(model);
        zeroconf_endpoint_list_free(endpoints);
    }

    return rec;
}

/* Parse and execute [expect] section
 */
static const inifile_record*
test_section_expect (inifile *ini, const inifile_record *rec, bool merged)
{
    devlist_item *expected = NULL, *discovered;

    conf.proto_auto = merged;

    /* Parse the section */
    rec = inifile_read(ini);
    while (rec != NULL && rec->type == INIFILE_VARIABLE) {
        devlist_item *item = devlist_item_parse(rec);
        item->next = expected;
        expected = item;
        rec = inifile_read(ini);
    }

    /* In a case of obviously broken file, return immediately */
    if (rec != NULL && rec->type != INIFILE_SECTION) {
        devlist_free(expected);
        return rec;
    }

    expected = devlist_revert(expected);
    discovered = devlist_from_zeroconf();

    devlist_compare(expected, discovered);

    devlist_free(discovered);
    devlist_free(expected);

    return rec;
}

/* Load and execute next test file section
 * Returns inifile_record that follows the section
 */
static const inifile_record*
test_section (inifile *ini, const inifile_record *rec)
{
    if (inifile_match_name(rec->section, "add")) {
        rec = test_section_add_del(ini, rec, true);
    } else if (inifile_match_name(rec->section, "del")) {
        rec = test_section_add_del(ini, rec, false);
    } else if (inifile_match_name(rec->section, "expect")) {
        rec = test_section_expect(ini, rec, false);
    } else if (inifile_match_name(rec->section, "merged")) {
        rec = test_section_expect(ini, rec, true);
    } else {
        die("%s:%d: unexpected section [%s]", rec->file, rec->line,
            rec->section);
    }
    return rec;
}

/* Load and execute all sections from the test file
 */
static void
test_all (inifile *ini)
{
    const inifile_record *rec;

    rec = inifile_read(ini);
    while (rec != NULL) {
        if (rec->type == INIFILE_SECTION) {
            rec = test_section(ini, rec);
        } else if (rec->type == INIFILE_SYNTAX) {
            die("%s:%d: sytnax error", rec->file, rec->line);
        } else {
            die("%s:%d: section expected", rec->file, rec->line);
        }
    }
}

/* Run test in the eloop thread context
 */
static void
run_test_in_eloop_thread (void)
{
    inifile              *ini;
    size_t               i, len;

    findings = ptr_array_new(zeroconf_finding);

    ini = inifile_open(test_file);
    if (ini == NULL) {
        die("%s: %s", test_file, strerror(errno));
    }

    test_all(ini);

    inifile_close(ini);

    for (i = 0, len = mem_len(findings); i < len; i ++) {
        zeroconf_finding_withdraw(findings[i]);
        finding_free(findings[i]);
    }

    mem_free(findings);
    findings = NULL;
}

/* eloop_add_start_stop_callback callback
 */
static void
start_stop_callback (bool start)
{
    if (start) {
        run_test_in_eloop_thread();
    }
}

/* Run test, using specified test file
 */
static void run_test (const char *file)
{
    char   title[1024];

    conf.dbg_enabled = true;
    conf.dbg_trace = str_dup(TRACE_DIR);
    conf.discovery = false;
    conf.proto_auto = false;
    conf.model_is_netname = true;

    test_file = file;

    sprintf(title, "=== %s ===", file);
    airscan_init(AIRSCAN_INIT_NO_CONF | AIRSCAN_INIT_NO_THREAD, title);
    eloop_add_start_stop_callback(start_stop_callback);
    eloop_thread_start();
    eloop_thread_stop();
    airscan_cleanup(NULL);
}

/* glob() error callback
 */
static int
glob_errfunc (const char *path, int err)
{
    die("%s: %s", path, strerror(err));
}

/* The main function
 */
int
main (void)
{
    glob_t glob_data;
    int    rc;
    size_t i;

    rc = glob(TEST_FILES, 0, glob_errfunc, &glob_data);
    if (rc != 0) {
        die("glob(%s): error %d", TEST_FILES, rc);
    }

    for (i = 0; i < glob_data.gl_pathc; i ++) {
        run_test(glob_data.gl_pathv[i]);
    }

    globfree(&glob_data);
}

/* vim:ts=8:sw=4:et
 */
