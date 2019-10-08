/* AirScan (a.k.a. eSCL) backend for SANE
 *
 * Copyright (C) 2019 and up by Alexander Pevzner (pzz@apevzner.com)
 * See LICENSE for license terms and conditions
 */

#include <sane/sane.h>

#include <stddef.h>

/******************** Static variables ********************/
// List of devices
static SANE_Device **airprint_device_list = NULL;

/******************** SANE API ********************/

/* Initialize the backend
 */
SANE_Status
sane_init (SANE_Int *version_code,
           SANE_Auth_Callback authorize)
{
    (void) version_code;
    (void) authorize;

    return SANE_STATUS_GOOD;
}

/* Exit the backend
 */
void
sane_exit (void) {
}

/* Get list of devices
 */
SANE_Status
sane_get_devices (const SANE_Device ***device_list, SANE_Bool local_only)
{
    (void) local_only;

    *device_list = (const SANE_Device **) airprint_device_list;

    return SANE_STATUS_GOOD;
}

/* Open the device
 */
SANE_Status
sane_open (SANE_String_Const devicename, SANE_Handle *handle)
{
    (void) devicename;
    (void) handle;

    return SANE_STATUS_INVAL;
}

/* Close the device
 */
void
sane_close (SANE_Handle handle)
{
    (void) handle;
}

/* Get option descriptor
 */
const SANE_Option_Descriptor *
sane_get_option_descriptor (SANE_Handle handle, SANE_Int option)
{
    (void) handle;
    (void) option;

    return NULL;
}

/* Get or set option value
 */
SANE_Status
sane_control_option (SANE_Handle handle, SANE_Int option, SANE_Action action,
                     void *value, SANE_Int *info)
{
    (void) handle;
    (void) option;
    (void) action;
    (void) value;
    (void) info;

    return SANE_STATUS_UNSUPPORTED;
}

/* Get current scan parameters
 */
SANE_Status
sane_get_parameters (SANE_Handle handle, SANE_Parameters *params)
{
    (void) handle;
    (void) params;

    return SANE_STATUS_INVAL;
}

/* Start scanning operation
 */
SANE_Status
sane_start (SANE_Handle handle)
{
    (void) handle;

    return SANE_STATUS_INVAL;
}

/* Read scanned image
 */
SANE_Status
sane_read (SANE_Handle handle, SANE_Byte *data,
           SANE_Int max_length, SANE_Int *length)
{
    (void) handle;
    (void) data;
    (void) max_length;
    (void) length;

    return SANE_STATUS_INVAL;
}

/* Cancel scanning operation
 */
void
sane_cancel (SANE_Handle handle)
{
    (void) handle;
}

/* Set I/O mode
 */
SANE_Status
sane_set_io_mode (SANE_Handle handle, SANE_Bool non_blocking)
{
    (void) handle;
    (void) non_blocking;

    return SANE_STATUS_GOOD;
}

/* Get select file descriptor
 */
SANE_Status
sane_get_select_fd (SANE_Handle handle, SANE_Int * fd)
{
    (void) handle;

    *fd = -1;
    return SANE_STATUS_UNSUPPORTED;
}

/* vim:ts=8:sw=4:et
 */
