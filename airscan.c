/* AirScan (a.k.a. eSCL) backend for SANE
 *
 * Copyright (C) 2019 and up by Alexander Pevzner (pzz@apevzner.com)
 * See LICENSE for license terms and conditions
 *
 * SANE API
 */

#include "airscan.h"

/* Static variables
 */
static const SANE_Device **sane_device_list;

/* Initialize the backend
 */
SANE_Status
sane_init (SANE_Int *version_code, SANE_Auth_Callback authorize)
{
    SANE_Status status;

    DBG_API_ENTER();

    conf_load();

    if (version_code != NULL) {
        *version_code = SANE_VERSION_CODE (SANE_CURRENT_MAJOR,
                SANE_CURRENT_MINOR, 0);
    }

    (void) authorize;

    /* Initialize all parts */
    status = eloop_init();
    if (status == SANE_STATUS_GOOD) {
        device_management_init();
    }
    if (status == SANE_STATUS_GOOD) {
        status = zeroconf_init();
    }

    if (status != SANE_STATUS_GOOD) {
        sane_exit();
    }

    /* Start airscan thread */
    eloop_thread_start(device_management_start_stop);

    DBG_API_LEAVE(status);

    return status;
}

/* Exit the backend
 */
void
sane_exit (void)
{
    DBG_API_ENTER();

    eloop_thread_stop();

    zeroconf_cleanup();
    device_management_cleanup();
    eloop_cleanup();
    device_list_free(sane_device_list);

    DBG_API_LEAVE(SANE_STATUS_GOOD);
}

/* Get list of devices
 */
SANE_Status
sane_get_devices (const SANE_Device ***device_list, SANE_Bool local_only)
{
    SANE_Status status = SANE_STATUS_GOOD;

    DBG_API_ENTER();

    if (local_only) {
        /* All our devices are non-local */
        static const SANE_Device *empty_devlist[1] = { 0 };
        *device_list = empty_devlist;
    } else {
        eloop_mutex_lock();

        device_list_free(sane_device_list);
        sane_device_list = device_list_get();
        *device_list = sane_device_list;

        eloop_mutex_unlock();
    }

    DBG_API_LEAVE(status);

    return status;
}

/* Open the device
 */
SANE_Status
sane_open (SANE_String_Const name, SANE_Handle *handle)
{
    SANE_Status status = SANE_STATUS_INVAL;

    DBG_API_ENTER();

    eloop_mutex_lock();
    device *dev = device_open(name);
    eloop_mutex_unlock();

    if (dev != NULL) {
        *handle = (SANE_Handle) dev;
        status = SANE_STATUS_GOOD;
    }

    DBG_API_LEAVE(status);

    return status;
}

/* Close the device
 */
void
sane_close (SANE_Handle handle)
{
    DBG_API_ENTER();

    eloop_mutex_lock();
    device_close((device*) handle);
    eloop_mutex_unlock();

    DBG_API_LEAVE(SANE_STATUS_GOOD);
}

/* Get option descriptor
 */
const SANE_Option_Descriptor *
sane_get_option_descriptor (SANE_Handle handle, SANE_Int option)
{
    device *dev = (device*) handle;
    const SANE_Option_Descriptor *desc;

    DBG_API_ENTER();
    desc = dev_get_option_descriptor(dev, option);
    DBG_API_LEAVE(desc ? SANE_STATUS_GOOD : SANE_STATUS_INVAL);

    return desc;
}

/* Get or set option value
 */
SANE_Status
sane_control_option (SANE_Handle handle, SANE_Int option, SANE_Action action,
                     void *value, SANE_Int *info)
{
    SANE_Status status = SANE_STATUS_INVAL;
    device *dev = (device*) handle;

    DBG_API_ENTER();

    /* Roughly validate arguments */
    if (dev == NULL || value == NULL) {
        goto DONE;
    }

    const SANE_Option_Descriptor *desc = dev_get_option_descriptor(dev, option);
    if (desc == NULL) {
        goto DONE;
    }

    if (action == SANE_ACTION_SET_VALUE && !SANE_OPTION_IS_SETTABLE(desc->cap)){
        goto DONE;
    }

    /* Get/set the option */
    eloop_mutex_lock();
    if (action == SANE_ACTION_GET_VALUE) {
        status = device_get_option(dev, option, value);
    } else {
        status = device_set_option(dev, option, value, info);
    }
    eloop_mutex_unlock();

    (void) info;

DONE:
    DBG_API_LEAVE(status);
    return status;
}

/* Get current scan parameters
 */
SANE_Status
sane_get_parameters (SANE_Handle handle, SANE_Parameters *params)
{
    SANE_Status status = SANE_STATUS_UNSUPPORTED;
    device *dev = (device*) handle;

    DBG_API_ENTER();

    eloop_mutex_lock();
    status = device_get_parameters(dev, params);
    eloop_mutex_unlock();

    DBG_API_LEAVE(status);

    return status;
}

/* Start scanning operation
 */
SANE_Status
sane_start (SANE_Handle handle)
{
    SANE_Status status = SANE_STATUS_UNSUPPORTED;
    device *dev = (device*) handle;

    DBG_API_ENTER();

    eloop_mutex_lock();
    status = device_start(dev);
    eloop_mutex_unlock();

    DBG_API_LEAVE(status);

    return status;
}

/* Read scanned image
 */
SANE_Status
sane_read (SANE_Handle handle, SANE_Byte *data,
           SANE_Int max_length, SANE_Int *length)
{
    SANE_Status status = SANE_STATUS_UNSUPPORTED;

    DBG_API_ENTER();

    (void) handle;
    (void) data;
    (void) max_length;
    (void) length;

    DBG_API_LEAVE(status);

    return status;
}

/* Cancel scanning operation
 */
void
sane_cancel (SANE_Handle handle)
{
    DBG_API_ENTER();

    (void) handle;

    DBG_API_LEAVE(SANE_STATUS_GOOD);
}

/* Set I/O mode
 */
SANE_Status
sane_set_io_mode (SANE_Handle handle, SANE_Bool non_blocking)
{
    SANE_Status status = SANE_STATUS_UNSUPPORTED;

    DBG_API_ENTER();

    (void) handle;
    (void) non_blocking;

    DBG_API_LEAVE(status);

    return status;
}

/* Get select file descriptor
 */
SANE_Status
sane_get_select_fd (SANE_Handle handle, SANE_Int * fd)
{
    SANE_Status status = SANE_STATUS_UNSUPPORTED;

    DBG_API_ENTER();

    (void) handle;

    *fd = -1;

    DBG_API_LEAVE(status);

    return status;
}

/******************** API aliases for libsane-dll ********************/
SANE_Status __attribute__ ((alias ("sane_init")))
sane_airscan_init (SANE_Int *version_code, SANE_Auth_Callback authorize);

void __attribute__ ((alias ("sane_exit")))
sane_airscan_exit (void);

SANE_Status __attribute__ ((alias ("sane_get_devices")))
sane_airscan_get_devices (const SANE_Device ***device_list, SANE_Bool local_only);

SANE_Status __attribute__ ((alias ("sane_open")))
sane_airscan_open (SANE_String_Const devicename, SANE_Handle *handle);

void __attribute__ ((alias ("sane_close")))
sane_airscan_close (SANE_Handle handle);

const SANE_Option_Descriptor * __attribute__ ((alias ("sane_get_option_descriptor")))
sane_airscan_get_option_descriptor (SANE_Handle handle, SANE_Int option);

SANE_Status __attribute__ ((alias ("sane_control_option")))
sane_airscan_control_option (SANE_Handle handle, SANE_Int option,
    SANE_Action action, void *value, SANE_Int *info);

SANE_Status __attribute__ ((alias ("sane_get_parameters")))
sane_airscan_get_parameters (SANE_Handle handle, SANE_Parameters *params);

SANE_Status __attribute__ ((alias ("sane_start")))
sane_airscan_start (SANE_Handle handle);

SANE_Status __attribute__ ((alias ("sane_read")))
sane_airscan_read (SANE_Handle handle, SANE_Byte *data,
           SANE_Int max_length, SANE_Int *length);

void __attribute__ ((alias ("sane_cancel")))
sane_airscan_cancel (SANE_Handle handle);

SANE_Status __attribute__ ((alias ("sane_set_io_mode")))
sane_airscan_set_io_mode (SANE_Handle handle, SANE_Bool non_blocking);

SANE_Status __attribute__ ((alias ("sane_get_select_fd")))
sane_airscan_get_select_fd (SANE_Handle handle, SANE_Int * fd);

/* vim:ts=8:sw=4:et
 */
