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

    if (version_code != NULL) {
        *version_code = SANE_VERSION_CODE (SANE_CURRENT_MAJOR,
                SANE_CURRENT_MINOR, 0);
    }

    (void) authorize;

    status = airscan_init(0, "sane_init() called");
    if (status == SANE_STATUS_GOOD) {
        status = device_management_init();
    }

    if (status != SANE_STATUS_GOOD) {
        log_debug(NULL, "sane_init(): %s", sane_strstatus(status));
    }

    return status;
}

/* Exit the backend
 */
void
sane_exit (void)
{
    log_debug(NULL, "sane_exit() called");

    eloop_thread_stop();
    device_management_cleanup();
    airscan_cleanup("sane_exit(): OK");
}

/* Get list of devices
 */
SANE_Status
sane_get_devices (const SANE_Device ***device_list, SANE_Bool local_only)
{
    if (local_only) {
        /* Note, all our devices are non-local */
        static const SANE_Device *empty_devlist[1] = {0};
        *device_list = empty_devlist;
    } else {
        eloop_mutex_lock();

        zeroconf_device_list_free(sane_device_list);
        sane_device_list = zeroconf_device_list_get();
        *device_list = sane_device_list;

        eloop_mutex_unlock();
    }

    return SANE_STATUS_GOOD;
}

/* Open the device
 */
SANE_Status
sane_open (SANE_String_Const name, SANE_Handle *handle)
{
    SANE_Status         status;
    device              *dev;
    const SANE_Device   **dev_list = NULL;

    eloop_mutex_lock();

    /* If name is not set, open the first device
     */
    if (name == NULL || *name == '\0') {
        dev_list = zeroconf_device_list_get();
        if (dev_list[0] != NULL) {
            name = dev_list[0]->name;
        }
    }

    dev = device_open(name, &status);

    eloop_mutex_unlock();

    if (dev != NULL) {
        *handle = (SANE_Handle) dev;
    }

    log_debug(device_log_ctx(dev), "sane_open(\"%s\"): %s", name ? name : "",
            sane_strstatus(status));

    zeroconf_device_list_free(dev_list);

    return status;
}

/* Close the device
 */
void
sane_close (SANE_Handle handle)
{
    device *dev = (device*) handle;

    log_debug(device_log_ctx(dev), "sane_close()");

    eloop_mutex_lock();
    device_close((device*) handle);
    eloop_mutex_unlock();
}

/* Get option descriptor
 */
const SANE_Option_Descriptor *
sane_get_option_descriptor (SANE_Handle handle, SANE_Int option)
{
    device *dev = (device*) handle;
    const SANE_Option_Descriptor *desc;

    eloop_mutex_lock();
    desc = device_get_option_descriptor(dev, option);
    eloop_mutex_unlock();

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
    const SANE_Option_Descriptor *desc;

    eloop_mutex_lock();

    /* Roughly validate arguments */
    if (dev == NULL || value == NULL) {
        goto DONE;
    }

    desc = device_get_option_descriptor(dev, option);
    if (desc == NULL) {
        goto DONE;
    }

    if (action == SANE_ACTION_SET_VALUE && !SANE_OPTION_IS_SETTABLE(desc->cap)){
        goto DONE;
    }

    /* Get/set the option */
    if (action == SANE_ACTION_GET_VALUE) {
        status = device_get_option(dev, option, value);
    } else {
        status = device_set_option(dev, option, value, info);
    }

DONE:
    eloop_mutex_unlock();

    return status;
}

/* Get current scan parameters
 */
SANE_Status
sane_get_parameters (SANE_Handle handle, SANE_Parameters *params)
{
    SANE_Status status = SANE_STATUS_GOOD;
    device *dev = (device*) handle;

    if (params != NULL) {
        eloop_mutex_lock();
        status = device_get_parameters(dev, params);
        eloop_mutex_unlock();
    }

    if (status != SANE_STATUS_GOOD) {
        log_debug(NULL, "sane_get_params(): %s", sane_strstatus(status));
    }

    return status;
}

/* Start scanning operation
 */
SANE_Status
sane_start (SANE_Handle handle)
{
    SANE_Status status;
    device *dev = (device*) handle;

    log_debug(device_log_ctx(dev), "sane_start()");

    eloop_mutex_lock();
    status = device_start(dev);
    eloop_mutex_unlock();

    if (status != SANE_STATUS_GOOD) {
        log_debug(device_log_ctx(dev),
            "sane_start(): %s", sane_strstatus(status));
    }

    return status;
}

/* Read scanned image
 */
SANE_Status
sane_read (SANE_Handle handle, SANE_Byte *data, SANE_Int max_len, SANE_Int *len)
{
    SANE_Status status;
    device *dev = (device*) handle;

    eloop_mutex_lock();
    status = device_read(dev, data, max_len, len);
    eloop_mutex_unlock();

    if (status != SANE_STATUS_GOOD) {
        log_debug(device_log_ctx(dev),
            "sane_read(): %s", sane_strstatus(status));
    }

    return status;
}

/* Cancel scanning operation
 */
void
sane_cancel (SANE_Handle handle)
{
    device *dev = handle;

    /* Note, no mutex lock here. We can be called from
     * signal handler. device_cancel() properly handles it
     */
    device_cancel(dev);
}

/* Set I/O mode
 */
SANE_Status
sane_set_io_mode (SANE_Handle handle, SANE_Bool non_blocking)
{
    device      *dev = handle;
    SANE_Status status;

    eloop_mutex_lock();
    status = device_set_io_mode(dev, non_blocking);
    eloop_mutex_unlock();

    if (status != SANE_STATUS_GOOD) {
        log_debug(device_log_ctx(dev), "sane_set_io_mode(%s): %s",
            non_blocking ? "true" : "false", sane_strstatus(status));
    }

    return status;
}

/* Get select file descriptor
 */
SANE_Status
sane_get_select_fd (SANE_Handle handle, SANE_Int *fd)
{
    device      *dev = handle;
    SANE_Status status;

    eloop_mutex_lock();
    status = device_get_select_fd(dev, fd);
    eloop_mutex_unlock();

    if (status != SANE_STATUS_GOOD) {
        log_debug(device_log_ctx(dev),
            "sane_get_select_fd(): %s", sane_strstatus(status));
    }

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
