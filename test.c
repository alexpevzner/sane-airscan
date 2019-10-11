/* sane-airscan backend test
 *
 * Copyright (C) 2019 and up by Alexander Pevzner (pzz@apevzner.com)
 * See LICENSE for license terms and conditions
 */

#include <sane/sane.h>

#include <stddef.h>
#include <unistd.h>

/******************** SANE API function prototypes ********************/
/* Initialize the backend
 */
SANE_Status
sane_init (SANE_Int *version_code, SANE_Auth_Callback authorize);

/* Exit the backend
 */
void
sane_exit (void);

/* Get list of devices
 */
SANE_Status
sane_get_devices (const SANE_Device ***device_list, SANE_Bool local_only);

/* Open the device
 */
SANE_Status
sane_open (SANE_String_Const devicename, SANE_Handle *handle);

/* Close the device
 */
void
sane_close (SANE_Handle handle);

/* Get option descriptor
 */
const SANE_Option_Descriptor *
sane_get_option_descriptor (SANE_Handle handle, SANE_Int option);

/* Get or set option value
 */
SANE_Status
sane_control_option (SANE_Handle handle, SANE_Int option, SANE_Action action,
                     void *value, SANE_Int *info);

/* Get current scan parameters
 */
SANE_Status
sane_get_parameters (SANE_Handle handle, SANE_Parameters *params);

/* Start scanning operation
 */
SANE_Status
sane_start (SANE_Handle handle);

/* Read scanned image
 */
SANE_Status
sane_read (SANE_Handle handle, SANE_Byte *data,
           SANE_Int max_length, SANE_Int *length);

/* Cancel scanning operation
 */
void
sane_cancel (SANE_Handle handle);

/* Set I/O mode
 */
SANE_Status
sane_set_io_mode (SANE_Handle handle, SANE_Bool non_blocking);

/* Get select file descriptor
 */
SANE_Status
sane_get_select_fd (SANE_Handle handle, SANE_Int * fd);


/******************** The main function ********************/
void
main (int argc, char **argv)
{
    (void) argc;
    (void) argv;

    sane_init(NULL, NULL);
    sleep(1000);
}

/* vim:ts=8:sw=4:et
 */
