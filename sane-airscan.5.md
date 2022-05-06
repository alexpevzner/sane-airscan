sane-airscan(5) -- SANE backend for AirScan (eSCL) and WSD scanners and MFP
===========================================================================

## DESCRIPTION

The `sane-airscan` is the universal backend for "driverless" document
scanning. Currently it supports two protocols:

    1. eSCL, also known as AirScan or AirPrint scan
    2. WSD, also known as WS-Scan

## CONFIGURATION

The sane-airscan loads its configuration files from the following places:

    1. /etc/sane.d/airscan.conf  
    2. /etc/sane.d/airscan.d/*

The configuration file syntax is very similar to the .INI file syntax.
It consist of sections, each section contains some variables. Comments
are started from # or ; characters and continies until end of line

    # This is a comment
    [section 1]
    variable 1 = value 1  ; and another comment
    variable 2 = value 2

Leading and trailing spaces of variable name and value are striped.
If you want to preserve them, put name or value into quotes ("like this").

## CONFIGURATION OF DEVICES

If scanner and computer are connected to the same LAN segment, everything
expected to "just work" out of box, without any need of manual configuration.

However, in some cases manual configuration can be useful. For example:

    1. If computer and scanner are connected via IP router
    2. There are a lot of devices on a corporate network, but
       only few of them are interesting
    3. Automatic discovery works unreliable

To manually configure a device, add the following section to the configuration
file:

    [devices]
    "Kyocera eSCL" = http://192.168.1.102:9095/eSCL, eSCL
    "Kyocera WSD" = http://192.168.1.102:5358/WSDScanner, WSD
    "Device I do not want to see" = disable

The `[devices]` section contains all manually configured devices, one line per
device, and each line contains a device name on a left side of equation and
device URL on a rights side, followed by protocol (eSCL or WSD). If protocol
is omitted, eSCL is assumed.  You may also disable particular device by
using the `disable` keyword instead of URL.

In addition, you can manually configure a device by directly passing its URL in
a device name without adding it to the configuration file.  This takes the
format `protocol:Device Name:URL`.  The examples above could be written as
`escl:Kyocera eSCL:http://192.168.1.102:9095/eSCL` and
`wsd:Kyocera WSD:http://192.168.1.102:5358/WSDScanner`.

To figure out URLs of available devices, the simplest way is to
run the supplied `airscan-discover(1)` tool on a computer connected with
scanner to the same LAN segment. On success, this program will
dump to its standard output a list of discovered devices in a
format suitable for inclusion into the configuration file.

If running `airscan-discover(1)` on the same LAN segment as a scanner is not
possible, you will have to follow a hard way. Your administrator must know
device IP address, consult your device manual for the eSCL port, and
the URL path component most likely is the "/eSCL", though on some
devices it may differ. Discovering WSD URLs doing this way is much
harder, because it is very difficult to guess TCP port and URL path,
that in a case of eSCL.

For eSCL devices, the URL can also use the unix:// scheme, such as
unix://scanner.sock/eSCL.  The "host" from the URL is a file name that will be
searched for in the directory specified by socket_dir (see below).  When
connecting to the scanner, all traffic will be sent to the specified UNIX socket
instead of a TCP connection.

## CONFIGURATION OPTIONS

Miscellaneous options all goes to the ``[options]`` section. Currently
the following options are supported:

    [options]
    ; If there are a lot of scanners around and you are only
    ; interested in few of them, disable auto discovery and
    ; configure scanners manually.
    discovery = enable | disable

    ; Choose what SANE apps will show in a list of devices:
    ; scanner network name (the default) or hardware model name.
    model = network | hardware

    ; If device supports both eSCL and WSD protocol, sane-airscan
    ; may either choose the "best" protocol automatically, or
    ; expose all variants for user, allowing manual protocol selection.
    ; The default is "auto".
    protocol = auto | manual

    ; Discovery of WSD devices may be "fast" or "full". The "fast"
    ; mode works as fast as DNS-SD discovery, but in some cases
    ; may be unreliable. The "full" mode is slow and reliable.
    ; It is also possible to disable automatic discovery
    ; of WSD devices. The default is "fast".
    ws-discovery = fast | full | off

    ; Scanners that use the unix:// schema in their URL can only specify a
    ; socket name (not a full path).  The name will be searched for in the
    ; directory specified here. The default is /var/run.
    socket_dir = /path/to/directory

## BLACKLISTING DEVICES

This feature can be useful, if you are on a very big network and have
a lot of devices around you, while interesting only in a few of them.

    [blacklist]
    model = "Xerox*"       ; blacklist by model name
    name  = "HP*"          ; blacklist by network name
    ip    = 192.168.0.1    ; blacklist by address
    ip    = 192.168.0.0/24 ; blacklist the whole subnet

Network names come from DNS-SD, WS-Discovery doesn't provide this
information. For filtering by network name to work, Avahi must be
enabled and device must be discoverable via DNS-SD (not necessarily
as a scanner, it's enough if WSD scanner is discoverable as a printer
via DNS-SD).

Blacklisting only affects automatic discovery, and doesn't
affect manually configured devices.

## DEBUGGING

sane-airscan provides very good instrumentation for troubleshooting
without physical access to the problemmatic device.

Debugging facilities can be controlled using the ``[debug]`` section
of the configuration file:

    [debug]
    ; Enable or disable console logging
    enable = false | true

    ; Enable protocol trace and configure output directory
    ; for trace files. Like in shell, to specify path relative to
    ; the home directory, start it with tilda character, followed
    ; by slash, i.e., "~/airscan/trace". The directory will
    ; be created automatically.
    trace = path

    ; Hex dump all traffic to the trace file (very verbose!)
    hexdump = false | true

## FILES

   * `/etc/sane.d/airscan.conf`, `/etc/sane.d/airscan.d/*`:
     The backend configuration files

   * `/usr/LIBDIR/sane/libsane-airscan.so`:
     The shared library implementing this backend

## ENVIRONMENT

   * `SANE_DEBUG_AIRSCAN`:
     This variable if set to `true` or non-zero numerical value,
     enables debug messages, that are printed to stdout

   * `SANE_CONFIG_DIR`:
     This variable alters the search path for configuration files. This is
     a colon-separated list of directories. These directories are searched
     for the airscan.conf configuration file and for the airscan.d
     subdirectory, before the standard path (/etc/sane.d) is searched.

## BUGS AND SUPPORT

If you have found a bug, please file a GitHub issue on a GitHub
project page: **https://github.com/alexpevzner/sane-airscan**

## SEE ALSO

**sane(7), scanimage(1), xsane(1), airscan-discover(1)**

## AUTHOR
Alexander Pevzner <pzz@apevzner.com\>

# vim:ts=8:sw=4:et
