sane-airscan(5) -- SANE backend for AirScan (eSCL) scanners and MFP
===================================================================

## DESCRIPTION

The `sane-airscan` implements a SANE backend that provides access network
scanners and MFP using eSCL protocol, also known as AirScan or AirPrint scan.

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

Unfortunately, automatic configuration doesn't work if there is an IP
router between computer and scanner. At this case scanner can be added
manually.


To manually configure a device, add the following section to the configuration
file:

    [devices]
    "Kyocera MFP Scanner" = http://192.168.1.102:9095/eSCL
    "Device I don't want to see" = disable

The `[devices]` section contains all manually configured devices, one line per
device, and each line contains a device name on a left side of equation and
device URL on a rights side. You may also disable particular device by
using the `disable` keyword instead of URL.

To figure out the device URL, you need to know its components:

    http://192.168.1.102:9095/eSCL
           <-----------> <--> <-->
                 |         |    |
                 |         |    `-- URL path
                 |         `------- IP port
                 `----------------- Device IP address

The most reliable way to obtain it information, is to execute the following
command, using a Linux computer, connected to the same LAN segment as as
a scanner:

    $ avahi-browse _uscan._tcp -r
    = wlp2s0 IPv4 Kyocera ECOSYS M2040dn
       hostname = [KM7B6A91.local]
       address = [192.168.1.102]
       port = [9095]
       txt = ["duplex=T" "is=platen,adf" "cs=color,grayscale,binary"
       "UUID=4509a320-00a0-008f-00b6-002507510eca"
       "pdl=application/pdf,image/jpeg" "note="
       "ty=Kyocera ECOSYS M2040dn" "rs=eSCL"
       "representation=https://..."
       "adminurl=https://..." "vers=2.62" "txtvers=1"]

Address and port are on obvious places. Please notice the "rs=eSCL"
record in the txt section - this is the path component of the URL.

If running avahi-browse on same LAN segment as a scanner is not possible,
you will have to follow a hard way. Your administrator must know
device IP address, consult your device manual for the eSCL port, and
the URL path component most likely is the "/eSCL", though on some
devices it may differ.

## CONFIGURATION OPTIONS

Miscellaneous options all goes to the ``[options]`` section. Currently
the following options are supported:

    [options]
    ; If there are a lot of scanners around and you are only
    ; interested if few of them, disable auto discovery and
    ; configure scanners manually
    discovery = enable | disable

    ; Choose what SANE apps will show in a list of devices:
    ; scanner network (the default) name or hardware model name
    model = network | hardware

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

sane(7), scanimage(1), xscane(1), airscan-discover(1)

## AUTHOR
Alexander Pevzner <pzz@apevzner.com\>

# vim:ts=8:sw=4:et
