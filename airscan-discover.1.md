airscan-discover -- Discover sane-airscan compatible scanners
===================================================================

## SYNOPSIS

`airscan-discover [options]`

## DESCRIPTION

`airscan-discover` is a command-line tool to find eSCL and WSD
scanners on a local network

It uses Avahi to discover DNS-SD devices and its own implementation
of WS-Discovery to discover WSD devices.

On success, it outputs a fragment of sane-airscan configuration
file, that can be directly added to `/etc/sane.d/airscan.conf`

## OPTIONS

   * `-test-fast` or `--test-fast`:
     Fast discovery mode (see ane-airscan(5) for details)

   * `-test-auto` or `--test-auto`:
     Automatic protocol selection (see ane-airscan(5) for details)

   * `-d`:
     Print debug messages to console

   * `-t`:
     Write a very detailed protocol trace to `airscan-discover-zeroconf.log`
     and `airscan-discover-zeroconf.tar`

   * `-h`:
     Print help screen

## FILES

   * `airscan-discover-zeroconf.log`:
     Protocol trace

   * `airscan-discover-zeroconf.tar`:
     Non-textual messages, if any, saved here. Textual (i.e., XML)
     messages included directly into the .log file

## SEE ALSO

**sane(7), sane-airscan(5)**

## AUTHOR
Alexander Pevzner <pzz@apevzner.com\>

# vim:ts=8:sw=4:et

