# sane-airscan -- Linux support of Apple AirScan (eSCL) compatible document scanners

Currently many new document scanners and MFPs come with Apple AirScan
support, also known as AirPrint scanning or eSCL protocol. And number of
AirScan-compatible devices tends to grow.

Looks that AirScan becomes de-facto standard protocol for document
scanners, connected to the network. This is very convenient for (Apple)
users, because installation of the new scanner becomes trivial task,
everything "just works" without need to worry about device drivers,
network configuration etc.

Unfortunately, Linux doesn't support AirScan, and the goal of this
project is to fix this situation.

### Features

1. Scan from platen and ADF, in duplex and simplex modes, multi-page
scan from ADF supported as well
2. Scan in color and gray scale modes
3. Reasonably low memory footprint, achieved by on demand decompression of
image received from scanner
4. The cancel operation is as fast as possible, depending on your hardware
5. Automatic discovery and configuration of the hardware
6. Manual configuration is also possible, in case zeroconf doesn't work
(i.e., computer and scanner are connected to the different subnets)

### Compatibility

In theory, sane-airscan must be compatible with any scanner, marked as
AirPrint compatible or Mopria certified, or with announces eSCL protocol
support.

Apple maintains [a comprehensive list](https://support.apple.com/en-us/HT201311)
of compatible devices, but please note, this list contains not only scanners
and MFP, but pure printers as well.

Sane-airscan was tested with the following scanners:
1. Kyocera ECOSYS M2040dn
2. TODO

If you have success with a scanner not included into this list,
please let me know.

### Installation from pre-build binaries

TODO

### Installation from sources
#### Install required libraries - Fedora and similar
As root, execute the following commands:
```
dnf install gcc git make pkgconf-pkg-config
dnf install avahi-devel avahi-glib-devel
dnf install glib2-devel libsoup-devel libxml2-devel
dnf install libjpeg-turbo-devel sane-backends-devel
```
#### Install required libraries - Ubuntu, Debian and similar
As root, execute the following commands:
```
apt-get install libavahi-client-dev libavahi-glib-dev
apt-get install gcc git make pkg-config
apt-get install libglib2.0-dev libsoup2.4-dev libxml2-dev
apt-get install libjpeg-turbo8-dev libsane-dev
```
#### Download, build and install sane-airscan
```
git clone https://github.com/alexpevzner/sane-airscan.git
cd sane-airscan
make
make install
```
### Reporting bugs
To report a bug, please [create a new GitHub issue](https://github.com/alexpevzner/sane-airscan/issues/new)

To create a helpful bug report, please perform the following steps:

1. Enable protocol trace in the sane-airscan, by adding the following
entries into the configuration file:
```
[debug]
trace = ~/airscan/trace ; Path to directory where trace files will be saved
```
You may use an arbitrary directory path, assuming you have enough rights
to create and write this directory. The directory will be created automatically.

2. Reproduce the problem. Please, don't use any confidential documents
when problem is being reproduces, as their content will be visible to
others.

3. Explain the problem carefully

4. In the directory you've specified as the trace parameter, you will find
two files. Assuming you are using program xsane and your device name is
"Kyocera MFP Scanner", file names will be **"xsane:Kyocera-MFP-Scanner.log"**
and **"xsane:Kyocera-MFP-Scanner.tar"**. Please, attach both of these files
to the new issue.

## References

[kno10/python-scan-eSCL](https://github.com/kno10/python-scan-eSCL)

[SimulPiscator/AirSane](https://github.com/SimulPiscator/AirSane)

[markosjal/AirScan-eSCL.txt](https://gist.github.com/markosjal/79d03cc4f1fd287016906e7ff6f07136)
