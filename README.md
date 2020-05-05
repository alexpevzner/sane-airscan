# WARNING WARNING WARNING WARNING

This project is a "development/unstable" branch of the [sane-airscan](https://github.com/alexpevzner/sane-airscan/)
project, forked for convenience into the separate repository. New major features
are developed here, and then merged back to sane-airscan.  It is not intended for common use.

# sane-airscan -- Linux support for Apple AirScan (eSCL) and Miscosoft WSD document scanners

Similar to how most modern network printers support "driverless" printing,
using the universal vendor-neutral printing protocol, many modern network
scanners and MFPs support "driverless" scanning.

Driverless scanning comes in two flavors:
* Apple **AirScan** or **AirPrint scanning** (official protocol name is eSCL)
* Microsoft **WSD**, or **WS-Scan** (term WSD means "Web Services for Devices)

This backend implements both protocols, choosing automatically between them.
It was successfully tested with many devices from **Brother**, **Canon**,
**Kyocera**, **Epson**, **HP** and **Xerox** both in WSD and eSCL modes.

For eSCL devices, Apple maintains [a comprehensive list](https://support.apple.com/en-us/HT201311)
of compatible devices, but please note, this list contains not only scanners and MFP,
but pure printers as well.

This backend doesn't require to install and doesn't conflict with
vendor-provided proprietary software like ScanGear from Canon, HPLIP from HP
and so on.

### Features

1. One backend for two different protocols, eSCL and WSD
2. Automatic and manual device discovery and configuration
3. Scan from platen and ADF, in duplex and simplex modes, multi-page
scan from ADF supported as well
4. Scan in color and gray scale modes
5. Line-by-line image unpacking, for low memory footprint
6. The cancel operation is as fast as possible, depending on your hardware
7. Both IPv4 and IPv6 are supported

### Compatibility

Any **eSCL** and **WSD** apable scanner expected to work. Here is a list of devices
that were actually tested. If you have success with a scanner not included
into this list, please let me know.

#### Scanners, tested in eSCL mode

* Brother MFC-L2750DW
* Canon D570
* Canon ImageCLASS MF743cdw <sup>[1](#noteMF743cdw)</sup>
* Canon Lide 400
* Canon TR4529 (PIXMA TR4500 Series)
* Canon TS 3100
* Canon TS 3300
* Canon TS 6151
* Canon TS 6250
* EPSON WF-7710
* EPSON XP-7100 Series
* HP Color Laserjet MFP m178-m181
* HP Color LaserJet MFP M281fdw
* HP DeskJet 2540
* HP ENVY 4500
* HP ENVY 5540
* HP LaserJet MFP M227sdn
* HP LaserJet MFP M426dw
* HP LaserJet MFP M630
* HP LaserJet Pro M28w
* HP LaserJet Pro MFP 148fdw
* HP LaserJet Pro MFP M428dw
* HP Officejet 4630
* HP Officejet Pro 6970
* HP OfficeJet Pro 6978
* HP OfficeJet Pro 8730
* HP OfficeJet Pro 9010 series
* Kyocera ECOSYS M2040dn
* Xerox VersaLink B405
* TODO

---
<a name="noteMF743cdw">[1]</a>: this device requires manual activation of AirPrint
scanning on its web console: Home->Menu->Preferences->Network->TCP/IP
Settings->Network Link Scan Settings->On.

#### Scanners, tested in WSD mode

* Brother MFC-L2750DW
* HP LaserJet Pro MFP M521dn
* HP OfficeJet Pro 8730
* Kyocera ECOSYS M2040dn <sup>[2](#noteM2040dn)</sup>

---
<a name="noteM2040dn">[2]</a>: this device requires manual action on its front
panel to initiate WSD scan: Send->WSD Scan->From Computer

### Installation from pre-build binaries

If you use one of the following Linux distros:
* **Debian** (9.0 and 10)
* **Fedora** (29, 30, 31 and 32)
* **openSUSE** (Leap and Tumbleweed)
* **Ubuntu** (16.04, 18.04, 19.04, 19.10 and 20.04)

[Follow this link](https://software.opensuse.org//download.html?project=home%3Apzz&package=sane-airscan),
where you will find packages and very detailed installation instructions.

Note, after a fresh build this link sometimes takes too long to update, so if you encounter
"Resource is no longer available!" problems, there is
a direct link to repositories: [https://download.opensuse.org/repositories/home:/pzz/](https://download.opensuse.org/repositories/home:/pzz/)

I strongly recommend you to choose "Add repository and install manually"
option rather that "Grab binary packages directly", because it will
enable automatic updates of the sane-airscan package.

**Linux Mint** users may use Ubuntu packages:
* Linux Mint 18.x - use packages for Ubuntu 16.04
* Linux Mint 19.x - use packages for Ubuntu 18.04

For **Arch Linux**, there are packages, maintained by
Thomas Kiss <thomas.kiss001@stud.fh-dortmund.de>:
* https://aur.archlinux.org/packages/sane-airscan/ - latest release
* https://aur.archlinux.org/packages/sane-airscan-git/ - GIT snapshot

Big thanks to [openSUSE Build Service](https://build.opensuse.org/), for
providing package build infrastructure.

If your distro is not listed, see
[Installation from sources](https://github.com/alexpevzner/sane-airscan#installation-from-sources)
section below.

### Installation from sources
#### Install required libraries - Fedora and similar
As root, execute the following commands:
```
dnf install gcc git make pkgconf-pkg-config
dnf install avahi-devel avahi-glib-devel
dnf install glib2-devel libsoup-devel libxml2-devel
dnf install libjpeg-turbo-devel sane-backends-devel
dnf install libpng-devel
```
#### Install required libraries - Ubuntu, Debian and similar
As root, execute the following commands:
```
apt-get install libavahi-client-dev libavahi-glib-dev
apt-get install gcc git make pkg-config
apt-get install libglib2.0-dev libsoup2.4-dev libxml2-dev
apt-get install libjpeg-dev libsane-dev
apt-get install libpng-dev
```
#### Download, build and install sane-airscan
```
git clone https://github.com/alexpevzner/sane-airscan.git
cd sane-airscan
make
make install
```
### Contribution

If you want to contribute to this project, consider using the following
branch:

https://github.com/alexpevzner/sane-airscan-wsd

All new features should go there. Here I can accept only bug fixing
and packaging changes.

Changes from the sane-airscan-wsd branch will be periodically merged into
the sane-airscan. Next merge expected to happen before middle of April 2020.

### Code Quality
I greatly appreciate a good static code analysis tools, as they help to maintain
a high code quality.

This project compiles without any warning by gcc and clang compilers.

Recently it was checked by [PVS-Studio](https://www.viva64.com/en/pvs-studio/) static code
analyser, and it found a couple of bugs (that were immediately fixed, of course), so I can
recommend this tool. Though this tool is commercial, they offer a free subscription for
open source projects.

### Reporting bugs
To report a bug, please [create a new GitHub issue](https://github.com/alexpevzner/sane-airscan/issues/new)

To create a helpful bug report, please perform the following steps:

1. Enable protocol trace in the sane-airscan, by adding the following
entries into the configuration file <br> (**/etc/sane.d/airscan.conf**):
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
"Kyocera MFP Scanner", file names will be **"xsane-Kyocera-MFP-Scanner.log"**
and **"xsane-Kyocera-MFP-Scanner.tar"**. Please, attach both of these files
to the new issue.

## References

The eSCL protocol is not documented, but this is simple protocol,
based on HTTP and XML, easy for reverse engineering. There are many
Internet resources around, related to this protocol, and among others
I want to note the following links:

* [kno10/python-scan-eSCL](https://github.com/kno10/python-scan-eSCL) - a tiny
Python script, able to scan from eSCL-compatible scanners
* [SimulPiscator/AirSane](https://github.com/SimulPiscator/AirSane) - this
project solves the reverse problem, converting any SANE-compatible scanner
into eSCL server. Author claims that it is compatible with Mopria and
Apple clients
* [markosjal/AirScan-eSCL.txt](https://gist.github.com/markosjal/79d03cc4f1fd287016906e7ff6f07136) - document,
describing eSCL protocol, based on reverse engineering. Not complete and
not always accurate, but gives the good introduction
