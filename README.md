# sane-airscan -- SANE backend for AirScan (eSCL) and WSD document scanners

Similar to how most modern network printers support "driverless" printing,
using the universal vendor-neutral printing protocol, many modern network
scanners and MFPs support "driverless" scanning.

Driverless scanning comes in two flavors:
* Apple **AirScan** or **AirPrint scanning** (official protocol name is eSCL)
* Microsoft **WSD**, or **WS-Scan** (term WSD means "Web Services for Devices)

This backend implements both protocols, choosing automatically between them.
It was successfully tested with many devices from **Brother**, **Canon**,
**Dell**, **Kyocera**, **Lexmark**, **Epson**, **HP**, **OKI**, **Panasonic**,
**Pantum**, **Ricoh**, **Samsung** and **Xerox** both in WSD and eSCL modes.

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

Any **eSCL** and **WSD** capable scanner expected to work. Here is a list of devices
that were actually tested. If you have success with a scanner not included
into this list, please let me know.

In most cases, devices were tested with network connection. However, most (all?) of
the **eSCL** devices will also work over **USB**, if **IPP-over-USB** daemon is installed on
your computer. WSD-only devices cannot be used with the IPP-over-USB daemon.

Currently, there is a choice of two **IPP-over-USB** implementations:
* [ippusbxd](https://github.com/OpenPrinting/ippusbxd), which comes with some distros
* [ipp-usb](https://github.com/OpenPrinting/ipp-usb), a modern replacement of the `ippusbxd`.
The `ipp-usb` works better, binary packages available for many popular distros (see link from
a project page).

Legend:

* **Yes** - device works perfectly
* **No** - protocol not supported by device
* **?** - device works with `sane-airscan`, but protocol is not reported by user
* Space - author has no information on this mode/device combination

| Device                             | eSCL mode                 | WSD mode                  |
| ---------------------------------- | :-----------------------: | :-----------------------: |
| Brother ADS-2700W                  | No                        | Yes                       |
| Brother DCP-7055W                  | No                        | Yes                       |
| Brother DCP-9020CDW                | No                        | Yes                       |
| Brother DCP-J552DW                 | No                        | Yes                       |
| Brother DCP-L2540DW                | No                        | Yes                       |
| Brother DCP-L2550DN / DCP-L2550DW  | Yes                       |                           |
| Brother HL-L2380DW series          | No                        | Yes                       |
| Brother HL-L2395DW series          | Yes                       |                           |
| Brother MFC-7360N                  | No                        | Yes                       |
| Brother MFC-8710DW                 | No                        | Yes                       |
| Brother MFC-J1300DW                | Yes                       |                           |
| Brother MFC-J4410DW                | No                        | Yes                       |
| Brother MFC-J485DW                 | Yes                       |                           |
| Brother MFC-J625DW                 | No                        | Yes                       |
| Brother MFC-L2700DW                | No                        | Yes                       |
| Brother MFC-L2710DW                | Yes                       | Yes                       |
| Brother MFC-L2720DW                | No                        | Yes                       |
| Brother MFC-L2750DW                | Yes                       | Yes                       |
| Canon D570                         | Yes                       |                           |
| Canon G600 series                  | Yes                       |                           |
| Canon imageCLASS MF642C/643C/644C  | Yes                       |                           |
| Canon imageCLASS MF743cdw          | Yes<sup>[1](#note1)</sup> |                           |
| Canon imageRUNNER 2625/2630        | Yes                       | Yes                       |
| Canon imageRUNNER ADVANCE 4545/4551| Yes                       | Yes                       |
| Canon imageRUNNER ADV C5550/5560   | Yes                       |                           |
| Canon imageRUNNER C3120L           | Yes                       | Yes                       |
| Canon i-SENSYS MF4780w             | No                        | Yes<sup>[4](#note4)</sup> |
| Canon i-SENSYS MF641C              | No                        | Yes<sup>[2](#note2)</sup> |
| Canon LiDE 300                     | Yes<sup>[3](#note3)</sup> |                           |
| Canon LiDE 400                     | Yes<sup>[3](#note3)</sup> |                           |
| Canon MB5100 series                | Yes                       |                           |
| Canon MB5400 series                | Yes                       | Yes                       |
| Canon MF110/910                    | Yes                       |                           |
| Canon MF240 Series                 | No                        | Yes<sup>[4](#note4)</sup> |
| Canon MF260 Series                 | Yes                       | Yes<sup>[4](#note4)</sup> |
| Canon MF410 Series                 | Yes                       | Yes                       |
| Canon MF440 Series                 | Yes                       | Yes                       |
| Canon MF645Cx                      | Yes                       |                           |
| Canon MF745C/746C                  | Yes                       | Yes                       |
| Canon MG5300 series                | No                        | Yes                       |
| Canon PIXMA G3000 series           | No                        | Yes                       |
| Canon PIXMA MG3600 series          | Yes                       |                           |
| Canon PIXMA MG5500 Series          | No                        | Yes                       |
| Canon PIXMA MG7700 Series          | Yes                       |                           |
| Canon PIXMA TS5000 Series          | Yes                       |                           |
| Canon PIXMA TS 9550 Series         | Yes                       |                           |
| Canon TR4529 (PIXMA TR4500 Series) | Yes                       | Yes                       |
| Canon TR7500 Series                | No                        | Yes                       |
| Canon TS 3100                      | Yes                       |                           |
| Canon TS 3300                      | Yes                       |                           |
| Canon TS 3400                      | Yes                       |                           |
| Canon TS 6151                      | Yes                       |                           |
| Canon TS 6200 series               | Yes                       | Yes                       |
| Canon TS 6400 series               | Yes                       |                           |
| Dell C1765nfw Color MFP            | No                        | Yes                       |
| Dell C2665dnf Color Laser Printer  | No                        | Yes                       |
| Dell C3765dnf Color MFP            | No                        | Yes                       |
| EPSON ET-2710 Series               | No                        | Yes                       |
| EPSON ET-2750 Series               | Yes                       |                           |
| EPSON ET-2760 Series               | Yes                       |                           |
| EPSON ET-2810 Series               | No                        | Yes                       |
| EPSON ET-2850 Series               | Yes                       |                           |
| EPSON ET-3750 Series               | Yes                       |                           |
| EPSON ET-4850 Series               | Yes                       |                           |
| EPSON ET-M2170 Series              | Yes                       |                           |
| EPSON Stylus SX535WD               | No                        | Yes                       |
| EPSON WF-7710 Series               | No                        | Yes                       |
| EPSON XP-2100 Series               | No                        | Yes                       |
| EPSON XP-340 Series                | Yes                       |                           |
| EPSON XP-442 445 Series            | Yes                       |                           |
| EPSON XP-5100 Series               | Yes                       |                           |
| EPSON XP-6100 Series               | Yes                       |                           |
| EPSON XP-7100 Series               | Yes                       |                           |
| EPSON XP-8600 Series               | Yes                       |                           |
| HP Color Laserjet MFP m178-m181    | Yes                       |                           |
| HP Color LaserJet MFP M182nw       | Yes                       |                           |
| HP Color LaserJet MFP M281fdw      | Yes                       |                           |
| HP Color LaserJet MFP M283fdw      | Yes                       |                           |
| HP Color LaserJet MFP M477fdw      | Yes                       | Yes                       |
| HP Color LaserJet Pro M478f-9f     | Yes                       |                           |
| HP Color LaserJet Pro MFP M277dw   | Yes                       |                           |
| HP DeskJet 2540                    | Yes                       |                           |
| HP DeskJet 2600 series             | Yes                       |                           |
| HP DeskJet 2700 series             | Yes                       |                           |
| HP DeskJet 3700 series             | Yes                       |                           |
| HP DeskJet 5000 series             | Yes                       |                           |
| HP DeskJet 5200 series             | Yes                       |                           |
| HP ENVY 4500                       | Yes                       |                           |
| HP ENVY 5055 series                | Yes                       |                           |
| HP ENVY 5530 series                | Yes                       |                           |
| HP ENVY 5540                       | Yes                       |                           |
| HP ENVY 5640                       | Yes                       |                           |
| HP ENVY Photo 6200 series          | Yes                       |                           |
| HP ENVY Photo 7800 series          | Yes                       |                           |
| HP ENVY Pro 6400 series            | Yes                       |                           |
| HP LaserJet 200 colorMFP M276n     | No                        | Yes                       |
| HP LaserJet MFP E62655             | Yes                       |                           |
| HP LaserJet MFP M130fw             | No                        | Yes                       |
| HP LaserJet MFP M227sdn            | Yes                       |                           |
| HP LaserJet MFP M426dw             | Yes                       |                           |
| HP LaserJet MFP M630               | Yes                       |                           |
| HP LaserJet Pro M28a               | Yes<sup>[3](#note3)</sup> |                           |
| HP LaserJet Pro M28w               | Yes                       | Yes                       |
| HP LaserJet Pro MFP 148fdw         | Yes                       |                           |
| HP LaserJet Pro MFP M125 series    | No                        | Yes                       |
| HP LaserJet Pro MFP M225dn         | No                        | Yes                       |
| HP LaserJet Pro MFP M428dw         | Yes                       |                           |
| HP LaserJet Pro MFP M521 series    | No                        | Yes                       |
| HP Laser MFP 131 133 135-138       | Yes                       |                           |
| HP Neverstop Laser MFP 1202nw      | ?                         | ?                         |
| HP OfficeJet 3830 series           | Yes                       |                           |
| HP Officejet 4630                  | Yes                       |                           |
| HP Officejet Pro 6970              | Yes                       |                           |
| HP OfficeJet Pro 6978              | Yes                       |                           |
| HP OfficeJet Pro 7740              | Yes                       | No                        |
| HP OfficeJet Pro 8010 series       | Yes                       |                           |
| HP OfficeJet Pro 8020 Series       | Yes                       |                           |
| HP OfficeJet Pro 8730              | Yes                       | Yes                       |
| HP OfficeJet Pro 9010 series       | Yes                       |                           |
| HP ScanJet Pro 3500 fn1            | Yes<sup>[3](#note3)</sup> |                           |
| HP ScanJet Pro 4500 fn1            | Yes                       |                           |
| HP Smart Tank Plus 550 series      | Yes                       |                           |
| Kyocera ECOSYS M2035dn             | No                        | Yes<sup>[5](#note5)</sup> |
| Kyocera ECOSYS M2040dn             | Yes                       | Yes<sup>[5](#note5)</sup> |
| Kyocera ECOSYS M5521cdw            | Yes                       | Yes<sup>[5](#note5)</sup> |
| Kyocera ECOSYS M5526cdw            | Yes                       |                           |
| Lexmark CX317dn                    | Yes<sup>[6](#note6)</sup> | Yes<sup>[6](#note6)</sup> |
| Lexmark MB2236adw                  | Yes                       |                           |
| Lexmark MC2535adwe                 | Yes                       |                           |
| Lexmark MC3224adwe                 | Yes                       |                           |
| Lexmark MC3326adwe                 | Yes                       |                           |
| OKI-MC853                          | Yes                       |                           |
| Panasonic KV-S1058Y                | No                        | Yes                       |
| Pantum M6500W series               | Yes                       |                           |
| Ricoh MP C3003                     | No                        | Yes<sup>[7](#note7)</sup> |
| Samsung M2070 Series               | No                        | Yes                       |
| Samsung M267x 287x Series          | No                        | Yes                       |
| Samsung M288x Series               | No                        | Yes                       |
| Samsung M337x 387x 407x Series     | No                        | Yes<sup>[8](#note8)</sup> |
| Samsung SCX-3400 Series            | No                        | Yes                       |
| Xerox B205                         | Yes                       | Yes                       |
| Xerox B215                         | Yes                       |                           |
| Xerox C235                         | Yes                       |                           |
| Xerox VersaLink B405               | Yes                       |                           |
| Xerox WorkCentre 3025              | No                        | Yes                       |
| TODO                               |                           |                           |

---
<a name="note1"><sup>[1]</sup></a>: this device requires manual activation of AirPrint
scanning on its web console: Home->Menu->Preferences->Network->TCP/IP
Settings->Network Link Scan Settings->On.

<a name="note2"><sup>[2]</sup></a>: WS-Scan needs to be manually enabled on this device:
Home->Menu->Preferences->Network->TCP/IP Settings->WSD Settings->Use WSD Scanning->ON

<a name="note3"><sup>[3]</sup></a>: this device is USB-only, but it works well with the
IPP-over-USB daemon.

<a name="note4"><sup>[4]</sup></a>: by default, WS-Scan is disabled on this
device and needs to be enabled before use: open web console, Click `[Settings/Registration]`,
Click `[Network Settings]`->`[TCP/IP Settings]`, Click `[Edit]` in `[WSD Settings]`,
enable `[Use WSD Scanning]` checkbox, Click `[OK]`

<a name="note5"><sup>[5]</sup></a>: this device requires manual action on its front
panel to initiate WSD scan: Send->WSD Scan->From Computer

<a name="note6"><sup>[6]</sup></a>: when low in memory, this device may scan at 400 DPI
instead of requested 600 DPI. As sane-airscan reports image parameters to SANE before actual
image is received, and then adjust actual image to reported parameters, image will
be scaled down by the factor 2/3 at this case. Lower resolutions works well.

<a name="note7"><sup>[7]</sup></a>: by default, WS-Scan is disabled on this
device and needs to be enabled before use: open web console, Click `[Configuration]`, click `[Initial Settings]`
under `[Scanner]`, and then set `[Prohibit WSD Scan Command]` to `[Do not Prohibit]` (from
http://support.ricoh.com/bb_v1oi/pub_e/oi_view/0001047/0001047003/view/scanner/int/0095.htm)

<a name="note8"><sup>[8]</sup></a>: with old firmware (tested with
V4.00.01.04 APR-09-2013) ADF scan causes device reboot. Firmware update
helps, version V4.00.02.20 MAY-27-2020 known to work.

### Distros that come with sane-airscan

The following distros (in alphabetical order) include `sane-airscan`
officially:
* ALT Linux (Sisyphus and p9)
* Arch Linux (in extra repository)
* Debian 10+
* Fedora 32+
* NixOS
* Ubuntu 20.10+

This list is constantly growing and may be very incomplete.

Also, `sane-airscan` works on BSD and included into FreeBSD, NetBSD and OpenBSD ports.

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
* Linux Mint 20.x - use packages for Ubuntu 20.04

Big thanks to [openSUSE Build Service](https://build.opensuse.org/) for
providing package build infrastructure.

If your distro is not listed, see
[Installation from sources](https://github.com/alexpevzner/sane-airscan#installation-from-sources)
section below.

### Installation from sources
#### Install required libraries - Fedora and similar
As root, execute the following commands:
```
dnf install gcc git make pkgconf-pkg-config
dnf install avahi-devel
dnf install libxml2-devel
dnf install libjpeg-turbo-devel libpng-devel
dnf install gnutls-devel
dnf install sane-backends-devel
```
#### Install required libraries - Ubuntu, Debian and similar
As root, execute the following commands:
```
apt-get install gcc git make pkg-config
apt-get install libavahi-client-dev
apt-get install libxml2-dev
apt-get install libjpeg-dev libpng-dev
apt-get install libsane-dev
apt-get install gnutls-dev
```
#### Download, build and install sane-airscan
```
git clone https://github.com/alexpevzner/sane-airscan.git
cd sane-airscan
make
make install
```
### Contribution

All contributions are welcome and greatly appreciated, assuming the following:

1. Feature that you propose has a general interest for many people
2. Your code is well-formatted and has a good quality

Please note, this project has two branches:

* stable branch: https://github.com/alexpevzner/sane-airscan
* development branch: https://github.com/alexpevzner/sane-airscan-unstable

Stable branch accepts mostly bug fixes and minor features with small
change in code base. Major features should be contributed into the
development branch.

### Paid consulting

If your business depends on my project, and you require any specific feature not
currently implemented here, you may consider contracting me on a paid basis.

### PVS-Studio

[PVS-Studio](https://www.viva64.com/en/pvs-studio/) is a static code analyser,
supporting C, C++, C# and Java.

Once upon a time I was chatting with its authors in Russian software development
forum and told them, that if their tool will find something interesting in my
code, I will put a reference to their project here.

Their tool actually found a couple real bugs, so I had to fulfill my promise :-)

Now I regularly test this code with PVS-Studio, and it really helps. Their
product is not free, but they offer free licenses for open source projects.

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
