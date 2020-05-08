project('sane-airscan', 'c')

sources = [
  'airscan-array.c',
  'airscan-bmp.c',
  'airscan-conf.c',
  'airscan-devcaps.c',
  'airscan-device.c',
  'airscan-devid.c',
  'airscan-devops.c',
  'airscan-eloop.c',
  'airscan-escl.c',
  'airscan-http.c',
  'airscan-id.c',
  'airscan-ip.c',
  'airscan-jpeg.c',
  'airscan-log.c',
  'airscan-math.c',
  'airscan-mdns.c',
  'airscan-netif.c',
  'airscan-png.c',
  'airscan-pollable.c',
  'airscan-rand.c',
  'airscan-trace.c',
  'airscan-uuid.c',
  'airscan-wsd.c',
  'airscan-wsdd.c',
  'airscan-xml.c',
  'airscan-zeroconf.c',
  'airscan.c',
  'sane_strstatus.c',
]

cc = meson.get_compiler('c')
m_dep = cc.find_library('m', required : false)

shared_deps = [
  m_dep,
  dependency('avahi-client'),
  dependency('avahi-glib'),
  dependency('libjpeg'),
  dependency('libpng'),
  dependency('libsoup-2.4'),
  dependency('libxml-2.0'),
]

shared_library(
  meson.project_name(),
  sources,
  version: '1',
  dependencies: shared_deps,
  link_args : [
    '-Wl,-z,nodelete',
    '-Wl,--version-script=' + join_paths(meson.current_source_dir(), 'airscan.sym')
  ],
  link_depends : [ 'airscan.sym' ],
  install : true,
  install_dir : 'lib/sane'
)

executable(
  'airscan-discover',
  sources + ['discover.c'],
  dependencies: shared_deps,
  install: true
)

install_man('sane-airscan.5')
install_man('airscan-discover.1')
install_data(['airscan.conf', 'dll.conf'], install_dir : 'etc/sane.d')
