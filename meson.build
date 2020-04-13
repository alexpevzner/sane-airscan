project('sane-airscan', 'c')

sources = [
  'airscan-array.c',
  'airscan-conf.c',
  'airscan-devcaps.c',
  'airscan-device.c',
  'airscan-devops.c',
  'airscan-eloop.c',
  'airscan-http.c',
  'airscan-jpeg.c',
  'airscan-log.c',
  'airscan-math.c',
  'airscan-opt.c',
  'airscan-pollable.c',
  'airscan-trace.c',
  'airscan-xml.c',
  'airscan-zeroconf.c',
  'airscan.c',
  'sane_strstatus.c',
]

cc = meson.get_compiler('c')
m_dep = cc.find_library('m', required : false)

shared_library(
  meson.project_name(),
  sources,
  dependencies: [
    m_dep,
    dependency('avahi-client'),
    dependency('avahi-glib'),
    dependency('libjpeg'),
    dependency('libsoup-2.4'),
    dependency('libxml-2.0'),
  ],
  link_args : [
    '-Wl,-z,nodelete',
    '-Wl,--version-script=' + join_paths(meson.current_source_dir(), 'airscan.sym')
  ],
  link_depends : [ 'airscan.sym' ],
  install : true,
  install_dir : 'lib/sane'
)

install_man('sane-airscan.5')
install_data(['airscan.conf', 'dll.conf'], install_dir : 'etc/sane.d')
