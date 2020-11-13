project('sane-airscan', 'c', 'cpp')

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
  'airscan-filter.c',
  'airscan-http.c',
  'airscan-id.c',
  'airscan-inifile.c',
  'airscan-init.c',
  'airscan-ip.c',
  'airscan-jpeg.c',
  'airscan-log.c',
  'airscan-math.c',
  'airscan-mdns.c',
  'airscan-memstr.c',
  'airscan-netif.c',
  'airscan-os.c',
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
  'http_parser.c',
  'sane_strstatus.c',
]

cc = meson.get_compiler('c')
m_dep = cc.find_library('m', required : false)

shared_deps = [
  m_dep,
  dependency('avahi-client'),
  dependency('gnutls'),
  dependency('libjpeg'),
  dependency('libpng'),
  dependency('libxml-2.0'),
  dependency('threads'),
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
  install_dir : join_paths(get_option('libdir'), 'sane')
)

executable(
  'airscan-discover',
  sources + ['discover.c'],
  dependencies: shared_deps,
  install: true
)

dll_file = configure_file(
  input : 'dll.conf',
  output: 'airscan',
  copy: true
)

foreach fuzzer : ['query', 'uri', 'xml']
  executable(
    'fuzzer-' + fuzzer,
    sources + ['fuzzer/@0@.cc'.format(fuzzer)],
    dependencies: shared_deps,
    build_by_default: false,
    cpp_args: ['-fsanitize=address', '-fsanitize=fuzzer-no-link'],
    link_args: ['-fsanitize=address', '-fsanitize=fuzzer']
  )
endforeach

install_man('sane-airscan.5')
install_man('airscan-discover.1')
install_data('airscan.conf',
  install_dir: join_paths(get_option('sysconfdir'),  'sane.d')
)
install_data(dll_file,
  install_dir: join_paths(get_option('sysconfdir'),  'sane.d', 'dll.d')
)
