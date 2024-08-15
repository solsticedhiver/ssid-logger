project('ssid-logger', 'c', version: '0.4.0')

cc = meson.get_compiler('c')

src = ['ssid-logger.c', 'hopper_thread.c', 'parsers.c', 'queue.c',
  'logger_thread.c', 'gps_thread.c', 'db.c', 'lruc.c']
pcap_dep = dependency('pcap', version: '>1.0')
pthread_dep = dependency('threads')
nl_dep = dependency('libnl-3.0')
genl_dep = dependency('libnl-genl-3.0')
gps_dep = dependency('libgps')
sqlite3_dep = dependency('sqlite3')
cmocka_dep = dependency('cmocka', required: false)

libwifi_dep = cc.find_library('wifi', required: false)
if not libwifi_dep.found()
  libwifi_proj = subproject('libwifi')
  libwifi_dep = libwifi_proj.get_variable('libwifi_dep')
endif

if get_option('blink_rpi0_led')
  add_project_arguments('-DBLINK_LED=1', language:'c')
  src += ['blink_thread.c']
endif

if cc.has_header('sys/prctl.h')
  add_project_arguments('-DHAS_SYS_PRCTL_H', language: 'c')
endif
if cc.has_header('sys/stat.h')
  add_project_arguments('-DHAS_SYS_STAT_H', language: 'c')
endif

# There is a bug with libpcap 1.10.0; see https://github.com/solsticedhiver/ssid-logger/issues/2. Using a work-around in that case
if pcap_dep.version() == '1.10.0'
  is_version_1_10_0 = 1
else
  is_version_1_10_0 = 0
endif

conf_data = configuration_data()
conf_data.set('version', meson.project_version())
conf_data.set('is_version_1_10_0', is_version_1_10_0)
configure_file(input : 'config.h.in',
               output : 'config.h',
               configuration : conf_data)

executable('ssid-logger', src,
  dependencies: [pcap_dep, pthread_dep, nl_dep, genl_dep, gps_dep, sqlite3_dep, libwifi_dep],
  install: true)

if cmocka_dep.found()
  t = executable('parsers_test',
    ['tests/parsers_test.c', 'parsers.c', 'queue.c', 'db.c', 'lruc.c'],
    dependencies: [cmocka_dep, pcap_dep, sqlite3_dep, libwifi_dep])
  test('Test parsers', t)
endif
