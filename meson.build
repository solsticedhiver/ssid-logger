project('ssid-logger', 'c', version: '0.2.3')

cc = meson.get_compiler('c')

conf_data = configuration_data()
conf_data.set('version', meson.project_version())
configure_file(input : 'config.h.in',
               output : 'config.h',
               configuration : conf_data)

src = ['ssid-logger.c', 'hopper_thread.c', 'parsers.c', 'queue.c', 'radiotap.c',
  'logger_thread.c', 'gps_thread.c', 'db.c', 'ap_info.c', 'lruc.c']
pcap_dep = dependency('pcap', version: '>1.0')
pthread_dep = dependency('threads')
nl_dep = dependency('libnl-3.0')
genl_dep = dependency('libnl-genl-3.0')
gps_dep = dependency('libgps')
sqlite3_dep = dependency('sqlite3')
cmocka_dep = dependency('cmocka', required: false)

# define blink_rpi0_led to enable the feature that will blink the rpi0 ACT led to inform you on gps fix
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

executable('ssid-logger', src,
  dependencies: [pcap_dep, pthread_dep, nl_dep, genl_dep, gps_dep, sqlite3_dep],
  install: true)

if cmocka_dep.found()
  t = executable('parsers_test',
    ['tests/parsers_test.c', 'parsers.c', 'queue.c', 'db.c', 'lruc.c', 'radiotap.c', 'ap_info.c'],
    dependencies: [cmocka_dep, pcap_dep, sqlite3_dep])
  test('Test parsers', t)
endif
