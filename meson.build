project('ssid-logger', 'c')
cc = meson.get_compiler('c')

src = [ 'ssid-logger.c', 'hopper_thread.c', 'parsers.c', 'queue.c', 'radiotap.c', 'worker_thread.c', 'gps_thread.c', 'db.c']
pcap_dep= dependency('pcap')
pthread_dep = dependency('threads')
nl_dep = dependency('libnl-3.0')
genl_dep = dependency('libnl-genl-3.0')
gps_dep = dependency('libgps')
sqlite3_dep = dependency('sqlite3')
math_dep = cc.find_library('m')

if gps_dep.version().version_compare('>3.19')
    add_project_arguments('-DGPS_VERSION=1', language:'c')
else
    add_project_arguments('-DGPS_VERSION=0', language:'c')
endif

executable('ssid-logger', src,
  dependencies: [pcap_dep, pthread_dep, nl_dep, genl_dep, gps_dep, sqlite3_dep, math_dep],
  install: true)
