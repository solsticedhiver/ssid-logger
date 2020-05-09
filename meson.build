project('ssid-logger', 'c', version:'0.1.2')

src = [ 'ssid-logger.c', 'hopper_thread.c', 'parsers.c', 'queue.c', 'radiotap.c', 'logger_thread.c', 'gps_thread.c', 'db.c']
pcap_dep = dependency('pcap', version: '>1.0')
pthread_dep = dependency('threads')
nl_dep = dependency('libnl-3.0')
genl_dep = dependency('libnl-genl-3.0')
gps_dep = dependency('libgps')
sqlite3_dep = dependency('sqlite3')

executable('ssid-logger', src,
  dependencies: [pcap_dep, pthread_dep, nl_dep, genl_dep, gps_dep, sqlite3_dep],
  install: true)
