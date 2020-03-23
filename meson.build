project('ssid-logger', 'c')

src = [ 'ssid-logger.c', 'hopper.c', 'parsers.c', 'queue.c', 'radiotap.c', 'worker.c', 'gps.c', 'db.c']
pcapdep= dependency('pcap')
pthreadep = dependency('threads')
nldep = dependency('libnl-3.0')
genldep = dependency('libnl-genl-3.0')
gpsdep = dependency('libgps')
sqlite3dep = dependency('sqlite3')

if gpsdep.version().version_compare('>3.19')
    add_project_arguments('-DGPS_VERSION=1', language:'c')
else
    add_project_arguments('-DGPS_VERSION=0', language:'c')
endif

executable('ssid-logger', src,
  dependencies: [pcapdep, pthreadep, nldep, genldep, gpsdep, sqlite3dep],
  install: true,
  kwargs: {'implicit_include_directories': false}) # this is needed otherwise the local gps.h is used instead of the one in /usr/include

# Note: using implicit_include_directories=false is playing with fire !
