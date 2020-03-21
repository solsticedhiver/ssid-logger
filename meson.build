project('ssid-logger', 'c')

src = [ 'ssid-logger.c', 'hopper.c', 'parsers.c', 'queue.c', 'radiotap.c', 'worker.c', 'gps.c', 'db.c']
pcapdep= dependency('libpcap')
pthreadep = dependency('threads')
nldep = dependency('libnl-3.0')
genldep = dependency('libnl-genl-3.0')
gpsdep = dependency('libgps')
sqlite3dep = dependency('sqlite3')

executable('ssid-logger', src,
  dependencies: [pcapdep, pthreadep, nldep, genldep, gpsdep, sqlite3dep],
  kwargs: {'implicit_include_directories': false}) # this is needed otherwise the local gps.h is used instead of the one in /usr/include

# Note: using implicit_include_directories=false is playing with fire !
