project('libwifi', 'c', version: '0.0.10', license: 'Apache-2.0')
version = meson.project_version()
gitbranch = run_command('git', 'rev-parse', '--abbrev-ref', 'HEAD', check: false)
if gitbranch.returncode() == 0
  gitbranch = gitbranch.stdout().strip()
else
  gitbranch = ''
endif
githash = run_command('git', 'log', '-1', '--pretty=format:%h', check: false)
if githash.returncode() == 0
  githash = githash.stdout().strip()
else
  githash = ''
endif
buildtime = run_command('date', '-Is', check: true)

message(' _  _  _                _   __  _   ')
message('| |(_)| |              (_) / _|(_)  ')
message('| | _ | |__  __      __ _ | |_  _   ')
message('| || || \'_ \\ \\ \\ /\\ / /| ||  _|| |  ')
message('| || || |_| | \\ V  V / | || |  | |  ')
message('|_||_||_.__/   \\_/\\_/  |_||_|  |_|  ')
message('-----------------------------------')
message('802.11 Parsing / Generation Library')
message('Version: ', version, ', Git: ', gitbranch, '(',githash, '), Time: ', buildtime.stdout().strip())

src = [ # find src/libwifi -name '*.c' | sort
'src/libwifi/core/core.c',
'src/libwifi/core/frame/crc.c',
'src/libwifi/core/frame/frame.c',
'src/libwifi/core/frame/tag.c',
'src/libwifi/core/frame/tag_iterator.c',
'src/libwifi/core/misc/epoch.c',
'src/libwifi/core/radiotap/radiotap.c',
'src/libwifi/gen/control/cts.c',
'src/libwifi/gen/control/rts.c',
'src/libwifi/gen/management/action.c',
'src/libwifi/gen/management/assoc_request.c',
'src/libwifi/gen/management/assoc_response.c',
'src/libwifi/gen/management/atim.c',
'src/libwifi/gen/management/authentication.c',
'src/libwifi/gen/management/beacon.c',
'src/libwifi/gen/management/deauthentication.c',
'src/libwifi/gen/management/disassociation.c',
'src/libwifi/gen/management/probe_request.c',
'src/libwifi/gen/management/probe_response.c',
'src/libwifi/gen/management/reassoc_request.c',
'src/libwifi/gen/management/reassoc_response.c',
'src/libwifi/gen/management/timing_ad.c',
'src/libwifi/gen/misc/radiotap.c',
'src/libwifi/parse/data/data.c',
'src/libwifi/parse/data/eapol.c',
'src/libwifi/parse/management/assoc_request.c',
'src/libwifi/parse/management/assoc_response.c',
'src/libwifi/parse/management/beacon.c',
'src/libwifi/parse/management/common.c',
'src/libwifi/parse/management/deauthentication.c',
'src/libwifi/parse/management/disassociation.c',
'src/libwifi/parse/management/probe_request.c',
'src/libwifi/parse/management/probe_response.c',
'src/libwifi/parse/management/reassoc_request.c',
'src/libwifi/parse/management/reassoc_response.c',
'src/libwifi/parse/misc/radiotap.c',
'src/libwifi/parse/misc/security.c',
]

# really?
cflags =  [
'-std=gnu17',
'-Wall',
'-Wextra',
'-Wformat=2',
'-fstack-protector-strong',
'-D_FORTIFY_SOURCE=2',
'-Wmissing-prototypes',
'-Wstrict-prototypes',
'-O2',
'-Wformat-overflow=2',
'-Wformat-truncation=2',
'-Wformat-security',
'-Wnull-dereference',
'-Wstack-protector',
'-Wtrampolines',
'-Walloca',
'-Wvla',
'-Warray-bounds=2',
'-Wimplicit-fallthrough=3',
'-Wtraditional-conversion',
'-Wshift-overflow=2',
'-Wcast-qual',
'-Wstringop-overflow=4',
'-Wconversion',
'-Wlogical-op',
'-Wduplicated-cond',
'-Wduplicated-branches',
'-Wformat-signedness',
'-Wshadow',
'-Wstrict-overflow=4',
'-Wundef',
'-Wstrict-prototypes',
'-Wswitch-default',
'-Wswitch-enum',
'-Wstack-usage=1000000',
'-Wcast-align=strict',
'-fstack-clash-protection',
'-Wl,-z,relro',
'-Wl,-z,now',
'-Wl,-z,noexecstack',
'-Wl,-z,separate-code',
]

libwifi = shared_library('wifi', src, c_args: cflags, version: version, soversion: 0, install: true)
# to compile that static lib, run `meson compile wifi:static_library -C build`
libwifi_static = static_library('wifi', src, c_args: cflags, install: false)
inc = ['src', 'src/libwifi/parse', 'src/libwifi/core', 'src/libwifi/gen']                                           
libwifi_dep = declare_dependency(include_directories : inc, link_with : libwifi_static)  

install_headers('src/libwifi.h')
headers_parse = [ # find src/libwifi/parse -name '*.h' | sort
'src/libwifi/parse/data/data.h',
'src/libwifi/parse/data/eapol.h',
'src/libwifi/parse/management/assoc_request.h',
'src/libwifi/parse/management/assoc_response.h',
'src/libwifi/parse/management/beacon.h',
'src/libwifi/parse/management/common.h',
'src/libwifi/parse/management/deauthentication.h',
'src/libwifi/parse/management/disassociation.h',
'src/libwifi/parse/management/probe_request.h',
'src/libwifi/parse/management/probe_response.h',
'src/libwifi/parse/management/reassoc_request.h',
'src/libwifi/parse/management/reassoc_response.h',
'src/libwifi/parse/misc/radiotap.h',
'src/libwifi/parse/misc/security.h',
]
install_headers(headers_parse, subdir: 'libwifi/parse')
headers_core = [ # find src/libwifi/core -name '*.h' | sort
'src/libwifi/core/core.h',
'src/libwifi/core/frame/control/cts.h',
'src/libwifi/core/frame/control/rts.h',
'src/libwifi/core/frame/crc.h',
'src/libwifi/core/frame/data/data.h',
'src/libwifi/core/frame/frame.h',
'src/libwifi/core/frame/management/action.h',
'src/libwifi/core/frame/management/assoc_request.h',
'src/libwifi/core/frame/management/assoc_response.h',
'src/libwifi/core/frame/management/atim.h',
'src/libwifi/core/frame/management/authentication.h',
'src/libwifi/core/frame/management/beacon.h',
'src/libwifi/core/frame/management/common.h',
'src/libwifi/core/frame/management/deauthentication.h',
'src/libwifi/core/frame/management/disassociation.h',
'src/libwifi/core/frame/management/probe_request.h',
'src/libwifi/core/frame/management/probe_response.h',
'src/libwifi/core/frame/management/reassoc_request.h',
'src/libwifi/core/frame/management/reassoc_response.h',
'src/libwifi/core/frame/management/timing_ad.h',
'src/libwifi/core/frame/tag.h',
'src/libwifi/core/frame/tag_iterator.h',
'src/libwifi/core/misc/byteswap.h',
'src/libwifi/core/misc/epoch.h',
'src/libwifi/core/misc/llc.h',
'src/libwifi/core/misc/radiotap.h',
'src/libwifi/core/misc/security.h',
'src/libwifi/core/misc/types.h',
'src/libwifi/core/radiotap/platform.h',
'src/libwifi/core/radiotap/radiotap.h',
'src/libwifi/core/radiotap/radiotap_iter.h',
]
install_headers(headers_core, subdir: 'libwifi/core')
headers_gen = [ # find src/libwifi/gen -name '*.h' | sort
'src/libwifi/gen/control/cts.h',
'src/libwifi/gen/control/rts.h',
'src/libwifi/gen/management/action.h',
'src/libwifi/gen/management/assoc_request.h',
'src/libwifi/gen/management/assoc_response.h',
'src/libwifi/gen/management/atim.h',
'src/libwifi/gen/management/authentication.h',
'src/libwifi/gen/management/beacon.h',
'src/libwifi/gen/management/common.h',
'src/libwifi/gen/management/deauthentication.h',
'src/libwifi/gen/management/disassociation.h',
'src/libwifi/gen/management/probe_request.h',
'src/libwifi/gen/management/probe_response.h',
'src/libwifi/gen/management/reassoc_request.h',
'src/libwifi/gen/management/reassoc_response.h',
'src/libwifi/gen/management/timing_ad.h',
'src/libwifi/gen/misc/radiotap.h',
]
install_headers(headers_gen, subdir: 'libwifi/gen')

# tests
subdir('test')

# meson compile benchmark_beacon -C build 
# meson run benchmark_beacon -C build 
pcap_dep = dependency('pcap', version: '>1.0')
bb = executable('benchmark_beacon', 'benchmark/benchmark_beacon.c',
  c_args: ['-Wall', '-Werror', '-O3'],
  link_with: libwifi,
  dependencies: pcap_dep,
  include_directories: 'src',
  install: false)
benchmark('benchmark_beacon', bb)

# examples
subdir('examples')

# utils
subdir('utils')
