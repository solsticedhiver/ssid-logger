executable('generate_beacon', 'generate_beacon/generate_beacon.c',
  c_args: ['-Wall', '-Werror', '-O3'],
  dependencies: pcap_dep,
  link_with: libwifi,
  include_directories: '../src',
  install: false
) 

executable('generate_rtscts', 'generate_rtscts/generate_rtscts.c',
  c_args: ['-Wall', '-Werror', '-O3'],
  dependencies: pcap_dep,
  link_with: libwifi,
  include_directories: '../src',
  install: false
) 

executable('parse_beacon', 'parse_beacon/parse_beacon.c',
  c_args: ['-Wall', '-Werror', '-O3'],
  dependencies: pcap_dep,
  link_with: libwifi,
  include_directories: '../src',
  install: false
) 

executable('parse_eapol', 'parse_eapol/parse_eapol.c',
  c_args: ['-Wall', '-Werror', '-O3'],
  dependencies: pcap_dep,
  link_with: libwifi,
  include_directories: '../src',
  install: false
) 

