cflags = ['-ggdb', '-O0']

executable('test_misc', ['src/helpers.c', 'src/test_misc.c'],
  c_args: cflags,
  link_with: libwifi,
  include_directories: '../src',
  install: false
)
executable('test_generation', ['src/helpers.c', 'src/test_generation.c'],
  c_args: cflags,
  dependencies: pcap_dep,
  link_with: libwifi,
  include_directories: '../src',
  install: false
)
executable('test_parsing', ['src/helpers.c', 'src/test_parsing.c'],
  c_args: cflags,
  dependencies: pcap_dep,
  link_with: libwifi,
  include_directories: '../src',
  install: false
)
