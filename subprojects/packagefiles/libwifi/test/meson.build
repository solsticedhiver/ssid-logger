# the tests. run `meson test -C build` where *build* is your build directory
e = executable('action_tests', 'src/action_tests.c', link_with: libwifi)
test('test_action_gen_full', e, args: ['--action-gen-full'])
test('test_action_gen_details', e, args: ['--action-gen-details'])

e = executable('assoc_req_tests', 'src/assoc_req_tests.c', link_with: libwifi)
test('test_assoc_req_gen_full', e, args: ['--assoc_req-gen-full'])
test('test_assoc_req_gen_tags', e, args: ['--assoc_req-gen-tags'])

e = executable('assoc_resp_tests', 'src/assoc_resp_tests.c', link_with: libwifi)
test('test_assoc_resp_gen_full', e, args: ['--assoc_resp-gen-full'])
test('test_assoc_resp_gen_tags', e, args: ['--assoc_resp-gen-tags'])

e = executable('atim_tests', 'src/atim_tests.c', link_with: libwifi)
test('test_atim_gen_full', e, args: ['--atim-gen-full'])

e = executable('auth_tests', 'src/auth_tests.c', link_with: libwifi)
test('test_auth_gen_full', e, args: ['--auth-gen-full'])
test('test_auth_gen_tags', e, args: ['--auth-gen-tags'])

e = executable('beacon_tests', 'src/beacon_tests.c', link_with: libwifi)
test('test_beacon_gen_full', e, args: ['--beacon-gen-full'])
test('test_beacon_gen_tags', e, args: ['--beacon-gen-tags'])
test('test_beacon_parse', e, args: ['--beacon-parse'])

e = executable('deauth_tests', 'src/deauth_tests.c', link_with: libwifi)
test('test_deauth_gen_full', e, args: ['--deauth-gen-full'])
test('test_deauth_gen_tags', e, args: ['--deauth-gen-tags'])

e = executable('disassoc_tests', 'src/disassoc_tests.c', link_with: libwifi)
test('test_disassoc_gen_full', e, args: ['--disassoc-gen-full'])
test('test_disassoc_gen_tags', e, args: ['--disassoc-gen-tags'])

e = executable('probe_req_tests', 'src/probe_req_tests.c', link_with: libwifi)
test('test_probe_req_gen_full', e, args: ['--probe_req-gen-full'])
test('test_probe_req_gen_tags', e, args: ['--probe_req-gen-tags'])

e = executable('probe_resp_tests', 'src/probe_resp_tests.c', link_with: libwifi)
test('test_probe_resp_gen_full', e, args: ['--probe_resp-gen-full'])
test('test_probe_resp_gen_tags', e, args: ['--probe_resp-gen-tags'])

e = executable('reassoc_req_tests', 'src/reassoc_req_tests.c', link_with: libwifi)
test('test_reassoc_req_gen_full', e, args: ['--reassoc_req-gen-full'])
test('test_reassoc_req_gen_tags', e, args: ['--reassoc_req-gen-tags'])

e = executable('reassoc_resp_tests', 'src/reassoc_resp_tests.c', link_with: libwifi)
test('test_reassoc_resp_gen_full', e, args: ['--reassoc_resp-gen-full'])
test('test_reassoc_resp_gen_tags', e, args: ['--reassoc_resp-gen-tags'])

e = executable('timing_ad_tests', 'src/timing_ad_tests.c', link_with: libwifi)
test('test_timing_ad_gen_tags', e, args: ['--timing_ad-gen-full'])

