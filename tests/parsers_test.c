#include <stdio.h>
#include <stdlib.h>
#include <pcap/pcap.h>
#include <time.h>
#include <string.h>

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>
#include <cmocka.h>

#include <unistd.h>

#include <libwifi.h>

#include "../parsers.h"
#include "../gps_thread.h"
#include "../queue.h"

#define PCAP_FILE "../tests/beacons.pcap"

/* lots of info at https://mrncciew.com/ */

const char *beacons[] = {
  "e4:9e:12:89:85:3b,FreeWifi,[ESS],1970-01-01 00:00:00,9,-104,0.000000,0.000000,0.000000,0.000000,WIFI",
  "10:fe:ed:bb:65:e6,TP-LINK_AP_BB65E6,[WPS][ESS],1970-01-01 00:00:00,3,-100,0.000000,0.000000,0.000000,0.000000,WIFI",
  "f4:ca:e5:da:ac:d8,freebox_CNFEBO,[WEP][ESS],1970-01-01 00:00:00,11,-106,0.000000,0.000000,0.000000,0.000000,WIFI",
  "ce:e2:1b:9b:a7:ae,FreeWifi_secure,[WPA-EAP-CCMP][ESS],1970-01-01 00:00:00,9,-102,0.000000,0.000000,0.000000,0.000000,WIFI",
  "14:0c:76:f7:b8:c8,FREEBOX_GERARD_TM,[WPA-PSK-CCMP+TKIP][ESS],1970-01-01 00:00:00,7,-98,0.000000,0.000000,0.000000,0.000000,WIFI",
  "44:ce:7d:92:00:6c,STYLING-L-ATELIER-SO-HAIR,[WPA-PSK-CCMP+TKIP][WPS][ESS],1970-01-01 00:00:00,6,-104,0.000000,0.000000,0.000000,0.000000,WIFI",
  "6c:38:a1:04:2c:58,Bbox-12DD42EC,[WPA-PSK-CCMP][WPA2-PSK-CCMP][WPS][ESS],1970-01-01 00:00:00,1,-102,0.000000,0.000000,0.000000,0.000000,WIFI",
  "a6:92:34:07:7f:e4,APPH,[WPA-PSK-TKIP+CCMP][ESS],1970-01-01 00:00:00,11,-108,0.000000,0.000000,0.000000,0.000000,WIFI",
  "02:1d:aa:16:64:e0,CDLR_C069901,[WPA-PSK-TKIP+CCMP][WPA2-PSK-TKIP+CCMP][ESS],1970-01-01 00:00:00,1,-102,0.000000,0.000000,0.000000,0.000000,WIFI",
  "a4:2b:8c:00:d7:68,Livebox-c798_EXT,[WPA-PSK-TKIP+CCMP][WPA2-PSK-TKIP+CCMP][WPS][ESS],1970-01-01 00:00:00,11,-108,0.000000,0.000000,0.000000,0.000000,WIFI",
  "bc:30:7d:e9:7e:3b,YN56JCTAXAAgentGeneral,[WPA-PSK-TKIP][ESS],1970-01-01 00:00:00,11,-102,0.000000,0.000000,0.000000,0.000000,WIFI",
  "22:18:0a:6f:5a:ea,DEMOWIFI,[WPA-EAP-CCMP+TKIP][WPA2-EAP/EAP+FT-CCMP+TKIP][ESS],1970-01-01 00:00:00,11,-100,0.000000,0.000000,0.000000,0.000000,WIFI",
  "ec:58:ea:2c:90:f8,Basic-Fit - Employees,[WPA2-EAP/EAP+FT-CCMP][ESS],1970-01-01 00:00:00,9,-89,0.000000,0.000000,0.000000,0.000000,WIFI",
  "e4:9e:12:89:85:3c,FreeWifi_secure,[WPA2-EAP-CCMP+TKIP][ESS],1970-01-01 00:00:00,9,-106,0.000000,0.000000,0.000000,0.000000,WIFI",
  "7a:ce:7d:92:00:6f,SFR WiFi Mobile,[WPA2-EAP-CCMP][ESS],1970-01-01 00:00:00,6,-108,0.000000,0.000000,0.000000,0.000000,WIFI",
  "70:6d:15:61:a8:e7,,[WPA-EAP-TKIP][WPA2-EAP-CCMP][ESS],1970-01-01 00:00:00,1,-92,0.000000,0.000000,0.000000,0.000000,WIFI",
  "38:0e:4d:cf:dc:30,pdt-wlan1,[WPA2-PSK/PSK+FT-CCMP][ESS],1970-01-01 00:00:00,1,-100,0.000000,0.000000,0.000000,0.000000,WIFI",
  "14:0c:76:7e:b0:be,freebox_VNBURX,[WPA2-PSK-CCMP+TKIP][ESS],1970-01-01 00:00:00,8,-104,0.000000,0.000000,0.000000,0.000000,WIFI",
  "ec:08:6b:70:fc:21,repeteur-Livebox-B0E0,[WPA2-PSK-CCMP+TKIP][WPS][ESS],1970-01-01 00:00:00,6,-108,0.000000,0.000000,0.000000,0.000000,WIFI",
  "c4:12:f5:aa:7c:50,Arteco_Lorient,[WPA-PSK-CCMP+TKIP][WPA2-PSK-CCMP+TKIP][ESS],1970-01-01 00:00:00,2,-104,0.000000,0.000000,0.000000,0.000000,WIFI",
  "7c:26:64:66:8c:ac,Livebox-8ca8,[WPA-PSK-CCMP+TKIP][WPA2-PSK-CCMP+TKIP][WPS][ESS],1970-01-01 00:00:00,1,-100,0.000000,0.000000,0.000000,0.000000,WIFI",
  "50:60:28:d1:da:02,EQWLAN,[WPA-PSK-TKIP][WPA2-PSK-CCMP+TKIP][ESS],1970-01-01 00:00:00,3,-98,0.000000,0.000000,0.000000,0.000000,WIFI",
  "2c:78:0e:eb:80:7a,HUAWEI-807A,[WPA2-PSK-CCMP][ESS],1970-01-01 00:00:00,10,-100,0.000000,0.000000,0.000000,0.000000,WIFI",
  "e4:9e:12:89:85:3a,Freebox-898539,[WPA2-PSK-CCMP][WPS][ESS],1970-01-01 00:00:00,9,-104,0.000000,0.000000,0.000000,0.000000,WIFI",
  "00:80:a3:c4:5e:a3,QLSO1431,[WPA-PSK-CCMP][WPA2-PSK-CCMP][ESS],1970-01-01 00:00:00,5,-98,0.000000,0.000000,0.000000,0.000000,WIFI",
  "ac:3b:77:5c:0c:a0,Bbox-1CAAB298,[WPA-PSK-CCMP][WPA2-PSK-CCMP][WPS][ESS],1970-01-01 00:00:00,6,-106,0.000000,0.000000,0.000000,0.000000,WIFI",
  "84:24:8d:b9:cf:f4,wifmobggs,[WPA-PSK-TKIP][WPA2-PSK-CCMP][ESS],1970-01-01 00:00:00,13,-108,0.000000,0.000000,0.000000,0.000000,WIFI",
  "c8:d3:a3:25:7a:db,Wifi-Jurilor,[WPA2-PSK-TKIP+CCMP][ESS],1970-01-01 00:00:00,13,-102,0.000000,0.000000,0.000000,0.000000,WIFI",
  "2c:d0:2d:85:b5:c0,BRD6J1?0!Q4D5%FR,[WPA-PSK-TKIP][WPA2-PSK-TKIP][ESS],1970-01-01 00:00:00,1,-100,0.000000,0.000000,0.000000,0.000000,WIFI",
};

queue_t queue; // not used
struct gps_loc gloc;
int pkt_count = 0, *pkt_len = NULL;
uint8_t **pkts = NULL;

static void test_parse_beacon_frame_from_pcap(void **state)
{
  (void) state; // unused
  char errbuf[PCAP_ERRBUF_SIZE];

  pcap_t *handle = pcap_open_offline(PCAP_FILE, errbuf);
  assert_non_null(handle);
  if (!handle) {
    fprintf(stderr, "Error: can't open pcap file");
    return;
  }
  struct pcap_pkthdr *header;
  const uint8_t *pkt;
  int ret, count = 0;
  gloc.lat=0.0; gloc.lon=0.0; gloc.alt=0.0; gloc.acc=0.0; gloc.ftime.tv_sec=0;

  while ((ret = pcap_next_ex(handle, &header, &pkt) != PCAP_ERROR_BREAK)) {
    uint16_t freq;
    int8_t rssi;

    int8_t offset = parse_radiotap_header(pkt, &freq, &rssi);
    struct libwifi_bss *bss = parse_beacon_frame(pkt, header->len, offset);
    bss->signal = rssi;
    char *tmp = bss_to_str(*bss, gloc);
    //printf("%s\n", tmp);fflush(stdout);
    assert_string_equal(tmp, beacons[count]);
    free(tmp);
    count++;
    libwifi_free_bss(bss);
  }
  free(handle);
}

static void test_authmode_from_crypto(void **state)
{
  (void) state; // unused
  char *authmode;

  struct libwifi_bss bss = {};
  authmode = authmode_from_crypto(bss);
  assert_string_equal(authmode, "[ESS]");
  free(authmode);

  bss.encryption_info |= WEP;
  authmode = authmode_from_crypto(bss);
  assert_string_equal(authmode, "[WEP][ESS]");
  free(authmode);

  bss.wps = 1;
  authmode = authmode_from_crypto(bss);
  assert_string_equal(authmode, "[WEP][WPS][ESS]");
  free(authmode);

  bss.encryption_info = 0;
  bss.encryption_info |= WPA2;
  bss.rsn_info.rsn_version = 1;
  bss.rsn_info.group_cipher_suite = (struct libwifi_cipher_suite){ .oui = CIPHER_SUITE_OUI, .suite_type = CIPHER_SUITE_CCMP128 };
  bss.rsn_info.num_pairwise_cipher_suites = 2;
  bss.rsn_info.pairwise_cipher_suites[0] = (struct libwifi_cipher_suite){ .oui = CIPHER_SUITE_OUI, .suite_type = CIPHER_SUITE_CCMP128 };
  bss.rsn_info.pairwise_cipher_suites[1] = (struct libwifi_cipher_suite){ .oui = CIPHER_SUITE_OUI, .suite_type = CIPHER_SUITE_TKIP };
  bss.rsn_info.num_auth_key_mgmt_suites = 1;
  bss.rsn_info.auth_key_mgmt_suites[0] = (struct libwifi_cipher_suite){ .oui = CIPHER_SUITE_OUI, .suite_type = AKM_SUITE_PSK};
  authmode = authmode_from_crypto(bss);
  assert_string_equal(authmode, "[WPA2-PSK-CCMP+TKIP][WPS][ESS]");
  free(authmode);

  bss.rsn_info.num_pairwise_cipher_suites = 1;
  authmode = authmode_from_crypto(bss);
  assert_string_equal(authmode, "[WPA2-PSK-CCMP][WPS][ESS]");
  free(authmode);

  bss.rsn_info.pairwise_cipher_suites[0] = (struct libwifi_cipher_suite){ .oui = CIPHER_SUITE_OUI, .suite_type = CIPHER_SUITE_TKIP };
  authmode = authmode_from_crypto(bss);
  assert_string_equal(authmode, "[WPA2-PSK-TKIP][WPS][ESS]");
  free(authmode);

  bss.rsn_info.num_pairwise_cipher_suites = 2;
  bss.rsn_info.pairwise_cipher_suites[1] = (struct libwifi_cipher_suite){ .oui = CIPHER_SUITE_OUI, .suite_type = CIPHER_SUITE_CCMP128 };
  authmode = authmode_from_crypto(bss);
  assert_string_equal(authmode, "[WPA2-PSK-TKIP+CCMP][WPS][ESS]");
  free(authmode);

  bss.rsn_info.pairwise_cipher_suites[0] = (struct libwifi_cipher_suite){ .oui = CIPHER_SUITE_OUI, .suite_type = CIPHER_SUITE_CCMP128 };
  bss.rsn_info.pairwise_cipher_suites[1] = (struct libwifi_cipher_suite){ .oui = CIPHER_SUITE_OUI, .suite_type = CIPHER_SUITE_TKIP };
  authmode = authmode_from_crypto(bss);
  assert_string_equal(authmode, "[WPA2-PSK-CCMP+TKIP][WPS][ESS]");
  free(authmode);

  bss.rsn_info.num_auth_key_mgmt_suites = 2;
  bss.rsn_info.auth_key_mgmt_suites[1] = (struct libwifi_cipher_suite){ .oui = CIPHER_SUITE_OUI, .suite_type = AKM_SUITE_PSK_FT};
  authmode = authmode_from_crypto(bss);
  assert_string_equal(authmode, "[WPA2-PSK/PSK+FT-CCMP+TKIP][WPS][ESS]");
  free(authmode);

  bss.rsn_info.auth_key_mgmt_suites[0] = (struct libwifi_cipher_suite){ .oui = CIPHER_SUITE_OUI, .suite_type = AKM_SUITE_PSK_FT};
  bss.rsn_info.auth_key_mgmt_suites[1] = (struct libwifi_cipher_suite){ .oui = CIPHER_SUITE_OUI, .suite_type = AKM_SUITE_PSK};
  authmode = authmode_from_crypto(bss);
  assert_string_equal(authmode, "[WPA2-PSK+FT/PSK-CCMP+TKIP][WPS][ESS]");
  free(authmode);

  bss.rsn_info.auth_key_mgmt_suites[0] = (struct libwifi_cipher_suite){ .oui = CIPHER_SUITE_OUI, .suite_type = AKM_SUITE_1X};
  bss.rsn_info.auth_key_mgmt_suites[1] = (struct libwifi_cipher_suite){ .oui = CIPHER_SUITE_OUI, .suite_type = AKM_SUITE_1X_FT};
  authmode = authmode_from_crypto(bss);
  assert_string_equal(authmode, "[WPA2-EAP/EAP+FT-CCMP+TKIP][WPS][ESS]");
  free(authmode);

  bss.rsn_info.num_auth_key_mgmt_suites = 1;
  bss.rsn_info.auth_key_mgmt_suites[0] = (struct libwifi_cipher_suite){ .oui = CIPHER_SUITE_OUI, .suite_type = AKM_SUITE_PSK_SHA256};
  authmode = authmode_from_crypto(bss);
  assert_string_equal(authmode, "[WPA2-PSK+SHA256-CCMP+TKIP][WPS][ESS]");
  free(authmode);

  bss.rsn_info.num_pairwise_cipher_suites = 1;
  bss.rsn_info.pairwise_cipher_suites[0] = (struct libwifi_cipher_suite){ .oui = CIPHER_SUITE_OUI, .suite_type = CIPHER_SUITE_CCMP128 };
  bss.rsn_info.num_auth_key_mgmt_suites = 2;
  bss.rsn_info.auth_key_mgmt_suites[0] = (struct libwifi_cipher_suite){ .oui = CIPHER_SUITE_OUI, .suite_type = AKM_SUITE_1X};
  bss.rsn_info.auth_key_mgmt_suites[1] = (struct libwifi_cipher_suite){ .oui = CIPHER_SUITE_OUI, .suite_type = AKM_SUITE_1X_FT};
  authmode = authmode_from_crypto(bss);
  assert_string_equal(authmode, "[WPA2-EAP/EAP+FT-CCMP][WPS][ESS]");
  free(authmode);

  bss.rsn_info.auth_key_mgmt_suites[0] = (struct libwifi_cipher_suite){ .oui = CIPHER_SUITE_OUI, .suite_type = AKM_SUITE_PSK};
  bss.rsn_info.auth_key_mgmt_suites[1] = (struct libwifi_cipher_suite){ .oui = CIPHER_SUITE_OUI, .suite_type = AKM_SUITE_PSK_FT};
  authmode = authmode_from_crypto(bss);
  assert_string_equal(authmode, "[WPA2-PSK/PSK+FT-CCMP][WPS][ESS]");
  free(authmode);

  bss.wpa_info.wpa_version = 1;
  bss.wpa_info.num_unicast_cipher_suites = 2;
  bss.wpa_info.unicast_cipher_suites[0] = (struct libwifi_cipher_suite){ .oui = MICROSOFT_OUI, .suite_type = CIPHER_SUITE_TKIP};
  bss.wpa_info.unicast_cipher_suites[1] = (struct libwifi_cipher_suite){ .oui = MICROSOFT_OUI, .suite_type = CIPHER_SUITE_CCMP128};
  bss.wpa_info.multicast_cipher_suite = (struct libwifi_cipher_suite){ .oui = MICROSOFT_OUI, .suite_type = CIPHER_SUITE_TKIP};
  bss.wpa_info.num_auth_key_mgmt_suites = 1;
  bss.wpa_info.auth_key_mgmt_suites[0] = (struct libwifi_cipher_suite){ .oui = MICROSOFT_OUI, .suite_type = AKM_SUITE_PSK};
  authmode = authmode_from_crypto(bss);
  assert_string_equal(authmode, "[WPA-PSK-TKIP+CCMP][WPA2-PSK/PSK+FT-CCMP][WPS][ESS]");
  free(authmode);
  // TODO: test with 4 akm suites
  //1,2,3,4 => WPA2-EAP/PSK+FT/EAP+FT/PSK-CCMP+TKIP
  //1,3,4,2 => WPA2-EAP/EAP+FT/PSK+FT/PSK-CCMP+TKIP
  //1,3,2,4 => WPA2-EAP/EAP+FT/PSK/PSK+FT-CCMP+TKIP
  //3,1,4,2 => WPA-EAP/EAP+FT/PSK/PSK+FT-CCMP+TKIP
}

int main(void) {
  const struct CMUnitTest tests[] = {
    cmocka_unit_test(test_parse_beacon_frame_from_pcap),
    cmocka_unit_test(test_authmode_from_crypto),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
