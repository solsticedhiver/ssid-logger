#include <stdio.h>
#include <stdlib.h>
#include <pcap/pcap.h>
#include <time.h>
#include <string.h>

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <cmocka.h>

#include <unistd.h>

#include "../parsers.h"
#include "../logger_thread.h"
#include "../gps_thread.h"
#include "../queue.h"

const char *beacons[] = {
  "E4:9E:12:D7:5E:8E,FreeWifi_secure,[WPA2-EAP-CCMP+TKIP][ESS],1970-01-01 00:00:00,1,-72,0.000000,0.000000,0.000000,0.000000,WIFI",
  "E4:9E:12:D7:5E:8C,Freebox-41B14F,[WPA2-PSK-CCMP][ESS],1970-01-01 00:00:00,1,-76,0.000000,0.000000,0.000000,0.000000,WIFI",
  "E2:55:7D:48:EE:CF,,[WEP][ESS],1970-01-01 00:00:00,1,-82,0.000000,0.000000,0.000000,0.000000,WIFI",
  "00:1D:6A:14:BC:0E,Livebox-6d3d,[WPA-PSK-CCMP+TKIP][WPA2-PSK-CCMP+TKIP][WPS][ESS],1970-01-01 00:00:00,6,-74,0.000000,0.000000,0.000000,0.000000,WIFI",
  "BC:25:E0:F5:64:E4,HUAWEI-E5186-64E4,[WPA2-PSK-CCMP][WPS][ESS],1970-01-01 00:00:00,5,-76,0.000000,0.000000,0.000000,0.000000,WIFI",
  "68:A3:78:7B:4D:D0,Freebox-7B4DCF,[WPA2-PSK-CCMP][WPS][ESS],1970-01-01 00:00:00,13,-74,0.000000,0.000000,0.000000,0.000000,WIFI",
  "68:A3:78:7B:4D:D1,FreeWifi,[ESS],1970-01-01 00:00:00,13,-72,0.000000,0.000000,0.000000,0.000000,WIFI",
  "68:A3:78:7B:4D:D2,FreeWifi_secure,[WPA2-EAP-CCMP+TKIP][ESS],1970-01-01 00:00:00,13,-72,0.000000,0.000000,0.000000,0.000000,WIFI",
  "E4:9E:12:D7:5E:8E,FreeWifi_secure,[WPA2-EAP-CCMP+TKIP][ESS],1970-01-01 00:00:00,1,-78,0.000000,0.000000,0.000000,0.000000,WIFI",
  "E4:9E:12:D7:5E:8C,Freebox-41B14F,[WPA2-PSK-CCMP][ESS],1970-01-01 00:00:00,1,-82,0.000000,0.000000,0.000000,0.000000,WIFI",
  "C8:66:5D:1D:26:54,'Mercialys Private,[WPA2-PSK-CCMP][ESS],1970-01-01 00:00:00,1,-80,0.000000,0.000000,0.000000,0.000000,WIFI",
  "52:33:8E:C2:29:C3,orange,[ESS],1970-01-01 00:00:00,6,-82,0.000000,0.000000,0.000000,0.000000,WIFI",
  "E0:1C:41:74:12:D5,'G La Galerie Pro,[WPA2-PSK-CCMP][ESS],1970-01-01 00:00:00,6,-78,0.000000,0.000000,0.000000,0.000000,WIFI",
  "E0:1C:41:74:12:D4,'G La Galerie,[ESS],1970-01-01 00:00:00,6,-78,0.000000,0.000000,0.000000,0.000000,WIFI",
  "E0:1C:41:74:12:D6,GLaGalerieExpo,[WPA-PSK-CCMP][ESS],1970-01-01 00:00:00,6,-76,0.000000,0.000000,0.000000,0.000000,WIFI",
  "5C:33:8E:79:A2:23,Livebox-8758,[WPA-PSK-CCMP+TKIP][WPA2-PSK-CCMP+TKIP][WPS][ESS],1970-01-01 00:00:00,6,-84,0.000000,0.000000,0.000000,0.000000,WIFI",
  "E0:1C:41:74:12:D6,GLaGalerieExpo,[WPA-PSK-CCMP][ESS],1970-01-01 00:00:00,6,-78,0.000000,0.000000,0.000000,0.000000,WIFI",
  "E6:E7:49:26:F0:35,DIRECT-35-HP PageWide Pro 477dw,[WPA2-PSK-CCMP][WPS][ESS],1970-01-01 00:00:00,6,-88,0.000000,0.000000,0.000000,0.000000,WIFI",
  "40:D6:3C:05:82:6F,Aromalink_826F,[WPA-PSK-TKIP+CCMP][WPA2-PSK-TKIP+CCMP][ESS],1970-01-01 00:00:00,9,-84,0.000000,0.000000,0.000000,0.000000,WIFI",
  "00:09:DD:12:37:EA,3Q41,[WPA2-EAP-][ESS],1970-01-01 00:00:00,11,-84,0.000000,0.000000,0.000000,0.000000,WIFI",
};

queue_t queue; // not used
struct gps_loc gloc = { .lat=0.0, .lon=0.0, .alt=0.0, .acc=0.0, .ftime={.tv_sec=0} };
int pkt_count = 0, *pkt_len = NULL;
uint8_t **pkts = NULL;

static void test_parse_beacon_frame(void **state) {
  (void) state; // unused
  char errbuf[PCAP_ERRBUF_SIZE];

  pcap_t *handle = pcap_open_offline("../tests/beacons.pcap", errbuf);
  assert_non_null(handle);
  if (!handle) {
    fprintf(stderr, "Error: %s", errbuf);
    return;
  }
  struct pcap_pkthdr *header;
  const uint8_t *pkt;
  int ret, count = 0;
  while ((ret = pcap_next_ex(handle, &header, &pkt) != PCAP_ERROR_BREAK)) {
    uint16_t freq;
    int8_t rssi;

    int8_t offset = parse_radiotap_header(pkt, &freq, &rssi);
    struct ap_info *ap = parse_beacon_frame(pkt, header->len, offset);
    ap->freq = freq;
    ap->rssi = rssi;
    char *tmp = ap_to_str(*ap, gloc);
    printf(tmp);fflush(stdout);
    assert_string_equal(tmp, beacons[count]);
    free(tmp);
    count++;
    free_ap_info(ap);
  }
  free(handle);
}

int main(void) {
  const struct CMUnitTest tests[] = {
    cmocka_unit_test(test_parse_beacon_frame),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
