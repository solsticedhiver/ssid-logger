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
  "e4:9e:12:d7:5e:8e,FreeWifi_secure,[WPA2-EAP-CCMP+TKIP][ESS],1970-01-01 00:00:00,1,-72,0.000000,0.000000,0.000000,0.000000,WIFI",
  "e4:9e:12:d7:5e:8c,Freebox-41B14F,[WPA2-PSK-CCMP][ESS],1970-01-01 00:00:00,1,-76,0.000000,0.000000,0.000000,0.000000,WIFI",
  "e2:55:7d:48:ee:cf,,[WEP][ESS],1970-01-01 00:00:00,1,-82,0.000000,0.000000,0.000000,0.000000,WIFI",
  "00:1d:6a:14:bc:0e,Livebox-6d3d,[WPA-PSK-CCMP+TKIP][WPA2-PSK-CCMP+TKIP][ESS][WPS],1970-01-01 00:00:00,6,-74,0.000000,0.000000,0.000000,0.000000,WIFI",
  "bc:25:e0:f5:64:e4,HUAWEI-E5186-64E4,[WPA2-PSK-CCMP][ESS][WPS],1970-01-01 00:00:00,5,-76,0.000000,0.000000,0.000000,0.000000,WIFI",
  "68:a3:78:7b:4d:d0,Freebox-7B4DCF,[WPA2-PSK-CCMP][ESS][WPS],1970-01-01 00:00:00,13,-74,0.000000,0.000000,0.000000,0.000000,WIFI",
  "68:a3:78:7b:4d:d1,FreeWifi,[ESS],1970-01-01 00:00:00,13,-72,0.000000,0.000000,0.000000,0.000000,WIFI",
  "68:a3:78:7b:4d:d2,FreeWifi_secure,[WPA2-EAP-CCMP+TKIP][ESS],1970-01-01 00:00:00,13,-72,0.000000,0.000000,0.000000,0.000000,WIFI",
  "e4:9e:12:d7:5e:8e,FreeWifi_secure,[WPA2-EAP-CCMP+TKIP][ESS],1970-01-01 00:00:00,1,-78,0.000000,0.000000,0.000000,0.000000,WIFI",
  "e4:9e:12:d7:5e:8c,Freebox-41B14F,[WPA2-PSK-CCMP][ESS],1970-01-01 00:00:00,1,-82,0.000000,0.000000,0.000000,0.000000,WIFI",
  "c8:66:5d:1d:26:54,'Mercialys Private,[WPA2-PSK-CCMP][ESS],1970-01-01 00:00:00,1,-80,0.000000,0.000000,0.000000,0.000000,WIFI",
  "52:33:8e:c2:29:c3,orange,[ESS],1970-01-01 00:00:00,6,-82,0.000000,0.000000,0.000000,0.000000,WIFI",
  "e0:1c:41:74:12:d5,'G La Galerie Pro,[WPA2-PSK-CCMP][ESS],1970-01-01 00:00:00,6,-78,0.000000,0.000000,0.000000,0.000000,WIFI",
  "e0:1c:41:74:12:d4,'G La Galerie,[ESS],1970-01-01 00:00:00,6,-78,0.000000,0.000000,0.000000,0.000000,WIFI",
  "e0:1c:41:74:12:d6,GLaGalerieExpo,[WPA-PSK-CCMP][ESS],1970-01-01 00:00:00,6,-76,0.000000,0.000000,0.000000,0.000000,WIFI",
  "5c:33:8e:79:a2:23,Livebox-8758,[WPA-PSK-CCMP+TKIP][WPA2-PSK-CCMP+TKIP][ESS][WPS],1970-01-01 00:00:00,6,-84,0.000000,0.000000,0.000000,0.000000,WIFI",
  "e0:1c:41:74:12:d6,GLaGalerieExpo,[WPA-PSK-CCMP][ESS],1970-01-01 00:00:00,6,-78,0.000000,0.000000,0.000000,0.000000,WIFI",
  "e6:e7:49:26:f0:35,DIRECT-35-HP PageWide Pro 477dw,[WPA2-PSK-CCMP][ESS][WPS],1970-01-01 00:00:00,6,-88,0.000000,0.000000,0.000000,0.000000,WIFI",
  "40:d6:3c:05:82:6f,Aromalink_826F,[WPA-PSK-TKIP+CCMP][WPA2-PSK-TKIP+CCMP][ESS],1970-01-01 00:00:00,9,-84,0.000000,0.000000,0.000000,0.000000,WIFI",
  "00:09:dd:12:37:ea,3Q41,[WPA2-EAP-][ESS],1970-01-01 00:00:00,11,-84,0.000000,0.000000,0.000000,0.000000,WIFI",
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
