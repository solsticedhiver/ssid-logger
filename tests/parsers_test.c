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

#define PCAP_FILE "../tests/beacons.pcap"

const char *beacons[] = {
  "e4:9e:12:89:85:3b,FreeWifi,[ESS],1970-01-01 00:00:00,9,-104,0.000000,0.000000,0.000000,0.000000,WIFI",
  "10:fe:ed:bb:65:e6,TP-LINK_AP_BB65E6,[ESS][WPS],1970-01-01 00:00:00,3,-100,0.000000,0.000000,0.000000,0.000000,WIFI",
  "f4:ca:e5:da:ac:d8,freebox_CNFEBO,[WEP][ESS],1970-01-01 00:00:00,11,-106,0.000000,0.000000,0.000000,0.000000,WIFI",
  "ce:e2:1b:9b:a7:ae,FreeWifi_secure,[WPA-EAP-CCMP][ESS],1970-01-01 00:00:00,9,-102,0.000000,0.000000,0.000000,0.000000,WIFI",
  "14:0c:76:f7:b8:c8,FREEBOX_GERARD_TM,[WPA-PSK-CCMP+TKIP][ESS],1970-01-01 00:00:00,7,-98,0.000000,0.000000,0.000000,0.000000,WIFI",
  "44:ce:7d:92:00:6c,STYLING-L-ATELIER-SO-HAIR,[WPA-PSK-CCMP+TKIP][ESS][WPS],1970-01-01 00:00:00,6,-104,0.000000,0.000000,0.000000,0.000000,WIFI",
  "6c:38:a1:04:2c:58,Bbox-12DD42EC,[WPA-PSK-CCMP][WPA2-PSK-CCMP][ESS][WPS],1970-01-01 00:00:00,1,-102,0.000000,0.000000,0.000000,0.000000,WIFI",
  "a6:92:34:07:7f:e4,APPH,[WPA-PSK-TKIP+CCMP][ESS],1970-01-01 00:00:00,11,-108,0.000000,0.000000,0.000000,0.000000,WIFI",
  "02:1d:aa:16:64:e0,CDLR_C069901,[WPA-PSK-TKIP+CCMP][WPA2-PSK-TKIP+CCMP][ESS],1970-01-01 00:00:00,1,-102,0.000000,0.000000,0.000000,0.000000,WIFI",
  "a4:2b:8c:00:d7:68,Livebox-c798_EXT,[WPA-PSK-TKIP+CCMP][WPA2-PSK-TKIP+CCMP][ESS][WPS],1970-01-01 00:00:00,11,-108,0.000000,0.000000,0.000000,0.000000,WIFI",
  "bc:30:7d:e9:7e:3b,YN56JCTAXAAgentGeneral,[WPA-PSK-TKIP][ESS],1970-01-01 00:00:00,11,-102,0.000000,0.000000,0.000000,0.000000,WIFI",
  "22:18:0a:6f:5a:ea,DEMOWIFI,[WPA-EAP-CCMP+TKIP][WPA2-EAP+FT/EAP-CCMP+TKIP][ESS],1970-01-01 00:00:00,11,-100,0.000000,0.000000,0.000000,0.000000,WIFI",
  "ec:58:ea:2c:90:f8,Basic-Fit - Employees,[WPA2-EAP+FT/EAP-CCMP][ESS],1970-01-01 00:00:00,9,-89,0.000000,0.000000,0.000000,0.000000,WIFI",
  "e4:9e:12:89:85:3c,FreeWifi_secure,[WPA2-EAP-CCMP+TKIP][ESS],1970-01-01 00:00:00,9,-106,0.000000,0.000000,0.000000,0.000000,WIFI",
  "7a:ce:7d:92:00:6f,SFR WiFi Mobile,[WPA2-EAP-CCMP][ESS],1970-01-01 00:00:00,6,-108,0.000000,0.000000,0.000000,0.000000,WIFI",
  "70:6d:15:61:a8:e7,,[WPA-EAP-TKIP][WPA2-EAP-CCMP][ESS],1970-01-01 00:00:00,1,-92,0.000000,0.000000,0.000000,0.000000,WIFI",
  "38:0e:4d:cf:dc:30,pdt-wlan1,[WPA2-PSK+FT/PSK-CCMP][ESS],1970-01-01 00:00:00,1,-100,0.000000,0.000000,0.000000,0.000000,WIFI",
  "14:0c:76:7e:b0:be,freebox_VNBURX,[WPA2-PSK-CCMP+TKIP][ESS],1970-01-01 00:00:00,8,-104,0.000000,0.000000,0.000000,0.000000,WIFI",
  "ec:08:6b:70:fc:21,repeteur-Livebox-B0E0,[WPA2-PSK-CCMP+TKIP][ESS][WPS],1970-01-01 00:00:00,6,-108,0.000000,0.000000,0.000000,0.000000,WIFI",
  "c4:12:f5:aa:7c:50,Arteco_Lorient,[WPA-PSK-CCMP+TKIP][WPA2-PSK-CCMP+TKIP][ESS],1970-01-01 00:00:00,2,-104,0.000000,0.000000,0.000000,0.000000,WIFI",
  "7c:26:64:66:8c:ac,Livebox-8ca8,[WPA-PSK-CCMP+TKIP][WPA2-PSK-CCMP+TKIP][ESS][WPS],1970-01-01 00:00:00,1,-100,0.000000,0.000000,0.000000,0.000000,WIFI",
  "50:60:28:d1:da:02,EQWLAN,[WPA-PSK-TKIP][WPA2-PSK-CCMP+TKIP][ESS],1970-01-01 00:00:00,3,-98,0.000000,0.000000,0.000000,0.000000,WIFI",
  "2c:78:0e:eb:80:7a,HUAWEI-807A,[WPA2-PSK-CCMP][ESS],1970-01-01 00:00:00,10,-100,0.000000,0.000000,0.000000,0.000000,WIFI",
  "e4:9e:12:89:85:3a,Freebox-898539,[WPA2-PSK-CCMP][ESS][WPS],1970-01-01 00:00:00,9,-104,0.000000,0.000000,0.000000,0.000000,WIFI",
  "00:80:a3:c4:5e:a3,QLSO1431,[WPA-PSK-CCMP][WPA2-PSK-CCMP][ESS],1970-01-01 00:00:00,5,-98,0.000000,0.000000,0.000000,0.000000,WIFI",
  "ac:3b:77:5c:0c:a0,Bbox-1CAAB298,[WPA-PSK-CCMP][WPA2-PSK-CCMP][ESS][WPS],1970-01-01 00:00:00,6,-106,0.000000,0.000000,0.000000,0.000000,WIFI",
  "84:24:8d:b9:cf:f4,wifmobggs,[WPA-PSK-TKIP][WPA2-PSK-CCMP][ESS],1970-01-01 00:00:00,13,-108,0.000000,0.000000,0.000000,0.000000,WIFI",
  "c8:d3:a3:25:7a:db,Wifi-Jurilor,[WPA2-PSK-TKIP+CCMP][ESS],1970-01-01 00:00:00,13,-102,0.000000,0.000000,0.000000,0.000000,WIFI",
  "2c:d0:2d:85:b5:c0,BRD6J1?0!Q4D5%FR,[WPA-PSK-TKIP][WPA2-PSK-TKIP][ESS],1970-01-01 00:00:00,1,-100,0.000000,0.000000,0.000000,0.000000,WIFI",
};

queue_t queue; // not used
struct gps_loc gloc = { .lat=0.0, .lon=0.0, .alt=0.0, .acc=0.0, .ftime={.tv_sec=0} };
int pkt_count = 0, *pkt_len = NULL;
uint8_t **pkts = NULL;

static void test_parse_beacon_frame(void **state) {
  (void) state; // unused
  char errbuf[PCAP_ERRBUF_SIZE];

  pcap_t *handle = pcap_open_offline(PCAP_FILE, errbuf);
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
    //printf("%s\n", tmp);fflush(stdout);
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
