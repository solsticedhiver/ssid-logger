#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>

#include "radiotap_iter.h"

#define SNAP_LEN 512
#define CSS_OUI "\000\017\254" // 0x000x0F0xAC or 00-0F-AC
#define MS_OUI "\000\120\362" // 0x000x500xF2 or 00-50-F2
#define WPS_ID "\000\120\362\004" // 0x000x500xF20x04 or 00-50-F2-04

const static u_char *CIPHER_SUITE_SELECTORS[] = {"Use group cipher suite", "WEP-40", "TKIP", "", "CCMP", "WEP-104", "BIP"};

struct cipher_suite {
    u_char group_cipher_suite[4];
    uint16_t pairwise_cipher_count;
    u_char **pairwise_cipher_suite;
    uint16_t akm_cipher_count;
    u_char **akm_cipher_suite;
};

pcap_t *handle; // global, to use it in sigint_handler

void sigint_handler(int s) {
  pcap_breakloop(handle);
}

void free_cipher_suite(struct cipher_suite *cs) {
  if (cs == NULL) return;

  uint16_t pcsc = cs->pairwise_cipher_count;
  for (int i=0; i< pcsc; i++) {
    free(cs->pairwise_cipher_suite[i]);
  }
  free(cs->pairwise_cipher_suite);

  uint16_t akmsc = cs->akm_cipher_count;
  for (int i=0; i< akmsc; i++) {
    free(cs->akm_cipher_suite[i]);
  }
  free(cs->akm_cipher_suite);

  free(cs);
  cs = NULL;
}

struct cipher_suite *parse_suite(u_char *start) {
  struct cipher_suite *cs = malloc(sizeof(struct cipher_suite));

  memcpy(cs->group_cipher_suite, start, 4);

  uint16_t pcsc = cs->pairwise_cipher_count = *(start + 4);
  cs->pairwise_cipher_suite = malloc(pcsc);
  for (int i=0; i< pcsc; i++) {
    cs->pairwise_cipher_suite[i] = malloc(4);
    memcpy(cs->pairwise_cipher_suite[i], start + 4 + 2 + i*4, 4);
  }

  uint16_t akmsc = cs->akm_cipher_count = *(start + 4 + 2 + pcsc*4);
  cs->akm_cipher_suite = malloc(akmsc);
  for (int i=0; i< akmsc; i++) {
    cs->akm_cipher_suite[i] = malloc(4);
    memcpy(cs->akm_cipher_suite[i], start + 4 + 2 + pcsc*4 + 2 + i*4, 4);
  }
  return cs;
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
  // parse radiotap header
  struct ieee80211_radiotap_header *rtaphdr;
  rtaphdr = (struct ieee80211_radiotap_header*)(packet);

  struct ieee80211_radiotap_iterator iter;
  int err;
  uint16_t freq = 0, flags = 0;
  int8_t rssi = 0, r;

  static const struct radiotap_align_size align_size_000000_00[] = {
    [0] = { .align = 1, .size = 4, },
    [52] = { .align = 1, .size = 4, },
  };

  static const struct ieee80211_radiotap_namespace vns_array[] = {
    {
      .oui = 0x000000,
      .subns = 0,
      .n_bits = sizeof(align_size_000000_00),
      .align_size = align_size_000000_00,
    },
  };

  static const struct ieee80211_radiotap_vendor_namespaces vns = {
    .ns = vns_array,
    .n_ns = sizeof(vns_array)/sizeof(vns_array[0]),
  };

  err = ieee80211_radiotap_iterator_init(&iter, rtaphdr, rtaphdr->it_len, &vns);
  if (err) {
    printf("Error: malformed radiotap header (init returned %d)\n", err);
    return;
  }

  while (!(err = ieee80211_radiotap_iterator_next(&iter))) {
    if (iter.this_arg_index == IEEE80211_RADIOTAP_CHANNEL) {
      assert(iter.this_arg_size == 4); // XXX: why ?
      freq = iter.this_arg[0] + (iter.this_arg[1] << 8);
      flags = iter.this_arg[2] + (iter.this_arg[3] << 8);
    }
    if (iter.this_arg_index == IEEE80211_RADIOTAP_DBM_ANTSIGNAL) {
      r = (int8_t)*iter.this_arg;
      if (r != 0) rssi = r; // XXX: why do we get multiple dBm_antSignal with 0 value after the first one ?
    }
    if (freq != 0 && rssi != 0) break;
  }

  // skip radiotap header to parse beacon frame
  uint8_t offset = rtaphdr->it_len;

  // BSSID
  const u_char *bssid_addr = packet + offset + 2 + 2 + 6 + 6; // FC + duration + DA + SA
  u_char *bssid = (u_char *)malloc(18); // AP mac address
  sprintf(bssid, "%02X:%02X:%02X:%02X:%02X:%02X", bssid_addr[0], bssid_addr[1], bssid_addr[2], bssid_addr[3], bssid_addr[4], bssid_addr[5]);
  // Capability Info
  const u_char *ci_addr = bssid_addr + 6 + 2 + 8 + 2;
  uint16_t ci_fields;
  memcpy(&ci_fields, ci_addr, sizeof(ci_fields));
  uint16_t ess = ci_fields & 0x0001;
  uint16_t privacy = (ci_fields & 0x0010) >> 4;
  // SSID
  const u_char *ssid_addr = bssid_addr + 6 + 2 + 8 + 2 + 2; // + BSSID + Seqctl + timestamp + B.I. + cap; IE.ID == 0
  const u_char *ssid_len = ssid_addr + 1;
  u_char *ssid = (u_char *)malloc(*ssid_len+1); // AP name
  snprintf(ssid, *ssid_len+1, "%s", ssid_addr+2);

  // iterate over Information Element to look for RSN crypto or MicrosoftWPA
  u_char *ie = (u_char *)ssid_addr + (*ssid_len + 2);
  uint8_t ie_len = *(ie + 1);
  uint8_t channel = 0;

  struct cipher_suite *rsn = NULL;
  struct cipher_suite *msw = NULL;
  uint8_t wps = 0;
  while (ie < packet + header->len) {
    if ((ie + ie_len + 2 < packet + header->len)) { // just double check that this is an IE with length inside packet
      if (*ie == 3) { // IE with id 3 is DS parameter set ~= channel
        channel = *(ie + 2);
      }
      if (*ie == 48) {
        // parse RSN IE
        u_char *start = ie + 4;
        rsn = parse_suite(start);
      }
      if (*ie == 221) {
        if (memcmp(ie + 2, MS_OUI "\001\001", 5) == 0) {
          // parse MicrosoftWPA IE
          u_char *start = ie + 8;
          msw = parse_suite(start);
        } else if (memcmp (ie +2, WPS_ID, 4) == 0) {
          wps = 1;
        }
      }
    }
    ie = ie + ie_len + 2;
    ie_len = *(ie + 1);
  }

  // print what we found
  printf("%s (%s)\n    CH%3d %4dMHz %ddBm ", ssid, bssid, channel, freq, rssi);
  if (msw != NULL) {
    printf("[WPA-");
    if (msw->akm_cipher_suite[0][3] == 1) {
      printf("EAP-");
    } else if (msw->akm_cipher_suite[0][3] == 2) {
      printf("PSK-");
    }
    for (int i=0; i< msw->pairwise_cipher_count; i++) {
      if (msw->pairwise_cipher_suite[i][3] == 2) {
        printf("+TKIP");
      } else if (msw->pairwise_cipher_suite[i][3] == 4) {
        printf("CCMP");
      } else if (msw->pairwise_cipher_suite[i][3] == 1) {
        printf("+WEP-40");
      } else if (msw->pairwise_cipher_suite[i][3] == 5) {
        printf("+WEP-104");
      }
    }
    printf("]");
  }
  if (rsn != NULL) {
    printf("[WPA2-");
    u_char last_byte = rsn->akm_cipher_suite[0][3];
    switch(last_byte) {
      case 1:
      printf("EAP-");
      break;
      case 2:
      printf("PSK-");
      break;
    }
    for (int i=0; i< rsn->pairwise_cipher_count; i++) {
      u_char last_byte = rsn->pairwise_cipher_suite[i][3];
      switch(last_byte) {
        case 2:
        printf("+TKIP");
        break;
        case 4:
        printf("CCMP");
        break;
      }
    }
    printf("]");
  }
  if (wps) {
    printf("[WPS]");
  }
  if (ess) {
    printf("[ESS]");
  }
  printf("\n");
  fflush(stdout);

  if (rsn != NULL) free_cipher_suite(rsn);
  if (msw != NULL) free_cipher_suite(msw);
  free(ssid);
  free(bssid);
}

void usage(void) {
  printf("Usage: ssid_logger -i INTERFACE\n");
}

int main(int argc, char *argv[]) {
  char *dev = NULL;
  int opt;
  while((opt = getopt(argc, argv, "i:")) != -1)  {
    switch(opt)  {
      case 'i':
      dev = optarg;
      break;
      case '?':
      usage();
      return 1;
      default:
      usage();
    }
  }

  if (dev == NULL) {
    fprintf(stderr, "Error: no interface selected\n");
    exit(EXIT_FAILURE);
  }
  //printf("The device you entered: %s\n", dev);

  char errbuf[PCAP_ERRBUF_SIZE];

  handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "Error: couldn't open device %s: %s\n", dev, errbuf);
    exit(EXIT_FAILURE);
  }

  if (pcap_datalink(handle) != DLT_IEEE802_11_RADIO) {
    fprintf(stderr, "Error: monitor mode is not enabled for %s\n", dev);
    if (pcap_can_set_rfmon(handle) == 1) {
      printf("Trying to set %s in monitor mode...\n", dev);
      if (pcap_set_rfmon(handle, 1) != 0) {
        fprintf(stderr, "Error: unable to set %s in monitor mode\n", dev);
        exit(EXIT_FAILURE);
      } else {
        printf("%s has been set in monitor mode\n", dev);
      }
    } else {
      exit(EXIT_FAILURE);
    }
  }

  // only capture beacon frames
  struct bpf_program bfp;
  u_char filter_exp[] = "type mgt subtype beacon";

  if (pcap_compile(handle, &bfp, filter_exp, 1, PCAP_NETMASK_UNKNOWN) == -1) {
    fprintf(stderr, "Error: couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
    exit(EXIT_FAILURE);
  }
  if (pcap_setfilter(handle, &bfp) == -1) {
    fprintf(stderr, "Error: couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
    exit(EXIT_FAILURE);
  }
  pcap_freecode(&bfp);

  // catch CTRL+C to break loop cleanly
  signal(SIGINT, sigint_handler);

  pcap_loop(handle, -1, (pcap_handler)got_packet, NULL);

  pcap_close(handle);

  return(0);
}
