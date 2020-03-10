#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <byteswap.h>
#include <assert.h>

#include "radiotap_iter.h"

#define SNAP_LEN 512
#define CSS_OUI "\000\017\254" // 0x000x0F0xAC

pcap_t *handle; // global, to use it in sigint_handler

void sigint_handler(int s) {
  pcap_breakloop(handle);
}

void print_hex(const u_char *s, int len) {
  int indx = 0;
  while (indx < len) {
    printf("\\x%02x", (unsigned int) *(s+indx));
    indx++;
  }
  printf("\n");
}

void print_bin(void const * const ptr, size_t const size) {
  unsigned char *b = (unsigned char*) ptr;
  unsigned char byte;
  int i, j;

  for (i=size-1;i>=0;i--) {
    for (j=7;j>=0;j--) {
      byte = (b[i] >> j) & 1;
      printf("%u", byte);
    }
  }
  puts("");
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

  // iterate over Information Element to parse RSN values
  u_char *eid = (u_char *)ssid_addr + (*ssid_len + 2);
  uint8_t channel = 0;
  int clen = eid - packet;
  while (*eid != 48 && clen < header->len) {
    if (*eid == 3) { // IE with id 3 is DS parameter set ~= channel
      channel = *(eid+2);
    }
    u_char *len = eid + 1;
    eid = eid + (*len + 2);
    clen += *len + 2;
  }
  printf("%s (%s)\n    CH%3d %4dMHz %ddBm ", ssid, bssid, channel, freq, rssi);

  if ((*eid == 48) && (*(eid+1)+eid < packet+header->len)) { // IE with id 48 is RSNElt
    uint16_t version = *(eid + 2);
    u_char *gcs = eid + 1 + 3;
    u_char gcs_oui[3];
    memcpy(gcs_oui, gcs, 3);
    assert((memcmp(gcs_oui, CSS_OUI, 3) == 0));
    u_char gcs_type;
    memcpy(&gcs_type, gcs+3, 1);

    uint16_t pcsc = *(eid + 1 + 7);
    u_char **pcs_list = malloc(pcsc);
    for (int i=0; i< pcsc; i++) {
      pcs_list[i] = malloc(4);
      memcpy(pcs_list[i], eid + 1 + 7 + 2 + i*4, 4);
    }
    uint16_t akmsc = *(eid + 1 + 7 + 2 + pcsc*4);
    u_char **akms_list = malloc(akmsc);
    for (int i=0; i< akmsc; i++) {
      akms_list[i] = malloc(4);
      memcpy(akms_list[i], eid + 1 + 7 + 2 + pcsc*4 + 2 + i*4, 4);
    }
    printf("[WPA2-");
    if (memcmp(akms_list[0], CSS_OUI"\001", 4) == 0) {
      printf("EAP-");
    } else if (memcmp(akms_list[0], CSS_OUI"\002", 4) == 0) {
      printf("PSK-");
    }
    for (int i=0; i< pcsc; i++) {
      if (memcmp(pcs_list[i], CSS_OUI"\002", 4) == 0) {
        printf("+TKIP");
      } else if (memcmp(pcs_list[i], CSS_OUI"\004", 4) == 0) {
        printf("CCMP");
      }
    }
    printf("]");
  }
  if (ess) {
    printf("[ESS]");
  }
  printf("\n");
  fflush(stdout);

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
