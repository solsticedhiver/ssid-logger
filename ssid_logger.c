#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>
#include <stdbool.h>
#include <pthread.h>
#include <net/if.h>
#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <linux/nl80211.h>

#include "radiotap_iter.h"

#define SNAP_LEN 512
#define CSS_OUI "\000\017\254" // 0x000x0F0xAC or 00-0F-AC
#define MS_OUI "\000\120\362" // 0x000x500xF2 or 00-50-F2
#define WPS_ID "\000\120\362\004" // 0x000x500xF20x04 or 00-50-F2-04

static const u_char *CIPHER_SUITE_SELECTORS[] = {"Use group cipher suite", "WEP-40", "TKIP", "", "CCMP", "WEP-104", "BIP"};
static const u_char EMPTY_SSID[] = "***";
static const uint8_t CHANNELS[] = {1,4,7,10,13,2,5,8,11,3,6,9,12};

#define HOP_PER_SECOND 5
#define SLEEP_DURATION (1000/HOP_PER_SECOND)*100
bool STOP_HOPPER = false;

struct cipher_suite {
    u_char group_cipher_suite[4];
    uint16_t pairwise_cipher_count;
    u_char **pairwise_cipher_suite;
    uint16_t akm_cipher_count;
    u_char **akm_cipher_suite;
};

struct ap_info {
  u_char *ssid;
  uint8_t ssid_len;
  u_char bssid[18];
  uint16_t channel;
  uint16_t freq;
  struct cipher_suite rsn;
  struct cipher_suite msw;
  bool ess;
  bool privacy;
  bool wps;
};

pcap_t *handle; // global, to use it in sigint_handler

u_char *already_seen_bssid[64];
uint8_t max_seen_bssid = 0;

void sigint_handler(int s) {
  // signal hopper thread to stop
  STOP_HOPPER = true;
  // stop pcap capture loop
  pcap_breakloop(handle);
}

void *channel_hopper(void *arg) {
  // based on https://stackoverflow.com/a/53602395/283067
  u_char *device = (u_char *)arg;
  uint8_t indx = 0;
  uint32_t freq = 2412 + (CHANNELS[0]-1)*5;
  size_t chan_number = sizeof(CHANNELS)/sizeof(uint8_t);
  struct nl_msg *msg;

  // Create the socket and connect to it
  struct nl_sock *sckt = nl_socket_alloc();
  genl_connect(sckt);
  int ctrl = genl_ctrl_resolve(sckt, "nl80211");
  enum nl80211_commands command = NL80211_CMD_SET_WIPHY;

  while (1) {
    if (STOP_HOPPER) {
      return NULL;
    }

    // Allocate a new message
    msg = nlmsg_alloc();

    // create the message so it will send a command to the nl80211 interface
    genlmsg_put(msg, 0, 0, ctrl, 0, 0, command, 0);

    // add specific attributes to change the frequency of the device
    NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, if_nametoindex(device));
    NLA_PUT_U32(msg, NL80211_ATTR_WIPHY_FREQ, freq);

    // finally send it and receive the amount of bytes sent
    int ret = nl_send_auto(sckt, msg);
    //printf("%d bytes sent\n", ret);

    nlmsg_free(msg);

    indx++;
    if (indx == chan_number) {
      indx = 0;
    }
    freq = 2412 + (CHANNELS[indx]-1)*5; // 2.4GHz band only for now

    usleep(SLEEP_DURATION);
    continue;

nla_put_failure:
    nlmsg_free(msg);
    fprintf(stderr, "Error: couldn't send PUT command to interface\n");
    fflush(stderr);
    sleep(5);
  }

  return NULL;
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

  return;
}

struct cipher_suite *parse_cipher_suite(u_char *start) {
  struct cipher_suite *cs = malloc(sizeof(struct cipher_suite));

  memcpy(cs->group_cipher_suite, start, 4);

  uint16_t pcsc = cs->pairwise_cipher_count = *(start + 4);
  cs->pairwise_cipher_suite = malloc(pcsc * sizeof(u_char *));
  for (int i=0; i< pcsc; i++) {
    cs->pairwise_cipher_suite[i] = malloc(4 * sizeof(u_char));
    memcpy(cs->pairwise_cipher_suite[i], start + 4 + 2 + i*4, 4);
  }

  uint16_t akmsc = cs->akm_cipher_count = *(start + 4 + 2 + pcsc*4);
  cs->akm_cipher_suite = malloc(akmsc * sizeof(u_char *));
  for (int i=0; i< akmsc; i++) {
    cs->akm_cipher_suite[i] = malloc(4 * sizeof(u_char));
    memcpy(cs->akm_cipher_suite[i], start + 4 + 2 + pcsc*4 + 2 + i*4, 4);
  }
  return cs;
}

int8_t parse_radiotap_header(const u_char *packet, uint16_t *freq, int8_t *rssi) {
  // parse radiotap header to get frequency and rssi
  // returns radiotap header size or -1 on error
  struct ieee80211_radiotap_header *rtaphdr;
  rtaphdr = (struct ieee80211_radiotap_header*)(packet);
  int8_t offset = (int8_t)rtaphdr->it_len;

  struct ieee80211_radiotap_iterator iter;
  uint16_t flags = 0;
  int8_t r;

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

  int err = ieee80211_radiotap_iterator_init(&iter, rtaphdr, rtaphdr->it_len, &vns);
  if (err) {
    printf("Error: malformed radiotap header (init returned %d)\n", err);
    return -1;
  }

  *freq = 0;
  *rssi = 0;
  // iterate through radiotap filed and look for frequency and rssi
  while (!(err = ieee80211_radiotap_iterator_next(&iter))) {
    if (iter.this_arg_index == IEEE80211_RADIOTAP_CHANNEL) {
      assert(iter.this_arg_size == 4); // XXX: why ?
      *freq = iter.this_arg[0] + (iter.this_arg[1] << 8);
      //flags = iter.this_arg[2] + (iter.this_arg[3] << 8);
    }
    if (iter.this_arg_index == IEEE80211_RADIOTAP_DBM_ANTSIGNAL) {
      r = (int8_t)*iter.this_arg;
      if (r != 0) *rssi = r; // XXX: why do we get multiple dBm_antSignal with 0 value after the first one ?
    }
    if (*freq != 0 && *rssi != 0) break;
  }
  return offset;
}

u_char *authmode_from_crypto(struct cipher_suite *rsn, struct cipher_suite *msw,
  bool ess, bool privacy, bool wps) {

  // TODO: rewrite this so that there is safeguard not to overflow authmode string
  u_char authmode[1024];
  authmode[0] = '\0'; // this is needed from strcat to work
  uint8_t last_byte;

  if (msw != NULL) {
    strcat(authmode, "[WPA-");
    last_byte = (uint8_t)msw->akm_cipher_suite[0][3];
    switch(last_byte) {
      case 1:
        strcat(authmode, "EAP-");
        break;
     case 2:
        strcat(authmode, "PSK-");
        break;
    }
    for (int i=0; i< msw->pairwise_cipher_count; i++) {
      last_byte = (uint8_t)msw->pairwise_cipher_suite[i][3];
      switch(last_byte) {
        case 2:
          strcat(authmode, "+TKIP");
          break;
        case 4:
          strcat(authmode, "CCMP");
          break;
        case 1:
          strcat(authmode, "+WEP-40");
          break;
        case 5:
          strcat(authmode, "+WEP-104");
          break;
      }
    }
    strcat(authmode, "]");
  }
  if (rsn != NULL) {
    strcat(authmode, "[WPA2-");
    last_byte = (uint8_t)rsn->akm_cipher_suite[0][3];
    switch(last_byte) {
      case 1:
        strcat(authmode, "EAP-");
        break;
      case 2:
        strcat(authmode, "PSK-");
        break;
    }
    for (int i=0; i< rsn->pairwise_cipher_count; i++) {
      last_byte = (uint8_t)rsn->pairwise_cipher_suite[i][3];
      switch(last_byte) {
        case 2:
          strcat(authmode, "+TKIP");
          break;
        case 4:
          strcat(authmode, "CCMP");
          break;
      }
    }
    strcat(authmode, "]");
  }
  if (!rsn && !msw && privacy) {
    strcat(authmode, "[WEP]");
  }
  if (wps) {
    strcat(authmode, "[WPS]");
  }
  if (ess) {
    strcat(authmode, "[ESS]");
  }

  u_char *tmp = malloc((strlen(authmode) + 1 ) * sizeof(u_char));
  strcpy(tmp, authmode); // TODO: use safer copy function
  return tmp;
}


void print_ssid_info(u_char *ssid, uint8_t ssid_len, u_char bssid[18], uint8_t channel,
  uint16_t freq, int8_t rssi, struct cipher_suite *rsn, struct cipher_suite *msw,
  bool ess, bool privacy, bool wps) {

  u_char *authmode = authmode_from_crypto(rsn, msw, ess, privacy, wps);
  printf("%s (%s)\n    CH%3d %4dMHz %ddBm %s\n", ssid_len != 0 ? ssid : EMPTY_SSID, bssid, channel, freq, rssi, authmode);
  fflush(stdout);
  free(authmode);
  return;
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
  uint16_t freq;
  int8_t rssi;
  // parse radiotap header
  int8_t offset = parse_radiotap_header(packet, &freq, &rssi);
  if (offset < 0) {
    return;
  }

  // parse the beacon frame to look for BSSID and Information Element we need (ssid, crypto, wps)
  // BSSID
  const u_char *bssid_addr = packet + offset + 2 + 2 + 6 + 6; // FC + duration + DA + SA
  u_char bssid[18];
  sprintf(bssid, "%02X:%02X:%02X:%02X:%02X:%02X", bssid_addr[0], bssid_addr[1], bssid_addr[2], bssid_addr[3], bssid_addr[4], bssid_addr[5]);

  // Capability Info
  const u_char *ci_addr = bssid_addr + 6 + 2 + 8 + 2;
  uint16_t ci_fields;
  memcpy(&ci_fields, ci_addr, sizeof(ci_fields));
  bool ess = (bool)(ci_fields & 0x0001);
  bool privacy = (bool)((ci_fields & 0x0010) >> 4);

  u_char *ssid = NULL;
  u_char *ie = (u_char *)ci_addr + 2;
  uint8_t ie_len = *(ie + 1);
  uint8_t channel = 0, ssid_len = 0;
  bool wps = false;

  struct cipher_suite *rsn = NULL;
  struct cipher_suite *msw = NULL;
  // iterate over Information Element to look for SSID and RSN crypto and MicrosoftWPA
  while (ie < packet + header->len) {
    if ((ie + ie_len + 2 < packet + header->len)) { // just double check that this is an IE with length inside packet
      switch(*ie) {
        case 0: // SSID aka IE with id 0
          ssid_len = *(ie + 1);
          ssid = (u_char *)malloc((ssid_len + 1) * sizeof(u_char)); // AP name
          snprintf(ssid, ssid_len + 1, "%s", ie + 2);
        case 3: // IE with id 3 is DS parameter set ~= channel
          channel = *(ie + 2);
          break;
        case 48: // parse RSN IE
          rsn = parse_cipher_suite(ie + 4);
          break;
        case 221:
          if (memcmp(ie + 2, MS_OUI "\001\001", 5) == 0) {
            // parse MicrosoftWPA IE
            msw = parse_cipher_suite(ie + 8);
          } else if (memcmp (ie +2, WPS_ID, 4) == 0) {
            wps = true;
          }
          break;
      }
    }
    ie = ie + ie_len + 2;
    ie_len = *(ie + 1);
  }

  // has that bssid already been seen ?
  bool seen = false;
  for (int i=0; i< max_seen_bssid; i++) {
    if (memcmp(already_seen_bssid[i], bssid, 18) == 0) {
      seen = true;
      break;
    }
  }
  // print what we found
  if (!seen) {
    print_ssid_info(ssid, ssid_len, bssid, channel, freq, rssi, rsn, msw, ess, privacy, wps);

    u_char *new_seen = malloc(18 * sizeof(u_char));
    strncpy(new_seen, bssid, 18);
    already_seen_bssid[max_seen_bssid] = new_seen;
    max_seen_bssid++;
  }

  if (rsn != NULL) free_cipher_suite(rsn);
  if (msw != NULL) free_cipher_suite(msw);
  free(ssid);
}

void usage(void) {
  printf("Usage: ssid_logger -i INTERFACE\n");
}

int main(int argc, char *argv[]) {
  char *iface = NULL;
  int opt;
  while((opt = getopt(argc, argv, "i:")) != -1)  {
    switch(opt)  {
      case 'i':
        iface = optarg;
        break;
      case '?':
        usage();
        exit(EXIT_FAILURE);
      default:
        usage();
        exit(EXIT_FAILURE);
    }
  }

  if (iface == NULL) {
    fprintf(stderr, "Error: no interface selected\n");
    exit(EXIT_FAILURE);
  }
  //printf("The device you entered: %s\n", iface);

  char errbuf[PCAP_ERRBUF_SIZE];

  // just check if iface is in the list of known devices
  pcap_if_t *devs = NULL;
  if (pcap_findalldevs(&devs, errbuf) == 0) {
    pcap_if_t *d = devs;
    bool found = false;
    while (!found && d != NULL) {
      if ((strlen(d->name) == strlen(iface)) && (memcmp(d->name, iface, strlen(iface)) == 0)) {
        found = true;
        break;
      }
      d = d->next;
    }
    pcap_freealldevs(devs);
    if (!found) {
      fprintf(stderr, "Error: %s is not a known interface.\n", iface);
      exit(EXIT_FAILURE);
    }
  }

  handle = pcap_open_live(iface, SNAP_LEN, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "Error: couldn't open device %s: %s\n", iface, errbuf);
    exit(EXIT_FAILURE);
  }

  if (pcap_datalink(handle) != DLT_IEEE802_11_RADIO) {
    fprintf(stderr, "Error: monitor mode is not enabled for %s\n", iface);
    if (pcap_can_set_rfmon(handle) == 1) {
      printf("Trying to set %s in monitor mode...\n", iface);
      if (pcap_set_rfmon(handle, 1) != 0) {
        fprintf(stderr, "Error: unable to set %s in monitor mode\n", iface);
        exit(EXIT_FAILURE);
      } else {
        printf("%s has been set in monitor mode\n", iface);
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

  pthread_t hopper;
  // start the channel hopper thread
  if (pthread_create(&hopper, NULL, channel_hopper, iface)) {
    fprintf(stderr, "Error creating channel hopper thread\n");
    exit(EXIT_FAILURE);
  }

  // catch CTRL+C to break loop cleanly
  signal(SIGINT, sigint_handler);

  pcap_loop(handle, -1, (pcap_handler)got_packet, NULL);

  pcap_close(handle);

  pthread_join(hopper, NULL);

  return(0);
}
