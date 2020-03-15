#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <signal.h>
#include <unistd.h>
#include <ctype.h>
#include <string.h>
#include <assert.h>
#include <stdbool.h>
#include <pthread.h>

#include "queue.h"
#include "hopper.h"
#include "parsers.h"
#include "worker.h"

#define SNAP_LEN 512
#define CSS_OUI "\000\017\254" // 0x000x0F0xAC or 00-0F-AC
#define MS_OUI "\000\120\362" // 0x000x500xF2 or 00-50-F2
#define WPS_ID "\000\120\362\004" // 0x000x500xF20x04 or 00-50-F2-04

#define MAX_QUEUE_SIZE 128

static const u_char *CIPHER_SUITE_SELECTORS[] = {"Use group cipher suite", "WEP-40", "TKIP", "", "CCMP", "WEP-104", "BIP"};

pcap_t *handle; // global, to use it in sigint_handler
queue_t *queue;
pthread_mutex_t lock_queue;
pthread_cond_t cv;

extern void *process_queue(void *args);

void sigint_handler(int s) {
  // stop pcap capture loop
  pcap_breakloop(handle);
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
          break;
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

  struct ap_info *ap = malloc(sizeof(struct ap_info));
  strncpy(ap->bssid, bssid, 18);
  ap->ssid = ssid;
  ap->channel = channel;
  ap->freq = freq;
  ap->rssi = rssi;
  ap->rsn = rsn;
  ap->msw = msw;
  ap->ess = ess;
  ap->privacy = privacy;
  ap->wps = wps;

  pthread_mutex_lock(&lock_queue);
  enqueue(queue, ap);
  if (queue->size == MAX_QUEUE_SIZE/2) {
    // the queue is half full; go and wake up the worker thread to process that
    pthread_cond_signal(&cv);
  }
  pthread_mutex_unlock(&lock_queue);
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
  if (pthread_create(&hopper, NULL, hop_channel, iface)) {
    fprintf(stderr, "Error creating channel hopper thread\n");
    exit(EXIT_FAILURE);
  }

  pthread_cond_init(&cv, NULL);
  pthread_mutex_init(&lock_queue, NULL);
  queue = new_queue(MAX_QUEUE_SIZE);
  pthread_t worker;
  // start the helper worker thread
  if (pthread_create(&worker, NULL, process_queue, NULL)) {
    fprintf(stderr, "Error creating worker thread\n");
    exit(EXIT_FAILURE);
  }

  // catch CTRL+C to break loop cleanly
  struct sigaction act;
  act.sa_handler = sigint_handler;
  sigaction(SIGINT, &act, NULL);

  pcap_loop(handle, -1, (pcap_handler)got_packet, NULL);

  pcap_close(handle);

  pthread_cancel(hopper);
  pthread_cancel(worker);

  // free up elements of the queue
  int qs = queue->size;
  struct ap_info *ap;
  for (int i= 0; i<qs; i++) {
      ap = (struct ap_info *)dequeue(queue);
      if (ap->rsn != NULL) free_cipher_suite(ap->rsn);
      if (ap->msw != NULL) free_cipher_suite(ap->msw);
      free(ap->ssid);
      free(ap);
  }
  free(queue);

  return(0);
}
