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
#include <time.h>
#include <sqlite3.h>
#include <time.h>

#include "queue.h"
#include "hopper_thread.h"
#include "parsers.h"
#include "worker_thread.h"
#include "gps_thread.h"
#include "db.h"

#define NAME "ssid-logger"
#define VERSION "0.1.2"

#define SNAP_LEN 512
#define CSS_OUI "\000\017\254"  // 0x000x0F0xAC or 00-0F-AC
#define MS_OUI "\000\120\362"   // 0x000x500xF2 or 00-50-F2
#define WPS_ID "\000\120\362\004"       // 0x000x500xF20x04 or 00-50-F2-04

#define MAX_QUEUE_SIZE 128

#define DB_NAME "beacon.db"

pcap_t *handle;                 // global, to use it in sigint_handler
queue_t *queue;                 // queue to hold parsed ap infos

pthread_t hopper;
pthread_t worker;
pthread_t gps;
int gps_thread_result = 0;
pthread_mutex_t mutex_queue;
pthread_mutex_t mutex_gloc;
pthread_mutex_t mutex_gtr;
pthread_cond_t cv;
pthread_cond_t cv_gtr;
struct timespec start_ts_queue;

sqlite3 *db = NULL;
bool format_csv = false;
bool option_gps = true;
FILE *file_ptr = NULL;

void sigint_handler(int s)
{
  // stop pcap capture loop
  pcap_breakloop(handle);
}

void got_packet(u_char * args, const struct pcap_pkthdr *header, const u_char * packet)
{
  uint16_t freq;
  int8_t rssi;
  // parse radiotap header
  int8_t offset = parse_radiotap_header(packet, &freq, &rssi);
  if (offset < 0) {
    return;
  }

  // parse the beacon frame to look for BSSID and Information Element we need (ssid, crypto, wps)
  // BSSID
  const u_char *bssid_addr = packet + offset + 2 + 2 + 6 + 6;   // FC + duration + DA + SA
  char bssid[18];
  sprintf(bssid, "%02X:%02X:%02X:%02X:%02X:%02X", bssid_addr[0],
    bssid_addr[1], bssid_addr[2], bssid_addr[3], bssid_addr[4],
    bssid_addr[5]);

  // Capability Info
  const u_char *ci_addr = bssid_addr + 6 + 2 + 8 + 2;
  uint16_t ci_fields;
  memcpy(&ci_fields, ci_addr, sizeof(ci_fields));
  bool ess = (bool) (ci_fields & 0x0001);
  bool privacy = (bool) ((ci_fields & 0x0010) >> 4);

  char *ssid = NULL;
  u_char *ie = (u_char *) ci_addr + 2;
  uint8_t ie_len = *(ie + 1);
  uint8_t channel = 0, ssid_len = 0;
  bool wps = false/*, utf8_ssid = false*/;

  struct cipher_suite *rsn = NULL;
  struct cipher_suite *msw = NULL;
  // iterate over Information Element to look for SSID and RSN crypto and MicrosoftWPA
  while (ie < packet + header->len) {
    if ((ie + ie_len + 2 < packet + header->len)) {     // just double check that this is an IE with length inside packet
      switch (*ie) {
      case 0:                  // SSID aka IE with id 0
        ssid_len = *(ie + 1);
        ssid = (char *) malloc((ssid_len + 1) * sizeof(u_char));        // AP name
        snprintf(ssid, ssid_len + 1, "%s", ie + 2);
        break;
      case 3:                  // IE with id 3 is DS parameter set ~= channel
        channel = *(ie + 2);
        break;
      case 48:                 // parse RSN IE
        rsn = parse_cipher_suite(ie + 4);
        break;
      case 127:                // Extended Capabilities IE
        if (ie_len >= 7) {
          //utf8_ssid = (bool) (*(ie + 1 + 7) & 0x01);
        }
        break;
      case 221:
        if (memcmp(ie + 2, MS_OUI "\001\001", 5) == 0) {
          // parse MicrosoftWPA IE
          msw = parse_cipher_suite(ie + 8);
        } else if (memcmp(ie + 2, WPS_ID, 4) == 0) {
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

  pthread_mutex_lock(&mutex_queue);
  enqueue(queue, ap);
  struct timespec now;
  clock_gettime(CLOCK_MONOTONIC, &now);
  if (queue->size == MAX_QUEUE_SIZE / 2 || now.tv_sec - start_ts_queue.tv_sec >= 1) {
    start_ts_queue = now;
    // the queue is half full or it's been more than a second; waking up the worker thread to process that
    pthread_cond_signal(&cv);
  }
  pthread_mutex_unlock(&mutex_queue);
}

void usage(void)
{
  printf("Usage: ssid-logger -i IFACE [-f csv|sqlite3] [-o FILENAME]\n");
  printf("  -i IFACE        interface to use\n"
         "  -f csv|sqlite3  output format to use (default sqlite3)\n"
         "  -o FILENAME     explicitly set the output filename\n");
}

int main(int argc, char *argv[])
{
  char *iface = NULL;
  char *option_file_format = NULL;
  char *option_file_name = NULL;
  char *file_name = NULL;
  int opt;

  while ((opt = getopt(argc, argv, "f:hi:no:V")) != -1) {
    switch (opt) {
    case 'f':
      option_file_format = optarg;
      break;
    case 'h':
      usage();
      exit(EXIT_SUCCESS);
      break;
    case 'i':
      iface = optarg;
      break;
    case 'n':
      option_gps = false;
      break;
    case 'o':
      option_file_name = optarg;
      break;
    case 'V':
      printf("%s %s\nCopyright © 2020 solsTice d'Hiver\nLicense GPLv3+: GNU GPL version 3\n", NAME, VERSION);
      exit(EXIT_SUCCESS);
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
  if (option_file_format) {
    if (strcmp(option_file_format, "csv") == 0) {
      format_csv = true;
    } else if (strcmp(option_file_format, "sqlite3") == 0) {
      format_csv = false;
    } else {
      fprintf(stderr, "Error: unrecognised format (not csv nor sqlite3)");
      exit(EXIT_FAILURE);
    }
  }
  if (option_file_name == NULL) {
    if (format_csv) {
      time_t now = time(NULL);
      char timestamp[16];
      strftime(timestamp, 16, "%Y%m%dT%H%M%S", gmtime(&now));
      file_name = malloc(20 * sizeof(char));
      snprintf(file_name, 20, "%s.csv", timestamp);
    } else {
      file_name = malloc((strlen(DB_NAME)+1)*sizeof(char));
      file_name = strncpy(file_name, DB_NAME, strlen(DB_NAME) +1);
    }
  } else {
    file_name = malloc(strlen(option_file_name) + 1);
    strncpy(file_name, option_file_name, strlen(option_file_name)+1);
  }

  if (!option_gps) {
    printf("Warning: you have disabled the use of gpsd. All the GPS data will be 0.0.\n"
      "<! Please don't upload such data file to wigle.net !>\n");
  }

  char errbuf[PCAP_ERRBUF_SIZE];

  // just check if iface is in the list of known devices
  pcap_if_t *devs = NULL;
  if (pcap_findalldevs(&devs, errbuf) == 0) {
    pcap_if_t *d = devs;
    bool found = false;
    while (!found && d != NULL) {
      if ((strlen(d->name) == strlen(iface))
          && (memcmp(d->name, iface, strlen(iface)) == 0)) {
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
  char filter_exp[] = "type mgt subtype beacon";

  if (pcap_compile(handle, &bfp, filter_exp, 1, PCAP_NETMASK_UNKNOWN) == -1) {
    fprintf(stderr, "Error: couldn't parse filter %s: %s\n",
            filter_exp, pcap_geterr(handle));
    exit(EXIT_FAILURE);
  }
  if (pcap_setfilter(handle, &bfp) == -1) {
    fprintf(stderr, "Error: couldn't install filter %s: %s\n",
            filter_exp, pcap_geterr(handle));
    exit(EXIT_FAILURE);
  }
  pcap_freecode(&bfp);

  // start the channel hopper thread
  if (pthread_create(&hopper, NULL, hop_channel, iface)) {
    fprintf(stderr, "Error creating channel hopper thread\n");
    exit(EXIT_FAILURE);
  }

  pthread_cond_init(&cv, NULL);
  pthread_mutex_init(&mutex_queue, NULL);
  queue = new_queue(MAX_QUEUE_SIZE);
  // start the helper worker thread
  if (pthread_create(&worker, NULL, process_queue, NULL)) {
    fprintf(stderr, "Error creating worker thread\n");
    exit(EXIT_FAILURE);
  }

  pthread_mutex_init(&mutex_gloc, NULL);
  // start the helper gps thread
  if (pthread_create(&gps, NULL, retrieve_gps_data, &option_gps)) {
    fprintf(stderr, "Error creating gps thread\n");
    exit(EXIT_FAILURE);
  }
  // this is a little over-kill but is there a better way ?
  pthread_mutex_init(&mutex_gtr, NULL);
  pthread_mutex_lock(&mutex_gtr);
  pthread_cond_wait(&cv_gtr, &mutex_gtr);
  if (gps_thread_result == 2) {
    // gps thread can't find gpsd
    pthread_cancel(hopper);
    pthread_cancel(worker);
    pthread_mutex_destroy(&mutex_queue);
    pthread_mutex_destroy(&mutex_gloc);
    pthread_mutex_destroy(&mutex_gtr);
    pthread_cond_destroy(&cv);
    pthread_cond_destroy(&cv_gtr);
    free(file_name);
    exit(EXIT_FAILURE);
  }
  pthread_mutex_unlock(&mutex_gtr);

  // catch CTRL+C to break loop cleanly
  struct sigaction act;
  act.sa_handler = sigint_handler;
  sigaction(SIGINT, &act, NULL);

  clock_gettime(CLOCK_MONOTONIC, &start_ts_queue);

  if (format_csv) {
    file_ptr = fopen(file_name, "a");
    fprintf(file_ptr, "WigleWifi-1.4,appRelease=%s,model=ssid-logger,release=%s,"
      "device=ssid-logger,display=ssid-logger,board=ssid-logger,brand=ssid-logger\n",
      VERSION, VERSION);
    fprintf(file_ptr, "MAC,SSID,AuthMode,FirstSeen,Channel,RSSI,"
      "CurrentLatitude,CurrentLongitude,AltitudeMeters,"
      "AccuracyMeters,Type\n");
  } else {
    init_beacon_db(file_name, &db);
    begin_txn(db);
  }

  // we have to cheat a little and print the message before pcap_loop
  printf(":: Started sniffing beacon on %s, writing to %s\n", iface, file_name);
  printf("Hit CTRL+C to quit\n");
  pcap_loop(handle, -1, (pcap_handler) got_packet, NULL);

  pcap_close(handle);

  pthread_cancel(hopper);
  pthread_cancel(worker);
  pthread_cancel(gps);
  pthread_mutex_destroy(&mutex_queue);
  pthread_mutex_destroy(&mutex_gloc);
  pthread_mutex_destroy(&mutex_gtr);
  pthread_cond_destroy(&cv);
  pthread_cond_destroy(&cv_gtr);

  // free up elements of the queue
  int qs = queue->size;
  struct ap_info *ap;
  for (int i = 0; i < qs; i++) {
    ap = (struct ap_info *) dequeue(queue);
    free_ap_info(ap);
  }
  free(queue);

  if (format_csv) {
    fclose(file_ptr);
  } else {
    commit_txn(db);
    sqlite3_close(db);
  }
  free(file_name);

  return (0);
}
