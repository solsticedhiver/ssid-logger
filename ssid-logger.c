#include <stdio.h>
#include <stdlib.h>
#include <pcap/pcap.h>
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
#include "logger_thread.h"
#include "gps_thread.h"
#include "db.h"

#define NAME "ssid-logger"
#define VERSION "0.1.4"

#define SNAP_LEN 512
#define MAX_QUEUE_SIZE 128

#define DB_NAME "beacon.db"

pcap_t *handle;                 // global, to use it in sigint_handler
queue_t *queue;                 // queue to hold parsed ap infos

pthread_t hopper;
pthread_t logger;
pthread_t gps;
int gps_thread_init_result = 0;
pthread_mutex_t mutex_queue = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t mutex_gloc = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t mutex_gtr = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t cv = PTHREAD_COND_INITIALIZER;
pthread_cond_t cv_gtr = PTHREAD_COND_INITIALIZER;
struct timespec start_ts_queue;

sqlite3 *db = NULL;
bool format_csv = false;
enum _option_gps option_gps = GPS_LOG_ONZ;
FILE *file_ptr = NULL;
int ret = 0;

void sigint_handler(int s)
{
  // stop pcap capture loop
  pcap_breakloop(handle);
}

void process_packet(uint8_t * args, const struct pcap_pkthdr *header, const uint8_t *packet)
{
  uint16_t freq;
  int8_t rssi;
  // parse radiotap header
  int8_t offset = parse_radiotap_header(packet, &freq, &rssi);
  if (offset < 0) {
    return;
  }

  struct ap_info *ap = parse_beacon_frame(packet, header->len, offset);
  ap->freq = freq;
  ap->rssi = rssi;

  pthread_mutex_lock(&mutex_queue);
  enqueue(queue, ap);
  struct timespec now;
  clock_gettime(CLOCK_MONOTONIC, &now);
  if (queue->size == MAX_QUEUE_SIZE / 2 || now.tv_sec - start_ts_queue.tv_sec >= 1) {
    start_ts_queue = now;
    // the queue is half full or it's been more than a second; waking up the logger thread to process that
    pthread_cond_signal(&cv);
  }
  pthread_mutex_unlock(&mutex_queue);
}

void usage(void)
{
  printf("Usage: ssid-logger -i IFACE [-f csv|sqlite3] [-o FILENAME] [-n] [-n] [-V]\n");
  printf("  -i IFACE        interface to use\n"
         "  -f csv|sqlite3  output format to use (default sqlite3)\n"
         "  -o FILENAME     explicitly set the output filename\n"
         "  -n              log ssid even if no gps coordinates are available\n"
         "  -nn or -n -n    don't try to use gpsd and log all ssids\n"
         "  -V              print version and exit\n"
       );
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
      // one -n: log all SSIDs even if no GPS data so with gps coord. as 0.0
      // two -n (-n -n): log all SSIDs with no gps coord. (0.0) and disable the use of gpsd
      option_gps++;
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

  if (option_gps == GPS_LOG_ZERO) {
    printf(":: Warning: you have disabled the use of gpsd. All the GPS data will be 0.0.\n"
      "** Please, don't upload such data file to wigle.net **\n");
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
  handle = pcap_create(iface, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "Error: unable to create pcap handle: %s\n", errbuf);
    exit(EXIT_FAILURE);
  }
  pcap_set_snaplen(handle, SNAP_LEN);
  pcap_set_timeout(handle, 1000);
  pcap_set_promisc(handle, 1);

  if (pcap_activate(handle)) {
    pcap_perror(handle, "Error: ");
    exit(EXIT_FAILURE);
  }
  // only capture packets received by interface
  if (pcap_setdirection(handle, PCAP_D_IN)) {
    pcap_perror(handle, "Error: ");
    exit(EXIT_FAILURE);
  }

  int *dlt_buf, dlt_buf_len;
  dlt_buf_len = pcap_list_datalinks(handle, &dlt_buf);
  if (dlt_buf_len < 0) {
    pcap_perror(handle, "Error: ");
    exit(EXIT_FAILURE);
  }
  bool found = false;
  for (int i=0; i< dlt_buf_len; i++) {
    if  (dlt_buf[i] == DLT_IEEE802_11_RADIO) {
      found = true;
    }
  }
  pcap_free_datalinks(dlt_buf);

  if (found) {
    if (pcap_set_datalink(handle, DLT_IEEE802_11_RADIO)) {
      pcap_perror(handle, "Error: ");
      exit(EXIT_FAILURE);
    }
  } else {
    fprintf(stderr, "Error: the interface %s does not support radiotap header or is not in monitor mode\n", iface);
    exit(EXIT_FAILURE);
  }

  // only capture beacon frames
  struct bpf_program bfp;
  char filter_exp[] = "type mgt subtype beacon";

  if (pcap_compile(handle, &bfp, filter_exp, 1, PCAP_NETMASK_UNKNOWN) == -1) {
    fprintf(stderr, "Error: couldn't parse filter %s: %s\n",
            filter_exp, pcap_geterr(handle));
    ret = EXIT_FAILURE;
    goto handle_failure;
  }
  if (pcap_setfilter(handle, &bfp) == -1) {
    fprintf(stderr, "Error: couldn't install filter '%s': %s\n",
            filter_exp, pcap_geterr(handle));
    exit(EXIT_FAILURE);
  }
  pcap_freecode(&bfp);

  // start the channel hopper thread
  if (pthread_create(&hopper, NULL, hop_channel, iface)) {
    fprintf(stderr, "Error creating channel hopper thread\n");
    ret = EXIT_FAILURE;
    goto hopper_failure;
  }
  pthread_detach(hopper);

  queue = new_queue(MAX_QUEUE_SIZE);
  // start the helper logger thread
  if (pthread_create(&logger, NULL, process_queue, NULL)) {
    fprintf(stderr, "Error creating logger thread\n");
    ret = EXIT_FAILURE;
    goto logger_failure;
  }
  pthread_detach(logger);

  // start the helper gps thread
  if (pthread_create(&gps, NULL, retrieve_gps_data, &option_gps)) {
    fprintf(stderr, "Error creating gps thread\n");
    ret = EXIT_FAILURE;
    goto gps_failure;
  }
  pthread_detach(gps);
  // this is a little over-kill but is there a better way ?
  pthread_mutex_lock(&mutex_gtr);
  pthread_cond_wait(&cv_gtr, &mutex_gtr);
  if (gps_thread_init_result == 2) {
    // gps thread can't find gpsd
    ret = EXIT_FAILURE;
    goto gps_init_failure;
  }
  pthread_mutex_unlock(&mutex_gtr);

  struct sigaction act;
  act.sa_handler = sigint_handler;
  // catch CTRL+C to break loop cleanly
  sigaction(SIGINT, &act, NULL);
  // catch quit signal to flush data to file on disk
  sigaction(SIGQUIT, &act, NULL);
  sigaction(SIGTERM, &act, NULL);

  clock_gettime(CLOCK_MONOTONIC, &start_ts_queue);

  if (format_csv) {
    char *os_name = NULL, *os_version = NULL;
    parse_os_release(&os_name, &os_version);

    file_ptr = fopen(file_name, "a");
    fprintf(file_ptr, "WigleWifi-1.4,appRelease=%s,model=%s,release=%s,"
      "device=ssid-logger,display=ssid-logger,board=ssid-logger,brand=ssid-logger\n",
      VERSION, os_name ? os_name : "linux", os_version ? os_version : "unknown");
    free(os_name);
    free(os_version);
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
  int err;
  if ((err = pcap_loop(handle, -1, (pcap_handler) process_packet, NULL))) {
    if (err == PCAP_ERROR) {
      pcap_perror(handle, "Error: ");
      ret = err;
    }
    if (err == PCAP_ERROR_BREAK) {
      printf("exiting...\n");
    }
  }

  if (format_csv) {
    fclose(file_ptr);
  } else {
    commit_txn(db);
    sqlite3_close(db);
  }

gps_init_failure:
  pthread_mutex_destroy(&mutex_gtr);
  pthread_cond_destroy(&cv_gtr);

gps_failure:
  pthread_cancel(gps);

logger_failure:
  pthread_cancel(logger);

  // free up elements of the queue
  int qs = queue->size;
  struct ap_info *ap;
  for (int i = 0; i < qs; i++) {
    ap = (struct ap_info *) dequeue(queue);
    free_ap_info(ap);
  }
  free(queue);

hopper_failure:
  pthread_cancel(hopper);
  pthread_mutex_destroy(&mutex_queue);
  pthread_mutex_destroy(&mutex_gloc);
  pthread_cond_destroy(&cv);

handle_failure:
  pcap_close(handle);

  free(file_name);

  return ret;
}
