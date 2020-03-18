/*
worker thread that will process the queue filled by got_packet()
*/

#include <pthread.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

#include "parsers.h"
#include "queue.h"
#include "worker.h"
#include "gps.h"

static const char HIDDEN_SSID[] = "***";

pthread_cond_t cv;
pthread_mutex_t lock_queue;
pthread_mutex_t lock_gloc;
extern queue_t *queue;
struct gps_loc gloc;            // global variable to hold retrieved gps data

char *already_seen_bssid[64];
uint8_t max_seen_bssid = 0;

void print_ssid_info(struct ap_info *ap)
{
  char *authmode =
      authmode_from_crypto(ap->rsn, ap->msw, ap->ess, ap->privacy, ap->wps);
  printf("%s (%s)\n    CH%3d %4dMHz %ddBm %s\n",
         strlen(ap->ssid) != 0 ? ap->ssid : HIDDEN_SSID, ap->bssid,
         ap->channel, ap->freq, ap->rssi, authmode);
  fflush(stdout);
  free(authmode);
  return;
}

void *process_queue(void *args)
{
  pthread_mutex_init(&lock_queue, NULL);
  pthread_mutex_init(&lock_gloc, NULL);
  struct ap_info *ap;
  struct ap_info **aps;
  int qs;

  while (1) {
    pthread_mutex_lock(&lock_queue);
    pthread_cond_wait(&cv, &lock_queue);

    qs = queue->size;
    aps = malloc(sizeof(struct ap_info *) * qs);
    // off-load queue to a tmp array
    for (int i = 0; i < qs; i++) {
      aps[i] = (struct ap_info *) dequeue(queue);
    }
    assert(queue->size == 0);
    pthread_mutex_unlock(&lock_queue);

    // process the array after having unlock the queue
    for (int j = 0; j < qs; j++) {
      ap = aps[j];
      // has that bssid already been seen ?
      bool seen = false;
      for (int i = 0; i < max_seen_bssid; i++) {
        if (memcmp(already_seen_bssid[i], ap->bssid, 18) == 0) {
          seen = true;
          break;
        }
      }
      // print what we found
      if (!seen) {
        print_ssid_info(ap);
        pthread_mutex_lock(&lock_gloc);
        printf("lat:%f, lon:%f, alt:%f, %ld\n", gloc.lat, gloc.lon, gloc.alt, gloc.time.tv_sec);
        pthread_mutex_unlock(&lock_gloc);

        char *new_seen = malloc(18 * sizeof(u_char));
        strncpy(new_seen, ap->bssid, 18);
        already_seen_bssid[max_seen_bssid] = new_seen;
        max_seen_bssid++;
      }
    }
    for (int j = 0; j < qs; j++) {
      ap = aps[j];
      if (ap->rsn != NULL)
        free_cipher_suite(ap->rsn);
      if (ap->msw != NULL)
        free_cipher_suite(ap->msw);
      free(ap->ssid);
      free(ap);
    }
    free(aps);
  }
  return NULL;
}
