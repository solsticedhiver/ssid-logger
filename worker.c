/*
worker thread that will process the queue filled by got_packet()
*/

#include <pthread.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <sqlite3.h>

#include "parsers.h"
#include "queue.h"
#include "worker.h"
#include "gps.h"
#include "db.h"

static const char HIDDEN_SSID[] = "***";

pthread_cond_t cv;
pthread_mutex_t lock_queue;
pthread_mutex_t lock_gloc;
extern queue_t *queue;
struct gps_loc gloc;            // global variable to hold retrieved gps data
sqlite3 *db;

void free_ap_info(struct ap_info *ap)
{
  if (ap->rsn != NULL)
    free_cipher_suite(ap->rsn);
  if (ap->msw != NULL)
    free_cipher_suite(ap->msw);
  free(ap->ssid);
  free(ap);
  ap = NULL;
}

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
      pthread_mutex_lock(&lock_gloc);
      if (gloc.lat && gloc.lon) {
        insert_beacon(*ap, gloc, db); // TODO: we need to use a cache to avoid writing to disk every second
      }
      pthread_mutex_unlock(&lock_gloc);
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
