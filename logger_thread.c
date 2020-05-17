/*
ssid-logger is a simple software to log SSID you encouter in your vicinity
Copyright © 2020 solsTiCe d'Hiver
*/
#include <pthread.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <sqlite3.h>
#include <time.h>
#include <stdbool.h>
#include <unistd.h>
#ifdef HAS_PRCTL_H
#include <sys/prctl.h>
#endif

#include "parsers.h"
#include "queue.h"
#include "logger_thread.h"
#include "gps_thread.h"
#include "db.h"
#include "ap_info.h"

extern pthread_cond_t cv;
extern pthread_mutex_t mutex_queue;
extern pthread_mutex_t mutex_gloc;
extern queue_t *queue;
extern struct gps_loc gloc;            // global variable to hold retrieved gps data
extern sqlite3 *db;
struct timespec start_ts_cache;
extern bool format_csv;
extern enum _option_gps option_gps;
extern FILE *file_ptr;

// worker thread that will process the queue filled by process_packet()
void *process_queue(void *args)
{
  struct ap_info *ap;
  struct ap_info **aps;
  int qs;
  struct timespec now;

  #ifdef HAS_PRCTL_H
  // name our thread; using prctl instead of pthread_setname_np to avoid defining _GNU_SOURCE
  prctl(PR_SET_NAME, "logger");
  #endif

  while (true) {
    pthread_mutex_lock(&mutex_queue);
    pthread_cond_wait(&cv, &mutex_queue);

    qs = queue->size;
    aps = malloc(sizeof(struct ap_info *) * qs);
    // off-load queue to a tmp array
    for (int i = 0; i < qs; i++) {
      aps[i] = (struct ap_info *) dequeue(queue);
    }
    assert(queue->size == 0);
    pthread_mutex_unlock(&mutex_queue);

    // process the array after having unlock the queue
    for (int j = 0; j < qs; j++) {
      ap = aps[j];
      pthread_mutex_lock(&mutex_gloc);
      if (option_gps == GPS_LOG_ZERO) {
        gloc.lat = gloc.lon = gloc.alt = gloc.acc = 0.0;
        // use system time because we can't use gps fix time
        clock_gettime(CLOCK_REALTIME, &gloc.ftime);
      } else if (option_gps == GPS_LOG_ALL) {
        if (!gloc.lat || !gloc.lon) {
          gloc.lat = gloc.lon = gloc.alt = gloc.acc = 0.0;
        }
      }
      if (((option_gps == GPS_LOG_ONZ) && gloc.lat && gloc.lon)
        || (option_gps == GPS_LOG_ALL) || (option_gps == GPS_LOG_ZERO)) {
        if (!format_csv) {
          insert_beacon(*ap, gloc, db);
        } else {
          char *tmp = ap_to_str(*ap, gloc);
          fprintf(file_ptr, "%s\n", tmp);
          free(tmp);
        }
      }
      pthread_mutex_unlock(&mutex_gloc);
    }
    clock_gettime(CLOCK_MONOTONIC, &now);
    if (now.tv_sec - start_ts_cache.tv_sec >= DB_CACHE_TIME) {
      if (format_csv) {
        fflush(file_ptr);
        fsync(fileno(file_ptr));
      } else {
        // commit to db
        commit_txn(db);
        begin_txn(db);
      }
      start_ts_cache = now;
    }
    for (int j = 0; j < qs; j++) {
      ap = aps[j];
      free_ap_info(ap);
    }
    free(aps);
  }
  return NULL;
}
