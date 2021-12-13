/*
ssid-logger is a simple software to log SSID you encounter in your vicinity
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
#ifdef HAS_SYS_PRCTL_H
#include <sys/prctl.h>
#endif
#include <semaphore.h>
#include <libwifi.h>

#include "parsers.h"
#include "queue.h"
#include "logger_thread.h"
#include "gps_thread.h"
#include "db.h"
#include "lruc.h"
#include "config.h"

extern pthread_mutex_t mutex_queue;
extern pthread_mutex_t mutex_gloc;
extern queue_t *queue;
extern sem_t queue_empty;
extern sem_t queue_full;
extern struct gps_loc gloc;            // global variable to hold retrieved gps data
extern sqlite3 *db;
struct timespec start_ts_cache;
extern bool format_csv;
extern option_gps_t option_gps;
extern FILE *file_ptr;

lruc *authmode_pk_cache = NULL, *ap_pk_cache = NULL;

void cleanup_caches(void *arg)
{
  lruc_free(authmode_pk_cache);
  lruc_free(ap_pk_cache);

  return;
}

// worker thread that will process the queue filled by process_packet()
void *process_queue(void *args)
{
  struct libwifi_bss *bss;
  struct timespec now;
  struct gps_loc tmp_gloc;

  #ifdef HAS_SYS_PRCTL_H
  // name our thread; using prctl instead of pthread_setname_np to avoid defining _GNU_SOURCE
  prctl(PR_SET_NAME, "logger");
  #endif

  // init caches
  authmode_pk_cache = lruc_new(AUTHMODE_CACHE_SIZE, 1);
  ap_pk_cache = lruc_new(AP_CACHE_SIZE, 1);

  // push cleanup code when exiting thread
  pthread_cleanup_push(cleanup_caches, NULL);

  clock_gettime(CLOCK_MONOTONIC, &now);
  start_ts_cache = now;

  while (true) {
    sem_wait(&queue_empty);
    pthread_mutex_lock(&mutex_queue);
    bss = (struct libwifi_bss *) dequeue(queue);
    pthread_mutex_unlock(&mutex_queue);
    sem_post(&queue_full);

    // process the bss
    pthread_mutex_lock(&mutex_gloc);
    tmp_gloc = gloc;
    pthread_mutex_unlock(&mutex_gloc);

    bool log = false;
    // process gps data in gloc
    if (option_gps == GPS_LOG_ZERO) {
      tmp_gloc.lat = tmp_gloc.lon = tmp_gloc.alt = tmp_gloc.acc = 0.0;
      // use system time because we can't use gps fix time
      clock_gettime(CLOCK_REALTIME, &now);
      tmp_gloc.ftime = now;
      log = true;
    } else {
      if (!tmp_gloc.updated) {
        clock_gettime(CLOCK_MONOTONIC, &now);
        // if gps data is older than MAX_GPS_DATA_AGE seconds (default is 2), don't use them
        if (now.tv_sec - tmp_gloc.ctime.tv_sec > MAX_GPS_DATA_AGE) {
          if (option_gps == GPS_LOG_ONZ) {
            log = false;
          } else {
            tmp_gloc.lat = tmp_gloc.lon = tmp_gloc.alt = tmp_gloc.acc = 0.0;
            log = true;
          }
        }
      } else {
        log = true;
      }
    }
    if (log) {
      if (option_gps == GPS_LOG_ONZ && tmp_gloc.lat == 0.0 && tmp_gloc.lon == 0.0) {
        // that's useless and against what is intended: GPS_LOG_ONZ means only log non zero
        goto nolog;
      }
      if (!format_csv) {
        insert_beacon(*bss, tmp_gloc, db, authmode_pk_cache, ap_pk_cache);
      } else {
        char *tmp = bss_to_str(*bss, tmp_gloc);
        fprintf(file_ptr, "%s\n", tmp);
        free(tmp);
      }
    }
nolog:
    libwifi_free_bss(bss);

    // commit our data if time elapsed is greater than DB_CACHE_TIME
    clock_gettime(CLOCK_MONOTONIC, &now);
    if (now.tv_sec - start_ts_cache.tv_sec >= DB_CACHE_TIME) {
      if (format_csv) {
        fflush(file_ptr);
        fsync(fileno(file_ptr)); // over-kill ?
      } else {
        // commit to db
        commit_txn(db);
        begin_txn(db);
      }
      start_ts_cache = now;
    }
  }

  pthread_cleanup_pop(1);

  return NULL;
}
