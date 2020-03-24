/*
helper thread that repeatedly retrieve gps coord. from the gpsd daemon
*/
#include <gps.h>
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <unistd.h>
#include <errno.h>
#include <stdbool.h>
#include <pthread.h>
#include <time.h>

#include "gps_thread.h"

int gps_thread_result;
pthread_mutex_t mutex_gtr;
pthread_cond_t cv_gtr;

void cleanup_gps_data(void *arg)
{
  struct gps_data_t *gps_data;
  gps_data = (struct gps_data_t *) arg;

  gps_stream(gps_data, WATCH_DISABLE, NULL);
  gps_close(gps_data);

  return;
}

void *retrieve_gps_data(void *arg)
{
  struct gps_data_t gps_data;
  pthread_mutex_t mutex_gloc;
  bool *option_gps;

  option_gps = (bool *)arg;
  if (!*option_gps) {
    pthread_mutex_lock(&mutex_gtr);
    gps_thread_result = 1;
    pthread_cond_signal(&cv_gtr);
    pthread_mutex_unlock(&mutex_gtr);
    return NULL;
  }

  if (gps_open("localhost", "2947", &gps_data) == -1) {
    fprintf(stderr, "Error(gpsd): %s\n", gps_errstr(errno));
    pthread_mutex_lock(&mutex_gtr);
    gps_thread_result = 2;
    pthread_cond_signal(&cv_gtr);
    pthread_mutex_unlock(&mutex_gtr);
    return NULL;
  }
  gps_stream(&gps_data, WATCH_ENABLE | WATCH_JSON, NULL);

  pthread_mutex_lock(&mutex_gtr);
  gps_thread_result = 0;
  pthread_cond_signal(&cv_gtr);
  pthread_mutex_unlock(&mutex_gtr);

  // push clean up code when thread is cancelled
  pthread_cleanup_push(cleanup_gps_data, (void *) (&gps_data));

  pthread_mutex_init(&mutex_gloc, NULL);

  while (1) {
    // wait at most for 1 second to receive data
    if (gps_waiting(&gps_data, 1000000)) {
      #if GPS_VERSION == 1
      if (gps_read(&gps_data, NULL, 0) > 0) {
      #else
      if (gps_read(&gps_data) > 0) {
      #endif
        if (gps_data.set && (gps_data.status == STATUS_FIX)
            && (gps_data.fix.mode == MODE_2D
                || gps_data.fix.mode == MODE_3D)
            && !isnan(gps_data.fix.latitude)
            && !isnan(gps_data.fix.longitude)) {
          pthread_mutex_lock(&mutex_gloc);
          // update global gloc gps location
          gloc.lat = gps_data.fix.latitude;
          gloc.lon = gps_data.fix.longitude;
          #if GPS_VERSION == 1
          gloc.alt = isnan(gps_data.fix.altMSL) ? 0.0 : gps_data.fix.altMSL;
          gloc.ftime = gps_data.fix.time;
          if (!isnan(gps_data.fix.eph)) {
            gloc.acc = gps_data.fix.eph;
          } else {
            gloc.acc = 0.0;
          }
          #else
          gloc.alt = isnan(gps_data.fix.altitude) ? 0.0 : gps_data.fix.altitude;
          gloc.ftime.tv_sec = (time_t)gps_data.fix.time;
          if (!isnan(gps_data.fix.epx) && !isnan(gps_data.fix.epy)) {
            gloc.acc = (gps_data.fix.epx + gps_data.fix.epy)/2;
          } else {
            gloc.acc = 0.0;
          }
          #endif
          // we use the system clock to avoid problem if
          // the system clock and the gps time are not in sync
          // gloc.ctime is only used for relative timing
          clock_gettime(CLOCK_MONOTONIC, &gloc.ctime);
          pthread_mutex_unlock(&mutex_gloc);
        }
      }
    }
    usleep(500000);
    pthread_testcancel();
  }

  pthread_cleanup_pop(1);

  return NULL;
}
