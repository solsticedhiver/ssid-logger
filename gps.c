/*
helper thread that repeatedly retrieve gps coord. from the gpsd daemon
*/
#include <gps.h>
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <time.h>

#include "gps.h"

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

  if (gps_open("localhost", "2947", &gps_data) == -1) {
    fprintf(stderr, "Error: %s\n", gps_errstr(errno));
    return NULL;
  }
  gps_stream(&gps_data, WATCH_ENABLE | WATCH_JSON, NULL);

  // push clean up code when thread is cancelled
  pthread_cleanup_push(cleanup_gps_data, (void *) (&gps_data));

  pthread_mutex_init(&mutex_gloc, NULL);

  while (1) {
    // wait at most for 1 second to receive data
    if (gps_waiting(&gps_data, 1000000)) {
      if (gps_read(&gps_data, NULL, 0) > 0) {
        if (gps_data.set && (gps_data.status == STATUS_FIX)
            && (gps_data.fix.mode == MODE_2D
                || gps_data.fix.mode == MODE_3D)
            && !isnan(gps_data.fix.latitude)
            && !isnan(gps_data.fix.longitude)) {
          pthread_mutex_lock(&mutex_gloc);
          // update global gloc gps location
          gloc.lat = gps_data.fix.latitude;
          gloc.lon = gps_data.fix.longitude;
          gloc.alt = gps_data.fix.altHAE;
          gloc.ftime = gps_data.fix.time;
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
