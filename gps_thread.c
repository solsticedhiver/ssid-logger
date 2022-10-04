/*
ssid-logger is a simple software to log SSID you encounter in your vicinity
Copyright © 2020-2022 solsTiCe d'Hiver
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
#ifdef HAS_SYS_PRCTL_H
#include <sys/prctl.h>
#endif
#include <math.h>

#include "config.h"
#include "gps_thread.h"

extern int gps_thread_init_result;
extern pthread_mutex_t mutex_gtr;
extern pthread_mutex_t mutex_gloc;
extern pthread_cond_t cv_gtr;
// global variable to hold the gps data retrieved by the GPS device
struct gps_loc gloc = {
  .updated = false, .lat = 0.0, .lon = 0.0, .alt = 0.0, .acc = 0.0,
  .ftime = { .tv_sec=0, .tv_nsec=0 },
  .ctime = { .tv_sec=0, .tv_nsec=0 }
};

bool has_gps_got_fix = false;

void cleanup_gps_data(void *arg)
{
  struct gps_data_t *gdt;
  gdt = (struct gps_data_t *) arg;

  gps_stream(gdt, WATCH_DISABLE, NULL);
  gps_close(gdt);

  return;
}

// gathers gps data from libgps gdt and store it in our middle man variable gloc
static inline int update_gloc(struct gps_data_t gdt)
{
  gloc.updated = true;
  // update global gloc gps location
  gloc.lat = gdt.fix.latitude;
  gloc.lon = gdt.fix.longitude;
  #if GPSD_API_MAJOR_VERSION >= 9
    gloc.alt = isfinite(gdt.fix.altMSL) ? gdt.fix.altMSL : 0.0;
    gloc.ftime = gdt.fix.time;
    if (isfinite(gdt.fix.eph)) {
      gloc.acc = gdt.fix.eph;
    } else {
      gloc.acc = 0.0;
    }
  #else
    gloc.alt = isfinite(gdt.fix.altitude) ? gdt.fix.altitude : 0.0;
    gloc.ftime.tv_sec = (time_t)gdt.fix.time;
    if (isfinite(gdt.fix.epx) && isfinite(gdt.fix.epy)) {
      gloc.acc = sqrt(2*pow(gdt.fix.epx, 2) + 2*pow(gdt.fix.epy, 2));
    } else {
      gloc.acc = 0.0;
    }
  #endif
  // we use the system monotonic clock to avoid problem if
  // the clock and the gps time are not in sync
  // gloc.ctime is only used for relative timing
  clock_gettime(CLOCK_MONOTONIC, &gloc.ctime);

  return 0;
}

// helper thread that repeatedly retrieve gps coord. from the gpsd daemon
void *retrieve_gps_data(void *arg)
{
  struct gps_data_t gdt;
  option_gps_t *option_gps;

  #ifdef HAS_SYS_PRCTL_H
  // name our thread; using prctl instead of pthread_setname_np to avoid defining _GNU_SOURCE
  prctl(PR_SET_NAME, "logger");
  #endif

  option_gps = (option_gps_t *)arg;
  if (*option_gps == GPS_LOG_ZERO) {
    // don't use gpsd
    pthread_mutex_lock(&mutex_gtr);
    gps_thread_init_result = 1;
    pthread_cond_signal(&cv_gtr);
    pthread_mutex_unlock(&mutex_gtr);
    return NULL;
  }

  if (gps_open(GPSD_HOST, GPSD_PORT, &gdt) == -1) {
    // error connecting to gpsd
    fprintf(stderr, "Error(gpsd): %s\n", gps_errstr(errno));
    pthread_mutex_lock(&mutex_gtr);
    gps_thread_init_result = 2;
    pthread_cond_signal(&cv_gtr);
    pthread_mutex_unlock(&mutex_gtr);
    return NULL;
  }
  gps_stream(&gdt, WATCH_ENABLE | WATCH_JSON, NULL);

  pthread_mutex_lock(&mutex_gtr);
  gps_thread_init_result = 0;
  pthread_cond_signal(&cv_gtr);
  pthread_mutex_unlock(&mutex_gtr);

  // push clean up code when thread is cancelled
  pthread_cleanup_push(cleanup_gps_data, (void *) (&gdt));

  int ret;

  while (true) {
    // wait at most for 1 second to receive data
    if (gps_waiting(&gdt, 1000000)) {
      #if GPSD_API_MAJOR_VERSION >= 7
        ret = gps_read(&gdt, NULL, 0);
      #else
        ret = gps_read(&gdt);
      #endif
      pthread_mutex_lock(&mutex_gloc);
      gloc.updated = false;
      // test everything is right
      if ((ret > 0) && gdt.set && ((gdt.fix.mode == MODE_2D) || (gdt.fix.mode == MODE_3D ))
          && isfinite(gdt.fix.latitude) && isfinite(gdt.fix.longitude)) {
          // update variable to change led blinking code
        has_gps_got_fix = true;
        update_gloc(gdt);
      } else {
        has_gps_got_fix = false;
      }
      pthread_mutex_unlock(&mutex_gloc);
    }
    usleep(500000);
    pthread_testcancel();
  }

  pthread_cleanup_pop(1);

  return NULL;
}
