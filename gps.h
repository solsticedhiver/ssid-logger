#ifndef GPS_H
#define GPS_H

#include <time.h>

struct gps_loc {
  double lat;
  double lon;
  double alt;
  struct timespec time;
} gloc;

void *retrieve_gps_data(void *arg);

#endif
