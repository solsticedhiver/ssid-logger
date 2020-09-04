#ifndef GPS_THREAD_H
#define GPS_THREAD_H

#include <time.h>
#include <stdbool.h>

enum option_gps {
  GPS_LOG_ONZ,   // log SSIDs only if gps data is available (Only Non Zero)
  GPS_LOG_ALL,   // log all SSIDs even if no gps data is available but as 0.0
  GPS_LOG_ZERO   // log all SSIDs but disable the use of gpsd and log 0.0 for gps data
};
typedef enum option_gps option_gps_t;

struct gps_loc {
  bool updated;
  double lat;
  double lon;
  double alt;
  double acc;
  struct timespec ctime;
  struct timespec ftime;
};

void *retrieve_gps_data(void *arg);

#endif
