#ifndef WORKER_H
#define WORKER_H

#include <ctype.h>

struct ap_info {
  u_char bssid[18];
  u_char *ssid;
  uint16_t channel;
  uint16_t freq;
  int8_t rssi;
  struct cipher_suite *rsn;
  struct cipher_suite *msw;
  bool ess;
  bool privacy;
  bool wps;
};

void *process_queue(void *args);

#endif
