#ifndef WORKER_THREAD_H
#define WORKER_THREAD_H

#include <ctype.h>
#include <stdbool.h>
#include <stdint.h>

struct ap_info {
  char bssid[18];
  char *ssid;
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
void free_ap_info(struct ap_info *ap);

#endif
