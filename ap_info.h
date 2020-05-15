#ifndef AP_INFO_H
#define AP_INFO_H

#include <ctype.h>
#include <stdbool.h>
#include <stdint.h>

struct ap_info {
  char bssid[18];
  char *ssid;
  int ssid_len;
  uint16_t channel;
  uint16_t freq;
  int8_t rssi;
  struct cipher_suite *rsn;
  struct cipher_suite *msw;
  bool ess;
  bool privacy;
  bool wps;
};

void free_ap_info(struct ap_info *ap);

#endif
