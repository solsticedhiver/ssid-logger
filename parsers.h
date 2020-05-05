#ifndef PARSERS_H
#define PARSERS_H

#include <stdbool.h>
#include <stdint.h>

#include "gps_thread.h"
#include "logger_thread.h"

#define CSS_OUI "\000\017\254"  // 0x000x0F0xAC or 00-0F-AC
#define MS_OUI "\000\120\362"   // 0x000x500xF2 or 00-50-F2
#define WPS_ID "\000\120\362\004"       // 0x000x500xF20x04 or 00-50-F2-04

struct cipher_suite {
  u_char group_cipher_suite[4];
  uint16_t pairwise_cipher_count;
  u_char **pairwise_cipher_suite;
  uint16_t akm_cipher_count;
  u_char **akm_cipher_suite;
};

extern void free_cipher_suite(struct cipher_suite *cs);

extern struct cipher_suite *parse_cipher_suite(u_char * start);

extern int8_t parse_radiotap_header(const u_char * packet, uint16_t * freq,
                                    int8_t * rssi);

extern void parse_beacon_frame(const u_char *packet, uint32_t header_len,
  int8_t offset, char **bssid, char **ssid, uint8_t *ssid_len, uint8_t *channel,
  bool *ess, bool *privacy, bool *wps, struct cipher_suite **rsn, struct cipher_suite **msw);

extern char *authmode_from_crypto(struct cipher_suite *rsn,
                                  struct cipher_suite *msw, bool ess,
                                  bool privacy, bool wps);

char *ap_to_str(struct ap_info ap, struct gps_loc gloc);

int parse_os_release(char **os_name, char **os_version);
#endif
