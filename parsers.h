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
  uint8_t group_cipher_suite[4];
  uint16_t pairwise_cipher_count;
  uint8_t **pairwise_cipher_suite;
  uint16_t akm_cipher_count;
  uint8_t **akm_cipher_suite;
};

void free_cipher_suite(struct cipher_suite *cs);

struct cipher_suite *parse_cipher_suite(uint8_t * start);

int8_t parse_radiotap_header(const uint8_t * packet, uint16_t * freq, int8_t * rssi);

struct ap_info *parse_beacon_frame(const uint8_t *packet, uint32_t packet_len, int8_t offset);

char *authmode_from_crypto(struct cipher_suite *rsn,
                                  struct cipher_suite *msw, bool ess,
                                  bool privacy, bool wps);

char *ap_to_str(struct ap_info ap, struct gps_loc gloc);

int parse_os_release(char **os_name, char **os_version);
#endif
