#ifndef PARSERS_H
#define PARSERS_H

#include <stdbool.h>
#include <stdint.h>

#include "gps.h"
#include "worker.h"

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

extern char *authmode_from_crypto(struct cipher_suite *rsn,
                                  struct cipher_suite *msw, bool ess,
                                  bool privacy, bool wps);

char *ap_to_str(struct ap_info ap, struct gps_loc gloc);
#endif
