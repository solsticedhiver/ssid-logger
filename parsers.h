#ifndef PARSERS_H
#define PARSERS_H

#include <stdbool.h>
#include <stdint.h>

#include "gps_thread.h"
#include "logger_thread.h"

#define CSS_OUI "\000\017\254"  // 0x000x0F0xAC or 00-0F-AC
#define MS_OUI "\000\120\362"   // 0x000x500xF2 or 00-50-F2
#define WPS_ID "\000\120\362\004"       // 0x000x500xF20x04 or 00-50-F2-04

#define MAX_AUTHMODE_LEN 128L

int8_t parse_radiotap_header(const uint8_t * packet, uint16_t * freq,
  int8_t * rssi);

struct libwifi_bss *parse_beacon_frame(const uint8_t *packet, uint32_t packet_len,
  int8_t offset);

char *authmode_from_crypto(struct libwifi_bss bss);

char *bss_to_str(struct libwifi_bss bss, struct gps_loc gloc);

int parse_os_release(char **os_name, char **os_version);

#endif
