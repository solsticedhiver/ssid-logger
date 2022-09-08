#ifndef PARSERS_H
#define PARSERS_H

#include <stdbool.h>
#include <stdint.h>

#include "gps_thread.h"
#include "logger_thread.h"

#define MAX_AUTHMODE_LEN 128L

struct libwifi_bss *parse_beacon_frame(const uint8_t *packet, uint32_t packet_len);

char *authmode_from_crypto(struct libwifi_bss bss);

char *bss_to_str(struct libwifi_bss bss, struct gps_loc gloc);

int parse_os_release(char **os_name, char **os_version);

#endif
