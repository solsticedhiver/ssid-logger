/*
ssid-logger is a simple software to log SSID you encounter in your vicinity
Copyright © 2020 solsTiCe d'Hiver
*/
#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <stdbool.h>
#include <time.h>
#include <math.h>

#include <libwifi.h>
#include <assert.h>

#include "radiotap_iter.h"
#include "parsers.h"
#include "gps_thread.h"

/* Cipher suite selectors
00-0F-AC-00 Use group cipher suite
00-0F-AC-01 WEP (WEP-40)
00-0F-AC-02 TKIP
00-0F-AC-03 Reserved
00-0F-AC-04 CCMP-128
00-0F-AC-05 WEP-104
00-0F-AC-06 BIP-CMAC-128
00-0F-AC-07 Group address traffic not allowed
00-0F-AC-08 GCMP-128
00-0F-AC-09 GCMP-256
00-0F-AC-10 CCMP-256
00-0F-AC-11 BIP-GMAC-128
00-0F-AC-12 BIP-GMAC-256
00-0F-AC-13 BIP-CMAC-256
00-0F-AC-14-255 Reserved
00-0F-AC-06 BIP-CMAC-128
Other OUI: vendor specific

AKM suite selectors
00-0F-AC-00 Reserved
00-0F-AC-01 802.1X (EAP)
00-0F-AC-02 PSK
00-0F-AC-03 FT over 802.1x (EAP+FT)
00-0F-AC-04 FT with PSK (PSK+FT)
00-0F-AC-05 802.1X or PMKSA with SHA256 (EAP-SHA256 ?)
00-0F-AC-06 PSK-SHA256
00-0F-AC-07 TDLS
00-0F-AC-08 SAE-SHA256
00-0F-AC-09 FT over SAE-SHA256 (FT+SAE-SHA256 ?)
00-0F-AC-10 AP Peer Key Authentication
00-0F-AC-11 802.1X with suite B compliant EAP SHA-256
00-0F-AC-12 802.1X with suite B compliant EAP SHA-384
00-0F-AC-13 FT+802.1X with SHA-384
00-0F-AC-14-255 Reserved
Other OUI: Vendor Specific
*/

// from https://stackoverflow.com/a/779960/283067
char *str_replace(const char *orig, const char *rep, const char *with)
{
    char *result;
    char *ins;
    char *tmp;
    int len_rep;
    int len_with;
    int len_front;
    int count;

    if (!orig || !rep)
        return NULL;
    len_rep = strlen(rep);
    if (len_rep == 0)
        return NULL;
    if (!with)
        with = "";
    len_with = strlen(with);

    ins = (char *)orig;
    for (count = 0; (tmp = strstr(ins, rep)); ++count) {
        ins = tmp + len_rep;
    }

    tmp = result = malloc(strlen(orig) + (len_with - len_rep) * count + 1);

    if (!result)
        return NULL;

    while (count--) {
        ins = strstr(orig, rep);
        len_front = ins - orig;
        tmp = strncpy(tmp, orig, len_front) + len_front;
        tmp = strcpy(tmp, with) + len_with;
        orig += len_front + len_rep;
    }
    strcpy(tmp, orig);
    return result;
}

// parse radiotap header to get frequency and rssi
// returns radiotap header size or -1 on error
int8_t parse_radiotap_header(const uint8_t *packet, uint16_t *freq, int8_t *rssi)
{
  struct ieee80211_radiotap_header *rtaphdr;
  rtaphdr = (struct ieee80211_radiotap_header *) (packet);
  int8_t offset = (int8_t) rtaphdr->it_len;

  struct ieee80211_radiotap_iterator iter;
  uint16_t tf = 0;
  //uint16_t flags = 0;
  int8_t r, tr = 0;

  static const struct radiotap_align_size align_size_000000_00[] = {
    [0] = {.align = 1,.size = 4, },
    [52] = {.align = 1,.size = 4, },
  };

  static const struct ieee80211_radiotap_namespace vns_array[] = {
    {
     .oui = 0x000000,
     .subns = 0,
     .n_bits = sizeof(align_size_000000_00),
     .align_size = align_size_000000_00,
      },
  };

  static const struct ieee80211_radiotap_vendor_namespaces vns = {
    .ns = vns_array,
    .n_ns = sizeof(vns_array) / sizeof(vns_array[0]),
  };

  int err = ieee80211_radiotap_iterator_init(&iter, rtaphdr, rtaphdr->it_len, &vns);
  if (err) {
    printf("Error: malformed radiotap header (init returned %d)\n", err);
    *freq = tf;
    *rssi = tr;
    return -1;
  }

  // iterate through radiotap fields and look for frequency and rssi
  while (!(err = ieee80211_radiotap_iterator_next(&iter))) {
    if (iter.this_arg_index == IEEE80211_RADIOTAP_CHANNEL) {
      assert(iter.this_arg_size == 4);  // XXX: why ?
      tf = iter.this_arg[0] + (iter.this_arg[1] << 8);
      //flags = iter.this_arg[2] + (iter.this_arg[3] << 8);
    }
    if (iter.this_arg_index == IEEE80211_RADIOTAP_DBM_ANTSIGNAL) {
      r = (int8_t) * iter.this_arg;
      if (r != 0)
        tr = r;              // XXX: why do we get multiple dBm_antSignal with 0 value after the first one ?
    }
    if (tf != 0 && tr != 0)
      break;
  }
  *freq = tf;
  *rssi = tr;
  return offset;
}

void _get_unicast_ciphers(struct libwifi_bss *bss, char *buf) {
  memset(buf, 0, LIBWIFI_SECURITY_BUF_LEN);

  int offset = 0;
  int append = 0;

  if (bss->wpa_info.num_unicast_cipher_suites == 0) {
    snprintf(buf + offset, LIBWIFI_SECURITY_BUF_LEN, "None");
    return;
  }

  for (int i=0; i< bss->wpa_info.num_unicast_cipher_suites; i++) {
    if (bss->wpa_info.unicast_cipher_suites[i].suite_type == 1) {
      _libwifi_add_sec_item(buf, &offset, &append, "WEP40");
    }
    if (bss->wpa_info.unicast_cipher_suites[i].suite_type == 2) {
      _libwifi_add_sec_item(buf, &offset, &append, "TKIP");
    }
    if (bss->wpa_info.unicast_cipher_suites[i].suite_type == 4) {
      _libwifi_add_sec_item(buf, &offset, &append, "CCMP");
    }
    if (bss->wpa_info.unicast_cipher_suites[i].suite_type == 5) {
      _libwifi_add_sec_item(buf, &offset, &append, "WEP104");
    }
  }
}

// parse the beacon frame to look for BSSID and Information Element we need (ssid, crypto, wps)
struct libwifi_bss *parse_beacon_frame(const uint8_t *packet, uint32_t packet_len, int8_t offset)
{
  unsigned long data_len = packet_len;
  unsigned char *data = (unsigned char *) packet;

  // Initialise a libwifi_frame struct and populate it
  struct libwifi_frame frame = {0};
  int ret = libwifi_get_wifi_frame(&frame, data, data_len, 1 /* has_radiotap*/);
  if (ret != 0) {
    return NULL;
  }

  // Double check that the frame is a beacon frame
  if (frame.frame_control.type == TYPE_MANAGEMENT && frame.frame_control.subtype == SUBTYPE_BEACON) {
    struct libwifi_bss *bss = malloc(sizeof(struct libwifi_bss));
    ret = libwifi_parse_beacon(bss, &frame);
    if (ret != 0) {
      libwifi_free_bss(bss);
      return NULL;
    }
    return bss;
  }
  return NULL;
}

// construct a string from crypto cipher suites and variables
char *authmode_from_crypto(struct libwifi_bss bss)
{
  char authmode[MAX_AUTHMODE_LEN];
  authmode[0] = '\0';           // this is needed for strcat to work
  long int length = MAX_AUTHMODE_LEN - 1; // used to avoid overflowing authmode

  char sec_buf[LIBWIFI_SECURITY_BUF_LEN];
  char *sec_types[4];
  char *context = NULL, *token;
  int i=0, num_sec_types;
  libwifi_get_security_type(&bss, sec_buf);
  if (!strcmp(sec_buf, "None")) {
    num_sec_types = 0;
  } else {
    context = sec_buf;
    while ((token = strtok_r(NULL, ", ", &context)) != NULL) {
      sec_types[i++] = strdup(token);
    }
    num_sec_types= i;
  }

  char *unicast_ciphers[LIBWIFI_MAX_CIPHER_SUITES];
  _get_unicast_ciphers(&bss, sec_buf);
  i=0;
  context = sec_buf;
  while ((token = strtok_r(NULL, ", ", &context)) != NULL) {
    unicast_ciphers[i++] = strdup(token);
  }
  int num_unicast_ciphers = i;

  char *pairwise_ciphers[LIBWIFI_MAX_CIPHER_SUITES];
  libwifi_get_pairwise_ciphers(&bss, sec_buf);
  int num_pairwire_ciphers;
  if (!strcmp(sec_buf, "None")) {
    num_pairwire_ciphers = 0;
  } else {
    i=0;
    context = sec_buf;
    while ((token = strtok_r(NULL, ", ", &context)) != NULL) {
        pairwise_ciphers[i++] = strdup(token);
    }
    num_pairwire_ciphers = i;
  }

  char *auth_key[LIBWIFI_MAX_CIPHER_SUITES];
  libwifi_get_auth_key_suites(&bss, sec_buf);
  int num_auth_key;
  if (!strcmp(sec_buf, "None")) {
    num_auth_key = 0;
  } else {
    i=0;
    context = sec_buf;
    while ((token = strtok_r(NULL, ", ", &context)) != NULL) {
        auth_key[i++] = strdup(token);
    }
    num_auth_key = i;
  }

  char tmp[256];
  for (i=num_sec_types-1; i>= 0; i--) {
    if (!strcmp(sec_types[i] , "WEP")) {
      strncat(authmode, "[WEP]", length);
      length -= 5;
      continue;
    }
    sprintf(tmp, "[%s-", sec_types[i]);
    strncat(authmode, tmp, length);
    length -= strlen(tmp);
    for (int j=0; j<num_auth_key; j++) {
      if (j != num_auth_key-1) {
        sprintf(tmp, "%s/", auth_key[j]);
        length -= 1;
      } else {
        sprintf(tmp, "%s", auth_key[j]);
      }
      strncat(authmode, tmp, length);
      length -= strlen(auth_key[j]);
    }
    strncat(authmode, "-", length);
    length -= 1;
    if (!strcmp(sec_types[i], "WPA")) {
      for(int j=0; j<num_unicast_ciphers; j++) {
        if (j != num_unicast_ciphers-1) {
          sprintf(tmp, "%s+", unicast_ciphers[j]);
          length -= 1;
        } else {
          sprintf(tmp, "%s", unicast_ciphers[j]);
        }
        strncat(authmode, tmp, length);
        length -= strlen(unicast_ciphers[j]);
      }
    } else {
      for(int j=0; j<num_pairwire_ciphers; j++) {
        if (j != num_pairwire_ciphers-1) {
          sprintf(tmp, "%s+", pairwise_ciphers[j]);
          length -= 1;
        } else {
          sprintf(tmp, "%s", pairwise_ciphers[j]);
        }
        strncat(authmode, tmp, length);
        length -= strlen(pairwise_ciphers[j]);
      }
    }
    strncat(authmode, "]", length);
    length -= 1;
  }
  if (bss.wps) {
    strncat(authmode, "[WPS]", length);
    length -= 5;
  }
  strncat(authmode, "[ESS]", length);
  length -= 5;

  // replacement
  char *tmp_rep = str_replace(authmode, "_", "+");
  strncpy(authmode, tmp_rep, MAX_AUTHMODE_LEN);
  tmp_rep = str_replace(authmode, "802.1X", "EAP");
  strncpy(authmode, tmp_rep, MAX_AUTHMODE_LEN);
  tmp_rep = str_replace(authmode, "CCMP128", "CCMP");
  strncpy(authmode, tmp_rep, MAX_AUTHMODE_LEN);
  free(tmp_rep);

  for (i=0; i< num_sec_types; i++) {
    free(sec_types[i]);
  }
  for (i=0; i< num_pairwire_ciphers; i++) {
    free(pairwise_ciphers[i]);
  }
  for (i=0; i< num_auth_key; i++) {
    free(auth_key[i]);
  }
  return strndup(authmode, MAX_AUTHMODE_LEN-length);
}

// turn ap_info into a string (used if format is csv)
char *bss_to_str(struct libwifi_bss bss, struct gps_loc gloc)
{
  char tail[64], firstseen[21];
  char *authmode, *bss_str;

  authmode = authmode_from_crypto(bss);
  if (authmode == NULL) {
    authmode = strdup("");
  }
  strftime(firstseen, 20, "%Y-%m-%d %H:%M:%S", gmtime(&gloc.ftime.tv_sec));
  sprintf(tail, "%d,%d,%-2.6f,%-2.6f,%-2.6f,%-2.6f,WIFI", bss.channel, bss.signal, gloc.lat,
    gloc.lon, gloc.alt, gloc.acc);

  size_t len = 18 + strnlen(bss.ssid, 32) + strlen(authmode) + 20 + 55;
  bss_str = malloc(len+1);
  snprintf(bss_str, len, MACSTR ",%s,%s,%s,%s", MAC2STR(bss.bssid), bss.ssid, authmode, firstseen, tail);
  free(authmode);

  return bss_str;

//MAC,SSID,AuthMode,FirstSeen,Channel,RSSI,CurrentLatitude,CurrentLongitude,AltitudeMeters,AccuracyMeters,Type
//A4:3E:51:XX:XX:XX,Livebox-XXXX,[WPA-PSK-CCMP+TKIP] [WPA2-PSK-CCMP+TKIP][ESS],2020-02-15 17:52:51,6,-78,50.0000000000,-3.0000000000,19.308001,0,WIFI
}

// attempt to get ID and VERSION_ID in any os-release file (see man 5 os-release)
int parse_os_release(char **os_name, char **os_version)
{
  char buf[BUFSIZ], *p;
  char *path = strdup("/etc/os-release");
  FILE *fp = fopen(path, "r");

  if (fp == NULL) {
    free(path);
    path = strdup("/usr/lib/os-release");
    fp = fopen(path, "r");
  }
  free(path);
  if (fp == NULL) {
    return -1;
  }
  while (fgets(buf, sizeof(buf), fp)) {
    char *value, *q;

    // ignore comments
    if (buf[0] == '#') {
      continue;
    }

    // split into name=value
    p = strchr(buf, '=');
    if (!p) {
      continue;
    }
    *p++ = 0;

    value = p;
    q = p;
    while (*p) {
      if (*p == '\\') {
        ++p;
        if (!*p) {
          break;
        }
        *q++ = *p++;
      } else if (*p == '\'' || *p == '"' ||
          *p == '\n') {
        ++p;
      } else {
        *q++ = *p++;
      }
    }
    *q = 0;

    if (!strcmp(buf, "ID")) {
      *os_name = strdup(value);
    } else if (!strcmp(buf, "VERSION_ID")) {
      *os_version = strdup(value);
    }
  }
  fclose(fp);

  return 0;
}
