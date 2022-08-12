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


char *get_wpa_from_bss(struct libwifi_bss bss)
{
  char *sec_buf = malloc(LIBWIFI_SECURITY_BUF_LEN*sizeof(char));
  sec_buf[0] = '\0';
  if (bss.wpa_info.wpa_version == 0) {
    return sec_buf;
  }

  strcat(sec_buf, "[WPA-");

  for (int i = 0; i < bss.wpa_info.num_auth_key_mgmt_suites; ++i) {
      if (i != 0) {
        strcat(sec_buf, "/");
      }
      switch (bss.wpa_info.auth_key_mgmt_suites[i].suite_type) {
          case AKM_SUITE_RESERVED:
              break;
          case AKM_SUITE_1X:
              strcat(sec_buf, "EAP");
              break;
          case AKM_SUITE_PSK:
              strcat(sec_buf, "PSK");
              break;
          case AKM_SUITE_1X_FT:
              strcat(sec_buf, "EAP+FT");
              break;
          case AKM_SUITE_PSK_FT:
              strcat(sec_buf, "PSK+FT");
              break;
      }
  }
  #if 0
  switch (bss.wpa_info.multicast_cipher_suite.suite_type) {
      case CIPHER_SUITE_WEP40:
          strcat(sec_buf, "-WEP40");
          break;
      case CIPHER_SUITE_WEP104:
          strcat(sec_buf, "-WEP104");
          break;
      case CIPHER_SUITE_TKIP:
          strcat(sec_buf, "-TKIP");
          break;
      case CIPHER_SUITE_RESERVED:
          break;
      case CIPHER_SUITE_CCMP128:
          strcat(sec_buf, "-CCMP");
          break;
      default:
          break;
  }
  #endif

  for (int i = 0; i < bss.wpa_info.num_unicast_cipher_suites; ++i) {
      if (i == 0) {
        strcat(sec_buf, "-");
      } else {
        strcat(sec_buf, "+");
      }
      switch (bss.wpa_info.unicast_cipher_suites[i].suite_type) {
          case CIPHER_SUITE_GROUP:
              strcat(sec_buf, "GROUP");
              break;
          case CIPHER_SUITE_TKIP:
              strcat(sec_buf, "TKIP");
              break;
          case CIPHER_SUITE_RESERVED:
              break;
          case CIPHER_SUITE_WEP40:
              strcat(sec_buf, "WEP40");
              break;
          case CIPHER_SUITE_WEP104:
              strcat(sec_buf, "WEP104");
              break;
          case CIPHER_SUITE_CCMP128:
              strcat(sec_buf, "CCMP");
              break;
          default:
              break;
      }
  }
  strcat(sec_buf, "]");

  return sec_buf;
}

char *get_rsn_from_bss(struct libwifi_bss bss)
{
  char *sec_buf = malloc(LIBWIFI_SECURITY_BUF_LEN*sizeof(char));
  sec_buf[0] = '\0';
  if (bss.rsn_info.rsn_version == 0) {
    return sec_buf;
  }

  char *wpa2_buf = malloc(LIBWIFI_SECURITY_BUF_LEN*sizeof(char));
  wpa2_buf[0] = '\0';
  bool wpa2_found = false;

  int found = 0;
  for (int i = 0; i < bss.rsn_info.num_auth_key_mgmt_suites; ++i) {
      if (memcmp(bss.rsn_info.auth_key_mgmt_suites[i].oui, CIPHER_SUITE_OUI, 3) == 0) {
          if (i == 0) {
            strcat(wpa2_buf, "[WPA2-");
          }
          if (found > 0) {
            strcat(wpa2_buf, "/");
            found = 0;
          }
          switch (bss.rsn_info.auth_key_mgmt_suites[i].suite_type) {
              case AKM_SUITE_RESERVED:
                  break;
              case AKM_SUITE_1X:
                  found++;
                  strcat(wpa2_buf, "EAP");
                  break;
              case AKM_SUITE_PSK:
                  found++;
                  strcat(wpa2_buf, "PSK");
                  break;
              case AKM_SUITE_1X_FT:
                  found++;
                  strcat(wpa2_buf, "EAP+FT");
                  break;
              case AKM_SUITE_PSK_FT:
                  found++;
                  strcat(wpa2_buf, "PSK+FT");
                  break;
              case AKM_SUITE_1X_SHA256:
                  found++;
                  strcat(wpa2_buf, "EAP+SHA256");
                  break;
              case AKM_SUITE_PSK_SHA256:
                  found++;
                  strcat(wpa2_buf, "PSK+SHA256");
                  break;
              case AKM_SUITE_TDLS:
                  found++;
                  strcat(wpa2_buf, "TDLS");
                  break;
              case AKM_SUITE_FILS_SHA256:
                  found++;
                  strcat(wpa2_buf, "FILS+SHA256");
                  break;
              case AKM_SUITE_FILS_SHA256_FT:
                  found++;
                  strcat(wpa2_buf, "FILS+FT+SHA256");
                  break;
          }
          wpa2_found = wpa2_found | (found > 0);
      }
  }
  if (found == 0) {
    wpa2_buf[strlen(wpa2_buf)-1] = '\0';
  }
  char *wpa3_buf = malloc(LIBWIFI_SECURITY_BUF_LEN*sizeof(char));
  wpa3_buf[0] = '\0';
  bool wpa3_found = false;

  found = 0;
  for (int i = 0; i < bss.rsn_info.num_auth_key_mgmt_suites; ++i) {
      if (memcmp(bss.rsn_info.auth_key_mgmt_suites[i].oui, CIPHER_SUITE_OUI, 3) == 0) {
          if (i == 0) {
            strcat(wpa3_buf, "[WPA3-");
          }
          if (found > 0) {
            strcat(wpa3_buf, "/");
            found = 0;
          }
          switch (bss.rsn_info.auth_key_mgmt_suites[i].suite_type) {
              case AKM_SUITE_SAE:
                  found++;
                  strcat(wpa3_buf, "SAE");
                  break;
              case AKM_SUITE_SAE_FT:
                  found++;
                  strcat(wpa3_buf, "SAE+FT");
                  break;
              case AKM_SUITE_AP_PEER:
                  found++;
                  strcat(wpa3_buf, "AP-PEER");
                  break;
              case AKM_SUITE_1X_SUITEB_SHA256:
                  found++;
                  strcat(wpa3_buf, "EAP+SHA256");
                  break;
              case AKM_SUITE_1X_SUITEB_SHA384:
                  found++;
                  strcat(wpa3_buf, "EAP+SHA384");
                  break;
              case AKM_SUITE_1X_FT_SHA384:
                  found++;
                  strcat(wpa3_buf, "EAP+FT+SHA384");
                  break;
              case AKM_SUITE_FILS_SHA384:
                  found++;
                  strcat(wpa3_buf, "FILS+SHA384");
                  break;
              case AKM_SUITE_FILS_SHA384_FT:
                  found++;
                  strcat(wpa3_buf, "FILS+FT-SHA384");
                  break;
              case AKM_SUITE_OWE:
                  found++;
                  strcat(wpa3_buf, "OWE");
                  break;
              case AKM_PSK_SHA384_FT:
                  found++;
                  strcat(wpa3_buf, "PSK+FT+SHA384");
                  break;
              case AKM_PSK_SHA384:
                  found++;
                  strcat(wpa3_buf, "PSK+SHA384");
                  break;
              default:
                  break;
          }
          wpa3_found = wpa3_found | (found > 0);
      }
  }
  if (found == 0) {
    wpa3_buf[strlen(wpa3_buf)-1] = '\0';
  }
  #if 0
  switch (bss.rsn_info.group_cipher_suite.suite_type) {
      case CIPHER_SUITE_WEP40:
          break;
      case CIPHER_SUITE_TKIP:
          break;
      case CIPHER_SUITE_RESERVED:
          break;
      case CIPHER_SUITE_CCMP128:
          break;
      case CIPHER_SUITE_WEP104:
          break;
      case CIPHER_SUITE_BIP_CMAC128:
          break;
      case CIPHER_SUITE_NOTALLOWED:
          break;
      case CIPHER_SUITE_GCMP128:
          break;
      case CIPHER_SUITE_GCMP256:
          break;
      case CIPHER_SUITE_CCMP256:
          break;
      case CIPHER_SUITE_BIP_GMAC128:
          break;
      case CIPHER_SUITE_BIP_GMAC256:
          break;
      case CIPHER_SUITE_BIP_CMAC256:
          break;
      default:
          break;
  }
  #endif

  char *tmp_buf = malloc(LIBWIFI_SECURITY_BUF_LEN);
  tmp_buf[0] = '\0';
  for (int i = 0; i < bss.rsn_info.num_pairwise_cipher_suites; ++i) {
      if (i == 0) {
        strcat(tmp_buf, "-");
      } else {
        strcat(tmp_buf, "+");
      }
      if ((memcmp(bss.rsn_info.pairwise_cipher_suites[i].oui, CIPHER_SUITE_OUI, 3) == 0)) {
          switch (bss.rsn_info.pairwise_cipher_suites[i].suite_type) {
              case CIPHER_SUITE_GROUP:
                  strcat(tmp_buf, "GROUP");
                  break;
              case CIPHER_SUITE_TKIP:
                  strcat(tmp_buf, "TKIP");
                  break;
              case CIPHER_SUITE_RESERVED:
                  break;
              case CIPHER_SUITE_CCMP128:
                  strcat(tmp_buf, "CCMP");
                  break;
              case CIPHER_SUITE_BIP_CMAC128:
                  strcat(tmp_buf, "BIP_CMAC128");
                  break;
              case CIPHER_SUITE_NOTALLOWED:
                  break;
              case CIPHER_SUITE_GCMP128:
                  strcat(tmp_buf, "GCMP128");
                  break;
              case CIPHER_SUITE_GCMP256:
                  strcat(tmp_buf, "GCMP256");
                  break;
              case CIPHER_SUITE_CCMP256:
                  strcat(tmp_buf, "CCMP256");
                  break;
              case CIPHER_SUITE_BIP_GMAC128:
                  strcat(tmp_buf, "BIP_GMAC128");
                  break;
              case CIPHER_SUITE_BIP_GMAC256:
                  strcat(tmp_buf, "BIP_GMAC256");
                  break;
              case CIPHER_SUITE_BIP_CMAC256:
                  strcat(tmp_buf, "BIP_CMAC256");
                  break;
              default:
                  break;
          }
      }
  }
  if (wpa2_found) {
    strcat(wpa2_buf, tmp_buf);
    strcat(wpa2_buf, "]");
  } else {
    strcpy(wpa2_buf, "");
  }
  if (wpa3_found) {
    strcat(wpa3_buf, tmp_buf);
    strcat(wpa3_buf, "]");
  } else {
    strcpy(wpa3_buf, "");
  }
  free(tmp_buf);

  strcat(sec_buf, wpa2_buf);
  strcat(sec_buf, wpa3_buf);
  free(wpa2_buf);
  free(wpa3_buf);

  return sec_buf;
}

// construct a string from crypto cipher suites and variables
char *authmode_from_crypto(struct libwifi_bss bss)
{
  char authmode[MAX_AUTHMODE_LEN];
  authmode[0] = '\0';           // this is needed for strcat to work
  long int length = MAX_AUTHMODE_LEN - 1; // used to avoid overflowing authmode

  char *wpa_info = get_wpa_from_bss(bss);
  strncat(authmode, wpa_info, length);
  length -= strlen(wpa_info);
  free(wpa_info);

  char *rsn_info = get_rsn_from_bss(bss);
  strncat(authmode, rsn_info, length);
  length -= strlen(rsn_info);
  free(rsn_info);

  if (bss.encryption_info & WEP) {
    strncat(authmode, "[WEP]", length);
    length -= 5;
  }

  if (bss.wps) {
    strncat(authmode, "[WPS]", length);
    length -= 5;
  }
  strncat(authmode, "[ESS]", length);
  length -= 5;

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
