/*
ssid-logger is a simple software to log SSID you encounter in your vicinity
Copyright © 2020-2022 solsTiCe d'Hiver
*/
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <time.h>
#include <math.h>

#include <libwifi.h>

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

// parse the beacon frame to look for BSSID and Information Element we need (ssid, crypto, wps)
struct libwifi_bss *parse_beacon_frame(const uint8_t *packet, uint32_t packet_len)
{
  unsigned long data_len = packet_len;
  unsigned char *data = (unsigned char *) packet;

  if (data_len == 0) {
    return NULL;
  }

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
  int length = LIBWIFI_SECURITY_BUF_LEN - 1; // used to avoid overflow

  if (bss.wpa_info.wpa_version == 0) {
    return sec_buf;
  }

  strncat(sec_buf, "[WPA-", length);
  length -= 5;

  for (int i = 0; i < bss.wpa_info.num_auth_key_mgmt_suites; ++i) {
      if (i != 0) {
        strncat(sec_buf, "/", length);
        length -= 1;
      }
      switch (bss.wpa_info.auth_key_mgmt_suites[i].suite_type) {
          case AKM_SUITE_RESERVED:
              break;
          case AKM_SUITE_1X:
              strncat(sec_buf, "EAP", length);
              length -= 3;
              break;
          case AKM_SUITE_PSK:
              strncat(sec_buf, "PSK",length);
              length -= 3;
              break;
          case AKM_SUITE_1X_FT:
              strncat(sec_buf, "EAP+FT", length);
              length -= 6;
              break;
          case AKM_SUITE_PSK_FT:
              strncat(sec_buf, "PSK+FT", length);
              length -= 6;
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
        strncat(sec_buf, "-", length);
        length -= 1;
      } else {
        strncat(sec_buf, "+", length);
        length -= 1;
      }
      switch (bss.wpa_info.unicast_cipher_suites[i].suite_type) {
          case CIPHER_SUITE_GROUP:
              strncat(sec_buf, "GROUP", length);
              length -= 5;
              break;
          case CIPHER_SUITE_TKIP:
              strncat(sec_buf, "TKIP", length);
              length -= 4;
              break;
          case CIPHER_SUITE_RESERVED:
              break;
          case CIPHER_SUITE_WEP40:
              strncat(sec_buf, "WEP40", length);
              length -= 5;
              break;
          case CIPHER_SUITE_WEP104:
              strncat(sec_buf, "WEP104", length);
              length -= 6;
              break;
          case CIPHER_SUITE_CCMP128:
              strncat(sec_buf, "CCMP", length);
              length -= 4;
              break;
          default:
              break;
      }
  }
  strncat(sec_buf, "]", length);
  length -= 1;

  return sec_buf;
}

char *get_rsn_from_bss(struct libwifi_bss bss)
{
  char *sec_buf = malloc(LIBWIFI_SECURITY_BUF_LEN*sizeof(char));
  sec_buf[0] = '\0';
  int s_length = LIBWIFI_SECURITY_BUF_LEN - 1; // used to avoid overflow
  if (bss.rsn_info.rsn_version == 0) {
    return sec_buf;
  }

  char *wpa2_buf = malloc(LIBWIFI_SECURITY_BUF_LEN*sizeof(char));
  wpa2_buf[0] = '\0';
  int w2_length = LIBWIFI_SECURITY_BUF_LEN - 1; // used to avoid overflow
  bool wpa2_found = false;

  int found = 0;
  for (int i = 0; i < bss.rsn_info.num_auth_key_mgmt_suites; ++i) {
      if (memcmp(bss.rsn_info.auth_key_mgmt_suites[i].oui, CIPHER_SUITE_OUI, 3) == 0) {
          if (i == 0) {
            strncat(wpa2_buf, "[WPA2-", w2_length);
            w2_length -= 6;
          }
          if (found > 0) {
            strncat(wpa2_buf, "/", w2_length);
            w2_length -=1;
            found = 0;
          }
          switch (bss.rsn_info.auth_key_mgmt_suites[i].suite_type) {
              case AKM_SUITE_RESERVED:
                  break;
              case AKM_SUITE_1X:
                  found++;
                  strncat(wpa2_buf, "EAP", w2_length);
                  w2_length -= 3;
                  break;
              case AKM_SUITE_PSK:
                  found++;
                  strncat(wpa2_buf, "PSK", w2_length);
                  w2_length -= 3;
                  break;
              case AKM_SUITE_1X_FT:
                  found++;
                  strncat(wpa2_buf, "EAP+FT", w2_length);
                  w2_length -= 6;
                  break;
              case AKM_SUITE_PSK_FT:
                  found++;
                  strncat(wpa2_buf, "PSK+FT", w2_length);
                  w2_length -= 6;
                  break;
              case AKM_SUITE_1X_SHA256:
                  found++;
                  strncat(wpa2_buf, "EAP+SHA256", w2_length);
                  w2_length -= 10;
                  break;
              case AKM_SUITE_PSK_SHA256:
                  found++;
                  strncat(wpa2_buf, "PSK+SHA256", w2_length);
                  w2_length -= 10;
                  break;
              case AKM_SUITE_TDLS:
                  found++;
                  strncat(wpa2_buf, "TDLS", w2_length);
                  w2_length -= 4;
                  break;
              case AKM_SUITE_FILS_SHA256:
                  found++;
                  strncat(wpa2_buf, "FILS+SHA256", w2_length);
                  w2_length -= 11;
                  break;
              case AKM_SUITE_FILS_SHA256_FT:
                  found++;
                  strncat(wpa2_buf, "FILS+FT+SHA256", w2_length);
                  w2_length -= 14;
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
  int w3_length = LIBWIFI_SECURITY_BUF_LEN - 1; // used to avoid overflow
  bool wpa3_found = false;

  found = 0;
  for (int i = 0; i < bss.rsn_info.num_auth_key_mgmt_suites; ++i) {
      if (memcmp(bss.rsn_info.auth_key_mgmt_suites[i].oui, CIPHER_SUITE_OUI, 3) == 0) {
          if (i == 0) {
            strncat(wpa3_buf, "[WPA3-", w3_length);
            w3_length -= 6;
          }
          if (found > 0) {
            strncat(wpa3_buf, "/", w3_length);
            w3_length -= 1;
            found = 0;
          }
          switch (bss.rsn_info.auth_key_mgmt_suites[i].suite_type) {
              case AKM_SUITE_SAE:
                  found++;
                  strncat(wpa3_buf, "SAE", w3_length);
                  w3_length -= 3;
                  break;
              case AKM_SUITE_SAE_FT:
                  found++;
                  strncat(wpa3_buf, "SAE+FT", w3_length);
                  w3_length -= 6;
                  break;
              case AKM_SUITE_AP_PEER:
                  found++;
                  strncat(wpa3_buf, "AP-PEER", w3_length);
                  w3_length -= 7;
                  break;
              case AKM_SUITE_1X_SUITEB_SHA256:
                  found++;
                  strncat(wpa3_buf, "EAP+SHA256", w3_length);
                  w3_length -= 10;
                  break;
              case AKM_SUITE_1X_SUITEB_SHA384:
                  found++;
                  strncat(wpa3_buf, "EAP+SHA384", w3_length);
                  w3_length -= 10;
                  break;
              case AKM_SUITE_1X_FT_SHA384:
                  found++;
                  strncat(wpa3_buf, "EAP+FT+SHA384", w3_length);
                  w3_length -= 13;
                  break;
              case AKM_SUITE_FILS_SHA384:
                  found++;
                  strncat(wpa3_buf, "FILS+SHA384", w3_length);
                  w3_length -= 11;
                  break;
              case AKM_SUITE_FILS_SHA384_FT:
                  found++;
                  strncat(wpa3_buf, "FILS+FT+SHA384", w3_length);
                  w3_length -= 14;
                  break;
              case AKM_SUITE_OWE:
                  found++;
                  strncat(wpa3_buf, "OWE", w3_length);
                  w3_length -= 3;
                  break;
              case AKM_PSK_SHA384_FT:
                  found++;
                  strncat(wpa3_buf, "PSK+FT+SHA384", w3_length);
                  w3_length -= 13;
                  break;
              case AKM_PSK_SHA384:
                  found++;
                  strncat(wpa3_buf, "PSK+SHA384", w3_length);
                  w3_length -= 10;
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
  int length = LIBWIFI_SECURITY_BUF_LEN - 1; // used to avoid overflow

  for (int i = 0; i < bss.rsn_info.num_pairwise_cipher_suites; ++i) {
      if (i == 0) {
        strncat(tmp_buf, "-", length);
        length -= 1;
      } else {
        strncat(tmp_buf, "+", length);
        length -= 1;
      }
      if ((memcmp(bss.rsn_info.pairwise_cipher_suites[i].oui, CIPHER_SUITE_OUI, 3) == 0)) {
          switch (bss.rsn_info.pairwise_cipher_suites[i].suite_type) {
              case CIPHER_SUITE_GROUP:
                  strncat(tmp_buf, "GROUP", length);
                  length -= 5;
                  break;
              case CIPHER_SUITE_TKIP:
                  strncat(tmp_buf, "TKIP", length);
                  length -= 4;
                  break;
              case CIPHER_SUITE_RESERVED:
                  break;
              case CIPHER_SUITE_CCMP128:
                  strncat(tmp_buf, "CCMP", length);
                  length -= 4;
                  break;
              case CIPHER_SUITE_BIP_CMAC128:
                  strncat(tmp_buf, "BIP_CMAC128", length);
                  length -= 11;
                  break;
              case CIPHER_SUITE_NOTALLOWED:
                  break;
              case CIPHER_SUITE_GCMP128:
                  strncat(tmp_buf, "GCMP128", length);
                  length -= 7;
                  break;
              case CIPHER_SUITE_GCMP256:
                  strncat(tmp_buf, "GCMP256", length);
                  length -= 7;
                  break;
              case CIPHER_SUITE_CCMP256:
                  strncat(tmp_buf, "CCMP256", length);
                  length -= 7;
                  break;
              case CIPHER_SUITE_BIP_GMAC128:
                  strncat(tmp_buf, "BIP_GMAC128", length);
                  length -= 11;
                  break;
              case CIPHER_SUITE_BIP_GMAC256:
                  strncat(tmp_buf, "BIP_GMAC256", length);
                  length -= 11;
                  break;
              case CIPHER_SUITE_BIP_CMAC256:
                  strncat(tmp_buf, "BIP_CMAC256", length);
                  length -= 11;
                  break;
              default:
                  break;
          }
      }
  }
  if (wpa2_found) {
    strncat(wpa2_buf, tmp_buf, w2_length);
    w2_length -= strlen(tmp_buf);
    strncat(wpa2_buf, "]", w2_length);
    w2_length -= 1;
  } else {
    strcpy(wpa2_buf, "");
  }
  if (wpa3_found) {
    strncat(wpa3_buf, tmp_buf, w3_length);
    w3_length -= strlen(tmp_buf);
    strncat(wpa3_buf, "]", w3_length);
    w3_length -= 1;
  } else {
    strcpy(wpa3_buf, "");
  }
  free(tmp_buf);

  strncat(sec_buf, wpa2_buf, s_length);
  s_length -= strlen(wpa2_buf);
  strncat(sec_buf, wpa3_buf, s_length);
  s_length -= strlen(wpa3_buf);
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
