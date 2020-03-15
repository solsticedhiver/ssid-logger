#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>

#include "radiotap_iter.h"
#include "parsers.h"

void free_cipher_suite(struct cipher_suite *cs) {
  if (cs == NULL) return;

  uint16_t pcsc = cs->pairwise_cipher_count;
  for (int i=0; i< pcsc; i++) {
    free(cs->pairwise_cipher_suite[i]);
  }
  free(cs->pairwise_cipher_suite);

  uint16_t akmsc = cs->akm_cipher_count;
  for (int i=0; i< akmsc; i++) {
    free(cs->akm_cipher_suite[i]);
  }
  free(cs->akm_cipher_suite);

  free(cs);
  cs = NULL;

  return;
}

struct cipher_suite *parse_cipher_suite(u_char *start) {
  struct cipher_suite *cs = malloc(sizeof(struct cipher_suite));

  memcpy(cs->group_cipher_suite, start, 4);

  uint16_t pcsc = cs->pairwise_cipher_count = *(start + 4);
  cs->pairwise_cipher_suite = malloc(pcsc * sizeof(u_char *));
  for (int i=0; i< pcsc; i++) {
    cs->pairwise_cipher_suite[i] = malloc(4 * sizeof(u_char));
    memcpy(cs->pairwise_cipher_suite[i], start + 4 + 2 + i*4, 4);
  }

  uint16_t akmsc = cs->akm_cipher_count = *(start + 4 + 2 + pcsc*4);
  cs->akm_cipher_suite = malloc(akmsc * sizeof(u_char *));
  for (int i=0; i< akmsc; i++) {
    cs->akm_cipher_suite[i] = malloc(4 * sizeof(u_char));
    memcpy(cs->akm_cipher_suite[i], start + 4 + 2 + pcsc*4 + 2 + i*4, 4);
  }
  return cs;
}

int8_t parse_radiotap_header(const u_char *packet, uint16_t *freq, int8_t *rssi) {
  // parse radiotap header to get frequency and rssi
  // returns radiotap header size or -1 on error
  struct ieee80211_radiotap_header *rtaphdr;
  rtaphdr = (struct ieee80211_radiotap_header*)(packet);
  int8_t offset = (int8_t)rtaphdr->it_len;

  struct ieee80211_radiotap_iterator iter;
  uint16_t flags = 0;
  int8_t r;

  static const struct radiotap_align_size align_size_000000_00[] = {
    [0] = { .align = 1, .size = 4, },
    [52] = { .align = 1, .size = 4, },
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
    .n_ns = sizeof(vns_array)/sizeof(vns_array[0]),
  };

  int err = ieee80211_radiotap_iterator_init(&iter, rtaphdr, rtaphdr->it_len, &vns);
  if (err) {
    printf("Error: malformed radiotap header (init returned %d)\n", err);
    return -1;
  }

  *freq = 0;
  *rssi = 0;
  // iterate through radiotap filed and look for frequency and rssi
  while (!(err = ieee80211_radiotap_iterator_next(&iter))) {
    if (iter.this_arg_index == IEEE80211_RADIOTAP_CHANNEL) {
      assert(iter.this_arg_size == 4); // XXX: why ?
      *freq = iter.this_arg[0] + (iter.this_arg[1] << 8);
      //flags = iter.this_arg[2] + (iter.this_arg[3] << 8);
    }
    if (iter.this_arg_index == IEEE80211_RADIOTAP_DBM_ANTSIGNAL) {
      r = (int8_t)*iter.this_arg;
      if (r != 0) *rssi = r; // XXX: why do we get multiple dBm_antSignal with 0 value after the first one ?
    }
    if (*freq != 0 && *rssi != 0) break;
  }
  return offset;
}

char *authmode_from_crypto(struct cipher_suite *rsn, struct cipher_suite *msw,
  bool ess, bool privacy, bool wps) {

  // TODO: rewrite this so that there is safeguard not to overflow authmode string
  char authmode[1024];
  authmode[0] = '\0'; // this is needed for strcat to work
  uint8_t last_byte;

  if (msw != NULL) {
    strcat(authmode, "[WPA-");
    last_byte = (uint8_t)msw->akm_cipher_suite[0][3];
    switch(last_byte) {
      case 1:
        strcat(authmode, "EAP-");
        break;
     case 2:
        strcat(authmode, "PSK-");
        break;
    }
    for (int i=0; i< msw->pairwise_cipher_count; i++) {
      last_byte = (uint8_t)msw->pairwise_cipher_suite[i][3];
      switch(last_byte) {
        case 2:
          strcat(authmode, "+TKIP");
          break;
        case 4:
          strcat(authmode, "CCMP");
          break;
        case 1:
          strcat(authmode, "+WEP-40");
          break;
        case 5:
          strcat(authmode, "+WEP-104");
          break;
      }
    }
    strcat(authmode, "]");
  }
  if (rsn != NULL) {
    strcat(authmode, "[WPA2-");
    last_byte = (uint8_t)rsn->akm_cipher_suite[0][3];
    switch(last_byte) {
      case 1:
        strcat(authmode, "EAP-");
        break;
      case 2:
        strcat(authmode, "PSK-");
        break;
    }
    for (int i=0; i< rsn->pairwise_cipher_count; i++) {
      last_byte = (uint8_t)rsn->pairwise_cipher_suite[i][3];
      switch(last_byte) {
        case 2:
          strcat(authmode, "+TKIP");
          break;
        case 4:
          strcat(authmode, "CCMP");
          break;
      }
    }
    strcat(authmode, "]");
  }
  if (!rsn && !msw && privacy) {
    strcat(authmode, "[WEP]");
  }
  if (wps) {
    strcat(authmode, "[WPS]");
  }
  if (ess) {
    strcat(authmode, "[ESS]");
  }

  char *tmp = malloc((strlen(authmode) + 1 ) * sizeof(char));
  strcpy(tmp, authmode); // TODO: use safer copy function
  return tmp;
}
