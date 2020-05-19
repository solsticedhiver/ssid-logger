/*
ssid-logger is a simple software to log SSID you encounter in your vicinity
Copyright © 2020 solsTiCe d'Hiver
*/
#include <net/if.h>
#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <linux/nl80211.h>
#include <stdbool.h>
#include <unistd.h>
#include <pthread.h>
#ifdef HAS_PRCTL_H
#include <sys/prctl.h>
#endif

#include "hopper_thread.h"

struct nl_sock *sckt = NULL;
struct nl_msg *msg = NULL;

void cleanup_socket(void *arg)
{
  nlmsg_free(msg);
  nl_close(sckt);
  nl_socket_free(sckt);

  return;
}

// thread whose sole purpose is to switch the channel of the interface card
// following the predefined pattern set in CHANNELS
void *hop_channel(void *arg)
{
  // based on https://stackoverflow.com/a/53602395/283067
  char *device = (char *) arg;
  uint8_t indx = 0;
  size_t chan_number = sizeof(CHANNELS) / sizeof(uint8_t);

  #ifdef HAS_PRCTL_H
  // name our thread; using prctl instead of pthread_setname_np to avoid defining _GNU_SOURCE
  prctl(PR_SET_NAME, "channel_hopper");
  #endif

  // push clean up code when thread is cancelled
  pthread_cleanup_push(cleanup_socket, NULL);

  // Create the socket and connect to it
  sckt = nl_socket_alloc();
  genl_connect(sckt);
  int ctrl = genl_ctrl_resolve(sckt, "nl80211");

  // create netlink message
  msg = nlmsg_alloc();
  genlmsg_put(msg, 0, 0, ctrl, 0, 0, NL80211_CMD_SET_CHANNEL, 0);
  NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, if_nametoindex(device));
  NLA_PUT_U32(msg, NL80211_ATTR_WIPHY_FREQ, 0); // correctly initialized below

  // find the frequency attribute in the netlink stream message
  struct nlattr *attr_freq = nlmsg_find_attr(nlmsg_hdr(msg), sizeof(uint32_t), NL80211_ATTR_WIPHY_FREQ);
  // and its data portion to change it later
  uint32_t *freq = nla_data(attr_freq);

  while (true) {
    // change the freq by changing the attribute in the netlink message
    *freq = 2412 + (CHANNELS[indx] - 1) * 5;     // 2.4GHz band only for now

    // send the modified message
    int ret = nl_send_auto(sckt, msg);
    if (!ret) {
      goto nla_put_failure;
    }

    indx++;
    if (indx == chan_number) {
      indx = 0;
    }

    usleep(SLEEP_DURATION);

    pthread_testcancel();
    continue;

  nla_put_failure:
    fprintf(stderr, "Error: failed to send netlink message\n");
    fflush(stderr);
    sleep(1);
  }

  nlmsg_free(msg);
  nl_close(sckt);
  nl_socket_free(sckt);

  pthread_cleanup_pop(1);

  return NULL;
}
