/*
ssid-logger is a simple software to log SSID you encouter in your vicinity
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

void cleanup_socket(void *arg){
  struct nl_sock *sckt = (struct nl_sock *)arg;
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
  uint32_t freq = 2412 + (CHANNELS[0] - 1) * 5;
  size_t chan_number = sizeof(CHANNELS) / sizeof(uint8_t);
  struct nl_msg *msg;

  #ifdef HAS_PRCTL_H
  // name our thread; using prctl instead of pthread_setname_np to avoid defininf _GNU_SOURCE
  prctl(PR_SET_NAME, "channel_hopper");
  #endif

  // Create the socket and connect to it
  struct nl_sock *sckt = nl_socket_alloc();
  genl_connect(sckt);
  int ctrl = genl_ctrl_resolve(sckt, "nl80211");
  enum nl80211_commands command = NL80211_CMD_SET_CHANNEL;

  // push clean up code when thread is cancelled
  pthread_cleanup_push(cleanup_socket, (void *) sckt);

  while (true) {
    msg = nlmsg_alloc();
    genlmsg_put(msg, 0, 0, ctrl, 0, 0, command, 0);
    NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, if_nametoindex(device));
    NLA_PUT_U32(msg, NL80211_ATTR_WIPHY_FREQ, freq);

    int ret = nl_send_auto(sckt, msg);
    if (!ret) {
      goto nla_put_failure;
    }

    nlmsg_free(msg);

    indx++;
    if (indx == chan_number) {
      indx = 0;
    }
    freq = 2412 + (CHANNELS[indx] - 1) * 5;     // 2.4GHz band only for now

    usleep(SLEEP_DURATION);

    pthread_testcancel();
    continue;

  nla_put_failure:
    nlmsg_free(msg);
    fprintf(stderr, "Error: failed to send netlink message\n");
    fflush(stderr);
    sleep(1);
  }

  pthread_cleanup_pop(1);

  return NULL;
}
