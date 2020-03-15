#include <net/if.h>
#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <linux/nl80211.h>
#include <stdbool.h>
#include <unistd.h>

#include "hopper.h"

void *hop_channel(void *arg) {
  // based on https://stackoverflow.com/a/53602395/283067
  char *device = (char *)arg;
  uint8_t indx = 0;
  uint32_t freq = 2412 + (CHANNELS[0]-1)*5;
  size_t chan_number = sizeof(CHANNELS)/sizeof(uint8_t);
  struct nl_msg *msg;

  // Create the socket and connect to it
  struct nl_sock *sckt = nl_socket_alloc();
  genl_connect(sckt);
  int ctrl = genl_ctrl_resolve(sckt, "nl80211");
  enum nl80211_commands command = NL80211_CMD_SET_WIPHY;

  while (1) {
    // Allocate a new message
    msg = nlmsg_alloc();

    // create the message so it will send a command to the nl80211 interface
    genlmsg_put(msg, 0, 0, ctrl, 0, 0, command, 0);

    // add specific attributes to change the frequency of the device
    NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, if_nametoindex(device));
    NLA_PUT_U32(msg, NL80211_ATTR_WIPHY_FREQ, freq);

    // finally send it and receive the amount of bytes sent
    int ret = nl_send_auto(sckt, msg);
    //printf("%d bytes sent\n", ret);

    nlmsg_free(msg);

    indx++;
    if (indx == chan_number) {
      indx = 0;
    }
    freq = 2412 + (CHANNELS[indx]-1)*5; // 2.4GHz band only for now

    usleep(SLEEP_DURATION);
    continue;

nla_put_failure:
    nlmsg_free(msg);
    fprintf(stderr, "Error: couldn't send PUT command to interface\n");
    fflush(stderr);
    sleep(5);
  }

  return NULL;
}
