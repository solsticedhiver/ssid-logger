#ifndef HOPPER_THREAD_H
#define HOPPER_THREAD_H

#include <stdbool.h>
#include <stdint.h>

#include "config.h"

#define SLEEP_DURATION (1000/HOP_PER_SECOND)*100

static const uint8_t CHANNELS[] =
    {1, 7, 13, 2, 8, 14, 3, 9, 4, 10, 5, 11, 6, 12};
    // TODO: we need to query the wifi interface for the available channels

extern void *hop_channel(void *arg);

#endif
