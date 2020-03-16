#ifndef HOPPER_H
#define HOPPER_H

#include <stdbool.h>

#define HOP_PER_SECOND 5
#define SLEEP_DURATION (1000/HOP_PER_SECOND)*100

static const uint8_t CHANNELS[] =
    { 1, 5, 9, 13, 2, 6, 10, 3, 7, 11, 4, 8, 12 };

extern void *hop_channel(void *arg);

#endif
