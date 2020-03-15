#ifndef HOPPER_H
#define HOPPER_H

#include <stdbool.h>

#define HOP_PER_SECOND 5
#define SLEEP_DURATION (1000/HOP_PER_SECOND)*100

static const uint8_t CHANNELS[] =
    { 1, 4, 7, 10, 13, 2, 5, 8, 11, 3, 6, 9, 12 };

extern void *hop_channel(void *arg);

#endif
