#include <stdio.h>
#include <unistd.h>
#include <stdbool.h>
#include <pthread.h>
#ifdef HAS_SYS_PRCTL_H
#include <sys/prctl.h>
#endif

#include "config.h"

extern unsigned int blink_led_pause;

// echo a value in a file
int echo_value(const char *path, int value)
{
  FILE *fp = fopen(path, "w");
  if (fp == NULL) {
    fprintf(stderr, "Error: can't open %s\n", path);
    return -1;
  }
  fprintf(fp, "%d\n", value);
  fclose(fp);
  return 0;
}

int turn_led_on(void)
{
  // echo 1 >/sys/class/leds/led0/brightness
  return echo_value(BRIGHTNESS, 1);
}
int turn_led_off(void)
{
// echo 0 >/sys/class/leds/led0/brightness
  return echo_value(BRIGHTNESS, 0);
}

void cleanup_led_state(void *arg)
{
  turn_led_off();
}

/*
 * will blink the led every LONG_PAUSE seconds until the gps fix is acquired
 * then will blink every SHORT_PAUSE seconds
 * by default, blink every 5 seconds, then every second
 *
 * for this to be visible and effective, one needs to use in /boot/config.txt
 * dtparam=act_led_trigger=none
 * dtparam=act_led_activelow=on
 */
void *blink_forever(void *arg)
{
  if (access(BRIGHTNESS, F_OK) == -1) {
    // abort because the file does not exist
    fprintf(stderr, "Error: %s does not exist\n", BRIGHTNESS);
    return NULL;
  }
  if (access(BRIGHTNESS, W_OK) == -1) {
    // abort because the file is not writable
    fprintf(stderr, "Error: can't write to %s\n", BRIGHTNESS);
    return NULL;
  }

  #ifdef HAS_SYS_PRCTL_H
  // name our thread; using prctl instead of pthread_setname_np to avoid defining _GNU_SOURCE
  prctl(PR_SET_NAME, "blinker");
  #endif

  // push clean up code when thread is cancelled
  pthread_cleanup_push(cleanup_led_state, NULL);

  while (true) {
    turn_led_on();
    usleep(FLASH_DURATION);
    turn_led_off();
    sleep(blink_led_pause);
  }

  pthread_cleanup_pop(1);
  return NULL;
}
