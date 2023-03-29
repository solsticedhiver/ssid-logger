#include <stdio.h>
#include <unistd.h>
#include <stdbool.h>
#include <pthread.h>
#ifdef HAS_SYS_PRCTL_H
#include <sys/prctl.h>
#endif

#include "config.h"

extern bool has_gps_got_fix;
 const char *BRIGHTNESS = LED0_BRIGHTNESS;

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

void blink_dot(void) {
  turn_led_on();
  usleep(DOT_LENGTH);
  turn_led_off();
  usleep(DOT_LENGTH);
}

void blink_dash(void) {
  turn_led_on();
  usleep(3*DOT_LENGTH);
  turn_led_off();
  usleep(DOT_LENGTH);
}

void letter_space(bool complete) {
  // 3 dots length
  usleep(2*DOT_LENGTH); // one has already been added at the end of last sign
  if (complete) {
    usleep(DOT_LENGTH);
  }
}
void word_space(bool complete) {
  // 7 dots length
  usleep(6*DOT_LENGTH); // one has already been added at the end of last sign
  if (complete) {
    usleep(DOT_LENGTH);
  }
}

void as_wait(void) {
  // _AS_ prosign (WAIT)
  blink_dot();
  blink_dash();
  blink_dot();
  blink_dot();
  blink_dot();
}

/*
 * will blink the led to signal gps fix or not
 * if no gps fix, will blink dot, dash, dot, dot, dot (.-...) aka _AS_ (WAIT) prosign in morse code
 * and then pause for 3 word spaces (by default, this is 5.25s)
 *
 * if gpx fix, will blink a dot and pause for 2 word spaces (by default 3.5s)

 * for this to be visible and effective, one needs to use in /boot/config.txt
 * dtparam=act_led_trigger=none
 * dtparam=act_led_activelow=on
 */


void *blink_forever(void *arg)
{
  if (access(BRIGHTNESS, F_OK) == -1) {
    fprintf(stderr, "Error: %s does not exist\n", BRIGHTNESS);
    // trying new new name for kernel 6.x
    BRIGHTNESS = ACT_BRIGHTNESS;
    if (access(BRIGHTNESS, F_OK) == -1) {
      fprintf(stderr, "Error: %s does not exist\n", BRIGHTNESS);
      // abort because the file does not exist
      return NULL;
    }
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
    if (!has_gps_got_fix) {
      as_wait();
      word_space(false);
      word_space(true);
      word_space(true);
    } else {
      blink_dot();
      word_space(false);
      word_space(true);
    }
  }

  pthread_cleanup_pop(1);
  return NULL;
}
