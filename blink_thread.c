#include <stdio.h>
#include <unistd.h>
#include <stdbool.h>
#include <pthread.h>

#define BRIGHTNESS "/sys/class/leds/led0/brightness"
#define FLASH_DURATION 500000 // in microseconds
#define LONG_WAIT 5 // in seconds
#define SHORT_WAIT 1 // in seconds

extern bool has_gps_got_fix;

int static inline echo_value(const char *path, int value)
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

int static inline turn_led_on(void)
{
  // echo 1 >/sys/class/leds/led0/brightness
  return echo_value(BRIGHTNESS, 1);
}
int static inline turn_led_off(void)
{
// echo 0 >/sys/class/leds/led0/brightness
  return echo_value(BRIGHTNESS, 0);
}

void cleanup_led_state(void *arg)
{
  turn_led_off();
}

/*
 * will blink the led every LONG_WAIT seconds until the gps fix is acquired
 * then will blink every SHORT_WAIT seconds
 * by default, blink every 5 seconds, then every second
 *
 * for this to be visible and effective, one needs to use in /boot/config.txt
 * dtparam=act_led_trigger=none
 * dtparam=act_led_activelow=on
 */
void *blink_forever(void *arg)
{
  unsigned int wait = LONG_WAIT;

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
  // push clean up code when thread is cancelled
  pthread_cleanup_push(cleanup_led_state, NULL);

  while (true) {
    turn_led_on();
    usleep(FLASH_DURATION);
    turn_led_off();
    sleep(wait);
    if (has_gps_got_fix) wait = SHORT_WAIT;
  }

  pthread_cleanup_pop(1);
  return NULL;
}
