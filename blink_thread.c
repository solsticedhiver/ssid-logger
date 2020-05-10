#include <stdio.h>
#include <unistd.h>
#include <stdbool.h>
#include <pthread.h>

#define BRIGHTNESS "/sys/class/leds/led0/brightness"
#define WAIT_FLASH_ON 500000 // in microseconds
#define LONG_WAIT_BETWEEN_FLASH 5 // in seconds
#define SHORT_WAIT_BETWEEN_FLASH 1 // in seconds
#define MAX_FAILED 10

bool is_gps_got_a_fix;

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
 * will blink the led every LONG_WAIT_BETWEEN_FLASH seconds until the gps fix is acquired
 * then will blink every SHORT_WAIT_BETWEEN_FLASH seconds
 * by default, blink every 5 seconds, then every second
 * abort if MAX_FAILED errors is reached
 */
void *blink_forever(void *arg)
{
  unsigned int wait = LONG_WAIT_BETWEEN_FLASH;
  int failed = 0;

  // push clean up code when thread is cancelled
  pthread_cleanup_push(cleanup_led_state, NULL);

  while (1) {
    failed += turn_led_on();
    usleep(WAIT_FLASH_ON);
    failed += turn_led_off();
    sleep(wait);
    if (is_gps_got_a_fix) wait = SHORT_WAIT_BETWEEN_FLASH;
    if (failed < MAX_FAILED*-1) break; // give up if too many errors
  }

  pthread_cleanup_pop(1);
  return NULL;
}
