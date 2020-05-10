#include <stdio.h>
#include <unistd.h>
#include <stdbool.h>
#include <pthread.h>

#define BRIGHTNESS "/sys/class/leds/led0/brightness"
#define WAIT_FLASH_ON 500000 // in microseconds
#define LONG_WAIT_BETWEEN_FLASH 5 // in seconds
#define SHORT_WAIT_BETWEEN_FLASH 1 // in seconds

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

void *blink_forever(void *arg)
{
  unsigned int wait = LONG_WAIT_BETWEEN_FLASH;

  // push clean up code when thread is cancelled
  pthread_cleanup_push(cleanup_led_state, NULL);

  while (1) {
    turn_led_on();
    usleep(WAIT_FLASH_ON);
    turn_led_off();
    sleep(wait);
    if (is_gps_got_a_fix) wait = SHORT_WAIT_BETWEEN_FLASH;
  }
  
  pthread_cleanup_pop(1);
  return 0;
}