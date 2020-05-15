#include <stdlib.h>

#include "ap_info.h"
#include "parsers.h"

void free_ap_info(struct ap_info *ap)
{
  if (ap->rsn != NULL)
    free_cipher_suite(ap->rsn);
  if (ap->msw != NULL)
    free_cipher_suite(ap->msw);
  free(ap->ssid);
  free(ap);
  ap = NULL;
}
