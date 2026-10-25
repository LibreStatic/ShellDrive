#include "sd_base/sd_mem.h"

/* Volatile stores cannot be removed by the optimizer (same technique as RtlSecureZeroMemory). */
void sd_secure_zero(void *p, size_t n)
{
  volatile uint8_t *v = (volatile uint8_t *)p;
  while (n--)
    *v++ = 0;
}
