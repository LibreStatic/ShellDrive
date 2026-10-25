/* Checked size arithmetic (01 §12.1): allocation sizes are computed only through these helpers.
 * Each returns 1 on overflow (leaving *out = SIZE_MAX / UINT64_MAX) and 0 on success.
 * Public data only; not constant time. Thread safety: pure functions. */
#ifndef SD_CHECKED_H
#define SD_CHECKED_H

#include "sd/base.h"

static SD_INLINE int sd_add_ovf(size_t a, size_t b, size_t *out)
{
  if (a > SIZE_MAX - b) { *out = SIZE_MAX; return 1; }
  *out = a + b;
  return 0;
}

static SD_INLINE int sd_mul_ovf(size_t a, size_t b, size_t *out)
{
  if (b != 0 && a > SIZE_MAX / b) { *out = SIZE_MAX; return 1; }
  *out = a * b;
  return 0;
}

static SD_INLINE int sd_add_ovf_u64(uint64_t a, uint64_t b, uint64_t *out)
{
  if (a > UINT64_MAX - b) { *out = UINT64_MAX; return 1; }
  *out = a + b;
  return 0;
}

static SD_INLINE int sd_mul_ovf_u64(uint64_t a, uint64_t b, uint64_t *out)
{
  if (b != 0 && a > UINT64_MAX / b) { *out = UINT64_MAX; return 1; }
  *out = a * b;
  return 0;
}

/* Saturating multiply, e.g. statvfs block counts times block size (02 §6.5, TM-R16). */
static SD_INLINE uint64_t sd_mul_sat_u64(uint64_t a, uint64_t b)
{
  uint64_t r;
  return sd_mul_ovf_u64(a, b, &r) ? UINT64_MAX : r;
}

#endif /* SD_CHECKED_H */
