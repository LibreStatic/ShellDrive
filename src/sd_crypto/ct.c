/* Constant-time helpers (sd_crypto/sd_ct.h, 01 §2.4 rules 2 and 7). Masks pass through a volatile
 * value barrier so the compiler cannot turn them back into branches. */
#include "sd_crypto/sd_ct.h"

#include "sd_ct64.h"

uint32_t sd_ct_is_zero_u32(uint32_t a)
{
  return sd_ct_barrier32(0u - ((~a & (a - 1u)) >> 31));
}

uint32_t sd_ct_eq_u32(uint32_t a, uint32_t b)
{
  return sd_ct_is_zero_u32(a ^ b);
}

uint32_t sd_ct_lt_u32(uint32_t a, uint32_t b)
{
  /* Borrow of a - b (Hacker's Delight 2-12). */
  uint32_t borrow = ((~a & b) | ((~a | b) & (a - b))) >> 31;
  return sd_ct_barrier32(0u - borrow);
}

uint32_t sd_ct_select_u32(uint32_t mask, uint32_t a, uint32_t b)
{
  mask = sd_ct_barrier32(mask);
  return b ^ (mask & (a ^ b));
}

uint64_t sd_ct_select_u64(uint64_t mask, uint64_t a, uint64_t b)
{
  mask = sd_ct_barrier64(mask);
  return b ^ (mask & (a ^ b));
}

void sd_ct_cswap_u32(uint32_t bit, uint32_t *a, uint32_t *b, size_t n)
{
  uint32_t m = sd_ct_barrier32(0u - (bit & 1u));
  size_t i;
  for (i = 0; i < n; i++) {
    uint32_t t = m & (a[i] ^ b[i]);
    a[i] ^= t;
    b[i] ^= t;
  }
}

void sd_ct_cswap_u64(uint64_t bit, uint64_t *a, uint64_t *b, size_t n)
{
  uint64_t m = sd_ct_barrier64(0u - (bit & 1u));
  size_t i;
  for (i = 0; i < n; i++) {
    uint64_t t = m & (a[i] ^ b[i]);
    a[i] ^= t;
    b[i] ^= t;
  }
}

void sd_ct_cmov(uint8_t *dst, const uint8_t *src, size_t n, uint8_t mask)
{
  /* Any nonzero mask counts as "true". */
  uint32_t m32 = (uint32_t)mask;
  uint8_t m = (uint8_t)sd_ct_barrier32(0u - ((m32 | (0u - m32)) >> 31));
  size_t i;
  for (i = 0; i < n; i++)
    dst[i] = (uint8_t)(dst[i] ^ (m & (dst[i] ^ src[i])));
}

int sd_ct_memeq(const void *a, const void *b, size_t n)
{
  const volatile uint8_t *x = (const volatile uint8_t *)a, *y = (const volatile uint8_t *)b;
  uint32_t acc = 0;
  size_t i;
  for (i = 0; i < n; i++)
    acc |= (uint32_t)(x[i] ^ y[i]);
  return (int)(sd_ct_is_zero_u32(acc) & 1u);
}
