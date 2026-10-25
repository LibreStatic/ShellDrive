/* Constant-time helpers (01 §2.4 rules 2 and 7). Declarations only; implemented in sd_crypto with a
 * value barrier so MSVC cannot turn masks back into branches. Masks are all-ones or zero.
 * On 32-bit targets 64-bit arithmetic on secrets goes through the internal sd_ct64.h (TM-R02).
 * Thread safety: pure functions. */
#ifndef SD_CT_H
#define SD_CT_H

#include "sd/base.h"

/* 1 if equal, 0 otherwise; time depends only on n. Use for every MAC/tag comparison. */
int      sd_ct_memeq(const void *a, const void *b, size_t n);
uint32_t sd_ct_eq_u32(uint32_t a, uint32_t b);           /* mask */
uint32_t sd_ct_lt_u32(uint32_t a, uint32_t b);           /* mask: a < b */
uint32_t sd_ct_is_zero_u32(uint32_t a);                  /* mask */
uint32_t sd_ct_select_u32(uint32_t mask, uint32_t a, uint32_t b);   /* mask ? a : b */
uint64_t sd_ct_select_u64(uint64_t mask, uint64_t a, uint64_t b);
/* Swaps a[i] and b[i] for i < n when bit != 0 (0 or 1). */
void     sd_ct_cswap_u32(uint32_t bit, uint32_t *a, uint32_t *b, size_t n);
void     sd_ct_cswap_u64(uint64_t bit, uint64_t *a, uint64_t *b, size_t n);
/* dst = mask ? src : dst, byte-wise. */
void     sd_ct_cmov(uint8_t *dst, const uint8_t *src, size_t n, uint8_t mask);

#endif /* SD_CT_H */
