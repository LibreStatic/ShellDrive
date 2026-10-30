/* Private 64-bit arithmetic primitives for constant-time code (01 §2.3, §2.4 rule 3, TM-R02).
 *
 * On 32-bit x86 every product of secrets must be a single 32x32->64 MUL (__emulu): MSVC's _allmul
 * helper takes shortcuts on zero/all-ones high words. 64-bit shifts by run-time counts and 64-bit
 * comparisons are not written in constant-time code; shifts by compile-time constants and 64-bit
 * additions are inlined by the compiler and allowed. These helpers are the allow-list for the
 * disassembly check (sd-ctcheck). Thread safety: pure functions. */
#ifndef SD_CT64_H
#define SD_CT64_H

#include "sd/base.h"

/* 32x32->64 product, one MUL instruction on every 32-bit target: __emulu on x86 (MUL), _arm_umull on ARM32
   (UMULL). The portable expression is the fallback for other targets (64-bit ones use 64-bit limbs and never
   reach SD_MUL32 with secrets, see bn.c). Rule 01 2.4.3: no 64x64 multiply on 32-bit targets. */
#if defined(_M_IX86)
#include <intrin.h>
#define SD_MUL32(a, b) __emulu((unsigned int)(a), (unsigned int)(b))
#elif defined(_M_ARM)
#include <intrin.h>
#define SD_MUL32(a, b) _arm_umull((unsigned int)(a), (unsigned int)(b))
#else
#define SD_MUL32(a, b) ((uint64_t)(uint32_t)(a) * (uint64_t)(uint32_t)(b))
#endif

#if defined(_M_X64) || defined(_M_ARM64)
#include <intrin.h>
#endif

/* Put before a loop that handles a secret mask. MSVC vectorizes such loops at /arch:SSE2 and emits a
   pointer-overlap check and a length split (forward branches on addresses and public sizes) around the vector
   body. Keeping the scalar body alone leaves one straight-line sequence per element (sd-isacheck, 01 2.4.1). */
#if defined(_MSC_VER)
#define SD_CT_NO_VECTOR __pragma(loop(no_vector))
#else
#define SD_CT_NO_VECTOR
#endif

/* Value barrier: the optimizer cannot see through a volatile round trip, so masks stay masks. */
static SD_FORCEINLINE uint32_t sd_ct_barrier32(uint32_t x)
{
  volatile uint32_t v = x;
  return v;
}

static SD_FORCEINLINE uint64_t sd_ct_barrier64(uint64_t x)
{
  volatile uint64_t v = x;
  return v;
}

/* Low 64 bits of a 64x64 product, built from 32x32 pieces. */
static SD_FORCEINLINE uint64_t sd_mul64_lo(uint64_t a, uint64_t b)
{
  uint32_t al = (uint32_t)a, ah = (uint32_t)(a >> 32), bl = (uint32_t)b, bh = (uint32_t)(b >> 32);
  uint64_t lo = SD_MUL32(al, bl);
  uint32_t cross = (uint32_t)SD_MUL32(al, bh) + (uint32_t)SD_MUL32(ah, bl);
  return lo + ((uint64_t)cross << 32);
}

/* Full 128-bit product. x64: _umul128; ARM64: MUL + UMULH (01 §2.4 rule 3: both are constant time on the
   cores that run Windows on ARM); other targets: 32x32 pieces. */
static SD_FORCEINLINE void sd_mul64_wide(uint64_t a, uint64_t b, uint64_t *lo, uint64_t *hi)
{
#if defined(_M_X64)
  *lo = _umul128(a, b, hi);
#elif defined(_M_ARM64)
  *lo = a * b;
  *hi = __umulh(a, b);
#else
  uint32_t al = (uint32_t)a, ah = (uint32_t)(a >> 32), bl = (uint32_t)b, bh = (uint32_t)(b >> 32);
  uint64_t ll = SD_MUL32(al, bl), lh = SD_MUL32(al, bh), hl = SD_MUL32(ah, bl), hh = SD_MUL32(ah, bh);
  uint64_t mid = (ll >> 32) + (uint32_t)lh + (uint32_t)hl;
  *lo = (mid << 32) | (uint32_t)ll;
  *hi = hh + (lh >> 32) + (hl >> 32) + (mid >> 32);
#endif
}

/* 64-bit carry and borrow chains (cin, bin are 0 or 1). x64 uses the intrinsics; the other 64-bit targets
   (ARM64 has no _addcarry_u64) use branch-free arithmetic. The result may alias an input. */
static SD_FORCEINLINE unsigned char sd_addcarry64(unsigned char cin, uint64_t a, uint64_t b, uint64_t *r)
{
#if defined(_M_X64)
  return _addcarry_u64(cin, a, b, (unsigned __int64 *)r);
#else
  uint64_t t = a + b, s = t + cin;
  unsigned char c1 = (unsigned char)(t < a), c2 = (unsigned char)(s < t);
  *r = s;
  return (unsigned char)(c1 | c2);
#endif
}

static SD_FORCEINLINE unsigned char sd_subborrow64(unsigned char bin, uint64_t a, uint64_t b, uint64_t *r)
{
#if defined(_M_X64)
  return _subborrow_u64(bin, a, b, (unsigned __int64 *)r);
#else
  uint64_t t = a - b, s = t - bin;
  unsigned char b1 = (unsigned char)(a < b), b2 = (unsigned char)(t < bin);
  *r = s;
  return (unsigned char)(b1 | b2);
#endif
}

/* Masks for 64-bit values without 64-bit compares (all-ones or zero). */
static SD_FORCEINLINE uint64_t sd_ct_is_zero_u64(uint64_t x)
{
  uint32_t t = (uint32_t)x | (uint32_t)(x >> 32);
  uint32_t m = 0u - ((~t & (t - 1u)) >> 31);
  m = sd_ct_barrier32(m);
  return ((uint64_t)m << 32) | m;
}

/* Shifts by a run-time count that is public (count < 64). Branches on the count only. */
static SD_FORCEINLINE uint64_t sd_shl64_pub(uint64_t x, unsigned n)
{
  uint32_t lo = (uint32_t)x, hi = (uint32_t)(x >> 32);
  if (n == 0) return x;
  if (n >= 32) {
    uint32_t h = lo << (n - 32);
    return (uint64_t)h << 32;
  } else {
    uint32_t h = (hi << n) | (lo >> (32 - n)), l = lo << n;
    return ((uint64_t)h << 32) | l;
  }
}

static SD_FORCEINLINE uint64_t sd_shr64_pub(uint64_t x, unsigned n)
{
  uint32_t lo = (uint32_t)x, hi = (uint32_t)(x >> 32);
  if (n == 0) return x;
  if (n >= 32) return (uint64_t)(hi >> (n - 32));
  return ((uint64_t)(hi >> n) << 32) | ((lo >> n) | (hi << (32 - n)));
}

#endif /* SD_CT64_H */
