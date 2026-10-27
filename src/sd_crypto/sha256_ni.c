/* SHA-256 compression with the x86 SHA extensions (SHA-NI; Intel "SHA Extensions" programming model,
 * FIPS 180-4 §6.2 for the function). Written against the instruction semantics, not copied from any library.
 *
 * Built only for the x86-sse2 and x64 flavours (SD_CRYPTO_X86_HW, src/sd_crypto/sources_hw.cmake). Called
 * only when sd_crypto_use_hw_sha256() says so: CPUID reports SHA and SSSE3 and the portable hook is off. The
 * portable block function in hash.c is the reference; the unit tests cross-check the two.
 *
 * The instructions run on XMM registers and do no secret-dependent branching or table lookups. The message
 * words live in registers and on the stack of this function; the stack copy is wiped before returning. */
#include "crypto_internal.h"

#if SD_CRYPTO_X86_HW

#include <immintrin.h>

#include "sd_base/sd_mem.h"

void sd_sha256_ni_blocks(uint32_t st[8], const uint8_t *p, size_t nblocks, const uint32_t k[64])
{
  /* Byte-swaps each 32-bit word: the message is big-endian. */
  const __m128i swap = _mm_set_epi64x(0x0c0d0e0f08090a0bLL, 0x0405060700010203LL);
  __m128i state0, state1, tmp, abef, cdgh, msg;
  __m128i w[4];   /* message schedule window: w[i & 3] holds words 4i..4i+3 */
  int i;

  /* Repack (A..H) into the instruction's ABEF / CDGH layout (Intel's sample sequence). */
  tmp = _mm_loadu_si128((const __m128i *)&st[0]);       /* A B C D */
  state1 = _mm_loadu_si128((const __m128i *)&st[4]);    /* E F G H */
  tmp = _mm_shuffle_epi32(tmp, 0xB1);                   /* B A D C */
  state1 = _mm_shuffle_epi32(state1, 0x1B);             /* H G F E */
  state0 = _mm_alignr_epi8(tmp, state1, 8);             /* ABEF */
  /* blend_epi16(state1, tmp, 0xF0) without SSE4.1: low qword from state1, high qword from tmp. */
  state1 = _mm_castpd_si128(_mm_shuffle_pd(_mm_castsi128_pd(state1), _mm_castsi128_pd(tmp), 2));   /* CDGH */

  while (nblocks != 0) {
    abef = state0;
    cdgh = state1;

    for (i = 0; i < 4; i++)
      w[i] = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i *)(p + 16 * i)), swap);

    for (i = 0; i < 16; i++) {
      if (i >= 4) {
        /* W[t] = sigma1(W[t-2]) + W[t-7] + sigma0(W[t-15]) + W[t-16], four words per step. */
        __m128i t = _mm_sha256msg1_epu32(w[i & 3], w[(i + 1) & 3]);
        t = _mm_add_epi32(t, _mm_alignr_epi8(w[(i + 3) & 3], w[(i + 2) & 3], 4));
        w[i & 3] = _mm_sha256msg2_epu32(t, w[(i + 3) & 3]);
      }
      msg = _mm_add_epi32(w[i & 3], _mm_loadu_si128((const __m128i *)(k + 4 * i)));
      state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
      msg = _mm_shuffle_epi32(msg, 0x0E);
      state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
    }

    state0 = _mm_add_epi32(state0, abef);
    state1 = _mm_add_epi32(state1, cdgh);
    p += 64;
    nblocks--;
  }

  /* Back to (A..H) order. */
  tmp = _mm_shuffle_epi32(state0, 0x1B);                /* F E B A */
  state1 = _mm_shuffle_epi32(state1, 0xB1);            /* G H C D */
  state0 = _mm_castpd_si128(_mm_shuffle_pd(_mm_castsi128_pd(tmp), _mm_castsi128_pd(state1), 2));  /* A B C D */
  state1 = _mm_alignr_epi8(state1, tmp, 8);             /* E F G H */
  _mm_storeu_si128((__m128i *)&st[0], state0);
  _mm_storeu_si128((__m128i *)&st[4], state1);

  sd_secure_zero(w, sizeof(w));
}

#endif /* SD_CRYPTO_X86_HW */
