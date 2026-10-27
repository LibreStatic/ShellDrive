/* AES encryption rounds with the AES instructions (AES-NI, FIPS 197 with the round functions of Intel's AES-NI
 * programming model). Used for the keystream of AES-CTR and AES-GCM and for AES-CBC encryption.
 *
 * Built only for the x86-sse2 and x64 flavours (SD_CRYPTO_X86_HW, src/sd_crypto/sources_hw.cmake). Called
 * only when the key was set up with k->hw, which requires CPUID AESNI and the portable hook off. The key
 * schedule is the bitsliced constant-time expansion in aes_ct.c; this file only consumes its byte round keys.
 *
 * AESENC and AESENCLAST take no secret-dependent branches or memory indices, so the timing is the same for
 * every key and block (AES-NI is constant-time by construction; sd-isacheck checks the surrounding code). */
#include "crypto_internal.h"

#if SD_CRYPTO_X86_HW

#include <immintrin.h>

void sd_aes_ni_encrypt_blocks_ct(const uint8_t *rk, uint32_t rounds, const uint8_t *in, uint8_t *out, size_t nblocks)
{
  uint32_t r;
  while (nblocks >= 4) {
    /* Four independent blocks in flight hide the AESENC latency. */
    __m128i k = _mm_loadu_si128((const __m128i *)rk);
    __m128i b0 = _mm_xor_si128(_mm_loadu_si128((const __m128i *)(in + 0)), k);
    __m128i b1 = _mm_xor_si128(_mm_loadu_si128((const __m128i *)(in + 16)), k);
    __m128i b2 = _mm_xor_si128(_mm_loadu_si128((const __m128i *)(in + 32)), k);
    __m128i b3 = _mm_xor_si128(_mm_loadu_si128((const __m128i *)(in + 48)), k);
    for (r = 1; r < rounds; r++) {
      k = _mm_loadu_si128((const __m128i *)(rk + 16 * r));
      b0 = _mm_aesenc_si128(b0, k);
      b1 = _mm_aesenc_si128(b1, k);
      b2 = _mm_aesenc_si128(b2, k);
      b3 = _mm_aesenc_si128(b3, k);
    }
    k = _mm_loadu_si128((const __m128i *)(rk + 16 * rounds));
    b0 = _mm_aesenclast_si128(b0, k);
    b1 = _mm_aesenclast_si128(b1, k);
    b2 = _mm_aesenclast_si128(b2, k);
    b3 = _mm_aesenclast_si128(b3, k);
    _mm_storeu_si128((__m128i *)(out + 0), b0);
    _mm_storeu_si128((__m128i *)(out + 16), b1);
    _mm_storeu_si128((__m128i *)(out + 32), b2);
    _mm_storeu_si128((__m128i *)(out + 48), b3);
    in += 64;
    out += 64;
    nblocks -= 4;
  }
  while (nblocks != 0) {
    __m128i k = _mm_loadu_si128((const __m128i *)rk);
    __m128i b = _mm_xor_si128(_mm_loadu_si128((const __m128i *)in), k);
    for (r = 1; r < rounds; r++)
      b = _mm_aesenc_si128(b, _mm_loadu_si128((const __m128i *)(rk + 16 * r)));
    b = _mm_aesenclast_si128(b, _mm_loadu_si128((const __m128i *)(rk + 16 * rounds)));
    _mm_storeu_si128((__m128i *)out, b);
    in += 16;
    out += 16;
    nblocks--;
  }
}

#endif /* SD_CRYPTO_X86_HW */
