/* sd-isacheck negative fixture: compiled /arch:SSE2 with SSE2 intrinsics; the ia32 floor must reject it. */
#include <emmintrin.h>
#include <stdio.h>

__declspec(noinline) void isacheck_fixture_sse2_add(int *out, const int *a, const int *b)
{
  __m128i x = _mm_loadu_si128((const __m128i *)a), y = _mm_loadu_si128((const __m128i *)b);
  _mm_storeu_si128((__m128i *)out, _mm_add_epi32(x, y));
}

int main(void)
{
  int a[4] = { 1, 2, 3, 4 }, b[4] = { 5, 6, 7, 8 }, r[4];
  isacheck_fixture_sse2_add(r, a, b);
  printf("%d\n", r[0] + r[1] + r[2] + r[3]);
  return 0;
}
