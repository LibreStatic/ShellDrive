/* sd-isacheck negative fixture: 64x64 multiplication and a 64-bit shift by a run-time count compile to
   _allmul / _allshl calls on 32-bit x86; the constant-time gate must name the calling functions. */
#include <stdint.h>

__declspec(noinline) uint64_t isacheck_fixture_mul64(uint64_t a, uint64_t b)
{
  return a * b;
}

__declspec(noinline) uint64_t isacheck_fixture_shl64(uint64_t a, unsigned n)
{
  return a << n;
}
