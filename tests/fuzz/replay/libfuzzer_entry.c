/* libFuzzer entry point for SD_FUZZ=ON builds (MSVC /fsanitize=fuzzer). Test-only. */
#include "sd_fuzz.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  return sd_fuzz_one(data, size);
}
