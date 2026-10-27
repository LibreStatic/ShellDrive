/* Fuzz harness contract (01 section 12.2, 04 section 11.2).
 *
 * Every harness in tests/fuzz/harness/ defines sd_fuzz_one(). Two drivers link it:
 *   - sd-fuzz-<target>.exe (always built): tests/fuzz/replay/sd_fuzz_replay.c runs every file of
 *     tests/fuzz/corpus/<target>/ and a fixed number of deterministic mutations (CTest label fuzz);
 *   - sd-fuzz-<target>-libfuzzer.exe (SD_FUZZ=ON only): tests/fuzz/replay/libfuzzer_entry.c forwards
 *     LLVMFuzzerTestOneInput to sd_fuzz_one under /fsanitize=fuzzer.
 *
 * Harnesses never fail on bad input (parsers are supposed to reject it). They check the invariants of
 * 01 section 12.2 with SD_FUZZ_CHECK, which aborts so that both drivers report a failure.
 * Harness code is test-only and never ships (TST-30). */
#ifndef SD_FUZZ_H
#define SD_FUZZ_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int sd_fuzz_one(const uint8_t *data, size_t size);

#define SD_FUZZ_CHECK(c)                                                                  \
  do {                                                                                    \
    if (!(c)) {                                                                           \
      fprintf(stderr, "sd-fuzz: invariant failed: %s (%s:%d)\n", #c, __FILE__, __LINE__); \
      abort();                                                                            \
    }                                                                                     \
  } while (0)

#endif /* SD_FUZZ_H */
