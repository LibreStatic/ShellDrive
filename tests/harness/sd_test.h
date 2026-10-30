/* Minimal unit-test harness (04 §4: our own, no third-party framework).
 *
 * Usage, one executable per module (sd_add_unit_test in cmake/SdModule.cmake):
 *
 *   SD_TEST(buf_reads_u32) { ... SD_CHECK(x == 1); SD_REQUIRE(p != NULL); ... }
 *   static const sd_test_case k_tests[] = { SD_TEST_ENTRY(buf_reads_u32), ... };
 *   int main(int argc, char **argv) { return sd_test_main(k_tests, SD_COUNTOF(k_tests), argc, argv); }
 *
 * Tests may be spread over several files: declare them with SD_TEST_DECL(name) where the table is.
 * Command line: --list, --filter <substring>. Exit code 0 when every selected test passed.
 * Tests run sequentially on the main thread; checks are not thread-safe (call them from it). */
#ifndef SD_TEST_H
#define SD_TEST_H

#include <stddef.h>
#include <stdint.h>

#include "sd/base.h"

typedef struct sd_test_ctx { const char *name; int failures; } sd_test_ctx;
typedef void (*sd_test_fn)(sd_test_ctx *t);
typedef struct sd_test_case { const char *name; sd_test_fn fn; } sd_test_case;

#define SD_TEST(name)       void sd_test_##name(sd_test_ctx *sd_t_)
#define SD_TEST_DECL(name)  void sd_test_##name(sd_test_ctx *sd_t_)
#define SD_TEST_ENTRY(name) { #name, sd_test_##name }

void sd_test_fail(sd_test_ctx *t, const char *file, int line, const char *fmt, ...);
int  sd_test_main(const sd_test_case *cases, size_t count, int argc, char **argv);

#define SD_CHECK(cond) \
  do { if (!(cond)) sd_test_fail(sd_t_, __FILE__, __LINE__, "check failed: %s", #cond); } while (0)
#define SD_REQUIRE(cond) \
  do { if (!(cond)) { sd_test_fail(sd_t_, __FILE__, __LINE__, "required: %s", #cond); return; } } while (0)
#define SD_CHECK_EQ_U64(a, b) \
  do { uint64_t a_ = (uint64_t)(a), b_ = (uint64_t)(b); \
       if (a_ != b_) sd_test_fail(sd_t_, __FILE__, __LINE__, "%s == %s: %llu != %llu", #a, #b, \
                                  (unsigned long long)a_, (unsigned long long)b_); } while (0)
#define SD_CHECK_EQ_INT(a, b) \
  do { long long a_ = (long long)(a), b_ = (long long)(b); \
       if (a_ != b_) sd_test_fail(sd_t_, __FILE__, __LINE__, "%s == %s: %lld != %lld", #a, #b, a_, b_); } while (0)
#define SD_CHECK_MEM(a, b, n) \
  do { if (sd_test_memcmp((a), (b), (n)) != 0) \
         sd_test_fail(sd_t_, __FILE__, __LINE__, "memory differs: %s vs %s (%u bytes)", #a, #b, (unsigned)(n)); \
  } while (0)
#define SD_CHECK_STR(a, b) \
  do { const char *a_ = (a), *b_ = (b); \
       if (a_ == NULL || b_ == NULL || sd_test_strcmp(a_, b_) != 0) \
         sd_test_fail(sd_t_, __FILE__, __LINE__, "%s == %s: \"%s\" != \"%s\"", #a, #b, \
                      a_ ? a_ : "(null)", b_ ? b_ : "(null)"); } while (0)

int sd_test_memcmp(const void *a, const void *b, size_t n);
int sd_test_strcmp(const char *a, const char *b);

/* Hex helper for vectors: decodes up to cap bytes, returns the byte count (or SIZE_MAX if invalid). */
size_t sd_test_unhex(const char *hex, uint8_t *out, size_t cap);

/* Resolves rel against the directory of the running test executable (the build's bin/<Config>
   directory): fixtures and build artifacts are referenced by name only, never by a compile-time
   absolute path, so the binary does not depend on the build directory (04 §12.2). Returns 1 and
   fills out (NUL-terminated) on success. */
int sd_test_exe_dir_path(const char *rel, char *out, size_t cap);

/* Allocation failure injection: the n-th allocation from now (0-based) and every later one fail
   until sd_test_alloc_fail_off(). Uses sd_mem_set_fail_hook (sd_base/sd_mem.h). */
void sd_test_alloc_fail_after(unsigned n);
void sd_test_alloc_fail_off(void);

#endif /* SD_TEST_H */
