/* Shared helpers for the sd_ssh unit tests. */
#ifndef SD_SSH_TEST_UTIL_H
#define SD_SSH_TEST_UTIL_H

#include "sd/base.h"
#include "sd_base/sd_err.h"

/* Reads tests/unit/sd_ssh/fixtures/<name> into an sd_alloc'ed buffer (NUL-terminated). */
int tu_read_fixture(const char *name, uint8_t **buf, size_t *len);
/* 1 when sd_crypto is complete; otherwise prints a skip line naming the test and returns 0. */
int tu_crypto_or_skip(const char *test);
/* Deterministic byte source installed with ssh_set_random_for_tests(). */
sd_err tu_det_random(void *p, size_t n);
/* Temp directory for file-store tests (created; trailing backslash, wide). */
int tu_temp_path(const wchar_t *name, wchar_t *out, size_t cap);

#endif
