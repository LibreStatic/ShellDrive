/* Helpers for the sd_crypto tests: hex, base64 and the compact vector files in tests/vectors. */
#ifndef SD_CRYPTO_TUTIL_H
#define SD_CRYPTO_TUTIL_H

#include <stddef.h>
#include <stdint.h>

#include <sal.h>

/* Zeroed allocation that aborts the test binary on failure. */
_Ret_notnull_ _Post_writable_byte_size_(n) void *tu_alloc(size_t n);

/* Decodes hex ("-" or "" is empty) into a malloc'd buffer (never NULL); returns the length. */
size_t tu_hex(const char *hex, uint8_t **out);
/* Decodes into a fixed buffer; returns the length or SIZE_MAX. */
size_t tu_hexbuf(const char *hex, uint8_t *out, size_t cap);
/* Standard base64 (ignores whitespace); returns the length or SIZE_MAX. */
size_t tu_base64(const char *b64, uint8_t *out, size_t cap);

/* Whole file from tests/vectors/<rel>, NUL-terminated, malloc'd; NULL if missing. */
char *tu_read_vector_file(const char *rel, size_t *len);

typedef struct tu_lines { char *buf, *pos; } tu_lines;
int  tu_lines_open(tu_lines *l, const char *rel);          /* 0 on success */
/* Splits the next non-comment line on spaces; returns the field count (0 at the end). */
int  tu_lines_next(tu_lines *l, char **fields, int max);
void tu_lines_close(tu_lines *l);

/* Deterministic test PRNG (xorshift); not crypto. */
void tu_rand_fill(uint64_t *state, uint8_t *p, size_t n);
uint32_t tu_rand_u32(uint64_t *state);

double tu_seconds(void);

#endif
