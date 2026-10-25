/* Bounded reader and growable writer for SSH/SFTP wire encodings (RFC 4251 §5; 01 §12.1).
 *
 * Reader rules: on any error (short input, length over the caller's semantic maximum, malformed
 * mpint or name-list) the read returns zero/empty values and sets the sticky `err` flag. Parse a
 * whole message, then check once with sd_rd_done() (or sd_rd_ok()) before acting on any value.
 * Spans point into the input buffer; they stay valid only while that buffer does.
 *
 * Writer rules: the buffer grows through sd_realloc up to `max`; overflow of `max` or allocation
 * failure sets the sticky `err` and later writes are ignored. Check sd_wr_ok() before using p/len.
 * A writer created with sd_wr_init_secret() wipes every buffer it releases (growth and free).
 * A writer over caller memory (sd_wr_init_fixed) never allocates.
 *
 * Neither type is internally locked: one owner thread at a time. Not constant time: never parse
 * secret-dependent lengths with these helpers. */
#ifndef SD_BUF_H
#define SD_BUF_H

#include "sd/base.h"

typedef struct sd_span { const uint8_t *p; size_t n; } sd_span;

/* ---- reader ---- */

typedef struct sd_rd { const uint8_t *p; size_t n; int err; } sd_rd;

void     sd_rd_init(sd_rd *r, const void *p, size_t n);
uint8_t  sd_rd_u8(sd_rd *r);
uint32_t sd_rd_u32(sd_rd *r);                         /* big-endian */
uint64_t sd_rd_u64(sd_rd *r);                         /* big-endian */
int      sd_rd_bool(sd_rd *r);                        /* any nonzero byte is true (RFC 4251) */
sd_span  sd_rd_bytes(sd_rd *r, size_t n);             /* fixed-size raw bytes */
sd_span  sd_rd_string(sd_rd *r, size_t max_len);      /* uint32 length + bytes, length <= max_len */
/* mpint: rejects negative values and non-canonical encodings (a 00 byte that is not needed, or a
   non-empty encoding of zero). Returns the magnitude without the sign byte; zero is an empty span. */
sd_span  sd_rd_mpint(sd_rd *r, size_t max_bytes);
/* name-list: comma-separated US-ASCII names, each non-empty, printable (0x21..0x7E), no NUL. */
sd_span  sd_rd_name_list(sd_rd *r, size_t max_len);
sd_rd    sd_rd_sub(sd_rd *r, size_t max_len);         /* a string read as a nested reader */
size_t   sd_rd_remaining(const sd_rd *r);
int      sd_rd_ok(const sd_rd *r);                    /* !err */
int      sd_rd_done(const sd_rd *r);                  /* !err && nothing left (trailing data is an error) */

/* Iterates the names of a validated name-list: returns 1 and sets *name, or 0 at the end. *list is
   consumed. */
int sd_namelist_next(sd_span *list, sd_span *name);
/* 1 if `name` (NUL-terminated) is an element of the list. */
int sd_namelist_contains(sd_span list, const char *name);

/* ---- writer ---- */

typedef struct sd_wr {
  uint8_t *p;
  size_t len, cap, max;
  int err;
  int flags;        /* SD_WR_F_* (internal) */
} sd_wr;

void sd_wr_init(sd_wr *w, size_t max);                /* heap-backed, grows on demand */
void sd_wr_init_secret(sd_wr *w, size_t max);         /* as sd_wr_init, wipes released memory */
void sd_wr_init_fixed(sd_wr *w, void *buf, size_t cap); /* caller memory, never grows */
void sd_wr_free(sd_wr *w);                            /* releases heap memory; no-op for fixed */
void sd_wr_reset(sd_wr *w);                           /* len = 0, err = 0, keeps the buffer */
int  sd_wr_ok(const sd_wr *w);

void sd_wr_u8(sd_wr *w, uint8_t v);
void sd_wr_u32(sd_wr *w, uint32_t v);
void sd_wr_u64(sd_wr *w, uint64_t v);
void sd_wr_bool(sd_wr *w, int v);
void sd_wr_bytes(sd_wr *w, const void *p, size_t n);
void sd_wr_string(sd_wr *w, const void *p, size_t n);
void sd_wr_cstring(sd_wr *w, const char *s);          /* string from a NUL-terminated C string */
/* mpint from an unsigned big-endian magnitude: strips leading zeros, adds the 00 sign byte when the
   top bit is set. Not constant time in the number of leading zero bytes. */
void sd_wr_mpint(sd_wr *w, const uint8_t *be, size_t n);
/* name-list from `count` NUL-terminated names. */
void sd_wr_name_list(sd_wr *w, const char *const *names, size_t count);
/* Reserves n bytes and returns a pointer to them (NULL on error); for in-place encoders. */
uint8_t *sd_wr_reserve(sd_wr *w, size_t n);
/* Overwrites a big-endian uint32 already written at offset `off` (e.g. a packet length). */
void sd_wr_patch_u32(sd_wr *w, size_t off, uint32_t v);

/* Big-endian load/store helpers. */
static SD_INLINE uint32_t sd_load_be32(const uint8_t *p)
{
  return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}
static SD_INLINE void sd_store_be32(uint8_t *p, uint32_t v)
{
  p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16); p[2] = (uint8_t)(v >> 8); p[3] = (uint8_t)v;
}
static SD_INLINE uint64_t sd_load_be64(const uint8_t *p)
{
  return ((uint64_t)sd_load_be32(p) << 32) | sd_load_be32(p + 4);
}
static SD_INLINE void sd_store_be64(uint8_t *p, uint64_t v)
{
  sd_store_be32(p, (uint32_t)(v >> 32)); sd_store_be32(p + 4, (uint32_t)v);
}

#endif /* SD_BUF_H */
