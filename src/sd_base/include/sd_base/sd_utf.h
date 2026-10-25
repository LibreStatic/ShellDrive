/* UTF-8 <-> UTF-16 conversion, the stage-1 lossless file-name mapping (01 §10.7, review C23) and
 * server-text sanitization (01 §6.1, TM-R09).
 *
 * Buffer convention for every converter: lengths are in code units (bytes for UTF-8, wchar_t for
 * UTF-16), inputs are not required to be NUL-terminated and outputs are not NUL-terminated.
 * Pass out = NULL to measure; *out_len always receives the full required length. If cap is too
 * small the function fails (SD_E_INVALID_PARAM, or SD_E_NAME_TOO_LONG for the name helpers) and
 * writes nothing useful.
 *
 * Thread safety: pure functions, any thread. */
#ifndef SD_UTF_H
#define SD_UTF_H

#include "sd/base.h"
#include "sd_base/sd_err.h"

enum {
  SD_UTF_STRICT  = 0,        /* invalid input -> SD_E_INVALID_PARAM */
  SD_UTF_REPLACE = 1u << 0   /* invalid input -> U+FFFD */
};

/* General text. Strict mode rejects overlongs, surrogate code points, > U+10FFFF and (UTF-16)
   unpaired surrogates. */
sd_err sd_utf8_to_utf16(const char *in, size_t len, wchar_t *out, size_t cap, size_t *out_len,
                        uint32_t flags);
sd_err sd_utf16_to_utf8(const wchar_t *in, size_t len, char *out, size_t cap, size_t *out_len,
                        uint32_t flags);
int    sd_utf8_valid(const char *in, size_t len);

/* Allocating variants: result is NUL-terminated, allocated with sd_alloc, released with sd_free.
   len = (size_t)-1 means "NUL-terminated input". */
sd_err sd_utf8_to_wide_alloc(const char *in, size_t len, uint32_t flags, wchar_t **out);
sd_err sd_wide_to_utf8_alloc(const wchar_t *in, size_t len, uint32_t flags, char **out);

/* Stage 1 name mapping, one path component at a time.
   Remote bytes -> UTF-16 (lossless). Valid UTF-8 decodes normally, EXCEPT:
   - each byte of an invalid sequence (bad lead, truncated, overlong, surrogate code point,
     > U+10FFFF) maps to U+F700 + byte (U+F780..U+F7FF);
   - a valid sequence encoding a code point in U+F780..U+F7FF is escaped byte-wise too,
     so bytes -> UTF-16 -> bytes is exact for every byte string.
   UTF-16 -> remote bytes: U+F780..U+F7FF -> the single byte (cp - 0xF700); everything else -> UTF-8.
   Fails with SD_E_INVALID_NAME on unpaired surrogates and on output that would contain 0x00 or
   0x2F ('/') (TM-R11). */
sd_err sd_name_to_wide(const char *bytes, uint32_t len, wchar_t *out, uint32_t cap, uint32_t *out_len);
sd_err sd_name_from_wide(const wchar_t *w, uint32_t len, char *out, uint32_t cap, uint32_t *out_len);
/* Rejects empty, "." and ".." components and components containing NUL or '/' (SD_E_INVALID_NAME). */
sd_err sd_name_component_check(const char *bytes, uint32_t len);

/* Server text (banners, prompts, SFTP messages): invalid UTF-8 -> U+FFFD; removes C0 controls except
   TAB/LF/CR, DEL, C1 controls, bidi controls (U+202A-202E, U+2066-2069, U+200E, U+200F, U+061C) and
   zero-width/invisible characters (U+200B-200D, U+2060, U+FEFF, U+180E). Output is valid UTF-8, at
   most `len` * 3 bytes (each invalid byte may become a 3-byte U+FFFD). */
sd_err sd_text_sanitize_server(const char *in, size_t len, char *out, size_t cap, size_t *out_len);
/* Host names shown in prompts: the same removals plus CR/LF/TAB. (Punycode display form: M2, IDN.) */
sd_err sd_text_sanitize_host(const char *in, size_t len, char *out, size_t cap, size_t *out_len);

#endif /* SD_UTF_H */
