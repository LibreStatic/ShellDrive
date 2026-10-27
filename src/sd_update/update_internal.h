/* sd_update internal helpers shared by update_verify.c, update_state.c, update_winhttp.c and
 * update_engine.c. Not part of the module's public API. */
#ifndef SD_UPDATE_INTERNAL_H
#define SD_UPDATE_INTERNAL_H

#include <stddef.h>
#include <stdint.h>

#include "sd_update/sd_update.h"

/* Text records (manifest and keyset share the syntax). */
sd_upd_res upd_check_text(const uint8_t *data, size_t len);
int        upd_next_line(const uint8_t *data, size_t len, size_t *pos, size_t *start, size_t *end);
int        upd_split(const uint8_t *s, const uint8_t *e, const uint8_t **f, size_t *fl, size_t maxf);
int        upd_field_is(const uint8_t *f, size_t fl, const char *lit);
sd_upd_res upd_copy_field(const uint8_t *f, size_t fl, char *out, size_t cap);
sd_upd_res upd_parse_u64(const uint8_t *f, size_t fl, uint64_t *out, int max_digits);
sd_upd_res upd_parse_hex(const uint8_t *f, size_t fl, uint8_t *out, size_t nbytes);

/* ed25519 over domain || data[0..len). Returns SD_UPD_OK or SD_UPD_E_SIGNATURE (or _E_NO_MEMORY). */
sd_upd_res upd_msg_verify(const uint8_t sig[64], const uint8_t pub[32], const char *domain,
                          const uint8_t *data, size_t len);

/* Keyset this client stored itself: format checks and records, no signature check (see update_verify.c). */
sd_upd_res upd_keyset_load_stored(const uint8_t *data, size_t len, const sd_upd_root *roots, uint32_t nroots,
                                  sd_upd_keyset *ks);

/* Wide-string helpers (engine and state). Bounded, always NUL-terminated, return 0 on overflow. */
int upd_wcpy(wchar_t *dst, size_t cap, const wchar_t *src);
int upd_wcat(wchar_t *dst, size_t cap, const wchar_t *src);

#endif /* SD_UPDATE_INTERNAL_H */
