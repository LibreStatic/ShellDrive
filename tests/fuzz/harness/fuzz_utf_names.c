/* fuzz_utf_names: remote-name mapping (TM-R11, TST-05). Two properties:
   1. bytes -> UTF-16 -> bytes is the identity whenever the forward mapping succeeds (bijection);
   2. UTF-16 -> bytes never emits '/' or NUL, whatever the wide input, whenever it succeeds. */
#include "sd_fuzz.h"
#include "sd_base/sd_utf.h"
#include "sd_base/sd_err.h"

#define NAME_MAX_IN 512u

int sd_fuzz_one(const uint8_t *data, size_t size)
{
  wchar_t wide[NAME_MAX_IN + 1];
  char back[NAME_MAX_IN * 4 + 4];
  uint32_t wlen = 0, blen = 0;
  size_t n = size < NAME_MAX_IN ? size : NAME_MAX_IN;

  if (n) {
    sd_err e = sd_name_to_wide((const char *)data, (uint32_t)n, wide, NAME_MAX_IN, &wlen);
    if (e == SD_OK) {
      sd_err e2 = sd_name_from_wide(wide, wlen, back, sizeof(back), &blen);
      size_t k;
      int has_nul_or_slash = 0;
      for (k = 0; k < n; k++)
        if (data[k] == 0 || data[k] == '/') has_nul_or_slash = 1;
      /* Remote bytes NUL and '/' are not valid name bytes: the reverse map refuses them (TM-R11, 01 10.7).
         Every other byte string must come back unchanged. */
      if (has_nul_or_slash) {
        SD_FUZZ_CHECK(e2 == SD_E_INVALID_NAME);
      } else {
        SD_FUZZ_CHECK(e2 == SD_OK);
        SD_FUZZ_CHECK(blen == n);
        SD_FUZZ_CHECK(memcmp(back, data, n) == 0);
      }
    }
  }

  /* Wide input: build code units from the bytes (two per unit). */
  {
    size_t units = size / 2;
    uint32_t out_len = 0;
    char out[NAME_MAX_IN * 4 + 4];
    size_t k;
    if (units > NAME_MAX_IN) units = NAME_MAX_IN;
    for (k = 0; k < units; k++) wide[k] = (wchar_t)((data[2 * k] << 8) | data[2 * k + 1]);
    if (sd_name_from_wide(wide, (uint32_t)units, out, sizeof(out), &out_len) == SD_OK) {
      for (k = 0; k < out_len; k++) {
        SD_FUZZ_CHECK(out[k] != '\0');
        SD_FUZZ_CHECK(out[k] != '/');
      }
    }
  }
  return 0;
}
