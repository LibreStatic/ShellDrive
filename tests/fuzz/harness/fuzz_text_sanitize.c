/* fuzz_text_sanitize: sd_text_sanitize_server (TM-R09). The output is valid UTF-8, has no C0 control other than
   TAB/LF/CR, no DEL, no C1 control, no bidi control and no zero-width or invisible character (sd_utf.h). */
#include "sd_fuzz.h"
#include "sd_base/sd_utf.h"
#include "sd_base/sd_err.h"

#define SAN_MAX_IN 4096u

static int is_bad_cp(uint32_t cp)
{
  if (cp < 0x20 && cp != '\t' && cp != '\n' && cp != '\r') return 1;
  if (cp == 0x7f || (cp >= 0x80 && cp <= 0x9f)) return 1;
  if (cp >= 0x202a && cp <= 0x202e) return 1;      /* bidi embedding and override */
  if (cp >= 0x2066 && cp <= 0x2069) return 1;      /* bidi isolates */
  if (cp == 0x200e || cp == 0x200f || cp == 0x061c) return 1;
  if (cp >= 0x200b && cp <= 0x200d) return 1;      /* zero-width */
  if (cp == 0x2060 || cp == 0xfeff || cp == 0x180e) return 1;
  return 0;
}

/* Decodes the (valid) UTF-8 in out[0..n) and checks every code point. Returns 0 if it is not valid. */
static int check_output(const char *out, size_t n)
{
  size_t i = 0;
  while (i < n) {
    uint8_t c = (uint8_t)out[i];
    uint32_t cp;
    size_t len;
    if (c < 0x80) { cp = c; len = 1; }
    else if ((c & 0xe0) == 0xc0) { cp = c & 0x1f; len = 2; }
    else if ((c & 0xf0) == 0xe0) { cp = c & 0x0f; len = 3; }
    else if ((c & 0xf8) == 0xf0) { cp = c & 0x07; len = 4; }
    else return 0;
    if (i + len > n) return 0;
    {
      size_t k;
      for (k = 1; k < len; k++) {
        uint8_t cc = (uint8_t)out[i + k];
        if ((cc & 0xc0) != 0x80) return 0;
        cp = (cp << 6) | (cc & 0x3f);
      }
    }
    SD_FUZZ_CHECK(!is_bad_cp(cp));
    i += len;
  }
  return 1;
}

int sd_fuzz_one(const uint8_t *data, size_t size)
{
  size_t n = size < SAN_MAX_IN ? size : SAN_MAX_IN;
  char *out;
  size_t out_len = 0;
  sd_err e;
  out = (char *)malloc(n * 3 + 4);
  if (!out) return 0;
  e = sd_text_sanitize_server((const char *)data, n, out, n * 3 + 4, &out_len);
  if (e == SD_OK) {
    SD_FUZZ_CHECK(out_len <= n * 3);
    SD_FUZZ_CHECK(check_output(out, out_len));
  }
  free(out);
  return 0;
}
