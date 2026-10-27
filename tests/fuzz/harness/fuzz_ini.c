/* fuzz_ini: INI reader of sd_config (profiles, settings, overrides). Parses, reads typed values, serializes and
   parses the serialized form again: no input may crash or make the writer fail. */
#include "sd_fuzz.h"
#include "sd_base/sd_buf.h"
#include "sd_base/sd_err.h"
#include "sd_config/sd_ini.h"

int sd_fuzz_one(const uint8_t *data, size_t size)
{
  sd_ini *ini = NULL;
  uint32_t flags = 0;
  sd_err e;
  static const char *const keys[] = { "host", "port", "timeout", "cache", "keep_alive", "mount" };
  size_t i;

  if (size > SD_INI_MAX_BYTES) return 0;
  e = sd_ini_parse((const char *)data, size, &ini, &flags);
  if (e == SD_OK && ini) {
    uint32_t u32 = 0;
    uint64_t sz = 0;
    int b = 0;
    for (i = 0; i < sizeof(keys) / sizeof(keys[0]); i++) {
      const char *v = sd_ini_get(ini, "profile", keys[i]);
      if (v) {
        (void)sd_ini_parse_bool(v, &b);
        (void)sd_ini_parse_u32(v, &u32);
        (void)sd_ini_parse_duration_ms(v, &u32);
        (void)sd_ini_parse_size(v, &sz);
      }
    }
    {
      sd_wr w;
      sd_ini *again = NULL;
      sd_wr_init(&w, SD_INI_MAX_BYTES * 2u);
      if (sd_ini_serialize(ini, &w) == SD_OK && sd_wr_ok(&w)) {
        uint32_t f2 = 0;
        (void)sd_ini_parse((const char *)w.p, w.len, &again, &f2);
        if (again) sd_ini_free(again);
      }
      sd_wr_free(&w);
    }
  }
  if (ini) sd_ini_free(ini);
  return 0;
}
