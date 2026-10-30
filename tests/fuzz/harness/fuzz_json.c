/* fuzz_json: strict JSON parser of sd_base (IPC requests, sd_json_parse with depth limit 32). */
#include "sd_fuzz.h"
#include "sd_base/sd_json.h"

static void walk(const sd_json *v, unsigned depth)
{
  size_t i, n;
  sd_json_type t;
  if (!v || depth > 64) return;
  t = sd_json_type_of(v);
  n = sd_json_count(v);
  if (t == SD_JSON_OBJECT) {
    (void)sd_json_get(v, "id");
    (void)sd_json_get_str(v, "method");
    (void)sd_json_get_int64(v, "version", NULL);
  }
  for (i = 0; i < n; i++) {
    const sd_json *c = sd_json_at(v, i);
    size_t len = 0;
    int64_t num = 0;
    if (t == SD_JSON_OBJECT) SD_FUZZ_CHECK(sd_json_key_at(v, i) != NULL);
    if (sd_json_str(c, &len)) SD_FUZZ_CHECK(len <= 1u << 20);
    (void)sd_json_int64(c, &num);
    walk(c, depth + 1);
  }
}

int sd_fuzz_one(const uint8_t *data, size_t size)
{
  sd_json *root = NULL;
  sd_err e = sd_json_parse((const char *)data, size, 32, &root);
  if (e == SD_OK) {
    SD_FUZZ_CHECK(root != NULL);
    walk(root, 0);
  }
  if (root) sd_json_free(root);
  return 0;
}
