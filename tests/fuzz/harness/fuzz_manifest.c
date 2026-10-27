/* fuzz_manifest: update manifest parser (sd_upd_manifest_parse, 04 section 12.1 and the signed text format), plus
   the date and version fields it reads. Signatures are not checked here: parsing must be safe on any bytes. */
#include "sd_fuzz.h"
#include "sd_base/sd_err.h"
#include "sd_update/sd_update.h"

int sd_fuzz_one(const uint8_t *data, size_t size)
{
  sd_upd_manifest *m;
  sd_upd_version ver;
  int64_t t = 0;

  if (size > 256u * 1024u) return 0;
  m = (sd_upd_manifest *)calloc(1, sizeof(*m));
  if (!m) return 0;
  (void)sd_upd_manifest_parse(data, size, m);
  free(m);
  (void)sd_upd_version_parse((const char *)data, size, &ver);
  (void)sd_upd_date_parse((const char *)data, size, 0, &t);
  (void)sd_upd_time_parse((const char *)data, size, &t);
  return 0;
}
