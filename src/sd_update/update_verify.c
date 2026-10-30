/* sd_update pure part (04 §9.2, §9.3; TM-R36, TM-R37, TM-R23): strict manifest and keyset parsing, the
 * signature chain, base64, dates and version comparison. No I/O and no clock: `now` is an argument.
 *
 * Syntax shared by both formats: printable ASCII (0x21..0x7E) and LF only; one record per line; fields
 * separated by exactly one space; the file ends with LF; the sig lines come last. The signed bytes are
 * exactly the bytes that were parsed (domain string || body), so nothing is re-serialized. */
#include <windows.h>
#include <string.h>

#include "sd_update/sd_update.h"
#include "sd_crypto/sd_crypto.h"
#include "sd_crypto/sd_ct.h"
#include "sd_base/sd_mem.h"
#include "update_internal.h"

/* ---- base64 (RFC 4648, canonical) ---- */

static int b64_val(char c)
{
  if (c >= 'A' && c <= 'Z') return c - 'A';
  if (c >= 'a' && c <= 'z') return c - 'a' + 26;
  if (c >= '0' && c <= '9') return c - '0' + 52;
  if (c == '+') return 62;
  if (c == '/') return 63;
  return -1;
}

int sd_upd_base64_decode(const char *s, size_t len, uint8_t *out, size_t cap)
{
  size_t i, o = 0;
  if (len == 0 || (len % 4) != 0)
    return -1;
  for (i = 0; i < len; i += 4) {
    int v[4], pad = 0;
    size_t k;
    for (k = 0; k < 4; k++) {
      char c = s[i + k];
      if (c == '=') {
        if (i + 4 != len || k < 2)          /* padding only at the very end, in the last two places */
          return -1;
        pad++;
        v[k] = 0;
      } else {
        if (pad)
          return -1;
        v[k] = b64_val(c);
        if (v[k] < 0)
          return -1;
      }
    }
    if (pad == 1 && (v[2] & 0x3) != 0)
      return -1;                            /* non-canonical: unused bits set */
    if (pad == 2 && (v[1] & 0xF) != 0)
      return -1;
    {
      uint8_t b[3];
      size_t n = 3 - (size_t)pad;
      b[0] = (uint8_t)((v[0] << 2) | (v[1] >> 4));
      b[1] = (uint8_t)(((v[1] & 0xF) << 4) | (v[2] >> 2));
      b[2] = (uint8_t)(((v[2] & 0x3) << 6) | v[3]);
      if (o + n > cap)
        return -1;
      memcpy(out + o, b, n);
      o += n;
    }
  }
  return (int)o;
}

/* ---- dates ---- */

static int64_t days_from_civil(int64_t y, unsigned m, unsigned d)
{
  int64_t era;
  unsigned yoe, doy, doe;
  y -= (m <= 2);
  era = (y >= 0 ? y : y - 399) / 400;
  yoe = (unsigned)(y - era * 400);
  doy = (153u * (m > 2 ? m - 3u : m + 9u) + 2u) / 5u + d - 1u;
  doe = yoe * 365u + yoe / 4u - yoe / 100u + doy;
  return era * 146097 + (int64_t)doe - 719468;
}

static int is_leap(unsigned y)
{
  return (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
}

static int digits(const char *s, size_t n, unsigned *out)
{
  size_t i;
  unsigned v = 0;
  if (n == 0)
    return 0;
  for (i = 0; i < n; i++) {
    if (s[i] < '0' || s[i] > '9')
      return 0;
    v = v * 10u + (unsigned)(s[i] - '0');
  }
  *out = v;
  return 1;
}

static sd_upd_res date_fields(const char *s, unsigned *y, unsigned *mo, unsigned *d)
{
  static const unsigned mdays[12] = { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
  if (s[4] != '-' || s[7] != '-')
    return SD_UPD_E_FORMAT;
  if (!digits(s, 4, y) || !digits(s + 5, 2, mo) || !digits(s + 8, 2, d))
    return SD_UPD_E_FORMAT;
  if (*y < 1970 || *y > 9999 || *mo < 1 || *mo > 12 || *d < 1)
    return SD_UPD_E_FORMAT;
  if (*d > mdays[*mo - 1] + ((*mo == 2 && is_leap(*y)) ? 1u : 0u))
    return SD_UPD_E_FORMAT;
  return SD_UPD_OK;
}

sd_upd_res sd_upd_date_parse(const char *s, size_t len, int end_of_day, int64_t *unix_s)
{
  unsigned y, mo, d;
  sd_upd_res r;
  if (s == NULL || unix_s == NULL || len != 10)
    return SD_UPD_E_FORMAT;
  if ((r = date_fields(s, &y, &mo, &d)) != SD_UPD_OK)
    return r;
  *unix_s = days_from_civil(y, mo, d) * 86400 + (end_of_day ? 86399 : 0);
  return SD_UPD_OK;
}

sd_upd_res sd_upd_time_parse(const char *s, size_t len, int64_t *unix_s)
{
  unsigned y, mo, d, hh, mi, ss;
  sd_upd_res r;
  if (s == NULL || unix_s == NULL || len != 20)
    return SD_UPD_E_FORMAT;
  if (s[10] != 'T' || s[13] != ':' || s[16] != ':' || s[19] != 'Z')
    return SD_UPD_E_FORMAT;
  if ((r = date_fields(s, &y, &mo, &d)) != SD_UPD_OK)
    return r;
  if (!digits(s + 11, 2, &hh) || !digits(s + 14, 2, &mi) || !digits(s + 17, 2, &ss))
    return SD_UPD_E_FORMAT;
  if (hh > 23 || mi > 59 || ss > 60)
    return SD_UPD_E_FORMAT;
  *unix_s = days_from_civil(y, mo, d) * 86400 + (int64_t)hh * 3600 + (int64_t)mi * 60 + ss;
  return SD_UPD_OK;
}

/* ---- versions ---- */

sd_upd_res sd_upd_version_parse(const char *s, size_t len, sd_upd_version *out)
{
  size_t i = 0;
  memset(out, 0, sizeof(*out));
  if (s == NULL || len == 0 || len > 31)
    return SD_UPD_E_FORMAT;
  for (;;) {
    size_t st = i, k;
    uint32_t v = 0;
    if (out->n == 4)
      return SD_UPD_E_FORMAT;
    while (i < len && s[i] != '.')
      i++;
    if (i == st || i - st > 5)
      return SD_UPD_E_FORMAT;
    for (k = st; k < i; k++) {
      if (s[k] < '0' || s[k] > '9')
        return SD_UPD_E_FORMAT;
      v = v * 10u + (uint32_t)(s[k] - '0');
    }
    if (v > 65535u)
      return SD_UPD_E_FORMAT;
    out->part[out->n++] = v;
    if (i == len)
      break;
    i++;                                    /* the '.' */
    if (i == len)
      return SD_UPD_E_FORMAT;               /* trailing dot */
  }
  return SD_UPD_OK;
}

int sd_upd_version_cmp(const sd_upd_version *a, const sd_upd_version *b)
{
  uint32_t i;
  for (i = 0; i < 4; i++) {
    uint32_t x = i < a->n ? a->part[i] : 0, y = i < b->n ? b->part[i] : 0;
    if (x != y)
      return x < y ? -1 : 1;
  }
  return 0;
}

/* ---- keys ---- */

void sd_upd_key_id(const uint8_t pub[32], uint8_t id[8])
{
  uint8_t h[32];
  sd_hash(SD_HASH_SHA256, pub, 32, h);
  memcpy(id, h, 8);
}

/* ---- shared record syntax ---- */

sd_upd_res upd_check_text(const uint8_t *data, size_t len)
{
  size_t i;
  if (len == 0 || data[len - 1] != '\n')
    return SD_UPD_E_FORMAT;
  for (i = 0; i < len; i++) {
    uint8_t c = data[i];
    if (c != '\n' && (c < 0x21 || c > 0x7E) && c != ' ')
      return SD_UPD_E_FORMAT;
  }
  return SD_UPD_OK;
}

/* Next line [*start, *end) without its LF; advances *pos. Returns 0 at the end. */
int upd_next_line(const uint8_t *data, size_t len, size_t *pos, size_t *start, size_t *end)
{
  size_t i = *pos;
  if (i >= len)
    return 0;
  *start = i;
  while (i < len && data[i] != '\n')
    i++;
  *end = i;
  *pos = (i < len) ? i + 1 : i;
  return 1;
}

/* Splits [s, e) on single spaces into at most maxf fields. Empty fields are errors. -1 on error. */
int upd_split(const uint8_t *s, const uint8_t *e, const uint8_t **f, size_t *fl, size_t maxf)
{
  size_t n = 0;
  const uint8_t *p = s;
  if (s == e)
    return -1;
  for (;;) {
    const uint8_t *q = p;
    if (n == maxf)
      return -1;
    while (q < e && *q != ' ')
      q++;
    if (q == p)
      return -1;
    f[n] = p;
    fl[n] = (size_t)(q - p);
    n++;
    if (q == e)
      break;
    p = q + 1;
    if (p == e)
      return -1;
  }
  return (int)n;
}

int upd_field_is(const uint8_t *f, size_t fl, const char *lit)
{
  size_t n = strlen(lit);
  return fl == n && memcmp(f, lit, n) == 0;
}

sd_upd_res upd_copy_field(const uint8_t *f, size_t fl, char *out, size_t cap)
{
  if (fl + 1 > cap)
    return SD_UPD_E_FORMAT;
  memcpy(out, f, fl);
  out[fl] = '\0';
  return SD_UPD_OK;
}

sd_upd_res upd_parse_u64(const uint8_t *f, size_t fl, uint64_t *out, int max_digits)
{
  uint64_t v = 0;
  size_t i;
  if (fl == 0 || (int)fl > max_digits)
    return SD_UPD_E_FORMAT;
  if (fl > 1 && f[0] == '0')
    return SD_UPD_E_FORMAT;                 /* canonical decimal only */
  for (i = 0; i < fl; i++) {
    if (f[i] < '0' || f[i] > '9')
      return SD_UPD_E_FORMAT;
    v = v * 10u + (uint64_t)(f[i] - '0');
  }
  *out = v;
  return SD_UPD_OK;
}

sd_upd_res upd_parse_hex(const uint8_t *f, size_t fl, uint8_t *out, size_t nbytes)
{
  size_t i;
  if (fl != nbytes * 2)
    return SD_UPD_E_FORMAT;
  for (i = 0; i < fl; i++) {
    uint8_t c = f[i], v;
    if (c >= '0' && c <= '9') v = (uint8_t)(c - '0');
    else if (c >= 'a' && c <= 'f') v = (uint8_t)(c - 'a' + 10);
    else return SD_UPD_E_FORMAT;            /* lowercase only */
    if ((i & 1) == 0) out[i / 2] = (uint8_t)(v << 4);
    else out[i / 2] |= v;
  }
  return SD_UPD_OK;
}

sd_upd_res upd_msg_verify(const uint8_t sig[64], const uint8_t pub[32], const char *domain,
                          const uint8_t *data, size_t len)
{
  size_t dl = strlen(domain), total = dl + len;
  uint8_t *m;
  sd_err e;
  if (total < dl)
    return SD_UPD_E_TOO_LARGE;
  m = (uint8_t *)sd_alloc(total ? total : 1);
  if (m == NULL)
    return SD_UPD_E_NO_MEMORY;
  memcpy(m, domain, dl);
  if (len)
    memcpy(m + dl, data, len);
  e = sd_ed25519_verify(sig, pub, m, total);
  sd_free(m);
  return e == SD_OK ? SD_UPD_OK : SD_UPD_E_SIGNATURE;
}

static sd_upd_res parse_key_id(const uint8_t *f, size_t fl, uint8_t id[8])
{
  return upd_parse_hex(f, fl, id, 8);
}

static sd_upd_res parse_pub_b64(const uint8_t *f, size_t fl, uint8_t pub[32])
{
  char tmp[48];
  int n;
  if (fl != 44)
    return SD_UPD_E_FORMAT;
  memcpy(tmp, f, fl);
  n = sd_upd_base64_decode(tmp, fl, pub, 32);
  return n == 32 ? SD_UPD_OK : SD_UPD_E_FORMAT;
}

static sd_upd_res parse_sig_fields(const uint8_t **f, const size_t *fl, int n, uint8_t key_id[8], uint8_t sig[64])
{
  char b64[96];
  int dec;
  if (n != 4 || !upd_field_is(f[0], fl[0], "sig") || !upd_field_is(f[1], fl[1], "ed25519"))
    return SD_UPD_E_FORMAT;
  if (parse_key_id(f[2], fl[2], key_id) != SD_UPD_OK)
    return SD_UPD_E_FORMAT;
  if (fl[3] != 88)
    return SD_UPD_E_FORMAT;
  memcpy(b64, f[3], fl[3]);
  dec = sd_upd_base64_decode(b64, fl[3], sig, 64);
  return dec == 64 ? SD_UPD_OK : SD_UPD_E_FORMAT;
}

static sd_upd_res parse_channel(const uint8_t *f, size_t fl, char *out, size_t cap)
{
  if (upd_field_is(f, fl, "stable") || upd_field_is(f, fl, "beta"))
    return upd_copy_field(f, fl, out, cap);
  return SD_UPD_E_FORMAT;
}

static sd_upd_res parse_url(const uint8_t *f, size_t fl, char *out, size_t cap)
{
  if (!((fl >= 8 && memcmp(f, "https://", 8) == 0) || (fl >= 7 && memcmp(f, "http://", 7) == 0)))
    return SD_UPD_E_FORMAT;
  return upd_copy_field(f, fl, out, cap);
}

static int file_name_ok(const uint8_t *f, size_t fl)
{
  size_t i;
  if (fl == 0 || fl > 127 || f[0] == '.')
    return 0;
  for (i = 0; i < fl; i++) {
    uint8_t c = f[i];
    if (c == '\\' || c == '/' || c == ':' || c == '*' || c == '?' || c == '"' || c == '<' || c == '>' || c == '|')
      return 0;
  }
  return 1;
}

/* sha256:<64 lowercase hex> or sha512:<128 lowercase hex> */
static sd_upd_res parse_digest(const uint8_t *f, size_t fl, int *alg, uint8_t *digest)
{
  if (fl > 7 && memcmp(f, "sha256:", 7) == 0) {
    *alg = 256;
    return upd_parse_hex(f + 7, fl - 7, digest, 32);
  }
  if (fl > 7 && memcmp(f, "sha512:", 7) == 0) {
    *alg = 512;
    return upd_parse_hex(f + 7, fl - 7, digest, 64);
  }
  return SD_UPD_E_FORMAT;
}

/* ---- manifest syntax ---- */

enum { MK_PRODUCT, MK_CHANNEL, MK_KEYSET, MK_SERIAL, MK_VERSION, MK_RELEASED, MK_EXPIRES, MK_COUNT };

sd_upd_res sd_upd_manifest_parse(const uint8_t *data, size_t len, sd_upd_manifest *m)
{
  size_t pos = 0, s, e;
  int line_no = 0, seen_sig = 0, have[MK_COUNT], i;
  size_t sig_start = 0;
  const uint8_t *f[8];
  size_t fl[8];
  sd_upd_res r;

  if (m == NULL || data == NULL)
    return SD_UPD_E_INVALID;
  if (len > SD_UPD_MANIFEST_MAX)
    return SD_UPD_E_TOO_LARGE;
  if ((r = upd_check_text(data, len)) != SD_UPD_OK)
    return r;
  memset(m, 0, sizeof(*m));
  memset(have, 0, sizeof(have));

  while (upd_next_line(data, len, &pos, &s, &e)) {
    const uint8_t *line = data + s;
    size_t ll = e - s;
    int n;
    line_no++;
    if (ll == 0 || ll > SD_UPD_LINE_MAX || seen_sig)
      return SD_UPD_E_FORMAT;               /* sig must be the last record */

    if (line_no == 1) {
      if ((n = upd_split(line, line + ll, f, fl, 8)) != 2 || !upd_field_is(f[0], fl[0], "shelldrive-manifest"))
        return SD_UPD_E_FORMAT;
      if (upd_field_is(f[1], fl[1], "1"))
        continue;
      return (fl[1] == 1 && f[1][0] >= '0' && f[1][0] <= '9') ? SD_UPD_E_FORMAT_VERSION : SD_UPD_E_FORMAT;
    }

    n = upd_split(line, line + ll, f, fl, 8);
    if (n < 2)
      return SD_UPD_E_FORMAT;

    if (upd_field_is(f[0], fl[0], "product")) {
      char prod[64];
      if (n != 2 || have[MK_PRODUCT]) return SD_UPD_E_FORMAT;
      have[MK_PRODUCT] = 1;
      if (upd_copy_field(f[1], fl[1], prod, sizeof(prod)) != SD_UPD_OK || strcmp(prod, SD_UPD_PRODUCT) != 0)
        return SD_UPD_E_PRODUCT;
    } else if (upd_field_is(f[0], fl[0], "channel")) {
      if (n != 2 || have[MK_CHANNEL]) return SD_UPD_E_FORMAT;
      have[MK_CHANNEL] = 1;
      if (parse_channel(f[1], fl[1], m->channel, sizeof(m->channel)) != SD_UPD_OK) return SD_UPD_E_FORMAT;
    } else if (upd_field_is(f[0], fl[0], "keyset")) {
      if (n != 2 || have[MK_KEYSET]) return SD_UPD_E_FORMAT;
      have[MK_KEYSET] = 1;
      if (upd_parse_u64(f[1], fl[1], &m->keyset, 10) != SD_UPD_OK || m->keyset == 0) return SD_UPD_E_FORMAT;
    } else if (upd_field_is(f[0], fl[0], "serial")) {
      if (n != 2 || have[MK_SERIAL]) return SD_UPD_E_FORMAT;
      have[MK_SERIAL] = 1;
      if (upd_parse_u64(f[1], fl[1], &m->serial, 20) != SD_UPD_OK || m->serial == 0) return SD_UPD_E_FORMAT;
    } else if (upd_field_is(f[0], fl[0], "version")) {
      if (n != 2 || have[MK_VERSION]) return SD_UPD_E_FORMAT;
      have[MK_VERSION] = 1;
      if (upd_copy_field(f[1], fl[1], m->version_str, sizeof(m->version_str)) != SD_UPD_OK) return SD_UPD_E_FORMAT;
      if (sd_upd_version_parse(m->version_str, fl[1], &m->version) != SD_UPD_OK) return SD_UPD_E_FORMAT;
    } else if (upd_field_is(f[0], fl[0], "released")) {
      if (n != 2 || have[MK_RELEASED]) return SD_UPD_E_FORMAT;
      have[MK_RELEASED] = 1;
      if (sd_upd_time_parse((const char *)f[1], fl[1], &m->released) != SD_UPD_OK) return SD_UPD_E_FORMAT;
    } else if (upd_field_is(f[0], fl[0], "expires")) {
      if (n != 2 || have[MK_EXPIRES]) return SD_UPD_E_FORMAT;
      have[MK_EXPIRES] = 1;
      if (sd_upd_time_parse((const char *)f[1], fl[1], &m->expires) != SD_UPD_OK) return SD_UPD_E_FORMAT;
    } else if (upd_field_is(f[0], fl[0], "notes")) {
      if (n != 2 || m->notes[0] != '\0') return SD_UPD_E_FORMAT;
      if (parse_url(f[1], fl[1], m->notes, sizeof(m->notes)) != SD_UPD_OK) return SD_UPD_E_FORMAT;
    } else if (upd_field_is(f[0], fl[0], "min-os")) {
      sd_upd_minos *x;
      if (n != 3 || m->nminos == SD_UPD_MAX_MINOS) return SD_UPD_E_FORMAT;
      x = &m->minos[m->nminos];
      if (upd_copy_field(f[1], fl[1], x->flavour, sizeof(x->flavour)) != SD_UPD_OK) return SD_UPD_E_FORMAT;
      if (sd_upd_version_parse((const char *)f[2], fl[2], &x->version) != SD_UPD_OK) return SD_UPD_E_FORMAT;
      m->nminos++;
    } else if (upd_field_is(f[0], fl[0], "file")) {
      /* file <id> <name> <size> <alg>:<hex> */
      sd_upd_file *x;
      uint64_t size;
      if (n != 5 || m->nfiles == SD_UPD_MAX_FILES) return SD_UPD_E_FORMAT;
      if (fl[1] == 0 || fl[1] >= sizeof(x->id)) return SD_UPD_E_FORMAT;
      if (!file_name_ok(f[2], fl[2])) return SD_UPD_E_FORMAT;
      if (upd_parse_u64(f[3], fl[3], &size, 12) != SD_UPD_OK) return SD_UPD_E_FORMAT;
      if (size == 0 || size > SD_UPD_MAX_FILE_BYTES) return SD_UPD_E_TOO_LARGE;
      x = &m->files[m->nfiles];
      memset(x, 0, sizeof(*x));
      memcpy(x->id, f[1], fl[1]);
      memcpy(x->name, f[2], fl[2]);
      x->size = size;
      if (parse_digest(f[4], fl[4], &x->hash_alg, x->digest) != SD_UPD_OK) return SD_UPD_E_FORMAT;
      m->nfiles++;
    } else if (upd_field_is(f[0], fl[0], "dokany")) {
      /* dokany <version> <arch> <name> <size> <alg>:<hex>  ->  file "dokany-<arch>" */
      sd_upd_file *x;
      sd_upd_version dv;
      uint64_t size;
      if (n != 6 || m->nfiles == SD_UPD_MAX_FILES) return SD_UPD_E_FORMAT;
      if (sd_upd_version_parse((const char *)f[1], fl[1], &dv) != SD_UPD_OK) return SD_UPD_E_FORMAT;
      if (!(upd_field_is(f[2], fl[2], "x86") || upd_field_is(f[2], fl[2], "x64") || upd_field_is(f[2], fl[2], "arm64")))
        return SD_UPD_E_FORMAT;
      if (!file_name_ok(f[3], fl[3])) return SD_UPD_E_FORMAT;
      if (upd_parse_u64(f[4], fl[4], &size, 12) != SD_UPD_OK || size == 0 || size > SD_UPD_MAX_FILE_BYTES)
        return SD_UPD_E_FORMAT;
      if (m->dokany_version[0] != '\0') return SD_UPD_E_FORMAT;   /* one dokany line */
      if (upd_copy_field(f[1], fl[1], m->dokany_version, sizeof(m->dokany_version)) != SD_UPD_OK) return SD_UPD_E_FORMAT;
      x = &m->files[m->nfiles];
      memset(x, 0, sizeof(*x));
      memcpy(x->id, "dokany-", 7);
      memcpy(x->id + 7, f[2], fl[2]);
      memcpy(x->name, f[3], fl[3]);
      x->size = size;
      if (parse_digest(f[5], fl[5], &x->hash_alg, x->digest) != SD_UPD_OK) return SD_UPD_E_FORMAT;
      m->nfiles++;
    } else if (upd_field_is(f[0], fl[0], "base")) {
      if (n != 2 || m->nbases == SD_UPD_MAX_BASES) return SD_UPD_E_FORMAT;
      if (parse_url(f[1], fl[1], m->bases[m->nbases], sizeof(m->bases[0])) != SD_UPD_OK) return SD_UPD_E_FORMAT;
      m->nbases++;
    } else if (upd_field_is(f[0], fl[0], "dokany-deny")) {
      /* dokany-deny <min>-<max> <reason-id> (TM-R23) */
      sd_upd_deny *x;
      size_t dash = 0;
      if (n != 3 || m->ndeny == SD_UPD_MAX_DENY) return SD_UPD_E_FORMAT;
      while (dash < fl[1] && f[1][dash] != '-')
        dash++;
      if (dash == fl[1] || dash == 0 || dash + 1 >= fl[1])
        return SD_UPD_E_FORMAT;
      x = &m->deny[m->ndeny];
      memset(x, 0, sizeof(*x));
      if (sd_upd_version_parse((const char *)f[1], dash, &x->min) != SD_UPD_OK) return SD_UPD_E_FORMAT;
      if (sd_upd_version_parse((const char *)f[1] + dash + 1, fl[1] - dash - 1, &x->max) != SD_UPD_OK)
        return SD_UPD_E_FORMAT;
      if (upd_copy_field(f[2], fl[2], x->reason, sizeof(x->reason)) != SD_UPD_OK) return SD_UPD_E_FORMAT;
      m->ndeny++;
    } else if (upd_field_is(f[0], fl[0], "sig")) {
      seen_sig = 1;
      sig_start = s;
      if (parse_sig_fields(f, fl, n, m->sig_key_id, m->sig) != SD_UPD_OK)
        return SD_UPD_E_FORMAT;
    } else {
      /* unknown keys are ignored (forward compatible, 04 §9.2) */
    }
  }

  for (i = 0; i < MK_COUNT; i++) {
    if (!have[i])
      return SD_UPD_E_FORMAT;
  }
  if (line_no < 2 || !seen_sig || m->nbases == 0 || m->nfiles == 0)
    return SD_UPD_E_FORMAT;
  m->sig_offset = (uint32_t)sig_start;
  return SD_UPD_OK;
}

/* ---- keyset ---- */

/* Pass 2 of the keyset: every sig line in the trailing block. A sig by a current root must verify. */
static sd_upd_res keyset_check_sigs(const uint8_t *data, size_t len, size_t body_len, const sd_upd_root *roots,
                                    uint32_t nroots, int *rotated, uint32_t *valid_by_root)
{
  size_t p = body_len, s, e;
  while (upd_next_line(data, len, &p, &s, &e)) {
    const uint8_t *f[8];
    size_t fl[8];
    uint8_t sig[64], kid[8];
    uint32_t i;
    int n = upd_split(data + s, data + e, f, fl, 8);
    if (parse_sig_fields(f, fl, n, kid, sig) != SD_UPD_OK)
      return SD_UPD_E_FORMAT;
    for (i = 0; i < nroots; i++) {
      if (!sd_ct_memeq(roots[i].id, kid, 8))
        continue;
      if (upd_msg_verify(sig, roots[i].pub, SD_UPD_DOMAIN_KEYSET, data, body_len) != SD_UPD_OK)
        return SD_UPD_E_KEYSET_SIGNATURE;
      valid_by_root[i]++;
    }
  }
  (void)rotated;
  return SD_UPD_OK;
}

/* check_sigs = 0 parses a keyset this client stored itself (state\keyset, written only after verification):
   the format and the records are checked, the signatures are not (the roots it was verified with are in
   state\roots, which may have changed since). */
static sd_upd_res keyset_core(const uint8_t *data, size_t len, const sd_upd_root *roots, uint32_t nroots,
                              uint64_t stored_version, int check_sigs, sd_upd_keyset *ks)
{
  size_t pos = 0, s, e, body_len = 0;
  int line_no = 0, have_product = 0, have_version = 0, rotated = 0, nsig = 0;
  uint32_t nroot_lines = 0, i;
  uint32_t valid_by_root[SD_UPD_MAX_ROOTS];
  uint8_t revoke_ids[SD_UPD_MAX_KEYS][8];
  uint32_t nrevoke = 0;
  sd_upd_root new_roots[SD_UPD_MAX_ROOTS];
  sd_upd_res r;

  if (ks == NULL || roots == NULL || nroots == 0 || nroots > SD_UPD_MAX_ROOTS)
    return SD_UPD_E_INVALID;
  if (len > SD_UPD_KEYSET_MAX)
    return SD_UPD_E_TOO_LARGE;
  if ((r = upd_check_text(data, len)) != SD_UPD_OK)
    return r;
  memset(ks, 0, sizeof(*ks));
  memset(valid_by_root, 0, sizeof(valid_by_root));

  /* The signed body: every line up to the first sig line. Sig lines must form the trailing block. */
  {
    int in_sig = 0;
    size_t p = 0;
    while (upd_next_line(data, len, &p, &s, &e)) {
      int is_sig = (e - s >= 4 && memcmp(data + s, "sig ", 4) == 0);
      if (is_sig) {
        if (!in_sig) { in_sig = 1; body_len = s; }
        nsig++;
      } else if (in_sig) {
        return SD_UPD_E_FORMAT;
      }
    }
    if (!in_sig)
      body_len = len;
  }
  if (nsig == 0)
    return SD_UPD_E_KEYSET_SIGNATURE;

  /* Pass 1: records inside the signed body. */
  pos = 0;
  while (upd_next_line(data, body_len, &pos, &s, &e)) {
    const uint8_t *f[8];
    size_t fl[8];
    int n;
    line_no++;
    if (e == s || e - s > SD_UPD_LINE_MAX)
      return SD_UPD_E_FORMAT;
    n = upd_split(data + s, data + e, f, fl, 8);
    if (n < 1)
      return SD_UPD_E_FORMAT;
    if (line_no == 1) {
      if (n != 2 || !upd_field_is(f[0], fl[0], "shelldrive-keyset"))
        return SD_UPD_E_FORMAT;
      if (upd_field_is(f[1], fl[1], "1"))
        continue;
      return (fl[1] == 1 && f[1][0] >= '0' && f[1][0] <= '9') ? SD_UPD_E_FORMAT_VERSION : SD_UPD_E_FORMAT;
    }
    if (upd_field_is(f[0], fl[0], "product")) {
      char prod[64];
      if (n != 2 || have_product) return SD_UPD_E_FORMAT;
      have_product = 1;
      if (upd_copy_field(f[1], fl[1], prod, sizeof(prod)) != SD_UPD_OK || strcmp(prod, SD_UPD_PRODUCT) != 0)
        return SD_UPD_E_PRODUCT;
    } else if (upd_field_is(f[0], fl[0], "version")) {
      if (n != 2 || have_version) return SD_UPD_E_FORMAT;
      have_version = 1;
      if (upd_parse_u64(f[1], fl[1], &ks->version, 10) != SD_UPD_OK || ks->version == 0) return SD_UPD_E_FORMAT;
    } else if (upd_field_is(f[0], fl[0], "issued")) {
      int64_t t;
      if (n != 2 || sd_upd_time_parse((const char *)f[1], fl[1], &t) != SD_UPD_OK) return SD_UPD_E_FORMAT;
    } else if (upd_field_is(f[0], fl[0], "key")) {
      /* key <key-id> <stable|beta> <pubkey-base64> <from YYYY-MM-DD> <to YYYY-MM-DD> */
      sd_upd_keyset_key *k;
      uint8_t want[8];
      if (n != 6 || ks->nkeys == SD_UPD_MAX_KEYS) return SD_UPD_E_FORMAT;
      k = &ks->keys[ks->nkeys];
      memset(k, 0, sizeof(*k));
      if (parse_key_id(f[1], fl[1], k->id) != SD_UPD_OK) return SD_UPD_E_FORMAT;
      if (parse_channel(f[2], fl[2], k->channel, sizeof(k->channel)) != SD_UPD_OK) return SD_UPD_E_FORMAT;
      if (parse_pub_b64(f[3], fl[3], k->pub) != SD_UPD_OK) return SD_UPD_E_FORMAT;
      if (sd_upd_date_parse((const char *)f[4], fl[4], 0, &k->valid_from) != SD_UPD_OK) return SD_UPD_E_FORMAT;
      if (sd_upd_date_parse((const char *)f[5], fl[5], 1, &k->valid_to) != SD_UPD_OK) return SD_UPD_E_FORMAT;
      if (k->valid_to < k->valid_from) return SD_UPD_E_FORMAT;
      sd_upd_key_id(k->pub, want);
      if (!sd_ct_memeq(want, k->id, 8)) return SD_UPD_E_FORMAT;   /* the id must be the key's id */
      ks->nkeys++;
    } else if (upd_field_is(f[0], fl[0], "root")) {
      /* root <key-id> <pubkey-base64>: a new root set (both current roots must sign) */
      sd_upd_root *rt;
      uint8_t want[8];
      if (n != 3 || nroot_lines == SD_UPD_MAX_ROOTS) return SD_UPD_E_FORMAT;
      rt = &new_roots[nroot_lines];
      if (parse_key_id(f[1], fl[1], rt->id) != SD_UPD_OK) return SD_UPD_E_FORMAT;
      if (parse_pub_b64(f[2], fl[2], rt->pub) != SD_UPD_OK) return SD_UPD_E_FORMAT;
      sd_upd_key_id(rt->pub, want);
      if (!sd_ct_memeq(want, rt->id, 8)) return SD_UPD_E_FORMAT;
      nroot_lines++;
      rotated = 1;
    } else if (upd_field_is(f[0], fl[0], "revoke")) {
      /* revoke <key-id> <reason-id>: applied after all key lines are read */
      if (n != 3 || nrevoke == SD_UPD_MAX_KEYS) return SD_UPD_E_FORMAT;
      if (parse_key_id(f[1], fl[1], revoke_ids[nrevoke]) != SD_UPD_OK) return SD_UPD_E_FORMAT;
      nrevoke++;
    }
    /* unknown records are ignored */
  }
  if (line_no < 2 || !have_product || !have_version)
    return SD_UPD_E_FORMAT;
  if (rotated && nroot_lines == 0)
    return SD_UPD_E_FORMAT;

  for (i = 0; i < nrevoke; i++) {
    uint32_t k;
    for (k = 0; k < ks->nkeys; k++) {
      if (sd_ct_memeq(ks->keys[k].id, revoke_ids[i], 8))
        ks->keys[k].revoked = 1;
    }
  }

  /* Pass 2: signatures by the current roots over the body. */
  if (check_sigs) {
    if ((r = keyset_check_sigs(data, len, body_len, roots, nroots, &rotated, valid_by_root)) != SD_UPD_OK)
      return r;
    if (rotated) {
      for (i = 0; i < nroots; i++) {
        if (valid_by_root[i] == 0)
          return SD_UPD_E_KEYSET_SIGNATURE;   /* rotation needs both current roots */
      }
    } else {
      int any = 0;
      for (i = 0; i < nroots; i++) {
        if (valid_by_root[i])
          any = 1;
      }
      if (!any)
        return SD_UPD_E_KEYSET_SIGNATURE;
    }
  }
  if (rotated) {
    ks->rotated_roots = 1;
    ks->nroots = nroot_lines;
    memcpy(ks->roots, new_roots, nroot_lines * sizeof(sd_upd_root));
  } else {
    ks->nroots = nroots;
    memcpy(ks->roots, roots, nroots * sizeof(sd_upd_root));
  }
  if (ks->version < stored_version)
    return SD_UPD_E_KEYSET_ROLLBACK;
  return SD_UPD_OK;
}

sd_upd_res sd_upd_keyset_verify(const uint8_t *data, size_t len, const sd_upd_root *roots, uint32_t nroots,
                                uint64_t stored_version, sd_upd_keyset *ks)
{
  if (roots == NULL || nroots == 0 || nroots > SD_UPD_MAX_ROOTS)
    return SD_UPD_E_INVALID;
  return keyset_core(data, len, roots, nroots, stored_version, 1, ks);
}

sd_upd_res upd_keyset_load_stored(const uint8_t *data, size_t len, const sd_upd_root *roots, uint32_t nroots,
                                  sd_upd_keyset *ks)
{
  if (roots == NULL || nroots == 0 || nroots > SD_UPD_MAX_ROOTS)
    return SD_UPD_E_INVALID;
  return keyset_core(data, len, roots, nroots, 0, 0, ks);
}

/* ---- manifest verification ---- */

sd_upd_res sd_upd_manifest_verify(const uint8_t *data, size_t len, const sd_upd_manifest *m,
                                  const sd_upd_keyset *ks, const char *expected_channel, int64_t now,
                                  uint64_t last_serial)
{
  const sd_upd_keyset_key *key = NULL;
  uint32_t i;
  int64_t max_days;
  sd_upd_res r;

  if (data == NULL || m == NULL || ks == NULL || expected_channel == NULL)
    return SD_UPD_E_INVALID;
  if (m->sig_offset > len)
    return SD_UPD_E_FORMAT;
  if (m->keyset > ks->version)
    return SD_UPD_E_KEYSET_NEEDED;

  /* The signing key: listed in the keyset with this id, authorized for the manifest's channel (TM-R37). */
  for (i = 0; i < ks->nkeys; i++) {
    if (sd_ct_memeq(ks->keys[i].id, m->sig_key_id, 8) && strcmp(ks->keys[i].channel, m->channel) == 0) {
      key = &ks->keys[i];
      break;
    }
  }
  if (key == NULL)
    return SD_UPD_E_UNKNOWN_KEY;
  if (key->revoked)
    return SD_UPD_E_KEY_REVOKED;
  if (now < key->valid_from || now > key->valid_to)
    return SD_UPD_E_KEY_EXPIRED;
  if ((r = upd_msg_verify(m->sig, key->pub, SD_UPD_DOMAIN_MANIFEST, data, m->sig_offset)) != SD_UPD_OK)
    return r;

  if (strcmp(m->channel, expected_channel) != 0)
    return SD_UPD_E_CHANNEL_MISMATCH;
  if (m->expires <= m->released)
    return SD_UPD_E_FORMAT;
  if (now >= m->expires)
    return SD_UPD_E_EXPIRED;                 /* TM-R36: a frozen mirror cannot hide a fix forever */
  max_days = strcmp(m->channel, "beta") == 0 ? SD_UPD_BETA_MAX_DAYS : SD_UPD_STABLE_MAX_DAYS;
  if (m->expires - m->released > max_days * 86400)
    return SD_UPD_E_FRESHNESS;
  if (m->serial < last_serial)
    return SD_UPD_E_ROLLBACK;                /* anti-rollback per channel (TM-R37) */
  return SD_UPD_OK;
}
