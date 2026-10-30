/* Payload table signature (docs/design/04 §6.1, §9.3; TM-R38, T-71). See setup_payload_sig.h.
 *
 * Fail closed: any malformed input, unknown key, wrong channel, revoked or out-of-date key, or a signature that
 * does not verify returns an error, and the stub refuses to unpack. Only sd_crypto (sd_ed25519_verify,
 * sd_hash) is used, which the stub may link (no CNG, TM-R33). */
#include <windows.h>
#include <string.h>

#include "sd_crypto/sd_crypto.h"
#include "setup_payload_sig.h"

#ifndef SD_SETUP_BUILD_CHANNEL
#define SD_SETUP_BUILD_CHANNEL "stable"
#endif

/* The keyring compiled into the stub: the keys of the build's keyset (installer/keys/keyset.txt, §9.3). The file
   in the repository holds only a revoked placeholder, so no payload verifies until the release pipeline
   generates it. */
static const sd_setup_psig_key k_builtin_keys[] = {
#include "setup_keyring.inc"
};

static const char k_header_magic[] = "shelldrive-payload-table 1\n";
static const char k_header_product[] = "product " SD_SETUP_PSIG_PRODUCT "\n";
static const char k_sig_prefix[] = "sig ed25519 ";

/* ---- base64 (RFC 4648, canonical, padded) ---- */

static int b64_val(char c)
{
  if (c >= 'A' && c <= 'Z') return c - 'A';
  if (c >= 'a' && c <= 'z') return c - 'a' + 26;
  if (c >= '0' && c <= '9') return c - '0' + 52;
  if (c == '+') return 62;
  if (c == '/') return 63;
  return -1;
}

int sd_setup_psig_b64_decode(const char *s, size_t len, uint8_t *out, size_t cap)
{
  size_t i, o = 0;
  if (s == NULL || out == NULL || len == 0 || (len % 4) != 0)
    return -1;
  for (i = 0; i < len; i += 4) {
    int v[4], pad = 0;
    size_t k;
    for (k = 0; k < 4; k++) {
      char c = s[i + k];
      if (c == '=') {
        if (i + 4 != len || k < 2)
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
      return -1;
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

static int hex_val(char c)
{
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  return -1;
}

/* ---- table syntax ---- */

/* Printable ASCII and LF only, LF-terminated. */
static int table_text_ok(const uint8_t *t, size_t n)
{
  size_t i;
  if (n == 0 || t[n - 1] != '\n')
    return 0;
  for (i = 0; i < n; i++) {
    if (t[i] != '\n' && (t[i] < 0x21 || t[i] > 0x7E) && t[i] != ' ')
      return 0;
  }
  return 1;
}

/* Returns the line length (without LF) starting at *pos and advances *pos past the LF; 0 at the end. */
static size_t next_line(const uint8_t *t, size_t n, size_t *pos, const uint8_t **line)
{
  size_t s = *pos, e = s;
  if (s >= n)
    return 0;
  while (e < n && t[e] != '\n')
    e++;
  *line = t + s;
  *pos = (e < n) ? e + 1 : e;
  return e - s;
}

int sd_setup_psig_table_channel(const uint8_t *table, size_t tlen, char *out, size_t cap)
{
  size_t pos = 0, len;
  const uint8_t *line;
  int line_no = 0;
  if (table == NULL || out == NULL || cap == 0)
    return 1;
  while ((len = next_line(table, tlen, &pos, &line)) != 0) {
    line_no++;
    if (line_no == 2) {
      /* product line: checked by the verifier, skipped here */
      continue;
    }
    if (line_no == 3) {
      if (len < 9 || memcmp(line, "channel ", 8) != 0 || len - 8 >= cap)
        return 1;
      memcpy(out, line + 8, len - 8);
      out[len - 8] = '\0';
      return 0;
    }
  }
  return 1;
}

/* Header: magic line, product line, channel line. Returns SD_SETUP_PSIG_OK when the header is well formed and its
   channel is the expected one, the error of the first failed rule otherwise. */
static sd_setup_psig_res check_header(const uint8_t *t, size_t n, const char *expected, char channel[8])
{
  size_t pos = 0, len;
  const uint8_t *line;
  if (n < sizeof(k_header_magic) - 1 || memcmp(t, k_header_magic, sizeof(k_header_magic) - 1) != 0)
    return SD_SETUP_PSIG_E_FORMAT;
  (void)next_line(t, n, &pos, &line);            /* magic, checked above */
  len = next_line(t, n, &pos, &line);           /* product */
  if (len != sizeof(k_header_product) - 2 || memcmp(line, k_header_product, len) != 0)
    return SD_SETUP_PSIG_E_PRODUCT;
  len = next_line(t, n, &pos, &line);           /* channel */
  if (len < 9 || len > 8 + 7 || memcmp(line, "channel ", 8) != 0)
    return SD_SETUP_PSIG_E_FORMAT;
  if (!((len == 14 && memcmp(line + 8, "stable", 6) == 0) || (len == 12 && memcmp(line + 8, "beta", 4) == 0)))
    return SD_SETUP_PSIG_E_FORMAT;
  memcpy(channel, line + 8, len - 8);
  channel[len - 8] = '\0';
  if (expected == NULL || strcmp(channel, expected) != 0)
    return SD_SETUP_PSIG_E_CHANNEL;
  return SD_SETUP_PSIG_OK;
}

/* sig line: "sig ed25519 <16 lowercase hex> <88 base64>" followed by LF, exactly. */
static sd_setup_psig_res parse_sig(const uint8_t *s, size_t n, uint8_t kid[8], uint8_t sig[64])
{
  char b64[88];
  size_t i;
  if (n > SD_SETUP_PSIG_SIG_MAX)
    return SD_SETUP_PSIG_E_TOO_LARGE;
  /* 12 + 16 + 1 + 88 + LF */
  if (n != 118 || s[117] != '\n')
    return SD_SETUP_PSIG_E_FORMAT;
  if (memcmp(s, k_sig_prefix, sizeof(k_sig_prefix) - 1) != 0 || s[28] != ' ')
    return SD_SETUP_PSIG_E_FORMAT;
  for (i = 0; i < 8; i++) {
    int hi = hex_val((char)s[12 + 2 * i]), lo = hex_val((char)s[13 + 2 * i]);
    if (hi < 0 || lo < 0)
      return SD_SETUP_PSIG_E_FORMAT;
    kid[i] = (uint8_t)((hi << 4) | lo);
  }
  for (i = 0; i < 88; i++) {
    if (s[29 + i] == '\n' || s[29 + i] == ' ')
      return SD_SETUP_PSIG_E_FORMAT;
    b64[i] = (char)s[29 + i];
  }
  if (sd_setup_psig_b64_decode(b64, 88, sig, 64) != 64)
    return SD_SETUP_PSIG_E_FORMAT;
  return SD_SETUP_PSIG_OK;
}

sd_setup_psig_res sd_setup_psig_verify(const uint8_t *table, size_t tlen, const uint8_t *sig, size_t slen,
                                       const sd_setup_psig_key *keys, size_t nkeys,
                                       const char *channel_expected, int64_t now)
{
  uint8_t kid[8], sigb[64], pub_hash[32];
  char channel[8];
  sd_setup_psig_res r;
  size_t i, match = (size_t)-1;
  /* domain || table, on the stack: the table is bounded by SD_SETUP_PSIG_TABLE_MAX. */
  uint8_t msg[sizeof(SD_SETUP_PSIG_DOMAIN) + SD_SETUP_PSIG_TABLE_MAX];
  size_t dl = sizeof(SD_SETUP_PSIG_DOMAIN) - 1;

  if (keys == NULL || nkeys == 0)
    return SD_SETUP_PSIG_E_NO_KEYS;
  if (table == NULL || sig == NULL || channel_expected == NULL)
    return SD_SETUP_PSIG_E_FORMAT;
  if (tlen == 0 || tlen > SD_SETUP_PSIG_TABLE_MAX || slen > SD_SETUP_PSIG_SIG_MAX)
    return SD_SETUP_PSIG_E_TOO_LARGE;
  if (!table_text_ok(table, tlen))
    return SD_SETUP_PSIG_E_FORMAT;
  if ((r = check_header(table, tlen, channel_expected, channel)) != SD_SETUP_PSIG_OK)
    return r;
  if ((r = parse_sig(sig, slen, kid, sigb)) != SD_SETUP_PSIG_OK)
    return r;

  for (i = 0; i < nkeys; i++) {
    sd_hash(SD_HASH_SHA256, keys[i].pub, 32, pub_hash);
    if (memcmp(pub_hash, kid, 8) == 0) {
      match = i;
      break;
    }
  }
  if (match == (size_t)-1)
    return SD_SETUP_PSIG_E_UNKNOWN_KEY;
  if (keys[match].revoked || now < keys[match].valid_from || now > keys[match].valid_to)
    return SD_SETUP_PSIG_E_KEY_INVALID;
  if (strcmp(keys[match].channel, channel) != 0)
    return SD_SETUP_PSIG_E_CHANNEL;

  memcpy(msg, SD_SETUP_PSIG_DOMAIN, dl);
  memcpy(msg + dl, table, tlen);
  if (sd_ed25519_verify(sigb, keys[match].pub, msg, dl + tlen) != SD_OK)
    return SD_SETUP_PSIG_E_SIGNATURE;
  return SD_SETUP_PSIG_OK;
}

int64_t sd_setup_psig_now(void)
{
  FILETIME ft;
  ULARGE_INTEGER u;
  GetSystemTimeAsFileTime(&ft);
  u.LowPart = ft.dwLowDateTime;
  u.HighPart = ft.dwHighDateTime;
  /* 100 ns intervals since 1601-01-01 -> unix seconds */
  return (int64_t)(u.QuadPart / 10000000ull) - 11644473600ll;
}

sd_setup_psig_res sd_setup_payload_sig_check(HINSTANCE inst, const uint8_t *table, size_t tlen)
{
  HRSRC hr;
  HGLOBAL hg;
  const uint8_t *p;
  DWORD n;

  hr = FindResourceW(inst, L"PAYLOAD_SIG", RT_RCDATA);
  hg = hr != NULL ? LoadResource(inst, hr) : NULL;
  if (hg == NULL || table == NULL)
    return SD_SETUP_PSIG_E_RESOURCE;
  p = (const uint8_t *)LockResource(hg);
  n = SizeofResource(inst, hr);
  if (p == NULL || n == 0)
    return SD_SETUP_PSIG_E_RESOURCE;
  return sd_setup_psig_verify(table, tlen, p, n, k_builtin_keys,
                              sizeof(k_builtin_keys) / sizeof(k_builtin_keys[0]),
                              SD_SETUP_BUILD_CHANNEL, sd_setup_psig_now());
}
