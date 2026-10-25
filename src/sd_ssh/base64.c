/* Base64 (RFC 4648) and small span helpers. Not constant time: never used on secret-dependent
 * lengths; key file bodies are decoded before any secret is derived from them. */
#include <string.h>

#include "ssh_internal.h"

static const char k_b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

size_t ssh_b64_encoded_len(size_t n, int pad)
{
  if (pad) return ((n + 2) / 3) * 4;
  return (n / 3) * 4 + ((n % 3) ? (n % 3) + 1 : 0);
}

size_t ssh_b64_encode(const uint8_t *in, size_t n, char *out, size_t cap, int pad)
{
  size_t need = ssh_b64_encoded_len(n, pad), i, o = 0;
  if (cap < need + 1) return 0;
  for (i = 0; i + 3 <= n; i += 3) {
    uint32_t v = ((uint32_t)in[i] << 16) | ((uint32_t)in[i + 1] << 8) | in[i + 2];
    out[o++] = k_b64[(v >> 18) & 63]; out[o++] = k_b64[(v >> 12) & 63];
    out[o++] = k_b64[(v >> 6) & 63];  out[o++] = k_b64[v & 63];
  }
  if (n - i == 1) {
    uint32_t v = (uint32_t)in[i] << 16;
    out[o++] = k_b64[(v >> 18) & 63]; out[o++] = k_b64[(v >> 12) & 63];
    if (pad) { out[o++] = '='; out[o++] = '='; }
  } else if (n - i == 2) {
    uint32_t v = ((uint32_t)in[i] << 16) | ((uint32_t)in[i + 1] << 8);
    out[o++] = k_b64[(v >> 18) & 63]; out[o++] = k_b64[(v >> 12) & 63];
    out[o++] = k_b64[(v >> 6) & 63];
    if (pad) out[o++] = '=';
  }
  out[o] = '\0';
  return o;
}

static int b64_val(char c)
{
  if (c >= 'A' && c <= 'Z') return c - 'A';
  if (c >= 'a' && c <= 'z') return c - 'a' + 26;
  if (c >= '0' && c <= '9') return c - '0' + 52;
  if (c == '+') return 62;
  if (c == '/') return 63;
  return -1;
}

sd_err ssh_b64_decode(const char *in, size_t n, uint8_t *out, size_t cap, size_t *out_len, int skip_ws)
{
  uint32_t acc = 0;
  int bits = 0, pads = 0;
  size_t i, o = 0;
  for (i = 0; i < n; i++) {
    char c = in[i];
    int v;
    if (skip_ws && (c == '\r' || c == '\n' || c == ' ' || c == '\t')) continue;
    if (c == '=') { pads++; continue; }
    if (pads) return SD_E_INVALID_PARAM;          /* data after padding */
    v = b64_val(c);
    if (v < 0) return SD_E_INVALID_PARAM;
    acc = (acc << 6) | (uint32_t)v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      if (o >= cap) return SD_E_INVALID_PARAM;
      out[o++] = (uint8_t)(acc >> bits);
    }
  }
  /* leftover bits must be zero and fewer than 6; padding must complete a quantum */
  if (bits >= 6 || (acc & ((1u << bits) - 1u)) != 0) return SD_E_INVALID_PARAM;
  if (pads > 2) return SD_E_INVALID_PARAM;
  if (pads && ((bits == 4 && pads != 2) || (bits == 2 && pads != 1) || bits == 0)) return SD_E_INVALID_PARAM;
  *out_len = o;
  return SD_OK;
}

int ssh_span_eq(sd_span a, const char *s)
{
  size_t n = strlen(s);
  return a.n == n && (n == 0 || memcmp(a.p, s, n) == 0);
}

int ssh_span_copy(sd_span a, char *out, size_t cap)
{
  if (cap == 0 || a.n >= cap) return 0;
  if (a.n) memcpy(out, a.p, a.n);
  out[a.n] = '\0';
  return 1;
}

sd_span ssh_blob_key_type(const uint8_t *blob, size_t len)
{
  sd_rd r;
  sd_span t;
  sd_rd_init(&r, blob, len);
  t = sd_rd_string(&r, 64);
  if (!sd_rd_ok(&r) || t.n == 0) { t.p = NULL; t.n = 0; }
  return t;
}
