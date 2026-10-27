/* sd-updsign: offline signing tool for the update pipeline (04 §9.3, §12.3). Build-time tool: it is never part
 * of a shipping image and never runs inside the product.
 *
 *   sd-updsign keygen   --seed <file> [--pub <file>]          new ed25519 key; prints the public key and key id
 *   sd-updsign pubkey   --seed <file>                         public key (base64) and key id of a seed file
 *   sd-updsign sign-keyset   --in <body> --root <seed> [--root <seed>...] --out <keyset.txt>
 *   sd-updsign sign-manifest --in <body> --key <seed> --out <manifest.txt>
 *   sd-updsign hash     --file <path> [--alg 256|512]         "sha256:<hex>" for a file line of the manifest
 *
 * <body> is the unsigned text (it ends with LF and has no sig line). The signature covers
 * domain || body, with the domain strings of sd_update.h (com.librestatic.shelldrive ... v1). Each root
 * --root adds one "sig" line; a keyset that rotates roots needs both current roots (the verifier decides).
 *
 * Seed files hold 32 bytes as 64 hex digits. Production seeds live on the offline signing machine in an
 * encrypted volume (04 §9.3); the tool itself never uploads or prints a seed. Exit codes: 0 ok, 1 usage,
 * 2 I/O or format error. */
#include <windows.h>
#include <stdio.h>
#include <string.h>

#include "sd/base.h"
#include "sd_base/sd_mem.h"
#include "sd_crypto/sd_crypto.h"
#include "sd_platform/sd_platform.h"
#include "sd_update/sd_update.h"

#define MAX_IN  (SD_UPD_KEYSET_MAX + 4096u)
#define MAX_SIG 64

static void out_text(HANDLE h, const char *s)
{
  DWORD n = 0;
  WriteFile(h, s, (DWORD)strlen(s), &n, NULL);
}

static void err_text(const char *s)
{
  out_text(GetStdHandle(STD_ERROR_HANDLE), s);
}

static int read_file(const wchar_t *path, uint8_t **buf, size_t *len, size_t max)
{
  HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  LARGE_INTEGER sz;
  DWORD got = 0;
  uint8_t *p;
  if (h == INVALID_HANDLE_VALUE)
    return 0;
  if (!GetFileSizeEx(h, &sz) || sz.QuadPart < 0 || (unsigned long long)sz.QuadPart > max) {
    CloseHandle(h);
    return 0;
  }
  p = (uint8_t *)sd_alloc((size_t)sz.QuadPart + 1);
  if (p == NULL) {
    CloseHandle(h);
    return 0;
  }
  if (sz.QuadPart && (!ReadFile(h, p, (DWORD)sz.QuadPart, &got, NULL) || got != (DWORD)sz.QuadPart)) {
    CloseHandle(h);
    sd_free(p);
    return 0;
  }
  CloseHandle(h);
  *buf = p;
  *len = got;
  return 1;
}

static int write_file(const wchar_t *path, const uint8_t *buf, size_t len)
{
  HANDLE h = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  DWORD put = 0;
  BOOL ok;
  if (h == INVALID_HANDLE_VALUE)
    return 0;
  ok = WriteFile(h, buf, (DWORD)len, &put, NULL) && put == (DWORD)len && FlushFileBuffers(h);
  CloseHandle(h);
  return ok != 0;
}

static const char k_b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static void b64_encode(const uint8_t *in, size_t n, char *out)
{
  size_t i, o = 0;
  for (i = 0; i < n; i += 3) {
    uint32_t v = (uint32_t)in[i] << 16;
    size_t rem = n - i;
    if (rem > 1) v |= (uint32_t)in[i + 1] << 8;
    if (rem > 2) v |= (uint32_t)in[i + 2];
    out[o++] = k_b64[(v >> 18) & 63];
    out[o++] = k_b64[(v >> 12) & 63];
    out[o++] = rem > 1 ? k_b64[(v >> 6) & 63] : '=';
    out[o++] = rem > 2 ? k_b64[v & 63] : '=';
  }
  out[o] = '\0';
}

static int hex_val(char c)
{
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

static int read_seed(const wchar_t *path, uint8_t seed[32])
{
  uint8_t *buf = NULL;
  size_t len = 0, i;
  int ok = 0;
  if (!read_file(path, &buf, &len, 256))
    return 0;
  if (len >= 64) {
    ok = 1;
    for (i = 0; i < 32; i++) {
      int hi = hex_val((char)buf[2 * i]), lo = hex_val((char)buf[2 * i + 1]);
      if (hi < 0 || lo < 0) { ok = 0; break; }
      seed[i] = (uint8_t)((hi << 4) | lo);
    }
  }
  sd_secure_free(buf, len + 1);
  return ok;
}

static void print_pub(const uint8_t pub[32])
{
  char b64[64], line[160];
  uint8_t id[8];
  int i;
  char hex[17];
  b64_encode(pub, 32, b64);
  sd_upd_key_id(pub, id);
  for (i = 0; i < 8; i++) sprintf_s(hex + 2 * i, sizeof(hex) - (size_t)(2 * i), "%02x", id[i]);
  sprintf_s(line, sizeof(line), "pubkey %s\nkey-id %s\n", b64, hex);
  out_text(GetStdHandle(STD_OUTPUT_HANDLE), line);
}

/* Appends "sig ed25519 <key-id> <base64>\n" for seed over domain || body. */
static int append_sig(uint8_t *out, size_t *olen, size_t cap, const uint8_t seed[32], const char *domain,
                      const uint8_t *body, size_t blen)
{
  uint8_t pub[32], sig[64], id[8], *msg;
  size_t dl = strlen(domain), total = dl + blen;
  char b64[96], hex[17], line[200];
  int i, n;
  if (sd_ed25519_pub_from_seed(pub, seed) != SD_OK)
    return 0;
  msg = (uint8_t *)sd_alloc(total);
  if (msg == NULL)
    return 0;
  memcpy(msg, domain, dl);
  memcpy(msg + dl, body, blen);
  if (sd_ed25519_sign(sig, seed, pub, msg, total) != SD_OK) {
    sd_free(msg);
    return 0;
  }
  sd_free(msg);
  sd_upd_key_id(pub, id);
  for (i = 0; i < 8; i++) sprintf_s(hex + 2 * i, sizeof(hex) - (size_t)(2 * i), "%02x", id[i]);
  b64_encode(sig, 64, b64);
  n = sprintf_s(line, sizeof(line), "sig ed25519 %s %s\n", hex, b64);
  if (n <= 0 || *olen + (size_t)n > cap)
    return 0;
  memcpy(out + *olen, line, (size_t)n);
  *olen += (size_t)n;
  return 1;
}

static const wchar_t *opt(int argc, wchar_t **argv, const wchar_t *name)
{
  int i;
  for (i = 1; i + 1 < argc; i++) {
    if (wcscmp(argv[i], name) == 0)
      return argv[i + 1];
  }
  return NULL;
}

static int body_ok(const uint8_t *b, size_t n)
{
  size_t i;
  if (n == 0 || b[n - 1] != '\n')
    return 0;
  for (i = 0; i + 4 <= n; i++) {
    if ((i == 0 || b[i - 1] == '\n') && memcmp(b + i, "sig ", 4) == 0)
      return 0;                          /* the body must not carry sig lines */
  }
  return 1;
}

static int cmd_sign(int argc, wchar_t **argv, int keyset)
{
  const wchar_t *in = opt(argc, argv, L"--in"), *out = opt(argc, argv, L"--out");
  uint8_t *body = NULL, *res;
  size_t blen = 0, rlen = 0, cap;
  int i, ok = 1;
  if (in == NULL || out == NULL)
    return 1;
  if (!read_file(in, &body, &blen, MAX_IN) || !body_ok(body, blen)) {
    err_text("sd-updsign: cannot read a well formed body\n");
    sd_free(body);
    return 2;
  }
  cap = blen + MAX_SIG * 128u;
  res = (uint8_t *)sd_alloc(cap);
  if (res == NULL) { sd_free(body); return 2; }
  memcpy(res, body, blen);
  rlen = blen;
  if (keyset) {
    for (i = 1; i + 1 < argc; i++) {
      uint8_t seed[32];
      if (wcscmp(argv[i], L"--root") != 0) continue;
      if (!read_seed(argv[i + 1], seed) || !append_sig(res, &rlen, cap, seed, SD_UPD_DOMAIN_KEYSET, body, blen)) {
        ok = 0;
        break;
      }
      sd_secure_zero(seed, sizeof(seed));
    }
  } else {
    uint8_t seed[32];
    const wchar_t *k = opt(argc, argv, L"--key");
    if (k == NULL || !read_seed(k, seed) || !append_sig(res, &rlen, cap, seed, SD_UPD_DOMAIN_MANIFEST, body, blen))
      ok = 0;
    sd_secure_zero(seed, sizeof(seed));
  }
  if (ok && !write_file(out, res, rlen))
    ok = 0;
  if (!ok)
    err_text("sd-updsign: signing failed (seed, body or output)\n");
  sd_free(body);
  sd_free(res);
  return ok ? 0 : 2;
}

static int cmd_keygen(int argc, wchar_t **argv)
{
  const wchar_t *seedp = opt(argc, argv, L"--seed"), *pubp = opt(argc, argv, L"--pub");
  uint8_t seed[32], pub[32];
  char hex[65];
  int i;
  if (seedp == NULL)
    return 1;
  if (sd_random(seed, sizeof(seed)) != SD_OK || sd_ed25519_pub_from_seed(pub, seed) != SD_OK)
    return 2;
  for (i = 0; i < 32; i++) sprintf_s(hex + 2 * i, sizeof(hex) - (size_t)(2 * i), "%02x", seed[i]);
  hex[64] = '\n';
  if (!write_file(seedp, (const uint8_t *)hex, 65)) {
    sd_secure_zero(seed, sizeof(seed));
    return 2;
  }
  if (pubp) {
    char b64[64], line[96];
    b64_encode(pub, 32, b64);
    sprintf_s(line, sizeof(line), "%s\n", b64);
    if (!write_file(pubp, (const uint8_t *)line, strlen(line))) {
      sd_secure_zero(seed, sizeof(seed));
      return 2;
    }
  }
  print_pub(pub);
  sd_secure_zero(seed, sizeof(seed));
  return 0;
}

static int cmd_pubkey(int argc, wchar_t **argv)
{
  const wchar_t *seedp = opt(argc, argv, L"--seed");
  uint8_t seed[32], pub[32];
  if (seedp == NULL || !read_seed(seedp, seed))
    return 1;
  if (sd_ed25519_pub_from_seed(pub, seed) != SD_OK)
    return 2;
  sd_secure_zero(seed, sizeof(seed));
  print_pub(pub);
  return 0;
}

static int cmd_hash(int argc, wchar_t **argv)
{
  const wchar_t *f = opt(argc, argv, L"--file");
  const wchar_t *a = opt(argc, argv, L"--alg");
  int alg = (a && wcscmp(a, L"512") == 0) ? 512 : 256;
  HANDLE h;
  sd_hash_ctx c;
  uint8_t *buf, digest[64];
  char line[160], hex[129];
  int i;
  size_t n;
  if (f == NULL)
    return 1;
  h = CreateFileW(f, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  if (h == INVALID_HANDLE_VALUE)
    return 2;
  buf = (uint8_t *)sd_alloc(65536);
  if (buf == NULL) { CloseHandle(h); return 2; }
  sd_hash_init(&c, alg == 512 ? SD_HASH_SHA512 : SD_HASH_SHA256);
  for (;;) {
    DWORD got = 0;
    if (!ReadFile(h, buf, 65536, &got, NULL)) { sd_free(buf); CloseHandle(h); return 2; }
    if (got == 0) break;
    sd_hash_update(&c, buf, got);
  }
  sd_hash_final(&c, digest);
  sd_free(buf);
  CloseHandle(h);
  n = alg == 512 ? 64 : 32;
  for (i = 0; i < (int)n; i++) sprintf_s(hex + 2 * i, sizeof(hex) - (size_t)(2 * i), "%02x", digest[i]);
  sprintf_s(line, sizeof(line), "sha%d:%s\n", alg, hex);
  out_text(GetStdHandle(STD_OUTPUT_HANDLE), line);
  return 0;
}

int wmain(int argc, wchar_t **argv)
{
  int rc = 1;
  if (argc < 2)
    goto usage;
  if (sd_platform_init() != SD_OK)
    return 2;
  if (wcscmp(argv[1], L"keygen") == 0) rc = cmd_keygen(argc, argv);
  else if (wcscmp(argv[1], L"pubkey") == 0) rc = cmd_pubkey(argc, argv);
  else if (wcscmp(argv[1], L"sign-keyset") == 0) rc = cmd_sign(argc, argv, 1);
  else if (wcscmp(argv[1], L"sign-manifest") == 0) rc = cmd_sign(argc, argv, 0);
  else if (wcscmp(argv[1], L"hash") == 0) rc = cmd_hash(argc, argv);
  else goto usage;
  return rc;

usage:
  err_text("usage: sd-updsign keygen|pubkey|sign-keyset|sign-manifest|hash (see docs/dev/m4-notes.md)\n");
  return 1;
}
