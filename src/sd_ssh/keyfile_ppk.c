/* PuTTY private key files PPK v2 and v3 (01 §6.6): ssh-rsa, ssh-ed25519, ecdsa-sha2-nistp*;
 * Encryption none or aes256-cbc; v2 keys from SHA-1 and an HMAC-SHA-1 MAC, v3 keys from Argon2id/i/d
 * and an HMAC-SHA-256 MAC. Strict header order as PuTTY writes it; unknown lines are an error.
 * No transport dependency. */
#include <string.h>

#include "sd_base/sd_mem.h"
#include "sd_crypto/sd_crypto.h"
#include "sd_crypto/sd_ct.h"
#include "keyfile_internal.h"
#include "ssh_internal.h"

#define PPK_MAX_HEADER  (256u * 1024u)
#define PPK_MAX_SECTION (64u * 1024u)
#define PPK_MAX_LINES   4096u

typedef struct ppk_file {
  int version;                  /* 2 or 3 */
  char alg[64];
  int encrypted;
  char comment[1024];
  size_t comment_len;
  uint8_t *pub; size_t pub_len;
  uint8_t *priv; size_t priv_len;      /* still encrypted */
  sd_argon2_type kdf;
  uint32_t mem_kib, passes, lanes;
  uint8_t salt[64]; size_t salt_len;
  uint8_t mac[32]; size_t mac_len;
} ppk_file;

static void ppk_free(ppk_file *f)
{
  sd_free(f->pub);
  if (f->priv) sd_secure_free(f->priv, f->priv_len);
  sd_secure_zero(f->comment, sizeof(f->comment));
  f->pub = f->priv = NULL;
}

typedef struct ppk_rd { const uint8_t *b; size_t len, pos; } ppk_rd;

/* Next line (without CR/LF); 0 at the end. */
static int ppk_line(ppk_rd *r, const uint8_t **s, size_t *n)
{
  size_t st = r->pos, e;
  if (r->pos >= r->len) return 0;
  while (r->pos < r->len && r->b[r->pos] != '\n') r->pos++;
  e = r->pos;
  if (r->pos < r->len) r->pos++;
  if (e > st && r->b[e - 1] == '\r') e--;
  *s = r->b + st;
  *n = e - st;
  return 1;
}

/* "Key: value" with exactly this key; value returned. */
static int ppk_field(ppk_rd *r, const char *key, const uint8_t **v, size_t *vn)
{
  const uint8_t *s;
  size_t n, kl = strlen(key);
  if (!ppk_line(r, &s, &n)) return 0;
  if (n < kl + 2 || memcmp(s, key, kl) != 0 || s[kl] != ':' || s[kl + 1] != ' ') return 0;
  *v = s + kl + 2;
  *vn = n - kl - 2;
  return 1;
}

static int parse_u32(const uint8_t *v, size_t n, uint32_t *out)
{
  uint64_t x = 0;
  size_t i;
  if (n == 0 || n > 10) return 0;
  for (i = 0; i < n; i++) {
    if (v[i] < '0' || v[i] > '9') return 0;
    x = x * 10u + (uint64_t)(v[i] - '0');
  }
  if (x > 0xFFFFFFFFu) return 0;
  *out = (uint32_t)x;
  return 1;
}

static int parse_hex(const uint8_t *v, size_t n, uint8_t *out, size_t cap, size_t *outn)
{
  size_t i;
  if (n % 2 || n / 2 > cap) return 0;
  for (i = 0; i < n; i += 2) {
    int hi = -1, lo = -1, k;
    for (k = 0; k < 2; k++) {
      uint8_t c = v[i + (size_t)k];
      int x = (c >= '0' && c <= '9') ? c - '0' : (c >= 'a' && c <= 'f') ? c - 'a' + 10 : (c >= 'A' && c <= 'F') ? c - 'A' + 10 : -1;
      if (k == 0) hi = x; else lo = x;
    }
    if (hi < 0 || lo < 0) return 0;
    out[i / 2] = (uint8_t)((hi << 4) | lo);
  }
  *outn = n / 2;
  return 1;
}

/* "<key>-Lines: N" then N base64 lines. */
static sd_err ppk_section(ppk_rd *r, const char *key, uint8_t **out, size_t *out_len)
{
  const uint8_t *v, *s, *start = NULL;
  size_t vn, n, i, total = 0, cap;
  uint32_t lines;
  char *buf;
  if (!ppk_field(r, key, &v, &vn) || !parse_u32(v, vn, &lines) || lines == 0 || lines > PPK_MAX_LINES)
    return SD_E_KEY_FORMAT;
  cap = (size_t)lines * 128u + 1u;
  if (cap > PPK_MAX_SECTION * 2u) return SD_E_KEY_FORMAT;
  buf = (char *)sd_alloc(cap);
  if (!buf) return SD_E_NO_MEMORY;
  for (i = 0; i < lines; i++) {
    if (!ppk_line(r, &s, &n) || n == 0 || n > 128 || total + n >= cap) { sd_secure_free(buf, cap); return SD_E_KEY_FORMAT; }
    if (!start) start = s;
    memcpy(buf + total, s, n);
    total += n;
  }
  *out = (uint8_t *)sd_alloc(total);
  if (!*out) { sd_secure_free(buf, cap); return SD_E_NO_MEMORY; }
  if (ssh_b64_decode(buf, total, *out, total, out_len, 0) != SD_OK || *out_len == 0 || *out_len > PPK_MAX_SECTION) {
    sd_secure_free(buf, cap);
    sd_secure_free(*out, total);
    *out = NULL;
    return SD_E_KEY_FORMAT;
  }
  sd_secure_free(buf, cap);
  return SD_OK;
}

static sd_err ppk_parse(const uint8_t *bytes, size_t len, ppk_file *f)
{
  ppk_rd r;
  const uint8_t *s, *v;
  size_t n, vn, i = 0;
  sd_err e;
  memset(f, 0, sizeof(*f));
  if (len >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF) i = 3;
  while (i < len && (bytes[i] == ' ' || bytes[i] == '\t' || bytes[i] == '\r' || bytes[i] == '\n')) i++;
  r.b = bytes + i;
  r.len = len - i;
  r.pos = 0;
  if (!ppk_line(&r, &s, &n) || n < 24 || memcmp(s, "PuTTY-User-Key-File-", 20) != 0) return SD_E_KEY_FORMAT;
  if (s[20] == '2' && s[21] == ':') f->version = 2;
  else if (s[20] == '3' && s[21] == ':') f->version = 3;
  else return SD_E_KEY_UNSUPPORTED;   /* v1 and future versions */
  if (s[22] != ' ' || n - 23 >= sizeof(f->alg)) return SD_E_KEY_FORMAT;
  memcpy(f->alg, s + 23, n - 23);
  f->alg[n - 23] = '\0';
  if (!ppk_field(&r, "Encryption", &v, &vn)) return SD_E_KEY_FORMAT;
  if (vn == 4 && memcmp(v, "none", 4) == 0) f->encrypted = 0;
  else if (vn == 10 && memcmp(v, "aes256-cbc", 10) == 0) f->encrypted = 1;
  else return SD_E_KEY_UNSUPPORTED;
  if (!ppk_field(&r, "Comment", &v, &vn)) return SD_E_KEY_FORMAT;
  if (vn >= sizeof(f->comment)) return SD_E_KEY_FORMAT;
  memcpy(f->comment, v, vn);
  f->comment_len = vn;
  e = ppk_section(&r, "Public-Lines", &f->pub, &f->pub_len);
  if (e != SD_OK) return e;
  if (f->version == 3 && f->encrypted) {
    if (!ppk_field(&r, "Key-Derivation", &v, &vn)) return SD_E_KEY_FORMAT;
    if (vn == 8 && memcmp(v, "Argon2id", 8) == 0) f->kdf = SD_ARGON2ID;
    else if (vn == 7 && memcmp(v, "Argon2i", 7) == 0) f->kdf = SD_ARGON2I;
    else if (vn == 7 && memcmp(v, "Argon2d", 7) == 0) f->kdf = SD_ARGON2D;
    else return SD_E_KEY_UNSUPPORTED;
    if (!ppk_field(&r, "Argon2-Memory", &v, &vn) || !parse_u32(v, vn, &f->mem_kib)) return SD_E_KEY_FORMAT;
    if (!ppk_field(&r, "Argon2-Passes", &v, &vn) || !parse_u32(v, vn, &f->passes)) return SD_E_KEY_FORMAT;
    if (!ppk_field(&r, "Argon2-Parallelism", &v, &vn) || !parse_u32(v, vn, &f->lanes)) return SD_E_KEY_FORMAT;
    if (!ppk_field(&r, "Argon2-Salt", &v, &vn) || !parse_hex(v, vn, f->salt, sizeof(f->salt), &f->salt_len) ||
        f->salt_len == 0)
      return SD_E_KEY_FORMAT;
    if (f->passes == 0 || f->lanes == 0 || f->mem_kib < 8u * f->lanes) return SD_E_KEY_FORMAT;
    if (f->mem_kib > SD_ARGON2_MAX_MEM_KIB || f->passes > SD_ARGON2_MAX_PASSES || f->lanes > SD_ARGON2_MAX_LANES)
      return SD_E_KEY_UNSUPPORTED;
  }
  e = ppk_section(&r, "Private-Lines", &f->priv, &f->priv_len);
  if (e != SD_OK) return e;
  if (!ppk_field(&r, "Private-MAC", &v, &vn) ||
      !parse_hex(v, vn, f->mac, sizeof(f->mac), &f->mac_len) || f->mac_len != (f->version == 2 ? 20u : 32u))
    return SD_E_KEY_FORMAT;
  while (ppk_line(&r, &s, &n))
    if (n) return SD_E_KEY_FORMAT;   /* trailing garbage */
  if (f->encrypted && f->priv_len % 16) return SD_E_KEY_FORMAT;
  return SD_OK;
}

sd_err ssh_ppk_probe(const uint8_t *bytes, size_t len, sd_ssh_key_probe_info *out)
{
  ppk_file f;
  sd_span t;
  sd_err e = ppk_parse(bytes, len, &f);
  memset(out, 0, sizeof(*out));
  if (e != SD_OK) { ppk_free(&f); return e; }
  t = ssh_blob_key_type(f.pub, f.pub_len);
  if (!ssh_span_eq(t, f.alg)) { ppk_free(&f); return SD_E_KEY_FORMAT; }
  e = ssh_pubblob_info(f.pub, f.pub_len, NULL, NULL, NULL);
  if (e == SD_OK) {
    ssh_probe_fill_from_pub(out, f.pub, f.pub_len);
    out->encrypted = f.encrypted;
    out->format = f.version == 2 ? SD_KEYFMT_PPK2 : SD_KEYFMT_PPK3;
  }
  ppk_free(&f);
  return e;
}

static void wr_str(sd_hmac_ctx *h, const void *p, size_t n)
{
  uint8_t l[4];
  sd_store_be32(l, (uint32_t)n);
  sd_hmac_update(h, l, 4);
  if (n) sd_hmac_update(h, p, n);
}

/* Private blob -> key. Trailing bytes are cipher padding (< 16 when encrypted). */
static sd_err ppk_build(const ppk_file *f, const uint8_t *priv, size_t n, sd_ssh_key **out)
{
  sd_rd pub, pr;
  sd_span type, comment;
  comment.p = (const uint8_t *)f->comment;
  comment.n = f->comment_len;
  sd_rd_init(&pub, f->pub, f->pub_len);
  sd_rd_init(&pr, priv, n);
  type = sd_rd_string(&pub, 64);
  if (ssh_span_eq(type, "ssh-rsa")) {
    sd_span e = sd_rd_mpint(&pub, 64), nn = sd_rd_mpint(&pub, SSH_RSA_MAX_BYTES + 1);
    sd_span d = sd_rd_mpint(&pr, SSH_RSA_MAX_BYTES + 1), p = sd_rd_mpint(&pr, SSH_RSA_MAX_BYTES + 1);
    sd_span q = sd_rd_mpint(&pr, SSH_RSA_MAX_BYTES + 1), iqmp = sd_rd_mpint(&pr, SSH_RSA_MAX_BYTES + 1);
    if (!sd_rd_done(&pub) || !sd_rd_ok(&pr) || sd_rd_remaining(&pr) >= 16) return SD_E_KEY_FORMAT;
    return ssh_key_new_rsa(nn, e, d, iqmp, p, q, comment, out);
  }
  if (ssh_span_eq(type, "ssh-ed25519")) {
    sd_span pk = sd_rd_string(&pub, 64), le = sd_rd_string(&pr, 32);
    uint8_t seed[32];
    sd_err e;
    if (!sd_rd_done(&pub) || !sd_rd_ok(&pr) || sd_rd_remaining(&pr) >= 16 || pk.n != 32 || le.n == 0) return SD_E_KEY_FORMAT;
    /* PuTTY writes the seed as a little-endian integer without its high zero bytes */
    memset(seed, 0, sizeof(seed));
    memcpy(seed, le.p, le.n);
    e = ssh_key_new_ed25519(seed, pk.p, comment, out);
    sd_secure_zero(seed, sizeof(seed));
    return e;
  }
  if (type.n > 11 && memcmp(type.p, "ecdsa-sha2-", 11) == 0) {
    sd_span cn = sd_rd_string(&pub, 64), q = sd_rd_string(&pub, 256), d = sd_rd_mpint(&pr, 67);
    uint32_t curve = ssh_curve_from_name(cn);
    if (!sd_rd_done(&pub) || !sd_rd_ok(&pr) || sd_rd_remaining(&pr) >= 16 || !curve) return SD_E_KEY_FORMAT;
    return ssh_key_new_ecdsa(curve, q, d, comment, out);
  }
  return SD_E_KEY_UNSUPPORTED;
}

sd_err ssh_ppk_load(const uint8_t *bytes, size_t len, const char *pass, size_t pass_len, sd_ssh_key **out)
{
  ppk_file f;
  uint8_t keys[80], mac[32];
  size_t mac_len;
  sd_hmac_ctx h;
  sd_err e = ppk_parse(bytes, len, &f);
  *out = NULL;
  if (e != SD_OK) { ppk_free(&f); return e; }
  if (!ssh_span_eq(ssh_blob_key_type(f.pub, f.pub_len), f.alg)) { ppk_free(&f); return SD_E_KEY_FORMAT; }
  e = ssh_pubblob_info(f.pub, f.pub_len, NULL, NULL, NULL);
  if (e != SD_OK) { ppk_free(&f); return e; }
  if (f.encrypted && !pass) { ppk_free(&f); return SD_E_KEY_PASSPHRASE_REQUIRED; }
  if (!ssh_crypto_ready()) { ppk_free(&f); return SD_E_UNSUPPORTED; }
  if (!f.encrypted) { pass = ""; pass_len = 0; }
  memset(keys, 0, sizeof(keys));
  if (f.version == 2) {
    sd_hash_ctx hc;
    uint8_t seq[4] = { 0, 0, 0, 0 }, dg[20];
    static const char mac_label[] = "putty-private-key-file-mac-key";
    if (f.encrypted) {
      sd_hash_init(&hc, SD_HASH_SHA1);
      sd_hash_update(&hc, seq, 4);
      sd_hash_update(&hc, pass, pass_len);
      sd_hash_final(&hc, keys);
      seq[3] = 1;
      sd_hash_init(&hc, SD_HASH_SHA1);
      sd_hash_update(&hc, seq, 4);
      sd_hash_update(&hc, pass, pass_len);
      sd_hash_final(&hc, dg);
      memcpy(keys + 20, dg, 12);   /* cipher key = first 32 bytes; IV = 0 */
      sd_secure_zero(dg, sizeof(dg));
    }
    sd_hash_init(&hc, SD_HASH_SHA1);
    sd_hash_update(&hc, mac_label, sizeof(mac_label) - 1);
    sd_hash_update(&hc, pass, pass_len);
    sd_hash_final(&hc, keys + 48);     /* MAC key (20 bytes) */
    sd_hmac_init(&h, SD_HASH_SHA1, keys + 48, 20);
    mac_len = 20;
  } else {
    if (f.encrypted) {
      e = sd_argon2(f.kdf, f.mem_kib, f.passes, f.lanes, pass, pass_len, f.salt, f.salt_len, keys, 80, NULL);
      if (e != SD_OK) { sd_secure_zero(keys, sizeof(keys)); ppk_free(&f); return e; }
      sd_hmac_init(&h, SD_HASH_SHA256, keys + 48, 32);
    } else {
      sd_hmac_init(&h, SD_HASH_SHA256, "", 0);
    }
    mac_len = 32;
  }
  if (f.encrypted) {
    uint8_t iv[16];
    if (f.version == 2) memset(iv, 0, sizeof(iv)); else memcpy(iv, keys + 32, 16);
    e = sd_aes_cbc(0, keys, 32, iv, f.priv, f.priv_len, f.priv);
    if (e != SD_OK) { sd_hmac_wipe(&h); sd_secure_zero(keys, sizeof(keys)); ppk_free(&f); return e; }
  }
  wr_str(&h, f.alg, strlen(f.alg));
  wr_str(&h, f.encrypted ? "aes256-cbc" : "none", f.encrypted ? 10u : 4u);
  wr_str(&h, f.comment, f.comment_len);
  wr_str(&h, f.pub, f.pub_len);
  wr_str(&h, f.priv, f.priv_len);
  sd_hmac_final(&h, mac);
  sd_hmac_wipe(&h);
  sd_secure_zero(keys, sizeof(keys));
  if (!sd_ct_memeq(mac, f.mac, mac_len)) {
    ppk_free(&f);
    return f.encrypted ? SD_E_BAD_PASSPHRASE : SD_E_KEY_FORMAT;
  }
  e = ppk_build(&f, f.priv, f.priv_len, out);
  if (e == SD_OK && !ssh_key_pub_equal(*out, f.pub, f.pub_len)) {
    sd_ssh_key_free(*out);
    *out = NULL;
    e = SD_E_KEY_FORMAT;
  }
  ppk_free(&f);
  return e;
}
