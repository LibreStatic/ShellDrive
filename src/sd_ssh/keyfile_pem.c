/* PEM private keys (01 §6.6): "RSA PRIVATE KEY" (PKCS#1), "EC PRIVATE KEY" (SEC1, P-256/384/521),
 * "PRIVATE KEY" (PKCS#8: rsaEncryption, id-ecPublicKey, id-Ed25519) and "ENCRYPTED PRIVATE KEY"
 * (PKCS#8 PBES2 with PBKDF2-HMAC-SHA1/256/384/512 and AES-CBC or DES-EDE3-CBC). Legacy OpenSSL
 * "Proc-Type: 4,ENCRYPTED" + "DEK-Info" (EVP_BytesToKey with MD5, one iteration) for AES-*-CBC and
 * DES-EDE3-CBC. scrypt, PBES1 and PKCS#12 PBE are reported as SD_E_KEY_UNSUPPORTED; so is DSA.
 * No transport dependency. */
#include <stdio.h>
#include <string.h>

#include "sd_base/sd_mem.h"
#include "sd_crypto/sd_crypto.h"
#include "keyfile_internal.h"
#include "ssh_internal.h"

#define PEM_MAX_ITER 10000000u

typedef enum pem_kind { PEM_RSA, PEM_EC, PEM_PKCS8, PEM_PKCS8_ENC, PEM_DSA } pem_kind;

typedef struct pem_file {
  pem_kind kind;
  int dek;                      /* legacy DEK-Info encryption */
  char dek_alg[32];
  uint8_t dek_iv[16]; size_t dek_iv_len;
  uint8_t *der; size_t der_len; /* decoded body (secret: may be a plain private key) */
} pem_file;

static void pem_free(pem_file *f)
{
  if (f->der) sd_secure_free(f->der, f->der_len + 1);
  f->der = NULL;
}

static int hexval(uint8_t c)
{
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

/* One line [p, eol) without the line end; returns the start of the next line. */
static size_t next_line(const uint8_t *b, size_t len, size_t pos, size_t *line_end)
{
  size_t i = pos;
  while (i < len && b[i] != '\n') i++;
  *line_end = (i > pos && b[i - 1] == '\r') ? i - 1 : i;
  return i < len ? i + 1 : i;
}

static int line_is(const uint8_t *b, size_t s, size_t e, const char *t)
{
  size_t n = strlen(t);
  while (e > s && (b[e - 1] == ' ' || b[e - 1] == '\t')) e--;
  return e - s == n && memcmp(b + s, t, n) == 0;
}

static int line_starts(const uint8_t *b, size_t s, size_t e, const char *t)
{
  size_t n = strlen(t);
  return e - s >= n && memcmp(b + s, t, n) == 0;
}

static sd_err parse_dek(pem_file *f, const uint8_t *v, size_t n)
{
  size_t i = 0, a = 0, ivn = 0;
  while (i < n && v[i] != ',') {
    if (a + 1 >= sizeof(f->dek_alg)) return SD_E_KEY_FORMAT;
    f->dek_alg[a++] = (char)v[i++];
  }
  f->dek_alg[a] = '\0';
  if (i >= n) return SD_E_KEY_FORMAT;
  i++;
  while (i < n) {
    int hi, lo;
    if (v[i] == ' ' || v[i] == '\t') { i++; continue; }
    if (i + 1 >= n) return SD_E_KEY_FORMAT;
    hi = hexval(v[i]);
    lo = hexval(v[i + 1]);
    if (hi < 0 || lo < 0 || ivn >= sizeof(f->dek_iv)) return SD_E_KEY_FORMAT;
    f->dek_iv[ivn++] = (uint8_t)((hi << 4) | lo);
    i += 2;
  }
  f->dek_iv_len = ivn;
  return SD_OK;
}

static sd_err pem_decode(const uint8_t *b, size_t len, pem_file *f)
{
  static const struct { const char *label; pem_kind kind; } k_labels[] = {
    { "RSA PRIVATE KEY", PEM_RSA }, { "EC PRIVATE KEY", PEM_EC }, { "PRIVATE KEY", PEM_PKCS8 },
    { "ENCRYPTED PRIVATE KEY", PEM_PKCS8_ENC }, { "DSA PRIVATE KEY", PEM_DSA },
  };
  char begin[64], end[64];
  size_t pos = 0, le, i, bstart = 0, bend = 0, body_cap;
  int found = 0, proc_enc = 0, have_dek = 0;
  uint8_t *body;
  size_t body_len = 0;
  memset(f, 0, sizeof(*f));
  if (len >= 3 && b[0] == 0xEF && b[1] == 0xBB && b[2] == 0xBF) pos = 3;
  while (pos < len && (b[pos] == ' ' || b[pos] == '\t' || b[pos] == '\r' || b[pos] == '\n')) pos++;
  {
    size_t nx = next_line(b, len, pos, &le);
    for (i = 0; i < SD_COUNTOF(k_labels); i++) {
      _snprintf_s(begin, sizeof(begin), _TRUNCATE, "-----BEGIN %s-----", k_labels[i].label);
      if (line_is(b, pos, le, begin)) {
        f->kind = k_labels[i].kind;
        _snprintf_s(end, sizeof(end), _TRUNCATE, "-----END %s-----", k_labels[i].label);
        found = 1;
        break;
      }
    }
    if (!found) return SD_E_KEY_FORMAT;
    pos = nx;
  }
  /* RFC 1421 headers (only before the base64 body) */
  {
    size_t nx = next_line(b, len, pos, &le);
    size_t s;
    int in_headers = 0;
    for (s = pos; s < le; s++) if (b[s] == ':') { in_headers = 1; break; }
    while (in_headers && pos < len) {
      nx = next_line(b, len, pos, &le);
      if (le == pos) { pos = nx; break; }      /* blank line ends the headers */
      if (line_starts(b, pos, le, "Proc-Type:")) {
        size_t v = pos + 10;
        while (v < le && b[v] == ' ') v++;
        if (!line_is(b, v, le, "4,ENCRYPTED")) return SD_E_KEY_UNSUPPORTED;
        proc_enc = 1;
      } else if (line_starts(b, pos, le, "DEK-Info:")) {
        size_t v = pos + 9;
        while (v < le && b[v] == ' ') v++;
        if (parse_dek(f, b + v, le - v) != SD_OK) return SD_E_KEY_FORMAT;
        have_dek = 1;
      } else {
        return SD_E_KEY_FORMAT;
      }
      pos = nx;
    }
  }
  if (proc_enc != have_dek) return SD_E_KEY_FORMAT;
  f->dek = have_dek;
  bstart = pos;
  while (pos < len) {
    size_t nx = next_line(b, len, pos, &le);
    if (line_is(b, pos, le, end)) { bend = pos; break; }
    if (le > pos && b[pos] == '-') return SD_E_KEY_FORMAT;
    pos = nx;
  }
  if (!bend) return SD_E_KEY_FORMAT;
  body_cap = bend - bstart + 1;
  body = (uint8_t *)sd_alloc(body_cap);
  if (!body) return SD_E_NO_MEMORY;
  if (ssh_b64_decode((const char *)b + bstart, bend - bstart, body, body_cap, &body_len, 1) != SD_OK || !body_len) {
    sd_secure_free(body, body_cap);
    return SD_E_KEY_FORMAT;
  }
  f->der = body;
  f->der_len = body_len;
  if (f->kind == PEM_DSA) { pem_free(f); return SD_E_KEY_UNSUPPORTED; }
  if (f->dek && (f->kind == PEM_PKCS8 || f->kind == PEM_PKCS8_ENC)) { pem_free(f); return SD_E_KEY_FORMAT; }
  return SD_OK;
}

/* ---- key structures ---- */

static sd_err parse_pkcs1(sd_span der, sd_ssh_key **out)
{
  ssh_der d, s;
  sd_span n, e, priv, p, q, iqmp, none = { NULL, 0 };
  uint32_t ver;
  ssh_der_init(&d, der.p, der.n);
  s = ssh_der_enter(&d, SSH_DER_SEQUENCE);
  ver = ssh_der_small(&s);
  n = ssh_der_uint(&s);
  e = ssh_der_uint(&s);
  priv = ssh_der_uint(&s);
  p = ssh_der_uint(&s);
  q = ssh_der_uint(&s);
  (void)ssh_der_uint(&s);   /* dp */
  (void)ssh_der_uint(&s);   /* dq */
  iqmp = ssh_der_uint(&s);
  if (!ssh_der_done(&s) || !ssh_der_done(&d)) return SD_E_KEY_FORMAT;
  if (ver != 0) return SD_E_KEY_UNSUPPORTED;   /* multi-prime */
  return ssh_key_new_rsa(n, e, priv, iqmp, p, q, none, out);
}

static uint32_t curve_from_oid(sd_span oid)
{
  if (ssh_der_oid_is(oid, "1.2.840.10045.3.1.7")) return 256;
  if (ssh_der_oid_is(oid, "1.3.132.0.34")) return 384;
  if (ssh_der_oid_is(oid, "1.3.132.0.35")) return 521;
  return 0;
}

/* SEC1 ECPrivateKey; outer_curve from PKCS#8 parameters (0 = must be inside). */
static sd_err parse_sec1(sd_span der, uint32_t outer_curve, sd_ssh_key **out)
{
  ssh_der d, s;
  sd_span dval, q = { NULL, 0 }, none = { NULL, 0 };
  uint32_t ver, curve = 0;
  ssh_der_init(&d, der.p, der.n);
  s = ssh_der_enter(&d, SSH_DER_SEQUENCE);
  ver = ssh_der_small(&s);
  dval = ssh_der_tlv(&s, SSH_DER_OCTET_STRING);
  if (ssh_der_peek(&s, SSH_DER_CTX0)) {
    ssh_der c0 = ssh_der_enter(&s, SSH_DER_CTX0);
    sd_span oid = ssh_der_tlv(&c0, SSH_DER_OID);
    if (!ssh_der_done(&c0)) return SD_E_KEY_FORMAT;
    curve = curve_from_oid(oid);
    if (!curve) return SD_E_KEY_UNSUPPORTED;
  }
  if (ssh_der_peek(&s, SSH_DER_CTX1)) {
    ssh_der c1 = ssh_der_enter(&s, SSH_DER_CTX1);
    sd_span bits = ssh_der_tlv(&c1, SSH_DER_BIT_STRING);
    if (!ssh_der_done(&c1) || bits.n < 2 || bits.p[0] != 0) return SD_E_KEY_FORMAT;
    q.p = bits.p + 1;
    q.n = bits.n - 1;
  }
  if (!ssh_der_done(&s) || !ssh_der_done(&d) || ver != 1) return SD_E_KEY_FORMAT;
  if (outer_curve && curve && outer_curve != curve) return SD_E_KEY_FORMAT;
  if (!curve) curve = outer_curve;
  if (!curve) return SD_E_KEY_FORMAT;
  while (dval.n > 1 && dval.p[0] == 0) { dval.p++; dval.n--; }
  return ssh_key_new_ecdsa(curve, q, dval, none, out);
}

static sd_err parse_pkcs8(sd_span der, sd_ssh_key **out)
{
  ssh_der d, s, alg;
  sd_span oid, priv, pub = { NULL, 0 }, none = { NULL, 0 };
  uint32_t ver;
  sd_err e;
  ssh_der_init(&d, der.p, der.n);
  s = ssh_der_enter(&d, SSH_DER_SEQUENCE);
  ver = ssh_der_small(&s);
  alg = ssh_der_enter(&s, SSH_DER_SEQUENCE);
  oid = ssh_der_tlv(&alg, SSH_DER_OID);
  priv = ssh_der_tlv(&s, SSH_DER_OCTET_STRING);
  if (ssh_der_peek(&s, SSH_DER_CTX0)) (void)ssh_der_tlv(&s, SSH_DER_CTX0);    /* attributes */
  if (ssh_der_peek(&s, 0x81)) {                                               /* [1] IMPLICIT publicKey */
    sd_span bits = ssh_der_tlv(&s, 0x81);
    if (bits.n < 2 || bits.p[0] != 0) return SD_E_KEY_FORMAT;
    pub.p = bits.p + 1;
    pub.n = bits.n - 1;
  }
  if (!ssh_der_done(&s) || !ssh_der_done(&d) || !ssh_der_ok(&alg) || ver > 1) return SD_E_KEY_FORMAT;
  if (ssh_der_oid_is(oid, "1.2.840.113549.1.1.1")) {             /* rsaEncryption */
    if (ssh_der_peek(&alg, SSH_DER_NULL)) (void)ssh_der_tlv(&alg, SSH_DER_NULL);
    if (!ssh_der_done(&alg)) return SD_E_KEY_FORMAT;
    return parse_pkcs1(priv, out);
  }
  if (ssh_der_oid_is(oid, "1.2.840.10045.2.1")) {                /* id-ecPublicKey */
    sd_span coid = ssh_der_tlv(&alg, SSH_DER_OID);
    uint32_t curve;
    if (!ssh_der_done(&alg)) return SD_E_KEY_FORMAT;
    curve = curve_from_oid(coid);
    if (!curve) return SD_E_KEY_UNSUPPORTED;
    return parse_sec1(priv, curve, out);
  }
  if (ssh_der_oid_is(oid, "1.3.101.112")) {                      /* id-Ed25519 (RFC 8410) */
    ssh_der inner;
    sd_span seed;
    if (!ssh_der_done(&alg)) return SD_E_KEY_FORMAT;
    ssh_der_init(&inner, priv.p, priv.n);
    seed = ssh_der_tlv(&inner, SSH_DER_OCTET_STRING);
    if (!ssh_der_done(&inner) || seed.n != 32 || (pub.n && pub.n != 32)) return SD_E_KEY_FORMAT;
    e = ssh_key_new_ed25519(seed.p, pub.n ? pub.p : NULL, none, out);
    return e;
  }
  if (ssh_der_oid_is(oid, "1.2.840.10040.4.1")) return SD_E_KEY_UNSUPPORTED;   /* DSA */
  return SD_E_KEY_UNSUPPORTED;
}

/* ---- decryption ---- */

static int unpad_pkcs7(const uint8_t *p, size_t *n, size_t block)
{
  uint8_t v;
  size_t i;
  if (*n == 0 || *n % block) return 0;
  v = p[*n - 1];
  if (v == 0 || v > block) return 0;
  for (i = 0; i < v; i++)
    if (p[*n - 1 - i] != v) return 0;
  *n -= v;
  return 1;
}

static int cbc_params(const char *alg, size_t *key_len, size_t *block, const char **oneshot)
{
  if (strcmp(alg, "AES-128-CBC") == 0) { *key_len = 16; *block = 16; *oneshot = "AES-128-CBC"; return 1; }
  if (strcmp(alg, "AES-192-CBC") == 0) { *key_len = 24; *block = 16; *oneshot = "AES-192-CBC"; return 1; }
  if (strcmp(alg, "AES-256-CBC") == 0) { *key_len = 32; *block = 16; *oneshot = "AES-256-CBC"; return 1; }
  if (strcmp(alg, "DES-EDE3-CBC") == 0) { *key_len = 24; *block = 8; *oneshot = "DES-EDE3-CBC"; return 1; }
  return 0;
}

/* CBC decryption in place. 3DES goes through sd_3des_cbc (sd_cipher_oneshot may not know the PEM
   name); AES through sd_cipher_oneshot. */
static sd_err cbc_decrypt(const char *name, const uint8_t *key, const uint8_t *iv, uint8_t *buf, size_t n)
{
  if (strcmp(name, "DES-EDE3-CBC") == 0) return sd_3des_cbc(0, key, iv, buf, n, buf);
  return sd_cipher_oneshot(name, 0, key, iv, buf, n);
}

/* MD5 (RFC 1321), only for EVP_BytesToKey of legacy encrypted PEM files: sd_crypto has no MD5 (its
   hash id 0 is reserved for it). Not used for anything that needs collision resistance. */
typedef struct pem_md5 { uint32_t h[4]; uint64_t len; uint8_t buf[64]; size_t n; } pem_md5;

static const uint32_t k_md5_k[64] = {
  0xd76aa478u, 0xe8c7b756u, 0x242070dbu, 0xc1bdceeeu, 0xf57c0fafu, 0x4787c62au, 0xa8304613u, 0xfd469501u,
  0x698098d8u, 0x8b44f7afu, 0xffff5bb1u, 0x895cd7beu, 0x6b901122u, 0xfd987193u, 0xa679438eu, 0x49b40821u,
  0xf61e2562u, 0xc040b340u, 0x265e5a51u, 0xe9b6c7aau, 0xd62f105du, 0x02441453u, 0xd8a1e681u, 0xe7d3fbc8u,
  0x21e1cde6u, 0xc33707d6u, 0xf4d50d87u, 0x455a14edu, 0xa9e3e905u, 0xfcefa3f8u, 0x676f02d9u, 0x8d2a4c8au,
  0xfffa3942u, 0x8771f681u, 0x6d9d6122u, 0xfde5380cu, 0xa4beea44u, 0x4bdecfa9u, 0xf6bb4b60u, 0xbebfbc70u,
  0x289b7ec6u, 0xeaa127fau, 0xd4ef3085u, 0x04881d05u, 0xd9d4d039u, 0xe6db99e5u, 0x1fa27cf8u, 0xc4ac5665u,
  0xf4292244u, 0x432aff97u, 0xab9423a7u, 0xfc93a039u, 0x655b59c3u, 0x8f0ccc92u, 0xffeff47du, 0x85845dd1u,
  0x6fa87e4fu, 0xfe2ce6e0u, 0xa3014314u, 0x4e0811a1u, 0xf7537e82u, 0xbd3af235u, 0x2ad7d2bbu, 0xeb86d391u
};
static const uint8_t k_md5_r[16] = { 7, 12, 17, 22, 5, 9, 14, 20, 4, 11, 16, 23, 6, 10, 15, 21 };

static void md5_block(pem_md5 *m, const uint8_t *p)
{
  uint32_t w[16], a = m->h[0], b = m->h[1], c = m->h[2], d = m->h[3];
  unsigned i;
  for (i = 0; i < 16; i++)
    w[i] = (uint32_t)p[4 * i] | ((uint32_t)p[4 * i + 1] << 8) | ((uint32_t)p[4 * i + 2] << 16) | ((uint32_t)p[4 * i + 3] << 24);
  for (i = 0; i < 64; i++) {
    uint32_t f, t;
    unsigned g, s;
    if (i < 16) { f = (b & c) | (~b & d); g = i; }
    else if (i < 32) { f = (d & b) | (~d & c); g = (5 * i + 1) & 15; }
    else if (i < 48) { f = b ^ c ^ d; g = (3 * i + 5) & 15; }
    else { f = c ^ (b | ~d); g = (7 * i) & 15; }
    s = k_md5_r[(i >> 4) * 4 + (i & 3)];
    t = a + f + k_md5_k[i] + w[g];
    a = d;
    d = c;
    c = b;
    b = b + ((t << s) | (t >> (32 - s)));
  }
  m->h[0] += a; m->h[1] += b; m->h[2] += c; m->h[3] += d;
  sd_secure_zero(w, sizeof(w));
}

static void md5_init(pem_md5 *m)
{
  m->h[0] = 0x67452301u; m->h[1] = 0xefcdab89u; m->h[2] = 0x98badcfeu; m->h[3] = 0x10325476u;
  m->len = 0;
  m->n = 0;
}

static void md5_update(pem_md5 *m, const void *data, size_t n)
{
  const uint8_t *p = (const uint8_t *)data;
  m->len += n;
  while (n) {
    size_t take = SD_MIN(n, 64 - m->n);
    memcpy(m->buf + m->n, p, take);
    m->n += take;
    p += take;
    n -= take;
    if (m->n == 64) { md5_block(m, m->buf); m->n = 0; }
  }
}

static void md5_final(pem_md5 *m, uint8_t out[16])
{
  uint64_t bits = m->len * 8u;
  uint8_t pad = 0x80, z = 0, lenb[8];
  unsigned i;
  md5_update(m, &pad, 1);
  while (m->n != 56) md5_update(m, &z, 1);
  for (i = 0; i < 8; i++) lenb[i] = (uint8_t)(bits >> (8 * i));
  md5_update(m, lenb, 8);
  for (i = 0; i < 16; i++) out[i] = (uint8_t)(m->h[i >> 2] >> (8 * (i & 3)));
  sd_secure_zero(m, sizeof(*m));
}

/* Exposed for the unit tests (RFC 1321 vectors). */
void ssh_pem_md5(const void *p, size_t n, uint8_t out[16]);
void ssh_pem_md5(const void *p, size_t n, uint8_t out[16])
{
  pem_md5 m;
  md5_init(&m);
  md5_update(&m, p, n);
  md5_final(&m, out);
}

/* EVP_BytesToKey(MD5, salt = first 8 IV bytes, count 1). */
static void bytes_to_key(const char *pass, size_t plen, const uint8_t salt[8], uint8_t *key, size_t klen)
{
  uint8_t d[16];
  size_t got = 0;
  int first = 1;
  while (got < klen) {
    pem_md5 h;
    size_t take;
    md5_init(&h);
    if (!first) md5_update(&h, d, 16);
    md5_update(&h, pass, plen);
    md5_update(&h, salt, 8);
    md5_final(&h, d);
    take = SD_MIN((size_t)16, klen - got);
    memcpy(key + got, d, take);
    got += take;
    first = 0;
  }
  sd_secure_zero(d, sizeof(d));
}

static sd_err dek_decrypt(pem_file *f, const char *pass, size_t plen)
{
  size_t klen, block;
  const char *name;
  uint8_t key[32];
  sd_err e;
  if (!cbc_params(f->dek_alg, &klen, &block, &name)) return SD_E_KEY_UNSUPPORTED;
  if (f->dek_iv_len != block || f->der_len % block) return SD_E_KEY_FORMAT;
  if (!pass) return SD_E_KEY_PASSPHRASE_REQUIRED;
  if (!ssh_crypto_ready()) return SD_E_UNSUPPORTED;
  bytes_to_key(pass, plen, f->dek_iv, key, klen);
  e = cbc_decrypt(name, key, f->dek_iv, f->der, f->der_len);
  sd_secure_zero(key, sizeof(key));
  if (e != SD_OK) return e;
  if (!unpad_pkcs7(f->der, &f->der_len, block)) return SD_E_BAD_PASSPHRASE;
  return SD_OK;
}

static int prf_hash(sd_span oid, sd_hash_alg *h)
{
  if (ssh_der_oid_is(oid, "1.2.840.113549.2.7")) { *h = SD_HASH_SHA1; return 1; }
  if (ssh_der_oid_is(oid, "1.2.840.113549.2.9")) { *h = SD_HASH_SHA256; return 1; }
  if (ssh_der_oid_is(oid, "1.2.840.113549.2.10")) { *h = SD_HASH_SHA384; return 1; }
  if (ssh_der_oid_is(oid, "1.2.840.113549.2.11")) { *h = SD_HASH_SHA512; return 1; }
  return 0;   /* hmacWithSHA224 (1.2.840.113549.2.8) and others */
}

static int enc_scheme(sd_span oid, size_t *key_len, size_t *block, const char **name)
{
  if (ssh_der_oid_is(oid, "2.16.840.1.101.3.4.1.2")) { *key_len = 16; *block = 16; *name = "AES-128-CBC"; return 1; }
  if (ssh_der_oid_is(oid, "2.16.840.1.101.3.4.1.22")) { *key_len = 24; *block = 16; *name = "AES-192-CBC"; return 1; }
  if (ssh_der_oid_is(oid, "2.16.840.1.101.3.4.1.42")) { *key_len = 32; *block = 16; *name = "AES-256-CBC"; return 1; }
  if (ssh_der_oid_is(oid, "1.2.840.113549.3.7")) { *key_len = 24; *block = 8; *name = "DES-EDE3-CBC"; return 1; }
  return 0;
}

/* EncryptedPrivateKeyInfo -> PKCS#8 PrivateKeyInfo, in place in f->der. probe_only: parse only. */
static sd_err pbes2_decrypt(pem_file *f, const char *pass, size_t plen, int probe_only)
{
  ssh_der d, s, alg, params, kdf, kdfp, enc;
  sd_span oid, kdf_oid, salt, enc_oid, iv, data;
  uint32_t iter, keylen = 0;
  sd_hash_alg h = SD_HASH_SHA1;
  size_t klen, block;
  const char *name;
  uint8_t key[32];
  sd_secbuf *plain = NULL;
  sd_err e;
  ssh_der_init(&d, f->der, f->der_len);
  s = ssh_der_enter(&d, SSH_DER_SEQUENCE);
  alg = ssh_der_enter(&s, SSH_DER_SEQUENCE);
  oid = ssh_der_tlv(&alg, SSH_DER_OID);
  if (!ssh_der_ok(&alg)) return SD_E_KEY_FORMAT;
  if (!ssh_der_oid_is(oid, "1.2.840.113549.1.5.13")) return SD_E_KEY_UNSUPPORTED;   /* PBES1, PKCS#12 PBE */
  params = ssh_der_enter(&alg, SSH_DER_SEQUENCE);
  kdf = ssh_der_enter(&params, SSH_DER_SEQUENCE);
  kdf_oid = ssh_der_tlv(&kdf, SSH_DER_OID);
  if (!ssh_der_ok(&kdf)) return SD_E_KEY_FORMAT;
  if (!ssh_der_oid_is(kdf_oid, "1.2.840.113549.1.5.12")) return SD_E_KEY_UNSUPPORTED;   /* scrypt, ... */
  kdfp = ssh_der_enter(&kdf, SSH_DER_SEQUENCE);
  salt = ssh_der_tlv(&kdfp, SSH_DER_OCTET_STRING);
  iter = ssh_der_small(&kdfp);
  if (ssh_der_peek(&kdfp, SSH_DER_INTEGER)) keylen = ssh_der_small(&kdfp);
  if (ssh_der_peek(&kdfp, SSH_DER_SEQUENCE)) {
    ssh_der prf = ssh_der_enter(&kdfp, SSH_DER_SEQUENCE);
    sd_span prf_oid = ssh_der_tlv(&prf, SSH_DER_OID);
    if (ssh_der_peek(&prf, SSH_DER_NULL)) (void)ssh_der_tlv(&prf, SSH_DER_NULL);
    if (!ssh_der_done(&prf)) return SD_E_KEY_FORMAT;
    if (!prf_hash(prf_oid, &h)) return SD_E_KEY_UNSUPPORTED;
  }
  enc = ssh_der_enter(&params, SSH_DER_SEQUENCE);
  enc_oid = ssh_der_tlv(&enc, SSH_DER_OID);
  iv = ssh_der_tlv(&enc, SSH_DER_OCTET_STRING);
  data = ssh_der_tlv(&s, SSH_DER_OCTET_STRING);
  if (!ssh_der_done(&kdfp) || !ssh_der_done(&kdf) || !ssh_der_done(&enc) || !ssh_der_done(&params) ||
      !ssh_der_done(&alg) || !ssh_der_done(&s) || !ssh_der_done(&d))
    return SD_E_KEY_FORMAT;
  if (!enc_scheme(enc_oid, &klen, &block, &name)) return SD_E_KEY_UNSUPPORTED;
  if (iv.n != block || data.n == 0 || data.n % block || salt.n == 0 || iter == 0 || (keylen && keylen != klen))
    return SD_E_KEY_FORMAT;
  if (iter > PEM_MAX_ITER) return SD_E_KEY_UNSUPPORTED;
  if (probe_only) return SD_OK;
  if (!pass) return SD_E_KEY_PASSPHRASE_REQUIRED;
  if (!ssh_crypto_ready()) return SD_E_UNSUPPORTED;
  e = sd_pbkdf2_hmac(h, pass, plen, salt.p, salt.n, iter, key, klen);
  if (e == SD_OK) e = sd_secbuf_from(data.p, data.n, &plain);
  if (e == SD_OK) {
    uint8_t ivc[16];
    memcpy(ivc, iv.p, block);
    e = cbc_decrypt(name, key, ivc, plain->p, plain->len);
  }
  sd_secure_zero(key, sizeof(key));
  if (e == SD_OK) {
    size_t n = plain->len;
    if (!unpad_pkcs7(plain->p, &n, block)) e = SD_E_BAD_PASSPHRASE;
    else {
      memcpy(f->der, plain->p, n);
      sd_secure_zero(f->der + n, f->der_len - n);
      f->der_len = n;
    }
  }
  sd_secbuf_free(plain);
  return e;
}

static sd_err parse_body(pem_kind kind, const uint8_t *der, size_t n, sd_ssh_key **out)
{
  sd_span s;
  s.p = der;
  s.n = n;
  switch (kind) {
  case PEM_RSA: return parse_pkcs1(s, out);
  case PEM_EC: return parse_sec1(s, 0, out);
  case PEM_PKCS8:
  case PEM_PKCS8_ENC: return parse_pkcs8(s, out);
  default: return SD_E_KEY_UNSUPPORTED;
  }
}

sd_err ssh_pem_load(const uint8_t *bytes, size_t len, const char *pass, size_t pass_len, sd_ssh_key **out)
{
  pem_file f;
  int encrypted;
  sd_err e = pem_decode(bytes, len, &f);
  *out = NULL;
  if (e != SD_OK) return e;
  encrypted = f.dek || f.kind == PEM_PKCS8_ENC;
  if (f.dek) e = dek_decrypt(&f, pass, pass_len);
  else if (f.kind == PEM_PKCS8_ENC) e = pbes2_decrypt(&f, pass, pass_len, 0);
  if (e == SD_OK) {
    e = parse_body(f.kind, f.der, f.der_len, out);
    /* after a decryption, a structure that does not parse means a wrong passphrase */
    if (encrypted && e == SD_E_KEY_FORMAT) e = SD_E_BAD_PASSPHRASE;
  }
  pem_free(&f);
  return e;
}

sd_err ssh_pem_probe(const uint8_t *bytes, size_t len, sd_ssh_key_probe_info *out)
{
  pem_file f;
  sd_err e = pem_decode(bytes, len, &f);
  memset(out, 0, sizeof(*out));
  if (e != SD_OK) return e;
  out->format = (f.kind == PEM_PKCS8 || f.kind == PEM_PKCS8_ENC) ? SD_KEYFMT_PKCS8 : SD_KEYFMT_PEM;
  if (f.dek || f.kind == PEM_PKCS8_ENC) {
    out->encrypted = 1;
    if (f.kind == PEM_PKCS8_ENC) e = pbes2_decrypt(&f, NULL, 0, 1);
    else {
      size_t kl, bl;
      const char *nm;
      if (!cbc_params(f.dek_alg, &kl, &bl, &nm)) e = SD_E_KEY_UNSUPPORTED;
    }
    if (f.kind == PEM_RSA) memcpy(out->type, "ssh-rsa", 8);
    pem_free(&f);
    return e;
  }
  {
    sd_ssh_key *k = NULL;
    e = parse_body(f.kind, f.der, f.der_len, &k);
    if (e == SD_OK) {
      ssh_span_copy(ssh_blob_key_type(k->pub, k->pub_len), out->type, sizeof(out->type));
      ssh_probe_fill_from_pub(out, k->pub, k->pub_len);
      sd_ssh_key_free(k);
    }
  }
  pem_free(&f);
  return e;
}
