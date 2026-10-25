/* Key objects and format detection (01 §6.6). Format detection uses the first non-blank line. No
 * transport dependency: the CLI and UI link this unit. */
#include <string.h>

#include "sd_base/sd_mem.h"
#include "sd_crypto/sd_crypto.h"
#include "sd_ssh/sd_known_hosts.h"
#include "keyfile_internal.h"
#include "ssh_internal.h"

/* ---- curves ---- */

uint32_t ssh_curve_from_name(sd_span name)
{
  if (ssh_span_eq(name, "nistp256")) return 256;
  if (ssh_span_eq(name, "nistp384")) return 384;
  if (ssh_span_eq(name, "nistp521")) return 521;
  return 0;
}

const char *ssh_curve_name(uint32_t curve)
{
  return curve == 256 ? "nistp256" : curve == 384 ? "nistp384" : curve == 521 ? "nistp521" : "";
}

size_t ssh_curve_bytes(uint32_t curve) { return curve == 256 ? 32u : curve == 384 ? 48u : curve == 521 ? 66u : 0u; }

/* ---- public blobs ---- */

static uint32_t mag_bits(sd_span m)
{
  uint32_t b;
  uint8_t top;
  if (m.n == 0) return 0;
  top = m.p[0];
  b = (uint32_t)(m.n - 1) * 8u;
  while (top) { b++; top >>= 1; }
  return b;
}

sd_err ssh_pubblob_info(const uint8_t *blob, size_t len, ssh_kt *kt, uint32_t *bits, uint32_t *curve)
{
  sd_rd r;
  sd_span type;
  ssh_kt k = SSH_KT_NONE;
  uint32_t b = 0, c = 0;
  if (!blob || len == 0) return SD_E_KEY_FORMAT;
  sd_rd_init(&r, blob, len);
  type = sd_rd_string(&r, 64);
  if (!sd_rd_ok(&r) || type.n == 0) return SD_E_KEY_FORMAT;
  if (ssh_span_eq(type, "ssh-ed25519")) {
    sd_span pk = sd_rd_string(&r, 64);
    if (!sd_rd_done(&r) || pk.n != 32) return SD_E_KEY_FORMAT;
    k = SSH_KT_ED25519;
    b = 256;
  } else if (type.n > 11 && memcmp(type.p, "ecdsa-sha2-", 11) == 0) {
    sd_span cn = sd_rd_string(&r, 64), q = sd_rd_string(&r, 256);
    sd_span suffix;
    size_t cb;
    suffix.p = type.p + 11;
    suffix.n = type.n - 11;
    c = ssh_curve_from_name(suffix);
    if (!c) return SD_E_KEY_UNSUPPORTED;
    cb = ssh_curve_bytes(c);
    if (!sd_rd_done(&r) || ssh_curve_from_name(cn) != c || q.n != 1 + 2 * cb || q.p[0] != 0x04) return SD_E_KEY_FORMAT;
    k = SSH_KT_ECDSA;
    b = c;
  } else if (ssh_span_eq(type, "ssh-rsa")) {
    sd_span e = sd_rd_mpint(&r, 64), n = sd_rd_mpint(&r, SSH_RSA_MAX_BYTES + 1);
    if (!sd_rd_done(&r) || e.n == 0 || n.n == 0 || !(e.p[e.n - 1] & 1) || !(n.p[n.n - 1] & 1)) return SD_E_KEY_FORMAT;
    b = mag_bits(n);
    if (b < SSH_RSA_MIN_BITS || b > SSH_RSA_MAX_BITS || (e.n == 1 && e.p[0] < 3)) return SD_E_KEY_UNSUPPORTED;
    k = SSH_KT_RSA;
  } else {
    return SD_E_KEY_UNSUPPORTED;
  }
  if (kt) *kt = k;
  if (bits) *bits = b;
  if (curve) *curve = c;
  return SD_OK;
}

void ssh_probe_fill_from_pub(sd_ssh_key_probe_info *out, const uint8_t *blob, size_t len)
{
  sd_span t;
  uint32_t bits = 0;
  out->pub_len = 0;
  out->fp_sha256[0] = '\0';
  if (!blob || !len || len > sizeof(out->pub_blob)) return;
  t = ssh_blob_key_type(blob, len);
  if (t.n && !out->type[0]) ssh_span_copy(t, out->type, sizeof(out->type));
  if (ssh_pubblob_info(blob, len, NULL, &bits, NULL) == SD_OK) out->bits = bits;
  memcpy(out->pub_blob, blob, len);
  out->pub_len = len;
  if (sd_hostkey_fingerprint_sha256(blob, len, out->fp_sha256) != SD_OK) out->fp_sha256[0] = '\0';
}

int ssh_key_pub_equal(const sd_ssh_key *k, const uint8_t *blob, size_t len)
{
  return k && blob && k->pub_len == len && memcmp(k->pub, blob, len) == 0;
}

/* ---- detection ---- */

typedef enum kf_kind { KF_UNKNOWN, KF_OPENSSH, KF_PEM, KF_PPK, KF_OTHER_KNOWN } kf_kind;

static int has_prefix(const uint8_t *p, size_t n, const char *s)
{
  size_t l = strlen(s);
  return n >= l && memcmp(p, s, l) == 0;
}

static kf_kind detect(const uint8_t *bytes, size_t len)
{
  size_t i = 0;
  const uint8_t *p;
  size_t n;
  if (len >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF) i = 3;   /* UTF-8 BOM */
  while (i < len && (bytes[i] == ' ' || bytes[i] == '\t' || bytes[i] == '\r' || bytes[i] == '\n')) i++;
  p = bytes + i;
  n = len - i;
  if (has_prefix(p, n, "-----BEGIN OPENSSH PRIVATE KEY-----")) return KF_OPENSSH;
  if (has_prefix(p, n, "-----BEGIN RSA PRIVATE KEY-----") || has_prefix(p, n, "-----BEGIN EC PRIVATE KEY-----") ||
      has_prefix(p, n, "-----BEGIN PRIVATE KEY-----") || has_prefix(p, n, "-----BEGIN ENCRYPTED PRIVATE KEY-----") ||
      has_prefix(p, n, "-----BEGIN DSA PRIVATE KEY-----"))
    return KF_PEM;
  if (has_prefix(p, n, "PuTTY-User-Key-File-")) return KF_PPK;
  if (has_prefix(p, n, "-----BEGIN ") || has_prefix(p, n, "---- BEGIN SSH2")) return KF_OTHER_KNOWN;
  if (has_prefix(p, n, "SDKEY1")) return KF_OTHER_KNOWN;   /* DPAPI image: unprotect first */
  return KF_UNKNOWN;
}

sd_err sd_ssh_key_probe(const uint8_t *bytes, size_t len, sd_ssh_key_probe_info *out)
{
  if (!out) return SD_E_INVALID_PARAM;
  memset(out, 0, sizeof(*out));
  if (!bytes || len == 0 || len > SSH_KEY_MAX_FILE) return SD_E_KEY_FORMAT;
  switch (detect(bytes, len)) {
  case KF_OPENSSH: return ssh_ossh_probe(bytes, len, out);
  case KF_PEM: return ssh_pem_probe(bytes, len, out);
  case KF_PPK: return ssh_ppk_probe(bytes, len, out);
  case KF_OTHER_KNOWN: return SD_E_KEY_UNSUPPORTED;
  default: return SD_E_KEY_FORMAT;
  }
}

sd_err sd_ssh_key_load(const uint8_t *bytes, size_t len, const char *pass, size_t pass_len, sd_ssh_key **out)
{
  if (!out) return SD_E_INVALID_PARAM;
  *out = NULL;
  if (!bytes || len == 0 || len > SSH_KEY_MAX_FILE) return SD_E_KEY_FORMAT;
  switch (detect(bytes, len)) {
  case KF_OPENSSH: return ssh_ossh_load(bytes, len, pass, pass_len, out);
  case KF_PEM: return ssh_pem_load(bytes, len, pass, pass_len, out);
  case KF_PPK: return ssh_ppk_load(bytes, len, pass, pass_len, out);
  case KF_OTHER_KNOWN: return SD_E_KEY_UNSUPPORTED;
  default: return SD_E_KEY_FORMAT;
  }
}

/* ---- object ---- */

void sd_ssh_key_free(sd_ssh_key *k)
{
  if (!k) return;
  sd_free(k->pub);
  sd_secbuf_free(k->priv);
  if (k->comment) sd_secure_free(k->comment, strlen(k->comment) + 1);
  sd_free(k->cert);
  sd_rsa_free(k->rsa);
  sd_ec_free(k->ec);
  sd_free(k);
}

const uint8_t *sd_ssh_key_public_blob(const sd_ssh_key *k, size_t *len)
{
  if (!k) { if (len) *len = 0; return NULL; }
  if (len) *len = k->pub_len;
  return k->pub;
}

const char *sd_ssh_key_type(const sd_ssh_key *k) { return k ? k->type : NULL; }
uint32_t sd_ssh_key_bits(const sd_ssh_key *k) { return k ? k->bits : 0; }
const char *sd_ssh_key_comment(const sd_ssh_key *k) { return k && k->comment ? k->comment : ""; }

const uint8_t *sd_ssh_key_cert_blob(const sd_ssh_key *k, size_t *len)
{
  if (!k || !k->cert) { if (len) *len = 0; return NULL; }
  if (len) *len = k->cert_len;
  return k->cert;
}

sd_err sd_ssh_key_attach_cert(sd_ssh_key *k, const uint8_t *cert, size_t cert_len)
{
  uint8_t plain[1024];
  size_t pl = 0;
  sd_span t;
  uint8_t *copy;
  sd_err e;
  if (!k || !cert || !cert_len) return SD_E_INVALID_PARAM;
  e = ssh_cert_plain_pub(cert, cert_len, plain, sizeof(plain), &pl);
  if (e != SD_OK) return e;
  if (!ssh_key_pub_equal(k, plain, pl)) return SD_E_KEY_FORMAT;
  t = ssh_blob_key_type(cert, cert_len);
  copy = (uint8_t *)sd_alloc(cert_len);
  if (!copy) return SD_E_NO_MEMORY;
  memcpy(copy, cert, cert_len);
  sd_free(k->cert);
  k->cert = copy;
  k->cert_len = cert_len;
  if (!ssh_span_copy(t, k->cert_type, sizeof(k->cert_type))) k->cert_type[0] = '\0';
  return SD_OK;
}

sd_err sd_ssh_key_serialize_openssh(const sd_ssh_key *k, sd_secbuf **out)
{
  if (!k || !out) return SD_E_INVALID_PARAM;
  *out = NULL;
  return ssh_ossh_serialize(k, out);
}
