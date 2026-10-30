/* Key construction with consistency checks, and signatures for publickey auth (01 §6.2, §6.6):
 * ssh-ed25519, ecdsa-sha2-nistp{256,384,521} (RFC 5656), RSA with ssh-rsa / rsa-sha2-256 /
 * rsa-sha2-512 (RFC 8332). The math is sd_crypto's (sd_crypto_pk.h); the SSH encodings are ours.
 * No transport dependency. */
#include <stdio.h>
#include <string.h>

#include "sd_base/sd_mem.h"
#include "sd_crypto/sd_crypto.h"
#include "keyfile_internal.h"
#include "ssh_internal.h"

static sd_err set_comment(sd_ssh_key *k, sd_span comment)
{
  k->comment = (char *)sd_alloc(comment.n + 1);
  if (!k->comment) return SD_E_NO_MEMORY;
  if (comment.n) memcpy(k->comment, comment.p, comment.n);
  k->comment[comment.n] = '\0';
  return SD_OK;
}

static sd_err set_pub(sd_ssh_key *k, sd_wr *w)
{
  if (!sd_wr_ok(w)) { sd_wr_free(w); return SD_E_NO_MEMORY; }
  k->pub = (uint8_t *)sd_alloc(w->len);
  if (!k->pub) { sd_wr_free(w); return SD_E_NO_MEMORY; }
  memcpy(k->pub, w->p, w->len);
  k->pub_len = w->len;
  sd_wr_free(w);
  return SD_OK;
}

sd_err ssh_key_new_ed25519(const uint8_t seed[32], const uint8_t *pub32, sd_span comment, sd_ssh_key **out)
{
  uint8_t pub[32];
  sd_ssh_key *k;
  sd_wr w;
  sd_err e;
  *out = NULL;
  if (ssh_crypto_ready()) {
    e = sd_ed25519_pub_from_seed(pub, seed);
    if (e != SD_OK) return e;
    if (pub32 && memcmp(pub, pub32, 32) != 0) return SD_E_KEY_FORMAT;
  } else {
    if (!pub32) return SD_E_UNSUPPORTED;
    memcpy(pub, pub32, 32);
  }
  k = (sd_ssh_key *)sd_calloc(1, sizeof(*k));
  if (!k) return SD_E_NO_MEMORY;
  k->kt = SSH_KT_ED25519;
  memcpy(k->type, "ssh-ed25519", 12);
  k->bits = 256;
  sd_wr_init(&w, 256);
  sd_wr_cstring(&w, "ssh-ed25519");
  sd_wr_string(&w, pub, 32);
  e = set_pub(k, &w);
  if (e == SD_OK) e = set_comment(k, comment);
  if (e == SD_OK) e = sd_secbuf_new(64, &k->priv);
  if (e != SD_OK) { sd_ssh_key_free(k); return e; }
  memcpy(k->priv->p, seed, 32);
  memcpy(k->priv->p + 32, pub, 32);
  k->priv->len = 64;
  *out = k;
  return SD_OK;
}

static sd_curve to_curve(uint32_t c) { return c == 256 ? SD_CURVE_P256 : c == 384 ? SD_CURVE_P384 : SD_CURVE_P521; }

sd_err ssh_key_new_ecdsa(uint32_t curve, sd_span q, sd_span d, sd_span comment, sd_ssh_key **out)
{
  size_t fl = ssh_curve_bytes(curve);
  uint8_t qbuf[SD_EC_MAX_POINT_LEN];
  size_t ql = sizeof(qbuf);
  sd_ssh_key *k;
  sd_wr w;
  char type[48];
  sd_err e;
  *out = NULL;
  while (d.n > 0 && d.p[0] == 0) { d.p++; d.n--; }
  if (!fl || d.n == 0 || d.n > fl) return SD_E_KEY_FORMAT;
  if (q.n && (q.n != 1 + 2 * fl || q.p[0] != 0x04)) return SD_E_KEY_FORMAT;
  k = (sd_ssh_key *)sd_calloc(1, sizeof(*k));
  if (!k) return SD_E_NO_MEMORY;
  k->kt = SSH_KT_ECDSA;
  k->curve = curve;
  k->bits = curve;
  e = sd_secbuf_new(fl, &k->priv);
  if (e != SD_OK) { sd_ssh_key_free(k); return e; }
  memcpy(k->priv->p + (fl - d.n), d.p, d.n);
  k->priv->len = fl;
  if (ssh_crypto_ready()) {
    e = sd_ec_import(to_curve(curve), q.n ? q.p : NULL, q.n, k->priv->p, fl, &k->ec);
    if (e == SD_E_CRYPTO) e = SD_E_KEY_FORMAT;
    if (e == SD_OK) e = sd_ec_export_pub(k->ec, qbuf, &ql);
  } else if (q.n) {
    memcpy(qbuf, q.p, q.n);
    ql = q.n;
    e = SD_OK;
  } else {
    e = SD_E_UNSUPPORTED;
  }
  if (e != SD_OK) { sd_ssh_key_free(k); return e; }
  _snprintf_s(type, sizeof(type), _TRUNCATE, "ecdsa-sha2-%s", ssh_curve_name(curve));
  memcpy(k->type, type, strlen(type) + 1);
  sd_wr_init(&w, 512);
  sd_wr_cstring(&w, type);
  sd_wr_cstring(&w, ssh_curve_name(curve));
  sd_wr_string(&w, qbuf, ql);
  e = set_pub(k, &w);
  if (e == SD_OK) e = set_comment(k, comment);
  if (e != SD_OK) { sd_ssh_key_free(k); return e; }
  *out = k;
  return SD_OK;
}

static sd_span strip0(sd_span s)
{
  while (s.n > 0 && s.p[0] == 0) { s.p++; s.n--; }
  return s;
}

sd_err ssh_key_new_rsa(sd_span n, sd_span e_, sd_span d, sd_span iqmp, sd_span p, sd_span q, sd_span comment,
                       sd_ssh_key **out)
{
  sd_ssh_key *k;
  sd_wr w;
  sd_err e;
  uint32_t bits;
  *out = NULL;
  n = strip0(n); e_ = strip0(e_); d = strip0(d); iqmp = strip0(iqmp); p = strip0(p); q = strip0(q);
  if (!n.n || !e_.n || !d.n || !p.n || !q.n || !iqmp.n) return SD_E_KEY_FORMAT;
  if (n.n > SSH_RSA_MAX_BYTES || e_.n > 8 || d.n > n.n || p.n > n.n || q.n > n.n || iqmp.n > n.n) return SD_E_KEY_FORMAT;
  bits = (uint32_t)(n.n - 1) * 8u;
  { uint8_t t = n.p[0]; while (t) { bits++; t >>= 1; } }
  if (bits < SSH_RSA_MIN_BITS || bits > SSH_RSA_MAX_BITS) return SD_E_KEY_UNSUPPORTED;
  k = (sd_ssh_key *)sd_calloc(1, sizeof(*k));
  if (!k) return SD_E_NO_MEMORY;
  k->kt = SSH_KT_RSA;
  k->bits = bits;
  memcpy(k->type, "ssh-rsa", 8);
  if (ssh_crypto_ready()) {
    sd_rsa_import_params ip;
    memset(&ip, 0, sizeof(ip));
    ip.n = n.p; ip.n_len = n.n;
    ip.e = e_.p; ip.e_len = e_.n;
    ip.d = d.p; ip.d_len = d.n;
    ip.p = p.p; ip.p_len = p.n;
    ip.q = q.p; ip.q_len = q.n;
    ip.iqmp = iqmp.p; ip.iqmp_len = iqmp.n;
    e = sd_rsa_import(&ip, &k->rsa);
    if (e == SD_E_CRYPTO) e = SD_E_KEY_FORMAT;
    if (e == SD_OK) {
      /* sd_rsa_import does not relate e and d: one signature with verify-after-sign does (a file
         with a corrupted public exponent is rejected here instead of failing at the server) */
      uint8_t dg[32], *sig = (uint8_t *)sd_alloc(SSH_RSA_MAX_BYTES);
      size_t sl = SSH_RSA_MAX_BYTES;
      memset(dg, 0x5A, sizeof(dg));
      if (!sig) e = SD_E_NO_MEMORY;
      else {
        e = sd_rsa_pkcs1_sign(k->rsa, SD_HASH_SHA256, dg, sizeof(dg), sig, &sl);
        if (e == SD_E_CRYPTO) e = SD_E_KEY_FORMAT;
        sd_free(sig);
      }
    }
    if (e != SD_OK) { sd_ssh_key_free(k); return e; }
  }
  sd_wr_init_secret(&w, 6u * (SSH_RSA_MAX_BYTES + 8u));
  sd_wr_mpint(&w, n.p, n.n);
  sd_wr_mpint(&w, e_.p, e_.n);
  sd_wr_mpint(&w, d.p, d.n);
  sd_wr_mpint(&w, iqmp.p, iqmp.n);
  sd_wr_mpint(&w, p.p, p.n);
  sd_wr_mpint(&w, q.p, q.n);
  e = sd_wr_ok(&w) ? sd_secbuf_from(w.p, w.len, &k->priv) : SD_E_NO_MEMORY;
  sd_wr_free(&w);
  if (e != SD_OK) { k->priv = NULL; sd_ssh_key_free(k); return e; }
  sd_wr_init(&w, SSH_RSA_MAX_BYTES + 128u);
  sd_wr_cstring(&w, "ssh-rsa");
  sd_wr_mpint(&w, e_.p, e_.n);
  sd_wr_mpint(&w, n.p, n.n);
  e = set_pub(k, &w);
  if (e == SD_OK) e = set_comment(k, comment);
  if (e != SD_OK) { sd_ssh_key_free(k); return e; }
  *out = k;
  return SD_OK;
}

/* ---- signatures ---- */

/* Maps a (possibly certificate) algorithm name to the signature algorithm and hash. */
static int rsa_alg(const char *alg, const char **sig_name, sd_hash_alg *h)
{
  if (!alg || !strcmp(alg, "rsa-sha2-512") || !strcmp(alg, "rsa-sha2-512-cert-v01@openssh.com")) {
    *sig_name = "rsa-sha2-512"; *h = SD_HASH_SHA512; return 1;
  }
  if (!strcmp(alg, "rsa-sha2-256") || !strcmp(alg, "rsa-sha2-256-cert-v01@openssh.com")) {
    *sig_name = "rsa-sha2-256"; *h = SD_HASH_SHA256; return 1;
  }
  if (!strcmp(alg, "ssh-rsa") || !strcmp(alg, "ssh-rsa-cert-v01@openssh.com")) {
    *sig_name = "ssh-rsa"; *h = SD_HASH_SHA1; return 1;
  }
  return 0;
}

static int alg_matches_type(const char *alg, const char *type)
{
  size_t n = strlen(type);
  if (!alg || !strcmp(alg, type)) return 1;
  return strncmp(alg, type, n) == 0 && strcmp(alg + n, "-cert-v01@openssh.com") == 0;
}

sd_err sd_ssh_key_sign_alg(const sd_ssh_key *k, const char *alg, const uint8_t *data, size_t len, uint8_t *sig,
                           size_t sig_cap, size_t *sig_len)
{
  sd_wr w;
  sd_err e;
  if (!k || !sig || !sig_len || (!data && len)) return SD_E_INVALID_PARAM;
  if (!ssh_crypto_ready()) return SD_E_UNSUPPORTED;
  sd_wr_init_fixed(&w, sig, sig_cap);
  switch (k->kt) {
  case SSH_KT_ED25519: {
    uint8_t raw[64];
    if (!alg_matches_type(alg, k->type)) return SD_E_KEY_UNSUPPORTED;
    e = sd_ed25519_sign(raw, k->priv->p, k->priv->p + 32, data, len);
    if (e != SD_OK) return e;
    sd_wr_cstring(&w, "ssh-ed25519");
    sd_wr_string(&w, raw, 64);
    break;
  }
  case SSH_KT_ECDSA: {
    sd_curve c = to_curve(k->curve);
    sd_hash_alg h = sd_ec_hash(c);
    uint8_t dg[SD_HASH_MAX_LEN], r[SD_EC_MAX_FIELD_LEN], s[SD_EC_MAX_FIELD_LEN];
    size_t fl = sd_ec_field_len(c);
    sd_wr inner;
    uint8_t ib[2 * (SD_EC_MAX_FIELD_LEN + 5)];
    if (!alg_matches_type(alg, k->type)) return SD_E_KEY_UNSUPPORTED;
    if (!k->ec) return SD_E_UNSUPPORTED;
    sd_hash(h, data, len, dg);
    e = sd_ecdsa_sign(k->ec, h, dg, sd_hash_len(h), r, s);
    if (e != SD_OK) return e;
    sd_wr_init_fixed(&inner, ib, sizeof(ib));
    sd_wr_mpint(&inner, r, fl);
    sd_wr_mpint(&inner, s, fl);
    if (!sd_wr_ok(&inner)) return SD_E_INTERNAL;
    sd_wr_cstring(&w, k->type);
    sd_wr_string(&w, inner.p, inner.len);
    break;
  }
  case SSH_KT_RSA: {
    const char *name;
    sd_hash_alg h;
    uint8_t dg[SD_HASH_MAX_LEN];
    uint8_t *raw;
    size_t rl;
    if (!rsa_alg(alg, &name, &h)) return SD_E_KEY_UNSUPPORTED;
    if (!k->rsa) return SD_E_UNSUPPORTED;
    rl = sd_rsa_len(k->rsa);
    raw = (uint8_t *)sd_alloc(rl);
    if (!raw) return SD_E_NO_MEMORY;
    sd_hash(h, data, len, dg);
    e = sd_rsa_pkcs1_sign(k->rsa, h, dg, sd_hash_len(h), raw, &rl);
    if (e == SD_OK) {
      sd_wr_cstring(&w, name);
      sd_wr_string(&w, raw, rl);
    }
    sd_free(raw);
    if (e != SD_OK) return e;
    break;
  }
  default:
    return SD_E_KEY_UNSUPPORTED;
  }
  if (!sd_wr_ok(&w)) return SD_E_INVALID_PARAM;
  *sig_len = w.len;
  return SD_OK;
}

sd_err sd_ssh_key_sign(const sd_ssh_key *k, const uint8_t *data, size_t len, uint8_t *sig, size_t sig_cap,
                       size_t *sig_len)
{
  return sd_ssh_key_sign_alg(k, NULL, data, len, sig, sig_cap, sig_len);
}
