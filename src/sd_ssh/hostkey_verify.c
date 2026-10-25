/* Public host keys, signature verification and OpenSSH host certificates (see hostkey_internal.h).
 * Public data only; no transport dependency (linked by the CLI/UI with known_hosts.c). */
#include <string.h>

#include "sd_base/sd_mem.h"
#include "hostkey_internal.h"
#include "ssh_internal.h"

static int span_is(sd_span s, const char *z)
{
  size_t n = strlen(z);
  return s.n == n && memcmp(s.p, z, n) == 0;
}

static const struct { const char *type, *curve_name; sd_curve curve; uint32_t bits; } k_curves[] = {
  { "ecdsa-sha2-nistp256", "nistp256", SD_CURVE_P256, 256 },
  { "ecdsa-sha2-nistp384", "nistp384", SD_CURVE_P384, 384 },
  { "ecdsa-sha2-nistp521", "nistp521", SD_CURVE_P521, 521 }
};

void ssh_pubkey_free(ssh_pubkey *k)
{
  if (!k) return;
  if (k->ec) sd_ec_free(k->ec);
  if (k->rsa) sd_rsa_free(k->rsa);
  memset(k, 0, sizeof(*k));
}

/* Parses the key fields after the type string (shared by plain keys and certificates). */
static sd_err parse_key_fields(sd_rd *r, sd_span type, ssh_pubkey *out)
{
  size_t i;
  memset(out, 0, sizeof(*out));
  if (span_is(type, "ssh-ed25519")) {
    sd_span pk = sd_rd_string(r, 64);
    if (!sd_rd_ok(r) || pk.n != 32) return SD_E_KEY_FORMAT;
    out->kind = SSH_PK_ED25519;
    memcpy(out->ed, pk.p, 32);
    out->bits = 256;
    memcpy(out->type, "ssh-ed25519", 12);
    return SD_OK;
  }
  for (i = 0; i < SD_COUNTOF(k_curves); i++) {
    if (span_is(type, k_curves[i].type)) {
      sd_span cn = sd_rd_string(r, 32), q = sd_rd_string(r, SD_EC_MAX_POINT_LEN);
      sd_err e;
      if (!sd_rd_ok(r) || !span_is(cn, k_curves[i].curve_name)) return SD_E_KEY_FORMAT;
      if (q.n != sd_ec_point_len(k_curves[i].curve)) return SD_E_KEY_FORMAT;
      e = sd_ec_import(k_curves[i].curve, q.p, q.n, NULL, 0, &out->ec);
      if (e != SD_OK) { out->ec = NULL; return e == SD_E_CRYPTO ? SD_E_CRYPTO : SD_E_KEY_FORMAT; }
      out->kind = SSH_PK_ECDSA;
      out->curve = k_curves[i].curve;
      out->bits = k_curves[i].bits;
      memcpy(out->type, k_curves[i].type, strlen(k_curves[i].type) + 1);
      return SD_OK;
    }
  }
  if (span_is(type, "ssh-rsa")) {
    sd_rsa_import_params p;
    sd_span e = sd_rd_mpint(r, 16), n = sd_rd_mpint(r, SD_RSA_MAX_BITS / 8 + 1);
    sd_err err;
    if (!sd_rd_ok(r) || !e.n || !n.n) return SD_E_KEY_FORMAT;
    memset(&p, 0, sizeof(p));
    p.n = n.p; p.n_len = n.n;
    p.e = e.p; p.e_len = e.n;
    err = sd_rsa_import(&p, &out->rsa);
    if (err != SD_OK) { out->rsa = NULL; return err == SD_E_KEY_UNSUPPORTED ? err : SD_E_KEY_FORMAT; }
    out->kind = SSH_PK_RSA;
    out->bits = sd_rsa_bits(out->rsa);
    memcpy(out->type, "ssh-rsa", 8);
    return SD_OK;
  }
  return SD_E_KEY_UNSUPPORTED;
}

sd_err ssh_pubkey_parse(const uint8_t *blob, size_t len, ssh_pubkey *out)
{
  sd_rd r;
  sd_span type;
  sd_err e;
  memset(out, 0, sizeof(*out));
  if (!blob || !len || len > SSH_HOSTKEY_MAX) return SD_E_INVALID_PARAM;
  sd_rd_init(&r, blob, len);
  type = sd_rd_string(&r, 64);
  if (!sd_rd_ok(&r)) return SD_E_KEY_FORMAT;
  e = parse_key_fields(&r, type, out);
  if (e != SD_OK) { ssh_pubkey_free(out); return e; }
  if (!sd_rd_done(&r)) { ssh_pubkey_free(out); return SD_E_KEY_FORMAT; }
  return SD_OK;
}

sd_err ssh_pubkey_verify(const ssh_pubkey *k, const char *sig_alg, int allow_sha1, const uint8_t *sig,
                         size_t sig_len, const uint8_t *data, size_t dlen)
{
  sd_rd r;
  sd_span alg, s;
  uint8_t dig[SD_HASH_MAX_LEN];
  if (!k || !sig || !data) return SD_E_INVALID_PARAM;
  sd_rd_init(&r, sig, sig_len);
  alg = sd_rd_string(&r, 64);
  s = sd_rd_string(&r, SD_RSA_MAX_BITS / 8 + 16);
  if (!sd_rd_done(&r)) return SD_E_CRYPTO;
  if (sig_alg && !span_is(alg, sig_alg)) return SD_E_CRYPTO;
  switch (k->kind) {
  case SSH_PK_ED25519:
    if (!span_is(alg, "ssh-ed25519") || s.n != 64) return SD_E_CRYPTO;
    return sd_ed25519_verify(s.p, k->ed, data, dlen) == SD_OK ? SD_OK : SD_E_CRYPTO;
  case SSH_PK_ECDSA: {
    sd_rd sr;
    sd_span rr, ss;
    sd_hash_alg h = sd_ec_hash(k->curve);
    if (!span_is(alg, k->type)) return SD_E_CRYPTO;
    sd_rd_init(&sr, s.p, s.n);
    rr = sd_rd_mpint(&sr, SD_EC_MAX_FIELD_LEN + 1);
    ss = sd_rd_mpint(&sr, SD_EC_MAX_FIELD_LEN + 1);
    if (!sd_rd_done(&sr) || !rr.n || !ss.n) return SD_E_CRYPTO;
    sd_hash(h, data, dlen, dig);
    return sd_ecdsa_verify(k->ec, dig, sd_hash_len(h), rr.p, rr.n, ss.p, ss.n) == SD_OK ? SD_OK : SD_E_CRYPTO;
  }
  case SSH_PK_RSA: {
    sd_hash_alg h;
    size_t mlen = sd_rsa_len(k->rsa);
    uint8_t *padded;
    sd_err e;
    if (span_is(alg, "rsa-sha2-512")) h = SD_HASH_SHA512;
    else if (span_is(alg, "rsa-sha2-256")) h = SD_HASH_SHA256;
    else if (span_is(alg, "ssh-rsa") && allow_sha1) h = SD_HASH_SHA1;
    else return SD_E_CRYPTO;
    if (!s.n || s.n > mlen) return SD_E_CRYPTO;
    padded = (uint8_t *)sd_calloc(1, mlen);
    if (!padded) return SD_E_NO_MEMORY;
    memcpy(padded + (mlen - s.n), s.p, s.n);   /* OpenSSH accepts a shorter ssh-rsa blob, left-padded */
    sd_hash(h, data, dlen, dig);
    e = sd_rsa_pkcs1_verify(k->rsa, h, dig, sd_hash_len(h), padded, mlen);
    sd_free(padded);
    return e == SD_OK ? SD_OK : SD_E_CRYPTO;
  }
  default:
    return SD_E_CRYPTO;
  }
}

/* ---- certificates ---- */

static const struct { const char *cert, *plain; } k_cert_types[] = {
  { "ssh-ed25519-cert-v01@openssh.com", "ssh-ed25519" },
  { "ecdsa-sha2-nistp256-cert-v01@openssh.com", "ecdsa-sha2-nistp256" },
  { "ecdsa-sha2-nistp384-cert-v01@openssh.com", "ecdsa-sha2-nistp384" },
  { "ecdsa-sha2-nistp521-cert-v01@openssh.com", "ecdsa-sha2-nistp521" },
  { "ssh-rsa-cert-v01@openssh.com", "ssh-rsa" }
};

static const char *cert_plain_type(sd_span t)
{
  size_t i;
  for (i = 0; i < SD_COUNTOF(k_cert_types); i++)
    if (span_is(t, k_cert_types[i].cert)) return k_cert_types[i].plain;
  return NULL;
}

int ssh_blob_is_cert(const uint8_t *blob, size_t len)
{
  return cert_plain_type(ssh_blob_key_type(blob, len)) != NULL;
}

void ssh_cert_free(ssh_cert *c)
{
  if (!c) return;
  ssh_pubkey_free(&c->key);
  sd_free(c->plain);
  memset(c, 0, sizeof(*c));
}

sd_err ssh_cert_parse(const uint8_t *blob, size_t len, ssh_cert *out)
{
  sd_rd r;
  sd_span type, keyf;
  const char *plain;
  size_t key_start, plen;
  sd_err e;
  sd_wr w;
  memset(out, 0, sizeof(*out));
  if (!blob || !len || len > SSH_HOSTKEY_MAX) return SD_E_INVALID_PARAM;
  sd_rd_init(&r, blob, len);
  type = sd_rd_string(&r, 64);
  plain = sd_rd_ok(&r) ? cert_plain_type(type) : NULL;
  if (!plain) return SD_E_KEY_UNSUPPORTED;
  memcpy(out->cert_type, type.p, type.n);
  out->cert_type[type.n] = '\0';
  (void)sd_rd_string(&r, 256);                          /* nonce */
  if (!sd_rd_ok(&r)) return SD_E_KEY_FORMAT;
  key_start = len - sd_rd_remaining(&r);
  {
    sd_span pt;
    pt.p = (const uint8_t *)plain;
    pt.n = strlen(plain);
    e = parse_key_fields(&r, pt, &out->key);
  }
  if (e != SD_OK) { ssh_cert_free(out); return e; }
  keyf.p = blob + key_start;
  keyf.n = (len - sd_rd_remaining(&r)) - key_start;
  out->serial = sd_rd_u64(&r);
  out->type = sd_rd_u32(&r);
  out->key_id = sd_rd_string(&r, 4096);
  out->principals = sd_rd_string(&r, 65536);
  out->valid_after = sd_rd_u64(&r);
  out->valid_before = sd_rd_u64(&r);
  out->critical = sd_rd_string(&r, 65536);
  out->extensions = sd_rd_string(&r, 65536);
  (void)sd_rd_string(&r, 65536);                        /* reserved */
  out->sig_key = sd_rd_string(&r, SSH_HOSTKEY_MAX);
  out->signed_len = len - sd_rd_remaining(&r);
  out->signature = sd_rd_string(&r, SSH_HOSTKEY_MAX);
  if (!sd_rd_done(&r)) { ssh_cert_free(out); return SD_E_KEY_FORMAT; }
  /* plain blob: string plain_type || key fields */
  plen = strlen(plain);
  sd_wr_init(&w, SSH_HOSTKEY_MAX);
  sd_wr_string(&w, plain, plen);
  sd_wr_bytes(&w, keyf.p, keyf.n);
  if (!sd_wr_ok(&w)) { sd_wr_free(&w); ssh_cert_free(out); return SD_E_NO_MEMORY; }
  out->plain = (uint8_t *)sd_alloc(w.len);
  if (!out->plain) { sd_wr_free(&w); ssh_cert_free(out); return SD_E_NO_MEMORY; }
  memcpy(out->plain, w.p, w.len);
  out->plain_len = w.len;
  sd_wr_free(&w);
  return SD_OK;
}

static int ascii_ieq(const uint8_t *a, size_t an, const char *b)
{
  size_t i, bn = strlen(b);
  if (an != bn) return 0;
  for (i = 0; i < an; i++) {
    char x = (char)a[i], y = b[i];
    if (x >= 'A' && x <= 'Z') x = (char)(x - 'A' + 'a');
    if (y >= 'A' && y <= 'Z') y = (char)(y - 'A' + 'a');
    if (x != y) return 0;
  }
  return 1;
}

sd_err ssh_cert_check_host(const ssh_cert *c, const uint8_t *blob, const char *host, uint64_t now_unix,
                           const char **why)
{
  sd_rd r;
  int found = 0, any = 0;
  ssh_pubkey ca;
  sd_span st;
  sd_err e;
  char name[320];
  size_t hn;
  *why = NULL;
  /* host without the "[...]:port" wrapper */
  hn = strlen(host);
  if (hn >= sizeof(name)) { *why = "name too long"; return SD_E_HOSTKEY_REJECTED; }
  if (host[0] == '[') {
    const char *close = strchr(host, ']');
    if (!close) { *why = "bad name"; return SD_E_HOSTKEY_REJECTED; }
    hn = (size_t)(close - host - 1);
    memcpy(name, host + 1, hn);
  } else {
    memcpy(name, host, hn);
  }
  name[hn] = '\0';

  if (c->type != SSH_CERT_TYPE_HOST) { *why = "not a host certificate"; return SD_E_HOSTKEY_REJECTED; }
  sd_rd_init(&r, c->principals.p, c->principals.n);
  while (sd_rd_ok(&r) && sd_rd_remaining(&r)) {
    sd_span p = sd_rd_string(&r, 1024);
    if (!sd_rd_ok(&r)) break;
    any = 1;
    if (ascii_ieq(p.p, p.n, name)) found = 1;
  }
  if (!sd_rd_ok(&r)) { *why = "malformed principals"; return SD_E_HOSTKEY_REJECTED; }
  if (!any) { *why = "empty principal list"; return SD_E_HOSTKEY_REJECTED; }
  if (!found) { *why = "host name not among the principals"; return SD_E_HOSTKEY_REJECTED; }
  if (c->valid_after > now_unix + 300u) { *why = "certificate not yet valid"; return SD_E_HOSTKEY_REJECTED; }
  {
    uint64_t vb = c->valid_before > UINT64_MAX - 300u ? UINT64_MAX : c->valid_before + 300u;
    if (vb != UINT64_MAX && now_unix >= vb) { *why = "certificate expired"; return SD_E_HOSTKEY_REJECTED; }
  }
  if (c->critical.n) { *why = "unknown critical option"; return SD_E_HOSTKEY_REJECTED; }
  st = ssh_blob_key_type(c->sig_key.p, c->sig_key.n);
  if (!st.n || cert_plain_type(st)) { *why = "CA key is not a plain key"; return SD_E_HOSTKEY_REJECTED; }
  e = ssh_pubkey_parse(c->sig_key.p, c->sig_key.n, &ca);
  if (e != SD_OK) { *why = "CA key unsupported"; return SD_E_HOSTKEY_REJECTED; }
  /* ssh-rsa (SHA-1) CA signatures are refused, as OpenSSH's CASignatureAlgorithms default does */
  e = ssh_pubkey_verify(&ca, NULL, 0, c->signature.p, c->signature.n, blob, c->signed_len);
  ssh_pubkey_free(&ca);
  if (e != SD_OK) { *why = "CA signature invalid"; return SD_E_HOSTKEY_REJECTED; }
  return SD_OK;
}

sd_err ssh_blob_plain_key(const uint8_t *blob, size_t len, uint8_t **out, size_t *out_len)
{
  *out = NULL;
  *out_len = 0;
  if (!blob || !len) return SD_E_INVALID_PARAM;
  if (ssh_blob_is_cert(blob, len)) {
    ssh_cert c;
    sd_err e = ssh_cert_parse(blob, len, &c);
    if (e != SD_OK) return e;
    *out = c.plain;
    *out_len = c.plain_len;
    c.plain = NULL;
    ssh_cert_free(&c);
    return SD_OK;
  }
  *out = (uint8_t *)sd_alloc(len);
  if (!*out) return SD_E_NO_MEMORY;
  memcpy(*out, blob, len);
  *out_len = len;
  return SD_OK;
}

/* Signature algorithm a host key algorithm signs H with. */
static const char *kex_sig_alg(const char *alg)
{
  if (strcmp(alg, "rsa-sha2-512-cert-v01@openssh.com") == 0) return "rsa-sha2-512";
  if (strcmp(alg, "rsa-sha2-256-cert-v01@openssh.com") == 0) return "rsa-sha2-256";
  if (strcmp(alg, "ssh-rsa-cert-v01@openssh.com") == 0) return "ssh-rsa";
  if (strcmp(alg, "ssh-ed25519-cert-v01@openssh.com") == 0) return "ssh-ed25519";
  if (strcmp(alg, "ecdsa-sha2-nistp256-cert-v01@openssh.com") == 0) return "ecdsa-sha2-nistp256";
  if (strcmp(alg, "ecdsa-sha2-nistp384-cert-v01@openssh.com") == 0) return "ecdsa-sha2-nistp384";
  if (strcmp(alg, "ecdsa-sha2-nistp521-cert-v01@openssh.com") == 0) return "ecdsa-sha2-nistp521";
  return alg;
}

/* Blob type K_S must have for a host key algorithm. */
static const char *kex_blob_type(const char *alg)
{
  if (strcmp(alg, "rsa-sha2-512-cert-v01@openssh.com") == 0 || strcmp(alg, "rsa-sha2-256-cert-v01@openssh.com") == 0)
    return "ssh-rsa-cert-v01@openssh.com";
  if (ssh_hostkey_alg_is_cert(alg)) return alg;
  return ssh_hostkey_alg_key_type(alg);
}

sd_err ssh_hostkey_verify_kex(const char *alg, const uint8_t *ks, size_t ks_len, const uint8_t *sig,
                              size_t sig_len, const uint8_t *h, size_t hlen, uint32_t *bits)
{
  const char *bt = kex_blob_type(alg);
  const char *sa = kex_sig_alg(alg);
  sd_span t = ssh_blob_key_type(ks, ks_len);
  sd_err e;
  *bits = 0;
  if (!bt || !span_is(t, bt)) return SD_E_KEX_FAILED;
  if (ssh_hostkey_alg_is_cert(alg)) {
    ssh_cert c;
    e = ssh_cert_parse(ks, ks_len, &c);
    if (e != SD_OK) return SD_E_KEX_FAILED;
    *bits = c.key.bits;
    e = ssh_pubkey_verify(&c.key, sa, 1, sig, sig_len, h, hlen);
    ssh_cert_free(&c);
  } else {
    ssh_pubkey k;
    e = ssh_pubkey_parse(ks, ks_len, &k);
    if (e != SD_OK) return SD_E_KEX_FAILED;
    *bits = k.bits;
    e = ssh_pubkey_verify(&k, sa, 1, sig, sig_len, h, hlen);
    ssh_pubkey_free(&k);
  }
  return e == SD_OK ? SD_OK : SD_E_CRYPTO;
}

uint32_t ssh_blob_key_bits(const uint8_t *blob, size_t len)
{
  uint32_t bits = 0;
  if (ssh_blob_is_cert(blob, len)) {
    ssh_cert c;
    if (ssh_cert_parse(blob, len, &c) == SD_OK) bits = c.key.bits;
    ssh_cert_free(&c);
  } else {
    ssh_pubkey k;
    if (ssh_pubkey_parse(blob, len, &k) == SD_OK) bits = k.bits;
    ssh_pubkey_free(&k);
  }
  return bits;
}

int ssh_hostkey_alg_supported(const char *name)
{
  return ssh_hostkey_alg_key_type(name) != NULL;
}
