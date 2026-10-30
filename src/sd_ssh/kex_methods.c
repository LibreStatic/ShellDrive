/* Key exchange methods (01 §4.2): curve25519-sha256(@libssh.org), ecdh-sha2-nistp256/384/521,
 * diffie-hellman-group1/14-sha1, group14-sha256, group16/18-sha512, diffie-hellman-group-exchange-
 * sha1/sha256 and mlkem768x25519-sha256. Pure computation; the state machine is kex.c. */
#include <string.h>

#include "sd_base/sd_mem.h"
#include "hostkey_internal.h"
#include "kex_internal.h"
#include "ssh_internal.h"

static const ssh_kex_method k_methods[] = {
  { "mlkem768x25519-sha256", SSH_KM_MLKEM, SD_HASH_SHA256, 0 },
  { "curve25519-sha256", SSH_KM_C25519, SD_HASH_SHA256, 0 },
  { "curve25519-sha256@libssh.org", SSH_KM_C25519, SD_HASH_SHA256, 0 },
  { "ecdh-sha2-nistp256", SSH_KM_ECDH, SD_HASH_SHA256, SD_CURVE_P256 },
  { "ecdh-sha2-nistp384", SSH_KM_ECDH, SD_HASH_SHA384, SD_CURVE_P384 },
  { "ecdh-sha2-nistp521", SSH_KM_ECDH, SD_HASH_SHA512, SD_CURVE_P521 },
  { "diffie-hellman-group-exchange-sha256", SSH_KM_GEX, SD_HASH_SHA256, 0 },
  { "diffie-hellman-group16-sha512", SSH_KM_DH, SD_HASH_SHA512, SD_DH_GROUP16 },
  { "diffie-hellman-group18-sha512", SSH_KM_DH, SD_HASH_SHA512, SD_DH_GROUP18 },
  { "diffie-hellman-group14-sha256", SSH_KM_DH, SD_HASH_SHA256, SD_DH_GROUP14 },
  { "diffie-hellman-group14-sha1", SSH_KM_DH, SD_HASH_SHA1, SD_DH_GROUP14 },
  { "diffie-hellman-group-exchange-sha1", SSH_KM_GEX, SD_HASH_SHA1, 0 },
  { "diffie-hellman-group1-sha1", SSH_KM_DH, SD_HASH_SHA1, SD_DH_GROUP1 }
};

const ssh_kex_method *ssh_kex_method_find(const char *name)
{
  size_t i;
  for (i = 0; i < SD_COUNTOF(k_methods); i++)
    if (strcmp(k_methods[i].name, name) == 0) return &k_methods[i];
  return NULL;
}

int ssh_kex_supported(const char *name) { return ssh_kex_method_find(name) != NULL; }

struct ssh_kexm {
  const ssh_kex_method *m;
  int allow_legacy;
  /* curve25519 */
  uint8_t x_priv[32];
  /* mlkem768x25519 */
  sd_mlkem768x25519_client mk;
  /* ECDH */
  sd_ec_key *ec;
  /* DH / GEX */
  sd_dh *dh;
  int awaiting_group;
  uint8_t *gex_p; size_t gex_plen;
  uint8_t *gex_g; size_t gex_glen;
  /* our public value as hashed: Q_C (string) or e (mpint magnitude, fixed width) */
  uint8_t *q_c; size_t q_c_len;
};

void ssh_kexm_free(ssh_kexm *s)
{
  if (!s) return;
  if (s->ec) sd_ec_free(s->ec);
  if (s->dh) sd_dh_free(s->dh);
  sd_free(s->gex_p);
  sd_free(s->gex_g);
  sd_free(s->q_c);
  sd_secure_zero(s, sizeof(*s));
  sd_free(s);
}

static sd_err keep_qc(ssh_kexm *s, const uint8_t *p, size_t n)
{
  s->q_c = (uint8_t *)sd_alloc(n);
  if (!s->q_c) return SD_E_NO_MEMORY;
  memcpy(s->q_c, p, n);
  s->q_c_len = n;
  return SD_OK;
}

/* DH public value for the current group (s->dh), written as mpint into w. */
static sd_err dh_init_msg(ssh_kexm *s, uint8_t msgno, sd_wr *w)
{
  size_t len = sd_dh_len(s->dh);
  uint8_t *e = (uint8_t *)sd_alloc(len);
  sd_err err;
  if (!e) return SD_E_NO_MEMORY;
  err = sd_dh_public(s->dh, e, len);
  if (err == SD_OK) err = keep_qc(s, e, len);
  if (err == SD_OK) {
    sd_wr_u8(w, msgno);
    sd_wr_mpint(w, e, len);
  }
  sd_free(e);
  return err;
}

sd_err ssh_kexm_start(const ssh_kex_method *m, int allow_legacy, ssh_kexm **out, sd_wr *w)
{
  ssh_kexm *s;
  sd_err e = SD_OK;
  *out = NULL;
  if (!m) return SD_E_UNSUPPORTED;
  s = (ssh_kexm *)sd_calloc(1, sizeof(*s));
  if (!s) return SD_E_NO_MEMORY;
  s->m = m;
  s->allow_legacy = allow_legacy;
  switch (m->kind) {
  case SSH_KM_C25519: {
    uint8_t q[32];
    e = ssh_random(s->x_priv, 32);
    if (e == SD_OK) e = sd_x25519_base(q, s->x_priv);
    if (e == SD_OK) e = keep_qc(s, q, 32);
    if (e == SD_OK) { sd_wr_u8(w, SSH_MSG_KEXDH_INIT); sd_wr_string(w, q, 32); }
    break;
  }
  case SSH_KM_MLKEM: {
    uint8_t q[SD_MLKEM768X25519_INIT_LEN];
    e = sd_mlkem768x25519_client_init(&s->mk, q);
    if (e == SD_OK) e = keep_qc(s, q, sizeof(q));
    if (e == SD_OK) { sd_wr_u8(w, SSH_MSG_KEXDH_INIT); sd_wr_string(w, q, sizeof(q)); }
    break;
  }
  case SSH_KM_ECDH: {
    uint8_t q[SD_EC_MAX_POINT_LEN];
    size_t ql = sizeof(q);
    e = sd_ec_generate((sd_curve)m->param, &s->ec);
    if (e == SD_OK) e = sd_ec_export_pub(s->ec, q, &ql);
    if (e == SD_OK) e = keep_qc(s, q, ql);
    if (e == SD_OK) { sd_wr_u8(w, SSH_MSG_KEXDH_INIT); sd_wr_string(w, q, ql); }
    break;
  }
  case SSH_KM_DH:
    e = sd_dh_new_group(m->param, 0, &s->dh);
    if (e == SD_OK) e = dh_init_msg(s, SSH_MSG_KEXDH_INIT, w);
    break;
  case SSH_KM_GEX:
    s->awaiting_group = 1;
    sd_wr_u8(w, SSH_MSG_KEX_DH_GEX_REQUEST);
    sd_wr_u32(w, SSH_GEX_MIN);
    sd_wr_u32(w, SSH_GEX_N);
    sd_wr_u32(w, SSH_GEX_MAX);
    break;
  }
  if (e == SD_OK && !sd_wr_ok(w)) e = SD_E_NO_MEMORY;
  if (e != SD_OK) { ssh_kexm_free(s); return e; }
  *out = s;
  return SD_OK;
}

int ssh_kexm_awaiting_group(const ssh_kexm *s) { return s && s->awaiting_group; }

uint8_t ssh_kexm_reply_msg(const ssh_kexm *s)
{
  if (s && s->m->kind == SSH_KM_GEX) return s->awaiting_group ? SSH_MSG_KEX_DH_GEX_GROUP : SSH_MSG_KEX_DH_GEX_REPLY;
  return SSH_MSG_KEXDH_REPLY;
}

static uint32_t be_bits(const uint8_t *p, size_t n)
{
  uint32_t b;
  uint8_t top;
  while (n && !*p) { p++; n--; }
  if (!n) return 0;
  b = (uint32_t)(n - 1) * 8u;
  for (top = p[0]; top; top >>= 1) b++;
  return b;
}

sd_err ssh_kexm_gex_group(ssh_kexm *s, const uint8_t *msg, size_t n, sd_wr *w, uint32_t *pbits)
{
  sd_rd r;
  sd_span p, g;
  sd_dh_gex_policy pol;
  sd_err e;
  *pbits = 0;
  if (!s || !s->awaiting_group) return SD_E_PROTOCOL;
  sd_rd_init(&r, msg + 1, n - 1);
  p = sd_rd_mpint(&r, SSH_GEX_MAX / 8 + 1);
  g = sd_rd_mpint(&r, SSH_GEX_MAX / 8 + 1);
  if (!sd_rd_done(&r) || !p.n || !g.n) return SD_E_PROTOCOL;
  *pbits = be_bits(p.p, p.n);
  /* No primality test (01 §4.2): the host key signature authenticates the group. */
  memset(&pol, 0, sizeof(pol));
  pol.min_bits = s->allow_legacy ? 1024u : SSH_GEX_MIN;
  pol.max_bits = SSH_GEX_MAX;
  pol.flags = SD_DH_GEX_NO_PRIME_TEST;
  e = sd_dh_gex_validate(p.p, p.n, g.p, g.n, &pol);
  if (e != SD_OK) return SD_E_KEX_FAILED;
  e = sd_dh_new(p.p, p.n, g.p, g.n, 0, &s->dh);
  if (e != SD_OK) { s->dh = NULL; return SD_E_KEX_FAILED; }
  s->gex_p = (uint8_t *)sd_alloc(p.n);
  s->gex_g = (uint8_t *)sd_alloc(g.n);
  if (!s->gex_p || !s->gex_g) return SD_E_NO_MEMORY;
  memcpy(s->gex_p, p.p, p.n);
  s->gex_plen = p.n;
  memcpy(s->gex_g, g.p, g.n);
  s->gex_glen = g.n;
  s->awaiting_group = 0;
  e = dh_init_msg(s, SSH_MSG_KEX_DH_GEX_INIT, w);
  if (e == SD_OK && !sd_wr_ok(w)) e = SD_E_NO_MEMORY;
  return e;
}

static void wr_str(sd_wr *w, const void *p, size_t n) { sd_wr_string(w, p, n); }

sd_err ssh_kexm_finish(ssh_kexm *s, const uint8_t *msg, size_t n, const ssh_kex_hash_in *hin,
                       sd_span *ks, sd_span *sig, sd_wr *k_enc, uint8_t *h, size_t *hlen)
{
  sd_rd r;
  sd_span qs;
  sd_wr hw;
  sd_err e = SD_OK;
  const ssh_kex_method *m;
  if (!s || s->awaiting_group) return SD_E_PROTOCOL;
  m = s->m;
  sd_rd_init(&r, msg + 1, n - 1);
  *ks = sd_rd_string(&r, SSH_HOSTKEY_MAX);
  if (m->kind == SSH_KM_DH || m->kind == SSH_KM_GEX) qs = sd_rd_mpint(&r, SD_DH_MAX_BITS / 8 + 1);
  else qs = sd_rd_string(&r, 2048);
  *sig = sd_rd_string(&r, SSH_HOSTKEY_MAX);
  if (!sd_rd_done(&r) || !ks->n) return SD_E_PROTOCOL;

  /* shared secret K */
  switch (m->kind) {
  case SSH_KM_C25519: {
    uint8_t shared[32];
    if (qs.n != 32) return SD_E_PROTOCOL;
    e = sd_x25519(shared, s->x_priv, qs.p);        /* rejects an all-zero result */
    sd_secure_zero(s->x_priv, sizeof(s->x_priv));
    if (e != SD_OK) return SD_E_KEX_FAILED;
    sd_wr_mpint(k_enc, shared, 32);                 /* RFC 8731: big-endian unsigned number */
    sd_secure_zero(shared, sizeof(shared));
    break;
  }
  case SSH_KM_MLKEM: {
    uint8_t k[32];
    if (qs.n != SD_MLKEM768X25519_REPLY_LEN) { sd_mlkem768x25519_client_wipe(&s->mk); return SD_E_PROTOCOL; }
    e = sd_mlkem768x25519_client_finish(&s->mk, qs.p, k);
    if (e != SD_OK) return SD_E_KEX_FAILED;
    sd_wr_string(k_enc, k, 32);                     /* K is a string here (01 §4.2) */
    sd_secure_zero(k, sizeof(k));
    break;
  }
  case SSH_KM_ECDH: {
    uint8_t x[SD_EC_MAX_FIELD_LEN];
    size_t xl = sizeof(x);
    e = sd_ecdh(s->ec, qs.p, qs.n, x, &xl);          /* full peer point validation */
    sd_ec_free(s->ec);
    s->ec = NULL;
    if (e != SD_OK) return SD_E_KEX_FAILED;
    sd_wr_mpint(k_enc, x, xl);
    sd_secure_zero(x, sizeof(x));
    break;
  }
  case SSH_KM_DH:
  case SSH_KM_GEX: {
    size_t kl = sd_dh_len(s->dh);
    uint8_t *k = (uint8_t *)sd_alloc(kl);
    if (!k) return SD_E_NO_MEMORY;
    e = sd_dh_compute(s->dh, qs.p, qs.n, k, kl);    /* checks 1 < f < p-1 */
    if (e == SD_OK) sd_wr_mpint(k_enc, k, kl);
    sd_secure_zero(k, kl);
    sd_free(k);
    sd_dh_free(s->dh);
    s->dh = NULL;
    if (e != SD_OK) return SD_E_KEX_FAILED;
    break;
  }
  }
  if (!sd_wr_ok(k_enc)) return SD_E_NO_MEMORY;

  /* exchange hash H */
  sd_wr_init(&hw, 256u * 1024u);
  wr_str(&hw, hin->v_c, strlen(hin->v_c));
  wr_str(&hw, hin->v_s, strlen(hin->v_s));
  wr_str(&hw, hin->i_c, hin->i_c_len);
  wr_str(&hw, hin->i_s, hin->i_s_len);
  wr_str(&hw, ks->p, ks->n);
  if (m->kind == SSH_KM_GEX) {
    sd_wr_u32(&hw, SSH_GEX_MIN);
    sd_wr_u32(&hw, SSH_GEX_N);
    sd_wr_u32(&hw, SSH_GEX_MAX);
    sd_wr_mpint(&hw, s->gex_p, s->gex_plen);
    sd_wr_mpint(&hw, s->gex_g, s->gex_glen);
  }
  if (m->kind == SSH_KM_DH || m->kind == SSH_KM_GEX) {
    sd_wr_mpint(&hw, s->q_c, s->q_c_len);
    sd_wr_mpint(&hw, qs.p, qs.n);
  } else {
    wr_str(&hw, s->q_c, s->q_c_len);
    wr_str(&hw, qs.p, qs.n);
  }
  sd_wr_bytes(&hw, k_enc->p, k_enc->len);
  if (!sd_wr_ok(&hw)) { sd_wr_free(&hw); return SD_E_NO_MEMORY; }
  sd_hash(m->hash, hw.p, hw.len, h);
  *hlen = sd_hash_len(m->hash);
  sd_secure_zero(hw.p, hw.len);
  sd_wr_free(&hw);
  return SD_OK;
}

void ssh_kex_derive(sd_hash_alg hash, const uint8_t *k_enc, size_t k_len, const uint8_t *h, size_t hlen,
                    char x, const uint8_t *sid, size_t sid_len, uint8_t *out, size_t need)
{
  uint8_t acc[192];
  size_t have, dl = sd_hash_len(hash);
  sd_hash_ctx hc;
  sd_hash_init(&hc, hash);
  sd_hash_update(&hc, k_enc, k_len);
  sd_hash_update(&hc, h, hlen);
  sd_hash_update(&hc, &x, 1);
  sd_hash_update(&hc, sid, sid_len);
  sd_hash_final(&hc, acc);
  have = dl;
  while (have < need && have + dl <= sizeof(acc)) {
    sd_hash_init(&hc, hash);
    sd_hash_update(&hc, k_enc, k_len);
    sd_hash_update(&hc, h, hlen);
    sd_hash_update(&hc, acc, have);
    sd_hash_final(&hc, acc + have);
    have += dl;
  }
  memcpy(out, acc, need);
  sd_secure_zero(acc, sizeof(acc));
}
