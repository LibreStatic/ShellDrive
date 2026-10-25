/* M2 transport: algorithm lists (D4, D33, D34, TM-R01, TM-R04), legacy classification, KEX methods
 * against an in-process mock server, host key signatures, certificates and CBC packet protection. */
#include <stdio.h>
#include <string.h>

#include "sd_base/sd_mem.h"
#include "sd_test.h"
#include "hostkey_internal.h"
#include "kex_internal.h"
#include "ssh_internal.h"
#include "test_util.h"

static int all_on(const char *n) { SD_UNUSED(n); return 1; }

static int make_server(sd_wr *w, ssh_kexinit *k, const char *kex, const char *hk, const char *enc, const char *mac)
{
  ssh_lists l;
  uint8_t cookie[16] = { 0 };
  memset(&l, 0, sizeof(l));
  memcpy(l.kex, kex, strlen(kex) + 1);
  memcpy(l.hostkey, hk, strlen(hk) + 1);
  memcpy(l.enc_c2s, enc, strlen(enc) + 1);
  memcpy(l.enc_s2c, enc, strlen(enc) + 1);
  memcpy(l.mac_c2s, mac, strlen(mac) + 1);
  memcpy(l.mac_s2c, mac, strlen(mac) + 1);
  memcpy(l.comp, "none", 5);
  sd_wr_init(w, 65536);
  ssh_kexinit_encode(w, cookie, &l);
  return sd_wr_ok(w) && ssh_kexinit_parse(w->p, w->len, k) == SD_OK;
}

static void all_input(ssh_list_input *in)
{
  memset(in, 0, sizeof(*in));
  in->initial = 1;
  in->allow_legacy = 1;
  in->cipher_available = all_on;
  in->kex_available = all_on;
  in->hostkey_available = all_on;
}

/* ---- lists ---- */

SD_TEST(tr_lists_static_order_modern_first)
{
  ssh_list_input in;
  ssh_lists l;
  ssh_list_result r;
  all_input(&in);
  SD_CHECK_EQ_INT(ssh_build_lists(&in, &l, &r), SD_OK);
  SD_CHECK_STR(l.kex,
               "mlkem768x25519-sha256,curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,"
               "ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,"
               "diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256,"
               "diffie-hellman-group14-sha1,diffie-hellman-group-exchange-sha1,diffie-hellman-group1-sha1,"
               "ext-info-c,kex-strict-c-v00@openssh.com");
  SD_CHECK_STR(l.hostkey,
               "ssh-ed25519-cert-v01@openssh.com,ecdsa-sha2-nistp256-cert-v01@openssh.com,"
               "ecdsa-sha2-nistp384-cert-v01@openssh.com,ecdsa-sha2-nistp521-cert-v01@openssh.com,"
               "rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,ssh-ed25519,"
               "ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,rsa-sha2-512,rsa-sha2-256,"
               "ssh-rsa-cert-v01@openssh.com,ssh-rsa");
  /* fallback lists (no server KEXINIT): GCM, CTR, chacha, then legacy CBC */
  SD_CHECK_STR(l.enc_c2s,
               "aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr,"
               "chacha20-poly1305@openssh.com,aes256-cbc,aes192-cbc,aes128-cbc,3des-cbc");
  SD_CHECK_STR(l.mac_c2s,
               "hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha2-512,"
               "hmac-sha1-etm@openssh.com,hmac-sha1");
  /* strict server: static order, chacha first without hardware AES */
  {
    sd_wr w;
    ssh_kexinit k;
    SD_REQUIRE(make_server(&w, &k, "curve25519-sha256,kex-strict-s-v00@openssh.com", "ssh-ed25519",
                           "aes128-ctr,chacha20-poly1305@openssh.com", "hmac-sha2-256"));
    in.server = &k;
    SD_CHECK_EQ_INT(ssh_build_lists(&in, &l, &r), SD_OK);
    SD_CHECK(r.strict);
    SD_CHECK_STR(l.enc_s2c,
                 "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,"
                 "aes192-ctr,aes128-ctr,aes256-cbc,aes192-cbc,aes128-cbc,3des-cbc");
    sd_wr_free(&w);
  }
}

SD_TEST(tr_lists_refuse_removes_legacy)
{
  ssh_list_input in;
  ssh_lists l;
  ssh_list_result r;
  static const char *const k_legacy[] = {
    "diffie-hellman-group14-sha1", "diffie-hellman-group-exchange-sha1", "diffie-hellman-group1-sha1",
    "ssh-rsa", "ssh-rsa-cert-v01@openssh.com", "aes256-cbc", "aes192-cbc", "aes128-cbc", "3des-cbc",
    "hmac-sha1", "hmac-sha1-etm@openssh.com"
  };
  size_t i;
  all_input(&in);
  in.allow_legacy = 0;
  SD_CHECK_EQ_INT(ssh_build_lists(&in, &l, &r), SD_OK);
  for (i = 0; i < SD_COUNTOF(k_legacy); i++) {
    SD_CHECK(ssh_alg_is_legacy(k_legacy[i]));
    SD_CHECK(!ssh_csv_contains(l.kex, k_legacy[i]) && !ssh_csv_contains(l.hostkey, k_legacy[i]) &&
             !ssh_csv_contains(l.enc_c2s, k_legacy[i]) && !ssh_csv_contains(l.mac_s2c, k_legacy[i]));
  }
  SD_CHECK(!ssh_alg_is_legacy("rsa-sha2-512") && !ssh_alg_is_legacy("mlkem768x25519-sha256"));
  /* a legacy-only server then has no common algorithm, and the error names the category */
  {
    sd_wr w;
    ssh_kexinit k;
    ssh_algs a;
    const char *cat = NULL;
    SD_REQUIRE(make_server(&w, &k, "diffie-hellman-group14-sha1", "ssh-rsa", "3des-cbc", "hmac-sha1"));
    in.server = &k;
    SD_CHECK_EQ_INT(ssh_build_lists(&in, &l, &r), SD_OK);
    SD_CHECK_EQ_INT(ssh_negotiate(&l, &k, &a, &cat), SD_E_KEX_FAILED);
    SD_CHECK_STR(cat, "kex");
    sd_wr_free(&w);
    in.allow_legacy = 1;
    SD_REQUIRE(make_server(&w, &k, "diffie-hellman-group14-sha1", "ssh-rsa", "3des-cbc", "hmac-sha1"));
    in.server = &k;
    SD_CHECK_EQ_INT(ssh_build_lists(&in, &l, &r), SD_OK);
    SD_CHECK_EQ_INT(ssh_negotiate(&l, &k, &a, &cat), SD_OK);
    SD_CHECK_STR(a.enc_c2s, "3des-cbc");
    SD_CHECK_STR(a.mac_c2s, "hmac-sha1");
    sd_wr_free(&w);
  }
}

SD_TEST(tr_lists_stored_types_map_to_algorithms)
{
  ssh_list_input in;
  ssh_lists l;
  ssh_list_result r;
  sd_kh_types t;
  all_input(&in);
  memset(&t, 0, sizeof(t));
  in.stored = &t;
  t.count = 1;
  memcpy(t.type[0], "ssh-rsa", 8);
  SD_CHECK_EQ_INT(ssh_build_lists(&in, &l, &r), SD_OK);
  SD_CHECK_STR(l.hostkey, "rsa-sha2-512,rsa-sha2-256,ssh-rsa");
  in.allow_legacy = 0;
  SD_CHECK_EQ_INT(ssh_build_lists(&in, &l, &r), SD_OK);
  SD_CHECK_STR(l.hostkey, "rsa-sha2-512,rsa-sha2-256");
  in.allow_legacy = 1;
  /* + @cert-authority: the cert variants of the stored types only */
  t.has_ca = 1;
  t.count = 2;
  memcpy(t.type[1], "ecdsa-sha2-nistp384", 20);
  SD_CHECK_EQ_INT(ssh_build_lists(&in, &l, &r), SD_OK);
  SD_CHECK_STR(l.hostkey,
               "ecdsa-sha2-nistp384-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,"
               "rsa-sha2-256-cert-v01@openssh.com,ecdsa-sha2-nistp384,rsa-sha2-512,rsa-sha2-256,"
               "ssh-rsa-cert-v01@openssh.com,ssh-rsa");
  /* only @cert-authority lines: certificate algorithms only */
  t.count = 0;
  SD_CHECK_EQ_INT(ssh_build_lists(&in, &l, &r), SD_OK);
  SD_CHECK(strstr(l.hostkey, "ssh-ed25519-cert-v01@openssh.com") == l.hostkey);
  SD_CHECK(!ssh_csv_contains(l.hostkey, "ssh-ed25519") && !ssh_csv_contains(l.hostkey, "rsa-sha2-512"));
  /* a stored type nobody implements: never a prompt, the connection fails (TM-R04) */
  t.has_ca = 0;
  t.count = 1;
  memcpy(t.type[0], "ssh-dss", 8);
  SD_CHECK_EQ_INT(ssh_build_lists(&in, &l, &r), SD_E_HOSTKEY_TYPE_UNAVAILABLE);
}

SD_TEST(tr_lists_terrapin_cbc_without_etm)
{
  sd_wr w;
  ssh_kexinit k;
  ssh_list_input in;
  ssh_lists l;
  ssh_list_result r;
  ssh_algs a;
  const char *cat;
  /* no strict KEX, only CBC: CBC runs with a non-ETM MAC (rule 2) */
  SD_REQUIRE(make_server(&w, &k, "curve25519-sha256", "ssh-ed25519", "aes128-cbc,aes256-cbc",
                         "hmac-sha2-256-etm@openssh.com,hmac-sha2-256,hmac-sha1"));
  all_input(&in);
  in.server = &k;
  SD_CHECK_EQ_INT(ssh_build_lists(&in, &l, &r), SD_OK);
  SD_CHECK(!r.strict && !r.terrapin_exposed && r.etm_removed);
  SD_CHECK(!ssh_csv_contains(l.mac_c2s, "hmac-sha2-256-etm@openssh.com"));
  SD_CHECK_EQ_INT(ssh_negotiate(&l, &k, &a, &cat), SD_OK);
  SD_CHECK_STR(a.enc_c2s, "aes256-cbc");
  SD_CHECK_STR(a.mac_c2s, "hmac-sha2-256");
  SD_CHECK(!(ssh_legacy_mask_for(&a, 0) & SD_LEGACY_TERRAPIN_EXPOSED));
  sd_wr_free(&w);
  /* chacha + CTR offered: chacha removed, CTR keeps the ETM MAC */
  SD_REQUIRE(make_server(&w, &k, "curve25519-sha256", "ssh-ed25519", "chacha20-poly1305@openssh.com,aes128-ctr",
                         "hmac-sha2-256-etm@openssh.com"));
  in.server = &k;
  SD_CHECK_EQ_INT(ssh_build_lists(&in, &l, &r), SD_OK);
  SD_CHECK(r.chacha_removed && !r.etm_removed && !r.terrapin_exposed);
  SD_CHECK_EQ_INT(ssh_negotiate(&l, &k, &a, &cat), SD_OK);
  SD_CHECK_STR(a.enc_s2c, "aes128-ctr");
  SD_CHECK_STR(a.mac_s2c, "hmac-sha2-256-etm@openssh.com");
  sd_wr_free(&w);
}

SD_TEST(tr_lists_terrapin_exposed_cbc_etm_only)
{
  sd_wr w;
  ssh_kexinit k;
  ssh_list_input in;
  ssh_lists l;
  ssh_list_result r;
  ssh_algs a;
  const char *cat;
  SD_REQUIRE(make_server(&w, &k, "curve25519-sha256", "ssh-ed25519", "aes128-cbc", "hmac-sha2-512-etm@openssh.com"));
  all_input(&in);
  in.server = &k;
  SD_CHECK_EQ_INT(ssh_build_lists(&in, &l, &r), SD_OK);
  SD_CHECK(r.terrapin_exposed);
  SD_CHECK_EQ_INT(ssh_negotiate(&l, &k, &a, &cat), SD_OK);
  SD_CHECK(ssh_legacy_mask_for(&a, 0) & SD_LEGACY_TERRAPIN_EXPOSED);
  in.refuse_terrapin_exposed = 1;
  SD_CHECK_EQ_INT(ssh_build_lists(&in, &l, &r), SD_E_KEX_FAILED);
  sd_wr_free(&w);
}

SD_TEST(tr_lists_fetch_hostkey_only)
{
  ssh_list_input in;
  ssh_lists l;
  ssh_list_result r;
  sd_kh_types t;
  all_input(&in);
  memset(&t, 0, sizeof(t));
  t.count = 1;
  memcpy(t.type[0], "ssh-ed25519", 12);
  in.stored = &t;
  in.hostkey_only = "rsa-sha2-512,rsa-sha2-256";
  SD_CHECK_EQ_INT(ssh_build_lists(&in, &l, &r), SD_OK);
  SD_CHECK_STR(l.hostkey, "rsa-sha2-512,rsa-sha2-256");
}

SD_TEST(tr_legacy_mask_and_names)
{
  ssh_algs a;
  char names[256];
  uint32_t m;
  memset(&a, 0, sizeof(a));
  memcpy(a.kex, "diffie-hellman-group1-sha1", 27);
  memcpy(a.hostkey, "ssh-rsa", 8);
  memcpy(a.enc_c2s, "3des-cbc", 9);
  memcpy(a.enc_s2c, "3des-cbc", 9);
  memcpy(a.mac_c2s, "hmac-sha1", 10);
  memcpy(a.mac_s2c, "hmac-sha1", 10);
  m = ssh_legacy_mask_for(&a, 1);
  SD_CHECK_EQ_INT(m, SD_LEGACY_KEX_SHA1 | SD_LEGACY_DH_1024 | SD_LEGACY_HOSTKEY_SHA1 | SD_LEGACY_CIPHER_CBC |
                         SD_LEGACY_CIPHER_3DES | SD_LEGACY_MAC_SHA1 | SD_LEGACY_MAC_NON_ETM);
  ssh_legacy_names(&a, m, names, sizeof(names));
  SD_CHECK_STR(names, "diffie-hellman-group1-sha1,ssh-rsa,3des-cbc,hmac-sha1");
  /* modern, strict: nothing but the informational non-ETM bit */
  memset(&a, 0, sizeof(a));
  memcpy(a.kex, "mlkem768x25519-sha256", 22);
  memcpy(a.hostkey, "ssh-ed25519", 12);
  memcpy(a.enc_c2s, "aes256-gcm@openssh.com", 23);
  memcpy(a.enc_s2c, "aes128-ctr", 11);
  memcpy(a.mac_s2c, "hmac-sha2-256", 14);
  SD_CHECK_EQ_INT(ssh_legacy_mask_for(&a, 1), SD_LEGACY_MAC_NON_ETM);
  m = ssh_legacy_mask_for(&a, 0) | SD_LEGACY_DH_SMALL;
  SD_CHECK(m & SD_LEGACY_NO_STRICT_KEX);
  ssh_legacy_names(&a, m, names, sizeof(names));
  SD_CHECK_STR(names, "dh_group_small,no_strict_kex");
}

SD_TEST(tr_hostkey_algs_for_type)
{
  char out[256];
  SD_CHECK_EQ_INT(ssh_hostkey_algs_for_type("ssh-rsa", 1, NULL, out, sizeof(out)), SD_OK);
  SD_CHECK_STR(out, "rsa-sha2-512,rsa-sha2-256,ssh-rsa");
  SD_CHECK_EQ_INT(ssh_hostkey_algs_for_type("ssh-rsa", 0, NULL, out, sizeof(out)), SD_OK);
  SD_CHECK_STR(out, "rsa-sha2-512,rsa-sha2-256");
  SD_CHECK_EQ_INT(ssh_hostkey_algs_for_type("ecdsa-sha2-nistp521", 0, NULL, out, sizeof(out)), SD_OK);
  SD_CHECK_STR(out, "ecdsa-sha2-nistp521");
  SD_CHECK_EQ_INT(ssh_hostkey_algs_for_type("ssh-dss", 1, NULL, out, sizeof(out)), SD_E_HOSTKEY_TYPE_UNAVAILABLE);
  SD_CHECK_STR(ssh_hostkey_alg_key_type("rsa-sha2-256-cert-v01@openssh.com"), "ssh-rsa");
  SD_CHECK(ssh_hostkey_alg_is_cert("ssh-ed25519-cert-v01@openssh.com"));
  SD_CHECK(ssh_kex_supported("mlkem768x25519-sha256") && ssh_kex_supported("diffie-hellman-group1-sha1"));
  SD_CHECK(!ssh_kex_supported("sntrup761x25519-sha512@openssh.com"));
}

/* ---- KEX methods against a mock server ---- */

static const uint8_t k_host_seed[32] = {
  1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 };

typedef struct mock {
  const ssh_kex_method *m;
  uint8_t host_pub[32];
  uint8_t ks[64]; size_t ks_len;
  ssh_kex_hash_in hin;
  sd_wr kenc;                 /* server's K encoding */
  uint8_t h[SD_HASH_MAX_LEN]; size_t hlen;
  /* GEX */
  const uint8_t *gp; size_t gplen;
  /* corruption knobs */
  int zero_qs, bad_point, f_one, short_mlkem;
} mock;

static void mock_init(mock *s, const ssh_kex_method *m)
{
  sd_wr w;
  static const uint8_t k_ic[] = { 20, 1, 2, 3 }, k_is[] = { 20, 9, 8, 7, 6 };
  memset(s, 0, sizeof(*s));
  s->m = m;
  sd_ed25519_pub_from_seed(s->host_pub, k_host_seed);
  sd_wr_init_fixed(&w, s->ks, sizeof(s->ks));
  sd_wr_cstring(&w, "ssh-ed25519");
  sd_wr_string(&w, s->host_pub, 32);
  s->ks_len = w.len;
  s->hin.v_c = "SSH-2.0-ShellDrive_test";
  s->hin.v_s = "SSH-2.0-mock";
  s->hin.i_c = k_ic; s->hin.i_c_len = sizeof(k_ic);
  s->hin.i_s = k_is; s->hin.i_s_len = sizeof(k_is);
  sd_wr_init(&s->kenc, 4096);
}

/* Builds the server reply (message byte included) for the client's INIT; 0 on failure. */
static int mock_reply(mock *s, const uint8_t *init, size_t n, sd_wr *reply)
{
  sd_rd r;
  sd_span q;
  sd_wr hw;
  uint8_t qs[SD_MLKEM768X25519_REPLY_LEN + 8];
  size_t qsl = 0;
  uint8_t sig[64];
  int dh = s->m->kind == SSH_KM_DH || s->m->kind == SSH_KM_GEX;
  sd_rd_init(&r, init + 1, n - 1);
  q = dh ? sd_rd_mpint(&r, 1100) : sd_rd_string(&r, 2048);
  if (!sd_rd_done(&r)) return 0;
  switch (s->m->kind) {
  case SSH_KM_C25519: {
    uint8_t priv[32], k[32];
    tu_det_random(priv, 32);
    if (sd_x25519_base(qs, priv) != SD_OK || sd_x25519(k, priv, q.p) != SD_OK) return 0;
    qsl = 32;
    if (s->zero_qs) memset(qs, 0, 32);
    sd_wr_mpint(&s->kenc, k, 32);
    break;
  }
  case SSH_KM_MLKEM: {
    uint8_t k[32];
    if (q.n != SD_MLKEM768X25519_INIT_LEN || sd_mlkem768x25519_server(q.p, qs, k) != SD_OK) return 0;
    qsl = s->short_mlkem ? SD_MLKEM768X25519_REPLY_LEN - 1 : SD_MLKEM768X25519_REPLY_LEN;
    sd_wr_string(&s->kenc, k, 32);
    break;
  }
  case SSH_KM_ECDH: {
    sd_ec_key *e = NULL;
    uint8_t x[SD_EC_MAX_FIELD_LEN];
    size_t xl = sizeof(x);
    qsl = sizeof(qs);
    if (sd_ec_generate((sd_curve)s->m->param, &e) != SD_OK || sd_ec_export_pub(e, qs, &qsl) != SD_OK ||
        sd_ecdh(e, q.p, q.n, x, &xl) != SD_OK) { sd_ec_free(e); return 0; }
    sd_ec_free(e);
    if (s->bad_point) memset(qs + 1, 0, qsl - 1);
    sd_wr_mpint(&s->kenc, x, xl);
    break;
  }
  case SSH_KM_DH:
  case SSH_KM_GEX: {
    sd_dh *d = NULL;
    uint8_t f[1100], k[1100];
    size_t len;
    uint8_t two = 2;
    sd_err e = s->m->kind == SSH_KM_DH ? sd_dh_new_group(s->m->param, 0, &d) : sd_dh_new(s->gp, s->gplen, &two, 1, 0, &d);
    if (e != SD_OK) return 0;
    len = sd_dh_len(d);
    if (sd_dh_public(d, f, len) != SD_OK || sd_dh_compute(d, q.p, q.n, k, len) != SD_OK) { sd_dh_free(d); return 0; }
    sd_dh_free(d);
    if (s->f_one) { memset(f, 0, len); f[len - 1] = 1; }
    memcpy(qs, f, SD_MIN(len, sizeof(qs)));
    qsl = len;
    sd_wr_mpint(&s->kenc, k, len);
    break;
  }
  }
  /* exchange hash, assembled independently of kex_methods.c */
  sd_wr_init(&hw, 1u << 20);
  sd_wr_cstring(&hw, s->hin.v_c);
  sd_wr_cstring(&hw, s->hin.v_s);
  sd_wr_string(&hw, s->hin.i_c, s->hin.i_c_len);
  sd_wr_string(&hw, s->hin.i_s, s->hin.i_s_len);
  sd_wr_string(&hw, s->ks, s->ks_len);
  if (s->m->kind == SSH_KM_GEX) {
    uint8_t two = 2;
    sd_wr_u32(&hw, SSH_GEX_MIN); sd_wr_u32(&hw, SSH_GEX_N); sd_wr_u32(&hw, SSH_GEX_MAX);
    sd_wr_mpint(&hw, s->gp, s->gplen);
    sd_wr_mpint(&hw, &two, 1);
  }
  if (dh) { sd_wr_mpint(&hw, q.p, q.n); sd_wr_mpint(&hw, qs, qsl); }
  else { sd_wr_string(&hw, q.p, q.n); sd_wr_string(&hw, qs, qsl); }
  sd_wr_bytes(&hw, s->kenc.p, s->kenc.len);
  sd_hash(s->m->hash, hw.p, hw.len, s->h);
  s->hlen = sd_hash_len(s->m->hash);
  sd_wr_free(&hw);
  sd_ed25519_sign(sig, k_host_seed, s->host_pub, s->h, s->hlen);
  sd_wr_u8(reply, s->m->kind == SSH_KM_GEX ? SSH_MSG_KEX_DH_GEX_REPLY : SSH_MSG_KEXDH_REPLY);
  sd_wr_string(reply, s->ks, s->ks_len);
  if (dh) sd_wr_mpint(reply, qs, qsl); else sd_wr_string(reply, qs, qsl);
  {
    uint8_t sb[128];
    sd_wr sw;
    sd_wr_init_fixed(&sw, sb, sizeof(sb));
    sd_wr_cstring(&sw, "ssh-ed25519");
    sd_wr_string(&sw, sig, 64);
    sd_wr_string(reply, sw.p, sw.len);
  }
  return sd_wr_ok(reply);
}

/* Runs one exchange; returns the client's finish result (SD_OK when everything matched). */
static sd_err run_exchange(sd_test_ctx *sd_t_, mock *s, int allow_legacy, int gex_group)
{
  ssh_kexm *c = NULL;
  sd_wr w, reply, kenc;
  sd_span ks, sig;
  uint8_t h[SD_HASH_MAX_LEN];
  size_t hlen = 0;
  uint32_t bits = 0;
  sd_err e;
  sd_wr_init(&w, 1u << 16);
  sd_wr_init(&reply, 1u << 16);
  sd_wr_init_secret(&kenc, 4096);
  e = ssh_kexm_start(s->m, allow_legacy, &c, &w);
  if (e != SD_OK) goto out;
  if (s->m->kind == SSH_KM_GEX) {
    sd_wr g;
    uint8_t two = 2;
    SD_CHECK(ssh_kexm_awaiting_group(c) && ssh_kexm_reply_msg(c) == SSH_MSG_KEX_DH_GEX_GROUP);
    SD_CHECK(w.p[0] == SSH_MSG_KEX_DH_GEX_REQUEST && w.len == 13);
    s->gp = sd_dh_group_modp(gex_group, &s->gplen);
    sd_wr_init(&g, 4096);
    sd_wr_u8(&g, SSH_MSG_KEX_DH_GEX_GROUP);
    sd_wr_mpint(&g, s->gp, s->gplen);
    sd_wr_mpint(&g, &two, 1);
    sd_wr_reset(&w);
    e = ssh_kexm_gex_group(c, g.p, g.len, &w, &bits);
    sd_wr_free(&g);
    if (e != SD_OK) goto out;
    SD_CHECK_EQ_INT(bits, (uint32_t)(s->gplen * 8));
    SD_CHECK(w.p[0] == SSH_MSG_KEX_DH_GEX_INIT);
  } else {
    SD_CHECK(w.p[0] == SSH_MSG_KEXDH_INIT);
  }
  if (!mock_reply(s, w.p, w.len, &reply)) { e = SD_E_INTERNAL; goto out; }
  e = ssh_kexm_finish(c, reply.p, reply.len, &s->hin, &ks, &sig, &kenc, h, &hlen);
  if (e != SD_OK) goto out;
  SD_CHECK_EQ_INT(hlen, s->hlen);
  SD_CHECK_MEM(h, s->h, hlen);
  SD_CHECK_EQ_INT(kenc.len, s->kenc.len);
  SD_CHECK_MEM(kenc.p, s->kenc.p, kenc.len);
  {
    uint32_t kb = 0;
    SD_CHECK_EQ_INT(ssh_hostkey_verify_kex("ssh-ed25519", ks.p, ks.n, sig.p, sig.n, h, hlen, &kb), SD_OK);
    SD_CHECK_EQ_INT(kb, 256);
    h[0] ^= 1;
    SD_CHECK_EQ_INT(ssh_hostkey_verify_kex("ssh-ed25519", ks.p, ks.n, sig.p, sig.n, h, hlen, &kb), SD_E_CRYPTO);
    SD_CHECK_EQ_INT(ssh_hostkey_verify_kex("rsa-sha2-512", ks.p, ks.n, sig.p, sig.n, h, hlen, &kb), SD_E_KEX_FAILED);
  }
out:
  ssh_kexm_free(c);
  sd_wr_free(&w);
  sd_wr_free(&reply);
  sd_wr_free(&kenc);
  sd_wr_free(&s->kenc);
  return e;
}

SD_TEST(tr_kex_methods_against_mock_server)
{
  static const char *const k_names[] = {
    "mlkem768x25519-sha256", "curve25519-sha256", "curve25519-sha256@libssh.org", "ecdh-sha2-nistp256",
    "ecdh-sha2-nistp384", "ecdh-sha2-nistp521", "diffie-hellman-group-exchange-sha256",
    "diffie-hellman-group16-sha512", "diffie-hellman-group18-sha512", "diffie-hellman-group14-sha256",
    "diffie-hellman-group14-sha1", "diffie-hellman-group-exchange-sha1", "diffie-hellman-group1-sha1"
  };
  size_t i;
  if (!tu_crypto_or_skip("tr_kex_methods_against_mock_server")) return;
  for (i = 0; i < SD_COUNTOF(k_names); i++) {
    mock s;
    sd_err e;
    const ssh_kex_method *m = ssh_kex_method_find(k_names[i]);
    SD_REQUIRE(m != NULL);
    mock_init(&s, m);
    e = run_exchange(sd_t_, &s, 1, SD_DH_GROUP14);
    if (e != SD_OK) sd_test_fail(sd_t_, __FILE__, __LINE__, "%s: %s", k_names[i], sd_err_name(e));
  }
}

SD_TEST(tr_kex_rejects_bad_server_values)
{
  mock s;
  if (!tu_crypto_or_skip("tr_kex_rejects_bad_server_values")) return;
  mock_init(&s, ssh_kex_method_find("curve25519-sha256"));
  s.zero_qs = 1;
  SD_CHECK_EQ_INT(run_exchange(sd_t_, &s, 1, 0), SD_E_KEX_FAILED);
  mock_init(&s, ssh_kex_method_find("ecdh-sha2-nistp384"));
  s.bad_point = 1;
  SD_CHECK_EQ_INT(run_exchange(sd_t_, &s, 1, 0), SD_E_KEX_FAILED);
  mock_init(&s, ssh_kex_method_find("diffie-hellman-group14-sha256"));
  s.f_one = 1;
  SD_CHECK_EQ_INT(run_exchange(sd_t_, &s, 1, 0), SD_E_KEX_FAILED);
  mock_init(&s, ssh_kex_method_find("mlkem768x25519-sha256"));
  s.short_mlkem = 1;
  SD_CHECK_EQ_INT(run_exchange(sd_t_, &s, 1, 0), SD_E_PROTOCOL);
  /* GEX: a 1024-bit group only with legacy allowed (D33, flagged DH_SMALL by kex.c) */
  mock_init(&s, ssh_kex_method_find("diffie-hellman-group-exchange-sha256"));
  SD_CHECK_EQ_INT(run_exchange(sd_t_, &s, 0, SD_DH_GROUP1), SD_E_KEX_FAILED);
  mock_init(&s, ssh_kex_method_find("diffie-hellman-group-exchange-sha256"));
  SD_CHECK_EQ_INT(run_exchange(sd_t_, &s, 1, SD_DH_GROUP1), SD_OK);
  /* GEX: an even modulus is refused */
  {
    ssh_kexm *c = NULL;
    sd_wr w, g;
    uint8_t p[256], two = 2;
    uint32_t bits;
    memset(p, 0xff, sizeof(p));
    p[255] = 0xfe;
    sd_wr_init(&w, 4096);
    sd_wr_init(&g, 4096);
    SD_REQUIRE(ssh_kexm_start(ssh_kex_method_find("diffie-hellman-group-exchange-sha256"), 1, &c, &w) == SD_OK);
    sd_wr_u8(&g, SSH_MSG_KEX_DH_GEX_GROUP);
    sd_wr_mpint(&g, p, sizeof(p));
    sd_wr_mpint(&g, &two, 1);
    SD_CHECK_EQ_INT(ssh_kexm_gex_group(c, g.p, g.len, &w, &bits), SD_E_KEX_FAILED);
    ssh_kexm_free(c);
    sd_wr_free(&w);
    sd_wr_free(&g);
  }
}

SD_TEST(tr_kex_derive_long_outputs)
{
  /* K1 = HASH(K || H || 'A' || sid), K2 = HASH(K || H || K1): checked by hand composition for SHA-1 */
  static const uint8_t k_k[] = { 0, 0, 0, 1, 7 }, k_h[20] = { 1 }, k_sid[20] = { 2 };
  uint8_t out[64], want[64], buf[256];
  size_t n = 0;
  if (!tu_crypto_or_skip("tr_kex_derive_long_outputs")) return;
  ssh_kex_derive(SD_HASH_SHA1, k_k, sizeof(k_k), k_h, sizeof(k_h), 'A', k_sid, sizeof(k_sid), out, 64);
  memcpy(buf, k_k, sizeof(k_k)); n = sizeof(k_k);
  memcpy(buf + n, k_h, 20); n += 20;
  buf[n++] = 'A';
  memcpy(buf + n, k_sid, 20); n += 20;
  sd_hash(SD_HASH_SHA1, buf, n, want);
  n = 0;
  memcpy(buf, k_k, sizeof(k_k)); n = sizeof(k_k);
  memcpy(buf + n, k_h, 20); n += 20;
  memcpy(buf + n, want, 20); n += 20;
  sd_hash(SD_HASH_SHA1, buf, n, want + 20);
  memcpy(buf + n, want + 20, 20); n += 20;
  sd_hash(SD_HASH_SHA1, buf, n, want + 40);
  memcpy(buf + n, want + 40, 20); n += 20;
  {
    uint8_t last[20];
    sd_hash(SD_HASH_SHA1, buf, n, last);
    memcpy(want + 60, last, 4);
  }
  SD_CHECK_MEM(out, want, 64);
}

/* ---- host key signatures ---- */

static const char k_rsa_n[] =
  "00d22337205d201c5fe7308f4f5422eefb72b99fab57b408a73a2563df55a6b8368335cf46a6c76177d8da0ac754d8ec3393384be253bd0a97"
  "d50f5d5d64db0b07857fbe9a9294791a87c381dff63bff88251cbdcf36c7082396b91e31f89fe4c0811c510c72f5781924dfeced0aab0e8a23"
  "53039a04defe906946dfe81a2e2a05eb1137cd7b8aebb1acdf69d78048b2ab2591ae21bae21b76227694977293a92502ad01f8bd13d3d532a6"
  "a9974c6e3b11a3e285fbd47cd299613979d90c05fb473f2e76f2d658938648d85bf947fe56deefb5902d06fe3bcc50457b7f004d8a50e03e21"
  "e90a72e2268ceee865055a4ee810e610fd33dafd85da84ade8882d522f";
static const char k_rsa_d[] =
  "084c53b4f7787926605ece89f76c99bb5c407049b7e0e82692693f9466317b3ccbd9a821c61c418116132631d0ebf007e95c63c2c043cad34c"
  "1a9b3940ee55752a946cd675cb5f2ce907936d60afe5db5e7bd0130abab95b8e6c2901182c584031d9086a516fd81a461681a8aaaf2e97cde5"
  "4d531bb6229f5948ef369f320b7eb5f6fd8969ef44869ed6d72dc51458a131ae257824ddda59958fccf81fbcbba1a913301715270adfc64b31"
  "c47543fca8d39fa8242995480c4ae267b984923f920ad5cbda79361c14274a178bd467c779fe5f81a55e8f20a208d13a10ae18b07e6573f2c5"
  "218d2174366715d749e846894f1f72f7f65ce4b2d262e90ad3686661";
static const char k_rsa_p[] =
  "00f9feedd5fe84c8802443d35e80e0df4ed1f08cad25bdab6c50a49ef181b1cfc793772c636275b54d10d19b15e40f9a1ac94674834e5b8087"
  "29728623d82f6eeffeffa69083edebc08df5ffa438af575d27477a4e1ade3bd1ce11ea01e705f589a9547715b80ad831f1fb471b0f66edb5e7"
  "3fe418dc6c00c1200bbdbe098c70b5";
static const char k_rsa_q[] =
  "00d72f38e9b12f708ef9a022e03e1baffe52e73fb2138f58bfd66e653c39ff30f7ad3f371702f6bf4aaffb09001e55bbca1d6e3189c351091c"
  "9c6820d273f5cad40b930c7fe45cade1180a70524b7d4dacba6edff904363ccc124c9b311d19d297efdb015ef662fe591ec7afb1a6dbfdb9b6"
  "d4431b9a9cfa6c303620442b37d9d3";

static void sig_blob(sd_wr *w, const char *alg, const uint8_t *s, size_t n)
{
  sd_wr_cstring(w, alg);
  sd_wr_string(w, s, n);
}

SD_TEST(tr_hostkey_signatures)
{
  static const uint8_t k_msg[] = "exchange hash stand-in";
  uint8_t dig[SD_HASH_MAX_LEN];
  uint32_t bits;
  size_t ci;
  if (!tu_crypto_or_skip("tr_hostkey_signatures")) return;
  /* ECDSA on the three curves */
  for (ci = 0; ci < 3; ci++) {
    static const sd_curve k_c[3] = { SD_CURVE_P256, SD_CURVE_P384, SD_CURVE_P521 };
    static const char *const k_t[3] = { "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521" };
    static const char *const k_n[3] = { "nistp256", "nistp384", "nistp521" };
    sd_ec_key *k = NULL;
    uint8_t q[SD_EC_MAX_POINT_LEN], r[SD_EC_MAX_FIELD_LEN], s[SD_EC_MAX_FIELD_LEN];
    size_t ql = sizeof(q), fl = sd_ec_field_len(k_c[ci]);
    sd_wr kb, sb, inner;
    sd_hash_alg h = sd_ec_hash(k_c[ci]);
    SD_REQUIRE(sd_ec_generate(k_c[ci], &k) == SD_OK && sd_ec_export_pub(k, q, &ql) == SD_OK);
    sd_hash(h, k_msg, sizeof(k_msg), dig);
    SD_REQUIRE(sd_ecdsa_sign(k, h, dig, sd_hash_len(h), r, s) == SD_OK);
    sd_wr_init(&kb, 1024); sd_wr_init(&sb, 1024); sd_wr_init(&inner, 1024);
    sd_wr_cstring(&kb, k_t[ci]); sd_wr_cstring(&kb, k_n[ci]); sd_wr_string(&kb, q, ql);
    sd_wr_mpint(&inner, r, fl); sd_wr_mpint(&inner, s, fl);
    sig_blob(&sb, k_t[ci], inner.p, inner.len);
    SD_CHECK_EQ_INT(ssh_hostkey_verify_kex(k_t[ci], kb.p, kb.len, sb.p, sb.len, k_msg, sizeof(k_msg), &bits), SD_OK);
    SD_CHECK_EQ_INT(bits, ci == 0 ? 256 : ci == 1 ? 384 : 521);
    SD_CHECK_EQ_INT(ssh_hostkey_verify_kex(k_t[ci], kb.p, kb.len, sb.p, sb.len, k_msg, sizeof(k_msg) - 1, &bits), SD_E_CRYPTO);
    SD_CHECK_EQ_INT(ssh_hostkey_verify_kex(k_t[(ci + 1) % 3], kb.p, kb.len, sb.p, sb.len, k_msg, sizeof(k_msg), &bits),
                    SD_E_KEX_FAILED);
    sd_ec_free(k);
    sd_wr_free(&kb); sd_wr_free(&sb); sd_wr_free(&inner);
  }
  /* RSA: rsa-sha2-512, rsa-sha2-256 and ssh-rsa (SHA-1) */
  {
    uint8_t n[300], d[300], p[160], q[160], e3[3] = { 1, 0, 1 }, sig[256];
    size_t nl = sd_test_unhex(k_rsa_n, n, sizeof(n)), dl = sd_test_unhex(k_rsa_d, d, sizeof(d));
    size_t pl = sd_test_unhex(k_rsa_p, p, sizeof(p)), qln = sd_test_unhex(k_rsa_q, q, sizeof(q)), sl;
    sd_rsa_import_params ip;
    sd_rsa_key *k = NULL;
    sd_wr kb, sb;
    ssh_pubkey pk;
    memset(&ip, 0, sizeof(ip));
    ip.n = n; ip.n_len = nl; ip.e = e3; ip.e_len = 3; ip.d = d; ip.d_len = dl; ip.p = p; ip.p_len = pl;
    ip.q = q; ip.q_len = qln;
    SD_REQUIRE(sd_rsa_import(&ip, &k) == SD_OK);
    sd_wr_init(&kb, 1024); sd_wr_init(&sb, 1024);
    sd_wr_cstring(&kb, "ssh-rsa"); sd_wr_mpint(&kb, e3, 3); sd_wr_mpint(&kb, n, nl);
    sd_hash(SD_HASH_SHA512, k_msg, sizeof(k_msg), dig);
    sl = sizeof(sig);
    SD_REQUIRE(sd_rsa_pkcs1_sign(k, SD_HASH_SHA512, dig, 64, sig, &sl) == SD_OK);
    sig_blob(&sb, "rsa-sha2-512", sig, sl);
    SD_CHECK_EQ_INT(ssh_hostkey_verify_kex("rsa-sha2-512", kb.p, kb.len, sb.p, sb.len, k_msg, sizeof(k_msg), &bits), SD_OK);
    SD_CHECK_EQ_INT(bits, 2048);
    /* the signature algorithm must be the negotiated one */
    SD_CHECK_EQ_INT(ssh_hostkey_verify_kex("rsa-sha2-256", kb.p, kb.len, sb.p, sb.len, k_msg, sizeof(k_msg), &bits), SD_E_CRYPTO);
    sd_wr_reset(&sb);
    sd_hash(SD_HASH_SHA1, k_msg, sizeof(k_msg), dig);
    sl = sizeof(sig);
    SD_REQUIRE(sd_rsa_pkcs1_sign(k, SD_HASH_SHA1, dig, 20, sig, &sl) == SD_OK);
    sig_blob(&sb, "ssh-rsa", sig, sl);
    SD_CHECK_EQ_INT(ssh_hostkey_verify_kex("ssh-rsa", kb.p, kb.len, sb.p, sb.len, k_msg, sizeof(k_msg), &bits), SD_OK);
    SD_REQUIRE(ssh_pubkey_parse(kb.p, kb.len, &pk) == SD_OK);
    SD_CHECK_EQ_INT(ssh_pubkey_verify(&pk, NULL, 1, sb.p, sb.len, k_msg, sizeof(k_msg)), SD_OK);
    SD_CHECK_EQ_INT(ssh_pubkey_verify(&pk, NULL, 0, sb.p, sb.len, k_msg, sizeof(k_msg)), SD_E_CRYPTO);
    ssh_pubkey_free(&pk);
    sd_rsa_free(k);
    sd_wr_free(&kb); sd_wr_free(&sb);
  }
}

/* ---- certificates ---- */

static size_t load_pub(const char *name, uint8_t *out, size_t cap)
{
  uint8_t *f;
  size_t n, i, s, e, bl = 0;
  if (!tu_read_fixture(name, &f, &n)) return 0;
  for (i = 0; i < n && f[i] != ' '; i++) {}
  s = i + 1;
  for (e = s; e < n && f[e] != ' ' && f[e] != '\n' && f[e] != '\r'; e++) {}
  if (ssh_b64_decode((const char *)f + s, e - s, out, cap, &bl, 0) != SD_OK) bl = 0;
  sd_free(f);
  return bl;
}

SD_TEST(tr_cert_parse_and_host_checks)
{
  uint8_t b[4096], plain[256];
  size_t bl, pl;
  ssh_cert c;
  const char *why;
  uint64_t now = 1800000000u;
  if (!tu_crypto_or_skip("tr_cert_parse_and_host_checks")) return;
  bl = load_pub("hk_host-cert.pub", b, sizeof(b));
  pl = load_pub("hk_host.pub", plain, sizeof(plain));
  SD_REQUIRE(bl && pl);
  SD_CHECK(ssh_blob_is_cert(b, bl) && !ssh_blob_is_cert(plain, pl));
  SD_REQUIRE(ssh_cert_parse(b, bl, &c) == SD_OK);
  SD_CHECK_STR(c.cert_type, "ssh-ed25519-cert-v01@openssh.com");
  SD_CHECK_EQ_INT(c.type, SSH_CERT_TYPE_HOST);
  SD_CHECK_EQ_INT(c.plain_len, pl);
  SD_CHECK_MEM(c.plain, plain, pl);
  SD_CHECK_EQ_INT(ssh_cert_check_host(&c, b, "host.example", now, &why), SD_OK);
  SD_CHECK_EQ_INT(ssh_cert_check_host(&c, b, "[host.example]:2222", now, &why), SD_OK);
  SD_CHECK_EQ_INT(ssh_cert_check_host(&c, b, "127.0.0.1", now, &why), SD_OK);
  SD_CHECK_EQ_INT(ssh_cert_check_host(&c, b, "other.example", now, &why), SD_E_HOSTKEY_REJECTED);
  ssh_cert_free(&c);
  /* a modified certificate breaks the CA signature */
  b[bl / 2] ^= 0x40;
  if (ssh_cert_parse(b, bl, &c) == SD_OK) {
    SD_CHECK_EQ_INT(ssh_cert_check_host(&c, b, "host.example", now, &why), SD_E_HOSTKEY_REJECTED);
  }
  ssh_cert_free(&c);
  {
    static const char *const k_bad[] = { "hk_host_expired-cert.pub", "hk_host_user-cert.pub", "hk_host_noprinc-cert.pub",
                                         "hk_host_rsasha1-cert.pub" };
    size_t i;
    for (i = 0; i < SD_COUNTOF(k_bad); i++) {
      bl = load_pub(k_bad[i], b, sizeof(b));
      SD_REQUIRE(bl);
      SD_REQUIRE(ssh_cert_parse(b, bl, &c) == SD_OK);
      if (ssh_cert_check_host(&c, b, "host.example", now, &why) != SD_E_HOSTKEY_REJECTED)
        sd_test_fail(sd_t_, __FILE__, __LINE__, "%s accepted", k_bad[i]);
      ssh_cert_free(&c);
    }
  }
  bl = load_pub("hk_host_rsaca-cert.pub", b, sizeof(b));
  SD_REQUIRE(bl && ssh_cert_parse(b, bl, &c) == SD_OK);
  SD_CHECK_EQ_INT(ssh_cert_check_host(&c, b, "host.example", now, &why), SD_OK);   /* rsa-sha2-512 CA signature */
  ssh_cert_free(&c);
  SD_CHECK_EQ_INT(ssh_blob_key_bits(b, bl), 256);
}

/* ---- CBC / SHA-1 packet protection ---- */

typedef struct combo { const char *cipher, *mac; } combo;

static void seal_some(sd_test_ctx *sd_t_, ssh_dir *tx, sd_wr *w, int count)
{
  uint8_t pl[300];
  int i;
  for (i = 0; i < count; i++) {
    size_t n = 1 + (size_t)(i * 37) % sizeof(pl);
    memset(pl, i, n);
    SD_CHECK_EQ_INT(ssh_pkt_seal(tx, pl, n, w), SD_OK);
  }
}

SD_TEST(tr_packet_cbc_and_sha1_roundtrip)
{
  static const combo k_combos[] = {
    { "3des-cbc", "hmac-sha1" }, { "aes128-cbc", "hmac-sha1-etm@openssh.com" }, { "aes192-cbc", "hmac-sha2-256" },
    { "aes256-cbc", "hmac-sha2-512-etm@openssh.com" }, { "aes128-ctr", "hmac-sha1" }
  };
  size_t i;
  if (!tu_crypto_or_skip("tr_packet_cbc_and_sha1_roundtrip")) return;
  for (i = 0; i < SD_COUNTOF(k_combos); i++) {
    ssh_dir tx, rx;
    sd_wr w;
    uint8_t key[64], iv[32], mk[64];
    size_t kl, il, ml, off = 0;
    int got = 0;
    if (!sd_pktcipher_find(k_combos[i].cipher)) {
      printf("  [skip] %s not provided by sd_crypto yet\n", k_combos[i].cipher);
      continue;
    }
    SD_REQUIRE(ssh_alg_key_sizes(k_combos[i].cipher, k_combos[i].mac, &kl, &il, &ml) == SD_OK);
    SD_CHECK_EQ_INT(ml, strstr(k_combos[i].mac, "sha1") ? 20 : strstr(k_combos[i].mac, "512") ? 64 : 32);
    tu_det_random(key, sizeof(key)); tu_det_random(iv, sizeof(iv)); tu_det_random(mk, sizeof(mk));
    ssh_dir_init(&tx);
    ssh_dir_init(&rx);
    SD_REQUIRE(ssh_dir_set_keys(&tx, 1, k_combos[i].cipher, k_combos[i].mac, key, iv, mk) == SD_OK);
    SD_REQUIRE(ssh_dir_set_keys(&rx, 0, k_combos[i].cipher, k_combos[i].mac, key, iv, mk) == SD_OK);
    sd_wr_init(&w, 1u << 20);
    seal_some(sd_t_, &tx, &w, 30);
    while (off < w.len) {
      size_t used = 0;
      sd_span pl;
      sd_err e = ssh_pkt_open(&rx, w.p + off, w.len - off, &used, &pl);
      SD_REQUIRE(e == SD_OK && pl.p);
      SD_CHECK(pl.n == 1 + (size_t)(got * 37) % 300 && pl.p[0] == (uint8_t)got);
      off += used;
      got++;
    }
    SD_CHECK_EQ_INT(got, 30);
    sd_wr_free(&w);
    ssh_dir_clear(&tx);
    ssh_dir_clear(&rx);
  }
}

SD_TEST(tr_packet_cbc_mac_failure_discards)
{
  ssh_dir tx, rx;
  sd_wr w;
  uint8_t key[32], iv[16], mk[20], *big;
  size_t used;
  sd_span pl;
  int pass;
  if (!tu_crypto_or_skip("tr_packet_cbc_mac_failure_discards")) return;
  if (!sd_pktcipher_find("aes128-cbc")) { printf("  [skip] aes128-cbc not provided by sd_crypto yet\n"); return; }
  big = (uint8_t *)sd_calloc(1, SSH_MAX_PACKET_LEN + 64);
  SD_REQUIRE(big != NULL);
  for (pass = 0; pass < 2; pass++) {
    tu_det_random(key, sizeof(key)); tu_det_random(iv, sizeof(iv)); tu_det_random(mk, sizeof(mk));
    ssh_dir_init(&tx);
    ssh_dir_init(&rx);
    SD_REQUIRE(ssh_dir_set_keys(&tx, 1, "aes128-cbc", "hmac-sha1", key, iv, mk) == SD_OK);
    SD_REQUIRE(ssh_dir_set_keys(&rx, 0, "aes128-cbc", "hmac-sha1", key, iv, mk) == SD_OK);
    sd_wr_init(&w, 4096);
    seal_some(sd_t_, &tx, &w, 1);
    if (pass == 0) w.p[w.len - 1] ^= 1;     /* MAC failure */
    else w.p[2] ^= 0x80;                   /* garbage length after decryption */
    memset(big, 0, SSH_MAX_PACKET_LEN + 64);
    memcpy(big, w.p, w.len);
    /* Albrecht countermeasure: no error until 256 KiB of the stream are buffered */
    SD_CHECK_EQ_INT(ssh_pkt_open(&rx, big, w.len, &used, &pl), SD_OK);
    SD_CHECK(pl.p == NULL);
    SD_CHECK_EQ_INT(ssh_pkt_open(&rx, big, SSH_MAX_PACKET_LEN - 1, &used, &pl), SD_OK);
    SD_CHECK(pl.p == NULL);
    SD_CHECK_EQ_INT(ssh_pkt_open(&rx, big, SSH_MAX_PACKET_LEN + 64, &used, &pl), SD_E_CRYPTO);
    sd_wr_free(&w);
    ssh_dir_clear(&tx);
    ssh_dir_clear(&rx);
  }
  sd_free(big);
  /* ETM fails at once */
  {
    tu_det_random(key, sizeof(key)); tu_det_random(iv, sizeof(iv)); tu_det_random(mk, sizeof(mk));
    ssh_dir_init(&tx);
    ssh_dir_init(&rx);
    SD_REQUIRE(ssh_dir_set_keys(&tx, 1, "aes128-cbc", "hmac-sha1-etm@openssh.com", key, iv, mk) == SD_OK);
    SD_REQUIRE(ssh_dir_set_keys(&rx, 0, "aes128-cbc", "hmac-sha1-etm@openssh.com", key, iv, mk) == SD_OK);
    sd_wr_init(&w, 4096);
    seal_some(sd_t_, &tx, &w, 1);
    w.p[w.len - 1] ^= 1;
    SD_CHECK_EQ_INT(ssh_pkt_open(&rx, w.p, w.len, &used, &pl), SD_E_CRYPTO);
    sd_wr_free(&w);
    ssh_dir_clear(&tx);
    ssh_dir_clear(&rx);
  }
}
