/* Key file formats (01 §6.3, §6.6): OpenSSH v1 for every key type and cipher, PEM PKCS#1/SEC1 (plain
 * and DEK-Info), PKCS#8 (plain and PBES2), PuTTY PPK v2/v3 (Argon2), certificates, public key
 * files, DPAPI-kept keys, signatures. Fixtures: fixtures/keys (gen.sh; passphrase "correct horse"). */
#include <windows.h>
#include <stdio.h>
#include <time.h>
#include <string.h>

#include "sd_base/sd_mem.h"
#include "sd_crypto/sd_crypto.h"
#include "sd_ssh/sd_keyfile.h"
#include "sd_test.h"
#include "keyfile_internal.h"
#include "ssh_internal.h"
#include "test_util.h"

#define PASS "correct horse"

void ssh_pem_md5(const void *p, size_t n, uint8_t out[16]);

static int read_key(const char *name, uint8_t **buf, size_t *len)
{
  char path[MAX_PATH];
  _snprintf_s(path, sizeof(path), _TRUNCATE, "keys/%s", name);
  return tu_read_fixture(path, buf, len);
}

/* Public blob of keys/<name>.pub (or of a -cert.pub file). */
static int read_pub(const char *name, uint8_t *blob, size_t cap, size_t *bl)
{
  uint8_t *f;
  size_t n;
  int ok;
  if (!read_key(name, &f, &n)) return 0;
  ok = sd_ssh_pubkey_parse(f, n, blob, cap, bl, NULL, 0) == SD_OK;
  sd_free(f);
  return ok;
}

/* Verifies an SSH signature blob over data with the key's public part (independent of signing). */
static int verify_sig(const sd_ssh_key *k, const char *alg, const uint8_t *data, size_t dlen, const uint8_t *sig, size_t sl)
{
  sd_rd r, p;
  sd_span t, raw;
  sd_rd_init(&r, sig, sl);
  t = sd_rd_string(&r, 64);
  raw = sd_rd_string(&r, 4096);
  if (!sd_rd_done(&r) || !ssh_span_eq(t, alg)) return 0;
  sd_rd_init(&p, k->pub, k->pub_len);
  (void)sd_rd_string(&p, 64);
  if (k->kt == SSH_KT_ED25519) {
    sd_span pk = sd_rd_string(&p, 64);
    return raw.n == 64 && sd_ed25519_verify(raw.p, pk.p, data, dlen) == SD_OK;
  }
  if (k->kt == SSH_KT_ECDSA) {
    sd_span cn = sd_rd_string(&p, 64), q = sd_rd_string(&p, 256), rr, ss;
    sd_curve c = k->curve == 256 ? SD_CURVE_P256 : k->curve == 384 ? SD_CURVE_P384 : SD_CURVE_P521;
    sd_ec_key *ek = NULL;
    uint8_t dg[64];
    sd_rd in;
    int ok;
    (void)cn;
    sd_rd_init(&in, raw.p, raw.n);
    rr = sd_rd_mpint(&in, 80);
    ss = sd_rd_mpint(&in, 80);
    if (!sd_rd_done(&in) || sd_ec_import(c, q.p, q.n, NULL, 0, &ek) != SD_OK) return 0;
    sd_hash(sd_ec_hash(c), data, dlen, dg);
    ok = sd_ecdsa_verify(ek, dg, sd_hash_len(sd_ec_hash(c)), rr.p, rr.n, ss.p, ss.n) == SD_OK;
    sd_ec_free(ek);
    return ok;
  }
  {
    sd_span e = sd_rd_mpint(&p, 64), n = sd_rd_mpint(&p, 2049);
    sd_rsa_import_params ip;
    sd_rsa_key *rk = NULL;
    sd_hash_alg h = !strcmp(alg, "ssh-rsa") ? SD_HASH_SHA1 : !strcmp(alg, "rsa-sha2-256") ? SD_HASH_SHA256 : SD_HASH_SHA512;
    uint8_t dg[64], padded[2048];
    int ok;
    memset(&ip, 0, sizeof(ip));
    ip.n = n.p; ip.n_len = n.n;
    ip.e = e.p; ip.e_len = e.n;
    if (sd_rsa_import(&ip, &rk) != SD_OK) return 0;
    sd_hash(h, data, dlen, dg);
    memset(padded, 0, sizeof(padded));
    if (raw.n > sd_rsa_len(rk)) { sd_rsa_free(rk); return 0; }
    memcpy(padded + sd_rsa_len(rk) - raw.n, raw.p, raw.n);
    ok = sd_rsa_pkcs1_verify(rk, h, dg, sd_hash_len(h), padded, sd_rsa_len(rk)) == SD_OK;
    sd_rsa_free(rk);
    return ok;
  }
}

typedef struct kcase {
  const char *file, *pub, *type;
  uint32_t bits;
  int encrypted, format;
} kcase;

static const kcase k_cases[] = {
  { "ossh_ed25519", "ossh_ed25519.pub", "ssh-ed25519", 256, 0, SD_KEYFMT_OPENSSH },
  { "ossh_p256", "ossh_p256.pub", "ecdsa-sha2-nistp256", 256, 0, SD_KEYFMT_OPENSSH },
  { "ossh_p384", "ossh_p384.pub", "ecdsa-sha2-nistp384", 384, 0, SD_KEYFMT_OPENSSH },
  { "ossh_p521", "ossh_p521.pub", "ecdsa-sha2-nistp521", 521, 0, SD_KEYFMT_OPENSSH },
  { "ossh_rsa2048", "ossh_rsa2048.pub", "ssh-rsa", 2048, 0, SD_KEYFMT_OPENSSH },
  { "ossh_rsa1024", "ossh_rsa1024.pub", "ssh-rsa", 1024, 0, SD_KEYFMT_OPENSSH },
  { "ossh_rsa3072_enc", "ossh_rsa3072_enc.pub", "ssh-rsa", 3072, 1, SD_KEYFMT_OPENSSH },
  { "ossh_p384_enc", "ossh_p384_enc.pub", "ecdsa-sha2-nistp384", 384, 1, SD_KEYFMT_OPENSSH },
  { "ossh_ed25519_gcm", "ossh_ed25519_gcm.pub", "ssh-ed25519", 256, 1, SD_KEYFMT_OPENSSH },
  { "ossh_ed25519_chacha", "ossh_ed25519_chacha.pub", "ssh-ed25519", 256, 1, SD_KEYFMT_OPENSSH },
  { "ossh_p256_cbc", "ossh_p256_cbc.pub", "ecdsa-sha2-nistp256", 256, 1, SD_KEYFMT_OPENSSH },
  { "ossh_ed25519_ctr192", "ossh_ed25519_ctr192.pub", "ssh-ed25519", 256, 1, SD_KEYFMT_OPENSSH },
  { "pem_rsa", "pem_rsa.pub", "ssh-rsa", 2048, 0, SD_KEYFMT_PEM },
  { "pem_p256", "pem_p256.pub", "ecdsa-sha2-nistp256", 256, 0, SD_KEYFMT_PEM },
  { "pem_rsa_enc", "pem_rsa_enc.pub", "ssh-rsa", 2048, 1, SD_KEYFMT_PEM },
  { "pem_p521_enc", "pem_p521_enc.pub", "ecdsa-sha2-nistp521", 521, 1, SD_KEYFMT_PEM },
  { "pem_rsa_aes256", "pem_rsa.pub", "ssh-rsa", 2048, 1, SD_KEYFMT_PEM },
  { "pem_p256_des3", "pem_p256.pub", "ecdsa-sha2-nistp256", 256, 1, SD_KEYFMT_PEM },
  { "p8_rsa", "p8_rsa.pub", "ssh-rsa", 2048, 0, SD_KEYFMT_PKCS8 },
  { "p8_p384", "p8_p384.pub", "ecdsa-sha2-nistp384", 384, 0, SD_KEYFMT_PKCS8 },
  { "p8_rsa_enc", "p8_rsa_enc.pub", "ssh-rsa", 2048, 1, SD_KEYFMT_PKCS8 },
  { "p8_p256_enc", "p8_p256_enc.pub", "ecdsa-sha2-nistp256", 256, 1, SD_KEYFMT_PKCS8 },
  { "p8_rsa_des3_sha1", "pem_rsa.pub", "ssh-rsa", 2048, 1, SD_KEYFMT_PKCS8 },
  { "p8_p256_aes192_sha512", "pem_p256.pub", "ecdsa-sha2-nistp256", 256, 1, SD_KEYFMT_PKCS8 },
  { "p8_ed25519", NULL, "ssh-ed25519", 256, 0, SD_KEYFMT_PKCS8 },
  { "p8_ed25519_enc", NULL, "ssh-ed25519", 256, 1, SD_KEYFMT_PKCS8 },
  { "ppk2_ed25519", "ossh_ed25519.pub", "ssh-ed25519", 256, 0, SD_KEYFMT_PPK2 },
  { "ppk2_rsa_enc", "ossh_rsa2048.pub", "ssh-rsa", 2048, 1, SD_KEYFMT_PPK2 },
  { "ppk3_p256", "ossh_p256.pub", "ecdsa-sha2-nistp256", 256, 0, SD_KEYFMT_PPK3 },
  { "ppk3_ed25519_enc", "ossh_ed25519.pub", "ssh-ed25519", 256, 1, SD_KEYFMT_PPK3 },
  { "ppk3_rsa_enc", "ossh_rsa2048.pub", "ssh-rsa", 2048, 1, SD_KEYFMT_PPK3 },
  { "ppk3_p521_enc", "ossh_p521.pub", "ecdsa-sha2-nistp521", 521, 1, SD_KEYFMT_PPK3 },
};

SD_TEST(ssh_keyfmt_probe_load_sign_all)
{
  size_t i;
  static const uint8_t msg[] = "publickey signed data";
  if (!tu_crypto_or_skip("ssh_keyfmt_probe_load_sign_all")) return;
  for (i = 0; i < SD_COUNTOF(k_cases); i++) {
    const kcase *kc = &k_cases[i];
    uint8_t *f, pub[1024], sig[1200];
    size_t n, pl = 0, sl = 0;
    sd_ssh_key_probe_info info;
    sd_ssh_key *k = NULL;
    sd_err e;
    printf("  %s\n", kc->file);
    SD_REQUIRE(read_key(kc->file, &f, &n));
    SD_CHECK_EQ_INT(sd_ssh_key_probe(f, n, &info), SD_OK);
    SD_CHECK_EQ_INT(info.encrypted, kc->encrypted);
    SD_CHECK_EQ_INT(info.format, kc->format);
    if (info.pub_len) {
      SD_CHECK_STR(info.type, kc->type);
      SD_CHECK_EQ_INT(info.bits, kc->bits);
      SD_CHECK(!strncmp(info.fp_sha256, "SHA256:", 7));
    }
    if (kc->encrypted) {
      SD_CHECK_EQ_INT(sd_ssh_key_load(f, n, NULL, 0, &k), SD_E_KEY_PASSPHRASE_REQUIRED);
      e = sd_ssh_key_load(f, n, "wrong", 5, &k);
      SD_CHECK_EQ_INT(e, SD_E_BAD_PASSPHRASE);
      SD_CHECK(k == NULL);
    }
    e = sd_ssh_key_load(f, n, kc->encrypted ? PASS : NULL, kc->encrypted ? strlen(PASS) : 0, &k);
    SD_CHECK_EQ_INT(e, SD_OK);
    if (e == SD_OK && k) {
      size_t kl;
      const uint8_t *kp = sd_ssh_key_public_blob(k, &kl);
      SD_CHECK_STR(sd_ssh_key_type(k), kc->type);
      SD_CHECK_EQ_INT(sd_ssh_key_bits(k), kc->bits);
      if (info.pub_len) SD_CHECK(info.pub_len == kl && memcmp(info.pub_blob, kp, kl) == 0);
      if (kc->pub) {
        SD_REQUIRE(read_pub(kc->pub, pub, sizeof(pub), &pl));
        SD_CHECK(pl == kl && memcmp(pub, kp, kl) == 0);
      }
      SD_CHECK_EQ_INT(sd_ssh_key_sign(k, msg, sizeof(msg), sig, sizeof(sig), &sl), SD_OK);
      if (!strcmp(kc->type, "ssh-rsa")) {
        SD_CHECK(verify_sig(k, "rsa-sha2-512", msg, sizeof(msg), sig, sl));
        SD_CHECK_EQ_INT(sd_ssh_key_sign_alg(k, "rsa-sha2-256", msg, sizeof(msg), sig, sizeof(sig), &sl), SD_OK);
        SD_CHECK(verify_sig(k, "rsa-sha2-256", msg, sizeof(msg), sig, sl));
        SD_CHECK_EQ_INT(sd_ssh_key_sign_alg(k, "ssh-rsa", msg, sizeof(msg), sig, sizeof(sig), &sl), SD_OK);
        SD_CHECK(verify_sig(k, "ssh-rsa", msg, sizeof(msg), sig, sl));
        SD_CHECK_EQ_INT(sd_ssh_key_sign_alg(k, "rsa-sha2-512-cert-v01@openssh.com", msg, sizeof(msg), sig, sizeof(sig), &sl), SD_OK);
        SD_CHECK(verify_sig(k, "rsa-sha2-512", msg, sizeof(msg), sig, sl));
        SD_CHECK_EQ_INT(sd_ssh_key_sign_alg(k, "ssh-ed25519", msg, sizeof(msg), sig, sizeof(sig), &sl), SD_E_KEY_UNSUPPORTED);
      } else {
        SD_CHECK(verify_sig(k, kc->type, msg, sizeof(msg), sig, sl));
        SD_CHECK_EQ_INT(sd_ssh_key_sign_alg(k, "rsa-sha2-256", msg, sizeof(msg), sig, sizeof(sig), &sl), SD_E_KEY_UNSUPPORTED);
      }
      /* the OpenSSH serializer round-trips every type (DPAPI storage, C22) */
      {
        sd_secbuf *sb = NULL;
        sd_ssh_key *k2 = NULL;
        size_t l2;
        SD_CHECK_EQ_INT(sd_ssh_key_serialize_openssh(k, &sb), SD_OK);
        if (sb) {
          SD_CHECK_EQ_INT(sd_ssh_key_load(sb->p, sb->len, NULL, 0, &k2), SD_OK);
          if (k2) {
            const uint8_t *p2 = sd_ssh_key_public_blob(k2, &l2);
            SD_CHECK(l2 == kl && memcmp(p2, kp, kl) == 0);
            SD_CHECK_STR(sd_ssh_key_comment(k2), sd_ssh_key_comment(k));
          }
          sd_ssh_key_free(k2);
          sd_secbuf_free(sb);
        }
      }
    }
    sd_ssh_key_free(k);
    sd_free(f);
  }
}

SD_TEST(ssh_keyfmt_unsupported)
{
  static const char *const names[] = { "p8_scrypt", "p8_pbes1", "pem_dsa" };
  size_t i;
  for (i = 0; i < SD_COUNTOF(names); i++) {
    uint8_t *f;
    size_t n;
    sd_ssh_key *k = NULL;
    sd_ssh_key_probe_info info;
    SD_REQUIRE(read_key(names[i], &f, &n));
    SD_CHECK_EQ_INT(sd_ssh_key_load(f, n, PASS, strlen(PASS), &k), SD_E_KEY_UNSUPPORTED);
    SD_CHECK_EQ_INT(sd_ssh_key_probe(f, n, &info), SD_E_KEY_UNSUPPORTED);
    sd_free(f);
  }
  {
    static const char v1[] = "PuTTY-User-Key-File-1: ssh-rsa\n";
    static const char ssh2[] = "---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----\n";
    sd_ssh_key_probe_info info;
    SD_CHECK_EQ_INT(sd_ssh_key_probe((const uint8_t *)v1, strlen(v1), &info), SD_E_KEY_UNSUPPORTED);
    SD_CHECK_EQ_INT(sd_ssh_key_probe((const uint8_t *)ssh2, strlen(ssh2), &info), SD_E_KEY_UNSUPPORTED);
  }
}

/* Every truncation and a sweep of single-byte corruptions fail cleanly (no crash, no success with a
   different key). */
SD_TEST(ssh_keyfmt_truncation_and_corruption)
{
  static const char *const names[] = { "ossh_p256", "ossh_rsa2048", "pem_p256", "p8_rsa", "ppk3_p256", "ppk2_ed25519",
                                       "p8_ed25519" };
  size_t i, j;
  if (!tu_crypto_or_skip("ssh_keyfmt_truncation_and_corruption")) return;
  for (i = 0; i < SD_COUNTOF(names); i++) {
    uint8_t *f;
    size_t n;
    sd_ssh_key *k = NULL, *ref = NULL;
    SD_REQUIRE(read_key(names[i], &f, &n));
    SD_REQUIRE(sd_ssh_key_load(f, n, NULL, 0, &ref) == SD_OK);
    for (j = 0; j + 30 < n; j += 7) {
      if (sd_ssh_key_load(f, j, NULL, 0, &k) == SD_OK) { sd_ssh_key_free(k); k = NULL; SD_CHECK(!"truncated file loaded"); }
    }
    for (j = 40; j + 40 < n; j += 23) {
      uint8_t save = f[j];
      f[j] = (uint8_t)(save == 'A' ? 'B' : 'A');
      if (sd_ssh_key_load(f, n, NULL, 0, &k) == SD_OK) {
        size_t l1, l2;
        const uint8_t *p1 = sd_ssh_key_public_blob(k, &l1), *p2 = sd_ssh_key_public_blob(ref, &l2);
        /* base64 padding/comment bytes may change without effect; the key must stay the same */
        SD_CHECK(l1 == l2 && memcmp(p1, p2, l1) == 0);
        sd_ssh_key_free(k);
        k = NULL;
      }
      f[j] = save;
    }
    sd_ssh_key_free(ref);
    sd_free(f);
  }
}

SD_TEST(ssh_keyfmt_certificates)
{
  uint8_t blob[4096], kb[1024];
  size_t bl, kl;
  char type[64];
  sd_ssh_cert_info ci;
  uint8_t *f;
  size_t n;
  sd_ssh_key *k = NULL;
  SD_REQUIRE(read_key("ossh_ed25519-cert.pub", &f, &n));
  SD_CHECK_EQ_INT(sd_ssh_pubkey_parse(f, n, blob, sizeof(blob), &bl, type, sizeof(type)), SD_OK);
  SD_CHECK_STR(type, "ssh-ed25519-cert-v01@openssh.com");
  sd_free(f);
  SD_CHECK_EQ_INT(sd_ssh_cert_parse(blob, bl, &ci), SD_OK);
  SD_CHECK_STR(ci.key_type, "ssh-ed25519");
  SD_CHECK_EQ_INT(ci.cert_type, SD_CERT_USER);
  SD_CHECK_STR(ci.key_id, "sd-ed25519-cert");
  SD_CHECK_EQ_INT(ci.principal_count, 2);
  SD_CHECK(strstr(ci.principals, ",other") != NULL);
  SD_CHECK(!strncmp(ci.ca_fp_sha256, "SHA256:", 7));
  SD_CHECK(sd_ssh_cert_valid_at(&ci, (uint64_t)time(NULL)));
  SD_CHECK(!sd_ssh_cert_valid_at(&ci, 1000));
  SD_REQUIRE(read_pub("ossh_ed25519.pub", kb, sizeof(kb), &kl));
  SD_CHECK(ci.key_len == kl && memcmp(ci.key_blob, kb, kl) == 0);
  /* attaching: only to the certified key */
  SD_REQUIRE(read_key("ossh_ed25519", &f, &n));
  if (tu_crypto_or_skip("ssh_keyfmt_certificates(attach)")) {
    SD_REQUIRE(sd_ssh_key_load(f, n, NULL, 0, &k) == SD_OK);
    SD_CHECK_EQ_INT(sd_ssh_key_attach_cert(k, blob, bl), SD_OK);
    {
      size_t cl;
      SD_CHECK(sd_ssh_key_cert_blob(k, &cl) != NULL && cl == bl);
    }
    sd_ssh_key_free(k);
    k = NULL;
  }
  sd_free(f);
  if (tu_crypto_or_skip("ssh_keyfmt_certificates(mismatch)")) {
    SD_REQUIRE(read_key("ossh_p256", &f, &n));
    SD_REQUIRE(sd_ssh_key_load(f, n, NULL, 0, &k) == SD_OK);
    SD_CHECK_EQ_INT(sd_ssh_key_attach_cert(k, blob, bl), SD_E_KEY_FORMAT);
    sd_ssh_key_free(k);
    sd_free(f);
  }
  /* RSA and ECDSA certificates, expired and host certificates */
  {
    static const struct { const char *f, *type; uint32_t ctype; int valid; } cs[] = {
      { "ossh_p256-cert.pub", "ecdsa-sha2-nistp256-cert-v01@openssh.com", SD_CERT_USER, 1 },
      { "ossh_rsa2048-cert.pub", "ssh-rsa-cert-v01@openssh.com", SD_CERT_USER, 1 },
      { "ossh_p384_exp-cert.pub", "ecdsa-sha2-nistp384-cert-v01@openssh.com", SD_CERT_USER, 0 },
      { "ossh_p521_host-cert.pub", "ecdsa-sha2-nistp521-cert-v01@openssh.com", SD_CERT_HOST, 1 },
    };
    size_t i;
    for (i = 0; i < SD_COUNTOF(cs); i++) {
      SD_REQUIRE(read_key(cs[i].f, &f, &n));
      SD_CHECK_EQ_INT(sd_ssh_pubkey_parse(f, n, blob, sizeof(blob), &bl, type, sizeof(type)), SD_OK);
      SD_CHECK_STR(type, cs[i].type);
      SD_CHECK_EQ_INT(sd_ssh_cert_parse(blob, bl, &ci), SD_OK);
      SD_CHECK_EQ_INT(ci.cert_type, cs[i].ctype);
      SD_CHECK_EQ_INT(sd_ssh_cert_valid_at(&ci, (uint64_t)time(NULL)), cs[i].valid);
      /* truncated certificates are rejected */
      SD_CHECK(sd_ssh_cert_parse(blob, bl - 1, &ci) != SD_OK);
      sd_free(f);
    }
  }
}

SD_TEST(ssh_keyfmt_pubkey_files)
{
  uint8_t blob[1024], b2[1024];
  size_t bl, l2;
  char type[64];
  /* RFC 4716 with a continued header line, same key as the one-line form */
  static const char one[] = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDdtlhWJx8c2XC36nz8A2l1/6MUfcs+UVR5s7rw65xze c\n";
  static const char rfc[] =
    "---- BEGIN SSH2 PUBLIC KEY ----\r\n"
    "Comment: \"a very long comment that is continued \\\r\n"
    "on the next line\"\r\n"
    "AAAAC3NzaC1lZDI1NTE5AAAAIDdtlhWJx8c2XC36nz8A2l1/\r\n"
    "6MUfcs+UVR5s7rw65xze\r\n"
    "---- END SSH2 PUBLIC KEY ----\r\n";
  static const char bad_type[] = "ssh-rsa AAAAC3NzaC1lZDI1NTE5AAAAIDdtlhWJx8c2XC36nz8A2l1/6MUfcs+UVR5s7rw65xze\n";
  SD_CHECK_EQ_INT(sd_ssh_pubkey_parse((const uint8_t *)one, strlen(one), blob, sizeof(blob), &bl, type, sizeof(type)), SD_OK);
  SD_CHECK_STR(type, "ssh-ed25519");
  SD_CHECK_EQ_INT(sd_ssh_pubkey_parse((const uint8_t *)rfc, strlen(rfc), b2, sizeof(b2), &l2, type, sizeof(type)), SD_OK);
  SD_CHECK(bl == l2 && memcmp(blob, b2, bl) == 0);
  SD_CHECK_EQ_INT(sd_ssh_pubkey_parse((const uint8_t *)bad_type, strlen(bad_type), b2, sizeof(b2), &l2, NULL, 0), SD_E_KEY_FORMAT);
  SD_CHECK_EQ_INT(sd_ssh_pubkey_parse((const uint8_t *)"junk", 4, b2, sizeof(b2), &l2, NULL, 0), SD_E_KEY_FORMAT);
}

SD_TEST(ssh_keyfmt_dpapi_roundtrip)
{
  uint8_t *f, *img = NULL;
  size_t n, il = 0;
  sd_ssh_key *k = NULL, *k2 = NULL;
  sd_ssh_dpapi_info di;
  sd_secbuf *plain = NULL;
  if (!tu_crypto_or_skip("ssh_keyfmt_dpapi_roundtrip")) return;
  SD_REQUIRE(read_key("ossh_p384_enc", &f, &n));
  SD_REQUIRE(sd_ssh_key_load(f, n, PASS, strlen(PASS), &k) == SD_OK);
  SD_CHECK_EQ_INT(sd_ssh_key_dpapi_protect(k, "key-1234", L"test profile", &img, &il), SD_OK);
  SD_REQUIRE(img != NULL);
  SD_CHECK_EQ_INT(sd_ssh_key_dpapi_probe(img, il, &di), SD_OK);
  SD_CHECK_STR(di.type, "ecdsa-sha2-nistp384");
  SD_CHECK_STR(di.comment, "sd-p384-enc");
  {
    size_t kl;
    const uint8_t *kp = sd_ssh_key_public_blob(k, &kl);
    SD_CHECK(di.pub_len == kl && memcmp(di.pub_blob, kp, kl) == 0);
  }
  SD_CHECK_EQ_INT(sd_ssh_key_dpapi_unprotect(img, il, "other-id", &plain), SD_E_ACCESS_DENIED);
  SD_CHECK_EQ_INT(sd_ssh_key_dpapi_unprotect(img, il, "key-1234", &plain), SD_OK);
  if (plain) {
    SD_CHECK_EQ_INT(sd_ssh_key_load(plain->p, plain->len, NULL, 0, &k2), SD_OK);   /* no passphrase any more */
    SD_CHECK(k2 && ssh_key_pub_equal(k2, k->pub, k->pub_len));
    sd_secbuf_free(plain);
    plain = NULL;
  }
  /* a tampered clear public blob is detected after decryption */
  img[20 + 4 + 25] ^= 1;
  SD_CHECK(sd_ssh_key_dpapi_unprotect(img, il, "key-1234", &plain) != SD_OK || (sd_secbuf_free(plain), 0));
  SD_CHECK_EQ_INT(sd_ssh_key_dpapi_probe(img, 10, &di), SD_E_KEY_FORMAT);
  sd_ssh_key_free(k2);
  sd_ssh_key_free(k);
  sd_free(img);
  sd_free(f);
}

SD_TEST(ssh_keyfmt_md5_and_der)
{
  static const struct { const char *in, *hex; } v[] = {
    { "", "d41d8cd98f00b204e9800998ecf8427e" },
    { "abc", "900150983cd24fb0d6963f7d28e17f72" },
    { "message digest", "f96b697d7cb7938d525a2f31aaf161d0" },
    { "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
      "57edf4a22be3c955ac49da2e2107b67a" },
  };
  size_t i;
  for (i = 0; i < SD_COUNTOF(v); i++) {
    uint8_t d[16];
    char hex[33];
    int j;
    ssh_pem_md5(v[i].in, strlen(v[i].in), d);
    for (j = 0; j < 16; j++) _snprintf_s(hex + 2 * j, 3, _TRUNCATE, "%02x", d[j]);
    SD_CHECK_STR(hex, v[i].hex);
  }
  {
    /* DER strictness: non-minimal length, indefinite length, non-canonical and negative integers */
    static const uint8_t nonmin[] = { 0x04, 0x81, 0x05, 1, 2, 3, 4, 5 };
    static const uint8_t indef[] = { 0x30, 0x80, 0x02, 0x01, 0x01, 0x00, 0x00 };
    static const uint8_t nc[] = { 0x02, 0x02, 0x00, 0x05 };
    static const uint8_t neg[] = { 0x02, 0x01, 0x85 };
    static const uint8_t ok[] = { 0x02, 0x02, 0x00, 0x85 };
    ssh_der d;
    sd_span s;
    ssh_der_init(&d, nonmin, sizeof(nonmin));
    (void)ssh_der_tlv(&d, SSH_DER_OCTET_STRING);
    SD_CHECK(!ssh_der_ok(&d));
    ssh_der_init(&d, indef, sizeof(indef));
    (void)ssh_der_enter(&d, SSH_DER_SEQUENCE);
    SD_CHECK(!ssh_der_ok(&d));
    ssh_der_init(&d, nc, sizeof(nc));
    (void)ssh_der_uint(&d);
    SD_CHECK(!ssh_der_ok(&d));
    ssh_der_init(&d, neg, sizeof(neg));
    (void)ssh_der_uint(&d);
    SD_CHECK(!ssh_der_ok(&d));
    ssh_der_init(&d, ok, sizeof(ok));
    s = ssh_der_uint(&d);
    SD_CHECK(ssh_der_done(&d) && s.n == 1 && s.p[0] == 0x85);
    {
      static const uint8_t oid[] = { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01 };
      sd_span o;
      o.p = oid;
      o.n = sizeof(oid);
      SD_CHECK(ssh_der_oid_is(o, "1.2.840.113549.1.1.1"));
      SD_CHECK(!ssh_der_oid_is(o, "1.2.840.113549.1.1.11"));
    }
  }
}
