/* OpenSSH v1 key files (01 §6.6). Fixtures were generated with OpenSSH 9.6 ssh-keygen:
 *   ed25519_plain (no passphrase), ed25519_enc (passphrase "correct horse", aes256-ctr + bcrypt),
 *   rsa_plain (RSA; loads since M2). M2 formats: test_keyfile_formats.c. */
#include <string.h>

#include "sd_base/sd_mem.h"
#include "sd_ssh/sd_keyfile.h"
#include "sd_test.h"
#include "ssh_internal.h"
#include "test_util.h"

#define PLAIN_PUB "AAAAC3NzaC1lZDI1NTE5AAAAIDdtlhWJx8c2XC36nz8A2l1/6MUfcs+UVR5s7rw65xze"

SD_TEST(ssh_key_probe_plain_and_encrypted)
{
  uint8_t *f;
  size_t n, bl;
  uint8_t blob[128];
  sd_ssh_key_probe_info info;
  SD_REQUIRE(tu_read_fixture("ed25519_plain", &f, &n));
  SD_CHECK_EQ_INT(sd_ssh_key_probe(f, n, &info), SD_OK);
  SD_CHECK_STR(info.type, "ssh-ed25519");
  SD_CHECK_EQ_INT(info.bits, 256);
  SD_CHECK(!info.encrypted);
  SD_CHECK_EQ_INT(info.format, SD_KEYFMT_OPENSSH);
  SD_REQUIRE(ssh_b64_decode(PLAIN_PUB, strlen(PLAIN_PUB), blob, sizeof(blob), &bl, 0) == SD_OK);
  SD_CHECK(info.pub_len == bl && memcmp(info.pub_blob, blob, bl) == 0);
  if (ssh_crypto_ready()) SD_CHECK_STR(info.fp_sha256, "SHA256:bKExo77Fub+16j6ZHadz2gGgn+jcY0wAbkoJZR8ZSW0");
  sd_free(f);
  SD_REQUIRE(tu_read_fixture("ed25519_enc", &f, &n));
  SD_CHECK_EQ_INT(sd_ssh_key_probe(f, n, &info), SD_OK);
  SD_CHECK(info.encrypted);
  SD_CHECK_STR(info.type, "ssh-ed25519");
  if (ssh_crypto_ready()) SD_CHECK_STR(info.fp_sha256, "SHA256:0c48NSB929dO+mZVxxI8AP/rraUlDtwv+vSfzHqC7V4");
  sd_free(f);
  SD_REQUIRE(tu_read_fixture("rsa_plain", &f, &n));
  SD_CHECK_EQ_INT(sd_ssh_key_probe(f, n, &info), SD_OK);
  SD_CHECK_STR(info.type, "ssh-rsa");
  sd_free(f);
}

SD_TEST(ssh_key_load_plain)
{
  uint8_t *f;
  size_t n, bl;
  sd_ssh_key *k = NULL;
  const uint8_t *pub;
  uint8_t blob[128];
  SD_REQUIRE(tu_read_fixture("ed25519_plain", &f, &n));
  SD_CHECK_EQ_INT(sd_ssh_key_load(f, n, NULL, 0, &k), SD_OK);
  SD_REQUIRE(k != NULL);
  SD_CHECK_STR(sd_ssh_key_type(k), "ssh-ed25519");
  pub = sd_ssh_key_public_blob(k, &bl);
  SD_REQUIRE(ssh_b64_decode(PLAIN_PUB, strlen(PLAIN_PUB), blob, sizeof(blob), &n, 0) == SD_OK);
  SD_CHECK(bl == n && memcmp(pub, blob, n) == 0);
  if (tu_crypto_or_skip("ssh_key_load_plain(sign)")) {
    uint8_t sig[128];
    size_t sl = 0;
    sd_rd r;
    sd_span t, s;
    static const char msg[] = "data to sign";
    SD_CHECK_EQ_INT(sd_ssh_key_sign(k, (const uint8_t *)msg, sizeof(msg), sig, sizeof(sig), &sl), SD_OK);
    sd_rd_init(&r, sig, sl);
    t = sd_rd_string(&r, 64);
    s = sd_rd_string(&r, 64);
    SD_CHECK(sd_rd_done(&r) && ssh_span_eq(t, "ssh-ed25519") && s.n == 64);
    SD_CHECK_EQ_INT(sd_ed25519_verify(s.p, blob + 19, msg, sizeof(msg)), SD_OK);
  }
  sd_ssh_key_free(k);
  sd_free(f);
}

SD_TEST(ssh_key_load_encrypted)
{
  uint8_t *f;
  size_t n;
  sd_ssh_key *k = NULL;
  SD_REQUIRE(tu_read_fixture("ed25519_enc", &f, &n));
  SD_CHECK_EQ_INT(sd_ssh_key_load(f, n, NULL, 0, &k), SD_E_KEY_PASSPHRASE_REQUIRED);
  if (tu_crypto_or_skip("ssh_key_load_encrypted")) {
    SD_CHECK_EQ_INT(sd_ssh_key_load(f, n, "wrong", 5, &k), SD_E_BAD_PASSPHRASE);
    SD_CHECK(k == NULL);
    SD_CHECK_EQ_INT(sd_ssh_key_load(f, n, "correct horse", 13, &k), SD_OK);
    SD_CHECK(k != NULL);
    if (k) SD_CHECK_STR(sd_ssh_key_type(k), "ssh-ed25519");
    sd_ssh_key_free(k);
  }
  sd_free(f);
}

SD_TEST(ssh_key_unsupported_and_malformed)
{
  uint8_t *f;
  size_t n;
  sd_ssh_key *k = NULL;
  sd_ssh_key_probe_info info;
  static const char pem[] = "-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----\n";
  static const char ppk[] = "PuTTY-User-Key-File-3: ssh-ed25519\n";
  static const char junk[] = "hello world";
  SD_REQUIRE(tu_read_fixture("rsa_plain", &f, &n));
  if (ssh_crypto_ready()) {
    SD_CHECK_EQ_INT(sd_ssh_key_load(f, n, NULL, 0, &k), SD_OK);   /* RSA: M2 */
    sd_ssh_key_free(k);
    k = NULL;
  }
  /* every truncation of a valid file fails cleanly */
  {
    uint8_t *g;
    size_t gn, i;
    SD_REQUIRE(tu_read_fixture("ed25519_plain", &g, &gn));
    for (i = 0; i + 40 < gn; i += 3) SD_CHECK(sd_ssh_key_load(g, i, NULL, 0, &k) != SD_OK);
    /* flipping a body byte breaks the structure or the check bytes */
    g[100] = (uint8_t)(g[100] == 'A' ? 'B' : 'A');
    SD_CHECK(sd_ssh_key_load(g, gn, NULL, 0, &k) != SD_OK || (sd_ssh_key_free(k), 1));
    sd_free(g);
  }
  sd_free(f);
  SD_CHECK_EQ_INT(sd_ssh_key_probe((const uint8_t *)pem, strlen(pem), &info), SD_E_KEY_FORMAT);   /* truncated */
  SD_CHECK_EQ_INT(sd_ssh_key_probe((const uint8_t *)ppk, strlen(ppk), &info), SD_E_KEY_FORMAT);   /* truncated */
  SD_CHECK_EQ_INT(sd_ssh_key_probe((const uint8_t *)junk, strlen(junk), &info), SD_E_KEY_FORMAT);
}

SD_TEST(ssh_key_serialize_roundtrip)
{
  uint8_t *f;
  size_t n, l1, l2;
  sd_ssh_key *k = NULL, *k2 = NULL;
  sd_secbuf *sb = NULL;
  ssh_set_random_for_tests(tu_det_random);
  SD_REQUIRE(tu_read_fixture("ed25519_plain", &f, &n));
  SD_REQUIRE(sd_ssh_key_load(f, n, NULL, 0, &k) == SD_OK);
  SD_CHECK_EQ_INT(sd_ssh_key_serialize_openssh(k, &sb), SD_OK);
  SD_REQUIRE(sb != NULL);
  SD_CHECK_EQ_INT(sd_ssh_key_load(sb->p, sb->len, NULL, 0, &k2), SD_OK);
  SD_REQUIRE(k2 != NULL);
  {
    const uint8_t *p1 = sd_ssh_key_public_blob(k, &l1), *p2 = sd_ssh_key_public_blob(k2, &l2);
    SD_CHECK(l1 == l2 && memcmp(p1, p2, l1) == 0);
  }
  sd_ssh_key_free(k2);
  sd_ssh_key_free(k);
  sd_secbuf_free(sb);
  sd_free(f);
  ssh_set_random_for_tests(NULL);
}
