/* Algorithm lists (TM-R01, TM-R04, D34), KEXINIT encoding/parsing, negotiation, ident lines. */
#include <string.h>

#include "sd_base/sd_mem.h"
#include "sd_test.h"
#include "ssh_internal.h"

static int all_ciphers(const char *n) { SD_UNUSED(n); return 1; }
static int no_gcm(const char *n) { return strstr(n, "gcm") == NULL; }

/* Builds a server KEXINIT payload from CSV lists into w and parses it into k. */
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
  memcpy(l.comp, "none,zlib@openssh.com", 22);
  sd_wr_init(w, 65536);
  ssh_kexinit_encode(w, cookie, &l);
  return sd_wr_ok(w) && ssh_kexinit_parse(w->p, w->len, k) == SD_OK;
}

#define OPENSSH_KEX "sntrup761x25519-sha512,curve25519-sha256,curve25519-sha256@libssh.org,ext-info-s,kex-strict-s-v00@openssh.com"
#define OPENSSH_ENC "chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com"
#define OPENSSH_MAC "umac-64-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1"

SD_TEST(ssh_pick_first_client_match)
{
  sd_wr w;
  ssh_kexinit k;
  char out[64];
  SD_REQUIRE(make_server(&w, &k, OPENSSH_KEX, "rsa-sha2-512,ssh-ed25519", OPENSSH_ENC, OPENSSH_MAC));
  SD_CHECK(ssh_pick("curve25519-sha256@libssh.org,curve25519-sha256", k.kex, out, sizeof(out)));
  SD_CHECK_STR(out, "curve25519-sha256@libssh.org");
  SD_CHECK(!ssh_pick("ecdh-sha2-nistp256", k.kex, out, sizeof(out)));
  /* pseudo algorithms are never chosen */
  SD_CHECK(!ssh_pick("ext-info-c,kex-strict-c-v00@openssh.com", k.kex, out, sizeof(out)));
  sd_wr_free(&w);
}

SD_TEST(ssh_lists_strict_server_keeps_static_order)
{
  sd_wr w;
  ssh_kexinit k;
  ssh_list_input in;
  ssh_lists l;
  ssh_list_result r;
  SD_REQUIRE(make_server(&w, &k, OPENSSH_KEX, "ssh-ed25519", OPENSSH_ENC, OPENSSH_MAC));
  memset(&in, 0, sizeof(in));
  in.server = &k;
  in.initial = 1;
  in.cipher_available = all_ciphers;
  SD_CHECK_EQ_INT(ssh_build_lists(&in, &l, &r), SD_OK);
  SD_CHECK(r.strict);
  SD_CHECK(!r.terrapin_exposed);
  SD_CHECK(strncmp(l.enc_c2s, "chacha20-poly1305@openssh.com,", 30) == 0);
  SD_CHECK(ssh_csv_contains(l.kex, "ext-info-c"));
  SD_CHECK(ssh_csv_contains(l.kex, "kex-strict-c-v00@openssh.com"));
  SD_CHECK_STR(l.hostkey, "ssh-ed25519");
  /* hardware AES: GCM first */
  in.hw_aes = 1;
  SD_CHECK_EQ_INT(ssh_build_lists(&in, &l, &r), SD_OK);
  SD_CHECK(strncmp(l.enc_c2s, "aes256-gcm@openssh.com,", 23) == 0);
  /* rekey lists carry no pseudo algorithms */
  in.initial = 0;
  SD_CHECK_EQ_INT(ssh_build_lists(&in, &l, &r), SD_OK);
  SD_CHECK(!ssh_csv_contains(l.kex, "ext-info-c"));
  SD_CHECK(!ssh_csv_contains(l.kex, "kex-strict-c-v00@openssh.com"));
  sd_wr_free(&w);
}

SD_TEST(ssh_lists_terrapin_drops_chacha_without_strict)
{
  sd_wr w;
  ssh_kexinit k;
  ssh_list_input in;
  ssh_lists l;
  ssh_list_result r;
  ssh_algs a;
  const char *cat;
  SD_REQUIRE(make_server(&w, &k, "curve25519-sha256", "ssh-ed25519", OPENSSH_ENC, OPENSSH_MAC));
  memset(&in, 0, sizeof(in));
  in.server = &k;
  in.initial = 1;
  in.cipher_available = all_ciphers;
  SD_CHECK_EQ_INT(ssh_build_lists(&in, &l, &r), SD_OK);
  SD_CHECK(!r.strict);
  SD_CHECK(r.chacha_removed);
  SD_CHECK(!r.terrapin_exposed);
  SD_CHECK(!ssh_csv_contains(l.enc_c2s, "chacha20-poly1305@openssh.com"));
  SD_CHECK(!ssh_csv_contains(l.enc_s2c, "chacha20-poly1305@openssh.com"));
  SD_CHECK_EQ_INT(ssh_negotiate(&l, &k, &a, &cat), SD_OK);
  SD_CHECK_STR(a.enc_c2s, "aes256-gcm@openssh.com");
  SD_CHECK_STR(a.mac_c2s, "");          /* AEAD: no MAC */
  sd_wr_free(&w);

  /* without GCM, CTR + an ETM MAC is the unaffected choice */
  SD_REQUIRE(make_server(&w, &k, "curve25519-sha256", "ssh-ed25519", OPENSSH_ENC, OPENSSH_MAC));
  in.server = &k;
  in.cipher_available = no_gcm;
  SD_CHECK_EQ_INT(ssh_build_lists(&in, &l, &r), SD_OK);
  SD_CHECK_EQ_INT(ssh_negotiate(&l, &k, &a, &cat), SD_OK);
  SD_CHECK_STR(a.enc_c2s, "aes256-ctr");
  SD_CHECK_STR(a.mac_c2s, "hmac-sha2-256-etm@openssh.com");
  sd_wr_free(&w);
}

SD_TEST(ssh_lists_terrapin_exposed_only_chacha)
{
  sd_wr w;
  ssh_kexinit k;
  ssh_list_input in;
  ssh_lists l;
  ssh_list_result r;
  SD_REQUIRE(make_server(&w, &k, "curve25519-sha256", "ssh-ed25519", "chacha20-poly1305@openssh.com", "hmac-sha2-256"));
  memset(&in, 0, sizeof(in));
  in.server = &k;
  in.initial = 1;
  in.cipher_available = all_ciphers;
  SD_CHECK_EQ_INT(ssh_build_lists(&in, &l, &r), SD_OK);
  SD_CHECK(r.terrapin_exposed);
  SD_CHECK(ssh_csv_contains(l.enc_c2s, "chacha20-poly1305@openssh.com"));
  in.refuse_terrapin_exposed = 1;
  SD_CHECK_EQ_INT(ssh_build_lists(&in, &l, &r), SD_E_KEX_FAILED);
  sd_wr_free(&w);
}

SD_TEST(ssh_lists_fallback_ranks_aes_first)
{
  ssh_list_input in;
  ssh_lists l;
  ssh_list_result r;
  memset(&in, 0, sizeof(in));
  in.initial = 1;
  in.cipher_available = all_ciphers;
  SD_CHECK_EQ_INT(ssh_build_lists(&in, &l, &r), SD_OK);
  SD_CHECK(strncmp(l.enc_c2s, "aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr", 56) == 0);
  {
    size_t n = strlen(l.enc_c2s);
    SD_CHECK(n > 29 && strcmp(l.enc_c2s + n - 29, "chacha20-poly1305@openssh.com") == 0);
  }
}

SD_TEST(ssh_lists_hostkey_restricted_to_stored_types)
{
  ssh_list_input in;
  ssh_lists l;
  ssh_list_result r;
  sd_kh_types t;
  memset(&in, 0, sizeof(in));
  memset(&t, 0, sizeof(t));
  in.initial = 1;
  in.cipher_available = all_ciphers;
  in.stored = &t;
  /* nothing stored: full list */
  SD_CHECK_EQ_INT(ssh_build_lists(&in, &l, &r), SD_OK);
  SD_CHECK_STR(l.hostkey, "ssh-ed25519");
  /* only an RSA key stored: no M0 algorithm can verify it -> type unavailable, never a prompt */
  t.count = 1;
  memcpy(t.type[0], "ssh-rsa", 8);
  SD_CHECK_EQ_INT(ssh_build_lists(&in, &l, &r), SD_E_HOSTKEY_TYPE_UNAVAILABLE);
  t.count = 2;
  memcpy(t.type[1], "ssh-ed25519", 12);
  SD_CHECK_EQ_INT(ssh_build_lists(&in, &l, &r), SD_OK);
  SD_CHECK_STR(l.hostkey, "ssh-ed25519");
  /* only @cert-authority: cert algorithms only (none in M0) */
  t.count = 0;
  t.has_ca = 1;
  SD_CHECK_EQ_INT(ssh_build_lists(&in, &l, &r), SD_E_HOSTKEY_TYPE_UNAVAILABLE);
}

SD_TEST(ssh_lists_disabled_and_unavailable)
{
  ssh_list_input in;
  ssh_lists l;
  ssh_list_result r;
  memset(&in, 0, sizeof(in));
  in.initial = 1;
  in.cipher_available = all_ciphers;
  in.disabled = "chacha20-poly1305@openssh.com,aes128-ctr,hmac-sha2-512";
  SD_CHECK_EQ_INT(ssh_build_lists(&in, &l, &r), SD_OK);
  SD_CHECK(!ssh_csv_contains(l.enc_c2s, "chacha20-poly1305@openssh.com"));
  SD_CHECK(!ssh_csv_contains(l.enc_c2s, "aes128-ctr"));
  SD_CHECK(!ssh_csv_contains(l.mac_c2s, "hmac-sha2-512"));
  SD_CHECK(ssh_csv_contains(l.mac_c2s, "hmac-sha2-512-etm@openssh.com"));
  in.disabled = "curve25519-sha256,curve25519-sha256@libssh.org";
  SD_CHECK_EQ_INT(ssh_build_lists(&in, &l, &r), SD_E_KEX_FAILED);
}

SD_TEST(ssh_negotiate_reports_category)
{
  sd_wr w;
  ssh_kexinit k;
  ssh_list_input in;
  ssh_lists l;
  ssh_list_result r;
  ssh_algs a;
  const char *cat = NULL;
  SD_REQUIRE(make_server(&w, &k, OPENSSH_KEX, "rsa-sha2-512,ecdsa-sha2-nistp256", OPENSSH_ENC, OPENSSH_MAC));
  memset(&in, 0, sizeof(in));
  in.server = &k;
  in.initial = 1;
  in.cipher_available = all_ciphers;
  SD_CHECK_EQ_INT(ssh_build_lists(&in, &l, &r), SD_OK);
  SD_CHECK_EQ_INT(ssh_negotiate(&l, &k, &a, &cat), SD_E_KEX_FAILED);
  SD_CHECK_STR(cat, "hostkey");
  sd_wr_free(&w);
  SD_REQUIRE(make_server(&w, &k, OPENSSH_KEX, "ssh-ed25519", "aes128-ctr", "hmac-sha1"));
  in.server = &k;
  SD_CHECK_EQ_INT(ssh_build_lists(&in, &l, &r), SD_OK);
  SD_CHECK_EQ_INT(ssh_negotiate(&l, &k, &a, &cat), SD_E_KEX_FAILED);
  SD_CHECK_STR(cat, "mac");
  sd_wr_free(&w);
}

SD_TEST(ssh_kexinit_parse_rejects_truncated)
{
  sd_wr w;
  ssh_kexinit k;
  size_t i;
  SD_REQUIRE(make_server(&w, &k, OPENSSH_KEX, "ssh-ed25519", OPENSSH_ENC, OPENSSH_MAC));
  SD_CHECK(sd_namelist_contains(k.kex, "kex-strict-s-v00@openssh.com"));
  SD_CHECK(k.lang_c2s.n == 0);
  SD_CHECK(!k.first_kex_follows);
  for (i = 0; i < w.len; i += 7) SD_CHECK(ssh_kexinit_parse(w.p, i, &k) != SD_OK);
  w.p[0] = 21;
  SD_CHECK(ssh_kexinit_parse(w.p, w.len, &k) != SD_OK);
  sd_wr_free(&w);
}

SD_TEST(ssh_version_lines)
{
  size_t ll;
  int id;
  char out[256];
  static const char a[] = "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\r\nrest";
  static const char b[] = "hello banner\nSSH-2.0-x\n";
  static const char c[] = "SSH-1.5-old\r\n";
  static const char d[] = "SSH-1.99-Compat\n";
  static const char e[] = "SSH-2.0-partial";
  SD_CHECK_EQ_INT(ssh_version_line((const uint8_t *)a, strlen(a), &ll, &id, out, sizeof(out)), SD_OK);
  SD_CHECK(id && ll == 40);
  SD_CHECK_STR(out, "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13");
  SD_CHECK_EQ_INT(ssh_version_line((const uint8_t *)b, strlen(b), &ll, &id, out, sizeof(out)), SD_OK);
  SD_CHECK(!id && ll == 13);
  SD_CHECK_EQ_INT(ssh_version_line((const uint8_t *)c, strlen(c), &ll, &id, out, sizeof(out)), SD_E_PROTOCOL);
  SD_CHECK_EQ_INT(ssh_version_line((const uint8_t *)d, strlen(d), &ll, &id, out, sizeof(out)), SD_OK);
  SD_CHECK(id);
  SD_CHECK_EQ_INT(ssh_version_line((const uint8_t *)e, strlen(e), &ll, &id, out, sizeof(out)), SD_OK);
  SD_CHECK(ll == 0);
  {
    /* identification line longer than 255 bytes */
    char big[400];
    memset(big, 'a', sizeof(big));
    memcpy(big, "SSH-2.0-", 8);
    big[300] = '\n';
    SD_CHECK_EQ_INT(ssh_version_line((const uint8_t *)big, 301, &ll, &id, out, sizeof(out)), SD_E_PROTOCOL);
  }
}

SD_TEST(ssh_base64_roundtrip)
{
  static const char *const vec[][2] = {
    { "", "" }, { "f", "Zg==" }, { "fo", "Zm8=" }, { "foo", "Zm9v" }, { "foob", "Zm9vYg==" },
    { "fooba", "Zm9vYmE=" }, { "foobar", "Zm9vYmFy" }
  };
  size_t i;
  for (i = 0; i < SD_COUNTOF(vec); i++) {
    char enc[32];
    uint8_t dec[32];
    size_t n = 0;
    SD_CHECK(ssh_b64_encode((const uint8_t *)vec[i][0], strlen(vec[i][0]), enc, sizeof(enc), 1) == strlen(vec[i][1]));
    SD_CHECK_STR(enc, vec[i][1]);
    SD_CHECK_EQ_INT(ssh_b64_decode(vec[i][1], strlen(vec[i][1]), dec, sizeof(dec), &n, 0), SD_OK);
    SD_CHECK(n == strlen(vec[i][0]) && memcmp(dec, vec[i][0], n) == 0);
  }
  {
    uint8_t dec[8];
    size_t n;
    SD_CHECK(ssh_b64_decode("Zm9v=Zg", 7, dec, sizeof(dec), &n, 0) != SD_OK);   /* data after padding */
    SD_CHECK(ssh_b64_decode("Zh==", 4, dec, sizeof(dec), &n, 0) != SD_OK);      /* non-zero trailing bits */
    SD_CHECK(ssh_b64_decode("Z", 1, dec, sizeof(dec), &n, 0) != SD_OK);
    SD_CHECK(ssh_b64_decode("Zm9v\r\nYmFy", 10, dec, sizeof(dec), &n, 1) == SD_OK && n == 6);
    SD_CHECK(ssh_b64_decode("Zm9v\r\nYmFy", 10, dec, sizeof(dec), &n, 0) != SD_OK);
  }
}
