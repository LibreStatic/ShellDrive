/* Payload table signature (TM-R38, docs/design/04 §6.1): the pure verifier against generated test keys.
 *
 * The keys below are TEST keys: fixed seeds, used only in this file, never in a build that ships. They are not
 * release keys and are not in installer/keys/. Every signature is made here at test time with sd_ed25519_sign. */
#include <windows.h>
#include <strsafe.h>
#include <string.h>

#include "sd_crypto/sd_crypto.h"
#include "sd_test.h"
#include "setup_payload_sig.h"

#define T_NOW 1700000000LL

/* Test seeds (never a release key). */
static const uint8_t k_seed_stable[32] = {
  0x51, 0x01, 0x52, 0x03, 0x54, 0x05, 0x56, 0x07, 0x58, 0x09, 0x5a, 0x0b, 0x5c, 0x0d, 0x5e, 0x0f,
  0x61, 0x11, 0x62, 0x13, 0x64, 0x15, 0x66, 0x17, 0x68, 0x19, 0x6a, 0x1b, 0x6c, 0x1d, 0x6e, 0x1f };
static const uint8_t k_seed_stable2[32] = {
  0x71, 0x21, 0x72, 0x23, 0x74, 0x25, 0x76, 0x27, 0x78, 0x29, 0x7a, 0x2b, 0x7c, 0x2d, 0x7e, 0x2f,
  0x81, 0x31, 0x82, 0x33, 0x84, 0x35, 0x86, 0x37, 0x88, 0x39, 0x8a, 0x3b, 0x8c, 0x3d, 0x8e, 0x3f };
static const uint8_t k_seed_beta[32] = {
  0x91, 0x41, 0x92, 0x43, 0x94, 0x45, 0x96, 0x47, 0x98, 0x49, 0x9a, 0x4b, 0x9c, 0x4d, 0x9e, 0x4f,
  0xa1, 0x51, 0xa2, 0x53, 0xa4, 0x55, 0xa6, 0x57, 0xa8, 0x59, 0xaa, 0x5b, 0xac, 0x5d, 0xae, 0x5f };
static const uint8_t k_seed_other[32] = {
  0xb1, 0x61, 0xb2, 0x63, 0xb4, 0x65, 0xb6, 0x67, 0xb8, 0x69, 0xba, 0x6b, 0xbc, 0x6d, 0xbe, 0x6f,
  0xc1, 0x71, 0xc2, 0x73, 0xc4, 0x75, 0xc6, 0x77, 0xc8, 0x79, 0xca, 0x7b, 0xcc, 0x7d, 0xce, 0x7f };

static const char k_b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static void b64_encode64(const uint8_t *in, char out[89])
{
  size_t i, o = 0;
  for (i = 0; i < 63; i += 3) {
    uint32_t v = ((uint32_t)in[i] << 16) | ((uint32_t)in[i + 1] << 8) | in[i + 2];
    out[o++] = k_b64[(v >> 18) & 63];
    out[o++] = k_b64[(v >> 12) & 63];
    out[o++] = k_b64[(v >> 6) & 63];
    out[o++] = k_b64[v & 63];
  }
  /* 64 bytes = 21 full groups + one byte: the last group is "X==" */
  {
    uint32_t v = (uint32_t)in[63] << 16;
    out[o++] = k_b64[(v >> 18) & 63];
    out[o++] = k_b64[(v >> 12) & 63];
    out[o++] = '=';
    out[o++] = '=';
  }
  out[o] = '\0';
}

static void hexlow(const uint8_t *in, size_t n, char *out)
{
  static const char h[] = "0123456789abcdef";
  size_t i;
  for (i = 0; i < n; i++) {
    out[2 * i] = h[in[i] >> 4];
    out[2 * i + 1] = h[in[i] & 15];
  }
  out[2 * n] = '\0';
}

/* The table of a test build: header and one flavour line. */
static size_t make_table(char *buf, size_t cap, const char *channel, const char *tail)
{
  HRESULT hr = StringCchPrintfA(buf, cap,
    "shelldrive-payload-table 1\nproduct com.librestatic.shelldrive\nchannel %s\n"
    "x86-ia32 0000000000000000000000000000000000000000000000000000000000000001 100\n%s",
    channel, tail != NULL ? tail : "");
  return SUCCEEDED(hr) ? strlen(buf) : 0;
}

/* Signature line "sig ed25519 <kid> <b64>\n" over domain || table (or over the table alone when raw). */
static size_t make_sig(const uint8_t seed[32], const char *table, size_t tlen, int raw, char *out, size_t cap)
{
  static uint8_t msg[sizeof(SD_SETUP_PSIG_DOMAIN) + SD_SETUP_PSIG_TABLE_MAX];
  uint8_t pub[32], h[32], sig[64];
  char kid[17], b64[89];
  size_t dl = raw ? 0 : sizeof(SD_SETUP_PSIG_DOMAIN) - 1;
  if (cap < 128)
    return 0;
  sd_ed25519_pub_from_seed(pub, seed);
  sd_hash(SD_HASH_SHA256, pub, 32, h);
  hexlow(h, 8, kid);
  memcpy(msg, raw ? "" : SD_SETUP_PSIG_DOMAIN, dl);
  memcpy(msg + dl, table, tlen);
  sd_ed25519_sign(sig, seed, pub, msg, dl + tlen);
  b64_encode64(sig, b64);
  StringCchPrintfA(out, cap, "sig ed25519 %s %s\n", kid, b64);
  return strlen(out);
}

static void keyring_for(sd_setup_psig_key *k, const uint8_t seed[32], const char *channel, int64_t from, int64_t to,
                        int revoked)
{
  memset(k, 0, sizeof(*k));
  sd_ed25519_pub_from_seed(k->pub, seed);
  StringCchCopyA(k->channel, sizeof(k->channel), channel);
  k->valid_from = from;
  k->valid_to = to;
  k->revoked = revoked;
}

/* A signed stable table, verified against the given ring. */
static sd_setup_psig_res verify_with(const char *table, const char *sig, const sd_setup_psig_key *ring, size_t n,
                                     const char *build_channel, int64_t now)
{
  return sd_setup_psig_verify((const uint8_t *)table, strlen(table), (const uint8_t *)sig, strlen(sig), ring, n,
                              build_channel, now);
}

SD_TEST(psig_valid_stable_table)
{
  char table[SD_SETUP_PSIG_TABLE_MAX + 1], sig[256];
  size_t tl = make_table(table, sizeof(table), "stable", NULL);
  sd_setup_psig_key ring[1];
  keyring_for(&ring[0], k_seed_stable, "stable", 0, T_NOW * 2, 0);
  make_sig(k_seed_stable, table, tl, 0, sig, sizeof(sig));
  SD_CHECK_EQ_INT(verify_with(table, sig, ring, 1, "stable", T_NOW), SD_SETUP_PSIG_OK);
}

SD_TEST(psig_tampered_table_refused)
{
  char table[SD_SETUP_PSIG_TABLE_MAX + 1], sig[256];
  size_t tl = make_table(table, sizeof(table), "stable", NULL);
  sd_setup_psig_key ring[1];
  keyring_for(&ring[0], k_seed_stable, "stable", 0, T_NOW * 2, 0);
  make_sig(k_seed_stable, table, tl, 0, sig, sizeof(sig));
  /* One digit of the size changes (100 -> 101): the hash line is covered by the signature. */
  table[tl - 2] = '1';      /* "100\n" -> "101\n" */
  SD_CHECK_EQ_INT(verify_with(table, sig, ring, 1, "stable", T_NOW), SD_SETUP_PSIG_E_SIGNATURE);
}

SD_TEST(psig_raw_table_without_domain_refused)
{
  char table[SD_SETUP_PSIG_TABLE_MAX + 1], sig[256];
  size_t tl = make_table(table, sizeof(table), "stable", NULL);
  sd_setup_psig_key ring[1];
  keyring_for(&ring[0], k_seed_stable, "stable", 0, T_NOW * 2, 0);
  make_sig(k_seed_stable, table, tl, 1, sig, sizeof(sig));   /* signed without the domain string */
  SD_CHECK_EQ_INT(verify_with(table, sig, ring, 1, "stable", T_NOW), SD_SETUP_PSIG_E_SIGNATURE);
}

SD_TEST(psig_wrong_build_channel_refused)
{
  char table[SD_SETUP_PSIG_TABLE_MAX + 1], sig[256];
  size_t tl = make_table(table, sizeof(table), "stable", NULL);
  sd_setup_psig_key ring[1];
  keyring_for(&ring[0], k_seed_stable, "stable", 0, T_NOW * 2, 0);
  make_sig(k_seed_stable, table, tl, 0, sig, sizeof(sig));
  SD_CHECK_EQ_INT(verify_with(table, sig, ring, 1, "beta", T_NOW), SD_SETUP_PSIG_E_CHANNEL);
}

SD_TEST(psig_beta_table_signed_by_stable_key_refused)
{
  char table[SD_SETUP_PSIG_TABLE_MAX + 1], sig[256];
  size_t tl = make_table(table, sizeof(table), "beta", NULL);
  sd_setup_psig_key ring[2];
  keyring_for(&ring[0], k_seed_stable, "stable", 0, T_NOW * 2, 0);
  keyring_for(&ring[1], k_seed_beta, "beta", 0, T_NOW * 2, 0);
  /* The stable key signs a beta table: channel binding (TM-R37) refuses it, even though the signature is valid. */
  make_sig(k_seed_stable, table, tl, 0, sig, sizeof(sig));
  SD_CHECK_EQ_INT(verify_with(table, sig, ring, 2, "beta", T_NOW), SD_SETUP_PSIG_E_CHANNEL);
  /* The beta key signs it: accepted for beta. */
  make_sig(k_seed_beta, table, tl, 0, sig, sizeof(sig));
  SD_CHECK_EQ_INT(verify_with(table, sig, ring, 2, "beta", T_NOW), SD_SETUP_PSIG_OK);
  /* And a beta-signed table is never accepted by a stable build. */
  SD_CHECK_EQ_INT(verify_with(table, sig, ring, 2, "stable", T_NOW), SD_SETUP_PSIG_E_CHANNEL);
}

SD_TEST(psig_unknown_key_refused)
{
  char table[SD_SETUP_PSIG_TABLE_MAX + 1], sig[256];
  size_t tl = make_table(table, sizeof(table), "stable", NULL);
  sd_setup_psig_key ring[1];
  keyring_for(&ring[0], k_seed_stable, "stable", 0, T_NOW * 2, 0);
  make_sig(k_seed_stable2, table, tl, 0, sig, sizeof(sig));   /* a key that is not in the ring */
  SD_CHECK_EQ_INT(verify_with(table, sig, ring, 1, "stable", T_NOW), SD_SETUP_PSIG_E_UNKNOWN_KEY);
  /* Key ID rewritten to the ring key's ID while the key is another one: the key ID check refuses it. */
  make_sig(k_seed_stable, table, tl, 0, sig, sizeof(sig));
  sig[12] = (sig[12] == '0') ? '1' : '0';
  SD_CHECK_EQ_INT(verify_with(table, sig, ring, 1, "stable", T_NOW), SD_SETUP_PSIG_E_UNKNOWN_KEY);
}

SD_TEST(psig_empty_keyring_fails_closed)
{
  char table[SD_SETUP_PSIG_TABLE_MAX + 1], sig[256];
  size_t tl = make_table(table, sizeof(table), "stable", NULL);
  make_sig(k_seed_stable, table, tl, 0, sig, sizeof(sig));
  SD_CHECK_EQ_INT(verify_with(table, sig, NULL, 0, "stable", T_NOW), SD_SETUP_PSIG_E_NO_KEYS);
}

SD_TEST(psig_revoked_and_expired_keys_refused)
{
  char table[SD_SETUP_PSIG_TABLE_MAX + 1], sig[256];
  size_t tl = make_table(table, sizeof(table), "stable", NULL);
  sd_setup_psig_key ring[1];
  make_sig(k_seed_stable, table, tl, 0, sig, sizeof(sig));

  keyring_for(&ring[0], k_seed_stable, "stable", 0, T_NOW * 2, 1);
  SD_CHECK_EQ_INT(verify_with(table, sig, ring, 1, "stable", T_NOW), SD_SETUP_PSIG_E_KEY_INVALID);

  /* Validity window [1000, 2000]: before and after are refused, inside is accepted. */
  keyring_for(&ring[0], k_seed_stable, "stable", 1000, 2000, 0);
  SD_CHECK_EQ_INT(verify_with(table, sig, ring, 1, "stable", 999), SD_SETUP_PSIG_E_KEY_INVALID);
  SD_CHECK_EQ_INT(verify_with(table, sig, ring, 1, "stable", 2001), SD_SETUP_PSIG_E_KEY_INVALID);
  SD_CHECK_EQ_INT(verify_with(table, sig, ring, 1, "stable", 1000), SD_SETUP_PSIG_OK);
  SD_CHECK_EQ_INT(verify_with(table, sig, ring, 1, "stable", 2000), SD_SETUP_PSIG_OK);
}

SD_TEST(psig_key_rotation_both_keys_accepted)
{
  char table[SD_SETUP_PSIG_TABLE_MAX + 1], sig[256];
  size_t tl = make_table(table, sizeof(table), "stable", NULL);
  sd_setup_psig_key ring[2];
  keyring_for(&ring[0], k_seed_stable, "stable", 0, T_NOW * 2, 1);     /* the old key, revoked */
  keyring_for(&ring[1], k_seed_stable2, "stable", 0, T_NOW * 2, 0);    /* its successor */
  make_sig(k_seed_stable2, table, tl, 0, sig, sizeof(sig));
  SD_CHECK_EQ_INT(verify_with(table, sig, ring, 2, "stable", T_NOW), SD_SETUP_PSIG_OK);
  make_sig(k_seed_stable, table, tl, 0, sig, sizeof(sig));
  SD_CHECK_EQ_INT(verify_with(table, sig, ring, 2, "stable", T_NOW), SD_SETUP_PSIG_E_KEY_INVALID);
}

SD_TEST(psig_header_and_format_refused)
{
  char table[SD_SETUP_PSIG_TABLE_MAX + 1], sig[256], bad[SD_SETUP_PSIG_TABLE_MAX + 64];
  sd_setup_psig_key ring[1];
  size_t tl;
  keyring_for(&ring[0], k_seed_stable, "stable", 0, T_NOW * 2, 0);

  /* Product of another vendor: refused before the signature is looked at. */
  tl = make_table(table, sizeof(table), "stable", NULL);
  StringCchCopyA(bad, sizeof(bad), table);
  {
    char *prod = strstr(bad, "com.librestatic");
    SD_CHECK(prod != NULL);
    if (prod != NULL)
      memcpy(prod, "com.example.evil", 16);
  }
  make_sig(k_seed_stable, bad, strlen(bad), 0, sig, sizeof(sig));
  SD_CHECK_EQ_INT(verify_with(bad, sig, ring, 1, "stable", T_NOW), SD_SETUP_PSIG_E_PRODUCT);

  /* Unknown channel name. */
  StringCchPrintfA(bad, sizeof(bad), "shelldrive-payload-table 1\nproduct com.librestatic.shelldrive\n"
                   "channel gamma\nx86-ia32 00 1\n");
  make_sig(k_seed_stable, bad, strlen(bad), 0, sig, sizeof(sig));
  SD_CHECK_EQ_INT(verify_with(bad, sig, ring, 1, "stable", T_NOW), SD_SETUP_PSIG_E_FORMAT);

  /* Missing magic line. */
  StringCchPrintfA(bad, sizeof(bad), "product com.librestatic.shelldrive\nchannel stable\n");
  make_sig(k_seed_stable, bad, strlen(bad), 0, sig, sizeof(sig));
  SD_CHECK_EQ_INT(verify_with(bad, sig, ring, 1, "stable", T_NOW), SD_SETUP_PSIG_E_FORMAT);

  /* CR line endings are not the table format. */
  StringCchCopyA(bad, sizeof(bad), table);
  bad[25] = '\r';
  make_sig(k_seed_stable, table, tl, 0, sig, sizeof(sig));
  SD_CHECK_EQ_INT(verify_with(bad, sig, ring, 1, "stable", T_NOW), SD_SETUP_PSIG_E_FORMAT);

  /* The table must end with LF: the same bytes without the last LF are a format error. */
  make_sig(k_seed_stable, table, tl, 0, sig, sizeof(sig));
  SD_CHECK_EQ_INT(sd_setup_psig_verify((const uint8_t *)table, tl - 1, (const uint8_t *)sig, strlen(sig), ring, 1,
                                       "stable", T_NOW),
                  SD_SETUP_PSIG_E_FORMAT);
}

SD_TEST(psig_signature_line_format_refused)
{
  char table[SD_SETUP_PSIG_TABLE_MAX + 1], sig[256], bad[256];
  sd_setup_psig_key ring[1];
  size_t tl = make_table(table, sizeof(table), "stable", NULL);
  keyring_for(&ring[0], k_seed_stable, "stable", 0, T_NOW * 2, 0);
  make_sig(k_seed_stable, table, tl, 0, sig, sizeof(sig));

  /* Trailing second line. */
  StringCchPrintfA(bad, sizeof(bad), "%s%s", sig, sig);
  SD_CHECK(verify_with(table, bad, ring, 1, "stable", T_NOW) != SD_SETUP_PSIG_OK);
  /* Missing LF. */
  StringCchCopyA(bad, sizeof(bad), sig);
  bad[strlen(bad) - 1] = ' ';
  SD_CHECK_EQ_INT(verify_with(table, bad, ring, 1, "stable", T_NOW), SD_SETUP_PSIG_E_FORMAT);
  /* Wrong algorithm name. */
  StringCchCopyA(bad, sizeof(bad), sig);
  bad[4] = 'x';
  SD_CHECK_EQ_INT(verify_with(table, bad, ring, 1, "stable", T_NOW), SD_SETUP_PSIG_E_FORMAT);
  /* Uppercase key ID. */
  StringCchCopyA(bad, sizeof(bad), sig);
  bad[12] = 'G';                              /* not a hex digit */
  SD_CHECK_EQ_INT(verify_with(table, bad, ring, 1, "stable", T_NOW), SD_SETUP_PSIG_E_FORMAT);
  /* Signature shorter than 64 bytes: a base64 group with the wrong padding. */
  StringCchCopyA(bad, sizeof(bad), sig);
  bad[strlen(bad) - 3] = 'A';
  bad[strlen(bad) - 2] = '=';
  SD_CHECK(verify_with(table, bad, ring, 1, "stable", T_NOW) != SD_SETUP_PSIG_OK);
  /* Oversized signature line (over SD_SETUP_PSIG_SIG_MAX). */
  {
    char big[512];
    memset(big, 'A', 300);
    big[300] = '\n';
    big[301] = '\0';
    SD_CHECK_EQ_INT(verify_with(table, big, ring, 1, "stable", T_NOW), SD_SETUP_PSIG_E_TOO_LARGE);
  }
}

SD_TEST(psig_size_limits)
{
  static char table[SD_SETUP_PSIG_TABLE_MAX + 2];
  char sig[256];
  sd_setup_psig_key ring[1];
  size_t tl;
  keyring_for(&ring[0], k_seed_stable, "stable", 0, T_NOW * 2, 0);

  /* Exactly the limit is accepted, one byte more is refused. */
  tl = make_table(table, sizeof(table), "stable", "");
  while (tl < SD_SETUP_PSIG_TABLE_MAX) {
    table[tl++] = '#';
  }
  table[tl - 1] = '\n';
  table[tl] = '\0';
  make_sig(k_seed_stable, table, tl, 0, sig, sizeof(sig));
  SD_CHECK_EQ_INT(verify_with(table, sig, ring, 1, "stable", T_NOW), SD_SETUP_PSIG_OK);

  /* One byte more than the limit: refused before the signature is looked at (the sig is only a placeholder). */
  table[tl] = '#';                 /* MAX + 1 bytes, still inside the buffer */
  table[tl + 1] = '\0';
  SD_CHECK_EQ_INT(sd_setup_psig_verify((const uint8_t *)table, tl + 1, (const uint8_t *)sig, strlen(sig), ring, 1,
                                       "stable", T_NOW),
                  SD_SETUP_PSIG_E_TOO_LARGE);
  SD_CHECK_EQ_INT(sd_setup_psig_verify((const uint8_t *)table, 0, (const uint8_t *)sig, strlen(sig), ring, 1,
                                       "stable", T_NOW),
                  SD_SETUP_PSIG_E_TOO_LARGE);
}

SD_TEST(psig_base64_canonical_only)
{
  uint8_t out[8];
  SD_CHECK_EQ_INT(sd_setup_psig_b64_decode("AAAA", 4, out, sizeof(out)), 3);
  SD_CHECK_EQ_INT(sd_setup_psig_b64_decode("AA==", 4, out, sizeof(out)), 1);
  SD_CHECK_EQ_INT(sd_setup_psig_b64_decode("AB==", 4, out, sizeof(out)), -1);   /* non-zero unused bits */
  SD_CHECK_EQ_INT(sd_setup_psig_b64_decode("AAA", 3, out, sizeof(out)), -1);    /* length not a multiple of 4 */
  SD_CHECK_EQ_INT(sd_setup_psig_b64_decode("A=AA", 4, out, sizeof(out)), -1);   /* padding in the middle */
  SD_CHECK_EQ_INT(sd_setup_psig_b64_decode("AA*A", 4, out, sizeof(out)), -1);
}

SD_TEST(psig_channel_helper_and_missing_resource)
{
  char table[SD_SETUP_PSIG_TABLE_MAX + 1], ch[16];
  make_table(table, sizeof(table), "beta", NULL);
  SD_CHECK_EQ_INT(sd_setup_psig_table_channel((const uint8_t *)table, strlen(table), ch, sizeof(ch)), 0);
  SD_CHECK(strcmp(ch, "beta") == 0);
  /* The test executable has no PAYLOAD_SIG resource, and the built-in keyring is revoked: refused. */
  SD_CHECK_EQ_INT(sd_setup_payload_sig_check(GetModuleHandleW(NULL), (const uint8_t *)table, strlen(table)),
                  SD_SETUP_PSIG_E_RESOURCE);
}
