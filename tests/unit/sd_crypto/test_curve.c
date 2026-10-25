/* X25519 (RFC 7748 §5.2, §6.1, Wycheproof) and Ed25519 (RFC 8032 §7.1, Wycheproof) tests. */
#include <stdlib.h>
#include <string.h>

#include "sd_crypto/sd_crypto.h"
#include "sd_test.h"
#include "tutil.h"

static void hx(sd_test_ctx *sd_t_, const char *hex, uint8_t *out, size_t n)
{
  size_t got = tu_hexbuf(hex, out, n);
  if (got != n)
    sd_test_fail(sd_t_, __FILE__, __LINE__, "bad test hex: %s", hex);
}

SD_TEST(x25519_rfc7748)
{
  uint8_t k[32], u[32], want[32], out[32], t[32];
  int i;
  hx(sd_t_, "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4", k, 32);
  hx(sd_t_, "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c", u, 32);
  hx(sd_t_, "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552", want, 32);
  SD_CHECK(sd_x25519(out, k, u) == SD_OK);
  SD_CHECK_MEM(out, want, 32);
  hx(sd_t_, "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d", k, 32);
  hx(sd_t_, "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493", u, 32);
  hx(sd_t_, "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957", want, 32);
  SD_CHECK(sd_x25519(out, k, u) == SD_OK);
  SD_CHECK_MEM(out, want, 32);
  /* iterated: k = u = 9; k, u = X25519(k, u), k */
  memset(k, 0, 32); k[0] = 9;
  memcpy(u, k, 32);
  for (i = 1; i <= 1000; i++) {
    SD_REQUIRE(sd_x25519(t, k, u) == SD_OK);
    memcpy(u, k, 32);
    memcpy(k, t, 32);
    if (i == 1) {
      hx(sd_t_, "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079", want, 32);
      SD_CHECK_MEM(k, want, 32);
    }
  }
  hx(sd_t_, "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51", want, 32);
  SD_CHECK_MEM(k, want, 32);
}

SD_TEST(x25519_rfc7748_dh)
{
  uint8_t a[32], b[32], pa[32], pb[32], want[32], s1[32], s2[32];
  hx(sd_t_, "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a", a, 32);
  hx(sd_t_, "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb", b, 32);
  SD_CHECK(sd_x25519_base(pa, a) == SD_OK);
  SD_CHECK(sd_x25519_base(pb, b) == SD_OK);
  hx(sd_t_, "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a", want, 32);
  SD_CHECK_MEM(pa, want, 32);
  hx(sd_t_, "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f", want, 32);
  SD_CHECK_MEM(pb, want, 32);
  SD_CHECK(sd_x25519(s1, a, pb) == SD_OK);
  SD_CHECK(sd_x25519(s2, b, pa) == SD_OK);
  hx(sd_t_, "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742", want, 32);
  SD_CHECK_MEM(s1, want, 32);
  SD_CHECK_MEM(s2, want, 32);
}

SD_TEST(wycheproof_x25519)
{
  tu_lines l;
  char *f[8];
  int n, count = 0;
  SD_REQUIRE(tu_lines_open(&l, "wycheproof/x25519_test.txt") == 0);
  while ((n = tu_lines_next(&l, f, 8)) != 0) {
    uint8_t pub[32], priv[32], shared[32], out[32];
    sd_err err;
    int zero;
    SD_REQUIRE(n == 6);
    hx(sd_t_, f[1], pub, 32);
    hx(sd_t_, f[2], priv, 32);
    hx(sd_t_, f[3], shared, 32);
    err = sd_x25519(out, priv, pub);
    zero = strstr(f[5], "ZeroSharedSecret") != NULL;
    if (zero) {
      /* acceptable either way by Wycheproof; we must reject (RFC 8731) */
      if (err != SD_E_CRYPTO)
        sd_test_fail(sd_t_, __FILE__, __LINE__, "x25519 tcId %s: zero shared secret not rejected", f[0]);
    } else if (f[4][0] != 'i') {
      if (err != SD_OK || memcmp(out, shared, 32) != 0)
        sd_test_fail(sd_t_, __FILE__, __LINE__, "x25519 tcId %s: wrong result", f[0]);
    }
    count++;
  }
  tu_lines_close(&l);
  SD_CHECK(count == 518);
}

typedef struct ed_kat { const char *seed, *pub, *msg, *sig; } ed_kat;

static const ed_kat k_ed[] = {
  { "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "-",
    "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46b"
    "d25bf5f0595bbe24655141438e7a100b" },
  { "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
    "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72",
    "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c"
    "387b2eaeb4302aeeb00d291612bb0c00" },
  { "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
    "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025", "af82",
    "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc659"
    "4a7c15e9716ed28dc027beceea1ec40a" },
};

SD_TEST(ed25519_rfc8032)
{
  size_t i;
  for (i = 0; i < SD_COUNTOF(k_ed); i++) {
    uint8_t seed[32], pub[32], want_sig[64], sig[64], got_pub[32], *msg;
    size_t ml;
    hx(sd_t_, k_ed[i].seed, seed, 32);
    hx(sd_t_, k_ed[i].pub, pub, 32);
    hx(sd_t_, k_ed[i].sig, want_sig, 64);
    ml = tu_hex(k_ed[i].msg, &msg);
    SD_CHECK(sd_ed25519_pub_from_seed(got_pub, seed) == SD_OK);
    SD_CHECK_MEM(got_pub, pub, 32);
    SD_CHECK(sd_ed25519_sign(sig, seed, pub, msg, ml) == SD_OK);
    SD_CHECK_MEM(sig, want_sig, 64);
    SD_CHECK(sd_ed25519_sign(sig, seed, NULL, msg, ml) == SD_OK);
    SD_CHECK_MEM(sig, want_sig, 64);
    SD_CHECK(sd_ed25519_verify(sig, pub, msg, ml) == SD_OK);
    sig[5] ^= 1;
    SD_CHECK(sd_ed25519_verify(sig, pub, msg, ml) == SD_E_CRYPTO);
    sig[5] ^= 1;
    sig[40] ^= 0x10;
    SD_CHECK(sd_ed25519_verify(sig, pub, msg, ml) == SD_E_CRYPTO);
    /* a wrong public key handed to sign is refused, not used */
    got_pub[0] ^= 1;
    SD_CHECK(sd_ed25519_sign(sig, seed, got_pub, msg, ml) == SD_E_INVALID_PARAM);
    free(msg);
  }
}

SD_TEST(ed25519_sign_verify_random)
{
  uint64_t rs = 99;
  int i;
  for (i = 0; i < 20; i++) {
    uint8_t seed[32], pub[32], sig[64], msg[100];
    size_t ml = tu_rand_u32(&rs) % sizeof(msg);
    tu_rand_fill(&rs, seed, 32);
    tu_rand_fill(&rs, msg, ml);
    SD_REQUIRE(sd_ed25519_pub_from_seed(pub, seed) == SD_OK);
    SD_REQUIRE(sd_ed25519_sign(sig, seed, pub, msg, ml) == SD_OK);
    SD_CHECK(sd_ed25519_verify(sig, pub, msg, ml) == SD_OK);
    msg[0] ^= 0x80;
    SD_CHECK(sd_ed25519_verify(sig, pub, msg, ml ? ml : 1) == SD_E_CRYPTO);
  }
}

SD_TEST(ed25519_rejects_noncanonical_s)
{
  /* S + L must be rejected even though it verifies modulo L. */
  static const uint8_t L[32] = {
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10
  };
  uint8_t seed[32], pub[32], sig[64];
  unsigned carry = 0;
  int i;
  memset(seed, 7, 32);
  SD_REQUIRE(sd_ed25519_pub_from_seed(pub, seed) == SD_OK);
  SD_REQUIRE(sd_ed25519_sign(sig, seed, pub, "m", 1) == SD_OK);
  SD_REQUIRE(sd_ed25519_verify(sig, pub, "m", 1) == SD_OK);
  for (i = 0; i < 32; i++) {
    carry += (unsigned)sig[32 + i] + L[i];
    sig[32 + i] = (uint8_t)carry;
    carry >>= 8;
  }
  SD_CHECK(sd_ed25519_verify(sig, pub, "m", 1) == SD_E_CRYPTO);
}

SD_TEST(wycheproof_ed25519)
{
  tu_lines l;
  char *f[8];
  int n, count = 0;
  SD_REQUIRE(tu_lines_open(&l, "wycheproof/ed25519_test.txt") == 0);
  while ((n = tu_lines_next(&l, f, 8)) != 0) {
    uint8_t pk[32], *msg, *sig;
    size_t ml, sl;
    sd_err err = SD_E_CRYPTO;
    SD_REQUIRE(n == 5);
    hx(sd_t_, f[1], pk, 32);
    ml = tu_hex(f[2], &msg);
    sl = tu_hex(f[3], &sig);
    if (sl == 64)
      err = sd_ed25519_verify(sig, pk, msg, ml);
    if (f[4][0] == 'v' && err != SD_OK)
      sd_test_fail(sd_t_, __FILE__, __LINE__, "ed25519 tcId %s: valid signature rejected", f[0]);
    if (f[4][0] == 'i' && err == SD_OK)
      sd_test_fail(sd_t_, __FILE__, __LINE__, "ed25519 tcId %s: invalid signature accepted", f[0]);
    free(msg);
    free(sig);
    count++;
  }
  tu_lines_close(&l);
  SD_CHECK(count == 210);
}

/* 500 random cases from an independent big-integer reference (tests/vectors/refimpl/x25519_ref.py),
   including non-canonical u >= p and inputs with bit 255 set. */
SD_TEST(x25519_independent_reference)
{
  tu_lines l;
  char *f[4];
  int bad = 0, cnt = 0;
  SD_REQUIRE(tu_lines_open(&l, "refimpl/x25519_random.txt") == 0);
  while (tu_lines_next(&l, f, 4) == 3) {
    uint8_t k[32], u[32], w[32], o[32];
    hx(sd_t_, f[0], k, 32);
    hx(sd_t_, f[1], u, 32);
    hx(sd_t_, f[2], w, 32);
    cnt++;
    if ((sd_x25519(o, k, u) != SD_OK || memcmp(o, w, 32) != 0) && bad++ < 3)
      sd_test_fail(sd_t_, __FILE__, __LINE__, "case %d: k=%s u=%s", cnt, f[0], f[1]);
  }
  tu_lines_close(&l);
  SD_CHECK(cnt == 500);
}
