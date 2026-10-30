/* Differential tests against CNG (01 Â§2.7.3): ECDSA (own sign -> CNG verify and CNG sign -> own verify),
 * ECDH (own vs CNG raw secret), RSA PKCS#1 v1.5 (identical deterministic signatures, cross verification,
 * CNG-generated keys imported into sd_crypto) and DH group14/16 (CNG raw secret). bcrypt.dll is resolved at
 * run time; each part is skipped with a note when the API is missing (raw secrets need Windows 8.1+). */
#include <windows.h>
#include <bcrypt.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pkt.h"
#include "sd_platform/sd_platform.h"
#include "sd_test.h"
#include "tutil.h"

#ifndef BCRYPT_KDF_RAW_SECRET
#define BCRYPT_KDF_RAW_SECRET L"TRUNCATE"
#endif
#ifndef BCRYPT_RSAFULLPRIVATE_BLOB
#define BCRYPT_RSAFULLPRIVATE_BLOB L"RSAFULLPRIVATEBLOB"
#endif

typedef NTSTATUS (WINAPI *pfn_open)(BCRYPT_ALG_HANDLE *, LPCWSTR, LPCWSTR, ULONG);
typedef NTSTATUS (WINAPI *pfn_close)(BCRYPT_ALG_HANDLE, ULONG);
typedef NTSTATUS (WINAPI *pfn_import_pair)(BCRYPT_ALG_HANDLE, BCRYPT_KEY_HANDLE, LPCWSTR, BCRYPT_KEY_HANDLE *,
                                           PUCHAR, ULONG, ULONG);
typedef NTSTATUS (WINAPI *pfn_export)(BCRYPT_KEY_HANDLE, BCRYPT_KEY_HANDLE, LPCWSTR, PUCHAR, ULONG, ULONG *, ULONG);
typedef NTSTATUS (WINAPI *pfn_gen_pair)(BCRYPT_ALG_HANDLE, BCRYPT_KEY_HANDLE *, ULONG, ULONG);
typedef NTSTATUS (WINAPI *pfn_finalize)(BCRYPT_KEY_HANDLE, ULONG);
typedef NTSTATUS (WINAPI *pfn_sign)(BCRYPT_KEY_HANDLE, VOID *, PUCHAR, ULONG, PUCHAR, ULONG, ULONG *, ULONG);
typedef NTSTATUS (WINAPI *pfn_verify)(BCRYPT_KEY_HANDLE, VOID *, PUCHAR, ULONG, PUCHAR, ULONG, ULONG);
typedef NTSTATUS (WINAPI *pfn_agree)(BCRYPT_KEY_HANDLE, BCRYPT_KEY_HANDLE, BCRYPT_SECRET_HANDLE *, ULONG);
typedef NTSTATUS (WINAPI *pfn_derive)(BCRYPT_SECRET_HANDLE, LPCWSTR, BCryptBufferDesc *, PUCHAR, ULONG, ULONG *,
                                      ULONG);
typedef NTSTATUS (WINAPI *pfn_destroy_secret)(BCRYPT_SECRET_HANDLE);
typedef NTSTATUS (WINAPI *pfn_destroy_key)(BCRYPT_KEY_HANDLE);
typedef NTSTATUS (WINAPI *pfn_set_prop)(BCRYPT_HANDLE, LPCWSTR, PUCHAR, ULONG, ULONG);

typedef struct cng {
  pfn_open open;
  pfn_close close;
  pfn_import_pair import_pair;
  pfn_export export_key;
  pfn_gen_pair gen_pair;
  pfn_finalize finalize;
  pfn_sign sign;
  pfn_verify verify;
  pfn_agree agree;
  pfn_derive derive;
  pfn_destroy_secret destroy_secret;
  pfn_destroy_key destroy_key;
  pfn_set_prop set_prop;
} cng;

#define RESOLVE(field, type, name) a->field = (type)sd_platform_resolve_by_name(L"bcrypt.dll", name)

static int cng_load(cng *a)
{
  RESOLVE(open, pfn_open, "BCryptOpenAlgorithmProvider");
  RESOLVE(close, pfn_close, "BCryptCloseAlgorithmProvider");
  RESOLVE(import_pair, pfn_import_pair, "BCryptImportKeyPair");
  RESOLVE(export_key, pfn_export, "BCryptExportKey");
  RESOLVE(gen_pair, pfn_gen_pair, "BCryptGenerateKeyPair");
  RESOLVE(finalize, pfn_finalize, "BCryptFinalizeKeyPair");
  RESOLVE(sign, pfn_sign, "BCryptSignHash");
  RESOLVE(verify, pfn_verify, "BCryptVerifySignature");
  RESOLVE(agree, pfn_agree, "BCryptSecretAgreement");
  RESOLVE(derive, pfn_derive, "BCryptDeriveKey");
  RESOLVE(destroy_secret, pfn_destroy_secret, "BCryptDestroySecret");
  RESOLVE(destroy_key, pfn_destroy_key, "BCryptDestroyKey");
  RESOLVE(set_prop, pfn_set_prop, "BCryptSetProperty");
  if (!(a->open && a->close && a->import_pair && a->export_key && a->gen_pair && a->finalize && a->sign &&
        a->verify && a->agree && a->derive && a->destroy_secret && a->destroy_key && a->set_prop)) {
    printf("    (CNG asymmetric API not available: differential test skipped)\n");
    return 0;
  }
  return 1;
}

static void reverse(uint8_t *p, size_t n)
{
  size_t i;
  for (i = 0; i < n / 2; i++) {
    uint8_t t = p[i];
    p[i] = p[n - 1 - i];
    p[n - 1 - i] = t;
  }
}

/* Raw secret of a CNG agreement, converted to big-endian. 0 if unsupported. */
static int cng_raw_secret(const cng *a, BCRYPT_KEY_HANDLE mine, BCRYPT_KEY_HANDLE peer, uint8_t *out, ULONG len)
{
  BCRYPT_SECRET_HANDLE s = NULL;
  ULONG got = 0;
  int ok;
  if (a->agree(mine, peer, &s, 0) != 0)
    return 0;
  ok = a->derive(s, BCRYPT_KDF_RAW_SECRET, NULL, out, len, &got, 0) == 0 && got == len;
  a->destroy_secret(s);
  if (ok)
    reverse(out, len);
  return ok;
}

static const struct { sd_curve c; LPCWSTR ecdsa, ecdh; ULONG pub_dsa, pub_dh, bits; } k_ec[] = {
  { SD_CURVE_P256, BCRYPT_ECDSA_P256_ALGORITHM, BCRYPT_ECDH_P256_ALGORITHM, BCRYPT_ECDSA_PUBLIC_P256_MAGIC,
    BCRYPT_ECDH_PUBLIC_P256_MAGIC, 256 },
  { SD_CURVE_P384, BCRYPT_ECDSA_P384_ALGORITHM, BCRYPT_ECDH_P384_ALGORITHM, BCRYPT_ECDSA_PUBLIC_P384_MAGIC,
    BCRYPT_ECDH_PUBLIC_P384_MAGIC, 384 },
  { SD_CURVE_P521, BCRYPT_ECDSA_P521_ALGORITHM, BCRYPT_ECDH_P521_ALGORITHM, BCRYPT_ECDSA_PUBLIC_P521_MAGIC,
    BCRYPT_ECDH_PUBLIC_P521_MAGIC, 521 },
};

/* BCRYPT_ECCPUBLIC_BLOB from an uncompressed point. */
static ULONG ecc_pub_blob(uint8_t *blob, ULONG magic, const uint8_t *pt, size_t fl)
{
  BCRYPT_ECCKEY_BLOB hdr;
  hdr.dwMagic = magic;
  hdr.cbKey = (ULONG)fl;
  memcpy(blob, &hdr, sizeof(hdr));
  memcpy(blob + sizeof(hdr), pt + 1, 2 * fl);
  return (ULONG)(sizeof(hdr) + 2 * fl);
}

SD_TEST(cng_diff_ecdsa)
{
  cng a;
  size_t ci;
  uint64_t seed = 186;
  if (!cng_load(&a))
    return;
  for (ci = 0; ci < SD_COUNTOF(k_ec); ci++) {
    BCRYPT_ALG_HANDLE alg = NULL;
    sd_curve c = k_ec[ci].c;
    size_t fl = sd_ec_field_len(c), pl = sd_ec_point_len(c);
    sd_hash_alg h = sd_ec_hash(c);
    ULONG hl = (ULONG)sd_hash_len(h);
    int it;
    SD_REQUIRE(a.open(&alg, k_ec[ci].ecdsa, NULL, 0) == 0);
    for (it = 0; it < 20; it++) {
      sd_ec_key *own = NULL, *imp = NULL;
      BCRYPT_KEY_HANDLE ck = NULL, cpriv = NULL;
      uint8_t pub[133], blob[256], dg[64], sig[132], r[66], s[66];
      ULONG bl, sl = 0;
      size_t l = sizeof(pub);
      tu_rand_fill(&seed, dg, hl);
      /* own key, own signature, CNG verification */
      SD_REQUIRE(sd_ec_generate(c, &own) == SD_OK);
      SD_REQUIRE(sd_ec_export_pub(own, pub, &l) == SD_OK && l == pl);
      bl = ecc_pub_blob(blob, k_ec[ci].pub_dsa, pub, fl);
      SD_REQUIRE(a.import_pair(alg, NULL, BCRYPT_ECCPUBLIC_BLOB, &ck, blob, bl, 0) == 0);
      SD_REQUIRE(sd_ecdsa_sign(own, h, dg, hl, sig, sig + fl) == SD_OK);
      if (a.verify(ck, NULL, dg, hl, sig, (ULONG)(2 * fl), 0) != 0)
        sd_test_fail(sd_t_, __FILE__, __LINE__, "CNG rejects our P-%u signature", (unsigned)k_ec[ci].bits);
      a.destroy_key(ck);
      /* CNG key, CNG signature, own verification; our signature with the imported CNG private key */
      SD_REQUIRE(a.gen_pair(alg, &cpriv, k_ec[ci].bits, 0) == 0 && a.finalize(cpriv, 0) == 0);
      SD_REQUIRE(a.export_key(cpriv, NULL, BCRYPT_ECCPRIVATE_BLOB, blob, sizeof(blob), &bl, 0) == 0);
      pub[0] = 0x04;
      memcpy(pub + 1, blob + sizeof(BCRYPT_ECCKEY_BLOB), 2 * fl);
      SD_REQUIRE(sd_ec_import(c, pub, pl, blob + sizeof(BCRYPT_ECCKEY_BLOB) + 2 * fl, fl, &imp) == SD_OK);
      SD_REQUIRE(a.sign(cpriv, NULL, dg, hl, sig, sizeof(sig), &sl, 0) == 0 && sl == 2 * fl);
      if (sd_ecdsa_verify(imp, dg, hl, sig, fl, sig + fl, fl) != SD_OK)
        sd_test_fail(sd_t_, __FILE__, __LINE__, "we reject a CNG P-%u signature", (unsigned)k_ec[ci].bits);
      SD_REQUIRE(sd_ecdsa_sign(imp, h, dg, hl, r, s) == SD_OK);
      memcpy(sig, r, fl);
      memcpy(sig + fl, s, fl);
      SD_CHECK(a.verify(cpriv, NULL, dg, hl, sig, (ULONG)(2 * fl), 0) == 0);
      sig[fl - 1] ^= 1;
      SD_CHECK(a.verify(cpriv, NULL, dg, hl, sig, (ULONG)(2 * fl), 0) != 0);
      a.destroy_key(cpriv);
      sd_ec_free(own);
      sd_ec_free(imp);
    }
    a.close(alg, 0);
  }
}

SD_TEST(cng_diff_ecdh)
{
  cng a;
  size_t ci;
  if (!cng_load(&a))
    return;
  for (ci = 0; ci < SD_COUNTOF(k_ec); ci++) {
    BCRYPT_ALG_HANDLE alg = NULL;
    sd_curve c = k_ec[ci].c;
    size_t fl = sd_ec_field_len(c), pl = sd_ec_point_len(c);
    int it;
    SD_REQUIRE(a.open(&alg, k_ec[ci].ecdh, NULL, 0) == 0);
    for (it = 0; it < 20; it++) {
      sd_ec_key *own = NULL;
      BCRYPT_KEY_HANDLE cpriv = NULL, cpub = NULL;
      uint8_t pub[133], blob[256], s1[66], s2[66];
      ULONG bl;
      size_t l = sizeof(pub);
      SD_REQUIRE(a.gen_pair(alg, &cpriv, k_ec[ci].bits, 0) == 0 && a.finalize(cpriv, 0) == 0);
      SD_REQUIRE(a.export_key(cpriv, NULL, BCRYPT_ECCPUBLIC_BLOB, blob, sizeof(blob), &bl, 0) == 0);
      SD_REQUIRE(sd_ec_generate(c, &own) == SD_OK);
      SD_REQUIRE(sd_ec_export_pub(own, pub, &l) == SD_OK);
      bl = ecc_pub_blob(blob, k_ec[ci].pub_dh, pub, fl);
      SD_REQUIRE(a.import_pair(alg, NULL, BCRYPT_ECCPUBLIC_BLOB, &cpub, blob, bl, 0) == 0);
      if (!cng_raw_secret(&a, cpriv, cpub, s2, (ULONG)fl)) {
        printf("    (CNG raw secret unsupported: ECDH differential skipped)\n");
        a.destroy_key(cpub);
        a.destroy_key(cpriv);
        sd_ec_free(own);
        a.close(alg, 0);
        return;
      }
      /* the CNG public point again, for our side */
      SD_REQUIRE(a.export_key(cpriv, NULL, BCRYPT_ECCPUBLIC_BLOB, blob, sizeof(blob), &bl, 0) == 0);
      pub[0] = 0x04;
      memcpy(pub + 1, blob + sizeof(BCRYPT_ECCKEY_BLOB), 2 * fl);
      l = sizeof(s1);
      SD_CHECK(sd_ecdh(own, pub, pl, s1, &l) == SD_OK && l == fl);
      if (memcmp(s1, s2, fl) != 0)
        sd_test_fail(sd_t_, __FILE__, __LINE__, "P-%u ECDH secret differs from CNG", (unsigned)k_ec[ci].bits);
      a.destroy_key(cpub);
      a.destroy_key(cpriv);
      sd_ec_free(own);
    }
    a.close(alg, 0);
  }
}

static ULONG rsa_blob(uint8_t *blob, ULONG magic, unsigned bits, const uint8_t *e, size_t el, const uint8_t *n,
                      size_t nl, const uint8_t *p, size_t pl, const uint8_t *q, size_t ql)
{
  BCRYPT_RSAKEY_BLOB hdr;
  uint8_t *w = blob + sizeof(hdr);
  hdr.Magic = magic;
  hdr.BitLength = bits;
  hdr.cbPublicExp = (ULONG)el;
  hdr.cbModulus = (ULONG)nl;
  hdr.cbPrime1 = (ULONG)pl;
  hdr.cbPrime2 = (ULONG)ql;
  memcpy(blob, &hdr, sizeof(hdr));
  memcpy(w, e, el); w += el;
  memcpy(w, n, nl); w += nl;
  if (p) { memcpy(w, p, pl); w += pl; memcpy(w, q, ql); w += ql; }
  return (ULONG)(w - blob);
}

static LPCWSTR cng_hash_name(sd_hash_alg h)
{
  switch ((int)h) {
  case 1: return BCRYPT_SHA1_ALGORITHM;
  case SD_HASH_SHA256: return BCRYPT_SHA256_ALGORITHM;
  case SD_HASH_SHA384: return BCRYPT_SHA384_ALGORITHM;
  default: return BCRYPT_SHA512_ALGORITHM;
  }
}

static const uint8_t *skipz(const uint8_t *p, size_t *n)
{
  while (*n > 1 && p[0] == 0) { p++; (*n)--; }
  return p;
}

SD_TEST(cng_diff_rsa)
{
  cng a;
  BCRYPT_ALG_HANDLE alg = NULL;
  tu_lines l;
  char *f[9];
  int nf, keys = 0, it;
  uint64_t seed = 8017;
  static const sd_hash_alg hs[] = { SD_HASH_SHA1, SD_HASH_SHA256, SD_HASH_SHA384, SD_HASH_SHA512 };
  uint8_t *blob = (uint8_t *)tu_alloc(8192), *sig = (uint8_t *)tu_alloc(1024), *sig2 = (uint8_t *)tu_alloc(1024);
  if (!cng_load(&a))
    goto out;
  SD_REQUIRE(a.open(&alg, BCRYPT_RSA_ALGORITHM, NULL, 0) == 0);
  /* reference keys up to 4096 bits: identical signatures both ways */
  SD_REQUIRE(tu_lines_open(&l, "refimpl/rsa_keys.txt") == 0);
  while ((nf = tu_lines_next(&l, f, 9)) > 0) {
    uint8_t *n, *e, *d, *p, *q, *iq;
    size_t nl, el, dl, pl, ql, il;
    unsigned bits;
    sd_rsa_import_params ip;
    sd_rsa_key *k = NULL;
    BCRYPT_KEY_HANDLE ck = NULL;
    ULONG bl;
    if (f[0][0] != 'K' || atoi(f[1]) > 4096)
      continue;
    bits = (unsigned)atoi(f[1]);
    nl = tu_hex(f[2], &n); el = tu_hex(f[3], &e); dl = tu_hex(f[4], &d);
    pl = tu_hex(f[5], &p); ql = tu_hex(f[6], &q); il = tu_hex(f[7], &iq);
    memset(&ip, 0, sizeof(ip));
    ip.n = n; ip.n_len = nl; ip.e = e; ip.e_len = el; ip.d = d; ip.d_len = dl;
    ip.p = p; ip.p_len = pl; ip.q = q; ip.q_len = ql; ip.iqmp = iq; ip.iqmp_len = il;
    SD_REQUIRE(sd_rsa_import(&ip, &k) == SD_OK);
    {
      const uint8_t *nn = skipz(n, &nl), *ee = skipz(e, &el), *pp = skipz(p, &pl), *qq = skipz(q, &ql);
      bl = rsa_blob(blob, BCRYPT_RSAPRIVATE_MAGIC, bits, ee, el, nn, nl, pp, pl, qq, ql);
    }
    SD_REQUIRE(a.import_pair(alg, NULL, BCRYPT_RSAPRIVATE_BLOB, &ck, blob, bl, 0) == 0);
    for (it = 0; it < 8; it++) {
      sd_hash_alg h = hs[it % 4];
      BCRYPT_PKCS1_PADDING_INFO pad;
      uint8_t dg[64];
      size_t s1 = 1024;
      ULONG s2 = 0, hl = (ULONG)sd_hash_len(h);
      tu_rand_fill(&seed, dg, hl);
      pad.pszAlgId = cng_hash_name(h);
      SD_REQUIRE(sd_rsa_pkcs1_sign(k, h, dg, hl, sig, &s1) == SD_OK);
      SD_REQUIRE(a.sign(ck, &pad, dg, hl, sig2, 1024, &s2, BCRYPT_PAD_PKCS1) == 0);
      if (s1 != s2 || memcmp(sig, sig2, s1) != 0)
        sd_test_fail(sd_t_, __FILE__, __LINE__, "RSA-%u signature differs from CNG", bits);
      SD_CHECK(a.verify(ck, &pad, dg, hl, sig, (ULONG)s1, BCRYPT_PAD_PKCS1) == 0);
      SD_CHECK(sd_rsa_pkcs1_verify(k, h, dg, hl, sig2, s2) == SD_OK);
    }
    a.destroy_key(ck);
    sd_rsa_free(k);
    free(n); free(e); free(d); free(p); free(q); free(iq);
    keys++;
  }
  tu_lines_close(&l);
  /* CNG-generated keys (full private blob) imported into sd_crypto */
  for (it = 0; it < 4; it++) {
    BCRYPT_KEY_HANDLE ck = NULL;
    BCRYPT_RSAKEY_BLOB hdr;
    sd_rsa_import_params ip;
    sd_rsa_key *k = NULL;
    ULONG bl = 0, s2 = 0, bits = it < 2 ? 2048 : 3072;
    uint8_t *w, dg[32];
    size_t s1 = 1024;
    BCRYPT_PKCS1_PADDING_INFO pad;
    SD_REQUIRE(a.gen_pair(alg, &ck, bits, 0) == 0 && a.finalize(ck, 0) == 0);
    SD_REQUIRE(a.export_key(ck, NULL, BCRYPT_RSAFULLPRIVATE_BLOB, blob, 8192, &bl, 0) == 0);
    memcpy(&hdr, blob, sizeof(hdr));
    w = blob + sizeof(hdr);
    memset(&ip, 0, sizeof(ip));
    ip.e = w; ip.e_len = hdr.cbPublicExp; w += hdr.cbPublicExp;
    ip.n = w; ip.n_len = hdr.cbModulus; w += hdr.cbModulus;
    ip.p = w; ip.p_len = hdr.cbPrime1; w += hdr.cbPrime1;
    ip.q = w; ip.q_len = hdr.cbPrime2; w += hdr.cbPrime2;
    w += hdr.cbPrime1 + hdr.cbPrime2;                         /* exponent1, exponent2 */
    ip.iqmp = w; ip.iqmp_len = hdr.cbPrime1; w += hdr.cbPrime1;
    ip.d = w; ip.d_len = hdr.cbModulus;
    SD_REQUIRE(sd_rsa_import(&ip, &k) == SD_OK);
    tu_rand_fill(&seed, dg, 32);
    pad.pszAlgId = BCRYPT_SHA256_ALGORITHM;
    SD_REQUIRE(sd_rsa_pkcs1_sign(k, SD_HASH_SHA256, dg, 32, sig, &s1) == SD_OK);
    SD_REQUIRE(a.sign(ck, &pad, dg, 32, sig2, 1024, &s2, BCRYPT_PAD_PKCS1) == 0);
    SD_CHECK(s1 == s2 && memcmp(sig, sig2, s1) == 0);
    a.destroy_key(ck);
    sd_rsa_free(k);
  }
  a.close(alg, 0);
  SD_CHECK(keys >= 5);
out:
  free(blob);
  free(sig);
  free(sig2);
}

SD_TEST(cng_diff_dh)
{
  cng a;
  BCRYPT_ALG_HANDLE alg = NULL;
  static const int ids[] = { 14, 16 };
  size_t gi;
  uint8_t *blob = (uint8_t *)tu_alloc(4096), *e = (uint8_t *)tu_alloc(512), *k1 = (uint8_t *)tu_alloc(512),
          *k2 = (uint8_t *)tu_alloc(512);
  if (!cng_load(&a))
    goto out;
  SD_REQUIRE(a.open(&alg, BCRYPT_DH_ALGORITHM, NULL, 0) == 0);
  for (gi = 0; gi < SD_COUNTOF(ids); gi++) {
    size_t pl;
    const uint8_t *p = sd_dh_group_modp(ids[gi], &pl);
    int it;
    for (it = 0; it < 3; it++) {
      BCRYPT_KEY_HANDLE cpriv = NULL, cpub = NULL;
      BCRYPT_DH_PARAMETER_HEADER ph;
      BCRYPT_DH_KEY_BLOB kh;
      sd_dh *d = NULL;
      ULONG bl = 0;
      ph.cbLength = (ULONG)(sizeof(ph) + 2 * pl);
      ph.dwMagic = BCRYPT_DH_PARAMETERS_MAGIC;
      ph.cbKeyLength = (ULONG)pl;
      memcpy(blob, &ph, sizeof(ph));
      memcpy(blob + sizeof(ph), p, pl);
      memset(blob + sizeof(ph) + pl, 0, pl);
      blob[sizeof(ph) + 2 * pl - 1] = 2;
      SD_REQUIRE(a.gen_pair(alg, &cpriv, (ULONG)(8 * pl), 0) == 0);
      SD_REQUIRE(a.set_prop(cpriv, BCRYPT_DH_PARAMETERS, blob, ph.cbLength, 0) == 0);
      SD_REQUIRE(a.finalize(cpriv, 0) == 0);
      SD_REQUIRE(a.export_key(cpriv, NULL, BCRYPT_DH_PUBLIC_BLOB, blob, 4096, &bl, 0) == 0);
      /* blob: header, p, g, y */
      SD_REQUIRE(sd_dh_new_group(ids[gi], 0, &d) == SD_OK);
      SD_REQUIRE(sd_dh_public(d, e, pl) == SD_OK);
      SD_REQUIRE(sd_dh_compute(d, blob + sizeof(kh) + 2 * pl, pl, k1, pl) == SD_OK);
      kh.dwMagic = BCRYPT_DH_PUBLIC_MAGIC;
      kh.cbKey = (ULONG)pl;
      memcpy(blob, &kh, sizeof(kh));
      memcpy(blob + sizeof(kh) + 2 * pl, e, pl);
      SD_REQUIRE(a.import_pair(alg, NULL, BCRYPT_DH_PUBLIC_BLOB, &cpub, blob, (ULONG)(sizeof(kh) + 3 * pl), 0) == 0);
      if (!cng_raw_secret(&a, cpriv, cpub, k2, (ULONG)pl)) {
        printf("    (CNG DH raw secret unsupported: DH differential skipped)\n");
        a.destroy_key(cpub);
        a.destroy_key(cpriv);
        sd_dh_free(d);
        goto done;
      }
      if (memcmp(k1, k2, pl) != 0)
        sd_test_fail(sd_t_, __FILE__, __LINE__, "group%d shared secret differs from CNG", ids[gi]);
      a.destroy_key(cpub);
      a.destroy_key(cpriv);
      sd_dh_free(d);
    }
  }
done:
  a.close(alg, 0);
out:
  free(blob); free(e); free(k1); free(k2);
}
