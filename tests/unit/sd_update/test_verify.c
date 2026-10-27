/* sd_update pure verification: versions, time, base64, strict parsing, the signature chain and each
 * tampering case of the task (manifest byte flip, wrong key, expired keyset, expired manifest, rollback,
 * channel mismatch, oversized manifest, keyset rotation and revocation). Fixtures come from sd-updsign. */
#include <windows.h>
#include <string.h>
#include <stdio.h>

#include "sd_test.h"
#include "fixture.h"
#include "sd_base/sd_mem.h"

static int64_t now_unix(void)
{
  int64_t t = 0;
  sd_upd_time_parse(FX_NOW_STR, strlen(FX_NOW_STR), &t);
  return t;
}

/* A stable manifest body for the standard fixture: one artifact (contents of a scratch file). */
typedef struct chain {
  fx *f;
  wchar_t artifact[MAX_PATH];
  uint8_t *kset;   size_t klen;   /* signed keyset (roots a and b) */
  uint8_t *mfst;   size_t mlen;   /* signed manifest, stable, serial 10, version 1.1.0 */
} chain;

static int make_artifact(fx *f, wchar_t *path, size_t cap)
{
  static const char data[] = "artifact bytes for the test manifest\n";
  fx_path(f, L"artifact.bin", path, cap);
  return fx_write(path, data, sizeof(data) - 1);
}

static int build_keyset(chain *c, const fx_keyset_opts *o, uint8_t **out, size_t *outlen, int rotated_sign)
{
  char body[4096];
  size_t n = fx_keyset_body(c->f, body, sizeof(body), o);
  const fx_key *roots[2];
  int nr = 0;
  roots[nr++] = &c->f->root_a;
  if (rotated_sign == 1) {
    /* rotation: both current roots must sign */
    roots[nr++] = &c->f->root_b;
  } else if (rotated_sign == 2) {
    roots[0] = &c->f->root_b;          /* only root b signs */
    nr = 1;
  } else if (rotated_sign == 3) {
    roots[0] = &c->f->root_c;          /* a root that is not trusted */
    nr = 1;
  } else {
    roots[nr++] = &c->f->root_b;
  }
  return fx_sign_keyset(c->f, body, n, roots, nr, out, outlen);
}

static int build_manifest(chain *c, const fx_manifest_opts *mo, const fx_key *k, uint8_t **out, size_t *outlen)
{
  static char body[80000];
  fx_file_entry fe;
  fx_manifest_opts o = *mo;
  size_t n;
  fe.id = "setup-universal";
  fe.name = "setup.exe";
  fe.path = c->artifact;
  o.files = &fe;
  o.nfiles = 1;
  o.base = o.base ? o.base : "https://example.invalid/releases/";
  n = fx_manifest_body(body, sizeof(body), &o);
  if (n == 0)
    return 0;
  return fx_sign_manifest(c->f, body, n, k, out, outlen);
}

static int standard_opts(fx_manifest_opts *o, const char *channel, uint64_t keyset)
{
  memset(o, 0, sizeof(*o));
  o->channel = channel;
  o->keyset = keyset;
  o->serial = 10;
  o->version = "1.1.0";
  return 1;
}

static int chain_setup(chain *c, fx *f)
{
  fx_keyset_opts ko;
  fx_manifest_opts mo;
  memset(c, 0, sizeof(*c));
  c->f = f;
  if (!make_artifact(f, c->artifact, sizeof(c->artifact) / sizeof(wchar_t)))
    return 0;
  memset(&ko, 0, sizeof(ko));
  ko.version = 3;
  if (!build_keyset(c, &ko, &c->kset, &c->klen, 0))
    return 0;
  standard_opts(&mo, "stable", 3);
  return build_manifest(c, &mo, &f->stable, &c->mfst, &c->mlen);
}

static void chain_free(chain *c)
{
  sd_free(c->kset);
  sd_free(c->mfst);
}

/* ---- versions, time, base64 ---- */

SD_TEST(versions_compare)
{
  sd_upd_version a, b, c, d;
  SD_CHECK(sd_upd_version_parse("1.0.0", 5, &a) == SD_UPD_OK);
  SD_CHECK(sd_upd_version_parse("1.0.1", 5, &b) == SD_UPD_OK);
  SD_CHECK(sd_upd_version_cmp(&a, &b) < 0);
  SD_CHECK(sd_upd_version_cmp(&b, &a) > 0);
  SD_CHECK(sd_upd_version_parse("1.0", 3, &c) == SD_UPD_OK);
  SD_CHECK(sd_upd_version_cmp(&a, &c) == 0);             /* missing parts are zero */
  SD_CHECK(sd_upd_version_parse("2.3.1.1000", 10, &d) == SD_UPD_OK);
  SD_CHECK(d.n == 4 && d.part[3] == 1000);
  SD_CHECK(sd_upd_version_parse("1..0", 4, &a) == SD_UPD_E_FORMAT);
  SD_CHECK(sd_upd_version_parse("1.0.", 4, &a) == SD_UPD_E_FORMAT);
  SD_CHECK(sd_upd_version_parse("1.0.0.0.1", 9, &a) == SD_UPD_E_FORMAT);
  SD_CHECK(sd_upd_version_parse("65536.0", 7, &a) == SD_UPD_E_FORMAT);
  SD_CHECK(sd_upd_version_parse("1.x", 3, &a) == SD_UPD_E_FORMAT);
}

SD_TEST(time_strict)
{
  int64_t a = 0, b = 0, d = 0;
  SD_CHECK(sd_upd_time_parse("2026-10-27T00:00:00Z", 20, &a) == SD_UPD_OK);
  SD_CHECK(sd_upd_time_parse("2026-10-28T00:00:00Z", 20, &b) == SD_UPD_OK);
  SD_CHECK_EQ_INT(b - a, 86400);
  SD_CHECK(sd_upd_time_parse("1970-01-01T00:00:00Z", 20, &d) == SD_UPD_OK);
  SD_CHECK_EQ_INT(d, 0);
  SD_CHECK(sd_upd_time_parse("2026-02-29T00:00:00Z", 20, &d) == SD_UPD_E_FORMAT);   /* not a leap year */
  SD_CHECK(sd_upd_time_parse("2028-02-29T00:00:00Z", 20, &d) == SD_UPD_OK);
  SD_CHECK(sd_upd_time_parse("2026-13-01T00:00:00Z", 20, &d) == SD_UPD_E_FORMAT);
  SD_CHECK(sd_upd_time_parse("2026-10-27 12:00:00Z", 20, &d) == SD_UPD_E_FORMAT);
  SD_CHECK(sd_upd_time_parse("2026-10-27T12:00:00+00", 22, &d) == SD_UPD_E_FORMAT);
  SD_CHECK(sd_upd_date_parse("2026-10-27", 10, 1, &d) == SD_UPD_OK);
  SD_CHECK_EQ_INT(d, a + 86399);
}

SD_TEST(base64_canonical)
{
  uint8_t out[8];
  SD_CHECK_EQ_INT(sd_upd_base64_decode("AAAA", 4, out, sizeof(out)), 3);
  SD_CHECK_EQ_INT(sd_upd_base64_decode("AA==", 4, out, sizeof(out)), 1);
  SD_CHECK_EQ_INT(sd_upd_base64_decode("AB==", 4, out, sizeof(out)), -1);   /* unused bits set */
  SD_CHECK_EQ_INT(sd_upd_base64_decode("AAA", 3, out, sizeof(out)), -1);    /* length not a multiple of 4 */
  SD_CHECK_EQ_INT(sd_upd_base64_decode("A*AA", 4, out, sizeof(out)), -1);   /* alphabet */
  SD_CHECK_EQ_INT(sd_upd_base64_decode("=AAA", 4, out, sizeof(out)), -1);   /* padding in front */
  SD_CHECK_EQ_INT(sd_upd_base64_decode("AA==AAAA", 8, out, sizeof(out)), -1);
}

/* ---- parsing and the chain ---- */

SD_TEST(manifest_parse_fields)
{
  chain c;
  static sd_upd_manifest m;
  static fx f;
  SD_REQUIRE(fx_init(&f, "parse"));
  SD_REQUIRE(chain_setup(&c, &f));
  SD_CHECK(sd_upd_manifest_parse(c.mfst, c.mlen, &m) == SD_UPD_OK);
  SD_CHECK_STR(m.channel, "stable");
  SD_CHECK_EQ_INT(m.keyset, 3);
  SD_CHECK_EQ_INT(m.serial, 10);
  SD_CHECK_STR(m.version_str, "1.1.0");
  SD_CHECK_EQ_INT(m.nfiles, 1);
  SD_CHECK_STR(m.files[0].id, "setup-universal");
  SD_CHECK_EQ_INT(m.files[0].hash_alg, 256);
  SD_CHECK_EQ_INT(m.nbases, 1);
  SD_CHECK(m.sig_offset > 0 && m.sig_offset < c.mlen);
  SD_CHECK(c.mfst[m.sig_offset] == 's');
  SD_CHECK(memcmp(m.sig_key_id, c.f->stable.id, 8) == 0);
  chain_free(&c);
  fx_done(&f);
}

SD_TEST(chain_valid)
{
  chain c;
  static sd_upd_keyset ks;
  static sd_upd_manifest m;
  static fx f;
  sd_upd_root roots[2];
  memset(roots, 0, sizeof(roots));
  SD_REQUIRE(fx_init(&f, "valid"));
  SD_REQUIRE(chain_setup(&c, &f));
  memcpy(roots[0].id, f.root_a.id, 8);
  memcpy(roots[0].pub, f.root_a.pub, 32);
  memcpy(roots[1].id, f.root_b.id, 8);
  memcpy(roots[1].pub, f.root_b.pub, 32);
  SD_CHECK(sd_upd_keyset_verify(c.kset, c.klen, roots, 2, 0, &ks) == SD_UPD_OK);
  SD_CHECK_EQ_INT(ks.version, 3);
  SD_CHECK_EQ_INT(ks.nkeys, 2);
  SD_CHECK_EQ_INT(ks.rotated_roots, 0);
  SD_CHECK(sd_upd_manifest_parse(c.mfst, c.mlen, &m) == SD_UPD_OK);
  SD_CHECK(sd_upd_manifest_verify(c.mfst, c.mlen, &m, &ks, "stable", now_unix(), 0) == SD_UPD_OK);
  chain_free(&c);
  fx_done(&f);
}

SD_TEST(manifest_byte_flip_is_refused)
{
  chain c;
  static sd_upd_keyset ks;
  static sd_upd_manifest m;
  static fx f;
  sd_upd_root roots[2];
  memset(roots, 0, sizeof(roots));
  char *hit;
  SD_REQUIRE(fx_init(&f, "flip"));
  SD_REQUIRE(chain_setup(&c, &f));
  memcpy(roots[0].id, f.root_a.id, 8); memcpy(roots[0].pub, f.root_a.pub, 32);
  memcpy(roots[1].id, f.root_b.id, 8); memcpy(roots[1].pub, f.root_b.pub, 32);
  SD_REQUIRE(sd_upd_keyset_verify(c.kset, c.klen, roots, 2, 0, &ks) == SD_UPD_OK);
  hit = strstr((char *)c.mfst, "version 1.1.0");
  SD_REQUIRE(hit != NULL);
  hit[12] = '2';                              /* 1.1.0 -> 1.1.2: well formed, different bytes */
  SD_CHECK(sd_upd_manifest_parse(c.mfst, c.mlen, &m) == SD_UPD_OK);
  SD_CHECK(sd_upd_manifest_verify(c.mfst, c.mlen, &m, &ks, "stable", now_unix(), 0) == SD_UPD_E_SIGNATURE);
  chain_free(&c);
  fx_done(&f);
}

SD_TEST(manifest_wrong_key_is_refused)
{
  chain c;
  static sd_upd_keyset ks;
  static sd_upd_manifest m;
  static fx f;
  sd_upd_root roots[2];
  memset(roots, 0, sizeof(roots));
  fx_manifest_opts mo;
  uint8_t *rogue = NULL;
  size_t rl = 0;
  SD_REQUIRE(fx_init(&f, "rogue"));
  SD_REQUIRE(chain_setup(&c, &f));
  memcpy(roots[0].id, f.root_a.id, 8); memcpy(roots[0].pub, f.root_a.pub, 32);
  memcpy(roots[1].id, f.root_b.id, 8); memcpy(roots[1].pub, f.root_b.pub, 32);
  SD_REQUIRE(sd_upd_keyset_verify(c.kset, c.klen, roots, 2, 0, &ks) == SD_UPD_OK);
  standard_opts(&mo, "stable", 3);
  SD_REQUIRE(build_manifest(&c, &mo, &f.rogue, &rogue, &rl));   /* signed by a key the keyset does not list */
  SD_CHECK(sd_upd_manifest_parse(rogue, rl, &m) == SD_UPD_OK);
  SD_CHECK(sd_upd_manifest_verify(rogue, rl, &m, &ks, "stable", now_unix(), 0) == SD_UPD_E_UNKNOWN_KEY);
  sd_free(rogue);
  chain_free(&c);
  fx_done(&f);
}

SD_TEST(beta_key_cannot_sign_stable_and_stable_cannot_sign_beta)
{
  chain c;
  static sd_upd_keyset ks;
  static sd_upd_manifest m;
  static fx f;
  sd_upd_root roots[2];
  memset(roots, 0, sizeof(roots));
  fx_manifest_opts mo;
  uint8_t *bm = NULL, *sm = NULL;
  size_t bl = 0, sl = 0;
  SD_REQUIRE(fx_init(&f, "keyuse"));
  SD_REQUIRE(chain_setup(&c, &f));
  memcpy(roots[0].id, f.root_a.id, 8); memcpy(roots[0].pub, f.root_a.pub, 32);
  memcpy(roots[1].id, f.root_b.id, 8); memcpy(roots[1].pub, f.root_b.pub, 32);
  SD_REQUIRE(sd_upd_keyset_verify(c.kset, c.klen, roots, 2, 0, &ks) == SD_UPD_OK);
  /* beta manifest signed with the beta key: fine by the keyset, but the expected channel is stable */
  standard_opts(&mo, "beta", 3);
  mo.released = "2026-10-24T00:00:00Z";           /* beta: at most 14 days between released and expires */
  mo.expires = "2026-11-05T00:00:00Z";
  SD_REQUIRE(build_manifest(&c, &mo, &f.beta, &bm, &bl));
  SD_CHECK(sd_upd_manifest_parse(bm, bl, &m) == SD_UPD_OK);
  SD_CHECK(sd_upd_manifest_verify(bm, bl, &m, &ks, "stable", now_unix(), 0) == SD_UPD_E_CHANNEL_MISMATCH);
  SD_CHECK(sd_upd_manifest_verify(bm, bl, &m, &ks, "beta", now_unix(), 0) == SD_UPD_OK);
  /* beta-labelled manifest signed with the stable key: the stable key is not authorized for beta */
  SD_REQUIRE(build_manifest(&c, &mo, &f.stable, &sm, &sl));
  SD_CHECK(sd_upd_manifest_parse(sm, sl, &m) == SD_UPD_OK);
  SD_CHECK(sd_upd_manifest_verify(sm, sl, &m, &ks, "beta", now_unix(), 0) == SD_UPD_E_UNKNOWN_KEY);
  sd_free(bm);
  sd_free(sm);
  chain_free(&c);
  fx_done(&f);
}

SD_TEST(manifest_expired_and_freshness)
{
  chain c;
  static sd_upd_keyset ks;
  static sd_upd_manifest m;
  static fx f;
  sd_upd_root roots[2];
  memset(roots, 0, sizeof(roots));
  fx_manifest_opts mo;
  uint8_t *x = NULL;
  size_t xl = 0;
  SD_REQUIRE(fx_init(&f, "expiry"));
  SD_REQUIRE(chain_setup(&c, &f));
  memcpy(roots[0].id, f.root_a.id, 8); memcpy(roots[0].pub, f.root_a.pub, 32);
  memcpy(roots[1].id, f.root_b.id, 8); memcpy(roots[1].pub, f.root_b.pub, 32);
  SD_REQUIRE(sd_upd_keyset_verify(c.kset, c.klen, roots, 2, 0, &ks) == SD_UPD_OK);

  standard_opts(&mo, "stable", 3);
  mo.expires = "2026-10-26T00:00:00Z";
  mo.released = "2026-10-01T00:00:00Z";
  SD_REQUIRE(build_manifest(&c, &mo, &f.stable, &x, &xl));
  SD_CHECK(sd_upd_manifest_parse(x, xl, &m) == SD_UPD_OK);
  SD_CHECK(sd_upd_manifest_verify(x, xl, &m, &ks, "stable", now_unix(), 0) == SD_UPD_E_EXPIRED);
  sd_free(x); x = NULL;

  standard_opts(&mo, "stable", 3);
  mo.released = "2026-08-01T00:00:00Z";           /* 114 days: more than 30 */
  mo.expires = "2026-11-23T00:00:00Z";
  SD_REQUIRE(build_manifest(&c, &mo, &f.stable, &x, &xl));
  SD_CHECK(sd_upd_manifest_parse(x, xl, &m) == SD_UPD_OK);
  SD_CHECK(sd_upd_manifest_verify(x, xl, &m, &ks, "stable", now_unix(), 0) == SD_UPD_E_FRESHNESS);
  sd_free(x); x = NULL;

  standard_opts(&mo, "beta", 3);
  mo.released = "2026-10-10T00:00:00Z";           /* 44 days for beta: more than 14 */
  mo.expires = "2026-11-23T00:00:00Z";
  SD_REQUIRE(build_manifest(&c, &mo, &f.beta, &x, &xl));
  SD_CHECK(sd_upd_manifest_parse(x, xl, &m) == SD_UPD_OK);
  SD_CHECK(sd_upd_manifest_verify(x, xl, &m, &ks, "beta", now_unix(), 0) == SD_UPD_E_FRESHNESS);
  sd_free(x);
  chain_free(&c);
  fx_done(&f);
}

SD_TEST(manifest_serial_rollback_refused)
{
  chain c;
  static sd_upd_keyset ks;
  static sd_upd_manifest m;
  static fx f;
  sd_upd_root roots[2];
  memset(roots, 0, sizeof(roots));
  SD_REQUIRE(fx_init(&f, "serial"));
  SD_REQUIRE(chain_setup(&c, &f));
  memcpy(roots[0].id, f.root_a.id, 8); memcpy(roots[0].pub, f.root_a.pub, 32);
  memcpy(roots[1].id, f.root_b.id, 8); memcpy(roots[1].pub, f.root_b.pub, 32);
  SD_REQUIRE(sd_upd_keyset_verify(c.kset, c.klen, roots, 2, 0, &ks) == SD_UPD_OK);
  SD_CHECK(sd_upd_manifest_parse(c.mfst, c.mlen, &m) == SD_UPD_OK);            /* serial 10 */
  SD_CHECK(sd_upd_manifest_verify(c.mfst, c.mlen, &m, &ks, "stable", now_unix(), 10) == SD_UPD_OK);
  SD_CHECK(sd_upd_manifest_verify(c.mfst, c.mlen, &m, &ks, "stable", now_unix(), 11) == SD_UPD_E_ROLLBACK);
  chain_free(&c);
  fx_done(&f);
}

SD_TEST(keyset_expired_key_refused)
{
  chain c;
  static sd_upd_keyset ks;
  static sd_upd_manifest m;
  static fx f;
  sd_upd_root roots[2];
  memset(roots, 0, sizeof(roots));
  fx_keyset_opts ko;
  uint8_t *kb = NULL, *mb = NULL;
  size_t kl = 0, ml = 0;
  fx_manifest_opts mo;
  SD_REQUIRE(fx_init(&f, "kexp"));
  SD_REQUIRE(chain_setup(&c, &f));
  memset(&ko, 0, sizeof(ko));
  ko.version = 4;
  ko.stable_to = "2026-10-01";                   /* the stable key expired before now */
  SD_REQUIRE(build_keyset(&c, &ko, &kb, &kl, 0));
  memcpy(roots[0].id, f.root_a.id, 8); memcpy(roots[0].pub, f.root_a.pub, 32);
  memcpy(roots[1].id, f.root_b.id, 8); memcpy(roots[1].pub, f.root_b.pub, 32);
  SD_REQUIRE(sd_upd_keyset_verify(kb, kl, roots, 2, 0, &ks) == SD_UPD_OK);
  standard_opts(&mo, "stable", 4);
  SD_REQUIRE(build_manifest(&c, &mo, &f.stable, &mb, &ml));
  SD_CHECK(sd_upd_manifest_parse(mb, ml, &m) == SD_UPD_OK);
  SD_CHECK(sd_upd_manifest_verify(mb, ml, &m, &ks, "stable", now_unix(), 0) == SD_UPD_E_KEY_EXPIRED);
  sd_free(kb);
  sd_free(mb);
  chain_free(&c);
  fx_done(&f);
}

SD_TEST(keyset_revoked_key_refused)
{
  chain c;
  static sd_upd_keyset ks;
  static sd_upd_manifest m;
  static fx f;
  sd_upd_root roots[2];
  memset(roots, 0, sizeof(roots));
  fx_keyset_opts ko;
  uint8_t *kb = NULL;
  size_t kl = 0;
  SD_REQUIRE(fx_init(&f, "krev"));
  SD_REQUIRE(chain_setup(&c, &f));
  memset(&ko, 0, sizeof(ko));
  ko.version = 4;
  ko.revoke_stable = 1;
  SD_REQUIRE(build_keyset(&c, &ko, &kb, &kl, 0));
  memcpy(roots[0].id, f.root_a.id, 8); memcpy(roots[0].pub, f.root_a.pub, 32);
  memcpy(roots[1].id, f.root_b.id, 8); memcpy(roots[1].pub, f.root_b.pub, 32);
  SD_REQUIRE(sd_upd_keyset_verify(kb, kl, roots, 2, 0, &ks) == SD_UPD_OK);
  SD_CHECK(sd_upd_manifest_parse(c.mfst, c.mlen, &m) == SD_UPD_OK);
  SD_CHECK(sd_upd_manifest_verify(c.mfst, c.mlen, &m, &ks, "stable", now_unix(), 0) == SD_UPD_E_KEY_REVOKED);
  sd_free(kb);
  chain_free(&c);
  fx_done(&f);
}

SD_TEST(keyset_tamper_and_rollback)
{
  chain c;
  static sd_upd_keyset ks;
  static fx f;
  sd_upd_root roots[2];
  memset(roots, 0, sizeof(roots));
  char *hit;
  SD_REQUIRE(fx_init(&f, "ktamp"));
  SD_REQUIRE(chain_setup(&c, &f));
  memcpy(roots[0].id, f.root_a.id, 8); memcpy(roots[0].pub, f.root_a.pub, 32);
  memcpy(roots[1].id, f.root_b.id, 8); memcpy(roots[1].pub, f.root_b.pub, 32);
  hit = strstr((char *)c.kset, "version 3");
  SD_REQUIRE(hit != NULL);
  hit[8] = '4';                                /* body changed under a valid signature */
  SD_CHECK(sd_upd_keyset_verify(c.kset, c.klen, roots, 2, 0, &ks) == SD_UPD_E_KEYSET_SIGNATURE);
  hit[8] = '3';
  SD_CHECK(sd_upd_keyset_verify(c.kset, c.klen, roots, 2, 0, &ks) == SD_UPD_OK);
  SD_CHECK(sd_upd_keyset_verify(c.kset, c.klen, roots, 2, 4, &ks) == SD_UPD_E_KEYSET_ROLLBACK);
  SD_CHECK(sd_upd_keyset_verify(c.kset, c.klen, roots, 2, 3, &ks) == SD_UPD_OK);  /* equal: idempotent */
  chain_free(&c);
  fx_done(&f);
}

SD_TEST(keyset_signed_by_unknown_root_refused)
{
  static fx f;
  fx_keyset_opts ko;
  char body[4096];
  size_t n;
  uint8_t *kb = NULL;
  size_t kl = 0;
  sd_upd_root roots[2];
  memset(roots, 0, sizeof(roots));
  static sd_upd_keyset ks;
  const fx_key *signers[1];
  SD_REQUIRE(fx_init(&f, "kroot"));
  memset(&ko, 0, sizeof(ko));
  ko.version = 2;
  n = fx_keyset_body(&f, body, sizeof(body), &ko);
  signers[0] = &f.root_c;                      /* not a trusted root */
  SD_REQUIRE(fx_sign_keyset(&f, body, n, signers, 1, &kb, &kl));
  memcpy(roots[0].id, f.root_a.id, 8); memcpy(roots[0].pub, f.root_a.pub, 32);
  memcpy(roots[1].id, f.root_b.id, 8); memcpy(roots[1].pub, f.root_b.pub, 32);
  SD_CHECK(sd_upd_keyset_verify(kb, kl, roots, 2, 0, &ks) == SD_UPD_E_KEYSET_SIGNATURE);
  sd_free(kb);
  fx_done(&f);
}

SD_TEST(keyset_rotation_needs_both_roots)
{
  static fx f;
  fx_keyset_opts ko;
  char body[4096];
  size_t n;
  uint8_t *both = NULL, *one = NULL;
  size_t bl = 0, ol = 0;
  sd_upd_root roots[2];
  memset(roots, 0, sizeof(roots));
  static sd_upd_keyset ks;
  const fx_key *signers[2];
  SD_REQUIRE(fx_init(&f, "krot"));
  memcpy(roots[0].id, f.root_a.id, 8); memcpy(roots[0].pub, f.root_a.pub, 32);
  memcpy(roots[1].id, f.root_b.id, 8); memcpy(roots[1].pub, f.root_b.pub, 32);

  memset(&ko, 0, sizeof(ko));
  ko.version = 5;
  ko.rotate = 1;
  n = fx_keyset_body(&f, body, sizeof(body), &ko);
  signers[0] = &f.root_a;
  signers[1] = &f.root_b;
  SD_REQUIRE(fx_sign_keyset(&f, body, n, signers, 2, &both, &bl));
  SD_CHECK(sd_upd_keyset_verify(both, bl, roots, 2, 0, &ks) == SD_UPD_OK);
  SD_CHECK(ks.rotated_roots == 1);
  SD_CHECK(ks.nroots == 2);
  SD_CHECK(memcmp(ks.roots[0].id, f.root_b.id, 8) == 0);
  SD_CHECK(memcmp(ks.roots[1].id, f.root_c.id, 8) == 0);

  signers[0] = &f.root_a;
  SD_REQUIRE(fx_sign_keyset(&f, body, n, signers, 1, &one, &ol));
  SD_CHECK(sd_upd_keyset_verify(one, ol, roots, 2, 0, &ks) == SD_UPD_E_KEYSET_SIGNATURE);
  sd_free(both);
  sd_free(one);
  fx_done(&f);
}

SD_TEST(product_and_format_version)
{
  chain c;
  static sd_upd_manifest m;
  static fx f;
  fx_manifest_opts mo;
  uint8_t *x = NULL;
  size_t xl = 0;
  static char body[4096];
  SD_REQUIRE(fx_init(&f, "prod"));
  SD_REQUIRE(chain_setup(&c, &f));
  standard_opts(&mo, "stable", 3);
  mo.product = "com.example.other";
  SD_REQUIRE(build_manifest(&c, &mo, &f.stable, &x, &xl));
  SD_CHECK(sd_upd_manifest_parse(x, xl, &m) == SD_UPD_E_PRODUCT);
  sd_free(x);

  /* unknown major: refused with the "update manually" result */
  memcpy(body, c.mfst, c.mlen);
  body[c.mlen] = 0;
  SD_CHECK(sd_upd_manifest_parse((const uint8_t *)"shelldrive-manifest 2\nproduct com.librestatic.shelldrive\n",
                                 strlen("shelldrive-manifest 2\nproduct com.librestatic.shelldrive\n"), &m) ==
           SD_UPD_E_FORMAT_VERSION);
  chain_free(&c);
  fx_done(&f);
}

SD_TEST(manifest_strict_syntax)
{
  chain c;
  static sd_upd_manifest m;
  static fx f;
  uint8_t *big;
  size_t i;
  uint8_t *tail;
  SD_REQUIRE(fx_init(&f, "syntax"));
  SD_REQUIRE(chain_setup(&c, &f));

  /* a record after the sig line is refused (the sig is the last record) */
  tail = (uint8_t *)sd_alloc(c.mlen + 32);
  SD_REQUIRE(tail != NULL);
  memcpy(tail, c.mfst, c.mlen);
  memcpy(tail + c.mlen, "x-after 1\n", 10);
  SD_CHECK(sd_upd_manifest_parse(tail, c.mlen + 10, &m) == SD_UPD_E_FORMAT);
  sd_free(tail);

  /* CR, tabs and double spaces are not in the format */
  tail = (uint8_t *)sd_alloc(c.mlen + 4);
  SD_REQUIRE(tail != NULL);
  memcpy(tail, c.mfst, c.mlen);
  for (i = 0; i < c.mlen; i++) {
    if (tail[i] == 'p') { tail[i] = '\r'; break; }
  }
  SD_CHECK(sd_upd_manifest_parse(tail, c.mlen, &m) == SD_UPD_E_FORMAT);
  sd_free(tail);

  /* oversized: refused before any parsing */
  big = (uint8_t *)sd_alloc(SD_UPD_MANIFEST_MAX + 64);
  SD_REQUIRE(big != NULL);
  memcpy(big, "shelldrive-manifest 1\n", 22);
  memset(big + 22, 'x', SD_UPD_MANIFEST_MAX + 40);
  big[SD_UPD_MANIFEST_MAX + 61] = '\n';
  SD_CHECK(sd_upd_manifest_parse(big, SD_UPD_MANIFEST_MAX + 62, &m) == SD_UPD_E_TOO_LARGE);
  sd_free(big);

  /* a body carrying its own sig line cannot be signed by the tool (exit code 2): the fixture reports failure */
  {
    fx_manifest_opts mo;
    static char body[4096];
    uint8_t *x = NULL;
    size_t xl = 0, n;
    fx_file_entry fe;
    standard_opts(&mo, "stable", 3);
    fe.id = "setup-universal"; fe.name = "setup.exe"; fe.path = c.artifact;
    mo.files = &fe; mo.nfiles = 1; mo.base = "https://example.invalid/";
    mo.extra = "sig ed25519 0000000000000000 AAAA\n";
    n = fx_manifest_body(body, sizeof(body), &mo);
    SD_CHECK(n > 0);
    SD_CHECK(fx_sign_manifest(&f, body, n, &f.stable, &x, &xl) == 0);
  }

  chain_free(&c);
  fx_done(&f);
}

SD_TEST(manifest_dokany_deny_and_unknown_keys)
{
  chain c;
  static sd_upd_keyset ks;
  static sd_upd_manifest m;
  static fx f;
  sd_upd_root roots[2];
  memset(roots, 0, sizeof(roots));
  fx_manifest_opts mo;
  uint8_t *x = NULL;
  size_t xl = 0;
  SD_REQUIRE(fx_init(&f, "deny"));
  SD_REQUIRE(chain_setup(&c, &f));
  memcpy(roots[0].id, f.root_a.id, 8); memcpy(roots[0].pub, f.root_a.pub, 32);
  memcpy(roots[1].id, f.root_b.id, 8); memcpy(roots[1].pub, f.root_b.pub, 32);
  SD_REQUIRE(sd_upd_keyset_verify(c.kset, c.klen, roots, 2, 0, &ks) == SD_UPD_OK);
  standard_opts(&mo, "stable", 3);
  mo.extra = "dokany-deny 2.0.0-2.3.0 cve-2026-0001\nx-future some-value\n";
  SD_REQUIRE(build_manifest(&c, &mo, &f.stable, &x, &xl));
  SD_CHECK(sd_upd_manifest_parse(x, xl, &m) == SD_UPD_OK);
  SD_CHECK_EQ_INT(m.ndeny, 1);
  SD_CHECK_STR(m.deny[0].reason, "cve-2026-0001");
  SD_CHECK(m.deny[0].min.part[0] == 2 && m.deny[0].max.part[1] == 3);
  SD_CHECK(sd_upd_manifest_verify(x, xl, &m, &ks, "stable", now_unix(), 0) == SD_UPD_OK);
  sd_free(x);
  chain_free(&c);
  fx_done(&f);
}

SD_TEST(select_file_by_mode_and_flavour)
{
  static sd_upd_manifest m;
  const sd_upd_file *hit = NULL;
  memset(&m, 0, sizeof(m));
  strcpy_s(m.files[0].id, sizeof(m.files[0].id), "setup-x64");
  strcpy_s(m.files[1].id, sizeof(m.files[1].id), "msi-x64-modern");
  strcpy_s(m.files[2].id, sizeof(m.files[2].id), "portable-x64-modern");
  m.nfiles = 3;
  SD_CHECK(sd_upd_select_file(&m, SD_UPD_MODE_SETUP, "x64-modern", &hit) == SD_UPD_OK);
  SD_CHECK(hit && strcmp(hit->id, "setup-x64") == 0);
  SD_CHECK(sd_upd_select_file(&m, SD_UPD_MODE_MSI, "x64-modern", &hit) == SD_UPD_OK);
  SD_CHECK(hit && strcmp(hit->id, "msi-x64-modern") == 0);
  SD_CHECK(sd_upd_select_file(&m, SD_UPD_MODE_MSI, "x86-sse2", &hit) == SD_UPD_E_NO_TARGET);
  SD_CHECK(sd_upd_select_file(&m, SD_UPD_MODE_PORTABLE, "x64-modern", &hit) == SD_UPD_OK);
  SD_CHECK(hit && strcmp(hit->id, "portable-x64-modern") == 0);
}

SD_TEST(res_names_are_stable)
{
  SD_CHECK_STR(sd_upd_res_code(SD_UPD_E_SIGNATURE), "update_verify_failed");
  SD_CHECK_STR(sd_upd_res_code(SD_UPD_E_SELFTEST), "selftest_failed");
  SD_CHECK_STR(sd_upd_res_code(SD_UPD_E_NETWORK), "update_unavailable");
  SD_CHECK_STR(sd_upd_res_name(SD_UPD_E_SIGNATURE), "signature_invalid");
  SD_CHECK_STR(sd_upd_res_name((sd_upd_res)999), "unknown");
}
