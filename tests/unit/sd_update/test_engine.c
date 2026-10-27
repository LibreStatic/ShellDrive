/* sd_update engine over the loopback server: check (manifest, keyset fetch, anti-rollback, expiry), stage (size,
 * digest, redirect policy, HTTPS-to-HTTP fallback), apply (file swap with rollback, --selftest, setup run),
 * cleanup. Test keys from sd-updsign, the "new binaries" are sd-test-update-fakeapp.exe copies. */
#include <windows.h>
#include <string.h>
#include <stdio.h>

#include "sd_test.h"
#include "fixture.h"
#include "sd_base/sd_mem.h"
#include "sd_crypto/sd_crypto.h"

#ifndef SD_TEST_FAKEAPP
#error "SD_TEST_FAKEAPP must name the fake application (tests/unit/sd_update/CMakeLists.txt)"
#endif

#define ROUTE_MANIFEST 0
#define ROUTE_KEYSET   1
#define ROUTE_GOOD     2
#define ROUTE_REDIR    3
#define ROUTE_BIG      4
#define ROUTE_BAD      5
#define ROUTE_COUNT    6

typedef struct sc {
  fx *f;
  fx_server srv;
  fx_route routes[ROUTE_COUNT];
  uint8_t *kset;   size_t klen;
  uint8_t *mfst;   size_t mlen;
  uint8_t *payload; size_t plen;        /* the bytes the good route serves */
  wchar_t payload_path[MAX_PATH];       /* the artifact on disk (manifest digest source) */
  wchar_t user[MAX_PATH], staging[MAX_PATH], install[MAX_PATH];
  sd_upd_state_dirs st;
  sd_upd_paths paths;
  sd_upd_trust trust;
  sd_upd_root roots[2];
  sd_upd_transport *tr;
} sc;

/* ---- helpers ---- */

static int fakeapp_bytes(uint8_t **buf, size_t *n)
{
  wchar_t path[MAX_PATH];
  int wl = MultiByteToWideChar(CP_UTF8, 0, SD_TEST_FAKEAPP, -1, path, MAX_PATH);
  if (wl <= 0)
    return 0;
  return fx_read(path, buf, n);
}

/* dest = fake application bytes followed by tail (a "version" marker). */
static int write_version(const wchar_t *dest, const char *tail)
{
  uint8_t *buf = NULL;
  size_t n = 0, tl = strlen(tail);
  uint8_t *all;
  int ok;
  if (!fakeapp_bytes(&buf, &n))
    return 0;
  all = (uint8_t *)sd_alloc(n + tl + 1);
  if (all == NULL) {
    sd_free(buf);
    return 0;
  }
  memcpy(all, buf, n);
  memcpy(all + n, tail, tl);
  ok = fx_write(dest, all, n + tl);
  sd_free(all);
  sd_free(buf);
  return ok;
}

static int sign_manifest(sc *s, const char *base, uint64_t serial, const char *version, const char *expires)
{
  static char body[8192];
  fx_file_entry fe;
  fx_manifest_opts o;
  size_t n;
  memset(&o, 0, sizeof(o));
  fe.id = "portable-x64-modern";
  fe.name = "shelldrive-host.exe";
  fe.path = s->payload_path;
  o.channel = "stable";
  o.keyset = 1;
  o.serial = serial;
  o.version = version;
  o.expires = expires;
  o.base = base;
  o.files = &fe;
  o.nfiles = 1;
  n = fx_manifest_body(body, sizeof(body), &o);
  if (n == 0)
    return 0;
  sd_free(s->mfst);
  s->mfst = NULL;
  return fx_sign_manifest(s->f, body, n, &s->f->stable, &s->mfst, &s->mlen) &&
         (s->routes[ROUTE_MANIFEST].body = s->mfst, s->routes[ROUTE_MANIFEST].len = s->mlen, 1);
}

/* Starts the loopback server and the fixtures every engine test shares. base_dir: "files" (good route). */
static int sc_setup(sc *s, fx *f, const char *name)
{
  fx_keyset_opts ko;
  static char kbody[4096];
  fx_key const *roots[2];
  wchar_t dir[MAX_PATH], install_file[MAX_PATH], code[MAX_PATH];
  char base[160];
  size_t kn;

  memset(s, 0, sizeof(*s));
  s->f = f;
  if (!fx_init(f, name))
    return 0;
  if (!fx_path(f, L"payload", dir, MAX_PATH) || !CreateDirectoryW(dir, NULL))
    return 0;
  if (!fx_path(f, L"payload\\shelldrive-host.exe", s->payload_path, MAX_PATH) ||
      !write_version(s->payload_path, "NEW-BYTES"))
    return 0;
  if (!fx_read(s->payload_path, &s->payload, &s->plen))
    return 0;

  s->routes[ROUTE_MANIFEST].path = "/manifest.txt";
  s->routes[ROUTE_KEYSET].path = "/keyset.txt";
  s->routes[ROUTE_GOOD].path = "/files/shelldrive-host.exe";
  s->routes[ROUTE_REDIR].path = "/redir/shelldrive-host.exe";
  s->routes[ROUTE_REDIR].status = 302;
  s->routes[ROUTE_REDIR].location = "http://203.0.113.9/evil.exe";
  s->routes[ROUTE_BIG].path = "/big/shelldrive-host.exe";
  s->routes[ROUTE_BAD].path = "/bad/shelldrive-host.exe";
  if (!fx_server_start(&s->srv, s->routes, ROUTE_COUNT))
    return 0;
  s->routes[ROUTE_GOOD].body = s->payload;
  s->routes[ROUTE_GOOD].len = s->plen;
  s->routes[ROUTE_BIG].body = s->payload;
  s->routes[ROUTE_BIG].len = s->plen;
  s->routes[ROUTE_BIG].declared = s->plen + 100;
  s->routes[ROUTE_BAD].body = s->payload;        /* served with one byte changed below */
  s->routes[ROUTE_BAD].len = s->plen;

  /* keyset.txt: version 1, stable and beta keys, signed by roots a and b */
  memset(&ko, 0, sizeof(ko));
  ko.version = 1;
  kn = fx_keyset_body(f, kbody, sizeof(kbody), &ko);
  roots[0] = &f->root_a;
  roots[1] = &f->root_b;
  if (!fx_sign_keyset(f, kbody, kn, roots, 2, &s->kset, &s->klen))
    return 0;
  s->routes[ROUTE_KEYSET].body = s->kset;
  s->routes[ROUTE_KEYSET].len = s->klen;

  _snprintf_s(base, sizeof(base), _TRUNCATE, "http://127.0.0.1:%u/files/", (unsigned)s->srv.port);
  if (!sign_manifest(s, base, 1, "1.1.0", "2026-11-23T00:00:00Z"))
    return 0;

  /* state, staging and an install directory holding the "old" version (selftest exit 0 by default) */
  if (!fx_path(f, L"state", s->user, MAX_PATH) || !CreateDirectoryW(s->user, NULL))
    return 0;
  if (!fx_path(f, L"staging", s->staging, MAX_PATH) || !CreateDirectoryW(s->staging, NULL))
    return 0;
  if (!fx_path(f, L"install", s->install, MAX_PATH) || !CreateDirectoryW(s->install, NULL))
    return 0;
  if (!fx_path(f, L"install\\shelldrive-host.exe", install_file, MAX_PATH) || !write_version(install_file, "OLD-BYTES"))
    return 0;
  if (!fx_path(f, L"install\\selftest.code", code, MAX_PATH) || !fx_write(code, "0", 1))
    return 0;

  memcpy(s->roots[0].id, f->root_a.id, 8);
  memcpy(s->roots[0].pub, f->root_a.pub, 32);
  memcpy(s->roots[1].id, f->root_b.id, 8);
  memcpy(s->roots[1].pub, f->root_b.pub, 32);
  s->trust.roots = s->roots;
  s->trust.nroots = 2;
  s->trust.keyset = NULL;
  s->trust.keyset_len = 0;
  s->st.user = s->user;
  s->st.machine = NULL;
  s->paths.staging = s->staging;
  s->paths.install = s->install;
  s->paths.selftest_exe = L"shelldrive-host.exe";
  s->tr = sd_upd_transport_winhttp_create(0);
  return s->tr != NULL;
}

static void sc_done(sc *s)
{
  if (s->tr)
    sd_upd_transport_destroy(s->tr);
  fx_server_stop(&s->srv);
  sd_free(s->kset);
  sd_free(s->mfst);
  sd_free(s->payload);
  fx_done(s->f);
}

static void sc_request(const sc *s, sd_upd_request *r, const char *installed, sd_upd_mode mode, wchar_t *url,
                       size_t ucap)
{
  memset(r, 0, sizeof(*r));
  _snwprintf_s(url, ucap, _TRUNCATE, L"http://127.0.0.1:%u/manifest.txt", (unsigned)s->srv.port);
  r->manifest_url = url;
  r->manifest_alt = NULL;
  r->channel = "stable";
  r->installed_version = installed;
  r->flavour = "x64-modern";
  r->mode = mode;
  {
    int64_t now = 0;
    sd_upd_time_parse(FX_NOW_STR, strlen(FX_NOW_STR), &now);
    r->now = now;
  }
  r->tr = s->tr;
  r->trust = &s->trust;
  r->state = &s->st;
  r->paths = &s->paths;
}

static int file_bytes_equal(const wchar_t *path, const uint8_t *want, size_t n)
{
  uint8_t *got = NULL;
  size_t gn = 0;
  int same = 0;
  if (!fx_read(path, &got, &gn))
    return 0;
  same = gn == n && memcmp(got, want, n) == 0;
  sd_free(got);
  return same;
}

/* ---- tests ---- */

SD_TEST(engine_check_stage_apply_success)
{
  static fx f;
  sc s;
  sd_upd_request r;
  static sd_upd_offer o;
  wchar_t url[256], staged[MAX_PATH], payload_dir[MAX_PATH], rb[MAX_PATH];
  const wchar_t *names[1];
  uint8_t *old = NULL;
  size_t old_n = 0;
  uint64_t serial = 0;
  SD_REQUIRE(sc_setup(&s, &f, "eok"));
  sc_request(&s, &r, "1.0.0", SD_UPD_MODE_PORTABLE, url, 256);
  SD_CHECK(sd_upd_check(&r, &o) == SD_UPD_OK);
  SD_CHECK(o.available == 1);
  SD_CHECK_STR(o.version, "1.1.0");
  SD_CHECK_STR(o.file_id, "portable-x64-modern");
  SD_CHECK(o.size == s.plen);
  SD_CHECK(sd_upd_stage(&r, &o, staged, MAX_PATH) == SD_UPD_OK);
  SD_CHECK(file_bytes_equal(staged, s.payload, s.plen));

  /* the file-swap apply: the new file replaces the old one, the old one is kept in .rollback */
  SD_REQUIRE(fx_path(&f, L"staging\\1.1.0", payload_dir, MAX_PATH));
  names[0] = L"shelldrive-host.exe";
  SD_CHECK(sd_upd_apply_files(&r, payload_dir, names, 1, "1.0.0", "1.1.0", 30000) == SD_UPD_OK);
  {
    wchar_t inst[MAX_PATH];
    SD_REQUIRE(fx_path(&f, L"install\\shelldrive-host.exe", inst, MAX_PATH));
    SD_CHECK(file_bytes_equal(inst, s.payload, s.plen));
    SD_REQUIRE(fx_path(&f, L"install\\.rollback\\1.0.0\\shelldrive-host.exe", rb, MAX_PATH));
    SD_CHECK(fx_read(rb, &old, &old_n));
    SD_CHECK(old_n > 9 && memcmp(old + old_n - 9, "OLD-BYTES", 9) == 0);
    sd_free(old);
  }
  SD_CHECK(sd_upd_state_read_serial(&s.st, "stable", &serial) == SD_UPD_OK);
  SD_CHECK_EQ_INT(serial, 1);
  sc_done(&s);
}

SD_TEST(engine_selftest_failure_restores_previous_version)
{
  static fx f;
  sc s;
  sd_upd_request r;
  static sd_upd_offer o;
  wchar_t url[256], staged[MAX_PATH], payload_dir[MAX_PATH], inst[MAX_PATH], code[MAX_PATH], sdnew[MAX_PATH];
  const wchar_t *names[1];
  uint8_t *old_bytes = NULL;
  size_t old_n = 0;
  SD_REQUIRE(sc_setup(&s, &f, "eself"));
  sc_request(&s, &r, "1.0.0", SD_UPD_MODE_PORTABLE, url, 256);
  SD_REQUIRE(sd_upd_check(&r, &o) == SD_UPD_OK);
  SD_REQUIRE(sd_upd_stage(&r, &o, staged, MAX_PATH) == SD_UPD_OK);

  /* the installed binary (the one that runs --selftest after the swap) reports failure */
  SD_REQUIRE(fx_path(&f, L"install\\selftest.code", code, MAX_PATH));
  SD_REQUIRE(fx_write(code, "3", 1));
  SD_REQUIRE(fx_path(&f, L"install\\shelldrive-host.exe", inst, MAX_PATH));
  SD_REQUIRE(fx_read(inst, &old_bytes, &old_n));
  sd_free(old_bytes);
  old_bytes = NULL;

  SD_REQUIRE(fx_path(&f, L"staging\\1.1.0", payload_dir, MAX_PATH));
  names[0] = L"shelldrive-host.exe";
  SD_CHECK(sd_upd_apply_files(&r, payload_dir, names, 1, "1.0.0", "1.1.0", 30000) == SD_UPD_E_SELFTEST);

  /* the previous version is back, byte for byte, and nothing is left behind */
  SD_CHECK(fx_read(inst, &old_bytes, &old_n));
  SD_CHECK(old_n > 9 && memcmp(old_bytes + old_n - 9, "OLD-BYTES", 9) == 0);
  sd_free(old_bytes);
  SD_REQUIRE(fx_path(&f, L"install\\shelldrive-host.exe.sd-new", sdnew, MAX_PATH));
  SD_CHECK(GetFileAttributesW(sdnew) == INVALID_FILE_ATTRIBUTES);
  sc_done(&s);
}

SD_TEST(engine_up_to_date_offers_nothing)
{
  static fx f;
  sc s;
  sd_upd_request r;
  static sd_upd_offer o;
  wchar_t url[256];
  SD_REQUIRE(sc_setup(&s, &f, "eutd"));
  sc_request(&s, &r, "1.1.0", SD_UPD_MODE_PORTABLE, url, 256);
  SD_CHECK(sd_upd_check(&r, &o) == SD_UPD_OK);
  SD_CHECK(o.available == 0);
  SD_CHECK_STR(o.version, "1.1.0");
  sc_done(&s);
}

SD_TEST(engine_serial_rollback_and_same_serial_bytes)
{
  static fx f;
  sc s;
  sd_upd_request r;
  static sd_upd_offer o;
  wchar_t url[256];
  SD_REQUIRE(sc_setup(&s, &f, "eroll"));
  sc_request(&s, &r, "1.0.0", SD_UPD_MODE_PORTABLE, url, 256);

  /* serve serial 2 (base points at the live server) */
  {
    char base[160];
    _snprintf_s(base, sizeof(base), _TRUNCATE, "http://127.0.0.1:%u/files/", (unsigned)s.srv.port);
    SD_REQUIRE(sign_manifest(&s, base, 2, "1.1.0", "2026-11-23T00:00:00Z"));
  }
  SD_CHECK(sd_upd_check(&r, &o) == SD_UPD_OK);
  SD_CHECK_EQ_INT(o.serial, 2);

  /* an older manifest (serial 1) is refused: anti-rollback per channel */
  {
    char base[160];
    _snprintf_s(base, sizeof(base), _TRUNCATE, "http://127.0.0.1:%u/files/", (unsigned)s.srv.port);
    SD_REQUIRE(sign_manifest(&s, base, 1, "1.1.0", "2026-11-23T00:00:00Z"));
  }
  SD_CHECK(sd_upd_check(&r, &o) == SD_UPD_E_ROLLBACK);

  /* the same serial with other bytes is refused too (a re-signed manifest needs a new serial) */
  {
    char base[160];
    _snprintf_s(base, sizeof(base), _TRUNCATE, "http://127.0.0.1:%u/files/", (unsigned)s.srv.port);
    SD_REQUIRE(sign_manifest(&s, base, 2, "1.1.0", "2026-11-22T00:00:00Z"));
  }
  SD_CHECK(sd_upd_check(&r, &o) == SD_UPD_E_ROLLBACK);
  sc_done(&s);
}

SD_TEST(engine_expired_manifest_changes_no_state)
{
  static fx f;
  sc s;
  sd_upd_request r;
  static sd_upd_offer o;
  wchar_t url[256];
  uint64_t serial = 9;
  SD_REQUIRE(sc_setup(&s, &f, "eexp"));
  {
    char base[160];
    _snprintf_s(base, sizeof(base), _TRUNCATE, "http://127.0.0.1:%u/files/", (unsigned)s.srv.port);
    SD_REQUIRE(sign_manifest(&s, base, 1, "1.1.0", "2026-10-26T00:00:00Z"));
  }
  sc_request(&s, &r, "1.0.0", SD_UPD_MODE_PORTABLE, url, 256);
  SD_CHECK(sd_upd_check(&r, &o) == SD_UPD_E_EXPIRED);
  SD_CHECK(sd_upd_state_read_serial(&s.st, "stable", &serial) == SD_UPD_OK);
  SD_CHECK_EQ_INT(serial, 0);
  sc_done(&s);
}

SD_TEST(engine_https_fallback_to_http_mirror)
{
  static fx f;
  sc s;
  sd_upd_request r;
  static sd_upd_offer o;
  wchar_t url[256], alt[256], closed_url[256];
  fx_server dead;
  fx_route none;
  memset(&none, 0, sizeof(none));
  none.path = "/x";
  SD_REQUIRE(sc_setup(&s, &f, "efall"));
  /* a port with nothing listening: bind, learn the port, close */
  SD_REQUIRE(fx_server_start(&dead, &none, 1));
  _snwprintf_s(closed_url, SD_COUNTOF(closed_url), _TRUNCATE, L"https://127.0.0.1:%u/manifest.txt", (unsigned)dead.port);
  fx_server_stop(&dead);
  sc_request(&s, &r, "1.0.0", SD_UPD_MODE_PORTABLE, url, 256);
  r.manifest_url = closed_url;
  _snwprintf_s(alt, SD_COUNTOF(alt), _TRUNCATE, L"http://127.0.0.1:%u/manifest.txt", (unsigned)s.srv.port);
  r.manifest_alt = alt;
  SD_CHECK(sd_upd_check(&r, &o) == SD_UPD_OK);
  SD_CHECK(o.available == 1);

  /* without the mirror the same failure is a network error, and the offer is not stale on a first try */
  r.manifest_alt = NULL;
  SD_CHECK(sd_upd_check(&r, &o) == SD_UPD_E_NETWORK);
  sc_done(&s);
}

SD_TEST(engine_stage_refuses_redirect_oversize_and_bad_digest)
{
  static fx f;
  sc s;
  sd_upd_request r;
  static sd_upd_offer o;
  wchar_t url[256], staged[MAX_PATH], path[MAX_PATH];
  char base[160];
  SD_REQUIRE(sc_setup(&s, &f, "estage"));
  sc_request(&s, &r, "1.0.0", SD_UPD_MODE_PORTABLE, url, 256);

  /* a base whose only file redirects to a foreign host: refused, nothing connects there (T-69) */
  _snprintf_s(base, sizeof(base), _TRUNCATE, "http://127.0.0.1:%u/redir/", (unsigned)s.srv.port);
  SD_REQUIRE(sign_manifest(&s, base, 2, "1.1.0", "2026-11-23T00:00:00Z"));
  SD_REQUIRE(sd_upd_check(&r, &o) == SD_UPD_OK);
  SD_CHECK(sd_upd_stage(&r, &o, staged, MAX_PATH) == SD_UPD_E_REDIRECT);

  /* declared size larger than the manifest: refused before the body is used */
  _snprintf_s(base, sizeof(base), _TRUNCATE, "http://127.0.0.1:%u/big/", (unsigned)s.srv.port);
  SD_REQUIRE(sign_manifest(&s, base, 3, "1.1.0", "2026-11-23T00:00:00Z"));
  SD_REQUIRE(sd_upd_check(&r, &o) == SD_UPD_OK);
  SD_CHECK(sd_upd_stage(&r, &o, staged, MAX_PATH) == SD_UPD_E_SIZE);

  /* same size, other bytes: the digest check refuses it and the file is not kept */
  s.routes[ROUTE_BAD].body = (const uint8_t *)NULL;
  {
    uint8_t *bad = (uint8_t *)sd_alloc(s.plen);
    SD_REQUIRE(bad != NULL);
    memcpy(bad, s.payload, s.plen);
    bad[s.plen - 1] ^= 0x55;
    s.routes[ROUTE_BAD].body = bad;
    s.routes[ROUTE_BAD].len = s.plen;
    _snprintf_s(base, sizeof(base), _TRUNCATE, "http://127.0.0.1:%u/bad/", (unsigned)s.srv.port);
    SD_REQUIRE(sign_manifest(&s, base, 4, "1.1.0", "2026-11-23T00:00:00Z"));
    SD_REQUIRE(sd_upd_check(&r, &o) == SD_UPD_OK);
    SD_CHECK(sd_upd_stage(&r, &o, staged, MAX_PATH) == SD_UPD_E_HASH);
    SD_REQUIRE(fx_path(&f, L"staging\\1.1.0\\shelldrive-host.exe", path, MAX_PATH));
    SD_CHECK(GetFileAttributesW(path) == INVALID_FILE_ATTRIBUTES);
    sd_free(bad);
    s.routes[ROUTE_BAD].body = NULL;
  }
  sc_done(&s);
}

SD_TEST(engine_setup_run_exit_code)
{
  static fx f;
  wchar_t dir[MAX_PATH], exe[MAX_PATH], code[MAX_PATH];
  SD_REQUIRE(fx_init(&f, "esetup"));
  SD_REQUIRE(fx_path(&f, L"setupdir", dir, MAX_PATH));
  SD_REQUIRE(CreateDirectoryW(dir, NULL));
  /* not "setup.exe": a 32-bit file with an installer-like name meets the installer heuristic at CreateProcess */
  SD_REQUIRE(fx_path(&f, L"setupdir\\stage-fake.exe", exe, MAX_PATH));
  SD_REQUIRE(write_version(exe, "SETUP"));
  SD_REQUIRE(fx_path(&f, L"setupdir\\selftest.code", code, MAX_PATH));
  SD_REQUIRE(fx_write(code, "0", 1));
  SD_CHECK_EQ_INT(sd_upd_apply_setup(exe, 30000), SD_UPD_OK);
  SD_REQUIRE(fx_write(code, "5", 1));
  SD_CHECK(sd_upd_apply_setup(exe, 30000) == SD_UPD_E_APPLY);
  fx_done(&f);
}

SD_TEST(engine_cleanup_keeps_current_version)
{
  static fx f;
  wchar_t stg[MAX_PATH], old[MAX_PATH], cur[MAX_PATH], file_old[MAX_PATH], file_cur[MAX_PATH];
  SD_REQUIRE(fx_init(&f, "eclean"));
  SD_REQUIRE(fx_path(&f, L"stg", stg, MAX_PATH));
  SD_REQUIRE(CreateDirectoryW(stg, NULL));
  SD_REQUIRE(_snwprintf_s(old, MAX_PATH, _TRUNCATE, L"%ls\\0.9.0", stg) > 0);
  SD_REQUIRE(_snwprintf_s(cur, MAX_PATH, _TRUNCATE, L"%ls\\1.1.0", stg) > 0);
  SD_REQUIRE(CreateDirectoryW(old, NULL));
  SD_REQUIRE(CreateDirectoryW(cur, NULL));
  SD_REQUIRE(_snwprintf_s(file_old, MAX_PATH, _TRUNCATE, L"%ls\\a.bin", old) > 0);
  SD_REQUIRE(_snwprintf_s(file_cur, MAX_PATH, _TRUNCATE, L"%ls\\a.bin", cur) > 0);
  SD_REQUIRE(fx_write(file_old, "x", 1));
  SD_REQUIRE(fx_write(file_cur, "y", 1));
  sd_upd_cleanup_staging(stg, "1.1.0");
  SD_CHECK(GetFileAttributesW(old) == INVALID_FILE_ATTRIBUTES);
  SD_CHECK(GetFileAttributesW(file_cur) != INVALID_FILE_ATTRIBUTES);
  fx_done(&f);
}

SD_TEST(engine_detects_a_known_flavour)
{
  char fl[16];
  SD_CHECK(sd_upd_detect_flavour(fl, sizeof(fl)) == SD_UPD_OK);
  SD_CHECK(strcmp(fl, "x64-modern") == 0 || strcmp(fl, "x64-xp") == 0 || strcmp(fl, "x86-sse2") == 0 ||
           strcmp(fl, "x86-ia32") == 0 || strcmp(fl, "arm64") == 0 || strcmp(fl, "arm32") == 0);
}
