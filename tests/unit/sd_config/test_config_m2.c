/* sd_config M2: profile keys, proxy specs, ProxyJump chains, legacy hash and the importers (PuTTY .reg
 * export, PuTTY sessions under a test registry key, ssh_config). The real PuTTY registry of the user
 * is never read. */
#include <windows.h>
#include <string.h>

#include "sd_test.h"
#include "sd_config/sd_config.h"
#include "sd_config/sd_import.h"
#include "sd_base/sd_mem.h"

#ifndef SD_CONFIG_TEST_FIXTURES
#error SD_CONFIG_TEST_FIXTURES must name tests/unit/sd_config/fixtures
#endif

static sd_ini *parse(const char *text)
{
  sd_ini *ini = NULL;
  uint32_t flags = 0;
  if (sd_ini_parse(text, strlen(text), &ini, &flags) != SD_OK)
    return NULL;
  return ini;
}

static uint8_t *read_fixture(const char *name, size_t *len)
{
  char path[MAX_PATH];
  HANDLE h;
  DWORD sz, got = 0;
  uint8_t *buf;
  strcpy_s(path, sizeof(path), SD_CONFIG_TEST_FIXTURES "/");
  strcat_s(path, sizeof(path), name);
  h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
  if (h == INVALID_HANDLE_VALUE)
    return NULL;
  sz = GetFileSize(h, NULL);
  buf = (uint8_t *)sd_alloc(sz + 1);
  if (buf && !ReadFile(h, buf, sz, &got, NULL)) got = 0;
  CloseHandle(h);
  if (buf) buf[got] = 0;
  *len = got;
  return buf;
}

SD_TEST(profile_m2_keys_round_trip)
{
  static const char text[] =
    "[profile]\nname = Web\nhost = web.example.org\nuser = deploy\n"
    "[auth]\nidentity = ~\\.ssh\\id_ed25519\nidentity.2 = C:\\keys\\b.ppk\nidentity.3 = C:\\keys\\c\n"
    "identity_store = 2b9e0000000000000000000000000001\ncertificate = ~\\.ssh\\id_ed25519-cert.pub\n"
    "agent = pageant\nidentities_only = no\nagent_keys = SHA256:aaa, SHA256:bbb\nsave_password = no\n"
    "cache_secrets_for_reconnect = no\n"
    "[proxy]\njump = bastion, admin@10.0.0.5:2222\nproxy = socks5://alice@socks.corp:1080\n"
    "proxy.3 = http://10.0.0.1:3128\nproxy_auth.3 = basic\n"
    "[connection]\nconnections = 4\n"
    "[security]\nlegacy_algorithms = ask\nlegacy_accepted = sha256:4f1c\nhost_key_alias = webalias\n"
    "update_host_keys = no\nkeepalive = 30s\nconnect_timeout = 1m\nrefuse_terrapin_exposed = yes\n";
  sd_ini *ini = parse(text), *out = NULL;
  sd_profile *p = (sd_profile *)sd_alloc(sizeof(*p)), *q = (sd_profile *)sd_alloc(sizeof(*q));
  const char *bad = NULL;
  sd_wr w;
  SD_REQUIRE(ini && p && q);
  SD_CHECK(sd_profile_from_ini(ini, p, &bad) == SD_OK);
  SD_CHECK(bad == NULL);
  SD_CHECK(sd_profile_identity_count(p) == 3);
  SD_CHECK_STR(sd_profile_identity_at(p, 1), "C:\\keys\\b.ppk");
  SD_CHECK_STR(p->identity_store, "2b9e0000000000000000000000000001");
  SD_CHECK(p->agent == SD_PROFILE_AGENT_PAGEANT && p->identities_only == 0);
  SD_CHECK(!sd_profile_identities_only(p));                    /* explicit no wins (D37) */
  SD_CHECK(p->save_password == 0 && p->cache_secrets == 0);
  SD_CHECK_STR(p->jump, "bastion, admin@10.0.0.5:2222");
  SD_CHECK(p->proxy[0].kind == SD_PROFILE_PROXY_SOCKS5 && p->proxy[0].port == 1080);
  SD_CHECK_STR(p->proxy[0].user, "alice");
  SD_CHECK(p->proxy[1].kind == SD_PROFILE_PROXY_NONE);
  SD_CHECK(p->proxy[2].kind == SD_PROFILE_PROXY_HTTP && p->proxy[2].port == 3128);
  SD_CHECK(p->proxy_auth[2] == SD_PROFILE_PROXY_AUTH_BASIC);
  SD_CHECK(p->connections == 4);
  SD_CHECK(p->legacy_algorithms == SD_PROFILE_LEGACY_ASK && p->update_host_keys == SD_PROFILE_HKU_NO);
  SD_CHECK(p->keepalive_ms == 30000 && p->connect_timeout_ms == 60000 && p->refuse_terrapin_exposed == 1);
  SD_CHECK_STR(p->host_key_alias, "webalias");
  /* write and read back */
  SD_REQUIRE(sd_profile_to_ini(p, &out) == SD_OK);
  sd_wr_init(&w, 1 << 20);
  SD_REQUIRE(sd_ini_serialize(out, &w) == SD_OK);
  sd_ini_free(out);
  out = NULL;
  SD_REQUIRE(sd_ini_parse((const char *)w.p, w.len, &out, NULL) == SD_OK);
  SD_CHECK(sd_profile_from_ini(out, q, &bad) == SD_OK);
  SD_CHECK(q->proxy[2].kind == SD_PROFILE_PROXY_HTTP && q->connections == 4 && q->identities_only == 0);
  SD_CHECK_STR(sd_ini_get(out, "proxy", "proxy"), "socks5://alice@socks.corp:1080");
  SD_CHECK_STR(sd_ini_get(out, "proxy", "proxy.3"), "http://10.0.0.1:3128");
  SD_CHECK_STR(sd_ini_get(out, "security", "keepalive"), "30000ms");
  sd_wr_free(&w);
  sd_ini_free(out);
  sd_ini_free(ini);
  /* defaults stay out of an M1 file */
  ini = parse("[profile]\nhost = h\n");
  SD_REQUIRE(ini && sd_profile_from_ini(ini, p, &bad) == SD_OK);
  SD_CHECK(p->connections == 1 && p->legacy_algorithms == SD_PROFILE_LEGACY_WARN &&
           p->update_host_keys == SD_PROFILE_HKU_ASK && p->identities_only == SD_PROFILE_UNSET &&
           p->save_password == 1 && p->cache_secrets == 1);
  SD_CHECK(!sd_profile_identities_only(p));
  strcpy_s(p->identity, sizeof(p->identity), "k");
  SD_CHECK(sd_profile_identities_only(p));                     /* D37: an identity implies yes */
  out = NULL;
  p->identity[0] = 0;
  SD_REQUIRE(sd_profile_to_ini(p, &ini) == SD_OK);
  SD_CHECK(sd_ini_get(ini, "connection", "connections") == NULL && sd_ini_get(ini, "security", "legacy_algorithms") == NULL &&
           sd_ini_get(ini, "auth", "identities_only") == NULL && sd_ini_get(ini, "proxy", "proxy") == NULL);
  sd_ini_free(ini);
  /* invalid values name their key */
  {
    static const char *const bads[][2] = {
      { "[profile]\nhost = h\n[connection]\nconnections = 5\n", "connection.connections" },
      { "[profile]\nhost = h\n[proxy]\nproxy = socks5://u:pw@h:1\n", "proxy.proxy" },
      { "[profile]\nhost = h\n[proxy]\nproxy.2 = system\n", "proxy.proxy" },
      { "[profile]\nhost = h\n[proxy]\nproxy = ftp://h\n", "proxy.proxy" },
      { "[profile]\nhost = h\n[proxy]\njump = a,,b\n", "proxy.jump" },
      { "[profile]\nhost = h\n[security]\nlegacy_algorithms = maybe\n", "security.legacy_algorithms" },
      { "[profile]\nhost = h\n[security]\nupdate_host_keys = always\n", "security.update_host_keys" },
      { "[profile]\nhost = h\n[auth]\nagent = gpg\n", "auth.agent" },
      { "[profile]\nhost = h\n[auth]\nidentity_store = xyz\n", "auth.identity_store" },
    };
    size_t i;
    for (i = 0; i < SD_COUNTOF(bads); i++) {
      ini = parse(bads[i][0]);
      bad = NULL;
      SD_CHECK(ini && sd_profile_from_ini(ini, p, &bad) == SD_E_INVALID_PARAM);
      SD_CHECK_STR(bad, bads[i][1]);
      sd_ini_free(ini);
    }
  }
  sd_free(p);
  sd_free(q);
}

SD_TEST(proxy_spec_and_jump_parse)
{
  sd_proxy_spec s;
  sd_jump_list jl;
  char out[300];
  SD_CHECK(sd_proxy_spec_parse("none", &s) == SD_OK && s.kind == SD_PROFILE_PROXY_NONE);
  SD_CHECK(sd_proxy_spec_parse("system", &s) == SD_OK && s.kind == SD_PROFILE_PROXY_SYSTEM);
  SD_CHECK(sd_proxy_spec_parse("http://proxy.corp", &s) == SD_OK && s.kind == SD_PROFILE_PROXY_HTTP && s.port == 8080);
  SD_CHECK(sd_proxy_spec_parse("socks5://[fd00::1]:1081", &s) == SD_OK && s.port == 1081);
  SD_CHECK_STR(s.host, "fd00::1");
  SD_CHECK(sd_proxy_spec_format(&s, out, sizeof(out)) == SD_OK);
  SD_CHECK_STR(out, "socks5://[fd00::1]:1081");
  SD_CHECK(sd_proxy_spec_parse("HTTP://bob@10.0.0.1:3128/", &s) == SD_OK && s.port == 3128);
  SD_CHECK_STR(s.user, "bob");
  SD_CHECK(sd_proxy_spec_parse("http://bob:secret@h:1", &s) == SD_E_INVALID_PARAM);
  SD_CHECK(sd_proxy_spec_parse("http://h:1/path", &s) == SD_E_INVALID_PARAM);
  SD_CHECK(sd_proxy_spec_parse("socks4://h", &s) == SD_E_INVALID_PARAM);
  SD_CHECK(sd_proxy_spec_parse("http://h:0", &s) == SD_E_INVALID_PARAM);
  SD_CHECK(sd_proxy_spec_parse("http://", &s) == SD_E_INVALID_PARAM);
  SD_CHECK(sd_jump_parse(" a , b@c:2 ,d ", &jl) == SD_OK && jl.count == 3);
  SD_CHECK_STR(jl.entry[1], "b@c:2");
  SD_CHECK(sd_jump_parse("none", &jl) == SD_OK && jl.count == 0);
  SD_CHECK(sd_jump_parse("1,2,3,4,5,6,7,8,9", &jl) == SD_E_INVALID_PARAM);
  SD_CHECK(sd_jump_parse("a,", &jl) == SD_E_INVALID_PARAM);
}

/* in-memory profile store for chain resolution */
typedef struct mem_store { sd_profile *p; uint32_t n; } mem_store;

static sd_err mem_lookup(void *ctx, const char *key, sd_profile *out)
{
  mem_store *m = (mem_store *)ctx;
  uint32_t i;
  for (i = 0; i < m->n; i++)
    if (strcmp(m->p[i].id, key) == 0 || _stricmp(m->p[i].name, key) == 0) {
      *out = m->p[i];
      return SD_OK;
    }
  return SD_E_NOT_FOUND;
}

static void mk(sd_profile *p, const char *id, const char *name, const char *host, const char *user, const char *jump)
{
  size_t i;
  sd_profile_defaults(p);
  for (i = 0; i < 32; i++) p->id[i] = id[0];
  p->id[32] = 0;
  strcpy_s(p->name, sizeof(p->name), name);
  strcpy_s(p->host, sizeof(p->host), host);
  strcpy_s(p->user, sizeof(p->user), user);
  strcpy_s(p->jump, sizeof(p->jump), jump);
}

SD_TEST(chain_resolution)
{
  mem_store ms;
  sd_chain *c = NULL;
  const char *why = NULL;
  ms.n = 4;
  ms.p = (sd_profile *)sd_calloc(ms.n, sizeof(sd_profile));
  SD_REQUIRE(ms.p);
  mk(&ms.p[0], "a", "target", "target.example", "deploy", "bastion, admin@10.0.0.5:2222");
  strcpy_s(ms.p[0].identity, sizeof(ms.p[0].identity), "C:\\k\\target");
  ms.p[0].proxy[0].kind = SD_PROFILE_PROXY_SOCKS5;
  strcpy_s(ms.p[0].proxy[0].host, sizeof(ms.p[0].proxy[0].host), "socks.corp");
  ms.p[0].proxy[0].port = 1080;
  ms.p[0].proxy[2].kind = SD_PROFILE_PROXY_HTTP;
  strcpy_s(ms.p[0].proxy[2].host, sizeof(ms.p[0].proxy[2].host), "10.0.0.1");
  ms.p[0].proxy[2].port = 3128;
  mk(&ms.p[1], "b", "bastion", "bastion.example", "jump", "outer");
  ms.p[1].proxy[0].kind = SD_PROFILE_PROXY_HTTP;          /* ignored: a referenced profile's proxy */
  strcpy_s(ms.p[1].proxy[0].host, sizeof(ms.p[1].proxy[0].host), "ignored");
  ms.p[1].proxy[0].port = 1;
  mk(&ms.p[2], "c", "outer", "outer.example", "o", "");
  mk(&ms.p[3], "d", "loop", "loop.example", "l", "loop");
  SD_REQUIRE(sd_chain_resolve(&ms.p[0], mem_lookup, &ms, &c, &why) == SD_OK);
  SD_CHECK(c->count == 4);
  SD_CHECK_STR(c->hop[0].host, "outer.example");
  SD_CHECK_STR(c->hop[1].host, "bastion.example");
  SD_CHECK_STR(c->hop[1].profile_name, "bastion");
  SD_CHECK_STR(c->hop[2].host, "10.0.0.5");
  SD_CHECK(c->hop[2].port == 2222);
  SD_CHECK_STR(c->hop[2].user, "admin");
  SD_CHECK(c->hop[2].identity_count == 1);                 /* inherited [auth] of the target profile */
  SD_CHECK(c->hop[2].identities_only == 1);
  SD_CHECK_STR(c->hop[3].host, "target.example");
  SD_CHECK(c->proxy[0].kind == SD_PROFILE_PROXY_SOCKS5 && c->proxy[2].kind == SD_PROFILE_PROXY_HTTP);
  sd_free(c);
  /* cycles, unknown entries, too long, proxy beyond the chain */
  SD_CHECK(sd_chain_resolve(&ms.p[3], mem_lookup, &ms, &c, &why) == SD_E_INVALID_PARAM);
  SD_CHECK_STR(why, "jump_cycle");
  strcpy_s(ms.p[2].jump, sizeof(ms.p[2].jump), "target");
  SD_CHECK(sd_chain_resolve(&ms.p[0], mem_lookup, &ms, &c, &why) == SD_E_INVALID_PARAM);
  SD_CHECK_STR(why, "jump_cycle");
  strcpy_s(ms.p[2].jump, sizeof(ms.p[2].jump), "not a host!");
  SD_CHECK(sd_chain_resolve(&ms.p[0], mem_lookup, &ms, &c, &why) == SD_E_INVALID_PARAM);
  SD_CHECK_STR(why, "jump_invalid");
  strcpy_s(ms.p[2].jump, sizeof(ms.p[2].jump), "h1,h2,h3,h4,h5,h6,h7");
  SD_CHECK(sd_chain_resolve(&ms.p[0], mem_lookup, &ms, &c, &why) == SD_E_INVALID_PARAM);
  SD_CHECK_STR(why, "jump_too_long");
  ms.p[2].jump[0] = 0;
  ms.p[0].jump[0] = 0;
  SD_CHECK(sd_chain_resolve(&ms.p[0], mem_lookup, &ms, &c, &why) == SD_E_INVALID_PARAM);
  SD_CHECK_STR(why, "proxy_leg");
  ms.p[0].proxy[2].kind = SD_PROFILE_PROXY_NONE;
  SD_REQUIRE(sd_chain_resolve(&ms.p[0], mem_lookup, &ms, &c, &why) == SD_OK);
  SD_CHECK(c->count == 1);
  sd_free(c);
  sd_free(ms.p);
}

SD_TEST(legacy_set_hash)
{
  const char *a[] = { "hmac-sha1", "3des-cbc", "hmac-sha1" };
  const char *b[] = { "3des-cbc", "hmac-sha1" };
  const char *c[] = { "3des-cbc" };
  char ha[80], hb[80], hc[80];
  sd_legacy_set_hash(a, 3, ha);
  sd_legacy_set_hash(b, 2, hb);
  sd_legacy_set_hash(c, 1, hc);
  SD_CHECK(strncmp(ha, "sha256:", 7) == 0 && strlen(ha) == 71);
  SD_CHECK_STR(ha, hb);
  SD_CHECK(strcmp(ha, hc) != 0);
}

static const sd_import_candidate *find_cand(const sd_import_result *r, const char *source)
{
  uint32_t i;
  for (i = 0; i < r->count; i++)
    if (strcmp(r->items[i].source, source) == 0) return &r->items[i];
  return NULL;
}

static int has_skip(const sd_import_result *r, sd_import_skip_kind k, const char *item)
{
  uint32_t i;
  for (i = 0; i < r->nskipped; i++)
    if (r->skipped[i].kind == k && strcmp(r->skipped[i].item, item) == 0) return 1;
  return 0;
}

static void check_putty(sd_test_ctx *sd_t_, const sd_import_result *r)
{
  const sd_import_candidate *c;
  SD_CHECK(r->count == 4);
  c = find_cand(r, "My Web Server");
  SD_REQUIRE(c != NULL);
  SD_CHECK_STR(c->p.host, "web.example.org");
  SD_CHECK_STR(c->p.user, "deploy");
  SD_CHECK(c->p.port == 2082);
  SD_CHECK_STR(c->p.identity, "C:\\Users\\alice\\keys\\web.ppk");
  SD_CHECK_STR(c->p.certificate, "C:\\Users\\alice\\keys\\web-cert.pub");
  SD_CHECK(c->p.proxy[0].kind == SD_PROFILE_PROXY_SOCKS5 && c->p.proxy[0].port == 1080);
  SD_CHECK_STR(c->p.proxy[0].host, "socks.corp");
  SD_CHECK_STR(c->p.proxy[0].user, "alice");
  SD_CHECK((c->flags & SD_IMPORT_F_ONLY_THIS_KEY) != 0);
  SD_CHECK(c->p.identities_only == SD_PROFILE_UNSET);
  c = find_cand(r, "db");
  SD_REQUIRE(c != NULL);
  SD_CHECK_STR(c->p.user, "defuser");                       /* from Default Settings */
  SD_CHECK(c->p.port == 22);
  SD_CHECK_STR(c->p.jump, "jump@bastion.example.org:22");
  c = find_cand(r, "proxied");
  SD_REQUIRE(c != NULL);
  SD_CHECK(c->p.proxy[0].kind == SD_PROFILE_PROXY_HTTP && c->p.proxy[0].port == 3128);
  c = find_cand(r, "old-socks4");
  SD_REQUIRE(c != NULL);
  SD_CHECK((c->flags & SD_IMPORT_F_PROXY_SKIPPED) != 0 && c->p.proxy[0].kind == SD_PROFILE_PROXY_NONE);
  SD_CHECK(has_skip(r, SD_IMPORT_SKIP_PROXY, "1"));
  SD_CHECK(has_skip(r, SD_IMPORT_SKIP_NOT_SSH, "telnet"));
  SD_CHECK(has_skip(r, SD_IMPORT_SKIP_INVALID, "HostName"));
  SD_CHECK(find_cand(r, "Default Settings") == NULL);
}

SD_TEST(import_putty_reg_export)
{
  sd_import_result r;
  size_t len = 0;
  uint8_t *data = read_fixture("putty_sessions.reg", &len);
  SD_REQUIRE(data != NULL);
  sd_import_result_init(&r);
  SD_REQUIRE(sd_import_putty_reg_text(data, len, &r) == SD_OK);
  check_putty(sd_t_, &r);
  sd_import_result_free(&r);
  SD_CHECK(sd_import_putty_reg_text((const uint8_t *)"not a reg file", 14, &r) == SD_E_KEY_FORMAT);
  sd_import_result_free(&r);
  sd_free(data);
}

static void reg_delete_tree(HKEY parent, const wchar_t *name)
{
  HKEY h;
  wchar_t sub[256];
  DWORD n;
  if (RegOpenKeyExW(parent, name, 0, KEY_READ | KEY_WRITE, &h) != ERROR_SUCCESS)
    return;
  for (;;) {
    n = SD_COUNTOF(sub);
    if (RegEnumKeyExW(h, 0, sub, &n, NULL, NULL, NULL, NULL) != ERROR_SUCCESS) break;
    reg_delete_tree(h, sub);
  }
  RegCloseKey(h);
  RegDeleteKeyW(parent, name);
}

static void set_sz(HKEY h, const wchar_t *name, const wchar_t *v)
{
  RegSetValueExW(h, name, 0, REG_SZ, (const BYTE *)v, (DWORD)((wcslen(v) + 1) * sizeof(wchar_t)));
}

static void set_dw(HKEY h, const wchar_t *name, DWORD v)
{
  RegSetValueExW(h, name, 0, REG_DWORD, (const BYTE *)&v, sizeof(v));
}

SD_TEST(import_putty_test_registry_key)
{
  wchar_t base[128], key[192], num[16];
  DWORD pid = GetCurrentProcessId();
  HKEY h;
  sd_import_result r;
  const sd_import_candidate *c;
  int i = 0;
  do { num[i++] = (wchar_t)(L'0' + pid % 10); pid /= 10; } while (pid);
  num[i] = 0;
  _wcsrev(num);
  wcscpy_s(base, SD_COUNTOF(base), L"Software\\LibreStatic\\ShellDriveTest-");
  wcscat_s(base, SD_COUNTOF(base), num);
  wcscpy_s(key, SD_COUNTOF(key), base);
  wcscat_s(key, SD_COUNTOF(key), L"\\Sessions\\My%20Box");
  SD_REQUIRE(RegCreateKeyExW(HKEY_CURRENT_USER, key, 0, NULL, 0, KEY_WRITE, NULL, &h, NULL) == ERROR_SUCCESS);
  set_sz(h, L"HostName", L"box.example.org");
  set_dw(h, L"PortNumber", 2200);
  set_sz(h, L"UserName", L"b\x00f6" L"b");                     /* "böb": UTF-16 -> UTF-8 */
  set_sz(h, L"Protocol", L"ssh");
  set_dw(h, L"ProxyMethod", 3);
  set_sz(h, L"ProxyHost", L"proxy.corp");
  set_dw(h, L"ProxyPort", 3128);
  RegCloseKey(h);
  wcscpy_s(key, SD_COUNTOF(key), base);
  wcscat_s(key, SD_COUNTOF(key), L"\\Sessions");
  sd_import_result_init(&r);
  SD_CHECK(sd_import_putty_registry(HKEY_CURRENT_USER, key, &r) == SD_OK);
  SD_CHECK(r.count == 1);
  c = find_cand(&r, "My Box");
  SD_CHECK(c != NULL);
  if (c) {
    SD_CHECK_STR(c->p.host, "box.example.org");
    SD_CHECK(c->p.port == 2200);
    SD_CHECK_STR(c->p.user, "b\xc3\xb6" "b");
    SD_CHECK(c->p.proxy[0].kind == SD_PROFILE_PROXY_HTTP && c->p.proxy[0].port == 3128);
  }
  sd_import_result_free(&r);
  reg_delete_tree(HKEY_CURRENT_USER, base);
  SD_CHECK(RegOpenKeyExW(HKEY_CURRENT_USER, base, 0, KEY_READ, &h) != ERROR_SUCCESS);
  SD_CHECK(sd_import_putty_registry(HKEY_CURRENT_USER, key, &r) == SD_E_NOT_FOUND);
}

SD_TEST(import_ssh_config)
{
  sd_import_result r;
  sd_import_env env;
  size_t len = 0;
  char *data = (char *)read_fixture("ssh_config", &len);
  const sd_import_candidate *c;
  SD_REQUIRE(data != NULL);
  env.home = "C:\\Users\\alice";
  env.local_user = "alice";
  sd_import_result_init(&r);
  SD_REQUIRE(sd_import_ssh_config_text(data, len, &env, &r) == SD_OK);
  SD_CHECK(r.count == 7);                                    /* web, web-alias, bastion, db, direct, build.corp, secret.corp */
  c = find_cand(&r, "web");
  SD_REQUIRE(c != NULL);
  SD_CHECK_STR(c->p.host, "web.example.org");
  SD_CHECK_STR(c->p.user, "globaluser");                    /* first obtained value wins (global line) */
  SD_CHECK(c->p.port == 2222);
  SD_CHECK(sd_profile_identity_count(&c->p) == 3);
  SD_CHECK_STR(c->p.identity, "C:\\Users\\alice\\.ssh\\id_global");
  SD_CHECK_STR(c->p.identity_n[0], "C:\\Users\\alice\\.ssh\\id_web");
  SD_CHECK_STR(c->p.identity_n[1], "C:\\Users\\alice\\.ssh\\id_globaluser_web.example.org");
  SD_CHECK_STR(c->p.certificate, "C:\\Users\\alice\\.ssh\\id_web-cert.pub");
  SD_CHECK((c->flags & SD_IMPORT_F_ONLY_THIS_KEY) != 0);
  SD_CHECK(find_cand(&r, "web-alias") != NULL);
  c = find_cand(&r, "bastion");
  SD_REQUIRE(c != NULL);
  SD_CHECK(c->p.identities_only == 0 && (c->flags & SD_IMPORT_F_ONLY_THIS_KEY) == 0);
  SD_CHECK(c->p.port == 2200);                              /* Host * */
  c = find_cand(&r, "db");
  SD_REQUIRE(c != NULL);
  SD_CHECK_STR(c->p.jump, "bastion,admin@10.0.0.5:2222");
  SD_CHECK(c->p.identities_only == 1);
  c = find_cand(&r, "direct");
  SD_REQUIRE(c != NULL);
  SD_CHECK(c->p.jump[0] == 0);
  c = find_cand(&r, "build.corp");
  SD_REQUIRE(c != NULL);
  SD_CHECK_STR(c->p.host, "build.corp.example");
  SD_CHECK(c->p.port == 2022);
  c = find_cand(&r, "secret.corp");
  SD_REQUIRE(c != NULL);
  SD_CHECK(c->p.port == 2200);                              /* !secret.corp excluded it from *.corp */
  SD_CHECK(has_skip(&r, SD_IMPORT_SKIP_KEYWORD, "ForwardAgent"));
  SD_CHECK(has_skip(&r, SD_IMPORT_SKIP_KEYWORD, "ProxyCommand"));
  SD_CHECK(has_skip(&r, SD_IMPORT_SKIP_KEYWORD, "Match"));
  SD_CHECK(has_skip(&r, SD_IMPORT_SKIP_KEYWORD, "Include"));
  SD_CHECK(has_skip(&r, SD_IMPORT_SKIP_KEYWORD, "ServerAliveInterval"));
  sd_import_result_free(&r);
  sd_free(data);
}

/* existing profiles for the duplicate check */
static sd_err fake_enum(sd_profile_enum_cb cb, void *ctx)
{
  sd_profile *p = (sd_profile *)sd_alloc(sizeof(*p));
  if (p == NULL) return SD_E_NO_MEMORY;
  sd_profile_defaults(p);
  strcpy_s(p->name, sizeof(p->name), "Existing");
  strcpy_s(p->host, sizeof(p->host), "WEB.example.org");
  strcpy_s(p->user, sizeof(p->user), "globaluser");
  p->port = 2222;
  cb(ctx, p, L"x");
  strcpy_s(p->name, sizeof(p->name), "bastion");
  strcpy_s(p->host, sizeof(p->host), "other.example.org");
  cb(ctx, p, L"y");
  sd_free(p);
  return SD_OK;
}

SD_TEST(import_duplicates_and_write)
{
  sd_import_result r;
  sd_import_env env;
  size_t len = 0;
  char *data = (char *)read_fixture("ssh_config", &len);
  wchar_t root[MAX_PATH];
  uint32_t written = 0, i;
  sd_profile *p = (sd_profile *)sd_alloc(sizeof(*p));
  SD_REQUIRE(data != NULL && p != NULL);
  env.home = "C:\\Users\\alice";
  env.local_user = "alice";
  sd_import_result_init(&r);
  SD_REQUIRE(sd_import_ssh_config_text(data, len, &env, &r) == SD_OK);
  sd_import_mark_duplicates(&r, fake_enum);
  SD_CHECK((find_cand(&r, "web")->flags & SD_IMPORT_F_DUPLICATE) != 0 && !find_cand(&r, "web")->selected);
  SD_CHECK((find_cand(&r, "bastion")->flags & SD_IMPORT_F_NAME_CHANGED) != 0);
  SD_CHECK_STR(find_cand(&r, "bastion")->p.name, "bastion (2)");
  /* write into a temporary configuration root */
  GetTempPathW(MAX_PATH, root);
  wcscat_s(root, MAX_PATH, L"sd-import-test");
  CreateDirectoryW(root, NULL);
  sd_config_set_root_override(root);
  SD_CHECK(sd_import_write(&r, &written) == SD_OK);
  SD_CHECK(written == r.count - 2);                          /* web and web-alias are duplicates */
  SD_CHECK(sd_profile_find("db", p, NULL, 0) == SD_OK);
  SD_CHECK_STR(p->jump, "bastion,admin@10.0.0.5:2222");
  SD_CHECK(sd_profile_find("web", p, NULL, 0) == SD_E_NOT_FOUND);
  for (i = 0; i < r.count; i++)
    if (r.items[i].selected) sd_profile_delete(r.items[i].p.name);
  sd_config_set_root_override(NULL);
  sd_import_result_free(&r);
  sd_free(data);
  sd_free(p);
}
