/* In-process service core (apps/shelldrive-host/service.c) with the scripted fake mount backend: no SCM, no elevation,
   no real drive. One core runs for the whole file (svc_run is process-wide); the tests share it in order and the last
   one stops it and checks that it left nothing behind.

   Clients: "testadmin" hellos get the test admin override (SD_SVC_TEST_HOOKS); every other client is checked for real.
   The restricted-token client impersonates a token with BUILTIN\Administrators disabled (CreateRestrictedToken), which
   is the non-admin case the pipe must refuse (03 §2.2). */
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "sd_test.h"
#include "host.h"
#include "service.h"
#include "sd_base/sd_json.h"
#include "sd_config/sd_config.h"
#include "sd_ipc/sd_ipc.h"
#include "sd_mount/sd_mount.h"
#include "sd_secret/sd_secret.h"
#include "sd_mount/sd_mount.h"
#include "svc_events.h"
#include "svc_repair.h"
#include "svc_scm.h"
#include "fake_backend.h"

/* Event Log sink of the shared core: records the ids in order (the core calls it on its own thread). */
#define T_EV_MAX 256
static DWORD g_ev_ids[T_EV_MAX];
static int g_ev_n;

static void test_event(void *ctx, DWORD msg_id, const wchar_t **args, size_t nargs)
{
  (void)ctx;
  (void)args;
  (void)nargs;
  if (g_ev_n < T_EV_MAX)
    g_ev_ids[g_ev_n++] = msg_id;
}

static int saw_event(DWORD msg_id)
{
  int i;
  for (i = 0; i < g_ev_n; i++) {
    if (g_ev_ids[i] == msg_id)
      return 1;
  }
  return 0;
}

/* Owner seams (svc_opts.owner_trusted): the fixture's folders are owned by this process, so the shared core trusts every
   owner; the start-refusal test trusts none and checks the refusal the shipping rule would give a foreign owner. */
static int owner_trust_all(void *ctx, PSID owner)
{
  (void)ctx;
  (void)owner;
  return 1;
}

static int owner_trust_none(void *ctx, PSID owner)
{
  (void)ctx;
  (void)owner;
  return 0;
}

#define T_ID_MOUNTED  "00000000000000000000000000000001"
#define T_ID_NOSUB    "00000000000000000000000000000002"
#define T_ID_TOFU     "00000000000000000000000000000003"
#define T_ID_PWPROMPT "00000000000000000000000000000004"
#define T_ID_PAGEANT  "00000000000000000000000000000005"
#define T_ID_ADMINONLY "00000000000000000000000000000006"
#define T_ID_HK_KNOWN  "0000000000000000000000000000000a"
#define T_ID_HK_CHANGED "0000000000000000000000000000000b"
#define T_ID_HK_FIRST  "0000000000000000000000000000000c"
#define T_ID_ROTATE    "0000000000000000000000000000000d"
static int make_chain_profiles(void);
#define T_ID_HOP1      "00000000000000000000000000000010"
#define T_ID_CHAIN     "00000000000000000000000000000011"
#define T_ID_HOPUSER   "00000000000000000000000000000012"
#define T_ID_CHAINUSER "00000000000000000000000000000013"
#define T_ID_PROXYPW   "00000000000000000000000000000014"
#define T_ID_PROXYSEC  "00000000000000000000000000000015"
#define T_ID_SYSPROXY  "00000000000000000000000000000016"
#define T_ID_SYSBASIC  "00000000000000000000000000000017"
#define T_ID_HKCHAIN   "00000000000000000000000000000018"
#define T_ID_WEBDAV    "00000000000000000000000000000019"
#define T_ID_WEBDAVDENY "0000000000000000000000000000001a"

/* proxy = system seam (svc_opts.sysproxy_ops): a stub machine configuration; the test changes allow to refuse by policy */
static svc_sysproxy_ops g_sysops;
static int g_sysread_calls;
static char g_sysread_host[256];

static sd_err test_sysproxy_read(void *ctx, const wchar_t *host, uint16_t port, int *kind, wchar_t *host_out,
                                 uint16_t *port_out)
{
  (void)ctx;
  (void)port;
  g_sysread_calls++;
  WideCharToMultiByte(CP_UTF8, 0, host, -1, g_sysread_host, (int)sizeof(g_sysread_host), NULL, NULL);
  *kind = SD_PROXY_HTTP;
  wcscpy_s(host_out, 256, L"machine.proxy.example");
  *port_out = 3128;
  return SD_OK;
}

static wchar_t g_root[MAX_PATH];
static HANDLE g_thread;
static HANDLE g_running;
static int g_started;
static int g_rc = -1;
static int g_core_ok;

/* ---- fixture ---- */

static void utf8_of(const wchar_t *w, char *out, size_t cch)
{
  WideCharToMultiByte(CP_UTF8, 0, w, -1, out, (int)cch, NULL, NULL);
  out[cch - 1] = 0;
}

static int write_file(const wchar_t *path, const char *data, size_t len)
{
  HANDLE h = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  DWORD n = 0;
  BOOL ok;
  if (h == INVALID_HANDLE_VALUE)
    return 0;
  ok = WriteFile(h, data, (DWORD)len, &n, NULL);
  CloseHandle(h);
  return ok && n == len;
}

static int write_profile(const wchar_t *file, const sd_profile *p)
{
  sd_ini *ini = NULL;
  sd_wr w;
  wchar_t path[MAX_PATH];
  int ok = 0;
  _snwprintf_s(path, MAX_PATH, _TRUNCATE, L"%s\\profiles\\%s", g_root, file);
  sd_wr_init(&w, 4096);
  if (sd_profile_to_ini(p, &ini) == SD_OK && sd_ini_serialize(ini, &w) == SD_OK)
    ok = write_file(path, (const char *)w.p, w.len);
  sd_ini_free(ini);
  sd_wr_free(&w);
  return ok;
}

static sd_profile base_profile(const char *id, const char *name, const char *host)
{
  sd_profile p;
  sd_profile_defaults(&p);
  p.scope = SD_PROFILE_SCOPE_SERVICE;
  strcpy_s(p.id, sizeof(p.id), id);
  strcpy_s(p.name, sizeof(p.name), name);
  strcpy_s(p.host, sizeof(p.host), host);
  strcpy_s(p.user, sizeof(p.user), "svc");
  strcpy_s(p.service_access, sizeof(p.service_access), "S-1-1-0");   /* Everyone: every token has it */
  p.auth_methods = SD_PROFILE_AUTH_PUBLICKEY | SD_PROFILE_AUTH_PASSWORD;
  p.agent = SD_PROFILE_AGENT_AUTO;
  return p;
}

static void identity_of(sd_profile *p)
{
  char utf8[MAX_PATH * 3];
  wchar_t w[MAX_PATH];
  _snwprintf_s(w, MAX_PATH, _TRUNCATE, L"%s\\service\\keys\\key1.ppk", g_root);
  utf8_of(w, utf8, sizeof(utf8));
  strcpy_s(p->identity, sizeof(p->identity), utf8);
}

static int make_fixture(void)
{
  sd_profile p;
  wchar_t d[MAX_PATH];
  wchar_t tmp[MAX_PATH];
  LARGE_INTEGER qpc;
  DWORD n = GetTempPathW(MAX_PATH, tmp);
  if (!(n > 0 && n < MAX_PATH)) return 0;
  QueryPerformanceCounter(&qpc);
  _snwprintf_s(g_root, MAX_PATH, _TRUNCATE, L"%ssdsvc-%lu-%lu", tmp, (unsigned long)GetCurrentProcessId(),
               (unsigned long)qpc.LowPart);
  if (!CreateDirectoryW(g_root, NULL)) return 0;
  _snwprintf_s(d, MAX_PATH, _TRUNCATE, L"%s\\profiles", g_root);
  if (!CreateDirectoryW(d, NULL)) return 0;
  _snwprintf_s(d, MAX_PATH, _TRUNCATE, L"%s\\service", g_root);
  if (!CreateDirectoryW(d, NULL)) return 0;
  _snwprintf_s(d, MAX_PATH, _TRUNCATE, L"%s\\service\\keys", g_root);
  if (!CreateDirectoryW(d, NULL)) return 0;
  /* the key file the identity profiles name: the start reads it through a checked handle (TM-R27) */
  _snwprintf_s(d, MAX_PATH, _TRUNCATE, L"%s\\service\\keys\\key1.ppk", g_root);
  if (!write_file(d, "fixture-key", 11)) return 0;
  _snwprintf_s(d, MAX_PATH, _TRUNCATE, L"%s\\service\\secrets", g_root);
  if (!CreateDirectoryW(d, NULL)) return 0;
  _snwprintf_s(d, MAX_PATH, _TRUNCATE, L"%s\\logs", g_root);
  if (!CreateDirectoryW(d, NULL)) return 0;

  p = base_profile(T_ID_MOUNTED, "mounted", "trusted.example");
  identity_of(&p);
  if (!write_profile(L"a-mounted.ini", &p)) return 0;

  p = base_profile(T_ID_NOSUB, "nosub", "pw.example");
  if (!write_profile(L"b-nosub.ini", &p)) return 0;

  p = base_profile(T_ID_TOFU, "tofu", "unknown.example");
  if (!write_profile(L"c-tofu.ini", &p)) return 0;

  p = base_profile(T_ID_PWPROMPT, "pwprompt", "pw2.example");
  if (!write_profile(L"d-pwprompt.ini", &p)) return 0;

  p = base_profile(T_ID_PAGEANT, "pageant", "trusted.example");
  p.agent = SD_PROFILE_AGENT_PAGEANT;                       /* D17: refused at load */
  if (!write_profile(L"e-pageant.ini", &p)) return 0;

  p = base_profile(T_ID_ADMINONLY, "adminonly", "trusted3.example");
  identity_of(&p);
  strcpy_s(p.service_access, sizeof(p.service_access), "S-1-5-32-544");   /* BUILTIN\Administrators only */
  if (!write_profile(L"f-adminonly.ini", &p)) return 0;

  p = base_profile("00000000000000000000000000000009", "userdrive", "x.example");
  p.scope = SD_PROFILE_SCOPE_USER;
  p.service_access[0] = 0;
  if (!write_profile(L"g-user.ini", &p)) return 0;

  /* M5 hostkey add: the hk.* hosts are scripted by name (the hostkey connection of fake_backend_hostkeys) */
  p = base_profile(T_ID_HK_KNOWN, "hkknown", "hk.known.test");
  identity_of(&p);
  if (!write_profile(L"h-hkknown.ini", &p)) return 0;

  p = base_profile(T_ID_HK_CHANGED, "hkchanged", "hk.changed.test");
  identity_of(&p);
  if (!write_profile(L"i-hkchanged.ini", &p)) return 0;

  p = base_profile(T_ID_HK_FIRST, "hkfirst", "hk.first.test");
  identity_of(&p);
  if (!write_profile(L"j-hkfirst.ini", &p)) return 0;

  /* M5 announcements: a mount of rotate.example raises one UpdateHostKeys announcement after it is ready */
  p = base_profile(T_ID_ROTATE, "rotate", "rotate.example");
  identity_of(&p);
  if (!write_profile(L"k-rotate.ini", &p)) return 0;

  if (!make_chain_profiles()) return 0;
  fake_backend_pre_trust("trusted.example");
  fake_backend_pre_trust("trusted3.example");
  fake_backend_pre_trust("pw.example");
  fake_backend_pre_trust("pw2.example");
  fake_backend_pre_trust("rotate.example");
  fake_backend_pre_trust("hop1.trusted.example");
  fake_backend_pre_trust("hop2.trusted.example");
  return 1;
}

/* M5 chains and proxies: the jump hosts and the leg proxies of the service profiles below. Every profile has the
   service identity, so the target authenticates with its key blob and no password prompt is raised. */
static int make_chain_profiles(void)
{
  sd_profile p;
  p = base_profile(T_ID_HOP1, "hop1", "hop1.trusted.example");
  identity_of(&p);
  if (!write_profile(L"l-hop1.ini", &p)) return 0;

  p = base_profile(T_ID_CHAIN, "chain", "trusted.example");
  identity_of(&p);
  strcpy_s(p.jump, sizeof(p.jump), "hop1");
  if (!write_profile(L"m-chain.ini", &p)) return 0;

  /* a jump to a profile whose identity is a user path: refused at mount time (TM-R27) */
  p = base_profile(T_ID_HOPUSER, "hopuser", "hop2.trusted.example");
  strcpy_s(p.identity, sizeof(p.identity), "%USERPROFILE%\\.ssh\\id_ed25519");
  if (!write_profile(L"n-hopuser.ini", &p)) return 0;

  p = base_profile(T_ID_CHAINUSER, "chainuser", "trusted.example");
  identity_of(&p);
  strcpy_s(p.jump, sizeof(p.jump), "hopuser");
  if (!write_profile(L"o-chainuser.ini", &p)) return 0;

  /* a basic proxy leg with a user: needs a proxy secret in the service store */
  p = base_profile(T_ID_PROXYPW, "proxypw", "trusted.example");
  identity_of(&p);
  if (sd_proxy_spec_parse("http://pu@proxy.example:3128", &p.proxy[0]) != SD_OK) return 0;
  p.proxy_auth[0] = SD_PROFILE_PROXY_AUTH_BASIC;
  if (!write_profile(L"p-proxypw.ini", &p)) return 0;

  p = base_profile(T_ID_PROXYSEC, "proxysec", "trusted.example");
  identity_of(&p);
  if (sd_proxy_spec_parse("http://pu@proxy.example:3128", &p.proxy[0]) != SD_OK) return 0;
  p.proxy_auth[0] = SD_PROFILE_PROXY_AUTH_BASIC;
  if (!write_profile(L"q-proxysec.ini", &p)) return 0;

  /* proxy = system: the machine configuration through the seam; with basic it is refused */
  p = base_profile(T_ID_SYSPROXY, "sysproxy", "trusted.example");
  identity_of(&p);
  p.proxy[0].kind = SD_PROFILE_PROXY_SYSTEM;
  if (!write_profile(L"r-sysproxy.ini", &p)) return 0;

  p = base_profile(T_ID_SYSBASIC, "sysbasic", "trusted.example");
  identity_of(&p);
  p.proxy[0].kind = SD_PROFILE_PROXY_SYSTEM;
  p.proxy_auth[0] = SD_PROFILE_PROXY_AUTH_BASIC;
  if (!write_profile(L"s-sysbasic.ini", &p)) return 0;

  /* hostkey add through a jump host whose key is not in the machine store: never accepted (2.6 rule 2) */
  p = base_profile(T_ID_HKCHAIN, "hkchain", "hkchain.known.test");
  identity_of(&p);
  strcpy_s(p.jump, sizeof(p.jump), "hkjump.untrusted.test");
  if (!write_profile(L"t-hkchain.ini", &p)) return 0;

  /* 02 §7.7 attach: a global WebDAV profile (hosted by the service, mapped per user) and one whose service_access
     names nobody this test can be (the attach reply must refuse it) */
  p = base_profile(T_ID_WEBDAV, "webdav", "webdav.example");
  identity_of(&p);
  p.backend = SD_PROFILE_BACKEND_WEBDAV;
  if (!write_profile(L"u-webdav.ini", &p)) return 0;
  fake_backend_pre_trust("webdav.example");

  p = base_profile(T_ID_WEBDAVDENY, "webdavdeny", "webdav.example");
  identity_of(&p);
  p.backend = SD_PROFILE_BACKEND_WEBDAV;
  strcpy_s(p.service_access, sizeof(p.service_access), "S-1-5-21-1-2-3-4");   /* valid SID, matches no token */
  if (!write_profile(L"v-webdavdeny.ini", &p)) return 0;
  return 1;
}

static void on_running(void *ctx)
{
  (void)ctx;
  SetEvent(g_running);
}

static DWORD WINAPI core_main(LPVOID arg)
{
  svc_opts *o = (svc_opts *)arg;
  g_rc = svc_run(o);
  return 0;
}

/* SCM seam of service.status (svc_opts.scm_ops): a running, automatic service with no Event Log source. The real SCM is
   never reached. */
static DWORD t_query_service(void *ctx, svc_status_report *out)
{
  (void)ctx;
  out->installed = 1;
  out->state = SERVICE_RUNNING;
  out->start_type = SERVICE_AUTO_START;
  wcscpy_s(out->binary, SD_COUNTOF(out->binary), L"\"C:\\fake\\shelldrive-host.exe\" service");
  return 0;
}

static DWORD t_query_source(void *ctx, const wchar_t *source, wchar_t *message_file, size_t cch)
{
  (void)ctx;
  (void)source;
  (void)message_file;
  (void)cch;
  return ERROR_FILE_NOT_FOUND;
}

static svc_scm_ops g_fake_scm;
static svc_repair_ops g_repair_ops;
static wchar_t g_repair_base[MAX_PATH];

/* Starts the core once, with a unique pipe name, the test owner SID and the fake backend. */
static int ensure_core(void)
{
  static svc_opts o;
  wchar_t sid[256], suffix[64];
  if (g_started)
    return g_core_ok;
  g_started = 1;
  if (!make_fixture()) { g_core_ok = 0; return 0; }
  if (sd_ipc_current_identity(sid, SD_COUNTOF(sid), NULL) != SD_OK) return 0;
  _snwprintf_s(suffix, SD_COUNTOF(suffix), _TRUNCATE, L"svc%lu", (unsigned long)GetCurrentProcessId());
  sd_ipc_set_instance_suffix(suffix);
  sd_ipc_test_set_expected_owner(sid);
  sd_ipc_test_set_service_owner(sid);
  memset(&o, 0, sizeof(o));
  o.backend = fake_backend_hostkeys();            /* the fake table plus the hostkey connection (M5) */
  o.machine_root = g_root;
  o.open_log = 0;
  o.on_running = on_running;
  o.test_all_admin = 1;
  o.owner_trusted = owner_trust_all;
  o.dacl_extra_ace = L"(A;OICI;FA;;;OW)";   /* the test process is only the owner of its folders (see svc_opts) */
  o.event = test_event;
  o.event_ctx = NULL;
  memset(&g_fake_scm, 0, sizeof(g_fake_scm));
  g_fake_scm.query_service = t_query_service;
  g_fake_scm.query_source = t_query_source;
  o.scm_ops = &g_fake_scm;
  /* service.repair_data works on a base folder of its own, never %ProgramData% */
  memset(&g_repair_ops, 0, sizeof(g_repair_ops));
  g_repair_ops.owner_trusted = owner_trust_all;
  g_repair_ops.extra_ace = L"(A;OICI;FA;;;OW)";
  o.repair_ops = &g_repair_ops;
  _snwprintf_s(g_repair_base, MAX_PATH, _TRUNCATE, L"%s-repair", g_root);
  if (!CreateDirectoryW(g_repair_base, NULL)) return 0;
  o.repair_base = g_repair_base;
  /* proxy = system never reads the real WinHTTP configuration in a test: the stub answers, the policy is on */
  g_sysops.allow = 1;
  g_sysops.read = test_sysproxy_read;
  g_sysops.ctx = NULL;
  o.sysproxy_ops = &g_sysops;
  g_running = CreateEventW(NULL, TRUE, FALSE, NULL);
  g_thread = CreateThread(NULL, 0, core_main, &o, 0, NULL);
  if (g_thread == NULL || g_running == NULL)
    return 0;
  g_core_ok = WaitForSingleObject(g_running, 15000) == WAIT_OBJECT_0;
  return g_core_ok;
}

/* ---- clients ---- */

static sd_err connect_as(const char *kind, uint32_t caps, sd_ipc_conn **out)
{
  sd_ipc_hello h;
  memset(&h, 0, sizeof(h));
  h.client_kind = kind;
  h.client_version = "test";
  h.lang = "en";
  h.caps = caps;
  return sd_ipc_connect(SD_IPC_SERVICE, &h, 0, 10000, out);
}

/* A token with BUILTIN\Administrators disabled (deny-only): the same user, not an admin for the pipe. */
static HANDLE restricted_token(void)
{
  HANDLE tok = NULL, rt = NULL;
  SID_IDENTIFIER_AUTHORITY nt = SECURITY_NT_AUTHORITY;
  PSID admins = NULL;
  SID_AND_ATTRIBUTES disable;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY, &tok))
    return NULL;
  if (AllocateAndInitializeSid(&nt, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0,
                               &admins)) {
    disable.Sid = admins;
    disable.Attributes = 0;
    if (!CreateRestrictedToken(tok, DISABLE_MAX_PRIVILEGE, 1, &disable, 0, NULL, 0, NULL, &rt))
      rt = NULL;
    FreeSid(admins);
  }
  CloseHandle(tok);
  return rt;
}

/* Connects while impersonating the restricted token (the pipe takes the thread's identity at connect time). */
static sd_err connect_restricted(sd_ipc_conn **out, int *has_token)
{
  HANDLE rt = restricted_token();
  sd_err e;
  *has_token = rt != NULL;
  if (rt == NULL)
    return SD_E_ACCESS_DENIED;
  if (!ImpersonateLoggedOnUser(rt)) {
    CloseHandle(rt);
    return SD_E_ACCESS_DENIED;
  }
  e = connect_as("testuser", 0, out);
  RevertToSelf();
  CloseHandle(rt);
  return e;
}

static sd_json *call(sd_ipc_conn *c, const char *method, const char *params, sd_ipc_error *err, sd_err *rc)
{
  sd_json *res = NULL;
  sd_err e;
  memset(err, 0, sizeof(*err));
  e = sd_ipc_call_raw(c, method, params, params ? strlen(params) : 0, 10000, &res, err);
  if (rc)
    *rc = e;
  return res;
}

/* Waits (up to timeout_ms) until status reports `want` for the mount; returns the last status object. */
static int wait_state(sd_ipc_conn *c, const char *mount_id, const char *want, uint32_t timeout_ms, sd_json **last)
{
  char params[128];
  uint32_t waited = 0;
  _snprintf_s(params, sizeof(params), _TRUNCATE, "{\"mount_id\":\"%s\"}", mount_id);
  for (;;) {
    sd_ipc_error err;
    sd_err e;
    sd_json *res = call(c, "status", params, &err, &e);
    if (res) {
      const char *st = sd_json_get_str(res, "state");
      int hit = st != NULL && strcmp(st, want) == 0;   /* compared before res is freed: st points into it */
      if (last) {
        if (*last) sd_json_free(*last);
        *last = res;
      } else {
        sd_json_free(res);
      }
      if (hit)
        return 1;
    } else if (strcmp(err.code, "not_mounted") == 0 && strcmp(want, "gone") == 0) {
      return 1;
    }
    if (waited >= timeout_ms)
      return 0;
    Sleep(100);
    waited += 100;
  }
}

/* Frees a status reply kept by wait_state and clears the pointer, so a later wait_state(..., &st) never frees it
   twice. */
static void json_drop(sd_json **j)
{
  if (*j != NULL) {
    sd_json_free(*j);
    *j = NULL;
  }
}

static sd_json *mount_profile(sd_ipc_conn *c, const char *profile, sd_ipc_error *err, sd_err *rc)
{
  char params[160];
  _snprintf_s(params, sizeof(params), _TRUNCATE, "{\"profile\":\"%s\"}", profile);
  return call(c, "mount", params, err, rc);
}

static int unmount_id(sd_ipc_conn *c, const char *mount_id)
{
  char params[128];
  sd_ipc_error err;
  sd_err e;
  sd_json *res;
  _snprintf_s(params, sizeof(params), _TRUNCATE, "{\"mount_id\":\"%s\",\"force\":true}", mount_id);
  res = call(c, "unmount", params, &err, &e);
  {
    int ok = res != NULL;
    if (res) sd_json_free(res);
    return ok;
  }
}

static void copy_str(char *dst, size_t cap, const char *src)
{
  strcpy_s(dst, cap, src ? src : "");
}

/* ---- tests ---- */

SD_TEST(svc_core_starts_and_answers_hello_and_selftest)
{
  sd_ipc_conn *c = NULL;
  sd_ipc_error err;
  sd_err e;
  sd_json *res;
  SD_REQUIRE(ensure_core());
  e = connect_as("testadmin", SD_IPC_CAP_PROMPTS_UI, &c);
  SD_REQUIRE(e == SD_OK);
  SD_CHECK(sd_ipc_conn_has_feature(c, "mount"));
  SD_CHECK(sd_ipc_conn_has_feature(c, "prompt.routing"));
  res = call(c, "selftest", NULL, &err, &e);
  SD_REQUIRE(res != NULL);
  {
    int healthy = 0;
    SD_CHECK(sd_json_get_bool(res, "healthy", &healthy) && healthy);
  }
  sd_json_free(res);
  sd_ipc_close(c);
}

SD_TEST(svc_loads_only_valid_service_profiles)
{
  sd_ipc_conn *c = NULL;
  sd_ipc_error err;
  sd_err e;
  sd_json *res;
  const sd_json *loaded;
  SD_REQUIRE(ensure_core());
  SD_REQUIRE(connect_as("testadmin", 0, &c) == SD_OK);
  /* 20 valid: mounted, nosub, tofu, pwprompt, adminonly, the M5 hostkey and rotate profiles, the M5 chain and proxy
     profiles and the two global WebDAV profiles (a chain is checked per hop at mount time, not at load). Refused:
     pageant (D17). Not loaded: the user profile. */
  res = call(c, "config.reload", NULL, &err, &e);
  SD_REQUIRE(res != NULL);
  loaded = sd_json_get(res, "profiles");
  {
    int64_t n = -1;
    SD_CHECK(sd_json_get_int64(loaded, "loaded", &n));
    SD_CHECK_EQ_INT(n, 20);
  }
  sd_json_free(res);
  sd_ipc_close(c);
}

SD_TEST(svc_non_admin_token_cannot_call_admin_methods)
{
  sd_ipc_conn *c = NULL;
  sd_ipc_error err;
  sd_err e;
  sd_json *res;
  int has_token = 0;
  SD_REQUIRE(ensure_core());
  e = connect_restricted(&c, &has_token);
  if (e != SD_OK) {
    /* the interactive-user ACE of the pipe may be absent in a service session; the refusal then happens at connect */
    SD_CHECK(has_token == 0 || e == SD_E_ACCESS_DENIED || e == SD_E_CONN_REFUSED || e == SD_E_BUSY);
    return;
  }
  res = mount_profile(c, "mounted", &err, &e);
  SD_CHECK(res == NULL);
  SD_CHECK_STR(err.code, "access_denied");
  res = call(c, "unmount", "{\"target\":\"Z:\"}", &err, &e);
  SD_CHECK(res == NULL);
  SD_CHECK_STR(err.code, "access_denied");
  res = call(c, "secret.set", "{\"profile\":\"mounted\",\"kind\":\"password\",\"value\":\"x\"}", &err, &e);
  SD_CHECK(res == NULL);
  SD_CHECK_STR(err.code, "access_denied");
  res = call(c, "config.reload", NULL, &err, &e);
  SD_CHECK(res == NULL);
  SD_CHECK_STR(err.code, "access_denied");
  res = call(c, "prompt.list", NULL, &err, &e);
  SD_CHECK(res == NULL);
  SD_CHECK_STR(err.code, "access_denied");
  /* the topic gate: prompt needs an elevated admin, mount is open */
  res = call(c, "subscribe", "{\"topics\":[\"prompt\"]}", &err, &e);
  SD_CHECK(res == NULL);
  SD_CHECK_STR(err.code, "access_denied");
  res = call(c, "subscribe", "{\"topics\":[\"mount\"]}", &err, &e);
  SD_CHECK(res != NULL);
  if (res) sd_json_free(res);
  sd_ipc_close(c);
}

SD_TEST(svc_admin_mounts_reports_and_unmounts)
{
  sd_ipc_conn *c = NULL;
  sd_ipc_error err;
  sd_err e;
  sd_json *res, *st = NULL;
  char mid[16];
  SD_REQUIRE(ensure_core());
  SD_REQUIRE(connect_as("testadmin", 0, &c) == SD_OK);
  res = mount_profile(c, "mounted", &err, &e);
  SD_REQUIRE(res != NULL);
  copy_str(mid, sizeof(mid), sd_json_get_str(res, "mount_id"));
  sd_json_free(res);
  SD_CHECK(mid[0] != 0);
  SD_CHECK(wait_state(c, mid, "mounted", 10000, &st));
  /* M5, Event 1200 (03 10.3): a change raised by the vfs reaches the Event Log seam as SVC_MSG_AUDIT. The fake vfs
     posts it to the control thread, so the test waits for it; the real Event Log is never written here. */
  {
    static const unsigned char k_sid[] = { 1, 5, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 0xE9, 3, 0, 0 };
    int i;
    fake_backend_vfs_audit(L"\\docs\\a.txt", "create", (PSID)(void *)k_sid);
    for (i = 0; i < 100 && !saw_event(SVC_MSG_AUDIT); i++)
      Sleep(50);
    SD_CHECK(saw_event(SVC_MSG_AUDIT));
  }
  if (st) {
    SD_CHECK(sd_json_get_str(st, "host") != NULL);     /* admins see the details */
    sd_json_free(st);
    st = NULL;
  }

  /* a second mount of the same profile is refused while it is up */
  res = mount_profile(c, "mounted", &err, &e);
  SD_CHECK(res == NULL);
  SD_CHECK_STR(err.code, "already_mounted");
  /* list shows it with its state */
  res = call(c, "list", NULL, &err, &e);
  SD_REQUIRE(res != NULL);
  SD_CHECK(sd_json_get(res, "mounts") != NULL && sd_json_count(sd_json_get(res, "mounts")) >= 1);
  sd_json_free(res);
  SD_CHECK(unmount_id(c, mid));
  SD_CHECK(wait_state(c, mid, "gone", 10000, NULL));
  sd_ipc_close(c);
}

SD_TEST(svc_mount_without_prompt_ui_fails_with_prompt_unavailable)
{
  sd_ipc_conn *c = NULL;
  sd_ipc_error err;
  sd_err e;
  sd_json *res, *st = NULL;
  char mid[16];
  SD_REQUIRE(ensure_core());
  SD_REQUIRE(connect_as("testadmin", 0, &c) == SD_OK);   /* no prompts.ui: nobody can answer */
  res = mount_profile(c, "nosub", &err, &e);
  SD_REQUIRE(res != NULL);
  copy_str(mid, sizeof(mid), sd_json_get_str(res, "mount_id"));
  sd_json_free(res);
  SD_CHECK(wait_state(c, mid, "failed", 10000, &st));
  if (st) {
    const sd_json *le = sd_json_get(st, "last_error");
    SD_CHECK(le != NULL);
    SD_CHECK_STR(sd_json_get_str(le, "code"), "prompt_unavailable");
    sd_json_free(st);
    st = NULL;
  }
  /* a failed mount keeps its record until the user unmounts it (1.11) */
  SD_CHECK(unmount_id(c, mid));
  SD_CHECK(wait_state(c, mid, "gone", 10000, NULL));
  sd_ipc_close(c);
}

SD_TEST(svc_host_key_prompt_is_refused_even_with_an_admin_ui)
{
  sd_ipc_conn *c = NULL;
  sd_ipc_error err;
  sd_err e;
  sd_json *res, *st = NULL;
  char mid[16];
  SD_REQUIRE(ensure_core());
  SD_REQUIRE(connect_as("testadmin", SD_IPC_CAP_PROMPTS_UI, &c) == SD_OK);
  res = call(c, "subscribe", "{\"topics\":[\"prompt\",\"mount\"]}", &err, &e);
  SD_REQUIRE(res != NULL);
  sd_json_free(res);
  res = mount_profile(c, "tofu", &err, &e);
  SD_REQUIRE(res != NULL);
  copy_str(mid, sizeof(mid), sd_json_get_str(res, "mount_id"));
  sd_json_free(res);
  SD_CHECK(wait_state(c, mid, "failed", 10000, &st));
  if (st) {
    /* 2.6 rule 2: no trust on first use for the service */
    SD_CHECK_STR(sd_json_get_str(sd_json_get(st, "last_error"), "code"), "host_key_unknown");
    sd_json_free(st);
    st = NULL;
  }
  SD_CHECK(unmount_id(c, mid));
  SD_CHECK(wait_state(c, mid, "gone", 10000, NULL));
  sd_ipc_close(c);
}

/* Waits for an attention event carrying exactly `want` on this connection (a content-free count, 2.6 rule 3). */
static int wait_attention(sd_ipc_conn *w, int64_t want)
{
  int i;
  for (i = 0; i < 100; i++) {
    sd_json *ev = NULL;
    if (sd_ipc_next_event(w, 200, &ev) == SD_OK && ev) {
      const char *name = sd_json_get_str(ev, "event");
      const sd_json *data = sd_json_get(ev, "data");
      int64_t n = -1;
      if (name && strcmp(name, "attention") == 0 && data && sd_json_get_int64(data, "count", &n) && n == want) {
        sd_json_free(ev);
        return 1;
      }
      sd_json_free(ev);
    }
  }
  return 0;
}

SD_TEST(svc_attention_counts_the_open_prompts)
{
  sd_ipc_conn *w = NULL, *c = NULL;
  sd_ipc_error err;
  sd_err e;
  sd_json *res, *st = NULL, *list;
  char mid[16], pid[24] = "";
  const sd_json *first;
  SD_REQUIRE(ensure_core());
  /* a plain client (not an admin) may watch the attention topic; it gets the count at once and on every change */
  SD_REQUIRE(connect_as("ui", 0, &w) == SD_OK);
  res = call(w, "subscribe", "{\"topics\":[\"attention\"]}", &err, &e);
  SD_REQUIRE(res != NULL);
  sd_json_free(res);
  SD_REQUIRE(wait_attention(w, 0));
  SD_REQUIRE(connect_as("testadmin", SD_IPC_CAP_PROMPTS_UI, &c) == SD_OK);
  res = call(c, "subscribe", "{\"topics\":[\"prompt\",\"mount\"]}", &err, &e);
  SD_REQUIRE(res != NULL);
  sd_json_free(res);
  res = mount_profile(c, "pwprompt", &err, &e);
  SD_REQUIRE(res != NULL);
  copy_str(mid, sizeof(mid), sd_json_get_str(res, "mount_id"));
  sd_json_free(res);
  SD_CHECK(wait_attention(w, 1));
  /* prompt.list carries the request fields, so an admin UI that connects late can show the dialog */
  list = call(c, "prompt.list", NULL, &err, &e);
  SD_REQUIRE(list != NULL);
  first = sd_json_at(sd_json_get(list, "prompts"), 0);
  SD_REQUIRE(first != NULL);
  SD_CHECK_STR(sd_json_get_str(first, "kind"), "password");
  copy_str(pid, sizeof(pid), sd_json_get_str(first, "prompt_id"));
  sd_json_free(list);
  {
    char params[256];
    _snprintf_s(params, sizeof(params), _TRUNCATE,
                "{\"prompt_id\":\"%s\",\"action\":\"accept\",\"responses\":[\"secret\"]}", pid);
    res = call(c, "prompt.answer", params, &err, &e);
    SD_REQUIRE(res != NULL);
    sd_json_free(res);
  }
  SD_CHECK(wait_attention(w, 0));
  SD_CHECK(wait_state(c, mid, "mounted", 10000, &st));
  json_drop(&st);
  SD_CHECK(unmount_id(c, mid));
  SD_CHECK(wait_state(c, mid, "gone", 10000, NULL));
  sd_ipc_close(c);
  sd_ipc_close(w);
}

SD_TEST(svc_admin_answers_a_password_prompt_on_the_pipe)
{
  sd_ipc_conn *c = NULL;
  sd_ipc_error err;
  sd_err e;
  sd_json *res, *st = NULL;
  char mid[16], pid[24] = "";
  int got = 0, i;
  SD_REQUIRE(ensure_core());
  SD_REQUIRE(connect_as("testadmin", SD_IPC_CAP_PROMPTS_UI, &c) == SD_OK);
  res = call(c, "subscribe", "{\"topics\":[\"prompt\",\"mount\"]}", &err, &e);
  SD_REQUIRE(res != NULL);
  sd_json_free(res);
  res = mount_profile(c, "pwprompt", &err, &e);
  SD_REQUIRE(res != NULL);
  copy_str(mid, sizeof(mid), sd_json_get_str(res, "mount_id"));
  sd_json_free(res);
  /* the prompt arrives as an event on the prompt topic */
  for (i = 0; i < 100 && !got; i++) {
    sd_json *ev = NULL;
    if (sd_ipc_next_event(c, 200, &ev) == SD_OK && ev) {
      const char *name = sd_json_get_str(ev, "event");
      if (name && strcmp(name, "prompt.request") == 0) {
        const sd_json *data = sd_json_get(ev, "data");
        const char *k = sd_json_get_str(data, "kind");
        SD_CHECK_STR(k, "password");
        copy_str(pid, sizeof(pid), sd_json_get_str(data, "prompt_id"));
        got = pid[0] != 0;
      }
      sd_json_free(ev);
    }
  }
  SD_REQUIRE(got);
  {
    char params[256];
    _snprintf_s(params, sizeof(params), _TRUNCATE,
                "{\"prompt_id\":\"%s\",\"action\":\"accept\",\"responses\":[\"secret\"]}", pid);
    res = call(c, "prompt.answer", params, &err, &e);
    SD_REQUIRE(res != NULL);
    sd_json_free(res);
  }
  SD_CHECK(wait_state(c, mid, "mounted", 10000, &st));
  json_drop(&st);
  SD_CHECK(unmount_id(c, mid));
  SD_CHECK(wait_state(c, mid, "gone", 10000, NULL));
  sd_ipc_close(c);
}

SD_TEST(svc_secret_round_trip_is_dpapi_service_scope)
{
  sd_ipc_conn *c = NULL;
  sd_ipc_error err;
  sd_err e;
  sd_json *res;
  char target[SD_SECRET_MAX_TARGET];
  sd_secbuf *b = NULL;
  SD_REQUIRE(ensure_core());
  SD_REQUIRE(connect_as("testadmin", 0, &c) == SD_OK);
  res = call(c, "secret.set", "{\"profile\":\"mounted\",\"kind\":\"password\",\"value\":\"topsecret\"}", &err, &e);
  SD_REQUIRE(res != NULL);
  sd_json_free(res);
  SD_REQUIRE(sd_secret_target_password("svc", "trusted.example", 22, target, sizeof(target)) == SD_OK);
  SD_REQUIRE(sd_secret_get(SD_SECRET_SERVICE, SD_SECRET_PASSWORD, target, &b) == SD_OK);
  SD_CHECK(b->len == strlen("topsecret") && memcmp(b->p, "topsecret", b->len) == 0);
  sd_secbuf_free(b);
  /* the user scope never sees it */
  SD_CHECK(sd_secret_get(SD_SECRET_USER, SD_SECRET_PASSWORD, target, &b) == SD_E_NOT_FOUND);
  res = call(c, "secret.delete", "{\"profile\":\"mounted\",\"kind\":\"password\"}", &err, &e);
  SD_REQUIRE(res != NULL);
  sd_json_free(res);
  res = call(c, "secret.delete", "{\"profile\":\"mounted\",\"kind\":\"password\"}", &err, &e);
  SD_CHECK(res == NULL);
  SD_CHECK_STR(err.code, "secret_not_found");
  sd_ipc_close(c);
}

SD_TEST(svc_list_hides_mounts_outside_service_access_from_users)
{
  sd_ipc_conn *admin = NULL, *user = NULL;
  sd_ipc_error err;
  sd_err e;
  sd_json *res, *st = NULL;
  char mid[16], letter[4] = "";
  int i, hidden = 1;
  int has_token = 0;
  SD_REQUIRE(ensure_core());
  SD_REQUIRE(connect_as("testadmin", 0, &admin) == SD_OK);
  res = mount_profile(admin, "adminonly", &err, &e);
  SD_REQUIRE(res != NULL);
  copy_str(mid, sizeof(mid), sd_json_get_str(res, "mount_id"));
  copy_str(letter, sizeof(letter), sd_json_get_str(res, "target"));
  sd_json_free(res);
  SD_CHECK(wait_state(admin, mid, "mounted", 10000, &st));
  json_drop(&st);

  e = connect_restricted(&user, &has_token);
  if (e != SD_OK) {
    /* the pipe refused the restricted token before any method (see the admin-method test) */
    (void)unmount_id(admin, mid);
    sd_ipc_close(admin);
    return;
  }
  res = call(user, "list", NULL, &err, &e);
  SD_REQUIRE(res != NULL);
  {
    const sd_json *mounts = sd_json_get(res, "mounts");
    for (i = 0; mounts && i < (int)sd_json_count(mounts); i++) {
      const char *got = sd_json_get_str(sd_json_at(mounts, i), "mount_id");
      if (got && strcmp(got, mid) == 0)
        hidden = 0;
    }
    /* the letter still shows, as a reserved letter (2.2) */
    {
      const sd_json *rl = sd_json_get(res, "reserved_letters");
      int found = 0;
      for (i = 0; rl && i < (int)sd_json_count(rl); i++) {
        const char *s = sd_json_str(sd_json_at(rl, i), NULL);
        if (s && s[0] == letter[0]) found = 1;
      }
      SD_CHECK(found);
    }
  }
  SD_CHECK(hidden);
  sd_json_free(res);
  /* a user asking for the details of that drive is refused */
  res = call(user, "status", "{\"profile\":\"adminonly\"}", &err, &e);
  SD_CHECK(res == NULL);
  SD_CHECK_STR(err.code, "access_denied");
  sd_ipc_close(user);
  SD_CHECK(unmount_id(admin, mid));
  SD_CHECK(wait_state(admin, mid, "gone", 10000, NULL));
  sd_ipc_close(admin);
}

/* Event 3101 count so far (the sink records ids in order). */
static int count_event(DWORD id)
{
  int i, n = 0;
  for (i = 0; i < g_ev_n; i++)
    if (g_ev_ids[i] == id)
      n++;
  return n;
}

/* A raw connection to the service pipe that never sends hello: it holds an instance and nothing else. */
static int open_raw_instance(HANDLE *out)
{
  wchar_t sid[256], name[512];
  DWORD session = 0;
  HANDLE h = INVALID_HANDLE_VALUE;
  int tries;
  *out = INVALID_HANDLE_VALUE;
  if (sd_ipc_current_identity(sid, SD_COUNTOF(sid), &session) != SD_OK)
    return 0;
  if (sd_ipc_pipe_name(SD_IPC_SERVICE, sid, session, name, SD_COUNTOF(name)) != SD_OK)
    return 0;
  for (tries = 0; tries < 100 && h == INVALID_HANDLE_VALUE; tries++) {
    h = CreateFileW(name, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE)
      WaitNamedPipeW(name, 100);
  }
  *out = h;
  return h != INVALID_HANDLE_VALUE;
}

/* 2.2, TM-R25: the request cap is 64 KiB for clients that are not elevated admins and 1 MiB for admins; the same
   100 KiB request is refused for the restricted token and accepted for the admin. Two of the 32 instances stay free
   for admins: with 30 held by other clients, a restricted client is refused at hello and the admin still connects.
   Event 3101 is written once for the SID in the window. All clients share this process's SID (the per-SID limit of 4
   applies), so at most one client here has completed hello at a time. */
#define T_BIG_PAD (100u * 1024u)
SD_TEST(svc_pipe_caps_and_reserved_admin_instances)
{
  sd_ipc_conn *adm = NULL, *user = NULL;
  sd_ipc_error err;
  sd_err e = SD_OK, rc = SD_OK;
  sd_json *res;
  char *big;
  size_t i;
  int has_token = 0, r, nraw = 0, ev0, ev1;
  HANDLE raw[30];
  SD_REQUIRE(ensure_core());
  big = (char *)malloc(T_BIG_PAD + 32);
  SD_REQUIRE(big != NULL);
  memcpy(big, "{\"pad\":\"", 8);
  for (i = 8; i < 8 + T_BIG_PAD; i++)
    big[i] = 'a';
  memcpy(big + 8 + T_BIG_PAD, "\"}", 3);

  /* non-admin: the oversize request closes the connection (no reply) */
  e = connect_restricted(&user, &has_token);
  if (e == SD_OK) {
    res = call(user, "list", big, &err, &rc);
    SD_CHECK(res == NULL);
    SD_CHECK(rc != SD_OK);
    if (res) sd_json_free(res);
    sd_ipc_close(user);
    user = NULL;
  }

  /* admin: the same size is accepted */
  SD_REQUIRE(connect_as("testadmin", 0, &adm) == SD_OK);
  res = call(adm, "list", big, &err, &rc);
  SD_CHECK(res != NULL);
  if (res) sd_json_free(res);

  /* 30 raw instances: the instances left are the two for administrators. The raw instances of this process count as
     administrators at connect (svc_test_connect_admin): the class of an unelevated test process is not one. */
  svc_test_connect_admin(1);
  for (nraw = 0; nraw < 30; nraw++)
    if (!open_raw_instance(&raw[nraw]))
      break;
  SD_REQUIRE(nraw == 30);
  Sleep(300);            /* the server takes the connect on its own thread: the class flag must outlive that */

  /* the class is decided at connect (2.2): a non-admin is refused when it connects, before hello */
  svc_test_connect_admin(0);
  ev0 = count_event(SVC_MSG_CLIENT_REFUSED);
  for (r = 0; r < 2; r++) {
    sd_ipc_conn *u = NULL;
    int ht = 0;
    e = connect_restricted(&u, &ht);
    if (ht) {
      SD_CHECK(u == NULL);
      SD_CHECK(e != SD_OK);
    }
    if (u) sd_ipc_close(u);
  }
  ev1 = count_event(SVC_MSG_CLIENT_REFUSED);
  SD_CHECK(ev1 - ev0 <= 1);

  /* an administrator still connects while the 30 are held */
  sd_ipc_close(adm);
  adm = NULL;
  svc_test_connect_admin(1);
  SD_REQUIRE(connect_as("testadmin", 0, &adm) == SD_OK);
  res = call(adm, "list", NULL, &err, &rc);
  SD_CHECK(res != NULL);
  if (res) sd_json_free(res);

  svc_test_connect_admin(0);
  sd_ipc_close(adm);
  for (i = 0; i < (size_t)nraw; i++)
    CloseHandle(raw[i]);
  free(big);
}

/* A restricted-token client that connects and never says hello is closed by the hello deadline (2.2, SVC_HELLO_MS).
   The instance is looked at with PeekNamedPipe after the deadline: a closed instance has no pipe to peek. The same wait
   leaves an instance of the administrator class open. Skipped when the process has no restricted token to use. */
static HANDLE raw_restricted_instance(void)
{
  HANDLE rt = restricted_token();
  HANDLE h = NULL;
  if (rt == NULL)
    return NULL;
  if (ImpersonateLoggedOnUser(rt)) {
    if (!open_raw_instance(&h))
      h = NULL;
    RevertToSelf();
  }
  CloseHandle(rt);
  return h;
}

SD_TEST(svc_non_admin_that_never_says_hello_is_closed_in_time)
{
  HANDLE raw = NULL;
  SD_REQUIRE(ensure_core());
  svc_test_connect_admin(0);
  raw = raw_restricted_instance();
  if (raw != NULL) {
    Sleep(7000);
    SD_CHECK(PeekNamedPipe(raw, NULL, 0, NULL, NULL, NULL) == 0);     /* closed by the server */
    CloseHandle(raw);
  }
  svc_test_connect_admin(1);
  SD_REQUIRE(open_raw_instance(&raw));
  Sleep(300);            /* the server takes the connect on its own thread: the class flag must outlive that */
  svc_test_connect_admin(0);
  Sleep(7000);
  SD_CHECK(PeekNamedPipe(raw, NULL, 0, NULL, NULL, NULL) != 0);       /* the administrator class is not on the deadline */
  CloseHandle(raw);
}

/* ---- M5 hostkey add and the machine announcements (03 §2.4, §2.6 rule 2, §5.6) ----
   The hostkey connection of the fake is scripted by the host name (fake_backend_hostkeys): hk.known.test verifies
   against a stored key and offers an ECDSA and an ssh-rsa key besides it, hk.changed.test mismatches, hk.first.test is a
   first contact (one ssh-ed25519 key). The machine store is never a file here: the fake counts its writes. */

static sd_json *hk_add_call(sd_ipc_conn *c, const char *host, const char *type, const char *expect, sd_ipc_error *err,
                            sd_err *rc)
{
  char type_part[96] = "", expect_part[160] = "", params[512];
  if (type)
    _snprintf_s(type_part, sizeof(type_part), _TRUNCATE, ",\"type\":\"%s\"", type);
  if (expect)
    _snprintf_s(expect_part, sizeof(expect_part), _TRUNCATE, ",\"expect\":\"%s\"", expect);
  _snprintf_s(params, sizeof(params), _TRUNCATE, "{\"host\":\"%s\",\"port\":22,\"lookup\":\"%s\"%s%s}", host, host,
              type_part, expect_part);
  return call(c, "hostkey.add", params, err, rc);
}

/* The announcement with this id in a hostkey.announced.list reply, or NULL. */
static const sd_json *announcement_with_id(const sd_json *res, const char *id)
{
  const sd_json *arr = sd_json_get(res, "announcements");
  size_t i;
  for (i = 0; i < sd_json_count(arr); i++) {
    const sd_json *x = sd_json_at(arr, i);
    const char *v = sd_json_get_str(x, "id");
    if (v && strcmp(v, id) == 0)
      return x;
  }
  return NULL;
}

/* Waits (up to 5 s) for the announcement of a mount: its id and the counts of new and removed keys. */
static int announcement_of_mount(sd_ipc_conn *c, const char *mount_id, char *id_out, size_t cap, size_t *nadd,
                                 size_t *nremove)
{
  uint32_t waited;
  for (waited = 0; waited <= 5000; waited += 100) {
    sd_ipc_error err;
    sd_err e;
    sd_json *res = call(c, "hostkey.announced.list", NULL, &err, &e);
    if (res) {
      const sd_json *arr = sd_json_get(res, "announcements");
      size_t i;
      for (i = 0; i < sd_json_count(arr); i++) {
        const sd_json *x = sd_json_at(arr, i);
        const char *m = sd_json_get_str(x, "mount_id");
        if (m && strcmp(m, mount_id) == 0) {
          copy_str(id_out, cap, sd_json_get_str(x, "id"));
          *nadd = sd_json_count(sd_json_get(x, "add"));
          *nremove = sd_json_count(sd_json_get(x, "remove"));
          sd_json_free(res);
          return 1;
        }
      }
      sd_json_free(res);
    }
    Sleep(100);
  }
  return 0;
}

SD_TEST(svc_hostkey_add_offers_then_accept_writes_the_machine_store)
{
  sd_ipc_conn *c = NULL;
  sd_ipc_error err;
  sd_err e;
  sd_json *res;
  char id[16] = "", params[96];
  uint32_t before;
  int64_t added = -1, removed = -1;
  int verified = 0;
  SD_REQUIRE(ensure_core());
  SD_REQUIRE(connect_as("testadmin", 0, &c) == SD_OK);

  /* a type restriction asks for that key only */
  res = hk_add_call(c, "hk.known.test", "ssh-rsa", NULL, &err, &e);
  SD_REQUIRE(res != NULL);
  SD_CHECK(sd_json_count(sd_json_get(res, "keys")) == 1);
  sd_json_free(res);

  before = fake_backend_apply_machine_calls();
  res = hk_add_call(c, "hk.known.test", NULL, NULL, &err, &e);
  SD_REQUIRE(res != NULL);
  SD_CHECK(sd_json_get_bool(res, "verified", &verified) && verified);
  SD_CHECK(sd_json_count(sd_json_get(res, "keys")) == 2);       /* the ECDSA and the ssh-rsa key */
  copy_str(id, sizeof(id), sd_json_get_str(res, "id"));
  sd_json_free(res);
  SD_CHECK(id[0] != 0);
  SD_CHECK(before == fake_backend_apply_machine_calls());        /* offered for review, not stored */

  res = call(c, "hostkey.announced.list", NULL, &err, &e);
  SD_REQUIRE(res != NULL);
  SD_CHECK(announcement_with_id(res, id) != NULL);
  sd_json_free(res);

  _snprintf_s(params, sizeof(params), _TRUNCATE, "{\"id\":\"%s\",\"add_only\":true}", id);
  res = call(c, "hostkey.announced.accept", params, &err, &e);
  SD_REQUIRE(res != NULL);
  SD_CHECK(sd_json_get_int64(res, "added", &added) && added == 2);
  SD_CHECK(sd_json_get_int64(res, "removed", &removed) && removed == 0);
  sd_json_free(res);
  SD_CHECK(fake_backend_apply_machine_calls() == before + 1);

  res = call(c, "hostkey.announced.list", NULL, &err, &e);
  SD_REQUIRE(res != NULL);
  SD_CHECK(announcement_with_id(res, id) == NULL);               /* taken out of the list */
  sd_json_free(res);
  res = call(c, "hostkey.announced.accept", params, &err, &e);
  SD_CHECK(res == NULL);
  SD_CHECK_STR(err.code, "announcement_not_found");
  sd_ipc_close(c);
}

SD_TEST(svc_hostkey_first_contact_is_offered_and_expect_stores_it)
{
  sd_ipc_conn *c = NULL;
  sd_ipc_error err;
  sd_err e;
  sd_json *res;
  char fp[96] = "", id[16] = "";
  uint32_t before;
  SD_REQUIRE(ensure_core());
  SD_REQUIRE(connect_as("testadmin", 0, &c) == SD_OK);

  /* first contact (5.2): the one key the server presented, offered for review, nothing stored */
  before = fake_backend_apply_machine_calls();
  res = hk_add_call(c, "hk.first.test", NULL, NULL, &err, &e);
  SD_REQUIRE(res != NULL);
  {
    int verified = 1;
    SD_CHECK(sd_json_get_bool(res, "verified", &verified) && !verified);
  }
  SD_CHECK(sd_json_count(sd_json_get(res, "keys")) == 1);
  copy_str(id, sizeof(id), sd_json_get_str(res, "id"));
  copy_str(fp, sizeof(fp), sd_json_get_str(sd_json_at(sd_json_get(res, "keys"), 0), "fingerprint"));
  sd_json_free(res);
  SD_CHECK(id[0] != 0 && fp[0] != 0);
  SD_CHECK(before == fake_backend_apply_machine_calls());

  /* --expect with a fingerprint that matches nothing: refused (exit 5), nothing stored */
  res = hk_add_call(c, "hk.first.test", NULL, "SHA256:nothing-matches", &err, &e);
  SD_CHECK(res == NULL);
  SD_CHECK_STR(err.code, "host_key_rejected");
  SD_CHECK(before == fake_backend_apply_machine_calls());

  /* --expect with the presented fingerprint: stored with no question, so no announcement id comes back */
  res = hk_add_call(c, "hk.first.test", NULL, fp, &err, &e);
  SD_REQUIRE(res != NULL);
  {
    int64_t added = -1;
    SD_CHECK(sd_json_get_int64(res, "added", &added) && added == 1);
  }
  SD_CHECK(sd_json_get_str(res, "id") == NULL);
  sd_json_free(res);
  SD_CHECK(before + 1 == fake_backend_apply_machine_calls());
  sd_ipc_close(c);
}

SD_TEST(svc_hostkey_add_refuses_a_changed_key_and_an_unknown_host)
{
  sd_ipc_conn *c = NULL;
  sd_ipc_error err;
  sd_err e;
  sd_json *res;
  uint32_t before;
  SD_REQUIRE(ensure_core());
  SD_REQUIRE(connect_as("testadmin", 0, &c) == SD_OK);
  before = fake_backend_apply_machine_calls();
  /* the stored key does not match: a mismatch fails (6.2), as for a mount, and nothing is offered */
  res = hk_add_call(c, "hk.changed.test", NULL, NULL, &err, &e);
  SD_CHECK(res == NULL);
  SD_CHECK_STR(err.code, "host_key_mismatch");
  /* no machine profile of scope service uses this host: nothing connects */
  res = hk_add_call(c, "nobody.example", NULL, NULL, &err, &e);
  SD_CHECK(res == NULL);
  SD_CHECK_STR(err.code, "profile_not_found");
  SD_CHECK(before == fake_backend_apply_machine_calls());
  sd_ipc_close(c);
}

SD_TEST(svc_hostkey_methods_are_for_elevated_admins)
{
  sd_ipc_conn *c = NULL;
  sd_ipc_error err;
  sd_err e;
  sd_json *res;
  int has_token = 0;
  SD_REQUIRE(ensure_core());
  e = connect_restricted(&c, &has_token);
  if (e != SD_OK) {
    /* as svc_non_admin_token_cannot_call_admin_methods: the refusal may be the connect itself */
    SD_CHECK(has_token == 0 || e == SD_E_ACCESS_DENIED || e == SD_E_CONN_REFUSED || e == SD_E_BUSY);
    return;
  }
  res = hk_add_call(c, "hk.known.test", NULL, NULL, &err, &e);
  SD_CHECK(res == NULL);
  SD_CHECK_STR(err.code, "access_denied");
  res = call(c, "hostkey.announced.list", NULL, &err, &e);
  SD_CHECK(res == NULL);
  SD_CHECK_STR(err.code, "access_denied");
  res = call(c, "hostkey.announced.accept", "{\"id\":\"a-1\"}", &err, &e);
  SD_CHECK(res == NULL);
  SD_CHECK_STR(err.code, "access_denied");
  sd_ipc_close(c);
}

/* A mount whose host announces new keys (UpdateHostKeys, policy ask, 5.6): the announcement is kept for review with the
   mount's id, Event 2300 is raised, and accepting it writes the change to the machine store (removals included). */
SD_TEST(svc_mount_announcement_is_kept_and_accepted_into_the_machine_store)
{
  sd_ipc_conn *c = NULL;
  sd_ipc_error err;
  sd_err e;
  sd_json *res, *st = NULL;
  char mid[16] = "", id[16] = "", params[96];
  size_t nadd = 0, nremove = 0;
  uint32_t before;
  int64_t removed = -1;
  SD_REQUIRE(ensure_core());
  SD_REQUIRE(connect_as("testadmin", 0, &c) == SD_OK);
  before = fake_backend_apply_machine_calls();
  res = mount_profile(c, "rotate", &err, &e);
  SD_REQUIRE(res != NULL);
  copy_str(mid, sizeof(mid), sd_json_get_str(res, "mount_id"));
  sd_json_free(res);
  SD_REQUIRE(mid[0] != 0);
  SD_CHECK(wait_state(c, mid, "mounted", 10000, &st));
  json_drop(&st);
  SD_REQUIRE(announcement_of_mount(c, mid, id, sizeof(id), &nadd, &nremove));
  SD_CHECK(nadd == 1 && nremove == 1);
  SD_CHECK(saw_event(SVC_MSG_HOSTKEYS_ANNOUNCED));
  SD_CHECK(before == fake_backend_apply_machine_calls());        /* kept, not applied */

  _snprintf_s(params, sizeof(params), _TRUNCATE, "{\"id\":\"%s\"}", id);
  res = call(c, "hostkey.announced.accept", params, &err, &e);
  SD_REQUIRE(res != NULL);
  SD_CHECK(sd_json_get_int64(res, "removed", &removed) && removed == 1);
  sd_json_free(res);
  SD_CHECK(fake_backend_apply_machine_calls() == before + 1);

  SD_CHECK(unmount_id(c, mid));
  SD_CHECK(wait_state(c, mid, "gone", 10000, NULL));
  sd_ipc_close(c);
}

/* hostkey.announced.reject (03 §2.4, M5 follow-up): a refused offer leaves the list and stores nothing; the id is then
   unknown to accept and to reject; a non-admin cannot reject. */
SD_TEST(svc_hostkey_offer_can_be_rejected)
{
  sd_ipc_conn *c = NULL, *user = NULL;
  sd_ipc_error err;
  sd_err e;
  sd_json *res;
  char id[16] = "", params[96];
  uint32_t before;
  int has_token = 0;
  SD_REQUIRE(ensure_core());
  SD_REQUIRE(connect_as("testadmin", 0, &c) == SD_OK);

  before = fake_backend_apply_machine_calls();
  res = hk_add_call(c, "hk.known.test", NULL, NULL, &err, &e);
  SD_REQUIRE(res != NULL);
  copy_str(id, sizeof(id), sd_json_get_str(res, "id"));
  sd_json_free(res);
  SD_REQUIRE(id[0] != 0);

  _snprintf_s(params, sizeof(params), _TRUNCATE, "{\"id\":\"%s\"}", id);
  if (connect_restricted(&user, &has_token) == SD_OK) {
    res = call(user, "hostkey.announced.reject", params, &err, &e);
    SD_CHECK(res == NULL);
    SD_CHECK_STR(err.code, "access_denied");
    sd_ipc_close(user);
  }

  res = call(c, "hostkey.announced.reject", params, &err, &e);
  SD_REQUIRE(res != NULL);
  SD_CHECK(sd_json_get(res, "rejected") != NULL);
  sd_json_free(res);

  res = call(c, "hostkey.announced.list", NULL, &err, &e);
  SD_REQUIRE(res != NULL);
  SD_CHECK(announcement_with_id(res, id) == NULL);
  sd_json_free(res);
  SD_CHECK(before == fake_backend_apply_machine_calls());        /* nothing stored */

  res = call(c, "hostkey.announced.reject", params, &err, &e);
  SD_CHECK(res == NULL);
  SD_CHECK_STR(err.code, "announcement_not_found");
  res = call(c, "hostkey.announced.accept", params, &err, &e);
  SD_CHECK(res == NULL);
  SD_CHECK_STR(err.code, "announcement_not_found");
  sd_ipc_close(c);
}
/* UpdateHostKeys under policy 2 (03 §3.5, 5.6): the proven new key of an announcement goes to the machine store at once
   (add only), and the removal stays for review. The registry is not touched: the test forces the value
   (svc_test_hk_policy). The ask case (policy 1, announcement kept, nothing stored) is the one of
   svc_mount_announcement_is_kept_and_accepted_into_the_machine_store. One mount only: a second mount of the same profile
   in this test process ends with heap corruption (0xc0000374) after its announcement (open item, m5-notes part 10). */
SD_TEST(svc_mount_announcement_under_policy_writes_the_machine_store_only_with_accept)
{
  sd_ipc_conn *c = NULL;
  sd_ipc_error err;
  sd_err e;
  sd_json *res, *st = NULL;
  char mid[16] = "", id[16] = "";
  size_t nadd = 0, nremove = 0;
  uint32_t before;
  SD_REQUIRE(ensure_core());
  SD_REQUIRE(connect_as("testadmin", 0, &c) == SD_OK);

  svc_test_hk_policy(1, 2);
  before = fake_backend_apply_machine_calls();
  res = mount_profile(c, "rotate", &err, &e);
  SD_REQUIRE(res != NULL);
  copy_str(mid, sizeof(mid), sd_json_get_str(res, "mount_id"));
  sd_json_free(res);
  SD_CHECK(wait_state(c, mid, "mounted", 10000, &st));
  json_drop(&st);
  SD_REQUIRE(announcement_of_mount(c, mid, id, sizeof(id), &nadd, &nremove));
  SD_CHECK(nadd == 0 && nremove == 1);                  /* the addition is stored, the removal waits */
  SD_CHECK(before + 1 == fake_backend_apply_machine_calls());
  SD_CHECK(saw_event(SVC_MSG_HOSTKEYS_ANNOUNCED));

  svc_test_hk_policy(0, 0);
  SD_CHECK(unmount_id(c, mid));
  SD_CHECK(wait_state(c, mid, "gone", 10000, NULL));
  sd_ipc_close(c);
}

/* A machine profile whose file is writable by an untrusted principal is not loaded (2.6 rule 1, TM-R27): the file is
   checked on its handle at every load. config.reload counts the profiles: one less while the file is open to Everyone,
   the full count again once the file is back to the 3.2 rule. */
SD_TEST(svc_profile_file_with_an_open_acl_is_not_loaded)
{
  sd_ipc_conn *c = NULL;
  sd_ipc_error err;
  sd_err e;
  sd_json *res;
  wchar_t path[MAX_PATH];
  PSECURITY_DESCRIPTOR open_sd = NULL, closed_sd = NULL;
  PACL open_dacl = NULL, closed_dacl = NULL;
  BOOL present = FALSE, defaulted = FALSE;
  int64_t n = -1, base = -1;
  SD_REQUIRE(ensure_core());
  SD_REQUIRE(connect_as("testadmin", 0, &c) == SD_OK);
  _snwprintf_s(path, MAX_PATH, _TRUNCATE, L"%s\\profiles\\a-mounted.ini", g_root);
  /* the owner keeps its own ACE in the closed DACL: the test process is the owner, and it must still read the file */
  SD_REQUIRE(ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:(A;;FA;;;WD)", SDDL_REVISION_1, &open_sd, NULL));
  SD_REQUIRE(ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:PAI(A;;FA;;;OW)(A;;FA;;;SY)(A;;FA;;;BA)",
                                                                 SDDL_REVISION_1, &closed_sd, NULL));
  SD_REQUIRE(GetSecurityDescriptorDacl(open_sd, &present, &open_dacl, &defaulted) && present);
  SD_REQUIRE(GetSecurityDescriptorDacl(closed_sd, &present, &closed_dacl, &defaulted) && present);

  /* the count with every fixture profile readable; the open ACL must cost exactly this one profile */
  res = call(c, "config.reload", NULL, &err, &e);
  SD_REQUIRE(res != NULL);
  SD_REQUIRE(sd_json_get_int64(sd_json_get(res, "profiles"), "loaded", &base) && base > 0);
  sd_json_free(res);
  SD_REQUIRE(SetNamedSecurityInfoW(path, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                                   NULL, NULL, open_dacl, NULL) == ERROR_SUCCESS);
  res = call(c, "config.reload", NULL, &err, &e);
  SD_REQUIRE(res != NULL);
  SD_CHECK(sd_json_get_int64(sd_json_get(res, "profiles"), "loaded", &n) && n == base - 1);
  sd_json_free(res);

  SD_CHECK(SetNamedSecurityInfoW(path, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                                 NULL, NULL, closed_dacl, NULL) == ERROR_SUCCESS);
  n = -1;
  res = call(c, "config.reload", NULL, &err, &e);
  SD_REQUIRE(res != NULL);
  SD_CHECK(sd_json_get_int64(sd_json_get(res, "profiles"), "loaded", &n) && n == base);
  sd_json_free(res);
  LocalFree(open_sd);
  LocalFree(closed_sd);
  sd_ipc_close(c);
}

SD_TEST(svc_status_method_reports_the_scm_the_pipe_and_the_machine_folder)
{
  sd_ipc_conn *c = NULL;
  sd_ipc_error err;
  sd_err e;
  sd_json *res;
  const sd_json *o;
  int b = 0;
  int64_t n = -1;
  SD_REQUIRE(ensure_core());
  SD_REQUIRE(connect_as("testadmin", 0, &c) == SD_OK);
  SD_CHECK(sd_ipc_conn_has_feature(c, "service.status"));
  SD_CHECK(sd_ipc_conn_has_feature(c, "service.repair_data"));
  res = call(c, "service.status", NULL, &err, &e);
  SD_REQUIRE(res != NULL);
  SD_CHECK(sd_json_get_bool(res, "installed", &b) && b);
  SD_CHECK_STR(sd_json_get_str(res, "state"), "running");
  SD_CHECK_STR(sd_json_get_str(res, "start_type"), "automatic");
  o = sd_json_get(res, "program");
  SD_CHECK_STR(sd_json_get_str(o, "path"), "\"C:\\fake\\shelldrive-host.exe\" service");
  o = sd_json_get(res, "event_source");
  SD_CHECK_STR(sd_json_get_str(o, "state"), "missing");
  o = sd_json_get(res, "pipe");
  SD_CHECK(sd_json_get_bool(o, "reachable", &b) && b);
  SD_CHECK(sd_json_get_bool(o, "healthy", &b) && b);
  SD_CHECK(sd_json_get_int64(o, "global_drives", &n) && n == 0);
  SD_CHECK(sd_json_get_int64(o, "prompts", &n) && n == 0);
  o = sd_json_get(res, "machine");
  SD_CHECK_STR(sd_json_get_str(o, "state"), "ok");
  SD_CHECK(sd_json_get_int64(o, "profiles", &n) && n == 20);  /* the fixture's valid profiles (svc_loads_only_valid_service_profiles) */
  SD_CHECK(sd_json_get_str(o, "reason") == NULL);
  sd_json_free(res);
  sd_ipc_close(c);
}

SD_TEST(svc_status_is_open_to_a_non_admin_and_repair_is_not)
{
  sd_ipc_conn *c = NULL;
  sd_ipc_error err;
  sd_err e;
  sd_json *res;
  int has_token = 0, b = 0;
  SD_REQUIRE(ensure_core());
  e = connect_restricted(&c, &has_token);
  if (e != SD_OK) {
    SD_CHECK(has_token == 0 || e == SD_E_ACCESS_DENIED || e == SD_E_CONN_REFUSED || e == SD_E_BUSY);
    return;
  }
  res = call(c, "service.status", NULL, &err, &e);
  SD_REQUIRE(res != NULL);
  SD_CHECK(sd_json_get_bool(res, "installed", &b) && b);
  sd_json_free(res);
  res = call(c, "service.repair_data", NULL, &err, &e);
  SD_CHECK(res == NULL);
  SD_CHECK_STR(err.code, "access_denied");
  sd_ipc_close(c);
}

SD_TEST(svc_repair_is_busy_while_a_global_drive_exists)
{
  sd_ipc_conn *c = NULL;
  sd_ipc_error err;
  sd_err e;
  sd_json *res, *st = NULL;
  const sd_json *o;
  int64_t n = -1;
  char mid[16];
  SD_REQUIRE(ensure_core());
  SD_REQUIRE(connect_as("testadmin", 0, &c) == SD_OK);
  res = mount_profile(c, "mounted", &err, &e);
  SD_REQUIRE(res != NULL);
  copy_str(mid, sizeof(mid), sd_json_get_str(res, "mount_id"));
  sd_json_free(res);
  SD_CHECK(wait_state(c, mid, "mounted", 10000, &st));
  json_drop(&st);
  res = call(c, "service.status", NULL, &err, &e);
  SD_REQUIRE(res != NULL);
  o = sd_json_get(res, "pipe");
  SD_CHECK(sd_json_get_int64(o, "global_drives", &n) && n == 1);
  sd_json_free(res);
  res = call(c, "service.repair_data", NULL, &err, &e);
  SD_CHECK(res == NULL);
  SD_CHECK_STR(err.code, "busy");
  /* the refused repair changed nothing: the profiles are still loaded and the drive is still up */
  res = call(c, "service.status", NULL, &err, &e);
  SD_REQUIRE(res != NULL);
  o = sd_json_get(res, "machine");
  SD_CHECK_STR(sd_json_get_str(o, "state"), "ok");
  SD_CHECK(sd_json_get_int64(o, "profiles", &n) && n == 20);  /* the fixture's valid profiles (svc_loads_only_valid_service_profiles) */
  sd_json_free(res);
  SD_CHECK(unmount_id(c, mid));
  SD_CHECK(wait_state(c, mid, "gone", 10000, NULL));
  sd_ipc_close(c);
}

/* M5: mounts a profile and waits for `want`; the mount id is copied to mid and the last status is left in *st (which
   must be NULL or a reply the caller still owns: wait_state frees it before it stores the next one). */
static int mount_and_wait(sd_ipc_conn *c, const char *profile, const char *want, char *mid, size_t cap, sd_json **st)
{
  sd_ipc_error err;
  sd_err e;
  sd_json *res = mount_profile(c, profile, &err, &e);
  if (res == NULL)
    return 0;
  copy_str(mid, cap, sd_json_get_str(res, "mount_id"));
  sd_json_free(res);
  return mid[0] != 0 && wait_state(c, mid, want, 10000, st);
}

/* M5: whether a failed mount's last error carries the IPC code. */
static int failed_with(const sd_json *st, const char *code)
{
  const sd_json *le = st ? sd_json_get(st, "last_error") : NULL;
  const char *got = le ? sd_json_get_str(le, "code") : NULL;
  return got != NULL && strcmp(got, code) == 0;
}

SD_TEST(svc_chain_two_hops_are_mounted_with_the_service_rules)
{
  sd_ipc_conn *c = NULL;
  sd_json *st = NULL;
  char mid[16] = "";
  SD_REQUIRE(ensure_core());
  SD_REQUIRE(connect_as("testadmin", 0, &c) == SD_OK);
  SD_REQUIRE(mount_and_wait(c, "chain", "mounted", mid, sizeof(mid), &st));
  json_drop(&st);
  /* jump hop, then the target; the identity of every hop is a key blob read from the service folder (TM-R27), no agent,
     the jump hop never updates host keys and the target keeps the profile's mode (ask) */
  SD_CHECK_EQ_INT(fake_backend_last_hop_count(), 2);
  SD_CHECK_STR(fake_backend_last_hop_host(0), "hop1.trusted.example");
  SD_CHECK_STR(fake_backend_last_hop_host(1), "trusted.example");
  SD_CHECK_EQ_INT(fake_backend_last_hop_blob(0), 1);
  SD_CHECK_EQ_INT(fake_backend_last_hop_blob(1), 1);
  SD_CHECK_EQ_INT(fake_backend_last_hop_identities_only(0), 1);
  SD_CHECK_EQ_INT(fake_backend_last_hop_agent_keys(0), 0);
  SD_CHECK((fake_backend_last_hop_auth_methods(0) & SD_AUTH_KBDINT) == 0);
  SD_CHECK_EQ_INT(fake_backend_last_hop_hku(0), SD_HKU_NO);
  SD_CHECK_EQ_INT(fake_backend_last_hop_hku(1), SD_HKU_ASK);
  SD_CHECK_EQ_INT(fake_backend_last_hop_proxy(0), SD_PROXY_NONE);
  SD_CHECK(unmount_id(c, mid));
  SD_CHECK(wait_state(c, mid, "gone", 10000, NULL));
  sd_ipc_close(c);
}

SD_TEST(svc_chain_refuses_a_hop_with_a_user_path_identity)
{
  sd_ipc_conn *c = NULL;
  sd_json *st = NULL;
  char mid[16] = "";
  SD_REQUIRE(ensure_core());
  SD_REQUIRE(connect_as("testadmin", 0, &c) == SD_OK);
  /* the jump profile's identity is outside the service folder: nothing connects, the mount is refused with usage */
  SD_REQUIRE(mount_and_wait(c, "chainuser", "failed", mid, sizeof(mid), &st));
  SD_CHECK(failed_with(st, "usage"));
  json_drop(&st);
  SD_CHECK(unmount_id(c, mid));
  SD_CHECK(wait_state(c, mid, "gone", 10000, NULL));
  sd_ipc_close(c);
}

SD_TEST(svc_proxy_basic_without_a_service_secret_is_refused)
{
  sd_ipc_conn *c = NULL;
  sd_json *st = NULL;
  char mid[16] = "";
  SD_REQUIRE(ensure_core());
  SD_REQUIRE(connect_as("testadmin", 0, &c) == SD_OK);
  /* basic proxy authentication needs the proxy password, and the service has none stored for this leg */
  SD_REQUIRE(mount_and_wait(c, "proxypw", "failed", mid, sizeof(mid), &st));
  SD_CHECK(failed_with(st, "usage"));
  json_drop(&st);
  SD_CHECK(unmount_id(c, mid));
  SD_CHECK(wait_state(c, mid, "gone", 10000, NULL));
  sd_ipc_close(c);
}

SD_TEST(svc_proxy_with_a_service_secret_is_mounted_and_answered_from_the_store)
{
  sd_ipc_conn *c = NULL;
  sd_json *st = NULL;
  char mid[16] = "", target[SD_SECRET_MAX_TARGET];
  uint32_t before;
  SD_REQUIRE(ensure_core());
  SD_REQUIRE(connect_as("testadmin", 0, &c) == SD_OK);
  SD_REQUIRE(sd_secret_target_proxy("http", "pu", "proxy.example", 3128, target, sizeof(target)) == SD_OK);
  SD_REQUIRE(sd_secret_put(SD_SECRET_SERVICE, SD_SECRET_PROXY, target, NULL, FAKE_PROXY_PASSWORD,
                           strlen(FAKE_PROXY_PASSWORD)) == SD_OK);
  before = fake_backend_store_answers();
  /* the target authenticates with its key blob; the only prompt is the proxy password, answered from the store */
  SD_CHECK(mount_and_wait(c, "proxysec", "mounted", mid, sizeof(mid), &st));
  json_drop(&st);
  SD_CHECK_EQ_INT(fake_backend_last_hop_proxy(0), SD_PROXY_HTTP);
  SD_CHECK_STR(fake_backend_last_hop_proxy_host(0), "proxy.example");
  SD_CHECK_STR(fake_backend_last_hop_proxy_user(0), "pu");
  SD_CHECK_EQ_INT(fake_backend_last_hop_proxy_port(0), 3128);
  SD_CHECK_EQ_INT(fake_backend_last_hop_proxy_auth(0), SD_PROXY_AUTH_BASIC);
  SD_CHECK(fake_backend_store_answers() > before);   /* the proxy password came from the service store */
  if (mid[0]) {
    SD_CHECK(unmount_id(c, mid));
    SD_CHECK(wait_state(c, mid, "gone", 10000, NULL));
  }
  (void)sd_secret_delete(SD_SECRET_SERVICE, SD_SECRET_PROXY, target);
  sd_ipc_close(c);
}

SD_TEST(svc_system_proxy_is_read_through_the_seam_and_policy_refuses_it)
{
  sd_ipc_conn *c = NULL;
  sd_json *st = NULL;
  char mid[16] = "", mid2[16] = "";
  SD_REQUIRE(ensure_core());
  SD_REQUIRE(connect_as("testadmin", 0, &c) == SD_OK);
  g_sysread_calls = 0;
  SD_REQUIRE(mount_and_wait(c, "sysproxy", "mounted", mid, sizeof(mid), &st));
  json_drop(&st);
  /* the machine configuration was asked for the target host, and its answer is the leg: no SSPI (TM-R10) */
  SD_CHECK(g_sysread_calls >= 1);
  SD_CHECK_STR(g_sysread_host, "trusted.example");
  SD_CHECK_EQ_INT(fake_backend_last_hop_proxy(0), SD_PROXY_HTTP);
  SD_CHECK_STR(fake_backend_last_hop_proxy_host(0), "machine.proxy.example");
  SD_CHECK_EQ_INT(fake_backend_last_hop_proxy_port(0), 3128);
  SD_CHECK_EQ_INT(fake_backend_last_hop_proxy_auth(0), 0);
  SD_CHECK(unmount_id(c, mid));
  SD_CHECK(wait_state(c, mid, "gone", 10000, NULL));
  /* machine policy AllowSystemProxy off: the same profile, mounted a second time, is refused before any connect */
  g_sysops.allow = 0;
  g_sysread_calls = 0;
  SD_CHECK(mount_and_wait(c, "sysproxy", "failed", mid2, sizeof(mid2), &st));
  g_sysops.allow = 1;
  SD_CHECK(failed_with(st, "usage"));
  SD_CHECK_EQ_INT(g_sysread_calls, 0);
  json_drop(&st);
  if (mid2[0]) {
    SD_CHECK(unmount_id(c, mid2));
    SD_CHECK(wait_state(c, mid2, "gone", 10000, NULL));
  }
  sd_ipc_close(c);
}

/* AllowSystemProxy and AllowSystemProxySspi are read from the machine policy (sd_policy_machine_get_dword) when the seam
   says -1. The test forces the values (svc_test_sysproxy_policy) and never writes HKLM: off refuses the leg before any
   read, on with SSPI off gives the leg no SSPI, on with SSPI on gives it the Kerberos-only Negotiate (TM-R10). */
SD_TEST(svc_system_proxy_policy_is_read_from_the_machine_values)
{
  sd_ipc_conn *c = NULL;
  sd_json *st = NULL;
  char mid[16] = "", mid2[16] = "", mid3[16] = "";
  SD_REQUIRE(ensure_core());
  SD_REQUIRE(connect_as("testadmin", 0, &c) == SD_OK);
  g_sysops.allow = -1;
  /* AllowSystemProxy 1, AllowSystemProxySspi 0 */
  svc_test_sysproxy_policy(1, 1, 0);
  g_sysread_calls = 0;
  SD_REQUIRE(mount_and_wait(c, "sysproxy", "mounted", mid, sizeof(mid), &st));
  json_drop(&st);
  SD_CHECK(g_sysread_calls >= 1);
  SD_CHECK_EQ_INT(fake_backend_last_hop_proxy_auth(0), 0);
  SD_CHECK(unmount_id(c, mid));
  SD_CHECK(wait_state(c, mid, "gone", 10000, NULL));
  /* AllowSystemProxy 0: refused before the machine configuration is read */
  svc_test_sysproxy_policy(1, 0, 1);
  g_sysread_calls = 0;
  SD_CHECK(mount_and_wait(c, "sysproxy", "failed", mid2, sizeof(mid2), &st));
  SD_CHECK(failed_with(st, "usage"));
  SD_CHECK_EQ_INT(g_sysread_calls, 0);
  json_drop(&st);
  if (mid2[0]) {
    SD_CHECK(unmount_id(c, mid2));
    SD_CHECK(wait_state(c, mid2, "gone", 10000, NULL));
  }
  /* AllowSystemProxy 1 and AllowSystemProxySspi 1: the leg may use the Kerberos-only Negotiate */
  svc_test_sysproxy_policy(1, 1, 1);
  SD_REQUIRE(mount_and_wait(c, "sysproxy", "mounted", mid3, sizeof(mid3), &st));
  json_drop(&st);
  SD_CHECK_EQ_INT(fake_backend_last_hop_proxy_auth(0), SD_PROXY_AUTH_SSPI_KERBEROS);
  SD_CHECK(unmount_id(c, mid3));
  SD_CHECK(wait_state(c, mid3, "gone", 10000, NULL));
  svc_test_sysproxy_policy(0, 0, 0);
  g_sysops.allow = 1;
  sd_ipc_close(c);
}

/* secret.set and secret.delete with kind proxy (M5, 4.5): the service stores the password of a proxy leg under the
   target the leg reads, admins only; the reply has no secret, and a spec with a password is refused. */
SD_TEST(svc_secret_proxy_set_and_delete_through_the_pipe)
{
  sd_ipc_conn *c = NULL;
  sd_ipc_error err;
  sd_err e;
  sd_json *res;
  char target[SD_SECRET_MAX_TARGET];
  sd_secbuf *b = NULL;
  SD_REQUIRE(ensure_core());
  SD_REQUIRE(connect_as("testadmin", 0, &c) == SD_OK);
  SD_REQUIRE(sd_secret_target_proxy("http", "px", "proxy.example", 3128, target, sizeof(target)) == SD_OK);
  res = call(c, "secret.set", "{\"kind\":\"proxy\",\"proxy\":\"http://px@proxy.example:3128\",\"value\":\"pxpw\"}", &err, &e);
  SD_REQUIRE(res != NULL);
  {
    int stored = 0;
    SD_CHECK(sd_json_get_bool(res, "stored", &stored) && stored == 1);
  }
  sd_json_free(res);
  SD_REQUIRE(sd_secret_get(SD_SECRET_SERVICE, SD_SECRET_PROXY, target, &b) == SD_OK);
  SD_CHECK(b->len == strlen("pxpw") && memcmp(b->p, "pxpw", b->len) == 0);
  sd_secbuf_free(b);
  /* a password in the spec, or no user, is refused and stores nothing */
  res = call(c, "secret.set", "{\"kind\":\"proxy\",\"proxy\":\"http://px:pw@proxy.example:3128\",\"value\":\"x\"}", &err, &e);
  SD_CHECK(res == NULL);
  SD_CHECK_STR(err.code, "usage");
  res = call(c, "secret.set", "{\"kind\":\"proxy\",\"proxy\":\"http://proxy.example:3128\",\"value\":\"x\"}", &err, &e);
  SD_CHECK(res == NULL);
  SD_CHECK_STR(err.code, "usage");
  res = call(c, "secret.delete", "{\"kind\":\"proxy\",\"proxy\":\"http://px@proxy.example:3128\"}", &err, &e);
  SD_REQUIRE(res != NULL);
  {
    int deleted = 0;
    SD_CHECK(sd_json_get_bool(res, "deleted", &deleted) && deleted == 1);
  }
  sd_json_free(res);
  SD_CHECK(sd_secret_get(SD_SECRET_SERVICE, SD_SECRET_PROXY, target, &b) == SD_E_NOT_FOUND);
  res = call(c, "secret.delete", "{\"kind\":\"proxy\",\"proxy\":\"http://px@proxy.example:3128\"}", &err, &e);
  SD_CHECK(res == NULL);
  SD_CHECK_STR(err.code, "secret_not_found");
  sd_ipc_close(c);
}

SD_TEST(svc_system_proxy_refuses_basic_auth_on_its_leg)
{
  sd_ipc_conn *c = NULL;
  sd_json *st = NULL;
  char mid[16] = "";
  SD_REQUIRE(ensure_core());
  SD_REQUIRE(connect_as("testadmin", 0, &c) == SD_OK);
  /* the machine configuration has no credentials to offer (TM-R10): basic on a system leg is refused */
  SD_REQUIRE(mount_and_wait(c, "sysbasic", "failed", mid, sizeof(mid), &st));
  SD_CHECK(failed_with(st, "usage"));
  json_drop(&st);
  SD_CHECK(unmount_id(c, mid));
  SD_CHECK(wait_state(c, mid, "gone", 10000, NULL));
  sd_ipc_close(c);
}

SD_TEST(svc_hostkey_add_through_an_unknown_jump_host_is_refused)
{
  sd_ipc_conn *c = NULL;
  sd_ipc_error err;
  sd_err e;
  sd_json *res;
  uint32_t before, prompts;
  SD_REQUIRE(ensure_core());
  SD_REQUIRE(connect_as("testadmin", 0, &c) == SD_OK);
  before = fake_backend_apply_machine_calls();
  prompts = fake_backend_hk_jump_prompts();
  /* 2.6 rule 2: the jump host's key is not in the machine store. It is not taken as a first contact (only the target's
     key can be): the prompt is refused, the connect fails, and no key of the target or the jump host is offered */
  res = hk_add_call(c, "hkchain.known.test", NULL, NULL, &err, &e);
  SD_CHECK(res == NULL);
  if (res)
    sd_json_free(res);
  SD_CHECK_STR(err.code, "host_key_rejected");
  SD_CHECK(fake_backend_hk_jump_prompts() == prompts + 1);
  SD_CHECK(before == fake_backend_apply_machine_calls());
  sd_ipc_close(c);
}

/* 02 §7.7 attach (G2/G7 shape): a global WebDAV profile is hosted by the service and reports the export a member's
   agent maps. The reply carries the UNC with the path token and the letter, and no credential. The mount is hosted,
   not mapped, so it needs no second session. */
SD_TEST(svc_webdav_mount_reports_its_attach_point)
{
  sd_ipc_conn *c = NULL;
  sd_ipc_error err;
  sd_err e;
  sd_json *res, *st = NULL;
  char mid[16] = "";
  int attach = 0;
  int64_t port = 0;
  SD_REQUIRE(ensure_core());
  SD_REQUIRE(connect_as("testadmin", 0, &c) == SD_OK);
  fake_backend_set_webclient(SD_WD_CLIENT_RUNNING, 1);
  SD_REQUIRE(mount_and_wait(c, "webdav", "mounted", mid, sizeof(mid), &st));
  json_drop(&st);
  res = call(c, "mount.attach_info", "{\"profile\":\"webdav\"}", &err, &e);
  SD_REQUIRE(res != NULL);
  SD_CHECK_STR(sd_json_get_str(res, "backend"), "webdav");
  SD_CHECK(sd_json_get_bool(res, "attach", &attach) && attach);
  SD_CHECK_STR(sd_json_get_str(res, "unc"), "\\\\localhost@49321\\DavWWWRoot\\s-aaaaaaaaaaaaaaaaaaaaaaaaaa");
  SD_CHECK_STR(sd_json_get_str(res, "xp_url"), "http://localhost:49321/s-aaaaaaaaaaaaaaaaaaaaaaaaaa");
  SD_CHECK(sd_json_get_int64(res, "port", &port) && port == 49321);
  sd_json_free(res);
  /* a Dokany global mount has no export: the same method reports nothing to attach */
  SD_CHECK(unmount_id(c, mid));
  SD_CHECK(wait_state(c, mid, "gone", 10000, NULL));
  SD_REQUIRE(mount_and_wait(c, "mounted", "mounted", mid, sizeof(mid), &st));
  json_drop(&st);
  res = call(c, "mount.attach_info", "{\"profile\":\"mounted\"}", &err, &e);
  SD_REQUIRE(res != NULL);
  SD_CHECK_STR(sd_json_get_str(res, "backend"), "dokany");
  attach = 1;
  SD_CHECK(sd_json_get_bool(res, "attach", &attach) && attach == 0);
  SD_CHECK(sd_json_get(res, "unc") == NULL);
  sd_json_free(res);
  SD_CHECK(unmount_id(c, mid));
  SD_CHECK(wait_state(c, mid, "gone", 10000, NULL));
  sd_ipc_close(c);
}

/* 02 §7.7 G7 / TM-R18: the attach information is only for a caller in service_access. A profile whose list names a
   SID this process does not carry answers access_denied, and no UNC leaves the service. */
SD_TEST(svc_attach_info_refuses_a_caller_outside_service_access)
{
  sd_ipc_conn *c = NULL;
  sd_ipc_error err;
  sd_err e;
  sd_json *res, *st = NULL;
  char mid[16] = "";
  SD_REQUIRE(ensure_core());
  SD_REQUIRE(connect_as("testadmin", 0, &c) == SD_OK);
  fake_backend_set_webclient(SD_WD_CLIENT_RUNNING, 1);
  SD_REQUIRE(mount_and_wait(c, "webdavdeny", "mounted", mid, sizeof(mid), &st));
  json_drop(&st);
  res = call(c, "mount.attach_info", "{\"profile\":\"webdavdeny\"}", &err, &e);
  SD_CHECK(res == NULL);
  if (res)
    sd_json_free(res);
  SD_CHECK_STR(err.code, "access_denied");
  SD_CHECK(unmount_id(c, mid));
  SD_CHECK(wait_state(c, mid, "gone", 10000, NULL));
  sd_ipc_close(c);
}

/* Regression: one profile mounted twice in one process, each mount raising its own UpdateHostKeys announcement (the
   mount slot, the announcement records and the status replies of the first mount must not leak into the second). */
SD_TEST(svc_one_profile_mounted_twice_keeps_both_announcements)
{
  sd_ipc_conn *c = NULL;
  sd_json *st = NULL;
  char mid1[16] = "", mid2[16] = "", id1[16] = "", id2[16] = "";
  size_t nadd = 0, nremove = 0;
  SD_REQUIRE(ensure_core());
  SD_REQUIRE(connect_as("testadmin", 0, &c) == SD_OK);
  SD_REQUIRE(mount_and_wait(c, "rotate", "mounted", mid1, sizeof(mid1), &st));
  json_drop(&st);
  SD_REQUIRE(announcement_of_mount(c, mid1, id1, sizeof(id1), &nadd, &nremove));
  SD_CHECK(unmount_id(c, mid1));
  SD_CHECK(wait_state(c, mid1, "gone", 10000, NULL));
  SD_REQUIRE(mount_and_wait(c, "rotate", "mounted", mid2, sizeof(mid2), &st));
  json_drop(&st);
  SD_REQUIRE(announcement_of_mount(c, mid2, id2, sizeof(id2), &nadd, &nremove));
  SD_CHECK(nadd == 1 && nremove == 1);
  SD_CHECK(strcmp(mid1, mid2) != 0);
  SD_CHECK(strcmp(id1, id2) != 0);
  SD_CHECK(unmount_id(c, mid2));
  SD_CHECK(wait_state(c, mid2, "gone", 10000, NULL));
  sd_ipc_close(c);
}

SD_TEST(svc_core_stops_and_leaves_nothing_behind)
{
  sd_ipc_conn *c = NULL;
  SD_REQUIRE(ensure_core());
  svc_request_stop();
  SD_REQUIRE(WaitForSingleObject(g_thread, 30000) == WAIT_OBJECT_0);
  CloseHandle(g_thread);
  g_thread = NULL;
  SD_CHECK_EQ_INT(g_rc, 0);
  /* Event Log (10.3): start, the mounts of the earlier tests, and stop last */
  SD_CHECK(g_ev_n > 0);
  SD_CHECK(g_ev_ids[0] == SVC_MSG_STARTED);
  SD_CHECK(saw_event(SVC_MSG_MOUNTED));
  SD_CHECK(saw_event(SVC_MSG_UNMOUNTED));
  SD_CHECK(saw_event(SVC_MSG_MOUNT_FAILED));
  SD_CHECK(g_ev_ids[g_ev_n - 1] == SVC_MSG_STOPPED);
  /* every machine folder of the fixture was trusted: no 3102 */
  SD_CHECK(!saw_event(SVC_MSG_UNTRUSTED_FOLDER));
  /* the pipe is gone with the core */
  SD_CHECK(connect_as("testadmin", 0, &c) != SD_OK);
  CloseHandle(g_running);
  g_running = NULL;
  g_started = 0;
  RemoveDirectoryW(g_repair_base);
}

/* ---- start refusal of a machine folder (3.2, TM-R34, Event 3102) ----
   Each run here is a core of its own (the core is process-wide; the one above has stopped). The owner seam trusts no
   owner, so the first machine folder checked, the root itself, is refused: the core stays up and idle, and Event 3102
   names the folder and the reason. The sink is a test sink: no Event Log write. */

static int g_ref_n;
static wchar_t g_ref_path[MAX_PATH];
static wchar_t g_ref_reason[64];
static int g_run_rc = -1;

static void refusal_event(void *ctx, DWORD msg_id, const wchar_t **args, size_t nargs)
{
  (void)ctx;
  if (msg_id != SVC_MSG_UNTRUSTED_FOLDER || nargs != 2)
    return;
  if (g_ref_n == 0) {
    _snwprintf_s(g_ref_path, MAX_PATH, _TRUNCATE, L"%s", args[0]);
    _snwprintf_s(g_ref_reason, SD_COUNTOF(g_ref_reason), _TRUNCATE, L"%s", args[1]);
  }
  g_ref_n++;
}

static void refusal_running(void *ctx)
{
  SetEvent((HANDLE)ctx);
}

static DWORD WINAPI refusal_core_main(LPVOID arg)
{
  g_run_rc = svc_run((svc_opts *)arg);
  return 0;
}

/* Runs one core with o until it listens, then stops it and waits for it. Returns 1 when it listened; *rc is svc_run's
   result. The pipe identity is set the same way as ensure_core does (process-wide, idempotent). */
static int run_one_core(svc_opts *o, int *rc)
{
  HANDLE running, thread = NULL;
  wchar_t sid[256], suffix[64];
  int listened = 0;
  running = CreateEventW(NULL, TRUE, FALSE, NULL);
  if (running == NULL)
    return 0;
  if (sd_ipc_current_identity(sid, SD_COUNTOF(sid), NULL) == SD_OK) {
    _snwprintf_s(suffix, SD_COUNTOF(suffix), _TRUNCATE, L"svc%lu", (unsigned long)GetCurrentProcessId());
    sd_ipc_set_instance_suffix(suffix);
    sd_ipc_test_set_expected_owner(sid);
    sd_ipc_test_set_service_owner(sid);
  }
  o->on_running = refusal_running;
  o->ctx = running;
  g_run_rc = -1;
  thread = CreateThread(NULL, 0, refusal_core_main, o, 0, NULL);
  if (thread != NULL) {
    listened = WaitForSingleObject(running, 15000) == WAIT_OBJECT_0;
    svc_request_stop();
    WaitForSingleObject(thread, 30000);
    CloseHandle(thread);
  }
  CloseHandle(running);
  *rc = g_run_rc;
  return listened;
}

/* A fresh folder under %TEMP% for one run; the core is given it as its machine root. */
static int make_run_root(wchar_t *root, size_t cch)
{
  wchar_t tmp[MAX_PATH];
  LARGE_INTEGER qpc;
  if (GetTempPathW(MAX_PATH, tmp) == 0)
    return 0;
  QueryPerformanceCounter(&qpc);
  _snwprintf_s(root, cch, _TRUNCATE, L"%ssdsvc-own-%lu-%lu", tmp, (unsigned long)GetCurrentProcessId(),
               (unsigned long)qpc.LowPart);
  return CreateDirectoryW(root, NULL) ? 1 : 0;
}

SD_TEST(svc_refuses_a_machine_folder_with_a_foreign_owner_at_start)
{
  static svc_opts o;
  wchar_t root[MAX_PATH], sub[MAX_PATH];
  int rc = -1;
  SD_REQUIRE(make_run_root(root, SD_COUNTOF(root)));
  memset(&o, 0, sizeof(o));
  o.backend = fake_backend();
  o.machine_root = root;
  o.open_log = 0;
  o.event = refusal_event;
  o.owner_trusted = owner_trust_none;
  g_ref_n = 0;
  g_ref_path[0] = 0;
  g_ref_reason[0] = 0;
  SD_REQUIRE(run_one_core(&o, &rc));
  SD_CHECK_EQ_INT(rc, 0);
  /* the root is the first folder checked: one event names it and the owner reason; nothing was created below it */
  SD_CHECK_EQ_INT(g_ref_n, 1);
  SD_CHECK(lstrcmpW(g_ref_path, root) == 0);
  SD_CHECK(lstrcmpW(g_ref_reason, L"owner") == 0);
  _snwprintf_s(sub, SD_COUNTOF(sub), _TRUNCATE, L"%s\\logs", root);
  SD_CHECK(GetFileAttributesW(sub) == INVALID_FILE_ATTRIBUTES);
  _snwprintf_s(sub, SD_COUNTOF(sub), _TRUNCATE, L"%s\\profiles", root);
  SD_CHECK(GetFileAttributesW(sub) == INVALID_FILE_ATTRIBUTES);
  RemoveDirectoryW(root);
}

/* ---- boot autostart (1.8, 3.4.1): the service mounts autostart = boot profiles at start ----
   Each test runs a core of its own on a fresh machine root after the shared one has stopped: the profiles are
   in place before the start, so what the test sees is the start-time autostart. */

#define T_ID_BOOTAUTO  "00000000000000000000000000000020"
#define T_ID_BOOTLOGON "00000000000000000000000000000021"

/* write_profile plus the [mount] autostart key, which sd_profile_to_ini does not write (the editor writes the
   key into the file itself): the service reads it back when it loads the profiles. */
static int write_profile_autostart(const wchar_t *root, const wchar_t *file, const sd_profile *p,
                                   const char *autostart)
{
  sd_ini *ini = NULL;
  sd_wr w;
  wchar_t path[MAX_PATH];
  int ok = 0;
  _snwprintf_s(path, MAX_PATH, _TRUNCATE, L"%s\\profiles\\%s", root, file);
  sd_wr_init(&w, 4096);
  if (sd_profile_to_ini(p, &ini) == SD_OK && sd_ini_set(ini, "mount", "autostart", autostart) == SD_OK &&
      sd_ini_serialize(ini, &w) == SD_OK)
    ok = write_file(path, (const char *)w.p, w.len);
  sd_ini_free(ini);
  sd_wr_free(&w);
  return ok;
}

static HANDLE g_boot_running;
static HANDLE g_boot_thread;
static int g_boot_rc = -1;

static void boot_core_running(void *ctx)
{
  SetEvent((HANDLE)ctx);
}

static DWORD WINAPI boot_core_main(LPVOID arg)
{
  g_boot_rc = svc_run((svc_opts *)arg);
  return 0;
}

/* Starts a core of its own on root (the seams of the shared core) and returns once it listens; the test talks
   to it over the pipe and stops it with stop_boot_core. */
static int start_boot_core(svc_opts *o, const wchar_t *root)
{
  wchar_t sid[256], suffix[64];
  memset(o, 0, sizeof(*o));
  o->backend = fake_backend_hostkeys();
  o->machine_root = root;
  o->owner_trusted = owner_trust_all;
  o->test_all_admin = 1;
  o->dacl_extra_ace = L"(A;OICI;FA;;;OW)";
  o->on_running = boot_core_running;
  if (sd_ipc_current_identity(sid, SD_COUNTOF(sid), NULL) != SD_OK)
    return 0;
  _snwprintf_s(suffix, SD_COUNTOF(suffix), _TRUNCATE, L"svc%lu", (unsigned long)GetCurrentProcessId());
  sd_ipc_set_instance_suffix(suffix);
  sd_ipc_test_set_expected_owner(sid);
  sd_ipc_test_set_service_owner(sid);
  g_boot_running = CreateEventW(NULL, TRUE, FALSE, NULL);
  if (g_boot_running == NULL)
    return 0;
  o->ctx = g_boot_running;
  g_boot_rc = -1;
  g_boot_thread = CreateThread(NULL, 0, boot_core_main, o, 0, NULL);
  if (g_boot_thread == NULL) {
    CloseHandle(g_boot_running);
    g_boot_running = NULL;
    return 0;
  }
  return WaitForSingleObject(g_boot_running, 15000) == WAIT_OBJECT_0;
}

static void stop_boot_core(void)
{
  svc_request_stop();
  (void)WaitForSingleObject(g_boot_thread, 30000);
  CloseHandle(g_boot_thread);
  g_boot_thread = NULL;
  CloseHandle(g_boot_running);
  g_boot_running = NULL;
}

/* Counts the records of the two autostart profiles in a list reply; mid keeps the mount id of the boot one. */
static void boot_list_scan(sd_json *res, int *n_boot, int *n_logon, char *mid, size_t mid_cap)
{
  const sd_json *mounts = sd_json_get(res, "mounts");
  int i;
  *n_boot = 0;
  *n_logon = 0;
  for (i = 0; mounts && i < (int)sd_json_count(mounts); i++) {
    const sd_json *m = sd_json_at(mounts, i);
    const char *pid = sd_json_get_str(m, "profile");
    if (pid == NULL)
      continue;
    if (strcmp(pid, T_ID_BOOTAUTO) == 0) {
      copy_str(mid, mid_cap, sd_json_get_str(m, "mount_id"));
      (*n_boot)++;
    } else if (strcmp(pid, T_ID_BOOTLOGON) == 0) {
      (*n_logon)++;
    }
  }
}

/* Waits until the boot profile is mounted through the start autostart (the mount comes up asynchronously) and
   the logon profile has no record; scans the list each round. Returns 1 when seen. */
static int wait_boot_list(sd_ipc_conn *c, int *n_boot, int *n_logon, char *mid, size_t mid_cap)
{
  sd_ipc_error err;
  sd_err e;
  uint32_t waited = 0;
  for (;;) {
    sd_json *res = call(c, "list", NULL, &err, &e);
    int seen = 0;
    if (res != NULL) {
      boot_list_scan(res, n_boot, n_logon, mid, mid_cap);
      sd_json_free(res);
      seen = *n_boot == 1 && *n_logon == 0 && mid[0] != 0;
      if (seen) {
        /* the record exists; mounted is what makes it the autostart the docs ask for */
        char params[64];
        sd_json *st;
        _snprintf_s(params, sizeof(params), _TRUNCATE, "{\"mount_id\":\"%s\"}", mid);
        st = call(c, "status", params, &err, &e);
        if (st != NULL) {
          const char *got = sd_json_get_str(st, "state");
          seen = got != NULL && strcmp(got, "mounted") == 0;
          sd_json_free(st);
        }
      }
    }
    if (seen)
      return 1;
    if (waited >= 10000)
      return 0;
    Sleep(100);
    waited += 100;
  }
}

/* A fresh machine root for one boot-autostart core: the profiles folder and the service key the profiles carry.
   The key must live under this root's own service folder (TM-R27): an identity outside it is refused at mount. */
static int make_boot_root(const wchar_t *root, wchar_t *key, size_t key_cch)
{
  wchar_t d[MAX_PATH];
  if (!make_run_root((wchar_t *)root, MAX_PATH))
    return 0;
  _snwprintf_s(d, MAX_PATH, _TRUNCATE, L"%s\\profiles", root);
  if (!CreateDirectoryW(d, NULL))
    return 0;
  _snwprintf_s(d, MAX_PATH, _TRUNCATE, L"%s\\service", root);
  if (!CreateDirectoryW(d, NULL))
    return 0;
  _snwprintf_s(d, MAX_PATH, _TRUNCATE, L"%s\\service\\keys", root);
  if (!CreateDirectoryW(d, NULL))
    return 0;
  _snwprintf_s(key, key_cch, _TRUNCATE, L"%s\\service\\keys\\key1.ppk", root);
  return write_file(key, "fixture-key", 11);
}

/* A service profile of the boot fixture: the shared base on `host`, the identity under root's own service folder
   and the [mount] autostart value. */
static int write_boot_profile(const wchar_t *root, const wchar_t *file, const char *id, const char *name,
                              const char *host, const char *autostart)
{
  sd_profile p = base_profile(id, name, host);
  char utf8[MAX_PATH * 3];
  wchar_t key[MAX_PATH];
  _snwprintf_s(key, MAX_PATH, _TRUNCATE, L"%s\\service\\keys\\key1.ppk", root);
  utf8_of(key, utf8, sizeof(utf8));
  strcpy_s(p.identity, sizeof(p.identity), utf8);
  return write_profile_autostart(root, file, &p, autostart);
}

SD_TEST(svc_autostart_boot_is_mounted_at_start_and_logon_is_not)
{
  static svc_opts o;
  wchar_t root[MAX_PATH], key[MAX_PATH];
  sd_ipc_conn *c = NULL;
  sd_ipc_error err;
  sd_err e;
  sd_json *res;
  int n_boot = -1, n_logon = -1;
  char mid[16] = "";
  SD_REQUIRE(make_boot_root(root, key, SD_COUNTOF(key)));
  SD_REQUIRE(write_boot_profile(root, L"a-bootauto.ini", T_ID_BOOTAUTO, "bootauto", "trusted.example", "boot"));
  SD_REQUIRE(write_boot_profile(root, L"b-bootlogon.ini", T_ID_BOOTLOGON, "bootlogon", "trusted.example", "logon"));
  fake_backend_pre_trust("trusted.example");   /* own trust: the test also runs alone (--filter) */
  SD_REQUIRE(start_boot_core(&o, root));
  SD_REQUIRE(connect_as("testadmin", 0, &c) == SD_OK);
  /* the service mounts the boot profile by itself; autostart = logon is the agent's business (3.4.1) */
  SD_CHECK(wait_boot_list(c, &n_boot, &n_logon, mid, sizeof(mid)));
  SD_CHECK_EQ_INT(n_boot, 1);
  SD_CHECK_EQ_INT(n_logon, 0);
  /* the autostart record is the one mount: a second one for the same profile is refused */
  res = mount_profile(c, T_ID_BOOTAUTO, &err, &e);
  SD_CHECK(res == NULL);
  SD_CHECK_STR(err.code, "already_mounted");
  sd_ipc_close(c);
  stop_boot_core();
  SD_CHECK_EQ_INT(g_boot_rc, 0);
  RemoveDirectoryW(root);           /* best effort: the root holds the profile files */
}

SD_TEST(svc_autostart_reload_does_not_double_mount)
{
  static svc_opts o;
  wchar_t root[MAX_PATH], key[MAX_PATH];
  sd_ipc_conn *c = NULL;
  sd_ipc_error err;
  sd_err e;
  sd_json *res;
  int n_boot = -1, n_logon = -1;
  char mid[16] = "", mid2[16] = "";
  SD_REQUIRE(make_boot_root(root, key, SD_COUNTOF(key)));
  SD_REQUIRE(write_boot_profile(root, L"a-bootauto.ini", T_ID_BOOTAUTO, "bootauto", "trusted.example", "boot"));
  fake_backend_pre_trust("trusted.example");   /* own trust: the test also runs alone (--filter) */
  SD_REQUIRE(start_boot_core(&o, root));
  SD_REQUIRE(connect_as("testadmin", 0, &c) == SD_OK);
  SD_REQUIRE(wait_boot_list(c, &n_boot, &n_logon, mid, sizeof(mid)));
  /* config.reload loads the profiles again: the mounted profile keeps its one mount, id included */
  res = call(c, "config.reload", NULL, &err, &e);
  SD_REQUIRE(res != NULL);
  sd_json_free(res);
  res = call(c, "list", NULL, &err, &e);
  SD_REQUIRE(res != NULL);
  boot_list_scan(res, &n_boot, &n_logon, mid2, sizeof(mid2));
  sd_json_free(res);
  SD_CHECK_EQ_INT(n_boot, 1);
  SD_CHECK_STR(mid2, mid);
  /* and the manual mount of the same profile is still refused */
  res = mount_profile(c, T_ID_BOOTAUTO, &err, &e);
  SD_CHECK(res == NULL);
  SD_CHECK_STR(err.code, "already_mounted");
  sd_ipc_close(c);
  stop_boot_core();
  SD_CHECK_EQ_INT(g_boot_rc, 0);
  RemoveDirectoryW(root);
}

/* The live lab defect of the boot autostart: the start mount runs before the machine host key exists and ends
   failed; its record stays for list and status (03 1.11). When the key is added, a mount of the same profile must
   replace the failed record (a new mount id, the same letter) instead of answering already_mounted, while a live
   mount of the profile still answers already_mounted. */
SD_TEST(svc_autostart_failed_mount_is_replaced_by_a_new_mount)
{
  static svc_opts o;
  wchar_t root[MAX_PATH], key[MAX_PATH];
  sd_ipc_conn *c = NULL;
  sd_ipc_error err;
  sd_err e;
  sd_json *res, *st = NULL;
  int n_boot = -1, n_logon = -1;
  uint32_t waited = 0;
  char mid[16] = "", mid2[16] = "", tgt1[4] = "", tgt2[4] = "";
  SD_REQUIRE(make_boot_root(root, key, SD_COUNTOF(key)));
  /* no key for late.example in the machine store yet: the autostart mount fails (TOFU refused, 2.6 rule 2) */
  SD_REQUIRE(write_boot_profile(root, L"a-bootauto.ini", T_ID_BOOTAUTO, "bootauto", "late.example", "boot"));
  SD_REQUIRE(start_boot_core(&o, root));
  SD_REQUIRE(connect_as("testadmin", 0, &c) == SD_OK);
  for (;;) {
    res = call(c, "list", NULL, &err, &e);
    if (res != NULL) {
      boot_list_scan(res, &n_boot, &n_logon, mid, sizeof(mid));
      sd_json_free(res);
      if (mid[0] != 0)
        break;
    }
    SD_REQUIRE(waited < 10000);
    Sleep(100);
    waited += 100;
  }
  SD_CHECK(wait_state(c, mid, "failed", 10000, &st));
  if (st) {
    copy_str(tgt1, sizeof(tgt1), sd_json_get_str(st, "target"));
    json_drop(&st);
  }
  /* the admin adds the host key and mounts again: the failed record does not answer already_mounted */
  fake_backend_pre_trust("late.example");
  res = mount_profile(c, T_ID_BOOTAUTO, &err, &e);
  SD_CHECK(res != NULL);
  if (res != NULL) {
    copy_str(mid2, sizeof(mid2), sd_json_get_str(res, "mount_id"));
    copy_str(tgt2, sizeof(tgt2), sd_json_get_str(res, "target"));
    sd_json_free(res);
  }
  SD_CHECK(mid2[0] != 0 && strcmp(mid2, mid) != 0);        /* a new mount id */
  SD_CHECK_STR(tgt2, tgt1);                                /* the same letter comes back */
  SD_CHECK(wait_state(c, mid, "gone", 10000, NULL));       /* the failed record was released */
  SD_CHECK(wait_state(c, mid2, "mounted", 20000, NULL));   /* the drive is up without an unmount */
  /* a live mount of the profile is still refused */
  res = mount_profile(c, T_ID_BOOTAUTO, &err, &e);
  SD_CHECK(res == NULL);
  SD_CHECK_STR(err.code, "already_mounted");
  SD_CHECK(unmount_id(c, mid2));
  SD_CHECK(wait_state(c, mid2, "gone", 10000, NULL));
  sd_ipc_close(c);
  stop_boot_core();
  SD_CHECK_EQ_INT(g_boot_rc, 0);
  RemoveDirectoryW(root);
}
