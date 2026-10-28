/* In-process service core (apps/shelldrive-host/service.c) with the scripted fake mount backend: no SCM, no elevation,
   no real drive. One core runs for the whole file (svc_run is process-wide); the tests share it in order and the last
   one stops it and checks that it left nothing behind.

   Clients: "testadmin" hellos get the test admin override (SD_SVC_TEST_HOOKS); every other client is checked for real.
   The restricted-token client impersonates a token with BUILTIN\Administrators disabled (CreateRestrictedToken), which
   is the non-admin case the pipe must refuse (03 §2.2). */
#include <windows.h>
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

  fake_backend_pre_trust("trusted.example");
  fake_backend_pre_trust("trusted3.example");
  fake_backend_pre_trust("pw.example");
  fake_backend_pre_trust("pw2.example");
  fake_backend_pre_trust("rotate.example");
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
      if (last) {
        if (*last) sd_json_free(*last);
        *last = res;
      } else {
        sd_json_free(res);
      }
      if (st && strcmp(st, want) == 0)
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
  /* 9 valid: mounted, nosub, tofu, pwprompt, adminonly and the M5 hostkey and rotate profiles. Refused: pageant (D17).
     Not loaded: the user profile. */
  res = call(c, "config.reload", NULL, &err, &e);
  SD_REQUIRE(res != NULL);
  loaded = sd_json_get(res, "profiles");
  {
    int64_t n = -1;
    SD_CHECK(sd_json_get_int64(loaded, "loaded", &n));
    SD_CHECK_EQ_INT(n, 9);
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
  if (st) sd_json_free(st);
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
  if (st) sd_json_free(st);
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
  if (st) sd_json_free(st);

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

  /* 30 raw instances: the instances left are the two for administrators */
  for (nraw = 0; nraw < 30; nraw++)
    if (!open_raw_instance(&raw[nraw]))
      break;
  SD_REQUIRE(nraw == 30);

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
  SD_REQUIRE(connect_as("testadmin", 0, &adm) == SD_OK);
  res = call(adm, "list", NULL, &err, &rc);
  SD_CHECK(res != NULL);
  if (res) sd_json_free(res);

  sd_ipc_close(adm);
  for (i = 0; i < (size_t)nraw; i++)
    CloseHandle(raw[i]);
  free(big);
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
  if (st)
    sd_json_free(st);
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
  SD_CHECK(sd_json_get_int64(o, "profiles", &n) && n == 5);
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
  if (st)
    sd_json_free(st);
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
  SD_CHECK(sd_json_get_int64(o, "profiles", &n) && n == 5);
  sd_json_free(res);
  SD_CHECK(unmount_id(c, mid));
  SD_CHECK(wait_state(c, mid, "gone", 10000, NULL));
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
