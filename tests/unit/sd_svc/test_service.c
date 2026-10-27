/* In-process service core (apps/shelldrive-host/service.c) with the scripted fake mount backend: no SCM, no elevation,
   no real drive. One core runs for the whole file (svc_run is process-wide); the tests share it in order and the last
   one stops it and checks that it left nothing behind.

   Clients: "testadmin" hellos get the test admin override (SD_SVC_TEST_HOOKS); every other client is checked for real.
   The restricted-token client impersonates a token with BUILTIN\Administrators disabled (CreateRestrictedToken), which
   is the non-admin case the pipe must refuse (03 §2.2). */
#include <windows.h>
#include <string.h>
#include <stdio.h>

#include "sd_test.h"
#include "host.h"
#include "service.h"
#include "sd_base/sd_json.h"
#include "sd_config/sd_config.h"
#include "sd_ipc/sd_ipc.h"
#include "sd_mount/sd_mount.h"
#include "sd_secret/sd_secret.h"
#include "sd_mount/sd_mount.h"
#include "fake_backend.h"

#define T_ID_MOUNTED  "00000000000000000000000000000001"
#define T_ID_NOSUB    "00000000000000000000000000000002"
#define T_ID_TOFU     "00000000000000000000000000000003"
#define T_ID_PWPROMPT "00000000000000000000000000000004"
#define T_ID_PAGEANT  "00000000000000000000000000000005"
#define T_ID_ADMINONLY "00000000000000000000000000000006"

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

  fake_backend_pre_trust("trusted.example");
  fake_backend_pre_trust("trusted3.example");
  fake_backend_pre_trust("pw.example");
  fake_backend_pre_trust("pw2.example");
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
  o.backend = fake_backend();
  o.machine_root = g_root;
  o.open_log = 0;
  o.on_running = on_running;
  o.test_all_admin = 1;
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
  /* 5 valid: mounted, nosub, tofu, pwprompt, adminonly. Refused: pageant (D17). Not loaded: the user profile. */
  res = call(c, "config.reload", NULL, &err, &e);
  SD_REQUIRE(res != NULL);
  loaded = sd_json_get(res, "profiles");
  {
    int64_t n = -1;
    SD_CHECK(sd_json_get_int64(loaded, "loaded", &n));
    SD_CHECK_EQ_INT(n, 5);
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

SD_TEST(svc_core_stops_and_leaves_nothing_behind)
{
  sd_ipc_conn *c = NULL;
  SD_REQUIRE(ensure_core());
  svc_request_stop();
  SD_REQUIRE(WaitForSingleObject(g_thread, 30000) == WAIT_OBJECT_0);
  CloseHandle(g_thread);
  g_thread = NULL;
  SD_CHECK_EQ_INT(g_rc, 0);
  /* the pipe is gone with the core */
  SD_CHECK(connect_as("testadmin", 0, &c) != SD_OK);
  CloseHandle(g_running);
  g_running = NULL;
  g_started = 0;
}
