/* shelldrive-host update methods (see update_ipc.h). Configuration precedence (04 §9.1, 03 §3.5):
 *   policy (HKLM, then HKCU: DisableUpdateCheck, UpdateChannel, UpdateUrl) > settings.ini [update] of the user
 *   (or of <exe dir>\data for a portable install) > settings.ini [update] of the machine (%ProgramData%) > defaults.
 * Defaults: enabled, channel stable, the GitHub bootstrap manifest. Trust: the release roots are compiled in by the
 * release build (04 §9.3); this build carries none, so every verification fails closed until they are added. */
#include <windows.h>
#include <process.h>
#include <stdio.h>
#include <string.h>

#include "update_ipc.h"
#include "sd/version.h"
#include "sd_base/sd_mem.h"
#include "sd_base/sd_utf.h"
#include "sd_config/sd_ini.h"
#include "sd_ipc/sd_ipc.h"
#include "sd_platform/sd_log.h"
#include "sd_platform/sd_thread.h"
#include "sd_platform/sd_time.h"
#include "sd_update/sd_update.h"

#define UPD_POLICY_KEY   L"Software\\Policies\\LibreStatic\\ShellDrive"
#define UPD_DEFAULT_URL  L"https://github.com/LibreStatic/ShellDrive/releases/latest/download/manifest.txt"
#define UPD_INI_MAX      (64u * 1024u)
#define UPD_APPLY_MS     600000u           /* the staged setup may wait for UAC and a file lock */

/* One check or apply at a time, per agent. */
static volatile LONG g_busy;

/* No release roots in this build (see the header comment). */
static const sd_upd_trust k_trust = { NULL, 0, NULL, 0 };

typedef struct upd_cfg {
  int         enabled;                     /* 0: checks disabled (reason says why) */
  const char *reason;                      /* "policy" | "settings" */
  int         portable;
  char        channel[8];
  wchar_t     url[1024];
  wchar_t     state_user[MAX_PATH];
  wchar_t     state_machine[MAX_PATH];
  wchar_t     staging[MAX_PATH];
  sd_upd_mode mode;
  sd_upd_state_dirs st;
  sd_upd_paths paths;
} upd_cfg;

typedef struct upd_job {
  sd_ipc_server *srv;
  uint64_t cid;
  int64_t  rid;
  int      apply;
  upd_cfg  cfg;
} upd_job;

static sd_err fail(sd_ipc_error *err, sd_err e, const char *code, const char *detail)
{
  sd_ipc_error_set(err, e, code, detail);
  return err->err;
}

/* ---- configuration ---- */

static int expand_env(const wchar_t *in, wchar_t *out, DWORD cch)
{
  DWORD n = ExpandEnvironmentStringsW(in, out, cch);
  return n > 0 && n <= cch;
}

/* Creates every missing directory of path. */
static void make_dirs(const wchar_t *path)
{
  wchar_t tmp[MAX_PATH];
  size_t i;
  tmp[0] = L'\0';
  if (wcslen(path) >= SD_COUNTOF(tmp))
    return;
  wcscpy_s(tmp, SD_COUNTOF(tmp), path);
  for (i = 1; i < SD_COUNTOF(tmp) && tmp[i] != L'\0'; i++) {
    if (tmp[i] == L'\\') {
      tmp[i] = L'\0';
      CreateDirectoryW(tmp, NULL);
      tmp[i] = L'\\';
    }
  }
  CreateDirectoryW(tmp, NULL);
}

static int read_small_file(const wchar_t *path, uint8_t **buf, size_t *len)
{
  HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                         OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  LARGE_INTEGER sz;
  DWORD got = 0;
  uint8_t *p;
  if (h == INVALID_HANDLE_VALUE)
    return 0;
  if (!GetFileSizeEx(h, &sz) || sz.QuadPart < 0 || (unsigned long long)sz.QuadPart > UPD_INI_MAX) {
    CloseHandle(h);
    return 0;
  }
  p = (uint8_t *)sd_alloc((size_t)sz.QuadPart + 1);
  if (p == NULL) {
    CloseHandle(h);
    return 0;
  }
  if (sz.QuadPart && (!ReadFile(h, p, (DWORD)sz.QuadPart, &got, NULL) || got != (DWORD)sz.QuadPart)) {
    CloseHandle(h);
    sd_free(p);
    return 0;
  }
  CloseHandle(h);
  *buf = p;
  *len = got;
  return 1;
}

static void load_ini(const wchar_t *path, upd_cfg *c)
{
  uint8_t *buf = NULL;
  size_t n = 0;
  sd_ini *ini = NULL;
  uint32_t flags = 0;
  const char *v;
  if (!read_small_file(path, &buf, &n))
    return;
  if (sd_ini_parse((const char *)buf, n, &ini, &flags) == SD_OK) {
    v = sd_ini_get(ini, "update", "enabled");
    if (v) {
      int b = 1;
      if (sd_ini_parse_bool(v, &b))
        c->enabled = b;
    }
    v = sd_ini_get(ini, "update", "channel");
    if (v && (strcmp(v, "stable") == 0 || strcmp(v, "beta") == 0))
      strcpy_s(c->channel, sizeof(c->channel), v);
    v = sd_ini_get(ini, "update", "manifest_url");
    if (v && (strncmp(v, "https://", 8) == 0 || strncmp(v, "http://", 7) == 0)) {
      wchar_t *w = NULL;
      if (sd_utf8_to_wide_alloc(v, strlen(v), SD_UTF_STRICT, &w) == SD_OK && wcslen(w) < SD_COUNTOF(c->url))
        wcscpy_s(c->url, SD_COUNTOF(c->url), w);
      sd_free(w);
    }
    sd_ini_free(ini);
  }
  sd_free(buf);
}

static int policy_dword(HKEY root, const wchar_t *name, DWORD *out)
{
  HKEY k;
  DWORD type = 0, sz = sizeof(DWORD);
  LONG r;
  if (RegOpenKeyExW(root, UPD_POLICY_KEY, 0, KEY_READ, &k) != ERROR_SUCCESS)
    return 0;
  r = RegQueryValueExW(k, name, NULL, &type, (LPBYTE)out, &sz);
  RegCloseKey(k);
  return r == ERROR_SUCCESS && type == REG_DWORD;
}

static int policy_string(HKEY root, const wchar_t *name, wchar_t *out, DWORD cch)
{
  HKEY k;
  DWORD type = 0, sz;
  LONG r;
  if (out == NULL || cch < 2)
    return 0;
  sz = cch * sizeof(wchar_t);
  if (RegOpenKeyExW(root, UPD_POLICY_KEY, 0, KEY_READ, &k) != ERROR_SUCCESS)
    return 0;
  r = RegQueryValueExW(k, name, NULL, &type, (LPBYTE)out, &sz);
  RegCloseKey(k);
  if (r != ERROR_SUCCESS || type != REG_SZ || sz < sizeof(wchar_t))
    return 0;                             /* a value longer than the buffer is ERROR_MORE_DATA: refused */
  out[cch - 1] = L'\0';
  return 1;
}

/* Points the engine's directory arguments at the arrays of this very struct. Call it on the copy that is
   used (a copied struct keeps pointers into the original). */
static void cfg_bind(upd_cfg *c)
{
  c->st.user = c->state_user[0] ? c->state_user : NULL;
  c->st.machine = c->state_machine[0] ? c->state_machine : NULL;
  c->paths.staging = c->staging[0] ? c->staging : NULL;
  c->paths.install = NULL;                 /* setup mode: the setup program replaces the files (04 §9.6) */
  c->paths.selftest_exe = L"shelldrive-host.exe";
}

static void load_config(upd_cfg *c)
{
  wchar_t exe[MAX_PATH], dir[MAX_PATH], path[MAX_PATH * 2];
  DWORD dw = 0;
  char chan[8];
  memset(c, 0, sizeof(*c));
  c->enabled = 1;
  strcpy_s(c->channel, sizeof(c->channel), "stable");
  wcscpy_s(c->url, SD_COUNTOF(c->url), UPD_DEFAULT_URL);

  if (GetModuleFileNameW(NULL, exe, SD_COUNTOF(exe)) == 0)
    exe[0] = L'\0';
  wcscpy_s(dir, SD_COUNTOF(dir), exe);
  {
    wchar_t *slash = wcsrchr(dir, L'\\');
    if (slash)
      *slash = L'\0';
  }
  _snwprintf_s(path, SD_COUNTOF(path), _TRUNCATE, L"%ls\\data\\settings.ini", dir);
  c->portable = GetFileAttributesW(path) != INVALID_FILE_ATTRIBUTES;

  if (expand_env(L"%ProgramData%\\LibreStatic\\ShellDrive\\settings.ini", path, SD_COUNTOF(path)))
    load_ini(path, c);
  if (c->portable) {
    _snwprintf_s(path, SD_COUNTOF(path), _TRUNCATE, L"%ls\\data\\settings.ini", dir);
    load_ini(path, c);
  } else if (expand_env(L"%APPDATA%\\LibreStatic\\ShellDrive\\settings.ini", path, SD_COUNTOF(path))) {
    load_ini(path, c);
  }

  /* policy: HKLM wins over HKCU (03 §3.5) */
  if (policy_dword(HKEY_LOCAL_MACHINE, L"DisableUpdateCheck", &dw) || policy_dword(HKEY_CURRENT_USER, L"DisableUpdateCheck", &dw)) {
    if (dw != 0) {
      c->enabled = 0;
      c->reason = "policy";
    }
  }
  {
    wchar_t pv[64];
    int have = policy_string(HKEY_LOCAL_MACHINE, L"UpdateChannel", pv, SD_COUNTOF(pv)) ||
               policy_string(HKEY_CURRENT_USER, L"UpdateChannel", pv, SD_COUNTOF(pv));
    if (have) {
      size_t i;
      for (i = 0; i < 8 && pv[i]; i++)
        chan[i] = (char)pv[i];
      chan[i < 8 ? i : 7] = '\0';
      if (strcmp(chan, "stable") == 0 || strcmp(chan, "beta") == 0)
        strcpy_s(c->channel, sizeof(c->channel), chan);
    }
  }
  {
    wchar_t pu[1024];
    if (policy_string(HKEY_LOCAL_MACHINE, L"UpdateUrl", pu, SD_COUNTOF(pu)) ||
        policy_string(HKEY_CURRENT_USER, L"UpdateUrl", pu, SD_COUNTOF(pu)))
      wcscpy_s(c->url, SD_COUNTOF(c->url), pu);
  }
  if (c->enabled == 0 && c->reason == NULL)
    c->reason = "settings";

  /* state and staging: per user, or next to the executable for a portable install (04 §9.2, §9.6) */
  if (c->portable) {
    c->mode = SD_UPD_MODE_PORTABLE;
    _snwprintf_s(c->state_user, SD_COUNTOF(c->state_user), _TRUNCATE, L"%ls\\data\\state", dir);
    _snwprintf_s(c->staging, SD_COUNTOF(c->staging), _TRUNCATE, L"%ls\\data\\updates", dir);
  } else {
    c->mode = SD_UPD_MODE_SETUP;
    if (expand_env(L"%LOCALAPPDATA%\\LibreStatic\\ShellDrive\\state", c->state_user, SD_COUNTOF(c->state_user)) == 0)
      c->state_user[0] = L'\0';
    if (expand_env(L"%LOCALAPPDATA%\\LibreStatic\\ShellDrive\\updates", c->staging, SD_COUNTOF(c->staging)) == 0)
      c->staging[0] = L'\0';
  }
  if (!expand_env(L"%ProgramData%\\LibreStatic\\ShellDrive\\state", c->state_machine, SD_COUNTOF(c->state_machine)))
    c->state_machine[0] = L'\0';

  if (c->state_user[0])
    make_dirs(c->state_user);
  if (c->staging[0])
    make_dirs(c->staging);
  cfg_bind(c);
}

/* ---- JSON helpers ---- */

static void write_offer(sd_json_writer *jw, const sd_upd_offer *o)
{
  sd_jw_key(jw, "available"); sd_jw_bool(jw, o->available);
  sd_jw_key(jw, "channel"); sd_jw_cstr(jw, o->channel);
  sd_jw_key(jw, "stale"); sd_jw_bool(jw, o->stale);
  if (o->available) {
    sd_jw_key(jw, "version"); sd_jw_cstr(jw, o->version);
    sd_jw_key(jw, "notes"); sd_jw_cstr(jw, o->notes);
    sd_jw_key(jw, "size"); sd_jw_int(jw, (int64_t)o->size);
    sd_jw_key(jw, "file_id"); sd_jw_cstr(jw, o->file_id);
    sd_jw_key(jw, "serial"); sd_jw_int(jw, (int64_t)o->serial);
  }
}

static void broadcast(sd_ipc_server *srv, const char *event, sd_wr *data)
{
  sd_wr w;
  sd_wr_init(&w, SD_IPC_MAX_MESSAGE);
  if (srv && sd_ipc_build_event(event, (const char *)data->p, data->len, &w) == SD_OK)
    (void)sd_ipc_broadcast_all(srv, (const char *)w.p, w.len);
  sd_wr_free(&w);
}

static void event_offer(sd_ipc_server *srv, const sd_upd_offer *o)
{
  sd_wr d;
  sd_json_writer jw;
  sd_wr_init(&d, 4096);
  sd_jw_init(&jw, &d);
  sd_jw_obj_begin(&jw);
  sd_jw_key(&jw, "version"); sd_jw_cstr(&jw, o->version);
  sd_jw_key(&jw, "channel"); sd_jw_cstr(&jw, o->channel);
  sd_jw_key(&jw, "notes"); sd_jw_cstr(&jw, o->notes);
  sd_jw_key(&jw, "size"); sd_jw_int(&jw, (int64_t)o->size);
  sd_jw_key(&jw, "file_id"); sd_jw_cstr(&jw, o->file_id);
  sd_jw_obj_end(&jw);
  if (sd_jw_finish(&jw) == SD_OK)
    broadcast(srv, "update.available", &d);
  sd_wr_free(&d);
}

static void event_progress(sd_ipc_server *srv, const char *stage, const sd_upd_offer *o)
{
  sd_wr d;
  sd_json_writer jw;
  sd_wr_init(&d, 1024);
  sd_jw_init(&jw, &d);
  sd_jw_obj_begin(&jw);
  sd_jw_key(&jw, "stage"); sd_jw_cstr(&jw, stage);
  sd_jw_key(&jw, "version"); sd_jw_cstr(&jw, o->version);
  sd_jw_obj_end(&jw);
  if (sd_jw_finish(&jw) == SD_OK)
    broadcast(srv, "update.progress", &d);
  sd_wr_free(&d);
}

static void event_stale(sd_ipc_server *srv, const upd_cfg *c)
{
  sd_wr d;
  sd_json_writer jw;
  int64_t last = 0;
  int64_t days = 0;
  if (sd_upd_state_read_verified(&c->st, c->channel, &last) == SD_UPD_OK && last > 0) {
    days = (sd_unix_time_now() - last) / 86400;
    if (days < 0) days = 0;
  }
  sd_wr_init(&d, 256);
  sd_jw_init(&jw, &d);
  sd_jw_obj_begin(&jw);
  sd_jw_key(&jw, "days"); sd_jw_int(&jw, days);
  sd_jw_obj_end(&jw);
  if (sd_jw_finish(&jw) == SD_OK)
    broadcast(srv, "update.stale", &d);
  sd_wr_free(&d);
}

/* ---- engine calls ---- */

static sd_upd_res do_check(const upd_cfg *c, sd_upd_transport *tr, sd_upd_request *r, sd_upd_offer *o, char *flavour, size_t fcap)
{
  sd_upd_res res = sd_upd_detect_flavour(flavour, fcap);
  if (res != SD_UPD_OK)
    return res;
  memset(r, 0, sizeof(*r));
  r->manifest_url = c->url;
  r->channel = c->channel;
  r->installed_version = SD_VERSION_STRING;
  r->flavour = flavour;
  r->mode = c->mode;
  r->now = sd_unix_time_now();
  r->tr = tr;
  r->trust = &k_trust;
  r->state = &c->st;
  r->paths = &c->paths;
  return sd_upd_check(r, o);
}

static void job_error(upd_job *j, sd_err e, const char *code, const char *detail)
{
  if (j->srv)
    (void)sd_ipc_reply_deferred(j->srv, j->cid, j->rid, e, code, detail, NULL, 0);
}

static void job_reply(upd_job *j, const sd_wr *d)
{
  if (j->srv)
    (void)sd_ipc_reply_deferred(j->srv, j->cid, j->rid, SD_OK, NULL, NULL, (const char *)d->p, d->len);
}

static unsigned __stdcall job_main(void *arg)
{
  upd_job *j = (upd_job *)arg;
  sd_upd_offer *o = (sd_upd_offer *)sd_calloc(1, sizeof(*o));
  sd_upd_request r;
  sd_upd_transport *tr = NULL;
  sd_upd_res res = SD_UPD_E_NO_MEMORY;
  char flavour[16];
  sd_wr d;
  sd_json_writer jw;

  if (o == NULL) {
    job_error(j, SD_E_NO_MEMORY, "no_memory", "out of memory");
    goto out;
  }
  tr = sd_upd_transport_winhttp_create(1);
  if (tr == NULL) {
    job_error(j, SD_E_FAILURE, "update_unavailable", "WinHTTP cannot be loaded");
    goto out;
  }

  res = do_check(&j->cfg, tr, &r, o, flavour, sizeof(flavour));
  if (res != SD_UPD_OK) {
    if (o->stale)
      event_stale(j->srv, &j->cfg);
    SD_LOGW("agent", "update.check failed: %s", sd_upd_res_name(res));
    job_error(j, SD_E_FAILURE, sd_upd_res_code(res), sd_upd_res_name(res));
    goto out;
  }
  if (o->available)
    event_offer(j->srv, o);

  if (!j->apply) {
    sd_wr_init(&d, 4096);
    sd_jw_init(&jw, &d);
    sd_jw_obj_begin(&jw);
    sd_jw_key(&jw, "enabled"); sd_jw_bool(&jw, 1);
    write_offer(&jw, o);
    sd_jw_obj_end(&jw);
    if (sd_jw_finish(&jw) == SD_OK)
      job_reply(j, &d);
    else
      job_error(j, SD_E_INTERNAL, "internal", "reply");
    sd_wr_free(&d);
    goto out;
  }

  /* update.apply: stage, then the staged setup with /update /passive (04 §9.6) */
  if (!o->available) {
    sd_wr_init(&d, 1024);
    sd_jw_init(&jw, &d);
    sd_jw_obj_begin(&jw);
    sd_jw_key(&jw, "applied"); sd_jw_bool(&jw, 0);
    sd_jw_key(&jw, "state"); sd_jw_cstr(&jw, "up_to_date");
    sd_jw_obj_end(&jw);
    if (sd_jw_finish(&jw) == SD_OK)
      job_reply(j, &d);
    sd_wr_free(&d);
    goto out;
  }
  {
    wchar_t staged[MAX_PATH * 2];
    event_progress(j->srv, "downloading", o);
    res = sd_upd_stage(&r, o, staged, SD_COUNTOF(staged));
    if (res != SD_UPD_OK) {
      job_error(j, SD_E_FAILURE, sd_upd_res_code(res), sd_upd_res_name(res));
      goto out;
    }
    event_progress(j->srv, "applying", o);
    res = sd_upd_apply_setup(staged, UPD_APPLY_MS);
    if (res != SD_UPD_OK) {
      event_progress(j->srv, "failed", o);
      job_error(j, SD_E_FAILURE, sd_upd_res_code(res), sd_upd_res_name(res));
      goto out;
    }
    sd_upd_cleanup_staging(j->cfg.staging, o->version);
    event_progress(j->srv, "done", o);
    sd_wr_init(&d, 1024);
    sd_jw_init(&jw, &d);
    sd_jw_obj_begin(&jw);
    sd_jw_key(&jw, "applied"); sd_jw_bool(&jw, 1);
    sd_jw_key(&jw, "state"); sd_jw_cstr(&jw, "applied");
    sd_jw_key(&jw, "version"); sd_jw_cstr(&jw, o->version);
    sd_jw_obj_end(&jw);
    if (sd_jw_finish(&jw) == SD_OK)
      job_reply(j, &d);
    sd_wr_free(&d);
  }

out:
  if (tr)
    sd_upd_transport_destroy(tr);
  sd_free(o);
  sd_free(j);
  InterlockedExchange(&g_busy, 0);
  return 0;
}

static sd_err start_job(sd_ipc_server *srv, sd_ipc_client *client, upd_job *j, sd_ipc_error *err)
{
  sd_thread t;
  if (!sd_ipc_defer(client, &j->rid)) {
    sd_free(j);
    InterlockedExchange(&g_busy, 0);
    return fail(err, SD_E_INTERNAL, "internal", "deferred reply unavailable");
  }
  j->srv = srv;
  j->cid = sd_ipc_client_id(client);
  cfg_bind(&j->cfg);
  if (sd_thread_create(&t, job_main, j, 0, L"sd-update") != SD_OK) {
    /* the client is waiting: answer now, nothing ran */
    (void)sd_ipc_reply_deferred(srv, j->cid, j->rid, SD_E_NO_MEMORY, "no_memory", "cannot start the update thread", NULL, 0);
    sd_free(j);
    InterlockedExchange(&g_busy, 0);
    return SD_OK;
  }
  CloseHandle(t.h);
  return SD_OK;
}

/* ---- methods ---- */

sd_err upd_method_check(sd_ipc_server *srv, sd_ipc_client *client, const sd_json *params, sd_json_writer *res, sd_ipc_error *err)
{
  upd_cfg c;
  upd_job *j;
  SD_UNUSED(params);
  load_config(&c);
  if (!c.enabled) {
    sd_jw_key(res, "enabled"); sd_jw_bool(res, 0);
    sd_jw_key(res, "reason"); sd_jw_cstr(res, c.reason ? c.reason : "settings");
    sd_jw_key(res, "available"); sd_jw_bool(res, 0);
    return SD_OK;
  }
  if (InterlockedCompareExchange(&g_busy, 1, 0) != 0)
    return fail(err, SD_E_BUSY, "busy", "an update check or install is running");
  j = (upd_job *)sd_calloc(1, sizeof(*j));
  if (j == NULL) {
    InterlockedExchange(&g_busy, 0);
    return fail(err, SD_E_NO_MEMORY, "no_memory", "out of memory");
  }
  j->cfg = c;
  j->apply = 0;
  return start_job(srv, client, j, err);
}

sd_err upd_method_apply(sd_ipc_server *srv, sd_ipc_client *client, const sd_json *params, sd_json_writer *res, sd_ipc_error *err)
{
  upd_cfg c;
  upd_job *j;
  int consent = 0;
  SD_UNUSED(res);
  if (!sd_json_get_bool(params, "consent", &consent) || !consent)
    return fail(err, SD_E_INVALID_PARAM, "consent_required", "update.apply needs consent: true (the user chose to install)");
  load_config(&c);
  if (!c.enabled)
    return fail(err, SD_E_UNSUPPORTED, "update_disabled", c.reason ? c.reason : "disabled");
  if (c.portable)
    return fail(err, SD_E_UNSUPPORTED, "update_disabled", "portable install: download the new version manually");
  if (InterlockedCompareExchange(&g_busy, 1, 0) != 0)
    return fail(err, SD_E_BUSY, "busy", "an update check or install is running");
  j = (upd_job *)sd_calloc(1, sizeof(*j));
  if (j == NULL) {
    InterlockedExchange(&g_busy, 0);
    return fail(err, SD_E_NO_MEMORY, "no_memory", "out of memory");
  }
  j->cfg = c;
  j->apply = 1;
  return start_job(srv, client, j, err);
}
