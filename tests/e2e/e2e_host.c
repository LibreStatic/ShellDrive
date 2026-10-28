/* The end-to-end host (tests/e2e). The service core runs in this process on a thread, as tests/unit/sd_svc runs it:
   service.c with SD_SVC_TEST_HOOKS, the scripted fake mount backend, a temp machine root, no SCM and no Event Log.
   The per-run pipe name comes from sd_ipc_set_instance_suffix, and every CLI child receives the same suffix through
   SHELLDRIVE_TEST_INSTANCE, so the only route from the CLI to the service is the named pipe.

   Test seams of the children (read only in SD_CLI_TEST_HOOKS builds, that is sd-test-cli.exe):
     SHELLDRIVE_TEST_INSTANCE, SHELLDRIVE_TEST_CONFIG_DIR   the pipe suffix and a temp configuration root
     SHELLDRIVE_TEST_EXPECTED_OWNER                          the pipe owner: this process's user (the pipe is not SYSTEM's)
     SHELLDRIVE_TEST_ELEVATED                                0 denies, 1 grants elevation (set per command by the test)
     SHELLDRIVE_TEST_SCM                                     running or absent: the service state the CLI's SCM query sees
   The service counts every client as an elevated administrator (svc_test_connect_admin), so the CLI's own elevation
   check is the one under test. */
#include <windows.h>
#include <string.h>
#include <stdio.h>

#include "e2e_host.h"
#include "fake_backend.h"
#include "sd_base/sd_json.h"
#include "sd_base/sd_mem.h"
#include "sd_config/sd_config.h"
#include "sd_ipc/sd_ipc.h"
#include "sd_mount/sd_mount.h"
#include "sd_secret/sd_secret.h"
#include "service.h"

#define E2E_ID_MOUNTED "00000000000000000000000000000001"
#define E2E_ID_HK_FIRST "00000000000000000000000000000002"

static wchar_t g_root[MAX_PATH];
static wchar_t g_cfg[MAX_PATH];
static wchar_t g_suffix[64];
static wchar_t g_sid[256];
static wchar_t g_repair_base[MAX_PATH];
static HANDLE g_thread;
static HANDLE g_running;
static int g_started;
static int g_core_ok;
static int g_rc = -1;
static svc_opts g_opts;

static int owner_trust_all(void *ctx, PSID owner)
{
  (void)ctx;
  (void)owner;
  return 1;
}

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

static int make_dir(const wchar_t *sub)
{
  wchar_t d[MAX_PATH];
  _snwprintf_s(d, MAX_PATH, _TRUNCATE, L"%s\\%s", g_root, sub);
  return CreateDirectoryW(d, NULL) != 0;
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

/* The identity profiles name the key file the service reads through a checked handle (TM-R27). */
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
  if (!(n > 0 && n < MAX_PATH))
    return 0;
  QueryPerformanceCounter(&qpc);
  _snwprintf_s(g_root, MAX_PATH, _TRUNCATE, L"%se2e-%lu-%lu", tmp, (unsigned long)GetCurrentProcessId(),
               (unsigned long)qpc.LowPart);
  if (!CreateDirectoryW(g_root, NULL))
    return 0;
  if (!make_dir(L"profiles") || !make_dir(L"service") || !make_dir(L"service\\keys") ||
      !make_dir(L"service\\secrets") || !make_dir(L"logs") || !make_dir(L"cfg"))
    return 0;
  _snwprintf_s(g_cfg, MAX_PATH, _TRUNCATE, L"%s\\cfg", g_root);
  _snwprintf_s(d, MAX_PATH, _TRUNCATE, L"%s\\service\\keys\\key1.ppk", g_root);
  if (!write_file(d, "fixture-key", 11))
    return 0;

  /* a mount of the service profile "mounted" reaches a trusted host, so it mounts without a prompt */
  p = base_profile(E2E_ID_MOUNTED, E2E_PROFILE_MOUNTED, "trusted.example");
  identity_of(&p);
  if (!write_profile(L"a-mounted.ini", &p))
    return 0;
  /* a host with no stored key: the first contact of hostkey add is an offer, not a stored key */
  p = base_profile(E2E_ID_HK_FIRST, "hkfirst", E2E_HOST_FIRST);
  identity_of(&p);
  if (!write_profile(L"b-hkfirst.ini", &p))
    return 0;
  fake_backend_pre_trust("trusted.example");
  return 1;
}

/* svc_run clears its state at start, so the test seams of the connections are set here, before the pipe is announced. */
static void on_running(void *ctx)
{
  (void)ctx;
  svc_test_connect_admin(1);
  svc_test_admin_all_clients(1);
  SetEvent(g_running);
}

static DWORD WINAPI core_main(LPVOID arg)
{
  svc_opts *o = (svc_opts *)arg;
  g_rc = svc_run(o);
  return 0;
}

int e2e_core_start(void)
{
  if (g_started)
    return g_core_ok;
  g_started = 1;
  if (!make_fixture())
    return 0;
  if (sd_ipc_current_identity(g_sid, SD_COUNTOF(g_sid), NULL) != SD_OK)
    return 0;
  _snwprintf_s(g_suffix, SD_COUNTOF(g_suffix), _TRUNCATE, L"e2e%lu", (unsigned long)GetCurrentProcessId());
  sd_ipc_set_instance_suffix(g_suffix);
  sd_ipc_test_set_expected_owner(g_sid);
  sd_ipc_test_set_service_owner(g_sid);
  memset(&g_opts, 0, sizeof(g_opts));
  g_opts.backend = fake_backend_hostkeys();
  g_opts.machine_root = g_root;
  g_opts.open_log = 0;
  g_opts.on_running = on_running;
  g_opts.owner_trusted = owner_trust_all;
  g_opts.dacl_extra_ace = L"(A;OICI;FA;;;OW)";   /* the test process owns its folders, not SYSTEM (see svc_opts) */
  /* service.repair_data gets a base folder of its own, never %ProgramData% */
  _snwprintf_s(g_repair_base, MAX_PATH, _TRUNCATE, L"%s-repair", g_root);
  if (!CreateDirectoryW(g_repair_base, NULL))
    return 0;
  g_opts.repair_base = g_repair_base;
  g_running = CreateEventW(NULL, TRUE, FALSE, NULL);
  g_thread = CreateThread(NULL, 0, core_main, &g_opts, 0, NULL);
  if (g_running == NULL || g_thread == NULL)
    return 0;
  g_core_ok = WaitForSingleObject(g_running, 15000) == WAIT_OBJECT_0;
  return g_core_ok;
}

int e2e_core_stop(void)
{
  if (!g_started || g_thread == NULL)
    return 0;
  svc_request_stop();
  if (WaitForSingleObject(g_thread, 30000) != WAIT_OBJECT_0)
    return 0;
  CloseHandle(g_thread);
  g_thread = NULL;
  if (g_running) {
    CloseHandle(g_running);
    g_running = NULL;
  }
  g_started = 0;
  g_core_ok = 0;
  RemoveDirectoryW(g_repair_base);
  return g_rc == 0;
}

static void set_env(const wchar_t *name, const wchar_t *value)
{
  SetEnvironmentVariableW(name, value);
}

/* The CLI next to this executable: sd-test-cli.exe in the same output directory. */
static int cli_path(wchar_t *out, size_t cch)
{
  DWORD n = GetModuleFileNameW(NULL, out, (DWORD)cch);
  wchar_t *slash;
  if (n == 0 || n >= cch)
    return 0;
  slash = wcsrchr(out, L'\\');
  if (slash == NULL)
    return 0;
  wcscpy_s(slash + 1, cch - (size_t)(slash - out) - 1, L"sd-test-cli.exe");
  return 1;
}

int e2e_run_cli(const wchar_t *args, const wchar_t *elevated, const wchar_t *scm, const char *input,
                e2e_cli_result *r)
{
  SECURITY_ATTRIBUTES sa;
  HANDLE out_rd = NULL, out_wr = NULL, in_rd = NULL, in_wr = NULL;
  STARTUPINFOW si;
  PROCESS_INFORMATION pi;
  wchar_t exe[MAX_PATH];
  wchar_t *cmd = NULL;
  size_t cmd_cch;
  DWORD got = 0, total = 0;
  int ok = 0;
  memset(r, 0, sizeof(*r));
  if (g_suffix[0] == 0 || !cli_path(exe, MAX_PATH))
    return 0;
  set_env(L"SHELLDRIVE_TEST_INSTANCE", g_suffix);
  set_env(L"SHELLDRIVE_TEST_CONFIG_DIR", g_cfg);
  set_env(L"SHELLDRIVE_TEST_EXPECTED_OWNER", g_sid);
  set_env(L"SHELLDRIVE_TEST_ELEVATED", elevated);
  set_env(L"SHELLDRIVE_TEST_SCM", scm);

  memset(&sa, 0, sizeof(sa));
  sa.nLength = sizeof(sa);
  sa.bInheritHandle = TRUE;
  if (!CreatePipe(&out_rd, &out_wr, &sa, 0) || !CreatePipe(&in_rd, &in_wr, &sa, 0))
    goto done;
  SetHandleInformation(out_rd, HANDLE_FLAG_INHERIT, 0);
  SetHandleInformation(in_wr, HANDLE_FLAG_INHERIT, 0);
  if (input && input[0]) {
    DWORD n = 0;
    WriteFile(in_wr, input, (DWORD)strlen(input), &n, NULL);
  }
  CloseHandle(in_wr);
  in_wr = NULL;

  cmd_cch = wcslen(exe) + wcslen(args) + 4;
  cmd = (wchar_t *)sd_alloc(cmd_cch * sizeof(wchar_t));
  if (cmd == NULL)
    goto done;
  _snwprintf_s(cmd, cmd_cch, _TRUNCATE, L"\"%s\" %s", exe, args);

  memset(&si, 0, sizeof(si));
  si.cb = sizeof(si);
  si.dwFlags = STARTF_USESTDHANDLES;
  si.hStdInput = in_rd;
  si.hStdOutput = out_wr;
  si.hStdError = out_wr;
  memset(&pi, 0, sizeof(pi));
  if (!CreateProcessW(exe, cmd, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
    goto done;
  CloseHandle(out_wr);
  out_wr = NULL;
  CloseHandle(in_rd);
  in_rd = NULL;
  for (;;) {
    char chunk[512];
    if (!ReadFile(out_rd, chunk, sizeof(chunk), &got, NULL) || got == 0)
      break;
    if (total + got < sizeof(r->out)) {
      memcpy(r->out + total, chunk, got);
      total += got;
    }
  }
  r->out[total] = 0;
  WaitForSingleObject(pi.hProcess, 60000);
  GetExitCodeProcess(pi.hProcess, &r->exit_code);
  CloseHandle(pi.hThread);
  CloseHandle(pi.hProcess);
  ok = 1;

done:
  sd_free(cmd);
  if (out_rd) CloseHandle(out_rd);
  if (out_wr) CloseHandle(out_wr);
  if (in_rd) CloseHandle(in_rd);
  if (in_wr) CloseHandle(in_wr);
  return ok;
}

unsigned long e2e_machine_writes(void)
{
  return (unsigned long)fake_backend_apply_machine_calls();
}

/* Reads the proxy password the service stored for user (the http leg of proxy.example:3128). found = 0 when there is
   none. Returns 0 when the store cannot be read at all. */
int e2e_secret_proxy_get(const char *user, char *out, size_t cap, int *found)
{
  char target[SD_SECRET_MAX_TARGET];
  sd_secbuf *b = NULL;
  sd_err e;
  *found = 0;
  out[0] = 0;
  if (sd_secret_target_proxy("http", user, "proxy.example", 3128, target, sizeof(target)) != SD_OK)
    return 0;
  e = sd_secret_get(SD_SECRET_SERVICE, SD_SECRET_PROXY, target, &b);
  if (e == SD_E_NOT_FOUND)
    return 1;
  if (e != SD_OK)
    return 0;
  if (b->len < cap) {
    memcpy(out, b->p, b->len);
    out[b->len] = 0;
    *found = 1;
  }
  sd_secbuf_free(b);
  return 1;
}

/* The first "id":"..." of a JSON output, copied into id. */
int e2e_json_id(const char *out, char *id, size_t cap)
{
  const char *p = strstr(out, "\"id\":\"");
  size_t n = 0;
  if (p == NULL || cap == 0)
    return 0;
  p += strlen("\"id\":\"");
  while (p[n] && p[n] != '"' && n + 1 < cap) {
    id[n] = p[n];
    n++;
  }
  id[n] = 0;
  return n > 0;
}
