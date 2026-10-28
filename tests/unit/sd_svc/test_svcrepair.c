/* service.status and service.repair_data of the service core (apps/shelldrive-host/service.c) on a machine folder the
 * start refuses. Each test runs a core of its own on a fresh folder under %TEMP% with the fake mount backend: no SCM, no
 * %ProgramData%, no elevation, no Event Log write. The owner rule is a seam the test flips (g_trust): off, every machine
 * folder has a foreign owner and the start stays idle (3.2, TM-R34); on, the folders are trusted. The repair works on the
 * base folder of the test (svc_opts.repair_base), which holds LibreStatic\ShellDrive, the machine root of the core. */
#include <windows.h>
#include <string.h>
#include <stdio.h>

#include "sd_test.h"
#include "host.h"
#include "service.h"
#include "sd_base/sd_json.h"
#include "sd_ipc/sd_ipc.h"
#include "fake_backend.h"

static volatile LONG g_trust;

static int owner_flag(void *ctx, PSID owner)
{
  (void)ctx;
  (void)owner;
  return g_trust ? 1 : 0;
}

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

typedef struct rp_core {
  svc_opts o;
  svc_scm_ops scm;
  svc_repair_ops rops;
  wchar_t base[MAX_PATH];        /* the repair base */
  wchar_t vendor[MAX_PATH];      /* <base>\LibreStatic */
  wchar_t root[MAX_PATH];        /* <base>\LibreStatic\ShellDrive: the machine root of the core */
  HANDLE thread, running;
  int rc;
} rp_core;

static void rp_on_running(void *ctx)
{
  SetEvent(((rp_core *)ctx)->running);
}

static DWORD WINAPI rp_main(LPVOID arg)
{
  rp_core *k = (rp_core *)arg;
  k->rc = svc_run(&k->o);
  return 0;
}

/* Creates <TEMP>\sdsvc-rp-<pid>-<qpc>\LibreStatic and starts a core whose machine root is ...\ShellDrive below it. */
static int rp_start(rp_core *k)
{
  wchar_t tmp[MAX_PATH], sid[256], suffix[64];
  LARGE_INTEGER qpc;
  memset(k, 0, sizeof(*k));
  k->rc = -1;
  if (GetTempPathW(MAX_PATH, tmp) == 0)
    return 0;
  QueryPerformanceCounter(&qpc);
  _snwprintf_s(k->base, MAX_PATH, _TRUNCATE, L"%ssdsvc-rp-%lu-%lu", tmp, (unsigned long)GetCurrentProcessId(),
               (unsigned long)qpc.LowPart);
  _snwprintf_s(k->vendor, MAX_PATH, _TRUNCATE, L"%s\\LibreStatic", k->base);
  _snwprintf_s(k->root, MAX_PATH, _TRUNCATE, L"%s\\ShellDrive", k->vendor);
  if (!CreateDirectoryW(k->base, NULL) || !CreateDirectoryW(k->vendor, NULL) || !CreateDirectoryW(k->root, NULL))
    return 0;
  if (sd_ipc_current_identity(sid, SD_COUNTOF(sid), NULL) != SD_OK)
    return 0;
  _snwprintf_s(suffix, SD_COUNTOF(suffix), _TRUNCATE, L"svc%lu", (unsigned long)GetCurrentProcessId());
  sd_ipc_set_instance_suffix(suffix);
  sd_ipc_test_set_expected_owner(sid);
  sd_ipc_test_set_service_owner(sid);
  k->scm.query_service = t_query_service;
  k->scm.query_source = t_query_source;
  k->rops.owner_trusted = owner_flag;
  k->rops.extra_ace = L"(A;OICI;FA;;;OW)";
  k->o.backend = fake_backend();
  k->o.machine_root = k->root;
  k->o.open_log = 0;
  k->o.on_running = rp_on_running;
  k->o.ctx = k;
  k->o.test_all_admin = 1;
  k->o.owner_trusted = owner_flag;
  k->o.dacl_extra_ace = L"(A;OICI;FA;;;OW)";
  k->o.scm_ops = &k->scm;
  k->o.repair_ops = &k->rops;
  k->o.repair_base = k->base;
  k->running = CreateEventW(NULL, TRUE, FALSE, NULL);
  if (k->running == NULL)
    return 0;
  k->thread = CreateThread(NULL, 0, rp_main, k, 0, NULL);
  if (k->thread == NULL)
    return 0;
  return WaitForSingleObject(k->running, 15000) == WAIT_OBJECT_0;
}

static void rp_stop(rp_core *k)
{
  if (k->thread != NULL) {
    svc_request_stop();
    WaitForSingleObject(k->thread, 30000);
    CloseHandle(k->thread);
    k->thread = NULL;
  }
  if (k->running != NULL)
    CloseHandle(k->running);
  k->running = NULL;
}

static sd_err rp_connect(const char *kind, sd_ipc_conn **out)
{
  sd_ipc_hello h;
  memset(&h, 0, sizeof(h));
  h.client_kind = kind;
  h.client_version = "test";
  h.lang = "en";
  return sd_ipc_connect(SD_IPC_SERVICE, &h, 0, 10000, out);
}

static sd_json *rp_call(sd_ipc_conn *c, const char *method, sd_ipc_error *err, sd_err *rc)
{
  sd_json *res = NULL;
  sd_err e;
  memset(err, 0, sizeof(*err));
  e = sd_ipc_call_raw(c, method, NULL, 0, 20000, &res, err);
  if (rc)
    *rc = e;
  return res;
}

/* Removes a tree (the test folders hold no links). */
static void rp_remove_tree(const wchar_t *dir)
{
  WIN32_FIND_DATAW fd;
  HANDLE fh;
  wchar_t pattern[MAX_PATH], child[MAX_PATH];
  _snwprintf_s(pattern, MAX_PATH, _TRUNCATE, L"%s\\*", dir);
  fh = FindFirstFileW(pattern, &fd);
  if (fh != INVALID_HANDLE_VALUE) {
    do {
      if (lstrcmpW(fd.cFileName, L".") == 0 || lstrcmpW(fd.cFileName, L"..") == 0)
        continue;
      _snwprintf_s(child, MAX_PATH, _TRUNCATE, L"%s\\%s", dir, fd.cFileName);
      if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
        rp_remove_tree(child);
      else
        DeleteFileW(child);
    } while (FindNextFileW(fh, &fd));
    FindClose(fh);
  }
  RemoveDirectoryW(dir);
}

/* Removes the base with everything the repair left in it, the ".untrusted-<n>" folders included. */
static void rp_cleanup(const rp_core *k)
{
  rp_remove_tree(k->base);
}

static int wide_equals_utf8(const wchar_t *w, const char *u)
{
  char buf[MAX_PATH * 3];
  WideCharToMultiByte(CP_UTF8, 0, w, -1, buf, (int)sizeof(buf), NULL, NULL);
  buf[sizeof(buf) - 1] = 0;
  return u != NULL && strcmp(buf, u) == 0;
}

SD_TEST(svc_status_names_a_refused_machine_folder_for_admins_only)
{
  rp_core k;
  sd_ipc_conn *adm = NULL;
  sd_ipc_error err;
  sd_err e;
  sd_json *res;
  const sd_json *m;
  int b = 1;
  int64_t n = -1;
  g_trust = 0;                       /* every machine folder has a foreign owner */
  SD_REQUIRE(rp_start(&k));
  SD_REQUIRE(rp_connect("testadmin", &adm) == SD_OK);
  res = rp_call(adm, "service.status", &err, &e);
  SD_REQUIRE(res != NULL);
  SD_CHECK(sd_json_get_bool(sd_json_get(res, "pipe"), "healthy", &b) && !b);
  m = sd_json_get(res, "machine");
  SD_CHECK_STR(sd_json_get_str(m, "state"), "refused");
  SD_CHECK_STR(sd_json_get_str(m, "reason"), "owner");
  SD_CHECK(wide_equals_utf8(k.root, sd_json_get_str(m, "path")));
  SD_CHECK(sd_json_get_int64(m, "profiles", &n) && n == 0);
  sd_json_free(res);
  sd_ipc_close(adm);
  rp_stop(&k);
  rp_cleanup(&k);
}

SD_TEST(svc_repair_moves_the_folder_aside_and_the_service_recovers)
{
  rp_core k;
  sd_ipc_conn *adm = NULL;
  sd_ipc_error err;
  sd_err e;
  sd_json *res;
  const sd_json *m;
  int b = 0;
  g_trust = 0;
  SD_REQUIRE(rp_start(&k));
  SD_REQUIRE(rp_connect("testadmin", &adm) == SD_OK);

  /* 1: the owner rule still trusts nobody: the vendor folder is moved aside and recreated, and the layout is still
     refused afterwards (the fresh folder is owned by this process, which the seam does not trust) */
  res = rp_call(adm, "service.repair_data", &err, &e);
  SD_REQUIRE(res != NULL);
  SD_CHECK(sd_json_get_bool(res, "moved", &b) && b);
  SD_CHECK(sd_json_get_str(res, "moved_to") != NULL);
  SD_CHECK(sd_json_get_bool(res, "healthy", &b) && !b);
  sd_json_free(res);
  res = rp_call(adm, "service.status", &err, &e);
  SD_REQUIRE(res != NULL);
  SD_CHECK_STR(sd_json_get_str(sd_json_get(res, "machine"), "state"), "refused");
  sd_json_free(res);

  /* 2: the owner is trusted now: the repair keeps the tree, the service leaves the idle state */
  g_trust = 1;
  res = rp_call(adm, "service.repair_data", &err, &e);
  SD_REQUIRE(res != NULL);
  SD_CHECK(sd_json_get_bool(res, "moved", &b) && !b);
  SD_CHECK(sd_json_get_bool(res, "healthy", &b) && b);
  SD_CHECK(sd_json_get(res, "folders") != NULL);
  sd_json_free(res);
  res = rp_call(adm, "service.status", &err, &e);
  SD_REQUIRE(res != NULL);
  m = sd_json_get(res, "machine");
  SD_CHECK_STR(sd_json_get_str(m, "state"), "ok");
  SD_CHECK(sd_json_get_str(m, "path") == NULL);
  SD_CHECK(sd_json_get_bool(sd_json_get(res, "pipe"), "healthy", &b) && b);
  sd_json_free(res);
  /* the selftest agrees: the machine folder is in order again */
  res = rp_call(adm, "selftest", &err, &e);
  SD_REQUIRE(res != NULL);
  SD_CHECK(sd_json_get_bool(res, "healthy", &b) && b);
  sd_json_free(res);
  sd_ipc_close(adm);
  rp_stop(&k);
  SD_CHECK_EQ_INT(k.rc, 0);
  rp_cleanup(&k);
}
