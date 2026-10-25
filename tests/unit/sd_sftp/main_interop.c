/* sd-test-sftp-interop: sd_sftp against OpenSSH sftp-server inside WSL, over stdio pipes.
 * Test fixture only (D21). Exit code 77 = skipped (no wsl.exe or no sftp-server). */
#include <stdio.h>
#include <string.h>
#include <wchar.h>

#include "sd_platform/sd_log.h"
#include "sd_platform/sd_time.h"
#include "sd_test.h"
#include "interop.h"

sd_sftp_session *g_s;
proc_tp *g_proc;
char g_dir[128];
evlog g_ev;

SD_TEST_DECL(interop_crud);
SD_TEST_DECL(interop_extensions);
SD_TEST_DECL(interop_readdir_10k);
SD_TEST_DECL(interop_pipelined_64mib);
SD_TEST_DECL(interop_rename_overwrite);
SD_TEST_DECL(interop_error_mapping);
SD_TEST_DECL(interop_deadline_expiry);

static const sd_test_case k_tests[] = {
  SD_TEST_ENTRY(interop_crud),
  SD_TEST_ENTRY(interop_extensions),
  SD_TEST_ENTRY(interop_readdir_10k),
  SD_TEST_ENTRY(interop_pipelined_64mib),
  SD_TEST_ENTRY(interop_rename_overwrite),
  SD_TEST_ENTRY(interop_error_mapping),
  SD_TEST_ENTRY(interop_deadline_expiry),
};

static int wsl_path(wchar_t *out, size_t cap)
{
  UINT n = GetSystemDirectoryW(out, (UINT)cap);
  if (n == 0 || n + 10 >= cap) return 0;
  wcscat_s(out, cap, L"\\wsl.exe");
  return GetFileAttributesW(out) != INVALID_FILE_ATTRIBUTES;
}

int interop_wsl(const char *shell_cmd, uint32_t timeout_ms)
{
  wchar_t wsl[MAX_PATH], cmd[4096];
  if (!wsl_path(wsl, MAX_PATH)) return -1;
  if (_snwprintf_s(cmd, SD_COUNTOF(cmd), _TRUNCATE, L"\"%ls\" -e sh -c \"%hs\"", wsl, shell_cmd) < 0) return -1;
  return run_cmd(cmd, timeout_ms);
}

int main(int argc, char **argv)
{
  wchar_t wsl[MAX_PATH], cmd[1024];
  sd_sftp_transport t;
  sd_sftp_options opt;
  int rc, list_only = 0, a;
  char rm[256];

  for (a = 1; a < argc; a++) if (strcmp(argv[a], "--list") == 0) list_only = 1;
  if (list_only) return sd_test_main(k_tests, SD_COUNTOF(k_tests), argc, argv);

  sd_log_set_level(SD_LOG_ERROR);
  if (!wsl_path(wsl, MAX_PATH)) { printf("SKIP: wsl.exe not found\n"); return 77; }
  if (interop_wsl("test -x " SFTP_SERVER, 60000) != 0) { printf("SKIP: %s not available in WSL\n", SFTP_SERVER); return 77; }

  sprintf_s(g_dir, sizeof(g_dir), "/tmp/sd-sftp-test-%lu-%lu", GetCurrentProcessId(), (DWORD)sd_tick_ms());
  _snwprintf_s(cmd, SD_COUNTOF(cmd), _TRUNCATE,
               L"\"%ls\" -e sh -c \"mkdir -p %hs && cd %hs && exec " SFTP_SERVER_W L" -e -l ERROR\"", wsl, g_dir, g_dir);
  evlog_init(&g_ev);
  if (proc_new(cmd, &t, &g_proc) != SD_OK) { printf("cannot create transport\n"); return 1; }
  sd_sftp_options_init(&opt);
  if (sd_sftp_session_create_transport(&t, &opt, evlog_cb, &g_ev, &g_s) != SD_OK) { printf("create failed\n"); return 1; }
  if (sd_sftp_session_start(g_s) != SD_OK || sd_event_wait(&g_ev.ready, 60000) != SD_OK ||
      sd_sftp_session_state(g_s) != SD_SFTP_ST_READY) {
    printf("sftp-server session did not become ready\n");
    return 1;
  }
  printf("sftp-server ready: home=%s ext=0x%x max_read=%llu max_write=%llu\n", g_ev.home, g_ev.ext,
         (unsigned long long)g_ev.max_read, (unsigned long long)g_ev.max_write);

  rc = sd_test_main(k_tests, SD_COUNTOF(k_tests), argc, argv);

  (void)sd_sftp_session_close(g_s);
  (void)sd_event_wait(&g_ev.ended, 10000);
  sd_sftp_session_destroy(g_s);
  evlog_free(&g_ev);
  sprintf_s(rm, sizeof(rm), "chmod -R u+rwx %s; rm -rf %s", g_dir, g_dir);
  (void)interop_wsl(rm, 60000);
  return rc;
}
