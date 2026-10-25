/* shelldrive-host.exe: agent and service host (03 §1.2, §1.3; D3).
 *
 *   shelldrive-host agent [--logon]    per-user agent (single instance per user + session)
 *   shelldrive-host --selftest          health check, no network (exit 0 = healthy)
 *   shelldrive-host --version
 * The service mode (`service`) arrives in M5. The host does not localize (03 §9.3): it produces
 * codes, clients localize. */
#include <windows.h>
#include <string.h>

#include "host.h"
#include "sd/version.h"
#include "sd_config/sd_config.h"
#include "sd_ipc/sd_ipc.h"
#include "sd_platform/sd_log.h"
#include "sd_platform/sd_platform.h"

static void out(const wchar_t *s)
{
  HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
  DWORD n = (DWORD)lstrlenW(s), mode, written;
  if (h == NULL || h == INVALID_HANDLE_VALUE)
    return;
  if (GetConsoleMode(h, &mode)) {
    WriteConsoleW(h, s, n, &written, NULL);
  } else {
    char buf[1024];
    int len = WideCharToMultiByte(CP_UTF8, 0, s, (int)n, buf, (int)sizeof(buf), NULL, NULL);
    if (len > 0)
      WriteFile(h, buf, (DWORD)len, &written, NULL);
  }
}

#ifdef SD_HOST_TEST_HOOKS
/* Test builds only (tests/apps): isolate pipe names, configuration and idle timeout. */
static uint32_t apply_test_hooks(void)
{
  wchar_t v[MAX_PATH];
  uint32_t idle = 0;
  if (GetEnvironmentVariableW(L"SHELLDRIVE_TEST_INSTANCE", v, MAX_PATH) - 1u < MAX_PATH - 1u)
    sd_ipc_set_instance_suffix(v);
  if (GetEnvironmentVariableW(L"SHELLDRIVE_TEST_CONFIG_DIR", v, MAX_PATH) - 1u < MAX_PATH - 1u)
    sd_config_set_root_override(v);
  if (GetEnvironmentVariableW(L"SHELLDRIVE_TEST_IDLE_MS", v, MAX_PATH) - 1u < MAX_PATH - 1u) {
    const wchar_t *p;
    for (p = v; *p >= L'0' && *p <= L'9'; p++)
      idle = idle * 10u + (uint32_t)(*p - L'0');
  }
  return idle;
}
#endif

static void open_log(void)
{
  wchar_t dir[MAX_PATH];
  if (sd_config_ensure_dirs() == SD_OK && sd_config_logs_dir(dir, SD_COUNTOF(dir)) == SD_OK &&
      wcslen(dir) + 12 < SD_COUNTOF(dir)) {
    wcscat_s(dir, SD_COUNTOF(dir), L"\\agent.log");
    (void)sd_log_open_file(dir);
  }
}

static int selftest(void)
{
  wchar_t root[MAX_PATH];
  int ok = 1;
  if (sd_platform_init() != SD_OK) ok = 0;
  if (sd_config_root(root, SD_COUNTOF(root)) != SD_OK) ok = 0;
  out(ok ? L"selftest: ok\r\n" : L"selftest: failed\r\n");
  return ok ? 0 : 17;
}

int wmain(int argc, wchar_t **argv)
{
  host_agent_opts opts;
  int i, rc;
#ifdef SD_HOST_TEST_HOOKS
  uint32_t test_idle;
#endif
  sd_platform_harden_dll_search();
  sd_platform_init();
#ifdef SD_HOST_TEST_HOOKS
  test_idle = apply_test_hooks();
#endif
  if (argc >= 2 && (wcscmp(argv[1], L"--version") == 0 || wcscmp(argv[1], L"version") == 0)) {
    out(L"shelldrive-host " SD_VERSION_STRING_W L" (" TEXT(SD_FLAVOUR_NAME) L", " TEXT(SD_GIT_COMMIT) L")\r\n");
    return 0;
  }
  if (argc >= 2 && wcscmp(argv[1], L"--selftest") == 0)
    return selftest();
  if (argc >= 2 && wcscmp(argv[1], L"agent") == 0) {
    memset(&opts, 0, sizeof(opts));
    opts.idle_exit_ms = 5u * 60u * 1000u;
    for (i = 2; i < argc; i++) {
      if (wcscmp(argv[i], L"--logon") == 0)
        opts.logon = 1;
    }
#ifdef SD_HOST_TEST_HOOKS
    if (test_idle)
      opts.idle_exit_ms = test_idle;
#endif
    open_log();
    rc = host_agent_run(&opts);
    sd_log_close();
    return rc;
  }
  out(L"usage: shelldrive-host agent [--logon] | --selftest | --version\r\n");
  return 2;
}
