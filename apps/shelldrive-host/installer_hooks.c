/* shelldrive-host --installer-hook <name> --apply|--revert (docs/design/03 §6.1, 04 §8.3).
 *
 * Hidden verbs run by the installers (the setup engine per user, MSI deferred actions per machine). Each is
 * idempotent. signal-shutdown is implemented here for the current account: it sets the shutdown events of
 * the agents of this user and session (04 §6.9 step 1). The other hooks are part of M5 (the service and
 * the Explorer/WebClient integration); they log that they are not implemented and succeed, so that an
 * installer run is not blocked by a hook that has nothing to do yet. */
#include <windows.h>
#include <sddl.h>
#include <strsafe.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>

#define SD_HOOK_AGENT_EVENT L"Global\\com.librestatic.shelldrive.agent.shutdown."

typedef BOOL (WINAPI *sd_ProcessIdToSessionId_t)(DWORD, DWORD *);

static const wchar_t *const k_hooks[] = {
  L"webdav-tune", L"user-cleanup", L"modern-menu", L"signal-shutdown", L"programdata-secure"
};

/* Shutdown events of this account's agent in this session (the current process session). */
static int signal_own_agents(void)
{
  HANDLE token = NULL;
  BYTE buf[256];
  DWORD need = 0;
  TOKEN_USER *tu = (TOKEN_USER *)buf;
  wchar_t *sid_text = NULL;
  wchar_t name[256];
  DWORD session = 0;
  HANDLE ev;
  sd_ProcessIdToSessionId_t sess_of;
  HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
  int rc = 1;

  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
    return 1;
  if (!GetTokenInformation(token, TokenUser, buf, sizeof(buf), &need) ||
      !ConvertSidToStringSidW(tu->User.Sid, &sid_text)) {
    CloseHandle(token);
    return 1;
  }
  CloseHandle(token);

  sess_of = k32 != NULL ? (sd_ProcessIdToSessionId_t)GetProcAddress(k32, "ProcessIdToSessionId") : NULL;
  if (sess_of == NULL || !sess_of(GetCurrentProcessId(), &session)) {
    LocalFree(sid_text);
    return 1;
  }

  StringCchPrintfW(name, sizeof(name) / sizeof(name[0]), L"%s%s.%lu", SD_HOOK_AGENT_EVENT, sid_text,
                   (unsigned long)session);
  LocalFree(sid_text);

  ev = OpenEventW(EVENT_MODIFY_STATE, FALSE, name);
  if (ev == NULL) {
    wprintf(L"signal-shutdown: no agent of this account is running in this session\n");
    return 0;
  }
  if (SetEvent(ev)) {
    wprintf(L"signal-shutdown: the agent was asked to exit\n");
    rc = 0;
  }
  CloseHandle(ev);
  return rc;
}

/* argv as given to wmain: argv[1] == "--installer-hook", argv[2] = name, then --apply or --revert. */
int sd_host_installer_hook(int argc, wchar_t **argv)
{
  const wchar_t *name;
  int known = 0;
  int apply = 0;
  int i;
  size_t k;

  if (argc < 4) {
    wprintf(L"usage: shelldrive-host --installer-hook <name> --apply|--revert\n");
    return 2;
  }
  name = argv[2];
  for (k = 0; k < sizeof(k_hooks) / sizeof(k_hooks[0]); k++) {
    if (wcscmp(name, k_hooks[k]) == 0)
      known = 1;
  }
  if (!known) {
    wprintf(L"shelldrive-host: unknown installer hook %s\n", name);
    return 2;
  }
  for (i = 3; i < argc; i++) {
    if (wcscmp(argv[i], L"--apply") == 0)
      apply = 1;
    else if (wcscmp(argv[i], L"--revert") != 0) {
      wprintf(L"shelldrive-host: unknown option %s\n", argv[i]);
      return 2;
    }
  }

  if (wcscmp(name, L"signal-shutdown") == 0) {
    if (!apply)
      return 0;                /* nothing to undo: the agents were asked to exit already */
    return signal_own_agents();
  }

  wprintf(L"installer hook %s: not yet implemented (M5)\n", name);
  return 0;
}
