/* shelldrive-host --installer-hook <name> --apply|--revert (docs/design/03 §6.1, 04 §8.3).
 *
 * Hidden verbs run by the installers (the setup engine per user, MSI deferred actions per machine). Each is
 * idempotent. signal-shutdown is implemented here for the current account: it sets the shutdown events of
 * the agents of this user and session (04 §6.9 step 1). The other hooks are part of M5 (the service and
 * the Explorer/WebClient integration); they log that they are not implemented and succeed, so that an
 * installer run is not blocked by a hook that has nothing to do yet. */
#include <windows.h>
#include <sddl.h>
#include <shlobj.h>
#include <strsafe.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>

#include "svc_repair.h"

#define SD_HOOK_AGENT_EVENT L"Global\\com.librestatic.shelldrive.agent.shutdown."

typedef BOOL (WINAPI *sd_ProcessIdToSessionId_t)(DWORD, DWORD *);

static const wchar_t *const k_hooks[] = {
  L"webdav-tune", L"user-cleanup", L"modern-menu", L"signal-shutdown", L"programdata-secure"
};

/* %ProgramData%\LibreStatic and \ShellDrive are checked by handle and set back to the 3.2 DACLs; an untrusted folder is
   moved aside (TM-R34, 04 §6.4). The same repair the setup stub runs before any elevated write. */
static int programdata_secure(void)
{
  wchar_t base[MAX_PATH];
  svc_repair_ops ops;
  svc_repair_result rr;
  DWORD err;

  if (FAILED(SHGetFolderPathW(NULL, CSIDL_COMMON_APPDATA, NULL, SHGFP_TYPE_CURRENT, base))) {
    wprintf(L"programdata-secure: the common application data folder is not known\n");
    return 1;
  }
  svc_repair_real_ops(&ops);
  memset(&rr, 0, sizeof(rr));
  err = svc_repair_data(&ops, base, &rr);
  if (err != 0) {
    wprintf(L"programdata-secure: the ProgramData folders could not be secured (error %lu)\n", (unsigned long)err);
    return 1;
  }
  if (rr.moved)
    wprintf(L"programdata-secure: an untrusted folder was moved aside to %s\n", rr.path);
  return 0;
}

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

  if (wcscmp(name, L"programdata-secure") == 0) {
    /* Nothing to undo: the folders are trusted and stay. */
    if (!apply)
      return 0;
    return programdata_secure();
  }

  wprintf(L"installer hook %s: not yet implemented (M5)\n", name);
  return 0;
}
