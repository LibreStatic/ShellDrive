/* shelldrive-setup: running agents (docs/design/04 §6.9 step 1, 03 §2.1, C3).
   Setup finds shelldrive-host.exe processes with Toolhelp (resolved at run time: not on the XP floor
   list), reads each owner SID and session id, and sets the agent's manual-reset shutdown event
   Global\com.librestatic.shelldrive.agent.shutdown.<SID>.<SessionId>. Pipes are never enumerated. */
#include "setup_int.h"

#include <tlhelp32.h>
#include <string.h>
#include <sddl.h>

typedef HANDLE (WINAPI *sd_CreateToolhelp32Snapshot_t)(DWORD, DWORD);
typedef BOOL (WINAPI *sd_Process32FirstW_t)(HANDLE, PROCESSENTRY32W *);
typedef BOOL (WINAPI *sd_Process32NextW_t)(HANDLE, PROCESSENTRY32W *);

#define SD_AGENT_EXE L"shelldrive-host.exe"
#define SD_AGENT_EVENT_PREFIX L"Global\\com.librestatic.shelldrive.agent.shutdown."

/* SID string of the token owner of a process; 0 on success. */
static int process_user_sid(DWORD pid, wchar_t *sid_out, size_t cch)
{
  HANDLE proc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
  HANDLE token = NULL;
  BYTE buf[256];
  DWORD need = 0;
  wchar_t *sid_text = NULL;
  int rc = 1;

  if (proc == NULL)
    return 1;
  if (OpenProcessToken(proc, TOKEN_QUERY, &token) && GetTokenInformation(token, TokenUser, buf, sizeof(buf), &need)) {
    TOKEN_USER *tu = (TOKEN_USER *)buf;
    if (ConvertSidToStringSidW(tu->User.Sid, &sid_text)) {
      if (SUCCEEDED(StringCchCopyW(sid_out, cch, sid_text)))
        rc = 0;
      LocalFree(sid_text);
    }
  }
  if (token != NULL)
    CloseHandle(token);
  CloseHandle(proc);
  return rc;
}

/* Walks the agent processes. mode 0 counts those of owner (or the current user), mode 1 also signals
   their shutdown events. Returns the number matched; the signalled count goes to *signalled. */
static unsigned walk_agents(const wchar_t *owner, int signal, unsigned *signalled)
{
  sd_CreateToolhelp32Snapshot_t snap;
  sd_Process32FirstW_t first;
  sd_Process32NextW_t next;
  HANDLE shot;
  PROCESSENTRY32W pe;
  unsigned matched = 0;
  wchar_t mine[128];

  snap = (sd_CreateToolhelp32Snapshot_t)sd_setup_proc(L"kernel32.dll", "CreateToolhelp32Snapshot");
  first = (sd_Process32FirstW_t)sd_setup_proc(L"kernel32.dll", "Process32FirstW");
  next = (sd_Process32NextW_t)sd_setup_proc(L"kernel32.dll", "Process32NextW");
  if (signalled != NULL)
    *signalled = 0;
  if (snap == NULL || first == NULL || next == NULL)
    return 0;

  if (owner == NULL) {
    if (sd_setup_current_sid(mine, SD_SETUP_COUNTOF(mine)) != 0)
      return 0;
    owner = mine;
  }

  shot = snap(TH32CS_SNAPPROCESS, 0);
  if (shot == INVALID_HANDLE_VALUE)
    return 0;
  memset(&pe, 0, sizeof(pe));
  pe.dwSize = sizeof(pe);
  if (first(shot, &pe)) {
    do {
      wchar_t sid[128];
      DWORD session = 0;
      if (_wcsicmp(pe.szExeFile, SD_AGENT_EXE) != 0)
        continue;
      if (process_user_sid(pe.th32ProcessID, sid, SD_SETUP_COUNTOF(sid)) != 0)
        continue;
      if (_wcsicmp(sid, owner) != 0)
        continue;
      matched++;
      if (signal) {
        wchar_t name[256];
        HANDLE ev;
        if (!ProcessIdToSessionId(pe.th32ProcessID, &session))
          continue;
        StringCchPrintfW(name, SD_SETUP_COUNTOF(name), L"%s%s.%lu", SD_AGENT_EVENT_PREFIX, sid,
                         (unsigned long)session);
        ev = OpenEventW(EVENT_MODIFY_STATE, FALSE, name);
        if (ev != NULL) {
          if (SetEvent(ev) && signalled != NULL)
            (*signalled)++;
          CloseHandle(ev);
        }
      }
    } while (next(shot, &pe));
  }
  CloseHandle(shot);
  return matched;
}

int sd_setup_current_sid(wchar_t *out, size_t cch)
{
  return process_user_sid(GetCurrentProcessId(), out, cch);
}

int sd_setup_signal_agents(const wchar_t *owner_sid, unsigned *signalled)
{
  unsigned n = 0;
  walk_agents(owner_sid, 1, &n);
  if (signalled != NULL)
    *signalled = n;
  return 0;
}

int sd_setup_wait_agents(unsigned timeout_ms, unsigned *still)
{
  unsigned waited = 0;
  unsigned n;

  for (;;) {
    n = walk_agents(NULL, 0, NULL);
    if (n == 0 || waited >= timeout_ms)
      break;
    Sleep(200);
    waited += 200;
  }
  if (still != NULL)
    *still = n;
  return 0;
}
