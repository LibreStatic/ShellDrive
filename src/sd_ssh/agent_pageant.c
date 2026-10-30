/* Pageant client (01 §6.5): WM_COPYDATA naming a file mapping "PageantRequest%08x" owned by our user
 * SID; request and reply are "uint32 len || message" in the view. TM-R08: the Pageant window must
 * belong to a process whose token user is ours and whose integrity level is at least ours. */
#include <windows.h>
#include <stdio.h>
#include <string.h>

#include "sd_base/sd_buf.h"
#include "sd_base/sd_mem.h"
#include "sd_platform/sd_log.h"
#include "sd_platform/sd_platform.h"
#include "sd_ssh/sd_ssh.h"
#include "agent_internal.h"

#pragma comment(lib, "user32.lib")

#define PAGEANT_COPYDATA_ID 0x804e50baul
#define PAGEANT_MAP_SIZE    SD_AGENT_MAX_REPLY

typedef DWORD (WINAPI *pfn_GetWindowThreadProcessId)(HWND, LPDWORD);

static sd_err token_user_sid(HANDLE tok, PSID *out)
{
  DWORD need = 0;
  TOKEN_USER *tu;
  DWORD sl;
  *out = NULL;
  GetTokenInformation(tok, TokenUser, NULL, 0, &need);
  if (need == 0 || need > 4096) return SD_E_ACCESS_DENIED;
  tu = (TOKEN_USER *)sd_alloc(need);
  if (!tu) return SD_E_NO_MEMORY;
  if (!GetTokenInformation(tok, TokenUser, tu, need, &need)) { sd_free(tu); return SD_E_ACCESS_DENIED; }
  sl = GetLengthSid(tu->User.Sid);
  *out = sd_alloc(sl);
  if (!*out) { sd_free(tu); return SD_E_NO_MEMORY; }
  if (!CopySid(sl, *out, tu->User.Sid)) { sd_free(*out); *out = NULL; sd_free(tu); return SD_E_INTERNAL; }
  sd_free(tu);
  return SD_OK;
}

uint32_t ssh_agent_token_integrity(HANDLE tok)
{
  uint8_t buf[128];
  DWORD need = 0;
  TOKEN_MANDATORY_LABEL *ml = (TOKEN_MANDATORY_LABEL *)buf;
  SID *s;
  if (!sd_os_at_least(6, 0, 0)) return 0;
  if (!GetTokenInformation(tok, TokenIntegrityLevel, buf, sizeof(buf), &need)) return 0;
  s = (SID *)ml->Label.Sid;
  if (!s || s->SubAuthorityCount == 0) return 0;
  return (uint32_t)s->SubAuthority[s->SubAuthorityCount - 1];
}

sd_err ssh_agent_self_sid(PSID *out)
{
  HANDLE tok = NULL;
  sd_err e;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) return SD_E_INTERNAL;
  e = token_user_sid(tok, out);
  CloseHandle(tok);
  return e;
}

static uint32_t self_integrity(void)
{
  HANDLE tok = NULL;
  uint32_t il;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) return 0;
  il = ssh_agent_token_integrity(tok);
  CloseHandle(tok);
  return il;
}

sd_err ssh_agent_process_sid(DWORD pid, PSID *out, uint32_t *integrity)
{
  DWORD access = sd_os_at_least(6, 0, 0) ? 0x1000u /* PROCESS_QUERY_LIMITED_INFORMATION */ : PROCESS_QUERY_INFORMATION;
  HANDLE ph, tok = NULL;
  sd_err e;
  *out = NULL;
  if (integrity) *integrity = 0;
  ph = OpenProcess(access, FALSE, pid);
  if (!ph) return SD_E_ACCESS_DENIED;
  if (!OpenProcessToken(ph, TOKEN_QUERY, &tok)) { CloseHandle(ph); return SD_E_ACCESS_DENIED; }
  e = token_user_sid(tok, out);
  if (e == SD_OK && integrity) *integrity = ssh_agent_token_integrity(tok);
  CloseHandle(tok);
  CloseHandle(ph);
  return e;
}

/* TM-R08: the window's owner process must run as us, with integrity >= ours. */
static sd_err verify_window(HWND hwnd)
{
  pfn_GetWindowThreadProcessId gwtp =
      (pfn_GetWindowThreadProcessId)sd_platform_resolve_by_name(L"user32.dll", "GetWindowThreadProcessId");
  DWORD pid = 0;
  PSID me = NULL, theirs = NULL;
  uint32_t il = 0;
  sd_err e;
  if (!gwtp || !gwtp(hwnd, &pid) || pid == 0) { ssh_agent_warn_untrusted(SD_AGENT_PAGEANT, NULL); return SD_E_ACCESS_DENIED; }
  e = ssh_agent_self_sid(&me);
  if (e != SD_OK) return e;
  e = ssh_agent_process_sid(pid, &theirs, &il);
  if (e != SD_OK || !EqualSid(me, theirs) || (sd_os_at_least(6, 0, 0) && il < self_integrity())) {
    ssh_agent_warn_untrusted(SD_AGENT_PAGEANT, theirs);
    e = SD_E_ACCESS_DENIED;
  }
  sd_free(me);
  sd_free(theirs);
  return e;
}

/* The protocol name, unless a unit test points the client at its own fake (ssh_pageant_test_set_window_name). */
static const wchar_t *g_pageant_window = L"Pageant";

void ssh_pageant_test_set_window_name(const wchar_t *name)
{
  g_pageant_window = name ? name : L"Pageant";
}

static HWND find_pageant(void) { return FindWindowW(g_pageant_window, g_pageant_window); }

sd_err ssh_pageant_probe(void)
{
  HWND h = find_pageant();
  if (!h) return SD_E_NOT_FOUND;
  return verify_window(h);
}

sd_err ssh_pageant_transact(const uint8_t *req, size_t n, uint8_t **resp, size_t *resp_len)
{
  HWND hwnd;
  char name[64];
  SECURITY_ATTRIBUTES sa;
  SECURITY_DESCRIPTOR sd;
  PSID me = NULL;
  HANDLE map;
  uint8_t *view;
  COPYDATASTRUCT cds;
  DWORD_PTR res = 0;
  uint32_t rl;
  wchar_t wname[64];
  sd_err e;
  *resp = NULL;
  *resp_len = 0;
  if (!req || n == 0 || n > PAGEANT_MAP_SIZE - 4) return SD_E_INVALID_PARAM;
  hwnd = find_pageant();
  if (!hwnd) return SD_E_NOT_FOUND;
  e = verify_window(hwnd);
  if (e != SD_OK) return e;
  e = ssh_agent_self_sid(&me);
  if (e != SD_OK) return e;
  /* Pageant refuses mappings whose owner is not the user SID */
  if (!InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION) || !SetSecurityDescriptorOwner(&sd, me, FALSE)) {
    sd_free(me);
    return SD_E_INTERNAL;
  }
  sa.nLength = sizeof(sa);
  sa.lpSecurityDescriptor = &sd;
  sa.bInheritHandle = FALSE;
  _snprintf_s(name, sizeof(name), _TRUNCATE, "PageantRequest%08x", (unsigned)GetCurrentThreadId());
  _snwprintf_s(wname, SD_COUNTOF(wname), _TRUNCATE, L"PageantRequest%08x", (unsigned)GetCurrentThreadId());
  map = CreateFileMappingW(INVALID_HANDLE_VALUE, &sa, PAGE_READWRITE, 0, PAGEANT_MAP_SIZE, wname);
  sd_free(me);
  if (!map) return SD_E_INTERNAL;
  if (GetLastError() == ERROR_ALREADY_EXISTS) { CloseHandle(map); return SD_E_BUSY; }
  view = (uint8_t *)MapViewOfFile(map, FILE_MAP_WRITE, 0, 0, 0);
  if (!view) { CloseHandle(map); return SD_E_INTERNAL; }
  sd_store_be32(view, (uint32_t)n);
  memcpy(view + 4, req, n);
  cds.dwData = PAGEANT_COPYDATA_ID;
  cds.cbData = (DWORD)strlen(name) + 1;
  cds.lpData = name;
  if (!SendMessageTimeoutW(hwnd, WM_COPYDATA, 0, (LPARAM)&cds, SMTO_ABORTIFHUNG, SD_AGENT_TIMEOUT_MS, &res)) {
    e = GetLastError() == ERROR_TIMEOUT ? SD_E_TIMEOUT : SD_E_NOT_FOUND;
  } else if (res == 0) {
    e = SD_E_AUTH_FAILED;      /* Pageant refused the request (e.g. mapping owner check) */
  } else {
    rl = sd_load_be32(view);
    if (rl == 0 || rl > PAGEANT_MAP_SIZE - 4) {
      e = SD_E_PROTOCOL;
    } else {
      *resp = (uint8_t *)sd_alloc(rl);
      if (!*resp) e = SD_E_NO_MEMORY;
      else {
        memcpy(*resp, view + 4, rl);
        *resp_len = rl;
        e = SD_OK;
      }
    }
  }
  SecureZeroMemory(view, PAGEANT_MAP_SIZE);
  UnmapViewOfFile(view);
  CloseHandle(map);
  return e;
}
