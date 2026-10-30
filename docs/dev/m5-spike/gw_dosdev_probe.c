/* M5 global WebDAV spike (D11): per-user DOS device probe. Not shipped, not part of any build target.
 *
 * What it checks, without elevation (it refuses to run in an elevated token):
 *   A. DefineDosDeviceW in the caller's own logon session with the raw target form that mechanism B of
 *      docs/design/02-filesystem.md 7.7 would use (\Device\Mup\localhost@PORT\DavWWWRoot\s-<token>), then
 *      QueryDosDevice, then removal. The definition is session-local (no "Global\" prefix).
 *   B. The same with a "Global\" name. A standard user is expected to be denied (SeCreateGlobalPrivilege
 *      is needed for the global namespace). If the call succeeds, the probe removes the link at once and says so.
 * Every definition the probe creates is removed before it exits. It opens no device, starts no service and
 * touches no registry key.
 *
 * Build (VS 2022 Build Tools, x64 developer prompt):  cl /nologo /W4 /O2 gw_dosdev_probe.c advapi32.lib
 * Run:  gw_dosdev_probe.exe
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <wchar.h>

typedef LONG (WINAPI *pfn_RtlGetVersion)(OSVERSIONINFOEXW *);

static int is_elevated(int *elevated)
{
  HANDLE tok = NULL;
  TOKEN_ELEVATION te;
  DWORD cb = 0;
  *elevated = 0;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok))
    return 0;
  if (GetTokenInformation(tok, TokenElevation, &te, sizeof(te), &cb))
    *elevated = te.TokenIsElevated ? 1 : 0;
  CloseHandle(tok);
  return cb != 0;
}

static void print_identity(void)
{
  HANDLE tok = NULL;
  TOKEN_STATISTICS ts;
  DWORD cb = 0, sid = 0;
  pfn_RtlGetVersion rgv;
  OSVERSIONINFOEXW vi;
  HMODULE nt = GetModuleHandleW(L"ntdll.dll");

  memset(&vi, 0, sizeof(vi));
  vi.dwOSVersionInfoSize = sizeof(vi);
  rgv = nt ? (pfn_RtlGetVersion)GetProcAddress(nt, "RtlGetVersion") : NULL;
  if (rgv && rgv(&vi) == 0)
    printf("os: %lu.%lu build %lu sp %u.%u\n", (unsigned long)vi.dwMajorVersion, (unsigned long)vi.dwMinorVersion,
           (unsigned long)vi.dwBuildNumber, (unsigned)vi.wServicePackMajor, (unsigned)vi.wServicePackMinor);
  if (ProcessIdToSessionId(GetCurrentProcessId(), &sid))
    printf("session: %lu\n", (unsigned long)sid);
  if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) {
    if (GetTokenInformation(tok, TokenStatistics, &ts, sizeof(ts), &cb))
      printf("logon session LUID: %08lx%08lx\n", (unsigned long)ts.AuthenticationId.HighPart,
             (unsigned long)ts.AuthenticationId.LowPart);
    CloseHandle(tok);
  }
}

/* Defines name -> target (raw), reads it back, removes it. Returns 0 when every step behaved as expected
   for a session-local definition. */
static int raw_round_trip(const wchar_t *name, const wchar_t *target, int expect_denied)
{
  wchar_t back[512];
  DWORD n, err;
  int rc = 0;

  if (!DefineDosDeviceW(DDD_RAW_TARGET_PATH | DDD_NO_BROADCAST_SYSTEM, name, target)) {
    err = GetLastError();
    printf("  define %ls: FAILED error %lu\n", name, (unsigned long)err);
    return expect_denied && err == ERROR_ACCESS_DENIED ? 0 : 1;
  }
  printf("  define %ls: ok\n", name);
  if (expect_denied)
    printf("  NOTE: a standard user created a global definition; removing it now\n");

  n = QueryDosDeviceW(name, back, (DWORD)(sizeof(back) / sizeof(back[0])));
  if (n == 0) {
    printf("  query: FAILED error %lu\n", (unsigned long)GetLastError());
    rc = 1;
  } else {
    /* QueryDosDevice returns a double-NUL list of targets */
    printf("  query: %ls\n", back);
    if (wcscmp(back, target) != 0 && wcsstr(back, target) == NULL) {
      printf("  query: target differs from the defined one\n");
      rc = 1;
    }
  }

  if (!DefineDosDeviceW(DDD_RAW_TARGET_PATH | DDD_REMOVE_DEFINITION | DDD_EXACT_MATCH_ON_REMOVE |
                            DDD_NO_BROADCAST_SYSTEM, name, target)) {
    printf("  remove %ls: FAILED error %lu (left behind!)\n", name, (unsigned long)GetLastError());
    return 1;
  }
  printf("  remove %ls: ok\n", name);

  n = QueryDosDeviceW(name, back, (DWORD)(sizeof(back) / sizeof(back[0])));
  if (n != 0) {
    printf("  after remove: still defined (left behind!)\n");
    rc = 1;
  } else if (GetLastError() != ERROR_FILE_NOT_FOUND) {
    printf("  after remove: query error %lu\n", (unsigned long)GetLastError());
    rc = 1;
  } else {
    printf("  after remove: not defined\n");
  }
  return rc;
}

int main(void)
{
  int elevated = 0, rc = 0;
  wchar_t name_a[64], name_b[96];
  const wchar_t *target = L"\\Device\\Mup\\localhost@1\\DavWWWRoot\\s-probeprobeprobeprobeprobe";
  DWORD pid = GetCurrentProcessId();

  if (!is_elevated(&elevated)) {
    printf("could not read the token elevation; refusing to run\n");
    return 2;
  }
  if (elevated) {
    printf("elevated token: this probe runs only as a standard user; nothing was done\n");
    return 2;
  }
  print_identity();

  _snwprintf_s(name_a, sizeof(name_a) / sizeof(name_a[0]), _TRUNCATE, L"SDGWPROBE_%lu", (unsigned long)pid);
  _snwprintf_s(name_b, sizeof(name_b) / sizeof(name_b[0]), _TRUNCATE, L"Global\\SDGWPROBE_G%lu", (unsigned long)pid);
  name_a[63] = 0;
  name_b[95] = 0;

  printf("A. session-local raw device, mechanism B shape:\n");
  rc |= raw_round_trip(name_a, target, 0);

  printf("B. global namespace (Global\\ prefix), standard user:\n");
  rc |= raw_round_trip(name_b, target, 1);

  printf(rc ? "result: FAILED (see lines above)\n" : "result: ok, nothing left defined\n");
  return rc ? 1 : 0;
}
