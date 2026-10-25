/* Windows OpenSSH agent client (01 §6.5): \\.\pipe\openssh-ssh-agent, or SSH_AUTH_SOCK when it names
 * a \\.\pipe\ path. Opened with SECURITY_IDENTIFICATION (the agent cannot impersonate us), overlapped
 * I/O with a 120 s timeout. TM-R08: before anything is written, the pipe owner must be LocalSystem
 * (the ssh-agent service; BUILTIN\Administrators is accepted too, the owner a LocalSystem service gets
 * by default) for the default pipe, or our own SID for a user pipe; the server process user, when it
 * can be read, must match the same principal. The default pipe is probed on Windows 10+ only. */
#include <windows.h>
#include <aclapi.h>
#include <string.h>

#include "sd_base/sd_buf.h"
#include "sd_base/sd_mem.h"
#include "sd_platform/sd_log.h"
#include "sd_platform/sd_platform.h"
#include "sd_platform/sd_time.h"
#include "sd_ssh/sd_ssh.h"
#include "agent_internal.h"

#define DEFAULT_PIPE L"\\\\.\\pipe\\openssh-ssh-agent"

typedef BOOL (WINAPI *pfn_GetNamedPipeServerProcessId)(HANDLE, PULONG);

/* Pipe name; *user_pipe = 1 for an SSH_AUTH_SOCK pipe. 0 when no pipe applies. */
static int pipe_name(wchar_t *out, size_t cap, int *user_pipe)
{
  wchar_t env[512];
  DWORD n = GetEnvironmentVariableW(L"SSH_AUTH_SOCK", env, SD_COUNTOF(env));
  *user_pipe = 0;
  if (n > 9 && n < SD_COUNTOF(env) && _wcsnicmp(env, L"\\\\.\\pipe\\", 9) == 0) {
    if ((size_t)n + 1 > cap) return 0;
    memcpy(out, env, ((size_t)n + 1) * sizeof(wchar_t));
    *user_pipe = 1;
    return 1;
  }
  if (!sd_os_at_least(10, 0, 0)) return 0;
  if (cap < SD_COUNTOF(DEFAULT_PIPE)) return 0;
  memcpy(out, DEFAULT_PIPE, sizeof(DEFAULT_PIPE));
  return 1;
}

static int sid_is(PSID s, DWORD rid1, DWORD rid2, BYTE count)
{
  SID_IDENTIFIER_AUTHORITY nt = SECURITY_NT_AUTHORITY;
  PSID w = NULL;
  int r;
  if (!s || !AllocateAndInitializeSid(&nt, count, rid1, rid2, 0, 0, 0, 0, 0, 0, &w)) return 0;
  r = EqualSid(s, w) ? 1 : 0;
  FreeSid(w);
  return r;
}

static int is_system(PSID s) { return sid_is(s, SECURITY_LOCAL_SYSTEM_RID, 0, 1); }
static int is_admins(PSID s) { return sid_is(s, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 2); }

static sd_err verify_pipe(HANDLE h, int user_pipe)
{
  PSID owner = NULL, me = NULL, server = NULL;
  PSECURITY_DESCRIPTOR psd = NULL;
  pfn_GetNamedPipeServerProcessId gp;
  ULONG pid = 0;
  sd_err e = SD_OK;
  if (GetSecurityInfo(h, SE_KERNEL_OBJECT, OWNER_SECURITY_INFORMATION, &owner, NULL, NULL, NULL, &psd) != ERROR_SUCCESS) {
    ssh_agent_warn_untrusted(SD_AGENT_OPENSSH, NULL);
    return SD_E_ACCESS_DENIED;
  }
  e = ssh_agent_self_sid(&me);
  if (e != SD_OK) { LocalFree(psd); return e; }
  if (user_pipe ? !EqualSid(owner, me) : !(is_system(owner) || is_admins(owner))) {
    ssh_agent_warn_untrusted(SD_AGENT_OPENSSH, owner);
    e = SD_E_ACCESS_DENIED;
  }
  gp = (pfn_GetNamedPipeServerProcessId)sd_platform_resolve_by_name(L"kernel32.dll", "GetNamedPipeServerProcessId");
  if (e == SD_OK && gp && gp(h, &pid)) {
    /* A LocalSystem server usually cannot be opened by a standard user; the owner check above
       already decided then. A readable token must name the expected principal. */
    if (ssh_agent_process_sid(pid, &server, NULL) == SD_OK) {
      if (user_pipe ? !EqualSid(server, me) : !is_system(server)) {
        ssh_agent_warn_untrusted(SD_AGENT_OPENSSH, server);
        e = SD_E_ACCESS_DENIED;
      }
    } else if (user_pipe) {
      ssh_agent_warn_untrusted(SD_AGENT_OPENSSH, NULL);
      e = SD_E_ACCESS_DENIED;
    }
  }
  sd_free(server);
  sd_free(me);
  LocalFree(psd);
  return e;
}

static sd_err open_pipe(HANDLE *out)
{
  wchar_t name[520];
  int user_pipe = 0, attempt;
  HANDLE h = INVALID_HANDLE_VALUE;
  sd_err e;
  *out = INVALID_HANDLE_VALUE;
  if (!pipe_name(name, SD_COUNTOF(name), &user_pipe)) return SD_E_UNSUPPORTED;
  for (attempt = 0; attempt < 2; attempt++) {
    h = CreateFileW(name, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING,
                    FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, NULL);
    if (h != INVALID_HANDLE_VALUE) break;
    if (GetLastError() != ERROR_PIPE_BUSY || attempt) {
      DWORD le = GetLastError();
      return le == ERROR_ACCESS_DENIED ? SD_E_ACCESS_DENIED : le == ERROR_PIPE_BUSY ? SD_E_BUSY : SD_E_NOT_FOUND;
    }
    if (!WaitNamedPipeW(name, 2000)) return SD_E_BUSY;
  }
  e = verify_pipe(h, user_pipe);
  if (e != SD_OK) { CloseHandle(h); return e; }
  *out = h;
  return SD_OK;
}

sd_err ssh_agent_pipe_probe(void)
{
  HANDLE h;
  sd_err e = open_pipe(&h);
  if (e == SD_OK) CloseHandle(h);
  return e;
}

/* Overlapped transfer of exactly n bytes with a deadline. */
static sd_err pipe_io(HANDLE h, HANDLE ev, int write, uint8_t *p, size_t n, uint64_t deadline)
{
  while (n) {
    OVERLAPPED ov;
    DWORD got = 0, chunk = (DWORD)SD_MIN(n, (size_t)65536);
    BOOL ok;
    uint64_t now = sd_tick_ms();
    memset(&ov, 0, sizeof(ov));
    ov.hEvent = ev;
    ResetEvent(ev);
    ok = write ? WriteFile(h, p, chunk, NULL, &ov) : ReadFile(h, p, chunk, NULL, &ov);
    if (!ok && GetLastError() != ERROR_IO_PENDING) return SD_E_DISCONNECTED;
    if (WaitForSingleObject(ev, now >= deadline ? 0 : (DWORD)(deadline - now)) != WAIT_OBJECT_0) {
      CancelIo(h);
      GetOverlappedResult(h, &ov, &got, TRUE);
      return SD_E_TIMEOUT;
    }
    if (!GetOverlappedResult(h, &ov, &got, FALSE) || got == 0) return SD_E_DISCONNECTED;
    p += got;
    n -= got;
  }
  return SD_OK;
}

sd_err ssh_agent_pipe_transact(const uint8_t *req, size_t n, uint8_t **resp, size_t *resp_len)
{
  HANDLE h, ev;
  uint8_t hdr[4];
  uint8_t *msg;
  uint32_t rl;
  uint64_t deadline;
  sd_err e;
  *resp = NULL;
  *resp_len = 0;
  if (!req || n == 0 || n > SD_AGENT_MAX_REPLY) return SD_E_INVALID_PARAM;
  e = open_pipe(&h);
  if (e != SD_OK) return e;
  ev = CreateEventW(NULL, TRUE, FALSE, NULL);
  if (!ev) { CloseHandle(h); return SD_E_INTERNAL; }
  deadline = sd_tick_ms() + SD_AGENT_TIMEOUT_MS;
  msg = (uint8_t *)sd_alloc(n + 4);
  if (!msg) { CloseHandle(ev); CloseHandle(h); return SD_E_NO_MEMORY; }
  sd_store_be32(msg, (uint32_t)n);
  memcpy(msg + 4, req, n);
  e = pipe_io(h, ev, 1, msg, n + 4, deadline);
  sd_secure_free(msg, n + 4);
  if (e == SD_OK) e = pipe_io(h, ev, 0, hdr, 4, deadline);
  if (e == SD_OK) {
    rl = sd_load_be32(hdr);
    if (rl == 0 || rl > SD_AGENT_MAX_REPLY) e = SD_E_PROTOCOL;
    else {
      *resp = (uint8_t *)sd_alloc(rl);
      if (!*resp) e = SD_E_NO_MEMORY;
      else {
        e = pipe_io(h, ev, 0, *resp, rl, deadline);
        if (e == SD_OK) *resp_len = rl;
        else { sd_free(*resp); *resp = NULL; }
      }
    }
  }
  CloseHandle(ev);
  CloseHandle(h);
  return e;
}
