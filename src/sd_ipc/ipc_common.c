/* sd_ipc common parts: names (D45), identity, named kernel objects (TM-R26), error table (C25). */
#include <windows.h>
#include <sddl.h>
#include <aclapi.h>
#include <string.h>

#include "ipc_internal.h"
#include "sd_base/sd_mem.h"
#include "sd_platform/sd_platform.h"
#include "sd_platform/sd_thread.h"

/* ---- hooks ---- */

static wchar_t g_suffix[64];
static wchar_t g_owner_override[192];
static wchar_t g_agent_path[MAX_PATH];

void sd_ipc_set_instance_suffix(const wchar_t *suffix)
{
  g_suffix[0] = 0;
  if (suffix && suffix[0])
    ipc_wcat(g_suffix, SD_COUNTOF(g_suffix), suffix);
}

void sd_ipc_test_set_expected_owner(const wchar_t *sid_string)
{
  g_owner_override[0] = 0;
  if (sid_string && sid_string[0])
    ipc_wcat(g_owner_override, SD_COUNTOF(g_owner_override), sid_string);
}

void sd_ipc_set_agent_path(const wchar_t *path)
{
  g_agent_path[0] = 0;
  if (path && path[0])
    ipc_wcat(g_agent_path, SD_COUNTOF(g_agent_path), path);
}

const wchar_t *ipc_instance_suffix(void) { return g_suffix; }
const wchar_t *ipc_expected_owner_override(void) { return g_owner_override[0] ? g_owner_override : NULL; }
const wchar_t *ipc_agent_path_override(void) { return g_agent_path[0] ? g_agent_path : NULL; }

/* ---- strings ---- */

int ipc_wcat(wchar_t *dst, size_t cch, const wchar_t *src)
{
  size_t n = wcslen(dst), i = 0;
  if (cch == 0)
    return 0;
  while (src[i]) {
    if (n + 1 >= cch) {
      dst[n] = 0;
      return 0;
    }
    dst[n++] = src[i++];
  }
  dst[n] = 0;
  return 1;
}

int ipc_wcat_u32(wchar_t *dst, size_t cch, uint32_t v)
{
  wchar_t tmp[12], out[12];
  size_t n = 0, i = 0;
  do { tmp[n++] = (wchar_t)(L'0' + v % 10u); v /= 10u; } while (v);
  while (n) out[i++] = tmp[--n];
  out[i] = 0;
  return ipc_wcat(dst, cch, out);
}

/* ---- identity ---- */

sd_err ipc_token_user_sid(HANDLE token, PSID *out)
{
  uint8_t buf[256];
  DWORD len = 0;
  TOKEN_USER *tu = (TOKEN_USER *)buf;
  DWORD sid_len;
  PSID copy;
  *out = NULL;
  if (!GetTokenInformation(token, TokenUser, buf, sizeof(buf), &len))
    return SD_E_ACCESS_DENIED;
  if (!IsValidSid(tu->User.Sid))
    return SD_E_ACCESS_DENIED;
  sid_len = GetLengthSid(tu->User.Sid);
  copy = sd_alloc(sid_len);
  if (copy == NULL)
    return SD_E_NO_MEMORY;
  if (!CopySid(sid_len, copy, tu->User.Sid)) {
    sd_free(copy);
    return SD_E_INTERNAL;
  }
  *out = copy;
  return SD_OK;
}

sd_err ipc_process_user_sid(PSID *out)
{
  HANDLE tok;
  sd_err e;
  *out = NULL;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok))
    return SD_E_ACCESS_DENIED;
  e = ipc_token_user_sid(tok, out);
  CloseHandle(tok);
  return e;
}

sd_err ipc_sid_to_string(PSID sid, wchar_t **out)
{
  LPWSTR s = NULL;
  size_t n;
  wchar_t *copy;
  *out = NULL;
  if (!ConvertSidToStringSidW(sid, &s))
    return SD_E_INTERNAL;
  n = wcslen(s);
  copy = (wchar_t *)sd_alloc((n + 1) * sizeof(wchar_t));
  if (copy == NULL) {
    LocalFree(s);
    return SD_E_NO_MEMORY;
  }
  memcpy(copy, s, (n + 1) * sizeof(wchar_t));
  LocalFree(s);
  *out = copy;
  return SD_OK;
}

sd_err sd_ipc_current_identity(wchar_t *sid_out, size_t sid_cch, DWORD *session_id)
{
  PSID sid;
  wchar_t *s;
  sd_err e;
  if (sid_out == NULL || sid_cch == 0)
    return SD_E_INVALID_PARAM;
  sid_out[0] = 0;
  e = ipc_process_user_sid(&sid);
  if (e != SD_OK)
    return e;
  e = ipc_sid_to_string(sid, &s);
  sd_free(sid);
  if (e != SD_OK)
    return e;
  if (!ipc_wcat(sid_out, sid_cch, s))
    e = SD_E_INVALID_PARAM;
  sd_free(s);
  if (e == SD_OK && session_id) {
    if (!ProcessIdToSessionId(GetCurrentProcessId(), session_id))
      *session_id = 0;
  }
  return e;
}

/* ---- names ---- */

static int add_suffix(wchar_t *out, size_t cch)
{
  if (g_suffix[0] == 0)
    return 1;
  return ipc_wcat(out, cch, L".") && ipc_wcat(out, cch, g_suffix);
}

sd_err sd_ipc_pipe_name(sd_ipc_endpoint ep, const wchar_t *user_sid, DWORD session_id,
                        wchar_t *out, size_t cch)
{
  int ok;
  if (out == NULL || cch == 0)
    return SD_E_INVALID_PARAM;
  out[0] = 0;
  if (ep == SD_IPC_SERVICE) {
    ok = ipc_wcat(out, cch, SD_IPC_SERVICE_PIPE);
  } else {
    if (user_sid == NULL || user_sid[0] == 0)
      return SD_E_INVALID_PARAM;
    ok = ipc_wcat(out, cch, SD_IPC_PIPE_PREFIX L"agent.") && ipc_wcat(out, cch, user_sid) &&
         ipc_wcat(out, cch, L".") && ipc_wcat_u32(out, cch, session_id);
  }
  ok = ok && add_suffix(out, cch);
  return ok ? SD_OK : SD_E_INVALID_PARAM;
}

sd_err sd_ipc_object_name(sd_ipc_object obj, wchar_t *out, size_t cch)
{
  wchar_t sid[192];
  DWORD session = 0;
  int ok;
  sd_err e;
  if (out == NULL || cch == 0)
    return SD_E_INVALID_PARAM;
  out[0] = 0;
  e = sd_ipc_current_identity(sid, SD_COUNTOF(sid), &session);
  if (e != SD_OK)
    return e;
  switch (obj) {
  case SD_IPC_OBJ_AGENT_MUTEX:
    ok = ipc_wcat(out, cch, L"Local\\com.librestatic.shelldrive.agent.") && ipc_wcat(out, cch, sid);
    break;
  case SD_IPC_OBJ_AGENT_READY:
    ok = ipc_wcat(out, cch, L"Local\\com.librestatic.shelldrive.agent.ready.") && ipc_wcat(out, cch, sid);
    break;
  case SD_IPC_OBJ_AGENT_STOP:
    ok = ipc_wcat(out, cch, L"Global\\com.librestatic.shelldrive.agent.shutdown.") && ipc_wcat(out, cch, sid) &&
         ipc_wcat(out, cch, L".") && ipc_wcat_u32(out, cch, session);
    break;
  default:
    return SD_E_INVALID_PARAM;
  }
  ok = ok && add_suffix(out, cch);
  return ok ? SD_OK : SD_E_INVALID_PARAM;
}

/* ---- security descriptors and owner checks ---- */

sd_err ipc_sd_from_sddl(const wchar_t *sddl, PSECURITY_DESCRIPTOR *out)
{
  *out = NULL;
  if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1, out, NULL))
    return SD_E_INTERNAL;
  return SD_OK;
}

#ifndef LABEL_SECURITY_INFORMATION
#define LABEL_SECURITY_INFORMATION 0x00000010L
#endif
#ifndef SYSTEM_MANDATORY_LABEL_ACE_TYPE
#define SYSTEM_MANDATORY_LABEL_ACE_TYPE 0x11
#endif

static DWORD sid_last_rid(PSID p)
{
  SID *s = (SID *)p;
  if (s == NULL || s->SubAuthorityCount == 0)
    return 0;
  return s->SubAuthority[s->SubAuthorityCount - 1];
}

sd_err ipc_verify_object_owner(HANDLE h, PSID expected, int check_label)
{
  PSID owner = NULL;
  PACL sacl = NULL;
  PSECURITY_DESCRIPTOR sd = NULL;
  SECURITY_INFORMATION si = OWNER_SECURITY_INFORMATION;
  int vista = sd_os_at_least(6, 0, 0);
  sd_err e = SD_E_ACCESS_DENIED;
  if (check_label && vista)
    si |= LABEL_SECURITY_INFORMATION;
  if (GetSecurityInfo(h, SE_KERNEL_OBJECT, si, &owner, NULL, NULL, check_label && vista ? &sacl : NULL,
                      &sd) != ERROR_SUCCESS) {
    /* Without the label right, fall back to the owner alone. */
    if (!(si & LABEL_SECURITY_INFORMATION) ||
        GetSecurityInfo(h, SE_KERNEL_OBJECT, OWNER_SECURITY_INFORMATION, &owner, NULL, NULL, NULL, &sd) !=
            ERROR_SUCCESS)
      return SD_E_ACCESS_DENIED;
    sacl = NULL;
  }
  if (owner && IsValidSid(owner) && EqualSid(owner, expected)) {
    e = SD_OK;
    if (sacl) {
      ACL_SIZE_INFORMATION info;
      DWORD i;
      if (GetAclInformation(sacl, &info, sizeof(info), AclSizeInformation)) {
        for (i = 0; i < info.AceCount; i++) {
          ACE_HEADER *ace = NULL;
          if (GetAce(sacl, i, (LPVOID *)&ace) && ace->AceType == SYSTEM_MANDATORY_LABEL_ACE_TYPE) {
            /* SYSTEM_MANDATORY_LABEL_ACE: header, mask, SID */
            PSID label = (PSID)((uint8_t *)ace + sizeof(ACE_HEADER) + sizeof(DWORD));
            if (sid_last_rid(label) < 0x2000)
              e = SD_E_ACCESS_DENIED;   /* below medium: planted by a low-integrity process */
          }
        }
      }
    }
  }
  LocalFree(sd);
  return e;
}

int ipc_token_integrity(HANDLE token, DWORD *rid)
{
  uint8_t buf[128];
  DWORD len = 0;
  if (!GetTokenInformation(token, (TOKEN_INFORMATION_CLASS)25 /* TokenIntegrityLevel */, buf, sizeof(buf), &len))
    return 0;
  *rid = sid_last_rid(((SID_AND_ATTRIBUTES *)buf)->Sid);
  return 1;
}

/* ---- named kernel objects ---- */

static sd_err object_sddl(sd_ipc_object obj, wchar_t *out, size_t cch)
{
  wchar_t sid[192];
  int ok;
  sd_err e = sd_ipc_current_identity(sid, SD_COUNTOF(sid), NULL);
  if (e != SD_OK)
    return e;
  out[0] = 0;
  if (obj == SD_IPC_OBJ_AGENT_STOP) {
    /* EVENT_MODIFY_STATE | SYNCHRONIZE for the user, SYSTEM and Administrators (03 §1.2) */
    ok = ipc_wcat(out, cch, L"O:") && ipc_wcat(out, cch, sid) && ipc_wcat(out, cch, L"D:P(A;;0x00100002;;;") &&
         ipc_wcat(out, cch, sid) && ipc_wcat(out, cch, L")(A;;0x00100002;;;SY)(A;;0x00100002;;;BA)");
  } else {
    ok = ipc_wcat(out, cch, L"O:") && ipc_wcat(out, cch, sid) && ipc_wcat(out, cch, L"D:P(A;;GA;;;") &&
         ipc_wcat(out, cch, sid) && ipc_wcat(out, cch, L")(A;;GA;;;SY)");
  }
  if (ok && sd_os_at_least(6, 0, 0))
    ok = ipc_wcat(out, cch, L"S:(ML;;NW;;;ME)");
  return ok ? SD_OK : SD_E_INVALID_PARAM;
}

sd_err sd_ipc_object_create(sd_ipc_object obj, HANDLE *out, int *existed)
{
  wchar_t name[IPC_NAME_CCH], sddl[512];
  PSECURITY_DESCRIPTOR sd = NULL;
  SECURITY_ATTRIBUTES sa;
  HANDLE h;
  DWORD gle;
  PSID me = NULL;
  sd_err e;
  *out = NULL;
  if (existed) *existed = 0;
  e = sd_ipc_object_name(obj, name, SD_COUNTOF(name));
  if (e == SD_OK) e = object_sddl(obj, sddl, SD_COUNTOF(sddl));
  if (e == SD_OK) e = ipc_sd_from_sddl(sddl, &sd);
  if (e != SD_OK)
    return e;
  sa.nLength = sizeof(sa);
  sa.lpSecurityDescriptor = sd;
  sa.bInheritHandle = FALSE;
  if (obj == SD_IPC_OBJ_AGENT_MUTEX)
    h = CreateMutexW(&sa, FALSE, name);
  else
    h = CreateEventW(&sa, TRUE, FALSE, name);
  gle = GetLastError();
  LocalFree(sd);
  if (h == NULL)
    return gle == ERROR_ACCESS_DENIED ? SD_E_ACCESS_DENIED : SD_E_INTERNAL;
  if (gle == ERROR_ALREADY_EXISTS) {
    e = ipc_process_user_sid(&me);
    if (e == SD_OK)
      e = ipc_verify_object_owner(h, me, 1);
    sd_free(me);
    if (e != SD_OK) {
      CloseHandle(h);
      return SD_E_ACCESS_DENIED;
    }
    if (existed) *existed = 1;
  }
  *out = h;
  return SD_OK;
}

sd_err sd_ipc_object_open(sd_ipc_object obj, HANDLE *out)
{
  wchar_t name[IPC_NAME_CCH];
  HANDLE h;
  PSID me = NULL;
  sd_err e;
  *out = NULL;
  e = sd_ipc_object_name(obj, name, SD_COUNTOF(name));
  if (e != SD_OK)
    return e;
  if (obj == SD_IPC_OBJ_AGENT_MUTEX)
    h = OpenMutexW(SYNCHRONIZE | READ_CONTROL, FALSE, name);
  else
    h = OpenEventW(SYNCHRONIZE | READ_CONTROL | (obj == SD_IPC_OBJ_AGENT_STOP ? EVENT_MODIFY_STATE : 0), FALSE, name);
  if (h == NULL)
    return GetLastError() == ERROR_FILE_NOT_FOUND ? SD_E_NOT_FOUND : SD_E_ACCESS_DENIED;
  e = ipc_process_user_sid(&me);
  if (e == SD_OK)
    e = ipc_verify_object_owner(h, me, 1);
  sd_free(me);
  if (e != SD_OK) {
    CloseHandle(h);
    return SD_E_ACCESS_DENIED;
  }
  *out = h;
  return SD_OK;
}

/* ---- events ---- */

sd_err sd_ipc_build_event(const char *event, const char *data_json, size_t data_len, sd_wr *out)
{
  sd_json_writer jw;
  sd_jw_init(&jw, out);
  sd_jw_obj_begin(&jw);
  sd_jw_key(&jw, "type");
  sd_jw_cstr(&jw, "evt");
  sd_jw_key(&jw, "event");
  sd_jw_cstr(&jw, event);
  sd_jw_key(&jw, "data");
  if (data_json && data_len)
    sd_jw_raw(&jw, data_json, data_len);
  else {
    sd_jw_obj_begin(&jw);
    sd_jw_obj_end(&jw);
  }
  sd_jw_obj_end(&jw);
  return sd_jw_finish(&jw);
}

/* ---- error table (03 §6.2) ---- */

int sd_ipc_exit_code_for_err(sd_err e)
{
  switch (e) {
  case SD_OK:                         return 0;
  case SD_E_EOF:                      return 1;
  case SD_E_NOT_FOUND:                return 3;
  case SD_E_ACCESS_DENIED:            return 9;
  case SD_E_EXISTS:                   return 10;
  case SD_E_NOT_EMPTY:                return 1;
  case SD_E_NOT_A_DIRECTORY:          return 1;
  case SD_E_IS_A_DIRECTORY:           return 1;
  case SD_E_NO_SPACE:                 return 1;
  case SD_E_QUOTA:                    return 1;
  case SD_E_READ_ONLY:                return 1;
  case SD_E_INVALID_NAME:             return 2;
  case SD_E_NAME_TOO_LONG:            return 2;
  case SD_E_LINK_LOOP:                return 1;
  case SD_E_LOCK_CONFLICT:            return 10;
  case SD_E_INVALID_PARAM:            return 2;
  case SD_E_UNSUPPORTED:              return 1;
  case SD_E_FAILURE:                  return 1;
  case SD_E_DISCONNECTED:             return 7;
  case SD_E_STALE_HANDLE:             return 7;
  case SD_E_TIMEOUT:                  return 12;
  case SD_E_CANCELLED:                return 13;
  case SD_E_PROTOCOL:                 return 7;
  case SD_E_BUSY:                     return 8;
  case SD_E_WOULD_DEADLOCK:           return 1;
  case SD_E_SHUTDOWN:                 return 8;
  case SD_E_DNS:                      return 7;
  case SD_E_CONN_REFUSED:             return 7;
  case SD_E_NET_UNREACHABLE:          return 7;
  case SD_E_KEX_FAILED:               return 7;
  case SD_E_HOSTKEY_REJECTED:         return 5;
  case SD_E_HOSTKEY_MISMATCH:         return 6;
  case SD_E_HOSTKEY_REVOKED:          return 6;
  case SD_E_HOSTKEY_TYPE_UNAVAILABLE: return 6;
  case SD_E_AUTH_FAILED:              return 4;
  case SD_E_AUTH_REQUIRED:            return 4;
  case SD_E_LEGACY_REJECTED:          return 15;
  case SD_E_PROXY:                    return 16;
  case SD_E_PROXY_AUTH:               return 16;
  case SD_E_POOL_ABANDONED:           return 1;
  case SD_E_NO_MEMORY:                return 1;
  case SD_E_CRYPTO:                   return 1;
  case SD_E_KEY_FORMAT:               return 1;
  case SD_E_KEY_UNSUPPORTED:          return 1;
  case SD_E_BAD_PASSPHRASE:           return 4;
  case SD_E_KEY_PASSPHRASE_REQUIRED:  return 4;
  case SD_E_INTERNAL:                 return 1;
  case SD_ERR_COUNT:                  break;
  }
  return 1;
}

static const struct { const char *code; int exit_code; } k_codes[] = {
  { "usage", 2 }, { "service_access_required", 2 }, { "invalid_target", 2 },
  { "profile_not_found", 3 }, { "mount_not_found", 3 },
  { "host_key_not_found", 3 }, { "announcement_not_found", 3 },
  { "session_not_found", 3 }, { "putty_not_found", 3 }, { "file_not_found", 3 },
  { "host_key_unknown", 5 },
  { "connect_failed", 7 },
  { "agent_unavailable", 8 }, { "service_not_installed", 8 }, { "too_many_connections", 8 },
  { "rate_limited", 8 },
  { "elevation_required", 9 },
  { "target_in_use", 10 }, { "already_mounted", 10 },
  { "backend_unavailable", 11 }, { "webclient_disabled", 11 },
  { "proto_unsupported", 14 },
  { "policy_denied", 15 },
  { "proxy_unsupported", 16 },
  { "selftest_failed", 17 }, { "update_verify_failed", 17 },
  { "io_error", 1 }, { "prompt_unavailable", 4 },
};

int sd_ipc_exit_code_for_code(const char *code)
{
  size_t i;
  sd_err e;
  if (code == NULL)
    return 1;
  for (i = 0; i < SD_COUNTOF(k_codes); i++)
    if (strcmp(k_codes[i].code, code) == 0)
      return k_codes[i].exit_code;
  e = sd_err_from_name(code);
  return e == SD_ERR_COUNT ? 1 : sd_ipc_exit_code_for_err(e);
}

static void copy_ascii(char *dst, size_t cap, const char *src)
{
  size_t i = 0;
  if (cap == 0)
    return;
  if (src)
    for (; src[i] && i + 1 < cap; i++)
      dst[i] = src[i];
  dst[i] = 0;
}

void sd_ipc_error_set(sd_ipc_error *err, sd_err e, const char *code, const char *detail)
{
  if (err == NULL)
    return;
  err->err = e == SD_OK ? SD_E_FAILURE : e;
  copy_ascii(err->code, sizeof(err->code), code ? code : sd_err_name(err->err));
  copy_ascii(err->detail, sizeof(err->detail), detail ? detail : "");
  err->exit_code = code ? sd_ipc_exit_code_for_code(code) : sd_ipc_exit_code_for_err(err->err);
}
