/* shelldrive-setup: %ProgramData% trust and the staging folder (docs/design/04 §6.4, TM-R34, T-63).

   The check is svc_repair_data (apps/shelldrive-host/svc_repair.c, shared source): every check runs on a handle opened
   with FILE_FLAG_OPEN_REPARSE_POINT, a link or a foreign-owned folder is renamed aside (never followed, never read), and
   a fresh folder is created with the 03 §3.2 DACL in the same call. This file adds the setup's log line, the common
   AppData lookup and the staging folder, which is created with its DACL in one call so no other user can write into it
   between the two steps. */
#include "setup_int.h"

#include <aclapi.h>
#include <sddl.h>
#include <shlobj.h>
#include <string.h>

#include "setup_trust.h"
#include "svc_repair.h"

#ifndef CSIDL_COMMON_APPDATA
#define CSIDL_COMMON_APPDATA 0x0023
#endif

/* Protected DACL of a stage folder: SYSTEM and Administrators only (04 §6.4, stage 1 step c). */
static const wchar_t *const k_stage_sddl = L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";

DWORD sd_setup_secure_programdata_with(const svc_repair_ops *ops, const wchar_t *base, sd_setup_trust_result *out)
{
  svc_repair_result rr;
  DWORD err;

  if (ops == NULL || base == NULL || out == NULL)
    return ERROR_INVALID_PARAMETER;
  memset(out, 0, sizeof(*out));
  memset(&rr, 0, sizeof(rr));
  err = svc_repair_data(ops, base, &rr);
  out->refused = rr.refused;
  out->moved = rr.moved;
  out->folders = rr.folders;
  StringCchCopyW(out->path, SD_SETUP_COUNTOF(out->path), rr.path);
  if (rr.moved)
    sd_setup_log("setup.programdata_untrusted", rr.path);
  return err;
}

DWORD sd_setup_secure_programdata(const wchar_t *base, sd_setup_trust_result *out)
{
  svc_repair_ops ops;

  svc_repair_real_ops(&ops);
  return sd_setup_secure_programdata_with(&ops, base, out);
}

DWORD sd_setup_common_appdata(wchar_t *out, size_t cch)
{
  if (out == NULL || cch < MAX_PATH)
    return ERROR_INVALID_PARAMETER;
  return sd_setup_special_folder(CSIDL_COMMON_APPDATA, out, cch) == 0 ? 0 : ERROR_PATH_NOT_FOUND;
}

DWORD sd_setup_create_stage_dir(const wchar_t *setup_dir, const wchar_t *extra_ace, wchar_t *out, size_t cch)
{
  wchar_t sddl[256];
  wchar_t hex[40];
  wchar_t path[MAX_PATH];
  PSECURITY_DESCRIPTOR sd = NULL;
  SECURITY_ATTRIBUTES sa;
  unsigned attempt;
  DWORD err = ERROR_INTERNAL_ERROR;

  if (setup_dir == NULL || out == NULL || cch < MAX_PATH)
    return ERROR_INVALID_PARAMETER;
  if (extra_ace != NULL)
    StringCchPrintfW(sddl, SD_SETUP_COUNTOF(sddl), L"%s%s", k_stage_sddl, extra_ace);
  else
    StringCchCopyW(sddl, SD_SETUP_COUNTOF(sddl), k_stage_sddl);
  if (sd_setup_mkdirs(setup_dir) != 0)
    return ERROR_PATH_NOT_FOUND;
  if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1, &sd, NULL))
    return GetLastError();

  for (attempt = 0; attempt < 8; attempt++) {
    if (sd_setup_random_hex(hex, SD_SETUP_COUNTOF(hex)) != 0) {
      err = ERROR_GEN_FAILURE;
      break;
    }
    if (sd_setup_path_join(path, MAX_PATH, setup_dir, hex) != 0) {
      err = ERROR_BUFFER_OVERFLOW;
      break;
    }
    memset(&sa, 0, sizeof(sa));
    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = sd;
    sa.bInheritHandle = FALSE;
    if (CreateDirectoryW(path, &sa)) {
      StringCchCopyW(out, cch, path);
      err = 0;
      break;
    }
    err = GetLastError();
    if (err != ERROR_ALREADY_EXISTS)
      break;
    err = ERROR_ALREADY_EXISTS;
  }
  LocalFree(sd);
  return err;
}
