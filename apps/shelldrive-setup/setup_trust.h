/* shelldrive-setup: %ProgramData% trust before elevated use (docs/design/04 §6.4, TM-R34, T-63) and the
   per-run staging folder of the elevated stages (04 §6.4 stage 1, step c).

   The owner, link and DACL checks are the service's own (apps/shelldrive-host/svc_repair.c, compiled into
   sd_setup_core from its shared source), so setup and `shelldrive service repair-data` cannot disagree. */
#ifndef SD_SETUP_TRUST_H
#define SD_SETUP_TRUST_H

#include <windows.h>

#include "setup_core.h"

struct svc_repair_ops;

typedef struct sd_setup_trust_result {
  int refused;                 /* the base is a link: nothing was changed */
  int moved;                   /* an untrusted folder was moved aside; path is its new name */
  wchar_t path[MAX_PATH];
  DWORD folders;               /* folders and stores checked, set or created */
} sd_setup_trust_result;

/* Secures <base>\LibreStatic and <base>\LibreStatic\ShellDrive (base is %ProgramData%, CSIDL_COMMON_APPDATA) before
   anything is written there. The shipping owner rule (SYSTEM and Administrators) applies. Returns 0 or a Win32
   error; a moved folder is logged as setup.programdata_untrusted. The caller checks elevation first. */
DWORD sd_setup_secure_programdata(const wchar_t *base, sd_setup_trust_result *out);

/* The same check with the seam given (tests): ops is a svc_repair_ops, extra_ace is appended to every DACL. */
DWORD sd_setup_secure_programdata_with(const struct svc_repair_ops *ops, const wchar_t *base,
                                       sd_setup_trust_result *out);

/* %ProgramData% (CSIDL_COMMON_APPDATA) with no trailing backslash. Returns 0 or a Win32 error. */
DWORD sd_setup_common_appdata(wchar_t *out, size_t cch);

/* Creates a new folder <setup_dir>\<random 128-bit hex> with a protected DACL (SYSTEM and Administrators full control,
   plus extra_ace when not NULL) in the same CreateDirectoryW call. setup_dir is created when missing. The name is new
   every time: an existing name is never reused (up to 8 attempts). out gets the full path. Returns 0 or a Win32 error. */
DWORD sd_setup_create_stage_dir(const wchar_t *setup_dir, const wchar_t *extra_ace, wchar_t *out, size_t cch);

#endif /* SD_SETUP_TRUST_H */
