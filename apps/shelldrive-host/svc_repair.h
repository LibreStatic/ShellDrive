/* Machine data folder repair: shelldrive service repair-data (03 §3.2, §6.1, TM-R34, T-63; 04 §6.4; M5).
 *
 * Checks %ProgramData%\LibreStatic and %ProgramData%\LibreStatic\ShellDrive (and the stores under it) and sets them
 * back to the 3.2 DACLs. A folder that is a reparse point (link or junction), has a foreign owner, or holds a reparse
 * point or a foreign-owned folder anywhere below it is moved aside (LibreStatic.untrusted-<n> or
 * ShellDrive.untrusted-<n>), never imported, and a fresh folder is created in its place. A link is renamed, never
 * followed. Every check and every SetSecurityInfo runs on a handle opened with FILE_FLAG_OPEN_REPARSE_POINT.
 *
 * The base folder (%ProgramData%) is taken as a parameter so the unit tests run on a temp directory; the CLI passes
 * CSIDL_COMMON_APPDATA. The caller checks elevation (the CLI exits 9 before it gets here). */
#ifndef SVC_REPAIR_H
#define SVC_REPAIR_H

#include <windows.h>

typedef struct svc_repair_ops {
  void *ctx;
  /* 1 when a folder with this owner is trusted. The shipping build trusts SYSTEM and BUILTIN\Administrators; the tests
     trust every owner or none. */
  int (*owner_trusted)(void *ctx, PSID owner);
  /* SDDL text appended to every DACL this repair sets (NULL in the shipping build). The tests pass "(A;OICI;FA;;;OW)":
     a non-elevated test process is only the owner of the folders it creates, and the owner needs the same rights as
     BUILTIN\Administrators to build and remove the tree. */
  const wchar_t *extra_ace;
} svc_repair_ops;

typedef struct svc_repair_result {
  int refused;                 /* the base folder is a link: nothing was changed; path names it */
  int moved;                   /* an untrusted folder was moved aside; path is its new name */
  wchar_t path[MAX_PATH];
  DWORD folders;               /* folders and stores checked, set or created */
} svc_repair_result;

/* Fills the seam with the shipping owner rule. Returns 0. */
int svc_repair_real_ops(svc_repair_ops *out);

/* Repairs the tree under base. Returns 0, or a Win32 error (a refused base gives ERROR_ACCESS_DENIED with
   out->refused set; a missing base gives ERROR_PATH_NOT_FOUND). */
DWORD svc_repair_data(const svc_repair_ops *ops, const wchar_t *base, svc_repair_result *out);

#endif /* SVC_REPAIR_H */
