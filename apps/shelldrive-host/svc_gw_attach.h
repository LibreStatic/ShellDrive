/* Per-user attach of a global WebDAV drive (02 §7.7 fallback, 03 §1.3 attach mode): the agent of the logged-on user maps
   the UNC that the service returns, in that user's own logon session, with that user's token (no credentials).

   The seam (svc_gw_attach_ops) keeps the WNet calls out of the tests; svc_gw_attach_real_ops is the only code that calls
   mpr.dll, and the tests never call it. Nothing here is wired to the service or the agent yet: the service method
   mount.attach_info for global profiles is not in this build. */
#ifndef SVC_GW_ATTACH_H
#define SVC_GW_ATTACH_H

#include <windows.h>

#include "sd_base/sd_err.h"

typedef struct svc_gw_attach_ops {
  void *ctx;
  /* Maps letter (A..Z, colon added by the implementation) to remote. xp_form selects the "Web Client Network" provider
     and the http:// form (02 §7.1). Returns a Win32 error (NO_ERROR on success). */
  DWORD (*add)(void *ctx, wchar_t letter, const wchar_t *remote, int xp_form);
  /* Cancels the mapping of letter in this logon session (forced, not persistent). Returns a Win32 error. */
  DWORD (*cancel)(void *ctx, wchar_t letter);
} svc_gw_attach_ops;

/* Pure shape check of the remote name the service returns (02 §7.3, §7.1):
     Vista+: \\localhost@PORT\DavWWWRoot\s-<26 base32 lowercase>
     XP:     http://localhost:PORT/s-<26 base32 lowercase>
   PORT is 1..65535 with no leading zero. Anything else (extra segments, other hosts, uppercase) is refused. */
int svc_gw_attach_remote_ok(const wchar_t *remote, int xp_form);

/* Maps letter to remote through ops. SD_E_INVALID_PARAM for a bad letter, a bad remote or missing ops; SD_E_EXISTS when
   the letter is already in use in this session; SD_E_FAILURE for other errors (*win32_error holds the code). */
sd_err svc_gw_attach_map(const svc_gw_attach_ops *ops, wchar_t letter, const wchar_t *remote, int xp_form,
                         DWORD *win32_error);
sd_err svc_gw_attach_unmap(const svc_gw_attach_ops *ops, wchar_t letter, DWORD *win32_error);

/* The real seam: WNetAddConnection2W / WNetCancelConnection2W without CONNECT_UPDATE_PROFILE (not persistent). */
extern const svc_gw_attach_ops svc_gw_attach_real_ops;

#endif /* SVC_GW_ATTACH_H */
