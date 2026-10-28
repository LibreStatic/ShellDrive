/* Machine folder and key file trust (03 §3.2, 2.6 rule 1, TM-R34, TM-R27, T-63, T-51): the checks shared by the service
 * start (service.c), the data folder repair (svc_repair.c) and the reads of identity and certificate files. Every check
 * runs on a handle opened with FILE_FLAG_OPEN_REPARSE_POINT, so a link is never followed. A folder is trusted when it is
 * a directory, not a reparse point, owned by a trusted SID (SYSTEM or BUILTIN\Administrators in the shipping build) and
 * (for key files and the folders above them) its DACL grants no write, modify, delete, WRITE_DAC or WRITE_OWNER to a
 * principal outside the trusted set. */
#ifndef SVC_FOLDER_H
#define SVC_FOLDER_H

#include <windows.h>

/* Owner rule seam: 1 when the owner is trusted. NULL in the callers means svc_folder_owner_shipping. */
typedef int (*svc_owner_fn)(void *ctx, PSID owner);

/* Why a path is not trusted. OK means trusted. */
typedef enum svc_folder_reason {
  SVC_FOLDER_OK = 0,
  SVC_FOLDER_OWNER,      /* the owner is not trusted, or the owner cannot be read (fail closed) */
  SVC_FOLDER_REPARSE,    /* a link or a junction: never followed */
  SVC_FOLDER_KIND,       /* a file where a folder belongs, or a folder where a store file belongs */
  SVC_FOLDER_NO_RIGHTS,  /* the path cannot be opened or created with the rights the service needs */
  SVC_FOLDER_ACL,        /* the DACL grants write, modify, delete, WRITE_DAC or WRITE_OWNER to an untrusted principal,
                            or cannot be set back to the 3.2 DACL */
  SVC_FOLDER_NOT_FILE    /* a key file that is a folder, or empty, or larger than the read limit */
} svc_folder_reason;

/* The shipping owner rule: SYSTEM or BUILTIN\Administrators. ctx is ignored. */
int svc_folder_owner_shipping(void *ctx, PSID owner);

/* Opens path for the checks (never follows a link). Returns 0, or the Win32 error: ERROR_FILE_NOT_FOUND and
   ERROR_PATH_NOT_FOUND mean the path is missing. *h is NULL on error. */
DWORD svc_folder_open(const wchar_t *path, DWORD access, HANDLE *h);

/* Inspects an open handle. want_dir = 1 checks a folder and its owner (owner_ok, NULL = shipping rule); 0 checks a
   store file (kind and reparse point only). Returns 0 with *why set, or the Win32 error of the query. */
DWORD svc_folder_inspect(HANDLE h, int want_dir, svc_owner_fn owner_ok, void *ctx, svc_folder_reason *why);

/* Makes the DACL of an open folder equal to the SDDL text (3.2: protected, the listed ACEs in order). The current DACL
   is compared ACE by ACE first; changed is set to 1 only when it was rewritten. Needs WRITE_DAC on the handle when it
   differs. Returns 0, or the Win32 error (a refusal: the caller reports SVC_FOLDER_ACL). */
DWORD svc_folder_apply_dacl(HANDLE h, const wchar_t *sddl, int *changed);

/* Checks a store file the service writes (the machine known_hosts, 5.1, 5.6, TM-R27) before it is changed: opened
   without following a link, a plain file whose owner is trusted and whose DACL grants no write to an untrusted
   principal. A missing file is trusted (the write creates it in the checked data folder). Returns 0 with *why set, or
   the Win32 error of the open. */
DWORD svc_store_check(const wchar_t *path, svc_owner_fn owner_ok, void *ctx, svc_folder_reason *why);

/* Reads a key file the service loads (identity and certificate files, 2.6 rule 1, TM-R27). path must be under base
   (the machine service folder). Every folder between base and the file is checked (reparse point, owner, DACL) by
   handle; the file is opened without following a link, checked on that same handle (plain file, owner, DACL) and read
   from that handle, and the share mode of the open excludes writers until the read is done.
   Returns 0 with *why = SVC_FOLDER_OK and *data / *len set (free with sd_secure_free), or 0 with *why set to the refusal,
   or a Win32 error when the file cannot be opened or read (*why = SVC_FOLDER_NO_RIGHTS). */
DWORD svc_file_read_trusted(const wchar_t *base, const wchar_t *path, svc_owner_fn owner_ok, void *ctx,
                            unsigned char **data, DWORD *len, svc_folder_reason *why);

/* The Event Log insert for a reason (10.3, `%2` of Event 3102): owner, reparse_point, not_directory, acl, not_file. */
const wchar_t *svc_folder_reason_text(svc_folder_reason why);

#endif /* SVC_FOLDER_H */
