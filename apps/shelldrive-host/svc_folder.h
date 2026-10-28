/* Machine folder trust (03 §3.2, TM-R34, T-63): the checks shared by the service start (service.c) and the data folder
 * repair (svc_repair.c). Every check runs on a handle opened with FILE_FLAG_OPEN_REPARSE_POINT, so a link is never
 * followed; a folder is trusted when it is a directory, not a reparse point, and owned by a trusted SID (SYSTEM or
 * BUILTIN\Administrators in the shipping build). */
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
  SVC_FOLDER_NO_RIGHTS   /* the path cannot be opened or created with the rights the service needs */
} svc_folder_reason;

/* The shipping owner rule: SYSTEM or BUILTIN\Administrators. ctx is ignored. */
int svc_folder_owner_shipping(void *ctx, PSID owner);

/* Opens path for the checks (never follows a link). Returns 0, or the Win32 error: ERROR_FILE_NOT_FOUND and
   ERROR_PATH_NOT_FOUND mean the path is missing. *h is NULL on error. */
DWORD svc_folder_open(const wchar_t *path, DWORD access, HANDLE *h);

/* Inspects an open handle. want_dir = 1 checks a folder and its owner (owner_ok, NULL = shipping rule); 0 checks a
   store file (kind and reparse point only). Returns 0 with *why set, or the Win32 error of the query. */
DWORD svc_folder_inspect(HANDLE h, int want_dir, svc_owner_fn owner_ok, void *ctx, svc_folder_reason *why);

/* The Event Log insert for a reason (10.3, `%2` of Event 3102): owner, reparse_point, not_directory, acl. */
const wchar_t *svc_folder_reason_text(svc_folder_reason why);

#endif /* SVC_FOLDER_H */
