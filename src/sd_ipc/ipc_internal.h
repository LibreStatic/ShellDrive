/* Private helpers shared by the sd_ipc translation units. */
#ifndef SD_IPC_INTERNAL_H
#define SD_IPC_INTERNAL_H

#include <windows.h>

#include "sd_ipc/sd_ipc.h"

#define IPC_NAME_CCH 512

/* Bounded wide-string builder: appends and always NUL-terminates; returns 0 on truncation. */
int ipc_wcat(wchar_t *dst, size_t cch, const wchar_t *src);
int ipc_wcat_u32(wchar_t *dst, size_t cch, uint32_t v);
/* TEST HOOK (sd_ipc_test_set_service_owner): service pipe owner override; NULL = SYSTEM. */
const wchar_t *ipc_service_owner_override(void);

/* User SID of a token / of this process, copied into sd_alloc memory (free with sd_free). */
sd_err ipc_token_user_sid(HANDLE token, PSID *out);
sd_err ipc_process_user_sid(PSID *out);
/* SID -> string (sd_alloc'ed, NUL-terminated). */
sd_err ipc_sid_to_string(PSID sid, wchar_t **out);

/* Owner SID of a kernel object handle equals `expected`; also enforces "no label or label >=
   medium" when check_label is set (Vista+). SD_OK or SD_E_ACCESS_DENIED. */
sd_err ipc_verify_object_owner(HANDLE h, PSID expected, int check_label);
sd_err ipc_owner_decision(int owner_ok, int want_label, int label_read, int label_present, DWORD label_rid);

/* Builds a self-relative security descriptor from SDDL (LocalFree the result). */
sd_err ipc_sd_from_sddl(const wchar_t *sddl, PSECURITY_DESCRIPTOR *out);

/* Process-wide hooks. */
const wchar_t *ipc_instance_suffix(void);       /* "" when unset */
const wchar_t *ipc_expected_owner_override(void);/* NULL when unset */
const wchar_t *ipc_agent_path_override(void);   /* NULL when unset */

/* Integrity RID of a token (0x2000 medium); returns 1 and sets *rid when available (Vista+). */
int ipc_token_integrity(HANDLE token, DWORD *rid);

#endif /* SD_IPC_INTERNAL_H */
