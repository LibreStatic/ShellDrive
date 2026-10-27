/* sd_policy: reader for the Group Policy values of ShellDrive (03 §3.5).
 *
 * Values live in HKLM and HKCU\Software\Policies\LibreStatic\ShellDrive; HKLM wins when both hold the
 * value. The names, registry types and ranges come from res/policy/policies.txt through the generated
 * sd_policy_ids.h and sd_policy_table.h (tools/sd-admxgen), the same table the ADMX is built from, so a
 * policy cannot be read under a name the template does not define.
 *
 * Reads never write and never create keys. A value of the wrong registry type, or a policy of the other
 * kind, reads as absent. */
#ifndef SD_POLICY_H
#define SD_POLICY_H

#include <windows.h>

#include "sd_policy_ids.h"   /* generated: enum sd_policy_id, SD_POLICY_ID_COUNT */

typedef enum sd_policy_kind {
  SD_POLICY_KIND_BOOLEAN,
  SD_POLICY_KIND_ENUM,
  SD_POLICY_KIND_TEXT,
  SD_POLICY_KIND_DECIMAL
} sd_policy_kind;

typedef enum sd_policy_reg {
  SD_POLICY_REG_DWORD,
  SD_POLICY_REG_SZ
} sd_policy_reg;

typedef struct sd_policy_def {
  const wchar_t *name;     /* registry value name and ADMX valueName */
  sd_policy_kind kind;
  sd_policy_reg reg;       /* registry type */
  unsigned long min, max;  /* REG_DWORD range: boolean 0..1, numeric enums, decimals */
  unsigned long maxlen;    /* REG_SZ maximum length in characters (text policies) */
} sd_policy_def;

/* Registry key below HKLM and HKCU (the @key line of the table). */
const wchar_t *sd_policy_key(void);

/* Definition of a policy, or NULL for an id outside the table. */
const sd_policy_def *sd_policy_def_of(sd_policy_id id);

/* The value of a REG_DWORD policy: HKLM first, then HKCU. Returns 1 when a value of the right type exists. */
int sd_policy_get_dword(sd_policy_id id, DWORD *value);

/* The value of a REG_SZ policy into buf (cch characters including the terminating NUL), HKLM first. Returns 1
 * when a value of the right type exists; the text is cut at cch - 1 characters. */
int sd_policy_get_sz(sd_policy_id id, wchar_t *buf, size_t cch);

#endif /* SD_POLICY_H */
