/* shelldrive-ui: the profile editor's model (03 §3.4.1, §7.5). Pure: no window, IPC or file calls, so the unit
 * tests (tests/ui) compile it on its own.
 *
 * Every editor field is one ui_pfield. Its value is text: UTF-8 for text fields, decimal digits for numbers and
 * enumerations (the editor maps combo box positions to these values), "1" or "0" for check boxes, and -1 for
 * the unset identities_only (D37). ui_pform_get and ui_pform_set move a value between an sd_profile and that
 * text, so the controls never hold a second copy of the profile. ui_pform_validate gives the field errors;
 * the authoritative check is sd_profile_validate (sd_config), whose first failure is mapped to a field.
 *
 * Keys that the sd_config parser does not support yet (3.4.1: scope, dotfiles, autostart, Cache TTLs, the
 * second and later proxy legs in the editor, "Keep a protected copy") are not fields. */
#ifndef SD_UI_PROFILE_MODEL_H
#define SD_UI_PROFILE_MODEL_H

#include <windows.h>

#include "sd/base.h"
#include "sd_base/sd_err.h"
#include "sd_config/sd_config.h"

typedef enum ui_pfield {
  UI_PF_NAME = 0,
  UI_PF_HOST,
  UI_PF_PORT,
  UI_PF_USER,
  UI_PF_REMOTE_PATH,
  UI_PF_METHOD_PUBLICKEY,
  UI_PF_METHOD_KBDINT,
  UI_PF_METHOD_PASSWORD,
  UI_PF_IDENTITY,
  UI_PF_CERTIFICATE,
  UI_PF_AGENT,
  UI_PF_IDENTITIES_ONLY,
  UI_PF_SAVE_PASSWORD,
  UI_PF_CACHE_SECRETS,
  UI_PF_JUMP,
  UI_PF_PROXY_KIND,
  UI_PF_PROXY_HOST,
  UI_PF_PROXY_PORT,
  UI_PF_PROXY_USER,
  UI_PF_PROXY_AUTH,
  UI_PF_CONNECTIONS,
  UI_PF_KEEPALIVE,
  UI_PF_CONNECT_TIMEOUT,
  UI_PF_TARGET,
  UI_PF_BACKEND,
  UI_PF_READ_ONLY,
  UI_PF_WRITE_MODE,
  UI_PF_SYMLINKS,
  UI_PF_LABEL,
  UI_PF_OFFLINE_WAIT,
  UI_PF_NETWORK_LOCATION,
  UI_PF_DISK_CACHE,
  UI_PF_LEGACY,
  UI_PF_HOST_KEY_ALIAS,
  UI_PF_UPDATE_HOST_KEYS,
  UI_PF_REFUSE_TERRAPIN,
  UI_PF_COUNT
} ui_pfield;

#define UI_PF_NONE (-1)          /* a validation error that is not tied to one field */

#define UI_PF_TEXT_MAX 1024      /* UTF-8 bytes of the longest text field, as a buffer size for get */

/* Reads one field as text. Returns SD_E_INVALID_PARAM when the buffer is too small or f is unknown. */
sd_err ui_pform_get(const sd_profile *p, ui_pfield f, char *out, size_t cap);
/* Writes one field from text (leading and trailing spaces are removed from text fields). Returns
   SD_E_INVALID_PARAM for a text that does not fit, a number that does not parse, or an unknown field; p is
   unchanged then. Range checks are left to ui_pform_validate. */
sd_err ui_pform_set(sd_profile *p, ui_pfield f, const char *text);
/* True for the fields whose value is text (name, host, paths, identity, label, target, ...). */
int    ui_pform_is_text(ui_pfield f);

typedef enum ui_perr {
  UI_PERR_NAME = 1,          /* the name is empty or has control characters */
  UI_PERR_HOST,              /* the host is empty */
  UI_PERR_PORT,              /* the port is not 1..65535 */
  UI_PERR_NUMBER,            /* a number field does not hold a number (reported by the editor) */
  UI_PERR_CONNECTIONS,       /* connection.connections is not 1..4 */
  UI_PERR_METHODS,           /* no authentication method is selected */
  UI_PERR_PROXY_HOST,        /* a proxy is selected but its host is empty */
  UI_PERR_PROXY_PORT,        /* the proxy port is not 1..65535 */
  UI_PERR_OTHER              /* sd_profile_validate rejects the value (see the field) */
} ui_perr;

typedef struct ui_pferr {
  int field;                 /* ui_pfield, or UI_PF_NONE */
  ui_perr code;
} ui_pferr;

/* Field errors of p (UI checks first, then sd_profile_validate when those pass). Returns the number of
   errors written to out (at most cap). An empty result means the profile can be saved. */
size_t ui_pform_validate(const sd_profile *p, ui_pferr *out, size_t cap);

/* Drive letters D..Z that are not in use (used_mask bit i = letter 'A' + i is in use, GetLogicalDrives).
   out[k] receives "X:" (3 units with NUL). Returns the count. */
#define UI_DRIVE_CANDIDATES 23
size_t ui_drive_free_list(uint32_t used_mask, wchar_t out[UI_DRIVE_CANDIDATES][3]);

/* JSON string body (no quotes): escapes quote, backslash and control characters. Returns SD_E_INVALID_PARAM
   when cap is too small. */
sd_err ui_json_escape(const char *in, char *out, size_t cap);

/* The "mount" params of 03 §2.4 for a profile (profile id) or an ad-hoc connection (adhoc object built from
   p), with the overrides of the mount dialog: target ("X:" or "auto", NULL = none), read_only and backend
   ("auto", "dokany" or "webdav", NULL = none). Returns SD_E_INVALID_PARAM when a value cannot be encoded. */
sd_err ui_mount_params_json(const sd_profile *p, int adhoc, const char *target, int read_only,
                            const char *backend, char *out, size_t cap);

#endif /* SD_UI_PROFILE_MODEL_H */
