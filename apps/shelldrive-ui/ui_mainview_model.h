/* shelldrive-ui: the model of the main window's list (03 §7.5, §7.6): the status text kind of a row, the Security
 * column (legacy encryption, Terrapin), the ListView group a row belongs to and the description of an outdated
 * algorithm for the security details dialog.
 *
 * The agent reports the security state of every mount in `list` (round 17): `legacy`, `legacy_algorithms`
 * (`[{category, name}]`) and `terrapin_exposed` for the current connection, and `scope` (`user`, `machine_template`,
 * `global`). They are valid after a UI restart, so the Security column, the details dialog and the groups come from
 * them. An agent that does not send them is still served by the `warnings` ring of `list` (code and mount_id) and by
 * `warning` events (`data.algorithms`), which name the algorithms only for warnings the UI saw.
 *
 * Pure: no window or process calls, so the unit tests (tests/ui) build this file on its own. */
#ifndef SD_UI_MAINVIEW_MODEL_H
#define SD_UI_MAINVIEW_MODEL_H

#include <windows.h>

#include "sd/base.h"
#include "sd_base/sd_err.h"
#include "sd_base/sd_json.h"

/* Bits of the Security column. */
#define UI_MV_SEC_LEGACY   0x1u      /* legacy_algorithms */
#define UI_MV_SEC_TERRAPIN 0x2u      /* terrapin_exposed */

/* Maximum length of the comma-joined algorithm names kept for a mount. */
#define UI_MV_ALGOS_MAX 256

/* The security bit of a warning code, 0 for any other warning. */
unsigned ui_mv_sec_flag(const char *code);

/* OR of the security bits of the warnings in `list.warnings` that name mount_id. */
unsigned ui_mv_sec_from_warnings(const sd_json *warnings, const char *mount_id);

/* Joins data.algorithms (array of strings) of a legacy_algorithms warning into csv: names made of letters, digits and
   "@._+-" only, at most 16, separated by ','. Returns the number of names kept. */
size_t ui_mv_algos_join(const sd_json *data, char *csv, size_t cap);

/* The legacy_accepted value of 7.6 for a comma-joined list: "sha256:<hex>" of the sorted list (sd_legacy_set_hash).
   Returns 0 for an empty list. */
int ui_mv_algos_hash(const char *csv, char out[80]);

/* ---- the security state of a mount in `list` ---- */

#define UI_MV_ALGOS_N 16

typedef struct ui_mv_security {
  unsigned sec;                          /* UI_MV_SEC_* bits */
  int from_mount;                        /* 1 when the mount object carried legacy or terrapin_exposed (valid for the
                                            current connection), 0 when the bits come from the warnings ring */
  size_t n_algos;
  char algos[UI_MV_ALGOS_MAX];           /* comma-joined names, as ui_mv_algos_join */
  unsigned char cats[UI_MV_ALGOS_N];     /* ui_mv_cat of the name at the same position; OTHER when not reported */
} ui_mv_security;

/* Reads one item of `list.mounts`: `legacy`, `legacy_algorithms` and `terrapin_exposed` when present, otherwise the
   bits of the `warnings` ring for mount_id (the list's top-level array, may be NULL). */
void ui_mv_security_from_mount(const sd_json *mount, const sd_json *warnings, const char *mount_id, ui_mv_security *out);

/* The agent's scope token of a mount ("user", "machine_template", "global") as SD_PROFILE_SCOPE_*; -1 for a missing or
   unknown token. */
int ui_mv_scope_of_token(const char *token);

/* ---- status ---- */

typedef enum ui_mv_status {
  UI_MV_ST_NOT_MOUNTED = 0, UI_MV_ST_CONNECTING, UI_MV_ST_AUTHENTICATING, UI_MV_ST_MOUNTED, UI_MV_ST_RECONNECTING,
  UI_MV_ST_OFFLINE, UI_MV_ST_AUTH_REQUIRED, UI_MV_ST_FAILED, UI_MV_ST_UNMOUNTING, UI_MV_ST_UNMOUNTED,
  UI_MV_ST_UNKNOWN
} ui_mv_status;

/* state: the mount state token ("" for a profile that is not mounted); session: connection.session ("" when absent);
   attempt: connection.attempt (0 when absent). A mount that is offline while its session waits to reconnect is
   RECONNECTING. */
ui_mv_status ui_mv_status_of(const char *state, const char *session, int attempt);

typedef enum ui_mv_icon { UI_MV_ICON_NONE = 0, UI_MV_ICON_OK, UI_MV_ICON_IDLE, UI_MV_ICON_WARN } ui_mv_icon;
ui_mv_icon ui_mv_status_icon(ui_mv_status st);
ui_mv_icon ui_mv_sec_icon(unsigned sec);

/* ---- groups (7.5) ---- */

typedef enum ui_mv_group { UI_MV_GROUP_MINE = 0, UI_MV_GROUP_ORG = 1, UI_MV_GROUP_GLOBAL = 2, UI_MV_GROUPS = 3 } ui_mv_group;
/* scope: SD_PROFILE_SCOPE_*; -1 for a mount without a saved profile. */
ui_mv_group ui_mv_group_of_scope(int scope);

/* ---- algorithms ---- */

typedef enum ui_mv_cat { UI_MV_CAT_OTHER = 0, UI_MV_CAT_KEX, UI_MV_CAT_HOSTKEY, UI_MV_CAT_CIPHER, UI_MV_CAT_MAC } ui_mv_cat;
typedef enum ui_mv_why {
  UI_MV_WHY_OTHER = 0,       /* generic: considered outdated */
  UI_MV_WHY_KEX_SHA1,        /* key exchange built on SHA-1 or on a small fixed group */
  UI_MV_WHY_CBC,             /* CBC cipher modes */
  UI_MV_WHY_MAC_SHA1,        /* HMAC with SHA-1 */
  UI_MV_WHY_HOSTKEY_SHA1     /* ssh-rsa signatures use SHA-1 */
} ui_mv_why;

void ui_mv_algo_info(const char *name, ui_mv_cat *cat, ui_mv_why *why);

/* The category token of `legacy_algorithms` ("kex", "hostkey", "cipher", "mac"); OTHER for anything else. */
ui_mv_cat ui_mv_cat_of_token(const char *token);

/* Splits csv at ',' into at most cap names (each at most 63 characters). Returns the count. */
size_t ui_mv_algos_split(const char *csv, char names[][64], size_t cap);

#endif /* SD_UI_MAINVIEW_MODEL_H */
