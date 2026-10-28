/* shelldrive-ui: which tray notice a change of the agent's state leads to (03 §7.7).
 *
 * The agent sends no "notification" events: the notices of 7.7 are derived from what it does send. A mount.state event
 * whose state changes gives connection lost (mounted -> offline), reconnected (offline -> mounted), mounted (anything
 * else -> mounted) and mount failed (-> failed; a changed host key or a wrong key type have their own always-on
 * balloons, ui_hkissue.c). The warning events with the codes proxy_cleartext, pool_limited and disk_cache_refused, a
 * hostkeys.announced event with applied = true (new host keys saved automatically) and the service's attention count
 * going up give the others. This module decides the kind, the switch of [ui] notify_<kind> it belongs to and the
 * once-per-(profile, proxy) rule of the proxy password notice. The balloons, the rate limit and the event list are
 * in ui_tray.c.
 *
 * Pure: no window or process calls, so the unit tests (tests/ui) build this file on its own. */
#ifndef SD_UI_NOTICE_MODEL_H
#define SD_UI_NOTICE_MODEL_H

#include <windows.h>

#include "sd/base.h"

typedef enum ui_nt_kind {
  UI_NT_NONE = 0,
  UI_NT_CONNECTION_LOST,
  UI_NT_RECONNECTED,
  UI_NT_MOUNT_FAILED,
  UI_NT_MOUNTED,
  UI_NT_PROXY_PASSWORD,
  UI_NT_POOL_LIMITED,
  UI_NT_SERVICE_ATTENTION,
  UI_NT_HOSTKEYS_SAVED,
  UI_NT_DISK_CACHE,
  UI_NT_KINDS
} ui_nt_kind;

/* The notice a mount.state event leads to. prev_state: the state this UI had for the mount ("" when it had none), state:
   the new one, error_code: error.code of the event or NULL. UI_NT_NONE when nothing changes for the user (the same state
   again, connection details only; reconnect attempts while offline; a host key error). */
ui_nt_kind ui_nt_of_mount_state(const char *prev_state, const char *state, const char *error_code);

/* The notice of a `warning` event code (proxy_cleartext, pool_limited, disk_cache_refused); UI_NT_NONE for any other. */
ui_nt_kind ui_nt_of_warning_code(const char *code);

/* The sd_notify_kind switch of a notice (7.7); -1 for a notice without a switch of its own. */
int ui_nt_switch_of(ui_nt_kind k);

/* 1 when the attention count rose: a new prompt waits for an administrator. */
int ui_nt_attention_grew(int previous, int now);

/* ---- once per (profile, proxy) ---- */

#define UI_NT_ONCE_SLOTS 32
#define UI_NT_ONCE_KEY_MAX 192

typedef struct ui_nt_once {
  char key[UI_NT_ONCE_SLOTS][UI_NT_ONCE_KEY_MAX];
  size_t next;                           /* the slot the next new key replaces (oldest first) */
} ui_nt_once;

/* 1 the first time a key is seen (it is remembered), 0 afterwards. The key is cut at UI_NT_ONCE_KEY_MAX - 1 characters. */
int ui_nt_once_take(ui_nt_once *o, const char *key);
/* "<profile>|<proxy>" for ui_nt_once_take; returns 0 when it does not fit. */
int ui_nt_once_key(const char *profile, const char *proxy, char *out, size_t cap);

#endif /* SD_UI_NOTICE_MODEL_H */
