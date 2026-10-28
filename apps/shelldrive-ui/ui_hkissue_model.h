/* shelldrive-ui: the model of the changed-key and wrong-key-type notifications (03 §5.2, §5.4, TM-R04).
 *
 * The agent reports a failed mount in the `error` object of a mount.state event (03 §2.4): for host_key_mismatch it
 * carries host, stored_type, stored_fp, offered_type, offered_fp, store_path and store_line; for
 * host_key_type_unavailable it carries the code and the detail only (the stored and offered types are not reported
 * yet, so a message that names them is used only when the agent sends `stored_type`). This module reads that object,
 * decides where the old key lives from the file path (the event has no store kind) and what the user can do about
 * it. There is no "connect anyway" anywhere (5.4): the dialog offers the host key manager, the file location of a
 * read-only source and "Stop using keys from this source".
 *
 * Pure: no window or process calls, so the unit tests (tests/ui) build this file on its own. */
#ifndef SD_UI_HKISSUE_MODEL_H
#define SD_UI_HKISSUE_MODEL_H

#include <windows.h>

#include "sd/base.h"
#include "sd_base/sd_err.h"
#include "sd_base/sd_json.h"

#define UI_HKI_HOST_MAX 256
#define UI_HKI_TYPE_MAX 48
#define UI_HKI_FP_MAX   64
#define UI_HKI_PATH_MAX 260
#define UI_HKI_ID_MAX   40

typedef enum ui_hki_kind {
  UI_HKI_NONE = 0,
  UI_HKI_CHANGED,            /* host_key_mismatch */
  UI_HKI_TYPE_UNAVAILABLE    /* host_key_type_unavailable */
} ui_hki_kind;

/* Where the stored (old) key lives. */
typedef enum ui_hki_source {
  UI_HKI_SRC_USER = 0,       /* ShellDrive's own list of this user: removable in the host key manager */
  UI_HKI_SRC_MACHINE,        /* ShellDrive's list for all users: only an administrator changes it */
  UI_HKI_SRC_OPENSSH,        /* a known_hosts file of OpenSSH, read live (5.1) */
  UI_HKI_SRC_PUTTY,          /* the PuTTY registry value, read live */
  UI_HKI_SRC_FILE            /* some other file */
} ui_hki_source;

typedef struct ui_hki {
  ui_hki_kind kind;
  char mount_id[UI_HKI_ID_MAX];
  char host[UI_HKI_HOST_MAX];            /* printable ASCII */
  char stored_type[UI_HKI_TYPE_MAX];
  char stored_fp[UI_HKI_FP_MAX];
  char offered_type[UI_HKI_TYPE_MAX];
  char offered_fp[UI_HKI_FP_MAX];
  wchar_t path[UI_HKI_PATH_MAX];         /* file of the old key; "" or a registry subkey for PuTTY */
  unsigned line;                         /* 1-based line of the old key, 0 when not known */
} ui_hki;

/* Reads the data of a mount.state event. Returns the kind (UI_HKI_NONE when the event has no such error). fallback_host
   is used when the error names no host (the host of the mount). Text is reduced to printable ASCII ('?' for the
   rest); the path loses control characters. */
ui_hki_kind ui_hki_parse(const sd_json *data, const char *fallback_host, ui_hki *out);

/* Classifies the file of the old key. user_store: the path of ShellDrive's own known_hosts of this user (NULL when
   unknown). An empty path or a PuTTY registry subkey is PuTTY. */
ui_hki_source ui_hki_classify(const wchar_t *path, const wchar_t *user_store);

/* 1 when the user can do something in ShellDrive's own host key manager about this source (remove the key). */
int ui_hki_source_removable_here(ui_hki_source s);
/* 1 when the source is a live read-only source whose keys can be switched off ("Stop using keys from this source"). */
int ui_hki_source_can_stop(ui_hki_source s);
/* 1 when "Open file location" applies: the source is a file with a path that is safe to hand to Explorer. */
int ui_hki_source_can_open(ui_hki_source s, const wchar_t *path);

/* 1 when path is an absolute drive or UNC path without quotes or control characters (safe in a command line). */
int ui_hki_path_ok(const wchar_t *path);
/* The Explorer arguments that select the file: /select,"<path>". 0 when the path is not ok or cap is too small. */
int ui_hki_select_args(const wchar_t *path, wchar_t *out, size_t cap);

/* Messages the dialog uses for a source: where the key is, and what to do. */
typedef enum ui_hki_where { UI_HKI_WHERE_USER = 0, UI_HKI_WHERE_MACHINE, UI_HKI_WHERE_FILE, UI_HKI_WHERE_PUTTY } ui_hki_where;
typedef enum ui_hki_todo { UI_HKI_TODO_USER = 0, UI_HKI_TODO_MACHINE, UI_HKI_TODO_SOURCE } ui_hki_todo;
ui_hki_where ui_hki_where_of(ui_hki_source s);
ui_hki_todo  ui_hki_todo_of(ui_hki_source s);

/* 1 when the agent reported a stored key type (the type-unavailable notification then names it). */
int ui_hki_has_stored_type(const ui_hki *h);

#endif /* SD_UI_HKISSUE_MODEL_H */
