/* shelldrive-ui: rows of the host key manager (03 §5.1, §5.6).
 *
 * A row is one plain key of a user or machine known_hosts store, read by sd_known_hosts_list_all. This module
 * decides what the row shows (host, port, key type, fingerprint, source) and whether it can be removed by name:
 * a hashed entry, a comma list or a wildcard pattern names no single host, so it is listed but cannot be removed
 * from this window. The announcement rows of the "Announced keys" tab are formatted here too.
 *
 * Pure: no window or process calls, so the unit tests (tests/ui) build this file on its own. */
#ifndef SD_UI_HOSTKEYS_MODEL_H
#define SD_UI_HOSTKEYS_MODEL_H

#include <windows.h>

#include "sd/base.h"
#include "sd_base/sd_err.h"

#define UI_HK_HOST_MAX   256
#define UI_HK_TYPE_MAX   48
#define UI_HK_FP_MAX     64
#define UI_HK_CELLS      5             /* host, port, key type, SHA256 fingerprint, source */
#define UI_HK_CELL_MAX   300

/* Store of a row: the machine store (read-only here) or the user store (writable). */
typedef enum ui_hk_store { UI_HK_STORE_MACHINE = 0, UI_HK_STORE_USER = 1 } ui_hk_store;

typedef struct ui_hk_row {
  ui_hk_store store;
  char pattern[UI_HK_HOST_MAX];      /* the host field as written, or "" when hashed */
  int hashed;                        /* "|1|salt|hash" entry: the name is not readable */
  char host[UI_HK_HOST_MAX];         /* host name for display ("" when hashed or a list) */
  unsigned port;                     /* 22 unless the pattern is "[host]:port" */
  int removable;                     /* 1: a single host name that sd_known_hosts_remove_key can address */
  char lookup[UI_HK_HOST_MAX + 8];   /* lookup name for removal: "host" or "[host]:port" */
  char type[UI_HK_TYPE_MAX];
  char fp[UI_HK_FP_MAX];
  uint32_t line;
} ui_hk_row;

/* Fills the derived fields of a row from its store, pattern, key type, fingerprint and line. */
sd_err ui_hk_row_init(ui_hk_row *row, ui_hk_store store, const char *pattern, int hashed, const char *type,
                      const char *fp, uint32_t line);

/* The five cells of a row as text. hashed_text: the host cell of a hashed entry ("(hashed)");
   machine_text / user_text: the source cell. Each cell is at most UI_HK_CELL_MAX - 1 characters. */
void ui_hk_row_cells(const ui_hk_row *row, const wchar_t *hashed_text, const wchar_t *machine_text,
                     const wchar_t *user_text, wchar_t cells[UI_HK_CELLS][UI_HK_CELL_MAX]);

/* Announcement row (the "Announced keys" tab): one key to add or to remove. action: 1 = add, 0 = remove. */
void ui_hk_announce_cells(const char *host, int action, const char *type, const char *fp,
                          const wchar_t *add_text, const wchar_t *remove_text,
                          wchar_t cells[4][UI_HK_CELL_MAX]);

#endif /* SD_UI_HOSTKEYS_MODEL_H */
