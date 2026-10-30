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
#include "sd_base/sd_json.h"

#define UI_HK_HOST_MAX   256
#define UI_HK_TYPE_MAX   48
#define UI_HK_FP_MAX     64
#define UI_HK_COMMENT_MAX 256
#define UI_HK_ADDED_MAX  16
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
  char md5[UI_HK_FP_MAX];            /* "MD5:xx:..." for the details pane ("" when not computed) */
  char comment[UI_HK_COMMENT_MAX];   /* the trailing comment of the line, "" if none */
  char added[UI_HK_ADDED_MAX];       /* "YYYY-MM-DD" from the added= member of the comment, or "" */
  int origin;                        /* ui_hk_origin, the order of sd_kh_origin (sd_known_hosts_list_all) */
} ui_hk_row;

/* Where a line came from (03 5.1, 7.5). The values are those of sd_kh_origin so the window can pass them on as they are. */
typedef enum ui_hk_origin {
  UI_HK_ORIGIN_OTHER = 0,            /* another tool, or a hand-written line */
  UI_HK_ORIGIN_SHELLDRIVE,           /* by=shelldrive, or a bare added= */
  UI_HK_ORIGIN_PUTTY,                /* imported-from=putty: "Copied from PuTTY" */
  UI_HK_ORIGIN_OPENSSH,              /* imported-from=openssh: "Copied from OpenSSH" */
  UI_HK_ORIGIN_SERVER,               /* updated-by=hostkeys-00: "Updated by server" */
  UI_HK_ORIGINS
} ui_hk_origin;

/* Sets what sd_known_hosts_list_all reports beyond the key itself: the MD5 fingerprint, the trailing comment, the added
   date and the origin. Text longer than the fields is cut; an origin out of range is "other". NULL is "". */
void ui_hk_row_set_extras(ui_hk_row *row, const char *md5, const char *comment, const char *added, int origin);

/* Fills the derived fields of a row from its store, pattern, key type, fingerprint and line. */
sd_err ui_hk_row_init(ui_hk_row *row, ui_hk_store store, const char *pattern, int hashed, const char *type,
                      const char *fp, uint32_t line);

/* The five cells of a row as text. hashed_text: the host cell of a hashed entry ("(hashed)");
   machine_text / user_text: the source cell. Each cell is at most UI_HK_CELL_MAX - 1 characters. */
void ui_hk_row_cells(const ui_hk_row *row, const wchar_t *hashed_text, const wchar_t *machine_text,
                     const wchar_t *user_text, wchar_t cells[UI_HK_CELLS][UI_HK_CELL_MAX]);

/* Details of the selected key (the pane under the Known keys list): host, port, key type, SHA256 and MD5 fingerprints,
   store, line in its file, the source (origin of the line), the date it was added and the comment of the line. A hashed
   entry shows hashed_text as the host and no port. origin_text[o]: the text of ui_hk_origin o ("ShellDrive", "Copied from
   PuTTY", ...). The fields the line does not have (MD5 not computed, origin other, no added date, no comment) are empty,
   and the window leaves their lines out. */
#define UI_HK_DETAILS 10
typedef enum ui_hk_detail { UI_HK_DET_HOST = 0, UI_HK_DET_PORT, UI_HK_DET_TYPE, UI_HK_DET_FP, UI_HK_DET_MD5,
                            UI_HK_DET_STORE, UI_HK_DET_LINE, UI_HK_DET_ORIGIN, UI_HK_DET_ADDED,
                            UI_HK_DET_COMMENT } ui_hk_detail;
void ui_hk_row_details(const ui_hk_row *row, const wchar_t *hashed_text, const wchar_t *machine_text,
                       const wchar_t *user_text, const wchar_t *const origin_text[UI_HK_ORIGINS],
                       wchar_t values[UI_HK_DETAILS][UI_HK_CELL_MAX]);

/* The hostkey.announced.reject request {"id": ...} for an announcement the user declined (03 2.4). Fails with
   SD_E_INVALID_PARAM for an id that ui_hk_id_ok refuses or when cap is too small. */
sd_err ui_hk_reject_params(const char *id, char *out, size_t cap);

/* Announcement row (the "Announced keys" tab): one key to add or to remove. action: 1 = add, 0 = remove. */
void ui_hk_announce_cells(const char *host, int action, const char *type, const char *fp,
                          const wchar_t *add_text, const wchar_t *remove_text,
                          wchar_t cells[4][UI_HK_CELL_MAX]);

/* ---- "Add key from server..." (03 §5.2, §6.1 hostkey add --from-server; agent IPC hostkey.add) ---- */

#define UI_HK_OFFER_KEYS 8             /* the agent keeps at most 8 keys of one host */
#define UI_HK_ID_MAX     64
#define UI_HK_SPEC_MAX   300           /* the server field as typed, UTF-16 units */

/* The server the user typed, reduced to what the agent needs. */
typedef struct ui_hk_target {
  char host[UI_HK_HOST_MAX];         /* lower case, ASCII (an IDN name is typed in its xn-- form) */
  unsigned port;                     /* 1..65535, 22 when none was typed */
  char lookup[UI_HK_HOST_MAX + 8];   /* known_hosts name: "host", or "[host]:port" when the port is not 22 */
} ui_hk_target;

/* Reads "host", "host:port", "[v6]" or "[v6]:port" (surrounding blanks ignored). A bare IPv6 address with several
   colons is a host without a port. Rejects an empty field, a user@ prefix, characters outside letters, digits and
   "-._" (":" only inside an IPv6 address), a port outside 1..65535 and a name that is too long. 1 on success. */
int ui_hk_target_parse(const char *spec, ui_hk_target *t);

/* The key types the dialog may restrict the lookup to (an empty type means any). 1 when type is acceptable to the
   agent: lower case letters, digits and "-@." only, 1..63 characters. */
int ui_hk_type_ok(const char *type);

/* The hostkey.add request object for t, with the optional key type (NULL or "" for any). Fails with
   SD_E_INVALID_PARAM when t or type is not valid or cap is too small. */
sd_err ui_hk_add_params(const ui_hk_target *t, const char *type, char *out, size_t cap);

typedef struct ui_hk_offer_key {
  char type[UI_HK_TYPE_MAX];
  char fp[UI_HK_FP_MAX];
} ui_hk_offer_key;

/* The reply of hostkey.add without "expect": the keys the server presented and the announcement that holds them. */
typedef struct ui_hk_offer {
  char host[UI_HK_HOST_MAX];
  int verified;                      /* 1: a stored key of the host matched in this connection (not a first contact) */
  char id[UI_HK_ID_MAX];             /* announcement id for hostkey.announced.accept; "" when the server offered nothing */
  size_t nkeys;
  ui_hk_offer_key keys[UI_HK_OFFER_KEYS];
} ui_hk_offer;

/* Reads a hostkey.add reply. Text is reduced to printable ASCII (a bad character becomes '?'). A reply without an id,
   or with an id outside [A-Za-z0-9._-], has no offer (id "" and nkeys 0). SD_E_INVALID_PARAM for a reply that is not
   an object. */
sd_err ui_hk_offer_parse(const sd_json *reply, ui_hk_offer *o);

/* 1 when id is usable in a hostkey.announced.accept request. */
int ui_hk_id_ok(const char *id);

/* One line per key for the review dialog: "<type>  <fingerprint>", lines joined with CR LF (an edit control). */
void ui_hk_offer_lines(const ui_hk_offer *o, wchar_t *out, size_t cap);

/* What went wrong with a hostkey.add call, for the message to show. */
typedef enum ui_hk_add_fail {
  UI_HK_ADD_FAIL_AGENT_DOWN = 0,     /* the agent is not running or the pipe broke */
  UI_HK_ADD_FAIL_UNSUPPORTED,        /* the agent build cannot collect keys from a server yet (not_implemented) */
  UI_HK_ADD_FAIL_MISMATCH,           /* the server's key does not match the stored one (host_key_mismatch) */
  UI_HK_ADD_FAIL_REJECTED,           /* host_key_rejected */
  UI_HK_ADD_FAIL_BUSY,               /* the request could not be queued or the agent is busy */
  UI_HK_ADD_FAIL_OTHER               /* connect failed, timeout and the rest: shown with the error name */
} ui_hk_add_fail;

ui_hk_add_fail ui_hk_add_fail_of(sd_err e);

#endif /* SD_UI_HOSTKEYS_MODEL_H */
