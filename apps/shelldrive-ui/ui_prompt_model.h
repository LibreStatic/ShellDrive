/* shelldrive-ui: the prompt model (03 §2.5, §5.2, §7.5, §7.6, TM-R09, TM-R05, §4.6).
 *
 * Pure: parses a prompt.request into a plain struct, sanitizes text that comes from the server or from the
 * remote host, and builds the prompt.answer JSON. Secrets are handled here: the answer builder wipes the
 * caller's wide-character response buffers and every temporary UTF-8 copy once the JSON is built.
 *
 * Compiled into the unit tests (SD_UI_PURE_SOURCES); it does no window, IPC or agent work. */
#ifndef SD_UI_PROMPT_MODEL_H
#define SD_UI_PROMPT_MODEL_H

#include <windows.h>

#include "sd/base.h"
#include "sd_base/sd_err.h"
#include "sd_base/sd_json.h"

#define UI_PROMPT_MAX_ITEMS  8        /* SD_MOUNT_PROMPT_MAX_ITEMS of sd_mount */
#define UI_PROMPT_MAX_ALGS   16
#define UI_PROMPT_ID_MAX     40
#define UI_PROMPT_HOST_MAX   300
#define UI_PROMPT_NAME_MAX   256
#define UI_PROMPT_TEXT_MAX   1024     /* UTF-16 units kept per server text field (2 KiB of input, TM-R09) */
#define UI_PROMPT_FP_MAX     160
#define UI_PROMPT_ALGS_MAX   512
#define UI_PROMPT_SERVER_MAX 2048     /* name + instruction shown in the read-only server box */

typedef enum ui_prompt_kind {
  UI_PK_NONE = 0,
  UI_PK_HOSTKEY,                      /* hostkey_unknown: a new server identity (TOFU) */
  UI_PK_HOSTKEY_CHANGED,              /* hostkey_changed: never sent by the agent (03 §5.4); informational */
  UI_PK_PASSWORD,
  UI_PK_PASSPHRASE,
  UI_PK_KBDINT,
  UI_PK_PASSWORD_CHANGE,              /* current, new, confirm (3 responses, 01 §6.1) */
  UI_PK_LEGACY_ACK,
  UI_PK_PROXY_PASSWORD,
  UI_PK_WEBDAV_TOKEN_ONLY             /* webdav_token_only: continue without SSPI for this enable (TM-R19, 03 §7.5) */
} ui_prompt_kind;

typedef struct ui_prompt_item {
  wchar_t text[UI_PROMPT_TEXT_MAX + 1];   /* server text, sanitized */
  int echo;
} ui_prompt_item;

typedef struct ui_prompt {
  char prompt_id[UI_PROMPT_ID_MAX];
  char mount_id[UI_PROMPT_ID_MAX];
  ui_prompt_kind kind;
  wchar_t profile[UI_PROMPT_NAME_MAX];     /* profile name: stripped of bidi and zero-width characters */
  wchar_t host[UI_PROMPT_HOST_MAX];
  int port;
  wchar_t user[UI_PROMPT_NAME_MAX];
  int hop;                                 /* 1-based, as the agent sends it */
  int hops;
  wchar_t via[UI_PROMPT_HOST_MAX];         /* jump host before this hop, empty for hop 1 */
  int is_reconnect;
  int hostkey_just_accepted;
  int can_save;
  int has_deadline;
  long long deadline_ms;                   /* remaining time when the prompt was received */
  /* host keys */
  wchar_t key_type[64];
  int key_bits;
  wchar_t fingerprint[UI_PROMPT_FP_MAX];   /* offered key (SHA256:...) */
  wchar_t stored_fingerprint[UI_PROMPT_FP_MAX];   /* changed key only */
  /* passphrase */
  wchar_t key_fingerprint[UI_PROMPT_FP_MAX];
  /* keyboard-interactive and password change */
  wchar_t name[UI_PROMPT_NAME_MAX];
  wchar_t instruction[UI_PROMPT_TEXT_MAX + 1];
  size_t item_count;
  ui_prompt_item items[UI_PROMPT_MAX_ITEMS];
  /* legacy_ack: comma-separated algorithm names, sanitized */
  wchar_t algorithms[UI_PROMPT_ALGS_MAX];
  /* proxy password */
  wchar_t proxy_host[UI_PROMPT_HOST_MAX];
  int proxy_port;
} ui_prompt;

/* Removes control characters, bidi controls (U+202A-U+202E, U+2066-U+2069, U+200E, U+200F) and zero-width
   characters (U+200B-U+200D, U+2060, U+FEFF) from UTF-8 input, converts to UTF-16 and keeps at most cch-1
   units. Input is cut at 2 KiB before conversion. Always NUL-terminates out. */
void ui_text_safe(const char *utf8, wchar_t *out, size_t cch);
/* The same for text that is already UTF-16. */
void ui_text_safe_w(const wchar_t *in, wchar_t *out, size_t cch);

/* Maps a prompt.request kind name to the kind. "hostkey_unknown" and "hostkey" are new identities. */
ui_prompt_kind ui_prompt_kind_from_name(const char *name);

/* Parses the data object of prompt.request (or the object of a queued event). Unknown kinds and missing
   prompt_id or mount_id are SD_E_INVALID_PARAM. */
sd_err ui_prompt_parse(const sd_json *data, ui_prompt *out);

/* A ready-made prompt for each kind (used by the smoke test and the unit tests). */
void ui_prompt_fixture(ui_prompt_kind kind, ui_prompt *out);

/* Builds {"prompt_id":..,"action":..,"responses":[..],"save":true} as UTF-8 in a buffer released with
   ui_secret_free. responses may be NULL when n is 0. action: accept, once, answer, reject or cancel.
   The wide responses are WIPED after the call, whatever the result (the caller still frees them). */
sd_err ui_prompt_build_answer(const char *prompt_id, const char *action, wchar_t *const *responses, size_t n,
                              int save, char **out, size_t *out_len);

/* Wipes and frees a buffer that may hold a secret. */
void ui_secret_free(void *p, size_t n);

#endif /* SD_UI_PROMPT_MODEL_H */
