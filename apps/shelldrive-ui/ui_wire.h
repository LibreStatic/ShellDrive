/* shelldrive-ui: the WM_COPYDATA payload and the verb allow-list (03 §1.4, TM-R26, T-48).
 *
 * Pure: no Win32 window or process calls, so the unit tests (tests/ui) build this file on its own.
 * The sender check (token SID and integrity level) is done by the window procedure in main.c before a
 * payload reaches this module.
 *
 * Payload layout (little-endian): u32 magic, u32 version, u32 argc, u32 reserved (0), then argc
 * arguments, each as u32 units followed by units UTF-16 code units (no terminator). */
#ifndef SD_UI_WIRE_H
#define SD_UI_WIRE_H

#include <windows.h>

#include "sd/base.h"
#include "sd_base/sd_err.h"

#define UI_WIRE_MAGIC       0x49554453u     /* bytes "SDUI" in memory order (little-endian u32) */
#define UI_WIRE_VERSION     1u
#define UI_WIRE_CDATA_TAG   0x49554453u     /* COPYDATASTRUCT.dwData of a forwarded command line */
#define UI_WIRE_HEADER      16u
#define UI_WIRE_MAX_BYTES   8192u           /* whole payload */
#define UI_WIRE_MAX_ARGS    8u
#define UI_WIRE_MAX_UNITS   260u            /* UTF-16 units of one argument, no terminator (MAX_PATH) */

typedef enum ui_verb {
  UI_VERB_NONE = 0,       /* no arguments: show the main window */
  UI_VERB_SHOW,           /* --action show */
  UI_VERB_TRAY,           /* --tray */
  UI_VERB_PROMPT_HOST,    /* --prompt-host */
  UI_VERB_MOUNT,          /* --action mount <profile id> */
  UI_VERB_MOUNT_FILE,     /* --action mount-file <absolute path> */
  UI_VERB_UNMOUNT,        /* --action unmount <drive> */
  UI_VERB_RECONNECT,      /* --action reconnect <drive or profile id> */
  UI_VERB_OPEN,           /* --action open <drive>: the shell extension's "Open" verb (03 §8.2) */
  UI_VERB_ELEVATED_ADMIN, /* --elevated-admin: answers the service prompts as an administrator (03 §2.6 rule 3) */
  UI_VERB_ELEVATED_SERVICE /* --elevated-service: the Service page alone, in an elevated process (03 §7.5) */
} ui_verb;

typedef enum ui_target_kind {
  UI_TARGET_NONE = 0,
  UI_TARGET_PROFILE,      /* 32 lower case hex digits */
  UI_TARGET_DRIVE,        /* "X:", normalized to upper case */
  UI_TARGET_PATH          /* absolute drive path */
} ui_target_kind;

typedef struct ui_request {
  ui_verb verb;
  ui_target_kind kind;
  wchar_t target[UI_WIRE_MAX_UNITS + 1];
} ui_request;

/* Encodes argv (program name excluded) into a payload allocated with sd_alloc (release with sd_free). */
sd_err ui_wire_encode(int argc, const wchar_t *const *argv, unsigned char **out, size_t *out_bytes);

/* Validates a received payload (header, lengths, well-formed UTF-16, no trailing bytes), then the verb
   grammar. Reads only inside [data, data + bytes). */
sd_err ui_request_from_payload(const void *data, size_t bytes, ui_request *req);

/* The verb grammar: used for the payload and for this process's own command line. Anything outside
   the grammar is SD_E_INVALID_PARAM. */
sd_err ui_request_from_args(int argc, const wchar_t *const *argv, ui_request *req);

int ui_profile_id_valid(const wchar_t *s);
int ui_drive_normalize(const wchar_t *s, wchar_t out[3]);
int ui_path_valid(const wchar_t *s);

#endif /* SD_UI_WIRE_H */
