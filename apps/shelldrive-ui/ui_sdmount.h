/* shelldrive-ui: the .sdmount file grammar (03 §8.1, TM-R32, T-61). Pure: no file or window calls, so the
 * unit tests (tests/ui) compile it on its own. The caller reads the file (ui_profiles.c) and checks that the
 * profile exists and is visible to the user.
 *
 * Grammar: at most 4096 bytes of UTF-8 (a UTF-8 byte order mark is allowed). Lines end with LF or CRLF.
 * Blank lines and comment lines (starting with # or ;, after optional spaces) are ignored. Exactly one other
 * line is allowed, "profile = <32 lowercase hex digits>", with optional spaces around "=". Any other key, a
 * second profile line, a value that is not an id, or invalid UTF-8 makes the file invalid. */
#ifndef SD_UI_SDMOUNT_H
#define SD_UI_SDMOUNT_H

#include <windows.h>

#include "sd/base.h"
#include "sd_base/sd_err.h"

#define UI_SDMOUNT_MAX_BYTES 4096u

/* Returns SD_OK and the 32-digit profile id (NUL-terminated, id[33]) or SD_E_INVALID_PARAM. */
sd_err ui_sdmount_parse(const unsigned char *data, size_t bytes, char id[33]);

#endif /* SD_UI_SDMOUNT_H */
