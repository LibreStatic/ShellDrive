/* shelldrive-setup engine: helpers shared by the engine's .c files. Not part of the public interface. */
#ifndef SD_SETUP_INT_H
#define SD_SETUP_INT_H

#include <windows.h>
#include <strsafe.h>
#include <stddef.h>

#include "setup_core.h"
#include "sd_l10n_installer_ids.h"

#define SD_SETUP_COUNTOF(a) (sizeof(a) / sizeof((a)[0]))

/* Resolves an export at run time (04 §2.4). module is a loaded or KnownDLL name such as L"kernel32.dll".
   Returns NULL when absent (older Windows). Loads the module with its full System32 path when it is not
   loaded yet, so no search path is involved (04 §6.4 rule 3). */
FARPROC sd_setup_proc(const wchar_t *module, const char *name);

/* Full path of a System32 file, e.g. "cabinet.dll" -> "C:\Windows\System32\cabinet.dll". */
int sd_setup_system_path(const wchar_t *file, wchar_t *out, size_t cch);

/* Path helpers. dst gets dir with exactly one trailing backslash, then the other parts. */
int sd_setup_path_join(wchar_t *dst, size_t cch, const wchar_t *dir, const wchar_t *name);
int sd_setup_dir_with_slash(wchar_t *dst, size_t cch, const wchar_t *dir);

/* Special folders (SHGetFolderPathW): csidl is CSIDL_LOCAL_APPDATA, CSIDL_APPDATA, ... */
int sd_setup_special_folder(int csidl, wchar_t *out, size_t cch);

/* Unique name for a new folder or file: 32 hex digits from CryptGenRandom. */
int sd_setup_random_hex(wchar_t *out, size_t cch);

/* Temp folder path with a trailing backslash. */
int sd_setup_temp_dir(wchar_t *out, size_t cch);

/* Recursively deletes a folder without following reparse points (junctions are removed, not walked).
   Files that cannot be deleted are counted in *failed; the call still returns 0. */
int sd_setup_remove_tree(const wchar_t *dir, unsigned *failed);

/* Creates dir and its missing parents. Returns 0 or the Windows error. */
DWORD sd_setup_mkdirs(const wchar_t *dir);

/* ASCII (CAB member names) to wide. Returns 0 on success. */
int sd_setup_ascii_to_wide(const char *src, wchar_t *dst, size_t cch);

/* Sets r->exit_code and r->msg, plus r->code when code != 0. Returns exit_code. */
int sd_setup_fail(sd_setup_result *r, int exit_code, sd_msg_id msg, long code);

/* Log line helper for file operations: event "file.copy", text "<src> -> <dst>". */
void sd_setup_log_error(const char *event, const wchar_t *what, DWORD err);

/* Value helpers for the registration rows. */
int sd_setup_sha256_hex(const unsigned char sha[32], char out[65]);

#endif /* SD_SETUP_INT_H */
