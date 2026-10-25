/* sd_config: per-user configuration locations, the profile model and profile files (03 §3).
 *
 * M0 scope: the per-user store %APPDATA%\LibreStatic\ShellDrive (D45; SHGetFolderPathW, XP+), one
 * profile per file in profiles\*.ini, and the profile keys a mount needs (3.4.1): profile.host,
 * port, user, remote_path, name, id; auth.identity, auth.methods; mount.target, read_only,
 * symlinks, write_mode, label. Every other key and comment is preserved on rewrite (sd_ini).
 * Folders are created with the protected DACL D:P(A;OICI;FA;;;<UserSID>)(A;OICI;FA;;;SY) (TM-R07).
 * Writers serialize on config.lock (LockFileEx) and replace files atomically (tmp + MoveFileExW).
 *
 * Not yet: machine profiles/templates, overrides, settings.ini, policies, portable detection,
 * directory change notifications (M3/M5).
 *
 * Thread safety: functions are reentrant; profile structs are plain data owned by the caller. */
#ifndef SD_CONFIG_H
#define SD_CONFIG_H

#include <windows.h>

#include "sd/base.h"
#include "sd_base/sd_err.h"
#include "sd_config/sd_ini.h"

#define SD_PROFILE_FORMAT 1

enum { SD_PROFILE_AUTH_PUBLICKEY = 1u << 0, SD_PROFILE_AUTH_KBDINT = 1u << 1, SD_PROFILE_AUTH_PASSWORD = 1u << 2 };
/* Same numeric values as sd_vfs_symlinks / sd_vfs_write_mode (sd_config does not depend on sd_vfs). */
enum { SD_PROFILE_SYMLINKS_FOLLOW_INSIDE = 0, SD_PROFILE_SYMLINKS_FOLLOW = 1, SD_PROFILE_SYMLINKS_HIDE = 2 };
enum { SD_PROFILE_WRITE_THROUGH = 0, SD_PROFILE_WRITE_BEHIND = 1 };

typedef struct sd_profile {
  int      format;
  char     id[33];               /* 32 lowercase hex; "" until assigned */
  char     name[128];            /* UTF-8 display name */
  char     host[256];            /* UTF-8: DNS name, IPv4 or IPv6 literal */
  uint16_t port;                 /* default 22 */
  char     user[128];            /* UTF-8; "" = current Windows user name at mount time */
  char     remote_path[1024];    /* UTF-8; "" = login directory */
  char     identity[MAX_PATH * 3]; /* UTF-8 as written (may contain %VAR% or ~\); "" = none */
  uint32_t auth_methods;         /* SD_PROFILE_AUTH_*; default all three */
  char     target[MAX_PATH * 3]; /* "auto" or "X:" (folders: Dokany, later) */
  int      read_only;
  int      symlinks;             /* SD_PROFILE_SYMLINKS_* (D40 default follow_inside) */
  int      write_mode;           /* SD_PROFILE_WRITE_* (D9 default through) */
  char     label[128];           /* "" = name */
} sd_profile;

void   sd_profile_defaults(sd_profile *p);
/* Reads and validates the M0 keys. On error *bad_key (if given) names the offending "section.key". */
sd_err sd_profile_from_ini(const sd_ini *ini, sd_profile *p, const char **bad_key);
/* Writes the M0 keys into ini (creating it when *ini is NULL), keeping everything else. */
sd_err sd_profile_to_ini(const sd_profile *p, sd_ini **ini);
sd_err sd_profile_validate(const sd_profile *p, const char **bad_key);
sd_err sd_profile_new_id(char out[33]);              /* 128-bit random (RtlGenRandom) */

/* Parses "[user@]host[:port]" (IPv6 as "[::1]:2222"). user/host are UTF-8 from UTF-16 input. */
sd_err sd_parse_host_spec(const wchar_t *spec, char *user, size_t user_cap, char *host, size_t host_cap,
                          uint16_t *port);
/* "X:" / "x:" / "X:\" -> 'X' (uppercase); 0 if not a drive letter. */
wchar_t sd_parse_drive_letter(const wchar_t *s);

/* ---- locations ---- */

/* Per-user root (%APPDATA%\LibreStatic\ShellDrive) or the override. */
sd_err sd_config_root(wchar_t *out, size_t cch);
sd_err sd_config_profiles_dir(wchar_t *out, size_t cch);
/* %LOCALAPPDATA%\LibreStatic\ShellDrive\logs (or <override>\logs). */
sd_err sd_config_logs_dir(wchar_t *out, size_t cch);
/* Creates root, profiles\ and logs\ with the protected per-user DACL when missing. */
sd_err sd_config_ensure_dirs(void);
/* Process-wide override of the per-user root (portable layouts, tests). NULL clears it. */
void   sd_config_set_root_override(const wchar_t *dir);

/* Expands %VAR% and a leading ~\ or ~/ (user profile) of a UTF-8 path value into UTF-16. */
sd_err sd_config_expand_path(const char *utf8, wchar_t *out, size_t cch);

/* ---- profile files ---- */

/* Exclusive lock on <root>\config.lock (3.6). Returns a handle for sd_config_unlock. */
sd_err sd_config_lock(HANDLE *lock, DWORD timeout_ms);
void   sd_config_unlock(HANDLE lock);

sd_err sd_profile_load_file(const wchar_t *path, sd_profile *p, const char **bad_key);
/* Finds a profile by id (exact) or name (case-insensitive). path_out may be NULL. */
sd_err sd_profile_find(const char *name_or_id, sd_profile *p, wchar_t *path_out, size_t path_cch);
/* Creates or updates the profile file (assigns an id when empty); unknown keys are preserved. */
sd_err sd_profile_save(sd_profile *p);
sd_err sd_profile_delete(const char *name_or_id);

typedef int (*sd_profile_enum_cb)(void *ctx, const sd_profile *p, const wchar_t *path);  /* 0 stops */
sd_err sd_profile_enum(sd_profile_enum_cb cb, void *ctx);

#endif /* SD_CONFIG_H */
