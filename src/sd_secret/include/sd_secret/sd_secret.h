/* sd_secret: saved passwords, key passphrases, proxy passwords and DPAPI-kept private keys (03 §4).
 *
 * Stores (03 §4.1-§4.5):
 * - User scope: Windows Credential Manager, CRED_TYPE_GENERIC (never CRED_TYPE_DOMAIN_PASSWORD),
 *   persistence CRED_PERSIST_LOCAL_MACHINE (CRED_PERSIST_ENTERPRISE when the user turned on roaming,
 *   settings [credentials] persist = enterprise). Blob = UTF-16LE secret without terminator, capped at
 *   512 bytes (the XP-era CRED_MAX_CREDENTIAL_BLOB_SIZE). Longer secrets, and every secret when
 *   CredGetSessionTypes reports that generic credentials cannot persist at LOCAL_MACHINE (XP Home,
 *   Vista Home Basic/Premium/Starter), go to the DPAPI fallback: <dir>\secrets\<hex SHA-256 of the
 *   target name>.sdsec = "SDSEC1\0\0", u32 version (1), u32 blob length, CryptProtectData blob
 *   (user scope, CRYPTPROTECT_UI_FORBIDDEN, entropy "com.librestatic.shelldrive/secret/v1/" + target
 *   name, description = target name), then a trailer u32 length + target name (UTF-8, clear) so
 *   that enumeration needs no decryption (an addition to 03 §4.3; readers accept files without it).
 *   Integers are little-endian. Both stores are read on get and cleared on delete.
 * - Service scope: DPAPI files only, under the service folder (SYSTEM user scope, 03 §4.5).
 * - Private keys "kept by ShellDrive" (4.4): keys\<id>.sdkey; the image format is sd_keyfile's.
 *
 * Target names (4.2): "com.librestatic.shelldrive:" + kind + ":" + target, where target is
 *   password    "<user>@<host>:<port>"
 *   passphrase  "SHA256:<base64 fingerprint of the public key>"
 *   proxy       "<http|socks5>:<user>@<proxyhost>:<port>"
 * Callers pass the raw target; escaping is done inside: in the user part '%' and uppercase ASCII
 * letters become %XX (TargetName is case-insensitive, Unix user names are not), the host part is
 * lowercased, IPv6 literals keep their brackets.
 *
 * Secrets are UTF-8 for callers (sd_prompt_answer takes UTF-8) and returned in sd_secbuf (wiped on
 * free). Nothing here logs a secret value.
 *
 * APIs: CredWriteW/CredReadW/CredDeleteW/CredEnumerateW/CredFree (XP+, static imports, in every floor
 * list), CredGetSessionTypes resolved at run time (sd_platform_resolve_by_name), CryptProtectData/
 * CryptUnprotectData (Windows 2000+). Thread safety: reentrant; configuration is process-wide and set
 * once at start (or by tests). File writes are atomic (tmp + MoveFileExW); folders get the protected
 * per-user DACL (TM-R07) through sd_config. */
#ifndef SD_SECRET_H
#define SD_SECRET_H

#include <windows.h>

#include "sd/base.h"
#include "sd_base/sd_err.h"
#include "sd_platform/sd_secbuf.h"

typedef enum sd_secret_kind { SD_SECRET_PASSWORD = 0, SD_SECRET_PASSPHRASE = 1, SD_SECRET_PROXY = 2 } sd_secret_kind;
typedef enum sd_secret_scope { SD_SECRET_USER = 0, SD_SECRET_SERVICE = 1 } sd_secret_scope;
typedef enum sd_secret_store { SD_SECRET_STORE_CREDMAN = 1, SD_SECRET_STORE_DPAPI = 2 } sd_secret_store;

#define SD_SECRET_PREFIX       "com.librestatic.shelldrive:"
#define SD_SECRET_MAX_TARGET   512          /* characters of a full target name */
#define SD_SECRET_CREDMAN_MAX  512          /* blob bytes (256 UTF-16 code units) */
#define SD_SECRET_MAX_VALUE    4096         /* bytes of a UTF-8 secret */

typedef struct sd_secret_config {
  const wchar_t *user_dir;     /* folder holding secrets\ and keys\; NULL = sd_config_root() */
  const wchar_t *service_dir;  /* NULL = %ProgramData%\LibreStatic\ShellDrive\service */
  const char *prefix;          /* NULL = SD_SECRET_PREFIX; tests use their own (must end with ':') */
  int persist_enterprise;      /* settings [credentials] persist = enterprise (roaming) */
  int force_dpapi;             /* never use Credential Manager (tests, portable mode) */
} sd_secret_config;
/* Copies the configuration (strings included). NULL restores the defaults. */
sd_err sd_secret_configure(const sd_secret_config *cfg);

/* Full target name for kind + raw target ("com.librestatic.shelldrive:password:alice@host:22"). */
sd_err sd_secret_target_name(sd_secret_kind k, const char *target, char *out, size_t cap);
/* Raw targets built from their parts (port 0 = 22 for passwords). scheme: "http" or "socks5". */
sd_err sd_secret_target_password(const char *user, const char *host, uint16_t port, char *out, size_t cap);
sd_err sd_secret_target_proxy(const char *scheme, const char *user, const char *host, uint16_t port,
                              char *out, size_t cap);

/* SD_E_NOT_FOUND when nothing is saved. *out holds the UTF-8 secret (len bytes, NUL after them). */
sd_err sd_secret_get(sd_secret_scope s, sd_secret_kind k, const char *target, sd_secbuf **out);
/* Picks Credential Manager or the DPAPI file (see above) and removes the copy in the other store.
   comment: the localized Credential Manager comment ("Saved by ShellDrive for <profile>"; may be NULL). */
sd_err sd_secret_put(sd_secret_scope s, sd_secret_kind k, const char *target, const wchar_t *comment,
                     const char *value, size_t len);
sd_err sd_secret_delete(sd_secret_scope s, sd_secret_kind k, const char *target);   /* SD_E_NOT_FOUND */
/* Which store a put would use for a value of this length (diagnostics, tests). */
sd_secret_store sd_secret_store_for(sd_secret_scope s, size_t value_len);

/* Targets only, never values. raw_target is the part after "<prefix><kind>:" in its stored (escaped)
   form. Returning 0 from cb stops. */
typedef int (*sd_secret_enum_cb)(void *ctx, sd_secret_kind k, const char *raw_target, sd_secret_store store);
sd_err sd_secret_enum(sd_secret_scope s, sd_secret_enum_cb cb, void *ctx);
/* Deletes every target of this prefix in both stores (user-cleanup --secrets, tests). */
sd_err sd_secret_delete_all(sd_secret_scope s, uint32_t *removed);

/* ---- DPAPI-kept private keys (4.4) ----
 * The SDKEY1 image (clear metadata + DPAPI blob) is produced and read by sd_keyfile
 * (sd_ssh_key_dpapi_protect / _probe / _unprotect); sd_secret only owns the files: keys\<id>.sdkey
 * in the scope's folder (protected DACL), written atomically. */

sd_err sd_secret_key_new_id(char id_out[33]);                       /* 128-bit random, lowercase hex */
sd_err sd_secret_key_write(sd_secret_scope s, const char *id, const uint8_t *image, size_t len);
/* *image is sd_alloc'ed (sd_free). SD_E_NOT_FOUND when there is no such key. */
sd_err sd_secret_key_read(sd_secret_scope s, const char *id, uint8_t **image, size_t *len);
sd_err sd_secret_key_delete(sd_secret_scope s, const char *id);
typedef int (*sd_secret_key_enum_cb)(void *ctx, const char *id);   /* 0 stops */
sd_err sd_secret_key_enum(sd_secret_scope s, sd_secret_key_enum_cb cb, void *ctx);

#endif /* SD_SECRET_H */
