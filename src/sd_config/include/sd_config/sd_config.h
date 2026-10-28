/* sd_config: per-user configuration locations, the profile model and profile files (03 §3).
 *
 * M0 scope: the per-user store %APPDATA%\LibreStatic\ShellDrive (D45; SHGetFolderPathW, XP+), one
 * profile per file in profiles\*.ini, and the profile keys a mount needs (3.4.1): profile.host,
 * port, user, remote_path, name, id; auth.identity, auth.methods; mount.target, read_only,
 * symlinks, write_mode, label. Every other key and comment is preserved on rewrite (sd_ini).
 * Folders are created with the protected DACL D:P(A;OICI;FA;;;<UserSID>)(A;OICI;FA;;;SY) (TM-R07).
 * Writers serialize on config.lock (LockFileEx) and replace files atomically (tmp + MoveFileExW).
 *
 * M1 keys: mount.backend, mount.offline_wait, mount.reconnect_grace, cache.disk, connection.channels
 * (written only when set or already present).
 *
 * M2 keys (3.4.1): auth.identity.N, identity_store, certificate, agent, identities_only, agent_keys,
 * save_password, cache_secrets_for_reconnect; proxy.jump, proxy.proxy(.N), proxy_auth(.N),
 * proxy_fallback_direct(.N); connection.connections; security.legacy_algorithms, legacy_accepted,
 * host_key_alias, update_host_keys, keepalive, connect_timeout, refuse_terrapin_exposed. The chain
 * resolver (sd_chain_resolve) and the importers (sd_import.h) build on them. Per-mount cache folders under
 * %LOCALAPPDATA%\LibreStatic\ShellDrive\cache (protected DACL) and the identity cache file in them.
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
/* Same numeric values as sd_mount_backend_kind. */
enum { SD_PROFILE_BACKEND_AUTO = 0, SD_PROFILE_BACKEND_DOKANY = 1, SD_PROFILE_BACKEND_WEBDAV = 2 };

/* ---- M2 (03 §3.4.1, §3.8) ---- */
#define SD_PROFILE_MAX_IDENTITIES 4               /* auth.identity, identity.2 .. identity.4 */
#define SD_PROFILE_MAX_HOPS       8               /* proxy.jump entries after expansion */
#define SD_PROFILE_MAX_LEGS       (SD_PROFILE_MAX_HOPS + 1)
enum { SD_PROFILE_UNSET = -1 };
enum { SD_PROFILE_AGENT_AUTO = 0, SD_PROFILE_AGENT_PAGEANT = 1, SD_PROFILE_AGENT_OPENSSH = 2, SD_PROFILE_AGENT_NONE = 3 };
/* Same numeric values as sd_proxy_kind (sd_ssh.h). */
enum { SD_PROFILE_PROXY_NONE = 0, SD_PROFILE_PROXY_HTTP = 1, SD_PROFILE_PROXY_SOCKS5 = 2, SD_PROFILE_PROXY_SYSTEM = 3 };
enum { SD_PROFILE_PROXY_AUTH_AUTO = 0, SD_PROFILE_PROXY_AUTH_BASIC = 1, SD_PROFILE_PROXY_AUTH_NEGOTIATE = 2,
       SD_PROFILE_PROXY_AUTH_NONE = 3 };
/* Same numeric values as sd_legacy_policy / sd_hku_mode (sd_ssh.h). */
enum { SD_PROFILE_LEGACY_ALLOW = 0, SD_PROFILE_LEGACY_WARN = 1, SD_PROFILE_LEGACY_ASK = 2, SD_PROFILE_LEGACY_REFUSE = 3 };
enum { SD_PROFILE_HKU_YES = 0, SD_PROFILE_HKU_ASK = 1, SD_PROFILE_HKU_NO = 2 };

/* One proxy leg (3.8): none | system | http://[user@]host[:port] | socks5://[user@]host[:port]. */
typedef struct sd_proxy_spec {
  int kind;                      /* SD_PROFILE_PROXY_* */
  char host[256];                /* UTF-8; IPv6 without brackets */
  uint16_t port;                 /* filled with the scheme default (8080 / 1080) by the parser */
  char user[128];                /* "" = none; passwords are never part of a spec */
} sd_proxy_spec;

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
  /* M1 */
  int      backend;              /* mount.backend: SD_PROFILE_BACKEND_* (auto) */
  uint32_t offline_wait_ms;      /* mount.offline_wait; 0 = default (3 s) */
  uint32_t reconnect_grace_ms;   /* mount.reconnect_grace; 0 = default (60 s) */
  uint32_t disk_cache_mb;        /* cache.disk in MiB; 0 = no disk tier (default) */
  uint32_t channels;             /* connection.channels: 1 or 2 (default 2) */
  /* M2: every key is written only when set or already present (M0/M1 files stay as they were) */
  char     identity_n[SD_PROFILE_MAX_IDENTITIES - 1][MAX_PATH * 3];  /* auth.identity.2 .. .4 */
  char     identity_store[33];   /* auth.identity_store: id of a DPAPI-kept key (4.4); "" = none */
  char     certificate[MAX_PATH * 3];   /* auth.certificate */
  int      agent;                /* auth.agent: SD_PROFILE_AGENT_* (auto) */
  int      identities_only;      /* auth.identities_only: SD_PROFILE_UNSET (D37 rule), 0 or 1 */
  char     agent_keys[512];      /* auth.agent_keys: comma list of SHA256: fingerprints */
  int      save_password;        /* auth.save_password (yes) */
  int      cache_secrets;        /* auth.cache_secrets_for_reconnect (yes) */
  char     jump[1024];           /* proxy.jump as written: profile names/ids or [user@]host[:port] */
  sd_proxy_spec proxy[SD_PROFILE_MAX_LEGS];   /* proxy.proxy (= leg 1) and proxy.proxy.N */
  int      proxy_auth[SD_PROFILE_MAX_LEGS];   /* proxy.proxy_auth(.N): SD_PROFILE_PROXY_AUTH_* */
  uint32_t proxy_fallback_direct;             /* bit k: proxy.proxy_fallback_direct(.k+1) */
  uint32_t connections;          /* connection.connections 1..4 (1, D18) */
  int      legacy_algorithms;    /* security.legacy_algorithms: SD_PROFILE_LEGACY_* (warn, D33) */
  char     legacy_accepted[80];  /* security.legacy_accepted: "sha256:<hex>" of the accepted set */
  char     host_key_alias[256];  /* security.host_key_alias */
  int      update_host_keys;     /* security.update_host_keys: SD_PROFILE_HKU_* (ask) */
  uint32_t keepalive_ms;         /* security.keepalive; 0 = default (15 s) */
  uint32_t connect_timeout_ms;   /* security.connect_timeout; 0 = default (20 s) */
  int      refuse_terrapin_exposed;   /* security.refuse_terrapin_exposed (no) */
  int      compression;          /* connection.compression (no): zlib@openssh.com, delayed (01 section 4.7) */
  int      network_location;     /* mount.network_location (yes): Network locations entry, 03 §8.7 (D14) */
  /* M3 (3.4.1). Every value holds its effective setting (sd_profile_defaults sets the defaults). "parsed only"
     keys are validated and round-tripped but have no consumer yet (docs/dev/m3-notes.md). */
  int      scope;                /* profile.scope: SD_PROFILE_SCOPE_* (user) */
  char     service_access[512];  /* profile.service_access (M5): comma list of SIDs or names; parsed only */
  char     service_access_write[512];  /* profile.service_access_write (M5): subset of the above; parsed only */
  int      trust;                /* security.trust: SD_PROFILE_TRUST_* (untrusted) */
  int      shell_active_files;   /* mount.shell_active_files: SD_PROFILE_UNSET (derived from trust, D41), 0 show, 1 block */
  int      hide_dotfiles;        /* mount.hide_dotfiles (yes) */
  int      exec_hint;            /* mount.exec_hint (yes); parsed only */
  int      autostart;            /* mount.autostart: SD_PROFILE_AUTOSTART_* (no) */
  int      autostart_sessions;   /* mount.autostart_sessions: SD_PROFILE_SESSIONS_* (any) */
  int      open_after_mount;     /* mount.open_after_mount (no) */
  int      fsync_on_flush;       /* mount.fsync_on_flush (yes) */
  int      atomic_put;           /* mount.atomic_put (no); parsed only */
  int      case_sensitive;       /* mount.case: 0 insensitive (default), 1 sensitive */
  int      remote_case;          /* mount.remote_case: 0 auto (default), 1 sensitive, 2 insensitive (sd_vfs_case) */
  char     remote_charset[32];   /* mount.remote_charset: "" = UTF-8; parsed only (the vfs refuses other code pages) */
  uint32_t umask;                /* mount.umask: 022 octal = 18; 1..0777 */
  int      map_readonly;         /* mount.map_readonly (yes) */
  int      show_special;         /* mount.show_special (no) */
  int      allow_system;         /* mount.allow_system (yes); M5, parsed only */
  int      strict_acl;           /* mount.strict_acl (no); parsed only */
  int      identity_probe_exec;  /* mount.identity_probe: 0 owner (default), 1 exec */
  char     fs_name[32];          /* mount.fs_name ("NTFS"): Dokany volume file system name */
  uint32_t offline_hint_over_mb; /* mount.offline_hint_over_mb (0 = off); parsed only */
  int      mark_of_the_web;      /* mount.mark_of_the_web: 0 off (default), 1 internet; parsed only (vfs refuses it) */
  uint32_t attr_ttl_ms, dir_ttl_ms, neg_ttl_ms;   /* cache.attr_ttl, dir_ttl, neg_ttl (30 s, 30 s, 10 s) */
  int      open_revalidate_ms;   /* cache.open_revalidate (1 s); -1 = never */
  uint32_t max_readahead;        /* cache.max_readahead (8 MiB) */
  int      crypto_backend;       /* security.crypto_backend: SD_PROFILE_CRYPTO_* (auto); parsed only */
  /* M4 (03 §3.4.1, §3.4 "write mode"): 1 when mount.write_mode is in the file (or was set by a writer). 0 means the
     key is absent and the effective mode comes from [defaults] write_mode (sd_profile_effective_write_mode). */
  int      write_mode_set;
} sd_profile;

enum { SD_PROFILE_SCOPE_USER = 0, SD_PROFILE_SCOPE_USERS = 1, SD_PROFILE_SCOPE_SERVICE = 2 };
enum { SD_PROFILE_TRUST_UNTRUSTED = 0, SD_PROFILE_TRUST_TRUSTED = 1 };
enum { SD_PROFILE_AUTOSTART_NO = 0, SD_PROFILE_AUTOSTART_LOGON = 1, SD_PROFILE_AUTOSTART_BOOT = 2 };
enum { SD_PROFILE_SESSIONS_ANY = 0, SD_PROFILE_SESSIONS_CONSOLE = 1, SD_PROFILE_SESSIONS_REMOTE = 2 };
enum { SD_PROFILE_CRYPTO_AUTO = 0, SD_PROFILE_CRYPTO_OWN = 1 };
#define SD_PROFILE_UMASK_DEFAULT 18u                       /* 022 octal */
#define SD_PROFILE_MAX_READAHEAD (1024u * 1024u * 1024u)   /* cache.max_readahead upper bound */

/* M3 helpers. The effective shell-active setting: 1 = block (shell_active_files, or the D41 default from
   security.trust when the key is unset). */
int sd_profile_block_shell_active(const sd_profile *p);
/* Parses "022"-style octal text (1 to 4 digits, value 1..0777) for mount.umask; 1 on success. */
int sd_profile_parse_umask(const char *v, uint32_t *out);

void   sd_profile_defaults(sd_profile *p);
/* Reads and validates the M0 keys. On error *bad_key (if given) names the offending "section.key". */
sd_err sd_profile_from_ini(const sd_ini *ini, sd_profile *p, const char **bad_key);
/* Writes the M0 keys into ini (creating it when *ini is NULL), keeping everything else. */
sd_err sd_profile_to_ini(const sd_profile *p, sd_ini **ini);
sd_err sd_profile_validate(const sd_profile *p, const char **bad_key);
sd_err sd_profile_new_id(char out[33]);              /* 128-bit random (RtlGenRandom) */

/* M2 helpers. sd_proxy_spec_parse: SD_E_INVALID_PARAM for anything else, including "user:pass@"
   (passwords never live in a spec, 3.8) and a path after the port. format is the inverse. */
sd_err sd_proxy_spec_parse(const char *s, sd_proxy_spec *out);
sd_err sd_proxy_spec_format(const sd_proxy_spec *p, char *out, size_t cap);
/* Number of auth.identity* entries that are set (identity first, then identity_n in order). */
uint32_t sd_profile_identity_count(const sd_profile *p);
const char *sd_profile_identity_at(const sd_profile *p, uint32_t i);
/* D37 / TM-Q07: identities_only as a bool (unset -> yes when identity, identity_store or agent_keys
   is set). */
int sd_profile_identities_only(const sd_profile *p);
/* "sha256:<hex>" of the sorted, comma-joined, de-duplicated algorithm list (7.6 legacy_accepted). */
void sd_legacy_set_hash(const char *const *names, uint32_t n, char out[80]);

/* proxy.jump split into entries (trimmed, empty entries rejected, at most SD_PROFILE_MAX_HOPS). */
typedef struct sd_jump_list { uint32_t count; char entry[SD_PROFILE_MAX_HOPS][300]; } sd_jump_list;
sd_err sd_jump_parse(const char *list, sd_jump_list *out);

/* The resolved connection chain of a profile (3.4.1 ProxyJump semantics): jump entries resolve to
   profiles of the same store (by id, then name; the own proxy.jump of a referenced profile is
   expanded in front of it, its proxy is not used) or are parsed as [user@]host[:port] and inherit
   [auth] of the referencing profile. hop[count - 1] is the target. Proxies come from the top profile
   only: leg k (proxy[k - 1]) reaches hop[k - 1]. Rejected with SD_E_INVALID_PARAM and *why: cycles
   ("jump_cycle"), more than 8 jump hops ("jump_too_long"), an entry that is neither a profile nor a
   host spec ("jump_invalid"), a proxy on a leg beyond the chain ("proxy_leg"), system on a leg other
   than 1 ("proxy_system_leg"). */
typedef struct sd_chain_hop {
  char host[256];
  uint16_t port;
  char user[128];                /* "" = the Windows user name (filled by the host) */
  uint32_t identity_count;
  char identity[SD_PROFILE_MAX_IDENTITIES][MAX_PATH * 3];
  char identity_store[33];
  char certificate[MAX_PATH * 3];
  int agent;                     /* SD_PROFILE_AGENT_* */
  int identities_only;           /* resolved bool (D37) */
  char agent_keys[512];
  uint32_t auth_methods;         /* SD_PROFILE_AUTH_* */
  char host_key_alias[256];
  int update_host_keys;          /* SD_PROFILE_HKU_* */
  int save_password, cache_secrets;
  char profile_name[128];        /* hop from a profile reference; "" for a host spec */
  char profile_id[33];
} sd_chain_hop;
typedef struct sd_chain {
  uint32_t count;                /* 1 + jump hops */
  sd_chain_hop hop[SD_PROFILE_MAX_LEGS];
  sd_proxy_spec proxy[SD_PROFILE_MAX_LEGS];
  int proxy_auth[SD_PROFILE_MAX_LEGS];
  uint32_t proxy_fallback_direct;
} sd_chain;
/* Looks a profile up by id or name; SD_E_NOT_FOUND when there is none. */
typedef sd_err (*sd_profile_lookup_fn)(void *ctx, const char *name_or_id, sd_profile *out);
/* *out is sd_alloc'ed (sd_free). lookup NULL = sd_profile_find on the per-user store. */
sd_err sd_chain_resolve(const sd_profile *p, sd_profile_lookup_fn lookup, void *ctx, sd_chain **out,
                        const char **why);

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
/* M2: creates one folder with the protected per-user DACL (user + SYSTEM, TM-R07) when it is
   missing; its parent must exist. Used by sd_secret for secrets\ and keys\. */
sd_err sd_config_make_protected_dir(const wchar_t *path);
/* M1: %LOCALAPPDATA%\LibreStatic\ShellDrive\cache\<16 hex digits of FNV-1a 64 of key> (or
   <override>\cache\...), created with the protected per-user DACL. key identifies one mount source,
   e.g. "user@host:port"; the disk tier and the identity cache of that source live there. */
sd_err sd_config_cache_dir(const char *key, wchar_t *out, size_t cch);
/* Identity cache (02 §3.4 step 2, D10): <dir>\identity.ini remembers the definitive uid/gid learned
   for the server whose verified host key is hostkey_fp. load returns SD_E_NOT_FOUND when nothing is
   cached for that key (a different host key never matches). */
sd_err sd_config_identity_load(const wchar_t *dir, const char *hostkey_fp, uint32_t *uid, uint32_t *gid);
sd_err sd_config_identity_store(const wchar_t *dir, const char *hostkey_fp, uint32_t uid, uint32_t gid);

/* Notification kinds with a [ui] notify_<kind> switch (03 §7.7). Always-on kinds (host key changed, write failed,
   agent stopped unexpectedly, session objects interference) have no switch. */
enum { SD_SETTINGS_PRIVACY_STANDARD = 0, SD_SETTINGS_PRIVACY_STRICT = 1 };
typedef enum sd_notify_kind {
  SD_NOTIFY_CONNECTION_LOST = 0, SD_NOTIFY_RECONNECTED, SD_NOTIFY_MOUNT_FAILED, SD_NOTIFY_MOUNTED,
  SD_NOTIFY_LEGACY_ALGORITHMS, SD_NOTIFY_HOSTKEYS_OFFERED, SD_NOTIFY_HOSTKEYS_SAVED, SD_NOTIFY_PROXY_PASSWORD,
  SD_NOTIFY_POOL_LIMITED, SD_NOTIFY_SERVICE_ATTENTION, SD_NOTIFY_UPDATE_AVAILABLE, SD_NOTIFY_UPDATE_STALE,
  SD_NOTIFY_TERRAPIN, SD_NOTIFY_HOSTKEYS_SOURCE, SD_NOTIFY_DISK_CACHE, SD_NOTIFY_COUNT
} sd_notify_kind;

/* M1 subset of <root>\settings.ini (03 §3.4.2): [log] level = error|warn|info|debug|trace (info) and
   [cache] memory = size (0 = sd_vfs default). A missing file gives the defaults; an invalid value
   is logged and ignored (the setting keeps its default). */
typedef struct sd_settings {
  int    log_level;              /* sd_log_level values: 0 error .. 4 trace; default 2 (info) */
  UINT64 cache_memory;           /* bytes; 0 = default */
  /* M2 */
  int    openssh_source;         /* [hostkeys] openssh_source (yes, D7) */
  int    putty_source;           /* [hostkeys] putty_source (yes, D7) */
  int    persist_enterprise;     /* [credentials] persist = local (0, default) | enterprise (1) */
  /* M3 (03 §3.2, §3.4.2): [ui] and [defaults] */
  char   ui_language[16];        /* [ui] language: "" = system default (the UI default language order, 9.3) */
  int    notify;                 /* [ui] notify = yes (balloons on, default) | no */
  int    default_backend;        /* [defaults] backend: SD_PROFILE_BACKEND_* (auto) */
  char   update_channel[8];      /* [update] channel: "stable" (default) or "beta" (04 §9.1, the Settings window) */
  /* M4 (03 §3.4 global settings, §7.7, §10.1) */
  int    default_write_mode;     /* [defaults] write_mode = through (default, D9) | behind: profiles without mount.write_mode */
  int    log_privacy;            /* [log] privacy = standard (default) | strict: SD_SETTINGS_PRIVACY_* (10.1, TM-R31) */
  int    agent_start_at_logon;   /* [agent] start_at_logon = yes | no (default): the agent's HKCU Run value (3.2 Start) */
  unsigned char notify_kind[SD_NOTIFY_COUNT];   /* [ui] notify_<kind> = yes | no, each under the notify master (7.7) */
} sd_settings;
void   sd_settings_defaults(sd_settings *s);
sd_err sd_settings_from_ini(const sd_ini *ini, sd_settings *s);   /* SD_E_INVALID_PARAM if a value was bad */
sd_err sd_settings_load(sd_settings *s);
/* Writes the settings this struct holds into settings.ini under the per-user root: other keys and comments
   are kept, the file is replaced atomically under config.lock. An empty ui_language removes [ui] language. */
sd_err sd_settings_save(const sd_settings *s);

/* M4 helpers. Key name under [ui] of one kind, e.g. "notify_connection_lost". */
const char *sd_notify_kind_key(sd_notify_kind k);
/* Kind of a `warning` event code (03 §2.4, §7.7), or -1 when the code has no per-kind setting. */
int sd_notify_kind_from_code(const char *code);
/* 1 when a balloon of this kind may be shown: the [ui] notify master switch and the kind's own switch. kind -1
   (no per-kind setting) follows the master switch only. */
int sd_settings_notify_on(const sd_settings *s, int kind);
/* Effective write mode of a profile (D9, 03 §3.4): the explicit mount.write_mode, else [defaults] write_mode.
   policy_force_through (ForceWriteThrough = 1) makes the effective mode through; an explicit behind under that
   policy is refused with SD_E_ACCESS_DENIED (a default is clamped to through instead). *mode is SD_PROFILE_WRITE_*. */
sd_err sd_profile_effective_write_mode(const sd_profile *p, const sd_settings *s, int policy_force_through, int *mode);
/* Effective [log] privacy, SD_SETTINGS_PRIVACY_*. policy_value is the LogPrivacy policy: -1 = not set, else 0 or 1;
   a set policy overrides the file (03 §3.1). */
int    sd_settings_effective_privacy(const sd_settings *s, int policy_value);
/* 1 when the agent's HKCU Run value should exist: [agent] start_at_logon = yes, or a profile with
   mount.autostart = logon (03 §3.2 Start). */
int    sd_settings_agent_run_wanted(const sd_settings *s);
/* The per-installation key of the log privacy hash (03 §10.1): 32 bytes read from state\log.key, created with
   sd_random and the protected per-user DACL when missing. */
sd_err sd_config_log_key(uint8_t key[32]);
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
/* As sd_profile_save; update_menu = 0 leaves menu.cache alone (the caller refreshes it once, sd_menucache_refresh). */
sd_err sd_profile_save_ex(sd_profile *p, int update_menu);
sd_err sd_profile_delete(const char *name_or_id);

typedef int (*sd_profile_enum_cb)(void *ctx, const sd_profile *p, const wchar_t *path);  /* 0 stops */
sd_err sd_profile_enum(sd_profile_enum_cb cb, void *ctx);

/* menu.cache (03 §8.2.2): the profile list of the This PC submenu, read read-only by the shell extension. Every
   profile add, rename and delete rewrites it (sd_profile_save, sd_profile_delete); sd_import_write rewrites it once
   after its saves. The file holds only profile ids and display names. */
#define SD_MENU_ID_CHARS      32u
#define SD_MENU_NAME_BYTES    384u     /* 128 UTF-16 units, at most 3 bytes each in UTF-8 */
#define SD_MENU_NAME_UNITS    128u
#define SD_MENU_MAX_PROFILES  256u
#define SD_MENU_MAX_BYTES     65536u

typedef struct sd_menu_entry {
  char id[SD_MENU_ID_CHARS + 1];      /* 32 lowercase hex digits */
  char name[SD_MENU_NAME_BYTES + 1];  /* UTF-8, sanitized by sd_menu_entry_from_profile */
} sd_menu_entry;

/* Entry of one profile. SD_E_INVALID_PARAM when the profile must not be listed: the id is not 32 lowercase hex
   digits, or no name is left after removing control, bidi and zero-width characters (leading and trailing spaces
   are trimmed, the name is cut at SD_MENU_NAME_UNITS UTF-16 units on a character boundary). */
sd_err sd_menu_entry_from_profile(const sd_profile *p, sd_menu_entry *e);

/* Writes the menu.cache text (header "SDMENU 1", then "<id>\t<name>" lines, LF ends, no BOM) into out. Entries whose
   id repeats an earlier one are skipped, the lines are sorted by name (ASCII case-insensitive), at most
   SD_MENU_MAX_PROFILES are used, and lines that would take the total past SD_MENU_MAX_BYTES are left out. Returns the
   length in bytes (no NUL is written), or 0 when cap is too small or an argument is invalid. */
size_t sd_menu_format(const sd_menu_entry *e, size_t n, char *out, size_t cap);

/* Rewrites menu.cache from the profile store, taking config.lock. The file is replaced atomically. */
sd_err sd_menucache_refresh(void);
/* Full path of menu.cache (LOCALAPPDATAibrestaticshelldrivestatemenu.cache, or <root>state under the test
   override). creates the state folder. */
sd_err sd_menucache_path(wchar_t *out, size_t cch);

#endif /* SD_CONFIG_H */
