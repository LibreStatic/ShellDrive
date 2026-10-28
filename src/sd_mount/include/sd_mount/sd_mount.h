/* sd_mount: turns resolved mount parameters into a running mount (03 §1.11):
 *   sd_known_hosts (user store) -> sd_ssh_config -> sd_sftp_session -> sd_vfs -> sd_dokan | sd_webdav.
 *
 * Backend selection (02 §10.1): params.backend = auto picks Dokany when sd_dokan_probe() is OK, else
 * WebDAV when the WebClient service is present and not disabled (a read-only query; WebClient is only
 * started after WebDAV was chosen, never for a Dokany mount, TM-R21). A forced backend never falls
 * back. sd_mount_backend_kind_used() reports the resolved one.
 *
 * Scope: drive letters only, prompts relayed to the host (hostkey TOFU, password, key passphrase,
 * keyboard-interactive, password change, legacy ack, proxy password). A changed host key is never a
 * prompt: sd_ssh fails the connection and sd_mount reports SD_E_HOSTKEY_MISMATCH with the stored and
 * offered fingerprints.
 *
 * M2 (03 §2.5, §3.4.1, §3.8, §4, §5.6, §7.6): a chain of up to 8 jump hops plus the target
 * (params.hops), a proxy per leg, several identities per hop (files, a DPAPI-kept key blob, agent keys
 * by fingerprint, certificates), agents, the D37 identities_only rule (resolved by the caller), the
 * store list of known_hosts (machine, user, live sources), legacy policy and the legacy warning, the
 * connection pool size (D18), UpdateHostKeys announcements, and saved secrets:
 * - Prompts are first answered from the host's secret store (cb.secret_get, on the control thread)
 *   with SD_ANSWER_FROM_STORE: passwords (and a keyboard-interactive round of exactly one non-echo
 *   prompt that looks like a password, 4.2), key passphrases and proxy passwords. Never on a
 *   hostkey_just_accepted connection for secrets that would travel through the freshly trusted hop or
 *   a later one (TM-R05; passphrases decrypt a local key and are still filled), never twice for the
 *   same hop and kind in one connection (a rejected stored secret goes to the user), never for OTP
 *   rounds, password changes or legacy acks.
 * - Pool members (is_pool_member) are answered from the store or cancelled, never shown; a cancelled
 *   member raises warning pool_limited (reason interactive_auth) once.
 * - An answer with SD_MOUNT_ANSWER_SAVE is written through cb.secret_put once the connection is READY
 *   (authentication succeeded), and wiped otherwise.
 *
 * M1 resilience (01 §10.6, 02 §5, 03 §1.11): the session reconnects by itself (policy from the params;
 * the reconnect secret cache is on, TM-R05 is enforced by sd_ssh). A MOUNTED mount whose connection is
 * lost goes OFFLINE (AUTH_REQUIRED while the loop needs the user) and keeps its drive; the next READY
 * puts it back to MOUNTED without remounting the backend. FAILED after READY also stays OFFLINE until
 * the user unmounts. sd_mount_get_conn() reports the session sub-state (reconnect attempt, backoff,
 * generation) and the write_failed count; cb.on_conn fires when it changes. sd_mount_start sets the
 * process-wide memory cache budget (sd_vfs_cache_set_budget).
 *
 * The other modules are reached through sd_mount_backend, a table with exactly their public
 * signatures: sd_mount_backend_real() binds the real modules (mount_real.c, its own library
 * sd_mount_real), tests bind fakes. sd_mount itself only links headers of sd_ssh/sd_sftp/sd_vfs/
 * sd_dokan.
 *
 * Threading (review §4.1, 03 §1.11):
 * - sd_mount_create/start/stop/destroy run on the host control thread only.
 * - Every callback in sd_mount_callbacks except `post` runs on the control thread: sd_mount hops
 *   there from sd_ssh/sd_sftp I/O threads and Dokany threads through `post`.
 * - sd_mount_answer may be called from any thread (the IPC thread); the answer goes straight to
 *   sd_prompt_* (thread-safe in sd_ssh); secrets are wiped by the caller.
 * Ownership: params strings are deep-copied by sd_mount_create. Prompt structs passed to on_prompt
 * are valid during the callback only. */
#ifndef SD_MOUNT_H
#define SD_MOUNT_H

#include <windows.h>

#include "sd/base.h"
#include "sd_base/sd_err.h"
#include "sd_ssh/sd_ssh.h"
#include "sd_sftp/sd_sftp.h"
#include "sd_vfs/sd_vfs.h"
#include "sd_dokan/sd_dokan.h"
#include "sd_webdav/sd_webdav.h"
#include "sd_platform/sd_secbuf.h"

typedef struct sd_mount sd_mount;

typedef enum sd_mount_state {
  SD_MOUNT_CONNECTING, SD_MOUNT_AUTHENTICATING, SD_MOUNT_MOUNTED, SD_MOUNT_OFFLINE,
  SD_MOUNT_AUTH_REQUIRED, SD_MOUNT_FAILED, SD_MOUNT_UNMOUNTING, SD_MOUNT_UNMOUNTED
} sd_mount_state;
const char *sd_mount_state_name(sd_mount_state st);    /* IPC spelling: "connecting", ... */

typedef enum sd_mount_backend_kind {
  SD_MOUNT_BACKEND_AUTO = 0, SD_MOUNT_BACKEND_DOKANY = 1, SD_MOUNT_BACKEND_WEBDAV = 2
} sd_mount_backend_kind;

/* M3 profile.test result: the negotiated algorithms, the target's host-key fingerprint and the realpath
   of the remote path (UTF-8). Strings are NUL-terminated and empty when unknown. */
typedef struct sd_mount_probe {
  char kex[64], hostkey[64], cipher_c2s[64], cipher_s2c[64], mac_c2s[64], mac_s2c[64];
  char hostkey_fp[64];
  char server_version[128];
  char remote_real[1024];
  int legacy;                           /* an outdated algorithm was negotiated on some hop */
} sd_mount_probe;

/* One SFTP connection of the pool (member 0 is the primary). */
typedef struct sd_mount_member {
  int ready;
  uint32_t srtt_ms, inflight, queued;
  uint64_t rx_total, tx_total;
} sd_mount_member;

/* M3 status stats (any thread, read under the mount's lock). has_session / has_vfs say which parts are
   valid. Rates are EWMA of about 2 s (02 R16); totals are bytes of the current generation. The total
   latency and rates come from the session; member[] holds the pool connections (members of 0..members-1). */
typedef struct sd_mount_stats {
  int has_session, has_vfs;
  uint32_t srtt_ms, rttvar_ms, inflight, queued, channels, generation, reconnect_attempts;
  uint64_t rx_bps, tx_bps, rx_total, tx_total;
  uint32_t members;                     /* 0..4 */
  sd_mount_member member[4];
  uint64_t cache_hits, cache_misses, bytes_rd, bytes_wr, write_failed, wb_bytes, reconnects;
} sd_mount_stats;

/* M3 mount.attach_info: the backend in use (requested before MOUNTED) and, for WebDAV, the loopback port of
   the export. The export token is never reported. */
typedef struct sd_mount_attach {
  sd_mount_backend_kind backend;
  wchar_t letter;
  int mounted;
  uint16_t webdav_port;                 /* 0 unless the backend is WebDAV and the export exists */
} sd_mount_attach;

/* A host key as the host keeps it (UpdateHostKeys announcements and hostkey add). */
#define SD_MOUNT_ANNOUNCE_MAX 8
typedef struct sd_mount_hostkey { char type[64]; char fp_sha256[64]; uint8_t blob[2048]; size_t len; } sd_mount_hostkey;

/* hostkey add --from-server (03 §6.1, 5.2): the result of one connect. verified = 1: a stored key of the host
   verified the connection (known_hosts MATCH), and keys are the server's host keys other than that one (the stored
   one is never listed again). verified = 0: first contact (TOFU), keys holds the single key the server presented,
   which the user must accept before anything is stored. count <= SD_MOUNT_ANNOUNCE_MAX. */
typedef struct sd_mount_hk_fetch {
  int verified;
  char lookup_name[300];                /* [host]:port, or host, as known_hosts names it */
  uint32_t count;
  sd_mount_hostkey keys[SD_MOUNT_ANNOUNCE_MAX];
} sd_mount_hk_fetch;

typedef struct sd_mount_backend {
  const char *name;
  sd_err (*ssh_global_init)(void);
  sd_err (*kh_open)(const sd_kh_store *stores, uint32_t count, sd_known_hosts **out);
  void   (*kh_close)(sd_known_hosts *kh);
  sd_err (*session_create)(const sd_ssh_config *ssh, const sd_ssh_callbacks *ssh_cb, const sd_sftp_options *opt,
                           sd_sftp_event_cb ev, void *ev_ctx, sd_sftp_session **out);
  sd_err (*session_start)(sd_sftp_session *s);
  sd_err (*session_close)(sd_sftp_session *s);
  void   (*session_destroy)(sd_sftp_session *s);
  sd_err (*prompt_answer)(sd_prompt *p, uint32_t n, const char *const *utf8_responses);
  sd_err (*prompt_answer_hostkey)(sd_prompt *p, sd_hostkey_decision d);
  sd_err (*prompt_cancel)(sd_prompt *p);
  sd_vfs_status (*vfs_mount)(sd_sftp_session *s, const sd_vfs_options *o, sd_vfs_event_cb cb, void *cb_ctx,
                             sd_vfs **out);
  void   (*vfs_quiesce)(sd_vfs *v, DWORD budget_ms);
  void   (*vfs_unmount)(sd_vfs *v);
  sd_dokan_avail (*dokan_probe)(const sd_dokan_deny *deny, sd_dokan_probe_info *info);
  sd_err (*dokan_mount_start)(sd_vfs *vfs, const sd_dokan_mount_cfg *cfg, sd_dokan_unmounted_cb cb, void *ctx,
                              sd_dokan_mount **out);
  sd_err (*dokan_mount_stop)(sd_dokan_mount *m);
  /* M1: WebDAV backend (02 §7). NULL entries mean "WebDAV unavailable" (fakes, bring-up builds). */
  sd_webdav_client_state (*webdav_query_client)(sd_webdav_client_info *out);
  sd_err (*webdav_ensure_client)(uint32_t timeout_ms, sd_webdav_client_info *out);
  sd_err (*webdav_mount_start)(sd_vfs *vfs, const sd_webdav_mount_cfg *cfg, sd_webdav_mount **out);
  sd_err (*webdav_mount_stop)(sd_webdav_mount *m);
  sd_err (*webdav_cleanup_mappings)(uint16_t keep_port, uint16_t only_port, uint32_t *removed);
  /* M1 (NULL in older fakes: skipped) */
  void   (*vfs_cache_set_budget)(UINT64 bytes);
  void   (*vfs_get_identity)(sd_vfs *v, sd_vfs_identity *out);
  void   (*webdav_emergency_unmap)(void);                /* crash filter (TM-R17 b) */
  /* M2 (NULL in older fakes: answer_ex falls back to answer, ack/apply/unprotect are unsupported) */
  sd_err (*prompt_answer_ex)(sd_prompt *p, uint32_t n, const char *const *utf8_responses, uint32_t answer_flags);
  sd_err (*prompt_answer_ack)(sd_prompt *p, int accept);
  sd_err (*kh_apply_hostkeys)(sd_known_hosts *kh, sd_kh_store_kind target, const char *lookup_name,
                              const sd_hk_key *add, uint32_t add_count, const sd_hk_key *remove, uint32_t remove_count);
  sd_err (*key_dpapi_unprotect)(const uint8_t *bytes, size_t len, const char *id, sd_secbuf **out);
  /* M3 (NULL in older fakes: the matching call answers SD_E_UNSUPPORTED or reports nothing) */
  sd_err (*session_probe)(sd_sftp_session *s, const char *remote, uint32_t timeout_ms, sd_mount_probe *out);
  void   (*session_stats)(const sd_sftp_session *s, sd_mount_stats *out);
  void   (*vfs_stats)(sd_vfs *v, sd_mount_stats *out);
  void   (*vfs_refresh)(sd_vfs *v, const wchar_t *subtree);
  void   (*vfs_cache_clear)(sd_vfs *v, int disk_too);
  UINT64 (*vfs_write_behind_bytes)(sd_vfs *v);
  uint16_t (*webdav_port)(const sd_webdav_mount *m);
  /* hostkey add (M5 part 8, 03 §6.1; added last, NULL in older fakes: the hostkey mount answers SD_E_UNSUPPORTED).
     The connection of a hostkey mount is an sd_ssh connection without sftp: create, connect (the profile's
     authentication), then fetch the other host keys inside the verified connection. Callbacks run on the sd_ssh
     I/O thread; hk_conn_destroy runs on the control thread. */
  sd_err (*hk_conn_create)(const sd_ssh_config *cfg, const sd_ssh_callbacks *cb, sd_ssh_conn **out);
  sd_err (*hk_conn_connect)(sd_ssh_conn *c, sd_ssh_done_cb done, void *ctx);
  sd_err (*hk_conn_fetch)(sd_ssh_conn *c, uint32_t hop_index, const char *const *types, uint32_t ntypes,
                          sd_ssh_hostkeys_cb done, void *ctx);
  void   (*hk_conn_destroy)(sd_ssh_conn *c);
} sd_mount_backend;

const char *sd_mount_backend_kind_name(sd_mount_backend_kind k);         /* "auto", "dokany", "webdav" */
int sd_mount_backend_kind_parse(const char *s, sd_mount_backend_kind *out);   /* 1 on success */

/* Real modules (library sd_mount_real; link it only when sd_ssh/sd_sftp/sd_vfs/sd_dokan are built). */
const sd_mount_backend *sd_mount_backend_real(void);

/* M3 vfs and session tuning from the profile (3.4.1). Zero means the sd_vfs_options default, except for the flag
   that is inverted on purpose: shell_active_show = 0 blocks shell-active files (D41, the safe default). */
typedef struct sd_mount_tuning {
  uint32_t attr_ttl_ms, dir_ttl_ms, neg_ttl_ms;   /* cache.attr_ttl, dir_ttl, neg_ttl; 0 = 30 s, 30 s, 10 s */
  int      open_revalidate_ms;                    /* cache.open_revalidate; 0 = 1 s, -1 = never */
  uint32_t max_readahead;                         /* cache.max_readahead; 0 = 8 MiB */
  uint32_t umask;                                 /* mount.umask; 0 = 022 */
  int      hide_dotfiles, map_readonly, show_special, case_sensitive, fsync_on_flush;
  int      remote_case;                           /* sd_vfs_case */
  int      shell_active_show;                     /* mount.shell_active_files = show (1); block (0) */
  int      identity_probe_exec;                   /* mount.identity_probe = exec: SD_SFTP_OPT_IDENTITY_EXEC */
  wchar_t  fs_name[32];                           /* mount.fs_name (Dokany); "" = NTFS */
} sd_mount_tuning;

typedef struct sd_mount_params {
  uint32_t struct_size;                 /* sizeof(sd_mount_params) */
  const wchar_t *host;                  /* as typed */
  uint16_t port;                        /* 0 = 22 */
  const char *user;                     /* UTF-8, required */
  const wchar_t *identity_path;         /* expanded key file path; NULL/"" = none */
  uint32_t auth_methods;                /* SD_AUTH_* (sd_ssh.h); 0 = publickey|kbdint|password */
  const char *remote_path;              /* UTF-8; NULL/"" = login directory */
  wchar_t letter;                       /* 'D'..'Z'; 0 only with hostkey_fetch (a hostkey mount has no drive) */
  int read_only;
  int symlinks;                         /* sd_vfs_symlinks */
  int write_mode;                       /* sd_vfs_write_mode */
  const wchar_t *volume_label;          /* NULL = host */
  const wchar_t *known_hosts_path;      /* user store file; NULL = sd_known_hosts default */
  int backend;                          /* sd_mount_backend_kind; 0 = auto (M1) */
  /* M1; 0 = default everywhere */
  UINT64 cache_memory_bytes;            /* process-wide memory tier ([cache] memory); 0 = min(256 MB, RAM/16) */
  uint32_t disk_cache_mb;               /* cache.disk; 0 = no disk tier */
  const wchar_t *disk_cache_dir;        /* created by the host with the protected DACL (03 §3.2) */
  uint32_t offline_wait_ms;             /* mount.offline_wait (3 s) */
  uint32_t reconnect_grace_ms;          /* mount.reconnect_grace (60 s; 0xFFFFFFFF = none) */
  uint32_t channels;                    /* connection.channels: 1 or 2 (2) */
  int reconnect_disabled;               /* 1 = a loss is final (tests, diagnostics) */
  uint32_t reconnect_initial_ms;        /* 1000 */
  uint32_t reconnect_max_ms;            /* 60000 */
  uint32_t reconnect_max_attempts;      /* 0 = unlimited */
  int no_secret_cache;                  /* auth.cache_secrets_for_reconnect = no */
  /* M2; 0 / NULL = M1 behaviour */
  const struct sd_mount_hop *hops;      /* jump hops then the target; NULL = one hop from the fields above */
  uint32_t hop_count;                   /* 0..9 */
  int legacy_policy;                    /* sd_legacy_policy; default SD_LEGACY_WARN (D33) */
  int refuse_terrapin_exposed;
  int compression;                      /* connection.compression (no): zlib@openssh.com, 01 section 4.7 */
  uint32_t connections;                 /* pool size 1..4 (D18); 0 = 1 */
  uint32_t keepalive_ms, connect_timeout_ms;   /* 0 = sd_ssh defaults */
  const wchar_t *profile_name;          /* shown in Credential Manager comments */
  const sd_kh_store *kh_stores;         /* store list (5.1); NULL = the user store at known_hosts_path */
  uint32_t kh_store_count;
  /* M3: 1 = connect, authenticate and realpath only (profile.test): no vfs, no backend, no drive letter
     needed. The result is read with sd_mount_get_probe() once the mount reports UNMOUNTED. */
  int test_only;
  sd_mount_tuning tuning;               /* M3: vfs and session options of the profile (3.4.1); zeros = defaults */
  /* M5: 1 = global mount (service, scope = service, 03 §1.3): Dokany without DOKAN_OPTION_CURRENT_SESSION.
     Requires volume_sd (a self-relative security descriptor, copied) that encodes service_access and
     service_access_write (02 §6.4); the mount is refused with SD_E_INVALID_PARAM without it. */
  int global_mount;
  const void *volume_sd;
  uint32_t volume_sd_len;
  /* TM-R19 (02 §7.4): 1 = token-only WebDAV (the path token is the only authenticator). Refused with
     SD_E_INVALID_PARAM for global mounts. The host sets it only when it already has the user's answer;
     otherwise sd_mount asks SD_MP_WEBDAV_TOKEN_ONLY when SSPI is unavailable. */
  int token_only;
  int token_only_confirmed;             /* 1 = the user confirmed this enable (03 §7.5) */
  /* M5: global mounts only. service_access (n_access >= 1, required) and service_access_write (may be empty) as
     SID pointers, deep-copied at create; the vfs checks every request against them (02 §6.7, 7.7). */
  void *const *access_sids; uint32_t n_access;
  void *const *write_sids;  uint32_t n_write;
  /* M5 hostkey add (03 §6.1, TM-R04): 1 = connect and fetch host keys inside the connection (test_only implied:
     no sftp session, no vfs, no drive). Authentication is the profile's, prompts go to the usual callbacks. The
     result is read with sd_mount_get_hostkeys() once the mount reports UNMOUNTED or FAILED. hostkey_type NULL =
     the default set of key types. */
  int hostkey_fetch;
  const char *hostkey_type;
} sd_mount_params;


/* One leg's proxy (3.8); kind SD_PROXY_NONE = direct. */
typedef struct sd_mount_proxy {
  int kind;                             /* sd_proxy_kind */
  const wchar_t *host; uint16_t port;
  const char *user;                     /* UTF-8; NULL/"" = none */
  uint32_t auth;                        /* SD_PROXY_AUTH_* */
  int allow_discovered_sspi;            /* policy AllowSystemProxySspi (TM-R10) */
  int allow_system;                     /* policy AllowSystemProxy (TM-R10): 1 lets proxy = system
                                           resolve; 0 (default) refuses the opt-in (03 §3.8) */
  int fallback_direct;                  /* system only */
} sd_mount_proxy;

#define SD_MOUNT_MAX_HOPS 9
#define SD_MOUNT_MAX_IDENTITIES 4
#define SD_MOUNT_MAX_AGENT_KEYS 8

/* One hop of the chain. Strings are deep-copied by sd_mount_create. */
typedef struct sd_mount_hop {
  const wchar_t *host; uint16_t port;   /* port 0 = 22 */
  const char *user;                     /* UTF-8, required */
  const wchar_t *const *identities; uint32_t identity_count;   /* expanded key files (<= 4) */
  const uint8_t *key_blob; size_t key_blob_len; const char *key_label;   /* decrypted DPAPI-kept key */
  const wchar_t *certificate;           /* auth.certificate (applies to the first identity) */
  uint32_t agents;                      /* SD_AGENT_* (0 in the service, D17) */
  int identities_only;                  /* resolved (D37) */
  const char *agent_keys;               /* comma list of SHA256: fingerprints (auth.agent_keys) */
  uint32_t auth_methods;                /* SD_AUTH_*; 0 = all three */
  const char *host_key_alias;
  int update_host_keys;                 /* sd_hku_mode */
  int no_save;                          /* auth.save_password = no: prompts are not savable */
  sd_mount_proxy proxy;                 /* the leg that reaches this hop */
} sd_mount_hop;

typedef enum sd_mount_prompt_kind {
  SD_MP_HOSTKEY, SD_MP_PASSWORD, SD_MP_PASSPHRASE, SD_MP_KBDINT,
  SD_MP_PASSWORD_CHANGE, SD_MP_LEGACY_ACK, SD_MP_PROXY_PASSWORD,    /* M2 */
  SD_MP_WEBDAV_TOKEN_ONLY           /* TM-R19: no sd_prompt; answered with accept (SD_MA_HOSTKEY_TRUST or _ONCE) or reject */
} sd_mount_prompt_kind;
/* "hostkey_unknown", "password", "passphrase", "kbdint", "password_change", "legacy_ack", "proxy_password",
   "webdav_token_only" */
const char *sd_mount_prompt_kind_name(sd_mount_prompt_kind k);

/* Secret kinds of cb.secret_get / secret_put: same values as sd_secret_kind. Targets are raw
   sd_secret targets ("user@host:port", "SHA256:...", "<http|socks5>:user@proxy:port"). */
enum { SD_MOUNT_SECRET_PASSWORD = 0, SD_MOUNT_SECRET_PASSPHRASE = 1, SD_MOUNT_SECRET_PROXY = 2 };

#define SD_MOUNT_PROMPT_MAX_ITEMS 8

typedef struct sd_mount_prompt {
  uint32_t id;                          /* unique per mount */
  sd_mount_prompt_kind kind;
  uint32_t hop_index;
  char host[256];                       /* sanitized by sd_ssh */
  uint16_t port;
  char user[128];
  /* SD_MP_HOSTKEY */
  char key_type[48];
  uint32_t key_bits;
  char fp_sha256[64];
  char lookup_name[300];
  /* SD_MP_PASSWORD / SD_MP_KBDINT / SD_MP_PASSPHRASE */
  uint32_t round;
  int hostkey_just_accepted;            /* TM-R05 */
  char key_path[520];                   /* passphrase: key file (UTF-8) */
  char key_fp[64];
  char name[256], instruction[1024];    /* kbd-int (server text, sanitized) */
  uint32_t item_count;
  struct { char text[512]; int echo; } items[SD_MOUNT_PROMPT_MAX_ITEMS];
  /* M2 */
  uint32_t hop_count;                   /* hops of the chain (1 = no jump hosts) */
  char via_host[256];                   /* hop_index >= 1: the jump host before it (TM-R03) */
  int is_reconnect;
  int can_save;                         /* a "save" answer would be kept (password, passphrase, proxy) */
  char proxy_host[256];                 /* SD_MP_PROXY_PASSWORD */
  uint16_t proxy_port;
  char legacy_names[512];               /* SD_MP_LEGACY_ACK: comma list */
} sd_mount_prompt;

/* UpdateHostKeys announcement (5.6), copied for the host. */
typedef struct sd_mount_announcement {
  uint32_t hop_index;
  char host[256];                       /* the hop's host (display) */
  char lookup_name[300];
  int mode;                             /* sd_hku_mode of the hop */
  uint32_t add_count, remove_count;
  sd_mount_hostkey add[SD_MOUNT_ANNOUNCE_MAX], remove[SD_MOUNT_ANNOUNCE_MAX];
} sd_mount_announcement;
/* Applies an announcement to the user store (never the machine store from a user connection):
   removals first unless add_only, then the proven additions with "# updated-by=hostkeys-00". Opens
   its own sd_known_hosts on the given store list (the user store must be writable in it). Any thread
   that may do file I/O. */
sd_err sd_mount_apply_hostkeys(const sd_mount_backend *be, const sd_kh_store *stores, uint32_t store_count,
                               const sd_mount_announcement *a, int add_only);
/* The same for a chosen store kind: target is the store the keys go to (SD_KH_STORE_MACHINE for the service, 5.6);
   that store must be writable in the list. sd_mount_apply_hostkeys is this with SD_KH_STORE_USER. */
sd_err sd_mount_apply_hostkeys_to(const sd_mount_backend *be, const sd_kh_store *stores, uint32_t store_count,
                                  sd_kh_store_kind target, const sd_mount_announcement *a, int add_only);

/* hostkey add result of a mount created with params.hostkey_fetch (03 §6.1): verified = 1 when the connection
   matched a stored key (the keys are the other host keys of the server); verified = 0 on first contact, where the
   one key the server presented is returned and nothing is stored by sd_mount. Control thread; valid once the
   mount is final. out->lookup_name is left empty (the caller knows its lookup name). */
sd_err sd_mount_get_hostkeys(const sd_mount *m, sd_mount_hk_fetch *out);

/* Details kept for the error report of a failed mount. */
typedef struct sd_mount_failure {
  sd_err err;
  const char *code;                     /* IPC code when it differs from sd_err_name (e.g. "backend_unavailable") */
  char detail[256];                     /* English, for logs */
  /* SD_E_HOSTKEY_MISMATCH: stored vs offered key (from on_hostkey_event) */
  char stored_type[48], stored_fp[64], offered_type[48], offered_fp[64];
  wchar_t store_path[260];              /* "" for the PuTTY registry (03 §5.4, sd_hk_result) */
  uint32_t store_line;                  /* 0 when not applicable (PuTTY) */
  /* SD_E_HOSTKEY_MISMATCH and SD_E_HOSTKEY_TYPE_UNAVAILABLE: the name the key was looked up under, and the
     store of the old key (has_store_kind = 1 for a MISMATCH). */
  char lookup_name[300];
  int has_store_kind;
  sd_kh_store_kind store_kind;
  /* SD_E_HOSTKEY_TYPE_UNAVAILABLE: comma lists of the stored key types and of the server's host key algorithms */
  char stored_types[160], offered_types[160];
} sd_mount_failure;

/* Security state of the current connection of a mount (03 §7.6, 2.4): the outdated algorithms negotiated on
   any hop (category kex, hostkey, cipher or mac; one entry per distinct name) and the Terrapin state. Both
   follow the latest negotiation of each hop; they are not the warnings of the agent's ring. */
#define SD_MOUNT_LEGACY_MAX (SD_MOUNT_MAX_HOPS * 6)
typedef struct sd_mount_legacy_alg {
  char category[12];                    /* "kex", "hostkey", "cipher" or "mac" */
  char name[64];
} sd_mount_legacy_alg;
typedef struct sd_mount_security {
  int legacy;                           /* an outdated algorithm, or an outdated legacy_mask bit, is negotiated */
  uint32_t legacy_count;
  sd_mount_legacy_alg legacy_algs[SD_MOUNT_LEGACY_MAX];
  int terrapin_exposed;                 /* SD_LEGACY_TERRAPIN_EXPOSED on some hop of the current connection */
} sd_mount_security;
/* Any thread; copies the state under the mount's lock. Returns 0 when out or m is NULL. */
int sd_mount_get_security(const sd_mount *m, sd_mount_security *out);

typedef struct sd_mount_callbacks {
  void *ctx;
  /* Any thread: runs fn(arg) later on the control thread, in order. Must not fail; if it cannot
     queue, it must run nothing and sd_mount leaks the item rather than run on a foreign thread. */
  void (*post)(void *ctx, void (*fn)(void *), void *arg);
  void (*on_state)(void *ctx, sd_mount *m, sd_mount_state st, sd_err why);
  void (*on_prompt)(void *ctx, sd_mount *m, const sd_mount_prompt *p);
  void (*on_prompt_closed)(void *ctx, sd_mount *m, uint32_t prompt_id);
  /* M1, all optional, control thread. */
  void (*on_conn)(void *ctx, sd_mount *m);                         /* sd_mount_get_conn() changed */
  /* Write-behind data lost (02 §4.4, C45): path is the mount-relative display path. */
  void (*on_write_failed)(void *ctx, sd_mount *m, const wchar_t *path, UINT64 bytes, const char *status);
  /* vfs NOTICE (e.g. code "disk_cache_refused") */
  void (*on_notice)(void *ctx, sd_mount *m, const char *code, const char *detail);
  /* Identity cache (02 §3.4 step 2, D10), keyed by the verified host key and the user: lookup before
     the vfs mounts (return 1 and fill *out to pass a known identity), store once it is definitive. */
  int  (*lookup_identity)(void *ctx, sd_mount *m, const char *hostkey_fp, sd_vfs_identity *out);
  void (*store_identity)(void *ctx, sd_mount *m, const char *hostkey_fp, const sd_vfs_identity *id);
  /* M2, all optional, control thread. secret_get: copy the saved secret (UTF-8, NUL-terminated) into
     out and return 1; out is wiped by sd_mount after use. secret_put: save (value is wiped after). */
  int  (*secret_get)(void *ctx, sd_mount *m, int kind, const char *target, char *out, size_t cap);
  void (*secret_put)(void *ctx, sd_mount *m, int kind, const char *target, const char *value);
  /* Warnings (03 §2.4, §7.6): "legacy_algorithms" (detail = comma list of the outdated algorithms
     of that hop, sorted; the host compares the set with security.legacy_accepted), "proxy_cleartext"
     (detail = proxy host:port), "pool_limited" (detail = "interactive_auth"). Once per mount and hop. */
  void (*on_warning)(void *ctx, sd_mount *m, const char *code, uint32_t hop, const char *detail);
  /* UpdateHostKeys (5.6): update_host_keys = yes was applied already (applied = 1, result in err);
     ask: the host keeps it for review (hostkeys.announced); no: not called. */
  void (*on_hostkeys_announced)(void *ctx, sd_mount *m, const sd_mount_announcement *a, int applied, sd_err err);
  /* M5, optional, control thread. A successful change through a global mount (03 10.3, Event 1200): sid is the
     requestor's SID (valid during the callback only), op the vfs operation ("create", "write_open", "delete",
     "rename", "setattr", "set_security"), path the mount-relative path. Coalesced per (SID, op, path) by the vfs.
     NULL = not reported (per-user mounts never raise it). */
  void (*on_audit)(void *ctx, sd_mount *m, PSID sid, const char *op, const wchar_t *path);
} sd_mount_callbacks;

sd_err sd_mount_create(const sd_mount_backend *be, const sd_mount_params *params, const sd_mount_callbacks *cb,
                       sd_mount **out);
sd_err sd_mount_start(sd_mount *m);
/* Starts the unmount (or cancels a connect); completion: on_state(UNMOUNTED) (or FAILED). */
sd_err sd_mount_stop(sd_mount *m);
/* Only after on_state reported UNMOUNTED or FAILED, or before sd_mount_start. */
void   sd_mount_destroy(sd_mount *m);

sd_mount_state sd_mount_get_state(const sd_mount *m);
wchar_t        sd_mount_letter(const sd_mount *m);
void           sd_mount_get_failure(const sd_mount *m, sd_mount_failure *out);
int            sd_mount_is_final(const sd_mount *m);    /* UNMOUNTED or FAILED and fully torn down */
/* Resolved backend once the mount started its backend (MOUNTED and later); the requested one before. */
sd_mount_backend_kind sd_mount_backend_kind_used(const sd_mount *m);

/* M1: connection sub-state (any thread). */
typedef struct sd_mount_conn {
  sd_sftp_state session;                /* last session state seen */
  sd_err reason;                        /* why the last loss / failed attempt happened */
  uint32_t attempt;                     /* RECONNECT_WAIT: attempt that follows (1-based) */
  uint32_t retry_in_ms;                 /* RECONNECT_WAIT: backoff of that attempt */
  uint32_t generation;                  /* session generation (0 before the first READY) */
  uint32_t reconnects;                  /* READYs after the first */
  UINT64 offline_since_ms;              /* sd_tick_ms() of the loss; 0 when connected */
  uint32_t write_failed;                /* WRITE_FAILED events of this mount */
  wchar_t last_write_failed[260];       /* display path of the last one */
  /* M2 */
  uint32_t pool;                        /* pool members READY (incl. the primary); 0 before the first POOL event */
  uint32_t pool_wanted;                 /* params.connections */
  uint32_t failed_hop;                  /* hop of the last failure (0-based) */
} sd_mount_conn;
const char *sd_mount_session_state_name(sd_sftp_state st);   /* "ready", "reconnect_wait", ... */
void sd_mount_get_conn(const sd_mount *m, sd_mount_conn *out);

typedef enum sd_mount_answer_kind {
  SD_MA_RESPONSES,                      /* password / passphrase / kbd-int / password change responses */
  SD_MA_HOSTKEY_TRUST,                  /* accept and store; for legacy_ack: continue */
  SD_MA_HOSTKEY_ONCE,                   /* accept for this connection */
  SD_MA_REJECT                          /* reject the key or cancel the prompt */
} sd_mount_answer_kind;
/* Any thread. SD_E_NOT_FOUND when the prompt was answered, withdrawn or never existed. */
sd_err sd_mount_answer(sd_mount *m, uint32_t prompt_id, sd_mount_answer_kind kind, uint32_t n,
                       const char *const *utf8_responses);
/* M2: answer flags. SAVE keeps the secret (cb.secret_put) once the connection is READY; ignored for
   prompts that are not savable (can_save = 0). */
enum { SD_MOUNT_ANSWER_SAVE = 1u << 0 };
sd_err sd_mount_answer_ex(sd_mount *m, uint32_t prompt_id, sd_mount_answer_kind kind, uint32_t n,
                          const char *const *utf8_responses, uint32_t flags);
/* Cancels every open prompt (e.g. the requesting client went away). Any thread. */
uint32_t sd_mount_cancel_prompts(sd_mount *m);   /* returns how many were open */

/* M3. sd_mount_stop_ex(force): the unmount does not wait for the write-behind drain; queued data left at
   that moment is reported as write_failed (02 §4.4). Control thread, like sd_mount_stop. */
sd_err sd_mount_stop_ex(sd_mount *m, int force);
/* refresh: invalidates the attribute and directory caches under subtree (NULL = all). SD_E_UNSUPPORTED
   when the mount has no vfs yet. Called with the host's lock that guards sd_mount_destroy. */
sd_err sd_mount_refresh(sd_mount *m, const wchar_t *subtree);
/* cache.clear: drops this mount's memory blocks and, when disk_too, its disk tier. SD_E_BUSY while
   write-behind data is queued, unless force (the queued data is not dropped either way). */
sd_err sd_mount_cache_clear(sd_mount *m, int disk_too, int force);
/* Stats and attach info: callable while the mount object exists (same lock rule as refresh). */
void   sd_mount_get_stats(const sd_mount *m, sd_mount_stats *out);
void   sd_mount_get_attach(const sd_mount *m, sd_mount_attach *out);
/* profile.test: 1 and the probe when the test_only mount reached READY and completed; 0 otherwise. */
int    sd_mount_get_probe(const sd_mount *m, sd_mount_probe *out);

#endif /* SD_MOUNT_H */
