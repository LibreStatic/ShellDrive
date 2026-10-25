/* sd_ssh public API: connection chains, transport, authentication, channels (01 §9).
 *
 * M0 scope (00 §6, 01 §13): one hop, direct TCP, curve25519-sha256 KEX, strict KEX, ext-info,
 * ssh-ed25519 host keys, chacha20-poly1305 / AES-GCM / AES-CTR+HMAC-SHA2(-ETM), password and Ed25519
 * key-file auth, known_hosts TOFU (user store). Fields for later milestones (ProxyJump, proxies,
 * agents, legacy algorithms, pools) are part of the contract now; unsupported settings fail with
 * SD_E_UNSUPPORTED instead of being ignored.
 *
 * Threading (01 §3.1, §10.8; review §4.1):
 * - Each connection chain has ONE I/O thread. Every callback (prompts, events, channel sinks, done
 *   callbacks) runs on it, serialized, and must return quickly: no blocking, no waiting on locks held
 *   by threads that wait for this connection.
 * - Lifecycle calls are non-blocking and may be made from any thread; completion is reported via
 *   callback. sd_ssh_conn_destroy must not be called on the connection's own I/O thread.
 * - Channel write/consumed calls are I/O-thread only; use sd_ssh_conn_post() to hop there.
 * Ownership: sd_ssh_conn_create deep-copies the config (strings, identities, blobs into secret
 * buffers). Pointers handed to callbacks are valid only during the callback. */
#ifndef SD_SSH_H
#define SD_SSH_H

#include "sd/base.h"
#include "sd_base/sd_err.h"
#include "sd_ssh/sd_known_hosts.h"
#include "sd_ssh/sd_prompt.h"

typedef struct sd_ssh_conn sd_ssh_conn;       /* a chain: hops + final connection */
typedef struct sd_ssh_channel sd_ssh_channel;

/* ---- configuration ---- */

enum { SD_AUTH_PUBLICKEY = 1u << 0, SD_AUTH_KBDINT = 1u << 1, SD_AUTH_PASSWORD = 1u << 2 };
enum { SD_AGENT_PAGEANT = 1u << 0, SD_AGENT_OPENSSH = 1u << 1 };

typedef enum sd_ssh_identity_kind { SD_ID_FILE, SD_ID_AGENT_KEY, SD_ID_BLOB } sd_ssh_identity_kind;
typedef struct sd_ssh_identity {
  sd_ssh_identity_kind kind;
  const wchar_t *path;                  /* SD_ID_FILE */
  const char *agent_fingerprint;        /* SD_ID_AGENT_KEY, "SHA256:..." */
  const uint8_t *blob; size_t blob_len; /* SD_ID_BLOB: key file bytes, deep-copied into a secret buffer */
  const char *label;                    /* SD_ID_BLOB: shown in passphrase prompts instead of a path */
} sd_ssh_identity;

typedef struct sd_ssh_auth_cfg {
  const char *user;                     /* UTF-8 */
  const sd_ssh_identity *identities; uint32_t identity_count;
  uint32_t methods;                     /* SD_AUTH_* */
  uint32_t agents;                      /* SD_AGENT_*; must be 0 in the service context (D17) */
  int identities_only;                  /* D37 */
  int cache_secrets_for_reconnect;
} sd_ssh_auth_cfg;

typedef enum sd_proxy_kind { SD_PROXY_NONE, SD_PROXY_HTTP, SD_PROXY_SOCKS5, SD_PROXY_SYSTEM } sd_proxy_kind;
enum { SD_PROXY_AUTH_BASIC = 1u << 0, SD_PROXY_AUTH_SSPI = 1u << 1, SD_PROXY_AUTH_USERPASS = 1u << 2,
       SD_PROXY_AUTH_SSPI_KERBEROS = 1u << 3 };
typedef struct sd_proxy_cfg {           /* M2 (D20); kind must be SD_PROXY_NONE in M0 */
  sd_proxy_kind kind;
  const wchar_t *host; uint16_t port;
  uint32_t auth;
  int allow_discovered_sspi;
  const char *user;
  int remote_dns;
  int fallback_direct;
} sd_proxy_cfg;

typedef enum sd_legacy_policy { SD_LEGACY_ALLOW, SD_LEGACY_WARN, SD_LEGACY_ASK, SD_LEGACY_REFUSE } sd_legacy_policy;
typedef enum sd_hku_mode { SD_HKU_YES, SD_HKU_ASK, SD_HKU_NO } sd_hku_mode;

typedef struct sd_ssh_hop {
  const wchar_t *host; uint16_t port;   /* host as typed; 0 port = 22 */
  const char *host_key_alias;           /* optional */
  sd_ssh_auth_cfg auth;
  sd_proxy_cfg proxy;
  sd_hku_mode update_host_keys;         /* default SD_HKU_ASK */
} sd_ssh_hop;

typedef struct sd_ssh_algo_cfg {
  sd_legacy_policy legacy_policy;       /* default SD_LEGACY_WARN */
  int refuse_terrapin_exposed;          /* TM-R01 */
  const char *disabled;                 /* comma list of algorithm names to remove; may be NULL */
  int crypto_backend;                   /* 0 auto, 1 own */
} sd_ssh_algo_cfg;

enum { SD_SSH_CFG_POOL_MEMBER = 1u << 0 };

typedef struct sd_ssh_config {
  uint32_t struct_size;                 /* sizeof(sd_ssh_config) */
  const sd_ssh_hop *hops; uint32_t hop_count;   /* 1..8, last = target; M0: exactly 1 */
  sd_ssh_algo_cfg algos;
  sd_known_hosts *known_hosts;          /* borrowed; must outlive the connection */
  uint32_t connect_timeout_ms;          /* 15000 if 0 */
  uint32_t keepalive_interval_ms;       /* 15000 if 0 */
  uint32_t keepalive_max_missed;        /* 3 if 0 */
  uint64_t rekey_bytes;                 /* 1 GiB if 0 */
  uint32_t rekey_seconds;               /* 3600 if 0 */
  int address_family;                   /* 0 = AF_UNSPEC, else AF_INET / AF_INET6 */
  uint32_t flags;                       /* SD_SSH_CFG_* */
} sd_ssh_config;

typedef struct sd_ssh_negotiated {
  uint32_t hop_index;
  const char *kex, *hostkey, *cipher_c2s, *cipher_s2c, *mac_c2s, *mac_s2c, *comp_c2s, *comp_s2c;
  const char *server_version;           /* e.g. "OpenSSH_9.9p1 Debian-3" (sanitized) */
  const char *hostkey_fp_sha256;
  int strict_kex;
  uint32_t legacy_mask;
} sd_ssh_negotiated;

typedef enum sd_hkev_kind { SD_HKEV_MISMATCH, SD_HKEV_REVOKED, SD_HKEV_ANNOUNCED } sd_hkev_kind;
typedef struct sd_hostkey_event {
  sd_hkev_kind kind; uint32_t hop_index; const char *lookup_name;
  sd_kh_store_kind store; const wchar_t *path; uint32_t line;
  const sd_hk_key *old_key, *new_key;                 /* MISMATCH */
  const sd_hk_key *add; uint32_t add_count;           /* ANNOUNCED: proven keys */
  const sd_hk_key *remove; uint32_t remove_count;     /* ANNOUNCED: removal candidates */
} sd_hostkey_event;

typedef struct sd_ssh_callbacks {
  void *ctx;
  /* exactly one of auth / hk is non-NULL, matching the prompt kind */
  void (*on_prompt)(void *ctx, sd_prompt *p, const sd_auth_prompt_info *auth,
                    const sd_hostkey_prompt_info *hk);
  void (*on_prompt_withdrawn)(void *ctx, sd_prompt *p);
  void (*on_banner)(void *ctx, uint32_t hop, const char *utf8);
  void (*on_negotiated)(void *ctx, const sd_ssh_negotiated *n);
  void (*on_hostkey_event)(void *ctx, const sd_hostkey_event *e);
  void (*on_log)(void *ctx, int level, const char *msg);   /* optional adapter; sd_log is always used */
} sd_ssh_callbacks;

/* ---- lifecycle ---- */

typedef void (*sd_ssh_done_cb)(void *ctx, sd_err err, uint32_t failed_hop);
sd_err sd_ssh_global_init(void);                  /* WSAStartup etc.; idempotent, thread-safe */
sd_err sd_ssh_conn_create(const sd_ssh_config *cfg, const sd_ssh_callbacks *cb, sd_ssh_conn **out);
sd_err sd_ssh_conn_connect(sd_ssh_conn *c, sd_ssh_done_cb done, void *ctx);
sd_err sd_ssh_conn_disconnect(sd_ssh_conn *c, sd_ssh_done_cb done, void *ctx);
void   sd_ssh_conn_destroy(sd_ssh_conn *c);       /* waits for the I/O thread; never call on it */
int    sd_ssh_conn_is_io_thread(const sd_ssh_conn *c);

typedef struct sd_ssh_auth_info { int noninteractive; uint32_t methods_used; } sd_ssh_auth_info;
sd_err sd_ssh_conn_auth_info(const sd_ssh_conn *c, sd_ssh_auth_info *out);

/* Liveness probe and RTT (01 §4.6); I/O thread only. */
void   sd_ssh_conn_probe(sd_ssh_conn *c);
void   sd_ssh_conn_rtt(const sd_ssh_conn *c, uint32_t *srtt_ms, uint32_t *rttvar_ms);

/* TM-R04 explicit "add a key of another type" (M2). */
typedef void (*sd_ssh_hostkeys_cb)(void *ctx, sd_err e, const sd_hk_key *keys, uint32_t count);
sd_err sd_ssh_conn_fetch_hostkeys(sd_ssh_conn *c, uint32_t hop_index, const char *const *types,
                                  uint32_t ntypes, sd_ssh_hostkeys_cb done, void *ctx);

/* Runs fn(arg) on the chain's I/O thread (used by sd_sftp to hop from caller threads). */
sd_err sd_ssh_conn_post(sd_ssh_conn *c, void (*fn)(void *), void *arg);

/* ---- channels (consumer callbacks run on the I/O thread) ---- */

typedef struct sd_ssh_channel_sink {
  void (*on_open)(void *ctx, sd_err err);
  void (*on_data)(void *ctx, const uint8_t *p, size_t n);   /* call sd_ssh_channel_consumed() later */
  void (*on_writable)(void *ctx);
  void (*on_eof)(void *ctx);
  void (*on_closed)(void *ctx, sd_err why);
} sd_ssh_channel_sink;
sd_err sd_ssh_channel_open_subsystem(sd_ssh_conn *c, const char *name, const sd_ssh_channel_sink *s,
                                     void *ctx, sd_ssh_channel **out);
/* identity_probe = exec only (D10): fixed command strings chosen by sd_sftp, never user input. */
sd_err sd_ssh_channel_open_exec(sd_ssh_conn *c, const char *command, const sd_ssh_channel_sink *s,
                                void *ctx, sd_ssh_channel **out);
sd_err sd_ssh_channel_write(sd_ssh_channel *ch, const uint8_t *p, size_t n, size_t *accepted);
void   sd_ssh_channel_consumed(sd_ssh_channel *ch, size_t n);
size_t sd_ssh_channel_send_space(const sd_ssh_channel *ch);
void   sd_ssh_channel_close(sd_ssh_channel *ch);

#endif /* SD_SSH_H */
