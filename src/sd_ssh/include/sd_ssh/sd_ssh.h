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
  /* M2 user certificates (01 §6.3, profile auth.certificate): an explicit certificate file, or its
     bytes (e.g. next to a DPAPI-kept key). Without either, SD_ID_FILE also tries "<path>-cert.pub".
     A certificate is offered before its plain key; expired, host or non-matching ones are skipped. */
  const wchar_t *cert_path;
  const uint8_t *cert_blob; size_t cert_blob_len;   /* a *-cert.pub file's bytes */
} sd_ssh_identity;
/* Agents and identities (M2, 01 §6.2, §6.5):
 * - SD_ID_AGENT_KEY selects an agent key by the SHA-256 fingerprint of its plain public key (a
 *   certificate the agent holds for that key is offered first). It needs `agents`.
 * - A file or blob identity whose public key an enabled agent holds is signed by the agent (no
 *   passphrase prompt).
 * - Without identities_only, every other agent key follows (Pageant first, then the OpenSSH agent,
 *   deduplicated by blob). At most 6 keys are offered per connection (OpenSSH MaxAuthTries).
 * - `agents` must be 0 in a LocalSystem process (D17): sd_ssh_conn_create fails with SD_E_UNSUPPORTED.
 * - RSA keys sign with rsa-sha2-512 / rsa-sha2-256 as the server's server-sig-algs allow, ssh-rsa
 *   only as a fallback (legacy bit SD_LEGACY_USERAUTH_SHA1); keys < 1024 bits are refused.
 * - Password: SSH_MSG_USERAUTH_PASSWD_CHANGEREQ raises SD_PROMPT_NEW_PASSWORD with three items
 *   (current, new, confirm; instruction = the server's text); a mismatch of new and confirm asks
 *   again. Keyboard-interactive: every INFO_REQUEST is one SD_PROMPT_KBDINT; `round` counts them
 *   within the connection (OTP rounds follow the password round). */

typedef struct sd_ssh_auth_cfg {
  const char *user;                     /* UTF-8 */
  const sd_ssh_identity *identities; uint32_t identity_count;
  uint32_t methods;                     /* SD_AUTH_* */
  uint32_t agents;                      /* SD_AGENT_*; must be 0 in the service context (D17) */
  int identities_only;                  /* D37 */
  int cache_secrets_for_reconnect;      /* M1: password and key passphrases are kept, encrypted in
                                           memory (CryptProtectMemory / RtlEncryptMemory), for later
                                           connects of the same sd_ssh_conn; see "reconnect" below */
} sd_ssh_auth_cfg;

/* Network proxies (M2, D20, 01 §5.2). A proxy says how ONE hop is reached: for hop 0 the TCP
 * connection goes to the proxy, which is asked to connect to the hop; for hop i >= 1 the
 * direct-tcpip channel on hop i-1 goes to the proxy (resolved by hop i-1's server) and the proxy
 * handshake runs over that channel. The SSH host key of the hop is verified as usual on top.
 * - SD_PROXY_HTTP: HTTP/1.1 CONNECT. port 0 = 8080. auth: SD_PROXY_AUTH_BASIC (needs user; the
 *   password comes from an SD_PROMPT_PROXY_PASSWORD prompt), SD_PROXY_AUTH_SSPI (Negotiate with NTLM
 *   fallback, bare NTLM; current logon credentials), SD_PROXY_AUTH_SSPI_KERBEROS (Negotiate restricted
 *   to Kerberos, profile proxy_auth = auto). Basic travels in clear text to the proxy. A 407 is
 *   answered at most 3 times; a proxy that closes between rounds is reconnected.
 * - SD_PROXY_SOCKS5: RFC 1928 CONNECT, port 0 = 1080; no-auth always offered, RFC 1929
 *   username/password too when user is set (SD_PROXY_AUTH_USERPASS or auth = 0). remote_dns = 1
 *   (the profile default; the host passes it) sends the name (ATYP 3); remote_dns = 0 resolves it
 *   locally first (ATYP 1/4). Literal addresses always go as ATYP 1/4.
 * - SD_PROXY_SYSTEM (hop 0 only; host/port ignored): resolved on every connect from WinHTTP
 *   (IE settings of the user; the WinHTTP default configuration when running as LocalSystem),
 *   including WPAD / PAC (WinHttpGetProxyForUrl) and the bypass list. socks= gives SOCKS5, https= or
 *   a generic entry gives HTTP CONNECT. A proxy found by WPAD/PAC has origin DISCOVERED: SSPI is never
 *   used towards it unless allow_discovered_sspi (machine policy AllowSystemProxySspi, TM-R10).
 *   Discovery failure falls back to a direct connection only with fallback_direct. The source itself
 *   is used only when the profile opts in (kind = SD_PROXY_SYSTEM) and allow_system (machine policy
 *   AllowSystemProxy) permits it; otherwise the connect is refused with SD_E_PROXY (03 §3.8, TM-R10).
 * Errors: SD_E_PROXY (refused, unreachable target, protocol error; reply code in the log),
 * SD_E_PROXY_AUTH (no acceptable method, rejected credentials, rounds exhausted), with failed_hop =
 * the hop the proxy leads to. Proxy passwords: prompt SD_PROMPT_PROXY_PASSWORD with proxy_host,
 * proxy_port, user, hop_index (answer from Credential Manager with SD_ANSWER_FROM_STORE where
 * possible; pool members must never show UI). With cache_secrets_for_reconnect of the hop, a proxy
 * password that worked is kept for reconnects like the SSH password (01 §7.4). */
typedef enum sd_proxy_kind { SD_PROXY_NONE, SD_PROXY_HTTP, SD_PROXY_SOCKS5, SD_PROXY_SYSTEM } sd_proxy_kind;
enum { SD_PROXY_AUTH_BASIC = 1u << 0, SD_PROXY_AUTH_SSPI = 1u << 1, SD_PROXY_AUTH_USERPASS = 1u << 2,
       SD_PROXY_AUTH_SSPI_KERBEROS = 1u << 3 };
typedef enum sd_proxy_origin {
  SD_PROXY_ORIGIN_CONFIGURED,           /* profile, policy ProxyServer, static system entry */
  SD_PROXY_ORIGIN_DISCOVERED            /* WPAD / PAC result (set by sd_ssh) */
} sd_proxy_origin;
typedef struct sd_proxy_cfg {           /* M2 (D20) */
  sd_proxy_kind kind;
  const wchar_t *host; uint16_t port;   /* HTTP / SOCKS5: the proxy (name or literal, "[v6]" allowed) */
  uint32_t auth;                        /* SD_PROXY_AUTH_* allowed; 0 = none (SOCKS5: userpass if user) */
  int allow_discovered_sspi;            /* TM-R10 policy AllowSystemProxySspi = 1; default 0 */
  int allow_system;                     /* TM-R10 policy AllowSystemProxy = 1 lets proxy = system resolve;
                                           0 (default) refuses the opt-in with SD_E_PROXY */
  const char *user;                     /* UTF-8, <= 255 bytes; NULL/"" = none */
  int remote_dns;                       /* SOCKS5: 1 = the proxy resolves the name */
  int fallback_direct;                  /* SD_PROXY_SYSTEM: connect directly if discovery fails */
} sd_proxy_cfg;

/* M5 (03 3.8, service): the WinHTTP machine configuration (WinHttpGetDefaultProxyConfiguration) for host:port, the
   static answer only (the default configuration has no WPAD and no PAC). *kind is SD_PROXY_NONE (no proxy configured,
   or the bypass list matches), SD_PROXY_HTTP or SD_PROXY_SOCKS5, with the proxy in host_out and *port_out. Returns
   SD_E_PROXY when the configuration cannot be read. Blocking: worker or control thread only. */
sd_err sd_ssh_proxy_machine(const wchar_t *host, uint16_t port, sd_proxy_kind *kind, wchar_t host_out[256],
                            uint16_t *port_out);

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

/* SD_SSH_CFG_COMPRESS: offer zlib@openssh.com (delayed, active after USERAUTH_SUCCESS, 01 section 4.7) before none;
 * off by default. */
enum { SD_SSH_CFG_POOL_MEMBER = 1u << 0, SD_SSH_CFG_COMPRESS = 1u << 1 };

/* ProxyJump (M2, 01 §5.1): hops[0] is reached over TCP (optionally through its proxy), hops[i]
 * (i >= 1) through a direct-tcpip channel on hops[i-1] to (host, port) as configured for hop i,
 * resolved by hop i-1's server. Each hop has its own user, auth, proxy and host-key verification
 * against its own lookup name ([host]:port, or host_key_alias); its host-key prompt carries
 * hop_index and via_host = hop i-1's host (TM-R03), its auth prompts carry hop_index and host.
 * All hops run on the chain's single I/O thread. on_negotiated / on_banner / on_hostkey_event carry
 * the hop index. A failure at hop k reports failed_hop = k; hops before k stay connected while the
 * connect is retried (a later sd_ssh_conn_connect() rebuilds from the first hop that is not
 * connected); sd_ssh_conn_disconnect() closes every hop, innermost first. noninteractive in
 * sd_ssh_auth_info covers every hop. SD_SSH_CFG_POOL_MEMBER applies to every hop. */
typedef struct sd_ssh_config {
  uint32_t struct_size;                 /* sizeof(sd_ssh_config) */
  const sd_ssh_hop *hops; uint32_t hop_count;   /* 1..8, last = target */
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

/* Reconnect (01 §8, M1). After the done callback of a connect reported an error, or after the
 * connection died or was disconnected (every channel got on_closed and, for a disconnect, its done
 * callback ran), sd_ssh_conn_connect() may be called again on the same object. The I/O thread, the
 * config and the following state survive; everything else (keys, channels, KEX/auth state) is new:
 * - the host key verified by the last successful connect is pinned. A reconnect runs the full
 *   known_hosts verification again: MATCH proceeds; MISMATCH / REVOKED / NEW_TYPE fail as usual
 *   (no accept path); NEW proceeds silently only when the key equals the pinned one (it was
 *   accepted once earlier), otherwise the host-key prompt carries is_reconnect = 1;
 * - with cache_secrets_for_reconnect, the password and key-file passphrases that worked are kept
 *   encrypted in memory and answered by sd_ssh itself on reconnect (no prompt, so the login counts
 *   as non-interactive). The cache is neither read nor written on a connection whose host key was
 *   just accepted by a prompt (TM-R05); a cached secret the server rejects is dropped and the
 *   normal prompt follows. Keyboard-interactive answers are never cached;
 * - every prompt raised by a reconnect carries is_reconnect = 1. */
typedef void (*sd_ssh_done_cb)(void *ctx, sd_err err, uint32_t failed_hop);
sd_err sd_ssh_global_init(void);                  /* WSAStartup etc.; idempotent, thread-safe */
sd_err sd_ssh_conn_create(const sd_ssh_config *cfg, const sd_ssh_callbacks *cb, sd_ssh_conn **out);
sd_err sd_ssh_conn_connect(sd_ssh_conn *c, sd_ssh_done_cb done, void *ctx);
sd_err sd_ssh_conn_disconnect(sd_ssh_conn *c, sd_ssh_done_cb done, void *ctx);
void   sd_ssh_conn_destroy(sd_ssh_conn *c);       /* waits for the I/O thread; never call on it */
int    sd_ssh_conn_is_io_thread(const sd_ssh_conn *c);

typedef struct sd_ssh_auth_info {
  int noninteractive; uint32_t methods_used;
  int is_reconnect;                     /* M1: the last connect was a reconnect */
  int hostkey_just_accepted;            /* M1: its host key was accepted by a prompt (TM-R05) */
} sd_ssh_auth_info;
sd_err sd_ssh_conn_auth_info(const sd_ssh_conn *c, sd_ssh_auth_info *out);

/* M1: drops every cached reconnect secret (e.g. after the user changed the password). Any thread. */
sd_err sd_ssh_conn_clear_secrets(sd_ssh_conn *c);

/* M1 keepalive tuning (01 §4.6): changes keepalive_interval_ms / keepalive_max_missed at run time
   (0 keeps a value; interval >= 1000 ms, max_missed <= 100). Applies to the current and later
   connects; any thread. */
sd_err sd_ssh_conn_set_keepalive(sd_ssh_conn *c, uint32_t interval_ms, uint32_t max_missed);

/* Liveness probe and RTT (01 §4.6); I/O thread only. */
void   sd_ssh_conn_probe(sd_ssh_conn *c);
void   sd_ssh_conn_rtt(const sd_ssh_conn *c, uint32_t *srtt_ms, uint32_t *rttvar_ms);

/* TM-R04 explicit "add a key of another type" (M2). */
typedef void (*sd_ssh_hostkeys_cb)(void *ctx, sd_err e, const sd_hk_key *keys, uint32_t count);
sd_err sd_ssh_conn_fetch_hostkeys(sd_ssh_conn *c, uint32_t hop_index, const char *const *types,
                                  uint32_t ntypes, sd_ssh_hostkeys_cb done, void *ctx);

/* Runs fn(arg) on the chain's I/O thread (used by sd_sftp to hop from caller threads). */
sd_err sd_ssh_conn_post(sd_ssh_conn *c, void (*fn)(void *), void *arg);

/* ---- channels (consumer callbacks run on the I/O thread) ----
 * Lifetime: the channel pointer stays valid until on_closed() returns, or until on_open() returns
 * with an error (a failed open never gets on_closed). Every opened channel gets exactly one
 * on_closed(), also when the connection dies (SD_E_DISCONNECTED / SD_E_TIMEOUT / SD_E_SHUTDOWN).
 * Opens may be requested from any thread; called on the I/O thread, on_open(err) can run before
 * the open call returns (and *out is then NULL). Opens time out after connect_timeout_ms. */

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
