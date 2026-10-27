/* Private state of an sd_ssh connection chain: one sd_ssh_conn per hop (M2, jump_chain.c). Shared by
 * conn.c, kex.c, auth.c, channel.c, prompt.c, jump_chain.c and proxy_conn.c. Everything in sd_ssh_conn
 * is touched only by the chain's I/O thread (the root's), except the command queue (qlock) and the
 * worker counter (Interlocked), which only the root uses. */
#ifndef SD_SSH_CONN_INTERNAL_H
#define SD_SSH_CONN_INTERNAL_H

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include "sd_platform/sd_log.h"
#include "sd_platform/sd_secbuf.h"
#include "sd_platform/sd_thread.h"
#include "sd_ssh/sd_keyfile.h"
#include "sd_ssh/sd_ssh.h"
#include "ssh_internal.h"
#include "proxy_internal.h"

#define SSH_MAX_CHANNELS   64u
#define SSH_CH_WINDOW      (2u * 1024u * 1024u)
#define SSH_CH_MAXPKT      32768u
#define SSH_OUT_BUDGET     (1024u * 1024u)    /* queued-but-unsent bytes we accept channel data for */
#define SSH_MAX_ADDRS      16u
#define SSH_KA_RING        8u

/* ---- command queue ---- */

typedef struct ssh_cmd ssh_cmd;
struct ssh_cmd {
  ssh_cmd *next;
  void (*run)(sd_ssh_conn *c, ssh_cmd *cmd);   /* I/O thread; frees cmd */
  void (*drop)(ssh_cmd *cmd);                  /* queue closed; frees cmd (no callbacks) */
  sd_ssh_conn *conn;                           /* set by ssh_post_cmd: the hop run() receives */
};

/* Posts a command; SD_E_SHUTDOWN once the I/O thread has exited (cmd is then NOT consumed).
   M2: c may be any hop of a chain; the command goes to the chain's queue (c->root) and run()
   receives c. */
sd_err ssh_post_cmd(sd_ssh_conn *c, ssh_cmd *cmd);

/* Worker items (QueueUserWorkItem). work() runs on the worker; then cmd is posted back. */
typedef struct ssh_work ssh_work;
struct ssh_work {
  ssh_cmd cmd;
  sd_ssh_conn *c;
  uint32_t gen;               /* connect generation; stale results are ignored */
  void (*work)(ssh_work *w);
};
sd_err ssh_queue_work(sd_ssh_conn *c, ssh_work *w);

/* ---- prompts (prompt.c) ---- */

typedef enum ssh_prompt_purpose {
  SSH_PP_HOSTKEY, SSH_PP_PASSWORD, SSH_PP_KBDINT, SSH_PP_PASSPHRASE, SSH_PP_LEGACY,
  SSH_PP_PROXY                /* M2: SD_PROMPT_PROXY_PASSWORD (proxy_conn.c) */
} ssh_prompt_purpose;

typedef struct ssh_prompt_answer {
  int cancelled;
  sd_hostkey_decision decision;
  int ack;
  uint32_t flags;
  uint32_t n;
  sd_secbuf *resp[16];
} ssh_prompt_answer;

/* Creates a prompt bound to c; strings are copied. Raises on_prompt (I/O thread). */
sd_prompt *ssh_prompt_new(sd_ssh_conn *c, ssh_prompt_purpose purpose, sd_prompt_kind kind);
const char *ssh_prompt_str(sd_prompt *p, const char *s);           /* copy owned by the prompt */
sd_auth_prompt_info *ssh_prompt_auth_info(sd_prompt *p);
sd_hostkey_prompt_info *ssh_prompt_hk_info(sd_prompt *p);
sd_prompt_item *ssh_prompt_items(sd_prompt *p, uint32_t n);        /* storage for n items (n <= 16) */
void ssh_prompt_raise(sd_ssh_conn *c, sd_prompt *p);
/* Withdraws (connection ending) or finishes the current prompt and drops sd_ssh's reference. */
void ssh_prompt_withdraw(sd_ssh_conn *c, sd_prompt *p);
void ssh_prompt_finish(sd_prompt *p);
ssh_prompt_purpose ssh_prompt_purpose_of(const sd_prompt *p);
ssh_prompt_answer *ssh_prompt_take_answer(sd_prompt *p);
/* Called by the answer command on the I/O thread (conn.c dispatches to kex/auth). */
void ssh_on_prompt_answered(sd_ssh_conn *c, sd_prompt *p);

/* ---- reconnect secret cache (seccache.c; 01 §7.4, TM-R05) ---- */

typedef struct ssh_secret { uint8_t *blob; size_t cap, len; } ssh_secret;   /* encrypted in memory */
typedef struct ssh_seccache {
  ssh_secret password;
  ssh_secret *pass; uint32_t npass;   /* key-file passphrase per identity index */
} ssh_seccache;

int    ssh_secret_cache_available(void);       /* CryptProtectMemory / RtlEncryptMemory present */
sd_err ssh_secret_store(ssh_secret *s, const uint8_t *p, size_t n);
sd_err ssh_secret_load(const ssh_secret *s, sd_secbuf **out);   /* plain copy for one use */
void   ssh_secret_clear(ssh_secret *s);
void   ssh_seccache_init(ssh_seccache *sc, uint32_t identities);
void   ssh_seccache_clear(ssh_seccache *sc);
void   ssh_seccache_free(ssh_seccache *sc);

/* ---- identities ---- */

typedef struct ssh_ident {
  sd_ssh_identity_kind kind;
  wchar_t *path;              /* SD_ID_FILE */
  char *path_utf8;            /* for prompts */
  sd_secbuf *blob;            /* SD_ID_BLOB */
  char *label;
  char agent_fp[64];          /* SD_ID_AGENT_KEY: "SHA256:..." */
  wchar_t *cert_path;         /* explicit certificate file (else <path>-cert.pub for SD_ID_FILE) */
  uint8_t *cert_blob; size_t cert_len;   /* explicit certificate file bytes (SD_ID_BLOB) */
} ssh_ident;

/* Auth configuration of one hop (auth_cfg.c): validation, deep copy into c, release. */
sd_err ssh_auth_cfg_check(const sd_ssh_auth_cfg *a);
sd_err ssh_auth_cfg_copy(sd_ssh_conn *c, const sd_ssh_auth_cfg *a);
void   ssh_auth_cfg_free(sd_ssh_conn *c);

/* ---- channels (channel.c) ---- */

typedef enum ssh_ch_state {
  SSH_CH_PENDING, SSH_CH_OPENING, SSH_CH_REQUEST, SSH_CH_OPEN, SSH_CH_CLOSING, SSH_CH_DEAD
} ssh_ch_state;

struct sd_ssh_channel {
  sd_ssh_conn *c;
  sd_ssh_channel_sink sink;
  void *ctx;
  int is_exec;
  int is_tcpip;               /* M2: direct-tcpip (arg = host, tcpip_port) for ProxyJump hops */
  uint16_t tcpip_port;
  char *arg;                  /* subsystem name or command */
  ssh_ch_state state;
  uint32_t local_id, remote_id;
  int have_remote;
  int opened;                 /* on_open(SD_OK) delivered */
  int close_sent, close_recv, eof_recv, close_wanted, refused;
  uint32_t local_window, consumed_unacked;
  uint32_t remote_window, remote_max_packet;
  int want_writable;
  uint64_t deadline;
  uint32_t stderr_logged;
  uint32_t serial;            /* identifies the channel in commands posted from other threads */
};

/* M2: direct-tcpip channel (01 §4.8) to host:port, originator 127.0.0.1:0. I/O thread only; on_open
   follows the same rules as the public opens (may run before this returns; *out is then NULL). */
sd_err ssh_channel_open_tcpip(sd_ssh_conn *c, const char *host, uint16_t port, const sd_ssh_channel_sink *s,
                              void *ctx, sd_ssh_channel **out);
void ssh_channel_on_msg(sd_ssh_conn *c, const uint8_t *p, size_t n);
void ssh_channels_fail_all(sd_ssh_conn *c, sd_err why);
void ssh_channels_timers(sd_ssh_conn *c, uint64_t now, uint64_t *next);
void ssh_channels_writable(sd_ssh_conn *c);

/* ---- KEX state (kex.c) ---- */

typedef struct ssh_kex_state {
  int active, initial;
  int we_sent_kexinit, got_server_kexinit, sent_init, reply_done, hostkey_ok;
  int newkeys_sent, newkeys_recv;
  int fallback_lists, ignore_next_kex_packet, hk_check_started;
  uint8_t *i_c; size_t i_c_len;
  uint8_t *i_s; size_t i_s_len;
  ssh_kexinit server;
  ssh_algs algs;
  struct ssh_kexm *km;        /* method state (kex_methods.c) */
  uint32_t gex_bits;          /* GEX: bits of the server's group */
  int fetch;                  /* re-key of sd_ssh_conn_fetch_hostkeys: another host key is expected */
  uint8_t key_c2s[64], key_s2c[64], iv_c2s[32], iv_s2c[32], mac_c2s[64], mac_s2c[64];
} ssh_kex_state;

void ssh_kex_reset(sd_ssh_conn *c);
void ssh_kex_on_ident(sd_ssh_conn *c);                 /* server identification received */
void ssh_kex_try_send_initial(sd_ssh_conn *c);         /* stored types / wait timer progressed */
void ssh_kex_on_msg(sd_ssh_conn *c, const uint8_t *p, size_t n);
void ssh_kex_start_rekey(sd_ssh_conn *c);
void ssh_kex_on_hostkey_answer(sd_ssh_conn *c, ssh_prompt_answer *a);
void ssh_kex_on_legacy_answer(sd_ssh_conn *c, ssh_prompt_answer *a);

/* ---- auth state (auth.c) ---- */

typedef enum ssh_auth_step {
  SSH_AU_NONE, SSH_AU_PK_PREP, SSH_AU_PK_QUERY, SSH_AU_PK_LOAD, SSH_AU_PK_SIGNING, SSH_AU_PK_SIGN,
  SSH_AU_PASSWORD, SSH_AU_PWCHANGE, SSH_AU_KBDINT, SSH_AU_PROMPT
} ssh_auth_step;

/* One publickey candidate (01 §6.2): a key or certificate to offer, and how to sign for it. */
enum { SSH_CS_KEY = 1, SSH_CS_AGENT = 2 };
typedef struct ssh_cand {
  uint8_t src;                /* SSH_CS_KEY: identity key file/blob; SSH_CS_AGENT: an agent signs */
  uint8_t is_cert;
  uint8_t pub_unknown;        /* encrypted PEM without public part: decrypt before the query */
  uint32_t ident;             /* identity index, or UINT32_MAX for extra agent keys */
  uint32_t agent;             /* SD_AGENT_* for SSH_CS_AGENT */
  uint8_t *blob; size_t blob_len;            /* offered key or certificate blob */
  uint8_t *sign_blob; size_t sign_blob_len;  /* SSH_CS_AGENT: blob the agent signs with */
  char key_type[64];          /* plain key type ("ssh-rsa", ...; agents may report unknown types) */
  char fp[64];                /* fingerprint of the plain key (logs, passphrase prompts) */
  uint32_t bits;
} ssh_cand;

typedef struct ssh_auth {
  ssh_auth_step step;
  char methods[512];
  /* publickey */
  int prep_done;
  ssh_cand *cand; uint32_t ncand, cand_next, pk_attempts;
  uint32_t nid;
  sd_secbuf **idfile;         /* per identity: key file bytes */
  sd_ssh_key **idkey;         /* per identity: decrypted key (kept for cert + plain candidates) */
  uint8_t *idenc;             /* per identity: encrypted */
  char alg[64];               /* algorithm of the current attempt */
  const char *rsa_algs[3]; uint32_t rsa_nalg, rsa_idx;   /* RSA signature algorithm sequence */
  uint32_t pass_tries;
  /* password / keyboard-interactive */
  uint32_t password_rounds, kbd_rounds, kbd_info_rounds, kbd_empty_rounds, pwchange_rounds;
  int partial_pk, partial_pw, partial_kbd;
  char pwchange_prompt[1024];
  /* reconnect cache (01 §7.4) */
  int pw_cache_tried, pw_from_cache, pp_cache_tried, pp_from_cache;
  sd_secbuf *pw_pending, *pp_pending;   /* user answers, stored in the cache once they worked */
} ssh_auth;

void ssh_auth_start(sd_ssh_conn *c);
void ssh_auth_on_msg(sd_ssh_conn *c, const uint8_t *p, size_t n);
void ssh_auth_on_answer(sd_ssh_conn *c, ssh_prompt_purpose purpose, ssh_prompt_answer *a);
void ssh_auth_clear(sd_ssh_conn *c);

/* ---- connection ---- */

/* M2 states: SYSPROXY (system proxy resolution on a worker), TUNNEL (hop i >= 1: direct-tcpip
   channel opening on hop i-1), PROXY (proxy handshake running over the socket or the tunnel). */
typedef enum ssh_conn_state {
  SSH_ST_IDLE, SSH_ST_SYSPROXY, SSH_ST_RESOLVING, SSH_ST_CONNECTING, SSH_ST_TUNNEL, SSH_ST_PROXY,
  SSH_ST_VERSION, SSH_ST_KEX, SSH_ST_LEGACY_ACK, SSH_ST_SERVICE, SSH_ST_AUTH, SSH_ST_CONNECTED,
  SSH_ST_CLOSING, SSH_ST_CLOSED
} ssh_conn_state;

typedef struct ssh_pending { struct ssh_pending *next; size_t n; uint8_t p[1]; } ssh_pending;

typedef struct ssh_attempt { SOCKET s; WSAEVENT ev; uint64_t started; } ssh_attempt;

/* ---- ProxyJump chain and proxies (jump_chain.c, proxy_conn.c; 01 §3.3, §5) ----
 * A chain is one sd_ssh_conn per hop. The public object is the target hop (hops[n-1]); it owns the
 * I/O thread, the command queue and the worker counter (root). Hop 0 runs over a TCP socket, hop
 * i >= 1 over a direct-tcpip channel on hop i-1 (ssh_tunnel). Either may carry a proxy handshake
 * first (ssh_px). Every hop has its own transport, KEX, host key check, auth and secret cache. */

typedef struct ssh_tunnel {           /* sink context of the direct-tcpip channel of hop i >= 1 */
  sd_ssh_conn *c;                     /* NULL once the hop let go of it */
  sd_ssh_channel *ch;
  int open;
} ssh_tunnel;

typedef struct ssh_pxcfg {            /* deep copy of sd_proxy_cfg */
  sd_proxy_kind kind;
  wchar_t *host_w; char *host8; uint16_t port;
  uint32_t auth;
  int allow_discovered_sspi, allow_system, remote_dns, fallback_direct;
  char *user;
} ssh_pxcfg;

typedef struct ssh_pxrun {            /* per connect attempt */
  sd_proxy_kind kind;                 /* effective (after system proxy resolution) */
  wchar_t host_w[256]; char host8[256]; uint16_t port;
  int sspi_allowed;                   /* TM-R10 verdict of ssh_sysproxy_decide for the resolved proxy */
  ssh_px px;
  int px_active;
  int pw_from_cache, pw_cache_tried;
  sd_secbuf *pw_pending;              /* user answer, cached once the tunnel is up */
  void *sspi;                         /* ssh_sspi */
  uint32_t reopens;
} ssh_pxrun;

struct sd_ssh_conn {
  /* configuration (deep copies) */
  wchar_t *host_w;
  char *host_utf8;            /* sanitized for prompts */
  uint16_t port;
  char lookup_name[320];
  char *user;
  ssh_ident *ids; uint32_t id_count;
  uint32_t agents;            /* SD_AGENT_* (auth_cfg.c) */
  int identities_only;        /* D37 */
  uint32_t methods;
  int pool_member;
  sd_legacy_policy legacy_policy;
  int refuse_terrapin;
  char *disabled;
  sd_known_hosts *kh;
  uint32_t connect_timeout_ms, ka_interval_ms, ka_max_missed, rekey_seconds;
  uint64_t rekey_bytes;
  int af;
  sd_ssh_callbacks cb;

  /* thread and queue */
  sd_thread thread;
  HANDLE cmd_ev;
  sd_mutex qlock;
  ssh_cmd *qhead, *qtail;
  int stopping, queue_closed;
  volatile LONG workers;
  HANDLE workers_idle;

  /* lifecycle */
  ssh_conn_state st;
  uint32_t gen;
  sd_ssh_done_cb connect_done; void *connect_ctx;
  sd_ssh_done_cb disc_done; void *disc_ctx;
  sd_err fail_err;            /* != SD_OK: finalize at the next safe point */
  int failing;
  uint64_t connect_deadline, close_deadline;

  /* sockets */
  struct sockaddr_storage addrs[SSH_MAX_ADDRS];
  int addr_len[SSH_MAX_ADDRS];
  uint32_t naddr, next_addr;
  ssh_attempt att[2];
  int last_connect_error;
  SOCKET s;
  WSAEVENT ev;
  uint8_t *in; size_t in_len, in_cap;
  sd_wr out; size_t out_off;
  int out_was_full;

  /* transport */
  char ident_s[256];          /* V_S */
  char server_version[256];   /* sanitized software version */
  uint32_t prebanner_lines; size_t prebanner_bytes;
  ssh_dir tx, rx;
  ssh_kex_state kex;
  ssh_lists fixed_lists;      /* lists of the initial KEX, reused for rekeys */
  uint8_t session_id[64]; size_t session_id_len;
  uint8_t hostkey[SSH_HOSTKEY_BUF]; size_t hostkey_len;
  char hostkey_fp[64];
  int strict;
  uint32_t legacy_mask;
  uint32_t rx_packets_before_kexinit;
  uint64_t kexinit_wait_deadline;
  int stored_types_done;
  sd_kh_types stored_types;
  uint64_t last_kex_tick;
  ssh_pending *pend_head, *pend_tail; size_t pend_bytes;
  char server_sig_algs[512];

  /* auth */
  ssh_auth auth;
  int hostkey_just_accepted, interactive_used;
  uint32_t methods_used;

  /* prompts */
  sd_prompt *cur_prompt;

  /* reconnect (01 §8): survives across connects of this object */
  int ever_connected;         /* a connect reached CONNECTED; later connects are reconnects */
  int is_reconnect;           /* the current connect is a reconnect (prompts carry is_reconnect) */
  uint8_t pinned_hostkey[SSH_HOSTKEY_BUF]; size_t pinned_len;   /* key verified by the last successful connect */
  int pinned_unstored;        /* the pinned key was accepted once (not in any store) */
  int hk_once;                /* this connect accepted the host key with ACCEPT_ONCE */
  int cache_secrets;          /* cache_secrets_for_reconnect */
  ssh_seccache cache;

  /* keepalive, probe, RTT */
  uint64_t last_rx_tick, next_ka_tick, probe_deadline;
  int probe_pending;
  uint64_t ka_ring[SSH_KA_RING]; uint32_t ka_head, ka_count;
  uint32_t srtt, rttvar; int have_rtt;

  /* channels */
  sd_ssh_channel *ch[SSH_MAX_CHANNELS];

  /* M2: chain (jump_chain.c) */
  sd_ssh_conn *root;          /* queue/thread owner (the target hop); == this for the public object */
  sd_ssh_conn **hops;         /* root only: hops[0..nhops-1], hops[nhops-1] == root */
  uint32_t nhops;
  uint32_t hop_index;
  sd_ssh_conn *outer;         /* hop i >= 1: hop i-1 */
  char *via_host;             /* hop i >= 1: sanitized host of hop i-1 (TM-R03); borrowed */
  char *host_ascii;           /* host as sent to proxies / direct-tcpip (brackets removed) */
  ssh_tunnel *tun;            /* hop i >= 1: the direct-tcpip channel carrying this hop */
  sd_ssh_callbacks user_cb;   /* root only: the caller's callbacks; every hop's cb are adapters */
  sd_ssh_done_cb chain_done; void *chain_ctx;           /* root: public connect */
  sd_ssh_done_cb chain_disc_done; void *chain_disc_ctx; /* root: public disconnect */
  int chain_service;          /* the process runs as LocalSystem (system proxy source) */

  /* M2: proxy (proxy_conn.c) */
  ssh_pxcfg pxcfg;
  ssh_pxrun pxr;
  ssh_secret px_secret;       /* cached proxy password (01 §7.4) */
  int in_reset;               /* the lower transport was reopened inside process_input */

  /* M2: transport (kex.c, hostkey_update.c) */
  sd_hku_mode hku_mode;       /* update_host_keys of this hop (01 §7.5) */
  struct ssh_hku *hku;        /* UpdateHostKeys / fetch_hostkeys state; ssh_hku_free() */
  sd_hk_result hk_res;        /* known_hosts verdict for this connect's host key */
  int hk_res_valid;
};

/* ---- M2 transport hooks (hostkey_update.c; 01 §7.5, §4.3) ---- */
/* Server global request; returns 1 if handled (the caller then does nothing else). */
int  ssh_hku_on_global_request(sd_ssh_conn *c, sd_span name, int want_reply, const uint8_t *p, size_t n);
/* REQUEST_SUCCESS / REQUEST_FAILURE / UNIMPLEMENTED for a global request; returns 1 if it answered
   one of ours (hostkeys-prove-00), 0 if it belongs to the keepalive accounting. */
int  ssh_hku_on_reply(sd_ssh_conn *c, const uint8_t *p, size_t n);
void ssh_hku_reset(sd_ssh_conn *c);         /* new connect: forget announcements and requests */
void ssh_hku_free(sd_ssh_conn *c);          /* connection destroyed; withdraws pending fetches */
/* Comma list of the legacy names for SD_PROMPT_LEGACY_ACK (kex.c). */
void ssh_kex_legacy_names(const sd_ssh_conn *c, char *out, size_t cap);

/* ---- per-hop setup (conn.c) ---- */
sd_err ssh_hop_init(sd_ssh_conn *c, const sd_ssh_config *cfg, const sd_ssh_hop *h, uint32_t hop_index);
void   ssh_hop_release(sd_ssh_conn *c);
unsigned __stdcall ssh_io_main(void *arg);      /* the chain's I/O thread (arg = root) */

/* ---- chain helpers (jump_chain.c) ---- */
sd_err ssh_chain_create(const sd_ssh_config *cfg, const sd_ssh_callbacks *cb, sd_ssh_conn **out);
void   ssh_chain_destroy(sd_ssh_conn *root);
void   ssh_chain_connect(sd_ssh_conn *root, sd_ssh_done_cb done, void *ctx);      /* I/O thread */
void   ssh_chain_disconnect(sd_ssh_conn *root, sd_ssh_done_cb done, void *ctx);   /* I/O thread */
/* Per hop (conn.c): start a connect attempt of this hop / disconnect it; done runs once. */
void   ssh_hop_connect(sd_ssh_conn *c, sd_ssh_done_cb done, void *ctx);
void   ssh_hop_disconnect(sd_ssh_conn *c, sd_ssh_done_cb done, void *ctx);
/* Transport below SSH is up (TCP connected or tunnel open): proxy handshake or identification. */
void   ssh_transport_up(sd_ssh_conn *c);
/* Bytes from the lower transport of a tunnelled hop. */
void   ssh_ingest(sd_ssh_conn *c, const uint8_t *p, size_t n);
void   ssh_flush(sd_ssh_conn *c);
void   ssh_tunnel_open(sd_ssh_conn *c);         /* hop i >= 1: SSH_ST_TUNNEL */
void   ssh_tunnel_release(sd_ssh_conn *c);      /* closes the tunnel channel, detaches */
void   ssh_start_dns(sd_ssh_conn *c);           /* hop 0: DNS of the proxy or the host */
void   ssh_close_lower(sd_ssh_conn *c);         /* socket or tunnel (for proxy reopen) */
void   ssh_reconnect_lower(sd_ssh_conn *c);     /* proxy reopen: close and connect the lower transport again */
void   ssh_proxy_tunnel_ready(sd_ssh_conn *c);  /* proxy handshake done: send the identification */

/* ---- proxy glue (proxy_conn.c) ---- */
sd_err ssh_pxcfg_copy(ssh_pxcfg *d, const sd_proxy_cfg *s, uint32_t hop_index);
void   ssh_pxcfg_free(ssh_pxcfg *d);
void   ssh_proxy_reset(sd_ssh_conn *c);          /* start of a connect attempt */
void   ssh_proxy_begin(sd_ssh_conn *c);          /* SYSPROXY step, then DNS / tunnel */
int    ssh_proxy_active(const sd_ssh_conn *c);   /* this attempt runs a proxy handshake */
void   ssh_proxy_start(sd_ssh_conn *c);          /* transport up: send the first proxy bytes */
size_t ssh_proxy_input(sd_ssh_conn *c, const uint8_t *p, size_t n);   /* bytes used; may switch to VERSION */
void   ssh_proxy_on_answer(sd_ssh_conn *c, ssh_prompt_answer *a);
void   ssh_proxy_done_cleanup(sd_ssh_conn *c);   /* wipes per-attempt proxy state */
/* Host and port the lower transport connects to (proxy or hop). */
const wchar_t *ssh_lower_host_w(const sd_ssh_conn *c);
const char    *ssh_lower_host8(const sd_ssh_conn *c);
uint16_t       ssh_lower_port(const sd_ssh_conn *c);

/* conn.c helpers used by the protocol units */
extern const char ssh_ident_c[];        /* V_C, without CR LF */
void ssh_log(sd_ssh_conn *c, sd_log_level level, _Printf_format_string_ const char *fmt, ...);
sd_err ssh_send(sd_ssh_conn *c, const uint8_t *payload, size_t n);   /* seals or defers during KEX */
sd_err ssh_send_wr(sd_ssh_conn *c, sd_wr *w);                         /* sends w (checks w->err) */
void ssh_fail(sd_ssh_conn *c, sd_err e, uint32_t reason, const char *why);
size_t ssh_out_pending(const sd_ssh_conn *c);
void ssh_flush_pending(sd_ssh_conn *c);                               /* after NEWKEYS */
void ssh_after_initial_kex(sd_ssh_conn *c);
void ssh_on_authenticated(sd_ssh_conn *c);
void ssh_send_keepalive(sd_ssh_conn *c);
int  ssh_cache_usable(const sd_ssh_conn *c);   /* cache on and no fresh host-key acceptance (TM-R05) */
uint64_t ssh_now(void);
void ssh_sanitize(const uint8_t *p, size_t n, char *out, size_t cap);

#endif /* SD_SSH_CONN_INTERNAL_H */
