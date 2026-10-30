/* Network proxy clients (01 §5.2, D20): HTTP CONNECT (proxy_http.c), SOCKS5 (proxy_socks5.c), SSPI
 * Negotiate/NTLM tokens (proxy_sspi.c), system proxy resolution (proxy_system.c). The codecs are pure
 * state machines over byte buffers, so the unit tests drive them with scripted replies; the glue
 * that runs them on a hop (sockets, tunnels, prompts, workers, reopen) is proxy_conn.c.
 *
 * Usage: ssh_px_init(), ssh_px_start() (first bytes into out), then ssh_px_input() with every byte
 * received from the proxy until it returns PX_DONE (the tunnel is up; *used bytes belonged to the
 * proxy, the rest is the SSH stream) or PX_FAIL (px->err). PX_NEED_PASSWORD / PX_NEED_SSPI ask the
 * caller for a secret or a token (ssh_px_set_password / ssh_px_set_token, then ssh_px_resume());
 * PX_REOPEN asks for a fresh connection to the proxy, then ssh_px_resume() on it.
 * Single owner; no locking. */
#ifndef SD_SSH_PROXY_INTERNAL_H
#define SD_SSH_PROXY_INTERNAL_H

#include "sd/base.h"
#include "sd_base/sd_buf.h"
#include "sd_base/sd_err.h"
#include "sd_platform/sd_secbuf.h"
#include "sd_ssh/sd_ssh.h"

#define SSH_PX_HDR_MAX    16384u   /* HTTP response head (status line + headers), 01 §5.2 */
#define SSH_PX_HDR_LINES  100u
#define SSH_PX_ROUNDS     3u       /* authentication rounds */
#define SSH_PX_TOKEN_MAX  12288u   /* SSPI token, raw bytes */

typedef enum ssh_px_status { PX_MORE, PX_DONE, PX_NEED_PASSWORD, PX_NEED_SSPI, PX_REOPEN, PX_FAIL } ssh_px_status;

enum { PX_SCHEME_NONE = 0, PX_SCHEME_BASIC = 1, PX_SCHEME_NEGOTIATE = 2, PX_SCHEME_NTLM = 3 };

typedef struct ssh_px {
  /* configuration (ssh_px_init) */
  sd_proxy_kind kind;               /* SD_PROXY_HTTP or SD_PROXY_SOCKS5 */
  char target[256];                 /* ASCII host of the hop (IPv6 literal without brackets) */
  uint16_t target_port;
  uint8_t target_addr[16]; int target_atyp;   /* SOCKS5 ATYP 1/4 when the address is known, else 3 */
  char proxy_host[256];             /* for the SSPI target name HTTP/<proxy host> and logs */
  uint16_t proxy_port;
  uint32_t auth;                    /* SD_PROXY_AUTH_* allowed */
  int sspi_allowed;                 /* TM-R10: configured origin, or policy AllowSystemProxySspi */
  char user[256];                   /* "" = none */
  const char *user_agent;           /* "ShellDrive/<ver>" */
  /* state */
  int step;
  sd_err err;
  uint32_t rounds;                  /* authentication rounds started */
  int scheme;                       /* PX_SCHEME_* of the last request */
  int kerberos_only;                /* Negotiate restricted to Kerberos (SD_PROXY_AUTH_SSPI_KERBEROS) */
  sd_secbuf *password;              /* Basic / RFC 1929, set by the caller */
  int password_failed;              /* the last password was rejected */
  uint8_t *token; size_t token_len; /* SSPI output token to send */
  uint8_t *challenge; size_t challenge_len;   /* SSPI input token from the proxy (decoded) */
  int sspi_started;
  /* HTTP response reader */
  uint8_t hdr[SSH_PX_HDR_MAX]; size_t hlen;
  uint64_t body_left;               /* 407 body to skip before the next request */
  int must_reopen;
  uint32_t status;                  /* last HTTP status / SOCKS reply code */
  /* SOCKS5 */
  uint8_t sbuf[512]; size_t slen;
  size_t sneed;
  int pending;                      /* action waiting for resume (internal) */
  char why[160];                    /* English detail for the log (sanitized) */
} ssh_px;

/* host: the hop host as typed (ASCII; "[v6]" brackets allowed). Returns SD_E_INVALID_PARAM for
   names that cannot be sent (too long, control characters). */
sd_err ssh_px_init(ssh_px *px, sd_proxy_kind kind, const char *host, uint16_t port, const char *proxy_host,
                   uint16_t proxy_port, uint32_t auth, int sspi_allowed, const char *user, int remote_dns);
void   ssh_px_free(ssh_px *px);                      /* wipes secrets */
void   ssh_px_start(ssh_px *px, sd_wr *out);
ssh_px_status ssh_px_input(ssh_px *px, const uint8_t *p, size_t n, size_t *used, sd_wr *out);
ssh_px_status ssh_px_resume(ssh_px *px, sd_wr *out); /* after NEED_* was satisfied, or on a reopened connection */
void   ssh_px_set_password(ssh_px *px, sd_secbuf *pw);   /* takes ownership */
sd_err ssh_px_set_token(ssh_px *px, const uint8_t *tok, size_t n);

/* SOCKS5 with remote_dns = 0: the locally resolved target address (atyp 1 = 4 bytes, 4 = 16). */
void   ssh_px_set_target_addr(ssh_px *px, int atyp, const uint8_t *addr);
/* 1 when the SOCKS5 target is a name that remote_dns = 0 wants resolved locally first. */
int    ssh_px_wants_local_dns(const ssh_px *px);
/* Parses "a.b.c.d" (4 bytes) or an IPv6 literal (16 bytes, optional %zone ignored). 0 on failure. */
int    ssh_px_parse_ipv4(const char *s, uint8_t out[4]);
int    ssh_px_parse_ipv6(const char *s, uint8_t out[16]);

/* internal dispatch targets */
void   ssh_px_socks5_start(ssh_px *px, sd_wr *out);
ssh_px_status ssh_px_socks5_input(ssh_px *px, const uint8_t *p, size_t n, size_t *used, sd_wr *out);
ssh_px_status ssh_px_socks5_resume(ssh_px *px, sd_wr *out);
const char *ssh_socks5_reply_name(uint8_t code);

/* ---- SSPI (proxy_sspi.c; secur32.dll resolved at run time) ---- */

typedef struct ssh_sspi ssh_sspi;
/* package: L"Negotiate" or L"NTLM"; kerberos_only restricts Negotiate with PackageList "!ntlm".
   target: SPN "HTTP/<proxy host>". Runs on a worker thread. */
sd_err ssh_sspi_create(const wchar_t *package, int kerberos_only, const wchar_t *target, ssh_sspi **out);
/* One InitializeSecurityContextW round. in may be NULL for the first. *out is sd_alloc'ed. */
sd_err ssh_sspi_step(ssh_sspi *s, const uint8_t *in, size_t in_len, uint8_t **out, size_t *out_len);
void   ssh_sspi_free(ssh_sspi *s);

/* ---- system proxy (proxy_system.c; winhttp.dll resolved at run time) ---- */

typedef struct ssh_sysproxy {
  sd_proxy_kind kind;               /* SD_PROXY_NONE = connect directly */
  wchar_t host[256]; uint16_t port;
  int discovered;                   /* WPAD / PAC result: SD_PROXY_ORIGIN_DISCOVERED (TM-R10) */
} ssh_sysproxy;
/* Resolves the proxy for host:port. service: use the WinHTTP default configuration (netsh winhttp)
   instead of the user's IE settings. SD_E_PROXY when discovery failed. Blocking: worker only. */
sd_err ssh_sysproxy_resolve(const wchar_t *host, uint16_t port, int service, ssh_sysproxy *out);
/* Pure helpers (unit tests): picks socks= / https= / generic from a WinHTTP proxy list. */
int    ssh_sysproxy_pick(const wchar_t *list, ssh_sysproxy *out);
/* 1 if host matches the bypass list ("<local>", wildcards, ';' or ' ' separated). */
int    ssh_sysproxy_bypassed(const wchar_t *bypass, const wchar_t *host);

/* The opt-in decision (01 §5.2, 03 §3.5/§3.8, TM-R10), factored out of the connect path so the unit
   tests drive it without WinHTTP: the system proxy is used only when the profile opts in AND the
   policy allows it, and SSPI is used towards it only when its origin allows. */
typedef struct ssh_sys_decision {
  sd_proxy_kind kind;               /* SD_PROXY_NONE = connect directly */
  wchar_t host[256]; uint16_t port;
  int discovered;                   /* origin of the proxy (TM-R10) */
  int sspi_allowed;                 /* TM-R10: SSPI towards the proxy */
} ssh_sys_decision;
/* opt_in: the profile asked for proxy = system. policy_system / policy_sspi: machine policy
   AllowSystemProxy / AllowSystemProxySspi. res: the resolution result (kind = SD_PROXY_NONE when
   nothing was found or discovery failed). Returns SD_OK and fills out, or SD_E_PROXY when the
   opt-in is refused by policy AllowSystemProxy. */
sd_err ssh_sysproxy_decide(int opt_in, int policy_system, int policy_sspi,
                           const ssh_sysproxy *res, ssh_sys_decision *out);

#endif /* SD_SSH_PROXY_INTERNAL_H */
