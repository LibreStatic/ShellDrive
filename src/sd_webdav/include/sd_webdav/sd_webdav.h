/* sd_webdav: local WebDAV server over sd_vfs for the Windows WebDAV redirector (02 §7).
 *
 * One loopback HTTP/1.1 server per process (127.0.0.1 and [::1] on the same random port, both with
 * SO_EXCLUSIVEADDRUSE). Each export (one per mount) is a path prefix /s-<token>/ with a 130-bit
 * random token (26 lowercase base32 chars). Every request except OPTIONS needs Negotiate/NTLM via
 * SSPI on its TCP connection, and the authenticated user SID must equal the server owner SID.
 * Browser-origin requests (Origin, Sec-Fetch-*) get 403 before anything else; wrong Host gets 400;
 * unknown prefixes get 404 before the authentication challenge.
 *
 * Every Win32 function that is not on the XP floor list (SSPI, iphlpapi, WNetOpenEnum, ETW) is
 * resolved at run time; secur32/iphlpapi are never imported.
 *
 * Threading:
 * - sd_webdav_server_* / sd_webdav_export_* / sd_webdav_map* / sd_webdav_mount_*: host control thread
 *   (any single thread). The server runs an accept thread and one thread per connection.
 * - sd_webdav_export_remove waits for in-flight requests of that export (they hold the sd_vfs).
 * - sd_webdav_query_client and sd_webdav_ensure_client: any thread.
 * Ownership: an export borrows its sd_vfs, which must outlive sd_webdav_export_remove. Config strings
 * and SIDs are copied. */
#ifndef SD_WEBDAV_H
#define SD_WEBDAV_H

#include <windows.h>

#include "sd/base.h"
#include "sd_base/sd_err.h"
#include "sd_vfs/sd_vfs.h"

/* ---- WebClient service (02 §7.2) ---- */

typedef enum sd_webdav_client_state {
  SD_WD_CLIENT_UNKNOWN = 0,   /* the SCM could not be queried */
  SD_WD_CLIENT_RUNNING,
  SD_WD_CLIENT_STOPPED,       /* installed, start type manual/automatic/trigger, not running */
  SD_WD_CLIENT_DISABLED,      /* start type disabled: needs an administrator (diag --fix webclient) */
  SD_WD_CLIENT_MISSING        /* service not installed (Server: WebDAV-Redirector / Desktop Experience) */
} sd_webdav_client_state;

typedef struct sd_webdav_client_info {
  sd_webdav_client_state state;
  DWORD start_type;            /* SERVICE_*_START, 0xFFFFFFFF if unknown */
  BOOL  trigger_start;         /* Windows 7+: started by the WebClient ETW trigger */
  DWORD pid;                   /* service process when running */
  DWORD error;                 /* last Win32 error of a failed step */
  BOOL  started_by_us;         /* ensure_client: we started it (StartService or trigger) */
  BOOL  needs_admin;           /* ensure_client: could not start it without elevation */
} sd_webdav_client_info;

/* Read-only SCM query: never starts the service and never writes the trigger event (TM-R21). */
sd_webdav_client_state sd_webdav_query_client(sd_webdav_client_info *out);

/* Starts WebClient for a mount that resolved to WebDAV: StartService, else (7+) the trigger event,
   then waits up to timeout_ms (0 = 10 s). SD_OK when running; SD_E_UNSUPPORTED when missing or
   disabled (info->state says which); SD_E_ACCESS_DENIED when it needs an administrator;
   SD_E_TIMEOUT when it did not come up. */
sd_err sd_webdav_ensure_client(uint32_t timeout_ms, sd_webdav_client_info *out);

/* ---- server ---- */

typedef struct sd_webdav_server sd_webdav_server;
typedef struct sd_webdav_export sd_webdav_export;

typedef struct sd_webdav_server_cfg {
  uint32_t struct_size;        /* sizeof(sd_webdav_server_cfg) */
  PSID     owner_sid;          /* allowed caller; NULL = the process user */
  uint16_t port;               /* 0 = ephemeral (normal); tests may force one */
  BOOL     no_ipv6;            /* do not listen on [::1] */
  /* limits; 0 = the 02 §7.3 defaults */
  uint32_t header_timeout_ms;  /* 10000: complete request head before authentication */
  uint32_t auth_timeout_ms;    /* 30000: complete authentication */
  uint32_t idle_timeout_ms;    /* 120000: authenticated keep-alive idle */
  uint32_t max_unauth;         /* 8 */
  uint32_t max_unauth_per_process;  /* 4 */
  uint32_t max_connections;    /* 64 */
} sd_webdav_server_cfg;

sd_err   sd_webdav_server_start(const sd_webdav_server_cfg *cfg, sd_webdav_server **out);
void     sd_webdav_server_stop(sd_webdav_server *s);      /* closes every connection, joins threads */
uint16_t sd_webdav_server_port(const sd_webdav_server *s);

typedef struct sd_webdav_export_cfg {
  uint32_t struct_size;        /* sizeof(sd_webdav_export_cfg) */
  BOOL read_only;              /* write methods omitted from Allow, refused with 403 */
  const wchar_t *label;        /* drive label (_LabelFromReg); NULL = none */
  BOOL token_only;             /* TM-R19: the path token is the only authenticator (no SSPI, caller = owner) */
} sd_webdav_export_cfg;

sd_err sd_webdav_export_add(sd_webdav_server *s, sd_vfs *vfs, const sd_webdav_export_cfg *cfg,
                            sd_webdav_export **out);
void   sd_webdav_export_remove(sd_webdav_export *e);
/* "/s-<token>" (no trailing slash). */
const char *sd_webdav_export_prefix(const sd_webdav_export *e);
/* Vista+ UNC: \\localhost@PORT\DavWWWRoot\s-<token>. XP: http://localhost:PORT/s-<token>. */
sd_err sd_webdav_export_remote_name(const sd_webdav_export *e, BOOL xp_form, wchar_t *out, size_t cap);

/* ---- drive mapping in the caller's logon session (not persistent, 02 §7.3) ---- */

/* Maps letter (L'A'..L'Z') to the export and writes _LabelFromReg. *win32_error gets the WNet error. */
sd_err sd_webdav_map(const sd_webdav_export *e, wchar_t letter, DWORD *win32_error);
/* Cancels the mapping (forced) and removes the MountPoints2 entry. */
sd_err sd_webdav_unmap(const sd_webdav_export *e, wchar_t letter);
/* TM-R17 (d)/(c): cancels every \\localhost@<port>\DavWWWRoot\s-<26 base32> connection (and the XP http
   form) of this logon session whose port differs from keep_port (0 = cancel all), plus the matching
   MountPoints2 entries. only_port != 0 restricts it to that port (watchers). */
sd_err sd_webdav_cleanup_mappings(uint16_t keep_port, uint16_t only_port, uint32_t *removed);
/* Crash filter (TM-R17 b): cancels the mappings made by this process. Safe to call in an exception
   filter (no allocation, no locks beyond a try-lock). */
void   sd_webdav_emergency_unmap(void);

/* ---- one-call mount used by sd_mount (process-wide server, started on first use) ---- */

typedef struct sd_webdav_mount sd_webdav_mount;

typedef struct sd_webdav_mount_cfg {
  uint32_t struct_size;        /* sizeof(sd_webdav_mount_cfg) */
  wchar_t letter;              /* drive letter */
  BOOL read_only;
  const wchar_t *label;
  PSID owner_sid;              /* NULL = process user; must match across mounts of the process */
  BOOL global;                 /* a service (global) mount: token-only is always refused */
  BOOL token_only;             /* request token-only mode (TM-R19); the host asked the user first */
  BOOL token_only_confirmed;   /* the user confirmed this enable in the host dialog (03 7.5) */
} sd_webdav_mount_cfg;

/* Starts the process server if needed (cleaning stale mappings first), adds the export, maps the
   letter. SD_E_EXISTS when the letter is taken. */
sd_err sd_webdav_mount_start(sd_vfs *vfs, const sd_webdav_mount_cfg *cfg, sd_webdav_mount **out);
/* Unmaps, removes the export, stops the server with the last mount. Frees m. */
sd_err sd_webdav_mount_stop(sd_webdav_mount *m);
uint16_t sd_webdav_mount_port(const sd_webdav_mount *m);

/* ---- token-only mode (TM-R19, 02 §7.4) ----
   Used when the redirector cannot authenticate. Never switched on by sd_webdav itself: the host asks the
   user each time it is enabled and passes token_only_confirmed. */

typedef enum sd_webdav_tok_verdict {
  SD_WD_TOK_OK = 0,
  SD_WD_TOK_FORBIDDEN_GLOBAL,      /* global (service) mounts never use token-only */
  SD_WD_TOK_FORBIDDEN_POLICY,      /* AllowWebDavTokenOnly = 0 (or a value other than 1) */
  SD_WD_TOK_NOT_CONFIRMED,         /* the user has not confirmed this enable */
  SD_WD_TOK_RDSH,                  /* Remote Desktop Session Host, a server product, or a remote session */
  SD_WD_TOK_SESSIONS               /* more than one active session, or the count is unknown */
} sd_webdav_tok_verdict;

typedef struct sd_webdav_tok_input {
  int policy;                      /* AllowWebDavTokenOnly: -1 when absent (default 1), else the value read */
  BOOL global;
  BOOL confirmed;
  BOOL rdsh;                       /* filled by sd_webdav_token_only_environment */
  DWORD active_sessions;           /* filled by sd_webdav_token_only_environment; 0xFFFFFFFF = unknown */
} sd_webdav_tok_input;

/* Pure decision (TM-R19): checks global, policy, confirmation, RDSH, then sessions. */
sd_webdav_tok_verdict sd_webdav_token_only_decide(const sd_webdav_tok_input *in);
/* Fills rdsh and active_sessions from the machine (read-only: registry, GetSystemMetrics, WTS enumeration).
   Anything it cannot establish is reported as the refusing value. */
void sd_webdav_token_only_environment(sd_webdav_tok_input *io);
const char *sd_webdav_tok_verdict_name(sd_webdav_tok_verdict v);

/* WinHTTP self-test (02 §7.4): on loopback with automatic logon disabled for the request, PROPFIND of
   prefix ("/s-<token>") must answer 2xx and PROPFIND of "/" (no token) must answer 4xx. Returns SD_OK;
   SD_E_AUTH_FAILED when the server does not behave that way; SD_E_UNSUPPORTED when WinHTTP is missing;
   SD_E_FAILURE when the request could not be made. */
sd_err sd_webdav_token_selftest(uint16_t port, const char *prefix);

#endif /* SD_WEBDAV_H */
