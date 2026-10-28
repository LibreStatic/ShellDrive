/* sd_webdav private: server, connection, export, lock and SSPI internals (02 §7.3-§7.5). */
#ifndef SD_WD_SERVER_H
#define SD_WD_SERVER_H

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include "sd/base.h"
#include "sd_base/sd_err.h"
#include "sd_platform/sd_thread.h"
#include "sd_vfs/sd_vfs.h"
#include "sd_webdav/sd_webdav.h"
#include "wd_proto.h"

#define WD_LOG "webdav"
#define WD_IBUF (64u * 1024u)
#define WD_IO_CHUNK (256u * 1024u)
#define WD_MAX_IF_TOKENS 8u

/* ---- locks (in memory, per export) ---- */
typedef struct wd_lock {
  struct wd_lock *next;
  char token[64];                 /* "opaquelocktoken:<uuid>" */
  WCHAR *path;                    /* vfs path */
  int exclusive, depth_inf;
  uint32_t timeout_s;
  uint64_t expires;               /* sd_tick_ms */
  char *owner;                    /* owner href/text (unescaped UTF-8) or NULL */
} wd_lock;

struct sd_webdav_export {
  struct sd_webdav_export *next;
  sd_webdav_server *srv;
  sd_vfs *vfs;
  char token[WD_TOKEN_CHARS + 1];
  char prefix[WD_TOKEN_CHARS + 4];   /* "/s-<token>" */
  BOOL read_only;
  BOOL token_only;                /* TM-R19: the path token authenticates, no SSPI (02 §7.4) */
  WCHAR *label;
  volatile LONG busy;
  int removing;
  sd_mutex lock_mu;
  wd_lock *locks;
  wchar_t mapped;                 /* drive letter mapped by sd_webdav_map, 0 = none */
};

struct sd_webdav_server {
  SOCKET ls[2]; int nls;
  uint16_t port;
  PSID owner;
  uint32_t header_ms, auth_ms, idle_ms, max_unauth, max_unauth_pp, max_conn;
  sd_thread accept_thr;
  volatile LONG stop;
  sd_mutex mu;                    /* conns, exports, counters */
  struct wd_conn *conns;
  uint32_t nconn, nunauth;
  volatile LONG live;             /* running connection threads */
  sd_event idle_ev;               /* set when live drops to 0 */
  sd_webdav_export *exports;
  DWORD webclient_pid; uint64_t webclient_pid_at;
};

/* ---- SSPI (wd_auth.c), XP-safe: secur32!InitSecurityInterfaceW resolved at run time ---- */
enum { WD_AUTH_FAIL = -1, WD_AUTH_CONTINUE = 0, WD_AUTH_OK = 1 };
typedef struct wd_auth { void *ctx; int have; } wd_auth;   /* ctx: CtxtHandle (opaque here) */
int  wd_auth_available(void);
/* value = "Negotiate <b64>" or "NTLM <b64>". On CONTINUE/OK with a token, out = "<scheme> <b64>"
   (NUL-terminated, empty when no token). On OK *user is the token user SID (sd_alloc). */
int  wd_auth_step(wd_auth *a, const char *value, size_t n, char *out, size_t cap, PSID *user);
void wd_auth_reset(wd_auth *a);

/* ---- connection ---- */
typedef struct wd_conn {
  struct wd_conn *next, *prev;
  sd_webdav_server *srv;
  SOCKET s;
  DWORD peer_pid;
  int exempt;                     /* WebClient service process */
  uint64_t accepted_at, last_at;
  int authed, unauth_counted;
  int tok;                        /* a token-only export answered here: pre-auth limits end, but authed stays 0,
                                     so every other export still requires SSPI (02 §7.4) */
  volatile LONG evict;
  wd_auth auth;
  PSID user;
  char auth_reply[1024];          /* final mutual-auth token for the next response, rarely used */
  char *ib; size_t ilen, ipos;
} wd_conn;

/* request in flight */
typedef struct wd_rq {
  wd_conn *c;
  wd_req r;
  wd_path path;
  sd_webdav_export *ex;           /* NULL for "/" */
  WCHAR *vpath;                   /* vfs path of the target */
  sd_vfs_caller caller;
  char host[64]; size_t host_n;
  /* body */
  uint64_t body_left; wd_chunked ch; int body_done, continue_sent, body_error;
  int close_after;
  int sent;                       /* a response was sent */
  int status;                     /* final status sent (logged with the method, never the path) */
} wd_rq;

/* wd_server.c: I/O used by the method handlers */
int  wd_send_all(wd_conn *c, const void *p, size_t n);
/* Sends status + headers (extra: CRLF-terminated lines or NULL) + body. ctype may be NULL. */
void wd_respond(wd_rq *q, int status, const char *extra, const char *ctype, const void *body, size_t n);
/* Sends status + headers only, announcing content_length; the caller streams the body. */
int  wd_respond_head(wd_rq *q, int status, const char *extra, const char *ctype, uint64_t content_length);
/* Next body slice (valid until the next call). 0 = ok (*n == 0 at end), -1 = framing/IO error. */
int  wd_body_next(wd_rq *q, const char **p, size_t *n);
int  wd_has_body(const wd_rq *q);
/* Reads the whole body up to max bytes into b. 0 ok, 413 too large, 400 framing error. */
int  wd_body_read_all(wd_rq *q, wd_sb *b, size_t max);

/* wd_tokenonly.c: 1 when the self-test pair passes (token PROPFIND 2xx, token-less PROPFIND 4xx). */
int  wd_selftest_verdict(int token_status, int plain_status);

/* wd_methods.c */
void wd_dispatch(wd_rq *q);
int  wd_status_from_vfs(sd_vfs_status st);
void wd_options(wd_rq *q);

/* wd_lock.c */
void wd_locks_free(sd_webdav_export *ex);
/* 1 when path (and, with_children, anything below it) is locked by a lock none of whose tokens was
   submitted. */
int  wd_lock_conflict(sd_webdav_export *ex, const WCHAR *path, int with_children, char toks[][80], uint32_t ntok);
/* Creates a lock; returns 0, or 423 on conflict, 500 on OOM. *out receives a copy of the token. */
int  wd_lock_create(sd_webdav_export *ex, const WCHAR *path, int exclusive, int depth_inf, uint32_t timeout_s,
                    const char *owner, char token_out[64]);
/* Refreshes the lock among toks that covers path; 0 ok (token_out set), 412 none. */
int  wd_lock_refresh(sd_webdav_export *ex, const WCHAR *path, char toks[][80], uint32_t ntok, uint32_t timeout_s,
                     char token_out[64]);
int  wd_lock_remove(sd_webdav_export *ex, const WCHAR *path, const char *token);   /* 0 / 409 */
void wd_lock_move(sd_webdav_export *ex, const WCHAR *from, const WCHAR *to);
void wd_lock_drop_tree(sd_webdav_export *ex, const WCHAR *path);
/* Replacing MOVE: the lock on to survives, locks below to go, locks on from move to to (02 §7.5). */
void wd_lock_replace(sd_webdav_export *ex, const WCHAR *from, const WCHAR *to);
/* Locks strictly below path (a replacing COPY deleted that tree). */
void wd_lock_drop_below(sd_webdav_export *ex, const WCHAR *path);
/* Appends <D:lockdiscovery>...</D:lockdiscovery> for locks covering path. */
void wd_lock_discovery(sd_webdav_export *ex, const WCHAR *path, wd_sb *b, const char *only_token);

#endif /* SD_WD_SERVER_H */
