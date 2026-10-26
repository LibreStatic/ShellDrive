/* sd_sftp: asynchronous SFTP v3 client, the contract with the filesystem layer (01 §10, reconciled
 * with 02 §9 R1-R19).
 *
 * M0 scope: core operations, pipelining, caller deadlines, error refinement, TM-R12 dirent filtering.
 * M1: meta + bulk SFTP channels with auto-degrade to one (D19), the reconnect loop with generations
 * and stale handles (01 §10.6), sd_sftp_file_reopen, statistics.
 * M2 pool (01 §10.9): connections 1..4 opens secondary members after READY when authentication was
 * non-interactive (prompts on a member are cancelled, never shown); every member must present the
 * same host-key fingerprint and the same realpath(".") as the primary, otherwise admissions stop for
 * the generation. Members carry one bulk channel; EV_POOL events and sd_sftp_session_stats()
 * report them. Striping (SD_SFTP_O_STRIPED routing, barriers, per-member loss semantics) is not
 * implemented yet: the flag is ignored and data flows over the primary.
 *
 * Reconnect contract (M1, 01 §10.4/§10.6; what sd_vfs relies on):
 * - The sd_sftp_session object survives reconnects. generation starts at 1 with the first READY and
 *   increments on every READY. sd_sftp_file objects survive too; on the loss of the connection all
 *   of them become stale (sd_sftp_file_get_info().stale = 1).
 * - Event order on loss: EV_STATE(DISCONNECTED, reason); completions of every request that was in
 *   flight or queued with SD_E_DISCONNECTED (maybe_executed = 1 when it had been sent: for mutating
 *   ops the effect is unknown, re-stat, never retry a rename blindly); every handle is marked stale;
 *   then EV_STATE(RECONNECT_WAIT, retry_in_ms, attempt) per attempt, EV_STATE(CONNECTING), possibly
 *   EV_STATE(AUTH_REQUIRED) while a reconnect prompt is outstanding, and finally EV_STATE(READY)
 *   followed by EV_READY_INFO with the new generation (re-read server_info: limits, extensions,
 *   home and identity may differ; names_by_id results are per generation).
 * - Backoff: attempt n waits min(max_delay, initial_delay * 2^n) +/- 20% jitter; max_attempts 0 =
 *   unlimited. sd_sftp_session_reconnect_now() skips the wait (or restarts the loop from FAILED /
 *   AUTH_REQUIRED), sd_sftp_session_reconnect_stop() cancels it (FAILED, reason SD_E_CANCELLED),
 *   sd_sftp_session_close() always ends it.
 * - The loop stops in FAILED for permanent errors (host key mismatch/revoked/rejected/type
 *   unavailable, legacy refused, KEX failure, unsupported) and when max_attempts is reached; in
 *   AUTH_REQUIRED when the user is needed (auth failed, prompt cancelled). The very first connect
 *   does not loop: its failure is FAILED (reconnect_now() retries it). Reconnect needs a transport
 *   with SD_SFTP_TP_REOPEN (sd_sftp_session_create() always has it); otherwise a loss is FAILED.
 * - Requests with SD_SFTP_REQ_WAIT_READY submitted in IDLE/CONNECTING/DISCONNECTED/RECONNECT_WAIT/
 *   AUTH_REQUIRED (with an attempt running) wait for READY until their timeout_ms (required > 0).
 *   Unsent WAIT_READY path operations queued at the moment of a loss keep waiting as well. Writes
 *   are never replayed by sd_sftp.
 * - Stale handles: every operation fails with SD_E_STALE_HANDLE except close/release (local
 *   success); sd_sftp_file_reopen() re-opens the same object in the current generation.
 *
 * Channels (M1, D19, C17): ch 0 "meta" carries path operations, opendir/readdir, opens with
 * SD_SFTP_REQ_CLASS_META and the handles they create; ch 1 "bulk" carries every other open and the
 * requests on its handle. When opt.channels = 1, the transport has no second stream, or the server
 * refuses another session channel (MaxSessions 1), the session runs on one channel and serves the
 * meta queue first at every turn. server_info.channels tells which (1 or 2), per generation.
 *
 * Threading (01 §10.8):
 * 1. All functions are thread-safe and non-blocking, except *_sync and sd_sftp_session_destroy.
 * 2. Callbacks and events of a session run on its I/O thread, serialized (pool of 1). No callback is
 *    ever invoked from inside a submit call.
 * 3. Inside a callback: submit, cancel, addref/release and session_close are allowed; *_sync,
 *    destroy and anything blocking are not. Callbacks should finish in under 1 ms and never take a
 *    VFS node or cache lock (review §4.1 rule 1). Callers never hold their own locks across a submit.
 * 4. Pointers inside a completion or event are valid only during the callback.
 * 5. *_sync and destroy only from the host control thread or CLI threads (never Dokany callbacks,
 *    WebDAV workers or I/O threads); *_sync returns SD_E_WOULD_DEADLOCK on an I/O thread.
 * Submission: SD_OK means the callback will be called exactly once; any other return means never.
 * Ownership: an open completion hands the caller one sd_sftp_file reference; buffers passed to
 * read/write must stay valid and untouched until their completion. */
#ifndef SD_SFTP_H
#define SD_SFTP_H

#include "sd/base.h"
#include "sd_base/sd_err.h"
#include "sd_ssh/sd_ssh.h"

typedef struct sd_sftp_session sd_sftp_session;
typedef struct sd_sftp_file    sd_sftp_file;    /* file or directory handle; refcounted, survives reconnect */
typedef struct sd_sftp_req     sd_sftp_req;     /* in-flight request token for cancellation */

/* ---- types (01 §10.3) ---- */

enum { SD_SFTP_ATTR_SIZE = 0x1, SD_SFTP_ATTR_UIDGID = 0x2, SD_SFTP_ATTR_PERM = 0x4, SD_SFTP_ATTR_TIMES = 0x8 };
#define SD_SFTP_ATTR_EXTENDED 0x80000000u   /* a macro: as an enum constant it would be a negative int */
typedef struct sd_sftp_extattr { const char *type; uint32_t type_len; const uint8_t *data; uint32_t data_len; }
        sd_sftp_extattr;
typedef struct sd_sftp_attrs {
  uint32_t valid;          /* SD_SFTP_ATTR_* */
  uint64_t size;
  uint32_t uid, gid;
  uint32_t perm;           /* POSIX mode incl. S_IFMT type bits (0170000) */
  int64_t  atime, mtime;   /* Unix seconds; wire is uint32 */
  /* Extended pairs (02 R10): valid only inside the delivering callback; NULL/0 in stored copies. */
  const sd_sftp_extattr *ext; uint32_t ext_count;
} sd_sftp_attrs;
#define SD_SFTP_IS_DIR(a)  (((a)->valid & SD_SFTP_ATTR_PERM) && (((a)->perm & 0170000u) == 0040000u))
#define SD_SFTP_IS_LNK(a)  (((a)->valid & SD_SFTP_ATTR_PERM) && (((a)->perm & 0170000u) == 0120000u))
#define SD_SFTP_IS_REG(a)  (((a)->valid & SD_SFTP_ATTR_PERM) && (((a)->perm & 0170000u) == 0100000u))

typedef struct sd_sftp_dirent {
  const char *name;       uint32_t name_len;      /* raw bytes, NUL-terminated copy; never empty, never
                                                     contains '/' or NUL, never "." or ".." (TM-R12) */
  const char *longname;   uint32_t longname_len;  /* ls -l style; may be "" */
  sd_sftp_attrs attrs;
} sd_sftp_dirent;

typedef struct sd_sftp_statvfs {
  uint64_t bsize, frsize, blocks, bfree, bavail, files, ffree, favail, fsid, flag, namemax;
} sd_sftp_statvfs;       /* flag: 0x1 ST_RDONLY, 0x2 ST_NOSUID */

typedef struct sd_sftp_limits {
  uint64_t max_packet, max_read, max_write, max_open_handles;   /* effective values; never 0 */
} sd_sftp_limits;

enum {
  SD_SFTP_EXT_POSIX_RENAME = 1u << 0, SD_SFTP_EXT_STATVFS = 1u << 1, SD_SFTP_EXT_FSTATVFS = 1u << 2,
  SD_SFTP_EXT_HARDLINK = 1u << 3, SD_SFTP_EXT_FSYNC = 1u << 4, SD_SFTP_EXT_LSETSTAT = 1u << 5,
  SD_SFTP_EXT_LIMITS = 1u << 6, SD_SFTP_EXT_EXPAND_PATH = 1u << 7, SD_SFTP_EXT_COPY_DATA = 1u << 8,
  SD_SFTP_EXT_HOME_DIRECTORY = 1u << 9, SD_SFTP_EXT_USERS_GROUPS_BY_ID = 1u << 10
};
enum { SD_SFTP_QUIRK_SYMLINK_OPENSSH_ORDER = 1u << 0, SD_SFTP_QUIRK_WIN_DRIVE_PATHS = 1u << 1 };

enum { SD_SFTP_ID_HOME_OWNER = 1, SD_SFTP_ID_EXEC = 2 };
typedef struct sd_sftp_identity {
  uint32_t source;              /* 0 = unknown, SD_SFTP_ID_* */
  uint32_t uid, gid;
  const uint32_t *gids; uint32_t gid_count;   /* only with SD_SFTP_ID_EXEC (max 64) */
} sd_sftp_identity;

typedef struct sd_sftp_ext_entry { const char *name; const char *version; } sd_sftp_ext_entry;

typedef struct sd_sftp_server_info {
  uint32_t generation;          /* increments on every successful (re)connect, starts at 1 */
  uint32_t version;             /* 3 */
  uint32_t ext;                 /* SD_SFTP_EXT_* */
  const sd_sftp_ext_entry *ext_list; uint32_t ext_count;   /* every announced extension (02 R12) */
  sd_sftp_limits limits;
  uint32_t channels;            /* SFTP channels on the primary connection (1 or 2) */
  uint32_t connections;         /* pool members READY, incl. the primary */
  uint32_t quirks;              /* SD_SFTP_QUIRK_* */
  const char *home;             /* realpath(".") at connect; raw bytes */
  sd_sftp_identity identity;
  const sd_ssh_negotiated *ssh; /* target hop: server version, host key fingerprint, legacy_mask */
} sd_sftp_server_info;          /* pointers valid until the next state change event */

int sd_sftp_has_ext(const sd_sftp_session *s, uint32_t ext_bit);   /* 0 when not READY */

/* ---- session lifecycle, state and events (01 §10.4) ---- */

typedef enum sd_sftp_state {
  SD_SFTP_ST_IDLE, SD_SFTP_ST_CONNECTING, SD_SFTP_ST_READY,
  SD_SFTP_ST_DISCONNECTED,      /* transient; reconnect pending per policy */
  SD_SFTP_ST_RECONNECT_WAIT,    /* backoff timer running */
  SD_SFTP_ST_AUTH_REQUIRED,     /* reconnect needs user interaction */
  SD_SFTP_ST_FAILED,            /* permanent: host key mismatch/revoked, auth failure, give-up */
  SD_SFTP_ST_CLOSED
} sd_sftp_state;

typedef struct sd_sftp_reconnect_policy {
  int enabled;                  /* default 1 (M1) */
  uint32_t initial_delay_ms;    /* 1000 */
  uint32_t max_delay_ms;        /* 60000; exponential x2 with +/-20% jitter */
  uint32_t max_attempts;        /* 0 = unlimited */
} sd_sftp_reconnect_policy;

enum {
  SD_SFTP_OPT_REFINE_ERRORS        = 1u << 0,   /* default on */
  SD_SFTP_OPT_SYMLINK_ORDER_DRAFT  = 1u << 1,
  SD_SFTP_OPT_SYMLINK_ORDER_OPENSSH = 1u << 2,
  SD_SFTP_OPT_IDENTITY_EXEC        = 1u << 3    /* identity_probe = exec (D10), default off */
};

typedef struct sd_sftp_options {
  uint32_t struct_size;         /* sizeof(sd_sftp_options) */
  uint32_t channels;            /* 2 (meta + bulk, default) or 1 */
  uint32_t connections;         /* pool size 1..4, default 1 */
  uint32_t stripe_bytes;        /* default 1 MiB */
  uint32_t max_inflight_reqs;   /* per channel, default 64 */
  uint32_t max_inflight_bytes;  /* per channel, default 8 MiB */
  uint32_t max_queued_reqs;     /* per session, default 4096; beyond: SD_E_BUSY (02 R5) */
  uint32_t flags;               /* SD_SFTP_OPT_* */
  sd_sftp_reconnect_policy reconnect;
  uint32_t default_timeout_ms;  /* when a request passes none; default 30000 */
} sd_sftp_options;

typedef enum sd_sftp_event_type { SD_SFTP_EV_STATE, SD_SFTP_EV_READY_INFO, SD_SFTP_EV_POOL } sd_sftp_event_type;
typedef struct sd_sftp_event {
  sd_sftp_event_type type;
  sd_sftp_state state; sd_err reason; uint32_t failed_hop;
  uint32_t retry_in_ms;                 /* RECONNECT_WAIT: delay before the next attempt */
  const sd_sftp_server_info *info;      /* READY_INFO */
  uint32_t member, connections;         /* POOL */
  /* M1 */
  uint32_t attempt;                     /* RECONNECT_WAIT: 1-based number of the attempt that follows */
  uint32_t generation;                  /* the session generation (READY / READY_INFO: the new one) */
} sd_sftp_event;
/* State events (M1):
   - DISCONNECTED: reason = why the connection was lost (SD_E_DISCONNECTED, SD_E_TIMEOUT for a
     failed keepalive or liveness probe, SD_E_PROTOCOL, ...).
   - RECONNECT_WAIT: reason = the loss or the failed attempt's error; retry_in_ms; attempt.
   - CONNECTING: an attempt starts (also the first connect).
   - AUTH_REQUIRED: a reconnect raised an auth prompt (reason SD_E_AUTH_REQUIRED; the attempt goes
     on when the prompt is answered), or the loop stopped because the user is needed (reason = the
     error, e.g. SD_E_AUTH_FAILED or SD_E_CANCELLED).
   - READY, then READY_INFO: connected; generation incremented.
   - FAILED: reason = the permanent error. CLOSED after sd_sftp_session_close(). */

typedef struct sd_sftp_conn_stats {
  uint32_t srtt_ms, rttvar_ms;
  uint64_t rx_bps, tx_bps;
  uint64_t rx_total, tx_total;
  uint32_t inflight_reqs, queued_reqs;
  int      ready;
} sd_sftp_conn_stats;
typedef struct sd_sftp_stats {
  sd_sftp_conn_stats total;
  sd_sftp_conn_stats conn[4];           /* [0] = primary */
  uint32_t conn_count;
  /* M1 */
  uint32_t generation;                  /* current generation (0 before the first READY) */
  uint32_t channels;                    /* SFTP channels in use (1 or 2; 0 when not READY) */
  uint32_t reconnect_attempts;          /* attempts of the running reconnect loop (0 when READY) */
} sd_sftp_stats;
/* Statistics (02 R16), any thread, cheap: srtt_ms/rttvar_ms from the transport's keepalive and
   probe samples (sd_ssh, 01 §4.6) or else from meta-channel round trips (RFC 6298 smoothing);
   rx_bps/tx_bps payload rates (EWMA, about 2 s); rx_total/tx_total bytes of this generation;
   inflight_reqs on the wire, queued_reqs submitted but not on the wire. */
sd_err sd_sftp_session_stats(const sd_sftp_session *s, sd_sftp_stats *out);

typedef void (*sd_sftp_event_cb)(void *ctx, const sd_sftp_event *ev);

/* Fills *o with the documented defaults (incl. SD_SFTP_OPT_REFINE_ERRORS and struct_size). Start
   from this and override fields; a NULL opt in session_create means exactly these defaults. */
void sd_sftp_options_init(sd_sftp_options *o);

/* ssh/ssh_cb/opt are deep-copied. */
sd_err sd_sftp_session_create(const sd_ssh_config *ssh, const sd_ssh_callbacks *ssh_cb,
                              const sd_sftp_options *opt, sd_sftp_event_cb ev, void *ev_ctx,
                              sd_sftp_session **out);
sd_err sd_sftp_session_start(sd_sftp_session *s);           /* async; progress via events */
/* Skips the backoff of RECONNECT_WAIT, or restarts the loop from FAILED / AUTH_REQUIRED (for example
   after the user fixed the credentials or removed a stale host key; attempts count from 0 again).
   No effect in READY or while an attempt runs. SD_E_UNSUPPORTED without SD_SFTP_TP_REOPEN,
   SD_E_INVALID_PARAM before start, SD_E_SHUTDOWN after close. Any thread; async. */
sd_err sd_sftp_session_reconnect_now(sd_sftp_session *s);
/* M1: cancels the reconnect loop (a running attempt is aborted): the session goes FAILED with reason
   SD_E_CANCELLED and waiting requests complete with SD_E_DISCONNECTED; reconnect_now() resumes.
   Any thread; async. */
sd_err sd_sftp_session_reconnect_stop(sd_sftp_session *s);
sd_err sd_sftp_session_close(sd_sftp_session *s);           /* async; in-flight -> SD_E_SHUTDOWN, then CLOSED */
void   sd_sftp_session_destroy(sd_sftp_session *s);         /* after CLOSED; never on the I/O thread */
sd_sftp_state sd_sftp_session_state(const sd_sftp_session *s);
uint32_t sd_sftp_session_generation(const sd_sftp_session *s);
sd_err sd_sftp_session_info(sd_sftp_session *s, sd_sftp_server_info *copy_out, char *home_buf, size_t home_len);
int    sd_sftp_session_is_io_thread(const sd_sftp_session *s);

/* ---- requests (01 §10.5) ---- */

typedef struct sd_sftp_completion {
  sd_err   err;
  uint32_t sftp_status;          /* raw status if a STATUS reply was received, else UINT32_MAX */
  const char *server_message;    /* UTF-8 (sanitized), may be "" */
  int      maybe_executed;       /* DISCONNECTED/TIMEOUT/CANCELLED/SHUTDOWN after the request was sent (any
                                    op; it matters for mutating ones: write, setstat, fsetstat, rename,
                                    remove, mkdir, rmdir, symlink, hardlink, copy-data, fsync, and opens
                                    with CREAT/TRUNC) */
  int      session_ready;        /* DISCONNECTED from a secondary pool member, session still READY */
  union {
    struct { sd_sftp_file *file; sd_sftp_attrs attrs; } open;   /* caller owns one reference */
    struct { uint32_t bytes; int eof; } read;                   /* contiguous bytes from offset */
    struct { uint32_t bytes; } write;                           /* contiguous bytes acknowledged */
    struct { sd_sftp_attrs attrs; } stat;
    struct { const sd_sftp_dirent *ents; uint32_t count; int eof; uint32_t dropped; } readdir;
    struct { const char *path; uint32_t len; sd_sftp_attrs attrs; } name;   /* realpath/readlink/expand/home */
    struct { sd_sftp_statvfs v; } statvfs;
    struct { const char *const *users; const char *const *groups; uint32_t nu, ng; } ids;
    struct { uint64_t bytes; } copy;
  } u;
} sd_sftp_completion;
typedef void (*sd_sftp_cb)(void *ctx, const sd_sftp_completion *c);

/* Completion details (M0 implementation notes):
   - read: err = SD_E_EOF (eof = 1, bytes = 0) when nothing could be read at off; otherwise SD_OK with
     the contiguous prefix in bytes and eof = 1 if end of file was reached inside the range.
   - readdir: end of listing is err = SD_OK, eof = 1, count = 0. dropped counts malformed names
     (empty, '/', NUL); the server's "." and ".." are removed silently.
   - write: on error, bytes is the contiguous acknowledged prefix.
   - reopen: u.open.file is the same object (no extra reference).
   Tokens from token_out are valid until the request's callback has started; cancelling later is
   harmless (SD_E_INVALID_PARAM) as tokens are never reused.
   Optional per-request options (may be NULL). timeout_ms = 0 -> default_timeout_ms. */
typedef struct sd_sftp_reqopt { uint32_t flags; uint32_t timeout_ms; sd_sftp_req **token_out; } sd_sftp_reqopt;
enum { SD_SFTP_REQ_WAIT_READY = 1u << 0, SD_SFTP_REQ_NO_REFINE = 1u << 1, SD_SFTP_REQ_CLASS_META = 1u << 2 };

/* Bits >= 1u<<24 are local to sd_sftp and never sent on the wire. */
enum { SD_SFTP_O_READ = 0x1, SD_SFTP_O_WRITE = 0x2, SD_SFTP_O_APPEND = 0x4,
       SD_SFTP_O_CREAT = 0x8, SD_SFTP_O_TRUNC = 0x10, SD_SFTP_O_EXCL = 0x20,
       SD_SFTP_O_STRIPED = 1u << 24 };

/* Paths are NUL-terminated raw byte strings (UTF-8 on normal servers); no normalization. */
sd_err sd_sftp_open(sd_sftp_session *s, const char *path, uint32_t oflags, const sd_sftp_attrs *create_attrs,
                    sd_sftp_file *same_channel_as, const sd_sftp_reqopt *o, sd_sftp_cb cb, void *ctx);
sd_err sd_sftp_opendir(sd_sftp_session *s, const char *path, const sd_sftp_reqopt *o, sd_sftp_cb cb, void *ctx);
sd_err sd_sftp_close(sd_sftp_file *f, const sd_sftp_reqopt *o, sd_sftp_cb cb, void *ctx); /* releases the caller's ref,
                                                                                              also when it fails */
void   sd_sftp_file_addref(sd_sftp_file *f);
void   sd_sftp_file_release(sd_sftp_file *f);   /* last ref on an open handle sends CLOSE in background */

sd_err sd_sftp_read (sd_sftp_file *f, uint64_t off, void *buf, uint32_t len,
                     const sd_sftp_reqopt *o, sd_sftp_cb cb, void *ctx);
sd_err sd_sftp_write(sd_sftp_file *f, uint64_t off, const void *buf, uint32_t len,
                     const sd_sftp_reqopt *o, sd_sftp_cb cb, void *ctx);
sd_err sd_sftp_readdir(sd_sftp_file *dir, const sd_sftp_reqopt *o, sd_sftp_cb cb, void *ctx);
sd_err sd_sftp_fstat(sd_sftp_file *f, const sd_sftp_reqopt *o, sd_sftp_cb cb, void *ctx);
sd_err sd_sftp_fsetstat(sd_sftp_file *f, const sd_sftp_attrs *a, const sd_sftp_reqopt *o, sd_sftp_cb cb, void *ctx);
sd_err sd_sftp_fsync(sd_sftp_file *f, const sd_sftp_reqopt *o, sd_sftp_cb cb, void *ctx);
sd_err sd_sftp_fstatvfs(sd_sftp_file *f, const sd_sftp_reqopt *o, sd_sftp_cb cb, void *ctx);
sd_err sd_sftp_copy_data(sd_sftp_file *src, uint64_t src_off, uint64_t len, sd_sftp_file *dst, uint64_t dst_off,
                         const sd_sftp_reqopt *o, sd_sftp_cb cb, void *ctx);

sd_err sd_sftp_stat    (sd_sftp_session *s, const char *path, const sd_sftp_reqopt *o, sd_sftp_cb cb, void *ctx);
sd_err sd_sftp_lstat   (sd_sftp_session *s, const char *path, const sd_sftp_reqopt *o, sd_sftp_cb cb, void *ctx);
sd_err sd_sftp_setstat (sd_sftp_session *s, const char *path, const sd_sftp_attrs *a, int no_follow,
                        const sd_sftp_reqopt *o, sd_sftp_cb cb, void *ctx);
sd_err sd_sftp_mkdir   (sd_sftp_session *s, const char *path, const sd_sftp_attrs *a,
                        const sd_sftp_reqopt *o, sd_sftp_cb cb, void *ctx);
sd_err sd_sftp_rmdir   (sd_sftp_session *s, const char *path, const sd_sftp_reqopt *o, sd_sftp_cb cb, void *ctx);
sd_err sd_sftp_remove  (sd_sftp_session *s, const char *path, const sd_sftp_reqopt *o, sd_sftp_cb cb, void *ctx);
enum { SD_SFTP_RENAME_OVERWRITE = 1u << 0 };   /* needs posix-rename; else SD_E_UNSUPPORTED */
sd_err sd_sftp_rename  (sd_sftp_session *s, const char *from, const char *to, uint32_t flags,
                        const sd_sftp_reqopt *o, sd_sftp_cb cb, void *ctx);
sd_err sd_sftp_readlink(sd_sftp_session *s, const char *path, const sd_sftp_reqopt *o, sd_sftp_cb cb, void *ctx);
sd_err sd_sftp_symlink (sd_sftp_session *s, const char *link_path, const char *target,
                        const sd_sftp_reqopt *o, sd_sftp_cb cb, void *ctx);
sd_err sd_sftp_hardlink(sd_sftp_session *s, const char *existing, const char *new_link,
                        const sd_sftp_reqopt *o, sd_sftp_cb cb, void *ctx);
sd_err sd_sftp_realpath(sd_sftp_session *s, const char *path, const sd_sftp_reqopt *o, sd_sftp_cb cb, void *ctx);
sd_err sd_sftp_expand_path(sd_sftp_session *s, const char *path, const sd_sftp_reqopt *o, sd_sftp_cb cb, void *ctx);
sd_err sd_sftp_home_directory(sd_sftp_session *s, const char *user, const sd_sftp_reqopt *o, sd_sftp_cb cb, void *ctx);
sd_err sd_sftp_statvfs_path(sd_sftp_session *s, const char *path, const sd_sftp_reqopt *o, sd_sftp_cb cb, void *ctx);
sd_err sd_sftp_names_by_id(sd_sftp_session *s, const uint32_t *uids, uint32_t nu, const uint32_t *gids, uint32_t ng,
                           const sd_sftp_reqopt *o, sd_sftp_cb cb, void *ctx);

/* Completes the request with SD_E_CANCELLED as soon as possible; afterwards the caller's buffer is
   never touched again. A cancelled OPEN whose reply later succeeds is closed automatically. */
sd_err sd_sftp_cancel(sd_sftp_req *r);

/* ---- reconnect contract (01 §10.6) ---- */

typedef struct sd_sftp_file_info {
  const char *path; uint32_t oflags; int is_dir; uint32_t generation; int stale; sd_sftp_attrs attrs_at_open;
} sd_sftp_file_info;
sd_err sd_sftp_file_get_info(sd_sftp_file *f, sd_sftp_file_info *out); /* path valid while a ref is held */
void  *sd_sftp_file_user(sd_sftp_file *f);
void   sd_sftp_file_set_user(sd_sftp_file *f, void *p);                /* VFS cookie */
/* Re-opens a stale handle in the current generation (01 §10.6), on the channel of its class:
   - files: OPEN(path, oflags & ~(CREAT|TRUNC|EXCL)) + FSTAT; directories: OPENDIR (a listing
     restarts at the beginning). The completion's u.open.file is the same object (no extra
     reference) and u.open.attrs holds the fresh attributes (files) for the identity check of the
     VFS; attrs_at_open and generation are updated and the handle is no longer stale.
   - On failure (e.g. SD_E_NOT_FOUND: the file is gone) the handle stays stale.
   - SD_E_INVALID_PARAM when the handle is not stale or its close was already submitted;
     SD_E_DISCONNECTED when not READY (unless SD_SFTP_REQ_WAIT_READY with a timeout).
   - Never re-sends data: replaying writes is the decision of the VFS (D9). */
sd_err sd_sftp_file_reopen(sd_sftp_file *f, const sd_sftp_reqopt *o, sd_sftp_cb cb, void *ctx);

/* ---- sync wrappers (CLI/tools; SD_E_WOULD_DEADLOCK on an I/O thread) ----
   timeout_ms = 0 -> default_timeout_ms. More wrappers are added as needed, one per async call. */
sd_err sd_sftp_stat_sync(sd_sftp_session *s, const char *path, sd_sftp_attrs *out, uint32_t timeout_ms);
sd_err sd_sftp_lstat_sync(sd_sftp_session *s, const char *path, sd_sftp_attrs *out, uint32_t timeout_ms);
sd_err sd_sftp_realpath_sync(sd_sftp_session *s, const char *path, char *out, size_t cap, uint32_t timeout_ms);
sd_err sd_sftp_open_sync(sd_sftp_session *s, const char *path, uint32_t oflags, const sd_sftp_attrs *create_attrs,
                         sd_sftp_file **out, sd_sftp_attrs *attrs_out, uint32_t timeout_ms);
sd_err sd_sftp_close_sync(sd_sftp_file *f, uint32_t timeout_ms);
sd_err sd_sftp_read_sync(sd_sftp_file *f, uint64_t off, void *buf, uint32_t len, uint32_t *got, uint32_t timeout_ms);
sd_err sd_sftp_write_sync(sd_sftp_file *f, uint64_t off, const void *buf, uint32_t len, uint32_t timeout_ms);
sd_err sd_sftp_mkdir_sync(sd_sftp_session *s, const char *path, const sd_sftp_attrs *a, uint32_t timeout_ms);
sd_err sd_sftp_remove_sync(sd_sftp_session *s, const char *path, uint32_t timeout_ms);
sd_err sd_sftp_rmdir_sync(sd_sftp_session *s, const char *path, uint32_t timeout_ms);
sd_err sd_sftp_rename_sync(sd_sftp_session *s, const char *from, const char *to, uint32_t flags, uint32_t timeout_ms);

/* SFTP status code -> sd_err per 01 §10.2 (exported for tests and the VFS error-table check). */
sd_err sd_sftp_status_to_err(uint32_t sftp_status);

#endif /* SD_SFTP_H */
