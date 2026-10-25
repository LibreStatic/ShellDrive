/* sd_sftp: asynchronous SFTP v3 client, the contract with the filesystem layer (01 §10, reconciled
 * with 02 §9 R1-R19).
 *
 * M0 scope: 1 SFTP channel, 1 connection, core operations, pipelining, caller deadlines, error
 * refinement, TM-R12 dirent filtering. Meta/bulk channels, reconnect and the pool arrive in M1/M2;
 * their API is final already (options are accepted and clamped: channels=1, connections=1).
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

enum { SD_SFTP_ATTR_SIZE = 0x1, SD_SFTP_ATTR_UIDGID = 0x2, SD_SFTP_ATTR_PERM = 0x4, SD_SFTP_ATTR_TIMES = 0x8,
       SD_SFTP_ATTR_EXTENDED = 0x80000000u };
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
  uint32_t retry_in_ms;                 /* RECONNECT_WAIT */
  const sd_sftp_server_info *info;      /* READY_INFO */
  uint32_t member, connections;         /* POOL */
} sd_sftp_event;

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
} sd_sftp_stats;
sd_err sd_sftp_session_stats(const sd_sftp_session *s, sd_sftp_stats *out);   /* any thread */

typedef void (*sd_sftp_event_cb)(void *ctx, const sd_sftp_event *ev);

/* ssh/ssh_cb/opt are deep-copied. */
sd_err sd_sftp_session_create(const sd_ssh_config *ssh, const sd_ssh_callbacks *ssh_cb,
                              const sd_sftp_options *opt, sd_sftp_event_cb ev, void *ev_ctx,
                              sd_sftp_session **out);
sd_err sd_sftp_session_start(sd_sftp_session *s);           /* async; progress via events */
sd_err sd_sftp_session_reconnect_now(sd_sftp_session *s);
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
  int      maybe_executed;       /* DISCONNECTED/TIMEOUT/CANCELLED after the request was sent */
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

/* Optional per-request options (may be NULL). timeout_ms = 0 -> default_timeout_ms. */
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
sd_err sd_sftp_close(sd_sftp_file *f, const sd_sftp_reqopt *o, sd_sftp_cb cb, void *ctx); /* releases the caller's ref */
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
