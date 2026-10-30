/* sd_vfs internals (02 §1-§5). Private to src/sd_vfs.
 *
 * Locking: one mutex per mount (v->lock) protects the node table, every node field, the
 * listings, the share counters, the handle list, block fetches and write-behind queues. It is the
 * degenerate form of 02 §5.5's order (tree_lock < node.lock < share_registry.lock) and is taken
 * before a memory-tier shard lock (vfs_cache.c) or a disk-tier lock (vfs_disk.c), never after. It
 * is never held across an sd_sftp submission or a network wait (review §4.1 rules 1 and 2), and
 * sd_sftp completions never take it (nor a shard lock): they only fill a batch slot and signal its
 * event (vfs_req.c). Read-ahead blocks and write-behind acknowledgements have no waiter; they stay
 * in their batch until a vfs thread (a reader, a writer, flush/cleanup or the per-mount background
 * timer) reaps them under v->lock. Every operation re-validates node state after a wait. */
#ifndef SD_VFS_INTERNAL_H
#define SD_VFS_INTERNAL_H

#include <windows.h>

#include "sd/base.h"
#include "sd_base/sd_err.h"
#include "sd_platform/sd_thread.h"
#include "sd_sftp/sd_sftp.h"
#include "sd_vfs/sd_vfs.h"

#define VFS_LOG "vfs"

/* POSIX type bits (S_IFMT and friends). */
#define VFS_S_IFMT   0170000u
#define VFS_S_IFDIR  0040000u
#define VFS_S_IFREG  0100000u
#define VFS_S_IFLNK  0120000u
#define VFS_S_ISGID  0002000u

/* Defaults (02 §1.4, §4.1, §5.7). */
#define VFS_DEF_ATTR_TTL      30000u
#define VFS_DEF_DIR_TTL       30000u
#define VFS_DEF_NEG_TTL       10000u
#define VFS_PROBE_NEG_TTL     300000u
#define VFS_DEF_REVALIDATE    1000
#define VFS_DEF_REQ_TIMEOUT   25000u
#define VFS_DEF_LIST_ENTRIES  1000000u
#define VFS_DEF_LIST_MB       256u
#define VFS_DEF_LIST_DEADLINE 120000u
#define VFS_DEF_LINK_STATS    4096u
#define VFS_DEF_UMASK         022u
#define VFS_STATFS_TTL        30000u
#define VFS_MAX_RAW_NAME      4096u
#define VFS_MAX_WIN_COMPONENT 255u
#define VFS_MAX_NODES         200000u
#define VFS_WAIT_GRACE_MS     5000u     /* beyond the request deadline before cancelling (sd_sftp bug guard) */
#define VFS_MAX_INFLIGHT      64u       /* chunks per data call */

/* Data cache, read-ahead and write modes (02 §4.2-§4.4, §5.2, §5.3). */
#define VFS_BLK_SHIFT         18u
#define VFS_BLK               (1u << VFS_BLK_SHIFT)   /* 256 KiB cache block */
#define VFS_RA_START          (256u * 1024u)
#define VFS_RA_SEQSCAN        (2u << 20)  /* FILE_FLAG_SEQUENTIAL_SCAN start window */
#define VFS_DEF_MAX_RA        (8u << 20)
#define VFS_DEF_WB_WINDOW     (16u << 20)
#define VFS_DEF_WB_MOUNT      (64u << 20)
#define VFS_DEF_GRACE         60000u
#define VFS_DEF_OFFLINE_WAIT  3000u
#define VFS_DEF_STRIPE_FILE   (8u << 20)  /* stripe_min_file default (02 §5.6) */
#define VFS_STRIPE_MIN_WRITE  (1u << 20)  /* sequential write that opts a handle in (02 §5.6) */
#define VFS_WB_COALESCE_MS    500u
#define VFS_WB_COALESCE_MAX   (1u << 20)
#define VFS_HOT_WINDOW_S      2
#define VFS_TIMER_MS          100u
#define VFS_DISK_TRIM_MS      60000u

/* Cached POSIX attributes (02 §1.5). */
typedef struct vfs_attr {
  uint32_t valid;       /* SD_SFTP_ATTR_* */
  uint64_t size;
  uint32_t mode, uid, gid;
  int64_t  atime, mtime;
} vfs_attr;

/* Entry flags (listing entries and nodes). */
enum {
  VFS_EF_LINK      = 1u << 0,   /* the remote object is a symlink */
  VFS_EF_LINK_BAD  = 1u << 1,   /* dangling, looping or (follow_inside) outside the root */
  VFS_EF_SPECIAL   = 1u << 2,   /* FIFO, socket or device */
  VFS_EF_DIR       = 1u << 3    /* effective type is a directory */
};

typedef struct vfs_dirent {
  char     *raw;   uint32_t raw_len;    /* remote component bytes, NUL-terminated */
  WCHAR    *wname; uint32_t wlen;       /* display name, NUL-terminated */
  WCHAR    *key;                        /* lookup key (folded in insensitive view) */
  char     *target;                     /* follow_inside: resolved absolute target of a good link */
  vfs_attr  attr;                       /* effective attributes (target's for good links) */
  uint32_t  eflags;
} vfs_dirent;

typedef struct vfs_listing {
  vfs_dirent *e; uint32_t n;
  uint64_t    time;                     /* sd_tick_ms() at fetch */
  uint32_t   *idx; uint32_t idx_cap;    /* open-addressing index by key (UINT32_MAX = empty) */
} vfs_listing;

/* Node flags. */
enum {
  VFS_NF_NEG            = 1u << 0,      /* negative cache entry */
  VFS_NF_IN_TABLE       = 1u << 1,
  VFS_NF_DELETE_PENDING = 1u << 2,
  VFS_NF_ROOT           = 1u << 3
};

typedef struct vfs_batch vfs_batch;
typedef struct vfs_extent { uint64_t off, end; } vfs_extent;

/* A thread waiting for node state to change (condition emulation: XP has no CONDITION_VARIABLE). */
typedef struct vfs_waiter { struct vfs_waiter *next; HANDLE ev; } vfs_waiter;

/* One 256 KiB block being fetched (single-flight, 02 §4.1/§4.3). Listed in node->fetch until it is
   processed into the cache; readers hold refs. v->lock protects every field. */
typedef struct vfs_fetch {
  struct vfs_fetch *next;
  uint64_t  blk;
  uint32_t  vgen;
  LONG      refs;
  vfs_batch *b;                         /* the chunk reads; owns buf */
  uint8_t  *buf;
  uint32_t  nch, chunk;
  BOOL      poisoned;                   /* a write or a validator change overlapped it: not cached */
  BOOL      processing, processed, listed;
  uint32_t  len; BOOL eof; sd_err err;  /* results once processed */
} vfs_fetch;

/* Write-behind extent (02 §4.4). data is owned by the extent; when an extent is discarded while its
   batch is in flight, data moves to the batch and is freed after the last completion. */
typedef struct vfs_wb {
  struct vfs_wb *next;
  uint64_t  off; uint32_t len;
  uint8_t  *data;
  vfs_batch *b;                         /* NULL: not sent (coalescing, blocked or waiting for reconnect) */
  uint32_t  nch, chunk;
  uint64_t  queued;                     /* tick */
  uint64_t  retry_until;                /* != 0: lost to a disconnect, retransmit before this tick */
  BOOL      maybe;                      /* sent at least once without an acknowledgement */
} vfs_wb;

struct vfs_dc;

typedef struct vfs_node {
  struct vfs_node *hnext;
  WCHAR    *key;  uint32_t hash;        /* full lookup path: L"" for the root, else L"\\A\\B" */
  WCHAR    *wname;                      /* display name of the last component (L"" for the root) */
  char     *raw;  uint32_t raw_len;     /* remote component bytes ("" for the root) */
  char     *lpath;                      /* absolute remote path of the object itself (the link for links) */
  char     *epath;                      /* path used for stat/data/children (resolved target for good links) */
  LONG      refs;
  uint32_t  flags;                      /* VFS_NF_* */
  uint32_t  eflags;                     /* VFS_EF_* */
  vfs_attr  attr;
  uint64_t  attr_time;                  /* tick of the attributes or of the negative result */
  uint32_t  neg_ttl;                    /* for negative entries */
  uint64_t  file_id;
  vfs_listing *list;                    /* directories: cached listing or NULL */
  /* share-mode state (02 §2.3, IoCheckShareAccess) */
  uint32_t  sh_open, sh_readers, sh_writers, sh_deleters, sh_sread, sh_swrite, sh_sdelete;
  uint32_t  open_count;                 /* handles not yet closed */
  uint32_t  uncleaned;                  /* handles not yet cleaned up */
  sd_sftp_file *fh; int fh_write;       /* lazily opened remote handle (02 §2.1) */
  int       stripe_wish;                /* a sequential write reached VFS_STRIPE_MIN_WRITE or the
                                           file grew past stripe_min_file (02 §5.6) */
  BOOL      reopening;                  /* a reopen after reconnect is running (02 §5.3) */
  vfs_extent *wext; uint32_t nwext, capwext;   /* write-through writes in flight (no two overlap) */
  vfs_waiter *waiters;                  /* woken on wext release, fetch processed, reopen done */
  struct vfs_node *lru_prev, *lru_next; /* idle (refs == 0) nodes in the table, oldest first */
  BOOL      in_lru;
  /* data cache validator (02 §4.2): blocks are keyed by (file_id, vgen) */
  uint32_t  vgen;
  BOOL      cv_valid; uint64_t cv_size; int64_t cv_mtime;   /* server (size, mtime) for vgen */
  uint64_t  srv_size;                   /* size on the server as far as acknowledged writes go */
  BOOL      mtime_pending;              /* local writes: the next server attrs give the mtime */
  BOOL      maybe_valid; uint64_t maybe_end;   /* a write that may have executed (5.3 identity) */
  vfs_fetch *fetch;                     /* blocks in flight */
  struct vfs_dc *dc;                    /* disk-tier entry while handles are open */
  /* write-behind queue (02 §4.4) */
  vfs_wb   *wq_head, *wq_tail;
  uint64_t  wq_bytes, wq_lost, wq_seq_end;
  sd_vfs_status wq_error;               /* sticky until the last handle closes */
  BOOL      wq_reported, wq_listed;
  struct vfs_node *wb_next;             /* v->wb_nodes list (holds a node ref) */
} vfs_node;

struct sd_vfs_handle {
  sd_vfs_handle *prev, *next;           /* live handle list (freed by sd_vfs_unmount) */
  sd_vfs   *v;
  vfs_node *node;
  uint32_t  access, share, opts;
  BOOL      is_dir, cleaned, wrote, delete_on_close, share_counted;
  BOOL      can_write;
  BOOL      times_pending; int64_t pend_atime, pend_mtime; BOOL pend_a, pend_m;
  /* read-ahead (02 §4.3) */
  uint64_t  ra_next, ra_end;            /* next sequential offset; end of what was issued */
  uint32_t  ra_window;                  /* 0: read-ahead off (RANDOM_ACCESS) */
  BOOL      write_through;              /* FILE_FLAG_WRITE_THROUGH on a write-behind mount */
  PSID      audit_sid;                  /* M5: owned copy of the requestor that opened for write on a global mount */
};

typedef struct vfs_hash { vfs_node **b; uint32_t nb, count; } vfs_hash;

struct vfs_disk;

/* M5 audit coalescing (03 10.3, Event 1200): one slot per (requestor SID, operation, path) raised in the last
   VFS_AUDIT_WINDOW_MS; a bounded table, so a flood of distinct paths cannot grow it. */
#define VFS_AUDIT_SLOTS      32u
#define VFS_AUDIT_WINDOW_MS  60000u
typedef struct vfs_audit_slot {
  BOOL      used;
  PSID      sid;                        /* owned copy */
  WCHAR    *path;                       /* owned copy */
  const char *op;                       /* static string */
  uint64_t  last;                       /* clock value of the last raised event */
} vfs_audit_slot;

struct sd_vfs {
  sd_sftp_session *s;
  sd_vfs_event_cb  cb; void *cb_ctx;
  sd_mutex lock;
  vfs_hash nodes;
  vfs_node *root;
  sd_vfs_handle *handles;
  uint64_t next_file_id;
  volatile LONG busy;                   /* requests in progress */
  volatile LONG quiescing;
  sd_mutex wait_lock;                   /* the offline waiters (vfs_data.c), never held across a wait */
  struct vfs_online_wait *waits;        /* offline waiters in flight, under wait_lock */
  /* options (resolved defaults) */
  BOOL read_only, hide_dotfiles, map_readonly, case_view_sensitive, show_special, allow_system;
  BOOL block_shell_active, remote_insensitive, fsync_on_flush;
  BOOL write_behind;
  int  symlinks;
  uint32_t max_readahead, wb_window, wb_window_mount, grace, offline_wait;
  uint32_t stripe_min_file;             /* striping size threshold (02 §5.6) */
  uint32_t umask, attr_ttl, dir_ttl, neg_ttl, req_timeout, list_entries, list_bytes, list_deadline,
           link_stats;
  int  revalidate;
  WCHAR *label, *fs_name, *offline_suffix;
  PSID owner_sid;
  /* M5 per-request access (02 §6.7, 7.7): copied lists and the well-known SIDs the check needs */
  BOOL global;
  PSID *acc_sids, *wrt_sids; uint32_t n_acc, n_wrt;
  PSID sid_system, sid_admins;
  /* M5 audit (02 6.7, 03 10.3): the clock is sd_tick_ms unless a test replaces it; audit_lock guards the 60 s
     coalescing table (initialized and destroyed with v->lock, so it exists on every failure path too) */
  uint64_t (*audit_now)(void);
  sd_mutex audit_lock;
  vfs_audit_slot audit[VFS_AUDIT_SLOTS];
  uint32_t serial;
  /* remote */
  char *root_path;  size_t root_len;    /* realpath of the mount root, no trailing '/' unless "/" */
  volatile LONG max_read, max_write;    /* re-read on every generation */
  volatile LONG gen;                    /* sd_sftp generation the mount state was last synced to */
  int64_t skew;                         /* server clock - local clock (s), from created objects */
  uint64_t mount_id;                    /* memory-tier key prefix */
  /* identity (02 §3.4) */
  BOOL uid_known, uid_definitive; uint32_t uid, gid;
  /* idle-node LRU, write-behind nodes, background timer, disk tier */
  vfs_node *lru_head, *lru_tail;
  vfs_node *wb_nodes;
  uint64_t wb_bytes;                    /* write-behind bytes queued on the mount */
  HANDLE timer;
  volatile LONG timer_busy;
  uint64_t next_trim;
  struct vfs_disk *disk;
  /* statvfs cache */
  sd_vfs_statfs fs; uint64_t fs_time;
  /* once-only notices */
  volatile LONG notice_shell, notice_rename_fallback;
  /* stats */
  volatile LONG64 bytes_rd, bytes_wr, cache_hits, cache_misses, write_failed, reconnects;
};

/* ---- vfs_name.c: stage-2 name mapping, folding, classification (02 §1.2, §1.3, §4.5) ---- */

/* Remote component -> display name (stage 1 + stage 2). Allocates *out (NUL-terminated). */
sd_vfs_status vfs_name_to_display(const char *raw, uint32_t raw_len, WCHAR **out, uint32_t *out_len);
/* Windows component -> remote bytes (stage-2 inverse + stage 1 + wire check). Allocates *out. */
sd_vfs_status vfs_name_from_display(const WCHAR *w, uint32_t len, char **out, uint32_t *out_len);
/* Validates a Windows input component (no stream syntax, wildcards or controls; length). */
sd_vfs_status vfs_name_check_input(const WCHAR *w, uint32_t len);
/* Folded key (LCMapStringW invariant uppercase); allocates. */
WCHAR *vfs_fold(const WCHAR *w, uint32_t len);
int    vfs_has_pua(const WCHAR *w, uint32_t len);       /* any code point in U+F000..U+F07F */
int    vfs_is_shell_active(const WCHAR *name);           /* 02 §4.5 set, case-insensitive */
int    vfs_is_probe_name(const WCHAR *name);             /* desktop.ini, Thumbs.db, ... (02 §4.1) */
/* Applies the ~cN collision rule to a listing whose keys are set; entries are sorted by raw bytes
   first. Returns the number of renamed entries, or (uint32_t)-1 on allocation failure. */
uint32_t vfs_mangle_collisions(vfs_dirent *e, uint32_t n, BOOL fold);
WCHAR *vfs_wcsdup(const WCHAR *w);
WCHAR *vfs_wcsndup(const WCHAR *w, size_t n);
char  *vfs_strndup(const char *s, size_t n);
uint32_t vfs_hash_w(const WCHAR *w);

/* ---- vfs_req.c: waiting on sd_sftp completions ---- */

typedef struct vfs_slot {
  vfs_batch *b;
  sd_sftp_req *token;
  volatile LONG done;
  sd_err err;
  int eof;
  int maybe_executed, session_ready;
  uint32_t bytes;
  sd_sftp_attrs attrs;                  /* ext pointers cleared */
  sd_sftp_file *file;                   /* open result (claimed by the waiter) */
  char *name; uint32_t name_len;        /* realpath/readlink result (heap) */
  sd_sftp_statvfs svfs;
  /* readdir result copies */
  struct vfs_rawent *ents; uint32_t nents; uint32_t dropped;
  uint64_t raw_bytes;
} vfs_slot;
typedef struct vfs_rawent { char *name; uint32_t len; sd_sftp_attrs attrs; } vfs_rawent;

vfs_batch *vb_new(uint32_t n);
vfs_slot  *vb_slot(vfs_batch *b, uint32_t i);
void       vb_attach_buf(vfs_batch *b, void *buf);   /* freed with the batch (after the last completion) */
BOOL       vb_done(vfs_batch *b);                     /* every submitted request completed */
HANDLE     vb_event(vfs_batch *b);                    /* manual-reset, set when done */
void       vb_ref(vfs_batch *b);                      /* extra reference, dropped with vb_free */
/* The options vb_opt armed for slot i, for a submission made after the arming (outside v->lock). */
const sd_sftp_reqopt *vb_optp(vfs_batch *b, uint32_t i);
/* Request options for slot i with the time left until deadline (tick ms). */
const sd_sftp_reqopt *vb_opt(vfs_batch *b, uint32_t i, uint64_t deadline);
sd_sftp_cb vb_cb(void);          /* status only */
sd_sftp_cb vb_cb_read(void);     /* bytes, eof */
sd_sftp_cb vb_cb_write(void);    /* bytes */
sd_sftp_cb vb_cb_readdir(void);  /* copies the entries into the slot */
sd_sftp_cb vb_cb_open(void);     /* file (claimed by the waiter), attrs */
sd_sftp_cb vb_cb_attrs(void);
sd_sftp_cb vb_cb_name(void);
void       vb_submitted(vfs_batch *b, uint32_t i, sd_err submit_result);
void       vb_wait(vfs_batch *b, uint64_t deadline);
void       vb_free(vfs_batch *b);
void       vb_free_rawents(vfs_slot *s);

/* Single-request helpers: each waits for its completion (or the deadline). */
sd_err vr_lstat(sd_vfs *v, const char *path, uint64_t dl, sd_sftp_attrs *out);
sd_err vr_stat(sd_vfs *v, const char *path, uint64_t dl, sd_sftp_attrs *out);
sd_err vr_realpath(sd_vfs *v, const char *path, uint64_t dl, char **out);
sd_err vr_open(sd_vfs *v, const char *path, uint32_t oflags, const sd_sftp_attrs *ca, uint64_t dl,
               sd_sftp_file **f, sd_sftp_attrs *attrs);
sd_err vr_mkdir(sd_vfs *v, const char *path, uint32_t perm, uint64_t dl);
sd_err vr_rmdir(sd_vfs *v, const char *path, uint64_t dl);
sd_err vr_remove(sd_vfs *v, const char *path, uint64_t dl);
sd_err vr_rename(sd_vfs *v, const char *from, const char *to, uint32_t flags, uint64_t dl);
sd_err vr_setstat(sd_vfs *v, const char *path, const sd_sftp_attrs *a, uint64_t dl);
sd_err vr_fsetstat(sd_sftp_file *f, const sd_sftp_attrs *a, uint64_t dl);
sd_err vr_fsync(sd_sftp_file *f, uint64_t dl);
sd_err vr_statvfs(sd_vfs *v, const char *path, uint64_t dl, sd_sftp_statvfs *out);
sd_err vr_reopen(sd_sftp_file *f, uint64_t dl, sd_sftp_attrs *out);

/* ---- vfs_core.c ---- */

uint64_t vfs_deadline(sd_vfs *v);
BOOL     vfs_online(sd_vfs *v);
void     vfs_event(sd_vfs *v, const sd_vfs_event *ev);
void     vfs_notice(sd_vfs *v, const char *code, const WCHAR *path);
void     vfs_attr_from_sftp(vfs_attr *a, const sd_sftp_attrs *s);
sd_vfs_status vfs_map_err(sd_err e);
/* Per-request access (M5, 02 §6.7, 7.7): vfs_access.c. init and free run at mount and unmount; check runs before
   every open or lookup (write: the request needs the write right). */
sd_vfs_status vfs_access_init(sd_vfs *v, const sd_vfs_options *o);
void          vfs_access_free(sd_vfs *v);
sd_vfs_status vfs_access_check(const sd_vfs *v, const sd_vfs_caller *c, BOOL write);
/* M5 audit (03 10.3, Event 1200): called after a mutating operation succeeded on a global mount. Raises
   SD_VFS_EV_AUDIT with the requestor SID, the operation and the path, unless the same (SID, operation, path) was
   raised within VFS_AUDIT_WINDOW_MS. who == NULL (per-user mounts, host-internal calls) raises nothing. */
void vfs_audit(sd_vfs *v, PSID who, const char *op, const WCHAR *path);
/* Copies the requestor SID for a handle that opened for write on a global mount (NULL when not needed). */
PSID vfs_audit_copy_sid(PSID sid);
void vfs_audit_init(sd_vfs *v);                 /* after v->lock: the clock and the table */
void vfs_audit_destroy(sd_vfs *v);
/* Remote path builder with the wire invariant (TM-R11). Allocates *out. */
sd_vfs_status vfs_join(sd_vfs *v, const char *parent, const char *raw, uint32_t raw_len, char **out);

void      vfs_node_ref(sd_vfs *v, vfs_node *n);            /* v->lock held */
void      vfs_node_unref(sd_vfs *v, vfs_node *n);          /* v->lock held */
vfs_node *vfs_table_find(sd_vfs *v, const WCHAR *key);      /* v->lock held, no ref */
void      vfs_table_remove(sd_vfs *v, vfs_node *n);         /* v->lock held */
void      vfs_table_readd(sd_vfs *v, vfs_node *n);          /* v->lock held; n not in the table */
BOOL      vfs_node_is_dir(const vfs_node *n);
WCHAR    *vfs_key_join(const WCHAR *parent_key, const WCHAR *child_key);

/* Path resolution. On SD_VFS_OK *node is referenced. On SD_VFS_E_NOT_FOUND, if parent_out is not
   NULL, *parent_out is the referenced parent directory and *leaf (allocated) the last Windows
   component; a missing intermediate directory yields SD_VFS_E_PATH_NOT_FOUND. force_fresh
   revalidates the leaf's attributes regardless of their age (open_revalidate). */
typedef struct vfs_path { WCHAR **comp; uint32_t n; WCHAR *key; } vfs_path;
sd_vfs_status vfs_path_parse(sd_vfs *v, const WCHAR *path, vfs_path *out);
void          vfs_path_free(vfs_path *p);
sd_vfs_status vfs_resolve(sd_vfs *v, const WCHAR *path, uint64_t dl, int64_t max_age_ms,
                          vfs_node **node, vfs_node **parent_out, WCHAR **leaf);
/* Fetches (if stale or forced) the listing of directory node d. */
sd_vfs_status vfs_listing_get(sd_vfs *v, vfs_node *d, uint64_t dl, BOOL force);
/* Inserts or updates a child node from fresh remote attributes; returns a referenced node. */
vfs_node *vfs_child_insert(sd_vfs *v, vfs_node *parent, const WCHAR *wname, const char *raw,
                           uint32_t raw_len, const vfs_attr *a, uint32_t eflags, const char *target);
void      vfs_listing_add(sd_vfs *v, vfs_node *parent, vfs_node *child);   /* v->lock held */
void      vfs_listing_del(sd_vfs *v, vfs_node *parent, const WCHAR *wname); /* v->lock held */
vfs_node *vfs_parent_of(sd_vfs *v, vfs_node *n);              /* v->lock held, no ref */
/* Remote path below n (its epath) + "/" + raw, built under v->lock: a concurrent rename may replace
   n->epath. */
sd_vfs_status vfs_join_under(sd_vfs *v, vfs_node *n, const char *raw, uint32_t raw_len, char **out);
WCHAR    *vfs_wname_copy(sd_vfs *v, vfs_node *n);
void      vfs_make_negative(sd_vfs *v, vfs_node *n);          /* v->lock held */
void      vfs_listing_sync(sd_vfs *v, vfs_node *n);           /* v->lock held: mirror attrs into the parent listing */
WCHAR    *vfs_node_path(sd_vfs *v, vfs_node *n);              /* v->lock held: L"\Dir\File" display path (allocated) */
void      vfs_learn_identity(sd_vfs *v, const vfs_attr *created, const vfs_attr *parent);
/* v->lock held: fresh server attributes for n; applies the data-cache validator rule (02 §4.2). */
void      vfs_node_set_attr(sd_vfs *v, vfs_node *n, const vfs_attr *a);
/* v->lock held: drops every cached block of n (new validator generation). */
void      vfs_node_invalidate(sd_vfs *v, vfs_node *n);
/* Re-reads server_info after a reconnect (limits, identity; 02 §5.1). Any vfs thread, no lock. */
void      vfs_sync_generation(sd_vfs *v);
/* Waits up to offline_wait for the session to come back (02 §5.2): one WAIT_READY request, completed by
   the session when it is READY again. FALSE on timeout, failure, or quiescing (vfs_cancel_waits). */
BOOL      vfs_wait_online(sd_vfs *v);
/* Cancels every offline waiter in flight so it returns FALSE now (quiesce and unmount). Any thread. */
void      vfs_cancel_waits(sd_vfs *v);

/* v->lock held: waits on n->waiters until woken or dl (FALSE on timeout), releasing the lock
   meanwhile. */
BOOL      vfs_cond_wait(sd_vfs *v, vfs_node *n, uint64_t dl);
void      vfs_cond_broadcast(vfs_node *n);                    /* v->lock held */

/* ---- vfs_data.c: data path (02 §4.2-§4.4, §5.3) ---- */
void      vfs_data_node_free(vfs_node *n);                    /* node teardown (no lock needed) */
struct vfs_dc *vfs_data_last_close(sd_vfs *v, vfs_node *n);  /* v->lock held; last local handle;
                                                                 close the returned entry unlocked */
sd_vfs_status vfs_data_cleanup(sd_vfs_handle *h, uint64_t dl);/* drain at cleanup (both modes) */
sd_vfs_status vfs_ext_drain(sd_vfs *v, vfs_node *n, uint64_t dl);
void      vfs_data_quiesce(sd_vfs *v, uint64_t end);
void      vfs_data_unmount(sd_vfs *v);
void      vfs_timer_start(sd_vfs *v);
void      vfs_timer_stop(sd_vfs *v);
void      vfs_handle_init_ra(sd_vfs_handle *h);
/* Referenced remote handle, reopened after a reconnect with the identity check (02 §5.3). */
sd_vfs_status vfs_get_fh(sd_vfs *v, vfs_node *n, BOOL need_write, uint64_t dl, sd_sftp_file **out,
                         BOOL seq);    /* seq: the caller's access looks sequential (02 §5.6) */

/* ---- vfs_cache.c: process-wide memory tier (02 §4.2) ---- */
typedef struct vc_key { uint64_t mount_id, file_id, blk; uint32_t vgen; } vc_key;
/* Copies [rel, rel+want) of a cached block into dst. Returns 1 on a hit (*got < want only at end of
   file, then *eof = 1), 0 on a miss. Hot blocks older than hot_ttl ms count as misses. */
int      vc_read(const vc_key *k, uint32_t rel, void *dst, uint32_t want, uint32_t *got, int *eof,
                 uint32_t hot_ttl);
int      vc_contains(const vc_key *k, uint32_t hot_ttl);
void     vc_put(const vc_key *k, const void *data, uint32_t len, int eof, int hot);
/* Updates a cached block in place with a local write of [rel, rel+n) (both write modes). A write
   that leaves a gap or passes a cached end of file drops the block instead. */
void     vc_write(const vc_key *k, uint32_t rel, const void *data, uint32_t n);
void     vc_drop(const vc_key *k);
void     vc_drop_file(uint64_t mount_id, uint64_t file_id);
void     vc_drop_mount(uint64_t mount_id);
uint64_t vc_new_mount_id(void);

/* ---- vfs_disk.c: per-mount disk tier (02 §4.2, TM-R29) ---- */
/* Validates the directory (reparse point, owner, DACL, persistent ACLs) and enables the tier; any
   failed check raises the disk_cache_refused notice and leaves the tier off. */
void     vfs_disk_open(sd_vfs *v, const sd_vfs_options *o, const char *host_fp);
void     vfs_disk_close(sd_vfs *v);
void     vfs_disk_trim(sd_vfs *v);
void     vfs_disk_clear(sd_vfs *v);          /* M3 cache.clear: every entry no vfs entry holds open */
BOOL     vfs_disk_enabled(sd_vfs *v);
/* Per-node entry: opened on the first data access, closed at the last handle close. NULL when the
   tier is off or the entry cannot be opened. */
struct vfs_dc *vfs_dc_open(sd_vfs *v, const char *rpath, uint64_t size, int64_t mtime, uint32_t vgen);
void     vfs_dc_close(sd_vfs *v, struct vfs_dc *dc);
/* 1 with the block's bytes when it is present for vgen. */
int      vfs_dc_read(sd_vfs *v, struct vfs_dc *dc, uint32_t vgen, uint64_t blk, uint8_t *buf, uint32_t *len,
                     int *eof);
void     vfs_dc_write(sd_vfs *v, struct vfs_dc *dc, uint32_t vgen, uint64_t blk, const uint8_t *buf,
                      uint32_t len);
void     vfs_dc_drop_range(sd_vfs *v, struct vfs_dc *dc, uint64_t off, uint64_t end);
int      vfs_dc_has(struct vfs_dc *dc, uint32_t vgen, uint64_t blk);
/* New validator: the same vgen keeps the blocks (our own writes), a new vgen truncates the file. */
void     vfs_dc_set_validator(sd_vfs *v, struct vfs_dc *dc, uint32_t vgen, uint64_t size, int64_t mtime);

/* Windows view of a node (02 §3.1, §3.2). v->lock held. */
void vfs_info_from(sd_vfs *v, const vfs_node *n, const WCHAR *name, const vfs_attr *a, uint32_t eflags,
                   sd_vfs_info *out);
uint32_t vfs_win_attrs(sd_vfs *v, const WCHAR *name, const vfs_attr *a, uint32_t eflags, BOOL is_root);
BOOL vfs_writable_by_us(sd_vfs *v, const vfs_attr *a);

/* ---- vfs_sd.c ---- */
sd_vfs_status vfs_build_sd(sd_vfs *v, const vfs_attr *a, BOOL is_dir, SECURITY_INFORMATION si,
                           PSECURITY_DESCRIPTOR out, ULONG len, ULONG *needed);

#endif /* SD_VFS_INTERNAL_H */
