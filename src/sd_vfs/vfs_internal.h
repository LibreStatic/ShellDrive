/* sd_vfs internals (02 §1-§5). Private to src/sd_vfs.
 *
 * Locking (M0): one mutex per mount (v->lock) protects the node table, every node field, the
 * listings, the share counters and the handle list. It is the degenerate form of 02 §5.5's order
 * (tree_lock < node.lock < share_registry.lock): it is never held across an sd_sftp submission or a
 * wait (review §4.1 rules 1 and 2), and sd_sftp completions never take it; they only fill the
 * request slot and signal its event (vfs_req.c). Every operation re-validates node state after a
 * wait. */
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

typedef struct vfs_extent { uint64_t off, end; } vfs_extent;

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
  vfs_extent *wext; uint32_t nwext, capwext;   /* writes in flight (no two overlap, 02 §4.4) */
} vfs_node;

struct sd_vfs_handle {
  sd_vfs_handle *prev, *next;           /* live handle list (freed by sd_vfs_unmount) */
  sd_vfs   *v;
  vfs_node *node;
  uint32_t  access, share, opts;
  BOOL      is_dir, cleaned, wrote, delete_on_close, share_counted;
  BOOL      can_write;
  BOOL      times_pending; int64_t pend_atime, pend_mtime; BOOL pend_a, pend_m;
};

typedef struct vfs_hash { vfs_node **b; uint32_t nb, count; } vfs_hash;

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
  /* options (resolved defaults) */
  BOOL read_only, hide_dotfiles, map_readonly, case_view_sensitive, show_special, allow_system;
  BOOL block_shell_active, remote_insensitive, fsync_on_flush;
  int  symlinks;
  uint32_t umask, attr_ttl, dir_ttl, neg_ttl, req_timeout, list_entries, list_bytes, list_deadline,
           link_stats;
  int  revalidate;
  WCHAR *label, *fs_name, *offline_suffix;
  PSID owner_sid;
  uint32_t serial;
  /* remote */
  char *root_path;  size_t root_len;    /* realpath of the mount root, no trailing '/' unless "/" */
  uint32_t max_read, max_write;
  /* identity (02 §3.4) */
  BOOL uid_known, uid_definitive; uint32_t uid, gid;
  /* statvfs cache */
  sd_vfs_statfs fs; uint64_t fs_time;
  /* once-only notices */
  volatile LONG notice_shell, notice_rename_fallback;
  /* stats */
  volatile LONG64 bytes_rd, bytes_wr, cache_hits, cache_misses;
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

typedef struct vfs_batch vfs_batch;
typedef struct vfs_slot {
  vfs_batch *b;
  sd_sftp_req *token;
  volatile LONG done;
  sd_err err;
  int eof;
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

/* ---- vfs_core.c ---- */

uint64_t vfs_deadline(sd_vfs *v);
BOOL     vfs_online(sd_vfs *v);
void     vfs_event(sd_vfs *v, const sd_vfs_event *ev);
void     vfs_notice(sd_vfs *v, const char *code, const WCHAR *path);
void     vfs_attr_from_sftp(vfs_attr *a, const sd_sftp_attrs *s);
sd_vfs_status vfs_map_err(sd_err e);
/* Remote path builder with the wire invariant (TM-R11). Allocates *out. */
sd_vfs_status vfs_join(sd_vfs *v, const char *parent, const char *raw, uint32_t raw_len, char **out);

void      vfs_node_ref(vfs_node *n);
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
void      vfs_learn_identity(sd_vfs *v, const vfs_attr *created, const vfs_attr *parent);

/* Windows view of a node (02 §3.1, §3.2). v->lock held. */
void vfs_info_from(sd_vfs *v, const vfs_node *n, const WCHAR *name, const vfs_attr *a, uint32_t eflags,
                   sd_vfs_info *out);
uint32_t vfs_win_attrs(sd_vfs *v, const WCHAR *name, const vfs_attr *a, uint32_t eflags, BOOL is_root);
BOOL vfs_writable_by_us(sd_vfs *v, const vfs_attr *a);

/* ---- vfs_sd.c ---- */
sd_vfs_status vfs_build_sd(sd_vfs *v, const vfs_attr *a, BOOL is_dir, SECURITY_INFORMATION si,
                           PSECURITY_DESCRIPTOR out, ULONG len, ULONG *needed);

#endif /* SD_VFS_INTERNAL_H */
