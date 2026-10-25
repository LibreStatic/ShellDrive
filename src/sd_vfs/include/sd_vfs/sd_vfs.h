/* sd_vfs: backend-neutral filesystem core between sd_sftp and the Dokany/WebDAV backends (02 §1-§5, §8).
 *
 * M0 scope: memory cache only (no disk tier), write-through (D9), symlinks follow_inside (D40),
 * Dokany backend. Option fields for later milestones are accepted; unsupported values fail the
 * mount with SD_VFS_E_UNSUPPORTED.
 *
 * Threading (02 §5.4, review §4.1):
 * - Request functions (create .. set_sd) are called concurrently from backend threads (Dokany
 *   callbacks, WebDAV workers). They block for at most the per-request deadline
 *   (request_timeout_ms, below the Dokany 30 s timeout) and never call *_sync APIs of sd_sftp.
 * - sd_vfs_mount, sd_vfs_quiesce and sd_vfs_unmount run on the host control thread only.
 * - The event callback runs on vfs threads with no vfs lock held; it must not call back into the
 *   unmount path.
 * Ownership: sd_vfs borrows the sd_sftp_session (owned by sd_mount; it must outlive sd_vfs_unmount).
 * Option strings and SIDs are deep-copied at mount. Handles are owned by the backend from
 * sd_vfs_create until sd_vfs_close. */
#ifndef SD_VFS_H
#define SD_VFS_H

#include <windows.h>

#include "sd/base.h"
#include "sd_base/sd_err.h"
#include "sd_sftp/sd_sftp.h"

typedef enum sd_vfs_status {
  SD_VFS_OK = 0,
  SD_VFS_E_NOT_FOUND, SD_VFS_E_PATH_NOT_FOUND, SD_VFS_E_EXISTS, SD_VFS_E_ACCESS_DENIED,
  SD_VFS_E_READ_ONLY, SD_VFS_E_SHARING, SD_VFS_E_DELETE_PENDING, SD_VFS_E_CANNOT_DELETE,
  SD_VFS_E_NOT_EMPTY, SD_VFS_E_IS_DIR, SD_VFS_E_NOT_DIR, SD_VFS_E_INVALID_NAME,
  SD_VFS_E_NAME_TOO_LONG, SD_VFS_E_NO_SPACE, SD_VFS_E_QUOTA, SD_VFS_E_TOO_LARGE,
  SD_VFS_E_DISCONNECTED, SD_VFS_E_STALE, SD_VFS_E_TIMEOUT, SD_VFS_E_UNSUPPORTED,
  SD_VFS_E_NO_MEMORY, SD_VFS_E_IO, SD_VFS_E_CANCELLED, SD_VFS_E_END_OF_FILE,
  SD_VFS_STATUS_COUNT
} sd_vfs_status;

/* sd_err -> sd_vfs_status (02 §8 table; one row per SD_ERR_LIST value, unit-tested). */
sd_vfs_status sd_vfs_status_from_err(sd_err e);

#define SD_VFS_MAX_CONN 4
#define SD_VFS_EOF      UINT64_MAX            /* sd_vfs_write offset: append at end of file */

typedef enum { SD_VFS_WRITE_THROUGH = 0, SD_VFS_WRITE_BEHIND = 1 } sd_vfs_write_mode;
typedef enum { SD_SYMLINK_FOLLOW_INSIDE = 0, SD_SYMLINK_FOLLOW = 1, SD_SYMLINK_HIDE = 2 } sd_vfs_symlinks;
typedef enum { SD_VFS_CASE_AUTO = 0, SD_VFS_CASE_SENSITIVE = 1, SD_VFS_CASE_INSENSITIVE = 2 } sd_vfs_case;

/* Kernel create dispositions and options (ntifs.h values, duplicated so no DDK header is needed). */
enum {
  SD_VFS_FILE_SUPERSEDE = 0, SD_VFS_FILE_OPEN = 1, SD_VFS_FILE_CREATE = 2, SD_VFS_FILE_OPEN_IF = 3,
  SD_VFS_FILE_OVERWRITE = 4, SD_VFS_FILE_OVERWRITE_IF = 5
};
enum {
  SD_VFS_FILE_DIRECTORY_FILE = 0x00000001, SD_VFS_FILE_WRITE_THROUGH = 0x00000002,
  SD_VFS_FILE_SEQUENTIAL_ONLY = 0x00000004, SD_VFS_FILE_NO_INTERMEDIATE_BUFFERING = 0x00000008,
  SD_VFS_FILE_NON_DIRECTORY_FILE = 0x00000040, SD_VFS_FILE_RANDOM_ACCESS = 0x00000800,
  SD_VFS_FILE_DELETE_ON_CLOSE = 0x00001000, SD_VFS_FILE_OPEN_REPARSE_POINT = 0x00200000
};

/* Numeric fields: 0 = the 02 default (TTLs 30 s / 30 s / 10 s, umask 022, request_timeout 25 s,
   list caps of 02 §1.4). open_revalidate_ms: 0 = default 1 s, -1 = never, n > 0 = n ms. BOOLs are
   taken literally (the host sets hide_dotfiles, map_readonly, allow_system, fsync_on_flush, which
   default to on in the profile). M0 rejects with SD_VFS_E_UNSUPPORTED: write_mode = behind,
   global_mount, disk_cache_mb, mark_of_the_web, remote_codepage. */
typedef struct sd_vfs_options {
  UINT32 struct_size;                 /* sizeof(sd_vfs_options) */
  const char *remote_root;            /* bytes; NULL = home */
  BOOL  read_only, hide_dotfiles, map_readonly, case_sensitive_view, show_special, allow_system;
  int   remote_case;                  /* sd_vfs_case */
  int   symlinks;                     /* sd_vfs_symlinks; default SD_SYMLINK_FOLLOW_INSIDE (D40) */
  BOOL  block_shell_active;           /* resolved by the host from security.trust (D41, 02 §4.5) */
  BOOL  mark_of_the_web;              /* Dokany only; default off (D44) */
  const char *motw_host_url;
  UINT  max_list_entries, max_list_mb, list_deadline_ms, max_link_stats;  /* 0 = defaults (02 §1.4) */
  UINT  umask, remote_codepage;       /* remote_codepage 0 = UTF-8 (stage 1) */
  UINT  attr_ttl_ms, dir_ttl_ms, neg_ttl_ms; int open_revalidate_ms;
  UINT  max_readahead;
  sd_vfs_write_mode write_mode;       /* default write-through (D9) */
  UINT  wb_window, wb_window_mount;   /* write-behind only */
  BOOL  fsync_on_flush;
  UINT  offline_wait_ms, reconnect_grace_ms;
  UINT  request_timeout_ms;           /* 25000 Dokany, 50000 WebDAV (02 §5.7) */
  UINT  stripe_min_file;              /* default 8 MiB */
  UINT  disk_cache_mb; const WCHAR *disk_cache_dir;   /* M1 */
  UINT  offline_hint_over_mb;         /* WebDAV only (D22) */
  const WCHAR *volume_fs_name;        /* Dokany; NULL = L"NTFS" (D23) */
  const WCHAR *volume_label, *offline_label_suffix;  /* localized by the host (C45) */
  PSID  owner_sid;                    /* mount owner */
  BOOL  global_mount;                 /* scope = service (D35) */
  const PSID *access_sids;  UINT n_access;
  const PSID *write_sids;   UINT n_write;
} sd_vfs_options;

typedef struct sd_vfs_caller {
  PSID sid;                           /* requestor / SSPI token user */
  BOOL can_write;                     /* FALSE: enforced like a read-only mount for this caller */
} sd_vfs_caller;

/* POSIX attributes as cached from the server (02 §3.1). */
typedef struct sd_vfs_attr {
  UINT32 valid;                       /* SD_SFTP_ATTR_* bits */
  UINT32 uid, gid, mode;
  INT64  atime, mtime;
} sd_vfs_attr;

typedef struct sd_vfs_identity {
  BOOL uid_known, definitive; UINT32 uid, gid;
  const UINT32 *groups; UINT32 ngroups;
} sd_vfs_identity;

typedef struct sd_vfs        sd_vfs;
typedef struct sd_vfs_handle sd_vfs_handle;

typedef enum {
  SD_VFS_EV_CHANGE,           /* path, new_path, is_dir: forwarded to DokanNotify* */
  SD_VFS_EV_WRITE_FAILED,     /* path, bytes, status: host raises write_failed (C45) */
  SD_VFS_EV_DELETE_FAILED,    /* path, status */
  SD_VFS_EV_STATE,            /* connected / disconnected / failed */
  SD_VFS_EV_IDENTITY,         /* uid learned or changed */
  SD_VFS_EV_AUDIT,            /* global mounts: requestor SID, operation, path (TM-R24) */
  SD_VFS_EV_NOTICE            /* English log text + code */
} sd_vfs_event_kind;
typedef struct sd_vfs_event {
  sd_vfs_event_kind kind; int change_kind; const WCHAR *path, *new_path; BOOL is_dir;
  UINT64 bytes; sd_vfs_status status; UINT32 conn_index; const char *code;
  PSID caller_sid; const char *op;
} sd_vfs_event;                       /* pointers valid during the callback only */
typedef void (*sd_vfs_event_cb)(void *ctx, const sd_vfs_event *ev);

/* ---- lifecycle (host control thread only) ---- */

sd_vfs_status sd_vfs_mount(sd_sftp_session *s, const sd_vfs_options *o,
                           sd_vfs_event_cb cb, void *cb_ctx, sd_vfs **out);
void          sd_vfs_quiesce(sd_vfs *v, DWORD budget_ms);   /* block new opens, drain writes */
void          sd_vfs_unmount(sd_vfs *v);

/* ---- requests (backend threads) ---- */

sd_vfs_status sd_vfs_create(sd_vfs *v, const WCHAR *path, const sd_vfs_caller *caller,
                            UINT32 access, UINT32 share,
                            UINT32 disposition, UINT32 create_options, UINT32 win_attrs,
                            sd_vfs_handle **h, BOOL *existed, BOOL *is_dir);
/* Last handle cleanup: releases share access, applies deferred times and performs a pending delete
   (02 §2.4); returns the delete's status (Dokany ignores it, the vfs raises SD_VFS_EV_DELETE_FAILED). */
sd_vfs_status sd_vfs_cleanup(sd_vfs_handle *h, BOOL delete_pending);
void          sd_vfs_close(sd_vfs_handle *h);

sd_vfs_status sd_vfs_read (sd_vfs_handle *h, UINT64 off, void *buf, UINT32 len, UINT32 *got);
sd_vfs_status sd_vfs_write(sd_vfs_handle *h, UINT64 off /* SD_VFS_EOF */, const void *buf,
                           UINT32 len, UINT32 *done, BOOL paging_io);
sd_vfs_status sd_vfs_flush(sd_vfs_handle *h);
sd_vfs_status sd_vfs_truncate(sd_vfs_handle *h, UINT64 size);

typedef struct sd_vfs_info {
  UINT32 win_attrs; UINT64 size, alloc, file_id;
  FILETIME ctime, atime, mtime;  sd_vfs_attr posix;
} sd_vfs_info;
sd_vfs_status sd_vfs_getattr(sd_vfs_handle *h, sd_vfs_info *out);
sd_vfs_status sd_vfs_stat_path(sd_vfs *v, const WCHAR *path, sd_vfs_info *out);
sd_vfs_status sd_vfs_set_winattrs(sd_vfs_handle *h, UINT32 attrs);
sd_vfs_status sd_vfs_set_times(sd_vfs_handle *h, const FILETIME *c, const FILETIME *a, const FILETIME *w);

/* Snapshot listing; the callback runs on the calling thread. Return FALSE to stop. */
typedef BOOL (*sd_vfs_dirent_cb)(void *ctx, const WCHAR *name, const sd_vfs_info *info);
sd_vfs_status sd_vfs_readdir(sd_vfs_handle *h, sd_vfs_dirent_cb cb, void *ctx);

sd_vfs_status sd_vfs_can_delete(sd_vfs_handle *h);
sd_vfs_status sd_vfs_delete_path(sd_vfs *v, const sd_vfs_caller *c, const WCHAR *path, BOOL recursive);
sd_vfs_status sd_vfs_rename(sd_vfs_handle *h, const WCHAR *new_path, BOOL replace);
sd_vfs_status sd_vfs_rename_path(sd_vfs *v, const sd_vfs_caller *c, const WCHAR *from, const WCHAR *to,
                                 BOOL replace);
sd_vfs_status sd_vfs_copy_path(sd_vfs *v, const sd_vfs_caller *c, const WCHAR *from, const WCHAR *to,
                               BOOL replace, BOOL recursive);

typedef struct sd_vfs_statfs { UINT64 total, free, avail; BOOL known; } sd_vfs_statfs;
sd_vfs_status sd_vfs_statfs_get(sd_vfs *v, sd_vfs_statfs *out);

/* Self-relative SD (02 §3.3). Returns SD_VFS_OK with *needed > len when the buffer is too small
   (the backend reports STATUS_BUFFER_OVERFLOW). */
sd_vfs_status sd_vfs_get_sd(sd_vfs_handle *h, SECURITY_INFORMATION si, PSECURITY_DESCRIPTOR sd,
                            ULONG len, ULONG *needed);
sd_vfs_status sd_vfs_set_sd(sd_vfs_handle *h, SECURITY_INFORMATION si, PSECURITY_DESCRIPTOR sd);

/* ---- diagnostics (any thread) ---- */

typedef struct sd_vfs_conn_stats { UINT32 state, generation, srtt_ms; UINT64 bytes_rd, bytes_wr,
                                   inflight_max, reconnects; } sd_vfs_conn_stats;
typedef struct sd_vfs_stats { UINT64 ops[32], rtts[32], cache_hits, cache_misses, bytes_rd, bytes_wr,
                              inflight_max, reconnects, write_failed;
                              UINT32 nconn; sd_vfs_conn_stats conn[SD_VFS_MAX_CONN]; } sd_vfs_stats;
void sd_vfs_get_stats(sd_vfs *v, sd_vfs_stats *out);
void sd_vfs_refresh(sd_vfs *v, const WCHAR *subtree);

/* Static volume facts for the backend (GetVolumeInformation, requestor check). Pointers stay valid
   until sd_vfs_unmount; `online` is a snapshot (append offline_suffix to the label when FALSE). */
typedef struct sd_vfs_volume {
  const WCHAR *label, *offline_suffix, *fs_name;   /* fs_name defaults to L"NTFS" (D23) */
  BOOL read_only, case_sensitive_view, allow_system, online;
  PSID owner_sid;                                  /* mount owner (copy; process user if not given) */
  UINT32 serial;
} sd_vfs_volume;
void sd_vfs_get_volume(sd_vfs *v, sd_vfs_volume *out);

#endif /* SD_VFS_H */
