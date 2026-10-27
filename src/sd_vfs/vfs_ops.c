/* sd_vfs requests: create/cleanup/close, data I/O, attributes, listing, delete, rename, statfs
 * (02 §2, §3, §4.4). Called concurrently from backend threads; see vfs_internal.h for locking. */
#include <windows.h>
#include <stdio.h>

#include "sd_base/sd_checked.h"
#include "sd_base/sd_mem.h"
#include "sd_platform/sd_log.h"
#include "sd_platform/sd_time.h"
#include "vfs_internal.h"

#define ACC_DATA_READ   (FILE_READ_DATA | FILE_EXECUTE)
#define ACC_DATA_WRITE  (FILE_WRITE_DATA | FILE_APPEND_DATA)
#define ACC_WRITE_CLASS (FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES | DELETE | \
                         WRITE_DAC | WRITE_OWNER | FILE_DELETE_CHILD)

static void enter(sd_vfs *v) { InterlockedIncrement(&v->busy); }
static void leave(sd_vfs *v) { InterlockedDecrement(&v->busy); }

static uint32_t map_generic(uint32_t a, BOOL ro)
{
  if (a & GENERIC_READ)    a |= FILE_GENERIC_READ;
  if (a & GENERIC_WRITE)   a |= FILE_GENERIC_WRITE;
  if (a & GENERIC_EXECUTE) a |= FILE_GENERIC_EXECUTE;
  if (a & GENERIC_ALL)     a |= FILE_ALL_ACCESS;
  if (a & MAXIMUM_ALLOWED) a |= FILE_GENERIC_READ | (ro ? 0 : (FILE_GENERIC_WRITE | DELETE));
  return a & ~(uint32_t)(GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE | GENERIC_ALL | MAXIMUM_ALLOWED);
}

static BOOL disp_truncates(uint32_t d)
{
  return d == SD_VFS_FILE_OVERWRITE || d == SD_VFS_FILE_OVERWRITE_IF || d == SD_VFS_FILE_SUPERSEDE;
}

/* ---- share modes (02 §2.3: IoCheckShareAccess among local opens) ---- */

static sd_vfs_status share_check(vfs_node *n, uint32_t access, uint32_t share, BOOL update)
{
  BOOL rd = (access & ACC_DATA_READ) != 0, wr = (access & ACC_DATA_WRITE) != 0, del = (access & DELETE) != 0;
  BOOL srd = (share & FILE_SHARE_READ) != 0, swr = (share & FILE_SHARE_WRITE) != 0,
       sdel = (share & FILE_SHARE_DELETE) != 0;
  if (!rd && !wr && !del)
    return SD_VFS_OK;                       /* attribute-only opens never conflict */
  if ((rd && n->sh_sread < n->sh_open) || (wr && n->sh_swrite < n->sh_open) ||
      (del && n->sh_sdelete < n->sh_open) || (n->sh_readers && !srd) || (n->sh_writers && !swr) ||
      (n->sh_deleters && !sdel))
    return SD_VFS_E_SHARING;
  if (update) {
    n->sh_open++;
    n->sh_readers += rd; n->sh_writers += wr; n->sh_deleters += del;
    n->sh_sread += srd; n->sh_swrite += swr; n->sh_sdelete += sdel;
  }
  return SD_VFS_OK;
}

static void share_release(vfs_node *n, uint32_t access, uint32_t share)
{
  BOOL rd = (access & ACC_DATA_READ) != 0, wr = (access & ACC_DATA_WRITE) != 0, del = (access & DELETE) != 0;
  if (!rd && !wr && !del)
    return;
  n->sh_open--;
  n->sh_readers -= rd; n->sh_writers -= wr; n->sh_deleters -= del;
  n->sh_sread -= (share & FILE_SHARE_READ) != 0;
  n->sh_swrite -= (share & FILE_SHARE_WRITE) != 0;
  n->sh_sdelete -= (share & FILE_SHARE_DELETE) != 0;
}

/* ---- helpers ---- */

static BOOL node_readonly_attr(sd_vfs *v, const vfs_node *n)
{
  return !vfs_node_is_dir(n) && !(n->eflags & (VFS_EF_LINK_BAD | VFS_EF_SPECIAL)) && v->map_readonly &&
         !vfs_writable_by_us(v, &n->attr);
}

static sd_vfs_status new_handle(sd_vfs *v, vfs_node *n, uint32_t access, uint32_t share, uint32_t opts,
                                BOOL can_write, sd_vfs_handle **out)
{
  /* v->lock held */
  sd_vfs_handle *h = (sd_vfs_handle *)sd_calloc(1, sizeof(*h));
  if (!h)
    return SD_VFS_E_NO_MEMORY;
  if (share_check(n, access, share, TRUE) != SD_VFS_OK) {
    sd_free(h);
    return SD_VFS_E_SHARING;
  }
  h->v = v;
  h->node = n;
  vfs_node_ref(v, n);
  h->access = access;
  h->share = share;
  h->opts = opts;
  h->is_dir = vfs_node_is_dir(n);
  h->share_counted = TRUE;
  h->can_write = can_write;
  h->delete_on_close = (opts & SD_VFS_FILE_DELETE_ON_CLOSE) != 0;
  vfs_handle_init_ra(h);
  n->open_count++;
  n->uncleaned++;
  h->next = v->handles;
  if (v->handles) v->handles->prev = h;
  v->handles = h;
  *out = h;
  return SD_VFS_OK;
}

/* ---- create (02 §2.2) ---- */

static sd_vfs_status open_existing(sd_vfs *v, vfs_node *n, uint32_t access, uint32_t share, uint32_t disp,
                                   uint32_t opts, BOOL ro, uint64_t dl, sd_vfs_handle **h, BOOL *existed,
                                   BOOL *is_dir)
{
  BOOL dir, data = (access & (ACC_DATA_READ | ACC_DATA_WRITE)) != 0;
  sd_vfs_status st = SD_VFS_OK;
  BOOL block_notice = FALSE;
  *existed = TRUE;
  sd_mutex_lock(&v->lock);
  dir = vfs_node_is_dir(n);
  if (n->flags & VFS_NF_DELETE_PENDING) st = SD_VFS_E_DELETE_PENDING;
  else if (disp == SD_VFS_FILE_CREATE) st = SD_VFS_E_EXISTS;
  else if ((n->eflags & VFS_EF_LINK_BAD) && (data || (opts & SD_VFS_FILE_DIRECTORY_FILE) || disp_truncates(disp)))
    st = SD_VFS_E_NOT_FOUND;                /* dangling / outside-root link: no data, no entering */
  else if (dir && (opts & SD_VFS_FILE_NON_DIRECTORY_FILE)) st = SD_VFS_E_IS_DIR;
  else if (dir && disp_truncates(disp)) st = SD_VFS_E_IS_DIR;
  else if (!dir && (opts & SD_VFS_FILE_DIRECTORY_FILE)) st = SD_VFS_E_NOT_DIR;
  else if ((n->eflags & VFS_EF_SPECIAL) && data) st = SD_VFS_E_ACCESS_DENIED;
  else if (ro && ((access & ACC_WRITE_CLASS) || disp_truncates(disp))) st = SD_VFS_E_READ_ONLY;
  else if (node_readonly_attr(v, n) && ((access & ACC_DATA_WRITE) || disp_truncates(disp))) st = SD_VFS_E_ACCESS_DENIED;
  else if ((opts & SD_VFS_FILE_DELETE_ON_CLOSE) && (n->flags & VFS_NF_ROOT)) st = SD_VFS_E_ACCESS_DENIED;
  else if ((opts & SD_VFS_FILE_DELETE_ON_CLOSE) && node_readonly_attr(v, n)) st = SD_VFS_E_CANNOT_DELETE;
  else if (!dir && v->block_shell_active && (access & ACC_DATA_READ) && vfs_is_shell_active(n->wname)) {
    st = SD_VFS_E_ACCESS_DENIED;            /* TM-R14 (02 §4.5) */
    block_notice = InterlockedCompareExchange(&v->notice_shell, 1, 0) == 0;
  } else st = share_check(n, access, share, FALSE);
  if (st == SD_VFS_OK && !dir && (access & ACC_DATA_WRITE) && !vfs_online(v))
    st = SD_VFS_E_DISCONNECTED;             /* open with write access while offline (02 §5.2) */
  sd_mutex_unlock(&v->lock);
  if (block_notice) {
    WCHAR *nm = vfs_wname_copy(v, n);
    vfs_notice(v, "shell_active_blocked", nm);
    sd_free(nm);
  }
  if (st != SD_VFS_OK)
    return st;

  if (!dir && disp_truncates(disp)) {
    sd_sftp_file *f = NULL, *old;
    sd_sftp_attrs a;
    char *path;
    sd_err e;
    if (!vfs_online(v))
      return SD_VFS_E_DISCONNECTED;
    sd_mutex_lock(&v->lock);
    path = vfs_strndup(n->epath, strlen(n->epath));
    sd_mutex_unlock(&v->lock);
    if (!path)
      return SD_VFS_E_NO_MEMORY;
    e = vr_open(v, path, SD_SFTP_O_READ | SD_SFTP_O_WRITE | SD_SFTP_O_TRUNC, NULL, dl, &f, &a);
    sd_free(path);
    if (e != SD_OK)
      return vfs_map_err(e);
    sd_mutex_lock(&v->lock);
    old = n->fh;
    n->fh = f;
    n->fh_write = TRUE;
    vfs_node_invalidate(v, n);              /* the content is gone: so are its cached blocks */
    n->attr.size = 0;                       /* TRUNC keeps the mode (02 §2.2) */
    n->attr.mtime = sd_unix_time_now();
    n->attr_time = sd_tick_ms();
    n->srv_size = n->cv_size = 0;
    n->cv_valid = TRUE;
    n->mtime_pending = TRUE;
    if (a.valid & SD_SFTP_ATTR_TIMES) {
      n->cv_mtime = a.mtime;                /* the open's FSTAT is the new validator */
      n->mtime_pending = FALSE;
    }
    vfs_listing_sync(v, n);
    sd_mutex_unlock(&v->lock);
    if (old)
      sd_sftp_file_release(old);
  }
  if (dir && (opts & SD_VFS_FILE_DELETE_ON_CLOSE) && !(n->eflags & VFS_EF_LINK)) {
    st = vfs_listing_get(v, n, dl, TRUE);
    if (st != SD_VFS_OK)
      return st;
    sd_mutex_lock(&v->lock);
    st = (n->list && n->list->n > 0) ? SD_VFS_E_NOT_EMPTY : SD_VFS_OK;
    sd_mutex_unlock(&v->lock);
    if (st != SD_VFS_OK)
      return st;
  }
  sd_mutex_lock(&v->lock);
  st = new_handle(v, n, access, share, opts, !ro, h);
  sd_mutex_unlock(&v->lock);
  *is_dir = dir;
  return st;
}

static sd_vfs_status create_new(sd_vfs *v, vfs_node *parent, const WCHAR *leaf, uint32_t access,
                                uint32_t share, uint32_t disp, uint32_t opts, uint32_t win_attrs, BOOL ro,
                                uint64_t dl, sd_vfs_handle **h, BOOL *is_dir)
{
  char *raw = NULL, *path = NULL;
  uint32_t raw_len = 0;
  WCHAR *disp_name = NULL;
  sd_vfs_status st;
  sd_sftp_attrs sa;
  sd_sftp_file *f = NULL;
  vfs_attr a, pattr;
  sd_err e;
  BOOL mkdir_ = (opts & SD_VFS_FILE_DIRECTORY_FILE) != 0;
  vfs_node *c;

  if (disp == SD_VFS_FILE_OPEN || disp == SD_VFS_FILE_OVERWRITE)
    return SD_VFS_E_NOT_FOUND;
  if (ro)
    return SD_VFS_E_READ_ONLY;
  if (!vfs_online(v))
    return SD_VFS_E_DISCONNECTED;
  if ((parent->flags & VFS_NF_ROOT) &&
      (_wcsicmp(leaf, L"$RECYCLE.BIN") == 0 || _wcsicmp(leaf, L"System Volume Information") == 0))
    return SD_VFS_E_ACCESS_DENIED;          /* fixed-type mounts: Explorer falls back to delete (02 §6.4) */
  st = vfs_name_from_display(leaf, (uint32_t)wcslen(leaf), &raw, &raw_len);
  if (st == SD_VFS_OK)
    st = vfs_name_to_display(raw, raw_len, &disp_name, NULL);
  if (st == SD_VFS_OK)
    st = vfs_join_under(v, parent, raw, raw_len, &path);
  if (st != SD_VFS_OK)
    goto out;
  memset(&sa, 0, sizeof(sa));
  if (mkdir_) {
    e = vr_mkdir(v, path, 0777u & ~v->umask, dl);
    if (e == SD_OK)
      e = vr_lstat(v, path, dl, &sa);
  } else {
    sd_sftp_attrs ca;
    uint32_t of = SD_SFTP_O_READ | SD_SFTP_O_WRITE | SD_SFTP_O_CREAT;
    if (disp == SD_VFS_FILE_CREATE) of |= SD_SFTP_O_EXCL;
    if (disp == SD_VFS_FILE_OVERWRITE_IF || disp == SD_VFS_FILE_SUPERSEDE) of |= SD_SFTP_O_TRUNC;
    memset(&ca, 0, sizeof(ca));
    ca.valid = SD_SFTP_ATTR_PERM;
    ca.perm = 0666u & ~v->umask;
    e = vr_open(v, path, of, &ca, dl, &f, &sa);
    if (e == SD_OK && (win_attrs & FILE_ATTRIBUTE_READONLY)) {
      /* Applied after creation so the creator can still write through its handle (02 §2.2). */
      sd_sftp_attrs ra;
      memset(&ra, 0, sizeof(ra));
      ra.valid = SD_SFTP_ATTR_PERM;
      ra.perm = 0444u & ~v->umask;
      if (vr_fsetstat(f, &ra, dl) == SD_OK) {
        sa.perm = (sa.valid & SD_SFTP_ATTR_PERM ? (sa.perm & VFS_S_IFMT) : VFS_S_IFREG) | ra.perm;
        sa.valid |= SD_SFTP_ATTR_PERM;
      }
    }
  }
  if (e != SD_OK) {
    st = vfs_map_err(e);
    if (st == SD_VFS_E_NOT_FOUND)
      st = SD_VFS_E_PATH_NOT_FOUND;         /* the parent vanished */
    goto out;
  }
  vfs_attr_from_sftp(&a, &sa);
  if (!(a.valid & SD_SFTP_ATTR_PERM)) {
    a.mode = (mkdir_ ? VFS_S_IFDIR | 0777u : VFS_S_IFREG | 0666u) & ~v->umask;
    a.valid |= SD_SFTP_ATTR_PERM;
  }
  if (!(a.valid & SD_SFTP_ATTR_SIZE)) {
    a.size = 0;
    a.valid |= SD_SFTP_ATTR_SIZE;
  }
  if (!(a.valid & SD_SFTP_ATTR_TIMES)) {
    a.mtime = a.atime = sd_unix_time_now();
    a.valid |= SD_SFTP_ATTR_TIMES;
  }
  sd_mutex_lock(&v->lock);
  pattr = parent->attr;
  vfs_learn_identity(v, &a, &pattr);
  c = vfs_child_insert(v, parent, disp_name, raw, raw_len, &a, mkdir_ ? VFS_EF_DIR : 0, NULL);
  if (!c) {
    sd_mutex_unlock(&v->lock);
    st = SD_VFS_E_NO_MEMORY;
    goto out;
  }
  if (f) {
    if (c->fh) sd_sftp_file_release(c->fh);   /* stale handle of a replaced object */
    c->fh = f;
    c->fh_write = TRUE;
    f = NULL;
  }
  vfs_listing_add(v, parent, c);
  st = new_handle(v, c, access, share, opts, TRUE, h);
  vfs_node_unref(v, c);
  sd_mutex_unlock(&v->lock);
  *is_dir = mkdir_;
out:
  if (f)
    sd_sftp_file_release(f);
  sd_free(raw);
  sd_free(path);
  sd_free(disp_name);
  return st;
}

sd_vfs_status sd_vfs_create(sd_vfs *v, const WCHAR *path, const sd_vfs_caller *caller, UINT32 access,
                            UINT32 share, UINT32 disposition, UINT32 create_options, UINT32 win_attrs,
                            sd_vfs_handle **h, BOOL *existed, BOOL *is_dir)
{
  BOOL ro, ex = FALSE, dir = FALSE;
  vfs_node *n = NULL, *parent = NULL;
  WCHAR *leaf = NULL;
  sd_vfs_status st;
  int64_t max_age;
  uint64_t dl;
  if (h) *h = NULL;
  if (existed) *existed = FALSE;
  if (is_dir) *is_dir = FALSE;
  if (!v || !path || !h)
    return SD_VFS_E_INVALID_NAME;
  if (disposition > SD_VFS_FILE_OVERWRITE_IF)
    return SD_VFS_E_UNSUPPORTED;
  if (InterlockedCompareExchange(&v->quiescing, 0, 0))
    return SD_VFS_E_DISCONNECTED;
  enter(v);
  ro = v->read_only || (caller && !caller->can_write);
  access = map_generic(access, ro);
  dl = vfs_deadline(v);
  max_age = (access & (ACC_DATA_READ | ACC_DATA_WRITE)) && v->revalidate >= 0 ? v->revalidate : (int64_t)v->attr_ttl;
  st = vfs_resolve(v, path, dl, max_age, &n, &parent, &leaf);
  if (st == SD_VFS_OK)
    st = open_existing(v, n, access, share, disposition, create_options, ro, dl, h, &ex, &dir);
  else if (st == SD_VFS_E_NOT_FOUND && parent)
    st = create_new(v, parent, leaf, access, share, disposition, create_options, win_attrs, ro, dl, h, &dir);
  sd_mutex_lock(&v->lock);
  if (n) vfs_node_unref(v, n);
  if (parent) vfs_node_unref(v, parent);
  sd_mutex_unlock(&v->lock);
  sd_free(leaf);
  if (st == SD_VFS_OK) {
    if (existed) *existed = ex;
    if (is_dir) *is_dir = dir;
  }
  leave(v);
  return st;
}

/* ---- cleanup / close ---- */

static void apply_times(sd_vfs *v, vfs_node *n, BOOL pa, int64_t at, BOOL pm, int64_t mt, uint64_t dl)
{
  sd_sftp_attrs a;
  char *path;
  sd_err e;
  memset(&a, 0, sizeof(a));
  sd_mutex_lock(&v->lock);
  a.valid = SD_SFTP_ATTR_TIMES;              /* ACMODTIME needs both: fill the other from the cache */
  a.atime = pa ? at : n->attr.atime;
  a.mtime = pm ? mt : n->attr.mtime;
  path = vfs_strndup(n->epath, strlen(n->epath));
  sd_mutex_unlock(&v->lock);
  if (!path)
    return;
  e = vr_setstat(v, path, &a, dl);
  sd_free(path);
  sd_mutex_lock(&v->lock);
  if (e == SD_OK) {
    n->attr.atime = a.atime;
    n->attr.mtime = a.mtime;
    vfs_listing_sync(v, n);
  } else {
    SD_LOGW(VFS_LOG, "deferred time update failed: %s", sd_err_name(e));
  }
  sd_mutex_unlock(&v->lock);
}

sd_vfs_status sd_vfs_cleanup(sd_vfs_handle *h, BOOL delete_pending)
{
  sd_vfs *v;
  vfs_node *n;
  BOOL do_delete, times, pa, pm, is_link, dir;
  int64_t at, mt;
  sd_vfs_status st = SD_VFS_OK;
  uint64_t dl;
  if (!h)
    return SD_VFS_OK;
  v = h->v;
  n = h->node;
  enter(v);
  dl = vfs_deadline(v);
  sd_mutex_lock(&v->lock);
  if (h->cleaned) {
    sd_mutex_unlock(&v->lock);
    leave(v);
    return SD_VFS_OK;
  }
  h->cleaned = TRUE;
  if (h->share_counted) {
    share_release(n, h->access, h->share);
    h->share_counted = FALSE;
  }
  if (delete_pending || h->delete_on_close)
    n->flags |= VFS_NF_DELETE_PENDING;
  n->uncleaned--;
  do_delete = (n->flags & VFS_NF_DELETE_PENDING) && n->uncleaned == 0 && (n->flags & VFS_NF_IN_TABLE);
  times = h->times_pending;
  pa = h->pend_a; pm = h->pend_m; at = h->pend_atime; mt = h->pend_mtime;
  h->times_pending = FALSE;
  is_link = (n->eflags & VFS_EF_LINK) != 0;
  dir = vfs_node_is_dir(n);
  sd_mutex_unlock(&v->lock);

  /* Write-behind: synchronous drain; a failure raises write_failed (02 §4.4). */
  vfs_data_cleanup(h, dl);
  if (times && !do_delete && vfs_online(v)) {
    vfs_ext_drain(v, n, dl);                /* other threads' writes first (02 §3.2, §4.4) */
    apply_times(v, n, pa, at, pm, mt, dl);
  }
  if (do_delete) {
    char *path;
    sd_err e = SD_E_DISCONNECTED;
    vfs_ext_drain(v, n, dl);
    sd_mutex_lock(&v->lock);
    path = vfs_strndup(n->lpath, strlen(n->lpath));   /* delete acts on the link itself */
    sd_mutex_unlock(&v->lock);
    if (path && vfs_online(v))
      e = (dir && !is_link) ? vr_rmdir(v, path, dl) : vr_remove(v, path, dl);
    sd_free(path);
    sd_mutex_lock(&v->lock);
    if (e == SD_OK || e == SD_E_NOT_FOUND) {
      vfs_node *p = vfs_parent_of(v, n);
      vfs_listing_del(v, p, n->wname);
      if (n->flags & VFS_NF_IN_TABLE)
        vfs_make_negative(v, n);
      sd_mutex_unlock(&v->lock);
    } else {
      sd_vfs_event ev;
      WCHAR *nm;
      n->flags &= ~VFS_NF_DELETE_PENDING;
      nm = vfs_wcsdup(n->wname);
      sd_mutex_unlock(&v->lock);
      st = vfs_map_err(e);
      SD_LOGW(VFS_LOG, "delete at cleanup failed: %s", sd_err_name(e));
      memset(&ev, 0, sizeof(ev));
      ev.kind = SD_VFS_EV_DELETE_FAILED;
      ev.path = nm;
      ev.status = st;
      vfs_event(v, &ev);                    /* Cleanup is void on Dokany: the host notifies (02 §2.4) */
      sd_free(nm);
    }
  }
  leave(v);
  return st;
}

void sd_vfs_close(sd_vfs_handle *h)
{
  sd_vfs *v;
  vfs_node *n;
  sd_sftp_file *f = NULL;
  struct vfs_dc *dc = NULL;
  if (!h)
    return;
  v = h->v;
  if (!h->cleaned)
    sd_vfs_cleanup(h, FALSE);
  n = h->node;
  sd_mutex_lock(&v->lock);
  if (h->prev) h->prev->next = h->next; else v->handles = h->next;
  if (h->next) h->next->prev = h->prev;
  if (--n->open_count == 0) {
    dc = vfs_data_last_close(v, n);
    if (n->fh && !n->wq_head) {
      f = n->fh;                            /* closed when the last local handle goes (02 §2.1); */
      n->fh = NULL;                         /* kept while write-behind data waits for a retransmit */
      n->fh_write = FALSE;
    }
  }
  vfs_node_unref(v, n);
  sd_mutex_unlock(&v->lock);
  if (f)
    sd_sftp_file_release(f);                /* CLOSE in the background */
  if (dc)
    vfs_dc_close(v, dc);
  sd_free(h);
}

/* ---- attributes ---- */

static void refresh_node(sd_vfs *v, vfs_node *n, uint64_t dl)
{
  sd_sftp_attrs sa;
  char *path;
  BOOL root, stale;
  sd_err e;
  sd_mutex_lock(&v->lock);
  root = (n->flags & VFS_NF_ROOT) != 0;
  stale = (n->flags & VFS_NF_IN_TABLE) && n->nwext == 0 && !n->wq_head && sd_tick_ms() - n->attr_time > v->attr_ttl &&
          !(n->eflags & VFS_EF_LINK_BAD);
  path = stale ? vfs_strndup(n->epath, strlen(n->epath)) : NULL;
  sd_mutex_unlock(&v->lock);
  if (!path)
    return;
  if (vfs_online(v)) {
    /* epath is the object itself or a link target already checked against the root. */
    e = (root || n->epath != n->lpath) ? vr_stat(v, path, dl, &sa) : vr_lstat(v, path, dl, &sa);
    if (e == SD_OK && !SD_SFTP_IS_LNK(&sa)) {
      sd_mutex_lock(&v->lock);
      if (n->nwext == 0 && !n->wq_head) {
        vfs_attr na;
        vfs_attr_from_sftp(&na, &sa);
        if (!(na.valid & SD_SFTP_ATTR_PERM)) {
          na.mode = VFS_S_IFREG | 0644u;
          na.valid |= SD_SFTP_ATTR_PERM;
        }
        vfs_node_set_attr(v, n, &na);       /* a changed validator drops the cached blocks */
        n->attr_time = sd_tick_ms();
        vfs_listing_sync(v, n);
      }
      sd_mutex_unlock(&v->lock);
    }
  }
  sd_free(path);
}

sd_vfs_status sd_vfs_getattr(sd_vfs_handle *h, sd_vfs_info *out)
{
  sd_vfs *v;
  if (!h || !out)
    return SD_VFS_E_INVALID_NAME;
  v = h->v;
  enter(v);
  refresh_node(v, h->node, vfs_deadline(v));
  sd_mutex_lock(&v->lock);
  vfs_info_from(v, h->node, h->node->wname, &h->node->attr, h->node->eflags, out);
  sd_mutex_unlock(&v->lock);
  leave(v);
  return SD_VFS_OK;
}

sd_vfs_status sd_vfs_stat_path(sd_vfs *v, const WCHAR *path, sd_vfs_info *out)
{
  vfs_node *n = NULL;
  sd_vfs_status st;
  if (!v || !path || !out)
    return SD_VFS_E_INVALID_NAME;
  enter(v);
  st = vfs_resolve(v, path, vfs_deadline(v), (int64_t)v->attr_ttl, &n, NULL, NULL);
  if (st == SD_VFS_OK) {
    sd_mutex_lock(&v->lock);
    vfs_info_from(v, n, n->wname, &n->attr, n->eflags, out);
    vfs_node_unref(v, n);
    sd_mutex_unlock(&v->lock);
  }
  leave(v);
  return st;
}

sd_vfs_status sd_vfs_set_winattrs(sd_vfs_handle *h, UINT32 attrs)
{
  sd_vfs *v;
  vfs_node *n;
  BOOL want_ro, cur_ro;
  sd_sftp_attrs a;
  char *path;
  sd_err e;
  if (!h)
    return SD_VFS_E_INVALID_NAME;
  v = h->v;
  n = h->node;
  if (attrs == 0)
    return SD_VFS_OK;                       /* NT: 0 = leave unchanged */
  if (v->read_only || !h->can_write)
    return SD_VFS_E_READ_ONLY;
  if (h->is_dir)
    return SD_VFS_OK;                       /* READONLY on directories means "customized folder": ignored */
  want_ro = (attrs & FILE_ATTRIBUTE_READONLY) != 0;
  sd_mutex_lock(&v->lock);
  cur_ro = !vfs_writable_by_us(v, &n->attr);
  memset(&a, 0, sizeof(a));
  a.valid = SD_SFTP_ATTR_PERM;
  a.perm = n->attr.mode & 07777u;
  if (want_ro)
    a.perm &= ~0222u;
  else
    a.perm |= 0200u | ((v->umask & 0020u) ? 0 : 0020u);
  path = (want_ro != cur_ro && (n->attr.valid & SD_SFTP_ATTR_PERM)) ? vfs_strndup(n->epath, strlen(n->epath)) : NULL;
  sd_mutex_unlock(&v->lock);
  if (!path)
    return SD_VFS_OK;                       /* HIDDEN, SYSTEM, ARCHIVE...: accepted and ignored (02 §3.1) */
  if (!vfs_online(v)) {
    sd_free(path);
    return SD_VFS_E_DISCONNECTED;
  }
  enter(v);
  e = vr_setstat(v, path, &a, vfs_deadline(v));
  sd_free(path);
  if (e == SD_OK) {
    sd_mutex_lock(&v->lock);
    n->attr.mode = (n->attr.mode & ~07777u) | a.perm;
    vfs_listing_sync(v, n);
    sd_mutex_unlock(&v->lock);
  }
  leave(v);
  return vfs_map_err(e);
}

static BOOL ft_to_unix(const FILETIME *f, int64_t *out)
{
  uint64_t t;
  int64_t u;
  if (!f)
    return FALSE;
  t = ((uint64_t)f->dwHighDateTime << 32) | f->dwLowDateTime;
  if (t == 0 || t == UINT64_MAX || (f->dwHighDateTime == 0xFFFFFFFFu && f->dwLowDateTime == 0xFFFFFFFEu))
    return FALSE;                           /* 0 / -1 / -2: "do not change" */
  u = sd_filetime_to_unix(t);
  if (u < 0) u = 0;                         /* SFTP v3: 32-bit unsigned seconds (02 §3.2) */
  if (u > 0xFFFFFFFFll) u = 0xFFFFFFFFll;
  *out = u;
  return TRUE;
}

sd_vfs_status sd_vfs_set_times(sd_vfs_handle *h, const FILETIME *c, const FILETIME *a, const FILETIME *w)
{
  sd_vfs *v;
  vfs_node *n;
  int64_t at = 0, mt = 0;
  BOOL pa, pm, defer;
  SD_UNUSED(c);                             /* creation time: accepted and ignored */
  if (!h)
    return SD_VFS_E_INVALID_NAME;
  v = h->v;
  n = h->node;
  pa = ft_to_unix(a, &at);
  pm = ft_to_unix(w, &mt);
  if (!pa && !pm)
    return SD_VFS_OK;
  if (v->read_only || !h->can_write)
    return SD_VFS_E_READ_ONLY;
  sd_mutex_lock(&v->lock);
  /* Deferred to cleanup on handles that write: later (paging) writes would bump the mtime again. */
  defer = (h->access & ACC_DATA_WRITE) != 0 && !h->is_dir;
  if (defer) {
    if (pa) { h->pend_a = TRUE; h->pend_atime = at; n->attr.atime = at; }
    if (pm) { h->pend_m = TRUE; h->pend_mtime = mt; n->attr.mtime = mt; }
    h->times_pending = TRUE;
    vfs_listing_sync(v, n);
  }
  sd_mutex_unlock(&v->lock);
  if (defer)
    return SD_VFS_OK;
  if (!vfs_online(v))
    return SD_VFS_E_DISCONNECTED;
  enter(v);
  apply_times(v, n, pa, at, pm, mt, vfs_deadline(v));
  leave(v);
  return SD_VFS_OK;
}

/* ---- listing ---- */

typedef struct snap_ent { WCHAR *name; sd_vfs_info info; } snap_ent;

sd_vfs_status sd_vfs_readdir(sd_vfs_handle *h, sd_vfs_dirent_cb cb, void *ctx)
{
  sd_vfs *v;
  vfs_node *n;
  sd_vfs_status st;
  snap_ent *snap = NULL;
  uint32_t i, cnt = 0;
  if (!h || !cb)
    return SD_VFS_E_INVALID_NAME;
  v = h->v;
  n = h->node;
  if (!h->is_dir)
    return SD_VFS_E_NOT_DIR;
  enter(v);
  st = vfs_listing_get(v, n, vfs_deadline(v), FALSE);
  if (st == SD_VFS_OK) {
    sd_mutex_lock(&v->lock);
    if (n->list) {
      cnt = n->list->n;
      snap = (snap_ent *)sd_calloc(cnt ? cnt : 1, sizeof(*snap));
      if (!snap) {
        st = SD_VFS_E_NO_MEMORY;
        cnt = 0;
      }
      for (i = 0; i < cnt; i++) {
        const vfs_dirent *e = &n->list->e[i];
        WCHAR *ck = vfs_key_join(n->key, e->key);
        vfs_node *c = ck ? vfs_table_find(v, ck) : NULL;
        sd_free(ck);
        snap[i].name = vfs_wcsdup(e->wname);
        /* A cached child with writes or a fresher stat knows better than the listing. */
        if (c && !(c->flags & VFS_NF_NEG) && c->attr_time >= n->list->time)
          vfs_info_from(v, c, e->wname, &c->attr, c->eflags, &snap[i].info);
        else
          vfs_info_from(v, c && !(c->flags & VFS_NF_NEG) ? c : NULL, e->wname, &e->attr, e->eflags, &snap[i].info);
      }
    }
    sd_mutex_unlock(&v->lock);
  }
  /* Snapshot: the callback runs without any vfs lock. */
  for (i = 0; i < cnt; i++) {
    if (snap[i].name && !cb(ctx, snap[i].name, &snap[i].info))
      break;
  }
  for (i = 0; i < cnt; i++)
    sd_free(snap[i].name);
  sd_free(snap);
  leave(v);
  return st;
}

/* ---- delete (02 §2.4) ---- */

sd_vfs_status sd_vfs_can_delete(sd_vfs_handle *h)
{
  sd_vfs *v;
  vfs_node *n;
  sd_vfs_status st = SD_VFS_OK;
  BOOL dir;
  if (!h)
    return SD_VFS_E_INVALID_NAME;
  v = h->v;
  n = h->node;
  if (v->read_only || !h->can_write)
    return SD_VFS_E_READ_ONLY;
  sd_mutex_lock(&v->lock);
  if (n->flags & VFS_NF_ROOT) st = SD_VFS_E_ACCESS_DENIED;
  else if (node_readonly_attr(v, n)) st = SD_VFS_E_CANNOT_DELETE;
  dir = vfs_node_is_dir(n) && !(n->eflags & VFS_EF_LINK);
  sd_mutex_unlock(&v->lock);
  if (st != SD_VFS_OK || !dir)
    return st;
  enter(v);
  st = vfs_listing_get(v, n, vfs_deadline(v), TRUE);   /* emptiness against a fresh listing */
  if (st == SD_VFS_OK) {
    sd_mutex_lock(&v->lock);
    if (n->list && n->list->n > 0)
      st = SD_VFS_E_NOT_EMPTY;
    sd_mutex_unlock(&v->lock);
  }
  leave(v);
  return st;
}

typedef struct del_ctx { WCHAR **names; uint32_t n, cap; BOOL oom; } del_ctx;

static BOOL collect_name(void *ctx, const WCHAR *name, const sd_vfs_info *info)
{
  del_ctx *d = (del_ctx *)ctx;
  SD_UNUSED(info);
  if (d->n == d->cap) {
    uint32_t cap = d->cap ? d->cap * 2 : 32;
    WCHAR **nn = (WCHAR **)sd_realloc(d->names, (size_t)cap * sizeof(WCHAR *));
    if (!nn) { d->oom = TRUE; return FALSE; }
    d->names = nn;
    d->cap = cap;
  }
  d->names[d->n] = vfs_wcsdup(name);
  if (!d->names[d->n]) { d->oom = TRUE; return FALSE; }
  d->n++;
  return TRUE;
}

static WCHAR *path_join_w(const WCHAR *a, const WCHAR *b)
{
  size_t la = wcslen(a), lb = wcslen(b);
  BOOL sep = !(la > 0 && a[la - 1] == L'\\');
  WCHAR *r = (WCHAR *)sd_alloc((la + lb + 2) * sizeof(WCHAR));
  if (r) {
    memcpy(r, a, la * sizeof(WCHAR));
    if (sep) r[la++] = L'\\';
    memcpy(r + la, b, (lb + 1) * sizeof(WCHAR));
  }
  return r;
}

sd_vfs_status sd_vfs_delete_path(sd_vfs *v, const sd_vfs_caller *c, const WCHAR *path, BOOL recursive)
{
  sd_vfs_handle *h = NULL;
  BOOL existed, is_dir;
  sd_vfs_status st;
  st = sd_vfs_create(v, path, c, DELETE | FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                     SD_VFS_FILE_OPEN, 0, 0, &h, &existed, &is_dir);
  if (st != SD_VFS_OK)
    return st;
  if (is_dir && recursive && !(h->node->eflags & VFS_EF_LINK)) {
    del_ctx d;
    uint32_t i;
    memset(&d, 0, sizeof(d));
    st = sd_vfs_readdir(h, collect_name, &d);
    if (d.oom) st = SD_VFS_E_NO_MEMORY;
    for (i = 0; i < d.n; i++) {
      if (st == SD_VFS_OK) {
        WCHAR *cp = path_join_w(path, d.names[i]);
        st = cp ? sd_vfs_delete_path(v, c, cp, TRUE) : SD_VFS_E_NO_MEMORY;
        sd_free(cp);
      }
      sd_free(d.names[i]);
    }
    sd_free(d.names);
  }
  if (st == SD_VFS_OK)
    st = sd_vfs_can_delete(h);
  if (st == SD_VFS_OK)
    st = sd_vfs_cleanup(h, TRUE);
  sd_vfs_close(h);
  return st;
}

/* ---- rename (02 §2.5) ---- */

static BOOL key_has_prefix(const WCHAR *key, const WCHAR *prefix, size_t pl)
{
  return wcsncmp(key, prefix, pl) == 0 && (key[pl] == 0 || key[pl] == L'\\');
}

static char *replace_prefix(const char *s, size_t ol, const char *neu)
{
  size_t nl = strlen(neu), sl = strlen(s);
  char *r = (char *)sd_alloc(nl + (sl - ol) + 1);
  if (r) {
    memcpy(r, neu, nl);
    memcpy(r + nl, s + ol, sl - ol + 1);
  }
  return r;
}

static BOOL path_has_prefix(const char *s, const char *p, size_t pl)
{
  return strncmp(s, p, pl) == 0 && (s[pl] == 0 || s[pl] == '/');
}

/* v->lock held: moves src (and its cached subtree) to new_key / new remote path. */
static void move_subtree(sd_vfs *v, vfs_node *src, const WCHAR *new_key, const char *new_lpath)
{
  WCHAR *old_key = vfs_wcsdup(src->key);
  char *old_epath = vfs_strndup(src->epath, strlen(src->epath));
  BOOL src_resolved_link = src->epath != src->lpath;
  size_t okl;
  vfs_node **list = NULL;
  uint32_t cnt = 0, cap = 0, i;
  if (!old_key || !old_epath) {
    sd_free(old_key);
    sd_free(old_epath);
    return;
  }
  okl = wcslen(old_key);
  for (i = 0; i < v->nodes.nb; i++) {
    vfs_node *n;
    for (n = v->nodes.b[i]; n; n = n->hnext) {
      if (!key_has_prefix(n->key, old_key, okl))
        continue;
      if (cnt == cap) {
        uint32_t nc = cap ? cap * 2 : 16;
        vfs_node **nl2 = (vfs_node **)sd_realloc(list, (size_t)nc * sizeof(*nl2));
        if (!nl2) break;
        list = nl2;
        cap = nc;
      }
      list[cnt++] = n;
    }
  }
  for (i = 0; i < cnt; i++) {
    vfs_node *n = list[i];
    size_t nkl = wcslen(new_key), rest = wcslen(n->key) - okl;
    WCHAR *nk;
    if (n->flags & VFS_NF_NEG) {
      vfs_table_remove(v, n);
      continue;
    }
    nk = (WCHAR *)sd_alloc((nkl + rest + 1) * sizeof(WCHAR));
    if (!nk) {
      vfs_table_remove(v, n);               /* forget it rather than keep a wrong key */
      continue;
    }
    memcpy(nk, new_key, nkl * sizeof(WCHAR));
    memcpy(nk + nkl, n->key + okl, (rest + 1) * sizeof(WCHAR));
    vfs_node_ref(v, n);
    vfs_table_remove(v, n);
    sd_free(n->key);
    n->key = nk;
    if (n == src) {
      char *lp = vfs_strndup(new_lpath, strlen(new_lpath));
      if (lp) {
        if (n->epath == n->lpath) n->epath = lp;
        sd_free(n->lpath);
        n->lpath = lp;
      }
    } else if (!src_resolved_link) {
      /* Descendants were built from the source's path: rebase both paths. */
      size_t ol = strlen(old_epath);
      if (path_has_prefix(n->lpath, old_epath, ol)) {
        BOOL same = n->epath == n->lpath;
        char *lp = replace_prefix(n->lpath, ol, new_lpath);
        if (lp) {
          sd_free(n->lpath);
          n->lpath = lp;
          if (same) n->epath = lp;
        }
      }
      if (n->epath != n->lpath && path_has_prefix(n->epath, old_epath, ol)) {
        char *ep = replace_prefix(n->epath, ol, new_lpath);
        if (ep) {
          sd_free(n->epath);
          n->epath = ep;
        }
      }
    }
    {
      vfs_node *clash = vfs_table_find(v, n->key);
      if (clash)
        vfs_table_remove(v, clash);
    }
    /* table_insert is static in vfs_core.c; re-adding goes through vfs_table_readd. */
    vfs_table_readd(v, n);
    vfs_node_unref(v, n);
  }
  sd_free(list);
  sd_free(old_key);
  sd_free(old_epath);
}

static sd_vfs_status split_parent(const WCHAR *path, WCHAR **parent, WCHAR **leaf)
{
  size_t len = wcslen(path);
  const WCHAR *sl;
  while (len > 1 && path[len - 1] == L'\\') len--;
  sl = path + len;
  while (sl > path && sl[-1] != L'\\') sl--;
  if (sl == path + len)
    return SD_VFS_E_INVALID_NAME;
  *parent = vfs_wcsndup(path, (size_t)(sl - path));
  *leaf = vfs_wcsndup(sl, (size_t)(path + len - sl));
  if (!*parent || !*leaf) {
    sd_free(*parent);
    sd_free(*leaf);
    return SD_VFS_E_NO_MEMORY;
  }
  return SD_VFS_OK;
}

sd_vfs_status sd_vfs_rename(sd_vfs_handle *h, const WCHAR *new_path, BOOL replace)
{
  sd_vfs *v;
  vfs_node *src, *tparent = NULL, *tnode = NULL, *dummy_parent = NULL;
  WCHAR *ppath = NULL, *leaf = NULL, *disp_name = NULL, *fk = NULL, *new_key = NULL, *dleaf = NULL;
  char *raw = NULL, *newpath = NULL, *from = NULL;
  uint32_t raw_len = 0;
  sd_vfs_status st;
  sd_err e = SD_OK;
  uint64_t dl;
  BOOL same;
  if (!h || !new_path)
    return SD_VFS_E_INVALID_NAME;
  v = h->v;
  src = h->node;
  if (!src)
    return SD_VFS_E_INVALID_NAME;
  if (v->read_only || !h->can_write)
    return SD_VFS_E_READ_ONLY;
  if (src->flags & VFS_NF_ROOT)
    return SD_VFS_E_ACCESS_DENIED;
  if (!vfs_online(v))
    return SD_VFS_E_DISCONNECTED;
  enter(v);
  dl = vfs_deadline(v);
  st = split_parent(new_path, &ppath, &leaf);
  if (st == SD_VFS_OK)
    st = vfs_name_check_input(leaf, (uint32_t)wcslen(leaf));
  if (st == SD_VFS_OK) {
    st = vfs_resolve(v, ppath, dl, (int64_t)v->attr_ttl, &tparent, NULL, NULL);
    if (st == SD_VFS_E_NOT_FOUND) st = SD_VFS_E_PATH_NOT_FOUND;
    if (st == SD_VFS_OK && !vfs_node_is_dir(tparent)) st = SD_VFS_E_PATH_NOT_FOUND;
  }
  if (st == SD_VFS_OK) {
    st = vfs_resolve(v, new_path, dl, 0, &tnode, &dummy_parent, &dleaf);
    if (st == SD_VFS_E_NOT_FOUND) st = SD_VFS_OK;
  }
  if (st == SD_VFS_OK)
    st = vfs_name_from_display(leaf, (uint32_t)wcslen(leaf), &raw, &raw_len);
  if (st == SD_VFS_OK)
    st = vfs_name_to_display(raw, raw_len, &disp_name, NULL);
  if (st == SD_VFS_OK)
    st = vfs_join_under(v, tparent, raw, raw_len, &newpath);
  if (st != SD_VFS_OK)
    goto out;
  if (!newpath || !disp_name) {
    st = SD_VFS_E_NO_MEMORY;
    goto out;
  }

  sd_mutex_lock(&v->lock);
  same = (tnode == src);
  if (tnode && !same) {
    if (!replace) st = SD_VFS_E_EXISTS;
    else if (vfs_node_is_dir(tnode) && !(tnode->eflags & VFS_EF_LINK)) st = SD_VFS_E_ACCESS_DENIED;
    else if (tnode->sh_open > 0 && tnode->sh_sdelete < tnode->sh_open) st = SD_VFS_E_ACCESS_DENIED;
  }
  from = vfs_strndup(src->lpath, strlen(src->lpath));
  sd_mutex_unlock(&v->lock);
  if (st != SD_VFS_OK)
    goto out;
  if (!from) {
    st = SD_VFS_E_NO_MEMORY;
    goto out;
  }

  if (same && strcmp(from, newpath) == 0) {
    e = SD_OK;                              /* rename onto itself */
  } else if (same && v->remote_insensitive) {
    /* Case-only rename on a case-insensitive remote: through a temporary name (02 §2.5). */
    char tmpname[96], *tmp = NULL;
    _snprintf_s(tmpname, sizeof(tmpname), _TRUNCATE, ".%.40s.sd-%08lx%08lx", raw, (unsigned long)sd_tick_ms(),
                (unsigned long)GetCurrentThreadId());
    {
      size_t i;
      for (i = 0; tmpname[i]; i++)
        if (tmpname[i] == '/') tmpname[i] = '_';
    }
    if (vfs_join_under(v, tparent, tmpname, (uint32_t)strlen(tmpname), &tmp) != SD_VFS_OK) {
      st = SD_VFS_E_NO_MEMORY;
      goto out;
    }
    e = vr_rename(v, from, tmp, 0, dl);
    if (e == SD_OK) {
      e = vr_rename(v, tmp, newpath, 0, dl);
      if (e != SD_OK)
        vr_rename(v, tmp, from, 0, dl);     /* best effort back */
    }
    sd_free(tmp);
  } else if (tnode && !same) {
    if (sd_sftp_has_ext(v->s, SD_SFTP_EXT_POSIX_RENAME)) {
      e = vr_rename(v, from, newpath, SD_SFTP_RENAME_OVERWRITE, dl);
    } else {
      if (InterlockedCompareExchange(&v->notice_rename_fallback, 1, 0) == 0)
        SD_LOGW(VFS_LOG, "server lacks posix-rename: replacing rename is remove + rename (not atomic)");
      e = vr_remove(v, newpath, dl);
      if (e == SD_OK || e == SD_E_NOT_FOUND)
        e = vr_rename(v, from, newpath, 0, dl);
    }
    if (e == SD_E_NOT_EMPTY || e == SD_E_EXISTS || e == SD_E_IS_A_DIRECTORY)
      e = SD_E_ACCESS_DENIED;               /* NTFS answer for a directory target */
  } else {
    e = vr_rename(v, from, newpath, 0, dl);
  }
  if (e != SD_OK) {
    st = vfs_map_err(e);
    if (st == SD_VFS_E_NOT_FOUND) st = SD_VFS_E_PATH_NOT_FOUND;
    goto out;
  }

  sd_mutex_lock(&v->lock);
  {
    vfs_node *op = vfs_parent_of(v, src);
    fk = v->case_view_sensitive ? vfs_wcsdup(disp_name) : vfs_fold(disp_name, (uint32_t)wcslen(disp_name));
    new_key = fk ? vfs_key_join(tparent->key, fk) : NULL;
    if (tnode && !same) {
      vfs_listing_del(v, tparent, tnode->wname);
      vfs_table_remove(v, tnode);
    }
    vfs_listing_del(v, op, src->wname);
    if (new_key) {
      move_subtree(v, src, new_key, newpath);
      sd_free(src->wname);
      src->wname = disp_name;
      disp_name = NULL;
      sd_free(src->raw);
      src->raw = raw;
      src->raw_len = raw_len;
      raw = NULL;
      if (src->flags & VFS_NF_IN_TABLE)
        vfs_listing_add(v, tparent, src);
    } else {
      vfs_table_remove(v, src);             /* out of memory: forget the node */
    }
  }
  sd_mutex_unlock(&v->lock);

out:
  sd_mutex_lock(&v->lock);
  if (tparent) vfs_node_unref(v, tparent);
  if (tnode) vfs_node_unref(v, tnode);
  if (dummy_parent) vfs_node_unref(v, dummy_parent);
  sd_mutex_unlock(&v->lock);
  sd_free(ppath); sd_free(leaf); sd_free(dleaf); sd_free(disp_name); sd_free(fk); sd_free(new_key);
  sd_free(raw); sd_free(newpath); sd_free(from);
  leave(v);
  return st;
}

sd_vfs_status sd_vfs_rename_path(sd_vfs *v, const sd_vfs_caller *c, const WCHAR *from, const WCHAR *to,
                                 BOOL replace)
{
  sd_vfs_handle *h = NULL;
  BOOL existed, is_dir;
  sd_vfs_status st = sd_vfs_create(v, from, c, DELETE | FILE_READ_ATTRIBUTES,
                                   FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, SD_VFS_FILE_OPEN, 0, 0,
                                   &h, &existed, &is_dir);
  if (st != SD_VFS_OK)
    return st;
  st = sd_vfs_rename(h, to, replace);
  sd_vfs_cleanup(h, FALSE);
  sd_vfs_close(h);
  return st;
}

sd_vfs_status sd_vfs_copy_path(sd_vfs *v, const sd_vfs_caller *c, const WCHAR *from, const WCHAR *to,
                               BOOL replace, BOOL recursive)
{
  SD_UNUSED(v); SD_UNUSED(c); SD_UNUSED(from); SD_UNUSED(to); SD_UNUSED(replace); SD_UNUSED(recursive);
  return SD_VFS_E_UNSUPPORTED;              /* WebDAV COPY: M2 */
}

/* ---- statfs (02 §6.5) ---- */

sd_vfs_status sd_vfs_statfs_get(sd_vfs *v, sd_vfs_statfs *out)
{
  sd_sftp_statvfs s;
  BOOL fresh;
  if (!v || !out)
    return SD_VFS_E_INVALID_NAME;
  sd_mutex_lock(&v->lock);
  fresh = v->fs_time != 0 && (sd_tick_ms() - v->fs_time <= VFS_STATFS_TTL || !vfs_online(v));
  *out = v->fs;
  sd_mutex_unlock(&v->lock);
  if (fresh)
    return SD_VFS_OK;
  memset(out, 0, sizeof(*out));
  if (vfs_online(v) && sd_sftp_has_ext(v->s, SD_SFTP_EXT_STATVFS)) {
    sd_err e;
    enter(v);
    e = vr_statvfs(v, v->root_path, vfs_deadline(v), &s);
    leave(v);
    if (e == SD_OK) {
      uint64_t fr = s.frsize ? s.frsize : s.bsize;
      out->total = sd_mul_sat_u64(s.blocks, fr);   /* checked, saturating (TM-R16) */
      out->free = sd_mul_sat_u64(s.bfree, fr);
      out->avail = sd_mul_sat_u64(s.bavail, fr);
      if (out->free > out->total) out->free = out->total;
      if (out->avail > out->total) out->avail = out->total;
      out->known = TRUE;
    }
  }
  if (!out->known) {
    /* Unknown: 1 PiB free of 2 PiB, so Explorer never blocks a copy on a guess. */
    out->total = 2ull << 50;
    out->free = out->avail = 1ull << 50;
  }
  sd_mutex_lock(&v->lock);
  v->fs = *out;
  v->fs_time = sd_tick_ms();
  sd_mutex_unlock(&v->lock);
  return SD_VFS_OK;
}

/* ---- security (02 §3.3) ---- */

sd_vfs_status sd_vfs_get_sd(sd_vfs_handle *h, SECURITY_INFORMATION si, PSECURITY_DESCRIPTOR sd, ULONG len,
                            ULONG *needed)
{
  vfs_attr a;
  BOOL dir;
  if (!h)
    return SD_VFS_E_INVALID_NAME;
  sd_mutex_lock(&h->v->lock);
  a = h->node->attr;
  dir = vfs_node_is_dir(h->node);
  sd_mutex_unlock(&h->v->lock);
  return vfs_build_sd(h->v, &a, dir, si, sd, len, needed);
}

sd_vfs_status sd_vfs_set_sd(sd_vfs_handle *h, SECURITY_INFORMATION si, PSECURITY_DESCRIPTOR sd)
{
  SD_UNUSED(si); SD_UNUSED(sd);
  if (!h)
    return SD_VFS_E_INVALID_NAME;
  if (h->v->read_only || !h->can_write)
    return SD_VFS_E_READ_ONLY;
  /* M0: accepted without change (02 §3.3 "otherwise"); DACL -> chmod mapping is M1. */
  return SD_VFS_OK;
}

/* ---- diagnostics ---- */

void sd_vfs_get_stats(sd_vfs *v, sd_vfs_stats *out)
{
  if (!out)
    return;
  memset(out, 0, sizeof(*out));
  if (!v)
    return;
  out->bytes_rd = (UINT64)sd_atomic_load64(&v->bytes_rd);
  out->bytes_wr = (UINT64)sd_atomic_load64(&v->bytes_wr);
  out->cache_hits = (UINT64)sd_atomic_load64(&v->cache_hits);
  out->cache_misses = (UINT64)sd_atomic_load64(&v->cache_misses);
  out->write_failed = (UINT64)sd_atomic_load64(&v->write_failed);
  out->reconnects = (UINT64)sd_atomic_load64(&v->reconnects);
  out->nconn = 1;
}

UINT64 sd_vfs_write_behind_bytes(sd_vfs *v)
{
  UINT64 n = 0;
  if (!v)
    return 0;
  sd_mutex_lock(&v->lock);
  n = v->wb_bytes;
  sd_mutex_unlock(&v->lock);
  return n;
}

void sd_vfs_cache_clear(sd_vfs *v, BOOL disk_too)
{
  if (!v)
    return;
  vc_drop_mount(v->mount_id);
  if (disk_too)
    vfs_disk_clear(v);
}

void sd_vfs_refresh(sd_vfs *v, const WCHAR *subtree)
{
  vfs_path p;
  WCHAR *key = NULL;
  uint32_t i;
  size_t kl = 0;
  if (!v)
    return;
  if (subtree && vfs_path_parse(v, subtree, &p) == SD_VFS_OK) {
    size_t total = 1;
    for (i = 0; i < p.n; i++) total += wcslen(p.comp[i]) + 1;
    key = (WCHAR *)sd_calloc(total, sizeof(WCHAR));
    if (key) {
      for (i = 0; i < p.n; i++) {
        WCHAR *f = v->case_view_sensitive ? vfs_wcsdup(p.comp[i]) : vfs_fold(p.comp[i], (uint32_t)wcslen(p.comp[i]));
        wcscat_s(key, total, L"\\");
        if (f) wcscat_s(key, total, f);
        sd_free(f);
      }
      kl = wcslen(key);
    }
    vfs_path_free(&p);
  }
  sd_mutex_lock(&v->lock);
  for (i = 0; i < v->nodes.nb; i++) {
    vfs_node *n = v->nodes.b[i], *next;
    for (; n; n = next) {
      next = n->hnext;
      if (key && !key_has_prefix(n->key, key, kl))
        continue;
      if (n->flags & VFS_NF_NEG) {
        vfs_table_remove(v, n);
        continue;
      }
      n->attr_time = 0;
      if (n->list) n->list->time = 0;
    }
  }
  sd_mutex_unlock(&v->lock);
  sd_free(key);
}

void sd_vfs_get_volume(sd_vfs *v, sd_vfs_volume *out)
{
  if (!out)
    return;
  memset(out, 0, sizeof(*out));
  if (!v)
    return;
  out->label = v->label;
  out->offline_suffix = v->offline_suffix;
  out->fs_name = v->fs_name;
  out->read_only = v->read_only;
  out->case_sensitive_view = v->case_view_sensitive;
  out->allow_system = v->allow_system;
  out->owner_sid = v->owner_sid;
  out->serial = v->serial;
  out->online = vfs_online(v);
}
