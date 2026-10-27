/* sd_vfs data path (02 §4.2-§4.4, §5.2, §5.3): block cache lookups, single-flight block fetches,
 * read-ahead, write-through and write-behind, flush and truncate, lazy re-open after a reconnect
 * with the identity check, and the per-mount background timer (write-behind coalescing, grace
 * expiry, retransmission, disk-cache trim). Locking rules: vfs_internal.h. */
#include <windows.h>

#include "sd_base/sd_checked.h"
#include "sd_base/sd_mem.h"
#include "sd_platform/sd_log.h"
#include "sd_platform/sd_time.h"
#include "vfs_internal.h"

#define ACC_DATA_WRITE (FILE_WRITE_DATA | FILE_APPEND_DATA)

static void enter(sd_vfs *v) { InterlockedIncrement(&v->busy); }
static void leave(sd_vfs *v) { InterlockedDecrement(&v->busy); }

static vc_key vkey(const sd_vfs *v, const vfs_node *n, uint32_t vgen, uint64_t blk)
{
  vc_key k;
  k.mount_id = v->mount_id;
  k.file_id = n->file_id;
  k.vgen = vgen;
  k.blk = blk;
  return k;
}

static uint32_t max_read(sd_vfs *v) { return (uint32_t)InterlockedCompareExchange(&v->max_read, 0, 0); }
static uint32_t max_write(sd_vfs *v) { return (uint32_t)InterlockedCompareExchange(&v->max_write, 0, 0); }

/* ---- condition emulation ---- */

BOOL vfs_cond_wait(sd_vfs *v, vfs_node *n, uint64_t dl)
{
  vfs_waiter w, **pp;
  uint64_t now = sd_tick_ms();
  BOOL ok;
  if (now >= dl)
    return FALSE;
  w.ev = CreateEventW(NULL, TRUE, FALSE, NULL);
  if (!w.ev) {
    sd_mutex_unlock(&v->lock);              /* no event: degrade to a short poll */
    Sleep(1);
    sd_mutex_lock(&v->lock);
    return TRUE;
  }
  w.next = n->waiters;
  n->waiters = &w;
  sd_mutex_unlock(&v->lock);
  ok = WaitForSingleObject(w.ev, (DWORD)SD_MIN(dl - now, 0x7FFFFFFFu)) == WAIT_OBJECT_0;
  sd_mutex_lock(&v->lock);
  for (pp = &n->waiters; *pp; pp = &(*pp)->next) {
    if (*pp == &w) {
      *pp = w.next;
      break;
    }
  }
  CloseHandle(w.ev);
  return ok;
}

void vfs_cond_broadcast(vfs_node *n)
{
  vfs_waiter *w;
  for (w = n->waiters; w; w = w->next)
    SetEvent(w->ev);
}

/* ---- deferred work (things that must not happen under v->lock) ---- */

typedef struct wf_ev { WCHAR *path; uint64_t bytes; sd_vfs_status st; } wf_ev;
typedef struct vfs_defer {
  sd_sftp_file *files[8]; uint32_t nf;
  wf_ev ev[8]; uint32_t nev;
} vfs_defer;

static void defer_file(vfs_defer *d, sd_sftp_file *f)
{
  if (!f)
    return;
  if (d->nf < SD_COUNTOF(d->files))
    d->files[d->nf++] = f;
  else
    sd_sftp_file_release(f);                /* rare overflow: release now (no lock is held by callers then) */
}

/* v->lock held: write_failed for n, at most once per error (02 §4.4, C45). */
static void defer_write_failed(sd_vfs *v, vfs_defer *d, vfs_node *n, uint64_t bytes)
{
  if (n->wq_reported || d->nev >= SD_COUNTOF(d->ev))
    return;
  n->wq_reported = TRUE;
  d->ev[d->nev].path = vfs_node_path(v, n);
  d->ev[d->nev].bytes = bytes;
  d->ev[d->nev].st = n->wq_error != SD_VFS_OK ? n->wq_error : SD_VFS_E_IO;
  d->nev++;
}

static void defer_run(sd_vfs *v, vfs_defer *d)
{
  uint32_t i;
  for (i = 0; i < d->nf; i++)
    sd_sftp_file_release(d->files[i]);
  for (i = 0; i < d->nev; i++) {
    sd_vfs_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.kind = SD_VFS_EV_WRITE_FAILED;
    ev.path = d->ev[i].path;
    ev.bytes = d->ev[i].bytes;
    ev.status = d->ev[i].st;
    sd_atomic_inc64(&v->write_failed);
    SD_LOGW(VFS_LOG, "write-behind data lost: %llu bytes (%d)", (unsigned long long)ev.bytes, (int)ev.status);
    vfs_event(v, &ev);
    sd_free(d->ev[i].path);
  }
  memset(d, 0, sizeof(*d));
}

/* ---- generation and online state ---- */

void vfs_sync_generation(sd_vfs *v)
{
  uint32_t g = sd_sftp_session_generation(v->s);
  sd_sftp_server_info info;
  char home[1024];
  BOOL changed = FALSE;
  LONG old = InterlockedCompareExchange(&v->gen, 0, 0);
  if (g == 0 || (LONG)g == old || sd_sftp_session_state(v->s) != SD_SFTP_ST_READY)
    return;
  if (InterlockedCompareExchange(&v->gen, (LONG)g, old) != old)
    return;                                 /* another thread syncs */
  memset(&info, 0, sizeof(info));
  if (sd_sftp_session_info(v->s, &info, home, sizeof(home)) == SD_OK) {
    /* server_info may change per generation (02 §5.1): limits and identity. */
    InterlockedExchange(&v->max_read,
                        (LONG)SD_MIN(info.limits.max_read ? info.limits.max_read : 32768u, (uint64_t)VFS_BLK));
    InterlockedExchange(&v->max_write,
                        (LONG)SD_MIN(info.limits.max_write ? info.limits.max_write : 32768u, (uint64_t)VFS_BLK));
    sd_mutex_lock(&v->lock);
    if (info.identity.source == SD_SFTP_ID_EXEC) {
      changed = !v->uid_known || v->uid != info.identity.uid;
      v->uid = info.identity.uid;
      v->gid = info.identity.gid;
      v->uid_known = v->uid_definitive = TRUE;
    } else if (!v->uid_definitive && info.identity.source == SD_SFTP_ID_HOME_OWNER && info.identity.uid != 0) {
      changed = !v->uid_known || v->uid != info.identity.uid;
      v->uid = info.identity.uid;
      v->gid = info.identity.gid;
      v->uid_known = TRUE;
    }
    sd_mutex_unlock(&v->lock);
  }
  sd_atomic_inc64(&v->reconnects);
  SD_LOGI(VFS_LOG, "session generation %u: handles reopen lazily", (unsigned)g);
  {
    sd_vfs_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.kind = SD_VFS_EV_STATE;
    ev.change_kind = SD_SFTP_ST_READY;
    vfs_event(v, &ev);
    if (changed) {
      ev.kind = SD_VFS_EV_IDENTITY;
      ev.change_kind = 0;
      vfs_event(v, &ev);
    }
  }
}

BOOL vfs_wait_online(sd_vfs *v)
{
  /* Polls the session state: sd_sftp has no per-caller "ready" notification for the vfs, and this
     wait is the rare offline case (02 §5.2 offline_wait, default 3 s). */
  uint64_t end = sd_tick_ms() + v->offline_wait;
  while (!vfs_online(v)) {
    if (sd_tick_ms() >= end || InterlockedCompareExchange(&v->quiescing, 0, 0))
      return FALSE;
    Sleep(50);
  }
  vfs_sync_generation(v);
  return TRUE;
}

/* ---- validator (02 §4.2) ---- */

static void fetch_unlist(sd_vfs *v, vfs_node *n, vfs_fetch *r);

/* v->lock held */
void vfs_node_invalidate(sd_vfs *v, vfs_node *n)
{
  vfs_fetch *r, *next;
  n->vgen++;
  for (r = n->fetch; r; r = next) {
    next = r->next;
    r->poisoned = TRUE;
    fetch_unlist(v, n, r);
  }
  vc_drop_file(v->mount_id, n->file_id);
}

static void adopt_validator(sd_vfs *v, vfs_node *n, uint64_t size, int64_t mtime, BOOL keep_blocks)
{
  if (!keep_blocks)
    vfs_node_invalidate(v, n);
  n->cv_valid = TRUE;
  n->cv_size = size;
  n->cv_mtime = mtime;
  n->srv_size = size;
  n->mtime_pending = FALSE;
  if (n->dc)
    vfs_dc_set_validator(v, n->dc, n->vgen, size, mtime);
}

void vfs_node_set_attr(sd_vfs *v, vfs_node *n, const vfs_attr *a)
{
  BOOL dir = (a->mode & VFS_S_IFMT) == VFS_S_IFDIR;
  if (n->nwext > 0 || n->wq_head)
    return;                                 /* local writes in flight: our view is newer */
  if (!dir && (a->valid & SD_SFTP_ATTR_SIZE) && (a->valid & SD_SFTP_ATTR_TIMES)) {
    if (n->mtime_pending)
      adopt_validator(v, n, a->size, a->mtime, a->size == n->attr.size);   /* our writes landed */
    else if (!n->cv_valid)
      adopt_validator(v, n, a->size, a->mtime, TRUE);
    else if (a->size != n->cv_size || a->mtime != n->cv_mtime)
      adopt_validator(v, n, a->size, a->mtime, FALSE);                  /* changed on the server */
  }
  n->attr = *a;
  n->srv_size = a->size;
}

static BOOL node_hot(sd_vfs *v, const vfs_node *n)
{
  int64_t d = sd_unix_time_now() + v->skew - n->cv_mtime;
  if (n->mtime_pending || !n->cv_valid)
    return TRUE;
  return (d < 0 ? -d : d) <= VFS_HOT_WINDOW_S;
}

/* ---- single-flight block fetches ---- */

static void fetch_unref(vfs_fetch *r)
{
  if (--r->refs == 0) {
    vb_free(r->b);                          /* the buffer lives until the last completion */
    sd_free(r);
  }
}

static void fetch_unlist(sd_vfs *v, vfs_node *n, vfs_fetch *r)
{
  vfs_fetch **pp;
  SD_UNUSED(v);
  if (!r->listed)
    return;
  for (pp = &n->fetch; *pp; pp = &(*pp)->next) {
    if (*pp == r) {
      *pp = r->next;
      break;
    }
  }
  r->next = NULL;
  r->listed = FALSE;
  fetch_unref(r);                           /* the list's reference */
}

static vfs_fetch *fetch_find(vfs_node *n, uint64_t blk, uint32_t vgen)
{
  vfs_fetch *r;
  for (r = n->fetch; r; r = r->next)
    if (r->blk == blk && r->vgen == vgen)
      return r;
  return NULL;
}

static BOOL writes_overlap(const vfs_node *n, uint64_t off, uint64_t end)
{
  uint32_t i;
  const vfs_wb *e;
  for (i = 0; i < n->nwext; i++)
    if (off < n->wext[i].end && n->wext[i].off < end)
      return TRUE;
  for (e = n->wq_head; e; e = e->next)
    if (off < e->off + e->len && e->off < end)
      return TRUE;
  return FALSE;
}

/* v->lock held: a new listed fetch with its reads armed; the caller submits them unlocked. */
static vfs_fetch *fetch_new(sd_vfs *v, vfs_node *n, uint64_t blk, uint64_t dl)
{
  vfs_fetch *r = (vfs_fetch *)sd_calloc(1, sizeof(*r));
  uint32_t chunk = max_read(v), i;
  if (!r)
    return NULL;
  if (chunk == 0 || chunk > VFS_BLK) chunk = VFS_BLK;
  r->chunk = chunk;
  r->nch = (VFS_BLK + chunk - 1) / chunk;
  r->b = vb_new(r->nch);
  r->buf = r->b ? (uint8_t *)sd_alloc(VFS_BLK) : NULL;
  if (!r->buf) {
    if (r->b) vb_free(r->b);
    sd_free(r);
    return NULL;
  }
  vb_attach_buf(r->b, r->buf);
  for (i = 0; i < r->nch; i++)
    vb_opt(r->b, i, dl);                    /* armed now, so a waiter never sees an empty batch */
  r->blk = blk;
  r->vgen = n->vgen;
  r->refs = 1;
  r->listed = TRUE;
  r->poisoned = writes_overlap(n, blk << VFS_BLK_SHIFT, (blk + 1) << VFS_BLK_SHIFT);
  r->next = n->fetch;
  n->fetch = r;
  sd_atomic_inc64(&v->cache_misses);
  return r;
}

static void fetch_submit(vfs_fetch *r, sd_sftp_file *f)
{
  uint32_t i;
  uint64_t base = r->blk << VFS_BLK_SHIFT;
  for (i = 0; i < r->nch; i++) {
    uint32_t o = i * r->chunk, l = SD_MIN(r->chunk, VFS_BLK - o);
    vb_submitted(r->b, i, sd_sftp_read(f, base + o, r->buf + o, l, vb_optp(r->b, i), vb_cb_read(), vb_slot(r->b, i)));
  }
}

/* Evaluates a completed fetch, completes short reads synchronously, and inserts the block into
   both tiers unless it was poisoned. Exactly one thread processes; the others wait. */
static void fetch_process(sd_vfs *v, vfs_node *n, vfs_fetch *r, sd_sftp_file *f, uint64_t dl)
{
  uint32_t len = 0, i;
  BOOL eof = FALSE, shortread = FALSE, cache = FALSE, disk = FALSE;
  sd_err err = SD_OK;
  struct vfs_dc *dc = NULL;
  sd_mutex_lock(&v->lock);
  while (r->processing && !r->processed) {
    if (!vfs_cond_wait(v, n, dl + VFS_WAIT_GRACE_MS * 2))
      break;
  }
  if (r->processed || r->processing) {
    sd_mutex_unlock(&v->lock);
    return;
  }
  r->processing = TRUE;
  sd_mutex_unlock(&v->lock);

  vb_wait(r->b, dl);
  for (i = 0; i < r->nch; i++) {
    vfs_slot *s = vb_slot(r->b, i);
    uint32_t l = SD_MIN(r->chunk, VFS_BLK - i * r->chunk);
    if (s->err == SD_E_EOF) { eof = TRUE; break; }
    if (s->err != SD_OK) { err = s->err; break; }
    len += SD_MIN(s->bytes, l);
    if (s->bytes < l) {
      if (s->eof) eof = TRUE; else shortread = TRUE;
      break;
    }
    if (s->eof) { eof = TRUE; break; }
  }
  /* Short reads not at EOF: some servers cap the read size silently (02 §4.3). */
  while (shortread && err == SD_OK && !eof && len < VFS_BLK && f) {
    vfs_batch *b = vb_new(1);
    vfs_slot *s;
    if (!b) { err = SD_E_NO_MEMORY; break; }
    s = vb_slot(b, 0);
    vb_submitted(b, 0, sd_sftp_read(f, (r->blk << VFS_BLK_SHIFT) + len, r->buf + len, VFS_BLK - len, vb_opt(b, 0, dl),
                                    vb_cb_read(), s));
    vb_wait(b, dl);
    if (s->err == SD_E_EOF || (s->err == SD_OK && s->bytes == 0)) eof = TRUE;
    else if (s->err != SD_OK) err = s->err;
    else { len += s->bytes; if (s->eof) eof = TRUE; }
    vb_free(b);
  }
  if (shortread && !f && !eof && err == SD_OK)
    err = SD_E_DISCONNECTED;                /* cannot complete the block: not cached */

  sd_mutex_lock(&v->lock);
  if (err != SD_OK && len > 0) {
    r->err = SD_OK;                         /* partial data is still returned to the reader */
    r->len = len;
    r->eof = FALSE;
  } else {
    r->err = err;
    r->len = len;
    r->eof = eof;
  }
  if (err == SD_OK && (len == VFS_BLK || eof) && !r->poisoned && r->vgen == n->vgen) {
    BOOL hot = node_hot(v, n);
    vc_key k = vkey(v, n, r->vgen, r->blk);
    vc_put(&k, r->buf, len, eof, hot);
    cache = TRUE;
    if (!hot && n->dc) {
      dc = n->dc;
      disk = TRUE;
    }
  }
  r->processed = TRUE;
  r->processing = FALSE;
  fetch_unlist(v, n, r);
  vfs_cond_broadcast(n);
  sd_mutex_unlock(&v->lock);
  SD_UNUSED(cache);
  /* The entry stays open while the handle that reads is open (closed at the last close). */
  if (disk)
    vfs_dc_write(v, dc, r->vgen, r->blk, r->buf, len);
}

/* ---- remote handle and reopen (02 §5.3) ---- */

/* v->lock held: discards the write-behind queue of a conflicted or failed node. */
static void wb_discard(sd_vfs *v, vfs_node *n)
{
  vfs_wb *e = n->wq_head, *next;
  for (; e; e = next) {
    vc_key k;
    uint64_t b;
    next = e->next;
    n->wq_lost += e->len;
    for (b = e->off >> VFS_BLK_SHIFT; b <= (e->off + e->len - 1) >> VFS_BLK_SHIFT; b++) {
      k = vkey(v, n, n->vgen, b);
      vc_drop(&k);                          /* the data never reached the server */
    }
    if (n->dc) vfs_dc_drop_range(v, n->dc, e->off, e->off + e->len);
    if (e->b) {
      vb_attach_buf(e->b, e->data);         /* in flight: freed after the last completion */
      vb_free(e->b);
    } else {
      sd_free(e->data);
    }
    v->wb_bytes -= e->len;
    sd_free(e);
  }
  n->wq_head = n->wq_tail = NULL;
  n->wq_bytes = 0;
}

static sd_vfs_status reopen_node(sd_vfs *v, vfs_node *n, sd_sftp_file *f, uint64_t dl, vfs_defer *d)
{
  sd_sftp_attrs sa;
  sd_err e;
  vfs_attr na;
  BOOL ok, maybe, unacked;
  uint64_t hi;
  vfs_wb *w;
  sd_vfs_status st = SD_VFS_OK;
  memset(&sa, 0, sizeof(sa));
  e = vr_reopen(f, dl, &sa);
  if (e == SD_E_INVALID_PARAM)
    return SD_VFS_OK;                       /* no longer stale: the caller looks again */
  if (e != SD_OK && e != SD_E_NOT_FOUND)
    return vfs_map_err(e == SD_E_STALE_HANDLE ? SD_E_DISCONNECTED : e);
  vfs_attr_from_sftp(&na, &sa);
  sd_mutex_lock(&v->lock);
  unacked = n->wq_head != NULL;
  maybe = n->maybe_valid;
  hi = SD_MAX(n->srv_size, n->maybe_valid ? n->maybe_end : 0);
  for (w = n->wq_head; w; w = w->next) {
    if (w->maybe) {
      maybe = TRUE;
      hi = SD_MAX(hi, w->off + w->len);
    }
  }
  /* Identity check: size adjusted for our acknowledged writes; an extent that may have executed
     widens the accepted size and suspends the mtime comparison. */
  ok = e == SD_OK && (na.valid & SD_SFTP_ATTR_SIZE) &&
       (na.size == n->srv_size || (maybe && na.size >= n->srv_size && na.size <= hi)) &&
       (maybe || n->mtime_pending || !n->cv_valid || !(na.valid & SD_SFTP_ATTR_TIMES) || na.mtime == n->cv_mtime);
  if (ok) {
    if (maybe || n->mtime_pending || !n->cv_valid) {
      n->cv_valid = TRUE;
      n->cv_size = na.size;
      n->cv_mtime = na.mtime;
      n->mtime_pending = FALSE;
      n->srv_size = na.size;
      if (n->dc) vfs_dc_set_validator(v, n->dc, n->vgen, na.size, na.mtime);
    }
    n->maybe_valid = FALSE;
  } else {
    SD_LOGW(VFS_LOG, "file changed while disconnected (%s)", e == SD_OK ? "attributes differ" : "gone");
    if (unacked) {
      /* Conflicted (02 §5.3): writes discarded, handle failed, write_failed raised. */
      uint64_t lost = n->wq_bytes;
      wb_discard(v, n);
      n->wq_error = SD_VFS_E_STALE;
      defer_write_failed(v, d, n, lost);
    }
    n->maybe_valid = FALSE;
    vfs_node_invalidate(v, n);
    n->cv_valid = e == SD_OK;
    n->cv_size = na.size;
    n->cv_mtime = na.mtime;
    n->mtime_pending = FALSE;
    if (e == SD_OK) {
      n->srv_size = na.size;
      if (!(n->attr.mode & VFS_S_IFMT) || (na.valid & SD_SFTP_ATTR_PERM)) n->attr.mode = na.mode;
      n->attr.size = na.size;
      n->attr.mtime = na.mtime;
      n->attr.atime = na.atime;
      n->attr_time = sd_tick_ms();
      vfs_listing_sync(v, n);
    }
    if (n->dc) vfs_dc_set_validator(v, n->dc, n->vgen, na.size, na.mtime);
    if (e != SD_OK || unacked)
      st = SD_VFS_E_STALE;
  }
  sd_mutex_unlock(&v->lock);
  return st;
}

/* Striping decision (02 §5.6): a data handle is opened with SD_SFTP_O_STRIPED only while the pool
   has more than the primary connection (`conns`, 0 when not READY), for a file (never a directory)
   accessed sequentially, and only when the file is at least stripe_min_file (8 MiB) or a sequential
   write has reached VFS_STRIPE_MIN_WRITE (1 MiB, n->stripe_wish). Append-only handles never
   qualify: sd_vfs_write keeps them out of the sequential class and never opens a remote handle with
   SD_SFTP_O_APPEND, so it never asks for what sd_sftp refuses (01 §10.9). v->lock held. */
static uint32_t stripe_oflags(uint32_t conns, const sd_vfs *v, const vfs_node *n, BOOL need_write, BOOL seq)
{
  if (conns < 2 || !seq || vfs_node_is_dir(n))
    return 0;
  if (n->attr.size < v->stripe_min_file && !(need_write && n->stripe_wish))
    return 0;
  return SD_SFTP_O_STRIPED;
}

sd_vfs_status vfs_get_fh(sd_vfs *v, vfs_node *n, BOOL need_write, uint64_t dl, sd_sftp_file **out, BOOL seq)
{
  sd_sftp_file *f = NULL, *old = NULL;
  char *path;
  sd_err e;
  sd_sftp_server_info info;
  uint32_t conns, ofl;
  *out = NULL;
  vfs_sync_generation(v);
  conns = sd_sftp_session_info(v->s, &info, NULL, 0) == SD_OK ? info.connections : 0;
  for (;;) {
    sd_sftp_file_info fi;
    sd_mutex_lock(&v->lock);
    if (n->fh && (n->fh_write || !need_write)) {
      if (sd_sftp_file_get_info(n->fh, &fi) == SD_OK && fi.stale) {
        sd_vfs_status st;
        vfs_defer d;
        if (n->reopening) {
          BOOL ok = vfs_cond_wait(v, n, dl);
          sd_mutex_unlock(&v->lock);
          if (!ok) return SD_VFS_E_TIMEOUT;
          continue;
        }
        if (!vfs_online(v)) {
          sd_mutex_unlock(&v->lock);
          return SD_VFS_E_DISCONNECTED;
        }
        n->reopening = TRUE;
        f = n->fh;
        sd_sftp_file_addref(f);
        sd_mutex_unlock(&v->lock);
        memset(&d, 0, sizeof(d));
        st = reopen_node(v, n, f, dl, &d);
        sd_mutex_lock(&v->lock);
        n->reopening = FALSE;
        vfs_cond_broadcast(n);
        sd_mutex_unlock(&v->lock);
        sd_sftp_file_release(f);
        f = NULL;
        defer_run(v, &d);
        if (st != SD_VFS_OK)
          return st;
        continue;
      }
      {
        /* Striping upgrade (02 §5.6): a handle opened before the node qualified is replaced by a
           striped one. In-flight requests keep the old handle (writes are serialized per extent,
           4.4); a failed open is not an error, striping is only an optimization. */
        uint32_t want = stripe_oflags(conns, v, n, need_write, seq);
        if (want && !(fi.oflags & SD_SFTP_O_STRIPED) && !n->reopening) {
          BOOL was_write = n->fh_write;
          sd_sftp_file *cur = n->fh;
          sd_sftp_file_addref(cur);
          path = vfs_strndup(n->epath, strlen(n->epath));
          sd_mutex_unlock(&v->lock);
          f = NULL;
          e = SD_E_DISCONNECTED;
          if (path && vfs_online(v))
            e = vr_open(v, path, SD_SFTP_O_READ | (was_write ? SD_SFTP_O_WRITE : 0) | want, NULL, dl, &f, NULL);
          sd_free(path);
          sd_mutex_lock(&v->lock);
          if (e == SD_OK && n->fh == cur) {
            n->fh = f;                        /* cur keeps its references until the last request */
            n->fh_write = was_write;
            sd_sftp_file_addref(f);
            *out = f;
            sd_mutex_unlock(&v->lock);
            sd_sftp_file_release(cur);
            return SD_VFS_OK;
          }
          sd_mutex_unlock(&v->lock);
          if (e == SD_OK)
            sd_sftp_file_release(f);          /* another thread swapped the handle meanwhile */
          sd_sftp_file_release(cur);
          sd_mutex_lock(&v->lock);
        }
      }
      sd_sftp_file_addref(n->fh);
      *out = n->fh;
      sd_mutex_unlock(&v->lock);
      return SD_VFS_OK;
    }
    path = vfs_strndup(n->epath, strlen(n->epath));
    sd_mutex_unlock(&v->lock);
    break;
  }
  if (!path)
    return SD_VFS_E_NO_MEMORY;
  if (!vfs_online(v)) {
    sd_free(path);
    return SD_VFS_E_DISCONNECTED;
  }
  sd_mutex_lock(&v->lock);
  ofl = stripe_oflags(conns, v, n, need_write, seq);
  sd_mutex_unlock(&v->lock);
  e = vr_open(v, path, SD_SFTP_O_READ | (need_write ? SD_SFTP_O_WRITE : 0) | ofl, NULL, dl, &f, NULL);
  sd_free(path);
  if (e != SD_OK)
    return vfs_map_err(e);
  sd_mutex_lock(&v->lock);
  if (n->fh && (n->fh_write || !need_write)) {
    old = f;                                /* another thread won the lazy open */
    f = n->fh;
  } else {
    old = n->fh;
    n->fh = f;
    n->fh_write = need_write;
  }
  sd_sftp_file_addref(f);
  sd_mutex_unlock(&v->lock);
  if (old)
    sd_sftp_file_release(old);
  *out = f;
  return SD_VFS_OK;
}

/* ---- read (02 §4.2, §4.3) ---- */

void vfs_handle_init_ra(sd_vfs_handle *h)
{
  sd_vfs *v = h->v;
  if (h->opts & SD_VFS_FILE_RANDOM_ACCESS) {
    h->ra_window = 0;                       /* RANDOM_ACCESS disables read-ahead */
  } else {
    h->ra_window = (h->opts & SD_VFS_FILE_SEQUENTIAL_ONLY) ? VFS_RA_SEQSCAN : VFS_RA_START;
    if (h->ra_window > v->max_readahead) h->ra_window = v->max_readahead;
  }
  h->ra_next = 0;
  h->ra_end = 0;
  h->write_through = (h->opts & SD_VFS_FILE_WRITE_THROUGH) != 0;
}

/* v->lock held: the range to read ahead after a read of [off, end), or FALSE. */
static BOOL ra_plan(sd_vfs *v, sd_vfs_handle *h, vfs_node *n, uint64_t off, uint64_t end, uint64_t *from,
                    uint64_t *to)
{
  uint64_t lim, want, start;
  uint32_t base;
  if (h->opts & SD_VFS_FILE_RANDOM_ACCESS || v->max_readahead == 0)
    return FALSE;
  base = (h->opts & SD_VFS_FILE_SEQUENTIAL_ONLY) ? VFS_RA_SEQSCAN : VFS_RA_START;
  if (base > v->max_readahead) base = v->max_readahead;
  if (off == h->ra_next && h->ra_window) {
    h->ra_window = (uint32_t)SD_MIN((uint64_t)h->ra_window * 2, (uint64_t)v->max_readahead);
  } else {
    h->ra_window = base;                    /* a random access resets the window */
    h->ra_end = 0;
  }
  h->ra_next = end;
  lim = n->attr.size;
  if (lim > UINT64_MAX - VFS_BLK)
    return FALSE;
  lim = (lim + VFS_BLK - 1) & ~(uint64_t)(VFS_BLK - 1);
  want = SD_MIN(end + h->ra_window, lim);
  start = SD_MAX(end, h->ra_end) & ~(uint64_t)(VFS_BLK - 1);
  if (want <= start)
    return FALSE;
  /* Top up only when less than half a window is left ahead, so small reads do not issue one
     block each. */
  if (h->ra_end > end && h->ra_end - end >= h->ra_window / 2 && h->ra_end < lim)
    return FALSE;
  *from = start;
  *to = want;
  h->ra_end = want;
  return TRUE;
}

/* Copies what the cache tiers have for [off+pos, off+len) into buf. Returns the new pos; *eof
   when the cached data ends the file. Promotes disk blocks into memory. */
static uint32_t read_cached(sd_vfs *v, vfs_node *n, uint32_t vgen, struct vfs_dc *dc, uint64_t off, uint8_t *buf,
                            uint32_t len, uint32_t pos, BOOL *eof, uint8_t **tmp)
{
  while (pos < len && !*eof) {
    uint64_t at = off + pos, b = at >> VFS_BLK_SHIFT;
    uint32_t rel = (uint32_t)(at & (VFS_BLK - 1)), want = SD_MIN(len - pos, VFS_BLK - rel), got = 0, blen = 0;
    int e = 0;
    vc_key k = vkey(v, n, vgen, b);
    if (vc_read(&k, rel, buf + pos, want, &got, &e, v->attr_ttl)) {
      pos += got;
      if (e) *eof = TRUE;
      sd_atomic_inc64(&v->cache_hits);
      continue;
    }
    if (!dc)
      break;
    if (!*tmp)
      *tmp = (uint8_t *)sd_alloc(VFS_BLK);
    if (!*tmp)
      break;
    if (!vfs_dc_read(v, dc, vgen, b, *tmp, &blen, &e))
      break;
    vc_put(&k, *tmp, blen, e, 0);           /* disk blocks are never hot */
    sd_atomic_inc64(&v->cache_hits);
    if (rel >= blen) {
      if (e) *eof = TRUE; else break;
      continue;
    }
    got = SD_MIN(want, blen - rel);
    memcpy(buf + pos, *tmp + rel, got);
    pos += got;
    if (got < want) {
      if (e) *eof = TRUE; else break;
    }
  }
  return pos;
}

/* v->lock held: overlays queued write-behind data onto [off, off+*pos) and extends the result to
   the local size (02 §4.4: the queue is newer than the server). */
static void wb_overlay(vfs_node *n, uint64_t off, uint8_t *buf, uint32_t len, uint32_t *pos, BOOL *eof)
{
  const vfs_wb *e;
  uint64_t end;
  if (!n->wq_head)
    return;
  if (n->attr.size > off + *pos) {
    uint32_t to = (uint32_t)SD_MIN((uint64_t)len, n->attr.size - off);
    if (to > *pos) {
      memset(buf + *pos, 0, to - *pos);     /* beyond the server's end: zeros, then the queue */
      *pos = to;
    }
    *eof = off + *pos >= n->attr.size;
  }
  end = off + *pos;
  for (e = n->wq_head; e; e = e->next) {
    uint64_t lo = SD_MAX(off, e->off), hi = SD_MIN(end, e->off + e->len);
    if (lo < hi)
      memcpy(buf + (lo - off), e->data + (lo - e->off), (size_t)(hi - lo));
  }
}

static struct vfs_dc *ensure_dc(sd_vfs *v, vfs_node *n)
{
  struct vfs_dc *dc;
  char *path;
  uint64_t size;
  int64_t mtime;
  uint32_t vgen;
  if (!vfs_disk_enabled(v))
    return NULL;
  sd_mutex_lock(&v->lock);
  dc = n->dc;
  if (dc || !n->cv_valid || n->open_count == 0) {
    sd_mutex_unlock(&v->lock);
    return dc;
  }
  path = vfs_strndup(n->epath, strlen(n->epath));
  size = n->cv_size;
  mtime = n->cv_mtime;
  vgen = n->vgen;
  sd_mutex_unlock(&v->lock);
  dc = path ? vfs_dc_open(v, path, size, mtime, vgen) : NULL;
  sd_free(path);
  if (!dc)
    return NULL;
  sd_mutex_lock(&v->lock);
  if (!n->dc && n->open_count > 0) {
    n->dc = dc;
    if (n->vgen != vgen || n->cv_size != size || n->cv_mtime != mtime)
      vfs_dc_set_validator(v, dc, n->vgen, n->cv_size, n->cv_mtime);
    dc = NULL;
  }
  sd_mutex_unlock(&v->lock);
  if (dc)
    vfs_dc_close(v, dc);                    /* lost a race */
  sd_mutex_lock(&v->lock);
  dc = n->dc;
  sd_mutex_unlock(&v->lock);
  return dc;
}

/* One pass of the slow path: finds or creates the fetches for the missing demand blocks and the
   read-ahead range, submits the new ones on f, then copies the demand range in order. Returns the
   first fetch error (SD_OK if data was copied or the range ended). */
static sd_err read_fetch(sd_vfs *v, vfs_node *n, sd_sftp_file *f, uint32_t vgen, struct vfs_dc *dc, uint64_t off,
                         uint8_t *buf, uint32_t len, uint32_t *pos, BOOL *eof, BOOL do_ra, uint64_t ra_from,
                         uint64_t ra_to, uint64_t dl, uint8_t **tmp)
{
  uint64_t end = off + len, b, b0 = (off + *pos) >> VFS_BLK_SHIFT, b1 = (end - 1) >> VFS_BLK_SHIFT;
  uint32_t ndem = 0, nra = 0, i, cap;
  vfs_fetch **dem, **ra;
  sd_err ferr = SD_OK;
  BOOL want_demand = *pos < len && !*eof;
  cap = (uint32_t)(want_demand ? b1 - b0 + 1 : 0);
  dem = (vfs_fetch **)sd_calloc((size_t)cap + 1, sizeof(*dem));
  ra = (vfs_fetch **)sd_calloc((size_t)(v->max_readahead >> VFS_BLK_SHIFT) + 2, sizeof(*ra));
  if (!dem || !ra) {
    sd_free(dem);
    sd_free(ra);
    return SD_E_NO_MEMORY;
  }
  sd_mutex_lock(&v->lock);
  for (b = b0; want_demand && b <= b1; b++) {
    vc_key k = vkey(v, n, vgen, b);
    vfs_fetch *r = NULL;
    if (!(vc_contains(&k, v->attr_ttl) || vfs_dc_has(dc, vgen, b))) {   /* cached meanwhile: copied below */
      r = fetch_find(n, b, vgen);
      if (!r && (r = fetch_new(v, n, b, dl)) != NULL)
        r->refs++;                          /* new: the list's ref + this reader's */
      else if (r)
        r = (vfs_fetch *)((ULONG_PTR)r | 1);   /* existing: tagged, nothing to submit */
    }
    dem[ndem++] = r;
  }
  if (do_ra) {
    uint64_t rlast = (ra_to - 1) >> VFS_BLK_SHIFT, maxra = (v->max_readahead >> VFS_BLK_SHIFT) + 1;
    for (b = ra_from >> VFS_BLK_SHIFT; b <= rlast && nra < maxra; b++) {
      vc_key k = vkey(v, n, vgen, b);
      vfs_fetch *r;
      if ((want_demand && b >= b0 && b <= b1) || fetch_find(n, b, vgen) || vc_contains(&k, v->attr_ttl) || vfs_dc_has(dc, vgen, b))
        continue;
      r = fetch_new(v, n, b, dl);
      if (!r)
        break;
      r->refs++;
      ra[nra++] = r;
    }
  }
  /* Every demand entry holds one reference for this reader. */
  for (i = 0; i < ndem; i++) {
    if ((ULONG_PTR)dem[i] & 1) {
      vfs_fetch *r = (vfs_fetch *)((ULONG_PTR)dem[i] & ~(ULONG_PTR)1);
      r->refs++;
    }
  }
  sd_mutex_unlock(&v->lock);

  /* Submit what this reader created (no lock held, review §4.1 rule 2). */
  for (i = 0; i < ndem; i++)
    if (dem[i] && !((ULONG_PTR)dem[i] & 1)) fetch_submit(dem[i], f);
  for (i = 0; i < nra; i++)
    fetch_submit(ra[i], f);
  sd_mutex_lock(&v->lock);
  for (i = 0; i < ndem; i++)
    dem[i] = (vfs_fetch *)((ULONG_PTR)dem[i] & ~(ULONG_PTR)1);
  for (i = 0; i < nra; i++)
    fetch_unref(ra[i]);                     /* read-ahead: only the list keeps it */
  sd_mutex_unlock(&v->lock);

  /* Copy in order, waiting for each missing block. */
  while (*pos < len && !*eof) {
    uint64_t at = off + *pos, idx = (at >> VFS_BLK_SHIFT) - b0;
    uint32_t rel = (uint32_t)(at & (VFS_BLK - 1)), want = SD_MIN(len - *pos, VFS_BLK - rel), cnt;
    vfs_fetch *r;
    BOOL done;
    if (idx >= ndem)
      break;
    r = dem[idx];
    if (!r) {
      uint32_t np = read_cached(v, n, vgen, dc, off, buf, len, *pos, eof, tmp);
      if (np == *pos && !*eof)
        break;                              /* evicted meanwhile: the caller tries again */
      *pos = np;
      continue;
    }
    fetch_process(v, n, r, f, dl);
    sd_mutex_lock(&v->lock);
    while (!r->processed && vfs_cond_wait(v, n, dl + VFS_WAIT_GRACE_MS * 2)) {}
    done = r->processed;
    sd_mutex_unlock(&v->lock);
    if (!done) { ferr = SD_E_TIMEOUT; break; }
    if (r->err != SD_OK) { ferr = r->err; break; }
    if (rel >= r->len) {
      if (r->eof) *eof = TRUE; else ferr = SD_E_FAILURE;
      break;
    }
    cnt = SD_MIN(want, r->len - rel);
    memcpy(buf + *pos, r->buf + rel, cnt);
    *pos += cnt;
    if (cnt < want) {
      if (r->eof) *eof = TRUE;
      else { ferr = SD_E_FAILURE; break; }  /* partial block: return what we have */
    }
  }
  sd_mutex_lock(&v->lock);
  for (i = 0; i < ndem; i++)
    if (dem[i]) fetch_unref(dem[i]);
  sd_mutex_unlock(&v->lock);
  sd_free(dem);
  sd_free(ra);
  return ferr;
}

sd_vfs_status sd_vfs_read(sd_vfs_handle *h, UINT64 off, void *buf, UINT32 len, UINT32 *got)
{
  sd_vfs *v;
  vfs_node *n;
  sd_sftp_file *f = NULL;
  sd_vfs_status st = SD_VFS_OK;
  uint64_t dl, end, ra_from = 0, ra_to = 0;
  uint32_t pos = 0, vgen, attempt;
  BOOL eof = FALSE, do_ra, seq;
  uint8_t *tmp = NULL;
  struct vfs_dc *dc;
  if (got) *got = 0;
  if (!h || (!buf && len))
    return SD_VFS_E_INVALID_NAME;
  v = h->v;
  n = h->node;
  if (h->is_dir)
    return SD_VFS_E_IS_DIR;
  if (n->eflags & VFS_EF_LINK_BAD)
    return SD_VFS_E_NOT_FOUND;
  if (n->eflags & VFS_EF_SPECIAL)
    return SD_VFS_E_ACCESS_DENIED;
  if (len == 0)
    return SD_VFS_OK;
  if (sd_add_ovf_u64(off, len, &end))
    return SD_VFS_E_END_OF_FILE;
  /* Sequential access (02 §5.6): SEQUENTIAL_ONLY, or a read continuing where the handle's
     read-ahead (4.3) expects the next one. RANDOM_ACCESS is never sequential. */
  seq = !(h->opts & SD_VFS_FILE_RANDOM_ACCESS) &&
        ((h->opts & SD_VFS_FILE_SEQUENTIAL_ONLY) || off == h->ra_next);
  enter(v);
  dl = vfs_deadline(v);
  dc = ensure_dc(v, n);
  {
    /* After a reconnect the first use of the node re-opens its handle, so the identity check
       (02 §5.3) runs before cached blocks are served again. While disconnected the cache is
       served as it was at the disconnect (02 §5.2). */
    sd_sftp_file_info fi;
    BOOL stale;
    sd_mutex_lock(&v->lock);
    stale = n->fh && sd_sftp_file_get_info(n->fh, &fi) == SD_OK && fi.stale;
    sd_mutex_unlock(&v->lock);
    if (stale && vfs_online(v) && vfs_get_fh(v, n, FALSE, dl, &f, seq) == SD_VFS_OK) {
      sd_sftp_file_release(f);
      f = NULL;
    }
  }
  for (attempt = 0; attempt < 3; attempt++) {
    sd_err ferr;
    sd_mutex_lock(&v->lock);
    if (n->wq_error == SD_VFS_E_STALE) {
      sd_mutex_unlock(&v->lock);
      st = SD_VFS_E_STALE;                  /* conflicted handle (02 §5.3) */
      break;
    }
    vgen = n->vgen;
    do_ra = attempt == 0 && ra_plan(v, h, n, off, end, &ra_from, &ra_to);
    sd_mutex_unlock(&v->lock);

    /* Cache first: served even while disconnected (02 §5.2). */
    pos = read_cached(v, n, vgen, dc, off, (uint8_t *)buf, len, pos, &eof, &tmp);
    if ((pos >= len || eof) && !do_ra)
      break;
    st = vfs_get_fh(v, n, FALSE, dl, &f, seq);
    if (st == SD_VFS_E_DISCONNECTED && pos < len && !eof && vfs_wait_online(v))
      st = vfs_get_fh(v, n, FALSE, dl, &f, seq);
    if (st != SD_VFS_OK) {
      if (pos >= len || eof)
        st = SD_VFS_OK;                     /* only the read-ahead could not be issued */
      break;
    }
    sd_mutex_lock(&v->lock);
    if (n->vgen != vgen) {
      /* The reopen found the file changed: what was copied came from the old content. */
      sd_mutex_unlock(&v->lock);
      sd_sftp_file_release(f);
      f = NULL;
      pos = 0;
      eof = FALSE;
      continue;
    }
    sd_mutex_unlock(&v->lock);
    ferr = read_fetch(v, n, f, vgen, dc, off, (uint8_t *)buf, len, &pos, &eof, do_ra, ra_from, ra_to, dl, &tmp);
    sd_sftp_file_release(f);
    f = NULL;
    if (ferr == SD_OK || pos > 0) {
      st = SD_VFS_OK;
      if (pos < len && !eof && ferr == SD_OK)
        continue;                           /* a block was evicted or poisoned meanwhile */
      break;
    }
    st = vfs_map_err(ferr == SD_E_STALE_HANDLE ? SD_E_DISCONNECTED : ferr);
    if ((ferr == SD_E_DISCONNECTED || ferr == SD_E_STALE_HANDLE || ferr == SD_E_BUSY) && attempt < 2) {
      if (ferr == SD_E_DISCONNECTED && !vfs_online(v) && !vfs_wait_online(v))
        break;
      continue;                             /* reopen and fetch again */
    }
    break;
  }
  if (f)
    sd_sftp_file_release(f);
  sd_free(tmp);
  if (st == SD_VFS_OK && v->write_behind) {
    sd_mutex_lock(&v->lock);
    wb_overlay(n, off, (uint8_t *)buf, len, &pos, &eof);
    sd_mutex_unlock(&v->lock);
  }
  if (st == SD_VFS_OK && pos == 0)
    st = eof ? SD_VFS_E_END_OF_FILE : SD_VFS_E_IO;
  if (got) *got = pos;
  sd_atomic_add64(&v->bytes_rd, pos);
  leave(v);
  return st;
}

/* ---- local writes into the cache (both modes, 02 §4.2) ---- */

/* v->lock held: cached blocks take the new data on submission; fetches in flight are poisoned. */
static void cache_local_write(sd_vfs *v, vfs_node *n, uint64_t off, const uint8_t *data, uint32_t len, uint64_t old_size)
{
  uint64_t end = off + len, first = off >> VFS_BLK_SHIFT, last = (end - 1) >> VFS_BLK_SHIFT, b;
  vfs_fetch *r, *next;
  for (r = n->fetch; r; r = next) {
    next = r->next;
    if (r->blk >= first && r->blk <= last) {
      r->poisoned = TRUE;
      fetch_unlist(v, n, r);
    }
  }
  for (b = first; b <= last; b++) {
    uint64_t bo = b << VFS_BLK_SHIFT, lo = SD_MAX(off, bo), hi = SD_MIN(end, bo + VFS_BLK);
    vc_key k = vkey(v, n, n->vgen, b);
    vc_write(&k, (uint32_t)(lo - bo), data + (lo - off), (uint32_t)(hi - lo));
  }
  if (off > old_size) {
    vc_key k = vkey(v, n, n->vgen, old_size >> VFS_BLK_SHIFT);
    vc_drop(&k);                            /* its end-of-file mark is wrong now */
  }
  if (n->dc) {
    vfs_dc_drop_range(v, n->dc, off, end);
    if (end > old_size)
      vfs_dc_drop_range(v, n->dc, old_size, old_size + 1);
  }
  n->mtime_pending = TRUE;
}

static void cache_drop_range(sd_vfs *v, vfs_node *n, uint64_t off, uint64_t end)
{
  uint64_t b;
  if (end <= off)
    return;
  for (b = off >> VFS_BLK_SHIFT; b <= (end - 1) >> VFS_BLK_SHIFT; b++) {
    vc_key k = vkey(v, n, n->vgen, b);
    vc_drop(&k);
  }
  if (n->dc)
    vfs_dc_drop_range(v, n->dc, off, end);
}

/* ---- write-through (02 §4.4) ---- */

static BOOL ext_overlaps(const vfs_node *n, uint64_t off, uint64_t end)
{
  uint32_t i;
  for (i = 0; i < n->nwext; i++)
    if (off < n->wext[i].end && n->wext[i].off < end)
      return TRUE;
  return FALSE;
}

/* v->lock held on entry and exit: registers [off, end) once no overlapping write is in flight. */
static sd_vfs_status ext_acquire(sd_vfs *v, vfs_node *n, uint64_t off, uint64_t end, uint64_t dl)
{
  while (ext_overlaps(n, off, end)) {
    if (!vfs_cond_wait(v, n, dl) && sd_tick_ms() >= dl)
      return SD_VFS_E_TIMEOUT;
  }
  if (n->nwext == n->capwext) {
    uint32_t cap = n->capwext ? n->capwext * 2 : 4;
    vfs_extent *ne = (vfs_extent *)sd_realloc(n->wext, (size_t)cap * sizeof(*ne));
    if (!ne)
      return SD_VFS_E_NO_MEMORY;
    n->wext = ne;
    n->capwext = cap;
  }
  n->wext[n->nwext].off = off;
  n->wext[n->nwext].end = end;
  n->nwext++;
  return SD_VFS_OK;
}

static void ext_release(vfs_node *n, uint64_t off, uint64_t end)
{
  uint32_t i;
  for (i = 0; i < n->nwext; i++) {
    if (n->wext[i].off == off && n->wext[i].end == end) {
      n->wext[i] = n->wext[--n->nwext];
      break;
    }
  }
  vfs_cond_broadcast(n);
}

sd_vfs_status vfs_ext_drain(sd_vfs *v, vfs_node *n, uint64_t dl)
{
  sd_vfs_status st = SD_VFS_OK;
  sd_mutex_lock(&v->lock);
  while (n->nwext > 0) {
    if (!vfs_cond_wait(v, n, dl) && sd_tick_ms() >= dl) {
      st = SD_VFS_E_TIMEOUT;
      break;
    }
  }
  sd_mutex_unlock(&v->lock);
  return st;
}

static sd_vfs_status wb_drain(sd_vfs *v, vfs_node *n, uint64_t dl, BOOL wait_reconnect);

static sd_vfs_status write_through(sd_vfs_handle *h, uint64_t off, const uint8_t *buf, uint32_t len, uint32_t *done,
                                   uint64_t dl, BOOL seq)
{
  sd_vfs *v = h->v;
  vfs_node *n = h->node;
  sd_sftp_file *f = NULL;
  sd_vfs_status st;
  uint64_t end = off + len, old_size;
  uint32_t pos = 0;
  BOOL maybe = FALSE;
  if (v->write_behind) {
    st = wb_drain(v, n, dl, FALSE);         /* other handles' queued data goes first */
    if (st != SD_VFS_OK)
      return st;
  }
  st = vfs_get_fh(v, n, TRUE, dl, &f, seq);
  if (st != SD_VFS_OK)
    return st;
  sd_mutex_lock(&v->lock);
  st = ext_acquire(v, n, off, end, dl);
  if (st != SD_VFS_OK) {
    sd_mutex_unlock(&v->lock);
    sd_sftp_file_release(f);
    return st;
  }
  old_size = n->attr.size;
  cache_local_write(v, n, off, buf, len, old_size);
  sd_mutex_unlock(&v->lock);

  while (st == SD_VFS_OK && pos < len) {
    uint32_t chunk = max_write(v), left = len - pos, nch, i;
    vfs_batch *b;
    BOOL fail = FALSE;
    if (chunk == 0) chunk = 32768;
    nch = SD_MIN((left + chunk - 1) / chunk, VFS_MAX_INFLIGHT);
    b = vb_new(nch);
    if (!b) {
      st = SD_VFS_E_NO_MEMORY;
      break;
    }
    for (i = 0; i < nch; i++) {
      uint32_t o = pos + i * chunk, l = SD_MIN(chunk, len - o);
      vb_submitted(b, i, sd_sftp_write(f, off + o, buf + o, l, vb_opt(b, i, dl), vb_cb_write(), vb_slot(b, i)));
    }
    vb_wait(b, dl);
    /* done = the contiguous acknowledged prefix; the first failed ack is this call's status. */
    for (i = 0; i < nch; i++) {
      uint32_t l = SD_MIN(chunk, len - pos);
      vfs_slot *s = vb_slot(b, i);
      sd_err e = s->err;
      uint32_t bytes = s->bytes;
      if (e == SD_E_DISCONNECTED && s->session_ready) {
        /* Only a secondary pool member was lost: resubmit on the same handle (02 §4.4, §5.6). */
        vfs_batch *r = vb_new(1);
        if (r) {
          vb_submitted(r, 0, sd_sftp_write(f, off + pos, buf + pos, l, vb_opt(r, 0, dl), vb_cb_write(), vb_slot(r, 0)));
          vb_wait(r, dl);
          e = vb_slot(r, 0)->err;
          bytes = vb_slot(r, 0)->bytes;
          maybe = maybe || vb_slot(r, 0)->maybe_executed;
          vb_free(r);
        }
      }
      if (e != SD_OK) {
        if (e == SD_E_DISCONNECTED || e == SD_E_TIMEOUT || e == SD_E_CANCELLED || s->maybe_executed)
          maybe = TRUE;
        st = vfs_map_err(e == SD_E_STALE_HANDLE ? SD_E_DISCONNECTED : e);
        fail = TRUE;
        break;
      }
      pos += SD_MIN(bytes, l);
      if (bytes < l)
        break;                              /* short ack: re-issue the rest */
    }
    vb_free(b);
    if (fail)
      break;
    if (pos < len && sd_tick_ms() >= dl) {
      st = SD_VFS_E_TIMEOUT;
      break;
    }
  }
  sd_sftp_file_release(f);
  sd_mutex_lock(&v->lock);
  ext_release(n, off, end);
  if (pos < len)
    cache_drop_range(v, n, off + pos, end); /* a write that fails drops the affected blocks */
  if (maybe) {
    n->maybe_valid = TRUE;                  /* identity check after reconnect (02 §5.3) */
    n->maybe_end = SD_MAX(n->maybe_end, end);
  }
  if (pos > 0) {
    if (off + pos > n->attr.size)
      n->attr.size = off + pos;
    if (off + pos > n->srv_size)
      n->srv_size = off + pos;
    n->attr.mtime = sd_unix_time_now();
    n->attr.valid |= SD_SFTP_ATTR_SIZE | SD_SFTP_ATTR_TIMES;
    n->attr_time = sd_tick_ms();
    h->wrote = TRUE;
    vfs_listing_sync(v, n);
  }
  sd_mutex_unlock(&v->lock);
  *done = pos;
  return st;
}

/* ---- write-behind (02 §4.4) ---- */

static BOOL wb_in_flight_overlap(const vfs_node *n, const vfs_wb *upto, uint64_t off, uint64_t end)
{
  const vfs_wb *e;
  for (e = n->wq_head; e && e != upto; e = e->next)
    if (off < e->off + e->len && e->off < end)
      return TRUE;                          /* an older extent covers it: wait for its ack */
  return FALSE;
}

/* v->lock held: processes completed extents. */
static void wb_reap(sd_vfs *v, vfs_node *n, vfs_defer *d)
{
  vfs_wb **pp = &n->wq_head, *e, *prev = NULL;
  while ((e = *pp) != NULL) {
    uint32_t i;
    sd_err err = SD_OK;
    BOOL maybe = FALSE, partial = FALSE;
    if (!e->b || !vb_done(e->b)) {
      prev = e;
      pp = &e->next;
      continue;
    }
    for (i = 0; i < e->nch; i++) {
      vfs_slot *s = vb_slot(e->b, i);
      uint32_t l = SD_MIN(e->chunk, e->len - i * e->chunk);
      if (s->maybe_executed) maybe = TRUE;
      if (s->err != SD_OK && err == SD_OK) err = s->err;
      if (s->err == SD_OK && s->bytes < l) partial = TRUE;
    }
    vb_free(e->b);
    e->b = NULL;
    if (err == SD_OK && !partial) {
      /* Acknowledged. */
      *pp = e->next;
      if (n->wq_tail == e) n->wq_tail = prev;
      if (e->off + e->len > n->srv_size) n->srv_size = e->off + e->len;
      n->mtime_pending = TRUE;
      n->wq_bytes -= e->len;
      v->wb_bytes -= e->len;
      sd_free(e->data);
      sd_free(e);
      continue;
    }
    if (err == SD_OK && partial) {
      e->maybe = TRUE;                      /* a short ack: send the whole extent again */
    } else if (err == SD_E_BUSY) {
      /* backpressure from sd_sftp: send again later */
    } else if (err == SD_E_DISCONNECTED || err == SD_E_TIMEOUT || err == SD_E_STALE_HANDLE || err == SD_E_SHUTDOWN ||
               err == SD_E_CANCELLED || err == SD_E_AUTH_REQUIRED) {
      e->maybe = e->maybe || maybe || err != SD_E_STALE_HANDLE;
      if (v->grace == 0) {
        if (n->wq_error == SD_VFS_OK) n->wq_error = SD_VFS_E_DISCONNECTED;
      } else if (e->retry_until == 0) {
        e->retry_until = sd_tick_ms() + v->grace;   /* grace retransmit (02 §5.3) */
      }
    } else {
      /* A server error on a write: sticky (02 §4.4). The data is lost. */
      if (n->wq_error == SD_VFS_OK) n->wq_error = vfs_map_err(err);
      SD_LOGW(VFS_LOG, "write-behind write failed: %s", sd_err_name(err));
      *pp = e->next;
      if (n->wq_tail == e) n->wq_tail = prev;
      n->wq_lost += e->len;
      cache_drop_range(v, n, e->off, e->off + e->len);
      n->wq_bytes -= e->len;
      v->wb_bytes -= e->len;
      sd_free(e->data);
      sd_free(e);
      continue;
    }
    prev = e;
    pp = &e->next;
  }
  if (n->wq_error != SD_VFS_OK && n->wq_head == NULL && n->wq_lost && !n->wq_reported && n->open_count == 0)
    defer_write_failed(v, d, n, n->wq_lost);   /* nobody left to see the sticky error */
}

/* v->lock held: sticky failure of every queued extent (grace expired, quiesce budget). */
static void wb_fail_all(sd_vfs *v, vfs_node *n, sd_vfs_status why, vfs_defer *d)
{
  uint64_t lost;
  if (!n->wq_head)
    return;
  wb_discard(v, n);
  if (n->wq_error == SD_VFS_OK) n->wq_error = why;
  lost = n->wq_lost;
  defer_write_failed(v, d, n, lost);
}

/* Sends eligible unsent extents (all = flush/cleanup/sequential, else only aged ones). */
static void wb_kick(sd_vfs *v, vfs_node *n, BOOL all, uint64_t dl)
{
  typedef struct wb_send { vfs_batch *b; uint64_t off; const uint8_t *data; uint32_t len, nch, chunk; } wb_send;
  sd_sftp_file *f = NULL;
  vfs_wb *e;
  wb_send send[64];
  uint32_t ns = 0, i, chunk;
  uint64_t now = sd_tick_ms(), unsent = 0;
  int wish = 0;
  sd_vfs_status st;
  vfs_defer d;
  memset(&d, 0, sizeof(d));
  if (!vfs_online(v))
    return;
  sd_mutex_lock(&v->lock);
  for (e = n->wq_head; e; e = e->next)
    if (!e->b) unsent += e->len;
  wish = n->stripe_wish;                  /* the queued stream qualified (5.6) */
  sd_mutex_unlock(&v->lock);
  if (unsent == 0)
    return;
  st = vfs_get_fh(v, n, TRUE, dl, &f, wish != 0);
  if (st != SD_VFS_OK)
    return;                                 /* kept: retried by the timer, failed by grace */
  chunk = max_write(v);
  if (chunk == 0) chunk = 32768;
  sd_mutex_lock(&v->lock);
  for (e = n->wq_head; e && ns < SD_COUNTOF(send); e = e->next) {
    uint32_t k;
    if (e->b)
      continue;
    if (!all && e->retry_until == 0 && unsent < VFS_WB_COALESCE_MAX && now - e->queued < VFS_WB_COALESCE_MS)
      continue;                             /* still coalescing */
    if (wb_in_flight_overlap(n, e, e->off, e->off + e->len))
      continue;
    e->chunk = chunk;
    e->nch = (e->len + chunk - 1) / chunk;
    e->b = vb_new(e->nch);
    if (!e->b)
      break;
    for (k = 0; k < e->nch; k++)
      vb_opt(e->b, k, dl);
    vb_ref(e->b);                           /* ours until submitted */
    e->retry_until = 0;
    e->maybe = TRUE;                        /* from now on it may execute without our knowing */
    /* Copied: the extent may be discarded meanwhile; its data then moves to the batch we hold. */
    send[ns].b = e->b;
    send[ns].off = e->off;
    send[ns].data = e->data;
    send[ns].len = e->len;
    send[ns].nch = e->nch;
    send[ns].chunk = e->chunk;
    ns++;
  }
  sd_mutex_unlock(&v->lock);
  for (i = 0; i < ns; i++) {
    wb_send *x = &send[i];
    uint32_t k;
    for (k = 0; k < x->nch; k++) {
      uint32_t o = k * x->chunk, l = SD_MIN(x->chunk, x->len - o);
      vb_submitted(x->b, k, sd_sftp_write(f, x->off + o, x->data + o, l, vb_optp(x->b, k), vb_cb_write(),
                                          vb_slot(x->b, k)));
    }
    vb_free(x->b);
  }
  sd_sftp_file_release(f);
  defer_run(v, &d);
}

/* v->lock held: adds n to the mount's write-behind list (holds a node ref). */
static void wb_list(sd_vfs *v, vfs_node *n)
{
  if (n->wq_listed)
    return;
  n->wq_listed = TRUE;
  vfs_node_ref(v, n);
  n->wb_next = v->wb_nodes;
  v->wb_nodes = n;
}

/* v->lock held: removes n from the list once its queue is empty; the caller must hold its own ref. */
static void wb_unlist_if_idle(sd_vfs *v, vfs_node *n, vfs_defer *d)
{
  vfs_node **pp;
  if (!n->wq_listed || n->wq_head)
    return;
  for (pp = &v->wb_nodes; *pp; pp = &(*pp)->wb_next) {
    if (*pp == n) {
      *pp = n->wb_next;
      break;
    }
  }
  n->wb_next = NULL;
  n->wq_listed = FALSE;
  if (n->open_count == 0) {
    defer_file(d, n->fh);                   /* kept open for the retransmit only */
    n->fh = NULL;
    n->fh_write = FALSE;
    n->wq_error = SD_VFS_OK;
    n->wq_reported = FALSE;
    n->wq_lost = 0;
  }
  vfs_node_unref(v, n);
}

/* Waits for the oldest in-flight extent of n (or of any node when n has none). Returns FALSE when
   nothing is in flight. Enters and leaves with v->lock held. */
static BOOL wb_wait_one(sd_vfs *v, vfs_node *n, uint64_t dl)
{
  vfs_wb *e;
  vfs_node *m;
  vfs_batch *b = NULL;
  uint64_t now = sd_tick_ms();
  for (e = n->wq_head; e && !b; e = e->next)
    if (e->b) b = e->b;
  for (m = v->wb_nodes; m && !b; m = m->wb_next)
    for (e = m->wq_head; e && !b; e = e->next)
      if (e->b) b = e->b;
  if (!b)
    return FALSE;
  vb_ref(b);
  sd_mutex_unlock(&v->lock);
  if (now < dl)
    WaitForSingleObject(vb_event(b), (DWORD)SD_MIN(dl - now, 0x7FFFFFFFu));
  vb_free(b);
  sd_mutex_lock(&v->lock);
  return TRUE;
}

/* Sends and waits until the node's queue is empty, a sticky error is set, or dl. With
   wait_reconnect, an outage within the grace period is waited out until dl. */
static sd_vfs_status wb_drain(sd_vfs *v, vfs_node *n, uint64_t dl, BOOL wait_reconnect)
{
  sd_vfs_status st = SD_VFS_OK;
  vfs_defer d;
  memset(&d, 0, sizeof(d));
  for (;;) {
    BOOL waited;
    sd_mutex_lock(&v->lock);
    wb_reap(v, n, &d);
    if (n->wq_error != SD_VFS_OK) {
      st = n->wq_error;
      sd_mutex_unlock(&v->lock);
      break;
    }
    if (!n->wq_head) {
      sd_mutex_unlock(&v->lock);
      break;
    }
    if (sd_tick_ms() >= dl) {
      st = vfs_online(v) ? SD_VFS_E_TIMEOUT : SD_VFS_E_DISCONNECTED;
      sd_mutex_unlock(&v->lock);
      break;
    }
    sd_mutex_unlock(&v->lock);
    if (!vfs_online(v)) {
      if (!wait_reconnect || !vfs_wait_online(v)) {
        st = SD_VFS_E_DISCONNECTED;
        break;
      }
      continue;
    }
    wb_kick(v, n, TRUE, dl);
    sd_mutex_lock(&v->lock);
    wb_reap(v, n, &d);
    waited = n->wq_head ? wb_wait_one(v, n, dl) : TRUE;
    sd_mutex_unlock(&v->lock);
    if (!waited) {
      /* Nothing in flight but data queued: blocked behind a failed send; back off briefly. */
      Sleep(10);
    }
  }
  defer_run(v, &d);
  return st;
}

/* Write-behind queues the extent; the kick that later opens the handle reads the node's
   stripe_wish (5.6), so the caller's instantaneous seq flag is not needed here. */
static sd_vfs_status write_behind(sd_vfs_handle *h, uint64_t off, const uint8_t *buf, uint32_t len, uint32_t *done,
                                  uint64_t dl)
{
  sd_vfs *v = h->v;
  vfs_node *n = h->node;
  vfs_wb *e = NULL, *t;
  uint64_t end = off + len;
  BOOL wseq, urgent;
  sd_vfs_status st = SD_VFS_OK;
  vfs_defer d;
  memset(&d, 0, sizeof(d));
  sd_mutex_lock(&v->lock);
  /* Backpressure: the window bounds unacknowledged data (16 MiB per node, 64 MiB per mount). */
  for (;;) {
    wb_reap(v, n, &d);
    if (n->wq_error != SD_VFS_OK) {
      st = n->wq_error;                     /* sticky (02 §4.4) */
      break;
    }
    if ((n->wq_bytes == 0 || n->wq_bytes + len <= v->wb_window) &&
        (v->wb_bytes == 0 || v->wb_bytes + len <= v->wb_window_mount))
      break;
    if (sd_tick_ms() >= dl) {
      st = SD_VFS_E_TIMEOUT;
      break;
    }
    if (!vfs_online(v)) {
      st = SD_VFS_E_DISCONNECTED;
      break;
    }
    sd_mutex_unlock(&v->lock);
    wb_kick(v, n, TRUE, dl);
    sd_mutex_lock(&v->lock);
    if (!wb_wait_one(v, n, dl)) {
      sd_mutex_unlock(&v->lock);
      Sleep(5);
      sd_mutex_lock(&v->lock);
    }
  }
  if (st != SD_VFS_OK) {
    sd_mutex_unlock(&v->lock);
    defer_run(v, &d);
    return st;
  }
  /* Coalesce into the unsent tail extent when contiguous or overlapping. */
  t = n->wq_tail;
  if (t && !t->b && !t->retry_until && off >= t->off && off <= t->off + t->len &&
      SD_MAX(end, t->off + t->len) - t->off <= VFS_WB_COALESCE_MAX) {
    uint32_t nl = (uint32_t)(SD_MAX(end, t->off + t->len) - t->off);
    uint8_t *nd = nl > t->len ? (uint8_t *)sd_realloc(t->data, nl) : t->data;
    if (nd) {
      t->data = nd;
      memcpy(nd + (off - t->off), buf, len);
      n->wq_bytes += nl - t->len;
      v->wb_bytes += nl - t->len;
      t->len = nl;
      e = t;
    }
  }
  if (!e) {
    e = (vfs_wb *)sd_calloc(1, sizeof(*e));
    if (e) e->data = (uint8_t *)sd_alloc(len);
    if (!e || !e->data) {
      sd_free(e);
      sd_mutex_unlock(&v->lock);
      defer_run(v, &d);
      return SD_VFS_E_NO_MEMORY;
    }
    memcpy(e->data, buf, len);
    e->off = off;
    e->len = len;
    e->queued = sd_tick_ms();
    if (n->wq_tail) n->wq_tail->next = e; else n->wq_head = e;
    n->wq_tail = e;
    n->wq_bytes += len;
    v->wb_bytes += len;
  }
  cache_local_write(v, n, off, buf, len, n->attr.size);
  if (end > n->attr.size)
    n->attr.size = end;
  n->attr.mtime = sd_unix_time_now();
  n->attr.valid |= SD_SFTP_ATTR_SIZE | SD_SFTP_ATTR_TIMES;
  n->attr_time = sd_tick_ms();
  h->wrote = TRUE;
  vfs_listing_sync(v, n);
  wb_list(v, n);
  wseq = off == n->wq_seq_end;
  n->wq_seq_end = end;
  urgent = wseq || len >= VFS_WB_COALESCE_MAX;
  sd_mutex_unlock(&v->lock);
  /* Sequential writes are sent at once; small random ones coalesce up to 500 ms / 1 MiB (the
     background timer sends them). */
  if (urgent)
    wb_kick(v, n, TRUE, dl);
  defer_run(v, &d);
  *done = len;
  return SD_VFS_OK;
}

sd_vfs_status sd_vfs_write(sd_vfs_handle *h, UINT64 off, const void *buf, UINT32 len, UINT32 *done, BOOL paging_io)
{
  sd_vfs *v;
  vfs_node *n;
  sd_vfs_status st;
  uint64_t dl, end;
  uint32_t d = 0;
  BOOL behind, seq = FALSE;
  if (done) *done = 0;
  if (!h || (!buf && len))
    return SD_VFS_E_INVALID_NAME;
  v = h->v;
  n = h->node;
  if (h->is_dir)
    return SD_VFS_E_IS_DIR;
  if (v->read_only || !h->can_write)
    return SD_VFS_E_READ_ONLY;
  if (!paging_io && !(h->access & ACC_DATA_WRITE))
    return SD_VFS_E_ACCESS_DENIED;
  if (!vfs_online(v))
    return SD_VFS_E_DISCONNECTED;           /* fail fast, never queued (02 §5.2, FS-7) */
  if (len == 0)
    return SD_VFS_OK;
  enter(v);
  dl = vfs_deadline(v);
  sd_mutex_lock(&v->lock);
  if (n->wq_error == SD_VFS_E_STALE) {
    sd_mutex_unlock(&v->lock);
    leave(v);
    return SD_VFS_E_STALE;                  /* conflicted handle (02 §5.3) */
  }
  if (off == SD_VFS_EOF || (!paging_io && (h->access & ACC_DATA_WRITE) == FILE_APPEND_DATA))
    off = n->attr.size;                     /* append: cached EOF (02 §2.2) */
  else if ((h->opts & SD_VFS_FILE_SEQUENTIAL_ONLY) || off == n->attr.size) {
    /* Sequential access (02 §5.6): SEQUENTIAL_ONLY, or a write that continues the file. A write of
       VFS_STRIPE_MIN_WRITE or more, or any sequential write on a file past stripe_min_file, keeps
       the node stripe-eligible for its later data-handle (re)opens. */
    seq = TRUE;
    if (len >= VFS_STRIPE_MIN_WRITE || n->attr.size >= v->stripe_min_file)
      n->stripe_wish = 1;
  }
  if (paging_io) {
    /* Paging writes never extend the file (NT rule, 02 §6.5). */
    if (off >= n->attr.size) {
      sd_mutex_unlock(&v->lock);
      leave(v);
      return SD_VFS_OK;
    }
    if (n->attr.size - off < len)
      len = (uint32_t)(n->attr.size - off);
  }
  behind = v->write_behind && !h->write_through;
  sd_mutex_unlock(&v->lock);
  if (sd_add_ovf_u64(off, len, &end)) {
    leave(v);
    return SD_VFS_E_TOO_LARGE;
  }
  st = behind ? write_behind(h, off, (const uint8_t *)buf, len, &d, dl)
              : write_through(h, off, (const uint8_t *)buf, len, &d, dl, seq);
  if (done) *done = d;
  sd_atomic_add64(&v->bytes_wr, d);
  leave(v);
  return st;
}

/* ---- flush, truncate, cleanup ---- */

sd_vfs_status sd_vfs_flush(sd_vfs_handle *h)
{
  sd_vfs *v;
  vfs_node *n;
  sd_vfs_status st;
  sd_sftp_file *f = NULL;
  uint64_t dl;
  if (!h)
    return SD_VFS_OK;
  v = h->v;
  n = h->node;
  if (h->is_dir)
    return SD_VFS_OK;
  enter(v);
  dl = vfs_deadline(v);
  st = vfs_ext_drain(v, n, dl);
  if (st == SD_VFS_OK && v->write_behind)
    st = wb_drain(v, n, dl, TRUE);          /* drains the window, returns the sticky error */
  if (st == SD_VFS_OK && v->fsync_on_flush && sd_sftp_has_ext(v->s, SD_SFTP_EXT_FSYNC)) {
    sd_mutex_lock(&v->lock);
    if (n->fh && n->fh_write) {
      f = n->fh;
      sd_sftp_file_addref(f);
    }
    sd_mutex_unlock(&v->lock);
    if (f) {
      sd_err e = vr_fsync(f, dl);
      sd_sftp_file_release(f);
      if (e != SD_OK)
        st = vfs_map_err(e == SD_E_STALE_HANDLE ? SD_E_DISCONNECTED : e);
    }
  }
  leave(v);
  return st;
}

sd_vfs_status sd_vfs_truncate(sd_vfs_handle *h, UINT64 size)
{
  sd_vfs *v;
  vfs_node *n;
  sd_vfs_status st;
  sd_sftp_file *f = NULL;
  sd_sftp_attrs a;
  uint64_t dl;
  sd_err e;
  if (!h)
    return SD_VFS_E_INVALID_NAME;
  v = h->v;
  n = h->node;
  if (h->is_dir)
    return SD_VFS_E_IS_DIR;
  if (v->read_only || !h->can_write)
    return SD_VFS_E_READ_ONLY;
  if (!vfs_online(v))
    return SD_VFS_E_DISCONNECTED;
  enter(v);
  dl = vfs_deadline(v);
  st = vfs_ext_drain(v, n, dl);
  if (st == SD_VFS_OK && v->write_behind)
    st = wb_drain(v, n, dl, FALSE);
  if (st == SD_VFS_OK)
    st = vfs_get_fh(v, n, TRUE, dl, &f, FALSE);   /* fsetstat is not a data access (5.6) */
  if (st == SD_VFS_OK) {
    memset(&a, 0, sizeof(a));
    a.valid = SD_SFTP_ATTR_SIZE;
    a.size = size;
    e = vr_fsetstat(f, &a, dl);
    sd_sftp_file_release(f);
    st = vfs_map_err(e);
  }
  if (st == SD_VFS_OK) {
    sd_mutex_lock(&v->lock);
    vfs_node_invalidate(v, n);              /* simplest correct form: the blocks go */
    n->attr.size = size;
    n->attr.valid |= SD_SFTP_ATTR_SIZE;
    n->attr.mtime = sd_unix_time_now();
    n->attr_time = sd_tick_ms();
    n->srv_size = size;
    n->cv_size = size;
    n->mtime_pending = TRUE;
    if (n->dc) vfs_dc_set_validator(v, n->dc, n->vgen, size, n->cv_mtime);
    h->wrote = TRUE;
    vfs_listing_sync(v, n);
    sd_mutex_unlock(&v->lock);
  }
  leave(v);
  return st;
}

sd_vfs_status vfs_data_cleanup(sd_vfs_handle *h, uint64_t dl)
{
  sd_vfs *v = h->v;
  vfs_node *n = h->node;
  sd_vfs_status st = SD_VFS_OK;
  vfs_defer d;
  if (h->is_dir || !v->write_behind)
    return SD_VFS_OK;
  sd_mutex_lock(&v->lock);
  if (!n->wq_head && n->wq_error == SD_VFS_OK) {
    sd_mutex_unlock(&v->lock);
    return SD_VFS_OK;
  }
  sd_mutex_unlock(&v->lock);
  /* Synchronous drain (02 §4.4). A disconnect keeps the data for the grace period; the timer
     retransmits it or reports it lost. */
  st = wb_drain(v, n, dl, FALSE);
  memset(&d, 0, sizeof(d));
  sd_mutex_lock(&v->lock);
  if (n->wq_error != SD_VFS_OK && n->wq_error != SD_VFS_E_DISCONNECTED)
    defer_write_failed(v, &d, n, n->wq_lost);   /* Cleanup is void: the host notifies (C45) */
  else if (n->wq_error == SD_VFS_E_DISCONNECTED && !n->wq_head)
    defer_write_failed(v, &d, n, n->wq_lost);
  sd_mutex_unlock(&v->lock);
  defer_run(v, &d);
  return st;
}

/* v->lock held: the last local handle of n is closing. Returns a disk entry to close unlocked. */
struct vfs_dc *vfs_data_last_close(sd_vfs *v, vfs_node *n)
{
  struct vfs_dc *dc = n->dc;
  vfs_fetch *r, *next;
  n->dc = NULL;
  for (r = n->fetch; r; r = next) {
    next = r->next;
    fetch_unlist(v, n, r);                  /* in-flight reads keep their own memory */
  }
  if (!n->wq_head) {
    n->wq_error = SD_VFS_OK;                /* sticky until the last handle closes */
    n->wq_reported = FALSE;
    n->wq_lost = 0;
  }
  return dc;
}

void vfs_data_node_free(vfs_node *n)
{
  vfs_fetch *r, *next;
  vfs_wb *e, *en;
  for (r = n->fetch; r; r = next) {
    next = r->next;
    vb_free(r->b);
    sd_free(r);
  }
  n->fetch = NULL;
  for (e = n->wq_head; e; e = en) {
    en = e->next;
    if (e->b) {
      vb_attach_buf(e->b, e->data);
      vb_free(e->b);
    } else {
      sd_free(e->data);
    }
    sd_free(e);
  }
  n->wq_head = n->wq_tail = NULL;
}

/* ---- quiesce and the background timer ---- */

void vfs_data_quiesce(sd_vfs *v, uint64_t end)
{
  for (;;) {
    vfs_node *n;
    vfs_defer d;
    sd_mutex_lock(&v->lock);
    for (n = v->wb_nodes; n && !n->wq_head; n = n->wb_next) {}
    if (!n) {
      sd_mutex_unlock(&v->lock);
      return;
    }
    vfs_node_ref(v, n);
    sd_mutex_unlock(&v->lock);
    wb_drain(v, n, end, FALSE);
    memset(&d, 0, sizeof(d));
    sd_mutex_lock(&v->lock);
    if (n->wq_head)
      wb_fail_all(v, n, SD_VFS_E_DISCONNECTED, &d);   /* still dirty at the end of the budget */
    wb_unlist_if_idle(v, n, &d);
    vfs_node_unref(v, n);
    sd_mutex_unlock(&v->lock);
    defer_run(v, &d);
  }
}

static void timer_tick(sd_vfs *v)
{
  vfs_node *list[64];
  uint32_t cnt = 0, i;
  uint64_t now = sd_tick_ms();
  BOOL online;
  vfs_node *n;
  vfs_sync_generation(v);
  online = vfs_online(v);
  sd_mutex_lock(&v->lock);
  for (n = v->wb_nodes; n && cnt < SD_COUNTOF(list); n = n->wb_next) {
    vfs_node_ref(v, n);
    list[cnt++] = n;
  }
  sd_mutex_unlock(&v->lock);
  for (i = 0; i < cnt; i++) {
    vfs_defer d;
    BOOL kick = FALSE, expired = FALSE;
    vfs_wb *e;
    n = list[i];
    memset(&d, 0, sizeof(d));
    sd_mutex_lock(&v->lock);
    wb_reap(v, n, &d);
    for (e = n->wq_head; e; e = e->next) {
      if (!online && e->retry_until == 0 && v->grace)
        e->retry_until = now + v->grace;    /* accepted but unacknowledged data waits for the link */
      if (e->retry_until && now >= e->retry_until && !e->b)
        expired = TRUE;
      if (!e->b) kick = TRUE;
    }
    if (!online && v->grace == 0 && n->wq_head)
      expired = TRUE;                       /* no grace retransmit configured */
    if (expired) {
      SD_LOGW(VFS_LOG, "reconnect grace expired with write-behind data queued");
      wb_fail_all(v, n, SD_VFS_E_DISCONNECTED, &d);
      kick = FALSE;
    }
    sd_mutex_unlock(&v->lock);
    if (kick && online)
      wb_kick(v, n, FALSE, sd_tick_ms() + v->req_timeout);
    sd_mutex_lock(&v->lock);
    wb_reap(v, n, &d);
    wb_unlist_if_idle(v, n, &d);
    vfs_node_unref(v, n);
    sd_mutex_unlock(&v->lock);
    defer_run(v, &d);
  }
  if (v->disk && now >= v->next_trim) {
    v->next_trim = now + VFS_DISK_TRIM_MS;
    vfs_disk_trim(v);
  }
}

static VOID CALLBACK timer_cb(PVOID ctx, BOOLEAN fired)
{
  sd_vfs *v = (sd_vfs *)ctx;
  SD_UNUSED(fired);
  if (InterlockedCompareExchange(&v->timer_busy, 1, 0) != 0)
    return;                                 /* the previous tick still runs */
  timer_tick(v);
  InterlockedExchange(&v->timer_busy, 0);
}

void vfs_timer_start(sd_vfs *v)
{
  if (!v->write_behind && !v->disk)
    return;
  v->next_trim = sd_tick_ms() + VFS_DISK_TRIM_MS;
  if (!CreateTimerQueueTimer(&v->timer, NULL, timer_cb, v, VFS_TIMER_MS, VFS_TIMER_MS, WT_EXECUTELONGFUNCTION)) {
    v->timer = NULL;
    SD_LOGW(VFS_LOG, "background timer unavailable: write-behind coalescing and grace expiry run on demand");
  }
}

void vfs_timer_stop(sd_vfs *v)
{
  if (v->timer) {
    if (!DeleteTimerQueueTimer(NULL, v->timer, INVALID_HANDLE_VALUE))   /* waits for a running tick */
      SD_LOGW(VFS_LOG, "background timer delete failed: %u", (unsigned)GetLastError());
    v->timer = NULL;
  }
}
