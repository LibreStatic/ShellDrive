/* Waiting on sd_sftp completions (02 §5.4, review §4.1 rule 1).
 *
 * A batch is a heap block with one slot per submitted request, an event and a reference count
 * (1 for the waiter + 1 per submitted request). Completions run on the sd_sftp I/O thread: they copy
 * the result into their slot, signal the event when the last one arrives and drop their reference.
 * They take no vfs lock. The waiter waits until every request completed; sd_sftp completes each one
 * by its timeout_ms (the remaining budget). A grace period beyond the deadline guards against a
 * missing completion: then the waiter cancels what is left (after sd_sftp_cancel the caller buffer
 * is never touched again) and drops its reference, so a late completion still finds valid memory.
 * Thread safety: a batch is used by one waiter thread plus the completions. */
#include <windows.h>

#include "sd_base/sd_mem.h"
#include "sd_platform/sd_log.h"
#include "sd_platform/sd_time.h"
#include "vfs_internal.h"

struct vfs_batch {
  volatile LONG refs;
  volatile LONG pending;
  HANDLE ev;
  uint32_t n;
  sd_sftp_reqopt *opt;
  vfs_slot *s;
};

static void slot_clear(vfs_slot *s)
{
  if (s->file) {
    sd_sftp_file_release(s->file);
    s->file = NULL;
  }
  sd_free(s->name);
  s->name = NULL;
  vb_free_rawents(s);
}

void vb_free_rawents(vfs_slot *s)
{
  uint32_t i;
  for (i = 0; i < s->nents; i++)
    sd_free(s->ents[i].name);
  sd_free(s->ents);
  s->ents = NULL;
  s->nents = 0;
}

static void batch_release(vfs_batch *b)
{
  uint32_t i;
  if (InterlockedDecrement(&b->refs) != 0)
    return;
  for (i = 0; i < b->n; i++)
    slot_clear(&b->s[i]);
  if (b->ev)
    CloseHandle(b->ev);
  sd_free(b->opt);
  sd_free(b->s);
  sd_free(b);
}

vfs_batch *vb_new(uint32_t n)
{
  vfs_batch *b = (vfs_batch *)sd_calloc(1, sizeof(*b));
  uint32_t i;
  if (!b)
    return NULL;
  b->s = (vfs_slot *)sd_calloc(n ? n : 1, sizeof(vfs_slot));
  b->opt = (sd_sftp_reqopt *)sd_calloc(n ? n : 1, sizeof(sd_sftp_reqopt));
  b->ev = CreateEventW(NULL, TRUE, FALSE, NULL);
  if (!b->s || !b->opt || !b->ev) {
    if (b->ev) CloseHandle(b->ev);
    sd_free(b->s);
    sd_free(b->opt);
    sd_free(b);
    return NULL;
  }
  b->n = n;
  b->refs = 1;
  for (i = 0; i < n; i++) {
    b->s[i].b = b;
    b->s[i].err = SD_E_INTERNAL;
    b->s[i].done = 1;                     /* not submitted */
  }
  return b;
}

vfs_slot *vb_slot(vfs_batch *b, uint32_t i) { return &b->s[i]; }

const sd_sftp_reqopt *vb_opt(vfs_batch *b, uint32_t i, uint64_t deadline)
{
  uint64_t now = sd_tick_ms();
  sd_sftp_reqopt *o = &b->opt[i];
  uint64_t left = deadline > now ? deadline - now : 1;
  vfs_slot *s = &b->s[i];
  o->flags = 0;
  o->timeout_ms = (uint32_t)SD_MIN(left, 0x7FFFFFFFu);
  o->token_out = &s->token;
  /* Armed before the submit: the completion may run before the submit call returns. */
  s->done = 0;
  s->err = SD_E_INTERNAL;
  InterlockedIncrement(&b->refs);
  InterlockedIncrement(&b->pending);
  ResetEvent(b->ev);
  return o;
}

static void copy_attrs(sd_sftp_attrs *dst, const sd_sftp_attrs *src)
{
  *dst = *src;
  dst->ext = NULL;
  dst->ext_count = 0;
}

static void finish(vfs_slot *s)
{
  vfs_batch *b = s->b;
  InterlockedExchange(&s->done, 1);
  if (InterlockedDecrement(&b->pending) == 0)
    SetEvent(b->ev);
  batch_release(b);
}

/* Status-only completion. */
static void on_complete(void *ctx, const sd_sftp_completion *c)
{
  vfs_slot *s = (vfs_slot *)ctx;
  s->err = c->err;
  finish(s);
}

sd_sftp_cb vb_cb(void) { return on_complete; }

void vb_submitted(vfs_batch *b, uint32_t i, sd_err submit_result)
{
  if (submit_result == SD_OK)
    return;
  /* Never called back: undo the arming. */
  b->s[i].err = submit_result;
  b->s[i].done = 1;
  InterlockedDecrement(&b->refs);
  if (InterlockedDecrement(&b->pending) == 0)
    SetEvent(b->ev);
}

void vb_wait(vfs_batch *b, uint64_t deadline)
{
  uint64_t now = sd_tick_ms();
  uint64_t limit = deadline + VFS_WAIT_GRACE_MS;
  uint32_t i;
  if (InterlockedCompareExchange(&b->pending, 0, 0) == 0)
    return;
  while (InterlockedCompareExchange(&b->pending, 0, 0) != 0) {
    DWORD ms = now >= limit ? 0 : (DWORD)SD_MIN(limit - now, 0x7FFFFFFFu);
    if (WaitForSingleObject(b->ev, ms) == WAIT_OBJECT_0)
      continue;
    now = sd_tick_ms();
    if (now < limit)
      continue;
    /* Missing completions past the deadline + grace: cancel them and wait a little more. */
    SD_LOGW(VFS_LOG, "request completion missing past deadline; cancelling");
    for (i = 0; i < b->n; i++) {
      if (!InterlockedCompareExchange(&b->s[i].done, 0, 0) && b->s[i].token)
        sd_sftp_cancel(b->s[i].token);
    }
    if (WaitForSingleObject(b->ev, VFS_WAIT_GRACE_MS) != WAIT_OBJECT_0) {
      for (i = 0; i < b->n; i++) {
        if (!InterlockedCompareExchange(&b->s[i].done, 0, 0))
          b->s[i].err = SD_E_TIMEOUT;     /* the waiter reports a timeout; memory stays valid */
      }
    }
    return;
  }
}

void vb_free(vfs_batch *b)
{
  if (b)
    batch_release(b);
}

/* ---- typed completions ---- */

static void on_attrs(void *ctx, const sd_sftp_completion *c)
{
  vfs_slot *s = (vfs_slot *)ctx;
  s->err = c->err;
  if (c->err == SD_OK)
    copy_attrs(&s->attrs, &c->u.stat.attrs);
  finish(s);
}

static void on_name(void *ctx, const sd_sftp_completion *c)
{
  vfs_slot *s = (vfs_slot *)ctx;
  s->err = c->err;
  if (c->err == SD_OK && c->u.name.path) {
    s->name = vfs_strndup(c->u.name.path, c->u.name.len);
    s->name_len = c->u.name.len;
    if (!s->name)
      s->err = SD_E_NO_MEMORY;
  }
  finish(s);
}

static void on_open(void *ctx, const sd_sftp_completion *c)
{
  vfs_slot *s = (vfs_slot *)ctx;
  s->err = c->err;
  if (c->err == SD_OK) {
    s->file = c->u.open.file;
    copy_attrs(&s->attrs, &c->u.open.attrs);
  }
  finish(s);
}

static void on_statvfs(void *ctx, const sd_sftp_completion *c)
{
  vfs_slot *s = (vfs_slot *)ctx;
  s->err = c->err;
  if (c->err == SD_OK)
    s->svfs = c->u.statvfs.v;
  finish(s);
}

static void on_read(void *ctx, const sd_sftp_completion *c)
{
  vfs_slot *s = (vfs_slot *)ctx;
  s->err = c->err;
  if (c->err == SD_OK) {
    s->bytes = c->u.read.bytes;
    s->eof = c->u.read.eof;
  } else if (c->err == SD_E_EOF) {
    s->bytes = 0;
    s->eof = 1;
  }
  finish(s);
}

static void on_write(void *ctx, const sd_sftp_completion *c)
{
  vfs_slot *s = (vfs_slot *)ctx;
  s->err = c->err;
  if (c->err == SD_OK)
    s->bytes = c->u.write.bytes;
  finish(s);
}

/* READDIR batch: entries are valid only during the callback, so they are copied here (bounded by
   the batch size the server sends; no vfs lock is taken). */
static void on_readdir(void *ctx, const sd_sftp_completion *c)
{
  vfs_slot *s = (vfs_slot *)ctx;
  uint32_t i;
  s->err = c->err;
  s->eof = (c->err == SD_E_EOF) || (c->err == SD_OK && c->u.readdir.eof);
  if (c->err == SD_E_EOF)
    s->err = SD_OK;
  if (c->err == SD_OK && c->u.readdir.count > 0) {
    s->ents = (vfs_rawent *)sd_calloc(c->u.readdir.count, sizeof(vfs_rawent));
    if (!s->ents) {
      s->err = SD_E_NO_MEMORY;
    } else {
      for (i = 0; i < c->u.readdir.count; i++) {
        const sd_sftp_dirent *d = &c->u.readdir.ents[i];
        vfs_rawent *r = &s->ents[s->nents];
        r->name = (char *)sd_alloc((size_t)d->name_len + 1);
        if (!r->name) {
          s->err = SD_E_NO_MEMORY;
          break;
        }
        if (d->name_len) memcpy(r->name, d->name, d->name_len);
        r->name[d->name_len] = 0;
        r->len = d->name_len;
        copy_attrs(&r->attrs, &d->attrs);
        s->raw_bytes += d->name_len;
        s->nents++;
      }
    }
    s->dropped = c->u.readdir.dropped;
  }
  finish(s);
}

sd_sftp_cb vb_cb_read(void) { return on_read; }
sd_sftp_cb vb_cb_write(void) { return on_write; }
sd_sftp_cb vb_cb_readdir(void) { return on_readdir; }
sd_sftp_cb vb_cb_open(void) { return on_open; }
sd_sftp_cb vb_cb_attrs(void) { return on_attrs; }
sd_sftp_cb vb_cb_name(void) { return on_name; }

/* Single request: allocate, submit, wait, extract. SUBMIT is an expression using o, cb, ctx. */
#define VR_ONE(v, dl, cbfn, SUBMIT, EXTRACT)                         \
  do {                                                                 \
    vfs_batch *b_ = vb_new(1);                                         \
    vfs_slot *s_;                                                      \
    sd_err e_;                                                         \
    const sd_sftp_reqopt *o;                                           \
    sd_sftp_cb cb = (cbfn);                                            \
    void *ctx;                                                         \
    if (!b_) return SD_E_NO_MEMORY;                                    \
    s_ = vb_slot(b_, 0);                                               \
    ctx = s_;                                                          \
    o = vb_opt(b_, 0, (dl));                                           \
    vb_submitted(b_, 0, (SUBMIT));                                     \
    vb_wait(b_, (dl));                                                 \
    e_ = s_->err;                                                      \
    if (e_ == SD_OK) { EXTRACT; }                                      \
    vb_free(b_);                                                       \
    return e_;                                                         \
  } while (0)

sd_err vr_lstat(sd_vfs *v, const char *path, uint64_t dl, sd_sftp_attrs *out)
{
  VR_ONE(v, dl, on_attrs, sd_sftp_lstat(v->s, path, o, cb, ctx), *out = s_->attrs);
}

sd_err vr_stat(sd_vfs *v, const char *path, uint64_t dl, sd_sftp_attrs *out)
{
  VR_ONE(v, dl, on_attrs, sd_sftp_stat(v->s, path, o, cb, ctx), *out = s_->attrs);
}

sd_err vr_realpath(sd_vfs *v, const char *path, uint64_t dl, char **out)
{
  VR_ONE(v, dl, on_name, sd_sftp_realpath(v->s, path, o, cb, ctx),
         { *out = s_->name; s_->name = NULL; if (!*out) e_ = SD_E_PROTOCOL; });
}

sd_err vr_open(sd_vfs *v, const char *path, uint32_t oflags, const sd_sftp_attrs *ca, uint64_t dl,
               sd_sftp_file **f, sd_sftp_attrs *attrs)
{
  VR_ONE(v, dl, on_open, sd_sftp_open(v->s, path, oflags, ca, NULL, o, cb, ctx),
         { *f = s_->file; s_->file = NULL; if (attrs) *attrs = s_->attrs; });
}

sd_err vr_mkdir(sd_vfs *v, const char *path, uint32_t perm, uint64_t dl)
{
  sd_sftp_attrs a;
  memset(&a, 0, sizeof(a));
  a.valid = SD_SFTP_ATTR_PERM;
  a.perm = perm;
  VR_ONE(v, dl, on_complete, sd_sftp_mkdir(v->s, path, &a, o, cb, ctx), (void)0);
}

sd_err vr_rmdir(sd_vfs *v, const char *path, uint64_t dl)
{
  VR_ONE(v, dl, on_complete, sd_sftp_rmdir(v->s, path, o, cb, ctx), (void)0);
}

sd_err vr_remove(sd_vfs *v, const char *path, uint64_t dl)
{
  VR_ONE(v, dl, on_complete, sd_sftp_remove(v->s, path, o, cb, ctx), (void)0);
}

sd_err vr_rename(sd_vfs *v, const char *from, const char *to, uint32_t flags, uint64_t dl)
{
  VR_ONE(v, dl, on_complete, sd_sftp_rename(v->s, from, to, flags, o, cb, ctx), (void)0);
}

sd_err vr_setstat(sd_vfs *v, const char *path, const sd_sftp_attrs *a, uint64_t dl)
{
  VR_ONE(v, dl, on_complete, sd_sftp_setstat(v->s, path, a, 0, o, cb, ctx), (void)0);
}

sd_err vr_fsetstat(sd_sftp_file *f, const sd_sftp_attrs *a, uint64_t dl)
{
  VR_ONE(NULL, dl, on_complete, sd_sftp_fsetstat(f, a, o, cb, ctx), (void)0);
}

sd_err vr_fsync(sd_sftp_file *f, uint64_t dl)
{
  VR_ONE(NULL, dl, on_complete, sd_sftp_fsync(f, o, cb, ctx), (void)0);
}

sd_err vr_statvfs(sd_vfs *v, const char *path, uint64_t dl, sd_sftp_statvfs *out)
{
  VR_ONE(v, dl, on_statvfs, sd_sftp_statvfs_path(v->s, path, o, cb, ctx), *out = s_->svfs);
}
