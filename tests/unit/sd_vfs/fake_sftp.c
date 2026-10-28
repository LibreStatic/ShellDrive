/* In-memory fake sd_sftp (see fake_sftp.h). One worker thread executes requests in FIFO order and
 * delivers completions, like the single I/O thread of an M0 session. */
#include <windows.h>
#include <process.h>
#include <stdlib.h>
#include <string.h>

#include "fake_sftp.h"
#include "sd_base/sd_mem.h"
#include "sd_platform/sd_time.h"

/* Test fake: out of memory is fatal (no allocation-failure tests run against the fake). */
static _Ret_notnull_ void *must(void *p)
{
  if (!p)
    abort();
  return p;
}

#define S_IFMT_  0170000u
#define S_IFDIR_ 0040000u
#define S_IFREG_ 0100000u
#define S_IFLNK_ 0120000u
#define S_IFIFO_ 0010000u
#define S_ISGID_ 0002000u

typedef struct fnode {
  struct fnode *parent, *child, *next;
  char *name; uint32_t nlen;
  uint32_t mode, uid, gid;
  int64_t atime, mtime;
  uint8_t *data; uint64_t size, cap;
  char *link;
  int unlinked;
  LONG opens;
} fnode;

typedef struct inj { struct inj *next; char *dir; char *name; uint32_t len; uint32_t mode; } inj;

struct sd_sftp_file {
  sd_sftp_session *s;
  fnode *n;
  int is_dir, closed;
  uint32_t oflags;
  LONG refs;
  sd_sftp_dirent *snap; uint32_t nsnap, pos, snapped;
  char *path;                       /* as opened (for reopen) */
  uint32_t gen;
  volatile LONG stale;
  sd_sftp_attrs attrs_at_open;
  struct sd_sftp_file *fprev, *fnext;   /* every live file of the session */
};

typedef struct freq {
  struct freq *next;
  int op;
  sd_sftp_cb cb; void *ctx;
  volatile LONG cancelled;
  char *p1, *p2;
  uint32_t flags;
  sd_sftp_attrs a; int has_a;
  sd_sftp_file *f;
  uint64_t off; void *buf; const void *cbuf; uint32_t len;
  uint64_t due;                     /* tick at which the "server" executes it */
  /* SD_SFTP_REQ_WAIT_READY (as sd_sftp): held on the wait list while the session is not READY, queued in
     submission order once it is; completes with SD_E_TIMEOUT at its deadline or SD_E_CANCELLED. */
  struct sd_sftp_session *s;
  uint64_t deadline;
  struct freq *wnext, *out_next;
  sd_err expire_err;
} freq;

struct sd_sftp_session {
  CRITICAL_SECTION lock;
  HANDLE ev, thread;
  volatile LONG stop;
  freq *head, *tail;
  fnode *root;
  char home[512];
  fake_config cfg;
  sd_sftp_state state;
  uint32_t counts[FOP_COUNT];
  uint32_t striped_opens;             /* OPENs executed with SD_SFTP_O_STRIPED */
  LONG open_handles;
  int fail_op; sd_err fail_err;
  inj *injected;
  uint32_t gen;
  int hold;
  freq *held_head, *held_tail;
  uint32_t nheld;
  freq *wait_head, *wait_tail;        /* WAIT_READY requests held while not READY */
  sd_sftp_file *files;
};

/* ---- tree ---- */

static int64_t now_unix(void)
{
  FILETIME ft;
  ULONGLONG t;
  GetSystemTimeAsFileTime(&ft);
  t = ((ULONGLONG)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
  return (int64_t)((t - 116444736000000000ULL) / 10000000ULL);
}

static char *xstrndup(const char *s, size_t n)
{
  char *r = (char *)must(sd_alloc(n + 1));
  if (r) { memcpy(r, s, n); r[n] = 0; }
  return r;
}

static fnode *node_new(sd_sftp_session *s, fnode *parent, const char *name, uint32_t nlen, uint32_t mode)
{
  fnode *n = (fnode *)must(sd_calloc(1, sizeof(*n)));
  n->name = xstrndup(name, nlen);
  n->nlen = nlen;
  n->mode = mode;
  n->uid = s->cfg.uid;
  n->gid = (parent && (parent->mode & S_ISGID_)) ? parent->gid : s->cfg.gid;
  n->atime = n->mtime = now_unix();
  n->parent = parent;
  if (parent) {
    n->next = parent->child;
    parent->child = n;
  }
  return n;
}

static void node_free(fnode *n)
{
  while (n->child) {
    fnode *c = n->child;
    n->child = c->next;
    node_free(c);
  }
  sd_free(n->name);
  sd_free(n->data);
  sd_free(n->link);
  sd_free(n);
}

static void node_unlink(fnode *n)
{
  fnode **pp;
  if (!n->parent)
    return;
  for (pp = &n->parent->child; *pp; pp = &(*pp)->next) {
    if (*pp == n) { *pp = n->next; break; }
  }
  n->parent = NULL;
  n->next = NULL;
}

static void node_drop(fnode *n)
{
  node_unlink(n);
  n->unlinked = 1;
  if (n->opens == 0)
    node_free(n);
}

static int name_eq(sd_sftp_session *s, const fnode *n, const char *c, uint32_t len)
{
  if (n->nlen != len)
    return 0;
  return s->cfg.case_insensitive ? _strnicmp(n->name, c, len) == 0 : memcmp(n->name, c, len) == 0;
}

static fnode *find_child(sd_sftp_session *s, fnode *d, const char *c, uint32_t len)
{
  fnode *n;
  for (n = d->child; n; n = n->next)
    if (name_eq(s, n, c, len)) return n;
  return NULL;
}

static int is_dir(const fnode *n) { return (n->mode & S_IFMT_) == S_IFDIR_; }
static int is_lnk(const fnode *n) { return (n->mode & S_IFMT_) == S_IFLNK_; }

typedef struct resolved { fnode *node, *parent; const char *leaf; uint32_t leaf_len; } resolved;

static fnode *home_node(sd_sftp_session *s);

static sd_err resolve_at(sd_sftp_session *s, fnode *start, const char *path, int follow_last, int depth,
                         resolved *r)
{
  fnode *cur = path[0] == '/' ? s->root : start;
  const char *p = path;
  memset(r, 0, sizeof(*r));
  if (depth > 40)
    return SD_E_LINK_LOOP;
  for (;;) {
    const char *c, *e;
    uint32_t len;
    int last;
    fnode *ch;
    while (*p == '/') p++;
    if (!*p) {
      r->node = cur;
      return SD_OK;
    }
    c = p;
    while (*p && *p != '/') p++;
    e = p;
    len = (uint32_t)(e - c);
    { const char *q = p; while (*q == '/') q++; last = (*q == 0); }
    if (len == 1 && c[0] == '.') continue;
    if (len == 2 && c[0] == '.' && c[1] == '.') {
      cur = cur->parent ? cur->parent : s->root;
      continue;
    }
    if (!is_dir(cur))
      return SD_E_NOT_A_DIRECTORY;
    ch = find_child(s, cur, c, len);
    if (!ch) {
      if (last) {
        r->parent = cur;
        r->leaf = c;
        r->leaf_len = len;
      }
      return SD_E_NOT_FOUND;
    }
    if (is_lnk(ch) && (!last || follow_last)) {
      resolved t;
      sd_err err = resolve_at(s, cur, ch->link, 1, depth + 1, &t);
      if (err != SD_OK)
        return err == SD_E_LINK_LOOP ? err : SD_E_NOT_FOUND;
      cur = t.node;
      if (last) {
        r->node = cur;
        return SD_OK;
      }
      continue;
    }
    if (last) {
      r->node = ch;
      r->parent = cur;
      r->leaf = c;
      r->leaf_len = len;
      return SD_OK;
    }
    cur = ch;
  }
}

static fnode *home_node(sd_sftp_session *s)
{
  resolved r;
  return resolve_at(s, s->root, s->home, 1, 0, &r) == SD_OK ? r.node : s->root;
}

static sd_err resolve(sd_sftp_session *s, const char *path, int follow, resolved *r)
{
  return resolve_at(s, home_node(s), path, follow, 0, r);
}

static void canon(fnode *n, char *out, size_t cap)
{
  char tmp[4096];
  size_t pos = sizeof(tmp) - 1;
  tmp[pos] = 0;
  if (!n->parent) {
    strcpy_s(out, cap, "/");
    return;
  }
  for (; n->parent; n = n->parent) {
    if (pos < n->nlen + 1) break;
    pos -= n->nlen;
    memcpy(tmp + pos, n->name, n->nlen);
    tmp[--pos] = '/';
  }
  strcpy_s(out, cap, tmp + pos);
}

static void attrs_of(const fnode *n, sd_sftp_attrs *a)
{
  memset(a, 0, sizeof(*a));
  a->valid = SD_SFTP_ATTR_SIZE | SD_SFTP_ATTR_UIDGID | SD_SFTP_ATTR_PERM | SD_SFTP_ATTR_TIMES;
  a->size = is_lnk(n) ? (n->link ? strlen(n->link) : 0) : n->size;
  a->uid = n->uid;
  a->gid = n->gid;
  a->perm = n->mode;
  a->atime = n->atime;
  a->mtime = n->mtime;
}

static int set_size(fnode *n, uint64_t size)
{
  if (size > n->cap) {
    uint64_t cap = n->cap ? n->cap : 4096;
    uint8_t *d;
    while (cap < size) cap *= 2;
    d = (uint8_t *)sd_realloc(n->data, (size_t)cap);
    if (!d) return 0;
    n->data = d;
    n->cap = cap;
  }
  if (size > n->size)
    memset(n->data + n->size, 0, (size_t)(size - n->size));
  n->size = size;
  return 1;
}

static void apply_attrs(fnode *n, const sd_sftp_attrs *a)
{
  if (a->valid & SD_SFTP_ATTR_SIZE) { set_size(n, a->size); n->mtime = now_unix(); }  /* ftruncate bumps mtime */
  if (a->valid & SD_SFTP_ATTR_PERM) n->mode = (n->mode & S_IFMT_) | (a->perm & 07777u);
  if (a->valid & SD_SFTP_ATTR_UIDGID) { n->uid = a->uid; n->gid = a->gid; }
  if (a->valid & SD_SFTP_ATTR_TIMES) { n->atime = a->atime; n->mtime = a->mtime; }
}

/* ---- files ---- */

static sd_sftp_file *file_new(sd_sftp_session *s, fnode *n, int dir, uint32_t oflags)
{
  sd_sftp_file *f = (sd_sftp_file *)must(sd_calloc(1, sizeof(*f)));
  f->s = s;
  f->n = n;
  f->is_dir = dir;
  f->oflags = oflags;
  f->refs = 1;
  f->gen = s->gen;
  f->fnext = s->files;
  if (s->files) s->files->fprev = f;
  s->files = f;
  attrs_of(n, &f->attrs_at_open);
  n->opens++;
  InterlockedIncrement(&s->open_handles);
  return f;
}

static void snap_free(sd_sftp_file *f)
{
  uint32_t i;
  for (i = 0; i < f->nsnap; i++)
    sd_free((void *)f->snap[i].name);
  sd_free(f->snap);
  f->snap = NULL;
  f->nsnap = 0;
}

void sd_sftp_file_addref(sd_sftp_file *f) { InterlockedIncrement(&f->refs); }

void sd_sftp_file_release(sd_sftp_file *f)
{
  sd_sftp_session *s;
  if (!f || InterlockedDecrement(&f->refs) != 0)
    return;
  s = f->s;
  EnterCriticalSection(&s->lock);
  if (--f->n->opens == 0 && f->n->unlinked)
    node_free(f->n);
  s->counts[FOP_CLOSE]++;
  if (f->fprev) f->fprev->fnext = f->fnext; else s->files = f->fnext;
  if (f->fnext) f->fnext->fprev = f->fprev;
  LeaveCriticalSection(&s->lock);
  InterlockedDecrement(&s->open_handles);
  snap_free(f);
  sd_free(f->path);
  sd_free(f);
}

/* ---- request queue ---- */

static void req_free(freq *r);

static sd_err submit(sd_sftp_session *s, freq *r, const sd_sftp_reqopt *o)
{
  if (r->f && r->f->stale && r->op != FOP_CLOSE && r->op != FOP_REOPEN) {
    /* Like sd_sftp: operations on a stale handle fail at once (01 10.6). */
    sd_sftp_file_release(r->f);
    req_free(r);
    return SD_E_STALE_HANDLE;
  }
  r->due = sd_tick_ms() + s->cfg.latency_ms;
  r->s = s;
  if (o && o->token_out)
    *o->token_out = (sd_sftp_req *)r;
  EnterCriticalSection(&s->lock);
  if (o && (o->flags & SD_SFTP_REQ_WAIT_READY) && o->timeout_ms > 0 && s->state != SD_SFTP_ST_READY) {
    r->deadline = sd_tick_ms() + o->timeout_ms;
    if (s->wait_tail) s->wait_tail->wnext = r; else s->wait_head = r;
    s->wait_tail = r;
  } else {
    if (s->tail) s->tail->next = r; else s->head = r;
    s->tail = r;
  }
  LeaveCriticalSection(&s->lock);
  SetEvent(s->ev);
  return SD_OK;
}

static freq *req_new(int op, sd_sftp_cb cb, void *ctx)
{
  freq *r = (freq *)sd_calloc(1, sizeof(*r));
  if (r) {
    r->op = op;
    r->cb = cb;
    r->ctx = ctx;
  }
  return r;
}

static freq *req_path(int op, const char *p1, const char *p2, sd_sftp_cb cb, void *ctx)
{
  freq *r = req_new(op, cb, ctx);
  if (!r) return NULL;
  r->p1 = p1 ? xstrndup(p1, strlen(p1)) : NULL;
  r->p2 = p2 ? xstrndup(p2, strlen(p2)) : NULL;
  return r;
}

static void req_free(freq *r)
{
  sd_free(r->p1);
  sd_free(r->p2);
  sd_free(r);
}

static void execute(sd_sftp_session *s, freq *r)
{
  sd_sftp_completion c;
  resolved rv;
  sd_err err = SD_OK;
  char namebuf[4096];
  sd_sftp_dirent *ents = NULL;
  memset(&c, 0, sizeof(c));
  c.sftp_status = UINT32_MAX;
  c.server_message = "";
  EnterCriticalSection(&s->lock);
  if (r->op >= 0 && r->op < FOP_COUNT) s->counts[r->op]++;
  if (r->op == FOP_OPEN && (r->flags & SD_SFTP_O_STRIPED)) s->striped_opens++;
  if (r->cancelled) {
    err = SD_E_CANCELLED;
  } else if (s->state != SD_SFTP_ST_READY) {
    err = SD_E_DISCONNECTED;
    c.maybe_executed = r->op == FOP_WRITE;  /* "sent" before the loss: effect unknown */
  } else if (r->f && r->f->stale && r->op != FOP_CLOSE && r->op != FOP_REOPEN) {
    err = SD_E_STALE_HANDLE;
  } else if (s->fail_op == r->op && s->fail_err != SD_OK) {
    err = s->fail_err;
    s->fail_err = SD_OK;
    s->fail_op = -1;
  } else {
    switch (r->op) {
      case FOP_OPEN: {
        uint32_t of = r->flags;
        err = resolve(s, r->p1, 1, &rv);
        if (err == SD_OK) {
          if ((of & SD_SFTP_O_CREAT) && (of & SD_SFTP_O_EXCL)) err = SD_E_EXISTS;
          else if (is_dir(rv.node)) err = SD_E_IS_A_DIRECTORY;
          else if ((rv.node->mode & S_IFMT_) != S_IFREG_) err = SD_E_ACCESS_DENIED;
          else if ((of & SD_SFTP_O_WRITE) && !(rv.node->mode & 0200u)) err = SD_E_ACCESS_DENIED;
          else {
            if (of & SD_SFTP_O_TRUNC) { set_size(rv.node, 0); rv.node->mtime = now_unix(); }
            c.u.open.file = file_new(s, rv.node, 0, of);
            c.u.open.file->path = xstrndup(r->p1, strlen(r->p1));
            attrs_of(rv.node, &c.u.open.attrs);
          }
        } else if (err == SD_E_NOT_FOUND && (of & SD_SFTP_O_CREAT) && rv.parent) {
          fnode *n = node_new(s, rv.parent, rv.leaf, rv.leaf_len,
                              S_IFREG_ | ((r->has_a && (r->a.valid & SD_SFTP_ATTR_PERM)) ? (r->a.perm & 0777u) : 0644u));
          err = SD_OK;
          c.u.open.file = file_new(s, n, 0, of);
          c.u.open.file->path = xstrndup(r->p1, strlen(r->p1));
          attrs_of(n, &c.u.open.attrs);
        }
        break;
      }
      case FOP_OPENDIR:
        err = resolve(s, r->p1, 1, &rv);
        if (err == SD_OK && !is_dir(rv.node)) err = SD_E_NOT_A_DIRECTORY;
        if (err == SD_OK) {
          c.u.open.file = file_new(s, rv.node, 1, 0);
          c.u.open.file->path = xstrndup(r->p1, strlen(r->p1));
        }
        break;
      case FOP_CLOSE:
        if (!r->f) { err = SD_E_INVALID_PARAM; break; }
        r->f->closed = 1;
        break;
      case FOP_REOPEN: {
        sd_sftp_file *f = r->f;
        if (!f) { err = SD_E_INVALID_PARAM; break; }
        err = resolve(s, f->path, 1, &rv);
        if (err == SD_OK && f->is_dir != is_dir(rv.node)) err = SD_E_NOT_FOUND;
        if (err == SD_OK && !f->is_dir && (rv.node->mode & S_IFMT_) != S_IFREG_) err = SD_E_ACCESS_DENIED;
        if (err == SD_OK) {
          if (rv.node != f->n) {
            rv.node->opens++;
            if (--f->n->opens == 0 && f->n->unlinked) node_free(f->n);
            f->n = rv.node;
          }
          f->gen = s->gen;
          f->pos = 0;
          InterlockedExchange(&f->stale, 0);
          attrs_of(f->n, &c.u.open.attrs);
          f->attrs_at_open = c.u.open.attrs;
          c.u.open.file = f;                /* same object, no extra reference */
        }
        break;
      }
      case FOP_READ: {
        fnode *n;
        if (!r->f) { err = SD_E_INVALID_PARAM; break; }
        n = r->f->n;
        if (r->off >= n->size) {
          err = SD_E_EOF;
        } else {
          uint64_t k = n->size - r->off;
          uint32_t got = (uint32_t)(k < r->len ? k : r->len);
          memcpy(r->buf, n->data + r->off, got);
          c.u.read.bytes = got;
        }
        break;
      }
      case FOP_WRITE: {
        fnode *n;
        if (!r->f) { err = SD_E_INVALID_PARAM; break; }
        n = r->f->n;
        if (!(r->f->oflags & SD_SFTP_O_WRITE)) err = SD_E_ACCESS_DENIED;
        else if (r->off + r->len > n->size && !set_size(n, r->off + r->len)) err = SD_E_NO_SPACE;
        else {
          memcpy(n->data + r->off, r->cbuf, r->len);
          n->mtime = now_unix();
          c.u.write.bytes = r->len;
        }
        break;
      }
      case FOP_READDIR: {
        sd_sftp_file *f = r->f;
        uint32_t k, take;
        if (!f) { err = SD_E_INVALID_PARAM; break; }
        if (!f->snapped) {
          fnode *ch;
          inj *in;
          uint32_t cnt = 0;
          char dpath[4096];
          canon(f->n, dpath, sizeof(dpath));
          for (ch = f->n->child; ch; ch = ch->next) cnt++;
          for (in = s->injected; in; in = in->next) if (strcmp(in->dir, dpath) == 0) cnt++;
          f->snap = (sd_sftp_dirent *)must(sd_calloc(cnt ? cnt : 1, sizeof(sd_sftp_dirent)));
          for (ch = f->n->child; ch; ch = ch->next) {
            sd_sftp_dirent *d = &f->snap[f->nsnap++];
            d->name = xstrndup(ch->name, ch->nlen);
            d->name_len = ch->nlen;
            d->longname = "";
            attrs_of(ch, &d->attrs);
          }
          for (in = s->injected; in; in = in->next) {
            if (strcmp(in->dir, dpath) == 0) {
              sd_sftp_dirent *d = &f->snap[f->nsnap++];
              d->name = xstrndup(in->name, in->len);
              d->name_len = in->len;
              d->longname = "";
              d->attrs.valid = SD_SFTP_ATTR_PERM | SD_SFTP_ATTR_SIZE;
              d->attrs.perm = in->mode;
            }
          }
          f->snapped = 1;
        }
        if (f->pos >= f->nsnap) {
          err = SD_E_EOF;
          break;
        }
        take = f->nsnap - f->pos;
        if (take > 50) take = 50;
        ents = (sd_sftp_dirent *)must(sd_calloc(take, sizeof(*ents)));
        for (k = 0; k < take; k++) ents[k] = f->snap[f->pos + k];
        f->pos += take;
        c.u.readdir.ents = ents;
        c.u.readdir.count = take;
        break;
      }
      case FOP_FSTAT:
        if (!r->f) { err = SD_E_INVALID_PARAM; break; }
        attrs_of(r->f->n, &c.u.stat.attrs);
        break;
      case FOP_FSETSTAT:
        if (!r->f) { err = SD_E_INVALID_PARAM; break; }
        apply_attrs(r->f->n, &r->a);
        break;
      case FOP_FSYNC:
        if (!(s->cfg.ext & SD_SFTP_EXT_FSYNC)) err = SD_E_UNSUPPORTED;
        break;
      case FOP_STAT:
      case FOP_LSTAT:
        err = resolve(s, r->p1, r->op == FOP_STAT, &rv);
        if (err == SD_OK) attrs_of(rv.node, &c.u.stat.attrs);
        break;
      case FOP_SETSTAT:
        err = resolve(s, r->p1, !(r->flags & 1), &rv);
        if (err == SD_OK) apply_attrs(rv.node, &r->a);
        break;
      case FOP_MKDIR:
        err = resolve(s, r->p1, 0, &rv);
        if (err == SD_OK) err = SD_E_EXISTS;
        else if (err == SD_E_NOT_FOUND && rv.parent) {
          node_new(s, rv.parent, rv.leaf, rv.leaf_len,
                   S_IFDIR_ | ((r->a.valid & SD_SFTP_ATTR_PERM) ? (r->a.perm & 0777u) : 0755u));
          err = SD_OK;
        }
        break;
      case FOP_RMDIR:
        err = resolve(s, r->p1, 0, &rv);
        if (err == SD_OK) {
          if (!is_dir(rv.node)) err = SD_E_NOT_A_DIRECTORY;
          else if (rv.node->child) err = SD_E_NOT_EMPTY;
          else if (!rv.node->parent) err = SD_E_ACCESS_DENIED;
          else node_drop(rv.node);
        }
        break;
      case FOP_REMOVE:
        err = resolve(s, r->p1, 0, &rv);
        if (err == SD_OK) {
          if (is_dir(rv.node)) err = SD_E_IS_A_DIRECTORY;
          else node_drop(rv.node);
        }
        break;
      case FOP_RENAME: {
        resolved tv;
        fnode *src, *p;
        err = resolve(s, r->p1, 0, &rv);
        if (err != SD_OK) break;
        src = rv.node;
        err = resolve(s, r->p2, 0, &tv);
        if (err == SD_OK) {
          fnode *t = tv.node;
          if (t == src) { err = SD_OK; break; }
          if (!(r->flags & SD_SFTP_RENAME_OVERWRITE)) { err = SD_E_EXISTS; break; }
          if (!(s->cfg.ext & SD_SFTP_EXT_POSIX_RENAME)) { err = SD_E_UNSUPPORTED; break; }
          if (is_dir(t) && !is_dir(src)) { err = SD_E_IS_A_DIRECTORY; break; }
          if (!is_dir(t) && is_dir(src)) { err = SD_E_NOT_A_DIRECTORY; break; }
          if (is_dir(t) && t->child) { err = SD_E_NOT_EMPTY; break; }
          tv.parent = t->parent;
          node_drop(t);
        } else if (err != SD_E_NOT_FOUND || !tv.parent) {
          break;
        }
        for (p = tv.parent; p; p = p->parent)
          if (p == src) break;
        if (p) { err = SD_E_INVALID_PARAM; break; }
        node_unlink(src);
        sd_free(src->name);
        src->name = xstrndup(tv.leaf, tv.leaf_len);
        src->nlen = tv.leaf_len;
        src->parent = tv.parent;
        src->next = tv.parent->child;
        tv.parent->child = src;
        err = SD_OK;
        break;
      }
      case FOP_READLINK:
        err = resolve(s, r->p1, 0, &rv);
        if (err == SD_OK && !is_lnk(rv.node)) err = SD_E_INVALID_PARAM;
        if (err == SD_OK) {
          strcpy_s(namebuf, sizeof(namebuf), rv.node->link);
          c.u.name.path = namebuf;
          c.u.name.len = (uint32_t)strlen(namebuf);
        }
        break;
      case FOP_REALPATH:
        err = resolve(s, r->p1, 1, &rv);
        if (err == SD_OK) {
          canon(rv.node, namebuf, sizeof(namebuf));
          c.u.name.path = namebuf;
          c.u.name.len = (uint32_t)strlen(namebuf);
        }
        break;
      case FOP_STATVFS:
        if (!(s->cfg.ext & SD_SFTP_EXT_STATVFS)) { err = SD_E_UNSUPPORTED; break; }
        c.u.statvfs.v.bsize = 4096;
        c.u.statvfs.v.frsize = 4096;
        c.u.statvfs.v.blocks = 1000000;
        c.u.statvfs.v.bfree = 500000;
        c.u.statvfs.v.bavail = 400000;
        c.u.statvfs.v.namemax = 255;
        break;
      default:
        err = SD_E_UNSUPPORTED;
    }
  }
  LeaveCriticalSection(&s->lock);
  c.err = err;
  if (err != SD_E_DISCONNECTED) c.maybe_executed = 0;
  r->cb(r->ctx, &c);
  sd_free(ents);
  if (r->f)
    sd_sftp_file_release(r->f);           /* the request's own reference */
}

/* s->lock held. Once READY, WAIT_READY requests join the queue in submission order (their latency starts
   now). Otherwise the ones cancelled or past their deadline are unlinked and returned (out_next) to be
   completed outside the lock; *wait is lowered to the next deadline. */
static freq *wait_scan(sd_sftp_session *s, uint64_t now, DWORD *wait)
{
  freq *r, *out = NULL, **pp;
  if (!s->wait_head)
    return NULL;
  if (s->state == SD_SFTP_ST_READY) {
    while ((r = s->wait_head) != NULL) {
      s->wait_head = r->wnext;
      r->wnext = NULL;
      r->due = now + s->cfg.latency_ms;
      if (s->tail) s->tail->next = r; else s->head = r;
      s->tail = r;
    }
    s->wait_tail = NULL;
    return NULL;
  }
  for (pp = &s->wait_head; (r = *pp) != NULL;) {
    if (r->cancelled || now >= r->deadline) {
      *pp = r->wnext;
      r->wnext = NULL;
      r->expire_err = r->cancelled ? SD_E_CANCELLED : SD_E_TIMEOUT;
      r->out_next = out;
      out = r;
      continue;
    }
    if (r->deadline - now < *wait)
      *wait = (DWORD)(r->deadline - now);
    pp = &r->wnext;
  }
  for (r = s->wait_head; r && r->wnext; r = r->wnext)
    ;
  s->wait_tail = r;
  return out;
}

/* Completes a request that never reached the queue (outside s->lock). */
static void complete_waiting(freq *r)
{
  sd_sftp_completion c;
  memset(&c, 0, sizeof(c));
  c.sftp_status = UINT32_MAX;
  c.server_message = "";
  c.err = r->expire_err;
  r->cb(r->ctx, &c);
  req_free(r);
}

static unsigned __stdcall worker(void *arg)
{
  sd_sftp_session *s = (sd_sftp_session *)arg;
  while (!s->stop) {
    freq *r, *expired;
    DWORD wait = 100;
    uint64_t now = sd_tick_ms();
    EnterCriticalSection(&s->lock);
    expired = wait_scan(s, now, &wait);
    r = s->head;
    if (r && r->due > now) {
      if ((DWORD)(r->due - now) < wait)
        wait = (DWORD)(r->due - now);       /* FIFO with a constant latency: the head is the earliest */
      r = NULL;
    } else if (r) {
      s->head = r->next;
      if (!s->head) s->tail = NULL;
      r->next = NULL;
      if (r->op == FOP_WRITE && s->hold && s->state == SD_SFTP_ST_READY && !r->cancelled) {
        if (s->held_tail) s->held_tail->next = r; else s->held_head = r;
        s->held_tail = r;
        s->nheld++;
        r = NULL;
        wait = 0;
      }
    }
    LeaveCriticalSection(&s->lock);
    while (expired) {
      freq *x = expired;
      expired = x->out_next;
      complete_waiting(x);
    }
    if (!r) {
      if (wait) WaitForSingleObject(s->ev, wait);
      continue;
    }
    execute(s, r);
    req_free(r);
  }
  return 0;
}

/* ---- API ---- */

sd_sftp_session *fake_session_create(const fake_config *cfg)
{
  sd_sftp_session *s = (sd_sftp_session *)must(sd_calloc(1, sizeof(*s)));
  const char *home;
  InitializeCriticalSection(&s->lock);
  if (cfg) s->cfg = *cfg;
  if (!s->cfg.uid) s->cfg.uid = 1000;
  if (!s->cfg.gid) s->cfg.gid = 1000;
  if (!s->cfg.max_read) s->cfg.max_read = 256 * 1024;
  if (!s->cfg.max_write) s->cfg.max_write = 256 * 1024;
  if (s->cfg.no_ext) s->cfg.ext = 0;
  else if (!s->cfg.ext) s->cfg.ext = SD_SFTP_EXT_POSIX_RENAME | SD_SFTP_EXT_STATVFS | SD_SFTP_EXT_FSYNC;
  home = s->cfg.home ? s->cfg.home : "/home/user";
  strcpy_s(s->home, sizeof(s->home), home);
  s->cfg.home = s->home;
  s->fail_op = -1;
  s->root = node_new(s, NULL, "", 0, S_IFDIR_ | 0755u);
  s->root->uid = 0;
  {
    /* mkdir -p home */
    fnode *cur = s->root;
    {
      const char *q = home;
      while (*q) {
        const char *c;
        fnode *ch;
        while (*q == '/') q++;
        if (!*q) break;
        c = q;
        while (*q && *q != '/') q++;
        ch = find_child(s, cur, c, (uint32_t)(q - c));
        if (!ch) ch = node_new(s, cur, c, (uint32_t)(q - c), S_IFDIR_ | 0755u);
        cur = ch;
      }
    }
  }
  if (s->cfg.home_uid_set) {
    resolved hr;
    if (resolve_at(s, s->root, s->home, 1, 0, &hr) == SD_OK) hr.node->uid = s->cfg.home_uid;
  }
  s->gen = 1;
  s->state = SD_SFTP_ST_READY;
  s->ev = CreateEventW(NULL, FALSE, FALSE, NULL);
  s->thread = (HANDLE)_beginthreadex(NULL, 0, worker, s, 0, NULL);
  return s;
}

void fake_session_destroy(sd_sftp_session *s)
{
  inj *in;
  if (!s) return;
  InterlockedExchange(&s->stop, 1);
  SetEvent(s->ev);
  WaitForSingleObject(s->thread, INFINITE);
  CloseHandle(s->thread);
  CloseHandle(s->ev);
  while (s->head) {
    freq *r = s->head;
    s->head = r->next;
    req_free(r);
  }
  while (s->held_head) {
    freq *r = s->held_head;
    s->held_head = r->next;
    req_free(r);
  }
  while (s->wait_head) {
    freq *r = s->wait_head;
    s->wait_head = r->wnext;
    req_free(r);
  }
  while ((in = s->injected) != NULL) {
    s->injected = in->next;
    sd_free(in->dir);
    sd_free(in->name);
    sd_free(in);
  }
  node_free(s->root);
  DeleteCriticalSection(&s->lock);
  sd_free(s);
}

#define REQ_OR_FAIL(r) do { if (!(r)) return SD_E_NO_MEMORY; } while (0)

sd_err sd_sftp_open(sd_sftp_session *s, const char *path, uint32_t oflags, const sd_sftp_attrs *create_attrs,
                    sd_sftp_file *same_channel_as, const sd_sftp_reqopt *o, sd_sftp_cb cb, void *ctx)
{
  freq *r = req_path(FOP_OPEN, path, NULL, cb, ctx);
  (void)same_channel_as;
  REQ_OR_FAIL(r);
  r->flags = oflags;
  if (create_attrs) { r->a = *create_attrs; r->has_a = 1; }
  return submit(s, r, o);
}

sd_err sd_sftp_opendir(sd_sftp_session *s, const char *path, const sd_sftp_reqopt *o, sd_sftp_cb cb, void *ctx)
{
  freq *r = req_path(FOP_OPENDIR, path, NULL, cb, ctx);
  REQ_OR_FAIL(r);
  return submit(s, r, o);
}

static sd_err file_req(int op, sd_sftp_file *f, const sd_sftp_reqopt *o, sd_sftp_cb cb, void *ctx, freq **out)
{
  freq *r = req_new(op, cb, ctx);
  REQ_OR_FAIL(r);
  r->f = f;
  sd_sftp_file_addref(f);
  *out = r;
  (void)o;
  return SD_OK;
}

sd_err sd_sftp_close(sd_sftp_file *f, const sd_sftp_reqopt *o, sd_sftp_cb cb, void *ctx)
{
  freq *r;
  sd_err e = file_req(FOP_CLOSE, f, o, cb, ctx, &r);
  if (e != SD_OK) return e;
  sd_sftp_file_release(f);                 /* the caller's reference moves to the request */
  return submit(f->s, r, o);
}

sd_err sd_sftp_read(sd_sftp_file *f, uint64_t off, void *buf, uint32_t len, const sd_sftp_reqopt *o,
                    sd_sftp_cb cb, void *ctx)
{
  freq *r;
  sd_err e = file_req(FOP_READ, f, o, cb, ctx, &r);
  if (e != SD_OK) return e;
  r->off = off; r->buf = buf; r->len = len;
  return submit(f->s, r, o);
}

sd_err sd_sftp_write(sd_sftp_file *f, uint64_t off, const void *buf, uint32_t len, const sd_sftp_reqopt *o,
                     sd_sftp_cb cb, void *ctx)
{
  freq *r;
  sd_err e = file_req(FOP_WRITE, f, o, cb, ctx, &r);
  if (e != SD_OK) return e;
  r->off = off; r->cbuf = buf; r->len = len;
  return submit(f->s, r, o);
}

sd_err sd_sftp_readdir(sd_sftp_file *dir, const sd_sftp_reqopt *o, sd_sftp_cb cb, void *ctx)
{
  freq *r;
  sd_err e = file_req(FOP_READDIR, dir, o, cb, ctx, &r);
  if (e != SD_OK) return e;
  return submit(dir->s, r, o);
}

sd_err sd_sftp_fstat(sd_sftp_file *f, const sd_sftp_reqopt *o, sd_sftp_cb cb, void *ctx)
{
  freq *r;
  sd_err e = file_req(FOP_FSTAT, f, o, cb, ctx, &r);
  if (e != SD_OK) return e;
  return submit(f->s, r, o);
}

sd_err sd_sftp_fsetstat(sd_sftp_file *f, const sd_sftp_attrs *a, const sd_sftp_reqopt *o, sd_sftp_cb cb, void *ctx)
{
  freq *r;
  sd_err e = file_req(FOP_FSETSTAT, f, o, cb, ctx, &r);
  if (e != SD_OK) return e;
  r->a = *a;
  return submit(f->s, r, o);
}

sd_err sd_sftp_fsync(sd_sftp_file *f, const sd_sftp_reqopt *o, sd_sftp_cb cb, void *ctx)
{
  freq *r;
  sd_err e = file_req(FOP_FSYNC, f, o, cb, ctx, &r);
  if (e != SD_OK) return e;
  return submit(f->s, r, o);
}

sd_err sd_sftp_stat(sd_sftp_session *s, const char *path, const sd_sftp_reqopt *o, sd_sftp_cb cb, void *ctx)
{
  freq *r = req_path(FOP_STAT, path, NULL, cb, ctx);
  REQ_OR_FAIL(r);
  return submit(s, r, o);
}

sd_err sd_sftp_lstat(sd_sftp_session *s, const char *path, const sd_sftp_reqopt *o, sd_sftp_cb cb, void *ctx)
{
  freq *r = req_path(FOP_LSTAT, path, NULL, cb, ctx);
  REQ_OR_FAIL(r);
  return submit(s, r, o);
}

sd_err sd_sftp_setstat(sd_sftp_session *s, const char *path, const sd_sftp_attrs *a, int no_follow,
                       const sd_sftp_reqopt *o, sd_sftp_cb cb, void *ctx)
{
  freq *r = req_path(FOP_SETSTAT, path, NULL, cb, ctx);
  REQ_OR_FAIL(r);
  r->a = *a;
  r->flags = no_follow ? 1u : 0u;
  return submit(s, r, o);
}

sd_err sd_sftp_mkdir(sd_sftp_session *s, const char *path, const sd_sftp_attrs *a, const sd_sftp_reqopt *o,
                     sd_sftp_cb cb, void *ctx)
{
  freq *r = req_path(FOP_MKDIR, path, NULL, cb, ctx);
  REQ_OR_FAIL(r);
  if (a) r->a = *a;
  return submit(s, r, o);
}

sd_err sd_sftp_rmdir(sd_sftp_session *s, const char *path, const sd_sftp_reqopt *o, sd_sftp_cb cb, void *ctx)
{
  freq *r = req_path(FOP_RMDIR, path, NULL, cb, ctx);
  REQ_OR_FAIL(r);
  return submit(s, r, o);
}

sd_err sd_sftp_remove(sd_sftp_session *s, const char *path, const sd_sftp_reqopt *o, sd_sftp_cb cb, void *ctx)
{
  freq *r = req_path(FOP_REMOVE, path, NULL, cb, ctx);
  REQ_OR_FAIL(r);
  return submit(s, r, o);
}

sd_err sd_sftp_rename(sd_sftp_session *s, const char *from, const char *to, uint32_t flags,
                      const sd_sftp_reqopt *o, sd_sftp_cb cb, void *ctx)
{
  freq *r = req_path(FOP_RENAME, from, to, cb, ctx);
  REQ_OR_FAIL(r);
  r->flags = flags;
  return submit(s, r, o);
}

sd_err sd_sftp_readlink(sd_sftp_session *s, const char *path, const sd_sftp_reqopt *o, sd_sftp_cb cb, void *ctx)
{
  freq *r = req_path(FOP_READLINK, path, NULL, cb, ctx);
  REQ_OR_FAIL(r);
  return submit(s, r, o);
}

sd_err sd_sftp_realpath(sd_sftp_session *s, const char *path, const sd_sftp_reqopt *o, sd_sftp_cb cb, void *ctx)
{
  freq *r = req_path(FOP_REALPATH, path, NULL, cb, ctx);
  REQ_OR_FAIL(r);
  return submit(s, r, o);
}

sd_err sd_sftp_statvfs_path(sd_sftp_session *s, const char *path, const sd_sftp_reqopt *o, sd_sftp_cb cb,
                            void *ctx)
{
  freq *r = req_path(FOP_STATVFS, path, NULL, cb, ctx);
  REQ_OR_FAIL(r);
  return submit(s, r, o);
}

sd_err sd_sftp_cancel(sd_sftp_req *r)
{
  if (r) {
    freq *q = (freq *)r;
    InterlockedExchange(&q->cancelled, 1);
    SetEvent(q->s->ev);                   /* a waiter is woken to complete it */
  }
  return SD_OK;
}

int sd_sftp_has_ext(const sd_sftp_session *s, uint32_t ext_bit)
{
  return s->state == SD_SFTP_ST_READY && (s->cfg.ext & ext_bit) != 0;
}

sd_sftp_state sd_sftp_session_state(const sd_sftp_session *s) { return s->state; }

sd_err sd_sftp_session_info(sd_sftp_session *s, sd_sftp_server_info *copy_out, char *home_buf, size_t home_len)
{
  memset(copy_out, 0, sizeof(*copy_out));
  copy_out->generation = s->gen;
  copy_out->version = 3;
  copy_out->ext = s->cfg.ext;
  copy_out->limits.max_packet = 256 * 1024 + 1024;
  copy_out->limits.max_read = s->cfg.max_read;
  copy_out->limits.max_write = s->cfg.max_write;
  copy_out->limits.max_open_handles = 1024;
  copy_out->channels = 1;
  copy_out->connections = s->cfg.connections ? s->cfg.connections : 1;
  if (home_buf && home_len) {
    strcpy_s(home_buf, home_len, s->home);
    copy_out->home = home_buf;
  }
  copy_out->identity.source = SD_SFTP_ID_HOME_OWNER;
  copy_out->identity.uid = s->cfg.home_uid_set ? s->cfg.home_uid : s->cfg.uid;
  copy_out->identity.gid = s->cfg.gid;
  return SD_OK;
}

uint32_t sd_sftp_session_generation(const sd_sftp_session *s) { return s->gen; }

sd_err sd_sftp_file_get_info(sd_sftp_file *f, sd_sftp_file_info *out)
{
  memset(out, 0, sizeof(*out));
  out->path = f->path ? f->path : "";
  out->oflags = f->oflags;
  out->is_dir = f->is_dir;
  out->generation = f->gen;
  out->stale = (int)InterlockedCompareExchange(&f->stale, 0, 0);
  out->attrs_at_open = f->attrs_at_open;
  return SD_OK;
}

sd_err sd_sftp_file_reopen(sd_sftp_file *f, const sd_sftp_reqopt *o, sd_sftp_cb cb, void *ctx)
{
  freq *r;
  if (!f || !cb || !f->stale)
    return SD_E_INVALID_PARAM;
  if (f->s->state != SD_SFTP_ST_READY)
    return SD_E_DISCONNECTED;
  r = req_new(FOP_REOPEN, cb, ctx);
  REQ_OR_FAIL(r);
  r->f = f;
  sd_sftp_file_addref(f);
  return submit(f->s, r, o);
}

/* ---- test hooks ---- */

static fnode *create_at(sd_sftp_session *s, const char *path, uint32_t mode, int *err)
{
  resolved rv;
  sd_err e = resolve(s, path, 0, &rv);
  *err = 0;
  if (e == SD_OK) { *err = 1; return NULL; }
  if (e != SD_E_NOT_FOUND || !rv.parent) { *err = 2; return NULL; }
  return node_new(s, rv.parent, rv.leaf, rv.leaf_len, mode);
}

int fake_mkdir(sd_sftp_session *s, const char *path, uint32_t perm)
{
  int err;
  EnterCriticalSection(&s->lock);
  create_at(s, path, S_IFDIR_ | (perm & 07777u), &err);
  LeaveCriticalSection(&s->lock);
  return err;
}

int fake_put(sd_sftp_session *s, const char *path, const void *data, size_t len, uint32_t perm)
{
  int err;
  fnode *n;
  EnterCriticalSection(&s->lock);
  n = create_at(s, path, S_IFREG_ | (perm & 07777u), &err);
  if (n && len) {
    set_size(n, len);
    memcpy(n->data, data, len);
  }
  LeaveCriticalSection(&s->lock);
  return err;
}

int fake_symlink(sd_sftp_session *s, const char *path, const char *target)
{
  int err;
  fnode *n;
  EnterCriticalSection(&s->lock);
  n = create_at(s, path, S_IFLNK_ | 0777u, &err);
  if (n) n->link = xstrndup(target, strlen(target));
  LeaveCriticalSection(&s->lock);
  return err;
}

int fake_mkfifo(sd_sftp_session *s, const char *path)
{
  int err;
  EnterCriticalSection(&s->lock);
  create_at(s, path, S_IFIFO_ | 0644u, &err);
  LeaveCriticalSection(&s->lock);
  return err;
}

int fake_set_owner(sd_sftp_session *s, const char *path, uint32_t uid, uint32_t gid)
{
  resolved rv;
  int r = -1;
  EnterCriticalSection(&s->lock);
  if (resolve(s, path, 0, &rv) == SD_OK) { rv.node->uid = uid; rv.node->gid = gid; r = 0; }
  LeaveCriticalSection(&s->lock);
  return r;
}

long long fake_get(sd_sftp_session *s, const char *path, void *buf, size_t cap)
{
  resolved rv;
  long long r = -1;
  EnterCriticalSection(&s->lock);
  if (resolve(s, path, 1, &rv) == SD_OK && !is_dir(rv.node)) {
    r = (long long)rv.node->size;
    if (buf && cap) memcpy(buf, rv.node->data, (size_t)(rv.node->size < cap ? rv.node->size : cap));
  }
  LeaveCriticalSection(&s->lock);
  return r;
}

int fake_exists(sd_sftp_session *s, const char *path)
{
  resolved rv;
  int r;
  EnterCriticalSection(&s->lock);
  r = resolve(s, path, 0, &rv) == SD_OK;
  LeaveCriticalSection(&s->lock);
  return r;
}

uint32_t fake_mode(sd_sftp_session *s, const char *path)
{
  resolved rv;
  uint32_t m = 0;
  EnterCriticalSection(&s->lock);
  if (resolve(s, path, 0, &rv) == SD_OK) m = rv.node->mode;
  LeaveCriticalSection(&s->lock);
  return m;
}

int64_t fake_mtime(sd_sftp_session *s, const char *path)
{
  resolved rv;
  int64_t m = -1;
  EnterCriticalSection(&s->lock);
  if (resolve(s, path, 0, &rv) == SD_OK) m = rv.node->mtime;
  LeaveCriticalSection(&s->lock);
  return m;
}

void fake_inject_dirent(sd_sftp_session *s, const char *dir, const char *name, uint32_t len, uint32_t mode)
{
  inj *in = (inj *)must(sd_calloc(1, sizeof(*in)));
  in->dir = xstrndup(dir, strlen(dir));
  in->name = (char *)must(sd_alloc(len + 1));
  memcpy(in->name, name, len);
  in->name[len] = 0;
  in->len = len;
  in->mode = mode;
  EnterCriticalSection(&s->lock);
  in->next = s->injected;
  s->injected = in;
  LeaveCriticalSection(&s->lock);
}

uint32_t fake_count(sd_sftp_session *s, int op)
{
  uint32_t c;
  EnterCriticalSection(&s->lock);
  c = s->counts[op];
  LeaveCriticalSection(&s->lock);
  return c;
}

void fake_reset_counts(sd_sftp_session *s)
{
  EnterCriticalSection(&s->lock);
  memset(s->counts, 0, sizeof(s->counts));
  s->striped_opens = 0;
  LeaveCriticalSection(&s->lock);
}

uint32_t fake_striped_opens(sd_sftp_session *s)
{
  uint32_t c;
  EnterCriticalSection(&s->lock);
  c = s->striped_opens;
  LeaveCriticalSection(&s->lock);
  return c;
}

uint32_t fake_open_handles(sd_sftp_session *s) { return (uint32_t)InterlockedCompareExchange(&s->open_handles, 0, 0); }

void fake_set_state(sd_sftp_session *s, sd_sftp_state st)
{
  EnterCriticalSection(&s->lock);
  s->state = st;
  LeaveCriticalSection(&s->lock);
}

void fake_fail_next(sd_sftp_session *s, int op, sd_err err)
{
  EnterCriticalSection(&s->lock);
  s->fail_op = op;
  s->fail_err = err;
  LeaveCriticalSection(&s->lock);
}

/* ---- connection loss simulation ---- */

static void requeue_held_front(sd_sftp_session *s)
{
  /* s->lock held: held writes go back to the front of the queue, in order. */
  if (!s->held_head)
    return;
  s->held_tail->next = s->head;
  if (!s->head) s->tail = s->held_tail;
  s->head = s->held_head;
  s->held_head = s->held_tail = NULL;
  s->nheld = 0;
}

void fake_disconnect(sd_sftp_session *s)
{
  sd_sftp_file *f;
  EnterCriticalSection(&s->lock);
  s->state = SD_SFTP_ST_DISCONNECTED;
  for (f = s->files; f; f = f->fnext)
    InterlockedExchange(&f->stale, 1);
  requeue_held_front(s);                   /* they complete with SD_E_DISCONNECTED, maybe_executed */
  LeaveCriticalSection(&s->lock);
  SetEvent(s->ev);
}

void fake_reconnect(sd_sftp_session *s)
{
  EnterCriticalSection(&s->lock);
  s->gen++;
  s->state = SD_SFTP_ST_READY;
  LeaveCriticalSection(&s->lock);
  SetEvent(s->ev);
}

void fake_hold_writes(sd_sftp_session *s, int on)
{
  EnterCriticalSection(&s->lock);
  s->hold = on;
  if (!on)
    requeue_held_front(s);
  LeaveCriticalSection(&s->lock);
  SetEvent(s->ev);
}

uint32_t fake_held_writes(sd_sftp_session *s)
{
  uint32_t n;
  EnterCriticalSection(&s->lock);
  n = s->nheld;
  LeaveCriticalSection(&s->lock);
  return n;
}

int fake_overwrite(sd_sftp_session *s, const char *path, const void *data, size_t len, int64_t mtime)
{
  resolved rv;
  int r = -1;
  EnterCriticalSection(&s->lock);
  if (resolve(s, path, 1, &rv) == SD_OK && !is_dir(rv.node) && set_size(rv.node, len)) {
    if (len) memcpy(rv.node->data, data, len);
    rv.node->mtime = mtime ? mtime : now_unix();
    r = 0;
  }
  LeaveCriticalSection(&s->lock);
  return r;
}

int fake_set_mtime(sd_sftp_session *s, const char *path, int64_t mtime)
{
  resolved rv;
  int r = -1;
  EnterCriticalSection(&s->lock);
  if (resolve(s, path, 0, &rv) == SD_OK) {
    rv.node->mtime = mtime;
    rv.node->atime = mtime;
    r = 0;
  }
  LeaveCriticalSection(&s->lock);
  return r;
}
