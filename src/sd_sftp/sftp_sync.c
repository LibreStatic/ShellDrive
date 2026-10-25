/* Blocking wrappers for the CLI and tools (01 §10.5). Never on an I/O thread. */
#include <string.h>

#include "sd_base/sd_mem.h"
#include "sftp_internal.h"

typedef struct sync_wait {
  sd_event ev;
  sd_err err;
  sd_sftp_attrs attrs;
  sd_sftp_file *file;
  uint32_t bytes;
  char *path_out; size_t path_cap;
} sync_wait;

static void sync_cb(void *ctx, const sd_sftp_completion *c)
{
  sync_wait *w = (sync_wait *)ctx;
  w->err = c->err;
  w->attrs = c->u.stat.attrs;
  w->attrs.ext = NULL;
  w->attrs.ext_count = 0;
  sd_event_set(&w->ev);
}

static void sync_open_cb(void *ctx, const sd_sftp_completion *c)
{
  sync_wait *w = (sync_wait *)ctx;
  w->err = c->err;
  w->file = c->err == SD_OK ? c->u.open.file : NULL;
  w->attrs = c->u.open.attrs;
  w->attrs.ext = NULL;
  w->attrs.ext_count = 0;
  sd_event_set(&w->ev);
}

static void sync_rw_cb(void *ctx, const sd_sftp_completion *c)
{
  sync_wait *w = (sync_wait *)ctx;
  w->err = c->err;
  w->bytes = c->u.read.bytes;     /* read.bytes and write.bytes share the first member */
  sd_event_set(&w->ev);
}

static void sync_name_cb(void *ctx, const sd_sftp_completion *c)
{
  sync_wait *w = (sync_wait *)ctx;
  w->err = c->err;
  if (c->err == SD_OK) {
    if (c->u.name.len >= w->path_cap) w->err = SD_E_NAME_TOO_LONG;
    else { memcpy(w->path_out, c->u.name.path, c->u.name.len); w->path_out[c->u.name.len] = 0; }
  }
  sd_event_set(&w->ev);
}

static sd_err sync_begin(sd_sftp_session *s, sync_wait *w)
{
  memset(w, 0, sizeof(*w));
  if (!s) return SD_E_INVALID_PARAM;
  if (sd_sftp_session_is_io_thread(s)) return SD_E_WOULD_DEADLOCK;
  return sd_event_init(&w->ev, 1, 0);
}

static sd_err sync_end(sync_wait *w, sd_err submit)
{
  if (submit == SD_OK) {
    (void)sd_event_wait(&w->ev, SD_WAIT_INFINITE);   /* the request deadline bounds the wait */
    submit = w->err;
  }
  sd_event_destroy(&w->ev);
  return submit;
}

static sd_sftp_reqopt sync_opt(uint32_t timeout_ms)
{
  sd_sftp_reqopt o;
  o.flags = 0;
  o.timeout_ms = timeout_ms;
  o.token_out = NULL;
  return o;
}

static sd_sftp_session *file_session(sd_sftp_file *f) { return f ? f->s : NULL; }

sd_err sd_sftp_stat_sync(sd_sftp_session *s, const char *path, sd_sftp_attrs *out, uint32_t timeout_ms)
{
  sync_wait w; sd_sftp_reqopt o = sync_opt(timeout_ms);
  sd_err e = sync_begin(s, &w);
  if (e != SD_OK) return e;
  e = sync_end(&w, sd_sftp_stat(s, path, &o, sync_cb, &w));
  if (e == SD_OK && out) *out = w.attrs;
  return e;
}

sd_err sd_sftp_lstat_sync(sd_sftp_session *s, const char *path, sd_sftp_attrs *out, uint32_t timeout_ms)
{
  sync_wait w; sd_sftp_reqopt o = sync_opt(timeout_ms);
  sd_err e = sync_begin(s, &w);
  if (e != SD_OK) return e;
  e = sync_end(&w, sd_sftp_lstat(s, path, &o, sync_cb, &w));
  if (e == SD_OK && out) *out = w.attrs;
  return e;
}

sd_err sd_sftp_realpath_sync(sd_sftp_session *s, const char *path, char *out, size_t cap, uint32_t timeout_ms)
{
  sync_wait w; sd_sftp_reqopt o = sync_opt(timeout_ms);
  sd_err e;
  if (!out || cap == 0) return SD_E_INVALID_PARAM;
  e = sync_begin(s, &w);
  if (e != SD_OK) return e;
  w.path_out = out;
  w.path_cap = cap;
  return sync_end(&w, sd_sftp_realpath(s, path, &o, sync_name_cb, &w));
}

sd_err sd_sftp_open_sync(sd_sftp_session *s, const char *path, uint32_t oflags, const sd_sftp_attrs *create_attrs,
                         sd_sftp_file **out, sd_sftp_attrs *attrs_out, uint32_t timeout_ms)
{
  sync_wait w; sd_sftp_reqopt o = sync_opt(timeout_ms);
  sd_err e;
  if (!out) return SD_E_INVALID_PARAM;
  *out = NULL;
  e = sync_begin(s, &w);
  if (e != SD_OK) return e;
  e = sync_end(&w, sd_sftp_open(s, path, oflags, create_attrs, NULL, &o, sync_open_cb, &w));
  if (e == SD_OK) { *out = w.file; if (attrs_out) *attrs_out = w.attrs; }
  return e;
}

sd_err sd_sftp_close_sync(sd_sftp_file *f, uint32_t timeout_ms)
{
  sync_wait w; sd_sftp_reqopt o = sync_opt(timeout_ms);
  sd_err e = sync_begin(file_session(f), &w);
  if (e != SD_OK) { if (e != SD_E_INVALID_PARAM) sd_sftp_file_release(f); return e; }
  return sync_end(&w, sd_sftp_close(f, &o, sync_cb, &w));
}

sd_err sd_sftp_read_sync(sd_sftp_file *f, uint64_t off, void *buf, uint32_t len, uint32_t *got, uint32_t timeout_ms)
{
  sync_wait w; sd_sftp_reqopt o = sync_opt(timeout_ms);
  sd_err e = sync_begin(file_session(f), &w);
  if (got) *got = 0;
  if (e != SD_OK) return e;
  e = sync_end(&w, sd_sftp_read(f, off, buf, len, &o, sync_rw_cb, &w));
  if (got && (e == SD_OK || e == SD_E_EOF)) *got = w.bytes;
  return e;
}

sd_err sd_sftp_write_sync(sd_sftp_file *f, uint64_t off, const void *buf, uint32_t len, uint32_t timeout_ms)
{
  sync_wait w; sd_sftp_reqopt o = sync_opt(timeout_ms);
  sd_err e = sync_begin(file_session(f), &w);
  if (e != SD_OK) return e;
  return sync_end(&w, sd_sftp_write(f, off, buf, len, &o, sync_rw_cb, &w));
}

sd_err sd_sftp_mkdir_sync(sd_sftp_session *s, const char *path, const sd_sftp_attrs *a, uint32_t timeout_ms)
{
  sync_wait w; sd_sftp_reqopt o = sync_opt(timeout_ms);
  sd_err e = sync_begin(s, &w);
  if (e != SD_OK) return e;
  return sync_end(&w, sd_sftp_mkdir(s, path, a, &o, sync_cb, &w));
}

sd_err sd_sftp_remove_sync(sd_sftp_session *s, const char *path, uint32_t timeout_ms)
{
  sync_wait w; sd_sftp_reqopt o = sync_opt(timeout_ms);
  sd_err e = sync_begin(s, &w);
  if (e != SD_OK) return e;
  return sync_end(&w, sd_sftp_remove(s, path, &o, sync_cb, &w));
}

sd_err sd_sftp_rmdir_sync(sd_sftp_session *s, const char *path, uint32_t timeout_ms)
{
  sync_wait w; sd_sftp_reqopt o = sync_opt(timeout_ms);
  sd_err e = sync_begin(s, &w);
  if (e != SD_OK) return e;
  return sync_end(&w, sd_sftp_rmdir(s, path, &o, sync_cb, &w));
}

sd_err sd_sftp_rename_sync(sd_sftp_session *s, const char *from, const char *to, uint32_t flags, uint32_t timeout_ms)
{
  sync_wait w; sd_sftp_reqopt o = sync_opt(timeout_ms);
  sd_err e = sync_begin(s, &w);
  if (e != SD_OK) return e;
  return sync_end(&w, sd_sftp_rename(s, from, to, flags, &o, sync_cb, &w));
}
