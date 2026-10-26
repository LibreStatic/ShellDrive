#include <string.h>

#include "test_util.h"

void waiter_init(waiter *w, void *session)
{
  memset(w, 0, sizeof(*w));
  (void)sd_event_init(&w->ev, 1, 0);
  w->session = session;
}

void waiter_reset(waiter *w, int kind)
{
  sd_event_reset(&w->ev);
  w->kind = kind;
  w->calls = 0;
  w->err = SD_E_INTERNAL;
  w->file = NULL;
  w->session_ready = 0;
  w->bytes = 0; w->eof = 0; w->count = 0; w->dropped = 0;
}

void waiter_free(waiter *w) { sd_event_destroy(&w->ev); }

int waiter_wait(waiter *w, uint32_t ms) { return sd_event_wait(&w->ev, ms) == SD_OK; }

void waiter_cb(void *ctx, const sd_sftp_completion *c)
{
  waiter *w = (waiter *)ctx;
  size_t n;
  w->err = c->err;
  w->sftp_status = c->sftp_status;
  w->maybe_executed = c->maybe_executed;
  w->session_ready = c->session_ready;
  n = c->server_message ? strlen(c->server_message) : 0;
  if (n >= sizeof(w->msg)) n = sizeof(w->msg) - 1;
  if (n) memcpy(w->msg, c->server_message, n);
  w->msg[n] = 0;
  switch (w->kind) {
  case W_OPEN: w->file = c->u.open.file; w->attrs = c->u.open.attrs; break;
  case W_RW:   w->bytes = c->u.read.bytes; w->eof = c->u.read.eof; break;
  case W_NAME:
    w->path_len = c->err == SD_OK ? c->u.name.len : 0;
    if (w->path_len >= sizeof(w->path)) w->path_len = sizeof(w->path) - 1;
    if (w->path_len) memcpy(w->path, c->u.name.path, w->path_len);
    w->path[w->path_len] = 0;
    break;
  case W_DIR: {
    uint32_t i;
    w->count = c->u.readdir.count; w->dropped = c->u.readdir.dropped; w->eof = c->u.readdir.eof;
    for (i = 0; i < w->count && i < 8; i++) {
      uint32_t l = c->u.readdir.ents[i].name_len < 63 ? c->u.readdir.ents[i].name_len : 63;
      memcpy(w->names[i], c->u.readdir.ents[i].name, l);
      w->names[i][l] = 0;
    }
    if (w->dir_cb) w->dir_cb(w, c);
    break;
  }
  case W_VFS:  w->vfs = c->u.statvfs.v; break;
  default:     w->attrs = c->u.stat.attrs; break;
  }
  w->attrs.ext = NULL;
  if (w->session) w->on_io_thread = sd_sftp_session_is_io_thread((sd_sftp_session *)w->session);
  InterlockedIncrement(&w->calls);
  sd_event_set(&w->ev);
}

void evlog_init(evlog *e)
{
  memset(e, 0, sizeof(*e));
  (void)sd_event_init(&e->ready, 1, 0);
  (void)sd_event_init(&e->ended, 1, 0);
}

void evlog_free(evlog *e)
{
  sd_event_destroy(&e->ready);
  sd_event_destroy(&e->ended);
}

void evlog_cb(void *ctx, const sd_sftp_event *ev)
{
  evlog *e = (evlog *)ctx;
  if (ev->type == SD_SFTP_EV_STATE) {
    LONG i = e->n;
    if (i < 32) { e->states[i] = ev->state; e->reasons[i] = ev->reason; e->n = i + 1; }
    if (ev->state == SD_SFTP_ST_FAILED || ev->state == SD_SFTP_ST_CLOSED) {
      sd_event_set(&e->ended);
      sd_event_set(&e->ready);   /* unblock a waiter for READY */
    }
  } else if (ev->type == SD_SFTP_EV_READY_INFO) {
    size_t n = strlen(ev->info->home);
    e->ext = ev->info->ext;
    e->ext_count = ev->info->ext_count;
    e->max_read = ev->info->limits.max_read;
    e->max_write = ev->info->limits.max_write;
    e->quirks = ev->info->quirks;
    e->uid = ev->info->identity.uid;
    if (n >= sizeof(e->home)) n = sizeof(e->home) - 1;
    memcpy(e->home, ev->info->home, n);
    e->home[n] = 0;
    sd_event_set(&e->ready);
  } else if (ev->type == SD_SFTP_EV_POOL) {
    InterlockedIncrement(&e->n_pool);
    if (ev->reason != SD_OK) InterlockedIncrement(&e->n_pool_drop);
    e->pool_member = ev->member;
    e->pool_conns = ev->connections;
    e->pool_reason = ev->reason;
  }
}

int evlog_has(const evlog *e, sd_sftp_state st)
{
  LONG i;
  for (i = 0; i < e->n; i++) if (e->states[i] == st) return 1;
  return 0;
}
