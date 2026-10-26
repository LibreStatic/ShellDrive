/* sd_sftp session core (01 §10.4-§10.8, §11): request pipelining, chunking, caller deadlines,
 * cancellation, error refinement; M1: meta + bulk SFTP channels with request classes and
 * auto-degrade to one channel (D19, C17), and the reconnect loop (01 §10.6): exponential backoff
 * with jitter, generations, stale handles, sd_sftp_file_reopen.
 *
 * Channels: ch[0] ("meta") carries path operations, opendir/readdir and CLASS_META handles, plus the
 * startup sequence; ch[1] ("bulk") carries every other handle. With one channel (option, transport
 * without streams, or the server refused a second session channel) ch[0] serves the meta queue
 * before the bulk queue at every turn. Request ids are unique across both channels; each wire
 * records the channel it went out on, and a handle is valid only on the channel that opened it.
 *
 * Threading model: every piece of protocol state is owned by the transport's I/O thread. Callers
 * hand requests over through a mutex-protected inbox and one posted "drain" per batch. Completions
 * are delivered from the I/O thread with no sd_sftp lock held, and never from inside a submit call.
 * Errors detected deep inside the dispatcher only set `lost_err`; the connection is torn down at
 * the end of the current I/O-thread entry point (io_epilogue), so no structure is freed while a
 * loop over it is running. */
#include <string.h>

#include "sd_base/sd_mem.h"
#include "sd_base/sd_utf.h"
#include "sd_platform/sd_log.h"
#include "sd_platform/sd_time.h"
#include "sftp_internal.h"

enum {
  OP_STARTUP = 1, OP_OPEN, OP_OPENDIR, OP_REOPEN, OP_CLOSE, OP_READ, OP_WRITE, OP_READDIR, OP_FSTAT,
  OP_FSETSTAT, OP_FSYNC, OP_FSTATVFS, OP_COPY, OP_STAT, OP_LSTAT, OP_SETSTAT, OP_MKDIR, OP_RMDIR,
  OP_REMOVE, OP_RENAME, OP_READLINK, OP_SYMLINK, OP_HARDLINK, OP_REALPATH, OP_EXPAND, OP_HOME,
  OP_STATVFS, OP_NAMES
};
enum {
  PH_MAIN = 0, PH_FSTAT, PH_PR_LSTAT, PH_PR_OPENDIR, PH_PR_READDIR, PH_PR_CLOSE, PH_PR_STATVFS,
  PH_ST_LIMITS, PH_ST_REALPATH, PH_ST_STAT, PH_ORPHAN
};
enum { EXP_HANDLE = 1u << 0, EXP_DATA = 1u << 1, EXP_NAME = 1u << 2, EXP_ATTRS = 1u << 3, EXP_EXT = 1u << 4 };
enum { Q_META = 0, Q_BULK = 1 };

#define WIRE_BUCKETS   256u
#define OBUF_HIGH      (512u * 1024u)
#define TICK_MS        50u
#define NO_OFF         UINT64_MAX

#define NCH 2u
enum { SS_NONE = 0, SS_OPENING, SS_OPEN };

typedef struct sftp_chan {
  sd_sftp_session *s;
  uint32_t idx;
  int ss;                              /* stream state SS_* (I/O thread) */
  int got_version;
  sd_wr obuf; size_t osent;
  uint8_t *ibuf; size_t ilen, icap;
  uint32_t inflight; uint64_t inflight_bytes;
} sftp_chan;

struct sd_sftp_session {
  sd_sftp_transport tp;
  sd_sftp_options   opt;
  sd_sftp_event_cb  ev; void *ev_ctx;

  sd_mutex lock;                       /* inbox, files list, info copy */
  sftp_item *in_head, *in_tail;
  int kick_pending, in_closed;
  sftp_item tick_item, close_item, start_item;
  volatile LONG tick_pending, close_requested;
  volatile LONG state;
  volatile LONG live;                  /* submitted, not yet completed */
  uint32_t generation;
  sd_sftp_file *files;

  sd_thread timer; sd_event timer_stop; int timer_started;

  /* ---- I/O thread ---- */
  sftp_chan ch[NCH];
  uint32_t nchan;                      /* channels in use this generation (1 or 2) */
  int member_ready[4];                 /* pool members 1..3 admitted (I/O thread; read under lock for info) */
  int bulk_settled, startup_done, in_attempt;
  int tp_opened, tp_close_called, finalized;   /* per connection attempt */
  sd_err lost_err; int lost_pending, lost_done;   /* lost_done: the current connection is dead */
  sftp_wire *wires[WIRE_BUCKETS];
  uint32_t next_id;
  sftp_req *qh[2], *qt[2];
  sftp_req *wait_head;                 /* WAIT_READY requests before READY (singly linked by qnext) */
  sftp_req *live_head;
  sftp_req *startup;
  uint64_t startup_deadline, last_probe_ms;
  /* reconnect loop */
  int ever_ready, user_retry, retry_stopped;
  uint32_t attempts;
  uint64_t retry_at;
  uint32_t rng;
  int symlink_openssh;
  sd_sftp_extattr scratch_ext[SFTP_MAX_EXT_PAIRS];

  /* server info (written on the I/O thread under lock; read under lock by other threads) */
  sd_sftp_server_info info;
  sd_sftp_ext_entry *ext_list; char *ext_strings; char *home;
  uint64_t raw_limits[4];

  /* statistics */
  volatile LONG64 rx_total, tx_total;  /* since session start; stats report them per generation */
  volatile LONG64 gen_rx0, gen_tx0;
  uint32_t srtt_ms, rttvar_ms; int rtt_init;
  uint64_t rate_t0, rate_rx0, rate_tx0, rx_bps, tx_bps;
};

/* ---- global token table (sd_sftp_cancel) ---- */

static sd_once  g_tok_once = SD_ONCE_INIT;
static sd_mutex g_tok_lock;
static sftp_req *g_tok[64];
static uint64_t g_tok_next = 1;

static void tok_init(void *arg) { SD_UNUSED(arg); sd_mutex_init(&g_tok_lock); }

static uint64_t tok_register(sftp_req *r)
{
  uint64_t id;
  sd_once_run(&g_tok_once, tok_init, NULL);
  sd_mutex_lock(&g_tok_lock);
  id = g_tok_next++;
  r->token = id;
  r->tnext = g_tok[id % 64];
  g_tok[id % 64] = r;
  sd_mutex_unlock(&g_tok_lock);
  return id;
}

static void tok_unregister(sftp_req *r)
{
  sftp_req **pp;
  if (!r->token) return;
  sd_mutex_lock(&g_tok_lock);
  for (pp = &g_tok[r->token % 64]; *pp; pp = &(*pp)->tnext)
    if (*pp == r) { *pp = r->tnext; break; }
  sd_mutex_unlock(&g_tok_lock);
  r->token = 0;
}

/* Caller holds g_tok_lock. */
static sftp_req *tok_find_locked(uint64_t id)
{
  sftp_req *r;
  for (r = g_tok[id % 64]; r; r = r->tnext)
    if (r->token == id) return r;
  return NULL;
}

/* ---- small helpers ---- */

static char *dup_bytes(const void *p, size_t n)
{
  char *d = (char *)sd_alloc(n + 1);
  if (!d) return NULL;
  if (n) memcpy(d, p, n);
  d[n] = 0;
  return d;
}

static char *dup_str(const char *s) { return s ? dup_bytes(s, strlen(s)) : NULL; }

static char *sanitize_dup(const uint8_t *p, size_t n)
{
  size_t cap = n * 3 + 1, out = 0;
  char *d = (char *)sd_alloc(cap);
  if (!d) return NULL;
  if (sd_text_sanitize_server((const char *)p, n, d, cap, &out) != SD_OK) out = 0;
  d[out < cap ? out : cap - 1] = 0;
  return d;
}

static int refine_on(const sd_sftp_session *s, const sftp_req *r)
{
  return (s->opt.flags & SD_SFTP_OPT_REFINE_ERRORS) && !(r->flags & SD_SFTP_REQ_NO_REFINE);
}

/* ---- inbox ---- */

static void io_drain(void *arg);

static void kick(sd_sftp_session *s)
{
  int need;
  sd_mutex_lock(&s->lock);
  need = !s->kick_pending && s->in_head != NULL && !s->in_closed;
  if (need) s->kick_pending = 1;
  sd_mutex_unlock(&s->lock);
  if (need && s->tp.post(s->tp.ctx, io_drain, s) != SD_OK) {
    sd_mutex_lock(&s->lock);
    s->kick_pending = 0;
    sd_mutex_unlock(&s->lock);
  }
}

/* Returns 0 when the inbox is closed (session finished). */
static int inbox_put(sd_sftp_session *s, sftp_item *it)
{
  int ok;
  sd_mutex_lock(&s->lock);
  ok = !s->in_closed;
  if (ok) {
    it->next = NULL;
    if (s->in_tail) s->in_tail->next = it; else s->in_head = it;
    s->in_tail = it;
  }
  sd_mutex_unlock(&s->lock);
  if (ok) kick(s);
  return ok;
}

/* ---- events ---- */

static void set_state_ex(sd_sftp_session *s, sd_sftp_state st, sd_err reason, uint32_t retry_in, uint32_t attempt)
{
  sd_sftp_event e;
  InterlockedExchange(&s->state, (LONG)st);
  if (!s->ev) return;
  memset(&e, 0, sizeof(e));
  e.type = SD_SFTP_EV_STATE;
  e.state = st;
  e.reason = reason;
  e.retry_in_ms = retry_in;
  e.attempt = attempt;
  e.generation = s->generation;
  s->ev(s->ev_ctx, &e);
}

static void set_state(sd_sftp_session *s, sd_sftp_state st, sd_err reason) { set_state_ex(s, st, reason, 0, 0); }

/* ---- files ---- */

static void file_unlink_free(sd_sftp_session *s, sd_sftp_file *f)
{
  sd_mutex_lock(&s->lock);
  if (f->fprev) f->fprev->fnext = f->fnext; else if (s->files == f) s->files = f->fnext;
  if (f->fnext) f->fnext->fprev = f->fprev;
  sd_mutex_unlock(&s->lock);
  sd_free(f->path);
  sd_free(f);
}

static sd_sftp_file *file_new(sd_sftp_session *s, const char *path, uint32_t oflags, int is_dir, int meta,
                              uint32_t ch, const uint8_t *h, uint32_t hlen)
{
  sd_sftp_file *f = (sd_sftp_file *)sd_calloc(1, sizeof(*f));
  if (!f) return NULL;
  f->path = dup_str(path);
  if (!f->path) { sd_free(f); return NULL; }
  f->s = s;
  f->refs = 1;
  f->oflags = oflags;
  f->is_dir = is_dir;
  f->meta = meta;
  f->generation = s->generation;
  f->ch = ch;
  memcpy(f->handle, h, hlen);
  f->hlen = hlen;
  sd_mutex_lock(&s->lock);
  f->fnext = s->files;
  if (s->files) s->files->fprev = f;
  s->files = f;
  sd_mutex_unlock(&s->lock);
  return f;
}

void sd_sftp_file_addref(sd_sftp_file *f)
{
  if (f) InterlockedIncrement(&f->refs);
}

void sd_sftp_file_release(sd_sftp_file *f)
{
  sd_sftp_session *s;
  if (!f || InterlockedDecrement(&f->refs) != 0) return;
  s = f->s;
  f->rel_item.type = IT_RELEASE;
  f->rel_item.ptr = f;
  if (!inbox_put(s, &f->rel_item))
    file_unlink_free(s, f);           /* session finished: nothing to close on the wire */
}

void *sd_sftp_file_user(sd_sftp_file *f) { return f ? f->user : NULL; }
void sd_sftp_file_set_user(sd_sftp_file *f, void *p) { if (f) f->user = p; }

sd_err sd_sftp_file_get_info(sd_sftp_file *f, sd_sftp_file_info *out)
{
  if (!f || !out) return SD_E_INVALID_PARAM;
  memset(out, 0, sizeof(*out));
  out->path = f->path;
  out->oflags = f->oflags;
  out->is_dir = f->is_dir;
  out->generation = f->generation;
  out->stale = f->stale != 0;
  out->attrs_at_open = f->attrs_at_open;
  out->attrs_at_open.ext = NULL;
  out->attrs_at_open.ext_count = 0;
  return SD_OK;
}

/* ---- wires ---- */

static sftp_wire *wire_find(sd_sftp_session *s, uint32_t id)
{
  sftp_wire *w;
  for (w = s->wires[id % WIRE_BUCKETS]; w; w = w->hnext)
    if (w->id == id) return w;
  return NULL;
}

static sftp_wire *wire_take(sd_sftp_session *s, uint32_t id)
{
  sftp_wire **pp;
  for (pp = &s->wires[id % WIRE_BUCKETS]; *pp; pp = &(*pp)->hnext)
    if ((*pp)->id == id) {
      sftp_wire *w = *pp;
      sftp_chan *ch = &s->ch[w->ch];
      *pp = w->hnext;
      ch->inflight--;
      ch->inflight_bytes -= w->bytes;
      return w;
    }
  return NULL;
}

static sftp_wire *wire_new(sd_sftp_session *s, sftp_chan *ch, sftp_req *r, uint32_t phase, uint32_t expect)
{
  sftp_wire *w = (sftp_wire *)sd_calloc(1, sizeof(*w));
  if (!w) { if (!s->lost_pending) { s->lost_pending = 1; s->lost_err = SD_E_NO_MEMORY; } return NULL; }
  do { s->next_id++; } while (wire_find(s, s->next_id) != NULL);
  w->id = s->next_id;
  w->ch = ch->idx;
  w->r = r;
  w->phase = phase;
  w->expect = expect;
  w->sent_ms = sd_tick_ms();
  w->hnext = s->wires[w->id % WIRE_BUCKETS];
  s->wires[w->id % WIRE_BUCKETS] = w;
  ch->inflight++;
  if (r) { r->wires++; r->sent = 1; }
  return w;
}

static void lose(sd_sftp_session *s, sd_err e)
{
  if (!s->lost_pending && !s->lost_done) { s->lost_pending = 1; s->lost_err = e; }
}

/* ---- request lifetime ---- */

static void live_remove(sd_sftp_session *s, sftp_req *r)
{
  if (!r->in_live) return;
  if (r->lprev) r->lprev->lnext = r->lnext; else s->live_head = r->lnext;
  if (r->lnext) r->lnext->lprev = r->lprev;
  r->in_live = 0;
}

static void live_add(sd_sftp_session *s, sftp_req *r)
{
  r->lprev = NULL;
  r->lnext = s->live_head;
  if (s->live_head) s->live_head->lprev = r;
  s->live_head = r;
  r->in_live = 1;
}

static void send_orphan_close(sd_sftp_session *s, uint32_t ch, const uint8_t *h, uint32_t hlen);

static void req_free(sftp_req *r)
{
  sftp_range *g = r->reissue;
  while (g) { sftp_range *n = g->next; sd_free(g); g = n; }
  if (r->f) sd_sftp_file_release(r->f);
  if (r->f2) sd_sftp_file_release(r->f2);
  if (r->newf) sd_sftp_file_release(r->newf);
  sd_free(r->p1);
  sd_free(r->p2);
  sd_free(r->ids);
  sd_free(r->msg);
  sd_free(r);
}

static void req_maybe_free(sd_sftp_session *s, sftp_req *r)
{
  if (!r->done || r->wires || r->queued) return;
  if (r->ph_open && !s->lost_done) send_orphan_close(s, r->ph_ch, r->ph, r->phlen);
  r->ph_open = 0;
  req_free(r);
}

/* Delivers the completion exactly once. */
static void deliver(sd_sftp_session *s, sftp_req *r)
{
  if (r->done) return;
  r->done = 1;
  live_remove(s, r);
  tok_unregister(r);
  if (!r->c.server_message) r->c.server_message = r->msg ? r->msg : "";
  if (r->c.err == SD_E_DISCONNECTED || r->c.err == SD_E_TIMEOUT || r->c.err == SD_E_CANCELLED ||
      r->c.err == SD_E_SHUTDOWN)
    r->c.maybe_executed = r->sent;
  InterlockedDecrement(&s->live);
  if (r->cb) r->cb(r->ctx, &r->c);
}

static void finish(sd_sftp_session *s, sftp_req *r, sd_err err)
{
  r->c.err = err;
  deliver(s, r);
  req_maybe_free(s, r);
}

/* ---- queues ---- */

static int req_class(const sftp_req *r)
{
  switch (r->op) {
  case OP_CLOSE: case OP_READ: case OP_WRITE: case OP_READDIR: case OP_FSTAT: case OP_FSETSTAT:
  case OP_FSYNC: case OP_FSTATVFS: case OP_COPY:
    return r->f && !r->f->meta ? Q_BULK : Q_META;
  case OP_OPEN:      /* the OPEN goes out on the channel its handle will live on */
    if (r->flags & SD_SFTP_REQ_CLASS_META) return Q_META;
    if (r->f2) return r->f2->meta ? Q_META : Q_BULK;    /* same_channel_as */
    return Q_BULK;
  case OP_REOPEN:
    return r->f && !r->f->meta ? Q_BULK : Q_META;
  default:
    return Q_META;
  }
}

static void q_push(sd_sftp_session *s, sftp_req *r, int front)
{
  int c = req_class(r);
  if (r->queued) return;
  r->queued = 1;
  r->qclass = c;
  r->qnext = NULL;
  if (front) {
    r->qnext = s->qh[c];
    s->qh[c] = r;
    if (!s->qt[c]) s->qt[c] = r;
  } else {
    if (s->qt[c]) s->qt[c]->qnext = r; else s->qh[c] = r;
    s->qt[c] = r;
  }
}

static sftp_req *q_pop(sd_sftp_session *s, int c)
{
  sftp_req *r = s->qh[c];
  if (!r) return NULL;
  s->qh[c] = r->qnext;
  if (!s->qh[c]) s->qt[c] = NULL;
  r->qnext = NULL;
  r->queued = 0;
  return r;
}

static void queue_phase(sd_sftp_session *s, sftp_req *r, uint32_t phase, int front)
{
  r->phase = phase;
  r->emit_pending = 1;
  q_push(s, r, front);
}

static uint64_t chunk_cutoff(const sftp_req *r)
{
  uint64_t c = r->len;
  if (r->eof_at < c) c = r->eof_at;
  if (r->err_at < c) c = r->err_at;
  return c;
}

static int req_has_more(const sftp_req *r)
{
  if (r->done) return 0;
  if (r->phase == PH_MAIN && (r->op == OP_READ || r->op == OP_WRITE)) {
    const sftp_range *g;
    uint64_t cut = chunk_cutoff(r);
    if (r->op == OP_WRITE && r->err_at != NO_OFF) return 0;
    for (g = r->reissue; g; g = g->next)
      if (g->off - r->off < cut) return 1;
    return r->emit_off < cut;
  }
  return r->emit_pending;
}

static uint32_t next_chunk_bytes(const sd_sftp_session *s, const sftp_req *r)
{
  uint64_t max, left;
  if (r->phase != PH_MAIN || (r->op != OP_READ && r->op != OP_WRITE)) return 0;
  if (r->reissue) return r->reissue->len;
  max = r->op == OP_READ ? s->info.limits.max_read : s->info.limits.max_write;
  left = r->len - r->emit_off;
  return (uint32_t)(left < max ? left : max);
}

/* ---- packet encoding ---- */

static void put_handle(sd_wr *w, const sd_sftp_file *f) { sd_wr_string(w, f->handle, f->hlen); }

static int chan_live(const sd_sftp_session *s, const sftp_chan *ch)
{
  return ch->ss == SS_OPEN && ch->got_version && !s->lost_done && !s->lost_pending;
}

static void send_orphan_close(sd_sftp_session *s, uint32_t chi, const uint8_t *h, uint32_t hlen)
{
  sftp_chan *ch = &s->ch[chi < NCH ? chi : 0];
  sftp_wire *w;
  size_t st;
  if (!chan_live(s, ch)) return;
  w = wire_new(s, ch, NULL, PH_ORPHAN, 0);
  if (!w) return;
  st = sftp_pkt_begin(&ch->obuf, SFTP_CLOSE, 1, w->id);
  sd_wr_string(&ch->obuf, h, hlen);
  sftp_pkt_end(&ch->obuf, st);
}

static size_t begin_ext(sftp_chan *ch, sftp_wire *w, const char *name)
{
  size_t st = sftp_pkt_begin(&ch->obuf, SFTP_EXTENDED, 1, w->id);
  sd_wr_cstring(&ch->obuf, name);
  return st;
}

static const char *probe_path(const sftp_req *r)
{
  switch (r->op) {
  case OP_RENAME: case OP_HARDLINK: return r->p2;
  default: return r->p1;
  }
}

/* Emits the next wire of r on ch. May complete r (unsupported extension, local failures). */
static void emit(sd_sftp_session *s, sftp_chan *ch, sftp_req *r)
{
  sd_wr *o = &ch->obuf;
  sftp_wire *w;
  sd_sftp_file *f;
  size_t st;
  uint32_t ext = s->info.ext;

  if (r->phase == PH_MAIN && (r->op == OP_READ || r->op == OP_WRITE)) {
    uint64_t off; uint32_t len;
    if (r->reissue) {
      sftp_range *g = r->reissue;
      r->reissue = g->next;
      off = g->off; len = g->len;
      sd_free(g);
      if (off - r->off >= chunk_cutoff(r)) return;
    } else {
      len = next_chunk_bytes(s, r);
      off = r->off + r->emit_off;
      r->emit_off += len;
    }
    w = wire_new(s, ch, r, PH_MAIN, r->op == OP_READ ? EXP_DATA : 0);
    if (!w) return;
    w->off = off; w->len = len; w->bytes = len;
    ch->inflight_bytes += len;
    st = sftp_pkt_begin(o, r->op == OP_READ ? SFTP_READ : SFTP_WRITE, 1, w->id);
    put_handle(o, r->f);
    sd_wr_u64(o, off);
    if (r->op == OP_READ) sd_wr_u32(o, len);
    else { sd_wr_string(o, r->buf + (off - r->off), len); r->f->written = 1; }
    sftp_pkt_end(o, st);
    return;
  }

  r->emit_pending = 0;
  switch (r->phase) {
  case PH_FSTAT:
    w = wire_new(s, ch, r, PH_FSTAT, EXP_ATTRS); if (!w) return;
    st = sftp_pkt_begin(o, SFTP_FSTAT, 1, w->id);
    sd_wr_string(o, r->newf ? r->newf->handle : r->f->handle, r->newf ? r->newf->hlen : r->f->hlen);
    sftp_pkt_end(o, st);
    return;
  case PH_PR_LSTAT:
    w = wire_new(s, ch, r, PH_PR_LSTAT, EXP_ATTRS); if (!w) return;
    st = sftp_pkt_begin(o, SFTP_LSTAT, 1, w->id);
    sd_wr_cstring(o, probe_path(r));
    sftp_pkt_end(o, st);
    return;
  case PH_PR_OPENDIR:
    w = wire_new(s, ch, r, PH_PR_OPENDIR, EXP_HANDLE); if (!w) return;
    st = sftp_pkt_begin(o, SFTP_OPENDIR, 1, w->id);
    sd_wr_cstring(o, r->p1);
    sftp_pkt_end(o, st);
    return;
  case PH_PR_READDIR:
    w = wire_new(s, ch, r, PH_PR_READDIR, EXP_NAME); if (!w) return;
    st = sftp_pkt_begin(o, SFTP_READDIR, 1, w->id);
    sd_wr_string(o, r->ph, r->phlen);
    sftp_pkt_end(o, st);
    return;
  case PH_PR_CLOSE:
    w = wire_new(s, ch, r, PH_PR_CLOSE, 0); if (!w) return;
    st = sftp_pkt_begin(o, SFTP_CLOSE, 1, w->id);
    sd_wr_string(o, r->ph, r->phlen);
    sftp_pkt_end(o, st);
    r->ph_open = 0;
    return;
  case PH_PR_STATVFS:
    w = wire_new(s, ch, r, PH_PR_STATVFS, EXP_EXT); if (!w) return;
    st = begin_ext(ch, w, "statvfs@openssh.com");
    sd_wr_cstring(o, r->f->path);
    sftp_pkt_end(o, st);
    return;
  case PH_ST_LIMITS:
    w = wire_new(s, ch, r, PH_ST_LIMITS, EXP_EXT); if (!w) return;
    st = begin_ext(ch, w, "limits@openssh.com");
    sftp_pkt_end(o, st);
    return;
  case PH_ST_REALPATH:
    w = wire_new(s, ch, r, PH_ST_REALPATH, EXP_NAME); if (!w) return;
    st = sftp_pkt_begin(o, SFTP_REALPATH, 1, w->id);
    sd_wr_cstring(o, ".");
    sftp_pkt_end(o, st);
    return;
  case PH_ST_STAT:
    w = wire_new(s, ch, r, PH_ST_STAT, EXP_ATTRS); if (!w) return;
    st = sftp_pkt_begin(o, SFTP_STAT, 1, w->id);
    sd_wr_cstring(o, s->home ? s->home : ".");
    sftp_pkt_end(o, st);
    return;
  default:
    break;
  }

  /* PH_MAIN, single-wire operations. Local checks first. */
  if (r->f && r->op != OP_REOPEN && r->op != OP_OPEN && (r->f->stale || (r->f->wire_closed && r->op != OP_CLOSE))) {
    finish(s, r, r->op == OP_CLOSE ? SD_OK : SD_E_STALE_HANDLE);
    return;
  }
  if (r->f && r->op != OP_REOPEN && r->op != OP_OPEN && r->f->ch != ch->idx) {   /* handle of another channel */
    finish(s, r, r->op == OP_CLOSE ? SD_OK : SD_E_STALE_HANDLE);
    return;
  }
  if (r->op == OP_CLOSE && r->f->wire_closed) { finish(s, r, SD_OK); return; }
  {
    size_t need = 64 + (r->p1 ? strlen(r->p1) : 0) + (r->p2 ? strlen(r->p2) : 0);
    if (need > s->info.limits.max_packet) { finish(s, r, SD_E_NAME_TOO_LONG); return; }
  }
  switch (r->op) {
  case OP_FSYNC:    if (!(ext & SD_SFTP_EXT_FSYNC)) { finish(s, r, SD_E_UNSUPPORTED); return; } break;
  case OP_FSTATVFS: if (!(ext & SD_SFTP_EXT_FSTATVFS)) { finish(s, r, SD_E_UNSUPPORTED); return; } break;
  case OP_STATVFS:  if (!(ext & SD_SFTP_EXT_STATVFS)) { finish(s, r, SD_E_UNSUPPORTED); return; } break;
  case OP_COPY:     if (!(ext & SD_SFTP_EXT_COPY_DATA)) { finish(s, r, SD_E_UNSUPPORTED); return; } break;
  case OP_HARDLINK: if (!(ext & SD_SFTP_EXT_HARDLINK)) { finish(s, r, SD_E_UNSUPPORTED); return; } break;
  case OP_EXPAND:   if (!(ext & SD_SFTP_EXT_EXPAND_PATH)) { finish(s, r, SD_E_UNSUPPORTED); return; } break;
  case OP_HOME:     if (!(ext & SD_SFTP_EXT_HOME_DIRECTORY)) { finish(s, r, SD_E_UNSUPPORTED); return; } break;
  case OP_NAMES:    if (!(ext & SD_SFTP_EXT_USERS_GROUPS_BY_ID)) { finish(s, r, SD_E_UNSUPPORTED); return; } break;
  case OP_SETSTAT:  if (r->u1 && !(ext & SD_SFTP_EXT_LSETSTAT)) { finish(s, r, SD_E_UNSUPPORTED); return; } break;
  case OP_RENAME:
    if ((r->u1 & SD_SFTP_RENAME_OVERWRITE) && !(ext & SD_SFTP_EXT_POSIX_RENAME)) { finish(s, r, SD_E_UNSUPPORTED); return; }
    break;
  default: break;
  }
  if (r->op == OP_COPY) {
    sd_sftp_file *src = r->f2;
    if (!src || src->stale || src->wire_closed) { finish(s, r, SD_E_STALE_HANDLE); return; }
    if (!r->f || src->ch != r->f->ch) { finish(s, r, SD_E_INVALID_PARAM); return; }   /* same channel required */
  }

  f = r->f;
  switch (r->op) {
  case OP_OPEN: case OP_REOPEN: case OP_OPENDIR:
    if (r->op == OP_REOPEN && !f) { finish(s, r, SD_E_INTERNAL); return; }
    w = wire_new(s, ch, r, PH_MAIN, EXP_HANDLE); if (!w) return;
    if (r->op == OP_OPENDIR || (f && r->op == OP_REOPEN && f->is_dir)) {
      st = sftp_pkt_begin(o, SFTP_OPENDIR, 1, w->id);
      sd_wr_cstring(o, f && r->op == OP_REOPEN ? f->path : r->p1);
    } else {
      uint32_t fl = f && r->op == OP_REOPEN ? (f->oflags & ~(uint32_t)(SD_SFTP_O_CREAT | SD_SFTP_O_TRUNC | SD_SFTP_O_EXCL))
                                            : r->u1;
      st = sftp_pkt_begin(o, SFTP_OPEN, 1, w->id);
      sd_wr_cstring(o, f && r->op == OP_REOPEN ? f->path : r->p1);
      sd_wr_u32(o, fl & 0x3Fu);
      sftp_enc_attrs(o, r->op == OP_OPEN && r->has_attrs ? &r->a : NULL);
    }
    break;
  case OP_CLOSE:
    if (!f) { finish(s, r, SD_E_INTERNAL); return; }
    w = wire_new(s, ch, r, PH_MAIN, 0); if (!w) return;
    st = sftp_pkt_begin(o, SFTP_CLOSE, 1, w->id); put_handle(o, f);
    f->wire_closed = 1;
    break;
  case OP_READDIR:
    if (!f) { finish(s, r, SD_E_INTERNAL); return; }
    w = wire_new(s, ch, r, PH_MAIN, EXP_NAME); if (!w) return;
    st = sftp_pkt_begin(o, SFTP_READDIR, 1, w->id); put_handle(o, f);
    break;
  case OP_FSTAT:
    if (!f) { finish(s, r, SD_E_INTERNAL); return; }
    w = wire_new(s, ch, r, PH_MAIN, EXP_ATTRS); if (!w) return;
    st = sftp_pkt_begin(o, SFTP_FSTAT, 1, w->id); put_handle(o, f);
    break;
  case OP_FSETSTAT:
    if (!f) { finish(s, r, SD_E_INTERNAL); return; }
    w = wire_new(s, ch, r, PH_MAIN, 0); if (!w) return;
    st = sftp_pkt_begin(o, SFTP_FSETSTAT, 1, w->id); put_handle(o, f); sftp_enc_attrs(o, &r->a);
    break;
  case OP_FSYNC:
    if (!f) { finish(s, r, SD_E_INTERNAL); return; }
    w = wire_new(s, ch, r, PH_MAIN, 0); if (!w) return;
    st = begin_ext(ch, w, "fsync@openssh.com"); put_handle(o, f);
    break;
  case OP_FSTATVFS:
    if (!f) { finish(s, r, SD_E_INTERNAL); return; }
    w = wire_new(s, ch, r, PH_MAIN, EXP_EXT); if (!w) return;
    st = begin_ext(ch, w, "fstatvfs@openssh.com"); put_handle(o, f);
    break;
  case OP_COPY:
    if (!f) { finish(s, r, SD_E_INTERNAL); return; }
    w = wire_new(s, ch, r, PH_MAIN, 0); if (!w) return;
    st = begin_ext(ch, w, "copy-data");
    put_handle(o, f); sd_wr_u64(o, r->off); sd_wr_u64(o, r->len64);
    put_handle(o, r->f2); sd_wr_u64(o, r->off2);
    break;
  case OP_STAT: case OP_LSTAT:
    w = wire_new(s, ch, r, PH_MAIN, EXP_ATTRS); if (!w) return;
    st = sftp_pkt_begin(o, r->op == OP_STAT ? SFTP_STAT : SFTP_LSTAT, 1, w->id); sd_wr_cstring(o, r->p1);
    break;
  case OP_SETSTAT:
    w = wire_new(s, ch, r, PH_MAIN, 0); if (!w) return;
    if (r->u1) { st = begin_ext(ch, w, "lsetstat@openssh.com"); }
    else st = sftp_pkt_begin(o, SFTP_SETSTAT, 1, w->id);
    sd_wr_cstring(o, r->p1); sftp_enc_attrs(o, &r->a);
    break;
  case OP_MKDIR:
    w = wire_new(s, ch, r, PH_MAIN, 0); if (!w) return;
    st = sftp_pkt_begin(o, SFTP_MKDIR, 1, w->id); sd_wr_cstring(o, r->p1);
    sftp_enc_attrs(o, r->has_attrs ? &r->a : NULL);
    break;
  case OP_RMDIR: case OP_REMOVE: case OP_READLINK: case OP_REALPATH:
    w = wire_new(s, ch, r, PH_MAIN, (r->op == OP_READLINK || r->op == OP_REALPATH) ? EXP_NAME : 0); if (!w) return;
    st = sftp_pkt_begin(o, r->op == OP_RMDIR ? SFTP_RMDIR : r->op == OP_REMOVE ? SFTP_REMOVE :
                           r->op == OP_READLINK ? SFTP_READLINK : SFTP_REALPATH, 1, w->id);
    sd_wr_cstring(o, r->p1);
    break;
  case OP_RENAME:
    w = wire_new(s, ch, r, PH_MAIN, 0); if (!w) return;
    if (r->u1 & SD_SFTP_RENAME_OVERWRITE) st = begin_ext(ch, w, "posix-rename@openssh.com");
    else st = sftp_pkt_begin(o, SFTP_RENAME, 1, w->id);
    sd_wr_cstring(o, r->p1); sd_wr_cstring(o, r->p2);
    break;
  case OP_SYMLINK:   /* p1 = link path, p2 = target */
    w = wire_new(s, ch, r, PH_MAIN, 0); if (!w) return;
    st = sftp_pkt_begin(o, SFTP_SYMLINK, 1, w->id);
    if (s->symlink_openssh) { sd_wr_cstring(o, r->p2); sd_wr_cstring(o, r->p1); }
    else { sd_wr_cstring(o, r->p1); sd_wr_cstring(o, r->p2); }
    break;
  case OP_HARDLINK:
    w = wire_new(s, ch, r, PH_MAIN, 0); if (!w) return;
    st = begin_ext(ch, w, "hardlink@openssh.com"); sd_wr_cstring(o, r->p1); sd_wr_cstring(o, r->p2);
    break;
  case OP_EXPAND:
    w = wire_new(s, ch, r, PH_MAIN, EXP_NAME); if (!w) return;
    st = begin_ext(ch, w, "expand-path@openssh.com"); sd_wr_cstring(o, r->p1);
    break;
  case OP_HOME:
    w = wire_new(s, ch, r, PH_MAIN, EXP_NAME); if (!w) return;
    st = begin_ext(ch, w, "home-directory"); sd_wr_cstring(o, r->p1);
    break;
  case OP_STATVFS:
    w = wire_new(s, ch, r, PH_MAIN, EXP_EXT); if (!w) return;
    st = begin_ext(ch, w, "statvfs@openssh.com"); sd_wr_cstring(o, r->p1);
    break;
  case OP_NAMES: {
    uint32_t i;
    w = wire_new(s, ch, r, PH_MAIN, EXP_EXT); if (!w) return;
    st = begin_ext(ch, w, "users-groups-by-id@openssh.com");
    sd_wr_u32(o, r->nu * 4);
    for (i = 0; i < r->nu; i++) sd_wr_u32(o, r->ids[i]);
    sd_wr_u32(o, r->ng * 4);
    for (i = 0; i < r->ng; i++) sd_wr_u32(o, r->ids[r->nu + i]);
    break;
  }
  default:
    finish(s, r, SD_E_INTERNAL);
    return;
  }
  sftp_pkt_end(o, st);
}

/* ---- output ---- */

static sd_err tp_write(sd_sftp_session *s, uint32_t idx, const uint8_t *p, size_t n, size_t *acc)
{
  if (idx == 0 || !s->tp.write_stream) return s->tp.write(s->tp.ctx, p, n, acc);
  return s->tp.write_stream(s->tp.ctx, idx, p, n, acc);
}

static void tp_consumed(sd_sftp_session *s, uint32_t idx, size_t n)
{
  if (idx == 0 || !s->tp.consumed_stream) s->tp.consumed(s->tp.ctx, n);
  else s->tp.consumed_stream(s->tp.ctx, idx, n);
}

static void flush(sd_sftp_session *s, sftp_chan *ch)
{
  if (!sd_wr_ok(&ch->obuf)) { lose(s, SD_E_NO_MEMORY); return; }
  while (ch->ss == SS_OPEN && !s->lost_pending && !s->lost_done && ch->osent < ch->obuf.len) {
    size_t acc = 0;
    sd_err e = tp_write(s, ch->idx, ch->obuf.p + ch->osent, ch->obuf.len - ch->osent, &acc);
    if (e != SD_OK) { lose(s, e); return; }
    if (acc > ch->obuf.len - ch->osent) acc = ch->obuf.len - ch->osent;
    ch->osent += acc;
    sd_atomic_add64(&s->tx_total, (LONG64)acc);
    if (acc == 0) break;
  }
  if (ch->osent == ch->obuf.len) { sd_wr_reset(&ch->obuf); ch->osent = 0; }
  else if (ch->osent >= OBUF_HIGH) {
    memmove(ch->obuf.p, ch->obuf.p + ch->osent, ch->obuf.len - ch->osent);
    ch->obuf.len -= ch->osent;
    ch->osent = 0;
  }
}

/* Serves the class queues `cls[0..ncls)` on ch, the first class first at every turn (C17). */
static void schedule_chan(sd_sftp_session *s, sftp_chan *ch, const int *cls, int ncls)
{
  for (;;) {
    int i, emitted = 0;
    if (!chan_live(s, ch)) break;
    if (ch->obuf.len - ch->osent >= OBUF_HIGH) break;
    if (ch->inflight >= s->opt.max_inflight_reqs) break;
    for (i = 0; i < ncls && !emitted; i++) {
      int c = cls[i];
      sftp_req *r;
      for (;;) {     /* drop finished heads */
        r = s->qh[c];
        if (!r) break;
        if (req_has_more(r)) break;
        q_pop(s, c);
        req_maybe_free(s, r);
      }
      if (!r) continue;
      {
        uint32_t b = next_chunk_bytes(s, r);
        if (b && ch->inflight_bytes > 0 && ch->inflight_bytes + b > s->opt.max_inflight_bytes) continue;
      }
      emit(s, ch, r);
      emitted = 1;
      if (s->qh[c] == r && !req_has_more(r)) { q_pop(s, c); req_maybe_free(s, r); }
    }
    if (!emitted) break;
  }
  flush(s, ch);
}

static void schedule(sd_sftp_session *s)
{
  static const int k_meta_bulk[2] = { Q_META, Q_BULK }, k_bulk[1] = { Q_BULK };
  if (s->lost_pending || s->lost_done) return;
  /* ch[0] serves the bulk queue too unless a second channel is in use */
  schedule_chan(s, &s->ch[0], k_meta_bulk, s->nchan == 2 ? 1 : 2);
  if (s->nchan == 2) schedule_chan(s, &s->ch[1], k_bulk, 1);
}

/* ---- connection loss, close, reconnect ---- */

static void detach_all(sd_sftp_session *s)
{
  uint32_t b, i;
  int c;
  for (b = 0; b < WIRE_BUCKETS; b++) {
    sftp_wire *w = s->wires[b];
    s->wires[b] = NULL;
    while (w) {
      sftp_wire *n = w->hnext;
      sftp_req *r = w->r;
      sd_free(w);
      if (r) { r->wires--; if (r->done) req_maybe_free(s, r); }
      w = n;
    }
  }
  for (i = 0; i < NCH; i++) {
    sftp_chan *ch = &s->ch[i];
    ch->inflight = 0;
    ch->inflight_bytes = 0;
    ch->got_version = 0;
    ch->ilen = 0;
    sd_wr_reset(&ch->obuf);
    ch->osent = 0;
  }
  for (c = 0; c < 2; c++) {
    sftp_req *r;
    while ((r = q_pop(s, c)) != NULL) {
      if (r->done) req_maybe_free(s, r);
    }
  }
}

static void wait_push(sd_sftp_session *s, sftp_req *r)
{
  r->qnext = s->wait_head;
  s->wait_head = r;
  r->waiting = 1;
}

static void remove_waiting(sd_sftp_session *s, sftp_req *r)
{
  sftp_req **pp;
  if (!r->waiting) return;
  for (pp = &s->wait_head; *pp; pp = &(*pp)->qnext)
    if (*pp == r) { *pp = r->qnext; r->qnext = NULL; break; }
  r->waiting = 0;
}

/* Every live request (WAIT_READY ones included) completes with e. */
static void fail_live(sd_sftp_session *s, sd_err e)
{
  sftp_req *r;
  while ((r = s->wait_head) != NULL) { s->wait_head = r->qnext; r->qnext = NULL; r->waiting = 0; }
  while ((r = s->live_head) != NULL) finish(s, r, e);
}

/* Connection loss while READY (01 §10.4 step 2): everything in flight or queued completes with
   SD_E_DISCONNECTED (maybe_executed when it was sent). Path operations submitted with WAIT_READY
   that never went out keep waiting for the next READY within their deadline. */
static void fail_on_loss(sd_sftp_session *s)
{
  sftp_req *r = s->live_head, *n;
  for (; r; r = n) {
    n = r->lnext;
    if (r->waiting) continue;
    if (!r->sent && (r->flags & SD_SFTP_REQ_WAIT_READY) && !r->f && !r->done && r->op != OP_STARTUP) {
      r->emit_pending = 0;
      wait_push(s, r);
      continue;
    }
    finish(s, r, SD_E_DISCONNECTED);
  }
}

static void mark_files_stale(sd_sftp_session *s)
{
  sd_sftp_file *f;
  sd_mutex_lock(&s->lock);
  for (f = s->files; f; f = f->fnext) InterlockedExchange(&f->stale, 1);
  sd_mutex_unlock(&s->lock);
}

static int streams_quiet(const sd_sftp_session *s)
{
  uint32_t i;
  for (i = 0; i < NCH; i++) if (s->ch[i].ss != SS_NONE) return 0;
  return 1;
}

static int any_stream_open(const sd_sftp_session *s)
{
  uint32_t i;
  for (i = 0; i < NCH; i++) if (s->ch[i].ss == SS_OPEN) return 1;
  return 0;
}

/* Once per attempt, also when no stream is open any more: the transport may still hold the
   connection (e.g. sd_ssh connected but the subsystem channel was refused). */
static void close_transport(sd_sftp_session *s)
{
  if (s->tp_close_called || !s->tp_opened) return;
  s->tp_close_called = 1;
  s->tp.close(s->tp.ctx);
}

/* Errors that no retry can fix (01 §8, §10.6): host key problems, refused legacy algorithms, ... */
static int err_permanent(sd_err e)
{
  switch (e) {
  case SD_E_HOSTKEY_REJECTED: case SD_E_HOSTKEY_MISMATCH: case SD_E_HOSTKEY_REVOKED:
  case SD_E_HOSTKEY_TYPE_UNAVAILABLE: case SD_E_LEGACY_REJECTED: case SD_E_KEX_FAILED:
  case SD_E_UNSUPPORTED: case SD_E_INVALID_PARAM: case SD_E_KEY_FORMAT: case SD_E_KEY_UNSUPPORTED:
    return 1;
  default:
    return 0;
  }
}

/* Errors that need the user (a prompt was cancelled, the credentials no longer work). */
static int err_needs_user(sd_err e)
{
  return e == SD_E_AUTH_FAILED || e == SD_E_AUTH_REQUIRED || e == SD_E_CANCELLED || e == SD_E_BAD_PASSPHRASE ||
         e == SD_E_KEY_PASSPHRASE_REQUIRED;
}

static uint32_t rng_next(sd_sftp_session *s)
{
  uint32_t x = s->rng ? s->rng : (uint32_t)(sd_tick_ms() ^ (uintptr_t)s ^ 0x9E3779B9u);
  x ^= x << 13; x ^= x >> 17; x ^= x << 5;
  s->rng = x ? x : 1;
  return s->rng;
}

/* Backoff before attempt n (0-based): initial * 2^n, capped at max, +/-20% jitter (01 §10.4). */
static uint32_t backoff_ms(sd_sftp_session *s, uint32_t n)
{
  uint64_t d = s->opt.reconnect.initial_delay_ms, cap = s->opt.reconnect.max_delay_ms;
  uint32_t i;
  if (cap < d) cap = d;
  for (i = 0; i < n && d < cap; i++) d *= 2;
  if (d > cap) d = cap;
  if (d) d = d * (80u + rng_next(s) % 41u) / 100u;
  return (uint32_t)d;
}

static void schedule_retry(sd_sftp_session *s, sd_err why, uint32_t delay)
{
  s->retry_at = sd_tick_ms() + delay;
  s->attempts++;
  sd_log(SD_LOG_INFO, SFTP_COMP, NULL, "reconnect attempt %u in %u ms (%s)", s->attempts, delay, sd_err_name(why));
  set_state_ex(s, SD_SFTP_ST_RECONNECT_WAIT, why, delay, s->attempts);
}

/* The reconnect loop stopped: waiting requests fail, the state is final until reconnect_now(). */
static void stop_loop(sd_sftp_session *s, sd_sftp_state st, sd_err why)
{
  fail_live(s, SD_E_DISCONNECTED);
  mark_files_stale(s);
  s->in_attempt = 0;
  set_state(s, st, why);
}

/* After a connection (or a connection attempt) is gone: retry with backoff, or stop. */
static void after_loss(sd_sftp_session *s, sd_err why)
{
  const sd_sftp_reconnect_policy *rp = &s->opt.reconnect;
  int loop = rp->enabled && (s->tp.caps & SD_SFTP_TP_REOPEN) && (s->ever_ready || s->user_retry) && !s->retry_stopped;
  s->in_attempt = 0;
  if (s->close_requested) return;
  if (!loop || err_permanent(why)) { stop_loop(s, SD_SFTP_ST_FAILED, why); return; }
  if (err_needs_user(why)) { stop_loop(s, SD_SFTP_ST_AUTH_REQUIRED, why); return; }
  if (rp->max_attempts && s->attempts >= rp->max_attempts) {
    sd_log(SD_LOG_WARN, SFTP_COMP, NULL, "reconnect: giving up after %u attempts", s->attempts);
    stop_loop(s, SD_SFTP_ST_FAILED, why);
    return;
  }
  schedule_retry(s, why, backoff_ms(s, s->attempts));
}

static void do_lost(sd_sftp_session *s, sd_err why)
{
  sd_sftp_state prev = (sd_sftp_state)s->state;
  sftp_req *st = s->startup;
  s->lost_done = 1;
  s->lost_pending = 0;
  close_transport(s);
  s->startup = NULL;
  s->startup_done = 0;
  detach_all(s);
  if (st) req_free(st);
  sd_log(SD_LOG_WARN, SFTP_COMP, NULL, "session lost: %s (generation %u)", sd_err_name(why), s->generation);
  if (prev == SD_SFTP_ST_READY) {
    /* 01 §10.4 ordering: DISCONNECTED, in-flight completions, stale handles, then RECONNECT_WAIT */
    set_state(s, SD_SFTP_ST_DISCONNECTED, why);
    fail_on_loss(s);
    mark_files_stale(s);
  }
  after_loss(s, why);
}

static void finalize(sd_sftp_session *s)
{
  sftp_item *it;
  if (s->finalized) return;
  s->finalized = 1;
  sd_mutex_lock(&s->lock);
  s->in_closed = 1;
  it = s->in_head;
  s->in_head = s->in_tail = NULL;
  sd_mutex_unlock(&s->lock);
  while (it) {
    sftp_item *n = it->next;
    if (it->type == IT_SUBMIT) {
      sftp_req *r = (sftp_req *)it->ptr;
      live_add(s, r);
      finish(s, r, SD_E_SHUTDOWN);
    } else if (it->type == IT_CANCEL || it->type == IT_RECONNECT || it->type == IT_STOP) {
      sd_free(it);
    } else if (it->type == IT_RELEASE) {
      file_unlink_free(s, (sd_sftp_file *)it->ptr);
    }
    it = n;
  }
  mark_files_stale(s);
  set_state(s, SD_SFTP_ST_CLOSED, SD_OK);
}

static void do_close(sd_sftp_session *s)
{
  sftp_req *st = s->startup;
  s->startup = NULL;
  s->lost_done = 1;
  s->lost_pending = 0;
  s->in_attempt = 0;
  detach_all(s);
  if (st) req_free(st);
  fail_live(s, SD_E_SHUTDOWN);
  mark_files_stale(s);
  close_transport(s);
  if (!any_stream_open(s)) finalize(s);   /* else: once every open stream reported on_closed */
}

static void maybe_ready(sd_sftp_session *s);

static void io_epilogue(sd_sftp_session *s)
{
  int guard;
  if (s->finalized) return;
  for (guard = 0; guard < 4; guard++) {
    if (s->lost_pending) do_lost(s, s->lost_err);
    maybe_ready(s);
    schedule(s);
    if (!s->lost_pending) break;
  }
}

/* ---- startup ---- */

static void go_ready(sd_sftp_session *s)
{
  sd_sftp_event e;
  const sd_ssh_negotiated *neg = s->tp.negotiated ? s->tp.negotiated(s->tp.ctx) : NULL;
  uint32_t quirks = 0;
  sftp_req *r;
  int openssh = (neg && neg->server_version && strstr(neg->server_version, "OpenSSH") != NULL);

  if (s->opt.flags & SD_SFTP_OPT_SYMLINK_ORDER_OPENSSH) s->symlink_openssh = 1;
  else if (s->opt.flags & SD_SFTP_OPT_SYMLINK_ORDER_DRAFT) s->symlink_openssh = 0;
  else s->symlink_openssh = openssh || s->symlink_openssh;   /* any_openssh noted at VERSION */
  if (s->symlink_openssh) quirks |= SD_SFTP_QUIRK_SYMLINK_OPENSSH_ORDER;
  if ((neg && neg->server_version && strstr(neg->server_version, "OpenSSH_for_Windows")) ||
      (s->home && sftp_is_win_drive_path(s->home, strlen(s->home))))
    quirks |= SD_SFTP_QUIRK_WIN_DRIVE_PATHS;

  s->nchan = s->ch[1].got_version && s->ch[1].ss == SS_OPEN ? 2u : 1u;
  s->in_attempt = 0;
  s->ever_ready = 1;
  s->user_retry = 0;
  s->retry_stopped = 0;
  s->attempts = 0;
  /* only this thread writes gen_*0: adding the difference is an atomic store that works on x86 */
  sd_atomic_add64(&s->gen_rx0, sd_atomic_load64(&s->rx_total) - sd_atomic_load64(&s->gen_rx0));
  sd_atomic_add64(&s->gen_tx0, sd_atomic_load64(&s->tx_total) - sd_atomic_load64(&s->gen_tx0));
  sd_mutex_lock(&s->lock);
  s->generation++;
  s->info.generation = s->generation;
  s->info.version = 3;
  s->info.channels = s->nchan;
  s->info.connections = 1;
  s->info.quirks = quirks;
  s->info.home = s->home ? s->home : "";
  s->info.ssh = neg;
  sd_mutex_unlock(&s->lock);
  memset(s->member_ready, 0, sizeof(s->member_ready));   /* members re-admit after READY, 01 §10.9 */

  sd_log(SD_LOG_INFO, SFTP_COMP, NULL, "ready: generation %u channels=%u ext=0x%x max_read=%llu max_write=%llu quirks=0x%x",
         s->generation, s->nchan, s->info.ext, (unsigned long long)s->info.limits.max_read,
         (unsigned long long)s->info.limits.max_write, quirks);
  SD_LOGD(SFTP_COMP, "home=%s", s->info.home);     /* paths at debug level only (TM-R31) */
  set_state(s, SD_SFTP_ST_READY, SD_OK);
  if (s->ev) {
    memset(&e, 0, sizeof(e));
    e.type = SD_SFTP_EV_READY_INFO;
    e.state = SD_SFTP_ST_READY;
    e.info = &s->info;
    e.generation = s->generation;
    s->ev(s->ev_ctx, &e);
  }
  if (s->tp.notify_ready) s->tp.notify_ready(s->tp.ctx, s->home);   /* pool admission, 01 §10.9 */
  /* WAIT_READY requests in submission order (the list is LIFO). */
  {
    sftp_req *rev = NULL;
    while ((r = s->wait_head) != NULL) { s->wait_head = r->qnext; r->qnext = rev; rev = r; }
    while ((r = rev) != NULL) {
      rev = r->qnext;
      r->qnext = NULL;
      r->waiting = 0;
      if (r->done) { req_maybe_free(s, r); continue; }
      queue_phase(s, r, PH_MAIN, 0);
    }
  }
}

/* READY once the meta channel finished its startup and the bulk channel is up or settled as
   unavailable (01 §11 step 6). */
static void maybe_ready(sd_sftp_session *s)
{
  if (!s->in_attempt || s->lost_done || s->lost_pending || s->close_requested) return;
  if (s->startup_done && s->bulk_settled) go_ready(s);
}

static void degrade_bulk(sd_sftp_session *s, sd_err why)
{
  if (s->bulk_settled) return;
  s->bulk_settled = 1;
  sd_log(SD_LOG_INFO, SFTP_COMP, NULL, "bulk channel unavailable (%s): using one SFTP channel", sd_err_name(why));
}

static void startup_fail(sd_sftp_session *s, sd_err e)
{
  lose(s, e);
}

static int handle_version(sd_sftp_session *s, const uint8_t *p, size_t n)
{
  sftp_version_info *vi = (sftp_version_info *)sd_alloc(sizeof(*vi));
  size_t total = 0, i;
  char *str;
  sftp_req *st;
  sd_sftp_ext_entry *old_list, *new_list;
  char *old_strings, *new_strings;
  if (!vi) { lose(s, SD_E_NO_MEMORY); return -1; }
  if (sftp_parse_version(p, n, vi) != 0) { sd_free(vi); lose(s, SD_E_PROTOCOL); return -1; }
  if (vi->version != 3) {
    sd_log(SD_LOG_ERROR, SFTP_COMP, NULL, "server speaks SFTP version %u, need 3", vi->version);
    sd_free(vi);
    lose(s, SD_E_PROTOCOL);
    return -1;
  }
  for (i = 0; i < vi->ext_count; i++) total += vi->names[i].n + vi->versions[i].n + 2;
  new_list = (sd_sftp_ext_entry *)sd_calloc(vi->ext_count ? vi->ext_count : 1, sizeof(sd_sftp_ext_entry));
  new_strings = (char *)sd_alloc(total + 1);
  if (!new_list || !new_strings) { sd_free(new_list); sd_free(new_strings); sd_free(vi); lose(s, SD_E_NO_MEMORY); return -1; }
  str = new_strings;
  for (i = 0; i < vi->ext_count; i++) {
    new_list[i].name = str;
    memcpy(str, vi->names[i].p, vi->names[i].n); str += vi->names[i].n; *str++ = 0;
    new_list[i].version = str;
    memcpy(str, vi->versions[i].p, vi->versions[i].n); str += vi->versions[i].n; *str++ = 0;
  }
  /* the server may differ after a reconnect (01 §10.4): every generation re-reads everything */
  sd_mutex_lock(&s->lock);
  old_list = s->ext_list; old_strings = s->ext_strings;
  s->ext_list = new_list; s->ext_strings = new_strings;
  s->info.ext = vi->ext;
  s->info.ext_list = s->ext_list;
  s->info.ext_count = vi->ext_count;
  memset(s->raw_limits, 0, sizeof(s->raw_limits));
  sftp_effective_limits(s->raw_limits, &s->info.limits);
  memset(&s->info.identity, 0, sizeof(s->info.identity));
  sd_mutex_unlock(&s->lock);
  sd_free(old_list);
  sd_free(old_strings);
  s->symlink_openssh = vi->any_openssh;
  s->ch[0].got_version = 1;
  sd_free(vi);

  st = (sftp_req *)sd_calloc(1, sizeof(*st));
  if (!st) { lose(s, SD_E_NO_MEMORY); return -1; }
  st->s = s;
  st->op = OP_STARTUP;
  st->eof_at = st->err_at = NO_OFF;
  s->startup = st;
  queue_phase(s, st, (s->info.ext & SD_SFTP_EXT_LIMITS) ? PH_ST_LIMITS : PH_ST_REALPATH, 0);
  return 0;
}

static void startup_reply(sd_sftp_session *s, sftp_req *st, sftp_wire *w, uint8_t type, sd_rd *rd)
{
  if (w->phase == PH_ST_LIMITS) {
    if (type == SFTP_EXTENDED_REPLY) {
      uint64_t v[4];
      if (sftp_parse_limits(rd, v) != 0) { startup_fail(s, SD_E_PROTOCOL); return; }
      memcpy(s->raw_limits, v, sizeof(v));
      sd_mutex_lock(&s->lock);
      sftp_effective_limits(s->raw_limits, &s->info.limits);
      sd_mutex_unlock(&s->lock);
    }
    queue_phase(s, st, PH_ST_REALPATH, 1);
  } else if (w->phase == PH_ST_REALPATH) {
    if (type == SFTP_NAME) {
      uint32_t count = sd_rd_u32(rd);
      sd_span nm = sd_rd_string(rd, SFTP_MAX_PATH);
      if (!sd_rd_ok(rd) || count < 1) { startup_fail(s, SD_E_PROTOCOL); return; }
      sd_mutex_lock(&s->lock);
      sd_free(s->home);
      s->home = dup_bytes(nm.p, nm.n);
      sd_mutex_unlock(&s->lock);
      if (!s->home) { startup_fail(s, SD_E_NO_MEMORY); return; }
      queue_phase(s, st, PH_ST_STAT, 1);
    } else {
      uint32_t code = sd_rd_u32(rd);
      startup_fail(s, sd_rd_ok(rd) ? sd_sftp_status_to_err(code) : SD_E_PROTOCOL);
    }
  } else if (w->phase == PH_ST_STAT) {
    if (type == SFTP_ATTRS) {
      sd_sftp_attrs a;
      if (sftp_dec_attrs(rd, &a, NULL, 0) != 0) { startup_fail(s, SD_E_PROTOCOL); return; }
      if (a.valid & SD_SFTP_ATTR_UIDGID) {
        s->info.identity.source = SD_SFTP_ID_HOME_OWNER;
        s->info.identity.uid = a.uid;
        s->info.identity.gid = a.gid;
      }
    }
    s->startup = NULL;
    st->done = 1;
    req_maybe_free(s, st);
    s->startup_done = 1;          /* READY in maybe_ready(), once the bulk channel settled */
  }
}

/* ---- reply handling ---- */

typedef struct sftp_status { uint32_t code; sd_span msg; } sftp_status;

static int parse_status(sd_rd *rd, sftp_status *st)
{
  st->code = sd_rd_u32(rd);
  st->msg.p = NULL; st->msg.n = 0;
  if (!sd_rd_ok(rd)) return -1;
  if (sd_rd_remaining(rd) >= 4) {     /* message and language tag are optional in practice */
    sd_rd tmp = *rd;
    sd_span m = sd_rd_string(&tmp, 64 * 1024);
    if (sd_rd_ok(&tmp)) st->msg = m;
  }
  return 0;
}

static void keep_status(sftp_req *r, const sftp_status *st)
{
  r->c.sftp_status = st->code;
  sd_free(r->msg);
  r->msg = st->msg.n ? sanitize_dup(st->msg.p, st->msg.n) : NULL;
}

/* Starts a refinement probe for r after a FAILURE; returns 1 if a probe was queued. */
static int start_refine(sd_sftp_session *s, sftp_req *r)
{
  if (!refine_on(s, r)) return 0;
  switch (r->op) {
  case OP_MKDIR: case OP_SYMLINK: case OP_HARDLINK: case OP_RMDIR: case OP_REMOVE: case OP_OPENDIR:
    queue_phase(s, r, PH_PR_LSTAT, 1);
    return 1;
  case OP_OPEN:
    if ((r->u1 & (SD_SFTP_O_CREAT | SD_SFTP_O_EXCL)) == (SD_SFTP_O_CREAT | SD_SFTP_O_EXCL)) {
      queue_phase(s, r, PH_PR_LSTAT, 1);
      return 1;
    }
    return 0;
  case OP_RENAME:
    if (!(r->u1 & SD_SFTP_RENAME_OVERWRITE)) { queue_phase(s, r, PH_PR_LSTAT, 1); return 1; }
    return 0;
  case OP_WRITE: case OP_FSYNC: case OP_CLOSE:
    if (!(s->info.ext & SD_SFTP_EXT_STATVFS) || !r->f) return 0;
    if (r->op == OP_CLOSE && !r->f->written) return 0;
    queue_phase(s, r, PH_PR_STATVFS, 1);
    return 1;
  default:
    return 0;
  }
}

static void status_result(sd_sftp_session *s, sftp_req *r, const sftp_status *st)
{
  sd_err e = sd_sftp_status_to_err(st->code);
  keep_status(r, st);
  if (e == SD_E_FAILURE && start_refine(s, r)) { r->cerr = e; return; }
  finish(s, r, e);
}

static void open_handle_reply(sd_sftp_session *s, sftp_req *r, const sftp_wire *w, sd_rd *rd)
{
  sd_span h = sd_rd_string(rd, SFTP_MAX_HANDLE);
  if (!sd_rd_done(rd) || h.n == 0) { lose(s, SD_E_PROTOCOL); return; }
  if (r->done) { send_orphan_close(s, w->ch, h.p, (uint32_t)h.n); return; }
  if (r->op == OP_REOPEN) {
    memcpy(r->f->handle, h.p, h.n);
    r->f->hlen = (uint32_t)h.n;
    r->f->wire_closed = 0;
    r->f->written = 0;
    r->f->ch = w->ch;
    r->f->generation = s->generation;
    InterlockedExchange(&r->f->stale, 0);
    if (r->f->is_dir) { r->c.u.open.file = r->f; finish(s, r, SD_OK); return; }
    queue_phase(s, r, PH_FSTAT, 1);
    return;
  }
  r->newf = file_new(s, r->p1, r->op == OP_OPENDIR ? 0 : r->u1, r->op == OP_OPENDIR,
                     r->op == OP_OPENDIR || (r->flags & SD_SFTP_REQ_CLASS_META) || (r->f2 && r->f2->meta),
                     w->ch, h.p, (uint32_t)h.n);
  if (!r->newf) { send_orphan_close(s, w->ch, h.p, (uint32_t)h.n); finish(s, r, SD_E_NO_MEMORY); return; }
  if (r->op == OP_OPENDIR) {
    r->c.u.open.file = r->newf;
    r->newf = NULL;
    finish(s, r, SD_OK);
    return;
  }
  queue_phase(s, r, PH_FSTAT, 1);
}

static void read_reply(sd_sftp_session *s, sftp_req *r, sftp_wire *w, uint8_t type, sd_rd *rd)
{
  uint64_t rel = w->off - r->off;
  if (!r->done) {
    if (type == SFTP_DATA) {
      sd_span d = sd_rd_string(rd, w->len);
      if (!sd_rd_ok(rd)) { lose(s, SD_E_PROTOCOL); return; }
      if (d.n == 0) {
        if (rel < r->eof_at) r->eof_at = rel;
      } else {
        memcpy(r->buf + rel, d.p, d.n);
        if (d.n < w->len) {
          sftp_range *g = (sftp_range *)sd_alloc(sizeof(*g));
          if (!g) { lose(s, SD_E_NO_MEMORY); return; }
          g->off = w->off + d.n;
          g->len = w->len - (uint32_t)d.n;
          g->next = r->reissue;
          r->reissue = g;
          if (!r->queued) q_push(s, r, 1);
        }
      }
    } else {
      sftp_status st;
      if (parse_status(rd, &st) != 0) { lose(s, SD_E_PROTOCOL); return; }
      if (st.code == SFTP_FX_EOF) {
        if (rel < r->eof_at) r->eof_at = rel;
      } else if (st.code == SFTP_FX_OK) {
        lose(s, SD_E_PROTOCOL);
        return;
      } else if (rel < r->err_at) {
        r->err_at = rel;
        r->cerr = sd_sftp_status_to_err(st.code);
        keep_status(r, &st);
      }
    }
  }
  if (r->done || r->wires || req_has_more(r)) return;
  {
    uint64_t cut = chunk_cutoff(r);
    r->c.u.read.bytes = (uint32_t)cut;
    r->c.u.read.eof = r->eof_at != NO_OFF && r->eof_at <= cut;
    if (cut == 0) {
      if (r->err_at == 0) { finish(s, r, r->cerr); return; }
      finish(s, r, r->eof_at == 0 ? SD_E_EOF : SD_OK);
      return;
    }
    finish(s, r, SD_OK);
  }
}

static void write_reply(sd_sftp_session *s, sftp_req *r, sftp_wire *w, sd_rd *rd)
{
  sftp_status st;
  uint64_t rel = w->off - r->off;
  if (parse_status(rd, &st) != 0) { lose(s, SD_E_PROTOCOL); return; }
  if (!r->done && st.code != SFTP_FX_OK && rel < r->err_at) {
    r->err_at = rel;
    r->cerr = sd_sftp_status_to_err(st.code);
    keep_status(r, &st);
  }
  if (r->done || r->wires || req_has_more(r)) return;
  r->c.u.write.bytes = (uint32_t)(r->err_at < r->len ? r->err_at : r->len);
  if (r->err_at == NO_OFF) { finish(s, r, SD_OK); return; }
  if (r->cerr == SD_E_FAILURE && start_refine(s, r)) return;
  finish(s, r, r->cerr);
}

static void readdir_reply(sd_sftp_session *s, sftp_req *r, sd_rd *rd)
{
  uint32_t count, i, kept = 0, dropped = 0, total_ext = 0;
  size_t arena_cap;
  sd_rd scan;
  sd_sftp_dirent *ents;
  sd_sftp_extattr *ext;
  char *arena, *ap;

  count = sd_rd_u32(rd);
  if (!sd_rd_ok(rd) || count > sd_rd_remaining(rd) / 12) { lose(s, SD_E_PROTOCOL); return; }
  /* pass 1: validate, count extended pairs */
  scan = *rd;
  for (i = 0; i < count; i++) {
    uint32_t pairs;
    (void)sd_rd_string(&scan, SFTP_MAX_IN_PACKET);
    (void)sd_rd_string(&scan, SFTP_MAX_IN_PACKET);
    if (!sd_rd_ok(&scan) || sftp_count_attr_ext(&scan, &pairs) != 0) { lose(s, SD_E_PROTOCOL); return; }
    {
      sd_sftp_attrs tmp;
      if (sftp_dec_attrs(&scan, &tmp, NULL, 0) != 0) { lose(s, SD_E_PROTOCOL); return; }
    }
    total_ext += pairs;
  }
  if (!sd_rd_done(&scan)) { lose(s, SD_E_PROTOCOL); return; }
  if (r->done) return;
  arena_cap = sd_rd_remaining(rd) * 4 + (size_t)count * 2 + 16;
  ents = (sd_sftp_dirent *)sd_calloc(count ? count : 1, sizeof(*ents));
  ext = (sd_sftp_extattr *)sd_calloc(total_ext ? total_ext : 1, sizeof(*ext));
  arena = (char *)sd_alloc(arena_cap);
  if (!ents || !ext || !arena) {
    sd_free(ents); sd_free(ext); sd_free(arena);
    finish(s, r, SD_E_NO_MEMORY);
    return;
  }
  ap = arena;
  total_ext = 0;
  for (i = 0; i < count; i++) {
    sd_span nm = sd_rd_string(rd, SFTP_MAX_IN_PACKET);
    sd_span ln = sd_rd_string(rd, SFTP_MAX_IN_PACKET);
    sd_sftp_dirent *d = &ents[kept];
    uint32_t pairs = 0;
    size_t lout = 0;
    (void)sftp_count_attr_ext(rd, &pairs);
    (void)sftp_dec_attrs(rd, &d->attrs, ext + total_ext, pairs);
    if (!sftp_dirent_name_ok(nm.p, nm.n)) {
      if (!(nm.n == 1 && nm.p[0] == '.') && !(nm.n == 2 && nm.p[0] == '.' && nm.p[1] == '.')) {
        dropped++;
        if (!r->f->drop_logged) {
          char esc[64];
          size_t el = 0;
          r->f->drop_logged = 1;
          if (sd_text_sanitize_server((const char *)nm.p, nm.n < 20 ? nm.n : 20, esc, sizeof(esc), &el) != SD_OK) el = 0;
          esc[el < sizeof(esc) ? el : sizeof(esc) - 1] = 0;
          sd_log(SD_LOG_WARN, SFTP_COMP, NULL, "readdir: dropped malformed entry name \"%s\" (len %u)", esc,
                 (unsigned)nm.n);
        }
      }
      memset(d, 0, sizeof(*d));
      continue;
    }
    total_ext += pairs;
    memcpy(ap, nm.p, nm.n); ap[nm.n] = 0;
    d->name = ap; d->name_len = (uint32_t)nm.n;
    ap += nm.n + 1;
    if (sd_text_sanitize_server((const char *)ln.p, ln.n, ap, ln.n * 3 + 1, &lout) != SD_OK) lout = 0;
    ap[lout] = 0;
    d->longname = ap; d->longname_len = (uint32_t)lout;
    ap += lout + 1;
    kept++;
  }
  r->c.u.readdir.ents = ents;
  r->c.u.readdir.count = kept;
  r->c.u.readdir.dropped = dropped;
  r->c.u.readdir.eof = 0;
  finish(s, r, SD_OK);
  sd_free(ents); sd_free(ext); sd_free(arena);
}

static void name_reply(sd_sftp_session *s, sftp_req *r, sd_rd *rd)
{
  uint32_t count = sd_rd_u32(rd);
  sd_span nm = sd_rd_string(rd, SFTP_MAX_IN_PACKET);
  sd_span ln = sd_rd_string(rd, SFTP_MAX_IN_PACKET);
  sd_sftp_attrs a;
  char *path;
  SD_UNUSED(ln);
  if (!sd_rd_ok(rd) || count != 1 || sftp_dec_attrs(rd, &a, s->scratch_ext, SFTP_MAX_EXT_PAIRS) != 0) {
    lose(s, SD_E_PROTOCOL);
    return;
  }
  if (r->done) return;
  path = dup_bytes(nm.p, nm.n);
  if (!path) { finish(s, r, SD_E_NO_MEMORY); return; }
  r->c.u.name.path = path;
  r->c.u.name.len = (uint32_t)nm.n;
  r->c.u.name.attrs = a;
  sd_free(r->p2);
  r->p2 = path;                       /* freed with the request */
  if (r->op == OP_EXPAND || r->op == OP_HOME || r->op == OP_REALPATH || r->op == OP_READLINK)
    finish(s, r, SD_OK);
  else
    finish(s, r, SD_E_INTERNAL);
}

static void names_reply(sd_sftp_session *s, sftp_req *r, sd_rd *rd)
{
  sd_rd us = sd_rd_sub(rd, SFTP_MAX_IN_PACKET), gs = sd_rd_sub(rd, SFTP_MAX_IN_PACKET);
  const char **uv, **gv;
  char *arena, *ap;
  uint32_t i, nu = 0, ng = 0;
  if (!sd_rd_ok(rd)) { lose(s, SD_E_PROTOCOL); return; }
  if (r->done) return;
  uv = (const char **)sd_calloc(r->nu + 1, sizeof(char *));
  gv = (const char **)sd_calloc(r->ng + 1, sizeof(char *));
  arena = (char *)sd_alloc((us.n + gs.n) * 3 + (size_t)(r->nu + r->ng) + 2);
  if (!uv || !gv || !arena) { sd_free((void *)uv); sd_free((void *)gv); sd_free(arena); finish(s, r, SD_E_NO_MEMORY); return; }
  ap = arena;
  for (i = 0; i < r->nu + r->ng; i++) {
    sd_rd *src = i < r->nu ? &us : &gs;
    sd_span v = sd_rd_string(src, 4096);
    size_t out = 0;
    if (!sd_rd_ok(src)) v.n = 0;
    if (v.n && sd_text_sanitize_server((const char *)v.p, v.n, ap, v.n * 3 + 1, &out) != SD_OK) out = 0;
    ap[out] = 0;
    if (i < r->nu) uv[nu++] = ap; else gv[ng++] = ap;
    ap += out + 1;
  }
  r->c.u.ids.users = uv;
  r->c.u.ids.groups = gv;
  r->c.u.ids.nu = nu;
  r->c.u.ids.ng = ng;
  finish(s, r, SD_OK);
  sd_free((void *)uv); sd_free((void *)gv); sd_free(arena);
}

static void probe_reply(sd_sftp_session *s, sftp_req *r, sftp_wire *w, uint8_t type, sd_rd *rd)
{
  if (r->done) {
    if (type == SFTP_HANDLE && w->phase == PH_PR_OPENDIR) {
      sd_span h = sd_rd_string(rd, SFTP_MAX_HANDLE);
      if (sd_rd_ok(rd) && h.n) send_orphan_close(s, w->ch, h.p, (uint32_t)h.n);
    }
    return;
  }
  switch (w->phase) {
  case PH_PR_LSTAT:
    if (type == SFTP_ATTRS) {
      sd_sftp_attrs a;
      if (sftp_dec_attrs(rd, &a, NULL, 0) != 0) { lose(s, SD_E_PROTOCOL); return; }
      switch (r->op) {
      case OP_RMDIR:
        if (!(a.valid & SD_SFTP_ATTR_PERM)) break;
        if (!SD_SFTP_IS_DIR(&a)) { finish(s, r, SD_E_NOT_A_DIRECTORY); return; }
        queue_phase(s, r, PH_PR_OPENDIR, 1);
        return;
      case OP_REMOVE:
        if (SD_SFTP_IS_DIR(&a)) { finish(s, r, SD_E_IS_A_DIRECTORY); return; }
        break;
      case OP_OPENDIR:
        if ((a.valid & SD_SFTP_ATTR_PERM) && !SD_SFTP_IS_DIR(&a)) { finish(s, r, SD_E_NOT_A_DIRECTORY); return; }
        break;
      default:
        finish(s, r, SD_E_EXISTS);
        return;
      }
    }
    finish(s, r, r->cerr);
    return;
  case PH_PR_OPENDIR:
    if (type == SFTP_HANDLE) {
      sd_span h = sd_rd_string(rd, SFTP_MAX_HANDLE);
      if (!sd_rd_ok(rd) || h.n == 0) { lose(s, SD_E_PROTOCOL); return; }
      memcpy(r->ph, h.p, h.n);
      r->phlen = (uint32_t)h.n;
      r->ph_open = 1;
      r->ph_ch = w->ch;
      queue_phase(s, r, PH_PR_READDIR, 1);
      return;
    }
    finish(s, r, r->cerr);
    return;
  case PH_PR_READDIR:
    if (type == SFTP_NAME) {
      uint32_t count = sd_rd_u32(rd), i;
      for (i = 0; i < count && sd_rd_ok(rd); i++) {
        sd_span nm = sd_rd_string(rd, SFTP_MAX_IN_PACKET);
        sd_sftp_attrs a;
        (void)sd_rd_string(rd, SFTP_MAX_IN_PACKET);
        if (sftp_dec_attrs(rd, &a, NULL, 0) != 0) break;
        if (sftp_dirent_name_ok(nm.p, nm.n)) { r->probe_found = 1; break; }
      }
      if (!sd_rd_ok(rd) && !r->probe_found) { lose(s, SD_E_PROTOCOL); return; }
      if (r->probe_found) { r->cerr = SD_E_NOT_EMPTY; queue_phase(s, r, PH_PR_CLOSE, 1); return; }
      queue_phase(s, r, PH_PR_READDIR, 1);
      return;
    }
    queue_phase(s, r, PH_PR_CLOSE, 1);   /* EOF or error: nothing found */
    return;
  case PH_PR_CLOSE:
    finish(s, r, r->cerr);
    return;
  case PH_PR_STATVFS:
    if (type == SFTP_EXTENDED_REPLY) {
      sd_sftp_statvfs v;
      if (sftp_parse_statvfs(rd, &v) == 0 && v.bavail == 0) { finish(s, r, SD_E_NO_SPACE); return; }
    }
    finish(s, r, r->cerr);
    return;
  default:
    finish(s, r, SD_E_INTERNAL);
  }
}

static void reply(sd_sftp_session *s, sftp_req *r, sftp_wire *w, uint8_t type, sd_rd *rd)
{
  sftp_status st;

  if (r->op == OP_STARTUP) { startup_reply(s, r, w, type, rd); return; }
  if (r->op == OP_READ && w->phase == PH_MAIN) { read_reply(s, r, w, type, rd); return; }
  if (r->op == OP_WRITE && w->phase == PH_MAIN) { write_reply(s, r, w, rd); return; }
  if (w->phase >= PH_PR_LSTAT && w->phase <= PH_PR_STATVFS) { probe_reply(s, r, w, type, rd); return; }

  if (w->phase == PH_FSTAT) {
    sd_sftp_file *f = r->op == OP_REOPEN ? r->f : r->newf;
    if (r->done) return;
    if (type == SFTP_ATTRS) {
      if (sftp_dec_attrs(rd, &r->c.u.open.attrs, s->scratch_ext, SFTP_MAX_EXT_PAIRS) != 0) { lose(s, SD_E_PROTOCOL); return; }
      if (f) { f->attrs_at_open = r->c.u.open.attrs; f->attrs_at_open.ext = NULL; f->attrs_at_open.ext_count = 0; }
    }
    if (r->op == OP_REOPEN) { r->c.u.open.file = r->f; }
    else { r->c.u.open.file = r->newf; r->newf = NULL; }
    finish(s, r, SD_OK);
    return;
  }

  if (type == SFTP_STATUS) {
    if (parse_status(rd, &st) != 0) { lose(s, SD_E_PROTOCOL); return; }
    if (r->done) return;
    if (st.code == SFTP_FX_OK && (w->expect & (EXP_HANDLE | EXP_NAME | EXP_ATTRS | EXP_EXT))) {
      lose(s, SD_E_PROTOCOL);
      return;
    }
    if (r->op == OP_READDIR && st.code == SFTP_FX_EOF) {
      r->c.u.readdir.eof = 1;
      finish(s, r, SD_OK);
      return;
    }
    if (r->op == OP_CLOSE && st.code == SFTP_FX_OK) { finish(s, r, SD_OK); return; }
    if (r->op == OP_COPY && st.code == SFTP_FX_OK) r->c.u.copy.bytes = r->len64;
    status_result(s, r, &st);
    return;
  }

  switch (type) {
  case SFTP_HANDLE:
    open_handle_reply(s, r, w, rd);
    return;
  case SFTP_ATTRS:
    if (r->done) return;
    if (sftp_dec_attrs(rd, &r->c.u.stat.attrs, s->scratch_ext, SFTP_MAX_EXT_PAIRS) != 0) { lose(s, SD_E_PROTOCOL); return; }
    finish(s, r, SD_OK);
    return;
  case SFTP_NAME:
    if (r->op == OP_READDIR) readdir_reply(s, r, rd); else name_reply(s, r, rd);
    return;
  case SFTP_EXTENDED_REPLY:
    if (r->done) return;
    if (r->op == OP_NAMES) { names_reply(s, r, rd); return; }
    if (sftp_parse_statvfs(rd, &r->c.u.statvfs.v) != 0) { lose(s, SD_E_PROTOCOL); return; }
    finish(s, r, SD_OK);
    return;
  default:
    lose(s, SD_E_PROTOCOL);
  }
}

static uint32_t exp_bit(uint8_t type)
{
  switch (type) {
  case SFTP_HANDLE: return EXP_HANDLE;
  case SFTP_DATA: return EXP_DATA;
  case SFTP_NAME: return EXP_NAME;
  case SFTP_ATTRS: return EXP_ATTRS;
  case SFTP_EXTENDED_REPLY: return EXP_EXT;
  default: return 0;
  }
}

static void rtt_sample(sd_sftp_session *s, uint64_t sent)
{
  uint32_t m = (uint32_t)(sd_tick_ms() - sent);
  if (!s->rtt_init) { s->srtt_ms = m; s->rttvar_ms = m / 2; s->rtt_init = 1; return; }
  {
    uint32_t d = m > s->srtt_ms ? m - s->srtt_ms : s->srtt_ms - m;
    s->rttvar_ms = (3 * s->rttvar_ms + d) / 4;
    s->srtt_ms = (7 * s->srtt_ms + m) / 8;
  }
}

/* VERSION on the bulk channel: only the protocol version matters (extensions and limits come from
   the meta channel; both channels reach the same server). */
static void bulk_version(sd_sftp_session *s, sftp_chan *ch, const uint8_t *p, size_t n)
{
  sftp_version_info *vi = (sftp_version_info *)sd_alloc(sizeof(*vi));
  if (!vi) { lose(s, SD_E_NO_MEMORY); return; }
  if (sftp_parse_version(p, n, vi) != 0 || vi->version != 3) { sd_free(vi); lose(s, SD_E_PROTOCOL); return; }
  sd_free(vi);
  ch->got_version = 1;
  s->bulk_settled = 1;
}

static void dispatch(sd_sftp_session *s, sftp_chan *ch, const uint8_t *p, size_t n)
{
  uint8_t type = p[0];
  uint32_t id;
  sftp_wire *w;
  sftp_req *r;
  sd_rd rd;

  if (!ch->got_version) {
    if (type != SFTP_VERSION) { lose(s, SD_E_PROTOCOL); return; }
    if (ch->idx == 0) handle_version(s, p + 1, n - 1);
    else bulk_version(s, ch, p + 1, n - 1);
    return;
  }
  sd_rd_init(&rd, p + 1, n - 1);
  id = sd_rd_u32(&rd);
  if (!sd_rd_ok(&rd)) { lose(s, SD_E_PROTOCOL); return; }
  w = wire_take(s, id);
  if (w && w->ch != ch->idx) {
    sd_log(SD_LOG_ERROR, SFTP_COMP, NULL, "reply id %u on channel %u, sent on %u", id, ch->idx, w->ch);
    sd_free(w);
    lose(s, SD_E_PROTOCOL);
    return;
  }
  if (!w) {
    sd_log(SD_LOG_ERROR, SFTP_COMP, NULL, "reply with unknown id %u (type %u)", id, (unsigned)type);
    lose(s, SD_E_PROTOCOL);
    return;
  }
  if (type != SFTP_STATUS && !(exp_bit(type) & w->expect)) {
    sd_log(SD_LOG_ERROR, SFTP_COMP, NULL, "unexpected reply type %u for id %u", (unsigned)type, id);
    sd_free(w);
    lose(s, SD_E_PROTOCOL);
    return;
  }
  r = w->r;
  if (!r) { sd_free(w); return; }   /* orphan close acknowledged */
  r->wires--;
  if (r->done) {                     /* late reply (cancelled / timed out): discard, close stray handles */
    if (type == SFTP_HANDLE && (w->phase == PH_MAIN || w->phase == PH_PR_OPENDIR)) {
      sd_span h = sd_rd_string(&rd, SFTP_MAX_HANDLE);
      if (sd_rd_ok(&rd) && h.n) send_orphan_close(s, w->ch, h.p, (uint32_t)h.n);
    }
    sd_free(w);
    req_maybe_free(s, r);
    return;
  }
  if (w->ch == 0 && (w->phase != PH_MAIN || (r->op != OP_READ && r->op != OP_WRITE))) rtt_sample(s, w->sent_ms);
  reply(s, r, w, type, &rd);         /* may complete and free r */
  sd_free(w);
}

/* ---- transport sink (I/O thread; ctx is the sftp_chan) ---- */

static void open_bulk(sd_sftp_session *s);

static void stream_gone(sd_sftp_session *s)
{
  if (s->close_requested && !any_stream_open(s)) { do_close(s); return; }   /* finalizes */
  io_epilogue(s);
}

static void sink_on_open(void *ctx, sd_err err)
{
  sftp_chan *ch = (sftp_chan *)ctx;
  sd_sftp_session *s = ch->s;
  size_t st;
  if (s->finalized || ch->ss != SS_OPENING) return;
  if (err != SD_OK) {
    ch->ss = SS_NONE;
    if (ch->idx == 1) degrade_bulk(s, err);     /* e.g. MaxSessions 1: continue with one channel */
    else if (!s->lost_done) lose(s, err);
    stream_gone(s);
    return;
  }
  ch->ss = SS_OPEN;
  if (s->lost_done || s->close_requested) {   /* the connection is already being torn down */
    s->tp_close_called = 0;
    close_transport(s);
    return;
  }
  st = sftp_pkt_begin(&ch->obuf, SFTP_INIT, 0, 0);
  sd_wr_u32(&ch->obuf, 3);
  sftp_pkt_end(&ch->obuf, st);
  flush(s, ch);
  if (ch->idx == 0) {
    s->startup_deadline = sd_tick_ms() + s->opt.default_timeout_ms;
    open_bulk(s);
  }
  io_epilogue(s);
}

static int ibuf_reserve(sftp_chan *ch, size_t need)
{
  if (need <= ch->icap) return 1;
  {
    size_t cap = ch->icap ? ch->icap : 65536;
    uint8_t *p;
    while (cap < need) cap *= 2;
    p = (uint8_t *)sd_realloc(ch->ibuf, cap);
    if (!p) return 0;
    ch->ibuf = p;
    ch->icap = cap;
  }
  return 1;
}

/* Parses complete packets from p[0..n); returns bytes consumed or SIZE_MAX on a framing error. */
static size_t parse_packets(sd_sftp_session *s, sftp_chan *ch, const uint8_t *p, size_t n)
{
  size_t off = 0;
  while (n - off >= 4 && !s->lost_pending && !s->lost_done) {
    uint32_t len = sd_load_be32(p + off);
    if (len == 0 || len > SFTP_MAX_IN_PACKET) {
      sd_log(SD_LOG_ERROR, SFTP_COMP, NULL, "bad inbound packet length %u", len);
      return SIZE_MAX;
    }
    if (n - off - 4 < len) break;
    dispatch(s, ch, p + off + 4, len);
    off += 4 + (size_t)len;
  }
  return off;
}

static void sink_on_data(void *ctx, const uint8_t *p, size_t n)
{
  sftp_chan *ch = (sftp_chan *)ctx;
  sd_sftp_session *s = ch->s;
  if (s->finalized) return;
  sd_atomic_add64(&s->rx_total, (LONG64)n);
  if (!s->lost_done && !s->lost_pending && ch->ss == SS_OPEN) {
    if (ch->ilen == 0) {
      size_t used = parse_packets(s, ch, p, n);
      if (used == SIZE_MAX) lose(s, SD_E_PROTOCOL);
      else if (used < n && !s->lost_pending && !s->lost_done) {
        if (!ibuf_reserve(ch, n - used)) lose(s, SD_E_NO_MEMORY);
        else { memcpy(ch->ibuf, p + used, n - used); ch->ilen = n - used; }
      }
    } else {
      if (!ibuf_reserve(ch, ch->ilen + n)) lose(s, SD_E_NO_MEMORY);
      else {
        size_t used;
        memcpy(ch->ibuf + ch->ilen, p, n);
        ch->ilen += n;
        used = parse_packets(s, ch, ch->ibuf, ch->ilen);
        if (used == SIZE_MAX) lose(s, SD_E_PROTOCOL);
        else if (used && !s->lost_done) { memmove(ch->ibuf, ch->ibuf + used, ch->ilen - used); ch->ilen -= used; }
      }
    }
  }
  if (ch->ss == SS_OPEN) tp_consumed(s, ch->idx, n);
  io_epilogue(s);
}

static void sink_on_writable(void *ctx)
{
  sftp_chan *ch = (sftp_chan *)ctx;
  sd_sftp_session *s = ch->s;
  if (s->finalized) return;
  flush(s, ch);
  io_epilogue(s);
}

/* A stream ended. The bulk channel ending before its VERSION only degrades to one channel. */
static void stream_lost(sd_sftp_session *s, sftp_chan *ch, sd_err why)
{
  if (s->lost_done) return;
  if (ch->idx == 1 && !ch->got_version && s->in_attempt && !s->bulk_settled) { degrade_bulk(s, why); return; }
  lose(s, why);
}

static void sink_on_eof(void *ctx)
{
  sftp_chan *ch = (sftp_chan *)ctx;
  sd_sftp_session *s = ch->s;
  if (s->finalized) return;
  stream_lost(s, ch, SD_E_DISCONNECTED);
  io_epilogue(s);
}

static void sink_on_closed(void *ctx, sd_err why)
{
  sftp_chan *ch = (sftp_chan *)ctx;
  sd_sftp_session *s = ch->s;
  ch->ss = SS_NONE;
  if (s->finalized) return;
  if (!s->close_requested) stream_lost(s, ch, why != SD_OK && why != SD_E_SHUTDOWN ? why : SD_E_DISCONNECTED);
  stream_gone(s);
}

static const sd_ssh_channel_sink k_sink = {
  sink_on_open, sink_on_data, sink_on_writable, sink_on_eof, sink_on_closed
};

static void open_bulk(sd_sftp_session *s)
{
  sd_err e;
  if (s->opt.channels < 2 || !(s->tp.caps & SD_SFTP_TP_STREAMS) || !s->tp.open_stream) {
    s->bulk_settled = 1;
    return;
  }
  s->ch[1].ss = SS_OPENING;
  e = s->tp.open_stream(s->tp.ctx, 1, &k_sink, &s->ch[1]);
  if (e != SD_OK) { s->ch[1].ss = SS_NONE; degrade_bulk(s, e); }
}

void sftp_session_auth_prompt(sd_sftp_session *s)
{
  /* 01 §10.4: a reconnect that needs user interaction shows as AUTH_REQUIRED while the prompt is out */
  if (s && s->in_attempt && s->ever_ready && (sd_sftp_state)s->state == SD_SFTP_ST_CONNECTING)
    set_state(s, SD_SFTP_ST_AUTH_REQUIRED, SD_E_AUTH_REQUIRED);
}

/* 01 §10.9: a pool member settled (I/O thread). admitted: 1 the member is READY, 0 it was dropped
   (reason tells why). The pool count includes the primary. EV_POOL is informational only. */
void sftp_session_pool_change(sd_sftp_session *s, uint32_t member, int admitted, sd_err reason)
{
  sd_sftp_event e;
  uint32_t count = 1, i;
  if (!s || member == 0 || member > 3) return;
  for (i = 1; i <= 3; i++)
    if (s->member_ready[i] || (i == member && admitted)) count++;
  if (!admitted) s->member_ready[member] = 0;
  else s->member_ready[member] = 1;
  sd_mutex_lock(&s->lock);
  s->info.connections = count;
  sd_mutex_unlock(&s->lock);
  if (!s->ev) return;
  memset(&e, 0, sizeof(e));
  e.type = SD_SFTP_EV_POOL;
  e.state = (sd_sftp_state)s->state;
  e.reason = admitted ? SD_OK : reason;
  e.member = member;
  e.connections = count;
  s->ev(s->ev_ctx, &e);
}

/* ---- inbox processing (I/O thread) ---- */

/* WAIT_READY may wait in every state that can still lead to READY (02 §5.2 offline_wait). */
static int can_wait(const sd_sftp_session *s, sd_sftp_state st)
{
  if (s->close_requested) return 0;
  switch (st) {
  case SD_SFTP_ST_IDLE: case SD_SFTP_ST_CONNECTING: case SD_SFTP_ST_DISCONNECTED: case SD_SFTP_ST_RECONNECT_WAIT:
    return 1;
  case SD_SFTP_ST_AUTH_REQUIRED:
    return s->in_attempt;
  default:
    return 0;
  }
}

static void route_submitted(sd_sftp_session *s, sftp_req *r)
{
  sd_sftp_state st = (sd_sftp_state)s->state;
  live_add(s, r);
  if (r->cancel_pending) { finish(s, r, SD_E_CANCELLED); return; }
  if (r->op == OP_CLOSE && (r->f->stale || r->f->wire_closed)) { finish(s, r, SD_OK); return; }
  if (st == SD_SFTP_ST_READY && !s->lost_done) { queue_phase(s, r, PH_MAIN, 0); return; }
  if ((r->flags & SD_SFTP_REQ_WAIT_READY) && can_wait(s, st) && !(r->f && r->f->stale)) {
    wait_push(s, r);
    return;
  }
  finish(s, r, st == SD_SFTP_ST_CLOSED || s->close_requested ? SD_E_SHUTDOWN :
               (r->f && r->f->stale ? SD_E_STALE_HANDLE : SD_E_DISCONNECTED));
}

static void start_attempt(sd_sftp_session *s)
{
  sd_err e;
  uint32_t i;
  s->lost_done = 0;
  s->lost_pending = 0;
  s->lost_err = SD_OK;
  s->tp_close_called = 0;
  s->tp_opened = 1;
  s->startup_done = 0;
  s->bulk_settled = 0;
  s->nchan = 1;
  s->in_attempt = 1;
  s->retry_at = 0;
  for (i = 0; i < NCH; i++) { s->ch[i].got_version = 0; s->ch[i].ilen = 0; }
  /* until VERSION arrives the transport's own timeouts apply (sd_ssh: connect_timeout_ms) */
  s->startup_deadline = UINT64_MAX;
  set_state(s, SD_SFTP_ST_CONNECTING, SD_OK);
  s->ch[0].ss = SS_OPENING;
  e = s->tp.open(s->tp.ctx, &k_sink, &s->ch[0]);
  if (e != SD_OK) { s->ch[0].ss = SS_NONE; s->tp_opened = 0; lose(s, e); }
}

static void on_tick(sd_sftp_session *s)
{
  uint64_t now = sd_tick_ms();
  int any_sent = 0;
  sftp_req *r, *n;
  if (s->in_attempt && !s->startup_done && !s->lost_done && now >= s->startup_deadline) {
    lose(s, SD_E_TIMEOUT);
    return;
  }
  for (r = s->live_head; r; r = n) {
    n = r->lnext;
    if (r->deadline && now >= r->deadline) {
      if (r->sent) any_sent = 1;
      remove_waiting(s, r);
      finish(s, r, SD_E_TIMEOUT);
      n = s->live_head;   /* list may have changed; restart (finished ones are gone) */
    }
  }
  if (now - s->rate_t0 >= 1000) {
    uint64_t rx = (uint64_t)sd_atomic_load64(&s->rx_total), tx = (uint64_t)sd_atomic_load64(&s->tx_total);
    uint64_t dt = now - s->rate_t0;
    if (s->rate_t0) {
      s->rx_bps = (s->rx_bps + (rx - s->rate_rx0) * 1000 / dt) / 2;
      s->tx_bps = (s->tx_bps + (tx - s->rate_tx0) * 1000 / dt) / 2;
    }
    s->rate_t0 = now; s->rate_rx0 = rx; s->rate_tx0 = tx;
  }
  if (any_sent && s->tp.probe && s->ch[0].ss == SS_OPEN && !s->lost_done && now - s->last_probe_ms >= 1000) {
    s->last_probe_ms = now;
    s->tp.probe(s->tp.ctx);    /* liveness probe on request timeout (01 §4.6, C16) */
  }
  if ((sd_sftp_state)s->state == SD_SFTP_ST_RECONNECT_WAIT && !s->close_requested && now >= s->retry_at &&
      streams_quiet(s))
    start_attempt(s);
}

static void do_cancel(sd_sftp_session *s, uint64_t id)
{
  sftp_req *r;
  sd_mutex_lock(&g_tok_lock);
  r = tok_find_locked(id);
  sd_mutex_unlock(&g_tok_lock);
  if (!r || r->s != s || r->done) return;
  if (!r->in_live) { r->cancel_pending = 1; return; }
  remove_waiting(s, r);
  finish(s, r, SD_E_CANCELLED);
}

static void do_release(sd_sftp_session *s, sd_sftp_file *f)
{
  if (!f->stale && !f->wire_closed && f->hlen && !s->lost_done && (sd_sftp_state)s->state == SD_SFTP_ST_READY)
    send_orphan_close(s, f->ch, f->handle, f->hlen);
  file_unlink_free(s, f);
}

static void do_start(sd_sftp_session *s)
{
  start_attempt(s);
}

static void do_reconnect_now(sd_sftp_session *s)
{
  sd_sftp_state st = (sd_sftp_state)s->state;
  if (s->close_requested || !(s->tp.caps & SD_SFTP_TP_REOPEN)) return;
  if (st == SD_SFTP_ST_RECONNECT_WAIT) { s->retry_at = 0; return; }      /* skip the backoff */
  if (st == SD_SFTP_ST_FAILED || (st == SD_SFTP_ST_AUTH_REQUIRED && !s->in_attempt)) {
    s->user_retry = 1;
    s->retry_stopped = 0;
    s->attempts = 0;
    schedule_retry(s, SD_OK, 0);
  }
}

static void do_reconnect_stop(sd_sftp_session *s)
{
  sd_sftp_state st = (sd_sftp_state)s->state;
  if (s->close_requested || st == SD_SFTP_ST_READY || st == SD_SFTP_ST_FAILED || st == SD_SFTP_ST_CLOSED) return;
  s->retry_stopped = 1;
  if (s->in_attempt) { lose(s, SD_E_CANCELLED); return; }   /* after_loss() ends in FAILED */
  stop_loop(s, SD_SFTP_ST_FAILED, SD_E_CANCELLED);
}

static void io_drain(void *arg)
{
  sd_sftp_session *s = (sd_sftp_session *)arg;
  sftp_item *it;
  sd_mutex_lock(&s->lock);
  it = s->in_head;
  s->in_head = s->in_tail = NULL;
  s->kick_pending = 0;
  sd_mutex_unlock(&s->lock);
  while (it) {
    sftp_item *n = it->next;
    if (s->finalized) {   /* only after a close: drop what is left (finalize() handled the inbox) */
      if (it->type == IT_SUBMIT) { sftp_req *r = (sftp_req *)it->ptr; live_add(s, r); finish(s, r, SD_E_SHUTDOWN); }
      else if (it->type == IT_CANCEL || it->type == IT_RECONNECT || it->type == IT_STOP) sd_free(it);
      else if (it->type == IT_RELEASE) file_unlink_free(s, (sd_sftp_file *)it->ptr);
      it = n;
      continue;
    }
    switch (it->type) {
    case IT_SUBMIT:    route_submitted(s, (sftp_req *)it->ptr); break;
    case IT_CANCEL:    do_cancel(s, it->id); sd_free(it); break;
    case IT_RELEASE:   do_release(s, (sd_sftp_file *)it->ptr); break;
    case IT_TICK:      InterlockedExchange(&s->tick_pending, 0); on_tick(s); break;
    case IT_START:     do_start(s); break;
    case IT_CLOSE:     do_close(s); break;
    case IT_RECONNECT: sd_free(it); do_reconnect_now(s); break;
    case IT_STOP:      sd_free(it); do_reconnect_stop(s); break;
    default: break;
    }
    it = n;
  }
  io_epilogue(s);
}

/* ---- timer thread ---- */

static unsigned __stdcall timer_main(void *arg)
{
  sd_sftp_session *s = (sd_sftp_session *)arg;
  while (sd_event_wait(&s->timer_stop, TICK_MS) == SD_E_TIMEOUT) {
    sd_sftp_state st = (sd_sftp_state)s->state;
    if ((s->live > 0 || st == SD_SFTP_ST_CONNECTING || st == SD_SFTP_ST_READY || st == SD_SFTP_ST_RECONNECT_WAIT ||
         st == SD_SFTP_ST_AUTH_REQUIRED) &&
        InterlockedCompareExchange(&s->tick_pending, 1, 0) == 0) {
      s->tick_item.type = IT_TICK;
      if (!inbox_put(s, &s->tick_item)) break;
    }
  }
  return 0;
}

/* ---- lifecycle API ---- */

void sd_sftp_options_init(sd_sftp_options *o)
{
  memset(o, 0, sizeof(*o));
  o->struct_size = sizeof(*o);
  o->channels = 2;
  o->connections = 1;
  o->stripe_bytes = 1024u * 1024u;
  o->max_inflight_reqs = 64;
  o->max_inflight_bytes = 8u * 1024u * 1024u;
  o->max_queued_reqs = 4096;
  o->flags = SD_SFTP_OPT_REFINE_ERRORS;
  o->reconnect.enabled = 1;
  o->reconnect.initial_delay_ms = 1000;
  o->reconnect.max_delay_ms = 60000;
  o->default_timeout_ms = 30000;
}

static void chan_free(sftp_chan *ch)
{
  sd_wr_free(&ch->obuf);
  sd_free(ch->ibuf);
  ch->ibuf = NULL;
}

sd_err sd_sftp_session_create_transport(const sd_sftp_transport *t, const sd_sftp_options *opt,
                                        sd_sftp_event_cb ev, void *ev_ctx, sd_sftp_session **out)
{
  sd_sftp_session *s;
  sd_err e;
  uint32_t i;
  if (!out) return SD_E_INVALID_PARAM;
  *out = NULL;
  if (!t || !t->post || !t->open || !t->write || !t->consumed || !t->close || !t->destroy || !t->is_io_thread)
    return SD_E_INVALID_PARAM;
  if ((t->caps & SD_SFTP_TP_STREAMS) && (!t->open_stream || !t->write_stream || !t->consumed_stream))
    return SD_E_INVALID_PARAM;
  s = (sd_sftp_session *)sd_calloc(1, sizeof(*s));
  if (!s) return SD_E_NO_MEMORY;
  s->tp = *t;
  sd_sftp_options_init(&s->opt);
  if (opt) {
    size_t n = opt->struct_size && opt->struct_size < sizeof(*opt) ? opt->struct_size : sizeof(*opt);
    memcpy(&s->opt, opt, n);
    s->opt.struct_size = sizeof(s->opt);
  }
  if (s->opt.max_inflight_reqs == 0) s->opt.max_inflight_reqs = 64;
  if (s->opt.max_inflight_reqs > 1024) s->opt.max_inflight_reqs = 1024;
  if (s->opt.max_inflight_bytes == 0) s->opt.max_inflight_bytes = 8u * 1024u * 1024u;
  if (s->opt.max_queued_reqs == 0) s->opt.max_queued_reqs = 4096;
  if (s->opt.default_timeout_ms == 0) s->opt.default_timeout_ms = 30000;
  if (s->opt.channels != 1) s->opt.channels = 2;      /* 0 or out of range: the default */
  if (s->opt.connections == 0) s->opt.connections = 1;
  if (s->opt.connections > 4) s->opt.connections = 4;
  if (!s->opt.stripe_bytes) s->opt.stripe_bytes = 1024u * 1024u;
  if (s->opt.reconnect.max_delay_ms < s->opt.reconnect.initial_delay_ms)
    s->opt.reconnect.max_delay_ms = s->opt.reconnect.initial_delay_ms;
  s->ev = ev;
  s->ev_ctx = ev_ctx;
  s->state = SD_SFTP_ST_IDLE;
  s->nchan = 1;
  sd_mutex_init(&s->lock);
  for (i = 0; i < NCH; i++) {
    s->ch[i].s = s;
    s->ch[i].idx = i;
    sd_wr_init(&s->ch[i].obuf, 64u * 1024u * 1024u);
  }
  {
    uint64_t z[4] = { 0, 0, 0, 0 };
    sftp_effective_limits(z, &s->info.limits);
  }
  s->info.home = "";
  e = sd_event_init(&s->timer_stop, 1, 0);
  if (e == SD_OK) e = sd_thread_create(&s->timer, timer_main, s, 0, L"sd_sftp timer");
  if (e != SD_OK) {
    if (s->timer_stop.h) sd_event_destroy(&s->timer_stop);
    sd_mutex_destroy(&s->lock);
    for (i = 0; i < NCH; i++) chan_free(&s->ch[i]);
    sd_free(s);
    return e;
  }
  s->timer_started = 1;
  *out = s;
  return SD_OK;
}

sd_err sd_sftp_session_start(sd_sftp_session *s)
{
  if (!s) return SD_E_INVALID_PARAM;
  if (InterlockedCompareExchange(&s->state, SD_SFTP_ST_CONNECTING, SD_SFTP_ST_IDLE) != SD_SFTP_ST_IDLE)
    return SD_E_INVALID_PARAM;
  s->start_item.type = IT_START;
  if (!inbox_put(s, &s->start_item)) return SD_E_SHUTDOWN;
  return SD_OK;
}

static sd_err post_control(sd_sftp_session *s, uint32_t type)
{
  sftp_item *it = (sftp_item *)sd_calloc(1, sizeof(*it));
  if (!it) return SD_E_NO_MEMORY;
  it->type = type;
  if (!inbox_put(s, it)) { sd_free(it); return SD_E_SHUTDOWN; }
  return SD_OK;
}

sd_err sd_sftp_session_reconnect_now(sd_sftp_session *s)
{
  sd_sftp_state st;
  if (!s) return SD_E_INVALID_PARAM;
  st = (sd_sftp_state)s->state;
  if (st == SD_SFTP_ST_CLOSED || s->close_requested) return SD_E_SHUTDOWN;
  if (st == SD_SFTP_ST_IDLE) return SD_E_INVALID_PARAM;
  if (!(s->tp.caps & SD_SFTP_TP_REOPEN)) return SD_E_UNSUPPORTED;
  return post_control(s, IT_RECONNECT);
}

sd_err sd_sftp_session_reconnect_stop(sd_sftp_session *s)
{
  if (!s) return SD_E_INVALID_PARAM;
  if ((sd_sftp_state)s->state == SD_SFTP_ST_CLOSED || s->close_requested) return SD_E_SHUTDOWN;
  return post_control(s, IT_STOP);
}

sd_err sd_sftp_session_close(sd_sftp_session *s)
{
  if (!s) return SD_E_INVALID_PARAM;
  if (InterlockedCompareExchange(&s->close_requested, 1, 0) != 0) return SD_OK;
  s->close_item.type = IT_CLOSE;
  if (!inbox_put(s, &s->close_item)) return SD_OK;
  return SD_OK;
}

void sd_sftp_session_destroy(sd_sftp_session *s)
{
  uint32_t b, i;
  sd_sftp_file *f;
  sftp_item *it;
  sftp_req *r;
  if (!s) return;
  if (s->tp.is_io_thread(s->tp.ctx)) {
    sd_log(SD_LOG_ERROR, SFTP_COMP, NULL, "sd_sftp_session_destroy called on the I/O thread");
    return;
  }
  if (s->timer_started) {
    sd_event_set(&s->timer_stop);
    (void)sd_thread_join(&s->timer, SD_WAIT_INFINITE, NULL);
  }
  s->finalized = 1;          /* late transport callbacks during its shutdown are ignored */
  s->tp.destroy(s->tp.ctx);
  /* Everything below is unreachable from other threads now. */
  sd_mutex_lock(&s->lock);
  s->in_closed = 1;
  it = s->in_head;
  s->in_head = s->in_tail = NULL;
  sd_mutex_unlock(&s->lock);
  while (it) {
    sftp_item *n = it->next;
    if (it->type == IT_SUBMIT) req_free((sftp_req *)it->ptr);
    else if (it->type == IT_CANCEL || it->type == IT_RECONNECT || it->type == IT_STOP) sd_free(it);
    else if (it->type == IT_RELEASE) file_unlink_free(s, (sd_sftp_file *)it->ptr);
    it = n;
  }
  for (b = 0; b < WIRE_BUCKETS; b++) {
    sftp_wire *w = s->wires[b];
    while (w) { sftp_wire *n = w->hnext; sd_free(w); w = n; }
  }
  while ((r = s->wait_head) != NULL) { s->wait_head = r->qnext; r->qnext = NULL; }
  while (s->live_head) {
    r = s->live_head;
    live_remove(s, r);
    tok_unregister(r);
    r->f = r->f2 = r->newf = NULL;
    req_free(r);
  }
  if (s->startup) { s->startup->f = NULL; req_free(s->startup); }
  while ((f = s->files) != NULL) {
    s->files = f->fnext;
    sd_free(f->path);
    sd_free(f);
  }
  sd_event_destroy(&s->timer_stop);
  sd_mutex_destroy(&s->lock);
  for (i = 0; i < NCH; i++) chan_free(&s->ch[i]);
  sd_free(s->ext_list);
  sd_free(s->ext_strings);
  sd_free(s->home);
  sd_free(s);
}

sd_sftp_state sd_sftp_session_state(const sd_sftp_session *s)
{
  return s ? (sd_sftp_state)s->state : SD_SFTP_ST_CLOSED;
}

uint32_t sd_sftp_session_generation(const sd_sftp_session *s) { return s ? s->generation : 0; }

int sd_sftp_session_is_io_thread(const sd_sftp_session *s)
{
  return s ? s->tp.is_io_thread(s->tp.ctx) : 0;
}

int sd_sftp_has_ext(const sd_sftp_session *s, uint32_t ext_bit)
{
  if (!s || (sd_sftp_state)s->state != SD_SFTP_ST_READY) return 0;
  return (s->info.ext & ext_bit) == ext_bit && ext_bit != 0;
}

sd_err sd_sftp_session_info(sd_sftp_session *s, sd_sftp_server_info *copy_out, char *home_buf, size_t home_len)
{
  if (!s || !copy_out) return SD_E_INVALID_PARAM;
  sd_mutex_lock(&s->lock);
  *copy_out = s->info;
  if (home_buf && home_len) {
    size_t n = s->home ? strlen(s->home) : 0;
    if (n >= home_len) n = home_len - 1;
    if (n) memcpy(home_buf, s->home, n);
    home_buf[n] = 0;
    copy_out->home = home_buf;
  }
  sd_mutex_unlock(&s->lock);
  return (sd_sftp_state)s->state == SD_SFTP_ST_READY ? SD_OK : SD_E_DISCONNECTED;
}

sd_err sd_sftp_session_stats(const sd_sftp_session *s, sd_sftp_stats *out)
{
  uint32_t inflight;
  LONG live;
  if (!s || !out) return SD_E_INVALID_PARAM;
  memset(out, 0, sizeof(*out));
  out->conn[0].srtt_ms = s->srtt_ms;
  out->conn[0].rttvar_ms = s->rttvar_ms;
  if (s->tp.rtt) {     /* the transport's keepalive/probe samples (01 §4.6) win when it has them */
    uint32_t a = 0, b = 0;
    s->tp.rtt(s->tp.ctx, &a, &b);
    if (a) { out->conn[0].srtt_ms = a; out->conn[0].rttvar_ms = b; }
  }
  out->conn[0].rx_bps = s->rx_bps;
  out->conn[0].tx_bps = s->tx_bps;
  out->conn[0].rx_total = (uint64_t)(sd_atomic_load64(&s->rx_total) - sd_atomic_load64(&s->gen_rx0));
  out->conn[0].tx_total = (uint64_t)(sd_atomic_load64(&s->tx_total) - sd_atomic_load64(&s->gen_tx0));
  inflight = s->ch[0].inflight + s->ch[1].inflight;     /* racy snapshot; statistics only */
  live = s->live;
  out->conn[0].inflight_reqs = inflight;
  out->conn[0].queued_reqs = live > 0 && (uint32_t)live > inflight ? (uint32_t)live - inflight : 0;
  out->conn[0].ready = (sd_sftp_state)s->state == SD_SFTP_ST_READY;
  out->conn_count = 1;
  out->total = out->conn[0];
  if (s->tp.member_stats) {            /* pool members 1..3 (01 §10.9) */
    uint32_t n = 0, i;
    s->tp.member_stats(s->tp.ctx, &out->conn[1], &n);
    if (n > 3) n = 3;
    for (i = 0; i < n; i++) {
      out->total.rx_total += out->conn[1 + i].rx_total;
      out->total.tx_total += out->conn[1 + i].tx_total;
    }
    out->conn_count += n;
  }
  out->generation = s->generation;
  out->channels = (sd_sftp_state)s->state == SD_SFTP_ST_READY ? s->nchan : 0;
  out->reconnect_attempts = s->attempts;
  return SD_OK;
}

/* ---- submission ---- */

static sftp_req *req_alloc(sd_sftp_session *s, uint32_t op, const sd_sftp_reqopt *o, sd_sftp_cb cb, void *ctx)
{
  sftp_req *r = (sftp_req *)sd_calloc(1, sizeof(*r));
  if (!r) return NULL;
  r->s = s;
  r->op = op;
  r->cb = cb;
  r->ctx = ctx;
  r->flags = o ? o->flags : 0;
  r->eof_at = r->err_at = NO_OFF;
  r->c.sftp_status = UINT32_MAX;
  return r;
}

static sd_err req_submit(sd_sftp_session *s, sftp_req *r, const sd_sftp_reqopt *o)
{
  sd_sftp_state st = (sd_sftp_state)s->state;
  uint32_t tmo = o && o->timeout_ms ? o->timeout_ms : s->opt.default_timeout_ms;
  int local_close = r->op == OP_CLOSE && (r->f->stale || r->f->wire_closed);

  if (st == SD_SFTP_ST_CLOSED || s->close_requested) { req_free(r); return SD_E_SHUTDOWN; }
  if (st != SD_SFTP_ST_READY && !local_close) {
    int waitable = (r->flags & SD_SFTP_REQ_WAIT_READY) && o && o->timeout_ms > 0 &&
                   (st == SD_SFTP_ST_IDLE || st == SD_SFTP_ST_CONNECTING || st == SD_SFTP_ST_DISCONNECTED ||
                    st == SD_SFTP_ST_RECONNECT_WAIT || st == SD_SFTP_ST_AUTH_REQUIRED);
    if (!waitable) { req_free(r); return SD_E_DISCONNECTED; }
  }
  if ((uint32_t)InterlockedIncrement(&s->live) > s->opt.max_queued_reqs) {
    InterlockedDecrement(&s->live);
    req_free(r);
    return SD_E_BUSY;
  }
  r->deadline = sd_tick_ms() + tmo;
  if (o && o->token_out) *o->token_out = (sd_sftp_req *)(uintptr_t)tok_register(r);
  r->item.type = IT_SUBMIT;
  r->item.ptr = r;
  if (!inbox_put(s, &r->item)) {
    InterlockedDecrement(&s->live);
    tok_unregister(r);
    req_free(r);
    return SD_E_SHUTDOWN;
  }
  return SD_OK;
}

static sd_err check_path(const char *p)
{
  if (!p) return SD_E_INVALID_PARAM;
  if (strlen(p) > SFTP_MAX_PATH) return SD_E_NAME_TOO_LONG;
  return SD_OK;
}

static sd_err submit_path(sd_sftp_session *s, uint32_t op, const char *p1, const char *p2, const sd_sftp_attrs *a,
                          uint32_t u1, const sd_sftp_reqopt *o, sd_sftp_cb cb, void *ctx)
{
  sftp_req *r;
  sd_err e;
  if (!s || !cb) return SD_E_INVALID_PARAM;
  if ((e = check_path(p1)) != SD_OK) return e;
  if (p2 && (e = check_path(p2)) != SD_OK) return e;
  r = req_alloc(s, op, o, cb, ctx);
  if (!r) return SD_E_NO_MEMORY;
  r->p1 = dup_str(p1);
  r->p2 = p2 ? dup_str(p2) : NULL;
  if (!r->p1 || (p2 && !r->p2)) { req_free(r); return SD_E_NO_MEMORY; }
  if (a) { r->a = *a; r->a.ext = NULL; r->a.ext_count = 0; r->has_attrs = 1; }
  r->u1 = u1;
  return req_submit(s, r, o);
}

static sd_err submit_file(sd_sftp_file *f, uint32_t op, const sd_sftp_reqopt *o, sd_sftp_cb cb, void *ctx,
                          sftp_req **out)
{
  sftp_req *r;
  *out = NULL;
  if (!f || !cb) return SD_E_INVALID_PARAM;
  if (op != OP_CLOSE && f->stale) return SD_E_STALE_HANDLE;
  if (op != OP_CLOSE && f->closing) return SD_E_INVALID_PARAM;
  r = req_alloc(f->s, op, o, cb, ctx);
  if (!r) return SD_E_NO_MEMORY;
  sd_sftp_file_addref(f);
  r->f = f;
  *out = r;
  return SD_OK;
}

sd_err sd_sftp_open(sd_sftp_session *s, const char *path, uint32_t oflags, const sd_sftp_attrs *create_attrs,
                    sd_sftp_file *same_channel_as, const sd_sftp_reqopt *o, sd_sftp_cb cb, void *ctx)
{
  sftp_req *r;
  sd_err e;
  if (!same_channel_as)
    return submit_path(s, OP_OPEN, path, NULL, create_attrs, oflags & ~(uint32_t)SD_SFTP_O_STRIPED, o, cb, ctx);
  /* copy-data affinity: the new handle lives on the channel of same_channel_as */
  if (!s || !cb || same_channel_as->s != s) return SD_E_INVALID_PARAM;
  if (same_channel_as->stale) return SD_E_STALE_HANDLE;
  if ((e = check_path(path)) != SD_OK) return e;
  r = req_alloc(s, OP_OPEN, o, cb, ctx);
  if (!r) return SD_E_NO_MEMORY;
  r->flags &= ~(uint32_t)SD_SFTP_REQ_CLASS_META;     /* the class follows same_channel_as */
  r->p1 = dup_str(path);
  if (!r->p1) { req_free(r); return SD_E_NO_MEMORY; }
  if (create_attrs) { r->a = *create_attrs; r->a.ext = NULL; r->a.ext_count = 0; r->has_attrs = 1; }
  r->u1 = oflags & ~(uint32_t)SD_SFTP_O_STRIPED;
  sd_sftp_file_addref(same_channel_as);
  r->f2 = same_channel_as;
  return req_submit(s, r, o);
}

sd_err sd_sftp_opendir(sd_sftp_session *s, const char *path, const sd_sftp_reqopt *o, sd_sftp_cb cb, void *ctx)
{
  return submit_path(s, OP_OPENDIR, path, NULL, NULL, 0, o, cb, ctx);
}

sd_err sd_sftp_close(sd_sftp_file *f, const sd_sftp_reqopt *o, sd_sftp_cb cb, void *ctx)
{
  sftp_req *r;
  sd_err e;
  if (!f) return SD_E_INVALID_PARAM;
  if (InterlockedCompareExchange(&f->closing, 1, 0) != 0) {
    sd_sftp_file_release(f);
    return SD_E_INVALID_PARAM;
  }
  e = submit_file(f, OP_CLOSE, o, cb, ctx, &r);
  if (e == SD_OK) e = req_submit(f->s, r, o);
  sd_sftp_file_release(f);   /* the caller's reference, in every case */
  return e;
}

sd_err sd_sftp_read(sd_sftp_file *f, uint64_t off, void *buf, uint32_t len,
                    const sd_sftp_reqopt *o, sd_sftp_cb cb, void *ctx)
{
  sftp_req *r;
  sd_err e;
  if (!f || !buf || len == 0) return SD_E_INVALID_PARAM;
  if (f->is_dir) return SD_E_IS_A_DIRECTORY;
  if ((e = submit_file(f, OP_READ, o, cb, ctx, &r)) != SD_OK) return e;
  r->off = off; r->buf = (uint8_t *)buf; r->len = len;
  return req_submit(f->s, r, o);
}

sd_err sd_sftp_write(sd_sftp_file *f, uint64_t off, const void *buf, uint32_t len,
                     const sd_sftp_reqopt *o, sd_sftp_cb cb, void *ctx)
{
  sftp_req *r;
  sd_err e;
  if (!f || !buf || len == 0) return SD_E_INVALID_PARAM;
  if (f->is_dir) return SD_E_IS_A_DIRECTORY;
  if ((e = submit_file(f, OP_WRITE, o, cb, ctx, &r)) != SD_OK) return e;
  r->off = off; r->buf = (uint8_t *)(uintptr_t)buf; r->len = len;
  return req_submit(f->s, r, o);
}

static sd_err simple_file_op(sd_sftp_file *f, uint32_t op, const sd_sftp_attrs *a, const sd_sftp_reqopt *o,
                             sd_sftp_cb cb, void *ctx)
{
  sftp_req *r;
  sd_err e;
  if (!f) return SD_E_INVALID_PARAM;
  if ((e = submit_file(f, op, o, cb, ctx, &r)) != SD_OK) return e;
  if (a) { r->a = *a; r->a.ext = NULL; r->a.ext_count = 0; r->has_attrs = 1; }
  return req_submit(f->s, r, o);
}

sd_err sd_sftp_readdir(sd_sftp_file *dir, const sd_sftp_reqopt *o, sd_sftp_cb cb, void *ctx)
{
  if (dir && !dir->is_dir) return SD_E_NOT_A_DIRECTORY;
  return simple_file_op(dir, OP_READDIR, NULL, o, cb, ctx);
}
sd_err sd_sftp_fstat(sd_sftp_file *f, const sd_sftp_reqopt *o, sd_sftp_cb cb, void *ctx)
{ return simple_file_op(f, OP_FSTAT, NULL, o, cb, ctx); }
sd_err sd_sftp_fsetstat(sd_sftp_file *f, const sd_sftp_attrs *a, const sd_sftp_reqopt *o, sd_sftp_cb cb, void *ctx)
{ if (!a) return SD_E_INVALID_PARAM; return simple_file_op(f, OP_FSETSTAT, a, o, cb, ctx); }
sd_err sd_sftp_fsync(sd_sftp_file *f, const sd_sftp_reqopt *o, sd_sftp_cb cb, void *ctx)
{ return simple_file_op(f, OP_FSYNC, NULL, o, cb, ctx); }
sd_err sd_sftp_fstatvfs(sd_sftp_file *f, const sd_sftp_reqopt *o, sd_sftp_cb cb, void *ctx)
{ return simple_file_op(f, OP_FSTATVFS, NULL, o, cb, ctx); }

sd_err sd_sftp_copy_data(sd_sftp_file *src, uint64_t src_off, uint64_t len, sd_sftp_file *dst, uint64_t dst_off,
                         const sd_sftp_reqopt *o, sd_sftp_cb cb, void *ctx)
{
  sftp_req *r;
  sd_err e;
  if (!src || !dst || dst->s != src->s) return SD_E_INVALID_PARAM;
  if (dst->stale) return SD_E_STALE_HANDLE;
  if ((e = submit_file(src, OP_COPY, o, cb, ctx, &r)) != SD_OK) return e;
  sd_sftp_file_addref(dst);
  r->f2 = dst;
  r->off = src_off; r->len64 = len; r->off2 = dst_off;
  return req_submit(src->s, r, o);
}

sd_err sd_sftp_file_reopen(sd_sftp_file *f, const sd_sftp_reqopt *o, sd_sftp_cb cb, void *ctx)
{
  sftp_req *r;
  sd_err e;
  if (!f || !cb) return SD_E_INVALID_PARAM;
  if (!f->stale) return SD_E_INVALID_PARAM;
  if (f->closing) return SD_E_INVALID_PARAM;
  r = req_alloc(f->s, OP_REOPEN, o, cb, ctx);
  if (!r) return SD_E_NO_MEMORY;
  sd_sftp_file_addref(f);
  r->f = f;
  e = req_submit(f->s, r, o);
  return e;
}

sd_err sd_sftp_stat(sd_sftp_session *s, const char *path, const sd_sftp_reqopt *o, sd_sftp_cb cb, void *ctx)
{ return submit_path(s, OP_STAT, path, NULL, NULL, 0, o, cb, ctx); }
sd_err sd_sftp_lstat(sd_sftp_session *s, const char *path, const sd_sftp_reqopt *o, sd_sftp_cb cb, void *ctx)
{ return submit_path(s, OP_LSTAT, path, NULL, NULL, 0, o, cb, ctx); }
sd_err sd_sftp_setstat(sd_sftp_session *s, const char *path, const sd_sftp_attrs *a, int no_follow,
                       const sd_sftp_reqopt *o, sd_sftp_cb cb, void *ctx)
{ if (!a) return SD_E_INVALID_PARAM; return submit_path(s, OP_SETSTAT, path, NULL, a, no_follow ? 1u : 0u, o, cb, ctx); }
sd_err sd_sftp_mkdir(sd_sftp_session *s, const char *path, const sd_sftp_attrs *a,
                     const sd_sftp_reqopt *o, sd_sftp_cb cb, void *ctx)
{ return submit_path(s, OP_MKDIR, path, NULL, a, 0, o, cb, ctx); }
sd_err sd_sftp_rmdir(sd_sftp_session *s, const char *path, const sd_sftp_reqopt *o, sd_sftp_cb cb, void *ctx)
{ return submit_path(s, OP_RMDIR, path, NULL, NULL, 0, o, cb, ctx); }
sd_err sd_sftp_remove(sd_sftp_session *s, const char *path, const sd_sftp_reqopt *o, sd_sftp_cb cb, void *ctx)
{ return submit_path(s, OP_REMOVE, path, NULL, NULL, 0, o, cb, ctx); }
sd_err sd_sftp_rename(sd_sftp_session *s, const char *from, const char *to, uint32_t flags,
                      const sd_sftp_reqopt *o, sd_sftp_cb cb, void *ctx)
{ if (!to) return SD_E_INVALID_PARAM; return submit_path(s, OP_RENAME, from, to, NULL, flags, o, cb, ctx); }
sd_err sd_sftp_readlink(sd_sftp_session *s, const char *path, const sd_sftp_reqopt *o, sd_sftp_cb cb, void *ctx)
{ return submit_path(s, OP_READLINK, path, NULL, NULL, 0, o, cb, ctx); }
sd_err sd_sftp_symlink(sd_sftp_session *s, const char *link_path, const char *target,
                       const sd_sftp_reqopt *o, sd_sftp_cb cb, void *ctx)
{ if (!target) return SD_E_INVALID_PARAM; return submit_path(s, OP_SYMLINK, link_path, target, NULL, 0, o, cb, ctx); }
sd_err sd_sftp_hardlink(sd_sftp_session *s, const char *existing, const char *new_link,
                        const sd_sftp_reqopt *o, sd_sftp_cb cb, void *ctx)
{ if (!new_link) return SD_E_INVALID_PARAM; return submit_path(s, OP_HARDLINK, existing, new_link, NULL, 0, o, cb, ctx); }
sd_err sd_sftp_realpath(sd_sftp_session *s, const char *path, const sd_sftp_reqopt *o, sd_sftp_cb cb, void *ctx)
{ return submit_path(s, OP_REALPATH, path, NULL, NULL, 0, o, cb, ctx); }
sd_err sd_sftp_expand_path(sd_sftp_session *s, const char *path, const sd_sftp_reqopt *o, sd_sftp_cb cb, void *ctx)
{ return submit_path(s, OP_EXPAND, path, NULL, NULL, 0, o, cb, ctx); }
sd_err sd_sftp_home_directory(sd_sftp_session *s, const char *user, const sd_sftp_reqopt *o, sd_sftp_cb cb, void *ctx)
{ return submit_path(s, OP_HOME, user ? user : "", NULL, NULL, 0, o, cb, ctx); }
sd_err sd_sftp_statvfs_path(sd_sftp_session *s, const char *path, const sd_sftp_reqopt *o, sd_sftp_cb cb, void *ctx)
{ return submit_path(s, OP_STATVFS, path, NULL, NULL, 0, o, cb, ctx); }

sd_err sd_sftp_names_by_id(sd_sftp_session *s, const uint32_t *uids, uint32_t nu, const uint32_t *gids, uint32_t ng,
                           const sd_sftp_reqopt *o, sd_sftp_cb cb, void *ctx)
{
  sftp_req *r;
  if (!s || !cb || nu > 64 || ng > 64 || (nu && !uids) || (ng && !gids) || nu + ng == 0) return SD_E_INVALID_PARAM;
  r = req_alloc(s, OP_NAMES, o, cb, ctx);
  if (!r) return SD_E_NO_MEMORY;
  r->ids = (uint32_t *)sd_calloc(nu + ng, sizeof(uint32_t));
  if (!r->ids) { req_free(r); return SD_E_NO_MEMORY; }
  if (nu) memcpy(r->ids, uids, nu * sizeof(uint32_t));
  if (ng) memcpy(r->ids + nu, gids, ng * sizeof(uint32_t));
  r->nu = nu; r->ng = ng;
  return req_submit(s, r, o);
}

sd_err sd_sftp_cancel(sd_sftp_req *tok)
{
  uint64_t id = (uint64_t)(uintptr_t)tok;
  sftp_req *r;
  sftp_item *it;
  sd_sftp_session *s;
  int ok;
  if (!id) return SD_E_INVALID_PARAM;
  sd_once_run(&g_tok_once, tok_init, NULL);
  it = (sftp_item *)sd_calloc(1, sizeof(*it));
  if (!it) return SD_E_NO_MEMORY;
  it->type = IT_CANCEL;
  it->id = id;
  sd_mutex_lock(&g_tok_lock);
  r = tok_find_locked(id);
  s = r ? r->s : NULL;
  ok = s ? inbox_put(s, it) : 0;
  sd_mutex_unlock(&g_tok_lock);
  if (!ok) { sd_free(it); return SD_E_INVALID_PARAM; }
  return SD_OK;
}
