/* Test transports for sd_sftp (fixtures only). */
#include <stdio.h>
#include <string.h>
#include <wchar.h>

#include "sd_base/sd_mem.h"
#include "sd_platform/sd_thread.h"
#include "sftp_internal.h"      /* sftp_session_pool_change(): the fake plays the SSH pool's part */
#include "sftp_test_tp.h"

/* ---- I/O loop ---- */

typedef struct tl_item { struct tl_item *next; void (*fn)(void *); void *arg; } tl_item;
struct tl_loop {
  sd_mutex lock;
  sd_event ev;
  tl_item *head, *tail;
  int stop;
  sd_thread th;
  volatile LONG tid;
};

static unsigned __stdcall tl_main(void *arg)
{
  tl_loop *l = (tl_loop *)arg;
  InterlockedExchange(&l->tid, (LONG)GetCurrentThreadId());
  for (;;) {
    tl_item *it;
    sd_mutex_lock(&l->lock);
    it = l->head;
    if (it) { l->head = it->next; if (!l->head) l->tail = NULL; }
    if (!it && l->stop) { sd_mutex_unlock(&l->lock); break; }
    sd_mutex_unlock(&l->lock);
    if (!it) { (void)sd_event_wait(&l->ev, 100); continue; }
    it->fn(it->arg);
    sd_free(it);
  }
  return 0;
}

tl_loop *tl_loop_new(void)
{
  tl_loop *l = (tl_loop *)sd_calloc(1, sizeof(*l));
  if (!l) return NULL;
  sd_mutex_init(&l->lock);
  if (sd_event_init(&l->ev, 0, 0) != SD_OK) { sd_mutex_destroy(&l->lock); sd_free(l); return NULL; }
  if (sd_thread_create(&l->th, tl_main, l, 0, L"test io") != SD_OK) {
    sd_event_destroy(&l->ev); sd_mutex_destroy(&l->lock); sd_free(l); return NULL;
  }
  while (l->tid == 0) Sleep(1);
  return l;
}

void tl_loop_free(tl_loop *l)
{
  tl_item *it;
  if (!l) return;
  sd_mutex_lock(&l->lock);
  l->stop = 1;
  it = l->head;               /* drop unrun items */
  l->head = l->tail = NULL;
  sd_mutex_unlock(&l->lock);
  while (it) { tl_item *n = it->next; sd_free(it); it = n; }
  sd_event_set(&l->ev);
  (void)sd_thread_join(&l->th, SD_WAIT_INFINITE, NULL);
  sd_event_destroy(&l->ev);
  sd_mutex_destroy(&l->lock);
  sd_free(l);
}

sd_err tl_post(tl_loop *l, void (*fn)(void *), void *arg)
{
  tl_item *it = (tl_item *)sd_alloc(sizeof(*it));
  if (!it) return SD_E_NO_MEMORY;
  it->next = NULL; it->fn = fn; it->arg = arg;
  sd_mutex_lock(&l->lock);
  if (l->stop) { sd_mutex_unlock(&l->lock); sd_free(it); return SD_E_SHUTDOWN; }
  if (l->tail) l->tail->next = it; else l->head = it;
  l->tail = it;
  sd_mutex_unlock(&l->lock);
  sd_event_set(&l->ev);
  return SD_OK;
}

int tl_is_io(tl_loop *l) { return l && (DWORD)l->tid == GetCurrentThreadId(); }

/* ---- fake server ----
 * Up to five streams per fake "connection": 0 (meta, the open() stream), 1 (primary bulk) and, in
 * pool mode, 2..4 = pool members 1..3 (SD_SFTP_TP_POOL, 01 §10.9). With SD_SFTP_TP_REOPEN every
 * open() starts a new connection generation. Chunks queued for an older generation or a stream that
 * is no longer open are dropped, like bytes of a dead TCP connection. */

#define FK_STREAMS 5
#define FK_MEMBERS 3

typedef struct fake_stream {
  const sd_ssh_channel_sink *sink; void *sink_ctx;
  int state;                   /* 0 none, 1 opening, 2 open (I/O thread) */
  sd_wr in;                    /* client -> server reassembly */
} fake_stream;

struct fake_srv {
  tl_loop *loop;
  fake_handler h; void *hctx;
  fake_stream st[FK_STREAMS];
  volatile LONG gen;           /* connection generation, incremented by open() */
  volatile LONG closed;        /* current connection hung up / closed */
  volatile LONG packets;
  volatile LONG opens;
  volatile LONG cur;           /* stream of the packet being handled */
  volatile LONG fail_opens;    /* upcoming open() calls that fail */
  sd_err fail_err;
  sd_err refuse_bulk;          /* != SD_OK: open_stream(1) fails with it */
  uint32_t caps;
  int open_called;
  /* M2 pool */
  int pool;                    /* streams 2..4 are members 1..3 */
  uint32_t pool_target;        /* connections incl. the primary; members 1..target-1 admit */
  void *session;               /* set by fake_set_session(): notify_ready admits members on it */
  volatile LONG admitted;      /* bit member-1: the member was admitted */
  volatile LONG pkts[FK_STREAMS];
  volatile LONG tx[FK_MEMBERS], rx[FK_MEMBERS];
};

typedef struct fake_chunk { fake_srv *f; size_t n; int kind; uint32_t idx; LONG gen; sd_err err; uint8_t data[1]; } fake_chunk;
enum { FK_DATA, FK_OPEN, FK_CLOSED };

static void fake_deliver(void *arg)
{
  fake_chunk *c = (fake_chunk *)arg;
  fake_srv *f = c->f;
  fake_stream *st = &f->st[c->idx];
  if (c->gen != f->gen) { sd_free(c); return; }
  if (c->kind == FK_OPEN) {
    if (st->state == 1) {
      sd_err e = c->err != SD_OK ? c->err : (f->closed ? SD_E_SHUTDOWN : SD_OK);
      st->state = e == SD_OK ? 2 : 0;
      st->sink->on_open(st->sink_ctx, e);
    }
  } else if (c->kind == FK_CLOSED) {
    if (st->state == 2) { st->state = 0; st->sink->on_closed(st->sink_ctx, c->err); }
    else if (st->state == 1) { st->state = 0; st->sink->on_open(st->sink_ctx, c->err); }
  } else if (st->state == 2 && !f->closed) {
    st->sink->on_data(st->sink_ctx, c->data, c->n);
  }
  sd_free(c);
}

static void fake_post_kind(fake_srv *f, int kind, uint32_t idx, sd_err err, const void *p, size_t n)
{
  fake_chunk *c = (fake_chunk *)sd_alloc(sizeof(*c) + n);
  if (!c) return;
  c->f = f; c->n = n; c->kind = kind; c->idx = idx; c->err = err; c->gen = f->gen;
  if (n) memcpy(c->data, p, n);
  if (tl_post(f->loop, fake_deliver, c) != SD_OK) sd_free(c);
}

static sd_err ft_post(void *ctx, void (*fn)(void *), void *arg) { return tl_post(((fake_srv *)ctx)->loop, fn, arg); }
static int ft_is_io(void *ctx) { return tl_is_io(((fake_srv *)ctx)->loop); }

static sd_err ft_open(void *ctx, const sd_ssh_channel_sink *sink, void *sink_ctx)
{
  fake_srv *f = (fake_srv *)ctx;
  uint32_t i;
  InterlockedIncrement(&f->gen);
  InterlockedExchange(&f->closed, 0);
  InterlockedIncrement(&f->opens);
  for (i = 0; i < FK_STREAMS; i++) { f->st[i].state = 0; f->st[i].in.len = 0; }
  f->st[0].sink = sink; f->st[0].sink_ctx = sink_ctx; f->st[0].state = 1;
  f->open_called = 1;
  if (f->fail_opens > 0) {
    InterlockedDecrement(&f->fail_opens);
    fake_post_kind(f, FK_OPEN, 0, f->fail_err != SD_OK ? f->fail_err : SD_E_CONN_REFUSED, NULL, 0);
  } else {
    fake_post_kind(f, FK_OPEN, 0, SD_OK, NULL, 0);
  }
  return SD_OK;
}

static sd_err ft_open_stream(void *ctx, uint32_t idx, const sd_ssh_channel_sink *sink, void *sink_ctx)
{
  fake_srv *f = (fake_srv *)ctx;
  if (idx < 1 || idx >= FK_STREAMS) return SD_E_INVALID_PARAM;
  if (idx > 1 && !f->pool) return SD_E_INVALID_PARAM;      /* only members 1..3 need a pool */
  f->st[idx].sink = sink; f->st[idx].sink_ctx = sink_ctx; f->st[idx].state = 1; f->st[idx].in.len = 0;
  fake_post_kind(f, FK_OPEN, idx, idx == 1 ? f->refuse_bulk : SD_OK, NULL, 0);
  return SD_OK;
}

static sd_err ft_write_stream(void *ctx, uint32_t idx, const uint8_t *p, size_t n, size_t *accepted)
{
  fake_srv *f = (fake_srv *)ctx;
  fake_stream *st = &f->st[idx];
  size_t off = 0;
  *accepted = n;
  if (idx >= 2 && idx < FK_STREAMS) InterlockedExchangeAdd(&f->tx[idx - 2], (LONG)n);
  if (f->closed || st->state != 2) return SD_OK;
  sd_wr_bytes(&st->in, p, n);
  while (st->in.len - off >= 4) {
    uint32_t len = sd_load_be32(st->in.p + off);
    LONG g = f->gen;
    if (st->in.len - off - 4 < len) break;
    InterlockedIncrement(&f->packets);
    InterlockedIncrement(&f->pkts[idx]);
    InterlockedExchange(&f->cur, (LONG)idx);
    f->h(f, f->hctx, st->in.p + off + 4, len);
    if (g != f->gen || f->closed) { st->in.len = 0; return SD_OK; }   /* handler hung up */
    off += 4 + (size_t)len;
  }
  if (off) { memmove(st->in.p, st->in.p + off, st->in.len - off); st->in.len -= off; }
  return SD_OK;
}
static sd_err ft_write(void *ctx, const uint8_t *p, size_t n, size_t *accepted)
{ return ft_write_stream(ctx, 0, p, n, accepted); }
static void ft_consumed(void *ctx, size_t n) { SD_UNUSED(ctx); SD_UNUSED(n); }
static void ft_consumed_stream(void *ctx, uint32_t idx, size_t n)
{
  fake_srv *f = (fake_srv *)ctx;
  if (idx >= 2 && idx < FK_STREAMS) InterlockedExchangeAdd(&f->rx[idx - 2], (LONG)n);
}

static void fake_close_all(fake_srv *f, sd_err why)
{
  uint32_t i;
  InterlockedExchange(&f->closed, 1);
  for (i = 0; i < FK_STREAMS; i++) fake_post_kind(f, FK_CLOSED, i, why, NULL, 0);
}

static void ft_close(void *ctx) { fake_close_all((fake_srv *)ctx, SD_E_SHUTDOWN); }

/* The SSH pool's notify_ready() admits members once the primary is READY; the fake calls
   sftp_session_pool_change() with the session fake_set_session() handed over. */
static void ft_notify_ready(void *ctx, const char *realpath_dot)
{
  fake_srv *f = (fake_srv *)ctx;
  uint32_t m;
  SD_UNUSED(realpath_dot);
  if (!f->pool || !f->session) return;
  for (m = 1; m < f->pool_target && m <= FK_MEMBERS; m++) {
    InterlockedOr(&f->admitted, 1L << (m - 1));
    sftp_session_pool_change((sd_sftp_session *)f->session, m, 1, SD_OK);
  }
}

/* Per-member statistics, members 1..3 in out[member-1] (01 §10.9); *count = admitted members. */
static void ft_member_stats(void *ctx, sd_sftp_conn_stats out[3], uint32_t *count)
{
  fake_srv *f = (fake_srv *)ctx;
  uint32_t m, n = 0;
  if (!out) { if (count) *count = 0; return; }
  for (m = 1; m <= FK_MEMBERS; m++) {
    if (!(f->admitted & (1L << (m - 1)))) continue;
    memset(&out[m - 1], 0, sizeof(out[m - 1]));
    out[m - 1].ready = f->st[m].state == 2;
    out[m - 1].rx_total = (uint64_t)(ULONG)f->rx[m - 1];
    out[m - 1].tx_total = (uint64_t)(ULONG)f->tx[m - 1];
    n++;
  }
  if (count) *count = n;
}

static void ft_destroy(void *ctx)
{
  fake_srv *f = (fake_srv *)ctx;
  uint32_t i;
  tl_loop_free(f->loop);
  for (i = 0; i < FK_STREAMS; i++) sd_wr_free(&f->st[i].in);
  sd_free(f);
}

fake_srv *fake_new(fake_handler h, void *ctx)
{
  fake_srv *f = (fake_srv *)sd_calloc(1, sizeof(*f));
  uint32_t i;
  if (!f) return NULL;
  f->loop = tl_loop_new();
  if (!f->loop) { sd_free(f); return NULL; }
  f->h = h; f->hctx = ctx;
  for (i = 0; i < FK_STREAMS; i++) sd_wr_init(&f->st[i].in, 64u * 1024u * 1024u);
  return f;
}

void fake_transport(fake_srv *f, sd_sftp_transport *t)
{
  memset(t, 0, sizeof(*t));
  t->ctx = f;
  t->post = ft_post; t->is_io_thread = ft_is_io; t->open = ft_open; t->write = ft_write;
  t->consumed = ft_consumed; t->close = ft_close; t->destroy = ft_destroy;
  t->caps = f->caps;
  if (f->caps & SD_SFTP_TP_STREAMS) {
    t->open_stream = ft_open_stream; t->write_stream = ft_write_stream; t->consumed_stream = ft_consumed_stream;
  }
  if (f->pool) {
    /* a pool transport projects the member connections onto the stream vtable (01 §10.9) */
    t->caps |= SD_SFTP_TP_STREAMS | SD_SFTP_TP_POOL;
    t->open_stream = ft_open_stream; t->write_stream = ft_write_stream; t->consumed_stream = ft_consumed_stream;
    t->notify_ready = ft_notify_ready;
    t->member_stats = ft_member_stats;
  }
}

void fake_set_caps(fake_srv *f, uint32_t caps) { f->caps = caps; }
void fake_set_pool(fake_srv *f, uint32_t connections)
{
  f->pool = 1;
  f->pool_target = connections < 1 ? 1 : (connections > 1 + FK_MEMBERS ? 1 + FK_MEMBERS : connections);
}
void fake_set_session(fake_srv *f, sd_sftp_session *s) { f->session = s; }
void fake_drop_member(fake_srv *f, uint32_t member)
{
  if (member < 1 || member > FK_MEMBERS) return;
  fake_post_kind(f, FK_CLOSED, 1 + member, SD_E_DISCONNECTED, NULL, 0);   /* this channel only */
}
uint32_t fake_stream_packets(fake_srv *f, uint32_t idx) { return idx < FK_STREAMS ? (uint32_t)f->pkts[idx] : 0; }
void fake_refuse_bulk(fake_srv *f, sd_err e) { f->refuse_bulk = e; }
void fake_fail_opens(fake_srv *f, LONG n, sd_err e) { f->fail_err = e; InterlockedExchange(&f->fail_opens, n); }
uint32_t fake_opens(fake_srv *f) { return (uint32_t)f->opens; }
uint32_t fake_gen(fake_srv *f) { return (uint32_t)f->gen; }
uint32_t fake_cur_stream(fake_srv *f) { return (uint32_t)f->cur; }
int fake_stream_open(fake_srv *f, uint32_t idx) { return idx < FK_STREAMS && f->st[idx].state == 2; }

void fake_free_if_unused(fake_srv *f) { if (f) ft_destroy(f); }

void fake_run(fake_srv *f, void (*fn)(void *), void *arg) { (void)tl_post(f->loop, fn, arg); }

void fake_reply_on(fake_srv *f, uint32_t idx, const void *bytes, size_t n)
{
  fake_post_kind(f, FK_DATA, idx < FK_STREAMS ? idx : 0, SD_OK, bytes, n);
}

void fake_reply(fake_srv *f, const void *bytes, size_t n) { fake_reply_on(f, (uint32_t)f->cur, bytes, n); }

void fake_reply_wr(fake_srv *f, sd_wr *w)
{
  sd_wr_patch_u32(w, 0, (uint32_t)(w->len - 4));
  fake_reply(f, w->p, w->len);
  sd_wr_free(w);
}

void fake_hangup(fake_srv *f)
{
  if (InterlockedExchange(&f->closed, 1) == 0) fake_close_all(f, SD_E_DISCONNECTED);
}

uint32_t fake_packets(fake_srv *f) { return (uint32_t)f->packets; }

void pk_begin(sd_wr *w, uint8_t type, uint32_t id)
{
  sd_wr_init(w, 16u * 1024u * 1024u);
  sd_wr_u32(w, 0);
  sd_wr_u8(w, type);
  sd_wr_u32(w, id);
}

void pk_status(fake_srv *f, uint32_t id, uint32_t code, const char *msg)
{
  sd_wr w;
  pk_begin(&w, 101, id);
  sd_wr_u32(&w, code);
  sd_wr_cstring(&w, msg ? msg : "");
  sd_wr_cstring(&w, "");
  fake_reply_wr(f, &w);
}

void pk_handle(fake_srv *f, uint32_t id, const char *h)
{
  sd_wr w;
  pk_begin(&w, 102, id);
  sd_wr_cstring(&w, h);
  fake_reply_wr(f, &w);
}

void pk_attrs_body(sd_wr *w, uint32_t perm, uint64_t size)
{
  sd_wr_u32(w, 0xF);
  sd_wr_u64(w, size);
  sd_wr_u32(w, 1000); sd_wr_u32(w, 1000);
  sd_wr_u32(w, perm);
  sd_wr_u32(w, 1700000000u); sd_wr_u32(w, 1700000001u);
}

/* ---- process transport ---- */

#define PROC_OUT_CAP  (4u * 1024u * 1024u)
#define PROC_IN_CREDIT (4u * 1024u * 1024u)

struct proc_tp {
  tl_loop *loop;
  const sd_ssh_channel_sink *sink; void *sink_ctx;
  wchar_t *cmd;
  PROCESS_INFORMATION pi;
  HANDLE in_w, out_r, err_r;
  sd_thread reader, writer, errt;
  int threads;
  /* outgoing ring (writer thread) */
  sd_mutex olock; sd_event ohave; uint8_t *obuf; size_t ohead, olen; int want_writable; volatile LONG ostop;
  /* inbound credit */
  volatile LONG unconsumed; sd_event credit;
  volatile LONG paused; sd_event unpaused;
  volatile LONG closed_delivered, close_called;
};

typedef struct proc_chunk { proc_tp *p; size_t n; int kind; uint8_t data[1]; } proc_chunk;
enum { PK_DATA, PK_OPEN, PK_CLOSED, PK_WRITABLE };

static void proc_deliver(void *arg)
{
  proc_chunk *c = (proc_chunk *)arg;
  proc_tp *p = c->p;
  switch (c->kind) {
  case PK_OPEN: p->sink->on_open(p->sink_ctx, c->n ? SD_E_CONN_REFUSED : SD_OK); break;
  case PK_DATA: if (!p->closed_delivered) p->sink->on_data(p->sink_ctx, c->data, c->n); else InterlockedExchangeAdd(&p->unconsumed, -(LONG)c->n); break;
  case PK_WRITABLE: if (!p->closed_delivered) p->sink->on_writable(p->sink_ctx); break;
  case PK_CLOSED:
    if (InterlockedExchange(&p->closed_delivered, 1) == 0) p->sink->on_closed(p->sink_ctx, SD_E_DISCONNECTED);
    break;
  default: break;
  }
  sd_free(c);
}

static void proc_post(proc_tp *p, int kind, const void *data, size_t n)
{
  proc_chunk *c = (proc_chunk *)sd_alloc(sizeof(*c) + (kind == PK_DATA ? n : 0));
  if (!c) return;
  c->p = p; c->n = n; c->kind = kind;
  if (kind == PK_DATA && n) memcpy(c->data, data, n);
  if (tl_post(p->loop, proc_deliver, c) != SD_OK) sd_free(c);
}

static unsigned __stdcall proc_reader(void *arg)
{
  proc_tp *p = (proc_tp *)arg;
  uint8_t *buf = (uint8_t *)sd_alloc(256 * 1024);
  if (!buf) return 1;
  for (;;) {
    DWORD got = 0;
    while (p->unconsumed > (LONG)PROC_IN_CREDIT) (void)sd_event_wait(&p->credit, 50);
    if (!ReadFile(p->out_r, buf, 256 * 1024, &got, NULL) || got == 0) break;
    while (p->paused) (void)sd_event_wait(&p->unpaused, 50);
    InterlockedExchangeAdd(&p->unconsumed, (LONG)got);
    proc_post(p, PK_DATA, buf, got);
  }
  sd_free(buf);
  proc_post(p, PK_CLOSED, NULL, 0);
  return 0;
}

static unsigned __stdcall proc_err_reader(void *arg)
{
  proc_tp *p = (proc_tp *)arg;
  char buf[1024];
  DWORD got;
  while (ReadFile(p->err_r, buf, sizeof(buf) - 1, &got, NULL) && got) {
    buf[got] = 0;
    fprintf(stderr, "[sftp-server] %s", buf);
  }
  return 0;
}

static unsigned __stdcall proc_writer(void *arg)
{
  proc_tp *p = (proc_tp *)arg;
  for (;;) {
    size_t n, head;
    DWORD put = 0;
    int notify;
    sd_mutex_lock(&p->olock);
    n = p->olen; head = p->ohead;
    sd_mutex_unlock(&p->olock);
    if (n == 0) {
      if (p->ostop) break;
      (void)sd_event_wait(&p->ohave, 100);
      continue;
    }
    if (n > PROC_OUT_CAP - head) n = PROC_OUT_CAP - head;
    if (n > 1024 * 1024) n = 1024 * 1024;
    if (!WriteFile(p->in_w, p->obuf + head, (DWORD)n, &put, NULL)) break;
    sd_mutex_lock(&p->olock);
    p->ohead = (p->ohead + put) % PROC_OUT_CAP;
    p->olen -= put;
    notify = p->want_writable && p->olen < PROC_OUT_CAP / 2;
    if (notify) p->want_writable = 0;
    sd_mutex_unlock(&p->olock);
    if (notify) proc_post(p, PK_WRITABLE, NULL, 0);
  }
  CloseHandle(p->in_w);
  p->in_w = NULL;
  return 0;
}

static sd_err pt_post(void *ctx, void (*fn)(void *), void *arg) { return tl_post(((proc_tp *)ctx)->loop, fn, arg); }
static int pt_is_io(void *ctx) { return tl_is_io(((proc_tp *)ctx)->loop); }

static sd_err pt_open(void *ctx, const sd_ssh_channel_sink *sink, void *sink_ctx)
{
  proc_tp *p = (proc_tp *)ctx;
  SECURITY_ATTRIBUTES sa;
  STARTUPINFOW si;
  HANDLE in_r = NULL, out_w = NULL, err_w = NULL;
  p->sink = sink; p->sink_ctx = sink_ctx;
  memset(&sa, 0, sizeof(sa));
  sa.nLength = sizeof(sa);
  sa.bInheritHandle = TRUE;
  if (!CreatePipe(&in_r, &p->in_w, &sa, 1024 * 1024) || !CreatePipe(&p->out_r, &out_w, &sa, 1024 * 1024) ||
      !CreatePipe(&p->err_r, &err_w, &sa, 0)) {
    proc_post(p, PK_OPEN, NULL, 1);
    return SD_OK;
  }
  SetHandleInformation(p->in_w, HANDLE_FLAG_INHERIT, 0);
  SetHandleInformation(p->out_r, HANDLE_FLAG_INHERIT, 0);
  SetHandleInformation(p->err_r, HANDLE_FLAG_INHERIT, 0);
  memset(&si, 0, sizeof(si));
  si.cb = sizeof(si);
  si.dwFlags = STARTF_USESTDHANDLES;
  si.hStdInput = in_r; si.hStdOutput = out_w; si.hStdError = err_w;
#pragma warning(suppress: 6335)   /* handles are kept in p->pi and closed by pt_destroy */
  if (!CreateProcessW(NULL, p->cmd, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &p->pi)) {
    CloseHandle(in_r); CloseHandle(out_w); CloseHandle(err_w);
    proc_post(p, PK_OPEN, NULL, 1);
    return SD_OK;
  }
  CloseHandle(in_r); CloseHandle(out_w); CloseHandle(err_w);
  if (sd_thread_create(&p->reader, proc_reader, p, 0, L"proc reader") != SD_OK ||
      sd_thread_create(&p->writer, proc_writer, p, 0, L"proc writer") != SD_OK ||
      sd_thread_create(&p->errt, proc_err_reader, p, 0, L"proc stderr") != SD_OK)
    return SD_E_INTERNAL;
  p->threads = 1;
  proc_post(p, PK_OPEN, NULL, 0);
  return SD_OK;
}

static sd_err pt_write(void *ctx, const uint8_t *data, size_t n, size_t *accepted)
{
  proc_tp *p = (proc_tp *)ctx;
  size_t space, done = 0;
  sd_mutex_lock(&p->olock);
  space = PROC_OUT_CAP - p->olen;
  if (n > space) { n = space; p->want_writable = 1; }
  while (done < n) {
    size_t tail = (p->ohead + p->olen) % PROC_OUT_CAP;
    size_t run = PROC_OUT_CAP - tail;
    if (run > n - done) run = n - done;
    memcpy(p->obuf + tail, data + done, run);
    p->olen += run;
    done += run;
  }
  sd_mutex_unlock(&p->olock);
  sd_event_set(&p->ohave);
  *accepted = done;
  return SD_OK;
}

static void pt_consumed(void *ctx, size_t n)
{
  proc_tp *p = (proc_tp *)ctx;
  InterlockedExchangeAdd(&p->unconsumed, -(LONG)n);
  sd_event_set(&p->credit);
}

static void pt_close(void *ctx)
{
  proc_tp *p = (proc_tp *)ctx;
  if (InterlockedExchange(&p->close_called, 1)) return;
  InterlockedExchange(&p->ostop, 1);       /* writer flushes, then closes stdin: sftp-server exits */
  sd_event_set(&p->ohave);
  if (!p->threads) proc_post(p, PK_CLOSED, NULL, 0);
}

static void pt_destroy(void *ctx)
{
  proc_tp *p = (proc_tp *)ctx;
  InterlockedExchange(&p->ostop, 1);
  InterlockedExchange(&p->paused, 0);
  sd_event_set(&p->ohave);
  sd_event_set(&p->unpaused);
  if (p->pi.hProcess) {
    if (WaitForSingleObject(p->pi.hProcess, 3000) != WAIT_OBJECT_0) TerminateProcess(p->pi.hProcess, 1);
  }
  if (p->threads) {
    (void)sd_thread_join(&p->writer, SD_WAIT_INFINITE, NULL);
    (void)sd_thread_join(&p->reader, SD_WAIT_INFINITE, NULL);
    (void)sd_thread_join(&p->errt, SD_WAIT_INFINITE, NULL);
  }
  tl_loop_free(p->loop);
  if (p->pi.hProcess) { CloseHandle(p->pi.hProcess); CloseHandle(p->pi.hThread); }
  if (p->in_w) CloseHandle(p->in_w);
  if (p->out_r) CloseHandle(p->out_r);
  if (p->err_r) CloseHandle(p->err_r);
  sd_event_destroy(&p->ohave); sd_event_destroy(&p->credit); sd_event_destroy(&p->unpaused);
  sd_mutex_destroy(&p->olock);
  sd_free(p->obuf);
  sd_free(p->cmd);
  sd_free(p);
}

sd_err proc_new(const wchar_t *cmdline, sd_sftp_transport *t, proc_tp **handle)
{
  proc_tp *p = (proc_tp *)sd_calloc(1, sizeof(*p));
  size_t n = wcslen(cmdline);
  if (!p) return SD_E_NO_MEMORY;
  p->cmd = (wchar_t *)sd_calloc(n + 1, sizeof(wchar_t));
  p->obuf = (uint8_t *)sd_alloc(PROC_OUT_CAP);
  p->loop = tl_loop_new();
  if (!p->cmd || !p->obuf || !p->loop) { sd_free(p->cmd); sd_free(p->obuf); if (p->loop) tl_loop_free(p->loop); sd_free(p); return SD_E_NO_MEMORY; }
  memcpy(p->cmd, cmdline, n * sizeof(wchar_t));
  sd_mutex_init(&p->olock);
  (void)sd_event_init(&p->ohave, 0, 0);
  (void)sd_event_init(&p->credit, 0, 0);
  (void)sd_event_init(&p->unpaused, 0, 0);
  memset(t, 0, sizeof(*t));
  t->ctx = p;
  t->post = pt_post; t->is_io_thread = pt_is_io; t->open = pt_open; t->write = pt_write;
  t->consumed = pt_consumed; t->close = pt_close; t->destroy = pt_destroy;
  if (handle) *handle = p;
  return SD_OK;
}

void proc_pause(proc_tp *p, int paused)
{
  InterlockedExchange(&p->paused, paused ? 1 : 0);
  if (!paused) sd_event_set(&p->unpaused);
}

int run_cmd(const wchar_t *cmdline, uint32_t timeout_ms)
{
  STARTUPINFOW si;
  PROCESS_INFORMATION pi;
  DWORD code = (DWORD)-1;
  size_t n = wcslen(cmdline);
  wchar_t *cmd = (wchar_t *)sd_calloc(n + 1, sizeof(wchar_t));
  if (!cmd) return -1;
  memcpy(cmd, cmdline, n * sizeof(wchar_t));
  memset(&si, 0, sizeof(si));
  si.cb = sizeof(si);
  if (!CreateProcessW(NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) { sd_free(cmd); return -1; }
  if (WaitForSingleObject(pi.hProcess, timeout_ms) != WAIT_OBJECT_0) {
    TerminateProcess(pi.hProcess, 1);
    code = (DWORD)-1;
  } else if (!GetExitCodeProcess(pi.hProcess, &code)) {
    code = (DWORD)-1;
  }
  CloseHandle(pi.hProcess);
  CloseHandle(pi.hThread);
  sd_free(cmd);
  return (int)code;
}
