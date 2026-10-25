/* M1 resilience tests against a scripted in-memory server over the fake transport (no SSH, no
 * network): reconnect after drops while idle, during pipelined reads and writes, during OPEN and
 * READDIR; maybe_executed for mutating requests; WAIT_READY across an outage; sd_sftp_file_reopen;
 * meta/bulk channel classes and auto-degrade to one channel; backoff with jitter, permanent and
 * user-needed failures, max_attempts, reconnect_now / reconnect_stop; READY_INFO re-read; stats. */
#include <stdio.h>
#include <string.h>

#include "sd_base/sd_mem.h"
#include "sd_platform/sd_thread.h"
#include "sd_platform/sd_time.h"
#include "sd_test.h"
#include "sftp_proto.h"
#include "sftp_test_tp.h"
#include "test_util.h"

#define MS_FILE_MAX (8u * 1024u * 1024u)
#define MS_CHUNK    65536u

enum { HOLD_READ = 1u << 0, HOLD_WRITE = 1u << 1, HOLD_OPEN = 1u << 2, HOLD_READDIR = 1u << 3,
       HOLD_PATHOPS = 1u << 4, HOLD_STAT = 1u << 5 };

typedef struct msrv {
  fake_srv *f;
  sd_mutex lock;
  uint8_t *data; uint64_t size;           /* "/data" */
  volatile LONG hold;                     /* HOLD_* */
  volatile LONG held;                     /* requests swallowed while holding */
  volatile LONG on_stream[2][256];        /* request types seen per stream */
  volatile LONG readdir_calls;
  volatile LONG gone;                     /* "/data" removed (reopen of a vanished file) */
  int minimal_gen2;                       /* generation >= 2 announces no extensions */
  uint32_t dirpos[64];
} msrv;

/* ---- server ---- */

static void ms_version(msrv *m)
{
  static const char *const exts[][2] = {
    { "posix-rename@openssh.com", "1" }, { "statvfs@openssh.com", "2" }, { "fsync@openssh.com", "1" },
    { "limits@openssh.com", "1" },
  };
  sd_wr w;
  size_t i;
  sd_wr_init(&w, 4096);
  sd_wr_u32(&w, 0); sd_wr_u8(&w, SFTP_VERSION); sd_wr_u32(&w, 3);
  if (!(m->minimal_gen2 && fake_gen(m->f) >= 2))
    for (i = 0; i < SD_COUNTOF(exts); i++) { sd_wr_cstring(&w, exts[i][0]); sd_wr_cstring(&w, exts[i][1]); }
  fake_reply_wr(m->f, &w);
}

static void ms_attrs(msrv *m, uint32_t id, uint32_t perm, uint64_t size)
{
  sd_wr w;
  pk_begin(&w, SFTP_ATTRS, id);
  pk_attrs_body(&w, perm, size);
  fake_reply_wr(m->f, &w);
}

static void ms_name(msrv *m, uint32_t id, const char *name)
{
  sd_wr w;
  pk_begin(&w, SFTP_NAME, id);
  sd_wr_u32(&w, 1);
  sd_wr_cstring(&w, name); sd_wr_cstring(&w, "");
  sd_wr_u32(&w, 0);
  fake_reply_wr(m->f, &w);
}

static int span_is(sd_span s, const char *lit) { size_t n = strlen(lit); return s.n == n && memcmp(s.p, lit, n) == 0; }

/* handles: "F<gen>" for /data, "D<gen>:<slot>" for /dir */
static void ms_handle(msrv *m, uint32_t id, char kind, uint32_t slot)
{
  char h[32];
  _snprintf_s(h, sizeof(h), _TRUNCATE, "%c%u:%u", kind, fake_gen(m->f), slot);
  pk_handle(m->f, id, h);
}

static int handle_ok(msrv *m, sd_span h, char kind, uint32_t *slot)
{
  char want[16];
  int n = _snprintf_s(want, sizeof(want), _TRUNCATE, "%c%u:", kind, fake_gen(m->f));
  if (n <= 0 || h.n <= (size_t)n || memcmp(h.p, want, (size_t)n) != 0) return 0;
  if (slot) *slot = (uint32_t)(h.p[n] - '0');
  return 1;
}

static void ms_handler(fake_srv *f, void *ctx, const uint8_t *pkt, size_t n)
{
  msrv *m = (msrv *)ctx;
  uint8_t type = pkt[0];
  uint32_t id, stream = fake_cur_stream(f);
  LONG hold = m->hold;
  sd_rd rd;
  if (type == SFTP_INIT) { ms_version(m); return; }
  sd_rd_init(&rd, pkt + 1, n - 1);
  id = sd_rd_u32(&rd);
  InterlockedIncrement(&m->on_stream[stream & 1][type]);
  if (type == SFTP_EXTENDED) {
    sd_rd c = rd;
    sd_span nm = sd_rd_string(&c, 256);
    if (span_is(nm, "limits@openssh.com")) {
      sd_wr w;
      pk_begin(&w, SFTP_EXTENDED_REPLY, id);
      sd_wr_u64(&w, 262144); sd_wr_u64(&w, MS_CHUNK); sd_wr_u64(&w, MS_CHUNK); sd_wr_u64(&w, 1024);
      fake_reply_wr(f, &w);
      return;
    }
    if (hold & HOLD_PATHOPS) { InterlockedIncrement(&m->held); return; }
    if (span_is(nm, "posix-rename@openssh.com")) { pk_status(f, id, SFTP_FX_OK, ""); return; }
    pk_status(f, id, SFTP_FX_OP_UNSUPPORTED, "");
    return;
  }
  switch (type) {
  case SFTP_REALPATH: {
    sd_span p = sd_rd_string(&rd, 4096);
    if (span_is(p, ".")) { ms_name(m, id, "/home/u"); return; }
    if (hold & HOLD_PATHOPS) { InterlockedIncrement(&m->held); return; }
    ms_name(m, id, "/real");
    return;
  }
  case SFTP_STAT: case SFTP_LSTAT: {
    sd_span p = sd_rd_string(&rd, 4096);
    if (span_is(p, "/home/u")) { ms_attrs(m, id, 040755, 4096); return; }
    if ((hold & HOLD_STAT) || (hold & HOLD_PATHOPS)) { InterlockedIncrement(&m->held); return; }
    if (span_is(p, "/data") && !m->gone) { ms_attrs(m, id, 0100644, m->size); return; }
    if (span_is(p, "/dir")) { ms_attrs(m, id, 040755, 4096); return; }
    pk_status(f, id, SFTP_FX_NO_SUCH_FILE, "no such file");
    return;
  }
  case SFTP_OPEN: {
    sd_span p = sd_rd_string(&rd, 4096);
    if (hold & HOLD_OPEN) { InterlockedIncrement(&m->held); return; }
    if (span_is(p, "/data") && !m->gone) { ms_handle(m, id, 'F', 0); return; }
    pk_status(f, id, SFTP_FX_NO_SUCH_FILE, "no such file");
    return;
  }
  case SFTP_OPENDIR: {
    sd_span p = sd_rd_string(&rd, 4096);
    if (span_is(p, "/dir")) {
      uint32_t slot = (uint32_t)(InterlockedIncrement(&m->readdir_calls) % 8);   /* any free-ish slot */
      m->dirpos[slot] = 0;
      ms_handle(m, id, 'D', slot);
      return;
    }
    pk_status(f, id, SFTP_FX_NO_SUCH_FILE, "no such dir");
    return;
  }
  case SFTP_READDIR: {
    sd_span h = sd_rd_string(&rd, 256);
    uint32_t slot = 0;
    if (hold & HOLD_READDIR) { InterlockedIncrement(&m->held); return; }
    if (!handle_ok(m, h, 'D', &slot)) { pk_status(f, id, SFTP_FX_FAILURE, "bad handle"); return; }
    if (m->dirpos[slot]++ == 0) {
      sd_wr w;
      static const char *const names[] = { "a", "b", "c" };
      size_t i;
      pk_begin(&w, SFTP_NAME, id);
      sd_wr_u32(&w, 3);
      for (i = 0; i < 3; i++) { sd_wr_cstring(&w, names[i]); sd_wr_cstring(&w, ""); pk_attrs_body(&w, 0100644, 1); }
      fake_reply_wr(f, &w);
    } else {
      pk_status(f, id, SFTP_FX_EOF, "");
    }
    return;
  }
  case SFTP_CLOSE:
    pk_status(f, id, SFTP_FX_OK, "");
    return;
  case SFTP_FSTAT: {
    sd_span h = sd_rd_string(&rd, 256);
    if (handle_ok(m, h, 'F', NULL)) { ms_attrs(m, id, 0100644, m->size); return; }
    pk_status(f, id, SFTP_FX_FAILURE, "bad handle");
    return;
  }
  case SFTP_READ: {
    sd_span h = sd_rd_string(&rd, 256);
    uint64_t off = sd_rd_u64(&rd);
    uint32_t len = sd_rd_u32(&rd);
    sd_wr w;
    if (hold & HOLD_READ) { InterlockedIncrement(&m->held); return; }
    if (!handle_ok(m, h, 'F', NULL)) { pk_status(f, id, SFTP_FX_FAILURE, "bad handle"); return; }
    if (off >= m->size) { pk_status(f, id, SFTP_FX_EOF, ""); return; }
    if (len > m->size - off) len = (uint32_t)(m->size - off);
    pk_begin(&w, SFTP_DATA, id);
    sd_mutex_lock(&m->lock);
    sd_wr_string(&w, m->data + off, len);
    sd_mutex_unlock(&m->lock);
    fake_reply_wr(f, &w);
    return;
  }
  case SFTP_WRITE: {
    sd_span h = sd_rd_string(&rd, 256);
    uint64_t off = sd_rd_u64(&rd);
    sd_span d = sd_rd_string(&rd, 1024 * 1024);
    if (hold & HOLD_WRITE) { InterlockedIncrement(&m->held); return; }
    if (!handle_ok(m, h, 'F', NULL) || off + d.n > MS_FILE_MAX) { pk_status(f, id, SFTP_FX_FAILURE, "bad"); return; }
    sd_mutex_lock(&m->lock);
    memcpy(m->data + off, d.p, d.n);
    if (off + d.n > m->size) m->size = off + d.n;
    sd_mutex_unlock(&m->lock);
    pk_status(f, id, SFTP_FX_OK, "");
    return;
  }
  case SFTP_SETSTAT: case SFTP_FSETSTAT: case SFTP_REMOVE: case SFTP_MKDIR: case SFTP_RMDIR: case SFTP_RENAME:
    if (hold & HOLD_PATHOPS) { InterlockedIncrement(&m->held); return; }
    pk_status(f, id, SFTP_FX_OK, "");
    return;
  default:
    pk_status(f, id, SFTP_FX_OP_UNSUPPORTED, "unsupported in fake");
  }
}

/* ---- event capture ---- */

typedef struct rcev {
  sd_mutex lock;
  sd_event changed;
  sd_sftp_state st[128]; sd_err reason[128]; uint32_t retry[128], attempt[128], gen[128];
  int n;
  uint32_t ready_gen, ready_channels, ready_ext;
  uint64_t ready_max_read;
} rcev;

static void rcev_cb(void *ctx, const sd_sftp_event *ev)
{
  rcev *e = (rcev *)ctx;
  sd_mutex_lock(&e->lock);
  if (ev->type == SD_SFTP_EV_STATE && e->n < 128) {
    e->st[e->n] = ev->state; e->reason[e->n] = ev->reason; e->retry[e->n] = ev->retry_in_ms;
    e->attempt[e->n] = ev->attempt; e->gen[e->n] = ev->generation;
    e->n++;
  } else if (ev->type == SD_SFTP_EV_READY_INFO) {
    e->ready_gen = ev->info->generation;
    e->ready_channels = ev->info->channels;
    e->ready_ext = ev->info->ext;
    e->ready_max_read = ev->info->limits.max_read;
  }
  sd_mutex_unlock(&e->lock);
  sd_event_set(&e->changed);
}

/* Waits until the session is READY in generation >= gen (1 on success). */
static int wait_ready_gen(sd_sftp_session *s, rcev *e, uint32_t gen, uint32_t ms)
{
  uint64_t end = sd_tick_ms() + ms;
  for (;;) {
    uint32_t g;
    sd_mutex_lock(&e->lock);
    g = e->ready_gen;
    sd_mutex_unlock(&e->lock);
    if (g >= gen && sd_sftp_session_state(s) == SD_SFTP_ST_READY) return 1;
    if (sd_tick_ms() >= end) return 0;
    (void)sd_event_wait(&e->changed, 20);
  }
}

static int wait_state(sd_sftp_session *s, rcev *e, sd_sftp_state st, uint32_t ms)
{
  uint64_t end = sd_tick_ms() + ms;
  while (sd_sftp_session_state(s) != st) {
    if (sd_tick_ms() >= end) return 0;
    (void)sd_event_wait(&e->changed, 20);
  }
  return 1;
}

/* Index of the first event with state st at or after `from`, or -1. */
static int ev_find(rcev *e, sd_sftp_state st, int from)
{
  int i, r = -1;
  sd_mutex_lock(&e->lock);
  for (i = from; i < e->n; i++) if (e->st[i] == st) { r = i; break; }
  sd_mutex_unlock(&e->lock);
  return r;
}

static int ev_count(rcev *e, sd_sftp_state st)
{
  int i, c = 0;
  sd_mutex_lock(&e->lock);
  for (i = 0; i < e->n; i++) if (e->st[i] == st) c++;
  sd_mutex_unlock(&e->lock);
  return c;
}

/* ---- fixture ---- */

typedef struct rx { msrv m; sd_sftp_session *s; rcev ev; } rx;

static void rx_opts(sd_sftp_options *o)
{
  sd_sftp_options_init(o);
  o->reconnect.initial_delay_ms = 40;
  o->reconnect.max_delay_ms = 200;
  o->default_timeout_ms = 10000;
}

static rx *rx_start(const sd_sftp_options *opt, uint32_t caps, sd_err refuse_bulk)
{
  rx *x = (rx *)sd_calloc(1, sizeof(rx));
  sd_sftp_transport t;
  sd_sftp_options o;
  uint64_t i;
  if (!x) return NULL;
  sd_mutex_init(&x->m.lock);
  sd_mutex_init(&x->ev.lock);
  (void)sd_event_init(&x->ev.changed, 0, 0);
  x->m.data = (uint8_t *)sd_alloc(MS_FILE_MAX);
  if (!x->m.data) return NULL;
  x->m.size = 1024u * 1024u;
  for (i = 0; i < x->m.size; i++) x->m.data[i] = (uint8_t)(i * 13u + (i >> 11));
  x->m.f = fake_new(ms_handler, &x->m);
  if (!x->m.f) return NULL;
  fake_set_caps(x->m.f, caps);
  fake_refuse_bulk(x->m.f, refuse_bulk);
  fake_transport(x->m.f, &t);
  if (!opt) { rx_opts(&o); opt = &o; }
  if (sd_sftp_session_create_transport(&t, opt, rcev_cb, &x->ev, &x->s) != SD_OK) { fake_free_if_unused(x->m.f); return NULL; }
  if (sd_sftp_session_start(x->s) != SD_OK) return NULL;
  if (!wait_ready_gen(x->s, &x->ev, 1, 5000)) return NULL;
  return x;
}

static void rx_stop(rx *x)
{
  if (!x) return;
  if (x->s) {
    (void)sd_sftp_session_close(x->s);
    (void)wait_state(x->s, &x->ev, SD_SFTP_ST_CLOSED, 5000);
    sd_sftp_session_destroy(x->s);
  }
  sd_event_destroy(&x->ev.changed);
  sd_mutex_destroy(&x->ev.lock);
  sd_mutex_destroy(&x->m.lock);
  sd_free(x->m.data);
  sd_free(x);
}

#define CAPS_FULL (SD_SFTP_TP_REOPEN | SD_SFTP_TP_STREAMS)

static sd_sftp_file *rx_open(rx *x, const char *path, int dir, waiter *w)
{
  sd_sftp_reqopt o = { 0, 5000, NULL };
  sd_sftp_file *f = NULL;
  waiter_reset(w, W_OPEN);
  if ((dir ? sd_sftp_opendir(x->s, path, &o, waiter_cb, w) : sd_sftp_open(x->s, path, SD_SFTP_O_READ | SD_SFTP_O_WRITE, NULL, NULL, &o, waiter_cb, w)) != SD_OK)
    return NULL;
  if (!waiter_wait(w, 5000) || w->err != SD_OK) return NULL;
  f = w->file;
  return f;
}

static int check_data(const rx *x, const uint8_t *buf, uint64_t off, uint32_t len)
{
  uint32_t i;
  for (i = 0; i < len; i++) if (buf[i] != x->m.data[off + i]) return 0;
  return 1;
}

/* After a reconnect: the handle is stale, reopen makes it usable, the data reads back. */
static void check_reopen_and_read(sd_test_ctx *sd_t_, rx *x, sd_sftp_file *f, uint32_t gen)
{
  waiter w;
  sd_sftp_reqopt o = { 0, 5000, NULL };
  sd_sftp_file_info fi;
  uint8_t *buf = (uint8_t *)sd_alloc(256 * 1024);
  SD_REQUIRE(buf != NULL);
  waiter_init(&w, x->s);
  SD_CHECK(sd_sftp_file_get_info(f, &fi) == SD_OK && fi.stale);
  SD_CHECK_EQ_INT(sd_sftp_read(f, 0, buf, 1024, &o, waiter_cb, &w), SD_E_STALE_HANDLE);
  waiter_reset(&w, W_OPEN);
  SD_REQUIRE(sd_sftp_file_reopen(f, &o, waiter_cb, &w) == SD_OK);
  SD_REQUIRE(waiter_wait(&w, 5000));
  SD_CHECK_EQ_INT(w.err, SD_OK);
  SD_CHECK(w.file == f);
  SD_CHECK_EQ_U64(w.attrs.size, x->m.size);
  SD_CHECK(sd_sftp_file_get_info(f, &fi) == SD_OK && !fi.stale && fi.generation == gen);
  SD_CHECK_EQ_INT(sd_sftp_file_reopen(f, &o, waiter_cb, &w), SD_E_INVALID_PARAM);   /* not stale */
  waiter_reset(&w, W_RW);
  SD_REQUIRE(sd_sftp_read(f, 4096, buf, 200 * 1024, &o, waiter_cb, &w) == SD_OK);
  SD_REQUIRE(waiter_wait(&w, 5000));
  SD_CHECK_EQ_INT(w.err, SD_OK);
  SD_CHECK_EQ_INT(w.bytes, 200 * 1024);
  SD_CHECK(check_data(x, buf, 4096, 200 * 1024));
  waiter_free(&w);
  sd_free(buf);
}

/* ---- tests ---- */

SD_TEST(reconnect_after_idle_drop)
{
  rx *x = rx_start(NULL, CAPS_FULL, SD_OK);
  waiter w;
  sd_sftp_file *f;
  int i_disc, i_wait, i_conn, i_ready;
  sd_sftp_server_info info;
  SD_REQUIRE(x != NULL);
  SD_CHECK_EQ_INT(x->ev.ready_channels, 2);
  SD_CHECK_EQ_INT(sd_sftp_session_generation(x->s), 1);
  waiter_init(&w, x->s);
  f = rx_open(x, "/data", 0, &w);
  SD_REQUIRE(f != NULL);
  fake_hangup(x->m.f);
  SD_REQUIRE(wait_ready_gen(x->s, &x->ev, 2, 5000));
  SD_CHECK_EQ_INT(sd_sftp_session_generation(x->s), 2);
  SD_CHECK_EQ_INT(fake_opens(x->m.f), 2);
  /* 01 §10.4 ordering: DISCONNECTED, RECONNECT_WAIT, CONNECTING, READY */
  i_disc = ev_find(&x->ev, SD_SFTP_ST_DISCONNECTED, 0);
  i_wait = ev_find(&x->ev, SD_SFTP_ST_RECONNECT_WAIT, i_disc + 1);
  i_conn = ev_find(&x->ev, SD_SFTP_ST_CONNECTING, i_wait + 1);
  i_ready = ev_find(&x->ev, SD_SFTP_ST_READY, i_conn + 1);
  SD_CHECK(i_disc > 0 && i_wait > i_disc && i_conn > i_wait && i_ready > i_conn);
  SD_CHECK_EQ_INT(x->ev.reason[i_disc], SD_E_DISCONNECTED);
  SD_CHECK_EQ_INT(x->ev.attempt[i_wait], 1);
  SD_CHECK(x->ev.retry[i_wait] >= 32 && x->ev.retry[i_wait] <= 48);   /* 40 ms +/- 20% */
  SD_CHECK_EQ_INT(x->ev.gen[i_ready], 2);
  SD_CHECK(sd_sftp_session_info(x->s, &info, NULL, 0) == SD_OK && info.generation == 2 && info.channels == 2);
  check_reopen_and_read(sd_t_, x, f, 2);
  waiter_reset(&w, W_STAT);
  SD_CHECK_EQ_INT(sd_sftp_close(f, NULL, waiter_cb, &w), SD_OK);
  SD_REQUIRE(waiter_wait(&w, 5000));
  SD_CHECK_EQ_INT(w.err, SD_OK);
  {
    sd_sftp_stats st;
    SD_CHECK(sd_sftp_session_stats(x->s, &st) == SD_OK);
    SD_CHECK_EQ_INT(st.generation, 2);
    SD_CHECK_EQ_INT(st.channels, 2);
    SD_CHECK(st.conn[0].ready && st.conn[0].rx_total > 200 * 1024);
    SD_CHECK_EQ_INT(st.reconnect_attempts, 0);
  }
  waiter_free(&w);
  rx_stop(x);
}

static void hangup_when_held(rx *x, LONG n)
{
  while (x->m.held < n) Sleep(1);
  fake_hangup(x->m.f);
}

SD_TEST(reconnect_drop_during_pipelined_reads)
{
  rx *x = rx_start(NULL, CAPS_FULL, SD_OK);
  waiter w, w2;
  sd_sftp_file *f;
  sd_sftp_reqopt o = { 0, 10000, NULL };
  uint8_t *buf = (uint8_t *)sd_alloc(1024 * 1024);
  SD_REQUIRE(x != NULL && buf != NULL);
  waiter_init(&w, x->s);
  waiter_init(&w2, x->s);
  f = rx_open(x, "/data", 0, &w);
  SD_REQUIRE(f != NULL);
  InterlockedExchange(&x->m.hold, HOLD_READ);
  waiter_reset(&w, W_RW);
  SD_REQUIRE(sd_sftp_read(f, 0, buf, 1024 * 1024, &o, waiter_cb, &w) == SD_OK);   /* 16 pipelined chunks */
  hangup_when_held(x, 16);
  SD_REQUIRE(waiter_wait(&w, 5000));
  SD_CHECK_EQ_INT(w.err, SD_E_DISCONNECTED);
  SD_CHECK_EQ_INT(w.maybe_executed, 1);
  SD_CHECK_EQ_INT(w.calls, 1);
  /* submissions during the outage fail at once, except WAIT_READY ones */
  SD_CHECK_EQ_INT(sd_sftp_read(f, 0, buf, 10, &o, waiter_cb, &w2), SD_E_STALE_HANDLE);
  InterlockedExchange(&x->m.hold, 0);
  SD_REQUIRE(wait_ready_gen(x->s, &x->ev, 2, 5000));
  check_reopen_and_read(sd_t_, x, f, 2);
  /* the full pipelined read works again on the reopened handle */
  waiter_reset(&w, W_RW);
  SD_REQUIRE(sd_sftp_read(f, 0, buf, 1024 * 1024, &o, waiter_cb, &w) == SD_OK);
  SD_REQUIRE(waiter_wait(&w, 5000));
  SD_CHECK_EQ_INT(w.err, SD_OK);
  SD_CHECK_EQ_INT(w.bytes, 1024 * 1024);
  SD_CHECK(check_data(x, buf, 0, 1024 * 1024));
  sd_sftp_file_release(f);
  waiter_free(&w);
  waiter_free(&w2);
  sd_free(buf);
  rx_stop(x);
}

SD_TEST(reconnect_drop_during_pipelined_writes)
{
  rx *x = rx_start(NULL, CAPS_FULL, SD_OK);
  waiter w, w2;
  sd_sftp_file *f;
  sd_sftp_reqopt o = { 0, 10000, NULL };
  uint8_t *buf = (uint8_t *)sd_alloc(2 * 1024 * 1024);
  uint32_t i;
  SD_REQUIRE(x != NULL && buf != NULL);
  for (i = 0; i < 2 * 1024 * 1024; i++) buf[i] = (uint8_t)(i * 7u);
  waiter_init(&w, x->s);
  waiter_init(&w2, x->s);
  f = rx_open(x, "/data", 0, &w);
  SD_REQUIRE(f != NULL);
  InterlockedExchange(&x->m.hold, HOLD_WRITE);
  waiter_reset(&w, W_RW);
  SD_REQUIRE(sd_sftp_write(f, 0, buf, 2 * 1024 * 1024, &o, waiter_cb, &w) == SD_OK);
  hangup_when_held(x, 8);
  SD_REQUIRE(waiter_wait(&w, 5000));
  SD_CHECK_EQ_INT(w.err, SD_E_DISCONNECTED);
  SD_CHECK_EQ_INT(w.maybe_executed, 1);       /* effect unknown: the VFS re-stats */
  SD_CHECK_EQ_INT(w.bytes, 0);
  InterlockedExchange(&x->m.hold, 0);
  SD_REQUIRE(wait_ready_gen(x->s, &x->ev, 2, 5000));
  /* never replayed by sd_sftp: the server saw no write in generation 2 */
  SD_CHECK_EQ_INT(x->m.on_stream[1][SFTP_WRITE] + x->m.on_stream[0][SFTP_WRITE], x->m.held);
  waiter_reset(&w, W_OPEN);
  SD_REQUIRE(sd_sftp_file_reopen(f, &o, waiter_cb, &w) == SD_OK);
  SD_REQUIRE(waiter_wait(&w, 5000));
  SD_CHECK_EQ_INT(w.err, SD_OK);
  waiter_reset(&w, W_RW);
  SD_REQUIRE(sd_sftp_write(f, 0, buf, 2 * 1024 * 1024, &o, waiter_cb, &w) == SD_OK);
  SD_REQUIRE(waiter_wait(&w, 5000));
  SD_CHECK_EQ_INT(w.err, SD_OK);
  SD_CHECK_EQ_INT(w.bytes, 2 * 1024 * 1024);
  SD_CHECK(memcmp(x->m.data, buf, 2 * 1024 * 1024) == 0);
  sd_sftp_file_release(f);
  waiter_free(&w);
  waiter_free(&w2);
  sd_free(buf);
  rx_stop(x);
}

SD_TEST(reconnect_drop_during_open_and_readdir)
{
  rx *x = rx_start(NULL, CAPS_FULL, SD_OK);
  waiter w, w2;
  sd_sftp_file *d;
  sd_sftp_reqopt o = { 0, 10000, NULL };
  SD_REQUIRE(x != NULL);
  waiter_init(&w, x->s);
  waiter_init(&w2, x->s);
  d = rx_open(x, "/dir", 1, &w);
  SD_REQUIRE(d != NULL);
  waiter_reset(&w, W_DIR);
  SD_REQUIRE(sd_sftp_readdir(d, &o, waiter_cb, &w) == SD_OK);
  SD_REQUIRE(waiter_wait(&w, 5000));
  SD_CHECK(w.err == SD_OK && w.count == 3);
  /* OPEN and READDIR in flight when the connection drops */
  InterlockedExchange(&x->m.hold, HOLD_OPEN | HOLD_READDIR);
  waiter_reset(&w, W_DIR);
  waiter_reset(&w2, W_OPEN);
  SD_REQUIRE(sd_sftp_readdir(d, &o, waiter_cb, &w) == SD_OK);
  SD_REQUIRE(sd_sftp_open(x->s, "/data", SD_SFTP_O_READ, NULL, NULL, &o, waiter_cb, &w2) == SD_OK);
  hangup_when_held(x, 2);
  SD_REQUIRE(waiter_wait(&w, 5000));
  SD_REQUIRE(waiter_wait(&w2, 5000));
  SD_CHECK_EQ_INT(w.err, SD_E_DISCONNECTED);
  SD_CHECK_EQ_INT(w2.err, SD_E_DISCONNECTED);
  SD_CHECK_EQ_INT(w2.maybe_executed, 1);
  SD_CHECK(w2.file == NULL);
  InterlockedExchange(&x->m.hold, 0);
  SD_REQUIRE(wait_ready_gen(x->s, &x->ev, 2, 5000));
  /* directory reopen: the listing restarts at the beginning */
  SD_CHECK_EQ_INT(sd_sftp_readdir(d, &o, waiter_cb, &w), SD_E_STALE_HANDLE);
  waiter_reset(&w, W_OPEN);
  SD_REQUIRE(sd_sftp_file_reopen(d, &o, waiter_cb, &w) == SD_OK);
  SD_REQUIRE(waiter_wait(&w, 5000));
  SD_CHECK_EQ_INT(w.err, SD_OK);
  waiter_reset(&w, W_DIR);
  SD_REQUIRE(sd_sftp_readdir(d, &o, waiter_cb, &w) == SD_OK);
  SD_REQUIRE(waiter_wait(&w, 5000));
  SD_CHECK(w.err == SD_OK && w.count == 3 && strcmp(w.names[0], "a") == 0);
  /* the open works again */
  SD_REQUIRE(rx_open(x, "/data", 0, &w2) != NULL);
  sd_sftp_file_release(w2.file);
  sd_sftp_file_release(d);
  waiter_free(&w);
  waiter_free(&w2);
  rx_stop(x);
}

SD_TEST(reconnect_mutating_ops_maybe_executed)
{
  sd_sftp_options opt;
  rx *x;
  waiter w[5], ws, wq;
  sd_sftp_reqopt o = { 0, 10000, NULL };
  sd_sftp_reqopt wr = { SD_SFTP_REQ_WAIT_READY, 5000, NULL };
  sd_sftp_attrs a;
  int i;
  rx_opts(&opt);
  opt.reconnect.initial_delay_ms = 400;      /* the outage outlasts the checks below */
  opt.reconnect.max_delay_ms = 400;
  x = rx_start(&opt, CAPS_FULL, SD_OK);
  SD_REQUIRE(x != NULL);
  for (i = 0; i < 5; i++) { waiter_init(&w[i], x->s); waiter_reset(&w[i], W_STAT); }
  waiter_init(&ws, x->s);
  waiter_init(&wq, x->s);
  memset(&a, 0, sizeof(a));
  a.valid = SD_SFTP_ATTR_PERM;
  a.perm = 0600;
  InterlockedExchange(&x->m.hold, HOLD_PATHOPS);
  SD_REQUIRE(sd_sftp_rename(x->s, "/a", "/b", 0, &o, waiter_cb, &w[0]) == SD_OK);
  SD_REQUIRE(sd_sftp_rename(x->s, "/c", "/d", SD_SFTP_RENAME_OVERWRITE, &o, waiter_cb, &w[1]) == SD_OK);
  SD_REQUIRE(sd_sftp_remove(x->s, "/e", &o, waiter_cb, &w[2]) == SD_OK);
  SD_REQUIRE(sd_sftp_mkdir(x->s, "/f", NULL, &o, waiter_cb, &w[3]) == SD_OK);
  SD_REQUIRE(sd_sftp_setstat(x->s, "/g", &a, 0, &o, waiter_cb, &w[4]) == SD_OK);
  hangup_when_held(x, 5);
  for (i = 0; i < 5; i++) {
    SD_REQUIRE(waiter_wait(&w[i], 5000));
    SD_CHECK_EQ_INT(w[i].err, SD_E_DISCONNECTED);
    SD_CHECK_EQ_INT(w[i].maybe_executed, 1);
  }
  InterlockedExchange(&x->m.hold, 0);
  /* while not READY: plain submissions fail at once, WAIT_READY ones wait for the next READY */
  SD_CHECK(sd_sftp_session_state(x->s) != SD_SFTP_ST_READY);
  SD_CHECK_EQ_INT(sd_sftp_stat(x->s, "/data", &o, waiter_cb, &wq), SD_E_DISCONNECTED);
  waiter_reset(&ws, W_STAT);
  SD_REQUIRE(sd_sftp_stat(x->s, "/data", &wr, waiter_cb, &ws) == SD_OK);
  SD_REQUIRE(waiter_wait(&ws, 5000));
  SD_CHECK_EQ_INT(ws.err, SD_OK);
  SD_CHECK_EQ_U64(ws.attrs.size, x->m.size);
  SD_REQUIRE(wait_ready_gen(x->s, &x->ev, 2, 5000));
  for (i = 0; i < 5; i++) waiter_free(&w[i]);
  waiter_free(&ws);
  waiter_free(&wq);
  rx_stop(x);
}

SD_TEST(reconnect_wait_ready_survives_outage)
{
  sd_sftp_options opt;
  rx *x;
  waiter w;
  sd_sftp_reqopt wr = { SD_SFTP_REQ_WAIT_READY, 3000, NULL };
  sd_sftp_reqopt shortw = { SD_SFTP_REQ_WAIT_READY, 150, NULL };
  rx_opts(&opt);
  opt.reconnect.initial_delay_ms = 500;      /* a visible outage */
  opt.reconnect.max_delay_ms = 500;
  x = rx_start(&opt, CAPS_FULL, SD_OK);
  SD_REQUIRE(x != NULL);
  waiter_init(&w, x->s);
  fake_hangup(x->m.f);
  SD_REQUIRE(wait_state(x->s, &x->ev, SD_SFTP_ST_RECONNECT_WAIT, 3000));
  waiter_reset(&w, W_STAT);
  SD_REQUIRE(sd_sftp_stat(x->s, "/data", &shortw, waiter_cb, &w) == SD_OK);   /* expires during the outage */
  SD_REQUIRE(waiter_wait(&w, 3000));
  SD_CHECK_EQ_INT(w.err, SD_E_TIMEOUT);
  SD_CHECK_EQ_INT(w.maybe_executed, 0);
  waiter_reset(&w, W_STAT);
  SD_REQUIRE(sd_sftp_stat(x->s, "/data", &wr, waiter_cb, &w) == SD_OK);
  SD_REQUIRE(waiter_wait(&w, 5000));
  SD_CHECK_EQ_INT(w.err, SD_OK);
  SD_CHECK_EQ_INT(sd_sftp_session_generation(x->s), 2);
  waiter_free(&w);
  rx_stop(x);
}

SD_TEST(channels_meta_and_bulk_classes)
{
  rx *x = rx_start(NULL, CAPS_FULL, SD_OK);
  waiter w, ws;
  sd_sftp_file *f, *fm;
  sd_sftp_reqopt o = { 0, 10000, NULL };
  sd_sftp_reqopt meta = { SD_SFTP_REQ_CLASS_META, 5000, NULL };
  uint8_t *buf = (uint8_t *)sd_alloc(512 * 1024);
  SD_REQUIRE(x != NULL && buf != NULL);
  SD_CHECK_EQ_INT(x->ev.ready_channels, 2);
  SD_CHECK(x->m.on_stream[0][SFTP_REALPATH] >= 1 && x->m.on_stream[1][SFTP_REALPATH] == 0);   /* startup on meta */
  waiter_init(&w, x->s);
  waiter_init(&ws, x->s);
  f = rx_open(x, "/data", 0, &w);
  SD_REQUIRE(f != NULL);
  SD_CHECK_EQ_INT(x->m.on_stream[1][SFTP_OPEN], 1);        /* data handles live on bulk */
  /* a stat completes while bulk reads are stuck: metadata never waits behind data (C17) */
  InterlockedExchange(&x->m.hold, HOLD_READ);
  waiter_reset(&w, W_RW);
  SD_REQUIRE(sd_sftp_read(f, 0, buf, 512 * 1024, &o, waiter_cb, &w) == SD_OK);
  while (x->m.held < 8) Sleep(1);
  waiter_reset(&ws, W_STAT);
  SD_REQUIRE(sd_sftp_stat(x->s, "/data", &o, waiter_cb, &ws) == SD_OK);
  SD_REQUIRE(waiter_wait(&ws, 3000));
  SD_CHECK_EQ_INT(ws.err, SD_OK);
  SD_CHECK(x->m.on_stream[0][SFTP_STAT] >= 1 && x->m.on_stream[1][SFTP_STAT] == 0);
  SD_CHECK(x->m.on_stream[1][SFTP_READ] >= 8 && x->m.on_stream[0][SFTP_READ] == 0);
  /* attribute-only opens (CLASS_META) and their handle ops stay on meta */
  waiter_reset(&ws, W_OPEN);
  SD_REQUIRE(sd_sftp_open(x->s, "/data", SD_SFTP_O_READ, NULL, NULL, &meta, waiter_cb, &ws) == SD_OK);
  SD_REQUIRE(waiter_wait(&ws, 3000));
  SD_REQUIRE(ws.err == SD_OK);
  fm = ws.file;
  SD_CHECK_EQ_INT(x->m.on_stream[0][SFTP_OPEN], 1);
  SD_CHECK_EQ_INT(x->m.on_stream[0][SFTP_FSTAT], 1);
  /* copy-data affinity: same_channel_as puts the new handle on fm's channel */
  waiter_reset(&ws, W_OPEN);
  SD_REQUIRE(sd_sftp_open(x->s, "/data", SD_SFTP_O_READ, NULL, fm, &o, waiter_cb, &ws) == SD_OK);
  SD_REQUIRE(waiter_wait(&ws, 3000));
  SD_REQUIRE(ws.err == SD_OK);
  SD_CHECK_EQ_INT(x->m.on_stream[0][SFTP_OPEN], 2);
  sd_sftp_file_release(ws.file);
  sd_sftp_file_release(fm);
  InterlockedExchange(&x->m.hold, 0);
  sd_sftp_file_release(f);    /* the held read completes at close */
  waiter_free(&ws);
  rx_stop(x);
  SD_CHECK(waiter_wait(&w, 3000));
  waiter_free(&w);
  sd_free(buf);
}

SD_TEST(channels_degrade_to_one)
{
  rx *x = rx_start(NULL, CAPS_FULL, SD_E_BUSY);     /* MaxSessions 1: the bulk channel is refused */
  waiter w, ws;
  sd_sftp_file *f;
  sd_sftp_reqopt o = { 0, 10000, NULL };
  uint8_t *buf = (uint8_t *)sd_alloc(512 * 1024);
  sd_sftp_server_info info;
  SD_REQUIRE(x != NULL && buf != NULL);
  SD_CHECK_EQ_INT(x->ev.ready_channels, 1);
  SD_CHECK(sd_sftp_session_info(x->s, &info, NULL, 0) == SD_OK && info.channels == 1);
  waiter_init(&w, x->s);
  waiter_init(&ws, x->s);
  f = rx_open(x, "/data", 0, &w);
  SD_REQUIRE(f != NULL);
  waiter_reset(&w, W_RW);
  SD_REQUIRE(sd_sftp_read(f, 0, buf, 512 * 1024, &o, waiter_cb, &w) == SD_OK);
  SD_REQUIRE(waiter_wait(&w, 5000));
  SD_CHECK(w.err == SD_OK && w.bytes == 512 * 1024 && check_data(x, buf, 0, 512 * 1024));
  SD_CHECK(x->m.on_stream[0][SFTP_READ] == 8 && x->m.on_stream[1][SFTP_READ] == 0);
  /* with one channel the meta queue still goes first */
  InterlockedExchange(&x->m.hold, HOLD_READ);
  waiter_reset(&w, W_RW);
  SD_REQUIRE(sd_sftp_read(f, 0, buf, 512 * 1024, &o, waiter_cb, &w) == SD_OK);
  while (x->m.held < 8) Sleep(1);
  waiter_reset(&ws, W_STAT);
  SD_REQUIRE(sd_sftp_stat(x->s, "/data", &o, waiter_cb, &ws) == SD_OK);
  SD_REQUIRE(waiter_wait(&ws, 3000));
  SD_CHECK_EQ_INT(ws.err, SD_OK);
  /* a reconnect re-tries the bulk channel; the server now allows it */
  fake_refuse_bulk(x->m.f, SD_OK);
  InterlockedExchange(&x->m.hold, 0);
  fake_hangup(x->m.f);
  SD_REQUIRE(waiter_wait(&w, 5000));
  SD_CHECK_EQ_INT(w.err, SD_E_DISCONNECTED);
  SD_REQUIRE(wait_ready_gen(x->s, &x->ev, 2, 5000));
  SD_CHECK_EQ_INT(x->ev.ready_channels, 2);
  check_reopen_and_read(sd_t_, x, f, 2);
  sd_sftp_file_release(f);
  waiter_free(&w);
  waiter_free(&ws);
  sd_free(buf);
  rx_stop(x);
}

SD_TEST(channels_one_by_option_or_transport)
{
  sd_sftp_options opt;
  rx *x;
  rx_opts(&opt);
  opt.channels = 1;
  x = rx_start(&opt, CAPS_FULL, SD_OK);
  SD_REQUIRE(x != NULL);
  SD_CHECK_EQ_INT(x->ev.ready_channels, 1);
  SD_CHECK_EQ_INT(x->m.on_stream[1][SFTP_REALPATH], 0);
  rx_stop(x);
  x = rx_start(NULL, SD_SFTP_TP_REOPEN, SD_OK);      /* no second stream in the transport */
  SD_REQUIRE(x != NULL);
  SD_CHECK_EQ_INT(x->ev.ready_channels, 1);
  rx_stop(x);
}

SD_TEST(reconnect_backoff_jitter_and_retries)
{
  sd_sftp_options opt;
  rx *x;
  int i, k = 0;
  uint32_t lo[3] = { 80, 160, 320 }, hi[3] = { 120, 240, 480 };
  rx_opts(&opt);
  opt.reconnect.initial_delay_ms = 100;
  opt.reconnect.max_delay_ms = 400;
  x = rx_start(&opt, CAPS_FULL, SD_OK);
  SD_REQUIRE(x != NULL);
  fake_fail_opens(x->m.f, 3, SD_E_CONN_REFUSED);   /* sshd down for three attempts */
  fake_hangup(x->m.f);
  SD_REQUIRE(wait_ready_gen(x->s, &x->ev, 2, 10000));
  SD_CHECK_EQ_INT(fake_opens(x->m.f), 5);           /* initial + 3 refused + 1 good */
  SD_CHECK_EQ_INT(ev_count(&x->ev, SD_SFTP_ST_RECONNECT_WAIT), 4);
  sd_mutex_lock(&x->ev.lock);
  for (i = 0; i < x->ev.n; i++) {
    if (x->ev.st[i] != SD_SFTP_ST_RECONNECT_WAIT) continue;
    SD_CHECK_EQ_INT(x->ev.attempt[i], (uint32_t)k + 1);
    if (k > 0) SD_CHECK_EQ_INT(x->ev.reason[i], SD_E_CONN_REFUSED);
    if (k < 3) SD_CHECK(x->ev.retry[i] >= lo[k] && x->ev.retry[i] <= hi[k]);
    else SD_CHECK(x->ev.retry[i] >= 320 && x->ev.retry[i] <= 480);   /* capped at max 400 +/- 20% */
    k++;
  }
  sd_mutex_unlock(&x->ev.lock);
  rx_stop(x);
}

SD_TEST(reconnect_permanent_failure_and_reconnect_now)
{
  rx *x = rx_start(NULL, CAPS_FULL, SD_OK);
  waiter w;
  sd_sftp_reqopt wr = { SD_SFTP_REQ_WAIT_READY, 5000, NULL };
  int i;
  SD_REQUIRE(x != NULL);
  waiter_init(&w, x->s);
  fake_fail_opens(x->m.f, 1, SD_E_HOSTKEY_MISMATCH);
  fake_hangup(x->m.f);
  SD_REQUIRE(wait_state(x->s, &x->ev, SD_SFTP_ST_FAILED, 5000));
  i = ev_find(&x->ev, SD_SFTP_ST_FAILED, 0);
  SD_CHECK(i >= 0 && x->ev.reason[i] == SD_E_HOSTKEY_MISMATCH);
  Sleep(300);
  SD_CHECK_EQ_INT(fake_opens(x->m.f), 2);            /* no retry loop after a permanent error */
  waiter_reset(&w, W_STAT);
  SD_CHECK_EQ_INT(sd_sftp_stat(x->s, "/data", &wr, waiter_cb, &w), SD_E_DISCONNECTED);
  SD_CHECK_EQ_INT(sd_sftp_session_reconnect_now(x->s), SD_OK);   /* the user fixed known_hosts */
  SD_REQUIRE(wait_ready_gen(x->s, &x->ev, 2, 5000));
  SD_CHECK_EQ_INT(fake_opens(x->m.f), 3);
  waiter_free(&w);
  rx_stop(x);
}

SD_TEST(reconnect_auth_required_and_max_attempts)
{
  sd_sftp_options opt;
  rx *x = rx_start(NULL, CAPS_FULL, SD_OK);
  int i;
  SD_REQUIRE(x != NULL);
  fake_fail_opens(x->m.f, 1, SD_E_AUTH_FAILED);
  fake_hangup(x->m.f);
  SD_REQUIRE(wait_state(x->s, &x->ev, SD_SFTP_ST_AUTH_REQUIRED, 5000));
  i = ev_find(&x->ev, SD_SFTP_ST_AUTH_REQUIRED, 0);
  SD_CHECK(i >= 0 && x->ev.reason[i] == SD_E_AUTH_FAILED);
  SD_CHECK_EQ_INT(sd_sftp_session_reconnect_now(x->s), SD_OK);
  SD_REQUIRE(wait_ready_gen(x->s, &x->ev, 2, 5000));
  rx_stop(x);

  rx_opts(&opt);
  opt.reconnect.max_attempts = 2;
  x = rx_start(&opt, CAPS_FULL, SD_OK);
  SD_REQUIRE(x != NULL);
  fake_fail_opens(x->m.f, 10, SD_E_CONN_REFUSED);
  fake_hangup(x->m.f);
  SD_REQUIRE(wait_state(x->s, &x->ev, SD_SFTP_ST_FAILED, 5000));
  SD_CHECK_EQ_INT(fake_opens(x->m.f), 3);            /* initial + 2 attempts */
  SD_CHECK_EQ_INT(ev_count(&x->ev, SD_SFTP_ST_RECONNECT_WAIT), 2);
  rx_stop(x);
}

SD_TEST(reconnect_stop_and_disabled)
{
  sd_sftp_options opt;
  rx *x;
  waiter w;
  sd_sftp_reqopt wr = { SD_SFTP_REQ_WAIT_READY, 10000, NULL };
  int i;
  rx_opts(&opt);
  opt.reconnect.initial_delay_ms = 5000;
  opt.reconnect.max_delay_ms = 5000;
  x = rx_start(&opt, CAPS_FULL, SD_OK);
  SD_REQUIRE(x != NULL);
  waiter_init(&w, x->s);
  fake_hangup(x->m.f);
  SD_REQUIRE(wait_state(x->s, &x->ev, SD_SFTP_ST_RECONNECT_WAIT, 3000));
  waiter_reset(&w, W_STAT);
  SD_REQUIRE(sd_sftp_stat(x->s, "/data", &wr, waiter_cb, &w) == SD_OK);
  SD_CHECK_EQ_INT(sd_sftp_session_reconnect_stop(x->s), SD_OK);
  SD_REQUIRE(wait_state(x->s, &x->ev, SD_SFTP_ST_FAILED, 3000));
  i = ev_find(&x->ev, SD_SFTP_ST_FAILED, 0);
  SD_CHECK(i >= 0 && x->ev.reason[i] == SD_E_CANCELLED);
  SD_REQUIRE(waiter_wait(&w, 3000));
  SD_CHECK_EQ_INT(w.err, SD_E_DISCONNECTED);
  /* reconnect_now resumes at once (no 5 s backoff for the first attempt of the restarted loop) */
  SD_CHECK_EQ_INT(sd_sftp_session_reconnect_now(x->s), SD_OK);
  SD_REQUIRE(wait_ready_gen(x->s, &x->ev, 2, 2000));
  /* reconnect_now during a long backoff skips it */
  fake_hangup(x->m.f);
  SD_REQUIRE(wait_state(x->s, &x->ev, SD_SFTP_ST_RECONNECT_WAIT, 3000));
  SD_CHECK_EQ_INT(sd_sftp_session_reconnect_now(x->s), SD_OK);
  SD_REQUIRE(wait_ready_gen(x->s, &x->ev, 3, 2000));
  waiter_free(&w);
  rx_stop(x);

  rx_opts(&opt);
  opt.reconnect.enabled = 0;
  x = rx_start(&opt, CAPS_FULL, SD_OK);
  SD_REQUIRE(x != NULL);
  fake_hangup(x->m.f);
  SD_REQUIRE(wait_state(x->s, &x->ev, SD_SFTP_ST_FAILED, 3000));
  SD_CHECK_EQ_INT(fake_opens(x->m.f), 1);
  rx_stop(x);
}

SD_TEST(reconnect_ready_info_reread_and_reopen_gone)
{
  rx *x;
  waiter w;
  sd_sftp_file *f;
  sd_sftp_reqopt o = { 0, 5000, NULL };
  sd_sftp_file_info fi;
  x = (rx *)NULL;
  {
    /* generation 2 announces no extensions: READY_INFO must show it */
    x = rx_start(NULL, CAPS_FULL, SD_OK);
    SD_REQUIRE(x != NULL);
    x->m.minimal_gen2 = 1;
  }
  SD_CHECK(x->ev.ready_ext & SD_SFTP_EXT_LIMITS);
  SD_CHECK_EQ_U64(x->ev.ready_max_read, MS_CHUNK);
  SD_CHECK(sd_sftp_has_ext(x->s, SD_SFTP_EXT_POSIX_RENAME));
  waiter_init(&w, x->s);
  f = rx_open(x, "/data", 0, &w);
  SD_REQUIRE(f != NULL);
  fake_hangup(x->m.f);
  SD_REQUIRE(wait_ready_gen(x->s, &x->ev, 2, 5000));
  SD_CHECK_EQ_INT(x->ev.ready_ext, 0);
  SD_CHECK(x->ev.ready_max_read != MS_CHUNK);
  SD_CHECK(!sd_sftp_has_ext(x->s, SD_SFTP_EXT_POSIX_RENAME));
  /* the file vanished during the outage: reopen fails, the handle stays stale */
  InterlockedExchange(&x->m.gone, 1);
  waiter_reset(&w, W_OPEN);
  SD_REQUIRE(sd_sftp_file_reopen(f, &o, waiter_cb, &w) == SD_OK);
  SD_REQUIRE(waiter_wait(&w, 5000));
  SD_CHECK_EQ_INT(w.err, SD_E_NOT_FOUND);
  SD_CHECK(sd_sftp_file_get_info(f, &fi) == SD_OK && fi.stale && fi.generation == 1);
  waiter_reset(&w, W_STAT);
  SD_CHECK_EQ_INT(sd_sftp_close(f, &o, waiter_cb, &w), SD_OK);   /* stale close: local success */
  SD_REQUIRE(waiter_wait(&w, 5000));
  SD_CHECK_EQ_INT(w.err, SD_OK);
  waiter_free(&w);
  rx_stop(x);
}

SD_TEST(reconnect_close_during_backoff)
{
  sd_sftp_options opt;
  rx *x;
  waiter w;
  sd_sftp_reqopt wr = { SD_SFTP_REQ_WAIT_READY, 10000, NULL };
  rx_opts(&opt);
  opt.reconnect.initial_delay_ms = 5000;
  opt.reconnect.max_delay_ms = 5000;
  x = rx_start(&opt, CAPS_FULL, SD_OK);
  SD_REQUIRE(x != NULL);
  waiter_init(&w, x->s);
  fake_hangup(x->m.f);
  SD_REQUIRE(wait_state(x->s, &x->ev, SD_SFTP_ST_RECONNECT_WAIT, 3000));
  waiter_reset(&w, W_STAT);
  SD_REQUIRE(sd_sftp_stat(x->s, "/data", &wr, waiter_cb, &w) == SD_OK);
  SD_CHECK_EQ_INT(sd_sftp_session_close(x->s), SD_OK);
  SD_REQUIRE(waiter_wait(&w, 3000));
  SD_CHECK_EQ_INT(w.err, SD_E_SHUTDOWN);
  SD_REQUIRE(wait_state(x->s, &x->ev, SD_SFTP_ST_CLOSED, 3000));
  SD_CHECK_EQ_INT(fake_opens(x->m.f), 1);
  SD_CHECK_EQ_INT(sd_sftp_session_reconnect_now(x->s), SD_E_SHUTDOWN);
  waiter_free(&w);
  rx_stop(x);
}
