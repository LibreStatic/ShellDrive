/* Pool striping (01 §10.9, increment 2) against the extended scripted fake transport (no SSH, no
 * network). The fake projects members 1..3 onto streams 2..4, so a session with connections = 3
 * admits two members and a handle opened with SD_SFTP_O_STRIPED routes its stripe units over them.
 *
 * Covered: unit k goes to route_map[k % route_n] in submission order and sub-handles open lazily;
 * FSTAT/FSETSTAT barriers wait for the handle's outstanding data wires and run on the primary
 * handle, FSYNC/CLOSE wait the same way and also settle on every open sub-handle (the first error
 * wins); a member lost mid-flight gets its reads re-issued on the primary (with the right bytes) and
 * its writes completed with SD_E_DISCONNECTED / maybe_executed / session_ready while the session
 * stays READY; the route table is recomputed at the next barrier; plain, APPEND, CLASS_META and
 * directory handles never touch a member stream. */
#include <stdio.h>
#include <string.h>

#include "sd_base/sd_mem.h"
#include "sd_platform/sd_thread.h"
#include "sd_platform/sd_time.h"
#include "sd_test.h"
#include "sftp_proto.h"
#include "sftp_test_tp.h"
#include "test_util.h"

#define ST_UNIT  4096u
#define ST_CHUNK 32768u
#define ST_SIZE  (4u * 1024u * 1024u)
#define TR_MAX   512
#define HELD_MAX 8

enum { TR_OPEN = 1, TR_OPENDIR, TR_READ, TR_WRITE, TR_FSTAT, TR_FSETSTAT, TR_FSYNC, TR_CLOSE };

typedef struct tr_ev { uint32_t stream, type; uint64_t off; uint32_t len; char handle[8]; } tr_ev;
typedef struct held_rq { uint32_t stream, id, kind; uint64_t off; uint32_t len; } held_rq;

typedef struct xsrv {
  fake_srv *f;
  sd_mutex lock;
  tr_ev tr[TR_MAX];
  volatile LONG ntr;
  held_rq held[HELD_MAX];
  volatile LONG nheld;
  volatile LONG hold_read, hold_write;   /* reads/writes still to be held in flight */
  volatile LONG fail_fsync_stream;       /* stream whose FSYNC replies FAILURE (0: none) */
  uint8_t *wdata;                        /* WRITE mirror */
  uint64_t wlen;
} xsrv;

static uint8_t pat(uint64_t o) { return (uint8_t)(o * 7u + (o >> 9)); }

/* ---- trace of the requests the server saw ---- */

static void tr_add(xsrv *sv, uint32_t stream, uint32_t type, const char *handle, uint64_t off, uint32_t len)
{
  LONG i;
  sd_mutex_lock(&sv->lock);
  i = sv->ntr;
  if (i < TR_MAX) {
    tr_ev *e = &sv->tr[i];
    size_t n = handle ? strlen(handle) : 0;
    if (n > sizeof(e->handle) - 1) n = sizeof(e->handle) - 1;
    e->stream = stream; e->type = type; e->off = off; e->len = len;
    if (n) memcpy(e->handle, handle, n);
    e->handle[n] = 0;
    sv->ntr = i + 1;
  }
  sd_mutex_unlock(&sv->lock);
}

static void tr_add_span(xsrv *sv, uint32_t stream, uint32_t type, sd_span h, uint64_t off, uint32_t len)
{
  char tmp[8];
  size_t n = h.n < sizeof(tmp) - 1 ? h.n : sizeof(tmp) - 1;
  if (n) memcpy(tmp, h.p, n);
  tmp[n] = 0;
  tr_add(sv, stream, type, tmp, off, len);
}

static LONG tr_snapshot(xsrv *sv, tr_ev *out, LONG cap)
{
  LONG n;
  sd_mutex_lock(&sv->lock);
  n = sv->ntr < cap ? sv->ntr : cap;
  memcpy(out, sv->tr, (size_t)n * sizeof(tr_ev));
  sd_mutex_unlock(&sv->lock);
  return n;
}

/* Events of `type` on `stream` (stream 0: any). */
static int tr_n(const tr_ev *ev, LONG n, uint32_t type, uint32_t stream)
{
  LONG i;
  int c = 0;
  for (i = 0; i < n; i++) if (ev[i].type == type && (!stream || ev[i].stream == stream)) c++;
  return c;
}

static const tr_ev *tr_at(const tr_ev *ev, LONG n, uint32_t type, uint32_t stream, int k)
{
  LONG i;
  int c = 0;
  for (i = 0; i < n; i++) {
    if (ev[i].type != type || (stream && ev[i].stream != stream)) continue;
    if (c == k) return &ev[i];
    c++;
  }
  return NULL;
}

static const tr_ev *tr_off(const tr_ev *ev, LONG n, uint32_t type, uint64_t off)
{
  LONG i;
  for (i = 0; i < n; i++) if (ev[i].type == type && ev[i].off == off) return &ev[i];
  return NULL;
}

static const tr_ev *tr_off_s(const tr_ev *ev, LONG n, uint32_t type, uint32_t stream, uint64_t off)
{
  LONG i;
  for (i = 0; i < n; i++)
    if (ev[i].type == type && ev[i].stream == stream && ev[i].off == off) return &ev[i];
  return NULL;
}

/* ---- held (in-flight) requests ---- */

static void st_hold(xsrv *sv, uint32_t stream, uint32_t id, uint32_t kind, uint64_t off, uint32_t len)
{
  LONG i;
  sd_mutex_lock(&sv->lock);
  i = sv->nheld;
  if (i < HELD_MAX) {
    sv->held[i].stream = stream; sv->held[i].id = id; sv->held[i].kind = kind;
    sv->held[i].off = off; sv->held[i].len = len;
    sv->nheld = i + 1;
  }
  sd_mutex_unlock(&sv->lock);
}

static LONG st_held_count(xsrv *sv)
{
  LONG n;
  sd_mutex_lock(&sv->lock);
  n = sv->nheld;
  sd_mutex_unlock(&sv->lock);
  return n;
}

/* Answers every held request on its own stream (a request of a dropped member is simply dropped by
   the fake: its stream is no longer open). Runs on the fake's I/O thread. */
static void st_release_held(void *arg)
{
  xsrv *sv = (xsrv *)arg;
  LONG i, n;
  sd_mutex_lock(&sv->lock);
  n = sv->nheld;
  sv->nheld = 0;
  sd_mutex_unlock(&sv->lock);
  for (i = 0; i < n; i++) {
    sd_wr w;
    if (sv->held[i].kind == TR_READ) {
      uint32_t k, len = sv->held[i].len;
      pk_begin(&w, SFTP_DATA, sv->held[i].id);
      sd_wr_u32(&w, len);
      for (k = 0; k < len; k++) sd_wr_u8(&w, pat(sv->held[i].off + k));
    } else {
      pk_begin(&w, SFTP_STATUS, sv->held[i].id);
      sd_wr_u32(&w, SFTP_FX_OK);
      sd_wr_cstring(&w, "");
      sd_wr_cstring(&w, "");
    }
    sd_wr_patch_u32(&w, 0, (uint32_t)(w.len - 4));
    fake_reply_on(sv->f, sv->held[i].stream, w.p, w.len);
    sd_wr_free(&w);
  }
}

/* ---- server ---- */

static int span_is(sd_span s, const char *lit) { size_t n = strlen(lit); return s.n == n && memcmp(s.p, lit, n) == 0; }

static void st_version(xsrv *sv)
{
  static const char *const exts[][2] = {
    { "posix-rename@openssh.com", "1" }, { "statvfs@openssh.com", "2" },
    { "fsync@openssh.com", "1" }, { "limits@openssh.com", "1" },
  };
  sd_wr w;
  size_t i;
  sd_wr_init(&w, 4096);
  sd_wr_u32(&w, 0); sd_wr_u8(&w, SFTP_VERSION); sd_wr_u32(&w, 3);
  for (i = 0; i < SD_COUNTOF(exts); i++) { sd_wr_cstring(&w, exts[i][0]); sd_wr_cstring(&w, exts[i][1]); }
  fake_reply_wr(sv->f, &w);
}

static void st_attrs(xsrv *sv, uint32_t id, uint32_t perm, uint64_t size)
{
  sd_wr w;
  pk_begin(&w, SFTP_ATTRS, id);
  pk_attrs_body(&w, perm, size);
  fake_reply_wr(sv->f, &w);
}

static void st_name(xsrv *sv, uint32_t id, const char *name)
{
  sd_wr w;
  pk_begin(&w, SFTP_NAME, id);
  sd_wr_u32(&w, 1);
  sd_wr_cstring(&w, name); sd_wr_cstring(&w, "");
  sd_wr_u32(&w, 0);
  fake_reply_wr(sv->f, &w);
}

/* Handles are named after the stream that opened them ("h<stream>"), so a test can tell which
   channel a later request travelled on. */
static void st_handler(fake_srv *f, void *ctx, const uint8_t *pkt, size_t n)
{
  xsrv *sv = (xsrv *)ctx;
  uint8_t type = pkt[0];
  uint32_t id, stream = fake_cur_stream(f);
  sd_rd rd;
  if (type == SFTP_INIT) { st_version(sv); return; }
  sd_rd_init(&rd, pkt + 1, n - 1);
  id = sd_rd_u32(&rd);
  if (type == SFTP_EXTENDED) {
    sd_rd c = rd;
    sd_span nm = sd_rd_string(&c, 256);
    if (span_is(nm, "limits@openssh.com")) {
      sd_wr w;
      pk_begin(&w, SFTP_EXTENDED_REPLY, id);
      sd_wr_u64(&w, 262144); sd_wr_u64(&w, ST_CHUNK); sd_wr_u64(&w, ST_CHUNK); sd_wr_u64(&w, 1024);
      fake_reply_wr(f, &w);
      return;
    }
    if (span_is(nm, "fsync@openssh.com")) {
      sd_span h = sd_rd_string(&c, 256);
      tr_add_span(sv, stream, TR_FSYNC, h, 0, 0);
      if (sv->fail_fsync_stream == (LONG)stream) pk_status(f, id, SFTP_FX_FAILURE, "fsync failed");
      else pk_status(f, id, SFTP_FX_OK, "");
      return;
    }
    pk_status(f, id, SFTP_FX_OP_UNSUPPORTED, "unsupported in fake");
    return;
  }
  switch (type) {
  case SFTP_REALPATH: {
    sd_span p = sd_rd_string(&rd, 4096);
    if (span_is(p, ".")) { st_name(sv, id, "/home/u"); return; }
    pk_status(f, id, SFTP_FX_NO_SUCH_FILE, "no such file");
    return;
  }
  case SFTP_STAT: {
    sd_span p = sd_rd_string(&rd, 4096);
    if (span_is(p, "/home/u")) { st_attrs(sv, id, 040755, 4096); return; }
    pk_status(f, id, SFTP_FX_NO_SUCH_FILE, "no such file");
    return;
  }
  case SFTP_OPEN: {
    char h[16];
    (void)sd_rd_string(&rd, 4096);
    _snprintf_s(h, sizeof(h), _TRUNCATE, "h%u", stream);
    tr_add(sv, stream, TR_OPEN, h, 0, 0);
    pk_handle(f, id, h);
    return;
  }
  case SFTP_OPENDIR: {
    char h[16];
    (void)sd_rd_string(&rd, 4096);
    _snprintf_s(h, sizeof(h), _TRUNCATE, "d%u", stream);
    tr_add(sv, stream, TR_OPENDIR, h, 0, 0);
    pk_handle(f, id, h);
    return;
  }
  case SFTP_READDIR:
    pk_status(f, id, SFTP_FX_EOF, "End of file");
    return;
  case SFTP_FSTAT: {
    sd_span h = sd_rd_string(&rd, 256);
    tr_add_span(sv, stream, TR_FSTAT, h, 0, 0);
    st_attrs(sv, id, 0100644, ST_SIZE);
    return;
  }
  case SFTP_FSETSTAT: {
    sd_span h = sd_rd_string(&rd, 256);
    tr_add_span(sv, stream, TR_FSETSTAT, h, 0, 0);
    pk_status(f, id, SFTP_FX_OK, "");
    return;
  }
  case SFTP_CLOSE: {
    sd_span h = sd_rd_string(&rd, 256);
    tr_add_span(sv, stream, TR_CLOSE, h, 0, 0);
    pk_status(f, id, SFTP_FX_OK, "");
    return;
  }
  case SFTP_READ: {
    sd_span h = sd_rd_string(&rd, 256);
    uint64_t off = sd_rd_u64(&rd);
    uint32_t len = sd_rd_u32(&rd);
    sd_wr w;
    uint32_t k;
    tr_add_span(sv, stream, TR_READ, h, off, len);
    if (sv->hold_read > 0) {
      InterlockedDecrement(&sv->hold_read);
      st_hold(sv, stream, id, TR_READ, off, len);
      return;
    }
    if (off >= ST_SIZE) { pk_status(f, id, SFTP_FX_EOF, "EOF"); return; }
    if (len > ST_SIZE - off) len = (uint32_t)(ST_SIZE - off);
    pk_begin(&w, SFTP_DATA, id);
    sd_wr_u32(&w, len);
    for (k = 0; k < len; k++) sd_wr_u8(&w, pat(off + k));
    fake_reply_wr(f, &w);
    return;
  }
  case SFTP_WRITE: {
    sd_span h = sd_rd_string(&rd, 256);
    uint64_t off = sd_rd_u64(&rd);
    sd_span d = sd_rd_string(&rd, 1u << 20);
    tr_add_span(sv, stream, TR_WRITE, h, off, (uint32_t)d.n);
    if (sv->hold_write > 0) {
      InterlockedDecrement(&sv->hold_write);
      st_hold(sv, stream, id, TR_WRITE, off, (uint32_t)d.n);
      return;
    }
    if (off + d.n <= ST_SIZE && sv->wdata) memcpy(sv->wdata + off, d.p, d.n);
    if (off + d.n > sv->wlen) sv->wlen = off + d.n;
    pk_status(f, id, SFTP_FX_OK, "");
    return;
  }
  default:
    pk_status(f, id, SFTP_FX_OP_UNSUPPORTED, "unsupported in fake");
  }
}

/* ---- fixture ---- */

typedef struct xf { xsrv sv; sd_sftp_session *s; evlog ev; } xf;

/* The pool admission starts right after the READY_INFO event, so a round trip is the cheapest
   barrier that guarantees the member streams finished opening (the fake's I/O thread processes its
   queue in order). */
static int xf_settle(xf *x)
{
  waiter w;
  sd_sftp_reqopt o = { 0, 5000, NULL };
  int ok;
  waiter_init(&w, x->s);
  waiter_reset(&w, W_STAT);
  ok = sd_sftp_stat(x->s, "/home/u", &o, waiter_cb, &w) == SD_OK && waiter_wait(&w, 5000) && w.err == SD_OK;
  waiter_free(&w);
  return ok;
}

static xf *xf_new(uint32_t connections)
{
  xf *x = (xf *)sd_calloc(1, sizeof(*x));
  sd_sftp_transport t;
  sd_sftp_options o;
  if (!x) return NULL;
  sd_mutex_init(&x->sv.lock);
  evlog_init(&x->ev);
  x->sv.wdata = (uint8_t *)sd_calloc(1, ST_SIZE);
  x->sv.f = fake_new(st_handler, &x->sv);
  if (!x->sv.wdata || !x->sv.f) return NULL;
  sd_sftp_options_init(&o);
  o.connections = connections;
  o.stripe_bytes = ST_UNIT;
  o.default_timeout_ms = 5000;
  fake_set_pool(x->sv.f, connections);
  fake_transport(x->sv.f, &t);
  if (sd_sftp_session_create_transport(&t, &o, evlog_cb, &x->ev, &x->s) != SD_OK) {
    fake_free_if_unused(x->sv.f);
    return NULL;
  }
  fake_set_session(x->sv.f, x->s);
  if (sd_sftp_session_start(x->s) != SD_OK) return NULL;
  if (sd_event_wait(&x->ev.ready, 5000) != SD_OK) return NULL;
  if (sd_sftp_session_state(x->s) != SD_SFTP_ST_READY) return NULL;
  if (!xf_settle(x)) return NULL;
  return x;
}

/* Frees the fixture; the caller frees the struct itself (as in test_session.c). */
static void xf_stop(xf *x)
{
  if (x->s) {
    (void)sd_sftp_session_close(x->s);
    (void)sd_event_wait(&x->ev.ended, 5000);
    if (sd_sftp_session_state(x->s) != SD_SFTP_ST_CLOSED) {
      sd_event_reset(&x->ev.ended);
      (void)sd_event_wait(&x->ev.ended, 2000);
    }
    sd_sftp_session_destroy(x->s);
  }
  evlog_free(&x->ev);
  sd_mutex_destroy(&x->sv.lock);
  sd_free(x->sv.wdata);
}

static sd_sftp_file *xf_open_striped(xf *x, uint32_t flags)
{
  waiter w;
  sd_sftp_reqopt o = { 0, 5000, NULL };
  sd_sftp_file *f = NULL;
  waiter_init(&w, x->s);
  waiter_reset(&w, W_OPEN);
  if (sd_sftp_open(x->s, "/striped", SD_SFTP_O_STRIPED | flags, NULL, NULL, &o, waiter_cb, &w) == SD_OK &&
      waiter_wait(&w, 5000) && w.err == SD_OK)
    f = w.file;
  waiter_free(&w);
  return f;
}

static int wait_held(xf *x, LONG n, uint32_t ms)
{
  uint64_t end = sd_tick_ms() + ms;
  for (;;) {
    if (st_held_count(&x->sv) >= n) return 1;
    if (sd_tick_ms() >= end) return 0;
    Sleep(5);
  }
}

/* Drops one member channel and waits until the fake's I/O thread ran the resulting on_closed (and
   the session's member_lost behind it): both are posted functions, processed in order. */
static sd_event g_probe;
static int g_probe_ready;

static void st_probe_mark(void *arg) { SD_UNUSED(arg); sd_event_set(&g_probe); }

static void drop_member_wait(fake_srv *f, uint32_t member)
{
  if (!g_probe_ready) { (void)sd_event_init(&g_probe, 1, 0); g_probe_ready = 1; }
  sd_event_reset(&g_probe);
  fake_drop_member(f, member);
  fake_run(f, st_probe_mark, NULL);
  (void)sd_event_wait(&g_probe, 3000);
}

/* ---- striped routing ---- */

SD_TEST(striping_units_route_by_member_in_order)
{
  xf *x = xf_new(3);
  waiter w;
  sd_sftp_reqopt o = { 0, 5000, NULL };
  sd_sftp_file *f;
  uint8_t *buf = (uint8_t *)sd_alloc(8 * ST_UNIT);
  tr_ev ev[TR_MAX];
  LONG n;
  int i, ok = 1;
  uint64_t last[4];
  int seen[4];
  SD_REQUIRE(x != NULL && buf != NULL);
  f = xf_open_striped(x, SD_SFTP_O_READ);
  SD_REQUIRE(f != NULL);
  waiter_init(&w, x->s);
  waiter_reset(&w, W_RW);
  SD_REQUIRE(sd_sftp_read(f, 0, buf, 8 * ST_UNIT, &o, waiter_cb, &w) == SD_OK);
  SD_REQUIRE(waiter_wait(&w, 5000));
  SD_CHECK_EQ_INT(w.err, SD_OK);
  SD_CHECK_EQ_U64(w.bytes, 8 * ST_UNIT);
  for (i = 0; i < (int)(8 * ST_UNIT) && ok; i++) ok = buf[i] == pat((uint64_t)i);
  SD_CHECK(ok);

  n = tr_snapshot(&x->sv, ev, TR_MAX);
  SD_CHECK_EQ_INT(tr_n(ev, n, TR_READ, 0), 8);
  /* unit k = off / stripe_bytes goes to route_map[k % 3] = k % 3 (0 = primary, 1..2 = members) */
  for (i = 0; i < 8; i++) {
    const tr_ev *r = tr_off(ev, n, TR_READ, (uint64_t)i * ST_UNIT);
    char want[16];
    SD_REQUIRE(r != NULL);
    SD_CHECK_EQ_INT(r->stream, 1 + (i % 3));
    _snprintf_s(want, sizeof(want), _TRUNCATE, "h%u", (unsigned)r->stream);
    SD_CHECK_STR(r->handle, want);       /* the piece used the handle opened on that stream */
  }
  /* per stream the units arrive in submission order */
  memset(last, 0, sizeof(last));
  memset(seen, 0, sizeof(seen));
  for (i = 0; i < (int)n; i++) {
    uint32_t s = ev[i].stream;
    if (ev[i].type != TR_READ || s > 3) continue;
    if (seen[s]) SD_CHECK(ev[i].off > last[s]);
    last[s] = ev[i].off;
    seen[s] = 1;
  }
  /* one sub-handle per member, opened on its own stream */
  SD_CHECK_EQ_INT(tr_n(ev, n, TR_OPEN, 1), 1);
  SD_CHECK_EQ_INT(tr_n(ev, n, TR_OPEN, 2), 1);
  SD_CHECK_EQ_INT(tr_n(ev, n, TR_OPEN, 3), 1);
  {
    sd_sftp_stats st;
    SD_CHECK(sd_sftp_session_stats(x->s, &st) == SD_OK);
    SD_CHECK_EQ_INT(st.conn_count, 3);
    SD_CHECK(st.conn[1].ready && st.conn[2].ready);
    SD_CHECK(st.conn[1].rx_total > 0 && st.conn[2].rx_total > 0);
    SD_CHECK(st.total.rx_total >= st.conn[1].rx_total + st.conn[2].rx_total);
  }
  sd_sftp_file_release(f);
  waiter_free(&w);
  xf_stop(x);
  sd_free(buf);
  sd_free(x);
}

SD_TEST(striping_sub_handles_open_lazily)
{
  xf *x = xf_new(3);
  waiter w;
  sd_sftp_reqopt o = { 0, 5000, NULL };
  sd_sftp_file *f;
  uint8_t buf[ST_UNIT];
  SD_REQUIRE(x != NULL);
  f = xf_open_striped(x, SD_SFTP_O_READ);
  SD_REQUIRE(f != NULL);
  waiter_init(&w, x->s);

  /* a unit on the primary opens no member stream at all */
  waiter_reset(&w, W_RW);
  SD_REQUIRE(sd_sftp_read(f, 0, buf, ST_UNIT, &o, waiter_cb, &w) == SD_OK);
  SD_REQUIRE(waiter_wait(&w, 5000) && w.err == SD_OK);
  SD_CHECK_EQ_INT(fake_stream_packets(x->sv.f, 2), 0);
  SD_CHECK_EQ_INT(fake_stream_packets(x->sv.f, 3), 0);

  /* member 1's first unit opens its sub-handle (OPEN + FSTAT + READ); member 2 stays untouched */
  waiter_reset(&w, W_RW);
  SD_REQUIRE(sd_sftp_read(f, ST_UNIT, buf, ST_UNIT, &o, waiter_cb, &w) == SD_OK);
  SD_REQUIRE(waiter_wait(&w, 5000) && w.err == SD_OK);
  SD_CHECK(fake_stream_packets(x->sv.f, 2) >= 3);
  SD_CHECK_EQ_INT(fake_stream_packets(x->sv.f, 3), 0);
  SD_CHECK_EQ_INT(buf[0], pat(ST_UNIT));

  /* member 2 opens on its own first unit */
  waiter_reset(&w, W_RW);
  SD_REQUIRE(sd_sftp_read(f, 2 * ST_UNIT, buf, ST_UNIT, &o, waiter_cb, &w) == SD_OK);
  SD_REQUIRE(waiter_wait(&w, 5000) && w.err == SD_OK);
  SD_CHECK(fake_stream_packets(x->sv.f, 3) >= 3);
  SD_CHECK_EQ_INT(buf[0], pat(2 * ST_UNIT));

  sd_sftp_file_release(f);
  waiter_free(&w);
  xf_stop(x);
  sd_free(x);
}

/* ---- barriers ---- */

SD_TEST(striping_barrier_waits_for_data_wires)
{
  xf *x = xf_new(3);
  waiter w, wf, ws;
  sd_sftp_reqopt o = { 0, 5000, NULL };
  sd_sftp_file *f;
  sd_sftp_attrs a;
  uint8_t *buf = (uint8_t *)sd_alloc(3 * ST_UNIT);
  tr_ev ev[TR_MAX];
  LONG n;
  int base;
  SD_REQUIRE(x != NULL && buf != NULL);
  f = xf_open_striped(x, SD_SFTP_O_READ);
  SD_REQUIRE(f != NULL);
  waiter_init(&w, x->s);
  waiter_init(&wf, x->s);
  waiter_init(&ws, x->s);

  InterlockedExchange(&x->sv.hold_read, 3);
  waiter_reset(&w, W_RW);
  SD_REQUIRE(sd_sftp_read(f, 0, buf, 3 * ST_UNIT, &o, waiter_cb, &w) == SD_OK);
  SD_REQUIRE(wait_held(x, 3, 5000));

  /* the handle's own open already sent one FSTAT on the primary handle */
  n = tr_snapshot(&x->sv, ev, TR_MAX);
  base = tr_n(ev, n, TR_FSTAT, 1);
  SD_CHECK_EQ_INT(base, 1);
  SD_CHECK_EQ_INT(tr_n(ev, n, TR_FSETSTAT, 1), 0);
  SD_CHECK_EQ_INT(tr_n(ev, n, TR_FSTAT, 2), 1);      /* the sub-handle opens */
  SD_CHECK_EQ_INT(tr_n(ev, n, TR_FSTAT, 3), 1);

  /* FSTAT and FSETSTAT wait for the handle's outstanding data wires */
  waiter_reset(&wf, W_STAT);
  SD_REQUIRE(sd_sftp_fstat(f, &o, waiter_cb, &wf) == SD_OK);
  memset(&a, 0, sizeof(a));
  a.valid = SD_SFTP_ATTR_PERM;
  a.perm = 0600;
  waiter_reset(&ws, W_STAT);
  SD_REQUIRE(sd_sftp_fsetstat(f, &a, &o, waiter_cb, &ws) == SD_OK);
  SD_CHECK(!waiter_wait(&wf, 150));
  SD_CHECK(!waiter_wait(&ws, 150));
  n = tr_snapshot(&x->sv, ev, TR_MAX);
  SD_CHECK_EQ_INT(tr_n(ev, n, TR_FSTAT, 1), base);   /* no barrier on the primary yet */
  SD_CHECK_EQ_INT(tr_n(ev, n, TR_FSETSTAT, 1), 0);

  /* drained: the read completes and both barriers run on the primary handle */
  fake_run(x->sv.f, st_release_held, &x->sv);
  SD_REQUIRE(waiter_wait(&w, 5000));
  SD_CHECK_EQ_INT(w.err, SD_OK);
  SD_CHECK_EQ_U64(w.bytes, 3 * ST_UNIT);
  SD_REQUIRE(waiter_wait(&wf, 5000));
  SD_CHECK_EQ_INT(wf.err, SD_OK);
  SD_REQUIRE(waiter_wait(&ws, 5000));
  SD_CHECK_EQ_INT(ws.err, SD_OK);
  n = tr_snapshot(&x->sv, ev, TR_MAX);
  SD_CHECK_EQ_INT(tr_n(ev, n, TR_FSTAT, 1), base + 1);
  SD_CHECK_EQ_INT(tr_n(ev, n, TR_FSETSTAT, 1), 1);
  {
    const tr_ev *r = tr_at(ev, n, TR_FSTAT, 1, 1);   /* the barrier wire, after the open's */
    SD_REQUIRE(r != NULL);
    SD_CHECK_STR(r->handle, "h1");
  }
  /* the primary of a striped handle carries FSTAT/FSETSTAT: the sub-handles saw none */
  SD_CHECK_EQ_INT(tr_n(ev, n, TR_FSTAT, 2), 1);
  SD_CHECK_EQ_INT(tr_n(ev, n, TR_FSTAT, 3), 1);
  SD_CHECK_EQ_INT(tr_n(ev, n, TR_FSETSTAT, 2), 0);
  SD_CHECK_EQ_INT(tr_n(ev, n, TR_FSETSTAT, 3), 0);

  sd_sftp_file_release(f);
  waiter_free(&w);
  waiter_free(&wf);
  waiter_free(&ws);
  xf_stop(x);
  sd_free(buf);
  sd_free(x);
}

SD_TEST(striping_fsync_settles_on_every_sub_handle)
{
  xf *x = xf_new(3);
  waiter w;
  sd_sftp_reqopt o = { 0, 5000, NULL };
  sd_sftp_file *f;
  uint8_t *buf = (uint8_t *)sd_alloc(3 * ST_UNIT);
  tr_ev ev[TR_MAX];
  LONG n;
  SD_REQUIRE(x != NULL && buf != NULL);
  f = xf_open_striped(x, SD_SFTP_O_READ | SD_SFTP_O_WRITE);
  SD_REQUIRE(f != NULL);
  waiter_init(&w, x->s);
  /* one unit per member first, so both sub-handles are open */
  waiter_reset(&w, W_RW);
  SD_REQUIRE(sd_sftp_read(f, 0, buf, 3 * ST_UNIT, &o, waiter_cb, &w) == SD_OK);
  SD_REQUIRE(waiter_wait(&w, 5000) && w.err == SD_OK);

  /* fsync waits the same way and settles on the primary and on every open sub-handle */
  waiter_reset(&w, W_STAT);
  SD_REQUIRE(sd_sftp_fsync(f, &o, waiter_cb, &w) == SD_OK);
  SD_REQUIRE(waiter_wait(&w, 5000));
  SD_CHECK_EQ_INT(w.err, SD_OK);
  n = tr_snapshot(&x->sv, ev, TR_MAX);
  SD_CHECK_EQ_INT(tr_n(ev, n, TR_FSYNC, 1), 1);
  SD_CHECK_EQ_INT(tr_n(ev, n, TR_FSYNC, 2), 1);
  SD_CHECK_EQ_INT(tr_n(ev, n, TR_FSYNC, 3), 1);
  {
    const tr_ev *r = tr_at(ev, n, TR_FSYNC, 2, 0);
    SD_REQUIRE(r != NULL);
    SD_CHECK_STR(r->handle, "h2");     /* the member's own sub-handle */
  }

  /* an error on one sub-handle surfaces in the barrier's completion, after every wire settled */
  InterlockedExchange(&x->sv.fail_fsync_stream, 2);
  waiter_reset(&w, W_STAT);
  SD_REQUIRE(sd_sftp_fsync(f, &o, waiter_cb, &w) == SD_OK);
  SD_REQUIRE(waiter_wait(&w, 5000));
  SD_CHECK_EQ_INT(w.err, SD_E_FAILURE);
  n = tr_snapshot(&x->sv, ev, TR_MAX);
  SD_CHECK_EQ_INT(tr_n(ev, n, TR_FSYNC, 1), 2);
  SD_CHECK_EQ_INT(tr_n(ev, n, TR_FSYNC, 2), 2);
  SD_CHECK_EQ_INT(tr_n(ev, n, TR_FSYNC, 3), 2);
  InterlockedExchange(&x->sv.fail_fsync_stream, 0);

  sd_sftp_file_release(f);
  waiter_free(&w);
  xf_stop(x);
  sd_free(buf);
  sd_free(x);
}

SD_TEST(striping_close_settles_on_every_sub_handle)
{
  xf *x = xf_new(3);
  waiter w;
  sd_sftp_reqopt o = { 0, 5000, NULL };
  sd_sftp_file *f;
  uint8_t *buf = (uint8_t *)sd_alloc(3 * ST_UNIT);
  tr_ev ev[TR_MAX];
  LONG n;
  SD_REQUIRE(x != NULL && buf != NULL);
  f = xf_open_striped(x, SD_SFTP_O_READ | SD_SFTP_O_WRITE);
  SD_REQUIRE(f != NULL);
  waiter_init(&w, x->s);
  waiter_reset(&w, W_RW);
  SD_REQUIRE(sd_sftp_read(f, 0, buf, 3 * ST_UNIT, &o, waiter_cb, &w) == SD_OK);
  SD_REQUIRE(waiter_wait(&w, 5000) && w.err == SD_OK);

  waiter_reset(&w, W_STAT);
  SD_REQUIRE(sd_sftp_close(f, &o, waiter_cb, &w) == SD_OK);   /* releases the caller's reference */
  SD_REQUIRE(waiter_wait(&w, 5000));
  SD_CHECK_EQ_INT(w.err, SD_OK);
  n = tr_snapshot(&x->sv, ev, TR_MAX);
  SD_CHECK_EQ_INT(tr_n(ev, n, TR_CLOSE, 1), 1);     /* the primary handle */
  SD_CHECK_EQ_INT(tr_n(ev, n, TR_CLOSE, 2), 1);     /* member 1's sub-handle */
  SD_CHECK_EQ_INT(tr_n(ev, n, TR_CLOSE, 3), 1);     /* member 2's sub-handle */
  SD_CHECK_EQ_INT(sd_sftp_session_state(x->s), SD_SFTP_ST_READY);
  waiter_free(&w);
  xf_stop(x);
  sd_free(buf);
  sd_free(x);
}

/* ---- member loss ---- */

SD_TEST(striping_member_loss_reissues_reads_on_primary)
{
  xf *x = xf_new(3);
  waiter w;
  sd_sftp_reqopt o = { 0, 5000, NULL };
  sd_sftp_file *f, *f2;
  uint8_t *buf = (uint8_t *)sd_alloc(3 * ST_UNIT);
  uint8_t *buf2 = (uint8_t *)sd_alloc(2 * ST_UNIT);
  tr_ev ev[TR_MAX];
  LONG n;
  int i, ok = 1;
  SD_REQUIRE(x != NULL && buf != NULL && buf2 != NULL);
  f = xf_open_striped(x, SD_SFTP_O_READ);
  SD_REQUIRE(f != NULL);
  waiter_init(&w, x->s);

  InterlockedExchange(&x->sv.hold_read, 3);
  waiter_reset(&w, W_RW);
  SD_REQUIRE(sd_sftp_read(f, 0, buf, 3 * ST_UNIT, &o, waiter_cb, &w) == SD_OK);
  SD_REQUIRE(wait_held(x, 3, 5000));               /* units 0..2 are in flight on streams 1..3 */
  InterlockedExchange(&x->sv.hold_read, 0);
  drop_member_wait(x->sv.f, 1);                    /* member 1 dies mid-flight */
  fake_run(x->sv.f, st_release_held, &x->sv);      /* the primary's and member 2's replies */

  SD_REQUIRE(waiter_wait(&w, 5000));
  SD_CHECK_EQ_INT(w.err, SD_OK);                   /* the re-issued unit completed on the primary */
  SD_CHECK_EQ_U64(w.bytes, 3 * ST_UNIT);
  for (i = 0; i < (int)(3 * ST_UNIT) && ok; i++) ok = buf[i] == pat((uint64_t)i);
  SD_CHECK(ok);
  n = tr_snapshot(&x->sv, ev, TR_MAX);
  SD_CHECK(tr_off_s(ev, n, TR_READ, 2, ST_UNIT) != NULL);   /* first attempt on member 1 */
  SD_CHECK(tr_off_s(ev, n, TR_READ, 1, ST_UNIT) != NULL);   /* re-issued on the primary */
  SD_CHECK_EQ_INT(sd_sftp_session_state(x->s), SD_SFTP_ST_READY);

  /* the session stays usable: a later striped open and IO still work */
  f2 = xf_open_striped(x, SD_SFTP_O_READ);
  SD_REQUIRE(f2 != NULL);
  waiter_reset(&w, W_RW);
  SD_REQUIRE(sd_sftp_read(f2, 0, buf2, 2 * ST_UNIT, &o, waiter_cb, &w) == SD_OK);
  SD_REQUIRE(waiter_wait(&w, 5000));
  SD_CHECK_EQ_INT(w.err, SD_OK);
  ok = 1;
  for (i = 0; i < (int)(2 * ST_UNIT) && ok; i++) ok = buf2[i] == pat((uint64_t)i);
  SD_CHECK(ok);

  sd_sftp_file_release(f2);
  sd_sftp_file_release(f);
  waiter_free(&w);
  xf_stop(x);
  sd_free(buf);
  sd_free(buf2);
  sd_free(x);
}

SD_TEST(striping_member_loss_fails_writes_with_session_ready)
{
  xf *x = xf_new(3);
  waiter w;
  sd_sftp_reqopt o = { 0, 5000, NULL };
  sd_sftp_file *f, *f2;
  uint8_t *src = (uint8_t *)sd_alloc(3 * ST_UNIT);
  uint8_t *rbuf = (uint8_t *)sd_alloc(2 * ST_UNIT);
  int i, ok = 1;
  SD_REQUIRE(x != NULL && src != NULL && rbuf != NULL);
  for (i = 0; i < (int)(3 * ST_UNIT); i++) src[i] = pat((uint64_t)i + 5);
  f = xf_open_striped(x, SD_SFTP_O_READ | SD_SFTP_O_WRITE);
  SD_REQUIRE(f != NULL);
  waiter_init(&w, x->s);

  InterlockedExchange(&x->sv.hold_write, 3);
  waiter_reset(&w, W_RW);
  SD_REQUIRE(sd_sftp_write(f, 0, src, 3 * ST_UNIT, &o, waiter_cb, &w) == SD_OK);
  SD_REQUIRE(wait_held(x, 3, 5000));
  InterlockedExchange(&x->sv.hold_write, 0);
  drop_member_wait(x->sv.f, 1);

  SD_REQUIRE(waiter_wait(&w, 5000));
  SD_CHECK_EQ_INT(w.err, SD_E_DISCONNECTED);
  SD_CHECK_EQ_INT(w.maybe_executed, 1);
  SD_CHECK_EQ_INT(w.session_ready, 1);             /* the VFS resubmits it at once */
  SD_CHECK_EQ_INT(sd_sftp_session_state(x->s), SD_SFTP_ST_READY);

  /* the session stays usable: a later striped open and IO still work */
  f2 = xf_open_striped(x, SD_SFTP_O_READ);
  SD_REQUIRE(f2 != NULL);
  waiter_reset(&w, W_RW);
  SD_REQUIRE(sd_sftp_read(f2, 0, rbuf, 2 * ST_UNIT, &o, waiter_cb, &w) == SD_OK);
  SD_REQUIRE(waiter_wait(&w, 5000));
  SD_CHECK_EQ_INT(w.err, SD_OK);
  ok = 1;
  for (i = 0; i < (int)(2 * ST_UNIT) && ok; i++) ok = rbuf[i] == pat((uint64_t)i);
  SD_CHECK(ok);

  sd_sftp_file_release(f2);
  sd_sftp_file_release(f);
  waiter_free(&w);
  xf_stop(x);
  sd_free(src);
  sd_free(rbuf);
  sd_free(x);
}

SD_TEST(striping_route_recomputed_after_member_loss)
{
  xf *x = xf_new(3);
  waiter w;
  sd_sftp_reqopt o = { 0, 5000, NULL };
  sd_sftp_file *f;
  uint8_t *buf = (uint8_t *)sd_alloc(4 * ST_UNIT);
  tr_ev ev[TR_MAX];
  LONG n;
  int i, ok = 1;
  SD_REQUIRE(x != NULL && buf != NULL);
  f = xf_open_striped(x, SD_SFTP_O_READ);
  SD_REQUIRE(f != NULL);
  waiter_init(&w, x->s);
  /* unit k lands on member k % 3, so both sub-handles open */
  waiter_reset(&w, W_RW);
  SD_REQUIRE(sd_sftp_read(f, 0, buf, 3 * ST_UNIT, &o, waiter_cb, &w) == SD_OK);
  SD_REQUIRE(waiter_wait(&w, 5000) && w.err == SD_OK);
  drop_member_wait(x->sv.f, 1);

  /* the barrier is the quiescent point that recomputes the route table: route_map = {0, 2} */
  waiter_reset(&w, W_STAT);
  SD_REQUIRE(sd_sftp_fstat(f, &o, waiter_cb, &w) == SD_OK);
  SD_REQUIRE(waiter_wait(&w, 5000));
  SD_CHECK_EQ_INT(w.err, SD_OK);

  /* later units re-route among the live members only */
  waiter_reset(&w, W_RW);
  SD_REQUIRE(sd_sftp_read(f, 64 * ST_UNIT, buf, 4 * ST_UNIT, &o, waiter_cb, &w) == SD_OK);
  SD_REQUIRE(waiter_wait(&w, 5000));
  SD_CHECK_EQ_INT(w.err, SD_OK);
  for (i = 0; i < (int)(4 * ST_UNIT) && ok; i++) ok = buf[i] == pat(64 * ST_UNIT + (uint64_t)i);
  SD_CHECK(ok);
  n = tr_snapshot(&x->sv, ev, TR_MAX);
  for (i = 0; i < 4; i++)
    SD_CHECK(tr_off_s(ev, n, TR_READ, (i % 2) ? 3 : 1, (64 + (uint64_t)i) * ST_UNIT) != NULL);
  /* member 1 saw its one unit before the drop and nothing afterwards */
  SD_CHECK_EQ_INT(tr_n(ev, n, TR_READ, 2), 1);

  sd_sftp_file_release(f);
  waiter_free(&w);
  xf_stop(x);
  sd_free(buf);
  sd_free(x);
}

/* ---- regressions: nothing else touches a member stream ---- */

SD_TEST(striping_plain_and_append_handles_stay_off_members)
{
  xf *x = xf_new(3);
  waiter w;
  sd_sftp_reqopt o = { 0, 5000, NULL };
  sd_sftp_file *f, *fa;
  uint8_t *buf = (uint8_t *)sd_alloc(3 * ST_UNIT);
  uint32_t b1, b2, b3, a2, a3;
  SD_REQUIRE(x != NULL && buf != NULL);
  waiter_init(&w, x->s);

  /* a plain handle (no SD_SFTP_O_STRIPED): OPEN and READ on the primary bulk stream */
  b1 = fake_stream_packets(x->sv.f, 1);
  b2 = fake_stream_packets(x->sv.f, 2);
  b3 = fake_stream_packets(x->sv.f, 3);
  waiter_reset(&w, W_OPEN);
  SD_REQUIRE(sd_sftp_open(x->s, "/plain", SD_SFTP_O_READ, NULL, NULL, &o, waiter_cb, &w) == SD_OK);
  SD_REQUIRE(waiter_wait(&w, 5000) && w.err == SD_OK && w.file != NULL);
  f = w.file;
  waiter_reset(&w, W_RW);
  SD_REQUIRE(sd_sftp_read(f, 0, buf, 3 * ST_UNIT, &o, waiter_cb, &w) == SD_OK);
  SD_REQUIRE(waiter_wait(&w, 5000) && w.err == SD_OK);
  SD_CHECK(fake_stream_packets(x->sv.f, 1) > b1);
  SD_CHECK_EQ_INT(fake_stream_packets(x->sv.f, 2), b2);
  SD_CHECK_EQ_INT(fake_stream_packets(x->sv.f, 3), b3);

  /* APPEND is never striped, even with the bit set */
  a2 = fake_stream_packets(x->sv.f, 2);
  a3 = fake_stream_packets(x->sv.f, 3);
  waiter_reset(&w, W_OPEN);
  SD_REQUIRE(sd_sftp_open(x->s, "/append",
                          SD_SFTP_O_WRITE | SD_SFTP_O_APPEND | SD_SFTP_O_CREAT | SD_SFTP_O_STRIPED,
                          NULL, NULL, &o, waiter_cb, &w) == SD_OK);
  SD_REQUIRE(waiter_wait(&w, 5000) && w.err == SD_OK && w.file != NULL);
  fa = w.file;
  waiter_reset(&w, W_RW);
  SD_REQUIRE(sd_sftp_write(fa, 0, buf, 3 * ST_UNIT, &o, waiter_cb, &w) == SD_OK);
  SD_REQUIRE(waiter_wait(&w, 5000) && w.err == SD_OK);
  SD_CHECK_EQ_INT(fake_stream_packets(x->sv.f, 2), a2);
  SD_CHECK_EQ_INT(fake_stream_packets(x->sv.f, 3), a3);

  sd_sftp_file_release(f);
  sd_sftp_file_release(fa);
  waiter_free(&w);
  xf_stop(x);
  sd_free(buf);
  sd_free(x);
}

SD_TEST(striping_meta_and_directory_handles_stay_off_members)
{
  xf *x = xf_new(3);
  waiter w;
  sd_sftp_reqopt o = { 0, 5000, NULL };
  sd_sftp_reqopt meta = { SD_SFTP_REQ_CLASS_META, 5000, NULL };
  sd_sftp_file *fm, *d;
  uint8_t buf[ST_UNIT];
  uint32_t m1, m2, m3, d2, d3;
  SD_REQUIRE(x != NULL);
  waiter_init(&w, x->s);

  /* a CLASS_META handle keeps the striped bit out of the routing: everything stays on meta */
  m1 = fake_stream_packets(x->sv.f, 1);
  m2 = fake_stream_packets(x->sv.f, 2);
  m3 = fake_stream_packets(x->sv.f, 3);
  waiter_reset(&w, W_OPEN);
  SD_REQUIRE(sd_sftp_open(x->s, "/meta", SD_SFTP_O_READ | SD_SFTP_O_STRIPED, NULL, NULL, &meta,
                          waiter_cb, &w) == SD_OK);
  SD_REQUIRE(waiter_wait(&w, 5000) && w.err == SD_OK && w.file != NULL);
  fm = w.file;
  waiter_reset(&w, W_RW);
  SD_REQUIRE(sd_sftp_read(fm, 0, buf, ST_UNIT, &meta, waiter_cb, &w) == SD_OK);
  SD_REQUIRE(waiter_wait(&w, 5000) && w.err == SD_OK);
  SD_CHECK_EQ_INT(fake_stream_packets(x->sv.f, 1), m1);
  SD_CHECK_EQ_INT(fake_stream_packets(x->sv.f, 2), m2);
  SD_CHECK_EQ_INT(fake_stream_packets(x->sv.f, 3), m3);

  /* directories are never striped */
  d2 = fake_stream_packets(x->sv.f, 2);
  d3 = fake_stream_packets(x->sv.f, 3);
  waiter_reset(&w, W_OPEN);
  SD_REQUIRE(sd_sftp_opendir(x->s, "/dir", &o, waiter_cb, &w) == SD_OK);
  SD_REQUIRE(waiter_wait(&w, 5000) && w.err == SD_OK && w.file != NULL);
  d = w.file;
  waiter_reset(&w, W_DIR);
  SD_REQUIRE(sd_sftp_readdir(d, &o, waiter_cb, &w) == SD_OK);
  SD_REQUIRE(waiter_wait(&w, 5000));
  SD_CHECK_EQ_INT(w.err, SD_OK);
  SD_CHECK_EQ_INT(fake_stream_packets(x->sv.f, 2), d2);
  SD_CHECK_EQ_INT(fake_stream_packets(x->sv.f, 3), d3);

  sd_sftp_file_release(fm);
  sd_sftp_file_release(d);
  waiter_free(&w);
  xf_stop(x);
  sd_free(x);
}

SD_TEST(striping_transport_without_members_never_stripes)
{
  /* a pool transport with a single connection admits no member: a striped handle degrades to the
     primary bulk channel (route_n stays 1). */
  xf *x = xf_new(1);
  waiter w;
  sd_sftp_reqopt o = { 0, 5000, NULL };
  sd_sftp_file *f;
  uint8_t *buf = (uint8_t *)sd_alloc(3 * ST_UNIT);
  tr_ev ev[TR_MAX];
  LONG n;
  int i, ok = 1;
  SD_REQUIRE(x != NULL && buf != NULL);
  f = xf_open_striped(x, SD_SFTP_O_READ);
  SD_REQUIRE(f != NULL);
  waiter_init(&w, x->s);
  waiter_reset(&w, W_RW);
  SD_REQUIRE(sd_sftp_read(f, 0, buf, 3 * ST_UNIT, &o, waiter_cb, &w) == SD_OK);
  SD_REQUIRE(waiter_wait(&w, 5000));
  SD_CHECK_EQ_INT(w.err, SD_OK);
  for (i = 0; i < (int)(3 * ST_UNIT) && ok; i++) ok = buf[i] == pat((uint64_t)i);
  SD_CHECK(ok);
  n = tr_snapshot(&x->sv, ev, TR_MAX);
  SD_CHECK_EQ_INT(tr_n(ev, n, TR_READ, 1), 3);     /* every unit on the primary bulk stream */
  SD_CHECK_EQ_INT(tr_n(ev, n, TR_READ, 2), 0);
  SD_CHECK_EQ_INT(tr_n(ev, n, TR_READ, 3), 0);
  {
    sd_sftp_stats st;
    SD_CHECK(sd_sftp_session_stats(x->s, &st) == SD_OK);
    SD_CHECK_EQ_INT(st.conn_count, 1);
  }
  sd_sftp_file_release(f);
  waiter_free(&w);
  xf_stop(x);
  sd_free(buf);
  sd_free(x);
}