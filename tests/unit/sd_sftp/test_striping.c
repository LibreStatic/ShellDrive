/* Pool striping (01 §10.9, increment 2) against the extended scripted fake transport (no SSH, no
 * network). The fake projects members 1..3 onto streams 2..4, so a session with connections = 3
 * admits two members and a handle opened with SD_SFTP_O_STRIPED routes its stripe units over them.
 *
 * Covered: unit k goes to route_map[k % route_n] in submission order and sub-handles open lazily
 * (read and write routing with byte placement through each member's own sub-handle); a member whose
 * sub-handle OPEN is refused falls back to the primary at once; FSTAT/FSETSTAT barriers wait for
 * the handle's outstanding data wires and run on the primary handle, FSYNC/CLOSE wait the same way
 * and also settle on every open sub-handle (the first error wins), and a member dying with its
 * barrier wire in flight counts that wire as done; emit_piece's limits park the pump when a
 * member's accept window is shut and the write resumes once it reopens; a member lost mid-flight
 * gets its reads re-issued on the primary (with the right bytes) and its writes completed with
 * SD_E_DISCONNECTED / maybe_executed / session_ready while the session stays READY - including a
 * write that fails on the member's stream before the drop report has run; the route table is
 * recomputed at the next barrier; plain, APPEND, CLASS_META and directory handles never touch a
 * member stream. */
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
#define ST_LIMIT ST_CHUNK            /* the fake's negotiated max_read/max_write */
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
  volatile LONG hold_fsync_stream;       /* stream whose FSYNC is held in flight (0: none) */
  volatile LONG fail_open_stream;        /* stream whose SFTP_OPEN replies FAILURE (0: none) */
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
      if (sv->hold_fsync_stream > 0 && sv->hold_fsync_stream == (LONG)stream) {
        st_hold(sv, stream, id, TR_FSYNC, 0, 0);   /* the barrier wire stays in flight */
        return;
      }
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
    if (sv->fail_open_stream > 0 && sv->fail_open_stream == (LONG)stream) {   /* > 0: stream 0 (the
                                                               meta channel) is never refused */
      pk_status(f, id, SFTP_FX_FAILURE, "open refused");
      return;
    }
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

static xf *xf_new_full(uint32_t connections, uint32_t caps, uint32_t stripe_bytes, uint32_t infl_bytes)
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
  o.stripe_bytes = stripe_bytes;
  o.max_inflight_bytes = infl_bytes;           /* 0: the default */
  o.default_timeout_ms = 5000;
  o.reconnect.initial_delay_ms = 20;           /* a fast reconnect for the generation-reset tests */
  o.reconnect.max_delay_ms = 100;
  fake_set_caps(x->sv.f, caps);
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

static xf *xf_new_ex(uint32_t connections, uint32_t caps, uint32_t stripe_bytes)
{
  return xf_new_full(connections, caps, stripe_bytes, 0);
}

static xf *xf_new(uint32_t connections) { return xf_new_ex(connections, 0, ST_UNIT); }

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

/* Blocks until every already-posted item of the fake's I/O thread ran (the probe is queued last). */
static void xf_drain(xf *x)
{
  if (!g_probe_ready) { (void)sd_event_init(&g_probe, 1, 0); g_probe_ready = 1; }
  sd_event_reset(&g_probe);
  fake_run(x->sv.f, st_probe_mark, NULL);
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

/* A member that refuses the sub-handle OPEN (server STATUS error) must not stall the units routed
   to it: they fall back to the primary at once, and the next barrier recomputes the table without
   the member. Regression: the pump used to block on sub_state != SST_OPEN until the deadline. */
SD_TEST(striping_refused_sub_open_falls_back_to_primary)
{
  xf *x = xf_new(3);
  waiter w;
  sd_sftp_reqopt o = { 0, 5000, NULL };
  sd_sftp_file *f;
  uint8_t *buf = (uint8_t *)sd_alloc(3 * ST_UNIT);
  tr_ev ev[TR_MAX];
  LONG n;
  int i, ok = 1;
  SD_REQUIRE(x != NULL && buf != NULL);
  InterlockedExchange(&x->sv.fail_open_stream, 2);   /* member 1 refuses every OPEN */
  f = xf_open_striped(x, SD_SFTP_O_READ);
  SD_REQUIRE(f != NULL);
  waiter_init(&w, x->s);
  waiter_reset(&w, W_RW);
  SD_REQUIRE(sd_sftp_read(f, 0, buf, 3 * ST_UNIT, &o, waiter_cb, &w) == SD_OK);
  SD_REQUIRE(waiter_wait(&w, 5000));
  SD_CHECK_EQ_INT(w.err, SD_OK);                   /* completes, not SD_E_TIMEOUT */
  SD_CHECK_EQ_U64(w.bytes, 3 * ST_UNIT);
  for (i = 0; i < (int)(3 * ST_UNIT) && ok; i++) ok = buf[i] == pat((uint64_t)i);
  SD_CHECK(ok);
  n = tr_snapshot(&x->sv, ev, TR_MAX);
  SD_CHECK_EQ_INT(tr_n(ev, n, TR_OPEN, 2), 1);     /* the refused sub-open attempt */
  SD_CHECK_EQ_INT(tr_n(ev, n, TR_READ, 2), 0);     /* no data was ever sent to member 1 */
  {
    const tr_ev *r = tr_off_s(ev, n, TR_READ, 1, ST_UNIT);
    SD_REQUIRE(r != NULL);                         /* unit 1 ran on the primary instead */
    SD_CHECK_STR(r->handle, "h1");
  }
  SD_CHECK(tr_off_s(ev, n, TR_READ, 3, 2 * ST_UNIT) != NULL);
  SD_CHECK_EQ_INT(sd_sftp_session_state(x->s), SD_SFTP_ST_READY);

  /* the barrier recomputes the route table without the refused member: route_map = {0, 2} */
  waiter_reset(&w, W_STAT);
  SD_REQUIRE(sd_sftp_fstat(f, &o, waiter_cb, &w) == SD_OK);
  SD_REQUIRE(waiter_wait(&w, 5000));
  SD_CHECK_EQ_INT(w.err, SD_OK);
  waiter_reset(&w, W_RW);
  SD_REQUIRE(sd_sftp_read(f, 4 * ST_UNIT, buf, 2 * ST_UNIT, &o, waiter_cb, &w) == SD_OK);
  SD_REQUIRE(waiter_wait(&w, 5000));
  SD_CHECK_EQ_INT(w.err, SD_OK);
  n = tr_snapshot(&x->sv, ev, TR_MAX);
  SD_CHECK(tr_off_s(ev, n, TR_READ, 1, 4 * ST_UNIT) != NULL);
  SD_CHECK(tr_off_s(ev, n, TR_READ, 3, 5 * ST_UNIT) != NULL);
  SD_CHECK_EQ_INT(tr_n(ev, n, TR_READ, 2), 0);

  sd_sftp_file_release(f);
  waiter_free(&w);
  xf_stop(x);
  sd_free(buf);
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

/* ---- striped writes: routing and byte placement ---- */

SD_TEST(striping_write_units_route_and_place_bytes)
{
  xf *x = xf_new(3);
  waiter w;
  sd_sftp_reqopt o = { 0, 5000, NULL };
  sd_sftp_file *f;
  uint8_t *src = (uint8_t *)sd_alloc(4 * ST_UNIT);
  tr_ev ev[TR_MAX];
  LONG n;
  int i, ok = 1;
  SD_REQUIRE(x != NULL && src != NULL);
  for (i = 0; i < (int)(4 * ST_UNIT); i++) src[i] = pat((uint64_t)i + 5);
  f = xf_open_striped(x, SD_SFTP_O_WRITE);
  SD_REQUIRE(f != NULL);
  waiter_init(&w, x->s);
  waiter_reset(&w, W_RW);
  SD_REQUIRE(sd_sftp_write(f, 0, src, 4 * ST_UNIT, &o, waiter_cb, &w) == SD_OK);
  SD_REQUIRE(waiter_wait(&w, 5000));
  SD_CHECK_EQ_INT(w.err, SD_OK);
  SD_CHECK_EQ_U64(w.bytes, 4 * ST_UNIT);

  /* the mirror holds exactly the written bytes: unit k travelled on stream 1 + (k % 3) and the
     pieces were placed at their absolute offsets through each member's own sub-handle */
  n = tr_snapshot(&x->sv, ev, TR_MAX);
  for (i = 0; i < 4; i++) {
    const tr_ev *r = tr_off_s(ev, n, TR_WRITE, (uint32_t)(1 + (i % 3)), (uint64_t)i * ST_UNIT);
    char want[16];
    SD_REQUIRE(r != NULL);
    SD_CHECK_EQ_U64(r->len, ST_UNIT);
    _snprintf_s(want, sizeof(want), _TRUNCATE, "h%u", (unsigned)r->stream);
    SD_CHECK_STR(r->handle, want);
  }
  for (i = 0; i < (int)(4 * ST_UNIT) && ok; i++) ok = x->sv.wdata[i] == src[i];
  SD_CHECK(ok);
  SD_CHECK_EQ_U64(x->sv.wlen, 4 * ST_UNIT);
  /* per stream the units arrive in submission order */
  {
    uint64_t last[4];
    int seen[4], j;
    memset(last, 0, sizeof(last));
    memset(seen, 0, sizeof(seen));
    for (j = 0; j < (int)n; j++) {
      uint32_t s = ev[j].stream;
      if (ev[j].type != TR_WRITE || s > 3) continue;
      if (seen[s]) SD_CHECK(ev[j].off > last[s]);
      last[s] = ev[j].off;
      seen[s] = 1;
    }
  }

  sd_sftp_file_release(f);
  waiter_free(&w);
  xf_stop(x);
  sd_free(src);
  sd_free(x);
}

/* ---- emit_piece limits: a member stream that cannot accept bytes parks the pump ----
 *
 * The real pool transport accepts only what fits the member's TX queue; the fake models that with
 * a byte budget on the member's stream. The unit the budgeted member is due gets emitted into the
 * channel's obuf, flush cannot send it, and emit_piece's limits must park the request there: no
 * unit behind the stuck one is emitted. A broken limit check keeps emitting, which shows in the
 * exact per-stream request counts and in the write finishing while the window is still shut. */

#define GATE_MS 20000

/* A WRITE wire on a member stream: len(4) type(1) id(4) strlen(4) handle(2) off(8) strlen(4) data. */
static uint32_t gate_wire_bytes(uint32_t unit) { return unit + 27; }

/* Polls until the surviving channels saw exactly the units that precede the gated one and nothing
   more, and the write is still parked. Returns 1 when parked as expected. */
static int gate_wait_parked(xf *x, waiter *w, int want1, int want3)
{
  uint64_t end = sd_tick_ms() + 5000;
  tr_ev ev[TR_MAX];
  for (;;) {
    LONG n = tr_snapshot(&x->sv, ev, TR_MAX);
    if (tr_n(ev, n, TR_WRITE, 1) >= want1 && tr_n(ev, n, TR_WRITE, 3) >= want3) {
      Sleep(150);                      /* a broken pump overshoots the parked counts (or finishes) */
      n = tr_snapshot(&x->sv, ev, TR_MAX);
      return tr_n(ev, n, TR_WRITE, 1) == want1 && tr_n(ev, n, TR_WRITE, 3) == want3 &&
             !waiter_wait(w, 0);
    }
    if (sd_tick_ms() >= end) return 0;
    Sleep(5);
  }
}

/* The default request cap (64 per channel) parks the write at unit 202: the 68th member-1 wire
   would be the 65th unacknowledged one on that channel (three were budgeted through and acked).
   Once member 1's window reopens the write finishes exactly once. */
SD_TEST(striping_write_parks_at_max_inflight_reqs)
{
  xf *x = xf_new(3);
  waiter w;
  sd_sftp_reqopt o = { 0, GATE_MS, NULL };
  sd_sftp_file *f;
  uint8_t *src = (uint8_t *)sd_alloc(400 * ST_UNIT);
  uint8_t *pre = (uint8_t *)sd_alloc(3 * ST_UNIT);
  tr_ev ev[TR_MAX];
  LONG n;
  int i, ok = 1;
  SD_REQUIRE(x != NULL && src != NULL && pre != NULL);
  for (i = 0; i < (int)(400 * ST_UNIT); i++) src[i] = pat((uint64_t)i + 3);
  f = xf_open_striped(x, SD_SFTP_O_WRITE);
  SD_REQUIRE(f != NULL);
  waiter_init(&w, x->s);
  /* open both sub-handles first, so the write phase sees only WRITE wires on the members */
  waiter_reset(&w, W_RW);
  SD_REQUIRE(sd_sftp_read(f, 0, pre, 3 * ST_UNIT, &o, waiter_cb, &w) == SD_OK);
  SD_REQUIRE(waiter_wait(&w, 5000) && w.err == SD_OK);

  fake_limit_member_writes(x->sv.f, 1, (LONG)(3 * gate_wire_bytes(ST_UNIT)));
  waiter_reset(&w, W_RW);
  SD_REQUIRE(sd_sftp_write(f, 0, src, 400 * ST_UNIT, &o, waiter_cb, &w) == SD_OK);
  SD_CHECK(gate_wait_parked(x, &w, 68, 67));
  n = tr_snapshot(&x->sv, ev, TR_MAX);
  SD_CHECK_EQ_INT(tr_n(ev, n, TR_WRITE, 2), 3);    /* only the budgeted wires reached member 1 */

  /* reopen the window: the parked bytes flush, the write resumes and finishes exactly once */
  fake_limit_member_writes(x->sv.f, 1, -1);
  SD_REQUIRE(xf_settle(x));
  SD_REQUIRE(waiter_wait(&w, 10000));
  SD_CHECK_EQ_INT(w.err, SD_OK);
  SD_CHECK_EQ_U64(w.bytes, 400 * ST_UNIT);
  n = tr_snapshot(&x->sv, ev, TR_MAX);
  SD_CHECK_EQ_INT(tr_n(ev, n, TR_WRITE, 1), 134);  /* units 0,3,...,399 */
  SD_CHECK_EQ_INT(tr_n(ev, n, TR_WRITE, 2), 133);  /* units 1,4,...,397, the parked ones included */
  SD_CHECK_EQ_INT(tr_n(ev, n, TR_WRITE, 3), 133);  /* units 2,5,...,398 */
  SD_CHECK(tr_off_s(ev, n, TR_WRITE, 2, 202 * ST_UNIT) != NULL);   /* the gated unit went out late */
  for (i = 0; i < (int)(400 * ST_UNIT) && ok; i++) ok = x->sv.wdata[i] == src[i];
  SD_CHECK(ok);
  SD_CHECK_EQ_INT(sd_sftp_session_state(x->s), SD_SFTP_ST_READY);

  sd_sftp_file_release(f);
  waiter_free(&w);
  xf_stop(x);
  sd_free(src);
  sd_free(pre);
  sd_free(x);
}

/* The 512 KiB obuf high-water mark parks the write when the units are chunk-sized (the 64-request
   cap would allow 2 MiB in flight): the member-1 obuf crosses the mark at its 19th wire, so unit 58
   parks with 20 units out on the primary and 19 on member 2. */
SD_TEST(striping_write_parks_at_obuf_high_water)
{
  xf *x = xf_new_ex(3, 0, ST_LIMIT);               /* one stripe unit = one negotiated chunk */
  waiter w;
  sd_sftp_reqopt o = { 0, GATE_MS, NULL };
  sd_sftp_file *f;
  uint8_t *src = (uint8_t *)sd_alloc(160 * ST_LIMIT);
  uint8_t *pre = (uint8_t *)sd_alloc(3 * ST_LIMIT);
  tr_ev ev[TR_MAX];
  LONG n;
  int i, ok = 1;
  SD_REQUIRE(x != NULL && src != NULL && pre != NULL);
  for (i = 0; i < (int)(160 * ST_LIMIT); i++) src[i] = pat((uint64_t)i + 3);
  f = xf_open_striped(x, SD_SFTP_O_WRITE);
  SD_REQUIRE(f != NULL);
  waiter_init(&w, x->s);
  waiter_reset(&w, W_RW);
  SD_REQUIRE(sd_sftp_read(f, 0, pre, 3 * ST_LIMIT, &o, waiter_cb, &w) == SD_OK);
  SD_REQUIRE(waiter_wait(&w, 5000) && w.err == SD_OK);

  fake_limit_member_writes(x->sv.f, 1, (LONG)(3 * gate_wire_bytes(ST_LIMIT)));
  waiter_reset(&w, W_RW);
  SD_REQUIRE(sd_sftp_write(f, 0, src, 160 * ST_LIMIT, &o, waiter_cb, &w) == SD_OK);
  SD_CHECK(gate_wait_parked(x, &w, 20, 19));
  n = tr_snapshot(&x->sv, ev, TR_MAX);
  SD_CHECK_EQ_INT(tr_n(ev, n, TR_WRITE, 2), 3);

  fake_limit_member_writes(x->sv.f, 1, -1);
  SD_REQUIRE(xf_settle(x));
  SD_REQUIRE(waiter_wait(&w, 10000));
  SD_CHECK_EQ_INT(w.err, SD_OK);
  SD_CHECK_EQ_U64(w.bytes, 160 * ST_LIMIT);
  n = tr_snapshot(&x->sv, ev, TR_MAX);
  SD_CHECK_EQ_INT(tr_n(ev, n, TR_WRITE, 1), 54);   /* units 0,3,...,159 */
  SD_CHECK_EQ_INT(tr_n(ev, n, TR_WRITE, 2), 53);   /* units 1,4,...,157 */
  SD_CHECK_EQ_INT(tr_n(ev, n, TR_WRITE, 3), 53);   /* units 2,5,...,158 */
  SD_CHECK(tr_off_s(ev, n, TR_WRITE, 2, 58 * ST_LIMIT) != NULL);
  for (i = 0; i < (int)(100 * ST_LIMIT) && ok; i++) ok = x->sv.wdata[i] == src[i];   /* wdata is 4 MiB */
  SD_CHECK(ok);
  SD_CHECK_EQ_INT(sd_sftp_session_state(x->s), SD_SFTP_ST_READY);

  sd_sftp_file_release(f);
  waiter_free(&w);
  xf_stop(x);
  sd_free(src);
  sd_free(pre);
  sd_free(x);
}

/* The max_inflight_bytes option parks the write once the member's unacknowledged units exceed it
   (65536 + 32768 > 65536 at unit 13, the two budgeted wires being acked already): 5 units out on
   the primary, 4 on member 2. */
SD_TEST(striping_write_parks_at_max_inflight_bytes)
{
  xf *x = xf_new_full(3, 0, ST_LIMIT, 2 * ST_LIMIT);
  waiter w;
  sd_sftp_reqopt o = { 0, GATE_MS, NULL };
  sd_sftp_file *f;
  uint8_t *src = (uint8_t *)sd_alloc(100 * ST_LIMIT);
  uint8_t *pre = (uint8_t *)sd_alloc(3 * ST_LIMIT);
  tr_ev ev[TR_MAX];
  LONG n;
  int i, ok = 1;
  SD_REQUIRE(x != NULL && src != NULL && pre != NULL);
  for (i = 0; i < (int)(100 * ST_LIMIT); i++) src[i] = pat((uint64_t)i + 3);
  f = xf_open_striped(x, SD_SFTP_O_WRITE);
  SD_REQUIRE(f != NULL);
  waiter_init(&w, x->s);
  waiter_reset(&w, W_RW);
  SD_REQUIRE(sd_sftp_read(f, 0, pre, 3 * ST_LIMIT, &o, waiter_cb, &w) == SD_OK);
  SD_REQUIRE(waiter_wait(&w, 5000) && w.err == SD_OK);

  fake_limit_member_writes(x->sv.f, 1, (LONG)(2 * gate_wire_bytes(ST_LIMIT)));
  waiter_reset(&w, W_RW);
  SD_REQUIRE(sd_sftp_write(f, 0, src, 100 * ST_LIMIT, &o, waiter_cb, &w) == SD_OK);
  SD_CHECK(gate_wait_parked(x, &w, 5, 4));
  n = tr_snapshot(&x->sv, ev, TR_MAX);
  SD_CHECK_EQ_INT(tr_n(ev, n, TR_WRITE, 2), 2);

  fake_limit_member_writes(x->sv.f, 1, -1);
  SD_REQUIRE(xf_settle(x));
  SD_REQUIRE(waiter_wait(&w, 10000));
  SD_CHECK_EQ_INT(w.err, SD_OK);
  SD_CHECK_EQ_U64(w.bytes, 100 * ST_LIMIT);
  n = tr_snapshot(&x->sv, ev, TR_MAX);
  SD_CHECK_EQ_INT(tr_n(ev, n, TR_WRITE, 1), 34);   /* units 0,3,...,99 */
  SD_CHECK_EQ_INT(tr_n(ev, n, TR_WRITE, 2), 33);   /* units 1,4,...,97 */
  SD_CHECK_EQ_INT(tr_n(ev, n, TR_WRITE, 3), 33);   /* units 2,5,...,98 */
  SD_CHECK(tr_off_s(ev, n, TR_WRITE, 2, 13 * ST_LIMIT) != NULL);
  for (i = 0; i < (int)(100 * ST_LIMIT) && ok; i++) ok = x->sv.wdata[i] == src[i];
  SD_CHECK(ok);
  SD_CHECK_EQ_INT(sd_sftp_session_state(x->s), SD_SFTP_ST_READY);

  sd_sftp_file_release(f);
  waiter_free(&w);
  xf_stop(x);
  sd_free(src);
  sd_free(pre);
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
  SD_CHECK_EQ_INT(st_held_count(&x->sv), 3);       /* one wire per member incl. the primary */
  InterlockedExchange(&x->sv.hold_write, 0);
  drop_member_wait(x->sv.f, 1);

  SD_REQUIRE(waiter_wait(&w, 5000));
  SD_CHECK_EQ_INT(w.err, SD_E_DISCONNECTED);
  SD_CHECK_EQ_INT(w.maybe_executed, 1);
  SD_CHECK_EQ_INT(w.session_ready, 1);             /* the VFS resubmits it at once */
  SD_CHECK_EQ_INT(sd_sftp_session_state(x->s), SD_SFTP_ST_READY);

  /* The failed write's wires on the live channels (streams 1 and 3) stay in the table on purpose:
     their late acks must be discarded by dispatch's done-branch instead of surfacing as "reply with
     unknown id", which would lose the session (fbf8b17). Answer them and take no protocol loss. */
  fake_run(x->sv.f, st_release_held, &x->sv);
  xf_drain(x);
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

/* The drop window: the member's transport already fails its stream's writes, but the posted drop
   report has not run yet, so the session still sees the channel as SS_OPEN. A flush that hits that
   error used to lose() the whole session; it must leave the bytes queued for the drop report. */
SD_TEST(striping_member_write_error_in_drop_window_keeps_ready)
{
  xf *x = xf_new(3);
  waiter w, w2;
  sd_sftp_reqopt o = { 0, 5000, NULL };
  sd_sftp_file *f, *f2;
  uint8_t *src = (uint8_t *)sd_alloc(3 * ST_UNIT);
  uint8_t *src2 = (uint8_t *)sd_alloc(ST_UNIT);
  uint8_t *rbuf = (uint8_t *)sd_alloc(2 * ST_UNIT);
  int i, ok = 1;
  SD_REQUIRE(x != NULL && src != NULL && src2 != NULL && rbuf != NULL);
  for (i = 0; i < (int)(3 * ST_UNIT); i++) src[i] = pat((uint64_t)i + 5);
  for (i = 0; i < (int)ST_UNIT; i++) src2[i] = pat((uint64_t)i + 9);
  f = xf_open_striped(x, SD_SFTP_O_READ | SD_SFTP_O_WRITE);
  SD_REQUIRE(f != NULL);
  waiter_init(&w, x->s);
  waiter_init(&w2, x->s);

  /* three writes in flight, one per member (held) */
  InterlockedExchange(&x->sv.hold_write, 3);
  waiter_reset(&w, W_RW);
  SD_REQUIRE(sd_sftp_write(f, 0, src, 3 * ST_UNIT, &o, waiter_cb, &w) == SD_OK);
  SD_REQUIRE(wait_held(x, 3, 5000));
  InterlockedExchange(&x->sv.hold_write, 0);

  /* the drop window for member 1: its stream refuses writes, the drop report is still in flight */
  fake_fail_member_writes(x->sv.f, 1, SD_E_DISCONNECTED);
  waiter_reset(&w2, W_RW);
  SD_REQUIRE(sd_sftp_write(f, ST_UNIT, src2, ST_UNIT, &o, waiter_cb, &w2) == SD_OK);
  SD_REQUIRE(xf_settle(x));                        /* the session's pump ran the failing flush */
  SD_CHECK_EQ_INT(sd_sftp_session_state(x->s), SD_SFTP_ST_READY);   /* no session loss */
  SD_CHECK(!waiter_wait(&w2, 150));                /* the unit stays parked on the member */

  /* the drop report lands: both writes complete with session_ready, the session stays READY */
  drop_member_wait(x->sv.f, 1);
  SD_REQUIRE(waiter_wait(&w, 5000));
  SD_CHECK_EQ_INT(w.err, SD_E_DISCONNECTED);
  SD_CHECK_EQ_INT(w.session_ready, 1);
  SD_REQUIRE(waiter_wait(&w2, 5000));
  SD_CHECK_EQ_INT(w2.err, SD_E_DISCONNECTED);
  SD_CHECK_EQ_INT(w2.session_ready, 1);
  SD_CHECK_EQ_INT(sd_sftp_session_state(x->s), SD_SFTP_ST_READY);

  /* the surviving channels' late acks are discarded (fbf8b17) */
  fake_run(x->sv.f, st_release_held, &x->sv);
  xf_drain(x);
  SD_CHECK_EQ_INT(sd_sftp_session_state(x->s), SD_SFTP_ST_READY);

  /* the session stays usable: a later striped open and read still work (member 1 is out) */
  fake_fail_member_writes(x->sv.f, 0, SD_OK);
  f2 = xf_open_striped(x, SD_SFTP_O_READ);
  SD_REQUIRE(f2 != NULL);
  waiter_reset(&w, W_RW);
  SD_REQUIRE(sd_sftp_read(f2, 0, rbuf, 2 * ST_UNIT, &o, waiter_cb, &w) == SD_OK);
  SD_REQUIRE(waiter_wait(&w, 5000));
  SD_CHECK_EQ_INT(w.err, SD_OK);
  for (i = 0; i < (int)(2 * ST_UNIT) && ok; i++) ok = rbuf[i] == pat((uint64_t)i);
  SD_CHECK(ok);

  sd_sftp_file_release(f2);
  sd_sftp_file_release(f);
  waiter_free(&w);
  waiter_free(&w2);
  xf_stop(x);
  sd_free(src);
  sd_free(src2);
  sd_free(rbuf);
  sd_free(x);
}

/* A member dying while its barrier wire (fsync) is still in flight: the wire counts as done, the
   barrier completes with the surviving wires' outcome and the session stays READY. */
SD_TEST(striping_member_drop_during_barrier_counts_it_done)
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

  /* the fsync on member 2's sub-handle is in flight when the member dies */
  InterlockedExchange(&x->sv.hold_fsync_stream, 3);
  waiter_reset(&w, W_STAT);
  SD_REQUIRE(sd_sftp_fsync(f, &o, waiter_cb, &w) == SD_OK);
  SD_REQUIRE(wait_held(x, 1, 5000));               /* the primary's and member 1's wires settled */
  drop_member_wait(x->sv.f, 2);

  SD_REQUIRE(waiter_wait(&w, 5000));
  SD_CHECK_EQ_INT(w.err, SD_OK);                   /* the dead wire counted as done: no timeout */
  SD_CHECK_EQ_INT(sd_sftp_session_state(x->s), SD_SFTP_ST_READY);
  n = tr_snapshot(&x->sv, ev, TR_MAX);
  SD_CHECK_EQ_INT(tr_n(ev, n, TR_FSYNC, 1), 1);
  SD_CHECK_EQ_INT(tr_n(ev, n, TR_FSYNC, 2), 1);
  SD_CHECK_EQ_INT(tr_n(ev, n, TR_FSYNC, 3), 1);    /* the wire was out when the member died */

  /* the handle stays usable: the recomputed route runs the next barrier on the primary only */
  waiter_reset(&w, W_STAT);
  SD_REQUIRE(sd_sftp_fstat(f, &o, waiter_cb, &w) == SD_OK);
  SD_REQUIRE(waiter_wait(&w, 5000));
  SD_CHECK_EQ_INT(w.err, SD_OK);
  n = tr_snapshot(&x->sv, ev, TR_MAX);
  SD_CHECK_EQ_INT(tr_n(ev, n, TR_FSTAT, 1), 2);    /* open probe + barrier */
  SD_CHECK_EQ_INT(tr_n(ev, n, TR_FSTAT, 3), 1);    /* the open probe only: member 2 is out */

  InterlockedExchange(&x->sv.hold_fsync_stream, 0);
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

/* ---- life cycle: duplicate and stale member events (01 §10.9) ---- */

static int wait_gen_ready(xf *x, uint32_t gen, uint32_t ms)
{
  uint64_t end = sd_tick_ms() + ms;
  for (;;) {
    if (sd_sftp_session_generation(x->s) >= gen &&
        sd_sftp_session_state(x->s) == SD_SFTP_ST_READY) return 1;
    if (sd_tick_ms() >= end) return 0;
    Sleep(5);
  }
}

static int wait_connections(xf *x, uint32_t want, uint32_t ms)
{
  uint64_t end = sd_tick_ms() + ms;
  sd_sftp_stats st;
  for (;;) {
    if (sd_sftp_session_stats(x->s, &st) == SD_OK && st.conn_count >= want) return 1;
    if (sd_tick_ms() >= end) return 0;
    Sleep(5);
  }
}

/* A member drop reaches the session twice - the channel's on_closed and the pool's decision. The
   second report must neither emit a second EV_POOL nor walk member_lost again. */
SD_TEST(striping_member_drop_reported_twice_acts_once)
{
  xf *x = xf_new(3);
  waiter w;
  sd_sftp_reqopt o = { 0, 5000, NULL };
  sd_sftp_file *f;
  uint8_t *buf = (uint8_t *)sd_alloc(3 * ST_UNIT);
  tr_ev ev[TR_MAX];
  LONG n;
  int i, ok = 1;
  SD_REQUIRE(x != NULL && buf != NULL);
  SD_CHECK_EQ_INT(x->ev.n_pool_drop, 0);
  f = xf_open_striped(x, SD_SFTP_O_READ);
  SD_REQUIRE(f != NULL);
  waiter_init(&w, x->s);

  /* one unit per member is in flight, so member_lost has a read to reissue on the primary */
  InterlockedExchange(&x->sv.hold_read, 3);
  waiter_reset(&w, W_RW);
  SD_REQUIRE(sd_sftp_read(f, 0, buf, 3 * ST_UNIT, &o, waiter_cb, &w) == SD_OK);
  SD_REQUIRE(wait_held(x, 3, 5000));
  InterlockedExchange(&x->sv.hold_read, 0);

  /* first report: the channel's on_closed (member 1 dies mid-flight) */
  drop_member_wait(x->sv.f, 1);
  SD_CHECK_EQ_INT(x->ev.n_pool_drop, 1);
  /* second report: the pool's decision, for the same admitted generation */
  fake_pool_change(x->sv.f, 1, 0, SD_E_DISCONNECTED, sd_sftp_session_generation(x->s));
  xf_drain(x);
  SD_CHECK_EQ_INT(x->ev.n_pool_drop, 1);           /* still exactly one drop event */

  fake_run(x->sv.f, st_release_held, &x->sv);      /* the primary's and member 2's replies */
  SD_REQUIRE(waiter_wait(&w, 5000));
  SD_CHECK_EQ_INT(w.err, SD_OK);
  SD_CHECK_EQ_U64(w.bytes, 3 * ST_UNIT);
  for (i = 0; i < (int)(3 * ST_UNIT) && ok; i++) ok = buf[i] == pat((uint64_t)i);
  SD_CHECK(ok);
  n = tr_snapshot(&x->sv, ev, TR_MAX);
  SD_CHECK_EQ_INT(tr_n(ev, n, TR_READ, 0), 4);     /* the three units plus one reissue (not two) */
  SD_CHECK(tr_off_s(ev, n, TR_READ, 2, ST_UNIT) != NULL);   /* first attempt on member 1 */
  SD_CHECK(tr_off_s(ev, n, TR_READ, 1, ST_UNIT) != NULL);   /* re-issued once on the primary */
  SD_CHECK_EQ_INT(sd_sftp_session_state(x->s), SD_SFTP_ST_READY);

  sd_sftp_file_release(f);
  waiter_free(&w);
  xf_stop(x);
  sd_free(buf);
  sd_free(x);
}

/* A member event posted before a generation reset must not act on the freshly admitted member: its
   generation no longer matches the one the session recorded at (re-)admission. */
SD_TEST(striping_stale_member_event_after_generation_reset_is_ignored)
{
  xf *x = xf_new_ex(3, SD_SFTP_TP_REOPEN, ST_UNIT);
  sd_sftp_file *f;
  sd_sftp_stats st;
  uint32_t gen0;
  LONG drops_after_reset;
  SD_REQUIRE(x != NULL);
  f = xf_open_striped(x, SD_SFTP_O_READ);
  SD_REQUIRE(f != NULL);
  SD_REQUIRE(wait_connections(x, 3, 5000));

  gen0 = sd_sftp_session_generation(x->s);         /* the generation the members were admitted in */
  /* hard drop of the primary: the session reconnects, the generation advances and the members
     re-admit (their streams are reset and opened again) */
  fake_hangup(x->sv.f);
  SD_REQUIRE(wait_gen_ready(x, gen0 + 1, 5000));
  SD_REQUIRE(wait_connections(x, 3, 5000));
  drops_after_reset = x->ev.n_pool_drop;

  /* the stale drop carries the pre-reset generation: it must be dropped */
  fake_pool_change(x->sv.f, 1, 0, SD_E_DISCONNECTED, gen0);
  xf_drain(x);
  SD_CHECK_EQ_INT(x->ev.n_pool_drop, drops_after_reset);   /* no new drop event */
  SD_CHECK(sd_sftp_session_stats(x->s, &st) == SD_OK);
  SD_CHECK_EQ_INT(st.conn_count, 3);                       /* the fresh member survived */
  SD_CHECK_EQ_INT(sd_sftp_session_state(x->s), SD_SFTP_ST_READY);

  sd_sftp_file_release(f);
  xf_stop(x);
  sd_free(x);
}

/* ---- stripe_bytes limits (risk 5) ---- */

SD_TEST(striping_stripe_unit_clamped_to_negotiated_limits)
{
  /* the requested 256 KiB exceeds the server's negotiated 32 KiB max_read/max_write, so it is
     clamped to one chunk: units land on the members instead of staying on the primary */
  xf *x = xf_new_ex(3, 0, 256u * 1024u);
  waiter w;
  sd_sftp_reqopt o = { 0, 5000, NULL };
  sd_sftp_file *f;
  uint8_t *buf = (uint8_t *)sd_alloc(4 * ST_LIMIT);
  tr_ev ev[TR_MAX];
  LONG n;
  int i, ok = 1;
  SD_REQUIRE(x != NULL && buf != NULL);
  f = xf_open_striped(x, SD_SFTP_O_READ);
  SD_REQUIRE(f != NULL);
  waiter_init(&w, x->s);
  waiter_reset(&w, W_RW);
  SD_REQUIRE(sd_sftp_read(f, 0, buf, 4 * ST_LIMIT, &o, waiter_cb, &w) == SD_OK);
  SD_REQUIRE(waiter_wait(&w, 5000));
  SD_CHECK_EQ_INT(w.err, SD_OK);
  SD_CHECK_EQ_U64(w.bytes, 4 * ST_LIMIT);
  for (i = 0; i < (int)(4 * ST_LIMIT) && ok; i++) ok = buf[i] == pat((uint64_t)i);
  SD_CHECK(ok);
  n = tr_snapshot(&x->sv, ev, TR_MAX);
  SD_CHECK_EQ_INT(tr_n(ev, n, TR_READ, 0), 4);     /* four chunk-sized wires */
  SD_CHECK(tr_off_s(ev, n, TR_READ, 2, ST_LIMIT) != NULL);   /* unit 1 went to member 1, not the primary */
  SD_CHECK(tr_off_s(ev, n, TR_READ, 3, 2 * ST_LIMIT) != NULL);
  for (i = 0; i < (int)n; i++)
    if (ev[i].type == TR_READ) SD_CHECK(ev[i].len <= ST_LIMIT);

  sd_sftp_file_release(f);
  waiter_free(&w);
  xf_stop(x);
  sd_free(buf);
  sd_free(x);
}