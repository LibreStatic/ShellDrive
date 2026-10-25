/* sd_sftp over sd_ssh: the production transport. Stream 0 is the "meta" SFTP subsystem channel,
 * stream 1 the "bulk" one (D19); both live on one sd_ssh connection. The transport supports
 * SD_SFTP_TP_REOPEN: after close(), open() reconnects the same sd_ssh_conn, so the I/O thread, the
 * pinned host key and the reconnect secret cache survive (01 §8).
 * Kept in its own translation unit so test binaries that only use sd_sftp_session_create_transport()
 * do not pull in sd_ssh. Everything here runs on the connection's I/O thread except post,
 * is_io_thread, rtt and destroy. */
#include <string.h>

#include "sd_base/sd_mem.h"
#include "sftp_internal.h"

#define TP_STREAMS 2u

enum { ST_NONE = 0, ST_OPENING, ST_OPEN };
enum { CN_IDLE = 0, CN_CONNECTING, CN_CONNECTED, CN_DISCONNECTING };

struct ssh_tp;
typedef struct ssh_stream {
  struct ssh_tp *t;
  uint32_t idx;
  int state;                      /* ST_* */
  sd_ssh_channel *ch;
  const sd_ssh_channel_sink *sink;
  void *sink_ctx;
} ssh_stream;

typedef struct ssh_tp {
  sd_ssh_conn *conn;
  ssh_stream st[TP_STREAMS];
  int cn;                         /* CN_* */
  int open_after_disconnect;      /* open() arrived while the old connection was still closing */
  sd_ssh_callbacks user;          /* caller's callbacks (ctx inside) */
  sd_sftp_session *session;       /* for AUTH_REQUIRED during reconnects */
  int in_open_stream;             /* sd_ssh may fail a channel open synchronously */
  sd_ssh_negotiated neg;          /* target hop, strings below */
  char server_version[256];
  char hostkey_fp[128];
  int have_neg;
} ssh_tp;

static void copy_cstr(char *dst, size_t cap, const char *src)
{
  size_t n = src ? strlen(src) : 0;
  if (n >= cap) n = cap - 1;
  if (n) memcpy(dst, src, n);
  dst[n] = 0;
}

/* ---- sd_ssh callbacks: forward to the caller, remember the negotiated target hop ---- */

static void fw_prompt(void *ctx, sd_prompt *p, const sd_auth_prompt_info *a, const sd_hostkey_prompt_info *h)
{
  ssh_tp *t = (ssh_tp *)ctx;
  if (((a && a->is_reconnect) || (h && h->is_reconnect)) && t->session) sftp_session_auth_prompt(t->session);
  if (t->user.on_prompt) t->user.on_prompt(t->user.ctx, p, a, h);
  else sd_prompt_cancel(p);
}
static void fw_withdrawn(void *ctx, sd_prompt *p)
{ ssh_tp *t = (ssh_tp *)ctx; if (t->user.on_prompt_withdrawn) t->user.on_prompt_withdrawn(t->user.ctx, p); }
static void fw_banner(void *ctx, uint32_t hop, const char *utf8)
{ ssh_tp *t = (ssh_tp *)ctx; if (t->user.on_banner) t->user.on_banner(t->user.ctx, hop, utf8); }
static void fw_hostkey(void *ctx, const sd_hostkey_event *e)
{ ssh_tp *t = (ssh_tp *)ctx; if (t->user.on_hostkey_event) t->user.on_hostkey_event(t->user.ctx, e); }
static void fw_log(void *ctx, int level, const char *msg)
{ ssh_tp *t = (ssh_tp *)ctx; if (t->user.on_log) t->user.on_log(t->user.ctx, level, msg); }

static void fw_negotiated(void *ctx, const sd_ssh_negotiated *n)
{
  ssh_tp *t = (ssh_tp *)ctx;
  if (n) {
    memset(&t->neg, 0, sizeof(t->neg));
    t->neg.hop_index = n->hop_index;
    t->neg.strict_kex = n->strict_kex;
    t->neg.legacy_mask = n->legacy_mask;
    copy_cstr(t->server_version, sizeof(t->server_version), n->server_version);
    copy_cstr(t->hostkey_fp, sizeof(t->hostkey_fp), n->hostkey_fp_sha256);
    t->neg.server_version = t->server_version;
    t->neg.hostkey_fp_sha256 = t->hostkey_fp;
    t->have_neg = 1;
  }
  if (t->user.on_negotiated) t->user.on_negotiated(t->user.ctx, n);
}

/* ---- channel sinks (per stream) ---- */

static void report_open_fail(void *arg);
typedef struct open_fail { ssh_stream *st; sd_err err; } open_fail;

static void ch_on_open(void *ctx, sd_err err)
{
  ssh_stream *st = (ssh_stream *)ctx;
  if (st->state != ST_OPENING) return;
  if (err != SD_OK && st->t->in_open_stream) {   /* never inside open_stream(): report it posted */
    open_fail *of = (open_fail *)sd_calloc(1, sizeof(*of));
    if (of) {
      of->st = st;
      of->err = err;
      if (sd_ssh_conn_post(st->t->conn, report_open_fail, of) == SD_OK) return;
      sd_free(of);
    }
  }
  if (err != SD_OK) { st->ch = NULL; st->state = ST_NONE; }
  else st->state = ST_OPEN;
  st->sink->on_open(st->sink_ctx, err);
}
static void ch_on_data(void *ctx, const uint8_t *p, size_t n)
{ ssh_stream *st = (ssh_stream *)ctx; st->sink->on_data(st->sink_ctx, p, n); }
static void ch_on_writable(void *ctx)
{ ssh_stream *st = (ssh_stream *)ctx; st->sink->on_writable(st->sink_ctx); }
static void ch_on_eof(void *ctx)
{ ssh_stream *st = (ssh_stream *)ctx; st->sink->on_eof(st->sink_ctx); }
static void ch_on_closed(void *ctx, sd_err why)
{
  ssh_stream *st = (ssh_stream *)ctx;
  st->ch = NULL;
  st->state = ST_NONE;
  st->sink->on_closed(st->sink_ctx, why);
}
static const sd_ssh_channel_sink k_ch_sink = { ch_on_open, ch_on_data, ch_on_writable, ch_on_eof, ch_on_closed };

static void open_channel(ssh_tp *t, ssh_stream *st)
{
  sd_ssh_channel *ch = NULL;
  sd_err e = sd_ssh_channel_open_subsystem(t->conn, "sftp", &k_ch_sink, st, &ch);
  if (e == SD_OK) { if (st->state == ST_OPENING) st->ch = ch; }   /* on_open may already have failed */
  else ch_on_open(st, e);
}

/* ---- connection lifecycle ---- */

static sd_err start_connect(ssh_tp *t);

static void on_connected(void *ctx, sd_err err, uint32_t failed_hop)
{
  ssh_tp *t = (ssh_tp *)ctx;
  SD_UNUSED(failed_hop);
  if (err != SD_OK) {
    if (t->cn == CN_CONNECTING) t->cn = CN_IDLE;
    if (!t->open_after_disconnect) ch_on_open(&t->st[0], err);
    return;
  }
  if (t->cn != CN_CONNECTING) return;     /* closed meanwhile: on_disconnected settles stream 0 */
  t->cn = CN_CONNECTED;
  if (t->st[0].state == ST_OPENING) open_channel(t, &t->st[0]);
}

static void on_disconnected(void *ctx, sd_err err, uint32_t failed_hop)
{
  ssh_tp *t = (ssh_tp *)ctx;
  SD_UNUSED(err); SD_UNUSED(failed_hop);
  if (t->cn != CN_DISCONNECTING) return;
  t->cn = CN_IDLE;
  {
    uint32_t i;
    for (i = 0; i < TP_STREAMS; i++)    /* streams that were opening when close() came */
      if (t->st[i].state == ST_OPENING && !t->st[i].ch && !(i == 0 && t->open_after_disconnect))
        ch_on_open(&t->st[i], SD_E_SHUTDOWN);
  }
  if (t->open_after_disconnect) {
    sd_err e;
    t->open_after_disconnect = 0;
    e = start_connect(t);
    if (e != SD_OK) ch_on_open(&t->st[0], e);
  }
}

static sd_err start_connect(ssh_tp *t)
{
  sd_err e;
  t->cn = CN_CONNECTING;
  t->have_neg = 0;
  e = sd_ssh_conn_connect(t->conn, on_connected, t);
  if (e != SD_OK) t->cn = CN_IDLE;
  return e;
}

/* ---- transport ops ---- */

static sd_err tp_post(void *ctx, void (*fn)(void *), void *arg)
{ return sd_ssh_conn_post(((ssh_tp *)ctx)->conn, fn, arg); }

static int tp_is_io(void *ctx) { return sd_ssh_conn_is_io_thread(((ssh_tp *)ctx)->conn); }

static sd_err tp_open(void *ctx, const sd_ssh_channel_sink *sink, void *sink_ctx)
{
  ssh_tp *t = (ssh_tp *)ctx;
  ssh_stream *st = &t->st[0];
  if (st->state != ST_NONE) return SD_E_BUSY;
  st->sink = sink;
  st->sink_ctx = sink_ctx;
  st->state = ST_OPENING;
  if (t->cn == CN_DISCONNECTING) { t->open_after_disconnect = 1; return SD_OK; }
  if (t->cn != CN_IDLE) { st->state = ST_NONE; return SD_E_BUSY; }
  {
    sd_err e = start_connect(t);
    if (e != SD_OK) st->state = ST_NONE;
    return e;
  }
}

static void report_open_fail(void *arg)
{
  open_fail *of = (open_fail *)arg;
  ssh_stream *st = of->st;
  sd_err e = of->err;
  sd_free(of);
  ch_on_open(st, e);
}

static sd_err tp_open_stream(void *ctx, uint32_t idx, const sd_ssh_channel_sink *sink, void *sink_ctx)
{
  ssh_tp *t = (ssh_tp *)ctx;
  ssh_stream *st;
  if (idx == 0 || idx >= TP_STREAMS) return SD_E_INVALID_PARAM;
  st = &t->st[idx];
  if (st->state != ST_NONE || t->cn != CN_CONNECTED) return SD_E_DISCONNECTED;
  st->sink = sink;
  st->sink_ctx = sink_ctx;
  st->state = ST_OPENING;
  {
    sd_ssh_channel *ch = NULL;
    sd_err e;
    t->in_open_stream = 1;
    e = sd_ssh_channel_open_subsystem(t->conn, "sftp", &k_ch_sink, st, &ch);
    t->in_open_stream = 0;
    if (e == SD_OK) { if (st->state == ST_OPENING) st->ch = ch; return SD_OK; }
    st->state = ST_NONE;
    return e;
  }
}

static sd_err tp_write_stream(void *ctx, uint32_t idx, const uint8_t *p, size_t n, size_t *accepted)
{
  ssh_tp *t = (ssh_tp *)ctx;
  ssh_stream *st = idx < TP_STREAMS ? &t->st[idx] : NULL;
  if (!st || !st->ch) { *accepted = 0; return SD_E_DISCONNECTED; }
  return sd_ssh_channel_write(st->ch, p, n, accepted);
}

static sd_err tp_write(void *ctx, const uint8_t *p, size_t n, size_t *accepted)
{ return tp_write_stream(ctx, 0, p, n, accepted); }

static void tp_consumed_stream(void *ctx, uint32_t idx, size_t n)
{
  ssh_tp *t = (ssh_tp *)ctx;
  if (idx < TP_STREAMS && t->st[idx].ch) sd_ssh_channel_consumed(t->st[idx].ch, n);
}

static void tp_consumed(void *ctx, size_t n) { tp_consumed_stream(ctx, 0, n); }

/* Closes every stream and the connection. Open streams report on_closed (sd_ssh delivers it for
   every opened channel); a stream still opening reports on_open(err) when the connect or the
   channel open fails because of the disconnect. Safe to call again. */
static void tp_close(void *ctx)
{
  ssh_tp *t = (ssh_tp *)ctx;
  uint32_t i;
  t->open_after_disconnect = 0;
  for (i = 0; i < TP_STREAMS; i++)
    if (t->st[i].ch) sd_ssh_channel_close(t->st[i].ch);
  if (t->cn == CN_IDLE) {
    for (i = 0; i < TP_STREAMS; i++)        /* nothing on the wire: settle opening streams now */
      if (t->st[i].state == ST_OPENING && !t->st[i].ch) ch_on_open(&t->st[i], SD_E_SHUTDOWN);
    return;
  }
  if (t->cn == CN_DISCONNECTING) return;
  t->cn = CN_DISCONNECTING;
  if (sd_ssh_conn_disconnect(t->conn, on_disconnected, t) != SD_OK) t->cn = CN_IDLE;
}

static void tp_probe(void *ctx) { sd_ssh_conn_probe(((ssh_tp *)ctx)->conn); }

static void tp_rtt(void *ctx, uint32_t *srtt_ms, uint32_t *rttvar_ms)
{ sd_ssh_conn_rtt(((ssh_tp *)ctx)->conn, srtt_ms, rttvar_ms); }

static const sd_ssh_negotiated *tp_negotiated(void *ctx)
{
  ssh_tp *t = (ssh_tp *)ctx;
  return t->have_neg ? &t->neg : NULL;
}

static void tp_destroy(void *ctx)
{
  ssh_tp *t = (ssh_tp *)ctx;
  sd_ssh_conn_destroy(t->conn);
  sd_free(t);
}

sd_err sd_sftp_session_create(const sd_ssh_config *ssh, const sd_ssh_callbacks *ssh_cb,
                              const sd_sftp_options *opt, sd_sftp_event_cb ev, void *ev_ctx,
                              sd_sftp_session **out)
{
  ssh_tp *t;
  sd_ssh_callbacks cb;
  sd_sftp_transport tp;
  sd_err e;
  uint32_t i;
  if (!out) return SD_E_INVALID_PARAM;
  *out = NULL;
  if (!ssh) return SD_E_INVALID_PARAM;
  if ((e = sd_ssh_global_init()) != SD_OK) return e;
  t = (ssh_tp *)sd_calloc(1, sizeof(*t));
  if (!t) return SD_E_NO_MEMORY;
  for (i = 0; i < TP_STREAMS; i++) { t->st[i].t = t; t->st[i].idx = i; }
  if (ssh_cb) t->user = *ssh_cb;
  memset(&cb, 0, sizeof(cb));
  cb.ctx = t;
  cb.on_prompt = fw_prompt;
  cb.on_prompt_withdrawn = fw_withdrawn;
  cb.on_banner = fw_banner;
  cb.on_negotiated = fw_negotiated;
  cb.on_hostkey_event = fw_hostkey;
  cb.on_log = fw_log;
  e = sd_ssh_conn_create(ssh, &cb, &t->conn);
  if (e != SD_OK) { sd_free(t); return e; }
  memset(&tp, 0, sizeof(tp));
  tp.ctx = t;
  tp.post = tp_post;
  tp.is_io_thread = tp_is_io;
  tp.open = tp_open;
  tp.write = tp_write;
  tp.consumed = tp_consumed;
  tp.close = tp_close;
  tp.probe = tp_probe;
  tp.negotiated = tp_negotiated;
  tp.destroy = tp_destroy;
  tp.caps = SD_SFTP_TP_REOPEN | SD_SFTP_TP_STREAMS;
  tp.open_stream = tp_open_stream;
  tp.write_stream = tp_write_stream;
  tp.consumed_stream = tp_consumed_stream;
  tp.rtt = tp_rtt;
  e = sd_sftp_session_create_transport(&tp, opt, ev, ev_ctx, out);
  if (e != SD_OK) { tp_destroy(t); return e; }
  t->session = *out;     /* no callback can run before sd_sftp_session_start() */
  return SD_OK;
}
