/* sd_sftp over sd_ssh: the production transport. Stream 0 is the "meta" SFTP subsystem channel,
 * stream 1 the "bulk" one (D19); both live on one sd_ssh connection. The transport supports
 * SD_SFTP_TP_REOPEN: after close(), open() reconnects the same sd_ssh_conn, so the I/O thread, the
 * pinned host key and the reconnect secret cache survive (01 §8).
 * Kept in its own translation unit so test binaries that only use sd_sftp_session_create_transport()
 * do not pull in sd_ssh. Everything here runs on the connection's I/O thread except post,
 * is_io_thread, rtt and destroy. */
#include <string.h>
#include <stdio.h>

#include "sd_base/sd_mem.h"
#include "sd_platform/sd_log.h"
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
  struct pool_tp *pool;         /* the M2 pool owning this primary, if any */
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

static sd_err pool_create(ssh_tp *t, const sd_ssh_config *ssh, const sd_sftp_options *opt,
                              const sd_sftp_transport *base, sd_sftp_event_cb ev, void *ev_ctx,
                              sd_sftp_session **out);

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
  if (opt && opt->connections > 1) {
    /* the pool wraps the primary transport below and takes ownership of t on success */
    return pool_create(t, ssh, opt, &tp, ev, ev_ctx, out);
  }
  e = sd_sftp_session_create_transport(&tp, opt, ev, ev_ctx, out);
  if (e != SD_OK) { tp_destroy(t); return e; }
  t->session = *out;     /* no callback can run before sd_sftp_session_start() */
  return SD_OK;
}

/* ---- M2 connection pool (01 §10.9, 02 §5.6) ----
 *
 * pool_tp wraps the primary ssh_tp (streams 0/1, unchanged) and drives secondary members itself:
 * each member is its own sd_ssh_conn with ONE bulk SFTP channel. Members connect only after the
 * primary is READY and its authentication was non-interactive; every prompt is cancelled (a member
 * must never show UI), the host key must match without a prompt, and the member must present the
 * same host-key fingerprint and the same realpath(".") as the primary. Everything a member does
 * runs on its own I/O thread until the admit/drop decision, which is posted to the primary's I/O
 * thread (the session's) so the core sees pool changes serialized with everything else. */

#define POOL_REALPATH_CAP 512u
#define POOL_TX_CAP (1024u * 1024u)

typedef struct pool_tp pool_tp;

/* A queued chunk between the session's I/O thread and a member's I/O thread. */
typedef struct pool_blk {
  struct pool_blk *next;
  size_t len, sent;
  uint8_t data[1];
} pool_blk;

typedef struct pool_member {
  pool_tp *p;
  uint32_t idx;                        /* 1..3 */
  volatile LONG state;                 /* PM_* */
  sd_ssh_conn *conn;
  sd_ssh_channel *ch;
  sd_err err;                          /* why a member was dropped */
  char fp[128];                        /* negotiated host-key fingerprint (member thread) */
  char realpath[POOL_REALPATH_CAP];    /* the member's realpath(".") (member thread) */
  uint8_t in[1024];                    /* admission exchange input (member thread) */
  size_t in_len;
  int have_version;
  /* data streams (01 §10.9): the session's sink, driven on the primary I/O thread */
  const sd_ssh_channel_sink *sink; void *sink_ctx;
  volatile LONG sink_active;           /* primary thread sets; both threads read */
  sd_mutex qlock;
  pool_blk *rx_head, *rx_tail, *tx_head, *tx_tail;
  size_t rx_len, tx_len;
  volatile LONG rx_posted, tx_posted, consume_posted, writable_posted;
  volatile LONG credit;
  /* stats */
  uint32_t srtt_ms, rttvar_ms;
  volatile LONG64 rx, tx;
} pool_member;

enum { PM_IDLE = 0, PM_CONNECTING, PM_CHECKING, PM_READY, PM_DROPPED };

struct pool_tp {
  ssh_tp *primary;
  sd_sftp_session *session;
  const sd_ssh_config *cfg;            /* the caller's config (primary template) */
  sd_ssh_callbacks user;               /* the caller's callbacks */
  uint32_t target;                     /* 1..4 */
  volatile LONG disabled;              /* host-key trouble: no admissions for the session lifetime */
  uint32_t generation;                 /* admissions of the current session generation */
  int gen_stopped;                   /* identity mismatch: no more admissions this generation */
  char primary_realpath[POOL_REALPATH_CAP];
  pool_member m[3];                    /* members 1..3 */
};

static void member_on_connected(void *ctx, sd_err err, uint32_t failed_hop);
static void member_teardown(pool_member *m);
static void member_q_reset(pool_member *m);
static void member_stream_closed(void *arg);

/* ---- primary-thread helpers (posted decisions) ---- */

typedef struct pool_decide { pool_tp *p; uint32_t idx; int admitted; sd_err err; char fp[128]; char rp[POOL_REALPATH_CAP]; } pool_decide;

static void pool_start_next(pool_tp *p);

static void pool_decided(void *arg)
{
  pool_decide *d = (pool_decide *)arg;
  pool_tp *p = d->p;
  pool_member *m = &p->m[d->idx - 1];
  ssh_tp *t = p->primary;
  if (m->state != PM_CHECKING) { sd_free(d); return; }    /* closed meanwhile */
  if (d->admitted) {
    /* same server as the primary? (DNS round robin / load balancer, 01 §10.9) */
    if (!d->fp[0] || !t->have_neg || strcmp(d->fp, t->hostkey_fp) != 0) {
      d->admitted = 0;               /* not the same server: stop pooling for this generation */
      d->err = SD_E_HOSTKEY_MISMATCH;
      p->gen_stopped = 1;
      member_teardown(m);
    } else if (strcmp(d->rp, p->primary_realpath) != 0) {
      d->admitted = 0;
      d->err = SD_E_NOT_FOUND;
      p->gen_stopped = 1;
      member_teardown(m);
    }
  }
  if (!d->admitted) {
    m->state = PM_DROPPED;
    m->err = d->err;
    sd_log(SD_LOG_INFO, SFTP_COMP, NULL, "pool: member %u dropped: %s", d->idx, sd_err_name(d->err));
    sftp_session_pool_change(p->session, d->idx, 0, d->err);
  } else {
    m->state = PM_READY;
    sd_log(SD_LOG_INFO, SFTP_COMP, NULL, "pool: member %u ready", d->idx);
    sftp_session_pool_change(p->session, d->idx, 1, SD_OK);
  }
  sd_free(d);
  pool_start_next(p);                  /* one at a time, no bursts (01 §10.9) */
}

/* Runs on the primary I/O thread. */
static void pool_start_next(pool_tp *p)
{
  uint32_t i;
  if (p->disabled || p->gen_stopped || !p->session) return;
  for (i = 0; i < 3; i++) {
    pool_member *m = &p->m[i];
    if (m->state != PM_IDLE) continue;
    if (i + 1 >= p->target) return;    /* target reached (primary counts as member 0) */
    m->state = PM_CONNECTING;
    m->err = SD_OK;
    if (sd_ssh_conn_connect(m->conn, member_on_connected, m) != SD_OK) {
      m->state = PM_DROPPED;           /* conn_create problems are structural: do not retry */
      sftp_session_pool_change(p->session, i + 1, 0, SD_E_INTERNAL);
      continue;
    }
    return;
  }
}

/* ---- member side: everything below runs on the member's I/O thread ---- */

static void member_drop(pool_member *m, sd_err err);

/* The admit/drop decision for the member, posted to the primary thread. */
static void member_decide(pool_member *m, int admitted, sd_err err)
{
  pool_decide *d = (pool_decide *)sd_calloc(1, sizeof(*d));
  if (!d) { member_drop(m, SD_E_NO_MEMORY); return; }
  d->p = m->p;
  d->idx = m->idx;
  d->admitted = admitted;
  d->err = err;
  memcpy(d->fp, m->fp, sizeof(d->fp));
  memcpy(d->rp, m->realpath, sizeof(d->rp));
  if (sd_ssh_conn_post(m->p->primary->conn, pool_decided, d) != SD_OK) {
    sd_free(d);
    m->state = PM_DROPPED;
  }
}

/* Closes the member's channel and connection (any thread; non-blocking). */
static void member_teardown(pool_member *m)
{
  InterlockedExchange(&m->sink_active, 0);
  if (m->ch) { sd_ssh_channel_close(m->ch); m->ch = NULL; }
  if (m->conn) sd_ssh_conn_disconnect(m->conn, NULL, NULL);
}

static void member_drop(pool_member *m, sd_err err)
{
  m->err = err;
  member_decide(m, 0, err);
  member_teardown(m);
}

/* Admitted: hand the result to the primary thread (comparison happens there). */
static void member_check_done(pool_member *m)
{
  member_decide(m, 1, SD_OK);
  /* the channel stays open; the primary closes it with the pool */
}

/* Sends one length-framed SFTP packet (the wire format of the session core, sftp_proto.h).
   version_present: an SSH_FXP_INIT with its version field; path: one path argument. */
static void member_send(pool_member *m, uint8_t type, int id_present, uint32_t id, int version_present,
                        const char *path)
{
  sd_wr w;
  size_t st, acc = 0, len;
  sd_err e;
  sd_wr_init(&w, 256);
  st = sftp_pkt_begin(&w, type, id_present, id);
  if (version_present) sd_wr_u32(&w, 3);   /* SFTP v3, like the session core */
  if (path) sd_wr_cstring(&w, path);
  sftp_pkt_end(&w, st);
  len = w.len;
  e = sd_wr_ok(&w) ? sd_ssh_channel_write(m->ch, w.p, w.len, &acc) : SD_E_NO_MEMORY;
  sd_wr_free(&w);
  if (e != SD_OK) member_drop(m, e);
}

/* Parses one SFTP payload (without the length prefix) and drives the admission exchange. */
static void member_on_packet(pool_member *m, const uint8_t *p, size_t n)
{
  sd_rd r;
  uint8_t type;
  sd_rd_init(&r, p, n);
  type = sd_rd_u8(&r);
  if (!m->have_version) {
    uint32_t version;
    if (type != SFTP_VERSION) { member_drop(m, SD_E_PROTOCOL); return; }
    version = sd_rd_u32(&r);
    if (!sd_rd_ok(&r) || version < 3 || version > 6) { member_drop(m, SD_E_PROTOCOL); return; }
    m->have_version = 1;
    member_send(m, (uint8_t)SFTP_REALPATH, 1, 2, 0, ".");   /* private id space */
    return;
  }
  if (type == SFTP_NAME) {
    uint32_t count;
    (void)sd_rd_u32(&r);                /* the request id of our REALPATH */
    count = sd_rd_u32(&r);
    {
      sd_span nm = sd_rd_string(&r, SFTP_MAX_PATH);
      if (!sd_rd_ok(&r) || count < 1 || nm.n >= POOL_REALPATH_CAP) { member_drop(m, SD_E_PROTOCOL); return; }
      memcpy(m->realpath, nm.p, nm.n);
      m->realpath[nm.n] = 0;
    }
    member_check_done(m);
    return;
  }
  if (type == SFTP_STATUS) {
    uint32_t code;
    (void)sd_rd_u32(&r);                /* id */
    code = sd_rd_u32(&r);
    member_drop(m, sd_rd_ok(&r) ? sd_sftp_status_to_err(code) : SD_E_PROTOCOL);
    return;
  }
  member_drop(m, SD_E_PROTOCOL);
}

/* ---- member data proxy (01 §10.9) ----
 *
 * The session drives member streams from the PRIMARY connection's I/O thread, but a member's SFTP
 * channel lives on the member's own I/O thread. Bytes travel through two queues:
 *   RX: member thread -> rx queue -> posted drain on the primary thread -> the session's sink.
 *       The channel is credited only when the session consumed the bytes, so the queues stay
 *       bounded by the SSH receive window.
 *   TX: session (primary thread) -> bounded tx queue -> posted pump on the member thread, which
 *       writes to the channel and reports progress back with on_writable.
 * Only the member thread touches the channel; only the primary thread calls the session's sink. */

static pool_blk *pool_blk_new(const uint8_t *p, size_t n)
{
  pool_blk *b = (pool_blk *)sd_alloc(sizeof(*b) + n);
  if (!b) return NULL;
  b->next = NULL;
  b->len = n;
  b->sent = 0;
  if (p && n) memcpy(b->data, p, n);
  return b;
}

static void pool_q_free(pool_blk *b)
{
  while (b) { pool_blk *n = b->next; sd_free(b); b = n; }
}

/* An active data stream? Written under qlock by open/close, read by both threads. */
static int member_stream_live(pool_member *m)
{
  return InterlockedCompareExchange(&m->sink_active, 1, 1) != 0;
}

static void member_rx_drain(void *arg);

/* Member thread: queue received bytes and make sure the primary thread will drain them. */
static void member_rx_enqueue(pool_member *m, const uint8_t *p, size_t n)
{
  pool_blk *b;
  LONG first;
  if (!n) return;
  b = pool_blk_new(p, n);
  if (!b) { member_drop(m, SD_E_NO_MEMORY); return; }
  sd_mutex_lock(&m->qlock);
  if (m->rx_tail) m->rx_tail->next = b; else m->rx_head = b;
  m->rx_tail = b;
  m->rx_len += n;
  first = InterlockedExchange(&m->rx_posted, 1) == 0;
  sd_mutex_unlock(&m->qlock);
  if (first && sd_ssh_conn_post(m->p->primary->conn, member_rx_drain, m) != SD_OK)
    InterlockedExchange(&m->rx_posted, 0);
}

/* Primary thread: deliver queued bytes to the session, in order. */
static void member_rx_drain(void *arg)
{
  pool_member *m = (pool_member *)arg;
  for (;;) {
    pool_blk *b, *next;
    sd_mutex_lock(&m->qlock);
    b = m->rx_head;
    m->rx_head = m->rx_tail = NULL;
    m->rx_len = 0;
    if (!b) { InterlockedExchange(&m->rx_posted, 0); sd_mutex_unlock(&m->qlock); return; }
    sd_mutex_unlock(&m->qlock);
    for (; b; b = next) {
      next = b->next;
      if (member_stream_live(m) && m->sink) m->sink->on_data(m->sink_ctx, b->data, b->len);
      sd_free(b);
    }
  }
}

static void member_tx_pump(void *arg);
static void member_stream_writable(void *arg);
static void member_consume_drain(void *arg);

/* Primary thread: the session's consumed() credit goes back to the member thread. */
static void pool_consumed_stream(void *ctx, uint32_t idx, size_t n)
{
  ssh_tp *t = (ssh_tp *)ctx;
  pool_tp *p = t->pool;
  pool_member *m;
  if (idx < 2) { tp_consumed_stream(ctx, idx, n); return; }
  if (idx > 4 || !p || !n) return;
  m = &p->m[idx - 2];
  InterlockedExchangeAdd(&m->credit, (LONG)n);
  if (InterlockedExchange(&m->consume_posted, 1) == 0)
    if (sd_ssh_conn_post(m->conn, member_consume_drain, m) != SD_OK)
      InterlockedExchange(&m->consume_posted, 0);
}

/* Member thread: hand the accumulated credit to the channel. */
static void member_consume_drain(void *arg)
{
  pool_member *m = (pool_member *)arg;
  for (;;) {
    LONG n = InterlockedExchange(&m->credit, 0);
    if (n > 0 && m->ch) sd_ssh_channel_consumed(m->ch, (size_t)n);
    InterlockedExchange(&m->consume_posted, 0);
    if (m->credit == 0) return;
  }
}

/* Member thread: write queued bytes, then tell the session there is space again. */
static void member_tx_pump(void *arg)
{
  pool_member *m = (pool_member *)arg;
  int freed = 0;
  for (;;) {
    pool_blk *b;
    size_t accepted = 0;
    sd_err e;
    sd_mutex_lock(&m->qlock);
    b = m->tx_head;
    if (!b) {
      m->tx_tail = NULL;
      m->tx_len = 0;
      InterlockedExchange(&m->tx_posted, 0);
      sd_mutex_unlock(&m->qlock);
      break;
    }
    sd_mutex_unlock(&m->qlock);
    if (!m->ch || m->state != PM_READY) {
      InterlockedExchange(&m->tx_posted, 0);
      break;
    }
    e = sd_ssh_channel_write(m->ch, b->data + b->sent, b->len - b->sent, &accepted);
    if (e != SD_OK) {
      InterlockedExchange(&m->tx_posted, 0);
      member_drop(m, e);
      return;
    }
    sd_atomic_add64(&m->tx, (LONG64)accepted);
    b->sent += accepted;
    if (b->sent == b->len) {
      sd_mutex_lock(&m->qlock);
      if (m->tx_head == b) { m->tx_head = b->next; if (!m->tx_head) m->tx_tail = NULL; }
      if (m->tx_len >= b->len) m->tx_len -= b->len; else m->tx_len = 0;
      sd_mutex_unlock(&m->qlock);
      sd_free(b);
      freed = 1;
      continue;
    }
    InterlockedExchange(&m->tx_posted, 0);   /* window closed: on_writable resumes */
    break;
  }
  if (freed && member_stream_live(m) && InterlockedExchange(&m->writable_posted, 1) == 0)
    if (sd_ssh_conn_post(m->p->primary->conn, member_stream_writable, m) != SD_OK)
      InterlockedExchange(&m->writable_posted, 0);
}

/* Primary thread: the session may write again on this member stream. */
static void member_stream_writable(void *arg)
{
  pool_member *m = (pool_member *)arg;
  InterlockedExchange(&m->writable_posted, 0);
  if (member_stream_live(m) && m->sink && m->sink->on_writable) m->sink->on_writable(m->sink_ctx);
}

/* Primary thread: queue bytes for a member stream (bounded; 0 accepted means wait for
   on_writable). Never blocks: the member thread does the channel write. */
static sd_err pool_write_stream(void *ctx, uint32_t idx, const uint8_t *p, size_t n, size_t *accepted)
{
  ssh_tp *t = (ssh_tp *)ctx;
  pool_tp *p_ = t->pool;
  pool_member *m;
  pool_blk *b;
  size_t space, take;
  LONG first = 0;
  if (accepted) *accepted = 0;
  if (idx < 2) return tp_write_stream(ctx, idx, p, n, accepted);
  if (!p_ || idx > 4) return SD_E_INVALID_PARAM;
  m = &p_->m[idx - 2];
  if (m->state != PM_READY || !member_stream_live(m)) return SD_E_DISCONNECTED;
  if (!n) return SD_OK;
  sd_mutex_lock(&m->qlock);
  space = m->tx_len < POOL_TX_CAP ? POOL_TX_CAP - m->tx_len : 0;
  take = n < space ? n : space;
  b = take ? pool_blk_new(p, take) : NULL;
  if (take && !b) { sd_mutex_unlock(&m->qlock); return SD_E_NO_MEMORY; }
  if (b) {
    if (m->tx_tail) m->tx_tail->next = b; else m->tx_head = b;
    m->tx_tail = b;
    m->tx_len += take;
    first = InterlockedExchange(&m->tx_posted, 1) == 0;
  }
  sd_mutex_unlock(&m->qlock);
  if (accepted) *accepted = take;
  if (first && sd_ssh_conn_post(m->conn, member_tx_pump, m) != SD_OK)
    InterlockedExchange(&m->tx_posted, 0);
  return SD_OK;
}

/* Member thread: the channel died while it carried a session stream. */
static void member_stream_closed(void *arg)
{
  pool_member *m = (pool_member *)arg;
  m->sink_active = 0;
  if (m->sink) m->sink->on_closed(m->sink_ctx, m->err != SD_OK ? m->err : SD_E_DISCONNECTED);
}

static void member_ch_on_data(void *ctx, const uint8_t *p, size_t n)
{
  pool_member *m = (pool_member *)ctx;
  sd_atomic_add64(&m->rx, (LONG64)n);
  if (m->state == PM_READY && member_stream_live(m)) {   /* data plane: proxy to the session */
    member_rx_enqueue(m, p, n);
    return;
  }
  if (m->ch) sd_ssh_channel_consumed(m->ch, n);
  if (m->state != PM_CHECKING) return;
  /* length-framed stream: uint32 length, then the payload (sftp_proto.h) */
  while (n) {
    size_t take = SD_MIN(n, sizeof(m->in) - m->in_len);
    if (!take) { member_drop(m, SD_E_PROTOCOL); return; }
    memcpy(m->in + m->in_len, p, take);
    m->in_len += take;
    p += take;
    n -= take;
    while (m->state == PM_CHECKING && m->in_len >= 4) {
      uint32_t len = sd_load_be32(m->in);
      if (len < 1 || len > sizeof(m->in) - 4) { member_drop(m, SD_E_PROTOCOL); return; }
      if (m->in_len < 4 + (size_t)len) break;
      member_on_packet(m, m->in + 4, len);
      memmove(m->in, m->in + 4 + len, m->in_len - 4 - len);
      m->in_len -= 4 + len;
    }
    if (m->state != PM_CHECKING) return;
  }
}

static void member_ch_on_writable(void *ctx)
{
  pool_member *m = (pool_member *)ctx;
  if (m->state != PM_READY || !member_stream_live(m)) return;
  if (InterlockedExchange(&m->tx_posted, 1) == 0)
    if (sd_ssh_conn_post(m->conn, member_tx_pump, m) != SD_OK) InterlockedExchange(&m->tx_posted, 0);
}

static void member_ch_on_eof(void *ctx)
{
  pool_member *m = (pool_member *)ctx;
  SD_UNUSED(m);   /* EOF is followed by on_closed, which is what the session acts on */
}

/* Sends the INIT from a posted function: on_open can run before sd_ssh_channel_open_subsystem()
   returned and set m->ch, so writing directly in the callback would race the pointer. */
static void member_send_init(void *arg)
{
  pool_member *m = (pool_member *)arg;
  if (m->state != PM_CHECKING || !m->ch) return;
  member_send(m, (uint8_t)SFTP_INIT, 0, 0, 1, NULL);
}

static void member_ch_on_open(void *ctx, sd_err err)
{
  pool_member *m = (pool_member *)ctx;
  if (m->state != PM_CHECKING) return;
  if (err != SD_OK) { m->ch = NULL; member_drop(m, err); return; }
  if (sd_ssh_conn_post(m->conn, member_send_init, m) != SD_OK) member_drop(m, SD_E_INTERNAL);
}

static void member_ch_on_closed(void *ctx, sd_err why)
{
  pool_member *m = (pool_member *)ctx;
  m->ch = NULL;
  member_q_reset(m);
  if (m->state == PM_READY && member_stream_live(m)) {
    /* a session stream lived here: report it on the primary thread, which calls member_lost */
    m->err = why != SD_OK ? why : SD_E_DISCONNECTED;
    m->state = PM_DROPPED;
    InterlockedExchange(&m->sink_active, 0);
    (void)sd_ssh_conn_post(m->p->primary->conn, member_stream_closed, m);
    return;
  }
  if (m->state == PM_CHECKING || m->state == PM_READY)
    member_drop(m, why != SD_OK ? why : SD_E_DISCONNECTED);
}

static const sd_ssh_channel_sink k_member_sink = {
  member_ch_on_open, member_ch_on_data, member_ch_on_writable, member_ch_on_eof, member_ch_on_closed
};

static void member_on_connected(void *ctx, sd_err err, uint32_t failed_hop)
{
  pool_member *m = (pool_member *)ctx;
  SD_UNUSED(failed_hop);
  if (m->state != PM_CONNECTING) return;
  if (err != SD_OK) { member_drop(m, err); return; }
  m->state = PM_CHECKING;
  {
    sd_ssh_channel *ch = NULL;
    sd_err e = sd_ssh_channel_open_subsystem(m->conn, "sftp", &k_member_sink, m, &ch);
    if (e != SD_OK) member_drop(m, e);
    else m->ch = ch;
  }
}

/* A pool member never shows UI: every prompt is cancelled (01 §10.9). The cancelled prompt fails
   the member's connect, which takes the normal drop path with the real error. */
static void member_fw_prompt(void *ctx, sd_prompt *p, const sd_auth_prompt_info *a,
                             const sd_hostkey_prompt_info *h)
{
  SD_UNUSED(ctx); SD_UNUSED(a); SD_UNUSED(h);
  sd_prompt_cancel(p);
}

static void member_fw_hostkey(void *ctx, const sd_hostkey_event *e)
{
  pool_member *m = (pool_member *)ctx;
  if (e->kind != SD_HKEV_MISMATCH && e->kind != SD_HKEV_REVOKED) return;
  /* serious: the host changed under us. Report through the user's callback and stop pooling. */
  InterlockedExchange(&m->p->disabled, 1);
  if (m->p->user.on_hostkey_event) m->p->user.on_hostkey_event(m->p->user.ctx, e);
}

static void member_fw_negotiated(void *ctx, const sd_ssh_negotiated *n)
{
  pool_member *m = (pool_member *)ctx;
  if (n && n->hostkey_fp_sha256) copy_cstr(m->fp, sizeof(m->fp), n->hostkey_fp_sha256);
}

static void member_fw_log(void *ctx, int level, const char *msg)
{
  pool_tp *p = ((pool_member *)ctx)->p;
  if (p->user.on_log) p->user.on_log(p->user.ctx, level, msg);
}

/* ---- pool transport vtable (primary passthrough + pool ops) ---- */

static void pool_notify_ready(void *ctx, const char *realpath_dot)
{
  ssh_tp *t = (ssh_tp *)ctx;
  pool_tp *p = t->pool;
  sd_ssh_auth_info ai;
  uint32_t i;
  copy_cstr(p->primary_realpath, sizeof(p->primary_realpath), realpath_dot);
  for (i = 0; i < 3; i++) {
    /* a new generation: every member admits again (the primary reconnect dropped them) */
    pool_member *m = &p->m[i];
    if (m->state != PM_IDLE) {
      m->state = PM_IDLE;             /* before the teardown: its on_closed is then a no-op */
      InterlockedExchange(&m->sink_active, 0);
      member_teardown(m);
      m->have_version = 0;
      m->in_len = 0;
      m->err = SD_OK;
    }
  }
  p->gen_stopped = 0;
  if (p->target <= 1 || p->disabled) return;
  if (sd_ssh_conn_auth_info(t->conn, &ai) != SD_OK) return;
  if (!ai.noninteractive) {
    sd_log(SD_LOG_INFO, SFTP_COMP, NULL, "pool: staying at 1 connection: authentication was interactive");
    return;
  }
  pool_start_next(p);
}

static void member_stream_opened(void *arg)
{
  pool_member *m = (pool_member *)arg;
  if (member_stream_live(m) && m->sink) m->sink->on_open(m->sink_ctx, SD_OK);
}

/* Opens the session stream on an admitted member (called on the primary I/O thread). */
static sd_err pool_open_stream(void *ctx, uint32_t idx, const sd_ssh_channel_sink *sink, void *sink_ctx)
{
  ssh_tp *t = (ssh_tp *)ctx;
  pool_tp *p = t->pool;
  pool_member *m;
  if (idx < 2) return tp_open_stream(ctx, idx, sink, sink_ctx);
  if (!p || idx > 4) return SD_E_INVALID_PARAM;
  m = &p->m[idx - 2];
  if (m->idx != idx - 1 || m->state != PM_READY || !m->ch) return SD_E_DISCONNECTED;
  sd_mutex_lock(&m->qlock);
  m->sink = sink;
  m->sink_ctx = sink_ctx;
  sd_mutex_unlock(&m->qlock);
  InterlockedExchange(&m->sink_active, 1);
  if (sd_ssh_conn_post(t->conn, member_stream_opened, m) != SD_OK) {
    InterlockedExchange(&m->sink_active, 0);
    return SD_E_DISCONNECTED;
  }
  return SD_OK;                       /* on_open arrives asynchronously, on the primary thread */
}

static void pool_member_stats(void *ctx, sd_sftp_conn_stats out[3], uint32_t *count)
{
  pool_tp *p = ((ssh_tp *)ctx)->pool;
  uint32_t i, n = 0;
  for (i = 0; i < 3; i++) {
    pool_member *m = &p->m[i];
    if (m->state != PM_READY || !out) continue;
    memset(&out[m->idx - 1], 0, sizeof(out[m->idx - 1]));
    out[m->idx - 1].ready = 1;
    if (m->conn) sd_ssh_conn_rtt(m->conn, &out[m->idx - 1].srtt_ms, &out[m->idx - 1].rttvar_ms);
    out[m->idx - 1].rx_total = (uint64_t)sd_atomic_load64(&m->rx);
    out[m->idx - 1].tx_total = (uint64_t)sd_atomic_load64(&m->tx);
    out[m->idx - 1].inflight_reqs = 0;
    n++;
  }
  if (count) *count = n;
}

static void pool_close_members(pool_tp *p)
{
  uint32_t i;
  for (i = 0; i < 3; i++) {
    pool_member *m = &p->m[i];
    int live = m->state == PM_READY || m->state == PM_CHECKING || m->state == PM_CONNECTING;
    m->state = PM_IDLE;               /* first: the teardown's on_closed must not report a drop */
    InterlockedExchange(&m->sink_active, 0);
    if (live) member_teardown(m);
  }
}

static void pool_tp_close(void *ctx)
{
  pool_tp *p = ((ssh_tp *)ctx)->pool;
  pool_close_members(p);
  tp_close(p->primary);
}

static void member_q_reset(pool_member *m)
{
  pool_blk *rx, *tx;
  sd_mutex_lock(&m->qlock);
  rx = m->rx_head;
  tx = m->tx_head;
  m->rx_head = m->rx_tail = m->tx_head = m->tx_tail = NULL;
  m->rx_len = m->tx_len = 0;
  InterlockedExchange(&m->rx_posted, 0);     /* a drain still queued finds nothing to do */
  InterlockedExchange(&m->tx_posted, 0);
  sd_mutex_unlock(&m->qlock);
  pool_q_free(rx);
  pool_q_free(tx);
}

static void pool_tp_destroy(void *ctx)
{
  pool_tp *p = ((ssh_tp *)ctx)->pool;
  uint32_t i;
  if (!p) { tp_destroy(ctx); return; }
  for (i = 0; i < 3; i++) {
    pool_member *m = &p->m[i];
    InterlockedExchange(&m->sink_active, 0);
    if (m->conn) { sd_ssh_channel_close(m->ch); sd_ssh_conn_destroy(m->conn); m->conn = NULL; }
    member_q_reset(m);
    sd_mutex_destroy(&m->qlock);
  }
  tp_destroy(p->primary);
  sd_free(p);
}

/* Builds the pool around the primary transport `base` (already created over t). */
static sd_err pool_create(ssh_tp *t, const sd_ssh_config *ssh, const sd_sftp_options *opt,
                          const sd_sftp_transport *base, sd_sftp_event_cb ev, void *ev_ctx,
                          sd_sftp_session **out)
{
  pool_tp *p;
  sd_ssh_config mcfg;
  sd_ssh_callbacks mcb;
  sd_err e;
  uint32_t i, target = opt->connections > 4 ? 4 : opt->connections;

  p = (pool_tp *)sd_calloc(1, sizeof(*p));
  if (!p) { tp_destroy(t); return SD_E_NO_MEMORY; }
  p->primary = t;
  p->cfg = ssh;
  p->user = t->user;                   /* the primary kept the caller's callbacks */
  p->target = target;

  mcfg = *ssh;
  mcfg.flags |= SD_SSH_CFG_POOL_MEMBER;
  memset(&mcb, 0, sizeof(mcb));
  mcb.ctx = NULL;                      /* filled per member below */
  mcb.on_prompt = member_fw_prompt;
  mcb.on_hostkey_event = member_fw_hostkey;
  mcb.on_negotiated = member_fw_negotiated;
  mcb.on_log = member_fw_log;
  for (i = 0; i < 3; i++) {
    pool_member *m = &p->m[i];
    m->p = p;
    m->idx = i + 1;
    sd_mutex_init(&m->qlock);
    mcb.ctx = m;
    e = sd_ssh_conn_create(&mcfg, &mcb, &m->conn);
    if (e != SD_OK) {
      /* fewer members is fine; the pool runs smaller (01 §10.9) */
      m->conn = NULL;
      sd_log(SD_LOG_WARN, SFTP_COMP, NULL, "pool: member %u could not be created: %s", m->idx,
             sd_err_name(e));
    }
  }
  {
    sd_sftp_transport tp = *base;      /* the primary passthrough; ctx stays the ssh_tp */
    t->pool = p;
    tp.open_stream = pool_open_stream;
    tp.write_stream = pool_write_stream;
    tp.consumed_stream = pool_consumed_stream;
    tp.close = pool_tp_close;
    tp.destroy = pool_tp_destroy;
    tp.notify_ready = pool_notify_ready;
    tp.member_stats = pool_member_stats;
    tp.caps |= SD_SFTP_TP_POOL;
    e = sd_sftp_session_create_transport(&tp, opt, ev, ev_ctx, out);
    if (e != SD_OK) { t->pool = p; pool_tp_destroy(t); return e; }
  }
  p->session = *out;
  t->session = *out;
  return SD_OK;
}
