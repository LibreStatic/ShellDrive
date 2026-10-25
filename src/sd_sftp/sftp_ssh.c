/* sd_sftp over sd_ssh: the production transport (an "sftp" subsystem channel on one connection).
 * Kept in its own translation unit so test binaries that only use sd_sftp_session_create_transport()
 * do not pull in sd_ssh. */
#include <string.h>

#include "sd_base/sd_mem.h"
#include "sftp_internal.h"

typedef struct ssh_tp {
  sd_ssh_conn *conn;
  sd_ssh_channel *ch;
  const sd_ssh_channel_sink *sink;
  void *sink_ctx;
  sd_ssh_callbacks user;          /* caller's callbacks (ctx inside) */
  int opened, closed, open_reported, ch_closed;
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
{ ssh_tp *t = (ssh_tp *)ctx; if (t->user.on_prompt) t->user.on_prompt(t->user.ctx, p, a, h); }
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

/* ---- transport ops ---- */

static sd_err tp_post(void *ctx, void (*fn)(void *), void *arg)
{ return sd_ssh_conn_post(((ssh_tp *)ctx)->conn, fn, arg); }

static int tp_is_io(void *ctx) { return sd_ssh_conn_is_io_thread(((ssh_tp *)ctx)->conn); }

/* Channel sink wrapper: tracks the channel lifetime (sd_ssh: the pointer is valid until on_closed
   returns, or until a failed on_open returns) and forwards to the session. */
static void ch_on_open(void *ctx, sd_err err)
{
  ssh_tp *t = (ssh_tp *)ctx;
  if (t->open_reported) return;
  t->open_reported = 1;
  if (err != SD_OK) { t->ch = NULL; t->ch_closed = 1; }
  t->sink->on_open(t->sink_ctx, err);
}
static void ch_on_data(void *ctx, const uint8_t *p, size_t n)
{ ssh_tp *t = (ssh_tp *)ctx; t->sink->on_data(t->sink_ctx, p, n); }
static void ch_on_writable(void *ctx)
{ ssh_tp *t = (ssh_tp *)ctx; t->sink->on_writable(t->sink_ctx); }
static void ch_on_eof(void *ctx)
{ ssh_tp *t = (ssh_tp *)ctx; t->sink->on_eof(t->sink_ctx); }
static void ch_on_closed(void *ctx, sd_err why)
{
  ssh_tp *t = (ssh_tp *)ctx;
  t->ch = NULL;
  t->ch_closed = 1;
  t->sink->on_closed(t->sink_ctx, why);
}
static const sd_ssh_channel_sink k_ch_sink = { ch_on_open, ch_on_data, ch_on_writable, ch_on_eof, ch_on_closed };

static void on_connected(void *ctx, sd_err err, uint32_t failed_hop)
{
  ssh_tp *t = (ssh_tp *)ctx;
  sd_ssh_channel *ch = NULL;
  SD_UNUSED(failed_hop);
  if (err == SD_OK) {
    err = sd_ssh_channel_open_subsystem(t->conn, "sftp", &k_ch_sink, t, &ch);
    if (err == SD_OK && !t->ch_closed) t->ch = ch;   /* on_open may already have failed synchronously */
  }
  if (err != SD_OK) ch_on_open(t, err);
}

static sd_err tp_open(void *ctx, const sd_ssh_channel_sink *sink, void *sink_ctx)
{
  ssh_tp *t = (ssh_tp *)ctx;
  t->sink = sink;
  t->sink_ctx = sink_ctx;
  t->opened = 1;
  return sd_ssh_conn_connect(t->conn, on_connected, t);
}

static sd_err tp_write(void *ctx, const uint8_t *p, size_t n, size_t *accepted)
{
  ssh_tp *t = (ssh_tp *)ctx;
  if (!t->ch) { *accepted = 0; return SD_E_DISCONNECTED; }
  return sd_ssh_channel_write(t->ch, p, n, accepted);
}

static void tp_consumed(void *ctx, size_t n)
{
  ssh_tp *t = (ssh_tp *)ctx;
  if (t->ch) sd_ssh_channel_consumed(t->ch, n);
}

static void on_disconnected(void *ctx, sd_err err, uint32_t failed_hop)
{
  SD_UNUSED(ctx); SD_UNUSED(err); SD_UNUSED(failed_hop);
}

static void report_closed(void *ctx)
{
  ssh_tp *t = (ssh_tp *)ctx;
  if (t->ch_closed) return;
  t->ch_closed = 1;
  t->sink->on_closed(t->sink_ctx, SD_E_SHUTDOWN);
}

/* Session close: close the channel (its on_closed is the session's on_closed), then the connection.
   Without an open channel the session's on_closed is reported here. */
static void tp_close(void *ctx)
{
  ssh_tp *t = (ssh_tp *)ctx;
  int had_channel = t->ch != NULL;
  if (t->closed) return;
  t->closed = 1;
  if (had_channel) sd_ssh_channel_close(t->ch);
  (void)sd_ssh_conn_disconnect(t->conn, on_disconnected, t);
  if (!had_channel && !t->ch_closed && t->sink && sd_ssh_conn_post(t->conn, report_closed, t) != SD_OK)
    t->ch_closed = 1;
}

static void tp_probe(void *ctx) { sd_ssh_conn_probe(((ssh_tp *)ctx)->conn); }

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
  if (!out) return SD_E_INVALID_PARAM;
  *out = NULL;
  if (!ssh) return SD_E_INVALID_PARAM;
  if ((e = sd_ssh_global_init()) != SD_OK) return e;
  t = (ssh_tp *)sd_calloc(1, sizeof(*t));
  if (!t) return SD_E_NO_MEMORY;
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
  e = sd_sftp_session_create_transport(&tp, opt, ev, ev_ctx, out);
  if (e != SD_OK) tp_destroy(t);
  return e;
}
