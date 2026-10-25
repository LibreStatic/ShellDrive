/* Channels (RFC 4254 §5-§6; 01 §4.8): session channels with "subsystem" or "exec", window flow
 * control, EOF/CLOSE. Inbound CHANNEL_OPEN is refused in conn.c.
 *
 * Lifetime of an sd_ssh_channel: created by open_*; valid until on_closed(why) returns, or until
 * on_open(err != SD_OK) returns (a failed open never gets on_closed). sd_ssh frees it afterwards. */
#include <string.h>

#include "sd_base/sd_mem.h"
#include "conn_internal.h"

static void ch_free(sd_ssh_channel *ch)
{
  sd_free(ch->arg);
  sd_free(ch);
}

static void ch_release_slot(sd_ssh_conn *c, sd_ssh_channel *ch)
{
  if (ch->local_id < SSH_MAX_CHANNELS && c->ch[ch->local_id] == ch) c->ch[ch->local_id] = NULL;
}

/* Delivers the terminal callback and frees the channel. */
static void ch_finish(sd_ssh_conn *c, sd_ssh_channel *ch, sd_err why)
{
  ch_release_slot(c, ch);
  ch->state = SSH_CH_DEAD;
  if (ch->opened) { if (ch->sink.on_closed) ch->sink.on_closed(ch->ctx, why); }
  else if (ch->sink.on_open) ch->sink.on_open(ch->ctx, why == SD_OK ? SD_E_FAILURE : why);
  ch_free(ch);
}

static void send_close(sd_ssh_conn *c, sd_ssh_channel *ch)
{
  uint8_t b[8];
  if (ch->close_sent || !ch->have_remote) return;
  b[0] = SSH_MSG_CHANNEL_CLOSE;
  sd_store_be32(b + 1, ch->remote_id);
  ch->close_sent = 1;
  ssh_send(c, b, 5);
}

/* ---- open ---- */

typedef struct ch_cmd { ssh_cmd cmd; sd_ssh_channel *ch; uint32_t serial; int close; } ch_cmd;

static volatile LONG g_ch_serial;

/* For commands posted from other threads: the channel may have been freed meanwhile. */
static sd_ssh_channel *ch_lookup(sd_ssh_conn *c, sd_ssh_channel *ch, uint32_t serial)
{
  uint32_t i;
  for (i = 0; i < SSH_MAX_CHANNELS; i++)
    if (c->ch[i] == ch && ch->serial == serial) return ch;
  return NULL;
}

/* Returns 1 when the channel was registered; otherwise on_open(err) ran and ch is freed. */
static int open_now(sd_ssh_conn *c, sd_ssh_channel *ch)
{
  uint32_t i;
  sd_wr w;
  if (c->st != SSH_ST_CONNECTED || c->failing) {
    if (ch->sink.on_open) ch->sink.on_open(ch->ctx, SD_E_DISCONNECTED);
    ch_free(ch);
    return 0;
  }
  for (i = 0; i < SSH_MAX_CHANNELS && c->ch[i]; i++) {}
  if (i == SSH_MAX_CHANNELS) {
    if (ch->sink.on_open) ch->sink.on_open(ch->ctx, SD_E_BUSY);
    ch_free(ch);
    return 0;
  }
  c->ch[i] = ch;
  ch->local_id = i;
  ch->local_window = SSH_CH_WINDOW;
  ch->state = SSH_CH_OPENING;
  ch->deadline = ssh_now() + c->connect_timeout_ms;
  sd_wr_init(&w, 256);
  sd_wr_u8(&w, SSH_MSG_CHANNEL_OPEN);
  sd_wr_cstring(&w, "session");
  sd_wr_u32(&w, ch->local_id);
  sd_wr_u32(&w, SSH_CH_WINDOW);
  sd_wr_u32(&w, SSH_CH_MAXPKT);
  ssh_send_wr(c, &w);
  return 1;
}

static void ch_cmd_run(sd_ssh_conn *c, ssh_cmd *cmd)
{
  ch_cmd *cc = (ch_cmd *)cmd;
  sd_ssh_channel *ch = cc->ch;
  uint32_t serial = cc->serial;
  int close = cc->close;
  sd_free(cc);
  if (close) { ch = ch_lookup(c, ch, serial); if (ch) sd_ssh_channel_close(ch); }
  else (void)open_now(c, ch);
}

static void ch_cmd_drop(ssh_cmd *cmd)
{
  ch_cmd *cc = (ch_cmd *)cmd;
  if (!cc->close) ch_free(cc->ch);
  sd_free(cc);
}

static sd_err open_common(sd_ssh_conn *c, int is_exec, const char *arg, const sd_ssh_channel_sink *s, void *ctx,
                          sd_ssh_channel **out)
{
  sd_ssh_channel *ch;
  ch_cmd *cc;
  size_t n;
  sd_err e;
  if (!c || !arg || !s || !out) return SD_E_INVALID_PARAM;
  *out = NULL;
  n = strlen(arg);
  if (n == 0 || n > 4096) return SD_E_INVALID_PARAM;
  ch = (sd_ssh_channel *)sd_calloc(1, sizeof(*ch));
  cc = (ch_cmd *)sd_calloc(1, sizeof(*cc));
  if (ch) ch->arg = (char *)sd_alloc(n + 1);
  if (!ch || !cc || !ch->arg) { sd_free(cc); if (ch) ch_free(ch); return SD_E_NO_MEMORY; }
  memcpy(ch->arg, arg, n + 1);
  ch->c = c;
  ch->sink = *s;
  ch->ctx = ctx;
  ch->is_exec = is_exec;
  ch->state = SSH_CH_PENDING;
  ch->local_id = SSH_MAX_CHANNELS;
  ch->serial = (uint32_t)InterlockedIncrement(&g_ch_serial);
  *out = ch;
  if (sd_ssh_conn_is_io_thread(c)) {
    sd_free(cc);
    if (!open_now(c, ch)) *out = NULL;   /* on_open(err) already ran */
    return SD_OK;
  }
  cc->ch = ch;
  cc->cmd.run = ch_cmd_run;
  cc->cmd.drop = ch_cmd_drop;
  e = ssh_post_cmd(c, &cc->cmd);
  if (e != SD_OK) { *out = NULL; sd_free(cc); ch_free(ch); }
  return e;
}

sd_err sd_ssh_channel_open_subsystem(sd_ssh_conn *c, const char *name, const sd_ssh_channel_sink *s, void *ctx,
                                     sd_ssh_channel **out)
{
  return open_common(c, 0, name, s, ctx, out);
}

sd_err sd_ssh_channel_open_exec(sd_ssh_conn *c, const char *command, const sd_ssh_channel_sink *s, void *ctx,
                                sd_ssh_channel **out)
{
  return open_common(c, 1, command, s, ctx, out);
}

/* ---- data path ---- */

size_t sd_ssh_channel_send_space(const sd_ssh_channel *ch)
{
  size_t pend, budget;
  if (!ch || ch->state != SSH_CH_OPEN || ch->close_sent || ch->c->failing) return 0;
  pend = ssh_out_pending(ch->c);
  budget = pend >= SSH_OUT_BUDGET ? 0 : SSH_OUT_BUDGET - pend;
  return SD_MIN((size_t)ch->remote_window, budget);
}

sd_err sd_ssh_channel_write(sd_ssh_channel *ch, const uint8_t *p, size_t n, size_t *accepted)
{
  sd_ssh_conn *c;
  size_t space, done = 0;
  if (accepted) *accepted = 0;
  if (!ch || (!p && n)) return SD_E_INVALID_PARAM;
  c = ch->c;
  if (ch->state != SSH_CH_OPEN || ch->close_sent) return SD_E_DISCONNECTED;
  space = sd_ssh_channel_send_space(ch);
  while (done < n && done < space) {
    size_t chunk = SD_MIN(n - done, space - done);
    uint8_t *buf;
    sd_err e;
    chunk = SD_MIN(chunk, (size_t)SD_MIN(ch->remote_max_packet, SSH_CH_MAXPKT));
    buf = (uint8_t *)sd_alloc(chunk + 9);
    if (!buf) return SD_E_NO_MEMORY;
    buf[0] = SSH_MSG_CHANNEL_DATA;
    sd_store_be32(buf + 1, ch->remote_id);
    sd_store_be32(buf + 5, (uint32_t)chunk);
    memcpy(buf + 9, p + done, chunk);
    e = ssh_send(c, buf, chunk + 9);
    sd_free(buf);
    if (e != SD_OK) return e;
    ch->remote_window -= (uint32_t)chunk;
    done += chunk;
  }
  if (done < n) ch->want_writable = 1;
  if (accepted) *accepted = done;
  return SD_OK;
}

void sd_ssh_channel_consumed(sd_ssh_channel *ch, size_t n)
{
  sd_ssh_conn *c;
  if (!ch || ch->state == SSH_CH_DEAD) return;
  c = ch->c;
  ch->consumed_unacked += (uint32_t)n;
  if (ch->consumed_unacked >= SSH_CH_WINDOW / 2 && ch->state == SSH_CH_OPEN && !ch->close_sent) {
    uint8_t b[12];
    b[0] = SSH_MSG_CHANNEL_WINDOW_ADJUST;
    sd_store_be32(b + 1, ch->remote_id);
    sd_store_be32(b + 5, ch->consumed_unacked);
    ch->local_window += ch->consumed_unacked;
    ch->consumed_unacked = 0;
    ssh_send(c, b, 9);
  }
}

void sd_ssh_channel_close(sd_ssh_channel *ch)
{
  sd_ssh_conn *c;
  if (!ch) return;
  c = ch->c;
  if (!sd_ssh_conn_is_io_thread(c)) {
    ch_cmd *cc = (ch_cmd *)sd_calloc(1, sizeof(*cc));
    if (!cc) return;
    cc->ch = ch;
    cc->serial = ch->serial;
    cc->close = 1;
    cc->cmd.run = ch_cmd_run;
    cc->cmd.drop = ch_cmd_drop;
    if (ssh_post_cmd(c, &cc->cmd) != SD_OK) sd_free(cc);
    return;
  }
  if (ch->state == SSH_CH_DEAD || ch->close_sent) return;
  if (ch->state == SSH_CH_OPENING) { ch->close_wanted = 1; return; }
  ch->state = SSH_CH_CLOSING;
  send_close(c, ch);
}

/* ---- inbound ---- */

static sd_err map_open_failure(uint32_t reason)
{
  switch (reason) {
  case 1: return SD_E_ACCESS_DENIED;   /* administratively prohibited */
  case 3: return SD_E_UNSUPPORTED;     /* unknown channel type */
  case 4: return SD_E_BUSY;            /* resource shortage (e.g. MaxSessions) */
  default: return SD_E_FAILURE;
  }
}

static void send_request(sd_ssh_conn *c, sd_ssh_channel *ch)
{
  sd_wr w;
  sd_wr_init(&w, 8192);
  sd_wr_u8(&w, SSH_MSG_CHANNEL_REQUEST);
  sd_wr_u32(&w, ch->remote_id);
  sd_wr_cstring(&w, ch->is_exec ? "exec" : "subsystem");
  sd_wr_bool(&w, 1);
  sd_wr_cstring(&w, ch->arg);
  ch->state = SSH_CH_REQUEST;
  ssh_send_wr(c, &w);
}

void ssh_channel_on_msg(sd_ssh_conn *c, const uint8_t *p, size_t n)
{
  uint8_t m = p[0];
  sd_rd r;
  uint32_t id;
  sd_ssh_channel *ch;
  sd_rd_init(&r, p + 1, n - 1);
  id = sd_rd_u32(&r);
  ch = (sd_rd_ok(&r) && id < SSH_MAX_CHANNELS) ? c->ch[id] : NULL;
  if (!ch) {
    ssh_fail(c, SD_E_PROTOCOL, SSH_DISCONNECT_PROTOCOL_ERROR, "message for unknown channel");
    return;
  }
  switch (m) {
  case SSH_MSG_CHANNEL_OPEN_CONFIRMATION: {
    uint32_t rid = sd_rd_u32(&r), win = sd_rd_u32(&r), maxp = sd_rd_u32(&r);
    if (!sd_rd_ok(&r) || ch->state != SSH_CH_OPENING) break;
    ch->remote_id = rid;
    ch->have_remote = 1;
    ch->remote_window = win;
    ch->remote_max_packet = maxp ? maxp : 1;
    if (ch->close_wanted) { ch->state = SSH_CH_CLOSING; send_close(c, ch); return; }
    send_request(c, ch);
    return;
  }
  case SSH_MSG_CHANNEL_OPEN_FAILURE: {
    uint32_t reason = sd_rd_u32(&r);
    sd_span desc = sd_rd_string(&r, 4096);
    char txt[256];
    if (!sd_rd_ok(&r) || ch->state != SSH_CH_OPENING) break;
    ssh_sanitize(desc.p, desc.n, txt, sizeof(txt));
    ssh_log(c, SD_LOG_WARN, "channel open refused: %u %s", reason, txt);
    ch_finish(c, ch, map_open_failure(reason));
    return;
  }
  case SSH_MSG_CHANNEL_SUCCESS:
    if (ch->state != SSH_CH_REQUEST) break;
    ch->state = SSH_CH_OPEN;
    ch->opened = 1;
    ch->deadline = 0;
    if (ch->sink.on_open) ch->sink.on_open(ch->ctx, SD_OK);
    return;
  case SSH_MSG_CHANNEL_FAILURE:
    if (ch->state != SSH_CH_REQUEST) break;
    ssh_log(c, SD_LOG_WARN, "channel request %s refused", ch->is_exec ? "exec" : "subsystem");
    ch->state = SSH_CH_CLOSING;
    ch->deadline = 0;
    send_close(c, ch);
    /* on_open(SD_E_UNSUPPORTED) is delivered once the peer's CLOSE arrives (ch_finish) */
    ch->refused = 1;
    return;
  case SSH_MSG_CHANNEL_WINDOW_ADJUST: {
    uint32_t add = sd_rd_u32(&r);
    if (!sd_rd_ok(&r)) break;
    ch->remote_window = (uint32_t)SD_MIN((uint64_t)ch->remote_window + add, (uint64_t)0xFFFFFFFFu);
    if (ch->want_writable && ch->state == SSH_CH_OPEN && sd_ssh_channel_send_space(ch) > 0) {
      ch->want_writable = 0;
      if (ch->sink.on_writable) ch->sink.on_writable(ch->ctx);
    }
    return;
  }
  case SSH_MSG_CHANNEL_DATA: {
    sd_span d = sd_rd_string(&r, SSH_MAX_PACKET_LEN);
    if (!sd_rd_ok(&r)) break;
    if (d.n > ch->local_window) { ssh_fail(c, SD_E_PROTOCOL, SSH_DISCONNECT_PROTOCOL_ERROR, "channel window exceeded"); return; }
    ch->local_window -= (uint32_t)d.n;
    if (ch->state == SSH_CH_OPEN && ch->sink.on_data && d.n) ch->sink.on_data(ch->ctx, d.p, d.n);
    else sd_ssh_channel_consumed(ch, d.n);
    return;
  }
  case SSH_MSG_CHANNEL_EXTENDED_DATA: {
    uint32_t type = sd_rd_u32(&r);
    sd_span d = sd_rd_string(&r, SSH_MAX_PACKET_LEN);
    if (!sd_rd_ok(&r)) break;
    if (d.n > ch->local_window) { ssh_fail(c, SD_E_PROTOCOL, SSH_DISCONNECT_PROTOCOL_ERROR, "channel window exceeded"); return; }
    ch->local_window -= (uint32_t)d.n;
    if (ch->stderr_logged < 4096) {
      char txt[1024];
      size_t take = SD_MIN(d.n, (size_t)(4096 - ch->stderr_logged));
      ch->stderr_logged += (uint32_t)take;
      ssh_sanitize(d.p, SD_MIN(take, (size_t)340), txt, sizeof(txt));
      ssh_log(c, SD_LOG_INFO, "channel %u stderr(%u): %s", ch->local_id, type, txt);
    }
    sd_ssh_channel_consumed(ch, d.n);
    return;
  }
  case SSH_MSG_CHANNEL_EOF:
    ch->eof_recv = 1;
    if (ch->state == SSH_CH_OPEN && ch->sink.on_eof) ch->sink.on_eof(ch->ctx);
    return;
  case SSH_MSG_CHANNEL_CLOSE: {
    int refused = ch->refused;
    ch->close_recv = 1;
    send_close(c, ch);
    ch_finish(c, ch, refused ? SD_E_UNSUPPORTED : (ch->opened ? SD_OK : SD_E_FAILURE));
    return;
  }
  case SSH_MSG_CHANNEL_REQUEST: {
    sd_span type = sd_rd_string(&r, 256);
    int want = sd_rd_bool(&r);
    if (!sd_rd_ok(&r)) break;
    if (ssh_span_eq(type, "exit-status")) {
      uint32_t st = sd_rd_u32(&r);
      ssh_log(c, SD_LOG_DEBUG, "channel %u exit-status %u", ch->local_id, st);
    } else if (ssh_span_eq(type, "exit-signal")) {
      sd_span sig = sd_rd_string(&r, 64);
      char txt[200];
      ssh_sanitize(sig.p, sig.n, txt, sizeof(txt));
      ssh_log(c, SD_LOG_INFO, "channel %u exit-signal %s", ch->local_id, txt);
    }
    if (want && ch->have_remote && !ch->close_sent) {
      uint8_t b[8];
      b[0] = SSH_MSG_CHANNEL_FAILURE;
      sd_store_be32(b + 1, ch->remote_id);
      ssh_send(c, b, 5);
    }
    return;
  }
  default:
    break;
  }
  ssh_fail(c, SD_E_PROTOCOL, SSH_DISCONNECT_PROTOCOL_ERROR, "bad channel message");
}

void ssh_channels_fail_all(sd_ssh_conn *c, sd_err why)
{
  uint32_t i;
  for (i = 0; i < SSH_MAX_CHANNELS; i++) {
    sd_ssh_channel *ch = c->ch[i];
    if (!ch) continue;
    c->ch[i] = NULL;
    ch->state = SSH_CH_DEAD;
    if (ch->opened) { if (ch->sink.on_closed) ch->sink.on_closed(ch->ctx, why == SD_OK ? SD_E_DISCONNECTED : why); }
    else if (ch->sink.on_open) ch->sink.on_open(ch->ctx, why == SD_OK ? SD_E_DISCONNECTED : why);
    ch_free(ch);
  }
}

void ssh_channels_timers(sd_ssh_conn *c, uint64_t now, uint64_t *next)
{
  uint32_t i;
  for (i = 0; i < SSH_MAX_CHANNELS && !c->failing; i++) {
    sd_ssh_channel *ch = c->ch[i];
    if (!ch || !ch->deadline) continue;
    if (now >= ch->deadline) {
      /* per-request deadline: report the timeout now and probe the link (01 §4.6) */
      ssh_log(c, SD_LOG_WARN, "channel %u open timed out", ch->local_id);
      ch->deadline = 0;
      if (ch->sink.on_open) ch->sink.on_open(ch->ctx, SD_E_TIMEOUT);
      ch->sink.on_open = NULL;
      ch->sink.on_closed = NULL;
      ch->sink.on_data = NULL;
      ch->sink.on_eof = NULL;
      ch->sink.on_writable = NULL;
      if (ch->have_remote) { ch->state = SSH_CH_CLOSING; send_close(c, ch); }
      else ch->close_wanted = 1;
      sd_ssh_conn_probe(c);
    } else if (*next == 0 || ch->deadline < *next) {
      *next = ch->deadline;
    }
  }
}

void ssh_channels_writable(sd_ssh_conn *c)
{
  uint32_t i;
  for (i = 0; i < SSH_MAX_CHANNELS && !c->failing; i++) {
    sd_ssh_channel *ch = c->ch[i];
    if (!ch || !ch->want_writable || ch->state != SSH_CH_OPEN) continue;
    if (sd_ssh_channel_send_space(ch) == 0) continue;
    ch->want_writable = 0;
    if (ch->sink.on_writable) ch->sink.on_writable(ch->ctx);
  }
}
