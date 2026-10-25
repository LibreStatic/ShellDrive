/* ProxyJump with N hops (01 §5.1, §3.3): the chain object, per-hop callback adapters, the
 * direct-tcpip tunnels between hops, and the chain-level connect / disconnect.
 *
 * Structure: one sd_ssh_conn per hop. hops[n-1] is the public object (the target, the "root"): it
 * owns the single I/O thread, the command queue and the worker counter; every hop posts there
 * (ssh_post_cmd routes by c->root). Hop 0 runs over TCP; hop i >= 1 runs over a direct-tcpip channel
 * opened on hop i-1 to (host, port) of hop i, or to hop i's proxy when it has one. Each hop has its
 * own KEX, host-key verification (its own lookup name), authentication and reconnect secret cache.
 *
 * Callbacks: every hop's cb are adapters that stamp hop_index (and via_host, TM-R03) into prompts and
 * events before forwarding them to the caller's callbacks, so kex.c/auth.c stay hop-agnostic.
 *
 * Connect: the first hop that is not connected is connected, then the next one over its tunnel, up to
 * the target; a failure at hop k completes the public connect with failed_hop = k and leaves hops
 * < k connected (a later connect continues from there, 01 §5.1). Disconnect closes every hop,
 * innermost first. A dying hop fails the tunnel of the next hop, so the inner hops fail with it. */
#include <winsock2.h>
#include <windows.h>
#include <string.h>

#include "sd_base/sd_mem.h"
#include "sd_platform/sd_log.h"
#include "conn_internal.h"

/* ---- callback adapters (ctx = the hop) ---- */

static void ad_prompt(void *ctx, sd_prompt *p, const sd_auth_prompt_info *a, const sd_hostkey_prompt_info *hk)
{
  sd_ssh_conn *c = (sd_ssh_conn *)ctx, *r = c->root;
  /* the info structs belong to the prompt object (prompt.c) and are writable there */
  if (a) {
    sd_auth_prompt_info *m = (sd_auth_prompt_info *)(uintptr_t)a;
    m->hop_index = c->hop_index;
    if (!m->host) m->host = c->host_utf8;
  }
  if (hk) {
    sd_hostkey_prompt_info *m = (sd_hostkey_prompt_info *)(uintptr_t)hk;
    m->hop_index = c->hop_index;
    m->via_host = c->via_host;
    if (!m->port) m->port = c->port;
  }
  if (r->user_cb.on_prompt) r->user_cb.on_prompt(r->user_cb.ctx, p, a, hk);
  else sd_prompt_cancel(p);
}

static void ad_withdrawn(void *ctx, sd_prompt *p)
{
  sd_ssh_conn *r = ((sd_ssh_conn *)ctx)->root;
  if (r->user_cb.on_prompt_withdrawn) r->user_cb.on_prompt_withdrawn(r->user_cb.ctx, p);
}

static void ad_banner(void *ctx, uint32_t hop, const char *utf8)
{
  sd_ssh_conn *c = (sd_ssh_conn *)ctx, *r = c->root;
  SD_UNUSED(hop);
  if (c->pool_member) return;            /* 01 §10.9: pool members skip banners */
  if (r->user_cb.on_banner) r->user_cb.on_banner(r->user_cb.ctx, c->hop_index, utf8);
}

static void ad_negotiated(void *ctx, const sd_ssh_negotiated *n)
{
  sd_ssh_conn *c = (sd_ssh_conn *)ctx, *r = c->root;
  sd_ssh_negotiated m;
  if (!r->user_cb.on_negotiated || !n) return;
  m = *n;
  m.hop_index = c->hop_index;
  r->user_cb.on_negotiated(r->user_cb.ctx, &m);
}

static void ad_hostkey(void *ctx, const sd_hostkey_event *e)
{
  sd_ssh_conn *c = (sd_ssh_conn *)ctx, *r = c->root;
  sd_hostkey_event m;
  if (!r->user_cb.on_hostkey_event || !e) return;
  m = *e;
  m.hop_index = c->hop_index;
  r->user_cb.on_hostkey_event(r->user_cb.ctx, &m);
}

static void ad_log(void *ctx, int level, const char *msg)
{
  sd_ssh_conn *r = ((sd_ssh_conn *)ctx)->root;
  if (r->user_cb.on_log) r->user_cb.on_log(r->user_cb.ctx, level, msg);
}

/* ---- chain object ---- */

static void free_hop(sd_ssh_conn *c)
{
  if (!c) return;
  ssh_hop_release(c);
  sd_secure_zero(c, sizeof(*c));
  sd_free(c);
}

sd_err ssh_chain_create(const sd_ssh_config *cfg, const sd_ssh_callbacks *cb, sd_ssh_conn **out)
{
  uint32_t n = cfg->hop_count, i;
  sd_ssh_conn **hops;
  sd_ssh_conn *root;
  sd_err e = SD_OK;

  hops = (sd_ssh_conn **)sd_calloc(n, sizeof(*hops));
  if (!hops) return SD_E_NO_MEMORY;
  for (i = 0; i < n; i++) {
    hops[i] = (sd_ssh_conn *)sd_calloc(1, sizeof(sd_ssh_conn));
    if (!hops[i]) { e = SD_E_NO_MEMORY; break; }
    e = ssh_hop_init(hops[i], cfg, &cfg->hops[i], i);
    if (e != SD_OK) { sd_free(hops[i]); hops[i] = NULL; break; }
  }
  if (e != SD_OK) {
    for (i = 0; i < n; i++) if (hops[i]) free_hop(hops[i]);
    sd_free(hops);
    return e;
  }
  root = hops[n - 1];
  root->hops = hops;
  root->nhops = n;
  if (cb) root->user_cb = *cb;
  root->chain_service = 0;
  for (i = 0; i < n; i++) {
    sd_ssh_conn *c = hops[i];
    c->root = root;
    c->outer = i ? hops[i - 1] : NULL;
    c->via_host = i ? hops[i - 1]->host_utf8 : NULL;
    c->cb.ctx = c;
    c->cb.on_prompt = ad_prompt;
    c->cb.on_prompt_withdrawn = ad_withdrawn;
    c->cb.on_banner = ad_banner;
    c->cb.on_negotiated = ad_negotiated;
    c->cb.on_hostkey_event = ad_hostkey;
    c->cb.on_log = ad_log;
  }
  root->cmd_ev = CreateEventW(NULL, FALSE, FALSE, NULL);
  root->workers_idle = CreateEventW(NULL, TRUE, TRUE, NULL);
  if (!root->cmd_ev || !root->workers_idle) e = SD_E_INTERNAL;
  if (e == SD_OK) e = sd_thread_create(&root->thread, ssh_io_main, root, 256u * 1024u, L"sd_ssh io");
  if (e != SD_OK) {
    if (root->cmd_ev) CloseHandle(root->cmd_ev);
    if (root->workers_idle) CloseHandle(root->workers_idle);
    for (i = 0; i < n; i++) free_hop(hops[i]);
    sd_free(hops);
    return e;
  }
  if (n > 1) sd_log(SD_LOG_DEBUG, "ssh", NULL, "chain with %u hops created", n);
  *out = root;
  return SD_OK;
}

void ssh_chain_destroy(sd_ssh_conn *c)
{
  ssh_cmd *q;
  sd_ssh_conn **hops;
  uint32_t n, i;
  if (c->root && c->root != c) return;      /* only the public object */
  sd_mutex_lock(&c->qlock);
  c->stopping = 1;
  sd_mutex_unlock(&c->qlock);
  SetEvent(c->cmd_ev);
  sd_thread_join(&c->thread, SD_WAIT_INFINITE, NULL);
  WaitForSingleObject(c->workers_idle, INFINITE);
  /* the I/O thread closed the queue; anything left was posted by workers after it exited */
  q = c->qhead;
  while (q) { ssh_cmd *nx = q->next; q->drop(q); q = nx; }
  CloseHandle(c->cmd_ev);
  CloseHandle(c->workers_idle);
  hops = c->hops;
  n = c->nhops;
  for (i = 0; i + 1 < n; i++) free_hop(hops[i]);
  free_hop(c);
  sd_free(hops);
}

/* ---- chain connect / disconnect (I/O thread) ---- */

static void chain_hop_done(void *ctx, sd_err err, uint32_t failed_hop)
{
  sd_ssh_conn *h = (sd_ssh_conn *)ctx, *r = h->root;
  sd_ssh_done_cb done;
  void *dctx;
  SD_UNUSED(failed_hop);
  if (err == SD_OK && h != r) {
    sd_ssh_conn *nx = r->hops[h->hop_index + 1];
    ssh_log(h, SD_LOG_INFO, "hop %u (%s) connected; opening hop %u through it", h->hop_index, h->host_utf8,
            nx->hop_index);
    ssh_hop_connect(nx, chain_hop_done, nx);
    return;
  }
  done = r->chain_done;
  dctx = r->chain_ctx;
  r->chain_done = NULL;
  r->chain_ctx = NULL;
  if (err != SD_OK && r->nhops > 1)
    ssh_log(h, SD_LOG_WARN, "chain connect failed at hop %u (%s): %s", h->hop_index, h->host_utf8, sd_err_name(err));
  if (done) done(dctx, err, err == SD_OK ? 0 : h->hop_index);
}

void ssh_chain_connect(sd_ssh_conn *r, sd_ssh_done_cb done, void *ctx)
{
  uint32_t k, j;
  if (r->chain_done || r->chain_disc_done) { if (done) done(ctx, SD_E_BUSY, 0); return; }
  for (k = 0; k < r->nhops && r->hops[k]->st == SSH_ST_CONNECTED; k++) {}
  if (k == r->nhops) { if (done) done(ctx, SD_E_BUSY, 0); return; }   /* already connected */
  for (j = k; j < r->nhops; j++) {
    ssh_conn_state st = r->hops[j]->st;
    if ((st != SSH_ST_IDLE && st != SSH_ST_CLOSED) || r->hops[j]->failing) { if (done) done(ctx, SD_E_BUSY, 0); return; }
  }
  if (k > 0) ssh_log(r, SD_LOG_INFO, "reconnect: hops 0..%u still connected, rebuilding from hop %u", k - 1, k);
  r->chain_done = done;
  r->chain_ctx = ctx;
  ssh_hop_connect(r->hops[k], chain_hop_done, r->hops[k]);
}

static void chain_disc_next(sd_ssh_conn *r);

static void chain_disc_hop_done(void *ctx, sd_err err, uint32_t failed_hop)
{
  SD_UNUSED(err); SD_UNUSED(failed_hop);
  chain_disc_next(((sd_ssh_conn *)ctx)->root);
}

static void chain_disc_next(sd_ssh_conn *r)
{
  uint32_t i;
  sd_ssh_done_cb done;
  void *ctx;
  for (i = r->nhops; i-- > 0;) {
    sd_ssh_conn *h = r->hops[i];
    if (h->st != SSH_ST_IDLE && h->st != SSH_ST_CLOSED) {
      ssh_hop_disconnect(h, chain_disc_hop_done, h);
      return;
    }
  }
  done = r->chain_disc_done;
  ctx = r->chain_disc_ctx;
  r->chain_disc_done = NULL;
  r->chain_disc_ctx = NULL;
  if (done) done(ctx, SD_OK, 0);
}

void ssh_chain_disconnect(sd_ssh_conn *r, sd_ssh_done_cb done, void *ctx)
{
  if (r->chain_disc_done) { if (done) done(ctx, SD_E_BUSY, 0); return; }
  r->chain_disc_done = done;
  r->chain_disc_ctx = ctx;
  chain_disc_next(r);
}

/* ---- tunnels: the direct-tcpip channel that carries hop i >= 1 (01 §3.3, §4.8) ---- */

static sd_err map_tunnel_err(sd_err e)
{
  switch (e) {
  case SD_E_CONN_REFUSED: case SD_E_ACCESS_DENIED: case SD_E_TIMEOUT: case SD_E_DISCONNECTED: case SD_E_SHUTDOWN:
  case SD_E_NO_MEMORY: case SD_E_BUSY:
    return e;
  default:
    return SD_E_CONN_REFUSED;     /* the jump host could not reach the next hop */
  }
}

/* The hop's stream ended under it. */
static void tunnel_lost(sd_ssh_conn *c, sd_err why, const char *what)
{
  if (c->failing || c->st == SSH_ST_CLOSED || c->st == SSH_ST_IDLE) return;
  if (c->st == SSH_ST_CLOSING) { c->fail_err = SD_E_SHUTDOWN; c->failing = 1; return; }
  ssh_fail(c, why, 0, what);
}

static void tun_on_open(void *ctx, sd_err err)
{
  ssh_tunnel *t = (ssh_tunnel *)ctx;
  sd_ssh_conn *c = t->c;
  if (err != SD_OK) {
    if (c) {
      c->tun = NULL;
      if (c->st == SSH_ST_TUNNEL && !c->failing) {
        ssh_log(c, SD_LOG_WARN, "hop %u: %s could not open a tunnel to %s:%u: %s", c->hop_index,
                c->outer ? c->outer->host_utf8 : "?", ssh_lower_host8(c), (unsigned)ssh_lower_port(c), sd_err_name(err));
        ssh_fail(c, map_tunnel_err(err), 0, "tunnel open failed");
      }
    }
    sd_free(t);
    return;
  }
  t->open = 1;
  if (!c || c->st != SSH_ST_TUNNEL || c->failing) {   /* the hop gave up meanwhile */
    if (c && c->tun == t) c->tun = NULL;
    t->c = NULL;
    if (t->ch) sd_ssh_channel_close(t->ch);
    return;
  }
  ssh_log(c, SD_LOG_DEBUG, "hop %u: tunnel through hop %u open", c->hop_index, c->hop_index - 1);
  ssh_transport_up(c);
}

static void tun_on_data(void *ctx, const uint8_t *p, size_t n)
{
  ssh_tunnel *t = (ssh_tunnel *)ctx;
  sd_ssh_channel *ch = t->ch;
  if (t->c && !t->c->failing) ssh_ingest(t->c, p, n);
  if (ch) sd_ssh_channel_consumed(ch, n);    /* the hop processed every complete packet */
}

static void tun_on_writable(void *ctx)
{
  ssh_tunnel *t = (ssh_tunnel *)ctx;
  if (t->c) ssh_flush(t->c);
}

static void tun_on_eof(void *ctx)
{
  ssh_tunnel *t = (ssh_tunnel *)ctx;
  if (t->c) tunnel_lost(t->c, SD_E_DISCONNECTED, "tunnel closed by the jump host");
}

static void tun_on_closed(void *ctx, sd_err why)
{
  ssh_tunnel *t = (ssh_tunnel *)ctx;
  sd_ssh_conn *c = t->c;
  sd_free(t);
  if (!c) return;
  c->tun = NULL;
  tunnel_lost(c, (why == SD_OK || why == SD_E_SHUTDOWN) ? SD_E_DISCONNECTED : why, "tunnel closed");
}

static const sd_ssh_channel_sink k_tun_sink = { tun_on_open, tun_on_data, tun_on_writable, tun_on_eof, tun_on_closed };

void ssh_tunnel_open(sd_ssh_conn *c)
{
  ssh_tunnel *t;
  sd_ssh_channel *ch = NULL;
  sd_err e;
  sd_ssh_conn *o = c->outer;
  c->st = SSH_ST_TUNNEL;
  if (!o || o->st != SSH_ST_CONNECTED || o->failing) { ssh_fail(c, SD_E_DISCONNECTED, 0, "previous hop is not connected"); return; }
  t = (ssh_tunnel *)sd_calloc(1, sizeof(*t));
  if (!t) { ssh_fail(c, SD_E_NO_MEMORY, 0, "tunnel"); return; }
  t->c = c;
  c->tun = t;
  ssh_log(c, SD_LOG_INFO, "hop %u: opening direct-tcpip to %s:%u on %s", c->hop_index, ssh_lower_host8(c),
          (unsigned)ssh_lower_port(c), o->host_utf8);
  e = ssh_channel_open_tcpip(o, ssh_lower_host8(c), ssh_lower_port(c), &k_tun_sink, t, &ch);
  if (e != SD_OK) {        /* nothing was registered: no callback follows */
    if (c->tun == t) c->tun = NULL;
    sd_free(t);
    ssh_fail(c, e, 0, "tunnel open failed");
    return;
  }
  if (c->tun == t && ch) t->ch = ch;     /* a synchronous failure already freed t (c->tun is NULL) */
}

void ssh_tunnel_release(sd_ssh_conn *c)
{
  ssh_tunnel *t = c->tun;
  if (!t) return;
  c->tun = NULL;
  t->c = NULL;
  if (t->ch) sd_ssh_channel_close(t->ch);   /* the tunnel is freed by its on_closed / on_open(err) */
}
