/* UpdateHostKeys, client side (01 §7.5, D16): hostkeys-00@openssh.com announcements, proofs with
 * hostkeys-prove-00@openssh.com, SD_HKEV_ANNOUNCED for the host's review (sd_ssh never writes a
 * store), and sd_ssh_conn_fetch_hostkeys (01 §4.3 "add a key of another type", TM-R04): announced
 * keys are proven, other requested types are obtained by a re-key restricted to that type inside the
 * already verified connection. I/O thread only, except the public entry point. */
#include <string.h>

#include "sd_base/sd_mem.h"
#include "sd_platform/sd_time.h"
#include "hostkey_internal.h"
#include "transport_internal.h"

#define PROVE_NAME "hostkeys-prove-00@openssh.com"

ssh_hku *ssh_hku_get(sd_ssh_conn *c)
{
  if (!c->hku) c->hku = (ssh_hku *)sd_calloc(1, sizeof(ssh_hku));
  return c->hku;
}

static void key_clear(ssh_hku_key *k)
{
  sd_free(k->blob);
  memset(k, 0, sizeof(*k));
}

static sd_err key_set(ssh_hku_key *k, const uint8_t *blob, size_t len)
{
  sd_span t = ssh_blob_key_type(blob, len);
  memset(k, 0, sizeof(*k));
  if (!t.n || t.n >= sizeof(k->type)) return SD_E_INVALID_PARAM;
  k->blob = (uint8_t *)sd_alloc(len);
  if (!k->blob) return SD_E_NO_MEMORY;
  memcpy(k->blob, blob, len);
  k->len = len;
  memcpy(k->type, t.p, t.n);
  k->type[t.n] = '\0';
  if (sd_hostkey_fingerprint_sha256(blob, len, k->fp) != SD_OK) k->fp[0] = '\0';
  return SD_OK;
}

static void to_hk_key(const ssh_hku_key *s, sd_hk_key *d)
{
  d->blob = s->blob;
  d->len = s->len;
  d->type = s->type;
  d->fp_sha256 = s->fp;
}

static void finish_fetch(sd_ssh_conn *c, sd_err e)
{
  ssh_hku *u = c->hku;
  sd_hk_key keys[SSH_HKU_MAX_KEYS + 8];
  sd_ssh_hostkeys_cb done;
  void *ctx;
  uint32_t i, n;
  if (!u || !u->fetching) return;
  done = u->fetch_done;
  ctx = u->fetch_ctx;
  n = u->ngot;
  for (i = 0; i < n; i++) to_hk_key(&u->got[i], &keys[i]);
  if (e == SD_OK && n == 0) e = SD_E_HOSTKEY_TYPE_UNAVAILABLE;
  ssh_log(c, SD_LOG_INFO, "fetch_hostkeys finished: %u key(s), %s", n, sd_err_name(e));
  u->fetching = 0;
  u->fetch_rekey = 0;
  u->fetch_done = NULL;
  if (done) done(ctx, e, n ? keys : NULL, n);
  for (i = 0; i < n; i++) key_clear(&u->got[i]);
  u->ngot = 0;
}

void ssh_hku_reset(sd_ssh_conn *c)
{
  ssh_hku *u = c->hku;
  uint32_t i;
  if (!u) return;
  if (u->fetching) finish_fetch(c, c->fail_err != SD_OK ? c->fail_err : SD_E_DISCONNECTED);
  for (i = 0; i < u->nann; i++) key_clear(&u->ann[i]);
  for (i = 0; i < u->nrem; i++) key_clear(&u->rem[i]);
  for (i = 0; i < u->ngot; i++) key_clear(&u->got[i]);
  memset(u, 0, sizeof(*u));
}

void ssh_hku_free(sd_ssh_conn *c)
{
  if (!c->hku) return;
  ssh_hku_reset(c);
  sd_free(c->hku);
  c->hku = NULL;
}

/* The connection's host key was verified against a key trusted before it (01 §7.5 precondition 2):
   SD_HK_MATCH from a store or live source, not a prompt acceptance, not a certificate. */
static int verified_by_trusted_key(const sd_ssh_conn *c)
{
  return c->hk_res_valid && c->hk_res.status == SD_HK_MATCH && c->hk_res.trusted_before && !c->hostkey_just_accepted &&
         !c->hk_once;
}

static int same_key(const ssh_hku_key *k, const uint8_t *blob, size_t len)
{
  return k->len == len && memcmp(k->blob, blob, len) == 0;
}

/* ---- hostkeys-prove-00 ---- */

static sd_err send_prove(sd_ssh_conn *c, const uint32_t *idx, uint32_t n, ssh_hku_req purpose)
{
  ssh_hku *u = c->hku;
  sd_wr w;
  uint32_t i;
  sd_err e;
  sd_wr_init(&w, 256u * 1024u);
  sd_wr_u8(&w, SSH_MSG_GLOBAL_REQUEST);
  sd_wr_cstring(&w, PROVE_NAME);
  sd_wr_bool(&w, 1);
  for (i = 0; i < n; i++) sd_wr_string(&w, u->ann[idx[i]].blob, u->ann[idx[i]].len);
  e = ssh_send_wr(c, &w);
  if (e != SD_OK) return e;
  u->prove = purpose;
  u->prove_ahead = c->ka_count;     /* replies are in request order (RFC 4254 §4) */
  memcpy(u->prove_idx, idx, n * sizeof(idx[0]));
  u->nprove = n;
  ssh_log(c, SD_LOG_INFO, "hostkeys-prove-00: asking the server to prove %u key(s)", n);
  return SD_OK;
}

/* Verifies the REQUEST_SUCCESS payload; 1 if every signature is valid. */
static int check_proofs(sd_ssh_conn *c, const uint8_t *p, size_t n)
{
  ssh_hku *u = c->hku;
  sd_rd r;
  sd_wr d;
  uint32_t i;
  int ok = 1;
  sd_rd_init(&r, p + 1, n - 1);
  for (i = 0; i < u->nprove && ok; i++) {
    const ssh_hku_key *k = &u->ann[u->prove_idx[i]];
    sd_span sig = sd_rd_string(&r, SSH_HOSTKEY_MAX);
    ssh_pubkey pk;
    if (!sd_rd_ok(&r)) { ok = 0; break; }
    if (ssh_pubkey_parse(k->blob, k->len, &pk) != SD_OK) { ok = 0; break; }
    sd_wr_init(&d, SSH_HOSTKEY_MAX + 256);
    sd_wr_cstring(&d, PROVE_NAME);
    sd_wr_string(&d, c->session_id, c->session_id_len);
    sd_wr_string(&d, k->blob, k->len);
    /* RSA: rsa-sha2-512/256; ssh-rsa only while legacy is allowed (OpenSSH signs RSA proofs with
       ssh-rsa when the session's host key is not RSA) */
    if (!sd_wr_ok(&d) || ssh_pubkey_verify(&pk, NULL, c->legacy_policy != SD_LEGACY_REFUSE, sig.p, sig.n, d.p, d.len) != SD_OK)
      ok = 0;
    sd_wr_free(&d);
    ssh_pubkey_free(&pk);
    if (!ok) ssh_log(c, SD_LOG_WARN, "hostkeys-prove-00: proof for %s %s invalid", k->type, k->fp);
  }
  if (ok && !sd_rd_done(&r)) ok = 0;
  return ok;
}

/* ---- UpdateHostKeys (01 §7.5) ---- */

static void raise_announced(sd_ssh_conn *c, const uint32_t *add_idx, uint32_t nadd)
{
  ssh_hku *u = c->hku;
  sd_hostkey_event ev;
  sd_hk_key add[SSH_HKU_MAX_KEYS], rem[SSH_HKU_MAX_KEYS];
  uint32_t i;
  memset(&ev, 0, sizeof(ev));
  for (i = 0; i < nadd; i++) to_hk_key(&u->ann[add_idx[i]], &add[i]);
  for (i = 0; i < u->nrem; i++) to_hk_key(&u->rem[i], &rem[i]);
  ev.kind = SD_HKEV_ANNOUNCED;
  ev.hop_index = c->hop_index;
  ev.lookup_name = c->lookup_name;
  ev.store = u->target;
  ev.path = (c->hk_res.store == u->target && c->hk_res.path[0]) ? c->hk_res.path : NULL;
  ev.add = nadd ? add : NULL;
  ev.add_count = nadd;
  ev.remove = u->nrem ? rem : NULL;
  ev.remove_count = u->nrem;
  ssh_log(c, SD_LOG_INFO, "hostkeys-00: %u proven new key(s), %u removal candidate(s) for %Hs (%s store%s)", nadd,
          u->nrem, c->lookup_name, u->target == SD_KH_STORE_MACHINE ? "machine" : "user",
          u->target == SD_KH_STORE_MACHINE ? ", informational" : "");
  if (c->cb.on_hostkey_event) c->cb.on_hostkey_event(c->cb.ctx, &ev);
}

typedef struct hku_work {
  ssh_work w;
  sd_known_hosts *kh;
  char name[320];
  sd_kh_store_kind target;
  uint32_t n;
  uint8_t *blob[SSH_HKU_MAX_KEYS]; size_t len[SSH_HKU_MAX_KEYS];
  uint8_t *auth; size_t auth_len;       /* the key that authenticated this connection (plain) */
  int status[SSH_HKU_MAX_KEYS];         /* 0 new, 1 known, 2 revoked / unusable */
  uint32_t nrem;
  uint8_t *rem[SSH_HKU_MAX_KEYS]; size_t rem_len[SSH_HKU_MAX_KEYS];
  sd_err err;
} hku_work;

static void hku_work_free(hku_work *h)
{
  uint32_t i;
  for (i = 0; i < h->n; i++) sd_free(h->blob[i]);
  for (i = 0; i < h->nrem; i++) sd_free(h->rem[i]);
  sd_free(h->auth);
  sd_free(h);
}

typedef struct rem_ctx { hku_work *h; } rem_ctx;

static int rem_cb(void *ctx, const sd_kh_entry *e)
{
  hku_work *h = ((rem_ctx *)ctx)->h;
  uint32_t i;
  if (!e->explicit_name || h->nrem >= SSH_HKU_MAX_KEYS) return 0;
  for (i = 0; i < h->n; i++) if (h->len[i] == e->len && memcmp(h->blob[i], e->blob, e->len) == 0) return 0;
  for (i = 0; i < h->nrem; i++) if (h->rem_len[i] == e->len && memcmp(h->rem[i], e->blob, e->len) == 0) return 0;
  h->rem[h->nrem] = (uint8_t *)sd_alloc(e->len);
  if (!h->rem[h->nrem]) return 1;
  memcpy(h->rem[h->nrem], e->blob, e->len);
  h->rem_len[h->nrem] = e->len;
  h->nrem++;
  return 0;
}

static void hku_classify(ssh_work *w)
{
  hku_work *h = (hku_work *)w;
  uint32_t i;
  int auth_announced = 0;
  uint64_t now = (uint64_t)sd_unix_time_now();
  for (i = 0; i < h->n; i++) {
    sd_hk_result r;
    sd_err e = sd_known_hosts_check(h->kh, h->name, h->blob[i], h->len[i], now, &r);
    if (e != SD_OK) { h->status[i] = 2; continue; }
    if (r.status == SD_HK_MATCH) h->status[i] = 1;
    else if (r.status == SD_HK_REVOKED) h->status[i] = 2;
    else h->status[i] = 0;
    if (h->len[i] == h->auth_len && memcmp(h->blob[i], h->auth, h->auth_len) == 0) auth_announced = 1;
  }
  /* removal candidates only when the key that authenticated this connection is still announced */
  if (auth_announced) {
    rem_ctx rc;
    rc.h = h;
    (void)sd_known_hosts_list(h->kh, h->target, h->name, rem_cb, &rc);
  }
  h->err = SD_OK;
}

static void hku_classified(sd_ssh_conn *c, ssh_cmd *cmd)
{
  hku_work *h = (hku_work *)cmd;
  ssh_hku *u = c->hku;
  uint32_t i, idx[SSH_HKU_MAX_KEYS], nnew = 0;
  if (h->w.gen != c->gen || c->failing || c->st != SSH_ST_CONNECTED || !u) { hku_work_free(h); return; }
  for (i = 0; i < h->n && i < u->nann; i++) if (h->status[i] == 0) idx[nnew++] = i;
  for (i = 0; i < h->nrem; i++) {
    if (key_set(&u->rem[u->nrem], h->rem[i], h->rem_len[i]) == SD_OK) u->nrem++;
  }
  hku_work_free(h);
  if (nnew) {
    if (u->prove != SSH_HKU_REQ_NONE) { ssh_log(c, SD_LOG_INFO, "hostkeys-00: a proof request is in flight; ignored"); return; }
    if (send_prove(c, idx, nnew, SSH_HKU_REQ_UPDATE) != SD_OK) ssh_log(c, SD_LOG_WARN, "hostkeys-00: prove request failed");
    return;
  }
  if (u->nrem) raise_announced(c, NULL, 0);
  else ssh_log(c, SD_LOG_DEBUG, "hostkeys-00: every announced key is already known");
}

static void hku_drop(ssh_cmd *cmd) { hku_work_free((hku_work *)cmd); }

static void start_update(sd_ssh_conn *c)
{
  ssh_hku *u = c->hku;
  hku_work *h;
  uint32_t i;
  uint8_t *plain = NULL;
  size_t plen = 0;
  if (c->hku_mode == SD_HKU_NO) { ssh_log(c, SD_LOG_DEBUG, "hostkeys-00 ignored: update_host_keys = no"); return; }
  if (c->pool_member) { ssh_log(c, SD_LOG_DEBUG, "hostkeys-00 ignored on a pool member"); return; }
  if (!c->kh) { ssh_log(c, SD_LOG_DEBUG, "hostkeys-00 ignored: no known_hosts"); return; }
  if (!verified_by_trusted_key(c)) {
    ssh_log(c, SD_LOG_INFO, "hostkeys-00 ignored: the host key was not verified against a previously trusted key");
    return;
  }
  if (c->hk_res.wildcard_only) {
    ssh_log(c, SD_LOG_INFO, "hostkeys-00 ignored: the trusted entry matches %Hs only through a wildcard", c->lookup_name);
    return;
  }
  if (u->update_started) return;
  u->update_started = 1;
  u->target = c->hk_res.store == SD_KH_STORE_MACHINE ? SD_KH_STORE_MACHINE : SD_KH_STORE_USER;
  h = (hku_work *)sd_calloc(1, sizeof(*h));
  if (!h) return;
  h->kh = c->kh;
  memcpy(h->name, c->lookup_name, sizeof(h->name));
  h->target = u->target;
  for (i = 0; i < u->nann; i++) {
    h->blob[i] = (uint8_t *)sd_alloc(u->ann[i].len);
    if (!h->blob[i]) { hku_work_free(h); return; }
    memcpy(h->blob[i], u->ann[i].blob, u->ann[i].len);
    h->len[i] = u->ann[i].len;
    h->n = i + 1;
  }
  if (ssh_blob_plain_key(c->hostkey, c->hostkey_len, &plain, &plen) == SD_OK) { h->auth = plain; h->auth_len = plen; }
  h->w.cmd.run = hku_classified;
  h->w.cmd.drop = hku_drop;
  h->w.work = hku_classify;
  if (ssh_queue_work(c, &h->w) != SD_OK) hku_work_free(h);
}

static void on_hostkeys_00(sd_ssh_conn *c, const uint8_t *p, size_t n, size_t off)
{
  ssh_hku *u = ssh_hku_get(c);
  sd_rd r;
  uint32_t total = 0;
  if (!u) return;
  if (u->announced) { ssh_log(c, SD_LOG_DEBUG, "hostkeys-00: further announcement ignored"); return; }
  u->announced = 1;
  sd_rd_init(&r, p + off, n - off);
  while (sd_rd_remaining(&r) && sd_rd_ok(&r)) {
    sd_span b = sd_rd_string(&r, SSH_HOSTKEY_MAX);
    ssh_pubkey pk;
    uint32_t i;
    int dup = 0;
    if (!sd_rd_ok(&r)) break;
    total++;
    if (u->nann >= SSH_HKU_MAX_KEYS) continue;
    for (i = 0; i < u->nann; i++) if (same_key(&u->ann[i], b.p, b.n)) dup = 1;
    if (dup) continue;
    /* unsupported or malformed key types (certificates included) are ignored */
    if (ssh_pubkey_parse(b.p, b.n, &pk) != SD_OK) continue;
    ssh_pubkey_free(&pk);
    if (key_set(&u->ann[u->nann], b.p, b.n) == SD_OK) u->nann++;
  }
  if (!sd_rd_ok(&r)) { ssh_log(c, SD_LOG_WARN, "hostkeys-00: malformed announcement ignored"); u->nann = 0; return; }
  ssh_log(c, SD_LOG_INFO, "hostkeys-00: server announced %u key(s), %u usable", total, u->nann);
  if (u->nann) start_update(c);
}

int ssh_hku_on_global_request(sd_ssh_conn *c, sd_span name, int want_reply, const uint8_t *p, size_t n)
{
  if (ssh_span_eq(name, "hostkeys-00@openssh.com")) {
    size_t off = 1 + 4 + name.n + 1;   /* msg, string name, bool */
    if (off <= n) on_hostkeys_00(c, p, n, off);
    if (want_reply) { uint8_t b = SSH_MSG_REQUEST_FAILURE; ssh_send(c, &b, 1); }
    return 1;
  }
  return 0;
}

static void fetch_continue(sd_ssh_conn *c);

int ssh_hku_on_reply(sd_ssh_conn *c, const uint8_t *p, size_t n)
{
  ssh_hku *u = c->hku;
  ssh_hku_req purpose;
  int ok;
  uint32_t i, idx[SSH_HKU_MAX_KEYS], nidx;
  if (!u || u->prove == SSH_HKU_REQ_NONE) return 0;
  if (u->prove_ahead) { u->prove_ahead--; return 0; }
  purpose = u->prove;
  u->prove = SSH_HKU_REQ_NONE;
  ok = p[0] == SSH_MSG_REQUEST_SUCCESS && check_proofs(c, p, n);
  nidx = u->nprove;
  memcpy(idx, u->prove_idx, nidx * sizeof(idx[0]));
  u->nprove = 0;
  if (!ok) ssh_log(c, SD_LOG_WARN, "hostkeys-prove-00 %s: the whole update is rejected",
                   p[0] == SSH_MSG_REQUEST_SUCCESS ? "proof invalid" : "refused by the server");
  if (purpose == SSH_HKU_REQ_UPDATE) {
    if (ok) raise_announced(c, idx, nidx);
  } else if (purpose == SSH_HKU_REQ_FETCH && u->fetching) {
    if (ok)
      for (i = 0; i < nidx && u->ngot < SD_COUNTOF(u->got); i++)
        if (key_set(&u->got[u->ngot], u->ann[idx[i]].blob, u->ann[idx[i]].len) == SD_OK) u->ngot++;
    fetch_continue(c);
  }
  return 1;
}

/* ---- sd_ssh_conn_fetch_hostkeys (01 §4.3, §9) ---- */

static int type_requested(const ssh_hku *u, const char *type)
{
  uint32_t i;
  if (!u->nfetch_types) return 1;
  for (i = 0; i < u->nfetch_types; i++) if (strcmp(u->fetch_types[i], type) == 0) return 1;
  return 0;
}

static int have_type(const ssh_hku *u, const char *type)
{
  uint32_t i;
  for (i = 0; i < u->ngot; i++) if (strcmp(u->got[i].type, type) == 0) return 1;
  return 0;
}

void ssh_hku_on_fetch_key(sd_ssh_conn *c, const uint8_t *ks, size_t n)
{
  ssh_hku *u = c->hku;
  uint8_t *plain = NULL;
  size_t plen = 0;
  if (!u || !u->fetching || !u->fetch_rekey) return;
  if (n == c->hostkey_len && memcmp(ks, c->hostkey, n) == 0) return;   /* the key we already have */
  if (ssh_blob_plain_key(ks, n, &plain, &plen) != SD_OK) return;
  if (u->ngot < SD_COUNTOF(u->got) && key_set(&u->got[u->ngot], plain, plen) == SD_OK) {
    ssh_log(c, SD_LOG_INFO, "fetch_hostkeys: re-key produced %s %s", u->got[u->ngot].type, u->got[u->ngot].fp);
    u->ngot++;
  }
  sd_free(plain);
}

void ssh_hku_on_rekey_done(sd_ssh_conn *c)
{
  ssh_hku *u = c->hku;
  if (!u || !u->fetching || !u->fetch_rekey) return;
  u->fetch_rekey = 0;
  fetch_continue(c);
}

/* Next requested type that is neither proven nor the session's own type: re-key restricted to it. */
static void fetch_continue(sd_ssh_conn *c)
{
  ssh_hku *u = c->hku;
  char own_type[48];
  uint8_t *plain = NULL;
  size_t plen = 0;
  if (!u || !u->fetching) return;
  own_type[0] = '\0';
  if (ssh_blob_plain_key(c->hostkey, c->hostkey_len, &plain, &plen) == SD_OK) {
    if (!ssh_span_copy(ssh_blob_key_type(plain, plen), own_type, sizeof(own_type))) own_type[0] = '\0';
    sd_free(plain);
  }
  while (u->fetch_next_type < u->nfetch_types) {
    const char *t = u->fetch_types[u->fetch_next_type++];
    char algs[256], offer[256];
    sd_span sl;
    const char *q;
    if (have_type(u, t) || strcmp(t, own_type) == 0) continue;
    if (ssh_hostkey_algs_for_type(t, c->legacy_policy != SD_LEGACY_REFUSE, NULL, algs, sizeof(algs)) != SD_OK) continue;
    /* keep only what the server's first KEXINIT offered, so the re-key cannot fail */
    offer[0] = '\0';
    sl.p = (const uint8_t *)u->server_hk_algs;
    sl.n = strlen(u->server_hk_algs);
    q = algs;
    while (q && *q) {
      const char *e = strchr(q, ',');
      size_t l = e ? (size_t)(e - q) : strlen(q);
      char one[64];
      if (l < sizeof(one)) {
        memcpy(one, q, l);
        one[l] = '\0';
        if (sl.n && sd_namelist_contains(sl, one) && strlen(offer) + l + 2 < sizeof(offer)) {
          if (offer[0]) strcat_s(offer, sizeof(offer), ",");
          strcat_s(offer, sizeof(offer), one);
        }
      }
      q = e ? e + 1 : NULL;
    }
    if (!offer[0]) { ssh_log(c, SD_LOG_INFO, "fetch_hostkeys: the server offers no %s host key", t); continue; }
    u->fetch_rekey = 1;
    if (ssh_kex_start_fetch_rekey(c, offer) != SD_OK) { u->fetch_rekey = 0; finish_fetch(c, SD_E_BUSY); }
    return;
  }
  finish_fetch(c, SD_OK);
}

static void fetch_start(sd_ssh_conn *c)
{
  ssh_hku *u = ssh_hku_get(c);
  uint32_t i, idx[SSH_HKU_MAX_KEYS], n = 0;
  uint8_t *plain = NULL;
  size_t plen = 0;
  if (!u) { finish_fetch(c, SD_E_NO_MEMORY); return; }
  if (ssh_blob_plain_key(c->hostkey, c->hostkey_len, &plain, &plen) != SD_OK) { plain = NULL; plen = 0; }
  for (i = 0; i < u->nann; i++) {
    if (!type_requested(u, u->ann[i].type)) continue;
    if (plain && same_key(&u->ann[i], plain, plen)) continue;   /* the session's own key */
    idx[n++] = i;
  }
  sd_free(plain);
  if (n) {
    if (send_prove(c, idx, n, SSH_HKU_REQ_FETCH) != SD_OK) finish_fetch(c, SD_E_DISCONNECTED);
    return;
  }
  fetch_continue(c);
}

typedef struct fetch_cmd {
  ssh_cmd cmd;
  uint32_t hop_index;
  char types[8][48]; uint32_t ntypes;
  sd_ssh_hostkeys_cb done; void *ctx;
} fetch_cmd;

static void fetch_run(sd_ssh_conn *r, ssh_cmd *cmd)
{
  fetch_cmd *f = (fetch_cmd *)cmd;
  sd_ssh_conn *c = r;
  ssh_hku *u;
  sd_err e = SD_OK;
  uint32_t i;
  if (r->hops && r->nhops) c = f->hop_index < r->nhops ? r->hops[f->hop_index] : NULL;
  else if (f->hop_index != 0) c = NULL;
  if (!c) e = SD_E_INVALID_PARAM;
  else if (c->st != SSH_ST_CONNECTED || c->failing) e = SD_E_DISCONNECTED;
  else if (!verified_by_trusted_key(c)) e = SD_E_HOSTKEY_REJECTED;   /* 01 §4.3: verified MATCH only */
  if (e == SD_OK) {
    u = ssh_hku_get(c);
    if (!u) e = SD_E_NO_MEMORY;
    else if (u->fetching || u->prove != SSH_HKU_REQ_NONE) e = SD_E_BUSY;
  }
  if (e != SD_OK) {
    if (f->done) f->done(f->ctx, e, NULL, 0);
    sd_free(f);
    return;
  }
  u = c->hku;
  u->fetching = 1;
  u->fetch_done = f->done;
  u->fetch_ctx = f->ctx;
  u->nfetch_types = f->ntypes;
  for (i = 0; i < f->ntypes; i++) memcpy(u->fetch_types[i], f->types[i], sizeof(u->fetch_types[i]));
  u->fetch_next_type = 0;
  u->ngot = 0;
  sd_free(f);
  ssh_log(c, SD_LOG_INFO, "fetch_hostkeys started (%u type(s) requested)", u->nfetch_types);
  fetch_start(c);
}

static void fetch_drop(ssh_cmd *cmd) { sd_free(cmd); }

sd_err sd_ssh_conn_fetch_hostkeys(sd_ssh_conn *c, uint32_t hop_index, const char *const *types, uint32_t ntypes,
                                  sd_ssh_hostkeys_cb done, void *ctx)
{
  fetch_cmd *f;
  uint32_t i;
  sd_err e;
  if (!c || !done || ntypes > 8 || (ntypes && !types)) return SD_E_INVALID_PARAM;
  f = (fetch_cmd *)sd_calloc(1, sizeof(*f));
  if (!f) return SD_E_NO_MEMORY;
  for (i = 0; i < ntypes; i++) {
    /* key types ("ssh-rsa") or host key algorithm names ("rsa-sha2-512") */
    const char *t = types[i] ? ssh_hostkey_alg_key_type(types[i]) : NULL;
    if (!t || ssh_hostkey_alg_is_cert(types[i]) || strlen(t) >= sizeof(f->types[0])) { sd_free(f); return SD_E_INVALID_PARAM; }
    memcpy(f->types[i], t, strlen(t) + 1);
  }
  f->ntypes = ntypes;
  f->hop_index = hop_index;
  f->done = done;
  f->ctx = ctx;
  f->cmd.run = fetch_run;
  f->cmd.drop = fetch_drop;
  e = ssh_post_cmd(c, &f->cmd);
  if (e != SD_OK) sd_free(f);
  return e;
}
