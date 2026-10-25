/* Key exchange: curve25519-sha256 (RFC 8731), strict KEX, rekeying, host key verification
 * (01 §4.2-§4.4, §7.1; TM-R01, TM-R04, TM-R05). I/O thread only. */
#include <string.h>

#include "sd_base/sd_mem.h"
#include "sd_platform/sd_platform.h"
#include "sd_platform/sd_time.h"
#include "conn_internal.h"

void ssh_kex_reset(sd_ssh_conn *c)
{
  ssh_kex_state *k = &c->kex;
  if (k->i_c) sd_free(k->i_c);
  if (k->i_s) sd_free(k->i_s);
  sd_secure_zero(k, sizeof(*k));
}

void ssh_kex_on_ident(sd_ssh_conn *c)
{
  ssh_kex_try_send_initial(c);
}

static int hw_aes(void)
{
  uint32_t f = sd_cpu_features();
  return (f & SD_CPU_AESNI) && (f & SD_CPU_PCLMUL);
}

static sd_err send_kexinit(sd_ssh_conn *c, const ssh_lists *l)
{
  uint8_t cookie[16];
  sd_wr w;
  sd_err e = ssh_random(cookie, sizeof(cookie));
  if (e != SD_OK) return e;
  sd_wr_init(&w, 64 * 1024);
  ssh_kexinit_encode(&w, cookie, l);
  if (!sd_wr_ok(&w)) { sd_wr_free(&w); return SD_E_NO_MEMORY; }
  c->kex.i_c = (uint8_t *)sd_alloc(w.len);
  if (!c->kex.i_c) { sd_wr_free(&w); return SD_E_NO_MEMORY; }
  memcpy(c->kex.i_c, w.p, w.len);
  c->kex.i_c_len = w.len;
  c->kex.we_sent_kexinit = 1;
  return ssh_send_wr(c, &w);
}

static void send_ecdh_init(sd_ssh_conn *c);

static void negotiate(sd_ssh_conn *c)
{
  ssh_kex_state *k = &c->kex;
  const char *cat = NULL;
  sd_err e;
  /* The initial KEXINIT carried the same lists plus the pseudo names, which negotiation skips. */
  e = ssh_negotiate(&c->fixed_lists, &k->server, &k->algs, &cat);
  if (e != SD_OK) {
    int restricted = c->stored_types.count > 0 || c->stored_types.has_ca;
    ssh_log(c, SD_LOG_WARN, "no common %s algorithm", cat ? cat : "?");
    if (cat && strcmp(cat, "hostkey") == 0 && restricted)
      ssh_fail(c, SD_E_HOSTKEY_TYPE_UNAVAILABLE, SSH_DISCONNECT_KEY_EXCHANGE_FAILED, "host_key_type_unavailable");
    else
      ssh_fail(c, SD_E_KEX_FAILED, SSH_DISCONNECT_KEY_EXCHANGE_FAILED, "no common algorithm");
    return;
  }
  if (k->server.first_kex_follows) {
    char first[64];
    sd_span it, list = k->server.kex;
    int right = 0;
    if (sd_namelist_next(&list, &it) && ssh_span_copy(it, first, sizeof(first)) && strcmp(first, k->algs.kex) == 0) {
      list = k->server.hostkey;
      if (sd_namelist_next(&list, &it) && ssh_span_copy(it, first, sizeof(first)) && strcmp(first, k->algs.hostkey) == 0)
        right = 1;
    }
    k->ignore_next_kex_packet = !right;
  }
  if (k->initial) {
    if (!c->strict) c->legacy_mask |= SD_LEGACY_NO_STRICT_KEX;
    if (!c->strict && (strcmp(k->algs.enc_c2s, "chacha20-poly1305@openssh.com") == 0 ||
                       strcmp(k->algs.enc_s2c, "chacha20-poly1305@openssh.com") == 0)) {
      c->legacy_mask |= SD_LEGACY_TERRAPIN_EXPOSED;
      if (c->refuse_terrapin) {
        ssh_log(c, SD_LOG_WARN, "terrapin_exposed");
        ssh_fail(c, SD_E_KEX_FAILED, SSH_DISCONNECT_KEY_EXCHANGE_FAILED, "terrapin_exposed");
        return;
      }
    }
    if ((k->algs.mac_c2s[0] && !strstr(k->algs.mac_c2s, "-etm@")) || (k->algs.mac_s2c[0] && !strstr(k->algs.mac_s2c, "-etm@")))
      c->legacy_mask |= SD_LEGACY_MAC_NON_ETM;
  }
  ssh_log(c, SD_LOG_DEBUG, "negotiated kex=%s hostkey=%s c2s=%s/%s s2c=%s/%s", k->algs.kex, k->algs.hostkey,
          k->algs.enc_c2s, k->algs.mac_c2s, k->algs.enc_s2c, k->algs.mac_s2c);
  send_ecdh_init(c);
}

void ssh_kex_try_send_initial(sd_ssh_conn *c)
{
  ssh_kex_state *k = &c->kex;
  ssh_list_input in;
  ssh_list_result res, res2;
  ssh_lists sent;
  sd_err e;
  if (c->failing || c->st != SSH_ST_KEX || !k->initial || k->we_sent_kexinit) return;
  if (!c->stored_types_done) return;
  if (!k->got_server_kexinit && ssh_now() < c->kexinit_wait_deadline) return;

  memset(&in, 0, sizeof(in));
  in.server = k->got_server_kexinit ? &k->server : NULL;
  in.stored = &c->stored_types;
  in.hw_aes = hw_aes();
  in.disabled = c->disabled;
  in.refuse_terrapin_exposed = c->refuse_terrapin && in.server != NULL;
  in.initial = 1;
  e = ssh_build_lists(&in, &sent, &res);
  if (e == SD_OK) {
    in.initial = 0;
    e = ssh_build_lists(&in, &c->fixed_lists, &res2);
  }
  if (e != SD_OK) {
    if (e == SD_E_KEX_FAILED && res.terrapin_exposed) ssh_log(c, SD_LOG_WARN, "terrapin_exposed");
    ssh_fail(c, e, SSH_DISCONNECT_KEY_EXCHANGE_FAILED,
             e == SD_E_HOSTKEY_TYPE_UNAVAILABLE ? "host_key_type_unavailable" : "algorithm lists");
    return;
  }
  if (!in.server) {
    k->fallback_lists = 1;
    ssh_log(c, SD_LOG_INFO, "kexinit_wait_timeout");
  } else {
    if (res.terrapin_exposed) ssh_log(c, SD_LOG_WARN, "server offers only Terrapin-affected ciphers");
    if (res.chacha_removed) ssh_log(c, SD_LOG_DEBUG, "chacha20-poly1305 removed: server lacks strict KEX");
  }
  e = send_kexinit(c, &sent);
  if (e != SD_OK) { ssh_fail(c, e, SSH_DISCONNECT_KEY_EXCHANGE_FAILED, "send KEXINIT"); return; }
  if (k->got_server_kexinit) negotiate(c);
}

void ssh_kex_start_rekey(sd_ssh_conn *c)
{
  ssh_kex_state *k = &c->kex;
  sd_err e;
  if (c->failing || k->active || c->session_id_len == 0) return;
  ssh_kex_reset(c);
  k->active = 1;
  k->initial = 0;
  ssh_log(c, SD_LOG_DEBUG, "rekey started");
  e = send_kexinit(c, &c->fixed_lists);
  if (e != SD_OK) ssh_fail(c, e, SSH_DISCONNECT_KEY_EXCHANGE_FAILED, "send KEXINIT");
}

static void on_kexinit(sd_ssh_conn *c, const uint8_t *p, size_t n)
{
  ssh_kex_state *k = &c->kex;
  if (k->active && k->got_server_kexinit) {
    ssh_fail(c, SD_E_PROTOCOL, SSH_DISCONNECT_PROTOCOL_ERROR, "duplicate KEXINIT");
    return;
  }
  if (!k->active) {           /* server-initiated rekey */
    ssh_kex_reset(c);
    k->active = 1;
    k->initial = 0;
  }
  k->i_s = (uint8_t *)sd_alloc(n);
  if (!k->i_s) { ssh_fail(c, SD_E_NO_MEMORY, 0, "KEXINIT"); return; }
  memcpy(k->i_s, p, n);
  k->i_s_len = n;
  if (ssh_kexinit_parse(k->i_s, n, &k->server) != SD_OK) {
    ssh_fail(c, SD_E_PROTOCOL, SSH_DISCONNECT_PROTOCOL_ERROR, "bad KEXINIT");
    return;
  }
  k->got_server_kexinit = 1;
  if (k->initial) {
    c->strict = sd_namelist_contains(k->server.kex, "kex-strict-s-v00@openssh.com");
    if (c->strict && c->rx_packets_before_kexinit) {
      ssh_fail(c, SD_E_PROTOCOL, SSH_DISCONNECT_PROTOCOL_ERROR, "strict KEX: KEXINIT not first");
      return;
    }
    if (!k->we_sent_kexinit) { ssh_kex_try_send_initial(c); return; }
  } else if (!k->we_sent_kexinit) {
    sd_err e = send_kexinit(c, &c->fixed_lists);
    if (e != SD_OK) { ssh_fail(c, e, SSH_DISCONNECT_KEY_EXCHANGE_FAILED, "send KEXINIT"); return; }
  }
  negotiate(c);
}

static void send_ecdh_init(sd_ssh_conn *c)
{
  ssh_kex_state *k = &c->kex;
  uint8_t buf[64];
  sd_wr w;
  sd_err e;
  if (strcmp(k->algs.kex, "curve25519-sha256") != 0 && strcmp(k->algs.kex, "curve25519-sha256@libssh.org") != 0) {
    ssh_fail(c, SD_E_KEX_FAILED, SSH_DISCONNECT_KEY_EXCHANGE_FAILED, "unsupported kex");
    return;
  }
  e = ssh_random(k->x_priv, 32);
  if (e == SD_OK) e = sd_x25519_base(k->q_c, k->x_priv);
  if (e != SD_OK) { ssh_fail(c, SD_E_KEX_FAILED, SSH_DISCONNECT_KEY_EXCHANGE_FAILED, "x25519"); return; }
  sd_wr_init_fixed(&w, buf, sizeof(buf));
  sd_wr_u8(&w, SSH_MSG_KEX_ECDH_INIT);
  sd_wr_string(&w, k->q_c, 32);
  k->sent_init = 1;
  ssh_send(c, w.p, w.len);
}

/* RFC 4253 §7.2 key derivation with SHA-256. */
static void derive(const uint8_t *kmp, size_t kmp_len, const uint8_t *h, size_t hlen, char x,
                   const uint8_t *sid, size_t sid_len, uint8_t *out, size_t need)
{
  uint8_t acc[128];
  size_t have = 0;
  sd_hash_ctx hc;
  sd_hash_init(&hc, SD_HASH_SHA256);
  sd_hash_update(&hc, kmp, kmp_len);
  sd_hash_update(&hc, h, hlen);
  sd_hash_update(&hc, &x, 1);
  sd_hash_update(&hc, sid, sid_len);
  sd_hash_final(&hc, acc);
  have = 32;
  while (have < need && have + 32 <= sizeof(acc)) {
    sd_hash_init(&hc, SD_HASH_SHA256);
    sd_hash_update(&hc, kmp, kmp_len);
    sd_hash_update(&hc, h, hlen);
    sd_hash_update(&hc, acc, have);
    sd_hash_final(&hc, acc + have);
    have += 32;
  }
  memcpy(out, acc, need);
  sd_secure_zero(acc, sizeof(acc));
}

static void hash_string(sd_hash_ctx *hc, const void *p, size_t n)
{
  uint8_t l[4];
  sd_store_be32(l, (uint32_t)n);
  sd_hash_update(hc, l, 4);
  sd_hash_update(hc, p, n);
}

static void start_hostkey_check(sd_ssh_conn *c);
static void send_newkeys(sd_ssh_conn *c);

static void on_reply(sd_ssh_conn *c, const uint8_t *p, size_t n)
{
  ssh_kex_state *k = &c->kex;
  sd_rd r, kr, sr;
  sd_span ks, qs, sig, kt, pk, st, sv;
  uint8_t shared[32], h[32];
  sd_wr kmp;
  sd_hash_ctx hc;
  size_t klen = 0, ivlen = 0, mlen = 0, klen2 = 0, ivlen2 = 0, mlen2 = 0;
  sd_err e;

  if (!k->sent_init || k->reply_done) { ssh_fail(c, SD_E_PROTOCOL, SSH_DISCONNECT_PROTOCOL_ERROR, "unexpected KEX reply"); return; }
  sd_rd_init(&r, p + 1, n - 1);
  ks = sd_rd_string(&r, 16384);
  qs = sd_rd_string(&r, 64);
  sig = sd_rd_string(&r, 1024);
  if (!sd_rd_done(&r) || qs.n != 32 || ks.n > sizeof(c->hostkey)) {
    ssh_fail(c, SD_E_PROTOCOL, SSH_DISCONNECT_PROTOCOL_ERROR, "bad KEX reply");
    return;
  }
  sd_rd_init(&kr, ks.p, ks.n);
  kt = sd_rd_string(&kr, 64);
  pk = sd_rd_string(&kr, 64);
  if (!sd_rd_done(&kr) || !ssh_span_eq(kt, k->algs.hostkey) || !ssh_span_eq(kt, "ssh-ed25519") || pk.n != 32) {
    ssh_fail(c, SD_E_KEX_FAILED, SSH_DISCONNECT_KEY_EXCHANGE_FAILED, "host key type does not match");
    return;
  }
  sd_rd_init(&sr, sig.p, sig.n);
  st = sd_rd_string(&sr, 64);
  sv = sd_rd_string(&sr, 64);
  if (!sd_rd_done(&sr) || !ssh_span_eq(st, "ssh-ed25519") || sv.n != 64) {
    ssh_fail(c, SD_E_KEX_FAILED, SSH_DISCONNECT_KEY_EXCHANGE_FAILED, "bad host key signature encoding");
    return;
  }
  e = sd_x25519(shared, k->x_priv, qs.p);
  sd_secure_zero(k->x_priv, sizeof(k->x_priv));
  if (e != SD_OK) { ssh_fail(c, SD_E_KEX_FAILED, SSH_DISCONNECT_KEY_EXCHANGE_FAILED, "x25519 shared secret rejected"); return; }
  sd_wr_init_secret(&kmp, 64);
  sd_wr_mpint(&kmp, shared, 32);    /* RFC 8731: the X25519 output as a big-endian unsigned number */
  sd_secure_zero(shared, sizeof(shared));
  if (!sd_wr_ok(&kmp)) { sd_wr_free(&kmp); ssh_fail(c, SD_E_NO_MEMORY, 0, "kex"); return; }

  sd_hash_init(&hc, SD_HASH_SHA256);
  hash_string(&hc, ssh_ident_c, strlen(ssh_ident_c));
  hash_string(&hc, c->ident_s, strlen(c->ident_s));
  hash_string(&hc, k->i_c, k->i_c_len);
  hash_string(&hc, k->i_s, k->i_s_len);
  hash_string(&hc, ks.p, ks.n);
  hash_string(&hc, k->q_c, 32);
  hash_string(&hc, qs.p, 32);
  sd_hash_update(&hc, kmp.p, kmp.len);
  sd_hash_final(&hc, h);

  if (sd_ed25519_verify(sv.p, pk.p, h, 32) != SD_OK) {
    sd_wr_free(&kmp);
    ssh_fail(c, SD_E_KEX_FAILED, SSH_DISCONNECT_KEY_EXCHANGE_FAILED, "host key signature invalid");
    return;
  }
  if (c->session_id_len == 0) {
    memcpy(c->session_id, h, 32);
    c->session_id_len = 32;
  }
  e = ssh_alg_key_sizes(k->algs.enc_c2s, k->algs.mac_c2s, &klen, &ivlen, &mlen);
  if (e == SD_OK) e = ssh_alg_key_sizes(k->algs.enc_s2c, k->algs.mac_s2c, &klen2, &ivlen2, &mlen2);
  if (e != SD_OK || klen > 64 || klen2 > 64 || ivlen > 32 || ivlen2 > 32 || mlen > 64 || mlen2 > 64) {
    sd_wr_free(&kmp);
    ssh_fail(c, SD_E_KEX_FAILED, SSH_DISCONNECT_KEY_EXCHANGE_FAILED, "cipher unavailable");
    return;
  }
  if (ivlen) derive(kmp.p, kmp.len, h, 32, 'A', c->session_id, c->session_id_len, k->iv_c2s, ivlen);
  if (ivlen2) derive(kmp.p, kmp.len, h, 32, 'B', c->session_id, c->session_id_len, k->iv_s2c, ivlen2);
  derive(kmp.p, kmp.len, h, 32, 'C', c->session_id, c->session_id_len, k->key_c2s, klen);
  derive(kmp.p, kmp.len, h, 32, 'D', c->session_id, c->session_id_len, k->key_s2c, klen2);
  if (mlen) derive(kmp.p, kmp.len, h, 32, 'E', c->session_id, c->session_id_len, k->mac_c2s, mlen);
  if (mlen2) derive(kmp.p, kmp.len, h, 32, 'F', c->session_id, c->session_id_len, k->mac_s2c, mlen2);
  sd_wr_free(&kmp);
  sd_secure_zero(h, sizeof(h));
  k->reply_done = 1;

  if (k->initial) {
    memcpy(c->hostkey, ks.p, ks.n);
    c->hostkey_len = ks.n;
    if (sd_hostkey_fingerprint_sha256(ks.p, ks.n, c->hostkey_fp) != SD_OK) c->hostkey_fp[0] = '\0';
    ssh_log(c, SD_LOG_INFO, "host key %s %s", k->algs.hostkey, c->hostkey_fp);
    start_hostkey_check(c);
  } else {
    if (ks.n != c->hostkey_len || memcmp(ks.p, c->hostkey, ks.n) != 0) {
      ssh_fail(c, SD_E_HOSTKEY_MISMATCH, SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE, "host key changed during rekey");
      return;
    }
    k->hostkey_ok = 1;
    send_newkeys(c);
  }
}

static void kex_check_done(sd_ssh_conn *c)
{
  ssh_kex_state *k = &c->kex;
  int initial = k->initial;
  sd_ssh_negotiated neg;
  if (!k->newkeys_sent || !k->newkeys_recv) return;
  memset(&neg, 0, sizeof(neg));
  neg.hop_index = 0;
  neg.kex = k->algs.kex;
  neg.hostkey = k->algs.hostkey;
  neg.cipher_c2s = k->algs.enc_c2s;
  neg.cipher_s2c = k->algs.enc_s2c;
  neg.mac_c2s = k->algs.mac_c2s;
  neg.mac_s2c = k->algs.mac_s2c;
  neg.comp_c2s = k->algs.comp_c2s;
  neg.comp_s2c = k->algs.comp_s2c;
  neg.server_version = c->server_version;
  neg.hostkey_fp_sha256 = c->hostkey_fp;
  neg.strict_kex = c->strict;
  neg.legacy_mask = c->legacy_mask;
  ssh_log(c, SD_LOG_INFO, "kex done kex=%s cipher=%s/%s strict=%d", neg.kex, neg.cipher_c2s, neg.cipher_s2c, c->strict);
  if (c->cb.on_negotiated) c->cb.on_negotiated(c->cb.ctx, &neg);
  ssh_kex_reset(c);   /* wipes the derived keys (already installed) */
  c->last_kex_tick = ssh_now();
  if (initial) ssh_after_initial_kex(c);
}

static void send_newkeys(sd_ssh_conn *c)
{
  ssh_kex_state *k = &c->kex;
  uint8_t b = SSH_MSG_NEWKEYS;
  sd_err e;
  if (ssh_send(c, &b, 1) != SD_OK) return;
  e = ssh_dir_set_keys(&c->tx, 1, k->algs.enc_c2s, k->algs.mac_c2s, k->key_c2s, k->iv_c2s, k->mac_c2s);
  if (e != SD_OK) { ssh_fail(c, SD_E_KEX_FAILED, 0, "install keys"); return; }
  if (c->strict) c->tx.seq = 0;
  k->newkeys_sent = 1;
  ssh_flush_pending(c);
  kex_check_done(c);
}

static void on_newkeys(sd_ssh_conn *c)
{
  ssh_kex_state *k = &c->kex;
  sd_err e;
  if (!k->reply_done || k->newkeys_recv) { ssh_fail(c, SD_E_PROTOCOL, SSH_DISCONNECT_PROTOCOL_ERROR, "unexpected NEWKEYS"); return; }
  e = ssh_dir_set_keys(&c->rx, 0, k->algs.enc_s2c, k->algs.mac_s2c, k->key_s2c, k->iv_s2c, k->mac_s2c);
  if (e != SD_OK) { ssh_fail(c, SD_E_KEX_FAILED, 0, "install keys"); return; }
  if (c->strict) c->rx.seq = 0;
  k->newkeys_recv = 1;
  kex_check_done(c);
}

void ssh_kex_on_msg(sd_ssh_conn *c, const uint8_t *p, size_t n)
{
  uint8_t m = p[0];
  if (m == SSH_MSG_KEXINIT) { on_kexinit(c, p, n); return; }
  if (!c->kex.active) { ssh_fail(c, SD_E_PROTOCOL, SSH_DISCONNECT_PROTOCOL_ERROR, "KEX message outside KEX"); return; }
  if (m >= 30 && m <= 49 && c->kex.ignore_next_kex_packet) { c->kex.ignore_next_kex_packet = 0; return; }
  if (m == SSH_MSG_NEWKEYS) { on_newkeys(c); return; }
  if (m == SSH_MSG_KEX_ECDH_REPLY) { on_reply(c, p, n); return; }
  ssh_fail(c, SD_E_PROTOCOL, SSH_DISCONNECT_PROTOCOL_ERROR, "unexpected KEX message");
}

/* ---- host key verification (01 §7.1) ---- */

typedef struct hk_work {
  ssh_work w;
  sd_known_hosts *kh;
  char name[320];
  uint8_t blob[512]; size_t len;
  int add;                    /* 1: sd_known_hosts_add instead of check */
  sd_hk_result res;
  sd_err err;
} hk_work;

static void hk_do(ssh_work *w)
{
  hk_work *h = (hk_work *)w;
  if (h->add) {
    char comment[64];
    SYSTEMTIME t;
    GetSystemTime(&t);
    comment[0] = '\0';
    {
      /* "# added=YYYY-MM-DD" (03 §5.1 comment style) */
      static const char k_pfx[] = "# added=";
      char *o = comment;
      memcpy(o, k_pfx, sizeof(k_pfx) - 1); o += sizeof(k_pfx) - 1;
      *o++ = (char)('0' + (t.wYear / 1000) % 10); *o++ = (char)('0' + (t.wYear / 100) % 10);
      *o++ = (char)('0' + (t.wYear / 10) % 10); *o++ = (char)('0' + t.wYear % 10); *o++ = '-';
      *o++ = (char)('0' + t.wMonth / 10); *o++ = (char)('0' + t.wMonth % 10); *o++ = '-';
      *o++ = (char)('0' + t.wDay / 10); *o++ = (char)('0' + t.wDay % 10); *o = '\0';
    }
    h->err = sd_known_hosts_add(h->kh, SD_KH_STORE_USER, h->name, h->blob, h->len, comment);
  } else {
    h->err = sd_known_hosts_check(h->kh, h->name, h->blob, h->len, (uint64_t)sd_unix_time_now(), &h->res);
  }
}

static void raise_hostkey_prompt(sd_ssh_conn *c)
{
  sd_prompt *p = ssh_prompt_new(c, SSH_PP_HOSTKEY, SD_PROMPT_HOSTKEY);
  sd_hostkey_prompt_info *hi;
  if (!p) { ssh_fail(c, SD_E_NO_MEMORY, SSH_DISCONNECT_BY_APPLICATION, "prompt"); return; }
  hi = ssh_prompt_hk_info(p);
  hi->hop_index = 0;
  hi->host = c->host_utf8;
  hi->port = c->port;
  hi->via_host = NULL;
  hi->lookup_name = ssh_prompt_str(p, c->lookup_name);
  hi->key_type = ssh_prompt_str(p, c->kex.algs.hostkey);
  hi->key_bits = 256;
  hi->fp_sha256 = ssh_prompt_str(p, c->hostkey_fp);
  hi->fp_md5 = "";
  hi->status = SD_HK_NEW;
  ssh_prompt_raise(c, p);
}

static void hostkey_ok(sd_ssh_conn *c)
{
  c->kex.hostkey_ok = 1;
  send_newkeys(c);
}

/* 01 §8: the key the previous connect of this object verified. */
static int hostkey_is_pinned(const sd_ssh_conn *c)
{
  return c->pinned_len && c->pinned_len == c->hostkey_len && memcmp(c->pinned_hostkey, c->hostkey, c->hostkey_len) == 0;
}

/* Reconnect to a key that is in no store but was accepted (once) for this connection object before:
   no new prompt. It stays a fresh acceptance for TM-R05 (no cached or stored secrets). */
static int accept_pinned(sd_ssh_conn *c)
{
  if (!c->is_reconnect || !hostkey_is_pinned(c)) return 0;
  ssh_log(c, SD_LOG_INFO, "reconnect: host key of %s equals the key accepted for this session", c->lookup_name);
  c->hostkey_just_accepted = 1;
  c->hk_once = 1;
  hostkey_ok(c);
  return 1;
}

static void hk_done(sd_ssh_conn *c, ssh_cmd *cmd)
{
  hk_work *h = (hk_work *)cmd;
  if (h->add) {
    if (h->err != SD_OK) ssh_log(c, SD_LOG_WARN, "storing the host key failed: %s", sd_err_name(h->err));
    else ssh_log(c, SD_LOG_INFO, "host key stored for %s", h->name);
    sd_free(h);
    return;
  }
  if (h->w.gen != c->gen || c->failing || c->st != SSH_ST_KEX || !c->kex.initial || c->kex.hostkey_ok) { sd_free(h); return; }
  if (h->err != SD_OK) {
    ssh_log(c, SD_LOG_WARN, "known_hosts check failed: %s", sd_err_name(h->err));
    sd_free(h);
    ssh_fail(c, SD_E_HOSTKEY_REJECTED, SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE, "known_hosts unavailable");
    return;
  }
  switch (h->res.status) {
  case SD_HK_MATCH:
  case SD_HK_MATCH_CA:
    if (c->is_reconnect && c->pinned_len && !hostkey_is_pinned(c))
      ssh_log(c, SD_LOG_WARN, "host key of %s changed since the previous connection; it matches a trusted entry",
              c->lookup_name);
    ssh_log(c, SD_LOG_INFO, "host key verified for %s", c->lookup_name);
    sd_free(h);
    hostkey_ok(c);
    return;
  case SD_HK_NEW:
    sd_free(h);
    if (accept_pinned(c)) return;
    raise_hostkey_prompt(c);
    return;
  case SD_HK_NEW_TYPE:
    sd_free(h);
    ssh_fail(c, SD_E_HOSTKEY_TYPE_UNAVAILABLE, SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE, "host_key_type_unavailable");
    return;
  case SD_HK_MISMATCH:
  case SD_HK_REVOKED: {
    sd_hostkey_event ev;
    sd_hk_key oldk, newk;
    memset(&ev, 0, sizeof(ev));
    ev.kind = h->res.status == SD_HK_MISMATCH ? SD_HKEV_MISMATCH : SD_HKEV_REVOKED;
    ev.hop_index = 0;
    ev.lookup_name = c->lookup_name;
    ev.store = h->res.store;
    ev.path = h->res.path;
    ev.line = h->res.line;
    oldk.blob = NULL; oldk.len = 0; oldk.type = h->res.stored_type; oldk.fp_sha256 = h->res.stored_fp_sha256;
    newk.blob = c->hostkey; newk.len = c->hostkey_len; newk.type = c->kex.algs.hostkey; newk.fp_sha256 = c->hostkey_fp;
    ev.old_key = &oldk;
    ev.new_key = &newk;
    ssh_log(c, SD_LOG_WARN, "host key %s for %s (line %u)", h->res.status == SD_HK_MISMATCH ? "MISMATCH" : "REVOKED",
            c->lookup_name, h->res.line);
    if (c->cb.on_hostkey_event) c->cb.on_hostkey_event(c->cb.ctx, &ev);
    {
      sd_err e = h->res.status == SD_HK_MISMATCH ? SD_E_HOSTKEY_MISMATCH : SD_E_HOSTKEY_REVOKED;
      sd_free(h);
      ssh_fail(c, e, SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE, "host key not trusted");
    }
    return;
  }
  }
  sd_free(h);
  ssh_fail(c, SD_E_INTERNAL, SSH_DISCONNECT_BY_APPLICATION, "host key status");
}

static void hk_drop(ssh_cmd *cmd) { sd_free(cmd); }

static sd_err queue_hk_work(sd_ssh_conn *c, int add)
{
  hk_work *h = (hk_work *)sd_calloc(1, sizeof(*h));
  if (!h) return SD_E_NO_MEMORY;
  h->kh = c->kh;
  memcpy(h->name, c->lookup_name, sizeof(h->name));
  memcpy(h->blob, c->hostkey, c->hostkey_len);
  h->len = c->hostkey_len;
  h->add = add;
  h->w.cmd.run = hk_done;
  h->w.cmd.drop = hk_drop;
  h->w.work = hk_do;
  if (ssh_queue_work(c, &h->w) != SD_OK) { sd_free(h); return SD_E_INTERNAL; }
  return SD_OK;
}

static void start_hostkey_check(sd_ssh_conn *c)
{
  c->kex.hk_check_started = 1;
  if (!c->kh) { if (!accept_pinned(c)) raise_hostkey_prompt(c); return; }
  if (queue_hk_work(c, 0) != SD_OK) ssh_fail(c, SD_E_INTERNAL, SSH_DISCONNECT_BY_APPLICATION, "worker");
}

void ssh_kex_on_hostkey_answer(sd_ssh_conn *c, ssh_prompt_answer *a)
{
  if (c->st != SSH_ST_KEX || c->kex.hostkey_ok) return;
  if (a->cancelled || a->decision == SD_HK_REJECT) {
    ssh_fail(c, SD_E_HOSTKEY_REJECTED, SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE, "host key rejected by user");
    return;
  }
  c->hostkey_just_accepted = 1;   /* TM-R05 */
  c->hk_once = a->decision != SD_HK_ACCEPT_AND_STORE || !c->kh;
  if (a->decision == SD_HK_ACCEPT_AND_STORE) {
    if (c->kh) { if (queue_hk_work(c, 1) != SD_OK) ssh_log(c, SD_LOG_WARN, "could not queue host key store"); }
    else ssh_log(c, SD_LOG_WARN, "no known_hosts store configured; host key accepted once");
  }
  hostkey_ok(c);
}

void ssh_kex_on_legacy_answer(sd_ssh_conn *c, ssh_prompt_answer *a)
{
  if (c->st != SSH_ST_LEGACY_ACK) return;
  if (a->cancelled || !a->ack) {
    ssh_fail(c, SD_E_LEGACY_REJECTED, SSH_DISCONNECT_BY_APPLICATION, "legacy algorithms refused");
    return;
  }
  c->legacy_policy = SD_LEGACY_WARN;   /* acknowledged for this connection */
  ssh_after_initial_kex(c);
}
