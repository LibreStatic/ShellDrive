/* Matrix-driven interop tests (M2): each row of tests/interop/run-matrix.ps1 runs this binary with
 * the row's recipe in SD_IT_* variables (tests/interop/README.md). Exit code 77 when not under the
 * runner (plain ctest) or when sd_crypto is incomplete.
 *
 * Covers: the generic row recipe (direct server, jump chains, HTTP/SOCKS5 proxies, OTP, the demo
 * path) end to end with exec; negotiated KEX / host-key walking per fixture via the `disabled`
 * list (mlkem768x25519-sha256, curve25519, ECDH, DH/GEX incl. the SHA-1 legacy set, 3des-cbc);
 * the PQ-only server (a client without ML-KEM must fail KEX); UpdateHostKeys on the rotate
 * fixture: hostkeys-00 announcement, apply, rotation, reconnect on the learned key. */
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "sd_base/sd_mem.h"
#include "sd_platform/sd_thread.h"
#include "sd_platform/sd_time.h"
#include "sd_crypto/sd_crypto.h"
#include "sd_ssh/sd_ssh.h"
#include "sd_test.h"
#include "test_util.h"

/* ---- row environment ---- */

typedef struct mx {
  char server[32], host[64], key[MAX_PATH], cert[MAX_PATH];
  char jump[256], proxy[256], expect_kex[64];
  int expect_legacy, otp;
  char user[64], kh_src[MAX_PATH], fixture_sh[MAX_PATH];
  char otp_secret[128], proxy_user[64], proxy_pass[64];
  char pass[128];
  wchar_t whost[64], wkey[MAX_PATH], wcert[MAX_PATH], wkh[MAX_PATH];
  uint16_t port;
} mx;

static mx g;
static sd_known_hosts *g_kh;   /* one user-store copy for the process (cfg.known_hosts is borrowed) */

static void set_str(char *dst, size_t cap, const char *src)
{
  if (src && *src) _snprintf_s(dst, cap, _TRUNCATE, "%s", src);
  else dst[0] = 0;
}

static void to_wide(const char *utf8, wchar_t *out, int cap)
{
  MultiByteToWideChar(CP_UTF8, 0, utf8, -1, out, cap);
}

/* Row variable from the process environment (the runner exports it), else from the fixture
   endpoints file (when the binary is run by hand with SD_IT_ENV_FILE set). */
static int env_or_file(const char *name, char *out, size_t cap)
{
  static char buf[48 * 1024];
  static size_t len;
  static int loaded;
  char *p, *eq, *end;
  DWORD n = GetEnvironmentVariableA(name, out, (DWORD)cap);
  if (n > 0 && n < cap) return 1;
  if (!loaded) {
    static char path[MAX_PATH];
    DWORD k = GetEnvironmentVariableA("SD_IT_ENV_FILE", path, sizeof(path));
    FILE *f = NULL;
    loaded = 1;
    if (!k || k >= sizeof(path)) return 0;
    if (fopen_s(&f, path, "rb") != 0 || !f) return 0;
    len = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    buf[len] = 0;
  }
  for (p = buf; p < buf + len; p = end + 1) {
    end = strchr(p, '\n');
    if (!end) end = buf + len;
    eq = memchr(p, '=', end - p);
    if (eq && (size_t)(eq - p) == strlen(name) && memcmp(p, name, eq - p) == 0) {
      size_t vlen = (size_t)(end - eq - 1);
      if (end > eq && end[-1] == '\r') vlen--;
      if (vlen >= cap) return 0;
      memcpy(out, eq + 1, vlen);
      out[vlen] = 0;
      return 1;
    }
  }
  return 0;
}

static int mx_load(void)
{
  char port[16], expect_legacy[8], otp[8];
  wchar_t dir[MAX_PATH + 8], wsrc[MAX_PATH];
  sd_kh_store st;
  if (!GetEnvironmentVariableA("SD_IT_SERVER", g.server, sizeof(g.server))) return 0;
  if (!env_or_file("SD_IT_HOST", g.host, sizeof(g.host)) ||
      !env_or_file("SD_IT_PORT", port, sizeof(port)) ||
      !env_or_file("SD_IT_KEY", g.key, sizeof(g.key)) ||
      !env_or_file("SD_IT_USER", g.user, sizeof(g.user)) ||
      !env_or_file("SD_IT_KNOWN_HOSTS", g.kh_src, sizeof(g.kh_src)))
    return 0;
  g.port = (uint16_t)atoi(port);
  env_or_file("SD_IT_CERT", g.cert, sizeof(g.cert));
  env_or_file("SD_IT_JUMP", g.jump, sizeof(g.jump));
  env_or_file("SD_IT_PROXY", g.proxy, sizeof(g.proxy));
  env_or_file("SD_IT_EXPECT_KEX", g.expect_kex, sizeof(g.expect_kex));
  if (env_or_file("SD_IT_EXPECT_LEGACY", expect_legacy, sizeof(expect_legacy)))
    g.expect_legacy = atoi(expect_legacy);
  if (env_or_file("SD_IT_OTP", otp, sizeof(otp))) g.otp = atoi(otp);
  env_or_file("SD_IT_FIXTURE_SH", g.fixture_sh, sizeof(g.fixture_sh));
  env_or_file("SD_IT_OTP_SECRET", g.otp_secret, sizeof(g.otp_secret));
  env_or_file("SD_IT_PROXY_USER", g.proxy_user, sizeof(g.proxy_user));
  env_or_file("SD_IT_PROXY_PASS", g.proxy_pass, sizeof(g.proxy_pass));
  env_or_file("SD_IT_KEY_PASSPHRASE", g.pass, sizeof(g.pass));
  if (g.otp && !g.otp_secret[0]) return 0;
  to_wide(g.host, g.whost, (int)SD_COUNTOF(g.whost));
  to_wide(g.key, g.wkey, MAX_PATH);
  if (g.cert[0]) to_wide(g.cert, g.wcert, MAX_PATH);
  /* a private writable copy of the fixture known_hosts, per test process */
  GetTempPathW(MAX_PATH, dir);
  _snwprintf_s(g.wkh, SD_COUNTOF(g.wkh), _TRUNCATE, L"%sshelldrive-matrix-%lu-known-hosts", dir,
               (unsigned long)GetCurrentProcessId());
  to_wide(g.kh_src, wsrc, MAX_PATH);
  if (!CopyFileW(wsrc, g.wkh, FALSE)) return 0;
  st.kind = SD_KH_STORE_USER;
  st.path = g.wkh;
  st.writable = 1;
  if (sd_known_hosts_open(&st, 1, &g_kh) != SD_OK) return 0;
  return 1;
}

/* ---- TOTP (RFC 6238, SHA-1, 30 s, 6 digits) over the fixture secret ---- */

static int base32_decode(const char *s, uint8_t *out, size_t cap)
{
  size_t n = 0;
  uint32_t bits = 0, nbits = 0;
  for (; *s; s++) {
    int v;
    if (*s == '=' || *s == ' ') continue;
    if (*s >= 'A' && *s <= 'Z') v = *s - 'A';
    else if (*s >= 'a' && *s <= 'z') v = *s - 'a';
    else if (*s >= '2' && *s <= '7') v = *s - '2' + 26;
    else return 0;
    bits = (bits << 5) | (uint32_t)v;
    nbits += 5;
    if (nbits >= 8 && n < cap) {
      nbits -= 8;
      out[n++] = (uint8_t)(bits >> nbits);
    }
  }
  return (int)n;
}

static void totp_now(char out[8], int offset_steps)
{
  uint8_t key[80], mac[20], ctr[8], off;
  sd_hmac_ctx hc;
  size_t klen = (size_t)base32_decode(g.otp_secret, key, sizeof(key));
  uint64_t t = (uint64_t)time(NULL) / 30u + (uint64_t)offset_steps;
  uint32_t code;
  int i;
  for (i = 7; i >= 0; i--) { ctr[i] = (uint8_t)(t & 0xFF); t >>= 8; }
  sd_hmac_init(&hc, SD_HASH_SHA1, key, klen);
  sd_hmac_update(&hc, ctr, 8);
  sd_hmac_final(&hc, mac);
  sd_secure_zero(key, sizeof(key));
  off = mac[19] & 0x0F;
  code = ((uint32_t)(mac[off] & 0x7F) << 24) | ((uint32_t)mac[off + 1] << 16) |
         ((uint32_t)mac[off + 2] << 8) | mac[off + 3];
  _snprintf_s(out, 8, _TRUNCATE, "%06u", code % 1000000u);
}

/* ---- run harness ---- */

#define MX_MAX_HOPS 8

typedef struct mrun {
  sd_event done_ev, ch_ev;
  sd_err done_err;
  uint32_t failed_hop;
  sd_hostkey_decision hk_decision;
  int hk_prompts, kbd_prompts, pass_prompts, mismatch_events, announced;
  int legacy_ack_prompts, proxy_pw_prompts;
  char neg_kex[MX_MAX_HOPS][48], neg_hk[MX_MAX_HOPS][48], neg_cipher[MX_MAX_HOPS][48];
  int strict[MX_MAX_HOPS], legacy_mask[MX_MAX_HOPS], neg_count, target_neg;
  /* the proven add keys of the last SD_HKEV_ANNOUNCED (blobs copied; pointers die with the event) */
  uint8_t add_blob[8][1024];
  size_t add_len[8];
  char add_type[8][48], add_fp[8][64], hk_lookup[128];
  uint32_t add_count;
  /* channel */
  sd_ssh_channel *ch;
  sd_err open_err;
  int opened, closed, eof;
  uint8_t data[4096];
  size_t data_len;
  uint64_t total;
} mrun;

static void m_on_prompt(void *ctx, sd_prompt *p, const sd_auth_prompt_info *a, const sd_hostkey_prompt_info *h)
{
  mrun *r = (mrun *)ctx;
  if (h) {
    r->hk_prompts++;
    sd_prompt_answer_hostkey(p, r->hk_decision);
    return;
  }
  if (!a) { sd_prompt_cancel(p); return; }
  switch (a->kind) {
  case SD_PROMPT_KBDINT: {
    char code[8];
    const char *resp[1];
    totp_now(code, (int)a->round);      /* a later round: the code of the next 30 s step */
    resp[0] = code;
    r->kbd_prompts++;
    sd_prompt_answer(p, 1, resp);
    break;
  }
  case SD_PROMPT_KEY_PASSPHRASE: {
    const char *resp[1] = { g.pass[0] ? g.pass : "wrong" };
    r->pass_prompts++;
    sd_prompt_answer(p, 1, resp);
    break;
  }
  case SD_PROMPT_PROXY_PASSWORD: {
    const char *resp[1] = { g.proxy_pass[0] ? g.proxy_pass : "" };
    r->proxy_pw_prompts++;
    sd_prompt_answer(p, 1, resp);
    break;
  }
  case SD_PROMPT_LEGACY_ACK:
    r->legacy_ack_prompts++;
    sd_prompt_answer_ack(p, 1);
    break;
  default:
    sd_prompt_cancel(p);
  }
}

static void m_on_log(void *ctx, int level, const char *msg)
{
  SD_UNUSED(ctx); SD_UNUSED(level);
  if (GetEnvironmentVariableA("SD_IT_DBG", NULL, 0)) printf("  ssh: %s\n", msg);
}

static void m_on_negotiated(void *ctx, const sd_ssh_negotiated *n)
{
  mrun *r = (mrun *)ctx;
  if (n->hop_index >= MX_MAX_HOPS) return;
  _snprintf_s(r->neg_kex[n->hop_index], 48, _TRUNCATE, "%s", n->kex);
  _snprintf_s(r->neg_hk[n->hop_index], 48, _TRUNCATE, "%s", n->hostkey);
  _snprintf_s(r->neg_cipher[n->hop_index], 48, _TRUNCATE, "%s", n->cipher_c2s);
  r->strict[n->hop_index] = n->strict_kex;
  r->legacy_mask[n->hop_index] = (int)n->legacy_mask;
  if ((int)(n->hop_index + 1) > r->neg_count) r->neg_count = (int)(n->hop_index + 1);
  r->target_neg = (int)n->hop_index;    /* the last reported hop is the target */
}

static void m_on_hk_event(void *ctx, const sd_hostkey_event *e)
{
  mrun *r = (mrun *)ctx;
  uint32_t i;
  if (e->kind == SD_HKEV_MISMATCH) r->mismatch_events++;
  if (e->kind == SD_HKEV_ANNOUNCED) {
    r->announced++;
    _snprintf_s(r->hk_lookup, sizeof(r->hk_lookup), _TRUNCATE, "%s", e->lookup_name ? e->lookup_name : "");
    r->add_count = e->add_count < 8 ? e->add_count : 8;
    for (i = 0; i < r->add_count; i++) {
      const sd_hk_key *k = &e->add[i];
      size_t n = k->len < sizeof(r->add_blob[i]) ? k->len : sizeof(r->add_blob[i]);
      memcpy(r->add_blob[i], k->blob, n);
      r->add_len[i] = n;
      _snprintf_s(r->add_type[i], sizeof(r->add_type[i]), _TRUNCATE, "%s", k->type);
      _snprintf_s(r->add_fp[i], sizeof(r->add_fp[i]), _TRUNCATE, "%s", k->fp_sha256);
    }
  }
}

static void m_on_done(void *ctx, sd_err e, uint32_t hop)
{
  mrun *r = (mrun *)ctx;
  r->done_err = e;
  r->failed_hop = hop;
  sd_event_set(&r->done_ev);
}

typedef struct mopts {
  const char *disabled;
  uint32_t methods;
  int identities_only;
  sd_hostkey_decision hk_decision;
  const char *key_override;    /* UTF-8 path: SD_IT_KEY replacement (auth tests) */
  const char *cert_override;   /* UTF-8 path: SD_IT_CERT replacement */
} mopts;

static void fill_hop(sd_ssh_hop *h, const wchar_t *host, uint16_t port, const mopts *o)
{
  h->host = host;
  h->port = port;
  h->auth.user = g.user;
  h->auth.methods = o->methods ? o->methods : (SD_AUTH_PUBLICKEY | (g.otp ? SD_AUTH_KBDINT : 0));
  h->auth.identities_only = o->identities_only;
  h->update_host_keys = SD_HKU_ASK;
}

/* Builds the full row recipe and connects once. Returns SD_OK with *out connected. */
static sd_err mx_connect(mrun *r, const mopts *o, sd_ssh_conn **out)
{
  sd_ssh_config cfg;
  sd_ssh_hop hops[MX_MAX_HOPS];
  sd_ssh_callbacks cb;
  sd_ssh_identity id;
  sd_err e;
  uint32_t nhops, i, jn = 0;
  wchar_t *jump_hosts[MX_MAX_HOPS];
  sd_ssh_conn *c = NULL;

  *out = NULL;
  memset(&cfg, 0, sizeof(cfg));
  memset(&cb, 0, sizeof(cb));
  memset(&id, 0, sizeof(id));
  memset(r, 0, sizeof(*r));
  for (i = 0; i < MX_MAX_HOPS; i++) {
    memset(&hops[i], 0, sizeof(hops[i]));
    jump_hosts[i] = NULL;
  }

  if (g.jump[0]) {
    char jump[256], *ctx2 = NULL, *part;
    set_str(jump, sizeof(jump), g.jump);
    for (part = strtok_s(jump, ",", &ctx2); part; part = strtok_s(NULL, ",", &ctx2)) {
      char *colon = strrchr(part, ':');
      size_t wl;
      if (jn + 1 >= MX_MAX_HOPS) return SD_E_INVALID_PARAM;
      if (colon) *colon = 0;
      { char *at = strchr(part, '@'); if (at) memmove(part, at + 1, strlen(at + 1) + 1); }
      wl = strlen(part);
      jump_hosts[jn] = (wchar_t *)sd_alloc((wl + 1) * sizeof(wchar_t));
      if (!jump_hosts[jn]) return SD_E_NO_MEMORY;
      to_wide(part, jump_hosts[jn], (int)wl + 1);
      fill_hop(&hops[jn], jump_hosts[jn], colon ? (uint16_t)atoi(colon + 1) : 22, o);
      /* jump hops may ask kbdint (the OTP bastion of the demo row) */
      hops[jn].auth.methods = SD_AUTH_PUBLICKEY | SD_AUTH_KBDINT;
      jn++;
    }
  }
  fill_hop(&hops[jn], g.whost, g.port, o);
  nhops = jn + 1;

  id.kind = SD_ID_FILE;
  id.path = g.wkey;
  if (o->key_override) {
    static wchar_t wov[MAX_PATH];
    to_wide(o->key_override, wov, MAX_PATH);
    id.path = wov;
  }
  if (o->cert_override) {
    static wchar_t wcov[MAX_PATH];
    to_wide(o->cert_override, wcov, MAX_PATH);
    id.cert_path = wcov;
  } else if (g.cert[0]) id.cert_path = g.wcert;
  for (i = 0; i < nhops; i++) {
    hops[i].auth.identities = &id;
    hops[i].auth.identity_count = 1;
  }

  if (g.proxy[0]) {
    char url[256], *scheme_end, *hostpart, *cred_at, *colon;
    wchar_t *wpx = NULL;
    int is_http;
    set_str(url, sizeof(url), g.proxy);
    scheme_end = strstr(url, "://");
    if (!scheme_end) return SD_E_INVALID_PARAM;
    is_http = scheme_end - url == 4 && memcmp(url, "http", 4) == 0;
    if (!is_http && !(scheme_end - url == 6 && memcmp(url, "socks5", 6) == 0)) return SD_E_INVALID_PARAM;
    *scheme_end = 0;
    hostpart = scheme_end + 3;
    cred_at = strchr(hostpart, '@');     /* credentials come from SD_IT_PROXY_USER/PASS */
    if (cred_at) *cred_at = 0;
    if (cred_at) hostpart = cred_at + 1;
    colon = strrchr(hostpart, ':');
    if (colon) *colon = 0;
    wpx = (wchar_t *)sd_alloc((strlen(hostpart) + 1) * sizeof(wchar_t));
    if (!wpx) return SD_E_NO_MEMORY;
    to_wide(hostpart, wpx, (int)strlen(hostpart) + 1);
    hops[0].proxy.kind = is_http ? SD_PROXY_HTTP : SD_PROXY_SOCKS5;
    hops[0].proxy.host = wpx;
    hops[0].proxy.port = colon ? (uint16_t)atoi(colon + 1) : 0;
    if (g.proxy_user[0]) {
      hops[0].proxy.user = g.proxy_user;
      hops[0].proxy.auth = is_http ? SD_PROXY_AUTH_BASIC : SD_PROXY_AUTH_USERPASS;
    }
    hops[0].proxy.remote_dns = 0;        /* row endpoints are literals */
    jump_hosts[MX_MAX_HOPS - 1] = wpx;  /* freed with the jump hosts */
  }

  cfg.struct_size = sizeof(cfg);
  cfg.hops = hops;
  cfg.hop_count = nhops;
  cfg.known_hosts = g_kh;               /* borrowed: lives as long as the process */
  cfg.algos.disabled = o->disabled;
  cfg.connect_timeout_ms = 15000;
  cb.ctx = r;
  cb.on_prompt = m_on_prompt;
  cb.on_negotiated = m_on_negotiated;
  cb.on_hostkey_event = m_on_hk_event;
  cb.on_log = m_on_log;
  r->hk_decision = o->hk_decision;
  if (sd_event_init(&r->done_ev, 0, 0) != SD_OK || sd_event_init(&r->ch_ev, 0, 0) != SD_OK)
    e = SD_E_INTERNAL;
  else
    e = sd_ssh_conn_create(&cfg, &cb, &c);
  if (e == SD_OK) {
    if (sd_ssh_conn_connect(c, m_on_done, r) != SD_OK || sd_event_wait(&r->done_ev, 60000) != SD_OK)
      r->done_err = SD_E_TIMEOUT;
    if (r->done_err != SD_OK) e = r->done_err;
  }
  for (i = 0; i < MX_MAX_HOPS; i++) sd_free(jump_hosts[i]);
  if (e != SD_OK) {
    if (c) sd_ssh_conn_destroy(c);
    sd_event_destroy(&r->done_ev);      /* handles are zero-initialised */
    sd_event_destroy(&r->ch_ev);
    return e;
  }
  *out = c;
  return SD_OK;
}

static void mx_finish(mrun *r, sd_ssh_conn *c)
{
  if (c) {
    sd_ssh_conn_disconnect(c, m_on_done, r);
    sd_event_wait(&r->done_ev, 10000);
    sd_ssh_conn_destroy(c);
  }
  sd_event_destroy(&r->done_ev);
  sd_event_destroy(&r->ch_ev);
}

/* ---- channel helpers ---- */

static void m_ch_open(void *ctx, sd_err e)
{
  mrun *r = (mrun *)ctx;
  r->open_err = e;
  r->opened = 1;
  sd_event_set(&r->ch_ev);
}

static void m_ch_data(void *ctx, const uint8_t *p, size_t n)
{
  mrun *r = (mrun *)ctx;
  r->total += n;
  if (r->data_len + n < sizeof(r->data)) {
    memcpy(r->data + r->data_len, p, n);
    r->data_len += n;
  }
  sd_ssh_channel_consumed(r->ch, n);
  sd_event_set(&r->ch_ev);
}

static void m_ch_eof(void *ctx) { ((mrun *)ctx)->eof = 1; }
static void m_ch_writable(void *ctx) { SD_UNUSED(ctx); }

static void m_ch_closed(void *ctx, sd_err why)
{
  mrun *r = (mrun *)ctx;
  SD_UNUSED(why);
  r->closed = 1;
  sd_event_set(&r->ch_ev);
}

static const sd_ssh_channel_sink k_msink = { m_ch_open, m_ch_data, m_ch_writable, m_ch_eof, m_ch_closed };

static int m_wait(mrun *r, int *flag, uint32_t ms)
{
  uint64_t end = sd_tick_ms() + ms;
  while (!*flag) {
    uint64_t now = sd_tick_ms();
    if (now >= end) return 0;
    sd_event_wait(&r->ch_ev, (uint32_t)(end - now));
  }
  return 1;
}

static void exec_echo(sd_test_ctx *sd_t_, sd_ssh_conn *c, mrun *r)
{
  r->opened = r->closed = r->eof = 0;
  r->data_len = 0;
  r->total = 0;
  SD_CHECK_EQ_INT(sd_ssh_channel_open_exec(c, "echo sd-matrix-ok", &k_msink, r, &r->ch), SD_OK);
  SD_REQUIRE(m_wait(r, &r->opened, 15000));
  SD_CHECK_EQ_INT(r->open_err, SD_OK);
  SD_REQUIRE(m_wait(r, &r->closed, 30000));
  SD_CHECK(r->eof);
  SD_CHECK(r->data_len >= 12 && r->data_len <= 14 && memcmp(r->data, "sd-matrix-ok", 12) == 0);
}

/* ---- tests ---- */

/* The generic row recipe: connect with every SD_IT_* variable set for the row, run one exec,
   assert the negotiated algorithms and a silent host-key path. */
SD_TEST(matrix_connect_exec)
{
  mrun r;
  sd_ssh_conn *c = NULL;
  mopts o;
  memset(&o, 0, sizeof(o));
  o.hk_decision = SD_HK_ACCEPT_ONCE;    /* the fixture known_hosts decides; TOFU is recorded */
  {
    sd_err e = mx_connect(&r, &o, &c);
    if (e != SD_OK) {
      printf("  connect failed: %s (row %s)\n", sd_err_name(e), g.server);
      SD_CHECK(!"row recipe connect failed");
      return;
    }
  }
  if (g.expect_kex[0]) SD_CHECK_STR(r.neg_kex[r.target_neg], g.expect_kex);
  if (g.expect_legacy) SD_CHECK(r.legacy_mask[r.target_neg] != 0);
  else SD_CHECK(r.legacy_mask[r.target_neg] == 0);
  if (!g.expect_legacy) SD_CHECK(r.strict[r.target_neg] == 1);
  if (g.otp) SD_CHECK(r.kbd_prompts >= 1);
  exec_echo(sd_t_, c, &r);
  SD_CHECK(r.mismatch_events == 0);
  SD_CHECK(r.hk_prompts == 0);          /* the fixture known_hosts covers every hop */
  mx_finish(&r, c);
}

/* Walks the negotiated algorithms of the row's server with `disabled` lists: every KEX the
   fixture offers that the client supports, and its host-key algorithms. */
SD_TEST(matrix_kex_walk)
{
  struct step { const char *disabled, *kex, *hk; };
  const struct step *steps;
  size_t nsteps, i;
  char row[32];
  set_str(row, sizeof(row), g.server);

  if (!strcmp(row, "ossh10")) {
    static const struct step s[] = {
      { NULL, "mlkem768x25519-sha256", "ssh-ed25519" },
      { "mlkem768x25519-sha256", "curve25519-sha256", "ssh-ed25519" },
      { "ssh-ed25519", "mlkem768x25519-sha256", "ecdsa-sha2-nistp256" },
      { "ssh-ed25519,ecdsa-sha2-nistp256", "mlkem768x25519-sha256", "rsa-sha2-512" },
    };
    steps = s;
    nsteps = SD_COUNTOF(s);
  } else if (!strcmp(row, "ossh10pq")) {
    static const struct step s[] = {
      { NULL, "mlkem768x25519-sha256", "ssh-ed25519" },
      { "ssh-ed25519", "mlkem768x25519-sha256", "ecdsa-sha2-nistp256" },
    };
    steps = s;
    nsteps = SD_COUNTOF(s);
  } else if (!strcmp(row, "legacy")) {
    static const struct step s[] = {
      { NULL, "diffie-hellman-group-exchange-sha256", "ssh-rsa" },
      { "diffie-hellman-group-exchange-sha256", "diffie-hellman-group14-sha1", "ssh-rsa" },
      { "diffie-hellman-group-exchange-sha256,diffie-hellman-group14-sha1",
        "diffie-hellman-group-exchange-sha1", "ssh-rsa" },
      { "diffie-hellman-group-exchange-sha256,diffie-hellman-group14-sha1,diffie-hellman-group-exchange-sha1",
        "diffie-hellman-group1-sha1", "ssh-rsa" },
    };
    steps = s;
    nsteps = SD_COUNTOF(s);
  } else if (!strcmp(row, "legacy3des")) {
    static const struct step s[] = {
      { NULL, "diffie-hellman-group14-sha1", "ssh-rsa" },
    };
    steps = s;
    nsteps = SD_COUNTOF(s);
  } else if (!strcmp(row, "cert")) {
    static const struct step s[] = {
      { NULL, "curve25519-sha256", "ssh-ed25519-cert-v01@openssh.com" },
    };
    steps = s;
    nsteps = SD_COUNTOF(s);
  } else if (!strcmp(row, "modern")) {
    static const struct step s[] = {
      { NULL, "curve25519-sha256", "ssh-ed25519" },
    };
    steps = s;
    nsteps = SD_COUNTOF(s);
  } else {
    printf("  [skip] matrix_kex_walk: no walk table for row %s\n", row);
    return;
  }

  for (i = 0; i < nsteps; i++) {
    mrun r;
    sd_ssh_conn *c = NULL;
    mopts o;
    memset(&o, 0, sizeof(o));
    o.disabled = steps[i].disabled;
    o.hk_decision = SD_HK_ACCEPT_ONCE;
    if (mx_connect(&r, &o, &c) != SD_OK) {
      printf("  walk step %u (%s) failed to connect\n", (unsigned)i,
             steps[i].disabled ? steps[i].disabled : "default");
      SD_CHECK(!"walk connect failed");
      continue;
    }
    if (steps[i].kex) SD_CHECK_STR(r.neg_kex[r.target_neg], steps[i].kex);
    if (steps[i].hk) SD_CHECK_STR(r.neg_hk[r.target_neg], steps[i].hk);
    if (!strcmp(row, "legacy3des")) SD_CHECK_STR(r.neg_cipher[r.target_neg], "3des-cbc");
    if (!strcmp(row, "legacy") || !strcmp(row, "legacy3des"))
      SD_CHECK(r.legacy_mask[r.target_neg] != 0);
    else SD_CHECK(r.legacy_mask[r.target_neg] == 0);
    mx_finish(&r, c);
  }
}

/* The PQ-only server: without ML-KEM in the offer there is no KEX at all. */
SD_TEST(matrix_pq_required)
{
  mrun r;
  sd_ssh_conn *c = NULL;
  mopts o;
  memset(&o, 0, sizeof(o));
  o.disabled = "mlkem768x25519-sha256";
  o.hk_decision = SD_HK_ACCEPT_ONCE;
  SD_CHECK_EQ_INT(mx_connect(&r, &o, &c), SD_E_KEX_FAILED);
  SD_CHECK(c == NULL);
}

/* Drives the fixture script (rotation) through wsl.exe; returns the exit code, -1 on spawn error. */
static int run_fixture(const char *args)
{
  char cmd[1024];
  wchar_t wcmd[1024];
  STARTUPINFOW si;
  PROCESS_INFORMATION pi;
  DWORD rc;
  _snprintf_s(cmd, sizeof(cmd), _TRUNCATE, "wsl.exe -e sh %s %s", g.fixture_sh, args);
  to_wide(cmd, wcmd, SD_COUNTOF(wcmd));
  memset(&si, 0, sizeof(si));
  si.cb = sizeof(si);
  memset(&pi, 0, sizeof(pi));
  if (!CreateProcessW(NULL, wcmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) return -1;
  WaitForSingleObject(pi.hProcess, 60000);
  GetExitCodeProcess(pi.hProcess, &rc);
  CloseHandle(pi.hProcess);
  CloseHandle(pi.hThread);
  return (int)rc;
}

/* UpdateHostKeys on the rotate fixture (D16): with A known, mode `ab` announces B; after the
   announcement is applied to the store, switching the server to B only must still connect (the
   learned key matches). */
SD_TEST(matrix_hostkeys_update)
{
  mrun r;
  sd_ssh_conn *c = NULL;
  mopts o;
  sd_hk_key add[8];
  uint32_t i;
  memset(&o, 0, sizeof(o));
  o.hk_decision = SD_HK_ACCEPT_ONCE;
  if (!g.fixture_sh[0]) { printf("  [skip] matrix_hostkeys_update: no fixture.sh\n"); return; }
  if (run_fixture("rotate ab") != 0) { SD_CHECK(!"rotate ab failed"); return; }

  if (mx_connect(&r, &o, &c) != SD_OK) { SD_CHECK(!"connect on rotate failed"); return; }
  exec_echo(sd_t_, c, &r);
  SD_CHECK(r.announced >= 1);           /* hostkeys-00: the B key proven and announced */
  SD_CHECK(r.add_count >= 1);
  mx_finish(&r, c);

  /* apply the announcement to the store the connections use */
  SD_REQUIRE(r.hk_lookup[0]);
  for (i = 0; i < r.add_count; i++) {
    add[i].blob = r.add_blob[i];
    add[i].len = r.add_len[i];
    add[i].type = r.add_type[i];
    add[i].fp_sha256 = r.add_fp[i];
  }
  SD_CHECK_EQ_INT(sd_known_hosts_apply_hostkeys(g_kh, SD_KH_STORE_USER, r.hk_lookup,
                                                r.add_count ? add : NULL, r.add_count, NULL, 0), SD_OK);

  /* B only: the applied key must authenticate; leaving mode `ab` would also pass, `b` proves it */
  if (run_fixture("rotate b") != 0) {
    SD_CHECK(!"rotate b failed");
    run_fixture("rotate ab");
    return;
  }
  c = NULL;
  if (mx_connect(&r, &o, &c) != SD_OK) {
    SD_CHECK(!"connect on rotated key failed");
  } else {
    exec_echo(sd_t_, c, &r);
    SD_CHECK(r.hk_prompts == 0);
    mx_finish(&r, c);
  }
  run_fixture("rotate ab");   /* leave the fixture as this test found it */
}

/* Every private-key format the fixtures provide authenticates against the row's server: OpenSSH
   v1 (plain and encrypted), PPK v3/v2 unencrypted, and the puttygen-written encrypted PPKs
   (v3 Argon2id, v2 AES) with the fixture passphrase. */
SD_TEST(matrix_auth_key_formats)
{
  static const struct { const char *env; int enc; } cases[] = {
    { "SD_IT_KEY_ED25519", 0 },
    { "SD_IT_KEY_ECDSA", 0 },
    { "SD_IT_KEY_RSA", 0 },
    { "SD_IT_KEY_ED25519_ENC", 1 },
    { "SD_IT_KEY_ED25519_PPK3", 0 },
    { "SD_IT_KEY_RSA_PPK3", 0 },
    { "SD_IT_KEY_ECDSA_PPK3", 0 },
    { "SD_IT_KEY_ED25519_PPK2", 0 },
    { "SD_IT_KEY_ED25519_PPK3_ARGON2ID", 1 },
    { "SD_IT_KEY_RSA_PPK2_AES", 1 },
  };
  size_t i;
  for (i = 0; i < SD_COUNTOF(cases); i++) {
    char path[MAX_PATH];
    mrun r;
    sd_ssh_conn *c = NULL;
    mopts o;
    if (!env_or_file(cases[i].env, path, sizeof(path))) {
      printf("  [skip] %s not set (puttygen fixtures absent)\n", cases[i].env);
      continue;
    }
    memset(&o, 0, sizeof(o));
    o.hk_decision = SD_HK_ACCEPT_ONCE;
    o.key_override = path;
    if (mx_connect(&r, &o, &c) != SD_OK) {
      printf("  %s: connect failed\n", cases[i].env);
      SD_CHECK(!"key format connect failed");
      continue;
    }
    if (cases[i].enc) SD_CHECK(r.pass_prompts >= 1);
    else SD_CHECK_EQ_INT(r.pass_prompts, 0);
    SD_CHECK_EQ_INT(r.kbd_prompts, 0);
    exec_echo(sd_t_, c, &r);
    mx_finish(&r, c);
  }
}

/* User certificates on the cert instance (TrustedUserCAKeys, no authorized_keys): every valid
   cert type authenticates; expired, wrong-principal and revoked (KRL) ones fail. */
SD_TEST(matrix_auth_certs)
{
  static const struct { const char *key_env, *cert_env; int ok; } cases[] = {
    { "SD_IT_KEY_ED25519", "SD_IT_CERT_ED25519", 1 },
    { "SD_IT_KEY_RSA", "SD_IT_CERT_RSA", 1 },
    { "SD_IT_KEY_ECDSA", "SD_IT_CERT_ECDSA", 1 },
    { "SD_IT_CERT_EXPIRED_KEY", "SD_IT_CERT_EXPIRED", 0 },
    { "SD_IT_CERT_WRONGPRINC_KEY", "SD_IT_CERT_WRONGPRINC", 0 },
    { "SD_IT_CERT_REVOKED_KEY", "SD_IT_CERT_REVOKED", 0 },
  };
  size_t i;
  for (i = 0; i < SD_COUNTOF(cases); i++) {
    char key[MAX_PATH], cert[MAX_PATH];
    mrun r;
    sd_ssh_conn *c = NULL;
    mopts o;
    sd_err e;
    if (!env_or_file(cases[i].key_env, key, sizeof(key)) ||
        !env_or_file(cases[i].cert_env, cert, sizeof(cert))) {
      printf("  [skip] %s not set\n", cases[i].cert_env);
      continue;
    }
    memset(&o, 0, sizeof(o));
    o.hk_decision = SD_HK_ACCEPT_ONCE;
    o.key_override = key;
    o.cert_override = cert;
    e = mx_connect(&r, &o, &c);
    if (cases[i].ok) {
      if (e != SD_OK) {
        printf("  %s: connect failed (%s)\n", cases[i].cert_env, sd_err_name(e));
        SD_CHECK(!"valid certificate rejected");
        continue;
      }
      exec_echo(sd_t_, c, &r);
      SD_CHECK_EQ_INT(r.hk_prompts, 0);
      mx_finish(&r, c);
    } else {
      if (e == SD_OK) {
        SD_CHECK(!"invalid certificate accepted");
        mx_finish(&r, c);
        continue;
      }
      SD_CHECK_EQ_INT(e, SD_E_AUTH_FAILED);
    }
  }
}

/* ---- main ---- */

static const sd_test_case k_tests[] = {
  SD_TEST_ENTRY(matrix_connect_exec),
  SD_TEST_ENTRY(matrix_kex_walk),
  SD_TEST_ENTRY(matrix_pq_required),
  SD_TEST_ENTRY(matrix_hostkeys_update),
  SD_TEST_ENTRY(matrix_auth_key_formats),
  SD_TEST_ENTRY(matrix_auth_certs),
};

int main(int argc, char **argv)
{
  int rc;
  if (!tu_crypto_or_skip("matrix interop")) return 77;
  if (!mx_load()) {
    printf("  [skip] matrix interop: not running under run-matrix.ps1 (SD_IT_* unset)\n");
    return 77;
  }
  rc = sd_test_main(k_tests, SD_COUNTOF(k_tests), argc, argv);
  sd_known_hosts_close(g_kh);
  return rc;
}
