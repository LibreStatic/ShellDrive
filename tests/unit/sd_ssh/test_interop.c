/* Interop tests against the WSL OpenSSH fixture (tests/fixtures/wsl-sshd). Exit code 77 (CTest
 * "skipped") when the fixture is not running or sd_crypto is incomplete.
 *
 * Covers: TCP connect, version exchange, curve25519 KEX with strict KEX and ext-info, cipher
 * selection (chacha20-poly1305, AES-GCM, AES-CTR + EtM / non-EtM HMAC), TOFU prompt then MATCH,
 * MISMATCH hard block, TM-R04 type restriction, Ed25519 key files (plain and encrypted), exec and
 * sftp subsystem channels, volume rekeying with flow control; M1: reconnect on the same
 * sd_ssh_conn (pinned host key, is_reconnect prompts, reconnect secret cache with the TM-R05 rule,
 * host key mismatch on reconnect), run-time keepalive tuning. */
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sd_base/sd_mem.h"
#include "sd_platform/sd_thread.h"
#include "sd_platform/sd_time.h"
#include "sd_ssh/sd_ssh.h"
#include "sd_test.h"
#include "conn_internal.h"
#include "test_util.h"

static char g_dir[MAX_PATH];
static char g_user[64], g_key[MAX_PATH], g_key_enc[MAX_PATH], g_pass[128];
static uint16_t g_port = 2222;
/* The fixture's direct address in WSL NAT mode ("direct_host" in state/env) bypasses the localhost relay,
   which can wedge when sshd is killed during heavy traffic; SD_SSHD_VIA_RELAY=1 forces 127.0.0.1. */
static char g_host[64] = "127.0.0.1";
static wchar_t g_whost[64] = L"127.0.0.1";
static wchar_t g_kh_path[MAX_PATH];

/* ---- fixture discovery ---- */

static void trim(char *s)
{
  size_t n = strlen(s);
  while (n && (s[n - 1] == '\r' || s[n - 1] == '\n' || s[n - 1] == ' ')) s[--n] = 0;
}

static int load_env(void)
{
  char path[MAX_PATH], line[512];
  FILE *f;
  DWORD n = GetEnvironmentVariableA("SD_SSH_WSL_FIXTURE_DIR", g_dir, sizeof(g_dir));
  if (n == 0 || n >= sizeof(g_dir)) _snprintf_s(g_dir, sizeof(g_dir), _TRUNCATE, "%s", SD_SSH_WSL_FIXTURE_DIR);
  _snprintf_s(path, sizeof(path), _TRUNCATE, "%s/state/env", g_dir);
  if (fopen_s(&f, path, "rb") != 0 || !f) return 0;
  while (fgets(line, sizeof(line), f)) {
    char *eq = strchr(line, '=');
    trim(line);
    if (!eq) continue;
    *eq = 0;
    if (strcmp(line, "user") == 0) _snprintf_s(g_user, sizeof(g_user), _TRUNCATE, "%s", eq + 1);
    else if (strcmp(line, "port") == 0) g_port = (uint16_t)atoi(eq + 1);
    else if (strcmp(line, "direct_host") == 0 && !GetEnvironmentVariableA("SD_SSHD_VIA_RELAY", NULL, 0) &&
             strlen(eq + 1) < sizeof(g_host)) {
      _snprintf_s(g_host, sizeof(g_host), _TRUNCATE, "%s", eq + 1);
      MultiByteToWideChar(CP_UTF8, 0, g_host, -1, g_whost, (int)SD_COUNTOF(g_whost));
    }
    else if (strcmp(line, "key") == 0) _snprintf_s(g_key, sizeof(g_key), _TRUNCATE, "%s/state/%s", g_dir, eq + 1);
    else if (strcmp(line, "key_enc") == 0) _snprintf_s(g_key_enc, sizeof(g_key_enc), _TRUNCATE, "%s/state/%s", g_dir, eq + 1);
    else if (strcmp(line, "pass") == 0) _snprintf_s(g_pass, sizeof(g_pass), _TRUNCATE, "%s", eq + 1);
  }
  fclose(f);
  return g_user[0] && g_key[0];
}

/* Dotted-quad parser (inet_pton is Vista+, inet_addr is deprecated); host byte order. */
static uint32_t ipv4_or_loopback(const char *h)
{
  uint32_t v = 0, part = 0;
  int dots = 0, digits = 0;
  for (; *h; h++) {
    if (*h >= '0' && *h <= '9') { part = part * 10u + (uint32_t)(*h - '0'); if (++digits > 3 || part > 255) return 0x7F000001u; }
    else if (*h == '.' && digits && dots < 3) { v = (v << 8) | part; part = 0; digits = 0; dots++; }
    else return 0x7F000001u;
  }
  if (dots != 3 || !digits) return 0x7F000001u;
  return (v << 8) | part;
}

static int port_open(void)
{
  SOCKET s;
  struct sockaddr_in a;
  int ok;
  WSADATA wd;
  if (WSAStartup(MAKEWORD(2, 2), &wd) != 0) return 0;
  s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (s == INVALID_SOCKET) return 0;
  memset(&a, 0, sizeof(a));
  a.sin_family = AF_INET;
  a.sin_port = htons(g_port);
  a.sin_addr.s_addr = htonl(ipv4_or_loopback(g_host));
  ok = connect(s, (struct sockaddr *)&a, sizeof(a)) == 0;
  closesocket(s);
  return ok;
}

/* ---- connection harness ---- */

typedef struct run {
  sd_event done_ev, ch_ev;
  sd_err done_err;
  int hostkey_prompts, pass_prompts, other_prompts, mismatch_events;
  int reconnect_prompts, just_accepted_prompts;
  sd_hostkey_decision decision;
  char hk_lookup[128], hk_fp[64], neg_cipher[64], neg_mac[64], neg_kex[64];
  int strict, kex_count;
  /* channel */
  sd_ssh_channel *ch;
  sd_err open_err, close_err;
  int opened, closed, eof;
  uint8_t *data; size_t data_len, data_cap;
  uint64_t total;
  int keep_data;
} run;

static void on_prompt(void *ctx, sd_prompt *p, const sd_auth_prompt_info *a, const sd_hostkey_prompt_info *h)
{
  run *r = (run *)ctx;
  if ((a && a->is_reconnect) || (h && h->is_reconnect)) r->reconnect_prompts++;
  if (a && a->hostkey_just_accepted) r->just_accepted_prompts++;
  if (h) {
    r->hostkey_prompts++;
    _snprintf_s(r->hk_lookup, sizeof(r->hk_lookup), _TRUNCATE, "%s", h->lookup_name);
    _snprintf_s(r->hk_fp, sizeof(r->hk_fp), _TRUNCATE, "%s", h->fp_sha256);
    sd_prompt_answer_hostkey(p, r->decision);
  } else if (a && a->kind == SD_PROMPT_KEY_PASSPHRASE) {
    const char *resp[1];
    resp[0] = r->pass_prompts == 0 ? "wrong passphrase" : g_pass;   /* exercise the retry */
    r->pass_prompts++;
    sd_prompt_answer(p, 1, resp);
  } else {
    r->other_prompts++;
    sd_prompt_cancel(p);
  }
}

static void on_negotiated(void *ctx, const sd_ssh_negotiated *n)
{
  run *r = (run *)ctx;
  _snprintf_s(r->neg_cipher, sizeof(r->neg_cipher), _TRUNCATE, "%s", n->cipher_c2s);
  _snprintf_s(r->neg_mac, sizeof(r->neg_mac), _TRUNCATE, "%s", n->mac_c2s);
  _snprintf_s(r->neg_kex, sizeof(r->neg_kex), _TRUNCATE, "%s", n->kex);
  r->strict = n->strict_kex;
  r->kex_count++;
}

static void on_hk_event(void *ctx, const sd_hostkey_event *e)
{
  run *r = (run *)ctx;
  if (e->kind == SD_HKEV_MISMATCH) r->mismatch_events++;
}

static void on_done(void *ctx, sd_err e, uint32_t hop)
{
  run *r = (run *)ctx;
  SD_UNUSED(hop);
  r->done_err = e;
  sd_event_set(&r->done_ev);
}

static sd_known_hosts *open_kh(const char *initial)
{
  sd_kh_store st;
  sd_known_hosts *kh = NULL;
  DeleteFileW(g_kh_path);
  if (initial) {
    HANDLE h = CreateFileW(g_kh_path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    DWORD w;
    if (h == INVALID_HANDLE_VALUE) return NULL;
    WriteFile(h, initial, (DWORD)strlen(initial), &w, NULL);
    CloseHandle(h);
  }
  st.kind = SD_KH_STORE_USER;
  st.path = g_kh_path;
  st.writable = 1;
  return sd_known_hosts_open(&st, 1, &kh) == SD_OK ? kh : NULL;
}

typedef struct conn_opts {
  const char *key;            /* file path (UTF-8) */
  const char *disabled;
  uint64_t rekey_bytes;
  uint32_t methods;
  uint32_t keepalive_ms;
  sd_hostkey_decision decision;
  int cache_secrets;
} conn_opts;

static sd_err connect_once(sd_test_ctx *sd_t_, sd_known_hosts *kh, const conn_opts *o, run *r, sd_ssh_conn **out)
{
  sd_ssh_config cfg;
  sd_ssh_hop hop;
  sd_ssh_callbacks cb;
  sd_ssh_identity id;
  wchar_t wkey[MAX_PATH];
  sd_ssh_conn *c = NULL;
  memset(&cfg, 0, sizeof(cfg));
  memset(&hop, 0, sizeof(hop));
  memset(&cb, 0, sizeof(cb));
  memset(&id, 0, sizeof(id));
  MultiByteToWideChar(CP_UTF8, 0, o->key, -1, wkey, MAX_PATH);
  id.kind = SD_ID_FILE;
  id.path = wkey;
  hop.host = g_whost;
  hop.port = g_port;
  hop.auth.user = g_user;
  hop.auth.identities = &id;
  hop.auth.identity_count = 1;
  hop.auth.methods = o->methods ? o->methods : SD_AUTH_PUBLICKEY;
  hop.auth.identities_only = 1;
  hop.auth.cache_secrets_for_reconnect = o->cache_secrets;
  cfg.struct_size = sizeof(cfg);
  cfg.hops = &hop;
  cfg.hop_count = 1;
  cfg.known_hosts = kh;
  cfg.algos.disabled = o->disabled;
  cfg.rekey_bytes = o->rekey_bytes;
  cfg.keepalive_interval_ms = o->keepalive_ms;
  cfg.connect_timeout_ms = 10000;
  cb.ctx = r;
  cb.on_prompt = on_prompt;
  cb.on_negotiated = on_negotiated;
  cb.on_hostkey_event = on_hk_event;
  r->decision = o->decision;
  if (sd_event_init(&r->done_ev, 0, 0) != SD_OK || sd_event_init(&r->ch_ev, 0, 0) != SD_OK) return SD_E_INTERNAL;
  if (sd_ssh_conn_create(&cfg, &cb, &c) != SD_OK) return SD_E_INTERNAL;
  SD_CHECK_EQ_INT(sd_ssh_conn_connect(c, on_done, r), SD_OK);
  if (sd_event_wait(&r->done_ev, 30000) != SD_OK) r->done_err = SD_E_TIMEOUT;
  *out = c;
  return r->done_err;
}

static void finish(run *r, sd_ssh_conn *c)
{
  if (c) {
    sd_ssh_conn_disconnect(c, on_done, r);
    sd_event_wait(&r->done_ev, 5000);
    sd_ssh_conn_destroy(c);
  }
  sd_event_destroy(&r->done_ev);
  sd_event_destroy(&r->ch_ev);
  sd_free(r->data);
}

/* ---- channel sink ---- */

static void ch_open(void *ctx, sd_err e)
{
  run *r = (run *)ctx;
  r->open_err = e;
  r->opened = 1;
  if (e != SD_OK) { r->closed = 1; sd_event_set(&r->ch_ev); }
  else sd_event_set(&r->ch_ev);
}

static void ch_data(void *ctx, const uint8_t *p, size_t n)
{
  run *r = (run *)ctx;
  r->total += n;
  if (r->keep_data && r->data_len + n <= 1u << 20) {
    if (r->data_len + n > r->data_cap) {
      size_t nc = SD_MAX(r->data_cap * 2, r->data_len + n + 1024);
      uint8_t *nb = (uint8_t *)sd_realloc(r->data, nc);
      if (!nb) return;
      r->data = nb;
      r->data_cap = nc;
    }
    memcpy(r->data + r->data_len, p, n);
    r->data_len += n;
  }
  sd_ssh_channel_consumed(r->ch, n);
  sd_event_set(&r->ch_ev);
}

static void ch_eof(void *ctx) { ((run *)ctx)->eof = 1; }
static void ch_writable(void *ctx) { SD_UNUSED(ctx); }

static void ch_closed(void *ctx, sd_err why)
{
  run *r = (run *)ctx;
  r->close_err = why;
  r->closed = 1;
  sd_event_set(&r->ch_ev);
}

static const sd_ssh_channel_sink k_sink = { ch_open, ch_data, ch_writable, ch_eof, ch_closed };

static int wait_until(run *r, int *flag, uint32_t ms)
{
  uint64_t end = sd_tick_ms() + ms;
  while (!*flag) {
    uint64_t now = sd_tick_ms();
    if (now >= end) return 0;
    sd_event_wait(&r->ch_ev, (uint32_t)(end - now));
  }
  return 1;
}

static void exec_check(sd_test_ctx *sd_t_, sd_ssh_conn *c, run *r, const char *cmd, const char *expect,
                       uint64_t expect_total)
{
  r->opened = r->closed = r->eof = 0;
  r->data_len = 0;
  r->total = 0;
  r->keep_data = expect != NULL;
  SD_CHECK_EQ_INT(sd_ssh_channel_open_exec(c, cmd, &k_sink, r, &r->ch), SD_OK);
  SD_REQUIRE(wait_until(r, &r->opened, 10000));
  SD_CHECK_EQ_INT(r->open_err, SD_OK);
  SD_REQUIRE(wait_until(r, &r->closed, 60000));
  SD_CHECK(r->eof);
  if (expect) SD_CHECK(r->data_len == strlen(expect) && memcmp(r->data, expect, r->data_len) == 0);
  if (expect_total) SD_CHECK_EQ_U64(r->total, expect_total);
}

/* SFTP handshake over the "sftp" subsystem: INIT(3) -> VERSION(3). Writes happen on the I/O thread. */
typedef struct sftp_init { run *r; sd_event ev; sd_err err; size_t acc; } sftp_init;
static void post_sftp_init(void *arg)
{
  sftp_init *s = (sftp_init *)arg;
  static const uint8_t init[9] = { 0, 0, 0, 5, 1, 0, 0, 0, 3 };
  s->err = sd_ssh_channel_write(s->r->ch, init, sizeof(init), &s->acc);
  sd_event_set(&s->ev);
}

static void close_on_io(void *arg) { sd_ssh_channel_close(((run *)arg)->ch); }

/* ---- tests ---- */

SD_TEST(interop_tofu_then_match)
{
  sd_known_hosts *kh = open_kh(NULL);
  run r;
  sd_ssh_conn *c = NULL;
  conn_opts o;
  sd_ssh_auth_info ai;
  char expect_lookup[32];
  SD_REQUIRE(kh != NULL);
  memset(&o, 0, sizeof(o));
  o.key = g_key;
  o.decision = SD_HK_ACCEPT_AND_STORE;

  memset(&r, 0, sizeof(r));
  SD_CHECK_EQ_INT(connect_once(sd_t_, kh, &o, &r, &c), SD_OK);
  SD_CHECK_EQ_INT(r.hostkey_prompts, 1);
  _snprintf_s(expect_lookup, sizeof(expect_lookup), _TRUNCATE, "[%s]:%u", g_host, (unsigned)g_port);
  SD_CHECK_STR(r.hk_lookup, expect_lookup);
  SD_CHECK(strncmp(r.hk_fp, "SHA256:", 7) == 0);
  SD_CHECK_STR(r.neg_kex, "curve25519-sha256");
  SD_CHECK(r.strict);
  printf("  negotiated %s %s%s%s\n", r.neg_kex, r.neg_cipher, r.neg_mac[0] ? "/" : "", r.neg_mac);
  if (r.done_err == SD_OK) {
    SD_CHECK_EQ_INT(sd_ssh_conn_auth_info(c, &ai), SD_OK);
    SD_CHECK(ai.methods_used == SD_AUTH_PUBLICKEY);
    SD_CHECK(!ai.noninteractive);   /* the host key prompt was answered by "the user" */
    exec_check(sd_t_, c, &r, "echo shelldrive-interop", "shelldrive-interop\n", 0);

    /* sftp subsystem handshake */
    {
      sftp_init s;
      r.opened = r.closed = 0;
      r.data_len = 0;
      r.keep_data = 1;
      SD_CHECK_EQ_INT(sd_ssh_channel_open_subsystem(c, "sftp", &k_sink, &r, &r.ch), SD_OK);
      SD_REQUIRE(wait_until(&r, &r.opened, 10000));
      SD_REQUIRE(r.open_err == SD_OK);
      s.r = &r;
      s.err = SD_E_INTERNAL;
      s.acc = 0;
      SD_REQUIRE(sd_event_init(&s.ev, 0, 0) == SD_OK);
      SD_REQUIRE(sd_ssh_conn_post(c, post_sftp_init, &s) == SD_OK);
      SD_REQUIRE(sd_event_wait(&s.ev, 5000) == SD_OK);
      SD_CHECK_EQ_INT(s.err, SD_OK);
      SD_CHECK_EQ_INT(s.acc, 9);
      {
        uint64_t end = sd_tick_ms() + 10000;
        while (r.data_len < 9 && sd_tick_ms() < end) sd_event_wait(&r.ch_ev, 200);
      }
      SD_REQUIRE(r.data_len >= 9);
      SD_CHECK(r.data[4] == 2);                    /* SSH_FXP_VERSION */
      SD_CHECK(sd_load_be32(r.data + 5) == 3);     /* version 3 */
      SD_REQUIRE(sd_ssh_conn_post(c, close_on_io, &r) == SD_OK);
      SD_CHECK(wait_until(&r, &r.closed, 10000));
      sd_event_destroy(&s.ev);
    }
  }
  finish(&r, c);
  c = NULL;

  /* second connection: verified against the stored key, no prompt */
  memset(&r, 0, sizeof(r));
  SD_CHECK_EQ_INT(connect_once(sd_t_, kh, &o, &r, &c), SD_OK);
  SD_CHECK_EQ_INT(r.hostkey_prompts, 0);
  if (r.done_err == SD_OK) {
    SD_CHECK_EQ_INT(sd_ssh_conn_auth_info(c, &ai), SD_OK);
    SD_CHECK(ai.noninteractive);
  }
  finish(&r, c);
  sd_known_hosts_close(kh);
}

SD_TEST(interop_cipher_variants)
{
  static const struct { const char *disabled, *cipher, *mac; } k_v[] = {
    { "aes256-gcm@openssh.com,aes128-gcm@openssh.com", "chacha20-poly1305@openssh.com", "" },
    { "chacha20-poly1305@openssh.com,aes128-gcm@openssh.com", "aes256-gcm@openssh.com", "" },
    { "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com", "aes128-gcm@openssh.com", "" },
    { "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com", "aes256-ctr",
      "hmac-sha2-256-etm@openssh.com" },
    { "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,"
      "hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com", "aes192-ctr", "hmac-sha2-256" },
    { "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,"
      "hmac-sha2-256-etm@openssh.com,hmac-sha2-256", "aes128-ctr", "hmac-sha2-512-etm@openssh.com" }
  };
  size_t i;
  sd_known_hosts *kh = open_kh(NULL);
  SD_REQUIRE(kh != NULL);
  for (i = 0; i < SD_COUNTOF(k_v); i++) {
    run r;
    sd_ssh_conn *c = NULL;
    conn_opts o;
    memset(&o, 0, sizeof(o));
    memset(&r, 0, sizeof(r));
    o.key = g_key;
    o.disabled = k_v[i].disabled;
    o.decision = SD_HK_ACCEPT_ONCE;
    SD_CHECK_EQ_INT(connect_once(sd_t_, kh, &o, &r, &c), SD_OK);
    SD_CHECK_STR(r.neg_cipher, k_v[i].cipher);
    SD_CHECK_STR(r.neg_mac, k_v[i].mac);
    if (r.done_err == SD_OK) exec_check(sd_t_, c, &r, "echo variant", "variant\n", 0);
    finish(&r, c);
  }
  sd_known_hosts_close(kh);
}

SD_TEST(interop_encrypted_key)
{
  sd_known_hosts *kh = open_kh(NULL);
  run r;
  sd_ssh_conn *c = NULL;
  conn_opts o;
  SD_REQUIRE(kh != NULL);
  if (!g_key_enc[0]) { printf("  [skip] no encrypted fixture key\n"); sd_known_hosts_close(kh); return; }
  memset(&o, 0, sizeof(o));
  memset(&r, 0, sizeof(r));
  o.key = g_key_enc;
  o.decision = SD_HK_ACCEPT_ONCE;
  SD_CHECK_EQ_INT(connect_once(sd_t_, kh, &o, &r, &c), SD_OK);
  SD_CHECK_EQ_INT(r.pass_prompts, 2);   /* one wrong answer, then the right one */
  finish(&r, c);
  sd_known_hosts_close(kh);
}

SD_TEST(interop_mismatch_blocks)
{
  char text[512];
  uint8_t *f;
  size_t n;
  sd_known_hosts *kh;
  run r;
  sd_ssh_conn *c = NULL;
  conn_opts o;
  /* a different ed25519 key stored for the name */
  SD_REQUIRE(tu_read_fixture("other_host.pub", &f, &n));
  {
    char *sp = strchr((char *)f, ' ');
    char *sp2 = sp ? strchr(sp + 1, ' ') : NULL;
    if (sp2) *sp2 = 0;
    _snprintf_s(text, sizeof(text), _TRUNCATE, "[%s]:%u %s\n", g_host, (unsigned)g_port, (char *)f);
  }
  sd_free(f);
  kh = open_kh(text);
  SD_REQUIRE(kh != NULL);
  memset(&o, 0, sizeof(o));
  memset(&r, 0, sizeof(r));
  o.key = g_key;
  o.decision = SD_HK_ACCEPT_AND_STORE;   /* must never be asked */
  SD_CHECK_EQ_INT(connect_once(sd_t_, kh, &o, &r, &c), SD_E_HOSTKEY_MISMATCH);
  SD_CHECK_EQ_INT(r.hostkey_prompts, 0);
  SD_CHECK_EQ_INT(r.mismatch_events, 1);
  finish(&r, c);
  sd_known_hosts_close(kh);
}

SD_TEST(interop_stored_type_restriction)
{
  char text[256];
  sd_known_hosts *kh;
  run r;
  sd_ssh_conn *c = NULL;
  conn_opts o;
  /* only an RSA key known for the name: no prompt, host_key_type_unavailable (TM-R04) */
  _snprintf_s(text, sizeof(text), _TRUNCATE, "[%s]:%u ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQC7\n",
              g_host, (unsigned)g_port);
  kh = open_kh(text);
  SD_REQUIRE(kh != NULL);
  memset(&o, 0, sizeof(o));
  memset(&r, 0, sizeof(r));
  o.key = g_key;
  o.decision = SD_HK_ACCEPT_AND_STORE;
  SD_CHECK_EQ_INT(connect_once(sd_t_, kh, &o, &r, &c), SD_E_HOSTKEY_TYPE_UNAVAILABLE);
  SD_CHECK_EQ_INT(r.hostkey_prompts, 0);
  finish(&r, c);
  sd_known_hosts_close(kh);
}

SD_TEST(interop_reject_and_auth_failure)
{
  sd_known_hosts *kh = open_kh(NULL);
  run r;
  sd_ssh_conn *c = NULL;
  conn_opts o;
  SD_REQUIRE(kh != NULL);
  memset(&o, 0, sizeof(o));
  memset(&r, 0, sizeof(r));
  o.key = g_key;
  o.decision = SD_HK_REJECT;
  SD_CHECK_EQ_INT(connect_once(sd_t_, kh, &o, &r, &c), SD_E_HOSTKEY_REJECTED);
  finish(&r, c);
  c = NULL;
  /* password only, but the fixture disables passwords: no prompt, auth_failed */
  memset(&r, 0, sizeof(r));
  o.decision = SD_HK_ACCEPT_ONCE;
  o.methods = SD_AUTH_PASSWORD;
  SD_CHECK_EQ_INT(connect_once(sd_t_, kh, &o, &r, &c), SD_E_AUTH_FAILED);
  SD_CHECK_EQ_INT(r.other_prompts, 0);
  finish(&r, c);
  sd_known_hosts_close(kh);
}

SD_TEST(interop_rekey_bulk)
{
  sd_known_hosts *kh = open_kh(NULL);
  run r;
  sd_ssh_conn *c = NULL;
  conn_opts o;
  SD_REQUIRE(kh != NULL);
  memset(&o, 0, sizeof(o));
  memset(&r, 0, sizeof(r));
  o.key = g_key;
  o.decision = SD_HK_ACCEPT_ONCE;
  o.rekey_bytes = 256 * 1024;   /* many client-initiated rekeys during the transfer */
  SD_CHECK_EQ_INT(connect_once(sd_t_, kh, &o, &r, &c), SD_OK);
  if (r.done_err == SD_OK) {
    /* The bound is in bytes, not in round numbers: once rx crosses rekey_bytes we send KEXINIT, but
       the server may still deliver up to one channel window (SSH_CH_WINDOW) of data under the old
       keys before it sees it. So every key epoch carries at most rekey_bytes + one window (+ slack
       for framing), whatever the speed of the build (a slow unoptimized x86 KEX lets more of the
       window arrive per epoch: 8-9 rekeys for 12 MB on x86-ia32-debug, 16 on x64). 32 MB keeps the
       guaranteed count above 10. */
    const uint64_t total = 32000000;
    const uint64_t per_epoch = 256 * 1024 + SSH_CH_WINDOW + 64 * 1024;
    exec_check(sd_t_, c, &r, "head -c 32000000 /dev/zero", NULL, total);
    exec_check(sd_t_, c, &r, "echo after-rekey", "after-rekey\n", 0);
    printf("  %d key exchanges (at least %d required)\n", r.kex_count, 1 + (int)(total / per_epoch));
    SD_CHECK((uint64_t)(r.kex_count - 1) >= total / per_epoch);   /* volume rekeys honour the limit */
    SD_CHECK(r.kex_count > 10);
  }
  finish(&r, c);
  c = NULL;
  /* default client limit (1 GiB): the fixture's RekeyLimit 4M makes the server initiate them */
  memset(&r, 0, sizeof(r));
  o.rekey_bytes = 0;
  SD_CHECK_EQ_INT(connect_once(sd_t_, kh, &o, &r, &c), SD_OK);
  if (r.done_err == SD_OK) {
    exec_check(sd_t_, c, &r, "head -c 12000000 /dev/zero", NULL, 12000000);
    exec_check(sd_t_, c, &r, "echo after-server-rekey", "after-server-rekey\n", 0);
    printf("  %d key exchanges (server-initiated)\n", r.kex_count);
    SD_CHECK(r.kex_count >= 3);
  }
  finish(&r, c);
  sd_known_hosts_close(kh);
}

typedef struct rtt_q { sd_ssh_conn *c; sd_event ev; uint32_t srtt, var; int have; } rtt_q;
static void post_rtt(void *arg) { rtt_q *q = (rtt_q *)arg; sd_ssh_conn_rtt(q->c, &q->srtt, &q->var); q->have = q->c->have_rtt; sd_event_set(&q->ev); }
static void post_probe(void *arg) { sd_ssh_conn_probe((sd_ssh_conn *)arg); }

SD_TEST(interop_keepalive_and_probe)
{
  sd_known_hosts *kh = open_kh(NULL);
  run r;
  sd_ssh_conn *c = NULL;
  conn_opts o;
  rtt_q q;
  SD_REQUIRE(kh != NULL);
  memset(&o, 0, sizeof(o));
  memset(&r, 0, sizeof(r));
  o.key = g_key;
  o.decision = SD_HK_ACCEPT_ONCE;
  o.keepalive_ms = 300;
  SD_CHECK_EQ_INT(connect_once(sd_t_, kh, &o, &r, &c), SD_OK);
  if (r.done_err == SD_OK) {
    Sleep(1500);                                   /* idle: keepalive@openssh.com round trips */
    memset(&q, 0, sizeof(q));
    q.c = c;
    SD_REQUIRE(sd_event_init(&q.ev, 0, 0) == SD_OK);
    q.srtt = 0xFFFFFFFFu;
    SD_REQUIRE(sd_ssh_conn_post(c, post_rtt, &q) == SD_OK);
    SD_REQUIRE(sd_event_wait(&q.ev, 5000) == SD_OK);
    printf("  srtt %u ms, rttvar %u ms\n", q.srtt, q.var);
    SD_CHECK(q.have);   /* at least one keepalive round trip was measured */
    SD_CHECK(q.srtt < 1000);
    SD_REQUIRE(sd_ssh_conn_post(c, post_probe, c) == SD_OK);   /* liveness probe on a healthy link */
    Sleep(1200);
    exec_check(sd_t_, c, &r, "echo alive", "alive\n", 0);
    sd_event_destroy(&q.ev);
  }
  finish(&r, c);
  sd_known_hosts_close(kh);
}

/* ---- M1: reconnect on the same connection object (01 §8) ---- */

static sd_err reconnect(run *r, sd_ssh_conn *c)
{
  sd_event_reset(&r->done_ev);
  if (sd_ssh_conn_disconnect(c, on_done, r) != SD_OK) return SD_E_INTERNAL;
  if (sd_event_wait(&r->done_ev, 10000) != SD_OK) return SD_E_TIMEOUT;
  sd_event_reset(&r->done_ev);
  r->done_err = SD_E_INTERNAL;
  if (sd_ssh_conn_connect(c, on_done, r) != SD_OK) return SD_E_INTERNAL;
  if (sd_event_wait(&r->done_ev, 30000) != SD_OK) return SD_E_TIMEOUT;
  return r->done_err;
}

SD_TEST(interop_reconnect_pinned_host_key)
{
  sd_known_hosts *kh = open_kh(NULL);
  run r;
  sd_ssh_conn *c = NULL;
  conn_opts o;
  sd_ssh_auth_info ai;
  SD_REQUIRE(kh != NULL);
  memset(&o, 0, sizeof(o));
  memset(&r, 0, sizeof(r));
  o.key = g_key;
  o.decision = SD_HK_ACCEPT_ONCE;            /* nothing is stored */
  SD_REQUIRE(connect_once(sd_t_, kh, &o, &r, &c) == SD_OK);
  SD_CHECK_EQ_INT(r.hostkey_prompts, 1);
  SD_CHECK(sd_ssh_conn_auth_info(c, &ai) == SD_OK && !ai.is_reconnect && ai.hostkey_just_accepted);
  /* reconnect: the key is still in no store, but equals the one accepted for this object */
  SD_CHECK_EQ_INT(reconnect(&r, c), SD_OK);
  SD_CHECK_EQ_INT(r.hostkey_prompts, 1);
  SD_CHECK(sd_ssh_conn_auth_info(c, &ai) == SD_OK && ai.is_reconnect && ai.hostkey_just_accepted);
  exec_check(sd_t_, c, &r, "echo again", "again\n", 0);
  finish(&r, c);
  sd_known_hosts_close(kh);
}

SD_TEST(interop_reconnect_secret_cache)
{
  sd_known_hosts *kh = open_kh(NULL);
  run r;
  sd_ssh_conn *c = NULL;
  conn_opts o;
  sd_ssh_auth_info ai;
  SD_REQUIRE(kh != NULL);
  if (!g_key_enc[0]) { printf("  [skip] no encrypted fixture key\n"); sd_known_hosts_close(kh); return; }
  memset(&o, 0, sizeof(o));
  memset(&r, 0, sizeof(r));
  o.key = g_key_enc;
  o.decision = SD_HK_ACCEPT_AND_STORE;
  o.cache_secrets = 1;
  /* 1: TOFU. TM-R05: secrets used right after a fresh host-key acceptance are not cached */
  SD_REQUIRE(connect_once(sd_t_, kh, &o, &r, &c) == SD_OK);
  SD_CHECK_EQ_INT(r.hostkey_prompts, 1);
  SD_CHECK_EQ_INT(r.pass_prompts, 2);
  SD_CHECK_EQ_INT(r.reconnect_prompts, 0);
  /* 2: MATCH now; the cache is empty, so the passphrase prompt comes back with is_reconnect */
  SD_CHECK_EQ_INT(reconnect(&r, c), SD_OK);
  SD_CHECK_EQ_INT(r.hostkey_prompts, 1);
  SD_CHECK_EQ_INT(r.pass_prompts, 3);
  SD_CHECK_EQ_INT(r.reconnect_prompts, 1);
  SD_CHECK(sd_ssh_conn_auth_info(c, &ai) == SD_OK && ai.is_reconnect && !ai.hostkey_just_accepted && !ai.noninteractive);
  /* 3: answered from the reconnect cache: no prompt, non-interactive */
  SD_CHECK_EQ_INT(reconnect(&r, c), SD_OK);
  SD_CHECK_EQ_INT(r.pass_prompts, 3);
  SD_CHECK(sd_ssh_conn_auth_info(c, &ai) == SD_OK && ai.is_reconnect && ai.noninteractive);
  exec_check(sd_t_, c, &r, "echo cached", "cached\n", 0);
  /* 4: clearing the cache brings the prompt back */
  SD_CHECK_EQ_INT(sd_ssh_conn_clear_secrets(c), SD_OK);
  SD_CHECK_EQ_INT(reconnect(&r, c), SD_OK);
  SD_CHECK_EQ_INT(r.pass_prompts, 4);
  finish(&r, c);

  /* without cache_secrets_for_reconnect every reconnect asks */
  memset(&r, 0, sizeof(r));
  o.cache_secrets = 0;
  c = NULL;
  SD_REQUIRE(connect_once(sd_t_, kh, &o, &r, &c) == SD_OK);   /* MATCH: no host-key prompt */
  SD_CHECK_EQ_INT(r.hostkey_prompts, 0);
  SD_CHECK_EQ_INT(r.pass_prompts, 2);
  SD_CHECK_EQ_INT(reconnect(&r, c), SD_OK);
  SD_CHECK_EQ_INT(r.pass_prompts, 3);
  SD_CHECK_EQ_INT(r.reconnect_prompts, 1);
  finish(&r, c);
  sd_known_hosts_close(kh);
}

static int write_kh(const char *text)
{
  HANDLE h = CreateFileW(g_kh_path, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, 0, NULL);
  DWORD w = 0;
  BOOL ok;
  if (h == INVALID_HANDLE_VALUE) return 0;
  ok = WriteFile(h, text, (DWORD)strlen(text), &w, NULL);
  CloseHandle(h);
  return ok && w == strlen(text);
}

SD_TEST(interop_reconnect_host_key_mismatch)
{
  char text[512];
  uint8_t *f;
  size_t n;
  sd_known_hosts *kh = open_kh(NULL);
  run r;
  sd_ssh_conn *c = NULL;
  conn_opts o;
  SD_REQUIRE(kh != NULL);
  memset(&o, 0, sizeof(o));
  memset(&r, 0, sizeof(r));
  o.key = g_key;
  o.decision = SD_HK_ACCEPT_AND_STORE;
  SD_REQUIRE(connect_once(sd_t_, kh, &o, &r, &c) == SD_OK);
  SD_CHECK_EQ_INT(r.hostkey_prompts, 1);
  /* the stored key changes underneath (what a MITM after a drop would look like to us) */
  SD_REQUIRE(tu_read_fixture("other_host.pub", &f, &n));
  {
    char *sp = strchr((char *)f, ' ');
    char *sp2 = sp ? strchr(sp + 1, ' ') : NULL;
    if (sp2) *sp2 = 0;
    _snprintf_s(text, sizeof(text), _TRUNCATE, "[%s]:%u %s\n", g_host, (unsigned)g_port, (char *)f);
  }
  sd_free(f);
  SD_REQUIRE(write_kh(text));
  SD_CHECK_EQ_INT(reconnect(&r, c), SD_E_HOSTKEY_MISMATCH);
  SD_CHECK_EQ_INT(r.hostkey_prompts, 1);          /* never a prompt */
  SD_CHECK_EQ_INT(r.mismatch_events, 1);
  /* known_hosts emptied (key removed from every store): the pinned key reconnects silently */
  SD_REQUIRE(write_kh(""));
  r.done_err = SD_E_INTERNAL;
  sd_event_reset(&r.done_ev);
  SD_REQUIRE(sd_ssh_conn_connect(c, on_done, &r) == SD_OK);
  SD_REQUIRE(sd_event_wait(&r.done_ev, 30000) == SD_OK);
  SD_CHECK_EQ_INT(r.done_err, SD_OK);
  SD_CHECK_EQ_INT(r.hostkey_prompts, 1);
  finish(&r, c);
  sd_known_hosts_close(kh);
}

SD_TEST(interop_keepalive_tuning)
{
  sd_known_hosts *kh = open_kh(NULL);
  run r;
  sd_ssh_conn *c = NULL;
  conn_opts o;
  rtt_q q;
  SD_REQUIRE(kh != NULL);
  memset(&o, 0, sizeof(o));
  memset(&r, 0, sizeof(r));
  o.key = g_key;
  o.decision = SD_HK_ACCEPT_ONCE;
  o.keepalive_ms = 60000;                         /* effectively off ... */
  SD_REQUIRE(connect_once(sd_t_, kh, &o, &r, &c) == SD_OK);
  SD_CHECK_EQ_INT(sd_ssh_conn_set_keepalive(c, 1000, 0), SD_OK);
  SD_CHECK_EQ_INT(sd_ssh_conn_set_keepalive(c, 10, 0), SD_E_INVALID_PARAM);
  Sleep(1800);                                    /* ... until tuned down to 1 s at run time */
  memset(&q, 0, sizeof(q));
  q.c = c;
  SD_REQUIRE(sd_event_init(&q.ev, 0, 0) == SD_OK);
  SD_REQUIRE(sd_ssh_conn_post(c, post_rtt, &q) == SD_OK);
  SD_REQUIRE(sd_event_wait(&q.ev, 5000) == SD_OK);
  SD_CHECK(q.have);
  sd_event_destroy(&q.ev);
  finish(&r, c);
  sd_known_hosts_close(kh);
}

static const sd_test_case k_tests[] = {
  SD_TEST_ENTRY(interop_reconnect_pinned_host_key),
  SD_TEST_ENTRY(interop_reconnect_secret_cache),
  SD_TEST_ENTRY(interop_reconnect_host_key_mismatch),
  SD_TEST_ENTRY(interop_keepalive_tuning),
  SD_TEST_ENTRY(interop_keepalive_and_probe),
  SD_TEST_ENTRY(interop_tofu_then_match),
  SD_TEST_ENTRY(interop_cipher_variants),
  SD_TEST_ENTRY(interop_encrypted_key),
  SD_TEST_ENTRY(interop_mismatch_blocks),
  SD_TEST_ENTRY(interop_stored_type_restriction),
  SD_TEST_ENTRY(interop_reject_and_auth_failure),
  SD_TEST_ENTRY(interop_rekey_bulk),
};

int main(int argc, char **argv)
{
  int rc;
  sd_ssh_global_init();
  if (!load_env()) {
    printf("interop.ssh skipped: fixture not started (%s/state/env missing); run tests/fixtures/wsl-sshd/start.ps1\n", g_dir);
    return 77;
  }
  if (!port_open()) {
    printf("interop.ssh skipped: nothing listens on %s:%u; run tests/fixtures/wsl-sshd/start.ps1\n", g_host, (unsigned)g_port);
    return 77;
  }
  if (!ssh_crypto_ready()) {
    printf("interop.ssh: sd_crypto_init failed\n");
    return 1;
  }
  if (!tu_temp_path(L"interop_known_hosts", g_kh_path, SD_COUNTOF(g_kh_path))) return 1;
  rc = sd_test_main(k_tests, SD_COUNTOF(k_tests), argc, argv);
  DeleteFileW(g_kh_path);
  return rc;
}
