/* userauth state machine (auth.c; 01 §6) against a scripted server: the test drives a connection
 * object that is never connected (no socket, no KEX, plain packet framing), feeds server messages to
 * ssh_auth_on_msg, runs the connection's command queue itself and reads what the client sends.
 * Covers password change (PASSWD_CHANGEREQ), keyboard-interactive multi-round with echo flags (OTP),
 * publickey with certificates first, RSA signature algorithm choice and fallback, passphrase prompts
 * after PK_OK, agent-backed identities (identities_only, SD_ID_AGENT_KEY, a file key held by the
 * agent), the 6-attempt limit and skipped expired certificates. */
#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <string.h>

#include "sd_base/sd_mem.h"
#include "sd_platform/sd_time.h"
#include "sd_crypto/sd_crypto.h"
#include "sd_ssh/sd_agent.h"
#include "sd_test.h"
#include "agent_internal.h"
#include "conn_internal.h"
#include "keyfile_internal.h"
#include "test_agent.h"
#include "test_util.h"

#define PASS "correct horse"

typedef struct fake {
  sd_ssh_conn *c;
  /* prompts */
  sd_prompt *prompt;
  sd_auth_prompt_info info;
  char items[3][128];
  int item_echo[3];
  uint32_t nitems;
  char instruction[256];
  int prompts;
  /* done */
  int done;
  sd_err done_err;
  /* last client packet */
  uint8_t pkt[8192];       /* one auth message; the largest is a 4k-RSA certificate request */
  size_t pkt_len;
} fake;


static void on_prompt(void *ctx, sd_prompt *p, const sd_auth_prompt_info *a, const sd_hostkey_prompt_info *h)
{
  fake *f = (fake *)ctx;
  uint32_t i;
  SD_UNUSED(h);
  f->prompt = p;
  f->prompts++;
  f->info = *a;
  f->nitems = SD_MIN(a->item_count, 3u);
  for (i = 0; i < f->nitems; i++) {
    _snprintf_s(f->items[i], sizeof(f->items[i]), _TRUNCATE, "%s", a->items[i].text);
    f->item_echo[i] = a->items[i].echo;
  }
  _snprintf_s(f->instruction, sizeof(f->instruction), _TRUNCATE, "%s", a->instruction ? a->instruction : "");
}

static void on_done(void *ctx, sd_err e, uint32_t hop)
{
  fake *f = (fake *)ctx;
  SD_UNUSED(hop);
  f->done = 1;
  f->done_err = e;
}

static wchar_t *fixture_path(const char *name)
{
  static wchar_t buf[8][MAX_PATH];
  static int slot;
  char p[MAX_PATH];
  wchar_t *w = buf[slot++ & 7];
  _snprintf_s(p, sizeof(p), _TRUNCATE, "%s/keys/%s", SD_SSH_TEST_FIXTURES, name);
  MultiByteToWideChar(CP_UTF8, 0, p, -1, w, MAX_PATH);
  return w;
}

static int fake_new(fake *f, uint32_t methods, const sd_ssh_auth_cfg *acfg)
{
  sd_ssh_conn *c = (sd_ssh_conn *)sd_calloc(1, sizeof(*c));
  memset(f, 0, sizeof(*f));
  if (!c) return 0;
  f->c = c;
  c->s = INVALID_SOCKET;
  c->att[0].s = c->att[1].s = INVALID_SOCKET;
  sd_mutex_init(&c->qlock);
  c->cmd_ev = CreateEventW(NULL, FALSE, FALSE, NULL);
  c->workers_idle = CreateEventW(NULL, TRUE, TRUE, NULL);
  sd_wr_init(&c->out, 64u * 1024u * 1024u);
  ssh_dir_init(&c->tx);
  ssh_dir_init(&c->rx);
  c->user = (char *)sd_alloc(7);
  c->host_utf8 = (char *)sd_alloc(5);
  if (!c->user || !c->host_utf8) return 0;
  memcpy(c->user, "tester", 7);
  memcpy(c->host_utf8, "fake", 5);
  c->methods = methods;
  c->cb.ctx = f;
  c->cb.on_prompt = on_prompt;
  if (acfg && ssh_auth_cfg_copy(c, acfg) != SD_OK) return 0;
  ssh_seccache_init(&c->cache, c->id_count);
  c->gen = 1;
  c->session_id_len = 32;
  memset(c->session_id, 0x5A, 32);
  memcpy(c->server_version, "OpenSSH_9.6p1", 14);
  c->connect_done = on_done;
  c->connect_ctx = f;
  c->ka_interval_ms = 15000;
  return 1;
}

static void run_queue(sd_ssh_conn *c)
{
  for (;;) {
    ssh_cmd *cmd;
    sd_mutex_lock(&c->qlock);
    cmd = c->qhead;
    if (cmd) { c->qhead = cmd->next; if (!c->qhead) c->qtail = NULL; }
    sd_mutex_unlock(&c->qlock);
    if (!cmd) return;
    cmd->run(cmd->conn ? cmd->conn : c, cmd);
  }
}

/* Pops one client packet (plain framing) into f->pkt. */
static int take_packet(fake *f)
{
  sd_ssh_conn *c = f->c;
  uint32_t len;
  uint8_t pad;
  if (c->out.len < 5) return 0;
  len = sd_load_be32(c->out.p);
  pad = c->out.p[4];
  if (len + 4u > c->out.len || pad + 1u > len) return 0;
  f->pkt_len = len - pad - 1u;
  memcpy(f->pkt, c->out.p + 5, f->pkt_len);
  memmove(c->out.p, c->out.p + 4 + len, c->out.len - 4 - len);
  c->out.len -= 4 + len;
  return 1;
}

/* Runs the queue until the client sent a packet, raised a prompt, finished or failed. */
static int pump(fake *f, int want_packet)
{
  uint64_t end = sd_tick_ms() + 20000;
  int prompts = f->prompts;
  while (sd_tick_ms() < end) {
    run_queue(f->c);
    if (want_packet && take_packet(f)) return 1;
    if (!want_packet && f->prompts != prompts) return 1;
    if (f->c->failing || f->done) return 0;
    WaitForSingleObject(f->c->cmd_ev, 50);
  }
  return 0;
}

/* Waits for the n-th prompt of this connection. Prompts are raised synchronously while a srv_*
   helper delivers its message (this thread plays the I/O thread), so a pump() taken after the
   call would wait for a further prompt that never comes. */
static int pump_prompts(fake *f, int n)
{
  uint64_t end = sd_tick_ms() + 20000;
  while (sd_tick_ms() < end) {
    run_queue(f->c);
    if ((int)f->prompts >= n) return 1;
    if (f->c->failing || f->done) return 0;
    WaitForSingleObject(f->c->cmd_ev, 50);
  }
  return 0;
}

static void fake_free(fake *f)
{
  sd_ssh_conn *c = f->c;
  if (!c) return;
  WaitForSingleObject(c->workers_idle, 30000);
  run_queue(c);
  if (c->cur_prompt) ssh_prompt_withdraw(c, c->cur_prompt);
  run_queue(c);
  ssh_auth_clear(c);
  ssh_auth_cfg_free(c);
  ssh_seccache_free(&c->cache);
  sd_wr_free(&c->out);
  ssh_dir_clear(&c->tx);
  ssh_dir_clear(&c->rx);
  sd_free(c->user);
  sd_free(c->host_utf8);
  CloseHandle(c->cmd_ev);
  CloseHandle(c->workers_idle);
  sd_mutex_destroy(&c->qlock);
  sd_free(c);
  f->c = NULL;
}

/* ---- server messages ---- */

static void srv(fake *f, sd_wr *w)
{
  if (sd_wr_ok(w)) ssh_auth_on_msg(f->c, w->p, w->len);
  sd_wr_free(w);
}

static void srv_failure(fake *f, const char *methods, int partial)
{
  sd_wr w;
  sd_wr_init(&w, 4096);
  sd_wr_u8(&w, SSH_MSG_USERAUTH_FAILURE);
  sd_wr_cstring(&w, methods);
  sd_wr_bool(&w, partial);
  srv(f, &w);
}

static void srv_success(fake *f)
{
  uint8_t b = SSH_MSG_USERAUTH_SUCCESS;
  ssh_auth_on_msg(f->c, &b, 1);
}

/* Parses the publickey request in f->pkt: alg, blob, signature (optional). */
typedef struct pk_req { char alg[96]; sd_span blob, sig; int has_sig; size_t signed_end; } pk_req;

static int parse_pk(fake *f, pk_req *q)
{
  sd_rd r;
  sd_span user, svc, method, alg;
  memset(q, 0, sizeof(*q));
  sd_rd_init(&r, f->pkt, f->pkt_len);
  if (sd_rd_u8(&r) != SSH_MSG_USERAUTH_REQUEST) return 0;
  user = sd_rd_string(&r, 256);
  svc = sd_rd_string(&r, 256);
  method = sd_rd_string(&r, 256);
  if (!ssh_span_eq(user, "tester") || !ssh_span_eq(svc, "ssh-connection") || !ssh_span_eq(method, "publickey")) return 0;
  q->has_sig = sd_rd_bool(&r);
  alg = sd_rd_string(&r, 95);
  q->blob = sd_rd_string(&r, 65536);
  q->signed_end = f->pkt_len - sd_rd_remaining(&r);
  if (q->has_sig) q->sig = sd_rd_string(&r, 65536);
  if (!sd_rd_done(&r)) return 0;
  ssh_span_copy(alg, q->alg, sizeof(q->alg));
  return 1;
}

static void srv_pk_ok(fake *f, const pk_req *q)
{
  sd_wr w;
  sd_wr_init(&w, 8192);
  sd_wr_u8(&w, SSH_MSG_USERAUTH_PK_OK);
  sd_wr_cstring(&w, q->alg);
  sd_wr_string(&w, q->blob.p, q->blob.n);
  srv(f, &w);
}

/* Verifies the signature of a signed publickey request with the plain key of `keyfile`. */
static int verify_pk_sig(fake *f, const pk_req *q, const char *keyfile)
{
  uint8_t *fb;
  size_t n;
  sd_ssh_key *k = NULL;
  sd_wr d;
  sd_rd r;
  sd_span t, raw;
  int ok = 0;
  char path[MAX_PATH];
  _snprintf_s(path, sizeof(path), _TRUNCATE, "keys/%s", keyfile);
  if (!tu_read_fixture(path, &fb, &n)) return 0;
  if (sd_ssh_key_load(fb, n, NULL, 0, &k) == SD_E_KEY_PASSPHRASE_REQUIRED) (void)sd_ssh_key_load(fb, n, PASS, strlen(PASS), &k);
  sd_free(fb);
  if (!k) return 0;
  sd_wr_init(&d, 8192);
  sd_wr_string(&d, f->c->session_id, f->c->session_id_len);
  sd_wr_bytes(&d, f->pkt, q->signed_end);
  sd_rd_init(&r, q->sig.p, q->sig.n);
  t = sd_rd_string(&r, 64);
  raw = sd_rd_string(&r, 4096);
  if (sd_rd_done(&r)) {
    sd_rd p;
    sd_rd_init(&p, k->pub, k->pub_len);
    (void)sd_rd_string(&p, 64);
    if (k->kt == SSH_KT_ED25519) {
      sd_span pk = sd_rd_string(&p, 64);
      ok = ssh_span_eq(t, "ssh-ed25519") && sd_ed25519_verify(raw.p, pk.p, d.p, d.len) == SD_OK;
    } else if (k->kt == SSH_KT_RSA) {
      sd_span e = sd_rd_mpint(&p, 64), nn = sd_rd_mpint(&p, 2049);
      sd_rsa_import_params ip;
      sd_rsa_key *rk = NULL;
      sd_hash_alg h = ssh_span_eq(t, "ssh-rsa") ? SD_HASH_SHA1 : ssh_span_eq(t, "rsa-sha2-256") ? SD_HASH_SHA256 : SD_HASH_SHA512;
      uint8_t dg[64];
      memset(&ip, 0, sizeof(ip));
      ip.n = nn.p; ip.n_len = nn.n; ip.e = e.p; ip.e_len = e.n;
      if (sd_rsa_import(&ip, &rk) == SD_OK) {
        sd_hash(h, d.p, d.len, dg);
        ok = raw.n == sd_rsa_len(rk) && sd_rsa_pkcs1_verify(rk, h, dg, sd_hash_len(h), raw.p, raw.n) == SD_OK;
        sd_rsa_free(rk);
      }
    } else {
      sd_span cn = sd_rd_string(&p, 64), qq = sd_rd_string(&p, 256), rr, ss;
      sd_curve cv = k->curve == 256 ? SD_CURVE_P256 : k->curve == 384 ? SD_CURVE_P384 : SD_CURVE_P521;
      sd_ec_key *ek = NULL;
      uint8_t dg[64];
      sd_rd in;
      (void)cn;
      sd_rd_init(&in, raw.p, raw.n);
      rr = sd_rd_mpint(&in, 80);
      ss = sd_rd_mpint(&in, 80);
      if (sd_rd_done(&in) && sd_ec_import(cv, qq.p, qq.n, NULL, 0, &ek) == SD_OK) {
        sd_hash(sd_ec_hash(cv), d.p, d.len, dg);
        ok = sd_ecdsa_verify(ek, dg, sd_hash_len(sd_ec_hash(cv)), rr.p, rr.n, ss.p, ss.n) == SD_OK;
        sd_ec_free(ek);
      }
    }
  }
  sd_wr_free(&d);
  sd_ssh_key_free(k);
  return ok;
}

static int pub_of(const char *pubfile, uint8_t *blob, size_t cap, size_t *bl)
{
  char path[MAX_PATH];
  uint8_t *fb;
  size_t n;
  int ok;
  _snprintf_s(path, sizeof(path), _TRUNCATE, "keys/%s", pubfile);
  if (!tu_read_fixture(path, &fb, &n)) return 0;
  ok = sd_ssh_pubkey_parse(fb, n, blob, cap, bl, NULL, 0) == SD_OK;
  sd_free(fb);
  return ok;
}

/* none -> FAILURE(methods); returns after the client's next action. */
static void start_auth(fake *f, const char *methods)
{
  ssh_auth_start(f->c);
  take_packet(f);   /* "none" */
  srv_failure(f, methods, 0);
}

/* ---- tests ---- */

SD_TEST(ssh_auth_password_change)
{
  fake f;
  sd_rd r;
  const char *ans1[1] = { "old-pw" };
  const char *mismatch[3] = { "old-pw", "new-1", "new-2" };
  const char *good[3] = { "old-pw", "new-pw", "new-pw" };
  SD_REQUIRE(fake_new(&f, SD_AUTH_PASSWORD, NULL));
  start_auth(&f, "password");
  SD_REQUIRE(pump_prompts(&f, 1));
  SD_CHECK_EQ_INT(f.info.kind, SD_PROMPT_PASSWORD);
  SD_CHECK_EQ_INT(sd_prompt_answer(f.prompt, 1, ans1), SD_OK);
  SD_REQUIRE(pump(&f, 1));
  {
    sd_wr w;
    sd_wr_init(&w, 1024);
    sd_wr_u8(&w, SSH_MSG_USERAUTH_PASSWD_CHANGEREQ);
    sd_wr_cstring(&w, "Your password has expired\x1b[31m");
    sd_wr_cstring(&w, "");
    srv(&f, &w);
  }
  SD_REQUIRE(pump_prompts(&f, 2));
  SD_CHECK_EQ_INT(f.info.kind, SD_PROMPT_NEW_PASSWORD);
  SD_CHECK_EQ_INT(f.nitems, 3);
  SD_CHECK(strstr(f.instruction, "expired") != NULL && strchr(f.instruction, 0x1b) == NULL);   /* sanitized */
  SD_CHECK(!f.item_echo[0] && !f.item_echo[1] && !f.item_echo[2]);
  SD_CHECK(!f.info.may_autofill);
  SD_CHECK_EQ_INT(sd_prompt_answer(f.prompt, 3, mismatch), SD_OK);
  SD_REQUIRE(pump_prompts(&f, 3));               /* asked again, nothing sent */
  SD_CHECK_EQ_INT(f.info.kind, SD_PROMPT_NEW_PASSWORD);
  SD_CHECK(strstr(f.instruction, "do not match") != NULL);
  SD_CHECK_EQ_INT(f.c->out.len, 0);
  SD_CHECK_EQ_INT(sd_prompt_answer(f.prompt, 3, good), SD_OK);
  SD_REQUIRE(pump(&f, 1));
  sd_rd_init(&r, f.pkt, f.pkt_len);
  {
    sd_span user, svc, m, o, nw;
    int change;
    SD_CHECK_EQ_INT(sd_rd_u8(&r), SSH_MSG_USERAUTH_REQUEST);
    user = sd_rd_string(&r, 64); svc = sd_rd_string(&r, 64); m = sd_rd_string(&r, 64);
    change = sd_rd_bool(&r);
    o = sd_rd_string(&r, 64); nw = sd_rd_string(&r, 64);
    SD_CHECK(sd_rd_done(&r) && ssh_span_eq(m, "password") && change && ssh_span_eq(o, "old-pw") && ssh_span_eq(nw, "new-pw"));
    (void)user; (void)svc;
  }
  srv_success(&f);
  SD_CHECK(f.done && f.done_err == SD_OK);
  SD_CHECK(f.c->methods_used & SD_AUTH_PASSWORD);
  fake_free(&f);
}

SD_TEST(ssh_auth_kbdint_otp_rounds)
{
  fake f;
  const char *pw[1] = { "secret" };
  const char *otp[1] = { "123456" };
  SD_REQUIRE(fake_new(&f, SD_AUTH_KBDINT | SD_AUTH_PASSWORD, NULL));
  start_auth(&f, "keyboard-interactive");
  SD_REQUIRE(pump(&f, 1));                      /* keyboard-interactive request */
  {
    sd_wr w;
    sd_wr_init(&w, 1024);
    sd_wr_u8(&w, SSH_MSG_USERAUTH_INFO_REQUEST);
    sd_wr_cstring(&w, "PAM");
    sd_wr_cstring(&w, "");
    sd_wr_cstring(&w, "");
    sd_wr_u32(&w, 1);
    sd_wr_cstring(&w, "Password: ");
    sd_wr_bool(&w, 0);
    srv(&f, &w);
  }
  SD_REQUIRE(pump_prompts(&f, 1));
  SD_CHECK_EQ_INT(f.info.kind, SD_PROMPT_KBDINT);
  SD_CHECK_EQ_INT(f.info.round, 0);
  SD_CHECK(f.info.may_autofill);
  SD_CHECK_EQ_INT(sd_prompt_answer(f.prompt, 1, pw), SD_OK);
  SD_REQUIRE(pump(&f, 1));
  SD_CHECK(f.pkt[0] == SSH_MSG_USERAUTH_INFO_RESPONSE);
  {
    /* second round: an echoed OTP prompt (Google Authenticator style) */
    sd_wr w;
    sd_wr_init(&w, 1024);
    sd_wr_u8(&w, SSH_MSG_USERAUTH_INFO_REQUEST);
    sd_wr_cstring(&w, "");
    sd_wr_cstring(&w, "Two-factor authentication");
    sd_wr_cstring(&w, "");
    sd_wr_u32(&w, 1);
    sd_wr_cstring(&w, "Verification code: ");
    sd_wr_bool(&w, 1);
    srv(&f, &w);
  }
  SD_REQUIRE(pump_prompts(&f, 2));
  SD_CHECK_EQ_INT(f.info.round, 1);
  SD_CHECK(!f.info.may_autofill);
  SD_CHECK(f.item_echo[0]);
  SD_CHECK_STR(f.items[0], "Verification code: ");
  SD_CHECK_STR(f.instruction, "Two-factor authentication");
  SD_CHECK_EQ_INT(sd_prompt_answer(f.prompt, 1, otp), SD_OK);
  SD_REQUIRE(pump(&f, 1));
  {
    sd_rd r;
    sd_span a;
    sd_rd_init(&r, f.pkt, f.pkt_len);
    SD_CHECK_EQ_INT(sd_rd_u8(&r), SSH_MSG_USERAUTH_INFO_RESPONSE);
    SD_CHECK_EQ_INT(sd_rd_u32(&r), 1);
    a = sd_rd_string(&r, 64);
    SD_CHECK(sd_rd_done(&r) && ssh_span_eq(a, "123456"));
  }
  {
    /* a zero-prompt round is answered at once */
    sd_wr w;
    sd_wr_init(&w, 1024);
    sd_wr_u8(&w, SSH_MSG_USERAUTH_INFO_REQUEST);
    sd_wr_cstring(&w, ""); sd_wr_cstring(&w, ""); sd_wr_cstring(&w, "");
    sd_wr_u32(&w, 0);
    srv(&f, &w);
  }
  SD_REQUIRE(take_packet(&f));
  SD_CHECK(f.pkt_len == 5 && f.pkt[0] == SSH_MSG_USERAUTH_INFO_RESPONSE);
  srv_success(&f);
  SD_CHECK(f.done && f.done_err == SD_OK && (f.c->methods_used & SD_AUTH_KBDINT));
  fake_free(&f);
}

SD_TEST(ssh_auth_publickey_cert_first)
{
  fake f;
  sd_ssh_identity id;
  sd_ssh_auth_cfg acfg;
  pk_req q;
  uint8_t cert[4096], pub[1024];
  size_t cl, pl;
  if (!tu_crypto_or_skip("ssh_auth_publickey_cert_first")) return;
  memset(&id, 0, sizeof(id));
  memset(&acfg, 0, sizeof(acfg));
  id.kind = SD_ID_FILE;
  id.path = fixture_path("ossh_ed25519");
  acfg.identities = &id;
  acfg.identity_count = 1;
  acfg.identities_only = 1;
  SD_REQUIRE(pub_of("ossh_ed25519-cert.pub", cert, sizeof(cert), &cl));
  SD_REQUIRE(pub_of("ossh_ed25519.pub", pub, sizeof(pub), &pl));
  SD_REQUIRE(fake_new(&f, SD_AUTH_PUBLICKEY, &acfg));
  start_auth(&f, "publickey");
  SD_REQUIRE(pump(&f, 1));
  SD_REQUIRE(parse_pk(&f, &q));
  SD_CHECK(!q.has_sig);
  SD_CHECK_STR(q.alg, "ssh-ed25519-cert-v01@openssh.com");
  SD_CHECK(q.blob.n == cl && memcmp(q.blob.p, cert, cl) == 0);
  srv_failure(&f, "publickey", 0);              /* the server does not trust the CA */
  SD_REQUIRE(pump(&f, 1));
  SD_REQUIRE(parse_pk(&f, &q));
  SD_CHECK_STR(q.alg, "ssh-ed25519");
  SD_CHECK(q.blob.n == pl && memcmp(q.blob.p, pub, pl) == 0);
  srv_pk_ok(&f, &q);
  SD_REQUIRE(pump(&f, 1));
  SD_REQUIRE(parse_pk(&f, &q));
  SD_CHECK(q.has_sig);
  SD_CHECK(verify_pk_sig(&f, &q, "ossh_ed25519"));
  srv_success(&f);
  SD_CHECK(f.done && f.done_err == SD_OK && (f.c->methods_used & SD_AUTH_PUBLICKEY));
  SD_CHECK_EQ_INT(f.prompts, 0);
  fake_free(&f);
}

SD_TEST(ssh_auth_rsa_algorithms)
{
  fake f;
  sd_ssh_identity id;
  sd_ssh_auth_cfg acfg;
  pk_req q;
  if (!tu_crypto_or_skip("ssh_auth_rsa_algorithms")) return;
  memset(&id, 0, sizeof(id));
  memset(&acfg, 0, sizeof(acfg));
  id.kind = SD_ID_FILE;
  id.path = fixture_path("ossh_rsa2048");
  acfg.identities = &id;
  acfg.identity_count = 1;
  /* no server-sig-algs, OpenSSH >= 7.2: the <file>-cert.pub certificate goes first (01 §6.2) and
     walks the same rsa-sha2-512 > -256 > ssh-rsa ladder (§4.5), then the plain key; the signature
     is made with the algorithm that got PK_OK */
  {
    uint8_t cert[2048], pub[1024];
    size_t cl = 0, pl = 0;
    SD_REQUIRE(pub_of("ossh_rsa2048-cert.pub", cert, sizeof(cert), &cl));
    SD_REQUIRE(pub_of("ossh_rsa2048.pub", pub, sizeof(pub), &pl));
    SD_REQUIRE(fake_new(&f, SD_AUTH_PUBLICKEY, &acfg));
    start_auth(&f, "publickey");
    SD_REQUIRE(pump(&f, 1));
    SD_REQUIRE(parse_pk(&f, &q));
    SD_CHECK_STR(q.alg, "rsa-sha2-512-cert-v01@openssh.com");
    SD_CHECK(!q.has_sig && q.blob.n == cl && memcmp(q.blob.p, cert, cl) == 0);
    srv_failure(&f, "publickey", 0);
    SD_REQUIRE(pump(&f, 1));
    SD_REQUIRE(parse_pk(&f, &q));
    SD_CHECK_STR(q.alg, "rsa-sha2-256-cert-v01@openssh.com");
    srv_failure(&f, "publickey", 0);
    SD_REQUIRE(pump(&f, 1));
    SD_REQUIRE(parse_pk(&f, &q));
    SD_CHECK_STR(q.alg, "ssh-rsa-cert-v01@openssh.com");
    srv_failure(&f, "publickey", 0);
    SD_REQUIRE(pump(&f, 1));
    SD_REQUIRE(parse_pk(&f, &q));
    SD_CHECK_STR(q.alg, "rsa-sha2-512");
    SD_CHECK(q.blob.n == pl && memcmp(q.blob.p, pub, pl) == 0);
    srv_failure(&f, "publickey", 0);
    SD_REQUIRE(pump(&f, 1));
    SD_REQUIRE(parse_pk(&f, &q));
    SD_CHECK_STR(q.alg, "rsa-sha2-256");
    srv_pk_ok(&f, &q);
    SD_REQUIRE(pump(&f, 1));
    SD_REQUIRE(parse_pk(&f, &q));
    SD_CHECK(q.has_sig && verify_pk_sig(&f, &q, "ossh_rsa2048"));
    SD_CHECK(!(f.c->legacy_mask & SD_LEGACY_USERAUTH_SHA1));
    srv_failure(&f, "publickey", 0);              /* signature refused: last fallback is ssh-rsa */
    SD_REQUIRE(pump(&f, 1));
    SD_REQUIRE(parse_pk(&f, &q));
    SD_CHECK_STR(q.alg, "ssh-rsa");
    srv_pk_ok(&f, &q);
    SD_REQUIRE(pump(&f, 1));
    SD_REQUIRE(parse_pk(&f, &q));
    SD_CHECK(q.has_sig && verify_pk_sig(&f, &q, "ossh_rsa2048"));
    SD_CHECK(f.c->legacy_mask & SD_LEGACY_USERAUTH_SHA1);
    srv_success(&f);
    SD_CHECK(f.done && f.done_err == SD_OK);
    fake_free(&f);
  }
  /* server-sig-algs: only what the server lists, no fallback */
  SD_REQUIRE(fake_new(&f, SD_AUTH_PUBLICKEY | SD_AUTH_PASSWORD, &acfg));
  memcpy(f.c->server_sig_algs, "ssh-ed25519,rsa-sha2-256", 25);
  start_auth(&f, "publickey,password");
  SD_REQUIRE(pump(&f, 1));
  SD_REQUIRE(parse_pk(&f, &q));
  SD_CHECK_STR(q.alg, "rsa-sha2-256-cert-v01@openssh.com");
  srv_failure(&f, "publickey,password", 0);       /* certificate refused: plain key, same ladder */
  SD_REQUIRE(pump(&f, 1));
  SD_REQUIRE(parse_pk(&f, &q));
  SD_CHECK_STR(q.alg, "rsa-sha2-256");
  srv_failure(&f, "password", 0);
  SD_REQUIRE(pump_prompts(&f, 1));               /* next method: password prompt */
  SD_CHECK_EQ_INT(f.info.kind, SD_PROMPT_PASSWORD);
  sd_prompt_cancel(f.prompt);
  run_queue(f.c);
  SD_CHECK(f.c->failing && f.c->fail_err == SD_E_CANCELLED);
  fake_free(&f);
}

SD_TEST(ssh_auth_passphrase_after_pk_ok)
{
  fake f;
  sd_ssh_identity id;
  sd_ssh_auth_cfg acfg;
  pk_req q;
  const char *wrong[1] = { "nope" };
  const char *right[1] = { PASS };
  if (!tu_crypto_or_skip("ssh_auth_passphrase_after_pk_ok")) return;
  memset(&id, 0, sizeof(id));
  memset(&acfg, 0, sizeof(acfg));
  id.kind = SD_ID_FILE;
  id.path = fixture_path("ppk3_ed25519_enc");
  acfg.identities = &id;
  acfg.identity_count = 1;
  SD_REQUIRE(fake_new(&f, SD_AUTH_PUBLICKEY, &acfg));
  start_auth(&f, "publickey");
  SD_REQUIRE(pump(&f, 1));                      /* query first: no prompt for a key the server rejects */
  SD_REQUIRE(parse_pk(&f, &q));
  SD_CHECK_EQ_INT(f.prompts, 0);
  srv_pk_ok(&f, &q);
  SD_REQUIRE(pump_prompts(&f, 1));
  SD_CHECK_EQ_INT(f.info.kind, SD_PROMPT_KEY_PASSPHRASE);
  SD_CHECK(f.info.key_fingerprint && !strncmp(f.info.key_fingerprint, "SHA256:", 7));
  SD_CHECK(f.info.key_path && strstr(f.info.key_path, "ppk3_ed25519_enc") != NULL);
  SD_CHECK_EQ_INT(sd_prompt_answer(f.prompt, 1, wrong), SD_OK);
  SD_REQUIRE(pump_prompts(&f, 2));
  SD_CHECK_EQ_INT(f.info.kind, SD_PROMPT_KEY_PASSPHRASE);
  SD_CHECK_EQ_INT(f.info.round, 1);
  SD_CHECK_EQ_INT(sd_prompt_answer(f.prompt, 1, right), SD_OK);
  SD_REQUIRE(pump(&f, 1));
  SD_REQUIRE(parse_pk(&f, &q));
  SD_CHECK(q.has_sig && verify_pk_sig(&f, &q, "ossh_ed25519"));
  srv_success(&f);
  SD_CHECK(f.done && f.done_err == SD_OK);
  fake_free(&f);
}

SD_TEST(ssh_auth_expired_cert_skipped)
{
  fake f;
  sd_ssh_identity id;
  sd_ssh_auth_cfg acfg;
  pk_req q;
  if (!tu_crypto_or_skip("ssh_auth_expired_cert_skipped")) return;
  memset(&id, 0, sizeof(id));
  memset(&acfg, 0, sizeof(acfg));
  id.kind = SD_ID_FILE;
  id.path = fixture_path("ossh_p384_exp");     /* ossh_p384_exp-cert.pub expired in 2020 */
  acfg.identities = &id;
  acfg.identity_count = 1;
  SD_REQUIRE(fake_new(&f, SD_AUTH_PUBLICKEY, &acfg));
  start_auth(&f, "publickey");
  SD_REQUIRE(pump(&f, 1));
  SD_REQUIRE(parse_pk(&f, &q));
  SD_CHECK_STR(q.alg, "ecdsa-sha2-nistp384");
  srv_pk_ok(&f, &q);
  SD_REQUIRE(pump(&f, 1));
  SD_REQUIRE(parse_pk(&f, &q));
  SD_CHECK(q.has_sig && verify_pk_sig(&f, &q, "ossh_p384"));
  srv_success(&f);
  fake_free(&f);
}

SD_TEST(ssh_auth_agent_keys)
{
  static const char *const keys[] = { "ossh_p256", "ossh_ed25519", "ossh_rsa2048", "ossh_p384_enc" };
  ta_pipe_agent pa;
  fake f;
  sd_ssh_auth_cfg acfg;
  sd_ssh_identity id[2];
  pk_req q;
  uint8_t pub[1024];
  size_t pl;
  if (!tu_crypto_or_skip("ssh_auth_agent_keys")) return;
  memset(&pa, 0, sizeof(pa));
  SD_REQUIRE(ta_agent_init(&pa.agent, keys, 4) == SD_OK);
  SD_REQUIRE(ta_pipe_start(&pa) == SD_OK);

  /* no identities, identities_only off: agent keys in agent order */
  memset(&acfg, 0, sizeof(acfg));
  acfg.agents = SD_AGENT_OPENSSH;
  SD_REQUIRE(fake_new(&f, SD_AUTH_PUBLICKEY, &acfg));
  start_auth(&f, "publickey");
  SD_REQUIRE(pump(&f, 1));
  SD_REQUIRE(parse_pk(&f, &q));
  SD_CHECK_STR(q.alg, "ecdsa-sha2-nistp256");
  srv_failure(&f, "publickey", 0);
  SD_REQUIRE(pump(&f, 1));
  SD_REQUIRE(parse_pk(&f, &q));
  SD_CHECK_STR(q.alg, "ssh-ed25519");
  srv_pk_ok(&f, &q);
  SD_REQUIRE(pump(&f, 1));
  SD_REQUIRE(parse_pk(&f, &q));
  SD_CHECK(q.has_sig && verify_pk_sig(&f, &q, "ossh_ed25519"));
  SD_CHECK(pa.agent.sign_requests == 1);
  srv_success(&f);
  SD_CHECK(f.done && f.done_err == SD_OK);
  fake_free(&f);

  /* identities_only with an agent key selected by fingerprint and an encrypted file key that the
     agent also holds: only those two, both signed by the agent (no passphrase prompt) */
  {
    sd_ssh_key *rk = pa.agent.keys[2];
    char fp[64];
    size_t bl;
    const uint8_t *b = sd_ssh_key_public_blob(rk, &bl);
    SD_REQUIRE(sd_hostkey_fingerprint_sha256(b, bl, fp) == SD_OK);
    memset(id, 0, sizeof(id));
    id[0].kind = SD_ID_AGENT_KEY;
    id[0].agent_fingerprint = fp;
    id[1].kind = SD_ID_FILE;
    id[1].path = fixture_path("ossh_p384_enc");
    memset(&acfg, 0, sizeof(acfg));
    acfg.agents = SD_AGENT_OPENSSH;
    acfg.identities = id;
    acfg.identity_count = 2;
    acfg.identities_only = 1;
    pa.agent.last_flags = 0;
    SD_REQUIRE(fake_new(&f, SD_AUTH_PUBLICKEY | SD_AUTH_PASSWORD, &acfg));
    memcpy(f.c->server_sig_algs, "rsa-sha2-512,rsa-sha2-256", 26);
    start_auth(&f, "publickey,password");
    SD_REQUIRE(pump(&f, 1));
    SD_REQUIRE(parse_pk(&f, &q));
    SD_CHECK_STR(q.alg, "rsa-sha2-512");
    SD_CHECK(q.blob.n == bl && memcmp(q.blob.p, b, bl) == 0);
    srv_pk_ok(&f, &q);
    SD_REQUIRE(pump(&f, 1));
    SD_REQUIRE(parse_pk(&f, &q));
    SD_CHECK(q.has_sig && verify_pk_sig(&f, &q, "ossh_rsa2048"));
    SD_CHECK_EQ_INT(pa.agent.last_flags, SD_AGENT_SIGN_RSA_SHA2_512);
    srv_failure(&f, "publickey,password", 0);     /* refused: same key retried with rsa-sha2-256 (§4.5) */
    SD_REQUIRE(pump(&f, 1));
    SD_REQUIRE(parse_pk(&f, &q));
    SD_CHECK_STR(q.alg, "rsa-sha2-256");
    SD_CHECK(q.blob.n == bl && memcmp(q.blob.p, b, bl) == 0);
    srv_failure(&f, "publickey,password", 0);     /* ladder exhausted: next identity */
    SD_REQUIRE(pump(&f, 1));
    SD_REQUIRE(parse_pk(&f, &q));
    SD_CHECK_STR(q.alg, "ecdsa-sha2-nistp384");
    SD_REQUIRE(pub_of("ossh_p384_enc.pub", pub, sizeof(pub), &pl));
    SD_CHECK(q.blob.n == pl && memcmp(q.blob.p, pub, pl) == 0);
    srv_pk_ok(&f, &q);
    SD_REQUIRE(pump(&f, 1));
    SD_REQUIRE(parse_pk(&f, &q));
    SD_CHECK(q.has_sig && verify_pk_sig(&f, &q, "ossh_p384_enc"));
    SD_CHECK_EQ_INT(f.prompts, 0);
    srv_failure(&f, "password", 0);              /* no other agent key is offered */
    SD_REQUIRE(pump_prompts(&f, 1));
    SD_CHECK_EQ_INT(f.info.kind, SD_PROMPT_PASSWORD);
    sd_prompt_cancel(f.prompt);
    run_queue(f.c);
    fake_free(&f);
  }
  ta_pipe_stop(&pa);
  ta_agent_free(&pa.agent);
}

SD_TEST(ssh_auth_attempt_limit)
{
  static const char *const keys[] = { "ossh_p256", "ossh_ed25519", "ossh_rsa2048", "ossh_p384", "ossh_p521",
                                      "ossh_rsa1024", "ossh_ed25519_gcm" };
  ta_pipe_agent pa;
  fake f;
  sd_ssh_auth_cfg acfg;
  pk_req q;
  int queries = 0;
  if (!tu_crypto_or_skip("ssh_auth_attempt_limit")) return;
  memset(&pa, 0, sizeof(pa));
  SD_REQUIRE(ta_agent_init(&pa.agent, keys, 7) == SD_OK);
  SD_REQUIRE(ta_pipe_start(&pa) == SD_OK);
  memset(&acfg, 0, sizeof(acfg));
  acfg.agents = SD_AGENT_OPENSSH;
  SD_REQUIRE(fake_new(&f, SD_AUTH_PUBLICKEY | SD_AUTH_PASSWORD, &acfg));
  memcpy(f.c->server_sig_algs, "rsa-sha2-512", 13);
  start_auth(&f, "publickey,password");
  while (pump(&f, 1) && parse_pk(&f, &q)) {
    queries++;
    srv_failure(&f, "publickey,password", 0);
  }
  SD_CHECK_EQ_INT(queries, 6);                  /* OpenSSH MaxAuthTries */
  SD_CHECK_EQ_INT(f.info.kind, SD_PROMPT_PASSWORD);
  sd_prompt_cancel(f.prompt);
  run_queue(f.c);
  fake_free(&f);
  ta_pipe_stop(&pa);
  ta_agent_free(&pa.agent);
}
