/* Connection object: configuration validation, lifecycle without a server, prompt objects. */
#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <string.h>

#include "sd_platform/sd_thread.h"
#include "sd_test.h"
#include "conn_internal.h"
#include "test_util.h"

static void base_cfg(sd_ssh_config *cfg, sd_ssh_hop *hop, const wchar_t *host, uint16_t port)
{
  memset(cfg, 0, sizeof(*cfg));
  memset(hop, 0, sizeof(*hop));
  hop->host = host;
  hop->port = port;
  hop->auth.user = "tester";
  hop->auth.methods = SD_AUTH_PASSWORD;
  cfg->struct_size = sizeof(*cfg);
  cfg->hops = hop;
  cfg->hop_count = 1;
  cfg->connect_timeout_ms = 3000;
}

typedef struct done_ctx { sd_event ev; sd_err err; } done_ctx;
static void on_done(void *ctx, sd_err e, uint32_t hop) { done_ctx *d = (done_ctx *)ctx; SD_UNUSED(hop); d->err = e; sd_event_set(&d->ev); }

SD_TEST(ssh_conn_config_validation)
{
  sd_ssh_config cfg;
  sd_ssh_hop hops[2];
  sd_ssh_conn *c = NULL;
  sd_ssh_identity id;
  base_cfg(&cfg, &hops[0], L"127.0.0.1", 1);
  hops[1] = hops[0];
  cfg.hops = hops;
  cfg.hop_count = 2;
  SD_CHECK_EQ_INT(sd_ssh_conn_create(&cfg, NULL, &c), SD_OK);              /* jump chains (jump_chain.c) */
  sd_ssh_conn_destroy(c);
  c = NULL;
  cfg.hop_count = 1;
  hops[0].proxy.kind = SD_PROXY_SOCKS5;
  SD_CHECK_EQ_INT(sd_ssh_conn_create(&cfg, NULL, &c), SD_E_INVALID_PARAM); /* proxy without a host */
  hops[0].proxy.host = L"127.0.0.1";
  SD_CHECK_EQ_INT(sd_ssh_conn_create(&cfg, NULL, &c), SD_OK);
  sd_ssh_conn_destroy(c);
  c = NULL;
  hops[0].proxy.kind = SD_PROXY_NONE;
  hops[0].proxy.host = NULL;
  memset(&id, 0, sizeof(id));
  id.kind = SD_ID_AGENT_KEY;
  hops[0].auth.identities = &id;
  hops[0].auth.identity_count = 1;
  SD_CHECK_EQ_INT(sd_ssh_conn_create(&cfg, NULL, &c), SD_E_INVALID_PARAM); /* fingerprint required */
  id.agent_fingerprint = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
  SD_CHECK_EQ_INT(sd_ssh_conn_create(&cfg, NULL, &c), SD_E_INVALID_PARAM); /* agent source required */
  hops[0].auth.agents = SD_AGENT_OPENSSH;
  SD_CHECK_EQ_INT(sd_ssh_conn_create(&cfg, NULL, &c), SD_OK);
  sd_ssh_conn_destroy(c);
  c = NULL;
  hops[0].auth.identity_count = 0;
  hops[0].auth.agents = 0;
  cfg.struct_size = 4;
  SD_CHECK_EQ_INT(sd_ssh_conn_create(&cfg, NULL, &c), SD_E_INVALID_PARAM);
  cfg.struct_size = sizeof(cfg);
  hops[0].host = L"bad host";
  SD_CHECK_EQ_INT(sd_ssh_conn_create(&cfg, NULL, &c), SD_E_UNSUPPORTED);
  hops[0].host = L"127.0.0.1";
  SD_CHECK_EQ_INT(sd_ssh_conn_create(&cfg, NULL, &c), SD_OK);
  SD_REQUIRE(c != NULL);
  SD_CHECK_STR(c->lookup_name, "[127.0.0.1]:1");
  SD_CHECK(!sd_ssh_conn_is_io_thread(c));
  if (ssh_crypto_ready()) {
    /* nothing listens on port 1: refused (or timeout on unusual stacks) */
    done_ctx d;
    SD_REQUIRE(sd_event_init(&d.ev, 0, 0) == SD_OK);
    d.err = SD_E_INTERNAL;
    SD_CHECK_EQ_INT(sd_ssh_conn_connect(c, on_done, &d), SD_OK);
    SD_CHECK_EQ_INT(sd_event_wait(&d.ev, 10000), SD_OK);
    SD_CHECK(d.err == SD_E_CONN_REFUSED || d.err == SD_E_TIMEOUT);
    sd_event_destroy(&d.ev);
  } else {
    SD_CHECK_EQ_INT(sd_ssh_conn_connect(c, on_done, NULL), SD_E_UNSUPPORTED);
    tu_crypto_or_skip("ssh_conn_config_validation(connect)");
  }
  sd_ssh_conn_destroy(c);
}

/* ---- prompts ---- */

typedef struct prompt_ctx {
  sd_ssh_conn *c;
  sd_event ev;
  sd_prompt *raised, *withdrawn;
  int step;
} prompt_ctx;

static void cb_prompt(void *ctx, sd_prompt *p, const sd_auth_prompt_info *a, const sd_hostkey_prompt_info *h)
{
  prompt_ctx *pc = (prompt_ctx *)ctx;
  SD_UNUSED(a); SD_UNUSED(h);
  pc->raised = p;
}
static void cb_withdrawn(void *ctx, sd_prompt *p) { ((prompt_ctx *)ctx)->withdrawn = p; }

static void io_step(void *arg)
{
  prompt_ctx *pc = (prompt_ctx *)arg;
  sd_ssh_conn *c = pc->c;
  if (pc->step == 0) {
    sd_prompt *p = ssh_prompt_new(c, SSH_PP_PASSWORD, SD_PROMPT_PASSWORD);
    ssh_prompt_raise(c, p);
    ssh_prompt_withdraw(c, p);      /* connection "dies" before an answer */
  } else {
    sd_prompt *p;
    c->hostkey_just_accepted = 1;   /* TM-R05 */
    p = ssh_prompt_new(c, SSH_PP_PASSWORD, SD_PROMPT_PASSWORD);
    ssh_prompt_raise(c, p);
  }
  sd_event_set(&pc->ev);
}

SD_TEST(ssh_prompt_lifecycle)
{
  sd_ssh_config cfg;
  sd_ssh_hop hop;
  sd_ssh_callbacks cb;
  prompt_ctx pc;
  static const char *const resp[] = { "secret" };
  base_cfg(&cfg, &hop, L"localhost", 22);
  memset(&pc, 0, sizeof(pc));
  memset(&cb, 0, sizeof(cb));
  cb.ctx = &pc;
  cb.on_prompt = cb_prompt;
  cb.on_prompt_withdrawn = cb_withdrawn;
  SD_REQUIRE(sd_event_init(&pc.ev, 0, 0) == SD_OK);
  SD_REQUIRE(sd_ssh_conn_create(&cfg, &cb, &pc.c) == SD_OK);

  pc.step = 0;
  SD_REQUIRE(sd_ssh_conn_post(pc.c, io_step, &pc) == SD_OK);
  SD_REQUIRE(sd_event_wait(&pc.ev, 5000) == SD_OK);
  SD_CHECK(pc.raised != NULL);
  SD_CHECK(pc.withdrawn == pc.raised);
  /* answering a withdrawn prompt reports the cancellation (and releases it) */
  SD_CHECK_EQ_INT(sd_prompt_answer(pc.raised, 1, resp), SD_E_CANCELLED);

  pc.step = 1;
  pc.raised = pc.withdrawn = NULL;
  SD_REQUIRE(sd_ssh_conn_post(pc.c, io_step, &pc) == SD_OK);
  SD_REQUIRE(sd_event_wait(&pc.ev, 5000) == SD_OK);
  SD_REQUIRE(pc.raised != NULL);
  /* a stored secret must not answer right after a host key acceptance */
  SD_CHECK_EQ_INT(sd_prompt_answer_ex(pc.raised, 1, resp, SD_ANSWER_FROM_STORE), SD_E_INVALID_PARAM);
  SD_CHECK_EQ_INT(sd_prompt_answer_hostkey(pc.raised, SD_HK_ACCEPT_ONCE), SD_E_INVALID_PARAM);
  SD_CHECK_EQ_INT(sd_prompt_answer(pc.raised, 1, resp), SD_OK);
  sd_ssh_conn_destroy(pc.c);
  sd_event_destroy(&pc.ev);
}

/* ---- M1: reconnect secret cache (01 §7.4, TM-R05) and repeated connects ---- */

SD_TEST(ssh_secret_cache_roundtrip)
{
  static const char pw[] = "correct horse battery staple";
  ssh_secret sec;
  sd_secbuf *out = NULL;
  static sd_ssh_conn fake;             /* ~50 KB: keep the test off the stack */
  memset(&sec, 0, sizeof(sec));
  if (!ssh_secret_cache_available()) { printf("  [skip] no CryptProtectMemory / RtlEncryptMemory\n"); return; }
  SD_REQUIRE(ssh_secret_store(&sec, (const uint8_t *)pw, sizeof(pw) - 1) == SD_OK);
  SD_CHECK(sec.cap % 16 == 0 && sec.len == sizeof(pw) - 1);
  {
    size_t i;
    int plain = 0;           /* the protected blob never holds the secret in clear */
    for (i = 0; i + 8 <= sec.cap; i++) if (memcmp(sec.blob + i, pw, 8) == 0) plain = 1;
    SD_CHECK(!plain);
  }
  SD_REQUIRE(ssh_secret_load(&sec, &out) == SD_OK);
  SD_CHECK(out->len == sizeof(pw) - 1 && memcmp(out->p, pw, out->len) == 0);
  sd_secbuf_free(out);
  ssh_secret_clear(&sec);
  SD_CHECK(sec.blob == NULL);
  SD_CHECK_EQ_INT(ssh_secret_load(&sec, &out), SD_E_NOT_FOUND);
  SD_CHECK_EQ_INT(ssh_secret_store(&sec, (const uint8_t *)pw, 0), SD_E_INVALID_PARAM);
  memset(&fake, 0, sizeof(fake));
  fake.cache_secrets = 1;
  SD_CHECK(ssh_cache_usable(&fake));
  fake.hostkey_just_accepted = 1;     /* TM-R05: never right after a fresh host-key acceptance */
  SD_CHECK(!ssh_cache_usable(&fake));
  fake.hostkey_just_accepted = 0;
  fake.cache_secrets = 0;
  SD_CHECK(!ssh_cache_usable(&fake));
}

SD_TEST(ssh_conn_connect_again_after_failure)
{
  sd_ssh_config cfg;
  sd_ssh_hop hop;
  sd_ssh_conn *c = NULL;
  done_ctx d;
  sd_ssh_auth_info ai;
  int i;
  if (!tu_crypto_or_skip("ssh_conn_connect_again_after_failure")) return;
  base_cfg(&cfg, &hop, L"127.0.0.1", 1);      /* nothing listens on port 1 */
  SD_REQUIRE(sd_ssh_conn_create(&cfg, NULL, &c) == SD_OK);
  SD_REQUIRE(sd_event_init(&d.ev, 0, 0) == SD_OK);
  for (i = 0; i < 3; i++) {                   /* the same object connects again (reconnect loop) */
    d.err = SD_OK;
    SD_REQUIRE(sd_ssh_conn_connect(c, on_done, &d) == SD_OK);
    SD_REQUIRE(sd_event_wait(&d.ev, 10000) == SD_OK);
    SD_CHECK(d.err == SD_E_CONN_REFUSED || d.err == SD_E_TIMEOUT || d.err == SD_E_DISCONNECTED);
  }
  SD_CHECK(sd_ssh_conn_auth_info(c, &ai) == SD_OK && !ai.is_reconnect);   /* never connected */
  SD_CHECK_EQ_INT(sd_ssh_conn_set_keepalive(c, 999, 0), SD_E_INVALID_PARAM);
  SD_CHECK_EQ_INT(sd_ssh_conn_set_keepalive(c, 0, 101), SD_E_INVALID_PARAM);
  SD_CHECK_EQ_INT(sd_ssh_conn_set_keepalive(c, 5000, 2), SD_OK);
  SD_CHECK_EQ_INT(sd_ssh_conn_clear_secrets(c), SD_OK);
  sd_ssh_conn_destroy(c);
  sd_event_destroy(&d.ev);
}
