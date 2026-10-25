/* Connection object: configuration validation, lifecycle without a server, prompt objects. */
#include <winsock2.h>
#include <windows.h>
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
  SD_CHECK_EQ_INT(sd_ssh_conn_create(&cfg, NULL, &c), SD_E_UNSUPPORTED);   /* ProxyJump: M2 */
  cfg.hop_count = 1;
  hops[0].proxy.kind = SD_PROXY_SOCKS5;
  SD_CHECK_EQ_INT(sd_ssh_conn_create(&cfg, NULL, &c), SD_E_UNSUPPORTED);
  hops[0].proxy.kind = SD_PROXY_NONE;
  memset(&id, 0, sizeof(id));
  id.kind = SD_ID_AGENT_KEY;
  hops[0].auth.identities = &id;
  hops[0].auth.identity_count = 1;
  SD_CHECK_EQ_INT(sd_ssh_conn_create(&cfg, NULL, &c), SD_E_UNSUPPORTED);
  hops[0].auth.identity_count = 0;
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
