/* sd_mount M2 against the scripted fake: ProxyJump chains and proxies, saved secrets (autofill rules,
 * TM-R05, saving after success), keyboard-interactive rounds, legacy warning / ack, password change,
 * UpdateHostKeys announcements and the pool's 2FA rule. */
#include <windows.h>
#include <string.h>

#include "sd_test.h"
#include "fake_backend.h"
#include "sd_base/sd_mem.h"
#include "sd_platform/sd_thread.h"
#include "sd_platform/sd_time.h"

typedef struct qitem { struct qitem *next; void (*fn)(void *); void *arg; } qitem;

typedef struct secret { int kind; char target[320]; char value[64]; } secret;

typedef struct h2 {
  sd_mutex lock;
  HANDLE ev;
  qitem *head, *tail;
  sd_mount *m;
  /* prompts seen by the "user" */
  sd_mount_prompt prompts[16];
  uint32_t nprompts;
  sd_mount_answer_kind hk_answer, ack_answer;
  const char *otp;
  int save;                       /* answer with SD_MOUNT_ANSWER_SAVE */
  /* the host's secret store */
  secret store[8];
  uint32_t nstore, gets, puts;
  /* warnings and announcements */
  char warn_code[8][32], warn_detail[8][256];
  uint32_t nwarn;
  sd_mount_announcement ann[4];
  int ann_applied[4];
  uint32_t nann;
} h2;

static void q_post(void *ctx, void (*fn)(void *), void *arg)
{
  h2 *h = (h2 *)ctx;
  qitem *q = (qitem *)sd_calloc(1, sizeof(*q));
  if (q == NULL) return;
  q->fn = fn;
  q->arg = arg;
  sd_mutex_lock(&h->lock);
  if (h->tail) h->tail->next = q; else h->head = q;
  h->tail = q;
  sd_mutex_unlock(&h->lock);
  SetEvent(h->ev);
}

static void on_state(void *ctx, sd_mount *m, sd_mount_state st, sd_err why)
{
  SD_UNUSED(ctx); SD_UNUSED(m); SD_UNUSED(st); SD_UNUSED(why);
}

static void on_prompt(void *ctx, sd_mount *m, const sd_mount_prompt *p)
{
  h2 *h = (h2 *)ctx;
  const char *r[3];
  if (h->nprompts < 16) h->prompts[h->nprompts++] = *p;
  switch (p->kind) {
  case SD_MP_HOSTKEY:
    sd_mount_answer(m, p->id, h->hk_answer, 0, NULL);
    break;
  case SD_MP_LEGACY_ACK:
    sd_mount_answer(m, p->id, h->ack_answer, 0, NULL);
    break;
  case SD_MP_PASSWORD_CHANGE:
    r[0] = FAKE_PASSWORD; r[1] = "n3w-secret"; r[2] = "n3w-secret";
    sd_mount_answer(m, p->id, SD_MA_RESPONSES, 3, r);
    break;
  case SD_MP_PROXY_PASSWORD:
    r[0] = FAKE_PROXY_PASSWORD;
    sd_mount_answer_ex(m, p->id, SD_MA_RESPONSES, 1, r, h->save ? SD_MOUNT_ANSWER_SAVE : 0);
    break;
  case SD_MP_PASSPHRASE:
    r[0] = FAKE_PASSPHRASE;
    sd_mount_answer_ex(m, p->id, SD_MA_RESPONSES, 1, r, h->save ? SD_MOUNT_ANSWER_SAVE : 0);
    break;
  default:
    r[0] = (p->kind == SD_MP_KBDINT && strstr(p->items[0].text, "Verification")) ? h->otp : FAKE_PASSWORD;
    sd_mount_answer_ex(m, p->id, SD_MA_RESPONSES, 1, r, h->save ? SD_MOUNT_ANSWER_SAVE : 0);
    break;
  }
}

static int secret_get(void *ctx, sd_mount *m, int kind, const char *target, char *out, size_t cap)
{
  h2 *h = (h2 *)ctx;
  uint32_t i;
  SD_UNUSED(m);
  h->gets++;
  for (i = 0; i < h->nstore; i++)
    if (h->store[i].kind == kind && strcmp(h->store[i].target, target) == 0) {
      strcpy_s(out, cap, h->store[i].value);
      return 1;
    }
  return 0;
}

static void store_add(h2 *h, int kind, const char *target, const char *value)
{
  uint32_t i;
  for (i = 0; i < h->nstore; i++)
    if (h->store[i].kind == kind && strcmp(h->store[i].target, target) == 0) break;
  if (i == h->nstore) {
    if (h->nstore >= 8) return;
    h->nstore++;
  }
  h->store[i].kind = kind;
  strcpy_s(h->store[i].target, sizeof(h->store[i].target), target);
  strcpy_s(h->store[i].value, sizeof(h->store[i].value), value);
}

static void secret_put(void *ctx, sd_mount *m, int kind, const char *target, const char *value)
{
  h2 *h = (h2 *)ctx;
  SD_UNUSED(m);
  h->puts++;
  store_add(h, kind, target, value);
}

static void on_warning(void *ctx, sd_mount *m, const char *code, uint32_t hop, const char *detail)
{
  h2 *h = (h2 *)ctx;
  SD_UNUSED(m);
  SD_UNUSED(hop);
  if (h->nwarn < 8) {
    strcpy_s(h->warn_code[h->nwarn], 32, code);
    strcpy_s(h->warn_detail[h->nwarn], 256, detail ? detail : "");
    h->nwarn++;
  }
}

static void on_announced(void *ctx, sd_mount *m, const sd_mount_announcement *a, int applied, sd_err err)
{
  h2 *h = (h2 *)ctx;
  SD_UNUSED(m);
  SD_UNUSED(err);
  if (h->nann < 4) {
    h->ann[h->nann] = *a;
    h->ann_applied[h->nann] = applied;
    h->nann++;
  }
}

static void pump(h2 *h, uint32_t ms)
{
  uint64_t end = sd_tick_ms() + ms;
  while (sd_tick_ms() < end) {
    qitem *q;
    sd_mutex_lock(&h->lock);
    q = h->head;
    if (q) { h->head = q->next; if (!h->head) h->tail = NULL; }
    sd_mutex_unlock(&h->lock);
    if (q) {
      q->fn(q->arg);
      sd_free(q);
      continue;
    }
    WaitForSingleObject(h->ev, 20);
  }
}

static int pump_until(h2 *h, sd_mount_state st, uint32_t ms)
{
  uint64_t end = sd_tick_ms() + ms;
  while (sd_tick_ms() < end) {
    pump(h, 20);
    if (sd_mount_get_state(h->m) == st || (st == SD_MOUNT_FAILED && sd_mount_is_final(h->m)))
      return 1;
  }
  return 0;
}

static void init(h2 *h)
{
  memset(h, 0, sizeof(*h));
  sd_mutex_init(&h->lock);
  h->ev = CreateEventW(NULL, FALSE, FALSE, NULL);
  h->hk_answer = SD_MA_HOSTKEY_TRUST;
  h->ack_answer = SD_MA_HOSTKEY_TRUST;
  h->otp = FAKE_OTP;
}

static void stop(h2 *h)
{
  if (!sd_mount_is_final(h->m)) {
    uint64_t end = sd_tick_ms() + 5000;
    sd_mount_stop(h->m);
    while (!sd_mount_is_final(h->m) && sd_tick_ms() < end) pump(h, 20);
  }
  sd_mount_destroy(h->m);
  h->m = NULL;
  pump(h, 30);
}

static void done(h2 *h)
{
  if (h->m) stop(h);
  CloseHandle(h->ev);
  sd_mutex_destroy(&h->lock);
}

static sd_mount_callbacks callbacks(h2 *h)
{
  sd_mount_callbacks cb;
  memset(&cb, 0, sizeof(cb));
  cb.ctx = h;
  cb.post = q_post;
  cb.on_state = on_state;
  cb.on_prompt = on_prompt;
  cb.secret_get = secret_get;
  cb.secret_put = secret_put;
  cb.on_warning = on_warning;
  cb.on_hostkeys_announced = on_announced;
  return cb;
}

/* single hop through the M2 hop array */
static sd_err create1(h2 *h, const wchar_t *host, const char *user, wchar_t letter, int legacy, uint32_t conns,
                      int hku)
{
  sd_mount_params p;
  sd_mount_hop hop;
  sd_mount_callbacks cb = callbacks(h);
  memset(&p, 0, sizeof(p));
  memset(&hop, 0, sizeof(hop));
  hop.host = host;
  hop.user = user;
  hop.update_host_keys = hku;
  p.struct_size = sizeof(p);
  p.host = host;
  p.user = user;
  p.letter = letter;
  p.hops = &hop;
  p.hop_count = 1;
  p.legacy_policy = legacy;
  p.connections = conns;
  return sd_mount_create(fake_backend(), &p, &cb, &h->m);
}

static uint32_t count_kind(const h2 *h, sd_mount_prompt_kind k)
{
  uint32_t i, n = 0;
  for (i = 0; i < h->nprompts; i++)
    if (h->prompts[i].kind == k) n++;
  return n;
}

SD_TEST(mount_m2_chain_and_proxies)
{
  static h2 h;                         /* the prompt/announcement log is big: keep it off the stack */
  sd_mount_params p;
  sd_mount_hop hops[2];
  sd_mount_callbacks cb;
  const wchar_t *ids[2] = { L"C:\\k\\id_target", L"C:\\k\\id_second" };
  uint32_t i;
  init(&h);
  fake_backend_reset();
  cb = callbacks(&h);
  memset(&p, 0, sizeof(p));
  memset(hops, 0, sizeof(hops));
  hops[0].host = L"bastion.test";
  hops[0].user = "jump";
  hops[0].proxy.kind = SD_PROXY_SOCKS5;
  hops[0].proxy.host = L"socks.corp";
  hops[0].proxy.port = 1080;
  hops[1].host = L"target.test";
  hops[1].port = 2222;
  hops[1].user = "alice";
  hops[1].identities = ids;
  hops[1].identity_count = 2;
  hops[1].identities_only = 1;
  hops[1].agent_keys = "SHA256:agentkey1, SHA256:agentkey2";
  hops[1].proxy.kind = SD_PROXY_HTTP;
  hops[1].proxy.host = L"10.0.0.1";
  hops[1].proxy.port = 3128;
  hops[1].proxy.user = "pu";
  hops[1].proxy.auth = SD_PROXY_AUTH_BASIC;
  p.struct_size = sizeof(p);
  p.host = L"target.test";
  p.user = "alice";
  p.letter = L'P';
  p.hops = hops;
  p.hop_count = 2;
  SD_REQUIRE(sd_mount_create(fake_backend(), &p, &cb, &h.m) == SD_OK);
  SD_REQUIRE(sd_mount_start(h.m) == SD_OK);
  SD_CHECK(pump_until(&h, SD_MOUNT_MOUNTED, 5000));
  SD_CHECK(fake_backend_last_hop_count() == 2);
  SD_CHECK_STR(fake_backend_last_hop_host(0), "bastion.test");
  SD_CHECK_STR(fake_backend_last_hop_user(0), "jump");
  SD_CHECK(fake_backend_last_hop_proxy(0) == SD_PROXY_SOCKS5 && fake_backend_last_hop_proxy(1) == SD_PROXY_HTTP);
  SD_CHECK(fake_backend_last_hop_identities(1) == 2 && fake_backend_last_hop_agent_keys(1) == 2);
  SD_CHECK(fake_backend_last_hop_identities_only(1) == 1);
  /* prompts: hop 0 TOFU + password, leg 2 proxy password, hop 1 TOFU (through the bastion) */
  SD_CHECK(count_kind(&h, SD_MP_HOSTKEY) == 2 && count_kind(&h, SD_MP_PASSWORD) == 1 &&
           count_kind(&h, SD_MP_PROXY_PASSWORD) == 1);
  for (i = 0; i < h.nprompts; i++) {
    SD_CHECK(h.prompts[i].hop_count == 2);
    if (h.prompts[i].kind == SD_MP_HOSTKEY && h.prompts[i].hop_index == 1)
      SD_CHECK_STR(h.prompts[i].via_host, "bastion.test");
    if (h.prompts[i].kind == SD_MP_PROXY_PASSWORD) {
      SD_CHECK_STR(h.prompts[i].proxy_host, "10.0.0.1");
      SD_CHECK(h.prompts[i].proxy_port == 3128 && h.prompts[i].can_save);
      SD_CHECK_STR(h.prompts[i].user, "pu");
    }
  }
  /* HTTP Basic with a user: the clear-text warning names the proxy */
  SD_CHECK(h.nwarn == 1);
  SD_CHECK_STR(h.warn_code[0], "proxy_cleartext");
  SD_CHECK_STR(h.warn_detail[0], "10.0.0.1:3128");
  done(&h);
}

SD_TEST(mount_m2_autofill_rules)
{
  static h2 h;   /* big harness: off the stack */
  init(&h);
  fake_backend_reset();
  /* 1: TOFU in this connection -> the saved password is not sent (TM-R05) */
  store_add(&h, SD_MOUNT_SECRET_PASSWORD, "alice@store.test:22", FAKE_PASSWORD);
  SD_REQUIRE(create1(&h, L"store.test", "alice", L'P', SD_LEGACY_WARN, 1, SD_HKU_ASK) == SD_OK);
  SD_REQUIRE(sd_mount_start(h.m) == SD_OK);
  SD_CHECK(pump_until(&h, SD_MOUNT_MOUNTED, 5000));
  SD_CHECK(count_kind(&h, SD_MP_PASSWORD) == 1);
  SD_CHECK(h.prompts[1].hostkey_just_accepted == 1 && h.prompts[1].can_save == 1);
  SD_CHECK(fake_backend_store_answers() == 0);
  stop(&h);
  /* 2: the key is stored now: the password comes from the store, nobody is asked */
  h.nprompts = 0;
  SD_REQUIRE(create1(&h, L"store.test", "alice", L'P', SD_LEGACY_WARN, 1, SD_HKU_ASK) == SD_OK);
  SD_REQUIRE(sd_mount_start(h.m) == SD_OK);
  SD_CHECK(pump_until(&h, SD_MOUNT_MOUNTED, 5000));
  SD_CHECK(h.nprompts == 0);
  SD_CHECK(fake_backend_store_answers() == 1);
  stop(&h);
  /* 3: a wrong saved password is tried once, then the user is asked */
  store_add(&h, SD_MOUNT_SECRET_PASSWORD, "alice@store.test:22", "stale");
  h.nprompts = 0;
  SD_REQUIRE(create1(&h, L"store.test", "alice", L'P', SD_LEGACY_WARN, 1, SD_HKU_ASK) == SD_OK);
  SD_REQUIRE(sd_mount_start(h.m) == SD_OK);
  SD_CHECK(pump_until(&h, SD_MOUNT_MOUNTED, 5000));
  SD_CHECK(h.nprompts == 1 && h.prompts[0].kind == SD_MP_PASSWORD && h.prompts[0].round == 1);
  SD_CHECK(fake_backend_store_answers() == 2);
  done(&h);
}

SD_TEST(mount_m2_save_after_success)
{
  static h2 h;   /* big harness: off the stack */
  init(&h);
  fake_backend_reset();
  h.save = 1;
  SD_REQUIRE(create1(&h, L"save.test", "bob", L'P', SD_LEGACY_WARN, 1, SD_HKU_ASK) == SD_OK);
  SD_REQUIRE(sd_mount_start(h.m) == SD_OK);
  SD_CHECK(pump_until(&h, SD_MOUNT_MOUNTED, 5000));
  SD_CHECK(h.puts == 1 && h.nstore == 1);
  SD_CHECK(h.store[0].kind == SD_MOUNT_SECRET_PASSWORD);
  SD_CHECK_STR(h.store[0].target, "bob@save.test:22");
  SD_CHECK_STR(h.store[0].value, FAKE_PASSWORD);
  stop(&h);
  /* a failed login saves nothing */
  h.nstore = 0;
  h.puts = 0;
  SD_REQUIRE(create1(&h, L"unreachable.test", "bob", L'P', SD_LEGACY_WARN, 1, SD_HKU_ASK) == SD_OK);
  SD_REQUIRE(sd_mount_start(h.m) == SD_OK);
  SD_CHECK(pump_until(&h, SD_MOUNT_FAILED, 5000));
  SD_CHECK(h.puts == 0);
  done(&h);
}

SD_TEST(mount_m2_kbdint_password_round_and_otp)
{
  static h2 h;   /* big harness: off the stack */
  init(&h);
  fake_backend_reset();
  SD_REQUIRE(create1(&h, L"kbd.test", "carol", L'P', SD_LEGACY_WARN, 1, SD_HKU_ASK) == SD_OK);
  SD_REQUIRE(sd_mount_start(h.m) == SD_OK);
  SD_CHECK(pump_until(&h, SD_MOUNT_MOUNTED, 5000));
  SD_CHECK(count_kind(&h, SD_MP_KBDINT) == 2);
  stop(&h);
  /* the password-shaped round comes from the store; the OTP round never does */
  store_add(&h, SD_MOUNT_SECRET_PASSWORD, "carol@kbd.test:22", FAKE_PASSWORD);
  store_add(&h, SD_MOUNT_SECRET_PASSWORD, "carol@kbd.test:22", FAKE_PASSWORD);
  h.nprompts = 0;
  SD_REQUIRE(create1(&h, L"kbd.test", "carol", L'P', SD_LEGACY_WARN, 1, SD_HKU_ASK) == SD_OK);
  SD_REQUIRE(sd_mount_start(h.m) == SD_OK);
  SD_CHECK(pump_until(&h, SD_MOUNT_MOUNTED, 5000));
  SD_CHECK(h.nprompts == 1 && h.prompts[0].kind == SD_MP_KBDINT);
  SD_CHECK(strstr(h.prompts[0].items[0].text, "Verification") != NULL && h.prompts[0].items[0].echo == 0);
  SD_CHECK(!h.prompts[0].can_save);
  SD_CHECK_STR(h.prompts[0].instruction, "Two-factor authentication");
  done(&h);
}

SD_TEST(mount_m2_legacy_warn_ask_refuse)
{
  static h2 h;   /* big harness: off the stack */
  sd_mount_failure f;
  init(&h);
  fake_backend_reset();
  SD_REQUIRE(create1(&h, L"legacy.test", "dan", L'P', SD_LEGACY_WARN, 1, SD_HKU_ASK) == SD_OK);
  SD_REQUIRE(sd_mount_start(h.m) == SD_OK);
  SD_CHECK(pump_until(&h, SD_MOUNT_MOUNTED, 5000));
  SD_CHECK(h.nwarn == 1);
  SD_CHECK_STR(h.warn_code[0], "legacy_algorithms");
  SD_CHECK_STR(h.warn_detail[0], "3des-cbc,hmac-sha1");
  SD_CHECK(fake_backend_last_legacy_policy() == SD_LEGACY_WARN);
  stop(&h);
  /* ask: the ack prompt comes before authentication */
  h.nprompts = 0;
  h.nwarn = 0;
  SD_REQUIRE(create1(&h, L"legacy.test", "dan", L'P', SD_LEGACY_ASK, 1, SD_HKU_ASK) == SD_OK);
  SD_REQUIRE(sd_mount_start(h.m) == SD_OK);
  SD_CHECK(pump_until(&h, SD_MOUNT_MOUNTED, 5000));
  SD_CHECK(h.nprompts == 2 && h.prompts[0].kind == SD_MP_LEGACY_ACK && h.prompts[1].kind == SD_MP_PASSWORD);
  SD_CHECK_STR(h.prompts[0].legacy_names, "3des-cbc,hmac-sha1");
  stop(&h);
  h.ack_answer = SD_MA_REJECT;
  SD_REQUIRE(create1(&h, L"legacy.test", "dan", L'P', SD_LEGACY_ASK, 1, SD_HKU_ASK) == SD_OK);
  SD_REQUIRE(sd_mount_start(h.m) == SD_OK);
  SD_CHECK(pump_until(&h, SD_MOUNT_FAILED, 5000));
  sd_mount_get_failure(h.m, &f);
  SD_CHECK(f.err == SD_E_LEGACY_REJECTED);
  stop(&h);
  /* allow: no warning */
  h.nwarn = 0;
  SD_REQUIRE(create1(&h, L"legacy.test", "dan", L'P', SD_LEGACY_ALLOW, 1, SD_HKU_ASK) == SD_OK);
  SD_REQUIRE(sd_mount_start(h.m) == SD_OK);
  SD_CHECK(pump_until(&h, SD_MOUNT_MOUNTED, 5000));
  SD_CHECK(h.nwarn == 0);
  done(&h);
}

/* 03 §7.6, 2.4: the current security state of a mount, independent of the warnings and of the legacy policy.
   Outdated names come with their category (cipher and mac on both directions, deduplicated); Terrapin is its own
   flag and is not a legacy algorithm. */
SD_TEST(mount_m2_security_state)
{
  static h2 h;   /* big harness: off the stack */
  sd_mount_security sec;
  init(&h);
  fake_backend_reset();
  SD_CHECK(sd_mount_get_security(NULL, &sec) == 0);
  SD_REQUIRE(create1(&h, L"legacy.test", "dan", L'P', SD_LEGACY_ALLOW, 1, SD_HKU_ASK) == SD_OK);
  SD_REQUIRE(sd_mount_start(h.m) == SD_OK);
  SD_CHECK(pump_until(&h, SD_MOUNT_MOUNTED, 5000));
  SD_CHECK(h.nwarn == 0);                         /* allowed: no warning, the state is still reported */
  SD_REQUIRE(sd_mount_get_security(h.m, &sec));
  SD_CHECK_EQ_INT(sec.legacy, 1);
  SD_CHECK_EQ_INT(sec.terrapin_exposed, 0);
  SD_CHECK_EQ_INT(sec.legacy_count, 2);
  SD_CHECK_STR(sec.legacy_algs[0].category, "cipher");
  SD_CHECK_STR(sec.legacy_algs[0].name, "3des-cbc");
  SD_CHECK_STR(sec.legacy_algs[1].category, "mac");
  SD_CHECK_STR(sec.legacy_algs[1].name, "hmac-sha1");
  stop(&h);
  SD_REQUIRE(create1(&h, L"terrapin.test", "dan", L'P', SD_LEGACY_WARN, 1, SD_HKU_ASK) == SD_OK);
  SD_REQUIRE(sd_mount_start(h.m) == SD_OK);
  SD_CHECK(pump_until(&h, SD_MOUNT_MOUNTED, 5000));
  SD_REQUIRE(sd_mount_get_security(h.m, &sec));
  SD_CHECK_EQ_INT(sec.terrapin_exposed, 1);
  SD_CHECK_EQ_INT(sec.legacy, 0);                 /* Terrapin alone is not an outdated algorithm */
  SD_CHECK_EQ_INT(sec.legacy_count, 0);
  done(&h);
}

SD_TEST(mount_m2_password_change)
{
  static h2 h;   /* big harness: off the stack */
  init(&h);
  fake_backend_reset();
  SD_REQUIRE(create1(&h, L"chpw.test", "erin", L'P', SD_LEGACY_WARN, 1, SD_HKU_ASK) == SD_OK);
  SD_REQUIRE(sd_mount_start(h.m) == SD_OK);
  SD_CHECK(pump_until(&h, SD_MOUNT_MOUNTED, 5000));
  SD_CHECK(count_kind(&h, SD_MP_PASSWORD_CHANGE) == 1);
  SD_CHECK(h.prompts[h.nprompts - 1].item_count == 3);
  SD_CHECK_STR(h.prompts[h.nprompts - 1].instruction, "Your password has expired.");
  SD_CHECK_STR(fake_backend_last_new_password(), "n3w-secret");
  done(&h);
}

SD_TEST(mount_m2_hostkeys_announced)
{
  static h2 h;   /* big harness: off the stack */
  sd_kh_store st;
  const char *name = NULL;
  uint32_t removed = 0;
  init(&h);
  fake_backend_reset();
  SD_REQUIRE(create1(&h, L"rotate.test", "fay", L'P', SD_LEGACY_WARN, 1, SD_HKU_ASK) == SD_OK);
  SD_REQUIRE(sd_mount_start(h.m) == SD_OK);
  SD_CHECK(pump_until(&h, SD_MOUNT_MOUNTED, 5000));
  pump(&h, 100);
  SD_REQUIRE(h.nann == 1);
  SD_CHECK(h.ann_applied[0] == 0 && h.ann[0].add_count == 1 && h.ann[0].remove_count == 1);
  SD_CHECK_STR(h.ann[0].lookup_name, "rotate.test");
  SD_CHECK_STR(h.ann[0].add[0].type, "ssh-ed25519");
  SD_CHECK(fake_backend_apply_calls() == 0);              /* ask: nothing changes before the review */
  memset(&st, 0, sizeof(st));
  st.kind = SD_KH_STORE_USER;
  st.writable = 1;
  SD_CHECK(sd_mount_apply_hostkeys(fake_backend(), &st, 1, &h.ann[0], 0) == SD_OK);
  SD_CHECK(fake_backend_applied(&removed, &name) == 1 && removed == 1);
  SD_CHECK_STR(name, "rotate.test");
  stop(&h);
  /* yes: proven keys are added at once; the removal still waits for a review */
  h.nann = 0;
  SD_REQUIRE(create1(&h, L"rotate.test", "fay", L'P', SD_LEGACY_WARN, 1, SD_HKU_YES) == SD_OK);
  SD_REQUIRE(sd_mount_start(h.m) == SD_OK);
  SD_CHECK(pump_until(&h, SD_MOUNT_MOUNTED, 5000));
  pump(&h, 100);
  SD_CHECK(h.nann == 2 && h.ann_applied[0] == 1 && h.ann_applied[1] == 0 && h.ann[1].add_count == 0 &&
           h.ann[1].remove_count == 1);
  SD_CHECK(fake_backend_applied(&removed, NULL) == 2 && removed == 1);
  stop(&h);
  /* no: ignored */
  h.nann = 0;
  SD_REQUIRE(create1(&h, L"rotate.test", "fay", L'P', SD_LEGACY_WARN, 1, SD_HKU_NO) == SD_OK);
  SD_REQUIRE(sd_mount_start(h.m) == SD_OK);
  SD_CHECK(pump_until(&h, SD_MOUNT_MOUNTED, 5000));
  pump(&h, 100);
  SD_CHECK(h.nann == 0);
  done(&h);
}

SD_TEST(mount_m2_pool_needs_noninteractive_auth)
{
  static h2 h;   /* big harness: off the stack */
  sd_mount_conn c;
  init(&h);
  fake_backend_reset();
  /* the pool member asks for the password and nothing is saved: never shown, pool_limited */
  SD_REQUIRE(create1(&h, L"pool.test", "gus", L'P', SD_LEGACY_WARN, 4, SD_HKU_ASK) == SD_OK);
  SD_REQUIRE(sd_mount_start(h.m) == SD_OK);
  SD_CHECK(pump_until(&h, SD_MOUNT_MOUNTED, 5000));
  pump(&h, 150);
  SD_CHECK(fake_backend_last_connections() == 4);
  SD_CHECK(count_kind(&h, SD_MP_PASSWORD) == 1);          /* the primary's only */
  SD_CHECK(h.nwarn == 1);
  SD_CHECK_STR(h.warn_code[0], "pool_limited");
  sd_mount_get_conn(h.m, &c);
  SD_CHECK(c.pool == 1 && c.pool_wanted == 4);
  stop(&h);
  /* with a saved password the member signs in on its own */
  store_add(&h, SD_MOUNT_SECRET_PASSWORD, "gus@pool.test:22", FAKE_PASSWORD);
  h.nprompts = 0;
  h.nwarn = 0;
  SD_REQUIRE(create1(&h, L"pool.test", "gus", L'P', SD_LEGACY_WARN, 2, SD_HKU_ASK) == SD_OK);
  SD_REQUIRE(sd_mount_start(h.m) == SD_OK);
  SD_CHECK(pump_until(&h, SD_MOUNT_MOUNTED, 5000));
  pump(&h, 150);
  SD_CHECK(h.nprompts == 0 && h.nwarn == 0);
  sd_mount_get_conn(h.m, &c);
  SD_CHECK(c.pool == 2);
  done(&h);
}
