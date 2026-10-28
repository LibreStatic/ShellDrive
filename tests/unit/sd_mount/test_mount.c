/* sd_mount state machine against the scripted fake backend (no network). */
#include <windows.h>
#include <string.h>

#include "sd_test.h"
#include "fake_backend.h"
#include "sd_base/sd_mem.h"
#include "sd_platform/sd_thread.h"
#include "sd_platform/sd_time.h"

/* ---- a tiny control-thread queue driven by the test ---- */

typedef struct qitem { struct qitem *next; void (*fn)(void *); void *arg; } qitem;

typedef struct harness {
  sd_mutex lock;
  HANDLE ev;
  qitem *head, *tail;
  sd_mount *m;
  sd_mount_state states[32];
  uint32_t nstates;
  sd_mount_prompt last_prompt;
  uint32_t nprompts, nclosed;
  /* auto answers */
  sd_mount_answer_kind hk_answer;
  const char *password;      /* NULL = do not answer */
  int answer_inline;
  /* M1 callbacks */
  uint32_t nconn, nwrite_failed, nlookups, nstores;
  wchar_t wf_path[260];
  UINT64 wf_bytes;
  char wf_status[32];
  char lookup_fp[64];
  int known_uid;             /* 0 = lookup returns nothing */
  uint32_t stored_uid;
  /* TM-R19: the token-only question (SD_MP_WEBDAV_TOKEN_ONLY) is answered with token_answer when answer_token */
  int answer_token;
  sd_mount_answer_kind token_answer;
  uint32_t ntoken_prompts;
} harness;

static void h_post(void *ctx, void (*fn)(void *), void *arg)
{
  harness *h = (harness *)ctx;
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

static void h_on_state(void *ctx, sd_mount *m, sd_mount_state st, sd_err why)
{
  harness *h = (harness *)ctx;
  SD_UNUSED(m);
  SD_UNUSED(why);
  if (h->nstates < 32) h->states[h->nstates++] = st;
}

static void h_on_prompt(void *ctx, sd_mount *m, const sd_mount_prompt *p)
{
  harness *h = (harness *)ctx;
  h->last_prompt = *p;
  h->nprompts++;
  if (p->kind == SD_MP_WEBDAV_TOKEN_ONLY) {
    h->ntoken_prompts++;
    if (h->answer_token)
      sd_mount_answer(m, p->id, h->token_answer, 0, NULL);
    return;
  }
  if (!h->answer_inline)
    return;
  if (p->kind == SD_MP_HOSTKEY) {
    sd_mount_answer(m, p->id, h->hk_answer, 0, NULL);
  } else if (h->password) {
    const char *r[1];
    r[0] = h->password;
    sd_mount_answer(m, p->id, SD_MA_RESPONSES, 1, r);
  }
}

static void h_on_closed(void *ctx, sd_mount *m, uint32_t id)
{
  harness *h = (harness *)ctx;
  SD_UNUSED(m);
  SD_UNUSED(id);
  h->nclosed++;
}

static void h_on_conn(void *ctx, sd_mount *m)
{
  SD_UNUSED(m);
  ((harness *)ctx)->nconn++;
}

static void h_on_write_failed(void *ctx, sd_mount *m, const wchar_t *path, UINT64 bytes, const char *status)
{
  harness *h = (harness *)ctx;
  SD_UNUSED(m);
  h->nwrite_failed++;
  wcsncpy_s(h->wf_path, SD_COUNTOF(h->wf_path), path, _TRUNCATE);
  h->wf_bytes = bytes;
  strncpy_s(h->wf_status, sizeof(h->wf_status), status, _TRUNCATE);
}

static int h_lookup_identity(void *ctx, sd_mount *m, const char *fp, sd_vfs_identity *out)
{
  harness *h = (harness *)ctx;
  SD_UNUSED(m);
  h->nlookups++;
  strncpy_s(h->lookup_fp, sizeof(h->lookup_fp), fp, _TRUNCATE);
  if (!h->known_uid)
    return 0;
  memset(out, 0, sizeof(*out));
  out->uid_known = out->definitive = TRUE;
  out->uid = (UINT32)h->known_uid;
  out->gid = 100;
  return 1;
}

static void h_store_identity(void *ctx, sd_mount *m, const char *fp, const sd_vfs_identity *id)
{
  harness *h = (harness *)ctx;
  SD_UNUSED(m);
  SD_UNUSED(fp);
  h->nstores++;
  h->stored_uid = id->uid;
}

static void pump(harness *h, uint32_t ms)
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

static int pump_until_final(harness *h, uint32_t ms)
{
  uint64_t end = sd_tick_ms() + ms;
  while (sd_tick_ms() < end) {
    pump(h, 20);
    if (h->m && sd_mount_is_final(h->m))
      return 1;
  }
  return 0;
}

static int pump_until_state(harness *h, sd_mount_state st, uint32_t ms)
{
  uint64_t end = sd_tick_ms() + ms;
  while (sd_tick_ms() < end) {
    pump(h, 20);
    if (h->m && sd_mount_get_state(h->m) == st)
      return 1;
  }
  return 0;
}

static void h_init(harness *h)
{
  memset(h, 0, sizeof(*h));
  sd_mutex_init(&h->lock);
  h->ev = CreateEventW(NULL, FALSE, FALSE, NULL);
  h->answer_inline = 1;
  h->hk_answer = SD_MA_HOSTKEY_TRUST;
  h->password = FAKE_PASSWORD;
}

static void h_free(harness *h)
{
  pump(h, 50);
  CloseHandle(h->ev);
  sd_mutex_destroy(&h->lock);
}

/* M3: the next h_create_b makes a test-only mount (profile.test) when set */
static int h_test_only;
/* the next h_create_b makes a hostkey mount (params.hostkey_fetch: no drive, letter 0 allowed) when set */
static int h_hostkey_fetch;
/* TM-R19: the next h_create_b asks for token-only (params.token_only / token_only_confirmed) */
static int h_token_only, h_token_confirmed;

static sd_err h_create_b(harness *h, const wchar_t *host, const wchar_t *identity, wchar_t letter, int backend)
{
  sd_mount_params p;
  sd_mount_callbacks cb;
  memset(&p, 0, sizeof(p));
  p.struct_size = sizeof(p);
  p.host = host;
  p.user = "alice";
  p.identity_path = identity;
  p.letter = letter;
  p.remote_path = "/srv/data";
  p.backend = backend;
  p.test_only = h_test_only;
  p.hostkey_fetch = h_hostkey_fetch;
  p.token_only = h_token_only;
  p.token_only_confirmed = h_token_confirmed;
  memset(&cb, 0, sizeof(cb));
  cb.ctx = h;
  cb.post = h_post;
  cb.on_state = h_on_state;
  cb.on_prompt = h_on_prompt;
  cb.on_prompt_closed = h_on_closed;
  cb.on_conn = h_on_conn;
  cb.on_write_failed = h_on_write_failed;
  cb.lookup_identity = h_lookup_identity;
  cb.store_identity = h_store_identity;
  p.disk_cache_dir = L"C:\\fake\\cache\\0123456789abcdef";
  p.disk_cache_mb = 64;
  p.offline_wait_ms = 1500;
  p.reconnect_grace_ms = 30000;
  return sd_mount_create(h_hostkey_fetch ? fake_backend_hostkeys() : fake_backend(), &p, &cb, &h->m);
}

static sd_err h_create(harness *h, const wchar_t *host, const wchar_t *identity, wchar_t letter)
{
  return h_create_b(h, host, identity, letter, SD_MOUNT_BACKEND_AUTO);
}

SD_TEST(mount_tofu_password_mount_unmount)
{
  harness h;
  h_init(&h);
  fake_backend_reset();
  SD_REQUIRE(h_create(&h, L"good.test", NULL, L'Q') == SD_OK);
  SD_REQUIRE(sd_mount_start(h.m) == SD_OK);
  SD_CHECK(pump_until_state(&h, SD_MOUNT_MOUNTED, 5000));
  SD_CHECK(fake_backend_letter_mounted(L'Q'));
  SD_CHECK(fake_backend_is_trusted("good.test"));
  SD_CHECK_STR(fake_backend_last_remote_root(), "/srv/data");
  SD_CHECK_EQ_INT(h.nprompts, 2);                 /* hostkey + password */
  SD_CHECK(h.nstates >= 3);
  SD_CHECK_EQ_INT(h.states[0], SD_MOUNT_CONNECTING);
  SD_CHECK(sd_mount_stop(h.m) == SD_OK);
  SD_CHECK(pump_until_final(&h, 5000));
  SD_CHECK_EQ_INT(sd_mount_get_state(h.m), SD_MOUNT_UNMOUNTED);
  SD_CHECK(!fake_backend_letter_mounted(L'Q'));
  sd_mount_destroy(h.m);
  h_free(&h);
  SD_CHECK_EQ_INT(fake_backend_live_sessions(), 0);
}

SD_TEST(mount_second_connection_skips_tofu)
{
  harness h;
  h_init(&h);
  fake_backend_reset();
  SD_REQUIRE(h_create(&h, L"again.test", NULL, L'R') == SD_OK);
  SD_REQUIRE(sd_mount_start(h.m) == SD_OK);
  SD_REQUIRE(pump_until_state(&h, SD_MOUNT_MOUNTED, 5000));
  sd_mount_stop(h.m);
  SD_REQUIRE(pump_until_final(&h, 5000));
  sd_mount_destroy(h.m);
  h_free(&h);

  h_init(&h);
  SD_REQUIRE(h_create(&h, L"again.test", NULL, L'R') == SD_OK);
  SD_REQUIRE(sd_mount_start(h.m) == SD_OK);
  SD_CHECK(pump_until_state(&h, SD_MOUNT_MOUNTED, 5000));
  SD_CHECK_EQ_INT(h.nprompts, 1);                 /* password only */
  SD_CHECK_EQ_INT(h.last_prompt.kind, SD_MP_PASSWORD);
  sd_mount_stop(h.m);
  SD_CHECK(pump_until_final(&h, 5000));
  sd_mount_destroy(h.m);
  h_free(&h);
}

SD_TEST(mount_hostkey_rejected_fails)
{
  harness h;
  sd_mount_failure f;
  h_init(&h);
  fake_backend_reset();
  h.hk_answer = SD_MA_REJECT;
  SD_REQUIRE(h_create(&h, L"reject.test", NULL, L'S') == SD_OK);
  SD_REQUIRE(sd_mount_start(h.m) == SD_OK);
  SD_CHECK(pump_until_final(&h, 5000));
  SD_CHECK_EQ_INT(sd_mount_get_state(h.m), SD_MOUNT_FAILED);
  sd_mount_get_failure(h.m, &f);
  SD_CHECK_EQ_INT(f.err, SD_E_HOSTKEY_REJECTED);
  SD_CHECK(!fake_backend_is_trusted("reject.test"));
  SD_CHECK(!fake_backend_letter_mounted(L'S'));
  sd_mount_destroy(h.m);
  h_free(&h);
}

SD_TEST(mount_hostkey_once_is_not_stored)
{
  harness h;
  h_init(&h);
  fake_backend_reset();
  h.hk_answer = SD_MA_HOSTKEY_ONCE;
  SD_REQUIRE(h_create(&h, L"once.test", NULL, L'S') == SD_OK);
  SD_REQUIRE(sd_mount_start(h.m) == SD_OK);
  SD_CHECK(pump_until_state(&h, SD_MOUNT_MOUNTED, 5000));
  SD_CHECK(!fake_backend_is_trusted("once.test"));
  sd_mount_stop(h.m);
  SD_CHECK(pump_until_final(&h, 5000));
  sd_mount_destroy(h.m);
  h_free(&h);
}

SD_TEST(mount_mismatch_is_hard_failure_with_details)
{
  harness h;
  sd_mount_failure f;
  h_init(&h);
  fake_backend_reset();
  SD_REQUIRE(h_create(&h, L"mismatch.test", NULL, L'T') == SD_OK);
  SD_REQUIRE(sd_mount_start(h.m) == SD_OK);
  SD_CHECK(pump_until_final(&h, 5000));
  SD_CHECK_EQ_INT(sd_mount_get_state(h.m), SD_MOUNT_FAILED);
  SD_CHECK_EQ_INT(h.nprompts, 0);                 /* never a prompt */
  sd_mount_get_failure(h.m, &f);
  SD_CHECK_EQ_INT(f.err, SD_E_HOSTKEY_MISMATCH);
  SD_CHECK_STR(f.offered_fp, FAKE_FP);
  SD_CHECK_STR(f.stored_type, "ssh-ed25519");
  SD_CHECK_EQ_INT(f.store_line, 3);
  SD_CHECK_STR(f.lookup_name, "mismatch.test");
  SD_CHECK_EQ_INT(f.has_store_kind, 1);           /* the old key's store kind (03 §5.4) */
  SD_CHECK_EQ_INT(f.store_kind, SD_KH_STORE_USER);
  sd_mount_destroy(h.m);
  h_free(&h);
}

/* host_key_type_unavailable (03 §5.2, TM-R04): the stored types and the offered key reach the failure record;
   no store kind (there is no old key). */
SD_TEST(mount_type_unavailable_details)
{
  harness h;
  sd_mount_failure f;
  h_init(&h);
  fake_backend_reset();
  SD_REQUIRE(h_create(&h, L"typeunavail.test", NULL, L'U') == SD_OK);
  SD_REQUIRE(sd_mount_start(h.m) == SD_OK);
  SD_CHECK(pump_until_final(&h, 5000));
  SD_CHECK_EQ_INT(sd_mount_get_state(h.m), SD_MOUNT_FAILED);
  SD_CHECK_EQ_INT(h.nprompts, 0);                 /* never a prompt (TM-R04) */
  sd_mount_get_failure(h.m, &f);
  SD_CHECK_EQ_INT(f.err, SD_E_HOSTKEY_TYPE_UNAVAILABLE);
  SD_CHECK_STR(f.lookup_name, "typeunavail.test");
  SD_CHECK_STR(f.stored_types, "ssh-rsa,ecdsa-sha2-nistp256");
  SD_CHECK_STR(f.offered_types, "ssh-ed25519");
  SD_CHECK_STR(f.offered_type, "ssh-ed25519");
  SD_CHECK_STR(f.offered_fp, FAKE_FP);
  SD_CHECK_EQ_INT(f.has_store_kind, 0);
  sd_mount_destroy(h.m);
  h_free(&h);
}

SD_TEST(mount_wrong_password_fails_auth)
{
  harness h;
  sd_mount_failure f;
  h_init(&h);
  fake_backend_reset();
  h.password = "wrong";
  SD_REQUIRE(h_create(&h, L"pw.test", NULL, L'U') == SD_OK);
  SD_REQUIRE(sd_mount_start(h.m) == SD_OK);
  SD_CHECK(pump_until_final(&h, 5000));
  sd_mount_get_failure(h.m, &f);
  SD_CHECK_EQ_INT(f.err, SD_E_AUTH_FAILED);
  SD_CHECK_EQ_INT(h.last_prompt.round, 1);
  sd_mount_destroy(h.m);
  h_free(&h);
}

SD_TEST(mount_passphrase_and_identity)
{
  harness h;
  h_init(&h);
  fake_backend_reset();
  h.password = FAKE_PASSPHRASE;
  SD_REQUIRE(h_create(&h, L"key.test", L"C:\\keys\\encrypted_ed25519", L'V') == SD_OK);
  SD_REQUIRE(sd_mount_start(h.m) == SD_OK);
  SD_CHECK(pump_until_state(&h, SD_MOUNT_MOUNTED, 5000));
  SD_CHECK_EQ_INT(h.last_prompt.kind, SD_MP_PASSPHRASE);
  SD_CHECK(strstr(h.last_prompt.key_path, "encrypted") != NULL);
  sd_mount_stop(h.m);
  SD_CHECK(pump_until_final(&h, 5000));
  sd_mount_destroy(h.m);
  h_free(&h);
}

SD_TEST(mount_unreachable_and_no_dokany)
{
  harness h;
  sd_mount_failure f;
  h_init(&h);
  fake_backend_reset();
  SD_REQUIRE(h_create(&h, L"unreachable.test", NULL, L'W') == SD_OK);
  SD_REQUIRE(sd_mount_start(h.m) == SD_OK);
  SD_CHECK(pump_until_final(&h, 5000));
  sd_mount_get_failure(h.m, &f);
  SD_CHECK_EQ_INT(f.err, SD_E_CONN_REFUSED);
  sd_mount_destroy(h.m);
  h_free(&h);

  h_init(&h);
  SD_REQUIRE(h_create(&h, L"nodokany.test", L"C:\\keys\\id_ed25519", L'W') == SD_OK);
  SD_REQUIRE(sd_mount_start(h.m) == SD_OK);
  SD_CHECK(pump_until_final(&h, 5000));
  SD_CHECK_EQ_INT(sd_mount_get_state(h.m), SD_MOUNT_FAILED);
  sd_mount_get_failure(h.m, &f);
  SD_CHECK(f.code != NULL && strcmp(f.code, "backend_unavailable") == 0);
  sd_mount_destroy(h.m);
  h_free(&h);
}

SD_TEST(mount_stop_while_prompting)
{
  harness h;
  h_init(&h);
  fake_backend_reset();
  h.answer_inline = 0;                            /* leave the TOFU prompt open */
  SD_REQUIRE(h_create(&h, L"pending.test", NULL, L'X') == SD_OK);
  SD_REQUIRE(sd_mount_start(h.m) == SD_OK);
  pump(&h, 300);
  SD_CHECK_EQ_INT(h.nprompts, 1);
  SD_CHECK(sd_mount_stop(h.m) == SD_OK);
  SD_CHECK(pump_until_final(&h, 5000));
  SD_CHECK_EQ_INT(sd_mount_get_state(h.m), SD_MOUNT_UNMOUNTED);
  SD_CHECK(h.nclosed >= 1);
  /* the prompt is gone: a late answer is refused */
  SD_CHECK(sd_mount_answer(h.m, h.last_prompt.id, SD_MA_HOSTKEY_TRUST, 0, NULL) == SD_E_NOT_FOUND);
  sd_mount_destroy(h.m);
  h_free(&h);
  SD_CHECK(!fake_backend_is_trusted("pending.test"));
}

SD_TEST(mount_rejects_bad_params_and_names)
{
  harness h;
  sd_mount_params p;
  sd_mount_callbacks cb;
  sd_mount *m = NULL;
  h_init(&h);
  memset(&p, 0, sizeof(p));
  memset(&cb, 0, sizeof(cb));
  cb.post = h_post;
  cb.ctx = &h;
  p.struct_size = sizeof(p);
  p.host = L"x.test";
  p.user = "u";
  p.letter = L'1';
  SD_CHECK(sd_mount_create(fake_backend(), &p, &cb, &m) == SD_E_INVALID_PARAM);
  p.letter = L'Z';
  p.user = NULL;
  SD_CHECK(sd_mount_create(fake_backend(), &p, &cb, &m) == SD_E_INVALID_PARAM);
  SD_CHECK_STR(sd_mount_state_name(SD_MOUNT_AUTH_REQUIRED), "auth_required");
  SD_CHECK_STR(sd_mount_state_name(SD_MOUNT_UNMOUNTED), "unmounted");
  SD_CHECK_STR(sd_mount_prompt_kind_name(SD_MP_HOSTKEY), "hostkey_unknown");
  SD_CHECK_STR(sd_mount_prompt_kind_name(SD_MP_WEBDAV_TOKEN_ONLY), "webdav_token_only");
  h_free(&h);
}

/* 02 §10.1 backend selection with the WebDAV backend (M1). */
static void run_backend_case(sd_test_ctx *sd_t_, const wchar_t *host, int backend, sd_mount_state want,
                             const char *want_code, sd_mount_backend_kind want_used)
{
  harness h;
  sd_mount_failure f;
  h_init(&h);
  SD_REQUIRE(h_create_b(&h, host, L"C:\\keys\\id_ed25519", L'V', backend) == SD_OK);
  SD_REQUIRE(sd_mount_start(h.m) == SD_OK);
  if (want == SD_MOUNT_MOUNTED) {
    SD_CHECK(pump_until_state(&h, SD_MOUNT_MOUNTED, 5000));
    SD_CHECK_EQ_INT(sd_mount_backend_kind_used(h.m), want_used);
    SD_CHECK(fake_backend_letter_mounted(L'V'));
    SD_CHECK(sd_mount_stop(h.m) == SD_OK);
    SD_CHECK(pump_until_final(&h, 5000));
    SD_CHECK(!fake_backend_letter_mounted(L'V'));
  } else {
    SD_CHECK(pump_until_final(&h, 5000));
    SD_CHECK_EQ_INT(sd_mount_get_state(h.m), SD_MOUNT_FAILED);
    sd_mount_get_failure(h.m, &f);
    SD_CHECK(f.code != NULL && strcmp(f.code, want_code) == 0);
  }
  sd_mount_destroy(h.m);
  h_free(&h);
}

/* M1 regression: a lost connection used to stay OFFLINE for good (reconnect disabled, and a second
   READY would have mounted the backend again). Now the drive stays, the mount goes OFFLINE and comes
   back to MOUNTED on the next generation without a second vfs/Dokany mount. */
SD_TEST(mount_reconnect_keeps_drive)
{
  harness h;
  sd_mount_conn c;
  uint32_t i, saw_offline = 0;
  h_init(&h);
  fake_backend_reset();
  SD_REQUIRE(h_create(&h, L"flaky.test", L"C:\\keys\\id_ed25519", L'R') == SD_OK);
  SD_REQUIRE(sd_mount_start(h.m) == SD_OK);
  SD_CHECK(pump_until_state(&h, SD_MOUNT_MOUNTED, 5000));
  /* options handed down */
  SD_CHECK_EQ_INT(fake_backend_budget_calls(), 1);
  SD_CHECK_EQ_INT(fake_backend_last_reconnect_enabled(), 1);
  SD_CHECK_EQ_INT(fake_backend_last_channels(), 2);
  SD_CHECK_EQ_INT(fake_backend_last_secret_cache(), 1);
  SD_CHECK_EQ_INT(fake_backend_last_offline_wait(), 1500);
  SD_CHECK_EQ_INT(fake_backend_last_grace(), 30000);
  SD_CHECK_EQ_INT(fake_backend_last_disk_mb(), 64);
  SD_CHECK(wcscmp(fake_backend_last_disk_dir(), L"C:\\fake\\cache\\0123456789abcdef") == 0);
  SD_CHECK_EQ_INT(h.nlookups, 1);
  SD_CHECK_STR(h.lookup_fp, FAKE_FP);
  sd_mount_get_conn(h.m, &c);
  SD_CHECK_EQ_INT(c.session, SD_SFTP_ST_READY);
  SD_CHECK_EQ_INT(c.generation, 1);
  /* drop and reconnect */
  h.nstates = 0;
  fake_backend_drop(0);
  pump(&h, 300);
  SD_CHECK(pump_until_state(&h, SD_MOUNT_MOUNTED, 5000));
  for (i = 0; i < h.nstates; i++)
    if (h.states[i] == SD_MOUNT_OFFLINE) saw_offline = 1;
  SD_CHECK(saw_offline);
  SD_CHECK(h.nconn >= 2);
  SD_CHECK(fake_backend_letter_mounted(L'R'));
  SD_CHECK_EQ_INT(fake_backend_dokan_starts(), 1);
  SD_CHECK_EQ_INT(fake_backend_vfs_mounts(), 1);
  sd_mount_get_conn(h.m, &c);
  SD_CHECK_EQ_INT(c.session, SD_SFTP_ST_READY);
  SD_CHECK_EQ_INT(c.generation, 2);
  SD_CHECK_EQ_INT(c.reconnects, 1);
  SD_CHECK_EQ_INT(c.offline_since_ms, 0);
  /* a permanent failure after READY keeps the drive offline until the user unmounts */
  fake_backend_drop(1);
  SD_CHECK(pump_until_state(&h, SD_MOUNT_OFFLINE, 5000));
  pump(&h, 200);
  SD_CHECK_EQ_INT(sd_mount_get_state(h.m), SD_MOUNT_OFFLINE);
  SD_CHECK(fake_backend_letter_mounted(L'R'));
  sd_mount_get_conn(h.m, &c);
  SD_CHECK_EQ_INT(c.session, SD_SFTP_ST_FAILED);
  SD_CHECK(c.offline_since_ms != 0);
  SD_CHECK(sd_mount_stop(h.m) == SD_OK);
  SD_CHECK(pump_until_final(&h, 5000));
  SD_CHECK_EQ_INT(sd_mount_get_state(h.m), SD_MOUNT_UNMOUNTED);
  SD_CHECK(!fake_backend_letter_mounted(L'R'));
  sd_mount_destroy(h.m);
  h_free(&h);
  SD_CHECK_EQ_INT(fake_backend_live_sessions(), 0);
}

/* M1: vfs WRITE_FAILED reaches the host on the control thread with the path; IDENTITY is stored and a
   cached identity is handed to the vfs on the next mount. */
SD_TEST(mount_write_failed_and_identity)
{
  harness h;
  sd_mount_conn c;
  uint32_t uid = 0;
  h_init(&h);
  fake_backend_reset();
  SD_REQUIRE(h_create(&h, L"good-wf.test", L"C:\\keys\\id_ed25519", L'S') == SD_OK);
  SD_REQUIRE(sd_mount_start(h.m) == SD_OK);
  SD_CHECK(pump_until_state(&h, SD_MOUNT_MOUNTED, 5000));
  SD_CHECK(!fake_backend_last_known_uid(&uid));
  fake_backend_vfs_write_failed(L"\\docs\\report.txt", 4096);
  fake_backend_vfs_identity(1000, 1000);
  pump(&h, 200);
  SD_CHECK_EQ_INT(h.nwrite_failed, 1);
  SD_CHECK(wcscmp(h.wf_path, L"\\docs\\report.txt") == 0);
  SD_CHECK_EQ_INT((int)h.wf_bytes, 4096);
  SD_CHECK_STR(h.wf_status, "disconnected");
  sd_mount_get_conn(h.m, &c);
  SD_CHECK_EQ_INT(c.write_failed, 1);
  SD_CHECK(wcscmp(c.last_write_failed, L"\\docs\\report.txt") == 0);
  SD_CHECK_EQ_INT(h.nstores, 1);
  SD_CHECK_EQ_INT(h.stored_uid, 1000);
  SD_CHECK(sd_mount_stop(h.m) == SD_OK);
  SD_CHECK(pump_until_final(&h, 5000));
  sd_mount_destroy(h.m);
  h_free(&h);
  /* next mount: the host returns the cached identity */
  h_init(&h);
  h.known_uid = 1000;
  SD_REQUIRE(h_create(&h, L"good-wf.test", L"C:\\keys\\id_ed25519", L'S') == SD_OK);
  SD_REQUIRE(sd_mount_start(h.m) == SD_OK);
  SD_CHECK(pump_until_state(&h, SD_MOUNT_MOUNTED, 5000));
  SD_CHECK(fake_backend_last_known_uid(&uid));
  SD_CHECK_EQ_INT(uid, 1000);
  SD_CHECK(sd_mount_stop(h.m) == SD_OK);
  SD_CHECK(pump_until_final(&h, 5000));
  sd_mount_destroy(h.m);
  h_free(&h);
}

SD_TEST(mount_backend_selection)
{
  sd_mount_backend_kind k;
  fake_backend_reset();
  /* auto with Dokany: Dokany, and WebClient is never started (TM-R21) */
  fake_backend_set_webclient(SD_WD_CLIENT_STOPPED, 1);
  run_backend_case(sd_t_, L"good-auto.test", SD_MOUNT_BACKEND_AUTO, SD_MOUNT_MOUNTED, NULL, SD_MOUNT_BACKEND_DOKANY);
  SD_CHECK_EQ_INT(fake_backend_webclient_starts(), 0);
  SD_CHECK_EQ_INT(fake_backend_last_request_timeout(), 25000);
  /* auto without Dokany: WebDAV (started on demand), 50 s request deadline */
  run_backend_case(sd_t_, L"nodokany-auto.test", SD_MOUNT_BACKEND_AUTO, SD_MOUNT_MOUNTED, NULL, SD_MOUNT_BACKEND_WEBDAV);
  SD_CHECK_EQ_INT(fake_backend_webclient_starts(), 1);
  SD_CHECK_EQ_INT(fake_backend_webdav_mounts(), 1);
  SD_CHECK_EQ_INT(fake_backend_last_request_timeout(), 50000);
  /* forced webdav even though Dokany is fine */
  run_backend_case(sd_t_, L"good-webdav.test", SD_MOUNT_BACKEND_WEBDAV, SD_MOUNT_MOUNTED, NULL, SD_MOUNT_BACKEND_WEBDAV);
  /* forced dokany without Dokany: no fallback */
  run_backend_case(sd_t_, L"nodokany-forced.test", SD_MOUNT_BACKEND_DOKANY, SD_MOUNT_FAILED, "backend_unavailable",
                   SD_MOUNT_BACKEND_DOKANY);
  /* WebClient disabled / missing / not startable */
  fake_backend_set_webclient(SD_WD_CLIENT_DISABLED, 1);
  run_backend_case(sd_t_, L"nodokany-dis.test", SD_MOUNT_BACKEND_AUTO, SD_MOUNT_FAILED, "webclient_disabled",
                   SD_MOUNT_BACKEND_AUTO);
  fake_backend_set_webclient(SD_WD_CLIENT_MISSING, 1);
  run_backend_case(sd_t_, L"good-missing.test", SD_MOUNT_BACKEND_WEBDAV, SD_MOUNT_FAILED, "backend_unavailable",
                   SD_MOUNT_BACKEND_WEBDAV);
  fake_backend_set_webclient(SD_WD_CLIENT_STOPPED, 0);
  run_backend_case(sd_t_, L"good-admin.test", SD_MOUNT_BACKEND_WEBDAV, SD_MOUNT_FAILED, "backend_unavailable",
                   SD_MOUNT_BACKEND_WEBDAV);
  /* names */
  SD_CHECK_STR(sd_mount_backend_kind_name(SD_MOUNT_BACKEND_WEBDAV), "webdav");
  SD_CHECK(sd_mount_backend_kind_parse("dokany", &k) && k == SD_MOUNT_BACKEND_DOKANY);
  SD_CHECK(!sd_mount_backend_kind_parse("smb", &k));
}

/* M3 (sd_mount): profile.test (connect, authenticate, realpath; no vfs), refresh, cache clear with queued
   write-behind data, stats, attach info and the forced stop. */
SD_TEST(mount_m3_test_only_probe)
{
  harness h;
  sd_mount_probe p;
  uint32_t vfs0;
  fake_backend_reset();
  vfs0 = fake_backend_vfs_mounts();
  h_init(&h);
  h_test_only = 1;
  SD_REQUIRE(h_create(&h, L"probe.test", NULL, L'Z') == SD_OK);
  h_test_only = 0;
  SD_REQUIRE(sd_mount_start(h.m) == SD_OK);
  SD_CHECK(pump_until_final(&h, 5000));
  SD_CHECK_EQ_INT(sd_mount_get_state(h.m), SD_MOUNT_UNMOUNTED);
  /* the result: realpath of the remote path, the negotiated summary and the host-key fingerprint */
  SD_REQUIRE(sd_mount_get_probe(h.m, &p) == 1);
  SD_CHECK_STR(p.remote_real, "/srv/data");
  SD_CHECK_STR(p.kex, "curve25519-sha256");
  SD_CHECK_STR(p.hostkey, "ssh-ed25519");
  SD_CHECK_STR(p.hostkey_fp, FAKE_FP);
  SD_CHECK_STR(p.server_version, "FakeSSH_1.0");
  SD_CHECK(p.legacy == 0);
  /* no drive, no vfs, no backend: the test left nothing mapped */
  SD_CHECK_EQ_U64(fake_backend_vfs_mounts(), vfs0);
  SD_CHECK(!fake_backend_letter_mounted(L'Z'));
  /* the mount is over: refresh and cache clear find no file system */
  SD_CHECK(sd_mount_refresh(h.m, NULL) == SD_E_NOT_FOUND);
  SD_CHECK(sd_mount_cache_clear(h.m, 1, 0) == SD_E_NOT_FOUND);
  sd_mount_destroy(h.m);
  h_free(&h);
  SD_CHECK_EQ_INT(fake_backend_live_sessions(), 0);

  /* a realpath failure fails the test (FAILED), and no result is reported */
  h_init(&h);
  h_test_only = 1;
  SD_REQUIRE(h_create(&h, L"probefail.test", NULL, L'Z') == SD_OK);
  h_test_only = 0;
  SD_REQUIRE(sd_mount_start(h.m) == SD_OK);
  SD_CHECK(pump_until_final(&h, 5000));
  SD_CHECK_EQ_INT(sd_mount_get_state(h.m), SD_MOUNT_FAILED);
  SD_CHECK(sd_mount_get_probe(h.m, &p) == 0);
  sd_mount_destroy(h.m);
  h_free(&h);
}

SD_TEST(mount_hostkey_fetch_has_no_drive_letter)
{
  harness h;
  sd_mount_attach a;
  uint32_t vfs0;
  fake_backend_reset();
  vfs0 = fake_backend_vfs_mounts();
  h_init(&h);
  h.hk_answer = SD_MA_HOSTKEY_ONCE;
  /* a hostkey mount (params.hostkey_fetch) is created with letter 0: it never maps a drive */
  h_hostkey_fetch = 1;
  SD_REQUIRE(h_create(&h, L"hk.test", NULL, 0) == SD_OK);
  h_hostkey_fetch = 0;
  SD_CHECK(sd_mount_letter(h.m) == 0);
  SD_REQUIRE(sd_mount_start(h.m) == SD_OK);
  SD_CHECK(pump_until_final(&h, 5000));
  SD_CHECK_EQ_INT(sd_mount_get_state(h.m), SD_MOUNT_UNMOUNTED);
  sd_mount_get_attach(h.m, &a);
  SD_CHECK(a.letter == 0 && !a.mounted);
  SD_CHECK_EQ_U64(fake_backend_vfs_mounts(), vfs0);
  SD_CHECK(!fake_backend_letter_mounted(L'Z'));
  sd_mount_destroy(h.m);
  h_free(&h);
  /* any other mount still needs a drive letter, and a letter outside A..Z is refused for every mount */
  h_init(&h);
  SD_CHECK(h_create(&h, L"nodrive.test", NULL, 0) == SD_E_INVALID_PARAM);
  h_free(&h);
  h_init(&h);
  h_hostkey_fetch = 1;
  SD_CHECK(h_create(&h, L"badletter.test", NULL, L'1') == SD_E_INVALID_PARAM);
  h_hostkey_fetch = 0;
  h_free(&h);
}

SD_TEST(mount_m3_refresh_stats_cache_and_stop)
{
  harness h;
  sd_mount_stats st;
  sd_mount_attach a;
  int disk = -1;
  fake_backend_reset();
  h_init(&h);
  SD_REQUIRE(h_create(&h, L"m3.test", NULL, L'Q') == SD_OK);
  SD_REQUIRE(sd_mount_start(h.m) == SD_OK);
  SD_REQUIRE(pump_until_state(&h, SD_MOUNT_MOUNTED, 5000));

  /* refresh: a subtree, then the whole mount */
  SD_CHECK(sd_mount_refresh(h.m, L"dir") == SD_OK);
  SD_CHECK(sd_mount_refresh(h.m, NULL) == SD_OK);
  SD_CHECK_EQ_INT(fake_backend_refresh_calls(), 2);

  /* stats of a mounted mount: session, pool member and cache counters */
  memset(&st, 0, sizeof(st));
  sd_mount_get_stats(h.m, &st);
  SD_CHECK(st.has_session == 1 && st.has_vfs == 1);
  SD_CHECK_EQ_INT(st.srtt_ms, 12);
  SD_CHECK_EQ_INT(st.members, 1);
  SD_CHECK(st.member[0].ready == 1);
  SD_CHECK_EQ_U64(st.cache_hits, 7);
  SD_CHECK_EQ_U64(st.wb_bytes, 0);

  /* attach info: the backend in use, the drive and no WebDAV port on Dokany */
  memset(&a, 0, sizeof(a));
  sd_mount_get_attach(h.m, &a);
  SD_CHECK(a.backend == SD_MOUNT_BACKEND_DOKANY);
  SD_CHECK(a.mounted == 1 && a.letter == L'Q');
  SD_CHECK_EQ_INT(a.webdav_port, 0);

  /* cache clear: plain, then refused while write-behind data is queued (kept), then forced */
  SD_CHECK(sd_mount_cache_clear(h.m, 1, 0) == SD_OK);
  SD_CHECK_EQ_INT(fake_backend_cache_clears(&disk), 1);
  SD_CHECK_EQ_INT(disk, 1);
  fake_backend_set_wb_dirty(4096);
  SD_CHECK(sd_mount_cache_clear(h.m, 1, 0) == SD_E_BUSY);
  SD_CHECK_EQ_INT(fake_backend_cache_clears(NULL), 1);
  SD_CHECK(sd_mount_cache_clear(h.m, 0, 1) == SD_OK);
  SD_CHECK_EQ_INT(fake_backend_cache_clears(&disk), 2);
  SD_CHECK_EQ_INT(disk, 0);
  memset(&st, 0, sizeof(st));
  sd_mount_get_stats(h.m, &st);
  SD_CHECK_EQ_U64(st.wb_bytes, 4096);
  fake_backend_set_wb_dirty(0);

  /* a forced stop gives the drain no budget; the normal stop waits its 10 s */
  SD_CHECK(sd_mount_stop_ex(h.m, 1) == SD_OK);
  SD_CHECK(pump_until_final(&h, 5000));
  SD_CHECK_EQ_INT(fake_backend_last_quiesce_budget(), 0);
  sd_mount_destroy(h.m);
  h_free(&h);

  h_init(&h);
  SD_REQUIRE(h_create(&h, L"m3b.test", NULL, L'R') == SD_OK);
  SD_REQUIRE(sd_mount_start(h.m) == SD_OK);
  SD_REQUIRE(pump_until_state(&h, SD_MOUNT_MOUNTED, 5000));
  SD_CHECK(sd_mount_stop(h.m) == SD_OK);
  SD_CHECK(pump_until_final(&h, 5000));
  SD_CHECK_EQ_INT(fake_backend_last_quiesce_budget(), 10000);
  sd_mount_destroy(h.m);
  h_free(&h);
}

/* ---- TM-R19 token-only WebDAV (02 §7.4, 03 §7.5): plumbing and the consent answers ---- */

/* The params reach the WebDAV cfg (confirmed by the host), and no question is asked. */
SD_TEST(mount_token_only_params_reach_webdav_cfg)
{
  harness h;
  h_init(&h);
  fake_backend_reset();
  fake_backend_set_webclient(SD_WD_CLIENT_STOPPED, 1);
  h_token_only = 1;
  h_token_confirmed = 1;
  SD_REQUIRE(h_create_b(&h, L"good-webdav.test", L"C:\\keys\\id_ed25519", L'Y', SD_MOUNT_BACKEND_WEBDAV) == SD_OK);
  h_token_only = 0;
  h_token_confirmed = 0;
  SD_REQUIRE(sd_mount_start(h.m) == SD_OK);
  SD_CHECK(pump_until_state(&h, SD_MOUNT_MOUNTED, 5000));
  SD_CHECK_EQ_INT(fake_backend_last_webdav_token_only(), 1);
  SD_CHECK_EQ_INT(fake_backend_last_webdav_confirmed(), 1);
  SD_CHECK_EQ_INT(h.ntoken_prompts, 0);
  SD_CHECK(sd_mount_stop(h.m) == SD_OK);
  SD_CHECK(pump_until_final(&h, 5000));
  sd_mount_destroy(h.m);
  h_free(&h);
}

/* A global (service) mount never takes token-only: refused at create, and the plain global mount is fine. */
SD_TEST(mount_token_only_refused_for_global)
{
  harness h;
  sd_mount_params p;
  sd_mount_callbacks cb;
  sd_mount *m = NULL;
  static const unsigned char sd_bytes[4] = { 1, 0, 4, 0 };
  /* S-1-5-32-545 (BUILTIN\Users): the service_access list a global mount needs (M5) */
  static const unsigned char users_sid[] = { 1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 33, 2, 0, 0 };
  void *access_sids[1];
  access_sids[0] = (void *)users_sid;
  h_init(&h);
  fake_backend_reset();
  fake_backend_set_webclient(SD_WD_CLIENT_STOPPED, 1);
  memset(&p, 0, sizeof(p));
  p.struct_size = sizeof(p);
  p.host = L"good-webdav.test";
  p.user = "alice";
  p.identity_path = L"C:\\keys\\id_ed25519";
  p.letter = L'Y';
  p.remote_path = "/srv/data";
  p.backend = SD_MOUNT_BACKEND_WEBDAV;
  p.global_mount = 1;
  p.volume_sd = sd_bytes;
  p.volume_sd_len = sizeof(sd_bytes);
  p.access_sids = access_sids;
  p.n_access = 1;
  p.token_only = 1;
  p.token_only_confirmed = 1;
  memset(&cb, 0, sizeof(cb));
  cb.ctx = &h;
  cb.post = h_post;
  SD_CHECK(sd_mount_create(fake_backend(), &p, &cb, &m) == SD_E_INVALID_PARAM);
  SD_CHECK(m == NULL);
  p.token_only = 0;
  p.token_only_confirmed = 0;
  SD_CHECK(sd_mount_create(fake_backend(), &p, &cb, &m) == SD_OK);
  if (m) sd_mount_destroy(m);
  h_free(&h);
}

/* The no-SSPI question: accept (SD_MA_HOSTKEY_TRUST or _ONCE) continues with token-only for this enable. */
static void token_consent_accept_case(sd_test_ctx *sd_t_, sd_mount_answer_kind answer)
{
  harness h;
  h_init(&h);
  fake_backend_reset();
  fake_backend_set_webclient(SD_WD_CLIENT_STOPPED, 1);
  fake_backend_set_webdav_noauth(1);
  h.answer_inline = 1;
  h.hk_answer = SD_MA_HOSTKEY_TRUST;
  h.password = "pw";
  h.answer_token = 1;
  h.token_answer = answer;
  h_token_only = 0;
  h_token_confirmed = 0;
  SD_REQUIRE(h_create_b(&h, L"good-webdav.test", L"C:\\keys\\id_ed25519", L'Y', SD_MOUNT_BACKEND_WEBDAV) == SD_OK);
  SD_REQUIRE(sd_mount_start(h.m) == SD_OK);
  SD_CHECK(pump_until_state(&h, SD_MOUNT_MOUNTED, 5000));
  SD_CHECK_EQ_INT(h.ntoken_prompts, 1);
  SD_CHECK_EQ_INT(fake_backend_webdav_calls(), 2);            /* refused without SSPI, then token-only */
  SD_CHECK_EQ_INT(fake_backend_last_webdav_token_only(), 1);
  SD_CHECK_EQ_INT(fake_backend_last_webdav_confirmed(), 1);
  SD_CHECK(sd_mount_stop(h.m) == SD_OK);
  SD_CHECK(pump_until_final(&h, 5000));
  sd_mount_destroy(h.m);
  h_free(&h);
  fake_backend_set_webdav_noauth(0);
}

SD_TEST(mount_token_consent_accept_and_once)
{
  token_consent_accept_case(sd_t_, SD_MA_HOSTKEY_TRUST);
  token_consent_accept_case(sd_t_, SD_MA_HOSTKEY_ONCE);
}

/* Reject: the mount fails with token_only_refused and no token-only mount is started. */
SD_TEST(mount_token_consent_reject_fails)
{
  harness h;
  sd_mount_failure f;
  h_init(&h);
  fake_backend_reset();
  fake_backend_set_webclient(SD_WD_CLIENT_STOPPED, 1);
  fake_backend_set_webdav_noauth(1);
  h.answer_inline = 1;
  h.hk_answer = SD_MA_HOSTKEY_TRUST;
  h.password = "pw";
  h.answer_token = 1;
  h.token_answer = SD_MA_REJECT;
  h_token_only = 0;
  h_token_confirmed = 0;
  SD_REQUIRE(h_create_b(&h, L"good-webdav.test", L"C:\\keys\\id_ed25519", L'Y', SD_MOUNT_BACKEND_WEBDAV) == SD_OK);
  SD_REQUIRE(sd_mount_start(h.m) == SD_OK);
  SD_CHECK(pump_until_final(&h, 5000));
  SD_CHECK_EQ_INT(sd_mount_get_state(h.m), SD_MOUNT_FAILED);
  SD_CHECK_EQ_INT(h.ntoken_prompts, 1);
  SD_CHECK_EQ_INT(fake_backend_webdav_mounts(), 0);
  sd_mount_get_failure(h.m, &f);
  SD_CHECK(f.code != NULL && strcmp(f.code, "token_only_refused") == 0);
  fake_backend_set_webdav_noauth(0);
  sd_mount_destroy(h.m);
  h_free(&h);
}

/* The host asked for token-only without a confirmation: the question comes before any WebDAV start. */
SD_TEST(mount_token_only_asks_before_webdav_start)
{
  harness h;
  h_init(&h);
  fake_backend_reset();
  fake_backend_set_webclient(SD_WD_CLIENT_STOPPED, 1);
  h.answer_token = 1;
  h.token_answer = SD_MA_HOSTKEY_ONCE;
  h_token_only = 1;
  h_token_confirmed = 0;
  SD_REQUIRE(h_create_b(&h, L"good-webdav.test", L"C:\\keys\\id_ed25519", L'Y', SD_MOUNT_BACKEND_WEBDAV) == SD_OK);
  h_token_only = 0;
  h_token_confirmed = 0;
  SD_REQUIRE(sd_mount_start(h.m) == SD_OK);
  SD_CHECK(pump_until_state(&h, SD_MOUNT_MOUNTED, 5000));
  SD_CHECK_EQ_INT(h.ntoken_prompts, 1);
  SD_CHECK_EQ_INT(fake_backend_webdav_calls(), 1);
  SD_CHECK_EQ_INT(fake_backend_last_webdav_confirmed(), 1);
  SD_CHECK(sd_mount_stop(h.m) == SD_OK);
  SD_CHECK(pump_until_final(&h, 5000));
  sd_mount_destroy(h.m);
  h_free(&h);
}

SD_TEST(mount_m3_webdav_attach_port)
{
  harness h;
  sd_mount_attach a;
  fake_backend_reset();
  fake_backend_set_webclient(SD_WD_CLIENT_STOPPED, 1);
  fake_backend_set_webclient(SD_WD_CLIENT_STOPPED, 1);
  h_init(&h);
  SD_REQUIRE(h_create_b(&h, L"nodokany-m3.test", NULL, L'S', SD_MOUNT_BACKEND_AUTO) == SD_OK);
  SD_REQUIRE(sd_mount_start(h.m) == SD_OK);
  SD_REQUIRE(pump_until_state(&h, SD_MOUNT_MOUNTED, 5000));
  memset(&a, 0, sizeof(a));
  sd_mount_get_attach(h.m, &a);
  SD_CHECK(a.backend == SD_MOUNT_BACKEND_WEBDAV);
  SD_CHECK_EQ_INT(a.webdav_port, 49321);
  sd_mount_stop(h.m);
  SD_CHECK(pump_until_final(&h, 5000));
  sd_mount_destroy(h.m);
  h_free(&h);
}
