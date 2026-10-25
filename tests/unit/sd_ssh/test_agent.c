/* Agent clients (01 §6.5) against in-test fake agents: a named-pipe agent reached through
 * SSH_AUTH_SOCK (the OpenSSH agent protocol on a user pipe, TM-R08 owner = our SID) and a fake
 * Pageant window (WM_COPYDATA + file mapping). The real Windows OpenSSH agent is probed read-only
 * when its service runs (no keys are added or removed). */
#include <windows.h>
#include <stdio.h>
#include <string.h>

#include "sd_base/sd_mem.h"
#include "sd_crypto/sd_crypto.h"
#include "sd_platform/sd_thread.h"
#include "sd_ssh/sd_agent.h"
#include "sd_ssh/sd_ssh.h"
#include "sd_test.h"
#include "agent_internal.h"
#include "keyfile_internal.h"
#include "ssh_internal.h"
#include "test_agent.h"
#include "test_util.h"

/* ---- shared fake agent logic ---- */

static sd_ssh_key *load_fixture_key(const char *name, const char *pass)
{
  char path[MAX_PATH];
  uint8_t *f;
  size_t n;
  sd_ssh_key *k = NULL;
  _snprintf_s(path, sizeof(path), _TRUNCATE, "keys/%s", name);
  if (!tu_read_fixture(path, &f, &n)) return NULL;
  if (sd_ssh_key_load(f, n, pass, pass ? strlen(pass) : 0, &k) == SD_E_KEY_PASSPHRASE_REQUIRED)
    (void)sd_ssh_key_load(f, n, "correct horse", 13, &k);
  sd_free(f);
  return k;
}

sd_err ta_agent_init(ta_agent *a, const char *const *keys, uint32_t n)
{
  uint32_t i;
  memset(a, 0, sizeof(*a));
  for (i = 0; i < n && i < TA_MAX_KEYS; i++) {
    a->keys[i] = load_fixture_key(keys[i], NULL);
    if (!a->keys[i]) return SD_E_NOT_FOUND;
    a->nkeys++;
  }
  return SD_OK;
}

void ta_agent_free(ta_agent *a)
{
  uint32_t i;
  for (i = 0; i < a->nkeys; i++) sd_ssh_key_free(a->keys[i]);
  a->nkeys = 0;
}

/* Answers one agent request (body without the length prefix). */
static void agent_answer(ta_agent *a, const uint8_t *req, size_t n, sd_wr *out)
{
  sd_rd r;
  uint8_t t;
  uint32_t i;
  sd_rd_init(&r, req, n);
  t = sd_rd_u8(&r);
  a->requests++;
  if (t == SSH_AGENTC_REQUEST_IDENTITIES) {
    a->list_requests++;
    sd_wr_u8(out, SSH_AGENT_IDENTITIES_ANSWER);
    sd_wr_u32(out, a->nkeys + (a->cert_len ? 1u : 0u));
    if (a->cert_len) {
      sd_wr_string(out, a->cert, a->cert_len);
      sd_wr_cstring(out, "fake cert");
    }
    for (i = 0; i < a->nkeys; i++) {
      size_t bl;
      const uint8_t *b = sd_ssh_key_public_blob(a->keys[i], &bl);
      sd_wr_string(out, b, bl);
      sd_wr_cstring(out, sd_ssh_key_comment(a->keys[i]));
    }
    return;
  }
  if (t == SSH_AGENTC_SIGN_REQUEST) {
    sd_span blob = sd_rd_string(&r, 16384), data = sd_rd_string(&r, 1u << 20);
    uint32_t flags = sd_rd_u32(&r);
    a->sign_requests++;
    a->last_flags = flags;
    for (i = 0; i < a->nkeys && sd_rd_done(&r) && !a->refuse_sign; i++) {
      size_t bl;
      const uint8_t *b = sd_ssh_key_public_blob(a->keys[i], &bl);
      int match = bl == blob.n && memcmp(b, blob.p, bl) == 0;
      if (!match && a->cert_len && blob.n == a->cert_len && memcmp(blob.p, a->cert, a->cert_len) == 0) {
        uint8_t plain[1024];
        size_t pn = 0;
        match = ssh_cert_plain_pub(a->cert, a->cert_len, plain, sizeof(plain), &pn) == SD_OK && pn == bl &&
                memcmp(plain, b, bl) == 0;
      }
      if (match) {
        uint8_t sig[1200];
        size_t sl = 0;
        const char *alg = NULL;
        if (!strcmp(sd_ssh_key_type(a->keys[i]), "ssh-rsa"))
          alg = (flags & SD_AGENT_SIGN_RSA_SHA2_512) ? "rsa-sha2-512" : (flags & SD_AGENT_SIGN_RSA_SHA2_256) ? "rsa-sha2-256" : "ssh-rsa";
        if (sd_ssh_key_sign_alg(a->keys[i], alg, data.p, data.n, sig, sizeof(sig), &sl) == SD_OK) {
          sd_wr_u8(out, SSH_AGENT_SIGN_RESPONSE);
          sd_wr_string(out, sig, sl);
          return;
        }
      }
    }
  }
  sd_wr_u8(out, SSH_AGENT_FAILURE);
}

/* ---- fake pipe agent ---- */

static unsigned __stdcall pipe_main(void *arg)
{
  ta_pipe_agent *pa = (ta_pipe_agent *)arg;
  while (!pa->stop) {
    HANDLE h = CreateNamedPipeW(pa->name, PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT, 4, 65536,
                                65536, 0, NULL);
    uint8_t hdr[4], *body;
    DWORD got, len;
    if (h == INVALID_HANDLE_VALUE) break;
    SetEvent(pa->ready);
    if (!ConnectNamedPipe(h, NULL) && GetLastError() != ERROR_PIPE_CONNECTED) { CloseHandle(h); continue; }
    if (pa->stop) { CloseHandle(h); break; }
    for (;;) {
      sd_wr w;
      uint8_t lb[4];
      if (!ReadFile(h, hdr, 4, &got, NULL) || got != 4) break;
      len = sd_load_be32(hdr);
      if (len == 0 || len > (1u << 20)) break;
      body = (uint8_t *)sd_alloc(len);
      if (!body) break;
      {
        DWORD off = 0;
        while (off < len && ReadFile(h, body + off, len - off, &got, NULL) && got) off += got;
        if (off != len) { sd_free(body); break; }
      }
      sd_wr_init(&w, 1u << 20);
      agent_answer(&pa->agent, body, len, &w);
      sd_free(body);
      sd_store_be32(lb, (uint32_t)w.len);
      WriteFile(h, lb, 4, &got, NULL);
      WriteFile(h, w.p, (DWORD)w.len, &got, NULL);
      sd_wr_free(&w);
    }
    DisconnectNamedPipe(h);
    CloseHandle(h);
  }
  return 0;
}

sd_err ta_pipe_start(ta_pipe_agent *pa)
{
  _snwprintf_s(pa->name, SD_COUNTOF(pa->name), _TRUNCATE, L"\\\\.\\pipe\\sd-test-agent-%lu-%p",
               (unsigned long)GetCurrentProcessId(), (void *)pa);
  pa->ready = CreateEventW(NULL, FALSE, FALSE, NULL);
  pa->stop = 0;
  if (!pa->ready) return SD_E_INTERNAL;
  if (sd_thread_create(&pa->thread, pipe_main, pa, 256u * 1024u, L"fake agent") != SD_OK) return SD_E_INTERNAL;
  WaitForSingleObject(pa->ready, 5000);
  SetEnvironmentVariableW(L"SSH_AUTH_SOCK", pa->name);
  return SD_OK;
}

void ta_pipe_stop(ta_pipe_agent *pa)
{
  HANDLE h;
  pa->stop = 1;
  h = CreateFileW(pa->name, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);   /* unblock */
  if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
  sd_thread_join(&pa->thread, SD_WAIT_INFINITE, NULL);
  CloseHandle(pa->ready);
  SetEnvironmentVariableW(L"SSH_AUTH_SOCK", NULL);
}

/* ---- fake Pageant ---- */

static ta_pageant *g_pageant;

static LRESULT CALLBACK pageant_proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
  if (msg == WM_COPYDATA && g_pageant) {
    const COPYDATASTRUCT *cds = (const COPYDATASTRUCT *)lp;
    HANDLE map;
    uint8_t *view;
    LRESULT ok = 0;
    if (cds->dwData != 0x804e50baul || !cds->lpData || !memchr(cds->lpData, 0, cds->cbData)) return 0;
    map = OpenFileMappingA(FILE_MAP_ALL_ACCESS, FALSE, (const char *)cds->lpData);
    if (!map) return 0;
    view = (uint8_t *)MapViewOfFile(map, FILE_MAP_WRITE, 0, 0, 0);
    if (view) {
      uint32_t len = sd_load_be32(view);
      if (len && len < 8192) {
        sd_wr w;
        sd_wr_init(&w, 8192);
        agent_answer(&g_pageant->agent, view + 4, len, &w);
        if (sd_wr_ok(&w) && w.len + 4 <= SD_AGENT_MAX_REPLY) {
          sd_store_be32(view, (uint32_t)w.len);
          memcpy(view + 4, w.p, w.len);
          ok = 1;
        }
        sd_wr_free(&w);
      }
      UnmapViewOfFile(view);
    }
    CloseHandle(map);
    return ok;
  }
  return DefWindowProcW(hwnd, msg, wp, lp);
}

static unsigned __stdcall pageant_main(void *arg)
{
  ta_pageant *pg = (ta_pageant *)arg;
  WNDCLASSEXW wc;
  MSG m;
  memset(&wc, 0, sizeof(wc));
  wc.cbSize = sizeof(wc);
  wc.lpfnWndProc = pageant_proc;
  wc.hInstance = GetModuleHandleW(NULL);
  wc.lpszClassName = L"Pageant";
  RegisterClassExW(&wc);
  pg->hwnd = CreateWindowExW(0, L"Pageant", L"Pageant", 0, 0, 0, 0, 0, HWND_MESSAGE, NULL, wc.hInstance, NULL);
  SetEvent(pg->ready);
  if (!pg->hwnd) return 0;
  while (GetMessageW(&m, NULL, 0, 0) > 0) {
    TranslateMessage(&m);
    DispatchMessageW(&m);
  }
  DestroyWindow(pg->hwnd);
  UnregisterClassW(L"Pageant", wc.hInstance);
  return 0;
}

sd_err ta_pageant_start(ta_pageant *pg)
{
  if (FindWindowW(L"Pageant", L"Pageant")) return SD_E_EXISTS;   /* a real Pageant runs: leave it alone */
  g_pageant = pg;
  pg->ready = CreateEventW(NULL, FALSE, FALSE, NULL);
  if (!pg->ready) return SD_E_INTERNAL;
  if (sd_thread_create(&pg->thread, pageant_main, pg, 256u * 1024u, L"fake pageant") != SD_OK) return SD_E_INTERNAL;
  WaitForSingleObject(pg->ready, 5000);
  pg->tid = pg->thread.id;
  return pg->hwnd ? SD_OK : SD_E_INTERNAL;
}

void ta_pageant_stop(ta_pageant *pg)
{
  PostMessageW(pg->hwnd, WM_QUIT, 0, 0);
  PostThreadMessageW(pg->tid, WM_QUIT, 0, 0);
  sd_thread_join(&pg->thread, SD_WAIT_INFINITE, NULL);
  CloseHandle(pg->ready);
  g_pageant = NULL;
}

/* ---- tests ---- */

static void check_agent(sd_test_ctx *sd_t_, uint32_t kind, ta_agent *a)
{
  sd_agent_list *l = NULL;
  uint32_t i;
  static const uint8_t data[] = "session data to sign";
  SD_CHECK_EQ_INT(sd_agent_probe(kind), SD_OK);
  SD_CHECK_EQ_INT(sd_agent_list_identities(kind, &l), SD_OK);
  SD_REQUIRE(l != NULL);
  SD_CHECK_EQ_INT(l->count, a->nkeys);
  for (i = 0; i < l->count && i < a->nkeys; i++) {
    size_t bl;
    const uint8_t *b = sd_ssh_key_public_blob(a->keys[i], &bl);
    uint8_t *sig = NULL;
    size_t sl = 0;
    uint32_t flags = !strcmp(l->ids[i].type, "ssh-rsa") ? SD_AGENT_SIGN_RSA_SHA2_256 : 0;
    SD_CHECK(l->ids[i].blob_len == bl && memcmp(l->ids[i].blob, b, bl) == 0);
    SD_CHECK_STR(l->ids[i].type, sd_ssh_key_type(a->keys[i]));
    SD_CHECK_STR(l->ids[i].comment, sd_ssh_key_comment(a->keys[i]));
    SD_CHECK(!strncmp(l->ids[i].fp_sha256, "SHA256:", 7));
    SD_CHECK_EQ_INT(sd_agent_sign(kind, b, bl, data, sizeof(data), flags, &sig, &sl), SD_OK);
    if (sig) {
      sd_span t = ssh_blob_key_type(sig, sl);
      SD_CHECK(ssh_span_eq(t, flags ? "rsa-sha2-256" : sd_ssh_key_type(a->keys[i])));
      SD_CHECK_EQ_INT(a->last_flags, flags);
    }
    sd_free(sig);
  }
  /* an unknown key is refused */
  {
    uint8_t *sig = NULL;
    size_t sl = 0;
    static const uint8_t junk[] = { 0, 0, 0, 11, 's', 's', 'h', '-', 'e', 'd', '2', '5', '5', '1', '9', 0, 0, 0, 0 };
    a->refuse_sign = 0;
    SD_CHECK_EQ_INT(sd_agent_sign(kind, junk, sizeof(junk), data, sizeof(data), 0, &sig, &sl), SD_E_AUTH_FAILED);
    sd_free(sig);
  }
  sd_agent_list_free(l);
}

SD_TEST(ssh_agent_pipe_fake)
{
  static const char *const keys[] = { "ossh_ed25519", "ossh_p256", "ossh_rsa2048" };
  ta_pipe_agent pa;
  if (!tu_crypto_or_skip("ssh_agent_pipe_fake")) return;
  memset(&pa, 0, sizeof(pa));
  SD_REQUIRE(ta_agent_init(&pa.agent, keys, 3) == SD_OK);
  SD_REQUIRE(ta_pipe_start(&pa) == SD_OK);
  check_agent(sd_t_, SD_AGENT_OPENSSH, &pa.agent);
  ta_pipe_stop(&pa);
  /* the pipe is gone: unavailable, not an error loop */
  SetEnvironmentVariableW(L"SSH_AUTH_SOCK", L"\\\\.\\pipe\\sd-test-agent-none");
  SD_CHECK_EQ_INT(sd_agent_probe(SD_AGENT_OPENSSH), SD_E_NOT_FOUND);
  SetEnvironmentVariableW(L"SSH_AUTH_SOCK", NULL);
  ta_agent_free(&pa.agent);
}

SD_TEST(ssh_agent_pageant_fake)
{
  static const char *const keys[] = { "ossh_p384", "ossh_ed25519" };
  ta_pageant pg;
  sd_err e;
  if (!tu_crypto_or_skip("ssh_agent_pageant_fake")) return;
  memset(&pg, 0, sizeof(pg));
  SD_REQUIRE(ta_agent_init(&pg.agent, keys, 2) == SD_OK);
  e = ta_pageant_start(&pg);
  if (e == SD_E_EXISTS) {
    printf("  [skip] ssh_agent_pageant_fake: a real Pageant is running\n");
    ta_agent_free(&pg.agent);
    return;
  }
  SD_REQUIRE(e == SD_OK);
  check_agent(sd_t_, SD_AGENT_PAGEANT, &pg.agent);
  ta_pageant_stop(&pg);
  SD_CHECK_EQ_INT(sd_agent_probe(SD_AGENT_PAGEANT), SD_E_NOT_FOUND);
  ta_agent_free(&pg.agent);
}

/* TM-R08 on the real default pipe: the Windows OpenSSH agent service, when it runs, must pass the
   owner check; listing is read-only. Without the service: unavailable. */
SD_TEST(ssh_agent_windows_openssh_probe)
{
  sd_err e;
  sd_agent_list *l = NULL;
  SetEnvironmentVariableW(L"SSH_AUTH_SOCK", NULL);
  e = sd_agent_probe(SD_AGENT_OPENSSH);
  printf("  windows openssh agent probe: %s\n", sd_err_name(e));
  SD_CHECK(e == SD_OK || e == SD_E_NOT_FOUND || e == SD_E_UNSUPPORTED);
  if (e == SD_OK) {
    SD_CHECK_EQ_INT(sd_agent_list_identities(SD_AGENT_OPENSSH, &l), SD_OK);
    if (l) printf("  windows openssh agent: %u identities\n", l->count);
    sd_agent_list_free(l);
  }
}

SD_TEST(ssh_agent_reply_bounds)
{
  /* a fake agent answering garbage: the parser rejects it */
  ta_pipe_agent pa;
  sd_agent_list *l = NULL;
  memset(&pa, 0, sizeof(pa));
  pa.agent.nkeys = 0;
  SD_REQUIRE(ta_pipe_start(&pa) == SD_OK);
  SD_CHECK_EQ_INT(sd_agent_list_identities(SD_AGENT_OPENSSH, &l), SD_OK);
  SD_CHECK(l && l->count == 0);
  sd_agent_list_free(l);
  ta_pipe_stop(&pa);
}
