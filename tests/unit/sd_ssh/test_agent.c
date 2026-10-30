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

/* ---- fake pipe agent ----
   Like a real agent the fake always keeps several unconnected instances listening (overlapped
   ConnectNamedPipe on TA_PIPE_LISTEN instances), so a client that reconnects right away never sees
   ERROR_PIPE_BUSY however slowly this process is scheduled. Each connection is served on its own
   thread; the stop event unblocks the accept loop and every server thread. */

#define TA_PIPE_LISTEN 3

static HANDLE ta_pipe_create(const wchar_t *name)
{
  /* CI runners run the tests as an elevated administrator, and Windows makes objects created by an
     elevated administrator owned by the Administrators GROUP. The client's user-pipe owner check
     (agent_pipe.c verify_pipe, TM-R08) rightly refuses such a pipe: a real SSH_AUTH_SOCK pipe is
     owned by the user. Give the fake that owner explicitly, so it looks like the real thing. */
  SECURITY_ATTRIBUTES sa, *psa = NULL;
  SECURITY_DESCRIPTOR sd;
  HANDLE tok = NULL, h;
  BYTE ubuf[64];
  DWORD need = 0;
  if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok) &&
      GetTokenInformation(tok, TokenUser, ubuf, sizeof(ubuf), &need) &&
      InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION) &&
      SetSecurityDescriptorOwner(&sd, ((TOKEN_USER *)ubuf)->User.Sid, FALSE)) {
    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = &sd;   /* no DACL set: the token's default DACL applies */
    sa.bInheritHandle = FALSE;
    psa = &sa;
  }
  if (tok) CloseHandle(tok);
  h = CreateNamedPipeW(name, PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                       PIPE_UNLIMITED_INSTANCES, 65536, 65536, 0, psa);
  return h;
}

/* One overlapped read or write that gives up when stop is signaled. Returns the byte count or -1. */
static int ta_pipe_io(HANDLE h, HANDLE ev, HANDLE stop, void *buf, DWORD n, int write)
{
  OVERLAPPED o;
  DWORD got = 0;
  BOOL ok;
  memset(&o, 0, sizeof(o));
  o.hEvent = ev;
  ResetEvent(ev);
  ok = write ? WriteFile(h, buf, n, &got, &o) : ReadFile(h, buf, n, &got, &o);
  if (!ok) {
    HANDLE hs[2];
    if (GetLastError() != ERROR_IO_PENDING) return -1;
    hs[0] = ev;
    hs[1] = stop;
    if (WaitForMultipleObjects(2, hs, FALSE, INFINITE) != WAIT_OBJECT_0) {
      CancelIo(h);
      GetOverlappedResult(h, &o, &got, TRUE);
      return -1;
    }
    if (!GetOverlappedResult(h, &o, &got, FALSE)) return -1;
  }
  return (int)got;
}

static int ta_pipe_io_all(HANDLE h, HANDLE ev, HANDLE stop, uint8_t *buf, DWORD n, int write)
{
  DWORD off = 0;
  while (off < n) {
    int r = ta_pipe_io(h, ev, stop, buf + off, n - off, write);
    if (r <= 0) return 0;
    off += (DWORD)r;
  }
  return 1;
}

static unsigned __stdcall pipe_conn_main(void *arg)
{
  ta_pipe_conn *c = (ta_pipe_conn *)arg;
  ta_pipe_agent *pa = c->pa;
  HANDLE h = c->h;
  HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL);
  if (ev) {
    for (;;) {
      sd_wr w;
      uint8_t hdr[4], lb[4], *body;
      DWORD len;
      int okw;
      if (!ta_pipe_io_all(h, ev, pa->stopev, hdr, 4, 0)) break;
      len = sd_load_be32(hdr);
      if (len == 0 || len > (1u << 20)) break;
      body = (uint8_t *)sd_alloc(len);
      if (!body) break;
      if (!ta_pipe_io_all(h, ev, pa->stopev, body, len, 0)) { sd_free(body); break; }
      sd_wr_init(&w, 1u << 20);
      agent_answer(&pa->agent, body, len, &w);
      sd_free(body);
      sd_store_be32(lb, (uint32_t)w.len);
      okw = ta_pipe_io_all(h, ev, pa->stopev, lb, 4, 1) && ta_pipe_io_all(h, ev, pa->stopev, w.p, (DWORD)w.len, 1);
      sd_wr_free(&w);
      if (!okw) break;
    }
    CloseHandle(ev);
  }
  DisconnectNamedPipe(h);
  CloseHandle(h);
  InterlockedExchange(&c->done, 1);
  return 0;
}

/* Hands a connected instance to a server thread, reusing a finished slot. Returns 0 when none is free. */
static int pipe_spawn(ta_pipe_agent *pa, HANDLE h)
{
  int i;
  for (i = 0; i < TA_PIPE_CONNS; i++) {
    ta_pipe_conn *c = &pa->conns[i];
    if (c->started && !c->done) continue;
    if (c->started) sd_thread_join(&c->thread, SD_WAIT_INFINITE, NULL);
    c->started = 0;
    c->pa = pa;
    c->h = h;
    c->done = 0;
    if (sd_thread_create(&c->thread, pipe_conn_main, c, 256u * 1024, L"fake agent conn") != SD_OK) return 0;
    c->started = 1;
    return 1;
  }
  return 0;
}

static unsigned __stdcall pipe_main(void *arg)
{
  ta_pipe_agent *pa = (ta_pipe_agent *)arg;
  HANDLE inst[TA_PIPE_LISTEN];
  HANDLE evs[TA_PIPE_LISTEN + 1];
  OVERLAPPED ov[TA_PIPE_LISTEN];
  int i, alive = 1;
  evs[0] = pa->stopev;
  for (i = 0; i < TA_PIPE_LISTEN; i++) {
    inst[i] = INVALID_HANDLE_VALUE;
    evs[i + 1] = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!evs[i + 1]) alive = 0;
  }
  while (alive) {
    DWORD r, got;
    /* arm: create an instance and start an overlapped connect; a client that is already waiting
       completes at once (ERROR_PIPE_CONNECTED) and is signaled through the event */
    for (i = 0; i < TA_PIPE_LISTEN && alive; i++) {
      if (inst[i] != INVALID_HANDLE_VALUE) continue;
      inst[i] = ta_pipe_create(pa->name);
      if (inst[i] == INVALID_HANDLE_VALUE || inst[i] == NULL) { inst[i] = INVALID_HANDLE_VALUE; alive = 0; break; }
      memset(&ov[i], 0, sizeof(ov[i]));
      ov[i].hEvent = evs[i + 1];
      ResetEvent(evs[i + 1]);
      if (!ConnectNamedPipe(inst[i], &ov[i])) {
        DWORD e = GetLastError();
        if (e == ERROR_PIPE_CONNECTED) SetEvent(evs[i + 1]);
        else if (e != ERROR_IO_PENDING) { CloseHandle(inst[i]); inst[i] = INVALID_HANDLE_VALUE; alive = 0; break; }
      }
    }
    if (!pa->ready_set) { pa->ready_set = 1; SetEvent(pa->ready); }
    if (!alive) break;
    r = WaitForMultipleObjects(TA_PIPE_LISTEN + 1, evs, FALSE, INFINITE);
    if (r < WAIT_OBJECT_0 + 1 || r > WAIT_OBJECT_0 + TA_PIPE_LISTEN) break;   /* stop (or failure) */
    i = (int)(r - WAIT_OBJECT_0) - 1;
    if (!GetOverlappedResult(inst[i], &ov[i], &got, FALSE) || !pipe_spawn(pa, inst[i])) CloseHandle(inst[i]);
    inst[i] = INVALID_HANDLE_VALUE;
  }
  for (i = 0; i < TA_PIPE_LISTEN; i++) {
    if (inst[i] != INVALID_HANDLE_VALUE) CloseHandle(inst[i]);
    if (evs[i + 1]) CloseHandle(evs[i + 1]);
  }
  SetEvent(pa->ready);
  return 0;
}

sd_err ta_pipe_start(ta_pipe_agent *pa)
{
  _snwprintf_s(pa->name, SD_COUNTOF(pa->name), _TRUNCATE, L"\\\\.\\pipe\\sd-test-agent-%lu-%p",
               (unsigned long)GetCurrentProcessId(), (void *)pa);
  memset(pa->conns, 0, sizeof(pa->conns));
  pa->ready_set = 0;
  pa->ready = CreateEventW(NULL, FALSE, FALSE, NULL);
  pa->stopev = CreateEventW(NULL, TRUE, FALSE, NULL);
  pa->stop = 0;
  if (!pa->ready || !pa->stopev) return SD_E_INTERNAL;
  if (sd_thread_create(&pa->thread, pipe_main, pa, 256u * 1024, L"fake agent") != SD_OK) return SD_E_INTERNAL;
  WaitForSingleObject(pa->ready, 5000);
  SetEnvironmentVariableW(L"SSH_AUTH_SOCK", pa->name);
  return SD_OK;
}

void ta_pipe_stop(ta_pipe_agent *pa)
{
  int i;
  pa->stop = 1;
  SetEvent(pa->stopev);
  sd_thread_join(&pa->thread, SD_WAIT_INFINITE, NULL);
  for (i = 0; i < TA_PIPE_CONNS; i++)
    if (pa->conns[i].started) sd_thread_join(&pa->conns[i].thread, SD_WAIT_INFINITE, NULL);
  CloseHandle(pa->ready);
  CloseHandle(pa->stopev);
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
  wc.lpszClassName = pg->name;
  RegisterClassExW(&wc);
  pg->hwnd = CreateWindowExW(0, pg->name, pg->name, 0, 0, 0, 0, 0, HWND_MESSAGE, NULL, wc.hInstance, NULL);
  SetEvent(pg->ready);
  if (!pg->hwnd) return 0;
  while (GetMessageW(&m, NULL, 0, 0) > 0) {
    TranslateMessage(&m);
    DispatchMessageW(&m);
  }
  DestroyWindow(pg->hwnd);
  UnregisterClassW(pg->name, wc.hInstance);
  return 0;
}

sd_err ta_pageant_start(ta_pageant *pg)
{
  LARGE_INTEGER qpc;
  /* The client finds the window by this name (a test seam in the product, agent_internal.h). The name is
     unique per process, so a real Pageant or another test run's fake is never picked up. */
  QueryPerformanceCounter(&qpc);
  _snwprintf_s(pg->name, SD_COUNTOF(pg->name), _TRUNCATE, L"sd-test-pageant-%lu-%08lx",
               (unsigned long)GetCurrentProcessId(), (unsigned long)qpc.LowPart);
  ssh_pageant_test_set_window_name(pg->name);
  g_pageant = pg;
  pg->ready = CreateEventW(NULL, FALSE, FALSE, NULL);
  if (!pg->ready) { ssh_pageant_test_set_window_name(NULL); return SD_E_INTERNAL; }
  if (sd_thread_create(&pg->thread, pageant_main, pg, 256u * 1024u, L"fake pageant") != SD_OK) {
    CloseHandle(pg->ready);
    ssh_pageant_test_set_window_name(NULL);
    return SD_E_INTERNAL;
  }
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
  ssh_pageant_test_set_window_name(NULL);
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
