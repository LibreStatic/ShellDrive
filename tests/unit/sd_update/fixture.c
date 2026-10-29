/* sd_update test fixtures (see fixture.h). Keys are test keys: created by sd-updsign in a temp directory and
 * removed at the end of the test. */
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "fixture.h"
#include "sd_base/sd_mem.h"
#include "sd_crypto/sd_crypto.h"
#include "sd_platform/sd_platform.h"
#include "sd_test.h"

#ifndef SD_TEST_UPDSIGN
#error "SD_TEST_UPDSIGN must name the sd-updsign executable (tests/unit/sd_update/CMakeLists.txt)"
#endif




/* ---- files and processes ---- */

int fx_write(const wchar_t *path, const void *p, size_t n)
{
  HANDLE h = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  DWORD put = 0;
  BOOL ok;
  if (h == INVALID_HANDLE_VALUE)
    return 0;
  ok = (n == 0) || (WriteFile(h, p, (DWORD)n, &put, NULL) && put == (DWORD)n);
  CloseHandle(h);
  return ok != 0;
}

int fx_read(const wchar_t *path, uint8_t **buf, size_t *n)
{
  HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                         OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  LARGE_INTEGER sz;
  DWORD got = 0;
  uint8_t *p;
  if (h == INVALID_HANDLE_VALUE)
    return 0;
  if (!GetFileSizeEx(h, &sz) || sz.QuadPart > (1ll << 26)) {
    CloseHandle(h);
    return 0;
  }
  p = (uint8_t *)sd_alloc((size_t)sz.QuadPart + 1);
  if (p == NULL) {
    CloseHandle(h);
    return 0;
  }
  if (sz.QuadPart && (!ReadFile(h, p, (DWORD)sz.QuadPart, &got, NULL) || got != (DWORD)sz.QuadPart)) {
    CloseHandle(h);
    sd_free(p);
    return 0;
  }
  CloseHandle(h);
  p[got] = 0;
  *buf = p;
  *n = got;
  return 1;
}

static int run_wait(const wchar_t *cmdline, const wchar_t *stdout_path, DWORD *code)
{
  STARTUPINFOW si;
  PROCESS_INFORMATION pi;
  wchar_t cmd[4096];
  HANDLE out = INVALID_HANDLE_VALUE;
  SECURITY_ATTRIBUTES sa;
  int ok;
  if (wcslen(cmdline) >= SD_COUNTOF(cmd))
    return 0;
  wcscpy_s(cmd, SD_COUNTOF(cmd), cmdline);
  memset(&si, 0, sizeof(si));
  si.cb = sizeof(si);
  si.dwFlags = STARTF_USESTDHANDLES;
  si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
  si.hStdError = GetStdHandle(STD_ERROR_HANDLE);
  si.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
  if (stdout_path) {
    memset(&sa, 0, sizeof(sa));
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    out = CreateFileW(stdout_path, GENERIC_WRITE, FILE_SHARE_READ, &sa, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (out == INVALID_HANDLE_VALUE)
      return 0;
    si.hStdOutput = out;
  }
  memset(&pi, 0, sizeof(pi));
  ok = CreateProcessW(NULL, cmd, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
  if (out != INVALID_HANDLE_VALUE)
    CloseHandle(out);
  if (!ok)
    return 0;
  WaitForSingleObject(pi.hProcess, 60000);
  if (code)
    GetExitCodeProcess(pi.hProcess, code);
  CloseHandle(pi.hThread);
  CloseHandle(pi.hProcess);
  return 1;
}

static int run_tool(const fx *f, const wchar_t *args, const wchar_t *stdout_path)
{
  wchar_t cmd[4096];
  DWORD code = 99;
  _snwprintf_s(cmd, SD_COUNTOF(cmd), _TRUNCATE, L"\"%ls\" %ls", f->tool, args);
  return run_wait(cmd, stdout_path, &code) && code == 0;
}

void fx_remove_tree(const wchar_t *dir)
{
  wchar_t pat[MAX_PATH * 2];
  WIN32_FIND_DATAW fd;
  HANDLE h;
  _snwprintf_s(pat, SD_COUNTOF(pat), _TRUNCATE, L"%ls\\*", dir);
  h = FindFirstFileW(pat, &fd);
  if (h == INVALID_HANDLE_VALUE) {
    RemoveDirectoryW(dir);
    return;
  }
  do {
    wchar_t child[MAX_PATH * 2];
    if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0)
      continue;
    _snwprintf_s(child, SD_COUNTOF(child), _TRUNCATE, L"%ls\\%ls", dir, fd.cFileName);
    if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
      fx_remove_tree(child);
    else {
      SetFileAttributesW(child, FILE_ATTRIBUTE_NORMAL);
      DeleteFileW(child);
    }
  } while (FindNextFileW(h, &fd));
  FindClose(h);
  RemoveDirectoryW(dir);
}

int fx_path(const fx *f, const wchar_t *rel, wchar_t *out, size_t cap)
{
  return _snwprintf_s(out, cap, _TRUNCATE, L"%ls\\%ls", f->dir, rel) > 0;
}

/* ---- keys ---- */

static int hex_to_bytes(const char *hex, uint8_t *out, size_t n)
{
  size_t i;
  for (i = 0; i < n; i++) {
    unsigned v;
    if (sscanf_s(hex + 2 * i, "%2x", &v) != 1)
      return 0;
    out[i] = (uint8_t)v;
  }
  return 1;
}

static int make_key(fx *f, const wchar_t *name, fx_key *k)
{
  wchar_t out[MAX_PATH], pub[MAX_PATH], seed[MAX_PATH], args[1024];
  uint8_t *buf = NULL;
  size_t n = 0;
  char *p;
  _snwprintf_s(seed, SD_COUNTOF(seed), _TRUNCATE, L"%ls\\%ls.seed", f->dir, name);
  _snwprintf_s(pub, SD_COUNTOF(pub), _TRUNCATE, L"%ls\\%ls.pub", f->dir, name);
  _snwprintf_s(out, SD_COUNTOF(out), _TRUNCATE, L"%ls\\%ls.out", f->dir, name);
  _snwprintf_s(args, SD_COUNTOF(args), _TRUNCATE, L"keygen --seed \"%ls\" --pub \"%ls\"", seed, pub);
  if (!run_tool(f, args, out))
    return 0;
  if (!fx_read(out, &buf, &n))
    return 0;
  /* "pubkey <b64>\nkey-id <hex>\n" */
  p = strstr((char *)buf, "pubkey ");
  if (p == NULL || sscanf_s(p, "pubkey %47s", k->pub_b64, (unsigned)sizeof(k->pub_b64)) != 1) {
    sd_free(buf);
    return 0;
  }
  p = strstr((char *)buf, "key-id ");
  if (p == NULL || sscanf_s(p, "key-id %16s", k->id_hex, (unsigned)sizeof(k->id_hex)) != 1) {
    sd_free(buf);
    return 0;
  }
  sd_free(buf);
  if (!hex_to_bytes(k->id_hex, k->id, 8))
    return 0;
  wcscpy_s(k->seed_path, SD_COUNTOF(k->seed_path), seed);
  /* the public key bytes (for the tests that compare them) come from the seed */
  {
    uint8_t sd[32];
    if (!fx_read(seed, &buf, &n) || n < 64)
      return 0;
    if (!hex_to_bytes((char *)buf, sd, 32)) {
      sd_free(buf);
      return 0;
    }
    sd_free(buf);
    memcpy(k->seed, sd, 32);
    sd_ed25519_pub_from_seed(k->pub, k->seed);
  }
  return 1;
}

int fx_init(fx *f, const char *name)
{
  wchar_t tmp[MAX_PATH], wname[64];
  char tmp8[MAX_PATH];
  LARGE_INTEGER qpc;
  DWORD tick;
  QueryPerformanceCounter(&qpc);
  tick = (DWORD)qpc.LowPart;
  size_t i, n = strlen(name);
  wchar_t *wsrc = NULL;
  int wlen;
  memset(f, 0, sizeof(*f));
  if (!GetTempPathW(SD_COUNTOF(tmp), tmp))
    return 0;
  for (i = 0; i < n && i + 1 < SD_COUNTOF(wname); i++)
    wname[i] = (wchar_t)name[i];
  wname[i] = L'\0';
  _snwprintf_s(f->dir, SD_COUNTOF(f->dir), _TRUNCATE, L"%lssdupd-%ls-%lu-%lu", tmp, wname,
               (unsigned long)GetCurrentProcessId(), (unsigned long)tick);
  fx_remove_tree(f->dir);
  if (!CreateDirectoryW(f->dir, NULL))
    return 0;

  /* the tool sits next to this test executable; the name comes from CMake as UTF-8 */
  if (!sd_test_exe_dir_path(SD_TEST_UPDSIGN, tmp8, sizeof(tmp8)))
    return 0;
  wlen = MultiByteToWideChar(CP_UTF8, 0, tmp8, -1, NULL, 0);
  if (wlen <= 0 || wlen > MAX_PATH)
    return 0;
  wsrc = (wchar_t *)sd_alloc((size_t)wlen * sizeof(wchar_t));
  if (wsrc == NULL)
    return 0;
  MultiByteToWideChar(CP_UTF8, 0, tmp8, -1, wsrc, wlen);
  wcscpy_s(f->tool, SD_COUNTOF(f->tool), wsrc);
  sd_free(wsrc);

  if (!make_key(f, L"root-a", &f->root_a) || !make_key(f, L"root-b", &f->root_b) ||
      !make_key(f, L"root-c", &f->root_c) || !make_key(f, L"stable", &f->stable) ||
      !make_key(f, L"beta", &f->beta) || !make_key(f, L"rogue", &f->rogue))
    return 0;
  return 1;
}

void fx_done(fx *f)
{
  fx_remove_tree(f->dir);
}

/* ---- text ---- */

void fx_text_add(fx_text *t, const char *fmt, ...)
{
  char tmp[2048];
  int n;
  va_list ap;
  va_start(ap, fmt);
  n = _vsnprintf_s(tmp, sizeof(tmp), _TRUNCATE, fmt, ap);
  va_end(ap);
  if (n <= 0)
    return;
  if (t->n + (size_t)n + 1 > t->cap)
    return;                              /* fixtures are small; a full buffer is a test bug */
  memcpy(t->p + t->n, tmp, (size_t)n);
  t->n += (size_t)n;
  t->p[t->n] = '\0';
}

/* ---- keyset ---- */

size_t fx_keyset_body(const fx *f, char *out, size_t cap, const fx_keyset_opts *o)
{
  fx_text t;
  t.p = out;
  t.n = 0;
  t.cap = cap;
  out[0] = '\0';
  fx_text_add(&t, "shelldrive-keyset 1\n");
  fx_text_add(&t, "product com.librestatic.shelldrive\n");
  fx_text_add(&t, "version %llu\n", (unsigned long long)o->version);
  fx_text_add(&t, "issued 2026-10-24T00:00:00Z\n");
  fx_text_add(&t, "key %s stable %s %s %s\n", f->stable.id_hex, f->stable.pub_b64,
              o->stable_from ? o->stable_from : "2026-01-01", o->stable_to ? o->stable_to : "2030-01-01");
  fx_text_add(&t, "key %s beta %s 2026-01-01 %s\n", f->beta.id_hex, f->beta.pub_b64,
              o->beta_to ? o->beta_to : "2030-01-01");
  if (o->revoke_stable)
    fx_text_add(&t, "revoke %s compromised\n", f->stable.id_hex);
  if (o->rotate) {
    fx_text_add(&t, "root %s %s\n", f->root_b.id_hex, f->root_b.pub_b64);
    fx_text_add(&t, "root %s %s\n", f->root_c.id_hex, f->root_c.pub_b64);
  }
  return t.n;
}

int fx_sign_keyset(fx *f, const char *body, size_t blen, const fx_key *const *roots, int nroots,
                   uint8_t **out, size_t *olen)
{
  wchar_t in[MAX_PATH], res[MAX_PATH], args[2048];
  int i;
  size_t n = 0;
  _snwprintf_s(in, SD_COUNTOF(in), _TRUNCATE, L"%ls\\keyset.body", f->dir);
  _snwprintf_s(res, SD_COUNTOF(res), _TRUNCATE, L"%ls\\keyset.txt", f->dir);
  if (!fx_write(in, body, blen))
    return 0;
  _snwprintf_s(args, SD_COUNTOF(args), _TRUNCATE, L"sign-keyset --in \"%ls\" --out \"%ls\"", in, res);
  for (i = 0; i < nroots; i++) {
    size_t l = wcslen(args);
    _snwprintf_s(args + l, SD_COUNTOF(args) - l, _TRUNCATE, L" --root \"%ls\"", roots[i]->seed_path);
  }
  if (!run_tool(f, args, NULL))
    return 0;
  if (!fx_read(res, out, &n))
    return 0;
  *olen = n;
  return 1;
}

/* ---- manifest ---- */

int fx_file_digest(const wchar_t *path, char *out, size_t cap, uint64_t *size)
{
  HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  uint8_t *buf, digest[32];
  sd_hash_ctx c;
  LARGE_INTEGER sz;
  int i;
  if (h == INVALID_HANDLE_VALUE)
    return 0;
  if (!GetFileSizeEx(h, &sz)) {
    CloseHandle(h);
    return 0;
  }
  buf = (uint8_t *)sd_alloc(65536);
  if (buf == NULL) {
    CloseHandle(h);
    return 0;
  }
  sd_hash_init(&c, SD_HASH_SHA256);
  for (;;) {
    DWORD got = 0;
    if (!ReadFile(h, buf, 65536, &got, NULL))
      break;
    if (got == 0)
      break;
    sd_hash_update(&c, buf, got);
  }
  sd_hash_final(&c, digest);
  sd_free(buf);
  CloseHandle(h);
  if (cap < 8 + 64 + 1)
    return 0;
  memcpy(out, "sha256:", 7);
  for (i = 0; i < 32; i++)
    sprintf_s(out + 7 + 2 * i, cap - 7 - (size_t)(2 * i), "%02x", digest[i]);
  if (size)
    *size = (uint64_t)sz.QuadPart;
  return 1;
}

size_t fx_manifest_body(char *out, size_t cap, const fx_manifest_opts *o)
{
  fx_text t;
  t.p = out;
  t.n = 0;
  t.cap = cap;
  int i;
  out[0] = '\0';
  fx_text_add(&t, "shelldrive-manifest 1\n");
  fx_text_add(&t, "product %s\n", o->product ? o->product : "com.librestatic.shelldrive");
  fx_text_add(&t, "channel %s\n", o->channel);
  fx_text_add(&t, "keyset %llu\n", (unsigned long long)o->keyset);
  fx_text_add(&t, "serial %llu\n", (unsigned long long)o->serial);
  fx_text_add(&t, "version %s\n", o->version);
  fx_text_add(&t, "released %s\n", o->released ? o->released : "2026-10-24T12:00:00Z");
  fx_text_add(&t, "expires %s\n", o->expires ? o->expires : "2026-11-23T00:00:00Z");
  fx_text_add(&t, "notes https://example.invalid/releases/%s\n", o->version);
  fx_text_add(&t, "base %s\n", o->base);
  for (i = 0; i < o->nfiles; i++) {
    char digest[80];
    uint64_t size = 0;
    if (!fx_file_digest(o->files[i].path, digest, sizeof(digest), &size))
      return 0;
    fx_text_add(&t, "file %s %s %llu %s\n", o->files[i].id, o->files[i].name, (unsigned long long)size, digest);
  }
  if (o->extra)
    fx_text_add(&t, "%s", o->extra);
  return t.n;
}

int fx_sign_manifest(fx *f, const char *body, size_t blen, const fx_key *k, uint8_t **out, size_t *olen)
{
  wchar_t in[MAX_PATH], res[MAX_PATH], args[2048];
  size_t n = 0;
  _snwprintf_s(in, SD_COUNTOF(in), _TRUNCATE, L"%ls\\manifest.body", f->dir);
  _snwprintf_s(res, SD_COUNTOF(res), _TRUNCATE, L"%ls\\manifest.txt", f->dir);
  if (!fx_write(in, body, blen))
    return 0;
  _snwprintf_s(args, SD_COUNTOF(args), _TRUNCATE, L"sign-manifest --in \"%ls\" --key \"%ls\" --out \"%ls\"", in,
               k->seed_path, res);
  if (!run_tool(f, args, NULL))
    return 0;
  if (!fx_read(res, out, &n))
    return 0;
  *olen = n;
  return 1;
}

/* ---- loopback server ---- */

#define LS(p) ((SOCKET)(p)->ls)

static int g_wsa_refs;

static const char *reason(int s)
{
  switch (s) {
  case 200: return "OK";
  case 302: return "Found";
  case 404: return "Not Found";
  default: return "Error";
  }
}

static void serve_one(fx_server *s, SOCKET c)
{
  char req[2048];
  int got = 0, i;
  const fx_route *hit = NULL;
  char path[512] = "";
  char head[512];
  int hl;
  while (got < (int)sizeof(req) - 1) {
    int r = recv(c, req + got, (int)sizeof(req) - 1 - got, 0);
    if (r <= 0)
      break;
    got += r;
    req[got] = '\0';
    if (strstr(req, "\r\n\r\n"))
      break;
  }
  if (sscanf_s(req, "GET %511s", path, (unsigned)sizeof(path)) != 1) {
    hl = _snprintf_s(head, sizeof(head), _TRUNCATE, "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    send(c, head, hl, 0);
    return;
  }
  s->served++;
  for (i = 0; i < s->nroutes; i++) {
    if (strcmp(s->routes[i].path, path) == 0) {
      hit = &s->routes[i];
      break;
    }
  }
  if (hit == NULL) {
    hl = _snprintf_s(head, sizeof(head), _TRUNCATE, "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    send(c, head, hl, 0);
    return;
  }
  {
    int status = hit->status ? hit->status : 200;
    unsigned long long cl = hit->declared ? hit->declared : (unsigned long long)hit->len;
    if (status == 302) {
      hl = _snprintf_s(head, sizeof(head), _TRUNCATE, "HTTP/1.1 302 %s\r\nLocation: %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                       reason(302), hit->location);
      send(c, head, hl, 0);
      return;
    }
    hl = _snprintf_s(head, sizeof(head), _TRUNCATE, "HTTP/1.1 %d %s\r\nContent-Length: %llu\r\nConnection: close\r\n\r\n",
                     status, reason(status), cl);
    send(c, head, hl, 0);
    {
      size_t off = 0;
      while (off < hit->len) {
        int w = send(c, (const char *)hit->body + off, (int)(hit->len - off), 0);
        if (w <= 0)
          break;
        off += (size_t)w;
      }
    }
  }
}

static DWORD WINAPI server_main(LPVOID arg)
{
  fx_server *s = (fx_server *)arg;
  while (!s->stop) {
    SOCKET c = accept(LS(s), NULL, NULL);
    if (c == INVALID_SOCKET)
      break;
    serve_one(s, c);
    closesocket(c);
  }
  return 0;
}

int fx_server_start(fx_server *s, const fx_route *routes, int n)
{
  WSADATA wd;
  struct sockaddr_in sa;
  int len = sizeof(sa);
  BOOL one = TRUE;
  memset(s, 0, sizeof(*s));
  if (g_wsa_refs++ == 0 && WSAStartup(MAKEWORD(2, 2), &wd) != 0) {
    g_wsa_refs--;
    return 0;
  }
  s->routes = routes;
  s->nroutes = n;
  s->ls = (uintptr_t)socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (LS(s) == INVALID_SOCKET)
    return 0;
  setsockopt(LS(s), SOL_SOCKET, SO_REUSEADDR, (const char *)&one, sizeof(one));
  memset(&sa, 0, sizeof(sa));
  sa.sin_family = AF_INET;
  sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  sa.sin_port = 0;
  if (bind(LS(s), (struct sockaddr *)&sa, sizeof(sa)) != 0 || listen(LS(s), 8) != 0)
    return 0;
  if (getsockname(LS(s), (struct sockaddr *)&sa, &len) != 0)
    return 0;
  s->port = ntohs(sa.sin_port);
  s->thread = CreateThread(NULL, 0, server_main, s, 0, NULL);
  return s->thread != NULL;
}

void fx_server_stop(fx_server *s)
{
  struct sockaddr_in sa;
  SOCKET c;
  if (s->thread == NULL)
    return;
  InterlockedExchange(&s->stop, 1);
  /* wake accept() with a throwaway connection, then close the listener */
  c = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (c != INVALID_SOCKET) {
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = htons(s->port);
    connect(c, (struct sockaddr *)&sa, sizeof(sa));
    closesocket(c);
  }
  WaitForSingleObject(s->thread, 10000);
  CloseHandle(s->thread);
  s->thread = NULL;
  closesocket(LS(s));
  if (--g_wsa_refs == 0)
    WSACleanup();
}
