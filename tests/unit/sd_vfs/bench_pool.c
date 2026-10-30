/* Striping bench (02 §5.6): 1 GiB written and then read through sd_vfs against the wsl-sshd
 * fixture (tests/fixtures/wsl-sshd), with a connections = 1 session versus a connections = 3
 * session whose large sequential writes the vfs strips across the pool (SD_SFTP_O_STRIPED).
 * Prints both MB/s pairs. Plain ctest skips it: the binary exits 77 unless SD_IT_BENCH=1 and the
 * fixture is up (start it with tests/fixtures/wsl-sshd/start.ps1). */
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
#include "sd_vfs/sd_vfs.h"

#define BENCH_BYTES (1024ull * 1024ull * 1024ull)
#define CHUNK (1024u * 1024u)

static char g_dir[MAX_PATH], g_user[64], g_key[MAX_PATH], g_hostkey[256];
static char g_host[64] = "127.0.0.1";
static wchar_t g_whost[64] = L"127.0.0.1";
static wchar_t g_wkey[MAX_PATH], g_kh_path[MAX_PATH];
static uint16_t g_port = 2222;

static void trim(char *s)
{
  size_t n = strlen(s);
  while (n && (s[n - 1] == '\r' || s[n - 1] == '\n' || s[n - 1] == ' ')) s[--n] = 0;
}

/* Fixture connection data (tests/fixtures/wsl-sshd/state/env; no secrets). */
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
    else if (strcmp(line, "key") == 0) _snprintf_s(g_key, sizeof(g_key), _TRUNCATE, "%s/state/%s", g_dir, eq + 1);
    else if (strcmp(line, "hostkey") == 0) _snprintf_s(g_hostkey, sizeof(g_hostkey), _TRUNCATE, "%s", eq + 1);
  }
  fclose(f);
  if (!g_user[0] || !g_key[0] || !g_hostkey[0]) return 0;
  MultiByteToWideChar(CP_UTF8, 0, g_key, -1, g_wkey, (int)SD_COUNTOF(g_wkey));
  return 1;
}

/* Dotted-quad parser (inet_pton is Vista+); host byte order. */
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

static void on_prompt(void *ctx, sd_prompt *p, const sd_auth_prompt_info *auth,
                      const sd_hostkey_prompt_info *hk)
{
  SD_UNUSED(ctx);
  SD_UNUSED(auth);
  SD_UNUSED(hk);
  sd_prompt_cancel(p);                   /* key auth: no prompt is expected */
}

static void ev_cb(void *ctx, const sd_sftp_event *ev)
{
  SD_UNUSED(ctx);
  SD_UNUSED(ev);
}

/* The vfs polls the session state; no event object is needed (same pattern as vfs_wait_online). */
static int wait_ready(sd_sftp_session *s, uint32_t ms)
{
  uint64_t end = sd_tick_ms() + ms;
  while (sd_sftp_session_state(s) != SD_SFTP_ST_READY) {
    if (sd_tick_ms() >= end) return 0;
    Sleep(100);
  }
  return 1;
}

static int wait_pool(sd_sftp_session *s, uint32_t want, uint32_t ms)
{
  sd_sftp_server_info info;
  uint64_t end = sd_tick_ms() + ms;
  for (;;) {
    if (sd_sftp_session_info(s, &info, NULL, 0) == SD_OK && info.connections >= want) return 1;
    if (sd_tick_ms() >= end) return 0;
    Sleep(100);
  }
}

typedef struct vev { LONG notices; } vev;

static void vfs_event(void *ctx, const sd_vfs_event *ev)
{
  vev *l = (vev *)ctx;
  if (ev->kind == SD_VFS_EV_NOTICE) InterlockedIncrement(&l->notices);
}

static void fill_pattern(uint8_t *p, uint32_t len)
{
  uint32_t i;
  for (i = 0; i < len; i++) p[i] = (uint8_t)(i * 31u + 1);
}

/* One session, one mount, 1 GiB written and read back; returns 0 on failure. */
static int run_one(uint32_t connections, double *wr_mbs, double *rd_mbs)
{
  sd_ssh_config cfg;
  sd_ssh_hop hop;
  sd_ssh_identity id;
  sd_ssh_callbacks cb;
  sd_sftp_options opt;
  sd_kh_store st;
  sd_known_hosts *kh = NULL;
  sd_sftp_session *s = NULL;
  sd_vfs *v = NULL;
  sd_vfs_options vo;
  vev ve;
  sd_vfs_handle *h = NULL;
  static uint8_t buf[CHUNK];
  static char line[512];
  HANDLE fh;
  DWORD w;
  uint64_t off, t0;
  double sec;
  int ok = 0;
  memset(&ve, 0, sizeof(ve));
  memset(line, 0, sizeof(line));
  _snprintf_s(line, sizeof(line), _TRUNCATE, "[%s]:%u %s\n", g_host, (unsigned)g_port, g_hostkey);
  fh = CreateFileW(g_kh_path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
  if (fh == INVALID_HANDLE_VALUE) return 0;
  WriteFile(fh, line, (DWORD)strlen(line), &w, NULL);
  CloseHandle(fh);
  st.kind = SD_KH_STORE_USER;
  st.path = g_kh_path;
  st.writable = 1;
  if (sd_known_hosts_open(&st, 1, &kh) != SD_OK) goto out;
  memset(&cfg, 0, sizeof(cfg));
  memset(&hop, 0, sizeof(hop));
  memset(&id, 0, sizeof(id));
  memset(&cb, 0, sizeof(cb));
  id.kind = SD_ID_FILE;
  id.path = g_wkey;
  hop.host = g_whost;
  hop.port = g_port;
  hop.auth.user = g_user;
  hop.auth.identities = &id;
  hop.auth.identity_count = 1;
  hop.auth.methods = SD_AUTH_PUBLICKEY;
  hop.auth.identities_only = 1;
  cfg.struct_size = sizeof(cfg);
  cfg.hops = &hop;
  cfg.hop_count = 1;
  cfg.known_hosts = kh;
  cfg.connect_timeout_ms = 10000;
  cb.on_prompt = on_prompt;
  sd_sftp_options_init(&opt);
  opt.connections = connections;
  opt.default_timeout_ms = 30000;
  if (sd_sftp_session_create(&cfg, &cb, &opt, ev_cb, NULL, &s) != SD_OK) goto out;
  if (sd_sftp_session_start(s) != SD_OK) goto out;
  if (!wait_ready(s, 30000)) goto out;
  if (connections > 1 && !wait_pool(s, connections, 30000)) {
    printf("  pool never reached %u members\n", (unsigned)connections);
    goto out;
  }
  memset(&vo, 0, sizeof(vo));
  vo.struct_size = sizeof(vo);
  vo.request_timeout_ms = 30000;
  vo.write_mode = SD_VFS_WRITE_THROUGH;
  if (sd_vfs_mount(s, &vo, vfs_event, &ve, &v) != SD_VFS_OK) goto out;
  {
    BOOL existed = FALSE, is_dir = FALSE;
    if (sd_vfs_create(v, L"\\bench-1g.bin", NULL, GENERIC_WRITE, FILE_SHARE_READ, SD_VFS_FILE_CREATE,
                      SD_VFS_FILE_SEQUENTIAL_ONLY, 0, &h, &existed, &is_dir) != SD_VFS_OK)
      goto out;
  }
  fill_pattern(buf, CHUNK);
  t0 = sd_tick_ms();
  for (off = 0; off < BENCH_BYTES; off += CHUNK) {
    UINT32 done = 0;
    if (sd_vfs_write(h, off, buf, CHUNK, &done, FALSE) != SD_VFS_OK || done != CHUNK) {
      printf("  write failed at %llu\n", (unsigned long long)off);
      goto out_mounted;
    }
  }
  sec = (double)(sd_tick_ms() - t0) / 1000.0;
  *wr_mbs = (double)(BENCH_BYTES / (1024 * 1024)) / sec;
  sd_vfs_close(h);
  h = NULL;
  {
    BOOL existed = FALSE, is_dir = FALSE;
    if (sd_vfs_create(v, L"\\bench-1g.bin", NULL, GENERIC_READ, FILE_SHARE_WRITE, SD_VFS_FILE_OPEN_IF,
                      SD_VFS_FILE_SEQUENTIAL_ONLY, 0, &h, &existed, &is_dir) != SD_VFS_OK)
      goto out_mounted;
  }
  t0 = sd_tick_ms();
  for (off = 0; off < BENCH_BYTES; off += CHUNK) {
    UINT32 got = 0;
    uint32_t first = 0 * 31u + 1, last = (CHUNK - 1) * 31u + 1;
    if (sd_vfs_read(h, off, buf, CHUNK, &got) != SD_VFS_OK || got != CHUNK) {
      printf("  read failed at %llu\n", (unsigned long long)off);
      goto out_mounted;
    }
    if (buf[0] != (uint8_t)first || buf[CHUNK - 1] != (uint8_t)last) {
      printf("  read data mismatch at %llu\n", (unsigned long long)off);
      goto out_mounted;
    }
  }
  sec = (double)(sd_tick_ms() - t0) / 1000.0;
  *rd_mbs = (double)(BENCH_BYTES / (1024 * 1024)) / sec;
  ok = 1;
out_mounted:
  if (h) {
    sd_vfs_cleanup(h, TRUE);              /* delete the 1 GiB file again */
    sd_vfs_close(h);
  }
  sd_vfs_quiesce(v, 5000);
  sd_vfs_unmount(v);
out:
  if (s) {
    sd_sftp_session_close(s);
    sd_sftp_session_destroy(s);
  }
  if (kh) sd_known_hosts_close(kh);
  return ok;
}

int main(void)
{
  char flag[8];
  double wr1 = 0, rd1 = 0, wr3 = 0, rd3 = 0;
  int rc = 1;
  if (GetEnvironmentVariableA("SD_IT_BENCH", flag, sizeof(flag)) == 0 || strcmp(flag, "1") != 0) {
    printf("bench.vfs_pool skipped: set SD_IT_BENCH=1 to run the 1 GiB pool measurement\n");
    return 77;
  }
  {
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return 1;
  }
  if (!load_env()) {
    printf("bench.vfs_pool skipped: fixture environment not found\n");
    rc = 77;
    goto done;
  }
  if (!port_open()) {
    printf("bench.vfs_pool skipped: nothing listens on %s:%u (start tests/fixtures/wsl-sshd/start.ps1)\n",
           g_host, (unsigned)g_port);
    rc = 77;
    goto done;
  }
  _snwprintf_s(g_kh_path, SD_COUNTOF(g_kh_path), _TRUNCATE, L"%hs\\state\\bench_known_hosts", g_dir);
  printf("bench.vfs_pool: 1 GiB against %s:%u, connections=1 vs connections=3 striped\n",
         g_host, (unsigned)g_port);
  if (!run_one(1, &wr1, &rd1)) {
    printf("  connections=1 run failed\n");
    goto done;
  }
  printf("  connections=1: write %.1f MB/s, read %.1f MB/s\n", wr1, rd1);
  if (!run_one(3, &wr3, &rd3)) {
    printf("  connections=3 run failed\n");
    goto done;
  }
  printf("  connections=3 striped: write %.1f MB/s, read %.1f MB/s\n", wr3, rd3);
  printf("  pool speedup: write %.2fx, read %.2fx\n", wr1 > 0 ? wr3 / wr1 : 0, rd1 > 0 ? rd3 / rd1 : 0);
  rc = 0;
done:
  if (g_kh_path[0]) DeleteFileW(g_kh_path);
  WSACleanup();
  return rc;
}
