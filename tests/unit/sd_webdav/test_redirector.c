/* WebDAV redirector integration test (CTest label "webdav"): serves the fake-backed sd_vfs through
 * sd_webdav, maps it on a free drive letter with the real Windows WebDAV redirector (WebClient) and
 * drives it with plain Win32 file APIs: create/read/write, rename, delete, directories, listing, and a
 * large-file round trip with a checksum (64 MiB when FileSizeLimitInBytes allows it).
 * Exit code 77 = skipped: WebClient missing, disabled, or not startable without an administrator. */
#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <winnetwk.h>

#include "fake_sftp.h"
#include "sd_base/sd_mem.h"
#include "sd_platform/sd_log.h"
#include "sd_platform/sd_time.h"
#include "sd_test.h"
#include "sd_webdav/sd_webdav.h"

#define SKIP 77
#define BIG_SIZE (64u << 20)

static sd_sftp_session *g_s;
static sd_vfs *g_v;
static sd_webdav_server *g_srv;
static sd_webdav_export *g_ex;
static wchar_t g_letter;
static DWORD g_size_limit = 50000000;

static int make_download_files(void);

static void P(WCHAR *out, size_t cap, const WCHAR *rel)
{
  _snwprintf_s(out, cap, _TRUNCATE, L"%c:\\%s", g_letter, rel);
}

static uint64_t fnv(const uint8_t *p, size_t n, uint64_t h)
{
  size_t i;
  for (i = 0; i < n; i++) {
    h ^= p[i];
    h *= 1099511628211ull;
  }
  return h;
}

static void fill_pattern(uint8_t *b, size_t n, uint64_t off)
{
  size_t i;
  for (i = 0; i < n; i++)
    b[i] = (uint8_t)((off + i) * 2654435761u >> 13);
}

static DWORD read_limit(void)
{
  HKEY k;
  DWORD v = 50000000, t, sz = sizeof(v);
  if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\WebClient\\Parameters", 0, KEY_QUERY_VALUE,
                    &k) == ERROR_SUCCESS) {
    if (RegQueryValueExW(k, L"FileSizeLimitInBytes", NULL, &t, (BYTE *)&v, &sz) != ERROR_SUCCESS || t != REG_DWORD)
      v = 50000000;
    RegCloseKey(k);
  }
  return v;
}

static int setup(void)
{
  sd_vfs_options o;
  sd_webdav_server_cfg sc;
  sd_webdav_export_cfg ec;
  sd_webdav_client_info ci;
  DWORD drives, werr = 0;
  int letter;
  sd_err e;
  fake_config fc;
  e = sd_webdav_ensure_client(15000, &ci);
  printf("webdav: WebClient state=%d start_type=%lu trigger=%d started_by_us=%d needs_admin=%d err=%lu -> %s\n",
         (int)ci.state, (unsigned long)ci.start_type, (int)ci.trigger_start, (int)ci.started_by_us,
         (int)ci.needs_admin, (unsigned long)ci.error, sd_err_name(e));
  if (e != SD_OK)
    return SKIP;
  g_size_limit = read_limit();
  printf("webdav: FileSizeLimitInBytes = %lu\n", (unsigned long)g_size_limit);
  memset(&fc, 0, sizeof(fc));
  fc.max_read = fc.max_write = 256u * 1024u;
  g_s = fake_session_create(&fc);
  fake_put(g_s, "/home/user/hello.txt", "hello world", 11, 0644);
  fake_mkdir(g_s, "/home/user/docs", 0755);
  fake_put(g_s, "/home/user/docs/a.txt", "AAAA", 4, 0644);
  if (make_download_files() != 0)
    return 1;
  memset(&o, 0, sizeof(o));
  o.struct_size = sizeof(o);
  o.hide_dotfiles = TRUE;
  o.map_readonly = TRUE;
  o.allow_system = TRUE;
  o.fsync_on_flush = TRUE;
  o.request_timeout_ms = 50000;
  o.volume_label = L"SD WebDAV";
  if (sd_vfs_mount(g_s, &o, NULL, NULL, &g_v) != SD_VFS_OK)
    return 1;
  memset(&sc, 0, sizeof(sc));
  sc.struct_size = sizeof(sc);
  if (sd_webdav_server_start(&sc, &g_srv) != SD_OK)
    return 1;
  memset(&ec, 0, sizeof(ec));
  ec.struct_size = sizeof(ec);
  ec.label = L"SD WebDAV test";
  if (sd_webdav_export_add(g_srv, g_v, &ec, &g_ex) != SD_OK)
    return 1;
  drives = GetLogicalDrives();
  e = SD_E_FAILURE;
  for (letter = 'Y'; letter >= 'M'; letter--) {
    if (drives & (1u << (letter - 'A')))
      continue;
    e = sd_webdav_map(g_ex, (wchar_t)letter, &werr);
    if (e != SD_E_EXISTS)
      break;
  }
  {
    wchar_t unc[128];
    sd_webdav_export_remote_name(g_ex, FALSE, unc, SD_COUNTOF(unc));
    printf("webdav: mapping %c: -> %ls : %s (WNet error %lu)\n", letter, unc, sd_err_name(e), (unsigned long)werr);
  }
  if (e != SD_OK)
    return 1;
  g_letter = (wchar_t)letter;
  return 0;
}

static void teardown(void)
{
  if (g_letter) sd_webdav_unmap(g_ex, g_letter);
  if (g_ex) sd_webdav_export_remove(g_ex);
  if (g_srv) sd_webdav_server_stop(g_srv);
  if (g_v) {
    sd_vfs_quiesce(g_v, 10000);
    sd_vfs_unmount(g_v);
  }
  if (g_s) fake_session_destroy(g_s);
}

SD_TEST(redirector_volume_and_listing)
{
  WCHAR p[MAX_PATH];
  WIN32_FIND_DATAW fd;
  HANDLE h;
  int saw_hello = 0, saw_docs = 0;
  ULARGE_INTEGER avail, total, freeb;
  P(p, MAX_PATH, L"*");
  h = FindFirstFileW(p, &fd);
  SD_REQUIRE(h != INVALID_HANDLE_VALUE);
  do {
    if (wcscmp(fd.cFileName, L"hello.txt") == 0) {
      saw_hello = 1;
      SD_CHECK(fd.nFileSizeLow == 11);
    }
    if (wcscmp(fd.cFileName, L"docs") == 0) {
      saw_docs = 1;
      SD_CHECK((fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0);
    }
  } while (FindNextFileW(h, &fd));
  FindClose(h);
  SD_CHECK(saw_hello && saw_docs);
  P(p, MAX_PATH, L"");
  SD_CHECK(GetDiskFreeSpaceExW(p, &avail, &total, &freeb));
}

SD_TEST(redirector_read_write_rename_delete)
{
  WCHAR p[MAX_PATH], q[MAX_PATH];
  HANDLE f;
  char buf[64];
  DWORD n = 0;
  long long len;
  P(p, MAX_PATH, L"hello.txt");
  f = CreateFileW(p, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
  SD_REQUIRE(f != INVALID_HANDLE_VALUE);
  SD_CHECK(ReadFile(f, buf, sizeof(buf), &n, NULL) && n == 11 && memcmp(buf, "hello world", 11) == 0);
  CloseHandle(f);
  /* create + write; the redirector uploads on close */
  P(p, MAX_PATH, L"new file.txt");
  f = CreateFileW(p, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
  SD_REQUIRE(f != INVALID_HANDLE_VALUE);
  SD_CHECK(WriteFile(f, "written via redirector", 22, &n, NULL) && n == 22);
  SD_CHECK(CloseHandle(f));
  len = fake_get(g_s, "/home/user/new file.txt", buf, sizeof(buf));
  SD_CHECK(len == 22 && memcmp(buf, "written via redirector", 22) == 0);
  /* overwrite an existing file */
  f = CreateFileW(p, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  SD_REQUIRE(f != INVALID_HANDLE_VALUE);
  SD_CHECK(WriteFile(f, "v2", 2, &n, NULL) && n == 2);
  SD_CHECK(CloseHandle(f));
  len = fake_get(g_s, "/home/user/new file.txt", buf, sizeof(buf));
  SD_CHECK(len == 2 && memcmp(buf, "v2", 2) == 0);
  /* rename */
  P(q, MAX_PATH, L"renamed \x00e9.txt");
  SD_CHECK(MoveFileW(p, q));
  SD_CHECK(!fake_exists(g_s, "/home/user/new file.txt"));
  SD_CHECK(fake_exists(g_s, "/home/user/renamed \xC3\xA9.txt"));
  SD_CHECK(GetFileAttributesW(q) != INVALID_FILE_ATTRIBUTES);
  /* delete */
  SD_CHECK(DeleteFileW(q));
  SD_CHECK(!fake_exists(g_s, "/home/user/renamed \xC3\xA9.txt"));
  SD_CHECK(GetFileAttributesW(q) == INVALID_FILE_ATTRIBUTES);
}

SD_TEST(redirector_directories)
{
  WCHAR p[MAX_PATH], q[MAX_PATH];
  HANDLE f;
  DWORD n;
  P(p, MAX_PATH, L"dir A");
  SD_REQUIRE(CreateDirectoryW(p, NULL));
  SD_CHECK(fake_exists(g_s, "/home/user/dir A"));
  SD_CHECK((GetFileAttributesW(p) & FILE_ATTRIBUTE_DIRECTORY) != 0);
  P(q, MAX_PATH, L"dir A\\inner.txt");
  f = CreateFileW(q, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
  SD_REQUIRE(f != INVALID_HANDLE_VALUE);
  SD_CHECK(WriteFile(f, "in", 2, &n, NULL));
  CloseHandle(f);
  SD_CHECK(fake_exists(g_s, "/home/user/dir A/inner.txt"));
  P(q, MAX_PATH, L"dir B");
  SD_CHECK(MoveFileW(p, q));
  SD_CHECK(fake_exists(g_s, "/home/user/dir B/inner.txt"));
  P(p, MAX_PATH, L"dir B\\inner.txt");
  SD_CHECK(DeleteFileW(p));
  SD_CHECK(RemoveDirectoryW(q));
  SD_CHECK(!fake_exists(g_s, "/home/user/dir B"));
}

static int write_big(const WCHAR *path, uint32_t size, uint64_t *sum, DWORD *err)
{
  HANDLE f = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  uint8_t *buf = (uint8_t *)sd_alloc(1u << 20);
  uint64_t h = 1469598103934665603ull, off = 0;
  int ok = 1;
  *err = 0;
  if (f == INVALID_HANDLE_VALUE || buf == NULL) {
    *err = GetLastError();
    sd_free(buf);
    return 0;
  }
  while (off < size) {
    DWORD chunk = (DWORD)SD_MIN((uint64_t)(1u << 20), size - off), n = 0;
    fill_pattern(buf, chunk, off);
    h = fnv(buf, chunk, h);
    if (!WriteFile(f, buf, chunk, &n, NULL) || n != chunk) {
      *err = GetLastError();
      ok = 0;
      break;
    }
    off += chunk;
  }
  if (!CloseHandle(f) && ok) {
    *err = GetLastError();
    ok = 0;
  }
  sd_free(buf);
  *sum = h;
  return ok;
}

static uint64_t read_sum(const WCHAR *path, uint64_t *size, DWORD *err)
{
  HANDLE f = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
  uint8_t *buf = (uint8_t *)sd_alloc(1u << 20);
  uint64_t h = 1469598103934665603ull;
  DWORD got;
  *size = 0;
  *err = 0;
  if (f == INVALID_HANDLE_VALUE || buf == NULL) {
    *err = GetLastError();
    if (f != INVALID_HANDLE_VALUE) CloseHandle(f);
    sd_free(buf);
    return 0;
  }
  for (;;) {
    if (!ReadFile(f, buf, 1u << 20, &got, NULL)) {
      *err = GetLastError();
      break;
    }
    if (got == 0)
      break;
    h = fnv(buf, got, h);
    *size += got;
  }
  CloseHandle(f);
  sd_free(buf);
  return h;
}

/* Download sources are created on the backend before the mount, so no cache knows them: reading
   them through the drive makes the redirector GET them from the server. */
static uint32_t g_down_size;
static uint64_t g_down_sum;

static int make_download_files(void)
{
  uint8_t *buf = (uint8_t *)sd_alloc(BIG_SIZE);
  int rc = 0;
  if (buf == NULL)
    return -1;
  fill_pattern(buf, BIG_SIZE, 7);
  g_down_size = BIG_SIZE <= g_size_limit ? BIG_SIZE : g_size_limit - 1u;
  g_down_sum = fnv(buf, g_down_size, 1469598103934665603ull);
  if (fake_put(g_s, "/home/user/down.bin", buf, g_down_size, 0644) != 0)
    rc = -1;
  if (BIG_SIZE > g_size_limit && fake_put(g_s, "/home/user/over.bin", buf, BIG_SIZE, 0644) != 0)
    rc = -1;
  sd_free(buf);
  return rc;
}

SD_TEST(redirector_large_file_round_trip)
{
  WCHAR p[MAX_PATH], q[MAX_PATH];
  uint64_t wsum = 0, rsum, rsize, t0;
  DWORD err = 0;
  P(p, MAX_PATH, L"big.bin");
  /* upload: 64 MiB through the drive; the redirector PUTs the whole file when the handle closes */
  t0 = sd_tick_ms();
  SD_REQUIRE(write_big(p, BIG_SIZE, &wsum, &err));
  printf("webdav: uploaded %u bytes through the redirector in %llu ms\n", (unsigned)BIG_SIZE,
         (unsigned long long)(sd_tick_ms() - t0));
  {
    uint8_t *buf = (uint8_t *)sd_alloc(BIG_SIZE);
    long long n;
    SD_REQUIRE(buf != NULL);
    n = fake_get(g_s, "/home/user/big.bin", buf, BIG_SIZE);
    SD_CHECK(n == (long long)BIG_SIZE);
    if (n == (long long)BIG_SIZE)
      SD_CHECK(fnv(buf, BIG_SIZE, 1469598103934665603ull) == wsum);   /* bytes reached the vfs backend */
    sd_free(buf);
  }
  /* download through the server (GET) */
  P(q, MAX_PATH, L"down.bin");
  t0 = sd_tick_ms();
  rsum = read_sum(q, &rsize, &err);
  printf("webdav: downloaded %llu bytes through the redirector in %llu ms (error %lu)\n", (unsigned long long)rsize,
         (unsigned long long)(sd_tick_ms() - t0), (unsigned long)err);
  SD_CHECK_EQ_U64(rsize, g_down_size);
  SD_CHECK(rsum == g_down_sum);
  if (BIG_SIZE > g_size_limit) {
    /* FileSizeLimitInBytes limits downloads only (02 §7.1): 0x800700DF above it. The installer's
       WEBDAV_TUNING raises it; this machine has the default, so the 64 MiB download is refused. */
    P(q, MAX_PATH, L"over.bin");
    read_sum(q, &rsize, &err);
    printf("webdav: 64 MiB download with FileSizeLimitInBytes=%lu -> error %lu\n", (unsigned long)g_size_limit,
           (unsigned long)err);
    SD_CHECK(err == ERROR_FILE_TOO_LARGE);
  } else {
    /* full 64 MiB round trip: read the uploaded file back */
    rsum = read_sum(p, &rsize, &err);
    SD_CHECK_EQ_U64(rsize, BIG_SIZE);
    SD_CHECK(rsum == wsum);
  }
  SD_CHECK(DeleteFileW(p));
  SD_CHECK(!fake_exists(g_s, "/home/user/big.bin"));
}

SD_TEST(redirector_label_and_stale_cleanup)
{
  wchar_t key[256], label[64], drive[4];
  DWORD sz = sizeof(label), t;
  HKEY k;
  uint32_t removed = 0;
  _snwprintf_s(key, SD_COUNTOF(key), _TRUNCATE,
               L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2\\##localhost@%u#DavWWWRoot#%S",
               (unsigned)sd_webdav_server_port(g_srv), sd_webdav_export_prefix(g_ex) + 1);
  SD_REQUIRE(RegOpenKeyExW(HKEY_CURRENT_USER, key, 0, KEY_QUERY_VALUE, &k) == ERROR_SUCCESS);
  SD_CHECK(RegQueryValueExW(k, L"_LabelFromReg", NULL, &t, (BYTE *)label, &sz) == ERROR_SUCCESS && t == REG_SZ &&
           wcscmp(label, L"SD WebDAV test") == 0);
  RegCloseKey(k);
  {
    /* the short form the redirector reports (\\localhost@PORT\s-<token>) carries the label too */
    wchar_t key2[256];
    _snwprintf_s(key2, SD_COUNTOF(key2), _TRUNCATE,
                 L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2\\##localhost@%u#%S",
                 (unsigned)sd_webdav_server_port(g_srv), sd_webdav_export_prefix(g_ex) + 1);
    k = NULL;
    SD_CHECK(RegOpenKeyExW(HKEY_CURRENT_USER, key2, 0, KEY_QUERY_VALUE, &k) == ERROR_SUCCESS);
    if (k) RegCloseKey(k);
  }
  /* TM-R17: the cleanup removes mappings of a given port (watchers) and their MountPoints2 entry */
  SD_CHECK(sd_webdav_cleanup_mappings(0, sd_webdav_server_port(g_srv), &removed) == SD_OK);
  SD_CHECK(removed >= 1);
  _snwprintf_s(drive, SD_COUNTOF(drive), _TRUNCATE, L"%c:\\", g_letter);
  SD_CHECK(GetDriveTypeW(drive) == DRIVE_NO_ROOT_DIR);
  SD_CHECK(RegOpenKeyExW(HKEY_CURRENT_USER, key, 0, KEY_QUERY_VALUE, &k) != ERROR_SUCCESS);
  g_letter = 0;
}

/* Informational: which remote-name forms the redirector accepts on this OS (02 §7.1 lab item). */
static void probe_unc_forms(void)
{
  static const wchar_t *const fmts[] = {
    L"\\\\localhost@%u\\DavWWWRoot\\%S",
    L"\\\\localhost@%u\\%S",
    L"\\\\127.0.0.1@%u\\DavWWWRoot\\%S",
    L"http://localhost:%u/%S",
  };
  DWORD drives = GetLogicalDrives();
  wchar_t letter = 0, remote[160], local[3];
  int l;
  size_t i;
  for (l = 'L'; l >= 'G' && !letter; l--)
    if (!(drives & (1u << (l - 'A'))) && l != g_letter) letter = (wchar_t)l;
  if (!letter)
    return;
  local[0] = letter; local[1] = L':'; local[2] = 0;
  for (i = 0; i < SD_COUNTOF(fmts); i++) {
    NETRESOURCEW nr;
    DWORD rc, attrs;
    _snwprintf_s(remote, SD_COUNTOF(remote), _TRUNCATE, fmts[i], (unsigned)sd_webdav_server_port(g_srv),
                 sd_webdav_export_prefix(g_ex) + 1);
    memset(&nr, 0, sizeof(nr));
    nr.dwType = RESOURCETYPE_DISK;
    nr.lpLocalName = local;
    nr.lpRemoteName = remote;
    rc = WNetAddConnection2W(&nr, NULL, NULL, 0);
    attrs = INVALID_FILE_ATTRIBUTES;
    if (rc == NO_ERROR) {
      wchar_t probe[16];
      _snwprintf_s(probe, SD_COUNTOF(probe), _TRUNCATE, L"%c:\\hello.txt", letter);
      attrs = GetFileAttributesW(probe);
    }
    printf("webdav: form %ls -> WNet %lu, hello.txt %s\n", fmts[i], (unsigned long)rc,
           attrs != INVALID_FILE_ATTRIBUTES ? "visible" : "not visible");
    if (rc == NO_ERROR)
      rc = WNetCancelConnection2W(local, 0, TRUE);
  }
  /* Explorer may have recorded MountPoints2 entries for the probed forms: remove them */
  sd_webdav_cleanup_mappings(0, sd_webdav_server_port(g_srv), NULL);
}

static const sd_test_case k_tests[] = {
  SD_TEST_ENTRY(redirector_volume_and_listing),
  SD_TEST_ENTRY(redirector_read_write_rename_delete),
  SD_TEST_ENTRY(redirector_directories),
  SD_TEST_ENTRY(redirector_large_file_round_trip),
  SD_TEST_ENTRY(redirector_label_and_stale_cleanup),
};

/* Counts "request <METHOD> -> <status>" debug lines: which methods the redirector used on this OS. */
typedef struct seen { char key[48]; uint32_t n; } seen;
static seen g_seen[64];
static uint32_t g_nseen;

static void count_sink(void *ctx, sd_log_level level, const char *line, size_t len)
{
  const char *p = NULL;
  size_t i, k;
  SD_UNUSED(ctx);
  SD_UNUSED(level);
  for (i = 0; i + 8 < len; i++)
    if (memcmp(line + i, "request ", 8) == 0) { p = line + i + 8; break; }
  if (p == NULL)
    return;
  k = (size_t)(line + len - p);
  if (k >= sizeof(g_seen[0].key)) k = sizeof(g_seen[0].key) - 1;
  for (i = 0; i < g_nseen; i++)
    if (strlen(g_seen[i].key) == k && memcmp(g_seen[i].key, p, k) == 0) { g_seen[i].n++; return; }
  if (g_nseen < SD_COUNTOF(g_seen)) {
    memcpy(g_seen[g_nseen].key, p, k);
    g_seen[g_nseen].key[k] = 0;
    g_seen[g_nseen++].n = 1;
  }
}

int main(int argc, char **argv)
{
  int rc;
  uint32_t i;
  sd_log_set_level(SD_LOG_DEBUG);
  sd_log_add_sink(count_sink, NULL);
  rc = setup();
  if (rc != 0) {
    teardown();
    return rc;
  }
  rc = sd_test_main(k_tests, SD_COUNTOF(k_tests), argc, argv);
  probe_unc_forms();                       /* after the tests: its cleanup removes this port's mappings */
  teardown();
  sd_log_remove_sink(count_sink, NULL);
  printf("webdav: requests seen from the redirector:");
  for (i = 0; i < g_nseen; i++)
    printf(" [%s] x%u", g_seen[i].key, (unsigned)g_seen[i].n);
  printf("\n");
  return rc;
}
