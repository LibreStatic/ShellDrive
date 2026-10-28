/* Dokany integration test (CTest label "dokany"): mounts the fake-backed sd_vfs on a free drive
 * letter with a current-session mount, drives it through plain Win32 file APIs, copies a 256 MiB
 * file in and out with a checksum, then unmounts from this (control) thread.
 * Exit code 77 = skipped (no usable Dokany 2.1+ on this machine, or the mount was refused). */
#include <windows.h>
#include <stdio.h>
#include <string.h>

#include "fake_sftp.h"
#include "sd_base/sd_mem.h"
#include "sd_dokan/sd_dokan.h"
#include "sd_platform/sd_time.h"
#include "sd_test.h"

#define SKIP 77
#define BIG_SIZE (256u << 20)

static sd_sftp_session *g_s;
static sd_vfs *g_v;
static sd_dokan_mount *g_m;
static WCHAR g_drive[4] = L"?:\\";
static volatile LONG g_unmounted;

static void on_unmounted(void *ctx, sd_dokan_mount *m)
{
  SD_UNUSED(ctx);
  SD_UNUSED(m);
  InterlockedExchange(&g_unmounted, 1);    /* post only (C33) */
}

static void P(WCHAR *out, size_t cap, const WCHAR *rel)
{
  _snwprintf_s(out, cap, _TRUNCATE, L"%c:\\%s", g_drive[0], rel);
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

static uint64_t file_checksum(const WCHAR *path, uint64_t *size)
{
  HANDLE f = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
  static uint8_t buf[1 << 20];
  uint64_t h = 1469598103934665603ull;
  DWORD got;
  *size = 0;
  if (f == INVALID_HANDLE_VALUE)
    return 0;
  while (ReadFile(f, buf, sizeof(buf), &got, NULL) && got > 0) {
    h = fnv(buf, got, h);
    *size += got;
  }
  CloseHandle(f);
  return h;
}

static int mount_it(void)
{
  sd_vfs_options o;
  sd_dokan_mount_cfg cfg;
  DWORD drives = GetLogicalDrives();
  int letter;
  sd_err e = SD_E_FAILURE;
  uint64_t end;
  g_s = fake_session_create(NULL);
  fake_put(g_s, "/home/user/hello.txt", "hello world", 11, 0644);
  fake_mkdir(g_s, "/home/user/docs", 0755);
  fake_put(g_s, "/home/user/docs/a.txt", "AAAA", 4, 0644);
  fake_put(g_s, "/home/user/a:b", "colon", 5, 0644);
  fake_put(g_s, "/home/user/README", "upper", 5, 0644);
  fake_put(g_s, "/home/user/readme", "lower", 5, 0644);
  memset(&o, 0, sizeof(o));
  o.struct_size = sizeof(o);
  o.hide_dotfiles = TRUE;
  o.map_readonly = TRUE;
  o.allow_system = TRUE;
  o.fsync_on_flush = TRUE;
  o.symlinks = SD_SYMLINK_FOLLOW_INSIDE;
  o.request_timeout_ms = 25000;
  o.volume_label = L"SD Test";
  if (sd_vfs_mount(g_s, &o, NULL, NULL, &g_v) != SD_VFS_OK)
    return 0;
  memset(&cfg, 0, sizeof(cfg));
  cfg.struct_size = sizeof(cfg);
  cfg.current_session = TRUE;
  cfg.timeout_ms = 30000;
  for (letter = 'Z'; letter >= 'M'; letter--) {
    if (drives & (1u << (letter - 'A')))
      continue;
    g_drive[0] = (WCHAR)letter;
    cfg.mount_point = g_drive;
    e = sd_dokan_mount_start(g_v, &cfg, on_unmounted, NULL, &g_m);
    if (e == SD_OK)
      break;
  }
  if (e != SD_OK) {
    printf("dokany: mount refused (%s)\n", sd_err_name(e));
    return 0;
  }
  end = sd_tick_ms() + 15000;
  while (GetFileAttributesW(g_drive) == INVALID_FILE_ATTRIBUTES && sd_tick_ms() < end)
    Sleep(100);
  printf("dokany: mounted at %c: (non-elevated current-session mount)\n", (char)g_drive[0]);
  return GetFileAttributesW(g_drive) != INVALID_FILE_ATTRIBUTES;
}

SD_TEST(dokany_volume_information)
{
  WCHAR label[64], fs[32];
  DWORD serial = 0, maxc = 0, flags = 0;
  ULARGE_INTEGER avail, total, freeb;
  SD_REQUIRE(GetVolumeInformationW(g_drive, label, 64, &serial, &maxc, &flags, fs, 32));
  SD_CHECK(wcscmp(fs, L"NTFS") == 0);                  /* D23 */
  SD_CHECK(wcscmp(label, L"SD Test") == 0);
  SD_CHECK_EQ_INT(maxc, 255);
  SD_CHECK((flags & FILE_CASE_PRESERVED_NAMES) && (flags & FILE_UNICODE_ON_DISK));
  SD_CHECK(!(flags & FILE_CASE_SENSITIVE_SEARCH));
  SD_REQUIRE(GetDiskFreeSpaceExW(g_drive, &avail, &total, &freeb));
  SD_CHECK_EQ_U64(total.QuadPart, 1000000ull * 4096);   /* statvfs@openssh.com of the fake */
  SD_CHECK_EQ_U64(avail.QuadPart, 400000ull * 4096);
}

SD_TEST(dokany_create_write_read)
{
  WCHAR p[MAX_PATH];
  HANDLE f;
  DWORD n = 0;
  char buf[64];
  P(p, MAX_PATH, L"new.txt");
  f = CreateFileW(p, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
  SD_REQUIRE(f != INVALID_HANDLE_VALUE);
  SD_CHECK(WriteFile(f, "written via dokany", 18, &n, NULL) && n == 18);
  SD_CHECK(FlushFileBuffers(f));
  CloseHandle(f);
  SD_CHECK_EQ_INT(fake_get(g_s, "/home/user/new.txt", buf, sizeof(buf)), 18);
  SD_CHECK_MEM(buf, "written via dokany", 18);
  /* CREATE_NEW on an existing file fails with ERROR_FILE_EXISTS. */
  f = CreateFileW(p, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
  SD_CHECK(f == INVALID_HANDLE_VALUE && GetLastError() == ERROR_FILE_EXISTS);
  /* OPEN_ALWAYS on an existing file: ERROR_ALREADY_EXISTS (STATUS_OBJECT_NAME_COLLISION mapping). */
  f = CreateFileW(p, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_ALWAYS, 0, NULL);
  SD_REQUIRE(f != INVALID_HANDLE_VALUE);
  SD_CHECK(GetLastError() == ERROR_ALREADY_EXISTS);
  SD_CHECK(SetFilePointer(f, 0, NULL, FILE_END) == 18);
  SD_CHECK(WriteFile(f, "!", 1, &n, NULL) && n == 1);
  SD_CHECK(SetFilePointer(f, 0, NULL, FILE_BEGIN) == 0);
  memset(buf, 0, sizeof(buf));
  SD_CHECK(ReadFile(f, buf, sizeof(buf), &n, NULL) && n == 19);
  SD_CHECK_MEM(buf, "written via dokany!", 19);
  CloseHandle(f);
  /* Case-insensitive open of a remote name. */
  P(p, MAX_PATH, L"HELLO.TXT");
  f = CreateFileW(p, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
  SD_REQUIRE(f != INVALID_HANDLE_VALUE);
  SD_CHECK(ReadFile(f, buf, sizeof(buf), &n, NULL) && n == 11);
  SD_CHECK_MEM(buf, "hello world", 11);
  CloseHandle(f);
  P(p, MAX_PATH, L"missing.txt");
  SD_CHECK(GetFileAttributesW(p) == INVALID_FILE_ATTRIBUTES && GetLastError() == ERROR_FILE_NOT_FOUND);
  P(p, MAX_PATH, L"nodir\\missing.txt");
  SD_CHECK(GetFileAttributesW(p) == INVALID_FILE_ATTRIBUTES && GetLastError() == ERROR_PATH_NOT_FOUND);
}

SD_TEST(dokany_find_files)
{
  WCHAR p[MAX_PATH];
  WIN32_FIND_DATAW d;
  HANDLE fh;
  int hello = 0, docs = 0, colon = 0, upper = 0, mangled = 0, dot = 0, a = 0;
  P(p, MAX_PATH, L"*");
  fh = FindFirstFileW(p, &d);
  SD_REQUIRE(fh != INVALID_HANDLE_VALUE);
  do {
    if (wcscmp(d.cFileName, L"hello.txt") == 0) hello = d.nFileSizeLow == 11;
    if (wcscmp(d.cFileName, L"docs") == 0) docs = (d.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
    if (wcscmp(d.cFileName, L"a\xF03A" L"b") == 0) colon = 1;
    if (wcscmp(d.cFileName, L"README") == 0) upper = 1;
    if (wcscmp(d.cFileName, L"readme~c2") == 0) mangled = 1;
  } while (FindNextFileW(fh, &d));
  FindClose(fh);
  SD_CHECK(hello && docs && colon && upper && mangled);
  P(p, MAX_PATH, L"docs\\*");
  fh = FindFirstFileW(p, &d);
  SD_REQUIRE(fh != INVALID_HANDLE_VALUE);
  do {
    if (wcscmp(d.cFileName, L".") == 0 || wcscmp(d.cFileName, L"..") == 0) dot++;
    if (wcscmp(d.cFileName, L"a.txt") == 0) a = 1;
  } while (FindNextFileW(fh, &d));
  FindClose(fh);
  SD_CHECK(dot == 2 && a);
  P(p, MAX_PATH, L"*.txt");                       /* Dokany filters FindFiles by pattern */
  fh = FindFirstFileW(p, &d);
  SD_REQUIRE(fh != INVALID_HANDLE_VALUE);
  do {
    size_t n = wcslen(d.cFileName);
    SD_CHECK(n >= 4 && _wcsicmp(d.cFileName + n - 4, L".txt") == 0);
  } while (FindNextFileW(fh, &d));
  FindClose(fh);
}

SD_TEST(dokany_directory_ops_move_delete)
{
  WCHAR a[MAX_PATH], b[MAX_PATH], c[MAX_PATH], dir[MAX_PATH];
  HANDLE f;
  DWORD n;
  P(dir, MAX_PATH, L"work");
  SD_REQUIRE(CreateDirectoryW(dir, NULL));
  SD_CHECK(!CreateDirectoryW(dir, NULL) && GetLastError() == ERROR_ALREADY_EXISTS);
  SD_CHECK((fake_mode(g_s, "/home/user/work") & 0170000u) == 0040000u);
  P(a, MAX_PATH, L"work\\one.txt");
  P(b, MAX_PATH, L"work\\two.txt");
  P(c, MAX_PATH, L"moved.txt");
  f = CreateFileW(a, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
  SD_REQUIRE(f != INVALID_HANDLE_VALUE);
  WriteFile(f, "1", 1, &n, NULL);
  CloseHandle(f);
  f = CreateFileW(b, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
  SD_REQUIRE(f != INVALID_HANDLE_VALUE);
  WriteFile(f, "22", 2, &n, NULL);
  CloseHandle(f);
  SD_CHECK(!MoveFileExW(a, b, 0) && GetLastError() == ERROR_ALREADY_EXISTS);
  SD_CHECK(MoveFileExW(a, b, MOVEFILE_REPLACE_EXISTING));
  SD_CHECK(!fake_exists(g_s, "/home/user/work/one.txt"));
  SD_CHECK_EQ_INT(fake_get(g_s, "/home/user/work/two.txt", NULL, 0), 1);
  SD_CHECK(MoveFileExW(b, c, 0));                  /* across directories */
  SD_CHECK(fake_exists(g_s, "/home/user/moved.txt"));
  {
    WCHAR d2[MAX_PATH];
    P(d2, MAX_PATH, L"work2");
    SD_CHECK(MoveFileExW(dir, d2, 0));               /* directory rename */
    SD_CHECK(fake_exists(g_s, "/home/user/work2"));
    P(a, MAX_PATH, L"work2\\keep.txt");
    f = CreateFileW(a, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    SD_REQUIRE(f != INVALID_HANDLE_VALUE);
    CloseHandle(f);
    SD_CHECK(!RemoveDirectoryW(d2) && GetLastError() == ERROR_DIR_NOT_EMPTY);
    SD_CHECK(DeleteFileW(a));
    SD_CHECK(!fake_exists(g_s, "/home/user/work2/keep.txt"));
    SD_CHECK(RemoveDirectoryW(d2));
    SD_CHECK(!fake_exists(g_s, "/home/user/work2"));
  }
  SD_CHECK(DeleteFileW(c));
  SD_CHECK(!fake_exists(g_s, "/home/user/moved.txt"));
  SD_CHECK(!DeleteFileW(c) && GetLastError() == ERROR_FILE_NOT_FOUND);
  /* Read-only attribute round trip, and delete refused while it is set. */
  P(a, MAX_PATH, L"ro.txt");
  f = CreateFileW(a, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
  SD_REQUIRE(f != INVALID_HANDLE_VALUE);
  CloseHandle(f);
  SD_CHECK(SetFileAttributesW(a, FILE_ATTRIBUTE_READONLY));
  SD_CHECK((fake_mode(g_s, "/home/user/ro.txt") & 0222u) == 0);
  SD_CHECK((GetFileAttributesW(a) & FILE_ATTRIBUTE_READONLY) != 0);
  SD_CHECK(!DeleteFileW(a));
  SD_CHECK(SetFileAttributesW(a, FILE_ATTRIBUTE_NORMAL));
  SD_CHECK(DeleteFileW(a));
}

SD_TEST(dokany_copy_256mib_with_checksum)
{
  WCHAR tmp[MAX_PATH], src[MAX_PATH], back[MAX_PATH], dst[MAX_PATH], stem[64];
  LARGE_INTEGER qpc;
  HANDLE f;
  uint8_t *block = (uint8_t *)sd_alloc(1 << 20);
  uint32_t i, x = 0x9E3779B9u;
  uint64_t h_src = 1469598103934665603ull, h_remote, h_back, sz = 0, t0, t1, t2;
  DWORD n;
  long long rsz;
  SD_REQUIRE(block);
  /* the 256 MiB scratch files carry the PID and a stamp: a fixed name is shared by concurrent test runs */
  QueryPerformanceCounter(&qpc);
  _snwprintf_s(stem, SD_COUNTOF(stem), _TRUNCATE, L"%lu-%08lx", (unsigned long)GetCurrentProcessId(),
               (unsigned long)qpc.LowPart);
  GetTempPathW(MAX_PATH, tmp);
  _snwprintf_s(src, MAX_PATH, _TRUNCATE, L"%ssd-dokany-src-%s.bin", tmp, stem);
  _snwprintf_s(back, MAX_PATH, _TRUNCATE, L"%ssd-dokany-back-%s.bin", tmp, stem);
  P(dst, MAX_PATH, L"big.bin");
  f = CreateFileW(src, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY, NULL);
  SD_REQUIRE(f != INVALID_HANDLE_VALUE);
  for (i = 0; i < BIG_SIZE / (1u << 20); i++) {
    uint32_t k;
    for (k = 0; k < (1u << 20) / 4; k++) {
      x ^= x << 13; x ^= x >> 17; x ^= x << 5;
      ((uint32_t *)block)[k] = x;
    }
    h_src = fnv(block, 1 << 20, h_src);
    WriteFile(f, block, 1 << 20, &n, NULL);
  }
  CloseHandle(f);
  t0 = sd_tick_ms();
  SD_REQUIRE(CopyFileW(src, dst, FALSE));
  t1 = sd_tick_ms();
  rsz = fake_get(g_s, "/home/user/big.bin", NULL, 0);
  SD_CHECK_EQ_U64(rsz, BIG_SIZE);
  {
    /* The bytes that reached the "server", not the kernel cache above the drive. */
    uint8_t *remote = (uint8_t *)sd_alloc(BIG_SIZE);
    SD_REQUIRE(remote);
    SD_CHECK_EQ_U64(fake_get(g_s, "/home/user/big.bin", remote, BIG_SIZE), BIG_SIZE);
    SD_CHECK(fnv(remote, BIG_SIZE, 1469598103934665603ull) == h_src);
    sd_free(remote);
  }
  h_remote = file_checksum(dst, &sz);
  SD_CHECK_EQ_U64(sz, BIG_SIZE);
  SD_CHECK(h_remote == h_src);
  SD_REQUIRE(CopyFileW(dst, back, FALSE));
  t2 = sd_tick_ms();
  h_back = file_checksum(back, &sz);
  SD_CHECK_EQ_U64(sz, BIG_SIZE);
  SD_CHECK(h_back == h_src);
  printf("dokany: 256 MiB in %llu ms, out %llu ms\n", (unsigned long long)(t1 - t0),
         (unsigned long long)(t2 - t1));
  SD_CHECK(DeleteFileW(dst));
  DeleteFileW(src);
  DeleteFileW(back);
  sd_free(block);
}

static const sd_test_case k_tests[] = {
  SD_TEST_ENTRY(dokany_volume_information),
  SD_TEST_ENTRY(dokany_create_write_read),
  SD_TEST_ENTRY(dokany_find_files),
  SD_TEST_ENTRY(dokany_directory_ops_move_delete),
  SD_TEST_ENTRY(dokany_copy_256mib_with_checksum),
};

int main(int argc, char **argv)
{
  sd_dokan_probe_info info;
  int rc;
  uint64_t t;
  if (sd_dokan_probe(NULL, &info) != SD_DOKAN_OK) {
    printf("dokany: skipped (probe result %d, lib %u, driver %u, load error %lu)\n", (int)info.avail,
           (unsigned)info.lib_version, (unsigned)info.driver_version, (unsigned long)info.load_error);
    return SKIP;
  }
  printf("dokany: dokan2.dll %u, driver %u\n", (unsigned)info.lib_version, (unsigned)info.driver_version);
  sd_dokan_remove_stale_mounts();
  if (!mount_it()) {
    if (g_m) sd_dokan_mount_stop(g_m);
    if (g_v) sd_vfs_unmount(g_v);
    if (g_s) fake_session_destroy(g_s);
    printf("dokany: skipped (mount not possible here)\n");
    return SKIP;
  }
  rc = sd_test_main(k_tests, SD_COUNTOF(k_tests), argc, argv);
  /* Clean unmount from the control thread (C33): DokanCloseHandle waits for callbacks. */
  t = sd_tick_ms();
  sd_vfs_quiesce(g_v, 30000);
  sd_dokan_mount_stop(g_m);
  printf("dokany: unmounted in %llu ms (Unmounted callback %s)\n", (unsigned long long)(sd_tick_ms() - t),
         g_unmounted ? "seen" : "not seen");
  if (GetFileAttributesW(g_drive) != INVALID_FILE_ATTRIBUTES) {
    printf("dokany: drive still present after unmount\n");
    rc = 1;
  }
  sd_vfs_unmount(g_v);
  if (fake_open_handles(g_s) != 0) {
    printf("dokany: %u remote handles leaked\n", (unsigned)fake_open_handles(g_s));
    rc = 1;
  }
  fake_session_destroy(g_s);
  sd_dokan_shutdown();
  return rc;
}
