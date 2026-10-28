/* End-to-end tests of the setup engine in per-user and portable modes, into a temp folder.

   HKCU is redirected with RegOverridePredefKey to a throw-away key under HKCU\Software\ShellDriveTests, so
   the real Run key, Uninstall entries and account settings are never touched. Start menu shortcuts, the
   user-cleanup hook and the agent shutdown events are switched off (skip_* options): these tests must never
   change the account or stop a running agent. */
#include <windows.h>
#include <strsafe.h>
#include <string.h>
#include <stdio.h>

#include "setup_int.h"
#include "sd_test.h"
#include "test_common.h"

typedef LONG (WINAPI *sd_RegOverridePredefKey_t)(HKEY, HKEY);

/* The redirected HKCU for one test: its real-HKCU key is removed at the end. */
typedef struct fake_hkcu {
  HKEY key;
  wchar_t path[256];
  int active;
} fake_hkcu;

static int fake_hkcu_begin(fake_hkcu *f)
{
  wchar_t hex[40];
  sd_RegOverridePredefKey_t override_key =
    (sd_RegOverridePredefKey_t)sd_setup_proc(L"advapi32.dll", "RegOverridePredefKey");
  DWORD disp = 0;

  memset(f, 0, sizeof(*f));
  if (override_key == NULL) {
    fprintf(stderr, "RegOverridePredefKey not found\n");
    return 1;
  }
  if (sd_setup_random_hex(hex, SD_SETUP_COUNTOF_LOCAL(hex)) != 0)
    return 1;
  /* One level under HKCU: the key is removed by fake_hkcu_end with the same name. */
  StringCchPrintfW(f->path, SD_SETUP_COUNTOF_LOCAL(f->path), L"ShellDriveTest-%s", hex);
  {
    LONG crc = RegCreateKeyExW(HKEY_CURRENT_USER, f->path, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL,
                               &f->key, &disp);
    if (crc != ERROR_SUCCESS) {
      fprintf(stderr, "RegCreateKeyEx failed: %ld\n", (long)crc);
      return 1;
    }
  }
  {
    LONG orc = override_key(HKEY_CURRENT_USER, f->key);
    if (orc != ERROR_SUCCESS) {
      fprintf(stderr, "RegOverridePredefKey failed: %ld\n", (long)orc);
      RegCloseKey(f->key);
      f->key = NULL;
      return 1;
    }
  }
  f->active = 1;
  return 0;
}

/* Deletes name under parent and everything below it. Gives up on a child it cannot delete (no endless
   loop on a key that stays): the test then fails at the next check instead of hanging. */
static void reg_delete_tree(HKEY parent, const wchar_t *name)
{
  HKEY hk = NULL;
  wchar_t sub[256];
  DWORD len;
  int guard = 0;

  if (RegOpenKeyExW(parent, name, 0, KEY_ALL_ACCESS, &hk) != ERROR_SUCCESS)
    return;
  for (;;) {
    len = SD_SETUP_COUNTOF_LOCAL(sub);
    if (RegEnumKeyExW(hk, 0, sub, &len, NULL, NULL, NULL, NULL) != ERROR_SUCCESS)
      break;
    if (++guard > 4096)
      break;
    reg_delete_tree(hk, sub);
  }
  RegCloseKey(hk);
  RegDeleteKeyW(parent, name);
}

static void fake_hkcu_end(fake_hkcu *f)
{
  sd_RegOverridePredefKey_t override_key =
    (sd_RegOverridePredefKey_t)sd_setup_proc(L"advapi32.dll", "RegOverridePredefKey");
  if (f->active && override_key != NULL)
    override_key(HKEY_CURRENT_USER, NULL);
  if (f->key != NULL)
    RegCloseKey(f->key);
  f->key = NULL;
  f->active = 0;
  /* The real HKCU, now that the redirect is gone. */
  reg_delete_tree(HKEY_CURRENT_USER, f->path);
}

/* Reads an SZ value of the (redirected) HKCU; 1 when it has the expected text. */
static int reg_sz_is(const wchar_t *sub, const wchar_t *name, const wchar_t *expect)
{
  HKEY hk = NULL;
  wchar_t buf[512];
  DWORD type = 0, size = sizeof(buf);
  int ok = 0;

  if (RegOpenKeyExW(HKEY_CURRENT_USER, sub, 0, KEY_READ, &hk) != ERROR_SUCCESS)
    return 0;
  if (RegQueryValueExW(hk, name, NULL, &type, (BYTE *)buf, &size) == ERROR_SUCCESS && type == REG_SZ)
    ok = wcscmp(buf, expect) == 0;
  RegCloseKey(hk);
  return ok;
}

static int reg_value_exists(const wchar_t *sub, const wchar_t *name)
{
  HKEY hk = NULL;
  int ok;
  if (RegOpenKeyExW(HKEY_CURRENT_USER, sub, 0, KEY_READ, &hk) != ERROR_SUCCESS)
    return 0;
  ok = RegQueryValueExW(hk, name, NULL, NULL, NULL, NULL) == ERROR_SUCCESS;
  RegCloseKey(hk);
  return ok;
}

static int reg_key_exists(const wchar_t *sub)
{
  HKEY hk = NULL;
  if (RegOpenKeyExW(HKEY_CURRENT_USER, sub, 0, KEY_READ, &hk) != ERROR_SUCCESS)
    return 0;
  RegCloseKey(hk);
  return 1;
}

static int file_in(const wchar_t *dir, const wchar_t *leaf)
{
  wchar_t p[MAX_PATH];
  if (sd_setup_path_join(p, MAX_PATH, dir, leaf) != 0)
    return 0;
  return GetFileAttributesW(p) != INVALID_FILE_ATTRIBUTES;
}

/* A payload loaded from the fixture CAB, with its SHA-256. */
typedef struct test_payload {
  unsigned char *buf;
  size_t size;
  unsigned char sha[32];
  sd_setup_payload p;
} test_payload;

static int payload_load(const wchar_t *leaf, test_payload *tp)
{
  wchar_t path[MAX_PATH];
  memset(tp, 0, sizeof(*tp));
  test_fixture_path(leaf, path, MAX_PATH);
  if (test_read_file(path, &tp->buf, &tp->size) != 0)
    return 1;
  tp->p.data = tp->buf;
  tp->p.size = tp->size;
  sd_setup_sha256(tp->buf, tp->size, tp->sha);
  return 0;
}

static void payload_free(test_payload *tp)
{
  if (tp->buf != NULL)
    HeapFree(GetProcessHeap(), 0, tp->buf);
  tp->buf = NULL;
}

static void user_opts(sd_setup_install_opts *o, const test_payload *tp, const wchar_t *dir, const wchar_t *version)
{
  memset(o, 0, sizeof(*o));
  o->mode = SD_SETUP_MODE_USER;
  o->install_dir = dir;
  o->version = version;
  o->flavour = SD_SETUP_FL_X86_IA32;
  o->payload = &tp->p;
  o->expected_sha256 = tp->sha;
  o->autostart = 0;
  o->skip_shortcut = 1;
  o->skip_hooks = 1;
  o->skip_agents = 1;
  o->log_path = L"";
}

static void count_progress(void *ctx, sd_msg_id stage, const wchar_t *folder, unsigned pct)
{
  (void)stage;
  (void)folder;
  (void)pct;
  (*(unsigned *)ctx)++;
}

SD_TEST(setup_user_install_repair_uninstall)
{
  fake_hkcu f;
  test_payload tp;
  wchar_t base[MAX_PATH], app[MAX_PATH], slashed[MAX_PATH + 1];
  sd_setup_install_opts o;
  sd_setup_uninstall_opts uo;
  sd_setup_result r;
  unsigned progress_calls = 0;
  int rc;

  SD_REQUIRE(payload_load(L"payload-ok.cab", &tp) == 0);
  SD_REQUIRE(test_make_temp_dir(base, MAX_PATH) == 0);
  SD_REQUIRE(sd_setup_path_join(app, MAX_PATH, base, L"app") == 0);
  SD_REQUIRE(fake_hkcu_begin(&f) == 0);

  /* Install. */
  user_opts(&o, &tp, app, L"1.2.3");
  o.progress = count_progress;
  o.progress_ctx = &progress_calls;
  rc = sd_setup_install(&o, &r);
  if (rc != 0)
    sd_test_fail(sd_t_, __FILE__, __LINE__, "install failed: msg %lu, code %ld", (unsigned long)r.msg, r.code);
  SD_CHECK_EQ_INT(rc, 0);
  SD_CHECK_EQ_INT(r.count, 6);
  SD_CHECK(progress_calls > 0);
  SD_CHECK(file_in(app, L"shelldrive.exe"));
  SD_CHECK(file_in(app, L"shelldrive-ui.exe"));
  SD_CHECK(file_in(app, L"uninstall.exe"));
  SD_CHECK(reg_sz_is(L"Software\\LibreStatic\\ShellDrive", L"Version", L"1.2.3"));
  SD_CHECK(reg_sz_is(L"Software\\LibreStatic\\ShellDrive", L"Flavour", L"x86-ia32"));
  SD_CHECK(reg_sz_is(L"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\ShellDrive", L"DisplayName",
                     L"ShellDrive"));
  StringCchPrintfW(slashed, SD_SETUP_COUNTOF_LOCAL(slashed), L"%s\\", app);
  SD_CHECK(reg_sz_is(L"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\ShellDrive", L"InstallLocation",
                     slashed));
  SD_CHECK(!reg_value_exists(L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", L"ShellDrive"));

  /* Repair: the same version again. */
  rc = sd_setup_install(&o, &r);
  SD_CHECK_EQ_INT(rc, 0);
  SD_CHECK(file_in(app, L"shelldrive.exe"));

  /* Sign-in start is opt-in: it adds the Run value. */
  o.autostart = 1;
  rc = sd_setup_install(&o, &r);
  SD_CHECK_EQ_INT(rc, 0);
  SD_CHECK(reg_value_exists(L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", L"ShellDrive"));
  o.autostart = 0;

  /* Uninstall from the registered folder: files and registration go, the settings folder is not touched. */
  memset(&uo, 0, sizeof(uo));
  uo.install_dir = app;
  uo.skip_shortcut = 1;
  uo.skip_hooks = 1;
  uo.skip_agents = 1;
  uo.log_path = L"";
  rc = sd_setup_uninstall(&uo, &r);
  SD_CHECK_EQ_INT(rc, 0);
  SD_CHECK(!file_in(app, L"shelldrive.exe"));
  SD_CHECK(!reg_key_exists(L"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\ShellDrive"));
  SD_CHECK(!reg_key_exists(L"Software\\LibreStatic\\ShellDrive"));
  SD_CHECK(!reg_value_exists(L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", L"ShellDrive"));
  /* Our keys go completely, the CLSIDs with their InprocServer32 included (M4 open item 4). The shared parents
     (ContextMenuHandlers, shellex, the Windows This PC CLSID) stay: they are not ours to delete. */
  SD_CHECK(!reg_key_exists(L"Software\\Classes\\CLSID\\{C2A44993-862B-42AB-B40B-254EFB1F5C43}\\InprocServer32"));
  SD_CHECK(!reg_key_exists(L"Software\\Classes\\CLSID\\{C2A44993-862B-42AB-B40B-254EFB1F5C43}"));
  SD_CHECK(!reg_key_exists(L"Software\\Classes\\CLSID\\{5E1C7D02-3B8F-4A9E-9C61-7D24A0F3B5E8}\\InprocServer32"));
  SD_CHECK(!reg_key_exists(L"Software\\Classes\\CLSID\\{5E1C7D02-3B8F-4A9E-9C61-7D24A0F3B5E8}"));
  SD_CHECK(!reg_key_exists(L"Software\\Classes\\*\\shellex\\ContextMenuHandlers\\ShellDrive"));
  SD_CHECK(!reg_key_exists(L"Software\\Classes\\Drive\\shellex\\ContextMenuHandlers\\ShellDrive"));
  SD_CHECK(!reg_key_exists(L"Software\\Classes\\CLSID\\{20D04FE0-3AEA-1069-A2D8-08002B30309D}\\shellex\\ContextMenuHandlers\\ShellDrive"));
  SD_CHECK(reg_key_exists(L"Software\\Classes\\*\\shellex\\ContextMenuHandlers"));
  SD_CHECK(reg_key_exists(L"Software\\Classes\\CLSID\\{20D04FE0-3AEA-1069-A2D8-08002B30309D}\\shellex\\ContextMenuHandlers"));

  /* Uninstall again: nothing is registered any more. */
  memset(&uo, 0, sizeof(uo));
  uo.skip_shortcut = 1;
  uo.skip_hooks = 1;
  uo.skip_agents = 1;
  uo.log_path = L"";
  rc = sd_setup_uninstall(&uo, &r);
  SD_CHECK_EQ_INT(rc, SD_SETUP_EXIT_FATAL);
  SD_CHECK(r.msg == SD_MSG_INSTALLER_ERROR_NOT_INSTALLED);

  fake_hkcu_end(&f);
  payload_free(&tp);
  test_remove_tree(base);
}

SD_TEST(setup_user_newer_version_refused)
{
  fake_hkcu f;
  test_payload tp;
  wchar_t base[MAX_PATH], app[MAX_PATH];
  sd_setup_install_opts o;
  sd_setup_result r;
  int rc;

  SD_REQUIRE(payload_load(L"payload-ok.cab", &tp) == 0);
  SD_REQUIRE(test_make_temp_dir(base, MAX_PATH) == 0);
  SD_REQUIRE(sd_setup_path_join(app, MAX_PATH, base, L"app") == 0);
  SD_REQUIRE(fake_hkcu_begin(&f) == 0);

  user_opts(&o, &tp, app, L"2.0.0");
  SD_CHECK_EQ_INT(sd_setup_install(&o, &r), 0);

  user_opts(&o, &tp, app, L"1.0.0");
  rc = sd_setup_install(&o, &r);
  SD_CHECK_EQ_INT(rc, SD_SETUP_EXIT_NEWER);
  SD_CHECK(r.msg == SD_MSG_INSTALLER_ERROR_NEWER_INSTALLED);
  SD_CHECK(wcscmp(r.version, L"2.0.0") == 0);
  SD_CHECK(reg_sz_is(L"Software\\LibreStatic\\ShellDrive", L"Version", L"2.0.0"));

  /* /update allows the replacement. */
  o.update = 1;
  SD_CHECK_EQ_INT(sd_setup_install(&o, &r), 0);
  SD_CHECK(reg_sz_is(L"Software\\LibreStatic\\ShellDrive", L"Version", L"1.0.0"));

  fake_hkcu_end(&f);
  payload_free(&tp);
  test_remove_tree(base);
}

SD_TEST(setup_user_damaged_payload_refused)
{
  fake_hkcu f;
  test_payload tp;
  wchar_t base[MAX_PATH], app[MAX_PATH];
  sd_setup_install_opts o;
  sd_setup_result r;
  unsigned char wrong[32];

  SD_REQUIRE(payload_load(L"payload-ok.cab", &tp) == 0);
  SD_REQUIRE(test_make_temp_dir(base, MAX_PATH) == 0);
  SD_REQUIRE(sd_setup_path_join(app, MAX_PATH, base, L"app") == 0);
  SD_REQUIRE(fake_hkcu_begin(&f) == 0);

  memset(wrong, 0x11, sizeof(wrong));
  user_opts(&o, &tp, app, L"1.0.0");
  o.expected_sha256 = wrong;
  SD_CHECK_EQ_INT(sd_setup_install(&o, &r), SD_SETUP_EXIT_FATAL);
  SD_CHECK(r.msg == SD_MSG_INSTALLER_ERROR_PAYLOAD_DAMAGED);
  SD_CHECK(!file_in(app, L"shelldrive.exe"));
  SD_CHECK(!reg_key_exists(L"Software\\LibreStatic\\ShellDrive"));

  fake_hkcu_end(&f);
  payload_free(&tp);
  test_remove_tree(base);
}

SD_TEST(setup_user_traversal_refused)
{
  fake_hkcu f;
  test_payload tp;
  wchar_t base[MAX_PATH], app[MAX_PATH];
  sd_setup_install_opts o;
  sd_setup_result r;

  SD_REQUIRE(payload_load(L"payload-traversal.cab", &tp) == 0);
  SD_REQUIRE(test_make_temp_dir(base, MAX_PATH) == 0);
  SD_REQUIRE(sd_setup_path_join(app, MAX_PATH, base, L"app") == 0);
  SD_REQUIRE(fake_hkcu_begin(&f) == 0);

  user_opts(&o, &tp, app, L"1.0.0");
  SD_CHECK_EQ_INT(sd_setup_install(&o, &r), SD_SETUP_EXIT_FATAL);
  SD_CHECK(r.msg == SD_MSG_INSTALLER_ERROR_PAYLOAD_UNSAFE);
  SD_CHECK(!file_in(base, L"evil.txt"));
  SD_CHECK(!reg_key_exists(L"Software\\LibreStatic\\ShellDrive"));

  fake_hkcu_end(&f);
  payload_free(&tp);
  test_remove_tree(base);
}

SD_TEST(setup_portable_roundtrip)
{
  fake_hkcu f;
  test_payload tp;
  wchar_t base[MAX_PATH], dir[MAX_PATH], data[MAX_PATH];
  sd_setup_install_opts o;
  sd_setup_result r;

  SD_REQUIRE(payload_load(L"payload-ok.cab", &tp) == 0);
  SD_REQUIRE(test_make_temp_dir(base, MAX_PATH) == 0);
  SD_REQUIRE(sd_setup_path_join(dir, MAX_PATH, base, L"usb") == 0);
  SD_REQUIRE(fake_hkcu_begin(&f) == 0);

  memset(&o, 0, sizeof(o));
  o.mode = SD_SETUP_MODE_PORTABLE;
  o.portable_dir = dir;
  o.version = L"1.2.3";
  o.flavour = SD_SETUP_FL_X86_IA32;
  o.payload = &tp.p;
  o.expected_sha256 = tp.sha;
  o.log_path = L"";
  SD_CHECK_EQ_INT(sd_setup_install(&o, &r), 0);
  SD_CHECK(r.msg == SD_MSG_INSTALLER_DONE_PORTABLE);
  SD_CHECK(file_in(dir, L"shelldrive.exe"));
  SD_CHECK(file_in(dir, L"shelldrive.portable"));
  SD_REQUIRE(sd_setup_path_join(data, MAX_PATH, dir, L"data") == 0);
  SD_CHECK(GetFileAttributesW(data) != INVALID_FILE_ATTRIBUTES);
  /* No uninstaller and no registration of any kind (04 §6.8). */
  SD_CHECK(!file_in(dir, L"uninstall.exe"));
  SD_CHECK(!reg_key_exists(L"Software\\LibreStatic\\ShellDrive"));
  SD_CHECK(!reg_key_exists(L"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\ShellDrive"));

  /* A folder with files is refused, not overwritten. */
  SD_CHECK_EQ_INT(sd_setup_install(&o, &r), SD_SETUP_EXIT_FATAL);
  SD_CHECK(r.msg == SD_MSG_INSTALLER_ERROR_PORTABLE_NOT_EMPTY);

  fake_hkcu_end(&f);
  payload_free(&tp);
  test_remove_tree(base);
}

SD_TEST(setup_machine_mode_not_in_this_build)
{
  test_payload tp;
  wchar_t base[MAX_PATH];
  sd_setup_install_opts o;
  sd_setup_result r;

  SD_REQUIRE(payload_load(L"payload-ok.cab", &tp) == 0);
  SD_REQUIRE(test_make_temp_dir(base, MAX_PATH) == 0);
  memset(&o, 0, sizeof(o));
  o.mode = SD_SETUP_MODE_MACHINE;
  o.version = L"1.0.0";
  o.flavour = SD_SETUP_FL_X86_IA32;
  o.payload = &tp.p;
  o.log_path = L"";
  SD_CHECK_EQ_INT(sd_setup_install(&o, &r), SD_SETUP_EXIT_FATAL);
  SD_CHECK(r.msg == SD_MSG_INSTALLER_ERROR_MACHINE_UNSUPPORTED);
  payload_free(&tp);
  test_remove_tree(base);
}

SD_TEST(setup_shortcut_and_log_files)
{
  wchar_t base[MAX_PATH], lnk[MAX_PATH], logp[MAX_PATH];
  HANDLE h;
  char text[256];
  DWORD n = 0;

  SD_REQUIRE(test_make_temp_dir(base, MAX_PATH) == 0);
  SD_REQUIRE(sd_setup_path_join(lnk, MAX_PATH, base, L"ShellDrive.lnk") == 0);
  SD_CHECK_EQ_INT(sd_setup_shortcut_create(lnk, L"C:\\Windows\\System32\\notepad.exe", base, L"ShellDrive",
                                           L"C:\\Windows\\System32\\notepad.exe"), 0);
  SD_CHECK(GetFileAttributesW(lnk) != INVALID_FILE_ATTRIBUTES);

  SD_REQUIRE(sd_setup_path_join(logp, MAX_PATH, base, L"setup.log") == 0);
  SD_REQUIRE(sd_setup_log_open(logp) == 0);
  sd_setup_log("test.event", L"hello caf\x00e9");
  sd_setup_log_close();
  h = CreateFileW(logp, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
  SD_REQUIRE(h != INVALID_HANDLE_VALUE);
  SD_CHECK(ReadFile(h, text, sizeof(text) - 1, &n, NULL));
  text[n] = '\0';
  CloseHandle(h);
  SD_CHECK(strstr(text, "test.event hello caf") != NULL);
  SD_CHECK(strstr(text, "\r\n") != NULL);

  test_remove_tree(base);
}

SD_TEST(setup_current_sid_format)
{
  wchar_t sid[128];
  SD_CHECK_EQ_INT(sd_setup_current_sid(sid, SD_SETUP_COUNTOF_LOCAL(sid)), 0);
  SD_CHECK(wcsncmp(sid, L"S-1-", 4) == 0);
}

SD_TEST_DECL(setup_cab_extract_good);
SD_TEST_DECL(setup_cab_traversal_refused);
SD_TEST_DECL(setup_cab_size_limits);
SD_TEST_DECL(setup_cab_damaged_payload);
SD_TEST_DECL(setup_user_install_repair_uninstall);
SD_TEST_DECL(setup_user_newer_version_refused);
SD_TEST_DECL(setup_user_damaged_payload_refused);
SD_TEST_DECL(setup_user_traversal_refused);
SD_TEST_DECL(setup_portable_roundtrip);
SD_TEST_DECL(setup_machine_mode_not_in_this_build);
SD_TEST_DECL(setup_shortcut_and_log_files);
SD_TEST_DECL(setup_current_sid_format);
