/* Pure tests of the setup engine: flavour choice over a table of CPU/OS cases, command-line parsing,
   version order, the Dokany decision, CAB member-name rules, the payload table and SHA-256 vectors. */
#include <windows.h>
#include <strsafe.h>

#include <string.h>

#include "sd_l10n/sd_l10n.h"
#include "setup_core.h"
#include "sd_l10n_installer_ids.h"
#include "sd_test.h"
#include "test_common.h"

#ifndef IMAGE_FILE_MACHINE_I386
#define IMAGE_FILE_MACHINE_I386 0x014c
#endif
#ifndef IMAGE_FILE_MACHINE_AMD64
#define IMAGE_FILE_MACHINE_AMD64 0x8664
#endif
#ifndef IMAGE_FILE_MACHINE_ARM64
#define IMAGE_FILE_MACHINE_ARM64 0xAA64
#endif
#ifndef IMAGE_FILE_MACHINE_ARMNT
#define IMAGE_FILE_MACHINE_ARMNT 0x01c4
#endif

/* ---------------------------------------------------------------- flavour selection */

typedef struct flavour_case {
  const char *name;
  WORD machine;
  int sse2;
  unsigned major, minor;
  sd_setup_flavour override;
  sd_setup_flavour expect;      /* SD_SETUP_FL_NONE = refused */
} flavour_case;

static const flavour_case k_flavour_cases[] = {
  { "x86 with SSE2", IMAGE_FILE_MACHINE_I386, 1, 5, 1, SD_SETUP_FL_NONE, SD_SETUP_FL_X86_SSE2 },
  { "x86 without SSE2", IMAGE_FILE_MACHINE_I386, 0, 5, 1, SD_SETUP_FL_NONE, SD_SETUP_FL_X86_IA32 },
  { "x86 forced ia32 with SSE2", IMAGE_FILE_MACHINE_I386, 1, 5, 1, SD_SETUP_FL_X86_IA32, SD_SETUP_FL_X86_IA32 },
  { "x86 forced sse2 without SSE2", IMAGE_FILE_MACHINE_I386, 0, 5, 1, SD_SETUP_FL_X86_SSE2, SD_SETUP_FL_NONE },
  { "x86 forced x64-modern", IMAGE_FILE_MACHINE_I386, 1, 10, 0, SD_SETUP_FL_X64_MODERN, SD_SETUP_FL_NONE },
  { "x86 forced arm64", IMAGE_FILE_MACHINE_I386, 1, 10, 0, SD_SETUP_FL_ARM64, SD_SETUP_FL_NONE },
  { "x64 XP", IMAGE_FILE_MACHINE_AMD64, 1, 5, 2, SD_SETUP_FL_NONE, SD_SETUP_FL_X64_XP },
  { "x64 Vista", IMAGE_FILE_MACHINE_AMD64, 1, 6, 0, SD_SETUP_FL_NONE, SD_SETUP_FL_X64_XP },
  { "x64 Windows 7", IMAGE_FILE_MACHINE_AMD64, 1, 6, 1, SD_SETUP_FL_NONE, SD_SETUP_FL_X64_XP },
  { "x64 Windows 8.1", IMAGE_FILE_MACHINE_AMD64, 1, 6, 3, SD_SETUP_FL_NONE, SD_SETUP_FL_X64_XP },
  { "x64 Windows 10", IMAGE_FILE_MACHINE_AMD64, 1, 10, 0, SD_SETUP_FL_NONE, SD_SETUP_FL_X64_MODERN },
  { "x64 Windows 11", IMAGE_FILE_MACHINE_AMD64, 1, 10, 0, SD_SETUP_FL_NONE, SD_SETUP_FL_X64_MODERN },
  { "x64 forced xp on Windows 10", IMAGE_FILE_MACHINE_AMD64, 1, 10, 0, SD_SETUP_FL_X64_XP, SD_SETUP_FL_X64_XP },
  { "x64 forced modern on Vista", IMAGE_FILE_MACHINE_AMD64, 1, 6, 0, SD_SETUP_FL_X64_MODERN, SD_SETUP_FL_NONE },
  { "x64 forced ia32", IMAGE_FILE_MACHINE_AMD64, 1, 10, 0, SD_SETUP_FL_X86_IA32, SD_SETUP_FL_NONE },
  { "ARM64 Windows 10", IMAGE_FILE_MACHINE_ARM64, 1, 10, 0, SD_SETUP_FL_NONE, SD_SETUP_FL_ARM64 },
  { "ARM64 forced arm64", IMAGE_FILE_MACHINE_ARM64, 1, 10, 0, SD_SETUP_FL_ARM64, SD_SETUP_FL_ARM64 },
  { "ARM64 forced x64-modern", IMAGE_FILE_MACHINE_ARM64, 1, 10, 0, SD_SETUP_FL_X64_MODERN, SD_SETUP_FL_NONE },
  { "ARM32 needs its own setup", IMAGE_FILE_MACHINE_ARMNT, 0, 10, 0, SD_SETUP_FL_NONE, SD_SETUP_FL_NONE },
  { "unknown machine", 0, 0, 10, 0, SD_SETUP_FL_NONE, SD_SETUP_FL_NONE },
};

SD_TEST(setup_flavour_table)
{
  size_t i;
  for (i = 0; i < SD_SETUP_COUNTOF_LOCAL(k_flavour_cases); i++) {
    const flavour_case *c = &k_flavour_cases[i];
    sd_setup_host h;
    sd_setup_flavour got = SD_SETUP_FL_NONE;
    sd_msg_id reason = 0;
    int rc;

    memset(&h, 0, sizeof(h));
    h.native_machine = c->machine;
    h.sse2 = c->sse2;
    h.os_major = c->major;
    h.os_minor = c->minor;
    rc = sd_setup_select_flavour(&h, c->override, &got, &reason);
    if (c->expect == SD_SETUP_FL_NONE) {
      if (rc == 0)
        sd_test_fail(sd_t_, __FILE__, __LINE__, "%s: expected a refusal, got %s", c->name,
                     sd_setup_flavour_name(got) ? "a flavour" : "nothing");
      SD_CHECK(reason != 0);
    } else {
      if (rc != 0 || got != c->expect)
        sd_test_fail(sd_t_, __FILE__, __LINE__, "%s: expected flavour %d, rc %d got %d", c->name,
                     (int)c->expect, rc, (int)got);
    }
  }
}

SD_TEST(setup_flavour_names)
{
  SD_CHECK(sd_setup_flavour_parse(L"x64-modern") == SD_SETUP_FL_X64_MODERN);
  SD_CHECK(sd_setup_flavour_parse(L"X86-IA32") == SD_SETUP_FL_X86_IA32);
  SD_CHECK(sd_setup_flavour_parse(L"x86-sse2") == SD_SETUP_FL_X86_SSE2);
  SD_CHECK(sd_setup_flavour_parse(L"pdp11") == SD_SETUP_FL_NONE);
  SD_CHECK(sd_setup_flavour_parse(NULL) == SD_SETUP_FL_NONE);
  SD_CHECK(wcscmp(sd_setup_payload_resource(SD_SETUP_FL_X64_MODERN), L"PAYLOAD_X64_MODERN") == 0);
  SD_CHECK(wcscmp(sd_setup_payload_resource(SD_SETUP_FL_ARM64), L"PAYLOAD_ARM64") == 0);
}

SD_TEST(setup_detect_host_runs)
{
  sd_setup_host h;
  sd_setup_detect_host(&h);
  SD_CHECK(h.native_machine == IMAGE_FILE_MACHINE_I386 || h.native_machine == IMAGE_FILE_MACHINE_AMD64 ||
           h.native_machine == IMAGE_FILE_MACHINE_ARM64);
  SD_CHECK(h.os_major >= 5);
}

/* ---------------------------------------------------------------- command line */

static int parse(const wchar_t *const *argv, int n, sd_setup_args *a, const wchar_t **bad)
{
  return sd_setup_parse_args(n, argv, a, bad);
}

SD_TEST(setup_args_valid)
{
  static const wchar_t *const a1[] = { L"setup.exe", L"/quiet", L"/peruser", L"/norestart" };
  static const wchar_t *const a2[] = { L"setup.exe", L"/portable=C:\\Tools\\SD", L"/passive" };
  static const wchar_t *const a3[] = { L"setup.exe", L"/dokany=skip", L"/flavour=x64-modern", L"/lang=pt",
                                       L"/log=C:\\temp\\a.log", L"/autostart=1", L"PROPERTY_X=1" };
  static const wchar_t *const a4[] = { L"setup.exe", L"/uninstall", L"/force", L"/update", L"/waitpid=1234" };
  sd_setup_args a;
  const wchar_t *bad = NULL;

  SD_CHECK_EQ_INT(parse(a1, 4, &a, &bad), 0);
  SD_CHECK(a.mode == SD_SETUP_MODE_USER && a.quiet && a.norestart && !a.passive);

  SD_CHECK_EQ_INT(parse(a2, 3, &a, &bad), 0);
  SD_CHECK(a.mode == SD_SETUP_MODE_PORTABLE && a.passive && !a.quiet);
  SD_CHECK(wcscmp(a.portable_dir, L"C:\\Tools\\SD") == 0);

  SD_CHECK_EQ_INT(parse(a3, 7, &a, &bad), 0);
  SD_CHECK(a.dokany_set && a.dokany == SD_SETUP_DOKANY_SKIP);
  SD_CHECK(a.flavour_forced && a.flavour == SD_SETUP_FL_X64_MODERN);
  SD_CHECK(wcscmp(a.lang, L"pt") == 0);
  SD_CHECK(wcscmp(a.log_path, L"C:\\temp\\a.log") == 0);
  SD_CHECK_EQ_INT(a.autostart, 1);
  SD_CHECK_EQ_INT(a.properties, 1);

  SD_CHECK_EQ_INT(parse(a4, 5, &a, &bad), 0);
  SD_CHECK(a.mode == SD_SETUP_MODE_UNINSTALL && a.force && a.update);
  SD_CHECK_EQ_INT(a.wait_pid, 1234);
}

SD_TEST(setup_args_rejected)
{
  static const wchar_t *const bad_cases[][3] = {
    { L"setup.exe", L"/peruser", L"/permachine" },
    { L"setup.exe", L"/permachine", L"/portable=D:\\x" },
    { L"setup.exe", L"/dokany=maybe" },
    { L"setup.exe", L"/flavour=pdp11" },
    { L"setup.exe", L"/lang=xx" },
    { L"setup.exe", L"/portable" },
    { L"setup.exe", L"/autostart=2" },
    { L"setup.exe", L"/waitpid=abc" },
    { L"setup.exe", L"/unknownswitch" },
    { L"setup.exe", L"not an option" },
  };
  size_t i;

  for (i = 0; i < SD_SETUP_COUNTOF_LOCAL(bad_cases); i++) {
    sd_setup_args a;
    const wchar_t *bad = NULL;
    const wchar_t *expect = NULL;
    int n = 2;
    int j;
    int rc;

    if (bad_cases[i][2] != NULL)
      n = 3;
    /* The offending token is the last argument: the one that broke the mode rule or was unknown. */
    for (j = 1; j < 3; j++) {
      if (bad_cases[i][j] != NULL)
        expect = bad_cases[i][j];
    }
    rc = sd_setup_parse_args(n, bad_cases[i], &a, &bad);
    if (rc != SD_SETUP_EXIT_BADARGS || bad == NULL)
      sd_test_fail(sd_t_, __FILE__, __LINE__, "case %u should be rejected", (unsigned)i);
    else
      SD_CHECK(bad == expect);
  }
}

/* ---------------------------------------------------------------- versions and Dokany */

SD_TEST(setup_version_order)
{
  SD_CHECK(sd_setup_version_compare(L"1.2.3", L"1.2.10") < 0);
  SD_CHECK(sd_setup_version_compare(L"1.2", L"1.2.0.0") == 0);
  SD_CHECK(sd_setup_version_compare(L"2.0", L"1.9.9.9") > 0);
  SD_CHECK(sd_setup_version_compare(L"1.0.0.1", L"1.0.0") > 0);
  SD_CHECK(sd_setup_version_compare(L"0.9.12", L"0.10.0") < 0);
}

SD_TEST(setup_dokany_plan)
{
  SD_CHECK(sd_setup_dokany_decide(SD_SETUP_MODE_USER, 0, SD_SETUP_DOKANY_AUTO, 10, 0) == SD_SETUP_DOKANY_SKIP_PLAN);
  SD_CHECK(sd_setup_dokany_decide(SD_SETUP_MODE_MACHINE, 0, SD_SETUP_DOKANY_AUTO, 10, 0) == SD_SETUP_DOKANY_INSTALL_PLAN);
  SD_CHECK(sd_setup_dokany_decide(SD_SETUP_MODE_MACHINE, 1, SD_SETUP_DOKANY_SKIP, 10, 0) == SD_SETUP_DOKANY_SKIP_PLAN);
  SD_CHECK(sd_setup_dokany_decide(SD_SETUP_MODE_MACHINE, 0, SD_SETUP_DOKANY_AUTO, 6, 0) == SD_SETUP_DOKANY_UNAVAILABLE_PLAN);
  SD_CHECK(sd_setup_dokany_decide(SD_SETUP_MODE_MACHINE, 0, SD_SETUP_DOKANY_AUTO, 6, 1) == SD_SETUP_DOKANY_INSTALL_PLAN);
  SD_CHECK(sd_setup_dokany_decide(SD_SETUP_MODE_MACHINE, 1, SD_SETUP_DOKANY_INSTALL, 5, 1) == SD_SETUP_DOKANY_UNAVAILABLE_PLAN);
}

/* ---------------------------------------------------------------- CAB member names */

SD_TEST(setup_cab_names)
{
  SD_CHECK(sd_setup_cab_name_ok("shelldrive.exe"));
  SD_CHECK(sd_setup_cab_name_ok("sub\\readme.txt"));
  SD_CHECK(sd_setup_cab_name_ok(".hidden"));
  SD_CHECK(!sd_setup_cab_name_ok("..\\evil.txt"));
  SD_CHECK(!sd_setup_cab_name_ok("..\\..\\evil.txt"));
  SD_CHECK(!sd_setup_cab_name_ok("sub\\..\\..\\evil.txt"));
  SD_CHECK(!sd_setup_cab_name_ok(".."));
  SD_CHECK(!sd_setup_cab_name_ok("."));
  SD_CHECK(!sd_setup_cab_name_ok("\\windows\\system32\\x.dll"));
  SD_CHECK(!sd_setup_cab_name_ok("C:\\Windows\\x.dll"));
  SD_CHECK(!sd_setup_cab_name_ok("a//b"));
  SD_CHECK(!sd_setup_cab_name_ok("a\\\\b"));
  SD_CHECK(!sd_setup_cab_name_ok("trailing\\"));
  SD_CHECK(!sd_setup_cab_name_ok("name."));
  SD_CHECK(!sd_setup_cab_name_ok("name "));
  SD_CHECK(!sd_setup_cab_name_ok("con.txt"));
  SD_CHECK(!sd_setup_cab_name_ok("sub\\LPT1"));
  SD_CHECK(!sd_setup_cab_name_ok("bad<name"));
  SD_CHECK(!sd_setup_cab_name_ok("bad|name"));
  SD_CHECK(!sd_setup_cab_name_ok(""));
  SD_CHECK(!sd_setup_cab_name_ok(NULL));
  SD_CHECK(!sd_setup_cab_name_ok("caf\xc3\xa9.txt"));
}

/* ---------------------------------------------------------------- payload table and SHA-256 */

SD_TEST(setup_payload_table)
{
  static const char table[] =
    "x86-ia32 0000000000000000000000000000000000000000000000000000000000000001 100\r\n"
    "x64-modern ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff 200\r\n";
  unsigned char sha[32];
  size_t n = sizeof(table) - 1;
  SD_CHECK_EQ_INT(sd_setup_payload_table_lookup(table, n, L"x64-modern", sha), 0);
  SD_CHECK(sha[0] == 0xff && sha[31] == 0xff);
  SD_CHECK_EQ_INT(sd_setup_payload_table_lookup(table, n, L"x86-ia32", sha), 0);
  SD_CHECK(sha[31] == 0x01);
  SD_CHECK_EQ_INT(sd_setup_payload_table_lookup(table, n, L"arm64", sha), 1);
  SD_CHECK_EQ_INT(sd_setup_payload_table_lookup(table, n, L"x86", sha), 1);
}

SD_TEST(setup_sha256_vectors)
{
  unsigned char out[32];
  static const unsigned char abc[32] = {
    0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
    0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad };
  static const unsigned char empty[32] = {
    0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
    0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55 };
  static const char two_blocks[] = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
  static const unsigned char two_expect[32] = {
    0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8, 0xe5, 0xc0, 0x26, 0x93, 0x0c, 0x3e, 0x60, 0x39,
    0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff, 0x21, 0x67, 0xf6, 0xec, 0xed, 0xd4, 0x19, 0xdb, 0x06, 0xc1 };

  sd_setup_sha256("abc", 3, out);
  SD_CHECK_MEM(out, abc, 32);
  sd_setup_sha256("", 0, out);
  SD_CHECK_MEM(out, empty, 32);
  sd_setup_sha256(two_blocks, sizeof(two_blocks) - 1, out);
  SD_CHECK_MEM(out, two_expect, 32);
}

/* ---------------------------------------------------------------- messages from the catalog */

SD_TEST(setup_messages_format)
{
  sd_setup_result r;
  wchar_t buf[512];
  int n;

  sd_l10n_init(&sd_l10n_catalog_installer, L"en");
  memset(&r, 0, sizeof(r));
  StringCchCopyW(r.version, SD_SETUP_COUNTOF_LOCAL(r.version), L"2.0.0");
  n = sd_setup_format_message(&r, SD_MSG_INSTALLER_ERROR_NEWER_INSTALLED, buf, 512);
  SD_CHECK(n > 0);
  SD_CHECK(wcsstr(buf, L"2.0.0") != NULL && wcsstr(buf, L"/update") != NULL);

  memset(&r, 0, sizeof(r));
  r.count = 1;
  sd_setup_format_message(&r, SD_MSG_INSTALLER_SUMMARY_FILES, buf, 512);
  SD_CHECK(wcscmp(buf, L"1 file copied.") == 0);
  r.count = 3;
  sd_setup_format_message(&r, SD_MSG_INSTALLER_SUMMARY_FILES, buf, 512);
  SD_CHECK(wcscmp(buf, L"3 files copied.") == 0);

  memset(&r, 0, sizeof(r));
  StringCchCopyW(r.text, SD_SETUP_COUNTOF_LOCAL(r.text), L"x86-ia32");
  sd_setup_format_message(&r, SD_MSG_INSTALLER_ERROR_PAYLOAD_MISSING, buf, 512);
  SD_CHECK(wcsstr(buf, L"x86-ia32") != NULL);
}

SD_TEST(setup_messages_other_locale)
{
  sd_setup_result r;
  wchar_t buf[512];

  sd_l10n_init(&sd_l10n_catalog_installer, L"es");
  memset(&r, 0, sizeof(r));
  r.count = 2;
  sd_setup_format_message(&r, SD_MSG_INSTALLER_SUMMARY_FILES, buf, 512);
  SD_CHECK(wcscmp(buf, L"Se copiaron 2 archivos.") == 0);
  sd_l10n_init(&sd_l10n_catalog_installer, L"en");
}

SD_TEST_DECL(setup_flavour_table);
SD_TEST_DECL(setup_flavour_names);
SD_TEST_DECL(setup_detect_host_runs);
SD_TEST_DECL(setup_args_valid);
SD_TEST_DECL(setup_args_rejected);
SD_TEST_DECL(setup_version_order);
SD_TEST_DECL(setup_dokany_plan);
SD_TEST_DECL(setup_cab_names);
SD_TEST_DECL(setup_payload_table);
SD_TEST_DECL(setup_sha256_vectors);
SD_TEST_DECL(setup_messages_format);
SD_TEST_DECL(setup_messages_other_locale);
