/* Dokany chaining (docs/design/04 §7.3; C31, D32): the VC++ dependency of dokan2.dll read from a synthetic PE image,
   the chain choice, the command lines, and the run gate. No process is started: the runner is a fake, and the engine
   without a runner refuses. */
#include <windows.h>
#include <strsafe.h>
#include <string.h>
#include <wchar.h>

#include "sd_test.h"
#include "setup_core.h"
#include "setup_dokany.h"

static void put16(unsigned char *b, size_t off, DWORD v)
{
  b[off] = (unsigned char)(v & 0xFF);
  b[off + 1] = (unsigned char)((v >> 8) & 0xFF);
}

static void put32(unsigned char *b, size_t off, DWORD v)
{
  put16(b, off, v & 0xFFFF);
  put16(b, off + 2, (v >> 16) & 0xFFFF);
}

/* A minimal image: one .idata section at RVA 0x1000 (raw 0x400, 0x200 bytes), one import descriptor whose name is dll.
   The name lives at file offset 0x500. pe64 selects PE32+ (its optional header is larger). Returns the image size. */
static size_t make_pe(unsigned char *b, const char *dll, int pe64)
{
  size_t opt = 0x98;
  size_t optsz = pe64 ? 0xF0 : 0xE0;
  size_t dd = opt + (pe64 ? 112 : 96);
  size_t sec = opt + optsz;

  memset(b, 0, 0x600);
  b[0] = 'M';
  b[1] = 'Z';
  put32(b, 0x3C, 0x80);
  memcpy(b + 0x80, "PE\0\0", 4);
  put16(b, 0x80 + 4, 0x8664);          /* Machine (ignored by the parser) */
  put16(b, 0x80 + 6, 1);               /* NumberOfSections */
  put16(b, 0x80 + 20, (DWORD)optsz);   /* SizeOfOptionalHeader */
  put16(b, opt, pe64 ? 0x20B : 0x10B);
  put32(b, dd + 8, 0x1000);            /* import directory RVA */
  put32(b, dd + 12, 40);               /* import directory size */
  memcpy(b + sec, ".idata\0\0", 8);
  put32(b, sec + 8, 0x200);            /* VirtualSize */
  put32(b, sec + 12, 0x1000);          /* VirtualAddress */
  put32(b, sec + 16, 0x200);           /* SizeOfRawData */
  put32(b, sec + 20, 0x400);           /* PointerToRawData */
  put32(b, 0x400 + 12, 0x1100);        /* descriptor Name RVA: the file offset 0x500 */
  memcpy(b + 0x500, dll, strlen(dll) + 1);
  return 0x600;
}

SD_TEST(setup_dokany_pe_vcr_state)
{
  unsigned char img[0x600];
  size_t n;
  sd_setup_vcr_state st;

  n = make_pe(img, "vcruntime140.dll", 0);
  SD_CHECK_EQ_INT(sd_setup_pe_vcr_state(img, n, &st), 0);
  SD_CHECK_EQ_INT(st, SD_SETUP_VCR_NEEDED);

  n = make_pe(img, "MSVCP140_1.DLL", 0);
  SD_CHECK_EQ_INT(sd_setup_pe_vcr_state(img, n, &st), 0);
  SD_CHECK_EQ_INT(st, SD_SETUP_VCR_NEEDED);

  n = make_pe(img, "vcruntime140_1.dll", 1);
  SD_CHECK_EQ_INT(sd_setup_pe_vcr_state(img, n, &st), 0);
  SD_CHECK_EQ_INT(st, SD_SETUP_VCR_NEEDED);

  n = make_pe(img, "kernel32.dll", 0);
  SD_CHECK_EQ_INT(sd_setup_pe_vcr_state(img, n, &st), 0);
  SD_CHECK_EQ_INT(st, SD_SETUP_VCR_NOT_NEEDED);

  /* Universal CRT forwarders are not the VC++ 2015-2022 redistributable. */
  n = make_pe(img, "api-ms-win-crt-runtime-l1-1-0.dll", 0);
  SD_CHECK_EQ_INT(sd_setup_pe_vcr_state(img, n, &st), 0);
  SD_CHECK_EQ_INT(st, SD_SETUP_VCR_NOT_NEEDED);
}

SD_TEST(setup_dokany_pe_malformed_fails_closed)
{
  unsigned char img[0x600];
  size_t n = make_pe(img, "vcruntime140.dll", 0);
  sd_setup_vcr_state st = SD_SETUP_VCR_NOT_NEEDED;

  /* Truncated before the section data. */
  SD_CHECK_EQ_INT(sd_setup_pe_vcr_state(img, 0x300, &st), 1);
  SD_CHECK_EQ_INT(st, SD_SETUP_VCR_UNKNOWN);

  /* Not a PE. */
  img[0] = 'Z';
  SD_CHECK_EQ_INT(sd_setup_pe_vcr_state(img, n, &st), 1);
  SD_CHECK_EQ_INT(st, SD_SETUP_VCR_UNKNOWN);
  img[0] = 'M';

  /* e_lfanew outside the image. */
  put32(img, 0x3C, 0x10000);
  SD_CHECK_EQ_INT(sd_setup_pe_vcr_state(img, n, &st), 1);
  put32(img, 0x3C, 0x80);

  /* A name RVA that no section maps. */
  put32(img, 0x400 + 12, 0x9000);
  SD_CHECK_EQ_INT(sd_setup_pe_vcr_state(img, n, &st), 1);
  SD_CHECK_EQ_INT(st, SD_SETUP_VCR_UNKNOWN);
}

SD_TEST(setup_dokany_choose_chain)
{
  SD_CHECK_EQ_INT(sd_setup_dokany_choose(SD_SETUP_VCR_NOT_NEEDED, 1, 1), SD_SETUP_DOKANY_CHAIN_MSI);
  SD_CHECK_EQ_INT(sd_setup_dokany_choose(SD_SETUP_VCR_NOT_NEEDED, 0, 1), SD_SETUP_DOKANY_CHAIN_UNAVAILABLE);
  SD_CHECK_EQ_INT(sd_setup_dokany_choose(SD_SETUP_VCR_NEEDED, 1, 1), SD_SETUP_DOKANY_CHAIN_BUNDLE);
  SD_CHECK_EQ_INT(sd_setup_dokany_choose(SD_SETUP_VCR_NEEDED, 1, 0), SD_SETUP_DOKANY_CHAIN_UNAVAILABLE);
  /* An unknown dependency never chains: WebDAV only. */
  SD_CHECK_EQ_INT(sd_setup_dokany_choose(SD_SETUP_VCR_UNKNOWN, 1, 1), SD_SETUP_DOKANY_CHAIN_UNAVAILABLE);
}

SD_TEST(setup_dokany_command_lines)
{
  wchar_t exe[MAX_PATH * 2];
  wchar_t args[MAX_PATH * 4];

  SD_CHECK_EQ_INT(sd_setup_dokany_command(SD_SETUP_DOKANY_CHAIN_MSI, L"C:\\Windows\\System32", L"C:\\stage\\Dokan_x64.msi",
                                          L"C:\\stage\\dokan.log", exe, MAX_PATH * 2, args, MAX_PATH * 4),
                  0);
  SD_CHECK(wcscmp(exe, L"C:\\Windows\\System32\\msiexec.exe") == 0);
  SD_CHECK(wcscmp(args, L"/i \"C:\\stage\\Dokan_x64.msi\" /qn /norestart /l*v \"C:\\stage\\dokan.log\"") == 0);

  SD_CHECK_EQ_INT(sd_setup_dokany_command(SD_SETUP_DOKANY_CHAIN_BUNDLE, NULL, L"C:\\stage\\DokanSetup.exe",
                                          L"C:\\stage\\dokan.log", exe, MAX_PATH * 2, args, MAX_PATH * 4),
                  0);
  SD_CHECK(wcscmp(exe, L"C:\\stage\\DokanSetup.exe") == 0);
  SD_CHECK(wcscmp(args, L"/install /quiet /norestart /log \"C:\\stage\\dokan.log\"") == 0);

  /* No chain, and a quote in a path, give no command. */
  SD_CHECK(sd_setup_dokany_command(SD_SETUP_DOKANY_CHAIN_NONE, L"C:\\Windows\\System32", L"C:\\a.msi", L"C:\\a.log", exe,
                                   MAX_PATH * 2, args, MAX_PATH * 4) != 0);
  SD_CHECK(sd_setup_dokany_command(SD_SETUP_DOKANY_CHAIN_MSI, L"C:\\Windows\\System32", L"C:\\a\"b.msi", L"C:\\a.log",
                                   exe, MAX_PATH * 2, args, MAX_PATH * 4) != 0);
}

typedef struct fake_runner {
  int calls;
  wchar_t exe[MAX_PATH * 2];
  wchar_t args[MAX_PATH * 4];
  DWORD code;
  DWORD start_err;
} fake_runner;

static DWORD fake_run(void *ctx, const wchar_t *exe, const wchar_t *args, DWORD *exit_code)
{
  fake_runner *f = (fake_runner *)ctx;
  f->calls++;
  StringCchCopyW(f->exe, MAX_PATH * 2, exe);
  StringCchCopyW(f->args, MAX_PATH * 4, args);
  *exit_code = f->code;
  return f->start_err;
}

SD_TEST(setup_dokany_run_gate)
{
  static const unsigned char bytes[] = "not really a Dokan package";
  unsigned char sha[32];
  sd_setup_payload pkg;
  fake_runner f;
  DWORD code = 99;
  DWORD err;

  pkg.data = bytes;
  pkg.size = sizeof(bytes) - 1;
  sd_setup_sha256(pkg.data, pkg.size, sha);

  /* Without a runner nothing starts, even with good bytes. */
  err = sd_setup_dokany_run(SD_SETUP_DOKANY_CHAIN_MSI, &pkg, sha, L"C:\\Windows\\System32", L"C:\\s\\Dokan_x64.msi",
                            L"C:\\s\\dokan.log", NULL, NULL, &code);
  SD_CHECK_EQ_INT(err, ERROR_CALL_NOT_IMPLEMENTED);

  /* A chain that is not MSI or BUNDLE is refused before any check. */
  memset(&f, 0, sizeof(f));
  err = sd_setup_dokany_run(SD_SETUP_DOKANY_CHAIN_UNAVAILABLE, &pkg, sha, L"C:\\Windows\\System32", L"C:\\s\\x.msi",
                            L"C:\\s\\dokan.log", fake_run, &f, &code);
  SD_CHECK_EQ_INT(err, ERROR_NOT_SUPPORTED);
  SD_CHECK_EQ_INT(f.calls, 0);

  /* A digest that does not match is refused at install time, and nothing runs. */
  {
    unsigned char bad[32];
    memcpy(bad, sha, sizeof(bad));
    bad[0] ^= 0xFF;
    err = sd_setup_dokany_run(SD_SETUP_DOKANY_CHAIN_MSI, &pkg, bad, L"C:\\Windows\\System32", L"C:\\s\\Dokan_x64.msi",
                              L"C:\\s\\dokan.log", fake_run, &f, &code);
    SD_CHECK_EQ_INT(err, ERROR_INVALID_DATA);
    SD_CHECK_EQ_INT(f.calls, 0);
  }

  /* The matching bytes run the MSI command through the runner: 3010 (reboot) is success. */
  memset(&f, 0, sizeof(f));
  f.code = 3010;
  code = 0;
  err = sd_setup_dokany_run(SD_SETUP_DOKANY_CHAIN_MSI, &pkg, sha, L"C:\\Windows\\System32", L"C:\\s\\Dokan_x64.msi",
                            L"C:\\s\\dokan.log", fake_run, &f, &code);
  SD_CHECK_EQ_INT(err, 0);
  SD_CHECK_EQ_INT(code, 3010);
  SD_CHECK_EQ_INT(f.calls, 1);
  SD_CHECK(wcscmp(f.exe, L"C:\\Windows\\System32\\msiexec.exe") == 0);
  SD_CHECK(wcsstr(f.args, L"/qn /norestart") != NULL);

  /* A failing program is reported with its code. */
  memset(&f, 0, sizeof(f));
  f.code = 1603;
  err = sd_setup_dokany_run(SD_SETUP_DOKANY_CHAIN_BUNDLE, &pkg, sha, NULL, L"C:\\s\\DokanSetup.exe", L"C:\\s\\dokan.log",
                            fake_run, &f, &code);
  SD_CHECK_EQ_INT(err, 1603);
  SD_CHECK_EQ_INT(f.calls, 1);
  SD_CHECK(wcscmp(f.exe, L"C:\\s\\DokanSetup.exe") == 0);
  SD_CHECK(wcsstr(f.args, L"/install /quiet /norestart") != NULL);
}
