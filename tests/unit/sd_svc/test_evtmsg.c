/* The Event Log message tables of shelldrive-host (03 §10.3, §9.1).
 *
 * The generated svc_events.mc (written by sdl10n from l10n/svc, compiled by mc.exe -u) must hold six Language= blocks
 * for every MessageId, in the fixed order of the language table below. The shelldrive-host.exe that the build made
 * must resolve every id in every one of those languages (FormatMessage, FROM_HMODULE, LOAD_LIBRARY_AS_DATAFILE), and
 * the text it returns must be the text of that language in the .mc. Nothing here writes the Event Log or registers a
 * source: FormatMessage only reads the message table. */
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#include "sd_test.h"
#include "svc_events.h"

#ifndef SD_SVC_EVENTS_MC
#error "SD_SVC_EVENTS_MC must name the generated svc_events.mc"
#endif
#ifndef SD_SVC_HOST_EXE
#error "SD_SVC_HOST_EXE must name the built shelldrive-host.exe"
#endif

typedef struct mc_lang {
  const wchar_t *name;             /* the LanguageNames entry of sdl10n's .mc */
  LANGID lang;
} mc_lang;

/* Same order as sdl10n write_mc (k_mc_langs); the LCIDs are 0x409, 0x2C0A, 0x40C, 0x416, 0x410, 0x407. */
static const mc_lang k_mc_langs[] = {
  { L"English",          MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US) },
  { L"Spanish",          MAKELANGID(LANG_SPANISH, 0x0B) },   /* es-AR, the Rioplatense voseo text (11274) */
  { L"French",           MAKELANGID(LANG_FRENCH, SUBLANG_FRENCH) },
  { L"PortugueseBrazil", MAKELANGID(LANG_PORTUGUESE, SUBLANG_PORTUGUESE_BRAZILIAN) },
  { L"Italian",          MAKELANGID(LANG_ITALIAN, SUBLANG_ITALIAN) },
  { L"German",           MAKELANGID(LANG_GERMAN, SUBLANG_GERMAN) },
};
#define MC_LANG_COUNT (sizeof(k_mc_langs) / sizeof(k_mc_langs[0]))

/* Reads the UTF-16LE .mc into a NUL-terminated buffer of wchar_t (16 bits on Windows). */
static wchar_t *read_mc(size_t *units_out)
{
  FILE *f = NULL;
  long n;
  unsigned char *buf;
  wchar_t *w;
  size_t i, units;
  if (fopen_s(&f, SD_SVC_EVENTS_MC, "rb") != 0 || !f) return NULL;
  if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
  n = ftell(f);
  if (fseek(f, 0, SEEK_SET) != 0 || n < 4 || (n & 1)) { fclose(f); return NULL; }
  buf = (unsigned char *)malloc((size_t)n);
  if (!buf) { fclose(f); return NULL; }
  if (fread(buf, 1, (size_t)n, f) != (size_t)n) { fclose(f); free(buf); return NULL; }
  fclose(f);
  if (buf[0] != 0xFF || buf[1] != 0xFE) { free(buf); return NULL; }   /* UTF-16LE byte order mark */
  units = ((size_t)n - 2) / 2;
  w = (wchar_t *)malloc((units + 1) * sizeof(wchar_t));
  if (!w) { free(buf); return NULL; }
  for (i = 0; i < units; i++)
    w[i] = (wchar_t)(buf[2 + 2 * i] | (buf[3 + 2 * i] << 8));
  w[units] = 0;
  free(buf);
  *units_out = units;
  return w;
}

static size_t trimmed(const wchar_t *s, size_t n)
{
  while (n > 0 && (s[n - 1] == L'\r' || s[n - 1] == L'\n' || s[n - 1] == L' ')) n--;
  return n;
}

/* Severity names of the .mc (SeverityNames in sdl10n write_mc) to the top two bits of the message id. */
static int severity_code(const wchar_t *name, size_t len)
{
  static const struct { const wchar_t *n; int code; } k[] = {
    { L"Success", 0 }, { L"Informational", 1 }, { L"Warning", 2 }, { L"Error", 3 },
  };
  size_t i;
  for (i = 0; i < sizeof(k) / sizeof(k[0]); i++)
    if (wcslen(k[i].n) == len && wcsncmp(name, k[i].n, len) == 0) return k[i].code;
  return -1;
}

/* Walks every MessageId block of the .mc. For each id and language, checks the block structure and, when hm is
   not NULL, that the module resolves the id in that language to the same text. Returns the number of blocks. */
static int walk_mc(sd_test_ctx *sd_t_, HMODULE hm)
{
  size_t units = 0;
  wchar_t *w = read_mc(&units);
  const wchar_t *p, *end_of_file;
  int blocks = 0;
  if (!w) { sd_test_fail(sd_t_, __FILE__, __LINE__, "cannot read the generated %s", SD_SVC_EVENTS_MC); return 0; }
  end_of_file = w + units;
  p = wcsstr(w, L"MessageId=");
  while (p) {
    const wchar_t *next = wcsstr(p + 10, L"MessageId=");
    const wchar_t *end = next ? next : end_of_file;
    const wchar_t *q = p;
    const wchar_t *sev;
    DWORD id;
    int sev_code, count = 0;
    size_t k;

    id = (DWORD)wcstoul(p + 10, NULL, 10);
    sev = wcsstr(p, L"Severity=");
    sev_code = -1;
    if (sev && sev < end) {
      const wchar_t *s = sev + 9, *e = s;
      while (*e && *e != L' ' && *e != L'\r') e++;
      sev_code = severity_code(s, (size_t)(e - s));
    }
    if (sev_code < 0) {
      sd_test_fail(sd_t_, __FILE__, __LINE__, "MessageId %lu has no known Severity", (unsigned long)id);
    } else {
      id |= (DWORD)sev_code << 30;      /* mc.exe with no facility: the top two bits are the severity */
    }

    while ((q = wcsstr(q, L"Language=")) != NULL && q < end) { count++; q++; }
    if (count != (int)MC_LANG_COUNT)
      sd_test_fail(sd_t_, __FILE__, __LINE__, "MessageId %lu has %d Language= blocks, want %u",
                   (unsigned long)id, count, (unsigned)MC_LANG_COUNT);

    for (k = 0; k < MC_LANG_COUNT; k++) {
      wchar_t needle[64];
      const wchar_t *tstart, *tend;
      size_t tlen;
      wcscpy_s(needle, sizeof(needle) / sizeof(needle[0]), L"Language=");
      wcscat_s(needle, sizeof(needle) / sizeof(needle[0]), k_mc_langs[k].name);
      wcscat_s(needle, sizeof(needle) / sizeof(needle[0]), L"\r\n");
      tstart = wcsstr(p, needle);
      if (!tstart || tstart >= end) {
        sd_test_fail(sd_t_, __FILE__, __LINE__, "MessageId %lu lacks the %ls block", (unsigned long)id, k_mc_langs[k].name);
        continue;
      }
      tstart += wcslen(needle);
      tend = wcsstr(tstart, L"\r\n.\r\n");
      if (!tend || tend >= end || tend == tstart) {
        sd_test_fail(sd_t_, __FILE__, __LINE__, "MessageId %lu %ls text is empty or unterminated",
                     (unsigned long)id, k_mc_langs[k].name);
        continue;
      }
      tlen = (size_t)(tend - tstart);
      if (hm) {
        wchar_t out[2048];
        DWORD n;
        size_t olen, want;
        n = FormatMessageW(FORMAT_MESSAGE_FROM_HMODULE | FORMAT_MESSAGE_IGNORE_INSERTS, hm, id,
                           k_mc_langs[k].lang, out, (DWORD)(sizeof(out) / sizeof(out[0])), NULL);
        if (n == 0) {
          sd_test_fail(sd_t_, __FILE__, __LINE__, "id 0x%08lX does not resolve in %ls (error %lu)",
                       (unsigned long)id, k_mc_langs[k].name, (unsigned long)GetLastError());
          continue;
        }
        olen = trimmed(out, (size_t)n);
        want = trimmed(tstart, tlen);
        if (olen != want || wcsncmp(out, tstart, want) != 0)
          sd_test_fail(sd_t_, __FILE__, __LINE__, "id 0x%08lX in %ls differs from svc_events.mc (module returned %lu chars, mc %lu)",
                       (unsigned long)id, k_mc_langs[k].name, (unsigned long)olen, (unsigned long)want);
      }
    }
    blocks++;
    p = next;
  }
  free(w);
  return blocks;
}

SD_TEST(evtmsg_mc_has_six_languages_for_every_id)
{
  int blocks = walk_mc(sd_t_, NULL);
  SD_CHECK(blocks >= 10);
}

SD_TEST(evtmsg_module_resolves_every_id_in_every_language)
{
  HMODULE hm = LoadLibraryExA(SD_SVC_HOST_EXE, NULL, LOAD_LIBRARY_AS_DATAFILE);
  int blocks;
  SD_REQUIRE(hm != NULL);
  blocks = walk_mc(sd_t_, hm);
  SD_CHECK(blocks >= 10);
  FreeLibrary(hm);
}

SD_TEST(evtmsg_header_ids_carry_the_severity_bits)
{
  /* mc.exe puts the severity in the top two bits: Error = 3, Informational = 1, Warning = 2. */
  SD_CHECK_EQ_U64(SVC_MSG_START_FAILED, 0xC000083EUL);
  SD_CHECK_EQ_U64(SVC_MSG_AUDIT, 0x400004B0UL);
  SD_CHECK_EQ_U64(SVC_MSG_CLIENT_REFUSED, 0x80000C1DUL);
}
