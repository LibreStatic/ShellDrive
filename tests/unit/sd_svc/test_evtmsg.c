/* The Event Log message tables of shelldrive-host (03 §10.3, §9.1, §9.3).
 *
 * The generated svc_events.mc (written by sdl10n from l10n/svc, compiled by mc.exe -u) names one language per LANGID:
 * every sublanguage that Windows defines for the six primary languages, plus the primary-neutral id. The test reads
 * that LanguageNames list from the .mc, checks that every id has one Language= block per entry, and that the
 * shelldrive-host.exe the build made resolves every id in every LANGID (FormatMessage, FROM_HMODULE,
 * LOAD_LIBRARY_AS_DATAFILE) to the text of that block. Nothing here writes the Event Log or registers a source. */
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#include "sd_test.h"
#include "svc_events.h"

#ifndef SD_SVC_EVENTS_MC
#error "SD_SVC_EVENTS_MC must name the generated svc_events.mc (relative to the test executable)"
#endif
#ifndef SD_SVC_HOST_EXE
#error "SD_SVC_HOST_EXE must name the built shelldrive-host.exe (relative to the test executable)"
#endif

/* sdl10n write_mc: 17 en + 22 es + 7 fr + 3 pt + 3 it + 6 de LANGIDs (SDK SUBLANG values, with the neutral ids). */
#define MC_EXPECTED_LANGS 58
#define MC_MAX_LANGS 80
#define MC_EVENTS_MIN 10

typedef struct mc_entry {
  wchar_t name[16];             /* LanguageNames identifier, L<LCID> */
  LANGID lang;
} mc_entry;

static mc_entry g_langs[MC_MAX_LANGS];
static int g_nlangs;

/* Reads the UTF-16LE .mc into a NUL-terminated buffer of wchar_t (16 bits on Windows). */
static wchar_t *read_mc(size_t *units_out)
{
  FILE *f = NULL;
  long n;
  unsigned char *buf;
  wchar_t *w;
  char mc[MAX_PATH];
  size_t i, units;
  if (!sd_test_exe_dir_path(SD_SVC_EVENTS_MC, mc, sizeof(mc))) return NULL;
  if (fopen_s(&f, mc, "rb") != 0 || !f) return NULL;
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

/* Reads the LanguageNames=( ... ) list: one "L<LCID>=0x<LCID>:MSG<LCID>" entry per line. */
static int parse_language_names(const wchar_t *w)
{
  const wchar_t *p = wcsstr(w, L"LanguageNames=(");
  const wchar_t *close;
  int n = 0;
  if (!p) return 0;
  close = wcschr(p, L')');
  if (!close) return 0;
  p += 15;                       /* past "LanguageNames=(" */
  while (p < close && n < MC_MAX_LANGS) {
    const wchar_t *eq, *eol;
    size_t nl;
    while (p < close && (*p == L' ' || *p == L'\r' || *p == L'\n')) p++;
    if (p >= close) break;
    eq = wcschr(p, L'=');
    if (!eq || eq > close) break;
    nl = (size_t)(eq - p);
    if (nl == 0 || nl >= sizeof(g_langs[0].name) / sizeof(wchar_t)) break;
    wcsncpy_s(g_langs[n].name, sizeof(g_langs[n].name) / sizeof(wchar_t), p, nl);
    g_langs[n].lang = (LANGID)(wcstoul(eq + 1, NULL, 16) & 0xFFFF);
    eol = wcsstr(eq, L"\r\n");
    if (!eol || eol > close) eol = close;
    p = eol;
    n++;
  }
  return n;
}

static int lang_present(LANGID lang)
{
  int i;
  for (i = 0; i < g_nlangs; i++)
    if (g_langs[i].lang == lang) return 1;
  return 0;
}

/* Walks every MessageId block of the .mc. For each id and each LANGID of the LanguageNames list, checks the block and,
   when hm is not NULL, that the module resolves the id in that LANGID to the text of the block. Returns the blocks. */
static int walk_mc(sd_test_ctx *sd_t_, HMODULE hm)
{
  size_t units = 0;
  wchar_t *w = read_mc(&units);
  const wchar_t *p, *end_of_file;
  int blocks = 0;
  if (!w) { sd_test_fail(sd_t_, __FILE__, __LINE__, "cannot read the generated %s", SD_SVC_EVENTS_MC); return 0; }
  end_of_file = w + units;
  g_nlangs = parse_language_names(w);
  if (g_nlangs != MC_EXPECTED_LANGS)
    sd_test_fail(sd_t_, __FILE__, __LINE__, "LanguageNames lists %d languages, want %d", g_nlangs, MC_EXPECTED_LANGS);
  p = wcsstr(w, L"MessageId=");
  while (p) {
    const wchar_t *next = wcsstr(p + 10, L"MessageId=");
    const wchar_t *end = next ? next : end_of_file;
    const wchar_t *q = p;
    const wchar_t *sev;
    DWORD id;
    int sev_code, count = 0, k;

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
    if (count != g_nlangs)
      sd_test_fail(sd_t_, __FILE__, __LINE__, "MessageId %lu has %d Language= blocks, want %d",
                   (unsigned long)id, count, g_nlangs);

    for (k = 0; k < g_nlangs; k++) {
      wchar_t needle[32];
      const wchar_t *tstart, *tend;
      size_t tlen;
      wcscpy_s(needle, sizeof(needle) / sizeof(needle[0]), L"Language=");
      wcscat_s(needle, sizeof(needle) / sizeof(needle[0]), g_langs[k].name);
      wcscat_s(needle, sizeof(needle) / sizeof(needle[0]), L"\r\n");
      tstart = wcsstr(p, needle);
      if (!tstart || tstart >= end) {
        sd_test_fail(sd_t_, __FILE__, __LINE__, "MessageId %lu lacks the %ls block", (unsigned long)id, g_langs[k].name);
        continue;
      }
      tstart += wcslen(needle);
      tend = wcsstr(tstart, L"\r\n.\r\n");
      if (!tend || tend >= end || tend == tstart) {
        sd_test_fail(sd_t_, __FILE__, __LINE__, "MessageId %lu %ls text is empty or unterminated",
                     (unsigned long)id, g_langs[k].name);
        continue;
      }
      tlen = (size_t)(tend - tstart);
      if (hm) {
        wchar_t out[2048];
        DWORD n;
        size_t olen, want;
        n = FormatMessageW(FORMAT_MESSAGE_FROM_HMODULE | FORMAT_MESSAGE_IGNORE_INSERTS, hm, id,
                           g_langs[k].lang, out, (DWORD)(sizeof(out) / sizeof(out[0])), NULL);
        if (n == 0) {
          sd_test_fail(sd_t_, __FILE__, __LINE__, "id 0x%08lX does not resolve in LANGID 0x%04X (%ls, error %lu)",
                       (unsigned long)id, (unsigned)g_langs[k].lang, g_langs[k].name, (unsigned long)GetLastError());
          continue;
        }
        olen = trimmed(out, (size_t)n);
        want = trimmed(tstart, tlen);
        if (olen != want || wcsncmp(out, tstart, want) != 0)
          sd_test_fail(sd_t_, __FILE__, __LINE__, "id 0x%08lX in LANGID 0x%04X (%ls) differs from svc_events.mc (module %lu chars, mc %lu)",
                       (unsigned long)id, (unsigned)g_langs[k].lang, g_langs[k].name, (unsigned long)olen, (unsigned long)want);
      }
    }
    blocks++;
    p = next;
  }
  free(w);
  return blocks;
}

/* The LANGIDs the Event Viewer asks for in practice: the six primary neutral ids, the sublanguages the project
   names (es-ES, es-MX, pt-PT, fr-CA, de-AT, it-CH, en-GB) and the regional ids of the single texts. */
static const LANGID k_required[] = {
  0x0409, 0x0809, 0x0C0A, 0x080A, 0x2C0A, 0x0816, 0x0416, 0x0C0C, 0x040C, 0x0C07, 0x0407, 0x0810, 0x0410,
  0x0009, 0x000A, 0x000C, 0x0016, 0x0010, 0x0007,
};

SD_TEST(evtmsg_mc_has_every_langid_for_every_id)
{
  int blocks = walk_mc(sd_t_, NULL);
  size_t i;
  SD_CHECK(blocks >= MC_EVENTS_MIN);
  for (i = 0; i < sizeof(k_required) / sizeof(k_required[0]); i++)
    if (!lang_present(k_required[i]))
      sd_test_fail(sd_t_, __FILE__, __LINE__, "LanguageNames lacks LANGID 0x%04X", (unsigned)k_required[i]);
}

SD_TEST(evtmsg_module_resolves_every_id_in_every_langid)
{
  char host[MAX_PATH];
  HMODULE hm;
  int blocks;
  if (!sd_test_exe_dir_path(SD_SVC_HOST_EXE, host, sizeof(host))) {
    sd_test_fail(sd_t_, __FILE__, __LINE__, "cannot resolve %s next to the test executable", SD_SVC_HOST_EXE);
    return;
  }
  hm = LoadLibraryExA(host, NULL, LOAD_LIBRARY_AS_DATAFILE);
  SD_REQUIRE(hm != NULL);
  blocks = walk_mc(sd_t_, hm);
  SD_CHECK(blocks >= MC_EVENTS_MIN);
  FreeLibrary(hm);
}

SD_TEST(evtmsg_header_ids_carry_the_severity_bits)
{
  /* mc.exe puts the severity in the top two bits: Error = 3, Informational = 1, Warning = 2. */
  SD_CHECK_EQ_U64(SVC_MSG_START_FAILED, 0xC000083EUL);
  SD_CHECK_EQ_U64(SVC_MSG_AUDIT, 0x400004B0UL);
  SD_CHECK_EQ_U64(SVC_MSG_CLIENT_REFUSED, 0x80000C1DUL);
}
