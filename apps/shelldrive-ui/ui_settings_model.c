/* shelldrive-ui: the settings model of the Settings window (03 §3.2, §7.5, §9.3). See ui_settings_model.h.
 *
 * Pure: no window or process calls. */
#include <windows.h>
#include <string.h>
#include <wchar.h>

#include "ui_settings_model.h"

const char *const g_ui_set_lang_codes[UI_SET_LANG_COUNT] = { "", "en", "es", "fr", "pt-BR", "it", "de" };

int ui_settings_lang_index(const char *code)
{
  size_t i;
  if (code == NULL || code[0] == '\0')
    return 0;
  for (i = 1; i < UI_SET_LANG_COUNT; i++)
    if (_stricmp(code, g_ui_set_lang_codes[i]) == 0)
      return (int)i;
  return 0;
}

void ui_settings_from_sd(const sd_settings *s, ui_settings_model *m)
{
  memset(m, 0, sizeof(*m));
  if (strcmp(s->ui_language, "system") != 0)
    strcpy_s(m->language, sizeof(m->language), s->ui_language);
  m->notify = s->notify ? 1 : 0;
  m->default_backend = s->default_backend;
  /* the budget is stored in bytes and shown in whole MiB (rounded down) */
  m->cache_mb = (unsigned)(s->cache_memory / ((UINT64)1 << 20));
}

void ui_settings_to_sd(const ui_settings_model *m, sd_settings *s)
{
  strcpy_s(s->ui_language, sizeof(s->ui_language), m->language);
  s->notify = m->notify ? 1 : 0;
  s->default_backend = m->default_backend;
  s->cache_memory = (UINT64)m->cache_mb << 20;
}

sd_err ui_settings_parse_cache(const wchar_t *text, unsigned *mb)
{
  unsigned long v = 0;
  const wchar_t *p = text;
  int digits = 0;
  if (text == NULL || mb == NULL)
    return SD_E_INVALID_PARAM;
  while (*p == L' ' || *p == L'\t')
    p++;
  while (*p >= L'0' && *p <= L'9') {
    v = v * 10u + (unsigned long)(*p - L'0');
    if (v > UI_SET_CACHE_MB_MAX)
      return SD_E_INVALID_PARAM;
    digits++;
    p++;
  }
  while (*p == L' ' || *p == L'\t')
    p++;
  if (digits == 0 || *p != L'\0')
    return SD_E_INVALID_PARAM;
  if (v != 0 && v < UI_SET_CACHE_MB_MIN)
    return SD_E_INVALID_PARAM;
  *mb = (unsigned)v;
  return SD_OK;
}

sd_err ui_settings_run_command(const wchar_t *exe, wchar_t *out, size_t cap)
{
  if (exe == NULL || out == NULL || cap == 0)
    return SD_E_INVALID_PARAM;
  if (wcschr(exe, L'"') != NULL)
    return SD_E_INVALID_PARAM;
  if (_snwprintf_s(out, cap, _TRUNCATE, L"\"%s\" --tray", exe) < 0)
    return SD_E_NAME_TOO_LONG;
  return SD_OK;
}
