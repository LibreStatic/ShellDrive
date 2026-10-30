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
  int k;
  memset(m, 0, sizeof(*m));
  if (strcmp(s->ui_language, "system") != 0)
    strcpy_s(m->language, sizeof(m->language), s->ui_language);
  m->notify = s->notify ? 1 : 0;
  m->default_backend = s->default_backend;
  /* the budget is stored in bytes and shown in whole MiB (rounded down) */
  m->cache_mb = (unsigned)(s->cache_memory / ((UINT64)1 << 20));
  m->openssh_source = s->openssh_source ? 1 : 0;
  m->putty_source = s->putty_source ? 1 : 0;
  m->roam_credentials = s->persist_enterprise ? 1 : 0;
  m->write_mode = s->default_write_mode == SD_PROFILE_WRITE_BEHIND ? SD_PROFILE_WRITE_BEHIND : SD_PROFILE_WRITE_THROUGH;
  m->log_strict = s->log_privacy == SD_SETTINGS_PRIVACY_STRICT ? 1 : 0;
  m->agent_logon = s->agent_start_at_logon ? 1 : 0;
  for (k = 0; k < SD_NOTIFY_COUNT; k++)
    if (s->notify_kind[k])
      m->notify_kinds |= 1u << k;
}

void ui_settings_to_sd(const ui_settings_model *m, sd_settings *s)
{
  int k;
  strcpy_s(s->ui_language, sizeof(s->ui_language), m->language);
  s->notify = m->notify ? 1 : 0;
  s->default_backend = m->default_backend;
  s->cache_memory = (UINT64)m->cache_mb << 20;
  s->openssh_source = m->openssh_source ? 1 : 0;
  s->putty_source = m->putty_source ? 1 : 0;
  s->persist_enterprise = m->roam_credentials ? 1 : 0;
  s->default_write_mode = m->write_mode == SD_PROFILE_WRITE_BEHIND ? SD_PROFILE_WRITE_BEHIND : SD_PROFILE_WRITE_THROUGH;
  s->log_privacy = m->log_strict ? SD_SETTINGS_PRIVACY_STRICT : SD_SETTINGS_PRIVACY_STANDARD;
  s->agent_start_at_logon = m->agent_logon ? 1 : 0;
  for (k = 0; k < SD_NOTIFY_COUNT; k++)
    s->notify_kind[k] = (m->notify_kinds & (1u << k)) ? 1 : 0;
}

unsigned ui_settings_locked(const ui_set_policy *p)
{
  unsigned mask = 0;
  if (p == NULL)
    return 0;
  if (p->language_set && p->language[0] != '\0')
    mask |= UI_SET_F_LANGUAGE;
  if (p->sources_disabled)
    mask |= UI_SET_F_OPENSSH | UI_SET_F_PUTTY;
  if (p->force_through)
    mask |= UI_SET_F_WRITE;
  if (p->privacy_set)
    mask |= UI_SET_F_PRIVACY;
  return mask;
}

unsigned ui_settings_apply_policy(ui_settings_model *m, const ui_set_policy *p)
{
  unsigned mask = ui_settings_locked(p);
  if (mask & UI_SET_F_LANGUAGE)
    strcpy_s(m->language, sizeof(m->language), p->language);
  if (mask & UI_SET_F_OPENSSH)
    m->openssh_source = 0;
  if (mask & UI_SET_F_PUTTY)
    m->putty_source = 0;
  if (mask & UI_SET_F_WRITE)
    m->write_mode = SD_PROFILE_WRITE_THROUGH;
  if (mask & UI_SET_F_PRIVACY)
    m->log_strict = p->privacy_strict ? 1 : 0;
  return mask;
}

unsigned ui_settings_changed(const ui_settings_model *a, const ui_settings_model *b)
{
  unsigned d = 0;
  if (strcmp(a->language, b->language) != 0) d |= UI_SET_F_LANGUAGE;
  if ((a->notify != 0) != (b->notify != 0)) d |= UI_SET_F_NOTIFY;
  if (a->default_backend != b->default_backend) d |= UI_SET_F_BACKEND;
  if (a->cache_mb != b->cache_mb) d |= UI_SET_F_CACHE;
  if ((a->start_at_logon != 0) != (b->start_at_logon != 0)) d |= UI_SET_F_LOGON;
  if ((a->openssh_source != 0) != (b->openssh_source != 0)) d |= UI_SET_F_OPENSSH;
  if ((a->putty_source != 0) != (b->putty_source != 0)) d |= UI_SET_F_PUTTY;
  if ((a->roam_credentials != 0) != (b->roam_credentials != 0)) d |= UI_SET_F_ROAMING;
  if (a->write_mode != b->write_mode) d |= UI_SET_F_WRITE;
  if ((a->log_strict != 0) != (b->log_strict != 0)) d |= UI_SET_F_PRIVACY;
  if ((a->agent_logon != 0) != (b->agent_logon != 0)) d |= UI_SET_F_AGENT;
  if ((a->notify_kinds & UI_SET_KINDS_ALL) != (b->notify_kinds & UI_SET_KINDS_ALL)) d |= UI_SET_F_KINDS;
  return d;
}

void ui_settings_to_sd_masked(const ui_settings_model *m, unsigned locked, sd_settings *s)
{
  sd_settings keep = *s;
  ui_settings_to_sd(m, s);
  if (locked & UI_SET_F_LANGUAGE)
    strcpy_s(s->ui_language, sizeof(s->ui_language), keep.ui_language);
  if (locked & UI_SET_F_OPENSSH)
    s->openssh_source = keep.openssh_source;
  if (locked & UI_SET_F_PUTTY)
    s->putty_source = keep.putty_source;
  if (locked & UI_SET_F_WRITE)
    s->default_write_mode = keep.default_write_mode;
  if (locked & UI_SET_F_PRIVACY)
    s->log_privacy = keep.log_privacy;
}

ui_set_note ui_settings_source_note(int enabled, int locked, int src_state)
{
  if (locked)
    return UI_SET_NOTE_MANAGED;
  if (enabled && src_state == 3)
    return UI_SET_NOTE_INSECURE;
  return UI_SET_NOTE_NONE;
}

ui_set_webclient ui_settings_webclient_kind(int state)
{
  switch (state) {
  case 1: return UI_SET_WC_RUNNING;
  case 2: return UI_SET_WC_STOPPED;
  case 3: return UI_SET_WC_DISABLED;
  case 4: return UI_SET_WC_MISSING;
  default: return UI_SET_WC_UNKNOWN;
  }
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

sd_err ui_settings_agent_run_command(const wchar_t *host_exe, wchar_t *out, size_t cap)
{
  if (host_exe == NULL || out == NULL || cap == 0)
    return SD_E_INVALID_PARAM;
  if (wcschr(host_exe, L'"') != NULL)
    return SD_E_INVALID_PARAM;
  if (_snwprintf_s(out, cap, _TRUNCATE, L"\"%s\" agent --logon", host_exe) < 0)
    return SD_E_NAME_TOO_LONG;
  return SD_OK;
}
