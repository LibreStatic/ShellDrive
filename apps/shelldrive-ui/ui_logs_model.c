/* shelldrive-ui: the model of the Logs viewer (03 §10.1, §2.4.1). See ui_logs_model.h.
 *
 * Pure: no window or process calls. */
#include <windows.h>
#include <string.h>
#include <wchar.h>
#include <wctype.h>

#include "sd_base/sd_mem.h"
#include "sd_base/sd_utf.h"
#include "ui_logs_model.h"

static const char *const k_level_names[UI_LOG_LEVELS] = { "error", "warn", "info", "debug", "trace" };
static const wchar_t *const k_level_wide[UI_LOG_LEVELS] = { L"ERROR", L"WARN", L"INFO", L"DEBUG", L"TRACE" };

void ui_logs_model_init(ui_log_model *m)
{
  memset(m, 0, sizeof(*m));
}

void ui_logs_model_clear(ui_log_model *m)
{
  size_t i;
  for (i = 0; i < m->count; i++)
    sd_free(m->rec[i].line);
  m->count = 0;
  m->cursor[0] = '\0';
  m->reset = 0;
  m->dropped = 0;
}

void ui_logs_model_free(ui_log_model *m)
{
  ui_logs_model_clear(m);
  sd_free(m->rec);
  memset(m, 0, sizeof(*m));
}

int ui_log_level_parse(const char *s)
{
  size_t i;
  if (s == NULL)
    return -1;
  for (i = 0; i < UI_LOG_LEVELS; i++)
    if (strcmp(s, k_level_names[i]) == 0)
      return (int)i;
  return -1;
}

/* "<time> <LEVEL> <component> [<mount id>] <text>" for one record. Components and mount ids are ASCII; the
   text and the time are UTF-8 from the agent. */
static sd_err format_line(const sd_json *rec, int level, wchar_t **out)
{
  const char *time = sd_json_get_str(rec, "time");
  const char *comp = sd_json_get_str(rec, "component");
  const char *mount = sd_json_get_str(rec, "mount_id");
  const char *text = sd_json_get_str(rec, "text");
  wchar_t *wt = NULL, *wc = NULL, *wm = NULL, *wx = NULL, *line;
  size_t n;
  sd_err e = SD_OK;

  if (text == NULL)
    return SD_E_INVALID_PARAM;
  if (time && (e = sd_utf8_to_wide_alloc(time, (size_t)-1, SD_UTF_REPLACE, &wt)) != SD_OK)
    goto done;
  if (comp && (e = sd_utf8_to_wide_alloc(comp, (size_t)-1, SD_UTF_REPLACE, &wc)) != SD_OK)
    goto done;
  if (mount && (e = sd_utf8_to_wide_alloc(mount, (size_t)-1, SD_UTF_REPLACE, &wm)) != SD_OK)
    goto done;
  if ((e = sd_utf8_to_wide_alloc(text, (size_t)-1, SD_UTF_REPLACE, &wx)) != SD_OK)
    goto done;
  n = (wt ? wcslen(wt) : 0) + (wc ? wcslen(wc) : 0) + (wm ? wcslen(wm) : 0) + wcslen(wx) + 32;
  line = (wchar_t *)sd_alloc(n * sizeof(wchar_t));
  if (line == NULL) {
    e = SD_E_NO_MEMORY;
    goto done;
  }
  line[0] = L'\0';
  if (wt) wcscat_s(line, n, wt);
  if (wt) wcscat_s(line, n, L" ");
  wcscat_s(line, n, level >= 0 ? k_level_wide[level] : L"?");
  wcscat_s(line, n, L" ");
  if (wc) wcscat_s(line, n, wc);
  wcscat_s(line, n, L" ");
  if (wm) {
    wcscat_s(line, n, L"[");
    wcscat_s(line, n, wm);
    wcscat_s(line, n, L"] ");
  }
  wcscat_s(line, n, wx);
  *out = line;
done:
  sd_free(wt);
  sd_free(wc);
  sd_free(wm);
  sd_free(wx);
  return e;
}

static void drop_front(ui_log_model *m)
{
  sd_free(m->rec[0].line);
  memmove(&m->rec[0], &m->rec[1], (m->count - 1) * sizeof(ui_log_rec));
  m->count--;
}

sd_err ui_logs_model_apply(ui_log_model *m, const sd_json *result, size_t *appended)
{
  const sd_json *recs, *r;
  const char *cursor;
  int64_t dropped = 0;
  int reset = 0;
  size_t i, n, added = 0;

  if (appended)
    *appended = 0;
  if (result == NULL || sd_json_type_of(result) != SD_JSON_OBJECT)
    return SD_E_INVALID_PARAM;
  recs = sd_json_get(result, "records");
  if (recs == NULL || sd_json_type_of(recs) != SD_JSON_ARRAY)
    return SD_E_INVALID_PARAM;
  cursor = sd_json_get_str(result, "cursor");
  if (cursor == NULL || strlen(cursor) >= UI_LOG_CURSOR_MAX)
    return SD_E_INVALID_PARAM;
  if (sd_json_get(result, "dropped") && !sd_json_get_int64(result, "dropped", &dropped))
    return SD_E_INVALID_PARAM;
  if (sd_json_get(result, "reset") && !sd_json_get_bool(result, "reset", &reset))
    return SD_E_INVALID_PARAM;
  if (dropped < 0)
    return SD_E_INVALID_PARAM;

  /* every record is checked before the model changes */
  n = sd_json_count(recs);
  for (i = 0; i < n; i++) {
    r = sd_json_at(recs, i);
    if (sd_json_type_of(r) != SD_JSON_OBJECT || sd_json_get(r, "seq") == NULL ||
        sd_json_get_str(r, "text") == NULL)
      return SD_E_INVALID_PARAM;
  }

  if (m->cap == 0) {
    m->rec = (ui_log_rec *)sd_alloc(UI_LOG_MAX_RECORDS * sizeof(ui_log_rec));
    if (m->rec == NULL)
      return SD_E_NO_MEMORY;
    m->cap = UI_LOG_MAX_RECORDS;
  }

  if (reset && dropped == 0)
    ui_logs_model_clear(m);
  for (i = 0; i < n; i++) {
    const char *lv;
    int64_t seq = 0;
    wchar_t *line = NULL;
    int level;
    sd_err e;
    r = sd_json_at(recs, i);
    if (!sd_json_get_int64(r, "seq", &seq) || seq < 0)
      continue;
    lv = sd_json_get_str(r, "level");
    level = ui_log_level_parse(lv);
    e = format_line(r, level, &line);
    if (e != SD_OK)
      continue;
    if (m->count == m->cap)
      drop_front(m);
    m->rec[m->count].seq = (uint64_t)seq;
    m->rec[m->count].level = level;
    m->rec[m->count].line = line;
    m->count++;
    added++;
  }
  strcpy_s(m->cursor, sizeof(m->cursor), cursor);
  m->reset = reset ? 1 : 0;
  m->dropped = (uint64_t)dropped;
  if (appended)
    *appended = added;
  return SD_OK;
}

/* Case-insensitive substring test on wide text (CRT towlower; the viewer's search is for log text). */
static int contains_ci(const wchar_t *hay, const wchar_t *needle)
{
  size_t hn = wcslen(hay), nn = wcslen(needle), i, j;
  if (nn == 0)
    return 1;
  for (i = 0; i + nn <= hn; i++) {
    for (j = 0; j < nn; j++) {
      if (towlower(hay[i + j]) != towlower(needle[j]))
        break;
    }
    if (j == nn)
      return 1;
  }
  return 0;
}

int ui_logs_match(const ui_log_rec *r, int level_max, const wchar_t *search)
{
  /* a record of unknown level passes only the most verbose filter, so it is never silently lost */
  if (r->level >= 0 && r->level > level_max)
    return 0;
  if (r->level < 0 && level_max < UI_LOG_LEVELS - 1)
    return 0;
  if (search == NULL || search[0] == L'\0')
    return 1;
  return contains_ci(r->line, search);
}

sd_err ui_logs_build_text(const ui_log_model *m, int level_max, const wchar_t *search, wchar_t **out,
                          size_t *lines)
{
  size_t i, total = 1, pos = 0;
  size_t shown = 0;
  wchar_t *buf;

  if (out == NULL || lines == NULL)
    return SD_E_INVALID_PARAM;
  *out = NULL;
  *lines = 0;
  for (i = 0; i < m->count; i++) {
    if (!ui_logs_match(&m->rec[i], level_max, search))
      continue;
    total += wcslen(m->rec[i].line) + 2;
    shown++;
  }
  buf = (wchar_t *)sd_alloc(total * sizeof(wchar_t));
  if (buf == NULL)
    return SD_E_NO_MEMORY;
  for (i = 0; i < m->count; i++) {
    size_t len;
    if (!ui_logs_match(&m->rec[i], level_max, search))
      continue;
    len = wcslen(m->rec[i].line);
    memcpy(buf + pos, m->rec[i].line, len * sizeof(wchar_t));
    pos += len;
    buf[pos++] = L'\r';
    buf[pos++] = L'\n';
  }
  buf[pos] = L'\0';
  *out = buf;
  *lines = shown;
  return SD_OK;
}
