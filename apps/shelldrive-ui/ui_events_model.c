/* shelldrive-ui: the model of the event list (03 §7.7). See ui_events_model.h. */
#include <string.h>
#include <wchar.h>

#include "sd_base/sd_mem.h"
#include "ui_events_model.h"

void ui_ev_init(ui_ev_log *l)
{
  memset(l, 0, sizeof(*l));
  l->next_seq = 1;
}

void ui_ev_clear(ui_ev_log *l)
{
  unsigned long long seq = l->next_seq;
  memset(l, 0, sizeof(*l));
  l->next_seq = seq != 0 ? seq : 1;
}

static void copy_cut(wchar_t *dst, size_t cap, const wchar_t *src)
{
  size_t n = src != NULL ? wcslen(src) : 0;
  size_t i;
  if (n >= cap)
    n = cap - 1;
  for (i = 0; i < n; i++)
    dst[i] = src[i] < 0x20 ? L' ' : src[i];   /* control characters would break the rows and the copy */
  dst[n] = 0;
}

unsigned long long ui_ev_add(ui_ev_log *l, ui_ev_kind kind, const ui_ev_time *t, const wchar_t *subject,
                             const wchar_t *text)
{
  ui_ev_entry *e;
  size_t idx;
  if (l->next_seq == 0)
    l->next_seq = 1;
  if (l->count == UI_EV_MAX) {
    idx = l->first;
    l->first = (l->first + 1) % UI_EV_MAX;
  } else {
    idx = (l->first + l->count) % UI_EV_MAX;
    l->count++;
  }
  e = &l->entry[idx];
  memset(e, 0, sizeof(*e));
  e->seq = l->next_seq++;
  if (t != NULL)
    e->time = *t;
  e->kind = ((unsigned)kind < (unsigned)UI_EV_KINDS) ? kind : UI_EV_INFO;
  copy_cut(e->subject, UI_EV_SUBJECT_MAX, subject);
  copy_cut(e->text, UI_EV_TEXT_MAX, text);
  return e->seq;
}

const ui_ev_entry *ui_ev_at(const ui_ev_log *l, size_t i)
{
  if (i >= l->count)
    return NULL;
  return &l->entry[(l->first + i) % UI_EV_MAX];
}

static wchar_t *put_digits(wchar_t *p, unsigned v, unsigned width)
{
  unsigned i;
  for (i = width; i > 0; i--) {
    p[i - 1] = (wchar_t)(L'0' + v % 10);
    v /= 10;
  }
  return p + width;
}

void ui_ev_format_time(const ui_ev_time *t, wchar_t out[UI_EV_TIME_MAX])
{
  wchar_t *p = out;
  p = put_digits(p, t->year, 4);
  *p++ = L'-';
  p = put_digits(p, t->month, 2);
  *p++ = L'-';
  p = put_digits(p, t->day, 2);
  *p++ = L' ';
  p = put_digits(p, t->hour, 2);
  *p++ = L':';
  p = put_digits(p, t->minute, 2);
  *p++ = L':';
  p = put_digits(p, t->second, 2);
  *p = 0;
}

static wchar_t lower(wchar_t c)
{
  return (c >= L'A' && c <= L'Z') ? (wchar_t)(c + (L'a' - L'A')) : c;
}

/* Not the CRT wcsstr: the x86 build dispatches to SSE4.2 code that the x86-ia32 ISA audit has not reviewed. */
int ui_ev_contains(const wchar_t *s, const wchar_t *needle)
{
  size_t i, j;
  if (needle == NULL || needle[0] == 0)
    return 1;
  if (s == NULL)
    return 0;
  for (i = 0; s[i] != 0; i++) {
    for (j = 0; needle[j] != 0 && s[i + j] != 0 && lower(s[i + j]) == lower(needle[j]); j++)
      ;
    if (needle[j] == 0)
      return 1;
  }
  return 0;
}

int ui_ev_match(const ui_ev_entry *e, unsigned kind_mask, const wchar_t *search)
{
  if ((kind_mask & (1u << (unsigned)e->kind)) == 0)
    return 0;
  return ui_ev_contains(e->subject, search) || ui_ev_contains(e->text, search);
}

sd_err ui_ev_build_text(const ui_ev_log *l, unsigned kind_mask, const wchar_t *search,
                        const wchar_t *const kind_label[UI_EV_KINDS], wchar_t **out, size_t *lines)
{
  size_t i, need = 1, n = 0;
  wchar_t *buf, *p;
  *out = NULL;
  if (lines != NULL)
    *lines = 0;
  for (i = 0; i < l->count; i++) {
    const ui_ev_entry *e = ui_ev_at(l, i);
    if (!ui_ev_match(e, kind_mask, search))
      continue;
    need += UI_EV_TIME_MAX + wcslen(e->subject) + wcslen(kind_label[e->kind]) + wcslen(e->text) + 5;
  }
  buf = (wchar_t *)sd_alloc(need * sizeof(wchar_t));
  if (buf == NULL)
    return SD_E_NO_MEMORY;
  p = buf;
  for (i = 0; i < l->count; i++) {
    const ui_ev_entry *e = ui_ev_at(l, i);
    wchar_t tm[UI_EV_TIME_MAX];
    const wchar_t *parts[4];
    size_t k;
    if (!ui_ev_match(e, kind_mask, search))
      continue;
    ui_ev_format_time(&e->time, tm);
    parts[0] = tm;
    parts[1] = e->subject;
    parts[2] = kind_label[e->kind];
    parts[3] = e->text;
    for (k = 0; k < 4; k++) {
      size_t len = wcslen(parts[k]);
      memcpy(p, parts[k], len * sizeof(wchar_t));
      p += len;
      *p++ = k < 3 ? L'\t' : L'\r';
    }
    *p++ = L'\n';
    n++;
  }
  *p = 0;
  *out = buf;
  if (lines != NULL)
    *lines = n;
  return SD_OK;
}
