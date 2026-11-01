/* shelldrive-ui: the mapping of MessageBox flags to a task dialog (06 §6.2). See ui_taskdlg_model.h. */
#include <windows.h>
#include <string.h>
#include <wchar.h>

#include "ui_taskdlg_model.h"

#ifndef MB_TYPEMASK
#define MB_TYPEMASK 0x0000000Fu
#endif

int ui_task_map_flags(UINT mb_flags, ui_task_map *out)
{
  static const int ids_ok[] = { IDOK };
  static const int ids_okcancel[] = { IDOK, IDCANCEL };
  static const int ids_yesno[] = { IDYES, IDNO };
  static const int ids_yesnocancel[] = { IDYES, IDNO, IDCANCEL };
  static const int ids_retrycancel[] = { IDRETRY, IDCANCEL };
  const int *ids;
  size_t n, pick;
  unsigned buttons;
  int cancel;

  if (out == NULL)
    return 0;
  memset(out, 0, sizeof(*out));
  switch (mb_flags & MB_TYPEMASK) {
  case MB_OK:
    ids = ids_ok; n = 1; buttons = UI_TASK_BTN_OK; cancel = 1;
    break;
  case MB_OKCANCEL:
    ids = ids_okcancel; n = 2; buttons = UI_TASK_BTN_OK | UI_TASK_BTN_CANCEL; cancel = 1;
    break;
  case MB_YESNO:
    ids = ids_yesno; n = 2; buttons = UI_TASK_BTN_YES | UI_TASK_BTN_NO; cancel = 0;
    break;
  case MB_YESNOCANCEL:
    ids = ids_yesnocancel; n = 3; buttons = UI_TASK_BTN_YES | UI_TASK_BTN_NO | UI_TASK_BTN_CANCEL; cancel = 1;
    break;
  case MB_RETRYCANCEL:
    ids = ids_retrycancel; n = 2; buttons = UI_TASK_BTN_RETRY | UI_TASK_BTN_CANCEL; cancel = 1;
    break;
  default:
    return 0;
  }
  switch (mb_flags & MB_DEFMASK) {
  case MB_DEFBUTTON2: pick = 1; break;
  case MB_DEFBUTTON3: pick = 2; break;
  default: pick = 0; break;
  }
  if (pick >= n)
    pick = 0;
  out->buttons = buttons;
  out->default_id = ids[pick];
  out->allow_cancel = cancel;
  switch (mb_flags & MB_ICONMASK) {
  case MB_ICONERROR: out->icon = UI_TASK_ICON_ERROR; break;           /* also MB_ICONSTOP and MB_ICONHAND */
  case MB_ICONWARNING: out->icon = UI_TASK_ICON_WARNING; break;       /* also MB_ICONEXCLAMATION */
  case MB_ICONINFORMATION: out->icon = UI_TASK_ICON_INFO; break;      /* also MB_ICONASTERISK */
  default: out->icon = UI_TASK_ICON_NONE; break;
  }
  return 1;
}

static size_t append(wchar_t *out, size_t cap, size_t len, const wchar_t *sep, const wchar_t *text)
{
  size_t sl = len > 0 ? wcslen(sep) : 0, tl = wcslen(text);
  if (len + sl + tl + 1 > cap)
    return (size_t)-1;
  if (sl > 0)
    memcpy(out + len, sep, sl * sizeof(wchar_t));
  memcpy(out + len + sl, text, tl * sizeof(wchar_t));
  out[len + sl + tl] = L'\0';
  return len + sl + tl;
}

size_t ui_task_plain_text(const wchar_t *main_text, const wchar_t *content, const wchar_t *details,
                          wchar_t *out, size_t cap)
{
  size_t len = 0;
  if (out == NULL || cap == 0)
    return 0;
  out[0] = L'\0';
  if (main_text == NULL || main_text[0] == L'\0')
    return 0;
  len = append(out, cap, 0, L"\n\n", main_text);
  if (len != (size_t)-1 && content != NULL && content[0] != L'\0')
    len = append(out, cap, len, L"\n\n", content);
  if (len != (size_t)-1 && details != NULL && details[0] != L'\0')
    len = append(out, cap, len, L"\n\n", details);
  if (len == (size_t)-1) {
    out[0] = L'\0';
    return 0;
  }
  return len;
}
