/* shelldrive-ui: the mount list (from "list" and mount.state events) and the text helpers. */
#include <windows.h>
#include <string.h>
#include <wchar.h>

#include "sd_base/sd_mem.h"
#include "sd_l10n/sd_l10n.h"
#include "sd_l10n_ui_ids.h"
#include "ui_int.h"

void ui_text_utf8(const char *s, wchar_t *out, size_t cch)
{
  if (out == NULL || cch == 0)
    return;
  out[0] = 0;
  if (s == NULL)
    return;
  if (MultiByteToWideChar(CP_UTF8, 0, s, -1, out, (int)cch) == 0)
    out[0] = 0;
  out[cch - 1] = 0;
}

void ui_text_ascii(const wchar_t *s, char *out, size_t cch)
{
  size_t i;
  if (out == NULL || cch == 0)
    return;
  out[0] = 0;
  if (s == NULL)
    return;
  for (i = 0; i + 1 < cch && s[i] != 0; i++)
    out[i] = (s[i] < 0x80) ? (char)s[i] : '?';
  out[i] = 0;
}

wchar_t *ui_format1(sd_msg_id msg_id, const char *name, const wchar_t *value)
{
  sd_arg a[1];
  a[0].name = name;
  a[0].type = SD_ARG_STR;
  a[0].v.s = value ? value : L"";
  return sd_l10n_format_alloc(msg_id, a, 1);
}

wchar_t *ui_format_count(sd_msg_id msg_id, long long count)
{
  sd_arg a[1];
  a[0].name = "count";
  a[0].type = SD_ARG_INT;
  a[0].v.i = count;
  return sd_l10n_format_alloc(msg_id, a, 1);
}

void ui_model_clear(ui_model *m)
{
  memset(m, 0, sizeof(*m));
}

/* Appends ":port" to the host name unless the port is the SSH default or absent. */
static void server_text(const sd_json *mo, wchar_t *out, size_t cch)
{
  wchar_t host[256];
  int64_t port = 0;
  ui_text_utf8(sd_json_get_str(mo, "host"), host, SD_COUNTOF(host));
  wcsncpy_s(out, cch, host, _TRUNCATE);
  if (sd_json_get_int64(mo, "port", &port) && port > 0 && port != 22) {
    wchar_t rev[24];
    size_t k = 0, len = wcslen(out);
    uint64_t v = (uint64_t)port;
    do {
      rev[k++] = (wchar_t)(L'0' + (wchar_t)(v % 10u));
      v /= 10u;
    } while (v != 0 && k < SD_COUNTOF(rev));
    if (len + 1 < cch) {
      out[len++] = L':';
      out[len] = 0;
    }
    while (k > 0 && len + 1 < cch)
      out[len++] = rev[--k];
    out[len] = 0;
  }
}

void ui_model_set_list(ui_model *m, const sd_json *result)
{
  const sd_json *arr = sd_json_get(result, "mounts");
  size_t i, n = sd_json_count(arr);

  ui_model_clear(m);
  for (i = 0; i < n && m->count < UI_MAX_MOUNTS; i++) {
    const sd_json *mo = sd_json_at(arr, i);
    ui_mount *it = &m->items[m->count];
    const char *s;
    wchar_t tmp[8];

    if (sd_json_type_of(mo) != SD_JSON_OBJECT)
      continue;
    s = sd_json_get_str(mo, "mount_id");
    if (s == NULL || strlen(s) >= sizeof(it->id))
      continue;
    strcpy_s(it->id, sizeof(it->id), s);
    s = sd_json_get_str(mo, "state");
    if (s != NULL && strlen(s) < sizeof(it->state))
      strcpy_s(it->state, sizeof(it->state), s);
    ui_text_utf8(it->state, it->state_w, SD_COUNTOF(it->state_w));
    ui_text_utf8(sd_json_get_str(mo, "target"), tmp, SD_COUNTOF(tmp));
    if (!ui_drive_normalize(tmp, it->drive))
      it->drive[0] = 0;
    s = sd_json_get_str(mo, "profile_id");
    it->profile_id[0] = 0;
    if (s != NULL && strlen(s) < sizeof(it->profile_id))
      strcpy_s(it->profile_id, sizeof(it->profile_id), s);
    ui_text_utf8(sd_json_get_str(mo, "profile"), it->profile, SD_COUNTOF(it->profile));
    ui_text_utf8(sd_json_get_str(mo, "backend"), it->backend, SD_COUNTOF(it->backend));
    server_text(mo, it->server, SD_COUNTOF(it->server));
    m->count++;
  }
}

ui_mount *ui_model_find_id(ui_model *m, const char *id)
{
  size_t i;
  if (id == NULL)
    return NULL;
  for (i = 0; i < m->count; i++)
    if (strcmp(m->items[i].id, id) == 0)
      return &m->items[i];
  return NULL;
}

ui_mount *ui_model_find_drive(ui_model *m, const wchar_t *drive)
{
  size_t i;
  if (drive == NULL || drive[0] == 0)
    return NULL;
  for (i = 0; i < m->count; i++)
    if (wcscmp(m->items[i].drive, drive) == 0)
      return &m->items[i];
  return NULL;
}

void ui_model_remove(ui_model *m, ui_mount *item)
{
  size_t idx = (size_t)(item - m->items);
  if (item == NULL || idx >= m->count)
    return;
  memmove(&m->items[idx], &m->items[idx + 1], (m->count - idx - 1) * sizeof(ui_mount));
  m->count--;
  memset(&m->items[m->count], 0, sizeof(ui_mount));
}

const wchar_t *ui_model_state_text(const ui_mount *item)
{
  const char *s = item->state;
  if (strcmp(s, "connecting") == 0)
    return sd_l10n_get(SD_MSG_UI_STATE_CONNECTING);
  if (strcmp(s, "authenticating") == 0)
    return sd_l10n_get(SD_MSG_UI_STATE_AUTHENTICATING);
  if (strcmp(s, "mounted") == 0)
    return sd_l10n_get(SD_MSG_UI_STATE_MOUNTED);
  if (strcmp(s, "offline") == 0)
    return sd_l10n_get(SD_MSG_UI_STATE_OFFLINE);
  if (strcmp(s, "auth_required") == 0)
    return sd_l10n_get(SD_MSG_UI_STATE_AUTH_REQUIRED);
  if (strcmp(s, "failed") == 0)
    return sd_l10n_get(SD_MSG_UI_STATE_FAILED);
  if (strcmp(s, "unmounting") == 0)
    return sd_l10n_get(SD_MSG_UI_STATE_UNMOUNTING);
  if (strcmp(s, "unmounted") == 0)
    return sd_l10n_get(SD_MSG_UI_STATE_UNMOUNTED);
  /* A state this build does not know yet is shown as the agent names it. */
  return item->state_w;
}
