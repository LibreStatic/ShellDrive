/* shelldrive-ui: the updater glue (ui_update.h, 03 §3.2, 04 §9.7, 03 §2.4 and §2.8).
 *
 * The Settings window asks for a check ("Check now") or an install ("Install update"); the agent answers with
 * update.check and update.apply (deferred replies) and sends update.available, update.progress and update.stale
 * events. The state lives in ui_update_model.c; this file parses the JSON, reads the policies through sd_policy
 * (never the registry directly, tests/policy/check-raw-reads.ps1), shows the consent dialog and the balloon. */
#include <windows.h>
#include <shellapi.h>
#include <stdint.h>
#include <string.h>
#include <wchar.h>

#include "sd_base/sd_err.h"
#include "sd_base/sd_json.h"
#include "sd_l10n/sd_l10n.h"
#include "sd_l10n_ui_ids.h"
#include "sd_platform/sd_log.h"
#include "sd_policy/sd_policy.h"
#include "ui_int.h"
#include "ui_update.h"
#include "ui_win.h"

/* The one model of this process. Zero is the initial state (IDLE), so no init call is needed. */
static ui_upd_model g_upd;

void ui_update_reset(void)
{
  memset(&g_upd, 0, sizeof(g_upd));
}

/* ---- policy ---- */

void ui_update_policy_now(ui_upd_policy *p)
{
  DWORD dw = 0;
  wchar_t ch[16];

  memset(p, 0, sizeof(*p));
  if (sd_policy_get_dword(SD_POLICY_DISABLEUPDATECHECK, &dw))
    p->check_off = dw != 0 ? 1 : 0;
  if (sd_policy_get_sz(SD_POLICY_UPDATECHANNEL, ch, SD_COUNTOF(ch))) {
    ui_text_ascii(ch, p->channel, sizeof(p->channel));
    /* only the two channels the agent knows count; anything else is ignored, as the agent does */
    if (strcmp(p->channel, "stable") == 0 || strcmp(p->channel, "beta") == 0)
      p->channel_set = 1;
    else
      p->channel[0] = '\0';
  }
}

void ui_update_channel_now(const char *saved, char *out, size_t cch)
{
  ui_upd_policy p;
  const char *c;

  ui_update_policy_now(&p);
  c = ui_upd_effective_channel(&p, saved);
  strncpy_s(out, cch, c, _TRUNCATE);
}

void ui_update_view_now(int agent_ok, int can_apply, ui_upd_view *v)
{
  ui_upd_policy p;
  ui_update_policy_now(&p);
  ui_upd_view_of(&g_upd, &p, agent_ok, can_apply, v);
}

int ui_update_busy(void)
{
  return g_upd.state == UI_UPD_CHECKING || g_upd.state == UI_UPD_INSTALLING;
}

/* ---- text ---- */

static void arg_str(sd_arg *a, const char *name, const wchar_t *v)
{
  a->name = name;
  a->type = SD_ARG_STR;
  a->v.s = v != NULL ? v : L"";
}

static void arg_int(sd_arg *a, const char *name, long long v)
{
  a->name = name;
  a->type = SD_ARG_INT;
  a->v.i = v;
}

static size_t format_into(sd_msg_id id, const sd_arg *args, size_t nargs, wchar_t *out, size_t cch)
{
  int n = sd_l10n_format(out, cch, id, args, nargs);
  if (n < 0) {
    out[0] = L'\0';
    return 0;
  }
  return (size_t)n;
}

size_t ui_update_status_text(wchar_t *out, size_t cch)
{
  ui_upd_policy p;
  ui_upd_status_kind k;
  wchar_t version[UI_UPD_VERSION_MAX], code[UI_UPD_ERROR_MAX], channel[UI_UPD_CHANNEL_MAX];
  sd_arg a[3];
  long long kb;

  ui_update_policy_now(&p);
  k = ui_upd_status_of(&g_upd, &p);
  ui_text_utf8(g_upd.offer.version, version, SD_COUNTOF(version));
  ui_text_utf8(g_upd.error, code, SD_COUNTOF(code));
  ui_text_utf8(ui_upd_effective_channel(&p, g_upd.channel), channel, SD_COUNTOF(channel));

  switch (k) {
  case UI_UPD_SHOW_OFF_POLICY:
    return format_into(SD_MSG_UI_SETTINGS_UPDATE_OFF_POLICY, NULL, 0, out, cch);
  case UI_UPD_SHOW_OFF_SETTINGS:
    return format_into(SD_MSG_UI_SETTINGS_UPDATE_OFF_SETTINGS, NULL, 0, out, cch);
  case UI_UPD_SHOW_CHECKING:
    return format_into(SD_MSG_UI_UPDATE_STATUS_CHECKING, NULL, 0, out, cch);
  case UI_UPD_SHOW_CURRENT:
    arg_str(&a[0], "channel", channel);
    return format_into(SD_MSG_UI_UPDATE_STATUS_CURRENT, a, 1, out, cch);
  case UI_UPD_SHOW_AVAILABLE:
    kb = (long long)((g_upd.offer.size + 1023) / 1024);
    arg_str(&a[0], "version", version);
    arg_int(&a[1], "size", kb);
    return format_into(SD_MSG_UI_UPDATE_STATUS_AVAILABLE, a, 2, out, cch);
  case UI_UPD_SHOW_INSTALLING:
    if (g_upd.stage == UI_UPD_STAGE_DOWNLOADING)
      return format_into(SD_MSG_UI_UPDATE_STAGE_DOWNLOADING, NULL, 0, out, cch);
    if (g_upd.stage == UI_UPD_STAGE_APPLYING)
      return format_into(SD_MSG_UI_UPDATE_STAGE_APPLYING, NULL, 0, out, cch);
    arg_str(&a[0], "version", version);
    return format_into(SD_MSG_UI_UPDATE_STATUS_INSTALLING, a, 1, out, cch);
  case UI_UPD_SHOW_FAILED:
    arg_str(&a[0], "code", code);
    if (g_upd.stage == UI_UPD_STAGE_FAILED)
      return format_into(SD_MSG_UI_UPDATE_STAGE_FAILED, a, 1, out, cch);
    return format_into(SD_MSG_UI_UPDATE_STATUS_FAILED, a, 1, out, cch);
  case UI_UPD_SHOW_IDLE:
  default:
    if (g_upd.stage == UI_UPD_STAGE_DONE)
      return format_into(SD_MSG_UI_UPDATE_STAGE_DONE, NULL, 0, out, cch);
    return format_into(SD_MSG_UI_UPDATE_STATUS_IDLE, NULL, 0, out, cch);
  }
}

size_t ui_update_stale_text(wchar_t *out, size_t cch)
{
  sd_arg a[1];
  if (!g_upd.stale || g_upd.stale_days <= 0) {
    if (cch > 0)
      out[0] = L'\0';
    return 0;
  }
  arg_int(&a[0], "days", g_upd.stale_days);
  return format_into(SD_MSG_UI_UPDATE_STATUS_STALE, a, 1, out, cch);
}

/* ---- JSON ---- */

/* Copies a string member into dst ("" when absent). */
static void json_text(const sd_json *obj, const char *key, char *dst, size_t cch)
{
  const char *s = sd_json_get_str(obj, key);
  if (cch == 0)
    return;
  strncpy_s(dst, cch, s != NULL ? s : "", _TRUNCATE);
}

static void parse_offer(const sd_json *obj, ui_upd_offer *o)
{
  int64_t size = 0;
  memset(o, 0, sizeof(*o));
  json_text(obj, "version", o->version, sizeof(o->version));
  json_text(obj, "channel", o->channel, sizeof(o->channel));
  json_text(obj, "notes", o->notes, sizeof(o->notes));
  json_text(obj, "file_id", o->file_id, sizeof(o->file_id));
  if (sd_json_get_int64(obj, "size", &size) && size > 0)
    o->size = (unsigned long long)size;
}

/* ---- replies and events ---- */

static void on_check_reply(sd_err err, const sd_json *r)
{
  ui_upd_check c;
  int flag = 0;

  memset(&c, 0, sizeof(c));
  if (err != SD_OK) {
    ui_upd_on_check(&g_upd, sd_err_name(err), NULL);
    return;
  }
  if (r == NULL || !sd_json_get_bool(r, "enabled", &flag)) {
    ui_upd_on_check(&g_upd, "update_bad_reply", NULL);
    return;
  }
  c.enabled = flag ? 1 : 0;
  json_text(r, "reason", c.reason, sizeof(c.reason));
  flag = 0;
  c.available = sd_json_get_bool(r, "available", &flag) && flag ? 1 : 0;
  flag = 0;
  c.stale = sd_json_get_bool(r, "stale", &flag) && flag ? 1 : 0;
  json_text(r, "channel", c.channel, sizeof(c.channel));
  if (c.available)
    parse_offer(r, &c.offer);
  ui_upd_on_check(&g_upd, NULL, &c);
}

static void on_apply_reply(sd_err err, const sd_json *r)
{
  int applied = 0;
  if (err != SD_OK) {
    ui_upd_on_apply(&g_upd, sd_err_name(err), 0);
    return;
  }
  if (r != NULL)
    (void)sd_json_get_bool(r, "applied", &applied);
  ui_upd_on_apply(&g_upd, NULL, applied);
}

void ui_update_on_reply(int kind, sd_err err, const sd_json *result)
{
  if (kind == UI_IPC_UPDATE_CHECK)
    on_check_reply(err, result);
  else if (kind == UI_IPC_UPDATE_APPLY)
    on_apply_reply(err, result);
  else
    return;
  ui_settings_update_refresh();
}

void ui_update_on_event(const char *name, const sd_json *data)
{
  if (name == NULL)
    return;
  if (strcmp(name, "update.available") == 0) {
    ui_upd_offer o;
    parse_offer(data, &o);
    if (o.version[0] == '\0')
      return;
    /* one balloon per version (the model), then the notification limiter spaces the balloons */
    if (ui_upd_on_available(&g_upd, &o) && ui_tray_notify_wanted(SD_NOTIFY_UPDATE_AVAILABLE)) {
      wchar_t version[UI_UPD_VERSION_MAX];
      ui_text_utf8(o.version, version, SD_COUNTOF(version));
      ui_tray_notify_msg(SD_MSG_UI_NOTIFY_UPDATE, "version", version);
    }
  } else if (strcmp(name, "update.progress") == 0) {
    ui_upd_on_progress(&g_upd, sd_json_get_str(data, "stage"));
  } else if (strcmp(name, "update.stale") == 0) {
    int64_t days = 0;
    if (sd_json_get_int64(data, "days", &days))
      ui_upd_on_stale(&g_upd, (long long)days);
  } else {
    return;
  }
  ui_settings_update_refresh();
}

void ui_update_on_agent_state(int up)
{
  ui_upd_on_agent_state(&g_upd, up);
  ui_settings_update_refresh();
}

/* ---- actions ---- */

void ui_update_check(void)
{
  ui_upd_policy p;
  sd_err e;

  ui_update_policy_now(&p);
  if (p.check_off || !ui_upd_begin_check(&g_upd))
    return;
  e = ui_ipc_call(UI_IPC_UPDATE_CHECK, "update.check", NULL);
  if (e != SD_OK)
    ui_upd_on_check(&g_upd, sd_err_name(e), NULL);
  ui_settings_update_refresh();
}

void ui_update_install(HWND owner)
{
  wchar_t version[UI_UPD_VERSION_MAX];
  sd_err e;

  if (g_upd.state != UI_UPD_AVAILABLE || !g_upd.has_offer)
    return;
  ui_text_utf8(g_upd.offer.version, version, SD_COUNTOF(version));
  /* the consent: what happens and that ShellDrive restarts; the default button is "Not now" */
  if (!ui_confirm(owner, SD_MSG_UI_UPDATE_CONSENT_TITLE, SD_MSG_UI_UPDATE_CONSENT_TEXT, version,
                  SD_MSG_UI_UPDATE_CONSENT_YES, SD_MSG_UI_UPDATE_CONSENT_NO, 0))
    return;
  if (!ui_upd_begin_install(&g_upd))
    return;
  e = ui_ipc_call(UI_IPC_UPDATE_APPLY, "update.apply", "{\"consent\":true}");
  if (e != SD_OK)
    ui_upd_on_apply(&g_upd, sd_err_name(e), 0);
  ui_settings_update_refresh();
}

void ui_update_open_notes(HWND owner)
{
  wchar_t url[UI_UPD_NOTES_MAX];
  /* the offer comes from the signed manifest, but a link is opened only over https (04 §9) */
  if (g_upd.offer.notes[0] == '\0' || strncmp(g_upd.offer.notes, "https://", 8) != 0)
    return;
  ui_text_utf8(g_upd.offer.notes, url, SD_COUNTOF(url));
  ShellExecuteW(owner, L"open", url, NULL, NULL, SW_SHOWNORMAL);
}
