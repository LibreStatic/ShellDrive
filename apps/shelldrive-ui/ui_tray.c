/* shelldrive-ui: the notification area icon (03 §7.2, §7.7).
 *
 * The icon is identified by uID, not guidItem (7.2). On Windows Vista and later the icon uses NOTIFYICON_VERSION_4
 * (NIN_SELECT for a left click, WM_CONTEXTMENU for the menu, NIN_BALLOONUSERCLICK for a balloon click) and the V3
 * structure, so a balloon can carry NIIF_USER with our own icon (hBalloonIcon). XP keeps the version 0 callbacks, the
 * V2 structure and the classic balloon icons. ui_tray_callback reads LOWORD(lParam), which serves both.
 *
 * Balloons (7.7): at most one per (mount, event type) every 60 s (ui_notify_model.c). A balloon that is not allowed yet
 * waits in a small queue; the one-second timer UI_TIMER_NOTIFY (ui_app_on_timer calls ui_tray_flush) shows at most one
 * queued balloon per tick. A queued balloon for the same subject and kind is replaced by the newer text, never doubled.
 *
 * Re-added when Explorer restarts (TaskbarCreated, handled by the main window). */
#include <windows.h>
#include <shellapi.h>
#include <string.h>
#include <wchar.h>

#include "sd_base/sd_mem.h"
#include "sd_l10n/sd_l10n.h"
#include "sd_l10n_ui_ids.h"
#include "sd_platform/sd_log.h"
#include "sd_platform/sd_platform.h"
#include "sd_platform/sd_time.h"
#include "ui_flyout.h"
#include "ui_int.h"
#include "ui_mainview_model.h"
#include "ui_notice_model.h"
#include "ui_notify_model.h"
#include "ui_win.h"

#ifndef NIIF_RESPECT_QUIET_TIME
#define NIIF_RESPECT_QUIET_TIME 0x00000080
#endif
#ifndef NIIF_USER
#define NIIF_USER 0x00000004
#endif
#ifndef NIM_SETVERSION
#define NIM_SETVERSION 0x00000004
#endif
#ifndef NOTIFYICON_VERSION_4
#define NOTIFYICON_VERSION_4 4
#endif
#ifndef NIN_SELECT
#define NIN_SELECT (WM_USER + 0)
#endif
#ifndef NIN_KEYSELECT
#define NIN_KEYSELECT (WM_USER + 1)
#endif
#ifndef NIN_BALLOONUSERCLICK
#define NIN_BALLOONUSERCLICK (WM_USER + 5)
#endif

/* The NOTIFYICONDATAW layout of Windows 2000 and later, with the Vista fields (guidItem, hBalloonIcon). The XP SDK
   (7.1A, the v141_xp toolset) does not declare the Vista fields, so the layout is spelled out here. Shell_NotifyIconW
   reads cbSize bytes of it; the offsets are the ones the SDK uses on every flavour. */
typedef struct ui_nid {
  DWORD cbSize;
  HWND hWnd;
  UINT uID;
  UINT uFlags;
  UINT uCallbackMessage;
  HICON hIcon;
  WCHAR szTip[128];
  DWORD dwState;
  DWORD dwStateMask;
  WCHAR szInfo[256];
  union {
    UINT uTimeout;
    UINT uVersion;
  } u;
  WCHAR szInfoTitle[64];
  DWORD dwInfoFlags;
  GUID guidItem;
  HICON hBalloonIcon;
} ui_nid;

#define UI_TRAY_ID          1u
#define UI_NID_SIZE_V2      (FIELD_OFFSET(ui_nid, dwInfoFlags) + sizeof(DWORD))
#define UI_NID_SIZE_V3      (FIELD_OFFSET(ui_nid, hBalloonIcon) + sizeof(HICON))
#define UI_TRAY_QUEUE_MAX   16
#define UI_BALLOON_TEXT_MAX 255           /* szInfo has 256 units with the terminator */

typedef struct tray_pending {
  int used;
  sd_msg_id msg;
  wchar_t subject[UI_NOTIFY_SUBJECT_MAX + 1];
  wchar_t text[UI_BALLOON_TEXT_MAX + 1];
} tray_pending;

static int g_tray_added;
static int g_sizes_known;
static size_t g_nid_size = UI_NID_SIZE_V2;
static int g_nid_v4;                    /* Vista and later: NOTIFYICON_VERSION_4 and V3 balloons */
static int g_timer_on;
static sd_msg_id g_last_balloon = SD_MSG_UI_WARN_GENERIC;
static ui_notify_limiter g_limiter;
static wchar_t g_last_drive[4];         /* the drive of the last legacy or Terrapin balloon queued (7.6) */
static tray_pending g_queue[UI_TRAY_QUEUE_MAX];

static void copy_text(wchar_t *dst, size_t cch, const wchar_t *src)
{
  wcsncpy_s(dst, cch, src ? src : L"", _TRUNCATE);
}

static void ensure_sizes(void)
{
  if (g_sizes_known)
    return;
  g_sizes_known = 1;
  g_nid_v4 = sd_os_at_least(6, 0, 0) ? 1 : 0;
  g_nid_size = g_nid_v4 ? UI_NID_SIZE_V3 : UI_NID_SIZE_V2;
  ui_notify_limiter_init(&g_limiter);
}

static void fill_nid(ui_nid *nid)
{
  wchar_t *count_text = NULL;
  /* The tooltip counts the drives that are mounted: reconnecting ones count, failed ones do not (03 §7.2). */
  size_t n = ui_model_mounted_count(&g_app.model);

  memset(nid, 0, sizeof(*nid));
  nid->cbSize = (DWORD)g_nid_size;
  nid->hWnd = g_app.ctrl;
  nid->uID = UI_TRAY_ID;
  nid->uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
  nid->uCallbackMessage = UI_WM_TRAY;
  nid->hIcon = ui_icon_get(n > 0 && g_app.agent_up ? UI_ICON_CONNECTED : UI_ICON_IDLE,
                           GetSystemMetrics(SM_CXSMICON));
  if (g_app.attention > 0) {
    /* a global drive waits for an administrator: the warning icon and its text take precedence (03 §2.6 rule 3) */
    nid->hIcon = ui_icon_get(UI_ICON_WARNING, GetSystemMetrics(SM_CXSMICON));
    copy_text(nid->szTip, SD_COUNTOF(nid->szTip), sd_l10n_get(SD_MSG_UI_TRAY_ADMIN_TIP));
  } else if (n == 0) {
    copy_text(nid->szTip, SD_COUNTOF(nid->szTip), sd_l10n_get(SD_MSG_UI_TRAY_TIP_NONE));
  } else {
    count_text = ui_format_count(SD_MSG_UI_TRAY_TIP_COUNT, (long long)n);
    copy_text(nid->szTip, SD_COUNTOF(nid->szTip), count_text);
    sd_free(count_text);
  }
}

sd_err ui_tray_add(void)
{
  ui_nid nid;
  if (g_app.ctrl == NULL)
    return SD_E_INVALID_PARAM;
  ensure_sizes();
  fill_nid(&nid);
  if (!Shell_NotifyIconW(NIM_ADD, (NOTIFYICONDATAW *)&nid))
    return SD_E_FAILURE;             /* Explorer not ready yet; TaskbarCreated adds it later */
  g_tray_added = 1;
  if (g_nid_v4) {
    nid.u.uVersion = NOTIFYICON_VERSION_4;
    if (!Shell_NotifyIconW(NIM_SETVERSION, (NOTIFYICONDATAW *)&nid))
      SD_LOGW("ui", "the notification area did not accept version 4 callbacks; the legacy ones are used");
  }
  return SD_OK;
}

void ui_tray_readd(void)
{
  g_tray_added = 0;
  ui_tray_add();
}

void ui_tray_update(void)
{
  ui_nid nid;
  if (!g_tray_added)
    return;
  fill_nid(&nid);
  Shell_NotifyIconW(NIM_MODIFY, (NOTIFYICONDATAW *)&nid);
  ui_flyout_refresh();               /* an open flyout (06 §6.3) follows the mounts */
}

void ui_tray_remove(void)
{
  ui_nid nid;
  if (!g_tray_added)
    return;
  memset(&nid, 0, sizeof(nid));
  nid.cbSize = (DWORD)g_nid_size;
  nid.hWnd = g_app.ctrl;
  nid.uID = UI_TRAY_ID;
  Shell_NotifyIconW(NIM_DELETE, (NOTIFYICONDATAW *)&nid);
  g_tray_added = 0;
}

/* ---- balloons (7.7) ---- */

static int is_info_balloon(sd_msg_id msg)
{
  return msg == SD_MSG_UI_PROMPT_TIMEOUT || msg == SD_MSG_UI_NOTIFY_HOSTKEYS || msg == SD_MSG_UI_NOTICE_MOUNTED ||
         msg == SD_MSG_UI_NOTICE_RECONNECTED || msg == SD_MSG_UI_NOTICE_RECONNECTED_REASON ||
         msg == SD_MSG_UI_NOTICE_HOSTKEYS_SAVED || msg == SD_MSG_UI_NOTICE_POOL_LIMITED;
}

/* The balloon title: warnings say so, the neutral notices carry the product name. */
static int neutral_title(sd_msg_id msg)
{
  return msg == SD_MSG_UI_NOTIFY_HOSTKEYS || msg == SD_MSG_UI_NOTICE_MOUNTED || msg == SD_MSG_UI_NOTICE_RECONNECTED ||
         msg == SD_MSG_UI_NOTICE_RECONNECTED_REASON || msg == SD_MSG_UI_NOTICE_HOSTKEYS_SAVED ||
         msg == SD_MSG_UI_NOTICE_POOL_LIMITED;
}

/* Shows one balloon now; the limiter has already allowed it. */
static void show_balloon(sd_msg_id msg, const wchar_t *text)
{
  ui_nid nid;
  int info = is_info_balloon(msg);

  if (!g_tray_added)
    return;
  fill_nid(&nid);
  nid.uFlags |= NIF_INFO;
  copy_text(nid.szInfo, SD_COUNTOF(nid.szInfo), text);
  copy_text(nid.szInfoTitle, SD_COUNTOF(nid.szInfoTitle),
            neutral_title(msg) ? sd_l10n_get(SD_MSG_UI_NOTIFY_TITLE) : sd_l10n_get(SD_MSG_UI_WARN_TITLE));
  if (g_nid_v4) {
    nid.dwInfoFlags = NIIF_USER | NIIF_RESPECT_QUIET_TIME;
    nid.hBalloonIcon = ui_icon_get(info ? UI_ICON_CONNECTED : UI_ICON_WARNING, GetSystemMetrics(SM_CXICON));
  } else {
    nid.dwInfoFlags = (info ? NIIF_INFO : NIIF_WARNING) | NIIF_RESPECT_QUIET_TIME;
  }
  Shell_NotifyIconW(NIM_MODIFY, (NOTIFYICONDATAW *)&nid);
  g_last_balloon = msg;
}

static void start_timer(void)
{
  if (!g_timer_on && g_app.ctrl != NULL) {
    SetTimer(g_app.ctrl, UI_TIMER_NOTIFY, 1000, NULL);
    g_timer_on = 1;
  }
}

static void stop_timer(void)
{
  if (g_timer_on && g_app.ctrl != NULL)
    KillTimer(g_app.ctrl, UI_TIMER_NOTIFY);
  g_timer_on = 0;
}

/* One balloon: shown when the limiter allows it, otherwise queued. */
static void post_balloon(sd_msg_id msg, const wchar_t *subject, const wchar_t *text)
{
  unsigned long long now = sd_tick_ms(), wait = 0;
  size_t i;

  ensure_sizes();
  if (!g_tray_added)
    return;
  if (ui_notify_limiter_take(&g_limiter, subject, (int)msg, now, &wait)) {
    show_balloon(msg, text);
    return;
  }
  for (i = 0; i < UI_TRAY_QUEUE_MAX; i++) {
    tray_pending *p = &g_queue[i];
    if (p->used && p->msg == msg && wcscmp(p->subject, subject ? subject : L"") == 0) {
      copy_text(p->text, SD_COUNTOF(p->text), text);      /* the newest text replaces the queued one */
      return;
    }
  }
  for (i = 0; i < UI_TRAY_QUEUE_MAX; i++) {
    tray_pending *p = &g_queue[i];
    if (!p->used) {
      p->used = 1;
      p->msg = msg;
      copy_text(p->subject, SD_COUNTOF(p->subject), subject);
      copy_text(p->text, SD_COUNTOF(p->text), text);
      start_timer();
      return;
    }
  }
  SD_LOGW("ui", "balloon queue full: a notification was dropped");
}

/* Called by the timer once a second while balloons wait: shows the first queued balloon that is allowed now. */
void ui_tray_flush(void)
{
  unsigned long long now = sd_tick_ms();
  size_t i;
  int pending = 0, shown = 0;

  for (i = 0; i < UI_TRAY_QUEUE_MAX; i++) {
    tray_pending *p = &g_queue[i];
    if (!p->used)
      continue;
    if (!shown && ui_notify_limiter_take(&g_limiter, p->subject, (int)p->msg, now, NULL)) {
      show_balloon(p->msg, p->text);
      p->used = 0;
      shown = 1;
      continue;
    }
    pending++;
  }
  if (pending == 0)
    stop_timer();
}

/* The kind an event list entry (7.7) gets from the message of its balloon. */
static ui_ev_kind event_kind_of(sd_msg_id msg)
{
  if (msg == SD_MSG_UI_HKI_NOTIFY_CHANGED || msg == SD_MSG_UI_HKI_NOTIFY_TYPE ||
      msg == SD_MSG_UI_HKI_NOTIFY_TYPE_STORED || msg == SD_MSG_UI_NOTIFY_HOSTKEYS ||
      msg == SD_MSG_UI_NOTICE_HOSTKEYS_SAVED || msg == SD_MSG_UI_NOTICE_HOSTKEY_SOURCE)
    return UI_EV_HOSTKEY;
  if (msg == SD_MSG_UI_WARN_WRITE_FAILED || msg == SD_MSG_UI_NOTICE_MOUNT_FAILED)
    return UI_EV_ERROR;
  if (msg == SD_MSG_UI_NOTICE_MOUNTED || msg == SD_MSG_UI_NOTICE_RECONNECTED ||
      msg == SD_MSG_UI_NOTICE_RECONNECTED_REASON)
    return UI_EV_DRIVE;
  if (msg == SD_MSG_UI_WARN_LEGACY || msg == SD_MSG_UI_WARN_TERRAPIN || msg == SD_MSG_UI_WARN_GENERIC ||
      msg == SD_MSG_UI_NOTICE_LOST || msg == SD_MSG_UI_NOTICE_PROXY_PASSWORD || msg == SD_MSG_UI_NOTICE_DISK_CACHE ||
      msg == SD_MSG_UI_TRAY_ADMIN_PROMPTS)
    return UI_EV_WARNING;
  return UI_EV_INFO;
}

/* Every notification is also recorded in the event list (7.7), shown as a balloon or not. */
static void record_notice(sd_msg_id msg, const wchar_t *subject, const wchar_t *text)
{
  ui_events_record(event_kind_of(msg), subject != NULL ? subject : L"", text != NULL ? text : L"");
}

/* A balloon whose text the caller formatted (more than one placeholder); msg identifies the kind for the click. */
void ui_tray_notify_text(sd_msg_id msg, const wchar_t *subject, const wchar_t *text)
{
  record_notice(msg, subject, text);
  post_balloon(msg, subject != NULL ? subject : L"", text);
}

void ui_tray_notify_msg(sd_msg_id msg, const char *name, const wchar_t *arg)
{
  wchar_t *text = ui_format1(msg, name, arg ? arg : L"");
  if (text == NULL)
    return;
  record_notice(msg, arg, text);
  post_balloon(msg, arg ? arg : L"", text);
  sd_free(text);
}

int ui_tray_notify_wanted(int kind)
{
  return sd_settings_notify_on(&g_app.settings, kind);
}

void ui_tray_balloon(const char *code, const wchar_t *drive)
{
  sd_msg_id msg = SD_MSG_UI_WARN_GENERIC;
  /* write_failed is always shown (03 §7.7); the others follow the master switch and their own notify_<kind>. A
     notice that shows no balloon still goes to the event list (7.7). */
  int shown = (code && strcmp(code, "write_failed") == 0) || ui_tray_notify_wanted(sd_notify_kind_from_code(code));
  if (code && strcmp(code, "legacy_algorithms") == 0)
    msg = SD_MSG_UI_WARN_LEGACY;
  else if (code && strcmp(code, "terrapin_exposed") == 0)
    msg = SD_MSG_UI_WARN_TERRAPIN;
  else if (code && strcmp(code, "write_failed") == 0)
    msg = SD_MSG_UI_WARN_WRITE_FAILED;
  if (msg == SD_MSG_UI_WARN_LEGACY || msg == SD_MSG_UI_WARN_TERRAPIN)
    wcsncpy_s(g_last_drive, SD_COUNTOF(g_last_drive), drive ? drive : L"", _TRUNCATE);
  if (shown) {
    ui_tray_notify_msg(msg, "drive", drive);
  } else {
    /* no balloon, but the event list still has it (7.7) */
    wchar_t *text = ui_format1(msg, "drive", drive ? drive : L"");
    if (text != NULL) {
      record_notice(msg, drive, text);
      sd_free(text);
    }
  }
}

/* Why a drive reconnected (mount.state `reason`, an error code): the text of the codes the agent sends, the code itself
   for any other. */
void ui_reason_text(const char *code, wchar_t *out, size_t cch)
{
  static const sd_msg_id ids[UI_NT_REASONS] = {
    SD_MSG_UI_NOTICE_REASON_DISCONNECTED, SD_MSG_UI_NOTICE_REASON_TIMEOUT, SD_MSG_UI_NOTICE_REASON_DNS_FAILED,
    SD_MSG_UI_NOTICE_REASON_CONN_REFUSED, SD_MSG_UI_NOTICE_REASON_NET_UNREACHABLE, SD_MSG_UI_NOTICE_REASON_PROTOCOL,
    SD_MSG_UI_NOTICE_REASON_AUTH_FAILED, SD_MSG_UI_NOTICE_REASON_PROXY_FAILED
  };
  int i = ui_nt_reason_index(code);
  if (cch == 0)
    return;
  if (i >= 0)
    wcsncpy_s(out, cch, sd_l10n_get(ids[i]), _TRUNCATE);
  else
    ui_text_utf8(code != NULL ? code : "", out, cch);
}

/* The text and message of a notice of 7.7 (NULL for a kind without one). subject: the drive letter, else the profile or
   server; detail: the proxy (host:port) for the proxy password notice, the error code for a failed mount, the reason code
   for a reconnect (may be empty), the known_hosts source for the ignored source; count: the prompts waiting. */
static wchar_t *notice_text(ui_nt_kind kind, const wchar_t *name, const wchar_t *detail, int count, sd_msg_id *msg_out)
{
  sd_msg_id msg;
  sd_arg a[2];
  switch (kind) {
  case UI_NT_CONNECTION_LOST:   msg = SD_MSG_UI_NOTICE_LOST; break;
  case UI_NT_RECONNECTED:       msg = SD_MSG_UI_NOTICE_RECONNECTED; break;
  case UI_NT_MOUNT_FAILED:      msg = SD_MSG_UI_NOTICE_MOUNT_FAILED; break;
  case UI_NT_MOUNTED:           msg = SD_MSG_UI_NOTICE_MOUNTED; break;
  case UI_NT_PROXY_PASSWORD:    msg = SD_MSG_UI_NOTICE_PROXY_PASSWORD; break;
  case UI_NT_POOL_LIMITED:      msg = SD_MSG_UI_NOTICE_POOL_LIMITED; break;
  case UI_NT_HOSTKEYS_SAVED:    msg = SD_MSG_UI_NOTICE_HOSTKEYS_SAVED; break;
  case UI_NT_DISK_CACHE:        msg = SD_MSG_UI_NOTICE_DISK_CACHE; break;
  case UI_NT_HOSTKEYS_SOURCE:   msg = SD_MSG_UI_NOTICE_HOSTKEY_SOURCE; break;
  case UI_NT_SERVICE_ATTENTION: msg = SD_MSG_UI_TRAY_ADMIN_PROMPTS; break;
  default:
    return NULL;
  }
  *msg_out = msg;
  if (kind == UI_NT_SERVICE_ATTENTION)
    return ui_format_count(msg, (long long)count);
  if (kind == UI_NT_HOSTKEYS_SOURCE) {
    /* the source is OpenSSH or PuTTY; a warning without one names both */
    return ui_format1(msg, "source", detail != NULL && detail[0] != 0 ? detail : L"OpenSSH/PuTTY");
  }
  if (kind == UI_NT_RECONNECTED && detail != NULL && detail[0] != 0) {
    /* "{name}: connected again. Cause of the interruption: {reason}" (7.7) */
    char code[64];
    wchar_t reason[160];
    size_t i;
    for (i = 0; detail[i] != 0 && i + 1 < sizeof(code); i++)
      code[i] = detail[i] < 0x80 ? (char)detail[i] : '?';
    code[i] = 0;
    ui_reason_text(code, reason, SD_COUNTOF(reason));
    *msg_out = SD_MSG_UI_NOTICE_RECONNECTED_REASON;
    a[0].name = "name";
    a[0].type = SD_ARG_STR;
    a[0].v.s = name;
    a[1].name = "reason";
    a[1].type = SD_ARG_STR;
    a[1].v.s = reason;
    return sd_l10n_format_alloc(SD_MSG_UI_NOTICE_RECONNECTED_REASON, a, 2);
  }
  if (kind == UI_NT_PROXY_PASSWORD || kind == UI_NT_MOUNT_FAILED) {
    /* the proxy (host:port) or the error code of the failed mount is the second argument */
    a[0].name = "name";
    a[0].type = SD_ARG_STR;
    a[0].v.s = name;
    a[1].name = kind == UI_NT_PROXY_PASSWORD ? "proxy" : "code";
    a[1].type = SD_ARG_STR;
    a[1].v.s = detail != NULL ? detail : L"";
    return sd_l10n_format_alloc(msg, a, 2);
  }
  if (kind == UI_NT_HOSTKEYS_SAVED)
    return ui_format1(msg, "host", name);
  return ui_format1(msg, "name", name);
}

/* The notices of 7.7 that follow the agent's state (ui_notice_model.h). The text is always recorded in the event list;
   the balloon follows the master switch and the kind's own switch ([ui] notify_<kind>), and the rate limit of 60 s per
   (subject, kind) applies as for every balloon. See notice_text for the arguments. */
void ui_tray_notice(ui_nt_kind kind, const wchar_t *subject, const wchar_t *detail, int count)
{
  sd_msg_id msg = SD_MSG_UI_WARN_GENERIC;
  const wchar_t *name = kind == UI_NT_SERVICE_ATTENTION ? L"" : (subject != NULL ? subject : L"");
  wchar_t *text = notice_text(kind, name, detail, count, &msg);
  if (text == NULL)
    return;
  record_notice(msg, name, text);
  if (ui_tray_notify_wanted(ui_nt_switch_of(kind)))
    post_balloon(msg, name, text);
  sd_free(text);
}

/* The same notice for something the agent's history says happened at `when` (unix seconds): recorded in the event list at
   that time, with no balloon. */
void ui_tray_history_notice(ui_nt_kind kind, long long when, const wchar_t *subject, const wchar_t *detail)
{
  sd_msg_id msg = SD_MSG_UI_WARN_GENERIC;
  const wchar_t *name = subject != NULL ? subject : L"";
  wchar_t *text = notice_text(kind, name, detail, 0, &msg);
  if (text == NULL)
    return;
  ui_events_record_at(event_kind_of(msg), when, name, text);
  sd_free(text);
}

/* A warning of the history that has no notice of its own (legacy algorithms, Terrapin, write failed, others). */
void ui_tray_history_warning(const char *code, long long when, const wchar_t *subject)
{
  sd_msg_id msg = SD_MSG_UI_WARN_GENERIC;
  wchar_t *text;
  if (code && strcmp(code, "legacy_algorithms") == 0)
    msg = SD_MSG_UI_WARN_LEGACY;
  else if (code && strcmp(code, "terrapin_exposed") == 0)
    msg = SD_MSG_UI_WARN_TERRAPIN;
  else if (code && strcmp(code, "write_failed") == 0)
    msg = SD_MSG_UI_WARN_WRITE_FAILED;
  text = ui_format1(msg, "drive", subject != NULL ? subject : L"");
  if (text == NULL)
    return;
  ui_events_record_at(event_kind_of(msg), when, subject != NULL ? subject : L"", text);
  sd_free(text);
}

/* hostkeys.announced of the history: the offer of new host keys, without a balloon. */
void ui_tray_history_hostkeys(long long when, const wchar_t *host)
{
  wchar_t *text = ui_format1(SD_MSG_UI_NOTIFY_HOSTKEYS, "host", host != NULL ? host : L"");
  if (text == NULL)
    return;
  ui_events_record_at(UI_EV_HOSTKEY, when, host != NULL ? host : L"", text);
  sd_free(text);
}

static void notify_hostkeys(const wchar_t *host)
{
  wchar_t *text = ui_format1(SD_MSG_UI_NOTIFY_HOSTKEYS, "host", host);
  if (text == NULL)
    return;
  record_notice(SD_MSG_UI_NOTIFY_HOSTKEYS, host, text);
  if (ui_tray_notify_wanted(SD_NOTIFY_HOSTKEYS_OFFERED))
    post_balloon(SD_MSG_UI_NOTIFY_HOSTKEYS, host, text);
  sd_free(text);
}

/* hostkeys.announced (5.6): "example.org offered new host keys. Review", on the notifications switch. The host comes
   from the event; without one, the server of the mount named by mount_id is used. */
void ui_tray_on_hostkeys_announced(const sd_json *data)
{
  const char *host = sd_json_get_str(data, "host");
  const char *mount_id = sd_json_get_str(data, "mount_id");
  wchar_t w[UI_NOTIFY_SUBJECT_MAX + 1];
  ui_mount *m;

  if (host != NULL && host[0] != '\0') {
    ui_text_utf8(host, w, SD_COUNTOF(w));
    notify_hostkeys(w);
    return;
  }
  m = mount_id != NULL ? ui_model_find_id(&g_app.model, mount_id) : NULL;
  if (m != NULL)
    notify_hostkeys(m->server);
}

/* ---- menu and callbacks ---- */

/* Two-argument unmount item text: "Unmount {drive} ({profile})". */
static wchar_t *unmount_item_text(const wchar_t *drive, const wchar_t *profile)
{
  sd_arg a[2];
  a[0].name = "drive";
  a[0].type = SD_ARG_STR;
  a[0].v.s = drive;
  a[1].name = "profile";
  a[1].type = SD_ARG_STR;
  a[1].v.s = profile;
  return sd_l10n_format_alloc(SD_MSG_UI_TRAY_UNMOUNT, a, 2);
}

static void show_menu(void)
{
  HMENU menu;
  POINT pt;
  UINT cmd;
  size_t i, n = g_app.model.count, n_unmount = 0;
  wchar_t drives[UI_MAX_MOUNTS][3];

  menu = CreatePopupMenu();
  if (menu == NULL)
    return;
  if (g_app.attention > 0) {
    wchar_t *t = ui_format_count(SD_MSG_UI_TRAY_ADMIN_PROMPTS, (long long)g_app.attention);
    AppendMenuW(menu, MF_STRING, UI_CMD_ADMIN, t != NULL ? t : sd_l10n_get(SD_MSG_UI_TRAY_ADMIN_TIP));
    sd_free(t);
    AppendMenuW(menu, MF_SEPARATOR, 0, NULL);
  }
  for (i = 0; i < n; i++) {
    const ui_mount *it = &g_app.model.items[i];
    wchar_t *t;
    /* A failed mount is not a mounted drive (03 §1.11): it offers no Unmount item; the Reconnect the design
       gives it has no agent method in this build yet. */
    if (ui_mv_is_failed(it->state, it->session, it->attempt))
      continue;
    t = unmount_item_text(it->drive, it->profile);
    wcscpy_s(drives[n_unmount], SD_COUNTOF(drives[n_unmount]), it->drive);
    if (t != NULL) {
      AppendMenuW(menu, MF_STRING, UI_CMD_UNMOUNT_BASE + (UINT)n_unmount, t);
      sd_free(t);
    }
    n_unmount++;
  }
  if (n_unmount == 0)
    AppendMenuW(menu, MF_STRING | MF_GRAYED, 0, sd_l10n_get(SD_MSG_UI_TRAY_NO_DRIVES));
  else
    AppendMenuW(menu, MF_SEPARATOR, 0, NULL);
  AppendMenuW(menu, MF_STRING, UI_CMD_OPEN, sd_l10n_get(SD_MSG_UI_TRAY_OPEN));
  AppendMenuW(menu, MF_STRING, UI_CMD_HOSTKEYS, sd_l10n_get(SD_MSG_UI_MENU_HOSTKEYS));
  AppendMenuW(menu, MF_STRING, UI_CMD_LOGS, sd_l10n_get(SD_MSG_UI_MENU_LOGS));
  AppendMenuW(menu, MF_STRING, UI_CMD_EVENTS, sd_l10n_get(SD_MSG_UI_MENU_EVENTS));
  AppendMenuW(menu, MF_STRING, UI_CMD_SERVICE, sd_l10n_get(SD_MSG_UI_MENU_SERVICE));
  AppendMenuW(menu, MF_STRING, UI_CMD_SETTINGS, sd_l10n_get(SD_MSG_UI_MENU_SETTINGS));
  AppendMenuW(menu, MF_STRING, UI_CMD_ABOUT, sd_l10n_get(SD_MSG_UI_MENU_ABOUT));
  AppendMenuW(menu, MF_STRING, UI_CMD_EXIT, sd_l10n_get(SD_MSG_UI_TRAY_EXIT));
  SetMenuDefaultItem(menu, UI_CMD_OPEN, FALSE);

  GetCursorPos(&pt);
  /* Classic tray menu rules: foreground first, WM_NULL after, so the menu dismisses properly. */
  SetForegroundWindow(g_app.ctrl);
  cmd = (UINT)TrackPopupMenu(menu, TPM_RIGHTBUTTON | TPM_RETURNCMD | TPM_BOTTOMALIGN, pt.x, pt.y, 0,
                             g_app.ctrl, NULL);
  PostMessageW(g_app.ctrl, WM_NULL, 0, 0);
  DestroyMenu(menu);

  if (cmd == UI_CMD_OPEN) {
    ui_main_show();
  } else if (cmd == UI_CMD_HOSTKEYS || cmd == UI_CMD_LOGS || cmd == UI_CMD_SETTINGS || cmd == UI_CMD_SERVICE || cmd == UI_CMD_EVENTS ||
             cmd == UI_CMD_ABOUT) {
    ui_windows_command(cmd);
  } else if (cmd == UI_CMD_ADMIN) {
    (void)ui_svc_launch_admin(g_app.main);
  } else if (cmd == UI_CMD_EXIT) {
    ui_app_quit();
  } else if (cmd >= UI_CMD_UNMOUNT_BASE && cmd < UI_CMD_UNMOUNT_BASE + n_unmount) {
    /* The drive letter was captured when the menu was built; the list may have changed meanwhile. */
    ui_ipc_unmount(drives[cmd - UI_CMD_UNMOUNT_BASE]);
  }
}

/* A click on a balloon opens the window the balloon is about (7.7). */
static void balloon_clicked(void)
{
  if (g_last_balloon == SD_MSG_UI_NOTIFY_HOSTKEYS || g_last_balloon == SD_MSG_UI_NOTICE_HOSTKEYS_SAVED) {
    ui_windows_command(UI_CMD_HOSTKEYS);
  } else if (g_last_balloon == SD_MSG_UI_NOTICE_HOSTKEY_SOURCE) {
    ui_settings_open_security();       /* the known_hosts sources are on the Security page (TM-R06) */
  } else if (g_last_balloon == SD_MSG_UI_TRAY_ADMIN_PROMPTS) {
    (void)ui_svc_launch_admin(g_app.main);   /* the same as the tray menu item: the administrator window (UAC) */
  } else if (g_last_balloon == SD_MSG_UI_HKI_NOTIFY_CHANGED || g_last_balloon == SD_MSG_UI_HKI_NOTIFY_TYPE ||
             g_last_balloon == SD_MSG_UI_HKI_NOTIFY_TYPE_STORED) {
    ui_hkissue_open_last();            /* the details of a changed key, or the host key manager (5.4, TM-R04) */
  } else if ((g_last_balloon == SD_MSG_UI_WARN_LEGACY || g_last_balloon == SD_MSG_UI_WARN_TERRAPIN) &&
             g_last_drive[0] != 0) {
    ui_main_show();
    ui_secdlg_open(g_app.main, g_last_drive);   /* the legacy and Terrapin details (7.6) */
  } else {
    ui_main_show();
  }
}

void ui_tray_callback(LPARAM mouse_message)
{
  /* NOTIFYICON_VERSION_4 packs the icon id into HIWORD and the mouse message into LOWORD; version 0 sends the message
     itself. Mouse messages are below 0x10000, so LOWORD serves both. */
  UINT m = LOWORD(mouse_message);
  if (ui_flyout_wanted()) {
    /* Windows 11 (06 §6.3): a click or Enter opens the flyout, a double click the main window; the menu stays */
    if (m == NIN_SELECT || m == NIN_KEYSELECT) {
      ui_flyout_open();
      return;
    }
    if (m == WM_LBUTTONDBLCLK) {
      ui_flyout_close();
      ui_main_show();
      return;
    }
    if (m == WM_LBUTTONUP)
      return;
  }
  if (m == WM_LBUTTONUP || m == NIN_SELECT || m == NIN_KEYSELECT)
    ui_main_show();
  else if (m == WM_RBUTTONUP || m == WM_CONTEXTMENU)
    show_menu();
  else if (m == NIN_BALLOONUSERCLICK)
    balloon_clicked();
}
