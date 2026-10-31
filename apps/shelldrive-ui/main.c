/* shelldrive-ui.exe: tray icon and main window of ShellDrive (03 §1.4, §2, §7).
 *
 * One instance per (user, session): the named mutex SD_IPC_OBJ_UI_MUTEX. A second launch forwards its
 * command line as a versioned payload (ui_wire.c) with WM_COPYDATA to the first instance's message-only
 * window and exits. The receiving window accepts the message only from a process whose token user SID is
 * ours and whose integrity level is not lower than ours (TM-R26, T-48); everything else is dropped.
 *
 * Modes: no arguments opens the main window; --tray starts with the window hidden (Run key); --prompt-host
 * and --action <verb> <target> are the verbs of ui_wire.c; --elevated-admin (03 §2.6 rule 3) answers the service
 * prompts over the service pipe with no tray and no agent: it is relaunched by the tray attention item with UAC;
 * --elevated-service shows only the Service page (ui_service.c) in an elevated process, relaunched by its
 * "Repair data..." button, and exits when the page is closed;
 * --test-window is the smoke test of tests/ui: it
 * creates the main window hidden, checks the window class and its controls, and exits 0; --test-prompts
 * creates every prompt dialog hidden and destroys it (exit 0 when all were created).
 *
 * --prompt-host (03 §1.4, §2.5 step 3): the agent starts this process when a prompt has nobody to answer it.
 * It shows the tray icon and the prompt dialogs only, never starts an agent, leaves when the agent goes away
 * and after 60 s with no open prompt. A prompt-host process that finds a running UI forwards and exits. */
#include <windows.h>
#include <shellapi.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>
#include <commctrl.h>

#include "sd_base/sd_err.h"
#include "sd_base/sd_mem.h"
#include "sd_ipc/sd_ipc.h"
#include "sd_l10n/sd_l10n.h"
#include "sd_l10n_ui_ids.h"
#include "sd_platform/sd_log.h"
#include "sd_platform/sd_platform.h"
#include "ui_theme.h"
#include "sd_platform/sd_time.h"
#include "ui_dpi.h"
#include "ui_evhist_model.h"
#include "ui_wizard.h"
#include "sd_config/sd_config.h"
#include "ui_admin_model.h"
#include "ui_int.h"
#include "ui_mainview_model.h"
#include "ui_sdmount.h"
#include "ui_win.h"

#ifndef PROCESS_QUERY_LIMITED_INFORMATION
#define PROCESS_QUERY_LIMITED_INFORMATION 0x1000
#endif

ui_app g_app;

static wchar_t g_sid[256];

/* ---- identities for the WM_COPYDATA sender check (TM-R26) ---- */

typedef struct ui_identity {
  unsigned char *sid;           /* copy of the token user SID */
  DWORD sid_len;
  int has_integrity;            /* Vista and later */
  DWORD integrity;              /* mandatory label RID */
} ui_identity;

static ui_identity g_self;

static int read_identity(HANDLE tok, ui_identity *id)
{
  DWORD need = 0;
  TOKEN_USER *tu;

  memset(id, 0, sizeof(*id));
  GetTokenInformation(tok, TokenUser, NULL, 0, &need);
  if (need == 0)
    return 0;
  tu = sd_alloc(need);
  if (tu == NULL)
    return 0;
  if (!GetTokenInformation(tok, TokenUser, tu, need, &need)) {
    sd_free(tu);
    return 0;
  }
  id->sid_len = GetLengthSid(tu->User.Sid);
  id->sid = sd_alloc(id->sid_len);
  if (id->sid == NULL || !CopySid(id->sid_len, id->sid, tu->User.Sid)) {
    sd_free(id->sid);
    memset(id, 0, sizeof(*id));
    sd_free(tu);
    return 0;
  }
  sd_free(tu);

  if (sd_os_at_least(6, 0, 0)) {
    TOKEN_MANDATORY_LABEL *label;
    need = 0;
    GetTokenInformation(tok, TokenIntegrityLevel, NULL, 0, &need);
    if (need != 0) {
      label = sd_alloc(need);
      if (label != NULL && GetTokenInformation(tok, TokenIntegrityLevel, label, need, &need)) {
        UCHAR *count = GetSidSubAuthorityCount(label->Label.Sid);
        if (count != NULL && *count > 0) {
          id->integrity = *GetSidSubAuthority(label->Label.Sid, (DWORD)(*count - 1));
          id->has_integrity = 1;
        }
      }
      sd_free(label);
    }
  }
  return 1;
}

static int read_self(void)
{
  HANDLE tok = NULL;
  int ok = 0;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok))
    return 0;
  ok = read_identity(tok, &g_self);
  CloseHandle(tok);
  return ok;
}

/* True when the window belongs to a process of this user with an integrity level not below ours. */
static int sender_trusted(HWND sender)
{
  DWORD pid = 0;
  HANDLE proc, tok;
  ui_identity id;
  int ok = 0;

  if (sender == NULL || !GetWindowThreadProcessId(sender, &pid) || pid == 0)
    return 0;
  proc = OpenProcess(sd_os_at_least(6, 0, 0) ? PROCESS_QUERY_LIMITED_INFORMATION : PROCESS_QUERY_INFORMATION,
                     FALSE, pid);
  if (proc == NULL)
    return 0;
  if (OpenProcessToken(proc, TOKEN_QUERY, &tok)) {
    if (read_identity(tok, &id)) {
      ok = g_self.sid != NULL && id.sid != NULL && EqualSid(id.sid, g_self.sid);
      if (ok && id.has_integrity && g_self.has_integrity && id.integrity < g_self.integrity)
        ok = 0;
      sd_free(id.sid);
    }
    CloseHandle(tok);
  }
  CloseHandle(proc);
  return ok;
}

/* ---- requests ---- */

/* --action mount-file <path> (03 §8.1): the file must be a valid .sdmount naming one of the user's profiles. A file
   with Mark of the Web asks first. Nothing else in the file is read, so it can only start a configured mount. */
static void handle_mount_file(const wchar_t *path)
{
  unsigned char *buf;
  size_t n = 0;
  char id[33];
  sd_err e;
  const sd_profile *p = NULL;

  buf = (unsigned char *)sd_alloc(UI_SDMOUNT_MAX_BYTES + 1u);
  if (buf == NULL)
    return;
  e = ui_sdmount_read(path, buf, UI_SDMOUNT_MAX_BYTES + 1u, &n);
  if (e == SD_OK)
    e = ui_sdmount_parse(buf, n, id);
  sd_free(buf);
  if (e == SD_OK && ui_profiles_load() == SD_OK)
    p = ui_profiles_find_id(id);
  if (e != SD_OK || p == NULL) {
    MessageBoxW(g_app.main, sd_l10n_get(SD_MSG_UI_MOUNT_FILE_INVALID), L"ShellDrive", MB_OK | MB_ICONWARNING);
    return;
  }
  if (ui_file_has_mark(path)) {
    wchar_t name[160];
    ui_text_utf8(p->name, name, SD_COUNTOF(name));
    if (!ui_confirm(g_app.main, SD_MSG_UI_MOUNT_FILE_TITLE, SD_MSG_UI_MOUNT_FILE_MARK, name,
                    SD_MSG_UI_MOUNT_FILE_CONNECT, SD_MSG_UI_MOUNT_FILE_CANCEL, 0))
      return;
  }
  ui_ipc_mount(id);
}

void ui_app_handle_request(const ui_request *req)
{
  char id[40];
  ui_mount *m;

  switch (req->verb) {
  case UI_VERB_NONE:
  case UI_VERB_SHOW:
    ui_main_show();
    break;
  case UI_VERB_TRAY:
  case UI_VERB_PROMPT_HOST:
  case UI_VERB_ELEVATED_ADMIN:
    /* --tray changes nothing here; --prompt-host and --elevated-admin were handled in wWinMain (g_app.prompt_host,
       g_app.elevated_admin). */
    break;
  case UI_VERB_ELEVATED_SERVICE:
    ui_service_open();
    break;
  case UI_VERB_UNMOUNT:
    /* The drive must be one of this UI's mounts; the agent checks again. */
    m = ui_model_find_drive(&g_app.model, req->target);
    if (m == NULL) {
      SD_LOGW("ui", "unmount request for a drive that is not mounted: dropped");
      break;
    }
    ui_ipc_unmount(m->drive);
    break;
  case UI_VERB_MOUNT:
    ui_text_ascii(req->target, id, sizeof(id));
    ui_ipc_mount(id);
    break;
  case UI_VERB_OPEN:
    /* The shell extension's "Open" verb: the drive is one of ours (03 §8.2); Explorer shows it. */
    ui_open_drive(req->target);
    break;
  case UI_VERB_MOUNT_FILE:
    handle_mount_file(req->target);
    break;
  case UI_VERB_RECONNECT:
    /* The agent has no reconnect method yet (03 §2.4): the verb is accepted and logged only. */
    SD_LOGI("ui", "reconnect is not available in this build");
    break;
  default:
    break;
  }
}

void ui_app_on_agent_state(int up)
{
  g_app.agent_up = up ? 1 : 0;
  ui_windows_on_agent_state(g_app.agent_up);
  if (!up) {
    /* the agent is gone: its prompts are gone with it (dialogs close without an answer) */
    ui_model_clear(&g_app.model);
    ui_prompt_close_all();
    if (g_app.prompt_host) {
      SD_LOGI("ui", "prompt host: the agent is gone, leaving");
      ui_app_quit();
      return;
    }
  }
  ui_main_refresh();
  if (!up && g_app.prompt_host)
    ui_app_quit();              /* a prompt host lives only as long as the agent that started it */
}

void ui_app_on_list(sd_json *result)
{
  ui_model_set_list(&g_app.model, result);
  sd_json_free(result);
  ui_main_refresh();
}

/* The event list (7.7) gets every change of state of a drive, and a failed mount with the error code. m is the mount
   before the event is applied (NULL for one this UI has not listed). err_code: the error code of a failed state (NULL
   when the event has no error object); reason: why the drive reconnected (mount.state `reason`) or NULL; when: unix
   seconds for an entry of the agent's history, 0 for now. */
static void record_state_entry(const ui_mount *m, const char *state, int has_err, const char *err_code,
                               const char *reason, long long when)
{
  wchar_t text[160];
  wchar_t subject[UI_EV_SUBJECT_MAX];
  wchar_t state_w[24];
  const wchar_t *state_text;
  if (state == NULL || strlen(state) >= sizeof(m->state))
    return;
  ui_text_utf8(state, state_w, SD_COUNTOF(state_w));
  if (m != NULL) {
    ui_mount copy = *m;
    strcpy_s(copy.state, sizeof(copy.state), state);
    wcscpy_s(copy.state_w, SD_COUNTOF(copy.state_w), state_w);
    state_text = ui_model_state_text(&copy);
    wcsncpy_s(text, SD_COUNTOF(text), state_text, _TRUNCATE);
    wcsncpy_s(subject, SD_COUNTOF(subject), m->drive[0] != 0 ? m->drive : m->server, _TRUNCATE);
  } else {
    wcsncpy_s(text, SD_COUNTOF(text), state_w, _TRUNCATE);
    subject[0] = 0;
  }
  if (has_err) {
    wchar_t wcode[64];
    wchar_t *t;
    ui_text_utf8(err_code != NULL ? err_code : "error", wcode, SD_COUNTOF(wcode));
    t = ui_format1(SD_MSG_UI_EVENTS_TEXT_FAILED, "code", wcode);
    if (t != NULL) {
      ui_events_record_at(UI_EV_ERROR, when, subject, t);
      sd_free(t);
    }
    return;
  }
  if (reason != NULL && reason[0] != 0) {
    /* "Connecting (after: timeout)": the reason the connection comes back (03 2.4) */
    wchar_t wreason[160];
    wchar_t *t;
    sd_arg a[2];
    ui_reason_text(reason, wreason, SD_COUNTOF(wreason));
    a[0].name = "state";
    a[0].type = SD_ARG_STR;
    a[0].v.s = text;
    a[1].name = "reason";
    a[1].type = SD_ARG_STR;
    a[1].v.s = wreason;
    t = sd_l10n_format_alloc(SD_MSG_UI_EVENTS_TEXT_REASON, a, 2);
    if (t != NULL) {
      ui_events_record_at(UI_EV_DRIVE, when, subject, t);
      sd_free(t);
      return;
    }
  }
  ui_events_record_at(UI_EV_DRIVE, when, subject, text);
}

static void record_mount_event(const ui_mount *m, const sd_json *data, const char *state)
{
  const sd_json *err = sd_json_get(data, "error");
  if (state == NULL)
    return;
  if (err == NULL && m != NULL && strcmp(m->state, state) == 0)
    return;                                       /* the same state again (connection details only) */
  record_state_entry(m, state, err != NULL, sd_json_get_str(err, "code"), sd_json_get_str(data, "reason"), 0);
}

/* The name a notice carries: the drive letter, else the profile or the server; for a mount this UI has not listed, the
   target of the event (target_obj is the event data, or the data of a warning). */
static void notice_subject(const ui_mount *m, const sd_json *target_obj, wchar_t *out, size_t cch)
{
  out[0] = 0;
  if (m != NULL) {
    wcsncpy_s(out, cch, m->drive[0] != 0 ? m->drive : (m->profile[0] != 0 ? m->profile : m->server), _TRUNCATE);
    return;
  }
  ui_text_utf8(sd_json_get_str(target_obj, "target"), out, cch);
}

/* A mount.state change that leads to a notice of 7.7 (connection lost, reconnected, mounted, mount failed). */
static void notice_mount_state(ui_nt_kind kind, const ui_mount *m, const sd_json *data)
{
  wchar_t subject[UI_EV_SUBJECT_MAX];
  wchar_t code[64];
  const char *c = sd_json_get_str(sd_json_get(data, "error"), "code");
  notice_subject(m, data, subject, SD_COUNTOF(subject));
  if (kind == UI_NT_RECONNECTED) {
    /* why the connection was lost (mount.state `reason`, round 19): the notice says it when the agent does */
    c = sd_json_get_str(data, "reason");
    ui_text_utf8(c != NULL ? c : "", code, SD_COUNTOF(code));
  } else {
    ui_text_utf8(c != NULL ? c : "error", code, SD_COUNTOF(code));
  }
  ui_tray_notice(kind, subject, code, 0);
}

/* A `warning` with the code proxy_cleartext, pool_limited, disk_cache_refused or hostkey_source_insecure. The proxy password notice is once per
   (profile, proxy) for the life of the UI (7.7); the agent says it once per mount and hop. */
static void notice_warning(ui_nt_kind kind, const ui_mount *m, const sd_json *ev_data)
{
  static ui_nt_once once;
  const sd_json *d = sd_json_get(ev_data, "data");
  const char *detail = sd_json_get_str(d, "detail");
  wchar_t subject[UI_EV_SUBJECT_MAX];
  wchar_t wdetail[160];
  notice_subject(m, d, subject, SD_COUNTOF(subject));
  wdetail[0] = 0;
  if (kind == UI_NT_PROXY_PASSWORD) {
    char key[UI_NT_ONCE_KEY_MAX];
    const char *who = m != NULL && m->profile_id[0] != 0 ? m->profile_id : sd_json_get_str(ev_data, "mount_id");
    if (!ui_nt_once_key(who, detail, key, sizeof(key)) || !ui_nt_once_take(&once, key))
      return;
    ui_text_utf8(detail != NULL ? detail : "", wdetail, SD_COUNTOF(wdetail));
  }
  if (kind == UI_NT_HOSTKEYS_SOURCE) {
    /* detail names the live source the agent ignores: openssh or putty (TM-R06); the notice says which */
    const char *name = ui_nt_source_name(detail);
    ui_text_utf8(name != NULL ? name : "", wdetail, SD_COUNTOF(wdetail));
  }
  ui_tray_notice(kind, subject, wdetail, 0);
}

/* ---- the agent's event history (events.recent, 03 2.4, 7.7) ---- */

static ui_evh_state g_evh;
static int g_evh_ready;

/* The name of the mount in the event list: the drive letter, else the profile or the server; empty for a mount this UI
   does not know (the history has only its id). */
static void history_subject(const char *mount_id, wchar_t *out, size_t cch)
{
  const ui_mount *m = ui_model_find_id(&g_app.model, mount_id);
  out[0] = 0;
  if (m != NULL)
    wcsncpy_s(out, cch, m->drive[0] != 0 ? m->drive : (m->profile[0] != 0 ? m->profile : m->server), _TRUNCATE);
}

/* One record of the history becomes the entry the live event would have made, at the time it happened. prev: the state
   the mount had before (replayed from the history). */
static void history_record(const ui_evh_rec *r, const char *prev)
{
  wchar_t subject[UI_EV_SUBJECT_MAX];
  history_subject(r->mount_id, subject, SD_COUNTOF(subject));
  if (strcmp(r->event, "mount.state") == 0) {
    const ui_mount *m = ui_model_find_id(&g_app.model, r->mount_id);
    int failed = strcmp(r->state, "failed") == 0;
    ui_nt_kind nk = ui_nt_of_mount_state_r(prev, r->state, failed ? r->code : NULL, NULL);
    if (nk != UI_NT_NONE) {
      wchar_t code[64];
      ui_text_utf8(r->code[0] != 0 ? r->code : "error", code, SD_COUNTOF(code));
      ui_tray_history_notice(nk, r->time, subject, nk == UI_NT_MOUNT_FAILED ? code : L"");
    } else if (failed || strcmp(prev, r->state) != 0) {
      record_state_entry(m, r->state, failed, r->code, NULL, r->time);
    }
  } else if (strcmp(r->event, "warning") == 0) {
    ui_nt_kind nk = ui_nt_of_warning_code(r->code);
    if (nk == UI_NT_PROXY_PASSWORD)
      return;                                     /* the history does not say which proxy */
    if (nk != UI_NT_NONE)
      ui_tray_history_notice(nk, r->time, subject, L"");
    else
      ui_tray_history_warning(r->code, r->time, subject);
  } else if (strcmp(r->event, "hostkeys.announced") == 0) {
    const ui_mount *m = ui_model_find_id(&g_app.model, r->mount_id);
    if (m != NULL)
      ui_tray_history_hostkeys(r->time, m->server);
  }
}

/* The reply of events.recent: fills the event list with what happened before this UI was running, skipping what it has
   seen as live events already (ui_evhist_model.h). */
void ui_app_on_history(sd_json *result)
{
  const sd_json *arr = sd_json_get(result, "events");
  int64_t last = 0;
  size_t i, n = sd_json_count(arr);
  ui_evh_track track;
  if (!g_evh_ready) {
    ui_evh_init(&g_evh);
    g_evh_ready = 1;
  }
  if (!sd_json_get_int64(result, "last_seq", &last) || last < 0)
    last = 0;
  ui_evh_track_init(&track);
  ui_evh_begin(&g_evh, (unsigned long long)last);
  for (i = 0; i < n; i++) {
    ui_evh_rec r;
    char prev[24];
    if (!ui_evh_parse(sd_json_at(arr, i), &r))
      continue;
    prev[0] = 0;
    if (strcmp(r.event, "mount.state") == 0)
      ui_evh_track_step(&track, r.mount_id, r.state, prev);
    if (ui_evh_wanted(&g_evh, &r))
      history_record(&r, prev);
  }
  ui_evh_end(&g_evh, (unsigned long long)last);
  sd_json_free(result);
}

void ui_app_on_event(sd_json *ev)
{
  if (!g_evh_ready) {
    ui_evh_init(&g_evh);
    g_evh_ready = 1;
  }
  const char *name = sd_json_get_str(ev, "event");
  const sd_json *data = sd_json_get(ev, "data");

  if (name != NULL && strcmp(name, "mount.state") == 0) {
    const char *id = sd_json_get_str(data, "mount_id");
    const char *st = sd_json_get_str(data, "state");
    ui_mount *m = ui_model_find_id(&g_app.model, id);
    ui_nt_kind nk = ui_nt_of_mount_state_r(m != NULL ? m->state : "", st,
                                           sd_json_get_str(sd_json_get(data, "error"), "code"),
                                           sd_json_get_str(data, "reason"));
    ui_evh_note_live(&g_evh, name, id, st, sd_unix_time_now());
    /* a change the user is told about (7.7) is recorded by its notice, the others by the plain state entry */
    if (nk != UI_NT_NONE)
      notice_mount_state(nk, m, data);
    else
      record_mount_event(m, data, st);
    if (m == NULL) {
      /* A mount this UI has not listed yet: ask for the list again. */
      if (st != NULL && strcmp(st, "unmounted") != 0)
        ui_ipc_list();
    } else if (st != NULL && strcmp(st, "unmounted") == 0) {
      char profile_id[sizeof(m->profile_id)];
      strcpy_s(profile_id, sizeof(profile_id), m->profile_id);
      ui_model_remove(&g_app.model, m);
      ui_secdlg_on_unmounted(profile_id);
    } else if (st != NULL && strlen(st) < sizeof(m->state)) {
      strcpy_s(m->state, sizeof(m->state), st);
      ui_text_utf8(m->state, m->state_w, SD_COUNTOF(m->state_w));
      ui_model_set_connection(m, data);
    }
    /* a failed mount with a changed key or the wrong key type: the balloon and its details (5.4, TM-R04) */
    if (sd_json_get(data, "error") != NULL)
      ui_hkissue_on_mount_state(data, m != NULL ? m->host : NULL, m != NULL ? m->drive : L"");
    ui_main_refresh();
  } else if (name != NULL && strcmp(name, "warning") == 0) {
    const char *code = sd_json_get_str(data, "code");
    ui_mount *m = ui_model_find_id(&g_app.model, sd_json_get_str(data, "mount_id"));
    unsigned flag = ui_mv_sec_flag(code);
    ui_evh_note_live(&g_evh, name, sd_json_get_str(data, "mount_id"), code, sd_unix_time_now());
    if (m != NULL && flag != 0) {
      /* the Security column and the details dialog (7.6); a legacy warning names the algorithms */
      m->sec |= flag;
      if (flag == UI_MV_SEC_LEGACY && ui_mv_algos_join(sd_json_get(data, "data"), m->algos, sizeof(m->algos)) > 0)
        memset(m->algo_cat, 0, sizeof(m->algo_cat));    /* an event names no categories: the dialog derives them */
      ui_main_refresh();
    }
    {
      ui_nt_kind nk = ui_nt_of_warning_code(code);
      if (nk != UI_NT_NONE)
        notice_warning(nk, m, data);
      else
        ui_tray_balloon(code, m ? m->drive : L"");
    }
  } else if (name != NULL && strcmp(name, "prompt.request") == 0) {
    ui_prompt_on_request(data);
  } else if (name != NULL && strcmp(name, "prompt.closed") == 0) {
    ui_prompt_on_closed(sd_json_get_str(data, "prompt_id"), sd_json_get_str(data, "reason"));
  } else if (name != NULL && strcmp(name, "hostkeys.announced") == 0) {
    ui_evh_note_live(&g_evh, name, sd_json_get_str(data, "mount_id"), NULL, sd_unix_time_now());
    ui_tray_on_hostkeys_announced(data);
    ui_windows_on_event(name, data);
  } else if (name != NULL && strncmp(name, "update.", 7) == 0) {
    /* update.available, update.progress, update.stale: the Settings group and the balloon (ui_update.c) */
    ui_windows_on_event(name, data);
  }
  sd_json_free(ev);
}

/* the list carries the same fields as prompt.request: a prompt this UI does not show becomes a dialog
   (ui_prompt.c keeps the dialog of one that is already open, so none is shown twice) */
static void prompts_from_list(const sd_json *result)
{
  const sd_json *arr = sd_json_get(result, "prompts");
  size_t i, n = sd_json_count(arr);
  for (i = 0; i < n; i++)
    ui_prompt_on_request(sd_json_at(arr, i));
}

void ui_app_on_prompt_list(sd_json *result)
{
  ui_prompt_on_list(result);
  /* the agent's list (every mode) and the service's list (admin mode, ui_svc.c) both carry every prompt
     their sender still holds: one that was showing when the connection dropped is shown again, with its
     remaining deadline (03 §2.1 prompt.list) */
  prompts_from_list(result);
  sd_json_free(result);
}

/* attention {count} from the service (ui_svc.c): the tray shows it to an administrator only. */
void ui_app_on_attention(int count)
{
  int previous = g_app.attention;
  g_app.attention = ui_admin_attention_shown(count, g_app.user_admin) ? count : 0;
  ui_tray_update();
  if (ui_nt_attention_grew(previous, g_app.attention))
    ui_tray_notice(UI_NT_SERVICE_ATTENTION, L"", NULL, g_app.attention);   /* administrators only (7.7) */
}

/* Once a second. The prompt host leaves after UI_PROMPT_IDLE_MS with no open prompt (03 §1.4). */
void ui_app_on_timer(UINT_PTR id)
{
  if (id == UI_TIMER_NOTIFY) {
    ui_tray_flush();                      /* queued balloons (7.7), only while some wait */
    return;
  }
  if (id != UI_TIMER_PROMPT_IDLE || !g_app.prompt_host)
    return;
  if (ui_prompt_count() > 0) {
    g_app.idle_ms = 0;
    return;
  }
  g_app.idle_ms += 1000u;
  if (g_app.idle_ms >= UI_PROMPT_IDLE_MS) {
    SD_LOGI("ui", "prompt host: no prompt for 60 s, leaving");
    ui_app_quit();
  }
}

void ui_app_on_reply(ui_ipc_reply *r)
{
  if (r->kind == UI_IPC_AGENT_START) {
    ui_main_agent_start_done(r->err);
  } else if (r->kind >= UI_IPC_ANNOUNCED) {
    ui_windows_on_reply((int)r->kind, r->err, r->result);
  } else if (r->kind == UI_IPC_ANSWER) {
    /* answers close their dialog when queued; a refused one (answered elsewhere) needs no message */
    if (r->err != SD_OK)
      SD_LOGI("ui", "prompt answer not accepted by the agent (%s)", sd_err_name(r->err));
  } else if (r->kind == UI_IPC_MOUNT && r->err != SD_OK) {
    /* a refused or failed mount: the mount state events say what happened; this says the request did not start */
    MessageBoxW(g_app.main, sd_l10n_get(SD_MSG_UI_ERROR_MOUNT), L"ShellDrive", MB_OK | MB_ICONERROR);
  } else if (r->kind == UI_IPC_UNMOUNT && r->err != SD_OK) {
    wchar_t *t = ui_format1(SD_MSG_UI_ERROR_UNMOUNT, "drive", r->drive);
    if (t != NULL) {
      MessageBoxW(g_app.main, t, L"ShellDrive", MB_OK | MB_ICONERROR);
      sd_free(t);
    }
  }
  sd_json_free(r->result);
  sd_free(r);
}

void ui_app_quit(void)
{
  g_app.quit = 1;
  PostQuitMessage(0);
}

/* ---- control window: WM_COPYDATA, IPC results, tray callbacks ---- */

static LRESULT on_copydata(HWND sender, const COPYDATASTRUCT *cds)
{
  ui_request req;
  if (cds == NULL || cds->dwData != UI_WIRE_CDATA_TAG) {
    SD_LOGW("ui", "copydata with an unknown tag: dropped");
    return FALSE;
  }
  if (!sender_trusted(sender)) {
    SD_LOGW("ui", "copydata from another user or a higher integrity level: dropped");
    return FALSE;
  }
  if (ui_request_from_payload(cds->lpData, cds->cbData, &req) != SD_OK) {
    SD_LOGW("ui", "copydata payload rejected: dropped");
    return FALSE;
  }
  ui_app_handle_request(&req);
  return TRUE;
}

static LRESULT CALLBACK ctrl_proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
  switch (msg) {
  case WM_COPYDATA:
    return on_copydata((HWND)wp, (const COPYDATASTRUCT *)lp);
  case UI_WM_IPC_STATE:
    ui_app_on_agent_state(wp != 0);
    return 0;
  case UI_WM_IPC_LIST:
    ui_app_on_list((sd_json *)lp);
    return 0;
  case UI_WM_IPC_EVENT:
    ui_app_on_event((sd_json *)lp);
    return 0;
  case UI_WM_IPC_REPLY:
    ui_app_on_reply((ui_ipc_reply *)lp);
    return 0;
  case UI_WM_TRAY:
    ui_tray_callback(lp);
    return 0;
  case UI_WM_IPC_PROMPTS:
    ui_app_on_prompt_list((sd_json *)lp);
    return 0;
  case UI_WM_IPC_HISTORY:
    ui_app_on_history((sd_json *)lp);
    return 0;
  case UI_WM_SVC_ATTENTION:
    ui_app_on_attention((int)wp);
    return 0;
  case WM_TIMER:
    ui_app_on_timer(wp);
    return 0;
  default:
    break;
  }
  return DefWindowProcW(hwnd, msg, wp, lp);
}

static int register_ctrl_class(HINSTANCE inst)
{
  WNDCLASSEXW wc;
  memset(&wc, 0, sizeof(wc));
  wc.cbSize = sizeof(wc);
  wc.lpfnWndProc = ctrl_proc;
  wc.hInstance = inst;
  wc.lpszClassName = g_app.class_ctrl;
  return RegisterClassExW(&wc) != 0 || GetLastError() == ERROR_CLASS_ALREADY_EXISTS;
}

/* Config root of the --test-* smoke modes (a temporary folder unique to this process; removed at exit). */
static wchar_t g_smoke_root[MAX_PATH + 32];

static void remove_smoke_tree(const wchar_t *dir)
{
  wchar_t pat[MAX_PATH + 32], path[MAX_PATH + 32];
  WIN32_FIND_DATAW fd;
  HANDLE h;
  _snwprintf_s(pat, SD_COUNTOF(pat), _TRUNCATE, L"%s\\*", dir);
  h = FindFirstFileW(pat, &fd);
  if (h != INVALID_HANDLE_VALUE) {
    do {
      if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;
      _snwprintf_s(path, SD_COUNTOF(path), _TRUNCATE, L"%s\\%s", dir, fd.cFileName);
      if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) remove_smoke_tree(path);
      else DeleteFileW(path);
    } while (FindNextFileW(h, &fd));
    FindClose(h);
  }
  RemoveDirectoryW(dir);
}

static void build_class_names(void)
{
  wcscpy_s(g_app.class_ctrl, SD_COUNTOF(g_app.class_ctrl), L"com.librestatic.shelldrive.ui.");
  wcscat_s(g_app.class_ctrl, SD_COUNTOF(g_app.class_ctrl), g_sid);
  wcscpy_s(g_app.class_main, SD_COUNTOF(g_app.class_main), g_app.class_ctrl);
  wcscat_s(g_app.class_main, SD_COUNTOF(g_app.class_main), L".main");
}

/* Sends the command line to the running instance. The sender is a private message-only window, so the
   receiver can check our process (its token user and integrity level). */
static int forward_to_running(int argc, wchar_t **argv)
{
  unsigned char *buf = NULL;
  size_t n = 0;
  HWND target, sender;
  COPYDATASTRUCT cds;
  DWORD_PTR result = 0;
  int ok = 0;

  if (ui_wire_encode(argc, (const wchar_t *const *)argv, &buf, &n) != SD_OK)
    return 0;
  target = FindWindowExW(HWND_MESSAGE, NULL, g_app.class_ctrl, NULL);
  sender = CreateWindowExW(0, L"STATIC", L"", 0, 0, 0, 0, 0, HWND_MESSAGE, NULL, g_app.inst, NULL);
  if (target != NULL && sender != NULL) {
    cds.dwData = UI_WIRE_CDATA_TAG;
    cds.cbData = (DWORD)n;
    cds.lpData = buf;
    ok = SendMessageTimeoutW(target, WM_COPYDATA, (WPARAM)sender, (LPARAM)&cds, SMTO_ABORTIFHUNG, 5000,
                             &result) != 0 &&
         result != 0;
  }
  if (sender != NULL)
    DestroyWindow(sender);
  sd_free(buf);
  return ok;
}

/* --theme=<classic|aero|fluent-a|fluent-b|fluent-c>[-dark] (06 §8.1): the UI_FORCE_TIER override of the
   smoke modes, -1 when the value is not recognized. */
static int theme_option_forced(const wchar_t *v)
{
  size_t n = wcslen(v);
  int dark = 0;

  if (n > 5 && wcscmp(v + n - 5, L"-dark") == 0) {
    dark = 1;
    n -= 5;
  }
  if (n == 7 && wcsncmp(v, L"classic", 7) == 0)
    return UI_FORCE_TIER(UI_TIER_CLASSIC, 0, dark);
  if (n == 4 && wcsncmp(v, L"aero", 4) == 0)
    return UI_FORCE_TIER(UI_TIER_AERO, 0, dark);
  if (n == 8 && wcsncmp(v, L"fluent-", 7) == 0 && v[7] >= L'a' && v[7] <= L'c')
    return UI_FORCE_TIER(UI_TIER_FLUENT, (int)v[7], dark);
  return -1;
}

/* Smoke test (--test-window): the main window class is registered, the window and its controls exist,
   and the window stays hidden. It prints the theme the model selected (06 §8.1). */
static int run_smoke_test(void)
{
  WNDCLASSEXW wc;
  HWND w;
  int ok;
  const ui_theme *theme;

  if (!ui_main_register_class(g_app.inst, g_app.class_main))
    return 1;
  ui_theme_init();
  memset(&wc, 0, sizeof(wc));
  wc.cbSize = sizeof(wc);
  if (GetClassInfoExW(g_app.inst, g_app.class_main, &wc) == 0) {
    ui_theme_shutdown();
    return 1;
  }
  w = ui_main_create(g_app.inst, g_app.class_main, 0);
  if (w == NULL || !IsWindow(w)) {
    ui_theme_shutdown();
    return 1;
  }
  ok = ui_main_test_controls() && !IsWindowVisible(w);
  theme = ui_theme_current();
  if (theme != NULL)
    printf("theme tier=%d level=%c dark=%d backdrop=%d\n", theme->tier,
           theme->level != 0 ? theme->level : '0', theme->dark, theme->backdrop);
  DestroyWindow(w);
  ui_theme_shutdown();
  return ok ? 0 : 1;
}

int WINAPI wWinMain(_In_ HINSTANCE inst, _In_opt_ HINSTANCE prev, _In_ LPWSTR cmd, _In_ int show)
{
  wchar_t **argv = NULL;
  int argc = 0, rc = 1;
  ui_request req;
  wchar_t lang_buf[32];
  const wchar_t *lang = NULL;
  DWORD session = 0;
  INITCOMMONCONTROLSEX icc;
  HANDLE mutex = NULL;
  int existed = 0;
  int i, test_mode, theme_forced;
  sd_err e;
  MSG msg;

  (void)prev;
  (void)cmd;
  (void)show;
  sd_platform_harden_dll_search();
  sd_platform_init();
  ui_dpi_init();
  g_app.inst = inst;
  g_app.wm_taskbar = RegisterWindowMessageW(L"TaskbarCreated");

  argv = CommandLineToArgvW(GetCommandLineW(), &argc);
  if (argv == NULL)
    return 1;

  if (GetEnvironmentVariableW(L"SHELLDRIVE_LANG", lang_buf, SD_COUNTOF(lang_buf)) - 1u <
      SD_COUNTOF(lang_buf) - 1u)
    lang = lang_buf;
  sd_l10n_init(&sd_l10n_catalog_ui, lang);
  sd_settings_defaults(&g_app.settings);
  (void)sd_settings_load(&g_app.settings);

  memset(&icc, 0, sizeof(icc));
  icc.dwSize = sizeof(icc);
  icc.dwICC = ICC_LISTVIEW_CLASSES | ICC_BAR_CLASSES | ICC_TAB_CLASSES;
  InitCommonControlsEx(&icc);

  if (sd_ipc_current_identity(g_sid, SD_COUNTOF(g_sid), &session) != SD_OK || !read_self())
    goto done;
  build_class_names();

  test_mode = argc > 1 && (wcscmp(argv[1], L"--test-window") == 0 || wcscmp(argv[1], L"--test-prompts") == 0 ||
                           wcscmp(argv[1], L"--test-editor") == 0 || wcscmp(argv[1], L"--test-windows") == 0 ||
                           wcscmp(argv[1], L"--test-wizard") == 0);

  /* --theme=<...> (06 §8.1) forces a tier for the smoke runs; it is refused outside the test modes. */
  theme_forced = -1;
  for (i = 2; i < argc; i++) {
    if (wcsncmp(argv[i], L"--theme=", 8) == 0)
      break;
  }
  if (i < argc && !test_mode) {
    SD_LOGW("ui", "--theme is only valid together with the --test-* smoke modes");
    rc = 2;
    goto done;
  }
  if (i < argc) {
    theme_forced = theme_option_forced(argv[i] + 8);
    if (theme_forced < 0) {
      SD_LOGW("ui", "--theme value not recognized");
      rc = 2;
      goto done;
    }
  }
  ui_theme_set_options(UI_THEME_STYLE_AUTO, 1, theme_forced);

  if (test_mode) {
    /* the smoke tests never read or write the user's profiles: the store is a temporary folder that only
       this process uses (PID and stamp in the name, removed at exit), so concurrent runs never share it */
    wchar_t tmp[MAX_PATH];
    if (GetTempPathW(SD_COUNTOF(tmp), tmp) > 0 && wcslen(tmp) < SD_COUNTOF(tmp) - 64) {
      LARGE_INTEGER qpc;
      QueryPerformanceCounter(&qpc);
      _snwprintf_s(g_smoke_root, SD_COUNTOF(g_smoke_root), _TRUNCATE, L"%sshelldrive-ui-test-%lu-%08lx", tmp,
                   (unsigned long)GetCurrentProcessId(), (unsigned long)qpc.LowPart);
      sd_config_set_root_override(g_smoke_root);
    }
  }
  if (argc > 1 && wcscmp(argv[1], L"--test-window") == 0) {
    rc = run_smoke_test();
    goto done;
  }
  if (argc > 1 && wcscmp(argv[1], L"--test-prompts") == 0) {
    rc = ui_prompt_smoke_test() ? 0 : 1;
    goto done;
  }
  if (argc > 1 && wcscmp(argv[1], L"--test-editor") == 0) {
    rc = ui_editor_smoke_test() ? 0 : 1;
    goto done;
  }
  if (argc > 1 && wcscmp(argv[1], L"--test-windows") == 0) {
    rc = ui_windows_smoke_test() ? 0 : 1;
    goto done;
  }
  if (argc > 1 && wcscmp(argv[1], L"--test-wizard") == 0) {
    rc = ui_wizard_smoke_test() ? 0 : 1;
    goto done;
  }

  if (ui_request_from_args(argc - 1, (const wchar_t *const *)(argv + 1), &req) != SD_OK) {
    SD_LOGW("ui", "command line not recognized");
    rc = 2;
    goto done;
  }

  /* set before the IPC thread starts: it reads the flag at its first connect */
  g_app.elevated_admin = req.verb == UI_VERB_ELEVATED_ADMIN;
  /* the admin mode has the prompt host's lifetime (no main window, leaves when the service goes or idles) */
  g_app.prompt_host = req.verb == UI_VERB_PROMPT_HOST || g_app.elevated_admin;
  g_app.elevated_service = req.verb == UI_VERB_ELEVATED_SERVICE;
  if (!g_app.elevated_admin && !g_app.elevated_service) {
    /* the admin mode is not a second UI of the user: it never forwards to the running one (no mutex) */
    e = sd_ipc_object_create(SD_IPC_OBJ_UI_MUTEX, &mutex, &existed);
    if (e != SD_OK || mutex == NULL)
      goto done;
    g_app.mutex = mutex;
    if (existed) {
      rc = forward_to_running(argc - 1, argv + 1) ? 0 : 1;
      goto done;
    }
  }

  /* the theme (06 §4): the hook is installed before the first window of this process exists */
  ui_theme_init();
  if (!register_ctrl_class(inst) || !ui_main_register_class(inst, g_app.class_main))
    goto done;
  g_app.ctrl = CreateWindowExW(0, g_app.class_ctrl, L"", 0, 0, 0, 0, 0, HWND_MESSAGE, NULL, inst, NULL);
  if (g_app.ctrl == NULL)
    goto done;
  if (!g_app.prompt_host && !g_app.elevated_service && ui_main_create(inst, g_app.class_main, 0) == NULL)
    goto done;
  if (g_app.prompt_host)
    SetTimer(g_app.ctrl, UI_TIMER_PROMPT_IDLE, 1000, NULL);
  if (g_app.elevated_service) {
    /* the Service page alone: no tray, no agent, no service thread (it reads the service on demand) */
    g_app.user_admin = ui_svc_user_is_admin();
  } else if (g_app.elevated_admin) {
    /* no tray icon for the admin mode: its prompt dialogs are the window */
    if (ui_svc_start(1) != SD_OK)
      goto done;
  } else {
    /* Explorer may not be ready yet; TaskbarCreated adds the icon later. */
    ui_tray_add();
    if (ui_ipc_start() != SD_OK)
      goto done;
    /* attention watch (03 §2.6 rule 3): only for a logged-on administrator; other users never connect to the service */
    g_app.user_admin = ui_svc_user_is_admin();
    if (g_app.user_admin)
      (void)ui_svc_start(0);
  }
  ui_app_handle_request(&req);
  /* first run (7.5): only for the plain start and "show"; --tray and the prompt host never open it */
  if (g_app.elevated_service && !ui_service_is_open())
    goto done;                          /* the page could not be created: nothing to wait for */
  if (req.verb == UI_VERB_NONE || req.verb == UI_VERB_SHOW)
    ui_wizard_run_if_needed(g_app.main, 0, g_app.prompt_host);

  while (GetMessageW(&msg, NULL, 0, 0) > 0) {
    if (ui_prompt_filter(&msg))
      continue;                        /* IsDialogMessage: keyboard handling of the prompt dialogs */
    TranslateMessage(&msg);
    DispatchMessageW(&msg);
  }
  rc = 0;

  ui_windows_close_all();
  ui_svc_stop();
  ui_ipc_stop();
  ui_tray_remove();
  if (g_app.main != NULL && IsWindow(g_app.main))
    DestroyWindow(g_app.main);
  if (g_app.ctrl != NULL && IsWindow(g_app.ctrl))
    DestroyWindow(g_app.ctrl);
  ui_theme_shutdown();
  ui_icon_free_all();

done:
  if (g_smoke_root[0] != 0) {
    sd_config_set_root_override(NULL);
    remove_smoke_tree(g_smoke_root);
  }
  if (mutex != NULL)
    CloseHandle(mutex);
  if (argv != NULL)
    LocalFree(argv);
  return rc;
}
