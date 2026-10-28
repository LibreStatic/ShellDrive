/* shelldrive-ui: the Service page model. See ui_service_model.h. Pure. */
#include <windows.h>
#include <string.h>

#include "ui_service_model.h"

static void wide_of_utf8(const char *s, wchar_t *out, size_t cch)
{
  out[0] = 0;
  if (s != NULL && s[0] != 0)
    MultiByteToWideChar(CP_UTF8, 0, s, -1, out, (int)cch);
  out[cch - 1] = 0;
}

void ui_svc_view_init(ui_svc_view *v)
{
  memset(v, 0, sizeof(*v));
}

static ui_svc_state state_of_word(const char *w)
{
  if (w == NULL) return UI_SVC_ST_UNKNOWN;
  if (strcmp(w, "not_installed") == 0) return UI_SVC_ST_NOT_INSTALLED;
  if (strcmp(w, "running") == 0) return UI_SVC_ST_RUNNING;
  if (strcmp(w, "stopped") == 0) return UI_SVC_ST_STOPPED;
  if (strcmp(w, "starting") == 0) return UI_SVC_ST_STARTING;
  if (strcmp(w, "stopping") == 0) return UI_SVC_ST_STOPPING;
  if (strcmp(w, "paused") == 0) return UI_SVC_ST_PAUSED;
  return UI_SVC_ST_UNKNOWN;
}

static ui_svc_starttype start_of_word(const char *w)
{
  if (w == NULL) return UI_SVC_START_UNKNOWN;
  if (strcmp(w, "automatic") == 0) return UI_SVC_START_AUTOMATIC;
  if (strcmp(w, "manual") == 0) return UI_SVC_START_MANUAL;
  if (strcmp(w, "disabled") == 0) return UI_SVC_START_DISABLED;
  return UI_SVC_START_UNKNOWN;
}

static int program_check_of_word(const char *w)
{
  if (w == NULL) return UI_SVC_PROGRAM_UNKNOWN;
  if (strcmp(w, "ok") == 0) return UI_SVC_PROGRAM_OK;
  if (strcmp(w, "unquoted") == 0) return UI_SVC_PROGRAM_UNQUOTED;
  if (strcmp(w, "other") == 0) return UI_SVC_PROGRAM_OTHER;
  return UI_SVC_PROGRAM_UNKNOWN;
}

static int source_check_of_word(const char *w)
{
  if (w == NULL) return UI_SVC_SOURCE_UNKNOWN;
  if (strcmp(w, "registered") == 0) return UI_SVC_SOURCE_OK;
  if (strcmp(w, "missing") == 0) return UI_SVC_SOURCE_MISSING;
  if (strcmp(w, "other") == 0) return UI_SVC_SOURCE_OTHER;
  return UI_SVC_SOURCE_UNKNOWN;
}

static ui_svc_reason reason_of_word(const char *w)
{
  if (w == NULL) return UI_SVC_REASON_OTHER;
  if (strcmp(w, "owner") == 0) return UI_SVC_REASON_OWNER;
  if (strcmp(w, "reparse_point") == 0) return UI_SVC_REASON_LINK;
  if (strcmp(w, "acl") == 0) return UI_SVC_REASON_ACL;
  return UI_SVC_REASON_OTHER;
}

static long long count_of(const sd_json *o, const char *key)
{
  int64_t n = 0;
  if (!sd_json_get_int64(o, key, &n) || n < 0)
    return 0;
  return (long long)n;
}

sd_err ui_svc_view_from_status(ui_svc_view *v, const sd_json *res)
{
  int installed = 0;
  const sd_json *o;
  ui_svc_view_init(v);
  if (res == NULL || sd_json_type_of(res) != SD_JSON_OBJECT || !sd_json_get_bool(res, "installed", &installed))
    return SD_E_INVALID_PARAM;
  v->valid = 1;
  v->state = installed ? state_of_word(sd_json_get_str(res, "state")) : UI_SVC_ST_NOT_INSTALLED;
  if (installed && v->state == UI_SVC_ST_NOT_INSTALLED)
    v->state = UI_SVC_ST_UNKNOWN;
  v->start = installed ? start_of_word(sd_json_get_str(res, "start_type")) : UI_SVC_START_NONE;
  o = sd_json_get(res, "program");
  v->program_check = program_check_of_word(sd_json_get_str(o, "check"));
  wide_of_utf8(sd_json_get_str(o, "path"), v->program, UI_SVC_PATH_MAX);
  o = sd_json_get(res, "event_source");
  v->source_check = source_check_of_word(sd_json_get_str(o, "state"));
  o = sd_json_get(res, "pipe");
  if (o != NULL && sd_json_type_of(o) == SD_JSON_OBJECT) {
    int b = 0;
    v->pipe_reachable = sd_json_get_bool(o, "reachable", &b) && b ? 1 : 0;
    v->healthy = sd_json_get_bool(o, "healthy", &b) && b ? 1 : 0;
    v->drives = count_of(o, "global_drives");
    v->prompts = count_of(o, "prompts");
    v->service_reports = v->pipe_reachable;
  }
  o = sd_json_get(res, "machine");
  if (o != NULL && sd_json_type_of(o) == SD_JSON_OBJECT) {
    const char *st = sd_json_get_str(o, "state");
    if (st != NULL && strcmp(st, "ok") == 0) {
      v->machine = UI_SVC_MACHINE_OK;
    } else if (st != NULL && strcmp(st, "refused") == 0) {
      v->machine = UI_SVC_MACHINE_REFUSED;
      v->reason = reason_of_word(sd_json_get_str(o, "reason"));
      wide_of_utf8(sd_json_get_str(o, "path"), v->machine_path, UI_SVC_PATH_MAX);
    }
    v->profiles = count_of(o, "profiles");
  }
  /* a reply without the machine member is not a service that reports its folder */
  if (v->machine == UI_SVC_MACHINE_NONE)
    v->service_reports = 0;
  return SD_OK;
}

void ui_svc_view_from_scm(ui_svc_view *v, int installed, unsigned long state, unsigned long start_type,
                          int path_check, int source_check, const wchar_t *binary)
{
  ui_svc_view_init(v);
  v->valid = 1;
  if (!installed) {
    v->state = UI_SVC_ST_NOT_INSTALLED;
    v->start = UI_SVC_START_NONE;
  } else {
    switch (state) {
    case SERVICE_RUNNING: v->state = UI_SVC_ST_RUNNING; break;
    case SERVICE_STOPPED: v->state = UI_SVC_ST_STOPPED; break;
    case SERVICE_START_PENDING: v->state = UI_SVC_ST_STARTING; break;
    case SERVICE_STOP_PENDING: v->state = UI_SVC_ST_STOPPING; break;
    case SERVICE_PAUSED: v->state = UI_SVC_ST_PAUSED; break;
    default: v->state = UI_SVC_ST_UNKNOWN; break;
    }
    switch (start_type) {
    case SERVICE_AUTO_START: v->start = UI_SVC_START_AUTOMATIC; break;
    case SERVICE_DEMAND_START: v->start = UI_SVC_START_MANUAL; break;
    case SERVICE_DISABLED: v->start = UI_SVC_START_DISABLED; break;
    default: v->start = UI_SVC_START_UNKNOWN; break;
    }
    if (binary != NULL)
      wcsncpy_s(v->program, UI_SVC_PATH_MAX, binary, _TRUNCATE);
  }
  v->program_check = path_check >= UI_SVC_PROGRAM_OK && path_check <= UI_SVC_PROGRAM_OTHER ? path_check
                                                                                              : UI_SVC_PROGRAM_UNKNOWN;
  v->source_check = source_check >= UI_SVC_SOURCE_OK && source_check <= UI_SVC_SOURCE_OTHER ? source_check
                                                                                              : UI_SVC_SOURCE_UNKNOWN;
}

static void put(ui_svc_line *out, size_t *n, ui_svc_line_kind kind, int which, long long count, const wchar_t *text)
{
  if (*n >= UI_SVC_LINES_MAX)
    return;
  out[*n].kind = kind;
  out[*n].which = which;
  out[*n].count = count;
  out[*n].text = text;
  (*n)++;
}

size_t ui_svc_lines(const ui_svc_view *v, ui_svc_line out[UI_SVC_LINES_MAX])
{
  size_t n = 0;
  if (v == NULL || !v->valid)
    return 0;
  if (v->state == UI_SVC_ST_NOT_INSTALLED) {
    put(out, &n, UI_SVC_LINE_NOT_INSTALLED, 0, 0, NULL);
    put(out, &n, UI_SVC_LINE_SOURCE_CHECK, v->source_check, 0, NULL);
    return n;
  }
  put(out, &n, UI_SVC_LINE_STATE, (int)v->state, 0, NULL);
  put(out, &n, UI_SVC_LINE_START, (int)v->start, 0, NULL);
  put(out, &n, UI_SVC_LINE_PROGRAM, 0, 0, v->program);
  put(out, &n, UI_SVC_LINE_PROGRAM_CHECK, v->program_check, 0, NULL);
  put(out, &n, UI_SVC_LINE_SOURCE_CHECK, v->source_check, 0, NULL);
  if (v->state != UI_SVC_ST_RUNNING)
    return n;
  if (!v->pipe_reachable) {
    put(out, &n, UI_SVC_LINE_PIPE_DOWN, 0, 0, NULL);
    return n;
  }
  if (!v->service_reports) {
    put(out, &n, UI_SVC_LINE_OLD_SERVICE, 0, 0, NULL);
    return n;
  }
  if (v->machine == UI_SVC_MACHINE_REFUSED) {
    put(out, &n, UI_SVC_LINE_MACHINE_REFUSED, (int)v->reason, 0, NULL);
    if (v->machine_path[0] != 0)
      put(out, &n, UI_SVC_LINE_MACHINE_PATH, 0, 0, v->machine_path);
  } else {
    put(out, &n, UI_SVC_LINE_MACHINE_OK, 0, 0, NULL);
  }
  put(out, &n, UI_SVC_LINE_DRIVES, 0, v->drives, NULL);
  put(out, &n, UI_SVC_LINE_PROMPTS, 0, v->prompts, NULL);
  put(out, &n, UI_SVC_LINE_PROFILES, 0, v->profiles, NULL);
  return n;
}

ui_svc_repair_mode ui_svc_repair_mode_of(const ui_svc_view *v, int process_elevated, int user_is_admin)
{
  if (v == NULL || !v->valid || !user_is_admin)
    return UI_SVC_REPAIR_OFF;
  return process_elevated ? UI_SVC_REPAIR_RUN : UI_SVC_REPAIR_ELEVATE;
}

int ui_svc_repair_shield(ui_svc_repair_mode mode, int vista_or_later)
{
  return mode == UI_SVC_REPAIR_ELEVATE && vista_or_later ? 1 : 0;
}

ui_svc_repair_route ui_svc_repair_route_of(const ui_svc_view *v)
{
  return v != NULL && v->state == UI_SVC_ST_RUNNING && v->pipe_reachable && v->service_reports ? UI_SVC_ROUTE_PIPE
                                                                                                : UI_SVC_ROUTE_DIRECT;
}

ui_svc_repair_kind ui_svc_repair_kind_of_reply(const sd_json *res)
{
  int moved = 0, healthy = 1;
  (void)sd_json_get_bool(res, "moved", &moved);
  (void)sd_json_get_bool(res, "healthy", &healthy);
  if (moved)
    return UI_SVC_RP_MOVED;
  return healthy ? UI_SVC_RP_DONE : UI_SVC_RP_STILL_REFUSED;
}

ui_svc_repair_kind ui_svc_repair_kind_of_error(const char *code)
{
  if (code == NULL)
    return UI_SVC_RP_FAILED;
  if (strcmp(code, "access_denied") == 0) return UI_SVC_RP_DENIED;
  if (strcmp(code, "busy") == 0) return UI_SVC_RP_BUSY;
  if (strcmp(code, "repair_refused") == 0) return UI_SVC_RP_LINK;
  if (strcmp(code, "usage") == 0 || strcmp(code, "unsupported") == 0 || strcmp(code, "not_implemented") == 0)
    return UI_SVC_RP_UNSUPPORTED;
  return UI_SVC_RP_FAILED;
}

ui_svc_repair_kind ui_svc_repair_kind_of_direct(int refused, unsigned long win32, int moved)
{
  if (refused)
    return UI_SVC_RP_LINK;
  if (win32 != 0)
    return win32 == ERROR_ACCESS_DENIED ? UI_SVC_RP_DENIED : UI_SVC_RP_FAILED;
  return moved ? UI_SVC_RP_MOVED : UI_SVC_RP_DONE;
}
