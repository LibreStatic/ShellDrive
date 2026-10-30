/* Service status report: see svc_status.h. Pure. */
#include <windows.h>
#include <string.h>

#include "svc_status.h"

static void utf8_of(const wchar_t *w, char *out, size_t cch)
{
  out[0] = 0;
  if (w && w[0])
    WideCharToMultiByte(CP_UTF8, 0, w, -1, out, (int)cch, NULL, NULL);
  out[cch - 1] = 0;
}

const char *svc_status_state_key(DWORD st)
{
  switch (st) {
  case SERVICE_RUNNING: return "running";
  case SERVICE_STOPPED: return "stopped";
  case SERVICE_START_PENDING: return "starting";
  case SERVICE_STOP_PENDING: return "stopping";
  case SERVICE_PAUSED: return "paused";
  default: return "unknown";
  }
}

const char *svc_status_start_type_key(DWORD t)
{
  switch (t) {
  case SERVICE_AUTO_START: return "automatic";
  case SERVICE_DEMAND_START: return "manual";
  case SERVICE_DISABLED: return "disabled";
  default: return "unknown";
  }
}

const char *svc_status_path_check_key(int c)
{
  switch (c) {
  case SVC_PATH_OK: return "ok";
  case SVC_PATH_UNQUOTED: return "unquoted";
  case SVC_PATH_OTHER: return "other";
  default: return "unknown";
  }
}

const char *svc_status_source_check_key(int c)
{
  switch (c) {
  case SVC_SRC_OK: return "registered";
  case SVC_SRC_MISSING: return "missing";
  case SVC_SRC_OTHER: return "other";
  default: return "unknown";
  }
}

const char *svc_status_reason_key(svc_folder_reason why)
{
  switch (why) {
  case SVC_FOLDER_OWNER: return "owner";
  case SVC_FOLDER_REPARSE: return "reparse_point";
  case SVC_FOLDER_KIND: return "not_directory";
  case SVC_FOLDER_NO_RIGHTS: return "acl";
  case SVC_FOLDER_ACL: return "acl";
  case SVC_FOLDER_NOT_FILE: return "not_file";
  default: return "ok";
  }
}

void svc_status_write_members(sd_json_writer *jw, const svc_status_report *r, const svc_pipe_report *p,
                              const svc_machine_report *m)
{
  char path[1600], message_file[1600];
  utf8_of(r->binary, path, sizeof(path));
  utf8_of(r->message_file, message_file, sizeof(message_file));
  sd_jw_key(jw, "installed");
  sd_jw_bool(jw, r->installed);
  sd_jw_key(jw, "state");
  sd_jw_cstr(jw, r->installed ? svc_status_state_key(r->state) : "not_installed");
  sd_jw_key(jw, "start_type");
  if (r->installed) sd_jw_cstr(jw, svc_status_start_type_key(r->start_type)); else sd_jw_null(jw);
  sd_jw_key(jw, "program");
  if (r->installed) {
    sd_jw_obj_begin(jw);
    sd_jw_key(jw, "path");
    sd_jw_cstr(jw, path);
    sd_jw_key(jw, "check");
    sd_jw_cstr(jw, svc_status_path_check_key(r->binary_check));
    sd_jw_obj_end(jw);
  } else {
    sd_jw_null(jw);
  }
  sd_jw_key(jw, "event_source");
  sd_jw_obj_begin(jw);
  sd_jw_key(jw, "state");
  sd_jw_cstr(jw, svc_status_source_check_key(r->source_check));
  sd_jw_key(jw, "message_file");
  sd_jw_cstr(jw, message_file);
  sd_jw_obj_end(jw);
  sd_jw_key(jw, "pipe");
  if (p != NULL) {
    sd_jw_obj_begin(jw);
    sd_jw_key(jw, "reachable");
    sd_jw_bool(jw, p->reachable);
    sd_jw_key(jw, "healthy");
    sd_jw_bool(jw, p->healthy);
    sd_jw_key(jw, "global_drives");
    sd_jw_int(jw, p->drives);
    sd_jw_key(jw, "prompts");
    sd_jw_int(jw, p->prompts);
    sd_jw_obj_end(jw);
  } else {
    sd_jw_null(jw);
  }
  if (m != NULL) {
    sd_jw_key(jw, "machine");
    sd_jw_obj_begin(jw);
    sd_jw_key(jw, "state");
    sd_jw_cstr(jw, m->ok ? "ok" : "refused");
    if (!m->ok) {
      sd_jw_key(jw, "reason");
      sd_jw_cstr(jw, svc_status_reason_key(m->why));
      if (m->path[0] != 0) {
        char refused[1600];
        utf8_of(m->path, refused, sizeof(refused));
        sd_jw_key(jw, "path");
        sd_jw_cstr(jw, refused);
      }
    }
    sd_jw_key(jw, "profiles");
    sd_jw_int(jw, m->profiles);
    sd_jw_obj_end(jw);
  }
}

void svc_status_write_repair(sd_json_writer *jw, const svc_repair_result *r)
{
  char moved_to[1600];
  utf8_of(r->path, moved_to, sizeof(moved_to));
  sd_jw_key(jw, "moved");
  sd_jw_bool(jw, r->moved);
  sd_jw_key(jw, "moved_to");
  if (r->moved) sd_jw_cstr(jw, moved_to); else sd_jw_null(jw);
  sd_jw_key(jw, "folders");
  sd_jw_int(jw, (int64_t)r->folders);
}
