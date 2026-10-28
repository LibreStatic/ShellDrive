/* Service status report (03 §6.1 "service status", §2.4 service.status): the facts of `shelldrive service status`
 * and the service-pipe method service.status, in one place so the two stay identical.
 *
 * svc_status_write_members writes the members of the report object into an open JSON object: the CLI wraps it in its
 * own object (--json), the service writes it into the reply of service.status. The words (state, start type, checks)
 * are English identifiers; clients localize by them. Pure: no SCM, pipe or file access here. */
#ifndef SVC_STATUS_H
#define SVC_STATUS_H

#include <windows.h>
#include <stdint.h>

#include "sd_base/sd_json.h"
#include "svc_folder.h"
#include "svc_repair.h"
#include "svc_scm.h"

/* What the running service reports over its pipe. reachable = 0 when the pipe does not answer. */
typedef struct svc_pipe_report {
  int reachable;
  int healthy;                 /* selftest: the machine data folder is trusted (3.2) */
  int64_t drives;              /* global drives: visible ones plus the letters of the others (2.2) */
  int64_t prompts;             /* open administrator prompts, from the content-free attention count (2.6) */
} svc_pipe_report;

/* The machine data folder as the service found it at start (3.2, TM-R34), written by service.status only. */
typedef struct svc_machine_report {
  int ok;                      /* 1 = the layout is trusted, 0 = refused: the service stays idle */
  svc_folder_reason why;       /* the reason when refused */
  wchar_t path[MAX_PATH];      /* the first refused folder; empty for a caller that is not an elevated administrator */
  int64_t profiles;            /* machine profiles loaded */
} svc_machine_report;

const char *svc_status_state_key(DWORD state);           /* running, stopped, starting, stopping, paused, unknown */
const char *svc_status_start_type_key(DWORD start_type); /* automatic, manual, disabled, unknown */
const char *svc_status_path_check_key(int check);        /* ok, unquoted, other, unknown */
const char *svc_status_source_check_key(int check);      /* registered, missing, other, unknown */
const char *svc_status_reason_key(svc_folder_reason why);/* owner, reparse_point, not_directory, acl, not_file, ok */

/* Writes installed, state, start_type, program, event_source, pipe (null when pipe is NULL) and, when machine is not
   NULL, machine {state: ok|refused, reason?, path?, profiles}. jw must be inside an open object. */
void svc_status_write_members(sd_json_writer *jw, const svc_status_report *r, const svc_pipe_report *pipe,
                              const svc_machine_report *machine);

/* Writes the members of a repair-data result: moved, moved_to (null unless moved) and folders. Shared by
   `service repair-data --json` and the service.repair_data reply. jw must be inside an open object. */
void svc_status_write_repair(sd_json_writer *jw, const svc_repair_result *r);

#endif /* SVC_STATUS_H */
