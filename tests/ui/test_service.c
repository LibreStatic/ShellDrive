/* The Service page model (apps/shelldrive-ui/ui_service_model.c, ui_wire.c): the view built from the service.status
   reply or from the SCM report, the lines the page shows, when "Repair data..." is enabled and with the UAC shield,
   where the repair runs, and how its results are classified. Pure: no window, pipe, SCM or token call. */
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>

#include "sd_test.h"
#include "ui_service_model.h"
#include "ui_wire.h"

static sd_json *parse_text(const char *text)
{
  sd_json *root = NULL;
  if (sd_json_parse(text, strlen(text), 32, &root) != SD_OK)
    return NULL;
  return root;
}

static const char k_running_ok[] =
    "{\"installed\":true,\"state\":\"running\",\"start_type\":\"automatic\","
    "\"program\":{\"path\":\"\\\"C:\\\\ShellDrive\\\\shelldrive-host.exe\\\" service\",\"check\":\"ok\"},"
    "\"event_source\":{\"state\":\"registered\",\"message_file\":\"C:\\\\ShellDrive\\\\shelldrive-host.exe\"},"
    "\"pipe\":{\"reachable\":true,\"healthy\":true,\"global_drives\":2,\"prompts\":1},"
    "\"machine\":{\"state\":\"ok\",\"profiles\":3}}";

static const char k_running_refused[] =
    "{\"installed\":true,\"state\":\"running\",\"start_type\":\"automatic\","
    "\"program\":{\"path\":\"C:\\\\x\\\\h.exe\",\"check\":\"other\"},"
    "\"event_source\":{\"state\":\"missing\",\"message_file\":\"\"},"
    "\"pipe\":{\"reachable\":true,\"healthy\":false,\"global_drives\":0,\"prompts\":0},"
    "\"machine\":{\"state\":\"refused\",\"reason\":\"owner\",\"path\":\"C:\\\\ProgramData\\\\LibreStatic\",\"profiles\":0}}";

static size_t kinds_of(const ui_svc_view *v, ui_svc_line_kind *out, size_t cap)
{
  ui_svc_line lines[UI_SVC_LINES_MAX];
  size_t n = ui_svc_lines(v, lines), i;
  for (i = 0; i < n && i < cap; i++)
    out[i] = lines[i].kind;
  return n;
}

SD_TEST(service_view_reads_the_status_reply)
{
  sd_json *j = parse_text(k_running_ok);
  ui_svc_view v;
  SD_REQUIRE(j != NULL);
  SD_CHECK(ui_svc_view_from_status(&v, j) == SD_OK);
  SD_CHECK(v.valid);
  SD_CHECK(v.state == UI_SVC_ST_RUNNING);
  SD_CHECK(v.start == UI_SVC_START_AUTOMATIC);
  SD_CHECK(v.program_check == UI_SVC_PROGRAM_OK);
  SD_CHECK(v.source_check == UI_SVC_SOURCE_OK);
  SD_CHECK(wcsstr(v.program, L"shelldrive-host.exe") != NULL);
  SD_CHECK(v.pipe_reachable && v.service_reports && v.healthy);
  SD_CHECK_EQ_INT(v.drives, 2);
  SD_CHECK_EQ_INT(v.prompts, 1);
  SD_CHECK_EQ_INT(v.profiles, 3);
  SD_CHECK(v.machine == UI_SVC_MACHINE_OK);
  sd_json_free(j);

  j = parse_text(k_running_refused);
  SD_REQUIRE(j != NULL);
  SD_CHECK(ui_svc_view_from_status(&v, j) == SD_OK);
  SD_CHECK(v.machine == UI_SVC_MACHINE_REFUSED);
  SD_CHECK(v.reason == UI_SVC_REASON_OWNER);
  SD_CHECK(!v.healthy);
  SD_CHECK(v.program_check == UI_SVC_PROGRAM_OTHER);
  SD_CHECK(v.source_check == UI_SVC_SOURCE_MISSING);
  SD_CHECK(wcscmp(v.machine_path, L"C:\\ProgramData\\LibreStatic") == 0);
  sd_json_free(j);
}

SD_TEST(service_view_maps_every_refusal_reason)
{
  static const struct { const char *word; ui_svc_reason reason; } k[] = {
    { "owner", UI_SVC_REASON_OWNER }, { "reparse_point", UI_SVC_REASON_LINK }, { "acl", UI_SVC_REASON_ACL },
    { "not_directory", UI_SVC_REASON_OTHER }, { "not_file", UI_SVC_REASON_OTHER }, { "weird", UI_SVC_REASON_OTHER }
  };
  size_t i;
  for (i = 0; i < sizeof(k) / sizeof(k[0]); i++) {
    char text[512];
    sd_json *j;
    ui_svc_view v;
    _snprintf_s(text, sizeof(text), _TRUNCATE,
                "{\"installed\":true,\"state\":\"running\",\"start_type\":\"manual\",\"pipe\":{\"reachable\":true,"
                "\"healthy\":false,\"global_drives\":0,\"prompts\":0},\"machine\":{\"state\":\"refused\","
                "\"reason\":\"%s\",\"profiles\":0}}", k[i].word);
    j = parse_text(text);
    SD_REQUIRE(j != NULL);
    SD_CHECK(ui_svc_view_from_status(&v, j) == SD_OK);
    SD_CHECK(v.reason == k[i].reason);
    SD_CHECK(v.machine_path[0] == 0);          /* a caller that is not an elevated administrator gets no path */
    sd_json_free(j);
  }
}

SD_TEST(service_view_rejects_a_bad_reply)
{
  sd_json *j;
  ui_svc_view v;
  SD_CHECK(ui_svc_view_from_status(&v, NULL) == SD_E_INVALID_PARAM);
  SD_CHECK(!v.valid);
  j = parse_text("[1]");
  SD_REQUIRE(j != NULL);
  SD_CHECK(ui_svc_view_from_status(&v, j) == SD_E_INVALID_PARAM);
  sd_json_free(j);
  j = parse_text("{\"state\":\"running\"}");
  SD_REQUIRE(j != NULL);
  SD_CHECK(ui_svc_view_from_status(&v, j) == SD_E_INVALID_PARAM);
  SD_CHECK(!v.valid);
  sd_json_free(j);
  /* unknown words fall back to the unknown values */
  j = parse_text("{\"installed\":true,\"state\":\"melting\",\"start_type\":\"sometimes\"}");
  SD_REQUIRE(j != NULL);
  SD_CHECK(ui_svc_view_from_status(&v, j) == SD_OK);
  SD_CHECK(v.state == UI_SVC_ST_UNKNOWN && v.start == UI_SVC_START_UNKNOWN);
  sd_json_free(j);
}

SD_TEST(service_view_from_the_scm_alone)
{
  ui_svc_view v;
  ui_svc_view_from_scm(&v, 0, 0, 0, 0, UI_SVC_SOURCE_MISSING, NULL);
  SD_CHECK(v.valid && v.state == UI_SVC_ST_NOT_INSTALLED && v.start == UI_SVC_START_NONE);
  SD_CHECK(v.source_check == UI_SVC_SOURCE_MISSING);
  SD_CHECK(!v.pipe_reachable && !v.service_reports);

  ui_svc_view_from_scm(&v, 1, SERVICE_STOPPED, SERVICE_DEMAND_START, UI_SVC_PROGRAM_UNQUOTED, UI_SVC_SOURCE_OTHER,
                       L"C:\\x\\h.exe service");
  SD_CHECK(v.state == UI_SVC_ST_STOPPED && v.start == UI_SVC_START_MANUAL);
  SD_CHECK(v.program_check == UI_SVC_PROGRAM_UNQUOTED && v.source_check == UI_SVC_SOURCE_OTHER);
  SD_CHECK(wcscmp(v.program, L"C:\\x\\h.exe service") == 0);

  ui_svc_view_from_scm(&v, 1, SERVICE_START_PENDING, SERVICE_AUTO_START, 99, -3, L"p");
  SD_CHECK(v.state == UI_SVC_ST_STARTING && v.start == UI_SVC_START_AUTOMATIC);
  SD_CHECK(v.program_check == UI_SVC_PROGRAM_UNKNOWN && v.source_check == UI_SVC_SOURCE_UNKNOWN);

  ui_svc_view_from_scm(&v, 1, SERVICE_PAUSED, SERVICE_DISABLED, UI_SVC_PROGRAM_OK, UI_SVC_SOURCE_OK, L"p");
  SD_CHECK(v.state == UI_SVC_ST_PAUSED && v.start == UI_SVC_START_DISABLED);
  ui_svc_view_from_scm(&v, 1, 0x7777, 0x7777, UI_SVC_PROGRAM_OK, UI_SVC_SOURCE_OK, L"p");
  SD_CHECK(v.state == UI_SVC_ST_UNKNOWN && v.start == UI_SVC_START_UNKNOWN);
}

SD_TEST(service_lines_follow_the_state)
{
  ui_svc_view v;
  ui_svc_line_kind k[UI_SVC_LINES_MAX];
  ui_svc_line lines[UI_SVC_LINES_MAX];
  size_t n;
  sd_json *j;

  ui_svc_view_init(&v);
  SD_CHECK_EQ_INT(ui_svc_lines(&v, lines), 0);              /* no status yet */

  /* not installed: the message and the Event Log source only */
  ui_svc_view_from_scm(&v, 0, 0, 0, 0, UI_SVC_SOURCE_MISSING, NULL);
  n = kinds_of(&v, k, UI_SVC_LINES_MAX);
  SD_CHECK_EQ_INT(n, 2);
  SD_CHECK(k[0] == UI_SVC_LINE_NOT_INSTALLED && k[1] == UI_SVC_LINE_SOURCE_CHECK);

  /* installed and stopped: no pipe lines */
  ui_svc_view_from_scm(&v, 1, SERVICE_STOPPED, SERVICE_AUTO_START, UI_SVC_PROGRAM_OK, UI_SVC_SOURCE_OK, L"p");
  n = kinds_of(&v, k, UI_SVC_LINES_MAX);
  SD_CHECK_EQ_INT(n, 5);
  SD_CHECK(k[0] == UI_SVC_LINE_STATE && k[1] == UI_SVC_LINE_START && k[2] == UI_SVC_LINE_PROGRAM);
  SD_CHECK(k[3] == UI_SVC_LINE_PROGRAM_CHECK && k[4] == UI_SVC_LINE_SOURCE_CHECK);

  /* running, the pipe does not answer */
  ui_svc_view_from_scm(&v, 1, SERVICE_RUNNING, SERVICE_AUTO_START, UI_SVC_PROGRAM_OK, UI_SVC_SOURCE_OK, L"p");
  n = kinds_of(&v, k, UI_SVC_LINES_MAX);
  SD_CHECK_EQ_INT(n, 6);
  SD_CHECK(k[5] == UI_SVC_LINE_PIPE_DOWN);

  /* running, the pipe answers but the service is too old for service.status */
  v.pipe_reachable = 1;
  n = kinds_of(&v, k, UI_SVC_LINES_MAX);
  SD_CHECK_EQ_INT(n, 6);
  SD_CHECK(k[5] == UI_SVC_LINE_OLD_SERVICE);

  /* running and in order */
  j = parse_text(k_running_ok);
  SD_REQUIRE(j != NULL);
  SD_CHECK(ui_svc_view_from_status(&v, j) == SD_OK);
  sd_json_free(j);
  n = ui_svc_lines(&v, lines);
  SD_CHECK_EQ_INT(n, 9);
  SD_CHECK(lines[5].kind == UI_SVC_LINE_MACHINE_OK);
  SD_CHECK(lines[6].kind == UI_SVC_LINE_DRIVES && lines[6].count == 2);
  SD_CHECK(lines[7].kind == UI_SVC_LINE_PROMPTS && lines[7].count == 1);
  SD_CHECK(lines[8].kind == UI_SVC_LINE_PROFILES && lines[8].count == 3);

  /* running and refused: the reason and the folder (when the caller got it) */
  j = parse_text(k_running_refused);
  SD_REQUIRE(j != NULL);
  SD_CHECK(ui_svc_view_from_status(&v, j) == SD_OK);
  sd_json_free(j);
  n = ui_svc_lines(&v, lines);
  SD_CHECK_EQ_INT(n, 10);
  SD_CHECK(lines[5].kind == UI_SVC_LINE_MACHINE_REFUSED && lines[5].which == (int)UI_SVC_REASON_OWNER);
  SD_CHECK(lines[6].kind == UI_SVC_LINE_MACHINE_PATH && wcscmp(lines[6].text, L"C:\\ProgramData\\LibreStatic") == 0);
  v.machine_path[0] = 0;
  SD_CHECK_EQ_INT(ui_svc_lines(&v, lines), 9);              /* no path line without the path */
}

SD_TEST(service_repair_is_for_administrators_only)
{
  ui_svc_view v;
  ui_svc_view_init(&v);
  /* no status yet: off for everyone */
  SD_CHECK(ui_svc_repair_mode_of(&v, 1, 1) == UI_SVC_REPAIR_OFF);
  ui_svc_view_from_scm(&v, 1, SERVICE_RUNNING, SERVICE_AUTO_START, UI_SVC_PROGRAM_OK, UI_SVC_SOURCE_OK, L"p");
  /* not an administrator: off, elevated or not */
  SD_CHECK(ui_svc_repair_mode_of(&v, 0, 0) == UI_SVC_REPAIR_OFF);
  SD_CHECK(ui_svc_repair_mode_of(&v, 1, 0) == UI_SVC_REPAIR_OFF);
  /* an administrator without the elevated token: the shield and the relaunch */
  SD_CHECK(ui_svc_repair_mode_of(&v, 0, 1) == UI_SVC_REPAIR_ELEVATE);
  /* an elevated administrator runs it */
  SD_CHECK(ui_svc_repair_mode_of(&v, 1, 1) == UI_SVC_REPAIR_RUN);
  /* the same without a service: the folder can still be repaired */
  ui_svc_view_from_scm(&v, 0, 0, 0, 0, UI_SVC_SOURCE_MISSING, NULL);
  SD_CHECK(ui_svc_repair_mode_of(&v, 1, 1) == UI_SVC_REPAIR_RUN);
  SD_CHECK(ui_svc_repair_mode_of(&v, 0, 1) == UI_SVC_REPAIR_ELEVATE);
  SD_CHECK(ui_svc_repair_mode_of(&v, 0, 0) == UI_SVC_REPAIR_OFF);
}

SD_TEST(service_repair_shield_only_on_vista_and_later)
{
  SD_CHECK(ui_svc_repair_shield(UI_SVC_REPAIR_ELEVATE, 1));
  SD_CHECK(!ui_svc_repair_shield(UI_SVC_REPAIR_ELEVATE, 0));       /* XP has no UAC */
  SD_CHECK(!ui_svc_repair_shield(UI_SVC_REPAIR_RUN, 1));
  SD_CHECK(!ui_svc_repair_shield(UI_SVC_REPAIR_OFF, 1));
}

SD_TEST(service_repair_route_follows_the_pipe)
{
  ui_svc_view v;
  sd_json *j;
  ui_svc_view_from_scm(&v, 1, SERVICE_RUNNING, SERVICE_AUTO_START, UI_SVC_PROGRAM_OK, UI_SVC_SOURCE_OK, L"p");
  SD_CHECK(ui_svc_repair_route_of(&v) == UI_SVC_ROUTE_DIRECT);     /* the pipe does not answer */
  v.pipe_reachable = 1;
  SD_CHECK(ui_svc_repair_route_of(&v) == UI_SVC_ROUTE_DIRECT);     /* an older service without the method */
  j = parse_text(k_running_ok);
  SD_REQUIRE(j != NULL);
  SD_CHECK(ui_svc_view_from_status(&v, j) == SD_OK);
  sd_json_free(j);
  SD_CHECK(ui_svc_repair_route_of(&v) == UI_SVC_ROUTE_PIPE);
  ui_svc_view_from_scm(&v, 1, SERVICE_STOPPED, SERVICE_AUTO_START, UI_SVC_PROGRAM_OK, UI_SVC_SOURCE_OK, L"p");
  SD_CHECK(ui_svc_repair_route_of(&v) == UI_SVC_ROUTE_DIRECT);
  SD_CHECK(ui_svc_repair_route_of(NULL) == UI_SVC_ROUTE_DIRECT);
}

SD_TEST(service_repair_results_are_classified)
{
  sd_json *j;
  j = parse_text("{\"moved\":false,\"moved_to\":null,\"folders\":9,\"healthy\":true}");
  SD_REQUIRE(j != NULL);
  SD_CHECK(ui_svc_repair_kind_of_reply(j) == UI_SVC_RP_DONE);
  sd_json_free(j);
  j = parse_text("{\"moved\":true,\"moved_to\":\"C:\\\\x\",\"folders\":9,\"healthy\":false}");
  SD_REQUIRE(j != NULL);
  SD_CHECK(ui_svc_repair_kind_of_reply(j) == UI_SVC_RP_MOVED);      /* a moved folder wins */
  sd_json_free(j);
  j = parse_text("{\"moved\":false,\"folders\":9,\"healthy\":false}");
  SD_REQUIRE(j != NULL);
  SD_CHECK(ui_svc_repair_kind_of_reply(j) == UI_SVC_RP_STILL_REFUSED);
  sd_json_free(j);
  j = parse_text("{\"moved\":false,\"folders\":9}");                 /* the CLI shape: no healthy member */
  SD_REQUIRE(j != NULL);
  SD_CHECK(ui_svc_repair_kind_of_reply(j) == UI_SVC_RP_DONE);
  sd_json_free(j);

  SD_CHECK(ui_svc_repair_kind_of_error("access_denied") == UI_SVC_RP_DENIED);
  SD_CHECK(ui_svc_repair_kind_of_error("busy") == UI_SVC_RP_BUSY);
  SD_CHECK(ui_svc_repair_kind_of_error("repair_refused") == UI_SVC_RP_LINK);
  SD_CHECK(ui_svc_repair_kind_of_error("usage") == UI_SVC_RP_UNSUPPORTED);
  SD_CHECK(ui_svc_repair_kind_of_error("io_error") == UI_SVC_RP_FAILED);
  SD_CHECK(ui_svc_repair_kind_of_error(NULL) == UI_SVC_RP_FAILED);

  SD_CHECK(ui_svc_repair_kind_of_direct(1, ERROR_ACCESS_DENIED, 0) == UI_SVC_RP_LINK);   /* refused wins */
  SD_CHECK(ui_svc_repair_kind_of_direct(0, ERROR_ACCESS_DENIED, 0) == UI_SVC_RP_DENIED);
  SD_CHECK(ui_svc_repair_kind_of_direct(0, ERROR_PATH_NOT_FOUND, 0) == UI_SVC_RP_FAILED);
  SD_CHECK(ui_svc_repair_kind_of_direct(0, 0, 1) == UI_SVC_RP_MOVED);
  SD_CHECK(ui_svc_repair_kind_of_direct(0, 0, 0) == UI_SVC_RP_DONE);
}

SD_TEST(service_elevated_verb_is_exact)
{
  static const wchar_t *const ok[] = { L"--elevated-service" };
  static const wchar_t *const extra[] = { L"--elevated-service", L"x" };
  static const wchar_t *const nearby[] = { L"--elevated-services" };
  static const wchar_t *const admin[] = { L"--elevated-admin" };
  ui_request req;
  SD_CHECK(ui_request_from_args(1, ok, &req) == SD_OK);
  SD_CHECK(req.verb == UI_VERB_ELEVATED_SERVICE);
  SD_CHECK(ui_request_from_args(2, extra, &req) != SD_OK);
  SD_CHECK(ui_request_from_args(1, nearby, &req) != SD_OK);
  SD_CHECK(ui_request_from_args(1, admin, &req) == SD_OK);
  SD_CHECK(req.verb == UI_VERB_ELEVATED_ADMIN);                 /* the two modes stay apart */
}
