/* CLI smoke tests over the real service pipe (tests/e2e, docs/dev/m5-notes.md part 13).
   Each test starts sd-test-cli.exe as a child process; the CLI connects to the service core that this process hosts
   (e2e_host.c) and the test checks its exit code, its output and, where it matters, the service's stores. One core runs
   for the file: the last test stops it and checks that the CLI no longer reaches the pipe.

   Elevation is the CLI's own check (cli_is_elevated): "0" denies a command, "1" grants it. The service side is always
   an administrator (svc_test_connect_admin), so a denial comes from the CLI and nothing else. */
#include <windows.h>
#include <string.h>
#include <stdio.h>

#include "sd_test.h"
#include "e2e_host.h"

static int has(const char *s, const char *needle)
{
  return strstr(s, needle) != NULL;
}

SD_TEST(e2e_status_reaches_the_service_over_the_pipe)
{
  e2e_cli_result r;
  SD_REQUIRE(e2e_core_start());
  SD_REQUIRE(e2e_run_cli(L"--json service status", NULL, L"running", NULL, &r));
  SD_CHECK_EQ_INT(r.exit_code, 0);
  SD_CHECK(has(r.out, "\"reachable\":true"));
  SD_CHECK(has(r.out, "\"healthy\":true"));
}

SD_TEST(e2e_status_without_an_installed_service_does_not_query_the_pipe)
{
  e2e_cli_result r;
  SD_REQUIRE(e2e_core_start());
  SD_REQUIRE(e2e_run_cli(L"--json service status", NULL, L"absent", NULL, &r));
  SD_CHECK_EQ_INT(r.exit_code, 0);
  SD_CHECK(!has(r.out, "\"reachable\""));
}

SD_TEST(e2e_service_mount_and_unmount_need_elevation)
{
  e2e_cli_result r;
  SD_REQUIRE(e2e_core_start());
  /* a denied mount never reaches the service */
  SD_REQUIRE(e2e_run_cli(L"service mount mounted", L"0", NULL, NULL, &r));
  SD_CHECK_EQ_INT(r.exit_code, 9);
  SD_REQUIRE(e2e_run_cli(L"service mount mounted", L"1", NULL, NULL, &r));
  SD_CHECK_EQ_INT(r.exit_code, 0);
  SD_REQUIRE(e2e_run_cli(L"--json service status mounted", NULL, NULL, NULL, &r));
  SD_CHECK_EQ_INT(r.exit_code, 0);
  SD_CHECK(has(r.out, "\"state\":\"mounted\""));
  /* a denied unmount leaves the drive up; a granted one takes it down */
  SD_REQUIRE(e2e_run_cli(L"service unmount mounted", L"0", NULL, NULL, &r));
  SD_CHECK_EQ_INT(r.exit_code, 9);
  SD_REQUIRE(e2e_run_cli(L"--json service status mounted", NULL, NULL, NULL, &r));
  SD_CHECK(has(r.out, "\"state\":\"mounted\""));
  SD_REQUIRE(e2e_run_cli(L"service unmount mounted", L"1", NULL, NULL, &r));
  SD_CHECK_EQ_INT(r.exit_code, 0);
}

SD_TEST(e2e_hostkey_offer_is_listed_and_accepted_into_the_machine_store)
{
  e2e_cli_result r;
  char id[64] = "";
  wchar_t args[256];
  unsigned long before;
  SD_REQUIRE(e2e_core_start());

  /* without elevation nothing is offered and the machine store is not touched */
  before = e2e_machine_writes();
  SD_REQUIRE(e2e_run_cli(L"hostkey add --from-server hk.first.test --machine", L"0", NULL, NULL, &r));
  SD_CHECK_EQ_INT(r.exit_code, 9);
  SD_REQUIRE(e2e_run_cli(L"hostkey list --announced --machine", L"0", NULL, NULL, &r));
  SD_CHECK_EQ_INT(r.exit_code, 9);

  /* the elevated offer, in JSON so that no answer is asked for: the offer waits in the service, nothing is stored */
  SD_REQUIRE(e2e_run_cli(L"--json hostkey add --from-server hk.first.test --machine", L"1", NULL, NULL, &r));
  SD_CHECK_EQ_INT(r.exit_code, 0);
  SD_REQUIRE(e2e_json_id(r.out, id, sizeof(id)));
  SD_CHECK(e2e_machine_writes() == before);

  SD_REQUIRE(e2e_run_cli(L"--json hostkey list --announced --machine", L"1", NULL, NULL, &r));
  SD_CHECK_EQ_INT(r.exit_code, 0);
  SD_CHECK(has(r.out, id));

  _snwprintf_s(args, SD_COUNTOF(args), _TRUNCATE, L"hostkey accept-announced %S --add-only --machine", id);
  SD_REQUIRE(e2e_run_cli(args, L"1", NULL, NULL, &r));
  SD_CHECK_EQ_INT(r.exit_code, 0);
  SD_CHECK(e2e_machine_writes() == before + 1);

  /* taken out of the list, and a second accept finds nothing */
  SD_REQUIRE(e2e_run_cli(L"--json hostkey list --announced --machine", L"1", NULL, NULL, &r));
  SD_CHECK(!has(r.out, id));
  SD_REQUIRE(e2e_run_cli(args, L"1", NULL, NULL, &r));
  SD_CHECK(r.exit_code != 0);
  SD_CHECK(e2e_machine_writes() == before + 1);
}

SD_TEST(e2e_secret_set_and_delete_machine_proxy_through_the_service)
{
  e2e_cli_result r;
  char pw[64];
  int found = 0;
  SD_REQUIRE(e2e_core_start());
  SD_REQUIRE(e2e_run_cli(L"secret set --machine --proxy http://px@proxy.example:3128 --stdin", L"0", NULL, "pxpw\n", &r));
  SD_CHECK_EQ_INT(r.exit_code, 9);
  SD_REQUIRE(e2e_secret_proxy_get("px", pw, sizeof(pw), &found));
  SD_CHECK(!found);

  SD_REQUIRE(e2e_run_cli(L"secret set --machine --proxy http://px@proxy.example:3128 --stdin", L"1", NULL, "pxpw\n", &r));
  SD_CHECK_EQ_INT(r.exit_code, 0);
  SD_CHECK(!has(r.out, "pxpw"));                     /* the password is never printed */
  SD_REQUIRE(e2e_secret_proxy_get("px", pw, sizeof(pw), &found));
  SD_REQUIRE(found);
  SD_CHECK(strcmp(pw, "pxpw") == 0);

  SD_REQUIRE(e2e_run_cli(L"secret delete --machine --proxy http://px@proxy.example:3128", L"1", NULL, NULL, &r));
  SD_CHECK_EQ_INT(r.exit_code, 0);
  SD_REQUIRE(e2e_secret_proxy_get("px", pw, sizeof(pw), &found));
  SD_CHECK(!found);
}

SD_TEST(e2e_core_stops_and_the_cli_no_longer_reaches_the_pipe)
{
  e2e_cli_result r;
  SD_REQUIRE(e2e_core_stop());
  SD_REQUIRE(e2e_run_cli(L"--json service status", NULL, L"running", NULL, &r));
  SD_CHECK_EQ_INT(r.exit_code, 0);
  SD_CHECK(has(r.out, "\"reachable\":false"));
}
