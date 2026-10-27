/* shelldrive.exe M3 command parsing (03 §6.1): refresh, cache clear, profile test, status --stats, mount --open,
 * and the options that stay limited to their commands. */
#include <windows.h>
#include <string.h>

#include "sd_test.h"
#include "cli.h"
#include "sd_base/sd_mem.h"

static cli_usage_err parse_m3(const wchar_t *cmd, cli_args *a)
{
  int argc = 0;
  wchar_t **argv = NULL;
  /* argv must outlive the parsed pointers: keep the blocks for the test process lifetime */
  static wchar_t **keep[64];
  static int nkeep;
  if (cli_split_cmdline(cmd, &argc, &argv) != SD_OK || argv == NULL)
    return CLI_E_UNKNOWN_COMMAND;
  if (nkeep < 64)
    keep[nkeep++] = argv;
  return cli_parse(argc, argv, a);
}

SD_TEST(cli_parse_m3_commands)
{
  cli_args a;

  /* refresh <X:|PATH>[\sub\path] */
  SD_CHECK(parse_m3(L"sd refresh W:", &a) == CLI_OK);
  SD_CHECK_EQ_INT(a.cmd, CLI_CMD_REFRESH);
  SD_CHECK(wcscmp(a.positional, L"W:") == 0);
  SD_CHECK(parse_m3(L"sd refresh w:\\docs\\x", &a) == CLI_OK);
  SD_CHECK(wcscmp(a.positional, L"w:\\docs\\x") == 0);
  SD_CHECK(parse_m3(L"sd refresh /share", &a) == CLI_E_LETTER);
  SD_CHECK(parse_m3(L"sd refresh", &a) == CLI_E_MISSING_ARGUMENT);
  SD_CHECK(parse_m3(L"sd refresh W: --force", &a) == CLI_E_UNKNOWN_OPTION);

  /* cache clear [<profile>|X:|mount-id] | --all [--force] */
  SD_CHECK(parse_m3(L"sd cache clear --all", &a) == CLI_OK);
  SD_CHECK_EQ_INT(a.cmd, CLI_CMD_CACHE);
  SD_CHECK_EQ_INT(a.all, 1);
  SD_CHECK(parse_m3(L"sd cache clear web --force", &a) == CLI_OK);
  SD_CHECK(wcscmp(a.arg2, L"web") == 0);
  SD_CHECK_EQ_INT(a.force, 1);
  SD_CHECK_EQ_INT(a.all, 0);
  SD_CHECK(parse_m3(L"sd cache clear m-3", &a) == CLI_OK);
  SD_CHECK(wcscmp(a.arg2, L"m-3") == 0);
  SD_CHECK(parse_m3(L"sd cache clear W:", &a) == CLI_OK);
  SD_CHECK(wcscmp(a.arg2, L"W:") == 0);
  SD_CHECK(parse_m3(L"sd cache clear", &a) == CLI_E_MISSING_ARGUMENT);
  SD_CHECK(parse_m3(L"sd cache clear --force", &a) == CLI_E_MISSING_ARGUMENT);
  SD_CHECK(parse_m3(L"sd cache clear web --all", &a) == CLI_E_CONFLICT);
  SD_CHECK(parse_m3(L"sd cache flush web", &a) == CLI_E_UNKNOWN_COMMAND);
  SD_CHECK(parse_m3(L"sd cache clear a b", &a) == CLI_E_EXTRA_ARGUMENT);
  SD_CHECK(parse_m3(L"sd list --force", &a) == CLI_E_UNKNOWN_OPTION);
  SD_CHECK(parse_m3(L"sd unmount --force X:", &a) == CLI_OK);     /* unmount keeps its options */

  /* profile test <profile> */
  SD_CHECK(parse_m3(L"sd profile test web", &a) == CLI_OK);
  SD_CHECK(wcscmp(a.positional, L"test") == 0);
  SD_CHECK(wcscmp(a.arg2, L"web") == 0);
  SD_CHECK(parse_m3(L"sd profile test", &a) == CLI_E_MISSING_ARGUMENT);
  SD_CHECK(parse_m3(L"sd profile test a b", &a) == CLI_E_EXTRA_ARGUMENT);
  SD_CHECK(parse_m3(L"sd profile import putty", &a) == CLI_OK);    /* import keeps working */

  /* status --stats, and the stats alias (status <X:> --stats) */
  SD_CHECK(parse_m3(L"sd status --stats", &a) == CLI_OK);
  SD_CHECK_EQ_INT(a.cmd, CLI_CMD_STATUS);
  SD_CHECK_EQ_INT(a.stats, 1);
  SD_CHECK(parse_m3(L"sd stats W:", &a) == CLI_OK);
  SD_CHECK_EQ_INT(a.cmd, CLI_CMD_STATUS);
  SD_CHECK_EQ_INT(a.stats, 1);
  SD_CHECK(wcscmp(a.positional, L"W:") == 0);
  SD_CHECK(parse_m3(L"sd status W:", &a) == CLI_OK);
  SD_CHECK_EQ_INT(a.stats, 0);
  SD_CHECK(parse_m3(L"sd list --stats", &a) == CLI_E_UNKNOWN_OPTION);

  /* mount --open (the open request), not for the other commands */
  SD_CHECK(parse_m3(L"sd mount web --open", &a) == CLI_OK);
  SD_CHECK_EQ_INT(a.open_after, 1);
  SD_CHECK(parse_m3(L"sd mount web", &a) == CLI_OK);
  SD_CHECK_EQ_INT(a.open_after, 0);
  SD_CHECK(parse_m3(L"sd status --open", &a) == CLI_E_UNKNOWN_OPTION);
  SD_CHECK(parse_m3(L"sd unmount --open X:", &a) == CLI_E_UNKNOWN_OPTION);
}
