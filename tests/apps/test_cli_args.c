/* shelldrive.exe command-line splitting (MSVC CRT rules) and parsing (03 §6.1). */
#include <windows.h>
#include <string.h>

#include "sd_test.h"
#include "cli.h"
#include "sd_base/sd_mem.h"

static int split_is(const wchar_t *cmd, const wchar_t *const *expect, int n)
{
  int argc = 0, i, ok;
  wchar_t **argv = NULL;
  if (cli_split_cmdline(cmd, &argc, &argv) != SD_OK || argv == NULL)
    return 0;
  ok = argc == n && argv[argc] == NULL;
  for (i = 0; ok && i < n; i++)
    ok = argv[i] != NULL && wcscmp(argv[i], expect[i]) == 0;
  sd_free(argv);
  return ok;
}

SD_TEST(cli_split_follows_msvc_rules)
{
  static const wchar_t *const a[] = { L"C:\\Program Files\\sd.exe", L"mount", L"a b", L"c" };
  static const wchar_t *const b[] = { L"sd", L"a\\\\b", L"x\"y", L"\\\"", L"" };
  static const wchar_t *const c[] = { L"sd", L"a\\b\\", L"ab\"c" };
  static const wchar_t *const d[] = { L"sd" };
  static const wchar_t *const e[] = { L"sd", L"--opt=v w" };
  /* program name: quoted, no escape processing */
  SD_CHECK(split_is(L"\"C:\\Program Files\\sd.exe\" mount \"a b\" c", a, 4));
  /* a\\b stays; x\"y -> x"y; \\\" -> \"; "" -> empty argument */
  SD_CHECK(split_is(L"sd a\\\\b x\\\"y \\\\\\\" \"\"", b, 5));
  /* "a\b\\" -> a\b\ ; "ab""c" -> ab"c */
  SD_CHECK(split_is(L"sd \"a\\b\\\\\" \"ab\"\"c\"", c, 3));
  SD_CHECK(split_is(L"  sd   ", d, 1));
  SD_CHECK(split_is(L"sd \"--opt=v w\"", e, 2));
  SD_CHECK(split_is(L"", NULL, 0));
}

static cli_usage_err parse_line(const wchar_t *cmd, cli_args *a)
{
  int argc = 0;
  wchar_t **argv = NULL;
  /* argv must outlive the parsed pointers: keep the blocks for the test process lifetime */
  static wchar_t **keep[64];
  static int nkeep;
  if (cli_split_cmdline(cmd, &argc, &argv) != SD_OK || argv == NULL)
    return CLI_E_UNKNOWN_COMMAND;
  if (nkeep < 64) keep[nkeep++] = argv;
  return cli_parse(argc, argv, a);
}

SD_TEST(cli_parse_mount_forms)
{
  cli_args a;
  SD_CHECK(parse_line(L"sd mount web", &a) == CLI_OK);
  SD_CHECK_EQ_INT(a.cmd, CLI_CMD_MOUNT);
  SD_CHECK(wcscmp(a.positional, L"web") == 0);
  SD_CHECK(a.letter == 0);
  SD_CHECK(parse_line(L"sd mount --host alice@example.org:2222 --letter z: --identity C:\\k\\id "
                      L"--remote-path /srv --stdin --json", &a) == CLI_OK);
  SD_CHECK(wcscmp(a.host_spec, L"alice@example.org:2222") == 0);
  SD_CHECK(a.letter == L'Z');
  SD_CHECK(wcscmp(a.identity, L"C:\\k\\id") == 0);
  SD_CHECK(wcscmp(a.remote_path, L"/srv") == 0);
  SD_CHECK(a.use_stdin && a.json);
  SD_CHECK(parse_line(L"sd --json mount --host=h --target=Y: --prompt=none --read-only --no-wait", &a) == CLI_OK);
  SD_CHECK(a.letter == L'Y' && a.prompt == CLI_PROMPT_NONE && a.read_only && a.no_wait && a.json);
  SD_CHECK(parse_line(L"sd mount web --letter Q:\\ --prompt console", &a) == CLI_OK);
  SD_CHECK(a.letter == L'Q' && a.prompt == CLI_PROMPT_CONSOLE);
  SD_CHECK(parse_line(L"sd mount -i key --host h", &a) == CLI_OK);
  SD_CHECK(wcscmp(a.identity, L"key") == 0);
}

SD_TEST(cli_parse_errors)
{
  cli_args a;
  SD_CHECK(parse_line(L"sd", &a) == CLI_E_MISSING_ARGUMENT);
  SD_CHECK(parse_line(L"sd frobnicate", &a) == CLI_E_UNKNOWN_COMMAND);
  SD_CHECK(wcscmp(a.bad, L"frobnicate") == 0);
  SD_CHECK(parse_line(L"sd mount", &a) == CLI_E_MISSING_ARGUMENT);
  SD_CHECK(parse_line(L"sd mount web --host h", &a) == CLI_E_CONFLICT);
  SD_CHECK(parse_line(L"sd mount web --identity k", &a) == CLI_E_CONFLICT);
  SD_CHECK(parse_line(L"sd mount --host", &a) == CLI_E_MISSING_VALUE);
  SD_CHECK(wcscmp(a.bad, L"--host") == 0);
  SD_CHECK(parse_line(L"sd mount --host= --letter Z:", &a) == CLI_E_MISSING_VALUE);
  SD_CHECK(parse_line(L"sd mount --host u@ --letter Z:", &a) == CLI_E_HOST_SPEC);
  SD_CHECK(parse_line(L"sd mount --host h --letter C:", &a) == CLI_E_LETTER);
  SD_CHECK(parse_line(L"sd mount --host h --letter ZZ", &a) == CLI_E_LETTER);
  SD_CHECK(parse_line(L"sd mount --host h --prompt maybe", &a) == CLI_E_BAD_VALUE);
  SD_CHECK(parse_line(L"sd mount --host h --bogus", &a) == CLI_E_UNKNOWN_OPTION);
  SD_CHECK(parse_line(L"sd mount web extra", &a) == CLI_E_EXTRA_ARGUMENT);
  SD_CHECK(parse_line(L"sd list --all", &a) == CLI_E_UNKNOWN_OPTION);
  SD_CHECK(parse_line(L"sd --letter Z: list", &a) == CLI_E_UNKNOWN_OPTION);   /* mount option, other command */
  SD_CHECK(parse_line(L"sd unmount", &a) == CLI_E_MISSING_ARGUMENT);
  SD_CHECK(parse_line(L"sd unmount Z: --all", &a) == CLI_E_CONFLICT);
  SD_CHECK(parse_line(L"sd --json=1 list", &a) == CLI_E_BAD_VALUE);
  SD_CHECK(parse_line(L"sd agent", &a) == CLI_E_MISSING_ARGUMENT);
  SD_CHECK(parse_line(L"sd agent start", &a) == CLI_E_UNKNOWN_COMMAND);
  SD_CHECK(parse_line(L"sd list extra", &a) == CLI_E_EXTRA_ARGUMENT);
  SD_CHECK(parse_line(L"sd -- list", &a) == CLI_E_UNKNOWN_OPTION);
}

SD_TEST(cli_parse_other_commands)
{
  cli_args a;
  SD_CHECK(parse_line(L"sd --version", &a) == CLI_OK && a.cmd == CLI_CMD_VERSION);
  SD_CHECK(parse_line(L"sd version --json", &a) == CLI_OK && a.cmd == CLI_CMD_VERSION && a.json);
  SD_CHECK(parse_line(L"sd --help", &a) == CLI_OK && a.help);
  SD_CHECK(parse_line(L"sd /?", &a) == CLI_OK && a.help);
  SD_CHECK(parse_line(L"sd help mount", &a) == CLI_OK && a.cmd == CLI_CMD_HELP && wcscmp(a.positional, L"mount") == 0);
  SD_CHECK(parse_line(L"sd mount --help", &a) == CLI_OK && a.help && a.cmd == CLI_CMD_MOUNT);
  SD_CHECK(parse_line(L"sd unmount Z:", &a) == CLI_OK && a.cmd == CLI_CMD_UNMOUNT && wcscmp(a.positional, L"Z:") == 0);
  SD_CHECK(parse_line(L"sd umount --all --force", &a) == CLI_OK && a.all && a.force);
  SD_CHECK(parse_line(L"sd list --json --lang es -q", &a) == CLI_OK && a.cmd == CLI_CMD_LIST && a.quiet &&
           wcscmp(a.lang, L"es") == 0);
  SD_CHECK(parse_line(L"sd agent stop", &a) == CLI_OK && a.cmd == CLI_CMD_AGENT_STOP);
}
