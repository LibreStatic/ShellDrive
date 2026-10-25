/* shelldrive.exe: the command-line interface (03 §1.5, §6). Thin client of the agent over IPC.
 * The command line is split by our own parser over GetCommandLineW (MSVC CRT rules, no shell32
 * dependency); output follows 03 §6.4; exit codes follow 03 §6.2. */
#include <windows.h>
#include <string.h>

#include "cli.h"
#include "sd_base/sd_mem.h"
#include "sd_config/sd_config.h"
#include "sd_ipc/sd_ipc.h"
#include "sd_l10n/sd_l10n.h"
#include "sd_l10n_cli_ids.h"
#include "sd_platform/sd_platform.h"

#ifdef SD_CLI_TEST_HOOKS
/* Test builds only (tests/apps): isolated pipe names, configuration root and agent executable. */
static void apply_test_hooks(void)
{
  wchar_t v[MAX_PATH];
  if (GetEnvironmentVariableW(L"SHELLDRIVE_TEST_INSTANCE", v, MAX_PATH) - 1u < MAX_PATH - 1u)
    sd_ipc_set_instance_suffix(v);
  if (GetEnvironmentVariableW(L"SHELLDRIVE_TEST_CONFIG_DIR", v, MAX_PATH) - 1u < MAX_PATH - 1u)
    sd_config_set_root_override(v);
  if (GetEnvironmentVariableW(L"SHELLDRIVE_TEST_HOST_EXE", v, MAX_PATH) - 1u < MAX_PATH - 1u)
    sd_ipc_set_agent_path(v);
}
#endif

static void say2(sd_msg_id id, const char *n1, const wchar_t *v1, const char *n2, const wchar_t *v2)
{
  sd_arg args[2];
  wchar_t *s;
  args[0].name = n1; args[0].type = SD_ARG_STR; args[0].v.s = v1 ? v1 : L"";
  args[1].name = n2; args[1].type = SD_ARG_STR; args[1].v.s = v2 ? v2 : L"";
  s = sd_l10n_format_alloc(id, args, n2 ? 2 : 1);
  if (s) {
    cli_eprint(s);
    sd_free(s);
  }
}

static int usage_error(const cli_args *a)
{
  const wchar_t *cmd = a->cmd_name ? a->cmd_name : L"";
  if (a->json) {
    static const char k[] = "{\"ok\":false,\"error\":{\"code\":\"usage\",\"detail\":\"invalid command line\",\"exit_code\":2}}";
    cli_print_utf8_line(k, sizeof(k) - 1);
    return 2;
  }
  switch (a->err) {
  case CLI_E_UNKNOWN_COMMAND:
    say2(SD_MSG_CLI_UNKNOWN_COMMAND, "command", a->bad, NULL, NULL);
    return 2;
  case CLI_E_UNKNOWN_OPTION:  say2(SD_MSG_CLI_ERR_UNKNOWN_OPTION, "option", a->bad, NULL, NULL); break;
  case CLI_E_MISSING_VALUE:   say2(SD_MSG_CLI_ERR_MISSING_VALUE, "option", a->bad, NULL, NULL); break;
  case CLI_E_MISSING_ARGUMENT:
    if (a->cmd_name == NULL) {
      cli_print_help(NULL);
      return 2;
    }
    say2(SD_MSG_CLI_ERR_MISSING_ARGUMENT, "command", cmd, NULL, NULL);
    break;
  case CLI_E_EXTRA_ARGUMENT:  say2(SD_MSG_CLI_ERR_EXTRA_ARGUMENT, "argument", a->bad, NULL, NULL); break;
  case CLI_E_BAD_VALUE:       say2(SD_MSG_CLI_ERR_BAD_VALUE, "option", a->bad, "value", a->bad_value); break;
  case CLI_E_CONFLICT:        say2(SD_MSG_CLI_ERR_CONFLICT, "option", a->bad, "other", a->bad_value); break;
  case CLI_E_HOST_SPEC:       say2(SD_MSG_CLI_ERR_HOST_SPEC, "value", a->bad_value, NULL, NULL); break;
  case CLI_E_LETTER:          say2(SD_MSG_CLI_ERROR_INVALID_TARGET, "value", a->bad_value, NULL, NULL); break;
  default: break;
  }
  say2(SD_MSG_CLI_ERR_SEE_HELP, "command", cmd[0] ? cmd : L"", NULL, NULL);
  return 2;
}

int wmain(void)
{
  cli_args a;
  int argc = 0, rc;
  wchar_t **argv = NULL;
  wchar_t env_lang[32];
  const wchar_t *lang;
  sd_lang dummy;

  sd_platform_harden_dll_search();
  sd_platform_init();
#ifdef SD_CLI_TEST_HOOKS
  apply_test_hooks();
#endif
  if (cli_split_cmdline(GetCommandLineW(), &argc, &argv) != SD_OK)
    return 1;
  cli_parse(argc, argv, &a);
  lang = a.lang;
  if (lang == NULL && GetEnvironmentVariableW(L"SHELLDRIVE_LANG", env_lang, SD_COUNTOF(env_lang)) - 1u <
                      SD_COUNTOF(env_lang) - 1u)
    lang = env_lang;
  sd_l10n_init(&sd_l10n_catalog_cli, lang);
  cli_out_init(a.json, a.quiet);
  if (a.err == CLI_OK && a.lang && !sd_l10n_parse_lang(a.lang, &dummy)) {
    a.err = CLI_E_BAD_VALUE;
    a.bad = L"--lang";
    a.bad_value = a.lang;
  }
  if (a.err != CLI_OK)
    rc = usage_error(&a);
  else
    rc = cli_run(&a);
  sd_free(argv);
  return rc;
}
