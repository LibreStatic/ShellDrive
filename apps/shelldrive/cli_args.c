/* Command-line splitting and parsing for shelldrive.exe (03 §6.1). No I/O: unit-tested in tests/apps. */
#include <windows.h>
#include <string.h>

#include "cli.h"
#include "sd_base/sd_mem.h"
#include "sd_base/sd_checked.h"
#include "sd_config/sd_config.h"

sd_err cli_split_cmdline(const wchar_t *cmd, int *argc_out, wchar_t ***argv_out)
{
  size_t len, cap_args, bytes, i;
  wchar_t **argv;
  wchar_t *buf, *o;
  const wchar_t *p;
  int argc = 0;
  *argc_out = 0;
  *argv_out = NULL;
  if (cmd == NULL)
    cmd = L"";
  len = wcslen(cmd);
  cap_args = len / 2 + 2;                    /* at most one argument per two characters, + NULL */
  if (sd_mul_ovf(cap_args, sizeof(wchar_t *), &bytes) || sd_add_ovf(bytes, (len + cap_args + 1) * sizeof(wchar_t), &bytes))
    return SD_E_NO_MEMORY;
  argv = (wchar_t **)sd_alloc(bytes);
  if (argv == NULL)
    return SD_E_NO_MEMORY;
  buf = (wchar_t *)(argv + cap_args);
  o = buf;
  p = cmd;
  /* argv[0]: program name, no escape processing */
  while (*p == L' ' || *p == L'\t') p++;
  if (*p) {
    argv[argc++] = o;
    if (*p == L'"') {
      p++;
      while (*p && *p != L'"') *o++ = *p++;
      if (*p == L'"') p++;
    } else {
      while (*p && *p != L' ' && *p != L'\t') *o++ = *p++;
    }
    *o++ = 0;
  }
  for (;;) {
    int inq = 0;
    while (*p == L' ' || *p == L'\t') p++;
    if (*p == 0)
      break;
    argv[argc++] = o;
    for (;;) {
      if (*p == 0) break;
      if (!inq && (*p == L' ' || *p == L'\t')) break;
      if (*p == L'\\') {
        size_t nb = 0;
        while (p[nb] == L'\\') nb++;
        if (p[nb] == L'"') {
          for (i = 0; i < nb / 2; i++) *o++ = L'\\';
          if (nb % 2) { *o++ = L'"'; p += nb + 1; }
          else { p += nb; }       /* the quote is handled below */
        } else {
          for (i = 0; i < nb; i++) *o++ = L'\\';
          p += nb;
        }
        continue;
      }
      if (*p == L'"') {
        if (inq && p[1] == L'"') { *o++ = L'"'; p += 2; }   /* "" inside quotes */
        else { inq = !inq; p++; }
        continue;
      }
      *o++ = *p++;
    }
    *o++ = 0;
    if ((size_t)argc + 1 >= cap_args)
      break;
  }
  argv[argc] = NULL;
  *argc_out = argc;
  *argv_out = argv;
  return SD_OK;
}

/* ---- parsing ---- */

typedef enum { O_FLAG, O_VALUE } opt_kind;

typedef struct opt_def {
  const wchar_t *name;
  opt_kind kind;
  int id;
} opt_def;

enum {
  OPT_JSON, OPT_QUIET, OPT_LANG, OPT_HELP, OPT_VERSION, OPT_PROMPT, OPT_STDIN,
  OPT_HOST, OPT_LETTER, OPT_IDENTITY, OPT_REMOTE_PATH, OPT_READ_ONLY, OPT_NO_WAIT, OPT_ALL, OPT_FORCE,
  OPT_BACKEND
};

static const opt_def k_opts[] = {
  { L"--json", O_FLAG, OPT_JSON }, { L"--quiet", O_FLAG, OPT_QUIET }, { L"-q", O_FLAG, OPT_QUIET },
  { L"--lang", O_VALUE, OPT_LANG }, { L"--help", O_FLAG, OPT_HELP }, { L"-h", O_FLAG, OPT_HELP },
  { L"-?", O_FLAG, OPT_HELP }, { L"/?", O_FLAG, OPT_HELP }, { L"--version", O_FLAG, OPT_VERSION },
  { L"--prompt", O_VALUE, OPT_PROMPT }, { L"--stdin", O_FLAG, OPT_STDIN },
  { L"--host", O_VALUE, OPT_HOST }, { L"--letter", O_VALUE, OPT_LETTER }, { L"--target", O_VALUE, OPT_LETTER },
  { L"--identity", O_VALUE, OPT_IDENTITY }, { L"-i", O_VALUE, OPT_IDENTITY },
  { L"--remote-path", O_VALUE, OPT_REMOTE_PATH }, { L"--path", O_VALUE, OPT_REMOTE_PATH },
  { L"--read-only", O_FLAG, OPT_READ_ONLY }, { L"--no-wait", O_FLAG, OPT_NO_WAIT },
  { L"--all", O_FLAG, OPT_ALL }, { L"--force", O_FLAG, OPT_FORCE },
  { L"--backend", O_VALUE, OPT_BACKEND },
};

/* Which options each command accepts (globals are always accepted). */
static int allowed(cli_cmd cmd, int id)
{
  switch (id) {
  case OPT_JSON: case OPT_QUIET: case OPT_LANG: case OPT_HELP: case OPT_VERSION:
    return 1;
  case OPT_PROMPT: case OPT_STDIN: case OPT_HOST: case OPT_LETTER: case OPT_IDENTITY:
  case OPT_REMOTE_PATH: case OPT_READ_ONLY: case OPT_NO_WAIT: case OPT_BACKEND:
    return cmd == CLI_CMD_MOUNT;
  case OPT_ALL: case OPT_FORCE:
    return cmd == CLI_CMD_UNMOUNT;
  }
  return 0;
}

static cli_usage_err set_err(cli_args *a, cli_usage_err e, const wchar_t *bad, const wchar_t *value)
{
  if (a->err == CLI_OK) {
    a->err = e;
    a->bad = bad;
    a->bad_value = value;
  }
  return a->err;
}

static cli_cmd command_of(const wchar_t *w)
{
  if (wcscmp(w, L"mount") == 0) return CLI_CMD_MOUNT;
  if (wcscmp(w, L"unmount") == 0 || wcscmp(w, L"umount") == 0) return CLI_CMD_UNMOUNT;
  if (wcscmp(w, L"list") == 0 || wcscmp(w, L"ls") == 0) return CLI_CMD_LIST;
  if (wcscmp(w, L"version") == 0) return CLI_CMD_VERSION;
  if (wcscmp(w, L"help") == 0) return CLI_CMD_HELP;
  if (wcscmp(w, L"agent") == 0) return CLI_CMD_AGENT_STOP;   /* "agent stop" checked below */
  return CLI_CMD_NONE;
}

cli_usage_err cli_parse(int argc, wchar_t **argv, cli_args *a)
{
  int i, have_agent_verb = 0;
  memset(a, 0, sizeof(*a));
  a->prompt = CLI_PROMPT_AUTO;
  for (i = 1; i < argc; i++) {
    const wchar_t *arg = argv[i];
    if ((arg[0] == L'-' && arg[1] != 0) || wcscmp(arg, L"/?") == 0) {
      const opt_def *d = NULL;
      const wchar_t *eq = wcschr(arg, L'=');
      size_t nlen = eq ? (size_t)(eq - arg) : wcslen(arg), k;
      const wchar_t *value = NULL;
      if (wcscmp(arg, L"--") == 0)
        return set_err(a, CLI_E_UNKNOWN_OPTION, arg, NULL);
      for (k = 0; k < SD_COUNTOF(k_opts); k++)
        if (wcslen(k_opts[k].name) == nlen && wcsncmp(k_opts[k].name, arg, nlen) == 0) { d = &k_opts[k]; break; }
      if (d == NULL)
        return set_err(a, CLI_E_UNKNOWN_OPTION, arg, NULL);
      if (d->kind == O_VALUE) {
        if (eq) value = eq + 1;
        else if (i + 1 < argc) value = argv[++i];
        if (value == NULL || value[0] == 0)
          return set_err(a, CLI_E_MISSING_VALUE, d->name, NULL);
      } else if (eq) {
        return set_err(a, CLI_E_BAD_VALUE, d->name, eq + 1);
      }
      if (a->cmd != CLI_CMD_NONE && !allowed(a->cmd, d->id))
        return set_err(a, CLI_E_UNKNOWN_OPTION, d->name, NULL);
      switch (d->id) {
      case OPT_JSON: a->json = 1; break;
      case OPT_QUIET: a->quiet = 1; break;
      case OPT_LANG: a->lang = value; break;
      case OPT_HELP: a->help = 1; break;
      case OPT_VERSION: if (a->cmd == CLI_CMD_NONE) a->cmd = CLI_CMD_VERSION; break;
      case OPT_PROMPT:
        if (wcscmp(value, L"auto") == 0) a->prompt = CLI_PROMPT_AUTO;
        else if (wcscmp(value, L"console") == 0) a->prompt = CLI_PROMPT_CONSOLE;
        else if (wcscmp(value, L"gui") == 0) a->prompt = CLI_PROMPT_GUI;
        else if (wcscmp(value, L"none") == 0) a->prompt = CLI_PROMPT_NONE;
        else return set_err(a, CLI_E_BAD_VALUE, d->name, value);
        break;
      case OPT_STDIN: a->use_stdin = 1; break;
      case OPT_HOST: a->host_spec = value; break;
      case OPT_LETTER:
        a->letter = sd_parse_drive_letter(value);
        if (a->letter == 0 || a->letter < L'D')
          return set_err(a, CLI_E_LETTER, d->name, value);
        break;
      case OPT_IDENTITY: a->identity = value; break;
      case OPT_REMOTE_PATH: a->remote_path = value; break;
      case OPT_READ_ONLY: a->read_only = 1; break;
      case OPT_NO_WAIT: a->no_wait = 1; break;
      case OPT_ALL: a->all = 1; break;
      case OPT_FORCE: a->force = 1; break;
      case OPT_BACKEND:
        if (wcscmp(value, L"auto") == 0) a->backend = "auto";
        else if (wcscmp(value, L"dokany") == 0) a->backend = "dokany";
        else if (wcscmp(value, L"webdav") == 0) a->backend = "webdav";
        else return set_err(a, CLI_E_BAD_VALUE, d->name, value);
        break;
      }
      continue;
    }
    if (a->cmd == CLI_CMD_NONE || (a->cmd == CLI_CMD_VERSION && a->cmd_name == NULL)) {
      cli_cmd c = command_of(arg);
      if (c == CLI_CMD_NONE)
        return set_err(a, CLI_E_UNKNOWN_COMMAND, arg, NULL);
      a->cmd = c;
      a->cmd_name = arg;
      continue;
    }
    if (a->cmd == CLI_CMD_AGENT_STOP && !have_agent_verb) {
      if (wcscmp(arg, L"stop") != 0)
        return set_err(a, CLI_E_UNKNOWN_COMMAND, arg, NULL);
      have_agent_verb = 1;
      continue;
    }
    if (a->positional == NULL && (a->cmd == CLI_CMD_MOUNT || a->cmd == CLI_CMD_UNMOUNT || a->cmd == CLI_CMD_HELP)) {
      a->positional = arg;
      continue;
    }
    return set_err(a, CLI_E_EXTRA_ARGUMENT, arg, NULL);
  }
  /* options given before the command word: re-check against the command */
  if (a->cmd == CLI_CMD_NONE && !a->help)
    return set_err(a, CLI_E_MISSING_ARGUMENT, NULL, NULL);
  if (a->cmd != CLI_CMD_MOUNT && (a->host_spec || a->letter || a->identity || a->remote_path || a->read_only ||
                                  a->no_wait || a->use_stdin || a->prompt != CLI_PROMPT_AUTO || a->backend))
    return set_err(a, CLI_E_UNKNOWN_OPTION, a->backend ? L"--backend" : a->host_spec ? L"--host" : a->letter ? L"--letter" :
                   a->identity ? L"--identity" : a->remote_path ? L"--remote-path" : a->read_only ? L"--read-only" :
                   a->no_wait ? L"--no-wait" : a->use_stdin ? L"--stdin" : L"--prompt", NULL);
  if (a->cmd != CLI_CMD_UNMOUNT && (a->all || a->force))
    return set_err(a, CLI_E_UNKNOWN_OPTION, a->all ? L"--all" : L"--force", NULL);
  if (a->help)
    return CLI_OK;
  switch (a->cmd) {
  case CLI_CMD_MOUNT:
    if (a->host_spec && a->positional)
      return set_err(a, CLI_E_CONFLICT, L"--host", a->positional);
    if (!a->host_spec && !a->positional)
      return set_err(a, CLI_E_MISSING_ARGUMENT, a->cmd_name, NULL);
    if (a->host_spec) {
      char user[128], host[256];
      uint16_t port;
      if (sd_parse_host_spec(a->host_spec, user, sizeof(user), host, sizeof(host), &port) != SD_OK)
        return set_err(a, CLI_E_HOST_SPEC, L"--host", a->host_spec);
    } else if (a->identity || a->remote_path) {
      return set_err(a, CLI_E_CONFLICT, a->identity ? L"--identity" : L"--remote-path", L"<profile>");
    }
    break;
  case CLI_CMD_UNMOUNT:
    if (a->all && a->positional)
      return set_err(a, CLI_E_CONFLICT, L"--all", a->positional);
    if (!a->all && !a->positional)
      return set_err(a, CLI_E_MISSING_ARGUMENT, a->cmd_name, NULL);
    break;
  case CLI_CMD_AGENT_STOP:
    if (!have_agent_verb)
      return set_err(a, CLI_E_MISSING_ARGUMENT, a->cmd_name, NULL);
    break;
  default:
    break;
  }
  return CLI_OK;
}
