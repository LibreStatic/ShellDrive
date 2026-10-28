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

typedef enum { O_FLAG, O_VALUE, O_OPTVALUE } opt_kind;   /* O_OPTVALUE: the value may be left out (--bundle) */

typedef struct opt_def {
  const wchar_t *name;
  opt_kind kind;
  int id;
} opt_def;

enum {
  OPT_JSON, OPT_QUIET, OPT_LANG, OPT_HELP, OPT_VERSION, OPT_PROMPT, OPT_STDIN,
  OPT_HOST, OPT_LETTER, OPT_IDENTITY, OPT_REMOTE_PATH, OPT_READ_ONLY, OPT_NO_WAIT, OPT_ALL, OPT_FORCE,
  OPT_BACKEND, OPT_JUMP, OPT_PROXY, OPT_CONNECTIONS, OPT_TYPE, OPT_FROM, OPT_DRY_RUN, OPT_ADD_ONLY,
  OPT_ANNOUNCED, OPT_STATS, OPT_OPEN, OPT_MACHINE, OPT_FROM_SERVER, OPT_EXPECT,
  OPT_SCENARIO, OPT_SIZE, OPT_WRITE_MODE,
  OPT_CHECK, OPT_BUNDLE, OPT_INCLUDE_DUMPS, OPT_NO_ANONYMIZE, OPT_ANONYMIZE, OPT_FIX, OPT_YES
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
  { L"--jump", O_VALUE, OPT_JUMP }, { L"--proxy", O_VALUE, OPT_PROXY },
  { L"--connections", O_VALUE, OPT_CONNECTIONS },
  { L"--type", O_VALUE, OPT_TYPE }, { L"--from", O_VALUE, OPT_FROM },
  { L"--dry-run", O_FLAG, OPT_DRY_RUN }, { L"--add-only", O_FLAG, OPT_ADD_ONLY },
  { L"--announced", O_FLAG, OPT_ANNOUNCED }, { L"--stats", O_FLAG, OPT_STATS }, { L"--open", O_FLAG, OPT_OPEN },
  { L"--machine", O_FLAG, OPT_MACHINE }, { L"--from-server", O_VALUE, OPT_FROM_SERVER },
  { L"--expect", O_VALUE, OPT_EXPECT },
  { L"--scenario", O_VALUE, OPT_SCENARIO }, { L"--size", O_VALUE, OPT_SIZE },
  { L"--write-mode", O_VALUE, OPT_WRITE_MODE },
  { L"--check", O_FLAG, OPT_CHECK }, { L"--bundle", O_OPTVALUE, OPT_BUNDLE },
  { L"--include-dumps", O_FLAG, OPT_INCLUDE_DUMPS }, { L"--no-anonymize", O_FLAG, OPT_NO_ANONYMIZE },
  { L"--anonymize", O_FLAG, OPT_ANONYMIZE }, { L"--fix", O_VALUE, OPT_FIX }, { L"--yes", O_FLAG, OPT_YES },
};

/* Which options each command accepts (globals are always accepted). */
static int allowed(cli_cmd cmd, int id)
{
  switch (id) {
  case OPT_JSON: case OPT_QUIET: case OPT_LANG: case OPT_HELP: case OPT_VERSION:
    return 1;
  case OPT_STDIN:                       /* hostkey add: the answer to its question is read from standard input */
    return cmd == CLI_CMD_MOUNT || cmd == CLI_CMD_HOSTKEY;
  case OPT_PROMPT: case OPT_HOST: case OPT_LETTER: case OPT_IDENTITY:
  case OPT_REMOTE_PATH: case OPT_READ_ONLY: case OPT_NO_WAIT: case OPT_BACKEND:
  case OPT_JUMP: case OPT_PROXY: case OPT_CONNECTIONS:
    return cmd == CLI_CMD_MOUNT;
  case OPT_OPEN:
    return cmd == CLI_CMD_MOUNT;
  case OPT_STATS:
    return cmd == CLI_CMD_STATUS;
  case OPT_TYPE: case OPT_FROM: case OPT_ADD_ONLY: case OPT_ANNOUNCED:
  case OPT_MACHINE: case OPT_FROM_SERVER: case OPT_EXPECT:
    return cmd == CLI_CMD_HOSTKEY;
  case OPT_DRY_RUN:
    return cmd == CLI_CMD_PROFILE;
  case OPT_ALL: case OPT_FORCE:
    return cmd == CLI_CMD_UNMOUNT || cmd == CLI_CMD_CACHE;
  case OPT_SCENARIO: case OPT_SIZE: case OPT_WRITE_MODE:
    return cmd == CLI_CMD_DIAG || cmd == CLI_CMD_BENCH;
  case OPT_CHECK: case OPT_BUNDLE: case OPT_INCLUDE_DUMPS: case OPT_NO_ANONYMIZE: case OPT_ANONYMIZE:
  case OPT_FIX: case OPT_YES:
    return cmd == CLI_CMD_DIAG;
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

/* --expect SHA256:<base64 of the digest>, as "hostkey add" prints it (03 §5.5). Shape only: the digest is
   compared with the server's key later. */
static int hk_expect_ok(const wchar_t *v)
{
  size_t i, n = wcslen(v);
  if (n < 8 || wcsncmp(v, L"SHA256:", 7) != 0)
    return 0;
  for (i = 7; i < n; i++) {
    wchar_t c = v[i];
    if (!((c >= L'A' && c <= L'Z') || (c >= L'a' && c <= L'z') || (c >= L'0' && c <= L'9') ||
          c == L'+' || c == L'/' || c == L'='))
      return 0;
  }
  return 1;
}

/* The first of --machine, --from-server, --expect that is set (for "hostkey list|import|remove"). */
static const wchar_t *hk_add_option_name(const cli_args *a)
{
  return a->machine ? L"--machine" : a->from_server ? L"--from-server" : L"--expect";
}

/* diag bench --scenario NAME: one of the scenario names of cli_bench.c, or "all". */
static int bench_scenario_ok(const wchar_t *v)
{
  static const wchar_t *const names[] = { L"all", L"seq-write", L"seq-write-64k", L"seq-read", L"small-files", L"open" };
  size_t i;
  for (i = 0; i < SD_COUNTOF(names); i++)
    if (wcscmp(v, names[i]) == 0) return 1;
  return 0;
}

/* diag bench <X:> and bench <X:>: a drive letter, optionally with a backslash (the same shape as refresh). */
static int bench_drive_ok(const wchar_t *s)
{
  if (s == NULL || !((s[0] >= L'A' && s[0] <= L'Z') || (s[0] >= L'a' && s[0] <= L'z')) || s[1] != L':')
    return 0;
  return s[2] == 0 || (s[2] == L'\\' && s[3] == 0);
}

static cli_cmd command_of(const wchar_t *w)
{
  if (wcscmp(w, L"diag") == 0) return CLI_CMD_DIAG;     /* diag [--check|--bundle|--fix], diag bench <X:>, diag collect */
  if (wcscmp(w, L"admin") == 0) return CLI_CMD_DIAG;    /* admin webclient-enable = diag --fix webclient (03 §6.1) */
  if (wcscmp(w, L"bench") == 0) return CLI_CMD_BENCH;   /* alias of diag bench (03 §6.1) */
  if (wcscmp(w, L"mount") == 0) return CLI_CMD_MOUNT;
  if (wcscmp(w, L"unmount") == 0 || wcscmp(w, L"umount") == 0) return CLI_CMD_UNMOUNT;
  if (wcscmp(w, L"list") == 0 || wcscmp(w, L"ls") == 0) return CLI_CMD_LIST;
  if (wcscmp(w, L"status") == 0 || wcscmp(w, L"stats") == 0) return CLI_CMD_STATUS;   /* stats: status --stats */
  if (wcscmp(w, L"refresh") == 0) return CLI_CMD_REFRESH;
  if (wcscmp(w, L"cache") == 0) return CLI_CMD_CACHE;
  if (wcscmp(w, L"profile") == 0) return CLI_CMD_PROFILE;
  if (wcscmp(w, L"hostkey") == 0) return CLI_CMD_HOSTKEY;
  if (wcscmp(w, L"service") == 0) return CLI_CMD_SERVICE;
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
      } else if (d->kind == O_OPTVALUE) {
        /* --bundle [FILE]: the value is optional; the next word is taken only when it is not an option */
        if (eq) {
          value = eq + 1;
          if (value[0] == 0)
            return set_err(a, CLI_E_MISSING_VALUE, d->name, NULL);
        } else if (i + 1 < argc && argv[i + 1][0] != L'-') {
          value = argv[++i];
        }
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
      case OPT_JUMP:
        if (a->jump_count >= CLI_MAX_JUMP)
          return set_err(a, CLI_E_BAD_VALUE, d->name, value);
        a->jump[a->jump_count++] = value;
        break;
      case OPT_PROXY: a->proxy = value; break;
      case OPT_CONNECTIONS: {
        int n = 0;
        const wchar_t *p = value;
        while (*p >= L'0' && *p <= L'9') {
          n = n * 10 + (int)(*p - L'0');
          if (n > 99) { n = 0; break; }
          p++;
        }
        if (n < 1 || n > 4 || *p)
          return set_err(a, CLI_E_BAD_VALUE, d->name, value);
        a->connections = n;
        break;
      }
      case OPT_TYPE: a->hk_type = value; break;
      case OPT_FROM:
        if (wcscmp(value, L"putty") == 0 || wcscmp(value, L"openssh") == 0) a->from = value;
        else return set_err(a, CLI_E_BAD_VALUE, d->name, value);
        break;
      case OPT_DRY_RUN: a->dry_run = 1; break;
      case OPT_ADD_ONLY: a->add_only = 1; break;
      case OPT_ANNOUNCED: a->announced = 1; break;
      case OPT_MACHINE: a->machine = 1; break;
      case OPT_FROM_SERVER: a->from_server = value; break;
      case OPT_EXPECT: a->expect = value; break;
      case OPT_SCENARIO:
        if (!bench_scenario_ok(value))
          return set_err(a, CLI_E_BAD_VALUE, d->name, value);
        a->bench_scenario = value;
        break;
      case OPT_SIZE: {
        /* 1..4096 MiB: digits only, no sign, no leading overflow */
        int64_t mib = 0;
        const wchar_t *p = value;
        while (*p >= L'0' && *p <= L'9') {
          mib = mib * 10 + (*p - L'0');
          if (mib > 4096) break;
          p++;
        }
        if (mib < 1 || mib > 4096 || *p)
          return set_err(a, CLI_E_BAD_VALUE, d->name, value);
        a->bench_size_mib = (int)mib;
        break;
      }
      case OPT_WRITE_MODE:
        if (wcscmp(value, L"through") != 0 && wcscmp(value, L"behind") != 0)
          return set_err(a, CLI_E_BAD_VALUE, d->name, value);
        a->bench_write_mode = value;
        break;
      case OPT_STATS: a->stats = 1; break;
      case OPT_OPEN: a->open_after = 1; break;
      case OPT_CHECK: a->diag_check = 1; break;
      case OPT_BUNDLE: a->diag_bundle = 1; a->bundle_file = value; break;
      case OPT_INCLUDE_DUMPS: a->include_dumps = 1; break;
      case OPT_NO_ANONYMIZE: a->no_anonymize = 1; break;
      case OPT_ANONYMIZE: a->anonymize = 1; break;
      case OPT_FIX:
        if (wcscmp(value, L"webclient") == 0 || wcscmp(value, L"linked-connections") == 0) a->fix_item = value;
        else return set_err(a, CLI_E_BAD_VALUE, d->name, value);
        break;
      case OPT_YES: a->yes = 1; break;
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
    {
      /* positional slots per command (03 §6.1): mount/unmount/help/status take one, profile takes
         sub-verb + source + value, hostkey takes sub-verb + target */
      const wchar_t **slot = NULL;
      if (a->cmd == CLI_CMD_MOUNT || a->cmd == CLI_CMD_UNMOUNT || a->cmd == CLI_CMD_HELP ||
          a->cmd == CLI_CMD_STATUS || a->cmd == CLI_CMD_REFRESH || a->cmd == CLI_CMD_BENCH) {
        if (a->positional == NULL) slot = &a->positional;
      } else if (a->cmd == CLI_CMD_DIAG) {
        /* diag <verb> <X:>: the verb, then the drive (the verb is checked below) */
        if (a->positional == NULL) slot = &a->positional;
        else if (a->arg2 == NULL) slot = &a->arg2;
      } else if (a->cmd == CLI_CMD_CACHE) {
        if (a->positional == NULL) slot = &a->positional;
        else if (a->arg2 == NULL) slot = &a->arg2;
      } else if (a->cmd == CLI_CMD_SERVICE) {
        if (a->positional == NULL) slot = &a->positional;   /* the verb */
        else if (a->arg2 == NULL) slot = &a->arg2;          /* the profile or X: */
      } else if (a->cmd == CLI_CMD_PROFILE) {
        if (a->positional == NULL) slot = &a->positional;
        else if (a->arg2 == NULL) slot = &a->arg2;
        else if (a->arg3 == NULL) slot = &a->arg3;
      } else if (a->cmd == CLI_CMD_HOSTKEY) {
        if (a->positional == NULL) slot = &a->positional;
        else if (a->arg2 == NULL) slot = &a->arg2;
      }
      if (slot) { *slot = arg; continue; }
    }
    return set_err(a, CLI_E_EXTRA_ARGUMENT, arg, NULL);
  }
  a->subverb = (a->cmd == CLI_CMD_PROFILE || a->cmd == CLI_CMD_HOSTKEY) ? a->positional : NULL;
  /* "stats <X:>" is "status <X:> --stats" (03 §6.1 aliases) */
  if (a->cmd == CLI_CMD_STATUS && a->cmd_name && wcscmp(a->cmd_name, L"stats") == 0)
    a->stats = 1;
  /* options given before the command word: re-check against the command */
  if (a->cmd == CLI_CMD_NONE && !a->help)
    return set_err(a, CLI_E_MISSING_ARGUMENT, NULL, NULL);
  /* diag (03 §6.1): "diag bench <X:>" is the bench command, "diag collect" the bundle, "admin webclient-enable"
     the webclient fix; the options pick the form otherwise, and a plain "diag" is the checks. */
  if (a->cmd == CLI_CMD_DIAG && !a->help) {
    if (a->cmd_name && wcscmp(a->cmd_name, L"admin") == 0) {
      if (a->positional == NULL || wcscmp(a->positional, L"webclient-enable") != 0 || a->arg2)
        return set_err(a, CLI_E_UNKNOWN_COMMAND, a->positional ? a->positional : a->cmd_name, NULL);
      a->fix_item = L"webclient";
      a->positional = NULL;
    } else if (a->positional) {
      if (wcscmp(a->positional, L"bench") == 0) {
        a->cmd = CLI_CMD_BENCH;
        a->positional = a->arg2;
        a->arg2 = NULL;
      } else if (wcscmp(a->positional, L"collect") == 0) {
        if (a->arg2)
          return set_err(a, CLI_E_EXTRA_ARGUMENT, a->arg2, NULL);
        a->diag_bundle = 1;
        a->positional = NULL;
      } else {
        return set_err(a, CLI_E_UNKNOWN_COMMAND, a->positional, NULL);
      }
    }
  }
  if (a->cmd == CLI_CMD_DIAG && !a->help) {
    int forms = a->diag_check + a->diag_bundle + (a->fix_item != NULL);
    if (forms > 1)
      return set_err(a, CLI_E_CONFLICT, a->diag_bundle ? L"--bundle" : a->fix_item ? L"--fix" : L"--check",
                     a->diag_check ? L"--check" : a->fix_item ? L"--fix" : L"--bundle");
    if (forms == 0)
      a->diag_check = 1;
    if (a->yes && a->fix_item == NULL)
      return set_err(a, CLI_E_UNKNOWN_OPTION, L"--yes", NULL);
    if ((a->include_dumps || a->no_anonymize || a->anonymize) && !a->diag_bundle)
      return set_err(a, CLI_E_UNKNOWN_OPTION, a->include_dumps ? L"--include-dumps" : a->no_anonymize ?
                     L"--no-anonymize" : L"--anonymize", NULL);
    if (a->no_anonymize && a->anonymize)
      return set_err(a, CLI_E_CONFLICT, L"--anonymize", L"--no-anonymize");
  }
  if (a->cmd == CLI_CMD_BENCH && (a->diag_check || a->diag_bundle || a->fix_item || a->yes || a->include_dumps ||
                                  a->no_anonymize || a->anonymize))
    return set_err(a, CLI_E_UNKNOWN_OPTION, L"--check", NULL);
  if (a->cmd != CLI_CMD_BENCH && (a->bench_scenario || a->bench_size_mib || a->bench_write_mode))
    return set_err(a, CLI_E_UNKNOWN_OPTION, a->bench_scenario ? L"--scenario" : a->bench_size_mib ? L"--size" :
                   L"--write-mode", NULL);
  /* --stdin is also a hostkey add option (the answer to its question) */
  if (a->cmd != CLI_CMD_MOUNT && (a->host_spec || a->letter || a->identity || a->remote_path || a->read_only ||
                                  a->no_wait || (a->use_stdin && a->cmd != CLI_CMD_HOSTKEY) ||
                                  a->prompt != CLI_PROMPT_AUTO || a->backend ||
                                  a->jump_count || a->proxy || a->connections))
    return set_err(a, CLI_E_UNKNOWN_OPTION, a->backend ? L"--backend" : a->host_spec ? L"--host" : a->letter ? L"--letter" :
                   a->identity ? L"--identity" : a->remote_path ? L"--remote-path" : a->read_only ? L"--read-only" :
                   a->no_wait ? L"--no-wait" : (a->use_stdin && a->cmd != CLI_CMD_HOSTKEY) ? L"--stdin" :
                   a->jump_count ? L"--jump" : a->proxy ? L"--proxy" : a->connections ? L"--connections" :
                   L"--prompt", NULL);
  if (a->cmd != CLI_CMD_UNMOUNT && a->cmd != CLI_CMD_CACHE && (a->all || a->force))
    return set_err(a, CLI_E_UNKNOWN_OPTION, a->all ? L"--all" : L"--force", NULL);
  if (a->cmd != CLI_CMD_STATUS && a->stats)
    return set_err(a, CLI_E_UNKNOWN_OPTION, L"--stats", NULL);
  if (a->cmd != CLI_CMD_MOUNT && a->open_after)
    return set_err(a, CLI_E_UNKNOWN_OPTION, L"--open", NULL);
  if (a->cmd != CLI_CMD_HOSTKEY && (a->hk_type || a->from || a->add_only || a->announced))
    return set_err(a, CLI_E_UNKNOWN_OPTION, a->hk_type ? L"--type" : a->from ? L"--from" :
                   a->add_only ? L"--add-only" : L"--announced", NULL);
  if (a->cmd != CLI_CMD_HOSTKEY && (a->from_server || a->expect || a->machine))
    return set_err(a, CLI_E_UNKNOWN_OPTION, a->machine ? L"--machine" : a->from_server ? L"--from-server" :
                   L"--expect", NULL);
  if (a->cmd != CLI_CMD_PROFILE && a->dry_run)
    return set_err(a, CLI_E_UNKNOWN_OPTION, L"--dry-run", NULL);
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
    } else if (a->identity || a->remote_path || a->jump_count || a->proxy || a->connections) {
      return set_err(a, CLI_E_CONFLICT, a->identity ? L"--identity" : a->remote_path ? L"--remote-path" :
                     a->jump_count ? L"--jump" : a->proxy ? L"--proxy" : L"--connections", L"<profile>");
    }
    break;
  case CLI_CMD_UNMOUNT:
    if (a->all && a->positional)
      return set_err(a, CLI_E_CONFLICT, L"--all", a->positional);
    if (!a->all && !a->positional)
      return set_err(a, CLI_E_MISSING_ARGUMENT, a->cmd_name, NULL);
    break;
  case CLI_CMD_PROFILE:
    if (!a->positional)
      return set_err(a, CLI_E_MISSING_ARGUMENT, a->cmd_name, NULL);
    if (wcscmp(a->positional, L"test") == 0) {          /* profile test <profile> (03 §6.1) */
      if (!a->arg2)
        return set_err(a, CLI_E_MISSING_ARGUMENT, a->positional, NULL);
      if (a->arg3)
        return set_err(a, CLI_E_EXTRA_ARGUMENT, a->arg3, NULL);
      break;
    }
    if (wcscmp(a->positional, L"import") != 0)
      return set_err(a, CLI_E_UNKNOWN_COMMAND, a->positional, NULL);
    if (!a->arg2 || (wcscmp(a->arg2, L"putty") != 0 && wcscmp(a->arg2, L"ssh-config") != 0))
      return set_err(a, CLI_E_UNKNOWN_COMMAND, a->arg2 ? a->arg2 : L"", NULL);
    break;
  case CLI_CMD_REFRESH:
    /* X:, X:\ or X:\sub\path (folder targets need Dokany folder mounts, not in this build) */
    if (!a->positional)
      return set_err(a, CLI_E_MISSING_ARGUMENT, a->cmd_name, NULL);
    if (!((a->positional[0] >= L'A' && a->positional[0] <= L'Z') || (a->positional[0] >= L'a' && a->positional[0] <= L'z')) ||
        a->positional[1] != L':' || (a->positional[2] != 0 && a->positional[2] != L'\\' && a->positional[2] != L'/'))
      return set_err(a, CLI_E_LETTER, a->positional, a->positional);
    break;
  case CLI_CMD_CACHE:
    /* cache clear [<profile>|--all] [--force] (03 §6.1) */
    if (!a->positional)
      return set_err(a, CLI_E_MISSING_ARGUMENT, a->cmd_name, NULL);
    if (wcscmp(a->positional, L"clear") != 0)
      return set_err(a, CLI_E_UNKNOWN_COMMAND, a->positional, NULL);
    if (a->all && a->arg2)
      return set_err(a, CLI_E_CONFLICT, L"--all", a->arg2);
    if (!a->all && !a->arg2)
      return set_err(a, CLI_E_MISSING_ARGUMENT, a->positional, NULL);
    break;
  case CLI_CMD_SERVICE:
    /* list | mount <profile> | unmount <profile|X:> | status [<profile|X:>] | install | uninstall | start | stop |
       repair-data (cli_service.c) */
    if (!a->positional)
      return set_err(a, CLI_E_MISSING_ARGUMENT, a->cmd_name, NULL);
    if (wcscmp(a->positional, L"list") != 0 && wcscmp(a->positional, L"mount") != 0 &&
        wcscmp(a->positional, L"unmount") != 0 && wcscmp(a->positional, L"status") != 0 &&
        wcscmp(a->positional, L"install") != 0 && wcscmp(a->positional, L"uninstall") != 0 &&
        wcscmp(a->positional, L"start") != 0 && wcscmp(a->positional, L"stop") != 0 &&
        wcscmp(a->positional, L"repair-data") != 0)
      return set_err(a, CLI_E_UNKNOWN_COMMAND, a->positional, NULL);
    /* status takes no argument (the service report) or a drive or profile (the drive status) */
    if ((wcscmp(a->positional, L"mount") == 0 || wcscmp(a->positional, L"unmount") == 0) && !a->arg2)
      return set_err(a, CLI_E_MISSING_ARGUMENT, a->positional, NULL);
    break;
  case CLI_CMD_HOSTKEY:
    if (!a->positional)
      return set_err(a, CLI_E_MISSING_ARGUMENT, a->cmd_name, NULL);
    if (wcscmp(a->positional, L"list") == 0) {
      /* with --announced the pending updates are listed without a host (03 §6.1) */
      if (!a->arg2 && !a->announced)
        return set_err(a, CLI_E_MISSING_ARGUMENT, a->positional, NULL);
      if (a->hk_type || a->from || a->add_only)
        return set_err(a, CLI_E_UNKNOWN_OPTION, a->hk_type ? L"--type" : a->from ? L"--from" : L"--add-only", NULL);
      if (a->from_server || a->expect || a->machine)
        return set_err(a, CLI_E_UNKNOWN_OPTION, hk_add_option_name(a), NULL);
    } else if (wcscmp(a->positional, L"import") == 0) {
      if (!a->from)
        return set_err(a, CLI_E_MISSING_ARGUMENT, a->positional, NULL);
      if (a->announced || a->add_only || a->hk_type)
        return set_err(a, CLI_E_UNKNOWN_OPTION, a->announced ? L"--announced" :
                       a->add_only ? L"--add-only" : L"--type", NULL);
      if (a->from_server || a->expect || a->machine)
        return set_err(a, CLI_E_UNKNOWN_OPTION, hk_add_option_name(a), NULL);
    } else if (wcscmp(a->positional, L"remove") == 0) {
      if (!a->arg2)
        return set_err(a, CLI_E_MISSING_ARGUMENT, a->positional, NULL);
      if (a->announced || a->add_only || a->from)
        return set_err(a, CLI_E_UNKNOWN_OPTION, a->announced ? L"--announced" :
                       a->add_only ? L"--add-only" : L"--from", NULL);
      if (a->from_server || a->expect || a->machine)
        return set_err(a, CLI_E_UNKNOWN_OPTION, hk_add_option_name(a), NULL);
    } else if (wcscmp(a->positional, L"accept-announced") == 0) {
      if (!a->arg2)
        return set_err(a, CLI_E_MISSING_ARGUMENT, a->positional, NULL);
      if (a->announced || a->hk_type || a->from)
        return set_err(a, CLI_E_UNKNOWN_OPTION, a->announced ? L"--announced" :
                       a->hk_type ? L"--type" : L"--from", NULL);
      if (a->from_server || a->expect)
        return set_err(a, CLI_E_UNKNOWN_OPTION, a->from_server ? L"--from-server" : L"--expect", NULL);
    } else if (wcscmp(a->positional, L"add") == 0) {
      /* hostkey add --from-server host[:port] [--type T] [--expect SHA256:...] [--machine] (03 §6.1) */
      if (a->arg2)
        return set_err(a, CLI_E_EXTRA_ARGUMENT, a->arg2, NULL);
      if (!a->from_server)
        return set_err(a, CLI_E_MISSING_ARGUMENT, L"--from-server", NULL);
      if (a->announced || a->add_only || a->from)
        return set_err(a, CLI_E_UNKNOWN_OPTION, a->announced ? L"--announced" :
                       a->add_only ? L"--add-only" : L"--from", NULL);
      {
        char user[128], host[256];
        uint16_t port = 22;
        if (sd_parse_host_spec(a->from_server, user, sizeof(user), host, sizeof(host), &port) != SD_OK || host[0] == 0)
          return set_err(a, CLI_E_HOST_SPEC, L"--from-server", a->from_server);
      }
      if (a->expect && !hk_expect_ok(a->expect))
        return set_err(a, CLI_E_BAD_VALUE, L"--expect", a->expect);
    } else {
      return set_err(a, CLI_E_UNKNOWN_COMMAND, a->positional, NULL);
    }
    break;
  case CLI_CMD_BENCH:
    if (!a->positional)
      return set_err(a, CLI_E_MISSING_ARGUMENT, a->cmd_name, NULL);
    if (!bench_drive_ok(a->positional))
      return set_err(a, CLI_E_LETTER, a->positional, a->positional);
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
