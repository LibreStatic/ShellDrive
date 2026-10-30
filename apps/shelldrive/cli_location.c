/* shelldrive.exe location add|remove|repair (03 §6.1, §8.7): the Network location entries of the profiles, made
 * without an agent by explorer_data.c (the same code the agent runs). add and remove also write
 * mount.network_location of the profile (sd_profile_save_ex takes config.lock itself); repair holds config.lock
 * while it reconciles the entries. Every path refuses under policy DisableNetworkLocations and changes nothing.
 * Exit codes follow 03 §6.2 (usage 2, profile_not_found 3, io_error 1, policy_denied 15). User-facing text comes
 * from the cli catalog; JSON keys and codes stay English. */
#include <windows.h>
#include <string.h>

#include "cli_int.h"
#include "explorer_data.h"
#include "sd_base/sd_mem.h"
#include "sd_base/sd_utf.h"
#include "sd_config/sd_config.h"
#include "sd_ipc/sd_ipc.h"
#include "sd_l10n/sd_l10n.h"
#include "sd_l10n_cli_ids.h"

/* An error with its code and exit code; the message comes from print_error. */
static int fail_as(const cli_args *a, const char *code, int exit_code, const err_ctx *ec)
{
  print_error(a, code, NULL, exit_code, ec);
  return exit_code;
}

/* Maps an explorer_data.c result (EXPLORER_LOC_*) to the exit code of the verb; 0 for success. */
static int location_result(const cli_args *a, int r, const err_ctx *ec)
{
  if (r == EXPLORER_LOC_POLICY)
    return fail_as(a, "location_policy", 15, ec);
  if (r == EXPLORER_LOC_FAILED)
    return fail_as(a, "location_failed", 1, ec);
  return 0;
}

/* Prints one localized line with {name} = the profile name (UTF-8 in the profile). */
static void say_name(sd_msg_id id, const char *utf8_name)
{
  wchar_t *w = wide(utf8_name ? utf8_name : "");
  say1w(id, "name", w ? w : L"", 0);
  sd_free(w);
}

/* {"ok":true,"result":{ ... }} with the keys the caller writes between begin and end. */
static void json_result_begin(sd_json_writer *jw)
{
  sd_jw_obj_begin(jw);
  sd_jw_key(jw, "ok"); sd_jw_bool(jw, 1);
  sd_jw_key(jw, "result"); sd_jw_obj_begin(jw);
}

static void json_result_end(sd_json_writer *jw, sd_wr *w)
{
  sd_jw_obj_end(jw);
  sd_jw_obj_end(jw);
  if (sd_jw_finish(jw) == SD_OK)
    cli_print_utf8_line((const char *)w->p, w->len);
}

/* location add|remove <profile>: the profile's mount.network_location is set (saved only when it changes), then
   the entry follows. */
static int run_add_remove(const cli_args *a, int add)
{
  err_ctx ec;
  sd_profile *p;
  char *name8 = NULL;
  sd_err e;
  int rc, flag = 0;
  memset(&ec, 0, sizeof(ec));
  ec.name = a->arg2;
  if (explorer_location_blocked())
    return fail_as(a, "location_policy", 15, &ec);
  if (sd_wide_to_utf8_alloc(a->arg2, (size_t)-1, SD_UTF_STRICT, &name8) != SD_OK)
    return fail_code(a, "usage", "invalid profile name", &ec);
  p = (sd_profile *)sd_alloc(sizeof(*p));
  if (p == NULL) {
    sd_free(name8);
    return fail_code(a, "internal", "out of memory", &ec);
  }
  e = sd_profile_find(name8, p, NULL, 0);
  sd_free(name8);
  if (e == SD_E_NOT_FOUND) {
    sd_free(p);
    return fail_code(a, "profile_not_found", "no such profile", &ec);
  }
  if (e != SD_OK) {
    sd_free(p);
    return fail_code(a, "io_error", sd_err_name(e), &ec);
  }
  if (p->scope == SD_PROFILE_SCOPE_SERVICE) {
    sd_free(p);
    return fail_as(a, "location_service", 2, &ec);
  }
  if ((add && !p->network_location) || (!add && p->network_location)) {
    p->network_location = add ? 1 : 0;
    e = sd_profile_save_ex(p, 1);
    if (e != SD_OK) {
      sd_free(p);
      return fail_code(a, "io_error", sd_err_name(e), &ec);
    }
  }
  if (add) {
    int created = 0;
    rc = location_result(a, explorer_location_add(p->id, p->name, &created), &ec);
    flag = created;
  } else {
    int removed = 0;
    rc = location_result(a, explorer_location_remove(p->id, &removed), &ec);
    flag = removed;
  }
  if (rc == 0) {
    if (a->json) {
      sd_wr w;
      sd_json_writer jw;
      sd_wr_init(&w, 4096);
      sd_jw_init(&jw, &w);
      json_result_begin(&jw);
      sd_jw_key(&jw, "action"); sd_jw_cstr(&jw, add ? "add" : "remove");
      sd_jw_key(&jw, "profile_id"); sd_jw_cstr(&jw, p->id);
      sd_jw_key(&jw, "network_location"); sd_jw_bool(&jw, add ? 1 : 0);
      sd_jw_key(&jw, add ? "created" : "removed"); sd_jw_bool(&jw, flag);
      json_result_end(&jw, &w);
      sd_wr_free(&w);
    } else if (!a->quiet) {
      if (!add)
        say_name(SD_MSG_CLI_LOCATION_REMOVED, p->name);
      else if (flag)
        say_name(SD_MSG_CLI_LOCATION_ADDED, p->name);
      else
        say_name(SD_MSG_CLI_LOCATION_PRESENT, p->name);
    }
  }
  sd_free(p);
  return rc;
}

/* location repair: every entry of ours is brought in line with the profiles. */
static int run_repair(const cli_args *a)
{
  err_ctx ec;
  int r, changed = 0;
  memset(&ec, 0, sizeof(ec));
  r = explorer_location_repair(&changed);
  if (r != EXPLORER_LOC_OK)
    return location_result(a, r, &ec);
  if (a->json) {
    sd_wr w;
    sd_json_writer jw;
    sd_wr_init(&w, 4096);
    sd_jw_init(&jw, &w);
    json_result_begin(&jw);
    sd_jw_key(&jw, "action"); sd_jw_cstr(&jw, "repair");
    sd_jw_key(&jw, "changed"); sd_jw_int(&jw, changed);
    json_result_end(&jw, &w);
    sd_wr_free(&w);
  } else if (!a->quiet) {
    sd_arg arg;
    arg.name = "count"; arg.type = SD_ARG_INT; arg.v.i = (long long)changed;
    say(SD_MSG_CLI_LOCATION_REPAIRED, &arg, 1, 0);
  }
  return 0;
}

int cli_run_location(const cli_args *a)
{
  if (wcscmp(a->positional, L"repair") == 0)
    return run_repair(a);
  return run_add_remove(a, wcscmp(a->positional, L"add") == 0);
}
