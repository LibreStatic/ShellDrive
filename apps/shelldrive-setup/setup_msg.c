/* shelldrive-setup: user-visible text. Every message comes from the installer catalog (l10n/installer,
   03 §9, 04 §8.6); this file only supplies the placeholder values of a result. */
#include "setup_int.h"

#include "sd_l10n/sd_l10n.h"

static void set_str(sd_arg *a, const char *name, const wchar_t *s)
{
  a->name = name;
  a->type = SD_ARG_STR;
  a->v.s = s;
}

static void set_int(sd_arg *a, const char *name, long long i)
{
  a->name = name;
  a->type = SD_ARG_INT;
  a->v.i = i;
}

int sd_setup_format_message(const sd_setup_result *r, sd_msg_id id, wchar_t *buf, size_t cch)
{
  /* One argument per placeholder name used by the catalog. Arguments a message does not use are ignored. */
  sd_arg args[9];
  const wchar_t *text = r != NULL ? r->text : L"";
  const wchar_t *folder = r != NULL ? r->folder : L"";
  const wchar_t *version = r != NULL ? r->version : L"";
  const wchar_t *log_path = r != NULL ? r->log_path : L"";
  long long code = r != NULL ? (long long)r->code : 0;
  long long count = r != NULL ? (long long)r->count : 0;

  set_str(&args[0], "flavour", text);
  set_str(&args[1], "name", text);
  set_str(&args[2], "option", text);
  set_str(&args[3], "file", text);
  set_str(&args[4], "path", id == SD_MSG_INSTALLER_LOG_SAVED ? log_path : text);
  set_str(&args[5], "folder", folder);
  set_str(&args[6], "version", version);
  set_int(&args[7], "code", code);
  set_int(&args[8], "count", count);

  return sd_l10n_format(buf, cch, id, args, SD_SETUP_COUNTOF(args));
}
