/* shelldrive diag --bundle [FILE] (03 §10.5, TM-R31): a stored ZIP with the support material of this user.
 *
 * Contents: README.txt (what is in the file and what is not), check.json (the checks of --check), versions.txt,
 * agent.json (the agent's own data, from its diag.collect method, when the agent runs), config/ (settings.ini
 * and the profile files), logs/ (every .log of the logs folder), crash/list.txt (the crash dumps that exist) and,
 * with --include-dumps, the dumps themselves. Round 19 adds the service-side logs of the machine data folder
 * (service-logs/, read only, anonymized like logs/; this holds the Dokany install log, 04 §13) and the newest setup
 * log of the setup folder (setup-logs/, 04 §13).
 *
 * Anonymized by default: host names, user names and remote paths are replaced by tokens (anon_*), in the logs and
 * in the configuration. Secrets are never included, whatever the options: key files, the secrets and keys folders,
 * the per-installation log key and any value whose key names a password, passphrase, token or secret.
 * Nothing is sent: the user attaches the file. The file is created with CREATE_NEW; an existing file is never
 * replaced. */
#include <windows.h>
#include <string.h>
#include <stdio.h>

#include "cli_int.h"
#include "cli_diag.h"
#include "cli_zip.h"
#include "cli_anon.h"
#include "sd/version.h"
#include "sd_base/sd_buf.h"
#include "sd_base/sd_json.h"
#include "sd_base/sd_mem.h"
#include "sd_base/sd_utf.h"
#include "sd_config/sd_config.h"
#include "sd_ipc/sd_ipc.h"
#include "sd_l10n/sd_l10n.h"
#include "sd_l10n_cli_ids.h"

/* Appends a NUL-terminated text as raw bytes (sd_wr_cstring writes a length-prefixed SSH string). */
static void wr_text(sd_wr *w, const char *s)
{
  sd_wr_bytes(w, s, strlen(s));
}

#define BUNDLE_MAX_FILES      4096u
#define BUNDLE_LINE_OMITTED   "<line omitted: too many fields>"

typedef struct bundle_ctx {
  HANDLE file;
  zip_writer *zip;
  anon_ctx *anon;
  SYSTEMTIME now;
  int anonymized;
  unsigned files_skipped;
} bundle_ctx;

/* ---- the archive sink ---- */

static int sink_write(void *ctx, const void *p, size_t n)
{
  HANDLE h = (HANDLE)ctx;
  const unsigned char *b = (const unsigned char *)p;
  while (n) {
    DWORD chunk = n > 0x10000000u ? 0x10000000u : (DWORD)n, wrote = 0;
    if (!WriteFile(h, b, chunk, &wrote, NULL) || wrote == 0)
      return 1;
    b += wrote;
    n -= wrote;
  }
  return 0;
}

/* ---- text entries ---- */

static sd_err add_buffer(bundle_ctx *b, const char *name, const void *p, size_t n)
{
  sd_err e = zip_add_begin(b->zip, name, &b->now);
  if (e != SD_OK)
    return e;
  if (n)
    e = zip_add_data(b->zip, p, n);
  if (e != SD_OK)
    return e;
  return zip_add_end(b->zip);
}

/* Copies a file line by line through the anonymizer (config = configuration syntax). Lines the anonymizer cannot
   process are replaced by a marker, never copied raw. A file that cannot be read is skipped (counted). */
static sd_err add_text_file(bundle_ctx *b, const wchar_t *path, const char *entry, int config)
{
  char *buf = NULL;
  size_t len = 0, start = 0, i;
  sd_wr line, out;
  sd_err e = SD_OK;
  if (!diag_read_file(path, &buf, &len)) {
    b->files_skipped++;
    return SD_OK;
  }
  sd_wr_init(&line, 4096);
  sd_wr_init(&out, 4096);
  e = zip_add_begin(b->zip, entry, &b->now);
  for (i = 0; e == SD_OK && i <= len; i++) {
    if (i == len || buf[i] == '\n') {
      size_t end = i;
      if (i == len && start == len)
        break;
      if (end > start && buf[end - 1] == '\r')
        end--;
      sd_wr_reset(&line);
      sd_wr_reset(&out);
      if (config)
        e = anon_config_line(b->anon, buf + start, end - start, &line);
      else
        e = anon_log_line(b->anon, buf + start, end - start, &line);
      if (e != SD_OK) {
        /* the anonymizer refused this line: the marker keeps the rest of the file readable */
        wr_text(&out, BUNDLE_LINE_OMITTED);
        e = SD_OK;
      } else {
        sd_wr_bytes(&out, line.p, line.len);
      }
      wr_text(&out, "\r\n");
      if (sd_wr_ok(&out))
        e = zip_add_data(b->zip, out.p, out.len);
      else
        e = SD_E_NO_MEMORY;
      start = i + 1;
    }
  }
  if (e == SD_OK)
    e = zip_add_end(b->zip);
  sd_wr_free(&line);
  sd_wr_free(&out);
  sd_free(buf);
  return e;
}

/* ---- folders ---- */

/* Calls add for each file of dir that matches pattern (e.g. "*.log"). Folders are skipped. */
typedef sd_err (*file_fn)(bundle_ctx *b, const wchar_t *path, const wchar_t *name, void *ctx);

static sd_err for_each_file(bundle_ctx *b, const wchar_t *dir, const wchar_t *pattern, file_fn fn, void *ctx)
{
  WIN32_FIND_DATAW fd;
  HANDLE h;
  wchar_t spec[MAX_PATH];
  sd_err e = SD_OK;
  unsigned n = 0;
  if (_snwprintf_s(spec, SD_COUNTOF(spec), _TRUNCATE, L"%s\\%s", dir, pattern) < 0)
    return SD_E_INVALID_PARAM;
  h = FindFirstFileW(spec, &fd);
  if (h == INVALID_HANDLE_VALUE)
    return SD_OK;
  do {
    wchar_t path[MAX_PATH];
    if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
      continue;
    if (++n > BUNDLE_MAX_FILES) {
      e = SD_E_FAILURE;
      break;
    }
    _snwprintf_s(path, SD_COUNTOF(path), _TRUNCATE, L"%s\\%s", dir, fd.cFileName);
    e = fn(b, path, fd.cFileName, ctx);
  } while (e == SD_OK && FindNextFileW(h, &fd));
  FindClose(h);
  return e;
}

/* Wide file name to a UTF-8 entry name under prefix ("logs/"). */
static sd_err entry_name(const char *prefix, const wchar_t *name, char *out, size_t cap)
{
  char *u = NULL;
  size_t n;
  if (sd_wide_to_utf8_alloc(name, (size_t)-1, SD_UTF_REPLACE, &u) != SD_OK)
    return SD_E_INVALID_PARAM;
  n = strlen(prefix) + strlen(u);
  if (n + 1 > cap) {
    sd_free(u);
    return SD_E_INVALID_PARAM;
  }
  strcpy_s(out, cap, prefix);
  strcat_s(out, cap, u);
  sd_free(u);
  return SD_OK;
}

/* Profiles: the values of host, user, remote_path and identity are registered before any log is read, so the
   same values are hidden in the logs too. The profile lines themselves go through anon_config_line. */
static void register_profile_values(anon_ctx *c, const char *buf, size_t len)
{
  size_t start = 0, i;
  for (i = 0; i <= len; i++) {
    if (i == len || buf[i] == '\n') {
      size_t end = i, eq = start, ks, ke, vs, ve;
      char kind = 0;
      char v[512];
      if (end > start && buf[end - 1] == '\r') end--;
      while (eq < end && buf[eq] != '=') eq++;
      if (eq < end) {
        ks = start;
        while (ks < eq && (buf[ks] == ' ' || buf[ks] == '\t')) ks++;
        ke = eq;
        while (ke > ks && (buf[ke - 1] == ' ' || buf[ke - 1] == '\t')) ke--;
        vs = eq + 1;
        while (vs < end && (buf[vs] == ' ' || buf[vs] == '\t')) vs++;
        ve = end;
        while (ve > vs && (buf[ve - 1] == ' ' || buf[ve - 1] == '\t')) ve--;
        if (ve > vs && ve - vs < sizeof(v)) {
          size_t kl = ke - ks;
          if (kl == 4 && _strnicmp(buf + ks, "host", 4) == 0) kind = 'h';
          else if (kl == 4 && _strnicmp(buf + ks, "user", 4) == 0) kind = 'u';
          else if (kl == 11 && _strnicmp(buf + ks, "remote_path", 11) == 0) kind = 'p';
          else if (kl == 8 && _strnicmp(buf + ks, "identity", 8) == 0) kind = 'p';
          if (kind) {
            memcpy(v, buf + vs, ve - vs);
            v[ve - vs] = 0;
            anon_add_value(c, kind, v);
          }
        }
      }
    }
    if (i < len && buf[i] == '\n')
      start = i + 1;
    else if (i == len)
      break;
  }
}

static sd_err profile_register(bundle_ctx *b, const wchar_t *path, const wchar_t *name, void *ctx)
{
  char *buf = NULL;
  size_t len = 0;
  SD_UNUSED(ctx);
  SD_UNUSED(name);
  if (diag_read_file(path, &buf, &len)) {
    if (b->anonymized)
      register_profile_values(b->anon, buf, len);
    sd_free(buf);
  }
  return SD_OK;
}

static sd_err profile_copy(bundle_ctx *b, const wchar_t *path, const wchar_t *name, void *ctx)
{
  char entry[MAX_PATH * 2];
  SD_UNUSED(ctx);
  if (entry_name("config/profiles/", name, entry, sizeof(entry)) != SD_OK)
    return SD_OK;
  return add_text_file(b, path, entry, 1);
}

static sd_err log_copy(bundle_ctx *b, const wchar_t *path, const wchar_t *name, void *ctx)
{
  char entry[MAX_PATH * 2];
  SD_UNUSED(ctx);
  if (entry_name("logs/", name, entry, sizeof(entry)) != SD_OK)
    return SD_OK;
  return add_text_file(b, path, entry, 0);
}

static sd_err service_log_copy(bundle_ctx *b, const wchar_t *path, const wchar_t *name, void *ctx)
{
  char entry[MAX_PATH * 2];
  SD_UNUSED(ctx);
  if (entry_name("service-logs/", name, entry, sizeof(entry)) != SD_OK)
    return SD_OK;
  return add_text_file(b, path, entry, 0);
}

/* The newest setup log: the file names carry a local timestamp (yyyymmdd-hhmmss), so the largest name is the newest. */
typedef struct newest_ctx { wchar_t name[MAX_PATH]; } newest_ctx;

static sd_err newest_one(bundle_ctx *b, const wchar_t *path, const wchar_t *name, void *ctx)
{
  newest_ctx *n = (newest_ctx *)ctx;
  SD_UNUSED(b);
  SD_UNUSED(path);
  if (wcscmp(name, n->name) > 0)
    wcscpy_s(n->name, SD_COUNTOF(n->name), name);
  return SD_OK;
}

static sd_err setup_log_copy(bundle_ctx *b, const wchar_t *path, const wchar_t *name, void *ctx)
{
  newest_ctx *n = (newest_ctx *)ctx;
  char entry[MAX_PATH * 2];
  if (wcscmp(name, n->name) != 0)
    return SD_OK;
  if (entry_name("setup-logs/", name, entry, sizeof(entry)) != SD_OK)
    return SD_OK;
  return add_text_file(b, path, entry, 0);
}

/* crash/list.txt: one line per dump (name and size); with include_dumps the file is copied in chunks. */
typedef struct crash_ctx { int include; int listed; sd_wr *list; } crash_ctx;

static sd_err crash_one(bundle_ctx *b, const wchar_t *path, const wchar_t *name, void *ctx)
{
  crash_ctx *cc = (crash_ctx *)ctx;
  HANDLE h;
  LARGE_INTEGER size;
  char entry[MAX_PATH * 2];
  char *u = NULL;
  sd_err e;
  if (entry_name("crash/", name, entry, sizeof(entry)) != SD_OK)
    return SD_OK;
  if (sd_wide_to_utf8_alloc(name, (size_t)-1, SD_UTF_REPLACE, &u) != SD_OK)
    return SD_OK;
  h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  if (h == INVALID_HANDLE_VALUE || !GetFileSizeEx(h, &size)) {
    if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
    sd_free(u);
    return SD_OK;
  }
  wr_text(cc->list, u);
  wr_text(cc->list, "\t");
  {
    char num[32];
    sprintf_s(num, sizeof(num), "%llu", (unsigned long long)size.QuadPart);
    wr_text(cc->list, num);
  }
  wr_text(cc->list, "\r\n");
  cc->listed++;
  if (!cc->include) {
    CloseHandle(h);
    sd_free(u);
    return SD_OK;
  }
  e = zip_add_begin(b->zip, entry, &b->now);
  while (e == SD_OK) {
    unsigned char chunk[8192];
    DWORD got = 0;
    if (!ReadFile(h, chunk, sizeof(chunk), &got, NULL)) {
      e = SD_E_FAILURE;
      break;
    }
    if (got == 0)
      break;
    e = zip_add_data(b->zip, chunk, got);
  }
  if (e == SD_OK)
    e = zip_add_end(b->zip);
  CloseHandle(h);
  sd_free(u);
  return e;
}

/* ---- the agent's own data (diag.collect) ---- */

static void write_agent_json(bundle_ctx *b)
{
  sd_ipc_hello hello;
  sd_ipc_conn *c = NULL;
  sd_json *res = NULL;
  sd_ipc_error err;
  sd_wr w;
  sd_json_writer jw;
  sd_wr_init(&w, 4096);
  sd_jw_init(&jw, &w);
  if (sd_ipc_connect(SD_IPC_AGENT, quiet_hello(&hello), 0, 5000, &c) == SD_OK &&
      sd_ipc_call_raw(c, "diag.collect", NULL, 0, CALL_TIMEOUT, &res, &err) == SD_OK) {
    sd_jw_value(&jw, res);
  } else {
    sd_jw_obj_begin(&jw);
    sd_jw_key(&jw, "running"); sd_jw_bool(&jw, 0);
    sd_jw_obj_end(&jw);
  }
  if (sd_jw_finish(&jw) == SD_OK)
    add_buffer(b, "agent.json", w.p, w.len);
  sd_json_free(res);
  if (c)
    sd_ipc_close(c);
  sd_wr_free(&w);
}

/* ---- the whole bundle ---- */

static void utf8_line(sd_wr *w, const char *s)
{
  wr_text(w, s);
  wr_text(w, "\r\n");
}

static void write_readme(bundle_ctx *b, const cli_args *a)
{
  sd_wr w;
  char line[256];
  sd_wr_init(&w, 2048);
  utf8_line(&w, "ShellDrive diagnostic bundle");
  sprintf_s(line, sizeof(line), "Created (local time): %04u-%02u-%02u %02u:%02u:%02u",
            (unsigned)b->now.wYear, (unsigned)b->now.wMonth, (unsigned)b->now.wDay, (unsigned)b->now.wHour,
            (unsigned)b->now.wMinute, (unsigned)b->now.wSecond);
  utf8_line(&w, line);
  sprintf_s(line, sizeof(line), "Version: %s (%s, commit %s)", SD_VERSION_STRING, SD_FLAVOUR_NAME, SD_GIT_COMMIT);
  utf8_line(&w, line);
  utf8_line(&w, "");
  if (b->anonymized) {
    utf8_line(&w, "Anonymized: yes. Host names, user names and remote paths are replaced by tokens:");
    utf8_line(&w, "  h:xxxxxx host, u:xxxxxx user name, p:xxxxxx remote path. The same value always has the same");
    utf8_line(&w, "  token inside this bundle; the tokens cannot be compared with other bundles.");
  } else {
    utf8_line(&w, "Anonymized: no (--no-anonymize). Host names, user names and remote paths are included.");
  }
  utf8_line(&w, "Never included: passwords, passphrases, tokens and other secrets, key files, the secrets and keys");
  utf8_line(&w, "folders and the per-installation log key.");
  if (a->include_dumps)
    utf8_line(&w, "Crash dumps are included (--include-dumps). They can contain file names and file content.");
  else
    utf8_line(&w, "Crash dumps are not included; crash/list.txt names them.");
  utf8_line(&w, "");
  utf8_line(&w, "Nothing was sent. Attach this file yourself when you report a problem.");
  if (sd_wr_ok(&w))
    add_buffer(b, "README.txt", w.p, w.len);
  sd_wr_free(&w);
}

static void write_versions(bundle_ctx *b)
{
  sd_wr w;
  char line[256];
  sd_wr_init(&w, 512);
  sprintf_s(line, sizeof(line), "ShellDrive %s", SD_VERSION_STRING);
  utf8_line(&w, line);
  sprintf_s(line, sizeof(line), "commit %s", SD_GIT_COMMIT);
  utf8_line(&w, line);
  sprintf_s(line, sizeof(line), "flavour %s", SD_FLAVOUR_NAME);
  utf8_line(&w, line);
  if (sd_wr_ok(&w))
    add_buffer(b, "versions.txt", w.p, w.len);
  sd_wr_free(&w);
}

static void write_check_json(bundle_ctx *b)
{
  diag_report r;
  sd_wr w;
  sd_json_writer jw;
  diag_collect(diag_env_current(), &r);
  sd_wr_init(&w, 16 * 1024);
  sd_jw_init(&jw, &w);
  sd_jw_obj_begin(&jw);
  sd_jw_key(&jw, "ok"); sd_jw_bool(&jw, 1);
  sd_jw_key(&jw, "result");
  diag_json_result(&r, &jw);
  sd_jw_obj_end(&jw);
  if (sd_jw_finish(&jw) == SD_OK)
    add_buffer(b, "check.json", w.p, w.len);
  sd_wr_free(&w);
}

static int bundle_path_default(wchar_t *out, size_t cch)
{
  SYSTEMTIME st;
  GetLocalTime(&st);
  return _snwprintf_s(out, cch, _TRUNCATE, L"shelldrive-diag-%04u%02u%02u-%02u%02u%02u.zip", (unsigned)st.wYear,
                      (unsigned)st.wMonth, (unsigned)st.wDay, (unsigned)st.wHour, (unsigned)st.wMinute,
                      (unsigned)st.wSecond) > 0;
}

int cli_run_diag_bundle(const cli_args *a)
{
  wchar_t default_name[64], root[MAX_PATH], profiles[MAX_PATH], logs[MAX_PATH], crash[MAX_PATH];
  const wchar_t *path = a->bundle_file ? a->bundle_file : default_name;
  bundle_ctx b;
  sd_wr list;
  crash_ctx cc;
  HANDLE h;
  err_ctx ec;
  wchar_t num[24];
  DWORD err;
  unsigned files;
  int rc = 0;

  memset(&b, 0, sizeof(b));
  memset(&ec, 0, sizeof(ec));
  if (a->bundle_file == NULL && !bundle_path_default(default_name, SD_COUNTOF(default_name)))
    return fail_code(a, "io_error", "file name", &ec);
  b.anonymized = !a->no_anonymize;
  GetLocalTime(&b.now);
  if (sd_config_root(root, SD_COUNTOF(root)) != SD_OK || sd_config_profiles_dir(profiles, SD_COUNTOF(profiles)) != SD_OK ||
      sd_config_logs_dir(logs, SD_COUNTOF(logs)) != SD_OK)
    return fail_code(a, "io_error", "no per-user folder", &ec);
  _snwprintf_s(crash, SD_COUNTOF(crash), _TRUNCATE, L"%s\\crash", logs);

  if (a->no_anonymize && !a->json)
    say(SD_MSG_CLI_DIAG_BUNDLE_NO_ANON, NULL, 0, 1);
  if (a->include_dumps && !a->json)
    say(SD_MSG_CLI_DIAG_BUNDLE_DUMPS_NOTE, NULL, 0, 1);

  /* the file: CREATE_NEW, never a replacement */
  h = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
  if (h == INVALID_HANDLE_VALUE) {
    err = GetLastError();
    if (err == ERROR_FILE_EXISTS || err == ERROR_ALREADY_EXISTS) {
      if (a->json) json_err("io_error", "the file already exists", 1);
      else {
        sd_arg arg;
        arg.name = "path"; arg.type = SD_ARG_STR; arg.v.s = path;
        say(SD_MSG_CLI_DIAG_BUNDLE_EXISTS, &arg, 1, 1);
      }
      return 1;
    }
    if (a->json) json_err("io_error", "the file cannot be created", 1);
    else {
      sd_arg arg;
      arg.name = "code"; arg.type = SD_ARG_STR; arg.v.s = decimal(num, SD_COUNTOF(num), (long long)err);
      say(SD_MSG_CLI_DIAG_BUNDLE_FAILED, &arg, 1, 1);
    }
    return 1;
  }

  b.file = h;
  b.anon = anon_new(b.anonymized);
  b.zip = b.anon ? zip_open(sink_write, h) : NULL;
  if (b.zip == NULL) {
    if (b.anon) anon_free(b.anon);
    CloseHandle(h);
    DeleteFileW(path);
    return fail_code(a, "io_error", "out of memory", &ec);
  }

  /* profiles first (their values are hidden in the logs), then the rest */
  for_each_file(&b, profiles, L"*.ini", profile_register, NULL);
  {
    wchar_t settings[MAX_PATH];
    _snwprintf_s(settings, SD_COUNTOF(settings), _TRUNCATE, L"%s\\settings.ini", root);
    add_text_file(&b, settings, "config/settings.ini", 1);
  }
  write_readme(&b, a);
  write_versions(&b);
  write_check_json(&b);
  write_agent_json(&b);
  for_each_file(&b, profiles, L"*.ini", profile_copy, NULL);
  for_each_file(&b, logs, L"*.log", log_copy, NULL);

  /* service-side logs of the machine data folder, and the newest setup log (04 §13); read only */
  {
    const diag_env *env = diag_env_current();
    wchar_t mroot[MAX_PATH], mlogs[MAX_PATH], setup_dir[MAX_PATH];
    newest_ctx nc;
    if (sd_config_machine_root(mroot, SD_COUNTOF(mroot)) == SD_OK) {
      _snwprintf_s(mlogs, SD_COUNTOF(mlogs), _TRUNCATE, L"%s\\logs", mroot);
      for_each_file(&b, mlogs, L"*.log", service_log_copy, NULL);
    }
    if (env->setup_log_dir(env->ctx, setup_dir, SD_COUNTOF(setup_dir))) {
      size_t n = wcslen(setup_dir);
      if (n > 0 && setup_dir[n - 1] == L'\\')
        setup_dir[n - 1] = 0;
      memset(&nc, 0, sizeof(nc));
      for_each_file(&b, setup_dir, L"ShellDrive-setup-*.log", newest_one, &nc);
      if (nc.name[0] != 0)
        for_each_file(&b, setup_dir, L"ShellDrive-setup-*.log", setup_log_copy, &nc);
    }
  }

  sd_wr_init(&list, 1024);
  memset(&cc, 0, sizeof(cc));
  cc.include = a->include_dumps;
  cc.list = &list;
  for_each_file(&b, crash, L"*.dmp", crash_one, &cc);
  add_buffer(&b, "crash/list.txt", list.p, list.len);
  sd_wr_free(&list);

  if (zip_finish(b.zip) != SD_OK) {
    rc = 1;
  }
  files = zip_entry_count(b.zip);
  zip_free(b.zip);
  anon_free(b.anon);
  CloseHandle(h);
  if (rc) {
    DeleteFileW(path);   /* a partial file is ours (CREATE_NEW above) and is removed */
    if (a->json) json_err("io_error", "the bundle could not be written", 1);
    else {
      sd_arg arg;
      arg.name = "code"; arg.type = SD_ARG_STR; arg.v.s = decimal(num, SD_COUNTOF(num), (long long)GetLastError());
      say(SD_MSG_CLI_DIAG_BUNDLE_FAILED, &arg, 1, 1);
    }
    return 1;
  }

  if (a->json) {
    sd_wr w;
    sd_json_writer jw;
    char *u = NULL;
    sd_wr_init(&w, 2048);
    sd_jw_init(&jw, &w);
    sd_wide_to_utf8_alloc(path, (size_t)-1, SD_UTF_REPLACE, &u);
    sd_jw_obj_begin(&jw);
    sd_jw_key(&jw, "ok"); sd_jw_bool(&jw, 1);
    sd_jw_key(&jw, "result"); sd_jw_obj_begin(&jw);
    sd_jw_key(&jw, "path"); sd_jw_cstr(&jw, u ? u : "");
    sd_jw_key(&jw, "files"); sd_jw_int(&jw, files);
    sd_jw_key(&jw, "anonymized"); sd_jw_bool(&jw, b.anonymized);
    sd_jw_key(&jw, "dumps"); sd_jw_bool(&jw, a->include_dumps);
    sd_jw_key(&jw, "files_skipped"); sd_jw_int(&jw, b.files_skipped);
    sd_jw_obj_end(&jw);
    sd_jw_obj_end(&jw);
    if (sd_jw_finish(&jw) == SD_OK)
      cli_print_utf8_line((const char *)w.p, w.len);
    sd_wr_free(&w);
    sd_free(u);
  } else {
    sd_arg args[2];
    args[0].name = "path"; args[0].type = SD_ARG_STR; args[0].v.s = path;
    args[1].name = "count"; args[1].type = SD_ARG_INT; args[1].v.i = files;
    say(SD_MSG_CLI_DIAG_BUNDLE_WRITTEN, args, 2, 0);
  }
  return 0;
}
