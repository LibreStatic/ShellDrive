/* shelldrive.exe commands that do not mount (03 §6.1): status (detailed per-drive state),
 * profile import (the sd_import preview table, 03 §3.7) and hostkey list/import/remove (the
 * sd_known_hosts manager in this process, 03 §5.1/C19, §5.5) plus accept-announced, which applies
 * a reviewed UpdateHostKeys announcement held by the agent (03 §5.6, D16).
 *
 * Exit codes follow 03 §6.2: usage 2, not found 3 (host key, announcement, session, file),
 * agent unavailable 8, access denied 9. Every user-facing string comes from the cli catalog; JSON
 * keys, store names and error codes stay English. */
#include <windows.h>
#include <string.h>

#include "cli_int.h"
#include "sd_base/sd_mem.h"
#include "sd_base/sd_utf.h"
#include "sd_config/sd_config.h"
#include "sd_config/sd_import.h"
#include "sd_ipc/sd_ipc.h"
#include "sd_l10n/sd_l10n.h"
#include "sd_l10n_cli_ids.h"
#include "sd_ssh/sd_known_hosts.h"

/* ---- small shared helpers ---- */

static void pad_print(wchar_t *line, size_t cap, size_t *len, const wchar_t *s, size_t width)
{
  size_t n = wcslen(s), i;
  for (i = 0; i < n && *len + 1 < cap; i++) line[(*len)++] = s[i];
  for (; i < width && *len + 1 < cap; i++) line[(*len)++] = L' ';
  if (*len + 1 < cap) line[(*len)++] = L' ';
  line[*len] = 0;
}

/* "[user@]host[:port]" -> the known_hosts lookup name (01 §7.1): lowercase host, "[host]:port"
   when the port is not 22. Returns 0 on a bad spec. */
static int lookup_name_of(const wchar_t *spec, char *out, size_t cap)
{
  char user[128], host[256];
  uint16_t port = 22;
  size_t i;
  if (sd_parse_host_spec(spec, user, sizeof(user), host, sizeof(host), &port) != SD_OK || host[0] == 0)
    return 0;
  for (i = 0; host[i]; i++)
    if (host[i] >= 'A' && host[i] <= 'Z') host[i] = (char)(host[i] - 'A' + 'a');
  strcpy_s(out, cap, host);
  if (port != 22) {
    char bracket[320];
    size_t k = 0;
    uint32_t v = port;
    char p[8];
    bracket[0] = 0;
    strcat_s(bracket, sizeof(bracket), "[");
    strcat_s(bracket, sizeof(bracket), host);
    strcat_s(bracket, sizeof(bracket), "]:");
    do { p[k++] = (char)('0' + v % 10u); v /= 10u; } while (v && k < sizeof(p) - 1);
    while (k) {
      size_t bl = strlen(bracket);
      if (bl + 2 >= sizeof(bracket))
        return 0;
      bracket[bl] = p[--k];
      bracket[bl + 1] = 0;
    }
    if (strlen(bracket) >= cap)
      return 0;
    strcpy_s(out, cap, bracket);
  }
  return 1;
}

static const char *kh_store_name(sd_kh_store_kind k)
{
  switch (k) {
  case SD_KH_STORE_MACHINE: return "machine";
  case SD_KH_STORE_USER:    return "user";
  case SD_KH_SRC_OPENSSH:   return "openssh";
  case SD_KH_SRC_PUTTY:     return "putty";
  default:                  return "?";
  }
}

/* Opens the store list the mount would use: the machine store (read-only for users), the writable
   user store at <root>\known_hosts, and, when with_sources, the live sources of settings.ini (5.1). */
static int kh_open(int with_sources, sd_known_hosts **out)
{
  sd_kh_store stores[4];
  uint32_t n = 0;
  wchar_t root[MAX_PATH];
  static wchar_t user_kh[MAX_PATH];
  sd_settings st;
  user_kh[0] = 0;
  if (sd_config_root(root, SD_COUNTOF(root)) == SD_OK &&
      wcslen(root) + 13 < SD_COUNTOF(user_kh)) {
    memcpy(user_kh, root, (wcslen(root) + 1) * sizeof(wchar_t));
    wcscat_s(user_kh, SD_COUNTOF(user_kh), L"\\known_hosts");
  }
  memset(&stores[0], 0, sizeof(stores));
  stores[n].kind = SD_KH_STORE_MACHINE; stores[n].path = NULL; stores[n].writable = 0; n++;
  stores[n].kind = SD_KH_STORE_USER; stores[n].path = user_kh[0] ? user_kh : NULL;
  stores[n].writable = 1; n++;
  if (with_sources) {
    sd_settings_defaults(&st);
    if (sd_settings_load(&st) == SD_OK) {
      if (st.openssh_source) { stores[n].kind = SD_KH_SRC_OPENSSH; n++; }
      if (st.putty_source) { stores[n].kind = SD_KH_SRC_PUTTY; n++; }
    }
  }
  return sd_known_hosts_open(stores, n, out) == SD_OK;
}

/* ---- status ---- */

/* M2: an offline mount whose session is still trying shows "reconnecting". */
static sd_msg_id status_state_msg(const sd_json *m)
{
  const char *st = sd_json_get_str(m, "state");
  const char *sess = sd_json_get_str(sd_json_get(m, "connection"), "session");
  if (is(st, "offline") && (is(sess, "disconnected") || is(sess, "reconnect_wait") || is(sess, "connecting")))
    return SD_MSG_CLI_STATE_RECONNECTING;
  if (is(st, "connecting")) return SD_MSG_CLI_STATE_CONNECTING;
  if (is(st, "authenticating")) return SD_MSG_CLI_STATE_AUTHENTICATING;
  if (is(st, "mounted")) return SD_MSG_CLI_STATE_MOUNTED;
  if (is(st, "offline")) return SD_MSG_CLI_STATE_OFFLINE;
  if (is(st, "auth_required")) return SD_MSG_CLI_STATE_AUTH_REQUIRED;
  if (is(st, "unmounting")) return SD_MSG_CLI_STATE_UNMOUNTING;
  if (is(st, "unmounted")) return SD_MSG_CLI_STATE_UNMOUNTED;
  return SD_MSG_CLI_STATE_FAILED;
}

static void server_of(const sd_json *m, char *out, size_t cap)
{
  const char *h = sd_json_get_str(m, "host"), *u = sd_json_get_str(m, "user");
  int64_t port = 22;
  size_t o = 0, k;
  sd_json_get_int64(m, "port", &port);
  out[0] = 0;
  if (!u || !h || strlen(u) + strlen(h) + 16 >= cap)
    return;
  for (k = 0; u[k]; k++) out[o++] = u[k];
  out[o++] = '@';
  for (k = 0; h[k]; k++) out[o++] = h[k];
  if (port != 22) {
    char tmp[8];
    size_t tn = 0;
    int64_t v = port;
    out[o++] = ':';
    do { tmp[tn++] = (char)('0' + v % 10); v /= 10; } while (v && tn < 7);
    while (tn) out[o++] = tmp[--tn];
  }
  out[o] = 0;
}

/* The name matches the drive letter, the mount id ("m-...") or the profile name/id (the profile
   name case-insensitively, like sd_profile_find). */
static int mount_matches(const sd_json *m, const wchar_t *name)
{
  wchar_t letter = sd_parse_drive_letter(name);
  const char *id = sd_json_get_str(m, "mount_id"), *p = sd_json_get_str(m, "profile");
  wchar_t *wp;
  if (letter) {
    char t[3];
    t[0] = (char)letter; t[1] = ':'; t[2] = 0;
    return is(sd_json_get_str(m, "target"), t);
  }
  if (wcsncmp(name, L"m-", 2) == 0) {
    wchar_t *w = wide(id);
    int r = w && wcscmp(w, name) == 0;
    sd_free(w);
    return r;
  }
  wp = wide(p);
  {
    int r = wp && _wcsicmp(wp, name) == 0;
    sd_free(wp);
    return r;
  }
}

int cli_run_status(const cli_args *a)
{
  sd_ipc_hello hello;
  sd_ipc_conn *c = NULL;
  sd_ipc_error err;
  sd_json *res = NULL;
  const sd_json *arr;
  size_t i, n, shown = 0;
  int rc;
  if (a->stats)                                      /* status --stats (M3, 03 §6.1) */
    return cli_run_status_stats(a);
  if (sd_ipc_connect(SD_IPC_AGENT, quiet_hello(&hello), 0, 5000, &c) != SD_OK) {
    /* no agent: nothing is mounted in this session */
    if (a->positional) {
      err_ctx ec;
      memset(&ec, 0, sizeof(ec));
      ec.name = a->positional;
      return fail_code(a, "mount_not_found", "agent not running", &ec);
    }
    if (a->json) {
      static const char k[] = "{\"ok\":true,\"result\":{\"mounts\":[]}}";
      cli_print_utf8_line(k, sizeof(k) - 1);
    } else {
      say(SD_MSG_CLI_LIST_EMPTY, NULL, 0, 0);
    }
    return 0;
  }
  if (sd_ipc_call_raw(c, "list", NULL, 0, CALL_TIMEOUT, &res, &err) != SD_OK) {
    rc = fail_ipc(a, &err, NULL);
    sd_ipc_close(c);
    return rc;
  }
  sd_ipc_close(c);
  arr = sd_json_get(res, "mounts");
  n = sd_json_count(arr);
  if (a->json) {
    int any = 0;
    sd_wr w;
    sd_json_writer jw;
    for (i = 0; i < n && !any; i++)
      any = a->positional == NULL || mount_matches(sd_json_at(arr, i), a->positional);
    if (a->positional && !any) {
      sd_json_free(res);
      return fail_code(a, "mount_not_found", "no matching mount", NULL);
    }
    sd_wr_init(&w, SD_IPC_MAX_MESSAGE);
    sd_jw_init(&jw, &w);
    sd_jw_obj_begin(&jw);
    sd_jw_key(&jw, "ok"); sd_jw_bool(&jw, 1);
    sd_jw_key(&jw, "result");
    sd_jw_obj_begin(&jw);
    sd_jw_key(&jw, "mounts");
    sd_jw_arr_begin(&jw);
    for (i = 0; i < n; i++) {
      const sd_json *m = sd_json_at(arr, i);
      if (a->positional == NULL || mount_matches(m, a->positional))
        sd_jw_value(&jw, m);
    }
    sd_jw_arr_end(&jw);
    sd_jw_obj_end(&jw);
    sd_jw_obj_end(&jw);
    if (sd_jw_finish(&jw) == SD_OK)
      cli_print_utf8_line((const char *)w.p, w.len);
    sd_wr_free(&w);
    sd_json_free(res);
    return 0;
  }
  for (i = 0; i < n; i++) {
    const sd_json *m = sd_json_at(arr, i);
    if (a->positional && !mount_matches(m, a->positional))
      continue;
    shown++;
    {
      const sd_json *conn = sd_json_get(m, "connection");
      const char *sess = sd_json_get_str(conn, "session"), *reason = sd_json_get_str(conn, "reason");
      int64_t pool = 0, wanted = 0, wfail = 0, rec = 0;
      char server[512];
      wchar_t *t = wide(sd_json_get_str(m, "target")), *p = wide(sd_json_get_str(m, "profile"));
      wchar_t *ws, *wstate;
      wchar_t line[1024];
      size_t len = 0;
      wchar_t pbuf[24], wbuf[24], rbuf[24];
      sd_arg args[3];
      server_of(m, server, sizeof(server));
      ws = wide(server);
      line[0] = 0;
      len = 0;
      pad_print(line, SD_COUNTOF(line), &len, t ? t : L"?", 8);
      pad_print(line, SD_COUNTOF(line), &len, sd_l10n_get(status_state_msg(m)), 22);
      pad_print(line, SD_COUNTOF(line), &len, ws ? ws : L"", 30);
      pad_print(line, SD_COUNTOF(line), &len, p ? p : L"", 0);
      cli_print(line);
      sd_free(t); sd_free(p); sd_free(ws);
      wstate = wide(sess ? sess : "");
      args[0].name = "state"; args[0].type = SD_ARG_STR; args[0].v.s = wstate ? wstate : L"";
      say(SD_MSG_CLI_STATUS_CONN, args, 1, 0);
      sd_free(wstate);
      sd_json_get_int64(m, "pool", &pool);
      sd_json_get_int64(m, "pool_wanted", &wanted);
      if (pool || wanted > 1) {
        args[0].name = "count"; args[0].type = SD_ARG_STR; args[0].v.s = decimal(pbuf, SD_COUNTOF(pbuf), pool);
        args[1].name = "wanted"; args[1].type = SD_ARG_STR; args[1].v.s = decimal(wbuf, SD_COUNTOF(wbuf), wanted);
        say(SD_MSG_CLI_STATUS_POOL, args, 2, 0);
      }
      sd_json_get_int64(conn, "reconnects", &rec);
      if (rec > 0) {
        args[0].name = "count"; args[0].type = SD_ARG_STR; args[0].v.s = decimal(rbuf, SD_COUNTOF(rbuf), rec);
        say(SD_MSG_CLI_STATUS_RECONNECTS, args, 1, 0);
      }
      if (reason && reason[0]) {
        wchar_t *wr = wide(reason);
        args[0].name = "reason"; args[0].type = SD_ARG_STR; args[0].v.s = wr ? wr : L"";
        say(SD_MSG_CLI_STATUS_REASON, args, 1, 0);
        sd_free(wr);
      }
      sd_json_get_int64(m, "write_failed", &wfail);
      if (wfail > 0) {
        wchar_t *t2 = wide(sd_json_get_str(m, "target")), *lp = wide(sd_json_get_str(m, "last_write_failed"));
        args[0].name = "target"; args[0].type = SD_ARG_STR; args[0].v.s = t2 ? t2 : L"";
        args[1].name = "count"; args[1].type = SD_ARG_INT; args[1].v.i = wfail;
        args[2].name = "path"; args[2].type = SD_ARG_STR; args[2].v.s = lp ? lp : L"";
        say(SD_MSG_CLI_LIST_WRITE_FAILED, args, 3, 0);
        sd_free(t2); sd_free(lp);
      }
    }
  }
  if (a->positional && shown == 0) {
    err_ctx ec;
    memset(&ec, 0, sizeof(ec));
    ec.name = a->positional;
    sd_json_free(res);
    return fail_code(a, "mount_not_found", "no matching mount", &ec);
  }
  sd_json_free(res);
  return 0;
}

/* ---- profile import ---- */

static const char *skip_kind_name(sd_import_skip_kind k)
{
  switch (k) {
  case SD_IMPORT_SKIP_KEYWORD:  return "keyword";
  case SD_IMPORT_SKIP_NOT_SSH:  return "not_ssh";
  case SD_IMPORT_SKIP_PROXY:    return "proxy";
  default:                      return "invalid";
  }
}

static void import_notes(uint32_t flags, wchar_t *out, size_t cap)
{
  out[0] = 0;
  if (flags & SD_IMPORT_F_DUPLICATE) wcscat_s(out, cap, sd_l10n_get(SD_MSG_CLI_PI_NOTE_DUPLICATE));
  if (flags & SD_IMPORT_F_ONLY_THIS_KEY) {
    if (out[0]) wcscat_s(out, cap, L"; ");
    wcscat_s(out, cap, sd_l10n_get(SD_MSG_CLI_PI_NOTE_ONLY_THIS_KEY));
  }
  if (flags & SD_IMPORT_F_PROXY_SKIPPED) {
    if (out[0]) wcscat_s(out, cap, L"; ");
    wcscat_s(out, cap, sd_l10n_get(SD_MSG_CLI_PI_NOTE_PROXY_SKIPPED));
  }
  if (flags & SD_IMPORT_F_NAME_CHANGED) {
    if (out[0]) wcscat_s(out, cap, L"; ");
    wcscat_s(out, cap, sd_l10n_get(SD_MSG_CLI_PI_NOTE_NAME_CHANGED));
  }
}

static void print_import_table(const sd_import_result *r)
{
  size_t i;
  for (i = 0; i < r->count; i++) {
    const sd_import_candidate *c = &r->items[i];
    wchar_t *name = wide(c->source), *server, *wu;
    wchar_t note[512], line[2048];
    size_t len = 0;
    char srv[400];
    int64_t port = c->p.port;
    srv[0] = 0;
    if (c->p.host[0]) {
      strcpy_s(srv, sizeof(srv), c->p.host);
      if (port != 22 && port != 0) {
        char p[8];
        size_t tn = 0, sl = strlen(srv);
        uint32_t v = (uint32_t)port;
        do { p[tn++] = (char)('0' + v % 10u); v /= 10u; } while (v && tn < sizeof(p) - 1);
        while (tn && sl + 1 < sizeof(srv)) { srv[sl++] = ':'; srv[sl++] = p[--tn]; }
        srv[sl] = 0;
      }
    }
    server = wide(srv);
    import_notes(c->flags, note, SD_COUNTOF(note));
    wu = wide(c->p.user);
    line[0] = 0;
    len = 0;
    pad_print(line, SD_COUNTOF(line), &len, name ? name : L"", 24);
    pad_print(line, SD_COUNTOF(line), &len, server ? server : L"", 30);
    pad_print(line, SD_COUNTOF(line), &len, wu ? wu : L"", 16);
    pad_print(line, SD_COUNTOF(line), &len, note, 0);
    cli_print(line);
    sd_free(name); sd_free(server); sd_free(wu);
  }
  for (i = 0; i < r->nskipped; i++) {
    const sd_import_skip *s = &r->skipped[i];
    wchar_t *src = wide(s->source), *item = wide(s->item);
    sd_msg_id id;
    switch (s->kind) {
    case SD_IMPORT_SKIP_KEYWORD:
      id = src && src[0] ? SD_MSG_CLI_PI_SKIP_KEYWORD : SD_MSG_CLI_PI_SKIP_KEYWORD_GLOBAL;
      break;
    case SD_IMPORT_SKIP_NOT_SSH: id = SD_MSG_CLI_PI_SKIP_NOT_SSH; break;
    case SD_IMPORT_SKIP_PROXY:   id = SD_MSG_CLI_PI_SKIP_PROXY; break;
    default:                     id = SD_MSG_CLI_PI_SKIP_INVALID; break;
    }
    if (id == SD_MSG_CLI_PI_SKIP_KEYWORD_GLOBAL) {
      say1w(id, "item", item, 0);
    } else {
      sd_arg args[2];
      args[0].name = "source"; args[0].type = SD_ARG_STR; args[0].v.s = src ? src : L"";
      args[1].name = "item"; args[1].type = SD_ARG_STR; args[1].v.s = item ? item : L"";
      say(id, args, 2, 0);
    }
    sd_free(src); sd_free(item);
  }
}

static void print_import_json(const sd_import_result *r, uint32_t written, int dry_run)
{
  sd_wr w;
  sd_json_writer jw;
  size_t i;
  sd_wr_init(&w, SD_IPC_MAX_MESSAGE);
  sd_jw_init(&jw, &w);
  sd_jw_obj_begin(&jw);
  sd_jw_key(&jw, "ok"); sd_jw_bool(&jw, 1);
  sd_jw_key(&jw, "result");
  sd_jw_obj_begin(&jw);
  sd_jw_key(&jw, "imported"); sd_jw_int(&jw, written);
  sd_jw_key(&jw, "dry_run"); sd_jw_bool(&jw, dry_run);
  sd_jw_key(&jw, "profiles");
  sd_jw_arr_begin(&jw);
  for (i = 0; i < r->count; i++) {
    const sd_import_candidate *c = &r->items[i];
    sd_jw_obj_begin(&jw);
    sd_jw_key(&jw, "source"); sd_jw_cstr(&jw, c->source);
    sd_jw_key(&jw, "name"); sd_jw_cstr(&jw, c->p.name);
    sd_jw_key(&jw, "host"); sd_jw_cstr(&jw, c->p.host);
    sd_jw_key(&jw, "port"); sd_jw_int(&jw, c->p.port);
    sd_jw_key(&jw, "user"); sd_jw_cstr(&jw, c->p.user);
    sd_jw_key(&jw, "selected"); sd_jw_bool(&jw, c->selected);
    sd_jw_key(&jw, "flags"); sd_jw_int(&jw, c->flags);
    sd_jw_obj_end(&jw);
  }
  sd_jw_arr_end(&jw);
  sd_jw_key(&jw, "skipped");
  sd_jw_arr_begin(&jw);
  for (i = 0; i < r->nskipped; i++) {
    const sd_import_skip *s = &r->skipped[i];
    sd_jw_obj_begin(&jw);
    sd_jw_key(&jw, "source"); sd_jw_cstr(&jw, s->source);
    sd_jw_key(&jw, "item"); sd_jw_cstr(&jw, s->item);
    sd_jw_key(&jw, "reason"); sd_jw_cstr(&jw, skip_kind_name(s->kind));
    sd_jw_key(&jw, "line"); sd_jw_int(&jw, s->line);
    sd_jw_obj_end(&jw);
  }
  sd_jw_arr_end(&jw);
  sd_jw_obj_end(&jw);
  sd_jw_obj_end(&jw);
  if (sd_jw_finish(&jw) == SD_OK)
    cli_print_utf8_line((const char *)w.p, w.len);
  sd_wr_free(&w);
}

int cli_run_profile(const cli_args *a)
{
  sd_import_result r;
  if (wcscmp(a->positional, L"test") == 0)            /* profile test <profile> (03 §6.1, M3) */
    return cli_run_profile_test(a);
  err_ctx ec;
  int is_putty = wcscmp(a->arg2, L"putty") == 0;
  uint32_t written = 0;
  sd_err e;
  memset(&ec, 0, sizeof(ec));
  sd_import_result_init(&r);
  if (is_putty) {
    e = sd_import_putty_registry(NULL, NULL, &r);
    if (e == SD_E_NOT_FOUND) {
      sd_import_result_free(&r);
      return fail_code(a, "putty_not_found", "the PuTTY Sessions key does not exist", &ec);
    }
    if (e != SD_OK) {
      sd_import_result_free(&r);
      return fail_code(a, "io_error", sd_err_name(e), &ec);
    }
    if (a->arg3) {
      /* keep only the named session (the decoded session name, case-insensitive) */
      uint32_t i, kept = 0;
      wchar_t want[256];
      size_t got;
      e = sd_utf16_to_utf8(a->arg3, wcslen(a->arg3), (char *)want, sizeof(want) - 1, &got, SD_UTF_STRICT) != SD_OK
          ? SD_E_INVALID_PARAM : SD_OK;
      if (e != SD_OK) {
        sd_import_result_free(&r);
        return fail_code(a, "usage", "invalid session name", &ec);
      }
      ((char *)want)[got] = 0;
      for (i = 0; i < r.count; i++)
        if (_stricmp(r.items[i].source, (const char *)want) == 0)
          r.items[kept++] = r.items[i];
      if (kept == 0) {
        ec.name = a->arg3;
        sd_import_result_free(&r);
        return fail_code(a, "session_not_found", "no such PuTTY session", &ec);
      }
      r.count = kept;
    }
  } else {
    wchar_t def[MAX_PATH];
    const wchar_t *path = a->arg3;
    DWORD n;
    if (path == NULL) {
      /* sd_import_ssh_config_file default: %USERPROFILE%\.ssh\config */
      n = GetEnvironmentVariableW(L"USERPROFILE", def, SD_COUNTOF(def));
      if (n == 0 || n >= SD_COUNTOF(def) - 16) {
        sd_import_result_free(&r);
        return fail_code(a, "file_not_found", "cannot resolve the default ssh_config path", &ec);
      }
      wcscat_s(def, SD_COUNTOF(def), L"\\.ssh\\config");
      path = def;
    }
    ec.name = path;
    e = sd_import_ssh_config_file(path, NULL, &r);
    if (e == SD_E_NOT_FOUND) {
      sd_import_result_free(&r);
      return fail_code(a, "file_not_found", "cannot read the ssh_config file", &ec);
    }
    if (e != SD_OK) {
      sd_import_result_free(&r);
      return fail_code(a, "io_error", sd_err_name(e), &ec);
    }
  }
  sd_import_mark_duplicates(&r, NULL);
  if (r.count == 0 && r.nskipped == 0) {
    sd_import_result_free(&r);
    if (a->json) {
      print_import_json(&r, 0, a->dry_run);
      return 0;
    }
    say(SD_MSG_CLI_PI_EMPTY, NULL, 0, 0);
    return 0;
  }
  if (a->json) {
    if (!a->dry_run) {
      e = sd_import_write(&r, &written);
      if (e != SD_OK) {
        sd_import_result_free(&r);
        return fail_code(a, "io_error", sd_err_name(e), &ec);
      }
    }
    print_import_json(&r, written, a->dry_run);
  } else {
    print_import_table(&r);
    if (a->dry_run) {
      sd_arg arg;
      arg.name = "count"; arg.type = SD_ARG_INT; arg.v.i = (long long)r.count;
      say(SD_MSG_CLI_PI_FOUND, &arg, 1, 0);
    } else {
      e = sd_import_write(&r, &written);
      if (e != SD_OK) {
        sd_arg arg;
        arg.name = "count"; arg.type = SD_ARG_INT; arg.v.i = (long long)written;
        say(SD_MSG_CLI_PI_IMPORTED, &arg, 1, 0);
        sd_import_result_free(&r);
        return fail_code(a, "io_error", sd_err_name(e), &ec);
      }
      {
        sd_arg arg;
        arg.name = "count"; arg.type = SD_ARG_INT; arg.v.i = (long long)written;
        say(SD_MSG_CLI_PI_IMPORTED, &arg, 1, 0);
      }
    }
  }
  sd_import_result_free(&r);
  return 0;
}

/* ---- hostkey ---- */

typedef struct hk_row {
  int store;
  char type[48];
  char fp[64];
  uint32_t line;
} hk_row;

typedef struct hk_list {
  hk_row row[128];
  uint32_t n;
  int truncated;
} hk_list;

static int hk_collect(void *ctx, const sd_kh_entry *e)
{
  hk_list *l = (hk_list *)ctx;
  if (l->n >= SD_COUNTOF(l->row)) {
    l->truncated = 1;
    return 1;
  }
  l->row[l->n].store = 0;   /* filled by the caller (one call per store) */
  strcpy_s(l->row[l->n].type, sizeof(l->row[l->n].type), e->type ? e->type : "?");
  if (sd_hostkey_fingerprint_sha256(e->blob, e->len, l->row[l->n].fp) != SD_OK)
    l->row[l->n].fp[0] = 0;
  l->row[l->n].line = e->line;
  l->n++;
  return 0;
}

static const sd_kh_store_kind k_hk_list_stores[] = {
  SD_KH_STORE_MACHINE, SD_KH_STORE_USER, SD_KH_SRC_OPENSSH, SD_KH_SRC_PUTTY
};

static void print_announced(const sd_json *res)
{
  const sd_json *arr = sd_json_get(res, "announcements");
  size_t i, k;
  if (sd_json_count(arr) == 0) {
    say(SD_MSG_CLI_HK_ANNOUNCED_NONE, NULL, 0, 0);
    return;
  }
  for (i = 0; i < sd_json_count(arr); i++) {
    const sd_json *an = sd_json_at(arr, i);
    const sd_json *add = sd_json_get(an, "add"), *rem = sd_json_get(an, "remove");
    wchar_t *wi = wide(sd_json_get_str(an, "id")), *wh = wide(sd_json_get_str(an, "host"));
    sd_arg args[2];
    args[0].name = "id"; args[0].type = SD_ARG_STR; args[0].v.s = wi ? wi : L"";
    args[1].name = "host"; args[1].type = SD_ARG_STR; args[1].v.s = wh ? wh : L"";
    say(SD_MSG_CLI_HK_ANNOUNCED_ITEM, args, 2, 0);
    for (k = 0; k < sd_json_count(add); k++) {
      wchar_t *wt = wide(sd_json_get_str(sd_json_at(add, k), "type"));
      wchar_t *wf = wide(sd_json_get_str(sd_json_at(add, k), "fingerprint"));
      args[0].name = "type"; args[0].type = SD_ARG_STR; args[0].v.s = wt ? wt : L"";
      args[1].name = "fingerprint"; args[1].type = SD_ARG_STR; args[1].v.s = wf ? wf : L"";
      say(SD_MSG_CLI_HK_ANNOUNCED_ADD, args, 2, 0);
      sd_free(wt); sd_free(wf);
    }
    for (k = 0; k < sd_json_count(rem); k++) {
      wchar_t *wt = wide(sd_json_get_str(sd_json_at(rem, k), "type"));
      wchar_t *wf = wide(sd_json_get_str(sd_json_at(rem, k), "fingerprint"));
      args[0].name = "type"; args[0].type = SD_ARG_STR; args[0].v.s = wt ? wt : L"";
      args[1].name = "fingerprint"; args[1].type = SD_ARG_STR; args[1].v.s = wf ? wf : L"";
      say(SD_MSG_CLI_HK_ANNOUNCED_REMOVE, args, 2, 0);
      sd_free(wt); sd_free(wf);
    }
    sd_free(wi); sd_free(wh);
  }
}

static int hk_announced(const cli_args *a)
{
  sd_ipc_hello hello;
  sd_ipc_conn *c = NULL;
  sd_ipc_error err;
  sd_json *res = NULL;
  int rc = 0;
  if (sd_ipc_connect(SD_IPC_AGENT, quiet_hello(&hello), 0, 5000, &c) != SD_OK) {
    /* no agent: nobody holds an announcement */
    if (a->json) {
      static const char k[] = "{\"ok\":true,\"result\":{\"announcements\":[]}}";
      cli_print_utf8_line(k, sizeof(k) - 1);
    } else {
      say(SD_MSG_CLI_HK_ANNOUNCED_NONE, NULL, 0, 0);
    }
    return 0;
  }
  if (sd_ipc_call_raw(c, "hostkey.announced.list", NULL, 0, CALL_TIMEOUT, &res, &err) != SD_OK) {
    rc = fail_ipc(a, &err, NULL);
    sd_ipc_close(c);
    sd_json_free(res);
    return rc;
  }
  sd_ipc_close(c);
  if (a->json) {
    json_ok(res);
  } else {
    print_announced(res);
  }
  sd_json_free(res);
  return 0;
}

/* The collected rows (about 15 KB) live on the heap: a stack copy trips C6262 under /analyze. */
static int hk_list_run(const cli_args *a, const char *lookup, hk_list *l)
{
  sd_known_hosts *kh = NULL;
  size_t i, k;
  if (!kh_open(1, &kh))
    return fail_code(a, "io_error", "cannot open the known_hosts stores", NULL);
  for (k = 0; k < SD_COUNTOF(k_hk_list_stores); k++) {
    uint32_t before = l->n;
    if (sd_known_hosts_list(kh, k_hk_list_stores[k], lookup, hk_collect, l) != SD_OK)
      continue;
    for (i = before; i < l->n; i++)
      l->row[i].store = (int)k_hk_list_stores[k];
  }
  sd_known_hosts_close(kh);
  if (a->json) {
    sd_wr w;
    sd_json_writer jw;
    sd_wr_init(&w, SD_IPC_MAX_MESSAGE);
    sd_jw_init(&jw, &w);
    sd_jw_obj_begin(&jw);
    sd_jw_key(&jw, "ok"); sd_jw_bool(&jw, 1);
    sd_jw_key(&jw, "result");
    sd_jw_obj_begin(&jw);
    sd_jw_key(&jw, "keys");
    sd_jw_arr_begin(&jw);
    for (i = 0; i < l->n; i++) {
      sd_jw_obj_begin(&jw);
      sd_jw_key(&jw, "store"); sd_jw_cstr(&jw, kh_store_name((sd_kh_store_kind)l->row[i].store));
      sd_jw_key(&jw, "host"); sd_jw_cstr(&jw, lookup);
      sd_jw_key(&jw, "type"); sd_jw_cstr(&jw, l->row[i].type);
      sd_jw_key(&jw, "fingerprint"); sd_jw_cstr(&jw, l->row[i].fp);
      sd_jw_key(&jw, "line"); sd_jw_int(&jw, l->row[i].line);
      sd_jw_obj_end(&jw);
    }
    sd_jw_arr_end(&jw);
    sd_jw_obj_end(&jw);
    sd_jw_obj_end(&jw);
    if (sd_jw_finish(&jw) == SD_OK)
      cli_print_utf8_line((const char *)w.p, w.len);
    sd_wr_free(&w);
    return 0;
  }
  if (l->n == 0) {
    wchar_t *wh = wide(lookup);
    say1w(SD_MSG_CLI_HK_LIST_EMPTY, "host", wh ? wh : L"", 0);
    sd_free(wh);
    return 0;
  }
  {
    wchar_t line[1024];
    size_t len = 0;
    line[0] = 0;
    pad_print(line, SD_COUNTOF(line), &len, sd_l10n_get(SD_MSG_CLI_HK_COL_STORE), 10);
    pad_print(line, SD_COUNTOF(line), &len, sd_l10n_get(SD_MSG_CLI_HK_COL_TYPE), 18);
    pad_print(line, SD_COUNTOF(line), &len, sd_l10n_get(SD_MSG_CLI_HK_COL_FP), 0);
    cli_print(line);
  }
  for (i = 0; i < l->n; i++) {
    wchar_t line[1024];
    size_t len = 0;
    wchar_t *ws = wide(kh_store_name((sd_kh_store_kind)l->row[i].store));
    wchar_t *wt = wide(l->row[i].type), *wf = wide(l->row[i].fp);
    line[0] = 0;
    pad_print(line, SD_COUNTOF(line), &len, ws ? ws : L"", 10);
    pad_print(line, SD_COUNTOF(line), &len, wt ? wt : L"", 18);
    pad_print(line, SD_COUNTOF(line), &len, wf ? wf : L"", 0);
    cli_print(line);
    sd_free(ws); sd_free(wt); sd_free(wf);
  }
  if (l->truncated)
    say(SD_MSG_CLI_HK_LIST_TRUNCATED, NULL, 0, 0);
  return 0;
}

static int hk_list_cmd(const cli_args *a, const char *lookup)
{
  hk_list *l = (hk_list *)sd_calloc(1, sizeof(*l));
  int rc;
  if (!l)
    return fail_code(a, "io_error", "out of memory", NULL);
  rc = hk_list_run(a, lookup, l);
  sd_free(l);
  return rc;
}

static int hk_import(const cli_args *a)
{
  sd_kh_store stores[3];
  uint32_t n = 0;
  sd_known_hosts *kh = NULL;
  sd_kh_import_report rep;
  wchar_t root[MAX_PATH];
  static wchar_t user_kh[MAX_PATH];
  static wchar_t src_path[MAX_PATH];
  sd_kh_store_kind src = wcscmp(a->from, L"putty") == 0 ? SD_KH_SRC_PUTTY : SD_KH_SRC_OPENSSH;
  sd_err e;
  if (a->arg2 && src == SD_KH_SRC_PUTTY) {
    err_ctx ec;
    memset(&ec, 0, sizeof(ec));
    return fail_code(a, "usage", "putty imports read the registry; a file is only used with openssh", &ec);
  }
  user_kh[0] = 0;
  src_path[0] = 0;
  if (a->arg2 && src == SD_KH_SRC_OPENSSH) {
    DWORD k = GetFullPathNameW(a->arg2, MAX_PATH, src_path, NULL);
    if (k == 0 || k >= MAX_PATH)
      memcpy(src_path, a->arg2, (wcslen(a->arg2) + 1) * sizeof(wchar_t));
  }
  if (sd_config_root(root, SD_COUNTOF(root)) == SD_OK && wcslen(root) + 13 < SD_COUNTOF(user_kh)) {
    memcpy(user_kh, root, (wcslen(root) + 1) * sizeof(wchar_t));
    wcscat_s(user_kh, SD_COUNTOF(user_kh), L"\\known_hosts");
  }
  memset(&stores[0], 0, sizeof(stores));
  stores[n].kind = SD_KH_STORE_USER; stores[n].path = user_kh[0] ? user_kh : NULL; stores[n].writable = 1; n++;
  stores[n].kind = src; stores[n].path = src_path[0] ? src_path : NULL; stores[n].writable = 0; n++;
  if (sd_known_hosts_open(stores, n, &kh) != SD_OK)
    return fail_code(a, "io_error", "cannot open the known_hosts stores", NULL);
  e = sd_known_hosts_import(kh, src, SD_KH_STORE_USER, &rep);
  sd_known_hosts_close(kh);
  if (e != SD_OK) {
    err_ctx ec;
    memset(&ec, 0, sizeof(ec));
    if (e == SD_E_NOT_FOUND) {
      ec.name = a->arg2;
      return fail_code(a, "file_not_found", "cannot read the import source", &ec);
    }
    return fail_code(a, sd_err_name(e), "cannot import host keys", &ec);
  }
  if (a->json) {
    sd_wr w;
    sd_json_writer jw;
    sd_wr_init(&w, 1024);
    sd_jw_init(&jw, &w);
    sd_jw_obj_begin(&jw);
    sd_jw_key(&jw, "ok"); sd_jw_bool(&jw, 1);
    sd_jw_key(&jw, "result");
    sd_jw_obj_begin(&jw);
    sd_jw_key(&jw, "imported"); sd_jw_int(&jw, rep.imported);
    sd_jw_key(&jw, "already_present"); sd_jw_int(&jw, rep.already_present);
    sd_jw_key(&jw, "conflicts"); sd_jw_int(&jw, rep.conflicts);
    sd_jw_key(&jw, "invalid_lines"); sd_jw_int(&jw, rep.invalid_lines);
    sd_jw_obj_end(&jw);
    sd_jw_obj_end(&jw);
    if (sd_jw_finish(&jw) == SD_OK)
      cli_print_utf8_line((const char *)w.p, w.len);
    sd_wr_free(&w);
    return 0;
  }
  {
    sd_arg arg;
    if (rep.imported == 0 && rep.already_present == 0 && rep.conflicts == 0) {
      say(SD_MSG_CLI_HK_IMPORT_EMPTY, NULL, 0, 0);
      return 0;
    }
    arg.name = "count"; arg.type = SD_ARG_INT; arg.v.i = rep.imported;
    say(SD_MSG_CLI_HK_IMPORTED, &arg, 1, 0);
    if (rep.already_present) {
      arg.v.i = rep.already_present;
      say(SD_MSG_CLI_HK_IMPORT_KEPT, &arg, 1, 0);
    }
    if (rep.conflicts) {
      arg.v.i = rep.conflicts;
      say(SD_MSG_CLI_HK_IMPORT_CONFLICTS, &arg, 1, 0);
    }
    if (rep.invalid_lines) {
      arg.v.i = rep.invalid_lines;
      say(SD_MSG_CLI_HK_IMPORT_INVALID, &arg, 1, 0);
    }
  }
  return 0;
}

static int hk_remove(const cli_args *a, const char *lookup)
{
  sd_kh_store stores[2];
  uint32_t n = 0;
  sd_known_hosts *kh = NULL;
  wchar_t root[MAX_PATH];
  static wchar_t user_kh[MAX_PATH];
  char type[64];
  sd_err e;
  int rc;
  user_kh[0] = 0;
  type[0] = 0;
  if (a->hk_type) {
    size_t got = 0;
    if (sd_utf16_to_utf8(a->hk_type, wcslen(a->hk_type), type, sizeof(type) - 1, &got, SD_UTF_STRICT) != SD_OK)
      return fail_code(a, "usage", "invalid key type", NULL);
    type[got] = 0;
  }
  if (sd_config_root(root, SD_COUNTOF(root)) == SD_OK && wcslen(root) + 13 < SD_COUNTOF(user_kh)) {
    memcpy(user_kh, root, (wcslen(root) + 1) * sizeof(wchar_t));
    wcscat_s(user_kh, SD_COUNTOF(user_kh), L"\\known_hosts");
  }
  memset(&stores[0], 0, sizeof(stores));
  stores[n].kind = SD_KH_STORE_MACHINE; stores[n].path = NULL; stores[n].writable = 0; n++;
  stores[n].kind = SD_KH_STORE_USER; stores[n].path = user_kh[0] ? user_kh : NULL; stores[n].writable = 1; n++;
  if (sd_known_hosts_open(stores, n, &kh) != SD_OK)
    return fail_code(a, "io_error", "cannot open the known_hosts stores", NULL);
  e = sd_known_hosts_remove(kh, SD_KH_STORE_USER, lookup, type[0] ? type : NULL);
  sd_known_hosts_close(kh);
  if (e == SD_E_NOT_FOUND) {
    err_ctx ec;
    wchar_t *wh = wide(lookup);
    memset(&ec, 0, sizeof(ec));
    ec.name = wh;
    rc = fail_code(a, "host_key_not_found", "no such stored key", &ec);
    sd_free(wh);
    return rc;
  }
  if (e != SD_OK)
    return fail_code(a, sd_err_name(e), "cannot remove the stored key", NULL);
  if (a->json) {
    json_ok(NULL);
  } else {
    wchar_t *wh = wide(lookup);
    say1w(SD_MSG_CLI_HK_REMOVED, "host", wh ? wh : L"", 0);
    sd_free(wh);
  }
  return 0;
}

static int hk_accept(const cli_args *a)
{
  sd_ipc_hello hello;
  sd_ipc_conn *c = NULL;
  sd_ipc_error err;
  sd_json *res = NULL;
  sd_wr w;
  sd_json_writer jw;
  char *id = NULL;
  int rc;
  sd_err e;
  if (sd_ipc_connect(SD_IPC_AGENT, quiet_hello(&hello), 0, 5000, &c) != SD_OK)
    return fail_code(a, "agent_unavailable", "cannot connect to the agent", NULL);
  if (sd_wide_to_utf8_alloc(a->arg2, (size_t)-1, SD_UTF_STRICT, &id) != SD_OK) {
    sd_ipc_close(c);
    return fail_code(a, "usage", "invalid announcement id", NULL);
  }
  sd_wr_init(&w, 1024);
  sd_jw_init(&jw, &w);
  sd_jw_obj_begin(&jw);
  sd_jw_key(&jw, "id"); sd_jw_cstr(&jw, id);
  sd_jw_key(&jw, "add_only"); sd_jw_bool(&jw, a->add_only);
  sd_jw_obj_end(&jw);
  sd_free(id);
  e = sd_jw_finish(&jw) == SD_OK
      ? sd_ipc_call_raw(c, "hostkey.announced.accept", (const char *)w.p, w.len, CALL_TIMEOUT, &res, &err)
      : SD_E_INTERNAL;
  sd_wr_free(&w);
  sd_ipc_close(c);
  if (e != SD_OK) {
    rc = fail_ipc(a, &err, NULL);
    sd_json_free(res);
    return rc;
  }
  if (a->json) {
    json_ok(res);
  } else {
    const char *host = sd_json_get_str(res, "host");
    int64_t added = 0, removed = 0;
    sd_json_get_int64(res, "added", &added);
    sd_json_get_int64(res, "removed", &removed);
    {
      wchar_t *wh = wide(host);
      wchar_t abuf[24], rbuf[24];
      sd_arg args[3];
      args[0].name = "host"; args[0].type = SD_ARG_STR; args[0].v.s = wh ? wh : L"";
      args[1].name = "added"; args[1].type = SD_ARG_STR; args[1].v.s = decimal(abuf, SD_COUNTOF(abuf), added);
      args[2].name = "removed"; args[2].type = SD_ARG_STR; args[2].v.s = decimal(rbuf, SD_COUNTOF(rbuf), removed);
      say(SD_MSG_CLI_HK_ANNOUNCED_APPLIED, args, 3, 0);
      sd_free(wh);
    }
  }
  sd_json_free(res);
  return 0;
}

int cli_run_hostkey(const cli_args *a)
{
  char lookup[320];
  if (a->announced)
    return hk_announced(a);
  if (wcscmp(a->positional, L"import") == 0)
    return hk_import(a);
  if (wcscmp(a->positional, L"accept-announced") == 0)
    return hk_accept(a);
  if (!lookup_name_of(a->arg2, lookup, sizeof(lookup)))
    return fail_code(a, "usage", "invalid host", NULL);
  if (wcscmp(a->positional, L"remove") == 0)
    return hk_remove(a, lookup);
  return hk_list_cmd(a, lookup);
}
