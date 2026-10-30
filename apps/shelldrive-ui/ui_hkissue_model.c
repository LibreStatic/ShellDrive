/* shelldrive-ui: the model of the changed-key and wrong-key-type notifications (ui_hkissue_model.h). */
#include <windows.h>
#include <string.h>
#include <wchar.h>

#include "ui_hkissue_model.h"

/* Copies a JSON string reduced to printable ASCII. */
static void ascii_copy(const sd_json *obj, const char *key, char *out, size_t cap)
{
  const char *s = sd_json_get_str(obj, key);
  size_t i;
  out[0] = 0;
  if (s == NULL)
    return;
  for (i = 0; i + 1 < cap && s[i] != 0; i++) {
    unsigned char c = (unsigned char)s[i];
    out[i] = (c >= 0x20 && c < 0x7f) ? (char)c : '?';
  }
  out[i] = 0;
}

static void ascii_cut(const char *s, char *out, size_t cap)
{
  size_t i;
  for (i = 0; i + 1 < cap && s[i] != 0; i++) {
    unsigned char c = (unsigned char)s[i];
    out[i] = (c >= 0x20 && c < 0x7f) ? (char)c : '?';
  }
  out[i] = 0;
}

/* Reads a JSON array of strings into names; returns the number kept (empty strings are skipped). */
static size_t read_names(const sd_json *obj, const char *key, char (*names)[UI_HKI_TYPE_MAX], size_t max)
{
  const sd_json *arr = sd_json_get(obj, key);
  size_t i, n = sd_json_count(arr), kept = 0;
  if (sd_json_type_of(arr) != SD_JSON_ARRAY)
    return 0;
  for (i = 0; i < n && kept < max; i++) {
    const char *s = sd_json_str(sd_json_at(arr, i), NULL);
    if (s == NULL || s[0] == 0)
      continue;
    ascii_cut(s, names[kept], UI_HKI_TYPE_MAX);
    kept++;
  }
  return kept;
}

/* Splits a comma-joined list ("ssh-rsa,ssh-ed25519") into names. */
static size_t split_names(const char *csv, char (*names)[UI_HKI_TYPE_MAX], size_t max)
{
  size_t kept = 0;
  const char *p = csv;
  while (p != NULL && *p != 0 && kept < max) {
    const char *e = strchr(p, ',');
    size_t len = e != NULL ? (size_t)(e - p) : strlen(p);
    while (len > 0 && *p == ' ') {
      p++;
      len--;
    }
    if (len > 0) {
      size_t k;
      for (k = 0; k + 1 < UI_HKI_TYPE_MAX && k < len; k++) {
        unsigned char c = (unsigned char)p[k];
        names[kept][k] = (c >= 0x20 && c < 0x7f) ? (char)c : '?';
      }
      names[kept][k] = 0;
      kept++;
    }
    p = e != NULL ? e + 1 : NULL;
  }
  return kept;
}

static ui_hki_store store_of_token(const char *s)
{
  if (s == NULL)
    return UI_HKI_STORE_UNKNOWN;
  if (strcmp(s, "machine") == 0)
    return UI_HKI_STORE_MACHINE;
  if (strcmp(s, "user") == 0)
    return UI_HKI_STORE_USER;
  if (strcmp(s, "openssh") == 0)
    return UI_HKI_STORE_OPENSSH;
  if (strcmp(s, "putty") == 0)
    return UI_HKI_STORE_PUTTY;
  return UI_HKI_STORE_UNKNOWN;
}

static int ends_with_i(const wchar_t *s, const wchar_t *suffix)
{
  size_t n = wcslen(s), m = wcslen(suffix);
  return n >= m && _wcsicmp(s + n - m, suffix) == 0;
}

ui_hki_kind ui_hki_parse(const sd_json *data, const char *fallback_host, ui_hki *out)
{
  const sd_json *err = sd_json_get(data, "error");
  const char *code = sd_json_get_str(err, "code");
  const char *path;
  int64_t line = 0;
  size_t i, o = 0;

  memset(out, 0, sizeof(*out));
  if (err == NULL || code == NULL)
    return UI_HKI_NONE;
  if (strcmp(code, "host_key_mismatch") == 0)
    out->kind = UI_HKI_CHANGED;
  else if (strcmp(code, "host_key_type_unavailable") == 0)
    out->kind = UI_HKI_TYPE_UNAVAILABLE;
  else
    return UI_HKI_NONE;
  ascii_copy(data, "mount_id", out->mount_id, sizeof(out->mount_id));
  ascii_copy(err, "host", out->host, sizeof(out->host));
  if (out->host[0] == 0 && fallback_host != NULL) {
    for (i = 0; i + 1 < sizeof(out->host) && fallback_host[i] != 0; i++) {
      unsigned char c = (unsigned char)fallback_host[i];
      out->host[i] = (c >= 0x20 && c < 0x7f) ? (char)c : '?';
    }
    out->host[i] = 0;
  }
  ascii_copy(err, "lookup_name", out->lookup_name, sizeof(out->lookup_name));
  out->store = store_of_token(sd_json_get_str(err, "store_kind"));
  if (out->kind == UI_HKI_TYPE_UNAVAILABLE) {
    out->n_stored = read_names(err, "stored_types", out->stored_types, UI_HKI_STORED_MAX);
    out->n_offered = read_names(err, "offered_types", out->offered_types, UI_HKI_OFFERED_MAX);
  }
  ascii_copy(err, "stored_type", out->stored_type, sizeof(out->stored_type));
  ascii_copy(err, "stored_fp", out->stored_fp, sizeof(out->stored_fp));
  ascii_copy(err, "offered_type", out->offered_type, sizeof(out->offered_type));
  ascii_copy(err, "offered_fp", out->offered_fp, sizeof(out->offered_fp));
  path = sd_json_get_str(err, "store_path");
  if (path != NULL) {
    wchar_t tmp[UI_HKI_PATH_MAX];
    int n = MultiByteToWideChar(CP_UTF8, 0, path, -1, tmp, (int)(sizeof(tmp) / sizeof(tmp[0])));
    if (n > 0) {
      for (i = 0; tmp[i] != 0 && o + 1 < UI_HKI_PATH_MAX; i++)
        if (tmp[i] >= 0x20 && tmp[i] != 0x7f)
          out->path[o++] = tmp[i];
    }
    out->path[o] = 0;
  }
  if (out->kind == UI_HKI_TYPE_UNAVAILABLE && out->n_stored == 0)
    out->n_stored = split_names(out->stored_type, out->stored_types, UI_HKI_STORED_MAX);   /* an older agent */
  if (sd_json_get_int64(err, "store_line", &line) && line > 0 && line < 100000000)
    out->line = (unsigned)line;
  return out->kind;
}

/* 1 when needle occurs in s. Not the CRT wcsstr: its x86 version dispatches to SSE4.2 code that the x86-ia32 ISA
   audit has not reviewed (tools/sd-isacheck/crt-allow.txt), and these strings are short. */
static int has_substr(const wchar_t *s, const wchar_t *needle)
{
  size_t i, j;
  for (i = 0; s[i] != 0; i++) {
    for (j = 0; needle[j] != 0 && s[i + j] == needle[j]; j++)
      ;
    if (needle[j] == 0)
      return 1;
  }
  return 0;
}

ui_hki_source ui_hki_classify(const wchar_t *path, const wchar_t *user_store)
{
  if (path == NULL || path[0] == 0)
    return UI_HKI_SRC_PUTTY;
  if (has_substr(path, L"SimonTatham") && has_substr(path, L"PuTTY") && wcschr(path, L':') == NULL)
    return UI_HKI_SRC_PUTTY;
  if (user_store != NULL && _wcsicmp(path, user_store) == 0)
    return UI_HKI_SRC_USER;
  if (ends_with_i(path, L"\\LibreStatic\\ShellDrive\\known_hosts"))
    return UI_HKI_SRC_MACHINE;
  if (ends_with_i(path, L"\\known_hosts") || ends_with_i(path, L"\\known_hosts2") ||
      ends_with_i(path, L"\\ssh_known_hosts"))
    return UI_HKI_SRC_OPENSSH;
  return UI_HKI_SRC_FILE;
}

int ui_hki_source_removable_here(ui_hki_source s)
{
  return s == UI_HKI_SRC_USER;
}

int ui_hki_source_can_stop(ui_hki_source s)
{
  return s == UI_HKI_SRC_OPENSSH || s == UI_HKI_SRC_PUTTY;
}

int ui_hki_path_ok(const wchar_t *path)
{
  size_t i, n;
  if (path == NULL)
    return 0;
  n = wcslen(path);
  if (n < 4 || n >= UI_HKI_PATH_MAX)
    return 0;
  if (!(((path[0] >= L'A' && path[0] <= L'Z') || (path[0] >= L'a' && path[0] <= L'z')) && path[1] == L':' &&
        path[2] == L'\\') &&
      !(path[0] == L'\\' && path[1] == L'\\'))
    return 0;
  for (i = 0; i < n; i++)
    if (path[i] < 0x20 || path[i] == L'"')
      return 0;
  return 1;
}

int ui_hki_source_can_open(ui_hki_source s, const wchar_t *path)
{
  return s != UI_HKI_SRC_PUTTY && s != UI_HKI_SRC_USER && s != UI_HKI_SRC_MACHINE && ui_hki_path_ok(path);
}

int ui_hki_select_args(const wchar_t *path, wchar_t *out, size_t cap)
{
  static const wchar_t head[] = L"/select,\"";
  size_t n;
  if (!ui_hki_path_ok(path) || out == NULL)
    return 0;
  n = wcslen(path);
  if (cap < (sizeof(head) / sizeof(head[0])) - 1 + n + 2)
    return 0;
  wcscpy_s(out, cap, head);
  wcscat_s(out, cap, path);
  wcscat_s(out, cap, L"\"");
  return 1;
}

ui_hki_where ui_hki_where_of(ui_hki_source s)
{
  switch (s) {
  case UI_HKI_SRC_USER:    return UI_HKI_WHERE_USER;
  case UI_HKI_SRC_MACHINE: return UI_HKI_WHERE_MACHINE;
  case UI_HKI_SRC_PUTTY:   return UI_HKI_WHERE_PUTTY;
  default:                 return UI_HKI_WHERE_FILE;
  }
}

ui_hki_todo ui_hki_todo_of(ui_hki_source s)
{
  switch (s) {
  case UI_HKI_SRC_USER:    return UI_HKI_TODO_USER;
  case UI_HKI_SRC_MACHINE: return UI_HKI_TODO_MACHINE;
  default:                 return UI_HKI_TODO_SOURCE;
  }
}

int ui_hki_has_stored_type(const ui_hki *h)
{
  return h != NULL && (h->n_stored > 0 || h->stored_type[0] != 0);
}

ui_hki_source ui_hki_source_of(const ui_hki *h, const wchar_t *user_store)
{
  switch (h->store) {
  case UI_HKI_STORE_MACHINE: return UI_HKI_SRC_MACHINE;
  case UI_HKI_STORE_USER:    return UI_HKI_SRC_USER;
  case UI_HKI_STORE_OPENSSH: return UI_HKI_SRC_OPENSSH;
  case UI_HKI_STORE_PUTTY:   return UI_HKI_SRC_PUTTY;
  default:                   return ui_hki_classify(h->path, user_store);
  }
}

static size_t join_types(const char (*types)[UI_HKI_TYPE_MAX], size_t n, char *out, size_t cap)
{
  size_t i, len = 0, written = 0;
  if (out == NULL || cap == 0)
    return 0;
  out[0] = 0;
  for (i = 0; i < n; i++) {
    size_t tl = strlen(types[i]);
    size_t need = (i > 0 ? 2u : 0u) + tl;
    if (len + need + 1 > cap)
      break;
    if (i > 0) {
      out[len++] = ',';
      out[len++] = ' ';
    }
    memcpy(out + len, types[i], tl);
    len += tl;
    out[len] = 0;
    written++;
  }
  return written;
}

size_t ui_hki_stored_list(const ui_hki *h, char *out, size_t cap)
{
  return join_types((const char (*)[UI_HKI_TYPE_MAX])h->stored_types, h->n_stored, out, cap);
}

size_t ui_hki_offered_list(const ui_hki *h, char *out, size_t cap)
{
  return join_types((const char (*)[UI_HKI_TYPE_MAX])h->offered_types, h->n_offered, out, cap);
}

int ui_hki_has_offered_key(const ui_hki *h)
{
  return h != NULL && h->offered_type[0] != 0 && h->offered_fp[0] != 0;
}

const char *ui_hki_add_target(const ui_hki *h)
{
  return h->lookup_name[0] != 0 ? h->lookup_name : h->host;
}
