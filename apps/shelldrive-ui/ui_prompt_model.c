/* shelldrive-ui: the prompt model (03 §2.5). See ui_prompt_model.h. Pure: no window or IPC call. */
#include <windows.h>
#include <string.h>
#include <wchar.h>

#include "sd_base/sd_buf.h"
#include "sd_base/sd_json.h"
#include "sd_base/sd_mem.h"
#include "ui_prompt_model.h"

#define SERVER_TEXT_IN_BYTES 2048u     /* TM-R09: 2 KiB per field, cut before conversion */

/* ---- text ---- */

static int is_dropped(wchar_t c)
{
  if (c < 0x20 || (c >= 0x7F && c <= 0x9F))
    return 1;                                   /* C0 and C1 controls, DEL */
  if (c >= 0x202A && c <= 0x202E)
    return 1;                                   /* bidi embedding and override */
  if (c >= 0x2066 && c <= 0x2069)
    return 1;                                   /* bidi isolates */
  if (c == 0x200E || c == 0x200F)
    return 1;                                   /* LRM, RLM */
  if (c >= 0x200B && c <= 0x200D)
    return 1;                                   /* zero-width space, joiners */
  if (c == 0x2060 || c == 0xFEFF)
    return 1;                                   /* word joiner, BOM */
  return 0;
}

void ui_text_safe_w(const wchar_t *in, wchar_t *out, size_t cch)
{
  size_t i = 0, k = 0;
  if (out == NULL || cch == 0)
    return;
  out[0] = 0;
  if (in == NULL)
    return;
  for (i = 0; in[i] != 0 && k + 1 < cch; i++) {
    if (is_dropped(in[i]))
      continue;
    out[k++] = in[i];
  }
  out[k] = 0;
}

void ui_text_safe(const char *utf8, wchar_t *out, size_t cch)
{
  wchar_t tmp[SERVER_TEXT_IN_BYTES + 1];
  size_t len;
  int n;
  if (out == NULL || cch == 0)
    return;
  out[0] = 0;
  if (utf8 == NULL)
    return;
  len = strlen(utf8);
  if (len > SERVER_TEXT_IN_BYTES)
    len = SERVER_TEXT_IN_BYTES;
  n = MultiByteToWideChar(CP_UTF8, 0, utf8, (int)len, tmp, (int)SD_COUNTOF(tmp) - 1);
  if (n <= 0)
    return;
  tmp[n] = 0;
  ui_text_safe_w(tmp, out, cch);
  SecureZeroMemory(tmp, sizeof(tmp));
}

/* Text member of a JSON object, sanitized. Missing or non-string members give an empty string. */
static void json_text(const sd_json *obj, const char *key, wchar_t *out, size_t cch)
{
  const sd_json *v = sd_json_get(obj, key);
  size_t len = 0;
  const char *s = v != NULL ? sd_json_str(v, &len) : NULL;
  char tmp[SERVER_TEXT_IN_BYTES + 1];
  if (s == NULL) {
    ui_text_safe("", out, cch);
    return;
  }
  if (len > SERVER_TEXT_IN_BYTES)
    len = SERVER_TEXT_IN_BYTES;
  memcpy(tmp, s, len);
  tmp[len] = 0;
  ui_text_safe(tmp, out, cch);
}

static int json_int(const sd_json *obj, const char *key, int fallback)
{
  int64_t v = 0;
  if (!sd_json_get_int64(obj, key, &v))
    return fallback;
  if (v < INT32_MIN / 2 || v > INT32_MAX / 2)
    return fallback;
  return (int)v;
}

static int json_flag(const sd_json *obj, const char *key)
{
  int v = 0;
  return sd_json_get_bool(obj, key, &v) && v;
}

/* ---- parsing ---- */

ui_prompt_kind ui_prompt_kind_from_name(const char *name)
{
  if (name == NULL)
    return UI_PK_NONE;
  if (strcmp(name, "hostkey_unknown") == 0 || strcmp(name, "hostkey") == 0)
    return UI_PK_HOSTKEY;
  if (strcmp(name, "hostkey_changed") == 0)
    return UI_PK_HOSTKEY_CHANGED;
  if (strcmp(name, "password") == 0)
    return UI_PK_PASSWORD;
  if (strcmp(name, "passphrase") == 0)
    return UI_PK_PASSPHRASE;
  if (strcmp(name, "kbdint") == 0)
    return UI_PK_KBDINT;
  if (strcmp(name, "password_change") == 0)
    return UI_PK_PASSWORD_CHANGE;
  if (strcmp(name, "legacy_ack") == 0)
    return UI_PK_LEGACY_ACK;
  if (strcmp(name, "proxy_password") == 0)
    return UI_PK_PROXY_PASSWORD;
  if (strcmp(name, "webdav_token_only") == 0)
    return UI_PK_WEBDAV_TOKEN_ONLY;
  return UI_PK_NONE;
}

static void parse_algorithms(const sd_json *arr, wchar_t *out, size_t cch)
{
  size_t i, n = sd_json_count(arr), used = 0;
  out[0] = 0;
  for (i = 0; i < n && i < UI_PROMPT_MAX_ALGS; i++) {
    wchar_t one[64];
    size_t len = 0, k;
    const sd_json *item = sd_json_at(arr, i);
    const char *s = item != NULL ? sd_json_str(item, &len) : NULL;
    char tmp[64];
    if (s == NULL)
      continue;
    if (len >= sizeof(tmp))
      len = sizeof(tmp) - 1;
    memcpy(tmp, s, len);
    tmp[len] = 0;
    ui_text_safe(tmp, one, SD_COUNTOF(one));
    k = wcslen(one);
    if (k == 0)
      continue;
    if (used > 0) {
      if (used + 2 >= cch)
        break;
      out[used++] = L',';
      out[used++] = L' ';
    }
    if (used + k >= cch)
      break;
    wmemcpy(out + used, one, k);
    used += k;
    out[used] = 0;
  }
}

static void parse_items(const sd_json *kb, ui_prompt *p)
{
  const sd_json *arr = sd_json_get(kb, "prompts");
  size_t i, n = sd_json_count(arr);
  for (i = 0; i < n && p->item_count < UI_PROMPT_MAX_ITEMS; i++) {
    const sd_json *it = sd_json_at(arr, i);
    ui_prompt_item *dst = &p->items[p->item_count];
    if (sd_json_type_of(it) != SD_JSON_OBJECT)
      continue;
    json_text(it, "text", dst->text, SD_COUNTOF(dst->text));
    dst->echo = json_flag(it, "echo");
    p->item_count++;
  }
}

sd_err ui_prompt_parse(const sd_json *data, ui_prompt *out)
{
  const char *pid, *mid, *kind;
  const sd_json *kb;

  if (data == NULL || out == NULL || sd_json_type_of(data) != SD_JSON_OBJECT)
    return SD_E_INVALID_PARAM;
  pid = sd_json_get_str(data, "prompt_id");
  mid = sd_json_get_str(data, "mount_id");
  kind = sd_json_get_str(data, "kind");
  if (pid == NULL || mid == NULL || strlen(pid) >= UI_PROMPT_ID_MAX || strlen(mid) >= UI_PROMPT_ID_MAX)
    return SD_E_INVALID_PARAM;

  memset(out, 0, sizeof(*out));
  strcpy_s(out->prompt_id, sizeof(out->prompt_id), pid);
  strcpy_s(out->mount_id, sizeof(out->mount_id), mid);
  out->kind = ui_prompt_kind_from_name(kind);
  if (out->kind == UI_PK_NONE)
    return SD_E_INVALID_PARAM;

  json_text(data, "profile_name", out->profile, SD_COUNTOF(out->profile));
  json_text(data, "host", out->host, SD_COUNTOF(out->host));
  json_text(data, "user", out->user, SD_COUNTOF(out->user));
  json_text(data, "via_host", out->via, SD_COUNTOF(out->via));
  out->port = json_int(data, "port", 22);
  out->hop = json_int(data, "hop", 1);
  out->hops = json_int(data, "hops", 1);
  out->is_reconnect = json_flag(data, "is_reconnect");
  out->hostkey_just_accepted = json_flag(data, "hostkey_just_accepted");
  out->can_save = json_flag(data, "can_save");
  {
    int64_t dl = 0;
    if (sd_json_get_int64(data, "deadline_ms", &dl) && dl >= 0) {
      out->has_deadline = 1;
      out->deadline_ms = dl;
    }
  }

  json_text(data, "key_type", out->key_type, SD_COUNTOF(out->key_type));
  out->key_bits = json_int(data, "key_bits", 0);
  json_text(data, "fingerprint", out->fingerprint, SD_COUNTOF(out->fingerprint));
  json_text(data, "stored_fingerprint", out->stored_fingerprint, SD_COUNTOF(out->stored_fingerprint));
  json_text(data, "key_fingerprint", out->key_fingerprint, SD_COUNTOF(out->key_fingerprint));
  json_text(data, "proxy_host", out->proxy_host, SD_COUNTOF(out->proxy_host));
  out->proxy_port = json_int(data, "proxy_port", 0);

  parse_algorithms(sd_json_get(data, "algorithms"), out->algorithms, SD_COUNTOF(out->algorithms));

  kb = sd_json_get(data, "kbdint");
  if (kb != NULL && sd_json_type_of(kb) == SD_JSON_OBJECT) {
    json_text(kb, "name", out->name, SD_COUNTOF(out->name));
    json_text(kb, "instruction", out->instruction, SD_COUNTOF(out->instruction));
    parse_items(kb, out);
  }
  return SD_OK;
}

/* ---- fixtures ---- */

void ui_prompt_fixture(ui_prompt_kind kind, ui_prompt *p)
{
  memset(p, 0, sizeof(*p));
  strcpy_s(p->prompt_id, sizeof(p->prompt_id), "p-1-2");
  strcpy_s(p->mount_id, sizeof(p->mount_id), "m-1");
  p->kind = kind;
  wcscpy_s(p->profile, SD_COUNTOF(p->profile), L"Work server");
  wcscpy_s(p->host, SD_COUNTOF(p->host), L"files.example.org");
  p->port = 22;
  wcscpy_s(p->user, SD_COUNTOF(p->user), L"deploy");
  p->hop = 1;
  p->hops = 1;
  p->has_deadline = 1;
  p->deadline_ms = 120000;
  switch (kind) {
  case UI_PK_HOSTKEY:
    wcscpy_s(p->key_type, SD_COUNTOF(p->key_type), L"ED25519");
    p->key_bits = 256;
    wcscpy_s(p->fingerprint, SD_COUNTOF(p->fingerprint), L"SHA256:4bWb1xq0Lw2wKJyz0J7hG3sBfQO1mYc8P0hHk9nZ2aE");
    p->hop = 2;
    p->hops = 2;
    wcscpy_s(p->via, SD_COUNTOF(p->via), L"bastion.example.org");
    break;
  case UI_PK_HOSTKEY_CHANGED:
    wcscpy_s(p->key_type, SD_COUNTOF(p->key_type), L"ED25519");
    wcscpy_s(p->stored_fingerprint, SD_COUNTOF(p->stored_fingerprint), L"SHA256:old0000000000000000000000000000000000000000");
    wcscpy_s(p->fingerprint, SD_COUNTOF(p->fingerprint), L"SHA256:new1111111111111111111111111111111111111111");
    break;
  case UI_PK_PASSWORD:
    p->can_save = 1;
    p->hostkey_just_accepted = 1;
    break;
  case UI_PK_PASSPHRASE:
    p->can_save = 1;
    wcscpy_s(p->key_fingerprint, SD_COUNTOF(p->key_fingerprint), L"SHA256:Qk3zP0a1bC2dE3fG4hI5jK6lM7nO8pQ9rS0tU1vW2xY");
    break;
  case UI_PK_KBDINT:
    wcscpy_s(p->name, SD_COUNTOF(p->name), L"Two-factor sign-in");
    wcscpy_s(p->instruction, SD_COUNTOF(p->instruction), L"Enter the code from your app.");
    p->item_count = 2;
    wcscpy_s(p->items[0].text, SD_COUNTOF(p->items[0].text), L"Verification code: ");
    p->items[0].echo = 0;
    wcscpy_s(p->items[1].text, SD_COUNTOF(p->items[1].text), L"Device name: ");
    p->items[1].echo = 1;
    break;
  case UI_PK_PASSWORD_CHANGE:
    p->item_count = 3;
    wcscpy_s(p->items[0].text, SD_COUNTOF(p->items[0].text), L"Current password: ");
    wcscpy_s(p->items[1].text, SD_COUNTOF(p->items[1].text), L"New password: ");
    wcscpy_s(p->items[2].text, SD_COUNTOF(p->items[2].text), L"Retype new password: ");
    break;
  case UI_PK_LEGACY_ACK:
    wcscpy_s(p->algorithms, SD_COUNTOF(p->algorithms), L"hmac-sha1, 3des-cbc");
    break;
  case UI_PK_PROXY_PASSWORD:
    wcscpy_s(p->proxy_host, SD_COUNTOF(p->proxy_host), L"proxy.example.net");
    p->proxy_port = 3128;
    p->can_save = 1;
    break;
  default:
    break;
  }
}

/* ---- answers ---- */

void ui_secret_free(void *p, size_t n)
{
  sd_secure_free(p, n);
}

sd_err ui_prompt_build_answer(const char *prompt_id, const char *action, wchar_t *const *responses, size_t n,
                              int save, char **out, size_t *out_len)
{
  sd_wr w;
  sd_json_writer jw;
  char **u8 = NULL;
  size_t *u8_len = NULL, i;
  sd_err e = SD_OK;
  int ok;

  if (out == NULL || out_len == NULL)
    return SD_E_INVALID_PARAM;
  *out = NULL;
  *out_len = 0;
  memset(&w, 0, sizeof(w));
  if (prompt_id == NULL || action == NULL || (n > 0 && responses == NULL) || n > UI_PROMPT_MAX_ITEMS) {
    e = SD_E_INVALID_PARAM;
    goto wipe_inputs;
  }

  sd_wr_init_secret(&w, 64 * 1024);
  if (n > 0) {
    u8 = (char **)sd_calloc(n, sizeof(char *));
    u8_len = (size_t *)sd_calloc(n, sizeof(size_t));
    if (u8 == NULL || u8_len == NULL) {
      e = SD_E_NO_MEMORY;
      goto cleanup;
    }
  }
  for (i = 0; i < n; i++) {
    const wchar_t *r = responses != NULL ? responses[i] : NULL;
    size_t wl = r != NULL ? wcslen(r) : 0;
    int need = 0;
    if (wl > UI_PROMPT_TEXT_MAX) {
      e = SD_E_INVALID_PARAM;
      goto cleanup;
    }
    if (wl > 0) {
      need = WideCharToMultiByte(CP_UTF8, 0, r, (int)wl, NULL, 0, NULL, NULL);
      if (need <= 0) {
        e = SD_E_INVALID_PARAM;
        goto cleanup;
      }
    }
    u8[i] = (char *)sd_alloc((size_t)need + 1);
    if (u8[i] == NULL) {
      e = SD_E_NO_MEMORY;
      goto cleanup;
    }
    if (need > 0)
      WideCharToMultiByte(CP_UTF8, 0, r, (int)wl, u8[i], need, NULL, NULL);
    u8[i][need] = 0;
    u8_len[i] = (size_t)need;
  }

  sd_jw_init(&jw, &w);
  sd_jw_obj_begin(&jw);
  sd_jw_key(&jw, "prompt_id");
  sd_jw_cstr(&jw, prompt_id);
  sd_jw_key(&jw, "action");
  sd_jw_cstr(&jw, action);
  if (n > 0) {
    sd_jw_key(&jw, "responses");
    sd_jw_arr_begin(&jw);
    for (i = 0; i < n; i++)
      sd_jw_str(&jw, u8[i], u8_len[i]);
    sd_jw_arr_end(&jw);
  }
  if (save) {
    sd_jw_key(&jw, "save");
    sd_jw_bool(&jw, 1);
  }
  sd_jw_obj_end(&jw);
  ok = sd_jw_finish(&jw) == SD_OK;
  if (!ok || w.p == NULL) {
    e = SD_E_INVALID_PARAM;
    goto cleanup;
  }
  *out = (char *)sd_alloc(w.len + 1);
  if (*out == NULL) {
    e = SD_E_NO_MEMORY;
    goto cleanup;
  }
  memcpy(*out, w.p, w.len);
  (*out)[w.len] = 0;
  *out_len = w.len;

cleanup:
  for (i = 0; u8 != NULL && i < n; i++)
    if (u8[i] != NULL)
      ui_secret_free(u8[i], u8_len[i] + 1);
  sd_free(u8);
  sd_free(u8_len);
  sd_wr_free(&w);
wipe_inputs:
  /* the caller's secrets never outlive the build, whatever happened above */
  for (i = 0; responses != NULL && i < n; i++)
    if (responses[i] != NULL)
      SecureZeroMemory(responses[i], wcslen(responses[i]) * sizeof(wchar_t));
  if (e != SD_OK && *out != NULL) {
    ui_secret_free(*out, *out_len + 1);
    *out = NULL;
    *out_len = 0;
  }
  return e;
}
