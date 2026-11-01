/* shelldrive-ui: the model of the main window's list (ui_mainview_model.h). */
#include <windows.h>
#include <string.h>

#include "sd_config/sd_config.h"
#include "ui_mainview_model.h"

unsigned ui_mv_sec_flag(const char *code)
{
  if (code == NULL)
    return 0;
  if (strcmp(code, "legacy_algorithms") == 0)
    return UI_MV_SEC_LEGACY;
  if (strcmp(code, "terrapin_exposed") == 0)
    return UI_MV_SEC_TERRAPIN;
  return 0;
}

unsigned ui_mv_sec_from_warnings(const sd_json *warnings, const char *mount_id)
{
  size_t i, n = sd_json_count(warnings);
  unsigned flags = 0;
  if (mount_id == NULL || mount_id[0] == 0 || sd_json_type_of(warnings) != SD_JSON_ARRAY)
    return 0;
  for (i = 0; i < n; i++) {
    const sd_json *w = sd_json_at(warnings, i);
    const char *id = sd_json_get_str(w, "mount_id");
    if (id != NULL && strcmp(id, mount_id) == 0)
      flags |= ui_mv_sec_flag(sd_json_get_str(w, "code"));
  }
  return flags;
}

static int name_char_ok(unsigned char c)
{
  return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '@' || c == '.' ||
         c == '_' || c == '+' || c == '-';
}

size_t ui_mv_algos_join(const sd_json *data, char *csv, size_t cap)
{
  const sd_json *arr = sd_json_get(data, "algorithms");
  size_t i, n = sd_json_count(arr), kept = 0, len = 0;
  if (csv == NULL || cap == 0)
    return 0;
  csv[0] = 0;
  if (sd_json_type_of(arr) != SD_JSON_ARRAY)
    return 0;
  for (i = 0; i < n && kept < 16; i++) {
    const char *s = sd_json_str(sd_json_at(arr, i), NULL);
    size_t j, sl;
    int ok = 1;
    if (s == NULL || s[0] == 0)
      continue;
    sl = strlen(s);
    if (sl > 63)
      continue;
    for (j = 0; j < sl; j++)
      if (!name_char_ok((unsigned char)s[j]))
        ok = 0;
    if (!ok || len + sl + 2 > cap)
      continue;
    if (len > 0)
      csv[len++] = ',';
    memcpy(csv + len, s, sl);
    len += sl;
    csv[len] = 0;
    kept++;
  }
  return kept;
}

ui_mv_cat ui_mv_cat_of_token(const char *token)
{
  if (token == NULL)
    return UI_MV_CAT_OTHER;
  if (strcmp(token, "kex") == 0)
    return UI_MV_CAT_KEX;
  if (strcmp(token, "hostkey") == 0)
    return UI_MV_CAT_HOSTKEY;
  if (strcmp(token, "cipher") == 0)
    return UI_MV_CAT_CIPHER;
  if (strcmp(token, "mac") == 0)
    return UI_MV_CAT_MAC;
  return UI_MV_CAT_OTHER;
}

int ui_mv_scope_of_token(const char *token)
{
  if (token == NULL)
    return -1;
  if (strcmp(token, "user") == 0)
    return SD_PROFILE_SCOPE_USER;
  if (strcmp(token, "machine_template") == 0)
    return SD_PROFILE_SCOPE_USERS;
  if (strcmp(token, "global") == 0)
    return SD_PROFILE_SCOPE_SERVICE;
  return -1;
}

void ui_mv_security_from_mount(const sd_json *mount, const sd_json *warnings, const char *mount_id, ui_mv_security *out)
{
  int legacy = 0, terrapin = 0;
  int has_legacy = sd_json_get_bool(mount, "legacy", &legacy);
  int has_terrapin = sd_json_get_bool(mount, "terrapin_exposed", &terrapin);
  memset(out, 0, sizeof(*out));
  if (!has_legacy && !has_terrapin) {
    out->sec = ui_mv_sec_from_warnings(warnings, mount_id);
    return;
  }
  out->from_mount = 1;
  if (legacy)
    out->sec |= UI_MV_SEC_LEGACY;
  if (terrapin)
    out->sec |= UI_MV_SEC_TERRAPIN;
  {
    const sd_json *arr = sd_json_get(mount, "legacy_algorithms");
    size_t i, n = sd_json_count(arr), len = 0;
    if (sd_json_type_of(arr) != SD_JSON_ARRAY)
      return;
    for (i = 0; i < n && out->n_algos < UI_MV_ALGOS_N; i++) {
      const sd_json *e = sd_json_at(arr, i);
      const char *name = sd_json_get_str(e, "name");
      size_t j, sl;
      int ok = 1;
      if (name == NULL || name[0] == 0)
        continue;
      sl = strlen(name);
      if (sl > 63)
        continue;
      for (j = 0; j < sl; j++)
        if (!name_char_ok((unsigned char)name[j]))
          ok = 0;
      if (!ok || len + sl + 2 > sizeof(out->algos))
        continue;
      if (len > 0)
        out->algos[len++] = ',';
      memcpy(out->algos + len, name, sl);
      len += sl;
      out->algos[len] = 0;
      out->cats[out->n_algos++] = (unsigned char)ui_mv_cat_of_token(sd_json_get_str(e, "category"));
    }
    /* a mount with the flag but no list (an older agent): the names stay unknown */
  }
}

size_t ui_mv_algos_split(const char *csv, char names[][64], size_t cap)
{
  size_t n = 0;
  const char *p = csv;
  while (p != NULL && *p != 0 && n < cap) {
    const char *e = strchr(p, ',');
    size_t len = e ? (size_t)(e - p) : strlen(p);
    if (len > 0 && len < 64) {
      memcpy(names[n], p, len);
      names[n][len] = 0;
      n++;
    }
    p = e ? e + 1 : NULL;
  }
  return n;
}

int ui_mv_algos_hash(const char *csv, char out[80])
{
  char names[16][64];
  const char *ptrs[16];
  size_t i, n = ui_mv_algos_split(csv, names, 16);
  out[0] = 0;
  if (n == 0)
    return 0;
  for (i = 0; i < n; i++)
    ptrs[i] = names[i];
  sd_legacy_set_hash(ptrs, (uint32_t)n, out);
  return out[0] != 0;
}

ui_mv_status ui_mv_status_of(const char *state, const char *session, int attempt)
{
  if (state == NULL || state[0] == 0)
    return UI_MV_ST_NOT_MOUNTED;
  if (strcmp(state, "connecting") == 0)
    return UI_MV_ST_CONNECTING;
  if (strcmp(state, "authenticating") == 0)
    return UI_MV_ST_AUTHENTICATING;
  if (strcmp(state, "mounted") == 0)
    return UI_MV_ST_MOUNTED;
  if (strcmp(state, "offline") == 0)
    return (session != NULL && strcmp(session, "reconnect_wait") == 0 && attempt > 0) ? UI_MV_ST_RECONNECTING
                                                                                      : UI_MV_ST_OFFLINE;
  if (strcmp(state, "auth_required") == 0)
    return UI_MV_ST_AUTH_REQUIRED;
  if (strcmp(state, "failed") == 0)
    return UI_MV_ST_FAILED;
  if (strcmp(state, "unmounting") == 0)
    return UI_MV_ST_UNMOUNTING;
  if (strcmp(state, "unmounted") == 0)
    return UI_MV_ST_UNMOUNTED;
  return UI_MV_ST_UNKNOWN;
}

int ui_mv_is_mounted(const char *state, const char *session, int attempt)
{
  ui_mv_status st = ui_mv_status_of(state, session, attempt);
  return st == UI_MV_ST_MOUNTED || st == UI_MV_ST_RECONNECTING;
}

int ui_mv_is_failed(const char *state, const char *session, int attempt)
{
  return ui_mv_status_of(state, session, attempt) == UI_MV_ST_FAILED;
}

ui_mv_icon ui_mv_status_icon(ui_mv_status st)
{
  switch (st) {
  case UI_MV_ST_MOUNTED:
    return UI_MV_ICON_OK;
  case UI_MV_ST_RECONNECTING:
  case UI_MV_ST_OFFLINE:
  case UI_MV_ST_AUTH_REQUIRED:
  case UI_MV_ST_FAILED:
    return UI_MV_ICON_WARN;
  case UI_MV_ST_CONNECTING:
  case UI_MV_ST_AUTHENTICATING:
  case UI_MV_ST_UNMOUNTING:
    return UI_MV_ICON_IDLE;
  default:
    return UI_MV_ICON_NONE;
  }
}

ui_mv_icon ui_mv_sec_icon(unsigned sec)
{
  return sec != 0 ? UI_MV_ICON_WARN : UI_MV_ICON_NONE;
}

ui_mv_group ui_mv_group_of_scope(int scope)
{
  if (scope == SD_PROFILE_SCOPE_USERS)
    return UI_MV_GROUP_ORG;
  if (scope == SD_PROFILE_SCOPE_SERVICE)
    return UI_MV_GROUP_GLOBAL;
  return UI_MV_GROUP_MINE;
}

int ui_mv_scope_read_only(int scope)
{
  return scope == SD_PROFILE_SCOPE_USERS;
}

static int starts(const char *s, const char *p)
{
  return strncmp(s, p, strlen(p)) == 0;
}

static int ends(const char *s, const char *suffix)
{
  size_t n = strlen(s), m = strlen(suffix);
  return n >= m && strcmp(s + n - m, suffix) == 0;
}

void ui_mv_algo_info(const char *name, ui_mv_cat *cat, ui_mv_why *why)
{
  ui_mv_cat c = UI_MV_CAT_OTHER;
  ui_mv_why w = UI_MV_WHY_OTHER;
  if (name == NULL)
    name = "";
  if (starts(name, "diffie-hellman-") || starts(name, "curve25519") || starts(name, "ecdh-") ||
      starts(name, "mlkem") || starts(name, "sntrup")) {
    c = UI_MV_CAT_KEX;
    if (strstr(name, "sha1") != NULL)
      w = UI_MV_WHY_KEX_SHA1;
  } else if (starts(name, "ssh-rsa") || starts(name, "ssh-dss") || starts(name, "ssh-ed") || starts(name, "ecdsa-") ||
             starts(name, "rsa-sha2")) {
    c = UI_MV_CAT_HOSTKEY;
    if (starts(name, "ssh-rsa") || starts(name, "ssh-dss"))
      w = UI_MV_WHY_HOSTKEY_SHA1;
  } else if (starts(name, "hmac-") || starts(name, "umac-")) {
    c = UI_MV_CAT_MAC;
    if (starts(name, "hmac-sha1") || starts(name, "hmac-md5"))
      w = UI_MV_WHY_MAC_SHA1;
  } else if (starts(name, "aes") || starts(name, "3des") || starts(name, "chacha") || starts(name, "blowfish") ||
             starts(name, "cast128") || starts(name, "arcfour")) {
    c = UI_MV_CAT_CIPHER;
    if (ends(name, "-cbc"))
      w = UI_MV_WHY_CBC;
  }
  if (cat != NULL)
    *cat = c;
  if (why != NULL)
    *why = w;
}
