/* shelldrive-ui: the model of the tray notices (ui_notice_model.h). */
#include <windows.h>
#include <string.h>

#include "sd_config/sd_config.h"
#include "ui_notice_model.h"

static int same(const char *a, const char *b)
{
  return a != NULL && b != NULL && strcmp(a, b) == 0;
}

ui_nt_kind ui_nt_of_mount_state(const char *prev_state, const char *state, const char *error_code)
{
  if (state == NULL || state[0] == 0)
    return UI_NT_NONE;
  if (prev_state == NULL)
    prev_state = "";
  if (strcmp(state, "mounted") == 0) {
    if (strcmp(prev_state, "mounted") == 0)
      return UI_NT_NONE;                 /* the same state with new connection details */
    return strcmp(prev_state, "offline") == 0 ? UI_NT_RECONNECTED : UI_NT_MOUNTED;
  }
  if (strcmp(state, "offline") == 0)
    return strcmp(prev_state, "mounted") == 0 ? UI_NT_CONNECTION_LOST : UI_NT_NONE;
  if (strcmp(state, "failed") == 0) {
    if (strcmp(prev_state, "failed") == 0)
      return UI_NT_NONE;
    /* a changed host key and a wrong key type raise their own balloons, which cannot be switched off (5.4, 7.7) */
    if (same(error_code, "host_key_mismatch") || same(error_code, "host_key_type_unavailable"))
      return UI_NT_NONE;
    return UI_NT_MOUNT_FAILED;
  }
  return UI_NT_NONE;
}

ui_nt_kind ui_nt_of_warning_code(const char *code)
{
  if (code == NULL)
    return UI_NT_NONE;
  if (strcmp(code, "proxy_cleartext") == 0 || strcmp(code, "proxy_password") == 0)
    return UI_NT_PROXY_PASSWORD;
  if (strcmp(code, "pool_limited") == 0)
    return UI_NT_POOL_LIMITED;
  if (strcmp(code, "disk_cache_refused") == 0)
    return UI_NT_DISK_CACHE;
  return UI_NT_NONE;
}

int ui_nt_switch_of(ui_nt_kind k)
{
  switch (k) {
  case UI_NT_CONNECTION_LOST:    return SD_NOTIFY_CONNECTION_LOST;
  case UI_NT_RECONNECTED:        return SD_NOTIFY_RECONNECTED;
  case UI_NT_MOUNT_FAILED:       return SD_NOTIFY_MOUNT_FAILED;
  case UI_NT_MOUNTED:            return SD_NOTIFY_MOUNTED;
  case UI_NT_PROXY_PASSWORD:     return SD_NOTIFY_PROXY_PASSWORD;
  case UI_NT_POOL_LIMITED:       return SD_NOTIFY_POOL_LIMITED;
  case UI_NT_SERVICE_ATTENTION:  return SD_NOTIFY_SERVICE_ATTENTION;
  case UI_NT_HOSTKEYS_SAVED:     return SD_NOTIFY_HOSTKEYS_SAVED;
  case UI_NT_DISK_CACHE:         return SD_NOTIFY_DISK_CACHE;
  default:                       return -1;
  }
}

int ui_nt_attention_grew(int previous, int now)
{
  return now > 0 && now > previous;
}

int ui_nt_once_take(ui_nt_once *o, const char *key)
{
  char cut[UI_NT_ONCE_KEY_MAX];
  size_t i, n;
  memset(cut, 0, sizeof(cut));
  if (o == NULL || key == NULL)
    return 0;
  n = strlen(key);
  if (n >= sizeof(cut))
    n = sizeof(cut) - 1;
  memcpy(cut, key, n);
  cut[n] = 0;
  cut[UI_NT_ONCE_KEY_MAX - 1] = 0;
  for (i = 0; i < UI_NT_ONCE_SLOTS; i++)
    if (o->key[i][0] != 0 && strncmp(o->key[i], cut, UI_NT_ONCE_KEY_MAX) == 0)
      return 0;
  memset(o->key[o->next], 0, UI_NT_ONCE_KEY_MAX);
  memcpy(o->key[o->next], cut, n);
  o->next = (o->next + 1) % UI_NT_ONCE_SLOTS;
  return 1;
}

int ui_nt_once_key(const char *profile, const char *proxy, char *out, size_t cap)
{
  size_t a = profile != NULL ? strlen(profile) : 0, b = proxy != NULL ? strlen(proxy) : 0;
  if (out == NULL || cap == 0 || a + b + 2 > cap)
    return 0;
  if (a > 0)
    memcpy(out, profile, a);
  out[a] = '|';
  if (b > 0)
    memcpy(out + a + 1, proxy, b);
  out[a + 1 + b] = 0;
  return 1;
}
