/* shelldrive-ui: the profile editor's model (ui_profile_model.h). Pure. */
#include <windows.h>
#include <string.h>
#include <stdio.h>

#include "sd_base/sd_mem.h"
#include "ui_profile_model.h"

/* ---- text fields: the buffer of each, by field ---- */

static char *text_slot(sd_profile *p, ui_pfield f, size_t *cap)
{
  switch (f) {
  case UI_PF_NAME:           *cap = sizeof(p->name);            return p->name;
  case UI_PF_HOST:           *cap = sizeof(p->host);            return p->host;
  case UI_PF_USER:           *cap = sizeof(p->user);            return p->user;
  case UI_PF_REMOTE_PATH:    *cap = sizeof(p->remote_path);     return p->remote_path;
  case UI_PF_IDENTITY:       *cap = sizeof(p->identity);        return p->identity;
  case UI_PF_CERTIFICATE:    *cap = sizeof(p->certificate);     return p->certificate;
  case UI_PF_JUMP:           *cap = sizeof(p->jump);            return p->jump;
  case UI_PF_PROXY_HOST:     *cap = sizeof(p->proxy[0].host);   return p->proxy[0].host;
  case UI_PF_PROXY_USER:     *cap = sizeof(p->proxy[0].user);   return p->proxy[0].user;
  case UI_PF_TARGET:         *cap = sizeof(p->target);          return p->target;
  case UI_PF_LABEL:          *cap = sizeof(p->label);           return p->label;
  case UI_PF_HOST_KEY_ALIAS: *cap = sizeof(p->host_key_alias); return p->host_key_alias;
  default:                   *cap = 0;                          return NULL;
  }
}

int ui_pform_is_text(ui_pfield f)
{
  switch (f) {
  case UI_PF_NAME: case UI_PF_HOST: case UI_PF_USER: case UI_PF_REMOTE_PATH: case UI_PF_IDENTITY:
  case UI_PF_CERTIFICATE: case UI_PF_JUMP: case UI_PF_PROXY_HOST: case UI_PF_PROXY_USER: case UI_PF_TARGET:
  case UI_PF_LABEL: case UI_PF_HOST_KEY_ALIAS:
    return 1;
  default:
    return 0;
  }
}

/* ---- numbers ---- */

static int parse_u32(const char *s, unsigned long *out)
{
  unsigned long long v = 0;
  size_t i;
  if (s[0] == 0)
    return 0;
  for (i = 0; s[i]; i++) {
    if (s[i] < '0' || s[i] > '9')
      return 0;
    v = v * 10u + (unsigned)(s[i] - '0');
    if (v > 0xFFFFFFFFull)
      return 0;
  }
  *out = (unsigned long)v;
  return 1;
}

static void trim(char *s)
{
  size_t n = strlen(s), a = 0;
  while (a < n && (s[a] == ' ' || s[a] == '\t'))
    a++;
  while (n > a && (s[n - 1] == ' ' || s[n - 1] == '\t'))
    n--;
  if (a)
    memmove(s, s + a, n - a);
  s[n - a] = 0;
}

sd_err ui_pform_get(const sd_profile *p, ui_pfield f, char *out, size_t cap)
{
  char tmp[32];
  const char *v = NULL;
  size_t n;
  if (p == NULL || out == NULL || cap == 0 || f < 0 || f >= UI_PF_COUNT)
    return SD_E_INVALID_PARAM;
  if (ui_pform_is_text(f)) {
    size_t tcap;
    v = text_slot((sd_profile *)p, f, &tcap);   /* read-only use of the slot */
    if (v == NULL)
      return SD_E_INVALID_PARAM;
  } else {
    unsigned long x = 0;
    switch (f) {
    case UI_PF_PORT:               x = p->port; break;
    case UI_PF_METHOD_PUBLICKEY:   x = (p->auth_methods & SD_PROFILE_AUTH_PUBLICKEY) != 0; break;
    case UI_PF_METHOD_KBDINT:      x = (p->auth_methods & SD_PROFILE_AUTH_KBDINT) != 0; break;
    case UI_PF_METHOD_PASSWORD:    x = (p->auth_methods & SD_PROFILE_AUTH_PASSWORD) != 0; break;
    case UI_PF_AGENT:              x = (unsigned long)p->agent; break;
    case UI_PF_IDENTITIES_ONLY:
      if (p->identities_only < 0) {
        sprintf_s(tmp, sizeof(tmp), "-1");
        v = tmp;
        break;
      }
      x = p->identities_only ? 1 : 0;
      break;
    case UI_PF_SAVE_PASSWORD:      x = p->save_password ? 1 : 0; break;
    case UI_PF_CACHE_SECRETS:      x = p->cache_secrets ? 1 : 0; break;
    case UI_PF_PROXY_KIND:         x = (unsigned long)p->proxy[0].kind; break;
    case UI_PF_PROXY_PORT:         x = p->proxy[0].port; break;
    case UI_PF_PROXY_AUTH:         x = (unsigned long)p->proxy_auth[0]; break;
    case UI_PF_CONNECTIONS:        x = p->connections; break;
    case UI_PF_KEEPALIVE:          x = p->keepalive_ms; break;
    case UI_PF_CONNECT_TIMEOUT:    x = p->connect_timeout_ms; break;
    case UI_PF_BACKEND:            x = (unsigned long)p->backend; break;
    case UI_PF_READ_ONLY:          x = p->read_only ? 1 : 0; break;
    case UI_PF_WRITE_MODE:         x = (unsigned long)p->write_mode; break;
    case UI_PF_SYMLINKS:           x = (unsigned long)p->symlinks; break;
    case UI_PF_OFFLINE_WAIT:       x = p->offline_wait_ms; break;
    case UI_PF_NETWORK_LOCATION:   x = p->network_location ? 1 : 0; break;
    case UI_PF_DISK_CACHE:         x = p->disk_cache_mb; break;
    case UI_PF_LEGACY:             x = (unsigned long)p->legacy_algorithms; break;
    case UI_PF_UPDATE_HOST_KEYS:   x = (unsigned long)p->update_host_keys; break;
    case UI_PF_REFUSE_TERRAPIN:    x = p->refuse_terrapin_exposed ? 1 : 0; break;
    default:
      return SD_E_INVALID_PARAM;
    }
    if (v == NULL) {
      sprintf_s(tmp, sizeof(tmp), "%lu", x);
      v = tmp;
    }
  }
  n = strlen(v);
  if (n >= cap)
    return SD_E_INVALID_PARAM;
  memcpy(out, v, n + 1);
  return SD_OK;
}

sd_err ui_pform_set(sd_profile *p, ui_pfield f, const char *text)
{
  char buf[UI_PF_TEXT_MAX];
  unsigned long x = 0;
  size_t tcap = 0;
  char *slot;
  if (p == NULL || text == NULL || f < 0 || f >= UI_PF_COUNT)
    return SD_E_INVALID_PARAM;
  if (strlen(text) >= sizeof(buf))
    return SD_E_INVALID_PARAM;
  strcpy_s(buf, sizeof(buf), text);
  trim(buf);
  if (ui_pform_is_text(f)) {
    slot = text_slot(p, f, &tcap);
    if (slot == NULL || strlen(buf) >= tcap)
      return SD_E_INVALID_PARAM;
    strcpy_s(slot, tcap, buf);
    return SD_OK;
  }
  if (f == UI_PF_IDENTITIES_ONLY && strcmp(buf, "-1") == 0) {
    p->identities_only = SD_PROFILE_UNSET;
    return SD_OK;
  }
  if (!parse_u32(buf, &x))
    return SD_E_INVALID_PARAM;
  switch (f) {
  case UI_PF_PORT:
    if (x > 65535u) return SD_E_INVALID_PARAM;
    p->port = (uint16_t)x;
    break;
  case UI_PF_METHOD_PUBLICKEY:
  case UI_PF_METHOD_KBDINT:
  case UI_PF_METHOD_PASSWORD: {
    uint32_t bit = f == UI_PF_METHOD_PUBLICKEY ? SD_PROFILE_AUTH_PUBLICKEY
                 : f == UI_PF_METHOD_KBDINT ? SD_PROFILE_AUTH_KBDINT : SD_PROFILE_AUTH_PASSWORD;
    if (x > 1) return SD_E_INVALID_PARAM;
    p->auth_methods = x ? (p->auth_methods | bit) : (p->auth_methods & ~bit);
    break;
  }
  case UI_PF_AGENT:              p->agent = (int)x; break;
  case UI_PF_IDENTITIES_ONLY:    if (x > 1) return SD_E_INVALID_PARAM; p->identities_only = (int)x; break;
  case UI_PF_SAVE_PASSWORD:      if (x > 1) return SD_E_INVALID_PARAM; p->save_password = (int)x; break;
  case UI_PF_CACHE_SECRETS:      if (x > 1) return SD_E_INVALID_PARAM; p->cache_secrets = (int)x; break;
  case UI_PF_PROXY_KIND:         p->proxy[0].kind = (int)x; break;
  case UI_PF_PROXY_PORT:
    if (x > 65535u) return SD_E_INVALID_PARAM;
    p->proxy[0].port = (uint16_t)x;
    break;
  case UI_PF_PROXY_AUTH:         p->proxy_auth[0] = (int)x; break;
  case UI_PF_CONNECTIONS:        p->connections = (uint32_t)x; break;
  case UI_PF_KEEPALIVE:          p->keepalive_ms = (uint32_t)x; break;
  case UI_PF_CONNECT_TIMEOUT:    p->connect_timeout_ms = (uint32_t)x; break;
  case UI_PF_BACKEND:            p->backend = (int)x; break;
  case UI_PF_READ_ONLY:          if (x > 1) return SD_E_INVALID_PARAM; p->read_only = (int)x; break;
  case UI_PF_WRITE_MODE:         p->write_mode = (int)x; p->write_mode_set = 1; break;   /* an edit makes the key explicit (M4) */
  case UI_PF_SYMLINKS:           p->symlinks = (int)x; break;
  case UI_PF_OFFLINE_WAIT:       p->offline_wait_ms = (uint32_t)x; break;
  case UI_PF_NETWORK_LOCATION:   if (x > 1) return SD_E_INVALID_PARAM; p->network_location = (int)x; break;
  case UI_PF_DISK_CACHE:         p->disk_cache_mb = (uint32_t)x; break;
  case UI_PF_LEGACY:             p->legacy_algorithms = (int)x; break;
  case UI_PF_UPDATE_HOST_KEYS:   p->update_host_keys = (int)x; break;
  case UI_PF_REFUSE_TERRAPIN:    if (x > 1) return SD_E_INVALID_PARAM; p->refuse_terrapin_exposed = (int)x; break;
  default:
    return SD_E_INVALID_PARAM;
  }
  return SD_OK;
}

/* ---- validation ---- */

static int has_ctl(const char *s)
{
  for (; *s; s++)
    if ((unsigned char)*s < 0x20 || *s == 0x7F)
      return 1;
  return 0;
}

static size_t add_err(ui_pferr *out, size_t cap, size_t n, int field, ui_perr code)
{
  if (out != NULL && n < cap) {
    out[n].field = field;
    out[n].code = code;
  }
  return n + 1;
}

/* sd_profile_validate's bad key ("section.key") to a field; unknown keys stay general errors. */
static void map_bad_key(const char *bad, int *field, ui_perr *code)
{
  static const struct { const char *key; int field; } k_map[] = {
    { "profile.name", UI_PF_NAME },              { "profile.host", UI_PF_HOST },
    { "profile.port", UI_PF_PORT },              { "profile.user", UI_PF_USER },
    { "profile.remote_path", UI_PF_REMOTE_PATH }, { "auth.identity", UI_PF_IDENTITY },
    { "auth.methods", UI_PF_METHOD_PUBLICKEY },  { "auth.agent", UI_PF_AGENT },
    { "mount.target", UI_PF_TARGET },            { "mount.symlinks", UI_PF_SYMLINKS },
    { "mount.write_mode", UI_PF_WRITE_MODE },    { "mount.backend", UI_PF_BACKEND },
    { "mount.offline_wait", UI_PF_OFFLINE_WAIT }, { "cache.disk", UI_PF_DISK_CACHE },
    { "mount.label", UI_PF_LABEL },              { "connection.connections", UI_PF_CONNECTIONS },
    { "connection.channels", UI_PF_CONNECTIONS }, { "security.legacy_algorithms", UI_PF_LEGACY },
    { "security.update_host_keys", UI_PF_UPDATE_HOST_KEYS },
    { "security.host_key_alias", UI_PF_HOST_KEY_ALIAS },
    { "proxy.jump", UI_PF_JUMP },                { "proxy.proxy", UI_PF_PROXY_HOST },
  };
  size_t i;
  *field = UI_PF_NONE;
  *code = UI_PERR_OTHER;
  if (bad == NULL)
    return;
  for (i = 0; i < SD_COUNTOF(k_map); i++) {
    if (strcmp(bad, k_map[i].key) == 0) {
      *field = k_map[i].field;
      return;
    }
  }
}

size_t ui_pform_validate(const sd_profile *p, ui_pferr *out, size_t cap)
{
  size_t n = 0;
  const char *bad = NULL;
  if (p == NULL)
    return 0;
  if (p->name[0] == 0 || has_ctl(p->name))
    n = add_err(out, cap, n, UI_PF_NAME, UI_PERR_NAME);
  if (p->host[0] == 0)
    n = add_err(out, cap, n, UI_PF_HOST, UI_PERR_HOST);
  if (p->port == 0)
    n = add_err(out, cap, n, UI_PF_PORT, UI_PERR_PORT);
  if (p->auth_methods == 0)
    n = add_err(out, cap, n, UI_PF_METHOD_PUBLICKEY, UI_PERR_METHODS);
  if (p->connections < 1 || p->connections > 4)
    n = add_err(out, cap, n, UI_PF_CONNECTIONS, UI_PERR_CONNECTIONS);
  if (p->proxy[0].kind == SD_PROFILE_PROXY_HTTP || p->proxy[0].kind == SD_PROFILE_PROXY_SOCKS5) {
    if (p->proxy[0].host[0] == 0)
      n = add_err(out, cap, n, UI_PF_PROXY_HOST, UI_PERR_PROXY_HOST);
    if (p->proxy[0].port == 0)
      n = add_err(out, cap, n, UI_PF_PROXY_PORT, UI_PERR_PROXY_PORT);
  }
  /* The authoritative rules of sd_config; reported only when the checks above pass, one error at a time. */
  if (n == 0 && sd_profile_validate(p, &bad) != SD_OK) {
    int field;
    ui_perr code;
    map_bad_key(bad, &field, &code);
    n = add_err(out, cap, n, field, code);
  }
  return n;
}

/* ---- drives ---- */

size_t ui_drive_free_list(uint32_t used_mask, wchar_t out[UI_DRIVE_CANDIDATES][3])
{
  size_t n = 0;
  unsigned i;
  for (i = 3; i < 26; i++) {           /* D..Z: A and B are floppies, C is the system drive */
    if (used_mask & (1u << i))
      continue;
    out[n][0] = (wchar_t)(L'A' + i);
    out[n][1] = L':';
    out[n][2] = 0;
    n++;
  }
  return n;
}

/* ---- JSON and mount parameters ---- */

sd_err ui_json_escape(const char *in, char *out, size_t cap)
{
  size_t o = 0;
  const char *s;
  if (in == NULL || out == NULL || cap == 0)
    return SD_E_INVALID_PARAM;
  for (s = in; *s; s++) {
    unsigned char c = (unsigned char)*s;
    char piece[8];
    size_t k, plen;
    if (c == '"' || c == '\\') {
      piece[0] = '\\';
      piece[1] = (char)c;
      plen = 2;
    } else if (c < 0x20) {
      sprintf_s(piece, sizeof(piece), "\\u%04x", (unsigned)c);
      plen = 6;
    } else {
      piece[0] = (char)c;
      plen = 1;
    }
    if (o + plen + 1 > cap)
      return SD_E_INVALID_PARAM;
    for (k = 0; k < plen; k++)
      out[o++] = piece[k];
  }
  out[o] = 0;
  return SD_OK;
}

/* Appends text to a bounded buffer. */
static sd_err put(char *out, size_t cap, size_t *len, const char *text)
{
  size_t n = strlen(text);
  if (*len + n + 1 > cap)
    return SD_E_INVALID_PARAM;
  memcpy(out + *len, text, n + 1);
  *len += n;
  return SD_OK;
}

/* "key":"value" with the value escaped. */
static sd_err put_str(char *out, size_t cap, size_t *len, const char *key, const char *value)
{
  char esc[6 * UI_PF_TEXT_MAX + 8];   /* worst case: every byte escaped as \u00XX */
  char head[80];
  if (strlen(key) > 40 || ui_json_escape(value, esc, sizeof(esc)) != SD_OK)
    return SD_E_INVALID_PARAM;
  sprintf_s(head, sizeof(head), "\"%s\":\"", key);
  if (put(out, cap, len, head) != SD_OK)
    return SD_E_INVALID_PARAM;
  if (put(out, cap, len, esc) != SD_OK)
    return SD_E_INVALID_PARAM;
  return put(out, cap, len, "\"");
}

sd_err ui_mount_params_json(const sd_profile *p, int adhoc, const char *target, int read_only,
                            const char *backend, char *out, size_t cap)
{
  size_t len = 0;
  char num[32];
  char proxy[512];
  sd_err e = SD_OK;

  if (p == NULL || out == NULL || cap == 0)
    return SD_E_INVALID_PARAM;
  out[0] = 0;
  e = put(out, cap, &len, "{");
  if (adhoc) {
    e = e == SD_OK ? put(out, cap, &len, "\"adhoc\":{") : e;
    e = e == SD_OK ? put_str(out, cap, &len, "host", p->host) : e;
    sprintf_s(num, sizeof(num), "%u", (unsigned)p->port);
    e = e == SD_OK ? put(out, cap, &len, ",\"port\":") : e;
    e = e == SD_OK ? put(out, cap, &len, num) : e;
    if (p->user[0] && e == SD_OK) e = put(out, cap, &len, ",") == SD_OK ? put_str(out, cap, &len, "user", p->user) : SD_E_INVALID_PARAM;
    if (p->identity[0] && e == SD_OK) e = put(out, cap, &len, ",") == SD_OK ? put_str(out, cap, &len, "identity", p->identity) : SD_E_INVALID_PARAM;
    if (p->remote_path[0] && e == SD_OK) e = put(out, cap, &len, ",") == SD_OK ? put_str(out, cap, &len, "remote_path", p->remote_path) : SD_E_INVALID_PARAM;
    if (p->jump[0] && e == SD_OK) e = put(out, cap, &len, ",") == SD_OK ? put_str(out, cap, &len, "jump", p->jump) : SD_E_INVALID_PARAM;
    if (p->proxy[0].kind != SD_PROFILE_PROXY_NONE && e == SD_OK) {
      if (sd_proxy_spec_format(&p->proxy[0], proxy, sizeof(proxy)) != SD_OK)
        return SD_E_INVALID_PARAM;
      e = put(out, cap, &len, ",") == SD_OK ? put_str(out, cap, &len, "proxy", proxy) : SD_E_INVALID_PARAM;
    }
    e = e == SD_OK ? put(out, cap, &len, "}") : e;
  } else {
    e = e == SD_OK ? put_str(out, cap, &len, "profile", p->id) : e;
  }
  if (target != NULL && e == SD_OK)
    e = put(out, cap, &len, ",") == SD_OK ? put_str(out, cap, &len, "target", target) : SD_E_INVALID_PARAM;
  if (backend != NULL && e == SD_OK)
    e = put(out, cap, &len, ",") == SD_OK ? put_str(out, cap, &len, "backend", backend) : SD_E_INVALID_PARAM;
  if (read_only && e == SD_OK)
    e = put(out, cap, &len, ",\"read_only\":true");
  if (e == SD_OK)
    e = put(out, cap, &len, "}");
  if (e != SD_OK)
    out[0] = 0;
  return e;
}
