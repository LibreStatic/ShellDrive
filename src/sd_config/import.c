/* Profile importers: PuTTY sessions (registry or .reg export) and ssh_config (03 §3.7). See sd_import.h. */
#include <windows.h>
#include <string.h>

#include "sd_config/sd_import.h"
#include "config_internal.h"
#include "sd_base/sd_mem.h"
#include "sd_base/sd_utf.h"
#include "sd_platform/sd_log.h"

#define PUTTY_SESSIONS L"Software\\SimonTatham\\PuTTY\\Sessions"
#define MAX_VALUES 16          /* only the values listed in k_putty_values are kept */
#define MAX_SESSIONS 512

/* ---- result ---- */

void sd_import_result_init(sd_import_result *r)
{
  memset(r, 0, sizeof(*r));
}

void sd_import_result_free(sd_import_result *r)
{
  if (r == NULL) return;
  sd_free(r->items);
  sd_free(r->skipped);
  memset(r, 0, sizeof(*r));
}

static sd_import_candidate *add_item(sd_import_result *r)
{
  sd_import_candidate *c;
  if (r->count == r->cap) {
    uint32_t nc = r->cap ? r->cap * 2 : 8;
    sd_import_candidate *n = (sd_import_candidate *)sd_alloc((size_t)nc * sizeof(*n));
    if (n == NULL) return NULL;
    if (r->count) memcpy(n, r->items, (size_t)r->count * sizeof(*n));
    sd_free(r->items);
    r->items = n;
    r->cap = nc;
  }
  c = &r->items[r->count++];
  memset(c, 0, sizeof(*c));
  sd_profile_defaults(&c->p);
  c->selected = 1;
  return c;
}

static void add_skip(sd_import_result *r, sd_import_skip_kind k, const char *source, const char *item, uint32_t line)
{
  sd_import_skip *s;
  if (r->nskipped == r->skip_cap) {
    uint32_t nc = r->skip_cap ? r->skip_cap * 2 : 8;
    sd_import_skip *n = (sd_import_skip *)sd_alloc((size_t)nc * sizeof(*n));
    if (n == NULL) return;
    if (r->nskipped) memcpy(n, r->skipped, (size_t)r->nskipped * sizeof(*n));
    sd_free(r->skipped);
    r->skipped = n;
    r->skip_cap = nc;
  }
  s = &r->skipped[r->nskipped++];
  memset(s, 0, sizeof(*s));
  s->kind = k;
  strncpy_s(s->source, sizeof(s->source), source ? source : "", _TRUNCATE);
  strncpy_s(s->item, sizeof(s->item), item ? item : "", _TRUNCATE);
  s->line = line;
}

static void drop_last(sd_import_result *r) { if (r->count) r->count--; }

/* ---- PuTTY session model ---- */

typedef struct pt_value { char name[48]; int is_num; uint32_t num; char str[MAX_PATH * 3]; } pt_value;
typedef struct pt_session { char name[256]; uint32_t nvalues; pt_value v[MAX_VALUES]; } pt_session;

static pt_value *pt_find(pt_session *s, const char *name)
{
  uint32_t i;
  if (s == NULL) return NULL;
  for (i = 0; i < s->nvalues; i++)
    if (_stricmp(s->v[i].name, name) == 0) return &s->v[i];
  return NULL;
}

static const char *const k_putty_values[] = {
  "HostName", "PortNumber", "UserName", "Protocol", "PublicKeyFile", "DetachedCertificate",
  "ProxyMethod", "ProxyHost", "ProxyPort", "ProxyUsername"
};

/* NULL for values the importer does not read (a PuTTY session has about 200). */
static pt_value *pt_add(pt_session *s, const char *name)
{
  pt_value *v = pt_find(s, name);
  size_t i;
  int wanted = 0;
  if (v) return v;
  for (i = 0; i < SD_COUNTOF(k_putty_values); i++)
    if (_stricmp(k_putty_values[i], name) == 0) wanted = 1;
  if (!wanted) return NULL;
  if (s->nvalues >= MAX_VALUES || strlen(name) >= sizeof(v->name)) return NULL;
  v = &s->v[s->nvalues++];
  memset(v, 0, sizeof(*v));
  strcpy_s(v->name, sizeof(v->name), name);
  return v;
}

/* Value of session s, else of the defaults; NULL when neither has it. */
static pt_value *pt_get(pt_session *s, pt_session *def, const char *name)
{
  pt_value *v = pt_find(s, name);
  return v ? v : pt_find(def, name);
}

static const char *pt_str(pt_session *s, pt_session *def, const char *name)
{
  pt_value *v = pt_get(s, def, name);
  return (v && !v->is_num) ? v->str : "";
}

static int pt_num(pt_session *s, pt_session *def, const char *name, uint32_t *out)
{
  pt_value *v = pt_get(s, def, name);
  if (v == NULL) return 0;
  if (v->is_num) { *out = v->num; return 1; }
  return sd_ini_parse_u32(v->str, out);
}

static int hexval(char c)
{
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

/* PuTTY escapes session names like URLs ("My%20Server"). */
static void url_decode(const char *in, char *out, size_t cap)
{
  size_t o = 0;
  while (*in && o + 1 < cap) {
    if (in[0] == '%' && hexval(in[1]) >= 0 && hexval(in[2]) >= 0) {
      out[o++] = (char)(hexval(in[1]) * 16 + hexval(in[2]));
      in += 3;
    } else {
      out[o++] = *in++;
    }
  }
  out[o] = 0;
}

static void candidate_from_putty(sd_import_result *r, pt_session *s, pt_session *def)
{
  const char *hn = pt_str(s, def, "HostName"), *proto = pt_str(s, def, "Protocol");
  const char *bad = NULL;
  sd_import_candidate *c;
  uint32_t port = 22, method = 0;
  char user[128], host[256];
  uint16_t hp = 0;
  if (_stricmp(s->name, "Default Settings") == 0)
    return;
  if (proto[0] && _stricmp(proto, "ssh") != 0) {
    add_skip(r, SD_IMPORT_SKIP_NOT_SSH, s->name, proto, 0);
    return;
  }
  if (hn[0] == 0) {
    add_skip(r, SD_IMPORT_SKIP_INVALID, s->name, "HostName", 0);
    return;
  }
  if (!sd_cfg_parse_host_spec_utf8(hn, user, sizeof(user), host, sizeof(host), &hp)) {
    add_skip(r, SD_IMPORT_SKIP_INVALID, s->name, "HostName", 0);
    return;
  }
  if ((c = add_item(r)) == NULL)
    return;
  strncpy_s(c->source, sizeof(c->source), s->name, _TRUNCATE);
  strncpy_s(c->p.name, sizeof(c->p.name), s->name, _TRUNCATE);
  strcpy_s(c->p.host, sizeof(c->p.host), host);
  if (pt_num(s, def, "PortNumber", &port) && port >= 1 && port <= 65535)
    c->p.port = (uint16_t)port;
  if (hp) c->p.port = hp;
  if (user[0]) strcpy_s(c->p.user, sizeof(c->p.user), user);
  else strncpy_s(c->p.user, sizeof(c->p.user), pt_str(s, def, "UserName"), _TRUNCATE);
  strncpy_s(c->p.identity, sizeof(c->p.identity), pt_str(s, def, "PublicKeyFile"), _TRUNCATE);
  strncpy_s(c->p.certificate, sizeof(c->p.certificate), pt_str(s, def, "DetachedCertificate"), _TRUNCATE);
  if (c->p.identity[0])
    c->flags |= SD_IMPORT_F_ONLY_THIS_KEY;
  if (pt_num(s, def, "ProxyMethod", &method) && method != 0) {
    const char *ph = pt_str(s, def, "ProxyHost"), *pu = pt_str(s, def, "ProxyUsername");
    uint32_t pport = 0;
    pt_num(s, def, "ProxyPort", &pport);
    if ((method == 2 || method == 3) && ph[0]) {
      sd_proxy_spec *x = &c->p.proxy[0];
      x->kind = method == 2 ? SD_PROFILE_PROXY_SOCKS5 : SD_PROFILE_PROXY_HTTP;
      strncpy_s(x->host, sizeof(x->host), ph, _TRUNCATE);
      x->port = (uint16_t)(pport >= 1 && pport <= 65535 ? pport : (method == 2 ? 1080 : 8080));
      strncpy_s(x->user, sizeof(x->user), pu, _TRUNCATE);
    } else if (method >= 6 && method <= 8 && ph[0]) {
      char num[16];
      sd_cfg_u32_dec(num, pport >= 1 && pport <= 65535 ? pport : 22);
      c->p.jump[0] = 0;
      if (pu[0]) { strcat_s(c->p.jump, sizeof(c->p.jump), pu); strcat_s(c->p.jump, sizeof(c->p.jump), "@"); }
      if (strchr(ph, ':')) strcat_s(c->p.jump, sizeof(c->p.jump), "[");
      strcat_s(c->p.jump, sizeof(c->p.jump), ph);
      if (strchr(ph, ':')) strcat_s(c->p.jump, sizeof(c->p.jump), "]");
      strcat_s(c->p.jump, sizeof(c->p.jump), ":");
      strcat_s(c->p.jump, sizeof(c->p.jump), num);
    } else {
      char num[16];
      sd_cfg_u32_dec(num, method);
      add_skip(r, SD_IMPORT_SKIP_PROXY, s->name, num, 0);
      c->flags |= SD_IMPORT_F_PROXY_SKIPPED;
    }
  }
  if (sd_profile_validate(&c->p, &bad) != SD_OK) {
    add_skip(r, SD_IMPORT_SKIP_INVALID, s->name, bad ? bad : "profile", 0);
    drop_last(r);
  }
}

typedef struct pt_set { pt_session *s; uint32_t n, cap; } pt_set;

static pt_session *pt_new(pt_set *set, const char *name)
{
  pt_session *s;
  uint32_t i;
  for (i = 0; i < set->n; i++)
    if (strcmp(set->s[i].name, name) == 0) return &set->s[i];
  if (set->n >= MAX_SESSIONS) return NULL;
  if (set->n == set->cap) {
    uint32_t nc = set->cap ? set->cap * 2 : 8;
    pt_session *n = (pt_session *)sd_alloc((size_t)nc * sizeof(*n));
    if (n == NULL) return NULL;
    if (set->n) memcpy(n, set->s, (size_t)set->n * sizeof(*n));
    sd_free(set->s);
    set->s = n;
    set->cap = nc;
  }
  s = &set->s[set->n++];
  memset(s, 0, sizeof(*s));
  strncpy_s(s->name, sizeof(s->name), name, _TRUNCATE);
  return s;
}

static void pt_emit(pt_set *set, sd_import_result *out)
{
  pt_session *def = NULL;
  uint32_t i;
  for (i = 0; i < set->n; i++)
    if (_stricmp(set->s[i].name, "Default Settings") == 0) def = &set->s[i];
  for (i = 0; i < set->n; i++)
    candidate_from_putty(out, &set->s[i], def);
}

sd_err sd_import_putty_registry(HKEY root, const wchar_t *key, sd_import_result *out)
{
  HKEY h;
  DWORD idx;
  pt_set set;
  if (out == NULL)
    return SD_E_INVALID_PARAM;
  if (RegOpenKeyExW(root ? root : HKEY_CURRENT_USER, key ? key : PUTTY_SESSIONS, 0, KEY_READ, &h) != ERROR_SUCCESS)
    return SD_E_NOT_FOUND;
  memset(&set, 0, sizeof(set));
  for (idx = 0;; idx++) {
    wchar_t sub[256];
    DWORD sl = SD_COUNTOF(sub), vi;
    HKEY hs;
    char raw[768], name[256];
    size_t got = 0;
    pt_session *s;
    LONG rc = RegEnumKeyExW(h, idx, sub, &sl, NULL, NULL, NULL, NULL);
    if (rc == ERROR_NO_MORE_ITEMS) break;
    if (rc != ERROR_SUCCESS) continue;
    if (sd_utf16_to_utf8(sub, sl, raw, sizeof(raw) - 1, &got, SD_UTF_REPLACE) != SD_OK) continue;
    raw[got] = 0;
    url_decode(raw, name, sizeof(name));
    if (RegOpenKeyExW(h, sub, 0, KEY_READ, &hs) != ERROR_SUCCESS) continue;
    s = pt_new(&set, name);
    for (vi = 0; s; vi++) {
      wchar_t vn[64];
      BYTE data[MAX_PATH * 6];
      DWORD vnl = SD_COUNTOF(vn), type = 0, dl = sizeof(data) - 2;
      char vname[64];
      size_t vg = 0;
      pt_value *v;
      rc = RegEnumValueW(hs, vi, vn, &vnl, NULL, &type, data, &dl);
      if (rc == ERROR_NO_MORE_ITEMS) break;
      if (rc != ERROR_SUCCESS) continue;
      if (sd_utf16_to_utf8(vn, vnl, vname, sizeof(vname) - 1, &vg, SD_UTF_REPLACE) != SD_OK) continue;
      vname[vg] = 0;
      if (type == REG_DWORD && dl == 4) {
        if ((v = pt_add(s, vname)) != NULL) { v->is_num = 1; memcpy(&v->num, data, 4); }
      } else if (type == REG_SZ || type == REG_EXPAND_SZ) {
        size_t wn = dl / sizeof(wchar_t), sg = 0;
        while (wn && ((wchar_t *)data)[wn - 1] == 0) wn--;
        if ((v = pt_add(s, vname)) != NULL &&
            sd_utf16_to_utf8((const wchar_t *)data, wn, v->str, sizeof(v->str) - 1, &sg, SD_UTF_REPLACE) == SD_OK)
          v->str[sg] = 0;
      }
    }
    RegCloseKey(hs);
  }
  RegCloseKey(h);
  pt_emit(&set, out);
  sd_free(set.s);
  return SD_OK;
}

/* ---- .reg export ---- */

/* Converts the export to UTF-8 (UTF-16LE with BOM, UTF-8 with or without BOM, else ANSI). */
static char *reg_to_utf8(const uint8_t *data, size_t len)
{
  char *out = NULL;
  if (len >= 2 && data[0] == 0xFF && data[1] == 0xFE) {
    size_t wn = (len - 2) / 2, got = 0;
    wchar_t *w = (wchar_t *)sd_alloc(wn * sizeof(wchar_t) + 2);
    if (w == NULL) return NULL;
    memcpy(w, data + 2, wn * sizeof(wchar_t));
    out = (char *)sd_alloc(wn * 3 + 1);
    if (out && sd_utf16_to_utf8(w, wn, out, wn * 3, &got, SD_UTF_REPLACE) == SD_OK) out[got] = 0;
    else { sd_free(out); out = NULL; }
    sd_free(w);
    return out;
  }
  if (len >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF) { data += 3; len -= 3; }
  if (sd_utf8_valid((const char *)data, len)) {
    out = (char *)sd_alloc(len + 1);
    if (out) { memcpy(out, data, len); out[len] = 0; }
    return out;
  }
  {
    int wn = MultiByteToWideChar(CP_ACP, 0, (const char *)data, (int)len, NULL, 0);
    wchar_t *w = wn > 0 ? (wchar_t *)sd_alloc((size_t)wn * sizeof(wchar_t)) : NULL;
    size_t got = 0;
    if (w == NULL) return NULL;
    MultiByteToWideChar(CP_ACP, 0, (const char *)data, (int)len, w, wn);
    out = (char *)sd_alloc((size_t)wn * 3 + 1);
    if (out && sd_utf16_to_utf8(w, (size_t)wn, out, (size_t)wn * 3, &got, SD_UTF_REPLACE) == SD_OK) out[got] = 0;
    else { sd_free(out); out = NULL; }
    sd_free(w);
  }
  return out;
}

/* "...": unescapes \\ and \" into out; returns the char after the closing quote, or NULL. */
static const char *reg_qstr(const char *p, char *out, size_t cap)
{
  size_t o = 0;
  if (*p != '"') return NULL;
  p++;
  while (*p && *p != '"') {
    char c = *p++;
    if (c == '\\' && (*p == '\\' || *p == '"')) c = *p++;
    if (o + 1 < cap) out[o++] = c;
  }
  if (*p != '"') return NULL;
  out[o] = 0;
  return p + 1;
}

sd_err sd_import_putty_reg_text(const uint8_t *data, size_t len, sd_import_result *out)
{
  char *text, *line, *next;
  pt_set set;
  pt_session *cur = NULL;
  int continuation = 0, saw_header = 0;
  if (data == NULL || out == NULL)
    return SD_E_INVALID_PARAM;
  if ((text = reg_to_utf8(data, len)) == NULL)
    return SD_E_NO_MEMORY;
  memset(&set, 0, sizeof(set));
  for (line = text; line; line = next) {
    size_t n;
    next = strchr(line, '\n');
    if (next) *next++ = 0;
    n = strlen(line);
    while (n && (line[n - 1] == '\r' || line[n - 1] == ' ' || line[n - 1] == '\t')) line[--n] = 0;
    while (*line == ' ' || *line == '\t') line++;
    if (continuation) {                            /* hex(...) values spread over lines */
      continuation = n > 0 && line[strlen(line) - 1] == '\\';
      continue;
    }
    if (line[0] == 0 || line[0] == ';')
      continue;
    if (strcmp(line, "Windows Registry Editor Version 5.00") == 0 || strcmp(line, "REGEDIT4") == 0) {
      saw_header = 1;
      continue;
    }
    if (line[0] == '[') {
      char *end = strrchr(line, ']'), *last, name[256];
      const char *marker;
      cur = NULL;
      if (end == NULL) continue;
      *end = 0;
      marker = strstr(line, "\\Sessions\\");
      if (marker == NULL) continue;                /* the Sessions key itself, or another key */
      last = (char *)marker + 10;
      if (strchr(last, '\\')) continue;            /* a subkey below a session */
      url_decode(last, name, sizeof(name));
      cur = pt_new(&set, name);
      continue;
    }
    if (line[0] == '"' && cur) {
      char vname[64];
      const char *p = reg_qstr(line, vname, sizeof(vname));
      pt_value *v;
      if (p == NULL || *p != '=') continue;
      p++;
      if (*p == '"') {
        if ((v = pt_add(cur, vname)) != NULL && reg_qstr(p, v->str, sizeof(v->str)) == NULL)
          v->str[0] = 0;
      } else if (_strnicmp(p, "dword:", 6) == 0) {
        uint32_t num = 0;
        int k, ok = 1;
        p += 6;
        for (k = 0; k < 8; k++) {
          int h = hexval(p[k]);
          if (h < 0) { ok = 0; break; }
          num = num * 16u + (uint32_t)h;
        }
        if (ok && p[8] == 0 && (v = pt_add(cur, vname)) != NULL) { v->is_num = 1; v->num = num; }
      } else {
        continuation = line[strlen(line) - 1] == '\\';
      }
    }
  }
  sd_free(text);
  if (!saw_header) {
    sd_free(set.s);
    return SD_E_KEY_FORMAT;
  }
  pt_emit(&set, out);
  sd_free(set.s);
  return SD_OK;
}

/* ---- ssh_config ---- */

#define SC_MAX_ARGS 16

typedef struct sc_line { uint32_t line; char kw[32]; uint32_t nargs; char arg[SC_MAX_ARGS][MAX_PATH * 2]; } sc_line;

/* Splits one line into keyword and arguments (whitespace or '=' after the keyword, double quotes
   group). Returns 0 for blank lines and comments. */
static int sc_split(char *s, sc_line *out)
{
  size_t k = 0;
  out->nargs = 0;
  while (*s == ' ' || *s == '\t') s++;
  if (*s == 0 || *s == '#')
    return 0;
  while (*s && *s != ' ' && *s != '\t' && *s != '=' && k + 1 < sizeof(out->kw))
    out->kw[k++] = *s++;
  out->kw[k] = 0;
  while (*s == ' ' || *s == '\t') s++;
  if (*s == '=') s++;
  for (;;) {
    size_t o = 0;
    int q = 0;
    while (*s == ' ' || *s == '\t') s++;
    if (*s == 0 || *s == '#' || out->nargs >= SC_MAX_ARGS) break;
    while (*s && (q || (*s != ' ' && *s != '\t'))) {
      if (*s == '"') { q = !q; s++; continue; }
      if (o + 1 < sizeof(out->arg[0])) out->arg[out->nargs][o++] = *s;
      s++;
    }
    out->arg[out->nargs][o] = 0;
    out->nargs++;
  }
  return 1;
}

static int glob_match(const char *p, const char *s)
{
  for (;;) {
    char a = *p, b = *s;
    if (a == '*') {
      while (*p == '*') p++;
      if (*p == 0) return 1;
      for (; *s; s++)
        if (glob_match(p, s)) return 1;
      return 0;
    }
    if (a == 0) return b == 0;
    if (b == 0) return 0;
    if (a >= 'A' && a <= 'Z') a = (char)(a - 'A' + 'a');
    if (b >= 'A' && b <= 'Z') b = (char)(b - 'A' + 'a');
    if (a != '?' && a != b) return 0;
    p++;
    s++;
  }
}

static int has_wild(const char *s) { return strchr(s, '*') != NULL || strchr(s, '?') != NULL; }

/* Host section matches when a positive pattern matches and no negated one does (OpenSSH). */
static int section_matches(const sc_line *host, const char *alias)
{
  uint32_t i;
  int pos = 0;
  for (i = 0; i < host->nargs; i++) {
    const char *pat = host->arg[i];
    if (pat[0] == '!') {
      if (glob_match(pat + 1, alias)) return 0;
    } else if (glob_match(pat, alias)) {
      pos = 1;
    }
  }
  return pos;
}

typedef struct sc_values {
  char hostname[256], user[128], port[8], ident_only[8], jump[1024];
  char ident[SD_PROFILE_MAX_IDENTITIES][MAX_PATH * 2];
  uint32_t nident;
  char cert[MAX_PATH * 2];
  int have_jump;
} sc_values;

static int is_kw(const char *kw, const char *name) { return _stricmp(kw, name) == 0; }

static void sc_apply(sc_values *v, const sc_line *l)
{
  if (l->nargs == 0) return;
  if (is_kw(l->kw, "HostName")) { if (!v->hostname[0]) strncpy_s(v->hostname, sizeof(v->hostname), l->arg[0], _TRUNCATE); }
  else if (is_kw(l->kw, "User")) { if (!v->user[0]) strncpy_s(v->user, sizeof(v->user), l->arg[0], _TRUNCATE); }
  else if (is_kw(l->kw, "Port")) { if (!v->port[0]) strncpy_s(v->port, sizeof(v->port), l->arg[0], _TRUNCATE); }
  else if (is_kw(l->kw, "IdentitiesOnly")) { if (!v->ident_only[0]) strncpy_s(v->ident_only, sizeof(v->ident_only), l->arg[0], _TRUNCATE); }
  else if (is_kw(l->kw, "ProxyJump")) {
    if (!v->have_jump) {
      v->have_jump = 1;
      strncpy_s(v->jump, sizeof(v->jump), l->arg[0], _TRUNCATE);
    }
  } else if (is_kw(l->kw, "IdentityFile")) {
    uint32_t i;
    for (i = 0; i < v->nident; i++)
      if (strcmp(v->ident[i], l->arg[0]) == 0) return;
    if (v->nident < SD_PROFILE_MAX_IDENTITIES)
      strncpy_s(v->ident[v->nident++], sizeof(v->ident[0]), l->arg[0], _TRUNCATE);
  } else if (is_kw(l->kw, "CertificateFile")) {
    if (!v->cert[0]) strncpy_s(v->cert, sizeof(v->cert), l->arg[0], _TRUNCATE);
  }
}

static const char *const k_supported[] = { "Host", "HostName", "User", "Port", "IdentityFile", "IdentitiesOnly",
                                           "ProxyJump", "CertificateFile" };

static int supported_kw(const char *kw)
{
  size_t i;
  for (i = 0; i < SD_COUNTOF(k_supported); i++)
    if (is_kw(kw, k_supported[i])) return 1;
  return 0;
}

/* %d %u %h %r %% and a leading ~; '/' becomes '\'. 0 on an unknown token. */
static int sc_expand(const char *in, const char *home, const char *luser, const char *rhost, const char *ruser,
                     char *out, size_t cap)
{
  size_t o = 0;
  const char *p = in;
  out[0] = 0;
#define PUT(str) do { const char *q_ = (str); while (*q_) { if (o + 1 >= cap) return 0; out[o++] = *q_++; } } while (0)
  if (p[0] == '~' && (p[1] == '/' || p[1] == '\\' || p[1] == 0)) {
    PUT(home);
    p++;
  }
  for (; *p; p++) {
    if (*p == '%') {
      p++;
      if (*p == 'd') PUT(home);
      else if (*p == 'u') PUT(luser);
      else if (*p == 'h') PUT(rhost);
      else if (*p == 'r') PUT(ruser);
      else if (*p == '%') PUT("%");
      else return 0;
      continue;
    }
    if (o + 1 >= cap) return 0;
    out[o++] = *p == '/' ? '\\' : *p;
  }
  out[o] = 0;
#undef PUT
  return 1;
}

typedef struct sc_doc { sc_line *lines; uint32_t n, cap; } sc_doc;

static int sc_push(sc_doc *d, const sc_line *l)
{
  if (d->n == d->cap) {
    uint32_t nc = d->cap ? d->cap * 2 : 32;
    sc_line *n = (sc_line *)sd_alloc((size_t)nc * sizeof(*n));
    if (n == NULL) return 0;
    if (d->n) memcpy(n, d->lines, (size_t)d->n * sizeof(*n));
    sd_free(d->lines);
    d->lines = n;
    d->cap = nc;
  }
  d->lines[d->n++] = *l;
  return 1;
}

sd_err sd_import_ssh_config_text(const char *data, size_t len, const sd_import_env *env, sd_import_result *out)
{
  char *text, *line, *next, home[MAX_PATH * 3], luser[128];
  sc_doc doc;
  sc_line *l;
  sc_values *v;
  uint32_t lineno = 0, i, j, a;
  char (*aliases)[256] = NULL;
  uint32_t nalias = 0, alias_cap = 0;
  sd_err e = SD_OK;
  if (data == NULL || out == NULL)
    return SD_E_INVALID_PARAM;
  home[0] = luser[0] = 0;
  if (env && env->home) strncpy_s(home, sizeof(home), env->home, _TRUNCATE);
  else {
    wchar_t wh[MAX_PATH];
    DWORD n = GetEnvironmentVariableW(L"USERPROFILE", wh, MAX_PATH);
    size_t got = 0;
    if (n > 0 && n < MAX_PATH && sd_utf16_to_utf8(wh, n, home, sizeof(home) - 1, &got, SD_UTF_REPLACE) == SD_OK)
      home[got] = 0;
  }
  if (env && env->local_user) strncpy_s(luser, sizeof(luser), env->local_user, _TRUNCATE);
  else {
    wchar_t wu[128];
    DWORD n = SD_COUNTOF(wu);
    size_t got = 0;
    if (GetUserNameW(wu, &n) && n > 0 && sd_utf16_to_utf8(wu, n - 1, luser, sizeof(luser) - 1, &got, SD_UTF_REPLACE) == SD_OK)
      luser[got] = 0;
  }
  text = (char *)sd_alloc(len + 1);
  l = (sc_line *)sd_alloc(sizeof(*l));
  v = (sc_values *)sd_alloc(sizeof(*v));
  memset(&doc, 0, sizeof(doc));
  if (text == NULL || l == NULL || v == NULL) {
    sd_free(text); sd_free(l); sd_free(v);
    return SD_E_NO_MEMORY;
  }
  memcpy(text, data, len);
  text[len] = 0;
  if (len >= 3 && (uint8_t)text[0] == 0xEF && (uint8_t)text[1] == 0xBB && (uint8_t)text[2] == 0xBF)
    memmove(text, text + 3, len - 2);
  /* pass 1: lines, unsupported keywords, literal aliases */
  for (line = text; line; line = next) {
    size_t n;
    next = strchr(line, '\n');
    if (next) *next++ = 0;
    lineno++;
    n = strlen(line);
    while (n && (line[n - 1] == '\r')) line[--n] = 0;
    memset(l, 0, sizeof(*l));
    if (!sc_split(line, l))
      continue;
    l->line = lineno;
    if (!supported_kw(l->kw)) {
      add_skip(out, SD_IMPORT_SKIP_KEYWORD, "", l->kw, lineno);
      if (is_kw(l->kw, "Match")) {
        /* a Match block applies to whatever it matches: treat it as a section that matches nothing */
        sc_line m;
        memset(&m, 0, sizeof(m));
        strcpy_s(m.kw, sizeof(m.kw), "Host");
        m.line = lineno;
        if (!sc_push(&doc, &m)) { e = SD_E_NO_MEMORY; break; }
      }
      continue;
    }
    if (!sc_push(&doc, l)) { e = SD_E_NO_MEMORY; break; }
    if (is_kw(l->kw, "Host")) {
      for (a = 0; a < l->nargs; a++) {
        const char *al = l->arg[a];
        int dup = 0;
        if (al[0] == '!' || has_wild(al) || strlen(al) >= 256) continue;
        for (j = 0; j < nalias; j++)
          if (_stricmp(aliases[j], al) == 0) dup = 1;
        if (dup) continue;
        if (nalias == alias_cap) {
          uint32_t nc = alias_cap ? alias_cap * 2 : 16;
          char (*na)[256] = (char (*)[256])sd_alloc((size_t)nc * 256);
          if (na == NULL) { e = SD_E_NO_MEMORY; break; }
          if (nalias) memcpy(na, aliases, (size_t)nalias * 256);
          sd_free(aliases);
          aliases = na;
          alias_cap = nc;
        }
        strcpy_s(aliases[nalias++], 256, al);
      }
    }
  }
  /* pass 2: per alias, first obtained value wins */
  for (a = 0; a < nalias && e == SD_OK; a++) {
    int in = 1;                                  /* lines before the first Host apply to every host */
    sd_import_candidate *c;
    const char *bad = NULL;
    char rhost[256];
    memset(v, 0, sizeof(*v));
    for (i = 0; i < doc.n; i++) {
      if (is_kw(doc.lines[i].kw, "Host")) {
        in = section_matches(&doc.lines[i], aliases[a]);
        continue;
      }
      if (in) sc_apply(v, &doc.lines[i]);
    }
    if ((c = add_item(out)) == NULL) { e = SD_E_NO_MEMORY; break; }
    strcpy_s(c->source, sizeof(c->source), aliases[a]);
    strncpy_s(c->p.name, sizeof(c->p.name), aliases[a], _TRUNCATE);
    /* HostName: %h is the alias, %% a percent sign */
    if (v->hostname[0]) {
      if (!sc_expand(v->hostname, home, luser, aliases[a], v->user, rhost, sizeof(rhost)) ||
          !sd_cfg_scpy(c->p.host, sizeof(c->p.host), rhost)) {
        add_skip(out, SD_IMPORT_SKIP_INVALID, aliases[a], "HostName", 0);
        drop_last(out);
        continue;
      }
      for (j = 0; c->p.host[j]; j++) if (c->p.host[j] == '\\') c->p.host[j] = '/';
    } else {
      strcpy_s(c->p.host, sizeof(c->p.host), aliases[a]);
    }
    strcpy_s(c->p.user, sizeof(c->p.user), v->user);
    if (v->port[0]) {
      uint32_t pn;
      if (!sd_ini_parse_u32(v->port, &pn) || pn < 1 || pn > 65535) {
        add_skip(out, SD_IMPORT_SKIP_INVALID, aliases[a], "Port", 0);
        drop_last(out);
        continue;
      }
      c->p.port = (uint16_t)pn;
    }
    for (j = 0; j < v->nident; j++) {
      char path[MAX_PATH * 3];
      char *dst = j == 0 ? c->p.identity : c->p.identity_n[j - 1];
      size_t cap = j == 0 ? sizeof(c->p.identity) : sizeof(c->p.identity_n[0]);
      if (!sc_expand(v->ident[j], home, luser, c->p.host, c->p.user, path, sizeof(path)) ||
          !sd_cfg_scpy(dst, cap, path))
        add_skip(out, SD_IMPORT_SKIP_INVALID, aliases[a], "IdentityFile", 0);
    }
    if (v->cert[0]) {
      char path[MAX_PATH * 3];
      if (sc_expand(v->cert, home, luser, c->p.host, c->p.user, path, sizeof(path)))
        sd_cfg_scpy(c->p.certificate, sizeof(c->p.certificate), path);
    }
    if (v->ident_only[0]) {
      int b;
      if (sd_ini_parse_bool(v->ident_only, &b)) c->p.identities_only = b ? 1 : 0;
    }
    if (sd_profile_identity_count(&c->p) > 0 && c->p.identities_only == SD_PROFILE_UNSET)
      c->flags |= SD_IMPORT_F_ONLY_THIS_KEY;
    if (v->have_jump && _stricmp(v->jump, "none") != 0) {
      /* "ssh://user@host:port" entries lose the scheme; aliases stay (they name imported profiles) */
      char *p = v->jump, *o = c->p.jump;
      size_t left = sizeof(c->p.jump) - 1;
      while (*p && left) {
        if (_strnicmp(p, "ssh://", 6) == 0) { p += 6; continue; }
        *o++ = *p++;
        left--;
      }
      *o = 0;
    }
    if (sd_profile_validate(&c->p, &bad) != SD_OK) {
      add_skip(out, SD_IMPORT_SKIP_INVALID, aliases[a], bad ? bad : "profile", 0);
      drop_last(out);
    }
  }
  sd_free(aliases);
  sd_free(doc.lines);
  sd_free(text);
  sd_free(l);
  sd_free(v);
  return e;
}

sd_err sd_import_ssh_config_file(const wchar_t *path, const sd_import_env *env, sd_import_result *out)
{
  wchar_t def[MAX_PATH];
  HANDLE h;
  LARGE_INTEGER sz;
  DWORD got = 0;
  char *buf;
  sd_err e;
  if (path == NULL) {
    DWORD n = GetEnvironmentVariableW(L"USERPROFILE", def, MAX_PATH);
    if (n == 0 || n + 13 >= MAX_PATH)
      return SD_E_NOT_FOUND;
    wcscat_s(def, MAX_PATH, L"\\.ssh\\config");
    path = def;
  }
  h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
  if (h == INVALID_HANDLE_VALUE)
    return GetLastError() == ERROR_ACCESS_DENIED ? SD_E_ACCESS_DENIED : SD_E_NOT_FOUND;
  if (!GetFileSizeEx(h, &sz) || sz.QuadPart > (1 << 20)) {
    CloseHandle(h);
    return SD_E_INVALID_PARAM;
  }
  buf = (char *)sd_alloc((size_t)sz.QuadPart + 1);
  if (buf == NULL) {
    CloseHandle(h);
    return SD_E_NO_MEMORY;
  }
  if (!ReadFile(h, buf, (DWORD)sz.QuadPart, &got, NULL)) got = 0;
  CloseHandle(h);
  e = sd_import_ssh_config_text(buf, got, env, out);
  sd_free(buf);
  return e;
}

/* ---- duplicates and writing ---- */

typedef struct dup_ctx { sd_import_result *r; } dup_ctx;

static int same_host(const char *a, const char *b) { return _stricmp(a, b) == 0; }

static int dup_cb(void *ctx, const sd_profile *p, const wchar_t *path)
{
  dup_ctx *d = (dup_ctx *)ctx;
  uint32_t i;
  SD_UNUSED(path);
  for (i = 0; i < d->r->count; i++) {
    sd_import_candidate *c = &d->r->items[i];
    if (same_host(c->p.host, p->host) && c->p.port == p->port && strcmp(c->p.user, p->user) == 0) {
      c->flags |= SD_IMPORT_F_DUPLICATE;
      c->selected = 0;
    } else if (_stricmp(c->p.name, p->name) == 0) {
      size_t n = strlen(c->p.name);
      if (n + 5 < sizeof(c->p.name)) {
        strcat_s(c->p.name, sizeof(c->p.name), " (2)");
        c->flags |= SD_IMPORT_F_NAME_CHANGED;
      }
    }
  }
  return 1;
}

void sd_import_mark_duplicates(sd_import_result *r, sd_import_enum_fn enum_fn)
{
  dup_ctx d;
  if (r == NULL)
    return;
  d.r = r;
  (enum_fn ? enum_fn : sd_profile_enum)(dup_cb, &d);
}

sd_err sd_import_write(sd_import_result *r, uint32_t *written)
{
  uint32_t i, n = 0;
  sd_err first = SD_OK;
  if (written) *written = 0;
  if (r == NULL)
    return SD_E_INVALID_PARAM;
  for (i = 0; i < r->count; i++) {
    sd_err e;
    if (!r->items[i].selected)
      continue;
    e = sd_profile_save(&r->items[i].p);
    if (e == SD_OK) n++;
    else if (first == SD_OK) first = e;
  }
  if (written) *written = n;
  return first;
}
