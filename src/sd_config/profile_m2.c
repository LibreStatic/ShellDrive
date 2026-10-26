/* sd_config M2 profile keys (03 §3.4.1), proxy specs (3.8), ProxyJump lists and chain resolution. */
#include <windows.h>
#include <stdlib.h>
#include <string.h>

#include "config_internal.h"
#include "sd_base/sd_mem.h"
#include "sd_crypto/sd_crypto.h"

/* ---- shared helpers ---- */

int sd_cfg_has_ctl(const char *s)
{
  for (; *s; s++)
    if ((unsigned char)*s < 0x20 || *s == 0x7F)
      return 1;
  return 0;
}

int sd_cfg_scpy(char *dst, size_t cap, const char *src)
{
  size_t n = strlen(src);
  if (n + 1 > cap)
    return 0;
  memcpy(dst, src, n + 1);
  return 1;
}

int sd_cfg_valid_host(const char *h)
{
  size_t n = strlen(h), i;
  if (n == 0 || n >= 256)
    return 0;
  for (i = 0; i < n; i++) {
    unsigned char c = (unsigned char)h[i];
    if (c <= 0x20 || c == 0x7F || c == '/' || c == '\\' || c == '@')
      return 0;
  }
  return 1;
}

void sd_cfg_u32_dec(char out[16], uint32_t v)
{
  char tmp[16];
  size_t n = 0, i = 0;
  do { tmp[n++] = (char)('0' + v % 10u); v /= 10u; } while (v);
  while (n) out[i++] = tmp[--n];
  out[i] = 0;
}

static int parse_port(const char *s, size_t n, uint16_t *port)
{
  uint32_t v = 0;
  size_t i;
  if (n == 0 || n > 5)
    return 0;
  for (i = 0; i < n; i++) {
    if (s[i] < '0' || s[i] > '9') return 0;
    v = v * 10u + (uint32_t)(s[i] - '0');
  }
  if (v == 0 || v > 65535)
    return 0;
  *port = (uint16_t)v;
  return 1;
}

int sd_cfg_parse_host_spec_utf8(const char *spec, char *user, size_t ucap, char *host, size_t hcap, uint16_t *port)
{
  const char *at = strrchr(spec, '@'), *colon = NULL, *p, *end;
  const char *h = spec;                  /* the host part starts after a trailing @user */
  size_t n;
  user[0] = host[0] = 0;
  *port = 0;
  if (at) {
    n = (size_t)(at - spec);
    if (n == 0 || n >= ucap) return 0;
    memcpy(user, spec, n);
    user[n] = 0;
    if (sd_cfg_has_ctl(user) || strchr(user, ' ') || strchr(user, ',')) return 0;
  }
  if (at) h = at + 1;
  end = h + strlen(h);
  if (*h == '[') {
    const char *rb = strchr(h, ']');
    if (rb == NULL || rb == h + 1) return 0;
    n = (size_t)(rb - h - 1);
    if (n >= hcap) return 0;
    memcpy(host, h + 1, n);
    host[n] = 0;
    if (rb[1] == ':') colon = rb + 1;
    else if (rb[1] != 0) return 0;
  } else {
    const char *host_end;
    int colons = 0;
    for (p = h; *p; p++)
      if (*p == ':') { colons++; colon = p; }
    if (colons > 1) colon = NULL;          /* bare IPv6 literal */
    host_end = colon ? colon : end;
    n = (size_t)(host_end - h);
    if (n >= hcap) return 0;
    _Analysis_assume_(h != NULL);   /* h was dereferenced above; the analyzer's colon aliasing is spurious */
    memcpy(host, h, n);
    host[n] = 0;
  }
  if (colon && !parse_port(colon + 1, strlen(colon + 1), port))
    return 0;
  return sd_cfg_valid_host(host);
}

/* ---- proxy specs (3.8) ---- */

sd_err sd_proxy_spec_parse(const char *s, sd_proxy_spec *out)
{
  const char *rest;
  char user[128], host[256];
  uint16_t port = 0;
  if (s == NULL || out == NULL)
    return SD_E_INVALID_PARAM;
  memset(out, 0, sizeof(*out));
  if (_stricmp(s, "none") == 0 || s[0] == 0) {
    out->kind = SD_PROFILE_PROXY_NONE;
    return SD_OK;
  }
  if (_stricmp(s, "system") == 0) {
    out->kind = SD_PROFILE_PROXY_SYSTEM;
    return SD_OK;
  }
  if (_strnicmp(s, "http://", 7) == 0) {
    out->kind = SD_PROFILE_PROXY_HTTP;
    rest = s + 7;
  } else if (_strnicmp(s, "socks5://", 9) == 0) {
    out->kind = SD_PROFILE_PROXY_SOCKS5;
    rest = s + 9;
  } else {
    return SD_E_INVALID_PARAM;
  }
  {
    size_t n = strlen(rest);
    char tmp[400];
    if (n == 0 || n >= sizeof(tmp)) return SD_E_INVALID_PARAM;
    memcpy(tmp, rest, n + 1);
    if (tmp[n - 1] == '/') tmp[--n] = 0;       /* "http://proxy:3128/" */
    if (strchr(tmp, '/') || strchr(tmp, '?') || strchr(tmp, '#'))
      return SD_E_INVALID_PARAM;
    {
      const char *at = strrchr(tmp, '@');
      if (at) {
        const char *c;
        for (c = tmp; c < at; c++)
          if (*c == ':') return SD_E_INVALID_PARAM;   /* user:pass@ (3.8: never a password in a spec) */
      }
    }
    if (!sd_cfg_parse_host_spec_utf8(tmp, user, sizeof(user), host, sizeof(host), &port))
      return SD_E_INVALID_PARAM;
  }
  strcpy_s(out->host, sizeof(out->host), host);
  strcpy_s(out->user, sizeof(out->user), user);
  out->port = port ? port : (out->kind == SD_PROFILE_PROXY_HTTP ? 8080 : 1080);
  return SD_OK;
}

sd_err sd_proxy_spec_format(const sd_proxy_spec *p, char *out, size_t cap)
{
  char num[16];
  int v6;
  if (p == NULL || out == NULL || cap == 0)
    return SD_E_INVALID_PARAM;
  out[0] = 0;
  if (p->kind == SD_PROFILE_PROXY_NONE) return strcpy_s(out, cap, "none") == 0 ? SD_OK : SD_E_NAME_TOO_LONG;
  if (p->kind == SD_PROFILE_PROXY_SYSTEM) return strcpy_s(out, cap, "system") == 0 ? SD_OK : SD_E_NAME_TOO_LONG;
  if (p->kind != SD_PROFILE_PROXY_HTTP && p->kind != SD_PROFILE_PROXY_SOCKS5)
    return SD_E_INVALID_PARAM;
  v6 = strchr(p->host, ':') != NULL;
  sd_cfg_u32_dec(num, p->port);
  if (strcpy_s(out, cap, p->kind == SD_PROFILE_PROXY_HTTP ? "http://" : "socks5://") != 0 ||
      (p->user[0] && (strcat_s(out, cap, p->user) != 0 || strcat_s(out, cap, "@") != 0)) ||
      (v6 && strcat_s(out, cap, "[") != 0) || strcat_s(out, cap, p->host) != 0 ||
      (v6 && strcat_s(out, cap, "]") != 0) || strcat_s(out, cap, ":") != 0 || strcat_s(out, cap, num) != 0) {
    out[0] = 0;
    return SD_E_NAME_TOO_LONG;
  }
  return SD_OK;
}

/* ---- identities, D37 ---- */

uint32_t sd_profile_identity_count(const sd_profile *p)
{
  uint32_t n = 0, i;
  if (p->identity[0]) n++;
  for (i = 0; i < SD_PROFILE_MAX_IDENTITIES - 1; i++)
    if (p->identity_n[i][0]) n++;
  return n;
}

const char *sd_profile_identity_at(const sd_profile *p, uint32_t idx)
{
  uint32_t n = 0, i;
  if (p->identity[0] && n++ == idx) return p->identity;
  for (i = 0; i < SD_PROFILE_MAX_IDENTITIES - 1; i++)
    if (p->identity_n[i][0] && n++ == idx) return p->identity_n[i];
  return NULL;
}

int sd_profile_identities_only(const sd_profile *p)
{
  if (p->identities_only != SD_PROFILE_UNSET)
    return p->identities_only ? 1 : 0;
  return (sd_profile_identity_count(p) > 0 || p->identity_store[0] || p->agent_keys[0]) ? 1 : 0;
}

/* ---- legacy_accepted (7.6) ---- */

static int cmp_str(const void *a, const void *b)
{
  return strcmp(*(const char *const *)a, *(const char *const *)b);
}

void sd_legacy_set_hash(const char *const *names, uint32_t n, char out[80])
{
  static const char hex[] = "0123456789abcdef";
  const char *sorted[32];
  uint8_t h[32];
  sd_hash_ctx c;
  uint32_t i, k = 0;
  for (i = 0; i < n && k < SD_COUNTOF(sorted); i++)
    if (names[i] && names[i][0]) sorted[k++] = names[i];
  qsort((void *)sorted, k, sizeof(sorted[0]), cmp_str);
  sd_hash_init(&c, SD_HASH_SHA256);
  for (i = 0; i < k; i++) {
    if (i > 0 && strcmp(sorted[i], sorted[i - 1]) == 0)
      continue;                                  /* same algorithm in both directions */
    if (i > 0) sd_hash_update(&c, ",", 1);
    sd_hash_update(&c, sorted[i], strlen(sorted[i]));
  }
  sd_hash_final(&c, h);
  memcpy(out, "sha256:", 7);
  for (i = 0; i < 32; i++) {
    out[7 + 2 * i] = hex[h[i] >> 4];
    out[8 + 2 * i] = hex[h[i] & 15];
  }
  out[71] = 0;
}

/* ---- ProxyJump lists ---- */

sd_err sd_jump_parse(const char *list, sd_jump_list *out)
{
  const char *p = list;
  if (out == NULL)
    return SD_E_INVALID_PARAM;
  memset(out, 0, sizeof(*out));
  if (list == NULL || list[0] == 0 || _stricmp(list, "none") == 0)
    return SD_OK;
  for (;;) {
    const char *b, *e;
    size_t n;
    while (*p == ' ' || *p == '\t') p++;
    b = p;
    while (*p && *p != ',') p++;
    e = p;
    while (e > b && (e[-1] == ' ' || e[-1] == '\t')) e--;
    n = (size_t)(e - b);
    if (n == 0 || n >= sizeof(out->entry[0]) || out->count >= SD_PROFILE_MAX_HOPS)
      return SD_E_INVALID_PARAM;
    memcpy(out->entry[out->count], b, n);
    out->entry[out->count][n] = 0;
    if (sd_cfg_has_ctl(out->entry[out->count]))
      return SD_E_INVALID_PARAM;
    out->count++;
    if (*p == 0) break;
    p++;                                         /* ',' */
  }
  return SD_OK;
}

/* ---- M2 keys ---- */

static int valid_hex_id(const char *id)
{
  size_t i;
  if (strlen(id) != 32) return 0;
  for (i = 0; i < 32; i++)
    if (!((id[i] >= '0' && id[i] <= '9') || (id[i] >= 'a' && id[i] <= 'f'))) return 0;
  return 1;
}

void sd_profile_m2_defaults(sd_profile *p)
{
  uint32_t i;
  p->agent = SD_PROFILE_AGENT_AUTO;
  p->identities_only = SD_PROFILE_UNSET;
  p->save_password = 1;
  p->cache_secrets = 1;
  for (i = 0; i < SD_PROFILE_MAX_LEGS; i++) {
    p->proxy[i].kind = SD_PROFILE_PROXY_NONE;
    p->proxy_auth[i] = SD_PROFILE_PROXY_AUTH_AUTO;
  }
  p->connections = 1;
  p->legacy_algorithms = SD_PROFILE_LEGACY_WARN;
  p->update_host_keys = SD_PROFILE_HKU_ASK;
}

const char *sd_profile_m2_validate(const sd_profile *p)
{
  sd_jump_list jl;
  uint32_t i;
  for (i = 0; i < SD_PROFILE_MAX_IDENTITIES - 1; i++)
    if (sd_cfg_has_ctl(p->identity_n[i])) return "auth.identity.2";
  if (p->identity_store[0] && !valid_hex_id(p->identity_store)) return "auth.identity_store";
  if (sd_cfg_has_ctl(p->certificate)) return "auth.certificate";
  if (p->agent < SD_PROFILE_AGENT_AUTO || p->agent > SD_PROFILE_AGENT_NONE) return "auth.agent";
  if (p->identities_only < SD_PROFILE_UNSET || p->identities_only > 1) return "auth.identities_only";
  if (sd_cfg_has_ctl(p->agent_keys)) return "auth.agent_keys";
  if (sd_jump_parse(p->jump, &jl) != SD_OK) return "proxy.jump";
  for (i = 0; i < SD_PROFILE_MAX_LEGS; i++) {
    const sd_proxy_spec *x = &p->proxy[i];
    if (x->kind < SD_PROFILE_PROXY_NONE || x->kind > SD_PROFILE_PROXY_SYSTEM) return "proxy.proxy";
    if (x->kind == SD_PROFILE_PROXY_SYSTEM && i != 0) return "proxy.proxy";          /* system: leg 1 only */
    if ((x->kind == SD_PROFILE_PROXY_HTTP || x->kind == SD_PROFILE_PROXY_SOCKS5) &&
        (!sd_cfg_valid_host(x->host) || x->port == 0 || sd_cfg_has_ctl(x->user)))
      return "proxy.proxy";
    if (p->proxy_auth[i] < SD_PROFILE_PROXY_AUTH_AUTO || p->proxy_auth[i] > SD_PROFILE_PROXY_AUTH_NONE)
      return "proxy.proxy_auth";
  }
  if (p->connections < 1 || p->connections > 4) return "connection.connections";
  if (p->legacy_algorithms < SD_PROFILE_LEGACY_ALLOW || p->legacy_algorithms > SD_PROFILE_LEGACY_REFUSE)
    return "security.legacy_algorithms";
  if (sd_cfg_has_ctl(p->legacy_accepted)) return "security.legacy_accepted";
  if (p->host_key_alias[0] && !sd_cfg_valid_host(p->host_key_alias)) return "security.host_key_alias";
  if (p->update_host_keys < SD_PROFILE_HKU_YES || p->update_host_keys > SD_PROFILE_HKU_NO)
    return "security.update_host_keys";
  if (p->keepalive_ms > 3600000u) return "security.keepalive";
  if (p->connect_timeout_ms > 600000u) return "security.connect_timeout";
  return NULL;
}

/* "proxy" for leg 1, "proxy.N" for leg N (base "proxy", "proxy_auth", "proxy_fallback_direct"). */
static void leg_key(char *out, size_t cap, const char *base, uint32_t leg)
{
  char num[16];
  strcpy_s(out, cap, base);
  if (leg > 1) {
    sd_cfg_u32_dec(num, leg);
    strcat_s(out, cap, ".");
    strcat_s(out, cap, num);
  }
}

static const char *leg_value(const sd_ini *ini, const char *base, uint32_t leg)
{
  char k[48];
  const char *v;
  leg_key(k, sizeof(k), base, leg);
  v = sd_ini_get(ini, "proxy", k);
  if (v == NULL && leg == 1) {
    leg_key(k, sizeof(k), base, 2);
    k[strlen(k) - 1] = '1';                      /* "proxy.1" is accepted as leg 1 */
    v = sd_ini_get(ini, "proxy", k);
  }
  return v;
}

const char *sd_profile_m2_from_ini(const sd_ini *ini, sd_profile *p)
{
  const char *v;
  uint32_t u, i;
  int b;
  for (i = 0; i < SD_PROFILE_MAX_IDENTITIES - 1; i++) {
    char k[16];
    strcpy_s(k, sizeof(k), "identity.");
    k[9] = (char)('2' + i);
    k[10] = 0;
    if ((v = sd_ini_get(ini, "auth", k)) != NULL && !sd_cfg_scpy(p->identity_n[i], sizeof(p->identity_n[i]), v))
      return "auth.identity.2";
  }
  if ((v = sd_ini_get(ini, "auth", "identity_store")) != NULL &&
      (!sd_cfg_scpy(p->identity_store, sizeof(p->identity_store), v) || (v[0] && !valid_hex_id(v))))
    return "auth.identity_store";
  if ((v = sd_ini_get(ini, "auth", "certificate")) != NULL && !sd_cfg_scpy(p->certificate, sizeof(p->certificate), v))
    return "auth.certificate";
  if ((v = sd_ini_get(ini, "auth", "agent")) != NULL) {
    if (strcmp(v, "auto") == 0) p->agent = SD_PROFILE_AGENT_AUTO;
    else if (strcmp(v, "pageant") == 0) p->agent = SD_PROFILE_AGENT_PAGEANT;
    else if (strcmp(v, "openssh") == 0) p->agent = SD_PROFILE_AGENT_OPENSSH;
    else if (strcmp(v, "none") == 0) p->agent = SD_PROFILE_AGENT_NONE;
    else return "auth.agent";
  }
  if ((v = sd_ini_get(ini, "auth", "identities_only")) != NULL) {
    if (!sd_ini_parse_bool(v, &b)) return "auth.identities_only";
    p->identities_only = b ? 1 : 0;
  }
  if ((v = sd_ini_get(ini, "auth", "agent_keys")) != NULL && !sd_cfg_scpy(p->agent_keys, sizeof(p->agent_keys), v))
    return "auth.agent_keys";
  if ((v = sd_ini_get(ini, "auth", "save_password")) != NULL) {
    if (!sd_ini_parse_bool(v, &b)) return "auth.save_password";
    p->save_password = b;
  }
  if ((v = sd_ini_get(ini, "auth", "cache_secrets_for_reconnect")) != NULL) {
    if (!sd_ini_parse_bool(v, &b)) return "auth.cache_secrets_for_reconnect";
    p->cache_secrets = b;
  }
  if ((v = sd_ini_get(ini, "proxy", "jump")) != NULL) {
    sd_jump_list jl;
    if (!sd_cfg_scpy(p->jump, sizeof(p->jump), v) || sd_jump_parse(v, &jl) != SD_OK) return "proxy.jump";
    if (_stricmp(v, "none") == 0) p->jump[0] = 0;
  }
  for (i = 0; i < SD_PROFILE_MAX_LEGS; i++) {
    if ((v = leg_value(ini, "proxy", i + 1)) != NULL && sd_proxy_spec_parse(v, &p->proxy[i]) != SD_OK)
      return "proxy.proxy";
    if ((v = leg_value(ini, "proxy_auth", i + 1)) != NULL) {
      if (strcmp(v, "auto") == 0) p->proxy_auth[i] = SD_PROFILE_PROXY_AUTH_AUTO;
      else if (strcmp(v, "basic") == 0) p->proxy_auth[i] = SD_PROFILE_PROXY_AUTH_BASIC;
      else if (strcmp(v, "negotiate") == 0) p->proxy_auth[i] = SD_PROFILE_PROXY_AUTH_NEGOTIATE;
      else if (strcmp(v, "none") == 0) p->proxy_auth[i] = SD_PROFILE_PROXY_AUTH_NONE;
      else return "proxy.proxy_auth";
    }
    if ((v = leg_value(ini, "proxy_fallback_direct", i + 1)) != NULL) {
      if (!sd_ini_parse_bool(v, &b)) return "proxy.proxy_fallback_direct";
      if (b) p->proxy_fallback_direct |= 1u << i;
    }
  }
  if ((v = sd_ini_get(ini, "connection", "connections")) != NULL) {
    if (!sd_ini_parse_u32(v, &u) || u < 1 || u > 4) return "connection.connections";
    p->connections = u;
  }
  if ((v = sd_ini_get(ini, "security", "legacy_algorithms")) != NULL) {
    if (strcmp(v, "allow") == 0) p->legacy_algorithms = SD_PROFILE_LEGACY_ALLOW;
    else if (strcmp(v, "warn") == 0) p->legacy_algorithms = SD_PROFILE_LEGACY_WARN;
    else if (strcmp(v, "ask") == 0) p->legacy_algorithms = SD_PROFILE_LEGACY_ASK;
    else if (strcmp(v, "refuse") == 0) p->legacy_algorithms = SD_PROFILE_LEGACY_REFUSE;
    else return "security.legacy_algorithms";
  }
  if ((v = sd_ini_get(ini, "security", "legacy_accepted")) != NULL &&
      !sd_cfg_scpy(p->legacy_accepted, sizeof(p->legacy_accepted), v))
    return "security.legacy_accepted";
  if ((v = sd_ini_get(ini, "security", "host_key_alias")) != NULL &&
      !sd_cfg_scpy(p->host_key_alias, sizeof(p->host_key_alias), v))
    return "security.host_key_alias";
  if ((v = sd_ini_get(ini, "security", "update_host_keys")) != NULL) {
    if (strcmp(v, "ask") == 0) p->update_host_keys = SD_PROFILE_HKU_ASK;
    else if (strcmp(v, "yes") == 0) p->update_host_keys = SD_PROFILE_HKU_YES;
    else if (strcmp(v, "no") == 0) p->update_host_keys = SD_PROFILE_HKU_NO;
    else return "security.update_host_keys";
  }
  if ((v = sd_ini_get(ini, "security", "keepalive")) != NULL && !sd_ini_parse_duration_ms(v, &p->keepalive_ms))
    return "security.keepalive";
  if ((v = sd_ini_get(ini, "security", "connect_timeout")) != NULL &&
      !sd_ini_parse_duration_ms(v, &p->connect_timeout_ms))
    return "security.connect_timeout";
  if ((v = sd_ini_get(ini, "security", "refuse_terrapin_exposed")) != NULL) {
    if (!sd_ini_parse_bool(v, &b)) return "security.refuse_terrapin_exposed";
    p->refuse_terrapin_exposed = b;
  }
  return NULL;
}

sd_err sd_profile_m2_to_ini(const sd_profile *p, sd_ini *d)
{
  char num[24], k[48], spec[512];
  uint32_t i;
  sd_err e;
#define SET(s, key, v) do { if ((e = sd_ini_set(d, (s), (key), (v))) != SD_OK) return e; } while (0)
#define HAS(s, key) (sd_ini_get(d, (s), (key)) != NULL)
  for (i = 0; i < SD_PROFILE_MAX_IDENTITIES - 1; i++) {
    strcpy_s(k, sizeof(k), "identity.");
    k[9] = (char)('2' + i);
    k[10] = 0;
    if (p->identity_n[i][0] || HAS("auth", k)) SET("auth", k, p->identity_n[i]);
  }
  if (p->identity_store[0] || HAS("auth", "identity_store")) SET("auth", "identity_store", p->identity_store);
  if (p->certificate[0] || HAS("auth", "certificate")) SET("auth", "certificate", p->certificate);
  if (p->agent != SD_PROFILE_AGENT_AUTO || HAS("auth", "agent"))
    SET("auth", "agent", p->agent == SD_PROFILE_AGENT_PAGEANT ? "pageant" : p->agent == SD_PROFILE_AGENT_OPENSSH
                         ? "openssh" : p->agent == SD_PROFILE_AGENT_NONE ? "none" : "auto");
  if (p->identities_only != SD_PROFILE_UNSET)
    SET("auth", "identities_only", p->identities_only ? "yes" : "no");
  else if (HAS("auth", "identities_only"))
    sd_ini_remove(d, "auth", "identities_only");          /* back to the D37 rule */
  if (p->agent_keys[0] || HAS("auth", "agent_keys")) SET("auth", "agent_keys", p->agent_keys);
  if (!p->save_password || HAS("auth", "save_password")) SET("auth", "save_password", p->save_password ? "yes" : "no");
  if (!p->cache_secrets || HAS("auth", "cache_secrets_for_reconnect"))
    SET("auth", "cache_secrets_for_reconnect", p->cache_secrets ? "yes" : "no");
  if (p->jump[0] || HAS("proxy", "jump")) SET("proxy", "jump", p->jump);
  for (i = 0; i < SD_PROFILE_MAX_LEGS; i++) {
    leg_key(k, sizeof(k), "proxy", i + 1);
    if (p->proxy[i].kind != SD_PROFILE_PROXY_NONE || HAS("proxy", k)) {
      if ((e = sd_proxy_spec_format(&p->proxy[i], spec, sizeof(spec))) != SD_OK) return e;
      SET("proxy", k, spec);
    }
    leg_key(k, sizeof(k), "proxy_auth", i + 1);
    if (p->proxy_auth[i] != SD_PROFILE_PROXY_AUTH_AUTO || HAS("proxy", k))
      SET("proxy", k, p->proxy_auth[i] == SD_PROFILE_PROXY_AUTH_BASIC ? "basic"
                    : p->proxy_auth[i] == SD_PROFILE_PROXY_AUTH_NEGOTIATE ? "negotiate"
                    : p->proxy_auth[i] == SD_PROFILE_PROXY_AUTH_NONE ? "none" : "auto");
    leg_key(k, sizeof(k), "proxy_fallback_direct", i + 1);
    if ((p->proxy_fallback_direct & (1u << i)) || HAS("proxy", k))
      SET("proxy", k, (p->proxy_fallback_direct & (1u << i)) ? "yes" : "no");
  }
  if (p->connections != 1 || HAS("connection", "connections")) {
    sd_cfg_u32_dec(num, p->connections);
    SET("connection", "connections", num);
  }
  if (p->legacy_algorithms != SD_PROFILE_LEGACY_WARN || HAS("security", "legacy_algorithms"))
    SET("security", "legacy_algorithms", p->legacy_algorithms == SD_PROFILE_LEGACY_ALLOW ? "allow"
                                       : p->legacy_algorithms == SD_PROFILE_LEGACY_ASK ? "ask"
                                       : p->legacy_algorithms == SD_PROFILE_LEGACY_REFUSE ? "refuse" : "warn");
  if (p->legacy_accepted[0] || HAS("security", "legacy_accepted")) SET("security", "legacy_accepted", p->legacy_accepted);
  if (p->host_key_alias[0] || HAS("security", "host_key_alias")) SET("security", "host_key_alias", p->host_key_alias);
  if (p->update_host_keys != SD_PROFILE_HKU_ASK || HAS("security", "update_host_keys"))
    SET("security", "update_host_keys", p->update_host_keys == SD_PROFILE_HKU_YES ? "yes"
                                      : p->update_host_keys == SD_PROFILE_HKU_NO ? "no" : "ask");
  if (p->keepalive_ms || HAS("security", "keepalive")) {
    sd_cfg_u32_dec(num, p->keepalive_ms);
    strcat_s(num, sizeof(num), "ms");
    SET("security", "keepalive", num);
  }
  if (p->connect_timeout_ms || HAS("security", "connect_timeout")) {
    sd_cfg_u32_dec(num, p->connect_timeout_ms);
    strcat_s(num, sizeof(num), "ms");
    SET("security", "connect_timeout", num);
  }
  if (p->refuse_terrapin_exposed || HAS("security", "refuse_terrapin_exposed"))
    SET("security", "refuse_terrapin_exposed", p->refuse_terrapin_exposed ? "yes" : "no");
#undef SET
#undef HAS
  return SD_OK;
}

/* ---- chain resolution ---- */

static sd_err default_lookup(void *ctx, const char *name_or_id, sd_profile *out)
{
  SD_UNUSED(ctx);
  return sd_profile_find(name_or_id, out, NULL, 0);
}

typedef struct resolver {
  sd_profile_lookup_fn lookup;
  void *ctx;
  sd_chain *c;
  char visited[SD_PROFILE_MAX_HOPS + 1][33];
  uint32_t nvisited;
  const char *why;
} resolver;

static void hop_from_profile(sd_chain_hop *h, const sd_profile *p)
{
  uint32_t i, n = sd_profile_identity_count(p);
  memset(h, 0, sizeof(*h));
  strcpy_s(h->host, sizeof(h->host), p->host);
  h->port = p->port;
  strcpy_s(h->user, sizeof(h->user), p->user);
  for (i = 0; i < n && i < SD_PROFILE_MAX_IDENTITIES; i++)
    strcpy_s(h->identity[i], sizeof(h->identity[i]), sd_profile_identity_at(p, i));
  h->identity_count = n;
  strcpy_s(h->identity_store, sizeof(h->identity_store), p->identity_store);
  strcpy_s(h->certificate, sizeof(h->certificate), p->certificate);
  h->agent = p->agent;
  h->identities_only = sd_profile_identities_only(p);
  strcpy_s(h->agent_keys, sizeof(h->agent_keys), p->agent_keys);
  h->auth_methods = p->auth_methods;
  strcpy_s(h->host_key_alias, sizeof(h->host_key_alias), p->host_key_alias);
  h->update_host_keys = p->update_host_keys;
  h->save_password = p->save_password;
  h->cache_secrets = p->cache_secrets;
}

static int visited(resolver *r, const char *id)
{
  uint32_t i;
  for (i = 0; i < r->nvisited; i++)
    if (strcmp(r->visited[i], id) == 0) return 1;
  return 0;
}

/* Appends the jump hops of p (recursively), then (if add_self) p itself. */
static sd_err expand(resolver *r, const sd_profile *p, int add_self, uint32_t depth)
{
  sd_jump_list jl;
  sd_profile *ref;
  uint32_t i;
  sd_err e = SD_OK;
  if (depth > SD_PROFILE_MAX_HOPS) {
    r->why = "jump_too_long";
    return SD_E_INVALID_PARAM;
  }
  if (sd_jump_parse(p->jump, &jl) != SD_OK) {
    r->why = "jump_invalid";
    return SD_E_INVALID_PARAM;
  }
  ref = (sd_profile *)sd_alloc(sizeof(*ref));
  if (ref == NULL)
    return SD_E_NO_MEMORY;
  for (i = 0; i < jl.count && e == SD_OK; i++) {
    const char *ent = jl.entry[i];
    if (r->lookup(r->ctx, ent, ref) == SD_OK) {
      if ((ref->id[0] && visited(r, ref->id)) || (p->id[0] && strcmp(ref->id, p->id) == 0)) {
        r->why = "jump_cycle";
        e = SD_E_INVALID_PARAM;
        break;
      }
      if (r->nvisited < SD_COUNTOF(r->visited) && ref->id[0])
        strcpy_s(r->visited[r->nvisited++], 33, ref->id);
      e = expand(r, ref, 1, depth + 1);
    } else {
      char user[128], host[256];
      uint16_t port = 0;
      sd_chain_hop *h;
      if (!sd_cfg_parse_host_spec_utf8(ent, user, sizeof(user), host, sizeof(host), &port)) {
        r->why = "jump_invalid";
        e = SD_E_INVALID_PARAM;
        break;
      }
      if (r->c->count >= SD_PROFILE_MAX_HOPS) {
        r->why = "jump_too_long";
        e = SD_E_INVALID_PARAM;
        break;
      }
      h = &r->c->hop[r->c->count++];
      hop_from_profile(h, p);                    /* inherits [auth] of the referencing profile */
      strcpy_s(h->host, sizeof(h->host), host);
      h->port = port ? port : 22;
      if (user[0]) strcpy_s(h->user, sizeof(h->user), user);
      h->host_key_alias[0] = 0;                  /* the alias names the referencing host, not this one */
    }
  }
  sd_free(ref);
  if (e != SD_OK)
    return e;
  if (add_self) {
    if (r->c->count >= SD_PROFILE_MAX_HOPS) {
      r->why = "jump_too_long";
      return SD_E_INVALID_PARAM;
    }
    hop_from_profile(&r->c->hop[r->c->count], p);
    strcpy_s(r->c->hop[r->c->count].profile_name, sizeof(r->c->hop[0].profile_name), p->name);
    strcpy_s(r->c->hop[r->c->count].profile_id, sizeof(r->c->hop[0].profile_id), p->id);
    r->c->count++;
  }
  return SD_OK;
}

sd_err sd_chain_resolve(const sd_profile *p, sd_profile_lookup_fn lookup, void *ctx, sd_chain **out,
                        const char **why)
{
  resolver *r;
  sd_chain *c;
  uint32_t i;
  sd_err e;
  if (why) *why = NULL;
  if (p == NULL || out == NULL)
    return SD_E_INVALID_PARAM;
  *out = NULL;
  c = (sd_chain *)sd_calloc(1, sizeof(*c));
  r = (resolver *)sd_calloc(1, sizeof(*r));
  if (c == NULL || r == NULL) {
    sd_free(c);
    sd_free(r);
    return SD_E_NO_MEMORY;
  }
  r->lookup = lookup ? lookup : default_lookup;
  r->ctx = ctx;
  r->c = c;
  if (p->id[0])
    strcpy_s(r->visited[r->nvisited++], 33, p->id);
  e = expand(r, p, 0, 0);
  if (e == SD_OK) {
    hop_from_profile(&c->hop[c->count], p);     /* the target */
    strcpy_s(c->hop[c->count].profile_name, sizeof(c->hop[0].profile_name), p->name);
    strcpy_s(c->hop[c->count].profile_id, sizeof(c->hop[0].profile_id), p->id);
    c->count++;
    for (i = 0; i < SD_PROFILE_MAX_LEGS; i++) {
      if (p->proxy[i].kind == SD_PROFILE_PROXY_NONE)
        continue;
      if (i >= c->count) {
        r->why = "proxy_leg";
        e = SD_E_INVALID_PARAM;
        break;
      }
      if (p->proxy[i].kind == SD_PROFILE_PROXY_SYSTEM && i != 0) {
        r->why = "proxy_system_leg";
        e = SD_E_INVALID_PARAM;
        break;
      }
    }
    memcpy(c->proxy, p->proxy, sizeof(c->proxy));
    memcpy(c->proxy_auth, p->proxy_auth, sizeof(c->proxy_auth));
    c->proxy_fallback_direct = p->proxy_fallback_direct;
  }
  if (why) *why = r->why;
  sd_free(r);
  if (e != SD_OK) {
    sd_free(c);
    return e;
  }
  *out = c;
  return SD_OK;
}
